"""Program brief: where to look first on a bounty program, and why.

A deterministic briefing built from data the operator already has:

* the imported program (``program.json``: scope, severity caps, excluded
  classes, banned techniques),
* the recon store (records by type, as ``recon_query`` returns them),
* past findings (this engagement and other engagements on the same program),
* optionally, the operator's own report history
  (``control/<engagement>/report-history.json``), the shape of a HackerOne
  report export reduced to non-sensitive fields.

:func:`build_brief` returns the brief as data and :func:`to_markdown` renders
it. Nothing here sends a request, calls a bounty platform or asks an LLM.

The brief never says that something is vulnerable. It says where to look and
why, and every ``why`` names the data that produced it. An excluded class or a
banned technique never appears in ``suggested_focus``, whatever the history
says. Every string from the history file or the recon store is untrusted text:
it is cleaned on the way in and escaped on the way into Markdown.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from buggy.findings.grade import endpoint_host, severity_cap
from buggy.findings.model import CLASSES
from buggy.pipeline.report import rank_candidates
from buggy.program.gate import _BANNED_CLASS_MARKERS
from buggy.program.record import BASELINE_BANNED_TECHNIQUES, banned_technique_ids

HISTORY_FILE = "report-history.json"
BRIEF_FILE = "program-brief.md"

NO_HISTORY = "no history supplied"

#: Report states of a HackerOne report export.
HISTORY_STATES = (
    "resolved",
    "duplicate",
    "informative",
    "not-applicable",
    "triaged",
    "new",
)
PAID_STATES = frozenset({"resolved", "triaged"})
NOT_PAID_STATES = ("duplicate", "informative", "not-applicable")
DUPLICATE_RISK_STATES = frozenset({"duplicate", "resolved"})

MAX_HISTORY_ROWS = 5000
MAX_TEXT = 200
MAX_ID = 40
MAX_FOCUS = 30
MAX_CANDIDATES = 400
MAX_REPORT_IDS = 5
MIN_EXCLUDED_CHARS = 4

#: H1 weakness names (or our class names) -> our class. First match wins, so
#: the more specific wording comes first.
_WEAKNESS_CLASS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssrf", re.compile(r"\b(?:ssrf|server[- ]side request forgery)\b")),
    ("csrf", re.compile(r"\b(?:csrf|xsrf|cross[- ]site request forgery)\b")),
    ("xss", re.compile(r"\b(?:xss|cross[- ]site scripting)\b")),
    ("open_redirect", re.compile(r"\bopen[- _]redirect")),
    ("graphql", re.compile(r"\bgraphql\b")),
    (
        "file_handling",
        re.compile(
            r"\b(?:path traversal|directory traversal|lfi|rfi|file inclusion|xxe|"
            r"xml external entit\w*|(?:unrestricted |malicious )?file upload)\b"
        ),
    ),
    (
        "access_control",
        re.compile(
            r"\b(?:idor|bola|insecure direct object reference\w*|improper access control|"
            r"broken access control|improper authorization|missing authorization|"
            r"incorrect authorization|privilege escalation)\b"
        ),
    ),
    (
        "auth_session",
        re.compile(
            r"\b(?:improper authentication|authentication bypass|broken authentication|"
            r"account takeover|session fixation|session management|jwt|2fa|mfa|"
            r"password reset|weak password|credential\w*)\b"
        ),
    ),
    ("business_logic", re.compile(r"\b(?:business logic|race condition|logic error)\b")),
    ("api", re.compile(r"\b(?:mass assignment|api abuse)\b")),
    (
        "injection",
        re.compile(
            r"\b(?:sql injection|sqli|nosql injection|command injection|code injection|"
            r"os command|remote code execution|rce|template injection|ssti|ldap injection|"
            r"injection)\b"
        ),
    ),
    ("crypto", re.compile(r"\b(?:cryptograph\w*|weak crypto|insecure randomness)\b")),
    ("misconfiguration", re.compile(r"\b(?:misconfiguration|cors|security headers?)\b")),
    (
        "info_exposure",
        re.compile(
            r"\b(?:information disclosure|information exposure|sensitive data exposure|"
            r"sensitive information|data exposure)\b"
        ),
    ),
)

#: An exclusion with one of these words names a variant of a class (``Self-XSS``,
#: ``CSRF on logout``), not the whole class. Such an exclusion is cited next to
#: the class instead of removing it; an exclusion naming the class itself removes it.
_NARROWING = re.compile(
    r"\b(?:self|logout|login|missing|lack|without|best[- ]practice|only|theoretical|"
    r"non[- ]sensitive|low[- ]impact|unauthenticated|version)\b"
)

#: What a group of ``rank_candidates`` rows has in common, by (class, probe).
_PROBE_SUBJECT: dict[tuple[str, str], str] = {
    ("access_control", "idor"): "id-like parameters",
    ("ssrf", "ssrf_canary"): "url-like parameters",
    ("file_handling", "path_traversal"): "file-like parameters",
    ("api", "mass_assignment"): "a JSON request body",
    ("auth_session", "jwt_alg_none"): "a required token",
    ("graphql", "graphql_checks"): "a GraphQL endpoint",
    ("auth_session", "http_send"): "an authentication or session path",
    ("access_control", "http_send"): "an administrative or internal path",
}

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁠-⁤﻿]")
_SAFE_ID = re.compile(r"[^A-Za-z0-9_.:-]")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|~#])")


# ── untrusted text ───────────────────────────────────────────────────


def clean_text(value: Any, limit: int = MAX_TEXT) -> str:
    """One line of plain text: no control or bidi characters, collapsed, capped."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    text = " ".join(_CONTROL.sub(" ", str(value)).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def md_escape(value: Any, limit: int = MAX_TEXT) -> str:
    """Untrusted text as inert Markdown: no HTML, links, emphasis, headings or table breaks."""
    text = clean_text(value, limit)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", text)


def _safe_id(value: Any) -> str:
    return _SAFE_ID.sub("", clean_text(value, MAX_ID * 2))[:MAX_ID]


# ── classes, exclusions, hosts ───────────────────────────────────────


def weakness_class(weakness: Any) -> str:
    """Our class for a weakness name; ``""`` when the name does not tell."""
    text = clean_text(weakness).lower()
    if not text:
        return ""
    if text.replace(" ", "_") in CLASSES:
        return text.replace(" ", "_")
    for cls, pattern in _WEAKNESS_CLASS:
        if pattern.search(text):
            return cls
    return ""


def _excluded_entries(program: dict[str, Any]) -> list[str]:
    entries = program.get("excluded_classes")
    out: list[str] = []
    for entry in entries if isinstance(entries, (list, tuple)) else []:
        wording = clean_text(entry)
        if wording and wording not in out:
            out.append(wording)
    return out


def exclusion_for(cls: str, text: str, program: dict[str, Any]) -> tuple[str, str]:
    """``(why it is dropped, "")`` or ``("", narrower exclusion to cite)`` for a class.

    Dropped: an excluded-class entry the class name contains (the grader's
    rule), an entry that names this class outright, or a banned technique's
    whole-word pattern (``buggy.program.gate``) in the class or ``text``.
    """
    described = f"{cls} {cls.replace('_', ' ')}"
    narrower = ""
    for wording in _excluded_entries(program):
        name = wording.lower()
        if len(name) >= MIN_EXCLUDED_CHARS and name in described:
            return f"excluded by the program: {wording}", ""
        if weakness_class(wording) == cls:
            if _NARROWING.search(name):
                narrower = narrower or wording
            else:
                return f"excluded by the program: {wording}", ""
    banned = set(banned_technique_ids(program))
    scanned = f"{described} {text}".lower()
    for technique, pattern in _BANNED_CLASS_MARKERS.items():
        if technique in banned and pattern.search(scanned):
            return f"banned technique: {technique.replace('_', ' ')}", ""
    return "", narrower


def _host(value: Any) -> str:
    text = clean_text(value, 2048).lower()
    if "://" in text:
        return (urlsplit(text).hostname or "").rstrip(".")
    return text.split("/", 1)[0].split(":", 1)[0].rstrip(".") if text else ""


def _pattern_covers(pattern: str, host: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    for prefix in ("**.", "*."):
        if pattern.startswith(prefix):
            base = pattern[len(prefix) :]
            return bool(base) and "*" not in base and host.endswith("." + base)
    try:
        address = ipaddress.ip_address(host)
        return address in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


def _covered(host: str, patterns: Iterable[Any]) -> bool:
    return any(_pattern_covers(str(p), host) for p in patterns)


def in_scope(program: dict[str, Any], host: str) -> bool:
    return _covered(host, program.get("in_scope") or []) and not _covered(
        host, program.get("out_of_scope") or []
    )


def _record_host(record: dict[str, Any]) -> str:
    attrs = record.get("attrs") if isinstance(record.get("attrs"), dict) else {}
    for value in (attrs.get("url"), record.get("value")):
        host = _host(value)
        if host and "." in host and " " not in host:
            return host
    value = str(record.get("value") or "")
    # "GET https://..." style values.
    for word in value.split():
        if "://" in word:
            return _host(word)
    return _host(record.get("asset"))


def scope_hosts(
    program: dict[str, Any], recon: dict[str, list[dict[str, Any]]] | None
) -> list[str]:
    """In-scope hosts named by the program itself or by the recon store, sorted."""
    hosts: set[str] = set()
    for entry in program.get("in_scope") or []:
        value = str(entry).strip().lower()
        if value and "*" not in value and "/" not in value:
            hosts.add(value)
    for records in (recon or {}).values():
        for record in records if isinstance(records, list) else []:
            if isinstance(record, dict):
                host = _record_host(record)
                if host:
                    hosts.add(host)
                asset = _host(record.get("asset"))
                if asset:
                    hosts.add(asset)
    return sorted(h for h in hosts if in_scope(program, h))


# ── history ─────────────────────────────────────────────────────────


def _bounty(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if value >= 0 else None


def normalize_history(rows: Any) -> list[dict[str, Any]]:
    """History rows reduced to the documented fields, every string cleaned."""
    if isinstance(rows, dict):
        rows = rows.get("reports")
    out: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        state = clean_text(row.get("state"), 40).lower().replace("_", "-").replace(" ", "-")
        weakness = clean_text(row.get("weakness"))
        out.append(
            {
                "id": _safe_id(row.get("id")),
                "title": clean_text(row.get("title")),
                "weakness": weakness,
                "class": weakness_class(weakness),
                "asset": clean_text(row.get("asset")),
                "state": state if state in HISTORY_STATES else "unknown",
                "bounty": _bounty(row.get("bounty")),
                "created_at": clean_text(row.get("created_at"), 40),
            }
        )
        if len(out) >= MAX_HISTORY_ROWS:
            break
    return out


def load_history(path: Path) -> tuple[list[dict[str, Any]] | None, str]:
    """``(rows, "")``; ``(None, NO_HISTORY)`` when absent; ``(None, reason)`` when unusable."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, NO_HISTORY
    except OSError as exc:
        return None, f"history file {path} cannot be read: {exc}"
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return None, f"history file {path} is not valid JSON: {exc}"
    if not isinstance(data, (list, dict)):
        return None, f"history file {path} is not a list of reports"
    return normalize_history(data), ""


def _times(n: int) -> str:
    return "once" if n == 1 else f"{n} times"


def _money(value: float) -> str:
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.2f}"


def _ids(rows: list[dict[str, Any]]) -> list[str]:
    return [r["id"] for r in rows if r["id"]][:MAX_REPORT_IDS]


def _group_by_weakness(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = row["weakness"] or row["class"] or "(no weakness given)"
        groups.setdefault(key, []).append(row)
    return groups


def what_paid(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paid = [r for r in history if r["state"] in PAID_STATES and (r["bounty"] or 0) > 0]
    out = []
    for weakness, rows in _group_by_weakness(paid).items():
        total = sum(r["bounty"] or 0 for r in rows)
        out.append(
            {
                "weakness": weakness,
                "class": rows[0]["class"],
                "count": len(rows),
                "total_bounty": total,
                "report_ids": _ids(rows),
                "why": f"history: paid {_times(len(rows))} on this program, "
                f"total bounty {_money(total)}",
            }
        )
    return sorted(out, key=lambda r: (-r["count"], -r["total_bounty"], r["weakness"].lower()))


def what_did_not(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unpaid = [r for r in history if r["state"] in NOT_PAID_STATES]
    out = []
    for weakness, rows in _group_by_weakness(unpaid).items():
        states = {s: sum(1 for r in rows if r["state"] == s) for s in NOT_PAID_STATES}
        states = {s: n for s, n in states.items() if n}
        out.append(
            {
                "weakness": weakness,
                "class": rows[0]["class"],
                "count": len(rows),
                "states": states,
                "report_ids": _ids(rows),
                "why": "history: came back "
                + ", ".join(f"{s} {_times(n)}" for s, n in states.items())
                + " on this program",
            }
        )
    return sorted(out, key=lambda r: (-r["count"], r["weakness"].lower()))


# ── sections ─────────────────────────────────────────────────────────


def _section(status: str, items: list[dict[str, Any]], note: str = "") -> dict[str, Any]:
    return {"status": status, "note": note, "items": items}


def _scope_summary(program: dict[str, Any]) -> list[dict[str, Any]]:
    caps = program.get("severity_caps") if isinstance(program.get("severity_caps"), dict) else {}
    lowered = {str(k).strip().lower(): str(v).strip().lower() for k, v in caps.items()}
    offers = program.get("offers_bounties")
    out = []
    for entry in program.get("in_scope") or []:
        asset = clean_text(entry).lower()
        if not asset:
            continue
        cap = lowered.get(asset) or ""
        if not cap and asset.startswith("**."):
            cap = lowered.get("*." + asset[3:]) or ""
        if not cap and "*" not in asset:
            cap = severity_cap(program, asset)[0]
        out.append(
            {
                "asset": asset,
                "max_severity": cap or None,
                # program.json records eligibility for submission (every in-scope
                # asset); a bounty flag only when the import carried one.
                "eligible_for_submission": True,
                "bounty_eligible": offers if isinstance(offers, bool) else None,
            }
        )
    return out


def _excluded(program: dict[str, Any]) -> dict[str, Any]:
    rules = {e["id"]: e["rule"] for e in BASELINE_BANNED_TECHNIQUES}
    for entry in program.get("banned_techniques") or []:
        if isinstance(entry, dict) and entry.get("id") and entry["id"] != "excluded_class":
            rules.setdefault(str(entry["id"]), clean_text(entry.get("rule")))
    return {
        "classes": _excluded_entries(program),
        "banned_techniques": [{"id": i, "rule": rules.get(i, "")} for i in rules],
    }


def _untouched(
    program: dict[str, Any],
    recon: dict[str, list[dict[str, Any]]] | None,
    findings: list[dict[str, Any]] | None,
    captured_hosts: set[str] | None,
    notes: dict[str, str],
) -> dict[str, Any]:
    if captured_hosts is None:
        return _section(
            "unavailable",
            [],
            "captures could not be read, so no host can be called untouched"
            + (f" ({notes['captures']})" if notes.get("captures") else ""),
        )
    if findings is None:
        return _section(
            "unavailable",
            [],
            "findings could not be read, so no host can be called untouched"
            + (f" ({notes['findings']})" if notes.get("findings") else ""),
        )
    touched = {h.lower() for h in captured_hosts}
    touched |= {endpoint_host(str(f.get("endpoint") or "")) for f in findings}
    endpoints: dict[str, int] = {}
    operations: dict[str, int] = {}
    for kind, counter in (
        ("endpoint", endpoints),
        ("url", endpoints),
        ("api_operation", operations),
    ):
        for record in (recon or {}).get(kind) or []:
            if isinstance(record, dict):
                host = _record_host(record)
                counter[host] = counter.get(host, 0) + 1
    items = []
    for host in scope_hosts(program, recon):
        if host in touched:
            continue
        e, o = endpoints.get(host, 0), operations.get(host, 0)
        items.append(
            {
                "host": host,
                "surface": e + o,
                "endpoints": e,
                "operations": o,
                "why": f"no capture and no finding on this host; recon: {e} endpoint(s)/URL(s) "
                f"and {o} API operation(s)",
            }
        )
    items.sort(key=lambda r: (-r["surface"], r["host"]))
    note = "" if recon is not None else "recon unavailable: surface counts are zero"
    return _section("ok", items, note)


def _focus(
    program: dict[str, Any],
    recon: dict[str, list[dict[str, Any]]] | None,
    paid: list[dict[str, Any]] | None,
    unpaid: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """``(suggested_focus, dropped)``."""
    if not recon:
        return [], []
    candidates = rank_candidates(recon, limit=MAX_CANDIDATES)
    groups: dict[tuple[str, str], int] = {}
    for row in candidates:
        key = (row["class"], row["probe"])
        groups[key] = groups.get(key, 0) + 1

    paid_by_class: dict[str, tuple[int, float, list[str]]] = {}
    for row in paid or []:
        if row["class"]:
            n, total, ids = paid_by_class.get(row["class"], (0, 0.0, []))
            paid_by_class[row["class"]] = (
                n + row["count"],
                total + row["total_bounty"],
                ids + row["report_ids"],
            )
    unpaid_by_class: dict[str, dict[str, int]] = {}
    for row in unpaid or []:
        if row["class"]:
            states = unpaid_by_class.setdefault(row["class"], {})
            for state, n in row["states"].items():
                states[state] = states.get(state, 0) + n

    ranked: list[tuple[tuple[Any, ...], dict[str, str]]] = []
    dropped: list[dict[str, str]] = []
    for index, row in enumerate(candidates):
        cls, where, probe = row["class"], clean_text(row["where"], 300), row["probe"]
        reason, narrower = exclusion_for(cls, f"{row['why']} {where}", program)
        if reason:
            dropped.append({"class": cls, "where": where, "why": reason})
            continue
        count = groups[(cls, probe)]
        subject = _PROBE_SUBJECT.get((cls, probe), f"{cls} candidates")
        parts = [
            f"recon: {clean_text(row['why'], 300)}; "
            f"{count} location{'s' if count != 1 else ''} with {subject}"
        ]
        if paid is None:
            parts.append(f"history: {NO_HISTORY}")
        tier = 1
        n_paid, total, ids = paid_by_class.get(cls, (0, 0.0, []))
        if n_paid:
            tier = 0
            parts.append(
                f"history: paid {_times(n_paid)} on this program, total bounty {_money(total)}"
                + (f" (reports {', '.join(ids[:MAX_REPORT_IDS])})" if ids else "")
            )
        states = unpaid_by_class.get(cls)
        if states:
            if not n_paid:
                tier = 2
            parts.append(
                "history: came back "
                + ", ".join(f"{s} {_times(n)}" for s, n in states.items())
                + " on this program"
                + ("" if n_paid else "; down-weighted")
            )
        if paid is not None and not n_paid and not states:
            parts.append("history: no report of this class")
        if narrower:
            parts.append(f"program excludes the variant '{narrower}': stay clear of it")
        ranked.append(
            (
                (tier, -n_paid, -total, index),
                {"class": cls, "where": where, "why": "; ".join(parts), "probe": probe},
            )
        )
    ranked.sort(key=lambda pair: pair[0])
    return [item for _key, item in ranked[:MAX_FOCUS]], dropped


def _duplicates(
    engagement: str,
    findings: list[dict[str, Any]],
    history: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    risky = [r for r in history if r["state"] in DUPLICATE_RISK_STATES and r["class"]]
    out = []
    for finding in findings:
        if str(finding.get("engagement") or engagement) != engagement:
            continue
        if str(finding.get("status") or "") == "discarded":
            continue
        cls = str(finding.get("class") or finding.get("vuln_class") or "").lower()
        host = endpoint_host(str(finding.get("endpoint") or ""))
        if not cls or not host:
            continue
        matches = [
            r for r in risky if r["class"] == cls and _pattern_covers(_host(r["asset"]), host)
        ]
        if not matches:
            continue
        cited = ", ".join(
            f"{r['id'] or '(no id)'} ({r['state']})" for r in matches[:MAX_REPORT_IDS]
        )
        out.append(
            {
                "finding_id": clean_text(finding.get("id"), 40),
                "title": clean_text(finding.get("title")),
                "class": cls,
                "host": host,
                "history": [
                    {"id": r["id"], "state": r["state"], "title": r["title"], "asset": r["asset"]}
                    for r in matches[:MAX_REPORT_IDS]
                ],
                "why": f"history: {len(matches)} earlier report(s) of class {cls} on an asset "
                f"covering {host}: {cited}",
            }
        )
    return out


def build_brief(
    program: dict[str, Any],
    recon: dict[str, list[dict[str, Any]]] | None,
    findings: list[dict[str, Any]] | None,
    history: list[dict[str, Any]] | None = None,
    *,
    engagement: str = "",
    captured_hosts: set[str] | None = None,
    sources: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The brief as JSON-serialisable data.

    ``recon``, ``findings`` and ``captured_hosts`` are ``None`` when their
    source could not be read; ``history`` is ``None`` when none was supplied
    (raw or already normalised rows are accepted). ``sources`` carries a note
    per input for the brief to show (why something is missing).
    """
    program = program if isinstance(program, dict) else {}
    notes = {str(k): clean_text(v, 400) for k, v in (sources or {}).items()}
    engagement = engagement or clean_text(program.get("engagement"), 100)
    rows = normalize_history(history) if history is not None else None
    history_note = notes.get("history") or NO_HISTORY

    paid = what_paid(rows) if rows is not None else None
    unpaid = what_did_not(rows) if rows is not None else None
    focus, dropped = _focus(program, recon, paid, unpaid)

    def history_section(items: list[dict[str, Any]] | None) -> dict[str, Any]:
        if items is None:
            return _section("no history supplied", [], history_note)
        return _section("ok", items)

    if rows is None:
        duplicates = history_section(None)
    elif findings is None:
        duplicates = _section(
            "unavailable",
            [],
            "findings could not be read"
            + (f" ({notes['findings']})" if notes.get("findings") else ""),
        )
    else:
        duplicates = _section("ok", _duplicates(engagement, findings, rows))

    status = {
        "program": "ok",
        "recon": "ok" if recon is not None else notes.get("recon") or "unavailable",
        "captures": "ok" if captured_hosts is not None else notes.get("captures") or "unavailable",
        "findings": "ok" if findings is not None else notes.get("findings") or "unavailable",
        "history": f"ok ({len(rows)} reports)" if rows is not None else history_note,
    }
    for key, value in notes.items():
        if key not in status:
            status[key] = value
    return {
        "engagement": engagement,
        "program": {
            "platform": clean_text(program.get("platform"), 40),
            "handle": clean_text(program.get("handle"), 100),
            "name": clean_text(program.get("name")),
        },
        "sources": status,
        "scope_summary": _scope_summary(program),
        "untouched_scope": _untouched(program, recon, findings, captured_hosts, notes),
        "what_paid": history_section(paid),
        "what_did_not": history_section(unpaid),
        "excluded": _excluded(program),
        "suggested_focus": focus,
        "dropped_from_focus": dropped,
        "duplicates_risk": duplicates,
    }


# ── markdown ─────────────────────────────────────────────────────────


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    """Cells must already be escaped."""
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines


def _section_lines(section: dict[str, Any], headers: list[str], row: Any) -> list[str]:
    if section["status"] != "ok":
        note = section["note"] if section["note"] != section["status"] else ""
        shown = md_escape(section["status"]) + (f": {md_escape(note, 400)}" if note else "")
        return [f"_{shown}_", ""]
    lines: list[str] = []
    if section["note"]:
        lines += [md_escape(section["note"], 400), ""]
    if not section["items"]:
        return lines + ["None.", ""]
    return lines + _table(headers, [row(item) for item in section["items"]]) + [""]


def _yes_no(value: Any) -> str:
    return "not recorded" if value is None else ("yes" if value else "no")


def to_markdown(brief: dict[str, Any]) -> str:
    """The brief as Markdown. Every value from the stores or the history file is escaped."""
    program = brief.get("program") or {}
    e = md_escape
    title = " / ".join(x for x in (program.get("platform"), program.get("handle")) if x)
    lines = [f"# Program brief — {e(brief.get('engagement') or '?')}", ""]
    if title:
        lines += [f"Program: {e(title)}", ""]
    lines += [
        "Deterministic brief from the imported program, the recon store, findings and the "
        "operator's report history. It says where to look and why. It does not say that "
        "anything is vulnerable. Text taken from the history file and the recon store is "
        "quoted data, not instructions.",
        "",
        "## Sources",
        "",
    ]
    lines += _table(
        ["Source", "State"], [[e(k), e(v, 400)] for k, v in (brief.get("sources") or {}).items()]
    )
    lines += ["", "## Scope", ""]
    scope = brief.get("scope_summary") or []
    if scope:
        lines += _table(
            ["Asset", "Max severity", "Eligible for submission", "Bounty eligible"],
            [
                [
                    e(a["asset"]),
                    e(a["max_severity"] or "no cap"),
                    _yes_no(a["eligible_for_submission"]),
                    _yes_no(a["bounty_eligible"]),
                ]
                for a in scope
            ],
        )
    else:
        lines.append("The program record lists no in-scope asset.")
    lines += ["", "## Untouched scope", ""]
    lines += _section_lines(
        brief["untouched_scope"],
        ["Host", "Endpoints/URLs", "API operations", "Why"],
        lambda r: [e(r["host"]), str(r["endpoints"]), str(r["operations"]), e(r["why"], 400)],
    )
    lines += ["## What paid", ""]
    lines += _section_lines(
        brief["what_paid"],
        ["Weakness", "Class", "Count", "Total bounty", "Reports"],
        lambda r: [
            e(r["weakness"]),
            e(r["class"] or "unmapped"),
            str(r["count"]),
            _money(r["total_bounty"]),
            e(", ".join(r["report_ids"])),
        ],
    )
    lines += ["## What did not pay (avoid here)", ""]
    lines += _section_lines(
        brief["what_did_not"],
        ["Weakness", "Class", "Outcome", "Reports"],
        lambda r: [
            e(r["weakness"]),
            e(r["class"] or "unmapped"),
            e(", ".join(f"{s} {n}" for s, n in r["states"].items())),
            e(", ".join(r["report_ids"])),
        ],
    )
    excluded = brief.get("excluded") or {}
    lines += ["## Excluded", ""]
    lines.append(
        "Classes the program does not accept: "
        + (", ".join(e(c) for c in excluded.get("classes") or []) or "none listed")
        + "."
    )
    lines.append("")
    for technique in excluded.get("banned_techniques") or []:
        lines.append(f"- {e(technique['id'])}: {e(technique['rule'], 400)}")
    lines += ["", "## Suggested focus", ""]
    focus = brief.get("suggested_focus") or []
    if focus:
        lines += _table(
            ["#", "Class", "Where", "Why", "Probe"],
            [
                [str(i), e(f["class"]), e(f["where"], 300), e(f["why"], 600), e(f["probe"])]
                for i, f in enumerate(focus, 1)
            ],
        )
    elif (brief.get("sources") or {}).get("recon") != "ok":
        lines.append("Recon could not be read, so there is nothing to rank.")
    else:
        lines.append("Nothing in the recon store stood out.")
    dropped = brief.get("dropped_from_focus") or []
    if dropped:
        lines += [
            "",
            f"{len(dropped)} recon candidate(s) left out because the program excludes them.",
        ]
    lines += ["", "## Duplicate risk", ""]
    lines += _section_lines(
        brief["duplicates_risk"],
        ["Finding", "Class", "Host", "Why"],
        lambda r: [e(r["finding_id"]), e(r["class"]), e(r["host"]), e(r["why"], 400)],
    )
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "BRIEF_FILE",
    "HISTORY_FILE",
    "NO_HISTORY",
    "build_brief",
    "clean_text",
    "exclusion_for",
    "in_scope",
    "load_history",
    "md_escape",
    "normalize_history",
    "scope_hosts",
    "to_markdown",
    "weakness_class",
    "what_did_not",
    "what_paid",
]
