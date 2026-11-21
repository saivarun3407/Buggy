"""Findings report: one report, three renderings (Markdown, self-contained HTML, JSON).

:func:`build` turns the findings store's rows into a report dict; the
``to_*`` functions render it. Nothing here sends a request, reads the clock or
writes a file, and the same input gives byte-identical output.

What the report may call what:

* ``findings``   - ``exploit_verified`` only: the independent verifier re-sent
  every cited request and every assertion held on the fresh response. These are
  the only items counted by severity and the only items any heading calls a
  vulnerability or a finding.
* ``unverified`` - ``source_verified`` (a reviewer's note, nothing replayed) and
  ``inconclusive`` (a replay did not hold, or could not be made), each labelled,
  with the verifier's reasons.
* ``leads``      - ``candidate``: claims nobody has tried to prove yet.
* ``discarded``  - a count only.

All finding text (title, description, remediation, endpoint, parameter, source)
was written by an agent or taken from a target, so every renderer treats it as
hostile: HTML escapes it everywhere and carries no script, no external resource
and no event handler; Markdown escapes it so that no field can start a heading,
a list, a table cell, a link or raw HTML.

Evidence comes from the ``captures`` callable. It may return a
:class:`buggy.capture.store.Capture` (its redacted :meth:`detail` view is used,
and the reproduction carries :func:`buggy.capture.export.to_curl` with
``redact=True``) or a dict that already is that view (credential headers are
masked again; no curl command can be made from a dict). The report never shows
more than the redacted view.
"""

from __future__ import annotations

import html
import json
import re
import string
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from buggy.capture.export import to_curl
from buggy.capture.store import REDACTED, SENSITIVE_HEADERS, Capture
from buggy.findings.model import SEVERITIES, Status
from buggy.findings.verifier import DIFFERS_BELOW, SAME_AS_MIN

Report = dict[str, Any]
CaptureLookup = Callable[[str], Any]

REPORT_FORMAT = 1
#: Characters of a replayed response shown as proof.
EXCERPT_CHARS = 600

LABELS: dict[str, str] = {
    Status.SOURCE_VERIFIED.value: "source-verified: reviewed by a person or source analysis, "
    "not re-proved by a replay",
    Status.INCONCLUSIVE.value: "inconclusive: not proven; the replay did not hold or could not "
    "be made",
}

METHOD = (
    "A vulnerability in this report is a claim the independent verifier re-proved: it re-sent "
    "every request the claim cites through the capture gateway (scope, approval hold and rate "
    "limits applied) and every assertion held on the fresh response. Only those "
    "exploit-verified items are listed as findings and counted by severity. Source-verified "
    "items were vouched for by a reviewer's note and not replayed; inconclusive items did not "
    "hold on replay or could not be replayed; leads have not been tested. None of these is "
    "proven, and they are listed separately. Discarded claims cited evidence the verifier "
    "rejected and appear only as a count. Credentials are shown as they appear in the capture "
    "gateway's redacted view."
)

_UNVERIFIED_ORDER = (Status.SOURCE_VERIFIED.value, Status.INCONCLUSIVE.value)


# ── helpers ─────────────────────────────────────────────────────────


def _s(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _printable(text: str) -> str:
    """``text`` with control characters other than newline and tab replaced."""
    return "".join(ch if ch.isprintable() or ch in "\n\t" else "�" for ch in text)


def _severity_key(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _timestamp(value: Any) -> str:
    if isinstance(value, bool):
        raise TypeError("generated_at must be a timestamp or a string")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC).isoformat(timespec="seconds")
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise TypeError("generated_at is required: the report does not read the clock")


def _quote(text: str) -> str:
    return '"' + text + '"'


# ── evidence ────────────────────────────────────────────────────────


def _mask_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    return {
        _s(name): (REDACTED if _s(name).lower() in SENSITIVE_HEADERS else _s(value))
        for name, value in headers.items()
    }


def _lookup(captures: CaptureLookup, capture_id: str, engagement: str) -> tuple[dict, str] | None:
    """``(redacted view, curl text)`` of a capture, or ``None`` when it is not available."""
    if not capture_id:
        return None
    found = captures(capture_id)
    if isinstance(found, Capture):
        if found.engagement != engagement:
            return None
        return found.detail(), to_curl(found, redact=True)
    if isinstance(found, dict):
        if found.get("engagement") not in (None, "", engagement):
            return None
        view = dict(found)
        view["request_headers"] = _mask_headers(view.get("request_headers"))
        view["response_headers"] = _mask_headers(view.get("response_headers"))
        return view, ""
    return None


def _expectation_words(expect: dict[str, Any]) -> list[str]:
    words: list[str] = []
    status = expect.get("status")
    codes = status if isinstance(status, list) else ([status] if status is not None else [])
    if codes:
        words.append("status is " + " or ".join(str(code) for code in codes))
    for needle in expect.get("body_contains") or []:
        words.append(f"the body contains {_quote(_s(needle))}")
    for needle in expect.get("body_not_contains") or []:
        words.append(f"the body does not contain {_quote(_s(needle))}")
    if expect.get("same_as"):
        words.append(
            f"the response matches capture {_s(expect['same_as'])} "
            f"(similarity at least {SAME_AS_MIN:.2f})"
        )
    if expect.get("differs_from"):
        words.append(
            f"the response differs from capture {_s(expect['differs_from'])} "
            f"(similarity below {DIFFERS_BELOW:.2f} or a different status)"
        )
    return words


def _steps(
    finding: dict[str, Any], captures: CaptureLookup, engagement: str
) -> list[dict[str, Any]]:
    """Numbered reproduction steps, one per assertion, from the captures they cite."""
    outcomes: dict[int, str] = {}
    for entry in (finding.get("verification") or {}).get("assertions") or []:
        if isinstance(entry, dict) and isinstance(entry.get("index"), int):
            outcomes[entry["index"]] = _s(entry.get("outcome"))
    steps: list[dict[str, Any]] = []
    for index, assertion in enumerate(finding.get("assertions") or []):
        if not isinstance(assertion, dict):
            continue
        capture_id = _s(assertion.get("capture_id"))
        identity = _s(assertion.get("identity"))
        found = _lookup(captures, capture_id, engagement)
        view, curl = found if found is not None else ({}, "")
        method = _s(view.get("method"))
        url = _s(view.get("url"))
        who = f"as identity {_quote(identity)}" if identity else "with no named identity"
        expect = _expectation_words(assertion.get("expect") or {})
        number = len(steps) + 1
        if found is None:
            request = f"capture {capture_id} (not available to this report)"
        else:
            request = f"{method} {url} {who} (capture {capture_id})"
        text = f"{number}. Send {request}. Expect: " + ("; ".join(expect) or "nothing stated") + "."
        steps.append(
            {
                "number": number,
                "capture_id": capture_id,
                "method": method,
                "url": url,
                "identity": identity,
                "expect": expect,
                "outcome": outcomes.get(index, ""),
                "text": text,
                "curl": curl,
            }
        )
    return steps


def _proof(finding: dict[str, Any], captures: CaptureLookup, engagement: str) -> list[dict]:
    """The verifier's replay captures: status line and the first characters of the response."""
    out: list[dict[str, Any]] = []
    ids = (finding.get("verification") or {}).get("replay_capture_ids") or []
    for capture_id in dict.fromkeys(_s(value) for value in ids):
        found = _lookup(captures, capture_id, engagement)
        if found is None:
            out.append(
                {
                    "capture_id": capture_id,
                    "status_line": f"replay capture {capture_id} is not available to this report",
                    "response_headers": {},
                    "excerpt": "",
                    "truncated": False,
                }
            )
            continue
        view = found[0]
        status = view.get("status")
        if status is None:
            line = f"no response ({_s(view.get('error')) or 'no status recorded'})"
        else:
            line = f"HTTP {status}"
        line += f" to {_s(view.get('method'))} {_s(view.get('url'))}"
        if view.get("response_sha256"):
            line += f", response sha256 {_s(view['response_sha256'])}"
        body = _s(view.get("response_body"))
        headers = view.get("response_headers") or {}
        out.append(
            {
                "capture_id": capture_id,
                "status_line": line,
                "response_headers": {k: headers[k] for k in sorted(headers)},
                "excerpt": _printable(body[:EXCERPT_CHARS]),
                "truncated": len(body) > EXCERPT_CHARS or bool(view.get("response_truncated")),
            }
        )
    return out


# ── build ───────────────────────────────────────────────────────────


def _grade(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision": finding.get("grade") or None,
        "reasons": [_s(reason) for reason in finding.get("grade_reasons") or []],
    }


def _base(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _s(finding.get("id")),
        "title": _s(finding.get("title")),
        "severity": _s(finding.get("severity")),
        "cwe": _s(finding.get("cwe")),
        "class": _s(finding.get("class")),
        "endpoint": _s(finding.get("endpoint")),
        "method": _s(finding.get("method")),
        "parameter": _s(finding.get("parameter")),
        "source": _s(finding.get("source")),
    }


def _order(item: dict[str, Any]) -> tuple[int, str]:
    return _severity_key(item["severity"]), item["id"]


def build(
    engagement: str,
    findings: list[dict],
    *,
    recon_summary: dict | None,
    scope: list[str],
    captures: CaptureLookup,
    generated_at: Any,
    complete: bool = False,
) -> Report:
    """The report as a JSON-serialisable dict.

    ``findings`` are finding dicts (``Finding.to_dict()``); a row of another
    engagement is left out and counted. ``captures(id)`` returns a capture of
    this engagement (a ``Capture`` or its redacted ``detail()`` dict) or
    ``None``. ``generated_at`` is an epoch timestamp or a string; the clock is
    never read. ``complete`` says whether the engagement's testing finished.
    """
    verified: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    discarded = other_engagement = unrecognised = 0
    for finding in findings or []:
        if not isinstance(finding, dict):
            unrecognised += 1
            continue
        if finding.get("engagement") not in (None, "", engagement):
            other_engagement += 1
            continue
        status = _s(finding.get("status"))
        verification = finding.get("verification") or {}
        reasons = [_s(reason) for reason in verification.get("reasons") or []]
        if status == Status.EXPLOIT_VERIFIED.value:
            verified.append(
                {
                    **_base(finding),
                    "status": status,
                    "description": _s(finding.get("description")),
                    "remediation": _s(finding.get("remediation")),
                    "reproduction": _steps(finding, captures, engagement),
                    "proof": _proof(finding, captures, engagement),
                    "verifier_reasons": reasons,
                    "grade": _grade(finding),
                }
            )
        elif status in _UNVERIFIED_ORDER:
            unverified.append(
                {
                    **_base(finding),
                    "status": status,
                    "label": LABELS[status],
                    "description": _s(finding.get("description")),
                    "remediation": _s(finding.get("remediation")),
                    "verifier_reasons": reasons,
                    "grade": _grade(finding),
                }
            )
        elif status == Status.CANDIDATE.value:
            leads.append(
                {
                    **_base(finding),
                    "status": status,
                    "assertions": len(finding.get("assertions") or []),
                }
            )
        elif status == Status.DISCARDED.value:
            discarded += 1
        else:
            unrecognised += 1

    verified.sort(key=_order)
    unverified.sort(key=lambda item: (_UNVERIFIED_ORDER.index(item["status"]), *_order(item)))
    leads.sort(key=_order)
    by_severity = {severity: 0 for severity in SEVERITIES}
    for item in verified:
        if item["severity"] in by_severity:
            by_severity[item["severity"]] += 1
    return {
        "report_format": REPORT_FORMAT,
        "engagement": _s(engagement),
        "generated_at": _timestamp(generated_at),
        "summary": {
            "complete": bool(complete),
            "verified": len(verified),
            "verified_by_severity": by_severity,
            "source_verified": sum(i["status"] == Status.SOURCE_VERIFIED.value for i in unverified),
            "inconclusive": sum(i["status"] == Status.INCONCLUSIVE.value for i in unverified),
            "candidates": len(leads),
            "discarded": discarded,
            "other_engagement": other_engagement,
            "unrecognised": unrecognised,
        },
        "method": METHOD,
        "scope": [_s(entry) for entry in dict.fromkeys(scope or [])],
        "recon_summary": recon_summary if isinstance(recon_summary, dict) else None,
        "findings": verified,
        "unverified": unverified,
        "leads": leads,
    }


# ── JSON ────────────────────────────────────────────────────────────


def to_json(report: Report) -> str:
    """The report as JSON: sorted keys, two-space indent, ASCII only, one trailing newline."""
    return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def _recon_rows(recon: dict[str, Any] | None) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    source = recon or {}
    for key in sorted(source, key=str):
        value = source[key]
        shown = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
        rows.append((str(key), shown))
    return rows


# ── Markdown ────────────────────────────────────────────────────────

_PUNCTUATION = frozenset(string.punctuation)
_BACKTICKS = re.compile(r"`+")


def md_inline(value: Any) -> str:
    """One line of text that Markdown shows literally.

    Whitespace (newlines included) collapses to single spaces and every ASCII
    punctuation character is backslash-escaped, so no field can open a heading,
    list, table cell, link, emphasis, code span, entity or raw HTML.
    """
    text = " ".join(_printable(_s(value)).split())
    return "".join("\\" + ch if ch in _PUNCTUATION else ch for ch in text)


def md_text(value: Any) -> str:
    """Multi-paragraph text: paragraphs kept, each one rendered with :func:`md_inline`."""
    paragraphs = [md_inline(part) for part in re.split(r"\n\s*\n", _s(value))]
    return "\n\n".join(part for part in paragraphs if part)


def md_code(value: Any) -> str:
    """A fenced code block whose fence is longer than any backtick run in ``value``."""
    text = _printable(_s(value)).replace("\r\n", "\n").replace("\r", "\n")
    longest = max((len(run) for run in _BACKTICKS.findall(text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def _md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return lines


def _md_fields(item: dict[str, Any]) -> list[str]:
    pairs = [
        ("ID", item["id"]),
        ("Severity", item["severity"]),
        ("CWE", item["cwe"] or "none given"),
        ("Class", item["class"]),
        ("Endpoint", item["endpoint"]),
        ("Method", item["method"]),
        ("Parameter", item["parameter"] or "none"),
        ("Source", item["source"]),
    ]
    return [f"- **{name}:** {md_inline(value)}" for name, value in pairs]


def _md_grade(grade: dict[str, Any]) -> list[str]:
    decision = grade["decision"] or "not graded"
    lines = [f"**Grade:** {md_inline(decision)}", ""]
    lines.extend(f"- {md_inline(reason)}" for reason in grade["reasons"])
    return lines


def to_markdown(report: Report) -> str:
    summary = report["summary"]
    out: list[str] = [f"# Security report: {md_inline(report['engagement'])}", ""]
    out.append(f"Generated {md_inline(report['generated_at'])}.")
    out.append("")
    if summary["complete"]:
        out.append("Testing for this engagement is recorded as complete.")
    else:
        out.append("Testing for this engagement is **not** recorded as complete.")
    out.extend(["", "## Summary", ""])
    if summary["verified"]:
        out.append(f"{summary['verified']} exploit-verified finding(s).")
    else:
        out.append("Nothing was verified: no claim was re-proved by the verifier.")
    out.append("")
    out.extend(
        _md_table(
            ["Severity", "Verified"],
            [[sev, str(n)] for sev, n in summary["verified_by_severity"].items()],
        )
    )
    out.append("")
    out.extend(
        _md_table(
            ["Not proven or not reported", "Count"],
            [
                ["source-verified (not replayed)", str(summary["source_verified"])],
                ["inconclusive", str(summary["inconclusive"])],
                ["leads (candidates)", str(summary["candidates"])],
                ["discarded", str(summary["discarded"])],
            ],
        )
    )
    out.extend(["", "## Method", "", md_text(report["method"]), "", "## Scope", ""])
    out.extend(f"- {md_inline(entry)}" for entry in report["scope"])
    if not report["scope"]:
        out.append("No scope was given to this report.")
    if report["recon_summary"]:
        out.extend(["", "## Recon summary", ""])
        out.extend(
            _md_table(
                ["Item", "Value"],
                [[md_inline(k), md_inline(v)] for k, v in _recon_rows(report["recon_summary"])],
            )
        )

    out.extend(["", "## Verified findings", ""])
    if not report["findings"]:
        out.append("None. No vulnerability was exploit-verified.")
    for item in report["findings"]:
        out.extend([f"### {md_inline(item['id'])}: {md_inline(item['title'])}", ""])
        out.extend(_md_fields(item))
        out.extend(["", "#### Description", "", md_text(item["description"]) or "None given."])
        out.extend(["", "#### Reproduction", ""])
        if not item["reproduction"]:
            out.append("No assertions are recorded.")
        for step in item["reproduction"]:
            out.append(md_inline(step["text"]))
            out.append("")
            if step["curl"]:
                out.extend([md_code(step["curl"]), ""])
        out.extend(["", "#### Proof", ""])
        if not item["proof"]:
            out.append("No replay capture is recorded.")
        for proof in item["proof"]:
            out.extend([f"- {md_inline(proof['status_line'])}", ""])
            for name, value in proof["response_headers"].items():
                out.append(f"  - {md_inline(name)}: {md_inline(value)}")
            if proof["excerpt"]:
                more = " (truncated)" if proof["truncated"] else ""
                out.extend(["", f"First {EXCERPT_CHARS} characters of the response{more}:", ""])
                out.extend([md_code(proof["excerpt"]), ""])
        out.extend(["", "#### Remediation", "", md_text(item["remediation"]) or "None given."])
        out.extend(["", *_md_grade(item["grade"]), ""])

    out.extend(["", "## Not proven by replay", ""])
    if not report["unverified"]:
        out.append("None.")
    for item in report["unverified"]:
        out.extend([f"### {md_inline(item['id'])}: {md_inline(item['title'])}", ""])
        out.extend([f"*{md_inline(item['label'])}*", ""])
        out.extend(_md_fields(item))
        out.extend(["", md_text(item["description"]) or "No description given.", ""])
        out.append("Verifier's reasons:")
        out.append("")
        out.extend(f"- {md_inline(reason)}" for reason in item["verifier_reasons"] or ["none"])
        out.extend(["", *_md_grade(item["grade"]), ""])

    out.extend(["", "## Leads (not tested)", ""])
    if report["leads"]:
        out.extend(
            _md_table(
                ["ID", "Title", "Claimed severity", "Class", "Endpoint", "Source", "Assertions"],
                [
                    [
                        md_inline(lead["id"]),
                        md_inline(lead["title"]),
                        md_inline(lead["severity"]),
                        md_inline(lead["class"]),
                        md_inline(f"{lead['method']} {lead['endpoint']}"),
                        md_inline(lead["source"]),
                        str(lead["assertions"]),
                    ]
                    for lead in report["leads"]
                ],
            )
        )
    else:
        out.append("None.")
    out.extend(["", "## Discarded", ""])
    out.append(
        f"{summary['discarded']} claim(s) were discarded by the verifier and are not listed."
    )
    return "\n".join(out).rstrip("\n") + "\n"


# ── HTML ────────────────────────────────────────────────────────────


def _h(value: Any) -> str:
    return html.escape(_printable(_s(value)), quote=True)


def _h_text(value: Any) -> str:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", _s(value)) if p.strip()]
    return "".join(f"<p>{_h(p)}</p>" for p in paragraphs)


_CSS = """
:root{--bg:#ffffff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--card:#f6f8fa;
--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8d96a0;
--line:#30363d;--card:#161b22;--ok:#3fb950;--warn:#d29922;--bad:#f85149}}
body{margin:0 auto;max-width:960px;padding:24px 16px;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
h1,h2,h3,h4{line-height:1.25}h2{border-bottom:1px solid var(--line);padding-bottom:4px}
section.item{border:1px solid var(--line);border-radius:6px;padding:12px 16px;margin:16px 0;
background:var(--card)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px}dt{color:var(--muted)}
dd{margin:0;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--line);border-radius:6px;
padding:8px;background:var(--bg);font:13px/1.4 ui-monospace,monospace}
table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid var(--line);
padding:4px 8px;text-align:left;overflow-wrap:anywhere}
.label{color:var(--warn);font-style:italic}.muted{color:var(--muted)}
""".strip()


def _h_table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_h(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{_h(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _h_fields(item: dict[str, Any]) -> str:
    pairs = [
        ("ID", item["id"]),
        ("Severity", item["severity"]),
        ("CWE", item["cwe"] or "none given"),
        ("Class", item["class"]),
        ("Endpoint", item["endpoint"]),
        ("Method", item["method"]),
        ("Parameter", item["parameter"] or "none"),
        ("Source", item["source"]),
    ]
    return "<dl>" + "".join(f"<dt>{_h(k)}</dt><dd>{_h(v)}</dd>" for k, v in pairs) + "</dl>"


def _h_grade(grade: dict[str, Any]) -> str:
    reasons = "".join(f"<li>{_h(reason)}</li>" for reason in grade["reasons"])
    return f"<p><strong>Grade:</strong> {_h(grade['decision'] or 'not graded')}</p>" + (
        f"<ul>{reasons}</ul>" if reasons else ""
    )


def to_html(report: Report) -> str:
    """One self-contained HTML file: inline CSS, no script, no external resource."""
    summary = report["summary"]
    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Security report: {_h(report['engagement'])}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>Security report: {_h(report['engagement'])}</h1>",
        f'<p class="muted">Generated {_h(report["generated_at"])}. '
        + (
            "Testing for this engagement is recorded as complete."
            if summary["complete"]
            else "Testing for this engagement is <strong>not</strong> recorded as complete."
        )
        + "</p>",
        "<h2>Summary</h2>",
        (
            f"<p>{summary['verified']} exploit-verified finding(s).</p>"
            if summary["verified"]
            else "<p>Nothing was verified: no claim was re-proved by the verifier.</p>"
        ),
        _h_table(
            ["Severity", "Verified"],
            [[sev, str(n)] for sev, n in summary["verified_by_severity"].items()],
        ),
        _h_table(
            ["Not proven or not reported", "Count"],
            [
                ["source-verified (not replayed)", str(summary["source_verified"])],
                ["inconclusive", str(summary["inconclusive"])],
                ["leads (candidates)", str(summary["candidates"])],
                ["discarded", str(summary["discarded"])],
            ],
        ),
        "<h2>Method</h2>",
        _h_text(report["method"]),
        "<h2>Scope</h2>",
    ]
    if report["scope"]:
        parts.append("<ul>" + "".join(f"<li>{_h(e)}</li>" for e in report["scope"]) + "</ul>")
    else:
        parts.append("<p>No scope was given to this report.</p>")
    if report["recon_summary"]:
        parts.append("<h2>Recon summary</h2>")
        parts.append(
            _h_table(["Item", "Value"], [[k, v] for k, v in _recon_rows(report["recon_summary"])])
        )

    parts.append("<h2>Verified findings</h2>")
    if not report["findings"]:
        parts.append("<p>None. No vulnerability was exploit-verified.</p>")
    for item in report["findings"]:
        parts.append('<section class="item">')
        parts.append(f"<h3>{_h(item['id'])}: {_h(item['title'])}</h3>")
        parts.append(_h_fields(item))
        parts.append(
            "<h4>Description</h4>" + (_h_text(item["description"]) or "<p>None given.</p>")
        )
        parts.append("<h4>Reproduction</h4>")
        if not item["reproduction"]:
            parts.append("<p>No assertions are recorded.</p>")
        for step in item["reproduction"]:
            parts.append(f"<p>{_h(step['text'])}</p>")
            if step["curl"]:
                parts.append(f"<pre>{_h(step['curl'])}</pre>")
        parts.append("<h4>Proof</h4>")
        if not item["proof"]:
            parts.append("<p>No replay capture is recorded.</p>")
        for proof in item["proof"]:
            parts.append(f"<p>{_h(proof['status_line'])}</p>")
            if proof["response_headers"]:
                parts.append(
                    _h_table(
                        ["Header", "Value"], list(map(list, proof["response_headers"].items()))
                    )
                )
            if proof["excerpt"]:
                more = " (truncated)" if proof["truncated"] else ""
                parts.append(
                    f'<p class="muted">First {EXCERPT_CHARS} characters of the response{more}:</p>'
                )
                parts.append(f"<pre>{_h(proof['excerpt'])}</pre>")
        parts.append(
            "<h4>Remediation</h4>" + (_h_text(item["remediation"]) or "<p>None given.</p>")
        )
        parts.append(_h_grade(item["grade"]))
        parts.append("</section>")

    parts.append("<h2>Not proven by replay</h2>")
    if not report["unverified"]:
        parts.append("<p>None.</p>")
    for item in report["unverified"]:
        parts.append('<section class="item">')
        parts.append(f"<h3>{_h(item['id'])}: {_h(item['title'])}</h3>")
        parts.append(f'<p class="label">{_h(item["label"])}</p>')
        parts.append(_h_fields(item))
        parts.append(_h_text(item["description"]) or "<p>No description given.</p>")
        reasons = item["verifier_reasons"] or ["none"]
        parts.append(
            "<p>Verifier's reasons:</p><ul>"
            + "".join(f"<li>{_h(r)}</li>" for r in reasons)
            + "</ul>"
        )
        parts.append(_h_grade(item["grade"]))
        parts.append("</section>")

    parts.append("<h2>Leads (not tested)</h2>")
    if report["leads"]:
        parts.append(
            _h_table(
                ["ID", "Title", "Claimed severity", "Class", "Endpoint", "Source", "Assertions"],
                [
                    [
                        lead["id"],
                        lead["title"],
                        lead["severity"],
                        lead["class"],
                        f"{lead['method']} {lead['endpoint']}",
                        lead["source"],
                        str(lead["assertions"]),
                    ]
                    for lead in report["leads"]
                ],
            )
        )
    else:
        parts.append("<p>None.</p>")
    parts.append("<h2>Discarded</h2>")
    parts.append(
        f"<p>{summary['discarded']} claim(s) were discarded by the verifier and are not listed.</p>"
    )
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


__all__ = [
    "EXCERPT_CHARS",
    "LABELS",
    "METHOD",
    "REPORT_FORMAT",
    "Report",
    "build",
    "md_code",
    "md_inline",
    "md_text",
    "to_html",
    "to_json",
    "to_markdown",
]
