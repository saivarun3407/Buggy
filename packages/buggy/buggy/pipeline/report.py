"""Deterministic recon report: what the pipeline found, with no LLM involved.

``render_report`` turns recon records into Markdown a person can act on:
known issues by severity, what was *not* checked, live services, APIs, and a
short list of the places most worth testing next. ``rank_candidates`` is the
same prioritisation as data, for the agents.

Everything here is derived from stored records. Nothing is inferred beyond
simple, stated rules (a path parameter that looks like an identifier is an
access-control candidate; a parameter named ``url`` is an SSRF candidate).
"""

from __future__ import annotations

import re
import time
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")

#: Advice per issue family, keyed by a substring of the nuclei template id.
#: Only general, well-established fixes; the finding text is the scanner's.
REMEDIATION_HINTS: tuple[tuple[str, str], ...] = (
    ("missing-security-headers", "Set the missing response header at the edge or in the app."),
    ("cookies-without", "Set the Secure, HttpOnly and SameSite attributes on session cookies."),
    ("samesite", "Set SameSite=Lax or Strict on session cookies."),
    ("swagger", "Do not publish API documentation on production hosts, or require authentication."),
    ("graphql-field-suggestion", "Disable field suggestions in production error messages."),
    (
        "graphql-alias-batching",
        "Limit aliases and batch size per request; apply rate limits per operation.",
    ),
    ("graphql-array-batching", "Disable or cap array batching; apply rate limits per operation."),
    ("graphql-get-method", "Accept GraphQL operations over POST only, with a CSRF defence."),
    ("prometheus-metrics", "Restrict the metrics endpoint to the monitoring network."),
    ("missing-sri", "Add Subresource Integrity attributes to third-party scripts and styles."),
    ("cors", "Return Access-Control-Allow-Origin only for an allow-list of trusted origins."),
)

#: Candidates no deterministic probe covers; the agent tests them with http_send.
MANUAL = "http_send"

#: Coverage stamps in pipeline order, with what each one checks.
COVERAGE_STAGE_LABELS: tuple[tuple[str, str], ...] = (
    ("enumerate", "subdomain enumeration"),
    ("dns", "DNS resolution"),
    ("port", "port scan"),
    ("live", "live-service probe"),
    ("fingerprint", "technology, TLS and header fingerprints"),
    ("urls", "URL and endpoint discovery"),
    ("apispec", "API specification discovery"),
    ("issues", "known-issue and secret scanning"),
)
MAX_GAPS_PER_STAGE = 50

#: An identifier that follows a named collection: /orders/123, /users/{userId}.
#: A bare number such as "/10" is not an object reference.
_ID_SEGMENT = re.compile(
    r"/[a-z][\w-]*/(\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|\{[^}/]*\}|:[a-z_]+)(?=/|$|\?)",
    re.IGNORECASE,
)
_URL_PARAM = re.compile(
    r"\b(url|uri|callback|webhook|redirect|next|dest|image_?url|fetch|proxy)\b", re.IGNORECASE
)
_AUTH_PATH = re.compile(
    r"/(login|signin|logout|register|signup|reset|forgot|token|oauth|sso|session|mfa|2fa)\b",
    re.IGNORECASE,
)
_ADMIN_PATH = re.compile(
    r"/(admin|internal|manage|debug|actuator|config|backup|private)\b", re.IGNORECASE
)


def _attrs(record: dict[str, Any]) -> dict[str, Any]:
    attrs = record.get("attrs")
    return attrs if isinstance(attrs, dict) else {}


def _severity(record: dict[str, Any]) -> str:
    value = str(_attrs(record).get("severity") or "unknown").lower()
    return value if value in SEVERITY_ORDER else "unknown"


def remediation_for(template_id: str) -> str:
    lowered = template_id.lower()
    for needle, advice in REMEDIATION_HINTS:
        if needle in lowered:
            return advice
    return ""


def group_issues(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Scanner results grouped by template, most severe first."""
    grouped: dict[str, dict[str, Any]] = {}
    for record in vulnerabilities:
        attrs = _attrs(record)
        template = str(attrs.get("template_id") or str(record.get("value", "")).split(" ")[0])
        entry = grouped.setdefault(
            template,
            {
                "template_id": template,
                "name": str(attrs.get("name") or template),
                "severity": _severity(record),
                "description": str(attrs.get("description") or "").strip(),
                "references": [str(r) for r in attrs.get("reference") or []][:3],
                "cwe": [str(c).upper() for c in attrs.get("cwe") or []],
                "locations": [],
                "record_ids": [],
                "remediation": remediation_for(template),
            },
        )
        location = str(attrs.get("matched_at") or record.get("value") or "")
        if location and location not in entry["locations"]:
            entry["locations"].append(location)
        if record.get("id"):
            entry["record_ids"].append(str(record["id"]))
    return sorted(
        grouped.values(),
        key=lambda e: (SEVERITY_ORDER.index(e["severity"]), e["name"].lower()),
    )


def rank_candidates(
    records: dict[str, list[dict[str, Any]]], *, limit: int = 40
) -> list[dict[str, str]]:
    """Places worth testing first, each with the reason and the probe that fits."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, where: str, why: str, probe: str) -> None:
        key = (kind, where)
        if where and key not in seen and len(out) < limit:
            seen.add(key)
            out.append({"class": kind, "where": where, "why": why, "probe": probe})

    for record in records.get("graphql", []):
        attrs = _attrs(record)
        why = "GraphQL endpoint"
        if attrs.get("introspection_enabled"):
            why += " with introspection enabled"
        if attrs.get("mutations"):
            why += f", {len(attrs['mutations'])} mutation(s)"
        add("graphql", str(record.get("value")), why, "graphql_checks")

    for record in records.get("api_operation", []):
        attrs = _attrs(record)
        url = str(attrs.get("url") or record.get("value") or "")
        method = str(attrs.get("method") or "").upper()
        label = f"{method} {url}".strip()
        params = " ".join(
            str(p.get("name") if isinstance(p, dict) else p) for p in attrs.get("parameters") or []
        )
        if _ID_SEGMENT.search(url) or re.search(r"\bid\b", params, re.IGNORECASE):
            add("access_control", label, "object identifier in the path or parameters", "idor")
        if _URL_PARAM.search(params):
            add("ssrf", label, "parameter that takes a URL", "ssrf_canary")
        if method in ("POST", "PUT", "PATCH") and attrs.get("request_body_types"):
            add(
                "api",
                label,
                "accepts a JSON body: check for fields the client should not set",
                "mass_assignment",
            )
        if attrs.get("auth_required"):
            add(
                "auth_session",
                label,
                "requires a token: check signature and expiry handling",
                "jwt_alg_none",
            )

    for kind in ("endpoint", "url"):
        for record in records.get(kind, []):
            url = str(record.get("value") or "")
            path = url.split("?", 1)[0]
            query = url.split("?", 1)[1] if "?" in url else ""
            if _ID_SEGMENT.search(path):
                add("access_control", url, "object identifier in the path", "idor")
            if query and _URL_PARAM.search(query):
                add("ssrf", url, "query parameter that takes a URL", "ssrf_canary")
            if _AUTH_PATH.search(path):
                add(
                    "auth_session",
                    url,
                    "authentication or session endpoint: reset, MFA and session handling",
                    MANUAL,
                )
            if _ADMIN_PATH.search(path):
                add(
                    "access_control",
                    url,
                    "administrative or internal path: request it without and with a low-privilege account",
                    MANUAL,
                )
    order = {"access_control": 0, "auth_session": 1, "ssrf": 2, "api": 3, "graphql": 4}
    return sorted(out, key=lambda c: (order.get(c["class"], 9), c["where"]))


def coverage_overview(summary: dict[str, Any]) -> dict[str, Any]:
    """Coverage as the report needs it, from a ``recon_summary`` result.

    ``recorded`` is false when the store holds no stamp at all (no run yet, or
    a store written before stamps existed): then nothing is known to have been
    checked, which is not the same as nothing being missed.
    """
    raw = summary.get("coverage")
    counts = {
        status: int((raw if isinstance(raw, dict) else {}).get(status) or 0)
        for status in ("complete", "partial", "failed", "skipped")
    }
    gaps = [
        gap
        for gap in summary.get("coverage_gaps") or []
        if isinstance(gap, dict) and gap.get("asset") and gap.get("status") != "complete"
    ]
    gap_total = max(counts["partial"] + counts["failed"] + counts["skipped"], len(gaps))
    listed_assets = len({str(gap["asset"]) for gap in gaps})
    try:
        gap_assets = max(int(summary.get("coverage_gap_assets") or 0), listed_assets)
    except (TypeError, ValueError):
        gap_assets = listed_assets
    return {
        "recorded": sum(counts.values()) > 0 or bool(gaps),
        "counts": counts,
        "gaps": gaps,
        "gap_total": gap_total,
        "gap_assets": gap_assets,
    }


def _not_checked(coverage: dict[str, Any]) -> list[str]:
    """The "Not checked" section: gaps grouped by stage, each with its reason."""
    lines = ["## Not checked", ""]
    if not coverage["recorded"]:
        return lines + [
            "No coverage was recorded for this engagement, so nothing here can be assumed "
            "to have been checked.",
            "",
        ]
    if not coverage["gap_total"]:
        return lines + ["Every stage completed for every asset it was run on.", ""]
    lines += [
        "A stage listed here did not complete for the asset. That it reported nothing "
        "there means the asset was not checked, not that it is clean.",
        "",
    ]
    order = [stage for stage, _label in COVERAGE_STAGE_LABELS]
    labels = dict(COVERAGE_STAGE_LABELS)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for gap in coverage["gaps"]:
        grouped.setdefault(str(gap.get("stage") or "unknown"), []).append(gap)
    for stage in sorted(grouped, key=lambda s: (order.index(s) if s in order else len(order), s)):
        rows = sorted(grouped[stage], key=lambda gap: str(gap["asset"]))
        lines += [f"### {stage}" + (f" — {labels[stage]}" if stage in labels else ""), ""]
        lines += _table(
            ["Asset", "Status", "Reason"],
            [
                [str(gap["asset"]), str(gap.get("status") or ""), str(gap.get("detail") or "")]
                for gap in rows[:MAX_GAPS_PER_STAGE]
            ],
        )
        if len(rows) > MAX_GAPS_PER_STAGE:
            lines += ["", f"…and {len(rows) - MAX_GAPS_PER_STAGE} more in this stage."]
        lines.append("")
    if coverage["gap_total"] > len(coverage["gaps"]):
        lines += [
            f"Showing {len(coverage['gaps'])} of {coverage['gap_total']} gaps; the recon "
            "coverage query lists the rest.",
            "",
        ]
    return lines


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    def cell(text: str) -> str:
        return str(text).replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(cell(c) for c in row) + " |" for row in rows]
    return lines


def render_report(
    engagement: str,
    summary: dict[str, Any],
    records: dict[str, list[dict[str, Any]]],
    *,
    scope: list[str] | None = None,
    generated_at: float | None = None,
) -> str:
    """Markdown report of one engagement's recon store."""
    counts = summary.get("records") or {}
    run = summary.get("last_run") or {}
    when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(generated_at or time.time()))
    lines: list[str] = [f"# Recon report — {engagement}", ""]
    lines.append(f"Generated {when} from the recon store. No LLM was involved in this report.")
    lines.append("")
    if scope:
        lines.append("Scope: " + ", ".join(f"`{s}`" for s in scope))
        lines.append("")

    issues = group_issues(records.get("vulnerability", []))
    coverage = coverage_overview(summary)
    by_severity = {s: sum(1 for i in issues if i["severity"] == s) for s in SEVERITY_ORDER}
    lines += ["## Summary", ""]
    duration = ""
    if run.get("started_at") and run.get("finished_at"):
        duration = f"{float(run['finished_at']) - float(run['started_at']):.0f} s"
    lines += _table(
        ["Item", "Count"],
        [
            ["Hosts", str(counts.get("subdomain", 0))],
            ["Live web services", str(counts.get("http_service", 0))],
            ["Open ports", str(counts.get("port", 0))],
            ["URLs and endpoints", str(counts.get("url", 0) + counts.get("endpoint", 0))],
            ["API specifications", str(counts.get("api_spec", 0) + counts.get("graphql", 0))],
            ["API operations", str(counts.get("api_operation", 0))],
            ["Known issues (distinct)", str(len(issues))],
            ["Exposed secrets", str(counts.get("secret", 0))],
            ["Candidates dropped as out of scope", str(run.get("scope_drops", 0))],
            [
                "Assets with incomplete coverage",
                str(coverage["gap_assets"]) if coverage["recorded"] else "not recorded",
            ],
        ],
    )
    lines.append("")
    if run:
        lines.append(
            f"Last run `{run.get('run_id', '?')}`: {run.get('status', '?')}"
            + (f", {duration}" if duration else "")
            + "."
        )
        lines.append("")
    severities = ", ".join(f"{by_severity[s]} {s}" for s in SEVERITY_ORDER if by_severity[s])
    lines.append(f"Known issues by severity: {severities or 'none'}.")
    lines.append("")

    lines += ["## Known issues", ""]
    if coverage["gap_total"]:
        lines += [
            f"This list is not complete: {coverage['gap_assets']} asset(s) were not fully "
            'checked (see "Not checked").',
            "",
        ]
    elif not coverage["recorded"]:
        lines += [
            "This list cannot be taken as complete: no coverage was recorded for this "
            'engagement (see "Not checked").',
            "",
        ]
    if not issues:
        lines += ["None reported by the scanner templates that were run.", ""]
    for issue in issues:
        lines.append(f"### [{issue['severity'].upper()}] {issue['name']}")
        lines.append("")
        if issue["description"]:
            lines.append(issue["description"])
            lines.append("")
        lines.append(
            f"- Template: `{issue['template_id']}`"
            + (f" ({', '.join(issue['cwe'])})" if issue["cwe"] else "")
        )
        shown = issue["locations"][:5]
        more = len(issue["locations"]) - len(shown)
        lines.append(
            "- Where: "
            + ", ".join(f"`{loc}`" for loc in shown)
            + (f" and {more} more" if more > 0 else "")
        )
        if issue["remediation"]:
            lines.append(f"- Fix: {issue['remediation']}")
        if issue["references"]:
            lines.append("- Reference: " + ", ".join(issue["references"]))
        lines.append("")

    secrets = records.get("secret", [])
    if secrets:
        lines += ["## Exposed secrets", ""]
        lines += _table(
            ["Rule", "Where"],
            [
                [
                    str(_attrs(r).get("rule_id") or "secret"),
                    str(_attrs(r).get("url") or r.get("asset") or ""),
                ]
                for r in secrets[:50]
            ],
        )
        lines += [
            "",
            "Values are not printed here. Rotate each one and remove it from the source.",
            "",
        ]

    lines += _not_checked(coverage)

    services = records.get("http_service", [])
    lines += ["## Live services", ""]
    if services:
        tech: dict[str, list[str]] = {}
        for record in records.get("technology", []):
            attrs = _attrs(record)
            name = str(attrs.get("name") or "")
            if name:
                tech.setdefault(str(attrs.get("url") or ""), []).append(
                    name + (f" {attrs['version']}" if attrs.get("version") else "")
                )
        lines += _table(
            ["URL", "Status", "Title", "Technology"],
            [
                [
                    str(r.get("value")),
                    str(_attrs(r).get("status_code") or ""),
                    str(_attrs(r).get("title") or "")[:60],
                    ", ".join(sorted(set(tech.get(str(r.get("value")), []))))[:120],
                ]
                for r in services[:100]
            ],
        )
    else:
        lines.append("No live web service was found on the in-scope hosts.")
    lines.append("")

    specs = records.get("api_spec", []) + records.get("graphql", [])
    if specs:
        lines += ["## APIs", ""]
        rows = []
        for record in specs[:50]:
            attrs = _attrs(record)
            if record.get("type") == "graphql":
                detail = "GraphQL" + (
                    ", introspection enabled" if attrs.get("introspection_enabled") else ""
                )
            else:
                detail = f"{attrs.get('format', 'spec')} — {attrs.get('title', '')} ({attrs.get('operation_count', 0)} operations)"
            rows.append([str(record.get("value")), detail])
        lines += _table(["Location", "What"], rows)
        lines.append("")

    candidates = rank_candidates(records)
    lines += ["## Test next", ""]
    if candidates:
        lines.append(
            "Ranked by the classes that pay most. Each row names the deterministic probe that fits; "
            "a probe needs test accounts you own."
        )
        lines.append("")
        lines += _table(
            ["Class", "Where", "Why", "Probe"],
            [[c["class"], c["where"], c["why"], f"`{c['probe']}`"] for c in candidates],
        )
    else:
        lines.append("Nothing stood out from the recorded surface.")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "SEVERITY_ORDER",
    "coverage_overview",
    "group_issues",
    "rank_candidates",
    "remediation_for",
    "render_report",
]
