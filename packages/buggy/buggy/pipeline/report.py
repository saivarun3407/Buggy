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
from collections.abc import Callable
from typing import Any

from buggy.pipeline.tools import params

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
    ("web", "web recon: robots, sitemap, security.txt, headers, sign-in pages"),
    ("apispec", "API specification discovery"),
    ("api", "API recon: API roots, OAuth discovery, endpoint profiles"),
    ("issues", "known-issue and secret scanning"),
)
MAX_GAPS_PER_STAGE = 50

#: What a parameter hint (``pipeline/tools/params.py``) suggests testing:
#: hint -> (class, what the parameter is, probe).
_HINT_ROWS: dict[str, tuple[str, str, str]] = {
    "id-like": ("access_control", "object identifier", "idor"),
    "url-like": ("ssrf", "takes a URL", "ssrf_canary"),
    "file-like": ("file_handling", "names a file or path", "path_traversal"),
}
MAX_NAMED_PARAMETERS = 3
#: What a sign-in related page (``auth_surface`` kind) is worth testing for.
_SURFACE_WHY: dict[str, tuple[str, str]] = {
    "password_reset": (
        "auth_session",
        "password reset: token reuse, expiry, host-header poisoning, account enumeration",
    ),
    "mfa": ("auth_session", "multi-factor step: skipping it, reusing or brute-forcing codes"),
    "oauth": ("auth_session", "OAuth / single sign-on: redirect_uri, state and token handling"),
    "login": ("auth_session", "sign-in: account enumeration, lockout and session handling"),
    "signup": ("auth_session", "sign-up: duplicate accounts, role or privilege fields in the form"),
    "admin": (
        "access_control",
        "administrative page: request it without and with a low-privilege account",
    ),
}
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


#: What a recovered-source rule means as a lead: ``(class, what was found, what to do, probe)``.
_RECOVERED_ROWS: dict[str, tuple[str, str, str, str]] = {
    "client_auth": (
        "access_control",
        "role or permission checks in client code",
        "the server must enforce them too: request what they guard with a low-privilege account",
        MANUAL,
    ),
    "secret": (
        "info_exposure",
        "hard-coded secrets",
        "check whether each is live and what it opens (the value is not stored)",
        MANUAL,
    ),
    "dom_sink": (
        "xss",
        "DOM sinks",
        "trace what reaches them from the URL or a message",
        "xss_reflected",
    ),
    "debug_flag": (
        "misconfiguration",
        "debug switches",
        "check whether production honours them",
        MANUAL,
    ),
    "endpoint": (
        "api",
        "routes",
        "test the ones recon did not find with a live request",
        MANUAL,
    ),
}
#: Places named per row of a recovered-source lead, and admin/auth paths queued on their own.
_RECOVERED_NAMED = 6
_RECOVERED_PATHS = 10


def _rank_recovered(
    records: dict[str, list[dict[str, Any]]], add: Callable[[str, str, str, str], None]
) -> None:
    """Leads from the original files a source map gave back (``recovered_source`` js findings).

    One row per map and rule, naming the original file and line of the first
    hits; an administrative or login path named in that source is its own row.
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records.get("js_finding", []):
        attrs = _attrs(record)
        if attrs.get("kind") != "recovered_source" or attrs.get("rule") not in _RECOVERED_ROWS:
            continue
        where = str(attrs.get("map") or attrs.get("found_in") or "")
        groups.setdefault((str(attrs["rule"]), where), []).append(attrs)
    for rule in ("client_auth", "secret", "dom_sink", "debug_flag", "endpoint"):
        for (kind, where), hits in groups.items():
            if kind != rule:
                continue
            vuln_class, what, todo, probe = _RECOVERED_ROWS[rule]
            named = [
                f"{h.get('detail')} ({h.get('file')}:{h.get('line')})"
                for h in hits[:_RECOVERED_NAMED]
            ]
            more = len(hits) - _RECOVERED_NAMED
            add(
                vuln_class,
                where,
                f"{what} in source recovered from the source map: {', '.join(named)}"
                + (f" and {more} more" if more > 0 else "")
                + f"; {todo}",
                probe,
            )
            if rule != "endpoint":
                continue
            paths = 0
            for hit in hits:
                url = str(hit.get("url") or "")
                path = url.split("?", 1)[0]
                if not url or paths >= _RECOVERED_PATHS:
                    continue
                origin = f"named in recovered source {hit.get('file')}:{hit.get('line')}"
                if _ADMIN_PATH.search(path):
                    paths += 1
                    add(
                        "access_control",
                        url,
                        f"administrative path {origin}: request it without and with a "
                        "low-privilege account",
                        MANUAL,
                    )
                elif _AUTH_PATH.search(path):
                    paths += 1
                    add(
                        "auth_session",
                        url,
                        f"authentication path {origin}: reset, MFA and session handling",
                        MANUAL,
                    )


def rank_candidates(
    records: dict[str, list[dict[str, Any]]], *, limit: int = 40
) -> list[dict[str, str]]:
    """Places worth testing first, each with the reason and the probe that fits.

    The access-control, SSRF and file-handling rows come from parameter hints:
    those of the stored ``parameter`` records, and, for a URL, endpoint or API
    operation whose parameters are not among them, the same extraction run on
    that record. No URL is pattern-matched here.
    """
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, where: str, why: str, probe: str) -> None:
        key = (kind, where)
        if where and key not in seen and len(out) < limit:
            seen.add(key)
            out.append({"class": kind, "where": where, "why": why, "probe": probe})

    def add_inputs(where: str, parameters: list[dict[str, Any]]) -> None:
        """One row per hint that the parameters found at ``where`` carry."""
        for hint, (kind, what, probe) in _HINT_ROWS.items():
            names = [
                f"{attrs.get('location')} parameter {attrs.get('name')}"
                for attrs in parameters
                if hint in (attrs.get("hints") or [])
                # A value that is a number (page=2) is not a file name.
                and not (hint == "file-like" and "numeric" in attrs["hints"])
            ]
            if names:
                shown = ", ".join(names[:MAX_NAMED_PARAMETERS])
                more = len(names) - MAX_NAMED_PARAMETERS
                add(
                    kind,
                    where,
                    f"{what}: {shown}" + (f" and {more} more" if more > 0 else ""),
                    probe,
                )

    # API endpoints that answered a GET with no login (``api_profile``).
    for record in records.get("api_profile", []):
        attrs = _attrs(record)
        url = str(attrs.get("url") or "")
        status = attrs.get("status")
        if attrs.get("auth") != "none" or not isinstance(status, int) or not 200 <= status < 300:
            continue
        if "json" not in str(attrs.get("content_type") or ""):
            continue
        sensitive = [str(f) for f in attrs.get("sensitive_fields") or []]
        fields = f" with fields {', '.join(sensitive[:MAX_NAMED_PARAMETERS])}" if sensitive else ""
        if attrs.get("object_id_in_path"):
            add(
                "access_control",
                f"GET {url}",
                f"answers without a login and takes an object id in the path{fields}: "
                "change the id, then try another account",
                "idor",
            )
        elif sensitive:
            # A public list (products, languages) is not a lead; fields like
            # email or password handed to anyone are.
            count = attrs.get("items")
            listing = (
                f"returns {count} records" if isinstance(count, int) and count > 1 else "answers"
            )
            add("info_exposure", f"GET {url}", f"{listing} without a login{fields}", MANUAL)

    for record in records.get("auth_surface", []):
        attrs = _attrs(record)
        why = _SURFACE_WHY.get(str(attrs.get("kind") or ""))
        if why is not None:
            add(why[0], str(record.get("value") or ""), why[1], MANUAL)

    for record in records.get("api_base", []):
        attrs = _attrs(record)
        found = [str(v) for v in attrs.get("versions") or []]
        if len(found) > 1:
            add(
                "api",
                str(record.get("value") or ""),
                f"several API versions are served ({', '.join(found)}): "
                "an older one may lack checks the newer one has",
                MANUAL,
            )

    for record in records.get("graphql", []):
        attrs = _attrs(record)
        why = "GraphQL endpoint"
        if attrs.get("introspection_enabled"):
            why += " with introspection enabled"
        if attrs.get("mutations"):
            why += f", {len(attrs['mutations'])} mutation(s)"
        add("graphql", str(record.get("value")), why, "graphql_checks")

    stored: dict[str, list[dict[str, Any]]] = {}
    covered: set[str] = set()
    for record in records.get("parameter", []):
        attrs = _attrs(record)
        covered.add(str(record.get("value") or ""))
        where = f"{attrs.get('method') or ''} {attrs.get('url') or ''}".strip()
        stored.setdefault(where, []).append(attrs)
    for where, group in stored.items():
        add_inputs(where, group)

    def inputs_of(kind: str, record: dict[str, Any]) -> list[dict[str, Any]]:
        """Parameters of one record that no stored parameter record already names."""
        found = params.extract([{**record, "type": kind}])
        return [parameter.attrs for parameter in found if parameter.value not in covered]

    for record in records.get("api_operation", []):
        attrs = _attrs(record)
        url = str(attrs.get("url") or record.get("value") or "")
        method = str(attrs.get("method") or "").upper()
        label = f"{method} {url}".strip()
        add_inputs(label, inputs_of("api_operation", record))
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

    # DOM sinks the JS analysis found (``js_finding`` records), one row per script.
    sinks: dict[str, list[str]] = {}
    named_sinks = 6
    for record in records.get("js_finding", []):
        attrs = _attrs(record)
        if attrs.get("kind") != "dom_sink":
            continue
        script = str(attrs.get("found_in") or str(record.get("value") or "").rsplit("#", 1)[0])
        sinks.setdefault(script, []).append(f"{attrs.get('sink')} (line {attrs.get('line')})")
    for script, found in sinks.items():
        shown = ", ".join(found[:named_sinks])
        more = len(found) - named_sinks
        add(
            "xss",
            script,
            f"DOM sinks: {shown}" + (f" and {more} more" if more > 0 else ""),
            "xss_reflected",
        )

    _rank_recovered(records, add)

    for kind in ("endpoint", "url"):
        for record in records.get(kind, []):
            url = str(record.get("value") or "")
            path = url.split("?", 1)[0]
            add_inputs(url, inputs_of(kind, record))
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
    # Lower-value rows last, so they never push a stronger lead past the limit.
    for record in records.get("api_profile", []):
        attrs = _attrs(record)
        origin = str(attrs.get("cors_origin") or "")
        if origin in ("*", "null") and attrs.get("cors_credentials"):
            add(
                "misconfiguration",
                f"GET {attrs.get('url')}",
                f"allows cross-origin requests from {origin!r} with credentials",
                "cors",
            )
        if str(attrs.get("auth_scheme") or "").lower() == "bearer":
            add(
                "auth_session",
                f"GET {attrs.get('url')}",
                "asks for a bearer token: check signature and expiry handling",
                "jwt_alg_none",
            )
    for record in records.get("web_finding", []):
        attrs = _attrs(record)
        if attrs.get("kind") == "cookie_flags":
            add(
                "misconfiguration",
                str(attrs.get("url") or ""),
                f"cookie {attrs.get('name')}: {attrs.get('detail')}",
                MANUAL,
            )
    for record in records.get("js_file", []):
        attrs = _attrs(record)
        if attrs.get("kind") == "source_map":
            add(
                "info_exposure",
                str(record.get("value") or ""),
                f"source map published: {attrs.get('sources_count', 0)} original source files",
                MANUAL,
            )
    order = {
        "access_control": 0,
        "auth_session": 1,
        "ssrf": 2,
        "file_handling": 3,
        "api": 4,
        "graphql": 5,
        "xss": 6,
        "info_exposure": 7,
        "misconfiguration": 8,
    }
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


#: Where a value can be put, in the order the inputs section lists them.
_INPUT_PLACES = (
    ("form", "form fields"),
    ("query", "query string"),
    ("body", "JSON / request body"),
    ("path", "path segments (ids)"),
    ("header", "headers"),
    ("cookie", "cookies"),
)


def _inputs_section(records: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Every place a value can be put into the site, by where it goes, from ``parameter`` records."""
    parameters = records.get("parameter", [])
    if not parameters:
        return []
    by_place: dict[str, list[dict[str, Any]]] = {}
    for record in parameters:
        by_place.setdefault(str(_attrs(record).get("location") or "other"), []).append(record)
    lines = ["## Inputs", ""]
    lines.append(
        f"{len(parameters)} place(s) where the site accepts a value. Each is tested class by class."
    )
    lines.append("")
    rows = []
    for place, label in _INPUT_PLACES:
        found = by_place.get(place, [])
        if not found:
            continue
        examples = []
        for record in found[:4]:
            attrs = _attrs(record)
            examples.append(
                f"`{attrs.get('name')}` at {attrs.get('method') or ''} {attrs.get('url') or ''}".strip()
            )
        rows.append([label, str(len(found)), "; ".join(examples)])
    lines += _table(["Where", "Count", "Examples"], rows)
    lines.append("")
    return lines


def _web_section(records: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Sign-in pages, header findings and published files, from the ``web`` stage."""
    surface = records.get("auth_surface", [])
    findings = records.get("web_finding", [])
    if not surface and not findings:
        return []
    lines = ["## Web", ""]
    if surface:
        by_kind: dict[str, list[str]] = {}
        for record in surface:
            by_kind.setdefault(str(_attrs(record).get("kind") or "other"), []).append(
                str(record.get("value") or "")
            )
        lines += _table(
            ["Sign-in related pages", "Count", "Examples"],
            [
                [kind.replace("_", " "), str(len(urls)), ", ".join(f"`{u}`" for u in urls[:3])]
                for kind, urls in sorted(by_kind.items())
            ],
        )
        lines.append("")
    if findings:
        lines += _table(
            ["Where", "What", "Detail"],
            [
                [
                    str(_attrs(r).get("url") or ""),
                    f"{str(_attrs(r).get('kind') or '').replace('_', ' ')} {_attrs(r).get('name') or ''}".strip(),
                    str(_attrs(r).get("detail") or ""),
                ]
                for r in findings[:60]
            ],
        )
        lines += [
            "",
            "Missing headers and version banners are listed for the fix list; most programs "
            "do not accept them as findings on their own.",
            "",
        ]
    return lines


def _api_section(records: dict[str, list[dict[str, Any]]]) -> list[str]:
    """API roots and how each profiled endpoint answered, from the ``api`` stage."""
    bases = records.get("api_base", [])
    profiles = records.get("api_profile", [])
    if not bases and not profiles:
        return []
    lines = ["## API inventory", ""]
    if bases:
        lines += _table(
            ["API root", "Endpoints", "With an object id", "Versions"],
            [
                [
                    str(r.get("value") or ""),
                    str(_attrs(r).get("endpoints", 0)),
                    str(_attrs(r).get("with_object_id", 0)),
                    ", ".join(str(v) for v in _attrs(r).get("versions") or []) or "-",
                ]
                for r in bases[:40]
            ],
        )
        lines.append("")
    if profiles:
        open_count = sum(1 for r in profiles if _attrs(r).get("auth") == "none")
        closed = sum(1 for r in profiles if _attrs(r).get("auth") == "required")
        lines.append(
            f"{len(profiles)} endpoint(s) were requested once without a login: "
            f"{open_count} answered, {closed} asked for credentials."
        )
        lines.append("")
        lines += _table(
            ["Endpoint", "Status", "Login", "Fields worth a look"],
            [
                [
                    str(_attrs(r).get("url") or ""),
                    str(_attrs(r).get("status") or ""),
                    str(_attrs(r).get("auth") or ""),
                    ", ".join(str(f) for f in _attrs(r).get("sensitive_fields") or []) or "-",
                ]
                for r in sorted(profiles, key=lambda r: _attrs(r).get("auth") != "none")[:60]
            ],
        )
        lines.append("")
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
            ["Inputs (places a value can be put)", str(counts.get("parameter", 0))],
            ["API roots", str(counts.get("api_base", 0))],
            ["Sign-in related pages", str(counts.get("auth_surface", 0))],
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

    lines += _inputs_section(records)
    lines += _web_section(records)
    lines += _api_section(records)

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
