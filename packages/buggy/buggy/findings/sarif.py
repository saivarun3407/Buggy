"""SARIF 2.1.0 from a findings report, for code scanning and CI gates.

:func:`to_sarif` turns the dict :func:`buggy.findings.report.build` returns
(or the same dict read back from its JSON) into one SARIF log with one run.

What becomes a result is decided by the report, not here: the report's
``findings`` section holds only ``exploit_verified`` items, and each of them
becomes one result. An item in that section whose ``status`` is not
``exploit_verified`` (a hand-edited or doctored file) is skipped and counted.
The report's ``unverified`` and ``leads`` sections and its discarded count are
never results; they appear only as counts in the run's ``properties``.

Every finding field was written by an agent or taken from a target, so:

* message text is plain text with control characters removed, whitespace
  collapsed, SARIF placeholders (``{`` ``}``) doubled and embedded-link
  brackets (``[`` ``]``) backslash-escaped, so no field can become a link or a
  placeholder;
* a location URI is rebuilt from a parsed, validated ``http``/``https`` URL
  (lower-case host of letters, digits, dots and hyphens, or an IP literal; no
  credentials; every character outside the RFC 3986 path set percent-encoded;
  no query or fragment). An endpoint that does not pass is replaced by a fixed
  relative URI derived from the finding id, never by the raw text;
* rule ids come from the fixed class list, help URIs from integers only.

Nothing here reads the clock, the environment or a file; the same report and
``tool_version`` give the same document.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from buggy.findings.model import CLASSES, SEVERITIES, Status

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
DRIVER_NAME = "Buggy"
DRIVER_INFORMATION_URI = "https://github.com/saivarun3407/buggy"
RULE_PREFIX = "buggy/"
#: The rule a finding of a class outside :data:`CLASSES` is filed under.
UNCLASSIFIED = "unclassified"

#: ``level`` per severity. A verified finding of a severity the model does not
#: know is an ``error``: a gate does not pass on a finding it cannot rank.
LEVELS: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
UNKNOWN_LEVEL = "error"
#: GitHub code scanning's ``security-severity`` (0.0 to 10.0) per severity.
SECURITY_SEVERITY: dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 0.0,
}

#: One representative CWE per class, for the rule's ``helpUri``. A result
#: carries its own finding's CWE in its properties and tags.
CLASS_CWE: dict[str, int] = {
    "auth_session": 287,
    "access_control": 284,
    "ssrf": 918,
    "business_logic": 840,
    "api": 285,
    "graphql": 200,
    "injection": 74,
    "xss": 79,
    "file_handling": 22,
    "csrf": 352,
    "open_redirect": 601,
    "crypto": 327,
    "misconfiguration": 16,
    "info_exposure": 200,
}
CLASS_TITLES: dict[str, str] = {
    "auth_session": "Authentication or session management weakness",
    "access_control": "Broken access control",
    "ssrf": "Server-side request forgery",
    "business_logic": "Business logic flaw",
    "api": "API security weakness",
    "graphql": "GraphQL security weakness",
    "injection": "Injection",
    "xss": "Cross-site scripting",
    "file_handling": "Unsafe file handling",
    "csrf": "Cross-site request forgery",
    "open_redirect": "Open redirect",
    "crypto": "Cryptographic weakness",
    "misconfiguration": "Security misconfiguration",
    "info_exposure": "Information exposure",
    UNCLASSIFIED: "Verified finding of an unrecognised class",
}

MAX_MESSAGE = 1000
_CWE = re.compile(r"^CWE-(\d{1,7})$")
_FINDING_ID = re.compile(r"^F-[0-9a-f]{12}$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
#: RFC 3986 ``pchar`` plus ``/``, without ``%`` (handled separately).
_PATH_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@/"
)
_HEX = frozenset("0123456789abcdefABCDEF")
_AUTOMATION_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


# ── text ────────────────────────────────────────────────────────────


def _s(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def plain_text(value: Any, limit: int = MAX_MESSAGE) -> str:
    """``value`` as one line of SARIF plain message text that shows literally.

    Control and other non-printable characters are dropped, whitespace
    collapses to single spaces, ``{``/``}`` are doubled (SARIF placeholders)
    and ``\\``, ``[``, ``]`` are backslash-escaped (SARIF embedded links).
    """
    text = "".join(ch if ch.isprintable() else " " for ch in _s(value))
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    out: list[str] = []
    for ch in text:
        if ch in "{}":
            out.append(ch * 2)
        elif ch in "[]\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


# ── URIs ────────────────────────────────────────────────────────────


def _host(hostname: str) -> str | None:
    """The host as it may appear in a URI, or ``None`` when it is not a plain host."""
    if not hostname:
        return None
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if getattr(address, "scope_id", None):
            return None
        return f"[{address.compressed}]" if address.version == 6 else address.compressed
    if not hostname.isascii() or len(hostname) > 253:
        return None
    labels = hostname.rstrip(".").split(".")
    if not all(_HOST_LABEL.match(label) for label in labels):
        return None
    return hostname.rstrip(".")


def _encode_path(path: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(path):
        ch = path[index]
        if ch in _PATH_SAFE:
            out.append(ch)
        elif ch == "%" and len(path) >= index + 3 and set(path[index + 1 : index + 3]) <= _HEX:
            out.append(path[index : index + 3].upper())
            index += 3
            continue
        else:
            out.extend(f"%{byte:02X}" for byte in ch.encode("utf-8"))
        index += 1
    return "".join(out)


def endpoint_uri(endpoint: Any) -> str | None:
    """A safe absolute URI for ``endpoint``, or ``None`` when it is not an http(s) URL.

    The URI is rebuilt from the parts, never copied: scheme ``http``/``https``,
    a validated host, an optional numeric port, the percent-encoded path. A
    query or fragment is dropped (a finding's endpoint has none).
    """
    raw = _s(endpoint).strip()
    if not raw or len(raw) > 2048 or any(not ch.isprintable() or ch.isspace() for ch in raw):
        return None
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.netloc:
        return None
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return None
    host = _host((parts.hostname or "").lower())
    if host is None:
        return None
    path = _encode_path(parts.path or "/")
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{'' if port is None else f':{port}'}{path}"


def _fallback_uri(finding_id: str) -> str:
    """A relative URI for a finding whose endpoint is not a usable URL."""
    if _FINDING_ID.match(finding_id):
        return f"buggy-finding/{finding_id}"
    digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:12]
    return f"buggy-finding/unknown-{digest}"


def _cwe_number(value: Any) -> int | None:
    match = _CWE.match(_s(value).strip().upper())
    return int(match.group(1)) if match else None


def cwe_uri(number: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{int(number)}.html"


# ── document ────────────────────────────────────────────────────────


def _class_of(item: dict[str, Any]) -> str:
    cls = _s(item.get("class")).strip().lower()
    return cls if cls in CLASSES else UNCLASSIFIED


def _severity_of(item: dict[str, Any]) -> str:
    severity = _s(item.get("severity")).strip().lower()
    return severity if severity in SEVERITIES else ""


def _order(item: dict[str, Any]) -> tuple[int, str]:
    severity = _severity_of(item)
    # Unknown severity sorts first, like the gate treats it: as the worst.
    rank = SEVERITIES.index(severity) if severity else -1
    return rank, _s(item.get("id"))


def _rule(cls: str, severities: list[str]) -> dict[str, Any]:
    title = CLASS_TITLES[cls]
    rule: dict[str, Any] = {
        "id": RULE_PREFIX + cls,
        "name": "".join(part.capitalize() for part in cls.split("_")),
        "shortDescription": {"text": title},
        "fullDescription": {
            "text": f"{title}. Results under this rule were re-proved by Buggy's independent "
            "verifier: every cited request was re-sent and every assertion held."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security"]},
    }
    number = CLASS_CWE.get(cls)
    if number is not None:
        rule["helpUri"] = cwe_uri(number)
        rule["properties"]["tags"].append(f"external/cwe/cwe-{number}")
    known = [SECURITY_SEVERITY[s] for s in severities if s in SECURITY_SEVERITY]
    if known:
        # Code scanning reads the severity of an alert from its rule: the
        # highest of this run's verified results under it.
        rule["properties"]["security-severity"] = f"{max(known):.1f}"
    return rule


def _result(item: dict[str, Any], rule_index: int) -> dict[str, Any]:
    finding_id = _s(item.get("id"))
    severity = _severity_of(item)
    cls = _class_of(item)
    title = plain_text(item.get("title")) or "Untitled finding"
    endpoint = _s(item.get("endpoint"))
    method = _s(item.get("method")).strip().upper()
    uri = endpoint_uri(endpoint)
    where = plain_text(f"{method} {endpoint}".strip(), limit=500)
    message = f"{title} ({where})" if where else title
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri if uri is not None else _fallback_uri(finding_id)}
        },
        "properties": {
            "method": plain_text(method, limit=20),
            "parameter": plain_text(item.get("parameter"), limit=200),
        },
    }
    properties: dict[str, Any] = {
        "severity": severity or "unknown",
        "class": cls,
        "tags": ["security"],
    }
    if severity:
        properties["security-severity"] = f"{SECURITY_SEVERITY[severity]:.1f}"
    number = _cwe_number(item.get("cwe"))
    if number is not None:
        properties["cwe"] = f"CWE-{number}"
        properties["tags"].append(f"external/cwe/cwe-{number}")
    return {
        "ruleId": RULE_PREFIX + cls,
        "ruleIndex": rule_index,
        "level": LEVELS.get(severity, UNKNOWN_LEVEL),
        "message": {"text": message},
        "locations": [location],
        "partialFingerprints": {"findingId": finding_id},
        "properties": properties,
    }


def _count(summary: dict[str, Any], key: str, fallback: int) -> int:
    value = summary.get(key)
    return value if type(value) is int and value >= 0 else fallback


def to_sarif(report: dict[str, Any], *, tool_version: str) -> dict[str, Any]:
    """The report as a SARIF 2.1.0 log (a JSON-serialisable dict).

    Raises :class:`ValueError` when ``report`` is not a report: not a dict, or
    its ``findings``, ``unverified`` or ``leads`` is present and not a list.
    """
    if not isinstance(report, dict):
        raise ValueError("the report must be a JSON object")
    sections: dict[str, list[Any]] = {}
    for key in ("findings", "unverified", "leads"):
        value = report.get(key, [])
        if not isinstance(value, list):
            raise ValueError(f"the report's {key!r} must be a list")
        sections[key] = value
    raw_summary = report.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}

    verified: list[dict[str, Any]] = []
    not_results = 0
    for item in sections["findings"]:
        if isinstance(item, dict) and item.get("status") == Status.EXPLOIT_VERIFIED.value:
            verified.append(item)
        else:
            not_results += 1
    verified.sort(key=_order)

    by_class: dict[str, list[str]] = {}
    for item in verified:
        by_class.setdefault(_class_of(item), []).append(_severity_of(item))
    rule_ids = [*CLASSES, *([UNCLASSIFIED] if UNCLASSIFIED in by_class else [])]
    rules = [_rule(cls, by_class.get(cls, [])) for cls in rule_ids]
    index = {cls: position for position, cls in enumerate(rule_ids)}
    results = [_result(item, index[_class_of(item)]) for item in verified]

    unverified = [item for item in sections["unverified"] if isinstance(item, dict)]
    engagement = _AUTOMATION_SAFE.sub("-", _s(report.get("engagement"))).strip("-.") or "engagement"
    run_properties: dict[str, Any] = {
        "engagement": plain_text(report.get("engagement"), limit=128),
        "generated_at": plain_text(report.get("generated_at"), limit=64),
        "complete": summary.get("complete") is True,
        "verified": len(results),
        "not_proven": {
            "source_verified": _count(
                summary,
                "source_verified",
                sum(i.get("status") == Status.SOURCE_VERIFIED.value for i in unverified),
            ),
            "inconclusive": _count(
                summary,
                "inconclusive",
                sum(i.get("status") == Status.INCONCLUSIVE.value for i in unverified),
            ),
            "candidates": _count(summary, "candidates", len(sections["leads"])),
            "discarded": _count(summary, "discarded", 0),
        },
        "skipped_not_exploit_verified": not_results,
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": DRIVER_NAME,
                        "version": _s(tool_version) or "0",
                        "informationUri": DRIVER_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"buggy/{engagement[:100]}/"},
                "columnKind": "unicodeCodePoints",
                "results": results,
                "properties": run_properties,
            }
        ],
    }


__all__ = [
    "CLASS_CWE",
    "DRIVER_NAME",
    "LEVELS",
    "RULE_PREFIX",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SECURITY_SEVERITY",
    "UNCLASSIFIED",
    "cwe_uri",
    "endpoint_uri",
    "plain_text",
    "to_sarif",
]
