"""Turn a program's official scope data into an enforced scope.

Sources, all official:

* the HackerOne Hacker API (``structured_scopes``, ``scope_exclusions``, policy)
* the Bugcrowd API (program brief target groups)
* a HackerOne scope CSV the operator downloaded from the program page
  (``--csv``), for accounts without API access

Nothing here guesses. An asset type that is not a network target is listed as
non-network and never enters the scope; an over-broad pattern is rejected; the
result is always ``enforce`` mode with approval required for state-changing
requests and for report release. Only an operator can run this: it writes the
operator-controlled root, which no agent-facing container can write.
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import io
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from buggy.program.record import (
    BASELINE_BANNED_TECHNIQUES,
    DOS_COMMAND_PATTERNS,
    SOCIAL_ENGINEERING_COMMAND_PATTERNS,
)

PLATFORMS = ("hackerone", "bugcrowd")

#: Requests per second when the program states no limit. Deliberately low.
DEFAULT_RPS = 5
#: Hard ceiling an operator flag cannot exceed on a real program.
MAX_RPS = 20

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOST_RE = re.compile(rf"^(?:\*{{1,2}}\.)?(?:{_LABEL}\.)+[a-z]{{2,63}}$")
#: Registrable suffixes that must never be wildcarded as a whole.
_PUBLIC_SUFFIX_LIKE = re.compile(r"^(?:[a-z]{2,63}|(?:co|com|net|org|gov|edu|ac)\.[a-z]{2})$")
#: Smallest network a real program scope may contain (2^(32-16) addresses).
_MIN_V4_PREFIX = 16
#: Address space that is never a bounty target: it names whatever network the
#: stack itself happens to sit on, not the program's.
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
        "::/127",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


class ScopeImportError(Exception):
    """The program's scope could not be imported; the message says why."""


@dataclass(slots=True)
class OfficialScope:
    """A program's scope, normalised from one official source."""

    platform: str
    handle: str
    name: str = ""
    url: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    non_network_assets: list[str] = field(default_factory=list)
    excluded_classes: list[str] = field(default_factory=list)
    severity_caps: dict[str, str] = field(default_factory=dict)
    policy_excerpt: str = ""
    no_automated_tools: bool = False
    policy_delay_ms: int = 0
    policy_notes: list[str] = field(default_factory=list)
    source: str = ""
    source_sha256: str = ""


def _clean_handle(handle: str) -> str:
    value = (handle or "").strip().strip("/").lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", value):
        raise ScopeImportError(f"{handle!r} is not a valid program handle")
    return value


def from_intake_payload(payload: dict[str, Any], *, source: str) -> OfficialScope:
    """Normalise the dict returned by the official-API fetchers in ``bounty_intake``."""
    if payload.get("error"):
        detail = payload.get("how_to") or payload.get("detail") or payload.get("message") or ""
        raise ScopeImportError(f"{payload['error']}: {detail}".rstrip(": "))
    rules = payload.get("suggested_rules") or {}
    return OfficialScope(
        platform=str(payload.get("platform") or ""),
        handle=str(payload.get("program_handle") or ""),
        name=str(payload.get("program_name") or ""),
        url=str(payload.get("program_url") or ""),
        in_scope=[str(x) for x in payload.get("in_scope") or []],
        out_of_scope=[str(x) for x in payload.get("out_of_scope") or []],
        non_network_assets=[str(x) for x in payload.get("non_network_assets") or []],
        excluded_classes=[str(x) for x in payload.get("excluded_classes") or []],
        severity_caps={str(k): str(v) for k, v in (payload.get("severity_caps") or {}).items()},
        policy_excerpt=str(payload.get("policy_excerpt") or ""),
        no_automated_tools=bool(rules.get("no_automated_tools", False)),
        policy_delay_ms=int(rules.get("min_inter_request_delay_ms") or 0),
        policy_notes=[str(x) for x in rules.get("notes") or []],
        source=source,
    )


def fetch_official(platform: str, handle: str) -> OfficialScope:
    """Fetch the scope from the platform's API with the operator's credentials."""
    from buggy.tools.research import bounty_intake as intake  # noqa: PLC0415 - needs httpx

    slug = _clean_handle(handle)
    if platform == "hackerone":
        creds = intake._creds(intake._H1_USER_ENV, intake._H1_TOKEN_ENV)
        if creds is None:
            raise ScopeImportError(
                f"set {intake._H1_USER_ENV} and {intake._H1_TOKEN_ENV} (HackerOne API token), "
                "or download the program's scope CSV and pass it with --csv"
            )
        payload = intake._h1_scope(creds, slug)
        source = f"{intake.H1_API_BASE}/programs/{slug}/structured_scopes"
    elif platform == "bugcrowd":
        creds = intake._creds(intake._BC_USER_ENV, intake._BC_TOKEN_ENV)
        if creds is None:
            raise ScopeImportError(
                f"set {intake._BC_USER_ENV} and {intake._BC_TOKEN_ENV} (Bugcrowd API token)"
            )
        payload = intake._bc_scope(creds, slug)
        source = f"{intake.BUGCROWD_API_BASE}/programs/{slug}"
    else:
        raise ScopeImportError(f"unknown platform {platform!r}; expected one of {PLATFORMS}")
    return from_intake_payload(payload, source=source)


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"true", "yes", "1", "y"}


def from_hackerone_csv(text: str, handle: str) -> OfficialScope:
    """Parse the scope CSV a HackerOne program page offers for download.

    Columns used: ``identifier``, ``asset_type``, ``eligible_for_submission``,
    ``max_severity``. A row not eligible for submission is out of scope.
    """
    from buggy.tools.research import bounty_intake as intake  # noqa: PLC0415

    slug = _clean_handle(handle)
    reader = csv.DictReader(io.StringIO(text))
    fields = {name.strip().lower() for name in reader.fieldnames or []}
    missing = {"identifier", "asset_type", "eligible_for_submission"} - fields
    if missing:
        raise ScopeImportError(
            f"not a HackerOne scope CSV: missing column(s) {sorted(missing)}. Download it from "
            "the program's scope tab."
        )
    scopes: list[dict[str, Any]] = []
    for row in reader:
        clean = {str(k).strip().lower(): (v or "").strip() for k, v in row.items() if k}
        if not clean.get("identifier"):
            continue
        scopes.append(
            {
                "attributes": {
                    "asset_identifier": clean["identifier"],
                    "asset_type": clean.get("asset_type", ""),
                    "eligible_for_submission": _truthy(clean.get("eligible_for_submission")),
                    "max_severity": clean.get("max_severity", ""),
                }
            }
        )
    if not scopes:
        raise ScopeImportError("the scope CSV has no rows")
    in_scope, out_of_scope, non_network, caps = intake._partition_h1_scopes(scopes)
    return OfficialScope(
        platform="hackerone",
        handle=slug,
        name=slug,
        url=f"https://hackerone.com/{slug}",
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        non_network_assets=non_network,
        severity_caps=caps,
        source="hackerone scope CSV (operator download)",
        source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )


def classify_asset(asset: str) -> tuple[str | None, str]:
    """Return ``(scope_entry, "")`` for an enforceable asset, else ``(None, reason)``.

    A program's ``*.example.com`` means every subdomain at any depth, so it is
    written as the any-depth form ``**.example.com``. The apex is in scope
    only when the program lists it separately.
    """
    value = (asset or "").strip().lower().rstrip(".")
    if not value:
        return None, "empty"
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        pass
    else:
        if network.version == 4 and network.prefixlen < _MIN_V4_PREFIX:
            return None, f"network larger than /{_MIN_V4_PREFIX}"
        if any(network.version == net.version and network.overlaps(net) for net in _INTERNAL_NETS):
            return None, "private, loopback or link-local address"
        return str(network) if "/" in value else str(network.network_address), ""
    prefix = "**." if value.startswith("**.") else "*." if value.startswith("*.") else ""
    base = value[len(prefix) :]
    if "*" in base:
        return None, "wildcard is not a single leading label"
    if prefix and _PUBLIC_SUFFIX_LIKE.match(base):
        return None, "wildcard over a public suffix"
    if not _HOST_RE.match(value):
        return None, "not a hostname, wildcard or network"
    return (f"**.{base}" if prefix else value), ""


def build_documents(
    scope: OfficialScope,
    *,
    engagement: str,
    rps: int | None = None,
    port_scan: bool = False,
    imported_by: str = "",
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, str]]]:
    """Return ``(roe, program, rejected)`` for the operator to review and install.

    ``rejected`` lists assets from the official data that were *not* put in
    scope and why. The operator sees it before anything is written.
    """
    in_scope: list[str] = []
    rejected: list[dict[str, str]] = []
    for asset in scope.in_scope:
        entry, reason = classify_asset(asset)
        if entry is None:
            rejected.append({"asset": asset, "reason": reason})
        elif entry not in in_scope:
            in_scope.append(entry)
    out_of_scope: list[str] = []
    for asset in scope.out_of_scope:
        entry, _reason = classify_asset(asset)
        # An exclusion we cannot parse is kept verbatim: dropping it could widen the scope.
        value = entry or asset.strip().lower()
        if value and value not in out_of_scope:
            out_of_scope.append(value)
    if not in_scope:
        raise ScopeImportError(
            "the program's official scope contains no enforceable network asset "
            f"({len(scope.in_scope)} listed, {len(rejected)} rejected)"
        )

    requested = DEFAULT_RPS if rps is None else int(rps)
    if requested < 1 or requested > MAX_RPS:
        raise ScopeImportError(f"--rps must be between 1 and {MAX_RPS}")
    delay_ms = max(scope.policy_delay_ms, 1000 // requested)
    effective_rps = max(1, 1000 // delay_ms)

    forbidden = [*DOS_COMMAND_PATTERNS, *SOCIAL_ENGINEERING_COMMAND_PATTERNS]
    if scope.no_automated_tools:
        from buggy.tools.research.bounty_intake import SCANNER_COMMAND_PATTERNS  # noqa: PLC0415

        forbidden.extend(SCANNER_COMMAND_PATTERNS)

    banned = [dict(entry) for entry in BASELINE_BANNED_TECHNIQUES]
    if scope.no_automated_tools:
        banned.append(
            {
                "id": "automated_scanning",
                "rule": "The program forbids automated scanning: the pipeline runs passive "
                "sources only and scanner commands are refused.",
            }
        )
    for name in scope.excluded_classes:
        banned.append({"id": "excluded_class", "rule": f"Not accepted by the program: {name}"})

    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    program_ref = {"platform": scope.platform, "handle": scope.handle, "url": scope.url}
    roe: dict[str, Any] = {
        "version": 1,
        "engagement": engagement,
        "program": program_ref,
        "machine_enforcement": {
            "mode": "enforce",
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "forbidden_command_patterns": forbidden,
            "min_inter_request_delay_ms": delay_ms,
            "max_concurrent_connections": min(5, effective_rps),
            # State-changing requests need approval, and only the evidence
            # gateway can hold one. The agent's shell gets no route to the
            # target at all, so nothing can be sent around that hold.
            "sandbox_egress": "blocked",
        },
        "pipeline": {
            "rate_limit_rps": effective_rps,
            "concurrency": min(5, effective_rps),
            "passive_only": scope.no_automated_tools,
            "port_scan": bool(port_scan) and not scope.no_automated_tools,
            "nuclei_severities": ["medium", "high", "critical"],
        },
        "approvals": {"state_changing": "required", "report_submission": "required"},
        "network": {"allow_private_targets": False},
    }
    program: dict[str, Any] = {
        "schema": 1,
        **program_ref,
        "name": scope.name,
        "engagement": engagement,
        "imported_at": now,
        "imported_by": imported_by,
        "source": scope.source,
        "source_sha256": scope.source_sha256,
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "rejected_assets": rejected,
        "non_network_assets": scope.non_network_assets,
        "excluded_classes": scope.excluded_classes,
        "severity_caps": scope.severity_caps,
        "rate_limit": {
            "requests_per_second": effective_rps,
            "min_delay_ms": delay_ms,
            "basis": "program policy" if scope.policy_delay_ms >= 1000 // requested else "default",
        },
        "banned_techniques": banned,
        "policy_excerpt": scope.policy_excerpt,
        "policy_notes": scope.policy_notes,
        "requirements": {
            "mode": "enforce",
            "sandbox_network": "blocked: targets are reached only through the evidence "
            "gateway, the scoped browser and the pipeline",
            "state_changing_requests": "operator approval per request",
            "report_submission": "operator approval per report",
            "finding": "captured in-scope request that verifies, plus a remediation",
        },
    }
    return roe, program, rejected


__all__ = [
    "DEFAULT_RPS",
    "MAX_RPS",
    "PLATFORMS",
    "ScopeImportError",
    "OfficialScope",
    "build_documents",
    "classify_asset",
    "fetch_official",
    "from_hackerone_csv",
    "from_intake_payload",
]
