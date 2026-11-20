"""Validation of a decoded ``roe.json`` document (pure, no framework imports).

Shared by everything that must agree on what a policy means: the guardrail
middleware, ``buggy-cli scope``, and the deterministic pipeline's scope
filter. A document that fails here is rejected everywhere, so a rule the
matcher could not apply (and would therefore silently never match) cannot
become part of an enforced scope.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from buggy_core.types.roe import (
    MAX_INTER_REQUEST_DELAY_MS,
    EnforcementMode,
    MachineEnforcement,
    ScopeRule,
    _network_scope_pattern,
)
from buggy_core.types.tool_guard import MAX_RULES, compile_rules


class InvalidRoEError(ValueError):
    """An explicit RoE document cannot be read or interpreted safely."""


def _validate_target_entry(field: str, entry: Any) -> None:
    """Reject a scope or destination entry the matcher would otherwise never match."""
    if field == "forbidden_destinations" and not isinstance(entry, str):
        raise InvalidRoEError("RoE forbidden_destinations entries must be strings")
    target = entry.get("target") if isinstance(entry, dict) else entry
    kind = entry.get("type", "auto") if isinstance(entry, dict) else "auto"
    if not isinstance(target, str) or not target.strip():
        raise InvalidRoEError(f"RoE {field} entries require a nonempty target string")
    if kind not in ("auto", "host", "ip", "cidr", "domain-glob"):
        raise InvalidRoEError(f"RoE {field} contains an unsupported target type")
    if target.strip().lower().startswith(("http://", "https://")):
        rule = ScopeRule(pattern=target.strip(), kind=kind)
        if (
            field == "forbidden_destinations"
            or _network_scope_pattern(rule, deny=field == "out_of_scope") is None
        ):
            raise InvalidRoEError(f"RoE {field} contains an unsupported URL target")
        return
    try:
        if kind == "cidr" or (kind == "auto" and "/" in target):
            ipaddress.ip_network(target, strict=False)
        elif kind == "ip":
            ipaddress.ip_address(target.rstrip("."))
    except ValueError as exc:
        raise InvalidRoEError(f"RoE {field} contains an invalid network target") from exc


def _validate_tool_guard(block: dict[str, Any]) -> None:
    """Reject a guard rule set the middleware could not apply exactly as written."""
    _, errors = compile_rules(block.get("tool_guard", []), source="tool_guard")
    if errors:
        shown = "; ".join(errors[:5]) + (f"; and {len(errors) - 5} more" if len(errors) > 5 else "")
        raise InvalidRoEError(f"RoE tool_guard is invalid: {shown}")
    total = len(block.get("tool_guard", [])) + len(block.get("forbidden_command_patterns", []))
    if total > MAX_RULES:
        raise InvalidRoEError(
            f"RoE tool_guard plus forbidden_command_patterns must not exceed {MAX_RULES} rules"
        )


def parse_roe_document(document: Any, *, required: bool) -> MachineEnforcement:
    """Validate a decoded RoE document and return its enforcement rules.

    Raises :class:`InvalidRoEError` for anything the matcher could not apply
    safely. Shared by the runtime loader and ``buggy-cli scope`` so an
    operator cannot approve a policy the middleware would later reject.
    """
    if not isinstance(document, dict):
        raise InvalidRoEError("RoE document must be a JSON object")
    if "machine_enforcement" not in document:
        if required:
            raise InvalidRoEError(
                "RoE machine_enforcement block is required (BUGGY_ROE_REQUIRE) but absent"
            )
        return MachineEnforcement()
    block = document["machine_enforcement"]
    if not isinstance(block, dict):
        raise InvalidRoEError("RoE machine_enforcement must be a JSON object")
    mode = str(block.get("mode", EnforcementMode.AUDIT.value)).lower()
    if mode not in {member.value for member in EnforcementMode}:
        raise InvalidRoEError("RoE enforcement mode must be audit, warn or enforce")
    for field in (
        "in_scope",
        "out_of_scope",
        "forbidden_destinations",
        "forbidden_command_patterns",
        "authorized_windows",
        "blackout_windows",
        "tool_guard",
    ):
        if not isinstance(block.get(field, []), list):
            raise InvalidRoEError(f"RoE {field} must be a JSON array")
    for field in ("allow_cloud_metadata", "allow_sensitive_tlds"):
        if field in block and not isinstance(block[field], bool):
            raise InvalidRoEError(f"RoE {field} must be a boolean")
    for field in ("max_concurrent_connections", "min_inter_request_delay_ms"):
        value = block.get(field, 0)
        if field == "max_concurrent_connections" and value is None:
            continue
        if type(value) is not int or value < 0:
            raise InvalidRoEError(f"RoE {field} must be a nonnegative integer")
    if block.get("min_inter_request_delay_ms", 0) > MAX_INTER_REQUEST_DELAY_MS:
        raise InvalidRoEError(
            f"RoE min_inter_request_delay_ms must not exceed {MAX_INTER_REQUEST_DELAY_MS}"
        )
    for field in ("in_scope", "out_of_scope", "forbidden_destinations"):
        for entry in block.get(field, []):
            _validate_target_entry(field, entry)
    if any(
        not isinstance(entry, str) or not entry.strip()
        for entry in block.get("forbidden_command_patterns", [])
    ):
        raise InvalidRoEError("RoE forbidden_command_patterns entries must be nonempty strings")
    _validate_tool_guard(block)
    try:
        for pattern in block.get("forbidden_command_patterns", []):
            re.compile(pattern)
        rules = MachineEnforcement.from_dict(block)
    except (TypeError, ValueError, OverflowError, re.error) as exc:
        raise InvalidRoEError("RoE machine_enforcement cannot be interpreted") from exc
    for field in ("authorized_windows", "blackout_windows"):
        windows = getattr(rules, field)
        if len(windows) != len(block.get(field, [])):
            raise InvalidRoEError(f"RoE {field} contains an invalid time window")
        if any(start.tzinfo is None or end.tzinfo is None for start, end in windows):
            raise InvalidRoEError(f"RoE {field} timestamps must include a timezone")
    return rules


__all__ = ["InvalidRoEError", "parse_roe_document"]
