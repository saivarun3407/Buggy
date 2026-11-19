"""Policy model and name matching for the egress guard (standard library only).

The wire shape is the ``EgressPolicy`` dict compiled on the langgraph side by
``buggy.middleware.egress.compile_egress_policy``. Matching mirrors
``buggy_core.types.roe``: a ``*`` covers exactly one DNS label, so
``*.acme.com`` grants neither ``acme.com`` nor ``a.b.acme.com``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Mode(StrEnum):
    LOCKED = "locked"  # no policy yet: nothing is forwarded, no name resolves
    OPEN = "open"  # audit / warn engagement: forwarded, management plane still protected
    ENFORCE = "enforce"  # enforce engagement: allowlist / denylist applied


_HOST_RE = re.compile(r"[A-Za-z0-9*?_]([A-Za-z0-9*?_.-]{0,251}[A-Za-z0-9*?_])?")


def _is_network(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    return True


def _clean_cidrs(raw: Any) -> tuple[str, ...]:
    out: set[str] = set()
    for item in raw if isinstance(raw, (list, tuple)) else ():
        token = str(item).strip()
        if _is_network(token):
            out.add(str(ipaddress.ip_network(token, strict=False)))
    return tuple(sorted(out))


def _clean_hosts(raw: Any) -> tuple[str, ...]:
    out: set[str] = set()
    for item in raw if isinstance(raw, (list, tuple)) else ():
        token = str(item).strip().rstrip(".").lower()
        if token and not _is_network(token) and _HOST_RE.fullmatch(token):
            out.add(token)
    return tuple(sorted(out))


def glob_match(pattern: str, name: str) -> bool:
    """Label-bounded DNS glob (same semantics as ``buggy_core.types.roe``)."""
    regex = re.escape(pattern).replace(r"\*", "[^.]+").replace(r"\?", "[^.]")
    return re.fullmatch(regex, name, re.IGNORECASE) is not None


def _host_matches(pattern: str, name: str) -> bool:
    if "*" in pattern or "?" in pattern:
        return glob_match(pattern, name)
    return pattern == name


@dataclass(frozen=True, slots=True)
class Policy:
    """Validated egress policy held by the guard."""

    mode: Mode = Mode.LOCKED
    default_drop: bool = True
    allowed_cidrs: tuple[str, ...] = field(default_factory=tuple)
    allowed_hosts: tuple[str, ...] = field(default_factory=tuple)
    denied_cidrs: tuple[str, ...] = field(default_factory=tuple)
    denied_hosts: tuple[str, ...] = field(default_factory=tuple)
    engagement: str = ""
    # SHA-256 of the policy exactly as the langgraph side compiled it, so both
    # ends name the same policy by the same digest (the guard normalises
    # entries, which would otherwise change the hash).
    source_digest: str = ""

    @classmethod
    def locked(cls) -> Policy:
        return cls()

    @classmethod
    def from_wire(cls, data: Any, *, engagement: str = "") -> Policy:
        """Build a policy from the langgraph-compiled dict.

        Unknown or malformed entries are discarded rather than trusted. A
        non-enforcing policy becomes :attr:`Mode.OPEN`.
        """
        if not isinstance(data, dict):
            raise ValueError("policy must be a JSON object")
        if not isinstance(data.get("enforce"), bool):
            raise ValueError("policy.enforce must be a boolean")
        enforce = data["enforce"]
        denied_hosts = _clean_hosts(data.get("denied_hosts"))
        default_drop = bool(data.get("default_drop", False))
        # A wildcard deny cannot be turned into addresses. Fall back to
        # "only destinations vetted by the DNS proxy or listed by CIDR".
        if enforce and any("*" in host or "?" in host for host in denied_hosts):
            default_drop = True
        keys = (
            "enforce",
            "default_drop",
            "allowed_cidrs",
            "allowed_hosts",
            "denied_cidrs",
            "denied_hosts",
        )
        received = {
            key: (
                list(data.get(key) or [])
                if key.endswith(("cidrs", "hosts"))
                else bool(data.get(key))
            )
            for key in keys
        }
        source_digest = hashlib.sha256(
            json.dumps(received, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return cls(
            source_digest=source_digest,
            mode=Mode.ENFORCE if enforce else Mode.OPEN,
            default_drop=default_drop if enforce else False,
            allowed_cidrs=_clean_cidrs(data.get("allowed_cidrs")),
            allowed_hosts=_clean_hosts(data.get("allowed_hosts")),
            denied_cidrs=_clean_cidrs(data.get("denied_cidrs")),
            denied_hosts=denied_hosts,
            engagement=str(engagement)[:128],
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "enforce": self.mode == Mode.ENFORCE,
            "default_drop": self.default_drop,
            "allowed_cidrs": list(self.allowed_cidrs),
            "allowed_hosts": list(self.allowed_hosts),
            "denied_cidrs": list(self.denied_cidrs),
            "denied_hosts": list(self.denied_hosts),
        }

    def digest(self) -> str:
        if self.source_digest:
            return self.source_digest
        canonical = json.dumps(self.to_wire(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ── name decisions (DNS proxy) ──────────────────────────────────

    def name_decision(self, name: str) -> tuple[bool, str]:
        """Whether the DNS proxy may resolve ``name``; returns ``(allow, reason)``."""
        host = name.rstrip(".").lower()
        if self.mode == Mode.LOCKED:
            return False, "no_policy"
        if not host:
            return False, "empty_name"
        if self.mode == Mode.OPEN:
            return True, "open_mode"
        for pattern in self.denied_hosts:
            if _host_matches(pattern, host):
                return False, f"denied_host:{pattern}"
        if not self.default_drop:
            return True, "not_denied"
        for pattern in self.allowed_hosts:
            if _host_matches(pattern, host):
                return True, f"allowed_host:{pattern}"
        return False, "not_in_scope"

    def address_denied(self, address: str) -> bool:
        """Whether a resolved address falls in a denied range."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return True
        for cidr in self.denied_cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            if ip.version == network.version and ip in network:
                return True
        return False

    def literal_denied_hosts(self) -> tuple[str, ...]:
        return tuple(h for h in self.denied_hosts if "*" not in h and "?" not in h)


__all__ = ["Mode", "Policy", "glob_match"]
