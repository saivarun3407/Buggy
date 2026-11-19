"""Scope filter for the pipeline.

The pipeline scans only what the engagement's *enforced* RoE puts in scope.
It reads ``<control>/<engagement>/roe.json`` (operator-written, see
``buggy.middleware._control``), validates it with the same parser the
guardrail uses, and refuses to run unless the policy is in ``enforce`` mode
with a non-empty allowlist: a pipeline with nothing to constrain it would
scan whatever its inputs named.

Every stage calls :meth:`ScopeFilter.admit` on its inputs before a tool runs
and on the tool's outputs before they are stored. A rejected candidate is
logged to the store and never reaches a scanner.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from buggy.pipeline.schema import as_dict, host_of, is_hostname, normalize_host
from buggy_core.types.roe import (
    EnforcementMode,
    MachineEnforcement,
    ScopeRule,
    _network_scope_pattern,
    evaluate_target,
)
from buggy_core.types.roe_document import InvalidRoEError, parse_roe_document

# Largest CIDR the pipeline will expand into individual hosts.
MAX_CIDR_HOSTS = 1024

DropLogger = Callable[[str, str, str, str, str], None]  # stage, tool, direction, candidate, reason


class ScopeError(RuntimeError):
    """The engagement has no usable enforced scope; the pipeline must not run."""


@dataclass(frozen=True, slots=True)
class PipelineLimits:
    """Program rules that shape how the scanners are invoked."""

    rate_limit_rps: int = 10
    concurrency: int = 5
    passive_only: bool = False
    port_scan: bool = True
    ports: str = "top-100"
    crawl_depth: int = 2
    nuclei_severities: tuple[str, ...] = ("low", "medium", "high", "critical")
    disabled_stages: tuple[str, ...] = ()

    @classmethod
    def from_roe(cls, rules: MachineEnforcement, document: dict[str, Any]) -> PipelineLimits:
        """Derive limits from ``machine_enforcement`` plus an optional ``pipeline`` block.

        ``min_inter_request_delay_ms`` and ``max_concurrent_connections`` are
        hard ceilings: the ``pipeline`` block can only go lower. A program
        that bans automated scanning sets ``pipeline.passive_only``.
        """
        block = as_dict(document.get("pipeline"))
        defaults = cls()
        rps = _positive_int(block.get("rate_limit_rps"), defaults.rate_limit_rps)
        if rules.min_inter_request_delay_ms > 0:
            rps = min(rps, max(1, 1000 // rules.min_inter_request_delay_ms))
        concurrency = _positive_int(block.get("concurrency"), defaults.concurrency)
        if rules.max_concurrent_connections:
            concurrency = min(concurrency, max(1, int(rules.max_concurrent_connections)))
        concurrency = min(concurrency, rps)
        severities = block.get("nuclei_severities")
        allowed = {"info", "low", "medium", "high", "critical"}
        return cls(
            rate_limit_rps=rps,
            concurrency=concurrency,
            passive_only=bool(block.get("passive_only", False)),
            port_scan=bool(block.get("port_scan", True)),
            ports=str(block.get("ports") or defaults.ports),
            crawl_depth=max(
                1, min(_positive_int(block.get("crawl_depth"), defaults.crawl_depth), 5)
            ),
            nuclei_severities=(
                tuple(s for s in severities if s in allowed)
                if isinstance(severities, list) and severities
                else defaults.nuclei_severities
            ),
            disabled_stages=tuple(
                str(s) for s in block.get("disabled_stages") or [] if isinstance(s, str)
            ),
        )


def _positive_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


@dataclass
class ScopeFilter:
    """Decides, and records, whether a candidate may be scanned or stored."""

    rules: MachineEnforcement
    limits: PipelineLimits = field(default_factory=PipelineLimits)
    digest: str = ""
    log_drop: DropLogger | None = None

    # ── construction ────────────────────────────────────────────────

    @classmethod
    def from_document(cls, document: Any, *, log_drop: DropLogger | None = None) -> ScopeFilter:
        try:
            rules = parse_roe_document(document, required=True)
        except InvalidRoEError as exc:
            raise ScopeError(f"enforced scope is invalid: {exc}") from exc
        if rules.mode != EnforcementMode.ENFORCE:
            raise ScopeError(
                f"enforced scope is in {rules.mode.value!r} mode; the pipeline runs only in "
                "'enforce' mode"
            )
        if not rules.in_scope:
            raise ScopeError("enforced scope has an empty in_scope list; nothing may be scanned")
        block = document["machine_enforcement"]
        digest = hashlib.sha256(
            json.dumps(block, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        return cls(
            rules=rules,
            limits=PipelineLimits.from_roe(rules, document),
            digest=digest,
            log_drop=log_drop,
        )

    @classmethod
    def from_file(cls, path: Path, *, log_drop: DropLogger | None = None) -> ScopeFilter:
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ScopeError(
                f"no enforced scope at {path}; the operator must approve one first "
                "(buggy-cli scope approve <engagement>)"
            ) from exc
        except (OSError, ValueError) as exc:
            raise ScopeError(f"cannot read enforced scope {path}: {exc}") from exc
        return cls.from_document(document, log_drop=log_drop)

    # ── decisions ───────────────────────────────────────────────────

    def decide(self, candidate: str) -> tuple[bool, str]:
        """``(allowed, reason)`` for a host, ``host:port`` or URL."""
        host = host_of(candidate)
        if not host:
            return False, "NO_HOST"
        decision = evaluate_target(host, self.rules)
        return decision.allow, decision.reason_code

    def allows(self, candidate: str) -> bool:
        return self.decide(candidate)[0]

    def admit(
        self, candidates: Iterable[str], *, stage: str, tool: str, direction: str
    ) -> list[str]:
        """In-scope candidates, in order, de-duplicated. Rejections are logged."""
        kept: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            allowed, reason = self.decide(candidate)
            if allowed:
                kept.append(candidate)
            elif self.log_drop is not None:
                self.log_drop(stage, tool, direction, candidate, reason)
        return kept

    # ── seeds ───────────────────────────────────────────────────────

    def seeds(self) -> Seeds:
        """What the pipeline starts from, derived only from ``in_scope``.

        * ``*.acme.com``   → enumeration root ``acme.com`` (results are still
          filtered: a wildcard covers one label, and the apex is in scope
          only if listed).
        * ``app.acme.com`` → a host to resolve and probe, not enumerated.
        * address / CIDR   → hosts to probe (CIDRs larger than
          ``MAX_CIDR_HOSTS`` are skipped and reported).
        """
        roots: list[str] = []
        hosts: list[str] = []
        addresses: list[str] = []
        skipped: list[str] = []
        for rule in self.rules.in_scope:
            pattern = _network_scope_pattern(rule)
            if pattern is None:
                skipped.append(rule.pattern)
                continue
            kind = rule.resolved_kind() if pattern == rule.pattern else "host"
            if kind in ("cidr", "ip"):
                try:
                    network = ipaddress.ip_network(pattern, strict=False)
                except ValueError:
                    skipped.append(rule.pattern)
                    continue
                if network.num_addresses > MAX_CIDR_HOSTS:
                    skipped.append(rule.pattern)
                    continue
                members = list(network.hosts()) or [network.network_address]
                addresses.extend(str(ip) for ip in members)
            elif kind == "domain-glob":
                root = normalize_host(pattern.lstrip("*?.").lstrip("."))
                # Only a leading "*." wildcard names an enumerable root.
                if pattern.startswith("*.") and is_hostname(root) and "*" not in root:
                    roots.append(root)
                else:
                    skipped.append(rule.pattern)
            else:
                host = normalize_host(pattern)
                if is_hostname(host):
                    hosts.append(host)
                else:
                    skipped.append(rule.pattern)
        in_scope_hosts = [h for h in dict.fromkeys(hosts) if self.allows(h)]
        in_scope_addresses = [a for a in dict.fromkeys(addresses) if self.allows(a)]
        return Seeds(
            roots=tuple(dict.fromkeys(roots)),
            hosts=tuple(in_scope_hosts),
            addresses=tuple(in_scope_addresses),
            skipped=tuple(skipped),
        )


@dataclass(frozen=True, slots=True)
class Seeds:
    roots: tuple[str, ...]
    hosts: tuple[str, ...]
    addresses: tuple[str, ...]
    skipped: tuple[str, ...] = ()


def scope_rule_patterns(rules: MachineEnforcement) -> list[str]:
    return [rule.pattern for rule in rules.in_scope if isinstance(rule, ScopeRule)]


__all__ = [
    "MAX_CIDR_HOSTS",
    "PipelineLimits",
    "ScopeError",
    "ScopeFilter",
    "Seeds",
]
