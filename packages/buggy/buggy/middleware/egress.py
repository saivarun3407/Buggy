"""Layer-2 RoE egress guardrail — compile scope rules into a network boundary.

The parser-side :class:`~buggy.middleware.roe.RoEGuardrailMiddleware`
is a *fast-fail UX* gate: it reads the literal command text and refuses
early when it can see an out-of-scope target. It cannot be the
authoritative boundary — a target can hide behind variable indirection,
command substitution, or out-of-band DNS resolution the parser never
sees (see ``docs/design/2026-06-12-roe-guardrail-middleware-redesign.md``).

This module is the authoritative half. ``compile_egress_policy`` turns
the **same** ``roe.json:machine_enforcement`` block the parser reads into
an :class:`EgressPolicy`, which the sandbox enforces at its network edge:

  * an **nftables** connect-allowlist (``render_nftables``) — outbound
    packets are dropped unless their destination IP/CIDR is in scope;
    cloud-metadata / out-of-scope ranges drop before the scope allow so
    denylist precedence holds.
  * a **DNS allowlist** (``render_dns_allowlist``) — the sandbox
    resolver answers only in-scope hostnames / wildcards.

One scope definition, two enforcement points. A packet to an
out-of-scope host cannot leave the sandbox even when the command parser
missed the target.

Layering
--------
The renderer + applier (``render_nftables``, ``render_dns_allowlist``,
``apply_egress``) live in ``buggy.sandbox_kernel.egress`` because
they run *inside* the sandbox container — where ``nft`` exists, the
management subnet is locally discoverable, and the image ships no
``buggy_core``. They are re-exported here for convenience. This
module owns only the core-dependent step: ``MachineEnforcement`` →
:class:`EgressPolicy`. The compiled policy is serialised over the
``/provision_egress`` endpoint; the sandbox applier folds in the
locally-discovered management plane and loads the ruleset.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any

from buggy.sandbox_kernel.egress import (
    EgressPolicy,
    render_dns_allowlist,
    render_nftables,
)
from buggy_core.types.roe import (
    EnforcementMode,
    MachineEnforcement,
    ScopeRule,
    _network_scope_pattern,
)


def _is_ip_or_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def _classify(patterns: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split raw scope patterns into (ip/cidr literals, hostnames/globs)."""
    cidrs: list[str] = []
    hosts: list[str] = []
    for pat in patterns:
        (cidrs if _is_ip_or_cidr(pat) else hosts).append(pat)
    return tuple(cidrs), tuple(hosts)


def _rule_patterns(rules: Iterable[ScopeRule], *, deny: bool = False) -> list[str]:
    return [
        pattern
        for rule in rules
        if (pattern := _network_scope_pattern(rule, deny=deny)) is not None
    ]


def _norm(addrs: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({a for a in addrs if a}))


# OSINT search-provider hosts the sandbox may always reach, even under an
# enforcing in-scope allowlist. `web_search` is OSINT (target-exempt at the RoE
# tool layer); without this, an enforce-mode engagement's nftables/DNS allowlist
# — compiled from in_scope only — would drop the provider connection and
# web_search would silently fail. Mirrors the provider allowlist in
# buggy.sandbox_web.providers (kept as a small literal here to avoid the
# middleware importing the in-sandbox engine). Extend/replace via
# BUGGY_OSINT_EGRESS_HOSTS (comma-separated); set it empty to disable.
_DEFAULT_OSINT_EGRESS_HOSTS = ("duckduckgo.com", "html.duckduckgo.com")


def osint_egress_hosts() -> tuple[str, ...]:
    raw = os.environ.get("BUGGY_OSINT_EGRESS_HOSTS")
    if raw is None:
        return _DEFAULT_OSINT_EGRESS_HOSTS
    return tuple(h.strip() for h in raw.split(",") if h.strip())


def compile_egress_policy(rules: MachineEnforcement) -> EgressPolicy:
    """Compile a ``MachineEnforcement`` block into an :class:`EgressPolicy`.

    ``enforce`` follows ENFORCE mode (audit / warn never touch the
    network). ``default_drop`` is set only when an in-scope allowlist
    exists — an enforce-mode RoE that lists only *denies* tightens those
    destinations without otherwise restricting egress, mirroring the
    parser's ``evaluate_target`` (which constrains to the allowlist only
    when ``in_scope`` is non-empty).
    """
    enforce = rules.mode == EnforcementMode.ENFORCE

    allowed_cidrs, allowed_hosts = _classify(_rule_patterns(rules.in_scope))
    denied_cidrs, denied_hosts = _classify(
        [*_rule_patterns(rules.out_of_scope, deny=True), *rules.effective_forbidden_destinations()]
    )

    default_drop = enforce and bool(rules.in_scope)
    if rules.sandbox_blocked:
        # The sandbox gets no route to any target: targets are reached only by
        # the evidence gateway, the scoped browser and the pipeline.
        allowed_cidrs, allowed_hosts = (), ()
        default_drop = True

    # Always allow the OSINT search providers so target-exempt web_search reaches
    # them under an enforcing in-scope allowlist. (No effect when default_drop is
    # False — nothing is being dropped anyway.)
    allowed_hosts = (*allowed_hosts, *osint_egress_hosts())

    return EgressPolicy(
        enforce=enforce,
        default_drop=default_drop,
        allowed_cidrs=_norm(allowed_cidrs),
        allowed_hosts=_norm(allowed_hosts),
        denied_cidrs=_norm(denied_cidrs),
        denied_hosts=_norm(denied_hosts),
    )


class EgressProvisioningError(RuntimeError):
    """The network boundary for an engagement could not be put in place.

    Raised from the guardrail's ``before_agent`` hook so the run stops before
    any tool executes. A run that cannot prove its egress policy is loaded
    must not reach a target.
    """


def policy_digest(policy: EgressPolicy) -> str:
    """Stable SHA-256 of a compiled policy, used to detect scope changes."""
    canonical = json.dumps(policy.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def guard_endpoint() -> tuple[str, str] | None:
    """``(url, token)`` of the egress-guard sidecar, or ``None`` when not deployed.

    Raises :class:`EgressProvisioningError` when a guard URL is configured
    without a token: an unauthenticated control channel is a misconfiguration,
    not a mode.
    """
    url = (os.environ.get("BUGGY_EGRESS_GUARD_URL") or "").strip().rstrip("/")
    if not url:
        return None
    token = (os.environ.get("EGRESS_GUARD_TOKEN") or "").strip()
    if not token:
        raise EgressProvisioningError(
            "BUGGY_EGRESS_GUARD_URL is set but EGRESS_GUARD_TOKEN is empty"
        )
    return url, token


def provision_guard(
    policy: EgressPolicy,
    *,
    engagement: str,
    url: str,
    token: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Push ``policy`` to the egress guard and return its reply.

    The guard lives in its own container and network namespace; the sandbox
    has no route to this API and does not hold the token. Any transport or
    HTTP failure raises :class:`EgressProvisioningError`.
    """
    body = json.dumps(
        {"engagement": engagement, "policy": policy.to_dict(), "digest": policy_digest(policy)}
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - operator-configured http(s) URL
        f"{url}/policy",
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise EgressProvisioningError(
            f"egress guard rejected policy: HTTP {exc.code} {detail}"
        ) from exc
    except (OSError, ValueError) as exc:
        raise EgressProvisioningError(f"egress guard unreachable: {exc}") from exc
    if not isinstance(payload, dict):
        raise EgressProvisioningError("egress guard returned a malformed reply")
    return payload


__all__ = [
    "EgressPolicy",
    "EgressProvisioningError",
    "compile_egress_policy",
    "guard_endpoint",
    "policy_digest",
    "provision_guard",
    "render_dns_allowlist",
    "render_nftables",
]
