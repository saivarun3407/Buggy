"""nftables ruleset for the egress guard.

One table, ``inet buggy_guard``, rendered whole and loaded atomically with
``nft -f``. Chains:

``input``
    From the sandbox network the guard itself accepts DNS and the tunnel's
    VXLAN packets from the sandbox address, nothing else. The control API is
    therefore unreachable from the sandbox even before its token check.

``forward``
    Policy ``drop``. Only packets arriving through the tunnel are considered.
    Order: protected ranges (management plane) drop, then the engagement's
    deny set, then its allow sets, then the default verdict.

``dropped``
    Records the destination in a counted set, then drops. The service polls
    those sets and writes the drop ledger; no kernel log access is needed.

``postrouting``
    Masquerades sandbox traffic leaving through any other interface.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from buggy.egress_guard.policy import Mode, Policy

TABLE_FAMILY = "inet"
TABLE_NAME = "buggy_guard"
TABLE = f"{TABLE_FAMILY} {TABLE_NAME}"

Runner = Callable[[Sequence[str], str | None], "subprocess.CompletedProcess[str]"]


class FirewallError(RuntimeError):
    """The ruleset could not be loaded or read."""


@dataclass(frozen=True, slots=True)
class Topology:
    """What the guard learned about its own interfaces at start-up."""

    # Interface on the (internal) sandbox network: carries DNS and the tunnel.
    underlay_if: str
    underlay_ip: str
    # The sandbox container's address on that network (tunnel peer).
    peer_ip: str
    # Tunnel interface: every packet the sandbox sends to a target arrives here.
    tunnel_if: str
    tunnel_cidr: str
    tunnel_port: int = 4789
    # Ranges the sandbox must never reach through the guard: every network
    # the guard is attached to other than declared local target networks.
    protected_cidrs: tuple[str, ...] = ()


def _v4(cidrs: Iterable[str]) -> list[str]:
    out: list[str] = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            out.append(str(network))
    return sorted(set(out))


def _set_block(name: str, elements: Sequence[str], *, timeout: bool = False) -> list[str]:
    flags = "interval, timeout" if timeout else "interval"
    lines = [f"  set {name} {{", "    type ipv4_addr", f"    flags {flags}", "    auto-merge"]
    if elements:
        lines.append(f"    elements = {{ {', '.join(elements)} }}")
    lines.append("  }")
    return lines


def render_ruleset(
    policy: Policy,
    topology: Topology,
    *,
    resolved_denied_ips: Iterable[str] = (),
    learned: Iterable[tuple[str, int]] = (),
) -> str:
    """Render the full ruleset for ``policy``.

    ``resolved_denied_ips`` are addresses of literal denied hostnames.
    ``learned`` carries ``(address, seconds_left)`` pairs the DNS proxy already
    vetted, so a policy reload does not cut established name-based access.
    """
    und = topology.underlay_if
    tun = topology.tunnel_if
    allow = _v4(policy.allowed_cidrs)
    deny = _v4([*policy.denied_cidrs, *resolved_denied_ips])
    protected = _v4(topology.protected_cidrs)
    learned_elems = [
        f"{address} timeout {max(1, int(ttl))}s"
        for address, ttl in learned
        if _v4([address]) and int(ttl) > 0
    ]

    lines = [
        "#!/usr/sbin/nft -f",
        "# Buggy egress guard - generated; do not hand-edit.",
        f"add table {TABLE}",
        f"delete table {TABLE}",
        f"table {TABLE} {{",
        *_set_block("protected4", protected),
        *_set_block("allow4", allow),
        *_set_block("deny4", deny),
        "  set dyn4 {",
        "    type ipv4_addr",
        "    flags timeout",
        *([f"    elements = {{ {', '.join(learned_elems)} }}"] if learned_elems else []),
        "  }",
        "  set drops {",
        "    type ipv4_addr . inet_proto . inet_service",
        "    flags dynamic, timeout",
        "    counter",
        "    size 65536",
        "    timeout 6h",
        "  }",
        "  set drops_other {",
        "    type ipv4_addr . inet_proto",
        "    flags dynamic, timeout",
        "    counter",
        "    size 8192",
        "    timeout 6h",
        "  }",
        "  chain dropped {",
        "    meta l4proto { tcp, udp } update @drops { ip daddr . meta l4proto . th dport } drop",
        "    meta nfproto ipv4 update @drops_other { ip daddr . meta l4proto } drop",
        "    drop",
        "  }",
        "  chain input {",
        "    type filter hook input priority 0; policy accept;",
        f'    iifname {{ "{und}", "{tun}" }} ct state established,related accept',
        f'    iifname "{und}" udp dport 53 accept',
        f'    iifname "{und}" tcp dport 53 accept',
        f'    iifname "{und}" ip saddr {topology.peer_ip} udp dport {topology.tunnel_port} accept',
        f'    iifname {{ "{und}", "{tun}" }} icmp type echo-request accept',
        f'    iifname "{tun}" jump dropped',
        f'    iifname "{und}" drop',
        "  }",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        "    ct state established,related accept",
        f'    iifname != "{tun}" drop',
        "    meta nfproto ipv6 drop",
        "    tcp flags syn tcp option maxseg size set rt mtu",
        "    ip daddr @protected4 jump dropped",
    ]
    if policy.mode == Mode.OPEN:
        lines.append("    accept")
    elif policy.mode == Mode.ENFORCE:
        lines += [
            "    ip daddr @deny4 jump dropped",
            "    ip daddr @allow4 accept",
            "    ip daddr @dyn4 accept",
        ]
        if not policy.default_drop:
            lines.append("    accept")
        lines.append("    jump dropped")
    else:  # LOCKED
        lines.append("    jump dropped")
    lines += [
        "  }",
        "  chain postrouting {",
        "    type nat hook postrouting priority 100; policy accept;",
        f'    iifname "{tun}" oifname != {{ "{tun}", "{und}" }} masquerade',
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def run_nft(argv: Sequence[str], stdin: str | None = None) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        list(argv),
        input=stdin,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


class Firewall:
    """Thin wrapper over ``nft`` with an injectable runner for tests."""

    def __init__(self, topology: Topology, *, runner: Runner | None = None) -> None:
        self.topology = topology
        self._run = runner or run_nft

    def load(
        self,
        policy: Policy,
        *,
        resolved_denied_ips: Iterable[str] = (),
        learned: Iterable[tuple[str, int]] = (),
    ) -> str:
        ruleset = render_ruleset(
            policy,
            self.topology,
            resolved_denied_ips=resolved_denied_ips,
            learned=learned,
        )
        proc = self._run(["nft", "-f", "-"], ruleset)
        if proc.returncode != 0:
            raise FirewallError(f"nft load failed rc={proc.returncode}: {proc.stderr.strip()}")
        return ruleset

    def learn(self, address: str, ttl_seconds: int) -> None:
        """Allow a DNS-vetted address for ``ttl_seconds``."""
        if not _v4([address]):
            return
        ttl = max(1, int(ttl_seconds))
        element = f"{{ {address} timeout {ttl}s }}"
        proc = self._run(["nft", "add", "element", *TABLE.split(), "dyn4", element], None)
        if proc.returncode != 0:
            raise FirewallError(f"nft add element failed: {proc.stderr.strip()}")

    def read_drops(self) -> dict[tuple[str, str, int | None], int]:
        """Current ``(dst, proto, dport) -> packets`` counters from the drop sets."""
        counters: dict[tuple[str, str, int | None], int] = {}
        for set_name in ("drops", "drops_other"):
            proc = self._run(["nft", "-j", "list", "set", *TABLE.split(), set_name], None)
            if proc.returncode != 0:
                raise FirewallError(f"nft list set {set_name} failed: {proc.stderr.strip()}")
            for key, packets in parse_drop_set(proc.stdout):
                counters[key] = packets
        return counters


def parse_drop_set(raw_json: str) -> list[tuple[tuple[str, str, int | None], int]]:
    """Parse ``nft -j list set`` output for a drop set into ``(key, packets)`` rows."""
    try:
        document = json.loads(raw_json)
    except json.JSONDecodeError:
        return []
    rows: list[tuple[tuple[str, str, int | None], int]] = []
    for entry in document.get("nftables", []):
        elements = (entry.get("set") or {}).get("elem") or []
        for element in elements:
            body = element.get("elem") if isinstance(element, dict) else None
            if not isinstance(body, dict):
                continue
            concat = (
                (body.get("val") or {}).get("concat") if isinstance(body.get("val"), dict) else None
            )
            if not isinstance(concat, list) or len(concat) < 2:
                continue
            packets = int((body.get("counter") or {}).get("packets", 0))
            dst = str(concat[0])
            proto = str(concat[1])
            dport: int | None = None
            if len(concat) >= 3:
                try:
                    dport = int(concat[2])
                except (TypeError, ValueError):
                    dport = None
            rows.append(((dst, proto, dport), packets))
    return rows


__all__ = [
    "TABLE",
    "Firewall",
    "FirewallError",
    "Topology",
    "parse_drop_set",
    "render_ruleset",
    "run_nft",
]
