"""Egress guard service: firewall + DNS proxy + control API + drop ledger.

Start-up order matters and is fail-closed:

1. Discover the sandbox-facing interface. Fail if it cannot be found.
2. Create the VXLAN tunnel endpoint the sandbox routes through.
3. Load the LOCKED ruleset (nothing forwarded). Fail if ``nft`` refuses.
4. Start the DNS proxy on the sandbox-facing address.
5. Start the control API on the management-side addresses only.

Why a tunnel: the sandbox network is a Docker ``internal`` network, and
Docker drops every packet on it whose destination is outside its subnet -
which is what stops the sandbox from leaving any other way, even with raw
sockets. A packet "to a target via the guard" has an outside destination, so
it travels inside VXLAN, addressed to the guard.

Environment:

``EGRESS_GUARD_TOKEN``            required bearer token for the control API
``BUGGY_SANDBOX_SUBNET``          CIDR of the sandbox network (to pick the interface)
``BUGGY_SANDBOX_IP``              the sandbox container's address (tunnel peer)
``BUGGY_TUNNEL_SUBNET``           /30 for the tunnel (default 10.254.250.0/30;
                                  guard = first host, sandbox = second)
``BUGGY_TUNNEL_VNI``              VXLAN id (default 4242)
``BUGGY_GUARD_LOCAL_TARGET_CIDRS`` comma-separated attached networks that hold
                                  targets (labs); every other attached network
                                  is protected from the sandbox
``BUGGY_GUARD_CONTROL_PORT``      control API port (default 9440)
``BUGGY_GUARD_LEDGER``            drop ledger path (default /audit/egress-guard/egress-decisions.jsonl)
``BUGGY_GUARD_UPSTREAM_DNS``      comma-separated resolvers (default: /etc/resolv.conf)
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from buggy.egress_guard import dns as dnsproxy
from buggy.egress_guard.firewall import Firewall, FirewallError, Topology
from buggy.egress_guard.ledger import Ledger
from buggy.egress_guard.policy import Mode, Policy

log = logging.getLogger("buggy.egress_guard")

DEFAULT_CONTROL_PORT = 9440
DEFAULT_TUNNEL_SUBNET = "10.254.250.0/30"
DEFAULT_TUNNEL_VNI = 4242
TUNNEL_IF = "bgtun0"
TUNNEL_PORT = 4789
TUNNEL_MTU = 1400
DEFAULT_LEDGER = "/audit/egress-guard/egress-decisions.jsonl"
_MIN_LEARN_TTL = 60
_MAX_LEARN_TTL = 3600
_MAX_BODY = 1 << 20


class GuardStartupError(RuntimeError):
    """The guard cannot establish its boundary and must not run."""


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    address: str
    cidr: str


def list_interfaces(raw_json: str | None = None) -> list[Interface]:
    """IPv4 interfaces from ``ip -j -4 addr`` (loopback excluded)."""
    if raw_json is None:
        proc = subprocess.run(  # noqa: S603, S607 - fixed argv
            ["ip", "-j", "-4", "addr"], capture_output=True, text=True, timeout=10, check=False
        )
        if proc.returncode != 0:
            raise GuardStartupError(f"`ip addr` failed: {proc.stderr.strip()}")
        raw_json = proc.stdout
    interfaces: list[Interface] = []
    for link in json.loads(raw_json):
        name = str(link.get("ifname", ""))
        if not name or name == "lo":
            continue
        for info in link.get("addr_info", []):
            if info.get("family") != "inet":
                continue
            local = str(info.get("local", ""))
            prefix = int(info.get("prefixlen", 32))
            network = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
            interfaces.append(Interface(name=name, address=local, cidr=str(network)))
    return interfaces


def tunnel_addresses(tunnel_subnet: str) -> tuple[str, str, int]:
    """``(guard_address, sandbox_address, prefixlen)`` inside the tunnel subnet."""
    try:
        network = ipaddress.ip_network(tunnel_subnet, strict=True)
    except ValueError as exc:
        raise GuardStartupError(f"BUGGY_TUNNEL_SUBNET is not a network: {tunnel_subnet!r}") from exc
    hosts = list(network.hosts())
    if network.version != 4 or len(hosts) < 2:
        raise GuardStartupError("BUGGY_TUNNEL_SUBNET must be an IPv4 network with two hosts")
    return str(hosts[0]), str(hosts[1]), network.prefixlen


def discover_topology(
    interfaces: list[Interface],
    *,
    sandbox_subnet: str,
    sandbox_ip: str,
    tunnel_subnet: str = DEFAULT_TUNNEL_SUBNET,
    local_target_cidrs: tuple[str, ...] = (),
) -> tuple[Topology, list[Interface]]:
    """Pick the sandbox-facing interface; everything else is an uplink.

    Returns ``(topology, control_interfaces)``. Uplink networks are protected
    from the sandbox unless listed in ``local_target_cidrs``; the control API
    listens only on protected uplinks, never on a target network.
    """
    try:
        wanted = ipaddress.ip_network(sandbox_subnet, strict=False)
    except ValueError as exc:
        raise GuardStartupError(f"BUGGY_SANDBOX_SUBNET is not a CIDR: {sandbox_subnet!r}") from exc
    try:
        peer = ipaddress.ip_address(sandbox_ip)
    except ValueError as exc:
        raise GuardStartupError(f"BUGGY_SANDBOX_IP is not an address: {sandbox_ip!r}") from exc
    if peer not in wanted:
        raise GuardStartupError(f"BUGGY_SANDBOX_IP {peer} is outside sandbox subnet {wanted}")
    underlay = [i for i in interfaces if ipaddress.ip_address(i.address) in wanted]
    if len(underlay) != 1:
        raise GuardStartupError(
            f"expected exactly one interface in sandbox subnet {wanted}, found {len(underlay)}"
        )
    uplinks = [i for i in interfaces if i is not underlay[0] and i.name != TUNNEL_IF]
    if not uplinks:
        raise GuardStartupError("no uplink interface: the guard has nowhere to forward to")
    targets = [ipaddress.ip_network(c, strict=False) for c in local_target_cidrs]
    protected: list[str] = [str(wanted)]
    control: list[Interface] = []
    for uplink in uplinks:
        network = ipaddress.ip_network(uplink.cidr, strict=False)
        if any(network.subnet_of(t) for t in targets if t.version == network.version):
            continue
        protected.append(str(network))
        control.append(uplink)
    if not control:
        raise GuardStartupError("no management-side interface for the control API")
    _guard_tun, _sandbox_tun, prefix = tunnel_addresses(tunnel_subnet)
    tunnel_cidr = str(ipaddress.ip_network(tunnel_subnet, strict=True))
    del prefix
    topology = Topology(
        underlay_if=underlay[0].name,
        underlay_ip=underlay[0].address,
        peer_ip=str(peer),
        tunnel_if=TUNNEL_IF,
        tunnel_cidr=tunnel_cidr,
        tunnel_port=TUNNEL_PORT,
        protected_cidrs=tuple(sorted(set(protected))),
    )
    return topology, control


def tunnel_commands(topology: Topology, *, tunnel_subnet: str, vni: int) -> list[list[str]]:
    """``ip`` invocations that create the guard's tunnel endpoint."""
    guard_address, _sandbox_address, prefix = tunnel_addresses(tunnel_subnet)
    return [
        [
            "ip", "link", "add", topology.tunnel_if, "type", "vxlan",
            "id", str(vni),
            "local", topology.underlay_ip,
            "remote", topology.peer_ip,
            "dstport", str(topology.tunnel_port),
            "dev", topology.underlay_if,
        ],
        ["ip", "addr", "add", f"{guard_address}/{prefix}", "dev", topology.tunnel_if],
        ["ip", "link", "set", topology.tunnel_if, "mtu", str(TUNNEL_MTU), "up"],
    ]  # fmt: skip


def create_tunnel(topology: Topology, *, tunnel_subnet: str, vni: int) -> None:
    subprocess.run(  # noqa: S603, S607 - fixed argv; absent on first start
        ["ip", "link", "del", topology.tunnel_if], capture_output=True, check=False, timeout=10
    )
    for argv in tunnel_commands(topology, tunnel_subnet=tunnel_subnet, vni=vni):
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)  # noqa: S603
        if proc.returncode != 0:
            raise GuardStartupError(f"{' '.join(argv)} failed: {proc.stderr.strip()}")


def _resolve_ipv4(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


class Guard:
    """Holds the active policy and wires the DNS proxy to the firewall."""

    def __init__(
        self,
        firewall: Firewall,
        ledger: Ledger,
        *,
        resolve: Any = _resolve_ipv4,
        clock: Any = time.time,
    ) -> None:
        self.firewall = firewall
        self.ledger = ledger
        self._resolve = resolve
        self._clock = clock
        self._lock = threading.RLock()
        self._policy = Policy.locked()
        # address -> (name, expiry epoch) for DNS-vetted destinations.
        self._learned: dict[str, tuple[str, float]] = {}
        self._drop_seen: dict[tuple[str, str, int | None], int] = {}
        self.firewall.load(self._policy)

    # ── policy ──────────────────────────────────────────────────────

    @property
    def policy(self) -> Policy:
        with self._lock:
            return self._policy

    def apply(self, policy: Policy) -> dict[str, Any]:
        """Load ``policy`` atomically; on failure the previous rules stay."""
        self.collect_drops()  # counters reset with the table; record what is pending first
        denied_ips: list[str] = []
        if policy.mode == Mode.ENFORCE:
            for host in policy.literal_denied_hosts():
                denied_ips.extend(self._resolve(host))
        with self._lock:
            now = self._clock()
            learned = [
                (address, int(expiry - now))
                for address, (name, expiry) in self._learned.items()
                if expiry > now
                and policy.name_decision(name)[0]
                and not policy.address_denied(address)
            ]
            self.firewall.load(policy, resolved_denied_ips=denied_ips, learned=learned)
            kept = {address for address, _ttl in learned}
            self._learned = {a: v for a, v in self._learned.items() if a in kept}
            self._policy = policy
            self._drop_seen = {}
        digest = policy.digest()
        self.ledger.append(
            {
                "ts": self._clock(),
                "event": "policy_applied",
                "engagement": policy.engagement,
                "mode": policy.mode.value,
                "default_drop": policy.default_drop,
                "policy_sha256": digest,
                "allowed_hosts": len(policy.allowed_hosts),
                "allowed_cidrs": len(policy.allowed_cidrs),
                "denied_hosts": len(policy.denied_hosts),
                "denied_cidrs": len(policy.denied_cidrs),
            }
        )
        return {
            "applied": True,
            "enforce": policy.mode == Mode.ENFORCE,
            "mode": policy.mode.value,
            "policy_sha256": digest,
            "resolved_denied_ips": sorted(set(denied_ips)),
            "protected_cidrs": list(self.firewall.topology.protected_cidrs),
            "detail": "egress guard ruleset loaded",
        }

    def status(self) -> dict[str, Any]:
        policy = self.policy
        return {
            "mode": policy.mode.value,
            "engagement": policy.engagement,
            "policy_sha256": policy.digest() if policy.mode != Mode.LOCKED else "",
            "default_drop": policy.default_drop,
            "protected_cidrs": list(self.firewall.topology.protected_cidrs),
            "tunnel_cidr": self.firewall.topology.tunnel_cidr,
        }

    # ── DNS callbacks ───────────────────────────────────────────────

    def decide_name(self, name: str) -> tuple[bool, str]:
        return self.policy.name_decision(name)

    def on_refused(self, name: str, qtype: int, reason: str, client: str) -> None:
        policy = self.policy
        self._safe_append(
            {
                "ts": self._clock(),
                "event": "dns_refused",
                "engagement": policy.engagement,
                "decision": "drop",
                "qname": name.rstrip(".").lower(),
                "qtype": qtype,
                "reason": reason,
                "client": client,
                "policy_sha256": policy.digest() if policy.mode != Mode.LOCKED else "",
            }
        )

    def on_answer(self, name: str, addresses: list[dnsproxy.Address]) -> None:
        policy = self.policy
        if policy.mode != Mode.ENFORCE:
            return
        now = self._clock()
        for record in addresses:
            if policy.address_denied(record.address):
                self._safe_append(
                    {
                        "ts": now,
                        "event": "dns_answer_denied",
                        "engagement": policy.engagement,
                        "decision": "drop",
                        "qname": name.rstrip(".").lower(),
                        "address": record.address,
                        "reason": "resolved_to_denied_range",
                    }
                )
                continue
            ttl = min(max(record.ttl, _MIN_LEARN_TTL), _MAX_LEARN_TTL)
            try:
                self.firewall.learn(record.address, ttl)
            except FirewallError as exc:
                log.error("guard: could not allow %s for %s: %s", record.address, name, exc)
                continue
            with self._lock:
                self._learned[record.address] = (name.rstrip(".").lower(), now + ttl)

    # ── drop accounting ─────────────────────────────────────────────

    def collect_drops(self) -> int:
        """Write a ledger record for every destination dropped since the last call."""
        try:
            counters = self.firewall.read_drops()
        except FirewallError as exc:
            log.error("guard: cannot read drop counters: %s", exc)
            return 0
        policy = self.policy
        written = 0
        with self._lock:
            for key, packets in counters.items():
                previous = self._drop_seen.get(key, 0)
                if packets <= previous:
                    continue
                self._drop_seen[key] = packets
                dst, proto, dport = key
                self._safe_append(
                    {
                        "ts": self._clock(),
                        "event": "egress_drop",
                        "engagement": policy.engagement,
                        "decision": "drop",
                        "dst_ip": dst,
                        "proto": proto,
                        "dport": dport,
                        "packets": packets - previous,
                        "packets_total": packets,
                        "mode": policy.mode.value,
                        "policy_sha256": policy.digest() if policy.mode != Mode.LOCKED else "",
                    }
                )
                written += 1
        return written

    def _safe_append(self, record: dict[str, Any]) -> None:
        try:
            self.ledger.append(record)
        except OSError as exc:
            log.error("guard: ledger write failed: %s", exc)


def make_handler(guard: Guard, token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "buggy-egress-guard"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            log.info("control: " + format, *args)

        def _reply(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorised(self) -> bool:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return False
            return hmac.compare_digest(header[len("Bearer ") :].encode(), token.encode())

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._reply(200, {"status": "ok", "mode": guard.policy.mode.value})
                return
            if not self._authorised():
                self._reply(401, {"detail": "missing or invalid bearer token"})
                return
            if self.path == "/status":
                self._reply(200, guard.status())
                return
            self._reply(404, {"detail": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._authorised():
                self._reply(401, {"detail": "missing or invalid bearer token"})
                return
            if self.path == "/flush-drops":
                self._reply(200, {"written": guard.collect_drops()})
                return
            if self.path != "/policy":
                self._reply(404, {"detail": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > _MAX_BODY:
                    raise ValueError("bad Content-Length")
                document = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(document, dict):
                    raise ValueError("body must be a JSON object")
                policy = Policy.from_wire(
                    document.get("policy"), engagement=str(document.get("engagement", ""))
                )
            except (ValueError, UnicodeDecodeError) as exc:
                self._reply(400, {"applied": False, "detail": f"invalid policy: {exc}"})
                return
            try:
                result = guard.apply(policy)
            except (FirewallError, OSError) as exc:
                log.error("guard: policy load failed: %s", exc)
                self._reply(500, {"applied": False, "detail": f"policy not loaded: {exc}"})
                return
            self._reply(200, result)

    return Handler


def _split_env(name: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in os.environ.get(name, "").split(",") if part.strip())


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    token = (os.environ.get("EGRESS_GUARD_TOKEN") or "").strip()
    if len(token) < 16:
        raise GuardStartupError("EGRESS_GUARD_TOKEN must be set (at least 16 characters)")
    subnet = (os.environ.get("BUGGY_SANDBOX_SUBNET") or "").strip()
    if not subnet:
        raise GuardStartupError("BUGGY_SANDBOX_SUBNET must be set")

    sandbox_ip = (os.environ.get("BUGGY_SANDBOX_IP") or "").strip()
    if not sandbox_ip:
        raise GuardStartupError("BUGGY_SANDBOX_IP must be set")
    tunnel_subnet = (os.environ.get("BUGGY_TUNNEL_SUBNET") or DEFAULT_TUNNEL_SUBNET).strip()
    vni = int(os.environ.get("BUGGY_TUNNEL_VNI") or DEFAULT_TUNNEL_VNI)

    topology, control_ifs = discover_topology(
        list_interfaces(),
        sandbox_subnet=subnet,
        sandbox_ip=sandbox_ip,
        tunnel_subnet=tunnel_subnet,
        local_target_cidrs=_split_env("BUGGY_GUARD_LOCAL_TARGET_CIDRS"),
    )
    create_tunnel(topology, tunnel_subnet=tunnel_subnet, vni=vni)
    ledger = Ledger(Path(os.environ.get("BUGGY_GUARD_LEDGER") or DEFAULT_LEDGER))
    guard = Guard(Firewall(topology), ledger)  # loads the LOCKED ruleset or raises
    ledger.append(
        {
            "ts": time.time(),
            "event": "guard_started",
            "mode": Mode.LOCKED.value,
            "tunnel_cidr": topology.tunnel_cidr,
            "protected_cidrs": list(topology.protected_cidrs),
        }
    )
    log.info(
        "guard: locked; underlay=%s tunnel=%s peer=%s protected=%s",
        topology.underlay_if,
        topology.tunnel_if,
        topology.peer_ip,
        ",".join(topology.protected_cidrs),
    )

    upstreams = list(_split_env("BUGGY_GUARD_UPSTREAM_DNS")) or dnsproxy.read_resolvers()
    if not upstreams:
        raise GuardStartupError("no upstream DNS resolver available")
    resolver = dnsproxy.Resolver(
        decide=guard.decide_name,
        on_refused=guard.on_refused,
        on_answer=guard.on_answer,
        upstreams=upstreams,
    )
    dnsproxy.serve(resolver, topology.underlay_ip, 53)

    port = int(os.environ.get("BUGGY_GUARD_CONTROL_PORT") or DEFAULT_CONTROL_PORT)
    handler = make_handler(guard, token)
    for uplink in control_ifs:
        server = ThreadingHTTPServer((uplink.address, port), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        log.info("guard: control API on %s:%d", uplink.address, port)
    health = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=health.serve_forever, daemon=True).start()

    while True:
        time.sleep(1.0)
        guard.collect_drops()


if __name__ == "__main__":
    main()
