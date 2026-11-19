"""Unit tests for the egress guard (policy, DNS proxy, ruleset, service).

The guard's behaviour against a real kernel is covered by
``tests/e2e/test_scope_enforcement_e2e.py``; these tests pin the logic that
decides what is rendered and what is answered.
"""

from __future__ import annotations

import json
import socket
import struct
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from buggy.egress_guard import dns as dnsproxy
from buggy.egress_guard.firewall import (
    Firewall,
    FirewallError,
    Topology,
    parse_drop_set,
    render_ruleset,
)
from buggy.egress_guard.ledger import Ledger
from buggy.egress_guard.policy import Mode, Policy, glob_match
from buggy.egress_guard.service import (
    Guard,
    GuardStartupError,
    Interface,
    discover_topology,
    list_interfaces,
    make_handler,
    tunnel_addresses,
    tunnel_commands,
)
from buggy.middleware._audit_sink import iter_records, verify_ledger
from buggy.middleware.egress import compile_egress_policy, policy_digest
from buggy_core.types.roe import MachineEnforcement

TOPOLOGY = Topology(
    underlay_if="eth1",
    underlay_ip="172.30.250.2",
    peer_ip="172.30.250.3",
    tunnel_if="bgtun0",
    tunnel_cidr="10.254.250.0/30",
    protected_cidrs=("172.18.0.0/16", "172.30.250.0/24"),
)


def _wire(**overrides) -> dict:
    base = {
        "enforce": True,
        "default_drop": True,
        "allowed_cidrs": ["203.0.113.0/24"],
        "allowed_hosts": ["app.acme.test", "*.api.acme.test"],
        "denied_cidrs": ["169.254.169.254"],
        "denied_hosts": ["admin.acme.test"],
    }
    base.update(overrides)
    return base


# ── policy ───────────────────────────────────────────────────────────


class TestPolicy:
    def test_locked_policy_resolves_nothing(self) -> None:
        assert Policy.locked().name_decision("app.acme.test") == (False, "no_policy")

    def test_allowlist_and_denylist(self) -> None:
        policy = Policy.from_wire(_wire())
        assert policy.name_decision("app.acme.test")[0] is True
        assert policy.name_decision("APP.acme.test.")[0] is True
        assert policy.name_decision("v1.api.acme.test")[0] is True
        assert policy.name_decision("other.acme.test") == (False, "not_in_scope")
        assert policy.name_decision("admin.acme.test")[0] is False

    def test_wildcard_is_one_label_like_the_parser(self) -> None:
        # Same semantics as buggy_core.types.roe._glob_match.
        assert glob_match("*.acme.test", "a.acme.test")
        assert not glob_match("*.acme.test", "acme.test")
        assert not glob_match("*.acme.test", "a.b.acme.test")
        policy = Policy.from_wire(_wire(allowed_hosts=["*.acme.test"], denied_hosts=[]))
        assert policy.name_decision("deep.sub.acme.test")[0] is False

    def test_deny_wins_over_allow(self) -> None:
        policy = Policy.from_wire(
            _wire(allowed_hosts=["*.acme.test"], denied_hosts=["admin.acme.test"])
        )
        assert policy.name_decision("admin.acme.test")[0] is False
        assert policy.name_decision("www.acme.test")[0] is True

    def test_non_enforcing_policy_is_open(self) -> None:
        policy = Policy.from_wire(_wire(enforce=False))
        assert policy.mode == Mode.OPEN
        assert policy.name_decision("anything.example")[0] is True

    def test_wildcard_deny_forces_default_drop(self) -> None:
        policy = Policy.from_wire(
            _wire(default_drop=False, allowed_hosts=[], denied_hosts=["*.corp.acme.test"])
        )
        assert policy.default_drop is True

    def test_deny_only_policy_allows_other_names(self) -> None:
        policy = Policy.from_wire(
            _wire(default_drop=False, allowed_hosts=[], denied_hosts=["admin.acme.test"])
        )
        assert policy.name_decision("www.example.org")[0] is True
        assert policy.name_decision("admin.acme.test")[0] is False

    def test_malformed_entries_are_dropped_not_trusted(self) -> None:
        policy = Policy.from_wire(
            _wire(
                allowed_cidrs=["10.0.0.0/8", "not-a-cidr", "0.0.0.0/0; drop"],
                allowed_hosts=["ok.test", "bad host}", "{ 1.2.3.4 }"],
            )
        )
        assert policy.allowed_cidrs == ("10.0.0.0/8",)
        assert policy.allowed_hosts == ("ok.test",)

    @pytest.mark.parametrize("bad", [None, [], {"enforce": "yes"}, {}])
    def test_invalid_wire_documents_are_rejected(self, bad) -> None:
        with pytest.raises(ValueError):
            Policy.from_wire(bad)

    def test_address_denied(self) -> None:
        policy = Policy.from_wire(_wire(denied_cidrs=["169.254.169.254", "10.0.0.0/8"]))
        assert policy.address_denied("169.254.169.254")
        assert policy.address_denied("10.1.2.3")
        assert not policy.address_denied("203.0.113.9")
        assert policy.address_denied("not-an-ip")

    def test_digest_matches_the_langgraph_side(self) -> None:
        rules = MachineEnforcement.from_dict(
            {"mode": "enforce", "in_scope": ["app.acme.test", "203.0.113.0/24"]}
        )
        compiled = compile_egress_policy(rules)
        assert Policy.from_wire(compiled.to_dict()).digest() == policy_digest(compiled)


# ── DNS ──────────────────────────────────────────────────────────────


def _query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    body = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + body + struct.pack("!HH", qtype, 1)


def _answer(query: bytes, records: list[tuple[int, bytes, int]]) -> bytes:
    """Response to ``query`` with ``(type, rdata, ttl)`` records using name compression."""
    header = struct.pack(
        "!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8180, 1, len(records), 0, 0
    )
    out = header + query[12:]
    for rtype, rdata, ttl in records:
        out += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return out


class TestDNS:
    def test_parse_question(self) -> None:
        question = dnsproxy.parse_question(_query("App.Acme.test", qtype=28))
        assert (question.name, question.qtype, question.txid) == ("App.Acme.test", 28, 0x1234)

    @pytest.mark.parametrize(
        "packet",
        [b"", b"\x00" * 5, _query("a.test")[:14], struct.pack("!HHHHHH", 1, 0x8000, 1, 0, 0, 0)],
    )
    def test_malformed_queries_raise(self, packet: bytes) -> None:
        with pytest.raises(dnsproxy.DNSParseError):
            dnsproxy.parse_question(packet)

    def test_compression_loop_is_rejected(self) -> None:
        packet = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
        with pytest.raises(dnsproxy.DNSParseError, match="loop"):
            dnsproxy.parse_question(packet)

    def test_refusal_keeps_id_and_question(self) -> None:
        query = _query("out.test")
        reply = dnsproxy.build_error(query, dnsproxy.RCODE_REFUSED)
        txid, flags, qd, an = struct.unpack("!HHHH", reply[:8])
        assert txid == 0x1234 and qd == 1 and an == 0
        assert flags & 0x8000 and flags & 0x000F == dnsproxy.RCODE_REFUSED
        assert reply[12:] == query[12:]

    def test_extract_addresses_follows_compression_and_skips_other_types(self) -> None:
        query = _query("app.acme.test")
        response = _answer(
            query,
            [
                (5, b"\x03cdn\xc0\x10", 60),  # CNAME
                (1, socket.inet_aton("203.0.113.7"), 300),
                (28, b"\x00" * 16, 300),  # AAAA: ignored (IPv6 is never forwarded)
                (1, socket.inet_aton("203.0.113.8"), 5),
            ],
        )
        found = dnsproxy.extract_addresses(response)
        assert [(a.address, a.ttl) for a in found] == [("203.0.113.7", 300), ("203.0.113.8", 5)]

    def _resolver(self, policy: Policy, upstream):
        refused: list[tuple] = []
        answered: list[tuple] = []
        resolver = dnsproxy.Resolver(
            decide=policy.name_decision,
            on_refused=lambda *a: refused.append(a),
            on_answer=lambda name, addrs: answered.append((name, [x.address for x in addrs])),
            upstreams=["192.0.2.53"],
            udp_forward=upstream,
            tcp_forward=upstream,
        )
        return resolver, refused, answered

    def test_out_of_scope_name_is_refused_and_never_forwarded(self) -> None:
        forwarded: list[bytes] = []

        def upstream(query: bytes, _server: str) -> bytes:
            forwarded.append(query)
            return _answer(query, [(1, socket.inet_aton("198.51.100.1"), 60)])

        resolver, refused, answered = self._resolver(Policy.from_wire(_wire()), upstream)
        reply = resolver.handle(_query("evil.example"), "172.30.250.3", tcp=False)
        assert struct.unpack("!H", reply[2:4])[0] & 0xF == dnsproxy.RCODE_REFUSED
        assert forwarded == []
        assert refused == [("evil.example", 1, "not_in_scope", "172.30.250.3")]
        assert answered == []

    def test_in_scope_name_is_forwarded_and_addresses_reported(self) -> None:
        def upstream(query: bytes, _server: str) -> bytes:
            return _answer(query, [(1, socket.inet_aton("203.0.113.7"), 120)])

        resolver, refused, answered = self._resolver(Policy.from_wire(_wire()), upstream)
        query = _query("app.acme.test")
        assert resolver.handle(query, "172.30.250.3", tcp=False)[:2] == query[:2]
        assert refused == []
        assert answered == [("app.acme.test", ["203.0.113.7"])]

    def test_upstream_failure_is_servfail_not_a_leak(self) -> None:
        def upstream(_query: bytes, _server: str) -> bytes:
            raise OSError("timeout")

        resolver, _refused, answered = self._resolver(Policy.from_wire(_wire()), upstream)
        reply = resolver.handle(_query("app.acme.test"), "c", tcp=False)
        assert struct.unpack("!H", reply[2:4])[0] & 0xF == dnsproxy.RCODE_SERVFAIL
        assert answered == []

    def test_unreadable_answer_is_not_passed_through(self) -> None:
        def upstream(query: bytes, _server: str) -> bytes:
            return _answer(query, [(1, socket.inet_aton("203.0.113.7"), 120)])[:-2]

        resolver, _refused, answered = self._resolver(Policy.from_wire(_wire()), upstream)
        reply = resolver.handle(_query("app.acme.test"), "c", tcp=False)
        assert struct.unpack("!H", reply[2:4])[0] & 0xF == dnsproxy.RCODE_SERVFAIL
        assert answered == []

    def test_garbage_query_is_refused(self) -> None:
        resolver, _refused, _answered = self._resolver(Policy.from_wire(_wire()), lambda q, s: q)
        reply = resolver.handle(b"\x12\x34garbage", "c", tcp=False)
        assert struct.unpack("!H", reply[2:4])[0] & 0xF == dnsproxy.RCODE_REFUSED


# ── ruleset ──────────────────────────────────────────────────────────


def _forward_rules(ruleset: str) -> list[str]:
    block = ruleset.split("  chain forward {")[1].split("  }")[0]
    return [line.strip() for line in block.strip().splitlines()]


class TestRuleset:
    def test_locked_forwards_nothing(self) -> None:
        rules = _forward_rules(render_ruleset(Policy.locked(), TOPOLOGY))
        assert rules[0] == "type filter hook forward priority 0; policy drop;"
        assert rules[-1] == "jump dropped"
        assert not any(r.endswith("accept") and "established" not in r for r in rules)

    def test_enforce_order_is_protected_deny_allow_then_default(self) -> None:
        rules = _forward_rules(render_ruleset(Policy.from_wire(_wire()), TOPOLOGY))
        order = [
            rules.index('iifname != "bgtun0" drop'),
            rules.index("ip daddr @protected4 jump dropped"),
            rules.index("ip daddr @deny4 jump dropped"),
            rules.index("ip daddr @allow4 accept"),
            rules.index("ip daddr @dyn4 accept"),
            rules.index("jump dropped"),
        ]
        assert order == sorted(order)
        assert "accept" not in rules  # no bare accept when default_drop

    def test_deny_only_policy_accepts_after_denies(self) -> None:
        policy = Policy.from_wire(
            _wire(default_drop=False, allowed_hosts=[], allowed_cidrs=[], denied_hosts=[])
        )
        rules = _forward_rules(render_ruleset(policy, TOPOLOGY))
        assert rules.index("ip daddr @deny4 jump dropped") < rules.index("accept")

    def test_open_mode_still_protects_the_management_plane(self) -> None:
        rules = _forward_rules(render_ruleset(Policy.from_wire(_wire(enforce=False)), TOPOLOGY))
        assert rules.index("ip daddr @protected4 jump dropped") < rules.index("accept")
        assert "ip daddr @deny4 jump dropped" not in rules

    def test_sets_carry_policy_and_topology(self) -> None:
        ruleset = render_ruleset(
            Policy.from_wire(_wire()),
            TOPOLOGY,
            resolved_denied_ips=["198.51.100.9"],
            learned=[("203.0.113.50", 120), ("203.0.113.51", 0)],
        )
        assert "elements = { 172.18.0.0/16, 172.30.250.0/24 }" in ruleset
        assert "elements = { 203.0.113.0/24 }" in ruleset
        assert "elements = { 169.254.169.254/32, 198.51.100.9/32 }" in ruleset
        assert "elements = { 203.0.113.50 timeout 120s }" in ruleset
        assert "203.0.113.51" not in ruleset

    def test_input_only_admits_dns_and_the_tunnel_peer(self) -> None:
        ruleset = render_ruleset(Policy.locked(), TOPOLOGY)
        block = ruleset.split("  chain input {")[1].split("  }")[0]
        assert 'iifname "eth1" ip saddr 172.30.250.3 udp dport 4789 accept' in block
        assert 'iifname "eth1" udp dport 53 accept' in block
        assert block.strip().splitlines()[-1].strip() == 'iifname "eth1" drop'
        assert "9440" not in ruleset  # the control port is never opened to the sandbox side

    def test_load_is_atomic_replace_and_surfaces_nft_errors(self) -> None:
        calls: list[tuple] = []

        def runner(argv, stdin):
            calls.append((tuple(argv), stdin))
            return subprocess.CompletedProcess(argv, 1, "", "syntax error")

        with pytest.raises(FirewallError, match="syntax error"):
            Firewall(TOPOLOGY, runner=runner).load(Policy.locked())
        argv, stdin = calls[0]
        assert argv == ("nft", "-f", "-")
        assert "add table inet buggy_guard\ndelete table inet buggy_guard\n" in stdin

    def test_parse_drop_set(self) -> None:
        raw = json.dumps(
            {
                "nftables": [
                    {"metainfo": {}},
                    {
                        "set": {
                            "name": "drops",
                            "elem": [
                                {
                                    "elem": {
                                        "val": {"concat": ["198.51.100.7", "tcp", 443]},
                                        "counter": {"packets": 3, "bytes": 180},
                                    }
                                },
                                {"elem": {"val": {"concat": ["198.51.100.8", "icmp"]}}},
                            ],
                        }
                    },
                ]
            }
        )
        assert parse_drop_set(raw) == [
            (("198.51.100.7", "tcp", 443), 3),
            (("198.51.100.8", "icmp", None), 0),
        ]
        assert parse_drop_set("not json") == []


# ── topology ─────────────────────────────────────────────────────────

_IFACES = [
    Interface("eth0", "172.18.0.2", "172.18.0.0/16"),
    Interface("eth1", "172.30.250.2", "172.30.250.0/24"),
    Interface("eth2", "172.30.251.2", "172.30.251.0/24"),
]


class TestTopology:
    def test_list_interfaces_parses_ip_json(self) -> None:
        raw = json.dumps(
            [
                {
                    "ifname": "lo",
                    "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}],
                },
                {
                    "ifname": "eth0",
                    "addr_info": [{"family": "inet", "local": "172.18.0.2", "prefixlen": 16}],
                },
            ]
        )
        assert list_interfaces(raw) == [Interface("eth0", "172.18.0.2", "172.18.0.0/16")]

    def test_target_networks_are_not_protected_and_get_no_control_api(self) -> None:
        topology, control = discover_topology(
            _IFACES,
            sandbox_subnet="172.30.250.0/24",
            sandbox_ip="172.30.250.3",
            local_target_cidrs=("172.30.251.0/24",),
        )
        assert topology.underlay_if == "eth1" and topology.peer_ip == "172.30.250.3"
        assert topology.protected_cidrs == ("172.18.0.0/16", "172.30.250.0/24")
        assert [i.name for i in control] == ["eth0"]

    def test_every_uplink_is_protected_by_default(self) -> None:
        topology, control = discover_topology(
            _IFACES, sandbox_subnet="172.30.250.0/24", sandbox_ip="172.30.250.3"
        )
        assert "172.30.251.0/24" in topology.protected_cidrs
        assert [i.name for i in control] == ["eth0", "eth2"]

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"sandbox_subnet": "10.9.0.0/24", "sandbox_ip": "10.9.0.3"}, "exactly one interface"),
            (
                {"sandbox_subnet": "172.30.250.0/24", "sandbox_ip": "10.0.0.1"},
                "outside sandbox subnet",
            ),
            ({"sandbox_subnet": "nope", "sandbox_ip": "172.30.250.3"}, "not a CIDR"),
        ],
    )
    def test_bad_topology_refuses_to_start(self, kwargs, match) -> None:
        with pytest.raises(GuardStartupError, match=match):
            discover_topology(_IFACES, **kwargs)

    def test_no_uplink_refuses_to_start(self) -> None:
        with pytest.raises(GuardStartupError, match="no uplink"):
            discover_topology(
                [_IFACES[1]], sandbox_subnet="172.30.250.0/24", sandbox_ip="172.30.250.3"
            )

    def test_tunnel_commands(self) -> None:
        assert tunnel_addresses("10.254.250.0/30") == ("10.254.250.1", "10.254.250.2", 30)
        commands = tunnel_commands(TOPOLOGY, tunnel_subnet="10.254.250.0/30", vni=4242)
        assert commands[0][:6] == ["ip", "link", "add", "bgtun0", "type", "vxlan"]
        assert "172.30.250.3" in commands[0] and "172.30.250.2" in commands[0]
        assert commands[1] == ["ip", "addr", "add", "10.254.250.1/30", "dev", "bgtun0"]
        with pytest.raises(GuardStartupError):
            tunnel_addresses("10.0.0.0/32")


# ── service ──────────────────────────────────────────────────────────


class _FakeNft:
    """Records ``nft`` invocations and serves canned drop counters."""

    def __init__(self) -> None:
        self.loaded: list[str] = []
        self.learned: list[str] = []
        self.drops: dict[tuple[str, str, int], int] = {}
        self.fail_load = False

    def __call__(self, argv, stdin):
        argv = list(argv)
        if argv[:3] == ["nft", "-f", "-"]:
            if self.fail_load:
                return subprocess.CompletedProcess(argv, 1, "", "boom")
            self.loaded.append(stdin)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["nft", "add", "element"]:
            self.learned.append(argv[-1])
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:4] == ["nft", "-j", "list", "set"]:
            elems = (
                [
                    {"elem": {"val": {"concat": list(key)}, "counter": {"packets": count}}}
                    for key, count in self.drops.items()
                ]
                if argv[-1] == "drops"
                else []
            )
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"nftables": [{"set": {"elem": elems}}]}), ""
            )
        raise AssertionError(f"unexpected nft call: {argv}")


@pytest.fixture
def guard_env(tmp_path: Path):
    nft = _FakeNft()
    ledger_path = tmp_path / "egress" / "egress-decisions.jsonl"
    guard = Guard(
        Firewall(TOPOLOGY, runner=nft),
        Ledger(ledger_path, hmac_key=b"k" * 32),
        resolve=lambda host: {"admin.acme.test": ["198.51.100.9"]}.get(host, []),
    )
    return guard, nft, ledger_path


class TestGuard:
    def test_starts_locked(self, guard_env) -> None:
        guard, nft, _ledger = guard_env
        assert guard.policy.mode == Mode.LOCKED
        assert len(nft.loaded) == 1
        assert guard.decide_name("app.acme.test") == (False, "no_policy")

    def test_apply_loads_rules_resolves_literal_denies_and_logs(self, guard_env) -> None:
        guard, nft, ledger = guard_env
        result = guard.apply(Policy.from_wire(_wire(), engagement="acme"))
        assert result["applied"] is True and result["mode"] == "enforce"
        assert result["resolved_denied_ips"] == ["198.51.100.9"]
        assert "198.51.100.9/32" in nft.loaded[-1]
        record = list(iter_records(ledger))[-1]
        assert record["event"] == "policy_applied" and record["engagement"] == "acme"

    def test_failed_load_keeps_previous_policy(self, guard_env) -> None:
        guard, nft, _ledger = guard_env
        nft.fail_load = True
        with pytest.raises(FirewallError):
            guard.apply(Policy.from_wire(_wire()))
        assert guard.policy.mode == Mode.LOCKED

    def test_allowed_answers_are_learned_denied_ranges_are_not(self, guard_env) -> None:
        guard, nft, ledger = guard_env
        guard.apply(Policy.from_wire(_wire(), engagement="acme"))
        guard.on_answer(
            "app.acme.test",
            [
                dnsproxy.Address("app.acme.test", "203.0.113.7", 5),
                dnsproxy.Address("app.acme.test", "169.254.169.254", 300),
            ],
        )
        assert nft.learned == ["{ 203.0.113.7 timeout 60s }"]  # TTL floored
        events = [r["event"] for r in iter_records(ledger)]
        assert "dns_answer_denied" in events

    def test_learned_addresses_survive_a_reload_only_if_still_in_scope(self, guard_env) -> None:
        guard, nft, _ledger = guard_env
        guard.apply(Policy.from_wire(_wire()))
        guard.on_answer("app.acme.test", [dnsproxy.Address("app.acme.test", "203.0.113.7", 600)])
        guard.on_answer(
            "v1.api.acme.test", [dnsproxy.Address("v1.api.acme.test", "203.0.113.9", 600)]
        )
        guard.apply(Policy.from_wire(_wire(allowed_hosts=["app.acme.test"])))
        assert "203.0.113.7 timeout" in nft.loaded[-1]
        assert "203.0.113.9" not in nft.loaded[-1]

    def test_drops_are_logged_once_per_new_packet(self, guard_env) -> None:
        guard, nft, ledger = guard_env
        guard.apply(Policy.from_wire(_wire(), engagement="acme"))
        nft.drops[("198.51.100.7", "tcp", 443)] = 2
        assert guard.collect_drops() == 1
        assert guard.collect_drops() == 0
        nft.drops[("198.51.100.7", "tcp", 443)] = 5
        assert guard.collect_drops() == 1
        drops = [r for r in iter_records(ledger) if r["event"] == "egress_drop"]
        assert [(d["dst_ip"], d["dport"], d["packets"]) for d in drops] == [
            ("198.51.100.7", 443, 2),
            ("198.51.100.7", 443, 3),
        ]
        assert all(d["engagement"] == "acme" and d["decision"] == "drop" for d in drops)

    def test_refusals_are_logged(self, guard_env) -> None:
        guard, _nft, ledger = guard_env
        guard.on_refused("Evil.Example.", 1, "no_policy", "172.30.250.3")
        record = list(iter_records(ledger))[-1]
        assert (record["event"], record["qname"]) == ("dns_refused", "evil.example")

    def test_ledger_chain_verifies_with_the_shared_verifier(self, guard_env) -> None:
        guard, nft, ledger = guard_env
        guard.apply(Policy.from_wire(_wire(), engagement="acme"))
        nft.drops[("198.51.100.7", "tcp", 80)] = 1
        guard.collect_drops()
        assert verify_ledger(ledger, hmac_key=b"k" * 32).ok
        lines = ledger.read_text().splitlines()
        tampered = json.loads(lines[-1])
        tampered["dst_ip"] = "10.0.0.1"
        ledger.write_text("\n".join([*lines[:-1], json.dumps(tampered)]) + "\n")
        assert not verify_ledger(ledger, hmac_key=b"k" * 32).ok


class TestControlAPI:
    @pytest.fixture
    def api(self, guard_env):
        guard, nft, _ledger = guard_env
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(guard, "t" * 32))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        yield f"http://127.0.0.1:{server.server_address[1]}", guard, nft
        server.shutdown()
        server.server_close()

    def _post(self, url: str, body, token: str | None = "t" * 32):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_healthz_is_open_and_reports_mode(self, api) -> None:
        url, _guard, _nft = api
        with urllib.request.urlopen(f"{url}/healthz", timeout=5) as response:  # noqa: S310
            assert json.loads(response.read()) == {"status": "ok", "mode": "locked"}

    @pytest.mark.parametrize("token", [None, "wrong" * 8])
    def test_policy_requires_the_token(self, api, token) -> None:
        url, guard, _nft = api
        status, _body = self._post(f"{url}/policy", {"policy": _wire()}, token=token)
        assert status == 401
        assert guard.policy.mode == Mode.LOCKED

    def test_policy_push_applies(self, api) -> None:
        url, guard, _nft = api
        status, body = self._post(f"{url}/policy", {"engagement": "acme", "policy": _wire()})
        assert status == 200 and body["applied"] is True
        assert guard.policy.mode == Mode.ENFORCE and guard.policy.engagement == "acme"

    @pytest.mark.parametrize("body", [b"not json", {"policy": []}, {"policy": {"enforce": 1}}, []])
    def test_invalid_policy_is_rejected_and_nothing_changes(self, api, body) -> None:
        url, guard, _nft = api
        status, reply = self._post(f"{url}/policy", body)
        assert status == 400 and reply["applied"] is False
        assert guard.policy.mode == Mode.LOCKED

    def test_load_failure_is_reported_as_not_applied(self, api) -> None:
        url, guard, nft = api
        nft.fail_load = True
        status, reply = self._post(f"{url}/policy", {"policy": _wire()})
        assert status == 500 and reply["applied"] is False
        assert guard.policy.mode == Mode.LOCKED
