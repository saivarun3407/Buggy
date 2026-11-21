"""Wildcard DNS filter: names a wildcard record answers for are not hosts.

Two layers. The functions in ``buggy.pipeline.wildcard`` are tested on their
own with a dictionary for a resolver. Then the real pipeline is driven with the
recording fake scanners from ``test_pipeline_flow``, whose DNS is replaced by a
small zone model (fixed answers, plus an optional wildcard that answers for
every other name under a root), and the tests check what reached the store,
the scope-drop log, the coverage stamps and the later tools.

Every "these names are dropped" test has a control where nothing is.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import random
from collections.abc import Callable
from pathlib import Path

import pytest

from buggy.pipeline.pipeline import WILDCARD_STAGE, Pipeline
from buggy.pipeline.runner import RunResult
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools.base import Invocation
from buggy.pipeline.wildcard import WildcardInfo, detect, filter_names, probe_names, suspected

from .test_pipeline_flow import ROE, FakeOpener, FakeTools

ROOT = "acme.test"
WILD = "198.51.100.7"  # what the wildcard record answers
SHARED = "198.51.100.80"  # one load balancer in front of many real names

# ── the functions ───────────────────────────────────────────────────


class _Resolver:
    """``resolve`` over fixed answers; ``wild`` answers for every other name."""

    def __init__(
        self, answers: dict[str, set[str]], wild: Callable[[str], set[str]] | None
    ) -> None:
        self.answers = answers
        self.wild = wild
        self.asked: list[list[str]] = []

    def __call__(self, names: list[str]) -> dict[str, set[str]]:
        self.asked.append(list(names))
        out = {}
        for name in names:
            found = self.answers.get(name) or (self.wild(name) if self.wild else set())
            if found:
                out[name] = set(found)
        return out


def _resolver(
    answers: dict[str, set[str]], wild: Callable[[str], set[str]] | None = None
) -> _Resolver:
    """``resolve`` over fixed answers; ``wild`` answers for every other name."""
    return _Resolver(answers, wild)


class TestProbeNames:
    def test_three_distinct_sixteen_character_labels_under_the_root(self) -> None:
        names = probe_names(ROOT)
        assert len(names) == len(set(names)) == 3
        for name in names:
            label, _, parent = name.partition(".")
            assert parent == ROOT
            assert len(label) == 16 and label.isalnum() and label == label.lower()

    def test_n_is_honoured(self) -> None:
        assert len(probe_names(ROOT, n=5)) == 5

    def test_injected_rng_makes_the_names_reproducible(self) -> None:
        first = probe_names(ROOT, rng=random.Random(7))
        assert first == probe_names(ROOT, rng=random.Random(7))
        assert first != probe_names(ROOT, rng=random.Random(8))  # the seed is what decides

    def test_default_rng_is_not_reproducible(self) -> None:
        assert probe_names(ROOT) != probe_names(ROOT)


class TestDetect:
    def test_all_probes_on_one_address_set_is_a_wildcard(self) -> None:
        resolve = _resolver({}, wild=lambda _name: {WILD, "2001:db8::7"})
        info = detect(ROOT, resolve)
        assert info == WildcardInfo(ROOT, True, frozenset({WILD, "2001:db8::7"}))
        (asked,) = resolve.asked  # one resolver call, three random names
        assert len(asked) == 3 and all(name.endswith("." + ROOT) for name in asked)

    def test_probes_that_do_not_resolve_are_not_a_wildcard(self) -> None:
        assert detect(ROOT, _resolver({})) == WildcardInfo(ROOT, False, frozenset())

    def test_one_probe_without_an_answer_is_not_a_wildcard(self) -> None:
        names = probe_names(ROOT, rng=random.Random(3))
        answers = {names[0]: {WILD}, names[1]: {WILD}}  # the third gets nothing
        assert not detect(ROOT, _resolver(answers), rng=random.Random(3)).is_wildcard

    def test_rotating_addresses_are_treated_as_not_a_wildcard(self) -> None:
        """A wildcard that answers each name differently gives nothing to compare with.

        The choice: without one stable address set no enumerated name can be
        told apart from a made-up one, so the zone is reported as not a
        wildcard and nothing is dropped, rather than dropping names that may
        be real.
        """
        counter = itertools.count(1)
        info = detect(ROOT, _resolver({}, wild=lambda _name: {f"203.0.113.{next(counter)}"}))
        assert info == WildcardInfo(ROOT, False, frozenset())

    def test_detection_is_deterministic_with_an_injected_rng(self) -> None:
        first, second = _resolver({}), _resolver({})
        detect(ROOT, first, rng=random.Random(11))
        detect(ROOT, second, rng=random.Random(11))
        assert first.asked == second.asked == [probe_names(ROOT, rng=random.Random(11))]


class TestFilterNames:
    INFO = WildcardInfo(ROOT, True, frozenset({WILD}))
    RESOLVED = {
        "fake.acme.test": {WILD},
        "deep.fake.acme.test": {WILD},
        "real.acme.test": {"192.0.2.21"},
        "both.acme.test": {WILD, "192.0.2.22"},
        "silent.acme.test": set(),
        "app.acme.test": {WILD},
        ROOT: {WILD},
        "www.other.test": {WILD},
    }

    def test_only_names_on_the_wildcard_address_set_are_dropped(self) -> None:
        kept, dropped = filter_names(list(self.RESOLVED), self.INFO, self.RESOLVED)
        assert dropped == ["fake.acme.test", "deep.fake.acme.test", "app.acme.test"]
        assert kept == [
            "real.acme.test",  # resolves elsewhere
            "both.acme.test",  # a different set, even though it contains the wildcard address
            "silent.acme.test",  # does not resolve: nothing to compare
            ROOT,  # the root itself
            "www.other.test",  # not under this root
        ]

    def test_explicit_names_are_kept_on_the_wildcard_address(self) -> None:
        kept, dropped = filter_names(
            list(self.RESOLVED), self.INFO, self.RESOLVED, explicit={"app.acme.test"}
        )
        assert "app.acme.test" in kept
        assert dropped == ["fake.acme.test", "deep.fake.acme.test"]  # the others still go

    def test_nothing_is_dropped_outside_a_wildcard_zone(self) -> None:
        names = list(self.RESOLVED)
        assert filter_names(names, WildcardInfo(ROOT, False), self.RESOLVED) == (names, [])


class TestSuspected:
    def test_names_sharing_an_address_set_are_worth_a_probe(self) -> None:
        resolved = {"a.acme.test": {WILD}, "b.acme.test": {WILD}, "c.acme.test": {"192.0.2.9"}}
        assert suspected(list(resolved), ROOT, resolved)

    def test_a_name_sharing_the_root_address_is_worth_a_probe(self) -> None:
        resolved = {ROOT: {WILD}, "a.acme.test": {WILD}}
        assert suspected(list(resolved), ROOT, resolved)

    def test_every_name_on_its_own_address_is_not(self) -> None:
        resolved = {
            "a.acme.test": {"192.0.2.1"},
            "b.acme.test": {"192.0.2.2"},
            "c.acme.test": set(),
        }
        assert not suspected(list(resolved), ROOT, resolved)

    def test_names_that_do_not_resolve_are_not(self) -> None:
        resolved = {"a.acme.test": set(), "b.acme.test": set()}
        assert not suspected(list(resolved), ROOT, resolved)

    def test_shared_addresses_among_names_that_cannot_be_dropped_are_not(self) -> None:
        resolved = {ROOT: {WILD}, "app.acme.test": {WILD}}
        assert not suspected(list(resolved), ROOT, resolved, explicit={"app.acme.test"})

    def test_a_lone_wildcard_name_is_not_caught(self) -> None:
        """The known limit of probing on evidence: one made-up name, no twin, no probe."""
        resolved = {"only.acme.test": {WILD}, "real.acme.test": {"192.0.2.21"}}
        assert not suspected(list(resolved), ROOT, resolved)


# ── the pipeline ────────────────────────────────────────────────────


class ZoneTools(FakeTools):
    """``FakeTools`` over a zone the test controls.

    ``enumerated`` is what subdomain enumeration returns, ``address`` the
    names with their own records, and ``wildcard`` maps a root to the answer
    every *other* name under it gets (a callable, so it can rotate).
    """

    def __init__(self) -> None:
        super().__init__()
        self.address: dict[str, str] = {}
        self.enumerated: list[str] = []
        self.wildcard: dict[str, Callable[[str], list[str]]] = {}
        self.fail_probes = False  # the wildcard probe run exits 1 with no output

    def _subfinder(self, roots: list[str]) -> str:
        return "".join(
            json.dumps({"host": h, "input": roots[0], "sources": ["anubis"]}) + "\n"
            for h in self.enumerated
        )

    def _amass(self, _roots: list[str]) -> str:
        return ""

    def _answer(self, host: str) -> list[str]:
        if host in self.address:
            return [self.address[host]]
        for root, answer in self.wildcard.items():
            if host.endswith("." + root):
                return answer(host)
        return []

    def _dnsx(self, hosts: list[str]) -> str:
        lines = [
            json.dumps({"host": host, "a": self._answer(host), "status_code": "NOERROR"})
            for host in hosts
            if self._answer(host)
        ]
        return "\n".join(lines) + "\n"

    def execute(self, name: str, invocation: Invocation, raw_path: Path) -> RunResult:
        result = super().execute(name, invocation, raw_path)
        if name == "dnsx" and self.fail_probes and "-wildcard-" in raw_path.name:
            raw_path.write_text("")
            return dataclasses.replace(
                result,
                exit_code=1,
                size=0,
                sha256=hashlib.sha256(b"").hexdigest(),
                stderr_tail="resolver unreachable",
            )
        return result


NAMES = [f"h{i:02d}.acme.test" for i in range(50)]
REAL = {"h07.acme.test": "192.0.2.21", "h31.acme.test": "192.0.2.22"}
FAKES = [name for name in NAMES if name not in REAL]
# Most tests only need a handful of names: six made-up ones and the two real ones.
SMALL = [*NAMES[:6], *REAL]
SMALL_FAKES = NAMES[:6]


@pytest.fixture
def env(tmp_path: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {"store": store, "root": tmp_path / "data", "tools": ZoneTools(), "opener": FakeOpener()}
    store.close()


def _pipeline(env, roe: dict | None = None, **kwargs) -> Pipeline:
    return Pipeline(
        env["store"],
        ScopeFilter.from_document(roe or ROE),
        "acme",
        data_root=env["root"],
        executor=env["tools"].execute,
        resolver=env["tools"].resolve,
        http_opener=env["opener"],
        passive_fetch=lambda _url: b"[]",
        sleep=lambda _s: None,
        **kwargs,
    )


def _roe(in_scope: list[str] | None = None, **pipeline_block) -> dict:
    roe = json.loads(json.dumps(ROE))
    if in_scope is not None:
        roe["machine_enforcement"]["in_scope"] = in_scope
    roe["pipeline"].update(pipeline_block)
    return roe


def _wildcard_zone(env, names: list[str] = SMALL) -> None:
    """``names`` enumerated; all but ``REAL`` exist only through ``*.acme.test``."""
    tools = env["tools"]
    tools.enumerated = list(names)
    tools.address = {name: address for name, address in REAL.items() if name in names}
    tools.wildcard = {ROOT: lambda _name: [WILD]}


def _shared_hosting_zone(env, names: list[str] = SMALL) -> None:
    """Real names behind one address, and no wildcard record."""
    env["tools"].enumerated = list(names)
    env["tools"].address = dict.fromkeys(names, SHARED)


def _dnsx_calls(env) -> list[list[str]]:
    return [inputs for name, inputs, _argv in env["tools"].calls if name == "dnsx"]


def _wildcard_drops(env, run_id: str) -> list[dict]:
    drops = env["store"].scope_drops("acme", run_id=run_id, limit=5000)
    return [d for d in drops if d["reason"] == "wildcard_dns"]


def _resolving(env) -> set[str]:
    """Assets with an active address record."""
    return {
        r.asset
        for r in env["store"].query_records("acme", record_type="dns_record", limit=1000)
        if r.attrs.get("rtype") in ("A", "AAAA")
    }


def _wildcard_records(env) -> list:
    return [
        r
        for r in env["store"].query_records("acme", record_type="dns_record", limit=1000)
        if r.attrs.get("wildcard")
    ]


def _expire(env, stage: str) -> None:
    with env["store"]._tx() as cur:  # noqa: SLF001 - test-only cache expiry
        cur.execute("DELETE FROM stage_cache WHERE stage = ?", (stage,))


class TestWildcardZone:
    def test_only_the_real_names_and_the_root_are_kept(self, env) -> None:
        _wildcard_zone(env, NAMES)
        env["tools"].address[ROOT] = WILD  # the apex sits on the wildcard address too
        summary = _pipeline(env).run()

        assert _resolving(env) == {*REAL, ROOT}
        drops = _wildcard_drops(env, summary["run_id"])
        assert len(drops) == 48
        assert sorted(d["candidate"] for d in drops) == FAKES
        assert {(d["stage"], d["tool"], d["direction"]) for d in drops} == {
            ("dns", "dnsx", "output")
        }
        assert summary["stages"]["dns"]["tools"]["dnsx"]["wildcard_dropped"] == 48
        assert summary["stages"]["dns"]["tools"]["dnsx"]["wildcard_roots"] == [ROOT]

    def test_dropped_names_reach_no_later_tool_and_no_later_record(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        later = [(n, i, a) for n, i, a in env["tools"].calls if n not in ("subfinder", "amass")]
        assert {"naabu", "httpx", "katana", "nuclei"} <= {name for name, _i, _a in later}
        for name, inputs, argv in later[1:]:  # later[0] is the dnsx run that resolved them
            blob = " ".join([*inputs, *argv])
            for fake in SMALL_FAKES:
                assert fake not in blob, f"{name} was given {fake}"
        for record in env["store"].query_records("acme", status=None, limit=1000):
            if record.type != "subdomain":  # the enumerated name itself stays on record
                assert record.asset in {*REAL, ROOT}, record

    def test_the_root_gets_a_wildcard_dns_record(self, env) -> None:
        _wildcard_zone(env)
        summary = _pipeline(env).run()
        (record,) = _wildcard_records(env)
        assert record.asset == ROOT and record.value == "WILDCARD *.acme.test"
        assert record.attrs["wildcard"] is True
        assert record.attrs["addresses"] == [WILD]
        # It points at the probe's own raw output, which holds the three random answers.
        ref = f"raw/acme/{summary['run_id']}/dns-dnsx-wildcard-acme.test.out"
        assert record.raw_ref == ref
        meta = env["store"].raw_output("acme", ref)
        raw = (env["root"] / ref).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == meta["sha256"]
        assert raw.decode().count(WILD) == 3
        # The root is not turned into a resolving host by that record.
        assert ROOT not in _resolving(env)

    def test_probing_leaves_the_stage_raw_output_intact(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        kept = env["store"].query_records("acme", record_type="dns_record", asset="h07.acme.test")
        (record,) = kept
        meta = env["store"].raw_output("acme", record.raw_ref)
        raw_file = env["root"] / record.raw_ref.split("#")[0]
        assert raw_file.name == "dns-dnsx.out"
        assert hashlib.sha256(raw_file.read_bytes()).hexdigest() == meta["sha256"]
        line = raw_file.read_text().splitlines()[int(record.raw_ref.split("#L")[1]) - 1]
        assert json.loads(line)["host"] == "h07.acme.test"

    def test_dropped_names_are_not_coverage_gaps(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        store = env["store"]
        assert not [row for row in store.coverage("acme") if row["asset"] in SMALL_FAKES]
        assert not [gap for gap in store.coverage_gaps("acme") if gap["asset"] in SMALL_FAKES]
        dns = {row["asset"]: row["status"] for row in store.coverage("acme", stage="dns")}
        assert dns == {ROOT: "complete", **dict.fromkeys(REAL, "complete")}

    def test_explicitly_scoped_host_is_kept_on_the_wildcard_address(self, env) -> None:
        _wildcard_zone(env, names=NAMES[:10])
        roe = _roe(in_scope=["*.acme.test", "acme.test", "app.acme.test"])
        summary = _pipeline(env, roe).run()
        # app.acme.test has no record of its own: only the wildcard answers for it.
        (record,) = env["store"].query_records(
            "acme", record_type="dns_record", asset="app.acme.test"
        )
        assert record.value == f"A {WILD}"
        dropped = {d["candidate"] for d in _wildcard_drops(env, summary["run_id"])}
        assert "app.acme.test" not in dropped
        # The exemption is what kept it: unlisted names on the same address went.
        assert dropped == set(NAMES[:10]) - set(REAL)

    def test_seed_url_host_is_kept_on_the_wildcard_address(self, env) -> None:
        _wildcard_zone(env, names=[*NAMES[:10], "portal.acme.test"])
        roe = _roe(seed_urls=["https://portal.acme.test:8443/login"])
        summary = _pipeline(env, roe).run()
        assert "portal.acme.test" in _resolving(env)
        dropped = {d["candidate"] for d in _wildcard_drops(env, summary["run_id"])}
        assert dropped == set(NAMES[:10]) - set(REAL)

    def test_same_host_without_the_seed_url_is_dropped(self, env) -> None:
        """Control for the seed-URL exemption."""
        _wildcard_zone(env, names=[*NAMES[:10], "portal.acme.test"])
        summary = _pipeline(env).run()
        assert "portal.acme.test" not in _resolving(env)
        assert "portal.acme.test" in {
            d["candidate"] for d in _wildcard_drops(env, summary["run_id"])
        }

    def test_root_outside_the_scope_gets_no_record_but_names_are_still_filtered(self, env) -> None:
        """``*.acme.test`` alone leaves the apex out of scope; nothing is stored about it."""
        _wildcard_zone(env)
        summary = _pipeline(env, _roe(in_scope=["*.acme.test"])).run()
        assert _wildcard_records(env) == []
        assert not env["store"].query_records("acme", asset=ROOT, status=None)
        assert _resolving(env) == set(REAL)
        assert len(_wildcard_drops(env, summary["run_id"])) == len(SMALL_FAKES)
        drops = env["store"].scope_drops("acme", run_id=summary["run_id"], limit=5000)
        assert ("dns", "dnsx", "output", ROOT, "NOT_IN_SCOPE") in {
            (d["stage"], d["tool"], d["direction"], d["candidate"], d["reason"]) for d in drops
        }


class TestNotAWildcardZone:
    def test_shared_hosting_without_a_wildcard_drops_nothing(self, env) -> None:
        """Negative control: fifty names on one address, random names do not resolve."""
        _shared_hosting_zone(env, NAMES)
        summary = _pipeline(env).run()
        resolved, probes = _dnsx_calls(env)
        assert sorted(resolved) == sorted([ROOT, *NAMES])
        # The zone was probed, and the probes got no answer.
        assert len(probes) == 3 and not set(probes) & set(NAMES)
        assert all(p.endswith("." + ROOT) and len(p.split(".")[0]) == 16 for p in probes)
        ref = f"raw/acme/{summary['run_id']}/dns-dnsx-wildcard-acme.test.out"
        assert (env["root"] / ref).read_text().strip() == ""

        assert _wildcard_drops(env, summary["run_id"]) == []
        assert _resolving(env) == set(NAMES)
        assert _wildcard_records(env) == []
        assert "wildcard_dropped" not in summary["stages"]["dns"]["tools"]["dnsx"]
        dns = {row["asset"]: row["status"] for row in env["store"].coverage("acme", stage="dns")}
        assert dns == dict.fromkeys([ROOT, *NAMES], "complete")

    def test_rotating_wildcard_is_treated_as_not_a_wildcard(self, env) -> None:
        """Partial wildcard: every random name resolves, each to a different address.

        The choice (see ``TestDetect``): with no stable wildcard address set
        there is nothing to compare a name against, so the zone counts as not
        a wildcard and nothing is dropped.
        """
        _shared_hosting_zone(env)
        counter = itertools.count(1)
        env["tools"].wildcard = {ROOT: lambda _name: [f"203.0.113.{next(counter)}"]}
        summary = _pipeline(env).run()
        _resolved, probes = _dnsx_calls(env)
        ref = f"raw/acme/{summary['run_id']}/dns-dnsx-wildcard-acme.test.out"
        answers = [json.loads(line) for line in (env["root"] / ref).read_text().splitlines()]
        assert [a["host"] for a in answers] == probes  # all three probes resolved ...
        assert len({a["a"][0] for a in answers}) == 3  # ... each somewhere else

        assert _wildcard_drops(env, summary["run_id"]) == []
        assert _resolving(env) == set(SMALL)
        assert _wildcard_records(env) == []

    def test_zone_with_no_shared_answers_is_not_probed(self, env) -> None:
        env["tools"].enumerated = NAMES[:5]
        env["tools"].address = {name: f"192.0.2.{i + 1}" for i, name in enumerate(NAMES[:5])}
        summary = _pipeline(env).run()
        assert len(_dnsx_calls(env)) == 1
        assert _wildcard_drops(env, summary["run_id"]) == []
        assert env["store"].cached_input("acme", WILDCARD_STAGE, ROOT) is None


class TestProbes:
    def test_probe_names_come_from_the_injected_rng(self, env) -> None:
        _wildcard_zone(env)
        pipeline = _pipeline(env)
        pipeline._wildcard_rng = random.Random(7)  # noqa: SLF001
        pipeline.run()
        _resolved, probes = _dnsx_calls(env)
        assert probes == probe_names(ROOT, rng=random.Random(7))

    def test_two_runs_with_the_same_seed_end_the_same(self, env, tmp_path: Path) -> None:
        outcomes = []
        for index in range(2):
            store = ReconStore(tmp_path / f"again-{index}" / "recon.sqlite3")
            other = {
                **env,
                "store": store,
                "root": tmp_path / f"again-{index}",
                "tools": ZoneTools(),
            }
            _wildcard_zone(other)
            pipeline = _pipeline(other)
            pipeline._wildcard_rng = random.Random(42)  # noqa: SLF001
            summary = pipeline.run()
            outcomes.append(
                (
                    _dnsx_calls(other),
                    sorted(d["candidate"] for d in _wildcard_drops(other, summary["run_id"])),
                    sorted(_resolving(other)),
                )
            )
            store.close()
        assert outcomes[0] == outcomes[1]
        assert len(outcomes[0][1]) == len(SMALL_FAKES)

    def test_probes_use_the_stage_resolvers_and_rate_limit(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env, dns_resolvers=("10.0.0.53",)).run()
        main, probe = [argv for name, _inputs, argv in env["tools"].calls if name == "dnsx"]
        assert probe == main  # same binary, same flags; only the host list's content differs
        assert probe[probe.index("-r") + 1] == "10.0.0.53"
        assert probe[probe.index("-rl") + 1] == "50"  # 10 rps from the RoE, as for the stage

    def test_probe_names_are_scope_checked_like_any_input(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        scope = ScopeFilter.from_document(ROE)
        _resolved, probes = _dnsx_calls(env)
        assert all(scope.allows(name) for name in probes)

    def test_failed_probe_drops_nothing_and_is_not_read_as_clean(self, env) -> None:
        _wildcard_zone(env)
        env["tools"].fail_probes = True
        summary = _pipeline(env).run()
        assert _wildcard_drops(env, summary["run_id"]) == []
        assert _resolving(env) == set(SMALL)  # kept: unknown is not "wildcard"
        assert summary["stages"]["dns"]["tools"]["dnsx"]["wildcard_errors"] == {ROOT: "exit 1"}
        assert env["store"].cached_input("acme", WILDCARD_STAGE, ROOT) is None
        dns = {
            row["asset"]: (row["status"], row["detail"])
            for row in env["store"].coverage("acme", stage="dns")
        }
        assert dns["h00.acme.test"] == ("partial", "dnsx: wildcard check failed (exit 1)")
        assert dns[ROOT] == ("complete", "")  # the root is kept whatever the verdict

        # The next run checks the same names again, and this time decides.
        env["tools"].fail_probes = False
        env["tools"].calls.clear()
        summary = _pipeline(env).run()
        resolved, probes = _dnsx_calls(env)
        assert sorted(resolved) == SMALL and len(probes) == 3
        assert (
            sorted(d["candidate"] for d in _wildcard_drops(env, summary["run_id"])) == SMALL_FAKES
        )
        assert _resolving(env) == set(REAL)
        assert not [gap for gap in env["store"].coverage_gaps("acme") if gap["stage"] == "dns"]


class TestReRuns:
    def test_verdict_is_cached_per_root_and_reused_without_probing(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        cached = env["store"].cached_input("acme", WILDCARD_STAGE, ROOT)
        verdict = json.loads(cached["tool_versions"])
        assert verdict["wildcard"] is True and verdict["addresses"] == [WILD]

        # A new made-up name turns up; enumeration is due again, DNS is cached.
        _expire(env, "enumerate")
        env["tools"].enumerated.append("late.acme.test")
        env["tools"].calls.clear()
        summary = _pipeline(env).run()
        assert _dnsx_calls(env) == [["late.acme.test"]]  # resolved, and no probe run
        assert [d["candidate"] for d in _wildcard_drops(env, summary["run_id"])] == [
            "late.acme.test"
        ]
        assert _resolving(env) == set(REAL)

    def test_cached_not_wildcard_verdict_is_reused_too(self, env) -> None:
        _shared_hosting_zone(env)
        _pipeline(env).run()
        verdict = json.loads(
            env["store"].cached_input("acme", WILDCARD_STAGE, ROOT)["tool_versions"]
        )
        assert verdict["wildcard"] is False and verdict["addresses"] == []
        _expire(env, "enumerate")
        env["tools"].enumerated.append("late.acme.test")
        env["tools"].address["late.acme.test"] = SHARED
        env["tools"].calls.clear()
        summary = _pipeline(env).run()
        assert _dnsx_calls(env) == [["late.acme.test"]]
        assert _wildcard_drops(env, summary["run_id"]) == []
        assert "late.acme.test" in _resolving(env)

    def test_second_run_with_nothing_new_resolves_and_probes_nothing(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        env["tools"].calls.clear()
        summary = _pipeline(env).run()
        assert env["tools"].calls == []
        assert summary["diff"] == {"added": 0, "changed": 0, "removed": 0}
        assert _wildcard_drops(env, summary["run_id"]) == []  # nothing was looked at again

    def test_zone_that_becomes_a_wildcard_loses_what_was_stored_for_its_names(self, env) -> None:
        tools = env["tools"]
        tools.enumerated = NAMES[:6]
        tools.address = dict.fromkeys(NAMES[:6], SHARED)  # real names, one address
        _pipeline(env).run()
        assert _resolving(env) == set(NAMES[:6])
        assert {row["asset"] for row in env["store"].coverage("acme")} >= set(NAMES[:6])

        # The records go away and a wildcard on the same address takes over.
        tools.address = {NAMES[0]: "192.0.2.21"}
        tools.wildcard = {ROOT: lambda _name: [SHARED]}
        summary = _pipeline(env, force=True).run()
        gone = NAMES[1:6]
        assert sorted(d["candidate"] for d in _wildcard_drops(env, summary["run_id"])) == gone
        assert _resolving(env) == {NAMES[0]}
        removed = {
            (c["type"], c["asset"])
            for c in env["store"].diff("acme", summary["run_id"])
            if c["change"] == "removed"
        }
        for name in gone:
            assert ("dns_record", name) in removed and ("http_service", name) in removed
        # Their earlier stamps are gone with them: not complete, and not a gap.
        assert not [row for row in env["store"].coverage("acme") if row["asset"] in gone]

    def test_wildcard_record_is_retired_when_the_zone_stops_being_one(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        assert len(_wildcard_records(env)) == 1
        env["tools"].wildcard = {}  # the wildcard record is removed from the zone
        env["tools"].calls.clear()
        summary = _pipeline(env, force=True).run()
        assert len(_dnsx_calls(env)) == 2  # it was a wildcard last time, so it is probed again
        assert _wildcard_records(env) == []
        assert ("removed", "dns_record", "WILDCARD *.acme.test") in {
            (c["change"], c["type"], c["value"])
            for c in env["store"].diff("acme", summary["run_id"])
        }
        verdict = json.loads(
            env["store"].cached_input("acme", WILDCARD_STAGE, ROOT)["tool_versions"]
        )
        assert verdict["wildcard"] is False
        assert _wildcard_drops(env, summary["run_id"]) == []

    def test_root_that_leaves_the_scope_loses_its_verdict_and_record(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        assert len(_wildcard_records(env)) == 1
        other = _roe(in_scope=["*.other.test", "acme.test"])
        _pipeline(env, other).run()
        assert _wildcard_records(env) == []
        assert env["store"].cached_input("acme", WILDCARD_STAGE, ROOT) is None

    def test_single_asset_run_filters_that_asset_and_leaves_the_rest_alone(self, env) -> None:
        _wildcard_zone(env)
        _pipeline(env).run()
        env["tools"].calls.clear()
        summary = _pipeline(env, only_asset=SMALL_FAKES[0], force=True).run()
        resolved, probes = _dnsx_calls(env)
        assert resolved == [SMALL_FAKES[0]] and len(probes) == 3  # forced: the root is probed again
        assert [d["candidate"] for d in _wildcard_drops(env, summary["run_id"])] == [SMALL_FAKES[0]]
        assert _resolving(env) == set(REAL)
        assert len(_wildcard_records(env)) == 1  # other roots and names are left alone
