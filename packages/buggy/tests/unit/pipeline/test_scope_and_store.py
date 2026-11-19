"""Scope filter, program limits, and the recon store's dedupe / diff / cache behaviour."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from buggy.pipeline.schema import Record, RecordType, normalize_url
from buggy.pipeline.scope import PipelineLimits, ScopeError, ScopeFilter
from buggy.pipeline.store import ReconStore


def _doc(block: dict, pipeline: dict | None = None) -> dict:
    document: dict = {"machine_enforcement": block}
    if pipeline is not None:
        document["pipeline"] = pipeline
    return document


SCOPE = _doc(
    {
        "mode": "enforce",
        "in_scope": ["*.acme.test", "acme.test", "app.other.test", "192.0.2.0/30"],
        "out_of_scope": ["admin.acme.test"],
    }
)


class TestScopeFilter:
    @pytest.mark.parametrize(
        ("block", "match"),
        [
            ({"mode": "audit", "in_scope": ["a.test"]}, "enforce"),
            ({"mode": "warn", "in_scope": ["a.test"]}, "enforce"),
            ({"mode": "enforce", "in_scope": []}, "empty in_scope"),
            ({"mode": "enforce", "in_scope": ["http://a.test/path"]}, "invalid"),
        ],
    )
    def test_refuses_to_run_without_an_enforcing_allowlist(self, block, match) -> None:
        with pytest.raises(ScopeError, match=match):
            ScopeFilter.from_document(_doc(block))

    def test_missing_file_names_the_operator_step(self, tmp_path: Path) -> None:
        with pytest.raises(ScopeError, match="scope approve"):
            ScopeFilter.from_file(tmp_path / "control" / "acme" / "roe.json")

    def test_decisions_match_the_guardrail(self) -> None:
        scope = ScopeFilter.from_document(SCOPE)
        assert scope.allows("www.acme.test") and scope.allows("https://www.acme.test:8443/x?y=1")
        assert scope.allows("acme.test") and scope.allows("192.0.2.1")
        assert scope.decide("admin.acme.test") == (False, "OUT_OF_SCOPE")
        assert scope.decide("a.b.acme.test") == (False, "NOT_IN_SCOPE")  # wildcard = one label
        assert scope.decide("evil.example") == (False, "NOT_IN_SCOPE")
        assert scope.decide("169.254.169.254") == (False, "FORBIDDEN_DESTINATION")
        assert scope.decide("") == (False, "NO_HOST")

    def test_admit_filters_dedupes_and_logs(self) -> None:
        drops: list[tuple] = []
        scope = ScopeFilter.from_document(SCOPE, log_drop=lambda *a: drops.append(a))
        kept = scope.admit(
            ["www.acme.test", "evil.example", "www.acme.test", "admin.acme.test"],
            stage="dns",
            tool="dnsx",
            direction="input",
        )
        assert kept == ["www.acme.test"]
        assert drops == [
            ("dns", "dnsx", "input", "evil.example", "NOT_IN_SCOPE"),
            ("dns", "dnsx", "input", "admin.acme.test", "OUT_OF_SCOPE"),
        ]

    def test_seeds_come_only_from_in_scope(self) -> None:
        seeds = ScopeFilter.from_document(SCOPE).seeds()
        assert seeds.roots == ("acme.test",)
        assert seeds.hosts == ("acme.test", "app.other.test")
        assert seeds.addresses == ("192.0.2.1", "192.0.2.2")

    def test_oversized_cidr_and_inner_wildcards_are_not_expanded(self) -> None:
        scope = ScopeFilter.from_document(
            _doc({"mode": "enforce", "in_scope": ["10.0.0.0/8", "api-*.acme.test", "ok.acme.test"]})
        )
        seeds = scope.seeds()
        assert seeds.addresses == () and seeds.roots == ()
        assert set(seeds.skipped) == {"10.0.0.0/8", "api-*.acme.test"}
        assert seeds.hosts == ("ok.acme.test",)

    def test_digest_tracks_the_enforcement_block(self) -> None:
        a = ScopeFilter.from_document(SCOPE).digest
        changed = json.loads(json.dumps(SCOPE))
        changed["machine_enforcement"]["in_scope"].append("new.test")
        assert len(a) == 64 and ScopeFilter.from_document(changed).digest != a


class TestProgramLimits:
    def test_defaults(self) -> None:
        limits = ScopeFilter.from_document(SCOPE).limits
        assert limits == PipelineLimits()

    def test_roe_rate_rules_are_ceilings(self) -> None:
        document = _doc(
            {
                "mode": "enforce",
                "in_scope": ["a.test"],
                "min_inter_request_delay_ms": 500,  # 2 requests per second
                "max_concurrent_connections": 3,
            },
            {"rate_limit_rps": 100, "concurrency": 50},
        )
        limits = ScopeFilter.from_document(document).limits
        assert limits.rate_limit_rps == 2
        assert limits.concurrency == 2  # never more workers than requests per second

    def test_pipeline_block(self) -> None:
        document = _doc(
            {"mode": "enforce", "in_scope": ["a.test"]},
            {
                "passive_only": True,
                "port_scan": False,
                "ports": "80,443",
                "crawl_depth": 99,
                "nuclei_severities": ["critical", "bogus"],
                "disabled_stages": ["issues"],
                "rate_limit_rps": 3,
            },
        )
        limits = ScopeFilter.from_document(document).limits
        assert limits.passive_only and not limits.port_scan and limits.ports == "80,443"
        assert limits.crawl_depth == 5 and limits.nuclei_severities == ("critical",)
        assert limits.disabled_stages == ("issues",) and limits.rate_limit_rps == 3


def _sub(host: str, tool: str, **attrs) -> Record:
    return Record(RecordType.SUBDOMAIN, host, host, tool, attrs=attrs)


def _svc(url: str, **attrs) -> Record:
    from buggy.pipeline.schema import host_of

    return Record(RecordType.HTTP_SERVICE, host_of(url), normalize_url(url), "httpx", attrs=attrs)


@pytest.fixture
def store(tmp_path: Path):
    s = ReconStore(tmp_path / "recon.sqlite3")
    yield s
    s.close()


class TestStore:
    def test_same_fact_from_two_tools_is_one_record_with_two_observations(self, store) -> None:
        run = store.begin_run("acme", trigger="test")
        store.write_records(
            run,
            "acme",
            "enumerate",
            [(_sub("a.acme.test", "subfinder"), "acme.test")],
            tool_version="2.17.0",
            raw_ref="raw/acme/r/enumerate-subfinder.out",
        )
        store.write_records(
            run,
            "acme",
            "enumerate",
            [(_sub("a.acme.test", "amass"), "acme.test")],
            tool_version="4.2.0",
            raw_ref="raw/acme/r/enumerate-amass.out",
        )
        assert store.finish_run(run, status="completed", stats={}) == {
            "added": 1,
            "changed": 0,
            "removed": 0,
        }
        (record,) = store.query_records("acme", record_type="subdomain")
        assert record.sources == ("amass", "subfinder")
        detail = store.get_record("acme", record.id)
        assert {(o["source_tool"], o["tool_version"]) for o in detail["observations"]} == {
            ("subfinder", "2.17.0"),
            ("amass", "4.2.0"),
        }

    def test_record_carries_every_schema_field(self, store) -> None:
        run = store.begin_run("acme", trigger="test")
        record = Record(
            RecordType.PORT, "a.acme.test", "443/tcp", "naabu", attrs={"port": 443}, raw_line=7
        )
        store.write_records(
            run,
            "acme",
            "live",
            [(record, "a.acme.test")],
            tool_version="2.7.0",
            raw_ref="raw/acme/r/live-naabu.out",
            observed_at=1000.0,
        )
        data = store.query_records("acme")[0].to_dict()
        assert (
            data["asset"] == "a.acme.test" and data["type"] == "port" and data["value"] == "443/tcp"
        )
        assert data["source_tool"] == "naabu" and data["tool_version"] == "2.7.0"
        assert data["first_seen"] == data["last_seen"] == 1000.0
        assert data["engagement"] == "acme" and data["first_run_id"] == run
        assert data["raw_ref"] == "raw/acme/r/live-naabu.out#L7"

    def test_engagements_are_isolated(self, store) -> None:
        for engagement in ("acme", "other"):
            run = store.begin_run(engagement, trigger="test")
            store.write_records(
                run,
                engagement,
                "enumerate",
                [(_sub("shared.test", "subfinder"), "x")],
                tool_version="",
                raw_ref="",
            )
            store.finish_run(run, status="completed", stats={})
        acme = store.query_records("acme")
        assert len(acme) == 1 and acme[0].engagement == "acme"
        assert store.get_record("other", acme[0].id) is None

    def test_diff_added_changed_removed(self, store) -> None:
        run1 = store.begin_run("acme", trigger="test")
        store.write_records(
            run1,
            "acme",
            "live",
            [
                (_svc("https://a.acme.test/", status_code=200), "a.acme.test"),
                (_svc("https://b.acme.test/", status_code=200), "b.acme.test"),
            ],
            tool_version="1",
            raw_ref="",
        )
        store.complete_inputs(
            run1, "acme", "live", {"a.acme.test": "h1", "b.acme.test": "h1"}, tool_versions=""
        )
        assert store.finish_run(run1, status="completed", stats={})["added"] == 2

        run2 = store.begin_run("acme", trigger="test")
        # a changed, b was re-probed and is gone, c is new.
        store.write_records(
            run2,
            "acme",
            "live",
            [
                (_svc("https://a.acme.test/", status_code=403), "a.acme.test"),
                (_svc("https://c.acme.test/", status_code=200), "c.acme.test"),
            ],
            tool_version="1",
            raw_ref="",
        )
        retired = store.complete_inputs(
            run2,
            "acme",
            "live",
            {"a.acme.test": "h2", "b.acme.test": "h2", "c.acme.test": "h2"},
            tool_versions="",
        )
        assert retired == 1
        assert store.finish_run(run2, status="completed", stats={}) == {
            "added": 1,
            "changed": 1,
            "removed": 1,
        }
        changes = {(c["change"], c["value"]) for c in store.diff("acme", run2)}
        assert changes == {
            ("changed", "https://a.acme.test/"),
            ("removed", "https://b.acme.test/"),
            ("added", "https://c.acme.test/"),
        }
        assert {r.value for r in store.query_records("acme")} == {
            "https://a.acme.test/",
            "https://c.acme.test/",
        }
        assert len(store.query_records("acme", status=None)) == 3

    def test_unprocessed_inputs_keep_their_records(self, store) -> None:
        run1 = store.begin_run("acme", trigger="test")
        store.write_records(
            run1,
            "acme",
            "live",
            [
                (_svc("https://a.acme.test/"), "a.acme.test"),
                (_svc("https://b.acme.test/"), "b.acme.test"),
            ],
            tool_version="1",
            raw_ref="",
        )
        store.complete_inputs(
            run1, "acme", "live", {"a.acme.test": "h", "b.acme.test": "h"}, tool_versions=""
        )
        store.finish_run(run1, status="completed", stats={})
        run2 = store.begin_run("acme", trigger="test")
        # Only a is re-processed (b was served from the cache): b must survive.
        store.write_records(
            run2,
            "acme",
            "live",
            [(_svc("https://a.acme.test/"), "a.acme.test")],
            tool_version="1",
            raw_ref="",
        )
        store.complete_inputs(run2, "acme", "live", {"a.acme.test": "h"}, tool_versions="")
        assert store.finish_run(run2, status="completed", stats={}) == {
            "added": 0,
            "changed": 0,
            "removed": 0,
        }
        assert len(store.query_records("acme")) == 2

    def test_reappearing_record_is_added_again(self, store) -> None:
        run1 = store.begin_run("acme", trigger="t")
        store.write_records(
            run1,
            "acme",
            "live",
            [(_svc("https://a.acme.test/"), "a.acme.test")],
            tool_version="1",
            raw_ref="",
        )
        store.complete_inputs(run1, "acme", "live", {"a.acme.test": "h"}, tool_versions="")
        store.finish_run(run1, status="completed", stats={})
        run2 = store.begin_run("acme", trigger="t")
        store.complete_inputs(run2, "acme", "live", {"a.acme.test": "h"}, tool_versions="")
        assert store.finish_run(run2, status="completed", stats={})["removed"] == 1
        run3 = store.begin_run("acme", trigger="t")
        store.write_records(
            run3,
            "acme",
            "live",
            [(_svc("https://a.acme.test/"), "a.acme.test")],
            tool_version="1",
            raw_ref="",
        )
        assert store.finish_run(run3, status="completed", stats={})["added"] == 1

    def test_discovery_stage_marks_cache_without_retiring(self, store) -> None:
        run1 = store.begin_run("acme", trigger="t")
        store.write_records(
            run1,
            "acme",
            "enumerate",
            [(_sub("a.acme.test", "subfinder"), "acme.test")],
            tool_version="",
            raw_ref="",
        )
        store.finish_run(run1, status="completed", stats={})
        run2 = store.begin_run("acme", trigger="t")
        assert (
            store.complete_inputs(
                run2, "acme", "enumerate", {"acme.test": "h"}, tool_versions="", retire=False
            )
            == 0
        )
        assert store.cached_input("acme", "enumerate", "acme.test")["input_hash"] == "h"
        assert len(store.query_records("acme")) == 1

    def test_scope_drops_are_recorded_once_per_run(self, store) -> None:
        run = store.begin_run("acme", trigger="t")
        for _ in range(3):
            store.log_scope_drop(
                run,
                "acme",
                stage="urls",
                tool="katana",
                direction="output",
                candidate="evil.example",
                reason="NOT_IN_SCOPE",
            )
        assert store.scope_drops("acme", run_id=run) == [
            pytest.approx(
                {
                    "run_id": run,
                    "stage": "urls",
                    "tool": "katana",
                    "direction": "output",
                    "candidate": "evil.example",
                    "reason": "NOT_IN_SCOPE",
                    "dropped_at": store.scope_drops("acme")[0]["dropped_at"],
                }
            )
        ]

    def test_read_only_handle_cannot_write(self, store, tmp_path: Path) -> None:
        run = store.begin_run("acme", trigger="t")
        store.write_records(
            run,
            "acme",
            "enumerate",
            [(_sub("a.acme.test", "subfinder"), "x")],
            tool_version="",
            raw_ref="",
        )
        store.finish_run(run, status="completed", stats={})
        reader = ReconStore(tmp_path / "recon.sqlite3", read_only=True)
        try:
            assert len(reader.query_records("acme")) == 1
            with pytest.raises(sqlite3.OperationalError):
                reader.begin_run("acme", trigger="agent")
            with pytest.raises(sqlite3.OperationalError):
                reader.write_records(
                    "r",
                    "acme",
                    "enumerate",
                    [(_sub("evil.test", "agent"), "x")],
                    tool_version="",
                    raw_ref="",
                )
        finally:
            reader.close()
        assert len(store.query_records("acme")) == 1

    def test_query_filters_and_paging(self, store) -> None:
        run = store.begin_run("acme", trigger="t")
        store.write_records(
            run,
            "acme",
            "enumerate",
            [(_sub(f"h{i}.acme.test", "subfinder"), "acme.test") for i in range(5)],
            tool_version="",
            raw_ref="",
        )
        store.write_records(
            run,
            "acme",
            "live",
            [(_svc("https://h1.acme.test/login_50%"), "h1.acme.test")],
            tool_version="",
            raw_ref="",
        )
        assert len(store.query_records("acme", record_type="subdomain", limit=2)) == 2
        assert len(store.query_records("acme", record_type="subdomain", limit=2, offset=4)) == 1
        assert [r.type for r in store.query_records("acme", asset="h1.acme.test")] == [
            "http_service",
            "subdomain",
        ]
        # LIKE wildcards in the search text are literals, not patterns.
        assert len(store.query_records("acme", contains="50%")) == 1
        assert store.query_records("acme", contains="h_.acme") == []
        assert store.count_records("acme") == {"http_service": 1, "subdomain": 5}
        assert [a["asset"] for a in store.list_assets("acme")][:2] == [
            "h0.acme.test",
            "h1.acme.test",
        ]
