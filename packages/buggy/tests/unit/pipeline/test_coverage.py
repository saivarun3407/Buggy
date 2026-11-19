"""Coverage stamps: a stage that did not finish for an asset is never read as clean.

Every run stamps each asset it handled, per stage, as ``complete``, ``partial``,
``failed`` or ``skipped`` (with the reason). These tests drive the real
pipeline with the recording fake scanners from ``test_pipeline_flow`` and make
individual tools time out, fail or go missing, then check the stamps, the
query surface and the report. Each "this gap is reported" test has a control
showing a clean run reports none.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import urllib.error
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from buggy.pipeline.pipeline import COVERAGE_STAGES, STAGES, Pipeline, ToolOutcome, grade
from buggy.pipeline.query import MAX_SUMMARY_GAPS, QueryError, ReconQueries
from buggy.pipeline.report import render_report
from buggy.pipeline.runner import RunResult
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.store import COVERAGE_STATUSES, ReconStore
from buggy.pipeline.tools.base import Invocation

from .test_pipeline_flow import ROE, FakeOpener, FakeTools

HOSTS = ("api.acme.test", "www.acme.test")  # the two names that resolve and serve HTTP

#: What a clean run of the fake estate must stamp, and nothing else.
CLEAN = {
    "enumerate": {"acme.test"},
    "dns": {"acme.test", "api.acme.test", "crt-only.acme.test", "www.acme.test"},
    "port": set(HOSTS),
    "live": set(HOSTS),
    "fingerprint": set(HOSTS),
    "urls": set(HOSTS),
    "apispec": set(HOSTS),
    "issues": set(HOSTS),
}


class FlakyTools(FakeTools):
    """``FakeTools`` whose named scanners time out mid-output or die with none."""

    def __init__(self) -> None:
        super().__init__()
        self.time_out: set[str] = set()  # killed by the timeout after writing output
        self.fail: set[str] = set()  # exit 1, nothing written

    def execute(self, name: str, invocation: Invocation, raw_path: Path) -> RunResult:
        result = super().execute(name, invocation, raw_path)
        if name in self.time_out:
            assert result.size > 0, "a partial-output timeout needs output to keep"
            return dataclasses.replace(result, exit_code=None, timed_out=True)
        if name in self.fail:
            raw_path.write_text("")
            return dataclasses.replace(
                result,
                exit_code=1,
                size=0,
                sha256=hashlib.sha256(b"").hexdigest(),
                stderr_tail="connection refused",
            )
        return result


class PatchyOpener(FakeOpener):
    """``FakeOpener`` where every request to a host in ``down`` is a transport error."""

    def __init__(self) -> None:
        super().__init__()
        self.down: set[str] = set()

    def open(self, request, timeout=None):
        if urlsplit(request.full_url).hostname in self.down:
            self.requested.append((request.get_method(), request.full_url))
            raise urllib.error.URLError("connection refused")
        return super().open(request, timeout=timeout)


@pytest.fixture
def env(tmp_path: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {
        "store": store,
        "root": tmp_path / "data",
        "tools": FlakyTools(),
        "opener": PatchyOpener(),
    }
    store.close()


def _pipeline(env, roe: dict | None = None, **kwargs) -> Pipeline:
    crt = json.dumps([{"name_value": "www.acme.test\ncrt-only.acme.test\n*.acme.test"}]).encode()
    options = {
        "data_root": env["root"],
        "executor": env["tools"].execute,
        "resolver": env["tools"].resolve,
        "http_opener": env["opener"],
        "passive_fetch": lambda _url: crt,
        "sleep": lambda _s: None,
        **kwargs,
    }
    return Pipeline(env["store"], ScopeFilter.from_document(roe or ROE), "acme", **options)


def _roe(**pipeline_block) -> dict:
    roe = json.loads(json.dumps(ROE))
    roe["pipeline"].update(pipeline_block)
    return roe


def _stamps(store: ReconStore, engagement: str = "acme") -> dict[tuple[str, str], tuple[str, str]]:
    """``{(stage, asset): (status, detail)}`` for everything stamped."""
    return {
        (row["stage"], row["asset"]): (row["status"], row["detail"])
        for row in store.coverage(engagement)
    }


def _by_stage(store: ReconStore) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for stage, asset in _stamps(store):
        out.setdefault(stage, set()).add(asset)
    return out


def _queries(env) -> ReconQueries:
    return ReconQueries(env["store"], None, data_root=env["root"])


def _section(text: str, title: str) -> str:
    """The body of one ``## title`` section of a rendered report."""
    marker = f"## {title}\n"
    assert marker in text, f"report has no {title!r} section"
    return text.split(marker, 1)[1].split("\n## ", 1)[0]


# ── the stamps a run writes ─────────────────────────────────────────


class TestCleanRun:
    def test_every_handled_asset_is_complete_for_every_stage_that_ran(self, env) -> None:
        summary = _pipeline(env).run()
        store = env["store"]
        assert _by_stage(store) == CLEAN
        rows = store.coverage("acme")
        assert {row["status"] for row in rows} == {"complete"}
        assert {row["detail"] for row in rows} == {""}
        assert {row["run_id"] for row in rows} == {summary["run_id"]}
        assert set(CLEAN) == set(COVERAGE_STAGES) and set(STAGES) < set(COVERAGE_STAGES)

    def test_clean_run_has_no_gaps(self, env) -> None:
        """Negative control for every gap test below."""
        _pipeline(env).run()
        store = env["store"]
        assert store.coverage_gaps("acme") == []
        assert store.coverage_counts("acme") == {
            "complete": sum(len(assets) for assets in CLEAN.values()),
            "partial": 0,
            "failed": 0,
            "skipped": 0,
        }
        summary = _queries(env).summary("acme")
        assert summary["coverage_gaps"] == [] and summary["coverage_gap_assets"] == 0

    def test_port_scan_off_is_skipped_with_the_reason_not_clean(self, env) -> None:
        _pipeline(env, _roe(port_scan=False)).run()
        stamps = _stamps(env["store"])
        for host in HOSTS:
            status, detail = stamps[("port", host)]
            assert status == "skipped" and detail.startswith("port scan disabled")
            assert stamps[("live", host)] == ("complete", "")  # the HTTP probe did run
        gaps = env["store"].coverage_gaps("acme")
        assert {(g["stage"], g["asset"]) for g in gaps} == {("port", h) for h in HOSTS}
        assert env["store"].count_records("acme").get("port", 0) == 0


class TestToolFailures:
    def test_timeout_with_partial_output_is_partial_and_names_the_tool(self, env) -> None:
        env["tools"].time_out = {"nuclei"}
        _pipeline(env).run()
        stamps = _stamps(env["store"])
        for host in HOSTS:
            status, detail = stamps[("issues", host)]
            assert status == "partial"
            assert "nuclei" in detail and "timed out" in detail
        # What the scanner did report before it was killed is kept.
        assert env["store"].count_records("acme")["vulnerability"] == 1
        # Only the issues stage is affected.
        assert {stage for (stage, _a), (s, _d) in stamps.items() if s != "complete"} == {"issues"}

    def test_failure_with_no_output_is_failed_and_names_the_tool(self, env) -> None:
        env["tools"].fail = {"httpx"}
        _pipeline(env).run()
        store = env["store"]
        stamps = _stamps(store)
        for host in HOSTS:
            status, detail = stamps[("live", host)]
            assert status == "failed"
            assert "httpx" in detail and "exit 1" in detail and "no output" in detail
            # Fingerprints are read off the same probe, so they were not taken either.
            assert stamps[("fingerprint", host)][0] == "failed"
            assert stamps[("port", host)] == ("complete", "")  # naabu was fine
        assert "http_service" not in store.count_records("acme")
        # Nothing downstream ran for these hosts: no stamp, and above all no "complete".
        assert not {"urls", "apispec", "issues"} & set(_by_stage(store))
        assert store.coverage_counts("acme")["failed"] == 2 * len(HOSTS)

    def test_one_failed_source_among_several_makes_the_stage_partial(self, env) -> None:
        env["tools"].fail = {"subfinder"}
        _pipeline(env).run()
        status, detail = _stamps(env["store"])[("enumerate", "acme.test")]
        assert status == "partial" and detail.startswith("subfinder: exit 1")
        assert "amass" not in detail and "crtsh" not in detail

    def test_missing_tool_is_failed_until_a_later_run_scans_the_asset(self, env) -> None:
        env["tools"].missing = {"naabu", "nuclei"}
        _pipeline(env).run()
        store = env["store"]
        for host in HOSTS:
            # The only tool of the port scan produced nothing: failed.
            assert _stamps(store)[("port", host)] == ("failed", "naabu: naabu is not installed")
            assert _stamps(store)[("live", host)] == ("complete", "")
            # The secret scan of the stage did run, the template scan did not: partial.
            assert _stamps(store)[("issues", host)] == (
                "partial",
                "nuclei: nuclei is not installed",
            )
        env["tools"].missing = set()
        _pipeline(env).run()
        for host in HOSTS:
            # Unscanned services were left due, so this run scanned them...
            assert _stamps(store)[("issues", host)] == ("complete", "")
            # ...but the live stage is cached, and its port scan is still not done.
            assert _stamps(store)[("port", host)][0] == "failed"
        _pipeline(env, force=True).run()
        assert store.coverage_gaps("acme") == []

    def test_unanswered_builtin_requests_are_not_a_clean_result(self, env) -> None:
        env["opener"].down = {"api.acme.test"}
        _pipeline(env).run()
        stamps = _stamps(env["store"])
        status, detail = stamps[("apispec", "api.acme.test")]
        assert status == "failed" and "openapi: no response" in detail and "graphql" in detail
        status, detail = stamps[("urls", "api.acme.test")]
        assert status == "partial" and detail.startswith("jsparse: no response")
        # The host that answered (404s included) is complete.
        assert stamps[("apispec", "www.acme.test")] == ("complete", "")
        assert stamps[("urls", "www.acme.test")] == ("complete", "")

    def test_a_run_that_dies_stamps_the_inputs_it_was_working_on(self, env) -> None:
        def boom(*_args):
            raise RuntimeError("disk full")

        with pytest.raises(RuntimeError):
            _pipeline(env, executor=boom).run()
        assert _stamps(env["store"]) == {
            ("enumerate", "acme.test"): ("failed", "run failed: RuntimeError: disk full")
        }


class TestProgramRules:
    def test_passive_only_marks_active_stages_skipped(self, env) -> None:
        _pipeline(env, _roe(passive_only=True)).run()
        stamps = _stamps(env["store"])
        for host in HOSTS:
            for stage in ("port", "live", "fingerprint"):
                assert stamps[(stage, host)] == ("skipped", "passive_only")
        complete = {stage for (stage, _a), (status, _d) in stamps.items() if status == "complete"}
        assert complete == {"enumerate", "dns"}  # the passive stages really ran

    def test_disabled_stage_is_skipped_then_complete_once_enabled(self, env) -> None:
        _pipeline(env, _roe(disabled_stages=["issues"])).run()
        store = env["store"]
        for host in HOSTS:
            assert _stamps(store)[("issues", host)] == ("skipped", "disabled by program rules")
        assert {g["stage"] for g in store.coverage_gaps("acme")} == {"issues"}
        _pipeline(env).run()
        for host in HOSTS:
            assert _stamps(store)[("issues", host)] == ("complete", "")

    def test_disabling_a_stage_later_keeps_the_result_it_already_has(self, env) -> None:
        first = _pipeline(env).run()
        _pipeline(env, _roe(disabled_stages=["issues"])).run()
        rows = [r for r in env["store"].coverage("acme") if r["stage"] == "issues"]
        assert {(r["status"], r["run_id"]) for r in rows} == {("complete", first["run_id"])}


class TestReRuns:
    def test_cached_run_keeps_the_previous_stamps(self, env) -> None:
        env["tools"].time_out = {"nuclei"}
        first = _pipeline(env).run()
        store = env["store"]
        before = store.coverage("acme")
        assert {r["status"] for r in before} == {"complete", "partial"}

        env["tools"].time_out = set()
        env["tools"].calls.clear()
        second = _pipeline(env).run()
        assert env["tools"].calls == [] and second["run_id"] != first["run_id"]
        # Same rows, same run, same timestamp: the cached run did not re-stamp
        # anything, and did not turn the partial scan into a complete one.
        assert store.coverage("acme") == before
        assert {r["run_id"] for r in before} == {first["run_id"]}

    def test_reprocessing_replaces_the_stamp(self, env) -> None:
        env["tools"].time_out = {"nuclei"}
        _pipeline(env).run()
        env["tools"].time_out = set()
        third = _pipeline(env, force=True).run()
        rows = env["store"].coverage("acme")
        assert {r["status"] for r in rows} == {"complete"}
        assert {r["run_id"] for r in rows} == {third["run_id"]}

    def test_asset_that_stops_being_an_input_loses_its_stamps(self, env) -> None:
        _pipeline(env).run()
        del env["tools"].address["api.acme.test"]  # api no longer resolves
        _pipeline(env, force=True).run()
        by_stage = _by_stage(env["store"])
        assert "api.acme.test" in by_stage["dns"]  # still looked up
        for stage in ("port", "live", "fingerprint", "urls", "apispec", "issues"):
            assert by_stage[stage] == {"www.acme.test"}, stage
        assert env["store"].coverage_gaps("acme") == []

    def test_single_asset_run_leaves_other_assets_stamps_alone(self, env) -> None:
        env["tools"].time_out = {"nuclei"}
        first = _pipeline(env).run()
        env["tools"].time_out = set()
        _pipeline(env, only_asset="api.acme.test", force=True).run()
        rows = {(r["stage"], r["asset"]): r for r in env["store"].coverage("acme")}
        assert rows[("issues", "api.acme.test")]["status"] == "complete"
        assert rows[("issues", "www.acme.test")]["status"] == "partial"
        assert rows[("issues", "www.acme.test")]["run_id"] == first["run_id"]
        assert _by_stage(env["store"]) == CLEAN


# ── grading rules ───────────────────────────────────────────────────


def _outcome(tool: str, status: str, detail: str = "", assets=None) -> ToolOutcome:
    return ToolOutcome(tool, status, detail, None if assets is None else frozenset(assets))


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        ([("a", "complete"), ("b", "complete")], ("complete", "")),
        ([("a", "complete"), ("b", "partial", "timed out")], ("partial", "b: timed out")),
        ([("a", "complete"), ("b", "failed", "exit 2")], ("partial", "b: exit 2")),
        ([("a", "failed", "exit 2")], ("failed", "a: exit 2")),
        (
            [("a", "failed", "exit 2"), ("b", "skipped", "passive_only")],
            ("failed", "a: exit 2; b: skipped (passive_only)"),
        ),
        (
            [("a", "complete"), ("b", "skipped", "passive_only")],
            ("partial", "b: skipped (passive_only)"),
        ),
        (
            [("a", "skipped", "passive_only"), ("b", "skipped", "passive_only")],
            ("skipped", "passive_only"),
        ),
        ([], ("skipped", "no tool ran on this asset")),  # nothing ran: never "complete"
    ],
)
def test_grade(outcomes, expected) -> None:
    assert grade("h.test", [_outcome(*o) for o in outcomes]) == expected


def test_grade_only_counts_outcomes_for_the_asset() -> None:
    outcomes = [
        _outcome("scan", "complete"),
        _outcome("fetch", "failed", "no response", assets={"down.test"}),
        _outcome("fetch", "complete", assets={"up.test"}),
    ]
    assert grade("up.test", outcomes) == ("complete", "")
    assert grade("down.test", outcomes) == ("partial", "fetch: no response")


# ── the store ───────────────────────────────────────────────────────


@pytest.fixture
def store(tmp_path: Path):
    s = ReconStore(tmp_path / "recon.sqlite3")
    yield s
    s.close()


class TestStore:
    def test_one_stamp_per_asset_and_stage_and_the_latest_wins(self, store) -> None:
        store.set_coverage("acme", "a.test", "issues", "failed", "nuclei: exit 2, no output", "r1")
        store.set_coverage("acme", "a.test", "issues", "complete", "", "r2")
        store.set_coverage("acme", "a.test", "urls", "partial", "katana: timed out", "r2")
        store.set_coverage("acme", "b.test", "issues", "skipped", "passive_only", "r2")
        rows = store.coverage("acme")
        assert [(r["asset"], r["stage"], r["status"], r["run_id"]) for r in rows] == [
            ("a.test", "issues", "complete", "r2"),
            ("a.test", "urls", "partial", "r2"),
            ("b.test", "issues", "skipped", "r2"),
        ]
        assert all(r["updated_at"] > 0 for r in rows)
        assert [r["stage"] for r in store.coverage("acme", asset="a.test")] == ["issues", "urls"]
        assert store.coverage("acme", asset="nope.test") == []
        assert [(g["stage"], g["asset"], g["detail"]) for g in store.coverage_gaps("acme")] == [
            ("issues", "b.test", "passive_only"),
            ("urls", "a.test", "katana: timed out"),
        ]
        assert store.coverage_counts("acme") == {
            "complete": 1,
            "partial": 1,
            "failed": 0,
            "skipped": 1,
        }

    def test_status_must_be_one_of_the_four(self, store) -> None:
        for bad in ("ok", "clean", "", "COMPLETE"):
            with pytest.raises(ValueError, match="coverage status"):
                store.set_coverage("acme", "a.test", "issues", bad, "", "r1")
        assert store.coverage("acme") == []
        for good in COVERAGE_STATUSES:
            store.set_coverage("acme", f"{good}.test", "issues", good, "", "r1")
        assert len(store.coverage("acme")) == len(COVERAGE_STATUSES) == 4

    def test_engagements_are_isolated(self, store) -> None:
        store.set_coverage("acme", "a.test", "issues", "failed", "x", "r1")
        assert store.coverage("other") == [] and store.coverage_gaps("other") == []
        assert store.coverage_counts("other") == dict.fromkeys(COVERAGE_STATUSES, 0)

    def test_keep_complete_only_protects_complete_stamps(self, store) -> None:
        store.set_coverage("acme", "done.test", "issues", "complete", "", "r1")
        store.set_coverage("acme", "half.test", "issues", "partial", "nuclei: timed out", "r1")
        skipped = ("skipped", "disabled by program rules")
        written = store.stamp_coverage(
            "acme",
            "issues",
            dict.fromkeys(("done.test", "half.test", "new.test"), skipped),
            "r2",
            keep_complete=True,
        )
        assert written == 2
        assert {r["asset"]: (r["status"], r["run_id"]) for r in store.coverage("acme")} == {
            "done.test": ("complete", "r1"),
            "half.test": ("skipped", "r2"),
            "new.test": ("skipped", "r2"),
        }

    def test_read_only_handle_reads_stamps_and_cannot_write_them(
        self, store, tmp_path: Path
    ) -> None:
        store.set_coverage("acme", "a.test", "issues", "failed", "x", "r1")
        reader = ReconStore(tmp_path / "recon.sqlite3", read_only=True)
        try:
            assert [g["asset"] for g in reader.coverage_gaps("acme")] == ["a.test"]
            with pytest.raises(sqlite3.OperationalError):
                reader.set_coverage("acme", "a.test", "issues", "complete", "", "agent")
        finally:
            reader.close()
        assert store.coverage("acme")[0]["status"] == "failed"

    def test_store_from_before_coverage_reads_as_nothing_recorded(
        self, store, tmp_path: Path
    ) -> None:
        with store._tx() as cur:  # noqa: SLF001 - simulate a store written by an older build
            cur.execute("DROP TABLE coverage")
        reader = ReconStore(tmp_path / "recon.sqlite3", read_only=True)
        try:
            assert reader.coverage("acme") == [] and reader.coverage_gaps("acme") == []
            summary = ReconQueries(reader, None, data_root=tmp_path).summary("acme")
        finally:
            reader.close()
        assert summary["coverage"] == dict.fromkeys(COVERAGE_STATUSES, 0)
        text = render_report("acme", summary, {}, generated_at=0)
        assert "| Assets with incomplete coverage | not recorded |" in text
        assert "No coverage was recorded" in _section(text, "Not checked")
        assert _section(text, "Known issues").lstrip().startswith("This list cannot be taken")


# ── the agent's query surface ───────────────────────────────────────


class TestQueries:
    def _two_faults(self, env) -> None:
        """nuclei timed out on the first two hosts; httpx then died on a third."""
        env["tools"].time_out = {"nuclei"}
        _pipeline(env).run()
        with env["store"]._tx() as cur:  # noqa: SLF001 - make enumeration due again
            cur.execute("DELETE FROM stage_cache WHERE stage = 'enumerate'")
        env["tools"].extra_subdomains = ["new.acme.test"]
        env["tools"].address["new.acme.test"] = "192.0.2.12"
        env["tools"].time_out, env["tools"].fail = set(), {"httpx"}
        _pipeline(env).run()

    def test_summary_counts_match_the_stamps(self, env) -> None:
        self._two_faults(env)
        summary = _queries(env).summary("acme")
        rows = env["store"].coverage("acme")
        assert summary["coverage"] == {
            status: sum(1 for r in rows if r["status"] == status) for status in COVERAGE_STATUSES
        }
        assert summary["coverage"] == {"complete": 17, "partial": 2, "failed": 2, "skipped": 0}
        assert {(g["stage"], g["asset"], g["status"]) for g in summary["coverage_gaps"]} == {
            ("issues", "api.acme.test", "partial"),
            ("issues", "www.acme.test", "partial"),
            ("live", "new.acme.test", "failed"),
            ("fingerprint", "new.acme.test", "failed"),
        }
        assert summary["coverage_gap_assets"] == 3
        json.dumps(summary)  # the MCP tool returns it as JSON

    def test_report_names_what_was_not_checked(self, env) -> None:
        self._two_faults(env)
        summary = _queries(env).summary("acme")
        text = render_report("acme", summary, {}, generated_at=0)

        not_checked = _section(text, "Not checked")
        assert "### issues" in not_checked and "### live" in not_checked
        assert "| www.acme.test | partial | nuclei: timed out" in not_checked
        assert "| api.acme.test | partial | nuclei: timed out" in not_checked
        assert "| new.acme.test | failed | httpx: exit 1, no output |" in not_checked
        assert not_checked.index("### live") < not_checked.index("### issues")  # pipeline order
        assert "| Assets with incomplete coverage | 3 |" in _section(text, "Summary")
        known = _section(text, "Known issues").strip().splitlines()
        assert known[0] == (
            'This list is not complete: 3 asset(s) were not fully checked (see "Not checked").'
        )

    def test_clean_report_claims_no_gap(self, env) -> None:
        """Negative control: the same report on a clean run flags nothing."""
        _pipeline(env).run()
        text = render_report("acme", _queries(env).summary("acme"), {}, generated_at=0)
        assert "| Assets with incomplete coverage | 0 |" in text
        assert "not complete" not in text and "cannot be taken" not in text
        not_checked = _section(text, "Not checked")
        assert "Every stage completed" in not_checked
        assert "acme.test" not in not_checked and "|" not in not_checked

    def test_summary_lists_at_most_fifty_gaps_and_the_report_says_so(self, env) -> None:
        store = env["store"]
        stamps = {f"h{n:03}.acme.test": ("failed", "nuclei: exit 2, no output") for n in range(70)}
        store.stamp_coverage("acme", "issues", stamps, "r1")
        store.set_coverage("acme", "h000.acme.test", "urls", "partial", "katana: timed out", "r1")
        summary = _queries(env).summary("acme")
        assert len(summary["coverage_gaps"]) == MAX_SUMMARY_GAPS == 50
        assert summary["coverage"]["failed"] == 70 and summary["coverage_gap_assets"] == 70
        text = render_report("acme", summary, {}, generated_at=0)
        assert "| Assets with incomplete coverage | 70 |" in text
        assert "Showing 50 of 71 gaps" in _section(text, "Not checked")

    def test_coverage_query_by_asset_puts_gaps_first(self, env) -> None:
        self._two_faults(env)
        queries = _queries(env)
        everything = queries.coverage("acme")
        assert everything["total"] == 21 and not everything["truncated"]
        assert everything["counts"] == {"complete": 17, "partial": 2, "failed": 2, "skipped": 0}
        statuses = [row["status"] for row in everything["coverage"]]
        assert "complete" not in statuses[:4] and set(statuses[4:]) == {"complete"}

        one = queries.coverage("acme", asset="new.acme.test")
        assert {(r["stage"], r["status"]) for r in one["coverage"]} == {
            ("dns", "complete"),
            ("port", "complete"),
            ("live", "failed"),
            ("fingerprint", "failed"),
        }
        assert one["counts"] == {"complete": 2, "partial": 0, "failed": 2, "skipped": 0}
        # A URL names its host; an unknown asset has no stamps (not "all complete").
        by_url = queries.coverage("acme", asset="https://NEW.acme.test:8443/login")
        assert by_url["asset"] == "new.acme.test" and by_url["coverage"] == one["coverage"]
        unknown = queries.coverage("acme", asset="ghost.acme.test")
        assert unknown["coverage"] == [] and unknown["total"] == 0
        assert unknown["counts"]["complete"] == 0

        page = queries.coverage("acme", limit=5)
        assert len(page["coverage"]) == 5 and page["truncated"] and page["next_offset"] == 5
        json.dumps(everything)

    def test_coverage_query_is_bound_to_the_engagement(self, env) -> None:
        _pipeline(env).run()
        bound = ReconQueries(env["store"], None, data_root=env["root"], engagement="acme")
        assert bound.coverage("acme")["total"] > 0
        with pytest.raises(QueryError):
            bound.coverage("other")
        with pytest.raises(QueryError):
            bound.coverage("")
