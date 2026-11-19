"""``buggy-cli status``: one truthful, read-only snapshot of an engagement.

No stack is contacted. The roots are real directories under ``tmp_path``; the
remote reader is a fake that returns canned results, or - where the contract
with a store matters - the real recon store and the real capture gateway
behind a fake origin. The files are written by the code that writes them in
production (scope writer, gateway, ``approvals`` CLI, audit sink).
"""

from __future__ import annotations

import copy
import io
import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.mcp_server import CaptureTools
from buggy.cli import _paths, status
from buggy.cli import approvals as approvals_cli
from buggy.cli.__main__ import main as cli_main
from buggy.middleware._audit_sink import RoEAuditSink
from buggy.pipeline.query import ReconQueries
from buggy.pipeline.schema import Record, RecordType
from buggy.pipeline.store import ReconStore

NOW = 1_800_000_000.0

RECON = ("recon", "recon_summary")
CAPTURES = ("capture", "http_captures")
FINDINGS = ("capture", "findings_list")
REMOTE_SECTIONS = {"recon": RECON, "evidence": CAPTURES, "findings": FINDINGS}
ALL_SECTIONS = ("scope", "recon", "approvals", "evidence", "findings", "agents")


def roe(**top: Any) -> dict[str, Any]:
    """A scope document in the shape ``buggy-cli hunt`` writes."""
    document: dict[str, Any] = {
        "version": 1,
        "engagement_name": "acme",
        "machine_enforcement": {
            "mode": "enforce",
            "in_scope": ["app.acme.test", "**.acme.test"],
            "out_of_scope": ["admin.acme.test"],
            "forbidden_command_patterns": [],
            "min_inter_request_delay_ms": 200,
            "max_concurrent_connections": 5,
            "sandbox_egress": "blocked",
        },
        "pipeline": {"rate_limit_rps": 5, "concurrency": 5},
        "approvals": {"state_changing": "required"},
        "network": {"allow_private_targets": False},
    }
    document.update(top)
    return document


def running_summary() -> dict[str, Any]:
    return {
        "engagement": "acme",
        "record_types": [],
        "records": {"subdomain": 12, "url": 150, "endpoint": 200, "http_service": 4},
        "current_run": {
            "run_id": "run-2",
            "trigger": "scope:new",
            "started_at": NOW - 125,
            "stage": "urls",
            "stages_done": ["enumerate", "dns", "live", "fingerprint"],
        },
        "last_run": None,
    }


def completed_summary() -> dict[str, Any]:
    return {
        "engagement": "acme",
        "record_types": [],
        "records": {"subdomain": 12, "url": 150},
        "current_run": None,
        "last_run": {
            "run_id": "run-1",
            "status": "completed",
            "trigger": "scope:new",
            "started_at": NOW - 900,
            "finished_at": NOW - 300,
            "diff": {"added": 162, "changed": 0, "removed": 0},
            "scope_drops": 4,
            "tool_versions": {},
        },
    }


def finding(number: int, status_: str, severity: str, grade: str | None) -> dict[str, Any]:
    """A finding in the shape of ``board/CONTRACTS.md``."""
    return {
        "id": f"F-{number:012x}",
        "engagement": "acme",
        "title": f"Finding {number}",
        "class": "access_control",
        "cwe": "CWE-639",
        "severity": severity,
        "endpoint": f"https://app.acme.test/api/orders/{number}",
        "method": "GET",
        "parameter": "id",
        "source": "probe:idor",
        "status": status_,
        "grade": grade,
        "grade_reasons": [],
    }


FINDING_ROWS = [
    finding(1, "exploit_verified", "high", "submit"),
    finding(2, "exploit_verified", "critical", "hold"),
    finding(3, "candidate", "medium", None),
    finding(4, "inconclusive", "low", None),
    finding(5, "discarded", "info", "discard"),
]


class World:
    """One engagement, ``acme``, with a healthy stack; each test changes what it is about."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path
        self.control = tmp_path / "control"
        self.audit = tmp_path / "audit"
        self.audit.mkdir()
        _paths.write_control_roe(self.control, "acme", roe())
        self.now = NOW
        self.responses: dict[tuple[str, str], Any] = {
            RECON: completed_summary(),
            CAPTURES: {"captures": [], "count": 0},
            FINDINGS: {"findings": []},
        }
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.sleeps: list[float] = []
        self.after_sleep: Any = None

    # the remote reader and the clock
    def fetch(self, server: str, tool: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((server, tool, dict(arguments)))
        response = self.responses[(server, tool)]
        if isinstance(response, BaseException):
            raise response
        if callable(response):
            return response(arguments)
        return copy.deepcopy(response)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        assert len(self.sleeps) <= 20, "--follow did not stop"
        self.now += seconds
        if self.after_sleep is not None:
            self.after_sleep(len(self.sleeps))

    # what is under test
    def snapshot(self, engagement: str = "acme") -> dict[str, Any]:
        return status.snapshot(
            engagement, control=self.control, audit=self.audit, fetch=self.fetch, now=self.now
        )

    def main(self, *argv: str, engagement: str = "acme") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = status.main(
            [
                engagement,
                "--control-root",
                str(self.control),
                "--audit-root",
                str(self.audit),
                *argv,
            ],
            fetch=self.fetch,
            clock=lambda: self.now,
            sleep=self.sleep,
            stdout=out,
            stderr=err,
        )
        return code, out.getvalue(), err.getvalue()

    # files, written the way production writes them
    def paths(self) -> tuple[Path, Path]:
        return approvals_cli.paths_for(self.control, self.audit, "acme")

    def request(self, request_id: str, **fields: Any) -> None:
        """An approval request as the capture gateway files it."""
        requests_path, _ = self.paths()
        record = {
            "kind": "approval_request",
            "request_id": request_id,
            "engagement_name": "acme",
            "agent_name": "capture-gateway",
            "tool_name": "http_send",
            "tool_args_redacted": {
                "method": "POST",
                "url": f"https://app.acme.test/api/orders/{request_id}",
                "body_sha256": "0" * 64,
                "body_preview": "",
            },
            "reason": "POST can change state on the target",
            "created_at": NOW - 30,
            "metadata": {"fingerprint": request_id},
        }
        record.update(fields)
        requests_path.parent.mkdir(parents=True, exist_ok=True)
        with requests_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def decide(self, request_id: str, action: str) -> None:
        _, decisions_path = self.paths()
        approvals_cli.record_decision(decisions_path, request_id, action, operator="op")

    def ledger(self, **record: Any) -> None:
        RoEAuditSink(path=self.audit / "acme" / "roe-decisions.jsonl").append(record)

    def tree(self) -> dict[str, tuple[int, int]]:
        return {
            str(path.relative_to(self.root)): (path.stat().st_mtime_ns, path.stat().st_size)
            for path in sorted(self.root.rglob("*"))
        }


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


@pytest.fixture
def busy(world: World) -> World:
    """A run in progress with something in every section."""
    (world.control / "acme" / "program.json").write_text(
        json.dumps({"schema": 1, "platform": "hackerone", "handle": "acme", "name": "Acme"})
    )
    world.responses[RECON] = running_summary()
    world.responses[CAPTURES] = {
        "captures": [{"capture_id": "cap-9", "created_at": NOW - 60, "method": "GET"}],
        "count": 37,
    }
    world.responses[FINDINGS] = {"findings": FINDING_ROWS, "count": len(FINDING_ROWS)}
    world.request("apr-1")
    world.request("apr-2")
    world.request("apr-3")
    world.request(
        "rpt-1",
        agent_name="reporting",
        tool_name="report_submission",
        tool_args_redacted={"finding_id": "F-000000000001", "kind": "report"},
        reason="release the report for F-000000000001 for submission to the program",
    )
    world.decide("apr-2", "allow")
    world.decide("apr-3", "deny")
    world.ledger(ts=NOW - 20, engagement="acme", tool="execute", decision="allow")
    world.ledger(ts=NOW - 10, engagement="acme", tool="execute", decision="refuse")
    world.ledger(ts=NOW - 5, engagement="acme", tool="http_request", decision="allow")
    return world


# ── the whole snapshot ───────────────────────────────────────────────


class TestFullSnapshot:
    def test_every_section_and_the_next_hints(self, busy: World) -> None:
        assert busy.snapshot() == {
            "engagement": "acme",
            "generated_at": NOW,
            "scope": {
                "available": True,
                "mode": "enforce",
                "in_scope": ["app.acme.test", "**.acme.test"],
                "out_of_scope": ["admin.acme.test"],
                "rate_limit_rps": 5,
                "sandbox_egress": "blocked",
                "approvals": {"state_changing": "required", "report_submission": "not_required"},
                "program": {"platform": "hackerone", "handle": "acme"},
            },
            "recon": {
                "available": True,
                "state": "running",
                "stage": "urls",
                "stages_done": ["enumerate", "dns", "live", "fingerprint"],
                "started_at": NOW - 125,
                "elapsed_s": 125.0,
                "records": {"endpoint": 200, "http_service": 4, "subdomain": 12, "url": 150},
                "scope_drops": None,
            },
            "approvals": {
                "available": True,
                "total": 4,
                "pending": 2,
                "allowed": 1,
                "denied": 1,
                "other": 0,
                "pending_requests": [
                    {
                        "request_id": "apr-1",
                        "tool_name": "http_send",
                        "reason": "POST can change state on the target",
                        "method": "POST",
                        "url": "https://app.acme.test/api/orders/apr-1",
                    },
                    {
                        "request_id": "rpt-1",
                        "tool_name": "report_submission",
                        "reason": "release the report for F-000000000001 for submission to "
                        "the program",
                    },
                ],
            },
            "evidence": {
                "available": True,
                "count": 37,
                "count_is_lower_bound": False,
                "last_capture_at": NOW - 60,
            },
            "findings": {
                "available": True,
                "total": 5,
                "by_status": {
                    "candidate": 1,
                    "exploit_verified": 2,
                    "source_verified": 0,
                    "inconclusive": 1,
                    "discarded": 1,
                },
                "by_grade": {"submit": 1, "hold": 1, "discard": 1, "ungraded": 2},
                "exploit_verified": [
                    {
                        "id": "F-000000000002",
                        "title": "Finding 2",
                        "severity": "critical",
                        "class": "access_control",
                    },
                    {
                        "id": "F-000000000001",
                        "title": "Finding 1",
                        "severity": "high",
                        "class": "access_control",
                    },
                ],
            },
            "agents": {
                "available": True,
                "last": {"at": NOW - 5, "tool": "http_request", "decision": "allow", "event": ""},
                "allow": 2,
                "refuse": 1,
            },
            "next": [
                "2 requests wait for approval: buggy-cli approvals list acme",
                "Recon is running (stage: urls): buggy-cli status acme --follow",
                "2 findings are exploit-verified and ready for review",
                "2 findings are not verified yet (candidate or inconclusive) and do not count "
                "as findings",
            ],
        }

    def test_the_remote_reads_are_bound_to_the_engagement(self, busy: World) -> None:
        busy.snapshot()
        assert busy.calls == [
            ("recon", "recon_summary", {"engagement": "acme"}),
            ("capture", "http_captures", {"engagement": "acme", "limit": 1}),
            ("capture", "findings_list", {"engagement": "acme"}),
        ]

    def test_a_quiet_finished_engagement_has_nothing_to_do(self, world: World) -> None:
        # Negative control for every hint above: no pending request, recon complete,
        # no finding, an agent has acted.
        world.ledger(ts=NOW - 5, engagement="acme", tool="execute", decision="allow")
        snap = world.snapshot()
        assert snap["next"] == []
        assert snap["approvals"]["pending"] == 0
        assert snap["approvals"]["pending_requests"] == []
        assert snap["findings"]["exploit_verified"] == []
        assert snap["scope"]["program"] is None
        assert all(snap[name]["available"] for name in ALL_SECTIONS)

    def test_the_snapshot_is_json_serialisable(self, busy: World) -> None:
        snap = busy.snapshot()
        assert json.loads(json.dumps(snap)) == snap

    def test_nothing_is_written(self, busy: World) -> None:
        before = busy.tree()
        assert busy.main()[0] == 0
        assert busy.main("--json")[0] == 0
        assert busy.main("--follow", engagement="nope")[0] == 2
        assert busy.tree() == before


# ── scope ────────────────────────────────────────────────────────────


class TestScope:
    def test_rate_limit_is_the_enforced_ceiling_not_the_requested_rate(self, world: World) -> None:
        document = roe(pipeline={"rate_limit_rps": 50})
        document["machine_enforcement"]["min_inter_request_delay_ms"] = 500
        _paths.write_control_roe(world.control, "acme", document)
        assert world.snapshot()["scope"]["rate_limit_rps"] == 2

    def test_lab_scope_reports_its_looser_settings(self, world: World) -> None:
        document = roe(
            approvals={"state_changing": "not_required", "report_submission": "required"}
        )
        document["machine_enforcement"]["sandbox_egress"] = "scoped"
        document["machine_enforcement"]["mode"] = "warn"
        _paths.write_control_roe(world.control, "acme", document)
        scope = world.snapshot()["scope"]
        assert scope["mode"] == "warn"
        assert scope["sandbox_egress"] == "scoped"
        assert scope["approvals"] == {
            "state_changing": "not_required",
            "report_submission": "required",
        }

    def test_no_enforced_scope_is_unavailable_not_empty(self, world: World) -> None:
        (world.control / "acme" / "roe.json").unlink()
        snap = world.snapshot()
        assert snap["scope"]["available"] is False
        assert "no enforced scope" in snap["scope"]["detail"]
        assert "in_scope" not in snap["scope"]
        assert snap["next"][0].endswith("buggy-cli scope show acme")
        assert world.main()[0] == 0

    @pytest.mark.parametrize(
        "text",
        [
            "{not json",
            json.dumps({"engagement_name": "acme"}),  # no machine_enforcement block
            json.dumps({"machine_enforcement": {"mode": "sometimes", "in_scope": ["a.test"]}}),
        ],
    )
    def test_a_scope_the_guardrail_would_reject_is_unavailable(
        self, world: World, text: str
    ) -> None:
        (world.control / "acme" / "roe.json").write_text(text)
        scope = world.snapshot()["scope"]
        assert scope["available"] is False
        assert scope["detail"]
        assert world.main("--json")[0] == 0

    def test_a_damaged_program_record_is_reported(self, world: World) -> None:
        (world.control / "acme" / "program.json").write_text("{not json")
        snap = world.snapshot()
        assert snap["scope"]["available"] is True
        assert "not valid JSON" in snap["scope"]["program"]["invalid"]
        assert any("program record is damaged" in hint for hint in snap["next"])


# ── recon, against the real recon store ──────────────────────────────


class ReconWorld:
    def __init__(self, world: World, tmp_path: Path) -> None:
        self.world = world
        self.store = ReconStore(tmp_path / "pipeline" / "recon.sqlite3")
        queries = ReconQueries(self.store, None, data_root=tmp_path / "pipeline")
        world.responses[RECON] = lambda arguments: queries.summary(arguments["engagement"])

    def recon(self, *, after_start: float = 0.0) -> dict[str, Any]:
        run = self.store.latest_run("acme", finished_only=False)
        if run is not None:
            self.world.now = float(run["started_at"]) + after_start
        return self.world.snapshot()["recon"]

    def add_subdomains(self, run_id: str, *names: str) -> None:
        self.store.write_records(
            run_id,
            "acme",
            "enumerate",
            [
                (Record(RecordType.SUBDOMAIN, name, name, "subfinder"), "acme.test")
                for name in names
            ],
            tool_version="2.17.0",
            raw_ref="",
        )


@pytest.fixture
def recon_world(world: World, tmp_path: Path):
    out = ReconWorld(world, tmp_path)
    yield out
    out.store.close()


class TestReconStates:
    def test_no_run_yet(self, recon_world: ReconWorld) -> None:
        assert recon_world.recon() == {
            "available": True,
            "state": "not_started",
            "stage": "",
            "stages_done": [],
            "started_at": None,
            "elapsed_s": None,
            "records": {},
            "scope_drops": None,
        }
        hints = recon_world.world.snapshot()["next"]
        assert any(hint.startswith("Recon has not started") for hint in hints)

    def test_running_names_the_stage_and_counts_the_clock(self, recon_world: ReconWorld) -> None:
        run = recon_world.store.begin_run("acme", trigger="scope:new")
        recon_world.add_subdomains(run, "a.acme.test", "b.acme.test")
        recon_world.store.set_run_progress(run, stage="live", done=["enumerate", "dns"])
        started = recon_world.store.get_run(run)["started_at"]
        assert recon_world.recon(after_start=90.5) == {
            "available": True,
            "state": "running",
            "stage": "live",
            "stages_done": ["enumerate", "dns"],
            "started_at": started,
            "elapsed_s": 90.5,
            "records": {"subdomain": 2},
            "scope_drops": None,
        }
        hints = recon_world.world.snapshot()["next"]
        assert "Recon is running (stage: live): buggy-cli status acme --follow" in hints

    def test_completed(self, recon_world: ReconWorld) -> None:
        run = recon_world.store.begin_run("acme", trigger="scope:new")
        recon_world.add_subdomains(run, "a.acme.test")
        recon_world.store.finish_run(run, status="completed", stats={"scope_drops": 3})
        stored = recon_world.store.get_run(run)
        recon = recon_world.recon(after_start=5000)
        assert recon["state"] == "completed"
        assert recon["stage"] == "" and recon["stages_done"] == []
        assert recon["scope_drops"] == 3
        assert recon["records"] == {"subdomain": 1}
        # A finished run's duration, not the time since it started.
        assert recon["elapsed_s"] == round(stored["finished_at"] - stored["started_at"], 1)
        assert recon["elapsed_s"] < 5000
        assert status.is_settled(recon_world.world.snapshot())

    def test_interrupted_is_not_finished(self, recon_world: ReconWorld) -> None:
        run = recon_world.store.begin_run("acme", trigger="scope:new")
        recon_world.store.set_run_progress(run, stage="urls", done=["enumerate"])
        recon_world.store.interrupt_run(run, reason="the pipeline process stopped mid-run")
        snap = recon_world.world.snapshot()
        assert snap["recon"]["state"] == "interrupted"
        assert any(hint.startswith("Recon was interrupted") for hint in snap["next"])
        assert not status.is_settled(snap)

    def test_failed(self, recon_world: ReconWorld) -> None:
        run = recon_world.store.begin_run("acme", trigger="scope:new")
        recon_world.store.finish_run(run, status="failed", stats={"error": "boom"})
        snap = recon_world.world.snapshot()
        assert snap["recon"]["state"] == "failed"
        assert any("buggy-cli pipeline run acme" in hint for hint in snap["next"])
        assert status.is_settled(snap)

    def test_a_new_run_after_a_finished_one_is_running(self, recon_world: ReconWorld) -> None:
        first = recon_world.store.begin_run("acme", trigger="scope:new")
        recon_world.store.finish_run(first, status="completed", stats={"scope_drops": 9})
        second = recon_world.store.begin_run("acme", trigger="refresh")
        recon_world.store.set_run_progress(second, stage="dns", done=["enumerate"])
        recon = recon_world.recon(after_start=10)
        assert recon["state"] == "running" and recon["stage"] == "dns"
        # The drop count of the earlier run is not passed off as this run's.
        assert recon["scope_drops"] is None

    def test_another_engagements_run_is_not_reported(self, recon_world: ReconWorld) -> None:
        run = recon_world.store.begin_run("other", trigger="scope:new")
        recon_world.store.finish_run(run, status="completed", stats={})
        assert recon_world.recon()["state"] == "not_started"

    def test_recon_will_not_start_outside_enforce_mode(self, world: World) -> None:
        document = roe()
        document["machine_enforcement"]["mode"] = "audit"
        _paths.write_control_roe(world.control, "acme", document)
        world.responses[RECON] = {"records": {}, "current_run": None, "last_run": None}
        hints = world.snapshot()["next"]
        assert any(hint.startswith("Recon will not start") for hint in hints)
        assert not any(hint.startswith("Recon has not started") for hint in hints)

    def test_an_empty_result_is_not_read_as_not_started(self, world: World) -> None:
        world.responses[RECON] = {}
        recon = world.snapshot()["recon"]
        assert recon == {"available": False, "detail": "recon.recon_summary returned no run state"}


# ── approvals ────────────────────────────────────────────────────────


class TestApprovalsJoin:
    def test_pending_allowed_and_denied(self, world: World) -> None:
        for request_id in ("apr-1", "apr-2", "apr-3"):
            world.request(request_id)
        world.decide("apr-2", "allow")
        world.decide("apr-3", "deny")
        approvals = world.snapshot()["approvals"]
        assert (approvals["pending"], approvals["allowed"], approvals["denied"]) == (1, 1, 1)
        assert [item["request_id"] for item in approvals["pending_requests"]] == ["apr-1"]

    def test_a_denied_request_is_not_pending(self, world: World) -> None:
        world.request("apr-1")
        before = world.snapshot()
        assert before["approvals"]["pending"] == 1
        assert before["next"] == ["1 request waits for approval: buggy-cli approvals list acme"]
        assert not status.is_settled(before)

        world.decide("apr-1", "deny")
        after = world.snapshot()
        assert after["approvals"]["pending"] == 0
        assert after["approvals"]["denied"] == 1
        assert after["approvals"]["allowed"] == 0
        assert after["approvals"]["pending_requests"] == []
        assert not any("approval" in hint for hint in after["next"])
        assert status.is_settled(after)

    def test_the_last_decision_counts(self, world: World) -> None:
        world.request("apr-1")
        world.decide("apr-1", "deny")
        world.decide("apr-1", "allow")
        approvals = world.snapshot()["approvals"]
        assert (approvals["allowed"], approvals["denied"], approvals["pending"]) == (1, 0, 0)

    def test_a_decision_for_another_request_decides_nothing(self, world: World) -> None:
        world.request("apr-1")
        world.decide("apr-999", "allow")
        approvals = world.snapshot()["approvals"]
        assert approvals["total"] == 1
        assert (approvals["pending"], approvals["allowed"]) == (1, 0)

    def test_a_request_filed_twice_is_one_request(self, world: World) -> None:
        world.request("apr-1")
        world.request("apr-1")
        approvals = world.snapshot()["approvals"]
        assert approvals["total"] == 1 and approvals["pending"] == 1

    def test_an_unknown_action_is_neither_allowed_nor_pending(self, world: World) -> None:
        world.request("apr-1")
        world.decide("apr-1", "redirect")
        approvals = world.snapshot()["approvals"]
        assert approvals["other"] == 1
        assert (approvals["pending"], approvals["allowed"], approvals["denied"]) == (0, 0, 0)

    def test_method_and_url_only_when_the_request_has_them(self, world: World) -> None:
        world.request("apr-1")
        world.request("rpt-1", tool_name="report_submission", tool_args_redacted={"kind": "x"})
        first, second = world.snapshot()["approvals"]["pending_requests"]
        assert first["method"] == "POST" and first["url"].endswith("/apr-1")
        assert "method" not in second and "url" not in second

    def test_no_approval_files_means_no_requests(self, world: World) -> None:
        approvals = world.snapshot()["approvals"]
        assert approvals == {
            "available": True,
            "total": 0,
            "pending": 0,
            "allowed": 0,
            "denied": 0,
            "other": 0,
            "pending_requests": [],
        }

    def test_torn_lines_are_skipped(self, world: World) -> None:
        world.request("apr-1")
        requests_path, _ = world.paths()
        with requests_path.open("a", encoding="utf-8") as handle:
            handle.write('{"request_id": "apr-2", "tool_na\n\n[1, 2]\n')
        assert world.snapshot()["approvals"]["total"] == 1

    def test_unreadable_approval_files_are_unavailable(self, world: World) -> None:
        requests_path, _ = world.paths()
        requests_path.mkdir(parents=True)  # a directory where the file should be
        snap = world.snapshot()
        assert snap["approvals"]["available"] is False
        assert "cannot read the approval files" in snap["approvals"]["detail"]
        assert "pending" not in snap["approvals"]
        assert not status.is_settled(snap)
        assert world.main()[0] == 0


class Site:
    """A fake origin (copied from tests/unit/capture/test_gateway.py)."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], object] = {}
        self.seen: list[tuple[str, str]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        self.seen.append((method, url))
        status_code, payload = self.routes.get((method, url), (404, b"not found"))
        if status_code >= 300:
            raise urllib.error.HTTPError(url, status_code, "x", {}, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status_code, {"Content-Type": "text/plain"}
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


@pytest.fixture
def gateway_world(world: World, tmp_path: Path):
    """The real capture gateway and its tools, over the same roots as ``status``."""
    site = Site()
    roots = Roots(control=world.control, audit=world.audit, data=tmp_path / "capture")
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    tools = CaptureTools(gateway)
    world.responses[CAPTURES] = lambda arguments: tools.http_captures(**arguments)
    yield world, tools, site
    gateway.store.close()


class TestAgainstTheRealGateway:
    def test_a_held_request_is_pending_until_the_operator_answers(self, gateway_world) -> None:
        world, tools, site = gateway_world
        url = "https://app.acme.test/api/orders"
        held = tools.http_send("acme", "POST", url, body='{"qty": 1}')
        assert held["code"] == "APPROVAL_REQUIRED"
        assert site.seen == []

        approvals = world.snapshot()["approvals"]
        assert approvals["pending"] == 1
        assert approvals["pending_requests"] == [
            {
                "request_id": held["request_id"],
                "tool_name": "http_send",
                "reason": "POST can change state on the target",
                "method": "POST",
                "url": url,
            }
        ]

        code = approvals_cli.main(
            [
                "--control-root",
                str(world.control),
                "--audit-root",
                str(world.audit),
                "deny",
                "acme",
                held["request_id"],
            ]
        )
        assert code == 0
        approvals = world.snapshot()["approvals"]
        assert (approvals["pending"], approvals["denied"]) == (0, 1)

    def test_no_capture_yet(self, gateway_world) -> None:
        world, _tools, _site = gateway_world
        assert world.snapshot()["evidence"] == {
            "available": True,
            "count": 0,
            "count_is_lower_bound": False,
            "last_capture_at": None,
        }

    def test_a_page_count_is_never_passed_off_as_the_total(self, gateway_world) -> None:
        world, tools, site = gateway_world
        for path in ("a", "b", "c"):
            site.routes[("GET", f"https://app.acme.test/{path}")] = (200, b"ok")
            assert tools.http_send("acme", "GET", f"https://app.acme.test/{path}")["status"]
        newest = tools.gateway.store.list("acme", limit=1)[0]
        evidence = world.snapshot()["evidence"]
        # The server counts the one row it was asked for, and three exist.
        assert evidence["count"] == 1
        assert evidence["count_is_lower_bound"] is True
        assert evidence["last_capture_at"] == newest.created_at
        assert "at least 1 capture" in world.main()[1]


class TestEvidence:
    def test_a_total_reported_by_the_server_is_exact(self, world: World) -> None:
        world.responses[CAPTURES] = {"captures": [{"created_at": NOW - 1}], "count": 37}
        evidence = world.snapshot()["evidence"]
        assert (evidence["count"], evidence["count_is_lower_bound"]) == (37, False)
        text = world.main()[1]
        assert "37 captures" in text and "at least" not in text


# ── findings and agents ──────────────────────────────────────────────


class TestFindings:
    def test_only_exploit_verified_findings_are_listed(self, world: World) -> None:
        world.responses[FINDINGS] = {
            "findings": [
                finding(1, "candidate", "critical", None),
                finding(2, "inconclusive", "critical", None),
                finding(3, "source_verified", "high", "hold"),
                finding(4, "discarded", "high", "discard"),
            ]
        }
        snap = world.snapshot()
        assert snap["findings"]["exploit_verified"] == []
        assert snap["findings"]["by_status"]["exploit_verified"] == 0
        assert snap["findings"]["total"] == 4
        assert not any("exploit-verified" in hint for hint in snap["next"])
        assert any(hint.startswith("2 findings are not verified yet") for hint in snap["next"])

    def test_a_bare_list_result_is_read(self, world: World) -> None:
        # call_mcp_sync wraps a tool result that is not an object as {"result": ...}.
        world.responses[FINDINGS] = {"result": [finding(1, "exploit_verified", "low", "submit")]}
        findings = world.snapshot()["findings"]
        assert [item["id"] for item in findings["exploit_verified"]] == ["F-000000000001"]

    def test_a_result_without_a_finding_list_is_unavailable(self, world: World) -> None:
        world.responses[FINDINGS] = {"count": 3}
        findings = world.snapshot()["findings"]
        assert findings == {
            "available": False,
            "detail": "capture.findings_list returned no finding list",
        }


class TestAgents:
    def test_no_ledger_means_no_recorded_activity(self, world: World) -> None:
        snap = world.snapshot()
        assert snap["agents"] == {"available": True, "last": None, "allow": 0, "refuse": 0}

    HUNT_HINT = "buggy hunt <target> --engagement-name acme continues from this recon"

    def _suggests_hunt(self, world: World) -> bool:
        return any(self.HUNT_HINT in line for line in world.snapshot()["next"])

    def test_no_trace_of_an_agent_after_recon_suggests_starting_them(self, world: World) -> None:
        assert self._suggests_hunt(world)

    def test_a_guardrail_decision_is_a_trace(self, world: World) -> None:
        world.ledger(ts=NOW - 5, engagement="acme", tool="execute", decision="refuse")
        assert not self._suggests_hunt(world)

    def test_a_capture_is_a_trace(self, world: World) -> None:
        world.responses[CAPTURES] = {"captures": [{"created_at": NOW - 1}], "count": 1}
        assert not self._suggests_hunt(world)

    def test_an_approval_request_is_a_trace(self, world: World) -> None:
        world.request("apr-1")
        world.decide("apr-1", "allow")
        assert not self._suggests_hunt(world)

    def test_unreadable_evidence_is_not_taken_as_no_trace(self, world: World) -> None:
        world.responses[CAPTURES] = {"error": "the capture server is not configured"}
        assert not self._suggests_hunt(world)

    def test_recon_still_running_does_not_suggest_a_hunt(self, world: World) -> None:
        world.responses[RECON] = running_summary()
        assert not self._suggests_hunt(world)

    def test_a_last_line_without_a_decision_is_not_given_one(self, world: World) -> None:
        world.ledger(ts=NOW - 9, engagement="acme", tool="execute", decision="allow")
        world.ledger(ts=NOW - 8, engagement="acme", tool="execute", event="throttle")
        agents = world.snapshot()["agents"]
        assert agents["last"] == {
            "at": NOW - 8,
            "tool": "execute",
            "decision": "",
            "event": "throttle",
        }
        assert (agents["allow"], agents["refuse"]) == (1, 0)

    def test_an_unreadable_ledger_is_unavailable(self, world: World) -> None:
        (world.audit / "acme" / "roe-decisions.jsonl").mkdir(parents=True)
        snap = world.snapshot()
        assert snap["agents"]["available"] is False
        assert any(hint.startswith("Agent activity cannot be read") for hint in snap["next"])
        assert world.main()[0] == 0


# ── remote sections degrade ──────────────────────────────────────────

FAILURES = {
    "raises": RuntimeError("connection refused"),
    "error result": {"error": "the server is not configured (BUGGY_MCP_X_URL)"},
    "not an object": ["unexpected"],
}
REASONS = {
    "raises": "RuntimeError: connection refused",
    "error result": "the server is not configured (BUGGY_MCP_X_URL)",
    "not an object": "returned list, not an object",
}


class TestRemoteSectionsDegrade:
    @pytest.mark.parametrize("failure", list(FAILURES))
    @pytest.mark.parametrize("section", list(REMOTE_SECTIONS))
    def test_one_unreachable_source_costs_one_section(
        self, busy: World, section: str, failure: str
    ) -> None:
        healthy = busy.snapshot()
        busy.responses[REMOTE_SECTIONS[section]] = FAILURES[failure]
        snap = busy.snapshot()

        assert set(snap[section]) == {"available", "detail"}
        assert snap[section]["available"] is False
        assert REASONS[failure] in snap[section]["detail"]
        for other in ALL_SECTIONS:
            if other != section:
                assert snap[other] == healthy[other]
        assert any(snap[section]["detail"] in hint for hint in snap["next"])

        code, out, err = busy.main("--json")
        assert (code, err) == (0, "")
        assert json.loads(out)[section] == snap[section]
        code, out, err = busy.main()
        assert (code, err) == (0, "")
        assert f"unavailable: {snap[section]['detail']}" in out

    def test_everything_remote_down_still_exits_zero(self, busy: World) -> None:
        for key in REMOTE_SECTIONS.values():
            busy.responses[key] = ConnectionError("no route to host")
        snap = busy.snapshot()
        assert [name for name in ALL_SECTIONS if not snap[name]["available"]] == [
            "recon",
            "evidence",
            "findings",
        ]
        # What is on disk is still reported.
        assert snap["approvals"]["pending"] == 2
        assert snap["scope"]["mode"] == "enforce"
        assert busy.main()[0] == 0
        assert busy.main("--json")[0] == 0

    def test_a_healthy_stack_marks_nothing_unavailable(self, busy: World) -> None:
        snap = busy.snapshot()
        assert all(snap[name]["available"] is True for name in ALL_SECTIONS)
        assert "unavailable" not in busy.main()[1]
        assert not any("cannot be read" in hint or "unknown" in hint for hint in snap["next"])

    def test_the_real_reader_without_a_stack(self, world: World, monkeypatch, capsys) -> None:
        # Through the dispatcher, with the production reader and no server configured.
        for variable in ("BUGGY_MCP_RECON_URL", "BUGGY_MCP_CAPTURE_URL"):
            monkeypatch.delenv(variable, raising=False)
        world.request("apr-1")
        code = cli_main(
            [
                "status",
                "acme",
                "--json",
                "--control-root",
                str(world.control),
                "--audit-root",
                str(world.audit),
            ]
        )
        snap = json.loads(capsys.readouterr().out)
        assert code == 0
        assert snap["recon"] == {
            "available": False,
            "detail": "the recon server is not configured (BUGGY_MCP_RECON_URL)",
        }
        assert snap["evidence"]["available"] is False
        assert snap["findings"]["available"] is False
        assert snap["scope"]["available"] is True
        assert snap["approvals"]["pending"] == 1


# ── unknown engagement ───────────────────────────────────────────────


class TestUnknownEngagement:
    def test_exit_2_with_a_clear_message(self, world: World) -> None:
        code, out, err = world.main(engagement="nope")
        assert code == 2
        assert out == ""
        assert f"error: no engagement 'nope' under {world.control}" in err
        assert "known engagements: acme" in err
        assert world.calls == []  # no server is asked about an engagement that does not exist

    def test_json_and_follow_fail_the_same_way(self, world: World) -> None:
        assert world.main("--json", engagement="nope")[0] == 2
        assert world.main("--follow", engagement="nope")[0] == 2
        assert world.sleeps == []

    def test_the_known_engagement_is_found(self, world: World) -> None:
        code, out, err = world.main()
        assert (code, err) == (0, "")
        assert out.startswith("acme · status at ")

    @pytest.mark.parametrize("name", ["../outside", "acme/../acme", ".hidden", "", " acme"])
    def test_a_name_that_is_not_a_slug_never_leaves_the_roots(
        self, world: World, name: str
    ) -> None:
        (world.root / "outside").mkdir()
        (world.control / ".hidden").mkdir()
        with pytest.raises(status.UnknownEngagement):
            world.snapshot(name)
        assert world.calls == []

    def test_an_engagement_with_no_audit_directory_is_still_known(self, world: World) -> None:
        assert not (world.audit / "acme").exists()
        snap = world.snapshot()
        assert snap["approvals"]["available"] and snap["agents"]["available"]


# ── output ───────────────────────────────────────────────────────────


class TestOutput:
    def test_json_output_parses_and_is_the_snapshot(self, busy: World) -> None:
        code, out, err = busy.main("--json")
        assert (code, err) == (0, "")
        assert json.loads(out) == busy.snapshot()

    def test_human_output_is_compact_and_says_what_matters(self, busy: World) -> None:
        code, out, _err = busy.main()
        lines = out.rstrip("\n").splitlines()
        assert code == 0
        assert len(lines) <= 25
        assert lines[0] == "acme · status at 2027-01-15 08:00:00Z"
        text = "\n".join(lines)
        for expected in (
            "enforce mode · 5 req/s · sandbox blocked · state-changing approval required"
            " · program hackerone/acme",
            "app.acme.test, **.acme.test",
            "admin.acme.test",
            "running · stage urls · 4 stages done · started 07:57:55Z · 2:05 elapsed",
            "366 total (endpoint 200, url 150, subdomain 12, http_service 4)",
            "2 pending · 1 allowed · 1 denied",
            "apr-1  http_send POST https://app.acme.test/api/orders/apr-1",
            "37 captures · last 07:59:00Z",
            "1 candidate · 2 exploit_verified · 1 inconclusive · 1 discarded",
            "F-000000000002  critical  access_control  Finding 2",
            "last 07:59:55Z http_request allow · 2 allowed, 1 refused",
            "  - 2 requests wait for approval: buggy-cli approvals list acme",
        ):
            assert expected in text

    def test_long_lists_are_cut_and_say_so(self, world: World) -> None:
        for number in range(8):
            world.request(f"apr-{number}")
        world.responses[FINDINGS] = {
            "findings": [finding(n, "exploit_verified", "high", None) for n in range(9)]
        }
        out = world.main()[1]
        assert len(out.rstrip("\n").splitlines()) <= 25
        assert "(+5 more)" in out
        assert "(+6 more exploit-verified)" in out
        # The JSON keeps every entry.
        snap = json.loads(world.main("--json")[1])
        assert len(snap["approvals"]["pending_requests"]) == 8
        assert len(snap["findings"]["exploit_verified"]) == 9

    def test_nothing_to_do_is_said_in_words(self, world: World) -> None:
        world.ledger(ts=NOW - 5, engagement="acme", tool="execute", decision="allow")
        assert "nothing needs you right now" in world.main()[1]


# ── follow ───────────────────────────────────────────────────────────


def _snap(state: str, *, pending: int = 0, at: float = NOW, elapsed: float | None = None) -> dict:
    return {
        "engagement": "acme",
        "generated_at": at,
        "recon": {"available": True, "state": state, "elapsed_s": elapsed},
        "approvals": {"available": True, "pending": pending},
        "next": [],
    }


class Feed:
    """A sequence of snapshots; reading past its end is a failed test."""

    def __init__(self, *snapshots: dict) -> None:
        self.left = list(snapshots)
        self.emitted: list[dict] = []
        self.sleeps: list[float] = []

    def take(self) -> dict:
        assert self.left, "follow asked for a snapshot after it should have stopped"
        return self.left.pop(0)

    def run(self) -> dict:
        return status.follow(self.take, self.emitted.append, sleep=self.sleeps.append, interval=7.0)


class TestFollow:
    def test_reprints_on_change_and_stops_when_done(self) -> None:
        feed = Feed(
            _snap("running", at=NOW, elapsed=1.0),
            _snap("running", at=NOW + 7, elapsed=8.0),  # only the clock moved
            _snap("completed", pending=1, at=NOW + 14),  # recon done, one request waits
            _snap("completed", pending=1, at=NOW + 21),
            _snap("completed", pending=0, at=NOW + 28),
        )
        last = feed.run()
        assert [(s["recon"]["state"], s["approvals"]["pending"]) for s in feed.emitted] == [
            ("running", 0),
            ("completed", 1),
            ("completed", 0),
        ]
        assert last == feed.emitted[-1]
        assert feed.left == []
        assert feed.sleeps == [7.0, 7.0, 7.0, 7.0]

    def test_already_done_prints_once_and_does_not_wait(self) -> None:
        feed = Feed(_snap("completed"))
        feed.run()
        assert len(feed.emitted) == 1 and feed.sleeps == []

    @pytest.mark.parametrize(
        "snap",
        [
            _snap("running"),
            _snap("not_started"),
            _snap("interrupted"),
            _snap("completed", pending=1),
            {**_snap("completed"), "recon": {"available": False, "detail": "down"}},
            {**_snap("completed"), "approvals": {"available": False, "detail": "unreadable"}},
        ],
    )
    def test_it_keeps_waiting_while_something_is_open(self, snap: dict) -> None:
        assert not status.is_settled(snap)
        feed = Feed(snap, snap, snap)

        def sleep(seconds: float) -> None:
            feed.sleeps.append(seconds)
            if len(feed.sleeps) == 3:
                raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            status.follow(feed.take, feed.emitted.append, sleep=sleep, interval=1.0)
        assert len(feed.emitted) == 1  # unchanged, so printed once
        assert feed.left == []

    @pytest.mark.parametrize("state", ["completed", "failed"])
    def test_final_recon_states_settle(self, state: str) -> None:
        assert status.is_settled(_snap(state))

    def test_the_command_stops_by_itself(self, world: World) -> None:
        world.responses[RECON] = running_summary()
        world.request("apr-1")

        def progress(sleeps: int) -> None:
            if sleeps == 2:
                world.responses[RECON] = completed_summary()
            if sleeps == 4:
                world.decide("apr-1", "allow")

        world.after_sleep = progress
        code, out, err = world.main("--follow", "--json", "--interval", "3")
        printed = [json.loads(line) for line in out.splitlines()]
        assert (code, err) == (0, "")
        assert world.sleeps == [3.0, 3.0, 3.0, 3.0]
        assert [(s["recon"]["state"], s["approvals"]["pending"]) for s in printed] == [
            ("running", 1),
            ("completed", 1),
            ("completed", 0),
        ]
        assert printed[-1]["generated_at"] == NOW + 12

    def test_human_follow_reprints_whole_blocks(self, world: World) -> None:
        world.responses[RECON] = running_summary()
        world.after_sleep = lambda _n: world.responses.__setitem__(RECON, completed_summary())
        code, out, _err = world.main("--follow")
        assert code == 0
        assert out.count("acme · status at ") == 2
        assert world.sleeps == [status.DEFAULT_INTERVAL_SECONDS]

    def test_ctrl_c_ends_follow_cleanly(self, world: World) -> None:
        world.responses[RECON] = running_summary()

        def interrupt(sleeps: int) -> None:
            if sleeps == 3:
                raise KeyboardInterrupt

        world.after_sleep = interrupt
        code, out, err = world.main("--follow", "--json")
        assert (code, err) == (0, "")
        assert len(out.splitlines()) == 1  # nothing changed, so one line
        assert len(world.sleeps) == 3  # and it did not stop by itself

    def test_without_follow_nothing_waits(self, world: World) -> None:
        world.responses[RECON] = running_summary()
        assert world.main()[0] == 0
        assert world.sleeps == []

    @pytest.mark.parametrize("value", ["0", "-1", "soon", "nan", "inf"])
    def test_a_bad_interval_is_a_usage_error(self, world: World, value: str, capsys) -> None:
        with pytest.raises(SystemExit) as raised:
            world.main("--follow", "--interval", value)
        assert raised.value.code == 2
        assert "not a positive number of seconds" in capsys.readouterr().err
