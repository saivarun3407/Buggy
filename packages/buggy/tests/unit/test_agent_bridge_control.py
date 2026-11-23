"""The bridge under the operator's control: halt, lease, call log, budget, status, disprover."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from buggy import agent_bridge, agent_records
from buggy.agent_bridge import BRIEF_TOOL, SKEPTIC, Bridge
from buggy.capture import halt


def scope(tmp_path: Path) -> Path:
    control = tmp_path / "control"
    (control / "acme").mkdir(parents=True)
    document = {
        "machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]},
        "hunt": {"targets": ["https://app.acme.test"]},
    }
    (control / "acme" / "roe.json").write_text(json.dumps(document))
    return control


class Tool:
    def __init__(self, name: str, answer: object = "ok") -> None:
        self.name = name
        self.description = name
        self.args_schema = {"type": "object", "properties": {}}
        self.answer = answer
        self.seen: list[dict] = []

    async def ainvoke(self, args: dict) -> object:
        self.seen.append(args)
        return self.answer


LEADS = [
    {"id": "f-1", "title": "Order read by id", "class": "access_control", "endpoint": "/o/1"},
    {"id": "f-2", "title": "Reflected q", "class": "xss", "endpoint": "/search"},
]
VERIFIED = [
    {
        "id": "f-9",
        "title": "IDOR on orders",
        "class": "access_control",
        "source": "claude-code",
        "assertions": [{"capture_id": "cap-00000000000000a1"}],
    },
    {"id": "f-8", "title": "SQLi", "class": "injection", "source": "probe:sqli | claude-code"},
    {"id": "f-7", "title": "judged", "source": "claude-code", "challenge": {"verdict": "stands"}},
]


def fetch(_engagement: str, status: str) -> dict:
    if status == "candidate":
        return {"ok": True, "findings": LEADS, "total": 7}
    return {"ok": True, "findings": VERIFIED}


def make(
    tmp_path: Path, *tools: Tool, role: str = agent_bridge.ROLE, **kwargs
) -> tuple[Bridge, agent_records.RunRecords]:
    control = scope(tmp_path)
    records = agent_records.RunRecords(
        tmp_path / "audit", "acme", run_id="run1", session="s1", role=role, attempt=1
    )
    b = Bridge(
        "acme",
        control,
        tools={tool.name: tool for tool in tools},
        role=role,
        records=records,
        fetch=fetch,
        **kwargs,
    )
    return b, records


def call(b: Bridge, name: str, **args) -> str:
    return asyncio.run(b.call(name, args))


def trace(tmp_path: Path) -> list[dict]:
    return agent_records.calls(tmp_path / "audit", "acme")


class TestHalt:
    def test_a_halt_refuses_the_next_call_and_stops_the_run(self, tmp_path: Path) -> None:
        send = Tool("http_send")
        b, _ = make(tmp_path, send)
        assert call(b, "http_send", url="https://app.acme.test/") == "ok"
        halt.halt(b.control, "acme", reason="client said stop")
        answer = call(b, "http_send", url="https://app.acme.test/2")
        assert answer.startswith("HALTED") and "client said stop" in answer
        assert "final summary" in answer and b.stopped == "HALTED"
        # Even the brief is refused now, and nothing reaches a tool.
        assert call(b, BRIEF_TOOL).startswith("HALTED")
        assert len(send.seen) == 1
        lines = trace(tmp_path)
        assert [line["code"] for line in lines] == ["", "HALTED", "HALTED"]
        assert [line["status"] for line in lines] == ["ok", "refused", "refused"]

    def test_clearing_the_halt_does_not_revive_a_run_it_revoked(self, tmp_path: Path) -> None:
        send = Tool("http_send")
        b, _ = make(tmp_path, send)
        halt.halt(b.control, "acme")
        halt.clear(b.control, "acme")
        answer = call(b, "http_send", url="https://app.acme.test/")
        assert "LEASE_REVOKED" in answer and send.seen == []
        assert b.stopped == "LEASE_REVOKED"
        # A run started after the clear holds a fresh lease and works.
        fresh, _ = make(tmp_path / "again", send)
        halt.halt(fresh.control, "acme")
        halt.clear(fresh.control, "acme")
        fresh = Bridge("acme", fresh.control, tools={"http_send": send}, fetch=fetch)
        assert call(fresh, "http_send", url="https://app.acme.test/") == "ok"

    def test_an_engagement_halted_at_start_refuses_everything(self, tmp_path: Path) -> None:
        control = scope(tmp_path)
        halt.halt(control, "acme")
        b = Bridge("acme", control, tools={"http_send": Tool("http_send")}, fetch=fetch)
        assert call(b, BRIEF_TOOL).startswith("HALTED")

    def test_unreadable_control_state_refuses_but_does_not_stop(self, tmp_path: Path) -> None:
        send = Tool("http_send")
        b, _ = make(tmp_path, send)
        epoch = b.control / "acme" / halt.EPOCH_FILE
        epoch.write_text("garbage")
        answer = call(b, "http_send", url="https://app.acme.test/")
        assert "CONTROL_UNREADABLE" in answer and send.seen == [] and b.stopped == ""
        epoch.write_text("0")
        assert call(b, "http_send", url="https://app.acme.test/") == "ok"

    def test_unreadable_state_at_start_holds_no_lease(self, tmp_path: Path) -> None:
        control = scope(tmp_path)
        (control / "acme" / halt.EPOCH_FILE).write_text("garbage")
        b = Bridge("acme", control, tools={"http_send": Tool("http_send")}, fetch=fetch)
        (control / "acme" / halt.EPOCH_FILE).write_text("0")
        assert "LEASE_REVOKED" in call(b, "http_send", url="https://app.acme.test/")


class TestRecords:
    def test_every_call_is_logged_with_its_refusal_code(self, tmp_path: Path) -> None:
        answer = '{"capture_id": "cap-0123456789abcdef", "status": 200}'
        b, records = make(tmp_path, Tool("http_send", answer), Tool("probe_run", {"ok": False}))
        call(b, "http_send", url="https://app.acme.test/login")
        call(b, "probe_run", probe="sqli")
        call(b, "bash", command="id")
        lines = trace(tmp_path)
        assert [(line["tool"], line["status"], line["code"]) for line in lines] == [
            ("http_send", "ok", ""),
            ("probe_run", "refused", "NOT_OK"),
            ("bash", "refused", "NO_SUCH_TOOL"),
        ]
        first = lines[0]
        assert first["run"] == "run1" and first["session"] == "s1" and first["seq"] == 1
        assert first["captures"] == ["cap-0123456789abcdef"] and first["signin"] is True
        assert len(first["args_digest"]) == 16 and "url" not in json.dumps(first)
        lease = json.loads(records.lease_path.read_text())
        assert lease["run"] == "run1" and lease["epoch"] == 0 and lease["ended_at"] is None
        records.lease_end("ended")
        assert agent_records.open_leases(tmp_path / "audit", "acme") == []

    def test_guard_refusals_carry_their_code(self, tmp_path: Path) -> None:
        b, _ = make(tmp_path, Tool("http_send"), max_calls=2)
        call(b, "http_send", url="a")
        call(b, "http_send", url="b")
        call(b, "http_send", url="c")
        assert trace(tmp_path)[-1]["code"] == "CALL_CAP"

    def test_finding_submit_records_the_captures_it_cites(self, tmp_path: Path) -> None:
        b, _ = make(tmp_path, Tool("finding_submit"))
        b.tools.pop("skill_get", None)
        claim = {"class": "", "assertions": [{"capture_id": "cap-aaaaaaaaaaaaaaaa"}]}
        call(b, "finding_submit", finding_json=json.dumps(claim))
        assert trace(tmp_path)[0]["cited"] == ["cap-aaaaaaaaaaaaaaaa"]

    def test_a_records_folder_that_cannot_be_written_costs_only_the_records(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "audit").write_text("a file where a folder should be")
        b, _ = make(tmp_path, Tool("http_send"))
        assert call(b, "http_send", url="x") == "ok"


class TestBudget:
    def test_a_runs_cap_is_its_share_within_what_the_session_left(self) -> None:
        assert agent_bridge.run_budget(300, 100, 0) == 100
        assert agent_bridge.run_budget(300, 100, 250) == 50
        assert agent_bridge.run_budget(300, 0, 120) == 180
        assert agent_bridge.run_budget(300, 100, 400) == 0

    def test_the_brief_states_the_runs_cap(self, tmp_path: Path) -> None:
        b, _ = make(tmp_path, max_calls=42)
        assert "may make 42 tool calls" in call(b, BRIEF_TOOL)


class TestContinuation:
    def test_a_later_attempt_gets_the_open_leads_and_is_told_they_are_unproven(
        self, tmp_path: Path
    ) -> None:
        b, _ = make(tmp_path, attempt=2, attempts=3)
        text = call(b, BRIEF_TOOL)
        assert "attempt 2 of at most 3" in text and "7 lead(s) still open" in text
        assert "NOT proven" in text and "f-1: Order read by id" in text
        first, _ = make(tmp_path / "first")
        first_brief = call(first, BRIEF_TOOL)
        assert "This is attempt" not in first_brief and "NOT proven" not in first_brief


class TestSkeptic:
    def test_it_gets_only_read_tools_and_its_verdict(self, monkeypatch) -> None:
        for name in ("RECON", "CAPTURE", "SCOPE", "BROWSER"):
            monkeypatch.setenv(f"BUGGY_MCP_{name}_URL", "http://unused.invalid/mcp")
        table = agent_bridge.tool_table(SKEPTIC)
        assert set(table) == {
            "finding_get",
            "findings_list",
            "http_capture",
            "finding_challenge",
            "recon_summary",
            "recon_query",
            "recon_record",
            "recon_assets",
            "skill_list",
            "skill_get",
        }
        for tool in table.values():
            schema = agent_bridge.input_schema(tool)
            assert not {"engagement", "actor"} & set(schema.get("properties") or {})

    def test_its_brief_lists_the_agent_made_findings_not_yet_judged(self, tmp_path: Path) -> None:
        b, _ = make(tmp_path, role=SKEPTIC, max_calls=30)
        text = call(b, BRIEF_TOOL)
        assert "argue that each one is FALSE" in text and "f-9: IDOR on orders" in text
        assert "f-8" not in text  # proven by a probe
        assert "f-7" not in text  # already judged
        assert "may make 30 tool calls" in text

    def test_it_opens_only_captures_a_finding_cites(self, tmp_path: Path) -> None:
        capture = Tool("http_capture", '{"status": 200}')
        get = Tool("finding_get", '{"assertions": [{"capture_id": "cap-00000000000000b2"}]}')
        b, _ = make(tmp_path, capture, get, role=SKEPTIC)
        refused = call(b, "http_capture", capture_id="cap-00000000000000b2")
        assert refused.startswith("BLOCKED") and capture.seen == []
        call(b, "finding_get", finding_id="f-9")
        assert call(b, "http_capture", capture_id="cap-00000000000000b2") == '{"status": 200}'
        call(b, BRIEF_TOOL)  # the brief's findings cite theirs
        assert call(b, "http_capture", capture_id="cap-00000000000000a1") == '{"status": 200}'
        assert trace(tmp_path)[0]["code"] == "CAPTURE_NOT_CITED"


class TestStatus:
    def test_it_reports_halt_budget_calls_and_leads(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("BUGGY_MAX_TOOL_CALLS", "300")
        monkeypatch.delenv("BUGGY_MAX_TOOL_CALLS_CLAUDE_CODE", raising=False)
        b, _ = make(tmp_path, Tool("http_send"))
        for n in range(3):
            call(b, "http_send", url=str(n))
        other = agent_records.RunRecords(
            tmp_path / "audit", "acme", run_id="x", session="s0", role=agent_bridge.ROLE
        )
        other.call("http_send", {}, "ok", started=0.0)
        report = agent_bridge.status(
            b.control, tmp_path / "audit", "acme", session="s1", fetch=fetch
        )
        assert report["halted"] is False and report["budget_total"] == 300
        assert report["calls_used"] == 3 and report["calls_left"] == 297
        assert report["open_leads"] == 7 and report["leads"][0]["id"] == "f-1"
        assert report["to_challenge"] == 1
        assert [run["run"] for run in report["runs"]] == ["run1"]
        halt.halt(b.control, "acme")
        assert agent_bridge.status(b.control, tmp_path / "audit", "acme", fetch=fetch)["halted"]

    def test_a_record_from_the_launcher_is_appended(self, tmp_path: Path) -> None:
        b, _ = make(tmp_path, Tool("http_send"))
        call(b, "http_send", url="x")
        record = {"run": "run1", "role": "agent", "claude": {"total_cost_usd": 0.1}}
        report = agent_bridge.status(
            b.control, tmp_path / "audit", "acme", session="s1", fetch=fetch, record=record
        )
        assert report["recorded"]["tool_calls"] == 1
        summary = agent_records.cost_summary(
            agent_records.read_jsonl(agent_records.runs_file(tmp_path / "audit", "acme"))
        )
        assert summary is not None and summary["cost_usd"] == 0.1

    def test_unreadable_control_counts_as_halted(self, tmp_path: Path) -> None:
        control = scope(tmp_path)
        (control / "acme" / halt.EPOCH_FILE).write_text("x")
        report = agent_bridge.status(control, tmp_path / "audit", "acme", fetch=fetch)
        assert report["halted"] is True and "unreadable" in report["halt_reason"]

    def test_a_capture_server_error_is_reported_not_hidden(self, tmp_path: Path) -> None:
        report = agent_bridge.status(
            scope(tmp_path), tmp_path / "audit", "acme", fetch=lambda *_: {"error": "down"}
        )
        assert report["open_leads"] == 0 and report["errors"] == ["down", "down"]

    def test_main_prints_the_status_as_json(self, tmp_path: Path, monkeypatch, capfd) -> None:
        control = scope(tmp_path)
        monkeypatch.setattr("os.dup2", lambda *_a: None)
        monkeypatch.setattr(agent_bridge, "fetch_findings", fetch)
        code = agent_bridge.main(
            [
                "--engagement",
                "acme",
                "--control-root",
                str(control),
                "--audit-root",
                str(tmp_path / "audit"),
                "--status",
            ]
        )
        out = capfd.readouterr().out.strip().splitlines()[-1]
        assert code == 0 and json.loads(out)["open_leads"] == 7


@pytest.mark.parametrize(
    ("source", "made"),
    [
        ("claude-code", True),
        ("agent:hunter", True),
        ("recipe:idor-orders", True),
        ("probe:idor", False),
        ("pipeline:nuclei | claude-code", False),
        ("", True),
    ],
)
def test_which_findings_are_agent_made(source: str, made: bool) -> None:
    from buggy.findings.service import agent_made  # noqa: PLC0415

    assert agent_made(source) is made
