"""The bridge that gives an external agent Buggy's tools for one engagement."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from buggy import agent_bridge
from buggy.agent_bridge import BRIEF_TOOL, Bridge, Guard


def scope(tmp_path: Path, **enforcement) -> Path:
    control = tmp_path / "control"
    (control / "acme").mkdir(parents=True)
    document = {
        "machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"], **enforcement},
        "hunt": {
            "targets": ["https://app.acme.test"],
            "options": {"instruction": "focus on the orders API"},
        },
    }
    (control / "acme" / "roe.json").write_text(json.dumps(document))
    return control


class Tool:
    """A stand-in for one agent tool wrapper."""

    def __init__(self, name: str, answer: object = "ok") -> None:
        self.name = name
        self.description = f"{name} does a thing"
        self.args_schema = {"type": "object", "properties": {"url": {"type": "string"}}}
        self.answer = answer
        self.seen: list[dict] = []

    async def ainvoke(self, args: dict) -> object:
        self.seen.append(args)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def bridge(tmp_path: Path, *tools: Tool, **enforcement) -> Bridge:
    control = scope(tmp_path, **enforcement)
    return Bridge("acme", control, tools={tool.name: tool for tool in tools})


def call(b: Bridge, name: str, **args) -> str:
    return asyncio.run(b.call(name, args))


class TestGuard:
    def guard(self, max_calls: int = 300) -> Guard:
        return Guard(lambda: (), max_calls=max_calls)

    def test_a_normal_call_passes(self) -> None:
        assert self.guard().check("http_send", {"url": "https://app.acme.test/"}) is None

    def test_the_same_call_three_times_in_a_row_is_withheld(self) -> None:
        guard = self.guard()
        args = {"url": "https://app.acme.test/a"}
        assert guard.check("http_send", args) is None
        assert guard.check("http_send", dict(args)) is None
        refusal = guard.check("http_send", args)
        assert refusal is not None and "3 times in a row" in refusal
        # A different call clears it.
        assert guard.check("http_send", {"url": "https://app.acme.test/b"}) is None
        assert guard.check("http_send", args) is None
        assert guard.withheld == 1

    def test_the_run_has_a_call_cap(self) -> None:
        guard = self.guard(max_calls=2)
        assert guard.check("a", {"n": 1}) is None
        assert guard.check("a", {"n": 2}) is None
        refusal = guard.check("a", {"n": 3})
        assert refusal is not None and "used its 2 tool calls" in refusal

    def test_rules_that_cannot_be_read_refuse(self) -> None:
        def broken() -> tuple:
            raise OSError("scope file is gone")

        refusal = Guard(broken, max_calls=10).check("http_send", {"url": "x"})
        assert refusal is not None and refusal.startswith("BLOCKED")


class TestBridge:
    def test_a_call_reaches_the_tool_and_its_answer_comes_back(self, tmp_path: Path) -> None:
        send = Tool("http_send", '{"status": 200}')
        b = bridge(tmp_path, send)
        assert call(b, "http_send", url="https://app.acme.test/") == '{"status": 200}'
        assert send.seen == [{"url": "https://app.acme.test/"}]

    def test_a_non_text_answer_is_serialised(self, tmp_path: Path) -> None:
        b = bridge(tmp_path, Tool("scope_show", {"mode": "enforce"}))
        assert json.loads(call(b, "scope_show")) == {"mode": "enforce"}

    def test_an_unknown_tool_is_refused(self, tmp_path: Path) -> None:
        assert "no tool 'bash'" in call(bridge(tmp_path), "bash", command="id")

    def test_a_failing_tool_answers_with_an_error_not_a_crash(self, tmp_path: Path) -> None:
        b = bridge(tmp_path, Tool("http_send", RuntimeError("gateway down")))
        assert json.loads(call(b, "http_send", url="x")) == {"error": "RuntimeError: gateway down"}

    def test_an_operator_rule_stops_the_call_before_the_tool(self, tmp_path: Path) -> None:
        send = Tool("http_send")
        rule = {"pattern": "(?i)drop\\s+table", "name": "no-ddl", "message": "no schema changes"}
        b = bridge(tmp_path, send, tool_guard=[rule])
        refusal = call(b, "http_send", url="https://app.acme.test/?q=1;DROP%20TABLE users")
        assert refusal == "BLOCKED by rule 'no-ddl': no schema changes"
        assert send.seen == []
        assert call(b, "http_send", url="https://app.acme.test/?q=shoes") == "ok"

    def test_the_listing_offers_the_brief_first_then_every_tool(self, tmp_path: Path) -> None:
        b = bridge(tmp_path, Tool("scope_show"), Tool("http_send"))
        rows = b.listing()
        assert [row["name"] for row in rows] == [BRIEF_TOOL, "http_send", "scope_show"]
        assert all(row["inputSchema"]["type"] == "object" for row in rows)

    def test_the_brief_is_not_counted_or_guarded(self, tmp_path: Path) -> None:
        b = bridge(tmp_path)
        for _ in range(5):
            assert "authorized security engagement" in call(b, BRIEF_TOOL)
        assert b.guard.calls == 0


class TestBrief:
    def test_it_states_the_rules_the_targets_and_the_operators_instruction(
        self, tmp_path: Path
    ) -> None:
        text = agent_bridge.brief(scope(tmp_path), "acme")
        assert "you never approve" in text and "no shell" in text
        assert "Targets: https://app.acme.test." in text
        assert "Operator instruction: focus on the orders API" in text
        assert "candidates_next" in text and "finding_verify" in text
        # A tool this agent does not have is not mentioned.
        assert "report_record_finding" not in text

    def test_targets_fall_back_to_the_enforced_scope(self, tmp_path: Path) -> None:
        control = scope(tmp_path)
        path = control / "acme" / "roe.json"
        document = json.loads(path.read_text())
        del document["hunt"]
        path.write_text(json.dumps(document))
        assert "Targets: app.acme.test." in agent_bridge.brief(control, "acme")


class TestRealTools:
    def test_every_agent_tool_has_an_object_schema(self, monkeypatch) -> None:
        for name in ("RECON", "CAPTURE", "SCOPE", "BROWSER"):
            monkeypatch.setenv(f"BUGGY_MCP_{name}_URL", "http://unused.invalid/mcp")
        table = agent_bridge.tool_table()
        assert {"http_send", "probe_run", "finding_verify", "candidates_next", "scope_show"} <= set(
            table
        )
        assert {"surface_crawl", "authz_matrix_run", "identities_list"} <= set(table)
        for tool in table.values():
            schema = agent_bridge.input_schema(tool)
            assert schema.get("type") == "object", tool.name
            # The engagement and the actor are never arguments the agent supplies.
            assert not {"engagement", "actor"} & set(schema.get("properties") or {}), tool.name

    def test_no_server_configured_means_no_tools(self, monkeypatch) -> None:
        for name in ("RECON", "CAPTURE", "SCOPE", "BROWSER"):
            monkeypatch.delenv(f"BUGGY_MCP_{name}_URL", raising=False)
        assert agent_bridge.tool_table() == {}


class TestMain:
    def test_an_engagement_without_an_enforced_scope_is_refused(
        self, tmp_path: Path, monkeypatch, capfd
    ) -> None:
        monkeypatch.setattr("os.dup2", lambda *_a: None)
        code = agent_bridge.main(["--engagement", "nope", "--control-root", str(tmp_path)])
        assert code == 2 and "no enforced scope" in capfd.readouterr().err

    @pytest.mark.parametrize("name", ["../etc", ".hidden", "a/b"])
    def test_a_path_is_not_an_engagement(self, name: str) -> None:
        assert agent_bridge._valid_engagement(name) is False  # noqa: SLF001

    def test_actor_comes_from_the_process(self, monkeypatch) -> None:
        from buggy.tools import stack_mcp  # noqa: PLC0415

        monkeypatch.setenv("BUGGY_ACTOR", "claude-code")
        assert stack_mcp.current_actor() == "claude-code"
        monkeypatch.delenv("BUGGY_ACTOR")
        assert stack_mcp.current_actor() == "agent"
