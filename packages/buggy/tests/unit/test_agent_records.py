"""What agent runs leave behind: refusal codes, sign-in overhead, cost totals."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy import agent_records


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ('{"status": 200}', ("ok", "")),
        ("plain text", ("ok", "")),
        ('{"status": "refused", "code": "OUT_OF_SCOPE"}', ("refused", "OUT_OF_SCOPE")),
        ('{"ok": false, "code": "INVALID_FINDING"}', ("refused", "INVALID_FINDING")),
        ('{"error": "IN_SCOPE_USE_GATEWAY"}', ("error", "IN_SCOPE_USE_GATEWAY")),
        ('{"error": "RuntimeError: boom"}', ("error", "ERROR")),
        ("BLOCKED: this run has used its 3 tool calls.", ("refused", "BLOCKED")),
        ("HALTED [LEASE_REVOKED]: stop", ("refused", "LEASE_REVOKED")),
    ],
)
def test_refusal_code(result: str, expected: tuple[str, str]) -> None:
    assert agent_records.refusal_code(result) == expected


@pytest.mark.parametrize(
    ("tool", "args", "signin"),
    [
        ("identities_list", {}, True),
        ("http_send", {"url": "https://app.acme.test/api/login"}, True),
        ("browser_fill", {"selector": "#password", "text": "x"}, True),
        ("http_send", {"url": "https://app.acme.test/api/orders/1"}, False),
        ("http_send", {"url": "https://app.acme.test/x", "body": "password=1"}, False),
        ("recon_query", {"record_type": "login"}, False),
    ],
)
def test_signin_calls(tool: str, args: dict, signin: bool) -> None:
    assert agent_records.is_signin_call(tool, args) is signin


def test_capture_ids_are_found_once_in_order() -> None:
    text = "cap-00000000000000aa cap-00000000000000bb cap-00000000000000aa cap-123"
    assert agent_records.capture_ids(text) == ["cap-00000000000000aa", "cap-00000000000000bb"]


def run_line(**claude) -> dict:
    return {
        "role": "agent",
        "wall_seconds": 600,
        "tool_calls": 100,
        "signin_calls": 7,
        "claude": claude,
    }


def test_cost_totals_and_line() -> None:
    rows = [
        run_line(
            total_cost_usd=1.25,
            usage={"input_tokens": 1000, "output_tokens": 20000, "cache_read_input_tokens": 900000},
        ),
        run_line(total_cost_usd=0.5, usage={"input_tokens": 10, "cache_creation_input_tokens": 99}),
        {"role": "skeptic", "wall_seconds": 60, "tool_calls": 12},
    ]
    summary = agent_records.cost_summary(rows)
    assert summary is not None
    assert summary["sessions"] == 3 and summary["by_role"] == {"agent": 2, "skeptic": 1}
    assert summary["tool_calls"] == 212 and summary["signin_calls"] == 14
    assert summary["tokens"] == {
        "input": 1010,
        "output": 20000,
        "cache_read": 900000,
        "cache_creation": 99,
    }
    assert summary["cost_usd"] == 1.75 and summary["wall_seconds"] == 1260
    line = agent_records.cost_line(summary)
    assert line == (
        "3 Claude Code session(s), 212 tool calls (14 on sign-in), 901k input and 20k output "
        "tokens, $1.75 as reported by Claude Code, 21.0 min"
    )


def test_no_reported_cost_is_not_zero() -> None:
    summary = agent_records.cost_summary([{"tool_calls": 3, "claude": {"usage": "nonsense"}}])
    assert summary is not None and summary["cost_usd"] is None
    assert "cost not reported" in agent_records.cost_line(summary)
    assert agent_records.cost_summary([]) is None and agent_records.cost_line(None) == ""


def test_runs_file_lines_are_read_and_bad_lines_skipped(tmp_path: Path) -> None:
    path = agent_records.runs_file(tmp_path, "acme")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(run_line()) + "\nnot json\n[1]\n")
    assert len(agent_records.read_jsonl(path)) == 1


def test_a_session_line_keeps_numbers_and_names_and_adds_the_runs_counts(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv(agent_records.RECORDS_ENV, raising=False)
    records = agent_records.RunRecords(tmp_path, "acme", run_id="r1", session="s1", role="x")
    records.call("identities_list", {}, "ok", started=0.0)
    records.call("http_send", {"url": "u"}, '{"status": "refused", "code": "X"}', started=0.0)
    record = {
        "at": 1.5,
        "run": "r1",
        "role": "agent",
        "wall_seconds": 30,
        "tool_calls": 999,  # the launcher does not know; the log does
        "result": "the agent's summary is not kept",
        "claude": {
            "total_cost_usd": 0.4,
            "result": "not kept either",
            "usage": {"input_tokens": 10, "output_tokens": 2, "server_tool_use": {}},
        },
    }
    line = agent_records.append_run(tmp_path, "acme", record)
    assert line["tool_calls"] == 2 and line["refused"] == 1 and line["signin_calls"] == 1
    assert "result" not in line and "result" not in line["claude"]
    assert line["claude"]["usage"] == {"input_tokens": 10, "output_tokens": 2}
    stored = agent_records.read_jsonl(tmp_path / "acme" / "agent" / "agent-runs.jsonl")
    assert stored == [line]


def test_a_mounted_records_folder_is_used_for_writing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(agent_records.RECORDS_ENV, str(tmp_path / "mounted"))
    assert agent_records.runs_file(tmp_path, "acme") == tmp_path / "mounted" / "agent-runs.jsonl"


def test_run_counts() -> None:
    lines = [
        {"run": "a", "session": "s", "status": "ok", "signin": True},
        {"run": "a", "session": "s", "status": "refused"},
        {"run": "b", "session": "s", "status": "ok"},
        {"status": "ok"},
    ]
    counts = agent_records.run_counts(lines)
    assert counts["a"]["calls"] == 2 and counts["a"]["refused"] == 1
    assert counts["a"]["signin_calls"] == 1 and counts["b"]["calls"] == 1 and len(counts) == 2
