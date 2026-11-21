"""Tests for buggy.telemetry_run."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from buggy.telemetry_run import OTHER_TOOL, RunCounters, RunTelemetryWriter, spend


def _filled(counters: RunCounters, run_id: str = "run-1") -> None:
    counters.record_call(run_id, "recon", "bash", engagement="acme")
    counters.record_call(run_id, "recon", "bash")
    counters.record_call(run_id, "exploit", "http_request")
    counters.record_loop_block(run_id)
    counters.record_cap_block(run_id)
    counters.record_cap_block(run_id)
    counters.record_refusal(run_id)
    counters.record_error(run_id)


def test_snapshot_content():
    now = [100.0]
    counters = RunCounters(clock=lambda: now[0])
    _filled(counters)
    now[0] = 130.0
    counters.record_call("run-1", "recon", "bash")
    snap = counters.snapshot("run-1")
    assert snap == {
        "run_id": "run-1",
        "engagement": "acme",
        "started_at": 100.0,
        "updated_at": 130.0,
        "tool_calls": 4,
        "tool_calls_by_tool": {"bash": 3, "http_request": 1},
        "tool_calls_by_role": {"recon": 3, "exploit": 1},
        "blocked_by_loop": 1,
        "blocked_by_cap": 2,
        "refusals": 1,
        "guard_errors": 1,
    }
    json.dumps(snap)  # serialisable


def test_snapshot_of_unknown_run_is_zero_and_runs_are_separate():
    counters = RunCounters()
    _filled(counters, "a")
    snap = counters.snapshot("b")
    assert snap["tool_calls"] == 0 and snap["tool_calls_by_tool"] == {}
    assert "b" not in counters.run_ids()


def test_distinct_tool_names_are_bounded():
    counters = RunCounters(max_tools=3)
    for i in range(10):
        counters.record_call("r", "recon", f"tool{i}")
    by_tool = counters.snapshot("r")["tool_calls_by_tool"]
    assert len(by_tool) == 4
    assert by_tool[OTHER_TOOL] == 7
    assert sum(by_tool.values()) == 10


def test_bounded_memory_600_runs_lru():
    counters = RunCounters()
    for i in range(600):
        counters.record_call(f"run-{i}", "recon", "bash", engagement="acme")
        if i >= 100:
            counters.record_call("run-0", "recon", "bash")  # keep run-0 hot
    assert len(counters) == 500
    ids = set(counters.run_ids())
    assert "run-0" in ids and "run-599" in ids
    assert "run-1" not in ids  # least recently used went first
    assert counters.snapshot("run-0")["tool_calls"] == 501


def test_counters_are_thread_safe():
    counters = RunCounters()

    def worker():
        for _ in range(1000):
            counters.record_call("r", "recon", "bash")
            counters.record_refusal("r")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    snap = counters.snapshot("r")
    assert snap["tool_calls"] == 8000 and snap["refusals"] == 8000


def test_writer_appends_valid_json_lines(tmp_path):
    counters = RunCounters()
    _filled(counters)
    writer = RunTelemetryWriter(counters, audit_root=tmp_path)
    path = tmp_path / "acme" / "run-telemetry.jsonl"

    assert writer.write("run-1", reason="periodic")
    first = path.read_bytes()
    counters.record_call("run-1", "recon", "bash")
    assert writer.write("run-1")
    data = path.read_bytes()

    assert data.startswith(first)  # append-only: earlier line untouched
    lines = data.decode().splitlines()
    assert len(lines) == 2
    rows = [json.loads(line) for line in lines]
    assert rows[0]["reason"] == "periodic" and rows[0]["tool_calls"] == 3
    assert rows[1]["reason"] == "run_end" and rows[1]["tool_calls"] == 4
    assert all(r["run_id"] == "run-1" and r["engagement"] == "acme" for r in rows)


def test_writer_refuses_unsafe_or_missing_engagement(tmp_path):
    counters = RunCounters()
    counters.record_call("evil", "recon", "bash", engagement="../escape")
    counters.record_call("anon", "recon", "bash")
    writer = RunTelemetryWriter(counters, audit_root=tmp_path / "audit")
    assert not writer.write("evil")
    assert not writer.write("anon")
    assert not any(tmp_path.rglob("*.jsonl"))


def test_writer_uses_audit_root_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(tmp_path))
    counters = RunCounters()
    counters.record_call("r", "recon", "bash", engagement="acme")
    assert RunTelemetryWriter(counters).write("r")
    assert (tmp_path / "acme" / "run-telemetry.jsonl").is_file()


def test_maybe_write_respects_interval(tmp_path):
    now = [0.0]
    counters = RunCounters()
    counters.record_call("r", "recon", "bash", engagement="acme")
    writer = RunTelemetryWriter(
        counters, audit_root=tmp_path, interval_seconds=30, clock=lambda: now[0]
    )
    assert not writer.maybe_write("r")  # starts the clock
    now[0] = 29.9
    assert not writer.maybe_write("r")
    now[0] = 30.0
    assert writer.maybe_write("r")
    now[0] = 45.0
    assert not writer.maybe_write("r")
    now[0] = 61.0
    assert writer.maybe_write("r")
    lines = (tmp_path / "acme" / "run-telemetry.jsonl").read_text().splitlines()
    assert len(lines) == 2 and all(json.loads(x)["reason"] == "periodic" for x in lines)


def test_writer_state_bounded_with_600_runs(tmp_path):
    counters = RunCounters()
    writer = RunTelemetryWriter(counters, audit_root=tmp_path)
    for i in range(600):
        counters.record_call(f"run-{i}", "recon", "bash", engagement="acme")
        writer.write(f"run-{i}")
    assert len(counters) == 500
    assert len(writer._last_write) == 500
    lines = (tmp_path / "acme" / "run-telemetry.jsonl").read_text().splitlines()
    assert len(lines) == 600
    assert [json.loads(x)["run_id"] for x in lines] == [f"run-{i}" for i in range(600)]


# ── spend ─────────────────────────────────────────────────────────


@pytest.fixture
def _no_proxy(monkeypatch):
    for name in (
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_spend_returns_none_on_connection_error(_no_proxy):
    assert spend(f"http://127.0.0.1:{_closed_port()}", "test-master", since=0.0) is None


def _serve(payload):
    seen: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen["path"] = self.path
            seen["auth"] = self.headers.get("Authorization")
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, seen


def test_spend_reports_what_litellm_returns(_no_proxy):
    rows = [
        {"spend": 0.25, "prompt_tokens": 100, "completion_tokens": 20},
        {"spend": 0.5, "prompt_tokens": 300, "completion_tokens": 80},
    ]
    server, seen = _serve(rows)
    try:
        result = spend(f"http://127.0.0.1:{server.server_port}", "test-master", since=0.0)
    finally:
        server.shutdown()
    assert result == {
        "llm_calls": 2,
        "cost_usd": 0.75,
        "prompt_tokens": 400,
        "completion_tokens": 100,
        "tokens": 500,
    }
    assert seen["path"].startswith("/spend/logs?")
    assert seen["auth"] == "Bearer test-master"


def test_spend_returns_none_on_unexpected_payload(_no_proxy):
    server, _ = _serve({"detail": "not a list"})
    try:
        assert spend(f"http://127.0.0.1:{server.server_port}", "test-master", since=0.0) is None
    finally:
        server.shutdown()
