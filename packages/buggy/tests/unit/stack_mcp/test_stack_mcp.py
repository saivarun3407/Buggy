"""Agent-side tools against the real MCP servers, over streamable HTTP.

The four servers are started in-process on loopback ports and called through
``buggy.tools.stack_mcp`` exactly as an agent's tool call would reach them.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("mcp")
import uvicorn  # noqa: E402

from buggy.agents.build import build_tools  # noqa: E402
from buggy.capture import mcp_server as capture_server  # noqa: E402
from buggy.capture import scope_server  # noqa: E402
from buggy.capture.gateway import Roots  # noqa: E402
from buggy.middleware.roe import GATED_TOOL_NAMES, NETWORK_TARGET_EXTRACTORS  # noqa: E402
from buggy.pipeline import mcp_server as recon_server  # noqa: E402
from buggy.pipeline import service  # noqa: E402
from buggy.pipeline.mcp_http import McpStartupError, build_app, configured_token  # noqa: E402
from buggy.pipeline.schema import Record, RecordType  # noqa: E402
from buggy.pipeline.store import ReconStore  # noqa: E402
from buggy.tools import stack_mcp  # noqa: E402

STACK_TOKEN = "unit-test-stack-mcp-token-0123456789"  # noqa: S105 - test fixture


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Server:
    def __init__(self, mcp, port: int) -> None:
        # The same app the containers serve: bearer auth included.
        config = uvicorn.Config(build_app(mcp), host="127.0.0.1", port=port, log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("MCP server did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


class _Target(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b'{"hello": "target"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    control, audit, data = tmp_path / "control", tmp_path / "audit", tmp_path / "data"
    monkeypatch.setenv("BUGGY_STACK_MCP_TOKEN", STACK_TOKEN)
    (control / "acme").mkdir(parents=True)
    (control / "acme" / "roe.json").write_text(
        json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["127.0.0.1"]}})
    )
    (control / "acme" / "program.json").write_text(
        json.dumps({"platform": "hackerone", "handle": "acme"})
    )
    store = ReconStore(data / "pipeline" / service.STORE_FILE)
    run = store.begin_run("acme", trigger="test")
    store.write_records(
        run,
        "acme",
        "live",
        [(Record(RecordType.HTTP_SERVICE, "127.0.0.1", "http://127.0.0.1/", "httpx"), "127.0.0.1")],
        tool_version="1.12.0",
        raw_ref="",
    )
    store.finish_run(run, status="completed", stats={})
    store.close()

    target = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    ports = {name: _free_port() for name in ("recon", "capture", "scope")}
    servers = [
        _Server(
            recon_server.build_server(
                data_root=data / "pipeline",
                queue_root=data / "queue",
                control_root=control,
                port=ports["recon"],
            ),
            ports["recon"],
        ),
        _Server(
            capture_server.build_server(
                roots=Roots(control=control, audit=audit, data=data / "capture"),
                port=ports["capture"],
            ),
            ports["capture"],
        ),
        _Server(
            scope_server.build_server(control_root=control, port=ports["scope"]), ports["scope"]
        ),
    ]
    for name, port in ports.items():
        monkeypatch.setenv(stack_mcp.SERVER_ENV[name], f"http://127.0.0.1:{port}/mcp")
    monkeypatch.delenv(stack_mcp.SERVER_ENV["browser"], raising=False)
    monkeypatch.setenv("BUGGY_ENGAGEMENT_ID", "acme")
    yield {
        "target": f"http://127.0.0.1:{target.server_address[1]}",
        "audit": audit,
        "control": control,
        "ports": ports,
    }
    for server in servers:
        server.stop()
    target.shutdown()
    target.server_close()


def _call(tool, **kwargs) -> dict:
    return json.loads(asyncio.run(tool.ainvoke(kwargs)))


def test_recon_scope_and_capture_round_trip(stack) -> None:
    summary = _call(stack_mcp.recon_summary)
    assert summary["engagement"] == "acme" and summary["records"] == {"http_service": 1}
    records = _call(stack_mcp.recon_query, record_type="http_service")["records"]
    assert records[0]["source_tool"] == "httpx" and records[0]["tool_version"] == "1.12.0"

    assert _call(stack_mcp.scope_check, target=stack["target"])["in_scope"] is True
    refused = _call(stack_mcp.scope_check, target="https://evil.example/")
    assert refused["in_scope"] is False and refused["reason"] == "NOT_IN_SCOPE"
    assert _call(stack_mcp.scope_show)["state_changing_requests"] == "required"
    assert _call(stack_mcp.program_info)["handle"] == "acme"

    sent = _call(stack_mcp.http_send, method="GET", url=f"{stack['target']}/hello")
    assert sent["status"] == 200 and json.loads(sent["response_body"]) == {"hello": "target"}
    assert (
        _call(stack_mcp.capture_verify, capture_id=sent["capture_id"], expect_host=stack["target"])[
            "valid"
        ]
        is True
    )
    assert _call(stack_mcp.http_replay, capture_id=sent["capture_id"])["reproduced"] is True
    assert (stack["audit"] / "acme" / "captures.jsonl").exists()

    blocked = _call(stack_mcp.http_send, method="GET", url="https://evil.example/")
    assert blocked["status"] == "refused" and blocked["code"] == "OUT_OF_SCOPE"
    held = _call(stack_mcp.http_send, method="DELETE", url=f"{stack['target']}/orders/1")
    assert held["code"] == "APPROVAL_REQUIRED" and held["request_id"].startswith("apr-")

    probes = {p["probe"] for p in _call(stack_mcp.probe_list)["probes"]}
    assert {
        "idor",
        "jwt_alg_none",
        "ssrf_canary",
        "numeric_boundary",
        "mass_assignment",
        "graphql_checks",
    } == probes
    result = _call(
        stack_mcp.probe_run,
        probe="graphql_checks",
        params_json=json.dumps({"url": f"{stack['target']}/graphql"}),
    )
    assert result["code"] == "APPROVAL_REQUIRED"  # the probe POSTs; this engagement needs sign-off


def test_engagement_comes_from_the_run_not_from_the_model(stack, monkeypatch) -> None:
    for tool in stack_mcp.ALL_STACK_MCP_TOOLS:
        assert "engagement" not in tool.args, f"{tool.name} lets the model choose the engagement"
    monkeypatch.setenv("BUGGY_ENGAGEMENT_ID", "someone-else")
    assert _call(stack_mcp.recon_summary)["records"] == {}
    assert (
        "error" in _call(stack_mcp.scope_show)
        or _call(stack_mcp.scope_show).get("enforced") is False
    )
    monkeypatch.setenv("BUGGY_ENGAGEMENT_ID", "")
    assert "no engagement" in _call(stack_mcp.recon_summary)["error"]


def test_unreachable_or_unconfigured_server_is_an_error_result(monkeypatch) -> None:
    monkeypatch.setenv("BUGGY_ENGAGEMENT_ID", "acme")
    monkeypatch.delenv(stack_mcp.SERVER_ENV["recon"], raising=False)
    assert "not configured" in _call(stack_mcp.recon_summary)["error"]
    monkeypatch.setenv(stack_mcp.SERVER_ENV["recon"], "http://127.0.0.1:9/mcp")
    assert "call failed" in _call(stack_mcp.recon_summary)["error"]


def test_tools_are_offered_per_role_and_only_when_configured(monkeypatch) -> None:
    for env in stack_mcp.SERVER_ENV.values():
        monkeypatch.delenv(env, raising=False)
    assert stack_mcp.stack_mcp_tools_for("api_security") == []
    assert [t.name for t in build_tools(role="recon", standard_tools={})] == []

    for env in stack_mcp.SERVER_ENV.values():
        monkeypatch.setenv(env, "http://mcp.test/mcp")
    tester = {t.name for t in stack_mcp.stack_mcp_tools_for("api_security")}
    reader = {t.name for t in stack_mcp.stack_mcp_tools_for("recon")}
    assert {"recon_query", "scope_check", "http_send", "probe_run", "browser_open"} <= tester
    assert {"recon_query", "scope_check"} <= reader
    assert not reader & {"http_send", "probe_run", "browser_open"}  # readers cannot touch a target
    assert stack_mcp.stack_mcp_tools_for("phisher") == []
    assert "recon_summary" in {t.name for t in build_tools(role="recon", standard_tools={})}
    # No stack tool can run a scanner.
    names = {t.name for t in stack_mcp.ALL_STACK_MCP_TOOLS}
    assert not any(n.startswith(("nuclei", "scan", "run_")) for n in names)


def test_target_reaching_tools_are_roe_gated() -> None:
    assert {"http_send", "browser_open", "probe_run"} <= GATED_TOOL_NAMES
    assert NETWORK_TARGET_EXTRACTORS["http_send"]({"url": "https://a.test/x"}) == ["a.test"]
    params = json.dumps({"url": "https://a.test/o/1", "readback_url": "https://b.test/o/1"})
    assert NETWORK_TARGET_EXTRACTORS["probe_run"]({"params_json": params}) == ["a.test", "b.test"]
    assert NETWORK_TARGET_EXTRACTORS["probe_run"]({"params_json": "not json"}) == []


def test_servers_reject_callers_without_the_stack_token(stack, monkeypatch) -> None:
    import urllib.error
    import urllib.request

    for name, port in stack["ports"].items():
        for headers in ({}, {"Authorization": "Bearer wrong-token-wrong-token"}):
            request = urllib.request.Request(  # noqa: S310 - loopback test server
                f"http://127.0.0.1:{port}/mcp",
                data=b"{}",
                method="POST",
                headers={"Content-Type": "application/json", **headers},
            )
            with pytest.raises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(request, timeout=5)  # noqa: S310
            assert refused.value.code == 401, name

    # An agent runtime that lost the token gets an error, not data.
    monkeypatch.setenv("BUGGY_STACK_MCP_TOKEN", "")
    assert "error" in _call(stack_mcp.recon_summary)
    assert "error" in _call(stack_mcp.http_send, method="GET", url=f"{stack['target']}/hello")


def test_a_server_will_not_start_without_a_token(monkeypatch) -> None:
    monkeypatch.delenv("BUGGY_STACK_MCP_TOKEN", raising=False)
    monkeypatch.delenv("BUGGY_STACK_MCP_ALLOW_UNAUTHENTICATED", raising=False)
    with pytest.raises(McpStartupError, match="BUGGY_STACK_MCP_TOKEN must be set"):
        configured_token()
    monkeypatch.setenv("BUGGY_STACK_MCP_TOKEN", "short")
    with pytest.raises(McpStartupError, match="at least 16"):
        configured_token()
    monkeypatch.setenv("BUGGY_STACK_MCP_TOKEN", "")
    monkeypatch.setenv("BUGGY_STACK_MCP_ALLOW_UNAUTHENTICATED", "1")
    assert configured_token() is None
