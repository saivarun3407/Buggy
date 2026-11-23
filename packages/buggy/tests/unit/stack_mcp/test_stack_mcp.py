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
    def log_message(self, format: str, *args: object) -> None:
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
                roots=Roots(
                    control=control,
                    audit=audit,
                    data=data / "capture",
                    secrets=tmp_path / "secrets",
                ),
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
        "secrets": tmp_path / "secrets",
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
    } <= probes  # later probes are added to the registry; these must stay listed
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
    monkeypatch.delenv("BUGGY_AGENT_WEB", raising=False)
    # Without servers only research_fetch (public pages, never the target) is offered.
    assert [t.name for t in stack_mcp.stack_mcp_tools_for("api_security")] == ["research_fetch"]
    assert [t.name for t in build_tools(role="recon", standard_tools={})] == ["research_fetch"]
    monkeypatch.setenv("BUGGY_AGENT_WEB", "off")
    assert stack_mcp.stack_mcp_tools_for("api_security") == []
    assert [t.name for t in build_tools(role="recon", standard_tools={})] == []
    monkeypatch.delenv("BUGGY_AGENT_WEB")

    for env in stack_mcp.SERVER_ENV.values():
        monkeypatch.setenv(env, "http://mcp.test/mcp")
    tester = {t.name for t in stack_mcp.stack_mcp_tools_for("api_security")}
    reader = {t.name for t in stack_mcp.stack_mcp_tools_for("recon")}
    assert {"recon_query", "scope_check", "http_send", "probe_run", "browser_open"} <= tester
    assert {"recon_query", "scope_check"} <= reader
    assert not reader & {"http_send", "probe_run", "browser_open"}  # readers cannot touch a target
    assert "research_fetch" in tester and "research_fetch" in reader
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


# ── findings, queue, report, evidence, identities, lessons, board ────────────────────


def _lab_scope(stack, **extra) -> None:
    """Let the test target be reached: it is on loopback, which is a private address."""
    doc = {
        "machine_enforcement": {"mode": "enforce", "in_scope": ["127.0.0.1"]},
        "network": {"allow_private_targets": True},
        "approvals": {"state_changing": "not_required"},
        **extra,
    }
    (stack["control"] / "acme" / "roe.json").write_text(json.dumps(doc))


def test_every_capture_server_tool_has_an_agent_wrapper_and_no_actor_argument() -> None:
    wrapped = {t.name: t for t in stack_mcp.ALL_STACK_MCP_TOOLS}
    # candidates_add is used by the recon stage, owners_infer and accounts_provision by
    # the hunt command (operator side), not by agents. accounts_provision creates accounts
    # on the target, which an agent must never do. user_walk is the hunt command's walk as
    # each test account; an agent crawls with surface_crawl.
    for name in set(capture_server.TOOL_NAMES) - {
        "candidates_add",
        "owners_infer",
        "accounts_provision",
        "user_walk",
    }:
        assert name in wrapped, f"{name} has no agent wrapper"
    for name, tool in wrapped.items():
        assert not {"engagement", "actor"} & set(tool.args), (
            f"{name} lets the model choose who or where it is"
        )
    assert "recon_coverage" in wrapped


def test_a_claim_becomes_a_finding_only_through_the_verifier(stack) -> None:
    _lab_scope(stack)
    url = stack["target"] + "/"
    sent = _call(stack_mcp.http_send, method="GET", url=url)
    assert sent["status"] == 200 and sent["capture_id"]
    claim = {
        "title": "Greeting is readable without a session",
        "class": "access_control",
        "severity": "low",
        "endpoint": url,
        "method": "GET",
        "parameter": "",
        "description": "The endpoint answers anyone.",
        "remediation": "Require an authenticated session before returning the greeting.",
        "invariant": "only a signed-in user can read the greeting",
        "entry_point": f"GET {url}",
        "source": "agent:test",
        "status": "exploit_verified",  # a submitter cannot grant itself this
        "assertions": [
            {
                "capture_id": sent["capture_id"],
                "expect": {"status": 200, "body_contains": ["target"]},
            }
        ],
    }
    submitted = _call(stack_mcp.finding_submit, finding_json=json.dumps(claim))
    assert submitted["ok"] and submitted["finding"]["status"] == "candidate"
    finding_id = submitted["finding"]["id"]

    queue = _call(stack_mcp.candidates_next, limit=5)
    assert [row["id"] for row in queue["candidates"]] == [finding_id]
    assert queue["candidates"][0]["claimed_by"]  # claimed for the caller, named by the run

    verified = _call(stack_mcp.finding_verify, finding_id=finding_id)
    assert verified["finding"]["status"] == "exploit_verified"
    assert verified["verification"]["replay_capture_ids"]

    listed = _call(stack_mcp.findings_list, status="exploit_verified")
    assert [row["id"] for row in listed["findings"]] == [finding_id]
    assert _call(stack_mcp.finding_get, finding_id=finding_id)["events"]

    graded = _call(stack_mcp.finding_grade, finding_id=finding_id)
    assert graded["ok"] and graded["grade"]["decision"] in {"submit", "hold", "discard"}
    assert graded["grade"]["reasons"]

    # A claim whose evidence is on another endpoint is not verified.
    other = {**claim, "title": "Admin panel open", "endpoint": stack["target"] + "/admin"}
    other_id = _call(stack_mcp.finding_submit, finding_json=json.dumps(other))["finding"]["id"]
    refused = _call(stack_mcp.finding_verify, finding_id=other_id)
    assert refused["finding"]["status"] == "inconclusive"

    for fmt, marker in (("markdown", "#"), ("html", "<!doctype html"), ("json", "{")):
        built = _call(stack_mcp.report_build, fmt=fmt)
        assert built["ok"] and built["report"].lstrip().lower().startswith(marker)
    report = json.loads(_call(stack_mcp.report_build, fmt="json")["report"])
    assert [row["id"] for row in report["findings"]] == [finding_id]  # only the proven one

    # The inconclusive claim is in the ruled-out ledger, with the verifier's reason.
    ruled = _call(stack_mcp.leads_ruled_out, query="admin")
    assert [(r["finding_id"], r["reason"]) for r in ruled["ruled_out"]] == [
        (other_id, "inconclusive")
    ]
    chained = _call(stack_mcp.findings_chains)
    assert [node["id"] for node in chained["nodes"]] == [finding_id]
    assert _call(stack_mcp.findings_due)["count"] == 0

    bundle = _call(stack_mcp.evidence_export, finding_id=finding_id)
    assert bundle["ok"] and "curl" in bundle["files"]["reproduce.sh"]
    assert "ledger-excerpt.jsonl" not in bundle["files"]  # audit data stays with the operator
    # A finding's logs sit in the finding's own folder, next to its proof video.
    written = stack["audit"] / "acme" / "evidence" / finding_id / "logs"
    assert bundle["written_to"] == f"audit/acme/evidence/{finding_id}/logs/"
    assert (written / "evidence.har").is_file() and (written / "ledger-excerpt.jsonl").is_file()


def test_identities_are_listed_without_secrets_and_attached_by_name(stack) -> None:
    _lab_scope(stack)
    secret = "tok-" + "9f2c7a1b4d6e"  # built at runtime: not a real credential
    folder = stack["secrets"] / "acme"
    folder.mkdir(parents=True)
    (folder / "identities.json").write_text(
        json.dumps(
            {
                "identities": [
                    {
                        "name": "alice",
                        "role": "user",
                        "owner_of": [stack["target"] + "/"],
                        "static": {"headers": {"Authorization": f"Bearer {secret}"}},
                    }
                ]
            }
        )
    )
    listed = _call(stack_mcp.identities_list)
    assert [row["name"] for row in listed["identities"]] == ["alice"]
    assert secret not in json.dumps(listed)

    sent = _call(stack_mcp.http_send, method="GET", url=stack["target"] + "/", identity="alice")
    assert sent["status"] == 200 and sent["identity"] == "alice"
    assert secret not in json.dumps(sent)
    unknown = _call(
        stack_mcp.http_send, method="GET", url=stack["target"] + "/", identity="mallory"
    )
    assert unknown["code"] == "UNKNOWN_IDENTITY"

    matrix = _call(
        stack_mcp.authz_matrix_run, urls_json=json.dumps([stack["target"] + "/"]), max_requests=20
    )
    assert "matrix" in matrix and secret not in json.dumps(matrix)

    # An inferred owner reaches the server: alice declares no markers, so nothing is claimed.
    page = stack["target"] + "/"
    inferred = _call(
        stack_mcp.authz_matrix_run,
        urls_json=json.dumps([page]),
        owners_json=json.dumps({page: "alice"}),
        inferred_json=json.dumps([page]),
        max_requests=20,
    )
    assert inferred["verdicts"][page]["verdict"] == "inconclusive"
    assert "markers" in inferred["verdicts"][page]["reason"] and inferred["candidates"] == []


def test_lessons_are_scrubbed_and_trusted_only_with_a_verified_finding(stack) -> None:
    _lab_scope(stack)
    lesson = {
        "kind": "guide",
        "title": "GraphQL batching hides rate limits",
        "body": "Send aliases in one query against 127.0.0.1 to bypass per-request limits.",
        "classes": ["graphql"],
        "technologies": ["graphql"],
        "trust": "verified",  # a lesson cannot vouch for itself
        "finding_id": "F-000000000000",
    }
    saved = _call(stack_mcp.memory_save, lesson_json=json.dumps(lesson))
    assert saved["ok"] and saved["trusted"] is False
    assert "127.0.0.1" not in json.dumps(saved["lesson"])  # the target is scrubbed
    assert _call(stack_mcp.memory_search, technologies_json='["graphql"]')["lessons"] == []
    bad = _call(stack_mcp.memory_save, lesson_json="not json")
    assert bad["code"] == "BAD_ARGUMENT"


def test_the_board_coordinates_work_and_refuses_a_second_claim(stack, monkeypatch) -> None:
    fact = _call(stack_mcp.fact_add, text="Orders API uses numeric ids")["fact"]
    opened = _call(
        stack_mcp.intent_open,
        text="Check order ownership",
        from_facts_json=json.dumps([fact["id"]]),
    )["intent"]
    assert _call(stack_mcp.intent_claim, intent_id=opened["id"])["ok"]

    # Another worker (a different agent name in the run) cannot take a live claim.
    monkeypatch.setattr(stack_mcp, "current_actor", lambda: "other-agent:thread")
    taken = _call(stack_mcp.intent_claim, intent_id=opened["id"])
    assert taken.get("error") == "conflict"
    monkeypatch.undo()
    monkeypatch.setenv("BUGGY_STACK_MCP_TOKEN", STACK_TOKEN)
    for name, port in stack["ports"].items():
        monkeypatch.setenv(stack_mcp.SERVER_ENV[name], f"http://127.0.0.1:{port}/mcp")
    monkeypatch.setenv("BUGGY_ENGAGEMENT_ID", "acme")

    done = _call(
        stack_mcp.intent_conclude, intent_id=opened["id"], fact_text="Ownership is enforced (403)"
    )
    assert done["ok"]
    assert _call(stack_mcp.hint_add, text="Try the export endpoint next")["ok"]
    board = _call(stack_mcp.facts_list)
    assert len(board["facts"]) == 2 and board["open_work"] == []
    assert [h["text"] for h in _call(stack_mcp.hints_list)["hints"]] == [
        "Try the export endpoint next"
    ]


def test_recon_coverage_is_served(stack) -> None:
    coverage = _call(stack_mcp.recon_coverage)
    assert coverage["engagement"] == "acme" and "counts" in coverage


def test_the_matrix_tool_is_gated_on_every_url_it_would_request() -> None:
    assert "authz_matrix_run" in GATED_TOOL_NAMES
    urls = json.dumps(["https://a.test/o/1", "HEAD https://b.test/o/2", {"url": "https://c.test/"}])
    assert NETWORK_TARGET_EXTRACTORS["authz_matrix_run"]({"urls_json": urls}) == [
        "a.test",
        "b.test",
        "c.test",
    ]
    assert NETWORK_TARGET_EXTRACTORS["authz_matrix_run"]({"urls_json": "not json"}) == []
    # inferred_json only marks some of urls_json; it adds nothing to request.
    with_inferred = {"urls_json": urls, "inferred_json": json.dumps(["https://d.test/o/3"])}
    assert NETWORK_TARGET_EXTRACTORS["authz_matrix_run"](with_inferred) == [
        "a.test",
        "b.test",
        "c.test",
    ]


def test_a_probe_and_a_surface_crawl_run_as_a_declared_identity(stack) -> None:
    _lab_scope(stack)
    secret = "tok-" + "4b8e1d0c7a3f"  # built at runtime: not a real credential
    folder = stack["secrets"] / "acme"
    folder.mkdir(parents=True)
    alice = {"name": "alice", "static": {"headers": {"Authorization": f"Bearer {secret}"}}}
    (folder / "identities.json").write_text(json.dumps({"identities": [alice]}))
    assert "identity" in _call(stack_mcp.probe_list)["identity"]

    probe = _call(
        stack_mcp.probe_run,
        probe="cors",
        params_json=json.dumps({"url": stack["target"] + "/", "identity": "alice"}),
    )
    assert probe["status"] == "completed" and probe["identity"] == "alice", probe
    assert secret not in json.dumps(probe)
    refused = _call(
        stack_mcp.probe_run,
        probe="cors",
        params_json=json.dumps({"url": stack["target"] + "/", "identity": "mallory"}),
    )
    assert refused["code"] == "UNKNOWN_IDENTITY"

    crawled = _call(
        stack_mcp.surface_crawl,
        seeds_json=json.dumps([stack["target"] + "/", stack["target"] + "/logout"]),
        identity="alice",
        max_requests=5,
    )
    assert crawled["ok"] and crawled["identity"] == "alice", crawled
    assert crawled["requested"] == 1 and crawled["pages"][0]["status"] == 200
    assert crawled["skipped"][0]["url"] == stack["target"] + "/logout"
    capture = _call(stack_mcp.http_capture, capture_id=crawled["pages"][0]["capture_id"])
    assert capture["identity"] == "alice" and capture["method"] == "GET"
    assert secret not in json.dumps(crawled) + json.dumps(capture)


def test_the_surface_crawl_is_gated_on_the_hosts_of_its_seeds() -> None:
    assert "surface_crawl" in GATED_TOOL_NAMES
    seeds = json.dumps(["https://a.test/", "https://b.test/x?y=1", 7])
    extract = NETWORK_TARGET_EXTRACTORS["surface_crawl"]
    assert extract({"seeds_json": seeds}) == ["a.test", "b.test"]
    assert extract({"seeds_json": "not json"}) == []
    assert extract({"seeds_json": '{"url": "x"}'}) == []
    assert "surface_crawl" in {t.name for t in stack_mcp.ALL_STACK_MCP_TOOLS}


def _greeting_recipe(target: str) -> dict:
    """A read-only recipe against the loopback target, which answers every GET the same."""
    return {
        "name": "greeting-open",
        "class": "info_exposure",
        "title": "The greeting is served without a session",
        "endpoint": f"{target}/greeting",
        "remediation": "Require a session before serving the greeting, or make it public on purpose.",
        "steps": [
            {"id": "plain", "method": "GET", "url": f"{target}/greeting", "identity": "",
             "extract": {"who": {"from": "json", "path": "hello"}}},
            {"id": "again", "method": "GET", "url": f"{target}/greeting?x={{{{who|urlencode}}}}"},
        ],
        "verdict": {
            "vulnerable_if": [{"step": "again", "json": "hello", "equals": "target"}],
            "control": [{"step": "plain", "status": 200}, {"step": "again", "same_as": "plain"}],
        },
    }  # fmt: skip


def test_recipes_round_trip_through_the_agent_wrappers(stack) -> None:
    _lab_scope(stack)
    recipe = _greeting_recipe(stack["target"])
    checked = _call(stack_mcp.recipe_check, recipe_json=json.dumps(recipe))
    assert checked == {"ok": True, "state_changing": False, "steps": 2}
    no_control = {**recipe, "verdict": {**recipe["verdict"], "control": []}}
    refused = _call(stack_mcp.recipe_check, recipe_json=json.dumps(no_control))
    assert refused["ok"] is False and refused["errors"][0]["path"] == "verdict.control"

    saved = _call(stack_mcp.recipe_save, recipe_json=json.dumps(recipe))
    assert saved["ok"] and saved["name"] == "greeting-open"
    assert _call(stack_mcp.recipe_list)["recipes"][0]["name"] == "greeting-open"
    assert _call(stack_mcp.recipe_get, name="greeting-open")["recipe"]["steps"][0]["id"] == "plain"

    ran = _call(stack_mcp.recipe_run, recipe_json=json.dumps({"use": "greeting-open"}))
    assert ran["status"] == "completed" and ran["vulnerable"] is True, ran
    assert ran["variables"] == ["who"] and len(ran["evidence_capture_ids"]) == 2
    verified = _call(stack_mcp.finding_verify, finding_id=ran["finding_id"])
    assert verified["finding"]["status"] == "exploit_verified", verified
    assert verified["finding"]["source"] == "recipe:greeting-open"

    outside = {**recipe, "name": "outside", "endpoint": "https://evil.example/greeting"}
    outside["steps"] = [{**recipe["steps"][0], "url": "https://evil.example/greeting"}]
    outside["verdict"] = {
        "vulnerable_if": [{"step": "plain", "status": 200}],
        "control": [{"step": "plain", "status": 200}],
    }
    blocked = _call(stack_mcp.recipe_run, recipe_json=json.dumps(outside))
    assert blocked["status"] == "refused" and blocked["code"] == "OUT_OF_SCOPE", blocked


def test_recipe_tools_are_gated_on_every_step_host() -> None:
    assert {"recipe_check", "recipe_run", "recipe_save"} <= GATED_TOOL_NAMES
    recipe = {
        "endpoint": "https://a.test/o/1",
        "steps": [{"url": "https://a.test/o/{{id}}"}, {"url": "https://b.test/x"}, "junk"],
    }
    for name in ("recipe_check", "recipe_run", "recipe_save"):
        extract = NETWORK_TARGET_EXTRACTORS[name]
        assert extract({"recipe_json": json.dumps(recipe)}) == ["a.test", "a.test", "b.test"]
        assert extract({"recipe_json": "not json"}) == []
        assert extract({"recipe_json": json.dumps({"use": "saved"})}) == []
    names = {t.name for t in stack_mcp.ALL_STACK_MCP_TOOLS}
    assert {"recipe_check", "recipe_run", "recipe_save", "recipe_list", "recipe_get"} <= names
