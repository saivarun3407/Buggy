"""Production-posture tests for the RoE guardrail.

These cover the behaviour the rest of the unit suite opts out of (see
``tests/conftest.py``): the enforced scope lives outside the agent-writable
tree, a missing scope refuses, the audit ledger is written without being
handed a path, and a boundary that cannot be provisioned stops the run.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import ToolMessage

from buggy.middleware import _control
from buggy.middleware._audit_sink import iter_records, verify_ledger
from buggy.middleware.egress import EgressProvisioningError
from buggy.middleware.roe import (
    InvalidRoEError,
    RoEGuardrailMiddleware,
    _load_rules_for_workspace,
    _roe_required,
    default_audit_path,
    resolve_roe_path,
)
from buggy_core.types.roe import EnforcementMode


@pytest.fixture
def plane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """A workspace / control / audit layout with RoE required, as in compose."""
    roots = {name: tmp_path / name for name in ("workspace", "control", "audit")}
    for root in roots.values():
        root.mkdir()
    (roots["workspace"] / "acme" / "plan").mkdir(parents=True)
    monkeypatch.setenv("BUGGY_WORKSPACE_ROOT", str(roots["workspace"]))
    monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(roots["control"]))
    monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(roots["audit"]))
    monkeypatch.setenv("BUGGY_ROE_REQUIRE", "1")
    monkeypatch.delenv("BENCHMARK_MODE", raising=False)
    monkeypatch.delenv("BUGGY_ROE_AUDIT_PATH", raising=False)
    return roots


def _state(plane: dict[str, Path]) -> dict[str, str]:
    return {"workspace_path": str(plane["workspace"] / "acme"), "engagement_name": "acme"}


def _write(path: Path, block: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"machine_enforcement": block}), encoding="utf-8")


def _request(command: str, state: dict, tool: str = "bash") -> MagicMock:
    request = MagicMock()
    request.tool = MagicMock()
    request.tool.name = tool
    request.state = state
    request.tool_call = MagicMock()
    request.tool_call.args = {"command": command}
    request.tool_call.id = "tc-1"
    request.tool_call_args = {"command": command}
    request.tool_call_id = "tc-1"
    return request


def _ok_handler() -> MagicMock:
    return MagicMock(return_value=ToolMessage(content="ran", tool_call_id="tc-1"))


class TestRequiredByDefault:
    def test_unset_means_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BUGGY_ROE_REQUIRE", raising=False)
        monkeypatch.delenv("BENCHMARK_MODE", raising=False)
        assert _roe_required() is True

    def test_explicit_zero_opts_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BUGGY_ROE_REQUIRE", "0")
        assert _roe_required() is False

    def test_benchmark_mode_opts_out_only_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BUGGY_ROE_REQUIRE", raising=False)
        monkeypatch.setenv("BENCHMARK_MODE", "1")
        assert _roe_required() is False
        monkeypatch.setenv("BUGGY_ROE_REQUIRE", "1")
        assert _roe_required() is True

    def test_unrecognised_value_stays_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BUGGY_ROE_REQUIRE", "nope")
        assert _roe_required() is True


class TestControlPaths:
    def test_workspace_maps_to_same_relative_control_and_audit_dirs(self, plane) -> None:
        workspace = str(plane["workspace"] / "acme")
        assert _control.control_dir(workspace) == plane["control"] / "acme"
        assert _control.audit_dir(workspace) == plane["audit"] / "acme"

    def test_engagement_bound_at_root_uses_the_roots(self, plane) -> None:
        workspace = str(plane["workspace"])
        assert _control.control_dir(workspace) == plane["control"]
        assert _control.audit_dir(workspace) == plane["audit"]

    def test_slug_fallback_when_control_holds_the_whole_tree(self, plane) -> None:
        # Launcher bound one engagement at the workspace root, but the control
        # root still holds every engagement by slug.
        _write(plane["control"] / "acme" / "roe.json", {"mode": "enforce"})
        found = _control.control_dir(str(plane["workspace"]), "acme")
        assert found == plane["control"] / "acme"

    def test_traversal_and_foreign_paths_do_not_resolve(self, plane) -> None:
        assert _control.control_dir("/etc") is None
        assert _control.control_dir(str(plane["workspace"] / ".." / "control")) is None
        assert _control.control_dir(str(plane["workspace"]), "../control") == plane["control"]


class TestEnforcedScopeLivesOutsideTheWorkspace:
    def test_workspace_draft_is_ignored_when_required(self, plane) -> None:
        # The agent can write this file. It must not become the policy.
        _write(plane["workspace"] / "acme" / "plan" / "roe.json", {"mode": "audit"})
        with pytest.raises(InvalidRoEError, match="does not exist"):
            _load_rules_for_workspace(str(plane["workspace"] / "acme"), "acme")

    def test_control_copy_is_the_policy(self, plane) -> None:
        _write(plane["workspace"] / "acme" / "plan" / "roe.json", {"mode": "audit"})
        _write(
            plane["control"] / "acme" / "roe.json",
            {"mode": "enforce", "in_scope": ["10.0.0.0/24"]},
        )
        rules = _load_rules_for_workspace(str(plane["workspace"] / "acme"), "acme")
        assert rules.mode == EnforcementMode.ENFORCE
        path, origin = resolve_roe_path(str(plane["workspace"] / "acme"), "acme")
        assert origin == "control"
        assert path == plane["control"] / "acme" / "roe.json"

    def test_missing_scope_refuses_gated_tools(self, plane) -> None:
        mw = RoEGuardrailMiddleware()
        handler = _ok_handler()
        result = mw.wrap_tool_call(_request("curl http://example.com", _state(plane)), handler)
        assert not handler.called
        assert "INVALID_ROE" in result.content
        assert "scope approve" in result.content

    def test_agent_edit_to_draft_does_not_widen_scope(self, plane, monkeypatch) -> None:
        monkeypatch.setenv("BUGGY_EGRESS_DISABLE", "1")
        _write(
            plane["control"] / "acme" / "roe.json",
            {"mode": "enforce", "in_scope": ["10.0.0.0/24"]},
        )
        # The agent "approves" 8.8.8.8 for itself in the workspace.
        _write(
            plane["workspace"] / "acme" / "plan" / "roe.json",
            {"mode": "enforce", "in_scope": ["8.8.8.8", "10.0.0.0/24"]},
        )
        mw = RoEGuardrailMiddleware()
        handler = _ok_handler()
        result = mw.wrap_tool_call(_request("nmap 8.8.8.8", _state(plane)), handler)
        assert not handler.called
        assert "NOT_IN_SCOPE" in result.content

    def test_no_workspace_refuses_when_required(self, plane) -> None:
        with pytest.raises(InvalidRoEError, match="no engagement workspace"):
            _load_rules_for_workspace(None)

    def test_draft_still_used_when_not_required(self, plane, monkeypatch) -> None:
        monkeypatch.setenv("BUGGY_ROE_REQUIRE", "0")
        _write(plane["workspace"] / "acme" / "plan" / "roe.json", {"mode": "warn"})
        rules = _load_rules_for_workspace(str(plane["workspace"] / "acme"), "acme")
        assert rules.mode == EnforcementMode.WARN


class TestAuditLedgerActuallyWrites:
    def test_default_sink_writes_under_audit_root(self, plane, monkeypatch) -> None:
        monkeypatch.setenv("BUGGY_EGRESS_DISABLE", "1")
        monkeypatch.setenv("BUGGY_AUDIT_HMAC_KEY", "k" * 32)
        _write(
            plane["control"] / "acme" / "roe.json",
            {"mode": "enforce", "in_scope": ["10.0.0.0/24"]},
        )
        # Built exactly as the slot factory builds it: no sink, no path.
        mw = RoEGuardrailMiddleware()
        mw.wrap_tool_call(_request("nmap 10.0.0.5", _state(plane)), _ok_handler())
        mw.wrap_tool_call(_request("nmap 8.8.8.8", _state(plane)), _ok_handler())

        ledger = plane["audit"] / "acme" / "roe-decisions.jsonl"
        assert default_audit_path(str(plane["workspace"] / "acme"), "acme") == ledger
        records = list(iter_records(ledger))
        assert [r["decision"] for r in records] == ["allow", "refuse"]
        assert records[1]["reason_code"] == "NOT_IN_SCOPE"
        assert verify_ledger(ledger, hmac_key=b"k" * 32).ok
        # Nothing was written into the agent-writable tree.
        assert not (plane["workspace"] / "acme" / "audit").exists()

    def test_unwritable_ledger_refuses_gated_call(self, plane, monkeypatch) -> None:
        monkeypatch.setenv("BUGGY_EGRESS_DISABLE", "1")
        _write(
            plane["control"] / "acme" / "roe.json",
            {"mode": "enforce", "in_scope": ["10.0.0.0/24"]},
        )
        # A regular file where the engagement's audit directory should be.
        (plane["audit"] / "acme").write_text("not a directory", encoding="utf-8")
        mw = RoEGuardrailMiddleware()
        handler = _ok_handler()
        result = mw.wrap_tool_call(_request("nmap 10.0.0.5", _state(plane)), handler)
        assert not handler.called
        assert "AUDIT_UNAVAILABLE" in result.content

    def test_ungated_tool_is_not_blocked_by_audit_failure(self, plane, monkeypatch) -> None:
        monkeypatch.setenv("BUGGY_EGRESS_DISABLE", "1")
        _write(
            plane["control"] / "acme" / "roe.json", {"mode": "enforce", "in_scope": ["10.0.0.1"]}
        )
        (plane["audit"] / "acme").write_text("not a directory", encoding="utf-8")
        mw = RoEGuardrailMiddleware()
        handler = _ok_handler()
        mw.wrap_tool_call(_request("", _state(plane), tool="write_todos"), handler)
        assert handler.called


class _GuardStub:
    """A real HTTP server standing in for the egress guard's control API."""

    def __init__(self, token: str, reply: dict | None = None, status: int = 200) -> None:
        self.token = token
        self.reply = reply if reply is not None else {"applied": True, "detail": "loaded"}
        self.status = status
        self.received: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.headers.get("Authorization") != f"Bearer {stub.token}":
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"detail":"bad token"}')
                    return
                stub.received.append(json.loads(body))
                payload = json.dumps(stub.reply).encode()
                self.send_response(stub.status)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def guard(plane, monkeypatch):
    stub = _GuardStub(token="g" * 32)
    monkeypatch.delenv("BUGGY_EGRESS_DISABLE", raising=False)
    monkeypatch.setenv("BUGGY_EGRESS_GUARD_URL", stub.url)
    monkeypatch.setenv("EGRESS_GUARD_TOKEN", stub.token)
    yield stub
    stub.close()


class TestEgressProvisioningIsFailClosed:
    def test_policy_is_pushed_to_guard_once_per_digest(self, plane, guard) -> None:
        roe = plane["control"] / "acme" / "roe.json"
        _write(roe, {"mode": "enforce", "in_scope": ["app.acme.test"]})
        mw = RoEGuardrailMiddleware()
        mw.before_agent(_state(plane), runtime=None)
        mw.before_agent(_state(plane), runtime=None)
        assert len(guard.received) == 1
        pushed = guard.received[0]
        assert pushed["engagement"] == "acme"
        assert pushed["policy"]["enforce"] is True
        assert "app.acme.test" in pushed["policy"]["allowed_hosts"]

        # Operator widens the scope: the boundary follows on the next call.
        _write(roe, {"mode": "enforce", "in_scope": ["app.acme.test", "api.acme.test"]})
        mw.wrap_tool_call(_request("curl http://api.acme.test/", _state(plane)), _ok_handler())
        assert len(guard.received) == 2
        assert "api.acme.test" in guard.received[1]["policy"]["allowed_hosts"]

    def test_non_enforcing_policy_is_still_pushed_so_the_guard_unlocks(self, plane, guard) -> None:
        _write(plane["control"] / "acme" / "roe.json", {"mode": "audit"})
        RoEGuardrailMiddleware().before_agent(_state(plane), runtime=None)
        assert guard.received[0]["policy"]["enforce"] is False

    def test_wrong_token_aborts_the_run(self, plane, guard, monkeypatch) -> None:
        monkeypatch.setenv("EGRESS_GUARD_TOKEN", "x" * 32)
        _write(plane["control"] / "acme" / "roe.json", {"mode": "enforce", "in_scope": ["a.test"]})
        with pytest.raises(EgressProvisioningError, match="HTTP 401"):
            RoEGuardrailMiddleware().before_agent(_state(plane), runtime=None)

    def test_unreachable_guard_aborts_the_run(self, plane, guard) -> None:
        guard.close()
        _write(plane["control"] / "acme" / "roe.json", {"mode": "enforce", "in_scope": ["a.test"]})
        with pytest.raises(EgressProvisioningError, match="unreachable"):
            RoEGuardrailMiddleware().before_agent(_state(plane), runtime=None)

    def test_guard_reporting_not_applied_aborts_the_run(self, plane, guard) -> None:
        guard.reply = {"applied": False, "detail": "nft load failed"}
        _write(plane["control"] / "acme" / "roe.json", {"mode": "enforce", "in_scope": ["a.test"]})
        with pytest.raises(EgressProvisioningError, match="nft load failed"):
            RoEGuardrailMiddleware().before_agent(_state(plane), runtime=None)

    def test_guard_url_without_token_is_a_misconfiguration(self, plane, guard, monkeypatch) -> None:
        monkeypatch.delenv("EGRESS_GUARD_TOKEN")
        _write(plane["control"] / "acme" / "roe.json", {"mode": "enforce", "in_scope": ["a.test"]})
        with pytest.raises(EgressProvisioningError, match="EGRESS_GUARD_TOKEN"):
            RoEGuardrailMiddleware().before_agent(_state(plane), runtime=None)

    def test_gated_call_is_refused_and_audited_when_boundary_is_down(self, plane, guard) -> None:
        guard.close()
        _write(plane["control"] / "acme" / "roe.json", {"mode": "enforce", "in_scope": ["a.test"]})
        mw = RoEGuardrailMiddleware()
        handler = _ok_handler()
        result = mw.wrap_tool_call(_request("curl http://a.test/", _state(plane)), handler)
        assert not handler.called
        assert "EGRESS_NOT_PROVISIONED" in result.content
        events = [
            r.get("event") for r in iter_records(plane["audit"] / "acme" / "roe-decisions.jsonl")
        ]
        assert "egress_provisioning_failed" in events

    def test_successful_provisioning_is_audited(self, plane, guard) -> None:
        _write(plane["control"] / "acme" / "roe.json", {"mode": "enforce", "in_scope": ["a.test"]})
        RoEGuardrailMiddleware().before_agent(_state(plane), runtime=None)
        records = list(iter_records(plane["audit"] / "acme" / "roe-decisions.jsonl"))
        assert records[0]["event"] == "egress_provisioned"
        assert records[0]["boundary"] == "egress-guard"
        assert len(records[0]["policy_sha256"]) == 64

    def test_legacy_sandbox_boundary_not_applied_aborts(self, plane, monkeypatch) -> None:
        monkeypatch.delenv("BUGGY_EGRESS_DISABLE", raising=False)
        sandbox = MagicMock()
        sandbox.provision_egress.return_value = {
            "applied": False,
            "detail": "egress enforcement disabled",
        }
        monkeypatch.setattr("buggy.backends.factory.build_sandbox_backend", lambda: sandbox)
        _write(plane["control"] / "acme" / "roe.json", {"mode": "enforce", "in_scope": ["a.test"]})
        with pytest.raises(EgressProvisioningError, match="not applied"):
            RoEGuardrailMiddleware().before_agent(_state(plane), runtime=None)
