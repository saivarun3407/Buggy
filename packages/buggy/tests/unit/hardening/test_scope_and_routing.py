"""Wildcard depth, the blocked-sandbox policy, and routing of in-process tools."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import ToolMessage

from buggy.egress_guard.policy import Policy, glob_match
from buggy.middleware.egress import compile_egress_policy, osint_egress_hosts
from buggy.middleware.roe import RoEGuardrailMiddleware, parse_roe_document
from buggy.pipeline.scope import PipelineLimits, ScopeFilter
from buggy.tools import stack_mcp
from buggy_core.types.roe import MachineEnforcement, _glob_match, evaluate_target

CASES = [
    ("*.acme.test", "a.acme.test", True),
    ("*.acme.test", "a.b.acme.test", False),
    ("*.acme.test", "acme.test", False),
    ("**.acme.test", "a.acme.test", True),
    ("**.acme.test", "a.b.c.acme.test", True),
    ("**.acme.test", "acme.test", False),
    ("**.acme.test", "evilacme.test", False),
    ("**.acme.test", "a.acme.test.evil.example", False),
    ("**.acme.test", "A.B.ACME.TEST", True),
    ("api-?.acme.test", "api-1.acme.test", True),
    ("api-?.acme.test", "api-12.acme.test", False),
]


class TestWildcardDepth:
    @pytest.mark.parametrize(("pattern", "name", "expected"), CASES)
    def test_guardrail_and_network_guard_agree(
        self, pattern: str, name: str, expected: bool
    ) -> None:
        # Two implementations (the guard image ships no buggy_core) must never disagree:
        # a name the guardrail allows and the guard drops, or the reverse, is a hole.
        assert _glob_match(pattern, name) is expected
        assert glob_match(pattern, name) is expected

    def test_any_depth_scope_reaches_every_enforcement_point(self) -> None:
        document = {"machine_enforcement": {"mode": "enforce", "in_scope": ["**.acme.test"]}}
        rules = parse_roe_document(document, required=True)
        assert evaluate_target("a.b.acme.test", rules).allow
        assert not evaluate_target("acme.test", rules).allow
        scope = ScopeFilter.from_document(document)
        assert scope.allows("https://deep.sub.acme.test/x") and not scope.allows("acme.test")
        assert scope.seeds().roots == ("acme.test",)  # subdomain enumeration starts at the root
        guard = Policy.from_wire(compile_egress_policy(rules).to_dict())
        assert guard.name_decision("deep.sub.acme.test")[0] is True
        assert guard.name_decision("acme.test")[0] is False


def _block(**extra: Any) -> dict[str, Any]:
    return {"mode": "enforce", "in_scope": ["app.acme.test", "203.0.113.0/28"], **extra}


class TestBlockedSandboxNetwork:
    def test_default_is_scoped(self) -> None:
        rules = MachineEnforcement.from_dict(_block())
        assert rules.sandbox_egress == "scoped" and rules.sandbox_blocked is False
        policy = compile_egress_policy(rules)
        assert "app.acme.test" in policy.allowed_hosts and policy.allowed_cidrs

    def test_blocked_gives_the_sandbox_no_route_to_any_target(self) -> None:
        rules = MachineEnforcement.from_dict(_block(sandbox_egress="blocked"))
        assert rules.sandbox_blocked is True
        policy = compile_egress_policy(rules)
        assert policy.enforce and policy.default_drop
        # Only the fixed OSINT search providers stay reachable; no target does.
        assert policy.allowed_cidrs == ()
        assert set(policy.allowed_hosts) == set(osint_egress_hosts())
        assert "app.acme.test" not in policy.allowed_hosts
        guard = Policy.from_wire(policy.to_dict())
        assert guard.name_decision("app.acme.test")[0] is False
        # The gateway and pipeline still treat the target as in scope.
        document = {"machine_enforcement": _block(sandbox_egress="blocked")}
        assert ScopeFilter.from_document(document).allows("https://app.acme.test/")

    def test_blocked_only_means_something_in_enforce_mode(self) -> None:
        rules = MachineEnforcement.from_dict({"mode": "audit", "sandbox_egress": "blocked"})
        assert rules.sandbox_blocked is False

    @pytest.mark.parametrize("value", ["BLOCKED", "blocked"])
    def test_value_is_case_insensitive_and_unknown_values_are_scoped(self, value: str) -> None:
        assert MachineEnforcement.from_dict(_block(sandbox_egress=value)).sandbox_blocked
        assert not MachineEnforcement.from_dict(_block(sandbox_egress="maybe")).sandbox_blocked


@pytest.fixture
def plane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    for name in ("workspace", "control", "audit"):
        (tmp_path / name / "acme").mkdir(parents=True)
    monkeypatch.setenv("BUGGY_WORKSPACE_ROOT", str(tmp_path / "workspace"))
    monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(tmp_path / "control"))
    monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(tmp_path / "audit"))
    monkeypatch.setenv("BUGGY_ROE_REQUIRE", "1")
    monkeypatch.delenv("BENCHMARK_MODE", raising=False)
    (tmp_path / "control" / "acme" / "roe.json").write_text(
        json.dumps({"machine_enforcement": _block(sandbox_egress="blocked")})
    )
    return {"workspace_path": str(tmp_path / "workspace" / "acme"), "engagement_name": "acme"}


def _request(tool: str, args: dict[str, Any], state: dict[str, str]) -> MagicMock:
    request = MagicMock()
    request.tool = MagicMock()
    request.tool.name = tool
    request.state = state
    request.tool_call = MagicMock()
    request.tool_call.args = args
    request.tool_call.id = "tc-1"
    request.tool_call_args = args
    request.tool_call_id = "tc-1"
    return request


class TestGuardrailExplainsTheBlock:
    def _call(
        self, tool: str, args: dict[str, Any], state: dict[str, str]
    ) -> tuple[Any, MagicMock]:
        handler = MagicMock(return_value=ToolMessage(content="ran", tool_call_id="tc-1"))
        result = RoEGuardrailMiddleware().wrap_tool_call(_request(tool, args, state), handler)
        return result, handler

    def test_a_shell_command_aimed_at_the_target_is_refused_with_the_alternative(
        self, plane
    ) -> None:
        result, handler = self._call(
            "bash", {"command": "curl -X POST https://app.acme.test/api"}, plane
        )
        handler.assert_not_called()
        text = str(result.content)
        assert "SANDBOX_NETWORK_BLOCKED" in text and "http_send" in text and "probe_run" in text

    def test_offline_shell_work_still_runs(self, plane) -> None:
        result, handler = self._call(
            "bash", {"command": "jq . captures.json | sort | uniq -c"}, plane
        )
        handler.assert_called_once()
        assert result.content == "ran"

    def test_gateway_tools_are_not_blocked(self, plane) -> None:
        for tool in ("http_send", "browser_open", "http_request"):
            _result, handler = self._call(
                tool, {"url": "https://app.acme.test/", "method": "GET"}, plane
            )
            handler.assert_called_once()

    def test_sandbox_side_fetch_is_blocked_and_out_of_scope_is_still_its_own_refusal(
        self, plane
    ) -> None:
        result, handler = self._call("web_fetch", {"url": "https://app.acme.test/"}, plane)
        handler.assert_not_called()
        assert "SANDBOX_NETWORK_BLOCKED" in str(result.content)
        result, _ = self._call("bash", {"command": "curl https://evil.example/"}, plane)
        assert "SANDBOX_NETWORK_BLOCKED" not in str(result.content)
        assert "ROE_REFUSED" in str(result.content)


class _Gateway:
    """Records what the in-process tools hand to the evidence gateway."""

    def __init__(self, reply: dict[str, Any]) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def call(self, server: str, tool_name: str, arguments: dict[str, Any]) -> str:
        self.calls.append((server, tool_name, arguments))
        return json.dumps(self.reply)


OK_REPLY = {
    "status": 200,
    "capture_id": "cap-1",
    "elapsed_ms": 12,
    "response_headers": {"Server": "nginx/1.25.3", "X-Powered-By": "Express"},
    "response_body": "<html>hello</html>",
}


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> _Gateway:
    fake = _Gateway(dict(OK_REPLY))
    monkeypatch.setenv("BUGGY_MCP_CAPTURE_URL", "http://capture-mcp:9461/mcp")
    monkeypatch.setenv("BUGGY_MCP_BROWSER_URL", "http://browser-mcp:9463/mcp")
    monkeypatch.setenv("BUGGY_ENGAGEMENT_ID", "acme")
    monkeypatch.setattr(stack_mcp, "call_mcp", fake.call)
    return fake


def _invoke(tool: Any, **kwargs: Any) -> dict[str, Any]:
    return json.loads(asyncio.run(tool.ainvoke(kwargs)))


class TestInProcessToolsGoThroughTheGateway:
    def test_http_request_never_opens_its_own_connection(self, gateway, monkeypatch) -> None:
        from buggy.tools.web import tools as web

        monkeypatch.setattr(web, "_get_session", lambda: pytest.fail("opened a direct session"))
        out = _invoke(web.http_request, method="post", url="https://app.acme.test/api", body="{}")
        assert out["status"] == 200 and out["capture_id"] == "cap-1"
        assert out["redirects_followed"] is False
        server, tool_name, arguments = gateway.calls[0]
        assert (server, tool_name) == ("capture", "http_send")
        assert arguments["engagement"] == "acme" and arguments["method"] == "POST"

    def test_http_request_surfaces_a_refusal(self, gateway, monkeypatch) -> None:
        from buggy.tools.web import tools as web

        gateway.reply = {
            "status": "refused",
            "code": "APPROVAL_REQUIRED",
            "detail": "held",
            "request_id": "apr-1",
        }
        out = _invoke(web.http_request, method="DELETE", url="https://app.acme.test/x")
        assert "APPROVAL_REQUIRED" in out["error"] and out["request_id"] == "apr-1"

    def test_tech_detection_uses_one_recorded_get(self, gateway, monkeypatch) -> None:
        from buggy.tools.research import tech_detection

        monkeypatch.setattr(tech_detection, "_load_roe_rules", lambda: MachineEnforcement())
        monkeypatch.setattr(
            tech_detection.httpx, "AsyncClient", lambda **_k: pytest.fail("opened a direct client")
        )
        out = _invoke(tech_detection.detect_tech_stack, url="https://app.acme.test/")
        assert out["status_code"] == 200 and out["capture_id"] == "cap-1"
        assert out["server"] == "nginx/1.25.3"
        assert gateway.calls[0][2]["method"] == "GET"

    def test_proxy_send_request_is_the_gateway(self, gateway, monkeypatch) -> None:
        from buggy.tools.proxy import tools as proxy

        sent: list[dict[str, Any]] = []

        def fake_sync(server: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            sent.append({"server": server, "tool": tool_name, **arguments})
            return dict(OK_REPLY)

        monkeypatch.setattr(stack_mcp, "call_mcp_sync", fake_sync)
        monkeypatch.setattr(proxy, "CaidoClient", lambda: pytest.fail("started the proxy CLI"))
        out = json.loads(
            proxy.proxy_send_request.invoke({"method": "get", "url": "https://app.acme.test/"})
        )
        assert out["capture_id"] == "cap-1"
        assert sent[0]["tool"] == "http_send" and sent[0]["engagement"] == "acme"

    def test_browser_action_drives_the_scoped_browser(self, gateway, monkeypatch) -> None:
        from buggy.tools.browser import tools as browser

        monkeypatch.setattr(
            browser, "_dispatch", lambda *_a: pytest.fail("launched a local browser")
        )
        gateway.reply = {"url": "https://app.acme.test/", "status": 200}
        _invoke(
            browser.browser_action, action="goto", params_json='{"url": "https://app.acme.test/"}'
        )
        _invoke(
            browser.browser_action, action="type", params_json='{"selector": "#q", "text": "x"}'
        )
        _invoke(browser.browser_action, action="eval_js", params_json='{"expression": "1+1"}')
        assert [c[1] for c in gateway.calls] == ["browser_open", "browser_fill", "browser_eval"]
        assert gateway.calls[1][2] == {"engagement": "acme", "selector": "#q", "text": "x"}
        out = _invoke(browser.browser_action, action="pdf")
        assert "not available on the scoped browser" in out["error"]
        assert (
            "missing required parameter" in _invoke(browser.browser_action, action="goto")["error"]
        )

    def test_without_the_stack_services_the_tools_keep_their_old_path(self, monkeypatch) -> None:
        for env in stack_mcp.SERVER_ENV.values():
            monkeypatch.delenv(env, raising=False)
        assert not stack_mcp.server_configured("capture")
        assert not stack_mcp.server_configured("browser")


class TestSeedUrls:
    def test_only_http_urls_are_kept_and_they_do_not_widen_scope(self) -> None:
        document = {
            "machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]},
            "pipeline": {
                "seed_urls": [
                    "https://app.acme.test:8443/shop",
                    "ftp://app.acme.test/",
                    "https://evil.example/",
                    7,
                ]
            },
        }
        rules = parse_roe_document(document, required=True)
        limits = PipelineLimits.from_roe(rules, document)
        assert limits.seed_urls == ("https://app.acme.test:8443/shop", "https://evil.example/")
        drops: list[str] = []
        scope = ScopeFilter.from_document(document, log_drop=lambda *a: drops.append(a[3]))
        kept = scope.admit(list(limits.seed_urls), stage="live", tool="seed", direction="input")
        assert kept == ["https://app.acme.test:8443/shop"] and drops == ["https://evil.example/"]
