"""Agent-side tools for the stack's own MCP servers.

Four servers hold what agents must not do themselves, or must not be able to
alter:

``recon``    read-only pipeline data            (buggy.pipeline.mcp_server)
``capture``  evidence HTTP + deterministic probes (buggy.capture.mcp_server)
``scope``    enforced scope + program data       (buggy.capture.scope_server)
``browser``  scope-enforced browser              (buggy.scoped_browser.mcp_server)

Each tool here is a thin MCP client call. Two things are deliberately not
left to the model:

* the engagement is taken from the run's config, never from a tool argument,
  so an agent cannot read or act on another engagement;
* nothing is contacted at import time. A server is reached when its tool is
  called, and an unreachable server is an error result, not a crash.

A server is enabled by its URL variable (``BUGGY_MCP_RECON_URL``,
``BUGGY_MCP_CAPTURE_URL``, ``BUGGY_MCP_SCOPE_URL``, ``BUGGY_MCP_BROWSER_URL``);
unset means its tools are not offered.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from typing import Any

from langchain_core.tools import tool

from buggy_core.utils.engagement_scope import get_active_engagement
from buggy_core.utils.logging import get_logger

log = get_logger("tools.stack_mcp")

SERVER_ENV = {
    "recon": "BUGGY_MCP_RECON_URL",
    "capture": "BUGGY_MCP_CAPTURE_URL",
    "scope": "BUGGY_MCP_SCOPE_URL",
    "browser": "BUGGY_MCP_BROWSER_URL",
}
CALL_TIMEOUT_SECONDS = 180.0


def server_url(server: str) -> str:
    return (os.environ.get(SERVER_ENV[server]) or "").strip()


def current_engagement() -> str:
    """The run's engagement slug: run config first, then the active-engagement context."""
    try:
        from langgraph.config import get_config  # noqa: PLC0415

        configurable = (get_config() or {}).get("configurable") or {}
        name = configurable.get("engagement_name")
        if isinstance(name, str) and name:
            return name
    except Exception:  # noqa: BLE001, S110 - outside a run there is no config
        pass
    return get_active_engagement() or os.environ.get("BUGGY_ENGAGEMENT_ID", "")


def _result_text(result: Any) -> str:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        payload = structured.get("result", structured)
        return json.dumps(payload, indent=2, default=str)
    parts = [getattr(item, "text", "") for item in getattr(result, "content", []) or []]
    return "\n".join(p for p in parts if p) or "{}"


async def call_mcp(server: str, tool_name: str, arguments: dict[str, Any]) -> str:
    """Call one tool on one of the stack's MCP servers; always returns JSON text."""
    url = server_url(server)
    if not url:
        return json.dumps(
            {"error": f"the {server} server is not configured ({SERVER_ENV[server]})"}
        )
    try:
        from mcp import ClientSession  # noqa: PLC0415 - optional dependency
        from mcp.client.streamable_http import streamablehttp_client  # noqa: PLC0415
    except ImportError:
        return json.dumps({"error": "the MCP client is not installed (pip install 'buggy[mcp]')"})

    async def _call() -> str:
        async with streamablehttp_client(url) as (read, write, _session_id):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return _result_text(await session.call_tool(tool_name, arguments))

    try:
        return await asyncio.wait_for(_call(), timeout=CALL_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - the agent gets a result, not a stack trace
        log.warning("stack_mcp: %s.%s failed: %s", server, tool_name, exc)
        return json.dumps(
            {"error": f"{server} server call failed: {type(exc).__name__}: {str(exc)[:300]}"}
        )


def call_mcp_sync(server: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Blocking :func:`call_mcp` for synchronous callers; always returns a dict.

    Runs the call on its own thread and event loop, so it is safe to use from
    code that may or may not already be inside a running loop.
    """
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["text"] = asyncio.run(call_mcp(server, tool_name, arguments))
        except Exception as exc:  # noqa: BLE001 - reported to the caller as data
            box["text"] = json.dumps({"error": f"{type(exc).__name__}: {str(exc)[:300]}"})

    thread = threading.Thread(target=run, name=f"mcp-{server}-{tool_name}", daemon=True)
    thread.start()
    thread.join(CALL_TIMEOUT_SECONDS + 5)
    if thread.is_alive():
        return {"error": f"{server} server call timed out"}
    try:
        parsed = json.loads(box.get("text") or "{}")
    except ValueError:
        return {"error": f"{server} server returned a non-JSON result"}
    return parsed if isinstance(parsed, dict) else {"result": parsed}


async def _engagement_call(server: str, tool_name: str, **arguments: Any) -> str:
    engagement = current_engagement()
    if not engagement:
        return json.dumps({"error": "no engagement is active for this run"})
    return await call_mcp(server, tool_name, {"engagement": engagement, **arguments})


# ── recon: read-only pipeline data ───────────────────────────────────


@tool
async def recon_summary() -> str:
    """Deterministic recon already done for this engagement: record counts by type, the last
    pipeline run and what it changed. Start here instead of running recon tools."""
    return await _engagement_call("recon", "recon_summary")


@tool
async def recon_assets(limit: int = 200) -> str:
    """In-scope assets (hosts) the pipeline has facts about, with record counts."""
    return await _engagement_call("recon", "recon_assets", limit=limit)


@tool
async def recon_query(
    record_type: str = "", asset: str = "", contains: str = "", limit: int = 50, offset: int = 0
) -> str:
    """Query pipeline records. record_type: subdomain, dns_record, port, http_service,
    technology, tls, header, url, js_file, endpoint, api_spec, api_operation, graphql,
    vulnerability, secret. Filter by asset (host) and/or a substring of the value. Paged."""
    return await _engagement_call(
        "recon",
        "recon_query",
        record_type=record_type,
        asset=asset,
        contains=contains,
        limit=limit,
        offset=offset,
    )


@tool
async def recon_record(record_id: str) -> str:
    """One pipeline record with every observation: which tools reported it, when, raw_ref."""
    return await _engagement_call("recon", "recon_record", record_id=record_id)


@tool
async def recon_diff(run_id: str = "") -> str:
    """What the latest (or given) pipeline run added, changed or removed."""
    return await _engagement_call("recon", "recon_diff", run_id=run_id)


@tool
async def recon_raw(raw_ref: str, context_lines: int = 0) -> str:
    """The unparsed scanner output behind a record's raw_ref (argv, version, hash, line)."""
    return await _engagement_call(
        "recon", "recon_raw", raw_ref=raw_ref, context_lines=context_lines
    )


@tool
async def recon_request_rerun(asset: str, reason: str = "") -> str:
    """Ask the pipeline to re-run for ONE in-scope asset (host, host:port or URL). You cannot
    choose scanners or flags. Returns a request id; check it with recon_rerun_status."""
    return await _engagement_call("recon", "recon_request_rerun", asset=asset, reason=reason)


@tool
async def recon_rerun_status(request_id: str) -> str:
    """Status of a re-run request: pending, completed, rejected or failed."""
    return await _engagement_call("recon", "recon_rerun_status", request_id=request_id)


# ── capture: evidence HTTP and probes ────────────────────────────────


@tool
async def http_send(
    method: str, url: str, headers_json: str = "", body: str = "", note: str = ""
) -> str:
    """Send one HTTP request to an in-scope target through the capture gateway. The exchange
    is recorded outside your reach; the returned capture_id is what a finding cites as proof.
    Redirects are returned, not followed. A state-changing method may return
    APPROVAL_REQUIRED: tell the operator, then re-send the identical request."""
    return await _engagement_call(
        "capture",
        "http_send",
        method=method,
        url=url,
        headers_json=headers_json,
        body=body,
        note=note,
    )


@tool
async def http_replay(capture_id: str) -> str:
    """Re-send a captured request from the gateway and compare with the original, to show
    that a finding reproduces."""
    return await _engagement_call("capture", "http_replay", capture_id=capture_id)


@tool
async def http_capture(capture_id: str, body_chars: int = 8000) -> str:
    """One captured exchange in full (credentials in headers are redacted)."""
    return await _engagement_call(
        "capture", "http_capture", capture_id=capture_id, body_chars=body_chars
    )


@tool
async def http_captures(host: str = "", probe: str = "", limit: int = 20) -> str:
    """Recent captures, newest first, optionally for one host or probe."""
    return await _engagement_call("capture", "http_captures", host=host, probe=probe, limit=limit)


@tool
async def capture_verify(capture_id: str, expect_host: str = "") -> str:
    """Whether a capture exists for this engagement, is in scope and is for expect_host."""
    return await _engagement_call(
        "capture", "capture_verify", capture_id=capture_id, expect_host=expect_host
    )


@tool
async def probe_list() -> str:
    """The deterministic probes available: vulnerability class, what each checks, parameters."""
    return await call_mcp("capture", "probe_list", {})


@tool
async def probe_run(probe: str, params_json: str) -> str:
    """Run a deterministic probe (jwt_alg_none, idor, ssrf_canary, numeric_boundary,
    mass_assignment, graphql_checks). You choose the endpoint and identities; the probe sends
    the requests, compares the outcomes and returns vulnerable true / false / null (null =
    could not tell) with evidence capture ids. params_json is a JSON object (see probe_list)."""
    return await _engagement_call("capture", "probe_run", probe=probe, params_json=params_json)


# ── scope ────────────────────────────────────────────────────────────


@tool
async def scope_show() -> str:
    """The enforced scope for this engagement: in/out-of-scope rules, rate limits, whether
    state-changing requests need approval, banned techniques."""
    return await _engagement_call("scope", "scope_show")


@tool
async def scope_check(target: str) -> str:
    """Is this host, host:port or URL in the enforced scope? Returns the reason if not."""
    return await _engagement_call("scope", "scope_check", target=target)


@tool
async def program_info() -> str:
    """The bounty program's official scope data and binding rules, as imported by the operator:
    rate limit, banned techniques (no DoS, no social engineering, no data exfiltration beyond
    proof), excluded classes, and what a finding must contain. Read it before testing."""
    return await _engagement_call("scope", "program_info")


# ── browser ──────────────────────────────────────────────────────────


@tool
async def browser_open(url: str) -> str:
    """Open an in-scope URL in a real browser (JavaScript runs). Requests the page makes to
    out-of-scope hosts are blocked and reported."""
    return await _engagement_call("browser", "browser_open", url=url)


@tool
async def browser_click(selector: str) -> str:
    """Click the element matching a CSS selector in the open page."""
    return await _engagement_call("browser", "browser_click", selector=selector)


@tool
async def browser_fill(selector: str, text: str) -> str:
    """Type text into the input matching a CSS selector."""
    return await _engagement_call("browser", "browser_fill", selector=selector, text=text)


@tool
async def browser_eval(expression: str) -> str:
    """Evaluate a JavaScript expression in the open page and return its JSON value."""
    return await _engagement_call("browser", "browser_eval", expression=expression)


@tool
async def browser_text() -> str:
    """The visible text of the open page."""
    return await _engagement_call("browser", "browser_text")


@tool
async def browser_html() -> str:
    """The rendered HTML of the open page (after scripts ran)."""
    return await _engagement_call("browser", "browser_html")


@tool
async def browser_requests(limit: int = 50) -> str:
    """Requests the open page made: allowed ones, and blocked ones with the reason."""
    return await _engagement_call("browser", "browser_requests", limit=limit)


@tool
async def browser_cookies() -> str:
    """Cookie names and security flags for the browser session (values are not returned)."""
    return await _engagement_call("browser", "browser_cookies")


_BY_SERVER: dict[str, list[Any]] = {
    "recon": [
        recon_summary,
        recon_assets,
        recon_query,
        recon_record,
        recon_diff,
        recon_raw,
        recon_request_rerun,
        recon_rerun_status,
    ],
    "capture": [
        http_send,
        http_replay,
        http_capture,
        http_captures,
        capture_verify,
        probe_list,
        probe_run,
    ],
    "scope": [scope_show, scope_check, program_info],
    "browser": [
        browser_open,
        browser_click,
        browser_fill,
        browser_eval,
        browser_text,
        browser_html,
        browser_requests,
        browser_cookies,
    ],
}

ALL_STACK_MCP_TOOLS: list[Any] = [t for tools in _BY_SERVER.values() for t in tools]


def stack_mcp_tools() -> list[Any]:
    """Tools for the servers that are configured in this process."""
    return [t for server, tools in _BY_SERVER.items() if server_url(server) for t in tools]


# Which servers each role gets. Everyone who plans or tests reads recon data
# and scope; only roles that actively test a target get the capture gateway
# and the browser.
_READERS = frozenset({"buggy", "recon", "analyst", "scout", "asvs", "mitre_attack"})
_TESTERS = frozenset(
    {
        "exploit",
        "api_security",
        "authn_session",
        "business_logic",
        "clientside_security",
        "graphql_security",
        "llm_security",
        "secrets_cicd",
        "ssrf_cloud",
    }
)


def stack_mcp_tools_for(role: str) -> list[Any]:
    """The configured stack MCP tools appropriate for ``role`` (empty for other roles)."""
    if role in _TESTERS:
        servers = ("recon", "scope", "capture", "browser")
    elif role in _READERS:
        servers = ("recon", "scope")
    else:
        return []
    return [t for server in servers if server_url(server) for t in _BY_SERVER[server]]


__all__ = [
    "ALL_STACK_MCP_TOOLS",
    "SERVER_ENV",
    "call_mcp",
    "current_engagement",
    "stack_mcp_tools",
    "stack_mcp_tools_for",
]
