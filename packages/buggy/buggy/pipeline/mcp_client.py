"""Blocking client for the stack's MCP servers, for code that runs without an agent framework.

``buggy.tools.stack_mcp`` is the agent-side client; it registers LangChain
tools, so importing it needs ``langchain_core``. The operator commands that
only watch recon and write a report (``buggy-cli hunt --no-agent``) run from
the slim pipeline image, which has no agent framework. This module is the
same client call with the ``mcp`` SDK only.

It deliberately matches ``stack_mcp``: the same URL variables
(``BUGGY_MCP_RECON_URL`` and friends), the same bearer token header
(:func:`buggy.pipeline.mcp_http.client_headers`) and the same result shape.
Nothing is contacted at import time, and an unreachable, unauthenticated or
unconfigured server is an ``{"error": ...}`` result, never an exception.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from typing import Any

from buggy.pipeline.mcp_http import client_headers

log = logging.getLogger(__name__)

#: Which variable enables each server. Keep in step with ``buggy.tools.stack_mcp.SERVER_ENV``.
SERVER_ENV = {
    "recon": "BUGGY_MCP_RECON_URL",
    "capture": "BUGGY_MCP_CAPTURE_URL",
    "scope": "BUGGY_MCP_SCOPE_URL",
    "browser": "BUGGY_MCP_BROWSER_URL",
}
CALL_TIMEOUT_SECONDS = 180.0


def server_url(server: str) -> str:
    return (os.environ.get(SERVER_ENV[server]) or "").strip()


def server_configured(server: str) -> bool:
    """Whether this deployment runs the named stack MCP server."""
    return bool(server_url(server))


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
        from mcp import ClientSession  # noqa: PLC0415 - not needed to import this module
        from mcp.client.streamable_http import streamablehttp_client  # noqa: PLC0415
    except ImportError:
        return json.dumps({"error": "the MCP client is not installed (pip install 'buggy[mcp]')"})

    async def _call() -> str:
        async with streamablehttp_client(url, headers=client_headers()) as (
            read,
            write,
            _session_id,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return _result_text(await session.call_tool(tool_name, arguments))

    try:
        return await asyncio.wait_for(_call(), timeout=CALL_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - the caller gets a result, not a stack trace
        log.warning("mcp_client: %s.%s failed: %s", server, tool_name, exc)
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


__all__ = [
    "CALL_TIMEOUT_SECONDS",
    "SERVER_ENV",
    "call_mcp",
    "call_mcp_sync",
    "server_configured",
    "server_url",
]
