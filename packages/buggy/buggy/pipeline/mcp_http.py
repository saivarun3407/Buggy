"""Serve one of the stack's MCP servers over HTTP, behind a bearer token.

The recon, capture, scope and browser servers can act on targets or read
evidence, so reaching the port must not be enough to use them. Every request
must carry ``Authorization: Bearer <BUGGY_STACK_MCP_TOKEN>``. The token is
held by the servers and by langgraph only; the sandbox never has it.

A server refuses to start without a token unless
``BUGGY_STACK_MCP_ALLOW_UNAUTHENTICATED=1`` is set (tests, local debugging).
"""

from __future__ import annotations

import hmac
import json
import os
from typing import Any

TOKEN_ENV = "BUGGY_STACK_MCP_TOKEN"  # noqa: S105 - the name of an env var, not a secret
ALLOW_ENV = "BUGGY_STACK_MCP_ALLOW_UNAUTHENTICATED"
MIN_TOKEN_CHARS = 16


class McpStartupError(RuntimeError):
    """The server must not start in this configuration."""


def configured_token() -> str | None:
    """The required token, or ``None`` when unauthenticated use was allowed explicitly."""
    token = (os.environ.get(TOKEN_ENV) or "").strip()
    if token:
        if len(token) < MIN_TOKEN_CHARS:
            raise McpStartupError(f"{TOKEN_ENV} must be at least {MIN_TOKEN_CHARS} characters")
        return token
    if (os.environ.get(ALLOW_ENV) or "").strip().lower() in {"1", "true", "yes", "on"}:
        return None
    raise McpStartupError(
        f"{TOKEN_ENV} must be set (scripts/ensure-stack-secrets.sh or `buggy onboard` generate it); "
        f"set {ALLOW_ENV}=1 only for local debugging"
    )


def client_headers() -> dict[str, str]:
    """Headers a client in this deployment sends to the stack's MCP servers."""
    token = (os.environ.get(TOKEN_ENV) or "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


class BearerAuth:
    """ASGI middleware: 401 for any HTTP request without the exact bearer token."""

    def __init__(self, app: Any, token: str) -> None:
        self._app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        presented = b""
        for name, value in scope.get("headers") or []:
            if name == b"authorization":
                presented = value
                break
        if hmac.compare_digest(presented, self._expected):
            await self._app(scope, receive, send)
            return
        body = json.dumps({"error": "unauthorized"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b"Bearer"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def build_app(mcp: Any) -> Any:
    """The server's ASGI app, wrapped in bearer auth when a token is configured."""
    token = configured_token()
    app = mcp.streamable_http_app()
    return BearerAuth(app, token) if token is not None else app


def serve(mcp: Any, *, host: str, port: int) -> None:
    """Run ``mcp`` over streamable HTTP until the process is stopped."""
    import uvicorn  # noqa: PLC0415 - ships with the MCP SDK

    uvicorn.run(build_app(mcp), host=host, port=port, log_level="info")


__all__ = [
    "ALLOW_ENV",
    "TOKEN_ENV",
    "BearerAuth",
    "McpStartupError",
    "build_app",
    "client_headers",
    "configured_token",
    "serve",
]
