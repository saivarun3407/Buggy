"""MCP server: scope-enforced browser.

Run with ``python -m buggy.scoped_browser.mcp_server`` (streamable HTTP, port 9463).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from buggy.scoped_browser.session import BrowserError, ScopedBrowser

DEFAULT_PORT = 9463
TOOL_NAMES = (
    "browser_open",
    "browser_click",
    "browser_fill",
    "browser_eval",
    "browser_text",
    "browser_html",
    "browser_screenshot",
    "browser_cookies",
    "browser_requests",
    "browser_close",
)

INSTRUCTIONS = (
    "A real browser for the current engagement, for anything that needs JavaScript or a logged-in "
    "session: single-page apps, DOM XSS, client-side routing, auth flows. Every request the page "
    "makes is checked against the enforced scope; out-of-scope requests are blocked and listed by "
    "browser_requests. If the engagement requires approval for state-changing requests, the "
    "browser is read-only: send that request with http_send instead."
)


async def _guard(coro: Any) -> dict[str, Any]:
    try:
        return await coro
    except BrowserError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - Playwright errors go back to the agent as text
        return {"error": f"{type(exc).__name__}: {str(exc)[:400]}"}


def register_tools(mcp: Any, browser: ScopedBrowser) -> None:
    @mcp.tool()
    async def browser_open(engagement: str, url: str) -> dict[str, Any]:
        """Open an in-scope URL. Returns the final URL, status, title and any blocked requests."""
        return await _guard(browser.open(engagement, url))

    @mcp.tool()
    async def browser_click(engagement: str, selector: str) -> dict[str, Any]:
        """Click the element matching a CSS selector."""
        return await _guard(browser.click(engagement, selector))

    @mcp.tool()
    async def browser_fill(engagement: str, selector: str, text: str) -> dict[str, Any]:
        """Type text into the input matching a CSS selector."""
        return await _guard(browser.fill(engagement, selector, text))

    @mcp.tool()
    async def browser_eval(engagement: str, expression: str) -> dict[str, Any]:
        """Evaluate a JavaScript expression in the page and return its JSON value."""
        return await _guard(browser.evaluate(engagement, expression))

    @mcp.tool()
    async def browser_text(engagement: str) -> dict[str, Any]:
        """The visible text of the current page."""
        return await _guard(browser.text(engagement))

    @mcp.tool()
    async def browser_html(engagement: str) -> dict[str, Any]:
        """The rendered HTML of the current page (after scripts ran)."""
        return await _guard(browser.html(engagement))

    @mcp.tool()
    async def browser_screenshot(engagement: str) -> dict[str, Any]:
        """A PNG screenshot of the current viewport, base64-encoded."""
        return await _guard(browser.screenshot(engagement))

    @mcp.tool()
    async def browser_cookies(engagement: str) -> dict[str, Any]:
        """Cookie names and flags for the session (values are not returned)."""
        return await _guard(browser.cookies(engagement))

    @mcp.tool()
    async def browser_requests(engagement: str, limit: int = 50) -> dict[str, Any]:
        """Requests the page made: allowed ones, and blocked ones with the reason."""
        return {"requests": browser.requests(engagement, limit)}

    @mcp.tool()
    async def browser_close(engagement: str) -> dict[str, Any]:
        """Close the engagement's browser session."""
        await browser.close(engagement)
        return {"closed": True}


def build_server(
    *,
    control_root: Path | None = None,
    audit_root: Path | None = None,
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
) -> tuple[Any, ScopedBrowser]:
    from mcp.server.fastmcp import FastMCP  # noqa: PLC0415 - optional dependency

    browser = ScopedBrowser(
        control_root or Path(os.environ.get("BUGGY_CONTROL_ROOT") or "/control"),
        audit_root or Path(os.environ.get("BUGGY_AUDIT_ROOT") or "/audit"),
    )
    mcp = FastMCP("buggy-browser", instructions=INSTRUCTIONS, host=host, port=port)
    register_tools(mcp, browser)
    return mcp, browser


def main() -> None:
    host = os.environ.get("BUGGY_BROWSER_MCP_HOST", "0.0.0.0")  # noqa: S104 - container-internal
    port = int(os.environ.get("BUGGY_BROWSER_MCP_PORT") or DEFAULT_PORT)
    mcp, _browser = build_server(host=host, port=port)
    from buggy.pipeline.mcp_http import serve  # noqa: PLC0415

    serve(mcp, host=host, port=port)


if __name__ == "__main__":
    main()
