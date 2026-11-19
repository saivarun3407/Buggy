"""The scoped browser against a real Chromium and two local HTTP servers.

One server is in scope, the other is not. The in-scope page pulls an image
and a fetch() from the out-of-scope server and posts a form. The test asserts
on what the *servers* received, not on what the browser reports.

Skipped when Playwright or a Chromium build is not installed.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("playwright")

from buggy.middleware._audit_sink import iter_records, verify_ledger  # noqa: E402
from buggy.scoped_browser.session import BrowserError, ScopedBrowser, find_chromium  # noqa: E402

pytestmark = pytest.mark.skipif(
    find_chromium() is None, reason="no Chromium build available for Playwright"
)


class _Origin:
    """A tiny HTTP server that remembers every request it receives."""

    def __init__(self, host: str, pages: dict[str, str]) -> None:
        self.seen: list[tuple[str, str]] = []
        origin = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                return

            def _serve(self) -> None:
                origin.seen.append((self.command, self.path))
                body = pages.get(self.path.split("?")[0], "not found").encode()
                self.send_response(200 if self.path.split("?")[0] in pages else 404)
                self.send_header("Content-Type", "text/html")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _serve  # noqa: N815

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def sites(tmp_path: Path) -> Iterator[dict]:
    # 127.0.0.1 is in scope; the name "localhost" is a different host and is not.
    outside = _Origin(
        "127.0.0.1", {"/pixel.png": "x", "/api": "{}", "/landing": "<title>outside</title>"}
    )
    inside_pages: dict[str, str] = {}
    inside = _Origin("127.0.0.1", inside_pages)
    off_scope = f"http://localhost:{outside.port}"
    inside_pages["/"] = (
        "<html><head><title>inside</title></head><body><h1 id='h'>in scope</h1>"
        f"<img src='{off_scope}/pixel.png'>"
        "<form id='f' method='post' action='/submit'><input name='q' id='q'><button id='go'>go</button></form>"
        f"<a id='leave' href='{off_scope}/landing'>leave</a>"
        f"<script>fetch('{off_scope}/api').catch(()=>{{}}); fetch('/data.json');</script>"
        "</body></html>"
    )
    inside_pages["/data.json"] = '{"ok": true}'
    inside_pages["/submit"] = "<title>submitted</title>"
    control, audit = tmp_path / "control", tmp_path / "audit"
    (control / "acme").mkdir(parents=True)

    def scope(**extra) -> None:
        document = {"machine_enforcement": {"mode": "enforce", "in_scope": ["127.0.0.1"]}, **extra}
        (control / "acme" / "roe.json").write_text(json.dumps(document))

    scope()
    yield {
        "inside": inside,
        "outside": outside,
        "url": f"http://127.0.0.1:{inside.port}/",
        "off_scope": off_scope,
        "control": control,
        "audit": audit,
        "scope": scope,
    }
    inside.close()
    outside.close()


def _run(coro):
    return asyncio.run(coro)


def test_page_loads_and_out_of_scope_requests_never_leave(sites) -> None:
    async def scenario():
        browser = ScopedBrowser(sites["control"], sites["audit"])
        try:
            opened = await browser.open("acme", sites["url"])
            await asyncio.sleep(0.5)
            return opened, browser.requests("acme"), await browser.text("acme")
        finally:
            await browser.close()

    opened, requests, text = _run(scenario())
    assert opened["title"] == "inside" and opened["status"] == 200 and "in scope" in text["text"]
    # The in-scope server served the page and its own fetch...
    assert ("GET", "/") in sites["inside"].seen and ("GET", "/data.json") in sites["inside"].seen
    # ...and the out-of-scope server never heard from the browser.
    assert sites["outside"].seen == []
    blocked = {(r["url"], r["reason"]) for r in requests if r["outcome"] == "blocked"}
    assert (f"{sites['off_scope']}/pixel.png", "NOT_IN_SCOPE") in blocked
    assert (f"{sites['off_scope']}/api", "NOT_IN_SCOPE") in blocked
    ledger = sites["audit"] / "acme" / "browser-drops.jsonl"
    assert verify_ledger(ledger).ok
    logged = {r["url"] for r in iter_records(ledger)}
    assert f"{sites['off_scope']}/pixel.png" in logged


def test_navigation_off_scope_is_refused_and_clicks_cannot_leave(sites) -> None:
    async def scenario():
        browser = ScopedBrowser(sites["control"], sites["audit"])
        try:
            with pytest.raises(BrowserError, match="not in the enforced scope"):
                await browser.open("acme", f"{sites['off_scope']}/landing")
            await browser.open("acme", sites["url"])
            try:
                await browser.click("acme", "#leave")
            except Exception:  # noqa: BLE001, S110 - the aborted navigation may surface as an error
                pass
            await asyncio.sleep(0.5)
            return (await browser.text("acme"))["url"]
        finally:
            await browser.close()

    final_url = _run(scenario())
    assert sites["outside"].seen == []
    assert "localhost" not in final_url


def test_state_changing_requests_are_blocked_until_the_scope_waives_approval(sites) -> None:
    async def submit():
        browser = ScopedBrowser(sites["control"], sites["audit"])
        try:
            await browser.open("acme", sites["url"])
            await browser.fill("acme", "#q", "hello")
            try:
                await browser.click("acme", "#go")
            except Exception:  # noqa: BLE001, S110
                pass
            await asyncio.sleep(0.5)
            return browser.requests("acme")
        finally:
            await browser.close()

    requests = _run(submit())
    assert ("POST", "/submit") not in sites["inside"].seen
    assert any(
        r["reason"] == "APPROVAL_REQUIRED_USE_HTTP_SEND"
        for r in requests
        if r["outcome"] == "blocked"
    )

    sites["scope"](approvals={"state_changing": "not_required"})
    _run(submit())
    assert ("POST", "/submit") in sites["inside"].seen


def test_no_enforced_scope_means_no_browsing(sites, tmp_path: Path) -> None:
    async def scenario():
        browser = ScopedBrowser(tmp_path / "empty-control", sites["audit"])
        try:
            with pytest.raises(BrowserError):
                await browser.open("acme", sites["url"])
        finally:
            await browser.close()

    _run(scenario())
    assert sites["inside"].seen == []


def test_scope_change_takes_effect_on_the_next_request(sites) -> None:
    async def scenario():
        browser = ScopedBrowser(sites["control"], sites["audit"])
        try:
            await browser.open("acme", sites["url"])
            (sites["control"] / "acme" / "roe.json").write_text(
                json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["other.test"]}})
            )
            before = len(sites["inside"].seen)
            await browser.evaluate("acme", "fetch('/data.json').catch(() => 'blocked')")
            await asyncio.sleep(0.3)
            return before
        finally:
            await browser.close()

    before = _run(scenario())
    assert len(sites["inside"].seen) == before  # the operator removed it from scope mid-session
