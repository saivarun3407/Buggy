"""Playwright session with scope enforcement in the request path."""

from __future__ import annotations

import asyncio
import base64
import glob
import json
import os
import re
import shutil
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from buggy.capture.gateway import SAFE_METHODS, CaptureGateway, internal_address_block
from buggy.egress_guard.ledger import Ledger
from buggy.pipeline.scope import ScopeError, ScopeFilter

LOCAL_SCHEMES = frozenset({"data", "blob", "about", "chrome-error"})
MAX_LOG = 500
MAX_TEXT = 20000

# ── proof recording ─────────────────────────────────────────────────
PROOF_ID = re.compile(r"^F-[0-9a-f]{6,40}$")
MAX_PROOF_HTML = 2 * 1024 * 1024
PROOF_MAX_STEPS = 8
PROOF_VIEWPORT = {"width": 1280, "height": 720}
# The title card, then each step, then a short hold: at most 2.5 + 8 * 2.5 + 1 = 23.5 s.
PROOF_TITLE_SECONDS = 2.5
PROOF_STEP_SECONDS = 2.5
PROOF_END_SECONDS = 1.0
PROOF_VIDEO = "proof.webm"
PROOF_SCREENSHOT = "proof.png"
PROOF_FULL_SCREENSHOT = "proof-full.png"


class BrowserError(RuntimeError):
    """Something the caller can act on (no page open, selector missing, no scope)."""


class ProofError(BrowserError):
    """A proof recording that was refused or failed, with a code for the caller."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code

    def to_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": self.code, "detail": str(self)}


@dataclass
class RequestLog:
    entries: list[dict[str, Any]] = field(default_factory=list)

    def add(self, **entry: Any) -> None:
        self.entries.append({"at": time.time(), **entry})
        del self.entries[:-MAX_LOG]


def find_chromium() -> str | None:
    """An installed Chromium to fall back on when Playwright's own build is absent."""
    explicit = os.environ.get("BUGGY_BROWSER_EXECUTABLE")
    if explicit:
        return explicit
    for pattern in (
        "/opt/pw-browsers/chromium-*/chrome-linux*/chrome",
        "/ms-playwright/chromium-*/chrome-linux*/chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ):
        found = sorted(glob.glob(pattern))
        if found:
            return found[-1]
    return None


class ScopedBrowser:
    """One browser context per engagement, with every request scope-checked."""

    def __init__(self, control_root: Path, audit_root: Path, *, headless: bool = True) -> None:
        self._control = Path(control_root)
        self._audit = Path(audit_root)
        self._headless = headless
        self._playwright: Any = None
        self._browser: Any = None
        self._contexts: dict[str, Any] = {}
        self._pages: dict[str, Any] = {}
        self._logs: dict[str, RequestLog] = {}
        self._ledgers: dict[str, Ledger] = {}
        self._lock = asyncio.Lock()
        # How a proof recording waits between steps (a test makes it instant).
        self._pause: Callable[[float], Awaitable[Any]] = asyncio.sleep

    # ── scope ───────────────────────────────────────────────────────

    @staticmethod
    def _check_engagement(engagement: str) -> None:
        if not engagement or "/" in engagement or engagement.startswith("."):
            raise BrowserError("engagement name is required")

    def _scope(self, engagement: str) -> tuple[ScopeFilter, dict[str, Any]]:
        self._check_engagement(engagement)
        path = self._control / engagement / "roe.json"
        try:
            scope = ScopeFilter.from_file(path)
            document = json.loads(path.read_text(encoding="utf-8"))
        except ScopeError as exc:
            raise BrowserError(str(exc)) from exc
        return scope, document

    def _drop(self, engagement: str, url: str, method: str, reason: str, resource: str) -> None:
        self._logs.setdefault(engagement, RequestLog()).add(
            url=url[:500], method=method, resource=resource, outcome="blocked", reason=reason
        )
        ledger = self._ledgers.setdefault(
            engagement, Ledger(self._audit / engagement / "browser-drops.jsonl")
        )
        try:
            ledger.append(
                {
                    "ts": time.time(),
                    "event": "browser_request_blocked",
                    "engagement": engagement,
                    "decision": "drop",
                    "method": method,
                    "url": url[:2000],
                    "resource": resource,
                    "reason": reason,
                }
            )
        except OSError:
            pass

    def _decide(self, engagement: str, url: str, method: str) -> tuple[bool, str]:
        scheme = urlsplit(url).scheme.lower()
        if scheme in LOCAL_SCHEMES:
            return True, "LOCAL"
        if scheme not in ("http", "https", "ws", "wss"):
            return False, "UNSUPPORTED_SCHEME"
        try:
            scope, document = self._scope(engagement)
        except BrowserError:
            return False, "NO_ENFORCED_SCOPE"
        allowed, reason = scope.decide(url)
        if not allowed:
            return False, reason
        if internal_address_block(url, scope, document) is not None:
            return False, "INTERNAL_ADDRESS"
        if method.upper() not in SAFE_METHODS and CaptureGateway.approval_required(document):
            return False, "APPROVAL_REQUIRED_USE_HTTP_SEND"
        return True, reason

    # ── lifecycle ───────────────────────────────────────────────────

    async def _ensure_browser(self) -> None:
        if self._browser is not None:
            return
        from playwright.async_api import async_playwright  # noqa: PLC0415 - optional dependency

        self._playwright = await async_playwright().start()
        args = ["--no-sandbox", "--disable-dev-shm-usage"]
        try:
            self._browser = await self._playwright.chromium.launch(
                headless=self._headless, args=args
            )
        except Exception:  # noqa: BLE001 - fall back to an installed Chromium
            executable = find_chromium()
            if executable is None:
                raise
            self._browser = await self._playwright.chromium.launch(
                headless=self._headless, args=args, executable_path=executable
            )

    async def _page(self, engagement: str, *, create: bool = False) -> Any:
        if engagement in self._pages and not self._pages[engagement].is_closed():
            return self._pages[engagement]
        if not create:
            raise BrowserError("no page is open for this engagement; call browser_open first")
        self._scope(engagement)  # fail before launching anything
        await self._ensure_browser()
        context = await self._browser.new_context(ignore_https_errors=True, service_workers="block")
        log = self._logs.setdefault(engagement, RequestLog())

        async def on_route(route: Any, request: Any) -> None:
            allowed, reason = self._decide(engagement, request.url, request.method)
            if not allowed:
                self._drop(engagement, request.url, request.method, reason, request.resource_type)
                await route.abort("blockedbyclient")
                return
            log.add(
                url=request.url[:500],
                method=request.method,
                resource=request.resource_type,
                outcome="allowed",
            )
            await route.continue_()

        await context.route("**/*", on_route)
        if hasattr(context, "route_web_socket"):

            async def on_socket(socket: Any) -> None:
                allowed, reason = self._decide(engagement, socket.url, "GET")
                if allowed:
                    socket.connect_to_server()
                else:
                    self._drop(engagement, socket.url, "GET", reason, "websocket")
                    await socket.close()

            await context.route_web_socket("**/*", on_socket)
        page = await context.new_page()
        self._contexts[engagement] = context
        self._pages[engagement] = page
        return page

    async def close(self, engagement: str | None = None) -> None:
        names = [engagement] if engagement else list(self._contexts)
        for name in names:
            context = self._contexts.pop(name, None)
            self._pages.pop(name, None)
            if context is not None:
                try:
                    await context.close()
                except Exception:  # noqa: BLE001, S110 - already gone
                    pass
        if not self._contexts and self._browser is not None and engagement is None:
            await self._browser.close()
            await self._playwright.stop()
            self._browser = self._playwright = None

    # ── actions ─────────────────────────────────────────────────────

    async def open(self, engagement: str, url: str) -> dict[str, Any]:
        allowed, reason = self._decide(engagement, url, "GET")
        if not allowed:
            self._drop(engagement, url, "GET", reason, "navigation")
            raise BrowserError(f"{url!r} is not in the enforced scope ({reason}); not opened")
        async with self._lock:
            page = await self._page(engagement, create=True)
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:  # noqa: BLE001, S110 - a page that keeps polling is still usable
                pass
            return {
                "url": page.url,
                "status": response.status if response else None,
                "title": await page.title(),
                "blocked_requests": self.blocked(engagement)[-10:],
            }

    async def click(self, engagement: str, selector: str) -> dict[str, Any]:
        page = await self._page(engagement)
        await page.click(selector, timeout=10000)
        await asyncio.sleep(0.3)
        return {"url": page.url, "title": await page.title()}

    async def fill(self, engagement: str, selector: str, text: str) -> dict[str, Any]:
        page = await self._page(engagement)
        await page.fill(selector, text, timeout=10000)
        return {"filled": selector}

    async def evaluate(self, engagement: str, expression: str) -> dict[str, Any]:
        page = await self._page(engagement)
        value = await page.evaluate(expression)
        text = json.dumps(value, default=str)
        return {"result": text[:MAX_TEXT], "truncated": len(text) > MAX_TEXT}

    async def text(self, engagement: str) -> dict[str, Any]:
        page = await self._page(engagement)
        body = await page.inner_text("body")
        return {"url": page.url, "text": body[:MAX_TEXT], "truncated": len(body) > MAX_TEXT}

    async def html(self, engagement: str) -> dict[str, Any]:
        page = await self._page(engagement)
        content = await page.content()
        return {"url": page.url, "html": content[:MAX_TEXT], "truncated": len(content) > MAX_TEXT}

    async def screenshot(self, engagement: str) -> dict[str, Any]:
        page = await self._page(engagement)
        image = await page.screenshot(type="png", full_page=False)
        return {"url": page.url, "png_base64": base64.b64encode(image).decode("ascii")}

    async def cookies(self, engagement: str) -> dict[str, Any]:
        await self._page(engagement)
        cookies = await self._contexts[engagement].cookies()
        return {
            "cookies": [
                {
                    "name": c["name"],
                    "domain": c["domain"],
                    "path": c["path"],
                    "secure": c.get("secure"),
                    "httpOnly": c.get("httpOnly"),
                    "sameSite": c.get("sameSite"),
                    "value_length": len(c.get("value", "")),
                }
                for c in cookies
            ]
        }

    # ── proof recording (offline) ───────────────────────────────────

    def _proof_folder(self, engagement: str, finding_id: str, html: Any) -> Path:
        """The evidence folder a recording goes to, after every argument check."""
        if not isinstance(finding_id, str) or not PROOF_ID.fullmatch(finding_id):
            raise ProofError("BAD_FINDING_ID", "finding_id must look like F-<6 to 40 hex digits>")
        if not isinstance(html, str) or not html.strip():
            raise ProofError("BAD_HTML", "html is required: the proof page to record")
        size = len(html.encode("utf-8", "replace"))
        if size > MAX_PROOF_HTML:
            raise ProofError(
                "HTML_TOO_LARGE", f"the proof page is {size} bytes; at most {MAX_PROOF_HTML}"
            )
        try:
            self._scope(engagement)  # the same engagement guard and binding as browsing
        except BrowserError as exc:
            raise ProofError("BAD_ENGAGEMENT", str(exc)) from exc
        root = self._audit.resolve()
        folder = (self._audit / engagement / "evidence" / finding_id).resolve()
        if not folder.is_relative_to(root / engagement):
            raise ProofError("BAD_ENGAGEMENT", "the evidence folder is outside the audit root")
        return folder

    async def proof_record(self, engagement: str, finding_id: str, html: str) -> dict[str, Any]:
        """Record ``html`` (a proof page) as a video plus screenshots, with no network at all.

        The page is shown in a fresh context: JavaScript off, offline, every
        request aborted. Nothing is sent to the target; the page shows what the
        evidence gateway recorded. Files land in
        ``<audit>/<engagement>/evidence/<finding_id>/`` and replace earlier ones.
        """
        folder = self._proof_folder(engagement, finding_id, html)
        async with self._lock:
            await self._ensure_browser()
            with tempfile.TemporaryDirectory(prefix="buggy-proof-") as scratch:
                work = Path(scratch)
                result = await self._record(work, html)
                folder.mkdir(parents=True, exist_ok=True)
                for name in (PROOF_VIDEO, PROOF_SCREENSHOT, PROOF_FULL_SCREENSHOT):
                    staged = folder / f".{name}.part"
                    shutil.copyfile(work / name, staged)
                    staged.chmod(0o644)
                    staged.replace(folder / name)
        relative = f"evidence/{finding_id}"
        return {
            "ok": True,
            "video": f"{relative}/{PROOF_VIDEO}",
            "screenshot": f"{relative}/{PROOF_SCREENSHOT}",
            "full_screenshot": f"{relative}/{PROOF_FULL_SCREENSHOT}",
            "bytes": (folder / PROOF_VIDEO).stat().st_size,
            **result,
        }

    async def _record(self, work: Path, html: str) -> dict[str, Any]:
        blocked: list[str] = []
        context = await self._browser.new_context(
            viewport=dict(PROOF_VIEWPORT),
            record_video_dir=str(work / "video"),
            record_video_size=dict(PROOF_VIEWPORT),
            java_script_enabled=False,
            offline=True,
            service_workers="block",
            accept_downloads=False,
        )

        async def deny(route: Any, request: Any) -> None:
            blocked.append(str(request.url)[:200])
            await route.abort("blockedbyclient")

        video: Any = None
        started = time.monotonic()
        shown = 0
        try:
            await context.route("**/*", deny)
            if hasattr(context, "route_web_socket"):

                async def no_socket(socket: Any) -> None:
                    blocked.append(str(socket.url)[:200])
                    await socket.close()

                await context.route_web_socket("**/*", no_socket)
            page = await context.new_page()
            video = page.video
            started = time.monotonic()
            await page.set_content(html, wait_until="load", timeout=15000)
            await self._pause(PROOF_TITLE_SECONDS)
            for number in range(1, PROOF_MAX_STEPS + 1):
                section = page.locator(f"#step-{number}")
                if await section.count() == 0:
                    break
                await section.scroll_into_view_if_needed(timeout=5000)
                shown += 1
                await self._pause(PROOF_STEP_SECONDS)
            await self._pause(PROOF_END_SECONDS)
            first = page.locator("#step-1")
            if await first.count():
                await first.screenshot(path=str(work / PROOF_SCREENSHOT), timeout=10000)
            else:
                await page.screenshot(path=str(work / PROOF_SCREENSHOT), full_page=False)
            await page.screenshot(path=str(work / PROOF_FULL_SCREENSHOT), full_page=True)
        finally:
            await context.close()  # finalises the video
        seconds = round(time.monotonic() - started, 1)
        if video is None:
            raise ProofError("NO_VIDEO", "the browser did not record a video")
        await video.save_as(str(work / PROOF_VIDEO))
        return {"seconds": seconds, "steps_shown": shown, "blocked_requests": len(blocked)}

    def requests(self, engagement: str, limit: int = 50) -> list[dict[str, Any]]:
        return self._logs.get(engagement, RequestLog()).entries[-max(1, min(limit, MAX_LOG)) :]

    def blocked(self, engagement: str) -> list[dict[str, Any]]:
        return [
            e for e in self._logs.get(engagement, RequestLog()).entries if e["outcome"] == "blocked"
        ]


__all__ = ["BrowserError", "ProofError", "ScopedBrowser", "find_chromium"]
