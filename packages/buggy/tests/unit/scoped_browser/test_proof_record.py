"""proof_record: an offline recording of a proof page, with Playwright replaced by a fake.

The fake records how the context was opened and what was done with the page, so
the tests can check that the network is cut off, JavaScript is off, and the
files land in the finding's evidence folder. One opt-in test records a real
video with Chromium (``BUGGY_BROWSER_TEST=1``).
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from buggy.scoped_browser.mcp_server import TOOL_NAMES, register_tools
from buggy.scoped_browser.session import (
    MAX_PROOF_HTML,
    PROOF_MAX_STEPS,
    PROOF_VIEWPORT,
    ProofError,
    ScopedBrowser,
    find_chromium,
)

ENG = "acme"
FID = "F-0123456789ab"
EBML = b"\x1a\x45\xdf\xa3"
PNG = b"\x89PNG\r\n\x1a\n"


def page_html(steps: int) -> str:
    sections = "".join(
        f'<section id="step-{n}"><p>step {n}</p></section>' for n in range(1, steps + 1)
    )
    return f'<!DOCTYPE html><html><body><section id="title">t</section>{sections}</body></html>'


class FakeRoute:
    def __init__(self) -> None:
        self.aborted: str | None = None
        self.continued = False

    async def abort(self, reason: str = "failed") -> None:
        self.aborted = reason

    async def continue_(self) -> None:
        self.continued = True


class FakeRequest:
    def __init__(self, url: str) -> None:
        self.url = url
        self.method = "GET"
        self.resource_type = "image"


class FakeVideo:
    def __init__(self, context: FakeContext) -> None:
        self.context = context

    async def save_as(self, path: str) -> None:
        assert self.context.closed, "the video is only final once the context is closed"
        Path(path).write_bytes(EBML + b"fake webm")


class FakeLocator:
    def __init__(self, page: FakePage, selector: str) -> None:
        self.page = page
        self.selector = selector

    async def count(self) -> int:
        return int(f'id="{self.selector.lstrip("#")}"' in self.page.content)

    async def scroll_into_view_if_needed(self, timeout: float = 0) -> None:
        self.page.scrolled.append(self.selector)

    async def screenshot(self, path: str, timeout: float = 0) -> None:
        Path(path).write_bytes(PNG + self.selector.encode())


class FakePage:
    def __init__(self, context: FakeContext) -> None:
        self.context = context
        self.content = ""
        self.scrolled: list[str] = []
        self.video = FakeVideo(context)

    async def set_content(self, html: str, wait_until: str = "", timeout: float = 0) -> None:
        assert self.context.routes, "the network is cut off before the page is loaded"
        self.content = html
        # A page that tries to reach the target: every attempt goes through the route.
        for url in ("https://target.test/pixel.png", "http://127.0.0.1:9/x"):
            route = FakeRoute()
            await self.context.routes[0][1](route, FakeRequest(url))
            self.context.attempts.append((url, route))

    def locator(self, selector: str) -> FakeLocator:
        return FakeLocator(self, selector)

    async def screenshot(self, path: str, full_page: bool = False) -> None:
        Path(path).write_bytes(PNG + (b"full" if full_page else b"viewport"))


class FakeContext:
    def __init__(self, options: dict[str, Any]) -> None:
        self.options = options
        self.routes: list[tuple[str, Any]] = []
        self.socket_routes: list[str] = []
        self.attempts: list[tuple[str, FakeRoute]] = []
        self.pages: list[FakePage] = []
        self.closed = False

    async def route(self, pattern: str, handler: Any) -> None:
        self.routes.append((pattern, handler))

    async def route_web_socket(self, pattern: str, handler: Any) -> None:
        self.socket_routes.append(pattern)

    async def new_page(self) -> FakePage:
        page = FakePage(self)
        self.pages.append(page)
        return page

    async def close(self) -> None:
        self.closed = True


class FakeBrowser:
    def __init__(self) -> None:
        self.contexts: list[FakeContext] = []

    async def new_context(self, **options: Any) -> FakeContext:
        context = FakeContext(options)
        self.contexts.append(context)
        return context


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    control, audit = tmp_path / "control", tmp_path / "audit"
    (control / ENG).mkdir(parents=True)
    (control / ENG / "roe.json").write_text(
        json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}})
    )
    return control, audit


async def _no_pause(_seconds: float) -> None:
    return None


def fake_browser(roots: tuple[Path, Path]) -> tuple[ScopedBrowser, FakeBrowser]:
    browser = ScopedBrowser(*roots)
    fake = FakeBrowser()
    browser._browser = fake  # noqa: SLF001 - the fake stands in for a launched Chromium
    browser._pause = _no_pause  # noqa: SLF001
    return browser, fake


def record(browser: ScopedBrowser, html: str, *, engagement: str = ENG, fid: str = FID) -> dict:
    return asyncio.run(browser.proof_record(engagement, fid, html))


def test_files_land_in_the_findings_evidence_folder(roots) -> None:
    browser, _fake = fake_browser(roots)
    result = record(browser, page_html(3))
    folder = roots[1] / ENG / "evidence" / FID
    assert result["ok"] is True
    assert result["video"] == f"evidence/{FID}/proof.webm"
    assert result["screenshot"] == f"evidence/{FID}/proof.png"
    assert result["steps_shown"] == 3
    assert (folder / "proof.webm").read_bytes().startswith(EBML)
    assert result["bytes"] == (folder / "proof.webm").stat().st_size
    assert (folder / "proof.png").read_bytes() == PNG + b"#step-1"  # the first proof step
    assert (folder / "proof-full.png").read_bytes() == PNG + b"full"
    for name in ("proof.webm", "proof.png", "proof-full.png"):
        assert stat.S_IMODE((folder / name).stat().st_mode) == 0o644
    assert sorted(p.name for p in folder.iterdir()) == ["proof-full.png", "proof.png", "proof.webm"]
    assert isinstance(result["seconds"], float)


def test_the_context_has_no_network_and_no_javascript(roots) -> None:
    browser, fake = fake_browser(roots)
    record(browser, page_html(1))
    (context,) = fake.contexts
    options = context.options
    assert options["java_script_enabled"] is False
    assert options["offline"] is True
    assert options["viewport"] == PROOF_VIEWPORT and options["record_video_size"] == PROOF_VIEWPORT
    assert options["record_video_dir"]
    assert [pattern for pattern, _h in context.routes] == ["**/*"]
    assert context.socket_routes == ["**/*"]
    assert context.attempts and all(
        route.aborted and not route.continued for _u, route in context.attempts
    )
    assert context.closed


def test_a_fresh_context_each_time_and_a_rerun_overwrites(roots) -> None:
    browser, fake = fake_browser(roots)
    record(browser, page_html(1))
    record(browser, page_html(2))
    assert len(fake.contexts) == 2 and all(c.closed for c in fake.contexts)
    assert len(list((roots[1] / ENG / "evidence" / FID).iterdir())) == 3


def test_at_most_eight_steps_are_scrolled_through(roots) -> None:
    browser, fake = fake_browser(roots)
    result = record(browser, page_html(12))
    assert result["steps_shown"] == PROOF_MAX_STEPS
    assert fake.contexts[0].pages[0].scrolled == [f"#step-{n}" for n in range(1, 9)]


@pytest.mark.parametrize(
    "fid",
    [
        "",
        "F-12345",
        "F-XYZ123",
        "../F-0123456789ab",
        "F-0123456789ab/../../x",
        "F-" + "a" * 41,
        "f-0123456789ab",
    ],
)
def test_bad_finding_ids_are_refused(roots, fid: str) -> None:
    browser, fake = fake_browser(roots)
    with pytest.raises(ProofError) as refused:
        record(browser, page_html(1), fid=fid)
    assert refused.value.code == "BAD_FINDING_ID"
    assert fake.contexts == [] and not (roots[1] / ENG).exists()


@pytest.mark.parametrize("engagement", ["", "../acme", "acme/../x", ".hidden", "nope"])
def test_bad_or_unknown_engagements_are_refused(roots, engagement: str) -> None:
    browser, fake = fake_browser(roots)
    with pytest.raises(ProofError) as refused:
        record(browser, page_html(1), engagement=engagement)
    assert refused.value.code == "BAD_ENGAGEMENT"
    assert fake.contexts == []


def test_oversized_or_empty_html_is_refused(roots) -> None:
    browser, fake = fake_browser(roots)
    with pytest.raises(ProofError) as refused:
        record(browser, "x" * (MAX_PROOF_HTML + 1))
    assert refused.value.code == "HTML_TOO_LARGE"
    with pytest.raises(ProofError) as empty:
        record(browser, "  ")
    assert empty.value.code == "BAD_HTML"
    assert fake.contexts == []


def test_the_mcp_tool_is_registered_and_returns_structured_errors(roots) -> None:
    tools: dict[str, Any] = {}

    class FakeMCP:
        def tool(self):
            def register(fn):
                tools[fn.__name__] = fn
                return fn

            return register

    browser, _fake = fake_browser(roots)
    register_tools(FakeMCP(), browser)
    assert "proof_record" in tools and "proof_record" in TOOL_NAMES
    assert set(tools) == set(TOOL_NAMES)
    refused = asyncio.run(tools["proof_record"](ENG, "F-../../etc", page_html(1)))
    assert refused == {"ok": False, "error": "BAD_FINDING_ID", "detail": refused["detail"]}
    done = asyncio.run(tools["proof_record"](ENG, FID, page_html(1)))
    assert done["ok"] is True and done["video"] == f"evidence/{FID}/proof.webm"


# ── opt-in: a real Chromium recording ───────────────────────────────


@pytest.mark.skipif(os.environ.get("BUGGY_BROWSER_TEST") != "1", reason="set BUGGY_BROWSER_TEST=1")
def test_a_real_recording_is_a_webm(roots) -> None:
    pytest.importorskip("playwright")
    if find_chromium() is None:
        pytest.skip("no Chromium build available for Playwright")
    from buggy.findings.proof_page import proof_html  # noqa: PLC0415

    entry = {
        "id": FID,
        "title": "Reflected XSS",
        "severity": "high",
        "class": "xss",
        "endpoint": "https://app.acme.test/q",
        "parameter": "q",
        "reproduction": [
            {
                "number": n,
                "capture_id": f"cap-{n}",
                "shows": "Expect: status is 200.",
                "payload": "<img src=https://target.test/x.png>",
                "request": {"method": "GET", "url": "https://app.acme.test/q", "headers": {}},
                "response": {"status": 200, "body": "<img src=https://target.test/x.png>"},
            }
            for n in (1, 2)
        ],
    }
    browser = ScopedBrowser(*roots)

    async def run() -> dict[str, Any]:
        try:
            return await browser.proof_record(
                ENG, FID, proof_html(entry, engagement=ENG, generated_at="now")
            )
        finally:
            await browser.close()

    result = asyncio.run(run())
    video = roots[1] / ENG / "evidence" / FID / "proof.webm"
    assert result["ok"] is True and result["seconds"] < 30
    assert video.stat().st_size > 0 and video.read_bytes()[:4] == EBML
    assert (roots[1] / ENG / "evidence" / FID / "proof.png").read_bytes().startswith(PNG)
