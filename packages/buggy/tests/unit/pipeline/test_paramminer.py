"""The hidden-parameter miner, against fake pages (no network)."""

from __future__ import annotations

import itertools

from buggy.pipeline.tools import paramminer
from buggy.pipeline.tools.paramminer import Miner, snapshot

_clock = itertools.count()


def _page(location: str, pairs: dict[str, str]) -> paramminer.Snapshot:
    """A page with a timestamp line that changes on every request, plus hidden inputs."""
    lines = ["<html>", "<h1>Shop</h1>", f"<p>rendered at {next(_clock)}</p>"]
    headers = {"content-type": "text/html", "date": str(next(_clock))}
    status = 200
    if location == "query":
        if "debug" in pairs:
            lines.append("<pre>debug: on</pre>")
        if "q" in pairs:
            lines.append(f"<p>You searched for {pairs['q']}</p>")
        if "admin" in pairs and pairs["admin"] == "true":
            status = 403
    if location == "header" and "X-Forwarded-Host" in pairs:
        lines.append(f'<link href="//{pairs["X-Forwarded-Host"]}/app.css">')
    if location == "cookie" and "beta" in pairs:
        headers["x-beta"] = "1"
    return snapshot(status, headers, "\n".join(lines))


def _run(location: str, names: list[str], budget: int = 200) -> paramminer.Outcome:
    return Miner(_page, location, max_requests=budget).run(names)


def _found(outcome: paramminer.Outcome) -> dict[str, str]:
    return {f.name: f.reason for f in outcome.found}


FILLER = [f"name{i}" for i in range(300)]


def test_finds_a_hidden_query_parameter_and_ignores_the_noise() -> None:
    outcome = _run("query", [*FILLER[:150], "debug", *FILLER[150:]])
    assert _found(outcome) == {"debug": "body_changed"}
    assert outcome.requests < 40


def test_a_reflected_value_is_found_as_reflected() -> None:
    assert _found(_run("query", [*FILLER[:50], "q"])) == {"q": "reflected"}


def test_a_switch_name_is_tried_with_switch_values() -> None:
    found = _run("query", ["admin", *FILLER[:20]]).found
    assert [(f.name, f.reason, f.detail) for f in found] == [
        ("admin", "status_changed", "with the value 'true'")
    ]


def test_headers_and_cookies() -> None:
    assert _found(_run("header", ["X-Debug", "X-Forwarded-Host", "X-Original-URL"])) == {
        "X-Forwarded-Host": "reflected"
    }
    assert _found(_run("cookie", ["session_debug", "beta", "lang"])) == {"beta": "headers_changed"}


def test_nothing_found_on_a_plain_page() -> None:
    outcome = _run("query", FILLER)
    assert outcome.found == [] and outcome.skipped == ""


def test_the_budget_is_never_exceeded() -> None:
    outcome = _run("query", [*FILLER, "debug"], budget=5)
    assert outcome.requests == 5 and outcome.skipped == "request budget used up"


def test_a_page_that_reacts_to_any_name_gives_nothing() -> None:
    def echo_count(_location: str, pairs: dict[str, str]) -> paramminer.Snapshot:
        return snapshot(200, {}, "\n".join(f"<i>{n}</i>" for n in pairs))

    outcome = Miner(echo_count, "query", max_requests=500).run(FILLER[:200])
    assert outcome.found == []
    assert "reacts to any name" in outcome.skipped


def test_an_unstable_status_skips_the_page() -> None:
    statuses = itertools.cycle([200, 500])

    def flaky(_location: str, _pairs: dict[str, str]) -> paramminer.Snapshot:
        return snapshot(next(statuses), {}, "ok")

    outcome = Miner(flaky, "query", max_requests=50).run(["debug"])
    assert outcome.found == [] and outcome.skipped == "the status changes on its own"


def test_wordlists_and_harvest() -> None:
    harvested = paramminer.harvest(
        ["user[id]", "page"], ["data.email", "data.role"], ["https://a.test/api/orders/1"]
    )
    assert harvested[:2] == ["user", "page"]
    assert {"email", "role", "orders"} <= set(harvested)
    names = paramminer.wordlist("query", harvested, known=["page"])
    assert names[0] == "user" and "page" not in names and len(names) > 300
    headers = paramminer.wordlist("header", [])
    assert "X-Forwarded-Host" in headers
    assert not {n.lower() for n in headers} & paramminer.NEVER_SEND_HEADERS
    assert paramminer.curated("cookie")


def test_choose_endpoints() -> None:
    def never(url: str) -> str:
        return "logout" if "logout" in url else ""

    chosen = paramminer.choose_endpoints(
        "https://a.test",
        ["https://a.test/api/me?x=1"],
        [
            "https://a.test/logout",
            "https://a.test/app.js",
            "https://a.test/api/users/{id}",
            "https://a.test/api/users/:id",
            "https://b.test/other",
            "https://a.test/search",
            "https://a.test/a",
            "https://a.test/b",
        ],
        never=never,
    )
    assert chosen == [
        "https://a.test/api/me",
        "https://a.test/search",
        "https://a.test/a",
        "https://a.test/b",
    ]


# ── in the pipeline ─────────────────────────────────────────────────

import io  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402
from urllib.parse import parse_qs, urlsplit  # noqa: E402

import pytest  # noqa: E402

from buggy.pipeline.pipeline import PARAM_MAX_REQUESTS  # noqa: E402
from buggy.pipeline.report import rank_candidates  # noqa: E402
from buggy.pipeline.store import ReconStore  # noqa: E402

from .test_pipeline_flow import ROE, FakeOpener, FakeTools, _Body, _pipeline  # noqa: E402


class HiddenInputs(FakeOpener):
    """www.acme.test/ is a page with a hidden ``debug`` query name and an
    ``X-Forwarded-Host`` header it writes into a link, plus a line that changes
    on every request."""

    def __init__(self) -> None:
        super().__init__()
        self.ticks = 0

    def open(self, request, timeout=None) -> io.BytesIO:
        url = request.full_url
        parts = urlsplit(url)
        if parts.netloc != "www.acme.test" or parts.path != "/":
            return super().open(request, timeout)
        self.requested.append((request.get_method(), url))
        self.ticks += 1
        query = parse_qs(parts.query)
        headers = {k.lower(): v for k, v in request.header_items()}
        lines = ["<html>", "<h1>Acme</h1>", f"<p>served in {self.ticks} ms</p>"]
        if "debug" in query:
            lines.append("<pre>debug mode</pre>")
        if "x-forwarded-host" in headers:
            lines.append(f'<script src="//{headers["x-forwarded-host"]}/a.js"></script>')
        return _Body("\n".join(lines).encode())


@pytest.fixture
def env(tmp_path: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {
        "store": store,
        "root": tmp_path / "data",
        "tools": FakeTools(),
        "opener": HiddenInputs(),
    }
    store.close()


def _mined(env) -> dict[str, dict]:
    rows = env["store"].query_records("acme", record_type="parameter")
    return {r.value: r.attrs for r in rows if r.source_tool == paramminer.NAME}


class TestInThePipeline:
    def test_hidden_inputs_become_parameter_records(self, env) -> None:
        summary = _pipeline(env).run()
        mined = _mined(env)
        assert mined["GET https://www.acme.test/ query:debug"]["reason"] == "body_changed"
        header = mined["GET https://www.acme.test/ header:X-Forwarded-Host"]
        assert header["reason"] == "reflected" and header["hidden"] is True
        assert len(mined) == 2  # the changing line found nothing
        stage = summary["stages"]["paramguess"]
        assert 0 < stage["tools"][paramminer.NAME]["requests"] <= PARAM_MAX_REQUESTS
        # Only in-scope hosts were asked.
        hosts = {urlsplit(url).hostname for _m, url in env["opener"].requested}
        assert hosts <= {"www.acme.test", "api.acme.test"}
        assert {m for m, _url in env["opener"].requested if "zq" in _url} == {"GET"}

    def test_passive_and_disabled_runs_guess_nothing(self, env) -> None:
        roe = json.loads(json.dumps(ROE))
        roe["pipeline"]["disabled_stages"] = ["paramguess"]
        summary = _pipeline(env, roe).run()
        assert summary["stages"]["paramguess"]["skipped"] == "disabled by program rules"
        assert not any("zq" in url for _m, url in env["opener"].requested)
        assert _mined(env) == {}


def test_hidden_finds_become_leads() -> None:
    def row(name: str, location: str, reason: str) -> dict:
        url = "https://a.test/"
        return {
            "value": f"GET {url} {location}:{name}",
            "attrs": {"name": name, "location": location, "method": "GET", "url": url,
                      "hints": [], "hidden": True, "reason": reason},
        }  # fmt: skip

    leads = rank_candidates(
        {
            "parameter": [
                row("X-Forwarded-Host", "header", "reflected"),
                row("q", "query", "reflected"),
                row("debug", "query", "body_changed"),
            ]
        }
    )
    by_where = {c["where"]: (c["class"], c["probe"]) for c in leads}
    assert by_where["GET https://a.test/ header:X-Forwarded-Host"] == (
        "misconfiguration",
        "http_send",
    )
    assert by_where["GET https://a.test/ query:q"] == ("xss", "xss_reflected")
    assert by_where["GET https://a.test/ query:debug"] == ("misconfiguration", "http_send")


def test_finds_survive_a_budget_stop() -> None:
    # debug is in the first batch; the budget runs out in a later one.
    outcome = _run("query", ["debug", *FILLER[:95], *FILLER[100:300]], budget=20)
    assert outcome.skipped == "request budget used up"
    assert _found(outcome) == {"debug": "body_changed"}
