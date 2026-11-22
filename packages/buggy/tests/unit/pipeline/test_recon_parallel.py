"""Recon runs independent tools at the same time, and never above the program's rate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.pipeline.http import RateLimiter
from buggy.pipeline.report import render_report
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools.katana import Katana
from buggy.pipeline.tools.params import extract

from .test_pipeline_flow import ROE, FakeOpener, FakeTools, _pipeline


@pytest.fixture
def env(tmp_path: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {"store": store, "root": tmp_path / "data", "tools": FakeTools(), "opener": FakeOpener()}
    store.close()


def _roe(**pipeline) -> dict:
    roe = json.loads(json.dumps(ROE))
    roe["pipeline"].update(pipeline)
    return roe


def _rate(env, tool: str) -> int:
    argv = next(a for name, _i, a in env["tools"].calls if name == tool)
    return int(argv[argv.index("-rl") + 1])


class TestEarlyIssueScan:
    def test_it_is_not_started_when_the_stage_is_disabled(self, env) -> None:
        _pipeline(env, _roe(disabled_stages=["issues"])).run()
        names = [name for name, _i, _a in env["tools"].calls]
        assert "nuclei" not in names and _rate(env, "katana") == 10

    def test_a_rate_of_one_is_not_split(self, env) -> None:
        roe = _roe()
        roe["machine_enforcement"]["min_inter_request_delay_ms"] = 1000  # 1 rps
        _pipeline(env, roe).run()
        assert _rate(env, "katana") == 1 and _rate(env, "nuclei") == 1
        names = [name for name, _i, _a in env["tools"].calls]
        assert names.index("nuclei") > names.index("katana")  # ran after, in its own stage

    def test_its_result_is_stored_by_the_issues_stage(self, env) -> None:
        summary = _pipeline(env).run()
        assert summary["stages"]["issues"]["tools"]["nuclei"]["exit_code"] == 0
        assert env["store"].count_records("acme")["vulnerability"] == 1
        assert list(summary["stages"])[-1] == "issues"


class TestRateLimiter:
    def test_the_rate_can_change_while_running(self) -> None:
        clock = [0.0]
        slept: list[float] = []
        limiter = RateLimiter(10, clock=lambda: clock[0], sleep=slept.append)
        limiter.wait()
        limiter.set_rate(5)
        limiter.wait()  # the slot after the first was booked at 10 rps
        limiter.wait()
        assert slept == [pytest.approx(0.1), pytest.approx(0.3)]


class TestInputs:
    def test_katana_forms_become_form_inputs(self) -> None:
        line = {
            "request": {"method": "GET", "endpoint": "http://dvwa.lab/login.php"},
            "response": {
                "status_code": 200,
                "forms": [
                    {
                        "method": "POST",
                        "action": "http://dvwa.lab/login.php",
                        "parameters": ["username", "password", "Login", "user_token"],
                    }
                ],
            },
        }
        (record,) = list(Katana().parse(json.dumps(line)))
        assert record.attrs["form"][0]["method"] == "POST"
        names = {r.value for r in extract([record])}
        assert "POST http://dvwa.lab/login.php form:username" in names
        assert "POST http://dvwa.lab/login.php form:user_token" in names

    def test_the_report_lists_where_values_can_be_put(self) -> None:
        def param(location: str, name: str) -> dict:
            return {
                "type": "parameter",
                "value": f"GET http://h/p {location}:{name}",
                "attrs": {"location": location, "name": name, "method": "GET", "url": "http://h/p"},
            }

        text = render_report(
            "acme",
            {"records": {"parameter": 3}},
            {"parameter": [param("form", "q"), param("query", "id"), param("form", "name")]},
        )
        assert "## Inputs" in text and "3 place(s)" in text
        assert "| form fields | 2 |" in text and "| query string | 1 |" in text
