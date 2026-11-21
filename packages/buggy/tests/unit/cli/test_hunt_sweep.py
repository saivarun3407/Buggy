"""hunt runs the planned read-only probes, re-proves and grades what they find."""

from __future__ import annotations

import argparse
import json

import pytest

from buggy.cli import hunt

SEARCH = "https://app.test/search"
RECORDS = {
    "parameter": [
        {
            "type": "parameter",
            "attrs": {
                "name": "id",
                "location": "query",
                "method": "GET",
                "url": SEARCH,
                "example": "7",
                "hints": ["id-like", "numeric"],
            },
        }
    ],
    "http_service": [{"type": "http_service", "value": "https://app.test"}],
    "vulnerability": [
        {
            "type": "vulnerability",
            "value": "exposed-panel https://app.test/admin",
            "attrs": {
                "template_id": "exposed-panel",
                "severity": "info",
                "description": "x" * 5000,
            },
        }
    ],
}


class Server:
    """The capture server's tools as the sweep uses them."""

    def __init__(self, *, vulnerable: dict | None = None, verify: str = "exploit_verified") -> None:
        self.calls: list[tuple[str, dict]] = []
        self.vulnerable = vulnerable or {"sqli": True}
        self.verify = verify

    def __call__(self, tool: str, engagement: str, **arguments) -> dict:
        assert engagement == "acme"
        self.calls.append((tool, arguments))
        if tool == "probe_run":
            outcome = self.vulnerable.get(arguments["probe"], False)
            if isinstance(outcome, dict):
                return outcome
            result = {"status": "completed", "probe": arguments["probe"], "vulnerable": outcome}
            if outcome is True:
                result["finding_id"] = f"F-{arguments['probe']}"
            return result
        if tool == "finding_verify":
            return {"ok": True, "finding": {"id": arguments["finding_id"], "status": self.verify}}
        if tool == "finding_grade":
            return {"ok": True, "grade": {"decision": "submit"}}
        raise AssertionError(tool)

    def tools(self) -> list[str]:
        return [tool for tool, _arguments in self.calls]


@pytest.fixture
def server(monkeypatch) -> Server:
    fake = Server()
    monkeypatch.setattr(hunt, "_capture", fake)
    return fake


def test_a_positive_probe_is_verified_and_graded(server: Server) -> None:
    out = hunt.run_probe_sweep("acme", RECORDS)
    assert server.tools() == ["probe_run", "finding_verify", "finding_grade", "probe_run"]
    first = server.calls[0][1]
    assert first["probe"] == "sqli"
    assert json.loads(first["params_json"]) == {
        "url": f"{SEARCH}?id=7",
        "parameter": "id",
        "method": "GET",
        "location": "query",
    }
    assert out == {
        "planned": 2,
        "left_out": 0,
        "ran": 2,
        "vulnerable": 1,
        "not_vulnerable": 1,
        "undecided": 0,
        "refused": 0,
        "verified": 1,
        "submit": 1,
        "findings": [
            {
                "id": "F-sqli",
                "probe": "sqli",
                "url": f"{SEARCH}?id=7",
                "status": "exploit_verified",
                "grade": "submit",
            }
        ],
        "error": None,
    }


def test_the_grader_gets_the_scanner_records_slimmed(server: Server) -> None:
    hunt.run_probe_sweep("acme", RECORDS)
    (graded,) = [arguments for tool, arguments in server.calls if tool == "finding_grade"]
    assert json.loads(graded["known_issues_json"]) == [
        {
            "type": "vulnerability",
            "value": "exposed-panel https://app.test/admin",
            "attrs": {"template_id": "exposed-panel"},
        }
    ]


def test_a_positive_that_is_not_reproduced_is_not_graded(monkeypatch) -> None:
    fake = Server(verify="inconclusive")
    monkeypatch.setattr(hunt, "_capture", fake)
    out = hunt.run_probe_sweep("acme", RECORDS)
    assert "finding_grade" not in fake.tools()
    assert (out["vulnerable"], out["verified"], out["submit"]) == (1, 0, 0)
    assert out["findings"][0]["status"] == "inconclusive" and out["findings"][0]["grade"] == ""


def test_refusals_and_undecided_runs_are_counted_not_followed(monkeypatch) -> None:
    fake = Server(
        vulnerable={
            "sqli": {"status": "refused", "code": "OUT_OF_SCOPE", "probe": "sqli"},
            "cors": None,
        }
    )
    monkeypatch.setattr(hunt, "_capture", fake)
    out = hunt.run_probe_sweep("acme", RECORDS)
    assert fake.tools() == ["probe_run", "probe_run"]
    assert (out["ran"], out["refused"], out["undecided"], out["vulnerable"]) == (2, 1, 1, 0)


def test_the_sweep_stops_when_the_server_is_gone(monkeypatch) -> None:
    calls: list[str] = []

    def down(tool: str, _engagement: str, **_arguments) -> dict:
        calls.append(tool)
        return {"error": "capture server call failed: ConnectError"}

    monkeypatch.setattr(hunt, "_capture", down)
    records = {
        "parameter": [
            {
                "attrs": {
                    "name": f"p{n}",
                    "location": "query",
                    "method": "GET",
                    "url": SEARCH,
                    "example": "1",
                    "hints": ["id-like"],
                }
            }
            for n in range(10)
        ]
    }
    out = hunt.run_probe_sweep("acme", records)
    assert len(calls) == hunt.SWEEP_MAX_FAILURES and out["ran"] == 0
    assert "ConnectError" in out["error"]


def test_budget_is_passed_to_the_plan(server: Server) -> None:
    out = hunt.run_probe_sweep("acme", RECORDS, budget=1)
    assert (out["planned"], out["left_out"], out["ran"]) == (1, 1, 1)


class TestStage:
    def args(self, **overrides) -> argparse.Namespace:
        values = {"no_probes": False, "probe_budget": None, "non_interactive": False}
        return argparse.Namespace(**{**values, **overrides})

    def test_prints_one_summary_and_each_finding(self, server: Server, capsys) -> None:
        probes = hunt._sweep_stage(self.args(), "acme", RECORDS)  # noqa: SLF001
        assert probes is not None and probes["verified"] == 1
        err = capsys.readouterr().err
        assert "probe sweep      2 of 2 run, 1 positive, 1 re-proven, 1 graded submit" in err
        assert "F-sqli  sqli  exploit_verified/submit" in err

    @pytest.mark.parametrize("overrides", [{"no_probes": True}, {"probe_budget": 0}])
    def test_can_be_turned_off(self, server: Server, capsys, overrides: dict) -> None:
        assert hunt._sweep_stage(self.args(**overrides), "acme", RECORDS) is None  # noqa: SLF001
        assert server.calls == [] and "skipped" in capsys.readouterr().err

    def test_non_interactive_emits_one_event(self, server: Server, capsys) -> None:
        hunt._sweep_stage(self.args(non_interactive=True), "acme", RECORDS)  # noqa: SLF001
        event = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert event["type"] == "probe_sweep" and event["submit"] == 1


def test_result_file_section() -> None:
    assert hunt._probes_result(None) == {"ran_sweep": False}  # noqa: SLF001
    section = hunt._probes_result(  # noqa: SLF001
        {"planned": 3, "ran": 3, "vulnerable": 1, "verified": 1, "submit": 1, "findings": [1]}
    )
    assert section["ran_sweep"] is True and section["submit"] == 1 and "findings" not in section
    assert section["left_out"] == 0 and section["error"] is None
