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
        if tool == "finding_get":  # sibling leads of a proven finding (hunt.queue_siblings)
            finding = {"id": arguments["finding_id"], "status": self.verify, "class": "injection"}
            return {"ok": True, "finding": {**finding, "endpoint": SEARCH, "parameter": "id"}}
        if tool == "candidates_add":
            return {"ok": True, "created": len(json.loads(arguments["items_json"])["ranked"])}
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
        "held_for_approval": 0,
        "verified": 1,
        "submit": 1,
        "ruled_out": 0,
        "failed_attempts": 0,
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
        "by_class": {
            "injection": {"checks": 1, "held": 0, "positive": 1, "proven": 1},
            "misconfiguration": {"checks": 1, "held": 0, "positive": 0, "proven": 0},
        },
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
    assert out["held_for_approval"] == 0


def test_what_the_server_ruled_out_is_counted(monkeypatch) -> None:
    ruled = {"kind": "ruled_out", "reason": "not_vulnerable", "id": "L-1"}
    attempt = {"kind": "attempt", "reason": "delivery_failed", "id": "L-2"}
    fake = Server(
        vulnerable={
            "sqli": {"status": "completed", "vulnerable": False, "ledger": ruled},
            "cors": {"status": "completed", "vulnerable": None, "ledger": attempt},
        }
    )
    monkeypatch.setattr(hunt, "_capture", fake)
    out = hunt.run_probe_sweep("acme", RECORDS)
    assert (out["ruled_out"], out["failed_attempts"]) == (1, 1)


def test_a_read_only_check_sent_with_post_is_reported_as_waiting(monkeypatch, capsys) -> None:
    held = {"status": "refused", "code": "APPROVAL_REQUIRED", "request_id": "apr-1"}
    fake = Server(vulnerable={"sqli": False, "cors": held})
    monkeypatch.setattr(hunt, "_capture", fake)
    args = argparse.Namespace(
        no_probes=False, probe_budget=None, state_probe_budget=0, non_interactive=False
    )
    probes, _state = hunt._class_stage(args, "acme", RECORDS, None)  # noqa: SLF001
    assert probes is not None
    assert (probes["refused"], probes["held_for_approval"]) == (1, 1)
    assert "1 waiting for your approval (buggy-cli approvals list acme)" in capsys.readouterr().err


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
        values = {
            "no_probes": False,
            "probe_budget": None,
            "state_probe_budget": 0,
            "non_interactive": False,
        }
        return argparse.Namespace(**{**values, **overrides})

    def test_prints_one_summary_and_each_finding(self, server: Server, capsys) -> None:
        probes, _state = hunt._class_stage(self.args(), "acme", RECORDS, None)  # noqa: SLF001
        assert probes is not None and probes["verified"] == 1
        err = capsys.readouterr().err
        assert "logged out       2 of 2 run, 1 positive, 1 re-proven, 1 graded submit" in err
        assert "F-sqli  sqli  exploit_verified/submit" in err

    @pytest.mark.parametrize("overrides", [{"no_probes": True}, {"probe_budget": 0}])
    def test_can_be_turned_off(self, server: Server, capsys, overrides: dict) -> None:
        probes, _state = hunt._class_stage(self.args(**overrides), "acme", RECORDS, None)  # noqa: SLF001
        assert probes is None
        assert server.calls == [] and "skipped" in capsys.readouterr().err

    def test_non_interactive_emits_one_event(self, server: Server, capsys) -> None:
        hunt._class_stage(self.args(non_interactive=True), "acme", RECORDS, None)  # noqa: SLF001
        events = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
        (event,) = [e for e in events if e["type"] == "probe_sweep"]
        assert event["type"] == "probe_sweep" and event["submit"] == 1


def test_result_file_section() -> None:
    assert hunt._probes_result(None) == {"ran_sweep": False}  # noqa: SLF001
    section = hunt._probes_result(  # noqa: SLF001
        {"planned": 3, "ran": 3, "vulnerable": 1, "verified": 1, "submit": 1, "findings": [1]}
    )
    assert section["ran_sweep"] is True and section["submit"] == 1 and "findings" not in section
    assert section["left_out"] == 0 and section["error"] is None


def test_agents_are_told_what_the_sweep_already_covered() -> None:
    scope = {"targets": ["https://app.test"], "enforcement_extra": {"sandbox_egress": "blocked"}}
    plain = hunt.kickoff_text("acme", scope, recon_done=True, instruction="")
    assert "probe sweep" not in plain
    told = hunt.kickoff_text(
        "acme", scope, recon_done=True, instruction="", probes={"ran": 12, "verified": 2}
    )
    assert "A read-only probe sweep already ran (12 runs" in told and "2 findings re-proven" in told
    skipped = hunt.kickoff_text(
        "acme", scope, recon_done=True, instruction="", probes={"ran": 0, "verified": 0}
    )
    assert skipped == plain


class TestByClass:
    """Every planned run is sent one bug class at a time, in the owner's order."""

    def test_classes_run_in_order_across_logged_out_signed_in_and_writes(self, monkeypatch) -> None:
        sent: list[tuple[str, str]] = []

        def server(tool: str, _engagement: str, **arguments) -> dict:
            if tool == "probe_run":
                params = json.loads(arguments["params_json"])
                sent.append((arguments["probe"], params.get("identity", "")))
                return {"status": "ok", "vulnerable": False}
            return {}

        monkeypatch.setattr(hunt, "_capture", server)

        def plan(*steps: tuple[str, str]) -> dict:
            return {
                "steps": [
                    {"probe": probe, "params": {"url": "https://a.test/x", "identity": who}}
                    for probe, who in steps
                ],
                "left_out": 0,
            }

        logged_out, as_alice, writes = (
            hunt._empty_counts(),
            hunt._empty_counts(),
            hunt._empty_counts(),
        )  # noqa: SLF001
        rows = hunt.run_by_class(
            "acme",
            [
                ("logged out", plan(("xss_reflected", ""), ("sqli", ""), ("cors", "")), logged_out),
                ("as alice", plan(("sqli", "alice"), ("idor", "alice")), as_alice),
                ("writes", plan(("csrf", "alice"), ("xss_stored", "alice")), writes),
            ],
            "[]",
        )
        assert [probe for probe, _who in sent] == [
            "idor", "sqli", "sqli", "xss_reflected", "xss_stored", "cors", "csrf",
        ]  # fmt: skip
        assert [row["class"] for row in rows] == [
            "access_control", "injection", "xss", "misconfiguration", "csrf",
        ]  # fmt: skip
        assert (logged_out["ran"], as_alice["ran"], writes["ran"]) == (3, 2, 2)

    def test_it_stops_when_the_server_is_gone(self, monkeypatch) -> None:
        monkeypatch.setattr(
            hunt, "_capture", lambda *_a, **_k: {"error": "capture server call failed"}
        )
        steps = [{"probe": "sqli", "params": {"url": f"https://a.test/{i}"}} for i in range(6)]
        steps += [{"probe": "xss_reflected", "params": {"url": "https://a.test/x"}}]
        counts = hunt._empty_counts()  # noqa: SLF001
        rows = hunt.run_by_class(
            "acme", [("logged out", {"steps": steps, "left_out": 0}, counts)], "[]"
        )
        assert [row["class"] for row in rows] == ["injection"] and counts["error"]


def test_proven_findings_seed_sibling_leads(monkeypatch) -> None:
    calls: list[tuple[str, dict]] = []
    finding = {
        "id": "F-idor",
        "status": "exploit_verified",
        "class": "access_control",
        "title": "IDOR on /api/Users/{id}",
        "endpoint": "https://app.test/api/Users/{id}",
        "parameter": "",
        "source": "probe:idor",
    }

    def fake(tool: str, engagement: str, **arguments) -> dict:
        assert engagement == "acme"
        calls.append((tool, arguments))
        if tool == "finding_get":
            return {"ok": True, "finding": finding}
        if tool == "candidates_add":
            return {"ok": True, "created": len(json.loads(arguments["items_json"])["ranked"])}
        raise AssertionError(tool)

    monkeypatch.setattr(hunt, "_capture", fake)
    records = {"endpoint": [{"value": "https://app.test/api/Cards/{id}", "attrs": {}}]}
    out = hunt.queue_siblings("acme", records, [{"id": "F-idor", "status": "exploit_verified"}])
    assert out == {"ok": True, "created": 1, "rows": 1}
    ranked = json.loads(calls[-1][1]["items_json"])["ranked"]
    assert ranked[0]["where"] == "https://app.test/api/Cards/{id}" and "F-idor" in ranked[0]["why"]
    assert calls[-1][1]["actor"] == "siblings"
    calls.clear()
    assert hunt.queue_siblings("acme", {}, [{"id": "F-idor"}]) == {"rows": 0}
    assert [tool for tool, _a in calls] == ["finding_get"]
