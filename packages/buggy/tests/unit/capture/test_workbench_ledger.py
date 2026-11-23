"""The capture server keeps the ruled-out ledger: probes, verifier and grader write it,
agents read it, the queue honours it, and the operator reviews it from the CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.capture import workbench as workbench_module
from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.mcp_server import CaptureTools
from buggy.capture.workbench import WORKBENCH_TOOL_NAMES, Workbench
from buggy.cli import findings as findings_cli
from buggy.findings.ruled_out import DAY
from buggy.tools import stack_mcp

from .test_gateway import Site, _roe

URL = "https://app.acme.test/search"


@pytest.fixture
def bench(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    roots = Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        json.dumps(_roe(approvals={"state_changing": "not_required"}))
    )
    site = Site()
    state = {"vulnerable": False, "answer": (200, b"ok"), "remediation": "Use bound parameters."}

    def answer(_headers, _body):
        if isinstance(state["answer"], Exception):
            raise state["answer"]
        return state["answer"]

    site.routes[("GET", URL)] = answer
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    tools = CaptureTools(gateway, None, "acme")
    monkeypatch.setenv("BUGGY_REVIEW_DAYS", "10")
    wb = Workbench(gateway, None, tools._engagement)  # noqa: SLF001
    tools.workbench = wb

    def fake_probe(gw, engagement, name, params, *, canary=None):  # noqa: ARG001
        capture = gw.send(engagement, "GET", params["url"], probe=name)
        return {
            "status": "completed",
            "probe": name,
            "class": "injection",
            "cwe": "CWE-89",
            "vulnerable": state["vulnerable"],
            "summary": "the conditions differ" if state["vulnerable"] else "no difference",
            "evidence_capture_ids": [capture.id],
            "details": {"method": "GET"},
            "remediation": state["remediation"],
        }

    monkeypatch.setattr(workbench_module, "run_probe", fake_probe)
    monkeypatch.setattr("buggy.capture.mcp_server.run_probe", fake_probe)
    yield tools, wb, state, roots
    wb.close()
    gateway.store.close()


def _run(tools: CaptureTools, parameter: str = "q") -> dict:
    return tools.probe_run("acme", "sqli", json.dumps({"url": URL, "parameter": parameter}))


def _lead(wb: Workbench) -> str:
    leads = {"ranked": [{"class": "injection", "where": URL, "probe": "sqli", "why": "a query"}]}
    return wb.candidates_add("acme", json.dumps(leads), "recon")["ids"][0]


class TestTheWorkbenchWritesAndHonoursTheLedger:
    def test_a_negative_probe_is_ruled_out_and_its_lead_is_not_handed_out(self, bench) -> None:
        tools, wb, _state, _roots = bench
        lead = _lead(wb)
        assert [c["id"] for c in wb.candidates_next("acme", "hunter")["candidates"]] == [lead]

        result = _run(tools)
        assert result["ledger"]["reason"] == "not_vulnerable"
        assert result["ledger"]["retires_technique"] is True

        listed = wb.leads_ruled_out("acme")
        assert [(r["technique"], r["parameter"]) for r in listed["ruled_out"]] == [
            ("probe:sqli", "q")
        ]
        assert listed["ruled_out"][0]["review_at"] == pytest.approx(
            listed["ruled_out"][0]["at"] + 10 * DAY
        )
        queue = wb.candidates_next("acme", "hunter")
        assert queue["candidates"] == [] and queue["ruled_out_skipped"] == 1

    def test_a_timeout_retires_nothing(self, bench) -> None:
        tools, wb, state, _roots = bench
        lead = _lead(wb)
        state["answer"] = TimeoutError("timed out")
        result = _run(tools)
        assert result["ledger"] == {
            "id": result["ledger"]["id"],
            "kind": "attempt",
            "reason": "delivery_failed",
            "retires_technique": False,
        }
        assert wb.leads_ruled_out("acme")["failed_attempts_total"] == 1
        assert [c["id"] for c in wb.candidates_next("acme", "hunter")["candidates"]] == [lead]

    def test_verifier_and_grader_record_why_a_finding_was_dropped(self, bench) -> None:
        tools, wb, state, _roots = bench
        state["vulnerable"] = True
        finding_id = _run(tools)["finding_id"]
        state["vulnerable"] = False  # fixed before it could be re-proven
        assert wb.finding_verify("acme", finding_id)["finding"]["status"] == "inconclusive"
        entries = wb.leads_ruled_out("acme")["ruled_out"]
        assert [(e["reason"], e["technique"], e["finding_id"]) for e in entries] == [
            ("inconclusive", "probe:sqli", finding_id)
        ]
        assert "no longer reports" in entries[0]["why"]

        # Proven after all: the inconclusive ruling no longer holds; graded hold for review.
        state["vulnerable"] = True
        state["remediation"] = ""
        _run(tools)
        assert wb.finding_verify("acme", finding_id)["finding"]["status"] == "exploit_verified"
        assert wb.leads_ruled_out("acme")["ruled_out"] == []
        graded = wb.finding_grade("acme", finding_id)
        assert graded["grade"]["decision"] == "hold"
        assert wb.findings_due("acme")["count"] == 0
        held = wb.findings.store.ledger("acme", kinds=("held",))
        assert held[0]["reason"] == "graded_hold" and held[0]["code"].startswith("rule ")

    def test_agent_claims_need_an_invariant_for_access_control(self, bench) -> None:
        tools, wb, _state, _roots = bench
        capture = tools.http_send("acme", "GET", URL)
        claim = {
            "title": "Search answers anyone",
            "class": "access_control",
            "severity": "low",
            "endpoint": URL,
            "source": "agent:hunter",
            "assertions": [{"capture_id": capture["capture_id"], "expect": {"status": 200}}],
        }
        refused = wb.finding_submit("acme", json.dumps(claim), "hunter")
        assert refused["code"] == "INVALID_FINDING"
        named = {**claim, "invariant": "only members can search", "entry_point": f"GET {URL}"}
        assert wb.finding_submit("acme", json.dumps(named), "hunter")["ok"]

    def test_chains_and_due_reach_the_report(self, bench) -> None:
        tools, wb, state, _roots = bench
        state["vulnerable"] = True
        finding_id = _run(tools)["finding_id"]
        wb.finding_verify("acme", finding_id)
        out = wb.findings_chains("acme")
        assert out["ok"] and [n["id"] for n in out["nodes"]] == [finding_id]
        assert out["nodes"][0]["gives"] == ["database_read"]
        built = json.loads(wb.report_build("acme", "json")["report"])
        assert {"chains", "open_needs", "due_for_review"} <= set(built)
        assert built["findings"][0]["invariant"]

    def test_the_new_tools_are_registered_and_wrapped(self) -> None:
        assert {"leads_ruled_out", "findings_chains", "findings_due"} <= set(WORKBENCH_TOOL_NAMES)
        names = {t.name for t in stack_mcp.ALL_STACK_MCP_TOOLS}
        assert {"leads_ruled_out", "findings_chains"} <= names


class TestTheOperatorCommand:
    def test_due_extend_close_and_reopen(self, bench, monkeypatch, capsys) -> None:
        tools, wb, _state, roots = bench
        _lead(wb)
        entry_id = _run(tools)["ledger"]["id"]
        for name, path in (
            ("BUGGY_CONTROL_ROOT", roots.control),
            ("BUGGY_AUDIT_ROOT", roots.audit),
            ("BUGGY_CAPTURE_DATA", roots.data),
            ("BUGGY_SECRETS_ROOT", roots.secrets),
        ):
            monkeypatch.setenv(name, str(path))

        assert findings_cli.main(["due", "acme"]) == 0
        assert "nothing is due" in capsys.readouterr().out

        # Once its review date has passed the ruling is due and the lead is back in the queue.
        store = wb.findings.store
        store.ledger_set_state("acme", entry_id, actor="test", review_at=store.now() - 1)
        assert findings_cli.main(["due", "acme", "--json"]) == 0
        due = json.loads(capsys.readouterr().out)["due"]
        assert [d["id"] for d in due] == [entry_id]
        assert len(wb.candidates_next("acme", "hunter")["candidates"]) == 1
        assert wb.findings_due("acme")["count"] == 1

        assert findings_cli.main(["close", "acme", entry_id]) == 2  # a close needs a note
        assert findings_cli.main(["extend", "acme", "L-999"]) == 2
        assert findings_cli.main(["extend", "acme", entry_id, "--days", "5"]) == 0
        capsys.readouterr()
        assert findings_cli.main(["due", "acme"]) == 0
        assert "nothing is due" in capsys.readouterr().out
        assert findings_cli.main(["close", "acme", entry_id, "--note", "tested by hand"]) == 0
        assert "[closed]" in capsys.readouterr().out
        assert findings_cli.main(["reopen", "acme", entry_id]) == 0
        assert "[reopened]" in capsys.readouterr().out
        assert findings_cli.main(["ruled-out", "acme"]) == 0
        assert "ruled out (0)" in capsys.readouterr().out
