"""Program rules on the path a finding and a report actually take."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from buggy.cli import approvals as approvals_cli
from buggy.tools.reporting import tools as reporting
from buggy.tools.reporting.tools import gateway_verifier, record_finding, report_hackerone
from buggy_core.types.kg import KnowledgeGraph, Node, NodeKind

ENGAGEMENT = "h1-acme"
TARGET = "https://app.acme-bounty.example/api/orders/1002"


@pytest.fixture
def program(tmp_path: Path, monkeypatch) -> dict[str, Path]:
    roots = {"control": tmp_path / "control", "audit": tmp_path / "audit"}
    (roots["control"] / ENGAGEMENT).mkdir(parents=True)
    roots["audit"].mkdir()
    (roots["control"] / ENGAGEMENT / "program.json").write_text(
        json.dumps({"platform": "hackerone", "handle": "acme", "excluded_classes": ["Self-XSS"]})
    )
    monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(roots["control"]))
    monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(roots["audit"]))
    monkeypatch.setenv("BUGGY_CORROBORATION_REQUIRED", "0")
    return roots


def _finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": "IDOR on order lookup",
        "severity": "high",
        "poc_script_code": "GET /api/orders/1002 as account B",
        "poc_description": "Log in as B, request A's order id, receive A's order.",
        "evidence": "200 with account A's email in the body",
        "http_exchange_ids": None,
        "cvss_vector": "",
        "target": TARGET,
        "summary": "",
        "vuln_class": "idor",
        "sink_demonstrated": "",
        "capture_ids": ["cap-1"],
        "remediation": "Authorise the order lookup against the session's account on the server.",
    }
    return {**base, **overrides}


def _record(finding: dict[str, Any], *, engagement: str, verifier=None) -> tuple[dict, dict]:
    published: dict[str, Any] = {}

    def _publish(_engagement: str, fields: dict[str, Any], **_kw: Any) -> tuple[str, bool]:
        published.update(fields)
        return ("node-1", True)

    with (
        patch("buggy.tools.reporting.tools.publish_finding_node", side_effect=_publish),
        patch("buggy.tools.reporting.tools.persist_candidate_node", return_value=("cand-1", True)),
        patch("buggy.tools.reporting.tools.get_active_engagement", return_value=engagement),
    ):
        payload = record_finding(finding, strict=True, client=None, program_verifier=verifier)
    return payload, published


def _ok(_capture_id: str, _target: str) -> dict[str, Any]:
    return {"valid": True, "method": "GET", "reproduced": True}


class TestRecordingAFindingOnAProgram:
    def test_verified_capture_plus_remediation_is_published(self, program) -> None:
        payload, published = _record(_finding(), engagement=ENGAGEMENT, verifier=_ok)
        assert payload["success"] is True and payload["live_verified"] is True
        assert published["capture_ids"] == ["cap-1"]
        assert published["remediation"].startswith("Authorise the order lookup")

    def test_no_capture_no_finding(self, program) -> None:
        payload, published = _record(
            _finding(capture_ids=None), engagement=ENGAGEMENT, verifier=_ok
        )
        assert payload == {
            "success": False,
            "error": "Program rules not met",
            "errors": [
                "capture_ids is required: cite at least one request sent through the evidence "
                "gateway (http_send / probe_run) that demonstrates the issue"
            ],
        }
        assert published == {}

    def test_no_remediation_no_finding(self, program) -> None:
        payload, published = _record(_finding(remediation=""), engagement=ENGAGEMENT, verifier=_ok)
        assert payload["error"] == "Program rules not met" and published == {}

    def test_a_capture_the_gateway_rejects_blocks_the_finding(self, program) -> None:
        def bad(_capture_id: str, _target: str) -> dict[str, Any]:
            return {"valid": False, "reason": "capture target is not in the enforced scope"}

        payload, published = _record(_finding(), engagement=ENGAGEMENT, verifier=bad)
        assert payload["errors"] == ["capture cap-1: capture target is not in the enforced scope"]
        assert published == {}

    def test_the_other_proof_requirements_still_apply(self, program) -> None:
        payload, published = _record(
            _finding(poc_script_code="", evidence=""), engagement=ENGAGEMENT, verifier=_ok
        )
        assert payload["error"] == "Validation failed" and payload["errors"]
        assert published == {}

    def test_an_engagement_that_is_not_a_program_is_unchanged(self, program) -> None:
        payload, _published = _record(_finding(), engagement="internal-lab", verifier=_ok)
        # Off-program the original gate applies: a live proxy id is required.
        assert payload["error"] == "Validation failed"
        assert any("http_exchange_ids is REQUIRED" in e for e in payload["errors"])


class TestGatewayVerifier:
    def _verify(self, responses: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
        calls: list[str] = []

        def fake(server: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
            assert server == "capture" and arguments["engagement"] == ENGAGEMENT
            calls.append(tool)
            return responses[tool]

        with patch("buggy.tools.reporting.tools.call_mcp_sync", side_effect=fake):
            return gateway_verifier(ENGAGEMENT)("cap-1", TARGET), calls

    def test_a_read_request_is_replayed_and_must_reproduce(self) -> None:
        result, calls = self._verify(
            {
                "capture_verify": {"valid": True, "capture": {"method": "GET"}},
                "http_replay": {"status": "replayed", "reproduced": True},
            }
        )
        assert result["valid"] and result["reproduced"] is True
        assert calls == ["capture_verify", "http_replay"]

        result, _ = self._verify(
            {
                "capture_verify": {"valid": True, "capture": {"method": "GET"}},
                "http_replay": {"status": "replayed", "reproduced": False},
            }
        )
        assert result["reproduced"] is False

    def test_a_state_changing_request_is_never_replayed_automatically(self) -> None:
        result, calls = self._verify(
            {"capture_verify": {"valid": True, "capture": {"method": "POST"}}}
        )
        assert result == {"valid": True, "method": "POST", "reproduced": None}
        assert calls == ["capture_verify"]

    def test_an_unknown_capture_or_an_unreachable_gateway_does_not_verify(self) -> None:
        result, _ = self._verify(
            {"capture_verify": {"valid": False, "reason": "no such capture in this engagement"}}
        )
        assert result == {"valid": False, "reason": "no such capture in this engagement"}
        result, _ = self._verify(
            {"capture_verify": {"error": "the capture server is not configured"}}
        )
        assert result["valid"] is False and "unavailable" in result["reason"]


class TestReportIsHeldForApproval:
    EVIDENCE: dict[str, Any] = {
        "capture_ids": ["cap-1"],
        "remediation": "Authorise the order lookup against the session's account on the server.",
    }

    def _graph(self) -> tuple[KnowledgeGraph, str]:
        graph = KnowledgeGraph()
        node = Node(
            id="vuln-1",
            kind=NodeKind.VULNERABILITY,
            label="IDOR on order lookup",
            props={"title": "IDOR on order lookup", "severity": "high", **self.EVIDENCE},
        )
        graph.nodes[node.id] = node
        return graph, node.id

    def _render(self, engagement: str) -> dict[str, Any]:
        graph, node_id = self._graph()
        with (
            patch("buggy.tools.reporting.tools._load", return_value=(graph, None)),
            patch("buggy.tools.reporting.tools.get_active_engagement", return_value=engagement),
        ):
            return json.loads(asyncio.run(report_hackerone.ainvoke({"finding_id": node_id})))

    def test_the_report_text_is_not_returned_until_the_operator_allows_it(self, program) -> None:
        held = self._render(ENGAGEMENT)
        assert held["released"] is False and held["status"] == "approval_required"
        assert "markdown" not in held
        draft = program["audit"] / ENGAGEMENT / "reports" / f"{held['request_id']}.md"
        assert "IDOR on order lookup" in draft.read_text()

        _requests, decisions = approvals_cli.paths_for(
            program["control"], program["audit"], ENGAGEMENT
        )
        approvals_cli.record_decision(decisions, held["request_id"], "allow")
        released = self._render(ENGAGEMENT)
        assert "IDOR on order lookup" in released["markdown"]

    @pytest.mark.parametrize("missing", ["capture_ids", "remediation"])
    def test_a_node_without_program_evidence_is_never_reportable(
        self, program, monkeypatch, missing: str
    ) -> None:
        monkeypatch.setattr(
            type(self), "EVIDENCE", {k: v for k, v in self.EVIDENCE.items() if k != missing}
        )
        refused = self._render(ENGAGEMENT)
        assert refused["error"] == "not reportable to the program"
        assert list(refused["findings"]) == ["vuln-1"]
        # Nothing was filed for the operator: there is nothing fit to approve.
        assert not (program["audit"] / ENGAGEMENT / "approvals").exists()

    def test_off_program_reports_render_as_before(self, program) -> None:
        assert "markdown" in self._render("internal-lab")

    def test_a_damaged_program_record_blocks_release(self, program) -> None:
        (program["control"] / ENGAGEMENT / "program.json").write_text("{broken")
        assert "unreadable" in self._render(ENGAGEMENT)["error"]


def test_recording_tool_exposes_the_program_fields() -> None:
    fields = reporting.report_record_finding.args
    assert "capture_ids" in fields and "remediation" in fields
