"""The capture server's findings layer: a probe result is proven by running the probe again."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.capture import workbench as workbench_module
from buggy.capture.gateway import CaptureGateway, GatewayRefusal, Roots
from buggy.capture.mcp_server import CaptureTools
from buggy.capture.workbench import Workbench
from buggy.findings import verifier
from buggy.findings.model import validate

from .test_gateway import Site, _roe

URL = "https://app.acme.test/profile/image"


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
    site.routes[("GET", URL)] = (200, b"ok")
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    tools = CaptureTools(gateway, None, "acme")
    verified: list[dict] = []
    wb = Workbench(gateway, None, tools._engagement, on_verified=verified.append)  # noqa: SLF001
    tools.workbench = wb

    state = {"vulnerable": True, "runs": 0}

    def fake_probe(gw, engagement, name, params, *, canary=None):  # noqa: ARG001
        """A probe whose proof is not in the response (like an out-of-band callback)."""
        state["runs"] += 1
        capture = gw.send(engagement, "GET", params["url"], probe=name)
        return {
            "status": "completed",
            "probe": name,
            "class": "ssrf",
            "cwe": "CWE-918",
            "vulnerable": state["vulnerable"],
            "summary": "the target fetched the canary URL"
            if state["vulnerable"]
            else "no callback",
            "evidence_capture_ids": [capture.id],
            "details": {"method": "GET"},
            "remediation": "Fetch only allow-listed hosts and block internal addresses.",
        }

    monkeypatch.setattr(workbench_module, "run_probe", fake_probe)
    monkeypatch.setattr("buggy.capture.mcp_server.run_probe", fake_probe)
    yield tools, wb, site, state, verified
    wb.close()
    gateway.store.close()


def _run(tools: CaptureTools) -> dict:
    return tools.probe_run("acme", "ssrf_canary", json.dumps({"url": URL, "parameter": "imageUrl"}))


class TestProbeResultsAreProvenByRunningTheProbeAgain:
    def test_a_positive_probe_is_queued_and_verified_by_a_fresh_run(self, bench) -> None:
        tools, wb, _site, state, verified = bench
        result = _run(tools)
        finding_id = result["finding_id"]
        assert result["queue"] == {"queued": True}
        assert wb.finding_get("acme", finding_id)["finding"]["status"] == "candidate"

        outcome = wb.finding_verify("acme", finding_id)
        assert outcome["finding"]["status"] == "exploit_verified"
        assert outcome["verification"]["assertions"][0]["method"] == "probe_rerun"
        assert state["runs"] == 2  # the probe really ran again
        assert [f["id"] for f in verified] == [finding_id]  # the operator is told once

        wb.finding_verify("acme", finding_id)
        assert len(verified) == 1  # already verified: no second notification

    def test_a_fixed_target_is_not_verified_even_though_it_still_answers_200(self, bench) -> None:
        tools, wb, _site, state, verified = bench
        finding_id = _run(tools)["finding_id"]
        state["vulnerable"] = False  # the owner fixed it; the endpoint still returns 200
        outcome = wb.finding_verify("acme", finding_id)
        assert outcome["finding"]["status"] == "inconclusive"
        assert outcome["verification"]["reasons"] == [verifier.PROBE_NOT_REPRODUCED]
        assert verified == []

    def test_a_probe_that_cannot_decide_leaves_it_inconclusive(self, bench) -> None:
        tools, wb, _site, state, _verified = bench
        finding_id = _run(tools)["finding_id"]
        state["vulnerable"] = None
        outcome = wb.finding_verify("acme", finding_id)
        assert outcome["finding"]["status"] == "inconclusive"
        assert outcome["verification"]["reasons"] == [verifier.PROBE_UNDECIDED]

    @pytest.mark.parametrize("verdict", [False, None])
    def test_a_negative_or_undecided_probe_queues_nothing(self, bench, verdict) -> None:
        tools, wb, _site, state, _verified = bench
        state["vulnerable"] = verdict
        result = _run(tools)
        assert "finding_id" not in result
        assert wb.findings_list("acme")["findings"] == []

    def test_an_agent_claim_without_a_probe_run_uses_its_assertions(self, bench) -> None:
        tools, wb, _site, state, _verified = bench
        capture = tools.http_send("acme", "GET", URL)
        claim = {
            "title": "Image endpoint answers anyone",
            "class": "access_control",
            "severity": "low",
            "endpoint": URL,
            "method": "GET",
            "source": "agent:hunter",
            "remediation": "Require a session before serving profile images.",
            "invariant": "only a signed-in user can read profile images",
            "entry_point": f"GET {URL}",
            "assertions": [{"capture_id": capture["capture_id"], "expect": {"status": 200}}],
        }
        finding_id = wb.finding_submit("acme", json.dumps(claim), "hunter:t1")["finding"]["id"]
        outcome = wb.finding_verify("acme", finding_id)
        assert outcome["finding"]["status"] == "exploit_verified"
        assert state["runs"] == 0  # no probe is recorded for it, so none was run
        assert "method" not in outcome["verification"]["assertions"][0]


class TestVerifyByProbe:
    def _finding(self, endpoint: str = URL):
        return validate(
            {
                "engagement": "acme",
                "title": "ssrf",
                "class": "ssrf",
                "severity": "high",
                "endpoint": endpoint,
                "source": "probe:ssrf_canary",
            }
        )

    def test_a_probe_run_on_another_endpoint_proves_nothing_and_is_not_run(self) -> None:
        calls: list[int] = []
        outcome = verifier.verify_by_probe(
            self._finding("https://app.acme.test/other"),
            "ssrf_canary",
            URL,
            lambda: calls.append(1) or {"vulnerable": True, "evidence_capture_ids": ["cap-1"]},
        )
        assert outcome.status == "inconclusive" and calls == []
        assert outcome.reasons == [verifier.PROBE_OTHER_ENDPOINT]

    def test_true_without_evidence_is_not_verified(self) -> None:
        outcome = verifier.verify_by_probe(
            self._finding(), "ssrf_canary", URL, lambda: {"vulnerable": True}
        )
        assert outcome.status == "inconclusive"

    def test_a_refused_run_is_inconclusive_and_names_the_code(self) -> None:
        def refused() -> dict:
            raise GatewayRefusal("APPROVAL_REQUIRED", "a human must approve this request")

        outcome = verifier.verify_by_probe(self._finding(), "mass_assignment", URL, refused)
        assert outcome.status == "inconclusive" and "APPROVAL_REQUIRED" in outcome.reasons[0]

    def test_a_truthy_non_boolean_verdict_is_not_true(self) -> None:
        outcome = verifier.verify_by_probe(
            self._finding(),
            "ssrf_canary",
            URL,
            lambda: {"vulnerable": "true", "evidence_capture_ids": ["cap-1"]},
        )
        assert outcome.status == "inconclusive"
