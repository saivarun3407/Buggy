"""Tests for the deterministic corroboration gate (reporting/corroboration_gate.py)
and its wiring into the record-finding publish path."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

import pytest

from buggy.tools.proxy.tools import CaidoClient
from buggy.tools.reporting.corroboration_gate import (
    ClosureState,
    Contradiction,
    Corroboration,
    CorroborationResult,
    Modality,
    RuledOut,
    corroboration_verdict,
    independent_corroboration_count,
    validate_ruled_out,
)
from buggy.tools.reporting.kg_adapter import canonical_finding_key
from buggy.tools.reporting.tools import record_finding


def _corr(
    agent: str,
    tool: str = "sqlmap",
    modality: Modality = "dynamic_probe",
    evidence: str = "ev-1",
) -> Corroboration:
    return Corroboration(
        source_agent_id=agent, tool_family=tool, modality=modality, evidence_id=evidence
    )


TWO_INDEPENDENT = [_corr("validator-a", "sqlmap"), _corr("validator-b", "nuclei", evidence="ev-2")]


def _verdict(**over: Any) -> CorroborationResult:
    kwargs: dict[str, Any] = {
        "proof_accepted": True,
        "corroborations": TWO_INDEPENDENT,
        "contradictions": [],
        "evidence_resolves": True,
    }
    kwargs.update(over)
    return corroboration_verdict(**kwargs)


# ── Independence counting ──────────────────────────────────────────────


def test_same_agent_and_tool_family_counts_once() -> None:
    same_source = [_corr("a", evidence="ev-1"), _corr("a", evidence="ev-2")]
    assert independent_corroboration_count(same_source) == 1


def test_distinct_agents_need_distinct_tool_families() -> None:
    assert independent_corroboration_count([_corr("a"), _corr("b")]) == 1


def test_modality_alone_does_not_grant_independence() -> None:
    corroborations = [
        _corr("a", modality="dynamic_probe"),
        _corr("a", modality="response_diff"),
        _corr("a", modality="canary"),
    ]
    assert independent_corroboration_count(corroborations) == 1


def test_same_agent_different_tool_family_is_still_one_reviewer() -> None:
    assert independent_corroboration_count([_corr("a", "sqlmap"), _corr("a", "nuclei")]) == 1


def test_no_corroborations_count_zero() -> None:
    assert independent_corroboration_count([]) == 0


# ── Verdict ────────────────────────────────────────────────────────────


def test_proof_two_independent_and_resolved_evidence_confirms() -> None:
    result = _verdict()
    assert result.state is ClosureState.CONFIRMED
    assert result.published is True


def test_contradiction_rules_out_even_when_fully_corroborated() -> None:
    contradiction = Contradiction(
        source_agent_id="devils-advocate", reason="WAF strips the payload", evidence_id="ev-9"
    )
    result = _verdict(contradictions=[contradiction])
    assert result.state is ClosureState.RULED_OUT
    assert result.published is False
    assert "1 contradiction" in result.reasons[0]
    assert any("WAF strips the payload" in r for r in result.reasons)


@pytest.mark.parametrize(
    ("missing", "keyword"),
    [
        ({"proof_accepted": False}, "proof"),
        ({"corroborations": [_corr("validator-a")]}, "independent corroboration"),
        ({"evidence_resolves": False}, "evidence"),
    ],
)
def test_any_missing_condition_holds_with_that_reason(
    missing: dict[str, Any], keyword: str
) -> None:
    result = _verdict(**missing)
    assert result.state is ClosureState.OPEN_PROOF_GAP
    assert result.published is False
    assert len(result.reasons) == 1
    assert keyword in result.reasons[0]


def test_every_gap_is_listed() -> None:
    result = _verdict(proof_accepted=False, corroborations=[], evidence_resolves=False)
    assert result.state is ClosureState.OPEN_PROOF_GAP
    assert len(result.reasons) == 3


def test_same_source_agreement_is_held() -> None:
    echo = [_corr("finder", evidence="ev-1"), _corr("finder", modality="canary", evidence="ev-2")]
    result = _verdict(corroborations=echo)
    assert result.state is ClosureState.OPEN_PROOF_GAP
    assert result.published is False
    assert "1 independent" in result.reasons[0]


def test_min_independent_is_configurable() -> None:
    assert _verdict(min_independent=3).state is ClosureState.OPEN_PROOF_GAP
    three = [*TWO_INDEPENDENT, _corr("validator-c", "burp", evidence="ev-3")]
    assert _verdict(corroborations=three, min_independent=3).published is True


def test_verdict_is_order_independent() -> None:
    assert _verdict(corroborations=list(reversed(TWO_INDEPENDENT))) == _verdict()


# ── RuledOut must name a control at a location ─────────────────────────


def test_ruled_out_with_control_and_location_is_valid() -> None:
    assert validate_ruled_out(RuledOut("parameterized query", "app/db/users.py:42")) == []


@pytest.mark.parametrize(
    ("ruled_out", "error_count"),
    [
        (RuledOut("", "app/db/users.py:42"), 1),
        (RuledOut("parameterized query", "  "), 1),
        (RuledOut("", ""), 2),
    ],
)
def test_ruled_out_missing_control_or_location_rejected(
    ruled_out: RuledOut, error_count: int
) -> None:
    assert len(validate_ruled_out(ruled_out)) == error_count


# ── Record path: proof gate → corroboration gate → publish ─────────────


class _ConfirmingCaido(CaidoClient):
    """Proxy double that confirms every cited id and records replays."""

    def __init__(self) -> None:
        self.repeated: list[str] = []

    def view_request(self, request_id: str) -> dict[str, Any]:
        return {"id": request_id, "url": "https://app.example.com/login"}

    def repeat_request(self, request_id: str, mutations_json: str = "") -> dict[str, Any]:
        self.repeated.append(request_id)
        return {"replay_id": f"r{request_id}"}


def _proven_finding() -> dict[str, Any]:
    return {
        "title": "SQLi in /login",
        "severity": "high",
        "poc_script_code": "' OR 1=1--",
        "poc_description": "1. Submit the payload as username. 2. Observe login bypass.",
        "evidence": "Response 302 to /dashboard for a nonexistent user.",
        "http_exchange_ids": ["101"],
        "target": "https://app.example.com/login",
        "vuln_class": "sqli",
    }


@pytest.fixture
def corroboration_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUGGY_CORROBORATION_REQUIRED", "1")


def _record(
    provider: Any, client: _ConfirmingCaido, published: dict[str, Any] | None = None
) -> tuple[dict[str, Any], Any]:
    def _publish(engagement: str, fields: dict[str, Any], **kw: Any) -> tuple[str, bool]:
        if published is not None:
            published.update(fields)
        return ("node1", True)

    with (
        patch("buggy.tools.reporting.tools.publish_finding_node", side_effect=_publish) as persist,
        patch("buggy.tools.reporting.tools.get_active_engagement", return_value="eng-1"),
    ):
        payload = record_finding(
            _proven_finding(), strict=True, client=client, corroboration_provider=provider
        )
    return payload, persist


@pytest.mark.usefixtures("corroboration_on")
def test_tool_holds_proven_finding_with_no_corroboration() -> None:
    from buggy.tools.reporting.tools import report_record_finding

    client = _ConfirmingCaido()
    with (
        patch("buggy.tools.reporting.tools._new_caido_client", return_value=client),
        patch("buggy.tools.reporting.tools.publish_finding_node") as persist,
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "1"}, clear=False),
    ):
        raw = asyncio.run(report_record_finding.ainvoke(_proven_finding()))
    payload = json.loads(raw)
    assert payload["success"] is False
    assert payload["state"] == "open_proof_gap"
    assert any("independent corroboration" in r for r in payload["reasons"])
    persist.assert_not_called()
    assert client.repeated == []


@pytest.mark.usefixtures("corroboration_on")
def test_record_publishes_with_two_independent_corroborations() -> None:
    asked: list[str] = []

    def provider(key: str) -> tuple[list[Corroboration], list[Contradiction], bool]:
        asked.append(key)
        return TWO_INDEPENDENT, [], True

    client = _ConfirmingCaido()
    published: dict[str, Any] = {}
    payload, persist = _record(provider, client, published)
    assert payload["success"] is True
    assert payload["persisted"] is True
    persist.assert_called_once()
    assert asked == [canonical_finding_key(published)]
    assert client.repeated == ["101"]


@pytest.mark.usefixtures("corroboration_on")
def test_record_holds_same_source_corroborations() -> None:
    echo = [_corr("finder", evidence="ev-1"), _corr("finder", evidence="ev-2")]
    client = _ConfirmingCaido()
    payload, persist = _record(lambda key: (echo, [], True), client)
    assert payload["success"] is False
    assert payload["state"] == "open_proof_gap"
    persist.assert_not_called()
    assert client.repeated == []


@pytest.mark.usefixtures("corroboration_on")
def test_record_rules_out_contradicted_finding() -> None:
    contradiction = Contradiction("devils-advocate", "login fails for unknown users", "ev-9")
    payload, persist = _record(
        lambda key: (TWO_INDEPENDENT, [contradiction], True), _ConfirmingCaido()
    )
    assert payload["success"] is False
    assert payload["state"] == "ruled_out"
    persist.assert_not_called()


def test_record_publishes_on_proof_alone_when_corroboration_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BUGGY_CORROBORATION_REQUIRED", "0")
    payload, persist = _record(lambda key: ([], [], False), _ConfirmingCaido())
    assert payload["success"] is True
    persist.assert_called_once()
