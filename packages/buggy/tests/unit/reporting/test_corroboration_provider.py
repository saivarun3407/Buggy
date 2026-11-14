"""Unit tests for the real KG corroboration provider (Phase C.2) — driver-free.

Covers :func:`load_corroboration_inputs` reading CORROBORATES / CONTRADICTS
edges, the read-side self-corroboration drop, evidence resolution to the
immutable raw-output anchor, and graceful degradation. Then the full record
path with the REAL provider against a fake store: two independent
corroborations publish, one holds, a contradiction rules out, and the gate is
ON by default with no env override.

The full agent -> edge -> publish flow is only provable against a booted Neo4j;
these tests substitute a fake store for the KG backend.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from buggy.middleware.kg_internal.store import KGStore, KGStoreUnavailableError
from buggy.tools.proxy.tools import CaidoClient
from buggy.tools.reporting.kg_adapter import load_corroboration_inputs
from buggy.tools.reporting.tools import record_finding


class _ReadStore:
    """Fake KGStore answering the provider's reads from canned rows."""

    def __init__(
        self,
        *,
        finder: str | None = None,
        corrs: list[dict[str, Any]] | None = None,
        contras: list[dict[str, Any]] | None = None,
        anchors: dict[str, str] | None = None,
    ) -> None:
        self.finder = finder
        self.corrs = corrs or []
        self.contras = contras or []
        self.anchors = anchors or {}
        self.closed = False

    def execute_read(
        self, cypher: str, params: dict[str, Any] | None = None, *, engagement: str
    ) -> list[dict[str, Any]]:
        if "AS finder" in cypher:
            return [{"finder": self.finder}] if self.finder is not None else []
        if "CORROBORATES" in cypher:
            return list(self.corrs)
        if "CONTRADICTS" in cypher:
            return list(self.contras)
        if "AS anchor" in cypher:
            eid = (params or {}).get("evidence_id")
            if eid in self.anchors:
                return [{"anchor": self.anchors[eid]}]
            return []
        raise AssertionError(f"unexpected cypher: {cypher}")

    def close(self) -> None:
        self.closed = True


def _corr_row(agent: str, tool: str = "sqlmap", evidence: str = "e1") -> dict[str, Any]:
    return {
        "source_agent_id": agent,
        "tool_family": tool,
        "modality": "dynamic_probe",
        "evidence_id": evidence,
    }


def _load(store: _ReadStore, engagement: str | None = "eng-1") -> Any:
    with (
        patch.object(KGStore, "from_env", return_value=store),
        patch(
            "buggy.tools.reporting.kg_adapter.get_active_engagement",
            return_value=engagement,
        ),
    ):
        return load_corroboration_inputs("finding::x")


# ── Reading edges ──────────────────────────────────────────────────────


def test_two_independent_corroborations_resolve() -> None:
    store = _ReadStore(
        finder="finder-a",
        corrs=[_corr_row("validator-a", "sqlmap", "e1"), _corr_row("validator-b", "nuclei", "e2")],
        anchors={"e1": "tc-1", "e2": "tc-2"},
    )
    corrs, contras, resolves = _load(store)
    assert {c.source_agent_id for c in corrs} == {"validator-a", "validator-b"}
    assert {c.tool_family for c in corrs} == {"sqlmap", "nuclei"}
    assert contras == []
    assert resolves is True
    assert store.closed is True


def test_self_corroboration_dropped_on_read() -> None:
    # One corroboration is from the finding's own creator -> dropped.
    store = _ReadStore(
        finder="finder-a",
        corrs=[_corr_row("finder-a", "sqlmap", "e1"), _corr_row("validator-b", "nuclei", "e2")],
        anchors={"e2": "tc-2"},
    )
    corrs, _contras, resolves = _load(store)
    assert [c.source_agent_id for c in corrs] == ["validator-b"]
    assert resolves is True


def test_evidence_unresolved_when_anchor_missing() -> None:
    # Two survive, but one evidence node carries no source_episode_id anchor.
    store = _ReadStore(
        finder="finder-a",
        corrs=[_corr_row("validator-a", "sqlmap", "e1"), _corr_row("validator-b", "nuclei", "e2")],
        anchors={"e1": "tc-1"},  # e2 absent
    )
    _corrs, _contras, resolves = _load(store)
    assert resolves is False


def test_evidence_unresolved_when_anchor_empty() -> None:
    store = _ReadStore(
        finder="finder-a",
        corrs=[_corr_row("validator-a", "sqlmap", "e1")],
        anchors={"e1": "   "},  # present but blank
    )
    _corrs, _contras, resolves = _load(store)
    assert resolves is False


def test_no_corroborations_cannot_resolve() -> None:
    store = _ReadStore(finder="finder-a", corrs=[])
    corrs, contras, resolves = _load(store)
    assert corrs == []
    assert contras == []
    assert resolves is False


def test_contradiction_is_read() -> None:
    store = _ReadStore(
        finder="finder-a",
        corrs=[_corr_row("validator-a")],
        contras=[
            {"source_agent_id": "devils-advocate", "reason": "login fails", "evidence_id": "e9"}
        ],
        anchors={"e1": "tc-1"},
    )
    _corrs, contras, _resolves = _load(store)
    assert [c.source_agent_id for c in contras] == ["devils-advocate"]
    assert contras[0].reason == "login fails"


# ── Degradation ────────────────────────────────────────────────────────


def test_unset_engagement_holds_without_touching_store() -> None:
    with (
        patch.object(KGStore, "from_env", side_effect=AssertionError("must not construct")),
        patch("buggy.tools.reporting.kg_adapter.get_active_engagement", return_value=None),
    ):
        assert load_corroboration_inputs("finding::x") == ([], [], False)


def test_store_unavailable_holds() -> None:
    with (
        patch.object(KGStore, "from_env", side_effect=KGStoreUnavailableError("neo4j down")),
        patch("buggy.tools.reporting.kg_adapter.get_active_engagement", return_value="eng-1"),
    ):
        assert load_corroboration_inputs("finding::x") == ([], [], False)


def test_mid_read_failure_holds_and_closes() -> None:
    class _Boom(_ReadStore):
        def execute_read(self, *a: Any, **k: Any) -> list[dict[str, Any]]:
            raise RuntimeError("bolt gone")

    store = _Boom()
    result = _load(store)
    assert result == ([], [], False)
    assert store.closed is True


# ── Full record path with the REAL provider ────────────────────────────


class _ConfirmingCaido(CaidoClient):
    """Proxy double that confirms every cited id and records replays."""

    def __init__(self) -> None:
        self.repeated: list[str] = []

    def view_request(self, request_id: str) -> dict[str, Any]:
        return {"id": request_id}

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


def _run_full(store: _ReadStore) -> tuple[dict[str, Any], Any]:
    with (
        patch(
            "buggy.tools.reporting.tools.publish_finding_node", return_value=("node1", True)
        ) as persist,
        patch("buggy.tools.reporting.tools.get_active_engagement", return_value="eng-1"),
        patch.object(KGStore, "from_env", return_value=store),
        patch("buggy.tools.reporting.kg_adapter.get_active_engagement", return_value="eng-1"),
    ):
        payload = record_finding(_proven_finding(), strict=True, client=_ConfirmingCaido())
    return payload, persist


def test_record_publishes_with_two_independent_corroborations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BUGGY_CORROBORATION_REQUIRED", "1")
    store = _ReadStore(
        finder="finder-a",
        corrs=[_corr_row("validator-a", "sqlmap", "e1"), _corr_row("validator-b", "nuclei", "e2")],
        anchors={"e1": "tc-1", "e2": "tc-2"},
    )
    payload, persist = _run_full(store)
    assert payload["success"] is True
    persist.assert_called_once()


def test_record_holds_with_single_corroboration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUGGY_CORROBORATION_REQUIRED", "1")
    store = _ReadStore(
        finder="finder-a", corrs=[_corr_row("validator-a")], anchors={"e1": "tc-1"}
    )
    payload, persist = _run_full(store)
    assert payload["success"] is False
    assert payload["state"] == "open_proof_gap"
    persist.assert_not_called()


def test_record_rules_out_on_contradiction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUGGY_CORROBORATION_REQUIRED", "1")
    store = _ReadStore(
        finder="finder-a",
        corrs=[_corr_row("validator-a", "sqlmap", "e1"), _corr_row("validator-b", "nuclei", "e2")],
        contras=[{"source_agent_id": "critic", "reason": "unauth 401", "evidence_id": "e9"}],
        anchors={"e1": "tc-1", "e2": "tc-2"},
    )
    payload, persist = _run_full(store)
    assert payload["success"] is False
    assert payload["state"] == "ruled_out"
    persist.assert_not_called()


def test_gate_is_on_by_default_without_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # No BUGGY_CORROBORATION_REQUIRED in the environment at all: the gate must
    # still run and hold a proven finding that has no corroborations.
    monkeypatch.delenv("BUGGY_CORROBORATION_REQUIRED", raising=False)
    store = _ReadStore(finder="finder-a", corrs=[])
    payload, persist = _run_full(store)
    assert payload["success"] is False
    assert payload["state"] == "open_proof_gap"
    persist.assert_not_called()
