"""Unit tests for the corroboration writer tools — driver-free.

``submit_corroboration`` / ``submit_contradiction`` write a Corroboration /
Contradiction node plus a CORROBORATES / CONTRADICTS edge to a target Finding,
mirroring ``kg_record``'s InjectedState resolution of engagement / created_by /
source_episode_id. The crux under test is the self-corroboration guard: the
agent that recorded a finding cannot corroborate it.
"""

from __future__ import annotations

import json
from typing import Any

from buggy.middleware.kg_internal.tools import build_kg_tools


def _call(tool: Any, args: dict[str, Any], state: dict[str, Any]) -> str:
    payload = {
        "name": getattr(tool, "name", "tool"),
        "type": "tool_call",
        "id": "tc-submit",
        "args": {**args, "state": state},
    }
    return tool.invoke(payload).content


class _SubmitStore:
    """Fake KGStore: answers the finding-existence read, captures writes."""

    def __init__(self, finding_created_by: str | None) -> None:
        self._finder = finding_created_by
        self.writes: list[dict[str, Any]] = []

    def execute_read(
        self, cypher: str, params: dict[str, Any] | None = None, *, engagement: str
    ) -> list[dict[str, Any]]:
        # The only read the submit helpers issue is the finding -> created_by
        # lookup. ``None`` models a finding_key that is not in the engagement.
        if self._finder is None:
            return []
        return [{"finder": self._finder}]

    def record_observations(
        self,
        observations: Any,
        *,
        engagement: str,
        created_by: str,
        source_episode_id: str,
    ) -> dict[str, Any]:
        self.writes.append(
            {
                "obs": list(observations),
                "engagement": engagement,
                "created_by": created_by,
                "source_episode_id": source_episode_id,
            }
        )
        return {"created": 1, "merged": 0, "edges": 1, "revision": "rev-x"}


def _tool(store: _SubmitStore, name: str) -> Any:
    return next(t for t in build_kg_tools(store) for _ in [0] if t.name == name)  # type: ignore[arg-type]


# ── submit_corroboration: happy path ───────────────────────────────────


def test_submit_corroboration_writes_node_and_edge() -> None:
    store = _SubmitStore(finding_created_by="finder-a")
    out = json.loads(
        _call(
            _tool(store, "submit_corroboration"),
            {
                "finding_key": "finding::app/login::sqli",
                "tool_family": "sqlmap",
                "modality": "dynamic_probe",
                "evidence_id": "exchange::101",
            },
            state={"kg_engagement": "acme", "role": "validator-b"},
        )
    )
    assert out == {"created": 1, "merged": 0, "edges": 1, "revision": "rev-x"}
    assert len(store.writes) == 1
    write = store.writes[0]
    # Provenance is the submitting agent, not the finder.
    assert write["engagement"] == "acme"
    assert write["created_by"] == "validator-b"
    assert write["source_episode_id"] == "tc-submit"
    [obs] = write["obs"]
    assert obs["kind"] == "Corroboration"
    assert obs["key"].startswith("corroboration::")
    assert obs["props"] == {
        "tool_family": "sqlmap",
        "modality": "dynamic_probe",
        "evidence_id": "exchange::101",
    }
    assert obs["edges_out"] == [
        {"to_key": "finding::app/login::sqli", "kind": "CORROBORATES"}
    ]


# ── submit_corroboration: fail-closed guards ───────────────────────────


def test_submit_corroboration_unknown_finding_fails_closed() -> None:
    store = _SubmitStore(finding_created_by=None)  # finding not in engagement
    out = json.loads(
        _call(
            _tool(store, "submit_corroboration"),
            {
                "finding_key": "finding::ghost",
                "tool_family": "sqlmap",
                "modality": "dynamic_probe",
                "evidence_id": "e1",
            },
            state={"kg_engagement": "acme", "role": "validator-b"},
        )
    )
    assert "unknown finding" in out["error"]
    assert store.writes == []


def test_submit_corroboration_invalid_modality_rejected() -> None:
    store = _SubmitStore(finding_created_by="finder-a")
    out = json.loads(
        _call(
            _tool(store, "submit_corroboration"),
            {
                "finding_key": "finding::x",
                "tool_family": "sqlmap",
                "modality": "vibes",
                "evidence_id": "e1",
            },
            state={"kg_engagement": "acme", "role": "validator-b"},
        )
    )
    assert "invalid modality" in out["error"]
    assert store.writes == []


def test_submit_corroboration_refuses_self_corroboration() -> None:
    # The submitting agent equals the finding's creator -> refused.
    store = _SubmitStore(finding_created_by="validator-b")
    out = json.loads(
        _call(
            _tool(store, "submit_corroboration"),
            {
                "finding_key": "finding::x",
                "tool_family": "sqlmap",
                "modality": "dynamic_probe",
                "evidence_id": "e1",
            },
            state={"kg_engagement": "acme", "role": "validator-b"},
        )
    )
    assert "self-corroboration" in out["error"]
    assert store.writes == []


def test_submit_corroboration_requires_engagement() -> None:
    store = _SubmitStore(finding_created_by="finder-a")
    out = json.loads(
        _call(
            _tool(store, "submit_corroboration"),
            {
                "finding_key": "finding::x",
                "tool_family": "sqlmap",
                "modality": "dynamic_probe",
                "evidence_id": "e1",
            },
            state={},
        )
    )
    assert "kg_engagement" in out["error"]
    assert store.writes == []


# ── submit_contradiction ───────────────────────────────────────────────


def test_submit_contradiction_writes_node_and_edge() -> None:
    store = _SubmitStore(finding_created_by="finder-a")
    out = json.loads(
        _call(
            _tool(store, "submit_contradiction"),
            {
                "finding_key": "finding::app/login::sqli",
                "reason": "login actually fails for unknown users",
                "evidence_id": "exchange::9",
            },
            state={"kg_engagement": "acme", "role": "devils-advocate"},
        )
    )
    assert out["edges"] == 1
    [obs] = store.writes[0]["obs"]
    assert obs["kind"] == "Contradiction"
    assert obs["key"].startswith("contradiction::")
    assert obs["props"] == {
        "reason": "login actually fails for unknown users",
        "evidence_id": "exchange::9",
    }
    assert obs["edges_out"] == [
        {"to_key": "finding::app/login::sqli", "kind": "CONTRADICTS"}
    ]


def test_submit_contradiction_unknown_finding_fails_closed() -> None:
    store = _SubmitStore(finding_created_by=None)
    out = json.loads(
        _call(
            _tool(store, "submit_contradiction"),
            {"finding_key": "finding::ghost", "reason": "nope", "evidence_id": "e1"},
            state={"kg_engagement": "acme", "role": "devils-advocate"},
        )
    )
    assert "unknown finding" in out["error"]
    assert store.writes == []


def test_submit_contradiction_allows_self_retraction() -> None:
    # Unlike corroboration, the finder MAY contradict its own finding.
    store = _SubmitStore(finding_created_by="finder-a")
    out = json.loads(
        _call(
            _tool(store, "submit_contradiction"),
            {"finding_key": "finding::x", "reason": "I was wrong", "evidence_id": "e1"},
            state={"kg_engagement": "acme", "role": "finder-a"},
        )
    )
    assert "error" not in out
    assert len(store.writes) == 1
