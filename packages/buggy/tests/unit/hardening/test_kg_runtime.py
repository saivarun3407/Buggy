"""The KG schema is applied at first use and writes say which agent made them."""

from __future__ import annotations

from typing import Any

from buggy.middleware.kg_internal import migration_runner
from buggy.middleware.kg_internal.migration_runner import ensure_schema
from buggy.middleware.kg_internal.tools import _resolve_created_by


class _Store:
    """Minimal store: remembers statements and the migration log."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.applied: set[str] = set()
        self.statements: list[str] = []

    def execute_read(self, cypher: str, params: dict[str, Any], *, engagement: str) -> list[dict]:
        if self.fail:
            raise ConnectionError("neo4j is not reachable")
        return [{"name": name} for name in sorted(self.applied)]

    def execute_write(self, cypher: str, params: dict[str, Any], *, engagement: str) -> None:
        if self.fail:
            raise ConnectionError("neo4j is not reachable")
        assert engagement == "schema"
        self.statements.append(cypher)
        if "MigrationLog" in cypher and params.get("name"):
            self.applied.add(str(params["name"]))


def test_schema_is_applied_once_at_first_use() -> None:
    store = _Store()
    assert ensure_schema(store) is True
    assert {"V001__initial_schema", "V004__technology_node"} <= store.applied
    assert any("CONSTRAINT" in s.upper() for s in store.statements)
    count = len(store.statements)
    assert ensure_schema(store) is True
    assert len(store.statements) == count  # nothing re-run


def test_an_unreachable_database_degrades_and_is_retried(monkeypatch) -> None:
    store = _Store(fail=True)
    assert ensure_schema(store) is False  # no exception: the run goes on without the KG
    store.fail = False
    assert ensure_schema(store) is False  # still inside the retry pause
    monkeypatch.setattr(migration_runner, "_SCHEMA_RETRY_SECONDS", 0.0)
    setattr(store, migration_runner._RETRY_ATTR, 0.0)
    assert ensure_schema(store) is True and store.applied


def test_each_store_gets_its_own_check() -> None:
    first, second = _Store(), _Store()
    assert ensure_schema(first) and ensure_schema(second)
    assert first.applied == second.applied and second.statements


def test_writes_are_attributed_to_the_agent_role() -> None:
    assert _resolve_created_by({}, "authn_session") == "authn_session"
    assert _resolve_created_by(None, "recon") == "recon"
    # State still wins when a run sets it explicitly.
    assert _resolve_created_by({"role": "analyst"}, "recon") == "analyst"
    assert _resolve_created_by({"kg_created_by": "plugin-x"}, "") == "plugin-x"
    # With neither, the old constant keeps the trusted-write invariant.
    assert _resolve_created_by({}, "") == "agent"


def test_the_kg_middleware_carries_its_role_into_the_tools() -> None:
    from buggy.agents import middleware_slots

    captured: dict[str, Any] = {}

    class _KG:
        def __init__(self, *, role: str = "") -> None:
            captured["role"] = role

    original = middleware_slots.KGMiddleware
    middleware_slots.KGMiddleware = _KG  # type: ignore[assignment,misc]
    try:
        middleware_slots._make_kg(role="ssrf_cloud", backend=None)
    finally:
        middleware_slots.KGMiddleware = original  # type: ignore[misc]
    assert captured == {"role": "ssrf_cloud"}
