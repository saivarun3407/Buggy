"""Recon store -> knowledge graph projection (``buggy.pipeline.graph_export``).

The pure half drives ``project`` with a fixture of records and checks the
exact node keys, labels and edge triples, with controls for what must not
become a node (gone records, another engagement, unmapped types, secrets).
The writer half runs ``write`` against a fake KG store that keeps state and
counts upserts per key, and against the real ``KGStore`` over a recording
fake driver, so the Cypher it would send is checked without Neo4j.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from buggy.pipeline import graph_export
from buggy.pipeline.graph_export import LABELS, REL_TYPES, main, project, write
from buggy.pipeline.schema import Record, RecordType
from buggy.pipeline.store import ReconStore

ENG = "acme"
APP = "https://app.acme.test"
API = "https://api.acme.test"
OP_URL = f"{API}/v1/orders/{{id}}"
# Built at runtime so no provider-shaped literal sits in the source.
SECRET_VALUE = "sk_" + "live_" + "0123456789abcdefABCDEF"


def rec(
    kind: str,
    asset: str,
    value: str,
    attrs: dict[str, Any] | None = None,
    *,
    status: str = "active",
    last_seen: float = 100.0,
    engagement: str = ENG,
    tool: str = "tool",
) -> dict[str, Any]:
    return {
        "id": f"{kind}|{asset}|{value}",
        "engagement": engagement,
        "asset": asset,
        "type": kind,
        "value": value,
        "attrs": attrs or {},
        "source_tool": tool,
        "tool_version": "1",
        "sources": [tool],
        "first_seen": 1.0,
        "last_seen": last_seen,
        "first_run_id": "r1",
        "last_run_id": "r1",
        "raw_ref": "",
        "status": status,
    }


def fixture_records() -> list[dict[str, Any]]:
    return [
        rec("subdomain", "app.acme.test", "app.acme.test", {"root": "acme.test"}, tool="subfinder"),
        rec("subdomain", "api.acme.test", "api.acme.test", tool="subfinder"),
        rec("dns_record", "app.acme.test", "A 10.0.0.5", {"rtype": "A", "data": "10.0.0.5"}),
        rec(
            "dns_record",
            "app.acme.test",
            "AAAA 2001:db8::1",
            {"rtype": "AAAA", "data": "2001:db8::1"},
        ),
        rec(
            "dns_record",
            "app.acme.test",
            "CNAME edge.cdn.test",
            {"rtype": "CNAME", "data": "edge.cdn.test"},
        ),
        rec("dns_record", "acme.test", "WILDCARD *.acme.test", {"rtype": "WILDCARD"}),
        rec("port", "app.acme.test", "443/tcp", {"port": 443, "protocol": "tcp"}, tool="naabu"),
        rec(
            "http_service",
            "app.acme.test",
            APP,
            {"scheme": "https", "port": 443, "status_code": 200, "title": "App"},
            tool="httpx",
        ),
        rec(
            "technology",
            "app.acme.test",
            f"{APP} nginx",
            {"url": APP, "name": "nginx", "version": "1.25"},
            tool="httpx",
        ),
        rec("url", "app.acme.test", f"{APP}/login?next=/home", tool="katana"),
        rec("endpoint", "app.acme.test", f"{APP}/api/users", {"found_in": f"{APP}/main.js"}),
        rec(
            "api_spec",
            "api.acme.test",
            f"{API}/openapi.json",
            {"format": "openapi", "base_url": API, "operation_count": 1},
        ),
        rec(
            "api_operation",
            "api.acme.test",
            f"GET {OP_URL}",
            {
                "method": "GET",
                "url": OP_URL,
                "path": "/v1/orders/{id}",
                "spec_url": f"{API}/openapi.json",
            },
        ),
        rec(
            "parameter",
            "api.acme.test",
            f"GET {OP_URL} path:id",
            {"name": "id", "location": "path", "method": "GET", "url": OP_URL, "hints": ["id"]},
        ),
        rec(
            "parameter",
            "app.acme.test",
            f"GET {APP}/login query:next",
            {
                "name": "next",
                "location": "query",
                "method": "GET",
                "url": f"{APP}/login",
                "example": "/home",
            },
        ),
        rec(
            "parameter",
            "app.acme.test",
            f"POST {APP}/api/users body:email",
            {"name": "email", "location": "body", "method": "POST", "url": f"{APP}/api/users"},
        ),
        rec(
            "vulnerability",
            "app.acme.test",
            f"git-config {APP}/.git/config",
            {
                "template_id": "git-config",
                "matched_at": f"{APP}/.git/config",
                "severity": "medium",
                "extracted": [SECRET_VALUE],
            },
            tool="nuclei",
        ),
        rec(
            "vulnerability",
            "app.acme.test",
            "weak-cipher app.acme.test:443",
            {"template_id": "weak-cipher", "matched_at": "app.acme.test:443", "severity": "low"},
            tool="nuclei",
        ),
        rec("graphql", "api.acme.test", f"{API}/graphql", {"introspection_enabled": True}),
        rec(
            "secret",
            "app.acme.test",
            f"stripe-key {APP}/main.js:3",
            {"rule_id": "stripe-key", "location": f"{APP}/main.js", "match": SECRET_VALUE},
            tool="gitleaks",
        ),
        rec("tls", "app.acme.test", f"{APP} abc", {"url": APP, "sha256": "abc"}),
        rec("subdomain", "old.acme.test", "old.acme.test", status="gone"),
        rec("subdomain", "other.acme.test", "other.acme.test", engagement="globex"),
    ]


EXPECTED_NODES = {
    "host:app.acme.test": "Host",
    "host:api.acme.test": "Host",
    "ip:10.0.0.5": "IP",
    "ip:2001:db8::1": "IP",
    "port:app.acme.test:443/tcp": "Port",
    f"svc:{APP}": "Service",
    f"svc:{API}": "Service",
    "tech:nginx@1.25": "Technology",
    f"url:{APP}/login?next=/home": "Endpoint",
    f"url:{APP}/api/users": "Endpoint",
    f"url:{APP}/login": "Endpoint",
    f"spec:{API}/openapi.json": "ApiSpec",
    f"op:GET {OP_URL}": "Operation",
    f"param:GET {OP_URL} path:id": "Parameter",
    f"param:GET {APP}/login query:next": "Parameter",
    f"param:POST {APP}/api/users body:email": "Parameter",
    f"issue:git-config:{APP}/.git/config": "KnownIssue",
    "issue:weak-cipher:app.acme.test:443": "KnownIssue",
    f"graphql:{API}/graphql": "GraphQL",
}

EXPECTED_EDGES = {
    ("host:app.acme.test", "RESOLVES_TO", "ip:10.0.0.5"),
    ("host:app.acme.test", "RESOLVES_TO", "ip:2001:db8::1"),
    ("host:app.acme.test", "HAS_PORT", "port:app.acme.test:443/tcp"),
    ("host:app.acme.test", "SERVES", f"svc:{APP}"),
    ("host:api.acme.test", "SERVES", f"svc:{API}"),
    (f"svc:{APP}", "USES", "tech:nginx@1.25"),
    (f"svc:{APP}", "HAS_ENDPOINT", f"url:{APP}/login?next=/home"),
    (f"svc:{APP}", "HAS_ENDPOINT", f"url:{APP}/api/users"),
    (f"svc:{APP}", "HAS_ENDPOINT", f"url:{APP}/login"),
    (f"svc:{API}", "DESCRIBED_BY", f"spec:{API}/openapi.json"),
    (f"spec:{API}/openapi.json", "DECLARES", f"op:GET {OP_URL}"),
    (f"svc:{API}", "HAS_ENDPOINT", f"op:GET {OP_URL}"),
    (f"op:GET {OP_URL}", "TAKES", f"param:GET {OP_URL} path:id"),
    (f"url:{APP}/login", "TAKES", f"param:GET {APP}/login query:next"),
    (f"url:{APP}/api/users", "TAKES", f"param:POST {APP}/api/users body:email"),
    (f"svc:{APP}", "HAS_ISSUE", f"issue:git-config:{APP}/.git/config"),
    ("host:app.acme.test", "HAS_ISSUE", "issue:weak-cipher:app.acme.test:443"),
    (f"svc:{API}", "HAS_ENDPOINT", f"graphql:{API}/graphql"),
}


def _triples(graph) -> set[tuple[str, str, str]]:
    return {(e.src, e.type, e.dst) for e in graph.edges}


# ── pure projection ──────────────────────────────────────────────────────


def test_fixture_projects_to_exact_nodes_and_edges() -> None:
    graph = project(fixture_records(), ENG)
    assert {n.key: n.label for n in graph.nodes} == EXPECTED_NODES
    assert _triples(graph) == EXPECTED_EDGES
    assert len(graph.edges) == len(EXPECTED_EDGES)  # no duplicate triples


def test_every_node_carries_provenance() -> None:
    graph = project(fixture_records(), ENG)
    for node in graph.nodes:
        assert node.props["engagement"] == ENG
        assert node.props["record_id"]
        assert node.props["source_tool"]
        assert node.props["last_seen"] == 100.0
    by_key = {n.key: n for n in graph.nodes}
    # An explicit record gives its own provenance; a parent only a child implied says so.
    assert by_key["host:app.acme.test"].props["source_tool"] == "subfinder"
    assert "implied" not in by_key["host:app.acme.test"].props
    assert by_key[f"svc:{API}"].props["implied"] is True
    assert by_key["port:app.acme.test:443/tcp"].props["port"] == 443


def test_projection_does_not_depend_on_record_order() -> None:
    records = fixture_records()
    assert project(records, ENG).to_dict() == project(list(reversed(records)), ENG).to_dict()


def test_gone_records_produce_nothing() -> None:
    gone = [rec("subdomain", "old.acme.test", "old.acme.test", status="gone")]
    assert project(gone, ENG).nodes == []
    # Control: the same record while active is projected.
    active = [rec("subdomain", "old.acme.test", "old.acme.test")]
    assert [n.key for n in project(active, ENG).nodes] == ["host:old.acme.test"]
    # A gone child does not resurrect its parent either.
    gone_port = [rec("port", "old.acme.test", "22/tcp", status="gone")]
    assert project(gone_port, ENG).nodes == []


def test_other_engagements_records_produce_nothing() -> None:
    graph = project(fixture_records(), ENG)
    assert "host:other.acme.test" not in {n.key for n in graph.nodes}
    # Control: projected for its own engagement.
    other = project(fixture_records(), "globex")
    assert [n.key for n in other.nodes] == ["host:other.acme.test"]


def test_secret_values_never_reach_the_graph() -> None:
    graph = project(fixture_records(), ENG)
    dumped = json.dumps(graph.to_dict())
    assert SECRET_VALUE not in dumped  # nuclei ``extracted`` and the gitleaks record
    assert "stripe-key" not in dumped  # secret records are not projected at all
    assert "/home" not in dumped.replace("login?next=/home", "")  # parameter example
    # Control: the value is in the input, so the assertion above can fail.
    assert SECRET_VALUE in json.dumps(fixture_records())


def test_labels_and_relationship_types_pass_the_store_validators() -> None:
    from buggy.middleware.kg_internal.store import _safe_label, _safe_rel_type

    graph = project(fixture_records(), ENG)
    assert {n.label for n in graph.nodes} == set(LABELS)  # the fixture covers every label
    assert {e.type for e in graph.edges} == set(REL_TYPES)
    for label in LABELS:
        assert _safe_label(label) == label
    for rel in REL_TYPES:
        assert _safe_rel_type(rel) == rel
    # Control: the validators do reject malformed names.
    with pytest.raises(ValueError):
        _safe_label("Known Issue")
    with pytest.raises(ValueError):
        _safe_rel_type("has-issue")


def test_every_projected_label_has_a_key_engagement_constraint() -> None:
    from buggy.middleware.kg_internal.migration_runner import _DEFAULT_MIGRATIONS_DIR

    text = "\n".join(p.read_text() for p in sorted(_DEFAULT_MIGRATIONS_DIR.glob("V*.cypher")))
    constrained = set(
        re.findall(r"FOR \(n:(\w+)\) REQUIRE \(n\.key, n\.engagement\) IS UNIQUE", text)
    )
    assert set(LABELS) <= constrained, set(LABELS) - constrained


def test_ensure_schema_applies_the_projection_migration() -> None:
    from buggy.middleware.kg_internal.migration_runner import ensure_schema

    from ..hardening.test_kg_runtime import _Store

    store = _Store()
    assert ensure_schema(store) is True
    assert "V005__recon_projection" in store.applied
    for label in ("IP", "Port", "Endpoint", "ApiSpec", "Operation", "Parameter", "KnownIssue"):
        assert any(f"(n:{label})" in s and "IS UNIQUE" in s for s in store.statements), label


def _imports_heavy(module: str) -> subprocess.CompletedProcess[str]:
    # BUGGY_SKIP_BOOT=1 is how the slim pipeline image imports ``buggy``.
    code = (
        f"import sys, {module}\n"
        "bad = [m for m in sys.modules if m == 'neo4j' or m.startswith(('neo4j.', "
        "'buggy.middleware', 'langchain'))]\n"
        "print(bad)\n"
        "sys.exit(1 if bad else 0)\n"
    )
    env = {**os.environ, "BUGGY_SKIP_BOOT": "1"}
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False, env=env
    )


def test_module_imports_no_driver_or_middleware() -> None:
    done = _imports_heavy("buggy.pipeline.graph_export")
    assert done.returncode == 0, done.stdout + done.stderr
    # Control: the check does see a module that pulls in the KG store.
    assert _imports_heavy("buggy.middleware.kg_internal.store").returncode == 1


# ── writer against a stateful fake store ─────────────────────────────────


class FakeKG:
    """Implements the two KGStore methods ``write`` uses, with state.

    Upserts are counted per key. Node props are replaced on upsert like
    ``SET n += row.props``; edges are MERGEd only when both ends exist.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: set[tuple[str, str, str]] = set()
        self.edge_owner: dict[tuple[str, str, str], str] = {}
        self.upserts: Counter[str] = Counter()
        self.calls = 0

    def seed(self, key: str, label: str, created_by: str, **props: Any) -> None:
        self.nodes[key] = {"label": label, "created_by": created_by, "props": dict(props)}

    def execute_read(self, cypher: str, params: dict[str, Any], *, engagement: str) -> list[dict]:
        assert "$engagement" in cypher and engagement == ENG
        keys = set(params["keys"])
        if "-[r]->" in cypher:
            return [
                {"src": s, "type": t, "dst": d}
                for (s, t, d) in sorted(self.edges)
                if s in keys and self.edge_owner[(s, t, d)] == params["created_by"]
            ]
        return [
            {
                "key": key,
                "created_by": node["created_by"],
                "projection_hash": node["props"].get("projection_hash"),
            }
            for key, node in self.nodes.items()
            if key in keys
        ]

    def record_observations(
        self, observations, *, engagement: str, created_by: str, source_episode_id: str
    ) -> dict[str, Any]:
        from buggy.middleware.kg_internal.store import _safe_label, _safe_rel_type

        assert engagement == ENG and source_episode_id
        self.calls += 1
        created = merged = 0
        for obs in observations:
            _safe_label(obs["kind"])
            self.upserts[obs["key"]] += 1
            if obs["key"] in self.nodes:
                merged += 1
                self.nodes[obs["key"]]["props"].update(obs["props"])
                self.nodes[obs["key"]]["created_by"] = created_by
            else:
                created += 1
                self.seed(obs["key"], obs["kind"], created_by, **obs["props"])
        written = 0
        for obs in observations:
            for edge in obs["edges_out"]:
                triple = (obs["key"], _safe_rel_type(edge["kind"]), edge["to_key"])
                if edge["to_key"] in self.nodes:
                    self.edges.add(triple)
                    self.edge_owner[triple] = created_by
                    written += 1
        return {"created": created, "merged": merged, "edges": written}

    def delete_stale(self, **_kwargs: Any) -> int:
        raise AssertionError("the projection must never delete")


def test_write_creates_every_node_and_edge_once() -> None:
    graph = project(fixture_records(), ENG)
    kg = FakeKG()
    result = write(graph, kg, engagement=ENG, batch_size=4)
    assert set(kg.nodes) == set(EXPECTED_NODES)
    assert kg.edges == EXPECTED_EDGES  # small batches: children were written first
    assert set(kg.upserts.values()) == {1}
    assert result["created"] == len(EXPECTED_NODES)
    assert result["edges_written"] == len(EXPECTED_EDGES)
    assert all(n["created_by"] == "pipeline" for n in kg.nodes.values())


def test_second_write_of_the_same_store_changes_nothing() -> None:
    kg = FakeKG()
    write(project(fixture_records(), ENG), kg, engagement=ENG)
    before = (dict(kg.upserts), {k: dict(v["props"]) for k, v in kg.nodes.items()}, set(kg.edges))
    calls = kg.calls
    result = write(project(fixture_records(), ENG), kg, engagement=ENG)
    assert kg.calls == calls  # no upsert call at all
    assert (dict(kg.upserts), {k: dict(v["props"]) for k, v in kg.nodes.items()}, kg.edges) == (
        before
    )
    assert result["upserted"] == 0 and result["created"] == 0
    assert result["unchanged"] == len(EXPECTED_NODES)


def test_a_changed_record_upserts_only_its_node() -> None:
    kg = FakeKG()
    write(project(fixture_records(), ENG), kg, engagement=ENG)
    records = fixture_records()
    for record in records:
        if record["type"] == "http_service":
            record["attrs"]["title"] = "App v2"
    result = write(project(records, ENG), kg, engagement=ENG)
    assert result["upserted"] == 1 and result["created"] == 0
    assert kg.upserts[f"svc:{APP}"] == 2
    assert kg.nodes[f"svc:{APP}"]["props"]["title"] == "App v2"
    assert sum(kg.upserts.values()) == len(EXPECTED_NODES) + 1


def test_a_new_edge_resends_only_its_source() -> None:
    kg = FakeKG()
    write(project(fixture_records(), ENG), kg, engagement=ENG)
    records = fixture_records() + [rec("url", "app.acme.test", f"{APP}/admin")]
    result = write(project(records, ENG), kg, engagement=ENG)
    assert (f"svc:{APP}", "HAS_ENDPOINT", f"url:{APP}/admin") in kg.edges
    assert kg.upserts[f"url:{APP}/admin"] == 1
    assert result["upserted"] == 2  # the new endpoint and the service that links to it


def test_agent_created_nodes_are_never_overwritten() -> None:
    kg = FakeKG()
    kg.seed("host:app.acme.test", "Host", "analyst", note="crown jewel", explored=True)
    result = write(project(fixture_records(), ENG), kg, engagement=ENG)
    agent = kg.nodes["host:app.acme.test"]
    assert agent == {
        "label": "Host",
        "created_by": "analyst",
        "props": {"note": "crown jewel", "explored": True},
    }
    assert kg.upserts["host:app.acme.test"] == 0
    assert result["skipped_foreign_nodes"] == ["host:app.acme.test"]
    # Its outgoing projected edges are skipped (they would re-stamp the node) ...
    assert not any(src == "host:app.acme.test" for src, _t, _d in kg.edges)
    assert result["skipped_edges"] == 5
    # ... and everything else is still projected.
    assert set(kg.nodes) == set(EXPECTED_NODES)
    # A second run still leaves it alone and writes nothing.
    calls = kg.calls
    write(project(fixture_records(), ENG), kg, engagement=ENG)
    assert kg.calls == calls and kg.nodes["host:app.acme.test"]["created_by"] == "analyst"


# ── writer against the real KGStore over a recording driver ─────────────


class _Tx:
    def __init__(self, log: list[tuple[str, dict[str, Any]]]) -> None:
        self.log = log

    def run(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        self.log.append((cypher, params))
        if cypher.lstrip().startswith("UNWIND") and "MERGE (n:" in cypher:
            return [{"created": len(params["rows"]), "merged": 0}]
        if cypher.lstrip().startswith("UNWIND"):
            return [{"written": len(params["rows"])}]
        return []


class _Session:
    def __init__(self, log: list[tuple[str, dict[str, Any]]]) -> None:
        self.log = log

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute_read(self, fn):
        return fn(_Tx(self.log))

    def execute_write(self, fn):
        return fn(_Tx(self.log))


class _Driver:
    def __init__(self) -> None:
        self.log: list[tuple[str, dict[str, Any]]] = []

    def session(self, database: str) -> _Session:
        return _Session(self.log)

    def close(self) -> None:
        return None


def test_cypher_sent_through_the_real_store_is_scoped_and_never_deletes() -> None:
    from buggy.middleware.kg_internal.store import KGStore, KGStoreConfig

    driver = _Driver()
    store = KGStore(KGStoreConfig(uri="bolt://kg.invalid", user="u", password="p"), driver=driver)
    result = write(project(fixture_records(), ENG), store, engagement=ENG)
    assert result["created"] == len(EXPECTED_NODES)
    assert result["edges_written"] == len(EXPECTED_EDGES)
    assert driver.log
    merged_labels: set[str] = set()
    rel_types: set[str] = set()
    for cypher, params in driver.log:
        assert "$engagement" in cypher and params["engagement"] == ENG
        assert "DELETE" not in cypher.upper()
        merged_labels.update(re.findall(r"MERGE \(n:(\w+) \{key: row\.key", cypher))
        rel_types.update(re.findall(r"MERGE \(s\)-\[r:(\w+)\]->\(d\)", cypher))
        assert params.get("created_by") in (None, "pipeline")
    assert merged_labels == set(LABELS)
    assert rel_types == set(REL_TYPES)
    rows = [row for c, p in driver.log if "MERGE (n:" in c for row in p["rows"]]
    assert {row["key"] for row in rows} == set(EXPECTED_NODES)
    assert all(row["props"]["projection_hash"] for row in rows)
    assert SECRET_VALUE not in json.dumps([p for _c, p in driver.log], default=str)


# ── CLI ──────────────────────────────────────────────────────────────────


def _recon_store(root: Path) -> None:
    store = ReconStore(root / "recon.sqlite3")
    run = store.begin_run(ENG, trigger="test")
    store.write_records(
        run,
        ENG,
        "enumerate",
        [
            (Record(RecordType.SUBDOMAIN, "app.acme.test", "app.acme.test", "subfinder"), "a"),
            (Record(RecordType.SUBDOMAIN, "old.acme.test", "old.acme.test", "subfinder"), "b"),
        ],
        tool_version="1",
        raw_ref="raw/acme/r/enumerate.out",
    )
    store.write_records(
        run,
        ENG,
        "ports",
        [(Record(RecordType.PORT, "app.acme.test", "443/tcp", "naabu", {"port": 443}), "a")],
        tool_version="1",
        raw_ref="raw/acme/r/ports.out",
    )
    assert store.retire_input(run, ENG, "enumerate", "b") == 1  # old.acme.test is gone
    store.finish_run(run, status="completed", stats={})
    store.close()


def test_cli_exits_zero_when_the_kg_is_not_configured(tmp_path, monkeypatch, capsys) -> None:
    for name in ("BUGGY_NEO4J_URI", "BUGGY_NEO4J_USER", "BUGGY_NEO4J_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    assert main([ENG, "--data-root", str(tmp_path)]) == 0
    assert "not configured" in capsys.readouterr().out


def test_cli_exits_zero_when_the_kg_cannot_be_imported(tmp_path, capsys) -> None:
    _recon_store(tmp_path)

    def no_driver():
        raise ImportError("No module named 'neo4j'")

    assert main([ENG, "--data-root", str(tmp_path)], open_kg=no_driver) == 0
    assert "not available" in capsys.readouterr().out


def test_cli_projects_the_active_records_read_only(tmp_path, capsys) -> None:
    _recon_store(tmp_path)
    before = (tmp_path / "recon.sqlite3").read_bytes()
    kg = FakeKG()
    assert main([ENG, "--data-root", str(tmp_path)], open_kg=lambda: kg) == 0
    assert set(kg.nodes) == {"host:app.acme.test", "port:app.acme.test:443/tcp"}
    assert kg.edges == {("host:app.acme.test", "HAS_PORT", "port:app.acme.test:443/tcp")}
    out = json.loads(capsys.readouterr().out)
    assert out["created"] == 2
    # Idempotent through the CLI too, and the recon store is untouched.
    assert main([ENG, "--data-root", str(tmp_path)], open_kg=lambda: kg) == 0
    assert json.loads(capsys.readouterr().out)["upserted"] == 0
    assert (tmp_path / "recon.sqlite3").read_bytes() == before


def test_cli_fails_without_a_recon_store(tmp_path, capsys) -> None:
    assert main([ENG, "--data-root", str(tmp_path)], open_kg=FakeKG) == 1
    assert "no recon store" in capsys.readouterr().err


def test_read_records_pages_through_the_store(monkeypatch) -> None:
    class Paged:
        def query_records(self, engagement, *, status, limit, offset):
            assert status == "active"
            return [offset + i for i in range(min(limit, 2500 - offset))]

    assert graph_export.read_records(Paged(), ENG) == list(range(2500))
