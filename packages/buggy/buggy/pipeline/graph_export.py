"""Project the recon store into the knowledge graph, deterministically.

The pipeline stores flat records; agents reason better over relationships
(Host -> IP / Port / Service -> Endpoint / Operation -> Parameter, Service ->
Technology / KnownIssue). This module turns records into typed nodes and
edges with code, no model involved:

* :func:`project` is pure: records in, :class:`Graph` out. The same records
  in any order give the same graph. Records marked ``gone``, records of
  another engagement and record types without a mapping (``secret``, ``tls``,
  ``header``, ``js_file``) produce nothing.
* :func:`write` upserts a graph through the KG store's public methods
  (``execute_read`` and ``record_observations``). It writes only what is new
  or changed, so a second write of the same graph issues no upsert at all.
  It never deletes anything and never touches a node another writer (an
  agent) created under the same key.
* ``python -m buggy.pipeline.graph_export <engagement>`` reads the recon
  store read-only and writes the projection; it exits 0 with a message when
  no KG is configured.

No Neo4j driver and no KG middleware is imported at module level: the slim
pipeline image has neither. The store is passed in; the CLI imports it lazily.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from buggy.pipeline.schema import RecordType, host_of, normalize_host, normalize_url

CREATED_BY = "pipeline"
SOURCE_EPISODE = "recon-projection"
BATCH_SIZE = 500
PAGE_SIZE = 1000  # ReconStore.query_records caps a page at 1000 rows

# Every label and relationship type the projection can emit.
LABELS = (
    "Host",
    "IP",
    "Port",
    "Service",
    "Technology",
    "Endpoint",
    "ApiSpec",
    "Operation",
    "Parameter",
    "KnownIssue",
    "GraphQL",
)
REL_TYPES = (
    "RESOLVES_TO",
    "HAS_PORT",
    "SERVES",
    "USES",
    "HAS_ENDPOINT",
    "DESCRIBED_BY",
    "DECLARES",
    "TAKES",
    "HAS_ISSUE",
)


@dataclass(frozen=True, slots=True)
class Node:
    key: str
    label: str
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "label": self.label, "props": dict(self.props)}


@dataclass(frozen=True, slots=True)
class Edge:
    src: str
    type: str
    dst: str
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "type": self.type, "dst": self.dst, "props": dict(self.props)}


@dataclass(frozen=True, slots=True)
class Graph:
    nodes: list[Node]
    edges: list[Edge]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }


# ── keys ─────────────────────────────────────────────────────────────────


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of an http(s) URL, ``""`` when it has none."""
    normal = normalize_url(url)
    parts = urlsplit(normal)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def host_key(name: str) -> str:
    return f"host:{normalize_host(name)}"


def ip_key(address: str) -> str:
    return f"ip:{address.strip().lower()}"


def port_key(host: str, port: int | str, proto: str) -> str:
    return f"port:{normalize_host(host)}:{port}/{proto.lower()}"


def service_key(base_url: str) -> str:
    return f"svc:{base_url}"


def url_key(url: str) -> str:
    return f"url:{normalize_url(url)}"


def op_key(method: str, url: str) -> str:
    return f"op:{method.upper()} {normalize_url(url)}"


def param_key(method: str, url: str, location: str, name: str) -> str:
    return f"param:{method.upper()} {normalize_url(url)} {location}:{name}"


def tech_key(name: str, version: str = "") -> str:
    return f"tech:{name}" + (f"@{version}" if version else "")


def issue_key(template: str, matched_at: str) -> str:
    return f"issue:{template}:{matched_at}"


def spec_key(ref: str) -> str:
    return f"spec:{normalize_url(ref) if '://' in ref else ref}"


def graphql_key(url: str) -> str:
    return f"graphql:{normalize_url(url)}"


# ── projection ───────────────────────────────────────────────────────────


def _as_dict(record: Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        return dict(record)
    to_dict = getattr(record, "to_dict", None)
    return to_dict() if callable(to_dict) else {}


def _keep(attrs: Mapping[str, Any], *names: str) -> dict[str, Any]:
    return {name: attrs[name] for name in names if attrs.get(name) not in (None, "", [])}


class _Builder:
    """Collects candidate nodes and edges; resolves duplicates deterministically."""

    def __init__(self, engagement: str) -> None:
        self.engagement = engagement
        # key -> (rank, label, props); the highest rank wins.
        self.nodes: dict[str, tuple[tuple[Any, ...], str, dict[str, Any]]] = {}
        self.edges: set[tuple[str, str, str]] = set()
        self.explicit: set[str] = set()

    def node(
        self,
        key: str,
        label: str,
        record: Mapping[str, Any],
        props: Mapping[str, Any],
        *,
        implied: bool = False,
    ) -> str:
        last_seen = float(record.get("last_seen") or 0.0)
        record_id = str(record.get("id") or "")
        full = {
            "engagement": self.engagement,
            "source_tool": str(record.get("source_tool") or ""),
            "record_id": record_id,
            "last_seen": last_seen,
            **dict(props),
        }
        if implied:
            full["implied"] = True
        else:
            self.explicit.add(key)
        # An explicit record beats a node implied by a child; then the newest
        # observation; then the record id, so input order never matters.
        rank = (not implied, last_seen, record_id)
        current = self.nodes.get(key)
        if current is None or rank > current[0]:
            self.nodes[key] = (rank, label, full)
        return key

    def edge(self, src: str, rel: str, dst: str) -> None:
        self.edges.add((src, rel, dst))

    # parents a child record implies when its own record is not in the store

    def host(self, name: str, record: Mapping[str, Any], *, implied: bool = True) -> str:
        name = normalize_host(name)
        return self.node(host_key(name), "Host", record, {"name": name}, implied=implied)

    def service(self, url: str, record: Mapping[str, Any]) -> str:
        base = _origin(url)
        if not base:
            return ""
        key = self.node(service_key(base), "Service", record, {"url": base}, implied=True)
        host = host_of(base)
        if host:
            self.edge(self.host(host, record), "SERVES", key)
        return key

    def build(self) -> Graph:
        nodes = [
            Node(key=key, label=label, props=props)
            for key, (_rank, label, props) in sorted(self.nodes.items())
        ]
        edges = [
            Edge(src=src, type=rel, dst=dst)
            for src, rel, dst in sorted(self.edges)
            if src in self.nodes and dst in self.nodes
        ]
        return Graph(nodes=nodes, edges=edges)


def _project_one(b: _Builder, record: Mapping[str, Any]) -> None:
    kind = str(record.get("type") or "")
    value = str(record.get("value") or "")
    asset = str(record.get("asset") or "")
    attrs = record.get("attrs") if isinstance(record.get("attrs"), Mapping) else {}

    if kind == RecordType.SUBDOMAIN.value:
        name = normalize_host(value or asset)
        props = {"name": name, **_keep(attrs, "root", "sources")}
        b.node(host_key(name), "Host", record, props)

    elif kind == RecordType.DNS_RECORD.value:
        rtype = str(attrs.get("rtype") or value.partition(" ")[0]).upper()
        address = str(attrs.get("data") or value.partition(" ")[2]).strip()
        if rtype not in ("A", "AAAA") or not address or not asset:
            return
        ip = b.node(
            ip_key(address),
            "IP",
            record,
            {"address": address.lower(), "version": 4 if rtype == "A" else 6},
        )
        b.edge(b.host(asset, record), "RESOLVES_TO", ip)

    elif kind == RecordType.PORT.value:
        number, _, proto = value.partition("/")
        number = str(attrs.get("port") or number).strip()
        proto = str(attrs.get("protocol") or proto or "tcp").strip()
        if not number.isdigit() or not asset:
            return
        port = b.node(
            port_key(asset, number, proto),
            "Port",
            record,
            {"host": normalize_host(asset), "port": int(number), "protocol": proto.lower()},
        )
        b.edge(b.host(asset, record), "HAS_PORT", port)

    elif kind == RecordType.HTTP_SERVICE.value:
        base = _origin(value)
        if not base:
            return
        props = {"url": base, **_keep(attrs, "scheme", "port", "status_code", "title", "webserver")}
        svc = b.node(service_key(base), "Service", record, props)
        b.edge(b.host(host_of(base), record), "SERVES", svc)

    elif kind == RecordType.TECHNOLOGY.value:
        name = str(attrs.get("name") or "").strip()
        version = str(attrs.get("version") or "").strip()
        url = str(attrs.get("url") or value.partition(" ")[0])
        if not name:
            return
        props = {"name": name, **({"version": version} if version else {})}
        tech = b.node(tech_key(name, version), "Technology", record, props)
        svc = b.service(url, record)
        if svc:
            b.edge(svc, "USES", tech)

    elif kind in (RecordType.URL.value, RecordType.ENDPOINT.value):
        if not _origin(value):
            return
        url = normalize_url(value)
        props = {"url": url, "record_type": kind, **_keep(attrs, "method", "status_code")}
        endpoint = b.node(url_key(url), "Endpoint", record, props)
        b.edge(b.service(url, record), "HAS_ENDPOINT", endpoint)

    elif kind == RecordType.API_SPEC.value:
        if not value:
            return
        props = {
            "ref": value,
            **_keep(attrs, "format", "title", "api_version", "base_url", "operation_count"),
        }
        spec = b.node(spec_key(value), "ApiSpec", record, props)
        svc = b.service(str(attrs.get("base_url") or value), record)
        if svc:
            b.edge(svc, "DESCRIBED_BY", spec)

    elif kind == RecordType.API_OPERATION.value:
        verb, _, rest = value.partition(" ")
        method = str(attrs.get("method") or verb).upper()
        url = str(attrs.get("url") or rest)
        if not method or not _origin(url):
            return
        props = {
            "method": method,
            "url": normalize_url(url),
            **_keep(attrs, "path", "operation_id", "summary", "auth_required", "spec_url"),
        }
        op = b.node(op_key(method, url), "Operation", record, props)
        spec_ref = str(attrs.get("spec_url") or "")
        if spec_ref:
            spec = b.node(spec_key(spec_ref), "ApiSpec", record, {"ref": spec_ref}, implied=True)
            b.edge(spec, "DECLARES", op)
        b.edge(b.service(url, record), "HAS_ENDPOINT", op)

    elif kind == RecordType.PARAMETER.value:
        name = str(attrs.get("name") or "")
        location = str(attrs.get("location") or "")
        method = str(attrs.get("method") or "GET").upper()
        url = str(attrs.get("url") or "")
        if not name or not location or not _origin(url):
            return
        # ``example`` is left out on purpose: it is a value seen in traffic.
        props = {
            "name": name,
            "location": location,
            "method": method,
            "url": normalize_url(url),
            **_keep(attrs, "hints"),
        }
        b.node(param_key(method, url, location, name), "Parameter", record, props)
        # Its parent is linked after every record is in (see ``project``).

    elif kind == RecordType.VULNERABILITY.value:
        template = str(attrs.get("template_id") or value.partition(" ")[0])
        matched_at = str(attrs.get("matched_at") or value.rpartition(" ")[2])
        if not template or not matched_at:
            return
        # ``extracted`` (matched response content) is left out on purpose.
        props = {
            "template_id": template,
            "matched_at": matched_at,
            **_keep(attrs, "name", "severity", "tags", "cve", "cwe", "cvss_score"),
        }
        issue = b.node(issue_key(template, matched_at), "KnownIssue", record, props)
        svc = b.service(matched_at, record) if "://" in matched_at else ""
        if svc:
            b.edge(svc, "HAS_ISSUE", issue)
        elif host_of(matched_at) or asset:
            # A network-level match (``host:port``) has no HTTP service.
            b.edge(b.host(host_of(matched_at) or asset, record), "HAS_ISSUE", issue)

    elif kind == RecordType.GRAPHQL.value:
        if not _origin(value):
            return
        url = normalize_url(value)
        props = {
            "url": url,
            **_keep(attrs, "introspection_enabled", "query_type", "mutation_type"),
        }
        gql = b.node(graphql_key(url), "GraphQL", record, props)
        b.edge(b.service(url, record), "HAS_ENDPOINT", gql)

    # secret, tls, header, js_file: no mapping; nothing is projected.


def project(records: Iterable[Any], engagement: str) -> Graph:
    """Nodes and edges for ``engagement``'s active records. Pure and order-independent."""
    b = _Builder(engagement)
    params: list[dict[str, Any]] = []
    for raw in records:
        record = _as_dict(raw)
        if str(record.get("status") or "active") != "active":
            continue  # ``gone``: the asset or input that produced it no longer exists
        if str(record.get("engagement") or engagement) != engagement:
            continue
        _project_one(b, record)
        if record.get("type") == RecordType.PARAMETER.value:
            params.append(record)
    for record in params:
        attrs = record.get("attrs") or {}
        method = str(attrs.get("method") or "GET").upper()
        url = str(attrs.get("url") or "")
        name, location = str(attrs.get("name") or ""), str(attrs.get("location") or "")
        if not name or not location or not _origin(url):
            continue
        param = param_key(method, url, location, name)
        parents = [key for key in (op_key(method, url), url_key(url)) if key in b.explicit] or [
            b.node(url_key(url), "Endpoint", record, {"url": normalize_url(url)}, implied=True)
        ]
        for parent in parents:
            b.edge(parent, "TAKES", param)
        if parents == [url_key(url)] and url_key(url) not in b.explicit:
            b.edge(b.service(url, record), "HAS_ENDPOINT", url_key(url))
    return b.build()


# ── writer ───────────────────────────────────────────────────────────────


def _digest(node: Node) -> str:
    material = json.dumps(
        {"label": node.label, "props": node.props},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


_READ_NODES = (
    "MATCH (n) WHERE n.engagement = $engagement AND n.key IN $keys "
    "RETURN n.key AS key, n.created_by AS created_by, n.projection_hash AS projection_hash"
)
_READ_EDGES = (
    "MATCH (s)-[r]->(d) WHERE s.engagement = $engagement AND s.key IN $keys "
    "AND d.engagement = $engagement AND r.engagement = $engagement "
    "AND r.created_by = $created_by "
    "RETURN s.key AS src, type(r) AS type, d.key AS dst"
)


def _heights(graph: Graph) -> dict[str, int]:
    """Longest path from each node to a leaf, so children are written first."""
    children: dict[str, list[str]] = {}
    for edge in graph.edges:
        children.setdefault(edge.src, []).append(edge.dst)
    heights: dict[str, int] = {}

    def height(key: str, path: frozenset[str]) -> int:
        if key in heights:
            return heights[key]
        below = [height(c, path | {key}) for c in children.get(key, []) if c not in path]
        heights[key] = 1 + max(below) if below else 0
        return heights[key]

    for node in graph.nodes:
        height(node.key, frozenset())
    return heights


def write(
    graph: Graph,
    store: Any,
    *,
    engagement: str,
    created_by: str = CREATED_BY,
    batch_size: int = BATCH_SIZE,
) -> dict[str, Any]:
    """Upsert ``graph`` into the KG ``store``; only new or changed nodes and edges.

    ``store`` is a ``KGStore`` (or anything with its ``execute_read`` and
    ``record_observations``). A node whose key already exists with another
    ``created_by`` belongs to an agent: it is neither updated nor used as the
    source of a projected edge. Nothing is deleted.
    """
    keys = [node.key for node in graph.nodes]
    existing: dict[str, dict[str, Any]] = {}
    present_edges: set[tuple[str, str, str]] = set()
    for chunk in _chunks(keys, PAGE_SIZE):
        for row in store.execute_read(
            _READ_NODES, {"keys": chunk, "engagement": engagement}, engagement=engagement
        ):
            existing[str(row.get("key"))] = row
        for row in store.execute_read(
            _READ_EDGES,
            {"keys": chunk, "created_by": created_by, "engagement": engagement},
            engagement=engagement,
        ):
            present_edges.add((str(row.get("src")), str(row.get("type")), str(row.get("dst"))))

    foreign = sorted(
        key for key, row in existing.items() if str(row.get("created_by") or "") != created_by
    )
    foreign_set = set(foreign)
    digests = {node.key: _digest(node) for node in graph.nodes}
    changed = {
        node.key
        for node in graph.nodes
        if node.key not in foreign_set
        and existing.get(node.key, {}).get("projection_hash") != digests[node.key]
    }
    edges_out: dict[str, list[Edge]] = {}
    skipped_edges = 0
    for edge in graph.edges:
        if edge.src in foreign_set:
            skipped_edges += 1
            continue
        edges_out.setdefault(edge.src, []).append(edge)
    # A source node is re-sent when it changed or when one of its edges is missing.
    to_send = changed | {
        src
        for src, edges in edges_out.items()
        if any((e.src, e.type, e.dst) not in present_edges for e in edges)
    }

    heights = _heights(graph)
    by_key = {node.key: node for node in graph.nodes}
    ordered = sorted(to_send, key=lambda key: (heights.get(key, 0), key))
    observations = [
        {
            "kind": by_key[key].label,
            "key": key,
            "label": str(by_key[key].props.get("name") or by_key[key].props.get("url") or key),
            "props": {**by_key[key].props, "projection_hash": digests[key]},
            "edges_out": [
                {"to_key": e.dst, "kind": e.type, "props": dict(e.props)}
                for e in edges_out.get(key, [])
            ],
        }
        for key in ordered
    ]
    created = merged = edges_written = 0
    batches = 0
    for start in range(0, len(observations), max(1, batch_size)):
        result = store.record_observations(
            observations[start : start + max(1, batch_size)],
            engagement=engagement,
            created_by=created_by,
            source_episode_id=SOURCE_EPISODE,
        )
        batches += 1
        created += int(result.get("created") or 0)
        merged += int(result.get("merged") or 0)
        edges_written += int(result.get("edges") or 0)
    return {
        "engagement": engagement,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "upserted": len(observations),
        "unchanged": len(graph.nodes) - len(observations) - len(foreign),
        "created": created,
        "merged": merged,
        "edges_written": edges_written,
        "batches": batches,
        "skipped_foreign_nodes": foreign,
        "skipped_edges": skipped_edges,
    }


# ── CLI ──────────────────────────────────────────────────────────────────


def read_records(store: Any, engagement: str) -> list[Any]:
    """Every active record of ``engagement`` from a :class:`ReconStore`."""
    out: list[Any] = []
    offset = 0
    while True:
        page = store.query_records(engagement, status="active", limit=PAGE_SIZE, offset=offset)
        out.extend(page)
        if len(page) < PAGE_SIZE:
            return out
        offset += PAGE_SIZE


def _kg_configured() -> bool:
    return all(
        os.environ.get(name, "").strip()
        for name in ("BUGGY_NEO4J_URI", "BUGGY_NEO4J_USER", "BUGGY_NEO4J_PASSWORD")
    )


def _open_kg() -> Any:
    # Imported here: the slim pipeline image has neither neo4j nor the middleware.
    from buggy.middleware.kg_internal.migration_runner import ensure_schema
    from buggy.middleware.kg_internal.store import KGStore

    store = KGStore.from_env()
    if not ensure_schema(store):
        store.close()
        raise RuntimeError("the KG schema could not be applied (is Neo4j reachable?)")
    return store


def main(argv: list[str] | None = None, *, open_kg: Callable[[], Any] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m buggy.pipeline.graph_export",
        description="Project an engagement's recon records into the knowledge graph.",
    )
    parser.add_argument("engagement")
    parser.add_argument("--data-root", type=Path, default=None, help="Recon store directory.")
    args = parser.parse_args(argv)

    if open_kg is None:
        if not _kg_configured():
            print("knowledge graph not configured (BUGGY_NEO4J_*); nothing projected")
            return 0
        open_kg = _open_kg

    from buggy.pipeline import service
    from buggy.pipeline.store import StoreError

    path = (args.data_root or service.data_root()) / service.STORE_FILE
    if not path.exists():
        print(f"error: no recon store at {path}", file=sys.stderr)
        return 1
    try:
        recon = service.open_store(read_only=True, root=args.data_root)
    except StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    try:
        graph = project(read_records(recon, args.engagement), args.engagement)
    finally:
        recon.close()

    try:
        kg = open_kg()
    except ImportError as exc:
        print(f"knowledge graph not available in this image ({exc}); nothing projected")
        return 0
    except Exception as exc:  # noqa: BLE001 - report and fail, never a traceback
        print(f"error: cannot open the knowledge graph: {exc}", file=sys.stderr)
        return 1
    try:
        result = write(graph, kg, engagement=args.engagement)
    finally:
        close = getattr(kg, "close", None)
        if callable(close):
            close()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = [
    "CREATED_BY",
    "LABELS",
    "REL_TYPES",
    "Edge",
    "Graph",
    "Node",
    "main",
    "project",
    "read_records",
    "write",
]


if __name__ == "__main__":
    raise SystemExit(main())
