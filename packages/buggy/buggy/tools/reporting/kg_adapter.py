"""Adapter — read engagement-scoped KG data from the new KGStore and
build an in-memory :class:`KnowledgeGraph` for the reporting renderers.

The renderers in ``reporting/{hackerone,bugcrowd,executive,sarif,timeline}.py``
all operate on the :class:`KnowledgeGraph` Pydantic model. Rather than
rewriting every renderer in the same PR, this adapter reads from the
new :class:`KGStore` (the post-#545 backend) and constructs the same
``KnowledgeGraph`` shape — preserving deterministic Node / Edge IDs so
downstream consumers and existing test patches remain stable.

This module is the seam that lets ``tools/reporting`` retire the old
``tools/research/_state._load`` shim without touching the renderer
code or the back-end Neo4j wiring used by the (still legacy) AD /
Contract tool surfaces — those migrate in dedicated follow-up PRs.
"""

from __future__ import annotations

import re
from typing import Any, get_args
from uuid import uuid4

from buggy.middleware.kg_internal.store import (
    KGStore,
    KGStoreConfigError,
    KGStoreUnavailableError,
)
from buggy.tools.reporting.corroboration_gate import Contradiction, Corroboration, Modality
from buggy_core.types.kg import (
    Edge,
    EdgeKind,
    KnowledgeGraph,
    Node,
    NodeKind,
)
from buggy_core.utils.engagement_scope import get_active_engagement
from buggy_core.utils.normalize import normalize_endpoint, normalize_host

#: The closed modality vocabulary, sourced from the gate's ``Modality`` literal
#: so the submit tools and the gate can never drift out of agreement.
CORROBORATION_MODALITIES: frozenset[str] = frozenset(get_args(Modality))

# Provenance / reserved property names that ``KGStore`` auto-injects on
# every observation. They live on the Neo4j node so we can read them
# back when rebuilding the in-memory graph, but they don't belong on
# ``Node.props`` / ``Edge.props`` — those carry the agent-supplied
# props only. Strip them before constructing the Pydantic model.
#
# ``_legacy_id`` is the SHA1 the in-memory ``Node`` carried before
# persistence. The legacy ``_state`` shim stores it so edges (whose
# ``src`` / ``dst`` are SHA1s) can resolve their endpoints on round-trip.
# We strip it from ``Node.props`` on load and instead restore it onto
# ``Node.id`` directly, preserving the legacy graph's identity model.
_RESERVED_NODE_PROPS = frozenset(
    {
        "engagement",
        "key",
        "label",
        "firstseen",
        "lastupdated",
        "created_by",
        "source_episode_id",
        "_legacy_id",
    }
)
_RESERVED_EDGE_PROPS = frozenset(
    {
        "engagement",
        "key",
        "firstseen",
        "lastupdated",
        "created_by",
        "source_episode_id",
        "weight",
    }
)


def _coerce_props(raw: Any, reserved: frozenset[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if k not in reserved}


def canonical_finding_key(finding: dict[str, Any]) -> str:
    """Derive a merge-stable key for a gate-approved finding.

    The store MERGEs on ``(key, engagement)``. A title-derived key makes
    "SQL Injection on /login" and "SQLi in the /login endpoint" separate
    nodes for the same bug; a *locational* key — normalized host +
    normalized endpoint + vuln class (``kind``/``vuln_class``/``cwe``,
    else the title slug) — collapses them on write, so re-reporting an
    already-published finding refreshes its props instead of cloning it.

    Falls back to the title-based key whenever the finding carries no
    locational signal at all (a purely descriptive finding still dedups
    byte-identically, as before). An explicit ``key`` supplied by the
    caller always wins.
    """
    explicit = finding.get("key")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    raw_target = str(finding.get("target") or "")
    host = normalize_host(raw_target)
    endpoint = normalize_endpoint(raw_target)
    if endpoint and host and endpoint != host:
        # ``target`` was a URL — endpoint already carries ``host/path``.
        location = endpoint
    else:
        location = host or endpoint
    if not location:
        label = str(finding.get("title") or finding.get("label") or "finding")
        return f"finding::{label}"

    cls = (
        str(finding.get("kind") or finding.get("vuln_class") or finding.get("cwe") or "")
        .strip()
        .lower()
    )
    if not cls:
        cls = re.sub(r"[^a-z0-9]+", "-", str(finding.get("title") or "finding").lower()).strip("-")
    return f"finding::{location}::{cls}"


def publish_finding_node(
    engagement: str,
    finding: dict[str, Any],
    *,
    created_by: str = "proof_gate",
) -> tuple[str, bool]:
    """Persist a gate-approved finding as a FINDING node in the engagement KG.

    This is the write seam the proof gate publishes through: it is only ever
    called for a finding that has already passed :func:`verify_finding`, so a
    rejected (unproven / fabricated-evidence) finding never reaches here.

    Write-side dedup: when the caller supplies no explicit ``key``, the key
    is derived from the finding's normalized location + class
    (:func:`canonical_finding_key`), so the same bug reported twice —
    by different agents with different wording — MERGEs onto one node
    rather than producing near-duplicates that only the report-time
    dedupe pass could catch.

    Returns ``(node_id, persisted)``. Persistence is best-effort and soft-fails
    exactly like :func:`load_engagement_graph` — when the KG store is
    unavailable the deterministic node id is still returned (with
    ``persisted=False``) so the caller has a stable handle and the gate verdict
    stands regardless of backend availability.
    """
    label = str(finding.get("title") or finding.get("label") or "finding")
    key = canonical_finding_key(finding)
    props = {k: v for k, v in finding.items() if k not in {"title", "label", "key"}}
    node = Node.make(NodeKind.FINDING, label, key=key, **props)

    if not engagement:
        return node.id, False

    try:
        store = KGStore.from_env()
    except (KGStoreConfigError, KGStoreUnavailableError, ImportError):
        return node.id, False

    try:
        store.record_observations(
            [
                {
                    "kind": NodeKind.FINDING.value,
                    "key": key,
                    "label": label,
                    "props": props,
                    "edges_out": [],
                }
            ],
            engagement=engagement,
            created_by=created_by,
            source_episode_id=key,
        )
        return node.id, True
    except Exception:  # noqa: BLE001 — persistence must not break the gate
        return node.id, False
    finally:
        store.close()


def _finding_created_by(store: KGStore, engagement: str, finding_key: str) -> str | None:
    """The ``created_by`` of the Finding keyed ``finding_key`` in ``engagement``.

    ``None`` when no such Finding exists — the write guards fail closed on
    that, so a corroboration can never attach to a finding that is not there.
    """
    rows = store.execute_read(
        "MATCH (f:Finding {key: $key}) WHERE f.engagement = $engagement "
        "RETURN f.created_by AS finder LIMIT 1",
        {"key": finding_key},
        engagement=engagement,
    )
    if not rows:
        return None
    finder = rows[0].get("finder")
    return finder if isinstance(finder, str) else ""


def submit_corroboration_observation(
    store: KGStore,
    *,
    engagement: str,
    created_by: str,
    source_episode_id: str,
    finding_key: str,
    tool_family: str,
    modality: str,
    evidence_id: str,
) -> dict[str, Any]:
    """Write a Corroboration node + ``CORROBORATES`` edge to a target finding.

    Fails closed before any write on three conditions, each a
    ``ValueError`` the caller surfaces to the agent:

    - an unknown ``modality`` (not one of :data:`CORROBORATION_MODALITIES`);
    - a ``finding_key`` with no matching Finding node in the engagement;
    - self-corroboration — the submitting agent (``created_by``) equals the
      finding's own creator. The finder cannot certify itself; independence
      of the checker is the whole point of the gate.

    The store stamps ``created_by`` onto the node, so the submitting agent
    becomes the corroboration's ``source_agent_id`` on read.
    """
    if modality not in CORROBORATION_MODALITIES:
        raise ValueError(
            f"invalid modality {modality!r}; one of {sorted(CORROBORATION_MODALITIES)}"
        )
    finder = _finding_created_by(store, engagement, finding_key)
    if finder is None:
        raise ValueError(
            f"unknown finding {finding_key!r}: no Finding node in this engagement to corroborate"
        )
    if finder == created_by:
        raise ValueError(
            f"self-corroboration refused: agent {created_by!r} created finding {finding_key!r} "
            "and cannot corroborate it; corroboration must come from an independent source"
        )
    key = f"corroboration::{uuid4().hex}"
    return store.record_observations(
        [
            {
                "kind": "Corroboration",
                "key": key,
                "label": key,
                "props": {
                    "tool_family": tool_family,
                    "modality": modality,
                    "evidence_id": evidence_id,
                },
                "edges_out": [{"to_key": finding_key, "kind": "CORROBORATES"}],
            }
        ],
        engagement=engagement,
        created_by=created_by,
        source_episode_id=source_episode_id,
    )


def submit_contradiction_observation(
    store: KGStore,
    *,
    engagement: str,
    created_by: str,
    source_episode_id: str,
    finding_key: str,
    reason: str,
    evidence_id: str,
) -> dict[str, Any]:
    """Write a Contradiction node + ``CONTRADICTS`` edge to a target finding.

    Fails closed on an unknown ``finding_key`` (``ValueError``). Unlike
    corroboration there is no self guard: a finder recording disconfirming
    evidence against its own finding is a legitimate retraction, and any
    contradiction rules the finding out regardless of its source.
    """
    finder = _finding_created_by(store, engagement, finding_key)
    if finder is None:
        raise ValueError(
            f"unknown finding {finding_key!r}: no Finding node in this engagement to contradict"
        )
    key = f"contradiction::{uuid4().hex}"
    return store.record_observations(
        [
            {
                "kind": "Contradiction",
                "key": key,
                "label": key,
                "props": {"reason": reason, "evidence_id": evidence_id},
                "edges_out": [{"to_key": finding_key, "kind": "CONTRADICTS"}],
            }
        ],
        engagement=engagement,
        created_by=created_by,
        source_episode_id=source_episode_id,
    )


def _evidence_resolves(store: KGStore, engagement: str, evidence_id: str) -> bool:
    """True when ``evidence_id`` keys a node in ``engagement`` carrying a
    non-empty ``source_episode_id`` — the immutable raw-output anchor the
    store stamps on every observation."""
    if not evidence_id:
        return False
    rows = store.execute_read(
        "MATCH (n {key: $evidence_id}) WHERE n.engagement = $engagement "
        "RETURN n.source_episode_id AS anchor LIMIT 1",
        {"evidence_id": evidence_id},
        engagement=engagement,
    )
    if not rows:
        return False
    anchor = rows[0].get("anchor")
    return isinstance(anchor, str) and bool(anchor.strip())


def _read_corroboration_inputs(
    store: KGStore, engagement: str, finding_key: str
) -> tuple[list[Corroboration], list[Contradiction], bool]:
    finder = _finding_created_by(store, engagement, finding_key)

    corr_rows = store.execute_read(
        "MATCH (c:Corroboration)-[r:CORROBORATES]->(f:Finding {key: $key}) "
        "WHERE c.engagement = $engagement AND r.engagement = $engagement "
        "  AND f.engagement = $engagement "
        "RETURN c.created_by AS source_agent_id, c.tool_family AS tool_family, "
        "       c.modality AS modality, c.evidence_id AS evidence_id",
        {"key": finding_key},
        engagement=engagement,
    )
    corroborations: list[Corroboration] = []
    for row in corr_rows or []:
        source = row.get("source_agent_id")
        if not isinstance(source, str) or not source:
            continue
        # Defense in depth over the submit-tool self-corroboration guard: a
        # corroboration from the finding's own creator is dropped on read, so
        # a write that slipped past the guard still cannot certify the finder.
        if finder is not None and source == finder:
            continue
        corroborations.append(
            Corroboration(
                source_agent_id=source,
                tool_family=str(row.get("tool_family") or ""),
                modality=str(row.get("modality") or ""),  # type: ignore[arg-type]
                evidence_id=str(row.get("evidence_id") or ""),
            )
        )

    contra_rows = store.execute_read(
        "MATCH (c:Contradiction)-[r:CONTRADICTS]->(f:Finding {key: $key}) "
        "WHERE c.engagement = $engagement AND r.engagement = $engagement "
        "  AND f.engagement = $engagement "
        "RETURN c.created_by AS source_agent_id, c.reason AS reason, "
        "       c.evidence_id AS evidence_id",
        {"key": finding_key},
        engagement=engagement,
    )
    contradictions: list[Contradiction] = []
    for row in contra_rows or []:
        source = row.get("source_agent_id")
        if not isinstance(source, str) or not source:
            continue
        contradictions.append(
            Contradiction(
                source_agent_id=source,
                reason=str(row.get("reason") or ""),
                evidence_id=str(row.get("evidence_id") or ""),
            )
        )

    # Nothing survived → nothing to resolve → cannot confirm. Otherwise every
    # surviving corroboration must anchor to raw tool output.
    evidence_resolves = bool(corroborations) and all(
        _evidence_resolves(store, engagement, c.evidence_id) for c in corroborations
    )
    return corroborations, contradictions, evidence_resolves


def load_corroboration_inputs(
    finding_key: str,
) -> tuple[list[Corroboration], list[Contradiction], bool]:
    """Corroborations, contradictions, and evidence resolution for one finding.

    Reads the ``CORROBORATES`` / ``CONTRADICTS`` edges recorded against the
    Finding keyed ``finding_key`` in the active engagement, drops any
    corroboration whose source is the finding's own creator, and resolves
    evidence to the immutable raw-output anchor.

    ``evidence_resolves`` is True only when at least one corroboration
    survives and every surviving corroboration's ``evidence_id`` keys a node
    carrying a non-empty ``source_episode_id``. Nothing surviving → False.

    Resolves the active engagement from the engagement-scope contextvar, the
    same source :func:`publish_finding_node` is handed. Degrades like
    :func:`publish_finding_node` / :func:`load_engagement_graph`: an unset
    engagement or an unavailable store returns ``([], [], False)`` so the gate
    holds the finding rather than the record path crashing.
    """
    engagement = get_active_engagement()
    if not engagement:
        return [], [], False
    try:
        store = KGStore.from_env()
    except (KGStoreConfigError, KGStoreUnavailableError, ImportError):
        return [], [], False
    try:
        return _read_corroboration_inputs(store, engagement, finding_key)
    except Exception:  # noqa: BLE001 — a mid-read backend failure holds, never crashes record
        return [], [], False
    finally:
        store.close()


def load_engagement_graph(engagement: str) -> KnowledgeGraph:
    """Build a :class:`KnowledgeGraph` from the new KGStore for one engagement.

    Returns an empty graph if the store is unavailable or unreachable —
    matches the soft-fail behaviour of the legacy ``_state._load`` so
    the reporting tools degrade gracefully when Neo4j is not running.
    """
    try:
        store = KGStore.from_env()
    except (KGStoreConfigError, KGStoreUnavailableError, ImportError):
        return KnowledgeGraph()

    graph = KnowledgeGraph()
    try:
        node_rows = store.execute_read(
            (
                "MATCH (n) WHERE n.engagement = $engagement "
                "RETURN labels(n)[0] AS kind, "
                "       n.key AS key, "
                "       n.label AS label, "
                "       properties(n) AS props, "
                "       coalesce(n.firstseen, 0.0) AS created_at, "
                "       coalesce(n.lastupdated, 0.0) AS updated_at"
            ),
            {"engagement": engagement},
            engagement=engagement,
        )
        for row in node_rows or []:
            kind_raw = row.get("kind")
            if not isinstance(kind_raw, str):
                continue
            try:
                kind = NodeKind(kind_raw)
            except ValueError:
                continue
            key = row.get("key") or ""
            label = row.get("label") or key or kind_raw
            raw_props = row.get("props") or {}
            props = _coerce_props(raw_props, _RESERVED_NODE_PROPS)
            node = Node.make(kind, str(label), key=str(key), **props)
            # Restore the legacy SHA1 id when the node was persisted
            # by the legacy shim — keeps edge.src / edge.dst lookups
            # consistent across round-trip.
            legacy_id = raw_props.get("_legacy_id") if isinstance(raw_props, dict) else None
            if isinstance(legacy_id, str) and legacy_id:
                node.id = legacy_id
            node.created_at = float(row.get("created_at") or 0.0)
            node.updated_at = float(row.get("updated_at") or 0.0)
            graph.nodes[node.id] = node

        edge_rows = store.execute_read(
            (
                "MATCH (a)-[r]->(b) "
                "WHERE a.engagement = $engagement AND r.engagement = $engagement "
                "  AND b.engagement = $engagement "
                "RETURN labels(a)[0] AS src_kind, "
                "       a.key AS src_key, "
                "       labels(b)[0] AS dst_kind, "
                "       b.key AS dst_key, "
                "       type(r) AS kind, "
                "       coalesce(r.weight, 1.0) AS weight, "
                "       properties(r) AS props, "
                "       coalesce(r.firstseen, 0.0) AS created_at"
            ),
            {"engagement": engagement},
            engagement=engagement,
        )
        for row in edge_rows or []:
            kind_raw = row.get("kind")
            src_kind_raw = row.get("src_kind")
            dst_kind_raw = row.get("dst_kind")
            src_key = row.get("src_key")
            dst_key = row.get("dst_key")
            if not (
                isinstance(kind_raw, str)
                and isinstance(src_kind_raw, str)
                and isinstance(dst_kind_raw, str)
                and isinstance(src_key, str)
                and isinstance(dst_key, str)
            ):
                continue
            try:
                kind = EdgeKind(kind_raw)
                src_kind = NodeKind(src_kind_raw)
                dst_kind = NodeKind(dst_kind_raw)
            except ValueError:
                continue
            src_id = Node.make(src_kind, src_key, key=src_key).id
            dst_id = Node.make(dst_kind, dst_key, key=dst_key).id
            weight = float(row.get("weight") or 1.0)
            props = _coerce_props(row.get("props"), _RESERVED_EDGE_PROPS)
            edge = Edge.make(src_id, dst_id, kind, weight=weight, **props)
            edge.created_at = float(row.get("created_at") or 0.0)
            graph.edges[edge.id] = edge

        return graph
    finally:
        store.close()
