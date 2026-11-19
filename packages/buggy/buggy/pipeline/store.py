"""SQLite recon store — the single data store for pipeline output.

One writer (the pipeline), many readers (the read-only MCP server). The file
lives in a volume that is mounted into neither the sandbox nor the langgraph
service, so agents can query it only through the MCP tools.

Tables
------
``records``        one row per fact, identity ``(engagement, type, asset, value)``
``observations``   one row per (record, run, tool): provenance and raw-output ref
``runs``           pipeline executions
``run_touch``      which records a run saw, and their hash before it
``diffs``          per run: added / changed / removed records
``scope_drops``    candidates dropped by the scope filter, never scanned
``stage_cache``    which (stage, input) was processed, against what input hash
``raw_outputs``    registry of raw tool-output files (path, sha256, argv)
``rerun_requests`` agent requests to re-run the pipeline for one asset
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from buggy.pipeline import PIPELINE_SCHEMA_VERSION
from buggy.pipeline.schema import Record, StoredRecord, content_hash

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    engagement TEXT NOT NULL,
    trigger TEXT NOT NULL,
    status TEXT NOT NULL,
    scope_digest TEXT NOT NULL DEFAULT '',
    started_at REAL NOT NULL,
    finished_at REAL,
    stats TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS runs_engagement ON runs (engagement, started_at);

CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    engagement TEXT NOT NULL,
    asset TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    attrs TEXT NOT NULL DEFAULT '{}',
    source_tool TEXT NOT NULL,
    tool_version TEXT NOT NULL DEFAULT '',
    stage TEXT NOT NULL,
    input_key TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    first_run_id TEXT NOT NULL,
    last_run_id TEXT NOT NULL,
    raw_ref TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS records_engagement_type ON records (engagement, type, status);
CREATE INDEX IF NOT EXISTS records_engagement_asset ON records (engagement, asset, status);
CREATE INDEX IF NOT EXISTS records_stage_input ON records (engagement, stage, input_key);

CREATE TABLE IF NOT EXISTS observations (
    record_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    tool_version TEXT NOT NULL DEFAULT '',
    observed_at REAL NOT NULL,
    raw_ref TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (record_id, run_id, source_tool)
);

CREATE TABLE IF NOT EXISTS run_touch (
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    prev_hash TEXT,
    prev_status TEXT,
    PRIMARY KEY (run_id, record_id)
);

CREATE TABLE IF NOT EXISTS diffs (
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    engagement TEXT NOT NULL,
    change TEXT NOT NULL,
    prev_hash TEXT,
    new_hash TEXT,
    PRIMARY KEY (run_id, record_id)
);

CREATE TABLE IF NOT EXISTS scope_drops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    engagement TEXT NOT NULL,
    stage TEXT NOT NULL,
    tool TEXT NOT NULL,
    direction TEXT NOT NULL,
    candidate TEXT NOT NULL,
    reason TEXT NOT NULL,
    dropped_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS scope_drops_run ON scope_drops (run_id);
CREATE UNIQUE INDEX IF NOT EXISTS scope_drops_unique
    ON scope_drops (run_id, stage, tool, direction, candidate);

CREATE TABLE IF NOT EXISTS stage_cache (
    engagement TEXT NOT NULL,
    stage TEXT NOT NULL,
    input_key TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    tool_versions TEXT NOT NULL,
    run_id TEXT NOT NULL,
    completed_at REAL NOT NULL,
    PRIMARY KEY (engagement, stage, input_key)
);

CREATE TABLE IF NOT EXISTS raw_outputs (
    ref TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    engagement TEXT NOT NULL,
    stage TEXT NOT NULL,
    tool TEXT NOT NULL,
    tool_version TEXT NOT NULL DEFAULT '',
    argv TEXT NOT NULL DEFAULT '[]',
    sha256 TEXT NOT NULL DEFAULT '',
    bytes INTEGER NOT NULL DEFAULT 0,
    exit_code INTEGER,
    started_at REAL NOT NULL,
    finished_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS rerun_requests (
    id TEXT PRIMARY KEY,
    engagement TEXT NOT NULL,
    asset TEXT NOT NULL,
    requested_by TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    requested_at REAL NOT NULL,
    decided_at REAL,
    run_id TEXT
);
CREATE INDEX IF NOT EXISTS rerun_status ON rerun_requests (status, requested_at);
"""

_RECORD_COLUMNS = (
    "id, engagement, asset, type, value, attrs, source_tool, tool_version, first_seen, "
    "last_seen, first_run_id, last_run_id, raw_ref, content_hash, status"
)


class StoreError(RuntimeError):
    """The store could not be opened or is not usable."""


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class ReconStore:
    """Thread-safe wrapper over one SQLite file."""

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = Path(path)
        self.read_only = read_only
        self._lock = threading.RLock()
        try:
            if read_only:
                self._db = sqlite3.connect(
                    f"file:{self.path}?mode=ro", uri=True, check_same_thread=False, timeout=30
                )
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        except sqlite3.Error as exc:
            raise StoreError(f"cannot open recon store {self.path}: {exc}") from exc
        self._db.row_factory = sqlite3.Row
        if read_only:
            self._db.execute("PRAGMA query_only = ON")
            version = self._meta("schema_version")
            if version is not None and int(version) != PIPELINE_SCHEMA_VERSION:
                raise StoreError(f"recon store schema {version} != {PIPELINE_SCHEMA_VERSION}")
        else:
            # Rollback-journal mode on purpose (not WAL): the MCP server mounts
            # this directory read-only, and a WAL database needs writable
            # -shm/-wal files even for readers.
            with self._tx() as cur:
                cur.executescript(_SCHEMA)
                cur.execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                    (str(PIPELINE_SCHEMA_VERSION),),
                )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cursor = self._db.cursor()
            try:
                yield cursor
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise
            finally:
                cursor.close()

    def _meta(self, key: str) -> str | None:
        try:
            row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        except sqlite3.OperationalError:
            return None
        return row["value"] if row else None

    # ── runs ─────────────────────────────────────────────────────────

    def begin_run(self, engagement: str, *, trigger: str, scope_digest: str = "") -> str:
        run_id = f"run-{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{uuid.uuid4().hex[:8]}"
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO runs (id, engagement, trigger, status, scope_digest, started_at) "
                "VALUES (?, ?, ?, 'running', ?, ?)",
                (run_id, engagement, trigger, scope_digest, time.time()),
            )
        return run_id

    def finish_run(self, run_id: str, *, status: str, stats: dict[str, Any]) -> dict[str, int]:
        """Close a run: compute its diff from ``run_touch`` and store ``stats``."""
        with self._tx() as cur:
            run = cur.execute("SELECT engagement FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise StoreError(f"unknown run {run_id}")
            rows = cur.execute(
                "SELECT t.record_id, t.prev_hash, t.prev_status, r.content_hash, r.status "
                "FROM run_touch t JOIN records r ON r.id = t.record_id WHERE t.run_id = ?",
                (run_id,),
            ).fetchall()
            for row in rows:
                if row["status"] != "active":
                    continue  # handled as 'removed' by complete_inputs
                if row["prev_hash"] is None or row["prev_status"] == "gone":
                    change = "added"
                elif row["prev_hash"] != row["content_hash"]:
                    change = "changed"
                else:
                    continue
                cur.execute(
                    "INSERT OR REPLACE INTO diffs (run_id, record_id, engagement, change, "
                    "prev_hash, new_hash) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        row["record_id"],
                        run["engagement"],
                        change,
                        row["prev_hash"],
                        row["content_hash"],
                    ),
                )
            counts = {"added": 0, "changed": 0, "removed": 0}
            for row in cur.execute(
                "SELECT change, COUNT(*) AS n FROM diffs WHERE run_id = ? GROUP BY change",
                (run_id,),
            ):
                counts[row["change"]] = row["n"]
            merged = {**stats, "diff": counts}
            cur.execute(
                "UPDATE runs SET status = ?, finished_at = ?, stats = ? WHERE id = ?",
                (status, time.time(), json.dumps(merged, sort_keys=True), run_id),
            )
        return counts

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_row(row) if row else None

    def list_runs(self, engagement: str, *, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM runs WHERE engagement = ? ORDER BY started_at DESC LIMIT ?",
            (engagement, max(1, min(limit, 200))),
        ).fetchall()
        return [self._run_row(row) for row in rows]

    def latest_run(self, engagement: str, *, finished_only: bool = True) -> dict[str, Any] | None:
        clause = "AND status != 'running'" if finished_only else ""
        row = self._db.execute(
            f"SELECT * FROM runs WHERE engagement = ? {clause} ORDER BY started_at DESC LIMIT 1",  # noqa: S608
            (engagement,),
        ).fetchone()
        return self._run_row(row) if row else None

    @staticmethod
    def _run_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["stats"] = json.loads(data.get("stats") or "{}")
        return data

    # ── writes ───────────────────────────────────────────────────────

    def write_records(
        self,
        run_id: str,
        engagement: str,
        stage: str,
        records: Iterable[tuple[Record, str]],
        *,
        tool_version: str,
        raw_ref: str,
        observed_at: float | None = None,
    ) -> int:
        """Upsert ``(record, input_key)`` pairs; return how many were written.

        The first time a run touches a record its attributes replace the
        stored ones; later touches in the same run (another tool reporting
        the same fact) merge into them, so a multi-tool record does not flap.
        """
        now = observed_at if observed_at is not None else time.time()
        written = 0
        with self._tx() as cur:
            for record, input_key in records:
                rid = record.key(engagement)
                ref = f"{raw_ref}#L{record.raw_line}" if record.raw_line and raw_ref else raw_ref
                existing = cur.execute(
                    "SELECT attrs, content_hash, status FROM records WHERE id = ?", (rid,)
                ).fetchone()
                touched = cur.execute(
                    "SELECT 1 FROM run_touch WHERE run_id = ? AND record_id = ?", (run_id, rid)
                ).fetchone()
                if existing is None:
                    attrs = dict(record.attrs)
                    cur.execute(
                        "INSERT INTO records (id, engagement, asset, type, value, attrs, "
                        "source_tool, tool_version, stage, input_key, first_seen, last_seen, "
                        "first_run_id, last_run_id, raw_ref, content_hash, status) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
                        (
                            rid,
                            engagement,
                            record.asset,
                            record.type.value,
                            record.value,
                            json.dumps(attrs, sort_keys=True, default=str),
                            record.source_tool,
                            tool_version,
                            stage,
                            input_key,
                            now,
                            now,
                            run_id,
                            run_id,
                            ref,
                            content_hash(attrs),
                        ),
                    )
                    prev_hash, prev_status = None, None
                else:
                    stored = json.loads(existing["attrs"] or "{}")
                    attrs = {**stored, **record.attrs} if touched else dict(record.attrs)
                    cur.execute(
                        "UPDATE records SET attrs = ?, content_hash = ?, last_seen = ?, "
                        "last_run_id = ?, status = 'active', stage = ?, input_key = ?, "
                        "raw_ref = CASE WHEN ? THEN raw_ref ELSE ? END, "
                        "source_tool = CASE WHEN ? THEN source_tool ELSE ? END, "
                        "tool_version = CASE WHEN ? THEN tool_version ELSE ? END "
                        "WHERE id = ?",
                        (
                            json.dumps(attrs, sort_keys=True, default=str),
                            content_hash(attrs),
                            now,
                            run_id,
                            stage,
                            input_key,
                            bool(touched),
                            ref,
                            bool(touched),
                            record.source_tool,
                            bool(touched),
                            tool_version,
                            rid,
                        ),
                    )
                    prev_hash, prev_status = existing["content_hash"], existing["status"]
                if not touched:
                    cur.execute(
                        "INSERT INTO run_touch (run_id, record_id, prev_hash, prev_status) "
                        "VALUES (?, ?, ?, ?)",
                        (run_id, rid, prev_hash, prev_status),
                    )
                cur.execute(
                    "INSERT OR REPLACE INTO observations (record_id, run_id, source_tool, "
                    "tool_version, observed_at, raw_ref) VALUES (?, ?, ?, ?, ?, ?)",
                    (rid, run_id, record.source_tool, tool_version, now, ref),
                )
                written += 1
        return written

    def complete_inputs(
        self,
        run_id: str,
        engagement: str,
        stage: str,
        inputs: dict[str, str],
        *,
        tool_versions: str,
        retire: bool = True,
    ) -> int:
        """Mark ``{input_key: input_hash}`` processed and retire what they no longer produce.

        A record is marked ``gone`` only when the exact input that produced it
        was re-processed in this run and did not report it again. Inputs
        skipped by the cache are never passed here, so their records stay.
        With ``retire=False`` only the cache is updated (discovery stages,
        whose records accumulate). Returns the number of records retired.
        """
        removed = 0
        now = time.time()
        with self._tx() as cur:
            for input_key, input_hash in inputs.items():
                cur.execute(
                    "INSERT OR REPLACE INTO stage_cache (engagement, stage, input_key, input_hash, "
                    "tool_versions, run_id, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (engagement, stage, input_key, input_hash, tool_versions, run_id, now),
                )
                if not retire:
                    continue
                stale = cur.execute(
                    "SELECT id, content_hash FROM records WHERE engagement = ? AND stage = ? "
                    "AND input_key = ? AND status = 'active' AND last_run_id != ?",
                    (engagement, stage, input_key, run_id),
                ).fetchall()
                for row in stale:
                    cur.execute("UPDATE records SET status = 'gone' WHERE id = ?", (row["id"],))
                    cur.execute(
                        "INSERT OR REPLACE INTO diffs (run_id, record_id, engagement, change, "
                        "prev_hash, new_hash) VALUES (?, ?, ?, 'removed', ?, NULL)",
                        (run_id, row["id"], engagement, row["content_hash"]),
                    )
                    removed += 1
        return removed

    def cached_keys(self, engagement: str, stage: str) -> list[str]:
        """Every input this stage has processed for the engagement."""
        rows = self._db.execute(
            "SELECT input_key FROM stage_cache WHERE engagement = ? AND stage = ?",
            (engagement, stage),
        ).fetchall()
        return [row["input_key"] for row in rows]

    def retire_input(self, run_id: str, engagement: str, stage: str, input_key: str) -> int:
        """Retire everything a stage produced for an input that no longer exists.

        Used when an upstream fact disappears (a host stops resolving, a
        service goes away): the input is not a candidate any more, so nothing
        would otherwise re-process it. Returns the number of records retired.
        """
        removed = 0
        with self._tx() as cur:
            rows = cur.execute(
                "SELECT id, content_hash FROM records WHERE engagement = ? AND stage = ? "
                "AND input_key = ? AND status = 'active'",
                (engagement, stage, input_key),
            ).fetchall()
            for row in rows:
                cur.execute("UPDATE records SET status = 'gone' WHERE id = ?", (row["id"],))
                cur.execute(
                    "INSERT OR REPLACE INTO diffs (run_id, record_id, engagement, change, "
                    "prev_hash, new_hash) VALUES (?, ?, ?, 'removed', ?, NULL)",
                    (run_id, row["id"], engagement, row["content_hash"]),
                )
                removed += 1
            cur.execute(
                "DELETE FROM stage_cache WHERE engagement = ? AND stage = ? AND input_key = ?",
                (engagement, stage, input_key),
            )
        return removed

    def cached_input(self, engagement: str, stage: str, input_key: str) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT input_hash, tool_versions, completed_at, run_id FROM stage_cache "
            "WHERE engagement = ? AND stage = ? AND input_key = ?",
            (engagement, stage, input_key),
        ).fetchone()
        return dict(row) if row else None

    def invalidate_asset(self, engagement: str, asset: str) -> int:
        """Forget cache entries for ``asset`` so the next run re-processes it."""
        with self._tx() as cur:
            cur.execute(
                "DELETE FROM stage_cache WHERE engagement = ? AND (input_key = ? OR input_key LIKE ? "
                "ESCAPE '\\' OR input_key LIKE ? ESCAPE '\\')",
                (
                    engagement,
                    asset,
                    f"%://{_like_escape(asset)}%",
                    f"{_like_escape(asset)}:%",
                ),
            )
            return cur.rowcount

    def log_scope_drop(
        self,
        run_id: str,
        engagement: str,
        *,
        stage: str,
        tool: str,
        direction: str,
        candidate: str,
        reason: str,
    ) -> None:
        with self._tx() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO scope_drops (run_id, engagement, stage, tool, direction, "
                "candidate, reason, dropped_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, engagement, stage, tool, direction, candidate[:2048], reason, time.time()),
            )

    def register_raw_output(self, ref: str, **fields: Any) -> None:
        with self._tx() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO raw_outputs (ref, run_id, engagement, stage, tool, "
                "tool_version, argv, sha256, bytes, exit_code, started_at, finished_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ref,
                    fields["run_id"],
                    fields["engagement"],
                    fields["stage"],
                    fields["tool"],
                    fields.get("tool_version", ""),
                    json.dumps(fields.get("argv", [])),
                    fields.get("sha256", ""),
                    int(fields.get("bytes", 0)),
                    fields.get("exit_code"),
                    fields["started_at"],
                    fields["finished_at"],
                ),
            )

    # ── queries ──────────────────────────────────────────────────────

    def _to_record(self, row: sqlite3.Row, sources: tuple[str, ...] = ()) -> StoredRecord:
        return StoredRecord(
            id=row["id"],
            engagement=row["engagement"],
            asset=row["asset"],
            type=row["type"],
            value=row["value"],
            attrs=json.loads(row["attrs"] or "{}"),
            source_tool=row["source_tool"],
            tool_version=row["tool_version"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            first_run_id=row["first_run_id"],
            last_run_id=row["last_run_id"],
            raw_ref=row["raw_ref"],
            content_hash=row["content_hash"],
            status=row["status"],
            sources=sources,
        )

    def _sources(self, record_id: str) -> tuple[str, ...]:
        rows = self._db.execute(
            "SELECT DISTINCT source_tool FROM observations WHERE record_id = ? ORDER BY source_tool",
            (record_id,),
        ).fetchall()
        return tuple(row["source_tool"] for row in rows)

    def query_records(
        self,
        engagement: str,
        *,
        record_type: str | None = None,
        asset: str | None = None,
        contains: str | None = None,
        status: str | None = "active",
        limit: int = 100,
        offset: int = 0,
    ) -> list[StoredRecord]:
        clauses, params = ["engagement = ?"], [engagement]
        if record_type:
            clauses.append("type = ?")
            params.append(record_type)
        if asset:
            clauses.append("asset = ?")
            params.append(asset)
        if contains:
            clauses.append("value LIKE ? ESCAPE '\\'")
            params.append(f"%{_like_escape(contains)}%")
        if status:
            clauses.append("status = ?")
            params.append(status)
        params += [max(1, min(int(limit), 1000)), max(0, int(offset))]
        rows = self._db.execute(
            f"SELECT {_RECORD_COLUMNS} FROM records WHERE {' AND '.join(clauses)} "  # noqa: S608
            "ORDER BY type, asset, value LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [self._to_record(row, self._sources(row["id"])) for row in rows]

    def count_records(self, engagement: str, *, status: str = "active") -> dict[str, int]:
        rows = self._db.execute(
            "SELECT type, COUNT(*) AS n FROM records WHERE engagement = ? AND status = ? "
            "GROUP BY type ORDER BY type",
            (engagement, status),
        ).fetchall()
        return {row["type"]: row["n"] for row in rows}

    def get_record(self, engagement: str, record_id: str) -> dict[str, Any] | None:
        row = self._db.execute(
            f"SELECT {_RECORD_COLUMNS} FROM records WHERE id = ? AND engagement = ?",  # noqa: S608
            (record_id, engagement),
        ).fetchone()
        if row is None:
            return None
        data = self._to_record(row, self._sources(record_id)).to_dict()
        data["observations"] = [
            dict(obs)
            for obs in self._db.execute(
                "SELECT run_id, source_tool, tool_version, observed_at, raw_ref FROM observations "
                "WHERE record_id = ? ORDER BY observed_at DESC LIMIT 50",
                (record_id,),
            )
        ]
        return data

    def list_assets(self, engagement: str, *, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT asset, COUNT(*) AS records, COUNT(DISTINCT type) AS types, "
            "MAX(last_seen) AS last_seen FROM records WHERE engagement = ? AND status = 'active' "
            "GROUP BY asset ORDER BY asset LIMIT ?",
            (engagement, max(1, min(limit, 5000))),
        ).fetchall()
        return [dict(row) for row in rows]

    def diff(self, engagement: str, run_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT d.change, r.type, r.asset, r.value, r.source_tool, d.record_id "
            "FROM diffs d JOIN records r ON r.id = d.record_id "
            "WHERE d.run_id = ? AND d.engagement = ? ORDER BY d.change, r.type, r.asset, r.value "
            "LIMIT ?",
            (run_id, engagement, max(1, min(limit, 5000))),
        ).fetchall()
        return [dict(row) for row in rows]

    def scope_drops(
        self, engagement: str, *, run_id: str | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        clauses, params = ["engagement = ?"], [engagement]
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        params.append(max(1, min(limit, 5000)))
        rows = self._db.execute(
            "SELECT run_id, stage, tool, direction, candidate, reason, dropped_at FROM scope_drops "  # noqa: S608
            f"WHERE {' AND '.join(clauses)} ORDER BY id LIMIT ?",
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def raw_output(self, engagement: str, ref: str) -> dict[str, Any] | None:
        base = ref.split("#", 1)[0]
        row = self._db.execute(
            "SELECT * FROM raw_outputs WHERE ref = ? AND engagement = ?", (base, engagement)
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["argv"] = json.loads(data.get("argv") or "[]")
        return data

    # ── re-run requests ──────────────────────────────────────────────

    def add_rerun_request(
        self,
        engagement: str,
        asset: str,
        *,
        requested_by: str,
        reason: str,
        status: str,
        detail: str,
    ) -> str:
        request_id = f"rerun-{uuid.uuid4().hex[:12]}"
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO rerun_requests (id, engagement, asset, requested_by, reason, status, "
                "detail, requested_at, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    engagement,
                    asset,
                    requested_by[:128],
                    reason[:1000],
                    status,
                    detail[:1000],
                    time.time(),
                    None if status == "pending" else time.time(),
                ),
            )
        return request_id

    def pending_reruns(self, engagement: str | None = None) -> list[dict[str, Any]]:
        if engagement:
            rows = self._db.execute(
                "SELECT * FROM rerun_requests WHERE status = 'pending' AND engagement = ? "
                "ORDER BY requested_at",
                (engagement,),
            ).fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM rerun_requests WHERE status = 'pending' ORDER BY requested_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def resolve_rerun(self, request_id: str, *, status: str, detail: str, run_id: str = "") -> None:
        with self._tx() as cur:
            cur.execute(
                "UPDATE rerun_requests SET status = ?, detail = ?, run_id = ?, decided_at = ? "
                "WHERE id = ?",
                (status, detail[:1000], run_id, time.time(), request_id),
            )

    def get_rerun(self, engagement: str, request_id: str) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT * FROM rerun_requests WHERE id = ? AND engagement = ?", (request_id, engagement)
        ).fetchone()
        return dict(row) if row else None


__all__ = ["ReconStore", "StoreError"]
