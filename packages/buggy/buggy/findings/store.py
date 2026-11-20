"""SQLite store for findings and their history (``findings.sqlite3``, rollback journal).

Two tables: ``findings`` holds one row per finding id; ``finding_events`` is an
append-only history (who did what, when). Triggers reject any UPDATE or DELETE
on the history, so it cannot be rewritten through this connection or another.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

from buggy.findings.model import (
    GRADES,
    STATUSES,
    Assertion,
    Expect,
    Finding,
    Status,
    empty_verification,
)
from buggy.findings.model import finding_id as compute_finding_id

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement TEXT NOT NULL,
    title TEXT NOT NULL,
    class TEXT NOT NULL,
    cwe TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    parameter TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    assertions TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'candidate',
    verification TEXT NOT NULL DEFAULT '{}',
    grade TEXT,
    grade_reasons TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_engagement ON findings (engagement, status);
CREATE TABLE IF NOT EXISTS finding_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    engagement TEXT NOT NULL,
    at REAL NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS finding_events_finding ON finding_events (engagement, id, seq);
CREATE TRIGGER IF NOT EXISTS finding_events_no_update BEFORE UPDATE ON finding_events
BEGIN
    SELECT RAISE(ABORT, 'finding_events is append-only');
END;
CREATE TRIGGER IF NOT EXISTS finding_events_no_delete BEFORE DELETE ON finding_events
BEGIN
    SELECT RAISE(ABORT, 'finding_events is append-only');
END;
"""

# A decided finding does not go back in the queue.
_NEVER_BACK_TO_CANDIDATE = frozenset({Status.DISCARDED.value, Status.EXPLOIT_VERIFIED.value})


class IllegalTransition(ValueError):
    """The requested status change is not allowed."""


class FindingNotFound(LookupError):
    """No such finding in this engagement."""


def check_transition(current: str, new: str) -> None:
    """Raise :class:`IllegalTransition` unless ``current -> new`` is allowed."""
    if new not in STATUSES:
        raise IllegalTransition(f"unknown status {new!r}")
    if new == Status.CANDIDATE.value and current in _NEVER_BACK_TO_CANDIDATE:
        raise IllegalTransition(f"a {current} finding cannot go back to candidate")


def _expect_from(raw: Any) -> Expect:
    raw = raw if isinstance(raw, dict) else {}
    status = raw.get("status")
    return Expect(
        status=tuple(status) if isinstance(status, list) else status,
        body_contains=tuple(raw.get("body_contains") or ()),
        body_not_contains=tuple(raw.get("body_not_contains") or ()),
        differs_from=str(raw.get("differs_from") or ""),
        same_as=str(raw.get("same_as") or ""),
    )


class FindingStore:
    def __init__(
        self,
        path: str | Path,
        *,
        read_only: bool = False,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.RLock()
        if read_only:
            self._db = sqlite3.connect(
                f"file:{self.path}?mode=ro", uri=True, check_same_thread=False, isolation_level=None
            )
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(
                self.path, check_same_thread=False, timeout=30, isolation_level=None
            )
            # Rollback journal (not WAL): one file, readable from a read-only mount.
            self._db.execute("PRAGMA journal_mode=DELETE").fetchone()
            self._db.executescript(_SCHEMA)
        self._db.row_factory = sqlite3.Row

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Cursor]:
        """One write transaction: the read that decides and the write that follows are atomic."""
        with self._lock:
            cursor = self._db.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            try:
                yield cursor
                cursor.execute("COMMIT")
            except BaseException:
                cursor.execute("ROLLBACK")
                raise
            finally:
                cursor.close()

    # ── rows ────────────────────────────────────────────────────────

    @staticmethod
    def _row(row: sqlite3.Row) -> Finding:
        verification = json.loads(row["verification"] or "{}")
        if not isinstance(verification, dict):
            verification = {}
        return Finding(
            id=row["id"],
            engagement=row["engagement"],
            title=row["title"],
            vuln_class=row["class"],
            cwe=row["cwe"],
            severity=row["severity"],
            endpoint=row["endpoint"],
            method=row["method"],
            parameter=row["parameter"],
            source=row["source"],
            description=row["description"],
            remediation=row["remediation"],
            assertions=tuple(
                Assertion(
                    capture_id=str(item.get("capture_id") or ""),
                    identity=str(item.get("identity") or ""),
                    expect=_expect_from(item.get("expect")),
                )
                for item in json.loads(row["assertions"] or "[]")
            ),
            status=row["status"],
            verification={**empty_verification(), **verification},
            grade=row["grade"],
            grade_reasons=tuple(json.loads(row["grade_reasons"] or "[]")),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _select(cursor: sqlite3.Cursor, engagement: str, finding_id_: str) -> Finding | None:
        row = cursor.execute(
            "SELECT * FROM findings WHERE id = ? AND engagement = ?", (finding_id_, engagement)
        ).fetchone()
        return FindingStore._row(row) if row else None

    @staticmethod
    def _append_event(
        cursor: sqlite3.Cursor,
        engagement: str,
        finding_id_: str,
        at: float,
        actor: str,
        event: str,
        detail: dict[str, Any] | None,
    ) -> None:
        cursor.execute(
            "INSERT INTO finding_events (id, engagement, at, actor, event, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                finding_id_,
                engagement,
                at,
                actor,
                event,
                json.dumps(detail or {}, sort_keys=True, default=str),
            ),
        )

    @staticmethod
    def _actor(actor: str) -> str:
        name = (actor or "").strip() if isinstance(actor, str) else ""
        if not name:
            raise ValueError("actor is required: every change to a finding names who made it")
        return name[:200]

    # ── writes ──────────────────────────────────────────────────────

    def upsert(
        self,
        finding: Finding,
        actor: str,
        *,
        event: str = "",
        detail: dict[str, Any] | None = None,
    ) -> Finding:
        """Insert the finding, or replace the stored one with the same id.

        ``created_at`` is kept from the first insert; ``updated_at`` is set
        now. The status change, if any, must be a legal transition. One event
        is appended (``created`` / ``updated`` unless ``event`` names it).
        """
        who = self._actor(actor)
        expected = compute_finding_id(
            finding.engagement, finding.vuln_class, finding.endpoint, finding.parameter
        )
        if finding.id != expected:
            raise ValueError(f"finding id {finding.id!r} does not match its content ({expected})")
        if finding.status not in STATUSES:
            raise IllegalTransition(f"unknown status {finding.status!r}")
        if finding.grade is not None and finding.grade not in GRADES:
            raise ValueError(f"unknown grade {finding.grade!r}")
        now = self._clock()
        with self._tx() as cur:
            existing = self._select(cur, finding.engagement, finding.id)
            if existing is not None:
                check_transition(existing.status, finding.status)
            created_at = existing.created_at if existing is not None else now
            cur.execute(
                "INSERT INTO findings (id, engagement, title, class, cwe, severity, endpoint, "
                "method, parameter, source, description, remediation, assertions, status, "
                "verification, grade, grade_reasons, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET title = excluded.title, class = excluded.class, "
                "cwe = excluded.cwe, severity = excluded.severity, endpoint = excluded.endpoint, "
                "method = excluded.method, parameter = excluded.parameter, "
                "source = excluded.source, description = excluded.description, "
                "remediation = excluded.remediation, assertions = excluded.assertions, "
                "status = excluded.status, verification = excluded.verification, "
                "grade = excluded.grade, grade_reasons = excluded.grade_reasons, "
                "updated_at = excluded.updated_at WHERE findings.engagement = excluded.engagement",
                (
                    finding.id,
                    finding.engagement,
                    finding.title,
                    finding.vuln_class,
                    finding.cwe,
                    finding.severity,
                    finding.endpoint,
                    finding.method,
                    finding.parameter,
                    finding.source,
                    finding.description,
                    finding.remediation,
                    json.dumps([a.to_dict() for a in finding.assertions], sort_keys=True),
                    finding.status,
                    json.dumps(finding.to_dict()["verification"], sort_keys=True),
                    finding.grade,
                    json.dumps(list(finding.grade_reasons)),
                    created_at,
                    now,
                ),
            )
            if cur.rowcount != 1:
                raise ValueError(f"finding id {finding.id!r} belongs to another engagement")
            self._append_event(
                cur,
                finding.engagement,
                finding.id,
                now,
                who,
                event or ("created" if existing is None else "updated"),
                {
                    "status": finding.status,
                    "previous_status": existing.status if existing is not None else None,
                    "assertions": len(finding.assertions),
                    "source": finding.source,
                    **(detail or {}),
                },
            )
        return replace(finding, created_at=created_at, updated_at=now)

    def set_status(
        self,
        engagement: str,
        finding_id: str,
        status: str,
        *,
        actor: str,
        verification: dict[str, Any] | None = None,
        detail: dict[str, Any] | None = None,
    ) -> Finding:
        """Change a finding's status (and, when given, its verification record).

        Raises :class:`IllegalTransition` for ``discarded``/``exploit_verified``
        back to ``candidate`` and :class:`FindingNotFound` for an unknown id.
        Nothing is written when it raises.
        """
        who = self._actor(actor)
        now = self._clock()
        with self._tx() as cur:
            existing = self._select(cur, engagement, finding_id)
            if existing is None:
                raise FindingNotFound(f"no finding {finding_id!r} in engagement {engagement!r}")
            check_transition(existing.status, status)
            record = existing.verification if verification is None else verification
            updated = replace(existing, status=status, verification=record, updated_at=now)
            cur.execute(
                "UPDATE findings SET status = ?, verification = ?, updated_at = ? "
                "WHERE id = ? AND engagement = ?",
                (
                    status,
                    json.dumps(updated.to_dict()["verification"], sort_keys=True),
                    now,
                    finding_id,
                    engagement,
                ),
            )
            self._append_event(
                cur,
                engagement,
                finding_id,
                now,
                who,
                "status",
                {"from": existing.status, "to": status, **(detail or {})},
            )
        return self._require(engagement, finding_id)

    def add_event(
        self,
        engagement: str,
        finding_id: str,
        actor: str,
        event: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Append one history line for an existing finding."""
        who = self._actor(actor)
        if not event:
            raise ValueError("event name is required")
        with self._tx() as cur:
            if self._select(cur, engagement, finding_id) is None:
                raise FindingNotFound(f"no finding {finding_id!r} in engagement {engagement!r}")
            self._append_event(cur, engagement, finding_id, self._clock(), who, event, detail)

    # ── reads ───────────────────────────────────────────────────────

    def get(self, engagement: str, finding_id: str) -> Finding | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM findings WHERE id = ? AND engagement = ?", (finding_id, engagement)
            ).fetchone()
        return self._row(row) if row else None

    def _require(self, engagement: str, finding_id: str) -> Finding:
        found = self.get(engagement, finding_id)
        if found is None:
            raise FindingNotFound(f"no finding {finding_id!r} in engagement {engagement!r}")
        return found

    def list(
        self, engagement: str, *, status: str | None = None, grade: str | None = None
    ) -> list[Finding]:
        """Findings of one engagement, oldest first, optionally filtered by status and grade."""
        clauses = ["engagement = ?"]
        params: list[Any] = [engagement]
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if grade is not None:
            clauses.append("grade = ?")
            params.append(grade)
        with self._lock:
            rows = self._db.execute(
                f"SELECT * FROM findings WHERE {' AND '.join(clauses)} "  # noqa: S608
                "ORDER BY created_at, id",
                params,
            ).fetchall()
        return [self._row(row) for row in rows]

    def events(self, engagement: str, finding_id: str) -> list[dict[str, Any]]:
        """The finding's history, oldest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, id, at, actor, event, detail FROM finding_events "
                "WHERE engagement = ? AND id = ? ORDER BY seq",
                (engagement, finding_id),
            ).fetchall()
        return [
            {
                "seq": row["seq"],
                "id": row["id"],
                "at": row["at"],
                "actor": row["actor"],
                "event": row["event"],
                "detail": json.loads(row["detail"] or "{}"),
            }
            for row in rows
        ]


__all__ = [
    "FindingNotFound",
    "FindingStore",
    "IllegalTransition",
    "check_transition",
]
