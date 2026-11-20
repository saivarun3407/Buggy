"""Fact / intent / hint board: workers coordinate through shared state, not chat.

One SQLite file (``board.sqlite3``) holds, per engagement:

* **Facts** - what is known. Append-only: there is no update or delete call,
  and the file itself refuses ``UPDATE`` and ``DELETE`` on the facts table.
  The same text twice is one fact.
* **Intents** - work somebody proposed, linking the facts it starts from to
  the fact it ends in. A worker *claims* an intent and keeps the claim alive
  with heartbeats; while the lease is live any other worker gets
  :class:`Conflict`. Concluding writes the resulting fact and the link to it
  in one transaction. Abandoning writes the dead end as a fact too.
* **Hints** - out-of-band guidance from the operator or an agent. A hint is
  never a fact and changes nothing else on the board.

Every mutating call is one ``BEGIN IMMEDIATE`` transaction, so a claim is
decided by SQLite and holds across threads, connections and processes. Ids
(``f0001``, ``i0001``, ``h0001``) are numbered per engagement, and every read
and write is keyed by the engagement: nothing crosses from one to another.

Time comes from the ``clock`` given to :class:`Board`; each call also accepts
``now`` for a caller that owns the clock (tests, a scheduler). ``now`` and
``worker`` are trusted inputs: whoever exposes this to agents must set both
itself and never take them from the agent.

Standard library only; everything returned is a JSON-serialisable dict.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
import time
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

DB_FILENAME = "board.sqlite3"

FACT_KINDS = ("observation", "result", "origin", "goal")
OBSERVATION, RESULT, ORIGIN, GOAL = FACT_KINDS

INTENT_STATUSES = ("open", "claimed", "concluded", "abandoned")
OPEN, CLAIMED, CONCLUDED, ABANDONED = INTENT_STATUSES

HINT_AUTHORS = ("operator", "agent")

DEFAULT_INTENT_TIMEOUT = 600.0
MAX_FACT_CHARS = 500
MAX_INTENT_CHARS = 500
MAX_HINT_CHARS = 1000
MAX_EVIDENCE = 50
MAX_FROM_FACTS = 50

ABANDONED_PREFIX = "abandoned: "
REOPENED_PREFIX = "reopened: "
COMPLETE_PREFIX = "complete: "

# Statuses of an intent that is not finished.
_LIVE = (OPEN, CLAIMED)


class BoardError(ValueError):
    """A call the board cannot carry out as given. ``code`` names the reason."""

    code = "invalid"

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "detail": str(self)}


class NotFound(BoardError):
    """The fact or intent does not exist in this engagement."""

    code = "not_found"


class Conflict(BoardError):
    """Another worker holds a live claim on the intent (the 409 case)."""

    code = "conflict"

    def __init__(
        self,
        detail: str,
        *,
        intent_id: str = "",
        worker: str = "",
        lease_expires_at: float | None = None,
    ) -> None:
        super().__init__(detail)
        self.intent_id = intent_id
        self.worker = worker
        self.lease_expires_at = lease_expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            **super().to_dict(),
            "intent_id": self.intent_id,
            "worker": self.worker,
            "lease_expires_at": self.lease_expires_at,
        }


class NotClaimer(BoardError):
    """The caller does not hold the claim this call needs."""

    code = "not_claimer"


class Closed(BoardError):
    """The intent is already concluded or abandoned, or the engagement is already complete."""

    code = "closed"


# ── model ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Fact:
    id: str
    engagement: str
    text: str
    kind: str
    evidence: tuple[str, ...]
    created_by: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence"] = list(self.evidence)
        return data


@dataclass(frozen=True, slots=True)
class Intent:
    id: str
    engagement: str
    text: str
    from_facts: tuple[str, ...]
    to_fact: str | None
    creator: str
    worker: str | None
    last_heartbeat_at: float | None
    status: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["from_facts"] = list(self.from_facts)
        return data


@dataclass(frozen=True, slots=True)
class Hint:
    id: str
    engagement: str
    text: str
    author: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── validation ──────────────────────────────────────────────────────────

_SLUG = re.compile(r"[A-Za-z0-9_.:@-]{1,100}")
_REFERENCE = re.compile(r"[^\s\x00-\x1f\x7f]{1,200}")
_FACT_ID = re.compile(r"f(\d{4,})")
_INTENT_ID = re.compile(r"i(\d{4,})")
_TRAILING_PUNCTUATION = ".!?;:,"


def _slug(value: Any, name: str) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not _SLUG.fullmatch(text):
        raise BoardError(f"{name} is required (letters, digits and _.:@- only)")
    return text


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise BoardError(f"{name} must be a string")
    text = value.strip()
    if not text:
        raise BoardError(f"{name} is required")
    if len(text) > limit:
        raise BoardError(f"{name} is longer than {limit} characters")
    return text


def _strings(values: Any, name: str, limit: int) -> list[str]:
    """A list of distinct strings, in the order given. One string is a list of one."""
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, Iterable):
        raise BoardError(f"{name} must be a list of strings")
    kept: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise BoardError(f"{name} must be a list of strings")
        item = value.strip()
        if item and item not in kept:
            kept.append(item)
    if len(kept) > limit:
        raise BoardError(f"{name} has more than {limit} entries")
    return kept


def _evidence(values: Any) -> list[str]:
    kept = _strings(values, "evidence", MAX_EVIDENCE)
    for item in kept:
        if not _REFERENCE.fullmatch(item):
            raise BoardError("evidence entries are capture or record ids (no spaces, <= 200 chars)")
    return kept


def _fact_id(number: int) -> str:
    return f"f{number:04d}"


def _intent_id(number: int) -> str:
    return f"i{number:04d}"


def _hint_id(number: int) -> str:
    return f"h{number:04d}"


def _number(value: Any, pattern: re.Pattern[str], make: Callable[[int], str]) -> int | None:
    """The number inside a canonical id (``f0007`` -> 7); ``None`` for anything else."""
    if not isinstance(value, str):
        return None
    match = pattern.fullmatch(value.strip())
    if match is None:
        return None
    number = int(match.group(1))
    return number if number >= 1 and make(number) == value.strip() else None


def normalise_intent_text(text: str) -> str:
    """The form two intent texts are compared in: case, spacing and a trailing
    full stop do not make a different intent. Anything else does."""
    folded = " ".join(unicodedata.normalize("NFKC", text).casefold().split())
    return folded.rstrip(_TRAILING_PUNCTUATION).rstrip()


# ── store ───────────────────────────────────────────────────────────────

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS facts (
        engagement TEXT NOT NULL,
        n INTEGER NOT NULL,
        text TEXT NOT NULL,
        kind TEXT NOT NULL,
        evidence TEXT NOT NULL DEFAULT '[]',
        created_by TEXT NOT NULL,
        created_at REAL NOT NULL,
        PRIMARY KEY (engagement, n),
        UNIQUE (engagement, text)
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS facts_no_update BEFORE UPDATE ON facts
    BEGIN SELECT RAISE(ABORT, 'facts are append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS facts_no_delete BEFORE DELETE ON facts
    BEGIN SELECT RAISE(ABORT, 'facts are append-only'); END
    """,
    """
    CREATE TABLE IF NOT EXISTS intents (
        engagement TEXT NOT NULL,
        n INTEGER NOT NULL,
        text TEXT NOT NULL,
        norm_text TEXT NOT NULL,
        from_facts TEXT NOT NULL,
        from_key TEXT NOT NULL,
        to_fact TEXT,
        creator TEXT NOT NULL,
        worker TEXT,
        last_heartbeat_at REAL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at REAL NOT NULL,
        PRIMARY KEY (engagement, n)
    )
    """,
    "CREATE INDEX IF NOT EXISTS intents_status ON intents (engagement, status)",
    """
    CREATE TABLE IF NOT EXISTS hints (
        engagement TEXT NOT NULL,
        n INTEGER NOT NULL,
        text TEXT NOT NULL,
        author TEXT NOT NULL,
        created_at REAL NOT NULL,
        PRIMARY KEY (engagement, n)
    )
    """,
    # The standing completion of an engagement: set by complete(), cleared by reopen().
    """
    CREATE TABLE IF NOT EXISTS boards (
        engagement TEXT PRIMARY KEY,
        goal_fact TEXT,
        goal_intent TEXT,
        reopened INTEGER NOT NULL DEFAULT 0
    )
    """,
)


class Board:
    """The board file. ``intent_timeout`` is the claim lease in seconds."""

    def __init__(
        self,
        path: str | Path,
        *,
        intent_timeout: float = DEFAULT_INTENT_TIMEOUT,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not intent_timeout > 0:
            raise ValueError("intent_timeout must be positive")
        self.path = Path(path)
        self.intent_timeout = float(intent_timeout)
        self._clock = clock
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Autocommit connection: transactions are opened explicitly in _tx so a
        # write takes the file lock *before* it reads what it is about to change.
        # Rollback-journal mode (the SQLite default), as the other stores use.
        self._db = sqlite3.connect(
            self.path, check_same_thread=False, timeout=30, isolation_level=None
        )
        self._db.row_factory = sqlite3.Row
        with self._tx() as cur:
            for statement in _SCHEMA:
                cur.execute(statement)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextmanager
    def _tx(self, *, write: bool = True) -> Iterator[sqlite3.Cursor]:
        """One transaction. A write takes the lock up front (``BEGIN IMMEDIATE``);
        anything raised inside rolls the whole call back."""
        with self._lock:
            cursor = self._db.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield cursor
                cursor.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.rollback()
                raise
            finally:
                cursor.close()

    def _now(self, now: float | None) -> float:
        value = self._clock() if now is None else now
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BoardError("now must be a number (seconds since the epoch)")
        if not math.isfinite(value):
            raise BoardError("now must be a finite number")
        return float(value)

    # ── rows ────────────────────────────────────────────────────────

    @staticmethod
    def _fact(row: sqlite3.Row) -> dict[str, Any]:
        return Fact(
            id=_fact_id(row["n"]),
            engagement=row["engagement"],
            text=row["text"],
            kind=row["kind"],
            evidence=tuple(json.loads(row["evidence"] or "[]")),
            created_by=row["created_by"],
            created_at=row["created_at"],
        ).to_dict()

    def _lease_end(self, row: sqlite3.Row) -> float | None:
        if row["status"] != CLAIMED or row["last_heartbeat_at"] is None:
            return None
        return float(row["last_heartbeat_at"]) + self.intent_timeout

    def _expired(self, row: sqlite3.Row, at: float) -> bool:
        end = self._lease_end(row)
        return end is not None and at >= end

    def _intent(self, row: sqlite3.Row, at: float) -> dict[str, Any]:
        """The intent plus two derived fields: when its lease ends and whether it has."""
        data = Intent(
            id=_intent_id(row["n"]),
            engagement=row["engagement"],
            text=row["text"],
            from_facts=tuple(json.loads(row["from_facts"] or "[]")),
            to_fact=row["to_fact"],
            creator=row["creator"],
            worker=row["worker"],
            last_heartbeat_at=row["last_heartbeat_at"],
            status=row["status"],
            created_at=row["created_at"],
        ).to_dict()
        data["lease_expires_at"] = self._lease_end(row)
        data["expired"] = self._expired(row, at)
        return data

    @staticmethod
    def _hint(row: sqlite3.Row) -> dict[str, Any]:
        return Hint(
            id=_hint_id(row["n"]),
            engagement=row["engagement"],
            text=row["text"],
            author=row["author"],
            created_at=row["created_at"],
        ).to_dict()

    @staticmethod
    def _next(cur: sqlite3.Cursor, table: str, engagement: str) -> int:
        # ``table`` is one of three literals below, never caller input.
        row = cur.execute(
            f"SELECT COALESCE(MAX(n), 0) + 1 FROM {table} WHERE engagement = ?",  # noqa: S608
            (engagement,),
        ).fetchone()
        return int(row[0])

    # ── facts ───────────────────────────────────────────────────────

    def _write_fact(
        self,
        cur: sqlite3.Cursor,
        engagement: str,
        text: str,
        kind: str,
        evidence: list[str],
        created_by: str,
        at: float,
    ) -> tuple[dict[str, Any], bool]:
        """Insert the fact, or return the one that already has this text.
        The second value says whether it already existed."""
        existing = cur.execute(
            "SELECT * FROM facts WHERE engagement = ? AND text = ?", (engagement, text)
        ).fetchone()
        if existing is not None:
            return self._fact(existing), True
        number = self._next(cur, "facts", engagement)
        cur.execute(
            "INSERT INTO facts (engagement, n, text, kind, evidence, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (engagement, number, text, kind, json.dumps(evidence), created_by, at),
        )
        row = cur.execute(
            "SELECT * FROM facts WHERE engagement = ? AND n = ?", (engagement, number)
        ).fetchone()
        return self._fact(row), False

    def add_fact(
        self,
        engagement: str,
        text: str,
        created_by: str,
        *,
        kind: str = OBSERVATION,
        evidence: Iterable[str] = (),
        now: float | None = None,
    ) -> dict[str, Any]:
        """Record a fact and return it; ``duplicate`` says whether it already existed.

        A text the engagement already holds returns the existing fact (same
        ``id``, ``duplicate: true``) and stores nothing: the first fact keeps
        its kind, evidence and author. A ``goal`` fact is written only by
        :meth:`complete`.
        """
        engagement = _slug(engagement, "engagement")
        created_by = _slug(created_by, "created_by")
        text = _text(text, "fact text", MAX_FACT_CHARS)
        if kind not in FACT_KINDS:
            raise BoardError(f"fact kind must be one of {', '.join(FACT_KINDS)}")
        if kind == GOAL:
            raise BoardError("a goal fact is written by complete(), not add_fact()")
        references = _evidence(evidence)
        with self._tx() as cur:
            fact, duplicate = self._write_fact(
                cur, engagement, text, kind, references, created_by, self._now(now)
            )
        return {**fact, "duplicate": duplicate}

    def get_fact(self, engagement: str, fact_id: str) -> dict[str, Any] | None:
        engagement = _slug(engagement, "engagement")
        number = _number(fact_id, _FACT_ID, _fact_id)
        if number is None:
            return None
        with self._tx(write=False) as cur:
            row = cur.execute(
                "SELECT * FROM facts WHERE engagement = ? AND n = ?", (engagement, number)
            ).fetchone()
        return self._fact(row) if row else None

    def facts(self, engagement: str, *, kind: str | None = None) -> list[dict[str, Any]]:
        """The engagement's facts, oldest first, optionally of one kind."""
        engagement = _slug(engagement, "engagement")
        if kind is not None and kind not in FACT_KINDS:
            raise BoardError(f"fact kind must be one of {', '.join(FACT_KINDS)}")
        with self._tx(write=False) as cur:
            return self._facts(cur, engagement, kind)

    def _facts(self, cur: sqlite3.Cursor, engagement: str, kind: str | None = None) -> list[dict]:
        if kind is None:
            rows = cur.execute(
                "SELECT * FROM facts WHERE engagement = ? ORDER BY n", (engagement,)
            ).fetchall()
        else:
            rows = cur.execute(
                "SELECT * FROM facts WHERE engagement = ? AND kind = ? ORDER BY n",
                (engagement, kind),
            ).fetchall()
        return [self._fact(row) for row in rows]

    def _source_facts(self, cur: sqlite3.Cursor, engagement: str, from_facts: Any) -> list[str]:
        """``from_facts`` checked: at least one, every one a fact of this engagement."""
        sources = _strings(from_facts, "from_facts", MAX_FROM_FACTS)
        if not sources:
            raise BoardError("an intent needs at least one fact in from_facts")
        missing: list[str] = []
        for source in sources:
            number = _number(source, _FACT_ID, _fact_id)
            found = (
                number is not None
                and cur.execute(
                    "SELECT 1 FROM facts WHERE engagement = ? AND n = ?", (engagement, number)
                ).fetchone()
            )
            if not found:
                missing.append(source)
        if missing:
            raise NotFound(f"from_facts not on this engagement's board: {', '.join(missing)}")
        return sources

    # ── intents ─────────────────────────────────────────────────────

    def _insert_intent(
        self,
        cur: sqlite3.Cursor,
        engagement: str,
        text: str,
        sources: list[str],
        creator: str,
        at: float,
        *,
        status: str = OPEN,
        worker: str | None = None,
        to_fact: str | None = None,
    ) -> sqlite3.Row:
        number = self._next(cur, "intents", engagement)
        cur.execute(
            "INSERT INTO intents (engagement, n, text, norm_text, from_facts, from_key, to_fact, "
            "creator, worker, last_heartbeat_at, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                engagement,
                number,
                text,
                normalise_intent_text(text),
                json.dumps(sources),
                json.dumps(sorted(sources)),
                to_fact,
                creator,
                worker,
                at if worker is not None else None,
                status,
                at,
            ),
        )
        return self._intent_row(cur, engagement, number)

    @staticmethod
    def _intent_row(cur: sqlite3.Cursor, engagement: str, number: int) -> sqlite3.Row:
        return cur.execute(
            "SELECT * FROM intents WHERE engagement = ? AND n = ?", (engagement, number)
        ).fetchone()

    def _unfinished(self, cur: sqlite3.Cursor, engagement: str, intent_id: Any) -> sqlite3.Row:
        """The intent's row if it exists and is not finished; raises otherwise."""
        number = _number(intent_id, _INTENT_ID, _intent_id)
        row = self._intent_row(cur, engagement, number) if number is not None else None
        if row is None:
            raise NotFound(f"no intent {intent_id!r} on this engagement's board")
        if row["status"] in (CONCLUDED, ABANDONED):
            raise Closed(f"intent {_intent_id(row['n'])} is already {row['status']}")
        return row

    def _held_by(
        self, cur: sqlite3.Cursor, engagement: str, intent_id: Any, worker: str
    ) -> sqlite3.Row:
        """The intent's row if ``worker`` is its recorded claimer; raises otherwise."""
        row = self._unfinished(cur, engagement, intent_id)
        if row["status"] != CLAIMED or row["worker"] != worker:
            holder = row["worker"] if row["status"] == CLAIMED else None
            raise NotClaimer(
                f"intent {_intent_id(row['n'])} is "
                + (f"claimed by {holder}" if holder else "not claimed")
                + f"; {worker} does not hold it"
            )
        return row

    def open_intent(
        self,
        engagement: str,
        text: str,
        from_facts: Iterable[str],
        creator: str,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Propose work that starts from ``from_facts`` (one or more existing fact ids).

        If an unfinished intent (open or claimed) already has the same
        normalised text and the same set of source facts, that intent is
        returned with ``duplicate: true`` and nothing is stored.
        """
        engagement = _slug(engagement, "engagement")
        creator = _slug(creator, "creator")
        text = _text(text, "intent text", MAX_INTENT_CHARS)
        with self._tx() as cur:
            at = self._now(now)
            sources = self._source_facts(cur, engagement, from_facts)
            existing = cur.execute(
                "SELECT * FROM intents WHERE engagement = ? AND norm_text = ? AND from_key = ? "
                "AND status IN (?, ?) ORDER BY n LIMIT 1",
                (engagement, normalise_intent_text(text), json.dumps(sorted(sources)), *_LIVE),
            ).fetchone()
            if existing is not None:
                return {**self._intent(existing, at), "duplicate": True}
            row = self._insert_intent(cur, engagement, text, sources, creator, at)
            return {**self._intent(row, at), "duplicate": False}

    def get_intent(
        self, engagement: str, intent_id: str, now: float | None = None
    ) -> dict[str, Any] | None:
        engagement = _slug(engagement, "engagement")
        number = _number(intent_id, _INTENT_ID, _intent_id)
        if number is None:
            return None
        with self._tx(write=False) as cur:
            row = self._intent_row(cur, engagement, number)
            return self._intent(row, self._now(now)) if row else None

    def intents(
        self, engagement: str, *, status: str | None = None, now: float | None = None
    ) -> list[dict[str, Any]]:
        """The engagement's intents, oldest first, optionally with one stored status."""
        engagement = _slug(engagement, "engagement")
        if status is not None and status not in INTENT_STATUSES:
            raise BoardError(f"intent status must be one of {', '.join(INTENT_STATUSES)}")
        with self._tx(write=False) as cur:
            listed = self._intents(cur, engagement, self._now(now))
        return [item for item in listed if status is None or item["status"] == status]

    def _intents(self, cur: sqlite3.Cursor, engagement: str, at: float) -> list[dict[str, Any]]:
        rows = cur.execute(
            "SELECT * FROM intents WHERE engagement = ? ORDER BY n", (engagement,)
        ).fetchall()
        return [self._intent(row, at) for row in rows]

    def claim(
        self, engagement: str, intent_id: str, worker: str, now: float | None = None
    ) -> dict[str, Any]:
        """Take the intent, or renew the claim ``worker`` already has.

        Succeeds when the intent is unclaimed, when its lease ran out
        (``intent_timeout`` seconds since the last heartbeat), or when
        ``worker`` is the claimer (then it is a heartbeat). A live claim by
        another worker raises :class:`Conflict`.
        """
        engagement = _slug(engagement, "engagement")
        worker = _slug(worker, "worker")
        with self._tx() as cur:
            at = self._now(now)
            row = self._unfinished(cur, engagement, intent_id)
            if row["status"] == CLAIMED and row["worker"] != worker and not self._expired(row, at):
                raise Conflict(
                    f"intent {_intent_id(row['n'])} is claimed by {row['worker']}",
                    intent_id=_intent_id(row["n"]),
                    worker=row["worker"],
                    lease_expires_at=self._lease_end(row),
                )
            return self._beat(cur, row, worker, at)

    def _beat(self, cur: sqlite3.Cursor, row: sqlite3.Row, worker: str, at: float) -> dict:
        """Mark ``row`` claimed by ``worker`` with a heartbeat at ``at``."""
        if row["status"] == CLAIMED and row["worker"] == worker:
            # A heartbeat never shortens the lease the worker already has.
            at_or_later = max(at, float(row["last_heartbeat_at"] or at))
        else:
            at_or_later = at
        cur.execute(
            "UPDATE intents SET status = ?, worker = ?, last_heartbeat_at = ? "
            "WHERE engagement = ? AND n = ?",
            (CLAIMED, worker, at_or_later, row["engagement"], row["n"]),
        )
        return self._intent(self._intent_row(cur, row["engagement"], row["n"]), at)

    def heartbeat(
        self, engagement: str, intent_id: str, worker: str, now: float | None = None
    ) -> dict[str, Any]:
        """Renew the lease. Only the recorded claimer may; anyone else gets
        :class:`NotClaimer` (a worker whose expired claim was taken over included)."""
        engagement = _slug(engagement, "engagement")
        worker = _slug(worker, "worker")
        with self._tx() as cur:
            row = self._held_by(cur, engagement, intent_id, worker)
            return self._beat(cur, row, worker, self._now(now))

    def release(
        self, engagement: str, intent_id: str, worker: str, now: float | None = None
    ) -> dict[str, Any]:
        """Give the claim back; the intent is open again. Only the claimer may."""
        engagement = _slug(engagement, "engagement")
        worker = _slug(worker, "worker")
        with self._tx() as cur:
            row = self._held_by(cur, engagement, intent_id, worker)
            cur.execute(
                "UPDATE intents SET status = ?, worker = NULL, last_heartbeat_at = NULL "
                "WHERE engagement = ? AND n = ?",
                (OPEN, engagement, row["n"]),
            )
            return self._intent(self._intent_row(cur, engagement, row["n"]), self._now(now))

    def _finish(
        self,
        cur: sqlite3.Cursor,
        row: sqlite3.Row,
        status: str,
        worker: str,
        fact_text: str,
        evidence: list[str],
        at: float,
    ) -> dict[str, Any]:
        """Write the closing fact, then link the intent to it. Same transaction:
        if either statement fails, neither is stored."""
        fact, duplicate = self._write_fact(
            cur, row["engagement"], fact_text, RESULT, evidence, worker, at
        )
        cur.execute(
            "UPDATE intents SET status = ?, to_fact = ?, worker = ?, last_heartbeat_at = ? "
            "WHERE engagement = ? AND n = ?",
            (status, fact["id"], worker, at, row["engagement"], row["n"]),
        )
        intent = self._intent(self._intent_row(cur, row["engagement"], row["n"]), at)
        return {"intent": intent, "fact": {**fact, "duplicate": duplicate}}

    def conclude(
        self,
        engagement: str,
        intent_id: str,
        worker: str,
        fact_text: str,
        evidence: Iterable[str] = (),
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Finish the intent: write its ``result`` fact and set ``to_fact``, atomically.

        Only the recorded claimer may conclude. A claimer whose lease ran out
        but whose intent nobody took over is still the claimer, so finished
        work is not thrown away. If the text is already a fact, the intent is
        linked to that fact (``fact.duplicate`` is true) and no second one is
        written. Returns ``{"intent": ..., "fact": ...}``.
        """
        engagement = _slug(engagement, "engagement")
        worker = _slug(worker, "worker")
        fact_text = _text(fact_text, "fact text", MAX_FACT_CHARS)
        references = _evidence(evidence)
        with self._tx() as cur:
            row = self._held_by(cur, engagement, intent_id, worker)
            return self._finish(cur, row, CONCLUDED, worker, fact_text, references, self._now(now))

    def abandon(
        self,
        engagement: str,
        intent_id: str,
        worker: str,
        reason: str,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Give the intent up for good and remember why.

        Writes the ``result`` fact ``abandoned: <reason>`` and links the intent
        to it (``to_fact``), atomically. Allowed for the claimer, and for any
        worker when the intent is unclaimed or its lease ran out; a live claim
        by another worker raises :class:`Conflict`.
        """
        engagement = _slug(engagement, "engagement")
        worker = _slug(worker, "worker")
        reason = _text(reason, "reason", MAX_FACT_CHARS - len(ABANDONED_PREFIX))
        with self._tx() as cur:
            at = self._now(now)
            row = self._unfinished(cur, engagement, intent_id)
            if row["status"] == CLAIMED and row["worker"] != worker and not self._expired(row, at):
                raise Conflict(
                    f"intent {_intent_id(row['n'])} is claimed by {row['worker']}",
                    intent_id=_intent_id(row["n"]),
                    worker=row["worker"],
                    lease_expires_at=self._lease_end(row),
                )
            return self._finish(cur, row, ABANDONED, worker, ABANDONED_PREFIX + reason, [], at)

    def open_work(self, engagement: str, now: float | None = None) -> list[dict[str, Any]]:
        """Intents a worker can claim now: unclaimed, or claimed with an expired lease."""
        engagement = _slug(engagement, "engagement")
        with self._tx(write=False) as cur:
            listed = self._intents(cur, engagement, self._now(now))
        return [item for item in listed if _claimable(item)]

    def stop(self, engagement: str) -> dict[str, Any]:
        """Clear every claim of the engagement at once. The intents are open again."""
        engagement = _slug(engagement, "engagement")
        with self._tx() as cur:
            rows = cur.execute(
                "SELECT n FROM intents WHERE engagement = ? AND status = ? ORDER BY n",
                (engagement, CLAIMED),
            ).fetchall()
            cur.execute(
                "UPDATE intents SET status = ?, worker = NULL, last_heartbeat_at = NULL "
                "WHERE engagement = ? AND status = ?",
                (OPEN, engagement, CLAIMED),
            )
        return {"engagement": engagement, "released": [_intent_id(row["n"]) for row in rows]}

    # ── hints ───────────────────────────────────────────────────────

    def add_hint(
        self, engagement: str, text: str, author: str, *, now: float | None = None
    ) -> dict[str, Any]:
        """Leave guidance for the workers. ``author`` is ``operator`` or ``agent``."""
        engagement = _slug(engagement, "engagement")
        text = _text(text, "hint text", MAX_HINT_CHARS)
        if author not in HINT_AUTHORS:
            raise BoardError(f"hint author must be one of {', '.join(HINT_AUTHORS)}")
        with self._tx() as cur:
            number = self._next(cur, "hints", engagement)
            cur.execute(
                "INSERT INTO hints (engagement, n, text, author, created_at) VALUES (?, ?, ?, ?, ?)",
                (engagement, number, text, author, self._now(now)),
            )
            row = cur.execute(
                "SELECT * FROM hints WHERE engagement = ? AND n = ?", (engagement, number)
            ).fetchone()
            return self._hint(row)

    def hints(self, engagement: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        """The engagement's hints, newest first."""
        engagement = _slug(engagement, "engagement")
        with self._tx(write=False) as cur:
            listed = self._hints(cur, engagement)
        return listed if limit is None else listed[: max(0, int(limit))]

    def _hints(self, cur: sqlite3.Cursor, engagement: str) -> list[dict[str, Any]]:
        rows = cur.execute(
            "SELECT * FROM hints WHERE engagement = ? ORDER BY n DESC", (engagement,)
        ).fetchall()
        return [self._hint(row) for row in rows]

    # ── completion ──────────────────────────────────────────────────

    @staticmethod
    def _standing(cur: sqlite3.Cursor, engagement: str) -> sqlite3.Row | None:
        return cur.execute("SELECT * FROM boards WHERE engagement = ?", (engagement,)).fetchone()

    def complete(
        self,
        engagement: str,
        worker: str,
        from_facts: Iterable[str],
        summary: str,
        *,
        evidence: Iterable[str] = (),
        now: float | None = None,
    ) -> dict[str, Any]:
        """Declare the engagement done: one transaction writes the ``goal`` fact
        (``summary``) and the concluded intent that leads to it from ``from_facts``.

        Refused with :class:`Closed` while a completion stands (``reopen``
        first), and when ``summary`` repeats an existing fact: a completion is
        a new statement. Returns ``{"intent": ..., "fact": ...}``.
        """
        engagement = _slug(engagement, "engagement")
        worker = _slug(worker, "worker")
        summary = _text(summary, "summary", MAX_FACT_CHARS)
        references = _evidence(evidence)
        with self._tx() as cur:
            at = self._now(now)
            standing = self._standing(cur, engagement)
            if standing is not None and standing["goal_fact"]:
                raise Closed(
                    f"the engagement is already complete (goal {standing['goal_fact']}); "
                    "reopen it before completing again"
                )
            sources = self._source_facts(cur, engagement, from_facts)
            fact, duplicate = self._write_fact(
                cur, engagement, summary, GOAL, references, worker, at
            )
            if duplicate:
                raise BoardError(
                    f"fact {fact['id']} already says this; a completion needs its own summary"
                )
            row = self._insert_intent(
                cur,
                engagement,
                COMPLETE_PREFIX + summary,
                sources,
                worker,
                at,
                status=CONCLUDED,
                worker=worker,
                to_fact=fact["id"],
            )
            intent = self._intent(row, at)
            cur.execute(
                "INSERT INTO boards (engagement, goal_fact, goal_intent) VALUES (?, ?, ?) "
                "ON CONFLICT (engagement) DO UPDATE SET goal_fact = excluded.goal_fact, "
                "goal_intent = excluded.goal_intent",
                (engagement, fact["id"], intent["id"]),
            )
        return {"intent": intent, "fact": {**fact, "duplicate": False}}

    def reopen(
        self,
        engagement: str,
        feedback: str,
        *,
        author: str = "verifier",
        now: float | None = None,
    ) -> dict[str, Any]:
        """Overturn a standing completion (an external verifier found it false).

        One transaction: writes the corrective fact ``reopened: <feedback>``,
        opens an intent with the feedback as its text, linked from the
        overturned goal fact and the corrective fact, so the work shows up in
        :meth:`open_work`, and clears the completion. The goal fact stays on
        the board; facts are never removed. Raises :class:`BoardError` when
        there is no completion to overturn.
        """
        engagement = _slug(engagement, "engagement")
        author = _slug(author, "author")
        feedback = _text(feedback, "feedback", MAX_FACT_CHARS - len(REOPENED_PREFIX))
        with self._tx() as cur:
            at = self._now(now)
            standing = self._standing(cur, engagement)
            if standing is None or not standing["goal_fact"]:
                raise BoardError("the engagement is not complete; there is nothing to reopen")
            goal = standing["goal_fact"]
            fact, duplicate = self._write_fact(
                cur, engagement, REOPENED_PREFIX + feedback, OBSERVATION, [], author, at
            )
            row = self._insert_intent(cur, engagement, feedback, [goal, fact["id"]], author, at)
            cur.execute(
                "UPDATE boards SET goal_fact = NULL, goal_intent = NULL, reopened = reopened + 1 "
                "WHERE engagement = ?",
                (engagement,),
            )
            return {
                "engagement": engagement,
                "complete": False,
                "overturned_goal": goal,
                "fact": {**fact, "duplicate": duplicate},
                "intent": self._intent(row, at),
            }

    # ── the whole board ─────────────────────────────────────────────

    def snapshot(self, engagement: str, now: float | None = None) -> dict[str, Any]:
        """Everything on the engagement's board, read in one transaction: facts
        and intents oldest first, hints newest first, whether a completion
        stands, and counts."""
        engagement = _slug(engagement, "engagement")
        with self._tx(write=False) as cur:
            at = self._now(now)
            facts = self._facts(cur, engagement)
            intents = self._intents(cur, engagement, at)
            hints = self._hints(cur, engagement)
            standing = self._standing(cur, engagement)
        goal = standing["goal_fact"] if standing is not None else None
        by_kind = {kind: 0 for kind in FACT_KINDS}
        for fact in facts:
            by_kind[fact["kind"]] += 1
        by_status = {status: 0 for status in INTENT_STATUSES}
        for intent in intents:
            by_status[intent["status"]] += 1
        return {
            "engagement": engagement,
            "at": at,
            "complete": bool(goal),
            "goal_fact": goal or None,
            "goal_intent": (standing["goal_intent"] or None) if standing is not None else None,
            "reopened": int(standing["reopened"]) if standing is not None else 0,
            "facts": facts,
            "intents": intents,
            "hints": hints,
            "counts": {
                "facts": len(facts),
                "facts_by_kind": by_kind,
                "intents": len(intents),
                "intents_by_status": by_status,
                "open_work": sum(1 for intent in intents if _claimable(intent)),
                "hints": len(hints),
            },
        }


def _claimable(intent: dict[str, Any]) -> bool:
    return intent["status"] == OPEN or (intent["status"] == CLAIMED and intent["expired"])


__all__ = [
    "ABANDONED_PREFIX",
    "DB_FILENAME",
    "DEFAULT_INTENT_TIMEOUT",
    "FACT_KINDS",
    "HINT_AUTHORS",
    "INTENT_STATUSES",
    "MAX_FACT_CHARS",
    "MAX_HINT_CHARS",
    "MAX_INTENT_CHARS",
    "REOPENED_PREFIX",
    "Board",
    "BoardError",
    "Closed",
    "Conflict",
    "Fact",
    "Hint",
    "Intent",
    "NotClaimer",
    "NotFound",
    "normalise_intent_text",
]
