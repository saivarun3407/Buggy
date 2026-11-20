"""SQLite store for captured HTTP exchanges."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_STORED_BODY = 512 * 1024

_SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id TEXT PRIMARY KEY,
    engagement TEXT NOT NULL,
    created_at REAL NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    request_headers TEXT NOT NULL,
    request_body BLOB,
    request_sha256 TEXT NOT NULL,
    status INTEGER,
    response_headers TEXT NOT NULL DEFAULT '{}',
    response_body BLOB,
    response_sha256 TEXT NOT NULL DEFAULT '',
    response_bytes INTEGER NOT NULL DEFAULT 0,
    elapsed_ms REAL NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    probe TEXT NOT NULL DEFAULT '',
    replay_of TEXT NOT NULL DEFAULT '',
    approval_id TEXT NOT NULL DEFAULT '',
    scope_digest TEXT NOT NULL DEFAULT '',
    identity TEXT NOT NULL DEFAULT '',
    redaction TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS captures_engagement ON captures (engagement, created_at);
CREATE INDEX IF NOT EXISTS captures_host ON captures (engagement, host);
"""

# Columns added after the first release: a store created before them gains them on open.
_MIGRATIONS = {
    "identity": "ALTER TABLE captures ADD COLUMN identity TEXT NOT NULL DEFAULT ''",
    "redaction": "ALTER TABLE captures ADD COLUMN redaction TEXT NOT NULL DEFAULT ''",
}

# Header names whose values are credentials: stored, never echoed back in listings.
SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
)
REDACTED = "<redacted>"
# A session value shorter than this is not searched for in bodies: replacing every
# occurrence of a two-character string would shred the evidence without hiding anything.
MIN_SCRUBBED_VALUE = 8


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_fingerprint(method: str, url: str, body: bytes | None) -> str:
    """Identity of a request for approvals: what is sent, not who asked."""
    material = b"\x1f".join((method.upper().encode(), url.encode(), body or b""))
    return sha256_hex(material)


@dataclass(frozen=True, slots=True)
class Capture:
    id: str
    engagement: str
    created_at: float
    method: str
    url: str
    host: str
    request_headers: dict[str, str]
    request_body: bytes
    request_sha256: str
    status: int | None
    response_headers: dict[str, str]
    response_body: bytes
    response_sha256: str
    response_bytes: int
    elapsed_ms: float
    error: str
    note: str
    probe: str
    replay_of: str
    approval_id: str
    scope_digest: str
    # The named identity whose session the gateway attached ("" = none).
    identity: str = ""
    # Lower-case header names redacted for this capture on top of SENSITIVE_HEADERS:
    # the headers an identity's session is carried in.
    redact_headers: tuple[str, ...] = ()
    # True for the gateway's own login exchange: the request holds the account's
    # password and the response the fresh session, so neither body is ever shown.
    redact_bodies: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "capture_id": self.id,
            "created_at": self.created_at,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "response_bytes": self.response_bytes,
            "response_sha256": self.response_sha256,
            "elapsed_ms": self.elapsed_ms,
            "probe": self.probe,
            "note": self.note,
            "replay_of": self.replay_of,
            "error": self.error,
            "identity": self.identity,
        }

    def _session_values(self, hidden: frozenset[str]) -> list[str]:
        """The credential strings an identity's session put on this request.

        A target that echoes its caller's token or cookie back in a body would
        otherwise hand the agent the very value the header redaction hides.
        Only captures sent as a named identity are searched: there the gateway
        attached the credentials and the caller never held them.
        """
        if not self.identity:
            return []
        values: set[str] = set()
        for name, value in self.request_headers.items():
            if name.lower() not in hidden:
                continue
            values.add(value.strip())
            if name.lower() == "cookie":
                for pair in value.split(";"):
                    values.add(pair.partition("=")[2].strip())
            else:
                values.add(value.strip().rpartition(" ")[2])  # "Bearer <token>" -> token
        return sorted((v for v in values if len(v) >= MIN_SCRUBBED_VALUE), key=len, reverse=True)

    def detail(self, *, body_chars: int = 8000, reveal_credentials: bool = False) -> dict[str, Any]:
        hidden = SENSITIVE_HEADERS | frozenset(self.redact_headers)
        secrets = [] if reveal_credentials else self._session_values(hidden)

        def _scrub(value: str) -> str:
            for secret in secrets:
                value = value.replace(secret, REDACTED)
            return value

        def _headers(headers: dict[str, str]) -> dict[str, str]:
            if reveal_credentials:
                return headers
            return {k: (REDACTED if k.lower() in hidden else _scrub(v)) for k, v in headers.items()}

        def _body(raw: bytes) -> str:
            if self.redact_bodies and not reveal_credentials:
                return REDACTED
            return _scrub(raw.decode("utf-8", "replace"))[:body_chars]

        text = self.response_body.decode("utf-8", "replace")
        return {
            **self.summary(),
            "engagement": self.engagement,
            "request_headers": _headers(self.request_headers),
            "request_body": _body(self.request_body),
            # The hash of a login body would allow offline guessing of the password.
            "request_sha256": (
                REDACTED if self.redact_bodies and not reveal_credentials else self.request_sha256
            ),
            "response_headers": _headers(self.response_headers),
            "response_body": _body(self.response_body),
            "response_truncated": len(text) > body_chars
            or self.response_bytes > len(self.response_body),
            "approval_id": self.approval_id,
            "scope_digest": self.scope_digest,
        }


class CaptureStore:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        if read_only:
            self._db = sqlite3.connect(
                f"file:{self.path}?mode=ro", uri=True, check_same_thread=False
            )
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
            with self._tx() as cur:
                cur.executescript(_SCHEMA)
                present = {row[1] for row in cur.execute("PRAGMA table_info(captures)")}
                for column, statement in _MIGRATIONS.items():
                    if column not in present:
                        cur.execute(statement)
        self._db.row_factory = sqlite3.Row

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

    def add(
        self,
        *,
        engagement: str,
        method: str,
        url: str,
        host: str,
        request_headers: dict[str, str],
        request_body: bytes,
        status: int | None,
        response_headers: dict[str, str],
        response_body: bytes,
        elapsed_ms: float,
        error: str = "",
        note: str = "",
        probe: str = "",
        replay_of: str = "",
        approval_id: str = "",
        scope_digest: str = "",
        identity: str = "",
        redact_headers: tuple[str, ...] | list[str] = (),
        redact_bodies: bool = False,
    ) -> Capture:
        capture_id = f"cap-{uuid.uuid4().hex[:16]}"
        now = time.time()
        stored_response = response_body[:MAX_STORED_BODY]
        redaction = ""
        if redact_headers or redact_bodies:
            redaction = json.dumps(
                {
                    "headers": sorted({str(name).lower() for name in redact_headers}),
                    "bodies": bool(redact_bodies),
                }
            )
        row = (
            capture_id,
            engagement,
            now,
            method.upper(),
            url,
            host,
            json.dumps(request_headers, sort_keys=True),
            request_body[:MAX_STORED_BODY],
            request_fingerprint(method, url, request_body),
            status,
            json.dumps(response_headers, sort_keys=True),
            stored_response,
            sha256_hex(response_body),
            len(response_body),
            round(elapsed_ms, 2),
            error[:500],
            note[:500],
            probe[:64],
            replay_of,
            approval_id,
            scope_digest,
            identity[:64],
            redaction,
        )
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO captures (id, engagement, created_at, method, url, host, "
                "request_headers, request_body, request_sha256, status, response_headers, "
                "response_body, response_sha256, response_bytes, elapsed_ms, error, note, probe, "
                "replay_of, approval_id, scope_digest, identity, redaction) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
        found = self.get(engagement, capture_id)
        assert found is not None  # noqa: S101 - just inserted
        return found

    @staticmethod
    def _row(row: sqlite3.Row) -> Capture:
        # A read-only handle cannot migrate, so an older file may lack the new columns.
        columns = row.keys()
        redaction: dict[str, Any] = {}
        if "redaction" in columns and row["redaction"]:
            redaction = json.loads(row["redaction"])
        return Capture(
            id=row["id"],
            engagement=row["engagement"],
            created_at=row["created_at"],
            method=row["method"],
            url=row["url"],
            host=row["host"],
            request_headers=json.loads(row["request_headers"] or "{}"),
            request_body=bytes(row["request_body"] or b""),
            request_sha256=row["request_sha256"],
            status=row["status"],
            response_headers=json.loads(row["response_headers"] or "{}"),
            response_body=bytes(row["response_body"] or b""),
            response_sha256=row["response_sha256"],
            response_bytes=row["response_bytes"],
            elapsed_ms=row["elapsed_ms"],
            error=row["error"],
            note=row["note"],
            probe=row["probe"],
            replay_of=row["replay_of"],
            approval_id=row["approval_id"],
            scope_digest=row["scope_digest"],
            identity=(row["identity"] or "") if "identity" in columns else "",
            redact_headers=tuple(redaction.get("headers") or ()),
            redact_bodies=bool(redaction.get("bodies")),
        )

    def get(self, engagement: str, capture_id: str) -> Capture | None:
        row = self._db.execute(
            "SELECT * FROM captures WHERE id = ? AND engagement = ?", (capture_id, engagement)
        ).fetchone()
        return self._row(row) if row else None

    def list(
        self, engagement: str, *, host: str = "", probe: str = "", limit: int = 50
    ) -> list[Capture]:
        clauses: list[str] = ["engagement = ?"]
        params: list[Any] = [engagement]
        if host:
            clauses.append("host = ?")
            params.append(host.lower())
        if probe:
            clauses.append("probe = ?")
            params.append(probe)
        params.append(max(1, min(int(limit), 500)))
        rows = self._db.execute(
            f"SELECT * FROM captures WHERE {' AND '.join(clauses)} "  # noqa: S608
            "ORDER BY created_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [self._row(row) for row in rows]


__all__ = [
    "MAX_STORED_BODY",
    "REDACTED",
    "SENSITIVE_HEADERS",
    "Capture",
    "CaptureStore",
    "request_fingerprint",
    "sha256_hex",
]
