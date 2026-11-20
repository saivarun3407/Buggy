"""Cross-engagement lessons: what worked and what failed, kept between runs.

One SQLite file (``lessons.sqlite3``) holds short notes about technique. A
lesson is retrieved by technology and vulnerability class, optionally with a
text query. Three rules shape the module:

* **Trust comes from a finding, not from the author.** A lesson is ``verified``
  only when the caller of :meth:`LessonStore.save` passes
  ``verified_finding=True`` together with a finding id. Nothing inside the
  lesson itself can set it, so an agent cannot promote its own note.
* **A lesson is about technique, not about a customer.** Title, body and tags
  go through :func:`scrub` before they are written: credential shapes are
  replaced with a placeholder and the hostnames and addresses of the source
  engagement's scope become ``<target>``.
* **The store is bounded.** At most :data:`MAX_LESSONS` rows; the oldest
  unverified lesson is evicted first.

Search uses FTS5 when the SQLite build has it and ``LIKE`` otherwise
(:attr:`LessonStore.fts` says which). Standard library only; everything
returned is a JSON-serialisable dict.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DB_FILENAME = "lessons.sqlite3"

KINDS = ("guide", "failure", "payload")
VERIFIED = "verified"
UNVERIFIED = "unverified"

MAX_LESSONS = 5000
MAX_BODY_CHARS = 2000
MAX_TITLE_CHARS = 200
MAX_TAGS = 20
MAX_SEARCH_LIMIT = 50
MAX_QUERY_TERMS = 16

TARGET = "<target>"
REDACTED = "<redacted>"

# Rank weights (see ``LessonStore.search``).
TECHNOLOGY_WEIGHT = 2.0
CLASS_WEIGHT = 1.0
VERIFIED_WEIGHT = 1.0


class LessonError(ValueError):
    """A lesson that cannot be stored as given."""


# ── scrubbing ───────────────────────────────────────────────────────────

_PEM_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?")
_COOKIE_HEADER = re.compile(r"(?i)\b(set-cookie|cookie)([\"']?\s*:\s*[\"']?)[^\r\n'\"]*")
_COOKIE_FLAG = re.compile(r"(?<![\w-])(--cookie|-b)(\s+)(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)")
_AUTH_HEADER = re.compile(
    r"(?i)\b((?:proxy-)?authorization)\b([\"']?\s*[:=]\s*[\"']?)"
    r"(?:(bearer|basic|token|digest|negotiate|apikey|jwt)\s+)?[^\s\"',;]+"
)
_BEARER = re.compile(r"(?i)\b(bearer)(\s+)([A-Za-z0-9._~+/=-]{8,})")
_BASIC = re.compile(r"(?i)\b(basic)(\s+)([A-Za-z0-9+/]{8,}={0,2})")
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@")

# Names that hold a credential when followed by ``=`` or ``:``. The first group
# may be the tail of a longer name (``csrf_token``, ``PHPSESSID``); the short
# words in the second group only count as a whole name or after a separator, so
# ``bypass:`` and ``inside=`` are left alone.
_SECRET_NAME = (
    r"(?:[\w.-]*(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|sess(?:ion)?[_-]?id|session|credential)s?"
    r"|(?:[\w.-]*[_.-])?(?:auth|sid|pass|jwt|otp|pin))"
)
_KEY_VALUE = re.compile(
    rf"(?i)(?<![\w.-])([\"']?)({_SECRET_NAME})\1(\s*[:=]\s*)"
    r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s&;,\"'<>(){}\[\]]+)"
)
# "the password is Hunter2!x" - prose, no separator.
_PASSWORD_PROSE = re.compile(
    r"(?i)\b(passw(?:or)?d|passphrase|pwd)(\s+(?:is|was|are|of)\s+)([\"']?)([^\s\"']+)\3"
)

_KEY_SHAPES = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # GitHub token
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[abeprs]-[A-Za-z0-9-]{10,}"),  # Slack token
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),  # Google API key
    re.compile(r"\b(?:sk|pk|rk)[-_][A-Za-z0-9_-]{20,}"),  # sk-..., sk_live_...
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),  # long hex: API keys, session ids, digests
)
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])")

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_HOST_CHARS = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _bearer(match: re.Match[str]) -> str:
    token = match.group(3)
    # "Bearer authentication" is prose; a token has a digit or is long.
    if len(token) >= 20 or any(ch.isdigit() for ch in token):
        return f"{match.group(1)}{match.group(2)}{REDACTED}"
    return match.group(0)


def _basic(match: re.Match[str]) -> str:
    token = match.group(3)
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (binascii.Error, ValueError):
        return match.group(0)
    if b":" in decoded:  # user:password
        return f"{match.group(1)}{match.group(2)}{REDACTED}"
    return match.group(0)


def _password_prose(match: re.Match[str]) -> str:
    value = match.group(4).rstrip(".,;:)")
    # "the password is not checked" is technique; a value with a digit, a
    # symbol or mixed case is a password. A plain lower-case word is kept.
    if value.isalpha() and (value.islower() or value.isupper()):
        return match.group(0)
    return f"{match.group(1)}{match.group(2)}{REDACTED}"


def _long_token(match: re.Match[str]) -> str:
    token = match.group(0)
    mixed = (
        any(ch.isdigit() for ch in token)
        and any(ch.islower() for ch in token)
        and any(ch.isupper() for ch in token)
    )
    return REDACTED if mixed else token


def _scrub_credentials(text: str) -> str:
    text = _PEM_KEY.sub(REDACTED, text)
    text = _JWT.sub("<jwt>", text)
    text = _COOKIE_HEADER.sub(rf"\1\2{REDACTED}", text)
    text = _COOKIE_FLAG.sub(rf"\1\2{REDACTED}", text)
    text = _AUTH_HEADER.sub(rf"\1\2{REDACTED}", text)
    text = _BEARER.sub(_bearer, text)
    text = _BASIC.sub(_basic, text)
    text = _URL_USERINFO.sub(rf"\1{REDACTED}@", text)
    text = _KEY_VALUE.sub(rf"\1\2\1\3{REDACTED}", text)
    text = _PASSWORD_PROSE.sub(_password_prose, text)
    for shape in _KEY_SHAPES:
        text = shape.sub(REDACTED, text)
    return _LONG_TOKEN.sub(_long_token, text)


def _scope_targets(scope_hosts: Iterable[Any]) -> tuple[list[tuple[str, bool]], list[Network]]:
    """Scope entries as ``(hostname, subdomain_required)`` pairs and networks.

    Accepts what an enforced scope lists: hostnames, wildcards (``*.acme.test``,
    ``api-*.acme.test``), URLs, ``host:port``, IP addresses and CIDR ranges,
    each as a string or as ``{"target": ...}``.
    """
    hosts: dict[str, bool] = {}
    networks: list[Network] = []
    for entry in scope_hosts:
        raw = entry.get("target") if isinstance(entry, Mapping) else entry
        if not isinstance(raw, str):
            continue
        value = raw.strip().lower()
        if not value:
            continue
        if "://" in value:
            try:
                value = urlsplit(value).hostname or ""
            except ValueError:
                continue
        else:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
                continue
            except ValueError:
                pass
            value = value.split("/", 1)[0]
            if value.startswith("["):  # [v6]:port
                value = value[1:].split("]", 1)[0]
            elif value.count(":") == 1:  # host:port
                value = value.split(":", 1)[0]
        value = value.strip(".")
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
            continue
        except ValueError:
            pass
        labels = value.split(".")
        wildcard = any("*" in label for label in labels)
        while any("*" in label for label in labels):
            labels = labels[1:]
        host = ".".join(labels)
        if not host or not _HOST_CHARS.fullmatch(host):
            continue
        # "*.test" must not turn the bare word "test" into a target.
        subdomain_required = wildcard and len(labels) == 1
        hosts[host] = hosts.get(host, True) and subdomain_required
    ordered = sorted(hosts.items(), key=lambda item: (-len(item[0]), item[0]))
    return ordered, networks


def _scrub_targets(text: str, scope_hosts: Iterable[Any]) -> str:
    hosts, networks = _scope_targets(scope_hosts)
    if hosts:
        alternatives = [
            rf"(?:[A-Za-z0-9_-]+\.){'+' if subdomain_required else '*'}{re.escape(host)}"
            for host, subdomain_required in hosts
        ]
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_-])(?:{'|'.join(alternatives)})(?![A-Za-z0-9_-])", re.IGNORECASE
        )
        text = pattern.sub(TARGET, text)

    def _address(match: re.Match[str]) -> str:
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        if any(address.version == net.version and address in net for net in networks):
            return TARGET
        return match.group(0)

    if any(net.version == 4 for net in networks):
        text = _IPV4.sub(_address, text)
    if any(net.version == 6 for net in networks):
        text = _IPV6.sub(_address, text)
    return text


def scrub(text: str, scope_hosts: Iterable[Any] = ()) -> str:
    """``text`` without credentials and without the engagement's targets.

    Removes anything shaped like a credential (private keys, JWTs, ``Cookie`` /
    ``Authorization`` headers, Bearer and Basic tokens, ``user:pass@`` in URLs,
    ``password=`` / ``token:`` style pairs, well-known API-key formats, long hex
    and long mixed-case tokens) and replaces every hostname or address covered
    by ``scope_hosts`` with ``<target>``. It errs towards removing too much.
    """
    return _scrub_targets(_scrub_credentials(str(text)), scope_hosts)


def scope_hosts_from_document(document: Any) -> list[str]:
    """Target strings (``in_scope`` and ``out_of_scope``) of an enforced scope document."""
    if not isinstance(document, Mapping):
        return []
    block = document.get("machine_enforcement")
    if not isinstance(block, Mapping):
        return []
    targets: list[str] = []
    for field in ("in_scope", "out_of_scope"):
        entries = block.get(field)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            target = entry.get("target") if isinstance(entry, Mapping) else entry
            if isinstance(target, str) and target.strip() and target not in targets:
                targets.append(target)
    return targets


# ── model ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Lesson:
    """One lesson. Only the first seven fields are read by ``LessonStore.save``;
    the rest (``trust`` included) are assigned by the store."""

    kind: str
    title: str
    body: str
    classes: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    source_engagement: str = ""
    finding_id: str = ""
    id: str = ""
    trust: str = UNVERIFIED
    created_at: float = 0.0
    uses: int = 0
    last_used_at: float | None = None
    saved_by: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["classes"] = list(self.classes)
        data["technologies"] = list(self.technologies)
        return data


_TAG = re.compile(r"[a-z0-9][a-z0-9 +#._/-]{0,39}")
_SLUG = re.compile(r"[A-Za-z0-9_.:@-]{1,100}")
_FINDING_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_WORD = re.compile(r"\w+")


def _tags(values: Any, scope_hosts: Iterable[Any] = ()) -> tuple[str, ...]:
    """Lower-case tag names. A tag that scrubbing would change is dropped: tags
    are indexed and returned verbatim, so they must not carry a host or secret."""
    if values is None:
        return ()
    if isinstance(values, str):
        values = [values]
    scope = list(scope_hosts)
    kept: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        tag = " ".join(value.lower().split())
        if not _TAG.fullmatch(tag) or tag in kept or scrub(tag, scope) != tag:
            continue
        kept.append(tag)
        if len(kept) >= MAX_TAGS:
            break
    return tuple(kept)


def _field(source: Any, name: str, default: Any = "") -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _text_field(source: Any, name: str) -> str:
    value = _field(source, name, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise LessonError(f"lesson {name} must be a string")
    return value.strip()


def _lesson_id(kind: str, title: str, body: str) -> str:
    material = "\x1f".join((kind, title, body)).encode("utf-8")
    return f"L-{hashlib.sha256(material).hexdigest()[:12]}"


def _terms(query: str) -> list[str]:
    terms: list[str] = []
    for term in _WORD.findall(str(query or "").lower()):
        term = term[:64]
        if term not in terms:
            terms.append(term)
        if len(terms) >= MAX_QUERY_TERMS:
            break
    return terms


def fts5_available(db: sqlite3.Connection) -> bool:
    """Whether this SQLite build can create an FTS5 table."""
    try:
        db.execute("CREATE VIRTUAL TABLE temp.lessons_fts_probe USING fts5(x)")
        db.execute("DROP TABLE temp.lessons_fts_probe")
    except sqlite3.OperationalError:
        return False
    return True


# ── store ───────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lessons (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    classes TEXT NOT NULL DEFAULT '[]',
    technologies TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '',
    source_engagement TEXT NOT NULL DEFAULT '',
    finding_id TEXT NOT NULL DEFAULT '',
    trust TEXT NOT NULL DEFAULT 'unverified',
    saved_by TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0,
    last_used_at REAL
);
CREATE INDEX IF NOT EXISTS lessons_trust_age ON lessons (trust, created_at);
CREATE TABLE IF NOT EXISTS lessons_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
_FTS_SCHEMA = "CREATE VIRTUAL TABLE IF NOT EXISTS lessons_fts USING fts5(title, body, tags)"
_FTS_STALE = "fts_stale"


class LessonStore:
    """The lessons file. ``fts=None`` detects FTS5; ``fts=False`` forces ``LIKE``."""

    def __init__(
        self,
        path: str | Path,
        *,
        fts: bool | None = None,
        max_lessons: int = MAX_LESSONS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_lessons < 1:
            raise ValueError("max_lessons must be at least 1")
        self.path = Path(path)
        self.max_lessons = int(max_lessons)
        self._clock = clock
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        self.fts = fts5_available(self._db) if fts is None or fts else False
        if fts and not self.fts:
            self._db.close()
            raise LessonError("FTS5 was requested but this SQLite build does not have it")
        with self._tx() as cur:
            cur.executescript(_SCHEMA)
            if self.fts:
                cur.execute(_FTS_SCHEMA)
                self._sync_fts(cur)

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

    # ── index upkeep ────────────────────────────────────────────────

    def _sync_fts(self, cur: sqlite3.Cursor) -> None:
        """Rebuild the index when the file was written without it (LIKE mode)."""
        stale = cur.execute(
            "SELECT value FROM lessons_meta WHERE key = ?", (_FTS_STALE,)
        ).fetchone()
        rows = cur.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
        indexed = cur.execute("SELECT COUNT(*) FROM lessons_fts").fetchone()[0]
        if stale is None and rows == indexed:
            return
        cur.execute("DELETE FROM lessons_fts")
        cur.execute(
            "INSERT INTO lessons_fts (rowid, title, body, tags) "
            "SELECT seq, title, body, tags FROM lessons"
        )
        cur.execute("DELETE FROM lessons_meta WHERE key = ?", (_FTS_STALE,))

    def _index(self, cur: sqlite3.Cursor, seq: int, title: str, body: str, tags: str) -> None:
        if self.fts:
            cur.execute("DELETE FROM lessons_fts WHERE rowid = ?", (seq,))
            cur.execute(
                "INSERT INTO lessons_fts (rowid, title, body, tags) VALUES (?, ?, ?, ?)",
                (seq, title, body, tags),
            )
        else:
            self._mark_stale(cur)

    def _unindex(self, cur: sqlite3.Cursor, seq: int) -> None:
        if self.fts:
            cur.execute("DELETE FROM lessons_fts WHERE rowid = ?", (seq,))
        else:
            self._mark_stale(cur)

    @staticmethod
    def _mark_stale(cur: sqlite3.Cursor) -> None:
        cur.execute(
            "INSERT OR REPLACE INTO lessons_meta (key, value) VALUES (?, '1')", (_FTS_STALE,)
        )

    # ── writing ─────────────────────────────────────────────────────

    def save(
        self,
        lesson: Lesson | Mapping[str, Any],
        actor: str,
        *,
        verified_finding: bool = False,
        scope_hosts: Iterable[Any] = (),
    ) -> str:
        """Store ``lesson`` and return its id.

        ``lesson`` supplies ``kind``, ``title``, ``body``, ``classes``,
        ``technologies``, ``source_engagement`` and ``finding_id``; every other
        key (``trust``, ``id``, ``uses`` ...) is ignored. ``trust`` is
        ``verified`` only when ``verified_finding`` is true, which the caller
        sets after checking the finding in the findings store; it is never read
        from the lesson. ``scope_hosts`` are the targets of the source
        engagement's scope (see :func:`scope_hosts_from_document`).

        The id is derived from the scrubbed kind, title and body, so saving the
        same lesson again returns the same id. A repeat without a verified
        finding changes nothing; a repeat with one promotes the lesson.
        """
        actor = str(actor or "").strip()
        if not _SLUG.fullmatch(actor):
            raise LessonError("actor is required (letters, digits and _.:@- only)")
        scope = list(scope_hosts)

        kind = _text_field(lesson, "kind").lower()
        if kind not in KINDS:
            raise LessonError(f"lesson kind must be one of {', '.join(KINDS)}")
        raw_title = _text_field(lesson, "title")
        raw_body = _text_field(lesson, "body")
        if not raw_title:
            raise LessonError("lesson title is required")
        if not raw_body:
            raise LessonError("lesson body is required")
        if len(raw_title) > MAX_TITLE_CHARS:
            raise LessonError(f"lesson title is longer than {MAX_TITLE_CHARS} characters")
        if len(raw_body) > MAX_BODY_CHARS:
            raise LessonError(f"lesson body is longer than {MAX_BODY_CHARS} characters")
        # A placeholder can be longer than what it replaces; keep the stored limit.
        title = scrub(raw_title, scope)[:MAX_TITLE_CHARS]
        body = scrub(raw_body, scope)[:MAX_BODY_CHARS]
        classes = _tags(_field(lesson, "classes", ()), scope)
        technologies = _tags(_field(lesson, "technologies", ()), scope)
        source_engagement = _text_field(lesson, "source_engagement")
        if source_engagement and not _SLUG.fullmatch(source_engagement):
            raise LessonError("source_engagement must be an engagement name")
        finding_id = _text_field(lesson, "finding_id")
        if finding_id and not _FINDING_ID.fullmatch(finding_id):
            raise LessonError("finding_id is not a finding id")

        verified = verified_finding is True
        if verified and not finding_id:
            raise LessonError("a verified lesson must name its finding_id")
        trust = VERIFIED if verified else UNVERIFIED
        lesson_id = _lesson_id(kind, title, body)

        with self._tx() as cur:
            existing = cur.execute("SELECT * FROM lessons WHERE id = ?", (lesson_id,)).fetchone()
            if existing is not None:
                if verified:
                    self._promote(
                        cur, existing, classes, technologies, source_engagement, finding_id, actor
                    )
                return lesson_id
            self._make_room(cur, incoming_verified=verified)
            tags = " ".join((*classes, *technologies))
            cur.execute(
                "INSERT INTO lessons (id, kind, title, body, classes, technologies, tags, "
                "source_engagement, finding_id, trust, saved_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    lesson_id,
                    kind,
                    title,
                    body,
                    json.dumps(list(classes)),
                    json.dumps(list(technologies)),
                    tags,
                    source_engagement,
                    finding_id,
                    trust,
                    actor,
                    float(self._clock()),
                ),
            )
            self._index(cur, int(cur.lastrowid or 0), title, body, tags)
        return lesson_id

    def _promote(
        self,
        cur: sqlite3.Cursor,
        existing: sqlite3.Row,
        classes: tuple[str, ...],
        technologies: tuple[str, ...],
        source_engagement: str,
        finding_id: str,
        actor: str,
    ) -> None:
        """A verified save of a lesson that already exists: raise trust, add tags."""

        def _merged(stored: str, extra: tuple[str, ...]) -> list[str]:
            merged = list(json.loads(stored or "[]"))
            merged.extend(tag for tag in extra if tag not in merged)
            return merged[:MAX_TAGS]

        merged_classes = _merged(existing["classes"], classes)
        merged_technologies = _merged(existing["technologies"], technologies)
        tags = " ".join((*merged_classes, *merged_technologies))
        already = existing["trust"] == VERIFIED
        cur.execute(
            "UPDATE lessons SET trust = ?, classes = ?, technologies = ?, tags = ?, "
            "finding_id = ?, source_engagement = ?, saved_by = ? WHERE seq = ?",
            (
                VERIFIED,
                json.dumps(merged_classes),
                json.dumps(merged_technologies),
                tags,
                existing["finding_id"] if already else finding_id,
                existing["source_engagement"] if already else source_engagement,
                existing["saved_by"] if already else actor,
                existing["seq"],
            ),
        )
        self._index(cur, existing["seq"], existing["title"], existing["body"], tags)

    def _make_room(self, cur: sqlite3.Cursor, *, incoming_verified: bool) -> None:
        """Evict until one more row fits: oldest unverified first, then oldest verified
        (only for a verified newcomer - an unverified one never displaces a verified)."""
        count = cur.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
        while count >= self.max_lessons:
            victim = cur.execute(
                "SELECT seq FROM lessons WHERE trust = ? ORDER BY created_at ASC, seq ASC LIMIT 1",
                (UNVERIFIED,),
            ).fetchone()
            if victim is None:
                if not incoming_verified:
                    raise LessonError(
                        f"the lesson store is full ({self.max_lessons} verified lessons); "
                        "an unverified lesson does not replace a verified one"
                    )
                victim = cur.execute(
                    "SELECT seq FROM lessons ORDER BY created_at ASC, seq ASC LIMIT 1"
                ).fetchone()
            cur.execute("DELETE FROM lessons WHERE seq = ?", (victim["seq"],))
            self._unindex(cur, victim["seq"])
            count -= 1

    # ── reading ─────────────────────────────────────────────────────

    @staticmethod
    def _row(row: sqlite3.Row) -> Lesson:
        return Lesson(
            kind=row["kind"],
            title=row["title"],
            body=row["body"],
            classes=tuple(json.loads(row["classes"] or "[]")),
            technologies=tuple(json.loads(row["technologies"] or "[]")),
            source_engagement=row["source_engagement"],
            finding_id=row["finding_id"],
            id=row["id"],
            trust=row["trust"],
            created_at=row["created_at"],
            uses=row["uses"],
            last_used_at=row["last_used_at"],
            saved_by=row["saved_by"],
        )

    def get(self, lesson_id: str) -> dict[str, Any] | None:
        """One lesson by id, or ``None``. Does not count as a use."""
        with self._lock:
            row = self._db.execute("SELECT * FROM lessons WHERE id = ?", (lesson_id,)).fetchone()
        return self._row(row).to_dict() if row else None

    def count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0])

    def stats(self) -> dict[str, Any]:
        with self._lock:
            verified = self._db.execute(
                "SELECT COUNT(*) FROM lessons WHERE trust = ?", (VERIFIED,)
            ).fetchone()[0]
            total = self._db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
        return {
            "fts": self.fts,
            "lessons": int(total),
            "verified": int(verified),
            "unverified": int(total - verified),
            "max_lessons": self.max_lessons,
        }

    def _text_scores(self, cur: sqlite3.Cursor, terms: list[str]) -> dict[int, float]:
        """``seq -> text score`` for lessons matching any term (higher is better)."""
        if not terms:
            return {}
        if self.fts:
            match = " OR ".join(f'"{term}"' for term in terms)
            rows = cur.execute(
                "SELECT rowid AS seq, -bm25(lessons_fts, 2.0, 1.0, 1.0) AS score "
                "FROM lessons_fts WHERE lessons_fts MATCH ?",
                (match,),
            ).fetchall()
        else:
            haystack = "(title || ' ' || body || ' ' || tags)"
            hit = f"(CASE WHEN {haystack} LIKE ? ESCAPE '\\' THEN 1 ELSE 0 END)"
            patterns = [
                "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                for term in terms
            ]
            rows = cur.execute(
                f"SELECT seq, score FROM (SELECT seq, {' + '.join([hit] * len(terms))} AS score "  # noqa: S608
                "FROM lessons) WHERE score > 0",
                patterns,
            ).fetchall()
        return {int(row["seq"]): max(float(row["score"]), 0.0) for row in rows}

    def search(
        self,
        query: str = "",
        *,
        classes: Iterable[str] = (),
        technologies: Iterable[str] = (),
        kind: str | None = None,
        limit: int = 3,
        include_unverified: bool = False,
    ) -> list[dict[str, Any]]:
        """The best ``limit`` lessons, each with its ``score``.

        ``score`` = text score (FTS bm25, or the number of query terms found
        with ``LIKE``) + 2 per matching technology + 1 per matching class + 1
        if verified; ties go to the newer lesson. When a query or tags are
        given, a lesson must match at least one of them to be returned; with
        neither, the newest lessons are returned. Unverified lessons are left
        out unless ``include_unverified`` is true. Every returned lesson has
        its ``uses`` incremented.
        """
        if kind is not None and kind not in KINDS:
            raise LessonError(f"lesson kind must be one of {', '.join(KINDS)}")
        limit = max(1, min(int(limit), MAX_SEARCH_LIMIT))
        wanted_technologies = set(_tags(technologies))
        wanted_classes = set(_tags(classes))
        terms = _terms(query)
        filtered = bool(terms or wanted_technologies or wanted_classes)

        clauses: list[str] = []
        params: list[Any] = []
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        if not include_unverified:
            clauses.append("trust = ?")
            params.append(VERIFIED)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._tx() as cur:
            text = self._text_scores(cur, terms)
            rows = cur.execute(f"SELECT * FROM lessons{where}", params).fetchall()  # noqa: S608
            ranked: list[tuple[float, float, int, sqlite3.Row]] = []
            for row in rows:
                matched_technologies = wanted_technologies.intersection(
                    json.loads(row["technologies"] or "[]")
                )
                matched_classes = wanted_classes.intersection(json.loads(row["classes"] or "[]"))
                if (
                    filtered
                    and row["seq"] not in text
                    and not matched_technologies
                    and not matched_classes
                ):
                    continue
                score = (
                    text.get(row["seq"], 0.0)
                    + TECHNOLOGY_WEIGHT * len(matched_technologies)
                    + CLASS_WEIGHT * len(matched_classes)
                    + (VERIFIED_WEIGHT if row["trust"] == VERIFIED else 0.0)
                )
                ranked.append((score, row["created_at"], row["seq"], row))
            ranked.sort(key=lambda item: (-item[0], -item[1], -item[2]))
            top = ranked[:limit]
            now = float(self._clock())
            results: list[dict[str, Any]] = []
            for score, _created, seq, row in top:
                cur.execute(
                    "UPDATE lessons SET uses = uses + 1, last_used_at = ? WHERE seq = ?",
                    (now, seq),
                )
                entry = self._row(row).to_dict()
                entry["uses"] += 1
                entry["last_used_at"] = now
                entry["score"] = round(score, 6)
                results.append(entry)
        return results

    def for_engagement(
        self, technologies: Iterable[str], classes: Iterable[str] = (), limit: int = 5
    ) -> list[dict[str, Any]]:
        """The briefing for a new engagement: verified lessons that match its
        technologies (from recon ``technology`` records) or classes, best first.
        Nothing known about the engagement means nothing to brief."""
        wanted_technologies = _tags(technologies)
        wanted_classes = _tags(classes)
        if not wanted_technologies and not wanted_classes:
            return []
        return self.search(
            "", classes=wanted_classes, technologies=wanted_technologies, limit=limit
        )


__all__ = [
    "DB_FILENAME",
    "KINDS",
    "MAX_BODY_CHARS",
    "MAX_LESSONS",
    "UNVERIFIED",
    "VERIFIED",
    "Lesson",
    "LessonError",
    "LessonStore",
    "fts5_available",
    "scope_hosts_from_document",
    "scrub",
]
