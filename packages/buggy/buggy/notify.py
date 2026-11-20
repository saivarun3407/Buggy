"""Outbound notifications: tell the operator when something waits for them.

Buggy holds state-changing requests and report submissions until the operator
decides, but the operator only learns of a hold by running
``buggy-cli approvals list``. This module posts a short message to webhooks the
operator configured, for four events: an approval is waiting, recon finished, a
finding was verified, a run failed.

What the module guarantees:

* **Outbound only, operator-configured.** Destinations come from the process
  environment of the service that sends (``BUGGY_NOTIFY_*``), are fixed when
  the :class:`Notifier` is built, and are never taken from an :class:`Event`.
  Nothing here is an agent tool and nothing here reads a reply.
* **Never in the way.** :meth:`Notifier.notify` does not raise. Every sink is
  tried on its own thread with a socket timeout, and the caller waits a bounded
  time in total. A failure is returned as ``Delivery(ok=False, ...)``, logged
  and counted.
* **Privacy enforced in code.** A notification may name a method, a URL's host
  and path, a request id, a severity, a class and counts. It never carries a
  body, a header value, a token or a query string: :func:`sanitize_url` drops
  the query, the fragment and credentials; :class:`Event` rejects ``fields``
  keys named like secrets and scrubs every string it is given; the builders at
  the bottom copy only named, validated parts of a record and no free text an
  agent wrote (an approval's ``reason``, a finding's title or description).

Standard library only, and no import from the rest of ``buggy``.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

_log = logging.getLogger("buggy.notify")

APPROVAL_REQUIRED = "approval_required"
RECON_FINISHED = "recon_finished"
FINDING_VERIFIED = "finding_verified"
RUN_FAILED = "run_failed"
KINDS: tuple[str, ...] = (APPROVAL_REQUIRED, RECON_FINISHED, FINDING_VERIFIED, RUN_FAILED)

ENV_WEBHOOK = "BUGGY_NOTIFY_WEBHOOK_URL"
ENV_SLACK = "BUGGY_NOTIFY_SLACK_WEBHOOK_URL"
ENV_DISCORD = "BUGGY_NOTIFY_DISCORD_WEBHOOK_URL"
ENV_EVENTS = "BUGGY_NOTIFY_EVENTS"
ENV_MIN_INTERVAL = "BUGGY_NOTIFY_MIN_INTERVAL_SECONDS"

TIMEOUT_SECONDS = 5.0
DEFAULT_MIN_INTERVAL = 30.0
DISCORD_MAX_CHARS = 1900
USER_AGENT = "buggy-notify/1"

MAX_TITLE = 200
MAX_DETAIL = 1000
MAX_FIELD_VALUE = 300
MAX_FIELDS = 20
MAX_ERROR = 200
REDACTED = "[redacted]"

# How long past the socket timeout the caller waits for a sink's thread. The
# socket timeout does not cover name resolution; this bound does.
_GRACE_SECONDS = 0.5
_RECENT_FAILURES = 50
_RATE_KEYS_BEFORE_PRUNE = 1024

# ── privacy ─────────────────────────────────────────────────────────

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_FIELD_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,39}$")
_METHOD = re.compile(r"^[A-Z]{1,10}$")
_WORD = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_CWE = re.compile(r"^(?:CWE-)?(\d{1,7})$", re.IGNORECASE)
_TYPE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,79}$")

# A ``fields`` key whose name contains one of these is refused, whatever its value.
_SECRET_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "cookie",
    "credential",
    "authorization",
    "bearer",
    "session",
    "signature",
)
# ... and so is a key one of whose words (split on ``_`` and camelCase) is one of these.
_SECRET_KEY_WORDS = frozenset(
    {
        "pass",
        "pwd",
        "auth",
        "key",
        "keys",
        "jwt",
        "sid",
        "otp",
        "totp",
        "csrf",
        "xsrf",
        "nonce",
        "cred",
        "creds",
        "body",
        "bodies",
        "header",
        "headers",
        "query",
        "payload",
        "preview",
        "response",
    }
)
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_CONTROL = re.compile(r"[\x00-\x1f\x7f  ]+")
_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
_QUERY_IN_TEXT = re.compile(r"\?[^\s?]*=\S*")
_COOKIE_LINE = re.compile(r"\b((?:set-)?cookie\s*[:=]\s*).*", re.IGNORECASE)
_AUTH_LINE = re.compile(r"\b((?:proxy-)?authorization\s*[:=]\s*)\S+(?:\s+\S+)?", re.IGNORECASE)
_AUTH_SCHEME = re.compile(r"\b(bearer|basic|digest|negotiate)\s+[A-Za-z0-9._~+/=-]{8,}", re.I)
_SECRET_KV = re.compile(
    r"""(["']?[\w.-]{0,40}(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key"""
    r"""|private[_-]?key|credential|session(?:[_-]?id)?|jwt|otp|csrf|xsrf)[\w.-]{0,40}["']?\s*[:=]\s*)"""
    r"""(?:"[^"]*"|'[^']*'|[^\s,;&"']+)""",
    re.IGNORECASE,
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?")
_PROVIDER_KEY = re.compile(
    r"\b(?:(?:sk|pk|rk)_(?:live|test)_\w+|gh[pousr]_\w{20,}|xox[abprs]-[\w-]+"
    r"|(?:AKIA|ASIA)[0-9A-Z]{16})\b"
)
_OPAQUE_RUN = re.compile(r"[A-Za-z0-9+/_=~-]{24,}")
_PATH_PARAMS = re.compile(r";[^/]*")


def _is_opaque(segment: str) -> bool:
    """Whether ``segment`` looks like a token rather than a word or a short id."""
    if _JWT.match(segment) or _PROVIDER_KEY.fullmatch(segment):
        return True
    return (
        len(segment) >= 24
        and any(ch.isdigit() for ch in segment)
        and any(ch.isalpha() for ch in segment)
    )


def _mask_run(run: str, keep: frozenset[str]) -> str:
    def mask(part: str) -> str:
        return REDACTED if part not in keep and _is_opaque(part) else part

    if "/" in run and "+" not in run and "=" not in run:
        # A path: judge each segment, so ``/api/v1/orders/items/export`` survives.
        return "/".join(mask(part) for part in run.split("/"))
    return mask(run)


def _url_in_text(match: re.Match[str]) -> str:
    raw = match.group(0)
    url = raw.rstrip(".,;:!?)]}")
    return (sanitize_url(url) or REDACTED) + raw[len(url) :]


def sanitize_url(url: Any) -> str:
    """``scheme://host[:port]/path`` of ``url`` and nothing else.

    Dropped: the query string, the fragment, credentials before the host, path
    parameters (``;jsessionid=...``) and any path segment that looks like a
    token (a reset link, a JWT in the path). A value without a scheme is
    treated as a path. Anything that is not http(s) gives ``""``.
    """
    raw = _CONTROL.sub("", url if isinstance(url, str) else "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        if parts.scheme:
            host = (parts.hostname or "").lower()
            if parts.scheme.lower() not in ("http", "https") or not host:
                return ""
            if ":" in host:
                host = f"[{host}]"
            port = f":{parts.port}" if parts.port is not None else ""
            prefix = f"{parts.scheme.lower()}://{host}{port}"
        elif parts.netloc:
            return ""
        else:
            prefix = ""
        path = _PATH_PARAMS.sub("", parts.path)
    except ValueError:
        return ""
    segments = [REDACTED if _is_opaque(segment) else segment for segment in path.split("/")]
    return (prefix + "/".join(segments))[:MAX_FIELD_VALUE]


def scrub_text(text: Any, *, limit: int = MAX_DETAIL, keep: Iterable[str] = ()) -> str:
    """``text`` as one line with everything that could be a secret removed.

    URLs are reduced with :func:`sanitize_url`; query strings, ``Cookie`` and
    ``Authorization`` values, ``password=...``-style pairs, JWTs, provider keys
    and long opaque strings become ``[redacted]``. ``keep`` lists exact strings
    (the engagement name) that the opaque-string rule must leave alone.
    """
    out = "" if text is None else str(text)
    # Bound the work on a huge input, then drop the word the cut may have split.
    budget = max(4 * limit, 4096)
    if len(out) > budget:
        out = out[:budget].rsplit(None, 1)[0] if out[:budget].split() else ""
    out = _CONTROL.sub(" ", out)
    kept = frozenset(word for word in keep if word)
    out = _URL_IN_TEXT.sub(_url_in_text, out)
    out = _QUERY_IN_TEXT.sub("", out)
    out = _COOKIE_LINE.sub(lambda m: m.group(1) + REDACTED, out)
    out = _AUTH_LINE.sub(lambda m: m.group(1) + REDACTED, out)
    out = _AUTH_SCHEME.sub(lambda m: f"{m.group(1)} {REDACTED}", out)
    out = _SECRET_KV.sub(lambda m: m.group(1) + REDACTED, out)
    out = _JWT.sub(REDACTED, out)
    out = _PROVIDER_KEY.sub(REDACTED, out)
    out = _OPAQUE_RUN.sub(lambda m: _mask_run(m.group(0), kept), out)
    out = " ".join(out.replace("`", "'").split())
    return out if len(out) <= limit else out[: max(0, limit - 1)] + "…"


def secret_like_key(key: str) -> bool:
    """Whether a ``fields`` key is named like something that must not be sent."""
    flat = re.sub(r"[^a-z0-9]", "", key.lower())
    if any(marker in flat for marker in _SECRET_KEY_SUBSTRINGS):
        return True
    words = {word.lower() for word in re.split(r"[_\W]+", _CAMEL.sub("_", key)) if word}
    return bool(words & _SECRET_KEY_WORDS)


def _safe_name(value: Any) -> str:
    """``value`` if it is a plain name (engagement, request id), else ``""``."""
    return value if isinstance(value, str) and _NAME.match(value) else ""


# ── the event ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Event:
    """One thing the operator should know. Built clean or not at all.

    ``kind`` must be one of :data:`KINDS`. ``fields`` is a flat mapping of
    scalars; a key named like a secret, a body or a header is refused with
    ``ValueError`` (a programming error in the caller, not something to send
    in a different shape). ``title``, ``detail`` and string values are passed
    through :func:`scrub_text`. An ``engagement`` that is not a plain name
    becomes ``"unknown"``.
    """

    kind: str
    engagement: str
    title: str
    detail: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    at: float | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"kind must be one of {list(KINDS)}")
        if not isinstance(self.fields, Mapping):
            raise ValueError("fields must be a mapping of scalars")
        if len(self.fields) > MAX_FIELDS:
            raise ValueError(f"fields has more than {MAX_FIELDS} entries")
        engagement = _safe_name(self.engagement) or "unknown"
        keep = (engagement,)
        clean: dict[str, Any] = {}
        for key, value in self.fields.items():
            if not isinstance(key, str) or not _FIELD_KEY.match(key):
                raise ValueError("fields keys must be short identifiers")
            if secret_like_key(key):
                raise ValueError(f"fields key {key!r} is named like a secret, a body or a header")
            if value is None or isinstance(value, (bool, int)):
                clean[key] = value
            elif isinstance(value, float):
                clean[key] = value if math.isfinite(value) else None
            elif isinstance(value, str):
                clean[key] = scrub_text(value, limit=MAX_FIELD_VALUE, keep=keep)
            else:
                raise ValueError(f"fields value for {key!r} must be a string, number or bool")
        at = self.at
        if isinstance(at, bool) or not isinstance(at, (int, float)) or not math.isfinite(at):
            at = time.time()
        object.__setattr__(self, "engagement", engagement)
        object.__setattr__(self, "title", scrub_text(self.title, limit=MAX_TITLE, keep=keep))
        object.__setattr__(self, "detail", scrub_text(self.detail, limit=MAX_DETAIL, keep=keep))
        object.__setattr__(self, "fields", clean)
        object.__setattr__(self, "at", float(at))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "engagement": self.engagement,
            "title": self.title,
            "detail": self.detail,
            "fields": dict(self.fields),
            "at": self.at,
        }


# ── formats ─────────────────────────────────────────────────────────


def _display(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    # A command for the operator to copy is shown as code.
    return f"`{text}`" if text.startswith("buggy-cli ") else text


def _lines(event: Event) -> list[str]:
    lines = [event.detail] if event.detail else []
    lines.extend(f"{key}: {_display(value)}" for key, value in event.fields.items())
    return lines


def generic_payload(event: Event) -> dict[str, Any]:
    """``{kind, engagement, title, detail, fields, at}``."""
    return event.to_dict()


def _slack_escape(text: str) -> str:
    # Slack's three control characters. Escaping ``<`` also disarms ``<!channel>``
    # and ``<url|label>`` in anything that reached the text.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(event: Event) -> dict[str, Any]:
    """``{"text": ...}`` in mrkdwn: one bold title line, then bullets."""
    title = _slack_escape(event.title.replace("*", ""))
    head = f"*{title}* ({_slack_escape(event.engagement)})"
    bullets = [f"• {_slack_escape(line)}" for line in _lines(event)]
    return {"text": "\n".join([head, *bullets])}


def discord_payload(event: Event) -> dict[str, Any]:
    """``{"content": ...}``, at most :data:`DISCORD_MAX_CHARS` characters."""
    head = f"**{event.title.replace('*', '')}** ({event.engagement})"
    content = "\n".join([head, *(f"- {line}" for line in _lines(event))])
    # A zero-width space after ``@`` keeps ``@everyone`` and ``<@id>`` from pinging.
    content = content.replace("@", "@​")
    if len(content) > DISCORD_MAX_CHARS:
        content = content[: DISCORD_MAX_CHARS - 1] + "…"
    return {"content": content}


_FORMATS: dict[str, Callable[[Event], dict[str, Any]]] = {
    "webhook": generic_payload,
    "slack": slack_payload,
    "discord": discord_payload,
}


# ── sinks and delivery ──────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Sink:
    """One destination. ``name`` is ``webhook``, ``slack`` or ``discord`` and picks the format.

    The URL of a chat webhook is itself a credential, so it is left out of ``repr``.
    """

    name: str
    url: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.name not in _FORMATS:
            raise ValueError(f"sink name must be one of {sorted(_FORMATS)}")
        problem = _url_problem(self.url)
        if problem:
            raise ValueError(f"{self.name} sink URL {problem}")


def _url_problem(url: Any) -> str:
    """Why ``url`` cannot be a destination, or ``""``. Never repeats the URL."""
    if not isinstance(url, str) or not url:
        return "is empty"
    if _CONTROL.search(url) or any(ch.isspace() for ch in url):
        return "contains whitespace or control characters"
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError:
        return "is not a valid URL"
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return "must be an absolute http(s) URL"
    return ""


@dataclass(frozen=True, slots=True)
class Delivery:
    """What happened at one sink. ``error`` never contains the sink's URL."""

    sink: str
    ok: bool
    status: int | None = None
    error: str = ""
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink": self.sink,
            "ok": self.ok,
            "status": self.status,
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
        }


def _error_text(exc: BaseException, sink: Sink) -> str:
    reason = getattr(exc, "reason", None)
    if isinstance(exc, TimeoutError) or isinstance(reason, TimeoutError):
        return "timeout"
    text = f"{type(exc).__name__}: {reason if reason is not None else exc}"
    # Some urllib errors quote the URL or its path, and the path of a chat
    # webhook is the secret part.
    parts = urlsplit(sink.url)
    for piece in (sink.url, parts.query, parts.path):
        if len(piece) > 1:
            text = text.replace(piece, "<webhook>")
    return scrub_text(text, limit=MAX_ERROR)


class Notifier:
    """Sends events to the sinks it was built with. See the module docstring."""

    def __init__(
        self,
        sinks: Iterable[Sink] = (),
        *,
        events: Iterable[str] | None = None,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        opener: Callable[..., Any] = urllib.request.urlopen,
        timeout: float = TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        config_errors: Iterable[str] = (),
    ) -> None:
        self._sinks: tuple[Sink, ...] = tuple(sinks)
        self._events = frozenset(KINDS if events is None else events) & frozenset(KINDS)
        self._min_interval = max(0.0, float(min_interval))
        self._opener = opener
        self._timeout = float(timeout)
        self._clock = clock
        self.config_errors: tuple[str, ...] = tuple(config_errors)
        self._lock = threading.Lock()
        self._last: dict[tuple[str, str], float] = {}
        self._suppressed: dict[tuple[str, str], int] = {}
        self._filtered = 0
        self._delivered = 0
        self._failed = 0
        self._failures: deque[dict[str, Any]] = deque(maxlen=_RECENT_FAILURES)

    @classmethod
    def from_env(
        cls,
        opener: Callable[..., Any] = urllib.request.urlopen,
        *,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> Notifier:
        """The notifier the operator configured in this process's environment.

        Never raises: a malformed setting is skipped (a bad URL configures no
        sink, a bad interval means the default), logged without its value and
        listed in ``config_errors``. With no URL set the notifier is a no-op.
        """
        env = os.environ if environ is None else environ
        errors: list[str] = []
        sinks: list[Sink] = []
        for name, variable in (
            ("webhook", ENV_WEBHOOK),
            ("slack", ENV_SLACK),
            ("discord", ENV_DISCORD),
        ):
            url = str(env.get(variable) or "").strip()
            if not url:
                continue
            problem = _url_problem(url)
            if problem:
                errors.append(f"{variable} {problem}; that sink is off")
                continue
            sinks.append(Sink(name, url))

        events: set[str] = set()
        raw_events = [part.strip().lower() for part in str(env.get(ENV_EVENTS) or "").split(",")]
        raw_events = [part for part in raw_events if part]
        if not raw_events or "all" in raw_events or "*" in raw_events:
            events.update(KINDS)
        for part in raw_events:
            if part in KINDS:
                events.add(part)
            elif part not in ("all", "*"):
                errors.append(
                    f"{ENV_EVENTS} names an unknown event kind (known: {', '.join(KINDS)})"
                )

        interval = DEFAULT_MIN_INTERVAL
        raw_interval = str(env.get(ENV_MIN_INTERVAL) or "").strip()
        if raw_interval:
            try:
                interval = float(raw_interval)
                if not math.isfinite(interval) or interval < 0:
                    raise ValueError
            except ValueError:
                interval = DEFAULT_MIN_INTERVAL
                errors.append(
                    f"{ENV_MIN_INTERVAL} is not a non-negative number; using {DEFAULT_MIN_INTERVAL:g}"
                )
        for error in errors:
            _log.warning("notify config: %s", error)
        return cls(
            sinks,
            events=events,
            min_interval=interval,
            opener=opener,
            clock=clock,
            config_errors=errors,
        )

    @property
    def enabled(self) -> bool:
        return bool(self._sinks)

    @property
    def sink_names(self) -> tuple[str, ...]:
        return tuple(sink.name for sink in self._sinks)

    @property
    def events(self) -> tuple[str, ...]:
        return tuple(kind for kind in KINDS if kind in self._events)

    def stats(self) -> dict[str, Any]:
        """Counts since this notifier was built, and the most recent failures."""
        with self._lock:
            return {
                "delivered": self._delivered,
                "failed": self._failed,
                "filtered": self._filtered,
                "suppressed": sum(self._suppressed.values()),
                "suppressed_by": {
                    f"{kind}/{engagement}": count
                    for (kind, engagement), count in sorted(self._suppressed.items())
                },
                "recent_failures": list(self._failures),
            }

    # ── sending ─────────────────────────────────────────────────────

    def notify(self, event: Event) -> list[Delivery]:
        """Send ``event`` to every sink; one :class:`Delivery` per sink tried.

        ``[]`` means nothing was tried: no sink is configured, the kind is not
        in ``BUGGY_NOTIFY_EVENTS``, or an event of the same kind for the same
        engagement was sent less than the minimum interval ago (counted in
        :meth:`stats`). Never raises.
        """
        try:
            return self._notify(event)
        except Exception as exc:
            # Nothing a notification does may fail the action that caused it.
            _log.warning("notify: internal error %s; nothing more was sent", type(exc).__name__)
            delivery = Delivery("notifier", False, error=f"internal error: {type(exc).__name__}")
            try:
                self._record(event, [delivery])
            except Exception:
                pass
            return [delivery]

    def _notify(self, event: Event) -> list[Delivery]:
        if not self._sinks:
            return []
        if not isinstance(event, Event):
            raise TypeError("notify() takes an Event")
        key = (event.kind, event.engagement)
        with self._lock:
            if event.kind not in self._events:
                self._filtered += 1
                return []
            now = self._clock()
            last = self._last.get(key)
            if self._min_interval > 0 and last is not None and now - last < self._min_interval:
                self._suppressed[key] = self._suppressed.get(key, 0) + 1
                return []
            # The window starts when a send is attempted, not when one succeeds:
            # a dead sink must not cost the caller a timeout on every event.
            self._last[key] = now
            if len(self._last) > _RATE_KEYS_BEFORE_PRUNE:
                horizon = now - self._min_interval
                self._last = {k: at for k, at in self._last.items() if at > horizon}
        deliveries = self._send(event)
        self._record(event, deliveries)
        return deliveries

    def _send(self, event: Event) -> list[Delivery]:
        results: list[Delivery | None] = [None] * len(self._sinks)
        guard = threading.Lock()

        def work(index: int, sink: Sink) -> None:
            delivery = self._deliver(sink, event)
            with guard:
                results[index] = delivery

        threads: list[threading.Thread | None] = []
        for index, sink in enumerate(self._sinks):
            thread = threading.Thread(
                target=work, args=(index, sink), name=f"buggy-notify-{sink.name}", daemon=True
            )
            try:
                thread.start()
            except RuntimeError:
                results[index] = Delivery(sink.name, False, error="could not start a thread")
                threads.append(None)
            else:
                threads.append(thread)
        deadline = time.monotonic() + self._timeout + _GRACE_SECONDS
        for thread in threads:
            if thread is not None:
                thread.join(max(0.0, deadline - time.monotonic()))
        with guard:
            return [
                done
                if done is not None
                else Delivery(sink.name, False, error="timeout", elapsed_ms=self._timeout * 1000)
                for sink, done in zip(self._sinks, results, strict=True)
            ]

    def _deliver(self, sink: Sink, event: Event) -> Delivery:
        started = time.monotonic()

        def result(ok: bool, status: int | None = None, error: str = "") -> Delivery:
            return Delivery(sink.name, ok, status, error, (time.monotonic() - started) * 1000)

        try:
            body = json.dumps(_FORMATS[sink.name](event), allow_nan=False).encode("utf-8")
            request = urllib.request.Request(  # noqa: S310 - scheme checked when the sink was built
                sink.url,
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            )
            response = self._opener(request, timeout=self._timeout)
            try:
                status = getattr(response, "status", None)
                landed = getattr(response, "url", None)
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
            if isinstance(landed, str) and landed and landed != sink.url:
                # urllib follows a redirect of a POST as a GET without the body:
                # the answer is from another URL and the message went nowhere.
                return result(False, status, "redirected; the message was not delivered")
            if isinstance(status, int) and 200 <= status < 300:
                return result(True, status)
            return result(False, status if isinstance(status, int) else None, "not a 2xx answer")
        except urllib.error.HTTPError as exc:
            try:
                exc.close()
            except Exception:
                pass
            return result(False, exc.code, f"HTTP {exc.code}")
        except Exception as exc:
            return result(False, None, _error_text(exc, sink))

    def _record(self, event: Any, deliveries: list[Delivery]) -> None:
        kind = getattr(event, "kind", "?")
        engagement = getattr(event, "engagement", "?")
        with self._lock:
            for delivery in deliveries:
                if delivery.ok:
                    self._delivered += 1
                    continue
                self._failed += 1
                self._failures.append(
                    {
                        "at": time.time(),
                        "sink": delivery.sink,
                        "kind": kind,
                        "engagement": engagement,
                        "status": delivery.status,
                        "error": delivery.error,
                    }
                )
        for delivery in deliveries:
            if not delivery.ok:
                _log.warning(
                    "notify: %s delivery of %s for %s failed: %s",
                    delivery.sink,
                    kind,
                    engagement,
                    delivery.error,
                )


# ── events from the existing record shapes ──────────────────────────
#
# These never raise: a record that is missing parts gives an event that says
# less. They copy named, validated parts only.


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            converted = to_dict()
        except Exception:
            return {}
        if isinstance(converted, Mapping):
            return converted
    return {}


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _timestamp(*values: Any) -> float | None:
    for value in values:
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return float(value)
    return None


def _word(value: Any, default: str = "") -> str:
    text = str(value).strip().lower() if isinstance(value, str) else ""
    return text if _WORD.match(text) else default


def _commands(engagement: str, request_id: str) -> dict[str, Any]:
    """What the operator runs. Both parts are plain names, so the line is safe to paste."""
    where = engagement or "<engagement>"
    commands: dict[str, Any] = {}
    if engagement and request_id:
        commands["allow"] = f"buggy-cli approvals allow {engagement} {request_id}"
        commands["deny"] = f"buggy-cli approvals deny {engagement} {request_id}"
    commands["review"] = f"buggy-cli approvals list {where}"
    return commands


def approval_event(request_record: Any) -> Event:
    """An ``approval_required`` event from an approval request record.

    Understands the records written by ``capture/gateway.py::_check_approval``
    (a held HTTP request), ``program/gate.py::report_release`` (a report
    waiting for release) and the agent-tool approval middleware. The record's
    ``reason``, body preview, body hash and other tool arguments are not copied.
    """
    record = _mapping(request_record)
    args = _mapping(record.get("tool_args_redacted"))
    engagement = _safe_name(record.get("engagement_name")) or _safe_name(record.get("engagement"))
    request_id = _safe_name(record.get("request_id"))
    tool = _safe_name(record.get("tool_name")) or "unknown"
    agent = _safe_name(record.get("agent_name"))
    fields: dict[str, Any] = {"request_id": request_id or None, "tool": tool}
    if agent:
        fields["agent"] = agent

    if tool == "http_send":
        method = str(args.get("method") or "").upper()
        method = method if _METHOD.match(method) else ""
        url = sanitize_url(args.get("url"))
        what = " ".join(part for part in (method, url) if part) or "an HTTP request"
        title = f"Approval needed: {what}"
        detail = (
            "A request that can change state on the target is held. Nothing was sent. "
            "The agent re-sends the identical request once it is allowed."
        )
        fields.update({"method": method or None, "url": url or None})
    elif tool == "report_submission":
        finding = _safe_name(args.get("finding_id"))
        report_kind = _word(args.get("kind"), "report")
        title = f"Approval needed: release the {report_kind} for {finding or 'a finding'}"
        draft = f"reports/{request_id}.md" if request_id else "reports/"
        detail = (
            "A report is released only after you approve its exact text. Nothing was "
            f"submitted. The draft is {draft} in this engagement's audit directory."
        )
        fields.update({"finding_id": finding or None, "report_kind": report_kind})
    else:
        title = f"Approval needed: tool {tool}" + (f" ({agent})" if agent else "")
        detail = "An agent action is held until you decide. No answer in time means deny."
    fields.update(_commands(engagement, request_id))
    return Event(
        APPROVAL_REQUIRED,
        engagement,
        title,
        detail,
        fields,
        _timestamp(record.get("created_at"), record.get("requested_at")),
    )


def recon_event(summary: Any) -> Event:
    """A ``recon_finished`` event from a ``recon_summary`` result. Counts only."""
    data = _mapping(summary)
    engagement = _safe_name(data.get("engagement"))
    by_type = {
        name: count
        for name, count in ((_word(k), _count(v)) for k, v in _mapping(data.get("records")).items())
        if name and count
    }
    total = sum(by_type.values())
    run = _mapping(data.get("last_run"))
    diff = _mapping(run.get("diff"))
    status = _word(run.get("status"))
    timed_out = data.get("timed_out") is True
    gaps = _count(data.get("coverage_gap_assets"))

    if timed_out:
        title = f"Recon is still running after the wait limit: {total} records so far"
    elif run:
        title = f"Recon finished ({status or 'status unknown'}): {total} records"
    else:
        title = f"Recon: {total} records, no finished run recorded"
    parts = []
    if by_type:
        parts.append(", ".join(f"{name} {count}" for name, count in sorted(by_type.items())) + ".")
    if gaps:
        parts.append(
            f"{gaps} assets have a stage that did not finish: nothing found there means "
            "not checked, not clean."
        )
    fields: dict[str, Any] = {
        "run_id": _safe_name(run.get("run_id")) or None,
        "status": status or None,
        "records": total,
        "added": _count(diff.get("added")),
        "changed": _count(diff.get("changed")),
        "removed": _count(diff.get("removed")),
        "scope_drops": _count(run.get("scope_drops")),
        "coverage_gap_assets": gaps,
    }
    if timed_out:
        fields["timed_out"] = True
    return Event(
        RECON_FINISHED,
        engagement,
        title,
        " ".join(parts),
        fields,
        _timestamp(run.get("finished_at")),
    )


def finding_event(finding: Any) -> Event:
    """A ``finding_verified`` event from a Finding (the contract dict, or the dataclass).

    Carries the id, severity, class, CWE, method, endpoint host and path,
    status and grade. The finding's title, description, remediation and
    assertions are written by an agent or quote responses, and are not copied.
    A finding whose status is not ``exploit_verified`` is labelled as such.
    """
    data = _mapping(finding)
    engagement = _safe_name(data.get("engagement"))
    finding_id = _safe_name(data.get("id"))
    severity = _word(data.get("severity"), "unknown")
    vuln_class = _word(data.get("class") or data.get("vuln_class"), "unknown")
    status = _word(data.get("status"), "unknown")
    method = str(data.get("method") or "").upper()
    method = method if _METHOD.match(method) else ""
    endpoint = sanitize_url(data.get("endpoint"))
    cwe = _CWE.match(str(data.get("cwe") or "").strip())
    replays = _mapping(data.get("verification")).get("replay_capture_ids")

    where = " ".join(part for part in (method, endpoint) if part)
    what = f"{severity} {vuln_class}" + (f" on {where}" if where else "")
    if status == "exploit_verified":
        title = f"Finding verified: {what}"
        detail = "The finding's assertions held when its requests were re-sent."
    else:
        title = f"Finding not exploit-verified (status {status}): {what}"
        detail = "This is not a verified finding and does not count as one."
    return Event(
        FINDING_VERIFIED,
        engagement,
        title,
        detail,
        {
            "finding_id": finding_id or None,
            "severity": severity,
            "class": vuln_class,
            "cwe": f"CWE-{cwe.group(1)}" if cwe else None,
            "method": method or None,
            "endpoint": endpoint or None,
            "status": status,
            "grade": _word(data.get("grade")) or None,
            "replays": len(replays) if isinstance(replays, (list, tuple)) else None,
        },
        _timestamp(_mapping(data.get("verification")).get("at"), data.get("updated_at")),
    )


def failure_event(engagement: Any, stage: Any, error: Any) -> Event:
    """A ``run_failed`` event: where it failed, the error's type and a scrubbed message."""
    name = _safe_name(engagement)
    where = scrub_text(stage, limit=60, keep=(name,)) or "unknown stage"
    if isinstance(error, BaseException):
        error_type = type(error).__name__
        error_type = error_type if _TYPE_NAME.match(error_type) else "Exception"
        message = str(error)
    else:
        error_type = ""
        message = "" if error is None else str(error)
    title = f"Run failed at {where}" + (f" ({error_type})" if error_type else "")
    return Event(
        RUN_FAILED,
        name,
        title,
        scrub_text(message, limit=MAX_FIELD_VALUE, keep=(name,)),
        {"stage": where, "error_type": error_type or None},
    )


__all__ = [
    "APPROVAL_REQUIRED",
    "DISCORD_MAX_CHARS",
    "FINDING_VERIFIED",
    "KINDS",
    "RECON_FINISHED",
    "RUN_FAILED",
    "Delivery",
    "Event",
    "Notifier",
    "Sink",
    "approval_event",
    "discord_payload",
    "failure_event",
    "finding_event",
    "generic_payload",
    "recon_event",
    "sanitize_url",
    "scrub_text",
    "secret_like_key",
    "slack_payload",
]
