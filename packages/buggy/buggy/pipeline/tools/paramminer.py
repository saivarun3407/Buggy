"""Hidden-parameter discovery: query names, headers and cookies the site reacts to but never links.

The idea follows PortSwigger's Param Miner, Arjun and x8 (see docs/pipeline.md,
"Hidden parameters"); the code and the word lists are Buggy's own.

1. Baseline: the same request three times, each with one made-up name, to learn
   what "no change" looks like: the status, the response lines that vary on
   their own (timestamps, tokens), and the header names.
2. Guess in bulk: many candidate names in one request, each with its own
   random value.
3. Narrow down: a batch that changed the response is split in half until single
   names are left; each is then checked again with a new value, next to a
   made-up control name that must change nothing.
4. Signals: a different status, response lines that were not there (or are
   gone) beyond the noise, different header names, or the name's random value
   echoed back (reflected; a lead for XSS and injection).

Pure code: the request is a callback, so this module never touches the
network. The pipeline's ``paramguess`` stage sends through the scoped,
rate-limited client.
"""

from __future__ import annotations

import re
import secrets
import string
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

NAME = "param_miner"
LOCATIONS = ("query", "header", "cookie")
DATA = Path(__file__).with_name("data")

#: Names per request, by where they go.
CHUNK = {"query": 96, "header": 20, "cookie": 24}
#: Longest query string a guessing request may carry.
MAX_QUERY_CHARS = 3000
#: Response headers that change on their own and say nothing about a name.
VOLATILE_HEADERS = frozenset(
    {
        "date", "expires", "age", "etag", "last-modified", "set-cookie", "content-length",
        "x-request-id", "x-correlation-id", "x-runtime", "server-timing", "cf-ray", "report-to",
        "nel", "x-amzn-trace-id", "x-amz-cf-id", "x-served-by", "x-timer", "via",
    }
)  # fmt: skip
#: Request headers never guessed: the client sets them, or they change the transport.
NEVER_SEND_HEADERS = frozenset(
    {"host", "content-length", "connection", "transfer-encoding", "te", "upgrade", "cookie",
     "proxy-authorization", "authorization", "expect", "keep-alive", "trailer"}
)  # fmt: skip
#: Values tried on a found name that reads like a switch (x8's "custom parameters").
SWITCH_VALUES = ("true", "1", "admin")
_SWITCH = re.compile(r"(?i)^(debug|test|dev|admin|is_?admin|preview|beta|internal|verbose|trace)$")
_GOOD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-.\[\]]{0,40}$")
_PATH_WORD = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,29}$")
MAX_LINES = 3000


def _load(file_name: str) -> list[str]:
    try:
        text = (DATA / file_name).read_text(encoding="utf-8")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def curated(location: str) -> list[str]:
    """Buggy's curated list for ``location`` (query, header or cookie)."""
    return _load(
        {"query": "param_names.txt", "header": "header_names.txt"}.get(location, "cookie_names.txt")
    )


def harvest(
    parameter_names: Iterable[str] = (),
    json_fields: Iterable[str] = (),
    urls: Iterable[str] = (),
) -> list[str]:
    """Names the engagement already shows: parameters, JSON field names, path words.

    Param Miner harvests words from in-scope traffic; these are the same kind of
    words, read from what recon stored.
    """
    found = [str(n).split(".")[-1].split("[")[0] for n in parameter_names]
    for field_name in json_fields:
        found += str(field_name).split(".")
    for url in urls:
        found += [s for s in urlsplit(url).path.split("/") if _PATH_WORD.match(s)]
    return [name for name in dict.fromkeys(found) if _GOOD_NAME.match(name)]


_STATIC = re.compile(
    r"(?i)\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|pdf|zip|gz|mp4|mp3|txt|xml)$"
)


def choose_endpoints(
    origin: str,
    profiled: Iterable[str] = (),
    pages: Iterable[str] = (),
    *,
    never: Callable[[str], Any] | None = None,
    per_origin: int = 4,
) -> list[str]:
    """Up to ``per_origin`` URLs of ``origin`` to guess names on: API endpoints
    that answered, then pages, then the root. No query, no static files, no
    template, nothing ``never`` gives a reason for (logout, delete and the like)."""
    out: list[str] = []
    for url in [*profiled, *pages, origin + "/"]:
        url = url.split("#", 1)[0].split("?", 1)[0]
        if not url.startswith(origin + "/") and url != origin:
            continue
        path = urlsplit(url).path
        if _STATIC.search(path) or "{" in url or ":" in path or (never is not None and never(url)):
            continue
        if url not in out:
            out.append(url)
        if len(out) >= per_origin:
            break
    return out


def wordlist(
    location: str, harvested: Iterable[str], known: Iterable[str] = (), limit: int = 1500
) -> list[str]:
    """The names to guess: harvested first, then the curated list; known names left out."""
    skip = {name.lower() for name in known}
    names = list(harvested) + curated(location) if location == "query" else curated(location)
    if location == "header":
        names = [n for n in names if n.lower() not in NEVER_SEND_HEADERS]
    out = [n for n in dict.fromkeys(names) if n.lower() not in skip and _GOOD_NAME.match(n)]
    return out[:limit]


def random_value(length: int = 8) -> str:
    """A value that does not occur in normal pages (letters and digits, a fixed prefix)."""
    alphabet = string.ascii_lowercase + string.digits
    return "zq" + "".join(secrets.choice(alphabet) for _ in range(length))


@dataclass(frozen=True)
class Snapshot:
    status: int
    lines: frozenset[str]
    headers: frozenset[str]
    body: str


def snapshot(status: int, headers: Mapping[str, str], body: str) -> Snapshot:
    lines = frozenset(line.strip() for line in body.splitlines()[:MAX_LINES] if line.strip())
    names = frozenset(k.lower() for k in headers if k.lower() not in VOLATILE_HEADERS)
    return Snapshot(status, lines, names, body)


_VARYING = re.compile(r"(?i)\b[0-9a-f]{16,}\b|[A-Za-z0-9+/_-]{32,}={0,2}|\d+")


def _shape(snap: Snapshot, values: Iterable[str]) -> frozenset[str]:
    """The page's lines with numbers and long tokens blanked, minus the lines that
    carry a value this request sent (an echo is the reflection signal, not a change)."""
    sent = [v for v in values if v]
    return frozenset(
        _VARYING.sub("#", line) for line in snap.lines if not any(v in line for v in sent)
    )


# (location, {name: value}) -> Snapshot, or None when the request got no answer.
Send = Callable[[str, dict[str, str]], Snapshot | None]


@dataclass
class Found:
    name: str
    location: str
    reason: str  # status_changed, body_changed, headers_changed, reflected
    detail: str = ""


@dataclass
class Outcome:
    found: list[Found] = field(default_factory=list)
    requests: int = 0
    errors: int = 0
    skipped: str = ""  # why nothing was guessed (unstable page, budget, no answer)


class Miner:
    """Guesses names for one endpoint and one location within a request budget."""

    def __init__(self, send: Send, location: str, *, max_requests: int) -> None:
        self.send = send
        self.location = location
        self.max_requests = max_requests
        self.outcome = Outcome()
        self.base: Snapshot | None = None
        self.noise_lines: set[str] = set()
        self.base_shape: frozenset[str] = frozenset()
        self.noise_headers: set[str] = set()
        self.reflection = True

    def _request(self, pairs: dict[str, str]) -> Snapshot | None:
        if self.outcome.requests >= self.max_requests:
            raise _Budget
        self.outcome.requests += 1
        snap = self.send(self.location, pairs)
        if snap is None:
            self.outcome.errors += 1
        return snap

    def _baseline(self) -> bool:
        snaps: list[tuple[Snapshot, str]] = []
        for _ in range(3):
            junk = random_value(6)
            value = random_value()
            snap = self._request({junk: value})
            if snap is None:
                self.outcome.skipped = "the page did not answer"
                return False
            if value in snap.body:
                self.reflection = False  # any name is echoed: reflection says nothing here
            snaps.append((snap, value))
        if len({s.status for s, _v in snaps}) > 1:
            self.outcome.skipped = "the status changes on its own"
            return False
        shapes = [_shape(s, [v]) for s, v in snaps]
        for other, (snap, _v) in zip(shapes[1:], snaps[1:], strict=True):
            self.noise_lines |= set(shapes[0] ^ other)
            self.noise_headers |= set(snaps[0][0].headers ^ snap.headers)
        self.base = snaps[0][0]
        self.base_shape = shapes[0]
        return True

    def _changed(self, snap: Snapshot, values: Iterable[str]) -> str:
        base = self.base
        assert base is not None
        if snap.status != base.status:
            return "status_changed"
        if (_shape(snap, values) ^ self.base_shape) - self.noise_lines:
            return "body_changed"
        if (snap.headers ^ base.headers) - self.noise_headers:
            return "headers_changed"
        return ""

    def _reflected(self, snap: Snapshot, pairs: dict[str, str]) -> list[str]:
        if not self.reflection:
            return []
        return [name for name, value in pairs.items() if value in snap.body]

    def _split(self, names: list[str], into: list[tuple[str, str]]) -> None:
        if len(names) == 1:
            into.append((names[0], ""))
            return
        half = len(names) // 2
        for part in (names[:half], names[half:]):
            pairs = {name: random_value() for name in part}
            snap = self._request(pairs)
            if snap is None:
                continue
            reason = self._changed(snap, pairs.values())
            if reason:
                self._split(part, into)

    def _confirm(self, name: str, reflected: bool) -> Found | None:
        """Check a single name again with a new value, next to a control that changes nothing."""
        value = random_value()
        snap = self._request({name: value})
        if snap is None:
            return None
        control_value = random_value()
        control = self._request({random_value(6): control_value})
        if control is None or self._changed(control, [control_value]):
            return None  # the page moved on its own: no verdict
        if reflected and self.reflection and value in snap.body:
            return Found(name, self.location, "reflected", "the value comes back in the answer")
        reason = self._changed(snap, [value])
        return Found(name, self.location, reason) if reason else None

    def _switches(self, names: list[str], skip: set[str]) -> list[Found]:
        """Names that read like a switch, sent together with ``true``, ``1``, ``admin``;
        a value that changes the answer is then tried on each name alone."""
        switches = [n for n in names if _SWITCH.match(n) and n not in skip]
        out: list[Found] = []
        for value in SWITCH_VALUES:
            if not switches:
                break
            snap = self._request(dict.fromkeys(switches, value))
            if snap is None or not self._changed(snap, ()):
                continue
            for name in list(switches):
                single = self._request({name: value})
                reason = self._changed(single, ()) if single is not None else ""
                if reason:
                    out.append(Found(name, self.location, reason, f"with the value {value!r}"))
                    switches.remove(name)
        return out

    def run(self, names: list[str]) -> Outcome:
        try:
            if not names or not self._baseline():
                return self.outcome
            candidates: list[tuple[str, str]] = []
            reflected: set[str] = set()
            for chunk in _chunks(names, self.location):
                pairs = {name: random_value() for name in chunk}
                snap = self._request(pairs)
                if snap is None:
                    continue
                echoed = self._reflected(snap, pairs)
                reflected.update(echoed)
                if self._changed(snap, pairs.values()):
                    self._split([n for n in chunk if n not in echoed], candidates)
            names_to_check = list(dict.fromkeys([n for n, _ in candidates] + sorted(reflected)))
            # x8's --strict idea: when very many names "change" the page, none of them is trusted.
            if len(names_to_check) > max(8, len(names) // 10):
                self.outcome.skipped = (
                    f"{len(names_to_check)} names changed the answer: the page reacts to any name"
                )
                return self.outcome
            for name in names_to_check:
                found = self._confirm(name, name in reflected)
                if found is not None:
                    self.outcome.found.append(found)
            self.outcome.found += self._switches(names, {f.name for f in self.outcome.found})
        except _Budget:
            self.outcome.skipped = self.outcome.skipped or "request budget used up"
        return self.outcome


class _Budget(Exception):
    pass


def _chunks(names: list[str], location: str) -> Iterable[list[str]]:
    size = CHUNK.get(location, 32)
    chunk: list[str] = []
    for name in names:
        trial = [*chunk, name]
        too_long = (
            location == "query"
            and len(urlencode({n: "zq" + "x" * 8 for n in trial})) > MAX_QUERY_CHARS
        )
        if chunk and (len(trial) > size or too_long):
            yield chunk
            chunk = [name]
        else:
            chunk = trial
    if chunk:
        yield chunk


__all__ = [
    "CHUNK",
    "LOCATIONS",
    "NAME",
    "Found",
    "Miner",
    "Outcome",
    "Snapshot",
    "choose_endpoints",
    "curated",
    "harvest",
    "random_value",
    "snapshot",
    "wordlist",
]
