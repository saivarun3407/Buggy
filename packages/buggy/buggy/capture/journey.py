"""A test account uses the application the way a person would: by GET, through the gateway.

Deterministic code, no model. The HTML crawl (:mod:`buggy.capture.crawl`)
sees little of a single-page application: its pages are built in the browser
from JSON. The user walk adds what such an application's own front end would
ask for, as one signed-in account:

1. every concrete API ``GET`` endpoint recon found (``endpoint``,
   ``api_profile``, ``api_operation``), next to the HTML pages, walked like
   the crawl walks pages (same-host links, links in JSON answers);
2. then the endpoints recon knows only as templates (``/rest/basket/{id}``,
   ``/api/Users/{id}``), filled with identifiers this account itself received
   in earlier answers: its own user id and basket id (from its sign-in, or
   from an answer that carries its email), and ids listed in answers it got.

Everything the crawl refuses is refused here too: only ``GET``, never a URL
:func:`buggy.capture.crawl.never_request_reason` names, same hosts only, the
gateway's scope check, rate limit and ledger on every request, and a request
budget per account.

The result is the crawl's (``identity``, ``requested``, ``truncated``,
``pages``, ``urls``, ``forms``, ``skipped``) plus ``filled`` (the templated
URLs asked for and their status), ``own_data`` (URLs whose answer carried the
account's own marker) and ``owned`` (filled URLs whose identifier the target
gave this account as its own, for the same kind of object, and that answered
2xx). Owner inference reads ``urls`` and ``owned``; nothing else is needed.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from buggy.capture import accounts, crawl
from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.capture.store import Capture
from buggy.pipeline.tools import apirecon

PROBE = "user_walk"
NOTE = "user walk"
DEFAULT_MAX_REQUESTS = 150
MAX_REQUESTS = 300
#: Requests kept back from the walk for the templated endpoints.
FILL_RESERVE = 40
#: Identifiers tried per templated endpoint, and rounds of filling.
FILL_PER_TEMPLATE = 2
FILL_ROUNDS = 2
MAX_SEEDS = 150
MAX_TEMPLATES = 60
MAX_IDS = 500
MAX_FILLED = 200

_PLACEHOLDER = re.compile(r"^(?:\{[^}/]*\}|:[A-Za-z_]\w*|<[^>/]*>|%7B.*%7D)$", re.IGNORECASE)


# ── what to walk, read off recon records (pure) ─────────────────────


def _attrs(record: Any) -> dict[str, Any]:
    raw = record.get("attrs") if isinstance(record, dict) else None
    return raw if isinstance(raw, dict) else {}


def _clean(url: Any) -> str:
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return ""
    return url.split("#", 1)[0]


def walk_plan(records: Any, services: Any = ()) -> dict[str, list[str]]:
    """``{"seeds": [url], "templates": [url]}`` for a user walk, from recon records.

    Seeds are the live services (the HTML pages start there), then the API
    endpoints recon saw asking for credentials, then the other concrete API
    ``GET`` endpoints. Templates are API ``GET`` endpoints with one
    placeholder. A URL the crawler must never request is left out.
    """
    records = records if isinstance(records, dict) else {}
    first: list[str] = [u for u in (_clean(s) for s in services or ()) if u]
    guarded: list[str] = []
    api: list[str] = []
    templates: list[str] = []
    for record in records.get("api_profile") or []:
        attrs = _attrs(record)
        url = _clean(attrs.get("url"))
        if not url or attrs.get("status") in apirecon.NOT_THERE:
            continue
        (guarded if attrs.get("auth") == "required" else api).append(url)
    for record in records.get("api_operation") or []:
        attrs = _attrs(record)
        url = _clean(attrs.get("url"))
        if url and str(attrs.get("method") or "").upper() == "GET":
            (templates if apirecon.is_template(url) else api).append(url)
    for record in records.get("endpoint") or []:
        url = _clean(record.get("value") if isinstance(record, dict) else None)
        # The script's own call names its method; the walk only GETs what the app GETs.
        method = str(_attrs(record).get("method") or "GET").upper()
        if url and apirecon.api_root(url) and method == "GET":
            (templates if apirecon.is_template(url) else api).append(url)
    seeds = [
        url
        for url in dict.fromkeys([*first, *guarded, *api])
        if not apirecon.is_template(url)
        and not crawl.never_request_reason(url)
        and not _signs_in(url)
    ]
    shaped = [
        url
        for url in dict.fromkeys(templates)
        if _template_parts(url) is not None and not crawl.never_request_reason(url)
    ]
    return {"seeds": seeds[:MAX_SEEDS], "templates": shaped[:MAX_TEMPLATES]}


def _signs_in(url: str) -> bool:
    """A login or sign-up endpoint: the account is already signed in, a GET there is noise."""
    last = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1].lower()
    return last in _SIGN_IN_SEGMENTS


_SIGN_IN_SEGMENTS = frozenset(
    {"login", "log-in", "signin", "sign-in", "sign_in", "authenticate", "register", "signup"}
)


def _template_parts(url: str) -> tuple[list[str], int, str] | None:
    """``(path segments, placeholder index, collection)`` of a one-placeholder template."""
    try:
        segments = urlsplit(url).path.split("/")
    except ValueError:
        return None
    holes = [i for i, segment in enumerate(segments) if _PLACEHOLDER.match(segment)]
    if len(holes) != 1 or holes[0] < 2:
        return None
    collection = segments[holes[0] - 1]
    if not collection or _PLACEHOLDER.match(collection):
        return None
    return segments, holes[0], collection


# ── choosing identifiers for a template ─────────────────────────────


def _singular(word: str) -> str:
    low = word.lower().replace("-", "").replace("_", "")
    return low[:-1] if len(low) > 3 and low.endswith("s") else low


def _related(found: dict[str, Any], collection: str) -> bool:
    """Whether an identifier is one of ``collection``'s: by its key or the words around it.

    ``basketId`` / ``basket_id`` / ``bid`` belong to ``basket``; a plain ``id``
    belongs to it when it sat under ``basket`` or came from ``/api/Baskets``.
    """
    noun = _singular(collection)
    if not noun:
        return False
    key = str(found.get("key") or "")
    low = key.lower()
    stem = re.sub(r"[-_]?id$", "", low)
    if stem and stem != low and _singular(stem) == noun:
        return True
    if len(low) == 3 and low.endswith("id") and noun.startswith(low[0]):
        return True
    if low not in ("id", "uuid", "guid"):
        return False
    return any(_singular(str(word)) == noun for word in found.get("context") or [])


def _rank(found: dict[str, Any], collection: str) -> int:
    """3: the account's own, of this kind; 2: of this kind; 1: the account's own; 0: other."""
    related = _related(found, collection)
    if found.get("own"):
        return 3 if related else 1
    return 2 if related else 0


# ── the walk ────────────────────────────────────────────────────────


class _Walk(crawl._Crawl):  # noqa: SLF001 - same package, the crawler it extends
    def __init__(
        self,
        gateway: CaptureGateway,
        engagement: str,
        identity: str,
        max_requests: int,
        max_depth: int,
        markers: list[str],
        own_ids: list[dict[str, Any]],
    ) -> None:
        super().__init__(gateway, engagement, identity, max_requests, max_depth)
        self.markers = [m for m in markers if m]
        self.ids: list[dict[str, Any]] = []
        self._id_keys: set[tuple[str, str, bool]] = set()
        for found in own_ids:
            self.remember({**found, "own": True})
        self.pending: dict[str, dict[str, Any]] = {}
        self.filled: list[dict[str, Any]] = []
        self.tried: dict[str, set[str]] = {}
        self.own_data: list[str] = []
        self.owned: list[str] = []
        self.stopped = False

    def remember(self, found: dict[str, Any]) -> None:
        key = (str(found.get("key")), str(found.get("value")), bool(found.get("own")))
        if key in self._id_keys or len(self.ids) >= MAX_IDS or not key[1]:
            return
        self._id_keys.add(key)
        self.ids.append(found)

    def run(self) -> None:
        # Same loop as the crawl, under this walk's own note and probe name.
        while self.queue:
            if self.requested >= self.max_requests:
                self.truncated = True
                return
            url, depth = self.queue.popleft()
            try:
                capture = self.gateway.send(
                    self.engagement, "GET", url, identity=self.identity, note=NOTE, probe=PROBE
                )
            except GatewayRefusal as refusal:
                self.pending.pop(url, None)
                if refusal.code in crawl.STOP_CODES:
                    self.skip(url, f"refused: {refusal.code} (the walk stopped): {refusal.detail}")
                    self.truncated = True
                    self.stopped = True
                    return
                self.skip(url, f"refused: {refusal.code}: {refusal.detail}")
                continue
            self.requested += 1
            self.read(url, depth, capture)

    def read(self, url: str, depth: int, capture: Capture) -> None:
        fill = self.pending.pop(url, None)
        super().read(url, depth, capture)
        status = capture.status or 0
        answered = 200 <= status < 300
        if fill is not None:
            if len(self.filled) < MAX_FILLED:
                self.filled.append(
                    {"template": fill["template"], "url": url, "status": capture.status}
                )
            if answered:
                self.found(url)
                if fill["owned"]:
                    self.owned.append(url)
        if not answered:
            return
        body = crawl._decode(capture)  # noqa: SLF001 - same package
        if self.markers and any(marker in body for marker in self.markers):
            self.own_data.append(url)
        kind = crawl._header(capture, "content-type").split(";")[0].strip().lower()  # noqa: SLF001
        if kind != "application/json" and not kind.endswith("+json"):
            return
        try:
            document = json.loads(body)
        except ValueError:
            return
        words = [w.lower() for w in urlsplit(url).path.split("/") if w]
        for found in crawl.json_ids(document, self.markers, context=words):
            self.remember(found)

    def answered(self, url: str) -> bool:
        return any(page["url"] == url and 200 <= (page["status"] or 0) < 300 for page in self.pages)

    def fill(self, templates: list[str]) -> int:
        """Queue templated URLs filled with identifiers this account received. Returns how many."""
        added: list[str] = []
        for template in templates:
            parts = _template_parts(template)
            if parts is None or not self.on_host(template):
                continue
            segments, hole, collection = parts
            tried = self.tried.setdefault(template, set())
            room = FILL_PER_TEMPLATE - len(tried)
            if room <= 0:
                continue
            ranked = sorted(
                enumerate(self.ids), key=lambda item: (-_rank(item[1], collection), item[0])
            )
            for _index, found in ranked:
                if room <= 0:
                    break
                value = str(found["value"])
                if value in tried:
                    continue
                filled = list(segments)
                filled[hole] = quote(value, safe="")
                url = crawl.normalize(
                    urlunsplit(urlsplit(template)._replace(path="/".join(filled)))
                )
                tried.add(value)
                owned = _rank(found, collection) == 3
                if url and url in self.seen:
                    # The walk already asked for it (a link led there): it still counts.
                    if owned and self.answered(url):
                        self.owned.append(url)
                    continue
                if not url or crawl.never_request_reason(url):
                    continue
                room -= 1
                self.seen.add(url)
                self.pending[url] = {"template": template, "owned": owned}
                added.append(url)
        # Filled URLs go first: they are what the walk kept its reserve for.
        for url in reversed(added):
            self.queue.appendleft((url, self.max_depth))
        return len(added)

    def result(self) -> dict[str, Any]:
        out = super().result()
        out.update(
            {
                "filled": self.filled,
                "own_data": sorted(set(self.own_data)),
                "owned": sorted(set(self.owned)),
                "ids_seen": len(self.ids),
            }
        )
        return out


def walk(
    gateway: CaptureGateway,
    engagement: str,
    seeds: list[str],
    *,
    identity: str,
    templates: list[str] | tuple[str, ...] = (),
    max_requests: int = DEFAULT_MAX_REQUESTS,
    max_depth: int = crawl.DEFAULT_MAX_DEPTH,
) -> dict[str, Any]:
    """Use the application as ``identity``: walk ``seeds``, then fill ``templates``.

    At most ``max_requests`` GET requests (clamped to :data:`MAX_REQUESTS`); up
    to :data:`FILL_RESERVE` of them are kept for the templated endpoints. An
    unknown ``identity`` raises :class:`GatewayRefusal` before anything is
    sent. See the module docstring for the result.
    """
    name = str(identity or "").strip()
    if not name:
        raise GatewayRefusal("BAD_ARGUMENT", "a user walk needs a test account (identity)")
    gateway.check_identity(engagement, name)
    budget = max(0, min(int(max_requests), MAX_REQUESTS))
    shaped = [t for t in templates or () if isinstance(t, str) and _template_parts(t) is not None]
    reserve = min(FILL_RESERVE, budget // 3) if shaped else 0
    markers = [str(m) for m in gateway.identities.markers(engagement).get(name, ()) if str(m)]
    state = _Walk(
        gateway,
        engagement,
        name,
        budget - reserve,
        max(0, min(int(max_depth), crawl.MAX_DEPTH)),
        markers,
        accounts.stored_own_ids(gateway, engagement, name),
    )
    for seed in seeds or []:
        url = crawl.normalize(seed) if isinstance(seed, str) else ""
        if not url:
            state.skip(str(seed)[: crawl.MAX_URL_LENGTH], "a seed must be an absolute http(s) URL")
            continue
        state.hosts.add(urlsplit(url).hostname or "")
    for seed in seeds or []:
        url = crawl.normalize(seed) if isinstance(seed, str) else ""
        if url:
            state.consider(url, 0)
    state.run()
    state.max_requests = budget
    for _round in range(FILL_ROUNDS):
        if state.stopped or not shaped or state.fill(shaped) == 0:
            break
        state.run()
    if not state.stopped:
        state.run()  # what the reserve did not use goes to the rest of the walk
    state.truncated = state.stopped or bool(state.queue)
    return state.result()


__all__ = [
    "DEFAULT_MAX_REQUESTS",
    "FILL_PER_TEMPLATE",
    "MAX_REQUESTS",
    "walk",
    "walk_plan",
]
