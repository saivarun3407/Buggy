"""Signed-in surface crawl: what a test account can reach, by GET only.

Deterministic code, no model. From operator- or agent-chosen seed URLs the
crawl follows same-host links breadth-first, every request a ``GET`` through
:meth:`CaptureGateway.send` (so scope, the internal-address block, the rate
limit, the capture and the ledger line all apply), optionally as a declared
test account (``identity``) whose session the gateway attaches.

What it will not do, whatever the page says:

* send anything but ``GET``; forms are recorded (method, action, field names
  and default values), never submitted, and a password field's value is
  never kept;
* request a URL whose path or query names an action that could end the
  session or change state through a GET (:data:`NEVER_REQUEST_WORDS`): such
  a URL is listed under ``skipped`` with the reason;
* follow a link to another host than the seeds' hosts;
* spend its budget on one listing: at most :data:`PER_TEMPLATE` URLs are
  requested per path template (numeric, UUID and 24-hex segments are one
  ``{id}``);
* return a response body: the result lists pages by capture id.

Standard library only.
"""

from __future__ import annotations

import json
import re
from collections import deque
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit

from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.capture.store import Capture

PROBE = "surface_crawl"
NOTE = "surface crawl"
DEFAULT_MAX_REQUESTS = 120
MAX_REQUESTS = 300
DEFAULT_MAX_DEPTH = 3
MAX_DEPTH = 10
PER_TEMPLATE = 5
MAX_URLS = 2000
MAX_FORMS = 300
MAX_SKIPPED = 300
MAX_FIELDS = 50
MAX_VALUE = 200
MAX_JSON_STRINGS = 200
MAX_JSON_DEPTH = 6
MAX_URL_LENGTH = 2000

#: Words that make a URL off-limits for a crawler, matched case-insensitively
#: as whole words in the path and query (``-``, ``_``, ``/``, ``.``, ``?``,
#: ``&``, ``=`` and a camelCase step separate words). Applications do act on
#: GETs, and a crawler that clicks every link would undo its own work or the
#: target's data. Each family is here for a reason:
NEVER_REQUEST_WORDS: tuple[str, ...] = (
    # Ends the session the crawl is signed in with: everything after it would
    # be crawled signed out, and a server-side logout may revoke the session
    # other tools of the run share.
    r"log[-_ ]?out",
    r"log[-_ ]?off",
    r"sign[-_ ]?out",
    # Deletes or removes data, the target's or the test account's.
    "delete",
    "remove",
    "destroy",
    "purge",
    "drop",
    # Changes the state of an account, a subscription or a credential.
    "unsubscribe",
    "deactivate",
    "disable",
    "cancel",
    "revoke",
    "reset",
    # Starts a job or a bulk transfer the program did not ask us to trigger
    # (and that is often heavy on the target).
    "export",
    "download",
    # Switches a feature of the application on or off, for the account or for
    # everyone: a link like ?waf=on changed how every later request was answered.
    "enable",
    "toggle",
    "activate",
    "install",
    "uninstall",
)

#: A query value that flips a switch (``?feature=on``).
TOGGLE_VALUES = frozenset({"on", "off", "enable", "disable", "enabled", "disabled"})

#: A form whose action, field names or button labels carry one of these words
#: changes something when it is submitted, whatever its method.
ACTION_WORDS: tuple[str, ...] = (
    *NEVER_REQUEST_WORDS,
    "change", "update", "create", "add", "save", "edit", "upload", "import", "set",
    "password", "passwd", "pwd", "transfer", "pay", "buy", "order", "send", "invite",
    "grant", "apply", "confirm", "register", "signup", "sign[-_ ]?up", "post", "submit[-_ ]?order",
)  # fmt: skip
#: A form that must never be planned at all: submitting it destroys data or
#: reconfigures the application.
DESTRUCTIVE_WORDS: tuple[str, ...] = (
    "delete", "remove", "destroy", "purge", "drop", "reset", "wipe", "truncate", "erase",
    "uninstall", "install", "setup", "create[-_ ]?db", "format", "shutdown", "restart",
)  # fmt: skip
_NEVER = re.compile(
    r"(?<![a-z0-9])(?:" + "|".join(NEVER_REQUEST_WORDS) + r")(?![a-z0-9])", re.IGNORECASE
)
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")


def _word_pattern(words: tuple[str, ...]) -> re.Pattern[str]:
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(words) + r")(?![a-z0-9])", re.IGNORECASE)


_ACTION = _word_pattern(ACTION_WORDS)
_DESTRUCTIVE = _word_pattern(DESTRUCTIVE_WORDS)


def _form_text(form: Any) -> str:
    """The words of a form: its action path and query, its field names and its values."""
    if not isinstance(form, dict):
        return ""
    try:
        parts = urlsplit(str(form.get("action") or ""))
        pieces = [unquote(parts.path), unquote(parts.query.replace("+", " "))]
    except ValueError:
        pieces = []
    for field in form.get("fields") or []:
        if isinstance(field, dict):
            pieces += [str(field.get("name") or ""), str(field.get("value") or "")]
    return _CAMEL.sub(r"\1 \2", " ".join(pieces)).replace("_", " ")


def form_destructive_reason(form: Any) -> str:
    """Why a form must never be submitted by a planned check, or ``""``."""
    match = _DESTRUCTIVE.search(_form_text(form))
    return f"it names {match.group(0).lower()!r}" if match else ""


def form_changes_state(form: Any) -> str:
    """Why submitting a form changes something whatever its method, or ``""``.

    A form sent with GET is not read-only just because of its method: a
    change-password form is often a GET. Such a form is never probed by the
    read-only sweep; it is planned as a run that waits for approval.
    """
    match = _ACTION.search(_form_text(form))
    return f"it names {match.group(0).lower()!r}" if match else ""


#: Extensions that are not worth a request: nothing to extract from them.
STATIC_EXTENSIONS = frozenset(
    {
        # images
        "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "avif", "tif", "tiff",
        # fonts
        "woff", "woff2", "ttf", "otf", "eot",
        # style sheets, and scripts and their maps (recorded, not parsed)
        "css", "js", "mjs", "map",
        # media
        "mp4", "webm", "mp3", "wav", "ogg", "m4a", "mov", "avi", "flac", "mkv",
        # archives
        "zip", "gz", "tgz", "tar", "bz2", "xz", "7z", "rar",
    }
)  # fmt: skip

#: Refusals after which every further request would be refused the same way.
STOP_CODES = frozenset(
    {
        "RATE_LIMITED",
        "NO_ENFORCED_SCOPE",
        "BAD_ENGAGEMENT",
        "UNKNOWN_IDENTITY",
        "BAD_IDENTITIES",
        "LOGIN_FAILED",
        "APPROVAL_SPENT",
    }
)

_ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{24}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)


def never_request_reason(url: str) -> str:
    """Why ``url`` must not be requested by a crawler, or ``""``."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "malformed URL"
    for where, raw in (("path", parts.path), ("query", parts.query)):
        words = _CAMEL.sub(r"\1 \2", unquote(raw.replace("+", " ")))
        match = _NEVER.search(words)
        if match is not None:
            word = match.group(0).lower()
            return f"its {where} names {word!r}, which can end the session or change state"
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if value.strip().lower() in TOGGLE_VALUES:
            return f"its query sets {name!r} to {value.strip().lower()!r}, which flips a switch"
    return ""


def _static(url: str) -> bool:
    last = urlsplit(url).path.rsplit("/", 1)[-1]
    return "." in last and last.rsplit(".", 1)[-1].lower() in STATIC_EXTENSIONS


def normalize(url: str, base: str = "") -> str:
    """``url`` resolved against ``base``, fragment dropped, scheme and host lower-cased.

    ``""`` for anything that is not an http(s) URL with a host (``javascript:``,
    ``mailto:``, ``data:``, a malformed URL).
    """
    raw = (url or "").strip()
    if not raw or len(raw) > MAX_URL_LENGTH:
        return ""
    try:
        joined = urljoin(base, raw) if base else raw
        parts = urlsplit(joined)
        host = parts.hostname
    except ValueError:
        return ""
    if parts.scheme.lower() not in ("http", "https") or not host:
        return ""
    if parts.username or parts.password:
        return ""
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, "")
    )


def template_of(url: str) -> str:
    """The URL's host and path with id-like segments as ``{id}`` (the query is ignored)."""
    parts = urlsplit(url)
    segments = ["{id}" if _ID_SEGMENT.match(s) else s for s in parts.path.split("/")]
    return f"{parts.netloc}{'/'.join(segments)}"


def _header(capture: Capture, name: str) -> str:
    for key, value in capture.response_headers.items():
        if key.lower() == name:
            return str(value)
    return ""


class _Page(HTMLParser):
    """Links and forms of one HTML page; tolerant of broken markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base = ""
        self.links: list[str] = []
        self.actions: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self._select: dict[str, Any] | None = None
        self._select_set = False
        self._textarea: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {key.lower(): (value or "") for key, value in attrs}
        if tag == "base" and a.get("href") and not self.base:
            self.base = a["href"]
        if tag in ("a", "link", "area") and a.get("href"):
            self.links.append(a["href"])
        if tag in ("script", "iframe", "frame") and a.get("src"):
            self.links.append(a["src"])
        if tag == "form":
            self._form = {
                "method": (a.get("method") or "GET").upper()[:10],
                "action": a.get("action", ""),
                "fields": [],
            }
            self.forms.append(self._form)
            return
        form = self._form
        if form is None:
            return
        fields: list[dict[str, str]] = form["fields"]
        name = a.get("name", "")
        if tag == "input" and name and len(fields) < MAX_FIELDS:
            kind = a.get("type", "text").lower()
            value = "" if kind == "password" else a.get("value", "")
            fields.append({"name": name[:MAX_VALUE], "value": value[:MAX_VALUE], "type": kind[:40]})
        elif tag == "select" and name and len(fields) < MAX_FIELDS:
            self._select = {"name": name[:MAX_VALUE], "value": "", "type": "select"}
            self._select_set = False
            fields.append(self._select)
        elif tag == "option" and self._select is not None:
            if not self._select_set or "selected" in a:
                self._select["value"] = a.get("value", "")[:MAX_VALUE]
                self._select_set = True
        elif tag == "textarea" and name and len(fields) < MAX_FIELDS:
            self._textarea = {"name": name[:MAX_VALUE], "value": "", "type": "textarea"}
            fields.append(self._textarea)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = self._select = self._textarea = None
        elif tag == "select":
            self._select = None
        elif tag == "textarea":
            self._textarea = None

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            value = self._textarea["value"] + data
            self._textarea["value"] = value[:MAX_VALUE]


def _decode(capture: Capture) -> str:
    content_type = _header(capture, "content-type")
    charset = "utf-8"
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            charset = value.strip("\"' ")
    try:
        return capture.response_body.decode(charset, "replace")
    except LookupError:
        return capture.response_body.decode("utf-8", "replace")


def _json_strings(document: Any, depth: int = 0) -> list[str]:
    if depth > MAX_JSON_DEPTH:
        return []
    if isinstance(document, str):
        return [document]
    children: list[Any] = []
    if isinstance(document, dict):
        children = list(document.values())
    elif isinstance(document, list):
        children = list(document)
    out: list[str] = []
    for child in children:
        out += _json_strings(child, depth + 1)
    return out


class _Crawl:
    def __init__(
        self,
        gateway: CaptureGateway,
        engagement: str,
        identity: str,
        max_requests: int,
        max_depth: int,
    ) -> None:
        self.gateway = gateway
        self.engagement = engagement
        self.identity = identity
        self.max_requests = max_requests
        self.max_depth = max_depth
        self.hosts: set[str] = set()
        self.queue: deque[tuple[str, int]] = deque()
        self.seen: set[str] = set()
        self.urls: set[str] = set()
        self.templates: dict[str, int] = {}
        self.pages: list[dict[str, Any]] = []
        self.forms: list[dict[str, Any]] = []
        self.skipped: list[dict[str, str]] = []
        self.requested = 0
        self.truncated = False

    def skip(self, url: str, reason: str) -> None:
        if len(self.skipped) < MAX_SKIPPED:
            self.skipped.append({"url": url, "reason": reason})

    def on_host(self, url: str) -> bool:
        return (urlsplit(url).hostname or "") in self.hosts

    def found(self, url: str) -> None:
        if len(self.urls) < MAX_URLS:
            self.urls.add(url)

    def consider(self, url: str, depth: int, *, follow: bool = True) -> None:
        """A discovered (normalised) URL: record it, and queue it if it may be requested."""
        if not url or not self.on_host(url):
            return
        self.found(url)
        if not follow or url in self.seen:
            return
        self.seen.add(url)
        reason = never_request_reason(url)
        if reason:
            self.skip(url, reason)
            return
        if _static(url):
            self.skip(url, "static asset")
            return
        if depth > self.max_depth:
            return
        template = template_of(url)
        count = self.templates.get(template, 0)
        if count >= PER_TEMPLATE:
            self.skip(url, f"{PER_TEMPLATE} URLs of the template {template} are already queued")
            return
        self.templates[template] = count + 1
        self.queue.append((url, depth))

    def run(self) -> None:
        while self.queue:
            if self.requested >= self.max_requests:
                self.truncated = True
                return
            url, depth = self.queue.popleft()
            try:
                capture = self.gateway.send(
                    self.engagement,
                    "GET",
                    url,
                    identity=self.identity,
                    note=NOTE,
                    probe=PROBE,
                )
            except GatewayRefusal as refusal:
                if refusal.code in STOP_CODES:
                    self.skip(url, f"refused: {refusal.code} (the crawl stopped): {refusal.detail}")
                    self.truncated = True
                    return
                self.skip(url, f"refused: {refusal.code}: {refusal.detail}")
                continue
            self.requested += 1
            self.read(url, depth, capture)

    def read(self, url: str, depth: int, capture: Capture) -> None:
        content_type = _header(capture, "content-type").split(";")[0].strip().lower()
        self.pages.append(
            {
                "url": url,
                "status": capture.status,
                "content_type": content_type,
                "capture_id": capture.id,
            }
        )
        status = capture.status or 0
        if 300 <= status < 400:
            location = _header(capture, "location")
            if location:
                self.consider(normalize(location, url), depth + 1)
            return
        if content_type in ("text/html", "application/xhtml+xml"):
            self.read_html(url, depth, _decode(capture))
        elif content_type == "application/json" or content_type.endswith("+json"):
            self.read_json(url, depth, _decode(capture))

    def read_html(self, url: str, depth: int, body: str) -> None:
        page = _Page()
        try:
            page.feed(body)
            page.close()
        except (AssertionError, ValueError):
            pass  # what was parsed before the markup broke is still used
        base = normalize(page.base, url) or url
        for link in page.links:
            self.consider(normalize(link, base), depth + 1)
        for form in page.forms:
            action = normalize(form["action"], base) if form["action"] else base
            if action:
                self.consider(action, depth + 1, follow=False)
            if len(self.forms) < MAX_FORMS:
                self.forms.append(
                    {
                        "page": url,
                        "method": form["method"],
                        "action": action,
                        "fields": list(form["fields"]),
                    }
                )

    def read_json(self, url: str, depth: int, body: str) -> None:
        try:
            document = json.loads(body)
        except ValueError:
            return
        taken = 0
        for value in _json_strings(document):
            if taken >= MAX_JSON_STRINGS:
                return
            text = value.strip()
            if not text or any(ch.isspace() for ch in text):
                continue
            if text.startswith("/") and not text.startswith("//"):
                candidate = normalize(text, url)
            elif text.lower().startswith(("http://", "https://")):
                candidate = normalize(text)
            else:
                continue
            if candidate and self.on_host(candidate):
                taken += 1
                self.consider(candidate, depth + 1)

    def result(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "requested": self.requested,
            "truncated": self.truncated,
            "pages": self.pages,
            "urls": sorted(self.urls),
            "forms": self.forms,
            "skipped": self.skipped,
        }


def crawl(
    gateway: CaptureGateway,
    engagement: str,
    seeds: list[str],
    *,
    identity: str = "",
    max_requests: int = DEFAULT_MAX_REQUESTS,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> dict[str, Any]:
    """Crawl breadth-first from ``seeds`` by GET, as ``identity`` when one is named.

    Returns ``{"identity", "requested", "truncated", "pages": [{"url", "status",
    "content_type", "capture_id"}], "urls": [...], "forms": [{"page", "method",
    "action", "fields": [{"name", "value", "type"}]}], "skipped": [{"url", "reason"}]}``.
    ``type`` is the input type (``password``, ``checkbox``, ``hidden``, ...),
    ``select`` or ``textarea``; a password field's value is always ``""``.
    ``truncated`` is true when the budget ran out with URLs still queued, or a
    refusal stopped the crawl (named under ``skipped``). A refusal for one URL
    (out of scope, internal address) is listed under ``skipped`` and the crawl
    goes on. An unknown ``identity`` raises :class:`GatewayRefusal` before
    anything is sent.
    """
    name = str(identity or "").strip()
    if name:
        gateway.check_identity(engagement, name)
    state = _Crawl(
        gateway,
        engagement,
        name,
        max(0, min(int(max_requests), MAX_REQUESTS)),
        max(0, min(int(max_depth), MAX_DEPTH)),
    )
    starts: list[str] = []
    for seed in seeds or []:
        url = normalize(seed) if isinstance(seed, str) else ""
        if not url:
            state.skip(str(seed)[:MAX_URL_LENGTH], "a seed must be an absolute http(s) URL")
            continue
        state.hosts.add(urlsplit(url).hostname or "")
        starts.append(url)
    for url in starts:
        state.consider(url, 0)
    state.run()
    return state.result()


__all__ = [
    "MAX_REQUESTS",
    "NEVER_REQUEST_WORDS",
    "PER_TEMPLATE",
    "STATIC_EXTENSIONS",
    "crawl",
    "form_changes_state",
    "form_destructive_reason",
    "never_request_reason",
    "normalize",
    "template_of",
]
