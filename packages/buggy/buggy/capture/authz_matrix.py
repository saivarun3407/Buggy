"""Authorization matrix: every URL asked as every identity, and compared.

Access control is tested by asking for the same object as its owner, as
another user and with no credentials. :func:`run_matrix` does that for a list
of URLs the caller supplies and a set of declared identities (see
:mod:`buggy.capture.identities`), and says for each URL whether somebody who
does not own it received the owner's data.

Every request is a ``GET`` (or ``HEAD``) sent through
:meth:`CaptureGateway.send` with ``identity=<name>``: the gateway attaches the
session, checks scope, applies the rate limit and records the exchange. This
module never holds a credential and never sends a state-changing request; the
only other traffic it can cause is an identity's declared login, which the
session manager sends through the same gateway.

Verdict per URL:

``broken_access``
    the owner read it (2xx, twice, the same both times) and a non-owner or an
    unauthenticated request also got 2xx with the owner's content: similarity
    to the owner's response of at least ``SAME``, or one of the owner's marker
    strings in the body. A candidate finding is emitted.
``enforced``
    every non-owner was answered 401/403/404, or with something clearly
    different (similarity below ``DIFFERENT``), and no marker appeared.
``public``
    nobody is known to own the URL, no marker is defined for it, and the
    unauthenticated request got the same content as every identity. Not a
    finding; listed separately.
``inconclusive``
    anything else: the owner could not read it, the owner's two responses
    differ (a volatile page cannot be compared), a response was only partly
    similar, a request got no usable answer (transport error, 429, 5xx), the
    request budget ran out, or nobody is known to own the URL and it is not
    public. Never reported as a pass or a fail.

An owner may be *inferred* rather than declared: :func:`infer_owners` turns the
URLs each identity reached while signed in into ``{url: identity}``, giving an
object URL to the one identity that reached it. That is a hint, not proof: a
public page only one account happened to crawl looks the same. For a URL in
``require_marker_for``, ``broken_access`` therefore also needs one of the
owner's markers (``markers`` in ``identities.json``) in the owner's own response
and in the response of the one who should not have it; otherwise the verdict is
``inconclusive``.

Standard library only; no model or agent library is imported here.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.capture.identities import (
    Identity,
    IdentityError,
    LoginError,
    SessionManager,
    UnknownIdentity,
)
from buggy.capture.probes.base import ok, similarity, text
from buggy.capture.store import Capture

PROBE = "authz_matrix"
SOURCE = f"probe:{PROBE}"
# The matrix column for requests sent with no identity.
ANONYMOUS = "anonymous"
METHODS = ("GET", "HEAD")
# At or above this similarity to the owner's response, a response is the owner's content.
SAME = 0.95
# Below this, a response is clearly something else.
DIFFERENT = 0.5
DENIED = frozenset({401, 403, 404})
VERDICTS = ("broken_access", "enforced", "public", "inconclusive")

VULN_CLASS = "access_control"
REMEDIATION = (
    "Authorise every object access against the authenticated caller server-side; do not rely "
    "on identifiers being unguessable, and require authentication before any lookup."
)

# Refusals that are about who is asking, not about the URL.
_IDENTITY_REFUSALS = frozenset({"UNKNOWN_IDENTITY", "BAD_IDENTITIES", "LOGIN_FAILED"})
_ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
# Copied from buggy.pipeline.tools.params (_IDENTIFIER, _COLLECTION, _ID_NAME and
# _STATIC): an object reference is an identifier after a named collection
# (/orders/123), or an id-like query parameter with an identifier value.
_IDENTIFIER = re.compile(
    r"^(?:[0-9]+|[0-9a-f]{24}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_COLLECTION = re.compile(r"^[a-z][\w-]*$", re.IGNORECASE)
_ID_NAME = re.compile(r"^(?:(?i:id|.*[_-]id|uuid)|.*Id)$")
_STATIC = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|bmp|avif|tiff?|woff2?|ttf|eot|otf)$",
    re.IGNORECASE,
)
#: At most this many inferred owners are returned by :func:`infer_owners`.
MAX_INFERRED = 60
# How many shared (nobody's) URLs are listed back; the count is always given.
MAX_SHARED = 200


class _BudgetSpent(Exception):
    """``max_requests`` is reached; nothing more is sent."""


class _Skip(Exception):
    """This URL cannot be tested. ``reason`` says why; ``capture_id`` is the proof, if any."""

    def __init__(self, reason: str, capture_id: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.capture_id = capture_id


@dataclass(frozen=True, slots=True)
class _Target:
    key: str  # the matrix key: the URL, or "HEAD <url>"
    method: str
    url: str


@dataclass
class _Run:
    """The state of one matrix run: the request budget and which identities still work."""

    gateway: CaptureGateway
    sessions: SessionManager
    engagement: str
    max_requests: int
    requests: int = 0
    truncated: bool = False
    opened: set[str] = field(default_factory=set)
    unavailable: dict[str, str] = field(default_factory=dict)

    def _room(self) -> None:
        if self.requests >= self.max_requests:
            self.truncated = True
            raise _BudgetSpent

    def _open(self, who: str) -> bool:
        """Make sure ``who`` has a session. A failed login is tried once, not once per URL."""
        if who in self.opened:
            return True
        self._room()
        try:
            _session, fresh = self.sessions.session_for(self.engagement, who)
        except UnknownIdentity:
            self.unavailable[who] = "not declared for this engagement"
            return False
        except IdentityError as exc:
            self.unavailable[who] = f"the identities file is invalid ({exc})"
            return False
        except LoginError as exc:
            self.requests += 1  # the login was sent and did not yield a session
            self.unavailable[who] = str(exc)
            return False
        except GatewayRefusal as refusal:
            self.unavailable[who] = f"login refused ({refusal.code}: {refusal.detail})"
            return False
        if fresh:
            self.requests += 1  # the login request
        self.opened.add(who)
        return True

    def ask(self, target: _Target, who: str, note: str) -> Capture | None:
        """One request as ``who`` (``ANONYMOUS`` = no identity).

        Returns ``None`` when the identity cannot be used. Raises ``_BudgetSpent``
        or ``_Skip`` (the gateway refused the URL itself).
        """
        identity = "" if who == ANONYMOUS else who
        if identity and (who in self.unavailable or not self._open(who)):
            return None
        self._room()
        try:
            capture = self.gateway.send(
                self.engagement,
                target.method,
                target.url,
                identity=identity,
                note=f"authz matrix: {note}",
                probe=PROBE,
            )
        except GatewayRefusal as refusal:
            if identity and refusal.code in _IDENTITY_REFUSALS:
                self.opened.discard(who)
                self.unavailable[who] = f"{refusal.code}: {refusal.detail}"
                return None
            raise _Skip(f"{refusal.code}: {refusal.detail}") from refusal
        self.requests += 1
        return capture


# ── inputs ──────────────────────────────────────────────────────────


def _targets(urls: Iterable[Any]) -> tuple[list[_Target], list[dict[str, Any]]]:
    """The GET/HEAD targets to run, and the entries that are skipped unsent.

    An entry is a URL (``GET``), ``"<METHOD> <url>"`` or ``{"url": ..., "method": ...}``.
    """
    if isinstance(urls, (str, bytes, Mapping)):
        raise TypeError("urls must be a list of URLs")
    targets: list[_Target] = []
    skipped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in urls:
        method, url = "GET", ""
        if isinstance(entry, Mapping):
            method, url = str(entry.get("method") or "GET"), str(entry.get("url") or "")
        elif isinstance(entry, str):
            head, _, rest = entry.strip().partition(" ")
            # "POST https://..." names a method; anything else is a URL as written.
            method, url = (
                (head, rest.strip()) if rest and head.isalpha() else ("GET", entry.strip())
            )
        method = method.upper()
        if method not in METHODS:
            skipped.append(
                {
                    "url": url,
                    "method": method,
                    "reason": f"{method or 'this entry'} is not GET or HEAD: the matrix never "
                    "sends a request that can change state",
                }
            )
            continue
        key = url if method == "GET" else f"{method} {url}"
        if not url or key in seen:
            if not url:
                skipped.append({"url": url, "method": method, "reason": "no URL given"})
            continue
        seen.add(key)
        targets.append(_Target(key, method, url))
    return targets, skipped


def _identities(
    gateway: CaptureGateway, engagement: str, identities: Iterable[Any]
) -> tuple[dict[str, Identity], dict[str, str]]:
    """The declared identities to use, in the caller's order, and why the others are not."""
    if isinstance(identities, (str, bytes)):
        raise TypeError("identities must be a list of identity names")
    names: list[str] = []
    for entry in identities:
        if isinstance(entry, Mapping):
            name = entry.get("name")
        else:
            name = entry if isinstance(entry, str) else getattr(entry, "name", None)
        if not isinstance(name, str) or not name:
            raise TypeError("each identity must be a name or carry one")
        if name not in names:
            names.append(name)
    unavailable: dict[str, str] = {}
    try:
        declared = gateway.identities.load(engagement) if names else {}
    except IdentityError as exc:  # names the field, never a value from the file
        return {}, {name: f"the identities file is invalid ({exc})" for name in names}
    usable: dict[str, Identity] = {}
    for name in names:
        if name not in declared:
            unavailable[name] = "not declared for this engagement"
        elif name == ANONYMOUS:
            unavailable[name] = f"{ANONYMOUS!r} is the name of the column without credentials"
        else:
            usable[name] = declared[name]
    return usable, unavailable


def _markers(markers: Any) -> dict[str, tuple[str, ...]]:
    """``{identity name or URL: strings unique to that identity's / that URL's data}``."""
    if markers is None:
        return {}
    if not isinstance(markers, Mapping):
        raise TypeError("markers must map an identity name or a URL to a list of strings")
    out: dict[str, tuple[str, ...]] = {}
    for key, values in markers.items():
        if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
            raise TypeError("markers must map an identity name or a URL to a list of strings")
        out[str(key)] = tuple(dict.fromkeys(str(v) for v in values if str(v)))
    return out


def _owner(
    target: _Target, owners: Mapping[str, str] | None, identities: Mapping[str, Identity]
) -> tuple[str, str]:
    """``(owner, problem)`` for a URL: at most one of the two is set.

    An entry in ``owners`` wins. Otherwise the identities' ``owner_of`` patterns
    decide: an exact URL beats a prefix (a pattern ending in ``*``), and a longer
    prefix beats a shorter one.
    """
    declared = (owners or {}).get(target.url) or (owners or {}).get(target.key)
    if declared:
        if declared not in identities:
            return "", f"its owner {declared!r} is not one of the usable identities of this run"
        return str(declared), ""
    best: tuple[int, int] | None = None
    holders: list[str] = []
    for name, identity in identities.items():
        for pattern in identity.owner_of:
            if pattern == target.url:
                rank = (1, len(pattern))
            elif pattern.endswith("*") and target.url.startswith(pattern[:-1]):
                rank = (0, len(pattern))
            else:
                continue
            if best is None or rank > best:
                best, holders = rank, [name]
            elif rank == best and name not in holders:
                holders.append(name)
    if len(holders) > 1:
        return "", f"owner_of names more than one owner for it ({', '.join(holders)})"
    return (holders[0] if holders else ""), ""


# ── judging one URL ─────────────────────────────────────────────────


def _answered(capture: Capture) -> bool:
    """Whether the response says anything about access (not an outage or a throttle)."""
    status = capture.status
    return not capture.error and status is not None and status != 429 and status < 500


def _hits(capture: Capture, strings: tuple[str, ...]) -> list[str]:
    if not strings:
        return []
    body = text(capture)
    return [s for s in strings if s in body]


def _describe(who: str, capture: Capture) -> str:
    if capture.error or capture.status is None:
        return f"{who} got no response"
    return f"{who} got HTTP {capture.status}"


def _judge_owned(
    owner: str,
    captures: dict[str, Capture],
    repeat: Capture | None,
    strings: tuple[str, ...],
    complete: bool,
    owner_markers: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """``owner_markers`` is set when the owner was inferred: then only one of those
    strings, in the owner's response and in the other one, shows an exposure."""
    verdict: dict[str, Any] = {
        "verdict": "inconclusive",
        "owner": owner,
        "reason": "",
        "exposed_to": [],
        "owner_stability": None,
    }
    mine = captures.get(owner)
    if mine is None:
        verdict["reason"] = f"the owner {owner!r} could not be asked"
        return verdict
    if not ok(mine):
        verdict["reason"] = f"the owner could not read it ({_describe(owner, mine)})"
        return verdict
    if repeat is None:
        verdict["reason"] = "the owner's second request was not sent (max_requests reached)"
        return verdict
    stability = similarity(mine, repeat) if ok(repeat) and repeat.status == mine.status else 0.0
    verdict["owner_stability"] = stability
    if stability < SAME:
        verdict["reason"] = (
            "the page is unstable: the owner asked twice and got different answers "
            f"(similarity {stability}), so no other response can be compared with it"
        )
        return verdict

    inferred = owner_markers is not None
    needed: tuple[str, ...] = ()
    if owner_markers is not None:
        needed = tuple(_hits(mine, owner_markers))
        if not needed:
            verdict["reason"] = (
                f"the owner {owner!r} is inferred (only that account reached the URL), and an "
                "inferred owner needs a marker: "
                + (
                    "the owner's own response contains none of the owner's markers"
                    if owner_markers
                    else f"{owner!r} declares no markers"
                )
                + " (the markers field of identities.json), so the page may simply be public"
            )
            return verdict

    comparable = mine.response_bytes > 0
    unclear: list[str] = []
    compared = 0
    for who, capture in captures.items():
        if who == owner:
            continue
        compared += 1
        if not _answered(capture):
            unclear.append(f"{_describe(who, capture)}, which says nothing about access")
            continue
        score = similarity(mine, capture)
        hits = _hits(capture, strings)
        proof = _hits(capture, needed) if inferred else hits
        if ok(capture) and (proof or (not inferred and comparable and score >= SAME)):
            verdict["exposed_to"].append(who)
        elif not hits and (capture.status in DENIED or score < DIFFERENT):
            continue
        elif hits:
            unclear.append(f"{_describe(who, capture)} with an owner marker in the body")
        elif not comparable:
            unclear.append(f"{_describe(who, capture)} and the owner's response has no body")
        elif inferred and score >= SAME:
            unclear.append(
                f"{_describe(who, capture)}, like the owner's ({score}) but without the "
                "owner's marker that the owner's response has"
            )
        else:
            unclear.append(f"{_describe(who, capture)}, partly like the owner's ({score})")
    if verdict["exposed_to"]:
        verdict["verdict"] = "broken_access"
        verdict["reason"] = (
            f"{', '.join(verdict['exposed_to'])} received the object that belongs to {owner}"
        )
    elif unclear:
        verdict["reason"] = "; ".join(unclear)
    elif not complete:
        verdict["reason"] = "max_requests was reached before every identity was asked"
    elif not compared:
        verdict["reason"] = "there is nobody else to compare the owner with"
    else:
        verdict["verdict"] = "enforced"
        verdict["reason"] = "nobody but the owner received the object"
    return verdict


def _judge_unowned(
    captures: dict[str, Capture], strings: tuple[str, ...], complete: bool
) -> dict[str, Any]:
    """No owner is known: the only question is whether everyone gets the same thing."""
    verdict: dict[str, Any] = {
        "verdict": "inconclusive",
        "owner": "",
        "reason": "",
        "exposed_to": [],
        "owner_stability": None,
        "same_for_all_identities": False,
    }
    if not complete:
        verdict["reason"] = "max_requests was reached before every identity was asked"
        return verdict
    members = [c for who, c in captures.items() if who != ANONYMOUS]
    anonymous = captures.get(ANONYMOUS)

    def alike(group: list[Capture]) -> bool:
        if not all(ok(c) and c.response_bytes > 0 for c in group):
            return False
        return all(similarity(a, b) >= SAME for i, a in enumerate(group) for b in group[i + 1 :])

    shared = len(members) > 1 and alike(members)
    verdict["same_for_all_identities"] = shared
    if members and anonymous is not None and alike([*members, anonymous]):
        if strings:
            verdict["reason"] = (
                "everyone, with or without credentials, gets the same content, but markers are "
                "defined for this URL and nobody is known to own it"
            )
        else:
            verdict["verdict"] = "public"
            verdict["reason"] = "the same content is served with and without credentials"
    elif shared:
        verdict["reason"] = (
            "every identity gets the same content and a request without credentials does not; "
            "nobody is known to own it, so this may be shared or exposed"
        )
    else:
        verdict["reason"] = "nobody is known to own this URL, so there is nothing to compare with"
    return verdict


# ── owners inferred from what each identity reached ─────────────────


def _object_template(url: str) -> str:
    """The URL's path template if it names an object (``""`` otherwise).

    Identifier segments after a named collection become ``{id}``; id-like query
    parameters with an identifier value are kept by name as ``name={id}``.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    if _STATIC.search(parts.path):
        return ""
    segments = parts.path.split("/")
    found = False
    out: list[str] = []
    for index, segment in enumerate(segments):
        previous = segments[index - 1] if index else ""
        if index > 1 and _COLLECTION.match(previous) and _IDENTIFIER.match(segment):
            out.append("{id}")
            found = True
        else:
            out.append(segment)
    query = sorted(
        {
            name
            for name, value in parse_qsl(parts.query, keep_blank_values=True)
            if _ID_NAME.match(name) and _IDENTIFIER.match(value)
        }
    )
    if not found and not query:
        return ""
    template = f"{parts.scheme.lower()}://{parts.netloc.lower()}{'/'.join(out)}"
    return template + ("?" + "&".join(f"{name}={{id}}" for name in query) if query else "")


def _reached_urls(entries: Any) -> list[str]:
    """URLs out of a crawler list: strings, or pages ``{"url", "status"}`` (2xx only)."""
    if isinstance(entries, str):
        entries = [entries]
    if isinstance(entries, (bytes, Mapping)) or not isinstance(entries, Iterable):
        return []
    urls: list[str] = []
    for entry in entries:
        if isinstance(entry, Mapping):
            status = entry.get("status")
            if status is not None and not (isinstance(status, int) and 200 <= status < 300):
                continue
            entry = entry.get("url")
        if isinstance(entry, str) and entry.strip():
            urls.append(entry.strip().split("#", 1)[0])
    return urls


def infer_owners(
    reached: Mapping[str, Iterable[str]],
    markers_by_identity: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Which object URL belongs to which identity, judged from what each reached.

    ``reached`` maps an identity name to the URLs it reached while signed in.
    An object URL (an identifier after a named collection, or an id-like query
    parameter) reached by exactly one identity is given to it; one reached by
    two or more is ``shared``. Static assets and other URLs are ignored.

    This is a hint, not proof: pass the URLs of ``owners`` to :func:`run_matrix`
    as ``require_marker_for``. ``markers_by_identity`` only orders the choice:
    an identity with markers is picked first, since only its objects can be
    reported. At most ``MAX_INFERRED`` owners are returned, chosen so that every
    identity and every path template has one URL before any template gets a
    second; the order is deterministic.

    Returns ``{"owners": {url: identity}, "shared": [url], "per_identity":
    {name: objects only it reached}, "considered": number of object URLs}``.
    """
    holders: dict[str, set[str]] = {}
    names: list[str] = []
    if isinstance(reached, Mapping):
        for name, urls in reached.items():
            if not isinstance(name, str) or not name:
                continue
            names.append(name)
            for url in _reached_urls(urls):
                if _object_template(url):
                    holders.setdefault(url, set()).add(name)
    with_markers = {
        str(name)
        for name, values in (markers_by_identity or {}).items()
        if not isinstance(values, (str, bytes))
        and isinstance(values, Iterable)
        and any(str(v) for v in values)
    }
    unique = {url: next(iter(who)) for url, who in holders.items() if len(who) == 1}
    shared = sorted(url for url, who in holders.items() if len(who) > 1)
    per_identity = dict.fromkeys(sorted(set(names)), 0)
    for name in unique.values():
        per_identity[name] += 1

    # (template, url, identity), sorted; identities with markers first where it matters.
    pool = sorted((_object_template(url), url, name) for url, name in unique.items())
    chosen: dict[str, str] = {}
    used_templates: dict[str, int] = {}

    def take(item: tuple[str, str, str]) -> None:
        template, url, name = item
        chosen[url] = name
        used_templates[template] = used_templates.get(template, 0) + 1

    def rank(name: str) -> tuple[int, str]:
        return (0 if name in with_markers else 1, name)

    # 1. One URL per identity, in a template not used yet where possible.
    for name in sorted({n for _t, _u, n in pool}, key=rank):
        if len(chosen) >= MAX_INFERRED:
            break
        mine = [item for item in pool if item[2] == name]
        fresh = [item for item in mine if item[0] not in used_templates]
        take((fresh or mine)[0])
    # 2. Then rounds over the templates: one more URL per template per round,
    # preferring the identity with the fewest URLs chosen so far.
    by_template: dict[str, list[tuple[str, str, str]]] = {}
    for item in pool:
        if item[1] not in chosen:
            by_template.setdefault(item[0], []).append(item)
    while len(chosen) < MAX_INFERRED and any(by_template.values()):
        for template in sorted(by_template, key=lambda t: (used_templates.get(t, 0), t)):
            items = by_template[template]
            if not items or len(chosen) >= MAX_INFERRED:
                continue
            if used_templates.get(template, 0) > min(
                used_templates.get(t, 0) for t, rest in by_template.items() if rest
            ):
                continue
            here = dict.fromkeys((n for _t, _u, n in items), 0)
            overall = dict(here)
            for url, name in chosen.items():
                if name in here:
                    overall[name] += 1
                    if _object_template(url) == template:
                        here[name] += 1
            best = min(
                items, key=lambda item: (here[item[2]], overall[item[2]], rank(item[2]), item[1])
            )
            items.remove(best)
            take(best)
    return {
        "owners": dict(sorted(chosen.items())),
        "shared": shared[:MAX_SHARED],
        "shared_total": len(shared),
        "per_identity": per_identity,
        "considered": len(holders),
    }


# ── candidates ──────────────────────────────────────────────────────


def normalized_endpoint(url: str) -> str:
    """The endpoint a finding id is computed over: lower-case scheme and host, no
    query, numeric and UUID path segments replaced with ``{id}``."""
    parts = urlsplit(url)
    path = "/".join("{id}" if _ID_SEGMENT.match(seg) else seg for seg in parts.path.split("/"))
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"


def finding_id(engagement: str, vuln_class: str, endpoint: str, parameter: str = "") -> str:
    material = f"{engagement}|{vuln_class}|{normalized_endpoint(endpoint)}|{parameter}"
    return "F-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def _assertion(
    capture: Capture, identity: str, contains: list[str], same_as: str = ""
) -> dict[str, Any]:
    return {
        "capture_id": capture.id,
        "identity": identity,
        "expect": {
            "status": capture.status,
            "body_contains": contains,
            "body_not_contains": [],
            "differs_from": "",
            "same_as": same_as,
        },
    }


def _candidate(
    engagement: str,
    target: _Target,
    verdict: dict[str, Any],
    captures: dict[str, Capture],
    strings: tuple[str, ...],
) -> dict[str, Any]:
    owner = verdict["owner"]
    mine = captures[owner]
    exposed: list[str] = verdict["exposed_to"]
    without_credentials = ANONYMOUS in exposed
    assertions = [_assertion(mine, owner, _hits(mine, strings))]
    seen: list[str] = []
    for who in exposed:
        capture = captures[who]
        score = similarity(mine, capture)
        alike = mine.response_bytes > 0 and score >= SAME
        hits = _hits(capture, strings)
        assertions.append(
            _assertion(
                capture, "" if who == ANONYMOUS else who, hits, same_as=mine.id if alike else ""
            )
        )
        name = "a request without credentials" if who == ANONYMOUS else f"identity {who!r}"
        proof = f"similarity {score} to the owner's response"
        if hits:
            proof += f", {len(hits)} owner marker(s) in the body"
        seen.append(f"{name} (HTTP {capture.status}, {proof}, {capture.id})")
    path = urlsplit(normalized_endpoint(target.url)).path or "/"
    now = time.time()
    return {
        "id": finding_id(engagement, VULN_CLASS, target.url),
        "engagement": engagement,
        "title": f"Broken access control on {target.method} {path}",
        "class": VULN_CLASS,
        "cwe": "CWE-862" if without_credentials else "CWE-639",
        "severity": "high",
        "endpoint": target.url,
        "method": target.method,
        "parameter": "",
        "source": SOURCE,
        "description": (
            f"{target.method} {target.url} belongs to identity {owner!r} ({mine.id}, "
            f"HTTP {mine.status}). The same object was returned to " + "; ".join(seen) + "."
        ),
        "remediation": REMEDIATION,
        "assertions": assertions,
        "status": "candidate",
        "verification": {"at": 0.0, "replay_capture_ids": [], "reasons": []},
        "grade": None,
        "grade_reasons": [],
        "created_at": now,
        "updated_at": now,
    }


# ── the run ─────────────────────────────────────────────────────────


def _cell(capture: Capture, mine: Capture | None, strings: tuple[str, ...]) -> dict[str, Any]:
    score: float | None = None
    if mine is not None and mine.status is not None and capture.status is not None:
        score = 1.0 if capture is mine else similarity(mine, capture)
    cell: dict[str, Any] = {
        "status": capture.status,
        "bytes": capture.response_bytes,
        "sha256": capture.response_sha256,
        "capture_id": capture.id,
        "similarity_to_owner": score,
    }
    if strings:
        cell["markers_found"] = _hits(capture, strings)
    if capture.error:
        cell["error"] = capture.error
    return cell


def run_matrix(
    gateway: CaptureGateway,
    sessions: SessionManager | None,
    engagement: str,
    urls: Iterable[Any],
    *,
    identities: Iterable[Any],
    owners: Mapping[str, str] | None = None,
    include_anonymous: bool = True,
    markers: Mapping[str, Iterable[str]] | None = None,
    max_requests: int = 300,
    require_marker_for: Iterable[str] = (),
) -> dict[str, Any]:
    """Ask for every URL as every identity and report who received whose data.

    ``sessions`` is the gateway's session manager (``None`` = ``gateway.sessions``);
    it is used to open each identity's session once, so that a login that fails is
    not retried for every URL. ``identities`` are names of declared identities.
    ``owners`` maps a URL to the name of the identity it belongs to; a URL not
    listed there is matched against the identities' ``owner_of`` patterns.
    ``markers`` maps an identity name (strings unique to that identity's data) or
    a URL (strings unique to that URL's private content) to a list of strings.
    The identities' own declared ``markers`` are used too; an entry of ``markers``
    for the same identity replaces them.
    ``require_marker_for`` lists URLs (or ``"HEAD <url>"`` keys) whose owner was
    inferred (see :func:`infer_owners`): for those, ``broken_access`` needs one of
    the owner's markers in the owner's response and in the other response, and the
    verdict is ``inconclusive`` when the owner has none or its response lacks them.

    Each URL costs one request per identity, one more for its owner (asked twice
    to see that the page is stable) and one without credentials. A login made to
    open a session counts as a request; a renewal the gateway performs itself after
    a 401 is not seen here. At ``max_requests`` nothing more is sent and
    ``truncated`` is set.
    """
    if sessions is None:
        sessions = gateway.sessions
    targets, skipped = _targets(urls)
    usable, unavailable = _identities(gateway, engagement, identities)
    if isinstance(require_marker_for, (str, bytes)):
        raise TypeError("require_marker_for must be a list of URLs")
    strings_for = {name: ident.markers for name, ident in usable.items() if ident.markers}
    strings_for.update(_markers(markers))
    inferred = {str(url).strip() for url in require_marker_for if str(url).strip()}
    run = _Run(gateway, sessions, engagement, max(0, int(max_requests)), unavailable=unavailable)

    matrix: dict[str, dict[str, dict[str, Any]]] = {}
    verdicts: dict[str, dict[str, Any]] = {}
    candidates: list[dict[str, Any]] = []
    public: list[str] = []

    for target in targets:
        if run.truncated or run.requests >= run.max_requests:
            run.truncated = True
            skipped.append(
                {
                    "url": target.url,
                    "method": target.method,
                    "reason": "not requested: max_requests was reached",
                }
            )
            continue
        owner, problem = _owner(target, owners, usable)
        if problem:
            skipped.append({"url": target.url, "method": target.method, "reason": problem})
            continue
        strings = tuple(
            dict.fromkeys(
                [
                    *strings_for.get(owner, ()),
                    *strings_for.get(target.url, ()),
                    *strings_for.get(target.key, ()),
                ]
            )
        )
        order = [owner] if owner else []
        order += [name for name in usable if name != owner]
        if include_anonymous:
            order.append(ANONYMOUS)

        captures: dict[str, Capture] = {}
        repeat: Capture | None = None
        complete = True
        try:
            for who in order:
                role = "owner" if who == owner else "not the owner" if owner else "no known owner"
                label = "no credentials" if who == ANONYMOUS else f"as {who} ({role})"
                capture = run.ask(target, who, label)
                if capture is None:
                    continue
                if capture.status == 405 and not captures:
                    raise _Skip(
                        f"the server does not allow {target.method} here (HTTP 405), and the "
                        "matrix sends nothing else",
                        capture.id,
                    )
                captures[who] = capture
                if who == owner and ok(capture):
                    repeat = run.ask(target, who, f"as {who} (owner, again: is the page stable?)")
        except _BudgetSpent:
            complete = False
        except _Skip as skip:
            entry = {"url": target.url, "method": target.method, "reason": skip.reason}
            if skip.capture_id:
                entry["capture_id"] = skip.capture_id
            skipped.append(entry)
            continue
        if not captures:
            skipped.append(
                {
                    "url": target.url,
                    "method": target.method,
                    "reason": "not requested: max_requests was reached"
                    if not complete
                    else "not requested: no identity could be used",
                }
            )
            continue

        mine = captures.get(owner) if owner else None
        row = {who: _cell(capture, mine, strings) for who, capture in captures.items()}
        if owner and repeat is not None:
            row[owner]["repeat_capture_id"] = repeat.id
        matrix[target.key] = row
        if owner:
            needs_marker = target.url in inferred or target.key in inferred
            verdict = _judge_owned(
                owner,
                captures,
                repeat,
                strings,
                complete,
                strings_for.get(owner, ()) if needs_marker else None,
            )
        else:
            verdict = _judge_unowned(captures, strings, complete)
        verdicts[target.key] = verdict
        if verdict["verdict"] == "broken_access":
            candidates.append(_candidate(engagement, target, verdict, captures, strings))
        elif verdict["verdict"] == "public":
            public.append(target.key)

    return {
        "engagement": engagement,
        "identities": [name for name in usable if name not in run.unavailable],
        "matrix": matrix,
        "verdicts": verdicts,
        "candidates": candidates,
        "public": public,
        "skipped": skipped,
        "skipped_identities": dict(run.unavailable),
        "requests": run.requests,
        "truncated": run.truncated,
    }


__all__ = [
    "ANONYMOUS",
    "DIFFERENT",
    "METHODS",
    "PROBE",
    "SAME",
    "VERDICTS",
    "MAX_INFERRED",
    "finding_id",
    "infer_owners",
    "normalized_endpoint",
    "run_matrix",
]
