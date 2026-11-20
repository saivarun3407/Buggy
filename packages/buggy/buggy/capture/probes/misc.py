"""Open redirect, path traversal and CORS probes.

Three small read-only probes for classes that one or two responses decide.
Every payload is a constant in this module; nothing is written, deleted or
followed, and the only files the traversal probe asks for are two
world-readable markers (``etc/passwd`` and ``windows/win.ini``).

``open_redirect`` (never more than ``REDIRECT_MAX_REQUESTS``):

1. the original value (baseline, and the control: it must not already send
   the user to a site other than the target and the one the value names);
2. ``https://<random>.example/`` in the parameter. The host is fresh for each
   run and lives under a reserved TLD that nobody resolves; the gateway never
   follows a redirect. A 3xx whose ``Location`` points at that host, or a 2xx
   whose body has a meta refresh or a ``location`` assignment to it, proves
   the parameter chooses the destination;
3. only when the plain form is refused: at most four fixed bypass forms.

``path_traversal`` (never more than ``TRAVERSAL_MAX_REQUESTS``):

1. the original value (baseline, and the control: a marker it already
   contains does not count);
2. ``../`` chains of depth 2 to 6, plain and URL-encoded, with and without a
   ``%00`` + original extension suffix, towards the two marker files. The
   first response that carries a marker absent from the baseline is the proof.

``cors`` (exactly ``CORS_MAX_REQUESTS``): one GET without ``Origin`` (the
baseline), one with a fresh ``https://<random>.example`` origin and one with
``Origin: null``. Vulnerable only when the origin is reflected (or ``null`` is
allowed) together with ``Access-Control-Allow-Credentials: true``.

A positive verdict always rests on a control; anything the probe could not
attribute is reported as ``vulnerable: null``.
"""

from __future__ import annotations

import html
import posixpath
import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from buggy.capture.gateway import GatewayRefusal
from buggy.capture.probes.base import (
    Context,
    ProbeInputError,
    ProbeResult,
    headers_of,
    require,
    text,
)
from buggy.capture.probes.injection import (
    _as_text,
    _BudgetExceeded,
    _failed,
    _outcome,
    _Run,
    _Target,
)
from buggy.capture.probes.xss import _header, _PathTarget
from buggy.capture.store import Capture

LOCATIONS = ("query", "json", "form", "path")
RANDOM_TLD = "example"  # reserved (RFC 2606): never resolves, never anybody's site

# ── open redirect ────────────────────────────────────────────────────

REDIRECT_PROBE = "open_redirect"
REDIRECT_CLASS = "open_redirect"
REDIRECT_CWE = "CWE-601"
REDIRECT_MAX_REQUESTS = 6  # baseline + plain + 4 bypass forms
REDIRECT_REMEDIATION = (
    "Do not redirect to a URL taken from the request. Redirect to a fixed path or to an entry "
    "chosen by key from a server-side list; if absolute URLs must be accepted, parse the URL "
    "and compare its scheme and exact host against an allow-list (never a prefix, substring or "
    "regular-expression match on the raw string), and reject userinfo, backslashes and "
    "scheme-relative (//host) forms."
)
# ``{host}`` is the random host of the run, ``{allowed}`` the allow-listed URL
# and ``{allowed_host}`` its host. Sent in this order, only after the plain
# form was refused.
REDIRECT_PLAIN = "https://{host}/"
REDIRECT_BYPASSES: tuple[tuple[str, str], ...] = (
    ("scheme_relative", "//{host}/"),
    ("missing_slashes", "https:{host}/"),
    ("userinfo", "https://{allowed_host}@{host}/"),
    ("fragment", "https://{host}/#{allowed}"),
)
REDIRECT_CONTROL = (
    "baseline: the original value must not already send the user off-site (to a host other "
    "than the target and the one the value itself names); the proof host is random and fresh "
    "for each run, so it cannot be in the page by coincidence"
)

_META_REFRESH = re.compile(r"<meta\b[^>]*http-equiv\s*=\s*[\"']?refresh\b[^>]*>", re.IGNORECASE)
_META_CONTENT = re.compile(r"\bcontent\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.IGNORECASE)
_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\"]+)", re.IGNORECASE)
_JS_ASSIGN = re.compile(
    r"\b(?:window\.|document\.|self\.|top\.)?location(?:\.href)?\s*=\s*([\"'`])(.*?)\1",
    re.IGNORECASE,
)
_JS_CALL = re.compile(r"\blocation\.(?:replace|assign)\(\s*([\"'`])(.*?)\1", re.IGNORECASE)
_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$", re.DOTALL)
_STRIPPED = re.compile(r"[\t\n\r]")

# ── path traversal ───────────────────────────────────────────────────

TRAVERSAL_PROBE = "path_traversal"
TRAVERSAL_CLASS = "file_handling"
TRAVERSAL_CWE = "CWE-22"
TRAVERSAL_MAX_REQUESTS = 10  # baseline + the nine payloads below
TRAVERSAL_REMEDIATION = (
    "Do not build a file path from request data. Map the value to a file through a server-side "
    "allow-list or an opaque id; if a name must be accepted, reject separators and '..', "
    "decode exactly once, resolve the final path (realpath) and check that it stays inside the "
    "intended directory before opening it. Reject NUL bytes outright."
)
# The two files the probe may ask for, and the marker that proves one was read.
MARKER_FILES: dict[str, tuple[str, re.Pattern[str]]] = {
    "passwd": ("etc/passwd", re.compile(r"root:.*:0:0:")),
    "win_ini": ("windows/win.ini", re.compile(re.escape("[fonts]"))),
}
# ``(file, depth, encoding, null byte + original extension)``, in the order sent.
# "plain" climbs with ``../``; "encoded" with ``%2e%2e%2f`` (on the wire for a
# path segment; in the decoded value elsewhere, which catches a second decode).
TRAVERSAL_PAYLOADS: tuple[tuple[str, int, str, bool], ...] = (
    ("passwd", 2, "plain", False),
    ("passwd", 4, "plain", False),
    ("passwd", 6, "plain", False),
    ("passwd", 6, "encoded", False),
    ("passwd", 6, "plain", True),
    ("passwd", 6, "encoded", True),
    ("win_ini", 6, "plain", False),
    ("win_ini", 6, "encoded", False),
    ("win_ini", 6, "plain", True),
)
TRAVERSAL_CONTROL = (
    "baseline: the original value; a marker that is already in the baseline response is not counted"
)

# ── CORS ─────────────────────────────────────────────────────────────

CORS_PROBE = "cors"
CORS_CLASS = "misconfiguration"
CORS_CWE = "CWE-942"
CORS_MAX_REQUESTS = 3
CORS_REMEDIATION = (
    "Do not echo the Origin request header into Access-Control-Allow-Origin. Compare the "
    "origin with an exact allow-list of trusted origins, never allow the 'null' origin, send "
    "Access-Control-Allow-Credentials: true only for those origins, and add Vary: Origin."
)
CORS_CONTROL = (
    "baseline: the same GET without an Origin header; the reflected origin is random and fresh "
    "for each run, so it cannot be a configured allow-list entry"
)


# ── shared request side ──────────────────────────────────────────────


@dataclass(frozen=True)
class _WirePathTarget(_Target):
    """A path segment whose value is written as it goes on the wire (``%`` is kept)."""

    def request(self, value: Any) -> tuple[str, str | None]:
        placeholder = "{" + self.parameter + "}"
        return self.url.replace(placeholder, quote(str(value), safe="/%")), self.raw_body


def _target(params: dict[str, Any], path_class: type[_Target]) -> _Target:
    """C1's target for query / json / form, or a path segment with a ``{parameter}`` placeholder."""
    require(params, "url", "parameter")
    location = str(params.get("location") or "query").lower()
    if location not in LOCATIONS:
        raise ProbeInputError(f"location must be one of {', '.join(LOCATIONS)}")
    if location != "path":
        return _Target.from_params(params)
    url, parameter = str(params["url"]), str(params["parameter"])
    if "{" + parameter + "}" not in url.partition("?")[0]:
        raise ProbeInputError(
            f"location is path: the url path must contain the placeholder {{{parameter}}}"
        )
    value = params.get("value")
    if value in (None, "") or isinstance(value, (dict, list)):
        raise ProbeInputError(f"value is required: give a valid baseline value for {parameter!r}")
    body = params.get("body")
    return path_class(
        str(params.get("method") or "GET").upper(),
        url,
        "path",
        parameter,
        headers_of(params.get("headers")),
        None,
        [],
        None if body in (None, "") else _as_text(body),
        str(value),
    )


@dataclass
class _MiscRun(_Run):
    """C1's request bookkeeping with a per-probe identity, bound and result layout."""

    probe: str = ""
    vuln_class: str = ""
    cwe: str = ""
    remediation: str = ""
    control: str = ""
    bound: int = 0

    @property
    def left(self) -> int:
        return self.bound - len(self.evidence)

    def send_headers(self, role: str, headers: dict[str, str], note: str) -> Capture:
        """A GET of the target URL with these headers (for probes without a parameter)."""
        if self.left <= 0:
            raise _BudgetExceeded(role)
        self.payloads[role] = headers.get("Origin")
        capture = self.ctx.send(self.target.method, self.target.url, headers=headers, note=note)
        self.evidence.append(capture.id)
        self.captures[role] = capture.id
        return capture

    def result(self, vulnerable: bool | None, summary: str) -> ProbeResult:
        details: dict[str, Any] = {
            "technique": self.technique,
            "method": self.target.method,
            "location": self.target.location,
            "parameter": self.target.parameter,
            "requests_sent": len(self.evidence),
            "max_requests": self.bound,
            "captures": dict(self.captures),
            "payloads": dict(self.payloads),
            "control": self.control,
            **self.info,
        }
        if self.unresolved:
            details["unresolved"] = list(self.unresolved)
        return ProbeResult(
            self.probe,
            self.vuln_class,
            self.cwe,
            vulnerable,
            summary,
            list(self.evidence),
            details,
            self.remediation,
        )


def _guarded(run: _MiscRun, examine: Any) -> ProbeResult:
    try:
        return examine(run)
    except GatewayRefusal as refusal:
        run.info["refusal"] = refusal.to_dict()
        return run.result(
            None,
            f"the gateway refused a request ({refusal.code}) after {len(run.evidence)} sent; "
            "cannot tell",
        )
    except _BudgetExceeded as exc:
        return run.result(
            None, f"the request bound ({run.bound}) was reached before {exc}; cannot tell"
        )


def random_host() -> str:
    """A fresh host under the reserved ``.example`` TLD."""
    return f"bg{secrets.token_hex(6)}.{RANDOM_TLD}"


# ── open redirect ────────────────────────────────────────────────────


def browser_host(target: str, base_url: str) -> str | None:
    """The host a browser would go to for ``target`` on a page at ``base_url``.

    ``None`` for a URL that is not http(s) (``javascript:``, ``mailto:``...).
    Like a browser: tabs and newlines are dropped, backslashes count as
    slashes, any number of slashes may lead the authority, userinfo and port
    are not part of the host, and ``https:host`` is relative only when the
    page itself is https.
    """
    base = urlsplit(base_url)
    base_host = (base.hostname or "").lower()
    value = _STRIPPED.sub("", target).strip(" \x00\x0b\x0c").replace("\\", "/")
    match = _SCHEME.match(value)
    if match:
        scheme, rest = match.group(1).lower(), match.group(2)
        if scheme not in ("http", "https"):
            return None
        if scheme == base.scheme.lower() and not rest.startswith("//"):
            return base_host  # same scheme without an authority: a relative URL
        authority = rest.lstrip("/")
    elif value.startswith("//"):
        authority = value.lstrip("/")
    else:
        return base_host  # a path, query or fragment: same site
    authority = re.split(r"[/?#]", authority, maxsplit=1)[0].rpartition("@")[2]
    if authority.startswith("["):
        host = authority[1:].partition("]")[0]
    else:
        host = authority.partition(":")[0]
    return unquote(host).lower().rstrip(".")


def redirect_targets(capture: Capture) -> list[tuple[str, str]]:
    """``(kind, target)`` of every redirect a browser would act on in this response."""
    status = capture.status or 0
    if 300 <= status < 400:
        location = _header(capture, "location")
        return [("location", location)] if location else []
    if not 200 <= status < 300:
        return []
    body = text(capture)[:500_000]
    found: list[tuple[str, str]] = []
    for tag in _META_REFRESH.findall(body):
        content = _META_CONTENT.search(tag)
        if content:
            value = html.unescape(next(group for group in content.groups() if group is not None))
            url = _REFRESH_URL.search(value)
            if url:
                found.append(("meta_refresh", url.group(1).strip()))
    for pattern in (_JS_ASSIGN, _JS_CALL):
        for match in pattern.finditer(body):
            found.append(("javascript", match.group(2).replace("\\/", "/")))
    return found


def _hits(capture: Capture, base_url: str, host: str) -> tuple[str, str] | None:
    """The redirect in ``capture`` that goes to ``host``, if any."""
    for kind, target in redirect_targets(capture):
        if browser_host(target, base_url) == host:
            return kind, target
    return None


def _url_host(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme.lower() in ("http", "https") and parts.netloc:
        return (parts.hostname or "").lower()
    return ""


def open_redirect(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does one named parameter choose where the user is redirected?"""
    target = _target(params, _PathTarget)
    run = _MiscRun(
        ctx,
        target,
        probe=REDIRECT_PROBE,
        vuln_class=REDIRECT_CLASS,
        cwe=REDIRECT_CWE,
        remediation=REDIRECT_REMEDIATION,
        control=REDIRECT_CONTROL,
        bound=REDIRECT_MAX_REQUESTS,
    )
    hint = params.get("allowlist_hint")
    if isinstance(hint, (dict, list)):
        raise ProbeInputError("allowlist_hint must be text: an allowed URL or host")
    value = str(target.value)
    target_host = (urlsplit(target.url).hostname or "").lower()
    allowed = str(hint).strip() if hint not in (None, "") else ""
    if not allowed:
        allowed = value if _url_host(value) else target_host
    run.info["allowed"] = allowed
    run.info["allowed_host"] = _url_host(allowed) or allowed
    return _guarded(run, _examine_redirect)


def _examine_redirect(run: _MiscRun) -> ProbeResult:
    target = run.target
    parameter = target.parameter
    base_url = target.request(target.value)[0]
    target_host = (urlsplit(base_url).hostname or "").lower()
    value_host = _url_host(str(target.value))

    # 1. The original value: the control.
    baseline = run.send("baseline", target.value, "baseline (original value)")
    if _failed(baseline):
        return run.result(
            None, f"the baseline request failed ({_outcome(baseline)}); nothing to compare against"
        )
    destinations = [
        {"kind": kind, "target": goal[:300], "host": browser_host(goal, base_url)}
        for kind, goal in redirect_targets(baseline)
    ]
    run.info["baseline"] = {"status": baseline.status, "redirects": destinations}
    off_site = [
        entry
        for entry in destinations
        if entry["host"] is not None and entry["host"] not in (target_host, value_host)
    ]
    if off_site:
        return run.result(
            None,
            f"the original value already redirects to {off_site[0]['host']}, a site that is "
            "neither the target nor the one the value names: a redirect off-site cannot be "
            "attributed to the parameter; cannot tell",
        )

    # 2. The plain form, then the bypass forms.
    host = random_host()
    run.info["random_host"] = host
    fields = {
        "host": host,
        "allowed": run.info["allowed"],
        "allowed_host": run.info["allowed_host"],
    }
    forms = [("plain", REDIRECT_PLAIN), *REDIRECT_BYPASSES]
    tried: list[dict[str, Any]] = []
    run.info["tried"] = tried
    for name, template in forms:
        payload = template.format(**fields)
        capture = run.send(name, payload, f"redirect to a random host ({name})")
        entry: dict[str, Any] = {"form": name, "payload": payload, "status": capture.status}
        tried.append(entry)
        if capture.error or capture.status is None:
            entry["outcome"] = "no_answer"
            run.unresolved.append(f"the {name} request got no answer ({_outcome(capture)})")
            continue
        hit = _hits(capture, base_url, host)
        if hit is None:
            entry["outcome"] = "refused"
            continue
        kind, goal = hit
        entry.update({"outcome": "redirected", "redirect_kind": kind, "redirect_to": goal[:300]})
        run.technique = name
        how = {
            "location": f"HTTP {capture.status} with Location: {goal[:200]}",
            "meta_refresh": f"a meta refresh to {goal[:200]}",
            "javascript": f"a script that sets location to {goal[:200]}",
        }[kind]
        bypass = "" if name == "plain" else f" (allow-list bypassed with the {name} form)"
        return run.result(
            True,
            f"{parameter!r} chooses the redirect destination{bypass}: {how}. The host "
            f"{host} is random to this run and the original value stays on-site",
        )
    if run.unresolved:
        return run.result(None, "cannot tell: " + "; ".join(run.unresolved))
    return run.result(
        False,
        f"no open redirect through {parameter!r}: the plain form and {len(REDIRECT_BYPASSES)} "
        f"bypass forms never sent the user to {host}",
    )


# ── path traversal ───────────────────────────────────────────────────


def _extension(value: str) -> str:
    # The extension an extension check sees is the last one, after any NUL already in the value.
    name = posixpath.basename(unquote(unquote(value)))
    stem, dot, extension = name.rpartition(".")
    return f".{extension}" if dot and stem and extension.isalnum() and len(extension) <= 6 else ""


def traversal_payload(file: str, depth: int, encoding: str, extension: str, *, wire: bool) -> str:
    """One traversal value. ``wire``: written as it goes into a URL path (``%00`` is a NUL)."""
    climb = "../" if encoding == "plain" else "%2e%2e%2f"
    path = MARKER_FILES[file][0]
    if encoding == "encoded":
        path = path.replace("/", "%2f")
    suffix = ""
    if extension:
        suffix = ("%00" if wire else "\x00") + extension
    return climb * depth + path + suffix


def path_traversal(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does one named parameter let a request read a file outside its directory?"""
    run = _MiscRun(
        ctx,
        _target(params, _WirePathTarget),
        probe=TRAVERSAL_PROBE,
        vuln_class=TRAVERSAL_CLASS,
        cwe=TRAVERSAL_CWE,
        remediation=TRAVERSAL_REMEDIATION,
        control=TRAVERSAL_CONTROL,
        bound=TRAVERSAL_MAX_REQUESTS,
    )
    return _guarded(run, _examine_traversal)


def _examine_traversal(run: _MiscRun) -> ProbeResult:
    target = run.target
    parameter = target.parameter
    wire = target.location == "path"

    baseline = run.send("baseline", target.value, "baseline (original value)")
    if _failed(baseline):
        return run.result(
            None, f"the baseline request failed ({_outcome(baseline)}); nothing to compare against"
        )
    body = text(baseline)
    in_baseline = sorted(
        name for name, (_path, regex) in MARKER_FILES.items() if regex.search(body)
    )
    extension = _extension(str(target.value))
    run.info["baseline"] = {"status": baseline.status, "markers_present": in_baseline}
    run.info["extension"] = extension or None
    run.info["encoding"] = (
        "payloads are written as they go on the wire (path segment)"
        if wire
        else "payloads are the decoded value; the request encodes them once"
    )
    tried: list[dict[str, Any]] = []
    run.info["tried"] = tried
    skipped: list[str] = []

    for file, depth, encoding, null_byte in TRAVERSAL_PAYLOADS:
        role = f"{file}_d{depth}_{encoding}" + ("_null" if null_byte else "")
        if null_byte and not extension:
            skipped.append(f"{role}: the original value has no extension to keep")
            continue
        if file in in_baseline:
            skipped.append(f"{role}: the baseline already contains the {file} marker")
            continue
        payload = traversal_payload(
            file, depth, encoding, extension if null_byte else "", wire=wire
        )
        capture = run.send(role, payload, f"read {MARKER_FILES[file][0]} ({role})")
        entry: dict[str, Any] = {
            "role": role,
            "file": MARKER_FILES[file][0],
            "status": capture.status,
        }
        tried.append(entry)
        if capture.error or capture.status is None:
            entry["marker"] = None
            run.unresolved.append(f"the {role} request got no answer ({_outcome(capture)})")
            continue
        match = MARKER_FILES[file][1].search(text(capture))
        entry["marker"] = bool(match)
        if match:
            run.technique = f"{encoding}{'_null_byte' if null_byte else ''}"
            run.info.update({"file": MARKER_FILES[file][0], "depth": depth})
            if skipped:
                run.info["skipped"] = skipped
            return run.result(
                True,
                f"{parameter!r} reads files outside its directory: {depth} levels of "
                f"{encoding} ../ to {MARKER_FILES[file][0]} returned its contents "
                f"(HTTP {capture.status}, marker {match.group(0)[:40]!r}), which the baseline "
                "response does not contain",
            )
    if skipped:
        run.info["skipped"] = skipped
    if run.unresolved:
        return run.result(None, "cannot tell: " + "; ".join(run.unresolved))
    note = ""
    if in_baseline:
        note = (
            f" ({', '.join(in_baseline)} not tested: the baseline already contains that marker, "
            "so it could not prove a read)"
        )
    return run.result(
        False,
        f"no path traversal through {parameter!r}: none of the {len(tried)} traversal requests "
        f"returned a marker the baseline lacks{note}",
    )


# ── CORS ─────────────────────────────────────────────────────────────


def _cors_headers(capture: Capture) -> dict[str, str]:
    return {
        "allow_origin": _header(capture, "access-control-allow-origin").strip(),
        "allow_credentials": _header(capture, "access-control-allow-credentials").strip(),
        "vary": _header(capture, "vary").strip(),
    }


def cors(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does the endpoint let any origin read its responses with the user's credentials?"""
    require(params, "url")
    url = str(params["url"])
    headers = {k: v for k, v in headers_of(params.get("headers")).items() if k.lower() != "origin"}
    target = _Target("GET", url, "header", "Origin", headers, None, [], None, "")
    run = _MiscRun(
        ctx,
        target,
        probe=CORS_PROBE,
        vuln_class=CORS_CLASS,
        cwe=CORS_CWE,
        remediation=CORS_REMEDIATION,
        control=CORS_CONTROL,
        bound=CORS_MAX_REQUESTS,
    )
    return _guarded(run, _examine_cors)


def _examine_cors(run: _MiscRun) -> ProbeResult:
    headers = run.target.headers
    baseline = run.send_headers("baseline", dict(headers), "baseline (no Origin)")
    if _failed(baseline):
        return run.result(
            None, f"the baseline request failed ({_outcome(baseline)}); nothing to compare against"
        )
    origin = f"https://{random_host()}"
    run.info["random_origin"] = origin
    run.info["baseline"] = {"status": baseline.status, **_cors_headers(baseline)}
    responses: dict[str, Capture] = {}
    for role, sent in (("origin_random", origin), ("origin_null", "null")):
        responses[role] = run.send_headers(role, {**headers, "Origin": sent}, f"Origin: {sent}")

    observations: dict[str, dict[str, Any]] = {}
    informational: list[str] = []
    proven: list[tuple[str, str]] = []
    for role, sent in (("origin_random", origin), ("origin_null", "null")):
        capture = responses[role]
        seen = _cors_headers(capture)
        observations[role] = {"status": capture.status, **seen}
        if capture.error or capture.status is None:
            run.unresolved.append(f"the {role} request got no answer ({_outcome(capture)})")
            continue
        allowed = [part.strip().lower() for part in seen["allow_origin"].split(",") if part.strip()]
        credentials = seen["allow_credentials"].lower() == "true"
        if "*" in allowed:
            informational.append("wildcard-without-credentials")
        if sent.lower() in allowed:
            technique = "reflected_origin" if role == "origin_random" else "null_origin"
            if credentials:
                proven.append((technique, role))
            else:
                informational.append(f"{technique.replace('_', '-')}-without-credentials")
    run.info["responses"] = observations
    run.info["informational"] = list(dict.fromkeys(informational))

    if proven:
        technique, role = proven[0]
        run.technique = technique
        which = f"the random origin {origin}" if role == "origin_random" else "the null origin"
        return run.result(
            True,
            f"any site can read this endpoint with the user's credentials: {which} is allowed "
            "in Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true",
        )
    if run.unresolved:
        return run.result(None, "cannot tell: " + "; ".join(run.unresolved))
    if run.info["informational"]:
        return run.result(
            False,
            "no credentialed cross-origin read; informational: "
            + ", ".join(run.info["informational"])
            + " (a browser does not send cookies to such a response)",
        )
    return run.result(
        False, "no CORS misconfiguration: neither a random origin nor null is allowed"
    )


__all__ = [
    "CORS_MAX_REQUESTS",
    "MARKER_FILES",
    "REDIRECT_BYPASSES",
    "REDIRECT_MAX_REQUESTS",
    "TRAVERSAL_MAX_REQUESTS",
    "TRAVERSAL_PAYLOADS",
    "browser_host",
    "cors",
    "open_redirect",
    "path_traversal",
    "random_host",
    "redirect_targets",
    "traversal_payload",
]
