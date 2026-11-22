"""Remote file inclusion, clickjacking and CSRF probes.

``rfi`` (read-only, never more than ``RFI_MAX_REQUESTS``): needs the callback
listener (``capture/canary.py``); without one nothing is sent and the result
says it could not test.

1. the original value (baseline, and the control: the run's marker is not in it);
2. a fresh canary URL in the parameter, plain and with a ``?`` after it (an
   extension the server appends then lands in the query). Each URL serves a
   random marker text. The marker in the target's own response proves that
   the fetched file was included. A callback without the marker in any
   response proves only that the server fetched the URL: that is reported as
   server-side request forgery (class ``ssrf``), not as an inclusion.

``clickjacking`` (read-only, exactly one GET): a page can be framed by any
site when it sends neither ``X-Frame-Options: DENY|SAMEORIGIN`` nor a
``Content-Security-Policy`` ``frame-ancestors`` that excludes other sites. The
page must answer 2xx with HTML. The result carries a small proof page (an
iframe of the page) for the proof video. Re-proof is the same GET again.

``csrf`` (state-changing, needs a declared identity whose session is a
cookie; never more than ``CSRF_MAX_REQUESTS``):

1. the request as the identity, same-site (``Origin``/``Referer`` of the target):
   the baseline, and the control;
2. the anti-CSRF token fields and headers it carries, and the ``SameSite``
   attribute of the session cookie (from the login response and the
   baseline's ``Set-Cookie``). ``Strict`` (or ``Lax`` for anything but a GET)
   ends the run: a browser would not send the cookie cross-site;
3. the same request as the identity from a random ``https://<random>.example``
   origin, with every token removed (a JSON body goes as ``text/plain``, which
   a cross-site form can send). Accepted the same way as the baseline:
4. the same cross-site request without the session (the control that the
   action needs the session at all). Refused: the request is forgeable.

A positive verdict always rests on a control; anything the probe could not
attribute is reported as ``vulnerable: null``.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from buggy.capture.probes.base import (
    Context,
    ProbeInputError,
    ProbeResult,
    headers_of,
    require,
    similarity,
    text,
)
from buggy.capture.probes.injection import _BudgetExceeded, _failed, _outcome, _Target
from buggy.capture.probes.misc import _guarded, _MiscRun, _target, random_host
from buggy.capture.probes.xss import _header, _PathTarget, _renders_as_html, new_marker, tokenize
from buggy.capture.store import Capture

# ── shared ───────────────────────────────────────────────────────────


@dataclass
class _GetRun(_MiscRun):
    """``_MiscRun`` that can also send a request to any URL (a read-back, a page)."""

    def fetch(
        self,
        role: str,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        note: str = "",
        anonymous: bool = False,
    ) -> Capture:
        if self.left <= 0:
            raise _BudgetExceeded(role)
        self.payloads[role] = None
        capture = self.ctx.send(
            method, url, headers=headers, body=body, note=note, anonymous=anonymous
        )
        self.evidence.append(capture.id)
        self.captures[role] = capture.id
        return capture


def _accepted(capture: Capture) -> bool:
    return not capture.error and capture.status is not None and 200 <= capture.status < 400


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


# ── remote file inclusion ────────────────────────────────────────────

RFI_PROBE = "rfi"
RFI_CLASS = "file_handling"
RFI_CWE = "CWE-98"
RFI_MAX_REQUESTS = 3  # baseline + the two forms below
RFI_WAIT_SECONDS = 3.0
RFI_MAX_WAIT_SECONDS = 10.0
#: ``{url}`` is a fresh canary URL. Sent in this order.
RFI_FORMS: tuple[tuple[str, str], ...] = (
    ("plain", "{url}"),
    ("query_suffix", "{url}?"),
)
RFI_REMEDIATION = (
    "Never include or evaluate a file named by the request. Map the value to a file through a "
    "server-side allow-list, and turn remote includes off (in PHP: allow_url_include=Off and "
    "allow_url_fopen=Off)."
)
SSRF_CLASS = "ssrf"
SSRF_CWE = "CWE-918"
SSRF_REMEDIATION = (
    "Do not fetch caller-supplied URLs server-side. If required, resolve and validate the "
    "destination against an allow-list and block internal, link-local and metadata ranges."
)
RFI_CONTROL = (
    "baseline: the original value; the marker is random to the run and only the canary URL "
    "serves it, so it cannot be in the response unless the fetched file was included"
)
NO_LISTENER = (
    "no callback listener is configured (BUGGY_CANARY_BASE_URL), so the probe could not test; "
    "nothing was sent"
)


def _wait_seconds(params: dict[str, Any], default: float, limit: float) -> float:
    raw = params.get("wait_seconds")
    if raw in (None, ""):
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ProbeInputError("wait_seconds must be a number") from exc
    return max(0.0, min(value, limit))


def rfi(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does one named parameter make the server include a remote file?"""
    run = _GetRun(
        ctx,
        _target(params, _PathTarget),
        probe=RFI_PROBE,
        vuln_class=RFI_CLASS,
        cwe=RFI_CWE,
        remediation=RFI_REMEDIATION,
        control=RFI_CONTROL,
        bound=RFI_MAX_REQUESTS,
    )
    wait = _wait_seconds(params, RFI_WAIT_SECONDS, RFI_MAX_WAIT_SECONDS)
    if ctx.canary is None or not ctx.canary.available:
        return run.result(None, NO_LISTENER)
    return _guarded(run, lambda r: _examine_rfi(r, wait))


def _examine_rfi(run: _GetRun, wait: float) -> ProbeResult:
    ctx, target = run.ctx, run.target
    assert ctx.canary is not None
    parameter = target.parameter
    baseline = run.send("baseline", target.value, "baseline (original value)")
    if _failed(baseline):
        return run.result(
            None, f"the baseline request failed ({_outcome(baseline)}); nothing to compare against"
        )
    marker = "bgrfi" + new_marker()[2:]
    run.info["marker"] = marker
    run.info["baseline"] = {"status": baseline.status, "marker_present": marker in text(baseline)}
    if run.info["baseline"]["marker_present"]:
        return run.result(None, "the baseline already contains the run's marker; cannot tell")
    tokens: dict[str, str] = {}
    tried: list[dict[str, Any]] = []
    run.info["tried"] = tried
    for name, template in RFI_FORMS:
        token, url = ctx.canary.mint(ctx.engagement, body=marker)
        tokens[token] = name
        payload = template.format(url=url)
        capture = run.send(name, payload, f"remote file URL ({name})")
        entry: dict[str, Any] = {"form": name, "payload": payload, "status": capture.status}
        tried.append(entry)
        if capture.error or capture.status is None:
            entry["marker"] = None
            run.unresolved.append(f"the {name} request got no answer ({_outcome(capture)})")
            continue
        entry["marker"] = marker in text(capture)
        if entry["marker"]:
            run.technique = name
            run.info["callbacks"] = [h.to_dict() for h in ctx.canary.hits(ctx.engagement, token)]
            return run.result(
                True,
                f"{parameter!r} includes a remote file: the target fetched the URL given in it "
                f"and its response (HTTP {capture.status}) carries the marker that only that "
                "URL serves; the baseline response does not",
            )
    hits = ctx.canary.wait_for_any(ctx.engagement, list(tokens), timeout=wait)
    run.info["callbacks"] = [h.to_dict() for found in hits.values() for h in found]
    if hits:
        token = next(iter(hits))
        run.technique = tokens[token]
        run.vuln_class, run.cwe, run.remediation = SSRF_CLASS, SSRF_CWE, SSRF_REMEDIATION
        return run.result(
            True,
            f"the server fetches the URL given in {parameter!r} (callback from "
            f"{hits[token][0].remote}) but does not include its content: this is a server-side "
            "request (SSRF evidence), not a remote file inclusion",
        )
    if run.unresolved:
        return run.result(None, "cannot tell: " + "; ".join(run.unresolved))
    return run.result(
        False,
        f"no remote file inclusion through {parameter!r}: the target neither included nor "
        f"fetched the canary URL (waited {wait:g} s for a callback)",
    )


# ── clickjacking ─────────────────────────────────────────────────────

FRAME_PROBE = "clickjacking"
FRAME_CLASS = "misconfiguration"
FRAME_CWE = "CWE-1021"
FRAME_MAX_REQUESTS = 1
FRAME_REMEDIATION = (
    "Send Content-Security-Policy: frame-ancestors 'none' (or 'self' when the site frames its "
    "own pages), and X-Frame-Options: DENY (or SAMEORIGIN) for older browsers, on every page "
    "that holds an action or account data."
)
FRAME_CONTROL = (
    "the page itself: one GET; a page that answers with X-Frame-Options DENY/SAMEORIGIN or a "
    "frame-ancestors that excludes other sites is not framable, and the same GET re-proves it"
)
_PROTECTING_XFO = ("deny", "sameorigin")
_ANY_SOURCE = re.compile(r"^(?:\*|https?:|https?://\*|wss?:)$", re.IGNORECASE)


def frame_policy(capture: Capture) -> dict[str, Any]:
    """How the response limits framing, as a browser reads it.

    ``frame-ancestors`` (enforced CSP only) wins over ``X-Frame-Options``.
    ``framable`` is True when any site may frame the page.
    """
    xfo_raw = _header(capture, "x-frame-options").strip()
    xfo = [part.strip().lower() for part in xfo_raw.split(",") if part.strip()]
    csp_raw = _header(capture, "content-security-policy")
    ancestors: list[list[str]] = []
    for policy in csp_raw.split(","):
        for directive in policy.split(";"):
            words = directive.strip().split()
            if words and words[0].lower() == "frame-ancestors":
                ancestors.append(words[1:])
    report = {
        "x_frame_options": xfo_raw[:200],
        "frame_ancestors": [" ".join(sources)[:200] for sources in ancestors],
        "csp_report_only_ignored": bool(_header(capture, "content-security-policy-report-only")),
    }
    if ancestors:
        # Every enforced policy must allow the framing site; one closed policy protects.
        open_policies = [s for s in ancestors if any(_ANY_SOURCE.match(src) for src in s)]
        framable = len(open_policies) == len(ancestors)
        why = (
            "frame-ancestors allows any site"
            if framable
            else "frame-ancestors excludes other sites"
        )
        return {**report, "framable": framable, "decided_by": "frame-ancestors", "why": why}
    if any(value in _PROTECTING_XFO for value in xfo):
        return {
            **report,
            "framable": False,
            "decided_by": "x-frame-options",
            "why": f"X-Frame-Options {xfo_raw}",
        }
    why = "neither X-Frame-Options (DENY/SAMEORIGIN) nor CSP frame-ancestors is sent"
    if any(value.startswith("allow-from") for value in xfo):
        why += " (X-Frame-Options ALLOW-FROM is ignored by current browsers)"
    elif xfo:
        why += f" (X-Frame-Options {xfo_raw!r} is not a value browsers honour)"
    return {**report, "framable": True, "decided_by": "none", "why": why}


def proof_page(url: str) -> str:
    """A small page that frames ``url``: what an attacker's site would do."""
    src = html.escape(url, quote=True)
    return (
        "<!doctype html><meta charset=utf-8><title>Clickjacking proof</title>"
        "<p>This page is on another site. The target page below is loaded in a frame; an "
        "attacker would make it invisible and place a decoy button over its controls.</p>"
        f'<iframe src="{src}" width="1000" height="700" '
        'style="border:2px solid #e16f24"></iframe>'
    )


def clickjacking(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Can any site load this page in a frame?"""
    require(params, "url")
    url = str(params["url"])
    if not url.startswith(("http://", "https://")):
        raise ProbeInputError("url must be an absolute http(s) URL")
    target = _Target("GET", url, "page", "", headers_of(params.get("headers")), None, [], None, "")
    run = _GetRun(
        ctx,
        target,
        probe=FRAME_PROBE,
        vuln_class=FRAME_CLASS,
        cwe=FRAME_CWE,
        remediation=FRAME_REMEDIATION,
        control=FRAME_CONTROL,
        bound=FRAME_MAX_REQUESTS,
    )
    return _guarded(run, _examine_frame)


def _examine_frame(run: _GetRun) -> ProbeResult:
    url = run.target.url
    page = run.fetch("page", "GET", url, headers=dict(run.target.headers), note="load the page")
    if page.error or page.status is None:
        return run.result(None, f"the page did not answer ({_outcome(page)}); cannot tell")
    if not 200 <= page.status < 300:
        where = _header(page, "location")
        to = f" to {where[:200]}" if where else ""
        return run.result(
            None,
            f"the page answered HTTP {page.status}{to}, not the page itself; cannot tell (a page "
            "behind a login needs an identity)",
        )
    if not _renders_as_html(page):
        return run.result(
            None, "the response is not an HTML page, so framing it shows nothing; cannot tell"
        )
    policy = frame_policy(page)
    forms = [t for t in tokenize(text(page)) if t.kind == "start" and t.name == "form"]
    run.info["frame_policy"] = policy
    run.info["forms_on_page"] = len(forms)
    if not policy["framable"]:
        return run.result(False, f"the page cannot be framed by another site: {policy['why']}")
    run.technique = policy["decided_by"]
    run.info["proof_html"] = proof_page(url)
    return run.result(
        True,
        f"any site can load this page in a frame (HTTP {page.status}): {policy['why']}; a "
        "decoy page can trick a signed-in user into clicking its controls",
    )


# ── CSRF ─────────────────────────────────────────────────────────────

CSRF_PROBE = "csrf"
CSRF_CLASS = "csrf"
CSRF_CWE = "CWE-352"
CSRF_MAX_REQUESTS = 3
CSRF_LOCATIONS = ("form", "json", "query")
CSRF_REMEDIATION = (
    "Require a per-session anti-CSRF token (synchronizer or signed double-submit) on every "
    "state-changing request and reject requests whose Origin (or Referer) is not the site's own. "
    "Set the session cookie with SameSite=Lax or Strict as defence in depth."
)
CSRF_CONTROL = (
    "baseline: the same request same-site as the identity must be accepted; the cross-site copy "
    "is compared with it, and the same cross-site request without the session must be refused"
)
#: A body field or header with one of these names carries an anti-CSRF token.
TOKEN_FIELD = re.compile(
    r"csrf|xsrf|authenticity_?token|requestverificationtoken|anti_?forgery|^_?token$|nonce",
    re.IGNORECASE,
)
TOKEN_HEADER = re.compile(r"csrf|xsrf|^x-requested-with$", re.IGNORECASE)
SAME_THRESHOLD = 0.9
_SAMESITE_RANK = {"strict": 3, "lax": 2, "none": 0, "": 0}


def set_cookie_attributes(capture: Capture | None) -> dict[str, str]:
    """``{cookie name: its SameSite value, lower case ("" when absent)}`` from ``Set-Cookie``."""
    if capture is None:
        return {}
    out: dict[str, str] = {}
    for line in _header(capture, "set-cookie").split("\n"):
        pieces = [piece.strip() for piece in line.split(";")]
        name = pieces[0].partition("=")[0].strip()
        if not name:
            continue
        samesite = ""
        for piece in pieces[1:]:
            key, _, value = piece.partition("=")
            if key.strip().lower() == "samesite":
                samesite = value.strip().lower()
        out[name] = samesite
    return out


@dataclass(frozen=True)
class _Request:
    method: str
    url: str
    location: str
    headers: dict[str, str]
    fields: dict[str, Any] | list[tuple[str, str]]

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> _Request:
        require(params, "url")
        url = str(params["url"])
        if not url.startswith(("http://", "https://")):
            raise ProbeInputError("url must be an absolute http(s) URL")
        method = str(params.get("method") or "POST").upper()
        location = str(params.get("location") or ("query" if method == "GET" else "form")).lower()
        if location not in CSRF_LOCATIONS:
            raise ProbeInputError(f"location must be one of {', '.join(CSRF_LOCATIONS)}")
        body = params.get("body")
        fields: dict[str, Any] | list[tuple[str, str]]
        if location == "json":
            if isinstance(body, str) and body.strip():
                try:
                    body = json.loads(body)
                except ValueError as exc:
                    raise ProbeInputError("body is not valid JSON") from exc
            if not isinstance(body, dict):
                raise ProbeInputError("body must be a JSON object when location is json")
            fields = dict(body)
        elif location == "form":
            if isinstance(body, dict):
                fields = [(str(k), str(v)) for k, v in body.items()]
            elif isinstance(body, str):
                fields = parse_qsl(body, keep_blank_values=True)
            elif body in (None, ""):
                fields = []
            else:
                raise ProbeInputError("body must be a form string or an object of fields")
        else:
            fields = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        return cls(method, url, location, headers_of(params.get("headers")), fields)

    def names(self) -> list[str]:
        if isinstance(self.fields, dict):
            return list(self.fields)
        return [name for name, _value in self.fields]

    def build(self, drop: set[str], *, cross_site: bool) -> tuple[str, dict[str, str], str | None]:
        """``(url, headers, body)`` without the ``drop`` fields."""
        headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in ("content-type", "origin", "referer")
            and not (cross_site and TOKEN_HEADER.search(k))
        }
        url, body = self.url, None
        if isinstance(self.fields, dict):
            kept = {k: v for k, v in self.fields.items() if k not in drop}
            body = json.dumps(kept)
            # A cross-site form can send JSON text only as text/plain (no preflight).
            headers["Content-Type"] = "text/plain" if cross_site else "application/json"
        elif self.location == "form":
            body = urlencode([(k, v) for k, v in self.fields if k not in drop])
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            parts = urlsplit(self.url)
            query = urlencode([(k, v) for k, v in self.fields if k not in drop])
            url = urlunsplit(parts._replace(query=query))
        return url, headers, body


def csrf(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Can another site make the signed-in user's browser send this request?"""
    request = _Request.from_params(params)
    listed = params.get("token_fields")
    if listed not in (None, "") and not (
        isinstance(listed, list) and all(isinstance(n, str) for n in listed)
    ):
        raise ProbeInputError("token_fields must be a list of field names")
    if not ctx.identity:
        raise ProbeInputError("csrf needs identity: a declared test account with a cookie session")
    tokens = {n for n in request.names() if TOKEN_FIELD.search(n)} | set(listed or [])
    target = _Target(request.method, request.url, request.location, "", {}, None, [], None, "")
    run = _GetRun(
        ctx,
        target,
        probe=CSRF_PROBE,
        vuln_class=CSRF_CLASS,
        cwe=CSRF_CWE,
        remediation=CSRF_REMEDIATION,
        control=CSRF_CONTROL,
        bound=CSRF_MAX_REQUESTS,
    )
    run.info["token_fields"] = sorted(t for t in tokens if t in request.names())
    run.info["token_headers"] = sorted(k for k in request.headers if TOKEN_HEADER.search(k))
    return _guarded(run, lambda r: _examine_csrf(r, request, tokens))


def _session_cookies(run: _GetRun, baseline: Capture) -> tuple[dict[str, str], list[str]] | str:
    """``({session cookie: SameSite or "unknown"}, session header names)``, or why not known."""
    ctx = run.ctx
    try:
        session, _fresh = ctx.gateway.sessions.session_for(ctx.engagement, ctx.identity)
    except Exception as exc:  # noqa: BLE001 - any failure here means "cannot tell"
        return f"the identity's session could not be read ({type(exc).__name__})"
    seen: dict[str, str] = {}
    if session.login_capture_id:
        seen.update(
            set_cookie_attributes(ctx.gateway.store.get(ctx.engagement, session.login_capture_id))
        )
    seen.update(set_cookie_attributes(baseline))
    cookies = {name: seen.get(name, "unknown") for name in session.cookies}
    return cookies, sorted(session.headers)


def _same_outcome(first: Capture, second: Capture) -> tuple[bool, float]:
    if second.error or second.status != first.status:
        return False, 0.0
    if first.status is not None and 300 <= first.status < 400:
        same = _header(first, "location") == _header(second, "location")
        return same, 1.0 if same else 0.0
    score = similarity(first, second)
    return score >= SAME_THRESHOLD, score


def _examine_csrf(run: _GetRun, request: _Request, tokens: set[str]) -> ProbeResult:
    identity = run.ctx.identity
    origin = _origin(request.url)
    url, headers, body = request.build(set(), cross_site=False)
    same_site = {**headers, "Origin": origin, "Referer": request.url}
    if request.method == "GET":
        same_site.pop("Origin")
    baseline = run.fetch(
        "baseline", request.method, url, headers=same_site, body=body, note="same-site request"
    )
    run.info["baseline"] = {"status": baseline.status}
    if not _accepted(baseline):
        return run.result(
            None,
            f"the same-site request as {identity!r} was not accepted ({_outcome(baseline)}); "
            "nothing to compare against",
        )

    session = _session_cookies(run, baseline)
    if isinstance(session, str):
        return run.result(None, f"{session}; cannot tell")
    cookies, session_headers = session
    run.info["session_cookies"] = cookies
    if not cookies:
        return run.result(
            False,
            f"{identity!r} signs in with a header, not a cookie: a browser does not add it to a "
            "request another site makes, so the request cannot be forged",
        )
    if session_headers:
        run.info["session_headers"] = session_headers
        return run.result(
            None,
            f"{identity!r} also carries its session in a header ({', '.join(session_headers)}), "
            "which a browser would not add to a cross-site request and this probe cannot leave "
            "out; cannot tell",
        )
    known = [v for v in cookies.values() if v != "unknown"]
    strongest = max(known, key=lambda v: _SAMESITE_RANK.get(v, 0), default="unknown")
    if len(known) < len(cookies) and _SAMESITE_RANK.get(strongest, 0) < _SAMESITE_RANK["lax"]:
        strongest = "unknown"  # a cookie never seen in Set-Cookie may be the strict one
    run.info["samesite"] = strongest
    if strongest == "strict" or (strongest == "lax" and request.method != "GET"):
        return run.result(
            False,
            f"the session cookie is SameSite={strongest.title()}: a browser does not send it with "
            f"a cross-site {request.method}, so the request cannot be forged",
        )

    attacker = f"https://{random_host()}"
    run.info["cross_site_origin"] = attacker
    url, headers, body = request.build(tokens, cross_site=True)
    cross = {**headers, "Origin": attacker, "Referer": f"{attacker}/"}
    if request.method == "GET":
        cross.pop("Origin")
    forged = run.fetch(
        "cross_site", request.method, url, headers=cross, body=body,
        note=f"cross-site request from {attacker}, no anti-CSRF token",
    )  # fmt: skip
    same, score = _same_outcome(baseline, forged)
    run.info["cross_site"] = {"status": forged.status, "similarity": score, "same": same}
    removed = sorted(tokens & set(request.names())) + run.info["token_headers"]
    if forged.error or forged.status is None:
        return run.result(None, f"the cross-site request got no answer ({_outcome(forged)})")
    if not same:
        why = "it needs the anti-CSRF token" if removed else "it checks Origin or Referer"
        return run.result(
            False,
            f"the cross-site request is refused or handled differently (HTTP {forged.status}, "
            f"the same-site one HTTP {baseline.status}): {why}",
        )

    anonymous = run.fetch(
        "cross_site_no_session", request.method, url, headers=cross, body=body,
        note="the same cross-site request without the session (control)", anonymous=True,
    )  # fmt: skip
    without, _score = _same_outcome(baseline, anonymous)
    run.info["no_session"] = {"status": anonymous.status, "same": without}
    if anonymous.error or anonymous.status is None:
        return run.result(
            None, f"the control without the session got no answer ({_outcome(anonymous)})"
        )
    if without:
        return run.result(
            False,
            "the request is accepted without any session as well: it does not act as the signed-in "
            "user, so forging it gains nothing",
        )
    ignored = f"; the token(s) {', '.join(removed)} were removed and not missed" if removed else ""
    cookie = ", ".join(sorted(cookies))
    if strongest == "unknown":
        return run.result(
            None,
            f"a cross-site request without any token is accepted as {identity!r} like the "
            f"same-site one{ignored}, but the SameSite attribute of the session cookie ({cookie}) "
            "was never seen in a Set-Cookie header, so it is not known whether a browser sends "
            "it; cannot tell",
        )
    attribute = "no SameSite attribute" if strongest == "" else f"SameSite={strongest.title()}"
    note = (
        " (Chrome treats a cookie without the attribute as Lax; Firefox and Safari send it)"
        if strongest == ""
        else ""
    )
    run.technique = "missing_token" if not removed else "token_not_checked"
    return run.result(
        True,
        f"another site can make {identity!r}'s browser send this {request.method}: a request "
        f"from {attacker} without any anti-CSRF token is accepted like the same-site one (HTTP "
        f"{forged.status}){ignored}; the session cookie ({cookie}) has {attribute}{note}; "
        f"without the session the request is refused (HTTP {anonymous.status})",
    )


__all__ = [
    "CSRF_MAX_REQUESTS",
    "FRAME_MAX_REQUESTS",
    "RFI_FORMS",
    "RFI_MAX_REQUESTS",
    "clickjacking",
    "csrf",
    "frame_policy",
    "proof_page",
    "rfi",
    "set_cookie_attributes",
]
