"""Stored and blind XSS probes. Both write to the target, so both need an approved run.

``xss_stored`` (never more than ``STORED_MAX_REQUESTS``):

1. each read-back page before the write (the control: it does not hold the
   run's marker). The read-back pages are the ones given, else the write URL
   itself (a form's page, or the collection ``GET /x/Items`` of an API
   ``POST /x/Items``) and, for a PUT or PATCH of ``/x/Items/5``, the parent;
2. one write that stores ``<b data-buggy="MARKER">MARKER</b>`` in the named
   text field. The marker is random to the run; the markup does nothing;
3. each read-back page again. Proven only when an HTML response, tokenized,
   holds a new ``<b data-buggy="MARKER">`` element: the markup came back
   unescaped where a browser renders it. The marker returned raw in a JSON
   response is reported as not proven (a browser does not render JSON; a page
   that puts it into the DOM would be stored XSS), with the reason.

``xss_blind`` (exactly one write): needs the callback listener. Each named
text field gets a payload whose ``<script src>`` and ``<img src>`` load
``<canary>/c/<token>`` (a token per field). Proof is a callback for a token:
some browser, often an operator's back office, rendered the stored value. The
run waits a short bounded time; every planted token is written to
``<audit>/<engagement>/blind-xss-planted.jsonl`` so :func:`blind_hits` can
pick up a callback that arrives later. The canary answers with plain text,
so nothing runs in the browser that loads it.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway
from buggy.capture.probes.base import (
    Context,
    ProbeInputError,
    ProbeResult,
    require,
    set_path,
    text,
)
from buggy.capture.probes.injection import _outcome, _replace_pair, _Target
from buggy.capture.probes.misc import _guarded
from buggy.capture.probes.web import NO_LISTENER, _GetRun, _wait_seconds
from buggy.capture.probes.xss import (
    _JSON_TYPE,
    _media_type,
    _renders_as_html,
    new_marker,
    tokenize,
)
from buggy.capture.store import Capture

CWE = "CWE-79"
VULN_CLASS = "xss"
LOCATIONS = ("query", "json", "form")
REMEDIATION = (
    "Encode stored text for the context it is written into on every page that shows it (an "
    "auto-escaping template engine does this for HTML); never insert it with innerHTML or an "
    "unescaped template. A Content-Security-Policy limits the damage; it does not fix the flaw."
)

# ── stored ───────────────────────────────────────────────────────────

STORED_PROBE = "xss_stored"
MAX_READBACKS = 3
STORED_MAX_REQUESTS = 1 + 2 * MAX_READBACKS
STORED_PAYLOAD = '<b data-buggy="{marker}">{marker}</b>'
STORED_CONTROL = (
    "each read-back page is read before the write and does not hold the run's marker; the "
    "marker is random to the run, so markup named after it can only come from the write"
)


def _text_target(params: dict[str, Any]) -> _Target:
    require(params, "url")
    location = str(params.get("location") or "form").lower()
    if location not in LOCATIONS:
        raise ProbeInputError(f"location must be one of {', '.join(LOCATIONS)}")
    method = str(params.get("method") or ("GET" if location == "query" else "POST")).upper()
    first = params.get("parameter") or (_names(params) or [""])[0]
    return _Target.from_params(
        {**params, "parameter": first, "location": location, "method": method, "value": ""}
    )


def _names(params: dict[str, Any]) -> list[str]:
    raw = params.get("parameters")
    if raw in (None, "", []):
        return [str(params["parameter"])] if params.get("parameter") else []
    if not isinstance(raw, list) or not all(isinstance(n, str) and n for n in raw):
        raise ProbeInputError("parameters must be a list of field names")
    return list(dict.fromkeys(raw))


def _bare(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(query="", fragment=""))


def readback_urls(params: dict[str, Any], target: _Target) -> list[str]:
    """The pages read before and after the write, at most ``MAX_READBACKS``."""
    given = params.get("readback_urls")
    if given in (None, "", []):
        urls = [_bare(target.url)]
        path = urlsplit(target.url).path.rstrip("/")
        if target.method in ("PUT", "PATCH") and path.count("/") >= 2:
            urls.append(urlunsplit(urlsplit(urls[0])._replace(path=path.rsplit("/", 1)[0])))
    elif isinstance(given, str):
        urls = [given]
    elif isinstance(given, list) and all(isinstance(u, str) for u in given):
        urls = list(given)
    else:
        raise ProbeInputError("readback_urls must be a URL or a list of URLs")
    urls = list(dict.fromkeys(urls))
    if len(urls) > MAX_READBACKS:
        raise ProbeInputError(f"give at most {MAX_READBACKS} readback_urls")
    for url in urls:
        if not url.startswith(("http://", "https://")):
            raise ProbeInputError("readback_urls must be absolute http(s) URLs")
    return urls


def _readback_headers(target: _Target) -> dict[str, str]:
    return {k: v for k, v in target.headers.items() if k.lower() != "content-type"}


def xss_stored(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does a value written through one text field come back as live markup?"""
    require(params, "url", "parameter")
    target = _text_target(params)
    run = _GetRun(
        ctx,
        target,
        probe=STORED_PROBE,
        vuln_class=VULN_CLASS,
        cwe=CWE,
        remediation=REMEDIATION,
        control=STORED_CONTROL,
        bound=STORED_MAX_REQUESTS,
    )
    urls = readback_urls(params, target)
    return _guarded(run, lambda r: _examine_stored(r, urls))


def _proof(capture: Capture, marker: str) -> bool:
    for token in tokenize(text(capture)):
        if token.kind == "start" and token.name == "b":
            if any(name == "data-buggy" and value == marker for name, value in token.attrs):
                return True
    return False


def _examine_stored(run: _GetRun, urls: list[str]) -> ProbeResult:
    target = run.target
    parameter = target.parameter
    marker = new_marker()
    payload = STORED_PAYLOAD.format(marker=marker)
    headers = _readback_headers(target)
    run.info.update({"marker": marker, "payload": payload, "readback_urls": urls})
    pages: list[dict[str, Any]] = []
    run.info["pages"] = pages

    # 1. The control: the read-back pages before the write.
    for index, url in enumerate(urls):
        before = run.fetch(
            f"before_{index}", "GET", url, headers=headers, note="read back (before)"
        )
        pages.append(
            {
                "url": url,
                "before_status": before.status,
                "before_has_marker": marker.lower() in text(before).lower(),
            }
        )

    # 2. The write.
    write = run.send("write", payload, f"store a harmless marker in {parameter!r}")
    run.info["write_status"] = write.status
    if write.error or write.status is None or write.status >= 400:
        return run.result(
            None, f"the write was not accepted ({_outcome(write)}); nothing was stored to read back"
        )

    # 3. The read-back pages after it.
    for index, (url, page) in enumerate(zip(urls, pages, strict=True)):
        after = run.fetch(f"after_{index}", "GET", url, headers=headers, note="read back (after)")
        page["after_status"] = after.status
        body = text(after)
        if after.error or after.status is None:
            page["outcome"] = "no_answer"
            run.unresolved.append(f"the read-back of {url} got no answer ({_outcome(after)})")
        elif page["before_has_marker"]:
            page["outcome"] = "not_attributable"
            run.unresolved.append(f"{url} held the marker before the write")
        elif marker.lower() not in body.lower():
            page["outcome"] = "not_shown"
        elif _JSON_TYPE.search(_media_type(after)):
            page["outcome"] = "json_raw" if "<b data-buggy=" in body else "json_encoded"
        elif not _renders_as_html(after):
            page["outcome"] = f"shown_in_{_media_type(after) or 'unknown'}"
        elif _proof(after, marker):
            page["outcome"] = "rendered"
            page["capture"] = after.id
        else:
            page["outcome"] = "inert"  # encoded, or where markup is not parsed (a textarea)

    rendered = [p for p in pages if p["outcome"] == "rendered"]
    if rendered:
        run.technique = "stored_html"
        where = ", ".join(p["url"] for p in rendered)
        return run.result(
            True,
            f"markup written through {parameter!r} comes back unescaped on {where}: the HTML "
            f'response holds a new <b data-buggy="{marker}"> element, and the page did not '
            "hold the marker before the write",
        )
    raw_json = [p for p in pages if p["outcome"] == "json_raw"]
    if raw_json:
        return run.result(
            None,
            f"not proven: the markup written through {parameter!r} comes back unescaped only in "
            f"a JSON response ({raw_json[0]['url']}); a browser does not render JSON, and a page "
            "that writes this value into the DOM unescaped would be stored XSS (check it in a "
            "browser)",
        )
    if run.unresolved:
        return run.result(None, "cannot tell: " + "; ".join(run.unresolved))
    inert = [p for p in pages if p["outcome"] in ("inert", "json_encoded")]
    if inert:
        return run.result(
            False,
            f"the value written through {parameter!r} is stored but comes back inert (encoded, "
            f"or where markup is not parsed) on {', '.join(p['url'] for p in inert)}",
        )
    shown = [p for p in pages if p["outcome"].startswith("shown_in_")]
    if shown:
        return run.result(
            None,
            f"the marker comes back in a {shown[0]['outcome'][8:]} response, which this probe "
            "does not analyse; cannot tell",
        )
    return run.result(
        False,
        f"the value written through {parameter!r} did not come back on the read-back pages "
        f"({', '.join(urls)}); it may be shown elsewhere",
    )


# ── blind ────────────────────────────────────────────────────────────

BLIND_PROBE = "xss_blind"
BLIND_MAX_REQUESTS = 1
BLIND_MAX_FIELDS = 5
BLIND_WAIT_SECONDS = 5.0
BLIND_MAX_WAIT_SECONDS = 20.0
#: ``{url}`` is the field's canary URL. Breaks out of a quoted attribute first.
BLIND_PAYLOAD = '"\'><script src="{url}/s"></script><img src="{url}/i">'
BLIND_CONTROL = (
    "the callback token is random and planted in this one request only, so a callback for it "
    "can only come from something that rendered the stored value"
)
PLANTED_FILE = "blind-xss-planted.jsonl"
_PLANTED_LOCK = threading.Lock()


def planted_path(gateway: CaptureGateway, engagement: str) -> Path:
    return gateway.roots.audit / engagement / PLANTED_FILE


def _with_values(target: _Target, values: dict[str, str]) -> tuple[str, str | None]:
    """``(url, body)`` of the request with every named field set."""
    if target.location == "json":
        document = target.json_body or {}
        for name, value in values.items():
            document = set_path(document, name, value)
        return target.url, json.dumps(document)
    if target.location == "form":
        pairs = list(target.form_pairs)
        for name, value in values.items():
            pairs = _replace_pair(pairs, name, value)
        return target.url, urlencode(pairs)
    parts = urlsplit(target.url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    for name, value in values.items():
        pairs = _replace_pair(pairs, name, value)
    return urlunsplit(parts._replace(query=urlencode(pairs))), target.raw_body


def xss_blind(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does a stored value get rendered by some browser later (an admin page, a log viewer)?"""
    require(params, "url")
    names = _names(params)
    if not names:
        raise ProbeInputError("missing required parameter(s): parameter or parameters")
    if len(names) > BLIND_MAX_FIELDS:
        raise ProbeInputError(f"give at most {BLIND_MAX_FIELDS} parameters")
    target = _text_target({**params, "parameter": names[0]})
    wait = _wait_seconds(params, BLIND_WAIT_SECONDS, BLIND_MAX_WAIT_SECONDS)
    run = _GetRun(
        ctx,
        target,
        probe=BLIND_PROBE,
        vuln_class=VULN_CLASS,
        cwe=CWE,
        remediation=REMEDIATION,
        control=BLIND_CONTROL,
        bound=BLIND_MAX_REQUESTS,
    )
    run.info["parameters"] = names
    if ctx.canary is None or not ctx.canary.available:
        return run.result(None, NO_LISTENER)
    return _guarded(run, lambda r: _examine_blind(r, names, wait))


def _examine_blind(run: _GetRun, names: list[str], wait: float) -> ProbeResult:
    ctx, target = run.ctx, run.target
    assert ctx.canary is not None
    tokens: dict[str, str] = {}
    values: dict[str, str] = {}
    for name in names:
        token, url = ctx.canary.mint(ctx.engagement)
        tokens[token] = name
        values[name] = BLIND_PAYLOAD.format(url=url)
    url, body = _with_values(target, values)
    if run.left <= 0:
        return run.result(None, "the request bound was reached; cannot tell")
    capture = run.fetch(
        "write", target.method, url, headers=dict(target.headers), body=body,
        note="store payloads that call back when rendered",
    )  # fmt: skip
    run.payloads["write"] = values
    run.info["write_status"] = capture.status
    run.info["tokens"] = {name: token for token, name in tokens.items()}
    if capture.error or capture.status is None or capture.status >= 400:
        return run.result(
            None, f"the write was not accepted ({_outcome(capture)}); nothing was planted"
        )
    _record_planted(run, capture, tokens)
    hits = ctx.canary.wait_for_any(ctx.engagement, list(tokens), timeout=wait)
    run.info["callbacks"] = [h.to_dict() for found in hits.values() for h in found]
    if hits:
        token = next(iter(hits))
        run.technique = "callback"
        return run.result(
            True,
            f"the value stored through {tokens[token]!r} was rendered by a browser that loaded "
            f"its script: callback from {hits[token][0].remote} for the token planted in this "
            "write only",
        )
    return run.result(
        None,
        f"planted in {', '.join(names)}; no callback within {wait:g} s. A browser may render it "
        "later: blind_hits reports a later callback for this write",
    )


def _record_planted(run: _GetRun, capture: Capture, tokens: dict[str, str]) -> None:
    ctx, target = run.ctx, run.target
    path = planted_path(ctx.gateway, ctx.engagement)
    now = time.time()
    lines = [
        json.dumps(
            {
                "token": token,
                "engagement": ctx.engagement,
                "url": target.url,
                "method": target.method,
                "location": target.location,
                "parameter": name,
                "capture_id": capture.id,
                "identity": ctx.identity,
                "planted_at": now,
            }
        )
        for token, name in tokens.items()
    ]
    with _PLANTED_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")


def planted(gateway: CaptureGateway, engagement: str) -> list[dict[str, Any]]:
    """Every blind XSS token planted for ``engagement``, oldest first."""
    path = planted_path(gateway, engagement)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    out: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("engagement") == engagement and row.get("token"):
            out.append(row)
    return out


def blind_hits(
    gateway: CaptureGateway, canary: Canary | None, engagement: str
) -> list[dict[str, Any]]:
    """A probe result (``vulnerable: true``) for every planted token that got a callback.

    Re-registers every planted token with the listener first, so a callback
    that arrives after a restart still lands (one that arrived while the
    token was unknown is lost). Each result has the shape of ``probe_run``'s
    and names the write's capture as evidence and the run's ``url``.
    """
    if canary is None or not canary.available:
        return []
    out: list[dict[str, Any]] = []
    for row in planted(gateway, engagement):
        token = str(row["token"])
        if not canary.adopt(engagement, token):
            continue
        hits = canary.hits(engagement, token)
        if not hits:
            continue
        parameter = str(row.get("parameter") or "")
        delay = round(hits[0].at - float(row.get("planted_at") or hits[0].at))
        result = ProbeResult(
            BLIND_PROBE,
            VULN_CLASS,
            CWE,
            True,
            f"the value stored through {parameter!r} was rendered by a browser that loaded its "
            f"script: callback from {hits[0].remote}, {delay} s after the write, for the token "
            "planted in that write only",
            [str(row.get("capture_id") or "")],
            {
                "technique": "late_callback",
                "method": row.get("method"),
                "location": row.get("location"),
                "parameter": parameter,
                "token": token,
                "planted_at": row.get("planted_at"),
                "callbacks": [hit.to_dict() for hit in hits],
                "control": BLIND_CONTROL,
            },
            REMEDIATION,
        ).to_dict()
        result.update({"status": "completed", "url": row.get("url")})
        if row.get("identity"):
            result["identity"] = row["identity"]
        out.append(result)
    return out


__all__ = [
    "BLIND_MAX_REQUESTS",
    "BLIND_PAYLOAD",
    "MAX_READBACKS",
    "STORED_MAX_REQUESTS",
    "STORED_PAYLOAD",
    "blind_hits",
    "planted",
    "readback_urls",
    "xss_blind",
    "xss_stored",
]
