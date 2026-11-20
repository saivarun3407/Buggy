"""Reflected XSS probe: where is the value reflected, and can markup break out of it?

The probe proves that attacker-controlled markup characters come back
unencoded in a context where a browser acts on them, and names that context.
It never sends anything that would run: every payload is a constant in this
module built around a unique alphanumeric marker (``bg`` + 12 hex digits),
and the proof is structural (a new element, a new attribute, a terminated
string literal, a controlled URL scheme), found by tokenizing the response.
No browser is involved.

Request sequence (never more than ``MAX_REQUESTS``):

1. the bare marker (the baseline, and the control): not reflected in the
   body means not vulnerable; reflected in a JSON response means not
   exploitable, because a browser does not render JSON as HTML;
2. the baseline is tokenized and every reflection is classified by context;
3. one request per distinct context, each with a fresh marker and that
   context's breaking characters. The context is vulnerable when the
   response, tokenized again, holds the structure only unencoded breaking
   characters can create. Reflected in the same context without it: not
   vulnerable. Not reflected in that context at all: could not tell.

The control is the baseline: the same request with a value that has no markup
characters is reflected inert, and the element or attribute that proves a
context is named after a marker sent in that one request only, so it cannot
be part of the page by coincidence.

Out of bounds: stored and DOM XSS, and reflections in response headers.
"""

from __future__ import annotations

import re
import secrets
from bisect import bisect_right
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote

from buggy.capture.gateway import GatewayRefusal
from buggy.capture.probes.base import (
    Context,
    ProbeInputError,
    ProbeResult,
    headers_of,
    require,
    text,
)
from buggy.capture.probes.injection import _as_text, _BudgetExceeded, _outcome, _Run, _Target
from buggy.capture.store import Capture

PROBE = "xss_reflected"
VULN_CLASS = "xss"
CWE = "CWE-79"

MAX_REQUESTS = 6
MARKER_PREFIX = "bg"
BODY_LIMIT = 1_000_000  # characters of a response that are tokenized

CONTEXTS = (
    "html_text",
    "attribute_quoted",
    "attribute_unquoted",
    "script_string",
    "script_code",
    "comment",
    "url_attribute",
    "json_body",
)
# When a page reflects in more contexts than the request bound allows, these go first.
PRIORITY = (
    "html_text",
    "attribute_quoted",
    "attribute_unquoted",
    "script_string",
    "url_attribute",
    "script_code",
    "comment",
)

# One probe string per context. ``{marker}`` is a fresh marker; ``{variant}`` is
# the quote character of the context, or the raw-text element the text sits in.
# The script strings try both ways out of a script: ending the string literal
# or statement, and ending the whole block with its end tag.
PAYLOADS: dict[str, str] = {
    "html_text": "<{marker}x>",
    "html_text_in_element": "</{variant}><{marker}x>",
    "attribute_quoted": "{variant}{marker}=x",
    "attribute_unquoted": "x {marker}=x",
    "script_string": "{variant};{marker}//</script><{marker}x>",
    "script_code": ";{marker}//</script><{marker}x>",
    "url_attribute": "javascript:{marker}",
    "comment": "--><{marker}x>",
}

# Elements whose content a browser does not parse as markup: only the matching
# end tag gets out of them.
RAW_TEXT_ELEMENTS = (
    "script",
    "style",
    "textarea",
    "title",
    "xmp",
    "iframe",
    "noembed",
    "noframes",
    "noscript",
)
# (element, attribute) pairs where a ``javascript:`` URL, or a URL the attacker
# chooses outright, runs script.
URL_SINKS = frozenset(
    {
        ("a", "href"),
        ("area", "href"),
        ("base", "href"),
        ("iframe", "src"),
        ("frame", "src"),
        ("embed", "src"),
        ("script", "src"),
        ("object", "data"),
        ("form", "action"),
        ("button", "formaction"),
        ("input", "formaction"),
    }
)

CONTROL = (
    "baseline: the same request with a marker that has no markup characters is reflected "
    "inert; each proof names an element or attribute after a marker sent in that request only"
)
REMEDIATION = (
    "Apply contextual output encoding where the value is written into the response (an "
    "auto-escaping template engine does this for HTML text and quoted attributes)."
)
REMEDIATION_NOTE = (
    " A Content-Security-Policy limits what an injection can do; it does not remove the flaw."
)
FIXES: dict[str, str] = {
    "html_text": (
        "html_text: HTML-entity-encode the value (& < > \" ') before writing it into element "
        "content"
    ),
    "attribute_quoted": (
        "attribute_quoted: HTML-attribute-encode the value (at least & < \" ') and keep the "
        "attribute quoted"
    ),
    "attribute_unquoted": (
        "attribute_unquoted: put the attribute value in quotes and HTML-attribute-encode it; "
        "an unquoted value ends at the first space"
    ),
    "script_string": (
        "script_string: do not build script source from request data; hand the value over as "
        "JSON in a data attribute or a JSON block, or escape every non-alphanumeric character "
        "as \\uXXXX"
    ),
    "script_code": (
        "script_code: never write request data into script source as code; accept a strict "
        "allow-list (for example an integer) or move the value into a data attribute"
    ),
    "url_attribute": (
        "url_attribute: accept only http(s) or relative URLs (reject javascript: and data:), "
        "then HTML-attribute-encode the value"
    ),
    "comment": (
        "comment: do not echo request data into an HTML comment; if it must stay, "
        "HTML-entity-encode it so that --> cannot end the comment"
    ),
    "json_body": (
        "json_body: keep the JSON Content-Type and X-Content-Type-Options: nosniff, and "
        "encode the value where a page later writes it into the DOM"
    ),
}

_QUOTE_NAMES = {'"': "double", "'": "single", "`": "backtick"}
_WHITESPACE = "\t\n\r\f "
_JSON_TYPE = re.compile(r"(?:^|/|\+)(?:x-)?json$")
_HTML_TYPES = ("text/html", "application/xhtml+xml")
_JS_TYPE = re.compile(r"(?:text|application)/(?:x-)?(?:java|ecma|j|live)script[\d.]*")
# Attribute syntax as the HTML tokenizer reads it; used to learn how a value is quoted.
_ATTRIBUTE = re.compile(
    r"""(?<=['"\t\n\r\f /])([^\t\n\r\f />][^\t\n\r\f /=>]*)"""
    r"""(?:[\t\n\r\f ]*=[\t\n\r\f ]*(?:(')[^']*'|(")[^"]*"|(?!['"])[^>\t\n\r\f ]*))?"""
)
_TAG_NAME = re.compile(r"<[^\t\n\r\f />]*")
# A "/" after one of these (or at the start) opens a regular expression, not a division.
_REGEX_AFTER = "(,=:[!&|?{};+-*%<>~^"
_JS_QUOTES = ("'", '"', "`")


# ── tokenizing ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Token:
    """One piece of a tokenized document."""

    kind: str  # start | end | text | comment
    name: str = ""  # tag name; for text, the raw-text element around it ("" for none)
    data: str = ""  # text or comment content; the source of a start tag
    attrs: tuple[tuple[str, str | None], ...] = ()
    executable: bool = False  # text of a <script> that a browser runs as JavaScript


class _Tokenizer(HTMLParser):
    """``html.parser`` with the raw-text rules a scripting browser applies."""

    # Releases before the parser learned the full list know only script and style.
    CDATA_CONTENT_ELEMENTS = tuple(
        dict.fromkeys(
            (
                *HTMLParser.CDATA_CONTENT_ELEMENTS,
                "xmp",
                "iframe",
                "noembed",
                "noframes",
                "noscript",
                *(() if hasattr(HTMLParser, "RCDATA_CONTENT_ELEMENTS") else ("textarea", "title")),
            )
        )
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tokens: list[_Token] = []
        self._text: list[str] = []
        self._around = ""
        self._script_runs = False

    def _flush(self) -> None:
        if self._text:
            data = "".join(self._text)
            runs = self._around == "script" and self._script_runs
            self.tokens.append(_Token("text", self._around, data, executable=runs))
            self._text = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._flush()
        if tag == "script":
            kind = next((value or "" for name, value in attrs if name == "type"), "")
            kind = kind.strip().lower()
            self._script_runs = kind in ("", "module") or _JS_TYPE.fullmatch(kind) is not None
        self.tokens.append(_Token("start", tag, self.get_starttag_text() or "", tuple(attrs)))

    def handle_endtag(self, tag: str) -> None:
        self._flush()
        self.tokens.append(_Token("end", tag))

    def handle_data(self, data: str) -> None:
        around = getattr(self, "cdata_elem", None) or ""
        if around != self._around:
            self._flush()
            self._around = around
        self._text.append(data)

    def handle_comment(self, data: str) -> None:
        self._flush()
        self.tokens.append(_Token("comment", data=data))

    # Declarations and processing instructions are inert markup that ends at ">",
    # like a comment that was not closed properly.
    handle_decl = handle_comment
    handle_pi = handle_comment
    unknown_decl = handle_comment

    def close(self) -> None:
        super().close()
        self._flush()


def tokenize(document: str) -> list[_Token]:
    """The tokens of an HTML document, in order."""
    parser = _Tokenizer()
    parser.feed(document[:BODY_LIMIT])
    parser.close()
    return parser.tokens


def _attribute_quotes(source: str) -> list[tuple[str, str]]:
    """``(name, quote)`` of every attribute in a start tag's source ("" for unquoted)."""
    head = _TAG_NAME.match(source)
    matches = _ATTRIBUTE.finditer(source, head.end() if head else 0)
    return [(m.group(1).lower(), m.group(2) or m.group(3) or "") for m in matches]


def _js_spans(source: str) -> tuple[list[int], list[str]]:
    """Where each lexical state of a script starts: code, a quote character, a comment, regex."""
    starts, states = [0], ["code"]
    state, last, in_class = "code", "", False
    index, end = 0, len(source)

    def switch(to: str, at: int) -> str:
        starts.append(at)
        states.append(to)
        return to

    while index < end:
        char = source[index]
        if state == "code":
            if char in _JS_QUOTES:
                state = switch(char, index)
            elif source.startswith("//", index):
                state = switch("line_comment", index)
                index += 1
            elif source.startswith("/*", index):
                state = switch("block_comment", index)
                index += 1
            elif char == "/" and (not last or last in _REGEX_AFTER):
                state, in_class = switch("regex", index), False
            elif not char.isspace():
                last = char
        elif state in _JS_QUOTES:
            if char == "\\":
                index += 1
            elif char == state or (char in "\r\n" and state != "`"):
                state, last = switch("code", index + 1), '"'
        elif state == "line_comment":
            if char in "\r\n  ":
                state = switch("code", index + 1)
        elif state == "block_comment":
            if source.startswith("*/", index):
                index += 1
                state = switch("code", index + 1)
        elif char == "\\":
            index += 1
        elif char in "[]":
            in_class = char == "["
        elif (char == "/" and not in_class) or char in "\r\n":
            state, last = switch("code", index + 1), "/"
        index += 1
    return starts, states


def _script_hits(script: str, marker: str) -> list[tuple[int, str]]:
    """``(index, lexical state)`` of every occurrence of ``marker`` in a script."""
    hits = [match.start() for match in re.finditer(re.escape(marker), script, re.IGNORECASE)]
    if not hits:
        return []
    starts, states = _js_spans(script)
    return [(index, states[bisect_right(starts, index) - 1]) for index in hits]


# ── classifying reflections ──────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Reflection:
    context: str
    variant: str = ""  # the quote character, or the raw-text element around html_text
    where: str = ""
    url_sink: bool = False  # inside an attribute that takes a script-capable URL
    untestable: str = ""  # why no probe string is sent for this reflection

    @property
    def key(self) -> tuple[str, str]:
        return self.context, self.variant


def find_reflections(tokens: list[_Token], marker: str) -> list[_Reflection]:
    """Every place ``marker`` appears in a tokenized document, with its context."""
    marker = marker.lower()
    found: list[_Reflection] = []
    for token in tokens:
        if token.kind == "start":
            found.extend(_in_start_tag(token, marker))
        elif token.kind == "comment":
            if marker in token.data.lower():
                found.append(_Reflection("comment", where="HTML comment or declaration"))
        elif token.kind == "text":
            if token.executable:
                for _index, state in _script_hits(token.data, marker):
                    found.append(_in_script(state))
            elif marker in token.data.lower():
                where = f"text inside <{token.name}>" if token.name else "element content"
                found.append(_Reflection("html_text", token.name, where))
    return found


def _in_script(state: str) -> _Reflection:
    if state in _JS_QUOTES:
        return _Reflection("script_string", state, f"<script> string literal ({state})")
    if state in ("line_comment", "block_comment"):
        return _Reflection(
            "script_code",
            where="<script> comment",
            untestable="inside a JavaScript comment: this probe does not test a comment breakout",
        )
    return _Reflection("script_code", where="<script> code")


def _in_start_tag(token: _Token, marker: str) -> list[_Reflection]:
    found: list[_Reflection] = []
    quotes = _attribute_quotes(token.data)
    aligned = [name for name, _quote in quotes] == [name for name, _value in token.attrs]
    for position, (name, value) in enumerate(token.attrs):
        where = f"<{token.name} {name}>"
        if marker in name:
            found.append(_Reflection("attribute_unquoted", where=f"<{token.name}> attribute name"))
        if value is None or marker not in value.lower():
            continue
        sink = (token.name, name) in URL_SINKS
        if sink and _url_start(value).startswith(marker):
            found.append(_Reflection("url_attribute", where=where, url_sink=True))
        if not aligned:
            found.append(
                _Reflection(
                    "attribute_quoted",
                    where=where,
                    url_sink=sink,
                    untestable="could not determine how the attribute value is quoted",
                )
            )
        elif quotes[position][1]:
            found.append(_Reflection("attribute_quoted", quotes[position][1], where, sink))
        else:
            found.append(_Reflection("attribute_unquoted", where=where, url_sink=sink))
    return found


def _url_start(value: str) -> str:
    """An attribute value as a browser reads a URL from it: leading blanks dropped, lower case."""
    return value.lstrip("".join(chr(code) for code in range(33))).lower()


# ── proving a breakout ───────────────────────────────────────────────


def find_proof(context: str, variant: str, tokens: list[_Token], marker: str) -> str:
    """What in ``tokens`` proves a breakout from the context, or ``""``."""
    marker = marker.lower()
    element = f"{marker}x"
    if context == "html_text" and not variant:
        if any(token.kind == "start" and token.name == element for token in tokens):
            return f"a new <{element}> element was parsed"
        return ""
    if context == "html_text":
        return _element_after(tokens, element, variant)
    if context == "comment":
        return _element_after(tokens, element, "")
    if context in ("attribute_quoted", "attribute_unquoted"):
        for token in tokens:
            if token.kind == "start" and any(name == marker for name, _value in token.attrs):
                return f"a new attribute {marker} was parsed on <{token.name}>"
        return ""
    if context == "url_attribute":
        for token in tokens:
            for name, value in token.attrs if token.kind == "start" else ():
                wanted = f"javascript:{marker}"
                if (token.name, name) in URL_SINKS and _url_start(value or "").startswith(wanted):
                    return f"<{token.name} {name}> now starts with the javascript: scheme"
        return ""
    for token in tokens:
        if token.kind != "text" or not token.executable:
            continue
        for index, state in _script_hits(token.data, marker):
            before, after = token.data[:index], token.data[index + len(marker) :]
            if state != "code":
                continue
            if context == "script_string" and before.endswith(f"{variant};"):
                return f"the {variant} string literal was terminated: {marker} is now script code"
            if context == "script_code" and before.endswith(";") and after.startswith("//"):
                return f"statement syntax (; and //) around {marker} arrived intact in script code"
    return _element_after(tokens, element, "script")


def _element_after(tokens: list[_Token], element: str, closed: str) -> str:
    """Proof that ``<element>`` was parsed right after the reflection's container ended.

    ``closed`` names the raw-text element whose end tag must come just before
    it ("" for a comment). Looking at what precedes the new element keeps a
    second, unencoded reflection elsewhere on the page from being counted here.
    """
    for position, token in enumerate(tokens):
        if token.kind != "start" or token.name != element or not position:
            continue
        before = tokens[position - 1]
        if not closed:
            if before.kind == "comment":
                return f"the comment was closed and a new <{element}> element was parsed"
        elif before.kind == "end" and before.name == closed and position > 1:
            inside = tokens[position - 2]
            if inside.name == closed and inside.kind in ("start", "text"):
                return f"<{closed}> was closed and a new <{element}> element was parsed"
    return ""


def _still_reflected(context: str, variant: str, tokens: list[_Token], marker: str) -> bool:
    """Whether ``marker`` came back in the same context (so its handling was observed)."""
    reflections = find_reflections(tokens, marker)
    if context == "url_attribute":
        return any(reflection.url_sink for reflection in reflections)
    return any(reflection.key == (context, variant) for reflection in reflections)


def payload_for(context: str, variant: str, marker: str) -> str:
    """The fixed probe string of a context, built around ``marker``."""
    template = "html_text_in_element" if context == "html_text" and variant else context
    return PAYLOADS[template].format(marker=marker, variant=variant)


def new_marker() -> str:
    return MARKER_PREFIX + secrets.token_hex(6)


# ── the request side ─────────────────────────────────────────────────


@dataclass(frozen=True)
class _PathTarget(_Target):
    """The value is a path segment: the URL carries a ``{parameter}`` placeholder."""

    def request(self, value: Any) -> tuple[str, str | None]:
        placeholder = "{" + self.parameter + "}"
        return self.url.replace(placeholder, quote(str(value), safe="")), self.raw_body


def _target(params: dict[str, Any]) -> _Target:
    require(params, "url", "parameter")
    prefix = params.get("value")
    if isinstance(prefix, (dict, list)):
        raise ProbeInputError("value must be text: it is sent in front of the marker")
    prefix = "" if prefix is None else str(prefix)
    if str(params.get("location") or "query").lower() != "path":
        return _Target.from_params({**params, "value": prefix})
    url, parameter = str(params["url"]), str(params["parameter"])
    if "{" + parameter + "}" not in url.partition("?")[0]:
        raise ProbeInputError(
            f"location is path: the url path must contain the placeholder {{{parameter}}}"
        )
    body = params.get("body")
    return _PathTarget(
        str(params.get("method") or "GET").upper(),
        url,
        "path",
        parameter,
        headers_of(params.get("headers")),
        None,
        [],
        None if body in (None, "") else _as_text(body),
        prefix,
    )


@dataclass
class _XssRun(_Run):
    """C1's request bookkeeping with this probe's bound and result layout."""

    contexts: list[dict[str, Any]] = field(default_factory=list)

    @property
    def left(self) -> int:
        return MAX_REQUESTS - len(self.evidence)

    def result(self, vulnerable: bool | None, summary: str) -> ProbeResult:
        details: dict[str, Any] = {
            "method": self.target.method,
            "location": self.target.location,
            "parameter": self.target.parameter,
            "requests_sent": len(self.evidence),
            "max_requests": MAX_REQUESTS,
            "captures": dict(self.captures),
            "payloads": dict(self.payloads),
            "contexts": list(self.contexts),
            "control": CONTROL,
            "browser_confirmation": "not_run",
            **self.info,
        }
        named = [c["context"] for c in self.contexts if c["vulnerable"] is True] or [
            c["context"] for c in self.contexts
        ]
        fixes = [FIXES[name] for name in dict.fromkeys(named)]
        remediation = REMEDIATION + (" " + "; ".join(fixes) + "." if fixes else "")
        return ProbeResult(
            PROBE,
            VULN_CLASS,
            CWE,
            vulnerable,
            summary,
            list(self.evidence),
            details,
            remediation + REMEDIATION_NOTE,
        )


def _header(capture: Capture, name: str) -> str:
    for key, value in capture.response_headers.items():
        if key.lower() == name:
            return str(value)
    return ""


def _media_type(capture: Capture) -> str:
    return _header(capture, "content-type").split(";")[0].strip().lower()


def _renders_as_html(capture: Capture) -> bool:
    """HTML, or no declared type at all (which a browser may sniff as HTML)."""
    media_type = _media_type(capture)
    return not media_type or media_type in _HTML_TYPES


def _header_report(capture: Capture) -> dict[str, Any]:
    policy = _header(capture, "content-security-policy")
    report_only = _header(capture, "content-security-policy-report-only")
    return {
        "content_type": _header(capture, "content-type"),
        "x_content_type_options": _header(capture, "x-content-type-options"),
        "csp_present": bool(policy),
        "csp_report_only_present": bool(report_only),
        "content_security_policy": policy[:300],
        "note": "a Content-Security-Policy is reported, it does not change the verdict",
    }


def xss_reflected(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Is one named parameter reflected where markup characters break out of their context?"""
    run = _XssRun(ctx, _target(params))
    try:
        return _examine(run)
    except GatewayRefusal as refusal:
        run.info["refusal"] = refusal.to_dict()
        return run.result(
            None,
            f"the gateway refused a request ({refusal.code}) after {len(run.evidence)} sent; "
            "cannot tell",
        )
    except _BudgetExceeded as exc:
        return run.result(
            None, f"the request bound ({MAX_REQUESTS}) was reached before {exc}; cannot tell"
        )


def _examine(run: _XssRun) -> ProbeResult:
    target = run.target
    parameter = target.parameter

    # 1. The bare marker.
    marker = new_marker()
    baseline = run.send("baseline", target.inject(marker), "baseline (harmless marker)")
    run.info["marker"] = marker
    if baseline.error or baseline.status is None:
        return run.result(
            None, f"the baseline request failed ({_outcome(baseline)}); nothing to analyse"
        )
    body = text(baseline)
    reflected = marker in body.lower()
    run.info["response_headers"] = _header_report(baseline)
    run.info["baseline"] = {"status": baseline.status, "reflected": reflected}
    if not reflected:
        return run.result(
            False, f"not reflected: the value of {parameter!r} does not appear in the response body"
        )

    # 2. Where is it reflected?
    media_type = _media_type(baseline)
    if _JSON_TYPE.search(media_type):
        reason = (
            f"reflected inside a JSON response (Content-Type {media_type}): a browser does not "
            "render JSON as HTML, so markup in the value is not parsed"
        )
        run.contexts.append(
            {
                "context": "json_body",
                "reflections": body.lower().count(marker),
                "probe": None,
                "vulnerable": False,
                "reason": reason,
            }
        )
        return run.result(
            False,
            f"not exploitable as reflected XSS: {parameter!r} is {reason}. A page that writes "
            "this value into the DOM is a separate (DOM XSS) question",
        )
    if not _renders_as_html(baseline):
        return run.result(
            None,
            f"{parameter!r} is reflected in a {media_type} response; this probe analyses HTML "
            "responses only; cannot tell",
        )
    grouped: dict[tuple[str, str], list[_Reflection]] = {}
    for reflection in find_reflections(tokenize(body), marker):
        grouped.setdefault(reflection.key, []).append(reflection)
    run.info["baseline"]["reflections"] = sum(len(group) for group in grouped.values())
    if not grouped:
        return run.result(
            None,
            f"{parameter!r} is reflected in the HTML response, but not in a place this probe "
            "classifies (for example a tag name); cannot tell",
        )

    # 3. One probe string per distinct context.
    ordered = sorted(grouped, key=lambda key: (PRIORITY.index(key[0]), bool(key[1])))
    for context, variant in ordered:
        group = grouped[(context, variant)]
        entry: dict[str, Any] = {
            "context": context,
            "where": list(dict.fromkeys(reflection.where for reflection in group))[:3],
            "reflections": len(group),
            "probe": None,
            "vulnerable": None,
        }
        if context in ("attribute_quoted", "script_string") and variant:
            entry["quote"] = variant
        elif variant:
            entry["element"] = variant
        run.contexts.append(entry)
        testable = [reflection for reflection in group if not reflection.untestable]
        if not testable:
            entry["reason"] = f"not tested: {group[0].untestable}"
        elif run.left <= 0:
            entry["reason"] = f"not tested: the request bound ({MAX_REQUESTS}) was reached"
        else:
            _probe_context(run, entry, context, variant, baseline)

    proven = [entry for entry in run.contexts if entry["vulnerable"] is True]
    if proven:
        listed = "; ".join(f"{entry['context']} ({entry['reason']})" for entry in proven)
        return run.result(
            True,
            f"{parameter!r} is reflected with its markup characters unencoded in "
            f"{len(proven)} context(s): {listed}",
        )
    unknown = [entry for entry in run.contexts if entry["vulnerable"] is None]
    if unknown:
        listed = "; ".join(f"{entry['context']}: {entry['reason']}" for entry in unknown)
        return run.result(None, f"cannot tell: {listed}")
    names = ", ".join(dict.fromkeys(entry["context"] for entry in run.contexts))
    return run.result(
        False,
        f"{parameter!r} is reflected ({names}) but the breaking characters of each context "
        "came back encoded or removed",
    )


def _probe_context(
    run: _XssRun, entry: dict[str, Any], context: str, variant: str, baseline: Capture
) -> None:
    """Send the context's probe string and record the verdict in ``entry``."""
    marker = new_marker()
    payload = payload_for(context, variant, marker)
    role = "_".join(part for part in ("probe", context, _QUOTE_NAMES.get(variant, variant)) if part)
    capture = run.send(role, run.target.inject(payload), f"{context} probe string")
    entry.update({"probe": role, "capture": capture.id, "payload": payload, "marker": marker})
    entry["status"] = capture.status
    if capture.error or capture.status is None:
        entry["reason"] = f"the probe request got no answer ({_outcome(capture)})"
        return
    tokens = tokenize(text(capture)) if _renders_as_html(capture) else []
    proof = find_proof(context, variant, tokens, marker)
    if proof:
        entry["vulnerable"], entry["reason"] = True, proof
    elif _still_reflected(context, variant, tokens, marker):
        entry["vulnerable"] = False
        entry["reason"] = "reflected in the same context with the breaking characters neutralised"
    else:
        entry["reason"] = (
            f"the probe string was not reflected in this context (HTTP {capture.status}; the "
            f"baseline was HTTP {baseline.status}): the page is unstable, or it drops or "
            "blocks the value"
        )


__all__ = [
    "CONTEXTS",
    "MAX_REQUESTS",
    "PAYLOADS",
    "find_proof",
    "find_reflections",
    "new_marker",
    "payload_for",
    "tokenize",
    "xss_reflected",
]
