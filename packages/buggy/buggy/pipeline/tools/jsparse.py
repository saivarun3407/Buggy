"""Endpoint extraction and static analysis of JavaScript (built in; no binary).

Pulls quoted paths and URLs out of a script's text. It is a string scan, not
an interpreter: it finds routes that appear as literals (which is most of
what a bundled SPA contains) and nothing that is assembled at run time.

Three more extractions read the same text, also without executing or fully
parsing it:

* :func:`source_maps`: the ``sourceMappingURL`` targets the file names;
* :func:`dom_sinks`: a fixed list of DOM-XSS sinks, found in code only
  (comments and string contents are masked first);
* :func:`package_names`: npm package names from ``node_modules/<name>/``
  paths, which is where webpack's module comments and module ids put them.

Every scan is a bounded set of linear regular-expression passes over text no
longer than :data:`MAX_ANALYSIS_BYTES` (the caller skips larger files), under
a wall-clock budget. A snippet that looks like it carries a credential is
stored redacted.
"""

from __future__ import annotations

import re
import time
from bisect import bisect_right
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from buggy.pipeline.schema import Record, RecordType, host_of, normalize_url
from buggy.pipeline.tools.params import REDACTED

NAME = "jsparse"

# A quoted literal that is an absolute URL or a rooted / dotted relative path.
_LITERAL = re.compile(
    r"""(?P<q>["'`])(?P<v>
        (?:https?:)?//[A-Za-z0-9.\-_~:@]+(?:/[^\s"'`<>\\{}|^]*)?   # absolute or scheme-relative
      | /(?!/)[A-Za-z0-9_\-.~%!$&()*+,;=:@/]{1,300}(?:\?[^\s"'`<>\\]{0,200})?   # rooted path
      | \.{1,2}/[A-Za-z0-9_\-.~%/]{1,300}(?:\?[^\s"'`<>\\]{0,200})?            # ./ or ../ path
    )(?P=q)""",
    re.VERBOSE,
)

_STATIC = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|css|map|mp[34]|webm|avi|mov)(?:\?|$)",
    re.IGNORECASE,
)
# Literals that look like paths but are not routes.
_NOISE = re.compile(r"^/(?:[*/]|\s|$)|^/[A-Za-z]$|^/[gimsuy]{1,6}$|[<>{}]|\\")
_MIME = re.compile(
    r"^/?(?:application|text|image|audio|video|font|multipart|message)/[\w.+-]+$", re.IGNORECASE
)


# A template literal that interpolates: `${base}/rest/search?q=${term}`.
_TEMPLATE = re.compile(r"`((?:\\.|[^`\\\n]){3,600})`")
_INTERPOLATION = re.compile(r"\$\{[^{}`]{1,120}\}")
_TEMPLATE_PATH = re.compile(r"^/(?!/)[A-Za-z0-9_\-.~%/]{1,300}$")
_TEMPLATE_QUERY_NAME = re.compile(r"^[A-Za-z0-9_\-.\[\]]{1,100}$")
_MAX_TEMPLATE_PARAMETERS = 20


_SEGMENT_INTERPOLATION = re.compile(r"(?<=/)\$\{[^{}`]{1,120}\}(?=/|$|\?)")
# ``this.host = this.hostServer + "/api/BasketItems"``: a base URL variable and the
# path it adds. A template that starts with ``${this.host}`` builds on that path.
_BASE_ASSIGN = re.compile(
    r"((?:this\.)?[A-Za-z_$][\w$]{0,60})\s*=\s*[A-Za-z_$][\w$.]{0,80}\s*\+\s*"
    r"[\"'](/[A-Za-z0-9_\-./]{1,200})[\"']"
)
#: The placeholder a whole interpolated path segment becomes (``/basket/${e}``).
PLACEHOLDER = "{id}"
# ``http.post(`` / ``axios.put(`` / ``fetch(`` right before a literal: the call that sends it.
_CALL_BEFORE = re.compile(r"\.(get|post|put|patch|delete|head)\s*\(\s*$", re.IGNORECASE)


def _template_path(body: str, base: str = "") -> str | None:
    """The rooted path a template literal builds, or ``None`` when it cannot be told.

    Only what the text states is kept. A leading interpolation is the base URL
    and is dropped (the result resolves against the script's own origin); when
    the script set that variable to a base plus a path (``this.host =
    this.hostServer + "/api/Users"``), ``base`` is that path and is put back. An
    interpolation that is a whole path segment (``/rest/basket/${id}``) becomes
    the placeholder ``{id}``: the path is a template for one object. A query
    value that is interpolated is left empty, so the parameter's name is known
    and no value is invented. Any other interpolation inside the path is
    skipped: its real path is not in the text.
    """
    if "${" not in body:
        return None
    lead = _INTERPOLATION.match(body)
    if lead is not None:
        body = base + body[lead.end() :]
    elif base:
        return None
    head, mark, tail = body.partition("?")
    head = _SEGMENT_INTERPOLATION.sub(PLACEHOLDER, head)
    body = head + mark + tail
    if not body.startswith("/"):
        return None
    path, question, query = body.partition("?")
    if "${" in path or not _TEMPLATE_PATH.match(path.replace(PLACEHOLDER, "id")):
        return None
    if not question:
        return path
    pairs: list[str] = []
    for part in query.split("&")[:_MAX_TEMPLATE_PARAMETERS]:
        name, _, value = part.partition("=")
        if not _TEMPLATE_QUERY_NAME.match(name):
            return None
        value = "" if "${" in value else value
        if not re.fullmatch(r"[A-Za-z0-9_\-.~%+,:@/]{0,200}", value):
            return None
        pairs.append(f"{name}={value}")
    return f"{path}?{'&'.join(pairs)}" if pairs else path


def call_methods(script: str) -> dict[str, str]:
    """``{literal: METHOD}`` for literals passed straight to ``x.get(`` / ``x.post(`` and the like.

    A literal sent with more than one method keeps the first one seen that is
    not GET, so a path the app also writes to is never taken for a plain read.
    """
    methods: dict[str, str] = {}
    for pattern in (_LITERAL, _TEMPLATE):
        for match in pattern.finditer(script):
            call = _CALL_BEFORE.search(script[max(0, match.start() - 40) : match.start()])
            if call is None:
                continue
            method = call.group(1).upper()
            body = match.group("v") if pattern is _LITERAL else match.group(1)
            values = [body] if pattern is _LITERAL else []
            if pattern is _TEMPLATE:
                lead = _INTERPOLATION.match(body)
                values = [v for v in (_template_path(body),) if v]
                if lead is not None:
                    values += [v for v in _based_paths(script, body, match.start()) if v]
            for value in values:
                if methods.get(value, "GET") == "GET":
                    methods[value] = method
    return methods


def _based_paths(script: str, body: str, at: int) -> list[str]:
    lead = _INTERPOLATION.match(body)
    if lead is None:
        return []
    name = lead.group(0)[2:-1].strip()
    earlier = [m.group(2) for m in _BASE_ASSIGN.finditer(script[:at]) if m.group(1) == name]
    return [p for p in (_template_path(body, earlier[-1]),) if p] if earlier else []


def extract_literals(script: str, *, limit: int = 5000) -> list[str]:
    """Distinct path / URL literals in ``script``, in first-seen order.

    Plain string literals first, then the paths of interpolated template
    literals (:func:`_template_path`).
    """
    found: dict[str, None] = {}

    def keep(value: str) -> bool:
        plain = value.replace(PLACEHOLDER, "id")  # a template's placeholder is not noise
        if _STATIC.search(plain) or _NOISE.search(plain) or _MIME.match(plain):
            return len(found) < limit
        if value.startswith("/") and not value.startswith("//") and len(value) < 3:
            return len(found) < limit
        found.setdefault(value, None)
        return len(found) < limit

    for match in _LITERAL.finditer(script):
        if not keep(match.group("v")):
            return list(found)
    assigned: dict[str, list[tuple[int, str]]] = {}
    for match in _BASE_ASSIGN.finditer(script):
        assigned.setdefault(match.group(1), []).append((match.start(), match.group(2)))
    for match in _TEMPLATE.finditer(script):
        value = _template_path(match.group(1))
        lead = _INTERPOLATION.match(match.group(1))
        if lead is not None:
            name = lead.group(0)[2:-1].strip()
            # The nearest assignment before this use: one script often has many
            # classes, each with its own ``this.host``.
            earlier = [path for at, path in assigned.get(name, []) if at < match.start()]
            if earlier:
                value = _template_path(match.group(1), earlier[-1]) or value
        if value is not None and not keep(value):
            break
    return list(found)


# Client-side routes: ``{path: "/admin"}`` (React Router, Vue Router, Angular),
# ``<Route path="/admin">`` and ``<Link to="/admin">`` (JSX, before or after
# compiling), ``redirectTo: "home"``, ``navigate("/x")``, ``router.push("/x")``.
_ROUTE_VALUE = r"""(?P<q>["'`])(?P<v>[A-Za-z0-9_\-./:*~%]{1,200})(?P=q)"""
_ROUTE_PROPERTY = re.compile(
    r"(?<![\w$.\-])(?P<key>path|to|redirectTo)\s*[:=]\s*\{?\s*" + _ROUTE_VALUE
)
_ROUTE_CALL = re.compile(
    r"(?<![\w$])(?:(?:history|router|\$router|Router)\s*\.\s*(?:push|replace)"
    r"|navigate|navigateByUrl|redirect)\s*\(\s*\[?\s*" + _ROUTE_VALUE
)
_ROUTE_PARAM = re.compile(r"(?<=/):[A-Za-z_][\w]*\??")
MAX_ROUTES = 500


def client_routes(script: str) -> list[str]:
    """Rooted paths the script's client-side router serves, ``:id`` as ``{id}``.

    A relative route (``path: "admin"``, Angular) is rooted (``/admin``); a
    child route's parent is not known, so it may be one level short. Wildcards
    and empty routes are left out.
    """
    found: dict[str, None] = {}
    for pattern in (_ROUTE_PROPERTY, _ROUTE_CALL):
        for match in pattern.finditer(script):
            value = match.group("v")
            if pattern is _ROUTE_PROPERTY and match.group("key") == "to" and value[:1] != "/":
                continue  # ``{from: "en", to: "de"}`` is not a link
            if "//" in value or value.startswith(("./", "../", ".")) or "*" in value.strip("/*"):
                continue
            value = value.rstrip("*").rstrip("/") if value not in ("/",) else value
            if not value or value == "/" or value.endswith((".js", ".css", ".html", ".json")):
                continue
            route = "/" + value.lstrip("/")
            route = _ROUTE_PARAM.sub(PLACEHOLDER, route)
            if len(route) >= 3 and not _NOISE.search(route.replace(PLACEHOLDER, "id")):
                found.setdefault(route, None)
            if len(found) >= MAX_ROUTES:
                return list(found)
    return list(found)


def parse(script: str, *, js_url: str) -> Iterator[Record]:
    """Endpoint records for every literal, resolved against the script's URL.

    ``attrs.method`` is set when the literal is passed straight to a call that
    names its method (``http.post(...)``). A path the script's router serves
    carries ``attrs.client_route``; a route that is not a plain literal
    (``path: "admin"``, ``/users/:id``) gets a record of its own.
    """
    methods = call_methods(script)
    routes = client_routes(script)
    route_set = set(routes)
    seen: set[str] = set()
    for literal in [*extract_literals(script), *routes]:
        resolved = urljoin(js_url, literal)
        if urlsplit(resolved).scheme not in ("http", "https"):
            continue
        url = normalize_url(resolved)
        asset = host_of(url)
        if not asset or url in seen:
            continue
        seen.add(url)
        yield Record(
            type=RecordType.ENDPOINT,
            asset=asset,
            value=url,
            source_tool=NAME,
            attrs={
                "found_in": js_url,
                "literal": literal[:300],
                **({"method": methods[literal]} if literal in methods else {}),
                **({"client_route": True} if literal in route_set else {}),
            },
        )


# ── scripts a script loads: lazy chunks and imports ───────────────────

#: Scripts named per script (chunks and imports together).
MAX_SCRIPT_REFERENCES = 300
_JS_SUFFIX = re.compile(r"""\+\s*(["'])[^"'\\\n]{0,80}\.m?js\1""")
_MAP_PAIR = re.compile(
    r"""(?:(["'])([^"'\\]{1,80})\1|([\w$]{1,80}))\s*:\s*(["'])([^"'\\]{0,200})\4"""
)
_PUBLIC_PATH = re.compile(r"""(?<![\w$])[\w$]{1,40}\.p\s*=\s*(["'])([^"'\\\n]{0,300})\1""")
_SCRIPT_LITERAL = re.compile(r"""(["'`])((?:\.{1,2}/|/)?[\w\-.~/@]{1,250}\.m?js)\1""")
_IDENT_END = re.compile(r"[\w$.]")


def _term_before(text: str, end: int) -> tuple[int, tuple[str, Any]] | None:
    """The concatenation term that ends at ``end`` (exclusive), read right to left:
    ``("str", value)``, ``("map", ({id: value}, var))``, ``("fallback", (map, var))``
    or ``("var", name)``; ``None`` when it is none of those."""
    i = end - 1
    while i >= 0 and text[i].isspace():
        i -= 1
    if i < 0:
        return None
    char = text[i]
    if char in "\"'":
        start = text.rfind(char, max(0, i - 400), i)
        return (start, ("str", text[start + 1 : i])) if start >= 0 else None
    if char == "]":
        open_index = text.rfind("[", max(0, i - 80), i)
        var = text[open_index + 1 : i].strip() if open_index >= 0 else ""
        if not var or not re.fullmatch(r"[\w$]+", var) or text[open_index - 1] != "}":
            return None
        depth, j = 0, open_index - 1
        floor = max(0, j - 400_000)
        while j >= floor:
            if text[j] == "}":
                depth += 1
            elif text[j] == "{":
                depth -= 1
                if depth == 0:
                    break
            j -= 1
        if depth != 0:
            return None
        pairs = {
            (m.group(2) or m.group(3)): m.group(5)
            for m in _MAP_PAIR.finditer(text[j + 1 : open_index - 1])
        }
        return j, ("map", (pairs, var))
    if char == ")":
        inner_end = i
        match = re.search(r"\|\|\s*([\w$]+)\s*$", text[max(0, i - 80) : inner_end])
        if match is None:
            return None
        term = _term_before(text, inner_end - len(match.group(0)))
        if term is None or term[1][0] != "map":
            return None
        start = term[0] - 1
        while start >= 0 and text[start].isspace():
            start -= 1
        if start < 0 or text[start] != "(":
            return None
        return start, ("fallback", term[1][1])
    if _IDENT_END.match(char):
        j = i
        while j >= 0 and _IDENT_END.match(text[j]):
            j -= 1
        name = text[j + 1 : i + 1]
        if name in ("return", "typeof", "void") or name[0].isdigit():
            return None
        return j + 1, ("var", name)
    return None


def _chunk_names(script: str) -> list[tuple[str, bool]]:
    """``(file name, uses the public path)`` of every chunk a webpack-style runtime
    can load: ``"static/js/" + ({57: "admin"}[e] || e) + "." + {57: "a1b2"}[e] +
    ".chunk.js"`` gives one name per chunk id. Nothing is run."""
    out: list[tuple[str, bool]] = []
    for suffix in _JS_SUFFIX.finditer(script):
        terms: list[tuple[str, Any]] = [("str", suffix.group(0).split(suffix.group(1), 1)[1][:-1])]
        pos = suffix.start()
        for _ in range(10):
            term = _term_before(script, pos)
            if term is None:
                break
            terms.insert(0, term[1])
            pos = term[0]
            k = pos - 1
            while k >= 0 and script[k].isspace():
                k -= 1
            if k < 0 or script[k] != "+":
                break
            pos = k
        maps = [t[1] for t in terms if t[0] in ("map", "fallback")]
        if not maps:
            continue
        var = maps[-1][1]
        ids = list(dict.fromkeys(key for pairs, _v in maps for key in pairs))
        public = False
        for chunk_id in ids[:MAX_SCRIPT_REFERENCES]:
            parts: list[str] = []
            for kind, value in terms:
                if kind == "str":
                    parts.append(value)
                elif kind == "map":
                    if chunk_id not in value[0]:
                        break
                    parts.append(value[0][chunk_id])
                elif kind == "fallback":
                    parts.append(value[0].get(chunk_id) or chunk_id)
                elif value == var:
                    parts.append(chunk_id)
                elif value.endswith(".p"):
                    public = True  # the runtime's public path
                else:
                    break
            else:
                out.append(("".join(parts), public))
    return out


def script_references(script: str, *, js_url: str) -> list[str]:
    """Absolute URLs of the scripts ``script`` loads: lazy chunks whose names the
    runtime computes (webpack and similar), ``import("./x.js")``, Vite's
    preload lists (``"assets/x-1a2b.js"``). At most :data:`MAX_SCRIPT_REFERENCES`.
    """
    parts = urlsplit(js_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    public = _PUBLIC_PATH.search(script)
    public_path = public.group(2) if public and public.group(2) not in ("", "auto") else "/"
    if not public_path.startswith(("/", "http://", "https://")):
        public_path = "/" + public_path
    base = urljoin(origin + "/", public_path)
    if not base.endswith("/"):
        base += "/"
    found: dict[str, None] = {}

    def add(url: str) -> None:
        if urlsplit(url).scheme in ("http", "https") and len(found) < MAX_SCRIPT_REFERENCES:
            found.setdefault(normalize_url(url), None)

    for name, _public in _chunk_names(script):
        if name.startswith(("http://", "https://", "/")):
            add(urljoin(base, name))
        elif "/" in name or public:
            add(urljoin(base, name))
        else:
            add(urljoin(js_url, name))  # no folder and no public path: next to the script
    for match in _SCRIPT_LITERAL.finditer(script):
        value = match.group(2)
        if value.startswith(("./", "../")):
            add(urljoin(js_url, value))
        elif value.startswith("/"):
            add(origin + value)
        elif "/" in value:
            add(urljoin(base, value))
    return [url for url in found if url != normalize_url(js_url)]


# ── deeper analysis: source maps, DOM sinks, dependency names ─────────

#: Files larger than this are not analysed (the pipeline stamps them partial).
MAX_ANALYSIS_BYTES = 2 * 1024 * 1024
#: Wall-clock budget of one :func:`analyze` call.
TIME_BUDGET_S = 5.0
MAX_SOURCE_MAPS = 5
MAX_SINKS = 200
MAX_PACKAGES = 200
MAX_SNIPPET = 160
#: Source-map ``sources`` names kept on the record.
MAX_SOURCES_SAMPLE = 20
#: How far after ``addEventListener("message"`` an origin check is looked for.
ORIGIN_CHECK_WINDOW = 300
#: How far a call's argument list is followed (``postMessage``).
MAX_ARGS_SPAN = 500

_SOURCE_MAP = re.compile(
    r"(?:^[ \t]*//[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(?P<line>[^\s*]{1,2048})"
    r"|/\*[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(?P<block>[^\s*]{1,2048})[ \t]*\*/)",
    re.MULTILINE,
)

# One token of the masking pass. Comments and strings always match once they
# start (an unterminated one runs to the end of the file or line), and a regex
# literal is at most 200 characters, so the scan never re-reads the file.
_TOKEN = re.compile(
    r"""(?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
      | (?P<string>"(?:\\.|[^"\\\n])*"?|'(?:\\.|[^'\\\n])*'?|`(?:\\.|[^`\\])*`?)
      | (?P<regex>(?<=[(,=:\[!&|?{};])[ \t]*/(?![/*])
            (?:\\.|\[(?:\\.|[^\]\\\n]){0,100}\]|[^/\\\n\[]){1,200}/[a-z]{0,6})""",
    re.VERBOSE | re.DOTALL,
)
_NOT_NEWLINE = re.compile(r"[^\n]")

# (sink name, pattern). Matched on the comment-masked text; a match that
# starts inside a string literal is ignored.
_SINKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*\+?=(?!=)")),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*\+?=(?!=)")),
    ("document.write", re.compile(r"(?<![\w$.])document\s*\.\s*write(?:ln)?\s*\(")),
    ("insertAdjacentHTML", re.compile(r"\.\s*insertAdjacentHTML\s*\(")),
    ("eval", re.compile(r"(?<![\w$])eval\s*\(")),
    ("new-Function", re.compile(r"(?<![\w$.])new\s+Function\s*\(")),
    ("setTimeout-string", re.compile(r"(?<![\w$])setTimeout\s*\(\s*[\"'`]")),
    (
        "location-assign",
        re.compile(
            r"(?:(?<![\w$.])(?:window|document|self|top|parent)\s*\.\s*|(?<![\w$.]))"
            r"location(?:\s*\.\s*href)?\s*=(?!=)"
        ),
    ),
    ("postMessage-wildcard", re.compile(r"\.\s*postMessage\s*\(")),
    (
        "message-listener-no-origin-check",
        re.compile(r"(?<![\w$])addEventListener\s*\(\s*([\"'`])message\1"),
    ),
)
_STAR_ARG = re.compile(r"([\"'`])\*\1")
_ORIGIN_CHECK = re.compile(r"\.\s*origin\b|\[\s*[\"']origin[\"']\s*\]")
_LITERAL_END = frozenset(";,)}\n")

_PACKAGE = re.compile(
    r"node_modules[/\\]+(?P<name>(?:@[A-Za-z0-9][\w.~-]{0,100}[/\\]+)?[A-Za-z0-9][\w.~-]{0,213})"
    r"(?=[/\\\"'`\s*!:)]|$)"
)
_FILE_NAME = re.compile(r"\.(?:[cm]?js|jsx|tsx?|json|css|map)$", re.IGNORECASE)
#: Scopes of widely used public packages. A scoped name outside this list may
#: be an internal package: a dependency-confusion candidate to check by hand
#: against the public registry (the pipeline never queries it).
PUBLIC_SCOPES = frozenset(
    {
        "@algolia", "@amplitude", "@angular", "@ant-design", "@apollo", "@auth0", "@aws-amplify",
        "@aws-sdk", "@azure", "@babel", "@capacitor", "@codemirror", "@datadog", "@emotion",
        "@firebase", "@floating-ui", "@formatjs", "@fortawesome", "@google-cloud", "@grpc",
        "@headlessui", "@heroicons", "@hookform", "@ionic", "@jridgewell", "@lit", "@mapbox",
        "@material", "@material-ui", "@microsoft", "@mui", "@nestjs", "@next", "@ngrx",
        "@ngx-translate", "@nuxt", "@octokit", "@okta", "@opentelemetry", "@popperjs",
        "@protobufjs", "@radix-ui", "@react-aria", "@react-native", "@react-spring",
        "@reduxjs", "@remix-run", "@segment", "@sentry", "@stripe", "@supabase", "@sveltejs",
        "@swc", "@tanstack", "@tiptap", "@types", "@vercel", "@vue", "@vueuse", "@webcomponents",
        "@zxing",
    }
)  # fmt: skip

# What a credential looks like inside a snippet. Same intent as the parameter
# rule in ``params.py``: losing a snippet's detail costs nothing, storing a
# credential does.
_SECRET_ASSIGN = re.compile(
    r"""(?P<name>[\w$-]*(?:token|jwt|secret|passw|pwd|api_?key|sessid|session|signature|credential|auth)
            [\w$-]*["']?\s*[:=]\s*)
        (?P<q>["'`])[^"'`\n]{1,500}(?P=q)""",
    re.IGNORECASE | re.VERBOSE,
)
_SECRET_JWT = re.compile(r"eyJ[\w-]{4,}\.[\w-]{4,}\.[\w-]*")
#: A long run of key characters, wherever it stands (quoted or inside a
#: longer string). Path segments are not runs: ``/`` and ``.`` end one.
_SECRET_RUN = re.compile(r"(?<![\w+=/.-])[A-Za-z0-9_+=-]{20,500}(?![\w+=-])")
_DIGIT = re.compile(r"[0-9]")
_LETTER = re.compile(r"[A-Za-z]")


def _secret_run(match: re.Match[str]) -> str:
    """A long run that mixes letters and digits is treated as a credential."""
    value = match.group(0)
    if len(_DIGIT.findall(value)) >= 2 and len(_LETTER.findall(value)) >= 2:
        return REDACTED
    return value


def redact(text: str) -> str:
    """``text`` with anything credential-shaped replaced by ``<redacted>``."""
    text = _SECRET_JWT.sub(REDACTED, text)
    text = _SECRET_ASSIGN.sub(
        lambda m: f"{m.group('name')}{m.group('q')}{REDACTED}{m.group('q')}", text
    )
    return _SECRET_RUN.sub(_secret_run, text)


def source_maps(text: str, js_url: str) -> list[str]:
    """``sourceMappingURL`` targets of ``text`` resolved against ``js_url``.

    ``data:`` URIs (inline maps) and anything that is not http(s) are ignored.
    """
    found: dict[str, None] = {}
    for match in _SOURCE_MAP.finditer(text):
        target = (match.group("line") or match.group("block") or "").strip()
        if not target or target.lower().startswith("data:"):
            continue
        resolved = urljoin(js_url, target)
        if urlsplit(resolved).scheme not in ("http", "https") or not host_of(resolved):
            continue
        found.setdefault(normalize_url(resolved), None)
        if len(found) >= MAX_SOURCE_MAPS:
            break
    return list(found)


def _masks(text: str) -> tuple[str, str]:
    """``(code, bare)``: ``text`` with comments blanked, and with string and
    regex-literal contents blanked too. Both keep every offset and newline."""
    code: list[str] = []
    bare: list[str] = []
    last = 0
    for match in _TOKEN.finditer(text):
        start, end = match.span()
        between = text[last:start]
        code.append(between)
        bare.append(between)
        token = match.group(0)
        if match.group("comment") is not None:
            blank = _NOT_NEWLINE.sub(" ", token)
            code.append(blank)
            bare.append(blank)
        elif match.group("string") is not None:
            code.append(token)
            closed = len(token) >= 2 and token[-1] == token[0]
            inner = token[1:-1] if closed else token[1:]
            bare.append(token[0] + _NOT_NEWLINE.sub(" ", inner) + (token[-1] if closed else ""))
        else:
            code.append(token)
            bare.append(_NOT_NEWLINE.sub(" ", token))
        last = end
    code.append(text[last:])
    bare.append(text[last:])
    return "".join(code), "".join(bare)


def masked(text: str) -> tuple[str, str]:
    """``(code, bare)``: ``text`` with comments blanked, and also string contents blanked."""
    return _masks(text)


def _args_end(bare: str, open_paren: int) -> int:
    """Offset of the ``)`` closing the call whose ``(`` is at ``open_paren``."""
    depth = 0
    stop = min(len(bare), open_paren + MAX_ARGS_SPAN)
    for index in range(open_paren, stop):
        char = bare[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return index
    return stop


def _assigns_literal(bare: str, pos: int) -> bool:
    """Whether the right-hand side starting at ``pos`` is one plain string literal."""
    while pos < len(bare) and bare[pos] in " \t":
        pos += 1
    if pos >= len(bare) or bare[pos] not in "\"'`":
        return False
    close = bare.find(bare[pos], pos + 1)
    if close < 0:
        return False
    after = close + 1
    while after < len(bare) and bare[after] in " \t":
        after += 1
    return after >= len(bare) or bare[after] in _LITERAL_END


def _snippet(text: str, start: int, end: int, line_starts: list[int]) -> str:
    """The source line of a hit, cut to a window around it when it is long."""
    line_start = line_starts[bisect_right(line_starts, start) - 1]
    line_end = text.find("\n", start)
    line_end = len(text) if line_end < 0 else line_end
    if line_end - line_start <= MAX_SNIPPET:
        piece = text[line_start:line_end]
    else:
        lead = max(line_start, start - 60)
        piece = text[lead : min(line_end, max(end, lead + MAX_SNIPPET))]
    return redact(piece.strip())[:MAX_SNIPPET]


def dom_sinks(text: str, *, deadline: float | None = None) -> list[dict[str, Any]]:
    """DOM-XSS sinks in the code of ``text``: ``{sink, line, snippet}``, one per
    sink and line, in source order. Nothing in a comment or a string counts."""
    code, bare = _masks(text)
    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
    hits: dict[tuple[str, int], dict[str, Any]] = {}
    for sink, pattern in _SINKS:
        if len(hits) >= MAX_SINKS or (deadline is not None and time.monotonic() > deadline):
            break
        for match in pattern.finditer(code):
            start, end = match.span()
            if bare[start] == " ":  # starts inside a string literal
                continue
            if sink == "location-assign" and _assigns_literal(bare, end):
                continue
            if sink == "postMessage-wildcard" and not _STAR_ARG.search(
                code, end, _args_end(bare, end - 1) + 1
            ):
                continue
            if sink == "message-listener-no-origin-check" and _ORIGIN_CHECK.search(
                code, end, end + ORIGIN_CHECK_WINDOW
            ):
                continue
            line = bisect_right(line_starts, start)
            if (sink, line) not in hits:
                hits[(sink, line)] = {
                    "sink": sink,
                    "line": line,
                    "snippet": _snippet(text, start, end, line_starts),
                    "_at": start,
                }
                if len(hits) >= MAX_SINKS:
                    break
    ordered = sorted(hits.values(), key=lambda hit: (hit["_at"], hit["sink"]))
    return [{"sink": h["sink"], "line": h["line"], "snippet": h["snippet"]} for h in ordered]


def package_names(text: str) -> list[str]:
    """npm package names (``name`` or ``@scope/name``) from ``node_modules/`` paths."""
    found: dict[str, None] = {}
    for match in _PACKAGE.finditer(text):
        name = re.sub(r"[/\\]+", "/", match.group("name"))
        if _FILE_NAME.search(name):  # a file directly under node_modules, not a package
            continue
        found.setdefault(name, None)
        if len(found) >= MAX_PACKAGES:
            break
    return list(found)


def looks_private(name: str) -> bool:
    """A scoped package whose scope is not a well-known public one."""
    if not name.startswith("@") or "/" not in name:
        return False
    return name.split("/", 1)[0].lower() not in PUBLIC_SCOPES


@dataclass(slots=True)
class Analysis:
    """What :func:`analyze` found in one file; ``partial`` names a limit it hit."""

    source_maps: list[str] = field(default_factory=list)
    findings: list[Record] = field(default_factory=list)
    partial: str = ""


def analyze(
    text: str, *, js_url: str, size: int | None = None, budget_s: float = TIME_BUDGET_S
) -> Analysis:
    """Source maps, DOM sinks and dependency names of one script.

    ``size`` is the file's size in bytes (defaults to the encoded text's). A
    file over :data:`MAX_ANALYSIS_BYTES` is not read at all.
    """
    size = len(text.encode("utf-8", "replace")) if size is None else size
    if size > MAX_ANALYSIS_BYTES:
        return Analysis(
            partial=f"script over {MAX_ANALYSIS_BYTES // (1024 * 1024)} MB not analysed"
        )
    asset = host_of(js_url)
    out = Analysis(source_maps=source_maps(text, js_url))
    if not asset:
        return out
    deadline = time.monotonic() + budget_s
    for hit in dom_sinks(text, deadline=deadline):
        out.findings.append(
            Record(
                type=RecordType.JS_FINDING,
                asset=asset,
                value=f"{js_url}#{hit['sink']}@{hit['line']}",
                source_tool=NAME,
                attrs={"kind": "dom_sink", "found_in": js_url, **hit},
            )
        )
    if time.monotonic() > deadline:
        out.partial = f"script analysis stopped after {budget_s:g} s"
        return out
    for name in package_names(text):
        attrs: dict[str, Any] = {"kind": "dependency", "found_in": js_url, "name": name}
        if looks_private(name):
            attrs["hint"] = "check-public-registry"
        out.findings.append(
            Record(
                type=RecordType.JS_FINDING,
                asset=asset,
                value=f"{js_url}#dependency:{name}",
                source_tool=NAME,
                attrs=attrs,
            )
        )
    return out


def source_map_record(map_url: str, document: Any, *, js_url: str) -> Record | None:
    """A ``js_file`` record for a fetched source map, or ``None`` if it is not one.

    Only the number of sources and the first names are kept, never their content.
    """
    if not isinstance(document, dict) or not isinstance(document.get("sources"), list):
        return None
    asset = host_of(map_url)
    if not asset:
        return None
    sources = document["sources"]
    return Record(
        type=RecordType.JS_FILE,
        asset=asset,
        value=normalize_url(map_url),
        source_tool=NAME,
        attrs={
            "kind": "source_map",
            "found_in": js_url,
            "sources_count": len(sources),
            "sources_sample": [str(name)[:300] for name in sources[:MAX_SOURCES_SAMPLE]],
        },
    )
