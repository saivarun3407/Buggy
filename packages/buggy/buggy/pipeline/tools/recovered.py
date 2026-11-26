"""Recovered source: original files rebuilt from a published source map, scanned statically.

A source map that carries ``sourcesContent`` holds the application's original
files (TypeScript, JSX, ...). :func:`rebuild` writes them under the run's work
directory; :func:`scan` reads each with fixed rules. Nothing is executed or
evaluated: every rule is a bounded regular-expression pass over text.

Rules (``rule`` on each hit):

``dom_sink``     the DOM-XSS sinks of :func:`jsparse.dom_sinks`, on the line
                 of the original file;
``secret``       a key or token of the shared secret patterns
                 (:mod:`secret_patterns`), or a long key-shaped value assigned
                 to a key/secret/token/password name. The value is never kept;
``endpoint``     an API path or URL literal (:func:`jsparse.extract_literals`),
                 or a client-side route (``path: 'admin/users'``);
``client_auth``  a role or permission check in client code (``isAdmin``,
                 ``hasRole(``, ``role === 'admin'``): the server must enforce
                 the same rule, which is worth a live check;
``debug_flag``   a debug or development switch left on (``debug: true``,
                 ``production: false``, ``?debug=1``).

File names come from the map and are untrusted: :func:`safe_relative` keeps
only plain path segments (no ``..``, no absolute path, no drive, no scheme),
and every file is checked to stay inside the destination before it is
written. Third-party code (``node_modules``, the webpack runtime) is skipped.
Each hit is a lead: the pipeline stores it as a ``js_finding`` record
(``kind: recovered_source``) and the report ranks it; it needs a live proof.
"""

from __future__ import annotations

import re
import time
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from buggy.pipeline.schema import Record, RecordType, host_of, normalize_url
from buggy.pipeline.tools import jsparse
from buggy.pipeline.tools.params import REDACTED
from buggy.pipeline.tools.secret_patterns import SECRET_PATTERNS

KIND = "recovered_source"
RULES = ("dom_sink", "secret", "endpoint", "client_auth", "debug_flag")

#: Limits of one source map.
MAX_FILES = 400
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_HITS = 300
MAX_ENDPOINTS_PER_FILE = 60
TIME_BUDGET_S = 10.0
MAX_SEGMENTS = 12
MAX_SEGMENT = 100
MAX_SNIPPET = jsparse.MAX_SNIPPET

_SCHEME = re.compile(r"^[A-Za-z][\w+.-]{0,30}:/*")
_SEGMENT_SAFE = re.compile(r"[^A-Za-z0-9._@+\-]")
_THIRD_PARTY = ("node_modules", "(webpack)", "webpack", "__vite", "vite")
_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html")

_KEY_ASSIGN = re.compile(
    r"""(?P<name>[\w$]*(?:api_?key|apikey|secret|client_?secret|access_?token|auth_?token
            |private_?key|password|passwd)[\w$]*)["']?\s*[:=]\s*
        (?P<q>["'`])(?P<value>[A-Za-z0-9_+/=.\-]{16,300})(?P=q)""",
    re.IGNORECASE | re.VERBOSE,
)
_DIGIT = re.compile(r"[0-9]")
_LETTER = re.compile(r"[A-Za-z]")

# Router paths: ``{path: "/admin"}`` and, in JSX, ``<Route path="/admin">`` and
# ``<Link to="/admin">`` / ``<NavLink to={"/admin"}>``.
_ROUTE = re.compile(
    r"""(?<![\w$.\-])(?P<key>path|to)\s*[:=]\s*\{?\s*(?P<q>["'`])(?P<route>[A-Za-z0-9_\-./:*]{1,200})(?P=q)"""
)
_ROLE_WORDS = r"(?:admin|administrator|superuser|super_admin|root|staff|moderator|owner)"
# Matched where strings are blanked: a name in code, not a word in a message.
_CLIENT_AUTH_NAME = re.compile(
    r"(?<![\w$])(?:isAdmin|is_admin|isSuperUser|isSuperuser|is_superuser|isStaff|is_staff"
    r"|isModerator|hasRole|hasAnyRole|hasPermission|hasAuthority|isAuthorized|canActivate"
    r"|requireAdmin|adminOnly|AdminGuard|RoleGuard)(?![\w$])"
)
# Matched where only comments are blanked: a comparison with a role name in a string.
_CLIENT_AUTH_ROLE = re.compile(
    rf"(?<![\w$])(?:role|roles|userRole|user_role)\s*(?:===?|!==?)\s*[\"'`]{_ROLE_WORDS}[\"'`]"
    rf"|[\"'`]{_ROLE_WORDS}[\"'`]\s*(?:===?|!==?)\s*[\w$.]*role"
    rf"|\.(?:includes|indexOf)\(\s*[\"'`]{_ROLE_WORDS}[\"'`]\s*\)",
    re.IGNORECASE,
)
_DEBUG_FLAG = re.compile(
    r"(?<![\w$])(?:debug|debugMode|debug_mode|isDebug|enableDebug|showDebug|devMode|dev_mode"
    r"|isDev|DEV_MODE|DEBUG_MODE|DEBUG|verbose)\s*[:=]\s*(?:true|!0|1)(?![\w$.])"
    r"|(?<![\w$])production\s*:\s*(?:false|!1)(?![\w$])"
    r"|[?&]debug=(?:true|1)\b"
    r"|localStorage\.getItem\(\s*[\"'`]debug[\"'`]\s*\)"
)


def safe_relative(name: str) -> str | None:
    """A relative path for a source name that cannot leave its directory, or ``None``.

    ``webpack:///./src/app/x.ts`` gives ``src/app/x.ts``. ``..``, ``.`` and empty
    segments are dropped, a scheme and a drive letter are removed, any other
    character outside ``[A-Za-z0-9._@+-]`` becomes ``_``.
    """
    value = _SCHEME.sub("", str(name).strip()).split("?", 1)[0].split("#", 1)[0]
    segments: list[str] = []
    for raw in re.split(r"[/\\]+", value):
        if raw in ("", ".", "..") or re.fullmatch(r"[A-Za-z]:", raw):
            continue
        segment = _SEGMENT_SAFE.sub("_", raw)[:MAX_SEGMENT].strip(".") or "_"
        segments.append(segment)
    if not segments:
        return None
    return "/".join(segments[-MAX_SEGMENTS:])


def third_party(name: str) -> bool:
    """Library or bundler code, not the application's own."""
    parts = re.split(r"[/\\]+", str(name).lower())
    return any(part in _THIRD_PARTY for part in parts)


@dataclass(slots=True)
class RecoveredFile:
    name: str  # the safe relative path, also the name shown on findings
    path: Path
    text: str


@dataclass(slots=True)
class Recovered:
    files: list[RecoveredFile] = field(default_factory=list)
    findings: list[Record] = field(default_factory=list)
    partial: str = ""


def rebuild(document: Any, dest: Path) -> tuple[list[RecoveredFile], str]:
    """Write the map's original files under ``dest``; returns them and a limit hit, if any."""
    if not isinstance(document, dict):
        return [], ""
    sources = document.get("sources")
    contents = document.get("sourcesContent")
    if not isinstance(sources, list) or not isinstance(contents, list):
        return [], ""
    base = dest.resolve()
    files: list[RecoveredFile] = []
    used: set[str] = set()
    total = 0
    partial = ""
    for name, content in zip(sources, contents, strict=False):
        if not isinstance(content, str) or not content or third_party(str(name)):
            continue
        relative = safe_relative(str(name))
        if relative is None:
            continue
        if not relative.lower().endswith(_EXTENSIONS):
            continue
        if len(files) >= MAX_FILES:
            partial = f"source map has more than {MAX_FILES} original files"
            break
        data = content.encode("utf-8", "replace")
        if len(data) > MAX_FILE_BYTES:
            partial = f"original file over {MAX_FILE_BYTES // 1024} KB not scanned"
            continue
        if total + len(data) > MAX_TOTAL_BYTES:
            partial = f"recovered source over {MAX_TOTAL_BYTES // (1024 * 1024)} MB"
            break
        unique, count = relative, 1
        while unique in used:
            count += 1
            unique = f"{relative}~{count}"
        target = (base / unique).resolve()
        if not target.is_relative_to(base):  # never true after safe_relative; kept as a guard
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        used.add(unique)
        total += len(data)
        files.append(RecoveredFile(unique, target, content))
    return files, partial


def _line_starts(text: str) -> list[int]:
    return [0] + [m.end() for m in re.finditer("\n", text)]


def _line_of(line_starts: list[int], offset: int) -> int:
    return bisect_right(line_starts, offset)


def _line_text(text: str, line_starts: list[int], line: int) -> str:
    start = line_starts[line - 1]
    end = text.find("\n", start)
    return text[start : len(text) if end < 0 else end]


def _snippet(line_text: str, start: int, end: int, *, hide: bool = False) -> str:
    """The line around a hit, redacted; with ``hide`` the matched span itself is removed."""
    if hide:
        line_text = line_text[:start] + REDACTED + line_text[end:]
        end = start + len(REDACTED)
    if len(line_text) > MAX_SNIPPET:
        lead = max(0, start - 60)
        line_text = line_text[lead : max(end, lead + MAX_SNIPPET)]
    return jsparse.redact(line_text.strip())[:MAX_SNIPPET]


def _mixed(value: str) -> bool:
    return len(_DIGIT.findall(value)) >= 2 and len(_LETTER.findall(value)) >= 2


def scan(text: str, *, deadline: float | None = None) -> list[dict[str, Any]]:
    """Every hit in one original file: ``{rule, detail, line, snippet}`` (+ ``literal``/``route``)."""
    starts = _line_starts(text)
    code, bare = jsparse.masked(text)
    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

    def add(rule: str, detail: str, offset: int, end: int, *, hide: bool = False, **extra: Any):
        line = _line_of(starts, offset)
        key = (rule, detail, line)
        if key in seen or len(hits) >= MAX_HITS:
            return
        seen.add(key)
        line_start = starts[line - 1]
        snippet = _snippet(
            _line_text(text, starts, line), offset - line_start, end - line_start, hide=hide
        )
        hits.append({"rule": rule, "detail": detail, "line": line, "snippet": snippet, **extra})

    def late() -> bool:
        return deadline is not None and time.monotonic() > deadline

    for sink in jsparse.dom_sinks(text, deadline=deadline):
        line = int(sink["line"])
        key = ("dom_sink", str(sink["sink"]), line)
        if key not in seen and len(hits) < MAX_HITS:
            seen.add(key)
            hits.append(
                {
                    "rule": "dom_sink",
                    "detail": sink["sink"],
                    "line": line,
                    "snippet": sink["snippet"],
                }
            )
    if late():
        return hits
    secret_lines: set[int] = set()
    for pattern_name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            span = match.span(1) if pattern.groups else match.span()
            add("secret", pattern_name, span[0], span[1], hide=True)
            secret_lines.add(_line_of(starts, span[0]))
    for match in _KEY_ASSIGN.finditer(code):
        value = match.group("value")
        line = _line_of(starts, match.start("value"))
        if line in secret_lines or not _mixed(value) or value.startswith("/"):
            continue
        add(
            "secret",
            f"hardcoded:{match.group('name')[:60]}",
            match.start("value"),
            match.end("value"),
            hide=True,
        )
    if late():
        return hits
    for pattern, rule, where in (
        (_CLIENT_AUTH_NAME, "client_auth", bare),
        (_CLIENT_AUTH_ROLE, "client_auth", code),
        (_DEBUG_FLAG, "debug_flag", code),
    ):
        for match in pattern.finditer(where):
            add(rule, text[match.start() : match.end()][:80], match.start(), match.end())
    kept = 0
    for literal in jsparse.extract_literals(text):
        if kept >= MAX_ENDPOINTS_PER_FILE or late():
            break
        # Rooted paths and absolute URLs; ``./x`` and ``../x`` are module imports.
        if not literal.startswith(("/", "http://", "https://")) or literal.startswith("//"):
            continue
        probe = literal.split(jsparse.PLACEHOLDER, 1)[0] or literal
        offset = text.find(probe)
        if offset < 0:
            continue
        kept += 1
        add("endpoint", literal[:300], offset, offset + len(probe), literal=literal[:300])
    for match in _ROUTE.finditer(code):
        route = match.group("route")
        if route in ("", "*", "**") or kept >= MAX_ENDPOINTS_PER_FILE:
            continue
        if match.group("key") == "to" and not route.startswith("/"):
            continue  # ``{from: "en", to: "de"}`` is not a link
        kept += 1
        add("endpoint", f"route:{route}", match.start("route"), match.end("route"), route=route)
    return hits


def analyze(
    document: Any,
    *,
    map_url: str,
    js_url: str,
    dest: Path,
    in_scope: Callable[[str], bool] | None = None,
    budget_s: float = TIME_BUDGET_S,
) -> Recovered:
    """Rebuild the original files of one map under ``dest`` and scan them.

    Returns the files and one ``js_finding`` record per hit. A map without
    ``sourcesContent`` gives nothing. An endpoint on a host ``in_scope``
    refuses keeps its hit but not its ``url`` (it is never a lead).
    """
    asset = host_of(map_url)
    out = Recovered()
    if not asset:
        return out
    out.files, out.partial = rebuild(document, dest)
    deadline = time.monotonic() + budget_s
    map_value = normalize_url(map_url)
    for recovered in out.files:
        if time.monotonic() > deadline:
            out.partial = f"recovered-source scan stopped after {budget_s:g} s"
            break
        if len(out.findings) >= MAX_HITS:
            out.partial = f"more than {MAX_HITS} hits in recovered source"
            break
        for hit in scan(recovered.text, deadline=deadline):
            attrs: dict[str, Any] = {
                "kind": KIND,
                "rule": hit["rule"],
                "detail": hit["detail"],
                "file": recovered.name,
                "line": hit["line"],
                "snippet": hit["snippet"],
                "map": map_value,
                "found_in": js_url,
            }
            if hit["rule"] == "endpoint":
                url = _endpoint_url(hit, js_url)
                if url and (in_scope is None or in_scope(host_of(url))):
                    attrs["url"] = url
                if "route" in hit:
                    attrs["route"] = hit["route"]
            out.findings.append(
                Record(
                    type=RecordType.JS_FINDING,
                    asset=asset,
                    value=f"{map_value}#{hit['rule']}:{recovered.name}:{hit['line']}"
                    f":{str(hit['detail'])[:120]}",
                    source_tool=jsparse.NAME,
                    attrs=attrs,
                )
            )
            if len(out.findings) >= MAX_HITS:
                break
    return out


def _endpoint_url(hit: dict[str, Any], js_url: str) -> str:
    """The absolute URL an endpoint literal names (resolved against the script), or ``""``."""
    if "literal" not in hit:
        return ""
    resolved = urljoin(js_url, str(hit["literal"]))
    if urlsplit(resolved).scheme not in ("http", "https") or not host_of(resolved):
        return ""
    return normalize_url(resolved)


__all__ = [
    "KIND",
    "RULES",
    "Recovered",
    "RecoveredFile",
    "analyze",
    "rebuild",
    "safe_relative",
    "scan",
    "third_party",
]
