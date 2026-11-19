"""Endpoint extraction from JavaScript (built in; no binary).

Pulls quoted paths and URLs out of a script's text. It is a string scan, not
an interpreter: it finds routes that appear as literals (which is most of
what a bundled SPA contains) and nothing that is assembled at run time.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import urljoin, urlsplit

from buggy.pipeline.schema import Record, RecordType, host_of, normalize_url

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


def extract_literals(script: str, *, limit: int = 5000) -> list[str]:
    """Distinct path / URL literals in ``script``, in first-seen order."""
    found: dict[str, None] = {}
    for match in _LITERAL.finditer(script):
        value = match.group("v")
        if _STATIC.search(value) or _NOISE.search(value) or _MIME.match(value):
            continue
        if value.startswith("/") and not value.startswith("//") and len(value) < 3:
            continue
        found.setdefault(value, None)
        if len(found) >= limit:
            break
    return list(found)


def parse(script: str, *, js_url: str) -> Iterator[Record]:
    """Endpoint records for every literal, resolved against the script's URL."""
    for literal in extract_literals(script):
        resolved = urljoin(js_url, literal)
        if urlsplit(resolved).scheme not in ("http", "https"):
            continue
        url = normalize_url(resolved)
        asset = host_of(url)
        if not asset:
            continue
        yield Record(
            type=RecordType.ENDPOINT,
            asset=asset,
            value=url,
            source_tool=NAME,
            attrs={"found_in": js_url, "literal": literal[:300]},
        )
