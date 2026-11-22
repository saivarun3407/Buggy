"""Web recon: the files a site publishes about itself, its headers, and its sign-in pages.

Pure functions, no I/O. The pipeline's ``web`` stage fetches the known files
(``robots.txt``, ``sitemap.xml``, ``security.txt``) through its scoped client
and hands the text here; header and page analysis reads records the earlier
stages already stored and sends nothing.

What it produces:

- ``url`` records for paths named in ``robots.txt`` and URLs listed in a
  sitemap, so the parameter extraction and the tests see them;
- ``web_finding`` records: a missing security header, a session cookie without
  its flags, a server banner that names a version, a published
  ``security.txt``;
- ``auth_surface`` records: each sign-in, sign-up, password reset, logout,
  OAuth, multi-factor, account and admin page found, by kind.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urljoin, urlsplit

from buggy.pipeline.schema import Record, RecordType, host_of, normalize_url

KNOWN_FILES_TOOL = "known_files"
HEADERS_TOOL = "header_check"
SURFACE_TOOL = "auth_surface"

ROBOTS = "/robots.txt"
SITEMAP = "/sitemap.xml"
SECURITY_TXT = "/.well-known/security.txt"
KNOWN_FILES = (ROBOTS, SITEMAP, SECURITY_TXT)

#: How many URLs one sitemap may add, and how many nested sitemaps are read.
MAX_SITEMAP_URLS = 500
MAX_NESTED_SITEMAPS = 5
MAX_ROBOTS_PATHS = 200

_ROBOTS_LINE = re.compile(r"^\s*(allow|disallow|sitemap)\s*:\s*(\S+)", re.IGNORECASE)
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

#: Headers a browser-facing page is expected to send, with what each one stops.
EXPECTED_HEADERS: tuple[tuple[str, str], ...] = (
    ("content-security-policy", "limits where scripts may load from, which blunts XSS"),
    ("x-content-type-options", "stops the browser guessing a response's type"),
    ("referrer-policy", "keeps full URLs, and the tokens in them, out of other sites' logs"),
)
_VERSION = re.compile(r"\d+(?:\.\d+)+")
_SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt|login|remember", re.IGNORECASE)

#: Page kinds, checked in this order; the first match names the page.
AUTH_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("logout", re.compile(r"(?<![a-z])(log|sign)[-_]?(out|off)(?![a-z])", re.IGNORECASE)),
    (
        "password_reset",
        re.compile(r"(?<![a-z])(forgot|reset|recover)[-_]?(password|pass|pwd)?(?![a-z])", re.I),
    ),
    ("mfa", re.compile(r"(?<![a-z])(mfa|2fa|otp|totp|two[-_]?factor)(?![a-z])", re.IGNORECASE)),
    (
        "oauth",
        re.compile(
            r"(?<![a-z])(oauth2?|openid|oidc|sso|saml|authorize|callback|jwks)(?![a-z])", re.I
        ),
    ),
    (
        "signup",
        re.compile(r"(?<![a-z])(sign[-_]?up|register|registration|join|enrol+)(?![a-z])", re.I),
    ),
    ("login", re.compile(r"(?<![a-z])(log[-_]?in|sign[-_]?in|auth|session)(?![a-z])", re.I)),
    (
        "admin",
        re.compile(r"(?<![a-z])(admin|administrator|internal|manage|console|staff)(?![a-z])", re.I),
    ),
    (
        "account",
        re.compile(r"(?<![a-z])(account|profile|settings|me|user[-_]?info)(?![a-z])", re.I),
    ),
)


def known_file_urls(origin: str) -> list[str]:
    """The known files to fetch for one origin."""
    return [origin.rstrip("/") + path for path in KNOWN_FILES]


def parse_robots(text: str, base: str) -> tuple[list[str], list[str]]:
    """``(paths, sitemaps)`` named in a ``robots.txt``, as absolute URLs on ``base``.

    A path is cut at its first wildcard (``/private/*.pdf`` -> ``/private/``)
    and a lone ``/`` is dropped: it names the whole site, not a page.
    """
    paths: list[str] = []
    sitemaps: list[str] = []
    for line in text.splitlines()[:5000]:
        match = _ROBOTS_LINE.match(line.split("#", 1)[0])
        if match is None:
            continue
        field, value = match.group(1).lower(), match.group(2)
        if field == "sitemap":
            sitemaps.append(urljoin(base, value))
            continue
        path = value.split("*", 1)[0].rstrip("$")
        if not path.startswith("/") or path == "/":
            continue
        paths.append(urljoin(base, path))
        if len(paths) >= MAX_ROBOTS_PATHS:
            break
    return list(dict.fromkeys(paths)), list(dict.fromkeys(sitemaps))


def parse_sitemap(text: str) -> tuple[list[str], list[str]]:
    """``(page URLs, nested sitemap URLs)`` of one sitemap or sitemap index.

    Read with a pattern, not an XML parser: a sitemap is untrusted input and
    the ``<loc>`` elements are all that is used.
    """
    locations = list(dict.fromkeys(_LOC.findall(text[: 10 * 1024 * 1024])))
    if "<sitemapindex" in text[:2000].lower():
        return [], locations[:MAX_NESTED_SITEMAPS]
    return locations[:MAX_SITEMAP_URLS], []


def is_security_txt(text: str) -> bool:
    """Whether a body is a ``security.txt`` (it names a contact), not an error page."""
    head = text[:20000].lower()
    return "contact:" in head and "<html" not in head


def url_records(urls: Iterable[str], *, source: str) -> Iterator[Record]:
    """``url`` records for URLs a known file named; the pipeline scope-filters them."""
    for url in urls:
        try:
            value = normalize_url(url)
        except ValueError:
            continue
        asset = host_of(value)
        if not asset or urlsplit(value).scheme not in ("http", "https"):
            continue
        yield Record(RecordType.URL, asset, value, KNOWN_FILES_TOOL, attrs={"found_in": source})


def security_txt_record(url: str) -> Record:
    return Record(
        RecordType.WEB_FINDING,
        host_of(url),
        f"{url} security_txt",
        KNOWN_FILES_TOOL,
        attrs={"kind": "security_txt", "url": url, "detail": "publishes a security contact"},
    )


def header_findings(service_url: str, headers: dict[str, str]) -> Iterator[Record]:
    """``web_finding`` records for one service from the headers its first page sent.

    ``headers`` maps lower-case header names to values, as the ``header``
    records store them. Only what the headers show is reported: a header the
    page did not send, a session cookie without its flags, a banner with a
    version number.
    """
    asset = host_of(service_url)
    https = service_url.lower().startswith("https://")

    def finding(kind: str, name: str, detail: str) -> Record:
        return Record(
            RecordType.WEB_FINDING,
            asset,
            f"{service_url} {kind} {name}",
            HEADERS_TOOL,
            attrs={"kind": kind, "url": service_url, "name": name, "detail": detail},
        )

    for name, why in EXPECTED_HEADERS:
        if name not in headers:
            yield finding("missing_header", name, f"not sent; it {why}")
    csp = headers.get("content-security-policy", "").lower()
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        yield finding(
            "missing_header",
            "x-frame-options",
            "neither it nor a frame-ancestors policy is sent, so the page can be framed",
        )
    if https and "strict-transport-security" not in headers:
        yield finding(
            "missing_header",
            "strict-transport-security",
            "not sent; browsers may still try plain HTTP first",
        )
    for cookie in _cookies(headers.get("set-cookie", "")):
        name, flags = cookie
        if not _SESSION_COOKIE.search(name):
            continue
        missing = [
            flag
            for flag, wanted in (("secure", https), ("httponly", True), ("samesite", True))
            if wanted and flag not in flags
        ]
        if missing:
            yield finding(
                "cookie_flags",
                name,
                "session cookie set without " + ", ".join(m.capitalize() for m in missing),
            )
    for name in ("server", "x-powered-by"):
        value = headers.get(name, "")
        if _VERSION.search(value):
            yield finding("version_banner", name, f"names a version: {value[:120]}")


def _cookies(raw: str) -> Iterator[tuple[str, set[str]]]:
    """``(name, lower-case attribute names)`` per cookie of a joined Set-Cookie value."""
    # Several Set-Cookie headers arrive joined by ", " or newlines; an Expires
    # date also contains ", ", so split only where a new name=value starts.
    for part in re.split(r"\n|,\s*(?=[^;,=\s]+=)", raw):
        pieces = [p.strip() for p in part.split(";") if p.strip()]
        if not pieces or "=" not in pieces[0]:
            continue
        name = pieces[0].split("=", 1)[0].strip()
        flags = {p.split("=", 1)[0].strip().lower() for p in pieces[1:]}
        yield name, flags


def auth_kind(url: str) -> str:
    """What kind of sign-in related page a URL is, from its path; ``""`` for none."""
    path = urlsplit(url).path
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", path)
    for kind, pattern in AUTH_KINDS:
        if pattern.search(words):
            return kind
    return ""


def surface_records(urls: Iterable[tuple[str, str]]) -> Iterator[Record]:
    """``auth_surface`` records for ``(url, where it was found)`` pairs that are such a page."""
    seen: set[str] = set()
    for url, source in urls:
        page = url.split("#", 1)[0]
        kind = auth_kind(page)
        if not kind or page in seen:
            continue
        seen.add(page)
        yield Record(
            RecordType.AUTH_SURFACE,
            host_of(page),
            page,
            SURFACE_TOOL,
            attrs={"kind": kind, "found_in": source},
        )


def headers_by_service(header_records: Iterable[Any]) -> dict[str, dict[str, str]]:
    """``{service URL: {header name: value}}`` from stored ``header`` records."""
    out: dict[str, dict[str, str]] = {}
    for record in header_records:
        attrs = record.attrs if hasattr(record, "attrs") else record.get("attrs", {})
        url, name = str(attrs.get("url") or ""), str(attrs.get("name") or "").lower()
        if url and name:
            out.setdefault(url, {})[name] = str(attrs.get("value") or "")
    return out


__all__ = [
    "AUTH_KINDS",
    "EXPECTED_HEADERS",
    "HEADERS_TOOL",
    "KNOWN_FILES",
    "KNOWN_FILES_TOOL",
    "SURFACE_TOOL",
    "auth_kind",
    "header_findings",
    "headers_by_service",
    "is_security_txt",
    "known_file_urls",
    "parse_robots",
    "parse_sitemap",
    "security_txt_record",
    "surface_records",
    "url_records",
]
