"""API recon: which APIs a target serves, how they sign people in, and how each endpoint answers.

Pure functions, no I/O. The pipeline's ``api`` stage does the fetching
through its scoped client and hands the responses here.

What it produces:

- ``api_base`` records: one per API root (``/api/v2``, ``/rest``), with its
  versions, how many endpoints were found under it, and how many take an
  object identifier in the path;
- ``auth_surface`` records (kind ``oauth``) for the endpoints an OpenID or
  OAuth discovery document names;
- ``api_profile`` records: one unauthenticated GET per concrete endpoint,
  with the status, the content type, whether it asked for credentials and
  how, its cross-origin and rate-limit headers, the methods a 405 allowed,
  and the top-level field names of a JSON answer (never the values).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urlsplit

from buggy.pipeline.schema import Record, RecordType, host_of, normalize_url

INVENTORY_TOOL = "api_inventory"
PROFILE_TOOL = "api_profile"
OIDC_TOOL = "oidc_discovery"

OIDC_PATHS = ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")
#: Keys of a discovery document that name an endpoint, and what each one is.
OIDC_ENDPOINTS: dict[str, str] = {
    "authorization_endpoint": "authorize",
    "token_endpoint": "token",
    "userinfo_endpoint": "userinfo",
    "registration_endpoint": "client registration",
    "end_session_endpoint": "end session",
    "jwks_uri": "signing keys",
    "introspection_endpoint": "token introspection",
    "revocation_endpoint": "token revocation",
    "device_authorization_endpoint": "device authorization",
}

#: Statuses that mean the endpoint is not there; such a profile is not kept.
NOT_THERE = frozenset({404, 410})
#: Endpoints profiled per origin, and field names kept per answer.
MAX_PROFILES_PER_ORIGIN = 40
MAX_FIELDS = 25

_VERSION_SEGMENT = re.compile(r"^v\d+(\.\d+)?$", re.IGNORECASE)
_ROOT_SEGMENTS = frozenset(
    {"api", "apis", "rest", "graphql", "rpc", "jsonrpc", "odata", "services"}
)
_ID_SEGMENT = re.compile(
    r"^(\d+|[0-9a-f]{24}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|\{[^}/]+\}|:[a-z_]+|<[^>/]+>)$",
    re.IGNORECASE,
)
_TEMPLATE = re.compile(r"\{[^}]*\}|:[a-z_]+(?=/|$)|<[^>]*>|%7B|%7D", re.IGNORECASE)
#: An escaped quote or backslash in a path: a script's string that was cut out badly.
_ARTIFACT = re.compile(r"%5C|%22|%27|[\\\"']", re.IGNORECASE)
_RATE_HEADER = re.compile(r"^(x-)?rate-?limit|^retry-after$|^x-ratelimit", re.IGNORECASE)
#: Field names worth a person's attention when an endpoint returns them to anyone.
SENSITIVE_FIELD = re.compile(
    r"e-?mail|pass(word|wd)?|token|secret|api[-_]?key|ssn|phone|address|birth|"
    r"role|is[-_]?admin|admin|credit|card|iban|salary|hash",
    re.IGNORECASE,
)


def _segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def api_root(url: str) -> str:
    """The API root a URL sits under (``https://h/api/v2``), or ``""`` if it is not an API URL.

    The root runs to the last ``api``-like or version segment among the
    first three; ``/api/v2/users/7`` has root ``/api/v2``.
    """
    parts = urlsplit(url)
    segments = _segments(parts.path)
    end = 0
    for index, segment in enumerate(segments[:3]):
        if segment.lower() in _ROOT_SEGMENTS or _VERSION_SEGMENT.match(segment):
            end = index + 1
    if end == 0:
        return ""
    return f"{parts.scheme}://{parts.netloc}/" + "/".join(segments[:end])


def id_positions(url: str) -> list[int]:
    """Positions of path segments that are an object identifier (number, UUID, ``{id}``)."""
    return [i for i, s in enumerate(_segments(urlsplit(url).path)) if _ID_SEGMENT.match(s)]


def is_template(url: str) -> bool:
    """Whether a URL still has a placeholder (``/users/{id}``) and so cannot be requested."""
    return bool(_TEMPLATE.search(urlsplit(url).path))


def inventory(urls: Iterable[str]) -> Iterator[Record]:
    """One ``api_base`` record per API root found among ``urls``."""
    roots: dict[str, dict[str, Any]] = {}
    for url in urls:
        root = api_root(url)
        if not root:
            continue
        entry = roots.setdefault(root, {"endpoints": set(), "with_id": set()})
        path = urlsplit(url).path
        entry["endpoints"].add(path)
        if id_positions(url):
            entry["with_id"].add(path)
    versions_by_prefix: dict[str, set[str]] = {}
    for root in roots:
        head, _, last = root.rpartition("/")
        if _VERSION_SEGMENT.match(last):
            versions_by_prefix.setdefault(head, set()).add(last.lower())
    for root, entry in sorted(roots.items()):
        head, _, last = root.rpartition("/")
        siblings = sorted(
            versions_by_prefix.get(head, set()) if _VERSION_SEGMENT.match(last) else []
        )
        yield Record(
            RecordType.API_BASE,
            host_of(root),
            root,
            INVENTORY_TOOL,
            attrs={
                "endpoints": len(entry["endpoints"]),
                "with_object_id": len(entry["with_id"]),
                "versions": siblings,
                "sample": sorted(entry["endpoints"])[:10],
            },
        )


def parse_discovery(text: str, url: str) -> Iterator[Record]:
    """``auth_surface`` records for the endpoints an OpenID / OAuth discovery document names."""
    try:
        document = json.loads(text)
    except ValueError:
        return
    if not isinstance(document, dict) or not (
        document.get("issuer") or document.get("authorization_endpoint")
    ):
        return
    for key, what in OIDC_ENDPOINTS.items():
        value = document.get(key)
        if not isinstance(value, str) or not value.startswith(("http://", "https://")):
            continue
        try:
            endpoint = normalize_url(value)
        except ValueError:
            continue
        yield Record(
            RecordType.AUTH_SURFACE,
            host_of(endpoint),
            endpoint,
            OIDC_TOOL,
            attrs={"kind": "oauth", "role": what, "found_in": url},
        )


def profile_targets(urls: Iterable[str], *, never: Any = None) -> list[str]:
    """Concrete API endpoints to send one GET to, at most :data:`MAX_PROFILES_PER_ORIGIN` per origin.

    The query string is never sent. Templates are skipped (there is nothing
    to request), and so is any URL
    ``never(url)`` gives a reason for (it names logout, delete and the like).
    Endpoints with an object identifier come first: they matter most.
    """
    chosen: dict[str, list[str]] = {}
    # The query is dropped: an archived URL can carry a reset link's token, and
    # the profile is about the endpoint, not one past request to it.
    ordered = sorted(
        {u.split("#", 1)[0].split("?", 1)[0] for u in urls if api_root(u)},
        key=lambda u: (not id_positions(u), u),
    )
    for url in ordered:
        if is_template(url) or _ARTIFACT.search(url) or (never is not None and never(url)):
            continue
        parts = urlsplit(url)
        bucket = chosen.setdefault(f"{parts.scheme}://{parts.netloc}", [])
        if len(bucket) < MAX_PROFILES_PER_ORIGIN:
            bucket.append(url)
    return [url for bucket in chosen.values() for url in bucket]


def _fields(body: Any) -> tuple[list[str], int | None]:
    """Field names of a JSON answer (of its first item for a list), and the list length.

    Names one level down are kept as ``parent.child`` (``User.email``): an
    answer often nests the record that matters.
    """
    count = None
    if isinstance(body, dict):
        for key in ("data", "items", "results", "records"):
            if isinstance(body.get(key), list):
                count = len(body[key])
                body = body[key][0] if body[key] else {}
                break
    elif isinstance(body, list):
        count = len(body)
        body = body[0] if body else {}
    if not isinstance(body, dict):
        return [], count
    names: list[str] = []
    for key, value in body.items():
        names.append(str(key)[:60])
        if isinstance(value, dict):
            names += [f"{str(key)[:30]}.{str(sub)[:30]}" for sub in value]
        if len(names) >= MAX_FIELDS:
            break
    return names[:MAX_FIELDS], count


def profile(url: str, status: int, headers: dict[str, str], body: bytes) -> Record:
    """The ``api_profile`` record for one unauthenticated GET of ``url``."""
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    challenge = headers.get("www-authenticate", "")
    if status in (401, 403) or challenge:
        auth = "required"
    elif 200 <= status < 300:
        auth = "none"
    else:
        auth = "unknown"
    attrs: dict[str, Any] = {
        "url": url,
        "status": status,
        "content_type": content_type,
        "auth": auth,
    }
    if challenge:
        attrs["auth_scheme"] = challenge.split(" ", 1)[0].split(",", 1)[0].strip()
    origin = headers.get("access-control-allow-origin", "")
    if origin:
        attrs["cors_origin"] = origin[:200]
        attrs["cors_credentials"] = (
            headers.get("access-control-allow-credentials", "").lower() == "true"
        )
    rate = sorted(name for name in headers if _RATE_HEADER.match(name))
    attrs["rate_limit_headers"] = rate
    if status == 405 and headers.get("allow"):
        attrs["allowed_methods"] = sorted(
            {m.strip().upper() for m in headers["allow"].split(",") if m.strip()}
        )
    if 200 <= status < 300 and "json" in content_type:
        try:
            fields, count = _fields(json.loads(body.decode("utf-8", "replace")))
        except ValueError:
            fields, count = [], None
        if fields:
            attrs["fields"] = fields
            sensitive = [f for f in fields if SENSITIVE_FIELD.search(f)]
            if sensitive:
                attrs["sensitive_fields"] = sensitive
        if count is not None:
            attrs["items"] = count
    if id_positions(url):
        attrs["object_id_in_path"] = True
    return Record(RecordType.API_PROFILE, host_of(url), f"GET {url}", PROFILE_TOOL, attrs=attrs)


__all__ = [
    "INVENTORY_TOOL",
    "MAX_PROFILES_PER_ORIGIN",
    "OIDC_ENDPOINTS",
    "OIDC_PATHS",
    "OIDC_TOOL",
    "PROFILE_TOOL",
    "SENSITIVE_FIELD",
    "api_root",
    "id_positions",
    "inventory",
    "is_template",
    "parse_discovery",
    "profile",
    "profile_targets",
]
