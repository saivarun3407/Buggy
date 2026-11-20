"""Parameter extraction: every input the target accepts, as records (built in).

No network and no binary. :func:`extract` reads what the pipeline already
stored and names the inputs in it:

* ``url`` / ``endpoint`` records: query-string names, and path segments that
  are an identifier (digits, a UUID, 24 hex characters) or a placeholder
  (``{id}``, ``:id``);
* ``api_operation`` records: the declared parameters, the placeholders in the
  path, and the property names of the JSON body schema when the record
  carries one (``attrs.request_body_schema``, a JSON Schema object with its
  references already resolved, or ``attrs.request_body_properties``, a list of
  dotted names);
* a ``form`` list in any of those records' attrs. HTML is never fetched or
  parsed here.

One parameter is one record, however many records it was seen in; the tools
that reported those records are its ``sources``. ``hints`` are fixed rules on
the name and the example value, nothing more. The example of a parameter that
carries a credential is never stored.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from buggy.pipeline.schema import (
    Record,
    RecordType,
    StoredRecord,
    as_dict,
    as_list_of,
    host_of,
    normalize_url,
)

NAME = "params"

LOCATIONS = ("query", "path", "body", "header", "cookie", "form")
HINTS = ("id-like", "url-like", "file-like", "numeric", "auth-like")
REDACTED = "<redacted>"
MAX_EXAMPLE = 80
MAX_NAME = 100
MAX_FIELDS = 50  # names taken from one query string, form or parameter list
MAX_BODY_PROPERTIES = 200
MAX_SCHEMA_DEPTH = 6

#: Files whose query string is a cache-buster, not an input.
_STATIC = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|bmp|avif|tiff?|woff2?|ttf|eot|otf)$",
    re.IGNORECASE,
)
_METHOD = re.compile(r"^[A-Z]{1,10}$")
_NAME = re.compile(r"^[^\s\x00-\x1f\x7f]{1,%d}$" % MAX_NAME)
_NUMBER = re.compile(r"^-?[0-9]+(?:\.[0-9]+)?$")
#: A path segment that is an object reference when it follows a collection.
_IDENTIFIER = re.compile(
    r"^(?:[0-9]+|[0-9a-f]{24}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(r"^(?:\{([^{}/]+)\}|:([A-Za-z_]\w*))$")
#: A named collection: /orders/123. A bare "/10" is not an object reference.
_COLLECTION = re.compile(r"^[a-z][\w-]*$", re.IGNORECASE)

_ID_NAME = re.compile(r"^(?:(?i:id|.*[_-]id|uuid)|.*Id)$")
_URL_NAMES = frozenset(
    {
        "url",
        "uri",
        "callback",
        "webhook",
        "redirect",
        "next",
        "dest",
        "return",
        "image_url",
        "fetch",
        "proxy",
    }
)
_FILE_NAMES = frozenset({"file", "path", "filename", "template", "page", "include"})
_AUTH_NAMES = frozenset({"token", "jwt", "session", "api_key", "key"})
_WORD_BREAK = re.compile(r"[_\-.\s\[\]]+|(?<=[a-z0-9])(?=[A-Z])")
#: Redaction is wider than the ``auth-like`` hint: losing an example costs
#: nothing, storing a credential does.
_SECRET_NAME = re.compile(
    r"token|jwt|secret|passw|pwd|apikey|sessid|session|signature|credential", re.IGNORECASE
)
_SECRET_WORDS = frozenset({"key", "auth", "pass", "sig"})
_SECRET_VALUE = re.compile(r"^eyJ[\w-]+\.[\w-]+\.")

_IN = {
    "query": "query",
    "path": "path",
    "header": "header",
    "cookie": "cookie",
    "form": "form",
    "formdata": "form",
    "": "query",
    "none": "query",
}


@dataclass(frozen=True, slots=True)
class _Seen:
    """One sighting of a parameter in one record."""

    method: str
    url: str  # without the query string
    location: str
    name: str
    example: str = ""
    path_id: bool = False


@dataclass(slots=True)
class _Merged:
    seen: _Seen
    examples: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    path_id: bool = False


def _leaf(name: str) -> str:
    """The last step of a dotted body path: ``items[].image_url`` -> ``image_url``."""
    return name.rsplit(".", 1)[-1].removesuffix("[]") or name


def _words(name: str) -> set[str]:
    """``X-Api-Key`` / ``accessToken`` / ``access_token`` as lower-case words."""
    return {word.lower() for word in _WORD_BREAK.split(name) if word}


def hints_for(name: str, examples: Iterable[str] = (), *, path_id: bool = False) -> list[str]:
    """The fixed-rule hints of a parameter, in :data:`HINTS` order."""
    leaf = _leaf(name)
    plain = leaf.lower().replace("-", "_")
    words = _words(leaf)
    values = [value for value in examples if value]
    found = {
        "id-like": path_id or _ID_NAME.match(leaf) is not None,
        "url-like": plain in _URL_NAMES
        or any(value.lower().startswith(("http://", "https://")) for value in values),
        "file-like": plain in _FILE_NAMES,
        "numeric": bool(values) and all(_NUMBER.match(value) for value in values),
        "auth-like": plain in _AUTH_NAMES or bool(words & _AUTH_NAMES),
    }
    return [hint for hint in HINTS if found[hint]]


def _sensitive(name: str, hints: list[str], examples: Iterable[str]) -> bool:
    return (
        "auth-like" in hints
        or _SECRET_NAME.search(name) is not None
        or bool(_words(_leaf(name)) & _SECRET_WORDS)
        or any(_SECRET_VALUE.match(value) for value in examples)
    )


def _scalar(value: Any) -> str:
    """An example value as text; containers and ``None`` are not examples."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str | int | float):
        return str(value)
    return ""


def _method(value: Any) -> str:
    method = str(value or "GET").upper()
    return method if _METHOD.match(method) else "GET"


def _split(url: str) -> tuple[str, str, str] | None:
    """``(url without query, path, query)`` of an http(s) URL, else ``None``."""
    parts = urlsplit(normalize_url(url))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")), parts.path, parts.query


def _path_parameters(method: str, url: str, path: str) -> Iterator[_Seen]:
    segments = path.split("/")[1:]
    for index, segment in enumerate(segments):
        previous = segments[index - 1] if index else ""
        follows_collection = _COLLECTION.match(previous) is not None
        placeholder = _PLACEHOLDER.match(segment)
        if placeholder:
            name = placeholder.group(1) or placeholder.group(2)
            yield _Seen(method, url, "path", name, path_id=follows_collection)
        elif follows_collection and _IDENTIFIER.match(segment):
            yield _Seen(method, url, "path", f"{previous}_id", segment, path_id=True)


def _form_parameters(method: str, url: str, forms: Any) -> Iterator[_Seen]:
    """Fields of a ``form`` list a record already carries.

    An item is a field (a name, or ``{"name", "value"}``) of a form sent to
    the record's own URL, or a form (``{"action", "method", "parameters"}``,
    the crawler's shape). A form posting to another host is not this asset's.
    """
    for item in as_list_of(forms)[:MAX_FIELDS]:
        if not isinstance(item, dict) or "name" in item:
            fields, target, verb = [item], url, method
        else:
            fields = as_list_of(item.get("parameters") or item.get("fields"))
            action = _split(urljoin(url, str(item.get("action") or "")))
            if action is None or host_of(action[0]) != host_of(url):
                continue
            target, verb = action[0], _method(item.get("method"))
        for entry in fields[:MAX_FIELDS]:
            if isinstance(entry, dict):
                yield _Seen(
                    verb, target, "form", str(entry.get("name") or ""), _scalar(entry.get("value"))
                )
            else:
                yield _Seen(verb, target, "form", str(entry))


def _from_url(value: str, attrs: dict[str, Any]) -> Iterator[_Seen]:
    split = _split(value)
    if split is None or _STATIC.search(split[1]):
        return
    url, path, query = split
    method = _method(attrs.get("method"))
    for name, example in parse_qsl(query, keep_blank_values=True)[:MAX_FIELDS]:
        yield _Seen(method, url, "query", name, example)
    yield from _path_parameters(method, url, path)
    yield from _form_parameters(method, url, attrs.get("form"))


def _schema_properties(schema: Any, prefix: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    """``(dotted name, example)`` of every leaf property of a JSON Schema object."""
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return
    for keyword in ("allOf", "oneOf", "anyOf"):
        for branch in as_list_of(schema.get(keyword)):
            yield from _schema_properties(branch, prefix, depth + 1)
    if isinstance(schema.get("items"), dict):
        yield from _schema_properties(schema["items"], f"{prefix}[]", depth + 1)
    for name, child in as_dict(schema.get("properties")).items():
        dotted = f"{prefix}.{name}" if prefix else str(name)
        nested = list(_schema_properties(child, dotted, depth + 1))
        if nested:
            yield from nested
        else:
            yield dotted, _scalar(as_dict(child).get("example"))


def _from_operation(value: str, attrs: dict[str, Any]) -> Iterator[_Seen]:
    verb, _, rest = value.partition(" ")
    split = _split(str(attrs.get("url") or rest))
    if split is None:
        return
    url, path, _query = split
    method = _method(attrs.get("method") or verb)
    yield from _path_parameters(method, url, path)
    for item in as_list_of(attrs.get("parameters"))[:MAX_FIELDS]:
        if isinstance(item, dict):
            location = _IN.get(str(item.get("in") or "").lower())
            if location is not None:  # ``in: body`` names the body, not a field of it
                yield _Seen(
                    method, url, location, str(item.get("name") or ""), _scalar(item.get("example"))
                )
        else:
            yield _Seen(method, url, "query", str(item))
    body = list(_schema_properties(attrs.get("request_body_schema")))
    body += [(str(name), "") for name in as_list_of(attrs.get("request_body_properties"))]
    for name, example in body[:MAX_BODY_PROPERTIES]:
        yield _Seen(method, url, "body", name, example)
    yield from _form_parameters(method, url, attrs.get("form"))


def _field(record: StoredRecord | Mapping[str, Any], key: str) -> Any:
    return record.get(key) if isinstance(record, Mapping) else getattr(record, key, None)


def _read(record: StoredRecord | Mapping[str, Any]) -> tuple[str, str, dict[str, Any], list[str]]:
    """``(type, value, attrs, tools)`` of a stored record or its ``to_dict()`` form."""
    tools = [str(tool) for tool in _field(record, "sources") or () if tool]
    if not tools and _field(record, "source_tool"):
        tools = [str(_field(record, "source_tool"))]
    return (
        str(_field(record, "type") or ""),
        str(_field(record, "value") or ""),
        as_dict(_field(record, "attrs")),
        tools,
    )


def extract(records: Iterable[StoredRecord | Mapping[str, Any]]) -> Iterator[Record]:
    """Parameter records for ``records``, one per parameter, in a stable order.

    The result depends only on the set of records given, not on their order,
    so re-running it over an unchanged store changes nothing.
    """
    merged: dict[str, _Merged] = {}
    for record in records:
        kind, value, attrs, tools = _read(record)
        if kind in (RecordType.URL.value, RecordType.ENDPOINT.value):
            sightings = _from_url(value, attrs)
        elif kind == RecordType.API_OPERATION.value:
            sightings = _from_operation(value, attrs)
        else:
            continue
        for seen in sightings:
            if not _NAME.match(seen.name):
                continue
            entry = merged.setdefault(
                f"{seen.method} {seen.url} {seen.location}:{seen.name}", _Merged(seen)
            )
            entry.sources.update(tools)
            entry.path_id = entry.path_id or seen.path_id
            if seen.example:
                entry.examples.add(seen.example)
    for key in sorted(merged):
        entry = merged[key]
        seen = entry.seen
        examples = sorted(entry.examples)
        hints = hints_for(seen.name, examples, path_id=entry.path_id)
        # The stored example is one that the hints were computed from.
        links = [e for e in examples if e.lower().startswith(("http://", "https://"))]
        example = (links or examples or [""])[0][:MAX_EXAMPLE]
        if example and _sensitive(seen.name, hints, examples):
            example = REDACTED
        yield Record(
            type=RecordType.PARAMETER,
            asset=host_of(seen.url),
            value=key,
            source_tool=NAME,
            attrs={
                "name": seen.name,
                "location": seen.location,
                "method": seen.method,
                "url": seen.url,
                "example": example,
                "sources": sorted(entry.sources),
                "hints": hints,
            },
        )


__all__ = ["HINTS", "LOCATIONS", "NAME", "REDACTED", "extract", "hints_for"]
