"""Operator-supplied API contracts: OpenAPI / Swagger files and Postman collections (built in).

The target does not always publish its specification. The operator can put one
under ``<control>/<engagement>/contracts/`` and name it in the scope document
(``pipeline.api_contracts``); :func:`load` turns it into the same ``api_spec``
and ``api_operation`` records the discovery stage writes, with
``attrs.source = "operator"``.

A contract is input data, not an instruction:

* no request is made because of it. Nothing here opens a socket;
* every server and every operation URL it names goes through the engagement's
  scope filter before a record exists. What is out of scope is dropped and
  logged like any other scope drop;
* it can carry credentials (a Postman ``auth`` block, header values, example
  bodies, variables). Only names leave this module: header names, query names,
  body property names. No header value, no auth block, no body value, no query
  value and no URL userinfo is ever put in a record, and a Postman variable
  whose name says it holds a credential is never substituted into a URL.

Standard library only, plus PyYAML for a YAML file.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlsplit

from buggy.pipeline.schema import (
    Record,
    RecordType,
    as_dict,
    as_list_of,
    host_of,
    normalize_url,
)
from buggy.pipeline.tools import apispec

if TYPE_CHECKING:
    from collections.abc import Iterable

    from buggy.pipeline.scope import ScopeFilter

NAME = "contracts"
STAGE = "apispec"
#: Stage-cache namespace of the contracts: one row per contract, next to the
#: ``apispec`` stage's own per-origin rows, and the owner of their records.
CACHE_STAGE = "apispec:contracts"
DIRNAME = "contracts"
DEFAULT_CONTROL_ROOT = "/control"

MAX_BYTES = 10 * 1024 * 1024
MAX_NODES = 2_000_000  # values in a decoded document (a YAML alias can repeat one)
MAX_NESTING = 100
MAX_OPERATIONS = 5000
MAX_SERVERS = 10
MAX_FOLDER_DEPTH = 12
MAX_NAMES = 200
MAX_NAME = 200
MAX_BODY_DEPTH = 6
MAX_VARIABLE_PASSES = 5

UNRESOLVED_VARIABLE = "UNRESOLVED_VARIABLE"
SECRET_VARIABLE = "SECRET_VARIABLE"  # noqa: S105 - a reason code, not a credential
NOT_ABSOLUTE_URL = "NOT_ABSOLUTE_URL"

_VARIABLE = re.compile(r"\{\{\s*([^{}]*?)\s*\}\}")
_LEADING_VARIABLE = re.compile(r"^\{\{[^{}]*\}\}")
_PLACEHOLDER = re.compile(r"\{([^{}/]+)\}")
_USERINFO = re.compile(r"//[^/?#@]*@")
_METHOD = re.compile(r"^[A-Z]{1,10}$")
_PATH_VARIABLE = re.compile(r"/:([A-Za-z_][\w-]*)")
_POSTMAN_VERSION = re.compile(r"/v(\d+\.\d+(?:\.\d+)?)/")
_WORD_BREAK = re.compile(r"[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])")
#: A variable whose name has one of these words holds a credential.
_SECRET_WORDS = frozenset(
    {
        "token",
        "jwt",
        "secret",
        "password",
        "passwd",
        "pass",
        "pwd",
        "apikey",
        "key",
        "session",
        "sessid",
        "signature",
        "sig",
        "credential",
        "credentials",
        "bearer",
        "cookie",
    }
)
#: Headers that say how a request is sent, not what the operation accepts.
#: ``request_body_types`` and ``auth_required`` describe them instead.
_TRANSPORT_HEADERS = frozenset({"accept", "content-type", "authorization"})
_BODY_TYPES = {
    "urlencoded": "application/x-www-form-urlencoded",
    "formdata": "multipart/form-data",
    "graphql": "application/json",
    "file": "application/octet-stream",
}
_RAW_TYPES = {"json": "application/json", "xml": "application/xml", "text": "text/plain"}


class ContractError(ValueError):
    """A contract file could not be read or is not a contract."""


class _LeftOut(Exception):
    """A request that cannot become an operation: what to log, and why."""

    def __init__(self, candidate: str, reason: str) -> None:
        super().__init__(reason)
        self.candidate, self.reason = candidate, reason


# ── the file ─────────────────────────────────────────────────────────────


def control_dir_for(engagement: str) -> Path:
    """``<control root>/<engagement>``, the control root taken from the environment."""
    raw = os.environ.get("BUGGY_ENGAGEMENT_CONTROL") or os.environ.get("BUGGY_CONTROL_ROOT")
    return Path(raw or DEFAULT_CONTROL_ROOT) / engagement


def ref(entry: dict[str, Any]) -> str:
    """How records name the contract they came from (it has no URL)."""
    return f"contract:{entry.get('path') or ''}"


def key(entry: dict[str, Any]) -> str:
    """The contract's stage-cache key: its file, and the base URL it is read against."""
    base = str(entry.get("base_url") or "")
    return ref(entry) + (f"@{base}" if base else "")


def read(control_dir: Path, entry: dict[str, Any]) -> bytes:
    """The bytes of ``<control_dir>/contracts/<entry path>``; never a file outside it.

    The scope document is checked when it is loaded; this checks again, and
    also follows links, so a path that passed the first check cannot lead out.
    """
    relative = str(entry.get("path") or "").strip()
    if not relative or ".." in relative or relative.startswith(("/", "\\", "~")):
        raise ContractError("path must be a relative path under contracts/")
    try:
        root = (Path(control_dir) / DIRNAME).resolve()
        target = (root / relative).resolve()
        inside = target.is_relative_to(root)
        size = target.stat().st_size if inside and target.is_file() else -1
    except (OSError, ValueError) as exc:
        raise ContractError(f"cannot be read ({type(exc).__name__})") from exc
    if not inside:
        raise ContractError("path leads outside the contracts directory")
    if size < 0:
        raise ContractError("no such file under contracts/")
    if size > MAX_BYTES:
        raise ContractError(f"larger than {MAX_BYTES} bytes")
    try:
        return target.read_bytes()
    except OSError as exc:
        raise ContractError(f"cannot be read ({type(exc).__name__})") from exc


def _decode(data: bytes) -> dict[str, Any]:
    """The document in ``data``: JSON, else YAML. Always a mapping."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ContractError("not UTF-8 text") from exc
    document: Any = None
    if text.lstrip().startswith("{"):
        try:
            document = json.loads(text)
        except (ValueError, RecursionError):
            document = None
    if document is None:
        try:
            import yaml  # noqa: PLC0415 - only a YAML contract needs it
        except ImportError as exc:  # pragma: no cover - PyYAML ships with the image
            raise ContractError("not JSON, and PyYAML is not installed") from exc
        try:
            document = yaml.safe_load(text)
        except (yaml.YAMLError, RecursionError, ValueError) as exc:
            raise ContractError("neither JSON nor YAML") from exc
    if not isinstance(document, dict):
        raise ContractError("not a JSON or YAML object")
    _bound(document)
    return document


def _bound(document: Any) -> None:
    """Refuse a document too big or too deep to walk (a YAML alias can repeat a subtree)."""
    stack: list[tuple[Any, int]] = [(document, 0)]
    seen = 0
    while stack:
        node, depth = stack.pop()
        seen += 1
        if seen > MAX_NODES or depth > MAX_NESTING:
            raise ContractError("too large or too deeply nested")
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)


def _is_postman(document: dict[str, Any]) -> bool:
    schema = str(as_dict(document.get("info")).get("schema") or "")
    return isinstance(document.get("item"), list) and "/collection/v2" in schema


def _is_openapi(document: dict[str, Any]) -> bool:
    return bool(document.get("openapi") or document.get("swagger")) and isinstance(
        document.get("paths"), dict
    )


# ── what is left out, and why ────────────────────────────────────────────


def _printable(candidate: str) -> str:
    """A URL as it may be logged: no userinfo, no query string."""
    return _USERINFO.sub("//", candidate.split("?", 1)[0].split("#", 1)[0]).strip()[:500]


def _leave_out(scope: ScopeFilter, candidate: str, reason: str) -> None:
    """Log something the contract names that cannot become a record."""
    if scope.log_drop is not None:
        scope.log_drop(STAGE, NAME, "input", _printable(candidate), reason)


def _admit(scope: ScopeFilter, urls: list[str]) -> list[str]:
    """The in-scope ``urls``; the rest are logged as dropped inputs of this tool."""
    return scope.admit(urls, stage=STAGE, tool=NAME, direction="input")


def _base(url: str) -> str:
    """``scheme://host[:port]/path`` of an absolute http(s) URL, else ``""``. No userinfo."""
    parts = urlsplit(normalize_url(url))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


def _origin(url: str) -> str:
    parts = urlsplit(normalize_url(url))
    return f"{parts.scheme}://{parts.netloc}"


def _names(values: Iterable[Any]) -> list[str]:
    """Distinct usable names, in order."""
    kept: dict[str, None] = {}
    for value in values:
        name = value.strip() if isinstance(value, str) else ""
        if name and len(name) <= MAX_NAME and "{{" not in name:
            kept.setdefault(name)
    return list(kept)[:MAX_NAMES]


# ── OpenAPI / Swagger ────────────────────────────────────────────────────


def _server_url(server: dict[str, Any]) -> str:
    """An OpenAPI 3 server URL with each ``{variable}`` replaced by its default."""
    variables = as_dict(server.get("variables"))

    def default(match: re.Match[str]) -> str:
        value = as_dict(variables.get(match.group(1))).get("default")
        return str(value) if isinstance(value, str | int | float) else match.group(0)

    return _PLACEHOLDER.sub(default, str(server.get("url") or "").strip())


def _servers(spec: dict[str, Any], scope: ScopeFilter) -> list[str]:
    """Where the document says the API is served. Untrusted: the caller filters them."""
    if spec.get("swagger"):
        host = str(spec.get("host") or "").strip()
        schemes = [s for s in as_list_of(spec.get("schemes")) if isinstance(s, str)]
        scheme = schemes[0] if schemes else "https"
        return [f"{scheme}://{host}{spec.get('basePath') or ''}"] if host else []
    found: list[str] = []
    for server in as_list_of(spec.get("servers"))[:MAX_SERVERS]:
        url = _server_url(server) if isinstance(server, dict) else ""
        if _PLACEHOLDER.search(url.split("?", 1)[0]):
            _leave_out(scope, url, UNRESOLVED_VARIABLE)
        elif url:
            found.append(url)
    return found


def _openapi(
    spec: dict[str, Any], entry: dict[str, Any], scope: ScopeFilter, extra: dict[str, Any]
) -> list[Record]:
    override = str(entry.get("base_url") or "")
    bases: list[str] = []
    for server in [override] if override else _servers(spec, scope):
        base = _base(server)
        if base:
            bases.append(base)
        else:
            _leave_out(scope, server, NOT_ABSOLUTE_URL)
    if not bases:
        raise ContractError("names no absolute server URL; set base_url for this contract")
    specs: dict[str, Record] = {}
    operations: dict[tuple[str, str], Record] = {}
    for base in _admit(scope, bases):
        asset = host_of(base)
        found = apispec.openapi_operations(
            spec, base=base, spec_ref=ref(entry), asset=asset, tool=NAME, extra=extra
        )
        # A path is untrusted too: "@other.host/x" under a bare host names another host.
        allowed = set(_admit(scope, [operation.attrs["url"] for operation in found]))
        kept = [operation for operation in found if operation.attrs["url"] in allowed]
        for operation in kept[: MAX_OPERATIONS - len(operations)]:
            operations.setdefault((operation.asset, operation.value), operation)
        count = sum(1 for owner, _value in operations if owner == asset)
        attrs = apispec.openapi_spec_attrs(spec, base=base, operation_count=count)
        if asset in specs:  # a second server on the same host: one record, the first base
            attrs["base_url"] = specs[asset].attrs["base_url"]
        specs[asset] = Record(
            RecordType.API_SPEC, asset, ref(entry), NAME, attrs={**attrs, **extra}
        )
    return [*specs.values(), *operations.values()]


# ── Postman ──────────────────────────────────────────────────────────────


def _secret_name(name: str) -> bool:
    return bool({word.lower() for word in _WORD_BREAK.split(name) if word} & _SECRET_WORDS)


def _variables(collection: dict[str, Any]) -> dict[str, str]:
    """The collection's own variables. One named like a credential is left out."""
    found: dict[str, str] = {}
    for item in as_list_of(collection.get("variable")):
        if not isinstance(item, dict) or item.get("disabled"):
            continue
        name, value = str(item.get("key") or item.get("id") or ""), item.get("value")
        if name and isinstance(value, str | int | float) and not _secret_name(name):
            found[name] = str(value)
    return found


def _substitute(text: str, variables: dict[str, str]) -> str:
    """``text`` with every ``{{name}}`` the collection defines replaced."""
    for _ in range(MAX_VARIABLE_PASSES):
        resolved = _VARIABLE.sub(lambda m: variables.get(m.group(1), m.group(0)), text)
        if resolved == text:
            break
        text = resolved
    return text


def _assembled(url: dict[str, Any]) -> str:
    """A Postman URL object that has no ``raw`` form, put back together."""

    def joined(value: Any, separator: str) -> str:
        if isinstance(value, list):
            return separator.join(
                str(part.get("value") or "") if isinstance(part, dict) else str(part)
                for part in value
            )
        return str(value or "")

    host = joined(url.get("host"), ".")
    port = f":{url['port']}" if url.get("port") else ""
    scheme = f"{url['protocol']}://" if url.get("protocol") else ""
    return f"{scheme}{host}{port}/{joined(url.get('path'), '/').lstrip('/')}"


def _postman_url(
    request: dict[str, Any], variables: dict[str, str], override: str
) -> tuple[str, list[str]]:
    """``(url, query names)`` of a request, its variables resolved; the URL has no query.

    ``override`` (the entry's ``base_url``) takes the place of a leading
    ``{{variable}}``, and otherwise of the URL's scheme, host and port.
    """
    field = request.get("url")
    described = as_dict(field)
    raw = field if isinstance(field, str) else str(described.get("raw") or "")
    raw = (raw or (_assembled(described) if described else "")).strip().split("#", 1)[0]
    head, _, query = raw.partition("?")
    listed = [as_dict(item).get("key") for item in as_list_of(described.get("query"))]
    queries = _names(listed or [name for name, _ in parse_qsl(query, keep_blank_values=True)])

    head = _substitute(head, variables)
    if override and _LEADING_VARIABLE.match(head):
        head = override.rstrip("/") + _LEADING_VARIABLE.sub("", head, count=1)
    left = [match.group(1) for match in _VARIABLE.finditer(head)]
    if left:
        withheld = any(_secret_name(name) for name in left)
        raise _LeftOut(head, SECRET_VARIABLE if withheld else UNRESOLVED_VARIABLE)
    parts = urlsplit(normalize_url(head if "://" in head else f"http://{head}"))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise _LeftOut(head, NOT_ABSOLUTE_URL)
    origin = _origin(override) if override else f"{parts.scheme}://{parts.netloc}"
    path = _PATH_VARIABLE.sub(r"/{\1}", parts.path)  # ":id" is Postman's path variable
    return normalize_url(f"{origin}{path}"), queries


def _json_names(value: Any, prefix: str, depth: int, names: dict[str, None]) -> None:
    """Dotted names of the leaf properties of a JSON value, as ``params`` names a schema's."""
    if depth > MAX_BODY_DEPTH or len(names) >= MAX_NAMES:
        return
    if isinstance(value, list):
        for item in value[:20]:
            if isinstance(item, dict | list):
                _json_names(item, f"{prefix}[]", depth + 1, names)
    elif isinstance(value, dict):
        for name, child in value.items():
            dotted = f"{prefix}.{name}" if prefix else str(name)
            before = len(names)
            _json_names(child, dotted, depth + 1, names)
            if len(names) == before and len(dotted) <= MAX_NAME:
                names.setdefault(dotted)


def _body(body: Any) -> dict[str, Any]:
    """Mode, media type and field names of a Postman request body. Never a value."""
    body = as_dict(body)
    mode = str(body.get("mode") or "")
    if not mode or body.get("disabled"):
        return {}
    out: dict[str, Any] = {"request_body_mode": mode[:40], "request_body_properties": []}
    if mode == "raw":
        raw = body["raw"] if isinstance(body.get("raw"), str) else ""
        language = str(as_dict(as_dict(body.get("options")).get("raw")).get("language") or "")
        document: Any = None
        for text in (raw, _VARIABLE.sub("0", raw)):  # an unquoted {{variable}} is not JSON
            try:
                document = json.loads(text)
                break
            except (ValueError, RecursionError):
                continue
        if isinstance(document, dict | list):
            names: dict[str, None] = {}
            _json_names(document, "", 0, names)
            out["request_body_properties"] = list(names)
            language = "json"
        out["request_body_types"] = [_RAW_TYPES[language]] if language in _RAW_TYPES else []
        return out
    out["request_body_types"] = [_BODY_TYPES[mode]] if mode in _BODY_TYPES else []
    if mode in ("urlencoded", "formdata"):
        fields = _names(as_dict(item).get("key") for item in as_list_of(body.get(mode)))
        if fields:
            out["form"] = fields
    return out


def _auth_type(*blocks: Any) -> str:
    """The type of the nearest auth block (request, then folders, then collection)."""
    for block in blocks:
        if isinstance(block, dict) and block.get("type"):
            return str(block["type"]).lower()[:40]
    return ""


def _postman_operation(
    item: dict[str, Any],
    folders: tuple[str, ...],
    auths: tuple[Any, ...],
    variables: dict[str, str],
    entry: dict[str, Any],
    scope: ScopeFilter,
    extra: dict[str, Any],
) -> Record | None:
    request = item.get("request")
    if isinstance(request, str):
        request = {"url": request}
    if not isinstance(request, dict):
        return None
    method = str(request.get("method") or "GET").upper()
    method = method if _METHOD.match(method) else "GET"
    try:
        url, queries = _postman_url(request, variables, str(entry.get("base_url") or ""))
    except _LeftOut as left:
        _leave_out(scope, f"{method} {left.candidate}", left.reason)
        return None
    if not _admit(scope, [url]):
        return None
    path = urlsplit(url).path
    headers = _names(as_dict(h).get("key") for h in as_list_of(request.get("header")))
    parameters = [
        *(
            {"name": name, "in": "path", "required": True}
            for name in _names(_PLACEHOLDER.findall(path))
        ),
        *({"name": name, "in": "query", "required": False} for name in queries),
        *(
            {"name": name, "in": "header", "required": False}
            for name in headers
            if name.lower() not in _TRANSPORT_HEADERS
        ),
    ]
    auth = _auth_type(request.get("auth"), *auths)
    attrs: dict[str, Any] = {
        "method": method,
        "url": url,
        "path": path,
        "operation_id": "",
        "summary": str(item.get("name") or "")[:300],
        "tags": list(folders)[:20],
        "parameters": parameters[:MAX_NAMES],
        "request_body_types": [],
        "request_body_properties": [],
        "header_names": headers,
        "auth_required": auth not in ("", "noauth")
        or any(name.lower() == "authorization" for name in headers),
        "auth_type": auth,
        "spec_url": ref(entry),
        **_body(request.get("body")),
        **extra,
    }
    return Record(RecordType.API_OPERATION, host_of(url), f"{method} {url}", NAME, attrs=attrs)


def _merged(first: Record, second: Record) -> Record:
    """Two requests for the same method and URL (two examples of one operation) as one."""
    attrs = dict(first.attrs)
    for name in ("parameters", "request_body_types", "request_body_properties", "header_names"):
        attrs[name] = [*attrs[name], *(v for v in second.attrs[name] if v not in attrs[name])]
    fields = _names([*first.attrs.get("form", []), *second.attrs.get("form", [])])
    if fields:
        attrs["form"] = fields
    attrs["auth_required"] = bool(first.attrs["auth_required"] or second.attrs["auth_required"])
    return Record(first.type, first.asset, first.value, first.source_tool, attrs=attrs)


def _postman(
    collection: dict[str, Any], entry: dict[str, Any], scope: ScopeFilter, extra: dict[str, Any]
) -> list[Record]:
    variables = _variables(collection)
    operations: dict[tuple[str, str], Record] = {}
    # (items, folder names, auth blocks from the nearest folder out to the collection)
    queue: list[tuple[list[Any], tuple[str, ...], tuple[Any, ...]]] = [
        (as_list_of(collection.get("item")), (), (collection.get("auth"),))
    ]
    while queue and len(operations) < MAX_OPERATIONS:
        items, folders, auths = queue.pop(0)
        for item in items:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("item"), list):
                if len(folders) < MAX_FOLDER_DEPTH:
                    name = str(item.get("name") or "")[:100]
                    queue.append((item["item"], (*folders, name), (item.get("auth"), *auths)))
                continue
            found = _postman_operation(item, folders, auths, variables, entry, scope, extra)
            if found is not None and len(operations) < MAX_OPERATIONS:
                identity = (found.asset, found.value)
                known = operations.get(identity)
                operations[identity] = _merged(known, found) if known else found
    info = as_dict(collection.get("info"))
    version = _POSTMAN_VERSION.search(str(info.get("schema") or ""))
    specs: dict[str, Record] = {}
    for asset in dict.fromkeys(owner for owner, _value in operations):
        mine = [o for (owner, _value), o in operations.items() if owner == asset]
        attrs = {
            "format": "postman",
            "spec_version": version.group(1) if version else "",
            "title": str(info.get("name") or "")[:200],
            "api_version": info["version"] if isinstance(info.get("version"), str) else "",
            "base_url": _origin(mine[0].attrs["url"]),
            "operation_count": len(mine),
            "security_schemes": sorted({o.attrs["auth_type"] for o in mine} - {"", "noauth"}),
            **extra,
        }
        specs[asset] = Record(RecordType.API_SPEC, asset, ref(entry), NAME, attrs=attrs)
    return [*specs.values(), *operations.values()]


# ── entry points ─────────────────────────────────────────────────────────


def parse(data: bytes, entry: dict[str, Any], scope: ScopeFilter) -> list[Record]:
    """Records for the contract in ``data``: its ``api_spec`` records, then the operations.

    Every URL in the result is in scope. Raises :class:`ContractError` when
    ``data`` is not the kind of contract the entry says it is.
    """
    document = _decode(data)
    declared = str(entry.get("format") or "auto")
    kind = declared
    if declared == "auto":
        kind = "postman" if _is_postman(document) else "openapi" if _is_openapi(document) else ""
    extra = {
        "source": "operator",
        "contract": str(entry.get("path") or ""),
        "contract_sha256": hashlib.sha256(data).hexdigest(),
    }
    try:
        if kind == "openapi" and _is_openapi(document):
            return _openapi(document, entry, scope, extra)
        if kind == "postman" and isinstance(document.get("item"), list):
            return _postman(document, entry, scope, extra)
    except (TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise ContractError(f"malformed document ({type(exc).__name__})") from exc
    raise ContractError(
        "not an OpenAPI / Swagger document or a Postman v2 collection"
        if declared == "auto"
        else f"not a {declared} document"
    )


def load(control_dir: Path, entry: dict[str, Any], scope: ScopeFilter) -> list[Record]:
    """Read one ``pipeline.api_contracts`` entry and return its in-scope records.

    ``control_dir`` is ``<control>/<engagement>``; the file is looked up under
    its ``contracts/`` directory and only read. Nothing is requested.
    """
    return parse(read(control_dir, entry), entry, scope)


__all__ = [
    "CACHE_STAGE",
    "NAME",
    "ContractError",
    "control_dir_for",
    "key",
    "load",
    "parse",
    "read",
    "ref",
]
