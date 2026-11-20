"""API specification discovery: OpenAPI / Swagger and GraphQL (built in).

Parsers only. The stage sends the requests through the scope-checked client;
this module turns a response body into records.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import urljoin, urlsplit

from buggy.pipeline.schema import (
    Record,
    RecordType,
    as_dict,
    as_list_of,
    host_of,
    normalize_url,
)

OPENAPI_TOOL = "openapi"
GRAPHQL_TOOL = "graphql"

OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.yaml",
    "/swagger.yaml",
    "/api-docs/swagger-ui-init.js",
    "/swagger-ui-init.js",
)

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query")

INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
    "subscriptionType { name } types { kind name fields(includeDeprecated: true) { name "
    "args { name type { kind name ofType { kind name } } } "
    "type { kind name ofType { kind name } } } } } }"
)

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_MAX_LIST = 200
_MAX_SCHEMA_DEPTH = 6


def _embedded_swagger_doc(text: str) -> dict[str, Any] | None:
    """The ``swaggerDoc`` object swagger-ui-express inlines into its init script."""
    marker = text.find('"swaggerDoc"')
    if marker < 0:
        return None
    start = text.find("{", marker)
    if start < 0:
        return None
    depth, in_string, escaped = 0, False, False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    doc = json.loads(text[start : index + 1])
                except json.JSONDecodeError:
                    return None
                return doc if isinstance(doc, dict) else None
    return None


def load_spec(text: str) -> dict[str, Any] | None:
    """Decode an OpenAPI / Swagger document from JSON, YAML or a swagger-ui init script."""
    stripped = text.lstrip()
    document: Any = None
    if stripped.startswith("{"):
        try:
            document = json.loads(stripped)
        except json.JSONDecodeError:
            document = None
    if document is None and '"swaggerDoc"' in text:
        document = _embedded_swagger_doc(text)
    if (
        document is None
        and ("openapi:" in text or "swagger:" in text)
        and "<html" not in text[:2000].lower()
    ):
        try:
            import yaml  # noqa: PLC0415 - optional dependency

            document = yaml.safe_load(text)
        except Exception:  # noqa: BLE001 - not YAML, or PyYAML absent
            document = None
    if not isinstance(document, dict):
        return None
    if not (document.get("openapi") or document.get("swagger")):
        return None
    if not isinstance(document.get("paths"), dict):
        return None
    return document


def _base_url(spec: dict[str, Any], spec_url: str) -> str:
    """Where the described API is served, resolved against the spec's own URL."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        return urljoin(spec_url, str(servers[0].get("url") or "/"))
    if spec.get("swagger"):
        origin = urlsplit(spec_url)
        host = str(spec.get("host") or origin.netloc)
        schemes = spec.get("schemes") or [origin.scheme]
        scheme = str(schemes[0]) if isinstance(schemes, list) and schemes else origin.scheme
        return f"{scheme}://{host}{spec.get('basePath') or ''}"
    return urljoin(spec_url, "/")


def _deref(
    spec: dict[str, Any], node: Any, trail: tuple[str, ...]
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """``node`` with its local ``$ref`` chain followed, and the references taken.

    A reference outside the document, one that points at nothing, and one
    already on ``trail`` (a schema that contains itself) resolve to ``{}``.
    """
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if not ref.startswith("#/") or ref in trail:
            return {}, trail
        trail = (*trail, ref)
        node = spec
        for step in ref[2:].split("/"):
            node = (
                node.get(step.replace("~1", "/").replace("~0", "~"))
                if isinstance(node, dict)
                else None
            )
    return (node if isinstance(node, dict) else {}), trail


def _schema_names(
    spec: dict[str, Any],
    schema: Any,
    prefix: str,
    trail: tuple[str, ...],
    depth: int,
    names: dict[str, None],
) -> bool:
    """Add the dotted name of every leaf property of ``schema``; whether it had any.

    The names are the ones ``params`` gives a JSON Schema: ``profile.age`` for
    a nested object, ``items[].id`` for an array of objects.
    """
    node, trail = _deref(spec, schema, trail)
    if not node or depth > _MAX_SCHEMA_DEPTH or len(names) >= _MAX_LIST:
        return False
    found = False
    for keyword in ("allOf", "oneOf", "anyOf"):
        for branch in as_list_of(node.get(keyword)):
            found |= _schema_names(spec, branch, prefix, trail, depth + 1, names)
    if isinstance(node.get("items"), dict):
        found |= _schema_names(spec, node["items"], f"{prefix}[]", trail, depth + 1, names)
    for name, child in as_dict(node.get("properties")).items():
        dotted = f"{prefix}.{name}" if prefix else str(name)
        if not _schema_names(spec, child, dotted, trail, depth + 1, names):
            names.setdefault(dotted)
        found = True
    return found


def _body_properties(
    spec: dict[str, Any], operation: dict[str, Any], parameters: list[Any]
) -> list[str]:
    """Property names of the request body an operation declares, references resolved.

    OpenAPI 3 keeps the schema under ``requestBody.content.<media type>``;
    Swagger 2 in the parameter that is ``in: body``. Names only: an example or
    a default in the schema is never copied.
    """
    names: dict[str, None] = {}
    body, trail = _deref(spec, operation.get("requestBody"), ())
    content = as_dict(body.get("content"))
    for media in sorted(content, key=str):
        _schema_names(spec, as_dict(content[media]).get("schema"), "", trail, 0, names)
    for parameter in parameters:
        declared, trail = _deref(spec, parameter, ())
        if declared.get("in") == "body":
            _schema_names(spec, declared.get("schema"), "", trail, 0, names)
    return list(names)[:_MAX_LIST]


def openapi_operations(
    spec: dict[str, Any],
    *,
    base: str,
    spec_ref: str,
    asset: str = "",
    tool: str = OPENAPI_TOOL,
    extra: dict[str, Any] | None = None,
) -> list[Record]:
    """One ``api_operation`` record per path and method of ``spec``, served under ``base``.

    Shared by the discovery stage (``spec_ref`` is the URL the document was
    fetched from) and by operator-supplied contracts (``spec_ref`` names the
    file). ``asset`` is used for an operation whose URL has no host; ``extra``
    is added to every record's attrs.
    """
    global_security = bool(spec.get("security"))
    operations: list[Record] = []
    for path, item in spec["paths"].items():
        if not isinstance(item, dict) or not isinstance(path, str):
            continue
        shared = as_list_of(item.get("parameters"))
        for method in _HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            own = as_list_of(operation.get("parameters"))
            parameters = [
                {
                    "name": str(p.get("name")),
                    "in": str(p.get("in")),
                    "required": bool(p.get("required", False)),
                }
                for p in [*shared, *own]
                if isinstance(p, dict) and p.get("name")
            ][:_MAX_LIST]
            body = operation.get("requestBody")
            body_types = (
                sorted(body["content"])
                if isinstance(body, dict) and isinstance(body.get("content"), dict)
                else []
            )
            security = operation.get("security")
            auth_required = bool(security) if security is not None else global_security
            url = normalize_url(f"{base}{path}")
            operations.append(
                Record(
                    type=RecordType.API_OPERATION,
                    asset=host_of(url) or asset,
                    value=f"{method.upper()} {url}",
                    source_tool=tool,
                    attrs={
                        "method": method.upper(),
                        "url": url,
                        "path": path,
                        "operation_id": str(operation.get("operationId") or ""),
                        "summary": str(operation.get("summary") or "")[:300],
                        "tags": [str(t) for t in operation.get("tags") or []][:20],
                        "parameters": parameters,
                        "request_body_types": body_types,
                        "request_body_properties": _body_properties(
                            spec, operation, [*shared, *own]
                        ),
                        "auth_required": auth_required,
                        "spec_url": spec_ref,
                        **(extra or {}),
                    },
                )
            )
    return operations


def openapi_spec_attrs(spec: dict[str, Any], *, base: str, operation_count: int) -> dict[str, Any]:
    """The attrs of the ``api_spec`` record that describes ``spec``."""
    info = as_dict(spec.get("info"))
    components = as_dict(spec.get("components"))
    schemes = components.get("securitySchemes") or spec.get("securityDefinitions") or {}
    return {
        "format": "openapi" if spec.get("openapi") else "swagger",
        "spec_version": str(spec.get("openapi") or spec.get("swagger")),
        "title": str(info.get("title") or "")[:200],
        "api_version": str(info.get("version") or ""),
        "base_url": base,
        "operation_count": operation_count,
        "security_schemes": sorted(schemes) if isinstance(schemes, dict) else [],
    }


def parse_openapi(spec: dict[str, Any], *, spec_url: str) -> Iterator[Record]:
    spec_url = normalize_url(spec_url)
    asset = host_of(spec_url)
    base = _base_url(spec, spec_url).rstrip("/")
    operations = openapi_operations(spec, base=base, spec_ref=spec_url, asset=asset)
    yield Record(
        type=RecordType.API_SPEC,
        asset=asset,
        value=spec_url,
        source_tool=OPENAPI_TOOL,
        attrs=openapi_spec_attrs(spec, base=base, operation_count=len(operations)),
    )
    yield from operations


def parse_introspection(body: Any, *, endpoint: str) -> Iterator[Record]:
    """A GraphQL record when ``body`` is a successful introspection response."""
    schema = (body.get("data") or {}).get("__schema") if isinstance(body, dict) else None
    if not isinstance(schema, dict):
        return
    endpoint = normalize_url(endpoint)

    def _root(key: str) -> str:
        node = schema.get(key)
        return str(node.get("name")) if isinstance(node, dict) and node.get("name") else ""

    types = [t for t in schema.get("types") or [] if isinstance(t, dict)]
    by_name = {str(t.get("name")): t for t in types}

    def _fields(type_name: str) -> list[dict[str, Any]]:
        node = by_name.get(type_name) or {}
        out = []
        for item in node.get("fields") or []:
            if isinstance(item, dict) and item.get("name"):
                out.append(
                    {
                        "name": str(item["name"]),
                        "args": [
                            str(a.get("name"))
                            for a in item.get("args") or []
                            if isinstance(a, dict) and a.get("name")
                        ][:30],
                    }
                )
        return out[:_MAX_LIST]

    query_type, mutation_type, subscription_type = (
        _root("queryType"),
        _root("mutationType"),
        _root("subscriptionType"),
    )
    yield Record(
        type=RecordType.GRAPHQL,
        asset=host_of(endpoint),
        value=endpoint,
        source_tool=GRAPHQL_TOOL,
        attrs={
            "introspection_enabled": True,
            "query_type": query_type,
            "mutation_type": mutation_type,
            "subscription_type": subscription_type,
            "queries": _fields(query_type),
            "mutations": _fields(mutation_type),
            "subscriptions": _fields(subscription_type),
            "type_count": len([t for t in types if not str(t.get("name", "")).startswith("__")]),
        },
    )
