"""Probe registry and dispatch."""

from __future__ import annotations

from typing import Any

from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.capture.probes import checks
from buggy.capture.probes.base import Context, ProbeInputError, ProbeSpec
from buggy.capture.probes.execution import command_injection, ssti
from buggy.capture.probes.injection import sqli
from buggy.capture.probes.misc import cors, open_redirect, path_traversal
from buggy.capture.probes.xss import xss_reflected

REGISTRY: dict[str, ProbeSpec] = {
    spec.name: spec
    for spec in (
        ProbeSpec(
            "jwt_alg_none", "auth_session", "CWE-347",
            "Does an endpoint accept a JWT with its signature removed (alg=none)?",
            {
                "url": "GET endpoint that requires the token",
                "token": "a valid JWT for a test account",
                "header": "header carrying the token (default Authorization)",
                "claim_overrides": "optional claims to change in the forged token",
                "headers": "optional extra headers",
            },
            False, checks.jwt_alg_none,
        ),
        ProbeSpec(
            "idor", "access_control", "CWE-639",
            "Can a second identity read an object owned by the first?",
            {
                "url": "URL of an object that belongs to the owner",
                "owner_headers": "auth headers of the owning test account",
                "attacker_headers": "auth headers of a different test account",
                "markers": "optional strings unique to the owner's data",
                "check_unauthenticated": "also try with no credentials (default true)",
            },
            False, checks.idor,
        ),
        ProbeSpec(
            "ssrf_canary", "ssrf", "CWE-918",
            "Does the server fetch a caller-supplied URL? Confirmed by a callback.",
            {
                "url": "endpoint; may contain {{CANARY}}",
                "method": "HTTP method (default POST)",
                "body": "body (string or JSON) with {{CANARY}} where the URL goes",
                "headers": "optional headers",
                "wait_seconds": "how long to wait for the callback (default 8)",
            },
            True, checks.ssrf_canary,
        ),
        ProbeSpec(
            "numeric_boundary", "business_logic", "CWE-20",
            "Does the server accept a negative or zero quantity/amount?",
            {
                "url": "endpoint",
                "method": "HTTP method (default POST)",
                "body": "valid JSON body",
                "field": "dotted path of the numeric field",
                "values": "numbers to try (default [-1])",
                "headers": "auth headers",
            },
            True, checks.numeric_boundary,
        ),
        ProbeSpec(
            "mass_assignment", "api", "CWE-915",
            "Does the server store a privileged field supplied by the client?",
            {
                "url": "create/update endpoint",
                "method": "HTTP method (default POST)",
                "body": "valid JSON body",
                "extra_fields": "fields the client should not control, e.g. {\"role\": \"admin\"}",
                "readback_url": "optional URL to read the stored object back",
                "headers": "auth headers",
            },
            True, checks.mass_assignment,
        ),
        ProbeSpec(
            "graphql_checks", "graphql", "CWE-200",
            "GraphQL introspection, field suggestions, and data without credentials.",
            {
                "url": "GraphQL endpoint",
                "headers": "optional auth headers",
                "unauthenticated_query": "optional query that should need credentials",
                "markers": "optional strings that identify sensitive data in the result",
            },
            False, checks.graphql_checks,
        ),
        ProbeSpec(
            "sqli", "injection", "CWE-89",
            "Is one named parameter injectable into SQL? Boolean, error and (opt-in) time "
            "signals, each confirmed by a control. At most 9 requests, no data extraction.",
            {
                "url": "endpoint (the query string may already carry the parameter)",
                "parameter": "name of the parameter to test (dotted path for json)",
                "method": "HTTP method (default GET); any other method counts as "
                "state-changing and goes through the approval gate",
                "location": "where the parameter lives: query | json | form (default query)",
                "value": "a valid baseline value (default: the value already in the request)",
                "body": "request body for json/form (object or string)",
                "headers": "optional headers, e.g. auth",
                "allow_time": "also try 3-second delay payloads (default false)",
            },
            False, sqli,
        ),
        ProbeSpec(
            "xss_reflected", "xss", "CWE-79",
            "Is one named parameter reflected into HTML where its markup characters break out "
            "of their context? Names the context; marker-only strings, nothing that runs. At "
            "most 6 requests, no browser.",
            {
                "url": "endpoint (the query string may already carry the parameter; for "
                "location path it carries a {parameter} placeholder)",
                "parameter": "name of the parameter to test (dotted path for json)",
                "method": "HTTP method (default GET); any other method counts as "
                "state-changing and goes through the approval gate",
                "location": "where the parameter lives: query | json | form | path "
                "(default query)",
                "value": "optional text sent in front of the marker (default: none, the "
                "marker replaces the parameter's value)",
                "body": "request body for json/form (object or string)",
                "headers": "optional headers, e.g. auth or Accept: text/html",
            },
            False, xss_reflected,
        ),
        ProbeSpec(
            "ssti", "injection", "CWE-1336",
            "Is one named parameter evaluated as a server-side template expression? One "
            "arithmetic canary per engine family, confirmed by a plain-digits control; names "
            "the engine family. At most 8 requests, only a multiplication is evaluated.",
            {
                "url": "endpoint (the query string may already carry the parameter)",
                "parameter": "name of the parameter to test (dotted path for json)",
                "method": "HTTP method (default GET); any other method counts as "
                "state-changing and goes through the approval gate",
                "location": "where the parameter lives: query | json | form (default query)",
                "value": "a valid baseline value (default: the value already in the request)",
                "body": "request body for json/form (object or string)",
                "headers": "optional headers, e.g. auth",
            },
            False, ssti,
        ),
        ProbeSpec(
            "command_injection", "injection", "CWE-78",
            "Does one named parameter reach an OS shell? An arithmetic echo and a 3-second "
            "wait behind each separator, each confirmed by a control. At most 11 requests; "
            "only echo, sleep and ping of localhost, nothing is read or written.",
            {
                "url": "endpoint (the query string may already carry the parameter)",
                "parameter": "name of the parameter to test (dotted path for json)",
                "method": "HTTP method (default GET). The payloads are state-changing "
                "whatever the method: where the engagement requires approval they are held",
                "location": "where the parameter lives: query | json | form (default query)",
                "value": "a valid baseline value (default: the value already in the request)",
                "body": "request body for json/form (object or string)",
                "headers": "optional headers, e.g. auth",
                "allow_time": "also try 3-second delay payloads (default true)",
            },
            True, command_injection,
        ),
        ProbeSpec(
            "open_redirect", "open_redirect", "CWE-601",
            "Does one named parameter choose where the user is redirected? A random host under "
            "the reserved .example TLD, then at most 4 bypass forms if the plain one is "
            "refused. At most 6 requests; redirects are never followed.",
            {
                "url": "endpoint (the query string may already carry the parameter; for "
                "location path it carries a {parameter} placeholder)",
                "parameter": "name of the parameter to test (dotted path for json)",
                "method": "HTTP method (default GET); any other method counts as "
                "state-changing and goes through the approval gate",
                "location": "where the parameter lives: query | json | form | path "
                "(default query)",
                "value": "the original value, e.g. an allowed URL (default: the value already "
                "in the request)",
                "body": "request body for json/form (object or string)",
                "headers": "optional headers, e.g. auth",
                "allowlist_hint": "optional allowed URL or host used by the bypass forms "
                "(default: the original value when it is a URL, else the target's host)",
            },
            False, open_redirect,
        ),
        ProbeSpec(
            "path_traversal", "file_handling", "CWE-22",
            "Does one named parameter read a file outside its directory? ../ chains (depth "
            "2-6, plain and URL-encoded, with and without a NUL + extension suffix) to two "
            "world-readable markers only: etc/passwd and windows/win.ini. At most 10 requests.",
            {
                "url": "endpoint (the query string may already carry the parameter; for "
                "location path it carries a {parameter} placeholder)",
                "parameter": "name of the parameter to test (dotted path for json)",
                "method": "HTTP method (default GET); any other method counts as "
                "state-changing and goes through the approval gate",
                "location": "where the parameter lives: query | json | form | path "
                "(default query)",
                "value": "a valid file name (default: the value already in the request; "
                "required for path, written as it goes on the wire)",
                "body": "request body for json/form (object or string)",
                "headers": "optional headers, e.g. auth",
            },
            False, path_traversal,
        ),
        ProbeSpec(
            "cors", "misconfiguration", "CWE-942",
            "Does the endpoint allow a random or null Origin together with credentials? "
            "Three GETs: no Origin, a random .example origin, Origin: null.",
            {
                "url": "endpoint (GET)",
                "headers": "optional headers, e.g. auth (any Origin given here is replaced)",
            },
            False, cors,
        ),
    )
}  # fmt: skip


def describe() -> list[dict[str, Any]]:
    return [
        {
            "probe": spec.name,
            "class": spec.vuln_class,
            "cwe": spec.cwe,
            "summary": spec.summary,
            "params": spec.params,
            "state_changing": spec.state_changing,
        }
        for spec in REGISTRY.values()
    ]


def run_probe(
    gateway: CaptureGateway,
    engagement: str,
    name: str,
    params: dict[str, Any],
    *,
    canary: Canary | None = None,
) -> dict[str, Any]:
    """Run one probe; refusals and bad input come back as structured results."""
    spec = REGISTRY.get(name)
    if spec is None:
        return {"status": "error", "detail": f"unknown probe {name!r}", "probes": sorted(REGISTRY)}
    try:
        result = spec.run(Context(gateway, engagement, name, canary), params)
    except ProbeInputError as exc:
        return {"status": "error", "probe": name, "detail": str(exc), "params": spec.params}
    except GatewayRefusal as refusal:
        return {"probe": name, **refusal.to_dict()}
    return {"status": "completed", **result.to_dict()}


__all__ = ["REGISTRY", "describe", "run_probe"]
