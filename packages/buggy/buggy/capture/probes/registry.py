"""Probe registry and dispatch."""

from __future__ import annotations

from typing import Any

from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.capture.probes import checks
from buggy.capture.probes.base import Context, ProbeInputError, ProbeSpec
from buggy.capture.probes.injection import sqli

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
