"""Probe registry and dispatch."""

from __future__ import annotations

from typing import Any

from buggy.capture.canary import Canary
from buggy.capture.gateway import SAFE_METHODS, CaptureGateway, GatewayRefusal
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
            False, checks.jwt_alg_none, accepts_identity=False,
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
            False, checks.idor, accepts_identity=False,
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


#: The one parameter every probe shares. Said once here rather than in each table.
IDENTITY_PARAM = "identity"
IDENTITY_NOTE = (
    "Every probe with accepts_identity true also takes an optional top-level "
    '"identity": the name of a declared test account (identities_list). The whole run is then '
    "sent signed in as that account (the gateway attaches its session), the result names it, "
    "and a re-run by finding_verify uses it again."
)


def describe() -> list[dict[str, Any]]:
    return [
        {
            "probe": spec.name,
            "class": spec.vuln_class,
            "cwe": spec.cwe,
            "summary": spec.summary,
            "params": spec.params,
            "state_changing": spec.state_changing,
            "accepts_identity": spec.accepts_identity,
        }
        for spec in REGISTRY.values()
    ]


def split_identity(spec: ProbeSpec, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """``(identity, the parameters the probe function sees)``; raises on a bad identity.

    The caller's dict is not changed.
    """
    if IDENTITY_PARAM not in params:
        return "", params
    raw = params[IDENTITY_PARAM]
    rest = {k: v for k, v in params.items() if k != IDENTITY_PARAM}
    if raw is None or raw == "":
        return "", rest
    if not isinstance(raw, str) or not raw.strip():
        raise ProbeInputError("identity must be the name of a declared test account (a string)")
    if not spec.accepts_identity:
        raise ProbeInputError(
            f"{spec.name} takes the credentials of each account it compares in its own "
            "parameters and does not accept identity; pass the header parameters instead "
            "(or use authz_matrix_run, which compares declared identities)"
        )
    return raw.strip(), rest


def needs_run_approval(spec: ProbeSpec, params: dict[str, Any]) -> bool:
    """Whether a run can change state: the probe says so, or the caller chose such a method.

    Where the engagement requires approval, such a run is approved as a whole
    (one decision for the run), because its requests carry fresh random markers
    and could never match an approval given for one exact request.
    """
    method = str(params.get("method") or "GET").upper()
    return spec.state_changing or method not in SAFE_METHODS or params.get(DECLARED_FLAG) is True


#: A caller may declare that a run changes state although its method is safe
#: (a GET form that changes a password). The flag can only add the approval
#: hold, never remove it, and the probe function does not see it.
DECLARED_FLAG = "state_changing"


def run_probe(
    gateway: CaptureGateway,
    engagement: str,
    name: str,
    params: dict[str, Any],
    *,
    canary: Canary | None = None,
) -> dict[str, Any]:
    """Run one probe; refusals and bad input come back as structured results.

    ``params`` may carry a top-level ``identity`` (a declared test account):
    it is taken out of what the probe function sees and every request of the
    run is sent as that account. It is part of the run's approval fingerprint,
    and a result of such a run names it (``"identity"``).
    """
    spec = REGISTRY.get(name)
    if spec is None:
        return {"status": "error", "detail": f"unknown probe {name!r}", "probes": sorted(REGISTRY)}
    named: dict[str, Any] = {}
    try:
        identity, probe_params = split_identity(spec, params)
        named = {"identity": identity} if identity else {}
        if identity:
            # An unknown name is refused before an approval is filed or a byte is sent.
            gateway.check_identity(engagement, identity)
        grant = None
        declared = probe_params.get(DECLARED_FLAG) is True
        if DECLARED_FLAG in probe_params:
            if not isinstance(probe_params[DECLARED_FLAG], bool):
                raise ProbeInputError(f"{DECLARED_FLAG} must be true or false")
            probe_params = {k: v for k, v in probe_params.items() if k != DECLARED_FLAG}
        if declared or needs_run_approval(spec, probe_params):
            # The declaration is part of what the operator approves.
            approved = {**probe_params, **named, **({DECLARED_FLAG: True} if declared else {})}
            grant = gateway.probe_grant(engagement, name, approved, sends=spec.summary)
        context = Context(gateway, engagement, name, canary, grant, identity)
        result = spec.run(context, probe_params)
    except ProbeInputError as exc:
        return {"status": "error", "probe": name, "detail": str(exc), "params": spec.params}
    except GatewayRefusal as refusal:
        return {"probe": name, **named, **refusal.to_dict()}
    return {"status": "completed", **result.to_dict(), **named}


__all__ = [
    "IDENTITY_NOTE",
    "IDENTITY_PARAM",
    "REGISTRY",
    "describe",
    "needs_run_approval",
    "run_probe",
    "split_identity",
]
