"""Candidate queue: every lead in one deduplicated list, and what to prove next.

Three producers report leads: the pipeline's scanner (``vulnerability``
records), the deterministic probes (``probe_run`` results) and the agents. The
``from_*`` functions turn the first two, and the recon report's ranked surface,
into Finding-shaped dicts; :func:`enqueue` submits them through the finding
service, where the stable finding id makes the same lead from two producers
one row (assertions unioned, the higher severity kept, sources joined).
:func:`next_candidates` hands out the most valuable candidates first and lets
an agent claim what it takes, so that two agents do not work the same lead.

Nothing here sends a request, calls the verifier or decides anything about a
finding: everything stays a ``candidate`` until the verifier re-proves it.

Assertions built from a probe result
------------------------------------

A probe's result names its captures (``evidence_capture_ids`` in a fixed
order, or ``details.captures`` by role) and records what each one answered.
Only what the result records is asserted:

================  ==========================================================
``idor``          owner: status. Other identity: status, same as the owner's
                  response, the owner markers found. The request without
                  credentials too, when it also received the object.
``jwt_alg_none``  corrupted signature (control): status. Unsigned token: status.
``ssrf_canary``   the request that carried the canary URL: status.
``numeric_boundary``  each accepted out-of-range request: status.
``mass_assignment``   the request with the extra fields: status.
``sqli``          boolean: TRUE condition: status, same as the baseline; FALSE
                  condition: status, differs from the baseline. Error: single
                  quote: status, differs from the two-quote control; the
                  control: status. Time: none.
``xss_reflected`` the request of each proven context: status, and the probe
                  string in the body as it was sent.
``graphql_checks``    none.
================  ==========================================================

"None" means the result records nothing a replay could be checked against (a
delay, or no status at all): the candidate is queued without assertions and
the verifier will call it inconclusive rather than confirm it. For
``ssrf_canary`` (the proof is a callback) and ``mass_assignment`` (the proof
is a stored field) the status is all the result records that an expectation
can state, so a replay re-proves less than the probe did.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

from buggy.capture.gateway import ALLOWED_METHODS
from buggy.findings.chains import invariant_for, probe_of
from buggy.findings.grade import known_issue_class, known_issue_endpoint, known_issue_template
from buggy.findings.model import (
    CLASSES,
    MAX_ASSERTIONS,
    MAX_EXPECT_STRINGS,
    MAX_SHORT,
    MAX_TITLE,
    SEVERITIES,
    Finding,
    Severity,
    Status,
    VulnClass,
    finding_id,
    normalize_endpoint,
    severity_rank,
)
from buggy.findings.ruled_out import Ledger
from buggy.findings.store import FindingStore
from buggy.findings.verifier import SAME_AS_MIN
from buggy.pipeline.report import remediation_for

SOURCE_PIPELINE = "pipeline:nuclei"
SOURCE_SURFACE = "pipeline:surface"
SOURCE_PROBE_PREFIX = "probe:"

#: The scanner tag of a template that only names a technology.
TECH_TAG = "tech"

#: A claim nobody renewed for this long is free again.
LEASE_SECONDS = 15 * 60

#: Which class is worked first when assertions and severity are equal.
CLASS_PRIORITY: tuple[str, ...] = (
    VulnClass.ACCESS_CONTROL.value,
    VulnClass.AUTH_SESSION.value,
    VulnClass.SSRF.value,
    VulnClass.BUSINESS_LOGIC.value,
    VulnClass.API.value,
    VulnClass.GRAPHQL.value,
    VulnClass.INJECTION.value,
    VulnClass.XSS.value,
    VulnClass.FILE_HANDLING.value,
    VulnClass.CSRF.value,
    VulnClass.OPEN_REDIRECT.value,
    VulnClass.CRYPTO.value,
    VulnClass.MISCONFIGURATION.value,
    VulnClass.INFO_EXPOSURE.value,
)

#: The severity a probe's positive result is filed at, by class. A probe result
#: carries none; this is the claim's starting point and the grader caps it.
PROBE_SEVERITY: dict[str, str] = {
    VulnClass.ACCESS_CONTROL.value: Severity.HIGH.value,
    VulnClass.AUTH_SESSION.value: Severity.HIGH.value,
    VulnClass.SSRF.value: Severity.HIGH.value,
    VulnClass.INJECTION.value: Severity.HIGH.value,
    VulnClass.FILE_HANDLING.value: Severity.HIGH.value,
    VulnClass.BUSINESS_LOGIC.value: Severity.MEDIUM.value,
    VulnClass.API.value: Severity.MEDIUM.value,
    VulnClass.XSS.value: Severity.MEDIUM.value,
    VulnClass.CSRF.value: Severity.MEDIUM.value,
    VulnClass.CRYPTO.value: Severity.MEDIUM.value,
    VulnClass.GRAPHQL.value: Severity.LOW.value,
    VulnClass.OPEN_REDIRECT.value: Severity.LOW.value,
    VulnClass.MISCONFIGURATION.value: Severity.LOW.value,
    VulnClass.INFO_EXPOSURE.value: Severity.LOW.value,
}

# The method a probe sends when its result does not record one (``probes/registry.py``).
_PROBE_METHOD = {
    "ssrf_canary": "POST",
    "numeric_boundary": "POST",
    "mass_assignment": "POST",
    "graphql_checks": "POST",
}
# ``checks.idor`` calls a response the owner's object at this similarity.
_IDOR_EXPOSED = 0.9

_CWE_NUMBER = re.compile(r"\d{1,7}")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return [] if value in (None, "") else [value]


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


def _is_status(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599


def _cwe(values: Any) -> str:
    for value in _as_list(values):
        number = _CWE_NUMBER.search(str(value))
        if number is not None and int(number.group(0)) > 0:
            return f"CWE-{int(number.group(0))}"
    return ""


def _path(endpoint: str) -> str:
    normal = normalize_endpoint(endpoint)
    parts = urlsplit(normal)
    return (parts.path or "/") if parts.scheme and parts.netloc else normal


def _candidate(
    engagement: str,
    *,
    title: str,
    vuln_class: str,
    severity: str,
    endpoint: str,
    source: str,
    cwe: str = "",
    method: str = "GET",
    parameter: str = "",
    description: str = "",
    remediation: str = "",
    assertions: list[dict[str, Any]] | None = None,
    invariant: str = "",
    entry_point: str = "",
) -> dict[str, Any]:
    """A candidate in the contract's shape. The service validates it on submission."""
    endpoint = normalize_endpoint(endpoint)
    return {
        "invariant": invariant,
        "entry_point": entry_point,
        "id": finding_id(engagement, vuln_class, endpoint, parameter),
        "engagement": engagement,
        "title": title[:MAX_TITLE],
        "class": vuln_class,
        "cwe": cwe,
        "severity": severity,
        "endpoint": endpoint,
        "method": method,
        "parameter": parameter,
        "source": source,
        "description": description,
        "remediation": remediation,
        "assertions": list(assertions or []),
        "status": Status.CANDIDATE.value,
        "verification": {"at": 0.0, "replay_capture_ids": [], "reasons": []},
        "grade": None,
        "grade_reasons": [],
        "created_at": 0.0,
        "updated_at": 0.0,
    }


# ── pipeline scanner hits ───────────────────────────────────────────


def _tags(attrs: dict[str, Any]) -> set[str]:
    return {
        part.strip().lower()
        for tag in _as_list(attrs.get("tags"))
        for part in str(tag).split(",")
        if part.strip()
    }


def from_pipeline(records: list[dict], engagement: str) -> list[dict]:
    """Recon ``vulnerability`` records as candidates (``source="pipeline:nuclei"``).

    The class comes from the record's CWE ids, then its template tags and id
    (:func:`buggy.findings.grade.known_issue_class`); the severity is the
    record's, ``info`` when it has none. Left out: a record of another type or
    another engagement, a template that only names a technology (severity
    ``info`` and tag ``tech``), and a record whose class or location cannot
    be told. A scanner hit carries no capture, so it has no assertions.
    """
    out: list[dict] = []
    for record in records or []:
        if not isinstance(record, dict):
            continue
        if record.get("type") not in (None, "", "vulnerability"):
            continue
        if record.get("engagement") not in (None, "", engagement):
            continue
        attrs = _as_dict(record.get("attrs"))
        severity = _text(attrs.get("severity")).lower()
        if severity not in SEVERITIES:
            severity = Severity.INFO.value
        if severity == Severity.INFO.value and TECH_TAG in _tags(attrs):
            continue
        vuln_class = known_issue_class(record)
        endpoint = known_issue_endpoint(record)
        if not vuln_class or not endpoint:
            continue
        template = known_issue_template(record) or "(unnamed)"
        name = _text(attrs.get("name"))
        described = _text(attrs.get("description"))
        out.append(
            _candidate(
                engagement,
                title=f"{name} ({template})" if name and name != template else template,
                vuln_class=vuln_class,
                severity=severity,
                endpoint=endpoint,
                source=SOURCE_PIPELINE,
                cwe=_cwe(attrs.get("cwe")),
                description=(
                    f"Scanner template {template} matched at {endpoint}. Not re-proved."
                    + (f" {described}" if described else "")
                ),
                remediation=remediation_for(template),
            )
        )
    return out


# ── probe results ───────────────────────────────────────────────────


def _assertion(
    capture_id: Any,
    *,
    status: Any = None,
    same_as: Any = "",
    differs_from: Any = "",
    body_contains: Iterable[Any] = (),
) -> dict[str, Any] | None:
    """One assertion, or ``None`` when the capture is not named or nothing would be checked."""
    capture = _text(capture_id)
    strings = [s for s in body_contains if isinstance(s, str) and s and len(s) <= MAX_SHORT]
    expect = {
        "status": status if _is_status(status) else None,
        "body_contains": list(dict.fromkeys(strings))[:MAX_EXPECT_STRINGS],
        "body_not_contains": [],
        "differs_from": _text(differs_from),
        "same_as": _text(same_as),
    }
    if not capture or not (
        expect["status"] is not None
        or expect["body_contains"]
        or expect["differs_from"]
        or expect["same_as"]
    ):
        return None
    return {"capture_id": capture, "identity": "", "expect": expect}


def _at(ids: list[str], index: int) -> str:
    return ids[index] if index < len(ids) else ""


def _idor(ids: list[str], details: dict[str, Any]) -> list[dict[str, Any] | None]:
    # evidence: owner, other identity, then the request without credentials.
    owner, attacker, anonymous = _at(ids, 0), _at(ids, 1), _at(ids, 2)
    markers = [m for m in _as_list(details.get("markers_found")) if isinstance(m, str)]
    # Proved by markers alone, the two responses need not be alike.
    alike = not markers or _number(details.get("similarity")) >= SAME_AS_MIN
    out = [
        _assertion(owner, status=details.get("owner_status")),
        _assertion(
            attacker,
            status=details.get("attacker_status"),
            same_as=owner if alike else "",
            body_contains=markers,
        ),
    ]
    open_status = details.get("unauthenticated_status")
    if (
        isinstance(open_status, int)
        and _is_status(open_status)
        and 200 <= open_status < 300
        and _number(details.get("unauthenticated_similarity")) >= _IDOR_EXPOSED
    ):
        out.append(_assertion(anonymous, status=open_status, same_as=owner))
    return out


def _jwt_alg_none(ids: list[str], details: dict[str, Any]) -> list[dict[str, Any] | None]:
    # evidence: valid token, corrupted signature (control), unsigned token.
    return [
        _assertion(_at(ids, 1), status=details.get("corrupted_signature_status")),
        _assertion(_at(ids, 2), status=details.get("unsigned_status")),
    ]


def _ssrf_canary(ids: list[str], details: dict[str, Any]) -> list[dict[str, Any] | None]:
    return [_assertion(_at(ids, 0), status=details.get("request_status"))]


def _mass_assignment(ids: list[str], details: dict[str, Any]) -> list[dict[str, Any] | None]:
    # evidence: the request with the extra fields, then the read-back (no status recorded).
    return [_assertion(_at(ids, 0), status=details.get("status"))]


def _numeric_boundary(ids: list[str], details: dict[str, Any]) -> list[dict[str, Any] | None]:
    # evidence: one request per tested value, in order.
    tested = _as_list(details.get("tested"))
    if len(tested) != len(ids) or any(tested.count(value) > 1 for value in tested):
        return []  # which capture carried which value cannot be told
    out: list[dict[str, Any] | None] = []
    for entry in _as_list(details.get("accepted")):
        value = _as_dict(entry).get("value")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value > 0:
            continue
        if value in tested:
            out.append(_assertion(ids[tested.index(value)], status=_as_dict(entry).get("status")))
    return out


def _sqli(_ids: list[str], details: dict[str, Any]) -> list[dict[str, Any] | None]:
    captures = _as_dict(details.get("captures"))
    technique = details.get("technique")
    if technique == "boolean":
        baseline = captures.get("baseline")
        for entry in _as_list(details.get("boolean")):
            entry = _as_dict(entry)
            if entry.get("positive") is True:
                variant = entry.get("variant")
                return [
                    _assertion(
                        captures.get(f"boolean_true_{variant}"),
                        status=entry.get("true_status"),
                        same_as=baseline,
                    ),
                    _assertion(
                        captures.get(f"boolean_false_{variant}"),
                        status=entry.get("false_status"),
                        differs_from=baseline,
                    ),
                ]
    if technique == "error":
        error = _as_dict(details.get("error"))
        control = captures.get("error_control")
        return [
            _assertion(
                captures.get("error_quote"), status=error.get("quote_status"), differs_from=control
            ),
            _assertion(control, status=error.get("control_status")),
        ]
    return []  # time: the proof is a delay, which no expectation can state


def _xss_reflected(_ids: list[str], details: dict[str, Any]) -> list[dict[str, Any] | None]:
    # A proven context: its probe string came back with the breaking characters intact.
    return [
        _assertion(
            entry.get("capture"), status=entry.get("status"), body_contains=[entry.get("payload")]
        )
        for entry in map(_as_dict, _as_list(details.get("contexts")))
        if entry.get("vulnerable") is True
    ]


_Layout = Callable[[list[str], dict[str, Any]], list[dict[str, Any] | None]]
#: Probe name -> how its captures become assertions. A probe not listed here
#: (``graphql_checks`` records no status) is queued without assertions.
PROBE_LAYOUTS: dict[str, _Layout] = {
    "idor": _idor,
    "jwt_alg_none": _jwt_alg_none,
    "ssrf_canary": _ssrf_canary,
    "numeric_boundary": _numeric_boundary,
    "mass_assignment": _mass_assignment,
    "sqli": _sqli,
    "xss_reflected": _xss_reflected,
}


def probe_assertions(result: dict[str, Any]) -> list[dict[str, Any]]:
    """The assertions a probe result supports (see the module's table); possibly none.

    A run sent as a declared test account (``result["identity"]``) puts that
    name on every assertion, so the verifier re-sends them as the same account.
    """
    layout = PROBE_LAYOUTS.get(_text(result.get("probe")))
    if layout is None:
        return []
    identity = _text(result.get("identity"))[:MAX_SHORT]
    ids = [_text(value) for value in _as_list(result.get("evidence_capture_ids"))]
    out: list[dict[str, Any]] = []
    for assertion in layout(ids, _as_dict(result.get("details"))):
        if assertion is None:
            continue
        assertion = {**assertion, "identity": identity}
        if assertion not in out:
            out.append(assertion)
    return out[:MAX_ASSERTIONS]


def from_probe(result: dict, engagement: str, url: str, parameter: str = "") -> dict | None:
    """A ``probe_run`` result as a candidate, or ``None`` unless ``vulnerable is True``.

    ``False`` (not vulnerable) and ``None`` (could not tell) both produce
    nothing, as does anything that is not a result. ``url`` is the endpoint
    the probe was run against; ``parameter`` defaults to the one the result
    names (``details.parameter``), if any. A run sent as an identity carries it
    on every assertion (:func:`probe_assertions`).
    """
    if not isinstance(result, dict) or result.get("vulnerable") is not True:
        return None
    probe = _text(result.get("probe")) or "unknown"
    details = _as_dict(result.get("details"))
    cwe = _cwe(result.get("cwe"))
    # An explicit class wins, then the CWE; an unknown class is left for validation to name.
    vuln_class = known_issue_class({"class": result.get("class"), "attrs": {"cwe": cwe}})
    vuln_class = vuln_class or _text(result.get("class")).lower()
    method = _text(details.get("method")).upper()
    if method not in ALLOWED_METHODS:
        method = _PROBE_METHOD.get(probe, "GET")
    parameter = _text(parameter) or _text(details.get("parameter"))
    captures = [_text(v) for v in _as_list(result.get("evidence_capture_ids")) if _text(v)]
    summary = _text(result.get("summary")).rstrip(".") or "the target was reported vulnerable"
    return _candidate(
        engagement,
        title=f"{vuln_class.replace('_', ' ')} ({probe}) on {method} {_path(url)}",
        vuln_class=vuln_class,
        severity=PROBE_SEVERITY.get(vuln_class, Severity.MEDIUM.value),
        endpoint=_text(url),
        source=SOURCE_PROBE_PREFIX + probe,
        cwe=cwe,
        method=method,
        parameter=parameter,
        description=(
            f"Probe {probe}: {summary}."
            + (f" Captures: {', '.join(captures)}." if captures else "")
        ),
        remediation=_text(result.get("remediation")),
        assertions=probe_assertions(result),
        invariant=invariant_for(probe, vuln_class),
        entry_point=f"{method} {_text(url)}"[:MAX_SHORT],
    )


SOURCE_RECIPE_PREFIX = "recipe:"


def from_recipe(result: dict, engagement: str, recipe: dict) -> dict | None:
    """A ``recipe_run`` result as a candidate, or ``None`` unless ``vulnerable is True``.

    ``recipe`` is the validated recipe's JSON (``buggy.capture.recipes``):
    class, title, endpoint, parameter and remediation come from it, the
    severity from the same per-class table probes use. The finding carries no
    assertions: it is re-proved by running the recipe again, controls included.
    """
    if not isinstance(result, dict) or result.get("vulnerable") is not True:
        return None
    recipe = _as_dict(recipe)
    name = _text(recipe.get("name")) or "unnamed"
    vuln_class = _text(recipe.get("class")).lower()
    endpoint = _text(recipe.get("endpoint"))
    steps = [_as_dict(s) for s in _as_list(recipe.get("steps"))]
    wanted = _path(endpoint)

    def same_path(url: str) -> bool:
        # A segment with a placeholder ({id}, {{order}}) stands for any value.
        left = _path(url.split("?")[0]).rstrip("/").split("/")
        right = wanted.rstrip("/").split("/")
        return len(left) == len(right) and all(
            a == b or "{" in a or "{" in b for a, b in zip(left, right, strict=True)
        )

    on_endpoint = [s for s in steps if same_path(_text(s.get("url")))]
    method = _text((on_endpoint or steps or [{}])[0].get("method")).upper()
    if method not in ALLOWED_METHODS:
        method = "GET"
    first = steps[0] if steps else {}
    entry_point = f"{_text(first.get('method')).upper() or 'GET'} {_text(first.get('url'))}"
    captures = [_text(v) for v in _as_list(result.get("evidence_capture_ids")) if _text(v)]
    summary = (
        _text(result.get("summary")).rstrip(".") or "the recipe reported the target vulnerable"
    )
    return _candidate(
        engagement,
        title=_text(recipe.get("title")) or f"{vuln_class.replace('_', ' ')} on {wanted}",
        vuln_class=vuln_class,
        severity=PROBE_SEVERITY.get(vuln_class, Severity.MEDIUM.value),
        endpoint=endpoint,
        source=SOURCE_RECIPE_PREFIX + name,
        method=method,
        parameter=_text(recipe.get("parameter")),
        description=(
            f"Recipe {name} ({len(steps)} steps, built by the agent and run through the "
            f"gateway): {summary}." + (f" Captures: {', '.join(captures)}." if captures else "")
        ),
        remediation=_text(recipe.get("remediation")),
        invariant=_text(recipe.get("invariant")) or invariant_for("", vuln_class),
        entry_point=entry_point[:MAX_SHORT] if _text(first.get("url")) else "",
    )


# ── the report's ranked surface ─────────────────────────────────────


def from_ranked(candidates: list[dict], engagement: str) -> list[dict]:
    """``rank_candidates`` rows as leads: ``source="pipeline:surface"``, ``info``, no assertions.

    A row is a place worth testing, not an observed weakness, so it is filed
    at the lowest severity: it never raises the severity of a finding it
    merges into. A row without a known class or a location is left out.
    """
    out: list[dict] = []
    for row in candidates or []:
        if not isinstance(row, dict):
            continue
        vuln_class = _text(row.get("class")).lower()
        where = _text(row.get("where"))
        if vuln_class not in CLASSES or not where:
            continue
        # "GET https://..." names a method; anything else is a URL as written.
        head, _, rest = where.partition(" ")
        if rest.strip() and head.upper() in ALLOWED_METHODS:
            method, endpoint = head.upper(), rest.strip()
        else:
            method, endpoint = "GET", where
        why = _text(row.get("why"))
        probe = _text(row.get("probe"))
        out.append(
            _candidate(
                engagement,
                title=f"{vuln_class.replace('_', ' ')} on {method} {_path(endpoint)}",
                vuln_class=vuln_class,
                severity=Severity.INFO.value,
                endpoint=endpoint,
                source=SOURCE_SURFACE,
                method=method,
                description=(
                    "Recon lead, not an observed weakness"
                    + (f": {why}." if why else ".")
                    + (f" Suggested check: {probe}." if probe else "")
                ),
            )
        )
    return out


# ── the queue ───────────────────────────────────────────────────────


def enqueue(service: Any, items: Iterable[Any], actor: str) -> dict[str, Any]:
    """Submit every item to the finding service; items with the same id become one row.

    ``service`` is a :class:`buggy.findings.service.FindingService`: its
    ``submit`` unions the assertions, keeps the higher severity and joins the
    sources. ``None`` items (a probe result that was not a candidate) are
    skipped. An item the service rejects is reported in ``errors`` with its
    position; the others are still submitted.
    """
    ids: list[str] = []
    errors: list[dict[str, Any]] = []
    submitted = created = merged = 0
    for index, item in enumerate(items or []):
        if item is None:
            continue
        engagement = _text(item.get("engagement")) if isinstance(item, dict) else ""
        if not engagement:
            errors.append(
                {
                    "index": index,
                    "code": "INVALID_FINDING",
                    "detail": "engagement: is required",
                }
            )
            continue
        probe = probe_of(_text(item.get("source")))
        if probe and not _text(item.get("invariant")):
            # A probe's finding breaks the probe's fixed invariant (buggy.findings.chains).
            item = {
                **item,
                "invariant": invariant_for(probe, _text(item.get("class")).lower()),
                "entry_point": _text(item.get("entry_point"))
                or f"{_text(item.get('method')).upper() or 'GET'} {_text(item.get('endpoint'))}"[
                    :MAX_SHORT
                ],
            }
        out = service.submit(engagement, item, actor)
        if not out.get("ok"):
            error = {"index": index, "code": out.get("code"), "detail": out.get("detail")}
            if out.get("errors"):
                error["errors"] = out["errors"]
            errors.append(error)
            continue
        submitted += 1
        created += 1 if out.get("created") else 0
        merged += 1 if out.get("merged") else 0
        found = out["finding"]["id"]
        if found not in ids:
            ids.append(found)
    return {
        "ok": not errors,
        "submitted": submitted,
        "created": created,
        "merged": merged,
        "ids": ids,
        "errors": errors,
    }


def queue_order(finding: Finding) -> tuple[int, int, int, float, str]:
    """Sort key: with assertions first, then severity, class priority, oldest first."""
    cls = finding.vuln_class
    return (
        0 if finding.assertions else 1,
        severity_rank(finding.severity) if finding.severity in SEVERITIES else len(SEVERITIES),
        CLASS_PRIORITY.index(cls) if cls in CLASS_PRIORITY else len(CLASS_PRIORITY),
        finding.created_at,
        finding.id,
    )


def next_candidates(
    store: FindingStore,
    engagement: str,
    *,
    limit: int = 5,
    claimed_by: str = "",
    ledger: Ledger | None = None,
    skipped: dict[str, list[dict]] | None = None,
) -> list[dict]:
    """The next ``limit`` candidates of the engagement, most valuable first.

    Order: candidates with assertions (they can be verified now), then by
    severity, then by ``CLASS_PRIORITY``, then oldest first. Only findings
    whose status is ``candidate`` are in the queue.

    A lead whose techniques were all ruled out at its endpoint and parameter,
    for a reason that still holds (``buggy.findings.ruled_out``), is not
    handed out; ``skipped`` (when given) collects those ids with the entries
    that rule them out. A lead whose ruling passed its review date is handed
    out again with ``ruled_out_before`` saying why it was out. ``ledger``
    defaults to one over ``store``.

    With ``claimed_by``, every returned candidate is claimed for that name for
    ``LEASE_SECONDS`` (asking again renews it). A candidate somebody else
    claimed is skipped until it is released or the lease runs out, for a
    caller without a name too; such a caller claims nothing. Each row is the
    finding plus ``claimed_by``, ``claimed_at`` and ``claim_expires_at``.
    """
    who = _text(claimed_by)
    wanted = max(0, int(limit))
    out: list[dict] = []
    if not wanted:
        return out
    ledger = ledger or Ledger(store)
    holding = ledger.holding(engagement)
    queue = sorted(store.list(engagement, status=Status.CANDIDATE.value), key=queue_order)
    held = {} if who else store.claims(engagement, lease_seconds=LEASE_SECONDS)
    for finding in queue:
        blocking = ledger.blocking(finding, holding) if holding else []
        if blocking:
            if skipped is not None:
                skipped[finding.id] = [
                    {"id": e["id"], "technique": e["technique"], "reason": e["reason"]}
                    for e in blocking
                ]
            continue
        claimed_at = 0.0
        if who:
            taken = store.claim(engagement, finding.id, who, lease_seconds=LEASE_SECONDS)
            if taken is None:  # somebody else holds it, or it has just been decided
                continue
            claimed_at = taken
        elif finding.id in held:
            continue
        row = {
            **finding.to_dict(),
            "claimed_by": who,
            "claimed_at": claimed_at,
            "claim_expires_at": claimed_at + LEASE_SECONDS if who else 0.0,
        }
        earlier = ledger.earlier(finding)
        if earlier:
            row["ruled_out_before"] = earlier
        out.append(row)
        if len(out) >= wanted:
            break
    return out


def release(store: FindingStore, engagement: str, finding_id: str, claimed_by: str) -> dict:
    """Give a claimed candidate back to the queue. Only the holder's claim is released."""
    who = _text(claimed_by)
    if not who:
        return {
            "ok": False,
            "code": "BAD_ACTOR",
            "detail": "claimed_by is required: a release names whose claim it is",
        }
    return {
        "ok": True,
        "id": finding_id,
        "released": store.release(engagement, finding_id, who),
    }


__all__ = [
    "CLASS_PRIORITY",
    "LEASE_SECONDS",
    "PROBE_LAYOUTS",
    "PROBE_SEVERITY",
    "SOURCE_PIPELINE",
    "SOURCE_RECIPE_PREFIX",
    "SOURCE_SURFACE",
    "enqueue",
    "from_pipeline",
    "from_probe",
    "from_recipe",
    "from_ranked",
    "next_candidates",
    "probe_assertions",
    "queue_order",
    "release",
]
