"""Retest: re-run a finding's stored assertions and say whether it is fixed.

A retest re-sends what the finding cites through the independent verifier
(so scope, the approval hold, the rate limit and the capture ledger all apply)
and records one of three outcomes. It never changes the finding's ``status``;
it writes only the retest record (``retest = {at, outcome, capture_ids}``),
``fixed_at`` and the finding's history.

Outcomes
--------

``still_vulnerable``
    Every assertion passed on a fresh replay (what the verifier calls
    ``exploit_verified``). One attempt is enough.

``fixed``
    Two consecutive attempts both end "safe", with the same per-assertion
    result (outcome, response status and failed checks) each time. An attempt
    is safe when every assertion was re-sent and got a response, at least one
    assertion failed, every failed assertion failed in the safe direction (below),
    and, when the finding has more than one assertion, at least one still
    passes (a control showing the target is up and answering this request
    normally, so a broken login or an outage cannot look like a fix).

``inconclusive``
    Anything else: a transport error or a 5xx, a redirect or another status
    that is neither a normal answer nor a refusal, a request that was not
    re-sent (state-changing without ``allow_state_change``, held for approval,
    refused by the gateway), a cited capture that is missing or out of scope,
    or a second attempt that disagrees with the first (unstable target).

The safe direction, per expectation type
----------------------------------------

An assertion that failed is "safe" only if the fresh response has a status
(no transport error) that is 2xx or one of 401, 403, 404, and each failed
check is safe:

* ``status``: the fresh status is 401, 403 or 404 (the attacker is refused or
  the object is hidden), and the expected status was none of those (a claim
  whose proof *was* a refusal is not fixed by another refusal). A 401 counts
  only when it cannot be a stale credential: the replay was sent as a named
  identity (the gateway renews that session on a 401 before answering), or the
  cited request carried no ``Authorization`` or ``Cookie`` header at all.
* ``body_contains``: the proof marker is gone from the response.
* ``body_not_contains``: the text whose absence was the proof (typically an
  "access denied" or "login required" message) is now present.
* ``same_as``: the response is no longer the victim's response (for example
  the attacker now gets their own object). Only when the cited reference
  recorded a response; otherwise there was never anything to compare.
* ``differs_from``: the response is now the same as the baseline the attack
  used to differ from. Again only when the reference recorded a response.
* ``transport`` (no response) and an assertion that checks nothing are never
  safe. A target that is simply down is never "fixed".

A state-changing proof (a cited request whose method is not GET, HEAD or
OPTIONS) is retested only with ``allow_state_change=True``; without it the
result is ``inconclusive`` and nothing at all is sent. With it the gateway's
own approval hold still applies.
"""

from __future__ import annotations

from typing import Any

from buggy.capture.gateway import SAFE_METHODS
from buggy.findings import verifier
from buggy.findings.model import Finding, Status
from buggy.findings.store import (
    RETEST_FIXED,
    RETEST_INCONCLUSIVE,
    RETEST_STILL_VULNERABLE,
    FindingNotFound,
)

SAFE_STATUSES = frozenset({401, 403, 404})
ATTEMPTS_FOR_FIXED = 2

_VULNERABLE = "vulnerable"
_SAFE = "safe"
_DOUBT = "doubt"

STATE_CHANGE_NOT_ALLOWED = (
    "a cited request can change state; not re-sent without allow_state_change"
)
UNSTABLE = "the second attempt disagreed with the first; the target is unstable"
NO_CONTROL = (
    "every assertion failed and none still passes; the target may be refusing every "
    "request (an outage or an expired session), which is not proof of a fix"
)


def _normal_status(status: Any) -> bool:
    return isinstance(status, int) and (200 <= status < 300 or status in SAFE_STATUSES)


def _reference_has_response(gateway: Any, engagement: str, capture_id: str) -> bool:
    reference = gateway.store.get(engagement, capture_id) if capture_id else None
    return reference is not None and reference.status is not None and not reference.error


_CREDENTIAL_HEADERS = frozenset({"authorization", "cookie"})


def _stale_credential_possible(finding: Finding, result: dict[str, Any], gateway: Any) -> bool:
    """A 401 may only mean the credentials stored with the cited request expired."""
    fresh = gateway.store.get(finding.engagement, result.get("replay_capture_id") or "")
    if fresh is not None and fresh.identity:
        return False
    cited = gateway.store.get(finding.engagement, result["capture_id"])
    headers = cited.request_headers if cited is not None else {}
    return cited is None or any(str(k).lower() in _CREDENTIAL_HEADERS for k in headers)


def _unsafe_reason(  # noqa: PLR0911
    finding: Finding, result: dict[str, Any], gateway: Any
) -> str | None:
    """Why a failed assertion is not a failure in the safe direction, or ``None`` if it is."""
    label = f"assertion[{result['index']}] ({result['capture_id']})"
    status = result.get("replay_status")
    checks = list(result.get("failed_checks") or [])
    if not checks:
        return f"{label}: failed without a check that can show a fix"
    if "transport" in checks or status is None:
        return f"{label}: no response (the target may be down)"
    if not _normal_status(status):
        return f"{label}: status {status} is neither a normal answer nor a refusal"
    expect = finding.assertions[result["index"]].expect
    for check in checks:
        if check == "status":
            if status not in SAFE_STATUSES:
                return f"{label}: status {status} is not a refusal (401, 403 or 404)"
            if set(expect.statuses()) & SAFE_STATUSES:
                return f"{label}: the proof expected a refusal; another refusal shows nothing"
            if status == 401 and _stale_credential_possible(finding, result, gateway):
                return (
                    f"{label}: 401 to stored credentials that may simply have expired "
                    "(not sent as a named identity)"
                )
        elif check in ("body_contains", "body_not_contains"):
            continue
        elif check == "same_as":
            if not _reference_has_response(gateway, finding.engagement, expect.same_as):
                return f"{label}: same_as reference recorded no response"
        elif check == "differs_from":
            if not _reference_has_response(gateway, finding.engagement, expect.differs_from):
                return f"{label}: differs_from reference recorded no response"
        else:
            return f"{label}: failed check {check!r} has no safe direction"
    return None


def classify(
    finding: Finding, outcome: verifier.Verification, gateway: Any
) -> tuple[str, list[str]]:
    """``(vulnerable | safe | doubt, reasons)`` for one verifier attempt."""
    if outcome.status == Status.EXPLOIT_VERIFIED.value:
        return _VULNERABLE, list(outcome.reasons)
    results = outcome.results
    if not results or len(results) != len(finding.assertions):
        return _DOUBT, list(outcome.reasons) or ["not every assertion was evaluated"]
    not_evaluated = [r for r in results if r["outcome"] not in (verifier.PASSED, verifier.FAILED)]
    if not_evaluated:
        return _DOUBT, [reason for r in not_evaluated for reason in r["reasons"]]
    failed = [r for r in results if r["outcome"] == verifier.FAILED]
    unsafe = [reason for r in failed if (reason := _unsafe_reason(finding, r, gateway))]
    if unsafe:
        return _DOUBT, unsafe
    if len(results) > 1 and len(failed) == len(results):
        return _DOUBT, [NO_CONTROL]
    return _SAFE, [reason for r in failed for reason in r["reasons"]]


def _signature(outcome: verifier.Verification) -> list[tuple[Any, ...]]:
    return [
        (r["index"], r["outcome"], r["replay_status"], tuple(sorted(r["failed_checks"])))
        for r in outcome.results
    ]


def _state_changing(finding: Finding, gateway: Any) -> list[str]:
    """Labels of assertions whose cited request can change state."""
    out = []
    for index, assertion in enumerate(finding.assertions):
        capture = (
            gateway.store.get(finding.engagement, assertion.capture_id)
            if assertion.capture_id
            else None
        )
        if capture is not None and capture.method not in SAFE_METHODS:
            out.append(f"assertion[{index}] ({assertion.capture_id}): {capture.method}")
    return out


def retest(
    service: Any,
    engagement: str,
    finding_id: str,
    *,
    allow_state_change: bool = False,
    actor: str = "retest",
) -> dict[str, Any]:
    """Retest one stored finding and record the outcome. The finding's status is not changed.

    ``service`` is a :class:`buggy.findings.service.FindingService` (its
    ``store``, ``gateway`` and ``sessions`` are used). Returns ``ok``,
    ``outcome``, ``reasons``, ``capture_ids`` (every fresh capture this retest
    made), ``attempts``, ``status`` (the finding's, unchanged), ``retest``,
    ``fixed_at`` and ``regressed``; or ``ok: False`` with ``code``/``detail``.
    """
    store, gateway = service.store, service.gateway
    finding = store.get(engagement, finding_id)
    if finding is None:
        return {
            "ok": False,
            "code": "UNKNOWN_FINDING",
            "detail": f"no finding {finding_id!r} in this engagement",
        }

    attempts: list[dict[str, Any]] = []
    capture_ids: list[str] = []
    held = [] if allow_state_change else _state_changing(finding, gateway)
    if held:
        verdict, reasons = RETEST_INCONCLUSIVE, [STATE_CHANGE_NOT_ALLOWED, *held]
    else:
        verdict, reasons = RETEST_INCONCLUSIVE, []
        first_signature: list[tuple[Any, ...]] | None = None
        for _attempt in range(ATTEMPTS_FOR_FIXED):
            outcome = verifier.verify(
                finding,
                gateway,
                sessions=getattr(service, "sessions", None),
                allow_state_change=allow_state_change,
            )
            capture_ids.extend(outcome.replay_capture_ids)
            kind, why = classify(finding, outcome, gateway)
            attempts.append(
                {
                    "verdict": kind,
                    "replay_capture_ids": list(outcome.replay_capture_ids),
                    "reasons": why,
                    "assertions": [
                        {
                            key: r[key]
                            for key in (
                                "index",
                                "capture_id",
                                "outcome",
                                "replay_capture_id",
                                "replay_status",
                                "failed_checks",
                            )
                        }
                        for r in outcome.results
                    ],
                }
            )
            if kind == _VULNERABLE:
                if first_signature is None:
                    verdict, reasons = RETEST_STILL_VULNERABLE, why
                else:  # safe, then vulnerable: flaky
                    verdict, reasons = RETEST_INCONCLUSIVE, [UNSTABLE, *why]
                break
            if kind == _DOUBT:
                verdict, reasons = RETEST_INCONCLUSIVE, why
                if first_signature is not None:
                    reasons = [UNSTABLE, *why]
                break
            signature = _signature(outcome)
            if first_signature is None:
                first_signature = signature
                continue
            if signature == first_signature:
                verdict = RETEST_FIXED
                reasons = [
                    f"{ATTEMPTS_FOR_FIXED} consecutive attempts failed in the safe direction",
                    *why,
                ]
            else:
                verdict, reasons = RETEST_INCONCLUSIVE, [UNSTABLE]
    try:
        recorded = store.record_retest(
            engagement,
            finding_id,
            actor=actor,
            outcome=verdict,
            capture_ids=capture_ids,
            detail={
                "reasons": reasons,
                "attempts": len(attempts),
                "allow_state_change": allow_state_change,
            },
        )
    except FindingNotFound:
        return {
            "ok": False,
            "code": "UNKNOWN_FINDING",
            "detail": f"no finding {finding_id!r} in this engagement",
        }
    return {
        "ok": True,
        "engagement": engagement,
        "finding_id": finding_id,
        "title": finding.title,
        "status": finding.status,
        "outcome": verdict,
        "reasons": reasons,
        "capture_ids": capture_ids,
        "attempts": attempts,
        **recorded,
    }


__all__ = [
    "ATTEMPTS_FOR_FIXED",
    "NO_CONTROL",
    "SAFE_STATUSES",
    "STATE_CHANGE_NOT_ALLOWED",
    "UNSTABLE",
    "classify",
    "retest",
]
