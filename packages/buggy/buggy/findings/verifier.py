"""Independent verifier: re-send what a finding cites and check what it claims.

The verifier did not make the claim. It reads two things from a finding: the
engagement and the assertions. Title, description, severity and any other
prose never enter the decision. For each assertion it re-sends the cited
capture's request through the capture gateway (so scope, approval hold, rate
limit and the ledger all apply) and evaluates the expectations on the NEW
response.

Outcome:

* every assertion passes                     -> ``exploit_verified``
* an assertion fails on a re-send            -> ``inconclusive`` (the target may be flaky)
* a cited capture is missing, out of scope
  or from another engagement                 -> ``discarded``
* no assertions                              -> ``inconclusive: no assertions``
* nothing could be re-sent without approval  -> ``inconclusive: needs operator-approved replay``

``source_verified`` is never produced here; it takes an explicit
:func:`mark_source_verified` call.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from buggy.capture.gateway import SAFE_METHODS, CaptureGateway, GatewayRefusal
from buggy.capture.probes.base import similarity, text
from buggy.capture.store import Capture, request_fingerprint
from buggy.findings.model import Assertion, Expect, Finding, Status, normalize_endpoint

SAME_AS_MIN = 0.95
DIFFERS_BELOW = 0.80

NO_ASSERTIONS = "no assertions"
NEEDS_APPROVED_REPLAY = "needs operator-approved replay"
EVIDENCE_NOT_ON_ENDPOINT = "no cited capture targets the finding's endpoint"

PASSED = "passed"
FAILED = "failed"
NOT_REPLAYED = "not_replayed"
REFUSED = "refused"
INVALID = "invalid_capture"

_HELD_CODES = frozenset({"APPROVAL_REQUIRED", "APPROVAL_DENIED"})


class SourceVerificationError(ValueError):
    """The finding does not qualify for ``source_verified``."""


@dataclass
class Verification:
    """The verifier's decision. ``to_dict`` is the contract's ``verification`` record."""

    status: str
    at: float
    replay_capture_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "replay_capture_ids": list(self.replay_capture_ids),
            "reasons": list(self.reasons),
        }

    def detail(self) -> dict[str, Any]:
        """The record plus the status and the per-assertion outcomes."""
        return {"status": self.status, **self.to_dict(), "assertions": list(self.results)}


def _short(value: str, limit: int = 80) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _label(index: int, capture_id: str) -> str:
    return f"assertion[{index}] ({capture_id or 'no capture id'})"


def _accepts_identity(gateway: Any) -> bool:
    try:
        params = inspect.signature(gateway.send).parameters
    except (TypeError, ValueError):
        return False
    return "identity" in params or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
    )


def _has_response(capture: Capture) -> bool:
    return capture.status is not None and not capture.error


def evaluate(expect: Expect, fresh: Capture, cited: dict[str, Capture]) -> list[tuple[str, str]]:
    """``(check, reason)`` for every expectation the fresh response does not meet."""
    if not _has_response(fresh):
        return [("transport", f"the replay got no response ({_short(fresh.error or 'no status')})")]
    failures: list[tuple[str, str]] = []
    statuses = expect.statuses()
    if statuses and fresh.status not in statuses:
        wanted = " or ".join(str(code) for code in statuses)
        failures.append(("status", f"status {fresh.status}, expected {wanted}"))
    body = text(fresh)
    for needle in expect.body_contains:
        if needle not in body:
            failures.append(("body_contains", f"body does not contain {_short(needle)!r}"))
    for needle in expect.body_not_contains:
        if needle in body:
            failures.append(("body_not_contains", f"body contains {_short(needle)!r}"))
    if expect.same_as:
        reference = cited[expect.same_as]
        if not _has_response(reference):
            failures.append(("same_as", f"{expect.same_as} recorded no response to compare with"))
        else:
            score = similarity(fresh, reference)
            if score < SAME_AS_MIN:
                failures.append(
                    (
                        "same_as",
                        f"similarity {score:.2f} to {expect.same_as}, need >= {SAME_AS_MIN:.2f}",
                    )
                )
    if expect.differs_from:
        reference = cited[expect.differs_from]
        if not _has_response(reference):
            failures.append(
                ("differs_from", f"{expect.differs_from} recorded no response to compare with")
            )
        else:
            score = similarity(fresh, reference)
            if not (score < DIFFERS_BELOW or fresh.status != reference.status):
                failures.append(
                    (
                        "differs_from",
                        f"similarity {score:.2f} to {expect.differs_from} with the same status "
                        f"{fresh.status}, need < {DIFFERS_BELOW:.2f} or a different status",
                    )
                )
    return failures


def _cited_ids(assertion: Assertion) -> list[tuple[str, str]]:
    cited = [("capture_id", assertion.capture_id)]
    if assertion.expect.same_as:
        cited.append(("same_as", assertion.expect.same_as))
    if assertion.expect.differs_from:
        cited.append(("differs_from", assertion.expect.differs_from))
    return cited


def _on_endpoint(url: str, endpoint: str) -> bool:
    """True when ``url`` targets ``endpoint`` (same normalised form; a bare path matches any host)."""
    wanted = normalize_endpoint(endpoint).rstrip("/")
    if not wanted:
        return False
    got = normalize_endpoint(url).rstrip("/")
    if "://" in wanted:
        return got == wanted
    return urlsplit(got).path.rstrip("/") == wanted


def verify(
    finding: Finding,
    gateway: CaptureGateway,
    *,
    sessions: Any = None,
    allow_state_change: bool = False,
) -> Verification:
    """Re-prove ``finding`` and return the decision. Nothing is stored here.

    ``sessions`` enables identities: when it is given and an assertion names
    an identity, the re-send asks the gateway to attach that identity's
    current session (``identity=...``) instead of relying on the credentials
    stored with the cited capture. A request that can change state is re-sent
    only with ``allow_state_change=True``, and even then the gateway's own
    approval hold still applies.
    """
    now = time.time()
    engagement = finding.engagement
    assertions = tuple(finding.assertions)
    if not assertions:
        return Verification(Status.INCONCLUSIVE.value, now, reasons=[NO_ASSERTIONS])

    try:
        scope, _document = gateway.scope_for(engagement)
    except GatewayRefusal as refusal:
        return Verification(
            Status.INCONCLUSIVE.value,
            now,
            reasons=[
                f"no enforced scope to verify against ({refusal.code}: {_short(refusal.detail)}); "
                "nothing was re-sent"
            ],
        )

    # Pass 1, no network: every cited capture must exist in this engagement and
    # still be in scope. One bad citation discards the finding before anything is sent.
    cited: dict[str, Capture] = {}
    invalid: list[str] = []
    for index, assertion in enumerate(assertions):
        for role, capture_id in _cited_ids(assertion):
            where = _label(index, assertion.capture_id) + (
                "" if role == "capture_id" else f" {role}"
            )
            capture = gateway.store.get(engagement, capture_id) if capture_id else None
            if capture is None:
                invalid.append(
                    f"{where}: capture {capture_id!r} is not in engagement {engagement!r} "
                    "(missing, or it belongs to another engagement)"
                )
            elif not scope.allows(capture.url):
                invalid.append(
                    f"{where}: capture {capture_id} targets {capture.host}, which is not in the "
                    "enforced scope"
                )
            else:
                cited[capture_id] = capture
    if invalid:
        return Verification(Status.DISCARDED.value, now, reasons=invalid)

    # The evidence must be about the finding: at least one primary capture has
    # to target the endpoint the finding names. Passing assertions on some
    # other endpoint prove nothing about this one.
    if not any(_on_endpoint(cited[a.capture_id].url, finding.endpoint) for a in assertions):
        return Verification(Status.INCONCLUSIVE.value, now, reasons=[EVIDENCE_NOT_ON_ENDPOINT])

    # Pass 2: re-send and evaluate.
    results: list[dict[str, Any]] = []
    replay_ids: list[str] = []
    identity_supported = _accepts_identity(gateway)
    for index, assertion in enumerate(assertions):
        original = cited[assertion.capture_id]
        label = _label(index, assertion.capture_id)
        result: dict[str, Any] = {
            "index": index,
            "capture_id": assertion.capture_id,
            "identity": assertion.identity,
            "outcome": FAILED,
            "replay_capture_id": "",
            "replay_status": None,
            "failed_checks": [],
            "reasons": [],
        }
        results.append(result)

        def settle(outcome: str, reason: str, _result: dict[str, Any] = result) -> None:
            _result["outcome"] = outcome
            _result["reasons"].append(reason)

        if assertion.expect.is_empty():
            settle(FAILED, f"{label}: nothing to check (empty expect)")
            continue
        if original.method not in SAFE_METHODS and not allow_state_change:
            settle(
                NOT_REPLAYED,
                f"{label}: {original.method} can change state; not re-sent without "
                "allow_state_change",
            )
            continue
        stored_fingerprint = request_fingerprint(
            original.method, original.url, original.request_body
        )
        if stored_fingerprint != original.request_sha256:
            settle(REFUSED, f"{label}: the stored request body is truncated; it cannot be re-sent")
            continue
        extra: dict[str, Any] = {}
        if assertion.identity and sessions is not None:
            if not identity_supported:
                settle(
                    REFUSED,
                    f"{label}: the gateway cannot attach identity {assertion.identity!r}; "
                    "not re-sent",
                )
                continue
            extra["identity"] = assertion.identity
        try:
            fresh = gateway.send(
                engagement,
                original.method,
                original.url,
                headers=dict(original.request_headers),
                body=original.request_body,
                note="verifier",
                replay_of=original.id,
                **extra,
            )
        except GatewayRefusal as refusal:
            if refusal.code in _HELD_CODES:
                request_id = str(refusal.extra.get("request_id") or "")
                held = f" (approval request {request_id})" if request_id else ""
                settle(NOT_REPLAYED, f"{label}: {refusal.code}{held}; not re-sent")
            elif refusal.code == "OUT_OF_SCOPE":
                settle(INVALID, f"{label}: {_short(refusal.detail, 200)}")
                break
            else:
                settle(
                    REFUSED,
                    f"{label}: the gateway refused the replay ({refusal.code}: "
                    f"{_short(refusal.detail, 200)})",
                )
            continue

        replay_ids.append(fresh.id)
        result["replay_capture_id"] = fresh.id
        result["replay_status"] = fresh.status
        failures = evaluate(assertion.expect, fresh, cited)
        if failures:
            result["outcome"] = FAILED
            result["failed_checks"] = [check for check, _reason in failures]
            result["reasons"] = [f"{label}: {reason}" for _check, reason in failures]
        else:
            result["outcome"] = PASSED

    outcomes = [result["outcome"] for result in results]
    problems = [reason for result in results for reason in result["reasons"]]
    if INVALID in outcomes:
        status = Status.DISCARDED.value
        reasons = [r for res in results if res["outcome"] == INVALID for r in res["reasons"]]
    elif (
        results
        and len(results) == len(assertions)
        and all(outcome == PASSED for outcome in outcomes)
    ):
        status = Status.EXPLOIT_VERIFIED.value
        reasons = [f"all {len(results)} assertion(s) passed on a fresh replay"]
    elif all(outcome == NOT_REPLAYED for outcome in outcomes):
        status = Status.INCONCLUSIVE.value
        reasons = [NEEDS_APPROVED_REPLAY, *problems]
    else:
        status = Status.INCONCLUSIVE.value
        reasons = problems
    return Verification(
        status, now, replay_capture_ids=replay_ids, reasons=reasons, results=results
    )


def mark_source_verified(finding: Finding, note: str) -> Verification:
    """The only way to ``source_verified``: an explicit call with a reviewer's note.

    Allowed only for a finding whose ``source`` starts with ``source:`` and
    that has no assertions (there is nothing to replay; a human or a source
    analysis vouches for it). Anything else raises
    :class:`SourceVerificationError`. The caller stores the result.
    """
    if not finding.source.startswith("source:"):
        raise SourceVerificationError(
            "only a finding whose source starts with 'source:' can be source-verified"
        )
    if finding.assertions:
        raise SourceVerificationError(
            "a finding with assertions is verified by replaying them, not by a note"
        )
    reason = (note or "").strip()
    if not reason:
        raise SourceVerificationError("a note saying what was reviewed is required")
    return Verification(
        Status.SOURCE_VERIFIED.value,
        time.time(),
        reasons=[f"source-verified: {_short(reason, 500)}"],
    )


PROBE_NOT_REPRODUCED = "the probe no longer reports this issue"
PROBE_UNDECIDED = "the probe could not decide when re-run"
PROBE_OTHER_ENDPOINT = "the recorded probe run targets another endpoint than the finding names"


def verify_by_probe(
    finding: Finding,
    probe: str,
    url: str,
    rerun: Callable[[], dict[str, Any]],
) -> Verification:
    """Re-prove a probe-sourced finding by running its probe again.

    A probe carries its own controls (baseline, negative control, proof), so a
    fresh ``vulnerable: true`` is stronger than replaying single requests, and
    it is the only sound proof for probes whose evidence is not a response
    body (an out-of-band callback, a delay, a follow-up read). Anything other
    than a fresh ``true`` leaves the finding ``inconclusive``; a fixed target
    is never reported as verified.
    """
    now = time.time()
    if not _on_endpoint(url, finding.endpoint):
        return Verification(Status.INCONCLUSIVE.value, now, reasons=[PROBE_OTHER_ENDPOINT])
    try:
        result = rerun()
    except GatewayRefusal as refusal:
        return Verification(
            Status.INCONCLUSIVE.value,
            now,
            reasons=[f"probe {probe} was refused ({refusal.code}: {_short(refusal.detail)})"],
        )
    result = result if isinstance(result, dict) else {}
    ids = [str(c) for c in result.get("evidence_capture_ids") or [] if c]
    summary = _short(str(result.get("summary") or ""), 200)
    entry = {
        "index": 0,
        "capture_id": ids[0] if ids else "",
        "identity": "",
        "outcome": PASSED if result.get("vulnerable") is True else FAILED,
        "replay_capture_id": ids[-1] if ids else "",
        "replay_status": None,
        "failed_checks": [] if result.get("vulnerable") is True else ["probe"],
        "reasons": [f"probe {probe}: {summary}"] if summary else [],
        "method": "probe_rerun",
        "probe": probe,
    }
    if result.get("vulnerable") is True and ids:
        return Verification(Status.EXPLOIT_VERIFIED.value, now, ids, [], [entry])
    reason = PROBE_NOT_REPRODUCED if result.get("vulnerable") is False else PROBE_UNDECIDED
    code = str(result.get("code") or "")
    if code:
        reason = f"{reason} ({code})"
    request_id = str(result.get("request_id") or "")
    if code == "APPROVAL_REQUIRED" and request_id:
        reason = f"{reason}: the re-run needs approval {request_id}; verify again once allowed"
    return Verification(Status.INCONCLUSIVE.value, now, ids, [reason], [entry])


__all__ = [
    "DIFFERS_BELOW",
    "FAILED",
    "INVALID",
    "NEEDS_APPROVED_REPLAY",
    "NOT_REPLAYED",
    "EVIDENCE_NOT_ON_ENDPOINT",
    "NO_ASSERTIONS",
    "PROBE_NOT_REPRODUCED",
    "PROBE_OTHER_ENDPOINT",
    "PROBE_UNDECIDED",
    "PASSED",
    "REFUSED",
    "SAME_AS_MIN",
    "SourceVerificationError",
    "Verification",
    "evaluate",
    "mark_source_verified",
    "verify",
    "verify_by_probe",
]
