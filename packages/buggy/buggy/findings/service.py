"""Finding service: submit a claim, have it verified, read it back.

Plain methods returning JSON-serialisable dicts (the integrator wraps them as
MCP tools). Every result has ``ok``; a failure carries ``code`` and ``detail``
and, for a malformed finding, ``errors`` naming each field.

A submitter cannot verify or grade its own claim: ``status``, ``verification``
and ``grade`` in a submission are ignored. Only :meth:`FindingService.verify`
can make a finding ``exploit_verified``.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.findings import verifier
from buggy.findings.grade import (
    CHALLENGE_HOLDS,
    CHALLENGE_VERDICTS,
    HOLD,
    SUBMIT,
    challenge_reason,
)
from buggy.findings.grade import grade as grade_finding
from buggy.findings.model import (
    CONTEXT_REQUIRED_CLASSES,
    MAX_ASSERTIONS,
    Assertion,
    Finding,
    Status,
    ValidationError,
    context_errors,
    empty_verification,
    severity_rank,
    validate,
)
from buggy.findings.ruled_out import DEFAULT_REVIEW_DAYS, Ledger
from buggy.findings.store import FindingNotFound, FindingStore, IllegalTransition

log = logging.getLogger("buggy.findings.service")

# Decided by the service, never taken from a submission.
_SERVICE_OWNED = ("id", "status", "verification", "grade", "grade_reasons", "created_at")
_FINAL = frozenset({Status.EXPLOIT_VERIFIED.value, Status.DISCARDED.value})
SOURCE_SEPARATOR = " | "

#: Sources whose proof is code (a probe re-run, a scanner record): the disprover skips them.
CODE_SOURCES = ("probe:", "pipeline:")
CHALLENGED = "challenged"
MAX_CHALLENGE_REASON = 1000
#: Under the operator-controlled root: the operator's overrides of the disprover.
OVERRIDES_FILE = "disprover-overrides.jsonl"


def agent_made(source: str) -> bool:
    """Whether a finding's proof came from an agent's claim rather than from code."""
    parts = [part.strip() for part in str(source or "").split("|") if part.strip()]
    return not any(part.startswith(CODE_SOURCES) for part in parts)


def read_overrides(control: Path, engagement: str) -> dict[str, float]:
    """Finding id -> when the operator last overrode the disprover on it.

    Written only by ``buggy-cli disprover override``. A file that cannot be read
    gives no overrides, which keeps the findings held (the safe direction).
    """
    out: dict[str, float] = {}
    try:
        lines = (control / engagement / OVERRIDES_FILE).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return out
    for raw in lines:
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(row, dict) or not isinstance(row.get("finding_id"), str):
            continue
        at = row.get("at")
        if isinstance(at, int | float) and not isinstance(at, bool):
            out[row["finding_id"]] = max(out.get(row["finding_id"], 0.0), float(at))
    return out


def _error(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "code": code, "detail": detail, **extra}


def _assertion_key(assertion: Assertion) -> str:
    return json.dumps(assertion.to_dict(), sort_keys=True)


def _join_sources(current: str, incoming: str) -> str:
    parts = [part.strip() for part in current.split("|") if part.strip()]
    for part in incoming.split("|"):
        part = part.strip()
        if part and part not in parts:
            parts.append(part)
    return SOURCE_SEPARATOR.join(parts)


class FindingService:
    def __init__(
        self,
        store: FindingStore,
        gateway: CaptureGateway,
        sessions: Any = None,
        *,
        review_days: float = DEFAULT_REVIEW_DAYS,
    ) -> None:
        self.store = store
        self.gateway = gateway
        self.sessions = sessions
        # What was tried and dropped, and why (buggy.findings.ruled_out).
        self.ledger = Ledger(store, review_days=review_days)
        #: engagement -> {finding id: when the operator overrode the disprover}. The
        #: capture server reads the operator's file (:func:`read_overrides`).
        self.overrides: Callable[[str], dict[str, float]] = lambda _engagement: {}

    def _ledger(self, fn: Callable[[], Any]) -> None:
        """Record into the ledger; a ledger problem never fails the decision it follows."""
        try:
            fn()
        except (sqlite3.Error, ValueError, LookupError):
            log.warning("the ruled-out ledger could not be written", exc_info=True)

    def _captures(self, engagement: str) -> Callable[[str], Any]:
        store = getattr(self.gateway, "store", None)
        return lambda capture_id: store.get(engagement, capture_id) if store is not None else None

    # ── the disprover ───────────────────────────────────────────────

    def _challenges(self, engagement: str, finding_id: str) -> list[dict[str, Any]]:
        return [
            {
                "verdict": str(event["detail"].get("verdict") or ""),
                "reason": str(event["detail"].get("reason") or ""),
                "at": float(event["at"] or 0.0),
                "by": str(event["actor"] or ""),
            }
            for event in self.store.events(engagement, finding_id)
            if event["event"] == CHALLENGED and isinstance(event.get("detail"), dict)
        ]

    def standing_challenge(self, engagement: str, finding: Finding) -> dict[str, Any] | None:
        """The disprover's objection that holds this finding now, if any.

        Any ``false_positive`` or ``undetermined`` verdict recorded after the
        operator's latest override holds it: two disprovers that disagree leave it
        undetermined. ``stands`` never lifts an objection. Findings proven by code
        (a probe, the scanner) are never held by the disprover.
        """
        if not agent_made(finding.source):
            return None
        overridden = self.overrides(engagement).get(finding.id)
        for challenge in reversed(self._challenges(engagement, finding.id)):
            if overridden is not None and challenge["at"] <= overridden:
                break
            if challenge["verdict"] in CHALLENGE_HOLDS:
                return challenge
        return None

    def challenge(
        self, engagement: str, finding_id: str, verdict: str, reason: str, actor: str
    ) -> dict[str, Any]:
        """Record the disprover's verdict on an agent-made finding; code decides the effect.

        ``false_positive`` or ``undetermined`` hold the finding (grade rule 9) until
        the operator overrides it; a finding already graded ``submit`` is held at
        once. ``stands`` is recorded and changes nothing.
        """
        if not isinstance(actor, str) or not actor.strip():
            return _error("BAD_ACTOR", "actor is required: a verdict names who gave it")
        verdict = str(verdict or "").strip().lower()
        if verdict not in CHALLENGE_VERDICTS:
            return _error("INVALID", f"verdict must be one of {', '.join(CHALLENGE_VERDICTS)}")
        reason = " ".join(str(reason or "").split())
        if not reason:
            return _error("INVALID", "reason is required: say what in the evidence shows it")
        finding = self.store.get(engagement, finding_id)
        if finding is None:
            return _error("UNKNOWN_FINDING", f"no finding {finding_id!r} in this engagement")
        if not agent_made(finding.source):
            return _error(
                "NOT_AGENT_MADE",
                f"{finding_id} was proven by code ({finding.source}); the disprover judges "
                "agent-made findings only",
            )
        detail = {"verdict": verdict, "reason": reason[:MAX_CHALLENGE_REASON]}
        self.store.add_event(engagement, finding_id, actor, CHALLENGED, detail)
        effect = "none"
        standing = self.standing_challenge(engagement, finding)
        if standing is not None and finding.grade == SUBMIT:
            kept = tuple(r for r in finding.grade_reasons if not r.startswith("Rule 8 "))
            reasons = (*kept, challenge_reason(standing))
            try:
                finding = self.store.upsert(
                    replace(finding, grade=HOLD, grade_reasons=reasons),
                    actor,
                    event="graded",
                    detail={
                        "grade": HOLD,
                        "previous_grade": SUBMIT,
                        "reasons": list(reasons),
                        "challenge": standing["verdict"],
                    },
                )
            except IllegalTransition as exc:
                return _error("CONFLICT", f"the finding changed while it was being held: {exc}")
            effect = "held"
        elif standing is not None:
            effect = "held at grading"
        return {
            "ok": True,
            "verdict": verdict,
            "effect": effect,
            "finding": self._shown(engagement, finding),
        }

    # ── submit ──────────────────────────────────────────────────────

    def submit(
        self, engagement: str, data: Any, actor: str, *, require_context: bool = False
    ) -> dict[str, Any]:
        """Record a claim as a ``candidate``, or merge it into the finding with the same id.

        A second report of the same finding adds its assertions (duplicates
        dropped), keeps the higher severity and joins the sources. New
        assertions put an undecided finding back to ``candidate`` (and lift
        what the ledger ruled out for it); a finding that is already
        ``exploit_verified`` or ``discarded`` is left as it is and the
        duplicate is noted in its history.

        ``require_context`` (an agent's own submission) refuses a finding of a
        class in ``CONTEXT_REQUIRED_CLASSES`` that names no usable
        ``invariant`` and ``entry_point``, unless the stored finding has them.
        """
        if not isinstance(actor, str) or not actor.strip():
            return _error("BAD_ACTOR", "actor is required: a submission names who made it")
        if not isinstance(data, dict):
            return _error(
                "INVALID_FINDING",
                "finding: must be an object",
                errors=[{"field": "finding", "message": "must be an object"}],
            )
        supplied = data.get("engagement")
        if supplied not in (None, "", engagement):
            message = f"is {supplied!r}, but the finding is being submitted to {engagement!r}"
            return _error(
                "INVALID_FINDING",
                f"engagement: {message}",
                errors=[{"field": "engagement", "message": message}],
            )
        payload = {key: value for key, value in data.items() if key not in _SERVICE_OWNED}
        payload.pop("updated_at", None)
        payload["engagement"] = engagement
        try:
            incoming = validate(payload)
        except ValidationError as exc:
            return _error("INVALID_FINDING", str(exc), errors=exc.errors)

        existing = self.store.get(engagement, incoming.id)
        if require_context and incoming.vuln_class in CONTEXT_REQUIRED_CLASSES:
            problems = context_errors(
                incoming.invariant or (existing.invariant if existing else ""),
                incoming.entry_point or (existing.entry_point if existing else ""),
            )
            if problems:
                return _error(
                    "INVALID_FINDING",
                    "; ".join(f"{e['field']}: {e['message']}" for e in problems),
                    errors=problems,
                )
        if existing is None:
            stored = self.store.upsert(incoming, actor)
            return {"ok": True, "created": True, "merged": False, "finding": stored.to_dict()}

        if existing.status in _FINAL:
            self.store.add_event(
                engagement,
                existing.id,
                actor,
                "duplicate_submission",
                {"status": existing.status, "source": incoming.source},
            )
            return {
                "ok": True,
                "created": False,
                "merged": False,
                "note": f"already {existing.status}; the submission was not merged",
                "finding": existing.to_dict(),
            }

        known = {_assertion_key(assertion) for assertion in existing.assertions}
        fresh: list[Assertion] = []
        for assertion in incoming.assertions:
            key = _assertion_key(assertion)
            if key not in known:  # identical assertions count once
                known.add(key)
                fresh.append(assertion)
        if len(existing.assertions) + len(fresh) > MAX_ASSERTIONS:
            message = f"the merged finding would have more than {MAX_ASSERTIONS} assertions"
            return _error(
                "INVALID_FINDING",
                f"assertions: {message}",
                errors=[{"field": "assertions", "message": message}],
            )
        merged = replace(
            existing,
            assertions=(*existing.assertions, *fresh),
            severity=min(existing.severity, incoming.severity, key=severity_rank),
            source=_join_sources(existing.source, incoming.source),
            cwe=existing.cwe or incoming.cwe,
            description=existing.description or incoming.description,
            remediation=existing.remediation or incoming.remediation,
            invariant=existing.invariant or incoming.invariant,
            entry_point=existing.entry_point or incoming.entry_point,
        )
        if fresh:
            # New evidence has not been verified: back in the queue.
            merged = replace(
                merged, status=Status.CANDIDATE.value, verification=empty_verification()
            )
        stored = self.store.upsert(
            merged, actor, event="merged", detail={"assertions_added": len(fresh)}
        )
        if fresh:
            self._ledger(
                lambda: self.ledger.supersede_finding(
                    engagement, stored.id, actor=actor, note="new evidence was submitted"
                )
            )
        return {
            "ok": True,
            "created": False,
            "merged": True,
            "assertions_added": len(fresh),
            "finding": stored.to_dict(),
        }

    # ── verify ──────────────────────────────────────────────────────

    def verify(
        self,
        engagement: str,
        finding_id: str,
        *,
        allow_state_change: bool = False,
        actor: str = "verifier",
        prover: Callable[[Finding], verifier.Verification | None] | None = None,
    ) -> dict[str, Any]:
        """Run the independent verifier on a stored finding and record its decision.

        ``prover`` is tried first: the capture server passes one that re-runs
        the deterministic probe a finding came from. When it returns ``None``
        (no probe run is recorded for the finding) the stored assertions are
        replayed instead.
        """
        finding = self.store.get(engagement, finding_id)
        if finding is None:
            return _error("UNKNOWN_FINDING", f"no finding {finding_id!r} in this engagement")
        if finding.status == Status.SOURCE_VERIFIED.value and not finding.assertions:
            return {
                "ok": True,
                "note": "source-verified and has no assertions; there is nothing to replay",
                "finding": finding.to_dict(),
            }
        outcome = prover(finding) if prover is not None else None
        if outcome is None:
            outcome = verifier.verify(
                finding, self.gateway, sessions=self.sessions, allow_state_change=allow_state_change
            )
        stored = self.store.set_status(
            engagement,
            finding_id,
            outcome.status,
            actor=actor,
            verification=outcome.to_dict(),
            detail={
                "reasons": outcome.reasons,
                "replay_capture_ids": outcome.replay_capture_ids,
                "assertions": outcome.results,
                "allow_state_change": allow_state_change,
            },
        )
        self._ledger(
            lambda: self.ledger.after_verification(
                stored,
                outcome.status,
                outcome.results,
                outcome.reasons,
                actor=actor,
                replay_capture_ids=outcome.replay_capture_ids,
                lookup=self._captures(engagement),
            )
        )
        return {"ok": True, "finding": stored.to_dict(), "verification": outcome.detail()}

    def mark_source_verified(
        self, engagement: str, finding_id: str, note: str, actor: str
    ) -> dict[str, Any]:
        """Operator-side: record a source review. Not an agent tool."""
        finding = self.store.get(engagement, finding_id)
        if finding is None:
            return _error("UNKNOWN_FINDING", f"no finding {finding_id!r} in this engagement")
        try:
            outcome = verifier.mark_source_verified(finding, note)
        except verifier.SourceVerificationError as exc:
            return _error("NOT_SOURCE_VERIFIABLE", str(exc))
        stored = self.store.set_status(
            engagement,
            finding_id,
            outcome.status,
            actor=actor,
            verification=outcome.to_dict(),
            detail={"reasons": outcome.reasons},
        )
        return {"ok": True, "finding": stored.to_dict(), "verification": outcome.detail()}

    # ── grade ───────────────────────────────────────────────────────

    def grade(
        self,
        engagement: str,
        finding_id: str,
        *,
        program: dict[str, Any] | None = None,
        known_issues: list[dict[str, Any]] | None = None,
        prior: list[Finding] | None = None,
        scope: Any = None,
        actor: str = "grader",
    ) -> dict[str, Any]:
        """Grade a stored finding (submit, hold or discard) and record the decision.

        ``program`` is the engagement's program record, ``known_issues`` the
        pipeline's ``vulnerability`` records and ``prior`` earlier findings;
        the caller supplies them. The scope is the engagement's enforced scope
        unless one is passed. Without a usable scope nothing is graded or stored.
        """
        if not isinstance(actor, str) or not actor.strip():
            return _error("BAD_ACTOR", "actor is required: a grade names who gave it")
        finding = self.store.get(engagement, finding_id)
        if finding is None:
            return _error("UNKNOWN_FINDING", f"no finding {finding_id!r} in this engagement")
        if scope is None:
            try:
                scope, _document = self.gateway.scope_for(engagement)
            except GatewayRefusal as exc:
                return _error(exc.code, exc.detail)
        try:
            outcome = grade_finding(
                finding,
                program=program,
                scope=scope,
                known_issues=list(known_issues or []),
                prior=list(prior or []),
                challenge=self.standing_challenge(engagement, finding),
            )
        except ValueError as exc:
            return _error("BAD_SCOPE", str(exc))
        try:
            stored = self.store.upsert(
                replace(finding, grade=outcome.decision, grade_reasons=tuple(outcome.reasons)),
                actor,
                event="graded",
                detail={
                    "grade": outcome.decision,
                    "previous_grade": finding.grade,
                    "reasons": outcome.reasons,
                    "blocking": outcome.blocking,
                    "capped_severity": outcome.capped_severity,
                    "program": bool(program),
                    "known_issues": len(known_issues or []),
                    "prior": len(prior or []),
                },
            )
        except IllegalTransition as exc:
            return _error("CONFLICT", f"the finding changed while it was being graded: {exc}")
        self._ledger(
            lambda: self.ledger.after_grade(
                stored, outcome.decision, list(outcome.reasons), actor=actor
            )
        )
        return {"ok": True, "finding": stored.to_dict(), "grade": outcome.to_dict()}

    # ── read ────────────────────────────────────────────────────────

    def get(self, engagement: str, finding_id: str) -> dict[str, Any]:
        finding = self.store.get(engagement, finding_id)
        if finding is None:
            return _error("UNKNOWN_FINDING", f"no finding {finding_id!r} in this engagement")
        return {
            "ok": True,
            "finding": self._shown(engagement, finding),
            "events": self.store.events(engagement, finding_id),
        }

    def _shown(self, engagement: str, finding: Finding) -> dict[str, Any]:
        """The finding as readers get it: the contract dict, plus its latest retest if any.

        ``retest`` (``{at, outcome, capture_ids}``) and ``fixed_at`` are added
        only once a retest was recorded, so a finding that was never retested
        reads exactly as the contract defines it.
        """
        shown = finding.to_dict()
        try:
            challenges = self._challenges(engagement, finding.id)
        except (sqlite3.Error, ValueError, KeyError, TypeError):
            challenges = []
        if challenges:
            # The disprover's latest verdict, and whether one still holds the finding.
            standing = self.standing_challenge(engagement, finding)
            shown["challenge"] = {**challenges[-1], "holds": standing is not None}
        try:
            state = self.store.retest_state(engagement, finding.id)
        except (FindingNotFound, sqlite3.Error, ValueError):
            # A retest record that cannot be read never hides the finding itself.
            return shown
        if state.get("retest"):
            shown["retest"] = state["retest"]
            shown["fixed_at"] = state.get("fixed_at")
        return shown

    def list(
        self, engagement: str, *, status: str | None = None, grade: str | None = None
    ) -> dict[str, Any]:
        rows = self.store.list(engagement, status=status or None, grade=grade or None)
        counts: dict[str, int] = {}
        for row in rows:
            counts[row.status] = counts.get(row.status, 0) + 1
        return {
            "ok": True,
            "findings": [self._shown(engagement, row) for row in rows],
            "count": len(rows),
            "by_status": counts,
        }


__all__ = [
    "CODE_SOURCES",
    "OVERRIDES_FILE",
    "SOURCE_SEPARATOR",
    "FindingService",
    "agent_made",
    "read_overrides",
]
