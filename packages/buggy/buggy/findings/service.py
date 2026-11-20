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
from dataclasses import replace
from typing import Any

from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.findings import verifier
from buggy.findings.grade import grade as grade_finding
from buggy.findings.model import (
    MAX_ASSERTIONS,
    Assertion,
    Finding,
    Status,
    ValidationError,
    empty_verification,
    severity_rank,
    validate,
)
from buggy.findings.store import FindingStore, IllegalTransition

# Decided by the service, never taken from a submission.
_SERVICE_OWNED = ("id", "status", "verification", "grade", "grade_reasons", "created_at")
_FINAL = frozenset({Status.EXPLOIT_VERIFIED.value, Status.DISCARDED.value})
SOURCE_SEPARATOR = " | "


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
    def __init__(self, store: FindingStore, gateway: CaptureGateway, sessions: Any = None) -> None:
        self.store = store
        self.gateway = gateway
        self.sessions = sessions

    # ── submit ──────────────────────────────────────────────────────

    def submit(self, engagement: str, data: Any, actor: str) -> dict[str, Any]:
        """Record a claim as a ``candidate``, or merge it into the finding with the same id.

        A second report of the same finding adds its assertions (duplicates
        dropped), keeps the higher severity and joins the sources. New
        assertions put an undecided finding back to ``candidate``; a finding
        that is already ``exploit_verified`` or ``discarded`` is left as it
        is and the duplicate is noted in its history.
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
        )
        if fresh:
            # New evidence has not been verified: back in the queue.
            merged = replace(
                merged, status=Status.CANDIDATE.value, verification=empty_verification()
            )
        stored = self.store.upsert(
            merged, actor, event="merged", detail={"assertions_added": len(fresh)}
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
    ) -> dict[str, Any]:
        """Run the independent verifier on a stored finding and record its decision."""
        finding = self.store.get(engagement, finding_id)
        if finding is None:
            return _error("UNKNOWN_FINDING", f"no finding {finding_id!r} in this engagement")
        if finding.status == Status.SOURCE_VERIFIED.value and not finding.assertions:
            return {
                "ok": True,
                "note": "source-verified and has no assertions; there is nothing to replay",
                "finding": finding.to_dict(),
            }
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
        return {"ok": True, "finding": stored.to_dict(), "grade": outcome.to_dict()}

    # ── read ────────────────────────────────────────────────────────

    def get(self, engagement: str, finding_id: str) -> dict[str, Any]:
        finding = self.store.get(engagement, finding_id)
        if finding is None:
            return _error("UNKNOWN_FINDING", f"no finding {finding_id!r} in this engagement")
        return {
            "ok": True,
            "finding": finding.to_dict(),
            "events": self.store.events(engagement, finding_id),
        }

    def list(
        self, engagement: str, *, status: str | None = None, grade: str | None = None
    ) -> dict[str, Any]:
        rows = self.store.list(engagement, status=status or None, grade=grade or None)
        counts: dict[str, int] = {}
        for row in rows:
            counts[row.status] = counts.get(row.status, 0) + 1
        return {
            "ok": True,
            "findings": [row.to_dict() for row in rows],
            "count": len(rows),
            "by_status": counts,
        }


__all__ = ["SOURCE_SEPARATOR", "FindingService"]
