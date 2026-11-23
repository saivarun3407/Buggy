"""The ruled-out ledger: what was tried and dropped, why, and when to look again.

Every outcome that drops a lead is recorded with a reason code, a short text,
when, and by whom (or which probe): the probe said not vulnerable, the gateway
blocked the run, the operator refused the approval, the verifier could not
re-prove it, the grader discarded it. An entry is keyed by the technique and
where it was tried (``probe:sqli`` on this endpoint and parameter), so the same
technique on the same place is recognised next time.

Two kinds of failure are kept apart on purpose:

* a **ruled-out** entry retires the technique there: :func:`next_candidates`
  (``buggy.findings.candidates``) does not hand back a lead whose techniques are
  all ruled out at its endpoint and parameter;
* an **attempt** entry records one failed delivery (a timeout, a rate limit,
  a lost login, an exhausted approval) or a run that could not decide. It
  retires nothing: the next attempt may well work.

Decisions expire (``review_at``, default 30 days, ``BUGGY_REVIEW_DAYS``). A
ruled-out entry past its date no longer holds, so its lead is handed out
again, and it is listed as due for review together with findings graded
``hold`` or ``discard``. The operator extends, closes (keeps it for good) or
reopens an entry (``buggy-cli findings``). Later evidence supersedes an entry:
a positive run of the same technique, new assertions, a new grade.

Everything here is plain code over fixed tables; nothing is sent.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable
from typing import Any

from buggy.findings.model import Finding, Status, normalize_endpoint
from buggy.findings.store import (
    LEDGER_ATTEMPT,
    LEDGER_HELD,
    LEDGER_RULED_OUT,
    STATE_CLOSED,
    STATE_OPEN,
    FindingStore,
)

DAY = 86400.0
DEFAULT_REVIEW_DAYS = 30.0
REVIEW_DAYS_ENV = "BUGGY_REVIEW_DAYS"
MAX_REVIEW_DAYS = 3650.0
MAX_DETAIL = 300
MAX_LISTED = 100
MAX_ATTEMPTS_LISTED = 30

# ── reason codes ────────────────────────────────────────────────────

NOT_VULNERABLE = "not_vulnerable"
BLOCKED = "blocked"
APPROVAL_DENIED = "approval_denied"
INCONCLUSIVE = "inconclusive"
VERIFIER_DISCARDED = "verifier_discarded"
GRADED_DISCARD = "graded_discard"
GRADED_HOLD = "graded_hold"
DELIVERY_FAILED = "delivery_failed"
UNDECIDED = "undecided"

#: Reason code -> what it means, for the agent and the operator.
REASONS: dict[str, str] = {
    NOT_VULNERABLE: "the check ran and observed the safe behaviour",
    BLOCKED: "the evidence gateway refused to send it (see the code)",
    APPROVAL_DENIED: "the operator refused the approval",
    INCONCLUSIVE: "the verifier could not re-prove it (see its reasons)",
    VERIFIER_DISCARDED: "the verifier rejected the cited evidence",
    GRADED_DISCARD: "the grader discarded it (see the rule)",
    GRADED_HOLD: "the grader held it (see the rule); it waits for a review",
    DELIVERY_FAILED: "the request did not get through (timeout, rate limit, login, approval "
    "used up); only this attempt failed",
    UNDECIDED: "the check ran but could not decide (a precondition failed); only this "
    "attempt failed",
}

#: Gateway refusal codes that retire a technique where it was tried.
BLOCKING_REFUSALS: frozenset[str] = frozenset(
    {"OUT_OF_SCOPE", "INTERNAL_ADDRESS", "NOT_A_DECLARED_LOGIN", "NOT_AN_ACCOUNT_URL"}
)
#: Refusal codes that are a failed delivery: only that attempt failed.
DELIVERY_REFUSALS: frozenset[str] = frozenset(
    {"APPROVAL_SPENT", "LOGIN_FAILED", "RATE_LIMITED", "TIMEOUT"}
)
#: Response statuses that mean the request did not really reach the application.
DELIVERY_STATUSES: frozenset[int] = frozenset({408, 429, 502, 503, 504})

# ── techniques ──────────────────────────────────────────────────────

TECH_FINDING = "finding"  # the lead itself (a grade, an operator decision)
TECH_CLAIM = "claim"  # an agent's claim, proven by its cited captures
TECH_SCANNER = "scanner"
TECH_SURFACE = "surface"
_SUGGESTED = re.compile(r"Suggested check: ([a-z0-9_]+)")
_RULE = re.compile(r"^Rule (\d+) \(")


def review_days_from_env(default: float = DEFAULT_REVIEW_DAYS) -> float:
    """``BUGGY_REVIEW_DAYS`` as a number of days (1 to 3650), else ``default``."""
    raw = (os.environ.get(REVIEW_DAYS_ENV) or "").strip()
    try:
        days = float(raw) if raw else default
    except ValueError:
        return default
    return days if 0 < days <= MAX_REVIEW_DAYS else default


def technique_key(engagement: str, technique: str, endpoint: str, parameter: str) -> str:
    """``K-`` + 16 hex of sha256(engagement|technique|normalized endpoint|parameter)."""
    material = "|".join(
        (
            (engagement or "").strip(),
            (technique or "").strip().lower(),
            normalize_endpoint(endpoint or ""),
            (parameter or "").strip(),
        )
    )
    return "K-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def techniques_of(finding: Finding) -> list[str]:
    """The techniques a lead stands for, from its sources (deduplicated, in order).

    ``probe:x`` and ``recipe:x`` are themselves; a scanner hit is ``scanner``; a
    recon lead is the probe it suggests (``probe:sqli``) or ``surface``;
    anything else is an agent's ``claim``.
    """
    out: list[str] = []
    for part in (finding.source or "").split("|"):
        source = part.strip()
        if not source:
            continue
        if source.startswith(("probe:", "recipe:")):
            technique = source
        elif source == "pipeline:nuclei":
            technique = TECH_SCANNER
        elif source == "pipeline:surface":
            match = _SUGGESTED.search(finding.description or "")
            technique = f"probe:{match.group(1)}" if match else TECH_SURFACE
        else:
            technique = TECH_CLAIM
        if technique not in out:
            out.append(technique)
    return out or [TECH_CLAIM]


def _short(text: Any, limit: int = MAX_DETAIL) -> str:
    value = " ".join(str(text or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def holds(entry: dict[str, Any], now: float) -> bool:
    """Whether a ruled-out entry still retires its technique at ``now``."""
    if entry.get("kind") != LEDGER_RULED_OUT:
        return False
    if entry.get("state") == STATE_CLOSED:
        return True
    review_at = float(entry.get("review_at") or 0.0)
    return entry.get("state") == STATE_OPEN and (not review_at or review_at > now)


def is_due(entry: dict[str, Any], now: float) -> bool:
    """Whether an open ruled-out or held entry has passed its review date."""
    review_at = float(entry.get("review_at") or 0.0)
    return (
        entry.get("kind") in (LEDGER_RULED_OUT, LEDGER_HELD)
        and entry.get("state") == STATE_OPEN
        and 0 < review_at <= now
    )


CaptureLookup = Callable[[str], Any]


def _delivery_problem(capture_ids: list[str], lookup: CaptureLookup | None) -> str:
    """Why the run's requests did not reach the application, or "" when they did."""
    if lookup is None:
        return ""
    for capture_id in capture_ids:
        try:
            capture = lookup(capture_id)
        except Exception:  # noqa: BLE001 - an unreadable capture proves nothing either way
            continue
        if capture is None:
            continue
        error = str(getattr(capture, "error", "") or "")
        status = getattr(capture, "status", None)
        if error:
            return f"capture {capture_id}: no response ({_short(error, 120)})"
        if status is None:
            return f"capture {capture_id}: no response"
        if status in DELIVERY_STATUSES:
            return f"capture {capture_id}: answered {status}"
    return ""


class Ledger:
    """Records outcomes into the findings store's ``lead_ledger`` and reads them back."""

    def __init__(
        self,
        store: FindingStore,
        *,
        review_days: float = DEFAULT_REVIEW_DAYS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self.review_days = float(review_days)
        self._clock = clock or store.now

    def now(self) -> float:
        return self._clock()

    def review_at(self, days: float | None = None) -> float:
        return self.now() + float(self.review_days if days is None else days) * DAY

    # ── writing ─────────────────────────────────────────────────────

    def record(
        self,
        engagement: str,
        *,
        technique: str,
        endpoint: str,
        kind: str,
        reason: str,
        actor: str,
        parameter: str = "",
        code: str = "",
        detail: str = "",
        method: str = "",
        identity: str = "",
        finding_id: str = "",
        vuln_class: str = "",
    ) -> dict[str, Any]:
        """One ledger entry (merged with an open repeat). Attempts get no review date."""
        endpoint = normalize_endpoint(endpoint)
        return self.store.record_ledger(
            {
                "engagement": engagement,
                "key": technique_key(engagement, technique, endpoint, parameter),
                "technique": technique,
                "endpoint": endpoint,
                "parameter": (parameter or "").strip(),
                "method": (method or "").upper(),
                "identity": identity,
                "finding_id": finding_id,
                "class": vuln_class,
                "kind": kind,
                "reason": reason,
                "code": code,
                "detail": _short(detail),
                "review_at": 0.0 if kind == LEDGER_ATTEMPT else self.review_at(),
            },
            actor,
        )

    def supersede_key(
        self,
        engagement: str,
        technique: str,
        endpoint: str,
        parameter: str,
        *,
        actor: str,
        note: str,
    ) -> int:
        return self.store.ledger_supersede(
            engagement,
            actor=actor,
            note=note,
            key=technique_key(engagement, technique, endpoint, parameter),
        )

    def supersede_finding(self, engagement: str, finding_id: str, *, actor: str, note: str) -> int:
        return self.store.ledger_supersede(
            engagement, actor=actor, note=note, finding_id=finding_id
        )

    def _refusal(self, code: str) -> tuple[str, str] | None:
        """``(kind, reason)`` for a gateway refusal code, ``None`` when it decides nothing."""
        if code == "APPROVAL_DENIED":
            return LEDGER_RULED_OUT, APPROVAL_DENIED
        if code in BLOCKING_REFUSALS:
            return LEDGER_RULED_OUT, BLOCKED
        if code in DELIVERY_REFUSALS:
            return LEDGER_ATTEMPT, DELIVERY_FAILED
        return None  # waiting for approval, or the caller's own input error

    def _outcome(
        self, result: dict[str, Any], lookup: CaptureLookup | None
    ) -> tuple[str, str, str, str] | None:
        """``(kind, reason, code, detail)`` for a probe or recipe result; ``None`` = nothing."""
        if result.get("status") == "refused":
            code = str(result.get("code") or "")
            mapped = self._refusal(code)
            if mapped is None:
                return None
            return mapped[0], mapped[1], code, str(result.get("detail") or code)
        if result.get("status") == "error" or result.get("vulnerable") is True:
            return None
        captures = [str(c) for c in result.get("evidence_capture_ids") or [] if c]
        summary = str(result.get("summary") or "")
        problem = _delivery_problem(captures, lookup)
        outcome = str(result.get("outcome") or "")
        if problem or outcome == "not_sent":
            return LEDGER_ATTEMPT, DELIVERY_FAILED, outcome, problem or summary
        if result.get("vulnerable") is False:
            return LEDGER_RULED_OUT, NOT_VULNERABLE, outcome, summary
        return LEDGER_ATTEMPT, UNDECIDED, outcome, summary

    def after_probe(
        self,
        engagement: str,
        probe: str,
        params: dict[str, Any],
        result: dict[str, Any],
        *,
        lookup: CaptureLookup | None = None,
    ) -> dict[str, Any] | None:
        """Record a ``probe_run`` outcome; the entry, or ``None`` when nothing was recorded.

        A positive run supersedes what the same probe ruled out at the same
        place. The actor is the probe (``probe:<name>``).
        """
        if not isinstance(result, dict) or not isinstance(params, dict):
            return None
        url = str(params.get("url") or "")
        if not url:
            return None
        details = result.get("details") if isinstance(result.get("details"), dict) else {}
        parameter = str(params.get("parameter") or details.get("parameter") or "")
        technique = f"probe:{probe}"
        actor = technique
        if result.get("vulnerable") is True:
            self.supersede_key(
                engagement, technique, url, parameter, actor=actor, note="a later run was positive"
            )
            return None
        outcome = self._outcome(result, lookup)
        if outcome is None:
            return None
        kind, reason, code, detail = outcome
        return self.record(
            engagement,
            technique=technique,
            endpoint=url,
            parameter=parameter,
            kind=kind,
            reason=reason,
            code=code,
            detail=f"{probe}: {detail}" if detail else probe,
            method=str(details.get("method") or params.get("method") or ""),
            identity=str(result.get("identity") or params.get("identity") or ""),
            vuln_class=str(result.get("class") or ""),
            actor=actor,
        )

    def after_recipe(
        self,
        engagement: str,
        recipe: dict[str, Any],
        result: dict[str, Any],
        *,
        actor: str,
        lookup: CaptureLookup | None = None,
    ) -> dict[str, Any] | None:
        """Record a ``recipe_run`` outcome, keyed by ``recipe:<name>`` on its endpoint."""
        if not isinstance(result, dict) or not isinstance(recipe, dict):
            return None
        name = str(recipe.get("name") or "")
        endpoint = str(recipe.get("endpoint") or "")
        if not name or not endpoint:
            return None
        technique = f"recipe:{name}"
        parameter = str(recipe.get("parameter") or "")
        if result.get("vulnerable") is True:
            self.supersede_key(
                engagement,
                technique,
                endpoint,
                parameter,
                actor=actor,
                note="a later run was positive",
            )
            return None
        outcome = self._outcome(result, lookup)
        if outcome is None:
            return None
        kind, reason, code, detail = outcome
        return self.record(
            engagement,
            technique=technique,
            endpoint=endpoint,
            parameter=parameter,
            kind=kind,
            reason=reason,
            code=code,
            detail=detail,
            vuln_class=str(recipe.get("class") or ""),
            actor=actor,
        )

    def after_verification(
        self,
        finding: Finding,
        status: str,
        results: list[dict[str, Any]],
        reasons: list[str],
        *,
        actor: str,
        replay_capture_ids: list[str] | None = None,
        lookup: CaptureLookup | None = None,
    ) -> dict[str, Any] | None:
        """Record the verifier's decision on a finding.

        ``exploit_verified`` supersedes what was ruled out for the finding.
        ``discarded`` rules it out (the cited evidence was rejected).
        ``inconclusive`` rules the technique out at that place, unless nothing
        could be re-sent or a replay got no real answer: that is a failed
        delivery, recorded as an attempt.
        """
        engagement = finding.engagement
        if status == Status.EXPLOIT_VERIFIED.value:
            self.supersede_finding(engagement, finding.id, actor=actor, note="verified")
            return None
        if status not in (Status.INCONCLUSIVE.value, Status.DISCARDED.value):
            return None
        technique = TECH_CLAIM
        for result in results or []:
            if result.get("method") == "probe_rerun" and result.get("probe"):
                label = str(result["probe"])
                technique = label if label.startswith("recipe:") else f"probe:{label}"
                break
        text = "; ".join(str(r) for r in reasons or []) or status
        problem = _delivery_problem([str(c) for c in replay_capture_ids or [] if c], lookup)
        if status == Status.DISCARDED.value:
            kind, reason = LEDGER_RULED_OUT, VERIFIER_DISCARDED
        elif problem or self._verification_delivery(results, reasons):
            kind, reason = LEDGER_ATTEMPT, DELIVERY_FAILED
            text = f"{problem}; {text}" if problem else text
        else:
            kind, reason = LEDGER_RULED_OUT, INCONCLUSIVE
        return self.record(
            engagement,
            technique=technique,
            endpoint=finding.endpoint,
            parameter=finding.parameter,
            kind=kind,
            reason=reason,
            code=status,
            detail=text,
            method=finding.method,
            finding_id=finding.id,
            vuln_class=finding.vuln_class,
            actor=actor,
        )

    @staticmethod
    def _verification_delivery(results: list[dict[str, Any]], reasons: list[str]) -> bool:
        joined = " ".join(str(r) for r in reasons or [])
        if any(
            marker in joined
            for marker in (
                "needs operator-approved replay",
                "APPROVAL_REQUIRED",
                "no enforced scope",
                "was refused (",
            )
        ):
            return True
        for result in results or []:
            if result.get("outcome") in ("not_replayed", "refused"):
                return True
            if result.get("method") != "probe_rerun" and result.get("outcome") == "failed":
                status = result.get("replay_status")
                if result.get("replay_capture_id") and (
                    status is None or status in DELIVERY_STATUSES
                ):
                    return True
        return any(code in joined for code in DELIVERY_REFUSALS)

    def after_grade(
        self, finding: Finding, decision: str, reasons: list[str], *, actor: str
    ) -> dict[str, Any] | None:
        """Record a grade. ``hold`` and ``discard`` get a review date; ``submit`` ends both."""
        engagement = finding.engagement
        self.supersede_finding(engagement, finding.id, actor=actor, note=f"graded {decision}")
        if decision not in ("hold", "discard"):
            return None
        rules = [match.group(1) for r in reasons or [] if (match := _RULE.match(str(r)))]
        return self.record(
            engagement,
            technique=TECH_FINDING,
            endpoint=finding.endpoint,
            parameter=finding.parameter,
            kind=LEDGER_RULED_OUT if decision == "discard" else LEDGER_HELD,
            reason=GRADED_DISCARD if decision == "discard" else GRADED_HOLD,
            code=f"rule {rules[0]}" if rules else "",
            detail="; ".join(str(r) for r in reasons or []) or decision,
            method=finding.method,
            finding_id=finding.id,
            vuln_class=finding.vuln_class,
            actor=actor,
        )

    # ── reading ─────────────────────────────────────────────────────

    def holding(self, engagement: str) -> list[dict[str, Any]]:
        """Ruled-out entries that still retire their technique, newest first."""
        now = self.now()
        rows = self.store.ledger(
            engagement, kinds=(LEDGER_RULED_OUT,), states=(STATE_OPEN, STATE_CLOSED)
        )
        return [row for row in rows if holds(row, now)]

    def blocking(self, finding: Finding, holding: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The holding entries that rule this lead out; empty when it may be handed out.

        A lead is out when an entry names it (a grade), or when every one of its
        techniques is ruled out at its endpoint and parameter (an entry for any
        parameter counts for a lead that names none). An agent's ``claim`` is
        not one technique: only an entry about this very finding rules it out.
        """
        mine = [
            e
            for e in holding
            if e.get("finding_id") == finding.id and e["technique"] == TECH_FINDING
        ]
        if mine:
            return mine
        endpoint = normalize_endpoint(finding.endpoint)
        covering: list[dict[str, Any]] = []
        for technique in techniques_of(finding):
            found = [
                e
                for e in holding
                if e["technique"] == technique
                and e["endpoint"] == endpoint
                and (e["parameter"] == finding.parameter or not finding.parameter)
                and (technique != TECH_CLAIM or e.get("finding_id") == finding.id)
            ]
            if not found:
                return []
            covering.extend(found)
        return covering

    def earlier(self, finding: Finding) -> list[dict[str, Any]]:
        """Ruled-out entries for this lead that are past their review date (why it was out)."""
        now = self.now()
        endpoint = normalize_endpoint(finding.endpoint)
        techniques = set(techniques_of(finding)) | {TECH_FINDING}
        rows = self.store.ledger(
            finding.engagement, kinds=(LEDGER_RULED_OUT,), states=(STATE_OPEN,)
        )
        return [
            brief(row)
            for row in rows
            if is_due(row, now)
            and row["technique"] in techniques
            and row["endpoint"] == endpoint
            and (row["parameter"] == finding.parameter or not finding.parameter)
            and (
                row["technique"] not in (TECH_CLAIM, TECH_FINDING)
                or row["finding_id"] == finding.id
            )
        ]

    def listed(self, engagement: str, query: str = "") -> dict[str, Any]:
        """What the agent reads: what is ruled out (and why), recent failed attempts, due count."""
        now = self.now()
        needle = " ".join((query or "").lower().split())
        rows = self.store.ledger(engagement)

        def matches(row: dict[str, Any]) -> bool:
            if not needle:
                return True
            text = " ".join(
                str(row.get(k) or "")
                for k in ("technique", "endpoint", "parameter", "reason", "code", "detail", "class")
            ).lower()
            return all(word in text for word in needle.split())

        ruled = [brief(r, now) for r in rows if holds(r, now) and matches(r)]
        attempts = [
            brief(r, now)
            for r in rows
            if r["kind"] == LEDGER_ATTEMPT and r["state"] == STATE_OPEN and matches(r)
        ]
        return {
            "ok": True,
            "ruled_out": ruled[:MAX_LISTED],
            "ruled_out_total": len(ruled),
            "failed_attempts": attempts[:MAX_ATTEMPTS_LISTED],
            "failed_attempts_total": len(attempts),
            "due_for_review": sum(1 for r in rows if is_due(r, now)),
            "reasons": REASONS,
            "note": (
                "Do not repeat a ruled-out technique at the same endpoint and parameter. "
                "A failed attempt retired nothing: it may be retried."
            ),
        }

    def due(self, engagement: str) -> list[dict[str, Any]]:
        """Ruled-out and held entries whose review date has passed, oldest date first."""
        now = self.now()
        rows = [r for r in self.store.ledger(engagement) if is_due(r, now)]
        rows.sort(key=lambda r: (float(r.get("review_at") or 0.0), r["seq"]))
        return [brief(r, now) for r in rows]


def brief(row: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """One ledger entry as tools, the report and the CLI show it."""
    out = {
        "id": row["id"],
        "kind": row["kind"],
        "technique": row["technique"],
        "endpoint": row["endpoint"],
        "parameter": row["parameter"],
        "method": row["method"],
        "identity": row["identity"],
        "class": row["class"],
        "finding_id": row["finding_id"],
        "reason": row["reason"],
        "code": row["code"],
        "why": row["detail"],
        "by": row["actor"],
        "first_at": row["first_at"],
        "at": row["at"],
        "count": row["count"],
        "review_at": row["review_at"] or None,
        "state": row["state"],
    }
    if row.get("state_note"):
        out["state_note"] = row["state_note"]
        out["state_by"] = row["state_by"]
    if now is not None:
        out["holds"] = holds(row, now)
        out["due"] = is_due(row, now)
    return out


__all__ = [
    "APPROVAL_DENIED",
    "BLOCKED",
    "BLOCKING_REFUSALS",
    "DAY",
    "DEFAULT_REVIEW_DAYS",
    "DELIVERY_FAILED",
    "DELIVERY_REFUSALS",
    "DELIVERY_STATUSES",
    "GRADED_DISCARD",
    "GRADED_HOLD",
    "INCONCLUSIVE",
    "MAX_REVIEW_DAYS",
    "NOT_VULNERABLE",
    "REASONS",
    "REVIEW_DAYS_ENV",
    "TECH_CLAIM",
    "TECH_FINDING",
    "UNDECIDED",
    "VERIFIER_DISCARDED",
    "Ledger",
    "brief",
    "holds",
    "is_due",
    "review_days_from_env",
    "technique_key",
    "techniques_of",
]
