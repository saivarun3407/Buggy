"""Corroboration gate: the second, deterministic check between a proven finding
and a published one.

The proof gate (:mod:`proof_gate`) checks the finder's own evidence. This gate
refuses to let the finder certify itself: a finding publishes only when
independent sources corroborate it, nothing contradicts it, and its evidence
resolves to immutable raw tool output. Plain code over recorded data, no model
call, so identical inputs always yield the identical verdict and reason trace.
Design: ``docs/RESEARCH_PHASE_C.md`` sections 2 and 4.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal


class ClosureState(StrEnum):
    CONFIRMED = "confirmed"
    RULED_OUT = "ruled_out"
    OPEN_PROOF_GAP = "open_proof_gap"


Modality = Literal["static_match", "dynamic_probe", "response_diff", "canary", "log_event"]


@dataclass(frozen=True, slots=True)
class Corroboration:
    source_agent_id: str
    tool_family: str
    modality: Modality
    evidence_id: str


@dataclass(frozen=True, slots=True)
class Contradiction:
    source_agent_id: str
    reason: str
    evidence_id: str


@dataclass(frozen=True, slots=True)
class RuledOut:
    control_name: str
    location: str


@dataclass(frozen=True, slots=True)
class CorroborationResult:
    state: ClosureState
    reasons: list[str]

    @property
    def published(self) -> bool:
        return self.state is ClosureState.CONFIRMED


CorroborationProvider = Callable[[str], tuple[list[Corroboration], list[Contradiction], bool]]


def validate_ruled_out(r: RuledOut) -> list[str]:
    """A ruled_out closure must name a specific control at a specific location."""
    errors = []
    if not r.control_name.strip():
        errors.append("ruled_out must name the specific control that blocks the attack")
    if not r.location.strip():
        errors.append("ruled_out must name the location of that control")
    return errors


def independent_corroboration_count(corroborations: Iterable[Corroboration]) -> int:
    """Count distinct ``(source_agent_id, tool_family)`` sources.

    Agreement from one agent through one tool family is a single signal
    repeated, whatever its modality.
    """
    return len({(c.source_agent_id, c.tool_family) for c in corroborations})


def corroboration_verdict(
    *,
    proof_accepted: bool,
    corroborations: Iterable[Corroboration],
    contradictions: Iterable[Contradiction],
    evidence_resolves: bool,
    min_independent: int = 2,
) -> CorroborationResult:
    contradicted = list(contradictions)
    if contradicted:
        return CorroborationResult(
            state=ClosureState.RULED_OUT,
            reasons=[
                f"{len(contradicted)} contradiction(s) recorded against the finding",
                *(
                    f"contradicted by {c.source_agent_id}: {c.reason} (evidence {c.evidence_id})"
                    for c in contradicted
                ),
            ],
        )

    independent = independent_corroboration_count(corroborations)
    gaps = []
    if not proof_accepted:
        gaps.append("proof gate did not accept the finding")
    if independent < min_independent:
        gaps.append(
            f"{independent} independent corroboration(s), {min_independent} required "
            "(independent = distinct agent and tool family)"
        )
    if not evidence_resolves:
        gaps.append("evidence does not resolve to immutable raw tool output")
    if gaps:
        return CorroborationResult(state=ClosureState.OPEN_PROOF_GAP, reasons=gaps)

    return CorroborationResult(
        state=ClosureState.CONFIRMED,
        reasons=[f"{independent} independent corroborations, no contradictions"],
    )


__all__ = [
    "ClosureState",
    "Contradiction",
    "Corroboration",
    "CorroborationProvider",
    "CorroborationResult",
    "Modality",
    "RuledOut",
    "corroboration_verdict",
    "independent_corroboration_count",
    "validate_ruled_out",
]
