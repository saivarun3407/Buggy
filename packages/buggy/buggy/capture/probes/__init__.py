"""Deterministic probes: one mechanical check each, evidence included.

A probe takes the *where* from the agent (which endpoint, which identities,
which field) and does the *how* in code: it sends a fixed sequence of
requests through the capture gateway, compares the outcomes, and returns a
verdict with the capture ids that support it. Because every request goes
through the gateway, a probe is scope-checked, rate-limited, approval-gated
and recorded like any other evidence request.

A probe answers ``vulnerable: true`` only when it observed the unsafe
behaviour, ``false`` when it observed the safe behaviour, and ``null`` when it
could not tell (a precondition failed). It never guesses.
"""

from __future__ import annotations

from buggy.capture.probes.base import ProbeResult, ProbeSpec
from buggy.capture.probes.registry import REGISTRY, describe, run_probe

__all__ = ["REGISTRY", "ProbeResult", "ProbeSpec", "describe", "run_probe"]
