"""Findings — a claim is a finding only once it has been re-proved.

A finding is a claim plus machine-checkable assertions: "re-send the request
behind capture X; the response must have status 200 and contain ``bob@``".
Whoever makes the claim (an agent, a probe, a scanner) submits it as a
``candidate``. A verifier that did not make the claim then re-sends the cited
requests through the capture gateway and evaluates the assertions on the fresh
responses:

* every assertion passes -> ``exploit_verified``;
* an assertion fails -> ``inconclusive`` (flagged, never confirmed);
* a cited capture is missing, out of scope or from another engagement ->
  ``discarded``.

Only ``exploit_verified`` findings are findings in reports, gates and counts.
The prose that comes with a claim (title, description) never enters the
verifier's decision.

* ``model``    — the Finding schema, stable ids, validation.
* ``store``    — ``findings.sqlite3``: findings plus an append-only history.
* ``verifier`` — the replay-and-check decision.
* ``service``  — submit / verify / get / list as JSON-serialisable dicts.

No model or agent library is imported here.
"""

from buggy.findings.model import (
    CLASSES,
    SEVERITIES,
    STATUSES,
    Assertion,
    Expect,
    Finding,
    Severity,
    Status,
    ValidationError,
    VulnClass,
    finding_id,
    normalize_endpoint,
    validate,
)
from buggy.findings.service import FindingService
from buggy.findings.store import FindingNotFound, FindingStore, IllegalTransition
from buggy.findings.verifier import Verification, mark_source_verified, verify

__all__ = [
    "CLASSES",
    "SEVERITIES",
    "STATUSES",
    "Assertion",
    "Expect",
    "Finding",
    "FindingNotFound",
    "FindingService",
    "FindingStore",
    "IllegalTransition",
    "Severity",
    "Status",
    "ValidationError",
    "Verification",
    "VulnClass",
    "finding_id",
    "mark_source_verified",
    "normalize_endpoint",
    "validate",
    "verify",
]
