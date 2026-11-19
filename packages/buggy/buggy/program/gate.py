"""The rules a program engagement runs under. All of it is plain code.

* :func:`mode_error` — a program engagement runs in ``enforce`` mode or not at all.
* :func:`finding_errors` — a finding needs a captured request against the
  in-scope target that verifies (and, when safe to re-send, reproduces), and a
  remediation. Excluded classes and banned techniques are refused.
* :func:`report_release` — a report is released only after the operator
  approved that exact text.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from buggy.program.record import banned_technique_ids

#: ``verify(capture_id, target)`` -> ``{"valid": bool, "reason": str, "method": str,
#: "reproduced": bool | None}``. ``reproduced`` is ``None`` when the request was
#: not re-sent (it changes state).
Verifier = Callable[[str, str], dict[str, Any]]

MIN_REMEDIATION_CHARS = 30
_PLACEHOLDER = re.compile(r"^\W*(?:tbd|todo|n/?a|none|pending|fix it|see above)\W*$", re.IGNORECASE)

_BANNED_CLASS_MARKERS: dict[str, tuple[str, ...]] = {
    "denial_of_service": ("dos", "denial of service", "denial-of-service", "resource exhaustion"),
    "social_engineering": ("phishing", "social engineering", "social-engineering", "vishing"),
    "physical": ("physical access", "physical security"),
}


def mode_error(program: dict[str, Any] | None, mode: str) -> str | None:
    """Why this engagement may not run, or ``None``."""
    if program is None:
        return None
    if program.get("_invalid"):
        return f"program record is unreadable ({program['_invalid']}); re-import the scope"
    if str(mode).lower() != "enforce":
        return (
            f"this is a bounty-program engagement ({program.get('platform')}/"
            f"{program.get('handle')}) and its scope is in {mode!r} mode; program engagements "
            "run in 'enforce' mode only"
        )
    return None


def _text(finding: dict[str, Any], *keys: str) -> str:
    return " ".join(str(finding.get(k) or "") for k in keys).lower()


def finding_errors(finding: dict[str, Any], program: dict[str, Any], verify: Verifier) -> list[str]:
    """Every reason this finding may not be recorded for the program. Empty = acceptable."""
    errors: list[str] = []
    if program.get("_invalid"):
        return [f"program record is unreadable ({program['_invalid']}); re-import the scope"]

    remediation = str(finding.get("remediation") or "").strip()
    if len(remediation) < MIN_REMEDIATION_CHARS or _PLACEHOLDER.match(remediation):
        errors.append(
            "remediation is required: say what the owner should change to fix this "
            f"(at least {MIN_REMEDIATION_CHARS} characters, not a placeholder)"
        )

    described = _text(finding, "vuln_class", "title")
    banned = set(banned_technique_ids(program))
    for technique, markers in _BANNED_CLASS_MARKERS.items():
        if technique in banned and any(marker in described for marker in markers):
            errors.append(f"banned technique for this program: {technique.replace('_', ' ')}")
    for excluded in program.get("excluded_classes") or []:
        name = str(excluded).strip().lower()
        if name and len(name) >= 4 and name in described:
            errors.append(f"the program does not accept this class: {excluded}")

    target = str(finding.get("target") or "").strip()
    if not target:
        errors.append("target is required: the in-scope URL the captured request was sent to")
    capture_ids = [str(c).strip() for c in finding.get("capture_ids") or [] if str(c).strip()]
    if not capture_ids:
        errors.append(
            "capture_ids is required: cite at least one request sent through the evidence "
            "gateway (http_send / probe_run) that demonstrates the issue"
        )
        return errors
    for capture_id in capture_ids:
        result = verify(capture_id, target)
        if not result.get("valid"):
            errors.append(f"capture {capture_id}: {result.get('reason') or 'did not verify'}")
        elif result.get("reproduced") is False:
            errors.append(
                f"capture {capture_id}: the request did not reproduce when re-sent "
                f"({result.get('reason') or 'different outcome'})"
            )
    return errors


# ── report release ───────────────────────────────────────────────────


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                try:
                    obj = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
    except OSError:
        pass
    return rows


def report_fingerprint(finding_id: str, report_text: str) -> str:
    return hashlib.sha256(f"{finding_id}\n{report_text}".encode()).hexdigest()


def report_release(
    control_root: Path,
    audit_root: Path,
    engagement: str,
    finding_id: str,
    report_text: str,
    *,
    kind: str = "report",
) -> dict[str, Any]:
    """Whether the operator approved releasing exactly this report.

    The approval is bound to the text: an edited report is a new request. The
    first call files the request and writes the draft under the audit root for
    the operator to read; nothing is released until a decision exists in the
    operator-controlled root.
    """
    fingerprint = report_fingerprint(finding_id, report_text)
    requests_path = Path(audit_root) / engagement / "approvals" / "requests.jsonl"
    decisions_path = Path(control_root) / engagement / "approvals" / "decisions.jsonl"
    mine = [
        r
        for r in _read_jsonl(requests_path)
        if (r.get("metadata") or {}).get("fingerprint") == fingerprint
    ]
    decisions = {str(d.get("request_id")): d for d in _read_jsonl(decisions_path)}
    for request in mine:
        decision = decisions.get(str(request.get("request_id")))
        if decision is None:
            continue
        if str(decision.get("action")) == "allow":
            return {
                "released": True,
                "request_id": str(request["request_id"]),
                "approved_by": str(decision.get("operator") or ""),
            }
        return {
            "released": False,
            "status": "denied",
            "request_id": str(request["request_id"]),
            "operator_note": str(decision.get("operator_note") or ""),
        }
    if mine:
        request_id = str(mine[-1]["request_id"])
    else:
        request_id = f"rpt-{uuid.uuid4().hex[:12]}"
        draft = Path(audit_root) / engagement / "reports" / f"{request_id}.md"
        try:
            draft.parent.mkdir(parents=True, exist_ok=True)
            draft.write_text(report_text, encoding="utf-8")
            requests_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "kind": "approval_request",
                "request_id": request_id,
                "engagement_name": engagement,
                "agent_name": "reporting",
                "tool_name": "report_submission",
                "tool_args_redacted": {"finding_id": finding_id, "kind": kind, "draft": str(draft)},
                "reason": f"release the {kind} for {finding_id} for submission to the program",
                "metadata": {"fingerprint": fingerprint},
                "requested_at": time.time(),
            }
            with requests_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except OSError as exc:
            return {
                "released": False,
                "status": "unavailable",
                "detail": f"cannot file the approval request: {exc}",
            }
    return {
        "released": False,
        "status": "approval_required",
        "request_id": request_id,
        "detail": (
            "A report is released only after the operator approves this exact text. "
            f"Operator: buggy-cli approvals allow {engagement} {request_id}"
        ),
    }


__all__ = [
    "MIN_REMEDIATION_CHARS",
    "Verifier",
    "finding_errors",
    "mode_error",
    "report_fingerprint",
    "report_release",
]
