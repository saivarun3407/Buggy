"""``buggy-cli status <engagement>`` — one read-only snapshot of a run.

    buggy-cli status acme
    buggy-cli status acme --json
    buggy-cli status acme --follow --interval 5

Everything known about an engagement, assembled from the stores this shell
can reach, in seven sections: ``scope``, ``recon``, ``approvals``,
``evidence``, ``findings``, ``agents`` and ``next`` (what to do now).

Nothing is written, started or sent to a target. The operator-controlled
root and the audit root are read from disk; recon, evidence and findings are
read through the stack's MCP servers. A section that cannot be read says
``"available": false`` with the reason. It is never filled with a guess, and
the command still exits 0: an unreachable server is a fact about the run, not
a failure of ``status``. Exit 2 means the engagement does not exist.

:func:`snapshot` is the pure core (also the data source for the dashboard and
for ``hunt`` resume): the roots, the remote reader and the clock are
arguments, so it is testable without a stack.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, TextIO

from buggy.cli import _paths
from buggy.pipeline.scope import PipelineLimits
from buggy.program.record import load_program
from buggy_core.types.roe_document import InvalidRoEError, parse_roe_document

EXIT_OK = 0
EXIT_CONFIG = 2

DEFAULT_INTERVAL_SECONDS = 5.0

#: ``fetch(server, tool, arguments) -> dict``: one read from a stack MCP server.
Fetch = Callable[[str, str, dict[str, Any]], dict[str, Any]]

RECON_NOT_STARTED = "not_started"
RECON_RUNNING = "running"
#: Run states after which the pipeline does nothing more on its own. An
#: ``interrupted`` run is not one of them: the worker resumes it.
RECON_FINISHED = frozenset({"completed", "failed"})

#: ``http_captures`` is asked for the newest capture only.
CAPTURES_LIMIT = 1

FINDING_STATUSES = (
    "candidate",
    "exploit_verified",
    "source_verified",
    "inconclusive",
    "discarded",
)
FINDING_GRADES = ("submit", "hold", "discard")
UNGRADED = "ungraded"
SEVERITIES = ("critical", "high", "medium", "low", "info")

# How many list entries the human output shows per section.
SHOWN_PENDING = 3
SHOWN_FINDINGS = 3
SHOWN_PATTERNS = 4
SHOWN_RECORD_TYPES = 4


class UnknownEngagement(LookupError):
    """There is no directory for this engagement under the control root."""


# ── small helpers ────────────────────────────────────────────────────


def _unavailable(detail: str) -> dict[str, Any]:
    return {"available": False, "detail": detail}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float | None:
    """A JSON number as a float; ``None`` for anything else (booleans included)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _count(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None and number >= 0 else None


def _rule_text(entry: Any) -> str:
    return str(entry.get("target")) if isinstance(entry, dict) else str(entry)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """JSON objects, one per line. A missing file is empty; an unreadable one raises."""
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
    except FileNotFoundError:
        pass
    return rows


def _remote(
    fetch: Fetch, server: str, tool: str, arguments: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """``(result, None)`` for a usable result, ``({}, unavailable-section)`` otherwise."""
    try:
        result = fetch(server, tool, arguments)
    except Exception as exc:  # noqa: BLE001 - a failed read is reported in its section
        return {}, _unavailable(f"{server}.{tool} failed: {type(exc).__name__}: {str(exc)[:300]}")
    if not isinstance(result, dict):
        return {}, _unavailable(f"{server}.{tool} returned {type(result).__name__}, not an object")
    if result.get("error"):
        return {}, _unavailable(str(result["error"])[:400])
    return result, None


# ── sections ─────────────────────────────────────────────────────────


def _scope_section(control: Path, engagement: str) -> dict[str, Any]:
    """The enforced scope, read with the parser and the limits the enforcement uses."""
    path = control / engagement / "roe.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _unavailable(f"no enforced scope at {path}")
    except (OSError, ValueError) as exc:
        return _unavailable(f"cannot read the enforced scope {path}: {exc}")
    try:
        rules = parse_roe_document(document, required=True)
    except InvalidRoEError as exc:
        return _unavailable(f"the enforced scope {path} is invalid: {exc}")
    block = _dict(document.get("machine_enforcement"))
    approvals = _dict(document.get("approvals"))

    program: dict[str, Any] | None = None
    record = load_program(control, engagement)
    if record is not None:
        if "_invalid" in record:
            program = {"platform": "", "handle": "", "invalid": str(record["_invalid"])}
        else:
            program = {
                "platform": str(record.get("platform") or ""),
                "handle": str(record.get("handle") or ""),
            }
    return {
        "available": True,
        "mode": rules.mode.value,
        "in_scope": [_rule_text(entry) for entry in block.get("in_scope") or []],
        "out_of_scope": [_rule_text(entry) for entry in block.get("out_of_scope") or []],
        "rate_limit_rps": PipelineLimits.from_roe(rules, document).rate_limit_rps,
        "sandbox_egress": rules.sandbox_egress,
        "approvals": {
            "state_changing": str(approvals.get("state_changing", "required")),
            "report_submission": str(approvals.get("report_submission", "not_required")),
        },
        "program": program,
    }


def _recon_section(fetch: Fetch, engagement: str, now: float) -> dict[str, Any]:
    """Pipeline state from ``recon_summary``.

    ``stage`` and ``stages_done`` describe a run in progress; the summary does
    not report them for a finished run. ``scope_drops`` belongs to the last
    finished run, so it is ``None`` while a run is in progress or before any.
    """
    summary, failed = _remote(fetch, "recon", "recon_summary", {"engagement": engagement})
    if failed is not None:
        return failed
    if "current_run" not in summary or "last_run" not in summary:
        # An empty or foreign result must not read as "recon has not started".
        return _unavailable("recon.recon_summary returned no run state")
    current = _dict(summary.get("current_run"))
    last = _dict(summary.get("last_run"))
    records = {
        str(name): count
        for name, value in sorted(_dict(summary.get("records")).items())
        if (count := _count(value)) is not None
    }
    section: dict[str, Any] = {
        "available": True,
        "state": RECON_NOT_STARTED,
        "stage": "",
        "stages_done": [],
        "started_at": None,
        "elapsed_s": None,
        "records": records,
        "scope_drops": None,
    }
    if current:
        started = _number(current.get("started_at"))
        done = current.get("stages_done")
        section.update(
            state=RECON_RUNNING,
            stage=str(current.get("stage") or ""),
            stages_done=[str(stage) for stage in done] if isinstance(done, list) else [],
            started_at=started,
            elapsed_s=None if started is None else round(max(0.0, now - started), 1),
        )
    elif last:
        started = _number(last.get("started_at"))
        finished = _number(last.get("finished_at"))
        section.update(
            state=str(last.get("status") or "unknown"),
            started_at=started,
            elapsed_s=(
                None
                if started is None or finished is None
                else round(max(0.0, finished - started), 1)
            ),
            scope_drops=_count(last.get("scope_drops")),
        )
    return section


def _approvals_section(control: Path, audit: Path, engagement: str) -> dict[str, Any]:
    """Requests (audit root) joined with the operator's decisions (control root).

    A request is pending while no decision names it, which is what
    ``buggy-cli approvals list`` shows. The last decision for a request is the
    one that counts, as in the capture gateway.
    """
    requests_path = audit / engagement / "approvals" / "requests.jsonl"
    decisions_path = control / engagement / "approvals" / "decisions.jsonl"
    try:
        request_rows = _read_jsonl(requests_path)
        decision_rows = _read_jsonl(decisions_path)
    except OSError as exc:
        return _unavailable(f"cannot read the approval files: {exc}")

    requests: dict[str, dict[str, Any]] = {}
    for row in request_rows:
        request_id = str(row.get("request_id") or "")
        if request_id:
            requests.setdefault(request_id, row)
    actions = {
        str(row.get("request_id")): str(row.get("action") or "").lower() for row in decision_rows
    }

    counts = {"pending": 0, "allowed": 0, "denied": 0, "other": 0}
    pending: list[dict[str, Any]] = []
    for request_id, row in requests.items():
        action = actions.get(request_id)
        if action is None:
            counts["pending"] += 1
            item: dict[str, Any] = {
                "request_id": request_id,
                "tool_name": str(row.get("tool_name") or ""),
                "reason": str(row.get("reason") or ""),
            }
            arguments = _dict(row.get("tool_args_redacted"))
            for key in ("method", "url"):
                if arguments.get(key):
                    item[key] = str(arguments[key])
            pending.append(item)
        elif action == "allow":
            counts["allowed"] += 1
        elif action == "deny":
            counts["denied"] += 1
        else:
            counts["other"] += 1
    return {"available": True, "total": len(requests), **counts, "pending_requests": pending}


def _evidence_section(fetch: Fetch, engagement: str) -> dict[str, Any]:
    """Capture count and the time of the newest capture.

    ``count`` is what the capture server reports. A server that counts only
    the rows it returned cannot say more than "at least this many" once the
    page is full, and then ``count_is_lower_bound`` is true.
    """
    result, failed = _remote(
        fetch, "capture", "http_captures", {"engagement": engagement, "limit": CAPTURES_LIMIT}
    )
    if failed is not None:
        return failed
    captures = result.get("captures")
    if not isinstance(captures, list):
        return _unavailable("capture.http_captures returned no capture list")
    reported = _count(result.get("count"))
    count = len(captures) if reported is None else max(reported, len(captures))
    newest = _dict(captures[0]) if captures else {}
    return {
        "available": True,
        "count": count,
        "count_is_lower_bound": count == len(captures) and len(captures) >= CAPTURES_LIMIT,
        "last_capture_at": _number(newest.get("created_at")),
    }


def _severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _findings_section(fetch: Fetch, engagement: str) -> dict[str, Any]:
    result, failed = _remote(fetch, "capture", "findings_list", {"engagement": engagement})
    if failed is not None:
        return failed
    rows = result.get("findings", result.get("result"))
    if not isinstance(rows, list):
        return _unavailable("capture.findings_list returned no finding list")
    findings = [row for row in rows if isinstance(row, dict)]
    by_status = dict.fromkeys(FINDING_STATUSES, 0)
    by_grade = dict.fromkeys((*FINDING_GRADES, UNGRADED), 0)
    verified: list[dict[str, str]] = []
    for finding in findings:
        status = str(finding.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        grade = str(finding.get("grade") or UNGRADED)
        by_grade[grade] = by_grade.get(grade, 0) + 1
        if status == "exploit_verified":
            verified.append(
                {
                    "id": str(finding.get("id") or ""),
                    "title": str(finding.get("title") or ""),
                    "severity": str(finding.get("severity") or ""),
                    "class": str(finding.get("class") or ""),
                }
            )
    verified.sort(key=lambda item: (_severity_rank(item["severity"]), item["id"]))
    return {
        "available": True,
        "total": len(findings),
        "by_status": by_status,
        "by_grade": by_grade,
        "exploit_verified": verified,
    }


def _agents_section(audit: Path, engagement: str) -> dict[str, Any]:
    """The guardrail's decision ledger: its last line and how many calls it allowed or refused."""
    path = audit / engagement / "roe-decisions.jsonl"
    try:
        rows = _read_jsonl(path)
    except OSError as exc:
        return _unavailable(f"cannot read the decision ledger {path}: {exc}")
    decisions = [str(row.get("decision") or "") for row in rows]
    last: dict[str, Any] | None = None
    if rows:
        row = rows[-1]
        last = {
            "at": _number(row.get("ts")),
            "tool": str(row.get("tool") or ""),
            "decision": str(row.get("decision") or ""),
            "event": str(row.get("event") or ""),
        }
    return {
        "available": True,
        "last": last,
        "allow": decisions.count("allow"),
        "refuse": decisions.count("refuse"),
    }


# ── next actions ─────────────────────────────────────────────────────


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _no_sign_of_agents(
    approvals: Mapping[str, Any], evidence: Mapping[str, Any], agents: Mapping[str, Any]
) -> bool:
    """True only when all three places an agent leaves a trace were read and are empty."""
    return bool(
        agents.get("available")
        and agents.get("last") is None
        and approvals.get("available")
        and not approvals.get("total")
        and evidence.get("available")
        and not evidence.get("count")
    )


def next_actions(engagement: str, sections: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Plain-language next steps, most urgent first, computed only from the sections."""
    scope, recon = sections["scope"], sections["recon"]
    approvals, evidence = sections["approvals"], sections["evidence"]
    findings, agents = sections["findings"], sections["agents"]
    hints: list[str] = []

    if not scope.get("available"):
        hints.append(
            f"The enforced scope cannot be used ({scope.get('detail')}): "
            f"buggy-cli scope show {engagement}"
        )
    elif _dict(scope.get("program")).get("invalid"):
        hints.append(
            f"The program record is damaged ({scope['program']['invalid']}): import it again "
            "with buggy-cli scope import"
        )

    if approvals.get("available"):
        pending = int(approvals.get("pending") or 0)
        if pending:
            waits = "request waits" if pending == 1 else "requests wait"
            hints.append(f"{pending} {waits} for approval: buggy-cli approvals list {engagement}")
    else:
        hints.append(f"Approvals cannot be read: {approvals.get('detail')}")

    if recon.get("available"):
        state = recon.get("state")
        if state == RECON_NOT_STARTED:
            if scope.get("available") and scope.get("mode") != "enforce":
                hints.append(
                    f"Recon will not start: the pipeline runs only in 'enforce' mode and the "
                    f"scope is in {scope.get('mode')!r} mode"
                )
            else:
                hints.append(
                    "Recon has not started: the pipeline worker starts it when it sees the "
                    f"enforced scope (watch with buggy-cli status {engagement} --follow)"
                )
        elif state == RECON_RUNNING:
            stage = recon.get("stage") or "starting"
            hints.append(
                f"Recon is running (stage: {stage}): buggy-cli status {engagement} --follow"
            )
        elif state == "failed":
            hints.append(
                "Recon failed: read the pipeline service log, then run it again with "
                f"buggy-cli pipeline run {engagement}"
            )
        elif state == "interrupted":
            hints.append(
                "Recon was interrupted: the pipeline worker resumes it on its own "
                f"(watch with buggy-cli status {engagement} --follow)"
            )
        elif state == "completed" and _no_sign_of_agents(approvals, evidence, agents):
            hints.append(
                "Recon is complete and nothing shows that an agent has run (no guardrail "
                "decision, capture or approval request): "
                f"buggy hunt <target> --engagement-name {engagement} continues from this recon"
            )
    else:
        hints.append(f"Recon state is unknown: {recon.get('detail')}")

    if findings.get("available"):
        verified = len(findings.get("exploit_verified") or [])
        if verified:
            hints.append(
                f"{_plural(verified, 'finding is', 'findings are')} exploit-verified and "
                "ready for review"
            )
        by_status = _dict(findings.get("by_status"))
        unverified = int(by_status.get("candidate") or 0) + int(by_status.get("inconclusive") or 0)
        if unverified:
            hints.append(
                f"{_plural(unverified, 'finding is', 'findings are')} not verified yet "
                "(candidate or inconclusive) and do not count as findings"
            )
    else:
        hints.append(f"Findings cannot be read: {findings.get('detail')}")

    if not evidence.get("available"):
        hints.append(f"Evidence cannot be read: {evidence.get('detail')}")
    if not agents.get("available"):
        hints.append(f"Agent activity cannot be read: {agents.get('detail')}")
    return hints


# ── the snapshot ─────────────────────────────────────────────────────


def _valid_name(engagement: str) -> bool:
    name = engagement.strip()
    return (
        bool(name)
        and name == engagement
        and not name.startswith(".")
        and not ("/" in name or "\\" in name or "\x00" in name)
    )


def snapshot(
    engagement: str,
    *,
    control: Path,
    audit: Path,
    fetch: Fetch,
    now: float,
) -> dict[str, Any]:
    """Everything known about ``engagement`` right now, as a JSON-serialisable dict.

    ``control`` and ``audit`` are the roots that hold ``<engagement>/``.
    ``fetch(server, tool, arguments)`` reads from a stack MCP server
    (``buggy.tools.stack_mcp.call_mcp_sync`` in production). A read that
    raises, returns an ``error`` or returns something unusable turns its
    section into ``{"available": false, "detail": ...}``.

    Raises :class:`UnknownEngagement` when the control root has no directory
    for the engagement. Nothing is written.
    """
    control, audit = Path(control), Path(audit)
    if not _valid_name(engagement):
        raise UnknownEngagement(f"{engagement!r} is not an engagement name")
    if not (control / engagement).is_dir():
        raise UnknownEngagement(f"no engagement {engagement!r} under {control}")
    sections: dict[str, dict[str, Any]] = {
        "scope": _scope_section(control, engagement),
        "recon": _recon_section(fetch, engagement, now),
        "approvals": _approvals_section(control, audit, engagement),
        "evidence": _evidence_section(fetch, engagement),
        "findings": _findings_section(fetch, engagement),
        "agents": _agents_section(audit, engagement),
    }
    return {
        "engagement": engagement,
        "generated_at": now,
        **sections,
        "next": next_actions(engagement, sections),
    }


def is_settled(snap: Mapping[str, Any]) -> bool:
    """True when ``--follow`` has nothing left to wait for.

    That is: recon reached a final state and no approval request is pending.
    A section that could not be read is never taken as settled.
    """
    recon, approvals = _dict(snap.get("recon")), _dict(snap.get("approvals"))
    return bool(
        recon.get("available")
        and recon.get("state") in RECON_FINISHED
        and approvals.get("available")
        and not approvals.get("pending")
    )


def _comparable(snap: Mapping[str, Any]) -> str:
    """The snapshot without its clock readings, so a tick alone is not a change."""
    stable = {key: value for key, value in snap.items() if key != "generated_at"}
    recon = stable.get("recon")
    if isinstance(recon, dict):
        stable["recon"] = {key: value for key, value in recon.items() if key != "elapsed_s"}
    return json.dumps(stable, sort_keys=True, default=str)


def follow(
    take: Callable[[], dict[str, Any]],
    emit: Callable[[dict[str, Any]], None],
    *,
    sleep: Callable[[float], None],
    interval: float,
) -> dict[str, Any]:
    """Emit a snapshot whenever it changes; return the one that is settled.

    The first snapshot is always emitted. Runs until :func:`is_settled`, or
    until ``take`` or ``sleep`` raises (Ctrl-C).
    """
    previous: str | None = None
    while True:
        snap = take()
        current = _comparable(snap)
        if current != previous:
            emit(snap)
            previous = current
        if is_settled(snap):
            return snap
        sleep(interval)


# ── output ───────────────────────────────────────────────────────────


def _clock(at: Any, *, date: bool = False) -> str:
    number = _number(at)
    if number is None:
        return "unknown"
    try:
        moment = datetime.datetime.fromtimestamp(number, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return "unknown"
    return moment.strftime("%Y-%m-%d %H:%M:%SZ" if date else "%H:%M:%SZ")


def _duration(seconds: Any) -> str:
    number = _number(seconds)
    if number is None:
        return "unknown"
    whole = int(number)
    hours, rest = divmod(whole, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def _shown(items: Iterable[str], limit: int) -> str:
    values = list(items)
    text = ", ".join(values[:limit])
    return f"{text} (+{len(values) - limit} more)" if len(values) > limit else text


def _row(label: str, text: str) -> str:
    return f"{label:<10} {text}".rstrip()


def _sub(label: str, text: str) -> str:
    return f"  {label:<8} {text}".rstrip()


def _render_scope(scope: Mapping[str, Any]) -> list[str]:
    approvals = _dict(scope.get("approvals"))
    parts = [
        f"{scope.get('mode')} mode",
        f"{scope.get('rate_limit_rps')} req/s",
        f"sandbox {scope.get('sandbox_egress')}",
        f"state-changing approval {approvals.get('state_changing')}",
    ]
    program = _dict(scope.get("program"))
    if program.get("invalid"):
        parts.append("program record damaged")
    elif program:
        parts.append(f"program {program.get('platform')}/{program.get('handle')}")
    lines = [
        _row("scope", " · ".join(parts)),
        _sub("in", _shown(scope.get("in_scope") or [], SHOWN_PATTERNS) or "(nothing)"),
    ]
    if scope.get("out_of_scope"):
        lines.append(_sub("out", _shown(scope["out_of_scope"], SHOWN_PATTERNS)))
    return lines


def _render_recon(recon: Mapping[str, Any]) -> list[str]:
    state = str(recon.get("state"))
    parts = [state.replace("_", " ")]
    if state == RECON_RUNNING:
        done = recon.get("stages_done") or []
        parts.append(f"stage {recon.get('stage') or 'starting'}")
        parts.append(f"{_plural(len(done), 'stage', 'stages')} done")
    if recon.get("started_at") is not None:
        parts.append(f"started {_clock(recon['started_at'])}")
    if recon.get("elapsed_s") is not None:
        parts.append(f"{_duration(recon['elapsed_s'])} elapsed")
    records = _dict(recon.get("records"))
    by_size = sorted(records.items(), key=lambda item: (-item[1], item[0]))
    detail = f"{sum(records.values())} total"
    if by_size:
        named = _shown((f"{name} {count}" for name, count in by_size), SHOWN_RECORD_TYPES)
        detail += f" ({named})"
    if recon.get("scope_drops") is not None:
        detail += f" · {recon['scope_drops']} dropped as out of scope"
    return [_row("recon", " · ".join(parts)), _sub("records", detail)]


def _render_approvals(approvals: Mapping[str, Any]) -> list[str]:
    summary = (
        f"{approvals.get('pending')} pending · {approvals.get('allowed')} allowed · "
        f"{approvals.get('denied')} denied"
    )
    if approvals.get("other"):
        summary += f" · {approvals['other']} other"
    lines = [_row("approvals", summary)]
    pending = approvals.get("pending_requests") or []
    for item in pending[:SHOWN_PENDING]:
        what = " ".join(str(item[key]) for key in ("tool_name", "method", "url") if item.get(key))
        reason = f" — {item['reason']}" if item.get("reason") else ""
        lines.append(f"  {item.get('request_id')}  {what}{reason}"[:160])
    if len(pending) > SHOWN_PENDING:
        lines.append(f"  (+{len(pending) - SHOWN_PENDING} more)")
    return lines


def _render_evidence(evidence: Mapping[str, Any]) -> list[str]:
    count = int(evidence.get("count") or 0)
    if evidence.get("count_is_lower_bound"):
        text = f"at least {_plural(count, 'capture', 'captures')}"
    else:
        text = _plural(count, "capture", "captures")
    if evidence.get("last_capture_at") is not None:
        text += f" · last {_clock(evidence['last_capture_at'])}"
    return [_row("evidence", text)]


def _render_findings(findings: Mapping[str, Any]) -> list[str]:
    by_status = _dict(findings.get("by_status"))
    by_grade = _dict(findings.get("by_grade"))
    statuses = " · ".join(f"{count} {name}" for name, count in by_status.items() if count)
    grades = ", ".join(f"{count} {name}" for name, count in by_grade.items() if count)
    text = statuses or "none"
    if grades:
        text += f" | grade: {grades}"
    lines = [_row("findings", text)]
    verified = findings.get("exploit_verified") or []
    for item in verified[:SHOWN_FINDINGS]:
        lines.append(
            f"  {item.get('id')}  {item.get('severity')}  {item.get('class')}  {item.get('title')}"[
                :160
            ]
        )
    if len(verified) > SHOWN_FINDINGS:
        lines.append(f"  (+{len(verified) - SHOWN_FINDINGS} more exploit-verified)")
    return lines


def _render_agents(agents: Mapping[str, Any]) -> list[str]:
    last = agents.get("last")
    if not last:
        return [_row("agents", "no activity recorded")]
    what = " ".join(str(last[key]) for key in ("tool", "decision", "event") if last.get(key))
    return [
        _row(
            "agents",
            f"last {_clock(last.get('at'))} {what} · {agents.get('allow')} allowed, "
            f"{agents.get('refuse')} refused",
        )
    ]


_RENDERERS: tuple[tuple[str, Callable[[Mapping[str, Any]], list[str]]], ...] = (
    ("scope", _render_scope),
    ("recon", _render_recon),
    ("approvals", _render_approvals),
    ("evidence", _render_evidence),
    ("findings", _render_findings),
    ("agents", _render_agents),
)


def render_text(snap: Mapping[str, Any]) -> str:
    """Compact sections for a terminal. Times are UTC."""
    lines = [f"{snap.get('engagement')} · status at {_clock(snap.get('generated_at'), date=True)}"]
    for name, render in _RENDERERS:
        section = _dict(snap.get(name))
        if section.get("available"):
            lines.extend(render(section))
        else:
            lines.append(_row(name, f"unavailable: {section.get('detail')}"[:200]))
    actions = snap.get("next") or []
    if actions:
        lines.append("next")
        lines.extend(f"  - {action}"[:240] for action in actions)
    else:
        lines.append(_row("next", "nothing needs you right now"))
    return "\n".join(lines)


def render_json(snap: Mapping[str, Any], *, compact: bool = False) -> str:
    if compact:
        return json.dumps(snap, separators=(",", ":"), default=str)
    return json.dumps(snap, indent=2, default=str)


# ── CLI ──────────────────────────────────────────────────────────────


def _positive_seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        value = 0.0
    if not 0 < value < float("inf"):
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive number of seconds")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="buggy-cli status",
        description=(
            "Show one read-only snapshot of an engagement: scope, recon, approvals, evidence, "
            "findings, agent activity and what to do next. A section that cannot be read is "
            "marked unavailable. Exit 0 on a snapshot, 2 when the engagement does not exist."
        ),
    )
    parser.add_argument("engagement")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the snapshot as JSON (with --follow: one compact JSON object per line)",
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="print again whenever the snapshot changes, until Ctrl-C or until recon has "
        "finished and no approval request is pending",
    )
    parser.add_argument(
        "--interval",
        type=_positive_seconds,
        default=DEFAULT_INTERVAL_SECONDS,
        help="seconds between reads with --follow (default: %(default)s)",
    )
    parser.add_argument("--control-root", type=Path, default=None)
    parser.add_argument("--audit-root", type=Path, default=None)
    return parser


def _stack_fetch() -> Fetch:
    """The real remote reader; a reader that reports why when the client cannot be loaded."""
    try:
        from buggy.tools.stack_mcp import call_mcp_sync  # noqa: PLC0415 - heavy, only when run
    except ImportError as exc:
        reason = f"the stack MCP client cannot be loaded: {exc}"

        def missing(server: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
            return {"error": reason}

        return missing
    return call_mcp_sync


def _known_engagements(control: Path) -> list[str]:
    try:
        return sorted(p.name for p in control.iterdir() if p.is_dir() and _valid_name(p.name))
    except OSError:
        return []


def main(
    argv: list[str] | None = None,
    *,
    fetch: Fetch | None = None,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Print the snapshot. The keyword arguments replace the real world in tests."""
    args = _build_parser().parse_args(argv)
    control = _paths.control_root(args.control_root)
    audit = _paths.audit_root(args.audit_root)
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    clock = clock or time.time
    sleep = sleep or time.sleep
    reader = fetch or _stack_fetch()

    def take() -> dict[str, Any]:
        return snapshot(args.engagement, control=control, audit=audit, fetch=reader, now=clock())

    def emit(snap: dict[str, Any]) -> None:
        if args.json:
            print(render_json(snap, compact=args.follow), file=out)
        else:
            print(render_text(snap) + ("\n" if args.follow else ""), file=out)
        out.flush()

    try:
        if args.follow:
            follow(take, emit, sleep=sleep, interval=args.interval)
        else:
            emit(take())
    except UnknownEngagement as exc:
        known = _known_engagements(control)
        listed = f"known engagements: {_shown(known, 10)}" if known else "it holds no engagement"
        print(f"error: {exc} ({listed})", file=err)
        return EXIT_CONFIG
    except KeyboardInterrupt:
        return EXIT_OK
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
