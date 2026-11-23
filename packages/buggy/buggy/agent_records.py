"""What an outside agent's runs leave behind, under ``<audit>/<engagement>/agent/``.

    calls.jsonl         one line per tool call the bridge answered (the trace)
    leases/<run>.json   one lease per bridge run: started, epoch, ended
    agent-runs.jsonl    one line per Claude Code session: tokens, cost, wall time,
                        tool calls (the launcher's numbers, appended by ``--status``)

The operator container mounts the audit root read-only, so the launcher mounts
this one folder writable for the bridge and its status call and names it in
``BUGGY_AGENT_RECORDS``. Readers find it at its usual place. They are plain
code: the trace review, ``buggy-cli halt`` (which lists the leases it
revokes) and ``hunt --finalize`` (the "Agent cost" line).

Writing is best effort: a records directory that cannot be written costs the
records, never the run. Nothing here decides whether a call may go ahead; the
halt switch and the guards do that (:mod:`buggy.capture.halt`,
:mod:`buggy.agent_bridge`).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from buggy.pipeline.schema import as_dict

log = logging.getLogger("buggy.agent_records")

RECORDS_DIR = "agent"
CALLS_FILE = "calls.jsonl"
LEASES_DIR = "leases"
RUNS_FILE = "agent-runs.jsonl"

#: How a capture id looks (``capture/store.py``): found in tool results and finding claims.
CAPTURE_ID = re.compile(r"\bcap-[0-9a-f]{16}\b")
MAX_IDS_PER_LINE = 60

#: Tools that exist to sign in, and words in a call's arguments that point at signing in.
#: A heuristic for the overhead count only; nothing is refused on it.
SIGNIN_TOOLS = frozenset({"identities_list", "accounts_provision"})
SIGNIN_WORDS = re.compile(
    r"log[-_ ]?in|sign[-_ ]?in|sign[-_ ]?up|signon|register|oauth|sso\b|password|passwd|"
    r"/auth\b|/session|/token|reset",
    re.IGNORECASE,
)


#: Where the launcher mounted ``<audit>/<engagement>/agent`` writable, if it did.
RECORDS_ENV = "BUGGY_AGENT_RECORDS"


def records_dir(audit: Path, engagement: str) -> Path:
    mounted = (os.environ.get(RECORDS_ENV) or "").strip()
    return Path(mounted) if mounted else audit / engagement / RECORDS_DIR


def runs_file(audit: Path, engagement: str) -> Path:
    return records_dir(audit, engagement) / RUNS_FILE


#: What a session line keeps of the launcher's record, and of Claude Code's result.
_RUN_KEYS = (
    "at",
    "session",
    "run",
    "role",
    "attempt",
    "call_budget",
    "wall_seconds",
    "exit",
    "error",
)
_CLAUDE_KEYS = (
    "type",
    "subtype",
    "is_error",
    "num_turns",
    "duration_ms",
    "duration_api_ms",
    "total_cost_usd",
    "session_id",
    "terminal_reason",
    "stop_reason",
    "usage",
)
_USAGE_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


def append_run(audit: Path, engagement: str, record: dict[str, Any]) -> dict[str, Any]:
    """Append one session line: the launcher's numbers plus this run's call counts.

    Only known fields are kept (strings cut short), so the line holds numbers
    and names, never the agent's text. Raises ``OSError`` when it cannot write.
    """
    line: dict[str, Any] = {"engagement": engagement}
    for key in _RUN_KEYS:
        value = record.get(key)
        if isinstance(value, str):
            line[key] = value[:300]
        elif isinstance(value, int | float) and not isinstance(value, bool):
            line[key] = value
    claude = record.get("claude")
    if isinstance(claude, dict):
        kept = {k: claude[k] for k in _CLAUDE_KEYS if k in claude and k != "usage"}
        kept = {k: v[:120] if isinstance(v, str) else v for k, v in kept.items()}
        usage = claude.get("usage")
        if isinstance(usage, dict):
            kept["usage"] = {k: usage[k] for k in _USAGE_KEYS if isinstance(usage.get(k), int)}
        line["claude"] = kept
    counts = run_counts(calls(audit, engagement)).get(str(line.get("run") or ""), {})
    line["tool_calls"] = int(counts.get("calls", 0))
    line["refused"] = int(counts.get("refused", 0))
    line["signin_calls"] = int(counts.get("signin_calls", 0))
    path = runs_file(audit, engagement)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line) + "\n")
    return line


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """The objects of a JSONL file; a missing file is empty and bad lines are skipped."""
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
    except (FileNotFoundError, NotADirectoryError):
        pass
    except OSError as exc:
        log.warning("cannot read %s: %s", path, exc)
    return rows


def digest(value: Any) -> str:
    """A short stable digest of a JSON-able value (sorted keys)."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def capture_ids(text: str) -> list[str]:
    """Capture ids named in ``text``, first-seen order, at most ``MAX_IDS_PER_LINE``."""
    seen: dict[str, None] = {}
    for match in CAPTURE_ID.finditer(text or ""):
        seen.setdefault(match.group(0), None)
        if len(seen) >= MAX_IDS_PER_LINE:
            break
    return list(seen)


def is_signin_call(tool: str, args: dict[str, Any]) -> bool:
    """Whether a call looks like sign-in overhead (by tool, or by words in its arguments)."""
    if tool in SIGNIN_TOOLS:
        return True
    if tool not in {"http_send", "browser_open", "browser_fill", "browser_click", "surface_crawl"}:
        return False
    text = " ".join(str(v) for k, v in args.items() if k != "body")
    return bool(SIGNIN_WORDS.search(text))


def refusal_code(result: str) -> tuple[str, str]:
    """``(status, code)`` of a tool result: ``ok``, ``refused`` or ``error``.

    The bridge's own refusals are text starting with ``BLOCKED`` or ``HALTED``;
    a server's are JSON with ``status: refused`` (the gateway), ``ok: false``
    with a ``code`` (the finding service) or an ``error``.
    """
    text = (result or "").lstrip()
    if text.startswith(("BLOCKED", "HALTED")):
        match = re.match(r"(?:BLOCKED|HALTED)\s*\[([A-Z_]+)\]", text)
        return "refused", match.group(1) if match else text.split(":", 1)[0]
    try:
        parsed = json.loads(text)
    except ValueError:
        return "ok", ""
    if not isinstance(parsed, dict):
        return "ok", ""
    if parsed.get("status") == "refused":
        return "refused", str(parsed.get("code") or "REFUSED")[:60]
    if parsed.get("ok") is False:
        return "refused", str(parsed.get("code") or "NOT_OK")[:60]
    if parsed.get("error"):
        code = str(parsed["error"])
        return "error", code[:60] if re.fullmatch(r"[A-Z_]{3,60}", code) else "ERROR"
    return "ok", ""


class RunRecords:
    """The trace and the lease of one bridge run. Best effort: write failures are logged once."""

    def __init__(
        self,
        audit: Path,
        engagement: str,
        *,
        run_id: str,
        session: str = "",
        role: str = "",
        attempt: int = 0,
        clock: Any = time.time,
    ) -> None:
        self.directory = records_dir(audit, engagement)
        self.engagement = engagement
        self.run_id = run_id
        self.session = session
        self.role = role
        self.attempt = attempt
        self._clock = clock
        self._seq = 0
        self._warned = False

    @property
    def calls_path(self) -> Path:
        return self.directory / CALLS_FILE

    @property
    def lease_path(self) -> Path:
        return self.directory / LEASES_DIR / f"{self.run_id}.json"

    def _fail(self, what: str, exc: OSError) -> None:
        if not self._warned:
            log.warning("cannot write the agent %s under %s: %s", what, self.directory, exc)
            self._warned = True

    def call(
        self,
        tool: str,
        args: dict[str, Any],
        result: str,
        *,
        started: float,
        status: str = "",
        code: str = "",
    ) -> dict[str, Any]:
        """Append one trace line for a call and return it."""
        self._seq += 1
        if not status:
            status, code = refusal_code(result)
        line: dict[str, Any] = {
            "at": started,
            "run": self.run_id,
            "session": self.session,
            "role": self.role,
            "attempt": self.attempt,
            "seq": self._seq,
            "tool": tool,
            "args_digest": digest(args),
            "status": status,
            "code": code,
            "ms": int(max(0.0, self._clock() - started) * 1000),
            "result_digest": digest(result),
            "captures": capture_ids(result) if status == "ok" else [],
            "signin": is_signin_call(tool, args),
        }
        if tool == "finding_submit":
            line["cited"] = capture_ids(json.dumps(args, default=str))
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            with self.calls_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(line) + "\n")
        except OSError as exc:
            self._fail("trace", exc)
        return line

    def _write_lease(self, record: dict[str, Any]) -> None:
        try:
            self.lease_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.lease_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(record) + "\n", encoding="utf-8")
            os.replace(tmp, self.lease_path)
        except OSError as exc:
            self._fail("lease", exc)

    def lease_start(self, epoch: int) -> dict[str, Any]:
        record = {
            "run": self.run_id,
            "session": self.session,
            "role": self.role,
            "attempt": self.attempt,
            "engagement": self.engagement,
            "started_at": self._clock(),
            "epoch": epoch,
            "ended_at": None,
            "end": "",
        }
        self._lease = record
        self._write_lease(record)
        return record

    def lease_end(self, reason: str) -> None:
        record = getattr(self, "_lease", None)
        if record is None:
            return
        record = {**record, "ended_at": self._clock(), "end": reason[:200]}
        self._lease = record
        self._write_lease(record)


def open_leases(audit: Path, engagement: str) -> list[dict[str, Any]]:
    """Leases of runs that have not recorded an end (running, or stopped without one)."""
    directory = records_dir(audit, engagement) / LEASES_DIR
    out: list[dict[str, Any]] = []
    try:
        paths = sorted(directory.glob("*.json"))
    except OSError:
        return out
    for path in paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(record, dict) and not record.get("ended_at"):
            out.append(record)
    return out


def calls(audit: Path, engagement: str) -> list[dict[str, Any]]:
    return read_jsonl(records_dir(audit, engagement) / CALLS_FILE)


def run_counts(lines: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per run id: tool calls, refused calls, sign-in calls, role, attempt and session."""
    out: dict[str, dict[str, Any]] = {}
    for line in lines:
        run = str(line.get("run") or "")
        if not run:
            continue
        row = out.setdefault(
            run,
            {
                "run": run,
                "session": str(line.get("session") or ""),
                "role": str(line.get("role") or ""),
                "attempt": line.get("attempt") or 0,
                "calls": 0,
                "refused": 0,
                "signin_calls": 0,
            },
        )
        row["calls"] += 1
        row["refused"] += 1 if line.get("status") == "refused" else 0
        row["signin_calls"] += 1 if line.get("signin") else 0
    return out


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def cost_summary(rows: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """Totals over ``agent-runs.jsonl``: sessions, tool calls, tokens, cost, wall time.

    A field Claude Code did not report stays out of the total; ``cost_usd`` is
    ``None`` when no session reported a cost. ``None`` when there are no rows.
    """
    rows = [row for row in rows if isinstance(row, dict)]
    if not rows:
        return None
    tokens = dict.fromkeys(
        ("input", "output", "cache_read", "cache_creation"),
        0,
    )
    names = {
        "input": "input_tokens",
        "output": "output_tokens",
        "cache_read": "cache_read_input_tokens",
        "cache_creation": "cache_creation_input_tokens",
    }
    cost: float | None = None
    wall = 0.0
    tool_calls = signin = 0
    by_role: dict[str, int] = {}
    for row in rows:
        claude = as_dict(row.get("claude"))
        usage = as_dict(claude.get("usage"))
        for key, field in names.items():
            value = _number(usage.get(field))
            tokens[key] += int(value) if value is not None else 0
        spent = _number(claude.get("total_cost_usd"))
        if spent is not None:
            cost = (cost or 0.0) + spent
        wall += _number(row.get("wall_seconds")) or 0.0
        tool_calls += int(_number(row.get("tool_calls")) or 0)
        signin += int(_number(row.get("signin_calls")) or 0)
        role = str(row.get("role") or "agent")
        by_role[role] = by_role.get(role, 0) + 1
    return {
        "sessions": len(rows),
        "by_role": by_role,
        "tool_calls": tool_calls,
        "signin_calls": signin,
        "tokens": tokens,
        "cost_usd": round(cost, 4) if cost is not None else None,
        "wall_seconds": round(wall, 1),
    }


def _count(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 10_000:
        return f"{n // 1000}k"
    return str(n)


def cost_line(summary: dict[str, Any] | None) -> str:
    """One plain line for reports, e.g. ``2 Claude Code sessions, 143 tool calls ...``."""
    if not summary:
        return ""
    tokens = summary.get("tokens") or {}
    read_in = int(tokens.get("input", 0)) + int(tokens.get("cache_read", 0))
    read_in += int(tokens.get("cache_creation", 0))
    parts = [
        f"{summary['sessions']} Claude Code session(s)",
        f"{summary['tool_calls']} tool calls ({summary['signin_calls']} on sign-in)",
        f"{_count(read_in)} input and {_count(int(tokens.get('output', 0)))} output tokens",
        "cost not reported"
        if summary.get("cost_usd") is None
        else f"${summary['cost_usd']:.2f} as reported by Claude Code",
        f"{round(float(summary.get('wall_seconds') or 0) / 60, 1)} min",
    ]
    return ", ".join(parts)


__all__ = [
    "CALLS_FILE",
    "CAPTURE_ID",
    "RECORDS_ENV",
    "RUNS_FILE",
    "RunRecords",
    "append_run",
    "calls",
    "capture_ids",
    "cost_line",
    "cost_summary",
    "digest",
    "is_signin_call",
    "open_leases",
    "read_jsonl",
    "records_dir",
    "refusal_code",
    "run_counts",
    "runs_file",
]
