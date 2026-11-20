"""Per-run telemetry: what a run did, counted, not estimated.

``RunCounters`` holds thread-safe, in-memory counters per run (the LangGraph
thread id). They are fed by :mod:`buggy.middleware.loop_guard`, which sees
every tool call of the agent it wraps:

* tool calls by tool name and by agent role,
* calls withheld by the loop rule (``blocked_by_loop``) and by the hard
  per-role cap (``blocked_by_cap``),
* refusals by other gates observed in tool results (RoE, emergency abort,
  HITL denial) — only visible when the guard sits outside those gates,
* internal guard errors (``guard_errors``; the call was let through).

Memory is bounded: at most ``max_runs`` runs (LRU) and ``max_tools`` distinct
tool names per run (the rest are counted under ``"<other>"``).

``RunTelemetryWriter`` appends ``snapshot(run_id)`` as one JSON line to
``<audit root>/<engagement>/run-telemetry.jsonl`` (``BUGGY_AUDIT_ROOT``,
default ``/audit``). It never rewrites the file. The guard calls
``maybe_write`` after every tool call (a line at most every ``interval``
seconds, default 30) and ``write`` when an agent run ends. There is no
background thread: a run with no tool activity writes nothing until it ends.

Token and cost numbers are NOT produced here. :func:`spend` reads them from
LiteLLM's spend log through ``benchmark.lab.agent.spend_between`` and returns
``None`` when the proxy cannot be reached, the payload is unusable, or the
``benchmark`` package is not importable (it is a repo-root package and is not
shipped in the framework wheel).

Standard library only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_MAX_RUNS = 500
DEFAULT_MAX_TOOLS = 256
DEFAULT_INTERVAL_SECONDS = 30.0
TELEMETRY_FILENAME = "run-telemetry.jsonl"
OTHER_TOOL = "<other>"

_SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


@dataclass
class _Run:
    engagement: str = ""
    started_at: float = 0.0
    updated_at: float = 0.0
    by_tool: Counter = field(default_factory=Counter)
    by_role: Counter = field(default_factory=Counter)
    blocked_by_loop: int = 0
    blocked_by_cap: int = 0
    refusals: int = 0
    guard_errors: int = 0


class RunCounters:
    """Thread-safe per-run counters, bounded to ``max_runs`` runs (LRU)."""

    def __init__(
        self,
        *,
        max_runs: int = DEFAULT_MAX_RUNS,
        max_tools: int = DEFAULT_MAX_TOOLS,
        clock: Any = time.time,
    ) -> None:
        if max_runs < 1 or max_tools < 1:
            raise ValueError("max_runs and max_tools must be positive")
        self._max_runs = max_runs
        self._max_tools = max_tools
        self._clock = clock
        self._runs: OrderedDict[str, _Run] = OrderedDict()
        self._lock = threading.Lock()

    def _run(self, run_id: str, engagement: str = "") -> _Run:
        """Return (creating if needed) the run, marking it most recently used.

        Caller holds the lock.
        """
        run = self._runs.get(run_id)
        now = self._clock()
        if run is None:
            run = _Run(engagement=engagement, started_at=now, updated_at=now)
            self._runs[run_id] = run
            while len(self._runs) > self._max_runs:
                self._runs.popitem(last=False)
        else:
            self._runs.move_to_end(run_id)
            run.updated_at = now
            if engagement and not run.engagement:
                run.engagement = engagement
        return run

    def record_call(self, run_id: str, role: str, tool: str, *, engagement: str = "") -> None:
        with self._lock:
            run = self._run(run_id, engagement)
            if tool not in run.by_tool and len(run.by_tool) >= self._max_tools:
                tool = OTHER_TOOL
            run.by_tool[tool] += 1
            run.by_role[role] += 1

    def record_loop_block(self, run_id: str) -> None:
        with self._lock:
            self._run(run_id).blocked_by_loop += 1

    def record_cap_block(self, run_id: str) -> None:
        with self._lock:
            self._run(run_id).blocked_by_cap += 1

    def record_refusal(self, run_id: str) -> None:
        with self._lock:
            self._run(run_id).refusals += 1

    def record_error(self, run_id: str) -> None:
        with self._lock:
            self._run(run_id).guard_errors += 1

    def run_ids(self) -> list[str]:
        with self._lock:
            return list(self._runs)

    def __len__(self) -> int:
        with self._lock:
            return len(self._runs)

    def snapshot(self, run_id: str) -> dict[str, Any]:
        """JSON-serialisable view of one run; an unknown run yields zero counts."""
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                run = _Run()
            return {
                "run_id": run_id,
                "engagement": run.engagement,
                "started_at": run.started_at,
                "updated_at": run.updated_at,
                "tool_calls": sum(run.by_tool.values()),
                "tool_calls_by_tool": dict(run.by_tool),
                "tool_calls_by_role": dict(run.by_role),
                "blocked_by_loop": run.blocked_by_loop,
                "blocked_by_cap": run.blocked_by_cap,
                "refusals": run.refusals,
                "guard_errors": run.guard_errors,
            }


def _audit_root() -> Path:
    return Path(os.environ.get("BUGGY_AUDIT_ROOT") or "/audit")


class RunTelemetryWriter:
    """Append-only JSONL writer for :class:`RunCounters` snapshots."""

    def __init__(
        self,
        counters: RunCounters,
        *,
        audit_root: Path | str | None = None,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        max_runs: int = DEFAULT_MAX_RUNS,
        clock: Any = time.time,
    ) -> None:
        self._counters = counters
        self._audit_root = Path(audit_root) if audit_root is not None else None
        self._interval = interval_seconds
        self._max_runs = max_runs
        self._clock = clock
        self._last_write: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def path_for(self, engagement: str) -> Path | None:
        """``<audit root>/<engagement>/run-telemetry.jsonl``; None for an unsafe slug."""
        if not engagement or not _SLUG_RE.fullmatch(engagement) or engagement in (".", ".."):
            return None
        root = self._audit_root if self._audit_root is not None else _audit_root()
        return root / engagement / TELEMETRY_FILENAME

    def write(self, run_id: str, *, reason: str = "run_end") -> bool:
        """Append one snapshot line now. Returns whether it reached the file."""
        snap = self._counters.snapshot(run_id)
        path = self.path_for(snap["engagement"])
        if path is None:
            return False
        now = self._clock()
        line = json.dumps({"ts": now, "reason": reason, **snap}, sort_keys=True)
        with self._lock:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                log.warning("run telemetry: cannot append to %s: %s", path, exc)
                return False
            self._last_write[run_id] = now
            self._last_write.move_to_end(run_id)
            while len(self._last_write) > self._max_runs:
                self._last_write.popitem(last=False)
        return True

    def maybe_write(self, run_id: str) -> bool:
        """Write a periodic line if ``interval`` seconds passed since the last one.

        The first call for a run only starts its clock.
        """
        now = self._clock()
        with self._lock:
            last = self._last_write.get(run_id)
            if last is None:
                self._last_write[run_id] = now
                while len(self._last_write) > self._max_runs:
                    self._last_write.popitem(last=False)
                return False
            if now - last < self._interval:
                return False
        return self.write(run_id, reason="periodic")


def spend(litellm_url: str, key: str, since: float) -> dict[str, Any] | None:
    """Spend and tokens LiteLLM recorded from ``since`` until now, or ``None``.

    Reuses ``benchmark.lab.agent.spend_between`` (``/spend/logs``). Returns
    exactly what LiteLLM reports, summed: ``llm_calls``, ``cost_usd``,
    ``prompt_tokens``, ``completion_tokens``, ``tokens``. Nothing is estimated.
    """
    try:
        from benchmark.lab.agent import spend_between  # noqa: PLC0415
    except ImportError as exc:
        log.warning("run telemetry: spend reader unavailable: %s", exc)
        return None
    try:
        result = spend_between(since, time.time(), litellm_url=litellm_url, master_key=key)
    except Exception as exc:  # noqa: BLE001 - unreachable proxy reads as "no data"
        log.warning("run telemetry: spend query failed: %s", exc)
        return None
    if not isinstance(result, dict) or "error" in result:
        return None
    return result


__all__ = [
    "RunCounters",
    "RunTelemetryWriter",
    "spend",
]
