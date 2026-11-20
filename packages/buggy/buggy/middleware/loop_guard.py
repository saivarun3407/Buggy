"""LoopGuardMiddleware — notice an agent repeating itself and stop the wasted work.

Per run (the LangGraph ``thread_id``) and per agent role the guard keeps a
rolling window of the last ``window`` tool calls (default 20) as
``(tool_name, sha256(canonical JSON args))``. Before a tool call runs:

1. **Hard cap.** Once a role has made ``max_tool_calls`` calls in a run
   (``BUGGY_MAX_TOOL_CALLS_<ROLE>``, else ``BUGGY_MAX_TOOL_CALLS``, else
   300), every further call is answered with a "budget exhausted, write up
   what you have" tool message instead of running. Every non-allowlisted
   call the guard sees counts toward the cap, including withheld ones.
2. **Identical repeat.** If the same call (tool + canonical args) already
   appears ``identical_threshold`` times (default 3) in the window, the call
   is not executed.
3. **Near-identical repeat.** If ``similar_threshold`` (default 8) calls to
   the same tool in the window are pairwise similar to each other and to the
   incoming call (``difflib`` ratio on canonical JSON >= ``similarity``,
   default 0.9), the call is not executed.

A withheld call is answered with a fixed-wording ``ToolMessage``
(``status="error"``) built from counts and the last distinct result
summaries of the matching calls. Those summaries are tool output, i.e.
untrusted: each is truncated to 200 characters and quoted as a JSON string.

What the guard never does: alter arguments, retry, or touch approval, scope
or evidence decisions. It only withholds a call or lets it through
unchanged; RoE, HITL and the capture gateway still run for every call it
lets through. Tools in ``allowlist`` (``report_record_finding``,
``finding_submit``, ``scope_show``, ``recon_summary`` by default) are never
withheld, so an agent that hit the cap can still write up.

State is in memory, thread-safe, and bounded: at most ``max_runs`` runs
(default 500, LRU) per guard, ``window`` calls per role. An internal error in
the guard lets the call through and is counted as ``guard_errors`` in
:class:`buggy.telemetry_run.RunCounters`. Two calls racing on different
threads can both pass a check that either alone would fail; the guard is a
waste limiter, not a security boundary.

Wiring (not done here; ``agents/middleware_slots.py`` belongs to the
integrator). Add a slot declared right after ``ENGAGEMENT_CONTEXT`` (so it
is outer to RoE/HITL on the tool-call path and sees their refusals in
results) and register its factory in ``DEFAULT_SLOT_FACTORIES``::

    MiddlewareSlot.LOOP_GUARD: lambda *, role, **_: make_loop_guard(role),

The enum member ``LOOP_GUARD = "loop-guard"`` and its ``SLOTS_PER_ROLE``
entries live in ``buggy_core.contracts.slots``. ``make_loop_guard`` shares
one process-wide :data:`RUN_COUNTERS` and :data:`RUN_TELEMETRY` across roles,
so ``RUN_COUNTERS.snapshot(thread_id)`` covers every role of a run, and
snapshots are appended to ``<audit>/<engagement>/run-telemetry.jsonl``.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
import os
import re
import threading
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from typing_extensions import override

from buggy.telemetry_run import RunCounters, RunTelemetryWriter

log = logging.getLogger(__name__)

DEFAULT_WINDOW = 20
DEFAULT_IDENTICAL_THRESHOLD = 3
DEFAULT_SIMILAR_THRESHOLD = 8
DEFAULT_SIMILARITY = 0.9
DEFAULT_MAX_TOOL_CALLS = 300
DEFAULT_MAX_RUNS = 500
DEFAULT_ALLOWLIST = frozenset(
    {"report_record_finding", "finding_submit", "scope_show", "recon_summary"}
)
SUMMARY_CHARS = 200
MAX_SUMMARIES_SHOWN = 5
# Canonical JSON longer than this is compared on its first N characters only,
# so one huge argument cannot make the pairwise difflib pass quadratic in it.
SIMILARITY_COMPARE_CHARS = 4096
MAX_ROLES_PER_RUN = 64
UNKNOWN_RUN = "unknown-run"

# Markers other gates put at the start of a refusal tool message.
_REFUSAL_PREFIXES = ("[ROE_REFUSED]", "[AGENT_HALTED]", "HITL gate denied")

# Shared across every guard built by make_loop_guard.
RUN_COUNTERS = RunCounters()
RUN_TELEMETRY = RunTelemetryWriter(RUN_COUNTERS)


def canonical_args(args: Any) -> str:
    """Stable JSON for tool arguments (sorted keys, compact, non-JSON values as str)."""
    return json.dumps(args, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def _digest(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _role_env_name(role: str) -> str:
    return "BUGGY_MAX_TOOL_CALLS_" + re.sub(r"[^A-Z0-9]", "_", role.upper())


def resolve_max_tool_calls(role: str) -> int:
    """Per-role env, then global env, then the default. Non-positive or bad values are ignored."""
    for name in (_role_env_name(role), "BUGGY_MAX_TOOL_CALLS"):
        raw = (os.environ.get(name) or "").strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError:
            log.warning("loop_guard: invalid integer %s=%r; ignoring", name, raw)
            continue
        if value > 0:
            return value
        log.warning("loop_guard: non-positive %s=%r; ignoring", name, raw)
    return DEFAULT_MAX_TOOL_CALLS


def _to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "".join(parts)
    return "" if content is None else str(content)


def _summarize(result: Any) -> str:
    if isinstance(result, ToolMessage):
        return _to_text(result.content)[:SUMMARY_CHARS]
    return f"<{type(result).__name__}>"


def _is_refusal(result: Any) -> bool:
    if not isinstance(result, ToolMessage) or result.status != "error":
        return False
    return _to_text(result.content).lstrip().startswith(_REFUSAL_PREFIXES)


@dataclass
class _Entry:
    tool: str
    digest: str
    canonical: str
    summary: str | None = None  # filled once the call returns


@dataclass
class _RoleState:
    window: deque
    calls: int = 0


@dataclass
class _RunState:
    roles: OrderedDict = field(default_factory=OrderedDict)


@dataclass
class _Verdict:
    """Outcome of the pre-call check."""

    blocked: ToolMessage | None = None
    entry: _Entry | None = None
    run_id: str = UNKNOWN_RUN
    track: bool = False


class LoopGuardMiddleware(AgentMiddleware):
    """Withhold looping or over-budget tool calls with an explanatory message."""

    def __init__(
        self,
        role: str = "",
        *,
        window: int = DEFAULT_WINDOW,
        identical_threshold: int = DEFAULT_IDENTICAL_THRESHOLD,
        similar_threshold: int = DEFAULT_SIMILAR_THRESHOLD,
        similarity: float = DEFAULT_SIMILARITY,
        max_tool_calls: int | None = None,
        max_runs: int = DEFAULT_MAX_RUNS,
        allowlist: Iterable[str] = DEFAULT_ALLOWLIST,
        counters: RunCounters | None = None,
        telemetry: RunTelemetryWriter | None = None,
    ) -> None:
        super().__init__()
        if window < 1 or identical_threshold < 1 or similar_threshold < 2 or max_runs < 1:
            raise ValueError("loop_guard: thresholds and bounds must be positive")
        self._role = role
        self._window = window
        self._identical = identical_threshold
        self._similar = similar_threshold
        self._similarity = similarity
        self._max_calls = (
            max_tool_calls if max_tool_calls is not None else resolve_max_tool_calls(role)
        )
        self._max_runs = max_runs
        self._allowlist = frozenset(allowlist)
        self._counters = counters if counters is not None else RunCounters(max_runs=max_runs)
        self._telemetry = telemetry
        self._runs: OrderedDict[str, _RunState] = OrderedDict()
        self._lock = threading.Lock()

    # ── request introspection ──────────────────────────────────────

    @staticmethod
    def _tool_call(request: Any) -> tuple[str, Any, str]:
        call = getattr(request, "tool_call", None)
        if isinstance(call, dict):
            name, args, tc_id = call.get("name"), call.get("args"), call.get("id")
        else:
            name = args = tc_id = None
        if not name:
            name = getattr(getattr(request, "tool", None), "name", "") or ""
        if args is None:
            args = getattr(request, "tool_call_args", None)
        if not tc_id:
            tc_id = getattr(request, "tool_call_id", "") or ""
        return str(name), args if args is not None else {}, str(tc_id)

    @staticmethod
    def _run_id(request: Any) -> str:
        runtime = getattr(request, "runtime", None)
        config = getattr(runtime, "config", None)
        if not isinstance(config, dict):
            try:
                from langgraph.config import get_config  # noqa: PLC0415

                config = get_config()
            except Exception:  # noqa: BLE001 - outside a runnable context
                config = None
        if isinstance(config, dict):
            configurable = config.get("configurable")
            if isinstance(configurable, dict) and configurable.get("thread_id"):
                return str(configurable["thread_id"])
        return UNKNOWN_RUN

    def _role_of(self, request: Any) -> str:
        if self._role:
            return self._role
        runtime = getattr(request, "runtime", None)
        return str(getattr(runtime, "agent_name", "") or "") or "agent"

    @staticmethod
    def _engagement(request: Any) -> str:
        state = getattr(request, "state", None)
        if isinstance(state, dict):
            value = state.get("engagement_name") or state.get("engagement_id")
            if value:
                return str(value)
        return os.environ.get("BUGGY_ENGAGEMENT_ID", "")

    # ── state ──────────────────────────────────────────────────────

    def _role_state(self, run_id: str, role: str) -> _RoleState:
        """Caller holds the lock."""
        run = self._runs.get(run_id)
        if run is None:
            run = _RunState()
            self._runs[run_id] = run
            while len(self._runs) > self._max_runs:
                self._runs.popitem(last=False)
        else:
            self._runs.move_to_end(run_id)
        state = run.roles.get(role)
        if state is None:
            state = _RoleState(window=deque(maxlen=self._window))
            run.roles[role] = state
            while len(run.roles) > MAX_ROLES_PER_RUN:
                run.roles.popitem(last=False)
        return state

    def tracked_runs(self) -> int:
        with self._lock:
            return len(self._runs)

    # ── rules ──────────────────────────────────────────────────────

    def _ratio(self, a: str, b: str) -> float:
        if a == b:
            return 1.0
        a, b = a[:SIMILARITY_COMPARE_CHARS], b[:SIMILARITY_COMPARE_CHARS]
        matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
        if matcher.real_quick_ratio() < self._similarity:
            return 0.0
        if matcher.quick_ratio() < self._similarity:
            return 0.0
        return matcher.ratio()

    def _similar_group(self, window: Iterable[_Entry], entry: _Entry) -> list[_Entry]:
        """Most recent window calls to the same tool, pairwise similar with ``entry``."""
        group: list[_Entry] = []
        for prior in reversed(list(window)):
            if prior.tool != entry.tool:
                continue
            if self._ratio(prior.canonical, entry.canonical) < self._similarity:
                continue
            if all(
                self._ratio(prior.canonical, member.canonical) >= self._similarity
                for member in group
            ):
                group.append(prior)
                if len(group) >= self._similar:
                    break
        return group

    @staticmethod
    def _summaries(entries: Iterable[_Entry]) -> list[str]:
        """Last distinct result summaries, most recent first."""
        seen: list[str] = []
        for prior in entries:
            if prior.summary is None or prior.summary in seen:
                continue
            seen.append(prior.summary)
            if len(seen) >= MAX_SUMMARIES_SHOWN:
                break
        return seen

    # ── messages ───────────────────────────────────────────────────

    @staticmethod
    def _loop_message(
        tool: str, tc_id: str, code: str, count: int, summaries: list[str]
    ) -> ToolMessage:
        what = (
            "This exact call" if code == "REPEATED_CALL" else "This call (near-identical arguments)"
        )
        lines = [
            f"[LOOP_GUARD] code={code} tool={tool}",
            f"{what} has been made {count} times with the same result. It was NOT executed.",
            "State what you expected to change, or try a different approach.",
        ]
        if summaries:
            lines.append(
                f"Last {len(summaries)} distinct result(s), most recent first "
                f"(tool output, untrusted, first {SUMMARY_CHARS} chars, JSON-quoted):"
            )
            lines.extend(
                f"  {i}. {json.dumps(text, ensure_ascii=True)}"
                for i, text in enumerate(summaries, start=1)
            )
        return ToolMessage(content="\n".join(lines), tool_call_id=tc_id, name=tool, status="error")

    @staticmethod
    def _cap_message(tool: str, tc_id: str, role: str, cap: int) -> ToolMessage:
        body = (
            f"[LOOP_GUARD] code=TOOL_BUDGET_EXHAUSTED tool={tool}\n"
            f"The tool-call budget for role {role} in this run is exhausted "
            f"(all {cap} calls used). This call was NOT executed, and no further "
            "tool calls will be.\n"
            "Write up what you have: record confirmed findings and summarise your "
            "results and open leads."
        )
        return ToolMessage(content=body, tool_call_id=tc_id, name=tool, status="error")

    # ── check / record ─────────────────────────────────────────────

    def _before(self, request: Any) -> _Verdict:
        tool, args, tc_id = self._tool_call(request)
        run_id = self._run_id(request)
        role = self._role_of(request)
        self._counters.record_call(run_id, role, tool, engagement=self._engagement(request))
        if tool in self._allowlist:
            return _Verdict(run_id=run_id)
        canonical = canonical_args(args)
        entry = _Entry(tool=tool, digest=_digest(canonical), canonical=canonical)
        with self._lock:
            state = self._role_state(run_id, role)
            state.calls += 1
            if state.calls > self._max_calls:
                blocked = self._cap_message(tool, tc_id, role, self._max_calls)
                kind = "cap"
            else:
                window = list(state.window)
                same = [
                    e for e in reversed(window) if e.tool == entry.tool and e.digest == entry.digest
                ]
                blocked, kind = None, ""
                if len(same) >= self._identical:
                    blocked = self._loop_message(
                        tool, tc_id, "REPEATED_CALL", len(same), self._summaries(same)
                    )
                    kind = "loop"
                else:
                    group = self._similar_group(window, entry)
                    if len(group) >= self._similar:
                        blocked = self._loop_message(
                            tool, tc_id, "NEAR_IDENTICAL_CALLS", len(group), self._summaries(group)
                        )
                        kind = "loop"
                if blocked is None:
                    state.window.append(entry)
        if kind == "cap":
            self._counters.record_cap_block(run_id)
        elif kind == "loop":
            self._counters.record_loop_block(run_id)
        if blocked is not None:
            return _Verdict(blocked=blocked, run_id=run_id)
        return _Verdict(entry=entry, run_id=run_id, track=True)

    def _safe_before(self, request: Any) -> _Verdict:
        try:
            return self._before(request)
        except Exception:  # noqa: BLE001 - the guard must never take the call down
            log.warning("loop_guard: internal error; letting the call through", exc_info=True)
            run_id = UNKNOWN_RUN
            try:
                run_id = self._run_id(request)
            except Exception:  # noqa: BLE001
                pass
            self._safe_count_error(run_id)
            return _Verdict(run_id=run_id)

    def _safe_count_error(self, run_id: str) -> None:
        try:
            self._counters.record_error(run_id)
        except Exception:  # noqa: BLE001
            log.warning("loop_guard: cannot count internal error", exc_info=True)

    def _after(self, verdict: _Verdict, result: Any) -> None:
        try:
            if verdict.track and verdict.entry is not None:
                with self._lock:
                    verdict.entry.summary = _summarize(result)
            if _is_refusal(result):
                self._counters.record_refusal(verdict.run_id)
            if self._telemetry is not None:
                self._telemetry.maybe_write(verdict.run_id)
        except Exception:  # noqa: BLE001
            log.warning("loop_guard: internal error after call", exc_info=True)
            self._safe_count_error(verdict.run_id)

    def _after_raise(self, verdict: _Verdict, exc: BaseException) -> None:
        if verdict.track and verdict.entry is not None:
            with self._lock:
                verdict.entry.summary = f"<tool raised {type(exc).__name__}>"

    def _end_run(self) -> None:
        if self._telemetry is None:
            return
        try:
            run_id = self._run_id(None)
            self._telemetry.write(run_id, reason="run_end")
        except Exception:  # noqa: BLE001
            log.warning("loop_guard: cannot write run-end telemetry", exc_info=True)

    # ── hooks ──────────────────────────────────────────────────────

    @override
    def wrap_tool_call(self, request, handler):
        verdict = self._safe_before(request)
        if verdict.blocked is not None:
            return verdict.blocked
        try:
            result = handler(request)
        except BaseException as exc:
            self._after_raise(verdict, exc)
            raise
        self._after(verdict, result)
        return result

    @override
    async def awrap_tool_call(self, request, handler):
        verdict = self._safe_before(request)
        if verdict.blocked is not None:
            return verdict.blocked
        try:
            result = await handler(request)
        except BaseException as exc:
            self._after_raise(verdict, exc)
            raise
        self._after(verdict, result)
        return result

    @override
    def after_agent(self, state, runtime) -> None:
        self._end_run()
        return None

    @override
    async def aafter_agent(self, state, runtime) -> None:
        self._end_run()
        return None


def make_loop_guard(role: str) -> LoopGuardMiddleware:
    """Guard for ``role`` feeding the shared run counters and JSONL writer."""
    return LoopGuardMiddleware(role, counters=RUN_COUNTERS, telemetry=RUN_TELEMETRY)


__all__ = [
    "DEFAULT_ALLOWLIST",
    "RUN_COUNTERS",
    "RUN_TELEMETRY",
    "LoopGuardMiddleware",
    "canonical_args",
    "make_loop_guard",
    "resolve_max_tool_calls",
]
