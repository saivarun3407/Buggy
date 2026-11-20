"""RoE guardrail middleware - the advisory command-parse RoE gate.

This middleware sits between the LLM and the tool surface. Every
``bash`` (and other tool) call is evaluated against the engagement's
``roe.json:machine_enforcement`` block. The outcome is one of:

  * **PASS** in audit mode - logged, allowed to proceed.
  * **WARN** in warn mode - logged, a SystemMessage is appended to the
    tool's return so the model sees it failed RoE, but the call still
    executes.
  * **REFUSE** in enforce mode - logged, the tool call short-circuits
    with a ``[ROE_REFUSED]`` ToolMessage before the handler runs.

Defense-in-depth: this middleware is a *guardrail*, not the sole gate.
It parses the literal command text for target hosts, which is a strong
**fast-fail UX signal** (it tells the model early, before a wasted
round-trip) but cannot be the authoritative boundary — a determined
agent can hide a target behind variable indirection, command
substitution, or DNS resolution the parser never sees. The
authoritative scope boundary is the sandbox's network **egress**
(``middleware/egress.py`` → DNS allowlist + nftables connect
allowlist), compiled from the *same* ``machine_enforcement`` rules, so
the packet cannot leave even when the parse misses. One scope
definition, two enforcement points.

Every decision (PASS too, not just REFUSE) lands in the HMAC-chained
audit ledger via :class:`RoEAuditSink`. The ledger is the legal record
of "what the agent tried, what was approved, what was blocked" - the
key artifact for paid / regulated engagement out-briefs.

Reading the RoE:

  * Enforced location: ``<control>/<engagement>/roe.json`` - operator
    written and mounted read-only (see ``middleware/_control.py``). The
    sandbox cannot write there, so the agent cannot edit its own scope.
  * ``<workspace>/plan/roe.json`` is the agent-writable *draft*. It is read
    only when ``BUGGY_ROE_REQUIRE=0`` and no control copy exists (labs,
    benchmarks, standalone library use).
  * ``BUGGY_ROE_REQUIRE`` defaults to ON: a missing policy refuses every
    gated call instead of silently running in audit mode.
  * Resolved per call so an operator-edited RoE takes effect without a
    restart; the egress boundary is re-provisioned when its digest changes.
  * An unreadable or invalid explicit RoE refuses gated calls until repaired.

Fail-closed behaviour:

  * Egress provisioning failure raises ``EgressProvisioningError`` from
    ``before_agent`` - the run aborts before any tool executes.
  * When RoE is required and the audit ledger cannot be written, gated
    calls are refused (``AUDIT_UNAVAILABLE``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.types import Command
from typing_extensions import override

from buggy.middleware._audit_sink import RoEAuditSink
from buggy.middleware._command_targets import extract_targets
from buggy.middleware._control import (
    audit_dir,
    audit_root,
    control_dir,
    control_roe_path,
    workspace_roe_path,
)
from buggy.middleware.egress import EgressProvisioningError
from buggy_core.types.roe import (
    Decision,
    EnforcementMode,
    MachineEnforcement,
    evaluate_command,
    evaluate_target,
    evaluate_time_window,
)
from buggy_core.types.roe_document import (
    InvalidRoEError,
    _validate_target_entry,  # noqa: F401 - re-exported for buggy.cli.engage
    parse_roe_document,
)
from buggy_core.types.tool_guard import compile_rules, evaluate_call
from buggy_core.utils.env import env_flag, env_truthy

log = logging.getLogger(__name__)


GATED_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "bash",
        "bash_output",
        "bash_kill",
        "http_request",
        "proxy_send_request",
        "browser_action",
        # Open-web engine tools (ADR-0010). web_fetch is target-gated on its
        # url; web_search is OSINT (allowlisted provider) — gated for audit/
        # throttle but target-exempt via a no-op extractor below.
        "web_fetch",
        "web_search",
        "detect_tech_stack",
        # Stack MCP tools that reach a target. The capture gateway and the
        # scoped browser enforce scope themselves; gating them here as well
        # gives the model an early refusal and puts the call in the ledger.
        "http_send",
        "browser_open",
        "probe_run",
        "authz_matrix_run",
    }
)


def _host_from_url(url: Any) -> list[str]:
    if not isinstance(url, str) or not url:
        return []
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return []
    return [host] if host else []


def _hosts_from_url_arg(args: dict[str, Any]) -> list[str]:
    return _host_from_url(args.get("url"))


def _hosts_from_browser_action(args: dict[str, Any]) -> list[str]:
    raw = args.get("params_json")
    if not isinstance(raw, str) or not raw:
        return []
    try:
        params = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(params, dict):
        return []
    return _host_from_url(params.get("url"))


def _hosts_from_probe_run(args: dict[str, Any]) -> list[str]:
    """Hosts named in a probe's parameters (``url`` and ``readback_url``)."""
    raw = args.get("params_json")
    if not isinstance(raw, str) or not raw:
        return []
    try:
        params = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(params, dict):
        return []
    return [h for key in ("url", "readback_url") for h in _host_from_url(params.get(key))]


def _hosts_from_matrix(args: dict[str, Any]) -> list[str]:
    """Every URL an authorization-matrix run would request (``"<url>"``, ``"HEAD <url>"``
    or ``{"url": ...}`` entries of ``urls_json``)."""
    raw = args.get("urls_json")
    try:
        urls = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, ValueError):
        return []
    hosts: list[str] = []
    for entry in urls if isinstance(urls, list) else []:
        if isinstance(entry, dict):
            entry = entry.get("url")
        if isinstance(entry, str):
            hosts += _host_from_url(entry.split()[-1] if entry.strip() else "")
    return hosts


def _hosts_from_web_search(_args: dict[str, Any]) -> list[str]:
    """OSINT exemption: web_search hits an allowlisted provider, not a target.

    Returning no hosts means the per-target scope check is a no-op (the call is
    still audited + throttled because web_search is in GATED_TOOL_NAMES).
    """
    return []


NETWORK_TARGET_EXTRACTORS: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "http_request": _hosts_from_url_arg,
    "proxy_send_request": _hosts_from_url_arg,
    "web_fetch": _hosts_from_url_arg,
    "web_search": _hosts_from_web_search,
    "detect_tech_stack": _hosts_from_url_arg,
    "browser_action": _hosts_from_browser_action,
    "http_send": _hosts_from_url_arg,
    "browser_open": _hosts_from_url_arg,
    "probe_run": _hosts_from_probe_run,
    "authz_matrix_run": _hosts_from_matrix,
}


#: Gated tools with a target argument that execute inside the sandbox. The
#: others (``http_send``, ``probe_run``, ``browser_open`` and the tools routed
#: to them) reach the target through the evidence gateway or scoped browser.
SANDBOX_NETWORK_TOOLS: frozenset[str] = frozenset({"web_fetch"})


def _sandbox_blocked_decision(targets: list[str]) -> Decision:
    """Early, explanatory refusal; the egress guard drops the packets regardless."""
    return Decision.refuse(
        code="SANDBOX_NETWORK_BLOCKED",
        detail=(
            f"this engagement gives the sandbox no network path to targets ({', '.join(targets[:3])}). "
            "Send requests with http_send, run checks with probe_run, drive pages with browser_*, "
            "and read recon with recon_query. State-changing requests are held for the operator there."
        ),
    )


TOOL_GUARD_BLOCKED = "TOOL_GUARD_BLOCKED"


def _tool_guard_decision(
    tool_name: str, args: dict[str, Any], rules: MachineEnforcement
) -> Decision | None:
    """Refusal from the tool-call guard, or None when no guard rule matches.

    Rules: ``forbidden_command_patterns`` (all tools) followed by
    ``machine_enforcement.tool_guard``, in order. The refusal names the rule,
    never its pattern.
    """
    legacy, errors = compile_rules(
        rules.forbidden_command_patterns, source="forbidden_command_patterns"
    )
    if errors:  # only reachable when rules bypassed parse_roe_document
        return Decision.refuse(
            code=TOOL_GUARD_BLOCKED,
            detail="tool-guard rules are invalid; the operator must repair roe.json",
            matched=("forbidden_command_patterns",),
        )
    guard = evaluate_call(tool_name, args, (*legacy, *rules.tool_guard))
    if not guard.blocked:
        return None
    detail = f"tool-guard rule {guard.rule!r} matched {guard.where}"
    if guard.message:
        detail += f": {guard.message}"
    return Decision.refuse(code=TOOL_GUARD_BLOCKED, detail=detail[:600], matched=(guard.rule,))


def _roe_required() -> bool:
    """Whether a missing RoE policy refuses gated calls. Default ON.

    ``BUGGY_ROE_REQUIRE=0`` is the explicit opt-out for labs and standalone
    library use. With the variable unset, the policy is required unless
    ``BENCHMARK_MODE`` is on (benchmark providers launch their own local
    targets and do not write a policy).
    """
    raw = os.environ.get("BUGGY_ROE_REQUIRE")
    if raw is None or not raw.strip():
        return not env_flag("BENCHMARK_MODE")
    return env_truthy(raw, default=True)


def resolve_roe_path(
    workspace_path: str | None, engagement_name: str | None = None
) -> tuple[Path | None, str]:
    """Locate the RoE document that governs this engagement.

    Returns ``(path, origin)`` where origin is ``"control"`` (operator
    written, outside the agent-writable tree) or ``"workspace"`` (the
    agent-writable draft). The workspace draft is only ever returned when
    the policy is not required.
    """
    control = control_roe_path(workspace_path, engagement_name)
    if _roe_required():
        return control, "control"
    if control is not None and (control.is_file() or control.is_symlink()):
        return control, "control"
    return workspace_roe_path(workspace_path), "workspace"


def _load_rules_for_workspace(
    workspace_path: str | None, engagement_name: str | None = None
) -> MachineEnforcement:
    roe_path, origin = resolve_roe_path(workspace_path, engagement_name)
    if roe_path is None:
        if _roe_required():
            raise InvalidRoEError(
                "RoE file is required (BUGGY_ROE_REQUIRE) but this run has no engagement "
                "workspace, so no operator-controlled roe.json can be located"
            )
        return MachineEnforcement()
    try:
        document = json.loads(roe_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        if not roe_path.is_symlink():
            if _roe_required():
                raise InvalidRoEError(
                    f"RoE file is required (BUGGY_ROE_REQUIRE) but {roe_path} does not exist. "
                    "The operator must approve a scope first "
                    "(buggy-cli scope approve <engagement>)"
                ) from exc
            return MachineEnforcement()
        raise InvalidRoEError("RoE file links to a missing policy") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InvalidRoEError("RoE file is unreadable or contains invalid JSON") from exc
    return parse_roe_document(document, required=_roe_required())


def _abort_marker_present(workspace_path: str | None) -> bool:
    if not workspace_path:
        return False
    try:
        return (Path(workspace_path) / ".abort").exists()
    except OSError:
        return False


def _halted_message(tool_name: str, tool_call_id: str | None) -> ToolMessage:
    body = (
        f"[AGENT_HALTED] code=EMERGENCY_ABORT tool={tool_name}\n"
        "An out-of-band emergency abort was signalled by the operator "
        "(.abort marker in the workspace). This gated call was NOT executed.\n"
        "Stop work immediately and await operator instructions - do NOT "
        "retry or attempt alternative commands this turn."
    )
    return ToolMessage(content=body, tool_call_id=tool_call_id or "", status="error")


def _refused_message(decision: Decision, tool_name: str, tool_call_id: str | None) -> ToolMessage:
    body = (
        f"[ROE_REFUSED] code={decision.reason_code} tool={tool_name}\n"
        f"reason: {decision.reason_detail}\n\n"
        "The engagement's RoE blocked this call. If you believe this is a\n"
        "false positive, ask the operator to update the engagement's roe.json "
        "(machine_enforcement block) and re-run the objective. Continuing\n"
        "with a different target / different technique is the expected\n"
        "response - do NOT re-issue the same command this turn."
    )
    return ToolMessage(content=body, tool_call_id=tool_call_id or "", status="error")


def _warn_message(decision: Decision, tool_message: ToolMessage) -> ToolMessage:
    body = (
        f"[ROE_WARN] code={decision.reason_code}\n"
        f"reason: {decision.reason_detail}\n\n"
        "The tool call ran, but the RoE evaluator flagged it. Review the\n"
        "operator's intent before continuing.\n\n"
        "----- ORIGINAL TOOL OUTPUT -----\n"
        f"{_to_text(tool_message.content)}"
    )
    return ToolMessage(
        content=body,
        tool_call_id=tool_message.tool_call_id,
        status=tool_message.status,
        name=tool_message.name,
    )


def _to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict) and item.get("type") == "text":
                chunks.append(str(item.get("text", "")))
        return "".join(chunks)
    return str(content)


_REDACT_MASK = "***"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(sshpass\s+-p\s+)('[^']*'|\"[^\"]*\"|\S+)"),
    re.compile(r"(?i)(\bPGPASSWORD=)('[^']*'|\"[^\"]*\"|\S+)"),
    re.compile(
        r"(?i)((?:--password|--pass|--token)(?:[=\s]+)|-p\s+)"
        r"('[^']*'|\"[^\"]*\"|\S+)"
    ),
    re.compile(r"(?i)((?:-u|--user)\s+)('[^']*'|\"[^\"]*\"|[^\s:]+):(\S+)"),
    re.compile(
        r"(?i)((?:-H|--header)(?:[=\s]+))"
        r"('(?:[^']*(?:authorization|bearer|api-key|apikey|x-api-key)[^']*)'"
        r"|\"(?:[^\"]*(?:authorization|bearer|api-key|apikey|x-api-key)[^\"]*)\")",
    ),
    re.compile(r"(?i)([^\s/@:]+/[^\s/@:]+:)([^\s@]+)(@)"),
    re.compile(r"(?i)([A-Za-z][\w.-]*:)([^\s@:]+)(@[\w.-]+)"),
)


def _redact_header_value(match: re.Match[str]) -> str:
    flag, raw = match.group(1), match.group(2)
    quote = raw[0]
    inner = raw[1:-1]
    if ":" in inner:
        name, _, _value = inner.partition(":")
        return f"{flag}{quote}{name}: {_REDACT_MASK}{quote}"
    return f"{flag}{quote}{_REDACT_MASK}{quote}"


def _redact_secrets(cmd: str) -> str:
    if not cmd:
        return cmd
    out = cmd
    out = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}{_REDACT_MASK}", out)
    out = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}{_REDACT_MASK}", out)
    out = _SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}{_REDACT_MASK}", out)
    out = _SECRET_PATTERNS[3].sub(lambda m: f"{m.group(1)}{m.group(2)}:{_REDACT_MASK}", out)
    out = _SECRET_PATTERNS[4].sub(_redact_header_value, out)
    out = _SECRET_PATTERNS[5].sub(lambda m: f"{m.group(1)}{_REDACT_MASK}{m.group(3)}", out)
    out = _SECRET_PATTERNS[6].sub(lambda m: f"{m.group(1)}{_REDACT_MASK}{m.group(3)}", out)
    return out


def _tool_call_field(request, name: str) -> Any:
    """Read ``name`` from the request's tool call, which LangChain passes as a dict."""
    call = getattr(request, "tool_call", None)
    if isinstance(call, Mapping):
        return call.get(name)
    return getattr(call, name, None) if call else None


def _tool_call_args(request) -> dict[str, Any]:
    args = getattr(request, "tool_call_args", None)
    if not isinstance(args, dict):
        args = _tool_call_field(request, "args")
    return args if isinstance(args, dict) else {}


def _command_from_tool_call(request) -> str:
    args = _tool_call_args(request)
    cmd = args.get("command") or args.get("cmd") or ""
    return cmd if isinstance(cmd, str) else ""


def _egress_disabled() -> bool:
    """Whether the Layer-2 egress guardrail is turned OFF (opt-out).

    Default ON: an ``enforce``-mode engagement automatically gets the
    authoritative network boundary compiled + pushed to the sandbox — no
    extra env needed. ``BUGGY_EGRESS_DISABLE=1`` is the escape hatch
    for an operator whose environment the in-sandbox firewall doesn't fit
    (it falls back to the parser layer alone). audit / warn modes never
    touch the network regardless.
    """
    return env_flag("BUGGY_EGRESS_DISABLE")


def _state_getter(state) -> Callable[..., Any]:
    return state.get if hasattr(state, "get") else (lambda _k, _d=None: None)


def _audit_refused_message(tool_name: str, tool_call_id: str | None) -> ToolMessage:
    body = (
        f"[ROE_REFUSED] code=AUDIT_UNAVAILABLE tool={tool_name}\n"
        "The engagement audit ledger could not be written, so this gated call "
        "was NOT executed. Every action against a target must be recorded.\n"
        "Stop and report this to the operator - do NOT retry this turn."
    )
    return ToolMessage(content=body, tool_call_id=tool_call_id or "", status="error")


def _egress_refused_message(detail: str, tool_name: str, tool_call_id: str | None) -> ToolMessage:
    body = (
        f"[ROE_REFUSED] code=EGRESS_NOT_PROVISIONED tool={tool_name}\n"
        f"reason: {detail}\n\n"
        "The network boundary for this engagement is not in place, so this "
        "gated call was NOT executed. Stop and report this to the operator."
    )
    return ToolMessage(content=body, tool_call_id=tool_call_id or "", status="error")


def _program_refused_message(detail: str, tool_name: str, tool_call_id: str | None) -> ToolMessage:
    body = (
        f"[ROE_REFUSED] code=PROGRAM_REQUIRES_ENFORCE tool={tool_name}\n"
        f"reason: {detail}\n\n"
        "This gated call was NOT executed. Stop and report this to the operator; "
        "the scope must be re-imported with `buggy-cli scope import`."
    )
    return ToolMessage(content=body, tool_call_id=tool_call_id or "", status="error")


def _program_mode_error(state, rules: MachineEnforcement) -> str | None:
    """Why a bounty-program engagement may not run under the loaded policy."""
    from buggy.program.gate import mode_error  # noqa: PLC0415
    from buggy.program.record import load_program  # noqa: PLC0415

    get = _state_getter(state)
    directory = control_dir(get("workspace_path") or None, get("engagement_name") or None)
    if directory is None:
        return None
    return mode_error(load_program(directory.parent, directory.name), rules.mode.value)


class RoEGuardrailMiddleware(AgentMiddleware):
    """Evaluate every bash tool call against the engagement's RoE.

    Args:
        sink: ``RoEAuditSink`` instance. The middleware records every
            evaluation (PASS, WARN, REFUSE) so the engagement deliverable
            carries the full record.
        gated_tools: Override the default tool-name set. Use this to
            extend enforcement to additional tools (e.g. an HTTP
            request tool).
        jitter_frac: Fraction of ``min_inter_request_delay_ms`` added as
            random OPSEC jitter on top of the floor when a gated call is
            paced (0 disables jitter; the floor is still honoured).
    """

    def __init__(
        self,
        *,
        sink: RoEAuditSink | None = None,
        gated_tools: frozenset[str] | None = None,
        now: Callable[[], datetime] | None = None,
        jitter_frac: float = 0.25,
    ) -> None:
        super().__init__()
        self._sink = sink
        self._gated = gated_tools or GATED_TOOL_NAMES
        self._conc_lock = threading.Lock()
        self._conc_limit: int | None = None
        self._sync_sema: threading.Semaphore | None = None
        self._async_sema: asyncio.Semaphore | None = None
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._jitter_frac = max(0.0, jitter_frac)
        self._pace_lock = threading.Lock()
        self._last_gated_monotonic: float | None = None
        self._egress_lock = threading.Lock()
        # workspace -> digest of the policy currently loaded at the boundary.
        self._egress_provisioned: dict[str, str] = {}
        self._sink_lock = threading.Lock()
        self._sink_cache: dict[str, RoEAuditSink] = {}

    def _sink_for(self, state) -> RoEAuditSink | None:
        """The audit sink for this call's engagement.

        A sink passed to the constructor wins (tests, embedders). Otherwise
        the path is resolved from the request state on every call, because
        the engagement is not known when the middleware is built: that
        build-time lookup is why the default ledger used to stay empty.
        """
        if self._sink is not None:
            return self._sink
        get = _state_getter(state)
        path = default_audit_path(get("workspace_path") or None, get("engagement_name") or None)
        if path is None:
            return None
        key = str(path)
        with self._sink_lock:
            sink = self._sink_cache.get(key)
            if sink is None:
                sink = RoEAuditSink(path=path)
                self._sink_cache[key] = sink
            return sink

    def _append_audit(self, state, record: dict[str, Any]) -> bool:
        """Append one record; return whether it reached the ledger."""
        sink = self._sink_for(state)
        if sink is None:
            return False
        try:
            sink.append(record)
        except Exception as exc:  # noqa: BLE001 - reported to the caller as False
            log.error("roe: audit sink write failed: %s", exc)
            return False
        return True

    @override
    def before_agent(self, state, runtime) -> None:
        self._maybe_provision_egress(state)
        return None

    @override
    async def abefore_agent(self, state, runtime) -> None:
        # Provisioning does a one-time synchronous HTTP round-trip to the
        # sandbox daemon; offload it so the event loop isn't blocked.
        await asyncio.to_thread(self._maybe_provision_egress, state)
        return None

    @override
    def wrap_tool_call(self, request, handler) -> ToolMessage | Command:
        return self._dispatch_sync(request, handler)

    @override
    async def awrap_tool_call(self, request, handler) -> ToolMessage | Command:
        return await self._dispatch_async(request, handler)

    def _dispatch_sync(self, request, handler):
        halt = self._check_abort(request)
        if halt is not None:
            return halt
        decision, rules, tool_name = self._evaluate(request)
        recorded = self._record(request, tool_name, decision, rules.mode)
        if not decision.allow and rules.mode == EnforcementMode.ENFORCE:
            tc_id = _tcid(request)
            if tc_id is None:
                log.warning(
                    "RoEMiddleware: cannot extract tool_call_id for %s refusal; "
                    "using empty tool_call_id to preserve enforcement",
                    tool_name,
                )
            return _refused_message(decision, tool_name, tc_id)
        gated = tool_name in self._gated
        if gated:
            blocked = self._pre_execution_block(request, tool_name, rules, recorded)
            if blocked is not None:
                return blocked
        wait = self._pace_wait_seconds(rules)
        if wait > 0:
            self._record_throttle(request, tool_name, wait)
            time.sleep(wait)
        with self._sync_gate(rules, gated):
            result = handler(request)
        if (
            not decision.allow
            and rules.mode == EnforcementMode.WARN
            and isinstance(result, ToolMessage)
        ):
            return _warn_message(decision, result)
        return result

    async def _dispatch_async(self, request, handler):
        halt = self._check_abort(request)
        if halt is not None:
            return halt
        decision, rules, tool_name = self._evaluate(request)
        recorded = self._record(request, tool_name, decision, rules.mode)
        if not decision.allow and rules.mode == EnforcementMode.ENFORCE:
            tc_id = _tcid(request)
            if tc_id is None:
                log.warning(
                    "RoEMiddleware: cannot extract tool_call_id for %s refusal; "
                    "using empty tool_call_id to preserve enforcement",
                    tool_name,
                )
            return _refused_message(decision, tool_name, tc_id)
        gated = tool_name in self._gated
        if gated:
            blocked = await asyncio.to_thread(
                self._pre_execution_block, request, tool_name, rules, recorded
            )
            if blocked is not None:
                return blocked
        wait = self._pace_wait_seconds(rules)
        if wait > 0:
            self._record_throttle(request, tool_name, wait)
            await asyncio.sleep(wait)
        async with self._async_gate(rules, gated):
            result = await handler(request)
        if (
            not decision.allow
            and rules.mode == EnforcementMode.WARN
            and isinstance(result, ToolMessage)
        ):
            return _warn_message(decision, result)
        return result

    def _resolve_limit(self, rules: MachineEnforcement) -> int | None:
        limit = rules.max_concurrent_connections
        if limit is None or limit <= 0:
            return None
        with self._conc_lock:
            if self._conc_limit is None:
                self._conc_limit = limit
            return self._conc_limit

    @contextmanager
    def _sync_gate(self, rules: MachineEnforcement, gated: bool):
        limit = self._resolve_limit(rules) if gated else None
        if limit is None:
            yield
            return
        with self._conc_lock:
            if self._sync_sema is None:
                self._sync_sema = threading.Semaphore(limit)
            sema = self._sync_sema
        sema.acquire()
        try:
            yield
        finally:
            sema.release()

    @asynccontextmanager
    async def _async_gate(self, rules: MachineEnforcement, gated: bool):
        limit = self._resolve_limit(rules) if gated else None
        if limit is None:
            yield
            return
        with self._conc_lock:
            if self._async_sema is None:
                self._async_sema = asyncio.Semaphore(limit)
            sema = self._async_sema
        async with sema:
            yield

    def _check_abort(self, request) -> ToolMessage | None:
        tool = getattr(request, "tool", None)
        tool_name = getattr(tool, "name", "unknown") if tool else "unknown"
        if tool_name not in self._gated:
            return None
        state = getattr(request, "state", {}) or {}
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)
        workspace = get("workspace_path") or None
        if not _abort_marker_present(workspace):
            return None
        tc_id = _tcid(request)
        if tc_id is None:
            log.warning(
                "RoEMiddleware: cannot extract tool_call_id for %s abort; "
                "using empty tool_call_id to preserve abort enforcement",
                tool_name,
            )
        self._record_abort(request, tool_name)
        return _halted_message(tool_name, tc_id)

    def _record_abort(self, request, tool_name: str) -> None:
        state = getattr(request, "state", {}) or {}
        get = _state_getter(state)
        engagement = get("engagement_name") or "unknown-engagement"
        objective = get("active_objective_id") or get("current_objective") or ""
        record = {
            "ts": time.time(),
            "event": "abort",
            "engagement": engagement,
            "objective_id": objective,
            "tool": tool_name,
            "decision": "refuse",
            "reason_code": "EMERGENCY_ABORT",
            "command_excerpt": _redact_secrets(_command_from_tool_call(request))[:512],
        }
        self._append_audit(state, record)

    def _pre_execution_block(
        self, request, tool_name: str, rules: MachineEnforcement, recorded: bool
    ) -> ToolMessage | None:
        """Last checks before a gated tool runs: audit written, boundary current."""
        state = getattr(request, "state", {}) or {}
        if not recorded and _roe_required():
            return _audit_refused_message(tool_name, _tcid(request))
        program_error = _program_mode_error(state, rules)
        if program_error is not None:
            self._append_audit(
                state,
                {
                    "ts": time.time(),
                    "event": "program_mode_refused",
                    "engagement": _state_getter(state)("engagement_name") or "unknown-engagement",
                    "tool": tool_name,
                    "decision": "refuse",
                    "reason_code": "PROGRAM_REQUIRES_ENFORCE",
                    "reason_detail": program_error,
                },
            )
            return _program_refused_message(program_error, tool_name, _tcid(request))
        try:
            self._ensure_egress(state, rules)
        except EgressProvisioningError as exc:
            self._append_audit(
                state,
                {
                    "ts": time.time(),
                    "event": "egress_provisioning_failed",
                    "engagement": _state_getter(state)("engagement_name") or "unknown-engagement",
                    "tool": tool_name,
                    "decision": "refuse",
                    "reason_code": "EGRESS_NOT_PROVISIONED",
                    "reason_detail": str(exc),
                },
            )
            return _egress_refused_message(str(exc), tool_name, _tcid(request))
        return None

    def _maybe_provision_egress(self, state) -> None:
        """Put the Layer-2 network boundary in place before the agent runs.

        Skipped only when the operator opts out with ``BUGGY_EGRESS_DISABLE``.
        An unreadable RoE is left to the per-call gate (which refuses gated
        tools while keeping repair tools available). Any other failure raises
        :class:`EgressProvisioningError`, which aborts the run: an engagement
        whose boundary is not loaded must not reach a target.
        """
        if _egress_disabled():
            return
        get = _state_getter(state)
        workspace = get("workspace_path") or None
        if not workspace:
            return
        try:
            rules = _load_rules_for_workspace(workspace, get("engagement_name") or None)
        except InvalidRoEError as exc:
            log.error("roe: %s; gated calls will be refused until the policy is repaired", exc)
            return
        self._ensure_egress(state, rules)

    def _ensure_egress(self, state, rules: MachineEnforcement) -> None:
        """Push ``rules`` to the network boundary unless that exact policy is loaded.

        With an egress guard deployed (``BUGGY_EGRESS_GUARD_URL``) every mode
        is pushed, because the guard denies all sandbox egress until it holds
        a policy. Without one, only ``enforce`` mode touches the network (the
        legacy in-sandbox applier). Raises :class:`EgressProvisioningError`
        when the boundary cannot be confirmed.
        """
        if _egress_disabled():
            return
        get = _state_getter(state)
        workspace = get("workspace_path") or None
        if not workspace:
            return
        from buggy.middleware.egress import (
            compile_egress_policy,
            guard_endpoint,
            policy_digest,
            provision_guard,
        )

        guard = guard_endpoint()
        if guard is None and rules.mode != EnforcementMode.ENFORCE:
            return
        policy = compile_egress_policy(rules)
        digest = policy_digest(policy)
        with self._egress_lock:
            if self._egress_provisioned.get(workspace) == digest:
                return
        engagement = get("engagement_name") or "unknown-engagement"
        try:
            if guard is not None:
                result = provision_guard(
                    policy, engagement=engagement, url=guard[0], token=guard[1]
                )
            else:
                from buggy.backends.factory import build_sandbox_backend

                result = build_sandbox_backend().provision_egress(policy)
        except EgressProvisioningError:
            raise
        except Exception as exc:  # noqa: BLE001 - converted to the fail-closed error
            raise EgressProvisioningError(f"egress provisioning failed: {exc}") from exc
        if not isinstance(result, dict) or not result.get("applied"):
            detail = result.get("detail") if isinstance(result, dict) else "malformed reply"
            raise EgressProvisioningError(f"egress policy was not applied: {detail}")
        with self._egress_lock:
            self._egress_provisioned[workspace] = digest
        log.info("roe: egress provisioned for %s: digest=%s", workspace, digest[:12])
        self._append_audit(
            state,
            {
                "ts": time.time(),
                "event": "egress_provisioned",
                "engagement": engagement,
                "mode": rules.mode.value,
                "policy_sha256": digest,
                "boundary": "egress-guard" if guard is not None else "sandbox",
                "detail": str(result.get("detail", "")),
            },
        )

    def _evaluate(self, request) -> tuple[Decision, MachineEnforcement, str]:
        tool = getattr(request, "tool", None)
        tool_name = getattr(tool, "name", "unknown") if tool else "unknown"
        if tool_name not in self._gated:
            return Decision.allow_default(), MachineEnforcement(), tool_name
        state = getattr(request, "state", {}) or {}
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)
        workspace = get("workspace_path") or None
        try:
            rules = _load_rules_for_workspace(workspace, get("engagement_name") or None)
        except InvalidRoEError as exc:
            decision = Decision(
                allow=False,
                reason_code="INVALID_ROE",
                reason_detail=(
                    f"{exc}. The operator must repair the engagement's roe.json "
                    "before gated tools can run."
                ),
                risk="high",
            )
            return decision, MachineEnforcement(mode=EnforcementMode.ENFORCE), tool_name
        time_decision = evaluate_time_window(self._now(), rules)
        if not time_decision.allow:
            return time_decision, rules, tool_name
        extractor = NETWORK_TARGET_EXTRACTORS.get(tool_name)
        if extractor is not None:
            hosts = extractor(_tool_call_args(request))
            for host in sorted(set(hosts)):
                target_decision = evaluate_target(host, rules)
                if not target_decision.allow:
                    return target_decision, rules, tool_name
            if hosts and rules.sandbox_blocked and tool_name in SANDBOX_NETWORK_TOOLS:
                return _sandbox_blocked_decision(sorted(set(hosts))), rules, tool_name
            guard_decision = _tool_guard_decision(tool_name, _tool_call_args(request), rules)
            if guard_decision is not None:
                return guard_decision, rules, tool_name
            return Decision.allow_default(), rules, tool_name
        command = _command_from_tool_call(request)
        cmd_decision = evaluate_command(command, rules)
        if not cmd_decision.allow:
            return cmd_decision, rules, tool_name
        targets = extract_targets(command)
        for target in sorted(targets):
            target_decision = evaluate_target(target, rules)
            if not target_decision.allow:
                return target_decision, rules, tool_name
        if targets and rules.sandbox_blocked:
            return _sandbox_blocked_decision(sorted(targets)), rules, tool_name
        guard_decision = _tool_guard_decision(tool_name, _tool_call_args(request), rules)
        if guard_decision is not None:
            return guard_decision, rules, tool_name
        return Decision.allow_default(), rules, tool_name

    def _record(
        self,
        request,
        tool_name: str,
        decision: Decision,
        mode: EnforcementMode,
    ) -> bool:
        state = getattr(request, "state", {}) or {}
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)
        engagement = get("engagement_name") or "unknown-engagement"
        objective = get("active_objective_id") or get("current_objective") or ""
        record = {
            "ts": time.time(),
            "engagement": engagement,
            "objective_id": objective,
            "tool": tool_name,
            "decision": "allow" if decision.allow else "refuse",
            "reason_code": decision.reason_code,
            "reason_detail": decision.reason_detail,
            "risk": decision.risk,
            "matched_targets": list(decision.matched_targets),
            "mode": mode.value,
            "command_excerpt": _redact_secrets(_command_from_tool_call(request))[:512],
        }
        if decision.reason_code == TOOL_GUARD_BLOCKED:
            record["event"] = "tool_guard_blocked"
        return self._append_audit(state, record)

    def _pace_wait_seconds(self, rules: MachineEnforcement) -> float:
        """Seconds to sleep before a gated call to honour ``min_inter_request_delay_ms``.

        The first runtime request-cadence control (opplan only prints an OPSEC
        label). Isolated calls never wait; bursts are spaced to the floor plus
        up to ``jitter_frac`` of it, so the cadence is not a fixed-interval IOC.
        Never goes below the configured minimum; returns 0 when unset.
        """
        floor = rules.min_inter_request_delay_ms / 1000.0
        if floor <= 0:
            return 0.0
        now = time.monotonic()
        with self._pace_lock:
            last = self._last_gated_monotonic
            start_at = now if last is None else max(now, last + floor)
            self._last_gated_monotonic = start_at
        wait = start_at - now
        if wait > 0 and self._jitter_frac > 0:
            wait += random.uniform(0.0, floor * self._jitter_frac)
        return wait

    def _record_throttle(self, request, tool_name: str, wait_seconds: float) -> None:
        state = getattr(request, "state", {}) or {}
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)
        record = {
            "ts": time.time(),
            "engagement": get("engagement_name") or "unknown-engagement",
            "objective_id": get("active_objective_id") or get("current_objective") or "",
            "tool": tool_name,
            "event": "throttle",
            "reason_code": "MIN_INTER_REQUEST_DELAY",
            "delay_seconds": round(wait_seconds, 3),
        }
        self._append_audit(state, record)


def _tcid(request) -> str | None:
    tc = getattr(request, "tool_call_id", None)
    if isinstance(tc, str):
        return tc
    tc_attr = _tool_call_field(request, "id")
    return tc_attr if isinstance(tc_attr, str) else None


def default_audit_path(
    workspace_path: str | None, engagement_name: str | None = None
) -> Path | None:
    """Where this engagement's RoE decision ledger lives.

    Order: ``BUGGY_ROE_AUDIT_PATH`` (operator pin), then the audit root
    (``/audit/<engagement>/roe-decisions.jsonl`` - outside the sandbox), then
    the legacy ``<workspace>/audit/`` location when RoE is not required and
    no audit root is mounted. Returns ``None`` when nothing can be resolved.
    """
    env_path = os.environ.get("BUGGY_ROE_AUDIT_PATH")
    if env_path:
        return Path(env_path)
    if Path(audit_root()).is_dir():
        directory = audit_dir(workspace_path, engagement_name)
        if directory is not None:
            return directory / "roe-decisions.jsonl"
    if workspace_path and not _roe_required():
        return Path(workspace_path) / "audit" / "roe-decisions.jsonl"
    return None


def build_default_sink(
    workspace_path: str | None, engagement_name: str | None = None
) -> RoEAuditSink | None:
    """Sink at :func:`default_audit_path`, or ``None`` when it cannot be resolved.

    The middleware no longer relies on this at construction time (the
    engagement is unknown then); it resolves the sink per call instead.
    """
    path = default_audit_path(workspace_path, engagement_name)
    return RoEAuditSink(path=path) if path is not None else None


# Compat alias (removed at 2.0.0). The class was renamed
# ``RoEEnforcementMiddleware`` → ``RoEGuardrailMiddleware`` when RoE
# enforcement became genuinely layered (advisory command-parse here +
# authoritative sandbox egress). Downstream plugins / downstream subagents
# that import the old name keep working for one minor cycle.
RoEEnforcementMiddleware = RoEGuardrailMiddleware
