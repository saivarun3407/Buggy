"""Tool-call guard: ordered regex rules over every argument of a gated tool call.

The guardrail's ``forbidden_command_patterns`` used to see only the raw
``command`` string of shell tools. This module extends that mechanism to every
gated tool and every argument: the tool name, every string in the (nested)
argument structure, every dict key, any string that itself holds JSON, and the
compact JSON serialization of the whole call. Each string is also checked after
up to three rounds of percent-decoding and one pass of HTML-entity and
``\\xNN`` / ``\\uNNNN`` unescaping, so ``DROP%2520TABLE`` or ``DROP&#32;TABLE``
does not slip past ``(?i)drop\\s+table``.

The guard can only refuse. Rules are operator-authored (the enforced
``roe.json`` in the control root). Everything an argument can make the guard do
is bounded: nesting depth, the number of strings, total characters, the length
of each regex input and the time each rule may spend. When a bound is hit the
call is blocked (fail closed) rather than partially inspected.

Pure standard library: no agent-framework imports.
"""

from __future__ import annotations

import html
import json
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Iterable
from urllib.parse import unquote_plus

MAX_RULES = 100
MAX_PATTERN_LENGTH = 4096
#: Longest input handed to a single ``re.search``. Longer strings are scanned in
#: overlapping windows, so no part of them goes unchecked.
MAX_STRING_LENGTH = 100_000
WINDOW_OVERLAP = 4096
#: Container nesting (dicts / lists) the guard descends into.
MAX_DEPTH = 32
#: Levels of "a string that holds JSON" the guard parses and descends into.
MAX_JSON_STRING_DEPTH = 3
MAX_STRINGS = 20_000
MAX_TOTAL_CHARS = 4_000_000
DECODE_ROUNDS = 3
#: Wall-clock budget per rule per call. Python's ``re`` cannot be interrupted
#: mid-search, so the budget is checked between searches; an exceeded budget
#: blocks the call.
RULE_TIME_BUDGET_S = 1.0

_RULE_KEYS = frozenset({"pattern", "name", "tools", "message"})
_ESCAPE_RE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))")
LIMIT_RULE = "tool-guard-limits"
#: Locations ("args.body<json>.q") are built from argument keys; keep them short.
MAX_WHERE_LENGTH = 200


@dataclass(frozen=True, slots=True)
class GuardRule:
    """One ordered guard rule. ``tools=("*",)`` applies it to every gated tool.

    ``error`` is set only on a rule that could not be built from its
    configuration; such a rule blocks every call it applies to.
    """

    pattern: str
    name: str = ""
    tools: tuple[str, ...] = ("*",)
    message: str = ""
    error: str = ""

    def applies_to(self, tool_name: str) -> bool:
        return "*" in self.tools or tool_name in self.tools

    @property
    def label(self) -> str:
        return self.name or "unnamed rule"


@dataclass(frozen=True, slots=True)
class GuardDecision:
    """Outcome of :func:`evaluate_call`. ``rule`` is a rule name, never its pattern."""

    blocked: bool
    rule: str = ""
    match: str = ""
    where: str = ""
    message: str = ""


@lru_cache(maxsize=1024)
def _regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _parse_one(item: Any, index: int, source: str) -> tuple[GuardRule | None, str]:
    """Build one rule; return ``(rule, "")`` or ``(None, error)``."""
    default_name = f"{source}[{index}]"
    if isinstance(item, str):
        item = {"pattern": item}
    if not isinstance(item, dict):
        return None, f"{default_name}: a rule must be a regex string or an object"
    unknown = sorted(str(key) for key in item if key not in _RULE_KEYS)
    if unknown:
        return None, f"{default_name}: unknown rule keys {unknown}"
    name = item.get("name", "")
    if not isinstance(name, str):
        return None, f"{default_name}: name must be a string"
    label = name.strip() or default_name
    pattern = item.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        return None, f"{label}: pattern must be a nonempty string"
    if len(pattern) > MAX_PATTERN_LENGTH:
        return None, f"{label}: pattern longer than {MAX_PATTERN_LENGTH} characters"
    tools_raw = item.get("tools", ["*"])
    if isinstance(tools_raw, str):
        tools_raw = [tools_raw]
    if (
        not isinstance(tools_raw, list)
        or not tools_raw
        or not all(isinstance(t, str) and t.strip() for t in tools_raw)
    ):
        return None, f"{label}: tools must be a nonempty list of tool names"
    message = item.get("message", "")
    if not isinstance(message, str):
        return None, f"{label}: message must be a string"
    try:
        _regex(pattern)
    except (re.error, RecursionError, OverflowError) as exc:
        return None, f"{label}: invalid regex ({exc})"
    return (
        GuardRule(
            pattern=pattern,
            name=label,
            tools=tuple(t.strip() for t in tools_raw),
            message=message,
        ),
        "",
    )


def _build(
    patterns_or_dicts: Any, source: str
) -> tuple[list[GuardRule], list[str], list[GuardRule]]:
    """Return ``(valid rules, errors, all rules incl. errored placeholders)``."""
    if isinstance(patterns_or_dicts, (str, bytes, dict)) or not isinstance(
        patterns_or_dicts, Iterable
    ):
        error = f"{source}: must be a list of rules"
        return [], [error], [GuardRule(pattern="", name=source, error=error)]
    items = list(patterns_or_dicts)
    valid: list[GuardRule] = []
    errors: list[str] = []
    every: list[GuardRule] = []
    if len(items) > MAX_RULES:
        error = f"{source}: more than {MAX_RULES} rules"
        errors.append(error)
        every.append(GuardRule(pattern="", name=source, error=error))
    for index, item in enumerate(items):
        rule, error = _parse_one(item, index, source)
        if rule is None:
            errors.append(error)
            every.append(GuardRule(pattern="", name=f"{source}[{index}]", error=error))
        else:
            valid.append(rule)
            every.append(rule)
    return valid, errors, every


def compile_rules(
    patterns_or_dicts: Any, *, source: str = "tool_guard"
) -> tuple[tuple[GuardRule, ...], list[str]]:
    """Compile rules from plain regex strings (all tools) and ``{pattern, name, tools, message}``.

    Returns ``(rules, errors)``. A rule that cannot be compiled is never
    silently skipped: it is reported in ``errors``, and callers must reject the
    whole rule set when ``errors`` is nonempty.
    """
    valid, errors, _ = _build(patterns_or_dicts, source)
    return tuple(valid), errors


def guard_rules_from_config(
    patterns_or_dicts: Any, *, source: str = "tool_guard"
) -> tuple[GuardRule, ...]:
    """Every configured rule, with an invalid entry kept as an errored rule.

    Used by the lenient :meth:`MachineEnforcement.from_dict`: an errored rule
    blocks every call it applies to, so a rule set that bypassed load-time
    validation still fails closed.
    """
    _, _, every = _build(patterns_or_dicts, source)
    return tuple(every)


class _Limit(Exception):
    """An argument exceeded one of the inspection bounds."""


def _at(where: str, suffix: str) -> str:
    return (where + suffix)[:MAX_WHERE_LENGTH]


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    return len(stripped) >= 2 and stripped[0] in "{[" and stripped[-1] in "}]"


def _collect(args: Any) -> list[tuple[str, str]]:
    """``(where, text)`` for every string the guard inspects. Raises :class:`_Limit`."""
    out: list[tuple[str, str]] = []
    total = 0

    def add(where: str, text: str) -> None:
        nonlocal total
        if len(out) >= MAX_STRINGS:
            raise _Limit(f"more than {MAX_STRINGS} strings in the arguments")
        total += len(text)
        if total > MAX_TOTAL_CHARS:
            raise _Limit(f"arguments larger than {MAX_TOTAL_CHARS} characters")
        out.append((where, text))

    # Explicit stack: no recursion, so a hostile structure cannot exhaust it.
    stack: list[tuple[str, Any, int, int]] = [("args", args, 0, 0)]
    while stack:
        where, value, depth, json_depth = stack.pop()
        if depth > MAX_DEPTH:
            raise _Limit(f"arguments nested deeper than {MAX_DEPTH} levels")
        if isinstance(value, str):
            add(where, value)
            if (
                json_depth < MAX_JSON_STRING_DEPTH
                and len(value) <= MAX_STRING_LENGTH
                and _looks_like_json(value)
            ):
                try:
                    inner = json.loads(value)
                except (ValueError, RecursionError):
                    continue
                if isinstance(inner, (dict, list)):
                    stack.append((_at(where, "<json>"), inner, depth + 1, json_depth + 1))
        elif isinstance(value, dict):
            for key, item in reversed(list(value.items())):
                add(_at(where, " (key)"), str(key))
                stack.append((_at(where, f".{str(key)[:64]}"), item, depth + 1, json_depth))
        elif isinstance(value, (list, tuple)):
            for index in range(len(value) - 1, -1, -1):
                stack.append((_at(where, f"[{index}]"), value[index], depth + 1, json_depth))
        elif value is None:
            continue
        elif isinstance(value, bytes):
            add(where, value.decode("utf-8", "replace"))
        else:
            add(where, str(value))
    try:
        serialized = json.dumps(args, separators=(",", ":"), ensure_ascii=False, default=str)
    except (TypeError, ValueError, RecursionError) as exc:
        raise _Limit("arguments cannot be serialized") from exc
    add("args (serialized)", serialized)
    return out


def flatten(args: Any) -> list[str]:
    """Every string in ``args`` (nested), every dict key, and the compact JSON serialization.

    Strings that hold a JSON object or array are parsed and their contents
    included too (bounded depth). Raises ``ValueError`` when ``args`` exceeds
    the inspection bounds.
    """
    try:
        return [text for _, text in _collect(args)]
    except _Limit as exc:
        raise ValueError(str(exc)) from exc


def _unescape(text: str) -> str:
    text = html.unescape(text)
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), text)


def decode_rounds(text: str, rounds: int = DECODE_ROUNDS) -> list[str]:
    """``text``, each successive ``unquote_plus`` while it keeps changing (max ``rounds``),
    then one pass of HTML-entity and ``\\xNN`` / ``\\uNNNN`` unescaping of each of those."""
    variants = [text]
    current = text
    for _ in range(max(0, min(rounds, DECODE_ROUNDS))):
        decoded = unquote_plus(current)
        if decoded == current:
            break
        variants.append(decoded)
        current = decoded
    unescaped: list[str] = []
    for variant in variants:
        candidate = _unescape(variant)
        if candidate not in variants and candidate not in unescaped:
            unescaped.append(candidate)
    return variants + unescaped


def _windows(text: str) -> Iterable[str]:
    if len(text) <= MAX_STRING_LENGTH:
        yield text
        return
    step = MAX_STRING_LENGTH - WINDOW_OVERLAP
    for start in range(0, len(text), step):
        yield text[start : start + MAX_STRING_LENGTH]
        if start + MAX_STRING_LENGTH >= len(text):
            return


def evaluate_call(
    tool_name: str,
    args: Any,
    rules: Iterable[GuardRule],
    *,
    time_budget_s: float = RULE_TIME_BUDGET_S,
) -> GuardDecision:
    """Check a tool call against ordered ``rules``; the first matching rule wins.

    Checks the tool name and every flattened and decoded argument string.
    Blocks (fail closed) when an applicable rule is errored, the arguments
    exceed the inspection bounds, or a rule exceeds its time budget.
    """
    applicable = [rule for rule in rules if rule.applies_to(tool_name)]
    if not applicable:
        return GuardDecision(blocked=False)
    for rule in applicable:
        if rule.error:
            return GuardDecision(
                blocked=True,
                rule=rule.label,
                where="rule configuration",
                message="the rule is invalid, so every call it covers is refused",
            )
    try:
        collected = _collect(args)
    except _Limit as exc:
        return GuardDecision(blocked=True, rule=LIMIT_RULE, where=str(exc))
    candidates: list[tuple[str, str]] = [("tool name", tool_name)]
    for where, text in collected:
        for index, variant in enumerate(decode_rounds(text)):
            candidates.append((where if index == 0 else f"{where} (decoded)", variant))
    for rule in applicable:
        regex = _regex(rule.pattern)
        started = time.perf_counter()
        for where, text in candidates:
            for window in _windows(text):
                found = regex.search(window)
                if found is not None:
                    return GuardDecision(
                        blocked=True,
                        rule=rule.label,
                        match=found.group(0)[:200],
                        where=where,
                        message=rule.message,
                    )
                if time.perf_counter() - started > time_budget_s:
                    return GuardDecision(
                        blocked=True,
                        rule=rule.label,
                        where="time budget exceeded",
                        message="the rule took too long on these arguments",
                    )
    return GuardDecision(blocked=False)


__all__ = [
    "GuardDecision",
    "GuardRule",
    "compile_rules",
    "decode_rounds",
    "evaluate_call",
    "flatten",
    "guard_rules_from_config",
]
