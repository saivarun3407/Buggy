"""``buggy-cli trace-review`` — read the agent bridge's call log and flag what looks wrong.

    buggy-cli trace-review <engagement> [--session ID] [--json]

Deterministic: fixed rules over ``<audit>/<engagement>/agent/calls.jsonl``,
one line per tool call (see :mod:`buggy.agent_records`). Per run it flags:

* **loops**: the same call (tool and arguments) made ``LOOP_MIN`` times or more;
* **dead ends**: ``DEAD_END_MIN`` calls in a row that produced nothing new (refused,
  failed, or answered exactly as an earlier call did);
* **no progress**: ``NO_PROGRESS_MIN`` calls in a row with no submitted or verified
  finding, recorded fact or saved recipe;
* **invented observations**: a ``finding_submit`` citing a capture id that no tool
  returned earlier in the session (the claim names evidence the agent never saw);
* **refusals**: how many calls were refused, and a warning when policy refusals
  (scope, internal address, operator rule, target data in a URL) cluster: many
  in a short stretch is an early sign of a prompt injection steering the agent.

Nothing here reads the target, a response body or a model; it reads digests.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from buggy import agent_records
from buggy.cli import _paths

EXIT_OK = 0
EXIT_CONFIG = 2

LOOP_MIN = 3
DEAD_END_MIN = 6
NO_PROGRESS_MIN = 40
#: Policy refusals within a window of this many calls that make a spike.
SPIKE_WINDOW = 10
SPIKE_MIN = 4

#: Refusals that mean the agent tried something the operator's policy forbids.
POLICY_CODES = frozenset(
    {
        "OUT_OF_SCOPE",
        "INTERNAL_ADDRESS",
        "TOOL_RULE",
        "IN_SCOPE_USE_GATEWAY",
        "LOOKS_LIKE_TARGET_DATA",
        "BAD_URL",
        "APPROVAL_DENIED",
        "NOT_A_DECLARED_LOGIN",
        "NO_SUCH_TOOL",
        "CAPTURE_NOT_CITED",
        "UNKNOWN_IDENTITY",
    }
)
#: Calls that record progress when they succeed.
PROGRESS_TOOLS = frozenset(
    {"finding_submit", "finding_verify", "fact_add", "recipe_save", "finding_challenge"}
)


def _streaks(flags: list[tuple[int, bool]], minimum: int) -> list[dict[str, int]]:
    """Stretches of consecutive ``True`` flags at least ``minimum`` long, by sequence."""
    out: list[dict[str, int]] = []
    start = previous = -1
    length = 0
    for seq, flagged in [*flags, (-1, False)]:
        if flagged:
            if length == 0:
                start = seq
            length += 1
            previous = seq
            continue
        if length >= minimum:
            out.append({"from_seq": start, "to_seq": previous, "length": length})
        length = 0
    return out


def review_run(lines: list[dict[str, Any]], seen_before: set[str]) -> dict[str, Any]:
    """The flags for one run's lines (in order). ``seen_before``: capture ids already returned
    in this session by earlier runs; it is extended with this run's."""
    first = lines[0] if lines else {}
    keys = Counter((str(line.get("tool")), str(line.get("args_digest"))) for line in lines)
    first_seq: dict[tuple[str, str], int] = {}
    for line in lines:
        first_seq.setdefault((str(line.get("tool")), str(line.get("args_digest"))), line["seq"])
    loops = [
        {
            "tool": tool,
            "args_digest": digest,
            "count": count,
            "first_seq": first_seq[(tool, digest)],
        }
        for (tool, digest), count in keys.most_common()
        if count >= LOOP_MIN
    ]

    answers: set[str] = set()
    nothing_new: list[tuple[int, bool]] = []
    no_progress: list[tuple[int, bool]] = []
    invented: list[dict[str, Any]] = []
    refusal_codes: Counter[str] = Counter()
    policy_seqs: list[int] = []
    refused = 0
    for index, line in enumerate(lines):
        status = str(line.get("status") or "")
        code = str(line.get("code") or "")
        tool = str(line.get("tool") or "")
        answer = str(line.get("result_digest") or "")
        if tool == "finding_submit":
            missing = [c for c in line.get("cited") or [] if c not in seen_before]
            if missing:
                invented.append({"seq": line["seq"], "missing": missing})
        if status == "refused":
            refused += 1
            refusal_codes[code or "?"] += 1
        if code in POLICY_CODES:
            policy_seqs.append(index)
        stale = status != "ok" or answer in answers
        nothing_new.append((line["seq"], stale))
        no_progress.append((line["seq"], not (status == "ok" and tool in PROGRESS_TOOLS)))
        answers.add(answer)
        if status == "ok":
            seen_before.update(str(c) for c in line.get("captures") or [])

    spikes = 0
    for position, index in enumerate(policy_seqs):
        inside = [i for i in policy_seqs[position:] if i - index < SPIKE_WINDOW]
        if len(inside) >= SPIKE_MIN:
            spikes += 1
    warnings: list[str] = []
    if spikes:
        warnings.append(
            f"policy refusals spiked ({len(policy_seqs)} in this run, {SPIKE_MIN}+ within "
            f"{SPIKE_WINDOW} calls): read the run for a prompt injection steering the agent"
        )
    if invented:
        warnings.append(
            f"{len(invented)} finding_submit call(s) cited captures no tool had returned"
        )
    return {
        "run": str(first.get("run") or ""),
        "session": str(first.get("session") or ""),
        "role": str(first.get("role") or ""),
        "attempt": first.get("attempt") or 0,
        "calls": len(lines),
        "refused": refused,
        "policy_refusals": len(policy_seqs),
        "refusal_spike": bool(spikes),
        "refusal_codes": dict(refusal_codes.most_common()),
        "signin_calls": sum(1 for line in lines if line.get("signin")),
        "loops": loops,
        "dead_ends": _streaks(nothing_new, DEAD_END_MIN),
        "no_progress": _streaks(no_progress, NO_PROGRESS_MIN),
        "invented": invented,
        "warnings": warnings,
    }


def review(lines: list[dict[str, Any]], *, session: str = "") -> dict[str, Any]:
    """Review every run in ``lines`` (or one session's), oldest first."""
    runs: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for line in lines:
        if session and line.get("session") != session:
            continue
        if not isinstance(line.get("seq"), int):
            continue
        run = str(line.get("run") or "")
        if run not in runs:
            runs[run] = []
            order.append(run)
        runs[run].append(line)
    seen_by_session: dict[str, set[str]] = {}
    reviewed = []
    for run in order:
        rows = sorted(runs[run], key=lambda line: line["seq"])
        key = str(rows[0].get("session") or "") or f"run:{run}"
        reviewed.append(review_run(rows, seen_by_session.setdefault(key, set())))
    return {
        "runs": reviewed,
        "summary": {
            "runs": len(reviewed),
            "calls": sum(r["calls"] for r in reviewed),
            "refused": sum(r["refused"] for r in reviewed),
            "loops": sum(len(r["loops"]) for r in reviewed),
            "dead_ends": sum(len(r["dead_ends"]) for r in reviewed),
            "invented": sum(len(r["invented"]) for r in reviewed),
            "refusal_spikes": sum(1 for r in reviewed if r["refusal_spike"]),
            "warnings": sum(len(r["warnings"]) for r in reviewed),
        },
    }


def summary_line(result: dict[str, Any]) -> str:
    """One line for the end of a run."""
    s = result["summary"]
    if not s["runs"]:
        return "no agent tool calls were recorded"
    return (
        f"{s['runs']} run(s), {s['calls']} calls, {s['refused']} refused; "
        f"{s['loops']} loop(s), {s['dead_ends']} dead end(s), "
        f"{s['invented']} claim(s) citing unseen captures, {s['warnings']} warning(s)"
    )


def to_text(engagement: str, result: dict[str, Any]) -> str:
    out = [f"Trace review of {engagement}: {summary_line(result)}"]
    for run in result["runs"]:
        out.append(
            f"\nrun {run['run']} ({run['role'] or 'agent'}, attempt {run['attempt']}): "
            f"{run['calls']} calls, {run['refused']} refused, {run['signin_calls']} on sign-in"
        )
        if run["refusal_codes"]:
            codes = ", ".join(f"{code} {n}" for code, n in run["refusal_codes"].items())
            out.append(f"  refusals: {codes}")
        for loop in run["loops"][:10]:
            out.append(
                f"  loop: {loop['tool']} with the same arguments {loop['count']} times "
                f"(first at call {loop['first_seq']})"
            )
        for dead in run["dead_ends"][:10]:
            out.append(
                f"  dead end: calls {dead['from_seq']}-{dead['to_seq']} ({dead['length']}) "
                "produced nothing new"
            )
        for stretch in run["no_progress"][:5]:
            out.append(
                f"  no progress: calls {stretch['from_seq']}-{stretch['to_seq']} "
                f"({stretch['length']}) recorded no finding, fact or recipe"
            )
        for claim in run["invented"][:10]:
            out.append(
                f"  invented observation: finding_submit at call {claim['seq']} cites "
                f"{', '.join(claim['missing'][:5])}, which no tool returned"
            )
        for warning in run["warnings"]:
            out.append(f"  WARNING: {warning}")
    return "\n".join(out)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli trace-review", description=(__doc__ or "").split("\n\n")[0]
    )
    p.add_argument("engagement")
    p.add_argument("--session", default="", help="Only this launcher session's runs.")
    p.add_argument("--json", action="store_true", help="Print the review as JSON.")
    p.add_argument("--audit-root", type=Path, default=None)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    slug = args.engagement
    if not slug or "/" in slug or "\\" in slug or slug.startswith("."):
        print(f"error: {slug!r} is not an engagement name", file=sys.stderr)
        return EXIT_CONFIG
    audit = _paths.audit_root(args.audit_root)
    result = review(agent_records.calls(audit, slug), session=args.session)
    if args.json:
        print(json.dumps({"engagement": slug, **result}, indent=2))
    else:
        print(to_text(slug, result))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
