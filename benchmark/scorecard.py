"""Scorecard for one benchmark run, generated only from its evidence records.

``render(directory)`` reads the records written by :mod:`benchmark.evidence`
and nothing else: there is no way to pass it a number. Every record gets a row,
failures included; targets of the suite without a record are listed as "not
attempted"; there is no row without a record.

``python -m benchmark.scorecard <dir>`` prints the Markdown;
``--write`` saves it as ``<dir>/SCORECARD.md`` and is refused when the run
does not pass ``python -m benchmark.evidence verify``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

from benchmark import evidence
from benchmark.evidence import EvidenceError, RunRecord

COLUMNS = (
    "target",
    "level",
    "solved",
    "wall s",
    "in tokens",
    "out tokens",
    "cost",
    "transcript",
)
NOT_MEASURED = "n/a"
NO_OUTCOME = "no outcome"


@dataclass
class Summary:
    """What the scorecard states, computed from the records of one run directory."""

    records: list[RunRecord] = field(default_factory=list)
    # target id -> level, for every target of the suite (empty without a manifest).
    levels: dict[str, int | None] = field(default_factory=dict)
    has_manifest: bool = False
    not_attempted: list[str] = field(default_factory=list)

    @property
    def attempted(self) -> int:
        return len(self.records)

    @property
    def solved(self) -> int:
        return sum(1 for r in self.records if r.solved)

    @property
    def by_failure(self) -> dict[str, int]:
        counts = {state: 0 for state in (*evidence.FAILURE_STATES, NO_OUTCOME)}
        for record in self.records:
            if not record.solved:
                counts[record.terminal_state or NO_OUTCOME] += 1
        return counts

    def total(self, values: list[float | int | None]) -> tuple[float | int, int]:
        """Sum of the measured values and how many records have none."""
        known = [v for v in values if v is not None]
        return sum(known), len(values) - len(known)


def summarize(directory: Path) -> Summary:
    """Load a run directory. Unreadable record files are left to ``verify``."""
    directory = Path(directory)
    summary = Summary()
    try:
        manifest = evidence.load_manifest(directory)
    except EvidenceError:
        manifest = None
    if manifest is not None:
        summary.has_manifest = True
        summary.levels = {t.id: t.level for t in manifest.targets}

    for path in evidence.record_files(directory):
        try:
            summary.records.append(evidence.load_record(path))
        except EvidenceError:
            continue
    order = {target: index for index, target in enumerate(summary.levels)}
    summary.records.sort(key=lambda r: (order.get(r.target, len(order)), r.target, r.attempt))
    recorded = {r.target for r in summary.records}
    summary.not_attempted = [target for target in summary.levels if target not in recorded]
    return summary


def _distinct(values: list[str | None]) -> str:
    seen = sorted({value for value in values if value})
    missing = any(not value for value in values)
    parts = [f"`{value}`" for value in seen] + (["not recorded"] if missing or not seen else [])
    return ", ".join(parts)


def _number(value: float | int | None, fmt: str) -> str:
    return NOT_MEASURED if value is None else format(value, fmt)


def _total(pair: tuple[float | int, int], fmt: str) -> str:
    total, unmeasured = pair
    text = format(total, fmt)
    return f"{text} ({unmeasured} {NOT_MEASURED})" if unmeasured else text


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _record_row(record: RunRecord, summary: Summary) -> str:
    level = summary.levels.get(record.target)
    if record.solved:
        outcome = "yes"
    else:
        outcome = f"no ({record.terminal_state or NO_OUTCOME})"
    if record.transcript_file:
        transcript = f"[{record.transcript_file}]({record.transcript_file})"
        if record.win_evidence is not None:
            transcript += f" line {record.win_evidence.line}"
    else:
        transcript = "none"
    return _row(
        [
            f"`{record.target}`",
            NOT_MEASURED if level is None else str(level),
            outcome,
            _number(record.wall_seconds, ".1f"),
            _number(record.tokens.input, "d"),
            _number(record.tokens.output, "d"),
            _number(record.cost_usd, ".4f"),
            transcript,
        ]
    )


def _black_box_statement(records: list[RunRecord]) -> str:
    kinds = sorted({entry.split("=", 1)[0] for r in records for entry in r.black_box_inputs})
    if not kinds:
        return "none can be made: no record lists `black_box_inputs`."
    silent = sum(1 for r in records if not r.black_box_inputs)
    statement = (
        "the solver was given only what each record lists under `black_box_inputs` ("
        + ", ".join(kinds)
        + "). Each target's flag was random for the attempt; its sha256 was written to the "
        "record before the attempt and the flag itself after it."
    )
    if silent:
        statement += f" {silent} record(s) list no inputs."
    return statement


def render(directory: Path) -> str:
    """Markdown scorecard of a run directory, from its records only."""
    directory = Path(directory)
    summary = summarize(directory)
    records = summary.records
    problems = evidence.verify_run(directory, check_scorecard=False)

    dates = sorted(r.committed_at for r in records)
    lines = [
        f"# Benchmark scorecard: {_distinct([r.run_id for r in records])}",
        "",
        "Generated by `python -m benchmark.scorecard` from the records in this directory.",
        "No value on this page is typed by hand.",
        "",
        f"- Run id: {_distinct([r.run_id for r in records])}",
        f"- Suite: {_distinct([r.suite for r in records])}",
        f"- Date: {dates[0][:10] + ' (UTC, first commitment)' if dates else 'not recorded'}",
        f"- Revision: {_distinct([r.git_revision for r in records])}",
        f"- Model: {_distinct([r.model for r in records])}"
        f" (profile: {_distinct([r.model_profile for r in records])})",
        f"- Black-box statement: {_black_box_statement(records)}",
    ]
    if problems:
        lines.append(
            f"- Verification: **FAILED**, {len(problems)} problem(s) listed below. "
            "Do not cite this scorecard."
        )
    else:
        lines.append(
            "- Verification: passed when generated. Re-check with "
            "`python -m benchmark.evidence verify <this directory>`."
        )

    wall = summary.total([r.wall_seconds for r in records])
    tokens_in = summary.total([r.tokens.input for r in records])
    tokens_out = summary.total([r.tokens.output for r in records])
    cost = summary.total([r.cost_usd for r in records])
    lines += [
        "",
        "## Targets",
        "",
        _row(list(COLUMNS)),
        _row(["---", "---:", "---", "---:", "---:", "---:", "---:", "---"]),
        *[_record_row(record, summary) for record in records],
        _row(
            [
                "**total**",
                "",
                f"{summary.solved} of {summary.attempted} attempted",
                _total(wall, ".1f"),
                _total(tokens_in, "d"),
                _total(tokens_out, "d"),
                _total(cost, ".4f"),
                "",
            ]
        ),
        "",
        "Cost is in USD. `n/a` means not measured, never zero.",
        "",
        "## Totals",
        "",
        "- Targets in suite: "
        + (str(len(summary.levels)) if summary.has_manifest else "unknown (no manifest.json)"),
        f"- Attempted: {summary.attempted}",
        f"- Solved: {summary.solved}",
        f"- Not solved: {summary.attempted - summary.solved} ("
        + ", ".join(f"{state} {count}" for state, count in summary.by_failure.items())
        + ")",
        "- Not attempted: "
        + (str(len(summary.not_attempted)) if summary.has_manifest else "unknown"),
        "",
        "## Not attempted",
        "",
    ]
    if not summary.has_manifest:
        lines.append("Unknown: the run directory has no readable `manifest.json`.")
    elif summary.not_attempted:
        lines += [f"- `{target}`" for target in summary.not_attempted]
    else:
        lines.append("None: every target of the suite has a record.")
    if problems:
        lines += ["", "## Verification problems", ""]
        lines += [f"- {problem}" for problem in problems]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmark.scorecard",
        description="Render the scorecard of a benchmark run directory from its records.",
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--write", action="store_true", help=f"save as <directory>/{evidence.SCORECARD_FILE}"
    )
    args = parser.parse_args(argv)

    text = render(args.directory)
    failed = bool(evidence.verify_run(args.directory, check_scorecard=False))
    if not args.write:
        print(text, end="")
        return 1 if failed else 0
    if failed:
        print(text, end="")
        print(f"not written: {args.directory} does not pass verification")
        return 1
    path = Path(args.directory) / evidence.SCORECARD_FILE
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
