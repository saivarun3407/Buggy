"""``buggy-cli ci-gate`` — gate a pipeline on exploit-verified findings.

    buggy-cli ci-gate --report report.json
    buggy-cli ci-gate --report report.json --hunt-result hunt-result.json \\
        --fail-on high --sarif buggy.sarif

Reads the findings report JSON (:func:`buggy.findings.report.build`, rendered
with ``to_json``) and, optionally, the ``hunt-result.json`` a ``buggy-cli
hunt`` run wrote. Only the report's ``findings`` section counts: it holds the
``exploit_verified`` findings and nothing else, and an item there whose status
is not ``exploit_verified`` is ignored. Unverified items, leads and discarded
claims never fail the gate. A verified finding whose severity is not one of the
five meets every threshold, as in ``buggy-cli hunt``.

Prints one summary line and the gating findings to stdout, writes SARIF 2.1.0
(:func:`buggy.findings.sarif.to_sarif`) when ``--sarif`` is given, and exits
with the same codes as ``buggy-cli hunt``. One difference in precedence: here a
verified finding at or above the threshold fails the gate even when the run is
incomplete, because what was proven stays proven.

No agent framework is imported: this runs in the slim pipeline image.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_INCOMPLETE = 3
EXIT_FINDINGS = 10

#: Most severe first; the order ``--fail-on`` thresholds are read in.
SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_FAIL_ON = "high"
EXPLOIT_VERIFIED = "exploit_verified"
#: ``report_format`` values this gate reads.
REPORT_FORMATS = (1,)

EXIT_CODES_HELP = """\
exit codes:
  0   complete, and no exploit-verified finding is at or above --fail-on
  10  an exploit-verified finding is at or above --fail-on (with
      --fail-on-issues also a known issue from hunt-result.json); this wins
      over an incomplete run
  3   nothing at or above the threshold, but the run is incomplete: the
      report's summary.complete or the hunt result's complete is false, or the
      SARIF file could not be written
  2   bad input: a file is missing, is not JSON, or is not a report or a hunt
      result; or the two name different engagements
"""


class BadInput(ValueError):
    """An input file cannot be gated on."""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli ci-gate",
        description="Fail a CI job on exploit-verified findings and write SARIF for code scanning.",
        epilog=EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--report", required=True, type=Path, help="The findings report JSON.")
    p.add_argument(
        "--hunt-result",
        type=Path,
        default=None,
        help="hunt-result.json of the run; its 'complete' is honoured.",
    )
    p.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=DEFAULT_FAIL_ON,
        metavar="SEVERITY",
        help="Fail (exit 10) on an exploit-verified finding at or above this severity "
        "(critical, high, medium, low, info). Default: high.",
    )
    p.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="Also count known issues from --hunt-result at or above --fail-on, "
        "as `buggy-cli hunt --fail-on-issues` does.",
    )
    p.add_argument("--sarif", type=Path, default=None, help="Write SARIF 2.1.0 to this path.")
    return p


# ── input ────────────────────────────────────────────────────────────


def _load(path: Path, what: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BadInput(f"cannot read the {what} {path}: {type(exc).__name__}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise BadInput(f"the {what} {path} is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise BadInput(f"the {what} {path} is not a JSON object")
    return document


def check_report(report: dict[str, Any]) -> None:
    """Raise :class:`BadInput` unless ``report`` has the shape the gate reads."""
    fmt = report.get("report_format")
    if fmt is not None and (type(fmt) is not int or fmt not in REPORT_FORMATS):
        raise BadInput(f"unsupported report_format {fmt!r}")
    summary = report.get("summary")
    if not isinstance(summary, dict) or not isinstance(summary.get("complete"), bool):
        raise BadInput("the report has no summary.complete (true or false)")
    if not isinstance(report.get("findings"), list):
        raise BadInput("the report has no findings list")
    for key in ("unverified", "leads"):
        if key in report and not isinstance(report[key], list):
            raise BadInput(f"the report's {key} is not a list")


def check_hunt_result(result: dict[str, Any]) -> None:
    if not isinstance(result.get("complete"), bool):
        raise BadInput("the hunt result has no 'complete' (true or false)")
    issues = result.get("issues")
    if issues is not None and (
        not isinstance(issues, dict) or not all(type(v) is int and v >= 0 for v in issues.values())
    ):
        raise BadInput("the hunt result's issues are not counts")


# ── decision ─────────────────────────────────────────────────────────


def _at_or_above(fail_on: str) -> tuple[str, ...]:
    return SEVERITIES[: SEVERITIES.index(fail_on) + 1]


def gating_findings(report: dict[str, Any], fail_on: str) -> list[dict[str, Any]]:
    """Exploit-verified findings at or above ``fail_on``; unknown severity always gates."""
    levels = _at_or_above(fail_on)
    out = []
    for item in report.get("findings") or []:
        if not isinstance(item, dict) or item.get("status") != EXPLOIT_VERIFIED:
            continue
        severity = str(item.get("severity") or "").lower()
        if severity in levels or severity not in SEVERITIES:
            out.append(item)

    def order(item: dict[str, Any]) -> tuple[int, str]:
        severity = str(item.get("severity") or "").lower()
        return (SEVERITIES.index(severity) if severity in SEVERITIES else -1), str(item.get("id"))

    return sorted(out, key=order)


def gating_issues(hunt_result: dict[str, Any] | None, fail_on: str) -> int:
    if not hunt_result:
        return 0
    issues = hunt_result.get("issues") or {}
    return sum(issues.get(severity, 0) for severity in _at_or_above(fail_on))


def decide(
    report: dict[str, Any],
    hunt_result: dict[str, Any] | None,
    *,
    fail_on: str,
    fail_on_issues: bool = False,
) -> dict[str, Any]:
    """The verdict: exit code, gating findings, and why a run is incomplete."""
    findings = gating_findings(report, fail_on)
    issues = gating_issues(hunt_result, fail_on) if fail_on_issues else 0
    incomplete: list[str] = []
    if report["summary"]["complete"] is not True:
        incomplete.append("the report says testing is not complete")
    if hunt_result is not None and hunt_result["complete"] is not True:
        incomplete.append("the hunt result says the run is incomplete")
    if findings or issues:
        code = EXIT_FINDINGS
    elif incomplete:
        code = EXIT_INCOMPLETE
    else:
        code = EXIT_OK
    return {"code": code, "findings": findings, "issues": issues, "incomplete": incomplete}


# ── output ───────────────────────────────────────────────────────────


def _line(value: Any, limit: int = 200) -> str:
    """One line of log text: no control characters, collapsed whitespace."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value or ""))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def summary_line(verdict: dict[str, Any], *, fail_on: str, report: dict[str, Any]) -> str:
    summary = report["summary"]
    verified = sum(
        1
        for item in report["findings"]
        if isinstance(item, dict) and item.get("status") == EXPLOIT_VERIFIED
    )
    not_proven = sum(
        summary.get(key, 0) if type(summary.get(key)) is int else 0
        for key in ("source_verified", "inconclusive", "candidates")
    )
    word = {EXIT_OK: "PASS", EXIT_FINDINGS: "FAIL", EXIT_INCOMPLETE: "INCOMPLETE"}[verdict["code"]]
    parts = [
        f"{len(verdict['findings'])} of {verified} exploit-verified finding(s) at or above {fail_on}"
    ]
    if verdict["issues"]:
        parts.append(f"{verdict['issues']} known issue(s) at or above {fail_on}")
    parts.append("; ".join(verdict["incomplete"]) or "complete")
    parts.append(f"{not_proven} not proven (never gating)")
    return f"buggy ci-gate: {word} (exit {verdict['code']}): " + "; ".join(parts)


def finding_line(item: dict[str, Any]) -> str:
    severity = _line(item.get("severity"), 20) or "unknown"
    where = _line(f"{item.get('method') or ''} {item.get('endpoint') or ''}", 300)
    return f"  - [{severity}] {_line(item.get('id'), 40)} {_line(item.get('title'))} ({where})"


def write_sarif(path: Path, document: dict[str, Any]) -> None:
    """Write ``document`` atomically; a reader never sees half a file."""
    directory = path.parent if str(path.parent) else Path(".")
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".buggy-sarif-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(
                json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
                + "\n"
            )
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _tool_version() -> str:
    from buggy import __version__

    return str(__version__)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse: usage error (2) or --help (0)
        return EXIT_CONFIG if exc.code not in (0, None) else EXIT_OK
    if args.fail_on_issues and args.hunt_result is None:
        print("error: --fail-on-issues reads known issues from --hunt-result", file=sys.stderr)
        return EXIT_CONFIG
    try:
        report = _load(args.report, "report")
        check_report(report)
        hunt_result = None
        if args.hunt_result is not None:
            hunt_result = _load(args.hunt_result, "hunt result")
            check_hunt_result(hunt_result)
            names = {str(report.get("engagement") or ""), str(hunt_result.get("engagement") or "")}
            if len(names - {""}) > 1:
                raise BadInput("the report and the hunt result name different engagements")
    except BadInput as exc:
        print(f"error: {_line(exc, 500)}", file=sys.stderr)
        return EXIT_CONFIG

    verdict = decide(report, hunt_result, fail_on=args.fail_on, fail_on_issues=args.fail_on_issues)
    code = verdict["code"]
    if args.sarif is not None:
        from buggy.findings.sarif import to_sarif

        try:
            write_sarif(args.sarif, to_sarif(report, tool_version=_tool_version()))
        except (OSError, ValueError) as exc:
            print(f"error: cannot write SARIF to {args.sarif}: {exc}", file=sys.stderr)
            verdict["incomplete"].append("the SARIF file could not be written")
            if code != EXIT_FINDINGS:
                code = verdict["code"] = EXIT_INCOMPLETE
    print(summary_line(verdict, fail_on=args.fail_on, report=report))
    for item in verdict["findings"]:
        print(finding_line(item))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
