"""``buggy-cli program brief <engagement>`` — where to look first on a bounty program.

    buggy-cli program brief acme
    buggy-cli program brief acme --history ~/h1-export.json --json

Builds the brief of :mod:`buggy.program.brief` from the imported program
(``control/<engagement>/program.json``), the recon store, the capture store,
the findings of this engagement and of other engagements on the same program,
and the operator's report history (``control/<engagement>/report-history.json``
unless ``--history`` names another file). Writes
``control/<engagement>/program-brief.md``.

Recon, captures and findings are read through the stack's MCP servers with an
injected ``fetch(server, tool, arguments)`` (as ``buggy-cli status`` does). A
source that cannot be read is named in the brief and the sections that need it
say so; the command does not fail for it. Nothing is sent to a target or to a
bounty platform. Exit 2: not a program engagement, or its record is unreadable.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from buggy.cli import _paths
from buggy.program.brief import (
    BRIEF_FILE,
    HISTORY_FILE,
    build_brief,
    load_history,
    scope_hosts,
    to_markdown,
)
from buggy.program.record import load_program

EXIT_OK = 0
EXIT_WRITE = 1
EXIT_CONFIG = 2

#: ``fetch(server, tool, arguments) -> dict``: one read from a stack MCP server.
Fetch = Callable[[str, str, dict[str, Any]], dict[str, Any]]

#: Recon record types the brief reads, with a cap on rows per type.
RECON_TYPES: dict[str, int] = {
    "subdomain": 2000,
    "http_service": 500,
    "endpoint": 2000,
    "url": 2000,
    "api_operation": 1000,
    "parameter": 3000,
    "graphql": 50,
}
PAGE = 200
#: Hosts asked about one by one in the capture store.
MAX_CAPTURE_HOSTS = 300


class SourceUnavailable(Exception):
    """A remote read failed; the message says why."""


def _call(fetch: Fetch, server: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        result = fetch(server, tool, arguments)
    except Exception as exc:  # noqa: BLE001 - reported in the brief, never raised
        raise SourceUnavailable(
            f"{server}.{tool} failed: {type(exc).__name__}: {str(exc)[:300]}"
        ) from exc
    if not isinstance(result, dict):
        raise SourceUnavailable(f"{server}.{tool} returned {type(result).__name__}, not an object")
    if result.get("error"):
        raise SourceUnavailable(f"{server}.{tool}: {str(result['error'])[:300]}")
    return result


def read_recon(fetch: Fetch, engagement: str) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for record_type, cap in RECON_TYPES.items():
        rows: list[dict[str, Any]] = []
        offset = 0
        while len(rows) < cap:
            page = _call(
                fetch,
                "recon",
                "recon_query",
                {
                    "engagement": engagement,
                    "record_type": record_type,
                    "limit": PAGE,
                    "offset": offset,
                },
            )
            batch = page.get("records")
            if not isinstance(batch, list):
                raise SourceUnavailable("recon.recon_query returned no record list")
            rows.extend(r for r in batch if isinstance(r, dict))
            following = page.get("next_offset")
            if not page.get("truncated") or not isinstance(following, int) or following <= offset:
                break
            offset = following
        out[record_type] = rows[:cap]
    return out


def read_findings(fetch: Fetch, engagement: str) -> list[dict[str, Any]]:
    result = _call(fetch, "capture", "findings_list", {"engagement": engagement})
    rows = result.get("findings", result.get("result"))
    if not isinstance(rows, list):
        raise SourceUnavailable("capture.findings_list returned no finding list")
    return [{"engagement": engagement, **row} for row in rows if isinstance(row, dict)]


def read_captured_hosts(fetch: Fetch, engagement: str, hosts: list[str]) -> set[str]:
    """The hosts among ``hosts`` with at least one capture. Raises when it cannot tell."""
    if len(hosts) > MAX_CAPTURE_HOSTS:
        raise SourceUnavailable(
            f"{len(hosts)} in-scope hosts is more than the {MAX_CAPTURE_HOSTS} the capture "
            "store is asked about"
        )
    captured: set[str] = set()
    for host in hosts:
        result = _call(
            fetch, "capture", "http_captures", {"engagement": engagement, "host": host, "limit": 1}
        )
        captures = result.get("captures")
        if not isinstance(captures, list):
            raise SourceUnavailable("capture.http_captures returned no capture list")
        if captures:
            captured.add(host)
    return captured


def sibling_engagements(control: Path, engagement: str, program: dict[str, Any]) -> list[str]:
    """Other engagements under the control root imported from the same program."""
    key = (str(program.get("platform") or ""), str(program.get("handle") or ""))
    if not all(key):
        return []
    out: list[str] = []
    try:
        names = sorted(p.name for p in control.iterdir() if p.is_dir())
    except OSError:
        return []
    for name in names:
        if name == engagement:
            continue
        other = load_program(control, name)
        if other and not other.get("_invalid"):
            if (str(other.get("platform") or ""), str(other.get("handle") or "")) == key:
                out.append(name)
    return out


def brief_for(
    engagement: str,
    *,
    control: Path,
    fetch: Fetch,
    history_path: Path | None = None,
) -> dict[str, Any]:
    """Read every source, degrade what cannot be read, and build the brief."""
    program = load_program(control, engagement)
    if program is None:
        raise LookupError(
            f"{engagement!r} is not a program engagement: no {control / engagement / 'program.json'}"
        )
    if program.get("_invalid"):
        raise LookupError(f"the program record is unreadable: {program['_invalid']}")
    notes: dict[str, str] = {}

    recon: dict[str, list[dict[str, Any]]] | None
    try:
        recon = read_recon(fetch, engagement)
    except SourceUnavailable as exc:
        recon, notes["recon"] = None, f"unavailable: {exc}"

    findings: list[dict[str, Any]] | None
    try:
        findings = read_findings(fetch, engagement)
    except SourceUnavailable as exc:
        findings, notes["findings"] = None, f"unavailable: {exc}"
    if findings is not None:
        skipped: list[str] = []
        for other in sibling_engagements(control, engagement, program):
            try:
                findings.extend(read_findings(fetch, other))
            except SourceUnavailable:
                skipped.append(other)
        if skipped:
            notes["other engagements"] = "findings not read for: " + ", ".join(skipped)

    captured: set[str] | None
    try:
        captured = read_captured_hosts(fetch, engagement, scope_hosts(program, recon))
    except SourceUnavailable as exc:
        captured, notes["captures"] = None, f"unavailable: {exc}"

    path = history_path or control / engagement / HISTORY_FILE
    history, reason = load_history(path)
    if reason:
        notes["history"] = reason
    return build_brief(
        program,
        recon,
        findings,
        history,
        engagement=engagement,
        captured_hosts=captured,
        sources=notes,
    )


def _stack_fetch() -> Fetch:
    """The real remote reader; a reader that reports why when the client cannot be loaded."""
    try:
        # No agent-framework imports: this works from the slim pipeline image.
        from buggy.pipeline.mcp_client import call_mcp_sync  # noqa: PLC0415 - only when run
    except ImportError as exc:
        reason = f"the stack MCP client cannot be loaded: {exc}"

        def missing(server: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
            return {"error": reason}

        return missing
    return call_mcp_sync


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="buggy-cli program",
        description="Bounty-program commands that read the operator's own data.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    brief = sub.add_parser(
        "brief",
        help="where to look first on this program, and why",
        description=(
            "Build a deterministic brief from the imported program, recon, captures, findings "
            f"and the report history, and write control/<engagement>/{BRIEF_FILE}."
        ),
    )
    brief.add_argument("engagement")
    brief.add_argument(
        "--history",
        type=Path,
        default=None,
        help=f"report history JSON (default: control/<engagement>/{HISTORY_FILE})",
    )
    brief.add_argument("--json", action="store_true", help="print the brief as JSON")
    brief.add_argument("--control-root", type=Path, default=None)
    return parser


def main(
    argv: list[str] | None = None,
    *,
    fetch: Fetch | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = _build_parser().parse_args(argv)
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    control = _paths.control_root(args.control_root)
    try:
        brief = brief_for(
            args.engagement,
            control=control,
            fetch=fetch or _stack_fetch(),
            history_path=args.history,
        )
    except LookupError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_CONFIG
    text = to_markdown(brief)
    target = control / args.engagement / BRIEF_FILE
    try:
        target.write_text(text, encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write {target}: {exc}", file=err)
        return EXIT_WRITE
    if args.json:
        print(json.dumps(brief, indent=2), file=out)
    else:
        print(text, file=out)
    print(f"wrote {target}", file=err)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
