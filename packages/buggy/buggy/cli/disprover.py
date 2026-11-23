"""``buggy-cli disprover`` — review and override the disprover's verdicts.

    buggy-cli disprover list     <engagement>
    buggy-cli disprover override <engagement> <finding-id> --reason "why it stands"

After the agent stage, a second Claude Code session (the disprover, ``buggy
agent`` runs it) argues that each agent-made finding is false. A verdict of
``false_positive`` or ``undetermined`` holds the finding out of "submit" (grade
rule 9). Only the operator lifts that: ``override`` records the decision in
``<control>/<engagement>/disprover-overrides.jsonl`` (a file no agent can
write) and grades the finding again. A later disprover verdict against the
same finding holds it again.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path
from typing import Any

from buggy.cli import _paths

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_UNAVAILABLE = 3


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli disprover", description=(__doc__ or "").split("\n\n")[0]
    )
    p.add_argument("--control-root", type=Path, default=None)
    sub = p.add_subparsers(dest="command", required=True)
    ls = sub.add_parser("list", help="Agent-made verified findings and the disprover's verdicts.")
    ls.add_argument("engagement")
    ls.add_argument("--json", action="store_true")
    ov = sub.add_parser("override", help="Let a held finding be graded without the objection.")
    ov.add_argument("engagement")
    ov.add_argument("finding_id")
    ov.add_argument("--reason", required=True, help="Why the finding stands (kept with it).")
    return p


def _capture(tool: str, engagement: str, **arguments: Any) -> dict[str, Any]:
    from buggy.pipeline.mcp_client import call_mcp_sync, server_configured  # noqa: PLC0415

    if not server_configured("capture"):
        return {"error": "the capture server is not configured here; run this in the stack"}
    return call_mcp_sync("capture", tool, {"engagement": engagement, **arguments})


def _known_issues(engagement: str) -> str:
    """The scanner's known issues, as hunt grades with them; ``[]`` without recon."""
    from buggy.cli import hunt  # noqa: PLC0415

    if not hunt.recon_available():
        return "[]"
    page = hunt._recon("recon_query", engagement, record_type="vulnerability", limit=200)  # noqa: SLF001
    rows = [row for row in page.get("records") or [] if isinstance(row, dict)]
    return hunt._known_issues({"vulnerability": rows})  # noqa: SLF001


def record_override(
    control: Path, engagement: str, finding_id: str, reason: str, operator: str = ""
) -> dict[str, Any]:
    from buggy.findings.service import OVERRIDES_FILE  # noqa: PLC0415

    record = {
        "finding_id": finding_id,
        "reason": " ".join(reason.split())[:1000],
        "operator": operator or getpass.getuser(),
        "at": time.time(),
    }
    path = control / engagement / OVERRIDES_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    return record


def _valid(name: str) -> bool:
    return bool(name) and "/" not in name and "\\" not in name and not name.startswith(".")


def main(argv: list[str] | None = None) -> int:
    from buggy.findings.service import agent_made  # noqa: PLC0415

    args = _build_parser().parse_args(argv)
    control = _paths.control_root(args.control_root)
    slug = args.engagement
    if not _valid(slug) or not (control / slug / "roe.json").is_file():
        print(f"error: no engagement {slug!r} under {control}", file=sys.stderr)
        return EXIT_CONFIG

    if args.command == "list":
        listed = _capture("findings_list", slug, status="exploit_verified")
        if listed.get("error"):
            print(f"error: {listed['error']}", file=sys.stderr)
            return EXIT_UNAVAILABLE
        rows = [
            {
                "id": row.get("id"),
                "title": row.get("title"),
                "grade": row.get("grade"),
                "challenge": row.get("challenge"),
            }
            for row in listed.get("findings") or []
            if isinstance(row, dict) and agent_made(str(row.get("source") or ""))
        ]
        if args.json:
            print(json.dumps(rows, indent=2))
            return EXIT_OK
        if not rows:
            print("no agent-made verified finding")
        for row in rows:
            challenge = row["challenge"] if isinstance(row["challenge"], dict) else None
            verdict = "not judged" if challenge is None else str(challenge.get("verdict"))
            holds = " (holds it)" if challenge and challenge.get("holds") else ""
            print(f"{row['id']}  grade={row['grade'] or '-'}  disprover={verdict}{holds}")
            print(f"    {str(row['title'] or '')[:120]}")
            if challenge:
                print(f"    why: {str(challenge.get('reason') or '')[:300]}")
        return EXIT_OK

    found = _capture("finding_get", slug, finding_id=args.finding_id)
    if found.get("error") or found.get("ok") is False:
        detail = found.get("detail") or found.get("error")
        print(f"error: {detail}", file=sys.stderr)
        return EXIT_CONFIG if found.get("ok") is False else EXIT_UNAVAILABLE
    try:
        record = record_override(control, slug, args.finding_id, args.reason)
    except OSError as exc:
        print(f"error: cannot write the override under {control / slug}: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    print(f"override recorded for {record['finding_id']} by {record['operator']}")
    graded = _capture(
        "finding_grade", slug, finding_id=args.finding_id, known_issues_json=_known_issues(slug)
    )
    grade = graded.get("grade") if isinstance(graded, dict) else None
    if isinstance(grade, dict):
        print(f"graded again: {grade.get('decision')}")
        for reason in grade.get("reasons") or []:
            print(f"    {reason}")
        print(f"Rebuild the reports with `buggy-cli hunt --resume {slug} --finalize --yes`.")
        return EXIT_OK
    print(
        f"the finding could not be graded again ({graded.get('detail') or graded.get('error')}); "
        "the override is recorded and applies at the next grading",
        file=sys.stderr,
    )
    return EXIT_UNAVAILABLE


if __name__ == "__main__":
    raise SystemExit(main())
