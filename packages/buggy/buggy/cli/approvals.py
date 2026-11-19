"""``buggy-cli approvals`` — answer the agent's approval requests.

Requests are written by the langgraph process to
``<audit-root>/<engagement>/approvals/requests.jsonl``. Decisions are read
from ``<control-root>/<engagement>/approvals/decisions.jsonl``, a file only the
operator can write. An unanswered request times out to *deny*.

    buggy-cli approvals list  <engagement>
    buggy-cli approvals allow <engagement> <request-id> [--note "..."]
    buggy-cli approvals deny  <engagement> <request-id> [--note "..."]
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


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli approvals", description=(__doc__ or "").split("\n\n")[0]
    )
    p.add_argument("--control-root", type=Path, default=None)
    p.add_argument("--audit-root", type=Path, default=None)
    sub = p.add_subparsers(dest="command", required=True)
    ls = sub.add_parser("list", help="Show requests that have no decision yet.")
    ls.add_argument("engagement")
    ls.add_argument("--all", action="store_true", help="Include decided requests.")
    ls.add_argument("--json", action="store_true")
    for name in ("allow", "deny"):
        s = sub.add_parser(name, help=f"Record a {name} decision.")
        s.add_argument("engagement")
        s.add_argument("request_id")
        s.add_argument("--note", default="")
    return p


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
    except FileNotFoundError:
        pass
    return rows


def paths_for(control: Path, audit: Path, slug: str) -> tuple[Path, Path]:
    return (
        audit / slug / "approvals" / "requests.jsonl",
        control / slug / "approvals" / "decisions.jsonl",
    )


def pending(requests_path: Path, decisions_path: Path) -> list[dict[str, Any]]:
    decided = {str(d.get("request_id")) for d in _read_jsonl(decisions_path)}
    return [r for r in _read_jsonl(requests_path) if str(r.get("request_id")) not in decided]


def record_decision(
    decisions_path: Path, request_id: str, action: str, *, note: str = "", operator: str = ""
) -> dict[str, Any]:
    record = {
        "kind": "approval_decision",
        "request_id": request_id,
        "action": action,
        "operator": operator or getpass.getuser(),
        "operator_note": note,
        "decided_at": time.time(),
    }
    decisions_path.parent.mkdir(parents=True, exist_ok=True)
    with decisions_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    return record


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    control = _paths.control_root(args.control_root)
    audit = _paths.audit_root(args.audit_root)
    requests_path, decisions_path = paths_for(control, audit, args.engagement)

    if args.command == "list":
        rows = _read_jsonl(requests_path) if args.all else pending(requests_path, decisions_path)
        if args.json:
            print(json.dumps(rows, indent=2))
            return EXIT_OK
        if not rows:
            print("no pending approval requests")
            return EXIT_OK
        for row in rows:
            print(
                f"{row.get('request_id')}  tool={row.get('tool_name')}  agent={row.get('agent_name')}"
            )
            print(f"    reason: {row.get('reason')}")
            print(f"    args:   {json.dumps(row.get('tool_args_redacted'))[:400]}")
        return EXIT_OK

    known = {str(r.get("request_id")) for r in _read_jsonl(requests_path)}
    if args.request_id not in known:
        print(f"error: no request {args.request_id!r} in {requests_path}", file=sys.stderr)
        return EXIT_CONFIG
    record = record_decision(decisions_path, args.request_id, args.command, note=args.note)
    print(f"{record['action']} recorded for {record['request_id']} in {decisions_path}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
