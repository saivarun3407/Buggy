"""``buggy-cli findings`` — decisions that expire: what is due for review, and the operator's call.

    buggy-cli findings due <engagement> [--json]
    buggy-cli findings ruled-out <engagement> [--query WORDS] [--json]
    buggy-cli findings extend <engagement> <entry-id> [--days N] [--note TEXT]
    buggy-cli findings close <engagement> <entry-id> --note TEXT
    buggy-cli findings reopen <engagement> <entry-id> [--note TEXT]

A lead ruled out, and a finding graded ``hold`` or ``discard``, get a review
date (``BUGGY_REVIEW_DAYS``, default 30). Once it passes, the lead goes back to
the agents' queue and the decision is listed here and in the report. The
operator then extends it (a new review date), closes it (the decision stands
for good) or reopens it (the lead is back now).

Runs where the capture data is reachable (the operator side, or inside the
capture service): the store is ``$BUGGY_CAPTURE_DATA/findings.sqlite3``.
Nothing is sent to a target.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import UTC, datetime
from typing import Any

from buggy.capture.gateway import Roots
from buggy.findings.ruled_out import DAY, MAX_REVIEW_DAYS, Ledger, brief, review_days_from_env
from buggy.findings.store import STATE_CLOSED, STATE_REOPENED, FindingStore

EXIT_OK = 0
EXIT_USAGE = 2
ACTOR = "operator"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli findings",
        description=(__doc__ or "").split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)
    due = sub.add_parser("due", help="Decisions whose review date has passed.")
    due.add_argument("engagement")
    due.add_argument("--json", action="store_true", help="Print one JSON document.")
    ruled = sub.add_parser("ruled-out", help="Leads ruled out now, and recent failed attempts.")
    ruled.add_argument("engagement")
    ruled.add_argument("--query", default="", help="Words to look for (technique, URL, reason).")
    ruled.add_argument("--json", action="store_true", help="Print one JSON document.")
    for name, text in (
        ("extend", "Give a decision a new review date."),
        ("close", "Keep a decision for good: no more review."),
        ("reopen", "Lift a decision: the lead goes back to the queue now."),
    ):
        command = sub.add_parser(name, help=text)
        command.add_argument("engagement")
        command.add_argument("entry_id", help="The ledger entry, e.g. L-12.")
        command.add_argument("--note", default="", help="Why (kept with the entry).")
        if name == "extend":
            command.add_argument(
                "--days",
                type=float,
                default=None,
                help="Days from now (default: BUGGY_REVIEW_DAYS, else 30).",
            )
    return p


def _when(value: Any) -> str:
    if not value:
        return "-"
    return datetime.fromtimestamp(float(value), tz=UTC).strftime("%Y-%m-%d")


def _line(entry: dict[str, Any]) -> str:
    where = f"{entry['technique']} {entry['method']} {entry['endpoint']}".replace("  ", " ")
    if entry.get("parameter"):
        where += f" [{entry['parameter']}]"
    finding = f" {entry['finding_id']}" if entry.get("finding_id") else ""
    code = f" ({entry['code']})" if entry.get("code") else ""
    return (
        f"{entry['id']:<7} {entry['kind']:<9} {entry['reason']}{code}{finding}  {where}  "
        f"review {_when(entry.get('review_at'))}  — {entry.get('why') or ''}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code == 0 else EXIT_USAGE
    roots = Roots.from_env()
    try:
        store = FindingStore(roots.data / "findings.sqlite3")
    except (OSError, sqlite3.Error) as exc:
        print(
            f"findings: cannot open the findings store under {roots.data}: {exc}", file=sys.stderr
        )
        return EXIT_USAGE
    try:
        ledger = Ledger(store, review_days=review_days_from_env())
        if args.command == "due":
            rows = ledger.due(args.engagement)
            if args.json:
                print(json.dumps({"engagement": args.engagement, "due": rows}, indent=2))
            elif not rows:
                print(f"nothing is due for review in {args.engagement}")
            else:
                print(f"{len(rows)} decision(s) due for review in {args.engagement}:")
                for row in rows:
                    print(_line(row))
            return EXIT_OK
        if args.command == "ruled-out":
            listed = ledger.listed(args.engagement, args.query)
            if args.json:
                print(json.dumps(listed, indent=2))
                return EXIT_OK
            print(f"ruled out ({listed['ruled_out_total']}):")
            for row in listed["ruled_out"]:
                print("  " + _line(row))
            print(f"failed attempts, nothing retired ({listed['failed_attempts_total']}):")
            for row in listed["failed_attempts"]:
                print("  " + _line(row))
            return EXIT_OK
        entry = store.ledger_get(args.engagement, args.entry_id)
        if entry is None:
            print(
                f"findings: no ledger entry {args.entry_id!r} in engagement {args.engagement!r}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        if args.command == "extend":
            days = ledger.review_days if args.days is None else args.days
            if not 0 < days <= MAX_REVIEW_DAYS:
                print(
                    f"findings: --days must be between 0 and {MAX_REVIEW_DAYS:g}", file=sys.stderr
                )
                return EXIT_USAGE
            updated = store.ledger_set_state(
                args.engagement,
                args.entry_id,
                actor=ACTOR,
                state="open",
                review_at=ledger.now() + days * DAY,
                note=args.note or f"extended by {days:g} days",
            )
        elif args.command == "close":
            if not args.note.strip():
                print("findings: close needs --note saying why it stands", file=sys.stderr)
                return EXIT_USAGE
            updated = store.ledger_set_state(
                args.engagement, args.entry_id, actor=ACTOR, state=STATE_CLOSED, note=args.note
            )
        else:
            updated = store.ledger_set_state(
                args.engagement,
                args.entry_id,
                actor=ACTOR,
                state=STATE_REOPENED,
                note=args.note or "reopened by the operator",
            )
        print(_line(brief(updated)) + f"  [{updated['state']}]")
        return EXIT_OK
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
