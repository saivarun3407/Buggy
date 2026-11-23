"""``buggy-cli halt`` — stop every agent and probe of one engagement now.

    buggy-cli halt <engagement> [--reason "why"]    halt it
    buggy-cli halt <engagement> --clear              let new runs start again
    buggy-cli halt <engagement> --show               print the halt state

A halt is a file under the operator-controlled root (``<control>/<engagement>/HALT``)
that no agent can write. While it is there the evidence gateway and the scoped
browser send nothing for the engagement, and the agent bridge refuses every
tool call and stops its run. Each halt also revokes the leases of the agent
runs that are going on: they stay stopped after ``--clear``; only new runs start.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path

from buggy import agent_records
from buggy.capture import halt as halt_switch
from buggy.cli import _paths

EXIT_OK = 0
EXIT_CONFIG = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="buggy-cli halt", description=(__doc__ or "").split("\n\n")[0])
    p.add_argument("engagement")
    p.add_argument("--reason", default="", help="Why (shown to the agent and in the result).")
    action = p.add_mutually_exclusive_group()
    action.add_argument("--clear", action="store_true", help="Lift the halt for new runs.")
    action.add_argument("--show", action="store_true", help="Print the halt state and exit.")
    p.add_argument("--json", action="store_true", help="With --show: print JSON.")
    p.add_argument("--control-root", type=Path, default=None)
    p.add_argument("--audit-root", type=Path, default=None)
    return p


def _valid(name: str) -> bool:
    return bool(name) and "/" not in name and "\\" not in name and not name.startswith(".")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    control = _paths.control_root(args.control_root)
    audit = _paths.audit_root(args.audit_root)
    slug = args.engagement
    if not _valid(slug) or not (control / slug).is_dir():
        print(f"error: no engagement {slug!r} under {control}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        state = halt_switch.read_state(control, slug)
    except halt_switch.ControlStateError as exc:
        print(
            f"error: the halt state of {slug} cannot be read ({exc}); every agent call and "
            "request of this engagement is refused until it can",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    leases = agent_records.open_leases(audit, slug)

    if args.show:
        shown = {
            "engagement": slug,
            "halted": state.halted,
            "reason": state.reason,
            "at": state.at,
            "by": state.by,
            "epoch": state.epoch,
            "open_leases": [lease.get("run") for lease in leases],
        }
        if args.json:
            print(json.dumps(shown, indent=2))
        else:
            print(f"{slug}: {'HALTED' if state.halted else 'running'} (epoch {state.epoch})")
            if state.halted:
                when = time.strftime(" since %Y-%m-%d %H:%M:%S", time.localtime(state.at))
                who = f" by {state.by}" if state.by else ""
                print(f" {when if state.at else ''}{who}: {state.reason or 'no reason given'}")
            print(f"  open agent leases: {len(leases)}")
        return EXIT_OK

    if args.clear:
        if halt_switch.clear(control, slug):
            print(
                f"halt lifted for {slug}: new agent runs and requests may start. Runs that were "
                "going on when it was halted stay stopped."
            )
        else:
            print(f"{slug} was not halted")
        return EXIT_OK

    try:
        state = halt_switch.halt(control, slug, reason=args.reason, by=getpass.getuser())
    except OSError as exc:
        print(
            f"error: cannot write the halt under {control / slug}: {exc}. Run this on the host "
            "or in the operator container, where the control root is writable.",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    print(f"{slug} HALTED (epoch {state.epoch}): the gateway, the browser and the agent bridge")
    print("  refuse everything for this engagement until `buggy-cli halt " + slug + " --clear`.")
    if leases:
        runs = ", ".join(str(lease.get("run")) for lease in leases)
        print(f"  revoked {len(leases)} open agent lease(s): {runs}")
    else:
        print("  no agent run held a lease")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
