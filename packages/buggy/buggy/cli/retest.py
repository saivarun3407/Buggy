"""``buggy-cli retest`` — re-run verified findings' assertions and say whether they are fixed.

    buggy-cli retest <engagement> <finding-id> [--json]
    buggy-cli retest <engagement> --all-verified [--json]

Runs where the capture data is reachable (the operator side, or inside the
capture service): the roots come from ``BUGGY_CONTROL_ROOT``,
``BUGGY_AUDIT_ROOT``, ``BUGGY_CAPTURE_DATA`` and ``BUGGY_SECRETS_ROOT``. Every
request goes through the capture gateway. State-changing proofs are not
re-sent from here (they come out ``inconclusive``). A retest never changes a
finding's status.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from typing import Any

from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.identities import IdentityError
from buggy.findings.model import Status
from buggy.findings.retest import retest
from buggy.findings.service import FindingService
from buggy.findings.store import (
    RETEST_FIXED,
    RETEST_INCONCLUSIVE,
    RETEST_STILL_VULNERABLE,
    FindingStore,
)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_VULNERABLE = 10

EXIT_CODES_HELP = """\
exit codes:
  0   every retested finding is fixed (or there was nothing to retest)
  10  at least one finding is still vulnerable (this wins over 3)
  3   at least one retest was inconclusive and none is still vulnerable
  2   usage or configuration error (unknown finding, unreadable store)
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli retest",
        description=(__doc__ or "").split("\n\n")[0],
        epilog=EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("engagement")
    which = p.add_mutually_exclusive_group(required=True)
    which.add_argument("finding_id", nargs="?", default=None)
    which.add_argument(
        "--all-verified", action="store_true", help="Retest every exploit_verified finding."
    )
    p.add_argument("--json", action="store_true", help="Print one JSON document.")
    return p


def exit_code(results: list[dict[str, Any]]) -> int:
    outcomes = {r.get("outcome") for r in results}
    if RETEST_STILL_VULNERABLE in outcomes:
        return EXIT_VULNERABLE
    if RETEST_INCONCLUSIVE in outcomes or outcomes - {RETEST_FIXED}:
        return EXIT_INCOMPLETE
    return EXIT_OK


def _line(result: dict[str, Any]) -> str:
    reasons = result.get("reasons") or []
    why = f" — {reasons[0]}" if reasons and result["outcome"] != RETEST_FIXED else ""
    return f"{result['finding_id']}  {result['outcome']:<16}  {result.get('title', '')}{why}"


def _sessions(gateway: CaptureGateway, engagement: str) -> Any:
    """The gateway's session manager when the engagement declares identities, else ``None``.

    With it, an assertion that names a declared identity is re-sent with that
    account's current session instead of the credentials stored with the
    cited capture (which may have expired).
    """
    try:
        declared = gateway.identities.load(engagement)
    except IdentityError:  # a bad or unreadable file: no identities are attached
        return None
    return gateway.sessions if declared else None


def main(argv: list[str] | None = None, *, opener: Any = None, sleep: Any = None) -> int:
    """Entry point. ``opener``/``sleep`` replace the gateway's HTTP opener and sleep (tests)."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code == 0 else EXIT_USAGE

    roots = Roots.from_env()
    kwargs: dict[str, Any] = {}
    if opener is not None:
        kwargs["opener"] = opener
    if sleep is not None:
        kwargs["sleep"] = sleep
    try:
        store = FindingStore(roots.data / "findings.sqlite3")
    except (OSError, sqlite3.Error) as exc:
        print(f"retest: cannot open the findings store under {roots.data}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    gateway = CaptureGateway(roots, **kwargs)
    try:
        service = FindingService(store, gateway, sessions=_sessions(gateway, args.engagement))
        if args.all_verified:
            ids = [f.id for f in store.list(args.engagement, status=Status.EXPLOIT_VERIFIED.value)]
        else:
            if store.get(args.engagement, args.finding_id) is None:
                print(
                    f"retest: no finding {args.finding_id!r} in engagement {args.engagement!r}",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            ids = [args.finding_id]
        results: list[dict[str, Any]] = []
        for finding_id in ids:
            out = retest(service, args.engagement, finding_id)
            if not out.get("ok"):
                out = {
                    "finding_id": finding_id,
                    "outcome": RETEST_INCONCLUSIVE,
                    "reasons": [str(out.get("detail") or out.get("code") or "retest failed")],
                }
            results.append(out)
    finally:
        gateway.store.close()
        store.close()

    code = exit_code(results)
    if args.json:
        counts = {name: 0 for name in (RETEST_FIXED, RETEST_STILL_VULNERABLE, RETEST_INCONCLUSIVE)}
        for r in results:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        document = {
            "engagement": args.engagement,
            "exit_code": code,
            "counts": counts,
            "results": [
                {
                    "finding_id": r["finding_id"],
                    "title": r.get("title", ""),
                    "status": r.get("status"),
                    "outcome": r["outcome"],
                    "reasons": r.get("reasons", []),
                    "capture_ids": r.get("capture_ids", []),
                    "fixed_at": r.get("fixed_at"),
                    "regressed": bool(r.get("regressed")),
                }
                for r in results
            ],
        }
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        if not results:
            print(f"no exploit_verified findings in {args.engagement}")
        for r in results:
            print(_line(r))
    return code


__all__ = ["EXIT_INCOMPLETE", "EXIT_OK", "EXIT_USAGE", "EXIT_VULNERABLE", "exit_code", "main"]
