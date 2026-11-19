"""``buggy-cli pipeline`` / ``python -m buggy.pipeline`` — operator entry point.

pipeline run <engagement> [--force] [--asset HOST] [--max-age SECONDS]
pipeline status <engagement>
pipeline diff <engagement> [--run RUN_ID]
pipeline records <engagement> [--type T] [--asset HOST] [--contains TEXT]
pipeline drops <engagement> [--run RUN_ID]
pipeline worker [--once] [--interval SECONDS]
pipeline tools
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from buggy.pipeline import service, versions
from buggy.pipeline.pipeline import DEFAULT_MAX_AGE, STAGES
from buggy.pipeline.scope import ScopeError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli pipeline", description="Deterministic recon pipeline."
    )
    p.add_argument("--data-root", type=Path, default=None, help="Recon store directory.")
    p.add_argument("--control-root", type=Path, default=None, help="Operator-controlled root.")
    sub = p.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Run every stage for an engagement.")
    run.add_argument("engagement")
    run.add_argument("--force", action="store_true", help="Ignore the cache.")
    run.add_argument("--asset", default=None, help="Re-run for this in-scope asset only.")
    run.add_argument("--max-age", type=float, default=DEFAULT_MAX_AGE)
    for name in ("status", "diff", "records", "drops"):
        s = sub.add_parser(name)
        s.add_argument("engagement")
        if name in ("diff", "drops"):
            s.add_argument("--run", default=None)
        if name == "records":
            s.add_argument("--type", default=None)
            s.add_argument("--asset", default=None)
            s.add_argument("--contains", default=None)
            s.add_argument("--limit", type=int, default=100)
    worker = sub.add_parser("worker", help="Serve agent re-run requests.")
    worker.add_argument("--once", action="store_true")
    worker.add_argument("--interval", type=float, default=15.0)
    sub.add_parser("tools", help="Show pinned tool versions and what is installed.")
    return p


def _print(data: object) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = args.data_root or service.data_root()
    control = args.control_root or service.control_root()

    if args.command == "tools":
        rows = {}
        for name, pinned in versions.PINNED.items():
            try:
                binary, label = versions.verify(name)
                rows[name] = {
                    "pinned": pinned.version,
                    "status": "ok",
                    "version": label,
                    "path": binary,
                }
            except versions.ToolVersionError as exc:
                rows[name] = {"pinned": pinned.version, "status": "unavailable", "detail": str(exc)}
        rows["nuclei-templates"] = {"pinned": versions.NUCLEI_TEMPLATES_VERSION}
        _print(rows)
        return EXIT_OK if all(r.get("status", "ok") == "ok" for r in rows.values()) else EXIT_ERROR

    if args.command == "worker":
        if args.once:
            queue = service.open_queue()
            try:
                _print(service.worker_tick(queue, root=root, control=control))
            finally:
                queue.close()
            return EXIT_OK
        import logging  # noqa: PLC0415

        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
        )
        service.worker_loop(interval=args.interval)
        return EXIT_OK

    if args.command == "run":
        try:
            summary = service.run_engagement(
                args.engagement,
                force=args.force,
                only_asset=args.asset,
                max_age=args.max_age,
                root=root,
                control=control,
            )
        except ScopeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        except service.PipelineBusy as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        _print(summary)
        return EXIT_OK

    store = service.open_store(read_only=True, root=root)
    try:
        if args.command == "status":
            _print(
                {
                    "engagement": args.engagement,
                    "stages": list(STAGES),
                    "records": store.count_records(args.engagement),
                    "last_run": store.latest_run(args.engagement),
                }
            )
        elif args.command == "diff":
            run = store.get_run(args.run) if args.run else store.latest_run(args.engagement)
            if run is None:
                print("no runs", file=sys.stderr)
                return EXIT_CONFIG
            _print({"run_id": run["id"], "changes": store.diff(args.engagement, run["id"])})
        elif args.command == "drops":
            _print(store.scope_drops(args.engagement, run_id=args.run))
        else:  # records
            _print(
                [
                    r.to_dict()
                    for r in store.query_records(
                        args.engagement,
                        record_type=args.type,
                        asset=args.asset,
                        contains=args.contains,
                        limit=args.limit,
                    )
                ]
            )
    finally:
        store.close()
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
