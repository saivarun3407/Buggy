"""``buggy-cli scope`` — operator control of the enforced scope.

The guardrail enforces ``<control-root>/<engagement>/roe.json`` and nothing
else. The agent can draft a scope at ``<workspace>/<engagement>/plan/roe.json``
(the Soundwave interview does exactly that), but a draft has no effect until
an operator promotes it here:

    buggy-cli scope show    <engagement>            # enforced scope, or the draft
    buggy-cli scope diff    <engagement>            # draft vs enforced
    buggy-cli scope approve <engagement> [--yes]    # promote the draft
    buggy-cli scope set     <engagement> --file roe.json [--yes]
    buggy-cli scope import  --platform hackerone --handle <program> [--csv scope.csv]

``import`` builds the enforced scope from a bounty program's official scope
data (platform API, or the scope CSV downloaded from the program page). The
result is always enforce mode, with operator approval required for
state-changing requests and for releasing a report.

Every document is validated with the same parser the guardrail uses, so a
policy that would be rejected at run time cannot be approved.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import sys
from pathlib import Path
from typing import Any

from buggy.cli import _paths

EXIT_OK = 0
EXIT_CONFIG = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli scope", description=(__doc__ or "").split("\n\n")[0]
    )
    p.add_argument("--workspace-root", type=Path, default=None)
    p.add_argument("--control-root", type=Path, default=None)
    sub = p.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("show", "Print the enforced scope (or the draft when none is enforced)."),
        ("diff", "Show how the workspace draft differs from the enforced scope."),
    ):
        s = sub.add_parser(name, help=help_text)
        s.add_argument("engagement")
    approve = sub.add_parser("approve", help="Promote the workspace draft to the enforced scope.")
    approve.add_argument("engagement")
    approve.add_argument("--yes", action="store_true", help="Do not prompt for confirmation.")
    setp = sub.add_parser("set", help="Install a RoE file as the enforced scope.")
    setp.add_argument("engagement")
    setp.add_argument("--file", type=Path, required=True)
    setp.add_argument("--yes", action="store_true", help="Do not prompt for confirmation.")
    imp = sub.add_parser(
        "import", help="Build the enforced scope from a bounty program's official scope data."
    )
    imp.add_argument("--platform", required=True, choices=["hackerone", "bugcrowd"])
    imp.add_argument("--handle", required=True, help="Program handle as it appears in its URL.")
    imp.add_argument(
        "--csv", type=Path, default=None, help="HackerOne scope CSV from the program page."
    )
    imp.add_argument(
        "--engagement", default="", help="Engagement slug (default: <platform>-<handle>)."
    )
    imp.add_argument("--rps", type=int, default=None, help="Requests per second (1-20, default 5).")
    imp.add_argument(
        "--port-scan", action="store_true", help="Allow the pipeline's port scan (off by default)."
    )
    imp.add_argument("--yes", action="store_true", help="Do not prompt for confirmation.")
    return p


def _import_program(args: argparse.Namespace, control: Path) -> int:
    from buggy.program import importer
    from buggy.program.record import PROGRAM_FILE

    try:
        if args.csv is not None:
            if args.platform != "hackerone":
                raise importer.ScopeImportError("--csv is a HackerOne scope export")
            try:
                text = args.csv.read_text(encoding="utf-8-sig")
            except OSError as exc:
                raise importer.ScopeImportError(f"cannot read {args.csv}: {exc}") from exc
            official = importer.from_hackerone_csv(text, args.handle)
        else:
            official = importer.fetch_official(args.platform, args.handle)
        slug = args.engagement or f"{official.platform}-{official.handle}"
        roe, program, rejected = importer.build_documents(
            official,
            engagement=slug,
            rps=args.rps,
            port_scan=args.port_scan,
            imported_by=getpass.getuser(),
        )
    except importer.ScopeImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    _validate(roe)
    print(f"program:  {official.platform}/{official.handle}  {official.url}")
    print(f"source:   {official.source}")
    print(f"engagement {slug!r}:")
    print(_summary(roe))
    limit = program["rate_limit"]
    print(f"  rate limit:    {limit['requests_per_second']} req/s ({limit['basis']})")
    print(
        f"  pipeline:      {'passive sources only' if roe['pipeline']['passive_only'] else 'active'}"
        f", port scan {'on' if roe['pipeline']['port_scan'] else 'off'}"
    )
    print("  approvals:     every state-changing request; every report before release")
    print("  banned:")
    for entry in program["banned_techniques"]:
        print(f"    - {entry['rule']}")
    if official.non_network_assets:
        print(f"  not network targets (ignored): {', '.join(official.non_network_assets)}")
    for item in rejected:
        print(f"  REJECTED from scope: {item['asset']} ({item['reason']})")
    if not _confirm("Enforce this program scope?", args.yes):
        print("not approved; nothing changed", file=sys.stderr)
        return EXIT_CONFIG
    path = _install(control, slug, roe, official.source)
    program_path = path.parent / PROGRAM_FILE
    tmp = program_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(program, indent=2) + "\n", encoding="utf-8")
    tmp.replace(program_path)
    print(f"enforced scope written: {path}")
    print(f"program record written: {program_path}")
    return EXIT_OK


def _load(path: Path) -> dict[str, Any] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise SystemExit(f"error: {path} is not a JSON object")
    return document


def _summary(document: dict[str, Any]) -> str:
    block = document.get("machine_enforcement") or {}

    def _items(key: str) -> list[str]:
        out = []
        for entry in block.get(key) or []:
            out.append(str(entry.get("target")) if isinstance(entry, dict) else str(entry))
        return out

    lines = [
        f"  mode:          {block.get('mode', 'audit')}",
        f"  in scope:      {', '.join(_items('in_scope')) or '(none - nothing is constrained)'}",
        f"  out of scope:  {', '.join(_items('out_of_scope')) or '(none)'}",
        f"  forbidden:     {', '.join(_items('forbidden_destinations')) or '(defaults)'}",
    ]
    if block.get("sandbox_egress") == "blocked":
        lines.append(
            "  agent shell:   no network path to targets (gateway, browser, pipeline only)"
        )
    if block.get("min_inter_request_delay_ms"):
        lines.append(
            f"  min delay:     {block['min_inter_request_delay_ms']} ms between gated calls"
        )
    if block.get("max_concurrent_connections"):
        lines.append(f"  concurrency:   {block['max_concurrent_connections']}")
    return "\n".join(lines)


def _validate(document: dict[str, Any]) -> None:
    # From buggy_core, where they are defined: the middleware module needs the
    # agent framework and this command also runs from the slim pipeline image.
    from buggy_core.types.roe_document import InvalidRoEError, parse_roe_document

    try:
        rules = parse_roe_document(document, required=True)
    except InvalidRoEError as exc:
        raise SystemExit(f"error: scope rejected: {exc}") from exc
    if rules.mode.value == "enforce" and not rules.in_scope:
        raise SystemExit(
            "error: scope rejected: enforce mode with an empty in_scope list constrains "
            "nothing. List the in-scope targets explicitly."
        )


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("error: confirmation required; re-run with --yes", file=sys.stderr)
        return False
    return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}


def _install(control: Path, slug: str, document: dict[str, Any], source: str) -> Path:
    stamped = dict(document)
    stamped["approved"] = {
        "by": getpass.getuser(),
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "source": source,
    }
    return _paths.write_control_roe(control, slug, stamped)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    workspace = _paths.workspace_root(args.workspace_root)
    control = _paths.control_root(args.control_root)
    if args.command == "import":
        return _import_program(args, control)
    slug = args.engagement
    draft_path = workspace / slug / "plan" / "roe.json"
    enforced_path = control / slug / "roe.json"

    if args.command == "show":
        enforced = _load(enforced_path)
        if enforced is not None:
            print(f"enforced scope ({enforced_path}):")
            print(_summary(enforced))
            return EXIT_OK
        draft = _load(draft_path)
        if draft is None:
            print(f"no scope for {slug!r}: neither {enforced_path} nor {draft_path} exists")
            return EXIT_CONFIG
        print(f"NOT ENFORCED - draft only ({draft_path}):")
        print(_summary(draft))
        print(f"\npromote it with: buggy-cli scope approve {slug}")
        return EXIT_OK

    if args.command == "diff":
        draft, enforced = _load(draft_path), _load(enforced_path)
        if draft is None:
            print(f"no draft at {draft_path}")
            return EXIT_CONFIG
        a = (enforced or {}).get("machine_enforcement")
        b = draft.get("machine_enforcement")
        if a == b:
            print("draft and enforced scope are identical")
            return EXIT_OK
        print("enforced:" if enforced else "enforced: (none)")
        if enforced:
            print(_summary(enforced))
        print("draft:")
        print(_summary(draft))
        return 1

    if args.command == "approve":
        document = _load(draft_path)
        if document is None:
            print(f"error: no draft at {draft_path}", file=sys.stderr)
            return EXIT_CONFIG
        source = str(draft_path)
    else:  # set
        document = _load(args.file)
        if document is None:
            print(f"error: {args.file} does not exist", file=sys.stderr)
            return EXIT_CONFIG
        source = str(args.file)

    _validate(document)
    from buggy.program.gate import mode_error
    from buggy.program.record import load_program

    program = load_program(control, slug)
    if program is not None:
        mode = str((document.get("machine_enforcement") or {}).get("mode", "audit"))
        problem = mode_error(program, mode)
        if problem is not None:
            print(f"error: scope rejected: {problem}", file=sys.stderr)
            return EXIT_CONFIG
        print(
            "warning: this engagement was imported from a bounty program; hand-edited scope "
            "replaces the official one. Prefer `buggy-cli scope import`.",
            file=sys.stderr,
        )
    print(f"scope for {slug!r} (from {source}):")
    print(_summary(document))
    if not _confirm("Enforce this scope?", args.yes):
        print("not approved; nothing changed", file=sys.stderr)
        return EXIT_CONFIG
    path = _install(control, slug, document, source)
    print(f"enforced scope written: {path}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
