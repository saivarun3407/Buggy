"""``python -m buggy.cli`` dispatcher."""

from __future__ import annotations

import sys

# Every command is imported inside its own branch. Some commands need the
# agent framework; the slim pipeline image does not have it, and must still be
# able to run the others (hunt, scope, approvals, status, doctor).


def _print_help() -> int:
    print(
        "buggy-cli — headless / CI entry\n\n"
        "Subcommands:\n"
        "  hunt               Start a hunt against a target in one command (simple)\n"
        "  bounty             Start a HackerOne / Bugcrowd bounty via the Scout flow\n"
        "  engage             Start an authorized engagement from target + scope lists\n"
        "  scan               Run a one-shot security scan and emit SARIF\n"
        "  assessment         Track web/API inventory and evidence-backed coverage\n"
        "  workflows          Inspect capabilities and run bounded defensive workflows\n"
        "  auth               Show provider/auth configuration (API keys + subscriptions)\n\n"
        "  pipeline           Run / inspect the deterministic recon pipeline\n"
        "  scope              Show / approve the enforced scope (operator only)\n"
        "  approvals          List and answer the agent's approval requests\n"
        "  audit              Verify engagement audit ledgers\n"
        "  zip                Export/import engagement workspaces as ZIP archives\n\n"
        "  export-transcript  Render an engagement event log as Markdown\n\n"
        "  telemetry          Inspect/control usage telemetry (status|preview|off|on)\n\n"
        "Run a subcommand with --help for its flags.",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] in {"-h", "--help"}:
        return _print_help()
    sub = args[0]
    rest = args[1:]
    if sub == "hunt":
        from buggy.cli.hunt import main as hunt_main

        return hunt_main(rest)
    if sub == "bounty":
        from buggy.cli.bounty import main as bounty_main

        return bounty_main(rest)
    if sub == "engage":
        from buggy.cli.engage import main as engage_main

        return engage_main(rest)
    if sub == "pipeline":
        from buggy.pipeline.cli import main as pipeline_main

        return pipeline_main(rest)
    if sub == "scope":
        from buggy.cli.scope import main as scope_main

        return scope_main(rest)
    if sub == "approvals":
        from buggy.cli.approvals import main as approvals_main

        return approvals_main(rest)
    if sub == "assessment":
        from buggy.cli.assessment import main as assessment_main

        return assessment_main(rest)
    if sub == "workflows":
        from buggy.cli.workflows import main as workflows_main

        return workflows_main(rest)
    if sub == "scan":
        from buggy.cli.scan import main as scan_main

        return scan_main(rest)
    if sub == "auth":
        from buggy.cli.auth import main as auth_main

        return auth_main(rest)
    if sub == "audit":
        from buggy.cli.audit import main as audit_main

        return audit_main(rest)
    if sub == "zip":
        from buggy.cli.zip import main as zip_main

        return zip_main(rest)
    if sub == "export-transcript":
        from buggy.cli.export_transcript import main as export_transcript_main

        return export_transcript_main(rest)
    if sub == "telemetry":
        from buggy.cli.telemetry import main as telemetry_main

        return telemetry_main(rest)
    # Any other command is a module `buggy.cli.<name>` exposing
    # `main(argv) -> int` (dashes in the command become underscores), so a new
    # command is one new file and never an edit here.
    module_name = sub.replace("-", "_")
    if module_name.isidentifier() and not module_name.startswith("_"):
        import importlib

        try:
            module = importlib.import_module(f"buggy.cli.{module_name}")
        except ModuleNotFoundError as exc:
            if exc.name != f"buggy.cli.{module_name}":
                raise
        else:
            entry = getattr(module, "main", None)
            if callable(entry):
                return int(entry(rest) or 0)
    print(f"unknown subcommand: {sub}\n", file=sys.stderr)
    _print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
