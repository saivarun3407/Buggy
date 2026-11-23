"""``python -m benchmark.lab`` — lab scope, baselines and the comparison table.

scope             --engagement lab [--apps juice-shop,dvga]   write the lab RoE
pipeline-baseline --engagement lab [--apps ...]               score the recon store
agent-run         --engagement lab-a --arm with-pipeline      run one agent arm
report            [--results DIR]                             build the table
ground-truth                                                   list known entries
coverage          [--apps ...] [--write]                      one verdict per known bug
evaluate          --engagement E --control-root C --audit-root A --data-root D
                                                              stage scores of one hunt run
verify            DIR                                          re-check a stage-eval directory
compare           DIR_A DIR_B [--write DIR]                    two evaluated runs side by side
plain-agent       --engagement E --apps ... --tool-budget N   plain-agent baseline (prints
                                                              the plan; --execute runs it)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from benchmark.lab import lab, scorer

RESULTS = Path(__file__).parent / "results"


def _home() -> Path:
    return Path(os.environ.get("BUGGY_HOME") or Path.home() / ".buggy")


def _apps(raw: str) -> list[str]:
    names = [name.strip() for name in raw.split(",") if name.strip()]
    unknown = [n for n in names if n not in lab.APPS]
    if unknown:
        raise SystemExit(f"unknown lab app(s): {unknown}; available: {sorted(lab.APPS)}")
    return names


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m benchmark.lab", description=(__doc__ or "").split("\n\n")[0]
    )
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("scope", "pipeline-baseline", "agent-run"):
        s = sub.add_parser(name)
        s.add_argument("--engagement", required=True)
        s.add_argument("--apps", default="juice-shop,dvga")
        s.add_argument("--control-root", type=Path, default=None)
        if name == "pipeline-baseline":
            s.add_argument("--data-root", type=Path, required=True, help="Recon store directory.")
            s.add_argument("--out", type=Path, default=None)
        if name == "agent-run":
            s.add_argument("--arm", required=True, choices=["with-pipeline", "without-pipeline"])
            s.add_argument("--workspace-root", type=Path, default=None)
            s.add_argument(
                "--langgraph-url", default=os.environ.get("BUGGY_API_URL", "http://localhost:2024")
            )
            s.add_argument(
                "--litellm-url", default=os.environ.get("LITELLM_URL", "http://localhost:4000")
            )
            s.add_argument("--timeout", type=int, default=7200)
            s.add_argument("--out", type=Path, default=None)
    report = sub.add_parser("report")
    report.add_argument("--results", type=Path, default=RESULTS)
    report.add_argument("--apps", default="juice-shop,dvga")
    sub.add_parser("ground-truth")
    coverage_cmd = sub.add_parser("coverage")
    coverage_cmd.add_argument(
        "--apps", default=None, help="Comma-separated; default: every app with ground truth."
    )
    coverage_cmd.add_argument("--write", action="store_true", help="Also save results/coverage.md.")

    ev = sub.add_parser("evaluate", help="Stage-level scores of one finished hunt run.")
    ev.add_argument("--engagement", required=True)
    ev.add_argument("--control-root", type=Path, required=True)
    ev.add_argument("--audit-root", type=Path, required=True)
    ev.add_argument(
        "--data-root",
        type=Path,
        required=True,
        help="Folder with recon.sqlite3 and findings.sqlite3 (and captures.sqlite3 if present).",
    )
    ev.add_argument("--apps", default=None, help="Default: the lab apps the scope names.")
    ev.add_argument("--run-id", default=None, help="Default: <hunt date>-<engagement>.")
    ev.add_argument("--results", type=Path, default=RESULTS)
    ev.add_argument("--bridge-log", type=Path, default=None, help="Agent bridge call log (JSONL).")
    ev.add_argument("--arm", default="", help="Label of this arm, e.g. buggy or plain-agent.")
    ev.add_argument("--model", default="", help="Model the agent stage used, as you state it.")
    ev.add_argument("--tool-budget", type=int, default=None, help="Agent tool-call cap.")
    ev.add_argument(
        "--scoreboard",
        default="auto",
        help="Juice Shop scoreboard: auto (the lab host, if it runs), off, or a base URL.",
    )
    vf = sub.add_parser("verify", help="Re-check a stage-evaluation or comparison directory.")
    vf.add_argument("directory", type=Path)
    cmp = sub.add_parser("compare", help="Two evaluated runs side by side.")
    cmp.add_argument("first", type=Path)
    cmp.add_argument("second", type=Path)
    cmp.add_argument("--write", type=Path, default=None, help="Save COMPARISON.md in this folder.")
    pa = sub.add_parser("plain-agent", help="The plain-agent baseline arm (prints its plan).")
    pa.add_argument("--engagement", required=True)
    pa.add_argument("--apps", default="juice-shop")
    pa.add_argument("--tool-budget", type=int, required=True, help="Same cap as the Buggy arm.")
    pa.add_argument("--model", default="")
    pa.add_argument("--compose", default=None, help="Compose command the stack was started with.")
    pa.add_argument("--control-root", type=Path, default=None)
    pa.add_argument("--audit-root", type=Path, default=None)
    pa.add_argument("--data-root", type=Path, default=None)
    pa.add_argument(
        "--execute", action="store_true", help="Write the scope and run Claude Code now."
    )
    return p


def _write(result: dict, out: Path | None, default_name: str) -> Path:
    target = out or RESULTS / default_name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return target


def _revision() -> str:
    """Short HEAD of this checkout, marked when the evaluator's files differ from it."""
    root = Path(__file__).resolve().parents[2]

    def git(*args: str) -> str:
        done = subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()

    try:
        head = git("rev-parse", "--short", "HEAD")
        dirty = git(
            "status", "--porcelain", "--", "benchmark/lab/*.py", "benchmark/lab/ground_truth"
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return f"{head} (with uncommitted changes)" if dirty else head


def _stage_commands(args: argparse.Namespace) -> int:
    from benchmark.lab import baseline, evaluate  # noqa: PLC0415

    if args.command == "verify":
        problems = evaluate.verify_run(args.directory)
        for problem in problems:
            print(f"FAIL {problem}")
        if problems:
            return 1
        print(f"OK {args.directory}")
        return 0

    if args.command == "compare":
        try:
            if args.write:
                path = evaluate.write_comparison(args.write, args.first, args.second)
                print(path.read_text(encoding="utf-8"), end="")
                print(f"\nwrote {path}")
                return 0
            pairs = [
                (
                    json.loads((d / evaluate.EVALUATION_FILE).read_text(encoding="utf-8")),
                    json.loads((d / evaluate.MANIFEST_FILE).read_text(encoding="utf-8")),
                )
                for d in (args.first, args.second)
            ]
            print(evaluate.render_comparison(*pairs), end="")
        except (evaluate.EvaluationError, OSError, ValueError) as exc:
            print(f"compare failed: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "plain-agent":
        apps = _apps(args.apps)
        home = _home()
        control = args.control_root or home / "control"
        steps = baseline.plan(
            args.engagement,
            apps,
            tool_budget=args.tool_budget,
            control_root=control,
            audit_root=args.audit_root or home / "audit",
            data_root=args.data_root or Path("<recon and capture data folder>"),
            compose=args.compose or baseline.DEFAULT_COMPOSE,
            model=args.model,
        )
        print(baseline.render_plan(steps), end="")
        if not args.execute:
            print("# Not run: pass --execute to write the scope and start Claude Code.")
            return 0
        return baseline.run(steps, control_root=control)

    # evaluate
    apps = _apps(args.apps) if args.apps else None
    try:
        inputs, files = evaluate.collect(
            args.engagement,
            control_root=args.control_root,
            audit_root=args.audit_root,
            data_root=args.data_root,
            apps=apps,
            bridge_log=args.bridge_log,
            arm=args.arm,
            model=args.model,
            tool_budget=args.tool_budget,
            scoreboard=args.scoreboard,
        )
        finished = inputs["hunt"].get("finished_at")
        day = time.strftime(
            "%Y-%m-%d", time.gmtime(finished if isinstance(finished, int | float) else None)
        )
        run_id = args.run_id or f"{day}-{args.engagement}"
        path = evaluate.write_run(
            Path(args.results) / run_id,
            inputs,
            files,
            run_id=run_id,
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            revision=_revision(),
        )
    except evaluate.EvaluationError as exc:
        print(f"evaluate failed: {exc}", file=sys.stderr)
        return 2
    print(path.read_text(encoding="utf-8"), end="")
    print(f"\nwrote {path.parent}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "ground-truth":
        for app in scorer.available_apps():
            entries = scorer.load_ground_truth(app)
            verified = sum(1 for e in entries if e.verified_by)
            print(f"{app}: {len(entries)} entries, {verified} reproduced by a lab test")
            for entry in entries:
                mark = "x" if entry.verified_by else " "
                flag = " (prohibited)" if entry.prohibited else ""
                print(f"  [{mark}] {entry.cls:16} {entry.id:34} {entry.title}{flag}")
        return 0

    if args.command == "coverage":
        from benchmark.lab import coverage

        known = scorer.available_apps()
        names = (
            known if args.apps is None else [a.strip() for a in args.apps.split(",") if a.strip()]
        )
        unknown = [n for n in names if n not in known]
        if unknown or not names:
            raise SystemExit(f"unknown lab app(s): {unknown or names}; available: {known}")
        try:
            result = coverage.audit(names)
        except coverage.AuditError as exc:
            print(f"coverage audit failed: {exc}", file=sys.stderr)
            return 2
        text = coverage.render(
            result, date=time.strftime("%Y-%m-%d"), revision=coverage.git_revision()
        )
        print(text, end="")
        if args.write:
            coverage.COVERAGE_MD.parent.mkdir(parents=True, exist_ok=True)
            coverage.COVERAGE_MD.write_text(text, encoding="utf-8")
            print(f"\nwrote {coverage.COVERAGE_MD}")
        return 0

    if args.command in ("evaluate", "verify", "compare", "plain-agent"):
        return _stage_commands(args)

    if args.command == "report":
        apps = _apps(args.apps)
        columns: dict[str, dict | None] = {
            "pipeline only": None,
            "probes (lab-tested)": lab.score_probe_coverage(apps),
            "agent + pipeline": None,
            "agent, no pipeline": None,
        }
        labels = {
            "pipeline": "pipeline only",
            "agent:with-pipeline": "agent + pipeline",
            "agent:without-pipeline": "agent, no pipeline",
        }
        for path in sorted(Path(args.results).glob("*.json")):
            data = json.loads(path.read_text())
            if data.get("baseline") in labels:
                columns[labels[data["baseline"]]] = data
        print(lab.render_table(columns, apps))
        print()
        print("| Baseline | Seconds | LLM calls | Tokens | Cost (USD) |")
        print("|---|---:|---:|---:|---:|")
        for label, data in columns.items():
            if data is None:
                print(f"| {label} | not run | not run | not run | not run |")
                continue
            if data.get("baseline") == "probes":
                print(f"| {label} | see lab tests | 0 | 0 | 0.0 |")
                continue
            usage = data.get("usage") or data
            print(
                f"| {label} | {data.get('seconds', '?')} | {usage.get('llm_calls', 0)} | "
                f"{usage.get('tokens', 0)} | {usage.get('cost_usd', 0)} |"
            )
        return 0

    apps = _apps(args.apps)
    control = args.control_root or _home() / "control"

    if args.command == "scope":
        print(lab.write_scope(control, args.engagement, apps))
        return 0

    if args.command == "pipeline-baseline":
        records, run = lab.load_store_records(args.data_root, args.engagement)
        if run is None:
            print("no pipeline run for this engagement; run the pipeline first", file=sys.stderr)
            return 2
        result = lab.score_pipeline_records(records, apps, run=run)
        result["engagement"] = args.engagement
        path = _write(result, args.out, f"{time.strftime('%Y-%m-%d')}-pipeline.json")
        print(lab.render_table({"pipeline only": result}, apps))
        print(f"\nwrote {path}")
        return 0

    # agent-run
    if not lab.lab_env_ready():
        print(
            "no model provider key in the environment; the agent arms cannot run. "
            "Configure the stack (buggy onboard) and export the key first.",
            file=sys.stderr,
        )
        return 2
    from benchmark.lab import agent

    result = agent.run_arm(
        args.engagement,
        apps,
        args.arm,
        control_root=control,
        workspace_root=args.workspace_root or _home() / "workspace",
        langgraph_url=args.langgraph_url,
        litellm_url=args.litellm_url,
        timeout_seconds=args.timeout,
    )
    path = _write(result, args.out, f"{time.strftime('%Y-%m-%d')}-agent-{args.arm}.json")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
