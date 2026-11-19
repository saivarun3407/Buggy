"""``python -m benchmark.lab`` — lab scope, baselines and the comparison table.

scope             --engagement lab [--apps juice-shop,dvga]   write the lab RoE
pipeline-baseline --engagement lab [--apps ...]               score the recon store
agent-run         --engagement lab-a --arm with-pipeline      run one agent arm
report            [--results DIR]                             build the table
ground-truth                                                   list known entries
"""

from __future__ import annotations

import argparse
import json
import os
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
    return p


def _write(result: dict, out: Path | None, default_name: str) -> Path:
    target = out or RESULTS / default_name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return target


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
