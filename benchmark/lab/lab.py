"""Lab definitions, scope generation, and the two baselines.

Two baselines are measured against the same ground truth:

``pipeline``  what the deterministic Phase 2 pipeline surfaces with no agent
              and no model call. Runs anywhere the lab runs.
``agent``     what the agent finds, in two arms: with the pipeline's data
              available over MCP, and without it. Needs a model provider
              configured for the stack.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmark.lab import scorer
from benchmark.lab.taxonomy import CLASSES, DESCRIPTIONS


@dataclass(frozen=True, slots=True)
class LabApp:
    name: str
    host: str
    port: int
    base_path: str = "/"

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}{self.base_path}"


APPS: dict[str, LabApp] = {
    "juice-shop": LabApp("juice-shop", "juice-shop.lab", 3000),
    "dvga": LabApp("dvga", "dvga.lab", 5013),
    "dvwa": LabApp("dvwa", "dvwa.lab", 80),
}

LAB_SUFFIX = ".lab"


def lab_roe(engagement: str, apps: list[str]) -> dict[str, Any]:
    """An enforce-mode RoE whose scope is exactly the chosen lab hostnames."""
    chosen = [APPS[name] for name in apps]
    for app in chosen:
        if not app.host.endswith(LAB_SUFFIX):
            raise ValueError(f"{app.host} is not a lab hostname")
    return {
        "version": 1,
        "engagement_name": engagement,
        "generated_by": "benchmark.lab",
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "authorization": "Local intentionally-vulnerable containers on the operator's own host.",
        "machine_enforcement": {
            "mode": "enforce",
            "in_scope": [app.host for app in chosen],
            "out_of_scope": [],
            "forbidden_command_patterns": [],
        },
        "pipeline": {
            "ports": ",".join(str(p) for p in sorted({app.port for app in chosen})),
            "rate_limit_rps": 50,
            "concurrency": 10,
            "crawl_depth": 2,
            "nuclei_severities": ["info", "low", "medium", "high", "critical"],
            # DVGA switches into its hardened mode on a plain GET link.
            "crawl_exclude": ["/difficulty/"],
        },
        # Local training targets: state-changing requests need no sign-off,
        # and the lab hostnames resolve to private addresses by design.
        "approvals": {"state_changing": "not_required"},
        "network": {"allow_private_targets": True},
    }


def write_scope(control_root: Path, engagement: str, apps: list[str]) -> Path:
    """Write the lab RoE as the engagement's enforced scope."""
    directory = Path(control_root) / engagement
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "roe.json"
    path.write_text(json.dumps(lab_roe(engagement, apps), indent=2) + "\n", encoding="utf-8")
    return path


def _records_for(records: list[dict[str, Any]], app: LabApp) -> list[dict[str, Any]]:
    return [r for r in records if r.get("asset") == app.host]


def score_pipeline_records(
    records: list[dict[str, Any]], apps: list[str], *, run: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Score recon-store records (as dicts) against each app's ground truth."""
    result: dict[str, Any] = {
        "baseline": "pipeline",
        "apps": {},
        "llm_calls": 0,
        "tokens": 0,
        "cost_usd": 0.0,
    }
    if run:
        result["run_id"] = run.get("id") or run.get("run_id")
        started, finished = run.get("started_at"), run.get("finished_at")
        if started and finished:
            result["seconds"] = round(float(finished) - float(started), 1)
        result["tool_versions"] = (run.get("stats") or run).get("tool_versions", {})
    for name in apps:
        app = APPS[name]
        own = _records_for(records, app)
        scores = scorer.score_pipeline(own, scorer.load_ground_truth(name))
        result["apps"][name] = {
            "records": len(own),
            "classes": {cls: s.to_dict() for cls, s in scores.items()},
            "totals": scorer.totals(scores),
        }
    return result


def load_store_records(
    data_root: Path, engagement: str
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    from buggy.pipeline import service
    from buggy.pipeline.store import ReconStore

    store = ReconStore(Path(data_root) / service.STORE_FILE, read_only=True)
    try:
        records: list[dict[str, Any]] = []
        offset = 0
        while True:
            page = store.query_records(engagement, limit=1000, offset=offset)
            records.extend(r.to_dict() for r in page)
            if len(page) < 1000:
                break
            offset += 1000
        return records, store.latest_run(engagement)
    finally:
        store.close()


def score_agent_findings(findings_dir: Path, apps: list[str]) -> dict[str, Any]:
    """Score ``FIND-*.json`` findings against each app's ground truth by endpoint host."""
    findings = scorer.findings_from_structured(findings_dir)
    result: dict[str, Any] = {"apps": {}}
    for name in apps:
        app = APPS[name]
        own = [f for f in findings if app.host in f.endpoint or not f.endpoint]
        scores = scorer.score(own, scorer.load_ground_truth(name))
        result["apps"][name] = {
            "findings": len(own),
            "classes": {cls: s.to_dict() for cls, s in scores.items()},
            "totals": scorer.totals(scores),
        }
    return result


# ── reporting ────────────────────────────────────────────────────────


def _cell(score: dict[str, Any] | None) -> str:
    if not score or not score.get("known"):
        return "–"
    return f"{score['found']}/{score['known']}"


def score_probe_coverage(apps: list[str]) -> dict[str, Any]:
    """Known bugs a deterministic probe is proven to find, as a scored result.

    An entry counts only when its ``verified_by`` names a lab test, i.e. the
    probe was run against the real application and the test asserts the bug is
    reported. No LLM is involved, so the cost columns are zero.
    """
    out: dict[str, Any] = {"baseline": "probes", "apps": {}, "llm_calls": 0, "tokens": 0}
    out["cost_usd"] = 0.0
    for name in apps:
        classes: dict[str, dict[str, Any]] = {}
        for entry in scorer.load_ground_truth(name):
            if entry.prohibited:
                continue
            bucket = classes.setdefault(
                entry.cls, {"known": 0, "found": 0, "missed": 0, "found_ids": [], "missed_ids": []}
            )
            bucket["known"] += 1
            if entry.verified_by:
                bucket["found"] += 1
                bucket["found_ids"].append(entry.id)
            else:
                bucket["missed"] += 1
                bucket["missed_ids"].append(entry.id)
        out["apps"][name] = {"classes": classes}
    return out


def render_table(results: Mapping[str, dict[str, Any] | None], apps: list[str]) -> str:
    """Markdown: one row per class, ``found/known`` per baseline, summed over apps.

    ``results`` maps a column label to a scored result; a value of ``None`` in
    place of a result renders the column as "not run".
    """
    labels = list(results)
    lines = [
        "| Class | Known | " + " | ".join(labels) + " |",
        "|---|---:|" + "|".join(":---:" for _ in labels) + "|",
    ]
    for cls in CLASSES:
        known = 0
        for name in apps:
            known += sum(
                1 for e in scorer.load_ground_truth(name) if e.cls == cls and not e.prohibited
            )
        if not known:
            continue
        cells = []
        for label in labels:
            result = results[label]
            if result is None:
                cells.append("not run")
                continue
            found = sum(
                (result["apps"].get(name, {}).get("classes", {}).get(cls) or {}).get("found", 0)
                for name in apps
            )
            cells.append(f"{found}/{known}")
        lines.append(f"| {cls} | {known} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("Classes: " + "; ".join(f"`{c}` = {DESCRIPTIONS[c]}" for c in CLASSES))
    return "\n".join(lines)


def lab_env_ready() -> bool:
    """Whether a model provider is configured for the agent arms."""
    keys = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY")
    return any(os.environ.get(k) for k in keys)


__all__ = [
    "APPS",
    "LabApp",
    "lab_env_ready",
    "lab_roe",
    "load_store_records",
    "render_table",
    "score_agent_findings",
    "score_pipeline_records",
    "write_scope",
]
