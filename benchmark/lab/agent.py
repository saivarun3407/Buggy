"""Agent arms of the lab baseline: with and without the pipeline's data.

Not runnable without a model provider configured for the stack. Each arm is
a separate engagement so nothing carries over between them:

``with-pipeline``     the pipeline runs first; the agent is told recon data is
                      available through the ``recon_*`` tools.
``without-pipeline``  every pipeline stage is disabled for the engagement, so
                      the recon store is empty and the agent does its own recon.

Cost and tokens come from LiteLLM's spend log for the run's time window, so
they include every sub-agent call.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from benchmark.lab import lab

ARMS = ("with-pipeline", "without-pipeline")
ALL_STAGES = ["enumerate", "dns", "live", "fingerprint", "urls", "apispec", "issues"]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def spend_between(start: float, end: float, *, litellm_url: str, master_key: str) -> dict[str, Any]:
    """Sum spend and tokens from LiteLLM ``/spend/logs`` for ``[start, end]``."""
    query = urlencode({"start_date": _iso(start), "end_date": _iso(end)})
    request = urllib.request.Request(  # noqa: S310 - operator-configured LiteLLM URL
        f"{litellm_url.rstrip('/')}/spend/logs?{query}",
        headers={"Authorization": f"Bearer {master_key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            rows = json.loads(response.read())
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return {"error": f"spend log unavailable: {exc}"}
    if not isinstance(rows, list):
        return {"error": "spend log returned an unexpected payload"}
    totals = {"llm_calls": 0, "cost_usd": 0.0, "prompt_tokens": 0, "completion_tokens": 0}
    for row in rows:
        if not isinstance(row, dict):
            continue
        totals["llm_calls"] += 1
        totals["cost_usd"] += float(row.get("spend") or 0)
        totals["prompt_tokens"] += int(row.get("prompt_tokens") or 0)
        totals["completion_tokens"] += int(row.get("completion_tokens") or 0)
    totals["cost_usd"] = round(totals["cost_usd"], 4)
    totals["tokens"] = totals["prompt_tokens"] + totals["completion_tokens"]
    return totals


def arm_roe(engagement: str, apps: list[str], arm: str) -> dict[str, Any]:
    if arm not in ARMS:
        raise ValueError(f"arm must be one of {ARMS}")
    roe = lab.lab_roe(engagement, apps)
    if arm == "without-pipeline":
        roe["pipeline"]["disabled_stages"] = list(ALL_STAGES)
    return roe


def kickoff_text(engagement: str, apps: list[str], arm: str) -> str:
    targets = ", ".join(lab.APPS[name].url for name in apps)
    recon = (
        "Deterministic recon has already run: query it with the recon_* tools "
        "(start with recon_summary) and do not repeat enumeration, crawling or scanning yourself."
        if arm == "with-pipeline"
        else "No recon data exists for this engagement; perform your own reconnaissance."
    )
    return (
        f"Begin authorized lab engagement '{engagement}'. Targets: {targets}. "
        "These are local intentionally-vulnerable training applications. The enforced scope "
        "lists exactly these hosts. " + recon + " Find as many distinct vulnerabilities as you "
        "can across authentication, access control, SSRF, business logic, API and GraphQL "
        "weaknesses, injection and XSS. Record every confirmed finding with "
        "emit_structured_finding (include cwe, endpoint and method). Do not attempt denial of "
        "service."
    )


def run_arm(
    engagement: str,
    apps: list[str],
    arm: str,
    *,
    control_root: Path,
    workspace_root: Path,
    langgraph_url: str,
    litellm_url: str,
    timeout_seconds: int,
    assistant: str = "buggy",
) -> dict[str, Any]:
    """Run one arm end to end and return its scored result."""
    from buggy.cli.engage import _stream_kickoff  # noqa: PLC0415 - needs the framework

    directory = Path(control_root) / engagement
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "roe.json").write_text(json.dumps(arm_roe(engagement, apps, arm), indent=2) + "\n")
    started = time.time()
    error = ""
    try:
        _stream_kickoff(
            langgraph_url=langgraph_url,
            assistant=assistant,
            engagement_name=engagement,
            kickoff=kickoff_text(engagement, apps, arm),
            timeout_seconds=timeout_seconds,
            non_interactive=True,
        )
    except Exception as exc:  # noqa: BLE001 - recorded in the result
        error = f"{type(exc).__name__}: {exc}"
    finished = time.time()
    result = lab.score_agent_findings(Path(workspace_root) / engagement / "findings", apps)
    result.update(
        {
            "baseline": f"agent:{arm}",
            "engagement": engagement,
            "seconds": round(finished - started, 1),
            "usage": spend_between(
                started,
                finished,
                litellm_url=litellm_url,
                master_key=os.environ.get("LITELLM_MASTER_KEY", ""),
            ),
        }
    )
    if error:
        result["error"] = error
    return result


__all__ = ["ALL_STAGES", "ARMS", "arm_roe", "kickoff_text", "run_arm", "spend_between"]
