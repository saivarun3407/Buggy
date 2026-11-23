"""Plain-agent baseline arm: Claude Code with ``http_send`` and the finding tools only.

The question it answers: does Buggy (recon, leads, probes, recipes, skills) find
more than a plain coding agent given the same targets and the same tool-call
budget? The plain arm gets:

- the lab scope (``benchmark.lab scope``) and nothing else: no recon run, no
  probe sweep, no leads;
- the agent bridge with ``BUGGY_AGENT_PROFILE=plain``: ``http_send``,
  ``http_capture`` and the finding tools (``finding_submit``, ``finding_verify``,
  ``finding_get``, ``findings_list``), no probes, recipes, browser, recon,
  skills or web, and a brief with the rules, the budget and the targets only;
- the same tool-call cap (``BUGGY_MAX_TOOL_CALLS``) as the Buggy arm it is
  compared with, and the same model when one is named.

Every request still goes through the evidence gateway, and a finding still
counts only after the verifier re-proves it, so both arms are scored by the
same evaluator (``benchmark.lab evaluate``) and compared with ``compare``.

``plan`` only builds the commands. ``run`` executes them and needs the full
stack running with the lab apps up and Claude Code signed in; it sends
requests to the lab apps, so it is never run by a test.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from benchmark.lab import lab

ARM = "plain-agent"
DEFAULT_COMPOSE = (
    "docker compose -p buggy-full -f docker-compose.yml -f docker-compose.lab.yml "
    "--env-file .env --profile operator"
)
PROMPT = (
    "Call the engagement_brief tool of the buggy server, then test the targets it names "
    "using only that server's tools. Stop when the tools tell you to stop or you have nothing "
    "left to test, then give your final summary."
)
# The same system prompt the launcher gives the Buggy arm's Claude Code run.
SYSTEM = (
    "You are running unattended as the testing agent of an authorized security engagement. "
    "The buggy tool server enforces the scope and holds anything state-changing for the "
    "operator; treat every refusal as final and never ask for approval or credentials."
)


def plan(
    engagement: str,
    apps: list[str],
    *,
    tool_budget: int,
    control_root: Path,
    audit_root: Path,
    data_root: Path,
    compose: str = DEFAULT_COMPOSE,
    model: str = "",
) -> dict[str, Any]:
    """Every file and command of one plain-agent run, without running anything."""
    if tool_budget <= 0:
        raise ValueError("the tool-call budget must be positive")
    unknown = [a for a in apps if a not in lab.APPS]
    if unknown or not apps:
        raise ValueError(f"unknown lab app(s): {unknown or apps}; available: {sorted(lab.APPS)}")
    bridge = [
        *shlex.split(compose),
        "run",
        "--rm",
        "-T",
        "-e",
        "BUGGY_AGENT_PROFILE=plain",
        "-e",
        "BUGGY_AGENT_WEB=off",
        "-e",
        f"BUGGY_MAX_TOOL_CALLS={tool_budget}",
        "operator",
        "python",
        "-m",
        "buggy.agent_bridge",
        "--engagement",
        engagement,
    ]
    claude = [
        "claude",
        "-p",
        PROMPT,
        "--mcp-config",
        "{mcp_config}",
        "--strict-mcp-config",
        "--tools",
        "",
        "--allowedTools",
        "mcp__buggy",
        "--append-system-prompt",
        SYSTEM,
    ]
    if model:
        claude += ["--model", model]
    evaluate = [
        "uv",
        "run",
        "python",
        "-m",
        "benchmark.lab",
        "evaluate",
        "--engagement",
        engagement,
        "--control-root",
        str(control_root),
        "--audit-root",
        str(audit_root),
        "--data-root",
        str(data_root),
        "--arm",
        ARM,
        "--tool-budget",
        str(tool_budget),
    ]
    if model:
        evaluate += ["--model", model]
    return {
        "arm": ARM,
        "engagement": engagement,
        "apps": list(apps),
        "tool_budget": tool_budget,
        "model": model or "Claude Code's default (not recorded)",
        "scope": {
            "path": str(Path(control_root) / engagement / "roe.json"),
            "document": lab.lab_roe(engagement, apps),
        },
        "mcp_config": {"mcpServers": {"buggy": {"command": bridge[0], "args": bridge[1:]}}},
        "claude": claude,
        "evaluate": evaluate,
    }


def render_plan(steps: dict[str, Any]) -> str:
    """The plan as shell steps an operator can read and run by hand."""
    config = json.dumps(steps["mcp_config"], indent=2)
    claude = " ".join(
        shlex.quote(a) if a != "{mcp_config}" else "mcp.json" for a in steps["claude"]
    )
    return "\n".join(
        [
            f"# Plain-agent baseline for engagement {steps['engagement']} "
            f"({', '.join(steps['apps'])}); budget {steps['tool_budget']} tool calls; "
            f"model: {steps['model']}",
            "# 1. The lab scope, and nothing else (no recon, no probe sweep):",
            "uv run python -m benchmark.lab scope --engagement "
            f"{shlex.quote(steps['engagement'])} --apps {','.join(steps['apps'])}",
            "# 2. mcp.json in an empty folder (the bridge in the plain profile):",
            f"cat > mcp.json <<'EOF'\n{config}\nEOF",
            "# 3. Claude Code with no built-in tools and only the bridge:",
            claude,
            "# 4. Score it with the same evaluator as the Buggy arm:",
            " ".join(shlex.quote(a) for a in steps["evaluate"]),
            "",
        ]
    )


def run(steps: dict[str, Any], *, control_root: Path) -> int:
    """Write the scope and run Claude Code on it. Needs the stack, the lab apps and Claude Code."""
    lab.write_scope(Path(control_root), steps["engagement"], steps["apps"])
    with tempfile.TemporaryDirectory(prefix="buggy-plain-agent-") as folder:
        config = Path(folder) / "mcp.json"
        config.write_text(json.dumps(steps["mcp_config"]), encoding="utf-8")
        argv = [str(config) if a == "{mcp_config}" else a for a in steps["claude"]]
        done = subprocess.run(argv, cwd=folder, check=False)  # noqa: S603 - operator-run
    return done.returncode


__all__ = ["ARM", "DEFAULT_COMPOSE", "plan", "render_plan", "run"]
