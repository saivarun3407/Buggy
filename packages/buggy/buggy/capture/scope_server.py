"""MCP server: scope lookup.

What an agent may ask about scope, read-only:

``scope_show``    the enforced scope and program rules for the engagement
``scope_check``   whether one target is in scope, and why not
``program_info``  the program's official scope data as the operator imported
                  it from HackerOne / Bugcrowd (``buggy-cli scope import``)

The server holds no platform credentials and cannot change the scope. It
reads the operator-controlled root, which is mounted read-only.

Run with ``python -m buggy.capture.scope_server`` (streamable HTTP, port 9462).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from buggy.pipeline.schema import as_dict, host_of
from buggy.pipeline.scope import ScopeError, ScopeFilter

DEFAULT_PORT = 9462
TOOL_NAMES = ("scope_show", "scope_check", "program_info")

INSTRUCTIONS = (
    "Scope for the current engagement. Check a target with scope_check before planning work on "
    "it; the same rules are enforced by the tools and the network, so an out-of-scope request "
    "will not go through. program_info is the bounty program's official scope and rules."
)


def _rule_text(entry: Any) -> str:
    return str(entry.get("target")) if isinstance(entry, dict) else str(entry)


class ScopeTools:
    def __init__(self, control_root: Path, engagement: str | None = None) -> None:
        self._control = Path(control_root)
        self._bound = engagement or None

    def _dir(self, engagement: str) -> Path | None:
        name = (engagement or "").strip()
        if not name or "/" in name or name.startswith("."):
            return None
        if self._bound and name != self._bound:
            return None
        return self._control / name

    def _load(self, engagement: str) -> tuple[ScopeFilter, dict[str, Any]] | dict[str, Any]:
        directory = self._dir(engagement)
        if directory is None:
            return {"error": "unknown engagement"}
        try:
            scope = ScopeFilter.from_file(directory / "roe.json")
            document = json.loads((directory / "roe.json").read_text(encoding="utf-8"))
        except ScopeError as exc:
            return {"error": str(exc), "enforced": False}
        return scope, document

    def scope_show(self, engagement: str) -> dict[str, Any]:
        loaded = self._load(engagement)
        if isinstance(loaded, dict):
            return loaded
        scope, document = loaded
        block = as_dict(document.get("machine_enforcement"))
        limits = scope.limits
        return {
            "engagement": engagement,
            "enforced": True,
            "mode": scope.rules.mode.value,
            "scope_sha256": scope.digest,
            "in_scope": [_rule_text(e) for e in block.get("in_scope") or []],
            "out_of_scope": [_rule_text(e) for e in block.get("out_of_scope") or []],
            "forbidden_command_patterns": list(block.get("forbidden_command_patterns") or []),
            "rate_limit_rps": limits.rate_limit_rps,
            "max_concurrency": limits.concurrency,
            "passive_only": limits.passive_only,
            "state_changing_requests": str(
                as_dict(document.get("approvals")).get("state_changing", "required")
            ),
            "sandbox_network": (
                "blocked: send every request to the target with http_send, probe_run or browser_*"
                if scope.rules.sandbox_blocked
                else "scoped"
            ),
            "report_release": str(
                as_dict(document.get("approvals")).get("report_submission", "not_required")
            ),
            "banned_techniques": self._banned(engagement),
            "wildcard_note": "* covers exactly one DNS label; ** covers any depth; neither covers the apex",
        }

    def _banned(self, engagement: str) -> list[str]:
        """The program's binding rules, so they arrive with the scope itself."""
        program = self.program_info(engagement)
        return [
            str(entry.get("rule"))
            for entry in program.get("banned_techniques") or []
            if isinstance(entry, dict) and entry.get("rule")
        ]

    def scope_check(self, engagement: str, target: str) -> dict[str, Any]:
        loaded = self._load(engagement)
        if isinstance(loaded, dict):
            return {**loaded, "in_scope": False}
        scope, _document = loaded
        allowed, reason = scope.decide(target)
        return {"target": target, "host": host_of(target), "in_scope": allowed, "reason": reason}

    def program_info(self, engagement: str) -> dict[str, Any]:
        directory = self._dir(engagement)
        if directory is None:
            return {"error": "unknown engagement"}
        try:
            data = json.loads((directory / "program.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {
                "imported": False,
                "detail": "no program data was imported for this engagement "
                "(buggy-cli scope import --platform ... --handle ...)",
            }
        except (OSError, ValueError) as exc:
            return {"error": f"program data is unreadable: {exc}"}
        return {"imported": True, **(data if isinstance(data, dict) else {})}


def register_tools(mcp: Any, tools: ScopeTools) -> None:
    @mcp.tool()
    def scope_show(engagement: str) -> dict[str, Any]:
        """The enforced scope: in/out-of-scope rules, rate limits, approval and technique rules."""
        return tools.scope_show(engagement)

    @mcp.tool()
    def scope_check(engagement: str, target: str) -> dict[str, Any]:
        """Is this host, host:port or URL in the enforced scope? Returns the reason if not."""
        return tools.scope_check(engagement, target)

    @mcp.tool()
    def program_info(engagement: str) -> dict[str, Any]:
        """The bounty program's official scope data and rules as imported by the operator."""
        return tools.program_info(engagement)


def build_server(
    *, control_root: Path | None = None, host: str = "127.0.0.1", port: int = DEFAULT_PORT
) -> Any:
    from mcp.server.fastmcp import FastMCP  # noqa: PLC0415 - optional dependency

    tools = ScopeTools(
        control_root or Path(os.environ.get("BUGGY_CONTROL_ROOT") or "/control"),
        os.environ.get("BUGGY_SCOPE_ENGAGEMENT") or None,
    )
    mcp = FastMCP("buggy-scope", instructions=INSTRUCTIONS, host=host, port=port)
    register_tools(mcp, tools)
    return mcp


def main() -> None:
    host = os.environ.get("BUGGY_SCOPE_MCP_HOST", "0.0.0.0")  # noqa: S104 - container-internal
    port = int(os.environ.get("BUGGY_SCOPE_MCP_PORT") or DEFAULT_PORT)
    from buggy.pipeline.mcp_http import serve  # noqa: PLC0415

    serve(build_server(host=host, port=port), host=host, port=port)


if __name__ == "__main__":
    main()
