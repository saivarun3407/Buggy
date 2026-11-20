"""MCP server: evidence-grade HTTP (send, replay, verify) and deterministic probes.

Run with ``python -m buggy.capture.mcp_server`` (streamable HTTP, port 9461).

Environment: ``BUGGY_CONTROL_ROOT``, ``BUGGY_AUDIT_ROOT``, ``BUGGY_CAPTURE_DATA``,
``BUGGY_CAPTURE_ENGAGEMENT`` (serve one engagement only), ``BUGGY_CANARY_BIND``
(``host:port`` for the SSRF callback listener) and ``BUGGY_CANARY_BASE_URL``
(how a target reaches it).
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any

from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway, GatewayRefusal, Roots
from buggy.capture.probes import describe, run_probe
from buggy.capture.workbench import WORKBENCH_TOOL_NAMES, Workbench, register_workbench
from buggy.notify import Notifier, approval_event, finding_event

DEFAULT_PORT = 9461

INSTRUCTIONS = (
    "Evidence-grade HTTP for the current engagement. Requests sent here are scope-checked, "
    "rate-limited to the program's rules, recorded outside your reach and replayable, so a "
    "capture_id is what a finding cites as proof. Requests that can change state (anything but "
    "GET/HEAD/OPTIONS) may come back APPROVAL_REQUIRED: tell the operator and re-send the "
    "identical request once approved. probe_run performs a fixed, deterministic check "
    "(probe_list shows them); you choose the endpoint and identities, the probe does the "
    "requests and comparison and returns a verdict with capture ids; a positive result is "
    "queued as a candidate (finding_id in the result). Name a declared test account with "
    "identity=... (identities_list) and the gateway attaches its session; you never hold a "
    "credential. A claim becomes a finding only through finding_verify, which re-runs the "
    "probe or re-sends the cited captures. candidates_next is the list of leads to prove; "
    "facts_list / intent_* coordinate work with other agents; memory_search returns lessons "
    "from earlier engagements."
)

TOOL_NAMES = (
    "http_send",
    "http_replay",
    "http_capture",
    "http_captures",
    "capture_verify",
    "probe_list",
    "probe_run",
    *WORKBENCH_TOOL_NAMES,
)


def _json_arg(raw: str, name: str) -> Any:
    if not raw or not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GatewayRefusal("BAD_ARGUMENT", f"{name} is not valid JSON: {exc}") from exc


class CaptureTools:
    """Tool bodies, independent of the MCP transport (unit-testable)."""

    def __init__(
        self, gateway: CaptureGateway, canary: Canary | None = None, engagement: str | None = None
    ) -> None:
        self.gateway = gateway
        self.canary = canary
        self._bound = engagement or None
        # Set by build_server: queues positive probe results as candidates.
        self.workbench: Workbench | None = None

    def _engagement(self, engagement: str) -> str:
        name = (engagement or "").strip()
        if self._bound and name != self._bound:
            raise GatewayRefusal(
                "WRONG_ENGAGEMENT", f"this server serves engagement {self._bound!r} only"
            )
        return name

    def _guard(self, fn, *args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return fn(*args, **kwargs)
        except GatewayRefusal as refusal:
            return refusal.to_dict()

    def http_send(
        self,
        engagement: str,
        method: str,
        url: str,
        headers_json: str = "",
        body: str = "",
        note: str = "",
        identity: str = "",
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            headers = _json_arg(headers_json, "headers_json")
            if not isinstance(headers, dict):
                raise GatewayRefusal("BAD_ARGUMENT", "headers_json must be a JSON object")
            # Only the named identity is forwarded; nothing else reaches the gateway's
            # keyword arguments from here.
            capture = self.gateway.send(
                self._engagement(engagement),
                method,
                url,
                headers=headers,
                body=body or None,
                note=note,
                identity=str(identity or ""),
            )
            return {"status": "sent", **capture.detail(body_chars=6000)}

        return self._guard(run)

    def http_replay(self, engagement: str, capture_id: str) -> dict[str, Any]:
        return self._guard(
            lambda: {
                "status": "replayed",
                **self.gateway.replay(self._engagement(engagement), capture_id),
            }
        )

    def http_capture(
        self, engagement: str, capture_id: str, body_chars: int = 8000
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            capture = self.gateway.store.get(self._engagement(engagement), capture_id)
            if capture is None:
                raise GatewayRefusal(
                    "UNKNOWN_CAPTURE", f"no capture {capture_id!r} in this engagement"
                )
            return capture.detail(body_chars=max(200, min(int(body_chars), 40000)))

        return self._guard(run)

    def http_captures(
        self, engagement: str, host: str = "", probe: str = "", limit: int = 20
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            rows = self.gateway.store.list(
                self._engagement(engagement), host=host, probe=probe, limit=min(int(limit), 100)
            )
            return {"captures": [row.summary() for row in rows], "count": len(rows)}

        return self._guard(run)

    def capture_verify(
        self, engagement: str, capture_id: str, expect_host: str = ""
    ) -> dict[str, Any]:
        return self._guard(
            lambda: self.gateway.verify(
                self._engagement(engagement), capture_id, expect_host=expect_host
            )
        )

    def probe_list(self) -> dict[str, Any]:
        return {
            "probes": describe(),
            "ssrf_callback_available": bool(self.canary and self.canary.available),
        }

    def probe_run(self, engagement: str, probe: str, params_json: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            params = _json_arg(params_json, "params_json")
            if not isinstance(params, dict):
                raise GatewayRefusal("BAD_ARGUMENT", "params_json must be a JSON object")
            name = self._engagement(engagement)
            result = run_probe(self.gateway, name, probe, params, canary=self.canary)
            if self.workbench is not None:
                result = self.workbench.after_probe(name, probe, params, result)
            return result

        return self._guard(run)


def register_tools(mcp: Any, tools: CaptureTools) -> None:
    @mcp.tool()
    def http_send(
        engagement: str,
        method: str,
        url: str,
        headers_json: str = "",
        body: str = "",
        note: str = "",
        identity: str = "",
    ) -> dict[str, Any]:
        """Send one HTTP request to an in-scope target and record it. Returns capture_id,
        status, headers and body. Redirects are returned, not followed. State-changing
        methods may return APPROVAL_REQUIRED. headers_json is a JSON object. identity names
        a declared test account (identities_list) whose session the gateway attaches."""
        return tools.http_send(engagement, method, url, headers_json, body, note, identity)

    @mcp.tool()
    def http_replay(engagement: str, capture_id: str) -> dict[str, Any]:
        """Re-send a captured request from the gateway and compare with the original.
        Use it to show a finding reproduces."""
        return tools.http_replay(engagement, capture_id)

    @mcp.tool()
    def http_capture(engagement: str, capture_id: str, body_chars: int = 8000) -> dict[str, Any]:
        """One captured exchange in full (credentials in headers are redacted)."""
        return tools.http_capture(engagement, capture_id, body_chars)

    @mcp.tool()
    def http_captures(
        engagement: str, host: str = "", probe: str = "", limit: int = 20
    ) -> dict[str, Any]:
        """Recent captures, newest first, optionally for one host or probe."""
        return tools.http_captures(engagement, host, probe, limit)

    @mcp.tool()
    def capture_verify(engagement: str, capture_id: str, expect_host: str = "") -> dict[str, Any]:
        """Whether a capture exists for this engagement, is in scope and is for expect_host."""
        return tools.capture_verify(engagement, capture_id, expect_host)

    @mcp.tool()
    def probe_list() -> dict[str, Any]:
        """The deterministic probes: class, what each checks, and its parameters."""
        return tools.probe_list()

    @mcp.tool()
    def probe_run(engagement: str, probe: str, params_json: str) -> dict[str, Any]:
        """Run a deterministic probe (see probe_list). params_json is a JSON object. Returns
        vulnerable true/false/null (null = could not tell), a summary and evidence capture ids."""
        return tools.probe_run(engagement, probe, params_json)


def build_server(
    *, roots: Roots | None = None, host: str = "127.0.0.1", port: int = DEFAULT_PORT
) -> Any:
    from mcp.server.fastmcp import FastMCP  # noqa: PLC0415 - optional dependency

    gateway = CaptureGateway(roots or Roots.from_env())
    canary = Canary(base_url=os.environ.get("BUGGY_CANARY_BASE_URL", ""))
    bind = os.environ.get("BUGGY_CANARY_BIND", "")
    if bind and canary.available:
        bind_host, _, bind_port = bind.rpartition(":")
        canary.serve(bind_host or "0.0.0.0", int(bind_port))  # noqa: S104 - container-internal
    tools = CaptureTools(gateway, canary, os.environ.get("BUGGY_CAPTURE_ENGAGEMENT") or None)
    notifier = Notifier.from_env()
    bench = Workbench(
        gateway,
        canary,
        tools._engagement,  # noqa: SLF001 - the same engagement binding as the HTTP tools
        on_verified=lambda finding: _in_background(notifier.notify, finding_event(finding)),
    )
    tools.workbench = bench
    gateway.on_approval_request = lambda record: _in_background(
        notifier.notify, approval_event(record)
    )
    mcp = FastMCP("buggy-capture", instructions=INSTRUCTIONS, host=host, port=port)
    register_tools(mcp, tools)
    register_workbench(mcp, bench)
    return mcp


def _in_background(fn: Any, *args: Any) -> None:
    """Run a notification without delaying or failing the request that caused it."""
    threading.Thread(target=fn, args=args, daemon=True).start()


def main() -> None:
    host = os.environ.get("BUGGY_CAPTURE_MCP_HOST", "0.0.0.0")  # noqa: S104 - container-internal
    port = int(os.environ.get("BUGGY_CAPTURE_MCP_PORT") or DEFAULT_PORT)
    from buggy.pipeline.mcp_http import serve  # noqa: PLC0415

    serve(build_server(host=host, port=port), host=host, port=port)


if __name__ == "__main__":
    main()
