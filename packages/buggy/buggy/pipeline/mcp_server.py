"""MCP server: read-only pipeline data for agents.

Run with ``python -m buggy.pipeline.mcp_server`` (streamable HTTP, port 9460
by default). The recon store is opened read-only. The server exposes no tool
that runs a scanner: ``recon_request_rerun`` only queues the name of an asset,
which the pipeline worker re-validates against the enforced scope before it
does anything.

Environment:

``BUGGY_PIPELINE_DATA``        recon store directory (default /data/pipeline)
``BUGGY_PIPELINE_QUEUE``       re-run queue directory (default <data>/queue)
``BUGGY_PIPELINE_ENGAGEMENT``  serve this engagement only (recommended)
``BUGGY_PIPELINE_MCP_HOST`` / ``BUGGY_PIPELINE_MCP_PORT``
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from buggy.pipeline import service
from buggy.pipeline.query import QueryError, ReconQueries
from buggy.pipeline.store import ReconStore, StoreError

DEFAULT_PORT = 9460

INSTRUCTIONS = (
    "Deterministic recon data for the current engagement, produced by scanners that already "
    "ran. Query it instead of running recon tools yourself: subdomains, DNS, ports, live "
    "services, technologies, TLS, headers, URLs, JS endpoints, API specs, GraphQL schemas, "
    "nuclei findings and secret-scan hits. Every record carries its source tool, version, "
    "timestamps and a raw_ref to the unparsed output. You cannot run scanners from here; "
    "recon_request_rerun queues a re-run for one in-scope asset."
)


def _guard(fn):
    """Turn caller errors into a structured result instead of a tool exception."""

    def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return fn(*args, **kwargs)
        except QueryError as exc:
            return {"error": str(exc)}

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


def register_tools(mcp: Any, queries: ReconQueries) -> None:
    """Register the query tools on a FastMCP instance."""

    @mcp.tool()
    def recon_summary(engagement: str) -> dict[str, Any]:
        """Record counts by type, the last pipeline run and its diff. Start here."""
        return _guard(queries.summary)(engagement)

    @mcp.tool()
    def recon_assets(engagement: str, limit: int = 200) -> dict[str, Any]:
        """In-scope assets (hosts) the pipeline has facts about, with record counts."""
        return _guard(queries.assets)(engagement, limit)

    @mcp.tool()
    def recon_query(
        engagement: str,
        record_type: str = "",
        asset: str = "",
        contains: str = "",
        limit: int = 50,
        offset: int = 0,
        include_gone: bool = False,
    ) -> dict[str, Any]:
        """Query records. record_type is one of: subdomain, dns_record, port, http_service,
        technology, tls, header, url, js_file, endpoint, api_spec, api_operation, graphql,
        parameter, vulnerability, secret. A parameter record names one input (query, path,
        body, header, cookie, form) with hints such as id-like or url-like. Filter by asset (host) and/or a substring of the value.
        Results are paged: follow next_offset while truncated is true."""
        return _guard(queries.query)(
            engagement, record_type, asset, contains, limit, offset, include_gone
        )

    @mcp.tool()
    def recon_record(engagement: str, record_id: str) -> dict[str, Any]:
        """One record with all observations: which tools reported it, when, and raw_ref."""
        return _guard(queries.record)(engagement, record_id)

    @mcp.tool()
    def recon_diff(engagement: str, run_id: str = "") -> dict[str, Any]:
        """What the latest (or given) pipeline run added, changed or removed."""
        return _guard(queries.diff)(engagement, run_id)

    @mcp.tool()
    def recon_scope_drops(engagement: str, run_id: str = "", limit: int = 100) -> dict[str, Any]:
        """Candidates dropped as out of scope before any scan, with the reason."""
        return _guard(queries.scope_drops)(engagement, run_id, limit)

    @mcp.tool()
    def recon_raw(engagement: str, raw_ref: str, context_lines: int = 0) -> dict[str, Any]:
        """The unparsed tool output behind a record's raw_ref, with the tool's argv and hash."""
        return _guard(queries.raw)(engagement, raw_ref, context_lines)

    @mcp.tool()
    def recon_request_rerun(engagement: str, asset: str, reason: str = "") -> dict[str, Any]:
        """Request a pipeline re-run for ONE asset (host, host:port or URL). The asset must be
        in the enforced scope or the request is rejected. You cannot choose tools or flags."""
        return _guard(queries.request_rerun)(engagement, asset, reason)

    @mcp.tool()
    def recon_rerun_status(engagement: str, request_id: str) -> dict[str, Any]:
        """Status of a re-run request: pending, completed, rejected or failed."""
        return _guard(queries.rerun_status)(engagement, request_id)


TOOL_NAMES = (
    "recon_summary",
    "recon_assets",
    "recon_query",
    "recon_record",
    "recon_diff",
    "recon_scope_drops",
    "recon_raw",
    "recon_request_rerun",
    "recon_rerun_status",
)


def build_server(
    *,
    data_root: Path | None = None,
    queue_root: Path | None = None,
    control_root: Path | None = None,
    engagement: str | None = None,
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
) -> Any:
    from mcp.server.fastmcp import FastMCP  # noqa: PLC0415 - optional dependency

    root = data_root or service.data_root()
    try:
        store = ReconStore(root / service.STORE_FILE, read_only=True)
    except StoreError:
        # No pipeline run yet: create the empty schema once, then reopen read-only.
        ReconStore(root / service.STORE_FILE).close()
        store = ReconStore(root / service.STORE_FILE, read_only=True)
    queue = service.open_queue(queue_root or service.queue_root())
    queries = ReconQueries(
        store,
        queue,
        data_root=root,
        control_root=control_root or service.control_root(),
        engagement=engagement or os.environ.get("BUGGY_PIPELINE_ENGAGEMENT") or None,
    )
    mcp = FastMCP("buggy-recon", instructions=INSTRUCTIONS, host=host, port=port)
    register_tools(mcp, queries)
    return mcp


def main() -> None:
    host = os.environ.get("BUGGY_PIPELINE_MCP_HOST", "0.0.0.0")  # noqa: S104 - container-internal
    port = int(os.environ.get("BUGGY_PIPELINE_MCP_PORT") or DEFAULT_PORT)
    from buggy.pipeline.mcp_http import serve  # noqa: PLC0415

    serve(build_server(host=host, port=port), host=host, port=port)


if __name__ == "__main__":
    main()
