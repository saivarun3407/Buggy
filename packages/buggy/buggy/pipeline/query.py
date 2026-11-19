"""Read-only queries over the recon store, as plain functions.

These are the bodies of the MCP tools (``mcp_server``). They take and return
JSON-serialisable values so they can be unit-tested without an MCP client,
and they are the *only* surface an agent has onto pipeline data:

* every read is scoped to one engagement;
* results are capped, with ``total`` / ``truncated`` so the agent pages
  instead of pulling everything into context;
* the single write, :meth:`request_rerun`, cannot name a scanner or a flag.
  It names one asset, which is re-checked against the enforced scope.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from buggy.pipeline import service
from buggy.pipeline.schema import RecordType, host_of
from buggy.pipeline.store import ReconStore

MAX_LIMIT = 200
MAX_SUMMARY_GAPS = 50
MAX_RAW_LINES = 40
MAX_RAW_CHARS = 6000


class QueryError(ValueError):
    """Bad arguments from the caller."""


class ReconQueries:
    def __init__(
        self,
        store: ReconStore,
        queue: ReconStore | None,
        *,
        data_root: Path,
        control_root: Path | None = None,
        engagement: str | None = None,
    ) -> None:
        self._store = store
        self._queue = queue
        self._data_root = Path(data_root)
        self._control_root = control_root
        self._bound = engagement or None

    def _engagement(self, engagement: str) -> str:
        name = (engagement or "").strip()
        if not name:
            raise QueryError("engagement is required")
        if self._bound and name != self._bound:
            raise QueryError(f"this server serves engagement {self._bound!r} only")
        return name

    @staticmethod
    def _limit(limit: int) -> int:
        return max(1, min(int(limit or MAX_LIMIT), MAX_LIMIT))

    # ── reads ───────────────────────────────────────────────────────

    def summary(self, engagement: str) -> dict[str, Any]:
        """Record counts by type, the last run and what it changed."""
        name = self._engagement(engagement)
        run = self._store.latest_run(name)
        newest = self._store.latest_run(name, finished_only=False)
        current = newest if newest and newest["status"] == "running" else None
        gaps = self._store.coverage_gaps(name)
        return {
            "engagement": name,
            "record_types": [t.value for t in RecordType],
            "records": self._store.count_records(name),
            # Per (asset, stage) stamps. A stage that is not ``complete`` for an
            # asset found nothing *because it did not finish*, not because the
            # asset is clean. All zeros: no coverage was recorded at all.
            "coverage": self._store.coverage_counts(name),
            "coverage_gaps": gaps[:MAX_SUMMARY_GAPS],
            "coverage_gap_assets": len({gap["asset"] for gap in gaps}),
            "current_run": (
                {
                    "run_id": current["id"],
                    "trigger": current["trigger"],
                    "started_at": current["started_at"],
                    "stage": current["stats"].get("stage", ""),
                    "stages_done": current["stats"].get("stages_done", []),
                }
                if current
                else None
            ),
            "last_run": (
                {
                    "run_id": run["id"],
                    "status": run["status"],
                    "trigger": run["trigger"],
                    "started_at": run["started_at"],
                    "finished_at": run["finished_at"],
                    "diff": run["stats"].get("diff", {}),
                    "scope_drops": run["stats"].get("scope_drops", 0),
                    "tool_versions": run["stats"].get("tool_versions", {}),
                }
                if run
                else None
            ),
        }

    def assets(self, engagement: str, limit: int = MAX_LIMIT) -> dict[str, Any]:
        """In-scope assets the pipeline has facts about."""
        name = self._engagement(engagement)
        rows = self._store.list_assets(name, limit=self._limit(limit))
        return {"engagement": name, "assets": rows, "count": len(rows)}

    def coverage(
        self, engagement: str, asset: str = "", limit: int = MAX_LIMIT, offset: int = 0
    ) -> dict[str, Any]:
        """Per asset and stage: complete, partial, failed or skipped, and why.

        Gaps (anything not ``complete``) come first. An asset or stage with no
        stamp was never processed: that is "not checked", not "clean".
        """
        name = self._engagement(engagement)
        wanted = asset.strip().lower()
        rows = self._store.coverage(name, asset=wanted or None)
        if wanted and not rows and host_of(wanted) not in ("", wanted):
            wanted = host_of(wanted)  # a URL or host:port names its host
            rows = self._store.coverage(name, asset=wanted)
        rows.sort(key=lambda row: (row["status"] == "complete", row["asset"], row["stage"]))
        counts = {"complete": 0, "partial": 0, "failed": 0, "skipped": 0}
        for row in rows:
            if row["status"] in counts:
                counts[row["status"]] += 1
        capped, start = self._limit(limit), max(0, int(offset))
        page = rows[start : start + capped]
        truncated = start + capped < len(rows)
        return {
            "engagement": name,
            "asset": wanted,
            "counts": counts,
            "coverage": page,
            "total": len(rows),
            "truncated": truncated,
            "next_offset": start + capped if truncated else None,
        }

    def query(
        self,
        engagement: str,
        record_type: str = "",
        asset: str = "",
        contains: str = "",
        limit: int = 50,
        offset: int = 0,
        include_gone: bool = False,
    ) -> dict[str, Any]:
        """Records filtered by type, asset and/or a substring of the value."""
        name = self._engagement(engagement)
        if record_type and record_type not in {t.value for t in RecordType}:
            raise QueryError(
                f"unknown record_type {record_type!r}; one of {[t.value for t in RecordType]}"
            )
        capped = self._limit(limit)
        rows = self._store.query_records(
            name,
            record_type=record_type or None,
            asset=asset.strip().lower() or None,
            contains=contains or None,
            status=None if include_gone else "active",
            limit=capped + 1,
            offset=max(0, int(offset)),
        )
        return {
            "engagement": name,
            "records": [row.to_dict() for row in rows[:capped]],
            "truncated": len(rows) > capped,
            "next_offset": max(0, int(offset)) + capped if len(rows) > capped else None,
        }

    def record(self, engagement: str, record_id: str) -> dict[str, Any]:
        """One record with every observation of it (tool, version, time, raw reference)."""
        name = self._engagement(engagement)
        data = self._store.get_record(name, record_id)
        if data is None:
            raise QueryError(f"no record {record_id!r} in engagement {name!r}")
        return data

    def diff(self, engagement: str, run_id: str = "") -> dict[str, Any]:
        """What a run added, changed or removed (default: the latest finished run)."""
        name = self._engagement(engagement)
        run = self._store.get_run(run_id) if run_id else self._store.latest_run(name)
        if run is None or run["engagement"] != name:
            raise QueryError("no such run for this engagement")
        changes = self._store.diff(name, run["id"], limit=MAX_LIMIT + 1)
        return {
            "engagement": name,
            "run_id": run["id"],
            "counts": run["stats"].get("diff", {}),
            "changes": changes[:MAX_LIMIT],
            "truncated": len(changes) > MAX_LIMIT,
        }

    def scope_drops(self, engagement: str, run_id: str = "", limit: int = 100) -> dict[str, Any]:
        """Candidates the scope filter dropped (never scanned), and why."""
        name = self._engagement(engagement)
        rows = self._store.scope_drops(name, run_id=run_id or None, limit=self._limit(limit))
        return {"engagement": name, "drops": rows, "count": len(rows)}

    def raw(self, engagement: str, raw_ref: str, context_lines: int = 0) -> dict[str, Any]:
        """The unparsed tool output a record was derived from (provenance check)."""
        name = self._engagement(engagement)
        base, _, fragment = raw_ref.partition("#")
        meta = self._store.raw_output(name, base)
        if meta is None:
            raise QueryError(f"no raw output {base!r} in engagement {name!r}")
        path = (self._data_root / base).resolve()
        root = (self._data_root / "raw" / name).resolve()
        if root not in path.parents:
            raise QueryError("raw reference escapes the engagement's raw-output directory")
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise QueryError(f"raw output is no longer on disk: {exc}") from exc
        if fragment.startswith("L") and fragment[1:].isdigit():
            target = int(fragment[1:])
            span = max(0, min(int(context_lines), MAX_RAW_LINES // 2))
            first, last = max(1, target - span), min(len(lines), target + span)
        else:
            first, last = 1, min(len(lines), MAX_RAW_LINES)
        excerpt = [
            {"line": number, "text": lines[number - 1][:MAX_RAW_CHARS]}
            for number in range(first, last + 1)
        ]
        return {
            "engagement": name,
            "raw_ref": raw_ref,
            "tool": meta["tool"],
            "tool_version": meta["tool_version"],
            "argv": meta["argv"],
            "sha256": meta["sha256"],
            "total_lines": len(lines),
            "lines": excerpt,
        }

    # ── the one write ───────────────────────────────────────────────

    def request_rerun(
        self, engagement: str, asset: str, reason: str = "", requested_by: str = "agent"
    ) -> dict[str, Any]:
        """Ask for the pipeline to re-run on ONE in-scope asset."""
        name = self._engagement(engagement)
        if self._queue is None:
            raise QueryError("re-run requests are not enabled on this server")
        if not asset or len(asset) > 300:
            raise QueryError("asset must be a host, host:port or URL")
        return service.request_rerun(
            self._queue,
            name,
            asset,
            requested_by=requested_by,
            reason=reason,
            control=self._control_root,
        )

    def rerun_status(self, engagement: str, request_id: str) -> dict[str, Any]:
        name = self._engagement(engagement)
        if self._queue is None:
            raise QueryError("re-run requests are not enabled on this server")
        row = self._queue.get_rerun(name, request_id)
        if row is None:
            raise QueryError(f"no re-run request {request_id!r}")
        return {
            "request_id": row["id"],
            "asset": row["asset"],
            "status": row["status"],
            "detail": row["detail"],
            "run_id": row["run_id"] or "",
        }


__all__ = ["MAX_LIMIT", "MAX_SUMMARY_GAPS", "QueryError", "ReconQueries"]
