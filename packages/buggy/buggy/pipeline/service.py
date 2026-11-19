"""Run the pipeline for an engagement, and serve agent re-run requests.

``run_engagement`` is the one function behind the CLI, the worker loop and
the tests. It resolves the engagement's enforced scope from the control root,
takes a per-engagement lock (one run at a time), and executes the pipeline.

``process_rerun_requests`` is how an agent's request reaches a scanner: the
agent can only append a row naming an asset; this function re-checks the
asset against the enforced scope and, if it is in scope, runs the pipeline
for that asset alone. An out-of-scope request is rejected and recorded.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from buggy.pipeline.pipeline import DEFAULT_MAX_AGE, Pipeline, canonical_asset
from buggy.pipeline.schema import as_dict
from buggy.pipeline.scope import ScopeError, ScopeFilter
from buggy.pipeline.store import ReconStore

DEFAULT_DATA_ROOT = "/data/pipeline"
DEFAULT_CONTROL_ROOT = "/control"
STORE_FILE = "recon.sqlite3"
QUEUE_FILE = "rerun-queue.sqlite3"


def data_root() -> Path:
    return Path(os.environ.get("BUGGY_PIPELINE_DATA") or DEFAULT_DATA_ROOT)


def queue_root() -> Path:
    """Where agent re-run requests are queued (writable by the MCP server)."""
    return Path(os.environ.get("BUGGY_PIPELINE_QUEUE") or data_root() / "queue")


def control_root() -> Path:
    raw = os.environ.get("BUGGY_ENGAGEMENT_CONTROL") or os.environ.get("BUGGY_CONTROL_ROOT")
    return Path(raw) if raw else Path(DEFAULT_CONTROL_ROOT)


def open_store(*, read_only: bool = False, root: Path | None = None) -> ReconStore:
    return ReconStore((root or data_root()) / STORE_FILE, read_only=read_only)


def open_queue(root: Path | None = None) -> ReconStore:
    return ReconStore((root or queue_root()) / QUEUE_FILE)


def scope_path(engagement: str, control: Path | None = None) -> Path:
    return (control or control_root()) / engagement / "roe.json"


def load_scope(engagement: str, control: Path | None = None) -> tuple[ScopeFilter, dict[str, Any]]:
    path = scope_path(engagement, control)
    scope = ScopeFilter.from_file(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    return scope, document


class PipelineBusy(RuntimeError):
    """Another run for this engagement holds the lock."""


@contextmanager
def engagement_lock(root: Path, engagement: str) -> Iterator[None]:
    lock_dir = root / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    handle = (lock_dir / f"{engagement}.lock").open("w")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise PipelineBusy(f"a pipeline run for {engagement!r} is already in progress") from exc
        yield
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()


def run_engagement(
    engagement: str,
    *,
    trigger: str = "manual",
    force: bool = False,
    only_asset: str | None = None,
    max_age: float = DEFAULT_MAX_AGE,
    root: Path | None = None,
    control: Path | None = None,
    store: ReconStore | None = None,
    **pipeline_kwargs: Any,
) -> dict[str, Any]:
    """Run the pipeline once. Raises :class:`ScopeError` when there is no usable scope."""
    base = root or data_root()
    scope, document = load_scope(engagement, control)
    block = as_dict(document.get("pipeline"))
    repos = [str(r) for r in block.get("public_repos") or [] if isinstance(r, str)]
    templates = os.environ.get("BUGGY_NUCLEI_TEMPLATES")
    if templates:
        pipeline_kwargs.setdefault("nuclei_templates", templates)
    resolvers = os.environ.get("BUGGY_PIPELINE_DNS_RESOLVERS")
    if resolvers:
        pipeline_kwargs.setdefault(
            "dns_resolvers", tuple(r.strip() for r in resolvers.split(",") if r.strip())
        )
    owned = store is None
    active = store or open_store(root=base)
    try:
        with engagement_lock(base, engagement):
            pipeline = Pipeline(
                active,
                scope,
                engagement,
                data_root=base,
                force=force or bool(only_asset),
                only_asset=only_asset,
                max_age=max_age,
                public_repos=repos,
                **pipeline_kwargs,
            )
            return pipeline.run(trigger=trigger)
    finally:
        if owned:
            active.close()


def request_rerun(
    queue: ReconStore,
    engagement: str,
    asset: str,
    *,
    requested_by: str,
    reason: str,
    control: Path | None = None,
) -> dict[str, Any]:
    """Queue a re-run for one asset if, and only if, it is in the enforced scope."""
    name = canonical_asset(asset)
    try:
        scope, _document = load_scope(engagement, control)
    except ScopeError as exc:
        request_id = queue.add_rerun_request(
            engagement, name or asset, requested_by=requested_by, reason=reason,
            status="rejected", detail=str(exc),
        )  # fmt: skip
        return {"request_id": request_id, "status": "rejected", "detail": str(exc)}
    allowed, why = scope.decide(name) if name else (False, "NO_HOST")
    if not allowed:
        detail = f"{asset!r} is not in the enforced scope ({why}); nothing was scanned"
        request_id = queue.add_rerun_request(
            engagement, name or asset, requested_by=requested_by, reason=reason,
            status="rejected", detail=detail,
        )  # fmt: skip
        return {"request_id": request_id, "status": "rejected", "detail": detail}
    for pending in queue.pending_reruns(engagement):
        if pending["asset"] == name:
            return {"request_id": pending["id"], "status": "pending", "detail": "already queued"}
    request_id = queue.add_rerun_request(
        engagement, name, requested_by=requested_by, reason=reason, status="pending", detail="",
    )  # fmt: skip
    return {"request_id": request_id, "status": "pending", "detail": "queued"}


def process_rerun_requests(
    queue: ReconStore,
    *,
    root: Path | None = None,
    control: Path | None = None,
    **pipeline_kwargs: Any,
) -> list[dict[str, Any]]:
    """Run every pending request, re-validating scope at execution time."""
    results: list[dict[str, Any]] = []
    for request in queue.pending_reruns():
        engagement, asset = request["engagement"], request["asset"]
        try:
            scope, _document = load_scope(engagement, control)
            allowed, why = scope.decide(asset)
            if not allowed:
                raise ScopeError(f"{asset!r} is no longer in scope ({why})")
            summary = run_engagement(
                engagement,
                trigger=f"rerun:{request['id']}",
                only_asset=asset,
                root=root,
                control=control,
                **pipeline_kwargs,
            )
        except ScopeError as exc:
            queue.resolve_rerun(request["id"], status="rejected", detail=str(exc))
            results.append({"request_id": request["id"], "status": "rejected", "detail": str(exc)})
            continue
        except PipelineBusy as exc:
            results.append({"request_id": request["id"], "status": "pending", "detail": str(exc)})
            continue
        except Exception as exc:  # noqa: BLE001 - recorded on the request
            queue.resolve_rerun(
                request["id"], status="failed", detail=f"{type(exc).__name__}: {exc}"
            )
            results.append({"request_id": request["id"], "status": "failed", "detail": str(exc)})
            continue
        queue.resolve_rerun(
            request["id"],
            status="completed",
            detail=json.dumps(summary["diff"]),
            run_id=summary["run_id"],
        )
        results.append(
            {"request_id": request["id"], "status": "completed", "run_id": summary["run_id"]}
        )
    return results


def engagements_due(
    store: ReconStore, control: Path, *, refresh_seconds: float = 0.0
) -> list[tuple[str, str]]:
    """``(engagement, trigger)`` pairs that should run now.

    An engagement is due when the operator has approved a scope the pipeline
    has not run against yet (a new engagement, or a changed scope), or - with
    ``refresh_seconds`` set - when its last run is older than that. An
    engagement without a usable enforced scope is never due.
    """
    due: list[tuple[str, str]] = []
    try:
        candidates = sorted(p.parent.name for p in control.glob("*/roe.json"))
    except OSError:
        return due
    for engagement in candidates:
        try:
            scope, _document = load_scope(engagement, control)
        except ScopeError:
            continue
        last = store.latest_run(engagement, finished_only=False)
        if last is None:
            due.append((engagement, "scope:new"))
        elif last["status"] == "running":
            continue
        elif last["scope_digest"] != scope.digest:
            due.append((engagement, "scope:changed"))
        elif refresh_seconds > 0 and time.time() - float(last["started_at"]) > refresh_seconds:
            due.append((engagement, "refresh"))
    return due


def worker_tick(
    queue: ReconStore,
    *,
    root: Path | None = None,
    control: Path | None = None,
    refresh_seconds: float = 0.0,
    **pipeline_kwargs: Any,
) -> list[dict[str, Any]]:
    """One pass: run engagements whose scope is new or changed, then serve re-run requests."""
    base, ctl = root or data_root(), control or control_root()
    results: list[dict[str, Any]] = []
    store = open_store(root=base)
    try:
        due = engagements_due(store, ctl, refresh_seconds=refresh_seconds)
    finally:
        store.close()
    for engagement, trigger in due:
        try:
            summary = run_engagement(
                engagement, trigger=trigger, root=base, control=ctl, **pipeline_kwargs
            )
            results.append(
                {"engagement": engagement, "trigger": trigger, "run_id": summary["run_id"]}
            )
        except (ScopeError, PipelineBusy) as exc:
            results.append({"engagement": engagement, "trigger": trigger, "skipped": str(exc)})
        except Exception as exc:  # noqa: BLE001 - one engagement must not stop the worker
            results.append({"engagement": engagement, "trigger": trigger, "error": str(exc)})
    results.extend(process_rerun_requests(queue, root=base, control=ctl, **pipeline_kwargs))
    return results


def worker_loop(*, interval: float = 15.0, once: bool = False) -> None:
    """Run due engagements and serve re-run requests until interrupted."""
    refresh = float(os.environ.get("BUGGY_PIPELINE_REFRESH_SECONDS") or 0)
    queue = open_queue()
    try:
        while True:
            worker_tick(queue, refresh_seconds=refresh)
            if once:
                return
            time.sleep(interval)
    finally:
        queue.close()


__all__ = [
    "PipelineBusy",
    "control_root",
    "data_root",
    "engagement_lock",
    "engagements_due",
    "load_scope",
    "open_queue",
    "open_store",
    "process_rerun_requests",
    "queue_root",
    "request_rerun",
    "run_engagement",
    "worker_loop",
    "worker_tick",
]
