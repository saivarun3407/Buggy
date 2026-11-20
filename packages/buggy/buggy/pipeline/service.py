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
import logging
import os
import threading
import time
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
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


log = logging.getLogger("buggy.pipeline.service")


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
            if control is not None:
                # Operator-supplied API contracts are read from the same
                # control tree the scope came from, not from the environment.
                pipeline.control_dir = control / engagement
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
        elif last["status"] == "interrupted":
            # The process running it died (restart, crash). Finished stages are
            # cached, so running again only does what was left.
            due.append((engagement, "resume"))
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


def close_orphaned_runs(root: Path | None = None) -> list[str]:
    """Mark runs left ``running`` by a dead process as ``interrupted``.

    A run is orphaned when nothing holds its engagement's lock. Without this
    a restart mid-run would leave the engagement stuck: a run that looks
    in-progress forever is never due again.
    """
    base = root or data_root()
    closed: list[str] = []
    store = open_store(root=base)
    try:
        for run in store.running_runs():
            try:
                with engagement_lock(base, run["engagement"]):
                    store.interrupt_run(run["id"], reason="the pipeline process stopped mid-run")
                    closed.append(run["id"])
            except PipelineBusy:
                continue  # genuinely running in another process
    finally:
        store.close()
    return closed


DEFAULT_PARALLEL_ENGAGEMENTS = 3


class EngagementRunner:
    """Runs due engagements side by side, one run per engagement at a time.

    A slow scan (a polite request rate against a large target) must not hold
    up an engagement that was started after it. Each engagement still has at
    most one run in flight: the per-engagement lock and this in-flight set
    both guarantee it.
    """

    def __init__(
        self, *, parallel: int = DEFAULT_PARALLEL_ENGAGEMENTS, **pipeline_kwargs: Any
    ) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max(1, parallel), thread_name_prefix="recon")
        self._in_flight: dict[str, Future[Any]] = {}
        self._pipeline_kwargs = pipeline_kwargs
        self._guard = threading.Lock()

    def in_flight(self) -> list[str]:
        with self._guard:
            return sorted(name for name, future in self._in_flight.items() if not future.done())

    def _run(self, engagement: str, trigger: str, root: Path, control: Path) -> None:
        try:
            summary = run_engagement(
                engagement, trigger=trigger, root=root, control=control, **self._pipeline_kwargs
            )
            log.info(
                "recon run %s for %s: %s", summary.get("run_id"), engagement, summary.get("status")
            )
        except (ScopeError, PipelineBusy) as exc:
            log.info("recon for %s skipped: %s", engagement, exc)
        except Exception:
            log.exception("recon for %s failed", engagement)

    def submit_due(
        self, *, root: Path | None = None, control: Path | None = None, refresh_seconds: float = 0.0
    ) -> list[str]:
        """Start a run for every due engagement that has none in flight. Returns those started."""
        base, ctl = root or data_root(), control or control_root()
        store = open_store(root=base)
        try:
            due = engagements_due(store, ctl, refresh_seconds=refresh_seconds)
        finally:
            store.close()
        started: list[str] = []
        with self._guard:
            for name in [n for n, f in self._in_flight.items() if f.done()]:
                del self._in_flight[name]
            for engagement, trigger in due:
                if engagement in self._in_flight:
                    continue
                self._in_flight[engagement] = self._pool.submit(
                    self._run, engagement, trigger, base, ctl
                )
                started.append(engagement)
        return started

    def wait(self, timeout: float | None = None) -> None:
        """Block until every run started so far has ended (tests, ``--once``)."""
        with self._guard:
            futures = list(self._in_flight.values())
        for future in futures:
            future.result(timeout=timeout)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def worker_loop(*, interval: float = 15.0, once: bool = False) -> None:
    """Run due engagements and serve re-run requests until interrupted."""
    refresh = float(os.environ.get("BUGGY_PIPELINE_REFRESH_SECONDS") or 0)
    parallel = int(os.environ.get("BUGGY_PIPELINE_PARALLEL") or DEFAULT_PARALLEL_ENGAGEMENTS)
    for run_id in close_orphaned_runs():
        log.warning("closed orphaned pipeline run %s; it will resume", run_id)
    runner = EngagementRunner(parallel=parallel)
    queue = open_queue()
    try:
        while True:
            for engagement in runner.submit_due(refresh_seconds=refresh):
                log.info("recon started for %s", engagement)
            process_rerun_requests(queue)
            if once:
                runner.wait()
                return
            time.sleep(interval)
    finally:
        runner.shutdown()
        queue.close()


__all__ = [
    "EngagementRunner",
    "PipelineBusy",
    "close_orphaned_runs",
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
