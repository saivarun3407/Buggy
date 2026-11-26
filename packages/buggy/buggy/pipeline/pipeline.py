"""The pipeline: seven stages, in order, for one engagement.

Each stage follows the same shape:

1. pick its inputs from the store (the previous stages' records);
2. filter them against the scope (``direction="input"``) — a rejected
   candidate is logged and never reaches a tool;
3. skip inputs whose upstream facts have not changed since they were last
   processed (the cache), unless forced or stale;
4. run the tools on what is left;
5. parse, then filter the *outputs* against the scope (``direction="output"``);
6. write the survivors, with the raw-output reference, and mark the inputs
   processed (which also retires records they no longer produce);
7. stamp every input asset it handled with how the stage went for it
   (``complete`` / ``partial`` / ``failed`` / ``skipped`` and why), so a
   stage that did not finish is never read as "nothing found".

There is no model call anywhere on this path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import shutil
import subprocess
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from buggy.pipeline import versions, wildcard
from buggy.pipeline.http import OutOfScopeRequest, RateLimiter, Response, ScopedHTTP, fetch_passive
from buggy.pipeline.runner import RunResult, run_tool
from buggy.pipeline.schema import (
    Record,
    RecordType,
    StoredRecord,
    host_of,
    normalize_host,
    normalize_url,
)
from buggy.pipeline.scope import PipelineLimits, ScopeFilter
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools import (
    apirecon,
    apispec,
    crtsh,
    jsparse,
    paramminer,
    params,
    recovered,
    subguess,
    webrecon,
)
from buggy.pipeline.tools.amass import Amass
from buggy.pipeline.tools.archives import Gau, Waybackurls
from buggy.pipeline.tools.base import Invocation
from buggy.pipeline.tools.dnsx import Dnsx
from buggy.pipeline.tools.gitleaks import Gitleaks
from buggy.pipeline.tools.httpx import Httpx
from buggy.pipeline.tools.katana import Katana
from buggy.pipeline.tools.naabu import Naabu
from buggy.pipeline.tools.nuclei import Nuclei
from buggy.pipeline.tools.subfinder import Subfinder

log = logging.getLogger("buggy.pipeline")

STAGES = (
    "enumerate",
    "dns",
    "live",
    "fingerprint",
    "urls",
    "web",
    "apispec",
    "api",
    "paramguess",
    "issues",
)

# The live stage does two separate things to a host: the port scan (naabu) and
# the HTTP probe (httpx). Program rules can turn the first off while the second
# runs, so the port scan gets its own coverage stamp next to the stage's.
COVERAGE_PORT = "port"
COVERAGE_STAGES = (
    "enumerate",
    "dns",
    COVERAGE_PORT,
    "live",
    "fingerprint",
    "urls",
    "web",
    "apispec",
    "api",
    "paramguess",
    "issues",
)
PORT_SCAN_DISABLED = "port scan disabled by program rules"
STAGE_DISABLED = "disabled by program rules"

# Stages whose records are retired when a re-processed input stops reporting
# them. Discovery stages (subdomains, URLs) only accumulate.
RETIRING_STAGES = frozenset(
    {"dns", "live", "fingerprint", "web", "apispec", "api", "paramguess", "issues"}
)

# Stage-cache namespace of the DNS stage's wildcard check: one row per
# enumeration root (the verdict), next to the stage's own per-host rows.
WILDCARD_STAGE = "dns:wildcard"
ADDRESS_RTYPES = ("A", "AAAA")

DEFAULT_MAX_AGE = 24 * 3600.0
MAX_JS_FILES = 200
MAX_JS_BYTES = 3 * 1024 * 1024
#: Source maps per run whose original files are rebuilt and scanned.
MAX_RECOVERED_MAPS = 20
#: Hosts found in links that one run feeds back into DNS, live probing and the crawl.
MAX_LINKED_HOSTS = 50
LINKS_TOOL = "links"
LINK_TYPES = (RecordType.URL, RecordType.ENDPOINT, RecordType.JS_FILE)
#: Hidden-parameter guessing: pages per origin, requests per run, requests per page and place.
PARAM_ENDPOINTS_PER_ORIGIN = 4
PARAM_MAX_REQUESTS = 300
PARAM_BUDGET = {"query": 40, "header": 25, "cookie": 15}
PUBLIC_REPO_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

# (name, invocation, raw_path) -> RunResult. Injected in tests.
Executor = Callable[[str, Invocation, Path], RunResult]
# name -> (binary, version label). Injected in tests.
Resolver = Callable[[str], tuple[str, str]]


def default_executor(_name: str, invocation: Invocation, raw_path: Path) -> RunResult:
    target = raw_path
    result = run_tool(
        invocation.argv,
        raw_path=target,
        timeout=invocation.timeout,
        stdin_text=invocation.stdin,
    )
    if invocation.output_file is not None:
        # The tool wrote its results to a file; that file is the raw output.
        try:
            shutil.copyfile(invocation.output_file, raw_path)
        except OSError:
            raw_path.write_bytes(b"")
        data = raw_path.read_bytes()
        result = RunResult(
            argv=result.argv,
            exit_code=result.exit_code,
            raw_path=raw_path,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            started_at=result.started_at,
            finished_at=result.finished_at,
            timed_out=result.timed_out,
            stderr_tail=result.stderr_tail,
        )
    return result


def _hash(*parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """How one tool went in a stage, for the assets it was run on."""

    tool: str
    status: str  # complete | partial | failed | skipped
    detail: str = ""
    assets: frozenset[str] | None = None  # None: every asset the stage handled


def grade(asset: str, outcomes: Iterable[ToolOutcome]) -> tuple[str, str]:
    """``(status, detail)`` of one asset in one stage, from the tools run on it.

    * every tool returned and was parsed          -> ``complete``
    * every tool was held back by program rules   -> ``skipped`` (the reason)
    * no tool produced anything usable            -> ``failed`` (tool: why)
    * anything in between                         -> ``partial`` (tool: why)
    """
    relevant = [o for o in outcomes if o.assets is None or asset in o.assets]
    if not relevant:
        return "skipped", "no tool ran on this asset"
    statuses = {o.status for o in relevant}
    if statuses == {"complete"}:
        return "complete", ""
    if statuses == {"skipped"}:
        return "skipped", "; ".join(dict.fromkeys(o.detail or o.tool for o in relevant))
    notes = [
        f"{o.tool}: skipped ({o.detail})" if o.status == "skipped" else f"{o.tool}: {o.detail}"
        for o in relevant
        if o.status != "complete"
    ]
    status = "failed" if statuses <= {"failed", "skipped"} else "partial"
    return status, "; ".join(dict.fromkeys(notes))


@dataclass
class StageStats:
    inputs: int = 0
    processed: int = 0
    cached: int = 0
    records: int = 0
    retired: int = 0
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    skipped: str = ""

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "inputs": self.inputs,
            "processed": self.processed,
            "cached": self.cached,
            "records": self.records,
            "retired": self.retired,
            "tools": self.tools,
        }
        if self.skipped:
            data["skipped"] = self.skipped
        return data


@dataclass
class _Job:
    """A scanner run prepared by the pipeline, ready to execute."""

    stage: str
    stats: StageStats
    name: str
    inputs: list[str]
    version: str
    invocation: Invocation
    raw_path: Path
    ref: str
    assets: Iterable[str] | None


class Pipeline:
    """One engagement's pipeline run."""

    def __init__(
        self,
        store: ReconStore,
        scope: ScopeFilter,
        engagement: str,
        *,
        data_root: Path,
        force: bool = False,
        max_age: float = DEFAULT_MAX_AGE,
        only_asset: str | None = None,
        public_repos: Iterable[str] = (),
        executor: Executor | None = None,
        resolver: Resolver | None = None,
        http_opener: Any = None,
        passive_fetch: Callable[[str], bytes | None] | None = None,
        dns_resolvers: tuple[str, ...] = (),
        nuclei_templates: str = versions.NUCLEI_TEMPLATES_DIR,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.store = store
        self.scope = scope
        self.engagement = engagement
        self.data_root = Path(data_root)
        self.force = force
        self.max_age = max_age
        self.only_asset = normalize_host(only_asset) if only_asset else None
        self._round_hosts: set[str] | None = None  # set during the linked-hosts round
        self.linked_hosts: list[str] = []
        self.linked_stats: dict[str, StageStats] = {}
        self.public_repos = tuple(public_repos)
        self._executor = executor or default_executor
        self._resolver = resolver or versions.verify
        self._http_opener = http_opener
        self._limiter = RateLimiter(scope.limits.rate_limit_rps, sleep=sleep)
        # Limits for scanners that send to the target. Halved while the early
        # issue scan runs, so the two together stay within the program's rate.
        self._target_limits = scope.limits
        self._early_issues: tuple[_Job, Future[RunResult], dict[str, str]] | None = None
        self._passive_fetch = passive_fetch or (
            lambda url: fetch_passive(url, limiter=self._limiter)
        )
        # Custom resolvers go to every scanner: each ships its own public
        # resolver list and would otherwise not see internal (lab) names.
        self._resolvers = tuple(dns_resolvers)
        self._dnsx = Dnsx(resolvers=self._resolvers)
        self._nuclei = Nuclei(templates_dir=nuclei_templates, resolvers=self._resolvers)
        self.run_id = ""
        self.stats: dict[str, StageStats] = {}
        self._fingerprints: list[tuple[Record, str]] = []
        self._httpx_ref: tuple[str, str] = ("", "")
        self._js_sources: dict[str, str] = {}
        self._processed_services: list[str] = []
        self._tool_versions: dict[str, str] = {}
        # Coverage bookkeeping, reset for every stage.
        self._outcomes: list[ToolOutcome] = []
        self._handled: list[str] = []
        self._live_grades: dict[str, tuple[str, str]] = {}

    # ── entry point ─────────────────────────────────────────────────

    def run(self, *, trigger: str = "manual") -> dict[str, Any]:
        self.run_id = self.store.begin_run(
            self.engagement, trigger=trigger, scope_digest=self.scope.digest
        )
        self.scope.log_drop = self._log_drop
        status = "completed"
        error = ""
        handlers = {
            "enumerate": self._stage_enumerate,
            "dns": self._stage_dns,
            "live": self._stage_live,
            "fingerprint": self._stage_fingerprint,
            "urls": self._stage_urls,
            "web": self._stage_web,
            "apispec": self._stage_apispec,
            "api": self._stage_api,
            "paramguess": self._stage_paramguess,
            "issues": self._stage_issues,
        }
        current = ""
        try:
            done: list[str] = []
            for stage in STAGES:
                current = stage
                self._run_stage(stage, handlers[stage], done)
            # Hosts the pages, scripts and API descriptions link to that no
            # enumeration source listed: resolved, probed and crawled in one
            # more round that only looks at them.
            linked = self._linked_hosts() if "dns" not in self.scope.limits.disabled_stages else []
            if linked:
                # The round keeps its own stage stats, next to the first round's.
                self.linked_hosts = linked
                self._round_hosts = set(linked)
                first, self.stats = self.stats, {}
                try:
                    for stage in STAGES[1:]:
                        current = stage
                        self._run_stage(stage, handlers[stage], done)
                finally:
                    self._round_hosts = None
                    self.linked_stats, self.stats = self.stats, first
        except Exception as exc:  # noqa: BLE001 - the run is closed as failed, then re-raised
            status, error = "failed", f"{type(exc).__name__}: {exc}"
            log.exception("pipeline run %s failed", self.run_id)
            self._stamp_run_failure(current, error)
            raise
        finally:
            if self._early_issues is not None:  # the run ended before collecting it
                self._early_issues[1].result()
                self._early_issues = None
            summary = {
                # In pipeline order: the issues entry is created early, when its
                # scan starts next to the crawl.
                "stages": {
                    name: self.stats[name].to_dict() for name in STAGES if name in self.stats
                },
                "tool_versions": self._tool_versions,
                "limits": {
                    "rate_limit_rps": self.scope.limits.rate_limit_rps,
                    "concurrency": self.scope.limits.concurrency,
                    "passive_only": self.scope.limits.passive_only,
                },
                "only_asset": self.only_asset or "",
                "linked_hosts": list(self.linked_hosts),
                "linked_round": {
                    name: self.linked_stats[name].to_dict()
                    for name in STAGES
                    if name in self.linked_stats
                },
                "force": self.force,
                "scope_drops": len(self.store.scope_drops(self.engagement, run_id=self.run_id)),
            }
            if error:
                summary["error"] = error
            diff = self.store.finish_run(self.run_id, status=status, stats=summary)
            summary["diff"] = diff
            self.summary = summary
            shutil.rmtree(self._workdir(), ignore_errors=True)
        return {"run_id": self.run_id, "status": status, **summary}

    # ── shared helpers ──────────────────────────────────────────────

    def _log_drop(self, stage: str, tool: str, direction: str, candidate: str, reason: str) -> None:
        self.store.log_scope_drop(
            self.run_id,
            self.engagement,
            stage=stage,
            tool=tool,
            direction=direction,
            candidate=candidate,
            reason=reason,
        )

    def _workdir(self) -> Path:
        path = self.data_root / "work" / self.engagement / self.run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _raw_path(self, stage: str, tool: str, suffix: str = "out") -> tuple[Path, str]:
        ref = f"raw/{self.engagement}/{self.run_id}/{stage}-{tool}.{suffix}"
        return self.data_root / ref, ref

    def _run_stage(
        self, stage: str, handler: Callable[[StageStats], None], done: list[str]
    ) -> None:
        stats = self.stats.setdefault(stage, StageStats())
        self._outcomes, self._handled = [], []
        if stage in self.scope.limits.disabled_stages:
            stats.skipped = STAGE_DISABLED
            self._stamp_skipped(stage, STAGE_DISABLED)
            return
        self.store.set_run_progress(self.run_id, stage=stage, done=list(done))
        handler(stats)
        self._stamp_stage(stage)
        if stage not in done:
            done.append(stage)

    def _linked_hosts(self) -> list[str]:
        """In-scope hosts that stored URLs, scripts and API operations point to but
        that are not yet subdomain records, stored as ``subdomain`` records
        (source ``links``). At most :data:`MAX_LINKED_HOSTS` per run."""
        known = {r.asset for r in self._records(RecordType.SUBDOMAIN)}
        found: dict[str, str] = {}
        urls = [r.value for kind in LINK_TYPES for r in self._records(kind)]
        urls += [str(r.attrs.get("url") or "") for r in self._records(RecordType.API_OPERATION)]
        for url in urls:
            host = host_of(url)
            if not host or host in known or host in found or _is_address(host):
                continue
            if self._wanted(host) and self.scope.allows(host):
                found[host] = url
                if len(found) >= MAX_LINKED_HOSTS:
                    break
        if not found:
            return []
        stats = self.stats.setdefault("enumerate", StageStats())
        lines = [json.dumps({"host": h, "found_in": u}) for h, u in found.items()]
        ref = self._save_raw("enumerate", LINKS_TOOL, "\n".join(lines) + "\n")
        roots = self._enumeration_roots()
        kept = self._store(
            "enumerate",
            stats,
            LINKS_TOOL,
            (
                (
                    Record(
                        RecordType.SUBDOMAIN,
                        host,
                        host,
                        LINKS_TOOL,
                        attrs={"found_in": url},
                        raw_line=index,
                    ),
                    self._root_of(host, roots),
                )
                for index, (host, url) in enumerate(found.items(), start=1)
            ),
            version=versions.BUILTIN_VERSION,
            raw_ref=ref,
        )
        return sorted(found) if kept else []

    def _wanted(self, host: str) -> bool:
        """Whether a host is selected by ``only_asset`` (always true without it) and,
        in the linked-hosts round, is one of the hosts that round looks at."""
        if self._round_hosts is not None and host not in self._round_hosts:
            return False
        if not self.only_asset:
            return True
        return host == self.only_asset or host.endswith("." + self.only_asset)

    def _pending(self, stage: str, stats: StageStats, candidates: dict[str, str]) -> dict[str, str]:
        """``{input_key: input_hash}`` that must be processed this run."""
        stats.inputs += len(candidates)
        self._retire_vanished(stage, stats, candidates)
        self._prune_coverage(stage, candidates)
        pending: dict[str, str] = {}
        now = time.time()
        for key, input_hash in candidates.items():
            cached = self.store.cached_input(self.engagement, stage, key)
            fresh = (
                cached is not None
                and cached["input_hash"] == input_hash
                and now - float(cached["completed_at"]) < self.max_age
            )
            if fresh and not self.force:
                stats.cached += 1
            else:
                pending[key] = input_hash
        stats.processed += len(pending)
        self._handled = list(pending)
        return pending

    # ── coverage stamps ─────────────────────────────────────────────

    def _note(
        self, tool: str, status: str, detail: str = "", assets: Iterable[str] | None = None
    ) -> None:
        """Record how ``tool`` went, for every handled asset or just ``assets``."""
        scoped = None if assets is None else frozenset(assets)
        self._outcomes.append(ToolOutcome(tool, status, detail, scoped))

    def _note_requests(self, tool: str, tally: dict[str, list[int]]) -> None:
        """One outcome per asset from ``{asset: [requests sent, transport errors]}``."""
        for asset, (sent, errors) in tally.items():
            if errors == 0:
                self._note(tool, "complete", assets=[asset])
            elif errors >= sent:
                self._note(tool, "failed", f"no response to {sent} request(s)", assets=[asset])
            else:
                self._note(
                    tool, "partial", f"{errors} of {sent} requests got no response", assets=[asset]
                )

    def _stamp(
        self, stage: str, assets: Iterable[str], outcomes: Iterable[ToolOutcome]
    ) -> dict[str, tuple[str, str]]:
        outcomes = list(outcomes)
        stamps = {asset: grade(asset, outcomes) for asset in assets}
        if stamps:
            self.store.stamp_coverage(self.engagement, stage, stamps, self.run_id)
        return stamps

    def _stamp_stage(self, stage: str) -> None:
        """Stamp the assets this stage processed in this run.

        Inputs skipped by the cache are not in ``_handled``, so they keep the
        stamp of the run that last processed them.
        """
        if stage == "fingerprint":
            return  # stamped by the handler: its inputs are the live probe's
        assets = sorted({_asset(key) for key in self._handled})
        if stage == "live":
            self._stamp(COVERAGE_PORT, assets, (o for o in self._outcomes if o.tool == Naabu.name))
            self._live_grades = self._stamp(
                "live", assets, (o for o in self._outcomes if o.tool == Httpx.name)
            )
            return
        self._stamp(stage, assets, self._outcomes)

    def _stamp_skipped(self, stage: str, reason: str) -> None:
        """Stamp a stage that program rules kept from running at all.

        An asset whose stamp is already ``complete`` keeps it: the earlier
        result is still in the store, exactly as for a cached input.
        """
        stamps = dict.fromkeys(self._stage_assets(stage), ("skipped", reason))
        if not stamps:
            return
        for name in (COVERAGE_PORT, stage) if stage == "live" else (stage,):
            self.store.stamp_coverage(
                self.engagement, name, stamps, self.run_id, keep_complete=True
            )

    def _stamp_run_failure(self, stage: str, error: str) -> None:
        """The run died inside ``stage``: its inputs were not checked."""
        assets = sorted({_asset(key) for key in self._handled})
        if not stage or not assets:
            return
        failed = dict.fromkeys(assets, ("failed", f"run failed: {error}"[:300]))
        try:
            if stage == "live":
                scans = [o for o in self._outcomes if o.tool == Naabu.name]
                if scans:
                    self._stamp(COVERAGE_PORT, assets, scans)
                else:
                    self.store.stamp_coverage(self.engagement, COVERAGE_PORT, failed, self.run_id)
            self.store.stamp_coverage(self.engagement, stage, failed, self.run_id)
        except Exception:  # noqa: BLE001 - never mask the error that failed the run
            log.exception("pipeline: could not stamp coverage for failed stage %s", stage)

    def _prune_coverage(self, stage: str, candidates: Iterable[str]) -> None:
        """Drop stamps of assets that are no longer inputs of ``stage``.

        A host that stopped resolving or left the scope is not a gap in what
        was checked; keeping its stamp would list it as one for ever.
        """
        current = {_asset(key) for key in candidates}
        for name in (COVERAGE_PORT, stage) if stage == "live" else (stage,):
            for row in self.store.coverage(self.engagement, stage=name):
                asset = row["asset"]
                if asset in current or "/" in asset:  # "/" marks a repository, not a host
                    continue
                if self._wanted(asset):  # an --asset run only speaks for that asset
                    self.store.clear_coverage(self.engagement, asset, name)

    def _stage_assets(self, stage: str) -> list[str]:
        """The assets ``stage`` would take as input, from what the store holds now."""
        if stage == "enumerate":
            return sorted(self._enumeration_roots())
        if stage == "dns":
            hosts = {
                record.asset
                for record in self._records(RecordType.SUBDOMAIN)
                if self._wanted(record.asset) and not _is_address(record.asset)
            }
        elif stage in ("live", "fingerprint"):
            hosts = set(self._resolving_hosts())
        else:
            hosts = {
                record.asset
                for record in self._records(RecordType.HTTP_SERVICE)
                if self._wanted(record.asset)
            }
        return sorted(host for host in hosts if self.scope.allows(host))

    def _retire_vanished(self, stage: str, stats: StageStats, candidates: dict[str, str]) -> None:
        """Retire a stage's records for inputs that are no longer candidates.

        When an upstream fact disappears (a host stops resolving, a service
        goes away, an asset leaves the scope) the input it fed is simply not
        selected any more, so nothing would re-process it. Its records would
        stay "active" forever without this.
        """
        if stage not in RETIRING_STAGES:
            return
        for key in self.store.cached_keys(self.engagement, stage):
            if key in candidates or key.startswith("repo:"):
                continue
            if not self._wanted(host_of(key) or key):
                continue  # an --asset run only speaks for that asset
            stats.retired += self.store.retire_input(self.run_id, self.engagement, stage, key)

    def _complete(self, stage: str, stats: StageStats, inputs: dict[str, str]) -> None:
        if not inputs:
            return
        stats.retired += self.store.complete_inputs(
            self.run_id,
            self.engagement,
            stage,
            inputs,
            tool_versions=json.dumps(self._tool_versions, sort_keys=True),
            retire=stage in RETIRING_STAGES,
        )

    def _store(
        self,
        stage: str,
        stats: StageStats,
        tool: str,
        records: Iterable[tuple[Record, str]],
        *,
        version: str,
        raw_ref: str,
    ) -> int:
        """Scope-filter outputs, then write them. Returns how many were kept."""
        kept: list[tuple[Record, str]] = []
        allowed: dict[str, bool] = {}
        for record, input_key in records:
            verdict = allowed.get(record.asset)
            if verdict is None:
                verdict = bool(
                    self.scope.admit([record.asset], stage=stage, tool=tool, direction="output")
                )
                allowed[record.asset] = verdict
            if verdict:
                kept.append((record, input_key))
        written = self.store.write_records(
            self.run_id, self.engagement, stage, kept, tool_version=version, raw_ref=raw_ref
        )
        stats.records += written
        entry = stats.tools.setdefault(tool, {})
        entry["records"] = entry.get("records", 0) + written
        return written

    def _prepare_binary(
        self,
        stage: str,
        stats: StageStats,
        wrapper: Any,
        inputs: list[str],
        *,
        scope_inputs: bool = True,
        assets: Iterable[str] | None = None,
        limits: PipelineLimits | None = None,
        quiet: bool = False,
    ) -> _Job | None:
        """Everything before a scanner runs; ``None`` when it does not run at all.

        With ``quiet`` a scanner that cannot run notes nothing: the caller will
        try again the ordinary way (the early issue scan does this).
        """
        name = wrapper.name
        entry = stats.tools.setdefault(name, {})
        if self.scope.limits.passive_only and not wrapper.passive:
            if not quiet:
                entry["skipped"] = "passive_only"
                self._note(name, "skipped", "passive_only", assets)
            return None
        if scope_inputs:
            inputs = self.scope.admit(inputs, stage=stage, tool=name, direction="input")
        if not inputs:
            if not quiet:
                entry.setdefault("skipped", "no in-scope inputs")
            return None
        try:
            binary, version = self._resolver(name)
        except versions.ToolVersionError as exc:
            if not quiet:
                entry["error"] = str(exc)
                log.error("pipeline: %s unavailable: %s", name, exc)
                self._note(name, "failed", str(exc)[:200], assets)
            return None
        self._tool_versions[name] = version
        invocation = wrapper.invocation(
            binary, inputs, limits or self._target_limits, self._workdir()
        )
        raw_path, ref = self._raw_path(stage, name)
        return _Job(stage, stats, name, list(inputs), version, invocation, raw_path, ref, assets)

    def _execute(self, job: _Job) -> RunResult:
        return self._executor(job.name, job.invocation, job.raw_path)

    def _finish_binary(self, job: _Job, result: RunResult) -> tuple[str, str, str]:
        """Everything after a scanner ran: raw output registered, outcome noted, raw text read."""
        name, ref, version = job.name, job.ref, job.version
        self.store.register_raw_output(
            ref,
            run_id=self.run_id,
            engagement=self.engagement,
            stage=job.stage,
            tool=name,
            tool_version=version,
            argv=list(result.argv),
            sha256=result.sha256,
            bytes=result.size,
            exit_code=result.exit_code,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )
        entry = job.stats.tools.setdefault(name, {})
        entry.update(
            {
                "version": version,
                "exit_code": result.exit_code,
                "inputs": len(job.inputs),
                "raw_ref": ref,
                "seconds": round(result.finished_at - result.started_at, 2),
            }
        )
        if result.timed_out:
            entry["error"] = "timed out"
        elif result.exit_code not in (0, None) and result.size == 0:
            entry["error"] = result.stderr_tail[-300:] or f"exit {result.exit_code}"
        problem = ""
        if result.timed_out:
            problem = "timed out"
        elif result.exit_code not in (0, None):
            problem = f"exit {result.exit_code}"
        if not problem:
            self._note(name, "complete", assets=job.assets)
        elif result.size > 0:
            self._note(name, "partial", f"{problem}, output may be incomplete", job.assets)
        else:
            self._note(name, "failed", f"{problem}, no output", job.assets)
        try:
            raw = job.raw_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw = ""
        return raw, ref, version

    def _run_binary(
        self,
        stage: str,
        stats: StageStats,
        wrapper: Any,
        inputs: list[str],
        *,
        scope_inputs: bool = True,
        assets: Iterable[str] | None = None,
    ) -> tuple[str, str, str]:
        """Run one scanner. Returns ``(raw_text, raw_ref, version)``; raw is "" on failure.

        How the run went is noted for the coverage stamps: for every asset
        the stage handles, or for ``assets`` only when given.
        """
        job = self._prepare_binary(
            stage, stats, wrapper, inputs, scope_inputs=scope_inputs, assets=assets
        )
        if job is None:
            return "", "", ""
        return self._finish_binary(job, self._execute(job))

    def _run_together(
        self, stage: str, stats: StageStats, runs: list[tuple[Any, list[str], bool]]
    ) -> list[tuple[str, str, str]]:
        """Run several scanners of one stage at the same time; results in the order given.

        ``runs`` is ``(wrapper, inputs, scope_inputs)`` per scanner. Only use it
        for scanners that do not all send to the target: their request rates add up.
        """
        jobs = [
            self._prepare_binary(stage, stats, wrapper, inputs, scope_inputs=scoped)
            for wrapper, inputs, scoped in runs
        ]
        started = [job for job in jobs if job is not None]
        if not started:
            return [("", "", "")] * len(jobs)
        with ThreadPoolExecutor(max_workers=len(started)) as pool:
            futures = {id(job): pool.submit(self._execute, job) for job in started}
            results = {key: future.result() for key, future in futures.items()}
        return [
            ("", "", "") if job is None else self._finish_binary(job, results[id(job)])
            for job in jobs
        ]

    def _records(self, record_type: RecordType, *, limit: int = 1000) -> list[StoredRecord]:
        out: list[StoredRecord] = []
        offset = 0
        while True:
            page = self.store.query_records(
                self.engagement, record_type=record_type.value, limit=limit, offset=offset
            )
            out.extend(page)
            if len(page) < limit:
                return out
            offset += limit

    def _http(self, stage: str, tool: str) -> ScopedHTTP:
        return ScopedHTTP(
            self.scope, stage=stage, tool=tool, limiter=self._limiter, opener=self._http_opener
        )

    def _save_raw(self, stage: str, tool: str, text: str, suffix: str = "jsonl") -> str:
        path, ref = self._raw_path(stage, tool, suffix)
        path.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        path.write_text(text, encoding="utf-8")
        self._tool_versions.setdefault(tool, versions.BUILTIN_VERSION)
        self.store.register_raw_output(
            ref,
            run_id=self.run_id,
            engagement=self.engagement,
            stage=stage,
            tool=tool,
            tool_version=versions.BUILTIN_VERSION,
            argv=[],
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            bytes=len(text.encode("utf-8")),
            exit_code=0,
            started_at=now,
            finished_at=now,
        )
        return ref

    # ── stage 1: subdomain enumeration ──────────────────────────────

    def _stage_enumerate(self, stats: StageStats) -> None:
        seeds = self.scope.seeds()
        # Hosts and addresses the scope names outright are assets as-is.
        explicit = [
            (Record(RecordType.SUBDOMAIN, host, host, "scope", attrs={"explicit": True}), host)
            for host in (*seeds.hosts, *seeds.addresses)
            if self._wanted(host)
        ]
        if explicit:
            self._store("enumerate", stats, "scope", explicit, version="", raw_ref="")
        roots = {root: _hash(root, self.scope.digest) for root in self._enumeration_roots()}
        pending = self._pending("enumerate", stats, roots)
        if not pending:
            return
        targets = list(pending)
        # All three sources are passive (none sends to the target), so they run
        # at the same time: the two scanners and the certificate log lookups.
        with ThreadPoolExecutor(max_workers=4) as pool:
            bodies = {
                root: pool.submit(self._passive_fetch, crtsh.query_url(root)) for root in targets
            }
            wrappers = (Subfinder(), Amass())
            # Enumeration roots are derived from in_scope patterns, not scan
            # targets, so they are not themselves scope-filtered; every name
            # the tools return is.
            outputs = self._run_together(
                "enumerate", stats, [(wrapper, targets, False) for wrapper in wrappers]
            )
            fetched = {root: future.result() for root, future in bodies.items()}
        for wrapper, (raw, ref, version) in zip(wrappers, outputs, strict=True):
            if raw:
                self._store(
                    "enumerate",
                    stats,
                    wrapper.name,
                    ((r, self._root_of(r.asset, targets)) for r in wrapper.parse(raw)),
                    version=version,
                    raw_ref=ref,
                )
        for root in targets:
            body = fetched[root]
            entry = stats.tools.setdefault(crtsh.NAME, {"version": versions.BUILTIN_VERSION})
            if body is None:
                entry["error"] = "crt.sh unreachable"
                self._note(crtsh.NAME, "failed", "crt.sh unreachable", [root])
                continue
            self._note(crtsh.NAME, "complete", assets=[root])
            text = body.decode("utf-8", "replace")
            ref = self._save_raw("enumerate", f"{crtsh.NAME}-{root}", text, "json")
            self._store(
                "enumerate",
                stats,
                crtsh.NAME,
                ((r, root) for r in crtsh.parse(text, root=root)),
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )
        self._guess_subdomains(stats, targets)
        self._complete("enumerate", stats, pending)

    def _guess_subdomains(self, stats: StageStats, roots: list[str]) -> None:
        """Opt-in (``pipeline.subdomain_guess``): common labels and permutations of
        the hosts found, resolved through dnsx; only names that answer with more
        than a wildcard's echo are kept. Skipped in a passive run."""
        limits = self.scope.limits
        if not limits.subdomain_guess:
            return
        entry = stats.tools.setdefault(subguess.NAME, {"version": versions.BUILTIN_VERSION})
        if limits.passive_only:
            entry["skipped"] = "passive_only"
            self._note(subguess.NAME, "skipped", "passive_only", roots)
            return
        known = [r.asset for r in self._records(RecordType.SUBDOMAIN)]
        guessed = 0
        for root in roots:
            names = subguess.candidates(root, known, allowed=self.scope.allows)
            if not names:
                continue
            probes = [p for p in subguess.canaries(root) if self.scope.allows(p)]
            answers, ref, _version, problem = self._dnsx_resolve(
                "enumerate", f"guess-{root}", names + probes
            )
            guessed += len(names)
            if problem:
                entry.setdefault("errors", {})[root] = problem
                self._note(subguess.NAME, "failed", problem, [root])
                continue
            self._note(subguess.NAME, "complete", assets=[root])
            found = subguess.keep(answers, probes)
            if found:
                self._store(
                    "enumerate",
                    stats,
                    subguess.NAME,
                    (
                        (Record(RecordType.SUBDOMAIN, name, name, subguess.NAME), root)
                        for name in found
                    ),
                    version=versions.BUILTIN_VERSION,
                    raw_ref=ref,
                )
        entry["guessed"] = guessed

    def _enumeration_roots(self) -> list[str]:
        """Enumeration roots selected by ``only_asset`` (all of them without it)."""
        return [
            root
            for root in self.scope.seeds().roots
            if not self.only_asset
            or self.only_asset == root
            or self.only_asset.endswith("." + root)
        ]

    @staticmethod
    def _root_of(host: str, roots: list[str]) -> str:
        for root in sorted(roots, key=len, reverse=True):
            if host == root or host.endswith("." + root):
                return root
        return host

    # ── stage 2: DNS ────────────────────────────────────────────────

    def _stage_dns(self, stats: StageStats) -> None:
        hosts: dict[str, str] = {}
        for record in self._records(RecordType.SUBDOMAIN):
            if self._wanted(record.asset) and not _is_address(record.asset):
                hosts[record.asset] = _hash(record.asset)
        hosts = {
            host: digest
            for host, digest in hosts.items()
            if self.scope.admit([host], stage="dns", tool="dnsx", direction="input")
        }
        pending = self._pending("dns", stats, hosts)
        self._retire_wildcard_roots(stats)
        if not pending:
            return
        raw, ref, version = self._run_binary("dns", stats, self._dnsx, list(pending))
        if not ref:
            return  # tool unavailable: leave the cache untouched so the next run retries
        records = list(self._dnsx.parse(raw))
        # A target the operator named that does not resolve is a failure to
        # report, not a clean result: no later stage will ever look at it. (An
        # enumerated subdomain that does not resolve is just a stale name.)
        answered = {r.asset for r in records if r.attrs.get("rtype") in ("A", "AAAA", "CNAME")}
        # The apex of a wildcard entry is an enumeration root and often has no
        # address of its own; that is not a failure.
        named = self._named_hosts() - set(self._enumeration_roots())
        named |= {host_of(url) for url in self.scope.limits.seed_urls}
        unresolved = sorted(host for host in named & set(pending) if host not in answered)
        for host in unresolved:
            if host not in answered:
                self._note(
                    self._dnsx.name,
                    "failed",
                    "the scoped name did not resolve, so nothing was checked on it",
                    assets=[host],
                )
        # Names that resolve only because their zone answers for everything are
        # dropped here, before anything is stored: no later stage sees them.
        dropped, unsettled = self._wildcard_drops(stats, list(pending), records)
        self._store(
            "dns",
            stats,
            self._dnsx.name,
            ((r, r.asset) for r in records if r.asset not in dropped),
            version=version,
            raw_ref=ref,
        )
        # A name whose wildcard check failed stays out of the cache, so the
        # next run resolves and checks it again.
        # A named target that did not resolve is looked up again on every run.
        retry = unsettled | set(unresolved)
        self._complete(
            "dns", stats, {key: digest for key, digest in pending.items() if key not in retry}
        )

    def _named_hosts(self) -> set[str]:
        """Hosts the operator named outright: exact scope entries and seed-URL hosts."""
        return {
            *self.scope.seeds().hosts,
            *(host_of(url) for url in self.scope.limits.seed_urls),
        }

    # Where the random wildcard-probe labels come from; a seeded
    # ``random.Random`` in tests.
    _wildcard_rng: Any = secrets

    def _wildcard_drops(
        self, stats: StageStats, names: list[str], records: list[Record]
    ) -> tuple[set[str], set[str]]:
        """``(dropped, unsettled)`` among the names this run resolved.

        ``dropped`` are the names only a wildcard record answers for. Each is
        logged as a scope drop (``wildcard_dns``) and loses its DNS coverage
        stamp: a made-up name is not an asset, so it is not a gap in what was
        checked either. ``unsettled`` are the names a failed wildcard check
        left undecided; they are stamped ``partial``, never read as clean.
        """
        roots = self._enumeration_roots()
        resolved: dict[str, set[str]] = {name: set() for name in names}
        for record in records:
            if record.asset in resolved and record.attrs.get("rtype") in ADDRESS_RTYPES:
                resolved[record.asset].add(str(record.attrs["data"]))
        # Hosts the operator named outright are kept whatever they resolve to.
        explicit = self._named_hosts()
        entry = stats.tools.setdefault(self._dnsx.name, {})
        dropped: set[str] = set()
        unsettled: set[str] = set()
        for root in roots:
            group = [name for name in names if self._root_of(name, roots) == root]
            if not group:
                continue
            info, problem = self._wildcard_info(stats, root, group, resolved, explicit)
            if problem:
                # Only names the filter could have dropped are in doubt.
                doubtful = [n for n in group if n != root and n not in explicit and resolved[n]]
                unsettled.update(doubtful)
                self._note(
                    self._dnsx.name, "partial", f"wildcard check failed ({problem})", doubtful
                )
            if info is None or not info.is_wildcard:
                continue
            entry.setdefault("wildcard_roots", []).append(root)
            dropped.update(wildcard.filter_names(group, info, resolved, explicit)[1])
        if not dropped:
            return dropped, unsettled
        stamped = {row["asset"] for row in self.store.coverage(self.engagement, stage="dns")}
        for name in names:
            if name not in dropped:
                continue
            self._log_drop("dns", self._dnsx.name, "output", name, wildcard.REASON)
            if name in stamped:
                self.store.clear_coverage(self.engagement, name, "dns")
        self._handled = [key for key in self._handled if key not in dropped]
        entry["wildcard_dropped"] = len(dropped)
        return dropped, unsettled

    def _wildcard_info(
        self,
        stats: StageStats,
        root: str,
        names: list[str],
        resolved: dict[str, set[str]],
        explicit: set[str],
    ) -> tuple[wildcard.WildcardInfo | None, str]:
        """``(verdict, problem)`` for ``root``; the verdict is cached, fresh or ``None``.

        One row per root in the stage cache holds the last verdict; it is
        reused like any cached input (same resolvers, younger than
        ``max_age``, not forced). Otherwise the root is probed when this
        batch's answers look like a wildcard's, or when it was one last time.
        No verdict means nothing is dropped. ``problem`` is set when the
        probes could not be resolved.
        """
        input_hash = _hash(root, self._resolvers)
        cached = self.store.cached_input(self.engagement, WILDCARD_STAGE, root)
        known = _cached_wildcard(root, cached)
        if (
            known is not None
            and cached is not None
            and not self.force
            and cached["input_hash"] == input_hash
            and time.time() - float(cached["completed_at"]) < self.max_age
        ):
            return known, ""
        was_wildcard = known is not None and known.is_wildcard
        if not was_wildcard and not wildcard.suspected(names, root, resolved, explicit):
            return None, ""
        info, ref, version, problem = self._probe_wildcard(root)
        entry = stats.tools.setdefault(self._dnsx.name, {})
        if info is None:
            # Unknown is not "no wildcard". Nothing is cached, so the next run
            # probes again; until then the last verdict (if any) stands.
            entry.setdefault("wildcard_errors", {})[root] = problem
            log.warning("pipeline: wildcard check for %s failed: %s", root, problem)
            return known, problem
        if info.is_wildcard and self.scope.admit(
            [root], stage="dns", tool=self._dnsx.name, direction="output"
        ):
            record = Record(
                RecordType.DNS_RECORD,
                root,
                f"WILDCARD *.{root}",
                self._dnsx.name,
                attrs={
                    "rtype": "WILDCARD",
                    "data": f"*.{root}",
                    "wildcard": True,
                    "addresses": sorted(info.addresses),
                },
            )
            written = self.store.write_records(
                self.run_id,
                self.engagement,
                WILDCARD_STAGE,
                [(record, root)],
                tool_version=version,
                raw_ref=ref,
            )
            stats.records += written
            entry["records"] = entry.get("records", 0) + written
        # Caches the verdict, and retires the root's wildcard record when this
        # probe no longer reports one.
        stats.retired += self.store.complete_inputs(
            self.run_id,
            self.engagement,
            WILDCARD_STAGE,
            {root: input_hash},
            tool_versions=json.dumps(
                {
                    "dnsx": version,
                    "wildcard": info.is_wildcard,
                    "addresses": sorted(info.addresses),
                },
                sort_keys=True,
            ),
        )
        return info, ""

    def _probe_wildcard(self, root: str) -> tuple[wildcard.WildcardInfo | None, str, str, str]:
        """Probe ``root`` through the stage's own resolver path.

        Returns ``(info, raw_ref, version, problem)``; ``info`` is ``None``
        when the probes could not be resolved (``problem`` says why). The
        probes use the same dnsx wrapper as the stage, so the same resolvers
        and rate limit, and they pass the scope filter like any other input.
        Their raw output is kept under its own reference.
        """
        run = {"ref": "", "version": "", "problem": ""}

        def resolve(names: list[str]) -> dict[str, set[str]]:
            answers, ref, version, problem = self._dnsx_resolve("dns", f"wildcard-{root}", names)
            run["ref"], run["version"] = ref or run["ref"], version or run["version"]
            run["problem"] = run["problem"] or problem  # one failed probe settles nothing
            return answers

        info = wildcard.detect(root, resolve, rng=self._wildcard_rng)
        return (None if run["problem"] else info), run["ref"], run["version"], run["problem"]

    def _dnsx_resolve(
        self, stage: str, label: str, names: list[str]
    ) -> tuple[dict[str, set[str]], str, str, str]:
        """Resolve ``names`` with dnsx (same resolvers and rate as the DNS stage).

        Returns ``({name: addresses}, raw_ref, version, problem)``; ``problem``
        says why nothing could be resolved. Every name must pass the scope
        filter, or nothing is sent.
        """
        tool = self._dnsx.name
        answers: dict[str, set[str]] = {name: set() for name in names}
        if self.scope.admit(names, stage=stage, tool=tool, direction="input") != names:
            return answers, "", "", "probe names are not in scope"
        try:
            binary, version = self._resolver(tool)
        except versions.ToolVersionError as exc:
            return answers, "", "", str(exc)[:200]
        invocation = self._dnsx.invocation(binary, names, self.scope.limits, self._workdir())
        raw_path, ref = self._raw_path(stage, f"{tool}-{label}")
        result = self._executor(tool, invocation, raw_path)
        self.store.register_raw_output(
            ref,
            run_id=self.run_id,
            engagement=self.engagement,
            stage=stage,
            tool=tool,
            tool_version=version,
            argv=list(result.argv),
            sha256=result.sha256,
            bytes=result.size,
            exit_code=result.exit_code,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )
        if result.timed_out:
            return answers, ref, version, "timed out"
        if result.exit_code not in (0, None):
            return answers, ref, version, f"exit {result.exit_code}"
        try:
            raw = raw_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return answers, ref, version, "no output"
        for record in self._dnsx.parse(raw):
            if record.asset in answers and record.attrs.get("rtype") in ADDRESS_RTYPES:
                answers[record.asset].add(str(record.attrs["data"]))
        return answers, ref, version, ""

    def _retire_wildcard_roots(self, stats: StageStats) -> None:
        """Forget the verdict (and wildcard record) of a root the scope no longer names."""
        if self.only_asset:
            return  # an --asset run only speaks for that asset
        roots = set(self._enumeration_roots())
        for root in self.store.cached_keys(self.engagement, WILDCARD_STAGE):
            if root not in roots:
                stats.retired += self.store.retire_input(
                    self.run_id, self.engagement, WILDCARD_STAGE, root
                )

    # ── stage 3: live hosts and ports ───────────────────────────────

    def _seed_urls(self) -> list[str]:
        """Operator-named URLs that pass the scope filter."""
        return self.scope.admit(
            list(self.scope.limits.seed_urls), stage="live", tool="seed", direction="input"
        )

    def _resolving_hosts(self) -> dict[str, str]:
        """Hosts with address records, mapped to a hash of those records."""
        grouped: dict[str, list[str]] = {}
        for record in self._records(RecordType.DNS_RECORD):
            if record.attrs.get("rtype") in ("A", "AAAA", "CNAME"):
                grouped.setdefault(record.asset, []).append(record.value)
        hosts = {host: _hash(sorted(values)) for host, values in grouped.items()}
        for record in self._records(RecordType.SUBDOMAIN):
            if _is_address(record.asset):
                hosts[record.asset] = _hash(record.asset)
        return {host: digest for host, digest in hosts.items() if self._wanted(host)}

    def _stage_live(self, stats: StageStats) -> None:
        candidates = {
            host: digest
            for host, digest in self._resolving_hosts().items()
            if self.scope.admit([host], stage="live", tool="httpx", direction="input")
        }
        self._live_candidates = candidates
        pending = self._pending("live", stats, candidates)
        if not pending:
            return
        hosts = list(pending)
        ports: dict[str, list[int]] = {}
        naabu = Naabu(resolvers=self._resolvers)
        if self.scope.limits.port_scan:
            raw, ref, version = self._run_binary("live", stats, naabu, hosts)
            if raw:
                parsed = list(naabu.parse(raw))
                for record in parsed:
                    ports.setdefault(record.asset, []).append(int(record.attrs["port"]))
                self._store(
                    "live",
                    stats,
                    naabu.name,
                    ((r, r.asset) for r in parsed),
                    version=version,
                    raw_ref=ref,
                )
        else:
            stats.tools.setdefault(naabu.name, {})["skipped"] = PORT_SCAN_DISABLED
            self._note(naabu.name, "skipped", PORT_SCAN_DISABLED)

        # A target the operator gave as a URL names its own port; probe it even
        # when the port scan is off or did not cover that port.
        for seed in self._seed_urls():
            parts = urlsplit(seed)
            if parts.hostname in pending and parts.port:
                ports.setdefault(parts.hostname, []).append(parts.port)

        targets: list[str] = []
        for host in hosts:
            open_ports = sorted(set(ports.get(host, [])))
            targets.extend(
                f"{host}:{port}" for port in open_ports
            ) if open_ports else targets.append(host)
        httpx = Httpx(resolvers=self._resolvers)
        raw, ref, version = self._run_binary("live", stats, httpx, targets)
        if not ref:
            return
        services: list[tuple[Record, str]] = []
        self._fingerprints = []
        for record in httpx.parse(raw):
            if record.type == RecordType.HTTP_SERVICE:
                services.append((record, record.asset))
            else:
                self._fingerprints.append((record, record.asset))
        self._httpx_ref = (ref, version)
        self._store("live", stats, httpx.name, services, version=version, raw_ref=ref)
        self._complete("live", stats, pending)
        self._fingerprint_inputs = dict(pending)

    # ── stage 4: fingerprints ───────────────────────────────────────

    def _stage_fingerprint(self, stats: StageStats) -> None:
        """Technology, TLS and header records from the stage-3 probe (no new requests)."""
        inputs = getattr(self, "_fingerprint_inputs", {})
        stats.inputs += len(inputs)
        stats.processed += len(inputs)
        if hasattr(self, "_live_candidates"):  # absent when the live stage did not run
            self._retire_vanished("fingerprint", stats, self._live_candidates)
            self._prune_coverage("fingerprint", self._live_candidates)
        # Fingerprints are read off the live probe, so their coverage is the
        # probe's: skipped, failed or partial there means the same here.
        if self._live_grades:
            self.store.stamp_coverage(
                self.engagement, "fingerprint", self._live_grades, self.run_id
            )
        if not inputs:
            return
        ref, version = self._httpx_ref
        self._store("fingerprint", stats, "httpx", self._fingerprints, version=version, raw_ref=ref)
        self._complete("fingerprint", stats, inputs)

    # ── stage 5: URLs and endpoints ─────────────────────────────────

    def _live_services(self) -> list[StoredRecord]:
        return [
            record
            for record in self._records(RecordType.HTTP_SERVICE)
            if self._wanted(record.asset)
            and self.scope.admit([record.value], stage="urls", tool="katana", direction="input")
        ]

    def _stage_urls(self, stats: StageStats) -> None:
        services = self._live_services()
        candidates = {record.value: record.content_hash for record in services}
        pending = self._pending("urls", stats, candidates)
        self._processed_services = list(pending)
        if not pending:
            return
        self._start_early_issues()
        katana = Katana(resolvers=self._resolvers)
        live_hosts = {host_of(url) for url in pending}
        crawl_from = list(pending) + [
            seed
            for seed in self._seed_urls()
            if host_of(seed) in live_hosts
            and seed.rstrip("/") not in {u.rstrip("/") for u in pending}
        ]
        hosts = sorted({host_of(url) for url in pending if not _is_address(host_of(url))})
        # The archive lookups ask public archives, never the target, so they run
        # while the crawler does; only the crawler counts against the rate limit.
        runs: list[tuple[Any, list[str], bool]] = [(katana, crawl_from, True)]
        if hosts:
            runs += [(Gau(), hosts, True), (Waybackurls(), hosts, True)]
        for (wrapper, _inputs, _scoped), (raw, ref, version) in zip(
            runs, self._run_together("urls", stats, runs), strict=True
        ):
            if raw:
                self._store(
                    "urls",
                    stats,
                    wrapper.name,
                    ((r, r.asset) for r in wrapper.parse(raw)),
                    version=version,
                    raw_ref=ref,
                )
        self._parse_javascript(stats, {host_of(url) for url in pending})
        self._complete("urls", stats, pending)

    def _parse_javascript(self, stats: StageStats, hosts: set[str]) -> None:
        entry = stats.tools.setdefault(jsparse.NAME, {"version": versions.BUILTIN_VERSION})
        if self.scope.limits.passive_only:
            entry["skipped"] = "passive_only"
            self._note(jsparse.NAME, "skipped", "passive_only")
            return
        js_files = [
            r
            for r in self._records(RecordType.JS_FILE)
            if r.asset in hosts and r.attrs.get("kind") != "source_map"
        ][:MAX_JS_FILES]
        tally: dict[str, list[int]] = {host: [0, 0] for host in hosts}
        if not js_files:
            self._note_requests(jsparse.NAME, tally)
            return
        client = self._http("urls", jsparse.NAME)
        js_dir = self._workdir() / "js"
        js_dir.mkdir(parents=True, exist_ok=True)
        fetched = 0
        lines: list[str] = []
        pairs: list[tuple[Record, str]] = []
        source_maps: dict[str, str] = {}  # map URL -> the script that names it
        limited: dict[str, dict[str, int]] = {}  # asset -> {limit hit: files}
        # Scripts a fetched script loads (lazy chunks, imports) join the queue,
        # up to MAX_JS_FILES in all.
        queue = [(r.value, r.asset) for r in js_files]
        seen = {value for value, _asset in queue}
        loaded = 0
        index = 0
        while index < len(queue) and index < MAX_JS_FILES:
            js_url, js_asset = queue[index]
            index += 1
            try:
                response = client.get(js_url)
            except OutOfScopeRequest:
                continue
            tally[js_asset][0] += 1
            if response is None:  # transport error: the script was not read
                tally[js_asset][1] += 1
                continue
            if response.status != 200 or not response.body:
                continue
            if response.headers.get("content-type", "").startswith(("video/", "image/")):
                continue  # a .ts video segment, not TypeScript
            fetched += 1
            body = response.body[:MAX_JS_BYTES]
            name = hashlib.sha256(js_url.encode()).hexdigest()[:24] + ".js"
            (js_dir / name).write_bytes(body)
            self._js_sources[name] = js_url
            script = body.decode("utf-8", "replace")
            for endpoint in jsparse.parse(script, js_url=js_url):
                lines.append(
                    json.dumps(
                        {
                            "js": js_url,
                            "url": endpoint.value,
                            "literal": endpoint.attrs["literal"],
                        }
                    )
                )
                pairs.append(
                    (
                        Record(
                            endpoint.type,
                            endpoint.asset,
                            endpoint.value,
                            endpoint.source_tool,
                            attrs=endpoint.attrs,
                            raw_line=len(lines),
                        ),
                        endpoint.asset,
                    )
                )
            # Source maps, DOM sinks, dependency names. A file too large to
            # analyse leaves its host's stamp partial, not "nothing found".
            size = MAX_JS_BYTES + 1 if response.truncated else len(response.body)
            analysis = jsparse.analyze(script, js_url=js_url, size=size)
            if analysis.partial:
                limited.setdefault(js_asset, {}).setdefault(analysis.partial, 0)
                limited[js_asset][analysis.partial] += 1
            for finding in analysis.findings:
                lines.append(json.dumps({"js": js_url, **finding.attrs}, sort_keys=True))
                pairs.append((_with_line(finding, len(lines)), finding.asset))
            for map_url in analysis.source_maps:
                source_maps.setdefault(map_url, js_url)
            for ref in jsparse.script_references(script, js_url=js_url):
                ref_host = host_of(ref)
                if ref in seen or ref_host not in hosts or not self.scope.allows(ref):
                    continue
                seen.add(ref)
                queue.append((ref, ref_host))
                loaded += 1
                lines.append(json.dumps({"js": js_url, "loads": ref}))
                pairs.append(
                    (
                        Record(
                            RecordType.JS_FILE,
                            ref_host,
                            ref,
                            jsparse.NAME,
                            attrs={"found_in": js_url, "kind": "loaded"},
                            raw_line=len(lines),
                        ),
                        ref_host,
                    )
                )
        entry["fetched"] = fetched
        entry["loaded_scripts"] = loaded
        entry["source_maps"] = self._fetch_source_maps(
            client, source_maps, tally, lines, pairs, entry
        )
        self._note_requests(jsparse.NAME, tally)
        for asset, reasons in limited.items():
            detail = "; ".join(f"{count} {reason}" for reason, count in reasons.items())
            self._note(jsparse.NAME, "partial", detail, assets=[asset])
        if pairs:
            ref = self._save_raw("urls", jsparse.NAME, "\n".join(lines) + "\n")
            self._store(
                "urls", stats, jsparse.NAME, pairs, version=versions.BUILTIN_VERSION, raw_ref=ref
            )

    def _fetch_source_maps(
        self,
        client: ScopedHTTP,
        maps: dict[str, str],
        tally: dict[str, list[int]],
        lines: list[str],
        pairs: list[tuple[Record, str]],
        entry: dict[str, Any] | None = None,
    ) -> int:
        """Request each source map the scripts name, once, through the scoped
        client: an out-of-scope map URL is refused before anything is sent.
        Returns how many maps were recorded. The map record keeps no source
        content; the original files a map carries are rebuilt under the run's
        work directory and scanned (:meth:`_recover_source`)."""
        found = 0
        for map_url, js_url in maps.items():
            try:
                response = client.get(map_url)
            except OutOfScopeRequest:
                continue
            counts = tally.get(host_of(map_url))
            if counts is not None:
                counts[0] += 1
            if response is None:
                if counts is not None:
                    counts[1] += 1
                continue
            if response.status != 200 or response.truncated or not response.body:
                continue
            try:
                document = response.json()
            except (ValueError, RecursionError):
                continue
            record = jsparse.source_map_record(map_url, document, js_url=js_url)
            if record is None:
                continue
            found += 1
            lines.append(json.dumps({"js": js_url, "map": record.value, **record.attrs}))
            pairs.append((_with_line(record, len(lines)), record.asset))
            if found <= MAX_RECOVERED_MAPS:
                self._recover_source(document, record.value, js_url, lines, pairs, entry)
        return found

    def _recover_source(
        self,
        document: Any,
        map_url: str,
        js_url: str,
        lines: list[str],
        pairs: list[tuple[Record, str]],
        entry: dict[str, Any] | None,
    ) -> None:
        """Rebuild a map's original files (``sourcesContent``) and scan them with fixed rules.

        No request: the map was already fetched. Files go under
        ``work/<engagement>/<run>/recovered/<hash of the map URL>``; nothing in
        them is run. Each hit is a ``js_finding`` record of kind
        ``recovered_source``, a lead that still needs a live proof.
        """
        name = hashlib.sha256(map_url.encode()).hexdigest()[:24]
        dest = self._workdir() / "recovered" / name
        result = recovered.analyze(
            document,
            map_url=map_url,
            js_url=js_url,
            dest=dest,
            in_scope=self.scope.allows,
        )
        if entry is not None:
            entry["recovered_files"] = entry.get("recovered_files", 0) + len(result.files)
            entry["recovered_findings"] = entry.get("recovered_findings", 0) + len(result.findings)
        if result.partial:
            self._note(jsparse.NAME, "partial", result.partial, assets=[host_of(map_url)])
        for finding in result.findings:
            lines.append(json.dumps({"map": map_url, **finding.attrs}, sort_keys=True))
            pairs.append((_with_line(finding, len(lines)), finding.asset))

    # ── stage 6: web recon ──────────────────────────────────────────

    def _service_origins(self, stage: str, tool: str) -> dict[str, list[StoredRecord]]:
        """``{origin: its live services}`` for the in-scope services this run wants."""
        origins: dict[str, list[StoredRecord]] = {}
        for record in self._records(RecordType.HTTP_SERVICE):
            if not self._wanted(record.asset):
                continue
            origin = _origin(record.value)
            if self.scope.admit([origin], stage=stage, tool=tool, direction="input"):
                origins.setdefault(origin, []).append(record)
        return origins

    def _page_urls(self, *, operations: bool = True) -> list[tuple[str, str]]:
        """``(url, tool that found it)`` for every stored page and endpoint.

        With ``operations``, API operations too; the web stage leaves them
        out, because the API description stage that finds them runs after it.
        """
        pages: list[tuple[str, str]] = []
        for kind in (RecordType.URL, RecordType.ENDPOINT):
            pages += [(r.value, r.source_tool) for r in self._records(kind)]
        if operations:
            for record in self._records(RecordType.API_OPERATION):
                url = str(record.attrs.get("url") or "")
                if url:
                    pages.append((url, record.source_tool))
        return pages

    @staticmethod
    def _digest(*parts: Iterable[str]) -> str:
        """A stable hash of several string collections (a stage input's hash)."""
        sha = hashlib.sha256()
        for part in parts:
            for item in sorted(part):
                sha.update(item.encode("utf-8", "replace") + b"\0")
            sha.update(b"\1")
        return sha.hexdigest()

    def _fetch(self, client: ScopedHTTP, url: str, sent: list[int]) -> Response | None:
        """One GET through the scoped client; counts it, ``None`` if refused or unanswered."""
        try:
            response = client.get(url)
        except OutOfScopeRequest:
            return None
        sent[0] += 1
        if response is None:
            sent[1] += 1
        return response

    def _stage_web(self, stats: StageStats) -> None:
        """Known files, security headers and the sign-in pages of every live origin.

        ``robots.txt``, ``sitemap.xml`` and ``security.txt`` are fetched (one
        GET each, plus nested sitemaps); everything else is read off records
        the earlier stages stored. URLs the known files name become ``url``
        records, so the API description stage and the tests see them.
        """
        origins = self._service_origins("web", webrecon.KNOWN_FILES_TOOL)
        headers = webrecon.headers_by_service(self._records(RecordType.HEADER))
        pages = self._page_urls(operations=False)
        candidates = {
            origin: self._digest(
                [s.content_hash for s in services],
                [
                    f"{u}|{n}|{v}"
                    for u, h in headers.items()
                    if _origin(u) == origin
                    for n, v in h.items()
                ],
                # What this stage adds itself is not part of its input.
                [u for u, t in pages if _origin(u) == origin and t != webrecon.KNOWN_FILES_TOOL],
            )
            for origin, services in origins.items()
        }
        pending = self._pending("web", stats, candidates)
        if not pending:
            return
        known = {
            r.value
            for kind in (RecordType.URL, RecordType.JS_FILE, RecordType.ENDPOINT)
            for r in self._records(kind)
            if r.source_tool != webrecon.KNOWN_FILES_TOOL
        }
        found: list[tuple[Record, str]] = []
        found_lines: list[str] = []
        if self.scope.limits.passive_only:
            stats.tools.setdefault(webrecon.KNOWN_FILES_TOOL, {})["skipped"] = "passive_only"
            self._note(webrecon.KNOWN_FILES_TOOL, "skipped", "passive_only")
        else:
            client = self._http("web", webrecon.KNOWN_FILES_TOOL)
            tally: dict[str, list[int]] = {}
            for origin in pending:
                sent = tally.setdefault(_asset(origin), [0, 0])
                sitemaps = [origin + webrecon.SITEMAP]
                listed: list[str] = []
                robots = self._fetch(client, origin + webrecon.ROBOTS, sent)
                if robots is not None and robots.status == 200:
                    paths, named = webrecon.parse_robots(robots.text(), origin + "/")
                    listed += paths
                    sitemaps += named
                    found_lines.append(
                        json.dumps({"url": robots.url, "paths": paths, "sitemaps": named})
                    )
                queue = list(dict.fromkeys(sitemaps))
                read = 0
                while queue and read <= webrecon.MAX_NESTED_SITEMAPS:
                    url = queue.pop(0)
                    if url.lower().endswith(".gz"):
                        continue
                    read += 1
                    response = self._fetch(client, url, sent)
                    if response is None or response.status != 200:
                        continue
                    urls, nested = webrecon.parse_sitemap(response.text())
                    listed += urls
                    queue += [n for n in nested if n not in queue]
                    if urls or nested:
                        found_lines.append(
                            json.dumps({"url": response.url, "urls": len(urls), "nested": nested})
                        )
                security = self._fetch(client, origin + webrecon.SECURITY_TXT, sent)
                if (
                    security is not None
                    and security.status == 200
                    and webrecon.is_security_txt(security.text())
                ):
                    found.append((webrecon.security_txt_record(security.url), origin))
                new = [u for u in dict.fromkeys(listed) if u not in known]
                found += [
                    (record, origin) for record in webrecon.url_records(new, source="known_files")
                ]
            stats.tools.setdefault(webrecon.KNOWN_FILES_TOOL, {})["requests"] = client.requests_sent
            self._note_requests(webrecon.KNOWN_FILES_TOOL, tally)
        if found:
            ref = self._save_raw(
                "web", webrecon.KNOWN_FILES_TOOL, "\n".join(found_lines or ["{}"]) + "\n"
            )
            self._store(
                "web",
                stats,
                webrecon.KNOWN_FILES_TOOL,
                found,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )

        header_records = [
            (record, _origin(service_url))
            for service_url, sent_headers in sorted(headers.items())
            if _origin(service_url) in pending
            for record in webrecon.header_findings(service_url, sent_headers)
        ]
        self._note(webrecon.HEADERS_TOOL, "complete")
        if header_records:
            lines = [
                json.dumps({"value": r.value, **r.attrs}, sort_keys=True)
                for r, _o in header_records
            ]
            ref = self._save_raw("web", webrecon.HEADERS_TOOL, "\n".join(lines) + "\n")
            self._store(
                "web",
                stats,
                webrecon.HEADERS_TOOL,
                header_records,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )

        added = [(r.value, "known_files") for r, _o in found if r.type is RecordType.URL]
        surface = [
            (record, _origin(record.value))
            for record in webrecon.surface_records(
                (url, tool) for url, tool in [*pages, *added] if _origin(url) in pending
            )
        ]
        self._note(webrecon.SURFACE_TOOL, "complete")
        if surface:
            lines = [json.dumps({"url": r.value, **r.attrs}, sort_keys=True) for r, _o in surface]
            ref = self._save_raw("web", webrecon.SURFACE_TOOL, "\n".join(lines) + "\n")
            self._store(
                "web",
                stats,
                webrecon.SURFACE_TOOL,
                surface,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )
        self._complete("web", stats, pending)

    # ── stage 7: API specifications ─────────────────────────────────

    #: ``<control>/<engagement>``, where the operator's ``contracts/`` directory
    #: is. ``None``: the control root the environment names.
    control_dir: Path | None = None

    def _load_contracts(self, stats: StageStats, *, refresh: bool) -> None:
        """Store the operator's API contracts (``pipeline.api_contracts``). No request.

        A contract is one input of its own, cached on the hash of its file: an
        unchanged file is hashed and not parsed again. All of them are parsed
        again when one changed, went away or is stale, when the run is forced,
        and when the stage is about to re-probe an origin (``refresh``): a
        record a contract and a published spec both report then stays active
        while either of them reports it.
        """
        from buggy.pipeline.tools import contracts  # noqa: PLC0415 - only this step uses it

        entries = {contracts.key(entry): entry for entry in self.scope.limits.api_contracts}
        gone = set(self.store.cached_keys(self.engagement, contracts.CACHE_STAGE)) - set(entries)
        if not entries and not gone:
            return
        entry_stats = stats.tools.setdefault(contracts.NAME, {})
        directory = self.control_dir or contracts.control_dir_for(self.engagement)
        errors: list[str] = []
        files: dict[str, tuple[bytes, str]] = {}  # key -> (content, input hash)
        refresh = refresh or self.force or bool(gone)
        now = time.time()
        for key, entry in entries.items():
            try:
                data = contracts.read(directory, entry)
            except contracts.ContractError as exc:
                errors.append(f"{entry['path']}: {exc}")
                continue
            digest = _hash(hashlib.sha256(data).hexdigest(), entry, self.scope.digest)
            files[key] = (data, digest)
            cached = self.store.cached_input(self.engagement, contracts.CACHE_STAGE, key)
            refresh = refresh or not (
                cached is not None
                and cached["input_hash"] == digest
                and now - float(cached["completed_at"]) < self.max_age
            )
        lines: list[str] = []
        pairs: list[tuple[Record, str]] = []
        loaded: dict[str, str] = {}
        for key, (data, digest) in files.items() if refresh else ():
            try:
                records = contracts.parse(data, entries[key], self.scope)
            except contracts.ContractError as exc:
                errors.append(f"{entries[key]['path']}: {exc}")
                continue
            loaded[key] = digest
            for record in records:
                # The raw line is the record itself: the file can hold credentials.
                line = {"type": record.type.value, "value": record.value, **record.attrs}
                lines.append(json.dumps(line, sort_keys=True))
                pairs.append((_with_line(record, len(lines)), key))
        if pairs:
            ref = self._save_raw("apispec", contracts.NAME, "\n".join(lines) + "\n")
            self._store(
                contracts.CACHE_STAGE,
                stats,
                contracts.NAME,
                pairs,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )
        if loaded:
            stats.retired += self.store.complete_inputs(
                self.run_id,
                self.engagement,
                contracts.CACHE_STAGE,
                loaded,
                tool_versions=json.dumps({contracts.NAME: versions.BUILTIN_VERSION}),
            )
        for key in sorted(gone):  # the scope document no longer names it
            stats.retired += self.store.retire_input(
                self.run_id, self.engagement, contracts.CACHE_STAGE, key
            )
        entry_stats.update(
            {
                "contracts": len(entries),
                "loaded": len(loaded),
                "cached": 0 if refresh else len(files),
                "records": entry_stats.get("records", 0),
            }
        )
        for error in errors:
            log.error("pipeline: contract %s", error)
        if errors:
            entry_stats["errors"] = errors

    def _stage_apispec(self, stats: StageStats) -> None:
        if self.scope.limits.passive_only:
            self._load_contracts(stats, refresh=False)
            stats.skipped = "passive_only"
            self._stamp_skipped("apispec", "passive_only")
            return
        origins: dict[str, str] = {}
        for record in self._records(RecordType.HTTP_SERVICE):
            if self._wanted(record.asset):
                origins[_origin(record.value)] = record.content_hash
        origins = {
            origin: digest
            for origin, digest in origins.items()
            if self.scope.admit(
                [origin], stage="apispec", tool=apispec.OPENAPI_TOOL, direction="input"
            )
        }
        pending = self._pending("apispec", stats, origins)
        # Before any origin is probed, so the stage's parameter extraction and
        # its retirement of what a re-probed origin stopped reporting see them.
        self._load_contracts(stats, refresh=bool(pending))
        if not pending:
            return
        discovered = [
            r.value for kind in (RecordType.URL, RecordType.ENDPOINT) for r in self._records(kind)
        ]
        client = self._http("apispec", apispec.OPENAPI_TOOL)
        gql_client = self._http("apispec", apispec.GRAPHQL_TOOL)
        spec_lines: list[str] = []
        gql_lines: list[str] = []
        spec_records: list[tuple[Record, str]] = []
        gql_records: list[tuple[Record, str]] = []
        spec_tally: dict[str, list[int]] = {}
        gql_tally: dict[str, list[int]] = {}
        for origin in pending:
            spec_sent = spec_tally.setdefault(_asset(origin), [0, 0])
            gql_sent = gql_tally.setdefault(_asset(origin), [0, 0])
            spec_urls = [origin + path for path in apispec.OPENAPI_PATHS]
            gql_urls = [origin + path for path in apispec.GRAPHQL_PATHS]
            for url in discovered:
                if _origin(url) != origin:
                    continue
                path = urlsplit(url).path.lower()
                if any(k in path for k in ("swagger", "openapi", "api-docs")) and path.endswith(
                    (".json", ".yaml", ".yml", ".js", "api-docs")
                ):
                    spec_urls.append(url)
                if "graphql" in path:
                    gql_urls.append(url.split("?", 1)[0])
            found_spec = False
            for url in dict.fromkeys(spec_urls):
                if found_spec:
                    break
                try:
                    response = client.get(url)
                except OutOfScopeRequest:
                    continue
                spec_sent[0] += 1
                if response is None:  # transport error: this path was not checked
                    spec_sent[1] += 1
                    continue
                if response.status != 200:
                    continue
                spec = apispec.load_spec(response.text())
                if spec is None:
                    continue
                found_spec = True
                spec_lines.append(json.dumps({"url": response.url, "spec": spec}))
                for record in apispec.parse_openapi(spec, spec_url=response.url):
                    spec_records.append((_with_line(record, len(spec_lines)), origin))
            for url in dict.fromkeys(gql_urls):
                try:
                    response = gql_client.post_json(url, {"query": apispec.INTROSPECTION_QUERY})
                except OutOfScopeRequest:
                    continue
                gql_sent[0] += 1
                if response is None:  # transport error: this path was not checked
                    gql_sent[1] += 1
                    continue
                if response.status != 200:
                    continue
                try:
                    body = response.json()
                except ValueError:
                    continue
                records = list(apispec.parse_introspection(body, endpoint=response.url))
                if records:
                    gql_lines.append(json.dumps({"url": response.url, "response": body}))
                    gql_records.extend((_with_line(r, len(gql_lines)), origin) for r in records)
                    break
        stats.tools.setdefault(apispec.OPENAPI_TOOL, {})["requests"] = client.requests_sent
        stats.tools.setdefault(apispec.GRAPHQL_TOOL, {})["requests"] = gql_client.requests_sent
        self._note_requests(apispec.OPENAPI_TOOL, spec_tally)
        self._note_requests(apispec.GRAPHQL_TOOL, gql_tally)
        if spec_records:
            ref = self._save_raw("apispec", apispec.OPENAPI_TOOL, "\n".join(spec_lines) + "\n")
            self._store(
                "apispec",
                stats,
                apispec.OPENAPI_TOOL,
                spec_records,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )
        if gql_records:
            ref = self._save_raw("apispec", apispec.GRAPHQL_TOOL, "\n".join(gql_lines) + "\n")
            self._store(
                "apispec",
                stats,
                apispec.GRAPHQL_TOOL,
                gql_records,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )
        self._extract_parameters(stats, pending)
        self._complete("apispec", stats, pending)

    def _extract_parameters(self, stats: StageStats, pending: dict[str, str]) -> None:
        """Parameter records for the hosts this stage processed (no request, no tool).

        Read off the URLs, endpoints and API operations the store holds for
        those hosts. Every parameter belongs to one of the stage's inputs, so
        it is cached, re-derived and retired with that input. Nothing here can
        fail for one asset, so it adds no outcome to the coverage stamp.
        """
        owners: dict[str, list[str]] = {}
        for origin in sorted(pending):
            owners.setdefault(_asset(origin), []).append(origin)
        sources: list[StoredRecord] = []
        for kind in (RecordType.URL, RecordType.ENDPOINT, RecordType.API_OPERATION):
            for record in self._records(kind):
                if record.asset not in owners:
                    continue
                # An operation this run's fetch of its spec no longer reports is
                # retired when the stage completes; it is not an input any more.
                spec_origin = _origin(str(record.attrs.get("spec_url") or ""))
                if spec_origin in pending and record.last_run_id != self.run_id:
                    continue
                sources.append(record)
        lines: list[str] = []
        pairs: list[tuple[Record, str]] = []
        for record in params.extract(sources):
            hosts = owners.get(record.asset)
            if not hosts:
                continue
            origin = _origin(str(record.attrs["url"]))
            lines.append(json.dumps({"parameter": record.value, **record.attrs}, sort_keys=True))
            pairs.append(
                (_with_line(record, len(lines)), origin if origin in pending else hosts[0])
            )
        if pairs:
            ref = self._save_raw("apispec", params.NAME, "\n".join(lines) + "\n")
            self._store(
                "apispec", stats, params.NAME, pairs, version=versions.BUILTIN_VERSION, raw_ref=ref
            )

    # ── stage 8: API recon ──────────────────────────────────────────

    def _stage_api(self, stats: StageStats) -> None:
        """The API inventory, OAuth / OpenID discovery and one profile per API endpoint.

        The inventory is read off stored records. The discovery documents and
        the endpoint profiles are fetched: one unauthenticated GET each, never
        to a URL that names logout, delete or the like, at most
        :data:`apirecon.MAX_PROFILES_PER_ORIGIN` endpoints per origin.
        """
        from buggy.capture.crawl import never_request_reason  # noqa: PLC0415

        origins = self._service_origins("api", apirecon.PROFILE_TOOL)
        api_urls = [url for url, _tool in self._page_urls() if apirecon.api_root(url)]
        candidates = {
            origin: self._digest(
                [s.content_hash for s in services], [u for u in api_urls if _origin(u) == origin]
            )
            for origin, services in origins.items()
        }
        pending = self._pending("api", stats, candidates)
        if not pending:
            return
        mine = [u for u in api_urls if _origin(u) in pending]
        bases = [(record, _origin(record.value)) for record in apirecon.inventory(mine)]
        self._note(apirecon.INVENTORY_TOOL, "complete")
        if bases:
            lines = [json.dumps({"root": r.value, **r.attrs}, sort_keys=True) for r, _o in bases]
            ref = self._save_raw("api", apirecon.INVENTORY_TOOL, "\n".join(lines) + "\n")
            self._store(
                "api",
                stats,
                apirecon.INVENTORY_TOOL,
                bases,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )
        if self.scope.limits.passive_only:
            for tool in (apirecon.OIDC_TOOL, apirecon.PROFILE_TOOL):
                stats.tools.setdefault(tool, {})["skipped"] = "passive_only"
                self._note(tool, "skipped", "passive_only")
            self._complete("api", stats, pending)
            return

        oidc_client = self._http("api", apirecon.OIDC_TOOL)
        oidc_tally: dict[str, list[int]] = {}
        oidc: list[tuple[Record, str]] = []
        oidc_lines: list[str] = []
        for origin in pending:
            sent = oidc_tally.setdefault(_asset(origin), [0, 0])
            for path in apirecon.OIDC_PATHS:
                response = self._fetch(oidc_client, origin + path, sent)
                if response is None or response.status != 200:
                    continue
                records = list(apirecon.parse_discovery(response.text(), response.url))
                if records:
                    oidc_lines.append(
                        json.dumps({"url": response.url, "endpoints": [r.value for r in records]})
                    )
                    oidc += [(record, origin) for record in records]
                    break
        stats.tools.setdefault(apirecon.OIDC_TOOL, {})["requests"] = oidc_client.requests_sent
        self._note_requests(apirecon.OIDC_TOOL, oidc_tally)
        if oidc:
            ref = self._save_raw("api", apirecon.OIDC_TOOL, "\n".join(oidc_lines) + "\n")
            self._store(
                "api",
                stats,
                apirecon.OIDC_TOOL,
                oidc,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )

        client = self._http("api", apirecon.PROFILE_TOOL)
        tally: dict[str, list[int]] = {}
        profiles: list[tuple[Record, str]] = []
        lines: list[str] = []
        for url in apirecon.profile_targets(mine, never=never_request_reason):
            origin = _origin(url)
            sent = tally.setdefault(_asset(origin), [0, 0])
            response = self._fetch(client, url, sent)
            if response is None or response.status in apirecon.NOT_THERE:
                continue
            record = apirecon.profile(
                response.url, response.status, response.headers, response.body
            )
            lines.append(json.dumps({"value": record.value, **record.attrs}, sort_keys=True))
            profiles.append((_with_line(record, len(lines)), origin))
        stats.tools.setdefault(apirecon.PROFILE_TOOL, {})["requests"] = client.requests_sent
        self._note_requests(apirecon.PROFILE_TOOL, tally)
        if profiles:
            ref = self._save_raw("api", apirecon.PROFILE_TOOL, "\n".join(lines) + "\n")
            self._store(
                "api",
                stats,
                apirecon.PROFILE_TOOL,
                profiles,
                version=versions.BUILTIN_VERSION,
                raw_ref=ref,
            )
        self._complete("api", stats, pending)

    # ── stage 9: hidden parameters ──────────────────────────────────

    def _stage_paramguess(self, stats: StageStats) -> None:
        """Query names, headers and cookies the site reacts to but never links.

        Built in (``tools/paramminer.py``): read-only GETs through the scoped,
        rate-limited client, at most :data:`PARAM_ENDPOINTS_PER_ORIGIN` pages
        per origin and :data:`PARAM_MAX_REQUESTS` requests per run. Headers and
        cookies are guessed on one page per origin. Skipped in a passive run.
        """
        from buggy.capture.crawl import never_request_reason  # noqa: PLC0415

        tool = paramminer.NAME
        origins = self._service_origins("paramguess", tool)
        profiled = [
            str(r.attrs.get("url") or "")
            for r in self._records(RecordType.API_PROFILE)
            if isinstance(r.attrs.get("status"), int) and 200 <= r.attrs["status"] < 300
        ]
        parameters = self._records(RecordType.PARAMETER)
        with_inputs = [str(r.attrs.get("url") or "") for r in parameters]
        pages = [u for u, _tool in self._page_urls(operations=False)]
        chosen = {
            origin: paramminer.choose_endpoints(
                origin,
                profiled,
                with_inputs + pages,
                never=never_request_reason,
                per_origin=PARAM_ENDPOINTS_PER_ORIGIN,
            )
            for origin in origins
        }
        candidates = {
            origin: self._digest([s.content_hash for s in services], chosen[origin])
            for origin, services in origins.items()
        }
        pending = self._pending("paramguess", stats, candidates)
        if not pending:
            return
        if self.scope.limits.passive_only:
            stats.tools.setdefault(tool, {})["skipped"] = "passive_only"
            self._note(tool, "skipped", "passive_only")
            self._complete("paramguess", stats, pending)
            return
        harvested = paramminer.harvest(
            [str(r.attrs.get("name") or "") for r in parameters],
            [
                str(f)
                for r in self._records(RecordType.API_PROFILE)
                for f in r.attrs.get("fields") or []
            ],
            pages,
        )
        known: dict[str, set[str]] = {}
        for record in parameters:
            known.setdefault(str(record.attrs.get("url") or ""), set()).add(
                str(record.attrs.get("name") or "")
            )
        client = self._http("paramguess", tool)
        tally: dict[str, list[int]] = {}
        found: list[tuple[Record, str]] = []
        lines: list[str] = []
        skipped: list[str] = []
        left = PARAM_MAX_REQUESTS
        for origin in pending:
            sent = tally.setdefault(_asset(origin), [0, 0])
            for index, url in enumerate(chosen.get(origin, [])):
                locations = ["query"] + (["header", "cookie"] if index == 0 else [])
                for location in locations:
                    budget = min(PARAM_BUDGET[location], left)
                    if budget < 5:
                        break
                    names = paramminer.wordlist(location, harvested, known.get(url, ()))
                    miner = paramminer.Miner(
                        self._param_sender(client, url, sent), location, max_requests=budget
                    )
                    outcome = miner.run(names)
                    left -= outcome.requests
                    if outcome.skipped:
                        skipped.append(f"{url} {location}: {outcome.skipped}")
                    for hit in outcome.found:
                        record = Record(
                            type=RecordType.PARAMETER,
                            asset=host_of(url),
                            value=f"GET {url} {hit.location}:{hit.name}",
                            source_tool=tool,
                            attrs={
                                "name": hit.name,
                                "location": hit.location,
                                "method": "GET",
                                "url": url,
                                "example": "",
                                "sources": [tool],
                                "hints": params.hints_for(hit.name),
                                "hidden": True,
                                "reason": hit.reason,
                                "detail": hit.detail,
                            },
                        )
                        lines.append(json.dumps({"value": record.value, **record.attrs}))
                        found.append((_with_line(record, len(lines)), origin))
        entry = stats.tools.setdefault(tool, {})
        entry["requests"] = client.requests_sent
        if skipped:
            entry["not_guessed"] = skipped[:20]
        self._note_requests(tool, tally)
        if found:
            ref = self._save_raw("paramguess", tool, "\n".join(lines) + "\n")
            self._store(
                "paramguess", stats, tool, found, version=versions.BUILTIN_VERSION, raw_ref=ref
            )
        self._complete("paramguess", stats, pending)

    def _param_sender(self, client: ScopedHTTP, url: str, sent: list[int]) -> paramminer.Send:
        """The miner's request callback: names in the query, as headers or as cookies."""

        def send(location: str, pairs: dict[str, str]) -> paramminer.Snapshot | None:
            target, headers = url, None
            if location == "query":
                target = f"{url}?{urlencode(pairs)}"
            elif location == "header":
                headers = pairs
            else:
                headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in pairs.items())}
            try:
                response = client.get(target, headers=headers)
            except OutOfScopeRequest:
                return None
            sent[0] += 1
            if response is None:
                sent[1] += 1
                return None
            return paramminer.snapshot(response.status, response.headers, response.text())

        return send

    # ── stage 10: known issues ──────────────────────────────────────

    def _issue_inputs(self) -> dict[str, str]:
        return {
            record.value: record.content_hash
            for record in self._records(RecordType.HTTP_SERVICE)
            if self._wanted(record.asset)
            and self.scope.admit([record.value], stage="issues", tool="nuclei", direction="input")
        }

    def _start_early_issues(self) -> None:
        """Start the known-issue scan now, next to the crawl and the web and API recon.

        It needs only the live services, which exist from stage 3 on, and it is
        the slowest scanner. It gets half of the rate limit and half of the
        connections; the crawler and the built-in requests get the other half
        until it finishes, so together they never exceed the program's rate.
        The issues stage collects the result. Nothing starts when the stage is
        disabled, the run is passive, the rate cannot be split, or every input
        is cached.
        """
        limits = self.scope.limits
        if "issues" in limits.disabled_stages or limits.passive_only or limits.rate_limit_rps < 2:
            return
        now = time.time()
        pending: dict[str, str] = {}
        for key, input_hash in self._issue_inputs().items():
            cached = self.store.cached_input(self.engagement, "issues", key)
            fresh = (
                cached is not None
                and cached["input_hash"] == input_hash
                and now - float(cached["completed_at"]) < self.max_age
            )
            if self.force or not fresh:
                pending[key] = input_hash
        if not pending:
            return
        half = replace(
            limits,
            rate_limit_rps=limits.rate_limit_rps // 2,
            concurrency=max(1, limits.concurrency // 2),
        )
        rest = replace(
            limits,
            rate_limit_rps=limits.rate_limit_rps - half.rate_limit_rps,
            concurrency=max(1, limits.concurrency - half.concurrency),
        )
        stats = self.stats.setdefault("issues", StageStats())
        job = self._prepare_binary(
            "issues", stats, self._nuclei, list(pending), limits=half, quiet=True
        )
        if job is None:
            return
        self._target_limits = rest
        self._limiter.set_rate(rest.rate_limit_rps)
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(self._execute, job)
        future.add_done_callback(lambda _done: self._limiter.set_rate(limits.rate_limit_rps))
        pool.shutdown(wait=False)
        self._early_issues = (job, future, pending)

    def _stage_issues(self, stats: StageStats) -> None:
        services = self._issue_inputs()
        pending = self._pending("issues", stats, services)
        early, self._early_issues = self._early_issues, None
        result: RunResult | None = None
        if early is not None:
            result = early[1].result()  # the scan started next to the crawl
            self._target_limits = self.scope.limits
        if pending:
            if early is not None and result is not None and set(early[2]) == set(pending):
                raw, ref, version = self._finish_binary(early[0], result)
            else:
                raw, ref, version = self._run_binary("issues", stats, self._nuclei, list(pending))
            if ref:
                by_origin = {_origin(url): url for url in pending}
                self._store(
                    "issues",
                    stats,
                    self._nuclei.name,
                    (
                        (r, by_origin.get(_origin(str(r.attrs.get("matched_at", ""))), r.asset))
                        for r in self._nuclei.parse(raw)
                    ),
                    version=version,
                    raw_ref=ref,
                )
                if not self.scope.limits.passive_only:
                    self._complete("issues", stats, pending)
        self._scan_secrets(stats)

    def _scan_secrets(self, stats: StageStats) -> None:
        gitleaks = Gitleaks()
        js_dir = self._workdir() / "js"
        if self._js_sources and js_dir.is_dir():
            raw, ref, version = self._run_binary(
                "issues",
                stats,
                gitleaks,
                ["dir", str(js_dir)],
                scope_inputs=False,
                assets={host_of(url) for url in self._js_sources.values()},
            )
            if ref:
                self._store(
                    "issues",
                    stats,
                    gitleaks.name,
                    ((r, r.asset) for r in gitleaks.parse(raw, sources=self._js_sources)),
                    version=version,
                    raw_ref=ref,
                )
        for repo in self.public_repos:
            self._scan_repo(stats, gitleaks, repo)

    def _scan_repo(self, stats: StageStats, gitleaks: Gitleaks, repo: str) -> None:
        """Clone an operator-listed public repository and scan its history."""
        parts = urlsplit(repo)
        host = (parts.hostname or "").lower()
        entry = stats.tools.setdefault("gitleaks-repos", {})
        if parts.scheme != "https" or host not in PUBLIC_REPO_HOSTS or parts.username:
            entry.setdefault("rejected", []).append(repo)
            return
        asset = f"{host}{parts.path.removesuffix('.git').rstrip('/')}"
        key = f"repo:{asset}"
        cached = self.store.cached_input(self.engagement, "issues", key)
        if (
            not self.force
            and cached is not None
            and time.time() - float(cached["completed_at"]) < self.max_age
        ):
            return
        target = self._workdir() / "repos" / hashlib.sha256(repo.encode()).hexdigest()[:16]
        target.parent.mkdir(parents=True, exist_ok=True)
        clone = subprocess.run(  # noqa: S603, S607 - fixed argv, allow-listed https host
            ["git", "clone", "--quiet", "--depth", "200", "--no-tags", repo, str(target)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if clone.returncode != 0:
            entry.setdefault("errors", []).append(f"{repo}: {clone.stderr.strip()[-200:]}")
            self.store.set_coverage(
                self.engagement, asset, "issues", "failed", "git clone failed", self.run_id
            )
            return
        raw, ref, version = self._run_binary(
            "issues", stats, gitleaks, ["git", str(target)], scope_inputs=False, assets=[asset]
        )
        # The repository is its own asset: stamp it from this one scan.
        self._stamp("issues", [asset], [o for o in self._outcomes if o.assets == {asset}])
        if ref:
            written = self.store.write_records(
                self.run_id,
                self.engagement,
                "issues",
                ((r, key) for r in gitleaks.parse(raw, asset=asset)),
                tool_version=version,
                raw_ref=ref,
            )
            stats.records += written
            entry["records"] = entry.get("records", 0) + written
            self.store.complete_inputs(
                self.run_id,
                self.engagement,
                "issues",
                {key: _hash(repo)},
                tool_versions=version,
                retire=True,
            )


def _with_line(record: Record, line: int) -> Record:
    return Record(
        record.type,
        record.asset,
        record.value,
        record.source_tool,
        attrs=record.attrs,
        raw_line=line,
    )


def _cached_wildcard(root: str, cached: dict[str, Any] | None) -> wildcard.WildcardInfo | None:
    """The verdict held in a wildcard stage-cache row, or ``None`` if there is none."""
    if cached is None:
        return None
    try:
        payload = json.loads(cached["tool_versions"])
        return wildcard.WildcardInfo(
            root, bool(payload["wildcard"]), frozenset(map(str, payload["addresses"]))
        )
    except (KeyError, TypeError, ValueError):
        return None


def _is_address(value: str) -> bool:
    import ipaddress  # noqa: PLC0415

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def canonical_asset(value: str) -> str:
    """Asset name for a host, ``host:port`` or URL."""
    return host_of(normalize_url(value) if "://" in value else value)


def _asset(key: str) -> str:
    """The asset a stage input (root, host, URL or origin) belongs to."""
    return canonical_asset(key) or key


__all__ = [
    "COVERAGE_PORT",
    "COVERAGE_STAGES",
    "DEFAULT_MAX_AGE",
    "STAGES",
    "Pipeline",
    "ToolOutcome",
    "canonical_asset",
    "default_executor",
    "grade",
]
