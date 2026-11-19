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
   processed (which also retires records they no longer produce).

There is no model call anywhere on this path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from buggy.pipeline import versions
from buggy.pipeline.http import OutOfScopeRequest, RateLimiter, ScopedHTTP, fetch_passive
from buggy.pipeline.runner import RunResult, run_tool
from buggy.pipeline.schema import (
    Record,
    RecordType,
    StoredRecord,
    host_of,
    normalize_host,
    normalize_url,
)
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools import apispec, crtsh, jsparse
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

STAGES = ("enumerate", "dns", "live", "fingerprint", "urls", "apispec", "issues")

# Stages whose records are retired when a re-processed input stops reporting
# them. Discovery stages (subdomains, URLs) only accumulate.
RETIRING_STAGES = frozenset({"dns", "live", "fingerprint", "apispec", "issues"})

DEFAULT_MAX_AGE = 24 * 3600.0
MAX_JS_FILES = 200
MAX_JS_BYTES = 3 * 1024 * 1024
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
        self.public_repos = tuple(public_repos)
        self._executor = executor or default_executor
        self._resolver = resolver or versions.verify
        self._http_opener = http_opener
        self._limiter = RateLimiter(scope.limits.rate_limit_rps, sleep=sleep)
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
            "apispec": self._stage_apispec,
            "issues": self._stage_issues,
        }
        try:
            for stage in STAGES:
                stats = self.stats.setdefault(stage, StageStats())
                if stage in self.scope.limits.disabled_stages:
                    stats.skipped = "disabled by program rules"
                    continue
                handlers[stage](stats)
        except Exception as exc:  # noqa: BLE001 - the run is closed as failed, then re-raised
            status, error = "failed", f"{type(exc).__name__}: {exc}"
            log.exception("pipeline run %s failed", self.run_id)
            raise
        finally:
            summary = {
                "stages": {name: stats.to_dict() for name, stats in self.stats.items()},
                "tool_versions": self._tool_versions,
                "limits": {
                    "rate_limit_rps": self.scope.limits.rate_limit_rps,
                    "concurrency": self.scope.limits.concurrency,
                    "passive_only": self.scope.limits.passive_only,
                },
                "only_asset": self.only_asset or "",
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

    def _wanted(self, host: str) -> bool:
        """Whether a host is selected by ``only_asset`` (always true without it)."""
        if not self.only_asset:
            return True
        return host == self.only_asset or host.endswith("." + self.only_asset)

    def _pending(self, stage: str, stats: StageStats, candidates: dict[str, str]) -> dict[str, str]:
        """``{input_key: input_hash}`` that must be processed this run."""
        stats.inputs += len(candidates)
        self._retire_vanished(stage, stats, candidates)
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
        return pending

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

    def _run_binary(
        self,
        stage: str,
        stats: StageStats,
        wrapper: Any,
        inputs: list[str],
        *,
        scope_inputs: bool = True,
    ) -> tuple[str, str, str]:
        """Run one scanner. Returns ``(raw_text, raw_ref, version)``; raw is "" on failure."""
        name = wrapper.name
        entry = stats.tools.setdefault(name, {})
        if self.scope.limits.passive_only and not wrapper.passive:
            entry["skipped"] = "passive_only"
            return "", "", ""
        if scope_inputs:
            inputs = self.scope.admit(inputs, stage=stage, tool=name, direction="input")
        if not inputs:
            entry.setdefault("skipped", "no in-scope inputs")
            return "", "", ""
        try:
            binary, version = self._resolver(name)
        except versions.ToolVersionError as exc:
            entry["error"] = str(exc)
            log.error("pipeline: %s unavailable: %s", name, exc)
            return "", "", ""
        self._tool_versions[name] = version
        invocation = wrapper.invocation(binary, inputs, self.scope.limits, self._workdir())
        raw_path, ref = self._raw_path(stage, name)
        result = self._executor(name, invocation, raw_path)
        self.store.register_raw_output(
            ref,
            run_id=self.run_id,
            engagement=self.engagement,
            stage=stage,
            tool=name,
            tool_version=version,
            argv=list(result.argv),
            sha256=result.sha256,
            bytes=result.size,
            exit_code=result.exit_code,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )
        entry.update(
            {
                "version": version,
                "exit_code": result.exit_code,
                "inputs": len(inputs),
                "raw_ref": ref,
                "seconds": round(result.finished_at - result.started_at, 2),
            }
        )
        if result.timed_out:
            entry["error"] = "timed out"
        elif result.exit_code not in (0, None) and result.size == 0:
            entry["error"] = result.stderr_tail[-300:] or f"exit {result.exit_code}"
        try:
            raw = raw_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw = ""
        return raw, ref, version

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
        roots = {
            root: _hash(root, self.scope.digest)
            for root in seeds.roots
            if not self.only_asset
            or self.only_asset == root
            or self.only_asset.endswith("." + root)
        }
        pending = self._pending("enumerate", stats, roots)
        if not pending:
            return
        targets = list(pending)
        for wrapper in (Subfinder(), Amass()):
            # Enumeration roots are derived from in_scope patterns, not scan
            # targets, so they are not themselves scope-filtered; every name
            # the tools return is.
            raw, ref, version = self._run_binary(
                "enumerate", stats, wrapper, targets, scope_inputs=False
            )
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
            body = self._passive_fetch(crtsh.query_url(root))
            entry = stats.tools.setdefault(crtsh.NAME, {"version": versions.BUILTIN_VERSION})
            if body is None:
                entry["error"] = "crt.sh unreachable"
                continue
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
        self._complete("enumerate", stats, pending)

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
        if not pending:
            return
        raw, ref, version = self._run_binary("dns", stats, self._dnsx, list(pending))
        if not ref:
            return  # tool unavailable: leave the cache untouched so the next run retries
        self._store(
            "dns",
            stats,
            self._dnsx.name,
            ((r, r.asset) for r in self._dnsx.parse(raw)),
            version=version,
            raw_ref=ref,
        )
        self._complete("dns", stats, pending)

    # ── stage 3: live hosts and ports ───────────────────────────────

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
            stats.tools.setdefault(naabu.name, {})["skipped"] = (
                "port scan disabled by program rules"
            )

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
        katana = Katana(resolvers=self._resolvers)
        raw, ref, version = self._run_binary("urls", stats, katana, list(pending))
        if raw:
            self._store(
                "urls",
                stats,
                katana.name,
                ((r, r.asset) for r in katana.parse(raw)),
                version=version,
                raw_ref=ref,
            )
        hosts = sorted({host_of(url) for url in pending if not _is_address(host_of(url))})
        for wrapper in (Gau(), Waybackurls()):
            if not hosts:
                break
            raw, ref, version = self._run_binary("urls", stats, wrapper, hosts)
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
            return
        js_files = [r for r in self._records(RecordType.JS_FILE) if r.asset in hosts][:MAX_JS_FILES]
        if not js_files:
            return
        client = self._http("urls", jsparse.NAME)
        js_dir = self._workdir() / "js"
        js_dir.mkdir(parents=True, exist_ok=True)
        fetched = 0
        lines: list[str] = []
        pairs: list[tuple[Record, str]] = []
        for record in js_files:
            try:
                response = client.get(record.value)
            except OutOfScopeRequest:
                continue
            if response is None or response.status != 200 or not response.body:
                continue
            fetched += 1
            body = response.body[:MAX_JS_BYTES]
            name = hashlib.sha256(record.value.encode()).hexdigest()[:24] + ".js"
            (js_dir / name).write_bytes(body)
            self._js_sources[name] = record.value
            script = body.decode("utf-8", "replace")
            for endpoint in jsparse.parse(script, js_url=record.value):
                lines.append(
                    json.dumps(
                        {
                            "js": record.value,
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
        entry["fetched"] = fetched
        if pairs:
            ref = self._save_raw("urls", jsparse.NAME, "\n".join(lines) + "\n")
            self._store(
                "urls", stats, jsparse.NAME, pairs, version=versions.BUILTIN_VERSION, raw_ref=ref
            )

    # ── stage 6: API specifications ─────────────────────────────────

    def _stage_apispec(self, stats: StageStats) -> None:
        if self.scope.limits.passive_only:
            stats.skipped = "passive_only"
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
        for origin in pending:
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
                if response is None or response.status != 200:
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
                if response is None or response.status != 200:
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
        self._complete("apispec", stats, pending)

    # ── stage 7: known issues ───────────────────────────────────────

    def _stage_issues(self, stats: StageStats) -> None:
        services = {
            record.value: record.content_hash
            for record in self._records(RecordType.HTTP_SERVICE)
            if self._wanted(record.asset)
            and self.scope.admit([record.value], stage="issues", tool="nuclei", direction="input")
        }
        pending = self._pending("issues", stats, services)
        if pending:
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
                "issues", stats, gitleaks, ["dir", str(js_dir)], scope_inputs=False
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
            return
        raw, ref, version = self._run_binary(
            "issues", stats, gitleaks, ["git", str(target)], scope_inputs=False
        )
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


__all__ = ["DEFAULT_MAX_AGE", "STAGES", "Pipeline", "canonical_asset", "default_executor"]
