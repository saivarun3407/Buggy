"""Properties the pipeline must keep: no LLM, pinned tools, scoped HTTP, agent-safe queries."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
import urllib.error
from pathlib import Path

import pytest

from buggy.pipeline import service, versions
from buggy.pipeline.http import OutOfScopeRequest, RateLimiter, ScopedHTTP, fetch_passive
from buggy.pipeline.query import QueryError, ReconQueries
from buggy.pipeline.schema import Record, RecordType
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.store import ReconStore

REPO_ROOT = Path(__file__).resolve().parents[5]
ROE = {"machine_enforcement": {"mode": "enforce", "in_scope": ["*.acme.test", "acme.test"]}}


class TestNoLLMInTheLoop:
    def test_pipeline_imports_no_model_or_agent_library(self) -> None:
        """A clean interpreter that imports every pipeline module loads no LLM stack."""
        code = (
            "import sys, pkgutil, importlib, buggy.pipeline as p\n"
            "import buggy.pipeline.tools as t\n"
            "names = [m.name for m in pkgutil.iter_modules(p.__path__, 'buggy.pipeline.')]\n"
            "names += [m.name for m in pkgutil.iter_modules(t.__path__, 'buggy.pipeline.tools.')]\n"
            "names = [n for n in names if not n.endswith('mcp_server')]\n"
            "[importlib.import_module(n) for n in names]\n"
            "banned = ('langchain', 'langgraph', 'deepagents', 'anthropic', 'openai', 'litellm')\n"
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in banned)\n"
            "assert not bad, bad\n"
            "assert len(names) > 15, names\n"
        )
        env = {
            "BUGGY_SKIP_BOOT": "1",
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": ":".join(
                str(REPO_ROOT / "packages" / p) for p in ("buggy", "buggy-core")
            ),
        }
        subprocess.run([sys.executable, "-c", code], check=True, env=env)

    def test_no_pipeline_source_mentions_a_model_client(self) -> None:
        package = REPO_ROOT / "packages" / "buggy" / "buggy" / "pipeline"
        for path in package.rglob("*.py"):
            text = path.read_text()
            for needle in (
                "import langchain",
                "from langchain",
                "import langgraph",
                "from langgraph",
                "ChatAnthropic",
                "ChatOpenAI",
                "create_llm",
            ):
                assert needle not in text, f"{path.name} references {needle}"


class TestPinnedVersions:
    def test_every_scanner_is_pinned_to_an_exact_version(self) -> None:
        assert set(versions.PINNED) == {
            "subfinder", "amass", "dnsx", "httpx", "naabu", "katana", "nuclei", "gau", "waybackurls", "gitleaks",
        }  # fmt: skip
        for tool in versions.PINNED.values():
            assert tool.version.count(".") == 2 and tool.version[0].isdigit()
            assert "latest" not in tool.module
        assert versions.NUCLEI_TEMPLATES_VERSION.startswith("v")

    def test_dockerfile_installs_exactly_the_pins(self) -> None:
        dockerfile = (REPO_ROOT / "containers" / "pipeline.Dockerfile").read_text()
        assert "buggy.pipeline.versions --install-plan" in dockerfile
        assert "--write-manifest" in dockerfile
        assert "@latest" not in dockerfile
        assert (
            versions.NUCLEI_TEMPLATES_VERSION not in dockerfile
        )  # read from versions.py, not duplicated
        plan = versions.install_plan()
        assert "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1" in plan
        assert len(plan) == len(versions.PINNED)

    def _fake_binary(self, tmp_path: Path, monkeypatch, name: str, reports: str) -> Path:
        binary = tmp_path / name
        binary.write_text(f"#!/bin/sh\necho 'Current Version: {reports}'\n")
        binary.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        monkeypatch.delenv("BUGGY_PIPELINE_ALLOW_UNPINNED", raising=False)
        monkeypatch.setenv("BUGGY_PIPELINE_TOOL_MANIFEST", str(tmp_path / "absent.json"))
        return binary

    def test_matching_version_is_accepted(self, tmp_path, monkeypatch) -> None:
        self._fake_binary(tmp_path, monkeypatch, "httpx", "v1.12.0")
        assert versions.verify("httpx") == (str(tmp_path / "httpx"), "1.12.0")

    def test_other_version_is_refused(self, tmp_path, monkeypatch) -> None:
        self._fake_binary(tmp_path, monkeypatch, "httpx", "v1.6.0")
        with pytest.raises(versions.ToolVersionError, match="expected pinned 1.12.0, found 1.6.0"):
            versions.verify("httpx")
        monkeypatch.setenv("BUGGY_PIPELINE_ALLOW_UNPINNED", "1")
        assert versions.verify("httpx")[1] == "unpinned:1.6.0"

    def test_manifest_hash_mismatch_is_refused(self, tmp_path, monkeypatch) -> None:
        binary = self._fake_binary(tmp_path, monkeypatch, "httpx", "v1.12.0")
        good = {"httpx": {"version": "1.12.0", "sha256": versions._sha256(binary)}}  # noqa: SLF001
        assert versions.verify("httpx", manifest=good)[1] == "1.12.0"
        binary.write_text("#!/bin/sh\necho 'Current Version: v1.12.0'\necho tampered\n")
        with pytest.raises(versions.ToolVersionError, match="hash does not match"):
            versions.verify("httpx", manifest=good)
        stale = {"httpx": {"version": "1.11.0", "sha256": "x"}}
        with pytest.raises(versions.ToolVersionError, match="manifest records 1.11.0"):
            versions.verify("httpx", manifest=stale)

    def test_missing_and_unknown_tools(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("PATH", str(tmp_path))
        with pytest.raises(versions.ToolVersionError, match="not installed"):
            versions.verify("nuclei")
        with pytest.raises(versions.ToolVersionError, match="not a pinned"):
            versions.verify("sqlmap")


class _Opener:
    def __init__(self, routes: dict[str, object]) -> None:
        self.routes, self.seen = routes, []

    def open(self, request, timeout=None):  # noqa: ARG002
        self.seen.append(request.full_url)
        result = self.routes.get(request.full_url, 404)
        if isinstance(result, tuple):  # redirect
            code, location = result
            raise urllib.error.HTTPError(
                request.full_url, code, "redirect", {"Location": location}, io.BytesIO(b"")
            )
        if result == 404:
            raise urllib.error.HTTPError(request.full_url, 404, "nf", {}, io.BytesIO(b"gone"))
        body = io.BytesIO(result)
        body.status, body.headers = 200, {"Content-Type": "text/plain"}
        body.__enter__ = lambda *_: body
        body.__exit__ = lambda *_: False
        return body


class TestScopedHTTP:
    def _client(self, routes, drops=None):
        scope = ScopeFilter.from_document(
            ROE, log_drop=(lambda *a: drops.append(a)) if drops is not None else None
        )
        opener = _Opener(routes)
        return ScopedHTTP(
            scope, stage="apispec", tool="openapi", limiter=RateLimiter(0), opener=opener
        ), opener

    def test_out_of_scope_url_is_never_sent(self) -> None:
        drops: list = []
        client, opener = self._client({}, drops)
        with pytest.raises(OutOfScopeRequest):
            client.get("https://evil.example/openapi.json")
        assert opener.seen == []
        assert drops == [
            ("apispec", "openapi", "input", "https://evil.example/openapi.json", "NOT_IN_SCOPE")
        ]

    def test_redirect_to_out_of_scope_host_stops_before_the_request(self) -> None:
        client, opener = self._client({"https://www.acme.test/a": (302, "https://evil.example/b")})
        with pytest.raises(OutOfScopeRequest):
            client.get("https://www.acme.test/a")
        assert opener.seen == ["https://www.acme.test/a"]

    def test_in_scope_redirect_is_followed(self) -> None:
        client, opener = self._client(
            {"https://www.acme.test/a": (301, "/b"), "https://www.acme.test/b": b"hello"}
        )
        response = client.get("https://www.acme.test/a")
        assert response is not None
        assert response.status == 200 and response.text() == "hello"
        assert response.url == "https://www.acme.test/b" and client.requests_sent == 2

    def test_error_status_and_bad_scheme(self) -> None:
        client, _ = self._client({})
        missing = client.get("https://www.acme.test/missing")
        assert missing is not None
        assert missing.status == 404
        with pytest.raises(OutOfScopeRequest, match="scheme"):
            client.get("file:///etc/passwd")

    def test_passive_fetch_only_reaches_listed_sources(self) -> None:
        with pytest.raises(OutOfScopeRequest):
            fetch_passive("https://www.acme.test/", limiter=RateLimiter(0))
        with pytest.raises(OutOfScopeRequest):
            fetch_passive("http://crt.sh/?q=x", limiter=RateLimiter(0))

    def test_rate_limiter_spaces_requests(self) -> None:
        now, slept = [0.0], []

        def sleep(seconds: float) -> None:
            slept.append(round(seconds, 3))
            now[0] += seconds

        limiter = RateLimiter(4, clock=lambda: now[0], sleep=sleep)
        for _ in range(4):
            limiter.wait()
        assert slept == [0.25, 0.25, 0.25]


@pytest.fixture
def queries(tmp_path: Path):
    root, control = tmp_path / "data", tmp_path / "control"
    (control / "acme").mkdir(parents=True)
    (control / "acme" / "roe.json").write_text(json.dumps(ROE))
    writer = ReconStore(root / service.STORE_FILE)
    run = writer.begin_run("acme", trigger="test")
    raw = root / "raw" / "acme" / run / "live-httpx.out"
    raw.parent.mkdir(parents=True)
    raw.write_text('{"url":"https://www.acme.test"}\n{"url":"https://api.acme.test"}\n')
    ref = f"raw/acme/{run}/live-httpx.out"
    writer.register_raw_output(
        ref,
        run_id=run,
        engagement="acme",
        stage="live",
        tool="httpx",
        tool_version="1.12.0",
        argv=["httpx", "-l", "x"],
        sha256="s",
        bytes=10,
        exit_code=0,
        started_at=1.0,
        finished_at=2.0,
    )
    writer.write_records(
        run, "acme", "live",
        [(Record(RecordType.HTTP_SERVICE, f"h{i}.acme.test", f"https://h{i}.acme.test/", "httpx", raw_line=2), f"h{i}.acme.test") for i in range(260)],
        tool_version="1.12.0", raw_ref=ref,
    )  # fmt: skip
    writer.finish_run(run, status="completed", stats={"scope_drops": 0})
    (root / "raw" / "other").mkdir()
    (root / "raw" / "other" / "secret.out").write_text("another engagement\n")
    reader = ReconStore(root / service.STORE_FILE, read_only=True)
    queue = ReconStore(tmp_path / "queue" / service.QUEUE_FILE)
    yield (
        ReconQueries(reader, queue, data_root=root, control_root=control, engagement="acme"),
        queue,
        run,
    )
    for handle in (writer, reader, queue):
        handle.close()


class TestAgentQuerySurface:
    def test_summary_and_paged_query(self, queries) -> None:
        q, _queue, run = queries
        summary = q.summary("acme")
        assert summary["records"] == {"http_service": 260} and summary["last_run"]["run_id"] == run
        # No stage stamped anything in this fixture: zero everywhere, which the
        # report renders as "not recorded", never as "nothing missed".
        assert summary["coverage"] == {"complete": 0, "partial": 0, "failed": 0, "skipped": 0}
        assert summary["coverage_gaps"] == [] and summary["coverage_gap_assets"] == 0
        page = q.query("acme", record_type="http_service", limit=10_000)
        assert len(page["records"]) == 200 and page["truncated"] and page["next_offset"] == 200
        rest = q.query("acme", record_type="http_service", offset=200, limit=200)
        assert len(rest["records"]) == 60 and not rest["truncated"]
        record = page["records"][0]
        for field in (
            "asset",
            "type",
            "value",
            "source_tool",
            "tool_version",
            "first_seen",
            "engagement",
            "raw_ref",
        ):
            assert record[field] not in ("", None)

    def test_reads_are_bound_to_one_engagement(self, queries) -> None:
        q, _queue, _run = queries
        for call in (
            lambda: q.summary("other"),
            lambda: q.query("other"),
            lambda: q.diff("other"),
            lambda: q.summary(""),
        ):
            with pytest.raises(QueryError):
                call()
        with pytest.raises(QueryError, match="unknown record_type"):
            q.query("acme", record_type="exploit")

    def test_raw_output_lookup_gives_provenance(self, queries) -> None:
        q, _queue, run = queries
        record = q.query("acme", limit=1)["records"][0]
        raw = q.raw("acme", record["raw_ref"])
        assert (
            raw["tool"] == "httpx" and raw["tool_version"] == "1.12.0" and raw["argv"][0] == "httpx"
        )
        assert raw["lines"] == [{"line": 2, "text": '{"url":"https://api.acme.test"}'}]
        assert [
            line["line"] for line in q.raw("acme", record["raw_ref"], context_lines=1)["lines"]
        ] == [1, 2]

    @pytest.mark.parametrize(
        "ref",
        ["raw/other/secret.out", "raw/acme/../other/secret.out", "../../etc/passwd", "/etc/passwd"],
    )
    def test_raw_lookup_cannot_leave_the_engagement(self, queries, ref: str) -> None:
        q, _queue, _run = queries
        with pytest.raises(QueryError):
            q.raw("acme", ref)

    def test_rerun_request_is_scope_checked_and_names_only_an_asset(self, queries) -> None:
        q, queue, _run = queries
        rejected = q.request_rerun("acme", "https://evil.example/admin", reason="please")
        assert (
            rejected["status"] == "rejected" and "not in the enforced scope" in rejected["detail"]
        )
        accepted = q.request_rerun("acme", "https://api.acme.test:8443/v1?x=1", reason="new deploy")
        assert accepted["status"] == "pending"
        (pending,) = queue.pending_reruns("acme")
        assert pending["asset"] == "api.acme.test"  # reduced to a host: no URL, flags or tool
        assert q.request_rerun("acme", "api.acme.test")["detail"] == "already queued"
        assert q.rerun_status("acme", accepted["request_id"])["status"] == "pending"
        assert q.rerun_status("acme", rejected["request_id"])["status"] == "rejected"

    def test_mcp_server_exposes_only_the_query_tools(self, tmp_path: Path) -> None:
        pytest.importorskip("mcp")
        import asyncio
        import inspect

        from buggy.pipeline import mcp_server

        (tmp_path / "control" / "acme").mkdir(parents=True)
        (tmp_path / "control" / "acme" / "roe.json").write_text(json.dumps(ROE))
        server = mcp_server.build_server(
            data_root=tmp_path / "data",
            queue_root=tmp_path / "queue",
            control_root=tmp_path / "control",
            engagement="acme",
        )
        tools = asyncio.run(server.list_tools())
        assert sorted(t.name for t in tools) == sorted(mcp_server.TOOL_NAMES)
        writers = [t.name for t in tools if "rerun" not in t.name and "request" in t.name]
        assert writers == []
        for tool in tools:
            params = set(tool.inputSchema.get("properties", {}))
            # No tool takes anything that could steer a scanner.
            assert not params & {
                "argv",
                "args",
                "command",
                "flags",
                "tool",
                "template",
                "templates",
                "url_list",
            }, tool.name
        rerun = next(t for t in tools if t.name == "recon_request_rerun")
        assert set(rerun.inputSchema["properties"]) == {"engagement", "asset", "reason"}
        assert "subprocess" not in inspect.getsource(mcp_server)

        async def call(name: str, **kwargs):
            out = await server.call_tool(name, kwargs)
            content = out[0] if isinstance(out, tuple) else out
            return json.loads(content[0].text)

        assert asyncio.run(call("recon_summary", engagement="acme"))["records"] == {}
        assert "error" in asyncio.run(call("recon_summary", engagement="other"))
        assert (
            asyncio.run(call("recon_request_rerun", engagement="acme", asset="evil.example"))[
                "status"
            ]
            == "rejected"
        )


class TestRerunWorker:
    def test_scope_is_rechecked_when_the_request_is_served(self, tmp_path: Path) -> None:
        control = tmp_path / "control"
        (control / "acme").mkdir(parents=True)
        (control / "acme" / "roe.json").write_text(json.dumps(ROE))
        queue = ReconStore(tmp_path / "queue" / service.QUEUE_FILE)
        try:
            queued = service.request_rerun(
                queue, "acme", "api.acme.test", requested_by="agent", reason="", control=control
            )
            assert queued["status"] == "pending"
            # The operator narrows the scope before the worker gets to it.
            narrowed = {"machine_enforcement": {"mode": "enforce", "in_scope": ["www.acme.test"]}}
            (control / "acme" / "roe.json").write_text(json.dumps(narrowed))
            (result,) = service.process_rerun_requests(
                queue, root=tmp_path / "data", control=control
            )
            assert result["status"] == "rejected" and "no longer in scope" in result["detail"]
            assert queue.pending_reruns() == []
            assert not (tmp_path / "data" / service.STORE_FILE).exists()  # nothing ran
        finally:
            queue.close()

    def test_worker_runs_an_engagement_when_its_scope_is_new_or_changed(
        self, tmp_path: Path
    ) -> None:
        control, root = tmp_path / "control", tmp_path / "data"
        (control / "acme").mkdir(parents=True)
        (control / "draft-only").mkdir()
        (control / "audit-mode").mkdir()
        (control / "acme" / "roe.json").write_text(json.dumps(ROE))
        (control / "audit-mode" / "roe.json").write_text(
            json.dumps({"machine_enforcement": {"mode": "audit", "in_scope": ["x.test"]}})
        )
        store = ReconStore(root / service.STORE_FILE)
        try:
            # Only the engagement with a usable enforced scope is due.
            assert service.engagements_due(store, control) == [("acme", "scope:new")]
            run = store.begin_run(
                "acme", trigger="scope:new", scope_digest=ScopeFilter.from_document(ROE).digest
            )
            assert service.engagements_due(store, control) == []  # running
            store.finish_run(run, status="completed", stats={})
            assert service.engagements_due(store, control) == []  # same scope, already run
            widened = {
                "machine_enforcement": {"mode": "enforce", "in_scope": ["*.acme.test", "new.test"]}
            }
            (control / "acme" / "roe.json").write_text(json.dumps(widened))
            assert service.engagements_due(store, control) == [("acme", "scope:changed")]
            (control / "acme" / "roe.json").write_text(json.dumps(ROE))
            assert service.engagements_due(store, control, refresh_seconds=3600) == []
            assert service.engagements_due(store, control, refresh_seconds=1e-9) == [
                ("acme", "refresh")
            ]
        finally:
            store.close()

    def test_a_slow_engagement_does_not_hold_up_the_next_one(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import threading

        control, root = tmp_path / "control", tmp_path / "data"
        for name in ("slow", "fast"):
            (control / name).mkdir(parents=True)
            (control / name / "roe.json").write_text(json.dumps(ROE))
        release = threading.Event()
        finished: list[str] = []

        def fake_run(engagement: str, *, trigger: str, root: Path, control: Path, **_kw):
            # Stands in for a scan: "slow" blocks until released.
            store = ReconStore(root / service.STORE_FILE)
            try:
                run = store.begin_run(
                    engagement, trigger=trigger, scope_digest=ScopeFilter.from_document(ROE).digest
                )
                if engagement == "slow":
                    assert release.wait(timeout=20)
                store.finish_run(run, status="completed", stats={})
            finally:
                store.close()
            finished.append(engagement)
            return {"run_id": run, "status": "completed"}

        monkeypatch.setattr(service, "run_engagement", fake_run)
        runner = service.EngagementRunner(parallel=2)
        try:
            assert sorted(runner.submit_due(root=root, control=control)) == ["fast", "slow"]
            deadline = time.monotonic() + 10
            while "fast" not in finished and time.monotonic() < deadline:
                time.sleep(0.02)
            assert finished == ["fast"]  # done while "slow" is still scanning
            assert runner.in_flight() == ["slow"]
            # A tick while a run is in flight never starts a second one for it.
            assert runner.submit_due(root=root, control=control) == []
            release.set()
            runner.wait(timeout=10)
            assert sorted(finished) == ["fast", "slow"]
            assert runner.submit_due(root=root, control=control) == []  # nothing left to do
        finally:
            release.set()
            runner.shutdown()

    def test_a_run_whose_process_died_is_closed_and_resumed(self, tmp_path: Path) -> None:
        from buggy.pipeline.query import ReconQueries

        control, root = tmp_path / "control", tmp_path / "data"
        (control / "acme").mkdir(parents=True)
        (control / "acme" / "roe.json").write_text(json.dumps(ROE))
        store = ReconStore(root / service.STORE_FILE)
        try:
            digest = ScopeFilter.from_document(ROE).digest
            run = store.begin_run("acme", trigger="scope:new", scope_digest=digest)
            store.set_run_progress(run, stage="issues", done=["enumerate", "dns", "live"])
            # A reader watching the run sees which stage it is in.
            queries = ReconQueries(store, None, data_root=root)
            current = queries.summary("acme")["current_run"]
            assert current["run_id"] == run and current["stage"] == "issues"
            assert current["stages_done"] == ["enumerate", "dns", "live"]
            assert queries.summary("acme")["last_run"] is None
            assert service.engagements_due(store, control) == []  # looks in progress
        finally:
            store.close()

        # While a live process holds the engagement, the run is left alone.
        with service.engagement_lock(root, "acme"):
            assert service.close_orphaned_runs(root) == []
        # The process is gone (container restart): the run is closed...
        assert service.close_orphaned_runs(root) == [run]
        assert service.close_orphaned_runs(root) == []
        store = ReconStore(root / service.STORE_FILE)
        try:
            closed = store.get_run(run)
            assert closed is not None
            assert closed["status"] == "interrupted" and closed["finished_at"]
            assert "stopped mid-run" in closed["stats"]["error"]
            assert closed["stats"]["stage"] == "issues"  # where it stopped is kept
            # ...and the engagement is due again instead of stuck forever.
            assert service.engagements_due(store, control) == [("acme", "resume")]
            assert ReconQueries(store, None, data_root=root).summary("acme")["current_run"] is None
        finally:
            store.close()

    def test_no_scope_means_no_run(self, tmp_path: Path) -> None:
        from buggy.pipeline.scope import ScopeError

        with pytest.raises(ScopeError, match="scope approve"):
            service.run_engagement("ghost", root=tmp_path / "data", control=tmp_path / "control")

    def test_one_run_per_engagement_at_a_time(self, tmp_path: Path) -> None:
        with service.engagement_lock(tmp_path, "acme"):
            with pytest.raises(service.PipelineBusy):
                with service.engagement_lock(tmp_path, "acme"):
                    pass
            with service.engagement_lock(tmp_path, "other"):
                pass
