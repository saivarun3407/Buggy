"""The pipeline end to end, with the scanners replaced by a recording fake.

The fake executor writes output in each tool's real format (the shapes pinned
by ``test_parsers.py``) derived from the inputs it was given, and records
exactly what every tool was asked to scan. That is what lets these tests
assert the property that matters: an out-of-scope asset never reaches a tool,
and never reaches the store.
"""

from __future__ import annotations

import hashlib
import io
import json
import time
import urllib.error
from pathlib import Path

import pytest

from buggy.pipeline import versions
from buggy.pipeline.pipeline import STAGES, Pipeline
from buggy.pipeline.runner import RunResult
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools.apispec import INTROSPECTION_QUERY
from buggy.pipeline.tools.base import Invocation

OUT_OF_SCOPE = ("admin.acme.test", "deep.a.acme.test", "evil.example", "cdn.other.net")

ROE = {
    "machine_enforcement": {
        "mode": "enforce",
        "in_scope": ["*.acme.test", "acme.test"],
        "out_of_scope": ["admin.acme.test"],
        "min_inter_request_delay_ms": 100,  # 10 rps
        "max_concurrent_connections": 4,
    },
    "pipeline": {"ports": "443,8443"},
}


class FakeTools:
    """Stands in for every scanner binary and records what each was given."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], list[str]]] = []  # (tool, inputs, argv)
        self.extra_subdomains: list[str] = []
        self.missing: set[str] = set()
        self.address = {"www.acme.test": "192.0.2.10", "api.acme.test": "192.0.2.11"}

    # resolver ------------------------------------------------------
    def resolve(self, name: str) -> tuple[str, str]:
        if name in self.missing:
            raise versions.ToolVersionError(f"{name} is not installed")
        return f"/usr/local/bin/{name}", versions.PINNED[name].version

    # executor ------------------------------------------------------
    def _inputs(self, name: str, invocation: Invocation) -> list[str]:
        argv = invocation.argv
        for flag in ("-dL", "-df", "-l", "-list"):
            if flag in argv:
                return Path(argv[argv.index(flag) + 1]).read_text().split()
        if invocation.stdin is not None:
            return invocation.stdin.split()
        if name == "gau":
            return [a for a in argv[1:] if not a.startswith("-") and "." in a and "," not in a]
        return argv[1:3]  # gitleaks: [mode, path]

    def execute(self, name: str, invocation: Invocation, raw_path: Path) -> RunResult:
        inputs = self._inputs(name, invocation)
        self.calls.append((name, inputs, list(invocation.argv)))
        text = getattr(self, f"_{name}")(inputs)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(text)
        now = time.time()
        return RunResult(
            argv=tuple(invocation.argv),
            exit_code=0,
            raw_path=raw_path,
            sha256=hashlib.sha256(text.encode()).hexdigest(),
            size=len(text.encode()),
            started_at=now,
            finished_at=now,
            timed_out=False,
            stderr_tail="",
        )

    def _subfinder(self, roots: list[str]) -> str:
        hosts = [
            "www.acme.test",
            "api.acme.test",
            "admin.acme.test",
            "deep.a.acme.test",
            "evil.example",
        ]
        hosts += self.extra_subdomains
        return "".join(
            json.dumps({"host": h, "input": roots[0], "sources": ["anubis"]}) + "\n" for h in hosts
        )

    def _amass(self, _roots: list[str]) -> str:
        return (
            "www.acme.test (FQDN) --> a_record --> 192.0.2.10 (IPAddress)\n"
            "www.acme.test (FQDN) --> cname_record --> cdn.other.net (FQDN)\n"
        )

    def _dnsx(self, hosts: list[str]) -> str:
        lines = []
        for host in hosts:
            if host in self.address:
                obj = {"host": host, "a": [self.address[host]], "status_code": "NOERROR"}
                if host == "www.acme.test":
                    obj["cname"] = ["cdn.other.net"]
                lines.append(json.dumps(obj))
        return "\n".join(lines) + "\n"

    def _naabu(self, hosts: list[str]) -> str:
        lines = []
        for host in hosts:
            ports = [443, 8443] if host == "www.acme.test" else [443]
            lines += [
                json.dumps({"host": host, "ip": "192.0.2.10", "port": p, "protocol": "tcp"})
                for p in ports
            ]
        return "\n".join(lines) + "\n"

    def _httpx(self, targets: list[str]) -> str:
        lines = []
        for target in targets:
            host, _, port = target.partition(":")
            url = f"https://{host}" + (f":{port}" if port and port != "443" else "")
            lines.append(
                json.dumps(
                    {
                        "url": url,
                        "input": target,
                        "scheme": "https",
                        "port": port or "443",
                        "status_code": 200,
                        "title": f"{host} home",
                        "tech": ["nginx:1.25.3"],
                        "location": "https://evil.example/login",
                        "header": {"x_frame_options": "DENY"},
                        "tls": {
                            "probe_status": True,
                            "subject_cn": host,
                            "fingerprint_hash": {"sha256": "ab" * 32},
                        },
                        "failed": False,
                    }
                )
            )
        return "\n".join(lines) + "\n"

    def _katana(self, urls: list[str]) -> str:
        lines = []
        for url in urls:
            base = url.rstrip("/")
            for endpoint in (
                f"{base}/",
                f"{base}/app.js",
                f"{base}/login",
                "https://evil.example/track",
                "https://admin.acme.test/",
            ):
                lines.append(
                    json.dumps(
                        {
                            "request": {"method": "GET", "endpoint": endpoint, "source": url},
                            "response": {"status_code": 200, "headers": {}},
                        }
                    )
                )
        return "\n".join(lines) + "\n"

    def _gau(self, hosts: list[str]) -> str:
        return "".join(
            json.dumps({"url": f"https://{h}/old/report.pdf?id=1"}) + "\n"
            for h in [*hosts, "evil.example"]
        )

    def _waybackurls(self, hosts: list[str]) -> str:
        return "".join(f"https://{h}/legacy/\n" for h in [*hosts, "deep.a.acme.test"])

    def _nuclei(self, urls: list[str]) -> str:
        return (
            json.dumps(
                {
                    "template-id": "exposed-config",
                    "info": {"name": "Exposed config", "severity": "high", "tags": ["exposure"]},
                    "type": "http",
                    "host": urls[0],
                    "matched-at": urls[0].rstrip("/") + "/config.json",
                }
            )
            + "\n"
        )

    def _gitleaks(self, args: list[str]) -> str:
        files = sorted(p.name for p in Path(args[1]).glob("*.js"))
        return json.dumps(
            [
                {
                    "RuleID": "generic-api-key",
                    "File": f"{args[1]}/{files[0]}",
                    "StartLine": 2,
                    "Fingerprint": "f",
                }
            ]
            if files
            else []
        )


class FakeOpener:
    """Stands in for the network under the pipeline's built-in HTTP stages."""

    SPEC = {"openapi": "3.0.0", "info": {"title": "Acme"}, "paths": {"/v1/users": {"get": {}}}}
    SCHEMA = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [
                    {"kind": "OBJECT", "name": "Query", "fields": [{"name": "me", "args": []}]}
                ],
            }
        }
    }

    def __init__(self) -> None:
        self.requested: list[tuple[str, str]] = []

    def open(self, request, timeout=None) -> io.BytesIO:  # noqa: ARG002
        url, method = request.full_url, request.get_method()
        self.requested.append((method, url))
        if url.endswith("/app.js"):
            return _Body(
                b'fetch("/api/v1/users"); load("https://evil.example/t.js");\nconst k = "x";'
            )
        if url == "https://www.acme.test/openapi.json":
            return _Body(json.dumps(self.SPEC).encode())
        if url == "https://api.acme.test/graphql" and method == "POST":
            assert json.loads(request.data)["query"] == INTROSPECTION_QUERY
            return _Body(json.dumps(self.SCHEMA).encode())
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))


class _Body(io.BytesIO):
    status = 200
    headers: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        return None


@pytest.fixture
def env(tmp_path: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {"store": store, "root": tmp_path / "data", "tools": FakeTools(), "opener": FakeOpener()}
    store.close()


def _pipeline(env, roe: dict | None = None, **kwargs) -> Pipeline:
    crt = json.dumps([{"name_value": "www.acme.test\ncrt-only.acme.test\n*.acme.test"}]).encode()
    return Pipeline(
        env["store"],
        ScopeFilter.from_document(roe or ROE),
        "acme",
        data_root=env["root"],
        executor=env["tools"].execute,
        resolver=env["tools"].resolve,
        http_opener=env["opener"],
        passive_fetch=lambda _url: crt,
        sleep=lambda _s: None,
        **kwargs,
    )


def _called(env) -> list[str]:
    return [name for name, _inputs, _argv in env["tools"].calls]


class TestFullRun:
    def test_stages_run_in_order(self, env) -> None:
        summary = _pipeline(env).run()
        assert summary["status"] == "completed"
        assert list(summary["stages"]) == list(STAGES)
        called = _called(env)
        # Tools that run at the same time are compared as a group.
        assert set(called[:2]) == {"subfinder", "amass"}  # 1 enumerate (+ crt.sh, together)
        assert called[2:5] == ["dnsx", "naabu", "httpx"]  # 2 dns, 3 live
        # 5 urls: the crawler and the archive lookups, with the issue scan
        # started next to them (it only needs the live services).
        assert set(called[5:9]) == {"katana", "gau", "waybackurls", "nuclei"}
        assert called[9:] == ["gitleaks"]  # 9 issues (6-8 are built in)

    def test_out_of_scope_assets_never_reach_a_tool(self, env) -> None:
        _pipeline(env).run()
        for name, inputs, argv in env["tools"].calls:
            blob = " ".join([*inputs, *argv])
            for forbidden in OUT_OF_SCOPE:
                assert forbidden not in blob, f"{name} was given {forbidden}"
        # dnsx got exactly the in-scope names from all three enumeration sources.
        dnsx_inputs = next(inputs for name, inputs, _ in env["tools"].calls if name == "dnsx")
        assert sorted(dnsx_inputs) == [
            "acme.test",
            "api.acme.test",
            "crt-only.acme.test",
            "www.acme.test",
        ]
        # The built-in HTTP stages requested in-scope URLs only.
        assert env["opener"].requested
        for _method, url in env["opener"].requested:
            assert url.startswith(("https://www.acme.test", "https://api.acme.test"))

    def test_out_of_scope_outputs_are_dropped_and_logged_not_stored(self, env) -> None:
        pipeline = _pipeline(env)
        summary = pipeline.run()
        store = env["store"]
        scope = pipeline.scope
        records = store.query_records("acme", status=None, limit=1000)
        assert records and all(scope.allows(r.asset) for r in records)
        assert not [
            r
            for r in records
            if any(bad in r.value for bad in ("evil.example", "admin.acme.test"))
            and r.type in ("url", "endpoint", "subdomain", "http_service")
        ]
        drops = store.scope_drops("acme", run_id=summary["run_id"])
        seen = {(d["stage"], d["tool"], d["direction"], d["candidate"], d["reason"]) for d in drops}
        assert ("enumerate", "subfinder", "output", "admin.acme.test", "OUT_OF_SCOPE") in seen
        assert ("enumerate", "subfinder", "output", "deep.a.acme.test", "NOT_IN_SCOPE") in seen
        assert ("enumerate", "subfinder", "output", "evil.example", "NOT_IN_SCOPE") in seen
        assert ("urls", "katana", "output", "evil.example", "NOT_IN_SCOPE") in seen
        assert ("urls", "jsparse", "output", "evil.example", "NOT_IN_SCOPE") in seen
        assert summary["scope_drops"] == len(drops)

    def test_every_record_type_lands_in_the_one_schema(self, env) -> None:
        _pipeline(env).run()
        counts = env["store"].count_records("acme")
        assert counts == {
            "api_base": 4,  # /api/v1 on three services, /v1 on www (web and API recon)
            "api_operation": 1,
            "api_spec": 1,
            "auth_surface": 3,  # the /login page of each service
            "dns_record": 3,
            "endpoint": 3,
            "graphql": 1,
            "header": 3,
            "http_service": 3,
            "js_file": 3,
            "parameter": 2,  # the two archived URLs with an ?id= query
            "port": 3,
            "secret": 1,
            "subdomain": 4,
            "technology": 3,
            "tls": 3,
            "url": 10,
            "vulnerability": 1,
            "web_finding": 12,  # four headers the three services did not send
        }
        (www,) = env["store"].query_records("acme", record_type="subdomain", asset="www.acme.test")
        assert www.sources == ("amass", "crtsh", "subfinder")  # deduplicated across sources

    def test_records_point_at_registered_raw_output(self, env) -> None:
        summary = _pipeline(env).run()
        store, root = env["store"], env["root"]
        (finding,) = store.query_records("acme", record_type="vulnerability")
        assert finding.raw_ref == f"raw/acme/{summary['run_id']}/issues-nuclei.out#L1"
        assert finding.tool_version == versions.PINNED["nuclei"].version
        meta = store.raw_output("acme", finding.raw_ref)
        raw_file = root / finding.raw_ref.split("#")[0]
        assert hashlib.sha256(raw_file.read_bytes()).hexdigest() == meta["sha256"]
        assert meta["argv"][0] == "/usr/local/bin/nuclei" and meta["tool"] == "nuclei"
        assert "exposed-config" in raw_file.read_text().splitlines()[0]
        # Built-in stages keep raw output too.
        (spec,) = store.query_records("acme", record_type="api_spec")
        assert (root / spec.raw_ref.split("#")[0]).is_file()

    def test_program_rate_limits_reach_every_active_tool(self, env) -> None:
        _pipeline(env).run()
        argv = {name: a for name, _inputs, a in env["tools"].calls}
        assert argv["httpx"][argv["httpx"].index("-rl") + 1] == "10"
        assert argv["httpx"][argv["httpx"].index("-t") + 1] == "4"
        assert argv["naabu"][argv["naabu"].index("-rate") + 1] == "10"
        assert argv["naabu"][argv["naabu"].index("-p") + 1] == "443,8443"
        # The crawler and the issue scan run at the same time, so they share the
        # program's rate and connections: together never more than 10 req/s.
        katana_rl = int(argv["katana"][argv["katana"].index("-rl") + 1])
        nuclei_rl = int(argv["nuclei"][argv["nuclei"].index("-rl") + 1])
        assert (katana_rl, nuclei_rl) == (5, 5) and katana_rl + nuclei_rl == 10
        assert (
            int(argv["katana"][argv["katana"].index("-c") + 1])
            + int(argv["nuclei"][argv["nuclei"].index("-c") + 1])
            <= 4
        )


class TestReRuns:
    def test_second_run_processes_nothing_and_reports_no_change(self, env) -> None:
        _pipeline(env).run()
        env["tools"].calls.clear()
        env["opener"].requested.clear()
        summary = _pipeline(env).run()
        assert env["tools"].calls == [] and env["opener"].requested == []
        assert summary["diff"] == {"added": 0, "changed": 0, "removed": 0}
        assert all(s["processed"] == 0 for s in summary["stages"].values())

    def test_only_new_assets_are_processed_and_the_diff_names_them(self, env) -> None:
        _pipeline(env).run()
        store = env["store"]
        # Enumeration becomes due again; everything downstream stays cached.
        with store._tx() as cur:  # noqa: SLF001 - test-only cache expiry
            cur.execute("DELETE FROM stage_cache WHERE stage = 'enumerate'")
        env["tools"].extra_subdomains = ["new.acme.test"]
        env["tools"].address["new.acme.test"] = "192.0.2.12"
        env["tools"].calls.clear()

        summary = _pipeline(env).run()
        inputs = {name: i for name, i, _argv in env["tools"].calls}
        assert inputs["dnsx"] == ["new.acme.test"]
        assert inputs["naabu"] == ["new.acme.test"]
        assert inputs["httpx"] == ["new.acme.test:443"]
        assert inputs["katana"] == ["https://new.acme.test/"]
        assert inputs["nuclei"] == ["https://new.acme.test/"]
        changes = store.diff("acme", summary["run_id"])
        assert {c["change"] for c in changes} == {"added"}
        assert {c["asset"] for c in changes} == {"new.acme.test"}
        assert summary["diff"]["added"] == len(changes) > 5

    def test_changed_upstream_fact_reprocesses_that_asset_only(self, env) -> None:
        _pipeline(env).run()
        store = env["store"]
        env["tools"].address["api.acme.test"] = "192.0.2.99"  # api moved
        with store._tx() as cur:  # noqa: SLF001 - make the DNS stage due for every host
            cur.execute("DELETE FROM stage_cache WHERE stage = 'dns'")
        env["tools"].calls.clear()
        summary = _pipeline(env).run()
        inputs = {name: i for name, i, _argv in env["tools"].calls}
        assert inputs["naabu"] == ["api.acme.test"]  # www's DNS did not change
        changes = {
            (c["change"], c["type"], c["value"]) for c in store.diff("acme", summary["run_id"])
        }
        assert ("added", "dns_record", "A 192.0.2.99") in changes
        assert ("removed", "dns_record", "A 192.0.2.11") in changes

    def test_force_reprocesses_everything(self, env) -> None:
        _pipeline(env).run()
        env["tools"].calls.clear()
        summary = _pipeline(env, force=True).run()
        assert set(_called(env)[:2]) == {"subfinder", "amass"} and _called(env)[2] == "dnsx"
        assert summary["diff"] == {"added": 0, "changed": 0, "removed": 0}

    def test_service_that_disappears_is_retired_with_what_was_found_on_it(self, env) -> None:
        _pipeline(env).run()
        store = env["store"]
        del env["tools"].address["api.acme.test"]  # api no longer resolves
        summary = _pipeline(env, force=True).run()
        removed = {
            (c["type"], c["asset"])
            for c in store.diff("acme", summary["run_id"])
            if c["change"] == "removed"
        }
        assert ("dns_record", "api.acme.test") in removed
        assert ("graphql", "api.acme.test") not in {
            (r.type, r.asset) for r in store.query_records("acme")
        }
        assert store.query_records(
            "acme", record_type="subdomain", asset="api.acme.test"
        )  # names accumulate

    def test_only_asset_restricts_every_stage(self, env) -> None:
        _pipeline(env).run()
        env["tools"].calls.clear()
        _pipeline(env, only_asset="api.acme.test", force=True).run()
        inputs = {name: i for name, i, _argv in env["tools"].calls}
        assert inputs["dnsx"] == ["api.acme.test"]
        assert inputs["httpx"] == ["api.acme.test:443"]
        assert "subfinder" in inputs  # api.acme.test sits under the enumeration root
        assert all(
            "www.acme.test" not in " ".join(i)
            for name, i in inputs.items()
            if name not in ("subfinder", "amass")
        )


class TestProgramRules:
    def test_passive_only_never_touches_the_target(self, env) -> None:
        roe = json.loads(json.dumps(ROE))
        roe["pipeline"] = {"passive_only": True}
        summary = _pipeline(env, roe).run()
        assert set(_called(env)) <= {"subfinder", "amass", "dnsx"}
        assert env["opener"].requested == []
        assert summary["stages"]["live"]["tools"]["httpx"]["skipped"] == "passive_only"
        assert summary["stages"]["apispec"]["skipped"] == "passive_only"
        assert set(env["store"].count_records("acme")) == {"subdomain", "dns_record"}

    def test_disabled_stage_is_skipped(self, env) -> None:
        roe = json.loads(json.dumps(ROE))
        roe["pipeline"]["disabled_stages"] = ["issues"]
        summary = _pipeline(env, roe).run()
        assert "nuclei" not in _called(env)
        assert summary["stages"]["issues"]["skipped"] == "disabled by program rules"

    def test_port_scan_can_be_turned_off(self, env) -> None:
        roe = json.loads(json.dumps(ROE))
        roe["pipeline"]["port_scan"] = False
        _pipeline(env, roe).run()
        assert "naabu" not in _called(env)
        httpx_inputs = next(i for name, i, _ in env["tools"].calls if name == "httpx")
        assert "www.acme.test" in httpx_inputs  # default ports, no host:port targets

    def test_missing_tool_is_reported_and_the_run_continues(self, env) -> None:
        env["tools"].missing = {"naabu", "nuclei"}
        summary = _pipeline(env).run()
        assert summary["status"] == "completed"
        assert "not installed" in summary["stages"]["live"]["tools"]["naabu"]["error"]
        assert "not installed" in summary["stages"]["issues"]["tools"]["nuclei"]["error"]
        assert env["store"].count_records("acme")["http_service"] == 2
        # The unscanned services are not marked processed: the next run retries them.
        env["tools"].missing = set()
        env["tools"].calls.clear()
        _pipeline(env).run()
        assert "nuclei" in _called(env)

    def test_failed_run_is_recorded(self, env) -> None:
        def boom(*_args):
            raise RuntimeError("disk full")

        pipeline = _pipeline(env)
        pipeline._executor = boom  # noqa: SLF001
        with pytest.raises(RuntimeError):
            pipeline.run()
        run = env["store"].latest_run("acme")
        assert run["status"] == "failed" and "disk full" in run["stats"]["error"]
