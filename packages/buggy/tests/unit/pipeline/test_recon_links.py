"""Scripts a script loads, client routes, linked hosts and opt-in subdomain guessing."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools import jsparse, recovered, subguess
from buggy.pipeline.tools.katana import is_javascript

from .test_pipeline_flow import ROE, FakeOpener, FakeTools, _Body, _pipeline

# ── client routes ────────────────────────────────────────────────────

ROUTES = """
const routes = [{path: "administration", component: A}, {path: "order/:id"}, {path: "**"}];
e(Route, {path: "/profile"});
<Route path="/admin/users" element={<Users/>}/>
<Link to="/settings">Settings</Link>
<NavLink to={"/billing"}>Billing</NavLink>
navigate("/checkout"); router.push("/cart"); history.replace("/thanks");
s.replace("/api", ""); setCookie("a", 1, {path: "/"}); t({from: "en", to: "de"});
"""


def test_client_routes() -> None:
    assert jsparse.client_routes(ROUTES) == [
        "/administration",
        "/order/{id}",
        "/profile",
        "/admin/users",
        "/settings",
        "/billing",
        "/checkout",
        "/cart",
        "/thanks",
    ]


def test_routes_are_marked_on_endpoint_records() -> None:
    records = {r.value: r.attrs for r in jsparse.parse(ROUTES, js_url="https://a.test/main.js")}
    assert records["https://a.test/administration"]["client_route"] is True
    assert records["https://a.test/admin/users"]["client_route"] is True
    assert "client_route" not in records["https://a.test/api"]  # a .replace() argument


def test_recovered_source_reads_jsx_routes() -> None:
    hits = recovered.scan(
        'export const App = () => <Routes><Route path="/admin" element={<A/>}/>'
        '<Link to="/orders">x</Link></Routes>;\nconst i18n = {from: "en", to: "de"};\n'
    )
    routes = sorted(h["route"] for h in hits if "route" in h)
    assert routes == ["/admin", "/orders"]


# ── scripts a script loads ───────────────────────────────────────────


def test_webpack_lazy_chunks() -> None:
    runtime = (
        'r.p="/";r.u=e=>"static/js/"+({57:"admin"}[e]||e)+"."+{57:"a1b2",88:"c3d4"}[e]+".chunk.js";'
    )
    assert jsparse.script_references(runtime, js_url="https://a.test/static/js/main.js") == [
        "https://a.test/static/js/admin.a1b2.chunk.js",
        "https://a.test/static/js/88.c3d4.chunk.js",
    ]
    webpack5 = (
        '__webpack_require__.u = (chunkId) => { return "" + chunkId + "." + '
        '{"12":"a1","src_app_admin_ts":"b2"}[chunkId] + ".js"; }'
    )
    assert jsparse.script_references(webpack5, js_url="https://a.test/main.js") == [
        "https://a.test/12.a1.js",
        "https://a.test/src_app_admin_ts.b2.js",
    ]


def test_imports_and_vite_preload_lists() -> None:
    script = (
        'm.f=["assets/Admin-x1.js","assets/a.css"]; import("./Lazy-abc.js");'
        'import("/vendor/x.mjs"); const s = "not/a/script.json";'
    )
    assert jsparse.script_references(script, js_url="https://a.test/assets/index.js") == [
        "https://a.test/assets/Admin-x1.js",
        "https://a.test/assets/Lazy-abc.js",
        "https://a.test/vendor/x.mjs",
    ]


def test_script_suffixes() -> None:
    assert is_javascript("https://a.test/src/App.jsx")
    assert is_javascript("https://a.test/src/main.tsx")
    assert is_javascript("https://a.test/src/api.ts")
    assert is_javascript("https://a.test/x", "application/typescript")
    assert not is_javascript("https://a.test/video/hls/seg1.ts")
    assert not is_javascript("https://a.test/seg.ts", "video/mp2t")
    assert not is_javascript("https://a.test/app.css")


# ── subdomain guessing (pure) ────────────────────────────────────────


def test_permutations_and_candidates() -> None:
    assert {"api-dev", "dev-api", "apidev", "api2"} <= set(subguess.permutations("api"))
    assert {"app0", "app2", "app3"} <= set(subguess.permutations("app1"))
    names = subguess.candidates(
        "acme.test",
        ["api.acme.test", "www.acme.test"],
        allowed=lambda n: not n.startswith("admin."),
    )
    assert names[0] == "api-dev.acme.test"  # permutations of found hosts first
    assert "dev.acme.test" in names and "admin.acme.test" not in names
    assert "api.acme.test" not in names and len(names) <= subguess.MAX_GUESSES


def test_keep_drops_wildcard_echoes() -> None:
    answers = {
        "zzprobe1.a.test": {"192.0.2.9"},
        "zzprobe2.a.test": {"192.0.2.9"},
        "dev.a.test": {"192.0.2.9"},
        "vpn.a.test": {"192.0.2.20"},
        "nope.a.test": set(),
    }
    assert subguess.keep(answers, ["zzprobe1.a.test", "zzprobe2.a.test"]) == ["vpn.a.test"]


# ── in the pipeline ──────────────────────────────────────────────────


RUNTIME = (
    b'r.p="/";r.u=e=>"static/js/"+e+"."+{7:"ab12"}[e]+".chunk.js";'
    b'fetch("https://shop.acme.test/api/cart");'
)
CHUNK = b'const routes=[{path:"secret-admin"}];fetch("/api/hidden");'


class ChunkedApp(FakeOpener):
    def open(self, request, timeout=None) -> io.BytesIO:
        url = request.full_url
        if url == "https://www.acme.test/app.js":
            self.requested.append((request.get_method(), url))
            return _Body(RUNTIME)
        if url == "https://www.acme.test/static/js/7.ab12.chunk.js":
            self.requested.append((request.get_method(), url))
            return _Body(CHUNK)
        return super().open(request, timeout)


class LinkedTools(FakeTools):
    def __init__(self) -> None:
        super().__init__()
        self.address["shop.acme.test"] = "192.0.2.30"


@pytest.fixture
def env(tmp_path: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {
        "store": store,
        "root": tmp_path / "data",
        "tools": LinkedTools(),
        "opener": ChunkedApp(),
    }
    store.close()


def _values(env, kind: str, tool: str | None = None) -> dict[str, dict]:
    rows = env["store"].query_records("acme", record_type=kind)
    return {r.value: r.attrs for r in rows if tool is None or r.source_tool == tool}


class TestInThePipeline:
    def test_lazy_chunks_are_fetched_and_read(self, env) -> None:
        summary = _pipeline(env).run()
        chunk = "https://www.acme.test/static/js/7.ab12.chunk.js"
        assert ("GET", chunk) in env["opener"].requested
        loaded = _values(env, "js_file", "jsparse")
        assert loaded[chunk] == {"found_in": "https://www.acme.test/app.js", "kind": "loaded"}
        endpoints = _values(env, "endpoint")
        assert endpoints["https://www.acme.test/api/hidden"]["found_in"] == chunk
        assert endpoints["https://www.acme.test/secret-admin"]["client_route"] is True
        assert summary["stages"]["urls"]["tools"]["jsparse"]["loaded_scripts"] >= 1

    def test_a_linked_host_gets_its_own_round(self, env) -> None:
        summary = _pipeline(env).run()
        assert summary["linked_hosts"] == ["shop.acme.test"]
        subs = _values(env, "subdomain", "links")
        assert subs == {"shop.acme.test": {"found_in": "https://shop.acme.test/api/cart"}}
        calls = env["tools"].calls
        # The second round resolves, probes and crawls only the new host.
        dnsx = [inputs for name, inputs, _argv in calls if name == "dnsx"]
        assert dnsx[-1] == ["shop.acme.test"]
        httpx = [inputs for name, inputs, _argv in calls if name == "httpx"]
        assert len(httpx) == 2 and all("shop.acme.test" in t for t in httpx[-1])
        assert "https://shop.acme.test/" in _values(env, "http_service")
        # Out-of-scope links are never fed back.
        assert not {"admin.acme.test", "evil.example"} & set(_values(env, "subdomain", "links"))
        # A second run finds nothing new: no extra round.
        again = _pipeline(env).run()
        assert again["linked_hosts"] == []


class GuessTools(FakeTools):
    def __init__(self, *, wildcard: bool = False) -> None:
        super().__init__()
        self.wildcard = wildcard
        self.address.update({"dev.acme.test": "192.0.2.40", "api-dev.acme.test": "192.0.2.41"})

    def _dnsx(self, hosts: list[str]) -> str:
        if not self.wildcard:
            return super()._dnsx(hosts)
        return "".join(
            json.dumps({"host": h, "a": ["192.0.2.99"], "status_code": "NOERROR"}) + "\n"
            for h in hosts
        )


def _guess_roe() -> dict:
    roe = json.loads(json.dumps(ROE))
    roe["pipeline"]["subdomain_guess"] = True
    return roe


def test_guessing_is_off_by_default(env) -> None:
    env["tools"] = GuessTools()
    _pipeline(env).run()
    assert _values(env, "subdomain", "subdomain_guess") == {}


def test_guessed_names_that_resolve_are_kept(env) -> None:
    env["tools"] = GuessTools()
    summary = _pipeline(env, _guess_roe()).run()
    assert set(_values(env, "subdomain", "subdomain_guess")) == {
        "dev.acme.test",
        "api-dev.acme.test",
    }
    assert summary["stages"]["enumerate"]["tools"]["subdomain_guess"]["guessed"] > 100
    # Guesses go through the scope filter before anything is resolved.
    guessed = [i for n, i, _a in env["tools"].calls if n == "dnsx" and "dev.acme.test" in i][0]
    assert "admin.acme.test" not in guessed and all(h.endswith(".acme.test") for h in guessed)
    # The new hosts are resolved and probed like any other.
    assert "https://dev.acme.test/" in _values(env, "http_service")


def test_a_wildcard_zone_keeps_no_guess(env) -> None:
    env["tools"] = GuessTools(wildcard=True)
    _pipeline(env, _guess_roe()).run()
    assert _values(env, "subdomain", "subdomain_guess") == {}


def test_guessing_is_skipped_when_passive(env) -> None:
    env["tools"] = GuessTools()
    roe = _guess_roe()
    roe["pipeline"]["passive_only"] = True
    summary = _pipeline(env, roe).run()
    assert summary["stages"]["enumerate"]["tools"]["subdomain_guess"]["skipped"] == "passive_only"
    assert _values(env, "subdomain", "subdomain_guess") == {}
