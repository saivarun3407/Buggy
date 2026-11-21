"""JavaScript analysis beyond endpoints: source maps, DOM sinks, dependency names.

The pure functions are tested on the fixtures in ``fixtures/js``; the pipeline
tests drive the urls stage with the recording fakes of ``test_pipeline_flow``
and check what was requested, what was stored and how coverage was stamped.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

from buggy.pipeline.pipeline import Pipeline
from buggy.pipeline.report import rank_candidates
from buggy.pipeline.schema import RecordType
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools import jsparse

from .test_pipeline_flow import ROE, FakeOpener, FakeTools

FIXTURES = Path(__file__).parent / "fixtures" / "js"
JS_URL = "https://app.acme.test/static/bundle.min.js"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _fake_secret() -> str:
    """A credential-shaped value, built at run time and obviously fake."""
    return "zz" + "Q9" * 12 + "fake"


# ── source maps ─────────────────────────────────────────────────────


class TestSourceMaps:
    def test_minified_bundle_names_its_map_resolved_against_the_script(self) -> None:
        assert jsparse.source_maps(_read("bundle.min.js"), JS_URL) == [
            "https://app.acme.test/static/bundle.min.js.map"
        ]

    def test_block_comment_and_absolute_targets(self) -> None:
        text = "x();\n/*# sourceMappingURL=https://cdn.acme.test/m/app.map */"
        assert jsparse.source_maps(text, JS_URL) == ["https://cdn.acme.test/m/app.map"]

    def test_inline_data_uri_is_ignored(self) -> None:
        assert jsparse.source_maps(_read("inline_map.min.js"), JS_URL) == []

    def test_a_comment_inside_a_string_is_not_a_map(self) -> None:
        text = 'var s = "//# sourceMappingURL=fake.map"; var t = 1;'
        assert jsparse.source_maps(text, JS_URL) == []

    def test_non_http_targets_are_ignored(self) -> None:
        assert jsparse.source_maps("//# sourceMappingURL=file:///etc/passwd", JS_URL) == []

    def test_map_record_keeps_counts_and_names_not_content(self) -> None:
        names = [f"webpack:///src/m{i}.js" for i in range(25)]
        doc = {"version": 3, "sources": names, "sourcesContent": ["const hidden = 1;"] * 25}
        record = jsparse.source_map_record(JS_URL + ".map", doc, js_url=JS_URL)
        assert record is not None and record.type == RecordType.JS_FILE
        assert record.attrs["kind"] == "source_map"
        assert record.attrs["sources_count"] == 25
        assert record.attrs["sources_sample"] == names[:20]
        assert "hidden" not in json.dumps(record.attrs)

    def test_json_without_sources_is_not_a_map(self) -> None:
        assert jsparse.source_map_record(JS_URL + ".map", {"version": 3}, js_url=JS_URL) is None
        assert jsparse.source_map_record(JS_URL + ".map", ["sources"], js_url=JS_URL) is None


# ── DOM sinks ───────────────────────────────────────────────────────


EXPECTED_SINKS = [
    ("innerHTML", 3),
    ("outerHTML", 4),
    ("document.write", 5),
    ("insertAdjacentHTML", 6),
    ("eval", 7),
    ("new-Function", 8),
    ("setTimeout-string", 9),
    ("location-assign", 10),
    ("postMessage-wildcard", 11),
    ("message-listener-no-origin-check", 12),
]


class TestDomSinks:
    def test_each_sink_in_the_fixture_is_found_on_its_line(self) -> None:
        hits = jsparse.dom_sinks(_read("sinks.js"))
        assert [(h["sink"], h["line"]) for h in hits] == EXPECTED_SINKS

    def test_safe_look_alikes_in_the_fixture_are_not_flagged(self) -> None:
        text = _read("sinks.js")
        safe_from = text.splitlines().index("// Safe look-alikes below.") + 1
        assert all(h["line"] < safe_from for h in jsparse.dom_sinks(text))

    @pytest.mark.parametrize(
        "code",
        [
            "el.innerHTMLFoo = x;",
            "var copy = el.innerHTML;",
            "if (el.innerHTML == y) {}",
            "// eval(user.expr);",
            "/* eval(a); document.write(b); */",
            'var s = "eval(x) and el.innerHTML = y";',
            "myeval(1); obj.evaluate(2);",
            "var re = /eval\\(/g;",
            "setTimeout(function () {}, 10);",
            'window.location.href = "/home";',
            "location = '/login';",
            "obj.location = target;",
            'w.postMessage("ping", "https://app.acme.test");',
            'addEventListener("message", e => { if (e.origin !== o) return; go(e.data); });',
            'addEventListener("click", e => go(e));',
        ],
    )
    def test_negative_controls(self, code: str) -> None:
        assert jsparse.dom_sinks(code) == []

    @pytest.mark.parametrize(
        ("code", "sink"),
        [
            ("el.innerHTML += x;", "innerHTML"),
            ("document.writeln(x);", "document.write"),
            ("window.eval(x);", "eval"),
            ("setTimeout('go()', 5);", "setTimeout-string"),
            ("location = base + path;", "location-assign"),
            ('document.location.href = "/a?r=" + r;', "location-assign"),
            ("w.postMessage(data, '*');", "postMessage-wildcard"),
            ("addEventListener('message', function (e) { go(e.data); });", "onmessage"),
        ],
    )
    def test_positive_variants(self, code: str, sink: str) -> None:
        if sink == "onmessage":
            sink = "message-listener-no-origin-check"
        assert [h["sink"] for h in jsparse.dom_sinks(code)] == [sink]

    def test_origin_check_beyond_the_window_does_not_count(self) -> None:
        code = 'addEventListener("message", function (e) {' + " " * 400 + "e.origin; });"
        assert [h["sink"] for h in jsparse.dom_sinks(code)] == ["message-listener-no-origin-check"]

    def test_snippet_of_a_long_minified_line_is_bounded_and_around_the_hit(self) -> None:
        code = "var a=1;" * 500 + "el.innerHTML=x;" + "var b=2;" * 500
        (hit,) = jsparse.dom_sinks(code)
        assert hit["line"] == 1 and len(hit["snippet"]) <= 160
        assert "el.innerHTML=x;" in hit["snippet"]

    def test_secret_in_a_snippet_is_redacted(self) -> None:
        secret = _fake_secret()
        for code in (
            f'el.innerHTML = "{secret}";',
            f'el.innerHTML = render({{apiKey: "short-{secret[:6]}"}});',
        ):
            (hit,) = jsparse.dom_sinks(code)
            assert "<redacted>" in hit["snippet"]
            assert secret not in hit["snippet"] and secret[:6] not in hit["snippet"]

    def test_redaction_leaves_paths_and_plain_words(self) -> None:
        text = 'el.innerHTML = "/api/v1/users/profile/12345" + "hello world";'
        assert jsparse.redact(text) == text

    def test_hostile_input_is_scanned_quickly(self) -> None:
        nasty = "(/" * 200_000 + "/*" * 100_000 + '"' * 100_000 + "`" * 50_000
        started = time.monotonic()
        jsparse.dom_sinks(nasty)
        jsparse.package_names("node_modules/" * 50_000 + "a" * 300)
        assert time.monotonic() - started < 5


# ── dependency names ────────────────────────────────────────────────


class TestPackageNames:
    def test_webpack_module_paths_give_package_names(self) -> None:
        assert jsparse.package_names(_read("webpack.js")) == [
            "react",
            "@babel/runtime",
            "@acme-internal/billing-client",
            "lodash.debounce",
        ]

    def test_negative_controls(self) -> None:
        assert jsparse.package_names(_read("sinks.js")) == []
        assert jsparse.package_names('import x from "./src/node_modules_list";') == []
        assert jsparse.package_names("node_modules/.bin/tool node_modules/shim.js") == []

    def test_only_unknown_scopes_look_private(self) -> None:
        assert jsparse.looks_private("@acme-internal/billing-client")
        assert not jsparse.looks_private("@babel/runtime")
        assert not jsparse.looks_private("react")

    def test_analyze_tags_private_scopes_for_a_registry_check(self) -> None:
        found = jsparse.analyze(_read("webpack.js"), js_url=JS_URL).findings
        deps = {r.attrs["name"]: r.attrs for r in found if r.attrs["kind"] == "dependency"}
        assert set(deps) == {
            "react",
            "@babel/runtime",
            "@acme-internal/billing-client",
            "lodash.debounce",
        }
        assert deps["@acme-internal/billing-client"]["hint"] == "check-public-registry"
        assert all("hint" not in deps[n] for n in ("react", "@babel/runtime", "lodash.debounce"))
        assert all(r.type == RecordType.JS_FINDING for r in found)


def test_oversized_file_is_not_analysed() -> None:
    result = jsparse.analyze(
        "el.innerHTML = x;", js_url=JS_URL, size=jsparse.MAX_ANALYSIS_BYTES + 1
    )
    assert result.findings == [] and result.source_maps == [] and "not analysed" in result.partial
    small = jsparse.analyze("el.innerHTML = x;", js_url=JS_URL)
    assert [r.value for r in small.findings] == [f"{JS_URL}#innerHTML@1"] and small.partial == ""


def test_existing_endpoint_output_is_unchanged_by_the_new_analysis() -> None:
    script = _read("bundle.min.js")
    assert [r.value for r in jsparse.parse(script, js_url=JS_URL)] == [
        "https://app.acme.test/api/v2/items"
    ]


# ── in the pipeline ─────────────────────────────────────────────────


class ScriptOpener(FakeOpener):
    """``FakeOpener`` serving ``script`` for every ``app.js`` and a map for ``*.map``."""

    def __init__(self, script: str) -> None:
        super().__init__()
        self.script = script.encode()

    def open(self, request, timeout=None):
        url = request.full_url
        if url.endswith("/app.js"):
            self.requested.append((request.get_method(), url))
            return _Body(self.script)
        if url.endswith(".map"):
            self.requested.append((request.get_method(), url))
            names = [f"webpack:///src/file{i}.ts" for i in range(30)]
            return _Body(
                json.dumps({"version": 3, "sources": names, "sourcesContent": ["X"]}).encode()
            )
        return super().open(request, timeout)


class _Body(io.BytesIO):
    status = 200
    headers: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        return None


def _run(tmp_path: Path, script: str, **kwargs) -> tuple[ReconStore, ScriptOpener, Path]:
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    opener = ScriptOpener(script)
    crt = json.dumps([{"name_value": "www.acme.test"}]).encode()
    tools = FakeTools()
    Pipeline(
        store,
        ScopeFilter.from_document(ROE),
        "acme",
        data_root=tmp_path / "data",
        executor=tools.execute,
        resolver=tools.resolve,
        http_opener=opener,
        passive_fetch=lambda _url: crt,
        sleep=lambda _s: None,
        **kwargs,
    ).run()
    return store, opener, tmp_path / "data"


@pytest.fixture
def stores():
    opened: list[ReconStore] = []
    yield opened
    for store in opened:
        store.close()


def _urls(opener: ScriptOpener) -> list[str]:
    return [url for _method, url in opener.requested]


def test_in_scope_map_is_fetched_once_and_out_of_scope_maps_never(tmp_path, stores) -> None:
    script = (
        "el.innerHTML = x;\n"
        "//# sourceMappingURL=app.js.map\n"
        "//# sourceMappingURL=https://evil.example/app.js.map\n"
        "//# sourceMappingURL=https://admin.acme.test/app.js.map\n"
    )
    store, opener, _root = _run(tmp_path, script)
    stores.append(store)
    urls = _urls(opener)
    assert not any("evil.example" in u or "admin.acme.test" in u for u in urls)
    assert urls.count("https://www.acme.test/app.js.map") == 1
    maps = [
        r for r in store.query_records("acme", record_type="js_file") if r.value.endswith(".map")
    ]
    assert {r.value for r in maps} == {
        "https://www.acme.test/app.js.map",
        "https://www.acme.test:8443/app.js.map",
        "https://api.acme.test/app.js.map",
    }
    for record in maps:
        assert record.attrs["kind"] == "source_map" and record.attrs["sources_count"] == 30
        assert len(record.attrs["sources_sample"]) == 20
        assert "sourcesContent" not in record.attrs and "X" not in record.attrs["sources_sample"]
    drops = {(d["tool"], d["candidate"]) for d in store.scope_drops("acme")}
    assert any(tool == "jsparse" and "evil.example" in c for tool, c in drops)

    # A forced re-run fetches each map once again and never treats it as a script.
    opener.requested.clear()
    store2, opener2, _ = _run(tmp_path, script, force=True)
    stores.append(store2)
    assert _urls(opener2).count("https://www.acme.test/app.js.map") == 1


def test_sinks_and_dependencies_are_stored_with_secrets_redacted(tmp_path, stores) -> None:
    secret = _fake_secret()
    script = (
        f'el.innerHTML = "<i>{secret}</i>" + user;\n'
        "// eval(x);\n"
        "/*!*** ./node_modules/@acme-internal/billing-client/dist/index.js ***!*/\n"
    )
    store, _opener, root = _run(tmp_path, script)
    stores.append(store)
    found = store.query_records("acme", record_type=RecordType.JS_FINDING.value)
    by_value = {r.value: r for r in found}
    sink = by_value["https://www.acme.test/app.js#innerHTML@1"]
    assert sink.attrs["kind"] == "dom_sink" and sink.attrs["line"] == 1
    assert "<redacted>" in sink.attrs["snippet"]
    dep = by_value["https://www.acme.test/app.js#dependency:@acme-internal/billing-client"]
    assert dep.attrs["hint"] == "check-public-registry"
    assert not any("#eval@" in v for v in by_value)  # commented out
    assert all(secret not in json.dumps(r.to_dict()) for r in found)
    raw = (root / sink.raw_ref.split("#")[0]).read_text()
    assert secret not in raw and '"kind": "dom_sink"' in raw


def test_oversized_script_is_skipped_and_stamped_partial(tmp_path, stores) -> None:
    script = "el.innerHTML = x;\n//# sourceMappingURL=app.js.map\n" + "a" * (
        jsparse.MAX_ANALYSIS_BYTES + 1
    )
    store, opener, _root = _run(tmp_path, script)
    stores.append(store)
    assert store.query_records("acme", record_type=RecordType.JS_FINDING.value) == []
    assert not any(u.endswith(".map") for u in _urls(opener))
    stamps = {(r["stage"], r["asset"]): (r["status"], r["detail"]) for r in store.coverage("acme")}
    for host in ("www.acme.test", "api.acme.test"):
        status, detail = stamps[("urls", host)]
        assert status == "partial" and "not analysed" in detail


def test_small_scripts_leave_the_stamp_complete(tmp_path, stores) -> None:
    store, _opener, _root = _run(tmp_path, "el.innerHTML = x;\n")
    stores.append(store)
    stamps = {(r["stage"], r["asset"]): r["status"] for r in store.coverage("acme")}
    assert stamps[("urls", "www.acme.test")] == "complete"


# ── report ──────────────────────────────────────────────────────────


def _finding(value: str, **attrs) -> dict:
    return {"type": "js_finding", "value": value, "attrs": attrs}


def test_report_ranks_scripts_with_dom_sinks_as_xss_candidates() -> None:
    script = "https://a.test/app.js"
    rows = rank_candidates(
        {
            "js_finding": [
                _finding(f"{script}#eval@3", kind="dom_sink", sink="eval", line=3, found_in=script),
                _finding(
                    f"{script}#innerHTML@9",
                    kind="dom_sink",
                    sink="innerHTML",
                    line=9,
                    found_in=script,
                ),
                _finding(
                    "https://a.test/vendor.js#dependency:react",
                    kind="dependency",
                    name="react",
                    found_in="https://a.test/vendor.js",
                ),
            ]
        }
    )
    xss = [r for r in rows if r["class"] == "xss"]
    assert xss == [
        {
            "class": "xss",
            "where": script,
            "why": "DOM sinks: eval (line 3), innerHTML (line 9)",
            "probe": "xss_reflected",
        }
    ]


def test_report_has_no_xss_row_without_dom_sinks() -> None:
    rows = rank_candidates(
        {
            "js_finding": [
                _finding("https://a.test/v.js#dependency:react", kind="dependency", name="react")
            ]
        }
    )
    assert [r for r in rows if r["class"] == "xss"] == []
