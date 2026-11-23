"""Recovered source: original files rebuilt from a published source map, scanned with fixed rules.

The fixture ``fixtures/js/recovered.js.map`` is a webpack-style map whose
``sourcesContent`` holds a small Angular app. The credential the environment
file carries is built at run time (``__FAKE_KEY__`` is replaced) so no
key-shaped literal sits in the repository.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from buggy.findings.candidates import from_ranked
from buggy.pipeline.pipeline import Pipeline
from buggy.pipeline.report import rank_candidates
from buggy.pipeline.schema import RecordType
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools import recovered

from .test_pipeline_flow import ROE, FakeOpener, FakeTools

FIXTURE = Path(__file__).parent / "fixtures" / "js" / "recovered.js.map"
MAP_URL = "https://www.acme.test/main.js.map"
JS_URL = "https://www.acme.test/main.js"


def _fake_key() -> str:
    """Shaped like a cloud access key id, built at run time and obviously fake."""
    return "AKIA" + "Z7" * 8


def _document() -> dict:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    document["sourcesContent"] = [
        text.replace("__FAKE_KEY__", _fake_key()) for text in document["sourcesContent"]
    ]
    return document


def _in_scope(host: str) -> bool:
    return host == "acme.test" or host.endswith(".acme.test")


class TestFileNames:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("webpack:///./src/app/x.ts", "src/app/x.ts"),
            ("webpack:///../../../../etc/escape.ts", "etc/escape.ts"),
            ("/abs/path/y.ts", "abs/path/y.ts"),
            ("C:\\Users\\dev\\win.ts", "Users/dev/win.ts"),
            ("ng://app/a b$c.ts", "app/a_b_c.ts"),
            ("src/..\\..\\..\\z.ts", "src/z.ts"),
            ("../..", None),
            ("", None),
        ],
    )
    def test_names_never_leave_the_directory(self, name: str, expected: str | None) -> None:
        assert recovered.safe_relative(name) == expected

    def test_third_party_code_is_recognised(self) -> None:
        assert recovered.third_party("webpack:///node_modules/lodash/lodash.js")
        assert recovered.third_party("webpack:///webpack/bootstrap")
        assert not recovered.third_party("webpack:///./src/app/app.ts")


class TestRebuild:
    def test_files_are_written_inside_the_destination_only(self, tmp_path: Path) -> None:
        dest = tmp_path / "work" / "recovered" / "m"
        files, partial = recovered.rebuild(_document(), dest)
        assert partial == ""
        names = sorted(f.name for f in files)
        assert names == [
            "Users/dev/src/win.ts",
            "etc/escape.ts",
            "src/app/admin/admin.guard.ts",
            "src/app/app.routes.ts",
            "src/app/notes.ts",
            "src/app/search/search.component.ts",
            "src/environments/environment.ts",
        ]
        written = sorted(p for p in tmp_path.rglob("*") if p.is_file())
        assert all(p.resolve().is_relative_to(dest.resolve()) for p in written)
        assert len(written) == len(names)  # node_modules and the webpack runtime are skipped

    def test_two_sources_with_one_safe_name_do_not_overwrite_each_other(
        self, tmp_path: Path
    ) -> None:
        document = {
            "sources": ["webpack:///src/a.ts", "webpack:///../src/a.ts"],
            "sourcesContent": ["one\n", "two\n"],
        }
        files, _ = recovered.rebuild(document, tmp_path)
        assert [f.name for f in files] == ["src/a.ts", "src/a.ts~2"]
        assert (tmp_path / "src" / "a.ts").read_text() == "one\n"

    def test_limits(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(recovered, "MAX_FILE_BYTES", 10)
        document = {"sources": ["a.ts", "b.ts"], "sourcesContent": ["x" * 11, "short\n"]}
        files, partial = recovered.rebuild(document, tmp_path)
        assert [f.name for f in files] == ["b.ts"] and "not scanned" in partial
        monkeypatch.setattr(recovered, "MAX_FILES", 1)
        document = {"sources": ["a.ts", "b.ts"], "sourcesContent": ["1\n", "2\n"]}
        files, partial = recovered.rebuild(document, tmp_path / "two")
        assert len(files) == 1 and "more than 1" in partial

    @pytest.mark.parametrize(
        "document",
        [None, [], {"sources": ["a.ts"]}, {"sources": "a.ts", "sourcesContent": ["x"]}],
    )
    def test_maps_without_content_give_nothing(self, tmp_path: Path, document) -> None:
        assert recovered.rebuild(document, tmp_path) == ([], "")


class TestScan:
    @pytest.fixture
    def hits(self, tmp_path: Path) -> dict[tuple[str, str, int], dict]:
        result = recovered.analyze(
            _document(), map_url=MAP_URL, js_url=JS_URL, dest=tmp_path, in_scope=_in_scope
        )
        return {
            (r.attrs["rule"], r.attrs["file"], r.attrs["line"]): r.attrs for r in result.findings
        }

    def test_each_rule_finds_its_line_in_the_original_file(self, hits) -> None:
        assert set(hits) == {
            ("client_auth", "src/app/admin/admin.guard.ts", 4),
            ("client_auth", "src/app/admin/admin.guard.ts", 5),
            ("client_auth", "src/app/admin/admin.guard.ts", 7),
            ("dom_sink", "src/app/search/search.component.ts", 6),
            ("endpoint", "src/app/search/search.component.ts", 3),
            ("endpoint", "src/app/search/search.component.ts", 4),
            ("endpoint", "src/app/app.routes.ts", 2),
            ("endpoint", "src/app/app.routes.ts", 5),
            ("endpoint", "src/app/app.routes.ts", 6),
            ("endpoint", "src/app/app.routes.ts", 7),
            ("secret", "src/environments/environment.ts", 4),
            ("debug_flag", "src/environments/environment.ts", 2),
            ("debug_flag", "src/environments/environment.ts", 3),
        }

    def test_details(self, hits) -> None:
        sink = hits[("dom_sink", "src/app/search/search.component.ts", 6)]
        assert sink["kind"] == "recovered_source" and sink["detail"] == "innerHTML"
        assert sink["map"] == MAP_URL and sink["found_in"] == JS_URL
        assert "panel.innerHTML" in sink["snippet"]
        users = hits[("endpoint", "src/app/search/search.component.ts", 4)]
        assert users["url"] == "https://www.acme.test/api/Users/{id}"
        route = hits[("endpoint", "src/app/app.routes.ts", 2)]
        assert route["route"] == "administration" and "url" not in route
        assert hits[("secret", "src/environments/environment.ts", 4)]["detail"] == (
            "aws_access_key_id"
        )
        assert hits[("client_auth", "src/app/admin/admin.guard.ts", 7)]["detail"] == (
            "role === 'admin'"
        )

    def test_an_out_of_scope_endpoint_keeps_no_url(self, hits) -> None:
        assert "url" not in hits[("endpoint", "src/app/app.routes.ts", 7)]

    def test_the_secret_value_is_never_kept(self, hits) -> None:
        assert _fake_key() not in json.dumps(list(hits.values()))
        assert hits[("secret", "src/environments/environment.ts", 4)]["snippet"] == (
            "awsKey: '<redacted>',"
        )

    def test_comments_strings_and_third_party_code_do_not_count(self, hits) -> None:
        assert not any(file == "src/app/notes.ts" for _rule, file, _line in hits)
        assert not any("lodash" in file or "bootstrap" in file for _r, file, _l in hits)

    def test_a_generic_key_assignment_counts_only_when_key_shaped(self) -> None:
        value = "ab12" * 5
        found = recovered.scan(f"const clientSecret = '{value}';\nconst password = 'changeme';\n")
        assert [(h["rule"], h["detail"], h["line"]) for h in found] == [
            ("secret", "hardcoded:clientSecret", 1)
        ]
        assert value not in found[0]["snippet"]

    def test_hostile_input_is_scanned_quickly(self) -> None:
        text = ("isAdmin(" * 20000) + ("'" * 20000) + ("debug = " * 20000)
        assert recovered.scan(text, deadline=None) is not None


# ── the pipeline step ───────────────────────────────────────────────


class _Body(io.BytesIO):
    status = 200
    headers: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        return None


class MapOpener(FakeOpener):
    """Serves a script naming ``main.js.map`` and the fixture map."""

    def __init__(self) -> None:
        super().__init__()
        self.map = json.dumps(_document()).encode()

    def open(self, request, timeout=None):
        url = request.full_url
        if url.endswith("/app.js"):
            self.requested.append((request.get_method(), url))
            return _Body(b"var a = 1;\n//# sourceMappingURL=main.js.map\n")
        if url.endswith(".map"):
            self.requested.append((request.get_method(), url))
            return _Body(self.map)
        return super().open(request, timeout)


def _run(tmp_path: Path, roe: dict) -> tuple[ReconStore, MapOpener, Path]:
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    opener = MapOpener()
    crt = json.dumps([{"name_value": "www.acme.test"}]).encode()
    tools = FakeTools()
    Pipeline(
        store,
        ScopeFilter.from_document(roe),
        "acme",
        data_root=tmp_path / "data",
        executor=tools.execute,
        resolver=tools.resolve,
        http_opener=opener,
        passive_fetch=lambda _url: crt,
        sleep=lambda _s: None,
    ).run()
    return store, opener, tmp_path / "data"


def test_the_urls_stage_rebuilds_and_scans_each_map_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The run's work directory is removed when the run ends; keep it to look inside.
    monkeypatch.setattr("buggy.pipeline.pipeline.shutil.rmtree", lambda *_a, **_k: None)
    store, opener, root = _run(tmp_path, ROE)
    try:
        maps = [url for _m, url in opener.requested if url.endswith(".map")]
        assert maps.count("https://www.acme.test/main.js.map") == 1
        found = [
            r
            for r in store.query_records("acme", record_type=RecordType.JS_FINDING.value)
            if r.attrs.get("kind") == "recovered_source"
            and r.attrs["map"] == "https://www.acme.test/main.js.map"
        ]
        rules = {(r.attrs["rule"], r.attrs["file"], r.attrs["line"]) for r in found}
        assert ("dom_sink", "src/app/search/search.component.ts", 6) in rules
        assert ("secret", "src/environments/environment.ts", 4) in rules
        assert all(_fake_key() not in json.dumps(r.to_dict()) for r in found)
        work = root / "work" / "acme"
        rebuilt = sorted(p.name for p in work.rglob("*.ts"))
        assert "admin.guard.ts" in rebuilt and "lodash.js" not in rebuilt
        for path in work.rglob("*"):
            assert path.resolve().is_relative_to(work.resolve())
        raw = (root / found[0].raw_ref.split("#")[0]).read_text()
        assert _fake_key() not in raw and '"kind": "recovered_source"' in raw
    finally:
        store.close()


def test_passive_only_fetches_and_rebuilds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("buggy.pipeline.pipeline.shutil.rmtree", lambda *_a, **_k: None)
    roe = json.loads(json.dumps(ROE))
    roe["pipeline"]["passive_only"] = True
    store, opener, root = _run(tmp_path, roe)
    try:
        assert not any(url.endswith(".map") for _m, url in opener.requested)
        assert not list(root.rglob("*.ts"))
        found = store.query_records("acme", record_type=RecordType.JS_FINDING.value)
        assert not any(r.attrs.get("kind") == "recovered_source" for r in found)
    finally:
        store.close()


# ── leads ───────────────────────────────────────────────────────────


def _records(tmp_path: Path) -> dict[str, list[dict]]:
    result = recovered.analyze(
        _document(), map_url=MAP_URL, js_url=JS_URL, dest=tmp_path, in_scope=_in_scope
    )
    return {"js_finding": [_as_dict(r) for r in result.findings]}


def _as_dict(record) -> dict:
    return {"type": record.type.value, "value": record.value, "attrs": record.attrs}


def test_each_rule_becomes_a_ranked_lead_naming_file_and_line(tmp_path: Path) -> None:
    rows = rank_candidates(_records(tmp_path))
    by_class = {(r["class"], r["where"]): r for r in rows}
    auth = by_class[("access_control", MAP_URL)]
    assert "src/app/admin/admin.guard.ts:7" in auth["why"] and "low-privilege" in auth["why"]
    assert (
        "aws_access_key_id (src/environments/environment.ts:4)"
        in (by_class[("info_exposure", MAP_URL)]["why"])
    )
    assert by_class[("xss", MAP_URL)]["probe"] == "xss_reflected"
    assert "production: false" in by_class[("misconfiguration", MAP_URL)]["why"]
    assert "/api/Users/{id}" in by_class[("api", MAP_URL)]["why"]
    admin = by_class[("access_control", "https://www.acme.test/api/admin/users")]
    assert "src/app/app.routes.ts:5" in admin["why"]
    assert ("auth_session", "https://www.acme.test/rest/user/login") in by_class
    assert all(_fake_key() not in json.dumps(r) for r in rows)


def test_leads_are_queued_as_candidates_that_still_need_proof(tmp_path: Path) -> None:
    leads = from_ranked(rank_candidates(_records(tmp_path)), "acme")
    recovered_leads = [
        lead for lead in leads if "recovered from the source map" in lead["description"]
    ]
    assert recovered_leads
    for lead in recovered_leads:
        assert lead["status"] == "candidate" and lead["severity"] == "info"
        assert lead["assertions"] == []
