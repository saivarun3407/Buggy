"""Parameter records: every input the target accepts, extracted from stored records.

The first half drives ``params.extract`` with fixture records and checks the
parameter set, locations and hints, with controls for what must *not* become a
parameter (static assets, bare numbers, other record types) and for secrets.
The second half runs the real pipeline with the recording fakes from
``test_pipeline_flow`` and checks that extraction is in-process (no tool call,
no request), cached and retired with the ``apispec`` stage, and adds no
coverage stage.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from buggy.pipeline import versions
from buggy.pipeline.pipeline import COVERAGE_STAGES, Pipeline
from buggy.pipeline.query import ReconQueries
from buggy.pipeline.schema import RecordType, StoredRecord
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools import apirecon, apispec, params, webrecon

from .test_pipeline_flow import ROE, FakeOpener, FakeTools

UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
OBJECT_ID = "507f1f77bcf86cd799439011"


def _stored(kind: str, value: str, tools: tuple[str, ...] = ("katana",), **attrs) -> StoredRecord:
    host = urlsplit(value.split(" ")[-1]).hostname or ""
    return StoredRecord(
        id=f"{kind}:{value}",
        engagement="acme",
        asset=host,
        type=kind,
        value=value,
        attrs=attrs,
        source_tool=tools[0],
        tool_version="1",
        first_seen=0.0,
        last_seen=0.0,
        first_run_id="r1",
        last_run_id="r1",
        raw_ref="",
        content_hash="",
        status="active",
        sources=tools,
    )


def _found(records: list[StoredRecord]) -> dict[str, tuple[str, list[str]]]:
    return {r.value: (r.attrs["location"], r.attrs["hints"]) for r in params.extract(records)}


BODY_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "profile": {
            "type": "object",
            "properties": {
                "image_url": {"type": "string"},
                "age": {"type": "integer", "example": 30},
            },
        },
        "items": {
            "type": "array",
            "items": {"type": "object", "properties": {"product_id": {"type": "integer"}}},
        },
        "tags": {"type": "array", "items": {"type": "string"}},
    },
}

CASES = [
    pytest.param(
        [_stored("url", "https://a.test/search?q=shoes")],
        {"GET https://a.test/search query:q": ("query", [])},
        id="plain-query-name",
    ),
    pytest.param(
        [_stored("url", "https://a.test/fetch?url=https://x.test/a.png")],
        {"GET https://a.test/fetch query:url": ("query", ["url-like"])},
        id="query-named-url",
    ),
    pytest.param(
        [_stored("url", "https://a.test/go?target=https%3A%2F%2Fx.test%2Fhome")],
        {"GET https://a.test/go query:target": ("query", ["url-like"])},
        id="query-with-http-example",
    ),
    pytest.param(
        [_stored("url", "https://a.test/go?target=home")],
        {"GET https://a.test/go query:target": ("query", [])},
        id="same-name-without-http-example-is-not-url-like",
    ),
    pytest.param(
        [_stored("endpoint", "https://a.test/api/orders/1002", ("jsparse",))],
        {"GET https://a.test/api/orders/1002 path:orders_id": ("path", ["id-like", "numeric"])},
        id="numeric-path-id",
    ),
    pytest.param(
        [_stored("url", f"https://a.test/users/{UUID}/keys")],
        {f"GET https://a.test/users/{UUID}/keys path:users_id": ("path", ["id-like"])},
        id="uuid-path-id",
    ),
    pytest.param(
        [_stored("url", f"https://a.test/docs/{OBJECT_ID}")],
        {f"GET https://a.test/docs/{OBJECT_ID} path:docs_id": ("path", ["id-like"])},
        id="24-hex-path-id",
    ),
    pytest.param(
        [_stored("endpoint", "https://a.test/10"), _stored("url", "https://a.test/v2/users")],
        {},
        id="bare-number-and-version-segment-are-not-ids",
    ),
    pytest.param(
        [_stored("endpoint", "https://a.test/api/users/:id/posts", ("jsparse",))],
        {"GET https://a.test/api/users/:id/posts path:id": ("path", ["id-like"])},
        id="route-placeholder",
    ),
    pytest.param(
        [_stored("url", "https://a.test/download?file=report.txt&page=2")],
        {
            "GET https://a.test/download query:file": ("query", ["file-like"]),
            "GET https://a.test/download query:page": ("query", ["file-like", "numeric"]),
        },
        id="file-like-and-numeric",
    ),
    pytest.param(
        [_stored("url", "https://a.test/submit?user_id=7&userId=8&valid=1", method="POST")],
        {
            "POST https://a.test/submit query:user_id": ("query", ["id-like", "numeric"]),
            "POST https://a.test/submit query:userId": ("query", ["id-like", "numeric"]),
            "POST https://a.test/submit query:valid": ("query", ["numeric"]),
        },
        id="id-names-and-the-crawled-method",
    ),
    pytest.param(
        [
            _stored(
                "api_operation",
                "GET https://a.test/v1/items/{itemId}",
                ("openapi",),
                method="GET",
                url="https://a.test/v1/items/{itemId}",
                parameters=[
                    {"name": "itemId", "in": "path", "required": True},
                    {"name": "expand", "in": "query", "required": False},
                    {"name": "X-Api-Key", "in": "header", "required": True},
                    {"name": "session", "in": "cookie", "required": False},
                ],
            )
        ],
        {
            "GET https://a.test/v1/items/{itemId} path:itemId": ("path", ["id-like"]),
            "GET https://a.test/v1/items/{itemId} query:expand": ("query", []),
            "GET https://a.test/v1/items/{itemId} header:X-Api-Key": ("header", ["auth-like"]),
            "GET https://a.test/v1/items/{itemId} cookie:session": ("cookie", ["auth-like"]),
        },
        id="openapi-declared-parameters",
    ),
    pytest.param(
        [
            _stored(
                "api_operation",
                "POST https://a.test/v1/users",
                ("openapi",),
                method="POST",
                url="https://a.test/v1/users",
                parameters=[],
                request_body_schema=BODY_SCHEMA,
            )
        ],
        {
            "POST https://a.test/v1/users body:name": ("body", []),
            "POST https://a.test/v1/users body:profile.image_url": ("body", ["url-like"]),
            "POST https://a.test/v1/users body:profile.age": ("body", ["numeric"]),
            "POST https://a.test/v1/users body:items[].product_id": ("body", ["id-like"]),
            "POST https://a.test/v1/users body:tags": ("body", []),
        },
        id="nested-openapi-body-properties",
    ),
    pytest.param(
        [
            _stored(
                "api_operation",
                "POST https://a.test/v1/upload",
                ("openapi",),
                method="POST",
                url="https://a.test/v1/upload",
                parameters=[
                    {"name": "payload", "in": "body"},  # Swagger 2: names the body itself
                    {"name": "filename", "in": "formData"},
                ],
                request_body_properties=["callback"],
            )
        ],
        {
            "POST https://a.test/v1/upload form:filename": ("form", ["file-like"]),
            "POST https://a.test/v1/upload body:callback": ("body", ["url-like"]),
        },
        id="swagger2-form-data-and-flat-body-names",
    ),
    pytest.param(
        [
            _stored(
                "url",
                "https://a.test/account",
                form=[
                    {"action": "/login", "method": "post", "parameters": ["username", "next"]},
                    {"action": "https://other.test/x", "method": "post", "parameters": ["a"]},
                ],
            )
        ],
        {
            "POST https://a.test/login form:username": ("form", []),
            "POST https://a.test/login form:next": ("form", ["url-like"]),
        },
        id="form-list-already-in-attrs",
    ),
    pytest.param(
        [
            _stored("js_file", "https://a.test/app.js?id=3"),
            _stored("http_service", "https://a.test/?id=3"),
            _stored("vulnerability", "x https://a.test/api/orders/7?file=a"),
        ],
        {},
        id="other-record-types-are-not-inputs",
    ),
]


@pytest.mark.parametrize(("records", "expected"), CASES)
def test_fixture_records_yield_the_expected_parameters(records, expected) -> None:
    assert _found(records) == expected


def test_a_parameter_record_has_the_agreed_shape() -> None:
    long_value = "v" * 200
    (record,) = params.extract(
        [_stored("url", f"https://A.test:443/Search?q={long_value}", ("gau", "katana"))]
    )
    assert record.type is RecordType.PARAMETER and record.source_tool == "params"
    assert record.asset == "a.test"
    assert record.value == "GET https://a.test/Search query:q"
    assert record.attrs == {
        "name": "q",
        "location": "query",
        "method": "GET",
        "url": "https://a.test/Search",
        "example": "v" * 80,  # one example, truncated
        "sources": ["gau", "katana"],
        "hints": [],
    }


@pytest.mark.parametrize(
    "url",
    [
        "https://a.test/static/app.js?v=3",
        "https://a.test/assets/42/site.css?file=x",
        "https://a.test/img/logo.png?url=https://x.test/",
        "https://a.test/users/7/avatar.JPG?id=7",
        "https://a.test/fonts/a.woff2?token=1",
    ],
)
def test_static_assets_yield_no_parameters(url: str) -> None:
    assert _found([_stored("url", url), _stored("endpoint", url, ("jsparse",))]) == {}
    # Control: the same query and path on a page that is not a static file do.
    path, query = url.split("?", 1)
    page = path.rsplit(".", 1)[0] + "?" + query
    assert _found([_stored("url", page)]) != {}


def test_the_same_parameter_from_two_sources_is_one_record_with_both() -> None:
    crawled = _stored("url", "https://a.test/search?q=shoes", ("gau", "katana"))
    declared = _stored(
        "api_operation",
        "GET https://a.test/search",
        ("openapi",),
        method="GET",
        url="https://a.test/search",
        parameters=[{"name": "q", "in": "query"}, {"name": "limit", "in": "query"}],
    )
    both = {r.value: r.attrs for r in params.extract([crawled, declared])}
    assert set(both) == {
        "GET https://a.test/search query:q",
        "GET https://a.test/search query:limit",
    }
    assert both["GET https://a.test/search query:q"]["sources"] == ["gau", "katana", "openapi"]
    assert both["GET https://a.test/search query:q"]["example"] == "shoes"
    # Control: a parameter only one of them names keeps that one source.
    assert both["GET https://a.test/search query:limit"]["sources"] == ["openapi"]
    # A different method or location is a different parameter, not a merge.
    posted = _stored("url", "https://a.test/search?q=hats", ("katana",), method="POST")
    assert len(list(params.extract([crawled, declared, posted]))) == 3


def test_the_result_does_not_depend_on_record_order() -> None:
    records = [
        _stored("url", "https://a.test/items?id=9&next=home"),
        _stored("url", "https://a.test/items?id=10&next=https://x.test/"),
        _stored("endpoint", "https://a.test/items?id=abc", ("jsparse",)),
    ]
    forward = [(r.value, r.attrs) for r in params.extract(records)]
    assert forward == [(r.value, r.attrs) for r in params.extract(reversed(records))]
    by_name = {attrs["name"]: attrs for _value, attrs in forward}
    assert by_name["id"]["hints"] == ["id-like"]  # "abc" was seen too: not numeric
    # The stored example is the one the url-like hint came from.
    assert by_name["next"]["example"] == "https://x.test/"
    assert by_name["next"]["hints"] == ["url-like"]


def test_secret_examples_are_never_stored() -> None:
    token = "tok" + "en-value-" + "4f9a1c"
    password = "hunter2-" + "not-real"
    bearer = "eyJ" + "hbGciOiJub25lIn0" + "." + "eyJzdWIiOiIxIn0" + "." + "c2ln"
    records = [
        _stored("url", f"https://a.test/cb?token={token}&state=xyz"),
        _stored("url", f"https://a.test/cb2?access_token={token}&apiKey={token}&key={token}"),
        _stored("url", f"https://a.test/login?password={password}&user=bob"),
        _stored("url", f"https://a.test/cont?continue={bearer}"),
        _stored(
            "api_operation",
            "POST https://a.test/v1/session",
            ("openapi",),
            method="POST",
            url="https://a.test/v1/session",
            request_body_schema={"properties": {"jwt": {"type": "string", "example": token}}},
        ),
    ]
    found = {r.attrs["name"]: r for r in params.extract(records)}
    for name in ("token", "access_token", "apiKey", "key", "jwt"):
        assert found[name].attrs["example"] == params.REDACTED, name
        assert "auth-like" in found[name].attrs["hints"], name
    # Not hinted as auth-like, still a credential: redacted all the same.
    assert found["password"].attrs["example"] == params.REDACTED
    assert found["continue"].attrs["example"] == params.REDACTED
    blob = json.dumps([[r.value, r.attrs] for r in found.values()])
    assert token not in blob and password not in blob and bearer not in blob
    # Control: ordinary values are kept, and no value means nothing to redact.
    assert found["state"].attrs["example"] == "xyz" and found["user"].attrs["example"] == "bob"
    (declared,) = params.extract(
        [
            _stored(
                "api_operation",
                "GET https://a.test/v1/me",
                ("openapi",),
                method="GET",
                url="https://a.test/v1/me",
                parameters=[{"name": "token", "in": "query"}],
            )
        ]
    )
    assert declared.attrs["example"] == "" and declared.attrs["hints"] == ["auth-like"]


def test_extract_reads_the_dict_form_of_a_record_too() -> None:
    record = _stored("url", "https://a.test/fetch?url=https://x.test/a.png", ("gau", "katana"))
    assert [(r.value, r.attrs) for r in params.extract([record.to_dict()])] == [
        (r.value, r.attrs) for r in params.extract([record])
    ]


# ── in the pipeline ──────────────────────────────────────────────────

WWW_PDF = "GET https://www.acme.test/old/report.pdf query:id"
API_PDF = "GET https://api.acme.test/old/report.pdf query:id"
USER_ID = "GET https://www.acme.test/v1/users/{userId} path:userId"
USER_FIELDS = "GET https://www.acme.test/v1/users/{userId} query:fields"


class SpecOpener(FakeOpener):
    """``FakeOpener`` whose published spec declares parameters (and can change)."""

    def __init__(self) -> None:
        super().__init__()
        self.SPEC = {
            "openapi": "3.0.0",
            "info": {"title": "Acme"},
            "paths": {
                "/v1/users/{userId}": {
                    "get": {
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True},
                            {"name": "fields", "in": "query"},
                        ]
                    }
                }
            },
        }


@pytest.fixture
def env(tmp_path: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {"store": store, "root": tmp_path / "data", "tools": FakeTools(), "opener": SpecOpener()}
    store.close()


def _pipeline(env, **kwargs) -> Pipeline:
    crt = json.dumps([{"name_value": "www.acme.test\ncrt-only.acme.test\n*.acme.test"}]).encode()
    return Pipeline(
        env["store"],
        ScopeFilter.from_document(ROE),
        "acme",
        data_root=env["root"],
        executor=env["tools"].execute,
        resolver=env["tools"].resolve,
        http_opener=env["opener"],
        passive_fetch=lambda _url: crt,
        sleep=lambda _s: None,
        **kwargs,
    )


def _parameters(env) -> dict[str, StoredRecord]:
    return {r.value: r for r in env["store"].query_records("acme", record_type="parameter")}


class TestInThePipeline:
    def test_a_run_stores_parameters_from_what_it_already_collected(self, env) -> None:
        summary = _pipeline(env).run()
        found = _parameters(env)
        assert set(found) == {WWW_PDF, API_PDF, USER_ID, USER_FIELDS}
        archived = found[WWW_PDF]
        assert archived.asset == "www.acme.test"
        assert archived.source_tool == "params" and archived.sources == ("params",)
        assert archived.tool_version == versions.BUILTIN_VERSION == "builtin-1"
        assert archived.attrs == {
            "name": "id",
            "location": "query",
            "method": "GET",
            "url": "https://www.acme.test/old/report.pdf",
            "example": "1",
            "sources": ["gau"],
            "hints": ["id-like", "numeric"],
        }
        assert found[USER_ID].attrs["sources"] == ["openapi"]
        assert found[USER_ID].attrs["hints"] == ["id-like"]
        # Each record points at a line of registered raw output that names it.
        ref, _, line = archived.raw_ref.partition("#L")
        assert ref == f"raw/acme/{summary['run_id']}/apispec-params.jsonl"
        assert env["store"].raw_output("acme", archived.raw_ref)["tool"] == "params"
        raw = (env["root"] / ref).read_text().splitlines()
        assert json.loads(raw[int(line) - 1])["parameter"] == WWW_PDF
        assert summary["stages"]["apispec"]["tools"]["params"]["records"] == 4
        # The agents' query surface knows the type.
        queries = ReconQueries(env["store"], None, data_root=env["root"])
        assert "parameter" in queries.summary("acme")["record_types"]
        page = queries.query("acme", record_type="parameter", asset="api.acme.test")
        assert [r["value"] for r in page["records"]] == [API_PDF]

    def test_extraction_adds_no_tool_call_no_request_and_no_coverage_stage(self, env) -> None:
        _pipeline(env).run()
        assert _parameters(env)
        # The external calls are exactly the ones the stages made before.
        assert sorted(name for name, _inputs, _argv in env["tools"].calls) == sorted([
            "subfinder", "amass", "dnsx", "naabu", "httpx",
            "katana", "gau", "waybackurls", "nuclei", "gitleaks",
        ])  # fmt: skip
        # Every request is a known file, a spec or discovery probe, a script
        # fetch or one API endpoint profile, never with a query: no URL a
        # parameter was read from is ever requested as it was found.
        probes = {
            *apispec.OPENAPI_PATHS,
            *apispec.GRAPHQL_PATHS,
            *webrecon.KNOWN_FILES,
            *apirecon.OIDC_PATHS,
            "/app.js",
            "/api/v1/users",
            "/v1/users",
        }
        assert env["opener"].requested
        for _method, url in env["opener"].requested:
            assert urlsplit(url).path in probes and not urlsplit(url).query, url
        rows = env["store"].coverage("acme")
        assert {row["stage"] for row in rows} == set(COVERAGE_STAGES)
        stamps = {(row["stage"], row["asset"]): row["status"] for row in rows}
        assert stamps[("apispec", "www.acme.test")] == "complete"
        assert stamps[("apispec", "api.acme.test")] == "complete"

    def test_parameters_are_cached_with_the_stage(self, env) -> None:
        _pipeline(env).run()
        before = {value: record.last_run_id for value, record in _parameters(env).items()}
        summary = _pipeline(env).run()
        assert summary["diff"] == {"added": 0, "changed": 0, "removed": 0}
        assert "params" not in summary["stages"]["apispec"]["tools"]  # stage cached: not re-run
        assert {v: r.last_run_id for v, r in _parameters(env).items()} == before
        # Forced: re-derived, identical, so still no change.
        forced = _pipeline(env, force=True).run()
        assert forced["stages"]["apispec"]["tools"]["params"]["records"] == 4
        assert forced["diff"] == {"added": 0, "changed": 0, "removed": 0}
        assert all(r.last_run_id == forced["run_id"] for r in _parameters(env).values())

    def test_a_parameter_whose_source_is_gone_is_retired(self, env) -> None:
        _pipeline(env).run()
        assert USER_FIELDS in _parameters(env)
        # The spec no longer declares the operation.
        env["opener"].SPEC = {**env["opener"].SPEC, "paths": {"/v1/ping": {"get": {}}}}
        summary = _pipeline(env, force=True).run()
        removed = {
            (c["type"], c["value"])
            for c in env["store"].diff("acme", summary["run_id"])
            if c["change"] == "removed"
        }
        assert ("parameter", USER_ID) in removed and ("parameter", USER_FIELDS) in removed
        # Control: parameters whose source is still there are untouched.
        assert set(_parameters(env)) == {WWW_PDF, API_PDF}
        assert ("parameter", WWW_PDF) not in removed

    def test_a_secret_in_a_crawled_url_does_not_reach_a_parameter_record(self, env) -> None:
        secret = "s3ss" + "-" + "c0ffee1234"

        class Leaky(FakeTools):
            def _gau(self, hosts: list[str]) -> str:
                return "".join(
                    json.dumps({"url": f"https://{h}/cb?session={secret}&lang=en"}) + "\n"
                    for h in hosts
                )

        env["tools"] = Leaky()
        summary = _pipeline(env).run()
        session = _parameters(env)["GET https://www.acme.test/cb query:session"]
        assert session.attrs["example"] == params.REDACTED
        assert _parameters(env)["GET https://www.acme.test/cb query:lang"].attrs["example"] == "en"
        assert secret not in json.dumps([r.to_dict() for r in _parameters(env).values()])
        raw = env["root"] / f"raw/acme/{summary['run_id']}/apispec-params.jsonl"
        assert secret not in raw.read_text() and params.REDACTED in raw.read_text()
