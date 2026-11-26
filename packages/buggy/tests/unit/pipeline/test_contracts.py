"""Operator-supplied API contracts (OpenAPI, Swagger, Postman) as pipeline input.

The first half drives ``contracts.load`` with the three fixture files under
``fixtures/contracts`` and checks the operations each yields, what the scope
filter drops, how Postman variables resolve and that no credential in a
fixture leaves the module. Every fake credential in the fixtures contains the
word in ``CANARY``, so one search proves a record set is clean.

The second half runs the real pipeline with the recording fakes from
``test_pipeline_flow``: a contract adds records and parameters but no tool
call and no request, is cached on the hash of its file, and is retired when
the scope document stops naming it.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

import pytest

from buggy.pipeline.pipeline import Pipeline
from buggy.pipeline.schema import Record, RecordType
from buggy.pipeline.scope import PipelineLimits, ScopeFilter
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools import apispec, contracts

from .test_pipeline_flow import ROE, FakeOpener, FakeTools

FIXTURES = Path(__file__).parent / "fixtures" / "contracts"
OPENAPI, SWAGGER, POSTMAN = "shop.openapi.yaml", "legacy.swagger.json", "accounts.postman.json"
CANARY = "LEAKCANARY"
IN_SCOPE = ["*.example.test"]


def _entry(path: str, base_url: str = "", fmt: str = "auto") -> dict[str, str]:
    return {"path": path, "base_url": base_url, "format": fmt}


def _scope(in_scope: list[str] | None = None) -> tuple[ScopeFilter, list[tuple[str, ...]]]:
    """A scope filter and the list its drops are logged to."""
    drops: list[tuple[str, ...]] = []
    scope = ScopeFilter.from_document(
        {"machine_enforcement": {"mode": "enforce", "in_scope": in_scope or IN_SCOPE}},
        log_drop=lambda *row: drops.append(row),
    )
    return scope, drops


@pytest.fixture
def control(tmp_path: Path) -> Path:
    """``<control>/<engagement>`` holding a copy of the fixture contracts."""
    directory = tmp_path / "control" / "acme"
    shutil.copytree(FIXTURES, directory / "contracts")
    return directory


def _load(control: Path, entry: dict[str, str], in_scope: list[str] | None = None):
    scope, drops = _scope(in_scope)
    return contracts.load(control, entry, scope), drops


def _operations(records: list[Record]) -> dict[str, dict]:
    return {r.value: r.attrs for r in records if r.type == RecordType.API_OPERATION}


def _specs(records: list[Record]) -> list[Record]:
    return [r for r in records if r.type == RecordType.API_SPEC]


def _parameters(attrs: dict) -> set[tuple[str, str]]:
    return {(p["in"], p["name"]) for p in attrs["parameters"]}


def _blob(records: list[Record]) -> str:
    return json.dumps([[r.type.value, r.asset, r.value, r.source_tool, r.attrs] for r in records])


# ── each fixture yields the expected operations ──────────────────────────


class TestFixtures:
    def test_openapi3_yaml(self, control: Path) -> None:
        records, _drops = _load(control, _entry(OPENAPI))
        operations = _operations(records)
        base = "https://api.example.test/v1"
        assert set(operations) == {
            f"GET {base}/orders",
            f"POST {base}/orders",
            f"GET {base}/orders/{{orderId}}",
            f"DELETE {base}/orders/{{orderId}}",
            f"GET {base}/health",
        }
        listing = operations[f"GET {base}/orders"]
        assert listing["method"] == "GET" and listing["url"] == f"{base}/orders"
        assert _parameters(listing) == {("query", "status"), ("header", "X-Request-Id")}
        assert listing["auth_required"] is True  # the document's global security
        assert listing["operation_id"] == "listOrders" and listing["tags"] == ["orders"]
        create = operations[f"POST {base}/orders"]
        assert create["request_body_types"] == ["application/json"]
        # $ref resolved, nested objects dotted, arrays of objects as name[],
        # and a schema that contains itself stops at the first repeat.
        assert create["request_body_properties"] == [
            "customer_id",
            "coupon",
            "shipping.address",
            "shipping.callback_url",
            "items[].product_id",
            "items[].quantity",
            "category.name",
            "category.parent",
        ]
        for verb in ("GET", "DELETE"):
            one = operations[f"{verb} {base}/orders/{{orderId}}"]
            assert _parameters(one) == {("path", "orderId")}  # declared on the path item
            assert one["auth_required"] is True
        assert operations[f"GET {base}/health"]["auth_required"] is False  # security: []
        (spec,) = _specs(records)
        assert (spec.asset, spec.value) == ("api.example.test", f"contract:{OPENAPI}")
        assert spec.attrs["format"] == "openapi" and spec.attrs["spec_version"] == "3.0.3"
        assert spec.attrs["base_url"] == base and spec.attrs["operation_count"] == 5
        assert spec.attrs["security_schemes"] == ["bearerAuth"]

    def test_swagger2_json(self, control: Path) -> None:
        records, drops = _load(control, _entry(SWAGGER))
        operations = _operations(records)
        base = "https://legacy.example.test/api"  # host + basePath, first scheme
        assert set(operations) == {
            f"GET {base}/users/{{id}}",
            f"POST {base}/users",
            f"POST {base}/login",
        }
        get = operations[f"GET {base}/users/{{id}}"]
        assert _parameters(get) == {("path", "id"), ("query", "expand")}
        assert get["auth_required"] is True
        create = operations[f"POST {base}/users"]
        assert _parameters(create) == {("body", "body")}
        assert create["request_body_properties"] == [
            "username",
            "password",
            "profile.display_name",
            "profile.avatar_url",
        ]
        login = operations[f"POST {base}/login"]
        assert _parameters(login) == {("formData", "username"), ("formData", "password")}
        assert login["auth_required"] is False and login["request_body_properties"] == []
        (spec,) = _specs(records)
        assert spec.asset == "legacy.example.test" and spec.attrs["format"] == "swagger"
        assert spec.attrs["security_schemes"] == ["api_key"]
        assert drops == []

    def test_postman_v21(self, control: Path) -> None:
        records, _drops = _load(control, _entry(POSTMAN))
        operations = _operations(records)
        base = "https://api.example.test"
        assert set(operations) == {
            f"GET {base}/v2/users",
            f"POST {base}/v2/users",
            f"GET {base}/v2/users/{{userId}}",
            f"POST {base}/login",
            f"GET {base}/health",
        }
        listing = operations[f"GET {base}/v2/users"]
        assert listing["method"] == "GET" and listing["url"] == f"{base}/v2/users"
        assert _parameters(listing) == {
            ("query", "limit"),
            ("query", "api_key"),
            ("header", "X-Trace-Id"),
        }
        assert listing["header_names"] == ["Accept", "X-Trace-Id", "Authorization"]
        assert listing["auth_required"] is True and listing["tags"] == ["Users"]
        create = operations[f"POST {base}/v2/users"]
        assert create["request_body_mode"] == "raw"
        assert create["request_body_types"] == ["application/json"]
        assert create["request_body_properties"] == [
            "email",
            "password",
            "age",  # its value is an unquoted {{variable}} in the fixture
            "profile.display_name",
            "profile.avatar_url",
            "roles[].role_id",
            "tags",
        ]
        assert create["auth_required"] is True  # inherited from the collection
        one = operations[f"GET {base}/v2/users/{{userId}}"]
        assert _parameters(one) == {("path", "userId"), ("query", "fields")}
        assert one["auth_required"] is True and one["auth_type"] == "basic"
        login = operations[f"POST {base}/login"]
        assert login["request_body_mode"] == "urlencoded"
        assert login["form"] == ["username", "password"]
        assert login["auth_required"] is False  # its folder says "noauth"
        assert operations[f"GET {base}/health"]["auth_required"] is False
        (spec,) = _specs(records)
        assert (spec.asset, spec.value) == ("api.example.test", f"contract:{POSTMAN}")
        assert spec.attrs["format"] == "postman" and spec.attrs["spec_version"] == "2.1.0"
        assert spec.attrs["operation_count"] == 5 and spec.attrs["title"] == "Accounts API"

    @pytest.mark.parametrize("name", [OPENAPI, SWAGGER, POSTMAN])
    def test_every_record_says_the_operator_supplied_it(self, control: Path, name: str) -> None:
        records, _drops = _load(control, _entry(name))
        assert records
        for record in records:
            assert record.source_tool == "contracts"
            assert record.attrs["source"] == "operator" and record.attrs["contract"] == name
            assert record.asset.endswith(".example.test")
        for attrs in _operations(records).values():
            assert attrs["spec_url"] == f"contract:{name}"

    @pytest.mark.parametrize(
        ("name", "declared", "ok"),
        [
            (OPENAPI, "openapi", True),
            (SWAGGER, "openapi", True),
            (POSTMAN, "postman", True),
            (POSTMAN, "openapi", False),
            (OPENAPI, "postman", False),
        ],
    )
    def test_a_declared_format_must_match_the_file(
        self, control: Path, name: str, declared: str, ok: bool
    ) -> None:
        if ok:
            assert _load(control, _entry(name, fmt=declared))[0]
        else:
            with pytest.raises(contracts.ContractError, match=f"not a {declared} document"):
                _load(control, _entry(name, fmt=declared))

    @pytest.mark.parametrize(
        "content",
        [
            b"",
            b"just some text",
            b"[1, 2, 3]",
            b'{"openapi": "3.0.0"}',  # no paths
            b'{"info": {"name": "x"}, "item": []}',  # no Postman schema
            b"\xff\xfe\x00not text",
            b"a: [unclosed",
        ],
    )
    def test_a_file_that_is_not_a_contract_is_refused(self, control: Path, content: bytes) -> None:
        (control / "contracts" / "junk.json").write_bytes(content)
        with pytest.raises(contracts.ContractError):
            _load(control, _entry("junk.json"))

    def test_a_document_that_repeats_itself_without_end_is_refused(self, control: Path) -> None:
        bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\n" + "".join(
            f"{chr(98 + i)}: &{chr(98 + i)} [{', '.join(['*' + chr(97 + i)] * 10)}]\n"
            for i in range(9)
        )
        (control / "contracts" / "bomb.yaml").write_text(bomb + "openapi: 3.0.0\npaths: {}\n")
        with pytest.raises(contracts.ContractError, match="too large"):
            _load(control, _entry("bomb.yaml"))


# ── scope: what a contract names is untrusted ────────────────────────────


class TestScope:
    def test_an_out_of_scope_server_is_dropped_and_logged(self, control: Path) -> None:
        records, drops = _load(control, _entry(OPENAPI))
        assert ("apispec", "contracts", "input", "https://staging.example.net/v1", "NOT_IN_SCOPE") in drops  # fmt: skip
        assert "staging.example.net" not in _blob(records)
        assert {r.asset for r in records} == {"api.example.test"}

    def test_control_the_same_server_is_kept_when_the_scope_names_it(self, control: Path) -> None:
        records, drops = _load(control, _entry(OPENAPI), [*IN_SCOPE, "staging.example.net"])
        operations = _operations(records)
        assert "GET https://staging.example.net/v1/orders" in operations
        assert len(operations) == 10  # five per in-scope server
        assert {s.asset for s in _specs(records)} == {"api.example.test", "staging.example.net"}
        assert not [row for row in drops if row[4] == "NOT_IN_SCOPE"]

    def test_an_out_of_scope_postman_request_is_dropped_and_logged(self, control: Path) -> None:
        records, drops = _load(control, _entry(POSTMAN))
        assert ("apispec", "contracts", "input", "https://partner.example.net/export", "NOT_IN_SCOPE") in drops  # fmt: skip
        assert "partner.example.net" not in _blob(records)
        # Control: with that host in scope the same request is an operation.
        wider, _ = _load(control, _entry(POSTMAN), [*IN_SCOPE, "partner.example.net"])
        export = _operations(wider)["GET https://partner.example.net/export"]
        assert _parameters(export) == {("query", "since")}

    def test_an_excluded_host_is_dropped_even_under_an_in_scope_wildcard(
        self, control: Path
    ) -> None:
        drops: list[tuple[str, ...]] = []
        scope = ScopeFilter.from_document(
            {
                "machine_enforcement": {
                    "mode": "enforce",
                    "in_scope": IN_SCOPE,
                    "out_of_scope": ["legacy.example.test"],
                }
            },
            log_drop=lambda *row: drops.append(row),
        )
        assert contracts.load(control, _entry(SWAGGER), scope) == []
        assert drops == [
            ("apispec", "contracts", "input", "https://legacy.example.test/api", "OUT_OF_SCOPE")
        ]

    def test_a_path_cannot_move_an_operation_to_another_host(self, control: Path) -> None:
        document = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.test"}],
            "paths": {"@evil.example/steal": {"get": {}}, "/ok": {"get": {}}},
        }
        (control / "contracts" / "hostile.json").write_text(json.dumps(document))
        records, drops = _load(control, _entry("hostile.json"))
        assert set(_operations(records)) == {"GET https://api.example.test/ok"}
        assert "evil.example" not in _blob(records)
        assert [row[4] for row in drops if "evil.example" in row[3]] == ["NOT_IN_SCOPE"]

    def test_base_url_replaces_the_servers_a_document_names(self, control: Path) -> None:
        entry = _entry(OPENAPI, base_url="https://shop.example.test/api/")
        records, drops = _load(control, entry)
        assert "GET https://shop.example.test/api/orders" in _operations(records)
        assert {r.asset for r in records} == {"shop.example.test"}
        assert drops == []  # the document's own servers were never candidates
        # The override is filtered like any other server.
        away, drops = _load(control, _entry(OPENAPI, base_url="https://shop.example.net/api"))
        assert away == []
        assert [row[3:] for row in drops] == [("https://shop.example.net/api", "NOT_IN_SCOPE")]

    def test_a_document_without_an_absolute_server_needs_base_url(self, control: Path) -> None:
        document = {"openapi": "3.0.0", "servers": [{"url": "/v1"}], "paths": {"/a": {"get": {}}}}
        (control / "contracts" / "relative.json").write_text(json.dumps(document))
        with pytest.raises(contracts.ContractError, match="set base_url"):
            _load(control, _entry("relative.json"))
        records, _ = _load(control, _entry("relative.json", base_url="https://api.example.test"))
        assert set(_operations(records)) == {"GET https://api.example.test/a"}


# ── Postman variables ────────────────────────────────────────────────────


class TestPostmanVariables:
    def test_collection_variables_resolve_also_through_each_other(self, control: Path) -> None:
        # {{baseUrl}} is "https://{{apiHost}}" in the fixture; {{apiVersion}} is "v2".
        records, _drops = _load(control, _entry(POSTMAN))
        assert "GET https://api.example.test/v2/users" in _operations(records)
        assert "{{" not in _blob(records)

    def test_an_unresolved_variable_leaves_the_operation_out_with_a_reason(
        self, control: Path
    ) -> None:
        records, drops = _load(control, _entry(POSTMAN))
        assert not [value for value in _operations(records) if "report" in value]
        assert (
            "apispec",
            "contracts",
            "input",
            "GET https://{{tenant}}.example.test/report",
            "UNRESOLVED_VARIABLE",
        ) in drops

    def test_control_the_operation_appears_once_the_variable_is_defined(
        self, control: Path
    ) -> None:
        path = control / "contracts" / POSTMAN
        collection = json.loads(path.read_text())
        collection["variable"].append({"key": "tenant", "value": "blue"})
        path.write_text(json.dumps(collection))
        records, drops = _load(control, _entry(POSTMAN))
        report = _operations(records)["GET https://blue.example.test/report"]
        assert _parameters(report) == {("query", "key")}
        assert not [row for row in drops if row[4] == "UNRESOLVED_VARIABLE"]

    def test_a_credential_variable_is_never_put_into_a_url(self, control: Path) -> None:
        # "{{baseUrl}}/hooks/{{token}}/ping": the collection defines {{token}}.
        records, drops = _load(control, _entry(POSTMAN))
        assert not [value for value in _operations(records) if "hooks" in value]
        assert (
            "apispec",
            "contracts",
            "input",
            "POST https://api.example.test/hooks/{{token}}/ping",
            "SECRET_VARIABLE",
        ) in drops
        # Control: the same request with a variable that is not a credential resolves.
        path = control / "contracts" / POSTMAN
        path.write_text(path.read_text().replace("/hooks/{{token}}/", "/hooks/{{apiVersion}}/"))
        again, _ = _load(control, _entry(POSTMAN))
        assert "POST https://api.example.test/hooks/v2/ping" in _operations(again)

    def test_base_url_stands_in_for_a_variable_the_collection_does_not_define(
        self, control: Path
    ) -> None:
        collection = {
            "info": {
                "name": "env",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [
                {"name": "a", "request": {"method": "PUT", "url": "{{host}}/items/:id"}},
                {"name": "b", "request": {"url": "http://localhost:3000/local?x=1"}},
            ],
        }
        (control / "contracts" / "env.json").write_text(json.dumps(collection))
        nothing, drops = _load(control, _entry("env.json"))
        assert _operations(nothing) == {}
        assert sorted(row[4] for row in drops) == ["NOT_IN_SCOPE", "UNRESOLVED_VARIABLE"]
        records, _ = _load(control, _entry("env.json", base_url="https://api.example.test/v3"))
        assert set(_operations(records)) == {
            "PUT https://api.example.test/v3/items/{id}",  # the variable: the whole base
            "GET https://api.example.test/local",  # a literal host: scheme, host and port
        }


# ── credentials in a contract stay in the contract ───────────────────────


class TestNoCredentialLeavesTheContract:
    @pytest.mark.parametrize("name", [OPENAPI, SWAGGER, POSTMAN])
    def test_fixtures_hold_fake_credentials_and_no_record_does(
        self, control: Path, name: str
    ) -> None:
        text = (FIXTURES / name).read_text()
        assert text.count(CANARY) >= 5  # the fixture can fail this test
        records, drops = _load(control, _entry(name))
        assert len(records) >= 4
        assert CANARY not in _blob(records)
        assert CANARY not in json.dumps(drops)

    def test_postman_keeps_names_and_drops_every_value(self, control: Path) -> None:
        records, _drops = _load(control, _entry(POSTMAN))
        blob = _blob(records)
        # Names are kept: they are what the operation accepts.
        for name in ("X-Trace-Id", "Authorization", "api_key", "password", "username"):
            assert name in blob
        # Values, auth blocks, userinfo and example bodies are not.
        for value in ("Bearer ", "new.user@example.test", "admin", "user:", "application/json\\n"):
            assert value not in blob
        for attrs in _operations(records).values():
            assert not {"auth", "header", "headers", "body", "bearer", "basic"} & set(attrs)
            assert all(set(p) == {"name", "in", "required"} for p in attrs["parameters"])

    def test_a_server_url_with_userinfo_is_stored_without_it(self, control: Path) -> None:
        records, _drops = _load(control, _entry(OPENAPI))
        (spec,) = _specs(records)
        assert spec.attrs["base_url"] == "https://api.example.test/v1"
        assert "svc" not in _blob(records) and "@" not in _blob(records)


# ── the scope document ───────────────────────────────────────────────────


def _limits(entries: object) -> PipelineLimits:
    return ScopeFilter.from_document(
        {
            "machine_enforcement": {"mode": "enforce", "in_scope": IN_SCOPE},
            "pipeline": {"api_contracts": entries},
        }
    ).limits


class TestScopeDocument:
    def test_entries_are_parsed_with_their_defaults(self) -> None:
        limits = _limits(
            [
                {"path": "shop.yaml"},
                {"path": "v2/api.json", "base_url": "https://api.example.test/v2", "format": "OpenAPI"},
                {"path": "c.json", "format": "postman"},
            ]
        )  # fmt: skip
        assert limits.api_contracts == (
            {"path": "shop.yaml", "base_url": "", "format": "auto"},
            {"path": "v2/api.json", "base_url": "https://api.example.test/v2", "format": "openapi"},
            {"path": "c.json", "base_url": "", "format": "postman"},
        )
        assert _limits(None).api_contracts == () == PipelineLimits().api_contracts

    @pytest.mark.parametrize(
        "path",
        [
            "../roe.json",
            "../../other/contracts/a.yaml",
            "sub/../../roe.json",
            "..",
            "/etc/passwd",
            "/control/acme/contracts/a.yaml",
            "~/a.yaml",
            "\\\\host\\share\\a.yaml",
            "C:\\a.yaml",
            "a\x00.yaml",
            "",
            "   ",
            7,
            None,
        ],
    )
    def test_path_traversal_and_absolute_paths_are_rejected_at_scope_load(self, path) -> None:
        limits = _limits([{"path": path}, {"path": "kept.yaml"}])
        # Control: the well-formed entry next to it is still there.
        assert limits.api_contracts == ({"path": "kept.yaml", "base_url": "", "format": "auto"},)

    def test_a_rejected_path_is_reported(self) -> None:
        seen: list[str] = []

        class Collect(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                seen.append(record.getMessage())

        logger, handler = logging.getLogger("buggy.pipeline.scope"), Collect(logging.WARNING)
        logger.addHandler(handler)
        try:
            _limits([{"path": "../roe.json"}, {"path": "fine.yaml"}])
        finally:
            logger.removeHandler(handler)
        assert len(seen) == 1  # the well-formed entry is not reported
        assert "api_contracts[0] rejected" in seen[0] and "../roe.json" in seen[0]

    @pytest.mark.parametrize(
        "base_url", ["ftp://api.example.test", "api.example.test", "https://", 5, ["https://a"]]
    )
    def test_a_base_url_that_is_not_http_rejects_the_entry(self, base_url) -> None:
        assert _limits([{"path": "a.yaml", "base_url": base_url}]).api_contracts == ()

    def test_at_most_ten_contracts_and_no_duplicates(self) -> None:
        many = [{"path": f"c{n}.yaml"} for n in range(14)]
        assert [e["path"] for e in _limits(many).api_contracts] == [f"c{n}.yaml" for n in range(10)]
        assert len(_limits([{"path": "a.yaml"}, {"path": "a.yaml"}]).api_contracts) == 1
        for junk in ("shop.yaml", {"path": "shop.yaml"}, 3):
            assert _limits(junk).api_contracts == ()

    def test_the_loader_refuses_a_path_outside_contracts_on_its_own(self, control: Path) -> None:
        (control / "roe.json").write_text(json.dumps({"openapi": "3.0.0", "paths": {}}))
        scope, _drops = _scope()
        for path in ("../roe.json", str(control / "roe.json"), ""):
            with pytest.raises(contracts.ContractError, match="relative path under contracts"):
                contracts.load(control, _entry(path), scope)
        # A link inside contracts/ that points out of it is followed, then refused.
        (control / "contracts" / "link.json").symlink_to(control / "roe.json")
        with pytest.raises(contracts.ContractError, match="outside the contracts directory"):
            contracts.load(control, _entry("link.json"), scope)
        with pytest.raises(contracts.ContractError, match="no such file"):
            contracts.load(control, _entry("absent.yaml"), scope)
        # Control: a file in a sub-directory of contracts/ loads.
        (control / "contracts" / "v2").mkdir()
        shutil.copy(FIXTURES / SWAGGER, control / "contracts" / "v2" / "api.json")
        assert contracts.load(control, _entry("v2/api.json"), scope)


# ── the parser shared with the discovery stage ───────────────────────────


class TestSharedParser:
    SPEC = {
        "openapi": "3.0.0",
        "info": {"title": "T", "version": "1"},
        "paths": {
            "/pets": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}
                        }
                    }
                },
                "get": {},
            }
        },
        "components": {
            "schemas": {
                "Pet": {
                    "allOf": [
                        {"properties": {"name": {"type": "string", "example": "rex"}}},
                        {"properties": {"owner": {"properties": {"id": {"type": "integer"}}}}},
                    ]
                }
            }
        },
    }

    def test_a_discovered_spec_gets_body_property_names_too(self) -> None:
        records = list(apispec.parse_openapi(self.SPEC, spec_url="https://a.test/openapi.json"))
        operations = {r.value: r.attrs for r in records[1:]}
        assert operations["POST https://a.test/pets"]["request_body_properties"] == [
            "name",
            "owner.id",
        ]
        assert operations["GET https://a.test/pets"]["request_body_properties"] == []
        assert "rex" not in json.dumps(operations)  # names only, never an example

    def test_discovery_and_contract_describe_an_operation_the_same_way(self, control: Path) -> None:
        (control / "contracts" / "pets.json").write_text(json.dumps(self.SPEC))
        entry = _entry("pets.json", base_url="https://a.example.test")
        supplied = _operations(_load(control, entry)[0])["POST https://a.example.test/pets"]
        url = "https://a.example.test/openapi.json"
        (found,) = (
            r for r in apispec.parse_openapi(self.SPEC, spec_url=url) if r.value.startswith("POST")
        )
        assert found.source_tool == "openapi" and "source" not in found.attrs
        added = {"source", "contract", "contract_sha256"}
        assert {k: v for k, v in supplied.items() if k not in added | {"spec_url"}} == {
            k: v for k, v in found.attrs.items() if k != "spec_url"
        }
        assert found.attrs["spec_url"] == url  # where the discovered one was fetched


# ── in the pipeline ──────────────────────────────────────────────────────

API = "https://api.acme.test/v1"
SHOP = {"path": OPENAPI, "base_url": API}
ORDER_BODY = {
    f"POST {API}/orders body:{name}"
    for name in (
        "customer_id",
        "coupon",
        "shipping.address",
        "shipping.callback_url",
        "items[].product_id",
        "items[].quantity",
        "category.name",
        "category.parent",
    )
}


@pytest.fixture
def env(tmp_path: Path, control: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {
        "store": store,
        "root": tmp_path / "data",
        "tools": FakeTools(),
        "opener": FakeOpener(),
        "control": control,
    }
    store.close()


def _roe(*entries: dict, **pipeline) -> dict:
    roe = json.loads(json.dumps(ROE))
    roe["pipeline"].update(pipeline)
    if entries:
        roe["pipeline"]["api_contracts"] = list(entries)
    return roe


def _pipeline(env, roe: dict, **kwargs) -> Pipeline:
    crt = json.dumps([{"name_value": "www.acme.test\ncrt-only.acme.test\n*.acme.test"}]).encode()
    pipeline = Pipeline(
        env["store"],
        ScopeFilter.from_document(roe),
        "acme",
        data_root=env["root"],
        executor=env["tools"].execute,
        resolver=env["tools"].resolve,
        http_opener=env["opener"],
        passive_fetch=lambda _url: crt,
        sleep=lambda _s: None,
        **kwargs,
    )
    pipeline.control_dir = env["control"]
    return pipeline


def _values(env, record_type: str) -> set[str]:
    return {
        r.value for r in env["store"].query_records("acme", record_type=record_type, limit=1000)
    }


def _stats(summary: dict) -> dict:
    return summary["stages"]["apispec"]["tools"]["contracts"]


class TestInThePipeline:
    def test_a_run_stores_the_contract_and_the_parameters_it_declares(self, env) -> None:
        summary = _pipeline(env, _roe(SHOP)).run()
        assert summary["status"] == "completed"
        operations = _values(env, "api_operation")
        assert operations == {
            "GET https://www.acme.test/v1/users",  # discovered, as before
            f"GET {API}/orders",
            f"POST {API}/orders",
            f"GET {API}/orders/{{orderId}}",
            f"DELETE {API}/orders/{{orderId}}",
            f"GET {API}/health",
        }
        assert _values(env, "api_spec") == {
            "https://www.acme.test/openapi.json",
            f"contract:{OPENAPI}",
        }
        assert _stats(summary) == {"contracts": 1, "loaded": 1, "cached": 0, "records": 6}
        (create,) = env["store"].query_records(
            "acme", record_type="api_operation", contains="POST "
        )
        assert create.asset == "api.acme.test" and create.sources == ("contracts",)
        assert create.attrs["source"] == "operator" and create.attrs["auth_required"] is True
        # The record points at a raw line that is the record, not the file.
        ref, _, line = create.raw_ref.partition("#L")
        assert ref == f"raw/acme/{summary['run_id']}/apispec-contracts.jsonl"
        raw = (env["root"] / ref).read_text().splitlines()
        assert json.loads(raw[int(line) - 1])["value"] == create.value
        # The stage's parameter extraction reads the contract's operations.
        parameters = _values(env, "parameter")
        assert ORDER_BODY <= parameters
        assert {
            f"GET {API}/orders query:status",
            f"GET {API}/orders header:X-Request-Id",
            f"GET {API}/orders/{{orderId}} path:orderId",
            f"DELETE {API}/orders/{{orderId}} path:orderId",
        } <= parameters
        (body,) = env["store"].query_records(
            "acme", record_type="parameter", contains="body:coupon"
        )
        assert body.attrs["location"] == "body" and body.attrs["sources"] == ["contracts"]
        assert body.attrs["example"] == ""  # the schema's example is not carried

    def test_a_contract_adds_no_tool_call_and_no_request(self, env, tmp_path: Path) -> None:
        # Hidden-parameter guessing sends random values: off here, so the runs compare.
        off = {"disabled_stages": ["paramguess"]}
        postman = _entry(POSTMAN, base_url="https://www.acme.test")
        _pipeline(env, _roe(SHOP, postman, **off)).run()
        assert len(_values(env, "api_operation")) > 6
        plain_store = ReconStore(tmp_path / "plain" / "recon.sqlite3")
        plain = {**env, "store": plain_store, "root": tmp_path / "plain"}
        plain["tools"], plain["opener"] = FakeTools(), FakeOpener()
        try:
            summary = _pipeline(plain, _roe(**off)).run()
        finally:
            plain_store.close()
        assert "contracts" not in summary["stages"]["apispec"]["tools"]
        # Loading the contract sends nothing. The only extra requests are the API
        # recon stage's one GET to each concrete endpoint the contract names.
        extra = [r for r in env["opener"].requested if r not in plain["opener"].requested]
        assert plain["opener"].requested != []
        assert [r for r in env["opener"].requested if r not in extra] == plain["opener"].requested
        operations = {
            url.split("?", 1)[0]
            for value in _values(env, "api_operation")
            for method, _, url in [value.partition(" ")]
            if method == "GET"
        }
        assert extra and all(m == "GET" and url in operations for m, url in extra)
        assert summary["stages"]["api"]["tools"]["api_profile"]["requests"] < len(
            env["opener"].requested
        )
        # Same tools, same order, same inputs (gitleaks is given a per-run directory).
        with_contracts = [(n, i) for n, i, _argv in env["tools"].calls if n != "gitleaks"]
        # Tools that run at the same time may finish in either order.
        assert sorted(with_contracts) == sorted(
            (n, i) for n, i, _argv in plain["tools"].calls if n != "gitleaks"
        )
        assert sorted(c[0] for c in env["tools"].calls) == sorted(
            c[0] for c in plain["tools"].calls
        )
        assert len(with_contracts) == 9

    def test_nothing_out_of_scope_in_a_contract_is_stored_or_requested(self, env) -> None:
        # No base_url: the fixtures name example.test and example.net hosts,
        # none of which this engagement (acme.test) has in scope.
        summary = _pipeline(env, _roe(_entry(OPENAPI), _entry(SWAGGER), _entry(POSTMAN))).run()
        assert _stats(summary)["loaded"] == 3 and _stats(summary)["records"] == 0
        assert _values(env, "api_operation") == {"GET https://www.acme.test/v1/users"}
        records = env["store"].query_records("acme", status=None, limit=1000)
        assert not [r for r in records if "example." in json.dumps(r.to_dict())]
        drops = {
            (d["stage"], d["tool"], d["direction"], d["candidate"], d["reason"])
            for d in env["store"].scope_drops("acme", run_id=summary["run_id"])
        }
        for candidate in (
            "https://api.example.test/v1",
            "https://staging.example.net/v1",
            "https://legacy.example.test/api",
            "https://api.example.test/v2/users",
            "https://partner.example.net/export",
        ):
            assert ("apispec", "contracts", "input", candidate, "NOT_IN_SCOPE") in drops
        for _method, url in env["opener"].requested:
            assert "example." not in url

    def test_no_fixture_credential_reaches_the_store_or_the_raw_output(self, env) -> None:
        roe = _roe(
            SHOP,
            _entry(SWAGGER, base_url="https://api.acme.test/legacy"),
            _entry(POSTMAN, base_url="https://www.acme.test"),
        )
        summary = _pipeline(env, roe).run()
        assert _stats(summary)["loaded"] == 3 and _stats(summary)["records"] > 15
        store = env["store"]
        records = store.query_records("acme", status=None, limit=1000)
        assert any(r.source_tool == "contracts" for r in records)
        assert CANARY not in json.dumps([r.to_dict() for r in records])
        assert CANARY not in json.dumps(store.scope_drops("acme", run_id=summary["run_id"]))
        assert CANARY not in json.dumps(summary)
        raw_files = [p for p in (env["root"] / "raw").rglob("*") if p.is_file()]
        assert any(p.name == "apispec-contracts.jsonl" for p in raw_files)
        for path in raw_files:
            assert CANARY not in path.read_text(errors="replace"), path.name
        # The parameter records the stage derives from them carry no value either.
        names = _values(env, "parameter")
        assert "POST https://www.acme.test/v2/users body:password" in names
        assert "POST https://www.acme.test/login form:password" in names

    def test_an_unchanged_contract_is_cached_on_the_second_run(self, env, monkeypatch) -> None:
        first = _pipeline(env, _roe(SHOP)).run()
        before = {
            r.value: r.last_run_id
            for r in env["store"].query_records("acme", limit=1000)
            if r.source_tool == "contracts"
        }
        assert len(before) == 6 and set(before.values()) == {first["run_id"]}

        def parse_again(*_args):
            raise AssertionError("an unchanged contract was parsed again")

        monkeypatch.setattr(contracts, "parse", parse_again)
        env["opener"].requested.clear()
        second = _pipeline(env, _roe(SHOP)).run()
        assert _stats(second) == {"contracts": 1, "loaded": 0, "cached": 1, "records": 0}
        assert second["diff"] == {"added": 0, "changed": 0, "removed": 0}
        assert all(stage["processed"] == 0 for stage in second["stages"].values())
        assert env["opener"].requested == []
        after = {
            r.value: r.last_run_id
            for r in env["store"].query_records("acme", limit=1000)
            if r.source_tool == "contracts"
        }
        assert after == before

    def test_control_a_changed_contract_is_read_again(self, env) -> None:
        _pipeline(env, _roe(SHOP)).run()
        path = env["control"] / "contracts" / OPENAPI
        path.write_text(
            path.read_text()
            .replace("  /health:\n", "  /status:\n")
            .replace("operationId: health", "operationId: status")
        )
        summary = _pipeline(env, _roe(SHOP)).run()
        assert _stats(summary) == {"contracts": 1, "loaded": 1, "cached": 0, "records": 6}
        changes = {
            (c["change"], c["type"], c["value"])
            for c in env["store"].diff("acme", summary["run_id"])
        }
        assert ("added", "api_operation", f"GET {API}/status") in changes
        assert ("removed", "api_operation", f"GET {API}/health") in changes
        assert f"GET {API}/health" not in _values(env, "api_operation")
        # Only the contract was read again: no origin was probed for it.
        assert summary["stages"]["apispec"]["processed"] == 0

    def test_a_contract_the_scope_no_longer_names_is_retired(self, env) -> None:
        _pipeline(env, _roe(SHOP)).run()
        assert f"contract:{OPENAPI}" in _values(env, "api_spec")
        summary = _pipeline(env, _roe()).run()
        assert _values(env, "api_operation") == {"GET https://www.acme.test/v1/users"}
        assert _values(env, "api_spec") == {"https://www.acme.test/openapi.json"}
        # The six operations, and what API recon had derived from them.
        assert summary["diff"]["added"] == 0
        assert summary["diff"]["removed"] == 6 + summary["stages"]["api"]["retired"]
        assert _stats(summary) == {"contracts": 0, "loaded": 0, "cached": 0, "records": 0}
        # And nothing is left to do on the run after that.
        again = _pipeline(env, _roe()).run()
        assert "contracts" not in again["stages"]["apispec"]["tools"]

    def test_a_contract_that_cannot_be_read_is_reported_and_the_run_continues(self, env) -> None:
        (env["control"] / "contracts" / "broken.json").write_text('{"openapi": "3.0.0"}')
        roe = _roe(_entry("absent.yaml"), _entry("broken.json"), SHOP)
        summary = _pipeline(env, roe).run()
        assert summary["status"] == "completed"
        stats = _stats(summary)
        assert stats["contracts"] == 3 and stats["loaded"] == 1 and stats["records"] == 6
        assert stats["errors"] == [
            "absent.yaml: no such file under contracts/",
            "broken.json: not an OpenAPI / Swagger document or a Postman v2 collection",
        ]
        assert f"GET {API}/orders" in _values(env, "api_operation")

    def test_a_traversal_path_in_the_scope_document_reads_nothing(self, env) -> None:
        # A well-formed contract one level above contracts/, where roe.json lives.
        shutil.copy(FIXTURES / OPENAPI, env["control"] / "outside.yaml")
        roe = _roe({"path": "../outside.yaml", "base_url": API})
        summary = _pipeline(env, roe).run()
        assert "contracts" not in summary["stages"]["apispec"]["tools"]
        assert _values(env, "api_operation") == {"GET https://www.acme.test/v1/users"}
        # Control: the same file inside contracts/ is read.
        shutil.copy(FIXTURES / OPENAPI, env["control"] / "contracts" / "inside.yaml")
        summary = _pipeline(env, _roe({"path": "inside.yaml", "base_url": API})).run()
        assert _stats(summary)["loaded"] == 1 and f"GET {API}/orders" in _values(
            env, "api_operation"
        )

    def test_passive_only_still_reads_a_contract_and_sends_nothing(self, env) -> None:
        summary = _pipeline(env, _roe(SHOP, passive_only=True)).run()
        assert env["opener"].requested == []
        assert summary["stages"]["apispec"]["skipped"] == "passive_only"
        assert _stats(summary) == {"contracts": 1, "loaded": 1, "cached": 0, "records": 6}
        assert f"POST {API}/orders" in _values(env, "api_operation")

    def test_the_control_root_comes_from_the_environment(self, env, monkeypatch) -> None:
        pipeline = _pipeline(env, _roe(SHOP))
        pipeline.control_dir = None
        monkeypatch.delenv("BUGGY_ENGAGEMENT_CONTROL", raising=False)
        monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(env["control"].parent))
        assert _stats(pipeline.run())["loaded"] == 1
        # Control: pointed at a root without the file, the contract is not found.
        monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(env["root"]))
        other = _pipeline(env, _roe(SHOP), force=True)
        other.control_dir = None
        assert _stats(other.run())["errors"] == [f"{OPENAPI}: no such file under contracts/"]


class TestContractAndPublishedSpec:
    """An operation both a contract and the target's own spec declare is one record."""

    BOTH = "GET https://www.acme.test/v1/users"  # FakeOpener publishes it

    def _contract(self, env) -> dict:
        document = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://www.acme.test"}],
            "paths": {"/v1/users": {"get": {}}, "/v1/audit": {"get": {}}},
        }
        (env["control"] / "contracts" / "www.json").write_text(json.dumps(document))
        return _entry("www.json")

    def _republish(self, env) -> None:
        """The target's spec stops declaring the operation; the origin is due again."""
        env["opener"].SPEC = {**FakeOpener.SPEC, "paths": {"/v1/ping": {"get": {}}}}
        with env["store"]._tx() as cur:  # noqa: SLF001 - test-only cache expiry
            cur.execute("DELETE FROM stage_cache WHERE stage = 'apispec'")

    def test_both_sources_are_recorded_on_the_one_record(self, env) -> None:
        _pipeline(env, _roe(self._contract(env))).run()
        (record,) = env["store"].query_records(
            "acme", record_type="api_operation", contains="users"
        )
        assert record.value == self.BOTH and record.sources == ("contracts", "openapi")
        assert len(_values(env, "api_operation")) == 2

    def test_it_stays_while_the_contract_still_declares_it(self, env) -> None:
        _pipeline(env, _roe(self._contract(env))).run()
        self._republish(env)
        _pipeline(env, _roe(self._contract(env))).run()
        assert _values(env, "api_operation") == {
            self.BOTH,
            "GET https://www.acme.test/v1/audit",
            "GET https://www.acme.test/v1/ping",
        }

    def test_control_without_the_contract_it_is_retired(self, env) -> None:
        _pipeline(env, _roe()).run()
        assert self.BOTH in _values(env, "api_operation")
        self._republish(env)
        _pipeline(env, _roe()).run()
        assert _values(env, "api_operation") == {"GET https://www.acme.test/v1/ping"}


class TestServicePassesItsControlTree:
    """`run_engagement(control=...)` reads contracts from that tree, not from the environment."""

    def test_the_pipeline_is_given_the_control_directory_of_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from buggy.pipeline import service

        control = tmp_path / "control"
        (control / "acme").mkdir(parents=True)
        (control / "acme" / "roe.json").write_text(
            json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}})
        )
        monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(tmp_path / "elsewhere"))
        seen: dict[str, object] = {}

        def fake_run(self, trigger="manual"):
            seen["control_dir"] = self.control_dir
            return {}

        monkeypatch.setattr(service.Pipeline, "run", fake_run)
        service.run_engagement("acme", root=tmp_path / "data", control=control)
        assert seen["control_dir"] == control / "acme"

        # Control: without an explicit tree the pipeline falls back to the environment.
        (tmp_path / "elsewhere" / "acme").mkdir(parents=True)
        (tmp_path / "elsewhere" / "acme" / "roe.json").write_text(
            (control / "acme" / "roe.json").read_text()
        )
        service.run_engagement("acme", root=tmp_path / "data")
        assert seen["control_dir"] is None
