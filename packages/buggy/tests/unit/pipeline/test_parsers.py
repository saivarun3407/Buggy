"""Each tool's parser against real output of the pinned version (see fixtures/README.md)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from buggy.pipeline.schema import RecordType
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools import apispec, crtsh, jsparse
from buggy.pipeline.tools.amass import Amass
from buggy.pipeline.tools.archives import Gau, Waybackurls
from buggy.pipeline.tools.dnsx import Dnsx
from buggy.pipeline.tools.gitleaks import Gitleaks
from buggy.pipeline.tools.httpx import Httpx
from buggy.pipeline.tools.katana import Katana
from buggy.pipeline.tools.naabu import Naabu
from buggy.pipeline.tools.nuclei import EXCLUDED_TAGS, Nuclei
from buggy.pipeline.tools.subfinder import Subfinder

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _types(records) -> Counter:
    return Counter(r.type for r in records)


class TestSubfinder:
    def test_real_output(self) -> None:
        records = list(Subfinder().parse(_read("subfinder.jsonl")))
        assert len(records) == 62 and _types(records) == {RecordType.SUBDOMAIN: 62}
        first = records[0]
        assert first.asset == first.value == "ekaterinayna2.example.com"
        assert first.attrs == {"root": "example.com", "sources": ["anubis"]}
        assert first.raw_line == 1
        assert all(r.asset.endswith(".example.com") for r in records)

    def test_survives_banners_and_garbage(self) -> None:
        raw = '[INF] Enumerating subdomains\n{"host":"A.Example.com.","input":"example.com","source":"x"}\n{bad\n'
        records = list(Subfinder().parse(raw))
        assert [(r.asset, r.attrs["sources"], r.raw_line) for r in records] == [
            ("a.example.com", ["x"], 2)
        ]


class TestAmass:
    def test_real_output_keeps_names_not_addresses(self) -> None:
        records = list(Amass().parse(_read("amass.txt")))
        assert [r.asset for r in records] == ["example.com"]  # IPs, netblocks, ASNs are ignored
        assert records[0].raw_line == 1

    def test_relationship_lines(self) -> None:
        raw = (
            "www.acme.test (FQDN) --> cname_record --> edge.acme.test (FQDN)\n"
            "edge.acme.test (FQDN) --> a_record --> 192.0.2.5 (IPAddress)\n"
        )
        assert [r.asset for r in Amass().parse(raw)] == ["www.acme.test", "edge.acme.test"]


class TestCrtSh:
    def test_real_output_splits_sans_and_skips_wildcards(self) -> None:
        records = list(crtsh.parse(_read("crtsh.json"), root="example.com"))
        names = {r.asset for r in records}
        assert "emudhra-lab.example.com" in names
        assert not any("*" in name for name in names)
        assert len(names) == len(records)  # de-duplicated across certificates
        assert crtsh.query_url("acme.test") == "https://crt.sh/?q=%25.acme.test&output=json"

    @pytest.mark.parametrize("raw", ["", "<html>busy</html>", "{}", "[1, 2]"])
    def test_non_results_yield_nothing(self, raw: str) -> None:
        assert list(crtsh.parse(raw)) == []


class TestDnsx:
    def test_real_output_all_record_types(self) -> None:
        records = list(Dnsx().parse(_read("dnsx.jsonl")))
        by_host: dict[str, set[str]] = {}
        for record in records:
            assert record.type == RecordType.DNS_RECORD
            by_host.setdefault(record.asset, set()).add(record.value)
        assert by_host["www.lab.test"] == {
            "A 192.0.2.10",
            "AAAA 2001:db8::10",
            "CNAME app.lab.test",
        }
        assert by_host["lab.test"] == {"MX mail.lab.test", "TXT v=spf1 -all"}
        assert by_host["api.lab.test"] == {"A 192.0.2.11"}
        sample = next(r for r in records if r.value == "CNAME app.lab.test")
        assert sample.attrs == {"rtype": "CNAME", "data": "app.lab.test", "rcode": "NOERROR"}

    def test_argv_asks_for_every_record_type(self, tmp_path: Path) -> None:
        argv = (
            Dnsx(resolvers=("127.0.0.1:5353",))
            .invocation(
                "dnsx", ["a.test"], PipelineLimits(rate_limit_rps=7, concurrency=3), tmp_path
            )
            .argv
        )
        for flag in ("-a", "-aaaa", "-cname", "-mx", "-txt", "-ns", "-json"):
            assert flag in argv
        assert argv[argv.index("-r") + 1] == "127.0.0.1:5353"
        assert (tmp_path / "dnsx-hosts.txt").read_text() == "a.test\n"


class TestNaabu:
    def test_real_output_with_and_without_host_key(self) -> None:
        records = list(Naabu().parse(_read("naabu.jsonl")))
        assert {(r.asset, r.value) for r in records} == {
            ("127.0.0.1", "8443/tcp"),
            ("localhost", "8443/tcp"),
            ("127.0.0.1", "3000/tcp"),
            ("localhost", "3000/tcp"),
        }
        assert records[0].attrs == {"port": 8443, "protocol": "tcp", "ip": "127.0.0.1"}

    def test_rate_and_ports_come_from_program_limits(self, tmp_path: Path) -> None:
        argv = (
            Naabu()
            .invocation(
                "naabu",
                ["a.test"],
                PipelineLimits(rate_limit_rps=4, concurrency=2, ports="80,443"),
                tmp_path,
            )
            .argv
        )
        assert argv[argv.index("-rate") + 1] == "4" and argv[argv.index("-c") + 1] == "2"
        assert argv[argv.index("-p") + 1] == "80,443"
        assert argv[argv.index("-scan-type") + 1] == "c"
        top = Naabu().invocation("naabu", ["a.test"], PipelineLimits(), tmp_path).argv
        assert top[top.index("-top-ports") + 1] == "100"


class TestHttpx:
    def test_real_output_service_tech_tls_headers(self) -> None:
        records = list(Httpx().parse(_read("httpx.jsonl")))
        assert _types(records) == {
            RecordType.HTTP_SERVICE: 2,
            RecordType.TECHNOLOGY: 7,
            RecordType.TLS: 1,
            RecordType.HEADER: 4,
        }
        juice = next(r for r in records if r.value == "http://127.0.0.1:3000/")
        assert juice.type == RecordType.HTTP_SERVICE and juice.asset == "127.0.0.1"
        assert juice.attrs["title"] == "OWASP Juice Shop" and juice.attrs["status_code"] == 200
        assert juice.attrs["port"] == 3000 and juice.attrs["scheme"] == "http"

        tech = {
            r.attrs["name"]: r.attrs["version"] for r in records if r.type == RecordType.TECHNOLOGY
        }
        assert tech["jQuery"] == "2.2.4" and "Onsen UI" in tech

        tls = next(r for r in records if r.type == RecordType.TLS)
        assert tls.attrs["subject_cn"] == "app.lab.test" and tls.attrs["self_signed"] is True
        assert tls.attrs["subject_an"] == ["app.lab.test", "api.lab.test"]
        assert tls.attrs["tls_version"] == "tls13" and len(tls.attrs["sha256"]) == 64

        headers = {
            r.attrs["name"]: r.attrs["value"] for r in records if r.type == RecordType.HEADER
        }
        assert headers["x-frame-options"] == "SAMEORIGIN"
        assert headers["access-control-allow-origin"] == "*"

    def test_failed_probes_are_not_services(self) -> None:
        raw = '{"url":"http://127.0.0.1:9","input":"http://127.0.0.1:9","failed":true}\n'
        assert list(Httpx().parse(raw)) == []

    def test_never_follows_redirects(self, tmp_path: Path) -> None:
        argv = (
            Httpx().invocation("httpx", ["a.test"], PipelineLimits(rate_limit_rps=3), tmp_path).argv
        )
        assert "-fr" not in argv and "-follow-redirects" not in argv
        assert argv[argv.index("-rl") + 1] == "3"


class TestKatana:
    def test_real_output(self) -> None:
        records = list(Katana().parse(_read("katana.jsonl")))
        assert len(records) == 58
        assert _types(records) == {RecordType.URL: 54, RecordType.JS_FILE: 4}
        runtime = next(r for r in records if r.value == "http://127.0.0.1:3000/runtime.js")
        assert runtime.type == RecordType.JS_FILE
        assert runtime.attrs["found_in"] == "http://127.0.0.1:3000"
        assert runtime.attrs["status_code"] == 200 and runtime.attrs["tag"] == "script"
        assert {r.asset for r in records} == {"127.0.0.1"}

    def test_stays_on_host_and_respects_limits(self, tmp_path: Path) -> None:
        argv = (
            Katana()
            .invocation(
                "katana",
                ["http://a.test/"],
                PipelineLimits(rate_limit_rps=6, concurrency=2, crawl_depth=3),
                tmp_path,
            )
            .argv
        )
        assert argv[argv.index("-fs") + 1] == "fqdn"
        assert argv[argv.index("-rl") + 1] == "6" and argv[argv.index("-d") + 1] == "3"
        for forbidden in ("-headless", "-aff", "-automatic-form-fill", "-ns", "-no-scope"):
            assert forbidden not in argv


class TestArchives:
    def test_gau_real_output(self) -> None:
        records = list(Gau().parse(_read("gau.jsonl")))
        assert len(records) == 60
        assets = {r.asset for r in records}
        # Archive indexes return other hosts under the same suffix; the stage's
        # scope filter, not the parser, decides which of them are kept.
        assert "example.com" in assets and "api.example.com" in assets
        assert all(a == "example.com" or a.endswith(".example.com") for a in assets)
        assert all(r.attrs == {"archived": True} for r in records)
        assert any(r.type == RecordType.JS_FILE for r in records)

    def test_waybackurls_line_format(self) -> None:
        # Not a captured file (see fixtures/README.md): real archive URLs from the
        # gau capture, in waybackurls' one-URL-per-line output format.
        urls = [json.loads(line)["url"] for line in _read("gau.jsonl").splitlines()]
        raw = "\n".join(urls) + "\nnot a url\nftp://example.com/x\n\n"
        records = list(Waybackurls().parse(raw))
        assert len(records) == 60 and records[0].raw_line == 1
        assert Waybackurls().invocation(
            "waybackurls", ["a.test", "b.test"], PipelineLimits(), Path(".")
        ).stdin == ("a.test\nb.test\n")


class TestJsParse:
    def test_real_bundle_excerpt(self) -> None:
        records = list(
            jsparse.parse(_read("juice_main_excerpt.js"), js_url="http://127.0.0.1:3000/main.js")
        )
        values = {r.value for r in records}
        assert "http://127.0.0.1:3000/rest/user/login" in values
        assert "http://127.0.0.1:3000/api/Users" in values
        assert all(
            r.type == RecordType.ENDPOINT and r.attrs["found_in"].endswith("/main.js")
            for r in records
        )

    def test_literal_extraction_rules(self) -> None:
        script = """
            fetch("/api/v1/orders?limit=10"); x = '/a'; y = "/static/logo.png";
            import("./chunk.js"); z = "https://cdn.other.test/lib.js"; w = "application/json";
            re = /ab+c/gi; t = `/graphql`;
        """
        literals = jsparse.extract_literals(script)
        assert "/api/v1/orders?limit=10" in literals and "/graphql" in literals
        assert "./chunk.js" in literals and "https://cdn.other.test/lib.js" in literals
        assert "/static/logo.png" not in literals and "application/json" not in literals
        hosts = {r.asset for r in jsparse.parse(script, js_url="https://app.acme.test/js/main.js")}
        assert hosts == {
            "app.acme.test",
            "cdn.other.test",
        }  # the stage's scope filter drops the second


class TestApiSpec:
    def test_real_swagger_ui_embedded_document(self) -> None:
        spec = apispec.load_spec(_read("swagger-ui-init.js"))
        assert spec is not None and spec["openapi"].startswith("3.")
        url = "http://127.0.0.1:3000/api-docs/swagger-ui-init.js"
        records = list(apispec.parse_openapi(spec, spec_url=url))
        api = records[0]
        assert api.type == RecordType.API_SPEC and api.attrs["operation_count"] == 1
        assert api.attrs["security_schemes"] == ["bearerAuth"]
        operation = records[1]
        assert operation.type == RecordType.API_OPERATION
        assert operation.value == "POST http://127.0.0.1:3000/b2b/v2/orders"
        assert operation.attrs["auth_required"] is True
        assert operation.attrs["request_body_types"] == ["application/json"]

    def test_swagger2_and_parameters(self) -> None:
        spec = {
            "swagger": "2.0",
            "host": "api.acme.test",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/users/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "get": {"operationId": "getUser"},
                    "delete": {"security": [{"key": []}]},
                }
            },
        }
        records = list(apispec.parse_openapi(spec, spec_url="https://api.acme.test/swagger.json"))
        operations = {r.value: r.attrs for r in records if r.type == RecordType.API_OPERATION}
        assert set(operations) == {
            "GET https://api.acme.test/v1/users/%7Bid%7D",
            "DELETE https://api.acme.test/v1/users/%7Bid%7D",
        } or set(operations) == {
            "GET https://api.acme.test/v1/users/{id}",
            "DELETE https://api.acme.test/v1/users/{id}",
        }
        get = next(a for v, a in operations.items() if v.startswith("GET"))
        assert get["parameters"] == [{"name": "id", "in": "path", "required": True}]
        assert get["auth_required"] is False
        assert (
            next(a for v, a in operations.items() if v.startswith("DELETE"))["auth_required"]
            is True
        )

    @pytest.mark.parametrize(
        "text", ["<html>Swagger UI</html>", "{}", '{"openapi":"3.0.0"}', "not json"]
    )
    def test_non_specs_are_rejected(self, text: str) -> None:
        assert apispec.load_spec(text) is None

    def test_real_graphql_introspection(self) -> None:
        body = json.loads(_read("graphql_introspection.json"))
        (record,) = list(
            apispec.parse_introspection(body, endpoint="http://127.0.0.1:5013/graphql")
        )
        assert record.type == RecordType.GRAPHQL and record.attrs["introspection_enabled"] is True
        assert (
            record.attrs["query_type"] == "Query" and record.attrs["mutation_type"] == "Mutations"
        )
        queries = {q["name"]: q["args"] for q in record.attrs["queries"]}
        assert "pastes" in queries and "public" in queries["pastes"]
        assert any(m["name"] == "createPaste" for m in record.attrs["mutations"])

    def test_introspection_disabled(self) -> None:
        body = {"errors": [{"message": "introspection is disabled"}]}
        assert list(apispec.parse_introspection(body, endpoint="https://a.test/graphql")) == []


class TestNuclei:
    def test_real_output(self) -> None:
        records = list(Nuclei().parse(_read("nuclei.jsonl")))
        assert len(records) == 13 and _types(records) == {RecordType.VULNERABILITY: 13}
        by_id = {r.attrs["template_id"]: r for r in records}
        metrics = by_id["prometheus-metrics"]
        assert metrics.attrs["severity"] == "medium"
        assert metrics.attrs["matched_at"] == "http://127.0.0.1:3000/metrics"
        assert metrics.attrs["cwe"] == ["cwe-200"] and metrics.attrs["cvss_score"] == 5.3
        assert metrics.asset == "127.0.0.1"
        assert by_id["swagger-api"].attrs["severity"] == "info"

    def test_vetted_invocation(self, tmp_path: Path) -> None:
        limits = PipelineLimits(
            rate_limit_rps=9, concurrency=4, nuclei_severities=("high", "critical")
        )
        argv = (
            Nuclei(templates_dir="/opt/nuclei-templates")
            .invocation("nuclei", ["http://a.test/"], limits, tmp_path)
            .argv
        )
        templates = [argv[i + 1] for i, a in enumerate(argv) if a == "-t"]
        assert templates and all(t.startswith("/opt/nuclei-templates/") for t in templates)
        assert "-ni" in argv and "-dr" in argv  # no OAST, no redirects
        assert argv[argv.index("-etags") + 1] == ",".join(EXCLUDED_TAGS)
        assert {"dos", "intrusive", "fuzz", "brute-force"} <= set(EXCLUDED_TAGS)
        assert argv[argv.index("-severity") + 1] == "high,critical"
        assert argv[argv.index("-rl") + 1] == "9" and argv[argv.index("-c") + 1] == "4"
        for forbidden in ("-dast", "-headless", "-code", "-fr", "-ut", "-update-templates"):
            assert forbidden not in argv


class TestGitleaks:
    def test_real_output_is_redacted_and_mapped_to_source_url(self) -> None:
        raw = _read("gitleaks.json")
        records = list(Gitleaks().parse(raw, sources={"app.js": "http://127.0.0.1:3000/app.js"}))
        assert {r.attrs["rule_id"] for r in records} == {"stripe-access-token", "aws-access-token"}
        stripe = next(r for r in records if r.attrs["rule_id"] == "stripe-access-token")
        assert stripe.type == RecordType.SECRET and stripe.asset == "127.0.0.1"
        assert stripe.value == "stripe-access-token http://127.0.0.1:3000/app.js:5"
        assert stripe.attrs["redacted"] is True
        assert "AKIA" not in raw and "sk_live" not in raw  # --redact: the secret was never captured

    def test_always_redacts(self, tmp_path: Path) -> None:
        argv = (
            Gitleaks().invocation("gitleaks", ["dir", "/tmp/js"], PipelineLimits(), tmp_path).argv
        )
        assert "--redact" in argv and argv[1:3] == ["dir", "/tmp/js"]
        with pytest.raises(ValueError):
            Gitleaks().invocation("gitleaks", ["detect", "/x"], PipelineLimits(), tmp_path)

    def test_repo_findings_use_the_given_asset(self) -> None:
        raw = json.dumps(
            [
                {
                    "RuleID": "generic-api-key",
                    "File": "config.py",
                    "StartLine": 3,
                    "Commit": "abcdef1234567890",
                }
            ]
        )
        (record,) = list(Gitleaks().parse(raw, asset="github.com/acme/app"))
        assert record.asset == "github.com/acme/app"
        assert record.value == "generic-api-key config.py:3@abcdef123456"
