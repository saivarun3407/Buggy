"""Web recon and API recon: what they read, what they send, and what they store."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from buggy.pipeline.report import rank_candidates, render_report
from buggy.pipeline.schema import RecordType
from buggy.pipeline.store import ReconStore
from buggy.pipeline.tools import apirecon, webrecon

from .test_pipeline_flow import ROE, FakeOpener, FakeTools, _pipeline

WWW = "https://www.acme.test"


class Answer(io.BytesIO):
    def __init__(self, body: bytes, headers: dict[str, str] | None = None, status: int = 200):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        return None


class WebOpener(FakeOpener):
    """The fake estate, plus the files and endpoints web and API recon read."""

    def open(self, request, timeout=None):
        url, method = request.full_url, request.get_method()
        if url == f"{WWW}/robots.txt":
            self.requested.append((method, url))
            return Answer(
                b"User-agent: *\nDisallow: /admin/\nDisallow: /private/*.pdf\n"
                b"Allow: /\nSitemap: https://www.acme.test/sitemap-index.xml\n"
            )
        if url == f"{WWW}/sitemap-index.xml":
            self.requested.append((method, url))
            return Answer(
                b"<sitemapindex><sitemap><loc>https://www.acme.test/pages.xml</loc></sitemap>"
                b"<sitemap><loc>https://evil.example/s.xml</loc></sitemap></sitemapindex>"
            )
        if url == f"{WWW}/pages.xml":
            self.requested.append((method, url))
            return Answer(
                b"<urlset><url><loc>https://www.acme.test/password/reset</loc></url>"
                b"<url><loc>https://evil.example/elsewhere</loc></url>"
                b"<url><loc>https://www.acme.test/api/v2/accounts/42?token=abc</loc></url>"
                b"<url><loc>https://www.acme.test/api/v2/logout</loc></url>"
                b"<url><loc>https://www.acme.test/api/v1/orders</loc></url></urlset>"
            )
        if url == f"{WWW}/.well-known/security.txt":
            self.requested.append((method, url))
            return Answer(b"Contact: mailto:security@acme.test\n")
        if url == f"{WWW}/.well-known/openid-configuration":
            self.requested.append((method, url))
            return Answer(
                json.dumps(
                    {
                        "issuer": WWW,
                        "authorization_endpoint": f"{WWW}/oauth/authorize",
                        "token_endpoint": f"{WWW}/oauth/token",
                        "jwks_uri": "https://evil.example/jwks",
                    }
                ).encode()
            )
        if url == f"{WWW}/api/v2/accounts/42":
            self.requested.append((method, url))
            return Answer(
                json.dumps({"id": 42, "email": "a@acme.test", "role": "user"}).encode(),
                {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        if url == f"{WWW}/api/v1/orders":
            self.requested.append((method, url))
            raise urllib.error.HTTPError(
                url, 401, "Unauthorized", {"WWW-Authenticate": 'Bearer realm="api"'}, io.BytesIO()
            )
        return super().open(request, timeout)


@pytest.fixture
def env(tmp_path: Path):
    store = ReconStore(tmp_path / "data" / "recon.sqlite3")
    yield {"store": store, "root": tmp_path / "data", "tools": FakeTools(), "opener": WebOpener()}
    store.close()


def _records(env, kind: str) -> dict[str, dict]:
    return {r.value: r.attrs for r in env["store"].query_records("acme", record_type=kind)}


class TestWebRecon:
    def test_robots_and_sitemaps_add_in_scope_urls_only(self, env) -> None:
        _pipeline(env).run()
        urls = _records(env, "url")
        for added in ("/admin/", "/private/", "/password/reset", "/api/v1/orders"):
            assert f"{WWW}{added}" in urls, added
        assert urls[f"{WWW}/admin/"]["found_in"] == "known_files"
        assert not [u for u in urls if "evil.example" in u]
        requested = [url for _m, url in env["opener"].requested]
        assert "https://evil.example/s.xml" not in requested
        assert f"{WWW}/pages.xml" in requested

    def test_sign_in_pages_are_mapped_by_kind(self, env) -> None:
        _pipeline(env).run()
        surface = _records(env, "auth_surface")
        assert surface[f"{WWW}/password/reset"]["kind"] == "password_reset"
        assert surface[f"{WWW}/admin/"]["kind"] == "admin"
        assert surface[f"{WWW}/login"]["kind"] == "login"
        assert surface[f"{WWW}/oauth/authorize"] == {
            "kind": "oauth",
            "role": "authorize",
            "found_in": f"{WWW}/.well-known/openid-configuration",
        }
        assert not [u for u in surface if "evil.example" in u]

    def test_security_txt_and_missing_headers_are_recorded(self, env) -> None:
        _pipeline(env).run()
        findings = _records(env, "web_finding")
        assert findings[f"{WWW}/.well-known/security.txt security_txt"]["kind"] == "security_txt"
        missing = {a["name"] for a in findings.values() if a["kind"] == "missing_header"}
        assert {"content-security-policy", "strict-transport-security"} <= missing

    def test_a_second_run_sends_nothing_new(self, env) -> None:
        _pipeline(env).run()
        before = len(env["opener"].requested)
        summary = _pipeline(env).run()
        assert len(env["opener"].requested) == before
        assert summary["stages"]["web"]["cached"] and summary["stages"]["api"]["cached"]


class TestApiRecon:
    def test_endpoints_are_profiled_once_without_their_query(self, env) -> None:
        _pipeline(env).run()
        requested = [url for _m, url in env["opener"].requested]
        assert f"{WWW}/api/v2/accounts/42" in requested
        assert not [u for u in requested if "token=abc" in u]
        assert f"{WWW}/api/v2/logout" not in requested  # names logout: never requested
        profiles = _records(env, "api_profile")
        open_one = profiles[f"GET {WWW}/api/v2/accounts/42"]
        assert open_one["auth"] == "none" and open_one["object_id_in_path"] is True
        assert open_one["fields"] == ["id", "email", "role"]
        assert open_one["sensitive_fields"] == ["email", "role"]
        assert open_one["cors_origin"] == "*" and open_one["cors_credentials"] is True
        closed = profiles[f"GET {WWW}/api/v1/orders"]
        assert closed["auth"] == "required" and closed["auth_scheme"] == "Bearer"
        assert all(a["status"] not in (404, 410) for a in profiles.values())

    def test_api_roots_and_versions_are_listed(self, env) -> None:
        _pipeline(env).run()
        bases = _records(env, "api_base")
        assert bases[f"{WWW}/api/v2"]["with_object_id"] == 1
        assert bases[f"{WWW}/api/v2"]["versions"] == ["v1", "v2"]

    def test_passive_only_sends_nothing_but_still_reads_what_is_stored(self, env) -> None:
        _pipeline(env).run()  # the services and pages a passive run reads
        env["opener"].requested.clear()
        roe = json.loads(json.dumps(ROE))
        roe["pipeline"]["passive_only"] = True
        summary = _pipeline(env, roe, force=True).run()
        requested = [url for _m, url in env["opener"].requested]
        for path in (*webrecon.KNOWN_FILES, *apirecon.OIDC_PATHS, "/api/v1/users"):
            assert not [u for u in requested if u.endswith(path)], path
        assert summary["stages"]["web"]["tools"]["known_files"]["skipped"] == "passive_only"
        assert summary["stages"]["api"]["tools"]["api_profile"]["skipped"] == "passive_only"
        assert _records(env, "api_base") and _records(env, "auth_surface")


class TestLeadsAndReport:
    def _all(self, env) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for kind in RecordType:
            rows = env["store"].query_records("acme", record_type=kind.value, limit=1000)
            out[kind.value] = [r.to_dict() for r in rows]
        return out

    def test_recon_becomes_ranked_leads(self, env) -> None:
        _pipeline(env).run()
        rows = {(c["class"], c["where"]): c for c in rank_candidates(self._all(env), limit=200)}
        idor = rows[("access_control", f"GET {WWW}/api/v2/accounts/42")]
        assert idor["probe"] == "idor" and "email, role" in idor["why"]
        assert rows[("auth_session", f"{WWW}/password/reset")]["probe"] == "http_send"
        assert rows[("access_control", f"{WWW}/admin/")]["probe"] == "http_send"
        assert rows[("auth_session", f"{WWW}/oauth/authorize")]
        assert rows[("api", f"{WWW}/api/v2")]["why"].startswith("several API versions")
        assert rows[("misconfiguration", f"GET {WWW}/api/v2/accounts/42")]["probe"] == "cors"
        assert rows[("auth_session", f"GET {WWW}/api/v1/orders")]["probe"] == "jwt_alg_none"
        missing_header_leads = [c for c in rows.values() if "not sent" in c["why"]]
        assert missing_header_leads == []  # report-only, never a lead

    def test_report_has_web_and_api_sections(self, env) -> None:
        summary = _pipeline(env).run()
        text = render_report("acme", {"records": {}, "last_run": summary}, self._all(env))
        assert "## Web" in text and "## API inventory" in text
        assert "password reset" in text and f"{WWW}/api/v2" in text


class TestPureFunctions:
    def test_robots_paths_cut_at_wildcards_and_skip_the_root(self) -> None:
        paths, maps = webrecon.parse_robots(
            "Disallow: /a/*.php\nDisallow: /\nAllow: /b$\n# Disallow: /c\nSitemap: /s.xml",
            "https://h.test/",
        )
        assert paths == ["https://h.test/a/", "https://h.test/b"]
        assert maps == ["https://h.test/s.xml"]

    def test_sitemap_index_names_nested_sitemaps_only(self) -> None:
        assert webrecon.parse_sitemap("<urlset><loc>https://h/a</loc></urlset>") == (
            ["https://h/a"],
            [],
        )
        assert webrecon.parse_sitemap(
            "<sitemapindex><loc>https://h/s1.xml</loc></sitemapindex>"
        ) == ([], ["https://h/s1.xml"])

    def test_session_cookie_flags_and_version_banners(self) -> None:
        found = {
            (r.attrs["kind"], r.attrs["name"]): r.attrs["detail"]
            for r in webrecon.header_findings(
                "https://h.test/",
                {
                    "set-cookie": "sessionid=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT, "
                    "theme=dark; Path=/",
                    "server": "nginx/1.18.0",
                    "content-security-policy": "frame-ancestors 'none'",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "strict-transport-security": "max-age=1",
                },
            )
        }
        assert found == {
            ("cookie_flags", "sessionid"): "session cookie set without Secure, Httponly, Samesite",
            ("version_banner", "server"): "names a version: nginx/1.18.0",
        }

    def test_api_roots_ids_and_templates(self) -> None:
        assert apirecon.api_root("https://h/api/v2/users/7") == "https://h/api/v2"
        assert apirecon.api_root("https://h/rest/products") == "https://h/rest"
        assert apirecon.api_root("https://h/about/team") == ""
        assert apirecon.id_positions("https://h/api/users/7/orders/{orderId}") == [2, 4]
        assert apirecon.is_template("https://h/api/users/{id}")
        assert not apirecon.is_template("https://h/api/users/7")

    def test_profile_targets_cap_and_order(self) -> None:
        urls = [f"https://h/api/items/{i}" for i in range(60)] + ["https://h/api/list?q=1"]
        chosen = apirecon.profile_targets(urls)
        assert len(chosen) == apirecon.MAX_PROFILES_PER_ORIGIN
        assert all("?" not in u for u in chosen)

    def test_discovery_document_without_an_issuer_is_ignored(self) -> None:
        assert list(apirecon.parse_discovery('{"token_endpoint": "https://h/t"}', "u")) == []
        assert list(apirecon.parse_discovery("not json", "u")) == []


class TestFromTheLiveRun:
    """Cases taken from the recon run on the local Juice Shop."""

    def test_nested_record_fields_are_seen(self) -> None:
        body = {
            "status": "success",
            "data": [{"caption": "x", "User": {"email": "e", "password": "p"}}],
        }
        attrs = apirecon.profile(
            "http://h/rest/memories",
            200,
            {"content-type": "application/json"},
            json.dumps(body).encode(),
        ).attrs
        assert attrs["fields"] == ["caption", "User", "User.email", "User.password"]
        assert attrs["sensitive_fields"] == ["User.email", "User.password"]

    def test_a_public_list_is_not_a_lead_but_exposed_fields_are(self) -> None:
        def row(url: str, **attrs) -> dict:
            return {
                "type": "api_profile",
                "value": f"GET {url}",
                "attrs": {
                    "url": url,
                    "status": 200,
                    "auth": "none",
                    "content_type": "application/json",
                    **attrs,
                },
            }

        rows = rank_candidates(
            {
                "api_profile": [
                    row("http://h/api/Products", items=37, fields=["id", "name", "price"]),
                    row(
                        "http://h/rest/memories",
                        items=10,
                        sensitive_fields=["User.email", "User.password"],
                    ),
                ]
            }
        )
        assert [(r["class"], r["where"]) for r in rows] == [
            ("info_exposure", "GET http://h/rest/memories")
        ]

    def test_badly_cut_script_strings_are_never_requested(self) -> None:
        urls = [
            "http://h/api/%5C%22/",
            "http://h/api/%5C%22/ftp/legal.md%5C%22",
            "http://h/api/Products",
        ]
        assert apirecon.profile_targets(urls) == ["http://h/api/Products"]
