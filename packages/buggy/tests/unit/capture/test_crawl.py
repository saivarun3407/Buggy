"""The signed-in surface crawl against a fake origin: GET only, never a logout."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from buggy.capture.crawl import (
    NEVER_REQUEST_WORDS,
    PER_TEMPLATE,
    crawl,
    never_request_reason,
    normalize,
    template_of,
)
from buggy.capture.gateway import CaptureGateway, GatewayRefusal, Roots
from buggy.capture.workbench import WORKBENCH_TOOL_NAMES, Workbench

BASE = "https://app.acme.test"
OTHER = "https://cdn.other.test"
SESSION = "session-of-alice-" + "0123456789abcdef"  # built at runtime, shaped like nothing real
PASSWORD_DEFAULT = "pre" + "filled-" + "secret"
HTML = "text/html; charset=utf-8"
SCOPE = {"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}}


class Origin:
    """A fake origin: ``url -> (status, content type, body[, headers])``."""

    def __init__(self) -> None:
        self.routes: dict[str, tuple] = {}
        self.seen: list[tuple[str, str, dict[str, str]]] = []

    def page(self, path: str, body: str, content_type: str = HTML) -> None:
        self.routes[BASE + path] = (200, content_type, body.encode())

    def open(self, request, timeout=None):  # noqa: ARG002
        url = request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        self.seen.append((request.get_method(), url, headers))
        status, content_type, body, *extra = self.routes.get(url, (404, "text/plain", b"not found"))
        response_headers = {"Content-Type": content_type, **(extra[0] if extra else {})}
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", response_headers, io.BytesIO(body))
        response = io.BytesIO(body)
        response.status, response.headers = status, response_headers
        return response

    def requested(self) -> list[str]:
        return [url for _m, url, _h in self.seen]


@pytest.fixture
def env(tmp_path: Path):
    roots = Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(json.dumps(SCOPE))
    (roots.secrets / "acme").mkdir(parents=True)
    (roots.secrets / "acme" / "identities.json").write_text(
        json.dumps(
            {
                "identities": [
                    {"name": "alice", "static": {"cookies": {"sid": SESSION}}},
                ]
            }
        )
    )
    origin = Origin()
    gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
    yield SimpleNamespace(gateway=gateway, origin=origin, roots=roots)
    gateway.store.close()


def _site(origin: Origin) -> None:
    origin.page(
        "/",
        """<html><head><link href="/static/app.css" rel="stylesheet">
        <script src="/static/app.js"></script></head><body>
        <a href="/account">Account</a> <a href="/orders#top">Orders</a>
        <a href="/logout">Log out</a> <a href="/account/delete?confirm=1">Delete account</a>
        <a href="/settings/signOut">Sign out everywhere</a>
        <a href="mailto:help@acme.test">Mail</a> <a href="javascript:void(0)">JS</a>
        <a href="data:text/html,hi">data</a>
        <a href="https://cdn.other.test/lib">elsewhere</a>
        <iframe src="/widgets/frame"></iframe>
        <img src="/logo.png"></body></html>""",
    )
    origin.page(
        "/account",
        f"""<html><body><a href="/account/profile">Profile</a>
        <form method="post" action="/account/update">
          <input type="hidden" name="csrf" value="tok123">
          <input name="email" value="alice@acme.test">
          <input type="password" name="password" value="{PASSWORD_DEFAULT}">
          <select name="plan"><option value="free">Free</option>
            <option value="pro" selected>Pro</option></select>
          <textarea name="bio">Hello there</textarea>
          <button type="submit">Save</button>
        </form>
        <form action="search"><input name="q"></form></body></html>""",
    )
    origin.page(
        "/orders",
        '{"next": "/orders?page=2", "items": [{"href": "/orders/1"}]}',
        "application/json",
    )
    origin.page("/account/profile", "<p>deep</p>")
    origin.page("/widgets/frame", "<p>frame</p>")


def _hosts_seen(origin: Origin) -> set[str]:
    return {url.split("/")[2] for url in origin.requested()}


class TestWhatItRequests:
    def test_follows_same_host_links_breadth_first(self, env) -> None:
        _site(env.origin)
        result = crawl(env.gateway, "acme", [BASE + "/"])
        requested = env.origin.requested()
        assert requested[0] == BASE + "/"
        # Breadth first: every link of the first page before anything they link to.
        first_level = {BASE + "/account", BASE + "/orders", BASE + "/widgets/frame"}
        assert set(requested[1:4]) == first_level
        assert BASE + "/account/profile" in requested
        assert BASE + "/account/profile" not in requested[:4]
        assert _hosts_seen(env.origin) == {"app.acme.test"}
        assert result["requested"] == len(requested) and result["truncated"] is False
        assert [p["url"] for p in result["pages"]] == requested
        assert all(p["capture_id"] for p in result["pages"])
        assert result["urls"] == sorted(result["urls"])
        assert BASE + "/orders" in result["urls"]  # the fragment is dropped
        assert not any(url.startswith(OTHER) for url in result["urls"])

    def test_never_sends_anything_but_get(self, env) -> None:
        _site(env.origin)
        crawl(env.gateway, "acme", [BASE + "/"])
        assert env.origin.seen and {m for m, _u, _h in env.origin.seen} == {"GET"}
        # The form actions were recorded, never sent.
        assert BASE + "/account/update" not in env.origin.requested()
        assert BASE + "/account/search" not in env.origin.requested()

    def test_never_requests_a_logout_or_delete_url_and_says_why(self, env) -> None:
        _site(env.origin)
        result = crawl(env.gateway, "acme", [BASE + "/"])
        dangerous = {
            BASE + "/logout",
            BASE + "/account/delete?confirm=1",
            BASE + "/settings/signOut",
        }
        assert not dangerous & set(env.origin.requested())
        skipped = {row["url"]: row["reason"] for row in result["skipped"]}
        for url in dangerous:
            assert url in skipped and "change state" in skipped[url]
        assert dangerous <= set(result["urls"])  # discovered, listed, not requested

    def test_a_dangerous_seed_or_redirect_is_not_followed_either(self, env) -> None:
        env.origin.routes[BASE + "/go"] = (302, HTML, b"", {"Location": "/sign-out?next=/"})
        result = crawl(env.gateway, "acme", [BASE + "/logout", BASE + "/go"])
        assert env.origin.requested() == [BASE + "/go"]
        skipped = {row["url"] for row in result["skipped"]}
        assert {BASE + "/logout", BASE + "/sign-out?next=/"} <= skipped

    def test_a_redirect_on_the_same_host_is_a_discovered_link(self, env) -> None:
        env.origin.routes[BASE + "/start"] = (302, HTML, b"", {"Location": "/home"})
        env.origin.routes[BASE + "/away"] = (302, HTML, b"", {"Location": OTHER + "/x"})
        env.origin.page("/home", "<p>home</p>")
        result = crawl(env.gateway, "acme", [BASE + "/start", BASE + "/away"])
        assert env.origin.requested() == [BASE + "/start", BASE + "/away", BASE + "/home"]
        assert result["pages"][0]["status"] == 302

    def test_static_assets_are_not_requested(self, env) -> None:
        _site(env.origin)
        result = crawl(env.gateway, "acme", [BASE + "/"])
        for asset in ("/static/app.css", "/static/app.js", "/logo.png"):
            assert BASE + asset not in env.origin.requested()
        assert any(row["reason"] == "static asset" for row in result["skipped"])

    def test_every_request_carries_the_identitys_session(self, env) -> None:
        _site(env.origin)
        result = crawl(env.gateway, "acme", [BASE + "/"], identity="alice")
        assert result["identity"] == "alice"
        assert env.origin.seen
        assert all(f"sid={SESSION}" in h.get("cookie", "") for _m, _u, h in env.origin.seen)
        for page in result["pages"]:
            capture = env.gateway.store.get("acme", page["capture_id"])
            assert capture is not None and capture.identity == "alice"
        assert SESSION not in json.dumps(result)

    def test_without_identity_no_session_is_sent(self, env) -> None:
        _site(env.origin)
        result = crawl(env.gateway, "acme", [BASE + "/"])
        assert result["identity"] == ""
        assert not any("cookie" in h for _m, _u, h in env.origin.seen)

    def test_an_unknown_identity_sends_nothing(self, env) -> None:
        with pytest.raises(GatewayRefusal) as refused:
            crawl(env.gateway, "acme", [BASE + "/"], identity="mallory")
        assert refused.value.code == "UNKNOWN_IDENTITY" and env.origin.seen == []


class TestBudgetDepthAndTemplates:
    def test_the_request_budget_holds_and_is_reported(self, env) -> None:
        links = "".join(f'<a href="/p{i}">{i}</a>' for i in range(30))
        env.origin.page("/", f"<html>{links}</html>")
        result = crawl(env.gateway, "acme", [BASE + "/"], max_requests=7)
        assert len(env.origin.seen) == 7 == result["requested"]
        assert result["truncated"] is True
        assert len([u for u in result["urls"] if "/p" in u]) == 30

    def test_depth_is_bounded(self, env) -> None:
        for n in range(6):
            env.origin.page(f"/d{n}", f'<a href="/d{n + 1}">next</a>')
        result = crawl(env.gateway, "acme", [BASE + "/d0"], max_depth=2)
        assert env.origin.requested() == [BASE + "/d0", BASE + "/d1", BASE + "/d2"]
        assert BASE + "/d3" in result["urls"] and result["truncated"] is False

    def test_at_most_a_few_urls_per_path_template(self, env) -> None:
        products = "".join(f'<a href="/products/{i}">p</a>' for i in range(40))
        uuids = "".join(
            f'<a href="/items/{i:08d}-0000-4000-8000-000000000000/view">u</a>' for i in range(9)
        )
        env.origin.page("/", f"<html>{products}{uuids}<a href='/about'>about</a></html>")
        result = crawl(env.gateway, "acme", [BASE + "/"], max_requests=100)
        requested = env.origin.requested()
        assert len([u for u in requested if "/products/" in u]) == PER_TEMPLATE
        assert len([u for u in requested if "/items/" in u]) == PER_TEMPLATE
        assert BASE + "/about" in requested
        assert len([u for u in result["urls"] if "/products/" in u]) == 40
        assert any("template" in row["reason"] for row in result["skipped"])

    def test_template_of_replaces_ids(self) -> None:
        assert template_of(BASE + "/u/42/orders/5f1d7c2a9b3e4d5f6a7b8c9d?x=1") == (
            "app.acme.test/u/{id}/orders/{id}"
        )
        assert template_of(BASE + "/u/alice") == "app.acme.test/u/alice"


class TestWhatItReads:
    def test_forms_are_recorded_with_defaults_but_never_a_password(self, env) -> None:
        _site(env.origin)
        result = crawl(env.gateway, "acme", [BASE + "/"])
        forms = [f for f in result["forms"] if f["page"] == BASE + "/account"]
        update, search = forms
        assert update["method"] == "POST" and update["action"] == BASE + "/account/update"
        fields = {f["name"]: f["value"] for f in update["fields"]}
        assert fields == {
            "csrf": "tok123",
            "email": "alice@acme.test",
            "password": "",
            "plan": "pro",
            "bio": "Hello there",
        }
        assert PASSWORD_DEFAULT not in json.dumps(result)
        assert search["method"] == "GET" and search["action"] == BASE + "/search"
        # Each field record also carries its input type (a superset of {name, value}).
        types = {f["name"]: f["type"] for f in update["fields"]}
        assert types == {
            "csrf": "hidden",
            "email": "text",
            "password": "password",
            "plan": "select",
            "bio": "textarea",
        }

    def test_paths_are_taken_from_json(self, env) -> None:
        _site(env.origin)
        result = crawl(env.gateway, "acme", [BASE + "/orders"])
        assert {BASE + "/orders?page=2", BASE + "/orders/1"} <= set(env.origin.requested())
        assert BASE + "/orders/1" in result["urls"]

    def test_json_extraction_is_bounded(self, env) -> None:
        document = {
            "links": [f"/x{i}" for i in range(500)],
            "deep": {"a": {"b": {"c": {"d": {"e": {"f": {"g": "/too-deep"}}}}}}},
        }
        env.origin.page("/api", json.dumps(document), "application/json")
        result = crawl(env.gateway, "acme", [BASE + "/api"], max_requests=1)
        found = [u for u in result["urls"] if "/x" in u]
        assert len(found) == 200
        assert BASE + "/too-deep" not in result["urls"]

    def test_the_result_carries_no_response_bodies(self, env) -> None:
        marker = "UNIQUE-BODY-MARKER-" + "7f3a"
        env.origin.page("/", f"<html><p>{marker}</p><a href='/a'>a</a></html>")
        env.origin.page("/a", json.dumps({"secret": marker}), "application/json")
        result = crawl(env.gateway, "acme", [BASE + "/"])
        assert result["requested"] == 2 and marker not in json.dumps(result)
        assert set(result) == {
            "identity",
            "requested",
            "truncated",
            "pages",
            "urls",
            "forms",
            "skipped",
        }

    @pytest.mark.parametrize(
        "body",
        [
            "<a href='/ok'>ok</a><<<<>>>><a href=\"/broken",
            "<form><input name='x' value='1'><select name='s'><option>",
            "</div></form></select><textarea name=t>",
            "\x00\xff<a href='/ok'>",
            "<a href='http://[::1'>bad</a><a href='/ok'>ok</a>",
        ],
    )
    def test_malformed_html_does_not_crash(self, env, body: str) -> None:
        env.origin.page("/", body)
        env.origin.page("/ok", "<p>fine</p>")
        result = crawl(env.gateway, "acme", [BASE + "/"])
        assert result["requested"] >= 1


class TestRefusals:
    def test_a_refused_url_does_not_stop_the_crawl(self, env) -> None:
        refused = "https://admin.acme.test/"
        env.origin.page("/", "<a href='/next'>next</a>")
        env.origin.page("/next", "<p>next</p>")
        result = crawl(env.gateway, "acme", [refused, BASE + "/"])
        assert refused not in env.origin.requested()
        assert env.origin.requested() == [BASE + "/", BASE + "/next"]
        (row,) = [r for r in result["skipped"] if r["url"] == refused]
        assert "OUT_OF_SCOPE" in row["reason"] and result["truncated"] is False

    def test_a_refusal_that_would_repeat_stops_the_crawl(self, env, monkeypatch) -> None:
        env.origin.page("/", "<a href='/a'>a</a><a href='/b'>b</a>")
        real = env.gateway.send
        calls = {"n": 0}

        def limited(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] > 1:
                raise GatewayRefusal("RATE_LIMITED", "slow down")
            return real(*args, **kwargs)

        monkeypatch.setattr(env.gateway, "send", limited)
        result = crawl(env.gateway, "acme", [BASE + "/"])
        assert result["requested"] == 1 and result["truncated"] is True
        assert calls["n"] == 2  # it did not try the third URL
        assert "RATE_LIMITED" in result["skipped"][-1]["reason"]

    def test_seeds_must_be_absolute_urls(self, env) -> None:
        seeds: list[Any] = ["/relative", "ftp://app.acme.test/", 5]
        result = crawl(env.gateway, "acme", seeds)
        assert env.origin.seen == [] and result["requested"] == 0
        assert len(result["skipped"]) == 3


class TestTheNeverRequestList:
    @pytest.mark.parametrize(
        "url",
        [
            "/logout",
            "/user/log-out",
            "/auth/SignOut",
            "/session/logoff",
            "/x?action=delete",
            "/api/items/3/remove",
            "/account/deactivate",
            "/billing/cancel",
            "/tokens/revoke",
            "/password/reset",
            "/cache/purge",
            "/table/drop",
            "/mfa/disable",
            "/data/export.csv",
            "/files/download?id=1",
            "/newsletter/unsubscribe",
            "/deleteAccount",
            "/a/destroy_session",
        ],
    )
    def test_dangerous_words_are_caught(self, url: str) -> None:
        assert never_request_reason(BASE + url)

    @pytest.mark.parametrize(
        "url", ["/dropdown", "/exports-history-page", "/catalogue", "/logos", "/resetting"]
    )
    def test_words_inside_other_words_are_not(self, url: str) -> None:
        assert never_request_reason(BASE + url) == ""

    def test_every_family_is_in_the_constant(self) -> None:
        joined = " ".join(NEVER_REQUEST_WORDS)
        for word in ("out", "delete", "unsubscribe", "export", "download", "revoke"):
            assert word in joined

    def test_normalize(self) -> None:
        assert normalize("HTTPS://App.Acme.Test/a?b=1#frag") == "https://app.acme.test/a?b=1"
        assert normalize("../c", BASE + "/a/b/") == BASE + "/a/c"
        for bad in ("javascript:alert(1)", "mailto:x@y", "data:text/html,1", ""):
            assert normalize(bad, BASE + "/") == ""


class TestTheWorkbenchTool:
    def test_surface_crawl_is_a_workbench_tool_with_a_clamped_budget(self, env) -> None:
        assert "surface_crawl" in WORKBENCH_TOOL_NAMES
        links = "".join(f'<a href="/p{i}">{i}</a>' for i in range(400))
        env.origin.page("/", f"<html>{links}</html>")
        bench = Workbench(env.gateway, None, lambda name: name)
        try:
            out = bench.surface_crawl("acme", json.dumps([BASE + "/"]), "alice", 10_000)
            assert out["ok"] and out["requested"] == 300 and out["truncated"] is True
            assert out["identity"] == "alice"
            env.origin.seen.clear()
            one = bench.surface_crawl("acme", json.dumps([BASE + "/"]), max_requests=0)
            assert one["requested"] == 1 == len(env.origin.seen)
            assert bench.surface_crawl("acme", "not json")["code"] == "BAD_ARGUMENT"
            assert bench.surface_crawl("acme", "[]")["code"] == "BAD_ARGUMENT"
            unknown = bench.surface_crawl("acme", json.dumps([BASE + "/"]), "mallory")
            assert unknown["code"] == "UNKNOWN_IDENTITY"
        finally:
            bench.close()
