"""The ``rfi``, ``clickjacking`` and ``csrf`` probes against a fake origin.

The fake handlers behave like careless and careful servers do (include a
fetched file, append an extension, check a token or the Origin, set cookies
with or without SameSite). None of them matches on the probe's payloads.
"""

from __future__ import annotations

import html
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest

from buggy.capture.canary import Canary
from buggy.capture.probes import REGISTRY, describe, run_probe
from buggy.capture.probes.web import (
    CSRF_MAX_REQUESTS,
    FRAME_MAX_REQUESTS,
    RFI_MAX_REQUESTS,
    frame_policy,
    set_cookie_attributes,
)
from buggy.capture.store import Capture
from buggy.cli.approvals import paths_for, pending

from .fake_web import BASE, SCOPE, cookie_of, make

CANARY = "http://canary.test"


def evidence_ok(env, result: dict, bound: int) -> None:
    ids = result["evidence_capture_ids"]
    details = result["details"]
    assert len(ids) == details["requests_sent"] <= bound == details["max_requests"]
    assert list(details["captures"].values()) == ids
    assert details["control"]
    for capture_id in ids:
        stored = env.gateway.store.get("acme", capture_id)
        assert stored is not None and stored.probe == result["probe"]


# ── remote file inclusion ────────────────────────────────────────────


@pytest.fixture
def rfi_env(tmp_path: Path):
    env = make(tmp_path)
    env.canary = Canary(base_url=CANARY)
    yield env
    env.gateway.store.close()


def page_server(env, *, include: bool, fetch: bool = True, append: str = ""):
    """``GET /view?file=``: fetches a URL value (plus ``append``) and maybe includes it."""

    def handler(_method, url, _headers, _body):
        value = parse_qs(urlsplit(url).query).get("file", [""])[0] + append
        if value.startswith(CANARY + "/c/") and fetch:
            token = urlsplit(value).path.split("/")[2]
            known = env.canary.record(
                token, remote="203.0.113.9", method="GET", path="/", user_agent="php"
            )
            if known and include:
                return 200, [], f"<html><main>{env.canary.body_for(token)}</main></html>"
        return 200, [], f"<html><main>showing {html.escape(value)}</main></html>"

    env.web.route("GET", "/view", handler)


def rfi(env, **extra) -> dict:
    params = {"url": f"{BASE}/view?file=home.txt", "parameter": "file", "wait_seconds": 0}
    return run_probe(env.gateway, "acme", "rfi", {**params, **extra}, canary=env.canary)


class TestRfi:
    def test_included_marker_proves_inclusion(self, rfi_env) -> None:
        page_server(rfi_env, include=True)
        result = rfi(rfi_env)
        assert result["vulnerable"] is True, result
        assert (result["class"], result["cwe"]) == ("file_handling", "CWE-98")
        assert result["details"]["technique"] == "plain"
        assert result["details"]["callbacks"]
        evidence_ok(rfi_env, result, RFI_MAX_REQUESTS)
        # The marker is served by the canary only; the baseline response does not hold it.
        assert result["details"]["baseline"]["marker_present"] is False

    def test_appended_extension_is_passed_by_the_query_suffix(self, rfi_env) -> None:
        page_server(rfi_env, include=True, append=".php")
        result = rfi(rfi_env)
        assert result["vulnerable"] is True and result["details"]["technique"] == "query_suffix"
        assert result["details"]["requests_sent"] == 3

    def test_a_fetch_without_inclusion_is_ssrf_not_rfi(self, rfi_env) -> None:
        page_server(rfi_env, include=False)
        result = rfi(rfi_env)
        assert result["vulnerable"] is True
        assert (result["class"], result["cwe"]) == ("ssrf", "CWE-918")
        assert "not a remote file inclusion" in result["summary"]

    def test_a_reflected_url_is_not_an_inclusion(self, rfi_env) -> None:
        page_server(rfi_env, include=False, fetch=False)
        result = rfi(rfi_env)
        assert result["vulnerable"] is False, result
        assert "neither included nor fetched" in result["summary"]

    def test_without_a_listener_nothing_is_sent(self, rfi_env) -> None:
        page_server(rfi_env, include=True)
        params = {"url": f"{BASE}/view?file=home.txt", "parameter": "file"}
        result = run_probe(rfi_env.gateway, "acme", "rfi", params)
        assert result["vulnerable"] is None and "could not test" in result["summary"]
        assert rfi_env.web.seen == []

    def test_canary_serves_the_marker_for_its_token_only(self) -> None:
        canary = Canary(base_url=CANARY)
        token, url = canary.mint("acme", body="bgrfi-marker")
        plain, _ = canary.mint("acme")
        assert url == f"{CANARY}/c/{token}"
        assert canary.body_for(token) == "bgrfi-marker" and canary.body_for(plain) == "ok"


# ── clickjacking ─────────────────────────────────────────────────────


@pytest.fixture
def env(tmp_path: Path):
    made = make(tmp_path)
    yield made
    made.gateway.store.close()


ACCOUNT = f"{BASE}/account"
FORM_PAGE = '<html><form method="post" action="/account/email"><input name="email"></form></html>'


def serve_page(env, headers: list[tuple[str, str]], status: int = 200, body: str = FORM_PAGE):
    env.web.route("GET", "/account", lambda *_a: (status, headers, body))


def frame(env, **extra) -> dict:
    return run_probe(env.gateway, "acme", "clickjacking", {"url": ACCOUNT, **extra})


class TestClickjacking:
    def test_a_page_without_protection_is_framable_and_has_a_proof_page(self, env) -> None:
        serve_page(env, [])
        result = frame(env)
        assert result["vulnerable"] is True, result
        assert (result["class"], result["cwe"]) == ("misconfiguration", "CWE-1021")
        proof = result["details"]["proof_html"]
        assert f'<iframe src="{ACCOUNT}"' in proof and "<script" not in proof
        assert result["details"]["forms_on_page"] == 1
        evidence_ok(env, result, FRAME_MAX_REQUESTS)

    @pytest.mark.parametrize(
        "headers",
        [
            [("X-Frame-Options", "DENY")],
            [("X-Frame-Options", "sameorigin")],
            [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")],
            [("Content-Security-Policy", "frame-ancestors 'self' https://partner.acme.test")],
        ],
    )
    def test_protected_pages_are_not_flagged(self, env, headers) -> None:
        serve_page(env, headers)
        result = frame(env)
        assert result["vulnerable"] is False, result
        assert "proof_html" not in result["details"]

    @pytest.mark.parametrize(
        ("headers", "why"),
        [
            ([("X-Frame-Options", "ALLOW-FROM https://x.test")], "ALLOW-FROM is ignored"),
            (
                [("X-Frame-Options", "DENY"), ("Content-Security-Policy", "frame-ancestors *")],
                "frame-ancestors allows any site",
            ),
            (
                [("Content-Security-Policy-Report-Only", "frame-ancestors 'none'")],
                "neither X-Frame-Options",
            ),
        ],
    )
    def test_protection_a_browser_ignores_does_not_count(self, env, headers, why) -> None:
        serve_page(env, headers)
        result = frame(env)
        assert result["vulnerable"] is True and why in result["summary"], result

    def test_a_redirect_or_a_non_html_answer_cannot_tell(self, env) -> None:
        serve_page(env, [("Location", "/login")], status=302, body="")
        assert frame(env)["vulnerable"] is None
        serve_page(env, [("Content-Type", "application/json")], body="{}")
        assert frame(env)["vulnerable"] is None

    def test_frame_policy_reads_headers_like_a_browser(self) -> None:
        def capture(headers: dict[str, str]) -> Capture:
            return Capture(
                "c", "acme", 0.0, "GET", ACCOUNT, "app.acme.test", {}, b"", "", 200,
                headers, b"", "", 0, 0.0, "", "", "", "", "", "",
            )  # fmt: skip

        assert frame_policy(capture({}))["framable"] is True
        two = {"Content-Security-Policy": "frame-ancestors *, frame-ancestors 'self'"}
        assert frame_policy(capture(two))["framable"] is False  # every policy must allow it
        assert frame_policy(capture({"X-Frame-Options": "nonsense"}))["framable"] is True


# ── CSRF ─────────────────────────────────────────────────────────────

EMAIL = f"{BASE}/account/email"
TOKEN_VALUE = "form-token-of-alice"


def login_identity(name: str = "alice") -> dict:
    return {
        "name": name,
        "login": {
            "request": {"method": "POST", "url": f"{BASE}/login", "body": "user=" + name},
            "extract": [{"name": "sid", "from": "cookie", "cookie": "sid"}],
            "apply": {"cookies": {"sid": "{sid}"}},
        },
    }


def csrf_env(tmp_path: Path, samesite: str | None, *, check: str = "", open_action=False):
    """A site whose login cookie has ``samesite`` (None: no attribute) and whose
    ``POST /account/email`` checks ``check`` ("token", "origin" or nothing)."""
    identities = [
        login_identity(),
        {"name": "static", "static": {"cookies": {"sid": "alice-session-value"}}},
        {"name": "bearer", "static": {"headers": {"Authorization": "Bearer abc-session-value"}}},
    ]
    env = make(tmp_path, identities=identities)
    attribute = "" if samesite is None else f"; SameSite={samesite}"
    env.web.route(
        "POST",
        "/login",
        lambda *_a: (200, [("Set-Cookie", f"sid=alice-session-value; Path=/{attribute}")], "ok"),
    )

    def change(_method, url, headers, body):
        signed_in = cookie_of(headers).get("sid") == "alice-session-value"
        signed_in = signed_in or headers.get("authorization") == "Bearer abc-session-value"
        if not signed_in and not open_action:
            return 302, [("Location", "/login")], ""
        fields = dict(parse_qsl(body.decode() or urlsplit(url).query))
        if check == "token" and fields.get("csrf_token") != TOKEN_VALUE:
            return 403, [], "<p>invalid csrf token</p>"
        if check == "origin" and headers.get("origin", BASE) != BASE:
            return 403, [], "<p>cross-site request refused</p>"
        return 200, [], f"<p>email changed to {html.escape(fields.get('email', ''))}</p>"

    env.web.route("POST", "/account/email", change)
    env.web.route("GET", "/account/avatar/remove", change)
    return env


def csrf(env, identity: str = "alice", **extra) -> dict:
    params = {"url": EMAIL, "body": {"email": "a@acme.test"}, "identity": identity, **extra}
    return run_probe(env.gateway, "acme", "csrf", params)


def probe_requests(env) -> list[tuple[str, str, dict[str, str], bytes]]:
    return [seen for seen in env.web.seen if urlsplit(seen[1]).path != "/login"]


class TestCsrf:
    @pytest.fixture(autouse=True)
    def _close(self):
        self.envs: list = []
        yield
        for env in self.envs:
            env.gateway.store.close()

    def site(self, tmp_path: Path, samesite: str | None, **kwargs):
        env = csrf_env(tmp_path, samesite, **kwargs)
        self.envs.append(env)
        return env

    def test_forgeable_request_is_found(self, tmp_path) -> None:
        env = self.site(tmp_path, "None")
        result = csrf(env)
        assert result["vulnerable"] is True, result
        assert (result["class"], result["cwe"], result["identity"]) == ("csrf", "CWE-352", "alice")
        evidence_ok(env, result, CSRF_MAX_REQUESTS)
        baseline, cross, anonymous = probe_requests(env)
        assert baseline[2]["origin"] == BASE and cookie_of(baseline[2])["sid"]
        assert cross[2]["origin"].endswith(".example") and cookie_of(cross[2])["sid"]
        assert "sid" not in cookie_of(anonymous[2])
        assert result["details"]["samesite"] == "none"

    def test_an_unchecked_token_is_removed_and_not_missed(self, tmp_path) -> None:
        env = self.site(tmp_path, "None")
        result = csrf(env, body={"email": "a@acme.test", "csrf_token": TOKEN_VALUE})
        assert (
            result["vulnerable"] is True and result["details"]["technique"] == "token_not_checked"
        )
        assert result["details"]["token_fields"] == ["csrf_token"]
        _baseline, cross, _anon = probe_requests(env)
        assert b"csrf_token" not in cross[3]

    def test_a_checked_token_protects(self, tmp_path) -> None:
        env = self.site(tmp_path, "None", check="token")
        result = csrf(env, body={"email": "a@acme.test", "csrf_token": TOKEN_VALUE})
        assert result["vulnerable"] is False and "anti-CSRF token" in result["summary"], result
        assert len(probe_requests(env)) == 2

    def test_an_origin_check_protects(self, tmp_path) -> None:
        env = self.site(tmp_path, "None", check="origin")
        result = csrf(env)
        assert result["vulnerable"] is False and "Origin or Referer" in result["summary"]

    @pytest.mark.parametrize("samesite", ["Strict", "Lax"])
    def test_a_samesite_cookie_ends_the_run_after_the_baseline(self, tmp_path, samesite) -> None:
        env = self.site(tmp_path, samesite)
        result = csrf(env)
        assert result["vulnerable"] is False and f"SameSite={samesite}" in result["summary"]
        assert len(probe_requests(env)) == 1

    def test_a_lax_cookie_still_goes_with_a_cross_site_get(self, tmp_path) -> None:
        env = self.site(tmp_path, "Lax")
        result = csrf(env, url=f"{BASE}/account/avatar/remove?confirm=1", method="GET", body=None)
        assert result["vulnerable"] is True, result
        _baseline, cross, _anon = probe_requests(env)
        assert "origin" not in cross[2] and cross[2]["referer"].endswith(".example/")

    def test_a_cookie_without_samesite_is_reported_with_the_browser_note(self, tmp_path) -> None:
        env = self.site(tmp_path, None)
        result = csrf(env)
        assert result["vulnerable"] is True and "Chrome treats" in result["summary"]

    def test_a_static_cookie_never_seen_in_set_cookie_cannot_tell(self, tmp_path) -> None:
        env = self.site(tmp_path, "None")
        result = csrf(env, identity="static")
        assert result["vulnerable"] is None and "SameSite attribute" in result["summary"]
        assert result["details"]["session_cookies"] == {"sid": "unknown"}

    def test_an_action_that_needs_no_session_is_not_csrf(self, tmp_path) -> None:
        env = self.site(tmp_path, "None", open_action=True)
        result = csrf(env)
        assert result["vulnerable"] is False and "without any session" in result["summary"]

    def test_a_header_session_cannot_be_forged(self, tmp_path) -> None:
        env = self.site(tmp_path, "None")
        result = csrf(env, identity="bearer")
        assert result["vulnerable"] is False and "header, not a cookie" in result["summary"]
        assert len(probe_requests(env)) == 1

    def test_a_json_body_goes_cross_site_as_text_plain(self, tmp_path) -> None:
        env = self.site(tmp_path, "None")

        def api(_method, _url, headers, _body):
            if cookie_of(headers).get("sid") != "alice-session-value":
                return 401, [("Content-Type", "application/json")], '{"error": "login"}'
            if headers.get("content-type") != "application/json":
                return 415, [("Content-Type", "application/json")], '{"error": "json only"}'
            return 200, [("Content-Type", "application/json")], '{"ok": true}'

        env.web.route("POST", "/api/profile", api)
        params = {"url": f"{BASE}/api/profile", "location": "json", "body": {"name": "a"}}
        result = csrf(env, **params)
        assert result["vulnerable"] is False, result
        _baseline, cross = probe_requests(env)
        assert cross[2]["content-type"] == "text/plain"

    def test_a_refused_baseline_cannot_tell(self, tmp_path) -> None:
        env = self.site(tmp_path, "None")
        result = csrf(env, url=f"{BASE}/nowhere")
        assert result["vulnerable"] is None and "nothing to compare" in result["summary"]

    def test_without_identity_it_is_an_error_and_no_approval_is_asked(self, tmp_path) -> None:
        identities = [login_identity()]
        env = make(tmp_path, SCOPE, identities=identities)
        self.envs.append(env)
        result = run_probe(env.gateway, "acme", "csrf", {"url": EMAIL, "body": {"e": "1"}})
        assert result["status"] == "error" and "needs identity" in result["detail"]
        requests_path, decisions_path = paths_for(env.roots.control, env.roots.audit, "acme")
        assert pending(requests_path, decisions_path) == [] and env.web.seen == []

    def test_set_cookie_attributes(self) -> None:
        line = "sid=x; Path=/; SameSite=Lax\nprefs=y; Secure\ntheme=z; samesite=none"
        capture = Capture(
            "c", "acme", 0.0, "GET", EMAIL, "app.acme.test", {}, b"", "", 200,
            {"Set-Cookie": line}, b"", "", 0, 0.0, "", "", "", "", "", "",
        )  # fmt: skip
        assert set_cookie_attributes(capture) == {"sid": "lax", "prefs": "", "theme": "none"}


# ── registry ─────────────────────────────────────────────────────────


def test_registered_with_class_cwe_and_approval() -> None:
    expected = {
        "xss_stored": ("xss", "CWE-79", True),
        "xss_blind": ("xss", "CWE-79", True),
        "rfi": ("file_handling", "CWE-98", False),
        "clickjacking": ("misconfiguration", "CWE-1021", False),
        "csrf": ("csrf", "CWE-352", True),
    }
    for name, (vuln_class, cwe, state_changing) in expected.items():
        spec = REGISTRY[name]
        assert (spec.vuln_class, spec.cwe, spec.state_changing) == (vuln_class, cwe, state_changing)
    rows = {row["probe"]: row for row in describe()}
    assert [n for n, row in rows.items() if row["requires_identity"]] == ["csrf"]
    assert list(REGISTRY)[-5:] == list(expected)
