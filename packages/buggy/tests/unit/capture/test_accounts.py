"""Accounts Buggy creates itself: the switch, discovery, the exemption, storage.

No network: a fake origin like the one in ``test_identities`` answers the
sign-up, the login and a protected page in-process. No test writes a realistic
credential literal; emails and passwords are built at runtime from parts.
"""

from __future__ import annotations

import http.client
import io
import json
import stat
import urllib.error
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

from buggy.capture import accounts
from buggy.capture.accounts import (
    CAPTCHA,
    EMAIL_VERIFICATION,
    LOGIN_FAILED,
    NO_SIGNUP_FOUND,
    NOT_ENABLED,
    REGISTRATION_REFUSED,
    SSO_ONLY,
    UNKNOWN_REQUIRED_FIELD,
    AccountPolicy,
    AccountPolicyError,
    Field,
    Signup,
    account_creation_policy,
    find_login,
    find_signup,
    provision,
)
from buggy.capture.gateway import (
    ACCOUNT_CREATION,
    AccountGrant,
    CaptureGateway,
    GatewayRefusal,
    Roots,
)
from buggy.capture.workbench import WORKBENCH_TOOL_NAMES
from buggy.middleware._audit_sink import iter_records, verify_ledger

HOST = "app.test"
BASE = f"https://{HOST}"
SEED = f"{BASE}/"
REGISTER_URL = f"{BASE}/register"
LOGIN_URL = f"{BASE}/login"
ACCOUNT_URL = f"{BASE}/account"
# Built from parts so no test file carries a realistic credential or key literal.
EMAIL_LOCAL = "qa"
EMAIL_DOMAIN = "buggy" + ".test"
EMAIL_TEMPLATE = f"{EMAIL_LOCAL}+{{tag}}@{EMAIL_DOMAIN}"
CSRF_VALUE = "csrf-" + "0123456789abcdef"
SESSION_COOKIE = "formsess-" + "abcdef0123456789"


class Origin:
    """A fake origin: routes ``(method, url)`` to a tuple or a callable.

    A route is ``(status, content_type, body)`` or
    ``(status, content_type, body, [(header, value), ...])`` or a callable
    returning one of those. Headers travel in an ``HTTPMessage`` so Set-Cookie
    can repeat.
    """

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Any] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []

    def count(self, method: str, url: str) -> int:
        return sum(1 for m, u, _h, _b in self.seen if (m, u) == (method, url))

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data or b""
        self.seen.append((method, url, headers, body))
        route = self.routes.get((method, url), (404, "text/plain", b"not found"))
        status, content_type, payload, *rest = route(headers, body) if callable(route) else route
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode()
        message = http.client.HTTPMessage()
        message.add_header("Content-Type", content_type)
        for name, value in rest[0] if rest else []:
            message.add_header(name, value)
        if status >= 400:
            raise urllib.error.HTTPError(url, status, "x", message, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, message
        return response


class Target:
    """A small application: a landing page, a sign-up, a login and a protected page."""

    def __init__(self, origin: Origin, *, verify_email: bool = False) -> None:
        self.verify_email = verify_email
        self.users: dict[str, str] = {}  # email -> password
        self.tokens: set[str] = set()
        self.issued = 0
        origin.routes[("GET", SEED)] = (
            200,
            "text/html",
            """<html><body>
            <a href="/register">Create account</a>
            <a href="/login">Log in</a>
            <a href="/account">Account</a></body></html>""",
        )
        origin.routes[("GET", REGISTER_URL)] = self.register_page
        origin.routes[("POST", REGISTER_URL)] = self.register
        origin.routes[("GET", LOGIN_URL)] = self.login_page
        origin.routes[("POST", LOGIN_URL)] = self.login
        origin.routes[("GET", ACCOUNT_URL)] = self.account

    def register_page(self, _headers, _body):
        html = f"""<html><body>
        <form method="post" action="/register">
          <input type="hidden" name="csrf" value="{CSRF_VALUE}">
          <input type="email" name="email">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="password" name="confirm_password">
          <input type="checkbox" name="terms">
          <button type="submit">Sign up</button>
        </form></body></html>"""
        return (200, "text/html", html, [("Set-Cookie", f"formsess={SESSION_COOKIE}; Path=/")])

    def register(self, headers, body):
        data = {k: v[0] for k, v in parse_qs(body.decode()).items()}
        if data.get("csrf") != CSRF_VALUE or f"formsess={SESSION_COOKIE}" not in headers.get(
            "cookie", ""
        ):
            return 403, "application/json", {"error": "bad csrf"}
        if data.get("password") != data.get("confirm_password") or not data.get("email"):
            return 400, "application/json", {"error": "invalid"}
        self.users[data["email"]] = data["password"]
        if self.verify_email:
            return 200, "application/json", {"message": "Please verify your email to continue."}
        return 200, "application/json", {"ok": True}

    def login_page(self, _headers, _body):
        html = """<html><body>
        <form method="post" action="/login">
          <input type="email" name="email">
          <input type="password" name="password">
          <button type="submit">Log in</button>
        </form></body></html>"""
        return (200, "text/html", html)

    def login(self, _headers, body):
        data = {k: v[0] for k, v in parse_qs(body.decode()).items()}
        email, password = data.get("email", ""), data.get("password", "")
        if self.verify_email and email in self.users:
            return 401, "application/json", {"error": "email not verified"}
        if self.users.get(email) != password:
            return 401, "application/json", {"error": "bad credentials"}
        self.issued += 1
        token = f"jwt-{self.issued}-" + "aaaabbbbcccc"
        self.tokens.add(token)
        return 200, "application/json", {"authentication": {"token": token}}

    def account(self, headers, _body):
        token = headers.get("authorization", "").removeprefix("Bearer ")
        if token in self.tokens:
            return 200, "application/json", {"ok": True, "page": "account"}
        return 401, "application/json", {"error": "sign in"}


def _roots(tmp_path: Path) -> Roots:
    return Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )


def _roe(enabled: bool = True, **account_extra: Any) -> dict:
    enforcement: dict[str, Any] = {"mode": "enforce", "in_scope": [HOST]}
    if enabled:
        enforcement["account_creation"] = {
            "enabled": True,
            "email_template": EMAIL_TEMPLATE,
            "max_accounts": 2,
            **account_extra,
        }
    elif account_extra:
        enforcement["account_creation"] = account_extra
    return {"machine_enforcement": enforcement}


def _write_roe(roots: Roots, document: dict, engagement: str = "acme") -> None:
    (roots.control / engagement).mkdir(parents=True, exist_ok=True)
    (roots.control / engagement / "roe.json").write_text(json.dumps(document))


@pytest.fixture
def env(tmp_path: Path):
    roots = _roots(tmp_path)
    _write_roe(roots, _roe())
    origin = Origin()
    gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
    target = Target(origin)
    yield gateway, origin, roots, target
    gateway.store.close()


# ── the switch ──────────────────────────────────────────────────────


class TestPolicy:
    def test_enabled_block_parses(self) -> None:
        policy = account_creation_policy(_roe())
        assert policy == AccountPolicy(email_template=EMAIL_TEMPLATE, max_accounts=2)
        assert policy is not None
        assert policy.email_for("abcd1234") == f"{EMAIL_LOCAL}+abcd1234@{EMAIL_DOMAIN}"

    def test_absent_or_disabled_is_none(self) -> None:
        assert account_creation_policy(_roe(enabled=False)) is None
        assert account_creation_policy({"machine_enforcement": {}}) is None
        assert account_creation_policy({}) is None
        off = {"machine_enforcement": {"account_creation": {"enabled": False}}}
        assert account_creation_policy(off) is None

    def test_default_max_accounts_is_two(self) -> None:
        document = {
            "machine_enforcement": {
                "account_creation": {"enabled": True, "email_template": EMAIL_TEMPLATE}
            }
        }
        policy = account_creation_policy(document)
        assert policy is not None and policy.max_accounts == 2

    @pytest.mark.parametrize(
        "block",
        [
            {"enabled": True},
            {"enabled": True, "email_template": "no-placeholder@" + EMAIL_DOMAIN},
            {"enabled": True, "email_template": "not-an-email-{tag}"},
            {"enabled": True, "email_template": EMAIL_TEMPLATE, "max_accounts": 0},
            {"enabled": True, "email_template": EMAIL_TEMPLATE, "max_accounts": 4},
            {"enabled": True, "email_template": EMAIL_TEMPLATE, "surprise": 1},
            {"enabled": "yes", "email_template": EMAIL_TEMPLATE},
        ],
    )
    def test_malformed_block_raises(self, block: dict) -> None:
        with pytest.raises(AccountPolicyError):
            account_creation_policy({"machine_enforcement": {"account_creation": block}})


# ── discovery ───────────────────────────────────────────────────────


def _form(**fields: str) -> dict:
    out = []
    for name, kind in fields.items():
        clean = name.rstrip("_")
        out.append({"name": clean, "value": "", "type": kind})
    return {"page": REGISTER_URL, "method": "POST", "action": REGISTER_URL, "fields": out}


class TestDiscovery:
    def test_signup_found_in_html_form_with_csrf_and_cookie(self, env) -> None:
        gateway, _origin, _roots, _target = env
        result = accounts.crawl.crawl(gateway, "acme", [SEED])
        signup = find_signup(result)
        assert signup is not None
        assert signup.kind == "form" and signup.url == REGISTER_URL
        assert signup.hidden == {"csrf": CSRF_VALUE}
        roles = {f.name: f.role for f in signup.fields}
        assert roles == {
            "email": "email",
            "username": "username",
            "password": "password",
            "confirm_password": "password_confirm",
            "terms": "terms",
        }

    def test_signup_found_as_json_api(self) -> None:
        ops = [
            {"method": "GET", "url": f"{BASE}/api/me", "body_fields": []},
            {
                "method": "POST",
                "url": f"{BASE}/api/users",
                "body_fields": [{"name": "email"}, {"name": "password"}, {"name": "displayName"}],
            },
        ]
        signup = find_signup({"forms": []}, ops)
        assert signup is not None and signup.kind == "json"
        assert signup.url == f"{BASE}/api/users" and signup.method == "POST"
        assert {f.role for f in signup.fields} >= {"email", "password", "name"}

    def test_a_login_form_is_not_a_signup(self) -> None:
        login_form = {
            "page": LOGIN_URL,
            "method": "POST",
            "action": LOGIN_URL,
            "fields": [
                {"name": "email", "value": "", "type": "email"},
                {"name": "password", "value": "", "type": "password"},
                {"name": "signin", "value": "Sign in", "type": "submit"},
            ],
        }
        assert find_signup({"forms": [login_form]}) is None
        login = find_login({"forms": [login_form]})
        assert login is not None and login.kind == "form" and login.url == LOGIN_URL

    def test_a_confirmation_form_wins_over_a_bare_pair(self) -> None:
        plain = _form(email="email", password="password")
        plain["action"] = f"{BASE}/join"  # register signal, no confirm
        confirm = _form(email="email", password="password", confirm_password="password")
        signup = find_signup({"forms": [plain, confirm]})
        assert signup is not None and "confirm_password" in {f.name for f in signup.fields}


# ── stop reasons ────────────────────────────────────────────────────


class TestStopReasons:
    def test_not_enabled_sends_nothing(self, tmp_path: Path) -> None:
        roots = _roots(tmp_path)
        _write_roe(roots, _roe(enabled=False))
        origin = Origin()
        gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
        Target(origin)
        result = provision(gateway, "acme", [SEED])
        gateway.store.close()
        assert result["enabled"] is False and result["ok"] is False
        assert result["requests"] == 0 and origin.seen == []
        assert result["failed"][0]["reason"] == NOT_ENABLED

    def test_captcha_marker_stops_with_a_named_reason(self) -> None:
        signup = Signup("form", "POST", REGISTER_URL, REGISTER_URL, (Field("email", "email"),))
        reason, _detail = accounts._signup_blocker(signup, '<div class="g-recaptcha"></div>')
        assert reason == CAPTCHA
        with_field = Signup(
            "form", "POST", REGISTER_URL, REGISTER_URL, (Field("captcha", "other"),)
        )
        assert accounts._signup_blocker(with_field, "<form></form>")[0] == CAPTCHA

    def test_unknown_required_field_stops(self) -> None:
        signup = Signup(
            "form",
            "POST",
            REGISTER_URL,
            REGISTER_URL,
            (Field("email", "email"), Field("password", "password"), Field("invite_code", "other")),
        )
        assert accounts._signup_blocker(signup, "<form></form>")[0] == UNKNOWN_REQUIRED_FIELD
        # A field with a default value is sent back unchanged, not a blocker.
        ok = Signup(
            "form",
            "POST",
            REGISTER_URL,
            REGISTER_URL,
            (Field("locale", "other", value="en"),),
        )
        assert accounts._signup_blocker(ok, "<form></form>")[0] == ""

    def test_sso_only_page_is_detected(self) -> None:
        body = "<html><body><a href='/oauth/google'>Continue with Google</a></body></html>"
        assert accounts._sso_only(body) is True
        assert accounts._sso_only("<input type='password'>" + body) is False

    def test_sso_only_signup_stops_provisioning(self, tmp_path: Path) -> None:
        roots = _roots(tmp_path)
        _write_roe(roots, _roe())
        origin = Origin()
        origin.routes[("GET", SEED)] = (
            200,
            "text/html",
            '<html><body><a href="/register">Create account</a></body></html>',
        )
        origin.routes[("GET", REGISTER_URL)] = (
            200,
            "text/html",
            "<html><body><a href='/oauth/github'>Sign up with GitHub</a></body></html>",
        )
        gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
        result = provision(gateway, "acme", [SEED])
        gateway.store.close()
        assert result["signup"] is None and result["ok"] is False
        assert result["failed"][0]["reason"] == SSO_ONLY

    def test_no_signup_found(self, tmp_path: Path) -> None:
        roots = _roots(tmp_path)
        _write_roe(roots, _roe())
        origin = Origin()
        origin.routes[("GET", SEED)] = (200, "text/html", "<html><body>nothing here</body></html>")
        gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
        result = provision(gateway, "acme", [SEED])
        gateway.store.close()
        assert result["ok"] is False and result["signup"] is None
        assert result["failed"][0]["reason"] == NO_SIGNUP_FOUND

    def test_registration_refused(self, tmp_path: Path) -> None:
        roots = _roots(tmp_path)
        _write_roe(roots, _roe())
        origin = Origin()
        target = Target(origin)
        origin.routes[("POST", REGISTER_URL)] = lambda _h, _b: (400, "application/json", {"no": 1})
        gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
        result = provision(gateway, "acme", [SEED])
        gateway.store.close()
        assert target.users == {}
        assert all(f["reason"] == REGISTRATION_REFUSED for f in result["failed"])
        assert result["created"] == [] and result["ok"] is False

    def test_email_verification_wall(self, tmp_path: Path) -> None:
        roots = _roots(tmp_path)
        _write_roe(roots, _roe())
        origin = Origin()
        Target(origin, verify_email=True)
        gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
        result = provision(gateway, "acme", [SEED])
        gateway.store.close()
        assert result["created"] == [] and result["ok"] is False
        assert any(f["reason"] == EMAIL_VERIFICATION for f in result["failed"])

    def test_login_failed_when_no_session(self, tmp_path: Path) -> None:
        roots = _roots(tmp_path)
        _write_roe(roots, _roe())
        origin = Origin()
        Target(origin)
        origin.routes[("POST", LOGIN_URL)] = lambda _h, _b: (200, "application/json", {"ok": True})
        gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
        result = provision(gateway, "acme", [SEED])
        gateway.store.close()
        assert result["created"] == [] and result["ok"] is False
        assert any(f["reason"] == LOGIN_FAILED for f in result["failed"])


# ── the exemption cannot be abused ──────────────────────────────────


class TestExemption:
    def test_grant_is_refused_off_policy(self, tmp_path: Path) -> None:
        roots = _roots(tmp_path)
        _write_roe(roots, _roe(enabled=False))
        origin = Origin()
        gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
        with pytest.raises(GatewayRefusal) as refused:
            gateway.account_creation_grant("acme", [REGISTER_URL])
        gateway.store.close()
        assert refused.value.code == "NOT_ENABLED"

    def test_grant_only_covers_its_urls(self, env) -> None:
        gateway, origin, _roots, _target = env
        grant = gateway.account_creation_grant("acme", [REGISTER_URL])
        other = f"{BASE}/api/transfer"
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "POST", other, body="{}", account_grant=grant)
        assert refused.value.code == "NOT_AN_ACCOUNT_URL" and origin.count("POST", other) == 0

    def test_a_forged_grant_is_refused(self, env) -> None:
        gateway, origin, _roots, _target = env
        forged = AccountGrant("acme", frozenset({REGISTER_URL}), "acr-forged")
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "POST", REGISTER_URL, body="{}", account_grant=forged)
        assert refused.value.code == "NOT_A_DECLARED_LOGIN"
        assert origin.count("POST", REGISTER_URL) == 0

    def test_a_grant_of_another_engagement_is_refused(self, tmp_path: Path) -> None:
        roots = _roots(tmp_path)
        _write_roe(roots, _roe(), engagement="acme")
        _write_roe(roots, _roe(), engagement="other")
        origin = Origin()
        gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
        grant = gateway.account_creation_grant("other", [REGISTER_URL])
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "POST", REGISTER_URL, body="{}", account_grant=grant)
        gateway.store.close()
        assert refused.value.code == "NOT_A_DECLARED_LOGIN"

    def test_grant_cannot_be_combined_with_identity_or_internal(self, env) -> None:
        gateway, _origin, _roots, _target = env
        grant = gateway.account_creation_grant("acme", [REGISTER_URL])
        with pytest.raises(GatewayRefusal) as one:
            gateway.send(
                "acme", "POST", REGISTER_URL, body="{}", account_grant=grant, internal=True
            )
        assert one.value.code == "BAD_ARGUMENT"

    def test_a_plain_state_changing_request_still_waits_for_approval(self, env) -> None:
        gateway, origin, _roots, _target = env
        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "POST", REGISTER_URL, body="x")
        assert held.value.code == "APPROVAL_REQUIRED" and origin.count("POST", REGISTER_URL) == 0


# ── provisioning end to end ─────────────────────────────────────────


class TestProvision:
    def test_creates_accounts_signs_them_in_and_leaks_no_secret(self, env) -> None:
        gateway, _origin, roots, target = env
        result = provision(gateway, "acme", [SEED])
        assert result["ok"] is True and result["enabled"] is True
        assert result["created"] == ["auto1", "auto2"] and result["reused"] == []
        assert result["failed"] == []
        assert result["signup"] == {"kind": "form", "url": REGISTER_URL}
        assert result["login"] == {"kind": "form", "url": LOGIN_URL}
        assert len(target.users) == 2

        blob = json.dumps(result)
        assert EMAIL_LOCAL + "+" not in blob and EMAIL_DOMAIN not in blob
        for password in target.users.values():
            assert password not in blob
        assert "jwt-" not in blob and CSRF_VALUE not in blob

    def test_created_accounts_are_usable_and_carry_markers(self, env) -> None:
        gateway, _origin, _roots, _target = env
        provision(gateway, "acme", [SEED])
        rows = gateway.identities.public("acme")
        names = {r["name"]: r for r in rows}
        assert {"auto1", "auto2"} <= set(names)
        assert names["auto1"]["role"] == "auto" and names["auto1"]["kind"] == "static"
        # public() exposes no email; markers are the email and username, set automatically.
        assert "email" not in json.dumps(rows) and EMAIL_DOMAIN not in json.dumps(rows)
        markers = gateway.identities.markers("acme")
        assert len(markers["auto1"]) == 2 and any("@" in m for m in markers["auto1"])
        # A request as the created account is attached and answered.
        assert gateway.send("acme", "GET", ACCOUNT_URL, identity="auto1").status == 200

    def test_account_requests_are_recorded_and_redacted(self, env) -> None:
        gateway, _origin, roots, target = env
        provision(gateway, "acme", [SEED])
        captures = gateway.store.list("acme", limit=500)
        account_caps = [c for c in captures if c.approval_id == ACCOUNT_CREATION]
        assert account_caps  # registrations and logins
        for capture in account_caps:
            detail = capture.detail()
            assert detail["request_body"] == "<redacted>"
            assert detail["response_body"] == "<redacted>"
            assert detail["request_sha256"] == "<redacted>"
        # The ledger hides the registration/login body hashes too.
        lines = list(iter_records(roots.audit / "acme" / "captures.jsonl"))
        account_lines = [line for line in lines if line.get("approval_id") == ACCOUNT_CREATION]
        assert account_lines
        for line in account_lines:
            assert line["request_sha256"] == "<redacted>"
        blob = json.dumps(lines)
        for password in target.users.values():
            assert password not in blob
        assert verify_ledger(roots.audit / "acme" / "captures.jsonl").ok

    def test_files_are_written_private_for_the_operator(self, env) -> None:
        gateway, _origin, roots, _target = env
        provision(gateway, "acme", [SEED])
        private = roots.data / "accounts" / "acme.json"
        operator = roots.audit / "acme" / "accounts-created.json"
        for path in (private, operator):
            assert path.exists()
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        document = json.loads(operator.read_text())
        names = [a["name"] for a in document["accounts"]]
        assert names == ["auto1", "auto2"]
        # The operator copy keeps the password so a person can sign in or delete.
        assert all(a["password"] for a in document["accounts"])

    def test_is_idempotent(self, env) -> None:
        gateway, origin, _roots, target = env
        first = provision(gateway, "acme", [SEED])
        assert first["created"] == ["auto1", "auto2"]
        registrations = origin.count("POST", REGISTER_URL)
        emails = set(target.users)

        second = provision(gateway, "acme", [SEED])
        assert second["created"] == [] and sorted(second["reused"]) == ["auto1", "auto2"]
        # No new account was registered; the same two were reused.
        assert origin.count("POST", REGISTER_URL) == registrations
        assert set(target.users) == emails

    def test_count_limits_how_many_are_created(self, env) -> None:
        gateway, _origin, _roots, _target = env
        result = provision(gateway, "acme", [SEED], count=1)
        assert result["created"] == ["auto1"]

    def test_a_declared_identity_wins_on_a_name_clash(self, env) -> None:
        gateway, _origin, roots, _target = env
        provision(gateway, "acme", [SEED])
        # The operator declares an identity named auto1 of their own.
        declared = {
            "identities": [
                {"name": "auto1", "role": "operator", "static": {"headers": {"X-Op": "1"}}}
            ]
        }
        path = roots.secrets / "acme" / "identities.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(declared))
        loaded = gateway.identities.load("acme")
        assert loaded["auto1"].role == "operator" and loaded["auto1"].kind == "static"
        assert loaded["auto1"].static_headers == {"X-Op": "1"}
        # The created auto2 is still there, after the declared ones.
        assert list(loaded) == ["auto1", "auto2"]


def test_accounts_provision_is_a_workbench_tool_without_an_agent_wrapper() -> None:
    assert "accounts_provision" in WORKBENCH_TOOL_NAMES
    from buggy.tools import stack_mcp

    assert "accounts_provision" not in {t.name for t in stack_mcp.ALL_STACK_MCP_TOOLS}


class TestOperatorFinishesTheSignUp:
    """Where Buggy cannot register, it prepares the accounts and signs in once a person did."""

    def created(self, roots: Roots) -> list[dict]:
        path = roots.audit / "acme" / "accounts-created.json"
        return json.loads(path.read_text())["accounts"]

    def test_email_verification_is_finished_by_the_operator_and_buggy_signs_in(self, env) -> None:
        gateway, origin, roots, target = env
        target.verify_email = True
        first = provision(gateway, "acme", [SEED])
        assert first["created"] == [] and first["reused"] == []
        assert {f["reason"] for f in first["failed"]} == {accounts.EMAIL_VERIFICATION}
        registered = origin.count("POST", REGISTER_URL)
        assert registered == 2 and len(self.created(roots)) == 2

        # The operator has not clicked the links yet: nothing is registered twice.
        waiting = provision(gateway, "acme", [SEED])
        assert {f["reason"] for f in waiting["failed"]} == {accounts.WAITING_FOR_OPERATOR}
        assert origin.count("POST", REGISTER_URL) == registered

        # The operator clicks the links; the next run signs in and carries on.
        target.verify_email = False
        done = provision(gateway, "acme", [SEED])
        assert sorted(done["reused"]) == ["auto1", "auto2"] and done["failed"] == []
        assert origin.count("POST", REGISTER_URL) == registered
        assert gateway.send("acme", "GET", ACCOUNT_URL, identity="auto1").status == 200

    def test_without_a_sign_up_buggy_prepares_accounts_for_the_operator_to_register(
        self, env
    ) -> None:
        gateway, origin, roots, target = env
        # The site has a login but no sign-up Buggy can find.
        del origin.routes[("GET", REGISTER_URL)]
        del origin.routes[("POST", REGISTER_URL)]
        origin.routes[("GET", SEED)] = (200, "text/html", '<a href="/login">Log in</a>')

        first = provision(gateway, "acme", [SEED])
        assert first["ok"] is False and first["prepared"] == ["auto1", "auto2"]
        assert {f["reason"] for f in first["failed"]} == {accounts.NO_SIGNUP_FOUND}
        assert first["credentials_file"] == "audit/acme/accounts-created.json"
        prepared = self.created(roots)
        assert [a["name"] for a in prepared] == ["auto1", "auto2"]
        assert all(a["email"].endswith("@" + EMAIL_DOMAIN) and a["password"] for a in prepared)
        # Nothing about the prepared values is in the result the hunt command sees.
        assert prepared[0]["password"] not in json.dumps(first)
        assert prepared[0]["email"] not in json.dumps(first)

        # The operator registers exactly those values on the site (by hand).
        for account in prepared:
            target.users[account["email"]] = account["password"]
        second = provision(gateway, "acme", [SEED])
        assert second["ok"] is True and sorted(second["reused"]) == ["auto1", "auto2"]
        assert second["prepared"] == []
        # The same prepared accounts were kept, not replaced by new ones.
        assert self.created(roots)[0]["email"] == prepared[0]["email"]
        assert gateway.send("acme", "GET", ACCOUNT_URL, identity="auto2").status == 200
