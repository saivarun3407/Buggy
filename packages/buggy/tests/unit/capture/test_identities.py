"""Identities: the file, TOTP, the login flow and the sessions it yields."""

from __future__ import annotations

import copy
import http.client
import io
import json
import urllib.error
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from buggy.capture.gateway import INTERNAL_LOGIN, CaptureGateway, GatewayRefusal, Roots
from buggy.capture.identities import (
    IdentityError,
    IdentityStore,
    LoginError,
    SessionManager,
    UnknownIdentity,
    totp,
)
from buggy.middleware._audit_sink import iter_records, verify_ledger

LOGIN_URL = "https://app.acme.test/rest/user/login"
ME_URL = "https://app.acme.test/api/me"
EMAIL = "alice.fixture@acme.test"
PASSWORD = 'hunter2-S3cret "pw" \\ &=+'  # quotes, a backslash and form metacharacters
TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of the RFC 6238 SHA-1 seed
TOKEN = "tok-AAAA1111bbbb2222CCCC"
STATIC_TOKEN = "static-9f8e7d6c5b4a3210"
STATIC_COOKIE = "bobcookie-0123456789abcdef"
SECRETS = (EMAIL, PASSWORD, TOTP_SECRET, STATIC_TOKEN, STATIC_COOKIE)
NOW = 1_700_000_000.0


class Origin:
    """A fake origin like ``test_gateway.Site`` that can also set response headers.

    A route is ``(status, body)``, ``(status, body, [(header, value), ...])`` or a
    callable returning one of those. Headers travel in an ``HTTPMessage`` as they
    do from ``urllib``, so a header can repeat.
    """

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], object] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []

    def count(self, method: str, url: str) -> int:
        return sum(1 for m, u, _h, _b in self.seen if (m, u) == (method, url))

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data or b""
        self.seen.append((method, url, headers, body))
        route = self.routes.get((method, url), (404, b"not found"))
        status, payload, *rest = route(headers, body) if callable(route) else route
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode()
        message = http.client.HTTPMessage()
        for name, value in [("Content-Type", "application/json"), *(rest[0] if rest else [])]:
            message.add_header(name, value)
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", message, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, message
        return response


class App:
    """A fake application: a login that checks all three factors, and a protected page."""

    def __init__(self, origin: Origin, clock) -> None:
        self.clock = clock
        self.valid: set[str] = set()
        self.issued = 0
        self.login_bodies: list[dict] = []
        origin.routes[("POST", LOGIN_URL)] = self.login
        origin.routes[("GET", ME_URL)] = self.me

    def login(self, _headers, body):
        data = json.loads(body)
        self.login_bodies.append(data)
        expected = {"email": EMAIL, "password": PASSWORD, "otp": totp(TOTP_SECRET, at=self.clock())}
        if data != expected:
            return 401, {"error": "Invalid email or password."}
        self.issued += 1
        token = f"{TOKEN}-{self.issued}"
        self.valid.add(token)
        return 200, {"authentication": {"token": token, "umail": "a"}}

    def me(self, headers, _body):
        token = headers.get("authorization", "").removeprefix("Bearer ")
        return (200, {"user": "alice"}) if token in self.valid else (401, {"error": "expired"})


def _alice() -> dict:
    return {
        "name": "alice",
        "role": "user",
        "owner_of": ["https://app.acme.test/api/orders/1001"],
        "login": {
            "request": {
                "method": "POST",
                "url": LOGIN_URL,
                "headers": {"Content-Type": "application/json"},
                "body": '{"email": "{username}", "password": "{password}", "otp": "{totp}"}',
            },
            "credentials": {"username": EMAIL, "password": PASSWORD, "totp_secret": TOTP_SECRET},
            "extract": [{"name": "token", "from": "json", "path": "authentication.token"}],
            "apply": {"headers": {"Authorization": "Bearer {token}"}},
            "success": {"status": 200, "body_contains": "authentication"},
        },
    }


def _bob() -> dict:
    return {
        "name": "bob",
        "role": "admin",
        "static": {
            "headers": {"Authorization": f"Bearer {STATIC_TOKEN}"},
            "cookies": {"sid": STATIC_COOKIE},
        },
    }


def _document() -> dict:
    return {"identities": [_alice(), _bob()]}


def _write(roots: Roots, document: object, engagement: str = "acme") -> Path:
    path = roots.secrets / engagement / "identities.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    return path


@pytest.fixture
def env(tmp_path: Path):
    """A gateway whose engagement REQUIRES approval for state-changing requests."""
    roots = Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}})
    )
    origin = Origin()
    gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
    clock = {"now": NOW}
    store = IdentityStore(roots.secrets)
    sessions = SessionManager(gateway, store, clock=lambda: clock["now"])
    gateway.sessions = sessions  # the gateway and the test share one manager and one clock
    app = App(origin, lambda: clock["now"])
    _write(roots, _document())
    yield gateway, origin, roots, store, sessions, app
    gateway.store.close()


class TestTotp:
    # RFC 6238 appendix B, SHA-1 rows (8 digits; the seed is ASCII "12345678901234567890").
    VECTORS = (
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    )

    @pytest.mark.parametrize(("at", "expected"), VECTORS)
    def test_rfc_6238_vectors(self, at: int, expected: str) -> None:
        assert totp(TOTP_SECRET, at=at, digits=8) == expected
        assert totp(TOTP_SECRET, at=at) == expected[-6:]  # the default is six digits

    def test_code_holds_for_one_step_and_then_changes(self) -> None:
        assert totp(TOTP_SECRET, at=30) == totp(TOTP_SECRET, at=59)
        assert totp(TOTP_SECRET, at=59) != totp(TOTP_SECRET, at=60)
        assert totp("JBSWY3DPEHPK3PXP", at=59) != totp(TOTP_SECRET, at=59)  # the key matters

    def test_secret_is_read_as_authenticator_apps_show_it(self) -> None:
        spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
        assert totp(spaced, at=59, digits=8) == "94287082"
        for bad in ("", "not base32 !!", "1189"):
            with pytest.raises(ValueError):
                totp(bad, at=59)


class TestIdentityFile:
    def test_valid_file_loads_static_and_login_identities(self, env) -> None:
        _gateway, _origin, _roots, store, _sessions, _app = env
        identities = store.load("acme")
        assert list(identities) == ["alice", "bob"]
        alice, bob = identities["alice"], identities["bob"]
        assert (alice.kind, alice.role, alice.owner_of) == (
            "login",
            "user",
            ("https://app.acme.test/api/orders/1001",),
        )
        assert alice.login.request.url == LOGIN_URL and alice.login.success.status == 200
        assert (bob.kind, bob.login) == ("static", None)
        assert bob.static_headers == {"Authorization": f"Bearer {STATIC_TOKEN}"}
        assert store.get("acme", "bob") == bob
        with pytest.raises(UnknownIdentity):
            store.get("acme", "mallory")

    def test_no_file_means_no_identities(self, env) -> None:
        _gateway, _origin, _roots, store, _sessions, _app = env
        assert store.load("other") == {} and store.public("other") == []

    def test_public_view_holds_no_secret(self, env) -> None:
        _gateway, _origin, _roots, store, _sessions, _app = env
        public = store.public("acme")
        assert public == [
            {
                "name": "alice",
                "role": "user",
                "owner_of": ["https://app.acme.test/api/orders/1001"],
                "kind": "login",
            },
            {"name": "bob", "role": "admin", "owner_of": [], "kind": "static"},
        ]
        rendered = json.dumps(public)
        for secret in SECRETS:
            assert secret not in rendered and json.dumps(secret)[1:-1] not in rendered
        # The control: the same search does find them in what the operator wrote.
        written = (store.root / "acme" / "identities.json").read_text()
        assert all(json.dumps(secret)[1:-1] in written for secret in SECRETS)

    def test_store_root_defaults_to_the_secrets_env(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.delenv("BUGGY_SECRETS_ROOT", raising=False)
        assert IdentityStore().root == Path("/secrets") and Roots.from_env().secrets == Path(
            "/secrets"
        )
        monkeypatch.setenv("BUGGY_SECRETS_ROOT", str(tmp_path))
        assert IdentityStore().root == tmp_path and Roots.from_env().secrets == tmp_path

    @staticmethod
    def _edit(path: str, value: object, *, delete: bool = False) -> dict:
        """The valid document with one field changed; ``path`` walks keys and indexes."""
        document = copy.deepcopy(_document())
        *parents, last = path.split("/")
        node = document
        for part in parents:
            node = node[int(part)] if part.isdigit() else node[part]
        if delete:
            del node[last]
        else:
            node[int(last) if last.isdigit() else last] = value
        return document

    MALFORMED = (
        ("identities", {"not": "a list"}, False, "identities"),
        ("identities/0/name", None, True, "identities[0].name"),
        ("identities/0/name", "has spaces", False, "identities[0].name"),
        ("identities/1/name", "alice", False, "identities[1].name"),
        ("identities/0/owner_of", "https://app.acme.test/x", False, "identities[0].owner_of"),
        ("identities/0/colour", "blue", False, "identities[0].colour"),
        ("identities/1/static", None, True, "identities[1]"),
        (
            "identities/1/static/headers/Authorization",
            7,
            False,
            "identities[1].static.headers.Authorization",
        ),
        ("identities/1/static/cookies", {"s id": "x"}, False, "identities[1].static.cookies"),
        ("identities/0/login/request", None, True, "identities[0].login.request"),
        ("identities/0/login/request/url", "/rest/login", False, "identities[0].login.request.url"),
        (
            "identities/0/login/request/url",
            "https://app.acme.test/login?pw={password}",
            False,
            "identities[0].login.request.url",
        ),
        (
            "identities/0/login/request/method",
            "DELETE",
            False,
            "identities[0].login.request.method",
        ),
        ("identities/0/login/request/body", {"a": 1}, False, "identities[0].login.request.body"),
        (
            "identities/0/login/credentials/totp_secret",
            None,
            True,
            "identities[0].login.credentials.totp_secret",
        ),
        (
            "identities/0/login/credentials/totp_secret",
            "not base32 !!",
            False,
            "identities[0].login.credentials.totp_secret",
        ),
        (
            "identities/0/login/credentials/password",
            None,
            True,
            "identities[0].login.credentials.password",
        ),
        (
            "identities/0/login/extract/0/from",
            "xpath",
            False,
            "identities[0].login.extract[0].from",
        ),
        ("identities/0/login/extract/0/path", None, True, "identities[0].login.extract[0].path"),
        (
            "identities/0/login/extract/0",
            {"name": "token", "from": "regex", "pattern": "token=(["},
            False,
            "identities[0].login.extract[0].pattern",
        ),
        (
            "identities/0/login/apply/headers/Authorization",
            "Bearer {tokne}",
            False,
            "identities[0].login.apply.headers.Authorization",
        ),
        ("identities/0/login/apply", {}, False, "identities[0].login.apply"),
        ("identities/0/login/success/status", "200", False, "identities[0].login.success.status"),
        (
            "identities/0/login/success/body_contain",
            "authentication",
            False,
            "identities[0].login.success.body_contain",
        ),
    )

    @pytest.mark.parametrize(("path", "value", "delete", "field"), MALFORMED)
    def test_malformed_file_names_the_field(self, env, path, value, delete, field) -> None:
        _gateway, _origin, roots, store, _sessions, _app = env
        assert len(store.load("acme")) == 2  # the unedited document is valid
        _write(roots, self._edit(path, value, delete=delete))
        with pytest.raises(IdentityError) as bad:
            store.load("acme")
        assert bad.value.field == field, str(bad.value)
        assert str(bad.value).startswith(field + ": ")
        for secret in SECRETS:  # an error may be shown to an agent
            assert secret not in str(bad.value)
        with pytest.raises(IdentityError):
            store.public("acme")

    def test_invalid_json_reports_position_not_content(self, env) -> None:
        _gateway, _origin, roots, store, _sessions, _app = env
        _write(roots, json.dumps(_document())[:-40])
        with pytest.raises(IdentityError) as bad:
            store.load("acme")
        assert bad.value.field == "identities.json" and "line 1" in str(bad.value)
        for secret in SECRETS:
            assert secret not in str(bad.value)

    @pytest.mark.parametrize("engagement", ["", "../acme", ".hidden", "a/b"])
    def test_engagement_name_cannot_leave_the_secrets_root(self, env, engagement: str) -> None:
        _gateway, _origin, _roots, store, _sessions, _app = env
        with pytest.raises(IdentityError) as bad:
            store.load(engagement)
        assert bad.value.field == "engagement"


class TestMarkers:
    BOB_MARKER = "Bob Fixture-Admin"

    @staticmethod
    def _with_markers(alice: object, bob: object = None) -> dict:
        document = copy.deepcopy(_document())
        document["identities"][0]["markers"] = alice
        if bob is not None:
            document["identities"][1]["markers"] = bob
        return document

    def test_markers_are_loaded_and_listed_by_name(self, env) -> None:
        _gateway, _origin, roots, store, _sessions, _app = env
        assert store.markers("acme") == {"alice": (), "bob": ()}  # none declared yet
        _write(roots, self._with_markers([EMAIL, "ACC-0042", EMAIL], [self.BOB_MARKER]))
        identities = store.load("acme")
        assert identities["alice"].markers == (EMAIL, "ACC-0042")  # duplicates kept once
        assert store.markers("acme") == {"alice": (EMAIL, "ACC-0042"), "bob": (self.BOB_MARKER,)}
        assert store.markers("other") == {}

    def test_markers_are_not_in_the_public_view(self, env) -> None:
        _gateway, _origin, roots, store, _sessions, _app = env
        _write(roots, self._with_markers([EMAIL, "ACC-0042"], [self.BOB_MARKER]))
        public = store.public("acme")
        assert [set(row) for row in public] == [{"name", "role", "owner_of", "kind"}] * 2
        rendered = json.dumps(public)
        for marker in (EMAIL, "ACC-0042", self.BOB_MARKER):
            assert marker not in rendered
        assert "markers" not in store.load("acme")["alice"].public()

    @pytest.mark.parametrize(
        ("alice", "bob", "field"),
        [
            ("alice@example.test", None, "identities[0].markers"),  # not a list
            ({"email": EMAIL}, None, "identities[0].markers"),
            ([], None, "identities[0].markers"),  # 1-20 strings
            ([f"marker-{i:02d}" for i in range(21)], None, "identities[0].markers"),
            ([EMAIL, ""], None, "identities[0].markers[1]"),
            (["   "], None, "identities[0].markers[0]"),
            (["ab"], None, "identities[0].markers[0]"),  # would match by accident
            ([7], None, "identities[0].markers[0]"),
            (["x" * 201], None, "identities[0].markers[0]"),
            ([EMAIL], ["ACC-9", EMAIL], "identities[1].markers[1]"),  # shared by two accounts
        ],
    )
    def test_malformed_markers_name_the_field(self, env, alice, bob, field) -> None:
        _gateway, _origin, roots, store, _sessions, _app = env
        _write(roots, self._with_markers(alice, bob))
        with pytest.raises(IdentityError) as bad:
            store.load("acme")
        assert bad.value.field == field, str(bad.value)
        if field.endswith("markers[1]") and bob is not None:
            assert "alice" in str(bad.value) and EMAIL not in str(bad.value)

    def test_boundary_lengths_are_accepted(self, env) -> None:
        _gateway, _origin, roots, store, _sessions, _app = env
        markers = ["abc", "y" * 200, *(f"m-{i:02d}" for i in range(18))]
        _write(roots, self._with_markers(markers))
        assert len(store.markers("acme")["alice"]) == 20


class TestLoginFlow:
    def test_login_yields_the_applied_header_and_is_cached(self, env) -> None:
        gateway, origin, roots, _store, sessions, app = env
        headers, cookies = sessions.auth_for("acme", "alice")
        assert headers == {"Authorization": f"Bearer {TOKEN}-1"} and cookies == {}
        # The origin saw the real credentials, JSON-escaped, and the code for "now".
        assert app.login_bodies == [
            {"email": EMAIL, "password": PASSWORD, "otp": totp(TOTP_SECRET, at=NOW)}
        ]

        for _ in range(4):
            assert sessions.auth_for("acme", "alice")[0] == headers
        for _ in range(5):
            assert gateway.send("acme", "GET", ME_URL, identity="alice").status == 200
        assert origin.count("POST", LOGIN_URL) == 1 and origin.count("GET", ME_URL) == 5
        assert all(h["authorization"] == f"Bearer {TOKEN}-1" for m, _u, h, _b in origin.seen[1:])

        # What auth_for returns is a copy: a caller cannot poison the cached session.
        headers["Authorization"] = "Bearer tampered"
        assert sessions.auth_for("acme", "alice")[0] == {"Authorization": f"Bearer {TOKEN}-1"}

    def test_login_is_recorded_as_an_internal_login_without_an_approval(self, env) -> None:
        gateway, origin, roots, _store, sessions, _app = env
        # The engagement holds state-changing requests: the same POST from a caller waits.
        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "POST", LOGIN_URL, body="{}")
        assert held.value.code == "APPROVAL_REQUIRED" and origin.seen == []

        sessions.auth_for("acme", "alice")
        (login,) = gateway.store.list("acme", probe="login")
        assert (login.method, login.url, login.status) == ("POST", LOGIN_URL, 200)
        assert login.approval_id == INTERNAL_LOGIN == "internal_login"
        lines = list(iter_records(roots.audit / "acme" / "captures.jsonl"))
        (line,) = [entry for entry in lines if entry["event"] == "capture"]
        assert line["capture_id"] == login.id and line["approval_id"] == "internal_login"
        assert line["probe"] == "login" and len(line["scope_sha256"]) == 64
        assert verify_ledger(roots.audit / "acme" / "captures.jsonl").ok

    def test_wrong_credentials_give_a_clear_error_and_no_session(self, env) -> None:
        gateway, origin, roots, _store, sessions, _app = env
        document = _document()
        document["identities"][0]["login"]["credentials"]["password"] = "wrong-password-123"
        _write(roots, document)
        with pytest.raises(LoginError) as failed:
            sessions.auth_for("acme", "alice")
        message = str(failed.value)
        assert "'alice'" in message and "status 401" in message and "no session" in message
        assert "wrong-password-123" not in message and EMAIL not in message
        # Nothing was cached: the next use logs in again, and a request is not sent bare.
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "GET", ME_URL, identity="alice")
        assert refused.value.code == "LOGIN_FAILED" and "wrong-password-123" not in str(
            refused.value.to_dict()
        )
        assert origin.count("POST", LOGIN_URL) == 2 and origin.count("GET", ME_URL) == 0

    def test_unmet_success_condition_gives_a_clear_error_and_no_session(self, env) -> None:
        gateway, origin, roots, _store, sessions, app = env
        document = _document()
        document["identities"][0]["login"]["success"] = {"status": 200, "body_contains": "welcome"}
        _write(roots, document)
        with pytest.raises(LoginError) as failed:
            sessions.auth_for("acme", "alice")
        assert "declared success text" in str(failed.value) and "no session" in str(failed.value)
        assert TOKEN not in str(failed.value)  # the origin did issue one; it is not leaked
        assert app.issued == 1
        with pytest.raises(LoginError):
            sessions.auth_for("acme", "alice")
        assert origin.count("POST", LOGIN_URL) == 2  # not cached, so it tried again

        document["identities"][0]["login"]["success"] = {"status": 201}
        _write(roots, document)
        with pytest.raises(LoginError) as wrong_status:
            sessions.auth_for("acme", "alice")
        assert "status 200" in str(wrong_status.value) and "201" in str(wrong_status.value)

        # The control: with the condition the origin does meet, the same flow succeeds.
        document["identities"][0]["login"]["success"] = {"body_contains": "umail"}
        _write(roots, document)
        assert sessions.auth_for("acme", "alice")[0]["Authorization"].startswith(f"Bearer {TOKEN}")

    def test_without_a_declared_status_only_2xx_is_a_login(self, env) -> None:
        _gateway, origin, roots, _store, sessions, _app = env
        document = _document()
        del document["identities"][0]["login"]["success"]
        _write(roots, document)
        origin.routes[("POST", LOGIN_URL)] = (
            302,
            b"/login?error=1",
            [("X-Body", "authentication")],
        )
        with pytest.raises(LoginError) as failed:
            sessions.auth_for("acme", "alice")
        assert "status 302" in str(failed.value)

    def test_unreachable_login_is_an_error_not_a_session(self, env) -> None:
        gateway, origin, _roots, _store, sessions, _app = env

        def down(_headers, _body):
            raise ConnectionRefusedError("connection refused")

        origin.routes[("POST", LOGIN_URL)] = down
        with pytest.raises(LoginError) as failed:
            sessions.auth_for("acme", "alice")
        assert "got no response" in str(failed.value) and "no session" in str(failed.value)
        (attempt,) = gateway.store.list("acme", probe="login")  # the attempt is still recorded
        assert attempt.status is None and "ConnectionRefusedError" in attempt.error

    def test_a_later_401_triggers_exactly_one_relogin(self, env) -> None:
        gateway, origin, _roots, _store, _sessions, app = env
        assert gateway.send("acme", "GET", ME_URL, identity="alice").status == 200
        app.valid.clear()  # the application expires every session

        capture = gateway.send("acme", "GET", ME_URL, identity="alice", note="after expiry")
        assert capture.status == 200 and capture.identity == "alice"
        assert origin.count("POST", LOGIN_URL) == 2
        assert origin.seen[-1][2]["authorization"] == f"Bearer {TOKEN}-2"
        # Both exchanges are evidence: the rejected one is recorded too.
        statuses = [c.status for c in gateway.store.list("acme") if c.url == ME_URL]
        assert sorted(statuses) == [200, 200, 401]

        # The renewed session is the cached one from here on.
        assert gateway.send("acme", "GET", ME_URL, identity="alice").status == 200
        assert origin.count("POST", LOGIN_URL) == 2

    def test_an_endpoint_that_always_answers_401_does_not_loop(self, env) -> None:
        gateway, origin, _roots, _store, _sessions, _app = env
        denied = "https://app.acme.test/api/admin"
        origin.routes[("GET", denied)] = (401, {"error": "admins only"})
        assert gateway.send("acme", "GET", ME_URL, identity="alice").status == 200

        capture = gateway.send("acme", "GET", denied, identity="alice")
        assert capture.status == 401
        assert origin.count("POST", LOGIN_URL) == 2 and origin.count("GET", denied) == 2

    def test_a_401_straight_after_login_is_the_answer_not_a_stale_session(self, env) -> None:
        gateway, origin, _roots, _store, _sessions, _app = env
        denied = "https://app.acme.test/api/admin"
        origin.routes[("GET", denied)] = (401, {"error": "admins only"})
        assert gateway.send("acme", "GET", denied, identity="alice").status == 401
        assert origin.count("POST", LOGIN_URL) == 1 and origin.count("GET", denied) == 1

    def test_a_failed_relogin_leaves_the_401_as_the_answer(self, env) -> None:
        gateway, origin, _roots, _store, _sessions, app = env
        assert gateway.send("acme", "GET", ME_URL, identity="alice").status == 200
        app.valid.clear()
        origin.routes[("POST", LOGIN_URL)] = (503, {"error": "down"})
        assert gateway.send("acme", "GET", ME_URL, identity="alice").status == 401
        assert origin.count("GET", ME_URL) == 2  # not sent a second time without a session
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "GET", ME_URL, identity="alice")
        assert refused.value.code == "LOGIN_FAILED"

    def test_static_identity_needs_no_login_and_is_never_renewed(self, env) -> None:
        gateway, origin, _roots, _store, sessions, _app = env
        assert sessions.auth_for("acme", "bob") == (
            {"Authorization": f"Bearer {STATIC_TOKEN}"},
            {"sid": STATIC_COOKIE},
        )
        capture = gateway.send("acme", "GET", ME_URL, identity="bob")
        assert capture.status == 401 and capture.identity == "bob"  # the app does not know it
        assert origin.count("POST", LOGIN_URL) == 0 and origin.count("GET", ME_URL) == 1
        assert origin.seen[0][2]["authorization"] == f"Bearer {STATIC_TOKEN}"
        assert origin.seen[0][2]["cookie"] == f"sid={STATIC_COOKIE}"

    def test_invalidate_forgets_sessions(self, env) -> None:
        _gateway, origin, _roots, _store, sessions, _app = env
        sessions.auth_for("acme", "alice")
        sessions.invalidate("other")  # another engagement's sessions: not ours
        sessions.invalidate("acme", "bob")
        assert sessions.auth_for("acme", "alice")[0] == {"Authorization": f"Bearer {TOKEN}-1"}
        assert origin.count("POST", LOGIN_URL) == 1
        sessions.invalidate()
        assert sessions.auth_for("acme", "alice")[0] == {"Authorization": f"Bearer {TOKEN}-2"}
        assert origin.count("POST", LOGIN_URL) == 2

    def test_sessions_are_per_engagement(self, env) -> None:
        _gateway, origin, roots, _store, sessions, _app = env
        (roots.control / "beta").mkdir()
        (roots.control / "beta" / "roe.json").write_text(
            (roots.control / "acme" / "roe.json").read_text()
        )
        _write(roots, _document(), engagement="beta")
        first = sessions.auth_for("acme", "alice")
        second = sessions.auth_for("beta", "alice")
        assert first != second and origin.count("POST", LOGIN_URL) == 2
        with pytest.raises(UnknownIdentity):
            sessions.auth_for("gamma", "alice")

    def test_a_redeclared_identity_is_logged_in_again(self, env) -> None:
        _gateway, origin, roots, _store, sessions, _app = env
        sessions.auth_for("acme", "alice")
        document = _document()
        document["identities"][0]["role"] = "auditor"
        _write(roots, document)
        sessions.auth_for("acme", "alice")
        assert origin.count("POST", LOGIN_URL) == 2

    def test_form_login_escapes_credentials_for_the_content_type(self, env) -> None:
        _gateway, origin, roots, _store, sessions, _app = env
        document = _document()
        login = document["identities"][0]["login"]
        login["request"]["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
        login["request"]["body"] = "user={username}&pass={password}&literal={unknown}"
        seen: list[dict] = []

        def form_login(_headers, body):
            seen.append(parse_qs(body.decode(), keep_blank_values=True))
            return 200, {"authentication": {"token": TOKEN}}

        origin.routes[("POST", LOGIN_URL)] = form_login
        _write(roots, document)
        assert sessions.auth_for("acme", "alice")[0] == {"Authorization": f"Bearer {TOKEN}"}
        # One value each: the "&" and "=" inside the password did not split the form.
        assert seen == [{"user": [EMAIL], "pass": [PASSWORD], "literal": ["{unknown}"]}]

    def test_login_outside_the_scope_is_not_sent(self, env) -> None:
        gateway, origin, roots, _store, sessions, _app = env
        document = _document()
        document["identities"][0]["login"]["request"]["url"] = "https://sso.other.test/login"
        _write(roots, document)
        with pytest.raises(GatewayRefusal) as direct:
            sessions.auth_for("acme", "alice")
        assert direct.value.code == "OUT_OF_SCOPE"
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "GET", ME_URL, identity="alice")
        assert refused.value.code == "LOGIN_FAILED" and "OUT_OF_SCOPE" in refused.value.detail
        assert origin.seen == []  # neither the login nor the request left


class TestExtract:
    """Each ``extract`` source, through a real login."""

    VALUE = "sess-0f1e2d3c4b5a6978"

    CASES = (
        (
            {"name": "v", "from": "json", "path": "data.sessions.1.id"},
            (200, {"data": {"sessions": [{"id": "decoy-000000000000"}, {"id": VALUE}]}}),
        ),
        (
            {"name": "v", "from": "cookie", "cookie": "sid"},
            (
                200,
                {"ok": True},
                [
                    ("Set-Cookie", "theme=dark; Path=/"),
                    ("Set-Cookie", f"sid={VALUE}; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
                    ("Set-Cookie", "sidecar=decoy-000000000000; HttpOnly"),
                ],
            ),
        ),
        (
            {"name": "v", "from": "header", "header": "X-CSRF"},
            (200, {"ok": True}, [("x-csrf", VALUE)]),
        ),
        (
            {"name": "v", "from": "regex", "pattern": "token=([A-Za-z0-9._-]+)"},
            (200, f"<a href='/app?token={VALUE}&next=/'>continue</a>"),
        ),
        (
            {"name": "v", "from": "regex", "pattern": "sess-[0-9a-f]{16}"},  # no group: whole match
            (200, f"session {VALUE} opened"),
        ),
    )

    @staticmethod
    def _declare(roots: Roots, extract: dict) -> None:
        document = _document()
        login = document["identities"][0]["login"]
        login["extract"] = [extract]
        login["apply"] = {"headers": {"X-Auth": "{v}"}, "cookies": {"session": "{v}"}}
        login["success"] = {"status": 200}
        _write(roots, document)

    @pytest.mark.parametrize(("extract", "response"), CASES)
    def test_value_is_taken_from_the_declared_source(self, env, extract, response) -> None:
        _gateway, origin, roots, _store, sessions, _app = env
        self._declare(roots, extract)
        origin.routes[("POST", LOGIN_URL)] = response
        assert sessions.auth_for("acme", "alice") == (
            {"X-Auth": self.VALUE},
            {"session": self.VALUE},
        )

    @pytest.mark.parametrize(("extract", "_response"), CASES)
    def test_absent_value_is_an_error_naming_the_extract(self, env, extract, _response) -> None:
        _gateway, origin, roots, _store, sessions, _app = env
        self._declare(roots, extract)
        # A successful-looking response that carries the value nowhere.
        origin.routes[("POST", LOGIN_URL)] = (200, {"data": {"sessions": []}}, [("X-Other", "1")])
        with pytest.raises(LoginError) as failed:
            sessions.auth_for("acme", "alice")
        assert f"{extract['from']} value for extract 'v'" in str(failed.value)
        with pytest.raises(LoginError):
            sessions.auth_for("acme", "alice")
        assert origin.count("POST", LOGIN_URL) == 2  # no half-built session was cached
