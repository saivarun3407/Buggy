"""Test accounts on a single-page application: API sign-up and login, then the user walk.

No network: a fake origin shaped like OWASP Juice Shop answers in-process. It
has no HTML form at all; it registers at ``POST /api/Users``, signs in at
``POST /rest/user/login`` (a token and the account's basket id in the JSON),
and serves baskets to any signed-in user (a broken object-level check).
No test writes a realistic credential literal; tokens are built from parts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from buggy.capture import accounts, journey
from buggy.capture.accounts import CAPTCHA, REGISTRATION_REFUSED, provision
from buggy.capture.authz_matrix import infer_owners
from buggy.capture.gateway import CaptureGateway
from buggy.capture.workbench import WORKBENCH_TOOL_NAMES, Workbench

from .test_accounts import BASE, EMAIL_DOMAIN, SEED, Origin, _roe, _roots, _write_roe

USERS = f"{BASE}/api/Users"
LOGIN = f"{BASE}/rest/user/login"
WHOAMI = f"{BASE}/rest/user/whoami"
LOGOUT = f"{BASE}/rest/user/logout"
PRODUCTS = f"{BASE}/api/Products"
BASKET = f"{BASE}/rest/basket/{{id}}"
USER = f"{BASE}/api/Users/{{id}}"

#: What recon stores for such an application: the routes its script names, an
#: API profile, the sign-in surface.
RECORDS: dict[str, list[dict[str, Any]]] = {
    "http_service": [{"value": SEED}],
    "auth_surface": [
        {"value": f"{BASE}/login", "attrs": {"kind": "login"}},
        {"value": LOGIN, "attrs": {"kind": "login"}},
        {"value": LOGOUT, "attrs": {"kind": "logout"}},
    ],
    "api_base": [{"value": f"{BASE}/api"}, {"value": f"{BASE}/rest"}],
    "endpoint": [
        {"value": USERS},
        {"value": LOGIN},
        {"value": WHOAMI},
        {"value": LOGOUT},
        {"value": BASKET},
        {"value": USER},
        {"value": f"{BASE}/main.js"},
    ],
    "api_profile": [
        {"attrs": {"url": PRODUCTS, "status": 200, "auth": "none"}},
        {"attrs": {"url": WHOAMI, "status": 401, "auth": "required"}},
        {"attrs": {"url": f"{BASE}/api/Gone", "status": 404, "auth": "unknown"}},
    ],
}


class Shop:
    """The application: users, tokens and baskets, all in memory."""

    def __init__(self, origin: Origin) -> None:
        self.origin = origin
        self.users: dict[str, dict[str, Any]] = {}  # email -> {"id", "password", "bid"}
        self.tokens: dict[str, str] = {}  # token -> email
        self.registrations: list[dict[str, Any]] = []
        self.next_id = 20
        origin.routes[("GET", SEED)] = (
            200,
            "text/html",
            "<html><body><app-root></app-root><script src='/main.js'></script></body></html>",
        )
        origin.routes[("POST", USERS)] = self.register
        origin.routes[("POST", LOGIN)] = self.login
        origin.routes[("GET", WHOAMI)] = self.whoami
        origin.routes[("GET", USERS)] = self.listing
        origin.routes[("GET", LOGOUT)] = lambda _h, _b: (200, "application/json", {"bye": 1})
        origin.routes[("GET", PRODUCTS)] = (
            200,
            "application/json",
            {"data": [{"id": 1, "name": "apple"}, {"id": 2, "name": "pear"}]},
        )

    def who(self, headers: dict[str, str]) -> str:
        return self.tokens.get(headers.get("authorization", "").removeprefix("Bearer "), "")

    def register(self, _headers, body):
        data = json.loads(body.decode())
        self.registrations.append(data)
        email, password = data.get("email", ""), data.get("password", "")
        if not email or password != data.get("passwordRepeat"):
            return 400, "application/json", {"error": "invalid"}
        uid, bid = self.next_id, self.next_id + 100
        self.next_id += 1
        self.users[email] = {"id": uid, "password": password, "bid": bid}
        self.origin.routes[("GET", f"{BASE}/rest/basket/{bid}")] = self.basket(uid, bid)
        self.origin.routes[("GET", f"{BASE}/api/Users/{uid}")] = self.user(uid)
        user = {"id": uid, "email": email, "role": "customer"}
        return 201, "application/json", {"status": "success", "data": user}

    def login(self, _headers, body):
        data = json.loads(body.decode())
        user = self.users.get(data.get("email", ""))
        if user is None or user["password"] != data.get("password"):
            return 401, "text/plain", "Invalid email or password."
        token = f"tok-{len(self.tokens)}-" + "q" * 8
        self.tokens[token] = data["email"]
        answer = {"token": token, "bid": user["bid"], "umail": data["email"]}
        return 200, "application/json", {"authentication": answer}

    def whoami(self, headers, _body):
        email = self.who(headers)
        if not email:
            return 200, "application/json", {"user": {}}
        return 200, "application/json", {"user": {"id": self.users[email]["id"], "email": email}}

    def listing(self, headers, _body):
        if not self.who(headers):
            return 401, "application/json", {"error": "no"}
        rows = [{"id": u["id"], "email": e} for e, u in self.users.items()]
        return 200, "application/json", {"data": rows}

    def basket(self, uid: int, bid: int):
        def answer(headers, _body):
            # Any signed-in user gets any basket: the object-level check is missing.
            if not self.who(headers):
                return 401, "application/json", {"error": "no"}
            return 200, "application/json", {"data": {"id": bid, "UserId": uid, "Products": []}}

        return answer

    def user(self, uid: int):
        def answer(headers, _body):
            email = self.who(headers)
            if not email or self.users[email]["id"] != uid:
                return 403, "application/json", {"error": "not yours"}
            return 200, "application/json", {"data": {"id": uid, "email": email}}

        return answer


@pytest.fixture
def shop(tmp_path: Path):
    roots = _roots(tmp_path)
    _write_roe(roots, _roe(max_accounts=3))
    origin = Origin()
    gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
    app = Shop(origin)
    yield gateway, origin, roots, app
    gateway.store.close()


def _provision(gateway: CaptureGateway, count: int | None = None) -> dict[str, Any]:
    return provision(
        gateway, "acme", [SEED], api_surface=accounts.api_surface(RECORDS), count=count
    )


# ── finding the API sign-up and login ───────────────────────────────


class TestApiSurface:
    def test_sign_up_and_login_endpoints_come_from_recon(self) -> None:
        surface = accounts.api_surface(RECORDS)
        assert surface["signup"] == [USERS]
        assert LOGIN in surface["login"] and LOGOUT not in surface["login"]
        signups = accounts.api_signup_candidates(surface)
        assert [s.url for s in signups] == [USERS] and signups[0].kind == "json"
        # The HTML login page is not tried with a JSON body; the API login is.
        assert [s.url for s in accounts.api_login_candidates(surface)] == [LOGIN]

    def test_a_register_word_wins_and_at_most_three_are_tried(self) -> None:
        surface = {
            "signup": [
                f"{BASE}/register",  # a page, not an API: last
                f"{BASE}/api/accounts",
                f"{BASE}/api/v1/users",
                f"{BASE}/api/register",
                f"{BASE}/users",  # a listing page, not a sign-up
            ],
            "api_bases": [f"{BASE}/api"],
        }
        urls = [s.url for s in accounts.api_signup_candidates(surface)]
        assert urls == [f"{BASE}/api/register", f"{BASE}/api/accounts", f"{BASE}/api/v1/users"]

    def test_templates_and_logout_are_never_candidates(self) -> None:
        surface = {"signup": [USER, f"{BASE}/api/users/delete"], "login": [LOGOUT]}
        assert accounts.api_signup_candidates(surface) == []
        assert accounts.api_login_candidates(surface) == []

    def test_documented_write_operations_are_kept_with_their_fields(self) -> None:
        records = {
            "api_operation": [
                {
                    "attrs": {
                        "method": "POST",
                        "url": f"{BASE}/api/signup",
                        "request_body_properties": ["email", "password", "role"],
                    }
                },
                {"attrs": {"method": "GET", "url": PRODUCTS, "request_body_properties": []}},
            ]
        }
        operations = accounts.api_surface(records)["operations"]
        assert operations == [
            {
                "method": "POST",
                "url": f"{BASE}/api/signup",
                "body_fields": ["email", "password", "role"],
            }
        ]


# ── creating accounts on the application ────────────────────────────


class TestApiAccounts:
    def test_three_accounts_are_registered_and_signed_in_by_json(self, shop) -> None:
        gateway, _origin, roots, app = shop
        result = _provision(gateway)
        assert result["ok"] is True and result["failed"] == []
        assert result["created"] == ["auto1", "auto2", "auto3"]
        assert result["signup"] == {"kind": "json", "url": USERS}
        assert result["login"] == {"kind": "json", "url": LOGIN}
        assert len(app.users) == 3

        # The body a person's browser would send, with no role or admin field.
        body = app.registrations[0]
        assert body["password"] == body["passwordRepeat"] == body["confirmPassword"]
        assert body["email"].endswith("@" + EMAIL_DOMAIN) and body["username"]
        assert not {k for k in body if k.lower() in ("role", "isadmin", "admin")}

        # Each account is a bearer-token identity that the application accepts.
        assert gateway.send("acme", "GET", WHOAMI, identity="auto2").status == 200
        answer = gateway.send("acme", "GET", USERS, identity="auto1")
        assert answer.status == 200

        # Its own ids are kept for the walk: the user id and the basket id.
        own = accounts.stored_own_ids(gateway, "acme", "auto1")
        email = next(e for e, u in app.users.items() if u["id"] == 20)
        assert {(i["key"], i["value"]) for i in own} == {("id", "20"), ("bid", "120")}
        assert all(i["own"] for i in own)

        # Nothing secret reaches the result.
        blob = json.dumps(result)
        assert email not in blob and "tok-" not in blob
        assert all(u["password"] not in blob for u in app.users.values())
        stored = json.loads((roots.audit / "acme" / "accounts-created.json").read_text())
        assert [a["name"] for a in stored["accounts"]] == ["auto1", "auto2", "auto3"]

    def test_a_second_run_reuses_the_accounts(self, shop) -> None:
        gateway, origin, _roots, app = shop
        _provision(gateway)
        again = _provision(gateway)
        assert sorted(again["reused"]) == ["auto1", "auto2", "auto3"] and again["created"] == []
        assert origin.count("POST", USERS) == 3 and len(app.users) == 3

    def test_an_html_page_or_a_404_is_not_a_sign_up_and_each_is_tried_once(self, shop) -> None:
        gateway, origin, _roots, app = shop
        del origin.routes[("POST", USERS)]
        page = f"{BASE}/register"
        # A single-page application answers every path with its page, even a POST.
        origin.routes[("POST", page)] = (200, "text/html", "<!doctype html><app-root>")
        surface = {"signup": [page, f"{BASE}/api/signup"], "login": [LOGIN]}
        result = provision(gateway, "acme", [SEED], api_surface=surface)
        assert result["ok"] is False and result["created"] == []
        assert {f["reason"] for f in result["failed"]} == {REGISTRATION_REFUSED}
        # One request per endpoint, for the first account; the others are not sent.
        assert origin.count("POST", page) == 1
        assert origin.count("POST", f"{BASE}/api/signup") == 1
        assert app.users == {}

    def test_a_captcha_in_the_answer_stops_with_its_reason(self, shop) -> None:
        gateway, origin, _roots, _app = shop
        origin.routes[("POST", USERS)] = lambda _h, _b: (
            400,
            "application/json",
            {"error": "captcha verification required"},
        )
        result = _provision(gateway)
        assert result["ok"] is False
        assert {f["reason"] for f in result["failed"]} == {CAPTCHA}

    def test_a_documented_role_field_is_never_sent(self, shop) -> None:
        gateway, _origin, _roots, app = shop
        operation = {
            "method": "POST",
            "url": USERS,
            "body_fields": ["email", "password", "passwordRepeat", "role", "isAdmin"],
        }
        surface = {**accounts.api_surface(RECORDS), "operations": [operation]}
        result = provision(gateway, "acme", [SEED], api_surface=surface, count=1)
        assert result["created"] == ["auto1"]
        assert set(app.registrations[0]) == {"email", "password", "passwordRepeat"}


# ── the user walk ───────────────────────────────────────────────────


class TestWalk:
    def test_the_plan_reads_seeds_and_templates_off_recon(self) -> None:
        plan = journey.walk_plan(RECORDS, [SEED])
        # The page first, then what asked for credentials, then the other API GETs.
        assert plan["seeds"][:2] == [SEED, WHOAMI]
        assert {PRODUCTS, USERS} <= set(plan["seeds"])
        # Never a logout; the login is not a page a signed-in person opens.
        assert LOGOUT not in plan["seeds"] and LOGIN not in plan["seeds"]
        assert f"{BASE}/api/Gone" not in plan["seeds"]
        assert f"{BASE}/main.js" not in plan["seeds"]  # not an API endpoint
        assert plan["templates"] == [BASKET, USER]

    def test_the_account_uses_the_api_and_its_own_ids(self, shop) -> None:
        gateway, origin, _roots, app = shop
        _provision(gateway, count=1)
        sent = len(origin.seen)
        plan = journey.walk_plan(RECORDS, [SEED])
        out = journey.walk(
            gateway, "acme", plan["seeds"], identity="auto1", templates=plan["templates"]
        )
        walked = origin.seen[sent:]
        assert walked and {method for method, _u, _h, _b in walked} == {"GET"}
        assert all(url != LOGOUT for _m, url, _h, _b in walked)
        assert all(h.get("authorization", "").startswith("Bearer ") for _m, _u, h, _b in walked)

        own_basket, own_user = f"{BASE}/rest/basket/120", f"{BASE}/api/Users/20"
        filled = {f["url"]: f["status"] for f in out["filled"]}
        assert filled[own_basket] == 200 and filled[own_user] == 200
        assert out["owned"] == [own_user, own_basket]
        assert {own_basket, own_user, WHOAMI} <= set(out["urls"])
        assert WHOAMI in out["own_data"] and USERS in out["own_data"]
        assert out["requested"] <= journey.DEFAULT_MAX_REQUESTS
        assert len(app.users) == 1  # the walk changed nothing

    def test_the_budget_holds(self, shop) -> None:
        gateway, origin, _roots, _app = shop
        _provision(gateway, count=1)
        sent = len(origin.seen)
        plan = journey.walk_plan(RECORDS, [SEED])
        out = journey.walk(
            gateway,
            "acme",
            plan["seeds"],
            identity="auto1",
            templates=plan["templates"],
            max_requests=4,
        )
        assert out["requested"] <= 4 and len(origin.seen) - sent <= 4
        assert out["truncated"] is True

    def test_an_unknown_account_sends_nothing(self, shop) -> None:
        gateway, origin, _roots, _app = shop
        bench = Workbench(gateway, None, lambda name: name)
        try:
            out = bench.user_walk("acme", json.dumps([SEED]), "nobody")
            assert out.get("code") == "UNKNOWN_IDENTITY" and origin.seen == []
            assert bench.user_walk("acme", json.dumps([SEED]), "")["code"] == "BAD_ARGUMENT"
        finally:
            bench.close()

    def test_user_walk_is_for_the_hunt_command_only(self) -> None:
        assert "user_walk" in WORKBENCH_TOOL_NAMES
        from buggy.tools import stack_mcp  # noqa: PLC0415

        assert "user_walk" not in {t.name for t in stack_mcp.ALL_STACK_MCP_TOOLS}


# ── from the walk to the access-control matrix ──────────────────────


def test_two_accounts_swap_their_own_objects_and_the_open_basket_is_found(shop) -> None:
    gateway, _origin, _roots, _app = shop
    _provision(gateway, count=2)
    plan = journey.walk_plan(RECORDS, [SEED])
    bench = Workbench(gateway, None, lambda name: name)
    try:
        reached, owned = {}, {}
        for name in ("auto1", "auto2"):
            out = bench.user_walk(
                "acme", json.dumps(plan["seeds"]), name, json.dumps(plan["templates"])
            )
            assert out["ok"] is True
            reached[name], owned[name] = out["urls"], out["owned"]
        inferred = bench.owners_infer("acme", json.dumps(reached), json.dumps(owned))
        assert inferred["owned"] == {
            f"{BASE}/api/Users/20": "auto1",
            f"{BASE}/api/Users/21": "auto2",
            f"{BASE}/rest/basket/120": "auto1",
            f"{BASE}/rest/basket/121": "auto2",
        }
        urls = sorted(inferred["owned"])
        result = bench.authz_matrix_run(
            "acme",
            json.dumps(urls),
            identities_json=json.dumps(["auto1", "auto2"]),
            owners_json=json.dumps(inferred["owned"]),
            inferred_json=json.dumps([]),
        )
        verdicts = {url: v["verdict"] for url, v in result["verdicts"].items()}
        assert verdicts[f"{BASE}/rest/basket/120"] == "broken_access"
        assert verdicts[f"{BASE}/rest/basket/121"] == "broken_access"
        assert verdicts[f"{BASE}/api/Users/20"] == "enforced"
    finally:
        bench.close()


def test_an_object_reached_with_its_own_id_is_owned_even_when_shared() -> None:
    basket = f"{BASE}/rest/basket/120"
    result = infer_owners(
        {"alice": [basket], "bob": [basket]},
        {"alice": (), "bob": ()},
        owned={"alice": [basket]},
    )
    assert result["owners"] == {basket: "alice"} and result["owned"] == {basket: "alice"}
    # Claimed by two, it is nobody's for sure.
    both = infer_owners({"alice": [basket]}, owned={"alice": [basket], "bob": [basket]})
    assert both["owned"] == {} and both["owners"] == {basket: "alice"}
