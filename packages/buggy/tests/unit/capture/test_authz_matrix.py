"""Authorization matrix: who gets whose data, on a fake origin with three users."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from buggy.capture.authz_matrix import (
    ANONYMOUS,
    PROBE,
    SAME,
    finding_id,
    normalized_endpoint,
    run_matrix,
)
from buggy.capture.gateway import CaptureGateway, Roots

BASE = "https://app.acme.test"
USERS = ("alice", "bob", "carol")
# Built at runtime and shaped like nothing a provider issues.
TOKENS = {name: f"session-of-{name}-" + "0123456789abcdef" for name in USERS}
EMAIL = {name: f"{name}.fixture@acme.test" for name in USERS}
LOGIN_URL = f"{BASE}/session"
PASSWORDS = {"dave": "correct horse battery staple", "erin": "wrong on purpose"}

ORDER = f"{BASE}/api/orders/1001"  # alice's; the server checks the owner
INVOICE = f"{BASE}/api/invoices/2001"  # alice's; any logged-in user can read it
NOTE = f"{BASE}/api/notes/3001"  # alice's; no owner check, and a counter in every response
CATALOG = f"{BASE}/api/catalog"  # the same for everybody, with or without a session
DASHBOARD = f"{BASE}/api/dashboard/alice"  # alice only, different on every request
PROFILE = f"{BASE}/api/profiles/7"  # alice's private object, served to anybody
EXPORT = f"{BASE}/api/export/alice"  # others get another page that leaks alice's address
SUMMARY = f"{BASE}/api/summary/alice"  # others get another page that leaks nothing
MIXED = f"{BASE}/api/mixed/alice"  # others get a page that is half alice's
FLAKY = f"{BASE}/api/flaky/alice"  # others get a 503
MEMBERS = f"{BASE}/api/members/handbook"  # every logged-in user gets the same page
SUBMIT = f"{BASE}/api/orders"  # accepts POST only
BOB_ORDER = f"{BASE}/api/orders/1002"  # bob's; the server checks the owner
DAVE_FILE = f"{BASE}/api/files/dave"  # dave's (a login identity); no owner check


def _document(owner: str, kind: str, number: int) -> dict:
    """A private object: long enough that two different ones are clearly different."""
    return {
        "kind": kind,
        "number": number,
        "owner": owner,
        "email": EMAIL[owner] if owner in EMAIL else f"{owner}.fixture@acme.test",
        "lines": [{"sku": f"{kind}-{number}-{i}", "quantity": i + 1} for i in range(12)],
        "address": f"{number} Example Road, Testville",
    }


class Site:
    """The fake origin of ``test_gateway.Site``, with an application behind it."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], object] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []
        self.calls = 0
        self.sessions: dict[str, str] = {token: name for name, token in TOKENS.items()}
        self.fixed: set[str] = set()

        def owned(owner: str, body: dict, *, checked: bool):
            def route(headers, _body):
                who = self.who(headers)
                if not who:
                    return 401, {"error": "login required"}
                if checked and who != owner:
                    return 403, {"error": "forbidden"}
                return 200, body

            return route

        get = self.routes
        get[("GET", ORDER)] = owned("alice", _document("alice", "order", 1001), checked=True)
        get[("GET", BOB_ORDER)] = owned("bob", _document("bob", "order", 1002), checked=True)
        get[("GET", INVOICE)] = owned("alice", _document("alice", "invoice", 2001), checked=False)
        get[("GET", DAVE_FILE)] = owned("dave", _document("dave", "file", 9), checked=False)
        get[("GET", CATALOG)] = (200, {"products": [f"juice-{i}" for i in range(40)]})
        get[("GET", PROFILE)] = (200, _document("alice", "profile", 7))
        get[("GET", MEMBERS)] = owned("", {"handbook": "rules " * 60}, checked=False)
        get[("GET", NOTE)] = self._note
        get[("GET", DASHBOARD)] = self._dashboard
        get[("GET", EXPORT)] = self._other_page(leak=True)
        get[("GET", SUMMARY)] = self._other_page(leak=False)
        get[("GET", MIXED)] = self._mixed
        get[("GET", FLAKY)] = self._flaky
        get[("GET", SUBMIT)] = (405, {"error": "method not allowed"})
        get[("POST", SUBMIT)] = (201, {"created": True})
        get[("POST", LOGIN_URL)] = self._login
        get[("HEAD", ORDER)] = self._head(checked=True)
        get[("HEAD", INVOICE)] = self._head(checked=False)

    def who(self, headers: dict[str, str]) -> str:
        return self.sessions.get(headers.get("authorization", "").removeprefix("Bearer "), "")

    def _note(self, headers, _body):
        if not self.who(headers):
            return 401, {"error": "login required"}
        return 200, {**_document("alice", "note", 3001), "served": self.calls}

    def _dashboard(self, headers, _body):
        if self.who(headers) != "alice":
            return 403, {"error": "forbidden"}
        # A feed that shares nothing with the one served a moment ago.
        return 200, {"feed": chr(ord("a") + self.calls % 26) * 600}

    def _other_page(self, *, leak: bool):
        def route(headers, _body):
            who = self.who(headers)
            if who == "alice":
                return 200, _document("alice", "export", 4001)
            if not who:
                return 401, {"error": "login required"}
            contact = EMAIL["alice"] if leak else "the account owner"
            return 200, f"<html><p>ZZZZ QQQQ XXXX JJJJ WWWW: write to {contact}</p></html>".encode()

        return route

    def _mixed(self, headers, _body):
        who = self.who(headers)
        if not who:
            return 401, {"error": "login required"}
        if who == "alice":
            return 200, ("A" * 600 + "B" * 400).encode()
        return 200, ("A" * 600 + "Z" * 400).encode()

    def _flaky(self, headers, _body):
        who = self.who(headers)
        if who == "alice":
            return 200, _document("alice", "flaky", 5001)
        return (503, {"error": "try later"}) if who else (401, {"error": "login required"})

    def _head(self, *, checked: bool):
        def route(headers, _body):
            who = self.who(headers)
            if not who:
                return 401, b""
            return (403, b"") if checked and who != "alice" else (200, b"")

        return route

    def _login(self, _headers, body):
        data = json.loads(body)
        if data.get("user") == "dave" and data.get("password") == PASSWORDS["dave"]:
            token = "issued-to-dave-" + "fedcba9876543210"
            self.sessions[token] = "dave"
            return 200, {"token": token}
        return 401, {"error": "bad credentials"}

    def count(self, method: str, url: str) -> int:
        return sum(1 for m, u, _h, _b in self.seen if (m, u) == (method, url))

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data or b""
        self.seen.append((method, url, headers, body))
        self.calls += 1
        route = self.routes.get((method, url), (404, b"not found"))
        status, payload = route(headers, body) if callable(route) else route
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", {}, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, {"Content-Type": "application/json"}
        return response


def _static(name: str, owner_of: list[str] | None = None) -> dict:
    return {
        "name": name,
        "role": "user",
        "owner_of": owner_of or [],
        "static": {"headers": {"Authorization": f"Bearer {TOKENS[name]}"}},
    }


def _login(name: str, owner_of: list[str] | None = None) -> dict:
    return {
        "name": name,
        "owner_of": owner_of or [],
        "login": {
            "request": {
                "method": "POST",
                "url": LOGIN_URL,
                "headers": {"Content-Type": "application/json"},
                "body": '{"user": "{username}", "password": "{password}"}',
            },
            "credentials": {"username": name, "password": PASSWORDS[name]},
            "extract": [{"name": "token", "from": "json", "path": "token"}],
            "apply": {"headers": {"Authorization": "Bearer {token}"}},
            "success": {"status": 200},
        },
    }


def _write_identities(roots: Roots, entries: list[dict]) -> None:
    path = roots.secrets / "acme" / "identities.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"identities": entries}))


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
    _write_identities(
        roots,
        [
            _static("alice", [ORDER, f"{BASE}/api/invoices/*"]),
            _static("bob", [BOB_ORDER]),
            _static("carol"),
        ],
    )
    site = Site()
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    yield gateway, site, roots
    gateway.store.close()


def _run(gateway: CaptureGateway, urls, **kwargs) -> dict:
    kwargs.setdefault("identities", list(USERS))
    return run_matrix(gateway, gateway.sessions, "acme", urls, **kwargs)


def _alice_owns(*urls: str) -> dict[str, str]:
    return dict.fromkeys(urls, "alice")


class TestVerdicts:
    def test_endpoint_that_checks_ownership_is_enforced(self, env) -> None:
        gateway, site, _roots = env
        result = _run(gateway, [ORDER])
        assert result["verdicts"][ORDER]["verdict"] == "enforced"
        assert result["verdicts"][ORDER]["owner"] == "alice"  # from owner_of, an exact URL
        assert result["candidates"] == [] and result["public"] == []
        row = result["matrix"][ORDER]
        assert list(row) == ["alice", "bob", "carol", ANONYMOUS]
        assert [row[who]["status"] for who in row] == [200, 403, 403, 401]
        assert row["alice"]["similarity_to_owner"] == 1.0
        assert row["bob"]["similarity_to_owner"] < 0.5
        # One request per identity, one more for the owner, one without credentials.
        assert result["requests"] == 5 == len(site.seen) and result["truncated"] is False

    def test_endpoint_without_an_ownership_check_is_broken_access(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [INVOICE])
        verdict = result["verdicts"][INVOICE]
        assert verdict["verdict"] == "broken_access" and verdict["owner"] == "alice"
        # The logged-in strangers got it; the request without a session did not.
        assert verdict["exposed_to"] == ["bob", "carol"]
        row = result["matrix"][INVOICE]
        assert row["bob"]["sha256"] == row["alice"]["sha256"] and row[ANONYMOUS]["status"] == 401

        (candidate,) = result["candidates"]
        assert candidate["class"] == "access_control" and candidate["cwe"] == "CWE-639"
        assert candidate["status"] == "candidate" and candidate["source"] == "probe:authz_matrix"
        assert candidate["endpoint"] == INVOICE and candidate["method"] == "GET"
        owner, bob, carol = candidate["assertions"]
        assert (owner["capture_id"], owner["identity"]) == (row["alice"]["capture_id"], "alice")
        assert (bob["capture_id"], bob["identity"]) == (row["bob"]["capture_id"], "bob")
        assert carol["identity"] == "carol"
        assert bob["expect"]["status"] == 200
        assert bob["expect"]["same_as"] == owner["capture_id"] != bob["capture_id"]
        # The cited captures are real exchanges, sent as the identity the assertion names.
        for assertion in candidate["assertions"]:
            capture = gateway.store.get("acme", assertion["capture_id"])
            assert capture.identity == assertion["identity"] and capture.probe == PROBE
            assert capture.method == "GET" and capture.url == INVOICE
            assert json.loads(capture.response_body)["owner"] == "alice"

    def test_fixing_the_endpoint_changes_the_verdict(self, env) -> None:
        # The same URL, judged on what the server does: once the owner check is
        # added, the verdict is no longer broken_access.
        gateway, site, _roots = env
        assert _run(gateway, [INVOICE])["verdicts"][INVOICE]["verdict"] == "broken_access"
        site.routes[("GET", INVOICE)] = site.routes[("GET", ORDER)]
        fixed = _run(gateway, [INVOICE])
        assert fixed["verdicts"][INVOICE]["verdict"] == "enforced" and fixed["candidates"] == []

    def test_public_endpoint_is_public_and_not_a_candidate(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [CATALOG, INVOICE])
        assert result["verdicts"][CATALOG]["verdict"] == "public"
        assert result["verdicts"][CATALOG]["owner"] == ""
        assert result["public"] == [CATALOG]
        assert [c["endpoint"] for c in result["candidates"]] == [INVOICE]
        assert result["matrix"][CATALOG]["bob"]["similarity_to_owner"] is None

    def test_marker_on_a_page_everyone_gets_is_not_called_public(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [CATALOG], markers={CATALOG: ["juice-7"]})
        assert result["verdicts"][CATALOG]["verdict"] == "inconclusive"
        assert result["public"] == [] and result["candidates"] == []

    def test_owner_only_page_with_volatile_content_is_inconclusive(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [DASHBOARD], owners=_alice_owns(DASHBOARD))
        verdict = result["verdicts"][DASHBOARD]
        assert verdict["verdict"] == "inconclusive" and "unstable" in verdict["reason"]
        assert verdict["owner_stability"] < SAME
        assert result["candidates"] == []
        row = result["matrix"][DASHBOARD]
        assert row["alice"]["repeat_capture_id"] not in ("", row["alice"]["capture_id"])

    def test_small_change_between_requests_does_not_hide_the_bug(self, env) -> None:
        # Every response carries a counter, so no two are byte-identical. The page is
        # still stable enough to compare, and the stranger's copy is still alice's.
        gateway, _site, _roots = env
        result = _run(gateway, [NOTE], owners=_alice_owns(NOTE))
        verdict = result["verdicts"][NOTE]
        assert verdict["verdict"] == "broken_access"
        assert SAME <= verdict["owner_stability"] < 1.0
        row = result["matrix"][NOTE]
        assert row["bob"]["sha256"] != row["alice"]["sha256"]
        assert row["bob"]["similarity_to_owner"] >= SAME

    def test_anonymous_access_to_a_private_object_is_broken_access(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [PROFILE], owners=_alice_owns(PROFILE), identities=["alice"])
        verdict = result["verdicts"][PROFILE]
        assert verdict["verdict"] == "broken_access" and verdict["exposed_to"] == [ANONYMOUS]
        (candidate,) = result["candidates"]
        assert candidate["cwe"] == "CWE-862"  # no authentication at all
        owner, attacker = candidate["assertions"]
        assert attacker["identity"] == ""  # sent without credentials
        assert attacker["capture_id"] == result["matrix"][PROFILE][ANONYMOUS]["capture_id"]
        sent = gateway.store.get("acme", attacker["capture_id"])
        assert sent.identity == "" and "Authorization" not in sent.request_headers
        assert attacker["expect"]["same_as"] == owner["capture_id"]

    def test_private_object_is_not_judged_without_the_anonymous_column(self, env) -> None:
        # Negative control for the test above: with nobody but the owner asking,
        # nothing was observed, and nothing may be claimed.
        gateway, _site, _roots = env
        result = _run(
            gateway,
            [PROFILE],
            owners=_alice_owns(PROFILE),
            identities=["alice"],
            include_anonymous=False,
        )
        assert result["verdicts"][PROFILE]["verdict"] == "inconclusive"
        assert result["candidates"] == [] and list(result["matrix"][PROFILE]) == ["alice"]

    def test_owner_marker_in_a_different_looking_response_is_broken_access(self, env) -> None:
        gateway, _site, _roots = env
        owners = _alice_owns(EXPORT, SUMMARY)
        markers = {"alice": [EMAIL["alice"]]}
        result = _run(gateway, [EXPORT, SUMMARY], owners=owners, markers=markers)
        assert result["verdicts"][EXPORT]["verdict"] == "broken_access"
        assert result["verdicts"][EXPORT]["exposed_to"] == ["bob", "carol"]
        row = result["matrix"][EXPORT]
        assert row["bob"]["similarity_to_owner"] < 0.5  # found by the marker, not by likeness
        assert row["bob"]["markers_found"] == [EMAIL["alice"]]
        (candidate,) = result["candidates"]
        owner, bob, _carol = candidate["assertions"]
        assert bob["expect"]["body_contains"] == [EMAIL["alice"]]
        assert bob["expect"]["same_as"] == ""  # the responses are not alike
        assert owner["expect"]["body_contains"] == [EMAIL["alice"]]
        # The page that leaks nothing is not flagged by the same markers...
        assert result["verdicts"][SUMMARY]["verdict"] == "enforced"
        assert result["matrix"][SUMMARY]["bob"]["markers_found"] == []
        # ...and without markers the leaking page looks merely different.
        plain = _run(gateway, [EXPORT], owners=owners)
        assert plain["verdicts"][EXPORT]["verdict"] == "enforced" and plain["candidates"] == []

    def test_marker_of_another_identity_proves_nothing(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(
            gateway, [EXPORT], owners=_alice_owns(EXPORT), markers={"bob": [EMAIL["alice"]]}
        )
        assert result["verdicts"][EXPORT]["verdict"] == "enforced"

    def test_partly_similar_response_is_inconclusive(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [MIXED], owners=_alice_owns(MIXED))
        verdict = result["verdicts"][MIXED]
        assert 0.5 <= result["matrix"][MIXED]["bob"]["similarity_to_owner"] < SAME
        assert verdict["verdict"] == "inconclusive" and result["candidates"] == []

    def test_outage_is_inconclusive_not_enforced(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [FLAKY], owners=_alice_owns(FLAKY))
        assert result["matrix"][FLAKY]["bob"]["status"] == 503
        assert result["verdicts"][FLAKY]["verdict"] == "inconclusive"
        assert "503" in result["verdicts"][FLAKY]["reason"]

    def test_owner_who_cannot_read_the_object_is_inconclusive(self, env) -> None:
        gateway, site, _roots = env
        # The caller is wrong about the owner: bob is refused alice's order.
        result = _run(gateway, [ORDER], owners={ORDER: "bob"})
        verdict = result["verdicts"][ORDER]
        assert verdict["verdict"] == "inconclusive" and verdict["owner"] == "bob"
        assert "403" in verdict["reason"] and result["candidates"] == []
        assert site.count("GET", ORDER) == 4  # a failed owner is not asked a second time

    def test_no_known_owner_is_never_a_candidate(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [MEMBERS, PROFILE])
        members = result["verdicts"][MEMBERS]
        # Every user gets the same page and an anonymous request does not: that may be
        # a shared page or an exposed one, and without an owner it cannot be told.
        assert members["verdict"] == "inconclusive" and members["same_for_all_identities"] is True
        # With no owner declared, the profile is served to everyone alike: public.
        assert result["verdicts"][PROFILE]["verdict"] == "public"
        assert result["candidates"] == []

    def test_head_compares_statuses_but_never_bodies(self, env) -> None:
        gateway, site, _roots = env
        result = _run(gateway, [f"HEAD {ORDER}", {"method": "head", "url": INVOICE}])
        assert result["verdicts"][f"HEAD {ORDER}"]["verdict"] == "enforced"
        # Everyone got 200 and nothing else: there is no body to say whose data it was.
        assert result["verdicts"][f"HEAD {INVOICE}"]["verdict"] == "inconclusive"
        assert result["candidates"] == []
        assert {method for method, _u, _h, _b in site.seen} == {"HEAD"}


class TestOwners:
    def test_owner_of_prefix_pattern_names_the_owner(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [INVOICE, BOB_ORDER])
        assert result["verdicts"][INVOICE]["owner"] == "alice"  # .../api/invoices/*
        assert result["verdicts"][BOB_ORDER]["owner"] == "bob"
        assert result["verdicts"][BOB_ORDER]["verdict"] == "enforced"
        assert list(result["matrix"][BOB_ORDER])[0] == "bob"

    def test_explicit_owner_wins_over_owner_of(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [INVOICE], owners={INVOICE: "carol"})
        verdict = result["verdicts"][INVOICE]
        assert verdict["owner"] == "carol" and verdict["exposed_to"] == ["alice", "bob"]

    def test_exact_owner_of_beats_a_prefix_and_a_tie_is_not_guessed(self, env) -> None:
        gateway, site, roots = env
        _write_identities(
            roots,
            [
                _static("alice", [f"{BASE}/api/*"]),
                _static("bob", [BOB_ORDER, f"{BASE}/api/invoices/*"]),
                _static("carol", [f"{BASE}/api/invoices/*"]),
            ],
        )
        result = _run(gateway, [BOB_ORDER, INVOICE])
        assert result["verdicts"][BOB_ORDER]["owner"] == "bob"
        (skipped,) = result["skipped"]
        assert skipped["url"] == INVOICE and "more than one owner" in skipped["reason"]
        assert INVOICE not in result["matrix"] and site.count("GET", INVOICE) == 0

    def test_owner_outside_the_run_skips_the_url(self, env) -> None:
        gateway, site, _roots = env
        result = _run(gateway, [INVOICE], owners={INVOICE: "alice"}, identities=["bob", "carol"])
        (skipped,) = result["skipped"]
        assert "'alice'" in skipped["reason"] and site.seen == []
        assert result["verdicts"] == {} and result["candidates"] == []


class TestLimits:
    def test_max_requests_truncates(self, env) -> None:
        gateway, site, _roots = env
        owners = _alice_owns(ORDER, INVOICE, NOTE)
        result = _run(gateway, [ORDER, INVOICE, NOTE], owners=owners, max_requests=7)
        assert result["truncated"] is True and result["requests"] == 7 == len(site.seen)
        assert result["verdicts"][ORDER]["verdict"] == "enforced"  # finished before the limit
        # The second row stopped after the owner's two requests: nobody was compared.
        assert list(result["matrix"][INVOICE]) == ["alice"]
        assert result["verdicts"][INVOICE]["verdict"] == "inconclusive"
        assert "max_requests" in result["verdicts"][INVOICE]["reason"]
        assert result["candidates"] == []
        (skipped,) = result["skipped"]
        assert skipped["url"] == NOTE and "max_requests" in skipped["reason"]
        assert NOTE not in result["matrix"] and site.count("GET", NOTE) == 0

    def test_exact_budget_is_not_truncated(self, env) -> None:
        gateway, site, _roots = env
        result = _run(gateway, [INVOICE], max_requests=5)
        assert result["truncated"] is False and result["requests"] == 5 == len(site.seen)
        assert result["verdicts"][INVOICE]["verdict"] == "broken_access"
        nothing = _run(gateway, [INVOICE], max_requests=0)
        assert nothing["truncated"] is True and nothing["requests"] == 0
        assert nothing["matrix"] == {} and len(site.seen) == 5

    def test_post_only_url_is_skipped_with_a_reason(self, env) -> None:
        gateway, site, _roots = env
        result = _run(
            gateway,
            [f"POST {SUBMIT}", {"method": "DELETE", "url": ORDER}, SUBMIT],
            owners=_alice_owns(SUBMIT),
        )
        asked, deleted, refused = result["skipped"]
        # Named as POST or DELETE: never sent, by any method.
        assert (asked["url"], asked["method"]) == (SUBMIT, "POST")
        assert "never sends a request that can change state" in asked["reason"]
        assert deleted["method"] == "DELETE" and site.count("DELETE", ORDER) == 0
        # Given as a plain URL: asked once with GET, and the 405 ends it.
        assert refused["url"] == SUBMIT and "405" in refused["reason"]
        assert gateway.store.get("acme", refused["capture_id"]).status == 405
        assert site.seen[0][:2] == ("GET", SUBMIT) and len(site.seen) == 1
        assert result["matrix"] == {} and result["verdicts"] == {} and result["candidates"] == []

    def test_only_get_is_ever_sent(self, env) -> None:
        gateway, site, roots = env
        urls = [ORDER, INVOICE, NOTE, CATALOG, DASHBOARD, PROFILE, EXPORT, MIXED, FLAKY, SUBMIT]
        _run(gateway, urls, owners=_alice_owns(DASHBOARD, PROFILE, EXPORT, MIXED, FLAKY, NOTE))
        assert {method for method, _u, _h, _b in site.seen} == {"GET"}
        # The engagement requires approval for state changes; none was ever asked for.
        assert not (roots.audit / "acme" / "approvals" / "requests.jsonl").exists()

    def test_out_of_scope_url_is_skipped_and_never_sent(self, env) -> None:
        gateway, site, _roots = env
        result = _run(gateway, ["https://other.example/api/orders/1", INVOICE])
        (skipped,) = result["skipped"]
        assert skipped["reason"].startswith("OUT_OF_SCOPE")
        assert all(url == INVOICE for _m, url, _h, _b in site.seen)
        assert result["verdicts"][INVOICE]["verdict"] == "broken_access"

    def test_unknown_identity_is_reported_and_the_rest_still_run(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [INVOICE], identities=["alice", "mallory", "bob"])
        assert result["skipped_identities"] == {"mallory": "not declared for this engagement"}
        assert result["identities"] == ["alice", "bob"]
        assert result["verdicts"][INVOICE]["exposed_to"] == ["bob"]

    def test_result_is_json_and_holds_no_credential(self, env) -> None:
        gateway, _site, _roots = env
        result = _run(gateway, [ORDER, INVOICE, CATALOG], markers={"alice": [EMAIL["alice"]]})
        dumped = json.dumps(result)
        assert all(token not in dumped for token in TOKENS.values())
        for row in result["matrix"].values():
            for cell in row.values():
                assert {"status", "bytes", "sha256", "capture_id", "similarity_to_owner"} <= set(
                    cell
                )
                detail = gateway.store.get("acme", cell["capture_id"]).detail()
                assert all(token not in json.dumps(detail) for token in TOKENS.values())


class TestLoginIdentities:
    def test_login_is_counted_and_a_failed_login_is_tried_once(self, env) -> None:
        gateway, site, roots = env
        _write_identities(roots, [_login("dave", [DAVE_FILE]), _login("erin"), _static("bob")])
        result = _run(gateway, [DAVE_FILE, INVOICE, CATALOG], identities=["dave", "erin", "bob"])
        # dave logged in once; erin's login failed once and was not repeated per URL.
        assert site.count("POST", LOGIN_URL) == 2
        assert list(result["skipped_identities"]) == ["erin"]
        reason = result["skipped_identities"]["erin"]
        assert "401" in reason and PASSWORDS["erin"] not in json.dumps(result)
        assert result["identities"] == ["dave", "bob"]
        assert result["requests"] == len(site.seen)  # both logins are counted
        assert result["verdicts"][DAVE_FILE]["verdict"] == "broken_access"
        assert result["verdicts"][DAVE_FILE]["exposed_to"] == ["bob"]
        assert "erin" not in result["matrix"][DAVE_FILE]
        # The only non-GET requests are the two declared logins.
        assert [(m, u) for m, u, _h, _b in site.seen if m != "GET"] == [("POST", LOGIN_URL)] * 2


class TestCandidateShape:
    CONTRACT_KEYS = {
        "id",
        "engagement",
        "title",
        "class",
        "cwe",
        "severity",
        "endpoint",
        "method",
        "parameter",
        "source",
        "description",
        "remediation",
        "assertions",
        "status",
        "verification",
        "grade",
        "grade_reasons",
        "created_at",
        "updated_at",
    }
    EXPECT_KEYS = {"status", "body_contains", "body_not_contains", "differs_from", "same_as"}

    def test_candidate_has_the_contract_fields(self, env) -> None:
        gateway, _site, _roots = env
        (candidate,) = _run(gateway, [INVOICE])["candidates"]
        assert set(candidate) == self.CONTRACT_KEYS
        assert candidate["engagement"] == "acme" and candidate["severity"] == "high"
        assert candidate["grade"] is None and candidate["grade_reasons"] == []
        assert candidate["verification"] == {"at": 0.0, "replay_capture_ids": [], "reasons": []}
        assert candidate["title"] == "Broken access control on GET /api/invoices/{id}"
        assert candidate["created_at"] == candidate["updated_at"] > 0
        for assertion in candidate["assertions"]:
            assert set(assertion) == {"capture_id", "identity", "expect"}
            assert set(assertion["expect"]) == self.EXPECT_KEYS

    def test_finding_id_is_stable_across_object_ids(self, env) -> None:
        gateway, _site, _roots = env
        (candidate,) = _run(gateway, [INVOICE])["candidates"]
        assert candidate["id"] == finding_id("acme", "access_control", INVOICE)
        assert candidate["id"].startswith("F-") and len(candidate["id"]) == 14
        same = finding_id("acme", "access_control", f"{BASE}/api/invoices/2002?download=1")
        assert candidate["id"] == same
        assert candidate["id"] != finding_id("other", "access_control", INVOICE)
        assert candidate["id"] != finding_id("acme", "access_control", ORDER)
        assert candidate["id"] != finding_id("acme", "access_control", INVOICE, "id")
        uuid_url = "HTTPS://App.Acme.Test/api/files/123e4567-e89b-12d3-a456-426614174000/raw"
        assert normalized_endpoint(uuid_url) == f"{BASE}/api/files/{{id}}/raw"
        assert normalized_endpoint(f"{BASE}/api/v2/users/alice") == f"{BASE}/api/v2/users/alice"
