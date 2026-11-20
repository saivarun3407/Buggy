"""Capture gateway: what it refuses, what it records, and how approvals gate it."""

from __future__ import annotations

import inspect
import io
import json
import sqlite3
import urllib.error
from pathlib import Path

import pytest

from buggy.capture.canary import Canary
from buggy.capture.gateway import INTERNAL_LOGIN, CaptureGateway, GatewayRefusal, Roots
from buggy.capture.mcp_server import CaptureTools, register_tools
from buggy.capture.probes import REGISTRY, describe, run_probe
from buggy.capture.probes.base import Context, b64url_decode
from buggy.capture.probes.checks import forge_unsigned_jwt
from buggy.capture.store import CaptureStore, request_fingerprint
from buggy.cli import approvals as approvals_cli
from buggy.middleware._audit_sink import iter_records, verify_ledger


class Site:
    """A fake origin: routes ``(method, url)`` to ``(status, body)`` or a callable."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], object] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data or b""
        self.seen.append((method, url, headers, body))
        route = self.routes.get((method, url), (404, b"not found"))
        status, payload = route(headers, body) if callable(route) else route
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
        if status >= 300:
            location = {"Location": payload.decode()} if 300 <= status < 400 else {}
            raise urllib.error.HTTPError(url, status, "x", location, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, {"Content-Type": "application/json"}
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


def _roe(**extra) -> dict:
    return {"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}, **extra}


@pytest.fixture
def env(tmp_path: Path):
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        json.dumps(_roe(approvals={"state_changing": "not_required"}))
    )
    site = Site()
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    yield gateway, site, roots
    gateway.store.close()


def _set_roe(roots: Roots, document: dict) -> None:
    (roots.control / "acme" / "roe.json").write_text(json.dumps(document))


class TestScopeAndRecording:
    def test_in_scope_request_is_sent_and_recorded(self, env) -> None:
        gateway, site, roots = env
        site.routes[("GET", "https://app.acme.test/me")] = (200, {"id": 7})
        capture = gateway.send(
            "acme",
            "get",
            "https://app.acme.test/me",
            headers={"Authorization": "Bearer t"},
            note="who am i",
        )
        assert capture.status == 200 and json.loads(capture.response_body) == {"id": 7}
        assert capture.host == "app.acme.test" and len(capture.scope_digest) == 64
        stored = gateway.store.get("acme", capture.id)
        assert stored.request_headers["Authorization"] == "Bearer t"
        assert stored.detail()["request_headers"]["Authorization"] == "<redacted>"
        (line,) = list(iter_records(roots.audit / "acme" / "captures.jsonl"))
        assert line["event"] == "capture" and line["capture_id"] == capture.id
        assert line["response_sha256"] == capture.response_sha256
        assert verify_ledger(roots.audit / "acme" / "captures.jsonl").ok

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/",
            "https://admin.other.test/x",
            "http://169.254.169.254/latest/meta-data/",
        ],
    )
    def test_out_of_scope_request_is_never_sent(self, env, url: str) -> None:
        gateway, site, roots = env
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "GET", url)
        assert refused.value.code == "OUT_OF_SCOPE" and site.seen == []
        (line,) = list(iter_records(roots.audit / "acme" / "captures.jsonl"))
        assert line["event"] == "capture_refused" and line["url"] == url
        assert gateway.store.list("acme") == []

    @pytest.mark.parametrize(
        ("method", "url", "code"),
        [
            ("TRACE", "https://app.acme.test/", "BAD_METHOD"),
            ("GET", "ftp://app.acme.test/", "BAD_URL"),
            ("GET", "/relative", "BAD_URL"),
            ("GET", "https://user:pw@app.acme.test/", "BAD_URL"),
        ],
    )
    def test_malformed_requests_are_refused(self, env, method, url, code) -> None:
        gateway, site, _roots = env
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", method, url)
        assert refused.value.code == code and site.seen == []

    def test_no_enforced_scope_means_nothing_is_sent(self, env) -> None:
        gateway, site, roots = env
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("ghost", "GET", "https://app.acme.test/")
        assert refused.value.code == "NO_ENFORCED_SCOPE"
        _set_roe(roots, {"machine_enforcement": {"mode": "audit", "in_scope": ["app.acme.test"]}})
        with pytest.raises(GatewayRefusal):
            gateway.send("acme", "GET", "https://app.acme.test/")
        assert site.seen == []

    def test_in_scope_name_resolving_to_an_internal_address_is_refused(
        self, env, monkeypatch
    ) -> None:
        gateway, site, roots = env

        def resolves_to(address: str):
            return lambda *_a, **_k: [(2, 1, 6, "", (address, 0))]

        # The target's DNS (or an attacker who controls it) points the in-scope
        # name at the network the gateway itself sits on.
        for address in ("172.18.0.5", "127.0.0.1", "169.254.169.254", "10.0.0.8"):
            monkeypatch.setattr("buggy.capture.gateway.socket.getaddrinfo", resolves_to(address))
            with pytest.raises(GatewayRefusal) as refused:
                gateway.send("acme", "GET", "https://app.acme.test/")
            assert refused.value.code == "INTERNAL_ADDRESS", address
        assert site.seen == []

        # A public address is fine.
        monkeypatch.setattr(
            "buggy.capture.gateway.socket.getaddrinfo", resolves_to("93.184.216.34")
        )
        site.routes[("GET", "https://app.acme.test/")] = (200, b"ok")
        assert gateway.send("acme", "GET", "https://app.acme.test/").status == 200

        # An internal engagement declares it; a lab lists the address itself.
        monkeypatch.setattr("buggy.capture.gateway.socket.getaddrinfo", resolves_to("10.0.0.8"))
        _set_roe(roots, _roe(network={"allow_private_targets": True}))
        assert gateway.send("acme", "GET", "https://app.acme.test/").status == 200
        doc = _roe()
        doc["machine_enforcement"]["in_scope"].append("10.0.0.0/24")
        _set_roe(roots, doc)
        assert gateway.send("acme", "GET", "https://app.acme.test/").status == 200

    def test_redirects_are_returned_not_followed(self, env) -> None:
        gateway, site, _roots = env
        site.routes[("GET", "https://app.acme.test/go")] = (302, b"https://evil.example/landing")
        capture = gateway.send("acme", "GET", "https://app.acme.test/go")
        assert (
            capture.status == 302
            and capture.response_headers["Location"] == "https://evil.example/landing"
        )
        assert [url for _m, url, _h, _b in site.seen] == ["https://app.acme.test/go"]

    def test_connection_headers_cannot_be_set_by_the_caller(self, env) -> None:
        gateway, site, _roots = env
        site.routes[("GET", "https://app.acme.test/")] = (200, b"ok")
        gateway.send(
            "acme",
            "GET",
            "https://app.acme.test/",
            headers={"Host": "evil.example", "X-Test": "1", "X-Bad": "a\r\nInjected: 1"},
        )
        sent = site.seen[0][2]
        assert sent.get("host", "app.acme.test") != "evil.example" and sent["x-test"] == "1"
        assert "x-bad" not in sent and "injected" not in sent

    def test_rate_limit_comes_from_the_scope(self, env) -> None:
        gateway, site, roots = env
        doc = _roe(approvals={"state_changing": "not_required"})
        doc["machine_enforcement"]["min_inter_request_delay_ms"] = 500
        _set_roe(roots, doc)
        slept: list[float] = []
        gateway._sleep = slept.append  # noqa: SLF001
        site.routes[("GET", "https://app.acme.test/")] = (200, b"ok")
        gateway.send("acme", "GET", "https://app.acme.test/")
        # Freeze the limiter's clock at the first request, so the result does
        # not depend on how long this machine takes between sends.
        (limiter,) = gateway._limiters.values()  # noqa: SLF001
        first = limiter._next - limiter._interval  # noqa: SLF001
        limiter._clock = lambda: first  # noqa: SLF001
        for _ in range(2):
            gateway.send("acme", "GET", "https://app.acme.test/")
        # Slots are 0.5 s apart measured from the first request.
        assert slept == [pytest.approx(0.5), pytest.approx(1.0)]

    def test_replay_resends_from_the_gateway_and_compares(self, env) -> None:
        gateway, site, _roots = env
        state = {"n": 0}

        def route(_headers, _body):
            state["n"] += 1
            return 200, {"stable": True}

        site.routes[("GET", "https://app.acme.test/poc")] = route
        original = gateway.send(
            "acme", "GET", "https://app.acme.test/poc", headers={"Cookie": "s=1"}
        )
        outcome = gateway.replay("acme", original.id)
        assert outcome["reproduced"] and outcome["same_body"] and state["n"] == 2
        assert site.seen[1][2]["cookie"] == "s=1"  # the stored request, credentials included
        assert gateway.store.get("acme", outcome["replay"]["capture_id"]).replay_of == original.id
        with pytest.raises(GatewayRefusal):
            gateway.replay("acme", "cap-unknown")

    def test_verify_binds_a_capture_to_engagement_scope_and_host(self, env) -> None:
        gateway, site, roots = env
        site.routes[("GET", "https://app.acme.test/x")] = (200, b"ok")
        capture = gateway.send("acme", "GET", "https://app.acme.test/x")
        assert gateway.verify("acme", capture.id)["valid"] is True
        assert (
            gateway.verify("acme", capture.id, expect_host="https://app.acme.test/login")["valid"]
            is True
        )
        assert (
            gateway.verify("acme", capture.id, expect_host="https://other.acme.test/")["valid"]
            is False
        )
        assert gateway.verify("acme", "cap-forged")["valid"] is False
        (roots.control / "other").mkdir()
        (roots.control / "other" / "roe.json").write_text(json.dumps(_roe()))
        assert gateway.verify("other", capture.id)["valid"] is False  # another engagement's capture
        _set_roe(roots, {"machine_enforcement": {"mode": "enforce", "in_scope": ["new.acme.test"]}})
        assert gateway.verify("acme", capture.id)["valid"] is False  # no longer in scope


class TestApprovalGate:
    URL = "https://app.acme.test/api/orders/7"

    def test_state_changing_request_waits_for_a_human_by_default(self, env) -> None:
        gateway, site, roots = env
        _set_roe(roots, _roe())  # no waiver
        site.routes[("DELETE", self.URL)] = (204, b"")
        site.routes[("GET", self.URL)] = (200, {"id": 7})
        assert gateway.send("acme", "GET", self.URL).status == 200  # reads are not gated

        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "DELETE", self.URL, note="delete another user's order")
        assert held.value.code == "APPROVAL_REQUIRED"
        request_id = held.value.extra["request_id"]
        assert [m for m, *_ in site.seen] == ["GET"]  # the DELETE did not leave

        requests_file = roots.audit / "acme" / "approvals" / "requests.jsonl"
        (request,) = [json.loads(line) for line in requests_file.read_text().splitlines()]
        assert request["request_id"] == request_id and request["tool_name"] == "http_send"
        assert request["metadata"]["fingerprint"] == request_fingerprint("DELETE", self.URL, b"")

        # Asking again does not file a second request.
        with pytest.raises(GatewayRefusal) as again:
            gateway.send("acme", "DELETE", self.URL)
        assert again.value.extra["request_id"] == request_id
        assert len(requests_file.read_text().splitlines()) == 1

        # The operator approves with the CLI (writes the control root).
        assert (
            approvals_cli.main(
                [
                    "--control-root",
                    str(roots.control),
                    "--audit-root",
                    str(roots.audit),
                    "allow",
                    "acme",
                    request_id,
                ]
            )
            == 0
        )
        capture = gateway.send("acme", "DELETE", self.URL)
        assert capture.status == 204 and capture.approval_id == request_id

    def test_approval_covers_only_the_exact_request(self, env) -> None:
        gateway, site, roots = env
        _set_roe(roots, _roe())
        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "POST", self.URL, body='{"qty": 1}')
        approvals_cli.record_decision(
            roots.control / "acme" / "approvals" / "decisions.jsonl",
            held.value.extra["request_id"],
            "allow",
        )
        site.routes[("POST", self.URL)] = (200, {"ok": True})
        assert gateway.send("acme", "POST", self.URL, body='{"qty": 1}').status == 200
        for method, url, body in (
            ("POST", self.URL, '{"qty": 999}'),
            ("POST", self.URL + "8", '{"qty": 1}'),
            ("PUT", self.URL, '{"qty": 1}'),
        ):
            with pytest.raises(GatewayRefusal) as other:
                gateway.send("acme", method, url, body=body)
            assert other.value.code == "APPROVAL_REQUIRED"

    def test_denied_request_stays_denied(self, env) -> None:
        gateway, site, roots = env
        _set_roe(roots, _roe())
        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "DELETE", self.URL)
        approvals_cli.record_decision(
            roots.control / "acme" / "approvals" / "decisions.jsonl",
            held.value.extra["request_id"],
            "deny",
            note="production data",
        )
        with pytest.raises(GatewayRefusal) as denied:
            gateway.send("acme", "DELETE", self.URL)
        assert (
            denied.value.code == "APPROVAL_DENIED"
            and denied.value.extra["operator_note"] == "production data"
        )
        assert site.seen == []

    def test_an_approval_is_spent_after_a_few_uses(self, env) -> None:
        gateway, site, roots = env
        _set_roe(roots, _roe())
        site.routes[("POST", self.URL)] = (200, b"{}")
        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "POST", self.URL)
        approvals_cli.record_decision(
            roots.control / "acme" / "approvals" / "decisions.jsonl",
            held.value.extra["request_id"],
            "allow",
        )
        for _ in range(3):
            gateway.send("acme", "POST", self.URL)
        with pytest.raises(GatewayRefusal) as spent:
            gateway.send("acme", "POST", self.URL)
        assert (
            spent.value.code == "APPROVAL_REQUIRED"
            and spent.value.extra["request_id"] != held.value.extra["request_id"]
        )

    def test_decisions_in_the_agent_writable_tree_are_ignored(self, env, tmp_path: Path) -> None:
        gateway, site, roots = env
        _set_roe(roots, _roe())
        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "DELETE", self.URL)
        # The agent forges a decision where it can write.
        forged = tmp_path / "workspace" / "acme" / "approvals" / "decisions.jsonl"
        approvals_cli.record_decision(forged, held.value.extra["request_id"], "allow")
        approvals_cli.record_decision(
            roots.audit / "acme" / "approvals" / "decisions.jsonl",
            held.value.extra["request_id"],
            "allow",
        )
        with pytest.raises(GatewayRefusal):
            gateway.send("acme", "DELETE", self.URL)
        assert site.seen == []


class TestProbes:
    def test_registry_covers_the_priority_classes(self) -> None:
        classes = {spec.vuln_class for spec in REGISTRY.values()}
        # Later probes add classes; these six must never go missing.
        assert classes >= {
            "auth_session",
            "access_control",
            "ssrf",
            "business_logic",
            "api",
            "graphql",
        }
        assert {d["probe"] for d in describe()} == set(REGISTRY)

    def test_unsigned_jwt_forgery(self) -> None:
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIiwiZGF0YSI6eyJyb2xlIjoiY3VzdG9tZXIifX0.c2ln"
        forged = forge_unsigned_jwt(token, {"data": {"role": "admin"}})
        header, payload, signature = forged.split(".")
        assert (
            json.loads(b64url_decode(header)) == {"typ": "JWT", "alg": "none"} and signature == ""
        )
        assert json.loads(b64url_decode(payload)) == {"sub": "a", "data": {"role": "admin"}}

    def _jwt_site(self, site: Site, *, accept_unsigned: bool, verify: bool = True) -> str:
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln"

        def route(headers, _body):
            presented = headers.get("authorization", "").removeprefix("Bearer ")
            if presented == token or not verify:
                return 200, {"user": "a"}
            if (
                accept_unsigned
                and presented.endswith(".")
                and json.loads(b64url_decode(presented.split(".")[0]))["alg"] == "none"
            ):
                return 200, {"user": "a"}
            return 401, {"error": "invalid token"}

        site.routes[("GET", "https://app.acme.test/me")] = route
        return token

    def test_jwt_probe_true_false_and_no_verification(self, env) -> None:
        gateway, site, _roots = env
        token = self._jwt_site(site, accept_unsigned=True)
        result = run_probe(
            gateway, "acme", "jwt_alg_none", {"url": "https://app.acme.test/me", "token": token}
        )
        assert result["vulnerable"] is True and len(result["evidence_capture_ids"]) == 3
        token = self._jwt_site(site, accept_unsigned=False)
        assert (
            run_probe(
                gateway, "acme", "jwt_alg_none", {"url": "https://app.acme.test/me", "token": token}
            )["vulnerable"]
            is False
        )
        token = self._jwt_site(site, accept_unsigned=False, verify=False)
        unverified = run_probe(
            gateway, "acme", "jwt_alg_none", {"url": "https://app.acme.test/me", "token": token}
        )
        assert unverified["vulnerable"] is True and "not verified" in unverified["summary"]

    def test_jwt_probe_cannot_tell_without_a_working_token(self, env) -> None:
        gateway, _site, _roots = env
        result = run_probe(
            gateway, "acme", "jwt_alg_none", {"url": "https://app.acme.test/me", "token": "a.b.c"}
        )
        assert result["vulnerable"] is None

    def test_idor_probe(self, env) -> None:
        gateway, site, _roots = env

        def open_object(_headers, _body):
            return 200, {"owner": "alice", "card": "4111"}

        def protected(headers, _body):
            return (
                (200, {"owner": "alice", "card": "4111"})
                if headers.get("authorization") == "Bearer alice"
                else (403, {"error": "forbidden"})
            )

        params = {
            "owner_headers": {"Authorization": "Bearer alice"},
            "attacker_headers": {"Authorization": "Bearer bob"},
        }
        site.routes[("GET", "https://app.acme.test/orders/1")] = protected
        safe = run_probe(
            gateway, "acme", "idor", {"url": "https://app.acme.test/orders/1", **params}
        )
        assert safe["vulnerable"] is False

        def authenticated_only(headers, _body):
            return (
                (200, {"owner": "alice", "card": "4111"})
                if headers.get("authorization")
                else (401, {})
            )

        site.routes[("GET", "https://app.acme.test/orders/2")] = authenticated_only
        leak = run_probe(
            gateway, "acme", "idor", {"url": "https://app.acme.test/orders/2", **params}
        )
        assert leak["vulnerable"] is True and leak["cwe"] == "CWE-639"
        site.routes[("GET", "https://app.acme.test/orders/3")] = open_object
        public = run_probe(
            gateway, "acme", "idor", {"url": "https://app.acme.test/orders/3", **params}
        )
        assert public["vulnerable"] is True and public["cwe"] == "CWE-862"

    def test_boundary_and_mass_assignment_probes(self, env) -> None:
        gateway, site, _roots = env

        def cart(_headers, body):
            data = json.loads(body)
            return (200, {"data": data}) if data["quantity"] != 0 else (400, {"error": "quantity"})

        site.routes[("POST", "https://app.acme.test/cart")] = cart
        result = run_probe(
            gateway,
            "acme",
            "numeric_boundary",
            {
                "url": "https://app.acme.test/cart",
                "body": {"item": 1, "quantity": 1},
                "field": "quantity",
                "values": [-5, 0],
            },
        )
        assert result["vulnerable"] is True
        assert result["details"]["accepted"] == [
            {"value": -5, "status": 200, "echoed_in_response": True}
        ]

        def users(_headers, body):
            data = json.loads(body)
            return 201, {"data": {"email": data["email"], "role": data.get("role", "customer")}}

        site.routes[("POST", "https://app.acme.test/users")] = users
        ma = run_probe(
            gateway,
            "acme",
            "mass_assignment",
            {
                "url": "https://app.acme.test/users",
                "body": {"email": "a@b.c"},
                "extra_fields": {"role": "admin"},
            },
        )
        assert ma["vulnerable"] is True and ma["details"]["reflected_in_response"] == {
            "role": "admin"
        }
        ignored = run_probe(
            gateway,
            "acme",
            "mass_assignment",
            {
                "url": "https://app.acme.test/users",
                "body": {"email": "a@b.c"},
                "extra_fields": {"is_staff": True},
            },
        )
        assert ignored["vulnerable"] is False

    def test_ssrf_probe_needs_a_real_callback(self, env) -> None:
        gateway, site, _roots = env
        params = {"url": "https://app.acme.test/fetch", "body": {"imageUrl": "{{CANARY}}"}}
        assert (
            run_probe(gateway, "acme", "ssrf_canary", params)["vulnerable"] is None
        )  # no listener
        canary = Canary(base_url="http://canary.test")

        def fetches(_headers, body):
            url = json.loads(body)["imageUrl"]
            canary.record(
                url.rsplit("/", 1)[1],
                remote="203.0.113.5",
                method="GET",
                path="/c/x",
                user_agent="node",
            )
            return 200, b"{}"

        site.routes[("POST", "https://app.acme.test/fetch")] = fetches
        hit = run_probe(
            gateway, "acme", "ssrf_canary", {**params, "wait_seconds": 1}, canary=canary
        )
        assert (
            hit["vulnerable"] is True and hit["details"]["callbacks"][0]["remote"] == "203.0.113.5"
        )
        site.routes[("POST", "https://app.acme.test/fetch")] = (200, b"{}")
        assert (
            run_probe(
                gateway, "acme", "ssrf_canary", {**params, "wait_seconds": 0.3}, canary=canary
            )["vulnerable"]
            is False
        )
        missing = run_probe(
            gateway,
            "acme",
            "ssrf_canary",
            {"url": "https://app.acme.test/fetch", "body": "x"},
            canary=canary,
        )
        assert missing["status"] == "error" and "{{CANARY}}" in missing["detail"]

    def test_probe_refusals_are_structured_not_exceptions(self, env) -> None:
        gateway, site, roots = env
        out = run_probe(
            gateway,
            "acme",
            "idor",
            {
                "url": "https://evil.example/o/1",
                "owner_headers": {"A": "1"},
                "attacker_headers": {"A": "2"},
            },
        )
        assert out["status"] == "refused" and out["code"] == "OUT_OF_SCOPE" and site.seen == []
        _set_roe(roots, _roe())
        held = run_probe(
            gateway,
            "acme",
            "mass_assignment",
            {
                "url": "https://app.acme.test/users",
                "body": {"e": 1},
                "extra_fields": {"role": "admin"},
            },
        )
        assert held["code"] == "APPROVAL_REQUIRED" and site.seen == []
        assert run_probe(gateway, "acme", "nope", {})["status"] == "error"
        assert (
            run_probe(gateway, "acme", "idor", {"url": "https://app.acme.test/x"})["status"]
            == "error"
        )

    def test_canary_tokens_are_bound_to_their_engagement(self) -> None:
        canary = Canary(base_url="http://c.test")
        token, url = canary.mint("acme")
        assert url == f"http://c.test/c/{token}"
        assert (
            canary.record(token, remote="1.2.3.4", method="GET", path="/", user_agent="x") is True
        )
        assert (
            canary.record("unknown", remote="1.2.3.4", method="GET", path="/", user_agent="x")
            is False
        )
        assert len(canary.hits("acme", token)) == 1 and canary.hits("other", token) == []


LOGIN_URL = "https://app.acme.test/rest/user/login"
ORDER_URL = "https://app.acme.test/api/orders/7"
ALICE_PASSWORD = "correct-horse-battery-staple"
ALICE_TOKEN = "tok-5a5a5a5a6b6b6b6b7c7c"
BOB_TOKEN = "bob-static-0011223344556677"


def _identities() -> dict:
    return {
        "identities": [
            {
                "name": "alice",
                "role": "user",
                "owner_of": [ORDER_URL],
                "login": {
                    "request": {
                        "method": "POST",
                        "url": LOGIN_URL,
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"email": "alice@acme.test", "password": "{password}"}',
                    },
                    "credentials": {"password": ALICE_PASSWORD},
                    "extract": [{"name": "token", "from": "json", "path": "authentication.token"}],
                    "apply": {
                        "headers": {
                            "Authorization": "Bearer {token}",
                            "X-Session-Token": "{token}",
                        },
                        "cookies": {"sid": "{token}"},
                    },
                    "success": {"status": 200},
                },
            },
            {"name": "bob", "role": "admin", "static": {"headers": {"X-Api-Token": BOB_TOKEN}}},
        ]
    }


@pytest.fixture
def ident_env(tmp_path: Path):
    """Like ``env`` but with declared identities, and approvals REQUIRED (the default)."""
    roots = Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(json.dumps(_roe()))
    (roots.secrets / "acme").mkdir(parents=True)
    (roots.secrets / "acme" / "identities.json").write_text(json.dumps(_identities()))
    site = Site()

    def login(_headers, body):
        if json.loads(body) != {"email": "alice@acme.test", "password": ALICE_PASSWORD}:
            return 401, {"error": "Invalid email or password."}
        return 200, {"authentication": {"token": ALICE_TOKEN}}

    site.routes[("POST", LOGIN_URL)] = login
    site.routes[("GET", ORDER_URL)] = (200, {"id": 7, "owner": "alice"})
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    yield gateway, site, roots
    gateway.store.close()


def _logins(site: Site) -> int:
    return sum(1 for method, url, _h, _b in site.seen if (method, url) == ("POST", LOGIN_URL))


class TestIdentitySessions:
    def test_identity_session_is_attached_and_wins_over_the_callers_headers(
        self, ident_env
    ) -> None:
        gateway, site, roots = ident_env
        capture = gateway.send(
            "acme",
            "GET",
            ORDER_URL,
            headers={
                "authorization": "Bearer attacker-supplied",
                "Cookie": "theme=dark; sid=attacker-supplied",
                "X-Trace": "1",
            },
            identity="alice",
        )
        assert capture.status == 200 and _logins(site) == 1
        sent = site.seen[-1][2]
        assert sent["authorization"] == f"Bearer {ALICE_TOKEN}"
        assert sent["x-session-token"] == ALICE_TOKEN
        assert sent["cookie"] == f"theme=dark; sid={ALICE_TOKEN}"  # the caller's own cookie stays
        assert sent["x-trace"] == "1" and "attacker-supplied" not in json.dumps(sent)

        stored = gateway.store.get("acme", capture.id)
        assert stored.identity == "alice" and stored.summary()["identity"] == "alice"
        lines = list(iter_records(roots.audit / "acme" / "captures.jsonl"))
        assert [(line["probe"], line["identity"]) for line in lines] == [
            ("login", ""),
            ("", "alice"),
        ]
        assert verify_ledger(roots.audit / "acme" / "captures.jsonl").ok

        # The control: without an identity the caller's headers go out as written.
        plain = gateway.send("acme", "GET", ORDER_URL, headers={"Authorization": "Bearer mine"})
        assert site.seen[-1][2]["authorization"] == "Bearer mine"
        assert "cookie" not in site.seen[-1][2] and "x-session-token" not in site.seen[-1][2]
        assert plain.identity == "" and _logins(site) == 1

        # A static identity is attached the same way, with no login.
        gateway.send("acme", "GET", ORDER_URL, identity="bob")
        assert site.seen[-1][2]["x-api-token"] == BOB_TOKEN and _logins(site) == 1

    def test_session_headers_and_cookies_are_redacted_in_detail(self, ident_env) -> None:
        gateway, _site, _roots = ident_env
        capture = gateway.send("acme", "GET", ORDER_URL, identity="alice")
        stored = gateway.store.get("acme", capture.id)
        # The store keeps what was sent (a replay needs it) ...
        assert stored.request_headers["Authorization"] == f"Bearer {ALICE_TOKEN}"
        assert stored.request_headers["Cookie"] == f"sid={ALICE_TOKEN}"
        # ... and shows none of it.
        detail = stored.detail()
        for header in ("Authorization", "Cookie", "X-Session-Token"):
            assert detail["request_headers"][header] == "<redacted>", header
        assert detail["identity"] == "alice" and ALICE_TOKEN not in json.dumps(detail)
        assert ALICE_TOKEN in json.dumps(stored.detail(reveal_credentials=True))

        static = gateway.send("acme", "GET", ORDER_URL, identity="bob").detail()
        assert static["request_headers"]["X-Api-Token"] == "<redacted>"
        assert BOB_TOKEN not in json.dumps(static)

        # The control: the same header name sent by a caller with no identity is the
        # caller's own value and is shown, as before.
        plain = gateway.send(
            "acme", "GET", ORDER_URL, headers={"X-Session-Token": "callers-own-value-1234"}
        )
        assert plain.detail()["request_headers"]["X-Session-Token"] == "callers-own-value-1234"

    def test_a_token_the_target_echoes_back_is_not_shown(self, ident_env) -> None:
        gateway, site, _roots = ident_env
        echo = "https://app.acme.test/debug/echo"

        def reflect(headers, _body):
            return 200, {"authorization": headers.get("authorization"), "kept": "order 7"}

        site.routes[("GET", echo)] = reflect
        detail = gateway.send("acme", "GET", echo, identity="alice").detail()
        assert ALICE_TOKEN not in json.dumps(detail)
        assert json.loads(detail["response_body"]) == {
            "authorization": "<redacted>",
            "kept": "order 7",
        }
        # The control: a caller who supplied the token itself sees the response unchanged.
        own = gateway.send(
            "acme", "GET", echo, headers={"Authorization": f"Bearer {ALICE_TOKEN}"}
        ).detail()
        assert json.loads(own["response_body"])["authorization"] == f"Bearer {ALICE_TOKEN}"

    def test_no_tool_output_carries_the_password_or_the_token(self, ident_env) -> None:
        gateway, _site, _roots = ident_env
        tools = CaptureTools(gateway, None, "acme")
        capture = gateway.send("acme", "GET", ORDER_URL, identity="alice")
        (login,) = gateway.store.list("acme", probe="login")
        assert login.approval_id == INTERNAL_LOGIN and login.redact_bodies is True

        outputs = [
            tools.http_captures("acme"),
            tools.http_captures("acme", probe="login"),
            tools.http_capture("acme", login.id, 40000),
            tools.http_capture("acme", capture.id, 40000),
            tools.capture_verify("acme", login.id),
            tools.http_replay("acme", capture.id),
            tools.http_replay("acme", login.id),
            gateway.identities.public("acme"),
        ]
        rendered = json.dumps(outputs)
        for secret in (ALICE_PASSWORD, ALICE_TOKEN, BOB_TOKEN):
            assert secret not in rendered
        shown = tools.http_capture("acme", login.id)
        assert shown["request_body"] == "<redacted>" and shown["response_body"] == "<redacted>"
        assert shown["status"] == 200 and shown["probe"] == "login"  # the outcome is visible
        # The control: the search finds both in what the gateway itself holds.
        operator_view = json.dumps(login.detail(reveal_credentials=True))
        assert ALICE_PASSWORD in operator_view and ALICE_TOKEN in operator_view

    def test_login_exchange_cannot_be_replayed(self, ident_env) -> None:
        gateway, site, roots = ident_env
        gateway.send("acme", "GET", ORDER_URL, identity="alice")
        (login,) = gateway.store.list("acme", probe="login")
        with pytest.raises(GatewayRefusal) as refused:
            gateway.replay("acme", login.id)
        assert refused.value.code == "LOGIN_NOT_REPLAYABLE" and _logins(site) == 1
        assert CaptureTools(gateway).http_replay("acme", login.id)["status"] == "refused"
        # The password never reached an approval request's body preview either.
        assert not (roots.audit / "acme" / "approvals" / "requests.jsonl").exists()

    def test_replay_is_sent_as_the_same_identity(self, ident_env) -> None:
        gateway, site, _roots = ident_env
        original = gateway.send("acme", "GET", ORDER_URL, identity="alice")
        outcome = gateway.replay("acme", original.id)
        assert outcome["reproduced"] and outcome["replay"]["identity"] == "alice"
        assert site.seen[-1][2]["authorization"] == f"Bearer {ALICE_TOKEN}" and _logins(site) == 1
        replayed = gateway.store.get("acme", outcome["replay"]["capture_id"])
        assert replayed.replay_of == original.id
        assert replayed.detail()["request_headers"]["X-Session-Token"] == "<redacted>"

    @pytest.mark.parametrize("method", ["GET", "DELETE"])
    def test_unknown_identity_is_refused_before_anything_happens(
        self, ident_env, method: str
    ) -> None:
        gateway, site, roots = ident_env
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", method, ORDER_URL, identity="mallory")
        assert refused.value.code == "UNKNOWN_IDENTITY" and "'mallory'" in refused.value.detail
        assert site.seen == [] and gateway.store.list("acme") == []
        assert not (roots.audit / "acme" / "approvals" / "requests.jsonl").exists()
        # An engagement with no identities file knows no identity at all.
        (roots.control / "bare").mkdir()
        (roots.control / "bare" / "roe.json").write_text(json.dumps(_roe()))
        with pytest.raises(GatewayRefusal) as bare:
            gateway.send("bare", "GET", ORDER_URL, identity="alice")
        assert bare.value.code == "UNKNOWN_IDENTITY" and site.seen == []
        # The control: the declared name on the same request is not refused this way.
        if method == "GET":
            assert gateway.send("acme", method, ORDER_URL, identity="alice").status == 200

    def test_malformed_identities_file_refuses_and_names_the_field(self, ident_env) -> None:
        gateway, site, roots = ident_env
        document = _identities()
        document["identities"][0]["login"]["request"]["url"] = "not-a-url"
        (roots.secrets / "acme" / "identities.json").write_text(json.dumps(document))
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "GET", ORDER_URL, identity="bob")
        assert refused.value.code == "BAD_IDENTITIES"
        assert "identities[0].login.request.url" in refused.value.detail
        assert ALICE_PASSWORD not in refused.value.detail and site.seen == []
        # Requests that name no identity do not depend on the file.
        assert gateway.send("acme", "GET", ORDER_URL).status == 200


class TestInternalLoginIsNotACallerOption:
    def test_no_agent_facing_surface_takes_an_internal_argument(self, ident_env) -> None:
        gateway, _site, _roots = ident_env
        # The control: the parameter exists on the gateway, so the search below can find it.
        assert "internal" in inspect.signature(CaptureGateway.send).parameters

        assert "internal" not in inspect.signature(CaptureTools.http_send).parameters
        surfaces = [Context.send]
        surfaces += [
            member
            for name, member in inspect.getmembers(CaptureTools, inspect.isfunction)
            if not name.startswith("_")
        ]

        class Collector:
            def __init__(self) -> None:
                self.registered: list = []

            def tool(self):
                return lambda fn: self.registered.append(fn) or fn

        mcp = Collector()
        register_tools(mcp, CaptureTools(gateway, None, "acme"))
        assert {fn.__name__ for fn in mcp.registered} >= {"http_send", "http_replay", "probe_run"}
        surfaces += mcp.registered
        assert len(surfaces) >= 15
        for surface in surfaces:
            parameters = inspect.signature(surface).parameters
            assert "internal" not in parameters, surface
            assert not any(  # nothing that could forward an arbitrary keyword either
                p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()
            ), surface

    def test_state_changing_request_is_still_held_whoever_sends_it(self, ident_env) -> None:
        gateway, site, roots = ident_env
        site.routes[("DELETE", ORDER_URL)] = (204, b"")
        tools = CaptureTools(gateway, None, "acme")

        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "DELETE", ORDER_URL, identity="alice")
        assert held.value.code == "APPROVAL_REQUIRED"
        # Smuggling the word in through the arguments a tool does take changes nothing.
        via_tool = tools.http_send(
            "acme", "DELETE", ORDER_URL, headers_json='{"internal": "true", "X-Internal": "1"}'
        )
        assert via_tool["code"] == "APPROVAL_REQUIRED"
        assert via_tool["request_id"] == held.value.extra["request_id"]
        probe = tools.probe_run(
            "acme",
            "mass_assignment",
            json.dumps(
                {
                    "url": "https://app.acme.test/users",
                    "body": {"e": 1},
                    "extra_fields": {"role": "admin"},
                    "internal": True,
                }
            ),
        )
        assert probe["code"] == "APPROVAL_REQUIRED"
        assert site.seen == []  # nothing left, not even alice's login

        approvals_cli.record_decision(
            roots.control / "acme" / "approvals" / "decisions.jsonl",
            held.value.extra["request_id"],
            "allow",
        )
        capture = gateway.send("acme", "DELETE", ORDER_URL, identity="alice")
        assert capture.status == 204 and capture.approval_id == held.value.extra["request_id"]
        assert [m for m, *_ in site.seen] == ["POST", "DELETE"]  # login, then the approved request

    def test_internal_waives_approval_for_a_declared_login_and_nothing_else(
        self, ident_env, monkeypatch
    ) -> None:
        gateway, site, roots = ident_env
        site.routes[("DELETE", ORDER_URL)] = (204, b"")
        site.routes[("PUT", LOGIN_URL)] = (200, b"{}")
        (roots.control / "bare").mkdir()
        (roots.control / "bare" / "roe.json").write_text(json.dumps(_roe()))
        body = json.dumps({"email": "alice@acme.test", "password": ALICE_PASSWORD})

        not_logins = [
            ("acme", "DELETE", ORDER_URL, True),  # not a login at all
            ("acme", "POST", ORDER_URL, True),
            ("acme", "PUT", LOGIN_URL, True),  # the login URL, another method
            ("acme", "POST", LOGIN_URL + "?next=/admin", True),  # another URL
            ("bare", "POST", LOGIN_URL, True),  # declared, but for a different engagement
            ("acme", "POST", LOGIN_URL, "true"),  # not the flag, just something truthy
            ("acme", "POST", LOGIN_URL, 1),
        ]
        for engagement, method, url, flag in not_logins:
            with pytest.raises(GatewayRefusal) as refused:
                gateway.send(engagement, method, url, body=body, internal=flag)
            assert refused.value.code == "NOT_A_DECLARED_LOGIN", (engagement, method, url, flag)
        with pytest.raises(GatewayRefusal) as both:
            gateway.send("acme", "POST", LOGIN_URL, body=body, internal=True, identity="alice")
        assert both.value.code == "BAD_ARGUMENT"
        assert site.seen == [] and gateway.store.list("acme") == []
        refusals = [
            line["reason"]
            for line in iter_records(roots.audit / "acme" / "captures.jsonl")
            if line["event"] == "capture_refused"
        ]
        assert refusals == ["NOT_A_DECLARED_LOGIN"] * 6

        # Scope and the internal-address block are not waived for the declared login.
        monkeypatch.setattr(
            "buggy.capture.gateway.socket.getaddrinfo",
            lambda *_a, **_k: [(2, 1, 6, "", ("10.0.0.8", 0))],
        )
        with pytest.raises(GatewayRefusal) as internal_address:
            gateway.send("acme", "POST", LOGIN_URL, body=body, internal=True)
        assert internal_address.value.code == "INTERNAL_ADDRESS" and site.seen == []
        monkeypatch.undo()

        # The controls: the declared login is held without the flag and sent with it.
        with pytest.raises(GatewayRefusal) as held:
            gateway.send("acme", "POST", LOGIN_URL, body=body)
        assert held.value.code == "APPROVAL_REQUIRED" and site.seen == []
        capture = gateway.send("acme", "POST", LOGIN_URL, body=body, internal=True)
        assert capture.status == 200 and capture.approval_id == INTERNAL_LOGIN
        assert [m for m, *_ in site.seen] == ["POST"]

    def test_internal_login_obeys_the_rate_limit(self, ident_env) -> None:
        gateway, _site, roots = ident_env
        document = _roe()
        document["machine_enforcement"]["min_inter_request_delay_ms"] = 500
        _set_roe(roots, document)
        slept: list[float] = []
        gateway._sleep = slept.append  # noqa: SLF001
        gateway.send("acme", "GET", ORDER_URL, identity="alice")  # login, then the request
        assert len(slept) == 1 and 0.4 < slept[0] <= 0.5


_FIRST_RELEASE_SCHEMA = """
CREATE TABLE captures (
    id TEXT PRIMARY KEY, engagement TEXT NOT NULL, created_at REAL NOT NULL,
    method TEXT NOT NULL, url TEXT NOT NULL, host TEXT NOT NULL,
    request_headers TEXT NOT NULL, request_body BLOB, request_sha256 TEXT NOT NULL,
    status INTEGER, response_headers TEXT NOT NULL DEFAULT '{}', response_body BLOB,
    response_sha256 TEXT NOT NULL DEFAULT '', response_bytes INTEGER NOT NULL DEFAULT 0,
    elapsed_ms REAL NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '', probe TEXT NOT NULL DEFAULT '',
    replay_of TEXT NOT NULL DEFAULT '', approval_id TEXT NOT NULL DEFAULT '',
    scope_digest TEXT NOT NULL DEFAULT ''
);
"""


class TestIdentityColumnMigration:
    @staticmethod
    def _old_store(path: Path) -> None:
        db = sqlite3.connect(path)
        db.executescript(_FIRST_RELEASE_SCHEMA)
        db.execute(
            "INSERT INTO captures (id, engagement, created_at, method, url, host, "
            "request_headers, request_body, request_sha256, status) "
            "VALUES ('cap-old', 'acme', 1.0, 'GET', 'https://app.acme.test/', 'app.acme.test', "
            "?, x'', 'abc', 200)",
            (json.dumps({"Authorization": "Bearer old"}),),
        )
        db.commit()
        db.close()

    @staticmethod
    def _columns(path: Path) -> set[str]:
        db = sqlite3.connect(path)
        try:
            return {row[1] for row in db.execute("PRAGMA table_info(captures)")}
        finally:
            db.close()

    def test_old_store_gains_the_column_and_keeps_its_rows(self, tmp_path: Path) -> None:
        path = tmp_path / "captures.sqlite3"
        self._old_store(path)
        assert "identity" not in self._columns(path)

        store = CaptureStore(path)
        assert {"identity", "redaction"} <= self._columns(path)
        old = store.get("acme", "cap-old")
        assert (old.identity, old.redact_headers, old.redact_bodies) == ("", (), False)
        assert old.detail()["request_headers"]["Authorization"] == "<redacted>"
        new = store.add(
            engagement="acme",
            method="GET",
            url="https://app.acme.test/",
            host="app.acme.test",
            request_headers={"X-Session-Token": "abcdefgh12345678"},
            request_body=b"",
            status=200,
            response_headers={},
            response_body=b"hello abcdefgh12345678",
            elapsed_ms=1.0,
            identity="alice",
            redact_headers=["X-Session-Token"],
        )
        store.close()

        reopened = CaptureStore(path)  # the migration runs once; a second open is a no-op
        again = reopened.get("acme", new.id)
        assert (again.identity, again.redact_headers) == ("alice", ("x-session-token",))
        assert again.detail()["request_headers"]["X-Session-Token"] == "<redacted>"
        assert again.detail()["response_body"] == "hello <redacted>"
        assert {c.id for c in reopened.list("acme")} == {"cap-old", new.id}
        reopened.close()

    def test_read_only_handle_reads_an_old_store_without_migrating(self, tmp_path: Path) -> None:
        path = tmp_path / "captures.sqlite3"
        self._old_store(path)
        store = CaptureStore(path, read_only=True)
        assert store.get("acme", "cap-old").identity == ""
        store.close()
        assert "identity" not in self._columns(path)
