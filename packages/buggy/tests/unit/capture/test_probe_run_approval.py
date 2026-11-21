"""One operator approval covers one run of a state-changing probe."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from buggy.capture.gateway import (
    PROBE_RUN_MAX_REQUESTS,
    CaptureGateway,
    GatewayRefusal,
    ProbeGrant,
    Roots,
)
from buggy.capture.probes import run_probe
from buggy.cli.approvals import paths_for, pending, record_decision

BASE = "https://app.acme.test"
ROE = {"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test", "api.acme.test"]}}
ORDER = {
    "url": f"{BASE}/api/orders",
    "method": "POST",
    "body": {"item": "book", "quantity": 1},
    "field": "quantity",
    "headers": {"Authorization": "Bearer test-account"},
}


class _Response:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.headers = SimpleNamespace(items=lambda: [("Content-Type", "application/json")])
        self._body = io.BytesIO(body)

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class Shop:
    """Accepts any quantity, including a negative one."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, bytes]] = []

    def open(self, request, timeout: float = 0) -> _Response:  # noqa: ARG002
        self.seen.append((request.get_method(), request.full_url, request.data or b""))
        quantity = json.loads(request.data or b"{}").get("quantity")
        return _Response(201, json.dumps({"ok": True, "quantity": quantity}).encode())


@pytest.fixture
def env(tmp_path: Path):
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(json.dumps(ROE))
    shop = Shop()
    gateway = CaptureGateway(roots, opener=shop, sleep=lambda _s: None)
    yield SimpleNamespace(gateway=gateway, shop=shop, roots=roots)
    gateway.store.close()


def decide(env, request_id: str, action: str = "allow") -> None:
    _requests, decisions = paths_for(env.roots.control, env.roots.audit, "acme")
    record_decision(decisions, request_id, action, operator="operator")


def run(env, params: dict | None = None) -> dict:
    return run_probe(env.gateway, "acme", "numeric_boundary", params or ORDER)


def test_a_run_is_held_until_the_operator_allows_it(env) -> None:
    held = run(env)
    assert held["status"] == "refused" and held["code"] == "APPROVAL_REQUIRED", held
    assert env.shop.seen == []
    requests_path, decisions_path = paths_for(env.roots.control, env.roots.audit, "acme")
    (request,) = pending(requests_path, decisions_path)
    assert request["request_id"] == held["request_id"] and request["tool_name"] == "probe_run"
    shown = request["tool_args_redacted"]
    assert shown["probe"] == "numeric_boundary" and shown["url"] == ORDER["url"]
    assert shown["max_requests"] == PROBE_RUN_MAX_REQUESTS and shown["what_it_sends"]
    # Header names are shown, never their values.
    assert shown["header_names"] == ["Authorization"]
    assert "test-account" not in json.dumps(request)
    # Asking again does not file a second request.
    assert run(env)["request_id"] == held["request_id"]
    assert len(pending(requests_path, decisions_path)) == 1


def test_an_allowed_run_is_sent_and_recorded_under_the_approval(env) -> None:
    held = run(env)
    decide(env, held["request_id"])
    result = run(env)
    assert result["status"] == "completed" and result["vulnerable"] is True, result
    assert env.shop.seen and all(method == "POST" for method, _url, _body in env.shop.seen)
    captures = [env.gateway.store.get("acme", c) for c in result["evidence_capture_ids"]]
    assert captures and all(c.approval_id == held["request_id"] for c in captures)


def test_one_approval_is_one_run(env) -> None:
    first = run(env)
    decide(env, first["request_id"])
    assert run(env)["status"] == "completed"
    sent = len(env.shop.seen)
    again = run(env)
    assert again["status"] == "refused" and again["code"] == "APPROVAL_REQUIRED", again
    assert again["request_id"] != first["request_id"] and len(env.shop.seen) == sent


def test_an_approval_does_not_carry_to_other_parameters(env) -> None:
    held = run(env)
    decide(env, held["request_id"])
    other = run(env, {**ORDER, "url": f"{BASE}/api/refunds"})
    assert other["code"] == "APPROVAL_REQUIRED" and other["request_id"] != held["request_id"]
    assert env.shop.seen == []


def test_a_denied_run_is_never_sent(env) -> None:
    held = run(env)
    decide(env, held["request_id"], "deny")
    denied = run(env)
    assert denied["status"] == "refused" and denied["code"] == "APPROVAL_DENIED", denied
    assert env.shop.seen == []


def test_out_of_scope_run_files_no_request(env) -> None:
    result = run(env, {**ORDER, "url": "https://other.test/api/orders"})
    assert result["status"] == "refused" and result["code"] == "OUT_OF_SCOPE", result
    requests_path, decisions_path = paths_for(env.roots.control, env.roots.audit, "acme")
    assert pending(requests_path, decisions_path) == []


def test_no_approval_is_asked_where_the_engagement_waives_it(env) -> None:
    (env.roots.control / "acme" / "roe.json").write_text(
        json.dumps({**ROE, "approvals": {"state_changing": "not_required"}})
    )
    assert env.gateway.probe_grant("acme", "numeric_boundary", ORDER) is None
    assert run(env)["status"] == "completed"


class TestGrant:
    def grant(self, env) -> ProbeGrant:
        held = run(env)
        decide(env, held["request_id"])
        grant = env.gateway.probe_grant("acme", "numeric_boundary", ORDER)
        assert grant is not None
        return grant

    def send(self, env, grant, url: str = ORDER["url"], probe: str = "numeric_boundary"):
        return env.gateway.send("acme", "POST", url, body=b"{}", probe=probe, grant=grant)

    def test_covers_its_origin_only(self, env) -> None:
        grant = self.grant(env)
        assert self.send(env, grant).approval_id == grant.request_id
        with pytest.raises(GatewayRefusal) as refused:
            self.send(env, grant, "https://api.acme.test/api/orders")
        assert refused.value.code == "APPROVAL_REQUIRED"

    def test_covers_its_probe_only(self, env) -> None:
        grant = self.grant(env)
        with pytest.raises(GatewayRefusal) as refused:
            self.send(env, grant, probe="mass_assignment")
        assert refused.value.code == "APPROVAL_REQUIRED"

    def test_a_grant_the_gateway_did_not_issue_is_ignored(self, env) -> None:
        forged = ProbeGrant("apr-forged", "acme", "numeric_boundary", BASE)
        with pytest.raises(GatewayRefusal) as refused:
            self.send(env, forged)
        assert refused.value.code == "APPROVAL_REQUIRED" and env.shop.seen == []

    def test_a_run_cannot_send_more_than_its_cap(self, env) -> None:
        grant = self.grant(env)
        grant.remaining = 1
        self.send(env, grant)
        with pytest.raises(GatewayRefusal) as refused:
            self.send(env, grant)
        assert refused.value.code == "APPROVAL_SPENT" and len(env.shop.seen) == 1

    def test_used_approval_is_remembered_across_a_restart(self, env) -> None:
        grant = self.grant(env)
        fresh = CaptureGateway(env.roots, opener=env.shop, sleep=lambda _s: None)
        try:
            with pytest.raises(GatewayRefusal) as refused:
                fresh.probe_grant("acme", "numeric_boundary", ORDER)
            assert refused.value.code == "APPROVAL_REQUIRED"
            assert refused.value.extra["request_id"] != grant.request_id
        finally:
            fresh.store.close()


def test_time_is_recorded_on_the_request(env) -> None:
    before = time.time()
    held = run(env)
    requests_path, decisions_path = paths_for(env.roots.control, env.roots.audit, "acme")
    (request,) = pending(requests_path, decisions_path)
    assert request["created_at"] >= before and request["request_id"] == held["request_id"]


def test_a_get_run_declared_state_changing_is_held_and_the_probe_never_sees_the_flag(env) -> None:
    params = {"url": f"{BASE}/account?password_new=x&Change=Change", "parameter": "password_new"}
    plain = run_probe(env.gateway, "acme", "xss_reflected", params)
    assert plain["status"] == "completed"  # a GET is sent without a hold by default
    sent = len(env.shop.seen)
    held = run_probe(env.gateway, "acme", "xss_reflected", {**params, "state_changing": True})
    assert held["status"] == "refused" and held["code"] == "APPROVAL_REQUIRED", held
    assert len(env.shop.seen) == sent
    decide(env, held["request_id"])
    done = run_probe(env.gateway, "acme", "xss_reflected", {**params, "state_changing": True})
    assert done["status"] == "completed", done
    bad = run_probe(env.gateway, "acme", "xss_reflected", {**params, "state_changing": "yes"})
    assert bad["status"] == "error" and "state_changing" in bad["detail"]
