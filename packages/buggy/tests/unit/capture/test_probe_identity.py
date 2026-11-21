"""Probes run signed in as a declared test account (``identity`` in the probe's params)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.mcp_server import CaptureTools
from buggy.capture.probes import REGISTRY, describe, run_probe
from buggy.capture.workbench import Workbench
from buggy.cli.approvals import paths_for, pending, record_decision
from buggy.findings import candidates

from .test_gateway import Site

BASE = "https://app.acme.test"
PAGE = f"{BASE}/account"
ORDERS = f"{BASE}/api/orders"
GRAPHQL = f"{BASE}/graphql"
USERS = ("alice", "bob")
# Built at runtime and shaped like nothing a provider issues.
TOKENS = {name: f"session-of-{name}-" + "0123456789abcdef" for name in USERS}
SCOPE = {"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}}
NOT_REQUIRED = {**SCOPE, "approvals": {"state_changing": "not_required"}}
BOUNDARY = {
    "url": ORDERS,
    "method": "POST",
    "body": {"item": "book", "quantity": 1},
    "field": "quantity",
}


def _auth(name: str) -> str:
    return f"Bearer {TOKENS[name]}"


def _order(headers: dict[str, str], body: bytes):
    if not headers.get("authorization"):
        return 401, {"error": "login required"}
    return 201, {"ok": True, "quantity": json.loads(body or b"{}").get("quantity")}


def _make(tmp_path: Path, roe: dict) -> SimpleNamespace:
    roots = Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(json.dumps(roe))
    folder = roots.secrets / "acme"
    folder.mkdir(parents=True)
    (folder / "identities.json").write_text(
        json.dumps(
            {
                "identities": [
                    {"name": name, "static": {"headers": {"Authorization": _auth(name)}}}
                    for name in USERS
                ]
            }
        )
    )
    site = Site()
    site.routes[("GET", PAGE)] = (200, {"page": "account"})
    site.routes[("POST", ORDERS)] = _order
    site.routes[("POST", GRAPHQL)] = (200, {"data": {"me": {"email": "x@acme.test"}}})
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    return SimpleNamespace(gateway=gateway, site=site, roots=roots)


@pytest.fixture
def env(tmp_path: Path):
    made = _make(tmp_path, NOT_REQUIRED)
    yield made
    made.gateway.store.close()


@pytest.fixture
def held(tmp_path: Path):
    """An engagement that requires approval for state-changing runs."""
    made = _make(tmp_path, SCOPE)
    yield made
    made.gateway.store.close()


def _auth_headers(site: Site) -> list[str]:
    return [headers.get("authorization", "") for _m, _u, headers, _b in site.seen]


class TestARunAsAnIdentity:
    def test_every_request_carries_the_accounts_session_and_the_result_names_it(self, env):
        result = run_probe(env.gateway, "acme", "cors", {"url": PAGE, "identity": "alice"})
        assert result["status"] == "completed" and result["identity"] == "alice", result
        assert env.site.seen and set(_auth_headers(env.site)) == {_auth("alice")}
        for capture_id in result["evidence_capture_ids"]:
            capture = env.gateway.store.get("acme", capture_id)
            assert capture is not None and capture.identity == "alice"
            # The session is recorded but never shown.
            assert TOKENS["alice"] not in json.dumps(capture.detail())
        assert TOKENS["alice"] not in json.dumps(result)

    def test_without_identity_nothing_changes(self, env):
        result = run_probe(env.gateway, "acme", "cors", {"url": PAGE})
        assert result["status"] == "completed" and "identity" not in result
        assert set(_auth_headers(env.site)) == {""}
        for capture_id in result["evidence_capture_ids"]:
            capture = env.gateway.store.get("acme", capture_id)
            assert capture is not None and capture.identity == ""

    def test_the_callers_params_are_not_changed(self, env):
        params = {"url": PAGE, "identity": "alice"}
        run_probe(env.gateway, "acme", "cors", params)
        assert params == {"url": PAGE, "identity": "alice"}

    def test_an_unknown_identity_is_refused_and_nothing_is_sent(self, env):
        result = run_probe(env.gateway, "acme", "cors", {"url": PAGE, "identity": "mallory"})
        assert result["status"] == "refused" and result["code"] == "UNKNOWN_IDENTITY", result
        assert env.site.seen == []

    def test_an_unknown_identity_files_no_approval_request(self, held):
        params = {**BOUNDARY, "identity": "mallory"}
        result = run_probe(held.gateway, "acme", "numeric_boundary", params)
        assert result["code"] == "UNKNOWN_IDENTITY" and held.site.seen == []
        requests_path, decisions_path = paths_for(held.roots.control, held.roots.audit, "acme")
        assert pending(requests_path, decisions_path) == []

    @pytest.mark.parametrize("value", [7, ["alice"], {"name": "alice"}, "   "])
    def test_an_identity_that_is_not_a_name_is_an_input_error(self, env, value):
        result = run_probe(env.gateway, "acme", "cors", {"url": PAGE, "identity": value})
        assert result["status"] == "error" and "identity" in result["detail"]
        assert env.site.seen == []

    @pytest.mark.parametrize(
        ("probe", "params"),
        [
            (
                "idor",
                {
                    "url": PAGE,
                    "owner_headers": {"Authorization": "Bearer owner"},
                    "attacker_headers": {"Authorization": "Bearer other"},
                },
            ),
            ("jwt_alg_none", {"url": PAGE, "token": "a.b.c"}),
        ],
    )
    def test_probes_that_compare_credentials_themselves_refuse_identity(self, env, probe, params):
        result = run_probe(env.gateway, "acme", probe, {**params, "identity": "alice"})
        assert result["status"] == "error" and "does not accept identity" in result["detail"]
        assert env.site.seen == []
        assert REGISTRY[probe].accepts_identity is False

    def test_a_deliberate_request_without_credentials_does_not_carry_the_identity(self, env):
        params = {"url": GRAPHQL, "unauthenticated_query": "{ me { email } }", "identity": "bob"}
        result = run_probe(env.gateway, "acme", "graphql_checks", params)
        assert result["status"] == "completed", result
        *signed_in, anonymous = _auth_headers(env.site)
        assert signed_in and set(signed_in) == {_auth("bob")}
        assert anonymous == ""

    def test_describe_says_which_probes_accept_identity(self, env):
        rows = {row["probe"]: row for row in describe()}
        assert rows["idor"]["accepts_identity"] is False
        assert rows["sqli"]["accepts_identity"] is True
        listed = CaptureTools(env.gateway, None, "acme").probe_list()
        assert "identity" in listed["identity"]


class TestApprovalNamesTheIdentity:
    def test_an_approval_for_alice_does_not_cover_the_same_run_as_bob(self, held):
        requests_path, decisions_path = paths_for(held.roots.control, held.roots.audit, "acme")
        as_alice = {**BOUNDARY, "identity": "alice"}
        first = run_probe(held.gateway, "acme", "numeric_boundary", as_alice)
        assert first["code"] == "APPROVAL_REQUIRED" and first["identity"] == "alice"
        (request,) = pending(requests_path, decisions_path)
        assert request["tool_args_redacted"]["identity"] == "alice"
        record_decision(decisions_path, first["request_id"], "allow", operator="operator")

        as_bob = run_probe(
            held.gateway, "acme", "numeric_boundary", {**BOUNDARY, "identity": "bob"}
        )
        assert as_bob["code"] == "APPROVAL_REQUIRED", as_bob
        assert as_bob["request_id"] != first["request_id"]
        assert held.site.seen == []
        # Nor does it cover the run without an identity.
        anonymous = run_probe(held.gateway, "acme", "numeric_boundary", BOUNDARY)
        assert anonymous["request_id"] not in (first["request_id"], as_bob["request_id"])
        assert held.site.seen == []

        allowed = run_probe(held.gateway, "acme", "numeric_boundary", as_alice)
        assert allowed["status"] == "completed" and allowed["vulnerable"] is True, allowed
        assert set(_auth_headers(held.site)) == {_auth("alice")}


class TestTheQueueAndTheVerifierKeepTheIdentity:
    def test_assertions_built_from_a_run_carry_its_identity(self):
        result = {
            "probe": "numeric_boundary",
            "class": "business_logic",
            "cwe": "CWE-20",
            "vulnerable": True,
            "summary": "accepted",
            "identity": "alice",
            "evidence_capture_ids": ["cap-1"],
            "details": {"tested": [-1], "accepted": [{"value": -1, "status": 201}]},
        }
        candidate = candidates.from_probe(result, "acme", ORDERS)
        assert candidate is not None and candidate["assertions"]
        assert {a["identity"] for a in candidate["assertions"]} == {"alice"}
        plain = candidates.from_probe({**result, "identity": ""}, "acme", ORDERS)
        assert plain is not None and {a["identity"] for a in plain["assertions"]} == {""}

    def test_a_positive_run_is_queued_and_re_proved_as_the_same_account(self, env):
        tools = CaptureTools(env.gateway, None, "acme")
        bench = Workbench(env.gateway, None, tools._engagement)  # noqa: SLF001
        tools.workbench = bench
        try:
            params = {**BOUNDARY, "values": [-1], "identity": "alice"}
            result = tools.probe_run("acme", "numeric_boundary", json.dumps(params))
            assert result["vulnerable"] is True and result["identity"] == "alice", result
            finding_id = result["finding_id"]
            finding = bench.finding_get("acme", finding_id)["finding"]
            assert finding["assertions"]
            assert {a["identity"] for a in finding["assertions"]} == {"alice"}
            recorded = bench.probe_runs.get("acme", finding_id)
            assert recorded is not None and recorded[2]["identity"] == "alice"

            sent = len(env.site.seen)
            outcome = bench.finding_verify("acme", finding_id)
            assert outcome["finding"]["status"] == "exploit_verified", outcome
            assert outcome["verification"]["assertions"][0]["identity"] == "alice"
            rerun = env.site.seen[sent:]
            assert rerun and {h.get("authorization") for _m, _u, h, _b in rerun} == {_auth("alice")}
        finally:
            bench.close()
