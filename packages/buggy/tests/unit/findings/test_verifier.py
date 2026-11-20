"""The verifier re-proves a claim through a real ``CaptureGateway`` over a fake origin.

Every "this is verified" case has a control showing the same shape of claim is
NOT verified when the target does not behave that way.
"""

from __future__ import annotations

import io
import json
import urllib.error
from dataclasses import replace
from pathlib import Path

import pytest

from buggy.capture.gateway import CaptureGateway, Roots
from buggy.cli import approvals as approvals_cli
from buggy.findings.model import Assertion, Expect, Finding, finding_id, validate
from buggy.findings.service import FindingService
from buggy.findings.store import FindingStore
from buggy.findings.verifier import (
    NEEDS_APPROVED_REPLAY,
    NO_ASSERTIONS,
    SourceVerificationError,
    mark_source_verified,
    verify,
)
from buggy.middleware._audit_sink import iter_records, verify_ledger


class Site:
    """A fake origin: routes ``(method, url)`` to ``(status, body)`` or a callable.

    Copied from ``tests/unit/capture/test_gateway.py`` (the shared test double).
    """

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


ORDER = "https://app.acme.test/api/orders/1001"
ALICE = {"Authorization": "Bearer alice"}
BOB = {"Authorization": "Bearer bob"}
ALICE_ORDER = {
    "id": 1001,
    "owner": "alice@acme.test",
    "items": ["thinkpad x1", "usb-c dock"],
    "card": "4111-1111-1111-1111",
    "ship_to": "1 Main Street, Springfield",
}
BOB_ORDER = {"n": 7, "who": "bob", "basket": [], "note": "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"}


def _roe(**extra) -> dict:
    return {"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}, **extra}


def _set_roe(roots: Roots, document: dict, engagement: str = "acme") -> None:
    (roots.control / engagement).mkdir(parents=True, exist_ok=True)
    (roots.control / engagement / "roe.json").write_text(json.dumps(document))


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.roots = Roots(
            control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data"
        )
        _set_roe(self.roots, _roe(approvals={"state_changing": "not_required"}))
        self.site = Site()
        self.gateway = CaptureGateway(self.roots, opener=self.site, sleep=lambda _s: None)
        self.store = FindingStore(self.roots.data / "findings.sqlite3")
        self.service = FindingService(self.store, self.gateway)

    def close(self) -> None:
        self.gateway.store.close()
        self.store.close()

    # The three behaviours of the order endpoint.
    def vulnerable(self) -> None:
        """Any logged-in user can read Alice's order (the IDOR)."""
        self.site.routes[("GET", ORDER)] = lambda headers, _b: (
            (200, ALICE_ORDER) if headers.get("authorization") else (401, {"error": "login"})
        )

    def fixed(self) -> None:
        """Only Alice can read her order."""
        self.site.routes[("GET", ORDER)] = lambda headers, _b: (
            (200, ALICE_ORDER)
            if headers.get("authorization") == "Bearer alice"
            else (403, {"error": "forbidden"})
        )

    def per_user(self) -> None:
        """The URL answers 200 to everyone, but with the caller's own data."""
        self.site.routes[("GET", ORDER)] = lambda headers, _b: (
            (200, ALICE_ORDER)
            if headers.get("authorization") == "Bearer alice"
            else (200, BOB_ORDER)
        )

    def idor_claim(self, **overrides) -> dict:
        """Capture owner and attacker reads now and claim the attacker saw the owner's order."""
        owner = self.gateway.send("acme", "GET", ORDER, headers=ALICE, note="owner")
        attacker = self.gateway.send("acme", "GET", ORDER, headers=BOB, note="attacker")
        return {
            "title": "IDOR on GET /api/orders/{id}",
            "class": "access_control",
            "cwe": "CWE-639",
            "severity": "high",
            "endpoint": ORDER,
            "method": "GET",
            "parameter": "id",
            "source": "agent:hunter",
            "description": "Bob can read Alice's order by id.",
            "remediation": "Check that the order belongs to the caller before returning it.",
            "assertions": [
                {
                    "capture_id": owner.id,
                    "identity": "alice",
                    "expect": {"status": 200, "body_contains": ["alice@acme.test"]},
                },
                {
                    "capture_id": attacker.id,
                    "identity": "bob",
                    "expect": {
                        "status": 200,
                        "same_as": owner.id,
                        "body_contains": ["alice@acme.test"],
                    },
                },
            ],
            **overrides,
        }

    def submit(self, claim: dict) -> str:
        out = self.service.submit("acme", claim, "agent:hunter")
        assert out["ok"], out
        assert out["finding"]["status"] == "candidate"
        return out["finding"]["id"]


@pytest.fixture
def env(tmp_path: Path):
    environment = Env(tmp_path)
    yield environment
    environment.close()


class TestIdor:
    def test_vulnerable_target_is_exploit_verified_with_fresh_replays(self, env: Env) -> None:
        env.vulnerable()
        claim = env.idor_claim()
        cited = [a["capture_id"] for a in claim["assertions"]]
        finding = env.submit(claim)
        assert len(env.site.seen) == 2  # submitting sends nothing

        out = env.service.verify("acme", finding)

        assert out["ok"] and out["finding"]["status"] == "exploit_verified"
        replays = out["finding"]["verification"]["replay_capture_ids"]
        assert len(replays) == 2 and not set(replays) & set(cited)
        for replay_id, cited_id in zip(replays, cited, strict=True):
            replay = env.gateway.store.get("acme", replay_id)
            assert replay.replay_of == cited_id and replay.note == "verifier"
            assert replay.status == 200
        # The verifier really re-sent both requests, with the credentials of the cited captures.
        assert [seen[2]["authorization"] for seen in env.site.seen[2:]] == [
            "Bearer alice",
            "Bearer bob",
        ]
        assert [r["outcome"] for r in out["verification"]["assertions"]] == ["passed", "passed"]
        # The decision is stored, and the capture ledger recorded the replays like any request.
        stored = env.service.get("acme", finding)
        assert stored["finding"]["status"] == "exploit_verified"
        assert stored["finding"]["verification"]["replay_capture_ids"] == replays
        ledger = env.roots.audit / "acme" / "captures.jsonl"
        assert verify_ledger(ledger).ok
        assert [line["replay_of"] for line in iter_records(ledger)] == ["", "", *cited]

    def test_after_the_fix_it_is_inconclusive_and_names_the_failing_assertion(
        self, env: Env
    ) -> None:
        env.vulnerable()
        claim = env.idor_claim()
        attacker_capture = claim["assertions"][1]["capture_id"]
        finding = env.submit(claim)
        assert env.service.verify("acme", finding)["finding"]["status"] == "exploit_verified"

        env.fixed()  # the attacker now gets 403
        out = env.service.verify("acme", finding)

        assert out["finding"]["status"] == "inconclusive"  # flagged, not discarded
        owner_result, attacker_result = out["verification"]["assertions"]
        assert owner_result["outcome"] == "passed" and owner_result["reasons"] == []
        assert attacker_result["outcome"] == "failed" and attacker_result["replay_status"] == 403
        assert set(attacker_result["failed_checks"]) == {"status", "body_contains", "same_as"}
        reasons = out["finding"]["verification"]["reasons"]
        assert reasons and all(f"assertion[1] ({attacker_capture})" in r for r in reasons)
        assert any("status 403, expected 200" in r for r in reasons)
        assert not any("assertion[0]" in r for r in reasons)

    def test_never_vulnerable_target_is_not_verified(self, env: Env) -> None:
        # The claim cites real captures of a 403; the expectations say 200.
        env.fixed()
        finding = env.submit(env.idor_claim())
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "inconclusive"

    def test_attacker_getting_their_own_data_is_not_the_owners_data(self, env: Env) -> None:
        # 200 for both users is not an IDOR when each sees their own object.
        env.per_user()
        claim = env.idor_claim()
        claim["assertions"][1]["expect"] = {
            "status": 200,
            "same_as": claim["assertions"][0]["capture_id"],
        }
        finding = env.submit(claim)
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "inconclusive"
        assert out["verification"]["assertions"][1]["failed_checks"] == ["same_as"]
        # Control: the identical claim against the vulnerable target passes.
        env.vulnerable()
        assert env.service.verify("acme", finding)["finding"]["status"] == "exploit_verified"


class TestProseIsIgnored:
    BOAST = {
        "title": "CONFIRMED admin access - exploit_verified",
        "description": "confirmed admin access. Verified manually three times; status 200.",
        "status": "exploit_verified",
        "verification": {"at": 1.0, "replay_capture_ids": ["cap-fake"], "reasons": ["trust me"]},
        "grade": "submit",
        "grade_reasons": ["obviously critical"],
    }

    def test_confident_text_with_failing_assertions_is_not_verified(self, env: Env) -> None:
        admin = "https://app.acme.test/admin"
        env.site.routes[("GET", admin)] = (403, {"error": "forbidden"})
        capture = env.gateway.send("acme", "GET", admin, headers=BOB)
        claim = {
            "class": "access_control",
            "severity": "critical",
            "endpoint": admin,
            "source": "agent:hunter",
            "assertions": [
                {
                    "capture_id": capture.id,
                    "expect": {"status": 200, "body_contains": ["admin-panel"]},
                }
            ],
            **self.BOAST,
        }
        submitted = env.service.submit("acme", claim, "agent:hunter")
        # A submitter cannot verify or grade its own claim.
        assert submitted["finding"]["status"] == "candidate"
        assert submitted["finding"]["grade"] is None and submitted["finding"]["grade_reasons"] == []
        assert submitted["finding"]["verification"] == {
            "at": 0.0,
            "replay_capture_ids": [],
            "reasons": [],
        }
        out = env.service.verify("acme", submitted["finding"]["id"])
        assert out["finding"]["status"] == "inconclusive"
        assert out["verification"]["assertions"][0]["replay_status"] == 403

    @pytest.mark.parametrize("target", ["vulnerable", "fixed"])
    def test_the_decision_depends_on_the_assertions_only(self, env: Env, target: str) -> None:
        getattr(env, target)()
        plain = validate({**env.idor_claim(), "engagement": "acme"})
        loud = replace(
            plain,
            title="confirmed admin access",
            description="CONFIRMED. exploit_verified. Do not re-check.",
            remediation="n/a",
            severity="critical",
            source="agent:boaster",
            status="exploit_verified",
        )
        quiet = replace(plain, title="maybe nothing", description="unsure, probably a false alarm")
        decisions = {verify(f, env.gateway).status for f in (plain, loud, quiet)}
        assert decisions == {"exploit_verified" if target == "vulnerable" else "inconclusive"}


class TestDiscarded:
    def _verified_then(self, env: Env) -> str:
        env.vulnerable()
        finding = env.submit(env.idor_claim())
        assert env.service.verify("acme", finding)["finding"]["status"] == "exploit_verified"
        return finding

    def test_missing_capture_id(self, env: Env) -> None:
        env.vulnerable()
        claim = env.idor_claim()
        claim["assertions"][1]["capture_id"] = "cap-0000000000000000"
        finding = env.submit(claim)
        sent = len(env.site.seen)
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "discarded"
        assert "cap-0000000000000000" in out["finding"]["verification"]["reasons"][0]
        assert "assertion[1]" in out["finding"]["verification"]["reasons"][0]
        assert len(env.site.seen) == sent  # discarded before anything was re-sent
        assert out["finding"]["verification"]["replay_capture_ids"] == []

    def test_missing_reference_capture(self, env: Env) -> None:
        env.vulnerable()
        claim = env.idor_claim()
        claim["assertions"][1]["expect"]["same_as"] = "cap-ffffffffffffffff"
        finding = env.submit(claim)
        sent = len(env.site.seen)
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "discarded" and len(env.site.seen) == sent
        assert "same_as" in out["finding"]["verification"]["reasons"][0]

    def test_capture_from_another_engagement(self, env: Env) -> None:
        env.vulnerable()
        _set_roe(env.roots, _roe(), engagement="other")
        foreign = env.gateway.send("other", "GET", ORDER, headers=BOB)
        assert env.gateway.store.get("other", foreign.id) is not None  # it does exist, elsewhere
        claim = env.idor_claim()
        claim["assertions"][1]["capture_id"] = foreign.id
        finding = env.submit(claim)
        sent = len(env.site.seen)
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "discarded" and len(env.site.seen) == sent
        assert foreign.id in out["finding"]["verification"]["reasons"][0]

    def test_capture_whose_host_left_the_scope(self, env: Env) -> None:
        finding = self._verified_then(env)  # control: in scope, the same finding verifies
        _set_roe(
            env.roots,
            {"machine_enforcement": {"mode": "enforce", "in_scope": ["new.acme.test"]}},
        )
        sent = len(env.site.seen)
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "discarded" and len(env.site.seen) == sent
        assert "not in the enforced scope" in out["finding"]["verification"]["reasons"][0]

    def test_reference_capture_whose_host_left_the_scope(self, env: Env) -> None:
        # The request that gets re-sent stays in scope; the capture it is compared
        # with (never re-sent, so the gateway would not notice) does not.
        both = _roe(approvals={"state_changing": "not_required"})
        both["machine_enforcement"]["in_scope"].append("old.acme.test")
        _set_roe(env.roots, both)
        env.vulnerable()
        legacy = "https://old.acme.test/api/orders/1001"
        env.site.routes[("GET", legacy)] = (200, ALICE_ORDER)
        reference = env.gateway.send("acme", "GET", legacy, headers=ALICE)
        claim = env.idor_claim()
        claim["assertions"][1]["expect"]["same_as"] = reference.id
        finding = env.submit(claim)
        assert env.service.verify("acme", finding)["finding"]["status"] == "exploit_verified"

        _set_roe(env.roots, _roe(approvals={"state_changing": "not_required"}))
        sent = len(env.site.seen)
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "discarded" and len(env.site.seen) == sent
        assert "old.acme.test" in out["finding"]["verification"]["reasons"][0]

    def test_without_an_enforced_scope_nothing_is_sent_or_decided(self, env: Env) -> None:
        finding = self._verified_then(env)
        _set_roe(
            env.roots, {"machine_enforcement": {"mode": "audit", "in_scope": ["app.acme.test"]}}
        )
        sent = len(env.site.seen)
        out = env.service.verify("acme", finding)
        # Not verified, and not thrown away because of an operator-side condition.
        assert out["finding"]["status"] == "inconclusive" and len(env.site.seen) == sent
        assert "NO_ENFORCED_SCOPE" in out["finding"]["verification"]["reasons"][0]


class TestStateChangingRequests:
    COUPON = "https://app.acme.test/api/coupons/apply"
    BODY = '{"code": "WELCOME", "times": 5}'

    def _claim(self, env: Env) -> dict:
        env.site.routes[("POST", self.COUPON)] = (200, {"applied": True, "discount": 500})
        original = env.gateway.send("acme", "POST", self.COUPON, headers=BOB, body=self.BODY)
        assert original.status == 200
        env.site.seen.clear()
        return {
            "title": "Coupon can be applied repeatedly",
            "class": "business_logic",
            "severity": "medium",
            "endpoint": self.COUPON,
            "method": "POST",
            "parameter": "times",
            "source": "probe:numeric_boundary",
            "assertions": [
                {
                    "capture_id": original.id,
                    "expect": {"status": 200, "body_contains": ['"applied": true']},
                }
            ],
        }

    def test_post_is_not_replayed_without_allow_state_change(self, env: Env) -> None:
        finding = env.submit(self._claim(env))
        captures_before = len(env.gateway.store.list("acme"))

        out = env.service.verify("acme", finding)

        assert out["finding"]["status"] == "inconclusive"
        assert out["finding"]["verification"]["reasons"][0] == NEEDS_APPROVED_REPLAY
        assert env.site.seen == []  # the fake saw nothing
        assert len(env.gateway.store.list("acme")) == captures_before
        assert out["finding"]["verification"]["replay_capture_ids"] == []
        assert out["verification"]["assertions"][0]["outcome"] == "not_replayed"

        # Control: with the operator's go-ahead the same finding is re-sent and verified.
        allowed = env.service.verify("acme", finding, allow_state_change=True)
        assert allowed["finding"]["status"] == "exploit_verified"
        assert [(m, u, b) for m, u, _h, b in env.site.seen] == [
            ("POST", self.COUPON, self.BODY.encode())
        ]

    def test_allow_state_change_does_not_skip_the_gateways_approval_hold(self, env: Env) -> None:
        finding = env.submit(self._claim(env))
        _set_roe(env.roots, _roe())  # the engagement now requires approval for state changes

        held = env.service.verify("acme", finding, allow_state_change=True)

        assert held["finding"]["status"] == "inconclusive"
        assert held["finding"]["verification"]["reasons"][0] == NEEDS_APPROVED_REPLAY
        assert "APPROVAL_REQUIRED" in held["finding"]["verification"]["reasons"][1]
        assert env.site.seen == []
        requests_file = env.roots.audit / "acme" / "approvals" / "requests.jsonl"
        (request,) = [json.loads(line) for line in requests_file.read_text().splitlines()]

        approvals_cli.record_decision(
            env.roots.control / "acme" / "approvals" / "decisions.jsonl",
            request["request_id"],
            "allow",
        )
        approved = env.service.verify("acme", finding, allow_state_change=True)
        assert approved["finding"]["status"] == "exploit_verified"
        assert len(env.site.seen) == 1 and env.site.seen[0][0] == "POST"

    def test_a_passing_get_does_not_carry_an_unreplayed_post(self, env: Env) -> None:
        env.vulnerable()
        claim = self._claim(env)
        read = env.gateway.send("acme", "GET", ORDER, headers=BOB)
        env.site.seen.clear()
        claim["assertions"].insert(0, {"capture_id": read.id, "expect": {"status": 200}})
        finding = env.submit(claim)
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "inconclusive"
        assert [r["outcome"] for r in out["verification"]["assertions"]] == [
            "passed",
            "not_replayed",
        ]
        assert [m for m, *_ in env.site.seen] == ["GET"]
        assert any("assertion[1]" in r for r in out["finding"]["verification"]["reasons"])


class TestNoAssertions:
    def test_a_claim_without_assertions_is_inconclusive(self, env: Env) -> None:
        env.vulnerable()
        claim = env.idor_claim(assertions=[])
        finding = env.submit(claim)
        sent = len(env.site.seen)
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "inconclusive"
        assert out["finding"]["verification"]["reasons"] == [NO_ASSERTIONS]
        assert len(env.site.seen) == sent

    def test_an_assertion_that_checks_nothing_cannot_verify(self, env: Env) -> None:
        # ``validate`` rejects an empty ``expect``; the verifier must not rely on that.
        env.vulnerable()
        capture = env.gateway.send("acme", "GET", ORDER, headers=BOB)
        finding = Finding(
            id=finding_id("acme", "access_control", ORDER, "id"),
            engagement="acme",
            title="x",
            vuln_class="access_control",
            severity="high",
            endpoint=ORDER,
            assertions=(Assertion(capture_id=capture.id, expect=Expect()),),
        )
        sent = len(env.site.seen)
        outcome = verify(finding, env.gateway)
        assert outcome.status == "inconclusive" and len(env.site.seen) == sent


class TestExpectations:
    """Each expectation, passing and failing, against one fresh response."""

    PROFILE = "https://app.acme.test/api/me"
    BODY = {"email": "bob@acme.test", "role": "customer", "plan": "free", "id": 7}

    @pytest.fixture
    def refs(self, env: Env) -> dict[str, str]:
        base = "https://app.acme.test/ref/"
        env.site.routes[("GET", self.PROFILE)] = (200, self.BODY)
        env.site.routes[("GET", base + "same")] = (200, self.BODY)
        env.site.routes[("GET", base + "created")] = (201, self.BODY)
        env.site.routes[("GET", base + "other")] = (200, {"error": "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"})

        def down(_headers, _body):
            raise OSError("connection reset")

        env.site.routes[("GET", base + "down")] = down
        ids = {
            name: env.gateway.send("acme", "GET", base + name).id
            for name in ("same", "created", "other", "down")
        }
        ids["target"] = env.gateway.send("acme", "GET", self.PROFILE, headers=BOB).id
        return ids

    @pytest.mark.parametrize(
        ("expect", "failed"),
        [
            ({"status": 200}, []),
            ({"status": [200, 204]}, []),
            ({"status": 403}, ["status"]),
            ({"status": [401, 403]}, ["status"]),
            ({"body_contains": ["bob@acme.test", "customer"]}, []),
            ({"body_contains": ["bob@acme.test", "admin"]}, ["body_contains"]),
            ({"body_not_contains": ["admin"]}, []),
            ({"body_not_contains": ["admin", "customer"]}, ["body_not_contains"]),
            ({"same_as": "same"}, []),
            ({"same_as": "other"}, ["same_as"]),
            ({"same_as": "down"}, ["same_as"]),
            ({"differs_from": "other"}, []),
            ({"differs_from": "created"}, []),  # same body, different status
            ({"differs_from": "same"}, ["differs_from"]),
            ({"differs_from": "down"}, ["differs_from"]),  # nothing to differ from
            ({"status": 200, "body_contains": ["bob@"], "differs_from": "other"}, []),
            (
                {"status": 200, "body_contains": ["root@"], "same_as": "other"},
                ["body_contains", "same_as"],
            ),
        ],
    )
    def test_expectation(self, env: Env, refs: dict[str, str], expect: dict, failed: list) -> None:
        expect = {k: refs.get(v, v) if isinstance(v, str) else v for k, v in expect.items()}
        finding = validate(
            {
                "engagement": "acme",
                "title": "profile",
                "class": "info_exposure",
                "severity": "low",
                "endpoint": self.PROFILE,
                "source": "agent:hunter",
                "assertions": [{"capture_id": refs["target"], "expect": expect}],
            }
        )
        outcome = verify(finding, env.gateway)
        (result,) = outcome.results
        assert result["failed_checks"] == failed
        assert outcome.status == ("inconclusive" if failed else "exploit_verified")
        assert bool(outcome.reasons and "assertion[0]" in outcome.reasons[0]) == bool(failed)

    def test_a_replay_that_gets_no_response_is_inconclusive(self, env: Env) -> None:
        env.vulnerable()
        finding = env.submit(env.idor_claim())

        def down(_headers, _body):
            raise OSError("connection refused")

        env.site.routes[("GET", ORDER)] = down
        out = env.service.verify("acme", finding)
        assert out["finding"]["status"] == "inconclusive"  # flaky target: not discarded
        assert all(r["failed_checks"] == ["transport"] for r in out["verification"]["assertions"])
        assert len(out["finding"]["verification"]["replay_capture_ids"]) == 2


class _Sessions:
    """What task D1's SessionManager offers: the current headers for a named identity."""

    def __init__(self, tokens: dict[str, str]) -> None:
        self.tokens = tokens

    def auth_for(self, _engagement: str, name: str) -> tuple[dict[str, str], dict[str, str]]:
        return {"Authorization": f"Bearer {self.tokens[name]}"}, {}


class _IdentityGateway(CaptureGateway):
    """The real gateway plus the ``identity`` argument task D1 adds to ``send``."""

    def __init__(self, *args, sessions: _Sessions, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sessions = sessions
        self.identities: list[str] = []

    def send(self, engagement, method, url, *, headers=None, identity="", **kwargs):
        merged = dict(headers or {})
        if identity:
            self.identities.append(identity)
            merged.update(self._sessions.auth_for(engagement, identity)[0])
        return super().send(engagement, method, url, headers=merged, **kwargs)


class TestIdentities:
    """Sessions expire; with ``sessions`` the verifier asks for the identity's current one."""

    def _rotated(self, env: Env, gateway: CaptureGateway) -> Finding:
        live = {"alice", "bob-1"}

        def route(headers, _body):
            token = headers.get("authorization", "").removeprefix("Bearer ")
            return (200, ALICE_ORDER) if token in live else (401, {"error": "session expired"})

        env.site.routes[("GET", ORDER)] = route
        owner = gateway.send("acme", "GET", ORDER, headers=ALICE)
        attacker = gateway.send("acme", "GET", ORDER, headers={"Authorization": "Bearer bob-1"})
        assert attacker.status == 200
        live.remove("bob-1")  # Bob's first session has expired ...
        live.add("bob-2")  # ... and he has a new one
        return validate(
            {
                "engagement": "acme",
                "title": "IDOR",
                "class": "access_control",
                "severity": "high",
                "endpoint": ORDER,
                "parameter": "id",
                "source": "agent:hunter",
                "assertions": [
                    {"capture_id": owner.id, "identity": "alice", "expect": {"status": 200}},
                    {
                        "capture_id": attacker.id,
                        "identity": "bob",
                        "expect": {"status": 200, "same_as": owner.id},
                    },
                ],
            }
        )

    def test_identity_is_attached_only_when_sessions_are_given(self, env: Env) -> None:
        sessions = _Sessions({"alice": "alice", "bob": "bob-2"})
        gateway = _IdentityGateway(
            env.roots,
            store=env.gateway.store,
            opener=env.site,
            sleep=lambda _s: None,
            sessions=sessions,
        )
        finding = self._rotated(env, gateway)

        # Without sessions the stored (expired) credentials are replayed: not verified.
        stale = verify(finding, gateway)
        assert stale.status == "inconclusive" and gateway.identities == []
        assert stale.results[1]["replay_status"] == 401
        assert env.site.seen[-1][2]["authorization"] == "Bearer bob-1"

        fresh = verify(finding, gateway, sessions=sessions)
        assert fresh.status == "exploit_verified" and gateway.identities == ["alice", "bob"]
        assert env.site.seen[-1][2]["authorization"] == "Bearer bob-2"

    def test_a_gateway_without_identity_support_is_not_asked_and_nothing_is_sent(
        self, env: Env
    ) -> None:
        finding = self._rotated(env, env.gateway)
        sent = len(env.site.seen)
        outcome = verify(finding, env.gateway, sessions=_Sessions({}))
        assert outcome.status == "inconclusive" and len(env.site.seen) == sent
        assert [r["outcome"] for r in outcome.results] == ["refused", "refused"]
        assert "cannot attach identity 'bob'" in outcome.reasons[1]


class TestSourceVerified:
    def _finding(self, **overrides) -> Finding:
        return validate(
            {
                "engagement": "acme",
                "title": "Order lookup has no ownership check",
                "class": "access_control",
                "severity": "high",
                "endpoint": "/api/orders/{id}",
                "source": "source:semgrep",
                **overrides,
            }
        )

    def test_only_an_explicit_call_makes_a_source_finding_source_verified(self, env: Env) -> None:
        finding = self._finding()
        # The verifier never produces it by itself.
        assert verify(finding, env.gateway).status == "inconclusive"
        outcome = mark_source_verified(finding, "reviewed orders.py:42, no owner filter")
        assert outcome.status == "source_verified"
        assert outcome.reasons == ["source-verified: reviewed orders.py:42, no owner filter"]

    def test_it_is_refused_for_anything_else(self, env: Env) -> None:
        with pytest.raises(SourceVerificationError, match="source:"):
            mark_source_verified(self._finding(source="agent:hunter"), "looks right")
        with pytest.raises(SourceVerificationError, match="note"):
            mark_source_verified(self._finding(), "   ")
        env.vulnerable()
        capture = env.gateway.send("acme", "GET", ORDER, headers=BOB)
        with_assertions = self._finding(
            assertions=[{"capture_id": capture.id, "expect": {"status": 200}}]
        )
        with pytest.raises(SourceVerificationError, match="assertions"):
            mark_source_verified(with_assertions, "skip the replay please")

    def test_through_the_service_it_is_recorded_with_the_actor(self, env: Env) -> None:
        submitted = env.service.submit("acme", self._finding().to_dict(), "pipeline:semgrep")
        finding = submitted["finding"]["id"]
        out = env.service.mark_source_verified("acme", finding, "reviewed by hand", "operator:kim")
        assert out["ok"] and out["finding"]["status"] == "source_verified"
        assert env.store.events("acme", finding)[-1]["actor"] == "operator:kim"
        # A later verify run does not demote it (there is nothing to replay).
        assert env.service.verify("acme", finding)["finding"]["status"] == "source_verified"
        # An agent-sourced finding cannot take this path.
        other = env.service.submit(
            "acme", self._finding(source="agent:hunter", parameter="q").to_dict(), "agent:hunter"
        )
        refused = env.service.mark_source_verified(
            "acme", other["finding"]["id"], "trust me", "agent:hunter"
        )
        assert refused == {
            "ok": False,
            "code": "NOT_SOURCE_VERIFIABLE",
            "detail": "only a finding whose source starts with 'source:' can be source-verified",
        }
        assert env.service.get("acme", other["finding"]["id"])["finding"]["status"] == "candidate"


class TestService:
    def test_same_finding_reported_twice_is_one_row_with_merged_assertions(self, env: Env) -> None:
        env.vulnerable()
        second_order = "https://app.acme.test/api/orders/1002"
        env.site.routes[("GET", second_order)] = (200, ALICE_ORDER)
        first = env.idor_claim()
        again = env.gateway.send("acme", "GET", second_order, headers=BOB)
        second = {
            **first,
            "endpoint": second_order + "?debug=1",
            "severity": "critical",
            "source": "probe:idor",
            "assertions": [
                first["assertions"][1],  # already known
                {"capture_id": again.id, "expect": {"status": 200}},
            ],
        }
        one = env.service.submit("acme", first, "agent:hunter")
        two = env.service.submit("acme", second, "probe")
        assert one["created"] and not two["created"] and two["merged"]
        assert two["finding"]["id"] == one["finding"]["id"] and two["assertions_added"] == 1
        assert two["finding"]["endpoint"] == "https://app.acme.test/api/orders/{id}"
        assert len(two["finding"]["assertions"]) == 3
        assert two["finding"]["severity"] == "critical"
        assert two["finding"]["source"] == "agent:hunter | probe:idor"
        listed = env.service.list("acme")
        assert listed["count"] == 1 and listed["by_status"] == {"candidate": 1}
        assert [e["actor"] for e in env.store.events("acme", one["finding"]["id"])] == [
            "agent:hunter",
            "probe",
        ]

    def test_resubmitting_cannot_undo_or_dilute_a_verified_finding(self, env: Env) -> None:
        env.vulnerable()
        claim = env.idor_claim()
        finding = env.submit(claim)
        verified = env.service.verify("acme", finding)["finding"]
        assert verified["status"] == "exploit_verified"
        extra = env.gateway.send("acme", "GET", ORDER, headers=BOB)
        again = env.service.submit(
            "acme",
            {**claim, "assertions": [{"capture_id": extra.id, "expect": {"status": 500}}]},
            "agent:hunter",
        )
        assert again["ok"] and not again["merged"]
        assert again["finding"] == verified
        assert env.store.events("acme", finding)[-1]["event"] == "duplicate_submission"

    def test_new_evidence_puts_an_inconclusive_finding_back_in_the_queue(self, env: Env) -> None:
        env.fixed()
        claim = env.idor_claim()
        finding = env.submit(claim)
        assert env.service.verify("acme", finding)["finding"]["status"] == "inconclusive"
        # Repeating the same claim adds nothing and changes nothing.
        same = env.service.submit("acme", claim, "agent:hunter")
        assert same["assertions_added"] == 0 and same["finding"]["status"] == "inconclusive"
        extra = env.gateway.send("acme", "GET", ORDER, headers=ALICE)
        more = env.service.submit(
            "acme",
            {**claim, "assertions": [{"capture_id": extra.id, "expect": {"status": 200}}]},
            "agent:hunter",
        )
        assert more["assertions_added"] == 1 and more["finding"]["status"] == "candidate"
        assert more["finding"]["verification"]["reasons"] == []

    def test_errors_are_dicts_that_name_the_problem(self, env: Env) -> None:
        env.vulnerable()
        claim = env.idor_claim()
        bad = env.service.submit("acme", {**claim, "severity": "catastrophic"}, "agent:hunter")
        assert bad["ok"] is False and bad["code"] == "INVALID_FINDING"
        assert [e["field"] for e in bad["errors"]] == ["severity"]
        wrong = env.service.submit("acme", {**claim, "engagement": "other"}, "agent:hunter")
        assert wrong["ok"] is False and wrong["errors"][0]["field"] == "engagement"
        assert env.service.submit("acme", claim, "")["code"] == "BAD_ACTOR"
        assert env.service.list("acme")["count"] == 0  # nothing was stored
        assert env.service.verify("acme", "F-000000000000")["code"] == "UNKNOWN_FINDING"
        assert env.service.get("acme", "F-000000000000")["code"] == "UNKNOWN_FINDING"
        # Everything the service returns is JSON.
        finding = env.submit(claim)
        json.dumps(env.service.verify("acme", finding))
        json.dumps(env.service.get("acme", finding))
        json.dumps(env.service.list("acme", status="exploit_verified"))
        # A finding is visible only in its own engagement.
        assert env.service.get("other", finding)["code"] == "UNKNOWN_FINDING"
        assert env.service.list("other")["count"] == 0
