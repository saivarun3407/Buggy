"""Retest re-runs a finding's assertions through a real ``CaptureGateway`` over a fake origin.

"fixed" needs two consistent attempts that fail in the safe direction; every
case that is not that (flaky, down, 5xx, a possibly stale credential, a
request that was not re-sent) is ``inconclusive``. A retest never changes a
finding's status.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from tests.unit.findings.test_verifier import (
    ALICE,
    ALICE_ORDER,
    BOB,
    BOB_ORDER,
    ORDER,
    Env,
    _roe,
    _set_roe,
)

from buggy.cli import retest as retest_cli
from buggy.findings.retest import NO_CONTROL, STATE_CHANGE_NOT_ALLOWED, UNSTABLE, retest
from buggy.findings.store import FindingStore


def _must[T](value: T | None) -> T:
    """``value``, asserted present."""
    assert value is not None
    return value


INVOICE = "https://app.acme.test/api/invoices/5"
ADMIN = "https://app.acme.test/admin/users"
COUPON = "https://app.acme.test/api/coupons/apply"


@pytest.fixture
def env(tmp_path: Path):
    environment = Env(tmp_path)
    yield environment
    environment.close()


def behave(env: Env, url: str, mode: str) -> None:
    """How ``url`` answers the attacker (Bob). Alice always gets her order unless noted."""

    def handler(headers, _body):
        auth = headers.get("authorization")
        if mode == "down":
            raise OSError("connection refused")
        if mode == "error":
            return 500, {"error": "internal"}
        if mode == "all_forbidden":
            return 403, {"error": "forbidden"}
        if auth == "Bearer alice":
            return 200, ALICE_ORDER
        if mode == "vulnerable":
            return (200, ALICE_ORDER) if auth else (401, {"error": "login"})
        if mode == "fixed":
            return 403, {"error": "forbidden"}
        if mode == "per_user":
            return 200, BOB_ORDER
        if mode == "unauthorized":
            return 401, {"error": "login"}
        raise AssertionError(mode)

    env.site.routes[("GET", url)] = handler


def sequence(env: Env, url: str, attacker_answers: list[tuple[int, object]]) -> None:
    """Alice gets her order; Bob gets the next answer from the list on each request."""
    answers = list(attacker_answers)

    def handler(headers, _body):
        if headers.get("authorization") == "Bearer alice":
            return 200, ALICE_ORDER
        return answers.pop(0)

    env.site.routes[("GET", url)] = handler


def verified_idor(env: Env, url: str = ORDER) -> str:
    """Capture an IDOR on ``url``, submit it and have the verifier confirm it."""
    behave(env, url, "vulnerable")
    owner = env.gateway.send("acme", "GET", url, headers=ALICE, note="owner")
    attacker = env.gateway.send("acme", "GET", url, headers=BOB, note="attacker")
    claim = {
        "title": f"IDOR on GET {url}",
        "class": "access_control",
        "severity": "high",
        "endpoint": url,
        "method": "GET",
        "parameter": "id",
        "source": "agent:hunter",
        "assertions": [
            {
                "capture_id": owner.id,
                "expect": {"status": 200, "body_contains": ["alice@acme.test"]},
            },
            {
                "capture_id": attacker.id,
                "expect": {
                    "status": 200,
                    "same_as": owner.id,
                    "body_contains": ["alice@acme.test"],
                },
            },
        ],
    }
    finding = env.submit(claim)
    assert env.service.verify("acme", finding)["finding"]["status"] == "exploit_verified"
    env.site.seen.clear()
    return finding


def row(env: Env, finding: str) -> dict:
    stored = env.store.get("acme", finding)
    assert stored is not None
    return {"status": stored.status, "verification": stored.verification, "at": stored.updated_at}


def events(env: Env, finding: str) -> list[str]:
    return [event["event"] for event in env.store.events("acme", finding)]


class TestOutcomes:
    def test_vulnerable_target_is_still_vulnerable_after_one_attempt(self, env: Env) -> None:
        finding = verified_idor(env)
        before = row(env, finding)

        out = retest(env.service, "acme", finding)

        assert out["ok"] and out["outcome"] == "still_vulnerable"
        assert len(out["attempts"]) == 1 and len(env.site.seen) == 2
        assert len(out["capture_ids"]) == 2
        for capture_id in out["capture_ids"]:
            assert _must(env.gateway.store.get("acme", capture_id)).note == "verifier"
        assert out["fixed_at"] is None and out["regressed"] is False
        assert row(env, finding) == before  # status, verification, updated_at untouched
        state = env.store.retest_state("acme", finding)
        assert state["retest"]["outcome"] == "still_vulnerable"
        assert state["retest"]["capture_ids"] == out["capture_ids"]
        assert events(env, finding)[-1] == "retest"
        assert "regressed" not in events(env, finding)  # never fixed, so no regression

    def test_patched_target_is_fixed_only_after_two_consistent_attempts(self, env: Env) -> None:
        finding = verified_idor(env)
        before = row(env, finding)
        behave(env, ORDER, "fixed")

        out = retest(env.service, "acme", finding)

        assert out["outcome"] == "fixed"
        assert [a["verdict"] for a in out["attempts"]] == ["safe", "safe"]
        assert len(env.site.seen) == 4 and len(out["capture_ids"]) == 4
        statuses = [a["assertions"][1]["replay_status"] for a in out["attempts"]]
        assert statuses == [403, 403]
        assert out["fixed_at"] is not None
        assert env.store.retest_state("acme", finding)["fixed_at"] == out["fixed_at"]
        assert row(env, finding) == before
        (event,) = [e for e in env.store.events("acme", finding) if e["event"] == "retest"]
        assert event["detail"]["outcome"] == "fixed"
        assert event["detail"]["capture_ids"] == out["capture_ids"]

    def test_403_then_200_is_inconclusive_not_fixed(self, env: Env) -> None:
        finding = verified_idor(env)
        sequence(env, ORDER, [(403, {"error": "forbidden"}), (200, ALICE_ORDER)])

        out = retest(env.service, "acme", finding)

        assert out["outcome"] == "inconclusive"
        assert out["reasons"][0] == UNSTABLE
        assert [a["verdict"] for a in out["attempts"]] == ["safe", "vulnerable"]
        assert out["fixed_at"] is None

    def test_two_different_refusals_are_inconclusive(self, env: Env) -> None:
        finding = verified_idor(env)
        sequence(env, ORDER, [(403, {"error": "forbidden"}), (404, {"error": "nope"})])
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "inconclusive" and out["reasons"] == [UNSTABLE]

    def test_200_first_is_still_vulnerable_without_a_second_attempt(self, env: Env) -> None:
        finding = verified_idor(env)
        sequence(env, ORDER, [(200, ALICE_ORDER), (403, {"error": "forbidden"})])
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "still_vulnerable" and len(out["attempts"]) == 1

    def test_attacker_now_getting_their_own_data_is_fixed(self, env: Env) -> None:
        # The proof marker is gone and the response is no longer the victim's.
        finding = verified_idor(env)
        behave(env, ORDER, "per_user")
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "fixed"
        failed = out["attempts"][0]["assertions"][1]["failed_checks"]
        assert set(failed) == {"body_contains", "same_as"}

    def test_regression_after_fixed_clears_fixed_at_and_records_regressed(self, env: Env) -> None:
        finding = verified_idor(env)
        behave(env, ORDER, "fixed")
        fixed = retest(env.service, "acme", finding)
        assert fixed["outcome"] == "fixed" and fixed["fixed_at"]
        # Fixed again: fixed_at keeps the time of the first fix.
        again = retest(env.service, "acme", finding)
        assert again["outcome"] == "fixed" and again["fixed_at"] == fixed["fixed_at"]
        # Inconclusive does not clear it.
        behave(env, ORDER, "down")
        assert retest(env.service, "acme", finding)["fixed_at"] == fixed["fixed_at"]

        behave(env, ORDER, "vulnerable")
        out = retest(env.service, "acme", finding)

        assert out["outcome"] == "still_vulnerable" and out["regressed"] is True
        assert out["fixed_at"] is None
        assert env.store.retest_state("acme", finding)["fixed_at"] is None
        names = events(env, finding)
        assert names.count("regressed") == 1
        assert names[-2:] == ["regressed", "retest"]
        (regressed,) = [e for e in env.store.events("acme", finding) if e["event"] == "regressed"]
        assert regressed["detail"]["fixed_at"] == fixed["fixed_at"]
        assert _must(env.store.get("acme", finding)).status == "exploit_verified"
        # Still vulnerable once more: no second regression.
        retest(env.service, "acme", finding)
        assert events(env, finding).count("regressed") == 1


class TestNeverFixedWhenInDoubt:
    @pytest.mark.parametrize("mode", ["down", "error"])
    def test_a_target_that_is_down_is_never_fixed(self, env: Env, mode: str) -> None:
        finding = verified_idor(env)
        before = row(env, finding)
        behave(env, ORDER, mode)
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "inconclusive" and out["fixed_at"] is None
        assert len(out["attempts"]) == 1
        assert row(env, finding) == before

    def test_5xx_for_the_attacker_only_is_not_fixed(self, env: Env) -> None:
        finding = verified_idor(env)
        sequence(env, ORDER, [(503, {"error": "busy"}), (503, {"error": "busy"})])
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "inconclusive"
        assert any("503" in reason for reason in out["reasons"])

    @pytest.mark.parametrize(
        ("answer", "outcome"),
        [
            ((500, {"error": "internal"}), "inconclusive"),  # marker gone, but the target broke
            ((302, b"https://app.acme.test/login"), "inconclusive"),
            ((200, {"users": []}), "fixed"),  # control: a normal answer without the marker
        ],
    )
    def test_a_marker_gone_counts_only_on_a_normal_answer(
        self, env: Env, answer: tuple, outcome: str
    ) -> None:
        state = {"answer": (200, {"users": ["root@acme.test"]})}
        env.site.routes[("GET", ADMIN)] = lambda _h, _b: state["answer"]
        capture = env.gateway.send("acme", "GET", ADMIN)
        finding = env.submit(
            {
                "title": "Admin user list leaks root",
                "class": "info_exposure",
                "severity": "medium",
                "endpoint": ADMIN,
                "source": "agent:hunter",
                "assertions": [
                    {"capture_id": capture.id, "expect": {"body_contains": ["root@acme.test"]}}
                ],
            }
        )
        assert env.service.verify("acme", finding)["finding"]["status"] == "exploit_verified"
        state["answer"] = answer
        assert retest(env.service, "acme", finding)["outcome"] == outcome

    def test_a_redirect_is_not_a_refusal(self, env: Env) -> None:
        finding = verified_idor(env)
        sequence(env, ORDER, [(302, b"https://app.acme.test/login")] * 2)
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "inconclusive"

    def test_everyone_refused_is_not_a_fix(self, env: Env) -> None:
        finding = verified_idor(env)
        behave(env, ORDER, "all_forbidden")
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "inconclusive" and out["reasons"] == [NO_CONTROL]

    def test_401_to_a_stored_token_may_be_an_expired_token(self, env: Env) -> None:
        finding = verified_idor(env)
        behave(env, ORDER, "unauthorized")
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "inconclusive"
        assert any("expired" in reason for reason in out["reasons"])

    def test_401_to_an_unauthenticated_request_is_fixed(self, env: Env) -> None:
        # Control for the case above: no credential was involved, so 401 is the fix.
        state = {"open": True}
        env.site.routes[("GET", ADMIN)] = lambda _h, _b: (
            (200, {"users": ["root@acme.test"]}) if state["open"] else (401, {"error": "login"})
        )
        capture = env.gateway.send("acme", "GET", ADMIN)
        finding = env.submit(
            {
                "title": "Unauthenticated admin user list",
                "class": "access_control",
                "severity": "critical",
                "endpoint": ADMIN,
                "source": "agent:hunter",
                "assertions": [
                    {
                        "capture_id": capture.id,
                        "expect": {"status": 200, "body_contains": ["root@acme.test"]},
                    }
                ],
            }
        )
        assert env.service.verify("acme", finding)["finding"]["status"] == "exploit_verified"
        assert retest(env.service, "acme", finding)["outcome"] == "still_vulnerable"
        state["open"] = False
        assert retest(env.service, "acme", finding)["outcome"] == "fixed"

    def test_a_proof_that_was_a_refusal_is_not_fixed_by_another_refusal(self, env: Env) -> None:
        env.site.routes[("GET", ADMIN)] = (401, {"error": "login"})
        capture = env.gateway.send("acme", "GET", ADMIN)
        finding = env.submit(
            {
                "title": "Admin answers 401 with a stack trace",
                "class": "info_exposure",
                "severity": "low",
                "endpoint": ADMIN,
                "source": "agent:hunter",
                "assertions": [{"capture_id": capture.id, "expect": {"status": 401}}],
            }
        )
        assert env.service.verify("acme", finding)["finding"]["status"] == "exploit_verified"
        env.site.routes[("GET", ADMIN)] = (403, {"error": "forbidden"})
        out = retest(env.service, "acme", finding)
        assert out["outcome"] == "inconclusive"

    def test_unknown_finding(self, env: Env) -> None:
        out = retest(env.service, "acme", "F-000000000000")
        assert out == {
            "ok": False,
            "code": "UNKNOWN_FINDING",
            "detail": "no finding 'F-000000000000' in this engagement",
        }


class TestStateChangingProof:
    BODY = '{"code": "WELCOME", "times": 5}'

    def _finding(self, env: Env, *, with_get: bool = False) -> str:
        env.site.routes[("POST", COUPON)] = (200, {"applied": True, "discount": 500})
        original = env.gateway.send("acme", "POST", COUPON, headers=BOB, body=self.BODY)
        assertions = [{"capture_id": original.id, "expect": {"status": 200}}]
        if with_get:
            env.site.routes[("GET", COUPON)] = (200, {"applied": True})
            read = env.gateway.send("acme", "GET", COUPON, headers=BOB)
            assertions.insert(0, {"capture_id": read.id, "expect": {"status": 200}})
        finding = env.submit(
            {
                "title": "Coupon can be applied repeatedly",
                "class": "business_logic",
                "severity": "medium",
                "endpoint": COUPON,
                "method": "POST",
                "parameter": "times",
                "source": "probe:numeric_boundary",
                "assertions": assertions,
            }
        )
        verified = env.service.verify("acme", finding, allow_state_change=True)
        assert verified["finding"]["status"] == "exploit_verified"
        env.site.seen.clear()
        return finding

    @pytest.mark.parametrize("with_get", [False, True])
    def test_without_allow_state_change_nothing_is_sent(self, env: Env, with_get: bool) -> None:
        finding = self._finding(env, with_get=with_get)
        captures = len(env.gateway.store.list("acme"))
        before = row(env, finding)

        out = retest(env.service, "acme", finding)

        assert out["outcome"] == "inconclusive"
        assert out["reasons"][0] == STATE_CHANGE_NOT_ALLOWED
        assert env.site.seen == [] and out["capture_ids"] == []
        assert len(env.gateway.store.list("acme")) == captures
        assert row(env, finding) == before
        assert env.store.retest_state("acme", finding)["retest"]["outcome"] == "inconclusive"

    def test_allow_state_change_still_waits_for_the_operators_approval(self, env: Env) -> None:
        finding = self._finding(env)
        _set_roe(env.roots, _roe())  # state-changing requests now need approval
        out = retest(env.service, "acme", finding, allow_state_change=True)
        assert out["outcome"] == "inconclusive"
        assert any("APPROVAL_REQUIRED" in reason for reason in out["reasons"])
        assert env.site.seen == []

    def test_control_with_allow_state_change_and_no_approval_needed_it_is_sent(
        self, env: Env
    ) -> None:
        finding = self._finding(env)
        out = retest(env.service, "acme", finding, allow_state_change=True)
        assert out["outcome"] == "still_vulnerable"
        assert [m for m, *_ in env.site.seen] == ["POST"]


class TestStatusIsNeverChanged:
    @pytest.mark.parametrize("mode", ["vulnerable", "fixed", "down"])
    def test_an_inconclusive_finding_stays_inconclusive(self, env: Env, mode: str) -> None:
        finding = verified_idor(env)
        behave(env, ORDER, "fixed")
        assert env.service.verify("acme", finding)["finding"]["status"] == "inconclusive"
        before = row(env, finding)
        behave(env, ORDER, mode)
        out = retest(env.service, "acme", finding)
        assert out["status"] == "inconclusive"
        assert row(env, finding) == before


class TestStore:
    def test_upsert_keeps_the_retest_record(self, env: Env) -> None:
        finding = verified_idor(env)
        behave(env, ORDER, "fixed")
        out = retest(env.service, "acme", finding)
        stored = env.store.get("acme", finding)
        env.store.upsert(stored, "grader", event="graded")
        state = env.store.retest_state("acme", finding)
        assert state["fixed_at"] == out["fixed_at"]
        assert state["retest"]["outcome"] == "fixed"

    def test_a_store_without_the_columns_gains_them(self, tmp_path: Path) -> None:
        path = tmp_path / "old.sqlite3"
        db = sqlite3.connect(path)
        db.execute(
            "CREATE TABLE findings (id TEXT PRIMARY KEY, engagement TEXT NOT NULL, "
            "title TEXT NOT NULL, class TEXT NOT NULL, cwe TEXT NOT NULL DEFAULT '', "
            "severity TEXT NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'GET', "
            "parameter TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', "
            "description TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '', "
            "assertions TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'candidate', "
            "verification TEXT NOT NULL DEFAULT '{}', grade TEXT, "
            "grade_reasons TEXT NOT NULL DEFAULT '[]', created_at REAL NOT NULL, "
            "updated_at REAL NOT NULL, claimed_by TEXT NOT NULL DEFAULT '', "
            "claimed_at REAL NOT NULL DEFAULT 0)"
        )
        db.execute(
            "INSERT INTO findings (id, engagement, title, class, severity, endpoint, "
            "created_at, updated_at, claimed_by, claimed_at) "
            "VALUES ('F-1', 'acme', 't', 'api', 'low', '/x', 1, 1, 'w', 9e18)"
        )
        db.commit()
        db.close()
        # Read-only on the old file: claims still work, retest reads as empty.
        old = FindingStore(path, read_only=True)
        assert old.retest_state("acme", "F-1") == {"retest": None, "fixed_at": None}
        assert list(old.claims("acme", lease_seconds=60)) == ["F-1"]
        old.close()
        store = FindingStore(path)
        assert store.retest_state("acme", "F-1") == {"retest": None, "fixed_at": None}
        store.record_retest("acme", "F-1", actor="retest", outcome="fixed", capture_ids=["c"])
        assert store.retest_state("acme", "F-1")["fixed_at"] is not None
        with pytest.raises(ValueError, match="unknown retest outcome"):
            store.record_retest("acme", "F-1", actor="retest", outcome="maybe", capture_ids=[])
        store.close()


class TestCli:
    @pytest.fixture
    def cli(self, env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
        monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(env.roots.control))
        monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(env.roots.audit))
        monkeypatch.setenv("BUGGY_CAPTURE_DATA", str(env.roots.data))
        monkeypatch.setenv("BUGGY_SECRETS_ROOT", str(env.roots.control.parent / "secrets"))

        def run(*argv: str) -> tuple[int, str]:
            capsys.readouterr()
            code = retest_cli.main(list(argv), opener=env.site, sleep=lambda _s: None)
            return code, capsys.readouterr().out

        return run

    @pytest.mark.parametrize(
        ("order", "invoice", "expected"),
        [
            ("fixed", "fixed", 0),
            ("vulnerable", "fixed", 10),
            ("down", "fixed", 3),
            ("vulnerable", "down", 10),  # still vulnerable wins over inconclusive
            ("vulnerable", "vulnerable", 10),
            ("down", "error", 3),
        ],
    )
    def test_exit_code_matrix(self, env: Env, cli, order: str, invoice: str, expected: int) -> None:
        first, second = verified_idor(env, ORDER), verified_idor(env, INVOICE)
        behave(env, ORDER, order)
        behave(env, INVOICE, invoice)

        code, out = cli("acme", "--all-verified")

        assert code == expected
        lines = out.strip().splitlines()
        assert len(lines) == 2
        assert {line.split()[0] for line in lines} == {first, second}
        assert _must(env.store.get("acme", first)).status == "exploit_verified"

    @pytest.mark.parametrize(("mode", "expected"), [("fixed", 0), ("vulnerable", 10), ("down", 3)])
    def test_one_finding(self, env: Env, cli, mode: str, expected: int) -> None:
        finding = verified_idor(env)
        behave(env, ORDER, mode)
        code, out = cli("acme", finding)
        assert code == expected
        assert out.split()[:2] == [
            finding,
            {0: "fixed", 10: "still_vulnerable"}.get(code, "inconclusive"),
        ]

    def test_json_shape(self, env: Env, cli) -> None:
        first, second = verified_idor(env, ORDER), verified_idor(env, INVOICE)
        behave(env, ORDER, "fixed")
        behave(env, INVOICE, "vulnerable")

        code, out = cli("acme", "--all-verified", "--json")

        document = json.loads(out)
        assert code == 10 and document["exit_code"] == 10
        assert document["engagement"] == "acme"
        assert document["counts"] == {"fixed": 1, "still_vulnerable": 1, "inconclusive": 0}
        by_id = {r["finding_id"]: r for r in document["results"]}
        assert set(by_id) == {first, second}
        for result in document["results"]:
            assert set(result) == {
                "finding_id",
                "title",
                "status",
                "outcome",
                "reasons",
                "capture_ids",
                "fixed_at",
                "regressed",
            }
            assert result["status"] == "exploit_verified"
        assert by_id[first]["outcome"] == "fixed" and by_id[first]["fixed_at"]
        assert len(by_id[first]["capture_ids"]) == 4
        assert by_id[second]["outcome"] == "still_vulnerable" and by_id[second]["fixed_at"] is None

    def test_only_verified_findings_are_retested_with_all_verified(self, env: Env, cli) -> None:
        verified = verified_idor(env)
        behave(env, INVOICE, "vulnerable")
        owner = env.gateway.send("acme", "GET", INVOICE, headers=ALICE)
        candidate = env.submit(
            {
                "title": "unverified",
                "class": "access_control",
                "severity": "high",
                "endpoint": INVOICE,
                "parameter": "id",
                "source": "agent:hunter",
                "assertions": [{"capture_id": owner.id, "expect": {"status": 200}}],
            }
        )
        behave(env, ORDER, "fixed")
        code, out = cli("acme", "--all-verified", "--json")
        assert code == 0
        assert [r["finding_id"] for r in json.loads(out)["results"]] == [verified]
        assert env.store.retest_state("acme", candidate)["retest"] is None

    def test_nothing_to_retest(self, env: Env, cli) -> None:
        code, out = cli("acme", "--all-verified", "--json")
        assert code == 0 and json.loads(out)["results"] == []

    @pytest.mark.parametrize(
        "argv",
        [
            ("acme",),
            ("acme", "F-1", "--all-verified"),
            ("acme", "F-000000000000"),
        ],
    )
    def test_usage_errors(self, env: Env, cli, argv: tuple[str, ...]) -> None:
        code, _out = cli(*argv)
        assert code == 2
        assert env.site.seen == []

    def test_reached_through_the_dispatcher(self, env: Env, cli) -> None:
        from buggy.cli.__main__ import main as dispatch

        assert dispatch(["retest", "acme", "F-000000000000"]) == 2
        assert dispatch(["retest", "acme"]) == 2
