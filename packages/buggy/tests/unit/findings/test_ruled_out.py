"""The ruled-out ledger: why each dropped lead was dropped, what it retires, when it expires."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from buggy.findings import ruled_out
from buggy.findings.candidates import next_candidates
from buggy.findings.model import validate
from buggy.findings.ruled_out import (
    DAY,
    Ledger,
    review_days_from_env,
    technique_key,
    techniques_of,
)
from buggy.findings.service import FindingService
from buggy.findings.store import STATE_CLOSED, STATE_REOPENED, FindingStore

BASE = "https://app.acme.test"
SEARCH = f"{BASE}/search"


class Clock:
    """Held still unless moved."""

    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def env(tmp_path: Path):
    clock = Clock()
    store = FindingStore(tmp_path / "findings.sqlite3", clock=clock)
    ledger = Ledger(store, review_days=30)
    yield SimpleNamespace(store=store, ledger=ledger, clock=clock, path=tmp_path)
    store.close()


def _probe_result(vulnerable, *, captures=("cap-1",), **extra) -> dict:
    return {
        "status": "completed",
        "probe": "sqli",
        "class": "injection",
        "vulnerable": vulnerable,
        "summary": "no difference between the true and false conditions",
        "evidence_capture_ids": list(captures),
        "details": {"method": "GET"},
        **extra,
    }


def _capture(status=200, error=""):
    return SimpleNamespace(status=status, error=error)


def _lookup(**by_id):
    return lambda capture_id: by_id.get(capture_id)


def _lead(store: FindingStore, *, source: str, parameter: str = "q", description: str = "") -> str:
    finding = validate(
        {
            "engagement": "acme",
            "title": "search lead",
            "class": "injection",
            "severity": "info",
            "endpoint": SEARCH,
            "parameter": parameter,
            "source": source,
            "description": description,
        }
    )
    return store.upsert(finding, "test").id


class TestWhatIsRecorded:
    def test_not_vulnerable_retires_the_technique_with_its_reason(self, env) -> None:
        entry = env.ledger.after_probe(
            "acme",
            "sqli",
            {"url": SEARCH + "?q=1", "parameter": "q"},
            _probe_result(False),
            lookup=_lookup(**{"cap-1": _capture(200)}),
        )
        assert entry is not None
        assert (entry["kind"], entry["reason"], entry["technique"]) == (
            "ruled_out",
            ruled_out.NOT_VULNERABLE,
            "probe:sqli",
        )
        assert entry["endpoint"] == SEARCH and entry["parameter"] == "q"
        assert entry["actor"] == "probe:sqli" and entry["at"] == env.clock.t
        assert entry["review_at"] == env.clock.t + 30 * DAY
        assert "no difference" in entry["detail"]

    @pytest.mark.parametrize(
        ("capture", "why"),
        [
            (_capture(None, "TimeoutError: timed out"), "no response"),
            (_capture(429), "answered 429"),
            (_capture(503), "answered 503"),
        ],
    )
    def test_a_delivery_failure_is_an_attempt_that_retires_nothing(self, env, capture, why) -> None:
        entry = env.ledger.after_probe(
            "acme",
            "sqli",
            {"url": SEARCH, "parameter": "q"},
            _probe_result(False),
            lookup=_lookup(**{"cap-1": capture}),
        )
        assert entry is not None
        assert (entry["kind"], entry["reason"]) == ("attempt", ruled_out.DELIVERY_FAILED)
        assert why in entry["detail"] and entry["review_at"] == 0
        assert env.ledger.holding("acme") == []

    @pytest.mark.parametrize(
        ("code", "kind", "reason"),
        [
            ("OUT_OF_SCOPE", "ruled_out", ruled_out.BLOCKED),
            ("INTERNAL_ADDRESS", "ruled_out", ruled_out.BLOCKED),
            ("APPROVAL_DENIED", "ruled_out", ruled_out.APPROVAL_DENIED),
            ("APPROVAL_SPENT", "attempt", ruled_out.DELIVERY_FAILED),
            ("LOGIN_FAILED", "attempt", ruled_out.DELIVERY_FAILED),
        ],
    )
    def test_gateway_refusals_keep_their_code(self, env, code, kind, reason) -> None:
        refused = {"probe": "sqli", "status": "refused", "code": code, "detail": "not sent"}
        entry = env.ledger.after_probe("acme", "sqli", {"url": SEARCH, "parameter": "q"}, refused)
        assert entry is not None
        assert (entry["kind"], entry["reason"], entry["code"]) == (kind, reason, code)

    @pytest.mark.parametrize("code", ["APPROVAL_REQUIRED", "UNKNOWN_IDENTITY", "BAD_ARGUMENT"])
    def test_a_held_run_or_bad_input_rules_nothing_out(self, env, code) -> None:
        refused = {"probe": "sqli", "status": "refused", "code": code, "detail": "x"}
        assert env.ledger.after_probe("acme", "sqli", {"url": SEARCH}, refused) is None
        assert env.store.ledger("acme") == []

    def test_an_undecided_run_is_an_attempt(self, env) -> None:
        entry = env.ledger.after_probe(
            "acme", "sqli", {"url": SEARCH, "parameter": "q"}, _probe_result(None)
        )
        assert entry is not None
        assert (entry["kind"], entry["reason"]) == ("attempt", ruled_out.UNDECIDED)

    def test_a_repeat_is_merged_and_a_positive_supersedes_it(self, env) -> None:
        params = {"url": SEARCH, "parameter": "q"}
        first = env.ledger.after_probe("acme", "sqli", params, _probe_result(False))
        env.clock.t += 60
        again = env.ledger.after_probe("acme", "sqli", params, _probe_result(False))
        assert first is not None and again is not None
        assert again["id"] == first["id"] and again["count"] == 2
        assert again["first_at"] == first["at"] and again["at"] == first["at"] + 60
        assert len(env.ledger.holding("acme")) == 1

        assert env.ledger.after_probe("acme", "sqli", params, _probe_result(True)) is None
        assert env.ledger.holding("acme") == []
        assert env.store.ledger("acme")[0]["state"] == "superseded"

    def test_the_key_is_technique_endpoint_and_parameter(self) -> None:
        base = technique_key("acme", "probe:sqli", f"{BASE}/item/1?x=1", "q")
        assert base == technique_key("acme", "probe:sqli", f"{BASE}/item/2", "q")
        assert base != technique_key("acme", "probe:sqli", f"{BASE}/item/2", "id")
        assert base != technique_key("acme", "probe:xss_reflected", f"{BASE}/item/2", "q")
        assert base != technique_key("other", "probe:sqli", f"{BASE}/item/2", "q")


class TestTechniquesOfALead:
    @pytest.mark.parametrize(
        ("source", "description", "techniques"),
        [
            ("probe:sqli", "", ["probe:sqli"]),
            ("recipe:order-read", "", ["recipe:order-read"]),
            ("pipeline:nuclei", "", ["scanner"]),
            ("pipeline:surface", "Recon lead. Suggested check: sqli.", ["probe:sqli"]),
            ("pipeline:surface", "Recon lead.", ["surface"]),
            ("probe:sqli | agent:hunter", "", ["probe:sqli", "claim"]),
        ],
    )
    def test_sources_name_techniques(self, source, description, techniques) -> None:
        finding = validate(
            {
                "engagement": "acme",
                "title": "t",
                "class": "injection",
                "severity": "low",
                "endpoint": SEARCH,
                "source": source,
                "description": description,
            }
        )
        assert techniques_of(finding) == techniques


class TestTheQueue:
    def test_a_lead_whose_technique_failed_there_is_not_handed_out(self, env) -> None:
        lead = _lead(env.store, source="pipeline:surface", description="Suggested check: sqli.")
        other = _lead(env.store, source="pipeline:surface", parameter="page")
        env.ledger.after_probe(
            "acme", "sqli", {"url": SEARCH, "parameter": "q"}, _probe_result(False)
        )
        skipped: dict = {}
        rows = next_candidates(env.store, "acme", limit=5, ledger=env.ledger, skipped=skipped)
        assert [r["id"] for r in rows] == [other]
        assert list(skipped) == [lead]
        assert skipped[lead][0]["reason"] == ruled_out.NOT_VULNERABLE

    def test_a_lead_with_another_untried_technique_stays(self, env) -> None:
        lead = _lead(env.store, source="probe:sqli | agent:hunter")
        env.ledger.after_probe(
            "acme", "sqli", {"url": SEARCH, "parameter": "q"}, _probe_result(False)
        )
        assert [r["id"] for r in next_candidates(env.store, "acme", ledger=env.ledger)] == [lead]

    def test_one_claim_ruled_out_does_not_rule_out_another_claim_there(self, env) -> None:
        lead = _lead(env.store, source="agent:hunter")
        other = validate(
            {
                "engagement": "acme",
                "title": "xss claim",
                "class": "xss",
                "severity": "low",
                "endpoint": SEARCH,
                "parameter": "q",
                "source": "agent:other",
            }
        )
        env.store.upsert(other, "test")
        env.ledger.record(
            "acme",
            technique="claim",
            endpoint=SEARCH,
            parameter="q",
            kind="ruled_out",
            reason=ruled_out.INCONCLUSIVE,
            finding_id=other.id,
            actor="verifier",
        )
        rows = next_candidates(env.store, "acme", ledger=env.ledger)
        assert [r["id"] for r in rows] == [lead]

    def test_a_delivery_failure_does_not_take_the_lead_away(self, env) -> None:
        lead = _lead(env.store, source="probe:sqli")
        env.ledger.after_probe(
            "acme",
            "sqli",
            {"url": SEARCH, "parameter": "q"},
            _probe_result(False),
            lookup=_lookup(**{"cap-1": _capture(None, "TimeoutError: timed out")}),
        )
        assert [r["id"] for r in next_candidates(env.store, "acme", ledger=env.ledger)] == [lead]

    def test_after_the_review_date_the_lead_returns_with_why_it_was_out(self, env) -> None:
        lead = _lead(env.store, source="probe:sqli")
        entry = env.ledger.after_probe(
            "acme", "sqli", {"url": SEARCH, "parameter": "q"}, _probe_result(False)
        )
        assert entry is not None
        assert next_candidates(env.store, "acme", ledger=env.ledger) == []
        env.clock.t += 31 * DAY
        rows = next_candidates(env.store, "acme", ledger=env.ledger)
        assert [r["id"] for r in rows] == [lead]
        assert rows[0]["ruled_out_before"][0]["id"] == entry["id"]
        assert [d["id"] for d in env.ledger.due("acme")] == [entry["id"]]

    def test_the_operator_closes_extends_or_reopens(self, env) -> None:
        _lead(env.store, source="probe:sqli")
        entry = env.ledger.after_probe(
            "acme", "sqli", {"url": SEARCH, "parameter": "q"}, _probe_result(False)
        )
        assert entry is not None
        env.clock.t += 31 * DAY
        closed = env.store.ledger_set_state(
            "acme", entry["id"], actor="operator", state=STATE_CLOSED, note="checked by hand"
        )
        assert closed["state"] == STATE_CLOSED and closed["state_note"] == "checked by hand"
        assert env.ledger.due("acme") == []
        assert next_candidates(env.store, "acme", ledger=env.ledger) == []  # stands for good

        env.store.ledger_set_state("acme", entry["id"], actor="operator", state=STATE_REOPENED)
        assert len(next_candidates(env.store, "acme", ledger=env.ledger)) == 1

        env.store.ledger_set_state(
            "acme", entry["id"], actor="operator", state="open", review_at=env.clock.t + DAY
        )
        assert next_candidates(env.store, "acme", ledger=env.ledger) == []
        with pytest.raises(LookupError):
            env.store.ledger_set_state("acme", "L-999", actor="operator", state="closed")

    def test_the_agent_listing_filters_and_separates_attempts(self, env) -> None:
        env.ledger.after_probe(
            "acme", "sqli", {"url": SEARCH, "parameter": "q"}, _probe_result(False)
        )
        env.ledger.after_probe(
            "acme",
            "xss_reflected",
            {"url": f"{BASE}/hello", "parameter": "name"},
            {"status": "refused", "code": "LOGIN_FAILED", "detail": "login failed"},
        )
        listed = env.ledger.listed("acme")
        assert [r["technique"] for r in listed["ruled_out"]] == ["probe:sqli"]
        assert [r["technique"] for r in listed["failed_attempts"]] == ["probe:xss_reflected"]
        assert listed["ruled_out"][0]["why"] and listed["ruled_out"][0]["by"] == "probe:sqli"
        assert env.ledger.listed("acme", "hello")["ruled_out"] == []
        assert env.ledger.listed("acme", "search not_vulnerable")["ruled_out_total"] == 1


class _Gateway:
    store = None


class TestVerifierAndGrader:
    def _verified_lead(self, env) -> FindingService:
        service = FindingService(env.store, _Gateway(), review_days=10)
        _lead(env.store, source="agent:hunter")
        return service

    def test_an_inconclusive_replay_rules_the_claim_out(self, env) -> None:
        service = self._verified_lead(env)
        finding = env.store.list("acme")[0]
        entry = service.ledger.after_verification(
            finding,
            "inconclusive",
            [{"outcome": "failed", "replay_capture_id": "cap-9", "replay_status": 200}],
            ["assertion 0 (cap-1): status 200, expected 500"],
            actor="verifier",
        )
        assert entry is not None
        assert (entry["kind"], entry["reason"], entry["technique"]) == (
            "ruled_out",
            ruled_out.INCONCLUSIVE,
            "claim",
        )
        assert entry["finding_id"] == finding.id and "expected 500" in entry["detail"]
        assert entry["review_at"] == env.clock.t + 10 * DAY
        events = [e["event"] for e in env.store.events("acme", finding.id)]
        assert events[-1] == "ruled_out"

    @pytest.mark.parametrize(
        ("results", "reasons"),
        [
            ([{"outcome": "not_replayed"}], ["needs operator-approved replay"]),
            ([{"outcome": "failed", "replay_capture_id": "c", "replay_status": 503}], ["x"]),
            (
                [{"method": "probe_rerun", "probe": "sqli", "outcome": "failed"}],
                ["the probe could not decide when re-run (APPROVAL_REQUIRED)"],
            ),
        ],
    )
    def test_a_replay_that_did_not_get_through_is_only_an_attempt(
        self, env, results, reasons
    ) -> None:
        service = self._verified_lead(env)
        finding = env.store.list("acme")[0]
        entry = service.ledger.after_verification(
            finding, "inconclusive", results, reasons, actor="verifier"
        )
        assert entry is not None and entry["kind"] == "attempt"

    def test_a_probe_rerun_names_the_probe(self, env) -> None:
        service = self._verified_lead(env)
        finding = env.store.list("acme")[0]
        entry = service.ledger.after_verification(
            finding,
            "inconclusive",
            [{"method": "probe_rerun", "probe": "sqli", "outcome": "failed"}],
            ["the probe no longer reports this issue"],
            actor="verifier",
        )
        assert entry is not None and entry["technique"] == "probe:sqli"

    def test_grades_hold_and_discard_get_a_review_date_and_submit_ends_them(self, env) -> None:
        service = self._verified_lead(env)
        finding = env.store.list("acme")[0]
        held = service.ledger.after_grade(
            finding, "hold", ["Rule 7 (low impact): severity info"], actor="grader"
        )
        assert held is not None
        assert (held["kind"], held["reason"], held["code"]) == ("held", "graded_hold", "rule 7")
        discarded = service.ledger.after_grade(
            finding, "discard", ["Rule 3 (program exclusions): class excluded"], actor="grader"
        )
        assert discarded is not None and discarded["reason"] == "graded_discard"
        states = {row["id"]: row["state"] for row in env.store.ledger("acme")}
        assert states == {held["id"]: "superseded", discarded["id"]: "open"}
        env.clock.t += 11 * DAY
        assert [d["id"] for d in service.ledger.due("acme")] == [discarded["id"]]
        assert service.ledger.after_grade(finding, "submit", [], actor="grader") is None
        assert service.ledger.due("acme") == []


class TestConfigAndMigration:
    @pytest.mark.parametrize(
        ("raw", "days"), [("", 30.0), ("7", 7.0), ("0", 30.0), ("x", 30.0), ("99999", 30.0)]
    )
    def test_review_days_come_from_the_environment(self, monkeypatch, raw, days) -> None:
        monkeypatch.setenv("BUGGY_REVIEW_DAYS", raw)
        assert review_days_from_env() == days

    def test_a_store_written_before_the_new_fields_still_loads(self, tmp_path: Path) -> None:
        path = tmp_path / "old.sqlite3"
        db = sqlite3.connect(path)
        db.executescript(
            """
            CREATE TABLE findings (
                id TEXT PRIMARY KEY, engagement TEXT NOT NULL, title TEXT NOT NULL,
                class TEXT NOT NULL, cwe TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL,
                endpoint TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'GET',
                parameter TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
                assertions TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'candidate',
                verification TEXT NOT NULL DEFAULT '{}', grade TEXT,
                grade_reasons TEXT NOT NULL DEFAULT '[]', created_at REAL NOT NULL,
                updated_at REAL NOT NULL);
            """
        )
        finding = validate(
            {
                "engagement": "acme",
                "title": "old",
                "class": "xss",
                "severity": "low",
                "endpoint": SEARCH,
                "source": "agent:old",
            }
        )
        db.execute(
            "INSERT INTO findings (id, engagement, title, class, severity, endpoint, source, "
            "created_at, updated_at) VALUES (?, 'acme', 'old', 'xss', 'low', ?, 'agent:old', 1, 1)",
            (finding.id, SEARCH),
        )
        db.commit()
        db.close()

        readonly = FindingStore(path, read_only=True)
        old = readonly.get("acme", finding.id)
        assert old is not None and old.invariant == "" and old.entry_point == ""
        assert Ledger(readonly).holding("acme") == [] and readonly.ledger("acme") == []
        readonly.close()

        store = FindingStore(path)  # opening for writing adds the columns and the ledger
        loaded = store.get("acme", finding.id)
        assert loaded is not None and loaded.to_dict()["invariant"] == ""
        assert next_candidates(store, "acme")[0]["id"] == finding.id
        store.close()

    def test_invariant_and_entry_point_round_trip(self, env) -> None:
        finding = validate(
            {
                "engagement": "acme",
                "title": "basket",
                "class": "access_control",
                "severity": "high",
                "endpoint": f"{BASE}/rest/basket/2",
                "source": "agent:x",
                "invariant": "a user can only read their own basket",
                "entry_point": f"GET {BASE}/rest/basket/2",
            }
        )
        env.store.upsert(finding, "t")
        stored = env.store.get("acme", finding.id)
        assert stored is not None
        assert stored.invariant == "a user can only read their own basket"
        assert json.loads(json.dumps(stored.to_dict()))["entry_point"].startswith("GET ")
