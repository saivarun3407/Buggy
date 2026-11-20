"""Finding schema, stable ids, validation, and the SQLite store with its history."""

from __future__ import annotations

import ast
import json
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import buggy.findings
from buggy.findings.model import (
    CLASSES,
    SEVERITIES,
    STATUSES,
    Finding,
    Severity,
    Status,
    ValidationError,
    VulnClass,
    finding_id,
    normalize_endpoint,
    validate,
)
from buggy.findings.store import FindingNotFound, FindingStore, IllegalTransition

# The keys of the Finding contract in board/CONTRACTS.md, in its order.
CONTRACT_KEYS = [
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
]


def _claim(**overrides) -> dict:
    return {
        "engagement": "acme",
        "title": "IDOR on GET /api/orders/{id}",
        "class": "access_control",
        "cwe": "CWE-639",
        "severity": "high",
        "endpoint": "https://app.acme.test/api/orders/1001",
        "method": "GET",
        "parameter": "id",
        "source": "probe:idor",
        "description": "Bob reads Alice's order.",
        "remediation": "Check ownership of the order before returning it.",
        "assertions": [
            {
                "capture_id": "cap-aaaaaaaaaaaaaaaa",
                "identity": "bob",
                "expect": {
                    "status": 200,
                    "body_contains": ["alice@"],
                    "same_as": "cap-bbbbbbbbbbbbbbbb",
                },
            }
        ],
        **overrides,
    }


class TestFindingId:
    def test_format(self) -> None:
        value = finding_id("acme", "access_control", "https://app.acme.test/api/orders/1001", "id")
        assert value.startswith("F-") and len(value) == 14
        int(value[2:], 16)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "https://app.acme.test/api/orders/1002",
            "https://APP.Acme.Test/api/orders/1001",
            "HTTPS://app.acme.test/api/orders/1001?expand=items&debug=1",
            "https://app.acme.test/api/orders/1001#top",
            "https://app.acme.test/api/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            "https://app.acme.test/api/orders/3F2504E0-4F89-11D3-9A0C-0305E82C3301",
            "https://app.acme.test/api/orders/{id}",
        ],
    )
    def test_same_object_type_same_id(self, endpoint: str) -> None:
        reference = finding_id(
            "acme", "access_control", "https://app.acme.test/api/orders/1001", "id"
        )
        assert finding_id("acme", "access_control", endpoint, "id") == reference

    @pytest.mark.parametrize(
        ("engagement", "cls", "endpoint", "parameter"),
        [
            ("acme", "access_control", "https://app.acme.test/api/orders/1001", "order_id"),
            ("acme", "access_control", "https://app.acme.test/api/orders/1001", ""),
            ("acme", "api", "https://app.acme.test/api/orders/1001", "id"),
            ("other", "access_control", "https://app.acme.test/api/orders/1001", "id"),
            ("acme", "access_control", "https://app.acme.test/api/invoices/1001", "id"),
            ("acme", "access_control", "https://api.acme.test/api/orders/1001", "id"),
            ("acme", "access_control", "https://app.acme.test:8443/api/orders/1001", "id"),
            # Not an id: a word, a version, a mixed token.
            ("acme", "access_control", "https://app.acme.test/api/orders/latest", "id"),
            ("acme", "access_control", "https://app.acme.test/api/orders/1001a", "id"),
            ("acme", "access_control", "https://app.acme.test/api/orders/1001/items", "id"),
        ],
    )
    def test_anything_else_is_a_different_finding(
        self, engagement: str, cls: str, endpoint: str, parameter: str
    ) -> None:
        reference = finding_id(
            "acme", "access_control", "https://app.acme.test/api/orders/1001", "id"
        )
        assert finding_id(engagement, cls, endpoint, parameter) != reference

    @pytest.mark.parametrize(
        ("raw", "normal"),
        [
            (
                "https://App.Acme.Test/api/users/42/orders/1001?x=1#frag",
                "https://app.acme.test/api/users/{id}/orders/{id}",
            ),
            ("https://app.acme.test:8443/v2/items/7", "https://app.acme.test:8443/v2/items/{id}"),
            ("https://user:pw@app.acme.test/a/1", "https://app.acme.test/a/{id}"),
            ("/api/orders/1001?debug=1", "/api/orders/{id}"),
            ("https://app.acme.test/api/orders/abc123", "https://app.acme.test/api/orders/abc123"),
            ("https://app.acme.test", "https://app.acme.test"),
        ],
    )
    def test_normalisation_is_stable(self, raw: str, normal: str) -> None:
        assert normalize_endpoint(raw) == normal
        assert normalize_endpoint(normal) == normal  # idempotent


class TestValidate:
    def test_a_valid_claim_becomes_the_contract_shape(self) -> None:
        finding = validate(_claim())
        document = finding.to_dict()
        assert list(document) == CONTRACT_KEYS
        assert document["id"] == finding_id(
            "acme", "access_control", "https://app.acme.test/api/orders/1001", "id"
        )
        assert document["endpoint"] == "https://app.acme.test/api/orders/{id}"
        assert document["status"] == "candidate" and document["grade"] is None
        assert document["verification"] == {"at": 0.0, "replay_capture_ids": [], "reasons": []}
        assert document["assertions"] == [
            {
                "capture_id": "cap-aaaaaaaaaaaaaaaa",
                "identity": "bob",
                "expect": {
                    "status": 200,
                    "body_contains": ["alice@"],
                    "body_not_contains": [],
                    "differs_from": "",
                    "same_as": "cap-bbbbbbbbbbbbbbbb",
                },
            }
        ]
        json.dumps(document)
        # A stored document validates back to the same finding.
        assert validate(document) == finding

    def test_enums_cover_the_contract(self) -> None:
        assert STATUSES == (
            "candidate",
            "exploit_verified",
            "source_verified",
            "inconclusive",
            "discarded",
        )
        assert SEVERITIES == ("critical", "high", "medium", "low", "info")
        assert [s.value for s in Status] == list(STATUSES)
        assert [s.value for s in Severity] == list(SEVERITIES)
        assert [c.value for c in VulnClass] == list(CLASSES) and len(CLASSES) == 14

    @pytest.mark.parametrize(
        ("change", "field"),
        [
            ({"title": ""}, "title"),
            ({"title": None}, "title"),
            ({"title": 7}, "title"),
            ({"engagement": ""}, "engagement"),
            ({"engagement": "../other"}, "engagement"),
            ({"class": "idor"}, "class"),
            ({"class": None}, "class"),
            ({"severity": "catastrophic"}, "severity"),
            ({"endpoint": ""}, "endpoint"),
            ({"method": "TRACE"}, "method"),
            ({"cwe": "six-three-nine"}, "cwe"),
            ({"source": ""}, "source"),
            ({"status": "confirmed"}, "status"),
            ({"grade": "ship-it"}, "grade"),
            ({"grade_reasons": "because"}, "grade_reasons"),
            ({"created_at": "yesterday"}, "created_at"),
            ({"verification": []}, "verification"),
            ({"verification": {"replay_capture_ids": "cap-1"}}, "verification.replay_capture_ids"),
            ({"id": "F-000000000000"}, "id"),
            ({"assertions": {"capture_id": "cap-1"}}, "assertions"),
            ({"assertions": ["cap-1"]}, "assertions[0]"),
            ({"assertions": [{"expect": {"status": 200}}]}, "assertions[0].capture_id"),
            ({"assertions": [{"capture_id": "cap-1"}]}, "assertions[0].expect"),
            ({"assertions": [{"capture_id": "cap-1", "expect": {}}]}, "assertions[0].expect"),
            (
                {"assertions": [{"capture_id": "cap-1", "expect": {"status": "200"}}]},
                "assertions[0].expect.status",
            ),
            (
                {"assertions": [{"capture_id": "cap-1", "expect": {"status": True}}]},
                "assertions[0].expect.status",
            ),
            (
                {"assertions": [{"capture_id": "cap-1", "expect": {"status": [200, 999]}}]},
                "assertions[0].expect.status",
            ),
            (
                {"assertions": [{"capture_id": "cap-1", "expect": {"body_contains": [""]}}]},
                "assertions[0].expect.body_contains[0]",
            ),
            (
                {"assertions": [{"capture_id": "cap-1", "expect": {"body_not_contains": 5}}]},
                "assertions[0].expect.body_not_contains",
            ),
            (
                {"assertions": [{"capture_id": "cap-1", "expect": {"same_as": 12}}]},
                "assertions[0].expect.same_as",
            ),
            # A misspelt expectation would otherwise assert nothing.
            (
                {"assertions": [{"capture_id": "cap-1", "expect": {"body_contain": ["x"]}}]},
                "assertions[0].expect.body_contain",
            ),
            (
                {
                    "assertions": [
                        {
                            "capture_id": "cap-1",
                            "expects": {"status": 200},
                            "expect": {"status": 200},
                        }
                    ]
                },
                "assertions[0].expects",
            ),
            (
                {
                    "assertions": [
                        {"capture_id": "cap-1", "expect": {"status": 200}},
                        {"capture_id": "", "expect": {"status": 200}},
                    ]
                },
                "assertions[1].capture_id",
            ),
        ],
    )
    def test_an_error_names_the_field(self, change: dict, field: str) -> None:
        with pytest.raises(ValidationError) as raised:
            validate(_claim(**change))
        assert raised.value.fields == [field]
        assert str(raised.value).startswith(f"{field}: ")

    def test_all_errors_are_reported_at_once(self) -> None:
        with pytest.raises(ValidationError) as raised:
            validate({"title": "x", "severity": "huge", "assertions": [{"expect": {"status": 1}}]})
        assert raised.value.fields == [
            "engagement",
            "class",
            "severity",
            "endpoint",
            "source",
            "assertions[0].capture_id",
            "assertions[0].expect.status",
        ]
        assert all(set(error) == {"field", "message"} for error in raised.value.errors)

    def test_not_an_object(self) -> None:
        with pytest.raises(ValidationError) as raised:
            validate(["not", "a", "finding"])
        assert raised.value.fields == ["finding"]

    def test_tolerated_spellings_are_normalised(self) -> None:
        finding = validate(
            _claim(
                cwe=639,
                severity="High",
                method="get",
                assertions=[
                    {
                        "capture_id": " cap-1 ",
                        "expect": {"status": [200, 206], "body_contains": "alice@"},
                    }
                ],
                unknown_top_level_key="ignored",
            )
        )
        assert (finding.cwe, finding.severity, finding.method) == ("CWE-639", "high", "GET")
        assert finding.assertions[0].capture_id == "cap-1"
        assert finding.assertions[0].expect.statuses() == (200, 206)
        assert finding.assertions[0].expect.body_contains == ("alice@",)
        assert finding.to_dict()["assertions"][0]["expect"]["status"] == [200, 206]
        assert "unknown_top_level_key" not in finding.to_dict()


@pytest.fixture
def store(tmp_path: Path):
    clock = iter(range(1000, 100000))
    opened = FindingStore(tmp_path / "data" / "findings.sqlite3", clock=lambda: float(next(clock)))
    yield opened
    opened.close()


def _finding(**overrides) -> Finding:
    return validate(_claim(**overrides))


class TestStore:
    def test_upsert_get_list_and_filters(self, store: FindingStore) -> None:
        first = store.upsert(_finding(), "agent:hunter")
        second = store.upsert(_finding(parameter="user_id", severity="low"), "probe")
        elsewhere = store.upsert(_finding(engagement="other"), "agent:hunter")
        assert (first.created_at, first.updated_at) == (1000.0, 1000.0)

        assert store.get("acme", first.id) == first
        assert store.get("acme", first.id).to_dict() == first.to_dict()
        assert store.get("acme", "F-000000000000") is None
        # A finding is visible only inside its own engagement.
        assert store.get("other", first.id) is None and store.get("acme", elsewhere.id) is None
        assert [f.id for f in store.list("acme")] == [first.id, second.id]
        assert [f.id for f in store.list("other")] == [elsewhere.id]
        assert store.list("nobody") == []

        store.set_status("acme", second.id, "inconclusive", actor="verifier")
        assert [f.id for f in store.list("acme", status="candidate")] == [first.id]
        assert [f.id for f in store.list("acme", status="inconclusive")] == [second.id]
        assert store.list("acme", status="exploit_verified") == []
        store.upsert(replace(store.get("acme", first.id), grade="hold"), "grader")
        assert [f.id for f in store.list("acme", grade="hold")] == [first.id]
        assert store.list("acme", grade="submit") == []
        assert store.list("acme", status="inconclusive", grade="hold") == []

    def test_one_row_per_id_and_created_at_is_kept(self, store: FindingStore) -> None:
        first = store.upsert(_finding(), "agent:hunter")
        again = store.upsert(replace(first, title="Sharper title", severity="critical"), "agent:b")
        assert again.id == first.id and len(store.list("acme")) == 1
        stored = store.get("acme", first.id)
        assert (stored.title, stored.severity) == ("Sharper title", "critical")
        assert stored.created_at == first.created_at and stored.updated_at > first.updated_at
        assert stored.assertions == first.assertions

    def test_it_survives_a_reopen_and_uses_a_rollback_journal(self, tmp_path: Path) -> None:
        path = tmp_path / "findings.sqlite3"
        first = FindingStore(path)
        saved = first.upsert(_finding(), "agent:hunter")
        first.close()
        second = FindingStore(path)
        assert second.get("acme", saved.id) == saved
        assert [e["event"] for e in second.events("acme", saved.id)] == ["created"]
        second.close()
        raw = sqlite3.connect(path)
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        raw.close()
        assert not Path(str(path) + "-wal").exists()
        reader = FindingStore(path, read_only=True)
        assert reader.get("acme", saved.id) == saved
        with pytest.raises(sqlite3.OperationalError):
            reader.set_status("acme", saved.id, "inconclusive", actor="verifier")
        reader.close()

    @pytest.mark.parametrize("final", ["exploit_verified", "discarded"])
    def test_a_decided_finding_never_goes_back_to_candidate(
        self, store: FindingStore, final: str
    ) -> None:
        finding = store.upsert(_finding(), "agent:hunter")
        store.set_status("acme", finding.id, final, actor="verifier")
        history = store.events("acme", finding.id)

        with pytest.raises(IllegalTransition, match="cannot go back to candidate"):
            store.set_status("acme", finding.id, "candidate", actor="agent:hunter")
        with pytest.raises(IllegalTransition):
            store.upsert(replace(finding, status="candidate", title="again"), "agent:hunter")

        # Nothing was written by the refused changes.
        stored = store.get("acme", finding.id)
        assert stored.status == final and stored.title == finding.title
        assert store.events("acme", finding.id) == history

    def test_other_transitions_are_allowed(self, store: FindingStore) -> None:
        finding = store.upsert(_finding(), "agent:hunter")
        for status in (
            "inconclusive",
            "candidate",  # an undecided finding can be queued again
            "source_verified",
            "candidate",
            "exploit_verified",
            "inconclusive",  # a later replay failed
            "exploit_verified",
            "discarded",
        ):
            assert store.set_status("acme", finding.id, status, actor="verifier").status == status

    def test_unknown_status_and_unknown_finding(self, store: FindingStore) -> None:
        finding = store.upsert(_finding(), "agent:hunter")
        with pytest.raises(IllegalTransition, match="unknown status"):
            store.set_status("acme", finding.id, "confirmed", actor="verifier")
        with pytest.raises(FindingNotFound):
            store.set_status("acme", "F-000000000000", "inconclusive", actor="verifier")
        with pytest.raises(FindingNotFound):  # right id, wrong engagement
            store.set_status("other", finding.id, "inconclusive", actor="verifier")
        assert store.get("acme", finding.id).status == "candidate"

    def test_set_status_stores_the_verification_record(self, store: FindingStore) -> None:
        finding = store.upsert(_finding(), "agent:hunter")
        record = {"at": 5.0, "replay_capture_ids": ["cap-r1"], "reasons": ["all passed"]}
        updated = store.set_status(
            "acme", finding.id, "exploit_verified", actor="verifier", verification=record
        )
        assert updated.verification == record and updated.updated_at > finding.updated_at
        # Without a new record the previous one is kept.
        kept = store.set_status("acme", finding.id, "inconclusive", actor="verifier")
        assert kept.verification == record

    def test_a_forged_id_is_refused(self, store: FindingStore) -> None:
        finding = _finding()
        with pytest.raises(ValueError, match="does not match its content"):
            store.upsert(replace(finding, id="F-000000000000"), "agent:hunter")
        with pytest.raises(ValueError, match="does not match its content"):
            store.upsert(replace(finding, engagement="other"), "agent:hunter")
        assert store.list("acme") == [] and store.list("other") == []


class TestEvents:
    def test_every_change_is_recorded_with_its_actor_in_order(self, store: FindingStore) -> None:
        finding = store.upsert(_finding(), "agent:hunter")
        store.set_status(
            "acme", finding.id, "inconclusive", actor="verifier", detail={"reasons": ["status 403"]}
        )
        store.upsert(replace(store.get("acme", finding.id), severity="critical"), "operator:kim")
        store.add_event("acme", finding.id, "agent:hunter", "note", {"text": "retry later"})

        events = store.events("acme", finding.id)
        assert [(e["actor"], e["event"]) for e in events] == [
            ("agent:hunter", "created"),
            ("verifier", "status"),
            ("operator:kim", "updated"),
            ("agent:hunter", "note"),
        ]
        assert [e["at"] for e in events] == sorted(e["at"] for e in events)
        assert [e["seq"] for e in events] == sorted({e["seq"] for e in events})
        assert all(e["id"] == finding.id for e in events)
        assert events[1]["detail"] == {
            "from": "candidate",
            "to": "inconclusive",
            "reasons": ["status 403"],
        }
        assert events[0]["detail"]["status"] == "candidate"
        # Another finding's history is separate; so is another engagement's.
        other = store.upsert(_finding(parameter="q"), "probe")
        assert [e["actor"] for e in store.events("acme", other.id)] == ["probe"]
        assert store.events("other", finding.id) == []

    @pytest.mark.parametrize("actor", ["", "   ", None])
    def test_a_change_without_an_actor_is_refused(self, store: FindingStore, actor) -> None:
        with pytest.raises(ValueError, match="actor is required"):
            store.upsert(_finding(), actor)
        assert store.list("acme") == []
        finding = store.upsert(_finding(), "agent:hunter")
        with pytest.raises(ValueError, match="actor is required"):
            store.set_status("acme", finding.id, "inconclusive", actor=actor)
        with pytest.raises(ValueError, match="actor is required"):
            store.add_event("acme", finding.id, actor, "note")
        assert store.get("acme", finding.id).status == "candidate"
        assert len(store.events("acme", finding.id)) == 1

    def test_history_cannot_be_rewritten_or_deleted(self, store: FindingStore) -> None:
        finding = store.upsert(_finding(), "agent:hunter")
        store.set_status("acme", finding.id, "discarded", actor="verifier")
        before = store.events("acme", finding.id)
        # The API offers no way to change history...
        assert not [
            name
            for name in dir(store)
            if "event" in name and name.lstrip("_").split("_")[0] in ("delete", "update", "clear")
        ]
        # ...and the database itself refuses, for any connection to the file.
        raw = sqlite3.connect(store.path)
        for statement in (
            "UPDATE finding_events SET actor = 'someone-else'",
            "UPDATE finding_events SET event = 'created' WHERE event = 'status'",
            "DELETE FROM finding_events",
            "DELETE FROM finding_events WHERE event = 'status'",
        ):
            with pytest.raises(sqlite3.DatabaseError, match="append-only"):
                raw.execute(statement)
        raw.rollback()
        raw.close()
        assert store.events("acme", finding.id) == before
        # Appending still works.
        store.add_event("acme", finding.id, "operator:kim", "note")
        assert len(store.events("acme", finding.id)) == len(before) + 1

    def test_an_event_needs_an_existing_finding(self, store: FindingStore) -> None:
        with pytest.raises(FindingNotFound):
            store.add_event("acme", "F-000000000000", "agent:hunter", "note")


class TestPackageHygiene:
    ALLOWED = ("buggy.capture", "buggy.pipeline", "buggy.findings", "buggy_core")

    def test_only_stdlib_and_the_allowed_packages_are_imported(self) -> None:
        package = Path(buggy.findings.__file__).parent
        sources = sorted(package.glob("*.py"))
        assert {p.name for p in sources} >= {
            "__init__.py",
            "model.py",
            "store.py",
            "verifier.py",
            "service.py",
        }
        for source in sources:
            for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    assert node.level == 0, f"{source.name}: relative import"
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    top = name.split(".")[0]
                    allowed = top in sys.stdlib_module_names or any(
                        name == prefix or name.startswith(prefix + ".") for prefix in self.ALLOWED
                    )
                    assert allowed, f"{source.name} imports {name}"
