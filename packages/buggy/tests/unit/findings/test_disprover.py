"""The disprover's verdict (``finding_challenge``), what code makes of it, and the override."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.workbench import Workbench
from buggy.cli.disprover import record_override
from buggy.findings.grade import HOLD, SUBMIT
from buggy.findings.model import validate
from buggy.findings.service import FindingService, read_overrides
from buggy.findings.store import FindingStore

ORDER = "https://app.acme.test/api/orders/1001"


@pytest.fixture
def roots(tmp_path: Path) -> Roots:
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}})
    )
    return roots


@pytest.fixture
def service(roots: Roots) -> Iterator[FindingService]:
    gateway = CaptureGateway(roots, sleep=lambda _s: None)
    store = FindingStore(roots.data / "findings.sqlite3")
    yield FindingService(store, gateway)
    store.close()
    gateway.store.close()


def verified(service: FindingService, source: str = "claude-code") -> str:
    finding = validate(
        {
            "engagement": "acme",
            "title": "IDOR on GET /api/orders/{id}",
            "class": "access_control",
            "severity": "high",
            "endpoint": ORDER,
            "method": "GET",
            "parameter": "id",
            "source": source,
            "remediation": "Check that the order belongs to the caller before returning it.",
        }
    )
    service.store.upsert(replace(finding, status="exploit_verified"), "test")
    return finding.id


def graded(service: FindingService, finding_id: str) -> dict:
    out = service.grade("acme", finding_id)
    assert out["ok"], out
    return out["grade"]


def test_false_positive_holds_a_submitted_finding_at_once(service: FindingService) -> None:
    finding_id = verified(service)
    assert graded(service, finding_id)["decision"] == SUBMIT
    out = service.challenge(
        "acme", finding_id, "false_positive", "cap-x shows Bob's own order", "skeptic"
    )
    assert out["ok"] and out["effect"] == "held", out
    stored = service.store.get("acme", finding_id)
    assert stored is not None and stored.grade == HOLD
    assert stored.grade_reasons[-1].startswith("Rule 9 (disprover): the disprover's verdict")
    assert not any(reason.startswith("Rule 8 ") for reason in stored.grade_reasons)
    shown = out["finding"]["challenge"]
    assert shown["verdict"] == "false_positive" and shown["holds"] and shown["by"] == "skeptic"
    again = graded(service, finding_id)
    assert again["decision"] == HOLD and "buggy-cli disprover override" in again["blocking"][0]


def test_stands_changes_nothing_and_never_lifts_an_objection(service: FindingService) -> None:
    finding_id = verified(service)
    graded(service, finding_id)
    out = service.challenge("acme", finding_id, "stands", "the captures show it", "s1")
    stored = service.store.get("acme", finding_id)
    assert out["effect"] == "none" and stored is not None and stored.grade == SUBMIT
    assert out["finding"]["challenge"]["holds"] is False
    service.challenge("acme", finding_id, "undetermined", "cannot tell", "s2")
    service.challenge("acme", finding_id, "stands", "it does show it", "s3")
    # Two disprovers disagree: the finding stays held.
    assert graded(service, finding_id)["decision"] == HOLD


def test_an_unjudged_finding_reads_as_before(service: FindingService) -> None:
    finding_id = verified(service)
    assert "challenge" not in service.get("acme", finding_id)["finding"]


def test_the_operators_override_lifts_it_until_a_new_objection(service: FindingService) -> None:
    finding_id = verified(service)
    service.challenge("acme", finding_id, "undetermined", "no second user", "s")
    assert graded(service, finding_id)["decision"] == HOLD
    overrides = {finding_id: time.time() + 1}
    service.overrides = lambda _engagement: overrides
    assert graded(service, finding_id)["decision"] == SUBMIT
    overrides[finding_id] = 0.0  # the objection came after the override
    assert graded(service, finding_id)["decision"] == HOLD


def test_a_probe_finding_is_not_the_disprovers(service: FindingService) -> None:
    finding_id = verified(service, source="probe:idor")
    out = service.challenge("acme", finding_id, "false_positive", "no", "skeptic")
    assert out["ok"] is False and out["code"] == "NOT_AGENT_MADE"


@pytest.mark.parametrize(
    ("verdict", "reason", "code"),
    [("maybe", "x", "INVALID"), ("stands", "   ", "INVALID"), ("Stands", "x", "")],
)
def test_bad_verdicts_are_refused(
    service: FindingService, verdict: str, reason: str, code: str
) -> None:
    finding_id = verified(service)
    assert service.challenge("acme", finding_id, verdict, reason, "s").get("code", "") == code
    assert service.challenge("acme", "nope", "stands", "x", "s")["code"] == "UNKNOWN_FINDING"
    assert service.challenge("acme", finding_id, "stands", "x", " ")["code"] == "BAD_ACTOR"


def test_the_workbench_reads_the_operators_overrides(roots: Roots) -> None:
    bench = Workbench(CaptureGateway(roots, sleep=lambda _s: None), None, lambda name: name)
    try:
        finding_id = verified(bench.findings)
        out = bench.finding_challenge("acme", finding_id, "false_positive", "own data", "sk")
        assert out["ok"] and out["finding"]["challenge"]["holds"]
        assert bench.finding_grade("acme", finding_id)["grade"]["decision"] == HOLD
        time.sleep(0.01)
        record_override(roots.control, "acme", finding_id, "it stands: cap-2 is Alice's", "op")
        assert bench.finding_grade("acme", finding_id)["grade"]["decision"] == SUBMIT
    finally:
        bench.close()
        bench.gateway.store.close()


def test_override_file_reading(tmp_path: Path) -> None:
    record_override(tmp_path, "acme", "f-1", "it stands", operator="op")
    with (tmp_path / "acme" / "disprover-overrides.jsonl").open("a") as handle:
        handle.write("garbage\n" + json.dumps({"finding_id": "f-2", "at": "soon"}) + "\n")
    assert set(read_overrides(tmp_path, "acme")) == {"f-1"}
    assert read_overrides(tmp_path, "none") == {}
