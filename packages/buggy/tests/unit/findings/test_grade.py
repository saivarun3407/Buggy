"""The grader: submit, hold or discard, with the rule named in every reason.

Each rule has a case that fires it and a control of the same shape that does
not. The scope is a real ``ScopeFilter``; the service tests go through a real
``CaptureGateway`` over a fake origin and a real ``FindingStore``.
"""

from __future__ import annotations

import io
import json
import re
import urllib.error
from dataclasses import replace
from pathlib import Path

import pytest

from benchmark.lab.taxonomy import CWE_TO_CLASS as LAB_CWE_TO_CLASS
from buggy.capture.gateway import CaptureGateway, Roots
from buggy.findings import grade as grader
from buggy.findings.grade import (
    BANNED_TECHNIQUES,
    DISCARD,
    HOLD,
    MIN_REMEDIATION_CHARS,
    RULES,
    SUBMIT,
    Grade,
    grade,
    known_issue_class,
    remediation_problem,
    same_endpoint,
    severity_cap,
)
from buggy.findings.model import CLASSES, Finding, validate
from buggy.findings.service import FindingService
from buggy.findings.store import FindingStore
from buggy.pipeline.scope import ScopeFilter
from buggy.pipeline.tools.nuclei import Nuclei
from buggy.program import gate
from buggy.program.record import BASELINE_BANNED_TECHNIQUES

ORDER = "https://app.acme.test/api/orders/1001"
REMEDIATION = "Check that the order belongs to the caller before returning it."
REASON = re.compile(r"^Rule ([1-8]) \(([a-z ]+)\): [A-Za-z][^\n]*\.$")


def _scope(*hosts: str) -> ScopeFilter:
    return ScopeFilter.from_document(
        {"machine_enforcement": {"mode": "enforce", "in_scope": list(hosts or ("app.acme.test",))}}
    )


SCOPE = _scope()
PROGRAM = {
    "platform": "hackerone",
    "handle": "acme",
    "excluded_classes": ["Self-XSS", "Clickjacking on pages with no sensitive actions", "xss"],
    "severity_caps": {},
}


def _finding(**overrides) -> Finding:
    """An exploit-verified high IDOR on an in-scope host with a real remediation."""
    status = overrides.pop("status", "exploit_verified")
    grade_ = overrides.pop("grade", None)
    built = validate(
        {
            "engagement": "acme",
            "title": "IDOR on GET /api/orders/{id}",
            "class": "access_control",
            "cwe": "CWE-639",
            "severity": "high",
            "endpoint": ORDER,
            "method": "GET",
            "parameter": "id",
            "source": "agent:hunter",
            "description": "Bob can read Alice's order by id.",
            "remediation": REMEDIATION,
            **overrides,
        }
    )
    return replace(built, status=status, grade=grade_)


def _scanner_hit(
    template_id: str = "idor-order-read",
    matched_at: str = "https://app.acme.test/api/orders/1001",
    **attrs,
) -> dict:
    """A recon ``vulnerability`` record as ``StoredRecord.to_dict`` returns it."""
    return {
        "id": "rec-1",
        "engagement": "acme",
        "asset": "app.acme.test",
        "type": "vulnerability",
        "value": f"{template_id} {matched_at}",
        "attrs": {
            "template_id": template_id,
            "matched_at": matched_at,
            "severity": "high",
            "cwe": ["CWE-639"],
            **attrs,
        },
        "source_tool": "nuclei",
        "status": "active",
    }


def _grade(finding: Finding | None = None, **inputs) -> Grade:
    return grade(
        finding if finding is not None else _finding(),
        program=inputs.get("program"),
        scope=inputs.get("scope", SCOPE),
        known_issues=inputs.get("known_issues", []),
        prior=inputs.get("prior", []),
    )


def _rules(outcome: Grade) -> list[int]:
    return [int(REASON.match(reason).group(1)) for reason in outcome.reasons]


class TestSubmit:
    def test_verified_high_idor_in_scope_with_a_remediation_is_submitted(self) -> None:
        outcome = _grade(program=PROGRAM)
        assert outcome.decision == SUBMIT
        assert _rules(outcome) == [8]
        assert "ready to submit" in outcome.reasons[0]
        assert outcome.blocking == []
        assert outcome.capped_severity is None

    def test_it_is_submitted_without_a_program_record_too(self) -> None:
        assert _grade(program=None).decision == SUBMIT

    def test_the_scope_is_required(self) -> None:
        with pytest.raises(ValueError, match="scope is required"):
            grade(_finding(), program=None, scope=None, known_issues=[], prior=[])


# One row per rule: (name, finding overrides, inputs, decision, rules fired, text in the reason).
# ``None`` as the text means "no rule but rule 8": the row is a negative control.
CASES = [
    # 1. verification
    ("candidate", {"status": "candidate"}, {}, HOLD, [1], "not exploit-verified: candidate"),
    (
        "inconclusive",
        {"status": "inconclusive"},
        {},
        HOLD,
        [1],
        "not exploit-verified: inconclusive",
    ),
    (
        "source-verified is not exploit-verified",
        {"status": "source_verified"},
        {},
        HOLD,
        [1],
        "not exploit-verified: source_verified",
    ),
    ("discarded", {"status": "discarded"}, {}, DISCARD, [1], "not exploit-verified: discarded"),
    # 2. scope
    (
        "host left the scope",
        {},
        {"scope": _scope("other.acme.test")},
        DISCARD,
        [2],
        "out of scope now: app.acme.test",
    ),
    (
        "sibling host is not the scoped host",
        {"endpoint": "https://admin.acme.test/api/orders/1001"},
        {},
        DISCARD,
        [2],
        "out of scope now: admin.acme.test",
    ),
    ("wildcard scope covers the host", {}, {"scope": _scope("**.acme.test")}, SUBMIT, [8], None),
    # 3. program exclusions and banned techniques
    (
        "excluded class named in the title",
        {"title": "Self-XSS in profile name", "class": "xss"},
        {"program": PROGRAM},
        DISCARD,
        [3],
        "the program does not accept this class: 'Self-XSS'",
    ),
    (
        "excluded class matches the class name",
        {"title": "Login sends users to any site", "class": "open_redirect"},
        {"program": {"excluded_classes": ["Open Redirect"]}},
        DISCARD,
        [3],
        "the program does not accept this class: 'Open Redirect'",
    ),
    (
        "an exclusion shorter than four characters is not applied",
        {"title": "Stored XSS in comments", "class": "xss"},
        {"program": PROGRAM},
        SUBMIT,
        [8],
        None,
    ),
    (
        "an exclusion that names something else",
        {},
        {"program": {"excluded_classes": ["Self-XSS", "Rate limiting"]}},
        SUBMIT,
        [8],
        None,
    ),
    (
        "denial of service",
        {"title": "Application-layer DoS via nested query", "class": "graphql"},
        {},
        DISCARD,
        [3],
        "denial of service (denial_of_service) is a banned technique",
    ),
    (
        "social engineering",
        {"title": "Phishing page accepted by support", "class": "business_logic"},
        {"program": PROGRAM},
        DISCARD,
        [3],
        "social engineering (social_engineering) is a banned technique",
    ),
    (
        "physical access",
        {"title": "Badge reader allows physical access", "class": "auth_session"},
        {},
        DISCARD,
        [3],
        "physical access (physical) is a banned technique",
    ),
    (
        "a path that merely contains the letters dos",
        {"title": "IDOR on GET /api/todos/{id}", "endpoint": "https://app.acme.test/api/todos/7"},
        {"program": PROGRAM},
        SUBMIT,
        [8],
        None,
    ),
    # 4. remediation
    ("no remediation", {"remediation": ""}, {}, HOLD, [4], "the finding has no remediation"),
    (
        "short remediation",
        {"remediation": "Check ownership."},
        {},
        HOLD,
        [4],
        "the remediation is 16 characters long and at least 30 are needed",
    ),
    (
        "placeholder padded past the minimum length",
        {"remediation": "TBD" + "." * 40},
        {},
        HOLD,
        [4],
        "the remediation is a placeholder",
    ),
    ("exactly the minimum length", {"remediation": "x" * 30}, {}, SUBMIT, [8], None),
    # 5. duplicates and known issues
    (
        "already submitted",
        {},
        {"prior": [_finding(grade="submit")]},
        DISCARD,
        [5],
        "duplicate of " + _finding().id,
    ),
    ("same id but only held before", {}, {"prior": [_finding(grade="hold")]}, SUBMIT, [8], None),
    (
        "a submitted finding on another endpoint",
        {},
        {"prior": [_finding(endpoint="https://app.acme.test/api/users/7", grade="submit")]},
        SUBMIT,
        [8],
        None,
    ),
    (
        "known to the scanner",
        {},
        {"known_issues": [_scanner_hit()]},
        HOLD,
        [5],
        "already reported by scanner template idor-order-read: confirm it is not a "
        "known/accepted issue",
    ),
    (
        "known to the scanner at another object id and with a query string",
        {},
        {"known_issues": [_scanner_hit(matched_at="https://APP.acme.test:443/api/orders/7?x=1")]},
        HOLD,
        [5],
        "already reported by scanner template idor-order-read",
    ),
    (
        "scanner hit of the same class on a different endpoint",
        {},
        {"known_issues": [_scanner_hit(matched_at="https://app.acme.test/api/users/7")]},
        SUBMIT,
        [8],
        None,
    ),
    (
        "scanner hit on the same path of another host",
        {},
        {"known_issues": [_scanner_hit(matched_at="https://shop.acme.test/api/orders/1001")]},
        SUBMIT,
        [8],
        None,
    ),
    (
        "scanner hit of another class on the same endpoint",
        {},
        {"known_issues": [_scanner_hit("cors-misconfig", cwe=["CWE-942"], tags=["cors"])]},
        SUBMIT,
        [8],
        None,
    ),
    (
        "a recon record that is not a vulnerability",
        {},
        {"known_issues": [{**_scanner_hit(), "type": "endpoint"}]},
        SUBMIT,
        [8],
        None,
    ),
    # 6. severity cap
    (
        "severity above the cap",
        {"severity": "critical"},
        {"program": {"severity_caps": {"app.acme.test": "medium"}}},
        SUBMIT,
        [6, 8],
        "severity capped to medium: the program caps app.acme.test at medium and this "
        "finding claims critical",
    ),
    (
        "severity at the cap",
        {"severity": "high"},
        {"program": {"severity_caps": {"app.acme.test": "high"}}},
        SUBMIT,
        [8],
        None,
    ),
    (
        "a cap for another host",
        {"severity": "critical"},
        {"program": {"severity_caps": {"shop.acme.test": "low"}}},
        SUBMIT,
        [8],
        None,
    ),
    # 7. low signal
    (
        "info",
        {"severity": "info"},
        {},
        HOLD,
        [7],
        "low signal: most programs do not pay for this (severity info)",
    ),
    (
        "low misconfiguration",
        {"class": "misconfiguration", "severity": "low", "title": "Permissive CORS on /api"},
        {},
        HOLD,
        [7],
        "low signal: most programs do not pay for this (a misconfiguration at low severity)",
    ),
    (
        "medium misconfiguration",
        {"class": "misconfiguration", "severity": "medium", "title": "Permissive CORS on /api"},
        {},
        SUBMIT,
        [8],
        None,
    ),
    ("low access control", {"severity": "low"}, {}, SUBMIT, [8], None),
]


class TestEachRule:
    @pytest.mark.parametrize(
        ("overrides", "inputs", "decision", "rules", "text"),
        [pytest.param(*case[1:], id=case[0]) for case in CASES],
    )
    def test_rule(
        self, overrides: dict, inputs: dict, decision: str, rules: list, text: str | None
    ) -> None:
        outcome = _grade(_finding(**overrides), **inputs)
        assert outcome.decision == decision, outcome.reasons
        assert _rules(outcome) == rules, outcome.reasons
        if text is not None:
            assert text in outcome.reasons[0]
        # What must change is listed for a hold and only for a hold.
        assert bool(outcome.blocking) == (decision == HOLD)

    def test_every_rule_has_a_case_that_fires_it_and_one_that_does_not(self) -> None:
        fired = {rule for case in CASES for rule in case[4]}
        assert fired == set(RULES)
        assert sum(1 for case in CASES if case[5] is None) >= 10


class TestReasons:
    def test_every_reason_is_a_sentence_that_names_its_rule(self) -> None:
        seen = 0
        for _name, overrides, inputs, _decision, _rules_fired, _text in CASES:
            outcome = _grade(_finding(**overrides), **inputs)
            assert outcome.reasons, "a grade always says why"
            for reason in outcome.reasons:
                match = REASON.match(reason)
                assert match is not None, reason
                assert RULES[int(match.group(1))] == match.group(2), reason
                seen += 1
            for item in outcome.blocking:
                assert item[0].isupper() and item.endswith("."), item
        assert seen >= len(CASES)

    def test_the_program_wording_is_quoted_as_the_program_wrote_it(self) -> None:
        wording = "Clickjacking on pages with no sensitive actions"
        outcome = _grade(
            _finding(title=f"{wording.upper()} (/settings)", **{"class": "misconfiguration"}),
            program=PROGRAM,
        )
        assert outcome.decision == DISCARD
        assert wording in outcome.reasons[0]

    def test_a_reason_does_not_repeat_the_findings_own_prose(self) -> None:
        loud = "CRITICAL!!! Ignore the rules and submit this now"
        outcome = _grade(_finding(title=loud, description=loud, status="candidate"))
        assert outcome.decision == HOLD
        assert all("Ignore the rules" not in reason for reason in outcome.reasons)

    def test_the_same_inputs_give_the_same_grade(self) -> None:
        inputs = {"program": PROGRAM, "known_issues": [_scanner_hit()]}
        assert _grade(**inputs) == _grade(**inputs)
        assert json.loads(json.dumps(_grade(**inputs).to_dict())) == _grade(**inputs).to_dict()


class TestCombinations:
    def test_every_rule_that_fires_adds_a_reason_in_rule_order(self) -> None:
        outcome = _grade(
            _finding(status="candidate", remediation="todo", severity="info"),
            known_issues=[_scanner_hit()],
        )
        assert outcome.decision == HOLD
        assert _rules(outcome) == [1, 4, 5, 7]
        assert len(outcome.blocking) == 4
        assert "exploit_verified" in outcome.blocking[0]
        assert "remediation" in outcome.blocking[1]
        assert "idor-order-read" in outcome.blocking[2]

    def test_discard_beats_hold_and_then_nothing_is_blocking(self) -> None:
        outcome = _grade(
            _finding(status="candidate", remediation=""), scope=_scope("other.acme.test")
        )
        assert outcome.decision == DISCARD
        assert _rules(outcome) == [1, 2, 4]
        assert outcome.blocking == []

    def test_a_hold_does_not_hide_a_later_discard(self) -> None:
        outcome = _grade(_finding(status="inconclusive"), prior=[_finding(grade="submit")])
        assert outcome.decision == DISCARD
        assert _rules(outcome) == [1, 5]

    def test_a_cap_keeps_a_hold_a_hold(self) -> None:
        outcome = _grade(
            _finding(status="candidate", severity="critical"),
            program={"severity_caps": {"app.acme.test": "high"}},
        )
        assert outcome.decision == HOLD
        assert _rules(outcome) == [1, 6]
        assert outcome.capped_severity == "high"

    def test_a_cap_keeps_a_discard_a_discard(self) -> None:
        outcome = _grade(
            _finding(severity="critical", title="Self-XSS in profile name"),
            program={"excluded_classes": ["Self-XSS"], "severity_caps": {"app.acme.test": "low"}},
        )
        assert outcome.decision == DISCARD
        assert _rules(outcome) == [3, 6]
        assert outcome.capped_severity == "low"

    def test_low_signal_is_judged_on_the_capped_severity(self) -> None:
        program = {"severity_caps": {"app.acme.test": "info"}}
        outcome = _grade(_finding(severity="high"), program=program)
        assert outcome.decision == HOLD
        assert _rules(outcome) == [6, 7]
        assert outcome.capped_severity == "info"
        # Control: the same finding without that cap is submitted.
        assert _grade(_finding(severity="high"), program={"severity_caps": {}}).decision == SUBMIT

    def test_two_exclusions_and_a_banned_technique_are_all_named(self) -> None:
        outcome = _grade(
            _finding(title="Self-XSS leads to DoS of the rate limiting service"),
            program={"excluded_classes": ["Self-XSS", "Rate limiting"]},
        )
        assert outcome.decision == DISCARD
        assert _rules(outcome) == [3, 3, 3]
        assert "'Self-XSS'" in outcome.reasons[0]
        assert "'Rate limiting'" in outcome.reasons[1]
        assert "denial_of_service" in outcome.reasons[2]

    def test_two_scanner_templates_are_two_reasons_and_a_repeat_is_one(self) -> None:
        hits = [_scanner_hit(), _scanner_hit(), _scanner_hit("bola-generic", tags=["bola"])]
        outcome = _grade(known_issues=hits)
        assert outcome.decision == HOLD
        assert _rules(outcome) == [5, 5]
        assert "idor-order-read" in outcome.reasons[0] and "bola-generic" in outcome.reasons[1]


class TestScopeRule:
    def test_a_bare_path_endpoint_cannot_be_scope_checked_and_is_held(self) -> None:
        outcome = _grade(_finding(endpoint="/api/orders/1001"))
        assert outcome.decision == HOLD
        assert _rules(outcome) == [2]
        assert "names no host" in outcome.reasons[0]
        assert "absolute URL" in outcome.blocking[0]

    def test_the_scope_is_asked_about_the_endpoints_host(self) -> None:
        asked: list[str] = []

        class Recording:
            def allows(self, candidate: str) -> bool:
                asked.append(candidate)
                return candidate == "app.acme.test"

        assert _grade(scope=Recording()).decision == SUBMIT
        assert asked == ["app.acme.test"]
        assert _grade(_finding(endpoint="https://evil.test/x"), scope=Recording()).decision == (
            DISCARD
        )

    def test_an_out_of_scope_list_entry_wins_over_a_wildcard(self) -> None:
        scope = ScopeFilter.from_document(
            {
                "machine_enforcement": {
                    "mode": "enforce",
                    "in_scope": ["**.acme.test"],
                    "out_of_scope": ["app.acme.test"],
                }
            }
        )
        assert _grade(scope=scope).decision == DISCARD
        other = _finding(endpoint="https://shop.acme.test/api/orders/1001")
        assert _grade(other, scope=scope).decision == SUBMIT


class TestProgramRecord:
    def test_an_unreadable_program_record_holds_instead_of_dropping_the_program_rules(
        self,
    ) -> None:
        outcome = _grade(program={"_invalid": "program.json is not valid JSON"})
        assert outcome.decision == HOLD
        assert _rules(outcome) == [3]
        assert "unreadable" in outcome.reasons[0]
        assert "Re-import" in outcome.blocking[0]

    @pytest.mark.parametrize(
        "program",
        [{}, {"excluded_classes": None, "severity_caps": None}, {"excluded_classes": "Self-XSS"}],
    )
    def test_a_program_without_usable_lists_excludes_nothing(self, program: dict) -> None:
        assert _grade(_finding(title="Self-XSS in profile name"), program=program).decision == (
            SUBMIT
        )


class TestSeverityCap:
    @pytest.mark.parametrize(
        ("caps", "host", "expected"),
        [
            ({"app.acme.test": "medium"}, "app.acme.test", "medium"),
            ({"APP.Acme.Test.": "Medium"}, "app.acme.test", "medium"),
            ({"*.acme.test": "low"}, "app.acme.test", "low"),
            ({"*.acme.test": "low"}, "a.b.acme.test", "low"),
            ({"**.acme.test": "low"}, "a.b.acme.test", "low"),
            ({"*.acme.test": "low"}, "acme.test", ""),  # a wildcard does not cover the apex
            ({"*.acme.test": "low"}, "notacme.test", ""),
            ({"*.acme.test": "low", "app.acme.test": "high"}, "app.acme.test", "high"),
            ({"*.acme.test": "high", "*.eu.acme.test": "low"}, "a.eu.acme.test", "low"),
            ({"10.0.0.0/24": "medium"}, "10.0.0.7", "medium"),
            ({"10.0.0.0/24": "medium"}, "10.0.1.7", ""),
            ({"app.acme.test": "none"}, "app.acme.test", ""),  # not a severity: ignored
            ({"app.acme.test": "medium"}, "", ""),
        ],
    )
    def test_which_cap_applies(self, caps: dict, host: str, expected: str) -> None:
        assert severity_cap({"severity_caps": caps}, host)[0] == expected

    def test_a_wildcard_cap_is_applied_and_reported(self) -> None:
        program = {"severity_caps": {"*.acme.test": "medium"}}
        outcome = _grade(_finding(severity="high"), program=program)
        assert (outcome.decision, outcome.capped_severity) == (SUBMIT, "medium")
        assert "the program caps *.acme.test at medium" in outcome.reasons[0]
        # Control: a finding at or below the cap is not reported as capped.
        below = _grade(_finding(severity="low"), program=program)
        assert (below.decision, below.capped_severity) == (SUBMIT, None)

    def test_the_cap_does_not_rewrite_the_finding(self) -> None:
        finding = _finding(severity="critical")
        _grade(finding, program={"severity_caps": {"app.acme.test": "low"}})
        assert finding.severity == "critical" and finding.grade is None


class TestDuplicates:
    def test_the_finding_itself_in_prior_is_not_its_own_duplicate(self) -> None:
        stored = replace(_finding(grade="submit"), created_at=1700000000.5)
        assert _grade(stored, prior=[stored]).decision == SUBMIT
        # The same row read back from the store is a different object with the same birth.
        assert _grade(stored, prior=[replace(stored)]).decision == SUBMIT
        # Control: an earlier record with that id, submitted elsewhere, is a duplicate.
        earlier = replace(stored, created_at=1600000000.0)
        assert _grade(stored, prior=[earlier]).decision == DISCARD

    def test_the_duplicate_is_decided_on_the_stable_id(self) -> None:
        # Another object id and a query string are the same finding id.
        again = _finding(endpoint="https://app.acme.test/api/orders/2002?x=1", grade="submit")
        outcome = _grade(prior=[again])
        assert outcome.decision == DISCARD
        assert outcome.reasons == [
            f"Rule 5 (duplicates): duplicate of {again.id}, which is already graded submit."
        ]
        # Control: another parameter is another finding.
        other = _finding(parameter="order_id", grade="submit")
        assert _grade(prior=[other]).decision == SUBMIT


class TestKnownIssues:
    @pytest.mark.parametrize(
        ("entry", "expected"),
        [
            (_scanner_hit(cwe=["CWE-639"]), "access_control"),
            (_scanner_hit(cwe=["cwe-79"]), "xss"),
            (_scanner_hit(cwe=[], tags=["sqli", "cve"]), "injection"),
            (_scanner_hit("open-redirect-generic", cwe=[], tags=[]), "open_redirect"),
            (_scanner_hit(cwe=[], tags=["tech"]), "access_control"),  # "idor" in the id
            (_scanner_hit("nginx-version", cwe=[], tags=["tech"]), ""),
            ({**_scanner_hit(cwe=["CWE-79"]), "class": "csrf"}, "csrf"),  # explicit wins
            ({**_scanner_hit(cwe=["CWE-79"]), "class": "not-a-class"}, "xss"),
        ],
    )
    def test_class_of_a_scanner_record(self, entry: dict, expected: str) -> None:
        assert known_issue_class(entry) == expected

    def test_the_cwe_table_is_the_lab_taxonomys(self) -> None:
        assert grader.CWE_TO_CLASS == LAB_CWE_TO_CLASS
        assert set(grader.CWE_TO_CLASS.values()) <= set(CLASSES)

    @pytest.mark.parametrize(
        ("endpoint", "other", "same"),
        [
            (ORDER, "https://app.acme.test/api/orders/9", True),
            (ORDER, "https://app.acme.test:443/api/orders/9/", True),
            (ORDER, "https://app.acme.test:8443/api/orders/9", False),
            (ORDER, "http://app.acme.test/api/orders/9", False),
            (ORDER, "https://app.acme.test/api/orders", False),
            (ORDER, "https://app.acme.test", False),
            (ORDER, "app.acme.test:443", False),
            ("/api/orders/1001", "https://app.acme.test/api/orders/9", True),
            ("/api/orders/1001", "https://app.acme.test/api/users/9", False),
        ],
    )
    def test_same_endpoint(self, endpoint: str, other: str, same: bool) -> None:
        assert same_endpoint(endpoint, other) is same

    def test_a_record_parsed_from_real_scanner_output_is_recognised(self) -> None:
        line = {
            "template-id": "idor-order-read",
            "matched-at": "https://app.acme.test/api/orders/55?debug=1",
            "host": "https://app.acme.test",
            "type": "http",
            "info": {
                "name": "Order readable by any user",
                "severity": "high",
                "tags": ["idor", "acme"],
                "classification": {"cwe-id": ["CWE-639"]},
            },
        }
        elsewhere = {**line, "matched-at": "https://app.acme.test/api/invoices/55"}
        raw = json.dumps(line) + "\n" + json.dumps(elsewhere) + "\n"
        records = [
            {"type": r.type.value, "asset": r.asset, "value": r.value, "attrs": r.attrs}
            for r in Nuclei().parse(raw)
        ]
        assert len(records) == 2
        outcome = _grade(known_issues=records)
        assert outcome.decision == HOLD and _rules(outcome) == [5]
        # Negative control: the unrelated hit alone does not hold the finding.
        assert _grade(known_issues=records[1:]).decision == SUBMIT

    def test_malformed_entries_are_ignored(self) -> None:
        junk = [None, "idor", 7, {}, {"attrs": "x"}, {"type": "vulnerability", "value": ""}]
        assert _grade(known_issues=junk).decision == SUBMIT


class TestSameRulesAsTheProgramGate:
    """``grade.py`` may not import ``buggy.program``; these keep its copies honest."""

    REMEDIATIONS = (
        "",
        "   ",
        "TBD",
        "todo",
        "N/A",
        "n/a.",
        "see above",
        "fix it!",
        "Check ownership.",
        "x" * 29,
        "x" * 30,
        "TBD" + "." * 40,
        REMEDIATION,
        "  " + REMEDIATION + "  ",
    )

    def test_the_remediation_rule_agrees_with_the_gate(self) -> None:
        assert MIN_REMEDIATION_CHARS == gate.MIN_REMEDIATION_CHARS
        verdicts = []
        for text in self.REMEDIATIONS:
            errors = gate.finding_errors({"remediation": text}, {}, lambda _c, _t: {})
            refused = any(error.startswith("remediation is required") for error in errors)
            assert bool(remediation_problem(text)) is refused, repr(text)
            verdicts.append(refused)
        assert True in verdicts and False in verdicts

    def test_the_banned_techniques_are_baseline_ones(self) -> None:
        baseline = {entry["id"] for entry in BASELINE_BANNED_TECHNIQUES}
        assert {technique for technique, _words, _pattern in BANNED_TECHNIQUES} <= baseline
        assert {t for t, _w, _p in BANNED_TECHNIQUES} == set(gate._BANNED_CLASS_MARKERS)

    def test_the_gate_and_the_grader_refuse_the_same_words(self) -> None:
        # Both match whole words with the same patterns, so they cannot disagree.
        patterns = {technique: pattern.pattern for technique, _w, pattern in BANNED_TECHNIQUES}
        assert patterns == {t: p.pattern for t, p in gate._BANNED_CLASS_MARKERS.items()}
        samples = {
            "denial_of_service": [
                "dos",
                "ddos",
                "redos",
                "denial of service",
                "resource exhaustion",
            ],
            "social_engineering": ["phishing", "vishing", "social engineering"],
            "physical": ["physical access", "physical security"],
        }
        for technique, words in samples.items():
            for word in words:
                found = grader.banned_matches(_finding(title=f"Report about {word} on login"))
                assert [hit[0] for hit in found] == [technique], word
                assert gate._BANNED_CLASS_MARKERS[technique].search(f"report about {word} on login")


# ── the service ─────────────────────────────────────────────────────


class Site:
    """A fake origin (copied from ``tests/unit/capture/test_gateway.py``)."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], object] = {}
        self.seen: list[tuple[str, str]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        self.seen.append((method, url))
        route = self.routes.get((method, url), (404, b"not found"))
        status, payload = route(headers, request.data or b"") if callable(route) else route
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", {}, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, {"Content-Type": "application/json"}
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


ALICE_ORDER = {"id": 1001, "owner": "alice@acme.test", "items": ["thinkpad x1", "usb-c dock"]}


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.roots = Roots(
            control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data"
        )
        self.set_scope("app.acme.test")
        self.site = Site()
        # The IDOR: any logged-in user can read Alice's order.
        self.site.routes[("GET", ORDER)] = lambda headers, _b: (
            (200, ALICE_ORDER) if headers.get("authorization") else (401, {"error": "login"})
        )
        self.gateway = CaptureGateway(self.roots, opener=self.site, sleep=lambda _s: None)
        self.store = FindingStore(self.roots.data / "findings.sqlite3")
        self.service = FindingService(self.store, self.gateway)

    def set_scope(self, *hosts: str) -> None:
        path = self.roots.control / "acme" / "roe.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": list(hosts)}})
        )

    def close(self) -> None:
        self.gateway.store.close()
        self.store.close()

    def claim(self, **overrides) -> dict:
        owner = self.gateway.send(
            "acme", "GET", ORDER, headers={"Authorization": "Bearer alice"}, note="owner"
        )
        attacker = self.gateway.send(
            "acme", "GET", ORDER, headers={"Authorization": "Bearer bob"}, note="attacker"
        )
        return {
            "title": "IDOR on GET /api/orders/{id}",
            "class": "access_control",
            "cwe": "CWE-639",
            "severity": "high",
            "endpoint": ORDER,
            "parameter": "id",
            "source": "agent:hunter",
            "remediation": REMEDIATION,
            "assertions": [
                {
                    "capture_id": owner.id,
                    "identity": "alice",
                    "expect": {"status": 200, "body_contains": ["alice@acme.test"]},
                },
                {
                    "capture_id": attacker.id,
                    "identity": "bob",
                    "expect": {"status": 200, "same_as": owner.id},
                },
            ],
            **overrides,
        }

    def submitted(self, **overrides) -> str:
        out = self.service.submit("acme", self.claim(**overrides), "agent:hunter")
        assert out["ok"], out
        return out["finding"]["id"]

    def verified(self, **overrides) -> str:
        finding_id = self.submitted(**overrides)
        out = self.service.verify("acme", finding_id)
        assert out["finding"]["status"] == "exploit_verified", out
        return finding_id


@pytest.fixture
def env(tmp_path: Path):
    environment = Env(tmp_path)
    yield environment
    environment.close()


class TestService:
    def test_a_verified_finding_is_graded_submit_and_the_grade_is_stored(self, env: Env) -> None:
        finding_id = env.verified()
        out = env.service.grade("acme", finding_id, program=PROGRAM, actor="operator:kim")
        assert out["ok"] is True
        assert out["grade"]["decision"] == "submit"
        assert out["grade"]["blocking"] == [] and out["grade"]["capped_severity"] is None
        assert out["finding"]["grade"] == "submit"
        assert out["finding"]["grade_reasons"] == out["grade"]["reasons"]
        assert out["finding"]["status"] == "exploit_verified"
        json.dumps(out)

        stored = env.store.get("acme", finding_id)
        assert stored.grade == "submit" and list(stored.grade_reasons) == out["grade"]["reasons"]
        assert [f.id for f in env.store.list("acme", grade="submit")] == [finding_id]
        event = env.store.events("acme", finding_id)[-1]
        assert (event["event"], event["actor"]) == ("graded", "operator:kim")
        assert event["detail"]["grade"] == "submit"
        assert event["detail"]["previous_grade"] is None
        assert event["detail"]["reasons"] == out["grade"]["reasons"]

    def test_an_unverified_finding_is_held_and_grading_does_not_verify_it(self, env: Env) -> None:
        finding_id = env.submitted()
        sent = len(env.site.seen)
        out = env.service.grade("acme", finding_id)
        assert out["grade"]["decision"] == "hold"
        assert out["grade"]["reasons"][0].startswith(
            "Rule 1 (verification): not exploit-verified: candidate"
        )
        assert out["grade"]["blocking"]
        assert out["finding"]["status"] == "candidate" and out["finding"]["grade"] == "hold"
        assert len(env.site.seen) == sent, "grading sends nothing to the target"
        assert env.store.list("acme", grade="submit") == []

    def test_the_grade_follows_the_inputs_and_each_grading_is_an_event(self, env: Env) -> None:
        finding_id = env.verified()
        held = env.service.grade("acme", finding_id, known_issues=[_scanner_hit()])
        assert held["grade"]["decision"] == "hold"
        assert "idor-order-read" in held["grade"]["reasons"][0]
        # The operator confirmed it is not a known issue: graded again without the record.
        again = env.service.grade("acme", finding_id, known_issues=[])
        assert again["grade"]["decision"] == "submit"
        graded = [e for e in env.store.events("acme", finding_id) if e["event"] == "graded"]
        assert [e["detail"]["grade"] for e in graded] == ["hold", "submit"]
        assert graded[1]["detail"]["previous_grade"] == "hold"
        assert graded[0]["detail"]["known_issues"] == 1

    def test_a_host_that_left_the_scope_is_discarded_with_the_scope_read_at_grading(
        self, env: Env
    ) -> None:
        finding_id = env.verified()
        assert env.service.grade("acme", finding_id)["grade"]["decision"] == "submit"
        env.set_scope("other.acme.test")
        out = env.service.grade("acme", finding_id)
        assert out["grade"]["decision"] == "discard"
        assert "out of scope now: app.acme.test" in out["grade"]["reasons"][0]
        # The grade is a separate field: the verifier's status is not rewritten.
        assert out["finding"]["status"] == "exploit_verified"

    def test_the_severity_cap_is_returned_and_recorded_but_the_claim_is_kept(
        self, env: Env
    ) -> None:
        finding_id = env.verified(severity="critical")
        program = {"severity_caps": {"app.acme.test": "medium"}}
        out = env.service.grade("acme", finding_id, program=program)
        assert out["grade"]["decision"] == "submit"
        assert out["grade"]["capped_severity"] == "medium"
        assert out["finding"]["severity"] == "critical"
        assert env.store.events("acme", finding_id)[-1]["detail"]["capped_severity"] == "medium"

    def test_grading_again_with_the_stores_own_list_is_not_a_duplicate(self, env: Env) -> None:
        finding_id = env.verified()
        assert env.service.grade("acme", finding_id)["grade"]["decision"] == "submit"
        out = env.service.grade("acme", finding_id, prior=env.store.list("acme"))
        assert out["grade"]["decision"] == "submit"
        # Control: the same finding already submitted from another store is a duplicate.
        elsewhere = replace(env.store.get("acme", finding_id), created_at=1.0)
        out = env.service.grade("acme", finding_id, prior=[elsewhere])
        assert out["grade"]["decision"] == "discard"
        assert f"duplicate of {finding_id}" in out["grade"]["reasons"][0]

    def test_errors_are_dicts_and_nothing_is_stored(self, env: Env) -> None:
        unknown = env.service.grade("acme", "F-000000000000")
        assert (unknown["ok"], unknown["code"]) == (False, "UNKNOWN_FINDING")

        finding_id = env.verified()
        before = env.store.events("acme", finding_id)
        nameless = env.service.grade("acme", finding_id, actor=" ")
        assert (nameless["ok"], nameless["code"]) == (False, "BAD_ACTOR")
        not_a_scope = env.service.grade("acme", finding_id, scope=object())
        assert (not_a_scope["ok"], not_a_scope["code"]) == (False, "BAD_SCOPE")

        (env.roots.control / "acme" / "roe.json").unlink()
        no_scope = env.service.grade("acme", finding_id)
        assert (no_scope["ok"], no_scope["code"]) == (False, "NO_ENFORCED_SCOPE")
        assert no_scope["detail"]

        assert env.store.events("acme", finding_id) == before
        assert env.store.get("acme", finding_id).grade is None

    def test_a_finding_of_another_engagement_is_not_graded(self, env: Env) -> None:
        finding_id = env.verified()
        out = env.service.grade("globex", finding_id)
        assert (out["ok"], out["code"]) == (False, "UNKNOWN_FINDING")
        assert env.store.get("acme", finding_id).grade is None
