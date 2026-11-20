"""SARIF 2.1.0 from a findings report: structure, what becomes a result, hostile text, URIs.

Reports are made by the real :func:`buggy.findings.report.build`, so the
section rules under test are the report's own. The structure is checked
against the SARIF 2.1.0 required-property set (log, run, tool, driver,
reportingDescriptor, result, message, location) written out explicitly below.
"""

from __future__ import annotations

import copy
import json
import random
import re
from typing import Any
from urllib.parse import urlsplit

import pytest

from buggy.findings.model import CLASSES, finding_id
from buggy.findings.report import build, to_json
from buggy.findings.sarif import (
    SARIF_SCHEMA,
    endpoint_uri,
    plain_text,
    to_sarif,
)

ENG = "acme"
BASE = "https://app.acme.test"
GENERATED = "2026-11-20T12:00:00+00:00"
LEVELS = {"none", "note", "warning", "error"}
#: Every character a URI may hold (RFC 3986 unreserved, reserved and ``%``).
URI_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")


def finding(
    title: str,
    cls: str,
    severity: str,
    endpoint: str,
    status: str,
    *,
    parameter: str = "",
    method: str = "GET",
    cwe: str = "",
) -> dict[str, Any]:
    return {
        "id": finding_id(ENG, cls, endpoint, parameter),
        "engagement": ENG,
        "title": title,
        "class": cls,
        "cwe": cwe,
        "severity": severity,
        "endpoint": endpoint,
        "method": method,
        "parameter": parameter,
        "source": "agent:tester",
        "description": "",
        "remediation": "",
        "assertions": [],
        "status": status,
        "verification": {"at": 1.0, "replay_capture_ids": [], "reasons": ["held"]},
        "grade": None,
        "grade_reasons": [],
        "created_at": 1.0,
        "updated_at": 2.0,
    }


def make_report(findings: list[dict[str, Any]], *, complete: bool = True) -> dict[str, Any]:
    return build(
        ENG,
        findings,
        recon_summary=None,
        scope=[BASE],
        captures=lambda _id: None,
        generated_at=GENERATED,
        complete=complete,
    )


IDOR = finding(
    "IDOR on GET /api/orders/{id}",
    "access_control",
    "high",
    f"{BASE}/api/orders/{{id}}",
    "exploit_verified",
    parameter="id",
    cwe="CWE-639",
)
SQLI = finding(
    "SQL injection in search",
    "injection",
    "critical",
    f"{BASE}/search",
    "exploit_verified",
    parameter="q",
    method="POST",
    cwe="CWE-89",
)
REFLECT = finding("Reflected XSS", "xss", "medium", f"{BASE}/echo", "exploit_verified", cwe="")
INCONCLUSIVE = finding(
    "Maybe SSRF", "ssrf", "critical", f"{BASE}/fetch", "inconclusive", parameter="url"
)
SOURCE = finding("Reviewer says CSRF", "csrf", "high", f"{BASE}/settings", "source_verified")
LEAD = finding("Open redirect lead", "open_redirect", "low", f"{BASE}/go", "candidate")
DISCARDED = finding("Bogus", "crypto", "info", f"{BASE}/x", "discarded")
ALL = [IDOR, SQLI, REFLECT, INCONCLUSIVE, SOURCE, LEAD, DISCARDED]
VERIFIED_IDS = {IDOR["id"], SQLI["id"], REFLECT["id"]}
UNPROVEN = [INCONCLUSIVE, SOURCE, LEAD, DISCARDED]


def assert_valid_sarif(doc: dict[str, Any]) -> None:
    """The SARIF 2.1.0 required properties, and every reference resolves."""
    assert json.loads(json.dumps(doc, allow_nan=False)) == doc  # plain JSON
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == SARIF_SCHEMA
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    for run in doc["runs"]:
        driver = run["tool"]["driver"]
        assert isinstance(driver["name"], str) and driver["name"]
        rules = driver.get("rules", [])
        ids = [rule["id"] for rule in rules]
        assert len(ids) == len(set(ids)), "rule ids must be unique"
        for rule in rules:
            assert isinstance(rule["id"], str) and rule["id"]
            assert isinstance(rule["shortDescription"]["text"], str)
            if "helpUri" in rule:
                assert urlsplit(rule["helpUri"]).scheme == "https"
        assert isinstance(run["results"], list)
        for result in run["results"]:
            assert result["ruleId"] in ids, "every result references an existing rule"
            assert ids[result["ruleIndex"]] == result["ruleId"]
            assert result["level"] in LEVELS
            assert isinstance(result["message"]["text"], str) and result["message"]["text"]
            assert isinstance(result["locations"], list) and result["locations"]
            for location in result["locations"]:
                uri = location["physicalLocation"]["artifactLocation"]["uri"]
                assert isinstance(uri, str) and URI_CHARS.match(uri), uri
            for key, value in result.get("partialFingerprints", {}).items():
                assert isinstance(key, str) and isinstance(value, str)


def results_of(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return doc["runs"][0]["results"]


# ── structure ───────────────────────────────────────────────────────


def test_document_is_valid_sarif_with_one_rule_per_class() -> None:
    doc = to_sarif(make_report(ALL), tool_version="1.2.3")
    assert_valid_sarif(doc)
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Buggy"
    assert driver["version"] == "1.2.3"
    assert [rule["id"] for rule in driver["rules"]] == [f"buggy/{cls}" for cls in CLASSES]
    by_id = {rule["id"]: rule for rule in driver["rules"]}
    assert by_id["buggy/access_control"]["helpUri"] == (
        "https://cwe.mitre.org/data/definitions/284.html"
    )
    assert by_id["buggy/injection"]["properties"]["security-severity"] == "9.5"
    # A class with no result this run carries no severity of its own.
    assert "security-severity" not in by_id["buggy/ssrf"]["properties"]


def test_a_validator_that_would_reject_a_broken_document() -> None:
    doc = to_sarif(make_report(ALL), tool_version="1")
    broken = copy.deepcopy(doc)
    broken["runs"][0]["results"][0]["ruleId"] = "buggy/nope"
    with pytest.raises(AssertionError):
        assert_valid_sarif(broken)
    broken = copy.deepcopy(doc)
    del broken["$schema"]
    with pytest.raises(KeyError):
        assert_valid_sarif(broken)


# ── what becomes a result ───────────────────────────────────────────


def test_only_exploit_verified_findings_become_results() -> None:
    doc = to_sarif(make_report(ALL), tool_version="1")
    assert {r["partialFingerprints"]["findingId"] for r in results_of(doc)} == VERIFIED_IDS
    text = json.dumps(doc)
    for item in UNPROVEN:
        assert item["id"] not in text
        assert item["title"] not in text
    props = doc["runs"][0]["properties"]
    assert props["verified"] == 3
    assert props["not_proven"] == {
        "source_verified": 1,
        "inconclusive": 1,
        "candidates": 1,
        "discarded": 1,
    }


def test_unproven_findings_alone_produce_no_result() -> None:
    doc = to_sarif(make_report(UNPROVEN), tool_version="1")
    assert_valid_sarif(doc)
    assert results_of(doc) == []
    assert doc["runs"][0]["properties"]["verified"] == 0


def test_a_doctored_findings_section_cannot_smuggle_an_unproven_item_in() -> None:
    report = json.loads(to_json(make_report([IDOR, INCONCLUSIVE])))
    report["findings"].append(copy.deepcopy(report["unverified"][0]))  # status: inconclusive
    report["findings"].append({"id": "F-000000000000", "title": "no status"})
    report["findings"].append("not even an object")
    doc = to_sarif(report, tool_version="1")
    assert [r["partialFingerprints"]["findingId"] for r in results_of(doc)] == [IDOR["id"]]
    assert doc["runs"][0]["properties"]["skipped_not_exploit_verified"] == 3


def test_result_fields() -> None:
    doc = to_sarif(make_report([IDOR, SQLI, REFLECT]), tool_version="1")
    results = {r["partialFingerprints"]["findingId"]: r for r in results_of(doc)}
    sqli = results[SQLI["id"]]
    assert sqli["ruleId"] == "buggy/injection"
    assert sqli["level"] == "error"
    assert sqli["properties"]["security-severity"] == "9.5"
    assert sqli["properties"]["cwe"] == "CWE-89"
    assert "external/cwe/cwe-89" in sqli["properties"]["tags"]
    location = sqli["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == f"{BASE}/search"
    assert location["properties"] == {"method": "POST", "parameter": "q"}
    assert sqli["message"]["text"] == f"SQL injection in search (POST {BASE}/search)"

    idor = results[IDOR["id"]]
    assert idor["level"] == "error"
    assert idor["properties"]["security-severity"] == "8.0"
    # Braces are not URI characters: the endpoint template is percent-encoded.
    uri = idor["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == f"{BASE}/api/orders/%7Bid%7D"
    # ... and SARIF placeholders are doubled in message text.
    assert "{{id}}" in idor["message"]["text"]

    reflect = results[REFLECT["id"]]
    assert reflect["level"] == "warning"
    assert reflect["properties"]["security-severity"] == "5.5"
    assert "cwe" not in reflect["properties"]


@pytest.mark.parametrize(
    ("severity", "level", "score"),
    [
        ("critical", "error", "9.5"),
        ("high", "error", "8.0"),
        ("medium", "warning", "5.5"),
        ("low", "note", "3.0"),
        ("info", "note", "0.0"),
    ],
)
def test_level_and_security_severity_per_severity(severity: str, level: str, score: str) -> None:
    item = finding("t", "api", severity, f"{BASE}/a", "exploit_verified")
    (result,) = results_of(to_sarif(make_report([item]), tool_version="1"))
    assert result["level"] == level
    assert result["properties"]["security-severity"] == score


def test_unknown_class_and_severity_are_filed_safely() -> None:
    report = json.loads(to_json(make_report([IDOR])))
    report["findings"][0]["class"] = "x/../<evil>"
    report["findings"][0]["severity"] = "catastrophic"
    doc = to_sarif(report, tool_version="1")
    assert_valid_sarif(doc)
    (result,) = results_of(doc)
    assert result["ruleId"] == "buggy/unclassified"
    assert result["level"] == "error"
    assert "security-severity" not in result["properties"]
    assert "<evil>" not in json.dumps(doc)


# ── hostile text and URIs ───────────────────────────────────────────

HOSTILE_TITLE = (
    'Pwned {0} [click me](https://evil.test/) \\[x\\]\n::error::injected\x07\x1b[31m "quoted" '
    "<script>alert(1)</script>"
)


def test_a_hostile_title_stays_plain_text_and_does_not_break_the_document() -> None:
    item = finding(HOSTILE_TITLE, "xss", "high", f"{BASE}/p", "exploit_verified")
    doc = to_sarif(make_report([item]), tool_version="1")
    assert_valid_sarif(doc)
    text = results_of(doc)[0]["message"]["text"]
    assert "\n" not in text and "\x07" not in text and "\x1b" not in text
    assert "{{0}}" in text and "{0}" not in text.replace("{{0}}", "")
    # No unescaped bracket survives, so no embedded link can form.
    assert re.search(r"(?<!\\)[\[\]]", text.replace("\\\\", "")) is None
    assert "\\[click me\\](https://evil.test/)" in text
    assert "<script>alert(1)</script>" in text  # plain text: shown, not interpreted


def test_plain_text_escaping_is_exact() -> None:
    assert plain_text("a{b}c") == "a{{b}}c"
    assert plain_text("[l](u)") == "\\[l\\](u)"
    assert plain_text("back\\slash") == "back\\\\slash"
    assert plain_text(" two\n\nlines\t ") == "two lines"
    assert plain_text("safe text") == "safe text"


@pytest.mark.parametrize(
    "endpoint",
    [
        "javascript:alert(1)",
        "data:text/html,<script>x</script>",
        "file:///etc/passwd",
        "https://user:pw@app.acme.test/a",
        "https://app.acme.test\n.evil/a",
        "https://ho st/a",
        "https://evil_host!/a",
        "https://[fe80::1%25eth0]/a",
        "/relative/path",
        "",
        "https://app.acme.test:99999/a",
    ],
)
def test_an_unusable_endpoint_is_replaced_not_copied(endpoint: str) -> None:
    assert endpoint_uri(endpoint) is None
    report = json.loads(to_json(make_report([IDOR])))
    report["findings"][0]["endpoint"] = endpoint
    doc = to_sarif(report, tool_version="1")
    assert_valid_sarif(doc)
    uri = results_of(doc)[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == f"buggy-finding/{IDOR['id']}"


def test_a_hostile_finding_id_does_not_reach_the_fallback_uri() -> None:
    report = json.loads(to_json(make_report([IDOR])))
    report["findings"][0]["endpoint"] = "javascript:alert(1)"
    report["findings"][0]["id"] = "../../<x> y"
    uri = results_of(to_sarif(report, tool_version="1"))[0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert re.fullmatch(r"buggy-finding/unknown-[0-9a-f]{12}", uri)


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("https://App.Acme.Test/a/b", "https://app.acme.test/a/b"),
        ("HTTP://app.acme.test:8080/x", "http://app.acme.test:8080/x"),
        ("https://app.acme.test", "https://app.acme.test/"),
        ("https://app.acme.test/a?q=1#frag", "https://app.acme.test/a"),
        ('https://app.acme.test/a"b<c>`d', "https://app.acme.test/a%22b%3Cc%3E%60d"),
        ("https://app.acme.test/café", "https://app.acme.test/caf%C3%A9"),
        ("https://app.acme.test/a%2fb%zz", "https://app.acme.test/a%2Fb%25zz"),
        ("http://10.0.0.5/x", "http://10.0.0.5/x"),
        ("http://[::1]:8000/x", "http://[::1]:8000/x"),
    ],
)
def test_endpoint_uris_are_rebuilt_and_encoded(endpoint: str, expected: str) -> None:
    uri = endpoint_uri(endpoint)
    assert uri == expected
    assert URI_CHARS.match(uri)


# ── determinism and input ───────────────────────────────────────────


def test_output_is_deterministic_and_independent_of_input_order() -> None:
    first = to_sarif(make_report(ALL), tool_version="1")
    shuffled = list(ALL)
    random.Random(7).shuffle(shuffled)
    report = make_report(shuffled)
    report["findings"].reverse()  # even a reordered section
    assert json.dumps(to_sarif(report, tool_version="1"), sort_keys=True) == json.dumps(
        first, sort_keys=True
    )
    ids = [r["partialFingerprints"]["findingId"] for r in results_of(first)]
    assert ids == [SQLI["id"], IDOR["id"], REFLECT["id"]]  # severity, then id
    assert first["runs"][0]["properties"]["generated_at"] == GENERATED


def test_the_report_json_round_trip_gives_the_same_document() -> None:
    report = make_report(ALL)
    assert to_sarif(json.loads(to_json(report)), tool_version="1") == to_sarif(
        report, tool_version="1"
    )


@pytest.mark.parametrize(
    "bad", [[], "report", None, {"findings": "nope"}, {"findings": [], "leads": {}}]
)
def test_not_a_report_is_rejected(bad: Any) -> None:
    with pytest.raises(ValueError):
        to_sarif(bad, tool_version="1")


def test_hostile_engagement_name_is_sanitised_in_automation_id() -> None:
    report = make_report([IDOR])
    report["engagement"] = "../acme\n{x}"
    doc = to_sarif(report, tool_version="1")
    assert doc["runs"][0]["automationDetails"]["id"] == "buggy/acme-x/"
