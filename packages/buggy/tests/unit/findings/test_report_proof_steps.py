"""The request / response / payload keys a report's proof steps carry (for the proof page
and the Word report). They are additive: the existing keys are checked in test_report.py."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlsplit

from buggy.capture.store import REDACTED, Capture, sha256_hex
from buggy.findings.model import finding_id
from buggy.findings.report import WINDOW_CHARS, build, to_json

ENG = "acme"
BASE = "https://app.acme.test"
PAYLOAD = "' OR '1'='1"
SEARCH = f"{BASE}/search?q={quote(PAYLOAD)}&page=2"
PROOF_TEXT = "You have an error in your SQL syntax"
# A long body with the proving text deep inside it.
LONG_BODY = ("a" * 9000 + PROOF_TEXT + "b" * 9000).encode()


def capture(
    capture_id: str,
    url: str,
    *,
    body: bytes = b"",
    status: int | None = 200,
    request_body: bytes = b"",
    request_headers: dict[str, str] | None = None,
    note: str = "",
    replay_of: str = "",
    identity: str = "",
    method: str = "GET",
) -> Capture:
    return Capture(
        id=capture_id,
        engagement=ENG,
        created_at=1_700_000_000.0,
        method=method,
        url=url,
        host=urlsplit(url).hostname or "",
        request_headers=request_headers or {},
        request_body=request_body,
        request_sha256=sha256_hex(request_body),
        status=status,
        response_headers={"Content-Type": "text/html"},
        response_body=body,
        response_sha256=sha256_hex(body),
        response_bytes=len(body),
        elapsed_ms=5.0,
        error="",
        note=note,
        probe="",
        replay_of=replay_of,
        approval_id="",
        scope_digest="",
        identity=identity,
    )


def finding(parameter: str, assertions: list[dict], replay_ids: list[str], **extra: Any) -> dict:
    endpoint = extra.pop("endpoint", f"{BASE}/search")
    return {
        "id": finding_id(ENG, "injection", endpoint, parameter),
        "engagement": ENG,
        "title": "SQL injection",
        "class": "injection",
        "cwe": "CWE-89",
        "severity": "high",
        "endpoint": endpoint,
        "method": "GET",
        "parameter": parameter,
        "source": "probe:sqli",
        "description": "",
        "remediation": "",
        "assertions": assertions,
        "status": "exploit_verified",
        "verification": {"at": 1.0, "replay_capture_ids": replay_ids, "reasons": []},
        "grade": None,
        "grade_reasons": [],
        **extra,
    }


def expect(**values: Any) -> dict[str, Any]:
    return {
        "status": None,
        "body_contains": [],
        "body_not_contains": [],
        "differs_from": "",
        "same_as": "",
        **values,
    }


CAPTURES = {
    c.id: c
    for c in (
        capture(
            "cap-sql",
            SEARCH,
            body=LONG_BODY,
            status=500,
            request_headers={"Authorization": "Bearer abcdefgh-not-a-key", "Accept": "*/*"},
        ),
        capture("rp-sql", SEARCH, body=LONG_BODY, status=500, replay_of="cap-sql"),
        capture(
            "cap-form",
            f"{BASE}/login",
            method="POST",
            request_body=b"user=admin&pass=x%27--",
            body=b"welcome admin",
        ),
        capture(
            "cap-json",
            f"{BASE}/api",
            method="POST",
            request_body=json.dumps({"query": {"$ne": None}}).encode(),
            body=b"[...]",
        ),
        capture("cap-note", f"{BASE}/profile", note="role=admin", body=b"role: admin"),
    )
}


def make(findings: list[dict]) -> dict:
    return build(
        ENG,
        findings,
        recon_summary=None,
        scope=[BASE],
        captures=CAPTURES.get,
        generated_at="2026-11-22T00:00:00+00:00",
    )


SQLI = finding(
    "q",
    [{"capture_id": "cap-sql", "identity": "", "expect": expect(body_contains=[PROOF_TEXT])}],
    ["rp-sql"],
)


def test_a_step_carries_request_response_payload_and_hash() -> None:
    (step,) = make([SQLI])["findings"][0]["reproduction"]
    assert step["payload"] == PAYLOAD and step["payload_source"] == "parameter"
    assert step["request"]["method"] == "GET" and step["request"]["url"] == SEARCH
    assert step["request"]["headers"]["Authorization"] == REDACTED
    assert step["request"]["headers"]["Accept"] == "*/*"
    response = step["response"]
    assert response["capture_id"] == "rp-sql" and step["replayed"] is True
    assert response["status"] == 500
    assert response["match"] == PROOF_TEXT and PROOF_TEXT in response["body"]
    assert len(response["body"]) == WINDOW_CHARS
    assert response["omitted_before"] > 0 and response["omitted_after"] > 0
    assert response["omitted_before"] + len(response["body"]) + response["omitted_after"] == len(
        LONG_BODY
    )
    assert step["sha256"] == sha256_hex(LONG_BODY) == response["sha256"]
    assert step["highlight"] == [PROOF_TEXT]
    assert step["shows"].startswith("Expect: the body contains")


def test_the_replay_is_matched_by_what_it_replayed_not_by_position() -> None:
    two = finding(
        "q",
        [
            {"capture_id": "cap-note", "identity": "", "expect": expect(status=200)},
            {"capture_id": "cap-sql", "identity": "", "expect": expect(status=500)},
        ],
        ["rp-sql"],
    )
    first, second = make([two])["findings"][0]["reproduction"]
    assert second["response"]["capture_id"] == "rp-sql" and second["replayed"] is True
    # The first step has no replay of its own: its recorded response is shown, labelled.
    assert first["response"]["capture_id"] == "cap-note" and first["replayed"] is False


def test_payload_comes_from_a_form_or_json_body_or_the_capture_note() -> None:
    form = finding(
        "pass",
        [{"capture_id": "cap-form", "identity": "", "expect": expect(status=200)}],
        [],
        endpoint=f"{BASE}/login",
    )
    json_body = finding(
        "query",
        [{"capture_id": "cap-json", "identity": "", "expect": expect(status=200)}],
        [],
        endpoint=f"{BASE}/api",
    )
    noted = finding(
        "",
        [{"capture_id": "cap-note", "identity": "", "expect": expect(status=200)}],
        [],
        endpoint=f"{BASE}/profile",
    )
    steps = {
        item["parameter"]: item["reproduction"][0]
        for item in make([form, json_body, noted])["findings"]
    }
    assert steps["pass"]["payload"] == "x'--"
    assert steps["query"]["payload"] == '{"$ne": null}'
    assert (steps[""]["payload"], steps[""]["payload_source"]) == ("admin", "note")


def test_a_missing_capture_gives_empty_parts_not_invented_ones() -> None:
    ghost = finding(
        "q", [{"capture_id": "cap-gone", "identity": "", "expect": expect(status=200)}], ["rp-gone"]
    )
    item = make([ghost])["findings"][0]
    (step,) = item["reproduction"]
    assert step["request"] is None and step["response"] is None and step["payload"] == ""
    assert item["proof"][0]["request"] is None


def test_proof_entries_carry_the_same_keys_and_the_json_stays_stable() -> None:
    report = make([SQLI])
    (proof,) = report["findings"][0]["proof"]
    assert proof["response"]["match"] == PROOF_TEXT and proof["payload"] == PAYLOAD
    text = to_json(report)
    assert to_json(json.loads(text)) == text
    assert "abcdefgh-not-a-key" not in text
