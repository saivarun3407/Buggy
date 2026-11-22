"""After the tests: logs, a video and the Word report for every proven finding."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from buggy.cli import hunt

FINDING = {
    "id": "F-0a1b2c3d4e5f",
    "title": "SQL injection in id",
    "severity": "high",
    "cwe": "CWE-89",
    "class": "injection",
    "endpoint": "https://app.test/item",
    "method": "GET",
    "parameter": "id",
    "source": "probe:sqli",
    "description": "",
    "remediation": "Use parameterised queries for every statement.",
    "grade": {"decision": "submit", "reasons": []},
    "proof": [],
    "reproduction": [],
}
PNG = bytes.fromhex("89504e470d0a1a0a") + b"\x00" * 16


def setup(tmp_path: Path, findings: list[dict]) -> tuple[Path, Path]:
    control, audit = tmp_path / "control", tmp_path / "audit"
    (control / "acme").mkdir(parents=True)
    report = {
        "engagement": "acme",
        "generated_at": "2026-11-22T00:00:00+00:00",
        "findings": findings,
        "unverified": [],
        "leads": [],
        "summary": {},
        "scope": ["app.test"],
        "complete": True,
    }
    (control / "acme" / "report.json").write_text(json.dumps(report))
    return control, audit


def servers(monkeypatch, audit: Path, *, video: bool = True, logs: bool = True) -> list[tuple]:
    calls: list[tuple] = []

    def capture(tool: str, engagement: str, **arguments) -> dict:
        calls.append((tool, engagement, arguments))
        assert tool == "evidence_export"
        return (
            {"ok": True, "written_to": "x"} if logs else {"error": "EXPORT_REFUSED", "detail": "no"}
        )

    def browser(tool: str, engagement: str, **arguments) -> dict:
        calls.append((tool, engagement, arguments))
        assert tool == "proof_record"
        if not video:
            return {"ok": False, "error": "NO_BROWSER", "detail": "no browser server here"}
        folder = audit / engagement / "evidence" / arguments["finding_id"]
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "proof.png").write_bytes(PNG)
        relative = f"evidence/{arguments['finding_id']}"
        return {
            "ok": True,
            "video": f"{relative}/proof.webm",
            "screenshot": f"{relative}/proof.png",
        }

    monkeypatch.setattr(hunt, "_capture", capture)
    monkeypatch.setattr(hunt, "_browser", browser)
    return calls


def document(control: Path) -> str:
    data = (control / "acme" / hunt.WORD_REPORT).read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert "word/document.xml" in archive.namelist()
        return archive.read("word/document.xml").decode("utf-8")


RESULT = {
    "coverage": [
        {
            "class": "injection",
            "tested": True,
            "checks": 3,
            "waiting_for_approval": 0,
            "findings": 1,
            "reason": "",
        }
    ],
    "not_tested": [
        {
            "area": "everything behind the login",
            "reason": "no accounts",
            "enable": "declare accounts",
        }
    ],
}


def test_each_proven_finding_gets_logs_a_video_and_a_place_in_the_word_report(
    tmp_path, monkeypatch
) -> None:
    control, audit = setup(tmp_path, [FINDING])
    calls = servers(monkeypatch, audit)
    out = hunt.write_proof_and_word(control, audit, "acme", RESULT)
    assert out == {
        "videos": 1, "logs": 1, "word": hunt.WORD_REPORT, "errors": [], "valid": 1, "held": 0,
    }  # fmt: skip
    assert [c[0] for c in calls] == ["evidence_export", "proof_record"]
    recorded = calls[1][2]
    assert recorded["finding_id"] == FINDING["id"] and FINDING["title"] in recorded["html"]
    assert "<script" not in recorded["html"].lower()
    text = document(control)
    assert "SQL injection in id" in text and "proof.webm" in text
    assert "Use parameterised queries" in text
    # This run's class table and what it did not test are in the document.
    assert "everything behind the login" in text and "injection" in text


def test_the_word_report_is_written_even_when_no_video_can_be_recorded(
    tmp_path, monkeypatch
) -> None:
    control, audit = setup(tmp_path, [FINDING])
    servers(monkeypatch, audit, video=False, logs=False)
    out = hunt.write_proof_and_word(control, audit, "acme", RESULT)
    assert (out["videos"], out["logs"], out["word"]) == (0, 0, hunt.WORD_REPORT)
    assert len(out["errors"]) == 2 and "video" in out["errors"][1]
    assert "SQL injection in id" in document(control)


def test_no_findings_still_gives_a_report(tmp_path, monkeypatch) -> None:
    control, audit = setup(tmp_path, [])
    calls = servers(monkeypatch, audit)
    out = hunt.write_proof_and_word(control, audit, "acme", RESULT)
    assert calls == [] and out["word"] == hunt.WORD_REPORT and out["errors"] == []
    assert (
        "word/document.xml"
        in zipfile.ZipFile(
            io.BytesIO((control / "acme" / hunt.WORD_REPORT).read_bytes())
        ).namelist()
    )


def test_a_missing_or_damaged_report_is_reported(tmp_path, monkeypatch) -> None:
    control, audit = tmp_path / "control", tmp_path / "audit"
    (control / "acme").mkdir(parents=True)
    servers(monkeypatch, audit)
    assert hunt.write_proof_and_word(control, audit, "acme", RESULT)["errors"]
    (control / "acme" / "report.json").write_text("[1, 2]")
    out = hunt.write_proof_and_word(control, audit, "acme", RESULT)
    assert out["word"] == "" and out["errors"] == ["report.json: not a report"]


def test_only_valid_bugs_get_evidence(tmp_path, monkeypatch) -> None:
    held = {
        **FINDING,
        "id": "F-00000000aaaa",
        "title": "Duplicate of a scanner hit",
        "grade": {"decision": "hold", "reasons": ["rule 5: the scanner already reported this"]},
    }
    ungraded = {**FINDING, "id": "F-00000000bbbb", "title": "Never graded", "grade": {}}
    control, audit = setup(tmp_path, [FINDING, held, ungraded])
    calls = servers(monkeypatch, audit)
    out = hunt.write_proof_and_word(control, audit, "acme", RESULT)
    assert (out["valid"], out["held"], out["videos"], out["logs"]) == (1, 2, 1, 1)
    touched = {c[2]["finding_id"] for c in calls}
    assert touched == {FINDING["id"]}  # nothing was recorded or exported for the other two
    text = document(control)
    assert "Proven, not reportable: rule 5: the scanner already reported this" in text
    assert "Proven, not reportable: not graded yet" in text


def test_no_valid_bug_means_no_evidence_step(tmp_path, monkeypatch) -> None:
    held = {**FINDING, "grade": {"decision": "discard", "reasons": ["rule 2: out of scope now"]}}
    control, audit = setup(tmp_path, [held])
    calls = servers(monkeypatch, audit)
    out = hunt.write_proof_and_word(control, audit, "acme", RESULT)
    assert calls == [] and (out["valid"], out["held"], out["videos"]) == (0, 1, 0)
    assert not (audit / "acme").exists()
