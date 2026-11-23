"""buggy-cli disprover: the operator reviews and overrides the disprover's verdicts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.cli import disprover
from buggy.findings.service import read_overrides

FINDINGS = [
    {
        "id": "f-1",
        "title": "IDOR on orders",
        "source": "claude-code",
        "grade": "hold",
        "challenge": {"verdict": "false_positive", "reason": "own order", "holds": True},
    },
    {"id": "f-2", "title": "SQLi", "source": "probe:sqli", "grade": "submit"},
    {"id": "f-3", "title": "Open redirect", "source": "claude-code", "grade": "submit"},
]


@pytest.fixture
def control(tmp_path: Path, monkeypatch) -> tuple[Path, list]:
    (tmp_path / "acme").mkdir()
    (tmp_path / "acme" / "roe.json").write_text("{}")
    calls: list = []

    def capture(tool: str, engagement: str, **arguments):
        calls.append((tool, engagement, arguments))
        if tool == "findings_list":
            return {"ok": True, "findings": FINDINGS}
        if tool == "finding_get":
            if arguments["finding_id"] == "f-1":
                return {"ok": True, "finding": FINDINGS[0]}
            return {"ok": False, "code": "UNKNOWN_FINDING", "detail": "no finding"}
        if tool == "finding_grade":
            return {
                "ok": True,
                "grade": {"decision": "submit", "reasons": ["Rule 8 (submit): ok."]},
            }
        return {"error": "unexpected"}

    monkeypatch.setattr(disprover, "_capture", capture)
    monkeypatch.setattr(disprover, "_known_issues", lambda _engagement: "[]")
    return tmp_path, calls


def test_list_shows_agent_made_findings_and_verdicts(control, capsys) -> None:
    root, _ = control
    assert disprover.main(["--control-root", str(root), "list", "acme"]) == 0
    out = capsys.readouterr().out
    assert "f-1  grade=hold  disprover=false_positive (holds it)" in out and "own order" in out
    assert "f-3  grade=submit  disprover=not judged" in out and "f-2" not in out
    assert disprover.main(["--control-root", str(root), "list", "acme", "--json"]) == 0
    assert [row["id"] for row in json.loads(capsys.readouterr().out)] == ["f-1", "f-3"]


def test_override_records_the_decision_and_grades_again(control, capsys) -> None:
    root, calls = control
    argv = ["--control-root", str(root), "override", "acme", "f-1", "--reason", "cap-2 is Alice's"]
    assert disprover.main(argv) == 0
    out = capsys.readouterr().out
    assert "override recorded for f-1" in out and "graded again: submit" in out
    assert set(read_overrides(root, "acme")) == {"f-1"}
    assert calls[-1][0] == "finding_grade" and calls[-1][2]["finding_id"] == "f-1"


def test_an_unknown_finding_is_not_overridden(control, capsys) -> None:
    root, _ = control
    argv = ["--control-root", str(root), "override", "acme", "f-9", "--reason", "x"]
    assert disprover.main(argv) == disprover.EXIT_CONFIG
    assert "no finding" in capsys.readouterr().err
    assert read_overrides(root, "acme") == {}


def test_an_unknown_engagement_is_refused(control, capsys) -> None:
    root, _ = control
    assert disprover.main(["--control-root", str(root), "list", "nope"]) == disprover.EXIT_CONFIG
