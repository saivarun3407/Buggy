"""``buggy-cli ci-gate``: the exit-code matrix, SARIF output, slim import, and the Action.

Reports are made by the real :func:`buggy.findings.report.build` and written
with ``to_json``, exactly the file a hunt leaves behind.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from buggy.cli import ci_gate, hunt
from buggy.cli.__main__ import main as dispatch
from buggy.findings.model import finding_id
from buggy.findings.report import build, to_json

REPO = Path(__file__).resolve().parents[5]
ACTION = REPO / ".github" / "actions" / "buggy-gate" / "action.yml"
DOC = REPO / "docs" / "ci.md"
ENG = "acme"
BASE = "https://app.acme.test"


def finding(
    title: str, severity: str, status: str, *, cls: str = "access_control", path: str = "/a"
) -> dict[str, Any]:
    endpoint = BASE + path
    return {
        "id": finding_id(ENG, cls, endpoint, ""),
        "engagement": ENG,
        "title": title,
        "class": cls,
        "cwe": "",
        "severity": severity,
        "endpoint": endpoint,
        "method": "GET",
        "parameter": "",
        "source": "agent:tester",
        "description": "",
        "remediation": "",
        "assertions": [],
        "status": status,
        "verification": {"at": 1.0, "replay_capture_ids": [], "reasons": []},
        "grade": None,
        "grade_reasons": [],
        "created_at": 1.0,
        "updated_at": 2.0,
    }


HIGH = finding("IDOR on orders", "high", "exploit_verified", path="/orders")
MEDIUM = finding("Verbose error", "medium", "exploit_verified", cls="info_exposure", path="/err")
UNPROVEN = [
    finding("Maybe SQLi", "critical", "inconclusive", cls="injection", path="/s"),
    finding("Reviewer note", "critical", "source_verified", cls="csrf", path="/c"),
    finding("A lead", "critical", "candidate", cls="ssrf", path="/f"),
    finding("Rejected", "critical", "discarded", cls="crypto", path="/k"),
]


def write_report(tmp: Path, findings: list[dict[str, Any]], *, complete: bool = True) -> Path:
    report = build(
        ENG,
        findings,
        recon_summary=None,
        scope=[BASE],
        captures=lambda _id: None,
        generated_at="2026-11-20T12:00:00+00:00",
        complete=complete,
    )
    path = tmp / "report.json"
    path.write_text(to_json(report), encoding="utf-8")
    return path


def hunt_result(
    *, complete: bool = True, issues: dict[str, int] | None = None, verified: dict | None = None
) -> dict[str, Any]:
    return {
        "engagement": ENG,
        "finished_at": 1.0,
        "recon": {"state": "completed" if complete else "timed_out", "records": {}},
        "issues": {s: (issues or {}).get(s, 0) for s in hunt.SEVERITIES},
        "findings": {
            "available": True,
            "exploit_verified": {s: (verified or {}).get(s, 0) for s in hunt.SEVERITIES},
            "inconclusive": 0,
            "candidates": 0,
        },
        "approvals_pending": 0,
        "agent": {"ran": True, "error": None},
        "complete": complete,
    }


def write_hunt(tmp: Path, result: dict[str, Any]) -> Path:
    path = tmp / "hunt-result.json"
    path.write_text(json.dumps(result), encoding="utf-8")
    return path


def gate(*argv: str | Path) -> int:
    return ci_gate.main([str(a) for a in argv])


# ── exit-code matrix ─────────────────────────────────────────────────


def test_clean_complete_run_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = write_report(tmp_path, [])
    assert gate("--report", report) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1 and out[0].startswith("buggy ci-gate: PASS (exit 0)")


def test_verified_finding_at_threshold_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(tmp_path, [HIGH, MEDIUM])
    assert gate("--report", report, "--fail-on", "high") == 10
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("buggy ci-gate: FAIL (exit 10): 1 of 2 exploit-verified")
    assert out[1:] == [f"  - [high] {HIGH['id']} IDOR on orders (GET {BASE}/orders)"]


def test_default_threshold_is_high(tmp_path: Path) -> None:
    assert gate("--report", write_report(tmp_path, [HIGH])) == 10
    assert gate("--report", write_report(tmp_path, [MEDIUM])) == 0


def test_verified_finding_below_threshold_passes(tmp_path: Path) -> None:
    report = write_report(tmp_path, [MEDIUM])
    assert gate("--report", report, "--fail-on", "high") == 0
    assert gate("--report", report, "--fail-on", "medium") == 10


def test_unproven_findings_never_fail_the_gate(tmp_path: Path) -> None:
    report = write_report(tmp_path, UNPROVEN)
    assert gate("--report", report, "--fail-on", "info") == 0


def test_incomplete_report_is_not_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = write_report(tmp_path, [MEDIUM], complete=False)
    assert gate("--report", report, "--fail-on", "high") == 3
    assert "INCOMPLETE (exit 3)" in capsys.readouterr().out


def test_incomplete_hunt_result_is_not_clean(tmp_path: Path) -> None:
    report = write_report(tmp_path, [])
    result = write_hunt(tmp_path, hunt_result(complete=False))
    assert gate("--report", report, "--hunt-result", result) == 3
    complete = write_hunt(tmp_path, hunt_result(complete=True))
    assert gate("--report", report, "--hunt-result", complete) == 0


def test_vulnerable_wins_over_incomplete(tmp_path: Path) -> None:
    report = write_report(tmp_path, [HIGH], complete=False)
    result = write_hunt(tmp_path, hunt_result(complete=False))
    assert gate("--report", report, "--hunt-result", result, "--fail-on", "high") == 10


def test_unknown_severity_meets_every_threshold(tmp_path: Path) -> None:
    path = write_report(tmp_path, [HIGH])
    report = json.loads(path.read_text())
    report["findings"][0]["severity"] = "catastrophic"
    path.write_text(json.dumps(report))
    assert gate("--report", path, "--fail-on", "critical") == 10


def test_a_doctored_unproven_item_in_findings_does_not_gate(tmp_path: Path) -> None:
    path = write_report(tmp_path, UNPROVEN)
    report = json.loads(path.read_text())
    report["findings"].append(report["unverified"][0])  # inconclusive, critical
    path.write_text(json.dumps(report))
    assert gate("--report", path, "--fail-on", "info") == 0


def test_known_issues_gate_only_with_fail_on_issues(tmp_path: Path) -> None:
    report = write_report(tmp_path, [])
    result = write_hunt(tmp_path, hunt_result(issues={"high": 2, "low": 5}))
    assert gate("--report", report, "--hunt-result", result) == 0
    assert gate("--report", report, "--hunt-result", result, "--fail-on-issues") == 10
    args = ("--report", report, "--hunt-result", result, "--fail-on", "critical")
    assert gate(*args, "--fail-on-issues") == 0


def _broken(tmp: Path, name: str, text: str) -> Path:
    path = tmp / name
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "report_text",
    [
        "{not json",
        "[]",
        "{}",
        json.dumps({"summary": {"complete": "yes"}, "findings": []}),
        json.dumps({"summary": {"complete": True}, "findings": {}}),
        json.dumps({"summary": {"complete": True}, "findings": [], "report_format": 99}),
        json.dumps({"summary": {"complete": True}, "findings": [], "leads": "x"}),
    ],
)
def test_malformed_report_is_bad_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], report_text: str
) -> None:
    sarif = tmp_path / "out.sarif"
    assert gate("--report", _broken(tmp_path, "r.json", report_text), "--sarif", sarif) == 2
    assert "error:" in capsys.readouterr().err
    assert not sarif.exists()


@pytest.mark.parametrize(
    "hunt_text",
    [
        "nope",
        "[]",
        json.dumps({"engagement": ENG}),
        json.dumps({"engagement": ENG, "complete": True, "issues": {"high": -1}}),
        json.dumps({"engagement": "other", "complete": True}),
    ],
)
def test_malformed_hunt_result_is_bad_input(tmp_path: Path, hunt_text: str) -> None:
    report = write_report(tmp_path, [HIGH])
    assert gate("--report", report, "--hunt-result", _broken(tmp_path, "h.json", hunt_text)) == 2


def test_missing_files_and_bad_options_are_bad_input(tmp_path: Path) -> None:
    report = write_report(tmp_path, [])
    assert gate("--report", tmp_path / "missing.json") == 2
    assert gate("--report", report, "--hunt-result", tmp_path / "missing.json") == 2
    assert gate("--report", report, "--fail-on", "severe") == 2
    assert gate("--report", report, "--fail-on-issues") == 2
    assert gate() == 2


def test_agrees_with_hunt_exit_codes_when_both_apply(tmp_path: Path) -> None:
    """Same counts, same verdict as ``buggy-cli hunt`` (precedence aside, see below)."""
    cases = [
        ([], True, {}, "high", False),
        ([HIGH], True, {}, "high", False),
        ([MEDIUM], True, {}, "high", False),
        ([MEDIUM], True, {}, "medium", False),
        ([], True, {"critical": 1}, "high", True),
        ([], True, {"medium": 1}, "high", True),
        ([], False, {}, "high", False),
    ]
    for findings, complete, issues, fail_on, with_issues in cases:
        counts: dict[str, int] = {}
        for item in findings:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        result = hunt_result(complete=complete, issues=issues, verified=counts)
        expected = hunt.exit_code(result, fail_on=fail_on, fail_on_issues=with_issues)
        argv = ["--report", write_report(tmp_path, findings, complete=complete)]
        argv += ["--hunt-result", write_hunt(tmp_path, result), "--fail-on", fail_on]
        argv += ["--fail-on-issues"] if with_issues else []
        assert gate(*argv) == expected, (findings, complete, issues, fail_on)
    # The one documented difference: hunt reports an incomplete run first.
    vulnerable_incomplete = hunt_result(complete=False, verified={"high": 1})
    assert hunt.exit_code(vulnerable_incomplete, fail_on="high", fail_on_issues=False) == 3
    report = write_report(tmp_path, [HIGH], complete=False)
    assert (
        gate("--report", report, "--hunt-result", write_hunt(tmp_path, vulnerable_incomplete)) == 10
    )


def test_dispatched_as_buggy_cli_ci_gate(tmp_path: Path) -> None:
    assert dispatch(["ci-gate", "--report", str(write_report(tmp_path, [HIGH]))]) == 10


# ── SARIF output ─────────────────────────────────────────────────────


def test_writes_sarif_with_only_verified_results(tmp_path: Path) -> None:
    report = write_report(tmp_path, [HIGH, MEDIUM, *UNPROVEN])
    sarif = tmp_path / "nested" / "buggy.sarif"
    assert gate("--report", report, "--sarif", sarif, "--fail-on", "critical") == 0
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0" and doc["$schema"].startswith("https://")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Buggy"
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    found = {r["partialFingerprints"]["findingId"] for r in run["results"]}
    assert found == {HIGH["id"], MEDIUM["id"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids and result["message"]["text"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    first = sarif.read_bytes()
    gate("--report", report, "--sarif", sarif, "--fail-on", "critical")
    assert sarif.read_bytes() == first  # deterministic


def test_sarif_that_cannot_be_written(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    clean = write_report(tmp_path, [])
    assert gate("--report", clean, "--sarif", blocker / "out.sarif") == 3
    vulnerable = write_report(tmp_path, [HIGH])
    assert gate("--report", vulnerable, "--sarif", blocker / "out.sarif") == 10


def test_hostile_title_cannot_forge_log_lines_or_workflow_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    item = finding("x\n::error::forged\r\n::add-mask::y\x1b[2J", "critical", "exploit_verified")
    report = write_report(tmp_path, [item])
    sarif = tmp_path / "out.sarif"
    assert gate("--report", report, "--sarif", sarif) == 10
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert len(lines) == 2  # one summary line, one gating finding
    assert not any(line.lstrip().startswith("::") for line in lines)
    assert "\x1b" not in out and "\r" not in out
    json.loads(sarif.read_text(encoding="utf-8"))  # the document still parses


# ── slim image ───────────────────────────────────────────────────────

_BLOCKER = """
import importlib.abc, sys
BLOCKED = ("buggy.tools", "buggy.middleware", "langchain", "langchain_core", "langgraph")
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if any(name == b or name.startswith(b + ".") for b in BLOCKED):
            raise ImportError("blocked in the slim image: " + name)
        return None
sys.meta_path.insert(0, Block())
from buggy.cli import ci_gate
from buggy.findings import sarif
code = ci_gate.main(sys.argv[1:])
loaded = [m for m in sys.modules if any(m == b or m.startswith(b + ".") for b in BLOCKED)]
assert not loaded, loaded
print("exit", code)
"""


def test_importable_and_runs_without_the_agent_framework(tmp_path: Path) -> None:
    report = write_report(tmp_path, [HIGH])
    sarif = tmp_path / "out.sarif"
    # BUGGY_SKIP_BOOT=1 is what the slim pipeline image sets (containers/pipeline.Dockerfile).
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTEST", "BUGGY_"))}
    env["BUGGY_SKIP_BOOT"] = "1"
    proc = subprocess.run(
        [sys.executable, "-c", _BLOCKER, "--report", str(report), "--sarif", str(sarif)],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == "exit 10"
    assert sarif.exists()


# ── the GitHub Action and the example workflow ───────────────────────


def expressions_in_run_blocks(document: Any) -> list[str]:
    """Every ``run:`` script that contains a ``${{`` expression (script injection)."""
    found: list[str] = []
    if isinstance(document, dict):
        for key, value in document.items():
            if key == "run" and isinstance(value, str) and "${{" in value:
                found.append(value)
            else:
                found.extend(expressions_in_run_blocks(value))
    elif isinstance(document, list):
        for value in document:
            found.extend(expressions_in_run_blocks(value))
    return found


def test_injection_check_catches_an_expression_in_a_run_block() -> None:
    bad = yaml.safe_load(
        "runs:\n  steps:\n    - run: echo ${{ inputs.report }}\n    - run: echo fine\n"
    )
    assert expressions_in_run_blocks(bad) == ["echo ${{ inputs.report }}"]


def test_action_is_a_composite_action_with_the_documented_inputs() -> None:
    action = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    inputs = action["inputs"]
    assert set(inputs) == {"report", "hunt-result", "fail-on", "upload-sarif"}
    assert inputs["report"]["required"] is True
    assert inputs["fail-on"]["default"] == "high"
    assert inputs["upload-sarif"]["default"] == "true"
    assert "security-events: write" in inputs["upload-sarif"]["description"]
    steps = action["runs"]["steps"]
    assert expressions_in_run_blocks(action) == []
    for step in steps:
        if "run" in step:
            assert step.get("shell") == "bash"
            assert "set -x" not in step["run"]
    text = ACTION.read_text(encoding="utf-8")
    assert "secrets." not in text
    gate_step = next(s for s in steps if "ci-gate" in s.get("run", ""))
    assert "buggy-cli ci-gate" in gate_step["run"]
    assert set(gate_step["env"].values()) >= {
        "${{ inputs.report }}",
        "${{ inputs.hunt-result }}",
        "${{ inputs.fail-on }}",
    }
    upload = next(s for s in steps if "upload-sarif" in s.get("uses", ""))
    assert re.search(r"@[0-9a-f]{40}\b", upload["uses"]), "pin the upload action to a commit"
    assert "inputs.upload-sarif == 'true'" in upload["if"]
    assert "always()" in upload["if"]
    assert steps.index(upload) > steps.index(gate_step)


def test_ci_doc_example_workflow_parses_and_uses_the_action() -> None:
    text = DOC.read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(.*?)```", text, flags=re.DOTALL)
    assert blocks, "docs/ci.md has a yaml example"
    workflows = [yaml.safe_load(block) for block in blocks]
    workflow = next(w for w in workflows if isinstance(w, dict) and "jobs" in w)
    assert workflow["permissions"]["security-events"] == "write"
    steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
    runs = " ".join(step.get("run", "") for step in steps)
    assert "buggy hunt" in runs and "--lite" in runs and "--fail-on high" in runs
    action_steps = [s for s in steps if s.get("uses") == "./.github/actions/buggy-gate"]
    assert len(action_steps) == 1
    assert set(action_steps[0]["with"]) <= {"report", "hunt-result", "fail-on", "upload-sarif"}
    assert expressions_in_run_blocks(workflow) == []
