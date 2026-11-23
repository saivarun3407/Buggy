"""hunt closes a run whose agent stage happened outside it (Claude Code)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from buggy.cli import hunt

PRIOR = {
    "engagement": "acme",
    "recon": {"state": "completed", "records": {"http_service": 2}, "scope_drops": 0},
    "issues": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 3},
    "probes": {"ran_sweep": True, "planned": 13, "ran": 13, "vulnerable": 2, "verified": 2},
    "access": {"ran": False, "reason": "no test accounts are declared"},
    "agent": {"ran": False, "error": None},
}


def args(**overrides) -> argparse.Namespace:
    values = {"agent_runner": "claude-code", "no_agent": True, "force_agent": False}
    return argparse.Namespace(**{**values, **overrides})


def control_with(tmp_path: Path, prior: object) -> Path:
    (tmp_path / "acme").mkdir()
    (tmp_path / "acme" / hunt.RESULT_FILE).write_text(json.dumps(prior))
    return tmp_path


def test_earlier_stages_are_kept_and_the_agent_is_recorded(tmp_path: Path) -> None:
    outcome = hunt.finalize_outcome(control_with(tmp_path, PRIOR), "acme", args())
    assert outcome["recon"] == PRIOR["recon"]
    assert outcome["issues"]["high"] == 1 and outcome["issues"]["info"] == 3
    assert outcome["agent"] == {"ran": True, "error": None, "runner": "claude-code"}
    assert outcome["probes"]["verified"] == 2
    result = hunt.build_result("acme", outcome, {}, now=1.0)
    assert result["agent"] == {"ran": True, "error": None, "runner": "claude-code"}
    assert result["probes"]["ran_sweep"] is True and result["complete"] is True
    # The agents ran, so their kind of testing is no longer listed as missing.
    areas = [item["area"] for item in result["not_tested"]]
    assert not any(area.startswith("business logic") for area in areas)
    assert "access control between users (IDOR)" in areas


def test_a_sweep_that_never_ran_is_not_reported_as_run(tmp_path: Path) -> None:
    prior = {**PRIOR, "probes": {"ran_sweep": False}}
    outcome = hunt.finalize_outcome(control_with(tmp_path, prior), "acme", args())
    assert outcome["probes"] is None
    assert hunt.build_result("acme", outcome, {}, now=1.0)["probes"] == {"ran_sweep": False}


@pytest.mark.parametrize("prior", [None, [], "nonsense", {"recon": "x", "issues": 3}])
def test_a_missing_or_damaged_result_does_not_invent_a_recon(tmp_path: Path, prior) -> None:
    control = tmp_path
    (control / "acme").mkdir()
    if prior is not None:
        (control / "acme" / hunt.RESULT_FILE).write_text(json.dumps(prior))
    outcome = hunt.finalize_outcome(control, "acme", args())
    result = hunt.build_result("acme", outcome, {}, now=1.0)
    # "skipped" is hunt's own word for a recon it did not watch; no record counts appear.
    assert result["recon"]["state"] == "skipped" and not result["recon"].get("records")
    assert result["issues"] == dict.fromkeys(hunt.SEVERITIES, 0)


@pytest.mark.parametrize("name", ["", "claude code", "../x", "a" * 60])
def test_an_odd_runner_name_is_not_recorded(tmp_path: Path, name: str) -> None:
    outcome = hunt.finalize_outcome(control_with(tmp_path, PRIOR), "acme", args(agent_runner=name))
    assert outcome["agent"]["runner"] == "external"


def test_finalize_needs_resume(capsys) -> None:
    assert hunt.main(["--finalize"]) == hunt.EXIT_CONFIG
    assert "--finalize continues an engagement" in capsys.readouterr().err


class TestPointer:
    def test_written_only_under_the_name_the_launcher_chose(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv(hunt.POINTER_ENV, ".hunt-abc123DEF.json")
        hunt.write_pointer(tmp_path, "acme")
        assert json.loads((tmp_path / ".hunt-abc123DEF.json").read_text()) == {"engagement": "acme"}

    @pytest.mark.parametrize(
        "name", ["", "../.hunt-abcdef.json", "roe.json", ".hunt-abc.json", ".hunt-abcdef.json/x"]
    )
    def test_any_other_name_is_ignored(self, tmp_path, monkeypatch, name: str) -> None:
        monkeypatch.setenv(hunt.POINTER_ENV, name)
        hunt.write_pointer(tmp_path, "acme")
        assert list(tmp_path.iterdir()) == []


class TestAgentCostAndDisprover:
    def runs(self, audit: Path) -> None:
        (audit / "acme" / "agent").mkdir(parents=True)
        rows = [
            {
                "role": "agent",
                "wall_seconds": 300,
                "tool_calls": 80,
                "signin_calls": 6,
                "claude": {"total_cost_usd": 2.5, "usage": {"input_tokens": 50000}},
            },
            {"role": "skeptic", "wall_seconds": 60, "tool_calls": 9},
        ]
        (audit / "acme" / "agent" / "agent-runs.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows)
        )

    def test_the_result_records_the_cost_and_the_disprover(self, tmp_path: Path) -> None:
        control, audit = control_with(tmp_path, PRIOR), tmp_path / "audit"
        self.runs(audit)
        outcome = hunt.finalize_outcome(control, "acme", args(audit_root=audit, disprover="ran"))
        result = hunt.build_result("acme", outcome, {}, now=1.0)
        assert result["agent"]["disprover"] == "ran"
        cost = result["agent_cost"]
        assert cost["sessions"] == 2 and cost["tool_calls"] == 89 and cost["cost_usd"] == 2.5
        assert cost["line"].startswith("2 Claude Code session(s), 89 tool calls (6 on sign-in)")

    def test_no_runs_no_cost_section(self, tmp_path: Path) -> None:
        control = control_with(tmp_path, PRIOR)
        outcome = hunt.finalize_outcome(control, "acme", args(audit_root=tmp_path / "none"))
        assert "agent_cost" not in hunt.build_result("acme", outcome, {}, now=1.0)

    def test_the_markdown_report_gets_an_agent_cost_line(self) -> None:
        text = "# Security report: acme\n\nGenerated now.\n\n## Summary\n\nNothing.\n"
        out = hunt.with_agent_cost(text, "1 Claude Code session(s), 3 tool calls")
        assert "Agent cost: 1 Claude Code session(s), 3 tool calls.\n\n## Summary" in out
        assert hunt.with_agent_cost(text, "") == text

    def test_the_disprover_state_is_a_fixed_word(self) -> None:
        parser = hunt._build_parser()  # noqa: SLF001
        assert parser.parse_args(["--disprover", "skipped", "x"]).disprover == "skipped"
        with pytest.raises(SystemExit):
            parser.parse_args(["--disprover", "whatever", "x"])
