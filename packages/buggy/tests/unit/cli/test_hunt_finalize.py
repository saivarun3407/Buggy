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
