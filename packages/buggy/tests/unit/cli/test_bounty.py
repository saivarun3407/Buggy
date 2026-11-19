"""``buggy-cli bounty`` — kickoff wording + --print-kickoff."""

from __future__ import annotations

import pytest

from buggy.cli.bounty import main as bounty_main
from buggy.cli.bounty import scout_kickoff


def test_scout_kickoff_mentions_both_platforms_by_default() -> None:
    text = scout_kickoff()
    assert "HackerOne and Bugcrowd" in text
    assert "ingest_bounty_scope" in text


def test_scout_kickoff_single_platform() -> None:
    assert "HackerOne" in scout_kickoff("hackerone")
    assert "Bugcrowd" not in scout_kickoff("hackerone")
    assert "Bugcrowd" in scout_kickoff("bugcrowd")


def test_scout_kickoff_forbids_testing_before_scope() -> None:
    text = scout_kickoff()
    assert "Do not test anything until scope_show reports an enforced scope" in text
    # The agent drafts; only the operator's import enforces.
    assert "buggy-cli scope import" in text and "cannot enforce a scope yourself" in text


def test_print_kickoff_emits_and_exits_ok(capsys: pytest.CaptureFixture[str]) -> None:
    rc = bounty_main(["--print-kickoff"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "bounty Scout agent" in out or "Scout agent" in out


def test_print_kickoff_respects_platform(capsys: pytest.CaptureFixture[str]) -> None:
    rc = bounty_main(["--platform", "bugcrowd", "--print-kickoff"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Bugcrowd" in out
    assert "HackerOne" not in out
