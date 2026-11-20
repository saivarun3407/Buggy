"""Tests for benchmark.scorecard: a scorecard generated only from evidence records.

The run directories are fixtures built under ``tmp_path``; the figures in them
are arbitrary test inputs, not benchmark results.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from benchmark import evidence, scorecard

from .test_evidence import MODEL, REVISION, RUN_ID, build_run, flip_byte, new_flag, run_attempt


def table(markdown: str) -> list[list[str]]:
    """Cells of every table line, header and separator included."""
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in markdown.splitlines()
        if line.startswith("| ")
    ]


def target_rows(markdown: str) -> dict[str, list[str]]:
    """Record rows by target id (without the header, separator and total rows)."""
    return {row[0].strip("`"): row for row in table(markdown)[2:-1]}


def section(markdown: str, title: str) -> list[str]:
    lines = markdown.splitlines()
    start = lines.index(f"## {title}") + 1
    body: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        if line.strip():
            body.append(line)
    return body


def records_on_disk(directory: Path) -> list[dict]:
    """The records as plain JSON, read without the code under test."""
    return [
        json.loads(path.read_text())
        for path in sorted(directory.glob("*.json"))
        if path.name != "manifest.json"
    ]


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    directory = tmp_path / RUN_ID
    build_run(directory)
    return directory


class TestRows:
    def test_header_names_the_columns_of_the_contract(self, run_dir: Path) -> None:
        assert table(scorecard.render(run_dir))[0] == [
            "target",
            "level",
            "solved",
            "wall s",
            "in tokens",
            "out tokens",
            "cost",
            "transcript",
        ]

    def test_failed_targets_have_rows_with_their_terminal_state(self, run_dir: Path) -> None:
        rows = target_rows(scorecard.render(run_dir))

        assert list(rows) == ["T-001", "T-002", "T-003"]
        assert rows["T-001"][1:3] == ["1", "yes"]
        assert rows["T-002"][1:3] == ["2", "no (gave_up)"]
        assert rows["T-003"][1:3] == ["3", "no (timeout)"]
        assert rows["T-001"][3:7] == ["30.0", "1200", "300", "0.2500"]
        # Not measured is shown as such, never as zero.
        assert rows["T-003"][3:7] == ["60.0", "n/a", "n/a", "n/a"]
        assert rows["T-001"][7] == "[transcripts/T-001.jsonl](transcripts/T-001.jsonl) line 2"
        assert rows["T-002"][7] == "[transcripts/T-002.jsonl](transcripts/T-002.jsonl)"

    def test_not_attempted_targets_are_listed_by_id_and_have_no_row(self, run_dir: Path) -> None:
        markdown = scorecard.render(run_dir)

        assert section(markdown, "Not attempted") == ["- `T-004`"]
        assert "T-004" not in target_rows(markdown)

    def test_there_is_no_row_without_a_record(self, run_dir: Path) -> None:
        (run_dir / "T-002.json").unlink()

        markdown = scorecard.render(run_dir)

        assert list(target_rows(markdown)) == ["T-001", "T-003"]
        assert len(target_rows(markdown)) == len(records_on_disk(run_dir))
        assert section(markdown, "Not attempted") == ["- `T-002`", "- `T-004`"]

    def test_every_target_attempted_leaves_nothing_in_not_attempted(self, run_dir: Path) -> None:
        run_attempt(
            run_dir,
            "T-004",
            flag=new_flag(),
            lines=[{"text": "stuck"}],
            solved=False,
            terminal_state="error",
            error="target crashed",
            minute=30,
        )
        markdown = scorecard.render(run_dir)

        assert target_rows(markdown)["T-004"][2] == "no (error)"
        assert section(markdown, "Not attempted") == [
            "None: every target of the suite has a record."
        ]


class TestTotals:
    def _expect_totals(self, directory: Path) -> None:
        records = records_on_disk(directory)
        manifest = json.loads((directory / "manifest.json").read_text())
        solved = sum(1 for r in records if r["solved"])
        tokens_in = [r["tokens"]["input"] for r in records]
        tokens_out = [r["tokens"]["output"] for r in records]
        costs = [r["cost_usd"] for r in records]

        def cell(values: list, fmt: str) -> str:
            known = [v for v in values if v is not None]
            text = format(sum(known), fmt)
            missing = len(values) - len(known)
            return f"{text} ({missing} n/a)" if missing else text

        markdown = scorecard.render(directory)
        assert table(markdown)[-1] == [
            "**total**",
            "",
            f"{solved} of {len(records)} attempted",
            format(sum(r["wall_seconds"] for r in records), ".1f"),
            cell(tokens_in, "d"),
            cell(tokens_out, "d"),
            cell(costs, ".4f"),
            "",
        ]
        failures = {
            state: sum(1 for r in records if r["terminal_state"] == state)
            for state in ("gave_up", "timeout", "error")
        }
        assert section(markdown, "Totals") == [
            f"- Targets in suite: {len(manifest['targets'])}",
            f"- Attempted: {len(records)}",
            f"- Solved: {solved}",
            f"- Not solved: {len(records) - solved} (gave_up {failures['gave_up']}, "
            f"timeout {failures['timeout']}, error {failures['error']}, no outcome 0)",
            f"- Not attempted: {len(manifest['targets']) - len(records)}",
        ]

    def test_totals_equal_the_records(self, run_dir: Path) -> None:
        self._expect_totals(run_dir)
        # Spelled out once, so the helper above cannot be wrong in the same way as the code.
        assert table(scorecard.render(run_dir))[-1][2:7] == [
            "1 of 3 attempted",
            "135.0",
            "2000 (1 n/a)",
            "400 (1 n/a)",
            "0.3500 (1 n/a)",
        ]

    def test_totals_follow_the_records_when_they_change(self, run_dir: Path) -> None:
        before = table(scorecard.render(run_dir))[-1]
        flag = new_flag()
        run_attempt(
            run_dir,
            "T-004",
            flag=flag,
            lines=[{"text": f"found {flag}"}],
            solved=True,
            minute=30,
            wall=12,
            tokens=(10, 5),
            cost=0.01,
        )
        evidence.amend_record(run_dir, "T-003", tokens_input=7, tokens_output=3, cost_usd=0.5)

        self._expect_totals(run_dir)
        after = table(scorecard.render(run_dir))[-1]
        assert after != before
        assert after[2:7] == ["2 of 4 attempted", "147.0", "2017", "408", "0.8600"]

    def test_only_failures_gives_zero_solved(self, tmp_path: Path) -> None:
        evidence.write_manifest(tmp_path, run_id=RUN_ID, suite="fixture", targets=[("T-001", 1)])
        run_attempt(
            tmp_path,
            "T-001",
            flag=new_flag(),
            lines=[],
            solved=False,
            terminal_state="gave_up",
            error="no flag in solver output",
        )
        assert table(scorecard.render(tmp_path))[-1][2] == "0 of 1 attempted"


class TestHeader:
    def test_header_comes_from_the_records(self, run_dir: Path) -> None:
        markdown = scorecard.render(run_dir)

        assert f"- Run id: `{RUN_ID}`" in markdown
        assert "- Suite: `fixture`" in markdown
        assert "- Date: 2026-01-05 (UTC, first commitment)" in markdown
        assert f"- Revision: `{REVISION}`" in markdown
        assert f"- Model: `{MODEL}` (profile: `default`)" in markdown
        assert "lists under `black_box_inputs` (description, target_url)." in markdown

    def test_mixed_or_missing_model_is_shown_not_hidden(self, run_dir: Path) -> None:
        evidence.amend_record(run_dir, "T-002", model="other/model")
        data = json.loads((run_dir / "T-003.json").read_text())
        data["model"] = None
        (run_dir / "T-003.json").write_text(json.dumps(data))

        markdown = scorecard.render(run_dir)

        assert f"- Model: `{MODEL}`, `other/model`, not recorded" in markdown

    def test_no_black_box_statement_without_recorded_inputs(self, tmp_path: Path) -> None:
        evidence.write_manifest(tmp_path, run_id=RUN_ID, suite="fixture", targets=[("T-001", 1)])
        flag = new_flag()
        evidence.begin_attempt(
            tmp_path, run_id=RUN_ID, target="T-001", suite="fixture", flag=flag, model=MODEL
        )
        transcript = evidence.write_transcript(tmp_path, "T-001", [])
        evidence.finish_attempt(
            tmp_path,
            "T-001",
            flag=flag,
            solved=False,
            terminal_state="gave_up",
            error="nothing",
            transcript_file=transcript,
        )
        assert "- Black-box statement: none can be made" in scorecard.render(tmp_path)

    def test_without_a_manifest_not_attempted_is_unknown(self, run_dir: Path) -> None:
        (run_dir / "manifest.json").unlink()
        markdown = scorecard.render(run_dir)

        assert "- Targets in suite: unknown (no manifest.json)" in markdown
        assert section(markdown, "Not attempted") == [
            "Unknown: the run directory has no readable `manifest.json`."
        ]
        assert "missing_manifest" in markdown


class TestVerification:
    def test_sound_run_is_not_flagged(self, run_dir: Path) -> None:
        markdown = scorecard.render(run_dir)
        assert "FAILED" not in markdown
        assert "## Verification problems" not in markdown

    def test_tampered_run_is_flagged_on_the_scorecard(self, run_dir: Path) -> None:
        flip_byte(run_dir / "transcripts" / "T-001.jsonl")
        markdown = scorecard.render(run_dir)

        assert "- Verification: **FAILED**, 1 problem(s)" in markdown
        assert section(markdown, "Verification problems") == [
            "- T-001: transcript_hash_mismatch: transcripts/T-001.jsonl was changed"
        ]


class TestCli:
    def test_prints_the_scorecard(self, run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert scorecard.main([str(run_dir)]) == 0
        assert capsys.readouterr().out == scorecard.render(run_dir)
        assert not (run_dir / "SCORECARD.md").exists()

    def test_write_saves_the_scorecard_and_the_run_still_verifies(self, run_dir: Path) -> None:
        assert scorecard.main([str(run_dir), "--write"]) == 0

        assert (run_dir / "SCORECARD.md").read_text() == scorecard.render(run_dir)
        assert evidence.verify_run(run_dir) == []

    def test_hand_edited_scorecard_fails_verify(self, run_dir: Path) -> None:
        scorecard.main([str(run_dir), "--write"])
        path = run_dir / "SCORECARD.md"
        path.write_text(path.read_text().replace("1 of 3 attempted", "3 of 3 attempted"))

        assert [p.code for p in evidence.verify_run(run_dir)] == ["scorecard_stale"]

    def test_scorecard_goes_stale_when_a_record_is_added(self, run_dir: Path) -> None:
        scorecard.main([str(run_dir), "--write"])
        run_attempt(
            run_dir,
            "T-004",
            flag=new_flag(),
            lines=[],
            solved=False,
            terminal_state="gave_up",
            error="nothing",
            minute=30,
        )
        assert [p.code for p in evidence.verify_run(run_dir)] == ["scorecard_stale"]

    def test_write_is_refused_for_a_run_that_does_not_verify(
        self, run_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        tampered = run_dir.parent / "tampered"
        shutil.copytree(run_dir, tampered)
        flip_byte(tampered / "transcripts" / "T-002.jsonl")

        assert scorecard.main([str(tampered), "--write"]) == 1
        assert not (tampered / "SCORECARD.md").exists()
        assert "not written" in capsys.readouterr().out
        assert scorecard.main([str(tampered)]) == 1
