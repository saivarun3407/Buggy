"""Tests for benchmark.evidence: the record contract and its verifier.

Every run directory here is a fixture built under ``tmp_path`` with an injected
clock. None of it is a benchmark result.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import benchmark
from benchmark import evidence
from benchmark.evidence import EvidenceError, RunRecord

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
RUN_ID = "fixture-run"
SUITE = "fixture"
MODEL = "fixture-provider/fixture-model"
REVISION = "a1b2c3d"
TARGETS = [("T-001", 1), ("T-002", 2), ("T-003", 3), ("T-004", 1)]


def new_flag() -> str:
    return "FLAG{" + secrets.token_hex(32) + "}"


def run_attempt(
    directory: Path,
    target: str,
    *,
    flag: str,
    lines: list[dict],
    solved: bool,
    terminal_state: str | None = None,
    error: str | None = None,
    minute: int = 0,
    wall: int = 30,
    tokens: tuple[int | None, int | None] = (None, None),
    cost: float | None = None,
) -> RunRecord:
    """Commit, write a transcript, then record the outcome, on a fixed clock."""
    committed = T0 + timedelta(minutes=minute)
    started = committed + timedelta(seconds=5)
    finished = started + timedelta(seconds=wall)
    evidence.begin_attempt(
        directory,
        run_id=RUN_ID,
        target=target,
        suite=SUITE,
        flag=flag,
        git_revision=REVISION,
        model=MODEL,
        model_profile="default",
        now=committed,
    )
    transcript = evidence.write_transcript(directory, target, lines)
    return evidence.finish_attempt(
        directory,
        target,
        flag=flag,
        solved=solved,
        transcript_file=transcript,
        terminal_state=terminal_state,  # type: ignore[arg-type]
        error=error,
        started_at=started,
        finished_at=finished,
        now=finished + timedelta(seconds=1),
        black_box_inputs=[f"target_url=http://{target.lower()}.test", "description=fixture"],
        image_digests={"web": "sha256:" + "ab" * 32},
        tokens_input=tokens[0],
        tokens_output=tokens[1],
        cost_usd=cost,
    )


def build_run(directory: Path) -> dict[str, str]:
    """A fixture run: one win, one give-up, one timeout, one target not attempted.

    Returns the flag of each attempted target.
    """
    evidence.write_manifest(directory, run_id=RUN_ID, suite=SUITE, targets=TARGETS)
    flags = {target: new_flag() for target, _ in TARGETS[:3]}
    run_attempt(
        directory,
        "T-001",
        flag=flags["T-001"],
        lines=[
            {"role": "assistant", "text": "enumerating the target"},
            {"role": "tool", "text": f"response body: {flags['T-001']}"},
        ],
        solved=True,
        tokens=(1200, 300),
        cost=0.25,
    )
    run_attempt(
        directory,
        "T-002",
        flag=flags["T-002"],
        lines=[{"role": "assistant", "text": "nothing exploitable found"}],
        solved=False,
        terminal_state="gave_up",
        error="no flag in solver output",
        minute=10,
        wall=45,
        tokens=(800, 100),
        cost=0.1,
    )
    run_attempt(
        directory,
        "T-003",
        flag=flags["T-003"],
        lines=[],
        solved=False,
        terminal_state="timeout",
        error="Timeout after 60s",
        minute=20,
        wall=60,
    )
    return flags


def read_json(directory: Path, target: str) -> dict:
    return json.loads(evidence.record_path(directory, target).read_text())


def tamper(directory: Path, target: str, **changes: object) -> None:
    """Edit a record on disk the way someone with a text editor would."""
    data = read_json(directory, target)
    data.update(changes)
    evidence.record_path(directory, target).write_text(json.dumps(data, indent=2) + "\n")


def flip_byte(path: Path, index: int = 0) -> None:
    data = bytearray(path.read_bytes())
    data[index] ^= 0x01
    path.write_bytes(bytes(data))


def codes(directory: Path) -> set[str]:
    return {problem.code for problem in evidence.verify_run(directory)}


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    directory = tmp_path / RUN_ID
    build_run(directory)
    # Negative control for every tampering test below: untouched, it verifies.
    assert evidence.verify_run(directory) == []
    return directory


class TestCommitment:
    def test_commit_flag_is_sha256_of_the_flag(self) -> None:
        flag, other = new_flag(), new_flag()
        assert evidence.commit_flag(flag) == hashlib.sha256(flag.encode()).hexdigest()
        assert evidence.commit_flag(flag) != evidence.commit_flag(other)

    def test_commitment_is_written_without_the_flag(self, tmp_path: Path) -> None:
        flag = new_flag()
        evidence.write_manifest(tmp_path, run_id=RUN_ID, suite=SUITE, targets=TARGETS)
        record = evidence.begin_attempt(
            tmp_path, run_id=RUN_ID, target="T-001", suite=SUITE, flag=flag, now=T0
        )

        on_disk = evidence.record_path(tmp_path, "T-001").read_text()
        assert flag not in on_disk
        assert flag[5:-1] not in on_disk
        assert record.pending
        assert read_json(tmp_path, "T-001")["flag_commitment"] == evidence.commit_flag(flag)
        assert read_json(tmp_path, "T-001")["flag_revealed"] is None
        assert evidence.check_commitment(record) is False  # nothing revealed yet

    def test_check_commitment_follows_the_revealed_flag(self, run_dir: Path) -> None:
        record = evidence.load_record(evidence.record_path(run_dir, "T-002"))
        assert evidence.check_commitment(record) is True
        swapped = record.model_copy(update={"flag_revealed": new_flag()})
        assert evidence.check_commitment(swapped) is False


class TestVerify:
    def test_solved_record_with_commitment_and_flag_in_transcript_verifies(
        self, tmp_path: Path
    ) -> None:
        directory = tmp_path / RUN_ID
        flags = build_run(directory)

        assert evidence.verify_run(directory) == []

        record = evidence.load_record(evidence.record_path(directory, "T-001"))
        transcript = directory / "transcripts" / "T-001.jsonl"
        lines = transcript.read_bytes().split(b"\n")
        assert record.solved and record.terminal_state == "solved"
        assert record.flag_revealed == flags["T-001"]
        assert record.transcript_sha256 == hashlib.sha256(transcript.read_bytes()).hexdigest()
        assert record.win_evidence is not None
        assert record.win_evidence.line == 2
        assert flags["T-001"].encode() in lines[1]
        assert record.win_evidence.sha256_of_line == hashlib.sha256(lines[1]).hexdigest()

    def test_changed_flag_is_caught(self, run_dir: Path) -> None:
        tamper(run_dir, "T-001", flag_revealed=new_flag())
        assert {"commitment_mismatch", "flag_not_in_transcript"} <= codes(run_dir)

    def test_swapping_flag_and_commitment_together_is_caught(self, run_dir: Path) -> None:
        forged = new_flag()
        tamper(run_dir, "T-001", flag_revealed=forged, flag_commitment=evidence.commit_flag(forged))
        assert codes(run_dir) == {"flag_not_in_transcript"}

    @pytest.mark.parametrize("target", ["T-001", "T-002"])
    def test_changed_transcript_byte_is_caught(self, run_dir: Path, target: str) -> None:
        flip_byte(run_dir / "transcripts" / f"{target}.jsonl", index=3)
        assert "transcript_hash_mismatch" in codes(run_dir)

    def test_solved_true_without_the_flag_in_the_transcript_is_caught(self, run_dir: Path) -> None:
        # Promote the give-up to a win, citing a real line with its real hash.
        line = (run_dir / "transcripts" / "T-002.jsonl").read_bytes().split(b"\n")[0]
        tamper(
            run_dir,
            "T-002",
            solved=True,
            terminal_state="solved",
            error=None,
            win_evidence={
                "transcript_file": "transcripts/T-002.jsonl",
                "line": 1,
                "sha256_of_line": hashlib.sha256(line).hexdigest(),
            },
        )
        assert codes(run_dir) == {"flag_not_in_transcript"}

    def test_win_citing_a_line_without_the_flag_is_caught(self, run_dir: Path) -> None:
        line = (run_dir / "transcripts" / "T-001.jsonl").read_bytes().split(b"\n")[0]
        win = read_json(run_dir, "T-001")["win_evidence"]
        win.update(line=1, sha256_of_line=hashlib.sha256(line).hexdigest())
        tamper(run_dir, "T-001", win_evidence=win)
        assert codes(run_dir) == {"flag_not_in_transcript"}

    def test_solved_without_win_evidence_is_caught(self, run_dir: Path) -> None:
        tamper(run_dir, "T-001", win_evidence=None)
        assert codes(run_dir) == {"missing_win_evidence"}

    def test_commitment_written_after_the_reveal_is_caught(self, run_dir: Path) -> None:
        revealed = datetime.fromisoformat(read_json(run_dir, "T-001")["revealed_at"])
        tamper(run_dir, "T-001", committed_at=(revealed + timedelta(hours=1)).isoformat())
        assert "commitment_after_reveal" in codes(run_dir)

    def test_commitment_written_after_the_attempt_started_is_caught(self, run_dir: Path) -> None:
        started = datetime.fromisoformat(read_json(run_dir, "T-001")["started_at"])
        tamper(run_dir, "T-001", committed_at=(started + timedelta(seconds=10)).isoformat())
        assert codes(run_dir) == {"commitment_after_start"}

    def test_missing_transcript_is_caught(self, run_dir: Path) -> None:
        (run_dir / "transcripts" / "T-002.jsonl").unlink()
        assert codes(run_dir) == {"missing_transcript"}

    def test_transcript_outside_the_run_directory_is_caught(self, run_dir: Path) -> None:
        outside = run_dir.parent / "elsewhere.jsonl"
        shutil.copy(run_dir / "transcripts" / "T-002.jsonl", outside)
        tamper(run_dir, "T-002", transcript_file="../elsewhere.jsonl")
        assert codes(run_dir) == {"transcript_outside_run"}

    def test_duplicate_target_is_caught(self, run_dir: Path) -> None:
        shutil.copy(run_dir / "T-001.json", run_dir / "T-001-again.json")
        assert "duplicate_target" in codes(run_dir)

    @pytest.mark.parametrize("reason", [None, "", "   "])
    def test_failure_without_a_reason_is_caught(self, run_dir: Path, reason: str | None) -> None:
        tamper(run_dir, "T-002", error=reason)
        assert codes(run_dir) == {"no_failure_reason"}

    def test_commitment_without_an_outcome_is_caught(self, run_dir: Path) -> None:
        evidence.begin_attempt(
            run_dir, run_id=RUN_ID, target="T-004", suite=SUITE, flag=new_flag(), model=MODEL
        )
        problems = evidence.verify_run(run_dir)
        assert {(p.target, p.code) for p in problems} >= {("T-004", "no_outcome")}

    def test_record_for_a_target_outside_the_manifest_is_caught(self, run_dir: Path) -> None:
        manifest = json.loads((run_dir / "manifest.json").read_text())
        manifest["targets"] = [t for t in manifest["targets"] if t["id"] != "T-002"]
        (run_dir / "manifest.json").write_text(json.dumps(manifest))
        assert codes(run_dir) == {"target_not_in_manifest"}

    def test_missing_manifest_is_caught(self, run_dir: Path) -> None:
        (run_dir / "manifest.json").unlink()
        assert codes(run_dir) == {"missing_manifest"}

    def test_record_without_a_model_is_caught(self, run_dir: Path) -> None:
        tamper(run_dir, "T-003", model=None)
        assert codes(run_dir) == {"missing_model"}

    def test_unreadable_record_is_caught(self, run_dir: Path) -> None:
        (run_dir / "T-002.json").write_text("{not json")
        assert codes(run_dir) == {"unreadable_record"}

    def test_empty_directory_does_not_verify(self, tmp_path: Path) -> None:
        assert codes(tmp_path) == {"missing_manifest", "no_records"}
        assert codes(tmp_path / "absent") == {"no_run_directory"}


class TestWriteRecord:
    def _committed(self, tmp_path: Path, flag: str) -> RunRecord:
        evidence.write_manifest(tmp_path, run_id=RUN_ID, suite=SUITE, targets=TARGETS)
        return evidence.begin_attempt(
            tmp_path, run_id=RUN_ID, target="T-001", suite=SUITE, flag=flag, model=MODEL, now=T0
        )

    def _claim_win(self, pending: RunRecord, directory: Path, flag: str) -> RunRecord:
        """A fully-formed ``solved: true`` record citing line 1 of the transcript."""
        transcript = directory / "transcripts" / "T-001.jsonl"
        line = transcript.read_bytes().split(b"\n")[0]
        return pending.model_copy(
            update={
                "started_at": (T0 + timedelta(seconds=5)).isoformat(),
                "finished_at": (T0 + timedelta(seconds=35)).isoformat(),
                "revealed_at": (T0 + timedelta(seconds=36)).isoformat(),
                "wall_seconds": 30.0,
                "flag_revealed": flag,
                "solved": True,
                "terminal_state": "solved",
                "transcript_file": "transcripts/T-001.jsonl",
                "transcript_sha256": hashlib.sha256(transcript.read_bytes()).hexdigest(),
                "win_evidence": evidence.WinEvidence(
                    transcript_file="transcripts/T-001.jsonl",
                    line=1,
                    sha256_of_line=hashlib.sha256(line).hexdigest(),
                ),
            }
        )

    def test_refuses_solved_true_when_the_flag_is_not_in_the_transcript(
        self, tmp_path: Path
    ) -> None:
        flag = new_flag()
        pending = self._committed(tmp_path, flag)
        evidence.write_transcript(tmp_path, "T-001", [{"text": "I am sure I solved it"}])

        with pytest.raises(EvidenceError, match="flag_not_in_transcript"):
            evidence.write_record(self._claim_win(pending, tmp_path, flag), tmp_path)
        with pytest.raises(EvidenceError, match="not in the transcript"):
            evidence.finish_attempt(
                tmp_path,
                "T-001",
                flag=flag,
                solved=True,
                transcript_file="transcripts/T-001.jsonl",
            )

        on_disk = read_json(tmp_path, "T-001")
        assert on_disk["solved"] is False
        assert on_disk["flag_revealed"] is None

    def test_accepts_the_same_claim_when_the_flag_is_in_the_transcript(
        self, tmp_path: Path
    ) -> None:
        flag = new_flag()
        pending = self._committed(tmp_path, flag)
        evidence.write_transcript(tmp_path, "T-001", [{"text": f"got {flag}"}])

        evidence.write_record(self._claim_win(pending, tmp_path, flag), tmp_path)

        assert read_json(tmp_path, "T-001")["solved"] is True
        assert evidence.verify_run(tmp_path) == [
            evidence.Problem("T-001", "missing_git_revision", "no revision recorded")
        ]

    def test_refuses_solved_true_when_the_flag_does_not_match_the_commitment(
        self, tmp_path: Path
    ) -> None:
        pending = self._committed(tmp_path, new_flag())
        other = new_flag()
        evidence.write_transcript(tmp_path, "T-001", [{"text": f"got {other}"}])

        with pytest.raises(EvidenceError, match="commitment_mismatch"):
            evidence.write_record(self._claim_win(pending, tmp_path, other), tmp_path)
        with pytest.raises(EvidenceError, match="commitment_mismatch"):
            evidence.finish_attempt(
                tmp_path,
                "T-001",
                flag=other,
                solved=True,
                transcript_file="transcripts/T-001.jsonl",
            )
        assert read_json(tmp_path, "T-001")["solved"] is False

    def test_refuses_an_outcome_when_no_commitment_was_written_first(self, tmp_path: Path) -> None:
        flag = new_flag()
        source = tmp_path / "source"
        pending = self._committed(source, flag)
        evidence.write_transcript(source, "T-001", [{"text": f"got {flag}"}])
        finished = self._claim_win(pending, source, flag)

        target_dir = tmp_path / "fresh"
        shutil.copytree(source / "transcripts", target_dir / "transcripts")
        with pytest.raises(EvidenceError, match="no commitment on disk"):
            evidence.write_record(finished, target_dir)
        assert not (target_dir / "T-001.json").exists()

    def test_commitment_cannot_be_replaced(self, tmp_path: Path) -> None:
        self._committed(tmp_path, new_flag())
        before = (tmp_path / "T-001.json").read_bytes()

        with pytest.raises(EvidenceError):
            evidence.begin_attempt(
                tmp_path, run_id=RUN_ID, target="T-001", suite=SUITE, flag=new_flag(), now=T0
            )
        assert (tmp_path / "T-001.json").read_bytes() == before

    def test_a_failure_cannot_be_rewritten_into_a_win(self, run_dir: Path) -> None:
        record = evidence.load_record(evidence.record_path(run_dir, "T-002"))
        assert record.flag_revealed is not None
        transcript = run_dir / "transcripts" / "T-002.jsonl"
        transcript.write_text(json.dumps({"text": record.flag_revealed}) + "\n")
        line = transcript.read_bytes().split(b"\n")[0]
        forged = record.model_copy(
            update={
                "solved": True,
                "terminal_state": "solved",
                "error": None,
                "transcript_sha256": hashlib.sha256(transcript.read_bytes()).hexdigest(),
                "win_evidence": evidence.WinEvidence(
                    transcript_file="transcripts/T-002.jsonl",
                    line=1,
                    sha256_of_line=hashlib.sha256(line).hexdigest(),
                ),
            }
        )

        with pytest.raises(EvidenceError, match="cannot change after the outcome"):
            evidence.write_record(forged, run_dir)
        with pytest.raises(EvidenceError, match="already recorded"):
            evidence.finish_attempt(
                run_dir,
                "T-002",
                flag=record.flag_revealed,
                solved=True,
                transcript_file="transcripts/T-002.jsonl",
            )
        assert read_json(run_dir, "T-002")["solved"] is False

    def test_failure_needs_a_state_and_a_reason(self, tmp_path: Path) -> None:
        flag = new_flag()
        self._committed(tmp_path, flag)
        transcript = evidence.write_transcript(tmp_path, "T-001", [{"text": "no luck"}])

        with pytest.raises(EvidenceError, match="terminal_state"):
            evidence.finish_attempt(
                tmp_path, "T-001", flag=flag, solved=False, transcript_file=transcript
            )
        with pytest.raises(EvidenceError, match="no_failure_reason"):
            evidence.finish_attempt(
                tmp_path,
                "T-001",
                flag=flag,
                solved=False,
                terminal_state="gave_up",
                transcript_file=transcript,
            )
        assert read_json(tmp_path, "T-001")["terminal_state"] is None

    def test_amend_adds_measurements_but_cannot_turn_a_failure_into_a_win(
        self, run_dir: Path
    ) -> None:
        evidence.amend_record(
            run_dir, "T-003", tokens_input=50, tokens_output=7, cost_usd=0.02, model="p/m2"
        )
        evidence.amend_record(run_dir, "T-002", terminal_state="timeout", error="Timeout after 9s")

        amended = read_json(run_dir, "T-003")
        assert amended["tokens"] == {"input": 50, "output": 7}
        assert amended["cost_usd"] == 0.02
        assert amended["model"] == "p/m2"
        assert read_json(run_dir, "T-002")["terminal_state"] == "timeout"
        assert evidence.verify_run(run_dir) == []

        with pytest.raises(EvidenceError, match="failure states"):
            evidence.amend_record(run_dir, "T-002", terminal_state="solved")
        with pytest.raises(EvidenceError, match="failure states"):
            evidence.amend_record(run_dir, "T-001", terminal_state="gave_up")
        assert read_json(run_dir, "T-002")["solved"] is False
        assert read_json(run_dir, "T-001")["solved"] is True

    def test_attempt_needs_a_manifest_listing_the_target(self, tmp_path: Path) -> None:
        with pytest.raises(EvidenceError, match="manifest"):
            evidence.begin_attempt(
                tmp_path, run_id=RUN_ID, target="T-001", suite=SUITE, flag=new_flag()
            )
        evidence.write_manifest(tmp_path, run_id=RUN_ID, suite=SUITE, targets=TARGETS)
        with pytest.raises(EvidenceError, match="not a target"):
            evidence.begin_attempt(
                tmp_path, run_id=RUN_ID, target="T-999", suite=SUITE, flag=new_flag()
            )
        assert evidence.record_files(tmp_path) == []

    def test_manifest_cannot_be_rewritten_with_fewer_targets(self, tmp_path: Path) -> None:
        evidence.write_manifest(tmp_path, run_id=RUN_ID, suite=SUITE, targets=TARGETS)
        evidence.write_manifest(tmp_path, run_id=RUN_ID, suite=SUITE, targets=TARGETS)  # same: ok
        with pytest.raises(EvidenceError, match="different content"):
            evidence.write_manifest(tmp_path, run_id=RUN_ID, suite=SUITE, targets=TARGETS[:1])
        assert len(json.loads((tmp_path / "manifest.json").read_text())["targets"]) == len(TARGETS)

    @pytest.mark.parametrize("target", ["../escape", "a/b", "manifest", ""])
    def test_target_must_be_a_safe_file_name(self, tmp_path: Path, target: str) -> None:
        with pytest.raises(EvidenceError):
            evidence.write_manifest(tmp_path, run_id=RUN_ID, suite=SUITE, targets=[(target, 1)])
        assert not list(tmp_path.rglob("*.json"))


class TestCli:
    def test_verify_returns_0_for_a_sound_run_and_1_for_a_tampered_copy(
        self, run_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        tampered = run_dir.parent / "tampered"
        shutil.copytree(run_dir, tampered)
        flip_byte(tampered / "transcripts" / "T-001.jsonl")

        assert evidence.main(["verify", str(run_dir)]) == 0
        assert "FAIL" not in capsys.readouterr().out
        assert evidence.main(["verify", str(tampered)]) == 1
        assert "FAIL T-001: transcript_hash_mismatch" in capsys.readouterr().out

    def test_python_m_benchmark_evidence_exit_codes(self, run_dir: Path) -> None:
        tampered = run_dir.parent / "tampered"
        shutil.copytree(run_dir, tampered)
        tamper(tampered, "T-001", flag_revealed=new_flag())
        repo_root = Path(benchmark.__file__).resolve().parent.parent

        def verify(directory: Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "-m", "benchmark.evidence", "verify", str(directory)],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=120,
            )

        sound, broken = verify(run_dir), verify(tampered)
        assert sound.returncode == 0, sound.stdout + sound.stderr
        assert broken.returncode == 1, broken.stdout + broken.stderr
        assert "commitment_mismatch" in broken.stdout
