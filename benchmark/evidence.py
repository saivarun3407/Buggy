"""Benchmark evidence contract: one checkable record per target per run.

A run directory (``benchmark/results/<run-id>/``) holds:

- ``manifest.json``: run id, suite and every target of the suite (the
  denominator, so "not attempted" cannot be hidden).
- ``<target>.json``: one :class:`RunRecord`. It is written twice: first with
  only the sha256 commitment of the random flag, BEFORE the attempt starts, and
  again after the attempt with the revealed flag and the outcome.
- ``transcripts/<target>.jsonl``: the raw solver output the outcome was decided
  on.

``python -m benchmark.evidence verify <dir>`` re-checks every record from the
files alone and exits non-zero when anything does not hold.

What a passing ``verify`` shows: the files are internally consistent (the
revealed flag matches the commitment, the transcript is the one that was
hashed, a claimed win cites a transcript line that contains the flag, every
failure has a reason, nothing is duplicated or missing). Timestamps are
self-reported; the commitment only binds against after-the-fact edits for a
reader who obtained the commitment file before the reveal.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

SCHEMA_VERSION = 1
MANIFEST_FILE = "manifest.json"
SCORECARD_FILE = "SCORECARD.md"
TRANSCRIPT_DIR = "transcripts"
FAILURE_STATES = ("gave_up", "timeout", "error")
# finished_at - started_at may differ from wall_seconds by rounding only.
WALL_TOLERANCE_SECONDS = 1.0

TerminalState = Literal["solved", "gave_up", "timeout", "error"]

_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_RESERVED_TARGETS = {"manifest"}


class EvidenceError(Exception):
    """A record, manifest or transcript that the contract refuses to write."""


@dataclass(frozen=True)
class Problem:
    """One thing ``verify_run`` found wrong. ``target`` is a target id or a file name."""

    target: str
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.target}: {self.code}: {self.detail}"


def _check_target(value: str) -> str:
    if not _TARGET_RE.match(value) or value in _RESERVED_TARGETS:
        raise ValueError(f"target id {value!r} is not usable as a file name")
    return value


class WinEvidence(BaseModel):
    """Where in the transcript the flag appears. ``line`` is 1-based."""

    model_config = ConfigDict(extra="forbid")

    transcript_file: str
    line: int = Field(ge=1)
    sha256_of_line: str


class Tokens(BaseModel):
    """Token usage. ``None`` means "not measured", never zero."""

    model_config = ConfigDict(extra="forbid")

    input: int | None = Field(default=None, ge=0)
    output: int | None = Field(default=None, ge=0)


class RunRecord(BaseModel):
    """One attempt at one target. Timestamps are RFC 3339 with an offset."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    schema_version: int = SCHEMA_VERSION
    run_id: str
    target: str
    suite: str
    attempt: int = Field(default=1, ge=1)
    # When the commitment below was written. Must precede everything else.
    committed_at: str
    started_at: str | None = None
    finished_at: str | None = None
    # When ``flag_revealed`` was written.
    revealed_at: str | None = None
    wall_seconds: float | None = Field(default=None, ge=0)
    # "<provider>/<model id>" as the operator stated it; ``None`` is "not recorded".
    model: str | None = None
    model_profile: str | None = None
    git_revision: str | None = None
    image_digests: dict[str, str] = Field(default_factory=dict)
    # Exact list of what the solver was given, one "<name>=<value>" per entry.
    black_box_inputs: list[str] = Field(default_factory=list)
    # sha256 hex of the random flag, written BEFORE the attempt starts.
    flag_commitment: str
    # The flag itself, written after the attempt (solved or not).
    flag_revealed: str | None = None
    solved: bool = False
    win_evidence: WinEvidence | None = None
    tokens: Tokens = Field(default_factory=Tokens)
    cost_usd: float | None = Field(default=None, ge=0)
    # ``None`` while only the commitment exists.
    terminal_state: TerminalState | None = None
    error: str | None = None
    # Raw, unedited JSONL, relative to the run directory.
    transcript_file: str | None = None
    transcript_sha256: str | None = None

    @field_validator("target")
    @classmethod
    def _target_ok(cls, value: str) -> str:
        return _check_target(value)

    @property
    def pending(self) -> bool:
        """True while the record is only a commitment (no outcome yet)."""
        return self.terminal_state is None and self.flag_revealed is None


class ManifestTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    level: int | None = None

    @field_validator("id")
    @classmethod
    def _id_ok(cls, value: str) -> str:
        return _check_target(value)


class Manifest(BaseModel):
    """The suite a run draws from: every target, attempted or not."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = SCHEMA_VERSION
    run_id: str
    suite: str
    targets: list[ManifestTarget]


# ── small helpers ────────────────────────────────────────────────────────────


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise EvidenceError("timestamps must carry a UTC offset")
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _parse_time(value: str | None) -> datetime | None:
    """Parse a record timestamp; ``None`` when absent, malformed or without offset."""
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def new_run_id(suite: str) -> str:
    """``<suite>-<UTC time>-<random>``: sortable and unique per run."""
    return f"{suite}-{utc_now():%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"


def git_revision(cwd: Path | None = None) -> str | None:
    """HEAD of the checkout, with ``+dirty`` when tracked files are modified."""
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if not head:
        return None
    return f"{head}+dirty" if dirty else head


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def commit_flag(flag: str) -> str:
    """The commitment published before an attempt: sha256 hex of the flag.

    Plain sha256 hides the flag only because the flag itself is long and
    random; do not use this for guessable flags.
    """
    if not flag:
        raise EvidenceError("cannot commit to an empty flag")
    return sha256_bytes(flag.encode("utf-8"))


def check_commitment(record: RunRecord) -> bool:
    """True when the revealed flag hashes to the commitment written beforehand."""
    if not record.flag_revealed:
        return False
    return hmac.compare_digest(
        sha256_bytes(record.flag_revealed.encode("utf-8")), record.flag_commitment
    )


def record_path(directory: Path, target: str) -> Path:
    return Path(directory) / f"{_check_target(target)}.json"


def record_files(directory: Path) -> list[Path]:
    """Every record file of a run directory (all ``*.json`` but the manifest)."""
    return sorted(
        path
        for path in Path(directory).glob("*.json")
        if path.is_file() and path.name != MANIFEST_FILE
    )


def load_record(path: Path) -> RunRecord:
    try:
        return RunRecord.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError) as exc:
        raise EvidenceError(f"{Path(path).name}: not a readable record: {exc}") from exc


def load_manifest(directory: Path) -> Manifest:
    path = Path(directory) / MANIFEST_FILE
    try:
        return Manifest.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError) as exc:
        raise EvidenceError(f"{MANIFEST_FILE}: not a readable manifest: {exc}") from exc


def _dump(model: BaseModel) -> bytes:
    return (json.dumps(model.model_dump(mode="json"), indent=2) + "\n").encode("utf-8")


def _write_new(path: Path, data: bytes) -> None:
    """Create ``path``; fail if it already exists (never overwrite evidence)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError as exc:
        raise EvidenceError(f"{path.name} already exists; refusing to overwrite it") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _replace(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with tmp.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _transcript_path(directory: Path, relative: str) -> Path | None:
    """Resolve a record's transcript path; ``None`` if it leaves the run directory."""
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    root = Path(directory).resolve()
    resolved = (root / candidate).resolve()
    return resolved if resolved.is_relative_to(root) else None


def _transcript_lines(path: Path) -> list[bytes]:
    return path.read_bytes().split(b"\n")


def find_flag_line(path: Path, flag: str) -> tuple[int, str] | None:
    """First transcript line containing ``flag``: ``(1-based line, sha256 of the line)``."""
    needle = flag.encode("utf-8")
    for number, line in enumerate(_transcript_lines(path), start=1):
        if needle in line:
            return number, sha256_bytes(line)
    return None


# ── checks shared by write_record and verify_run ─────────────────────────────


def _check_times(record: RunRecord) -> list[Problem]:
    def problem(code: str, detail: str) -> Problem:
        return Problem(record.target, code, detail)

    times: dict[str, datetime] = {}
    problems: list[Problem] = []
    for name in ("committed_at", "started_at", "finished_at", "revealed_at"):
        moment = _parse_time(getattr(record, name))
        if moment is None:
            problems.append(problem("bad_timestamp", f"{name} is missing or not RFC 3339"))
        else:
            times[name] = moment
    if problems:
        return problems
    if times["committed_at"] >= times["revealed_at"]:
        problems.append(
            problem("commitment_after_reveal", "the commitment is not older than the reveal")
        )
    if times["committed_at"] > times["started_at"]:
        problems.append(
            problem("commitment_after_start", "the commitment was written after the attempt began")
        )
    if not times["started_at"] <= times["finished_at"] <= times["revealed_at"]:
        problems.append(
            problem("timestamps_out_of_order", "expected started <= finished <= revealed")
        )
    elapsed = (times["finished_at"] - times["started_at"]).total_seconds()
    if record.wall_seconds is None or abs(record.wall_seconds - elapsed) > WALL_TOLERANCE_SECONDS:
        problems.append(
            problem(
                "wall_seconds_mismatch",
                f"wall_seconds={record.wall_seconds} but finished - started = {elapsed:.3f}",
            )
        )
    return problems


def _check_win(record: RunRecord, transcript: Path | None) -> list[Problem]:
    def problem(code: str, detail: str) -> Problem:
        return Problem(record.target, code, detail)

    win = record.win_evidence
    if win is None:
        return [problem("missing_win_evidence", "solved without a cited transcript line")]
    if win.transcript_file != record.transcript_file:
        return [problem("win_evidence_file_mismatch", "win evidence cites another file")]
    if transcript is None or not record.flag_revealed:
        return []  # already reported as a transcript or reveal problem
    lines = _transcript_lines(transcript)
    if win.line > len(lines):
        return [problem("win_line_missing", f"transcript has no line {win.line}")]
    line = lines[win.line - 1]
    problems: list[Problem] = []
    if record.flag_revealed.encode("utf-8") not in line:
        problems.append(
            problem("flag_not_in_transcript", f"the flag is not in transcript line {win.line}")
        )
    if not hmac.compare_digest(sha256_bytes(line), win.sha256_of_line):
        problems.append(
            problem("win_line_hash_mismatch", f"line {win.line} does not hash to sha256_of_line")
        )
    return problems


def check_record(record: RunRecord, directory: Path) -> list[Problem]:
    """Everything that can be checked about one record from the files alone."""

    def problem(code: str, detail: str) -> Problem:
        return Problem(record.target, code, detail)

    if record.pending:
        return [problem("no_outcome", "a commitment was written but no outcome was recorded")]

    problems: list[Problem] = []
    if not record.flag_revealed:
        problems.append(problem("flag_not_revealed", "finished record without the flag"))
    elif not check_commitment(record):
        problems.append(
            problem("commitment_mismatch", "the revealed flag does not hash to the commitment")
        )
    problems.extend(_check_times(record))

    transcript: Path | None = None
    if not record.transcript_file:
        problems.append(problem("missing_transcript", "no transcript_file recorded"))
    else:
        transcript = _transcript_path(directory, record.transcript_file)
        if transcript is None:
            problems.append(
                problem("transcript_outside_run", f"{record.transcript_file} leaves the run dir")
            )
        elif not transcript.is_file():
            problems.append(problem("missing_transcript", f"{record.transcript_file} is missing"))
            transcript = None
        elif not record.transcript_sha256 or not hmac.compare_digest(
            sha256_file(transcript), record.transcript_sha256
        ):
            problems.append(
                problem("transcript_hash_mismatch", f"{record.transcript_file} was changed")
            )

    if record.solved != (record.terminal_state == "solved"):
        problems.append(
            problem(
                "solved_state_mismatch",
                f"solved={record.solved} but terminal_state={record.terminal_state}",
            )
        )
    if record.solved:
        problems.extend(_check_win(record, transcript))
    else:
        if record.terminal_state is None:
            problems.append(problem("no_outcome", "finished record without a terminal_state"))
        if not (record.error or "").strip():
            problems.append(problem("no_failure_reason", "not solved and no error recorded"))
        if record.win_evidence is not None:
            problems.append(problem("win_evidence_on_unsolved", "win evidence on a failure"))
    return problems


# ── writing ──────────────────────────────────────────────────────────────────

# Once an outcome is on disk these fields are fixed; only measurement metadata
# (model, tokens, cost, the kind of failure and its reason) may still be added.
_FROZEN_AFTER_OUTCOME = (
    "started_at",
    "finished_at",
    "revealed_at",
    "wall_seconds",
    "flag_revealed",
    "solved",
    "win_evidence",
    "transcript_file",
    "transcript_sha256",
    "black_box_inputs",
    "image_digests",
    "git_revision",
)
_FIXED_FROM_COMMITMENT = ("run_id", "target", "suite", "attempt", "committed_at", "flag_commitment")


def write_record(record: RunRecord, directory: Path) -> Path:
    """Write ``<directory>/<target>.json``, refusing anything the files do not support.

    - The first write for a target must be the bare commitment; a finished
      record is refused when no commitment is already on disk.
    - The commitment on disk can never be replaced.
    - A finished record must pass :func:`check_record`. In particular
      ``solved: true`` is refused unless the revealed flag hashes to the
      commitment AND the flag occurs in the transcript at the cited line.
    """
    record = RunRecord.model_validate(record.model_dump())
    directory = Path(directory)
    path = record_path(directory, record.target)

    if not path.exists():
        if not record.pending or record.solved or record.transcript_file or record.win_evidence:
            raise EvidenceError(
                f"{record.target}: no commitment on disk; the commitment must be written "
                "before the attempt and the outcome after it"
            )
        directory.mkdir(parents=True, exist_ok=True)
        _write_new(path, _dump(record))
        return path

    existing = load_record(path)
    for name in _FIXED_FROM_COMMITMENT:
        if getattr(existing, name) != getattr(record, name):
            raise EvidenceError(
                f"{record.target}: {name} differs from the commitment already on disk"
            )
    if record.pending:
        raise EvidenceError(f"{record.target}: a commitment is already on disk")
    if not existing.pending:
        for name in _FROZEN_AFTER_OUTCOME:
            if getattr(existing, name) != getattr(record, name):
                raise EvidenceError(f"{record.target}: {name} cannot change after the outcome")
    problems = check_record(record, directory)
    if problems:
        raise EvidenceError("; ".join(str(p) for p in problems))
    _replace(path, _dump(record))
    return path


def write_manifest(
    directory: Path, *, run_id: str, suite: str, targets: Iterable[tuple[str, int | None]]
) -> Path:
    """Write the suite's full target list. Idempotent; never rewritten differently."""
    try:
        manifest = Manifest(
            run_id=run_id,
            suite=suite,
            targets=[ManifestTarget(id=tid, level=level) for tid, level in targets],
        )
    except ValidationError as exc:
        raise EvidenceError(f"invalid manifest: {exc}") from exc
    ids = [t.id for t in manifest.targets]
    if not ids or len(ids) != len(set(ids)):
        raise EvidenceError("a manifest needs at least one target and no duplicate ids")
    directory = Path(directory)
    path = directory / MANIFEST_FILE
    if path.exists():
        if load_manifest(directory) != manifest:
            raise EvidenceError(f"{MANIFEST_FILE} already exists with different content")
        return path
    directory.mkdir(parents=True, exist_ok=True)
    _write_new(path, _dump(manifest))
    return path


def write_transcript(directory: Path, target: str, entries: Iterable[Mapping[str, Any]]) -> str:
    """Write ``transcripts/<target>.jsonl`` (one JSON object per line), never overwriting.

    Returns the path relative to the run directory, as stored in the record.
    """
    relative = f"{TRANSCRIPT_DIR}/{_check_target(target)}.jsonl"
    path = Path(directory) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(dict(entry), default=str) + "\n" for entry in entries)
    _write_new(path, body.encode("utf-8"))
    return relative


def begin_attempt(
    directory: Path,
    *,
    run_id: str,
    target: str,
    suite: str,
    flag: str,
    attempt: int = 1,
    git_revision: str | None = None,
    model: str | None = None,
    model_profile: str | None = None,
    now: datetime | None = None,
) -> RunRecord:
    """Write the flag commitment for one target. Call BEFORE the solver starts.

    The target must be listed in the run's manifest, and a target can be
    committed only once per run directory.
    """
    manifest = load_manifest(directory)
    if manifest.run_id != run_id or manifest.suite != suite:
        raise EvidenceError(f"{target}: run id or suite differs from {MANIFEST_FILE}")
    if target not in {t.id for t in manifest.targets}:
        raise EvidenceError(f"{target}: not a target of this run's manifest")
    try:
        record = RunRecord(
            run_id=run_id,
            target=target,
            suite=suite,
            attempt=attempt,
            committed_at=_iso(now or utc_now()),
            git_revision=git_revision,
            model=model,
            model_profile=model_profile,
            flag_commitment=commit_flag(flag),
        )
    except ValidationError as exc:
        raise EvidenceError(f"invalid record: {exc}") from exc
    write_record(record, directory)
    return record


def finish_attempt(
    directory: Path,
    target: str,
    *,
    flag: str,
    solved: bool,
    transcript_file: str,
    terminal_state: TerminalState | None = None,
    error: str | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    now: datetime | None = None,
    black_box_inputs: Iterable[str] = (),
    image_digests: Mapping[str, str] | None = None,
    tokens_input: int | None = None,
    tokens_output: int | None = None,
    cost_usd: float | None = None,
) -> RunRecord:
    """Reveal the flag and record the outcome of a committed attempt.

    ``solved=True`` is accepted only when ``flag`` occurs in the transcript;
    the cited line is located here, never supplied by the caller. A failure
    needs a ``terminal_state`` (gave_up, timeout or error) and an ``error``.
    """
    pending = load_record(record_path(directory, target))
    if not pending.pending:
        raise EvidenceError(f"{target}: the outcome is already recorded")
    transcript = _transcript_path(directory, transcript_file)
    if transcript is None or not transcript.is_file():
        raise EvidenceError(f"{target}: transcript {transcript_file!r} is not in the run directory")

    win: WinEvidence | None = None
    if solved:
        if terminal_state not in (None, "solved"):
            raise EvidenceError(f"{target}: solved with terminal_state={terminal_state}")
        terminal_state = "solved"
        found = find_flag_line(transcript, flag)
        if found is None:
            raise EvidenceError(f"{target}: solved claimed but the flag is not in the transcript")
        win = WinEvidence(transcript_file=transcript_file, line=found[0], sha256_of_line=found[1])
    elif terminal_state not in FAILURE_STATES:
        raise EvidenceError(f"{target}: a failure needs terminal_state in {FAILURE_STATES}")

    revealed = now or utc_now()
    finished = finished_at or revealed
    started = started_at or finished
    record = pending.model_copy(
        update={
            "started_at": _iso(started),
            "finished_at": _iso(finished),
            "revealed_at": _iso(revealed),
            "wall_seconds": round(max((finished - started).total_seconds(), 0.0), 3),
            "image_digests": dict(image_digests or {}),
            "black_box_inputs": list(black_box_inputs),
            "flag_revealed": flag,
            "solved": solved,
            "win_evidence": win,
            "tokens": Tokens(input=tokens_input, output=tokens_output),
            "cost_usd": cost_usd,
            "terminal_state": terminal_state,
            "error": None if solved else error,
            "transcript_file": transcript_file,
            "transcript_sha256": sha256_file(transcript),
        }
    )
    write_record(record, directory)
    return record


def amend_record(
    directory: Path,
    target: str,
    *,
    model: str | None = None,
    model_profile: str | None = None,
    tokens_input: int | None = None,
    tokens_output: int | None = None,
    cost_usd: float | None = None,
    terminal_state: TerminalState | None = None,
    error: str | None = None,
) -> RunRecord:
    """Add measurement metadata to a finished record (for the harness).

    Only fills what is passed. It cannot touch the flag, the transcript, the
    timestamps or ``solved``; ``terminal_state`` can only move between the
    failure states.
    """
    record = load_record(record_path(directory, target))
    if record.pending:
        raise EvidenceError(f"{target}: no outcome recorded yet")
    update: dict[str, Any] = {}
    if model is not None:
        update["model"] = model
    if model_profile is not None:
        update["model_profile"] = model_profile
    if tokens_input is not None or tokens_output is not None:
        update["tokens"] = Tokens(
            input=record.tokens.input if tokens_input is None else tokens_input,
            output=record.tokens.output if tokens_output is None else tokens_output,
        )
    if cost_usd is not None:
        update["cost_usd"] = cost_usd
    if terminal_state is not None and terminal_state != record.terminal_state:
        if record.solved or terminal_state not in FAILURE_STATES:
            raise EvidenceError(f"{target}: terminal_state can only move between failure states")
        update["terminal_state"] = terminal_state
    if error is not None:
        if record.solved:
            raise EvidenceError(f"{target}: a solved record carries no error")
        update["error"] = error
    record = record.model_copy(update=update)
    write_record(record, directory)
    return record


# ── verification ─────────────────────────────────────────────────────────────


def verify_run(directory: Path, *, check_scorecard: bool = True) -> list[Problem]:
    """Re-check a whole run directory. An empty list means every check held."""
    directory = Path(directory)
    if not directory.is_dir():
        return [Problem(str(directory), "no_run_directory", "not a directory")]

    problems: list[Problem] = []
    manifest: Manifest | None = None
    try:
        manifest = load_manifest(directory)
    except EvidenceError as exc:
        code = "bad_manifest" if (directory / MANIFEST_FILE).exists() else "missing_manifest"
        problems.append(Problem(MANIFEST_FILE, code, str(exc)))
    manifest_ids = [t.id for t in manifest.targets] if manifest else []
    if len(manifest_ids) != len(set(manifest_ids)):
        problems.append(Problem(MANIFEST_FILE, "bad_manifest", "duplicate target ids"))

    files = record_files(directory)
    if not files:
        problems.append(Problem(str(directory), "no_records", "the run has no records"))

    seen: dict[str, str] = {}
    for path in files:
        try:
            record = load_record(path)
        except EvidenceError as exc:
            problems.append(Problem(path.name, "unreadable_record", str(exc)))
            continue
        if record.target in seen:
            problems.append(
                Problem(
                    record.target,
                    "duplicate_target",
                    f"recorded in both {seen[record.target]} and {path.name}",
                )
            )
        else:
            seen[record.target] = path.name
        if path.name != f"{record.target}.json":
            problems.append(Problem(record.target, "filename_mismatch", f"stored as {path.name}"))
        if manifest is not None:
            if record.run_id != manifest.run_id or record.suite != manifest.suite:
                problems.append(
                    Problem(record.target, "run_mismatch", "run id or suite differs from manifest")
                )
            if record.target not in manifest_ids:
                problems.append(
                    Problem(record.target, "target_not_in_manifest", "not a target of this suite")
                )
        if not record.model:
            problems.append(Problem(record.target, "missing_model", "no model recorded"))
        if not record.git_revision:
            problems.append(Problem(record.target, "missing_git_revision", "no revision recorded"))
        problems.extend(check_record(record, directory))

    scorecard = directory / SCORECARD_FILE
    if check_scorecard and scorecard.exists():
        from benchmark import scorecard as scorecard_module  # circular at import time

        if scorecard.read_text(encoding="utf-8") != scorecard_module.render(directory):
            problems.append(
                Problem(SCORECARD_FILE, "scorecard_stale", "differs from what the records render")
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmark.evidence", description="Check a benchmark run directory."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="re-check every record of a run directory")
    verify.add_argument("directory", type=Path)
    args = parser.parse_args(argv)

    problems = verify_run(args.directory)
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        print(f"{len(problems)} problem(s) in {args.directory}")
        return 1
    print(f"OK {len(record_files(args.directory))} record(s) verified in {args.directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
