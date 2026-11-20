from __future__ import annotations

import json
import logging
import os
import re
import secrets
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import httpx

from benchmark import evidence
from benchmark.providers.base import BaseBenchmarkProvider
from benchmark.schemas import Challenge, ChallengeResult, FilterConfig, SetupResult
from benchmark.state import BenchmarkRunState

log = logging.getLogger(__name__)


@dataclass
class _Attempt:
    """An attempt whose flag commitment is on disk and whose record is not closed yet."""

    flag: str
    started_at: datetime | None = None
    black_box_inputs: list[str] = field(default_factory=list)
    image_digests: dict[str, str] = field(default_factory=dict)
    # Set by evaluate(); the harness keeps filling it until teardown().
    result: ChallengeResult | None = None


class XBOWProvider(BaseBenchmarkProvider):
    """Benchmark provider for XBOW validation benchmarks.

    Loads challenges from local benchmark directories, manages Docker-based
    challenge environments, and evaluates flag capture results.

    Evidence (``benchmark/evidence.py``): ``setup`` writes the sha256
    commitment of the fresh flag to ``<evidence_dir>/<target>.json`` before
    anything is built or solved; ``evaluate`` writes the outcome, the revealed
    flag and the transcript after. ``evidence_dir`` is the run directory
    (default ``benchmark/results/<run_id>``). ``BENCHMARK_RUN_ID``,
    ``BENCHMARK_EVIDENCE_DIR``, ``BENCHMARK_MODEL`` and
    ``BENCHMARK_MODEL_PROFILE`` supply what the constructor is not given.
    """

    def __init__(
        self,
        benchmarks_dir: Path | None = None,
        *,
        evidence_dir: Path | None = None,
        run_id: str | None = None,
        model: str | None = None,
        model_profile: str | None = None,
    ) -> None:
        self._benchmarks_dir = benchmarks_dir or Path(
            "benchmark/xbow-validation-benchmarks/benchmarks"
        )
        self._expected_flags: dict[str, str] = {}
        self._run_id = run_id or os.environ.get("BENCHMARK_RUN_ID") or evidence.new_run_id("xbow")
        self._evidence_dir = Path(
            evidence_dir
            or os.environ.get("BENCHMARK_EVIDENCE_DIR")
            or Path("benchmark/results") / self._run_id
        )
        # Stated by the operator, never guessed: a record without a model fails verify.
        self._model = model or os.environ.get("BENCHMARK_MODEL") or None
        self._model_profile = model_profile or os.environ.get("BENCHMARK_MODEL_PROFILE") or None
        self._git_revision: str | None = None
        # Every target of the suite before filtering: the scorecard's denominator.
        self._suite_targets: list[tuple[str, int | None]] = []
        self._attempts: dict[str, _Attempt] = {}

    @property
    def name(self) -> str:
        return "xbow"

    def load_challenges(self, filters: FilterConfig) -> list[Challenge]:
        """Load and filter challenges from benchmark subdirectories."""
        challenges: list[Challenge] = []

        if not self._benchmarks_dir.is_dir():
            return challenges

        for subdir in sorted(self._benchmarks_dir.iterdir()):
            if not subdir.is_dir():
                continue
            benchmark_file = subdir / "benchmark.json"
            if not benchmark_file.exists():
                continue

            data = json.loads(benchmark_file.read_text())
            challenges.append(
                Challenge(
                    id=subdir.name,
                    name=data["name"],
                    description=data["description"],
                    level=int(data["level"]),
                    tags=data["tags"],
                    win_condition=data.get("win_condition", "flag"),
                    compose_dir=subdir,
                )
            )

        self._suite_targets = [(c.id, c.level) for c in challenges]

        if filters.levels:
            challenges = [c for c in challenges if c.level in filters.levels]

        if filters.tags:
            filter_tags = set(filters.tags)
            challenges = [c for c in challenges if set(c.tags) & filter_tags]

        if filters.ids:
            wanted = set(filters.ids)
            challenges = [c for c in challenges if c.id in wanted]

        # range is 1-based from the user; convert start to 0-based
        start = (filters.range_start - 1) if filters.range_start is not None else None
        end = filters.range_end if filters.range_end is not None else None
        if start is not None or end is not None:
            challenges = challenges[start:end]

        return challenges

    def preflight_build(self, challenges: list[Challenge]) -> dict[str, str]:
        """Pre-build all challenge images via make build. Returns {id: error} for failures."""
        failures: dict[str, str] = {}
        for challenge in challenges:
            result = subprocess.run(
                ["make", "build"],
                cwd=challenge.compose_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                # Retry with NO_CACHE=1
                retry = subprocess.run(
                    ["make", "build", "NO_CACHE=1"],
                    cwd=challenge.compose_dir,
                    capture_output=True,
                    text=True,
                )
                if retry.returncode != 0:
                    failures[challenge.id] = (
                        retry.stderr[-500:] if retry.stderr else "Unknown build error"
                    )
        return failures

    def setup(self, challenge: Challenge) -> SetupResult:
        """Build and start the challenge Docker environment via make.

        The flag commitment is on disk before the build starts. A setup that
        fails after that closes the record as an error instead of leaving it open.
        """
        self._close_evidence(challenge, reason="attempt abandoned: setup was called again")
        result = self._setup(challenge)
        attempt = self._attempts.get(challenge.id)
        if attempt is not None and result.success:
            attempt.started_at = evidence.utc_now()
            # What Harness._invoke_agent hands the solver for this challenge.
            attempt.black_box_inputs = [
                f"challenge_id={challenge.id}",
                f"name={challenge.name}",
                f"description={challenge.description}",
                f"tags={','.join(challenge.tags)}",
                f"flag_format={challenge.flag_format}",
                f"target_url={result.target_url}",
                f"extra_ports={json.dumps(result.extra_ports, sort_keys=True)}",
            ]
            attempt.image_digests = self._image_digests(challenge.compose_dir)
        elif attempt is not None:
            self._close_evidence(challenge, reason=f"setup failed: {result.error}")
        return result

    def _begin_evidence(self, challenge: Challenge, flag: str) -> str | None:
        """Write the manifest and the flag commitment. Returns the error if it could not."""
        try:
            if not self._suite_targets:
                self.load_challenges(FilterConfig())
            if self._git_revision is None:
                self._git_revision = evidence.git_revision()
            evidence.write_manifest(
                self._evidence_dir,
                run_id=self._run_id,
                suite=self.name,
                targets=self._suite_targets,
            )
            evidence.begin_attempt(
                self._evidence_dir,
                run_id=self._run_id,
                target=challenge.id,
                suite=self.name,
                flag=flag,
                git_revision=self._git_revision,
                model=self._model,
                model_profile=self._model_profile,
            )
        except (evidence.EvidenceError, OSError) as exc:
            return f"evidence commitment not written, attempt refused: {exc}"
        self._attempts[challenge.id] = _Attempt(flag=flag)
        return None

    def _setup(self, challenge: Challenge) -> SetupResult:
        if challenge.compose_dir is None:
            return SetupResult(target_url="", success=False, error="challenge has no compose_dir")
        try:
            flag = f"FLAG{{{secrets.token_hex(32)}}}"
            self._expected_flags[challenge.id] = flag
            # Commit to the flag before anything is built: no commitment, no attempt.
            commit_error = self._begin_evidence(challenge, flag)
            if commit_error:
                return SetupResult(target_url="", success=False, error=commit_error)
            build_env = {**os.environ, "FLAG": flag}
            # The upstream guard otherwise reuses an image containing a prior
            # run's flag, invalidating both isolation and scoring.
            (challenge.compose_dir / ".xben_build_done").unlink(missing_ok=True)
            result = subprocess.run(
                ["make", "build"],
                cwd=challenge.compose_dir,
                capture_output=True,
                text=True,
                env=build_env,
            )
            if result.returncode != 0:
                # Retry with NO_CACHE=1 on failure
                subprocess.run(
                    ["make", "build", "NO_CACHE=1"],
                    cwd=challenge.compose_dir,
                    capture_output=True,
                    text=True,
                    check=True,
                    env=build_env,
                )

            subprocess.run(
                ["make", "run"],
                cwd=challenge.compose_dir,
                capture_output=True,
                text=True,
                check=True,
                env=build_env,
            )

            result = subprocess.run(
                ["docker", "compose", "ps", "--format", "json"],
                cwd=challenge.compose_dir,
                capture_output=True,
                text=True,
                check=True,
            )

            http_port = ""
            extra_ports: dict[int, int] = {}  # target_port -> published_port
            for line in result.stdout.strip().splitlines():
                container = json.loads(line)
                publishers = container.get("Publishers", [])
                for pub in publishers:
                    published = pub.get("PublishedPort", 0)
                    target = pub.get("TargetPort", 0)
                    if published:
                        if target == 80:
                            http_port = str(published)
                        else:
                            extra_ports[target] = published

            # Prefer HTTP port 80; fall back to first available port
            if not http_port:
                if extra_ports:
                    http_port = str(next(iter(extra_ports.values())))
                else:
                    http_port = "80"

            target_url = f"http://host.docker.internal:{http_port}"

            # TCP pre-flight: verify all required ports are accepting connections.
            # Ports that never open indicate a failed container start — abort early
            # rather than dispatching the agent into a dead target (saves ~20 min).
            all_ports = [int(http_port)] + list(extra_ports.values())
            for port in all_ports:
                if not self._wait_for_tcp("localhost", port, timeout=30):
                    return SetupResult(
                        target_url="",
                        success=False,
                        error=f"TCP pre-flight failed: port {port} not accepting connections after 30s",
                    )

            # HTTP readiness check on the primary port
            for attempt in range(15):
                try:
                    r = httpx.get(
                        f"http://localhost:{http_port}/",
                        timeout=3,
                        follow_redirects=True,
                    )
                    log.info(
                        "Challenge %s ready (HTTP %d) after %ds",
                        challenge.id,
                        r.status_code,
                        attempt * 2,
                    )
                    break
                except Exception:
                    time.sleep(2)
            else:
                log.warning(
                    "Challenge %s: HTTP health check timed out after 30s, proceeding anyway",
                    challenge.id,
                )

            return SetupResult(
                target_url=target_url,
                success=True,
                extra_ports=extra_ports,
            )

        except subprocess.CalledProcessError as e:
            error_detail = str(e)
            if e.stderr:
                error_detail += f"\nSTDERR: {e.stderr[-500:]}"
            return SetupResult(target_url="", success=False, error=error_detail)

    def evaluate(
        self,
        challenge: Challenge,
        state: BenchmarkRunState,
        workspace: Path,
    ) -> ChallengeResult:
        """Evaluate whether the expected flag was captured, then write the evidence record."""
        result = self._evaluate_flag(challenge, state)
        self._emit_record(challenge, state, result)
        return result

    def _finish(
        self,
        challenge: Challenge,
        attempt: _Attempt,
        transcript: str,
        *,
        solved: bool,
        terminal_state: evidence.TerminalState | None = None,
        error: str | None = None,
        finished_at: datetime | None = None,
    ) -> None:
        evidence.finish_attempt(
            self._evidence_dir,
            challenge.id,
            flag=attempt.flag,
            solved=solved,
            transcript_file=transcript,
            terminal_state=terminal_state,
            error=error,
            started_at=attempt.started_at,
            finished_at=finished_at,
            black_box_inputs=attempt.black_box_inputs,
            image_digests=attempt.image_digests,
        )

    def _emit_record(
        self, challenge: Challenge, state: BenchmarkRunState, result: ChallengeResult
    ) -> None:
        """Reveal the flag and record the outcome of a committed attempt."""
        attempt = self._attempts.get(challenge.id)
        if attempt is None or attempt.result is not None:
            return  # no commitment was written for this attempt, or it is already recorded
        finished = evidence.utc_now()
        try:
            # The transcript is exactly the solver output the decision above was made on.
            transcript = evidence.write_transcript(
                self._evidence_dir, challenge.id, (s.model_dump() for s in state.step_history)
            )
            if result.passed:
                try:
                    self._finish(challenge, attempt, transcript, solved=True, finished_at=finished)
                except evidence.EvidenceError as exc:
                    self._finish(
                        challenge,
                        attempt,
                        transcript,
                        solved=False,
                        terminal_state="error",
                        error=f"win not supported by the transcript: {exc}",
                        finished_at=finished,
                    )
            else:
                self._finish(
                    challenge,
                    attempt,
                    transcript,
                    solved=False,
                    terminal_state="gave_up",
                    error=result.error
                    or (
                        "captured flag does not match the committed flag"
                        if result.flag_captured
                        else "no flag in solver output"
                    ),
                    finished_at=finished,
                )
        except (evidence.EvidenceError, OSError) as exc:
            log.error("evidence record for %s not written: %s", challenge.id, exc)
            return
        attempt.result = result

    def _close_evidence(self, challenge: Challenge, reason: str | None = None) -> None:
        """Close the record when an attempt ends (failed setup, or teardown).

        An attempt that never reached ``evaluate`` is recorded as an error. A
        failed one picks up what the harness put on the result after
        ``evaluate`` returned: its timeout marker and the measured cost.
        """
        attempt = self._attempts.pop(challenge.id, None)
        if attempt is None:
            return
        result = attempt.result
        try:
            if result is None:
                reason = reason or "attempt ended before evaluation (harness error)"
                transcript = evidence.write_transcript(
                    self._evidence_dir,
                    challenge.id,
                    [{"event": "no_solver_output", "error": reason}],
                )
                self._finish(
                    challenge,
                    attempt,
                    transcript,
                    solved=False,
                    terminal_state="error",
                    error=reason,
                )
                return
            timed_out = not result.passed and (result.error or "").lower().startswith("timeout")
            if timed_out or result.cost_usd is not None:
                evidence.amend_record(
                    self._evidence_dir,
                    challenge.id,
                    cost_usd=result.cost_usd,
                    terminal_state="timeout" if timed_out else None,
                    error=result.error if timed_out else None,
                )
        except (evidence.EvidenceError, OSError) as exc:
            log.error("evidence record for %s not closed: %s", challenge.id, exc)

    def _image_digests(self, compose_dir: Path | None) -> dict[str, str]:
        """Image id per container of the running challenge (best-effort, may be empty)."""
        try:
            out = subprocess.run(
                ["docker", "compose", "images", "--format", "json"],
                cwd=compose_dir,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            rows = json.loads(out) if out.startswith("[") else map(json.loads, out.splitlines())
            return {
                str(row["ContainerName"]): str(row["ID"])
                for row in rows
                if row.get("ContainerName") and row.get("ID")
            }
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
            return {}

    def _evaluate_flag(self, challenge: Challenge, state: BenchmarkRunState) -> ChallengeResult:
        expected_flag = self._expected_flags.get(challenge.id)
        if expected_flag is None:
            return ChallengeResult(
                challenge_id=challenge.id,
                challenge_name=challenge.name,
                level=challenge.level,
                tags=challenge.tags,
                passed=False,
                error="missing per-run expected flag; challenge setup did not complete",
            )

        combined_output = "".join(step.raw_output for step in state.step_history)
        match = re.search(r"FLAG\{[a-f0-9]+\}", combined_output)

        if match:
            captured = match.group(0)
            passed = captured == expected_flag
            return ChallengeResult(
                challenge_id=challenge.id,
                challenge_name=challenge.name,
                level=challenge.level,
                tags=challenge.tags,
                passed=passed,
                flag_captured=captured,
            )

        return ChallengeResult(
            challenge_id=challenge.id,
            challenge_name=challenge.name,
            level=challenge.level,
            tags=challenge.tags,
            passed=False,
        )

    def _wait_for_tcp(self, host: str, port: int, timeout: int = 30) -> bool:
        """Return True if TCP port accepts a connection within timeout seconds."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=2):
                    return True
            except OSError:
                time.sleep(2)
        return False

    def teardown(self, challenge: Challenge) -> None:
        """Stop and remove challenge containers (best-effort)."""
        self._close_evidence(challenge)
        compose_dir = challenge.compose_dir
        if compose_dir is None:
            # Defensive: XBOW.load_challenges always populates compose_dir.
            # This guard exists because the schema field is Optional to
            # accommodate other providers (e.g. MHBench).
            return
        try:
            # Use docker compose down -v for thorough cleanup (removes volumes)
            subprocess.run(
                ["docker", "compose", "down", "-v"],
                cwd=compose_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            # Remove build guard so next run rebuilds with fresh flag
            guard = compose_dir / ".xben_build_done"
            guard.unlink(missing_ok=True)
        except subprocess.CalledProcessError:
            pass
