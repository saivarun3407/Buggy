"""Run one scanner as a subprocess and keep its raw output.

No shell is involved: ``argv`` is a list built by the tool wrapper, and the
targets arrive in a file the pipeline wrote after scope filtering. Standard
output is streamed to a file under the raw-output root; that file's path and
SHA-256 are what a record's ``raw_ref`` points back to.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RunResult:
    argv: tuple[str, ...]
    exit_code: int | None
    raw_path: Path
    sha256: str
    size: int
    started_at: float
    finished_at: float
    timed_out: bool
    stderr_tail: str

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.exit_code == 0


def _minimal_env() -> dict[str, str]:
    """Environment for a scanner: PATH/HOME and proxy settings, nothing else."""
    keep = (
        "PATH",
        "HOME",
        "LANG",
        "TMPDIR",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    )
    return {name: os.environ[name] for name in keep if name in os.environ}


def run_tool(
    argv: list[str],
    *,
    raw_path: Path,
    timeout: float,
    stdin_text: str | None = None,
    cwd: Path | None = None,
) -> RunResult:
    """Execute ``argv``; stdout goes to ``raw_path``. Never raises on tool failure."""
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    timed_out = False
    exit_code: int | None = None
    stderr_tail = ""
    with raw_path.open("wb") as out:
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, no shell, scope-filtered inputs
                argv,
                stdout=out,
                stderr=subprocess.PIPE,
                input=stdin_text.encode() if stdin_text is not None else None,
                stdin=None if stdin_text is not None else subprocess.DEVNULL,
                timeout=timeout,
                cwd=cwd,
                env=_minimal_env(),
                check=False,
            )
            exit_code = proc.returncode
            stderr_tail = proc.stderr.decode("utf-8", "replace")[-2000:]
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stderr_tail = (exc.stderr or b"").decode("utf-8", "replace")[-2000:]
        except OSError as exc:
            exit_code = 127
            stderr_tail = str(exc)
    digest = hashlib.sha256()
    size = 0
    with raw_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return RunResult(
        argv=tuple(argv),
        exit_code=exit_code,
        raw_path=raw_path,
        sha256=digest.hexdigest(),
        size=size,
        started_at=started,
        finished_at=time.time(),
        timed_out=timed_out,
        stderr_tail=stderr_tail,
    )


__all__ = ["RunResult", "run_tool"]
