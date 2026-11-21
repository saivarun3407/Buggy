"""Fixtures shared by the repository-level tests."""

from __future__ import annotations

import contextlib
import hashlib
import json
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

try:  # POSIX only; elsewhere the tests run in one process at a time anyway.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

REPO_ROOT = Path(__file__).resolve().parents[1]


def _state_path(env_file: Path) -> Path:
    digest = hashlib.sha256(str(env_file).encode()).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"buggy-tests-dotenv-{digest}.json"


@contextlib.contextmanager
def _locked(state: Path) -> Iterator[dict]:
    """The shared user count of the placeholder ``.env``, read and written under a lock."""
    with state.open("a+", encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        try:
            data = json.loads(handle.read() or "{}")
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        yield data
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps(data))
        handle.flush()


@contextlib.contextmanager
def placeholder_dotenv(env_file: Path) -> Iterator[None]:
    """Keep an (empty) ``.env`` in place for as long as any test process uses it.

    ``docker compose config`` needs the file for the services' ``env_file``
    entries. Test workers run in parallel: a worker that removed the file the
    moment its own test ended would break a render running in another worker,
    so users are counted and the file is removed by the last one, and only if
    the tests created it.
    """
    state = _state_path(env_file)
    with _locked(state) as data:
        users = int(data.get("users") or 0)
        if users == 0:
            data["created"] = not env_file.exists()
        if not env_file.exists():
            env_file.write_text("", encoding="utf-8")
        data["users"] = users + 1
    try:
        yield
    finally:
        with _locked(state) as data:
            data["users"] = max(0, int(data.get("users") or 0) - 1)
            if data["users"] == 0 and data.get("created"):
                env_file.unlink(missing_ok=True)
                data["created"] = False


@pytest.fixture
def repo_dotenv() -> Iterator[Path]:
    """The repository's ``.env``, present for the duration of the test."""
    env_file = REPO_ROOT / ".env"
    with placeholder_dotenv(env_file):
        yield env_file
