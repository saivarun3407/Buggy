"""The placeholder .env shared by parallel test workers."""

from __future__ import annotations

from pathlib import Path

from conftest import placeholder_dotenv


def test_created_for_the_first_user_and_removed_by_the_last(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    with placeholder_dotenv(env_file):
        assert env_file.read_text() == ""
        with placeholder_dotenv(env_file):
            assert env_file.exists()
        # One user is still inside: the file must stay.
        assert env_file.exists()
    assert not env_file.exists()


def test_an_existing_file_is_never_touched_or_removed(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SANDBOX_TOKEN=mine\n")
    with placeholder_dotenv(env_file):
        assert env_file.read_text() == "SANDBOX_TOKEN=mine\n"
    assert env_file.read_text() == "SANDBOX_TOKEN=mine\n"


def test_a_user_that_failed_still_releases_the_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    try:
        with placeholder_dotenv(env_file):
            raise RuntimeError("the test failed")
    except RuntimeError:
        pass
    assert not env_file.exists()
