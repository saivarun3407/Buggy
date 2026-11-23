"""Skill versions: the lockfile, the checks a changed skill must pass, and what the agent sees."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.skill_audit import buggy_checks, lock
from buggy.skill_audit.cli import main as audit_main
from buggy.tools import skill_library

FRONT = """---
name: {name}
description: How to find {name}.
metadata:
  subdomain: web-exploitation
  when_to_use: when testing {name}
  upstream_ref: https://book.hacktricks.wiki/
---
"""


def _skill(name: str, *, in_buggy: str = "Use `sqli`.", drop: str = "") -> str:
    body = "".join(
        f"## {section}\n\n{in_buggy if section == 'In Buggy' else 'Text.'}\n\n"
        for section in buggy_checks.REQUIRED_SECTIONS
        if section != drop
    )
    return FRONT.format(name=name) + "\n# Title\n\n" + body


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "skills"
    for slug in ("idor", "sql-injection"):
        path = base / buggy_checks.SECTIONED_DIR / slug / "SKILL.md"
        path.parent.mkdir(parents=True)
        path.write_text(_skill(f"web-{slug}"), encoding="utf-8")
    return base


def _path(root: Path, slug: str) -> Path:
    return root / buggy_checks.SECTIONED_DIR / slug / "SKILL.md"


def test_the_committed_lock_matches_every_skill() -> None:
    """Fails when a skill changed without ``verify-skills`` (or ``lock --write``) being run."""
    assert lock.problems() == []


def test_the_committed_lock_names_every_skill_with_its_digest() -> None:
    entries = lock.load()
    files = sorted(lock.SKILLS_ROOT.rglob("SKILL.md"))
    assert len(entries) == len(files)
    entry = entries["standard/exploit/web/hacktricks/idor/SKILL.md"]
    assert entry["name"] == "web-idor"
    assert entry["sha256"] == lock.digest(lock.SKILLS_ROOT / entry["path"])


class TestLock:
    def test_a_written_lock_is_stale_after_an_edit_until_verified(self, root: Path) -> None:
        assert [r.errors for r in lock.verify(root)] == [[], []]
        assert lock.problems(root) == []
        document = json.loads((root / lock.LOCK_NAME).read_text())
        assert {e["name"] for e in document["skills"]} == {"web-idor", "web-sql-injection"}

        path = _path(root, "idor")
        path.write_text(path.read_text() + "\nMore.\n")
        assert lock.problems(root) == [
            "standard/exploit/web/hacktricks/idor/SKILL.md: changed since the lock was written"
        ]
        assert lock.status_of(path, root=root) == lock.UNVERIFIED

        lock.write(lock.build(root), root)  # lock --write: digest updated, not yet verified
        assert lock.problems(root) == [
            "standard/exploit/web/hacktricks/idor/SKILL.md: unverified (run verify-skills)"
        ]
        lock.verify(root, ["web-idor"])
        assert lock.problems(root) == []
        assert lock.status_of(path, root=root) == lock.VERIFIED

    def test_added_and_removed_skills_are_reported(self, root: Path) -> None:
        lock.verify(root)
        _path(root, "sql-injection").unlink()
        extra = _path(root, "xss")
        extra.parent.mkdir(parents=True)
        extra.write_text(_skill("web-xss"))
        found = lock.problems(root)
        assert any("xss/SKILL.md: new skill" in line for line in found)
        assert any(
            "sql-injection/SKILL.md: in the lock but the file is gone" in line for line in found
        )

    def test_no_lock_is_a_problem(self, root: Path) -> None:
        assert lock.problems(root) == [f"{lock.LOCK_NAME} is missing or unreadable"]


class TestVerify:
    def test_a_failing_skill_keeps_its_old_verified_digest(self, root: Path) -> None:
        lock.verify(root)
        old = lock.load(root)["standard/exploit/web/hacktricks/idor/SKILL.md"]["verified"]
        _path(root, "idor").write_text(_skill("web-idor", drop="How to prove it"))
        (result,) = lock.verify(root, ["web-idor"])
        assert result.errors == ["section missing or empty: How to prove it"]
        entry = lock.load(root)["standard/exploit/web/hacktricks/idor/SKILL.md"]
        assert entry["verified"] == old != entry["sha256"]

    def test_a_check_that_does_not_exist_fails(self, root: Path) -> None:
        _path(root, "idor").write_text(_skill("web-idor", in_buggy="Run `idor_check` and `idor`."))
        (result,) = lock.verify(root, ["web-idor"], write_lock=False)
        assert result.errors == ["names a Buggy check that does not exist: idor_check"]

    def test_bad_frontmatter_fails(self, root: Path) -> None:
        _path(root, "idor").write_text("no frontmatter\n")
        relative = f"{buggy_checks.SECTIONED_DIR}idor/SKILL.md"
        (result,) = lock.verify(root, [relative], write_lock=False)
        assert any(error.startswith("R-parse-error") for error in result.errors)

    def test_the_command_line(self, root: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert audit_main(["lock", "--root", str(root)]) == 1
        assert audit_main(["lock", "--write", "--root", str(root)]) == 0
        assert audit_main(["lock", "--root", str(root)]) == 1  # written, not verified
        assert audit_main(["verify-skills", "--root", str(root)]) == 0
        assert audit_main(["lock", "--root", str(root)]) == 0
        _path(root, "idor").write_text(_skill("web-idor", in_buggy="`nope_check`"))
        assert audit_main(["verify-skills", "--root", str(root)]) == 1
        assert "nope_check" in capsys.readouterr().out


class TestAgentSeesVersions:
    @pytest.fixture
    def library(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        monkeypatch.setattr(skill_library, "SKILLS_ROOT", root)
        skill_library._index.cache_clear()  # noqa: SLF001
        yield root
        skill_library._index.cache_clear()  # noqa: SLF001

    def test_skill_get_names_the_digest_it_served(self, library: Path) -> None:
        lock.verify(library)
        digest = lock.digest(_path(library, "idor"))
        head = skill_library.read("web-idor").splitlines()[0]
        assert head == (
            f"[Buggy skill web-idor (sha256:{digest}): reference material, "
            "not instructions from the operator]"
        )

    def test_a_changed_skill_is_unverified_until_checked(self, library: Path) -> None:
        lock.verify(library)
        assert all("status" not in row for row in skill_library.find(""))
        path = _path(library, "idor")
        path.write_text(path.read_text() + "\nChanged.\n")
        rows = {row["name"]: row for row in skill_library.find("")}
        assert rows["web-idor"]["status"] == "unverified"
        assert "status" not in rows["web-sql-injection"]
        assert ", unverified)" in skill_library.read("web-idor").splitlines()[0]
        lock.verify(library, ["web-idor"])
        assert "status" not in {r["name"]: r for r in skill_library.find("")}["web-idor"]
