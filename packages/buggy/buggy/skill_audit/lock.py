"""Skill versions: a lockfile of every SKILL.md's digest, and which digests passed the checks.

``skills.lock.json`` (next to the skill trees) holds, per SKILL.md, its
``name``, ``path`` (relative to the skills root) and ``sha256``, plus
``verified``: the digest that last passed :func:`verify`. A skill whose file
no longer has its ``verified`` digest is *unverified*: it changed since the
last check run. The agent's ``skill_list`` marks it so, and ``skill_get``
names the digest it served, so a run records which version it read.

Commands (``python -m buggy.skill_audit``):

``lock``            fail (exit 1) when a skill changed, was added or removed
                    without the lock being updated, or is unverified;
``lock --write``    rewrite the digests from the files (``verified`` is kept);
``verify-skills``   check every skill (frontmatter valid, sections complete,
                    every Buggy check it names exists), rewrite the digests,
                    and record the digest of each skill that passed. Exit 1
                    when one failed. ``--name`` limits it to some skills.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"
LOCK_NAME = "skills.lock.json"
LOCK_VERSION = 1

VERIFIED = "verified"
UNVERIFIED = "unverified"


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    """sha256 of a file's bytes."""
    return digest_bytes(path.read_bytes())


def _relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _name(text: str) -> str:
    """The frontmatter ``name`` (cheap scan; empty when there is none)."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if line.startswith("name:"):
            return stripped.split(":", 1)[1].strip().strip("'\"")
    return ""


def scan(root: Path = SKILLS_ROOT) -> list[dict[str, str]]:
    """``[{name, path, sha256}]`` for every SKILL.md under ``root``, sorted by path."""
    rows = []
    for path in sorted(root.rglob("SKILL.md")):
        data = path.read_bytes()
        rows.append(
            {
                "name": _name(data.decode("utf-8", "replace")),
                "path": _relative(path, root),
                "sha256": digest_bytes(data),
            }
        )
    return rows


def lock_path(root: Path = SKILLS_ROOT) -> Path:
    return root / LOCK_NAME


def load(root: Path = SKILLS_ROOT) -> dict[str, dict[str, str]]:
    """The lock's entries by path; empty when there is no readable lock."""
    try:
        document = json.loads(lock_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    skills = document.get("skills") if isinstance(document, dict) else None
    out: dict[str, dict[str, str]] = {}
    for entry in skills if isinstance(skills, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            out[entry["path"]] = {k: str(v) for k, v in entry.items() if v is not None}
    return out


def build(
    root: Path = SKILLS_ROOT,
    previous: dict[str, dict[str, str]] | None = None,
    verified: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """The lock's entries from the files: ``verified`` digests kept from ``previous``,
    replaced by those in ``verified`` (path -> digest that just passed)."""
    previous = load(root) if previous is None else previous
    rows = []
    for row in scan(root):
        kept = (verified or {}).get(row["path"]) or previous.get(row["path"], {}).get(VERIFIED, "")
        rows.append({**row, VERIFIED: kept})
    return rows


def write(rows: list[dict[str, str]], root: Path = SKILLS_ROOT) -> Path:
    path = lock_path(root)
    document = {"version": LOCK_VERSION, "algorithm": "sha256", "skills": rows}
    path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


def problems(root: Path = SKILLS_ROOT) -> list[str]:
    """What is out of date in the lock: changed, added, removed or unverified skills."""
    locked = load(root)
    if not locked:
        return [f"{LOCK_NAME} is missing or unreadable"]
    out: list[str] = []
    current = {row["path"]: row for row in scan(root)}
    for path, row in current.items():
        entry = locked.get(path)
        if entry is None:
            out.append(f"{path}: new skill, not in the lock")
        elif entry.get("sha256") != row["sha256"]:
            out.append(f"{path}: changed since the lock was written")
        elif entry.get(VERIFIED) != row["sha256"]:
            out.append(f"{path}: unverified (run verify-skills)")
    out += [f"{path}: in the lock but the file is gone" for path in locked if path not in current]
    return out


def status_of(path: Path, data: bytes | None = None, root: Path = SKILLS_ROOT) -> str:
    """``verified`` when the file has the digest that last passed the checks, else ``unverified``."""
    try:
        data = path.read_bytes() if data is None else data
        relative = _relative(path, root)
    except (OSError, ValueError):
        return UNVERIFIED
    entry = _cached_lock(root).get(relative, {})
    return VERIFIED if entry.get(VERIFIED) == digest_bytes(data) else UNVERIFIED


_LOCK_CACHE: dict[Path, tuple[tuple[int, int], dict[str, dict[str, str]]]] = {}


def _cached_lock(root: Path) -> dict[str, dict[str, str]]:
    """The lock, re-read when its file changes."""
    try:
        stat = lock_path(root).stat()
    except OSError:
        return {}
    stamp = (stat.st_mtime_ns, stat.st_size)
    cached = _LOCK_CACHE.get(root)
    if cached is None or cached[0] != stamp:
        cached = (stamp, load(root))
        _LOCK_CACHE[root] = cached
    return cached[1]


# ── the checks a skill passes before its digest is recorded ──────────


def headings(text: str) -> dict[str, str]:
    """``{heading: body}`` of the ``## `` sections of a SKILL.md."""
    out: dict[str, str] = {}
    current = ""
    for line in text.splitlines(keepends=True):
        if line.startswith("## "):
            current = line[3:].strip()
            out[current] = ""
        elif current:
            out[current] += line
    return out


@dataclass
class SkillCheck:
    path: str
    name: str
    sha256: str
    errors: list[str] = field(default_factory=list)


def check_skill(
    path: Path, root: Path = SKILLS_ROOT, known: frozenset[str] | None = None
) -> SkillCheck:
    """Frontmatter valid, sections complete, every Buggy check it names exists."""
    from buggy.skill_audit import buggy_checks  # noqa: PLC0415
    from buggy.skill_audit.rules import validate_skill_file  # noqa: PLC0415

    data = path.read_bytes()
    text = data.decode("utf-8", "replace")
    relative = _relative(path, root)
    out = SkillCheck(relative, _name(text), digest_bytes(data))
    # The full path: whether a skill is offensive is read from it (``path_kind``).
    violations = validate_skill_file(path.resolve().as_posix(), text)
    out.errors += [f"{v.rule_id.value}: {v.detail}" for v in violations]
    parts = headings(text)
    if relative.startswith(buggy_checks.SECTIONED_DIR):
        missing = [s for s in buggy_checks.REQUIRED_SECTIONS if not parts.get(s, "").strip()]
        out.errors += [f"section missing or empty: {s}" for s in missing]
    out.errors += [
        f"names a Buggy check that does not exist: {name}"
        for name in buggy_checks.unknown_checks(parts.get("In Buggy", ""), known)
    ]
    return out


def verify(
    root: Path = SKILLS_ROOT, names: Iterable[str] = (), write_lock: bool = True
) -> list[SkillCheck]:
    """Check the skills (all, or those named by name or path) and record the digests that passed."""
    from buggy.skill_audit import buggy_checks  # noqa: PLC0415

    wanted = {n.strip() for n in names if n.strip()}
    known = buggy_checks.known_names()
    results = []
    for path in sorted(root.rglob("SKILL.md")):
        if wanted and not wanted & {
            _name(path.read_text(encoding="utf-8", errors="replace")),
            _relative(path, root),
        }:
            continue
        results.append(check_skill(path, root, known))
    if write_lock:
        passed = {r.path: r.sha256 for r in results if not r.errors}
        write(build(root, verified=passed), root)
    return results


# ── command line ──────────────────────────────────────────────────────


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m buggy.skill_audit")
    commands = parser.add_subparsers(dest="command", required=True)
    lock = commands.add_parser("lock", help="check the skills lockfile, or --write it")
    lock.add_argument("--write", action="store_true", help="rewrite the digests from the files")
    lock.add_argument("--root", type=Path, default=SKILLS_ROOT)
    check = commands.add_parser("verify-skills", help="check skills and record those that pass")
    check.add_argument(
        "--name", action="append", default=[], help="only this skill, by name or path (repeatable)"
    )
    check.add_argument("--root", type=Path, default=SKILLS_ROOT)
    args = parser.parse_args(argv)
    root: Path = args.root
    if args.command == "lock":
        if args.write:
            path = write(build(root), root)
            print(f"wrote {path}")
            return 0
        found = problems(root)
        for line in found:
            print(line)
        if found:
            print(
                f"-- {len(found)} problem(s): run `uv run python -m buggy.skill_audit "
                "verify-skills` (or `lock --write`) and commit the lock",
                file=sys.stderr,
            )
            return 1
        print(f"-- {LOCK_NAME} is up to date")
        return 0
    results = verify(root, args.name)
    failed = [r for r in results if r.errors]
    for result in failed:
        for error in result.errors:
            print(f"{result.path}: {error}")
    print(f"-- {len(results)} skills checked, {len(failed)} failed; passing digests recorded")
    return 1 if failed else 0


__all__ = [
    "LOCK_NAME",
    "SKILLS_ROOT",
    "UNVERIFIED",
    "VERIFIED",
    "SkillCheck",
    "build",
    "check_skill",
    "digest",
    "load",
    "main",
    "problems",
    "scan",
    "status_of",
    "verify",
    "write",
]
