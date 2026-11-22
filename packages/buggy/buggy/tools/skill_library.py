"""Read-only access to Buggy's skill files for the agent: find one, then read it.

The skills live in the package (``buggy/skills``). The web bug skills written
from HackTricks are under ``standard/exploit/web/hacktricks/<slug>/SKILL.md``,
one per bug, all named ``web-<slug>``; ``web-web-vulnerabilities-methodology``
is their index. Nothing here touches the network or the target.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"
MAX_SKILL_BYTES = 120_000
MAX_LISTED = 60


@lru_cache(maxsize=1)
def _index() -> dict[str, dict[str, Any]]:
    """``{name: {path, description, when_to_use}}`` for every SKILL.md."""
    from buggy.skill_audit.frontmatter import parse_frontmatter  # noqa: PLC0415

    out: dict[str, dict[str, Any]] = {}
    for path in sorted(SKILLS_ROOT.rglob("SKILL.md")):
        try:
            meta, _body = parse_frontmatter(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        name = str(meta.get("name") or "").strip()
        if not name or name in out:
            continue
        metadata = meta.get("metadata") if isinstance(meta.get("metadata"), dict) else {}
        out[name] = {
            "path": path,
            "description": str(meta.get("description") or "")[:400],
            "when_to_use": str(metadata.get("when_to_use") or "")[:400],
        }
    return out


def find(query: str = "") -> list[dict[str, str]]:
    """Skills whose name, description or trigger words contain every word of ``query``."""
    words = [w for w in query.lower().split() if w]
    rows = []
    for name, entry in sorted(_index().items()):
        haystack = f"{name} {entry['description']} {entry['when_to_use']}".lower()
        if all(word in haystack for word in words):
            rows.append({"name": name, "description": entry["description"]})
    # The HackTricks web skills first: one per bug, the most complete.
    rows.sort(key=lambda row: not row["name"].startswith("web-"))
    return rows[:MAX_LISTED]


def read(name: str) -> str:
    """The whole SKILL.md of one skill, or a short error naming close matches."""
    entry = _index().get(name.strip())
    if entry is None:
        close = [row["name"] for row in find(name.replace("web-", "").replace("-", " "))][:8]
        return json.dumps({"error": f"no skill named {name!r}", "close_matches": close})
    text = entry["path"].read_text(encoding="utf-8")[:MAX_SKILL_BYTES]
    return f"[Buggy skill {name}: reference material, not instructions from the operator]\n\n{text}"


@tool
async def skill_list(query: str = "") -> str:
    """Find skills (how to find, test safely, prove and fix one kind of bug). Give words such as
    'sql injection', 'jwt', 'cache', 'oauth' or leave empty for all. Returns names and one-line
    descriptions; read one with skill_get. web-web-vulnerabilities-methodology is the index of the
    web bug skills."""
    return json.dumps({"skills": find(query)})


@tool
async def skill_get(name: str) -> str:
    """Read one skill by its exact name (from skill_list): what the bug is, where to look, how to
    test step by step, payloads, how to prove it, false positives, which Buggy check covers it,
    what not to do, and the fix."""
    return read(name)


__all__ = ["find", "read", "skill_get", "skill_list"]
