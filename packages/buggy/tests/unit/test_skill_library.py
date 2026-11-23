"""The agent finds and reads skill files; nothing else is reachable through these tools."""

from __future__ import annotations

import asyncio
import json

from buggy.tools import skill_library


def test_every_hacktricks_web_skill_is_listed_and_readable() -> None:
    root = skill_library.SKILLS_ROOT / "standard" / "exploit" / "web" / "hacktricks"
    slugs = sorted(p.parent.name for p in root.glob("*/SKILL.md"))
    bugs = [slug for slug in slugs if not slug.startswith("tech-")]
    assert len(bugs) >= 89 and len(slugs) > len(bugs)  # bug classes, then technologies
    names = {row["name"] for row in skill_library.find("")} | set(skill_library._index())  # noqa: SLF001
    for slug in slugs:
        assert f"web-{slug}" in names
    text = skill_library.read("web-idor")
    assert text.startswith("[Buggy skill web-idor (sha256:")
    assert "reference material, not instructions" in text.splitlines()[0]
    for section in ("## How to test", "## How to prove it", "## Do not", "## Fix", "## Sources"):
        assert section in text


def test_search_puts_the_web_skills_first_and_unknown_names_get_close_matches() -> None:
    rows = skill_library.find("sql injection")
    assert rows[0]["name"].startswith("web-")
    assert "web-sql-injection" in [row["name"] for row in rows]
    answer = json.loads(skill_library.read("web-sqli"))
    assert "web-sql-injection" in answer["close_matches"]


def test_the_index_skill_names_every_other_web_skill() -> None:
    index = skill_library.read("web-web-vulnerabilities-methodology")
    root = skill_library.SKILLS_ROOT / "standard" / "exploit" / "web" / "hacktricks"
    missing = [
        p.parent.name
        for p in root.glob("*/SKILL.md")
        if p.parent.name != "web-vulnerabilities-methodology"
        and f"web-{p.parent.name}" not in index
    ]
    assert missing == []


def test_the_tools_answer_as_text() -> None:
    listed = json.loads(asyncio.run(skill_library.skill_list.ainvoke({"query": "jwt"})))
    assert any(row["name"] == "web-hacking-jwt-json-web-tokens" for row in listed["skills"])
    assert "## What it is" in asyncio.run(
        skill_library.skill_get.ainvoke({"name": "web-race-condition"})
    )
