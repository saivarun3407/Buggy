"""Leads and technologies point at skills that exist, and skills name checks that exist."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from buggy import agent_bridge
from buggy.findings import skill_map
from buggy.skill_audit import buggy_checks
from buggy.tools import skill_library

ROOT = skill_library.SKILLS_ROOT / "standard" / "exploit" / "web" / "hacktricks"
SKILL_NAMES = {f"web-{p.parent.name}" for p in ROOT.glob("*/SKILL.md")}


def test_every_skill_the_map_hands_out_exists() -> None:
    assert skill_map.all_names() - SKILL_NAMES == set()


def test_every_check_a_skill_names_exists() -> None:
    unknown: list[str] = []
    for path in sorted(ROOT.glob("*/SKILL.md")):
        part = skill_library.sections(path.read_text(encoding="utf-8")).get("In Buggy", "")
        unknown += [f"{path.parent.name}: {name}" for name in buggy_checks.unknown_checks(part)]
    assert unknown == []


def test_a_misspelled_check_would_be_caught() -> None:
    known = buggy_checks.known_names()
    for typo in ("sql_injection", "xss_dom", "recipe_verify"):
        assert buggy_checks.BUGGY_SHAPE.match(typo) and typo not in known
    assert buggy_checks.unknown_checks("Run `sqli` then `sql_injection`.") == ["sql_injection"]


class TestLeads:
    def test_a_probe_lead_gets_its_probe_skill_first(self) -> None:
        lead = {"source": "probe:sqli", "vuln_class": "injection", "endpoint": "https://a/search"}
        assert skill_map.for_lead(lead)[0] == "web-sql-injection"

    def test_words_and_paths_add_specific_skills(self) -> None:
        lead = {
            "vuln_class": "auth_session",
            "endpoint": "https://a/wp-login.php",
            "description": "password reset page",
        }
        skills = skill_map.for_lead(lead)
        assert "web-reset-password" in skills and "web-tech-wordpress" in skills
        assert len(skills) <= skill_map.MAX_SKILLS

    def test_a_lead_with_nothing_known_gets_the_index(self) -> None:
        assert skill_map.for_lead({}) == [skill_map.INDEX]

    def test_technologies_map_to_their_skills(self) -> None:
        found = skill_map.for_technologies(
            ["Nginx:1.25.3", "WordPress:6.4", "jQuery", "Apache Tomcat"]
        )
        assert found == ["web-tech-nginx", "web-tech-wordpress", "web-tech-tomcat"]


class TestSections:
    def test_one_section_or_several(self) -> None:
        text = skill_library.read("web-idor", "how to prove, do not")
        assert "## How to prove it" in text and "## Do not" in text
        assert "## Payloads and bypasses" not in text

    def test_an_unknown_section_lists_the_real_ones(self) -> None:
        answer = json.loads(skill_library.read("web-idor", "nonsense"))
        assert "How to test" in answer["sections"]


class TestReadBeforeSubmit:
    def _bridge(self, tmp_path: Path) -> agent_bridge.Bridge:
        class Echo:
            name = ""

            async def ainvoke(self, args: dict) -> str:
                return json.dumps({"ok": True, "args": args})

        (tmp_path / "acme").mkdir(exist_ok=True)
        (tmp_path / "acme" / "roe.json").write_text(
            json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["a.test"]}})
        )
        tools = {name: Echo() for name in ("finding_submit", "skill_get")}
        tools["skill_get"] = skill_library.skill_get
        return agent_bridge.Bridge("acme", tmp_path, tools=tools)

    def test_a_finding_is_refused_until_one_of_its_class_skills_is_read(
        self, tmp_path: Path
    ) -> None:
        bridge = self._bridge(tmp_path)
        claim = {"finding_json": json.dumps({"class": "injection", "title": "sqli"})}
        refused = asyncio.run(bridge.call("finding_submit", claim))
        assert refused.startswith("BLOCKED") and "web-sql-injection" in refused
        asyncio.run(bridge.call("skill_get", {"name": "web-command-injection", "section": "prove"}))
        assert json.loads(asyncio.run(bridge.call("finding_submit", claim)))["ok"] is True

    def test_a_claim_without_a_known_class_is_left_to_the_verifier(self, tmp_path: Path) -> None:
        bridge = self._bridge(tmp_path)
        claim = {"finding_json": json.dumps({"title": "x"})}
        assert json.loads(asyncio.run(bridge.call("finding_submit", claim)))["ok"] is True

    def test_the_brief_names_the_technology_skills(self, tmp_path: Path) -> None:
        from buggy.cli.hunt import write_technologies

        directory = tmp_path / "acme"
        directory.mkdir(exist_ok=True)
        (directory / "roe.json").write_text(
            json.dumps({"machine_enforcement": {"in_scope": ["a.test"]}})
        )
        records = {
            "technology": [
                {"attrs": {"name": "Nginx", "version": "1.25"}},
                {"attrs": {"name": "Express"}},
            ]
        }
        assert write_technologies(directory, records) == [
            "web-tech-nodejs-express",
            "web-tech-nginx",
        ]
        text = agent_bridge.brief(tmp_path, "acme")
        assert "Express, Nginx:1.25" in text and "web-tech-nginx" in text
