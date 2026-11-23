"""Which Buggy checks and tools a skill names, and whether they exist.

A skill's "In Buggy" section names the probe, record type or agent tool that
covers its bug, in backticks. A name shaped like a Buggy check that matches
nothing Buggy has is a typo or a check that was renamed: the agent would look
for a tool that is not there. :func:`unknown_checks` finds those.

The list of known names is built from the code (the probe registry, the recon
record types and the stack MCP tools), so it never goes out of date.
"""

from __future__ import annotations

import re
from functools import lru_cache

#: Section headings every web bug skill (``standard/exploit/web/hacktricks``) has.
REQUIRED_SECTIONS: tuple[str, ...] = (
    "What it is",
    "Where to look",
    "How to test",
    "Payloads and bypasses",
    "How to prove it",
    "False positives",
    "Impact and severity",
    "In Buggy",
    "Do not",
    "Fix",
    "Sources",
)
#: Where the skills that must have :data:`REQUIRED_SECTIONS` live, under the skills root.
SECTIONED_DIR = "standard/exploit/web/hacktricks/"

# Names in a skill's "In Buggy" section that are shaped like a Buggy check or tool.
BUGGY_SHAPE = re.compile(
    r"^(?:(?:recipe|probe|finding|browser|recon|skill|authz|owners|surface|accounts|proof|evidence"
    r"|xss|ssrf|jwt)_[a-z0-9_]+\*?"
    r"|[a-z0-9_]+_(?:run|check|checks|save|send|canary|injection|traversal|reflected|stored|blind"
    r"|boundary|assignment|alg_none))$"
)
_TICKED = re.compile(r"`([a-z][a-z0-9_]*\*?)`")

#: Agent tools that are not stack MCP tools, and families named with a wildcard.
_OTHER_NAMES = frozenset(
    {
        "skill_list", "skill_get", "research_fetch", "recipe_check", "recipe_save",
        "recipe_run", "recipe_list", "recipe_get", "authz_matrix_run", "owners_infer",
        "surface_crawl", "user_walk", "accounts_provision", "proof_record", "http_send",
        "browser_*", "recipe_*", "xss_*",
    }
)  # fmt: skip


@lru_cache(maxsize=1)
def known_names() -> frozenset[str]:
    """Every probe, recon record type and agent tool name Buggy has."""
    from buggy.capture.probes.registry import REGISTRY  # noqa: PLC0415
    from buggy.pipeline.schema import RecordType  # noqa: PLC0415
    from buggy.tools.stack_mcp import ALL_STACK_MCP_TOOLS  # noqa: PLC0415

    names = set(REGISTRY) | {t.value for t in RecordType}
    names |= {str(getattr(tool, "name", "")) for tool in ALL_STACK_MCP_TOOLS}
    return frozenset(names | _OTHER_NAMES)


def named_checks(in_buggy: str) -> list[str]:
    """The Buggy-shaped names in the text of an "In Buggy" section, in order."""
    return [token for token in _TICKED.findall(in_buggy) if BUGGY_SHAPE.match(token)]


def unknown_checks(in_buggy: str, known: frozenset[str] | None = None) -> list[str]:
    """Buggy-shaped names in ``in_buggy`` that are not a known check or tool."""
    known = known_names() if known is None else known
    return [name for name in named_checks(in_buggy) if name not in known]


__all__ = [
    "BUGGY_SHAPE",
    "REQUIRED_SECTIONS",
    "SECTIONED_DIR",
    "known_names",
    "named_checks",
    "unknown_checks",
]
