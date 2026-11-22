"""The scope of an engagement as four plain lists: in scope, out of scope, do, don't.

Built by rule from the stored scope document and, for an engagement imported
from a bounty program, its program record. It is a view of what is stored:
nothing is enforced from this text, and no line appears that the documents do
not back. Every place Buggy shows a scope prints this card.
"""

from __future__ import annotations

from typing import Any

SECTIONS = (
    ("in_scope", "IN SCOPE"),
    ("out_of_scope", "OUT OF SCOPE"),
    ("do", "DO"),
    ("dont", "DON'T"),
)

#: What Buggy never does on any engagement. The rate limit and the gateway
#: enforce the first by code; the agent is told all three in its rules.
ALWAYS_DONT = (
    "No denial of service or load testing.",
    "No social engineering.",
    "No data taken beyond what proves a bug.",
)


def _block(source: Any, name: str) -> dict[str, Any]:
    value = source.get(name) if isinstance(source, dict) else None
    return value if isinstance(value, dict) else {}


def _targets(entries: Any) -> list[str]:
    out = []
    for entry in entries or []:
        text = str(entry.get("target") or "") if isinstance(entry, dict) else str(entry)
        if text and text not in out:
            out.append(text)
    return out


def _rate(document: dict[str, Any], program: dict[str, Any] | None) -> int | None:
    limit = _block(program, "rate_limit").get("requests_per_second")
    if not isinstance(limit, int):
        limit = _block(document, "pipeline").get("rate_limit_rps")
    if not isinstance(limit, int):
        delay = _block(document, "machine_enforcement").get("min_inter_request_delay_ms")
        limit = 1000 // delay if isinstance(delay, int) and delay > 0 else None
    return limit if isinstance(limit, int) and limit > 0 else None


def _banned(program: dict[str, Any] | None) -> list[str]:
    rules = [
        str(entry["rule"]).strip()
        for entry in (program or {}).get("banned_techniques") or []
        if isinstance(entry, dict) and entry.get("rule")
    ]
    return rules or list(ALWAYS_DONT)


def card(document: dict[str, Any], program: dict[str, Any] | None = None) -> dict[str, Any]:
    """The four lists for one scope document. ``enforced`` is False for a draft or audit scope."""
    block = _block(document, "machine_enforcement")
    pipeline = _block(document, "pipeline")
    lab = _block(document, "approvals").get("state_changing") == "not_required"
    accounts = _block(block, "account_creation")
    creates = accounts.get("enabled") is True

    do = []
    rate = _rate(document, program)
    if rate:
        do.append(f"Send at most {rate} requests per second.")
    do.append("Read-only tests on every in-scope page and input.")
    do.append(
        "Tests that change data, without asking (practice target)."
        if lab
        else "Tests that change data, only after you approve each one."
    )
    if creates:
        do.append(
            f"Register up to {accounts.get('max_accounts', 2)} test accounts "
            f"(emails like {accounts.get('email_template', '')})."
        )
    if pipeline.get("port_scan"):
        do.append("Scan the top 100 ports.")
    do.append("Write the report. You submit it.")

    dont = _banned(program)
    if pipeline.get("passive_only"):
        dont.append("No automated scanning: recon from passive sources only.")
    if not pipeline.get("port_scan"):
        dont.append("No port scanning.")
    if not creates:
        dont.append("No account creation: only accounts you give it.")
    if not _block(document, "network").get("allow_private_targets"):
        dont.append("No requests to internal addresses.")
    dont.append("Never approves its own request and never submits a report.")

    return {
        "enforced": block.get("mode") == "enforce",
        "in_scope": _targets(block.get("in_scope")),
        "out_of_scope": [
            *_targets(block.get("out_of_scope")),
            "Everything not listed as in scope.",
        ],
        "do": do,
        "dont": dont,
    }


def render(shown: dict[str, Any], indent: str = "  ") -> str:
    """The card as text: a heading per list, one entry per line."""
    lines = []
    if not shown.get("enforced"):
        lines.append(f"{indent}NOT ENFORCED: this scope constrains nothing until it is enforced.")
    for key, heading in SECTIONS:
        lines.append(f"{indent}{heading}")
        lines += [f"{indent}  {entry}" for entry in shown.get(key) or ["(none)"]]
    return "\n".join(lines)
