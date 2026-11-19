"""``program.json`` — the operator-imported record of a bounty program."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROGRAM_FILE = "program.json"

#: Techniques no program engagement may use, whatever the program page says.
#: A program can add to this list; it can never remove from it.
BASELINE_BANNED_TECHNIQUES: tuple[dict[str, str], ...] = (
    {
        "id": "denial_of_service",
        "rule": "No denial of service: no flooding, stress or load testing, "
        "resource exhaustion, or anything intended to degrade availability.",
    },
    {
        "id": "social_engineering",
        "rule": "No social engineering: no phishing, vishing, pretexting or contact "
        "with the program's staff, customers or vendors.",
    },
    {
        "id": "physical",
        "rule": "No physical access or testing of offices, devices or staff.",
    },
    {
        "id": "data_exfiltration",
        "rule": "No data exfiltration beyond the minimum that proves the issue: read one "
        "record you are entitled to demonstrate with, stop, and report.",
    },
    {
        "id": "other_users",
        "rule": "Never access, change or delete another user's data. Use accounts you "
        "created for testing.",
    },
)

#: Commands that exist to degrade availability. Refused by the command parser
#: on every program engagement.
DOS_COMMAND_PATTERNS: tuple[str, ...] = (
    r"(?i)\b(?:slowloris|slowhttptest|goldeneye|hulk|torshammer|xerxes|thc-ssl-dos)\b",
    r"(?i)\bhping3?\b.*--flood",
    r"(?i)\b(?:loic|hoic)\b",
    r"(?i)\bab\b\s+.*-n\s*\d{5,}",
    r"(?i)\b(?:wrk|siege|vegeta|bombardier)\b",
    r"(?i)\bnping\b.*--rate\s*\d{4,}",
    r"(?i)\bmdk[34]\b",
)

#: Tools whose purpose is sending messages to people.
SOCIAL_ENGINEERING_COMMAND_PATTERNS: tuple[str, ...] = (
    r"(?i)\b(?:gophish|setoolkit|evilginx2?|king-phisher|swaks|sendemail)\b",
)


def load_program(control_root: Path, engagement: str) -> dict[str, Any] | None:
    """The program record for ``engagement``, or ``None`` when it is not a program engagement.

    An unreadable or malformed record is returned as ``{"_invalid": reason}``
    rather than ``None``: a damaged file must not silently drop the engagement
    back to the looser non-program rules.
    """
    name = (engagement or "").strip()
    if not name or "/" in name or name.startswith("."):
        return None
    path = Path(control_root) / name / PROGRAM_FILE
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        return {"_invalid": f"cannot read {path}: {exc}"}
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return {"_invalid": f"{path} is not valid JSON: {exc}"}
    if not isinstance(data, dict):
        return {"_invalid": f"{path} is not a JSON object"}
    return data


def banned_technique_ids(program: dict[str, Any]) -> list[str]:
    out = [entry["id"] for entry in BASELINE_BANNED_TECHNIQUES]
    for entry in program.get("banned_techniques") or []:
        if isinstance(entry, dict) and entry.get("id") and entry["id"] not in out:
            out.append(str(entry["id"]))
    return out
