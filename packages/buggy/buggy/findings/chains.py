"""Invariants, and what each proven finding gives and needs, so findings can be chained.

Two fixed tables per probe (and per class, for findings no probe made):

* the **invariant** a finding breaks ("a user can read only the objects they
  own"). An agent names its own; a probe's finding gets the probe's;
* what a finding **gives** an attacker and what it **needs** first, in a small
  fixed vocabulary (:data:`CAPABILITIES`): an access-control bug needs a
  logged-in user and other users' ids and gives their data; a forged-token
  login gives another user's session.

:func:`chains` pairs proven findings where one gives what another needs. A
chain is a **lead to test**, never a finding: nothing here sends a request or
claims that the combination works. Needs nobody gives are listed as open
needs, with the classes that would give them.
"""

from __future__ import annotations

from typing import Any

from buggy.findings.model import SEVERITIES, Status, severity_rank

# ── invariants ──────────────────────────────────────────────────────

#: The rule a probe's positive result breaks.
PROBE_INVARIANTS: dict[str, str] = {
    "idor": "a user can read only the objects they own",
    "authz_matrix": "a user can read only the objects they own",
    "jwt_alg_none": "the server accepts only tokens it signed itself",
    "sqli": "user input is never run as part of a database query",
    "command_injection": "user input is never run as part of a shell command",
    "ssti": "user input is never evaluated as a server-side template",
    "path_traversal": "a user can read only the files the application means to serve",
    "rfi": "the server never loads code or content from a URL the user supplies",
    "ssrf_canary": "the server never sends requests to a host the user chooses",
    "xss_reflected": "input is never echoed into a page as active markup",
    "xss_stored": "content one user stores is never shown to others as active markup",
    "xss_blind": "stored user content is never run as script in staff or back-office pages",
    "clickjacking": "another site cannot show this page in a frame",
    "csrf": "a state-changing request is accepted only when the user's own page sent it",
    "cors": "another origin cannot read a signed-in user's responses",
    "open_redirect": "the application redirects only to destinations it trusts",
    "numeric_boundary": "quantities and amounts stay within their valid range",
    "mass_assignment": "a client can set only the fields it is allowed to change",
    "graphql_checks": "the GraphQL API shows an anonymous client only what it may see",
}

#: The rule a finding of a class breaks, when no probe or agent named one.
CLASS_INVARIANTS: dict[str, str] = {
    "access_control": "a user can read or change only the objects they own",
    "auth_session": "only the right credentials give a session, and a session acts only as "
    "its own user",
    "ssrf": "the server never sends requests to a host the user chooses",
    "business_logic": "the application enforces its own business rules on every request",
    "api": "the API returns and accepts only what the caller is allowed to see and set",
    "graphql": "the GraphQL API shows a client only what it may see",
    "injection": "user input is never run as code or as part of a query",
    "xss": "user input is never shown as active markup",
    "file_handling": "a user can read or write only the files the application means them to",
    "csrf": "a state-changing request is accepted only when the user's own page sent it",
    "open_redirect": "the application redirects only to destinations it trusts",
    "crypto": "secrets and tokens cannot be guessed, forged or read",
    "misconfiguration": "the server's configuration does not weaken the application",
    "info_exposure": "the application does not hand out data the caller should not see",
}


def probe_of(source: str) -> str:
    """The probe named in a finding's source (``probe:sqli`` -> ``sqli``), else ""."""
    for part in (source or "").split("|"):
        part = part.strip()
        if part.startswith("probe:"):
            return part.removeprefix("probe:")
    return ""


def invariant_for(probe: str, vuln_class: str) -> str:
    """The fixed invariant of a probe, else of the class, else ""."""
    return PROBE_INVARIANTS.get(probe or "", "") or CLASS_INVARIANTS.get(vuln_class or "", "")


# ── needs and gives ─────────────────────────────────────────────────

CAPABILITIES: dict[str, str] = {
    "user_session": "a logged-in user",
    "other_user_session": "another user's session or token",
    "admin_role": "the admin role",
    "user_identifiers": "other users' ids, emails or object ids",
    "other_user_data": "read another user's data",
    "other_user_write": "change another user's data",
    "read_any_file": "read any file on the server",
    "secrets": "the application's credentials, keys or tokens",
    "database_read": "read the database",
    "code_execution": "run commands on the server",
    "ssrf_internal": "requests from the server to internal hosts (SSRF)",
    "script_in_victim_browser": "run script in a victim's browser on the target's origin",
    "victim_visit": "a victim opens a page the attacker chose",
    "act_as_victim": "make a victim's browser send a request the attacker chose",
    "cross_origin_read": "read a victim's data from another site",
}

#: Having the key gives everything in the value too.
IMPLIES: dict[str, frozenset[str]] = {
    "other_user_session": frozenset({"user_session", "other_user_data", "other_user_write"}),
    "admin_role": frozenset({"user_session"}),
    "code_execution": frozenset({"read_any_file", "ssrf_internal", "secrets", "database_read"}),
    "read_any_file": frozenset({"secrets"}),
    "database_read": frozenset({"user_identifiers"}),
    "other_user_data": frozenset({"user_identifiers"}),
    "script_in_victim_browser": frozenset({"act_as_victim"}),
    "cross_origin_read": frozenset({"other_user_data"}),
}

_G = "gives"
_N = "needs"

#: Probe -> what its finding gives and needs.
PROBE_EDGES: dict[str, dict[str, tuple[str, ...]]] = {
    "idor": {_G: ("other_user_data",), _N: ("user_session", "user_identifiers")},
    "authz_matrix": {_G: ("other_user_data",), _N: ("user_session", "user_identifiers")},
    "jwt_alg_none": {_G: ("other_user_session", "admin_role"), _N: ("user_session",)},
    "sqli": {_G: ("database_read",), _N: ()},
    "command_injection": {_G: ("code_execution",), _N: ()},
    "ssti": {_G: ("code_execution",), _N: ()},
    "path_traversal": {_G: ("read_any_file",), _N: ()},
    "rfi": {_G: ("code_execution",), _N: ()},
    "ssrf_canary": {_G: ("ssrf_internal",), _N: ()},
    "xss_reflected": {_G: ("script_in_victim_browser",), _N: ("victim_visit",)},
    "xss_stored": {_G: ("script_in_victim_browser",), _N: ("user_session",)},
    "xss_blind": {_G: ("script_in_victim_browser",), _N: ()},
    "clickjacking": {_G: ("act_as_victim",), _N: ("victim_visit",)},
    "csrf": {_G: ("act_as_victim", "other_user_write"), _N: ("victim_visit",)},
    "cors": {_G: ("cross_origin_read",), _N: ("victim_visit",)},
    "open_redirect": {_G: ("victim_visit",), _N: ()},
    "numeric_boundary": {_G: (), _N: ("user_session",)},
    "mass_assignment": {_G: ("admin_role",), _N: ("user_session",)},
    "graphql_checks": {_G: ("user_identifiers",), _N: ()},
}

#: Class -> what a finding of it gives and needs, when no probe made it.
CLASS_EDGES: dict[str, dict[str, tuple[str, ...]]] = {
    "access_control": {_G: ("other_user_data",), _N: ("user_session", "user_identifiers")},
    "auth_session": {_G: ("other_user_session",), _N: ()},
    "ssrf": {_G: ("ssrf_internal",), _N: ()},
    "business_logic": {_G: (), _N: ("user_session",)},
    "api": {_G: ("other_user_data",), _N: ("user_session",)},
    "graphql": {_G: ("user_identifiers",), _N: ()},
    "injection": {_G: ("database_read",), _N: ()},
    "xss": {_G: ("script_in_victim_browser",), _N: ("victim_visit",)},
    "file_handling": {_G: ("read_any_file",), _N: ()},
    "csrf": {_G: ("act_as_victim",), _N: ("victim_visit",)},
    "open_redirect": {_G: ("victim_visit",), _N: ()},
    "crypto": {_G: ("secrets",), _N: ()},
    "misconfiguration": {_G: (), _N: ()},
    "info_exposure": {_G: ("user_identifiers", "secrets"), _N: ()},
}

MAX_CHAINS = 50
#: Needs an attacker usually meets alone (sign up; send a link): never listed as open.
ASSUMED: frozenset[str] = frozenset({"user_session", "victim_visit"})


def closure(capabilities: set[str]) -> set[str]:
    """``capabilities`` plus everything they imply."""
    out = set(capabilities)
    while True:
        more = {implied for c in out for implied in IMPLIES.get(c, ())} - out
        if not more:
            return out
        out |= more


def edges(finding: dict[str, Any], roles: dict[str, str] | None = None) -> dict[str, list[str]]:
    """``{"gives": [...], "needs": [...]}`` for a finding dict, by its probe, else its class.

    A finding proven as a test account also needs a logged-in user, and one
    proven as an account whose role names ``admin`` needs the admin role.
    """
    probe = probe_of(str(finding.get("source") or ""))
    table = PROBE_EDGES.get(probe) or CLASS_EDGES.get(str(finding.get("class") or ""), {})
    gives = list(table.get(_G, ()))
    needs = list(table.get(_N, ()))
    identities = {
        str(a.get("identity") or "")
        for a in finding.get("assertions") or []
        if isinstance(a, dict) and a.get("identity")
    }
    if identities and "user_session" not in needs:
        needs.append("user_session")
    if any("admin" in str((roles or {}).get(name, "")).lower() for name in identities):
        needs.append("admin_role")
    return {"gives": gives, "needs": [n for n in dict.fromkeys(needs) if n not in gives]}


def _proven(finding: dict[str, Any]) -> bool:
    return finding.get("status") == Status.EXPLOIT_VERIFIED.value and finding.get("grade") != (
        "discard"
    )


def _rank(severity: Any) -> int:
    return severity_rank(severity) if severity in SEVERITIES else len(SEVERITIES)


def chains(findings: list[dict[str, Any]], roles: dict[str, str] | None = None) -> dict[str, Any]:
    """Possible chains between proven findings, and the needs nobody gives.

    Only ``exploit_verified`` findings not graded ``discard`` take part. A
    chain is ``A gives X, B needs X``; it is a lead to test, never a finding.
    Ordered by the more severe end first; at most :data:`MAX_CHAINS`.
    """
    nodes = []
    for finding in findings or []:
        if not isinstance(finding, dict) or not _proven(finding):
            continue
        sides = edges(finding, roles)
        nodes.append(
            {
                "id": str(finding.get("id") or ""),
                "title": str(finding.get("title") or ""),
                "class": str(finding.get("class") or ""),
                "severity": str(finding.get("severity") or ""),
                "endpoint": str(finding.get("endpoint") or ""),
                "invariant": str(finding.get("invariant") or ""),
                "gives": sides["gives"],
                "needs": sides["needs"],
                "_has": closure(set(sides["gives"])),
            }
        )
    found: list[dict[str, Any]] = []
    open_needs: dict[str, list[str]] = {}
    for target in nodes:
        for need in target["needs"]:
            givers = [n for n in nodes if n["id"] != target["id"] and need in n["_has"]]
            if not givers and need not in ASSUMED:
                open_needs.setdefault(need, []).append(target["id"])
            for giver in givers:
                found.append(
                    {
                        "from": giver["id"],
                        "to": target["id"],
                        "capability": need,
                        "text": (
                            f"{giver['id']} ({giver['title']}) gives {CAPABILITIES[need]}, which "
                            f"{target['id']} ({target['title']}) needs. Test whether the first "
                            "lets an attacker reach the second."
                        ),
                        "proven": False,
                        "_order": (
                            min(_rank(giver["severity"]), _rank(target["severity"])),
                            giver["id"],
                            target["id"],
                            need,
                        ),
                    }
                )
    found.sort(key=lambda chain: chain["_order"])
    for chain in found:
        del chain["_order"]
    givers_of = {
        need: sorted({cls for cls, table in CLASS_EDGES.items() if need in closure(set(table[_G]))})
        for need in open_needs
    }
    return {
        "ok": True,
        "chains": found[:MAX_CHAINS],
        "chains_total": len(found),
        "nodes": [{k: v for k, v in node.items() if k != "_has"} for node in nodes],
        "open_needs": [
            {
                "capability": need,
                "means": CAPABILITIES[need],
                "needed_by": ids,
                "classes_that_give_it": givers_of[need],
            }
            for need, ids in sorted(open_needs.items())
        ],
        "vocabulary": CAPABILITIES,
        "note": "A chain is a lead to test, not a proven finding.",
    }


__all__ = [
    "ASSUMED",
    "CAPABILITIES",
    "CLASS_EDGES",
    "CLASS_INVARIANTS",
    "IMPLIES",
    "MAX_CHAINS",
    "PROBE_EDGES",
    "PROBE_INVARIANTS",
    "chains",
    "closure",
    "edges",
    "invariant_for",
    "probe_of",
]
