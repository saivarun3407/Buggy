"""Grade: is a finding ready to submit, held, or discarded, and why.

A deterministic decision over a stored finding, the program's rules, the
enforced scope, the scanner's known issues and earlier findings. The rules are
evaluated in the order below and every rule that fires adds a reason; nothing
stops at the first hit, so the operator sees all of it at once.

 1. verification      not ``exploit_verified`` -> hold; ``discarded`` -> discard
 2. scope             the endpoint's host is not allowed by the scope -> discard
 3. program exclusions  the class or title matches a class the program excludes,
                      or a banned technique -> discard
 4. remediation       shorter than 30 characters, or a placeholder -> hold
 5. duplicates        already graded ``submit`` elsewhere -> discard; reported
                      by a scanner template at the same class and endpoint -> hold
 6. severity cap      above the program's cap for the host -> the decision is
                      kept and ``capped_severity`` is returned
 7. low signal        ``info``, or ``misconfiguration`` at ``low`` -> hold
 9. disprover         an agent-made finding the disprover called ``false_positive``
                      or ``undetermined``, not overridden by the operator -> hold
                      (checked before 8; numbered last so the older numbers stay)
 8. submit            none of the above held or discarded it

The decision is the strictest one any rule asked for: discard over hold over
submit. ``blocking`` says what has to change for a hold to become a submit; it
is empty for the other two decisions.

Nothing is sent and nothing is stored here.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from buggy.findings.model import (
    CLASSES,
    SEVERITIES,
    Finding,
    Severity,
    Status,
    VulnClass,
    normalize_endpoint,
    severity_rank,
)

SUBMIT = "submit"
HOLD = "hold"
DISCARD = "discard"

#: Rule number -> the name a reason carries ("Rule 2 (scope): ...").
RULES: dict[int, str] = {
    1: "verification",
    2: "scope",
    3: "program exclusions",
    4: "remediation",
    5: "duplicates",
    6: "severity cap",
    7: "low signal",
    8: "submit",
    9: "disprover",
}

#: The disprover's verdicts (``finding_challenge``) and the ones that hold a finding.
CHALLENGE_STANDS = "stands"
CHALLENGE_VERDICTS = (CHALLENGE_STANDS, "false_positive", "undetermined")
CHALLENGE_HOLDS = frozenset({"false_positive", "undetermined"})
CHALLENGE_BLOCKING = (
    "Answer the disprover's objection with evidence, or have the operator override it "
    "(buggy-cli disprover override ENGAGEMENT FINDING_ID --reason TEXT)."
)


def challenge_text(challenge: dict[str, Any] | None) -> str:
    """Rule 9's sentence for a standing objection, or ``""`` when it holds nothing."""
    challenge = challenge if isinstance(challenge, dict) else {}
    verdict = str(challenge.get("verdict") or "")
    if verdict not in CHALLENGE_HOLDS:
        return ""
    said = " ".join(str(challenge.get("reason") or "no reason given").split())[:300]
    return f"the disprover's verdict is {verdict}: {said.rstrip('.') or 'no reason given'}."


def challenge_reason(challenge: dict[str, Any] | None) -> str:
    """The full reason line rule 9 adds (``Rule 9 (disprover): ...``), or ``""``."""
    text = challenge_text(challenge)
    return f"Rule 9 ({RULES[9]}): {text}" if text else ""


# The remediation rule and the banned techniques mirror ``buggy.program.gate``.
# That module is outside what this package may import (see AGENT_RULES.md,
# "Dependencies"), so the values are repeated here and a test keeps them equal.
MIN_REMEDIATION_CHARS = 30
_PLACEHOLDER = re.compile(r"^\W*(?:tbd|todo|n/?a|none|pending|fix it|see above)\W*$", re.IGNORECASE)

MIN_EXCLUDED_CHARS = 4

#: Techniques no program accepts, whatever its page says: (id, words, what names it).
#: Whole words only, so ``/api/todos`` is not read as "dos".
BANNED_TECHNIQUES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "denial_of_service",
        "denial of service",
        re.compile(r"\b(?:(?:d|re)?dos|denial[- _]of[- _]service|resource exhaustion)\b"),
    ),
    (
        "social_engineering",
        "social engineering",
        re.compile(r"\b(?:phishing|vishing|social[- _]engineering)\b"),
    ),
    (
        "physical",
        "physical access",
        re.compile(r"\bphysical[- _](?:access|security)\b"),
    ),
)

# A scanner record carries no class of ours. This is the minimal map from what
# it does carry: CWE ids first (the lab taxonomy's table), then template tags.
_CWE_CLASS: dict[str, tuple[int, ...]] = {
    VulnClass.AUTH_SESSION: (
        287, 288, 290, 294, 295, 303, 304, 306, 307, 308,
        345, 347, 384, 521, 522, 613, 620, 640, 798, 1390,
    ),
    VulnClass.ACCESS_CONTROL: (284, 285, 425, 566, 639, 862, 863),
    VulnClass.SSRF: (918,),
    VulnClass.BUSINESS_LOGIC: (20, 840, 841, 799, 837, 1284),
    VulnClass.API: (213, 915),
    VulnClass.INJECTION: (74, 77, 78, 88, 89, 90, 91, 94, 95, 917, 943, 1336),
    VulnClass.XSS: (79, 80, 83, 87),
    VulnClass.FILE_HANDLING: (22, 23, 35, 73, 98, 434, 611, 776),
    VulnClass.CSRF: (352,),
    VulnClass.OPEN_REDIRECT: (601,),
    VulnClass.CRYPTO: (261, 310, 311, 312, 319, 326, 327, 328, 330, 331, 338, 759, 760, 916),
    VulnClass.MISCONFIGURATION: (16, 346, 693, 942, 1004, 1021, 614),
    VulnClass.INFO_EXPOSURE: (200, 201, 209, 215, 359, 497, 532, 538, 548),
}  # fmt: skip
CWE_TO_CLASS: dict[int, str] = {}
for _name, _ids in _CWE_CLASS.items():
    for _cwe in _ids:
        CWE_TO_CLASS.setdefault(_cwe, str(_name))

#: Template tags (and words of the template id), checked in order.
_TAG_CLASS: tuple[tuple[str, frozenset[str]], ...] = (
    (VulnClass.GRAPHQL, frozenset({"graphql"})),
    (VulnClass.SSRF, frozenset({"ssrf"})),
    (VulnClass.CSRF, frozenset({"csrf"})),
    (VulnClass.XSS, frozenset({"xss"})),
    (VulnClass.OPEN_REDIRECT, frozenset({"redirect"})),
    (VulnClass.INJECTION, frozenset({"sqli", "nosqli", "rce", "ssti", "cmdi", "injection"})),
    (VulnClass.FILE_HANDLING, frozenset({"lfi", "rfi", "xxe", "traversal", "fileupload"})),
    (VulnClass.ACCESS_CONTROL, frozenset({"idor", "bola"})),
    (VulnClass.AUTH_SESSION, frozenset({"jwt", "auth-bypass", "default-login"})),
    (VulnClass.MISCONFIGURATION, frozenset({"misconfig", "misconfiguration", "cors"})),
    (VulnClass.INFO_EXPOSURE, frozenset({"exposure", "disclosure"})),
)

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class Grade:
    """The grader's decision. ``reasons`` name the rule that produced each of them."""

    decision: str
    reasons: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)
    #: The program's cap when the claimed severity is above it, else ``None``.
    capped_severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reasons": list(self.reasons),
            "blocking": list(self.blocking),
            "capped_severity": self.capped_severity,
        }


def _short(value: Any, limit: int = 120) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return [] if value in (None, "") else [value]


def endpoint_host(endpoint: str) -> str:
    """The host an endpoint names, lower-case; ``""`` for a bare path."""
    parts = urlsplit((endpoint or "").strip())
    if not (parts.scheme and parts.netloc):
        return ""
    return (parts.hostname or "").rstrip(".").lower()


def _endpoint_key(value: str) -> tuple[str, str]:
    """``(origin, path)`` of an endpoint, default port and trailing slash dropped."""
    normal = normalize_endpoint(value)
    parts = urlsplit(normal)
    if not (parts.scheme and parts.netloc):
        return "", normal.rstrip("/")
    port = parts.port
    shown = "" if port in (None, _DEFAULT_PORTS.get(parts.scheme)) else f":{port}"
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}{shown}", parts.path.rstrip("/")


def same_endpoint(finding_endpoint: str, other: str) -> bool:
    """True when ``other`` is the finding's endpoint. A bare-path endpoint matches any host."""
    origin, path = _endpoint_key(finding_endpoint)
    other_origin, other_path = _endpoint_key(other)
    if not other_origin or path != other_path:
        return False
    return not origin or origin == other_origin


# ── rule 3: what the program does not take ──────────────────────────


def _described(finding: Finding) -> str:
    """The text the exclusion rules read: the class (both spellings) and the title."""
    cls = finding.vuln_class.lower()
    return " ".join((cls, cls.replace("_", " "), finding.title.lower()))


def excluded_matches(finding: Finding, program: dict[str, Any] | None) -> list[str]:
    """The program's ``excluded_classes`` entries this finding's class or title contains."""
    entries = _as_dict(program).get("excluded_classes")
    described = _described(finding)
    matched: list[str] = []
    for entry in entries if isinstance(entries, (list, tuple)) else []:
        wording = str(entry).strip()
        name = wording.lower()
        if len(name) >= MIN_EXCLUDED_CHARS and name in described and wording not in matched:
            matched.append(wording)
    return matched


def banned_matches(finding: Finding) -> list[tuple[str, str, str]]:
    """``(technique id, its name, the words that named it)`` for each banned technique."""
    described = _described(finding)
    out: list[tuple[str, str, str]] = []
    for technique, words, pattern in BANNED_TECHNIQUES:
        found = pattern.search(described)
        if found is not None:
            out.append((technique, words, found.group(0)))
    return out


# ── rule 4: remediation ─────────────────────────────────────────────


def remediation_problem(remediation: str) -> str:
    """Why this remediation does not tell the owner what to change; ``""`` when it does."""
    text = (remediation or "").strip()
    if not text:
        return "the finding has no remediation"
    if _PLACEHOLDER.match(text):
        return f"the remediation is a placeholder ({_short(text, 40)!r})"
    if len(text) < MIN_REMEDIATION_CHARS:
        return (
            f"the remediation is {len(text)} characters long and at least "
            f"{MIN_REMEDIATION_CHARS} are needed"
        )
    return ""


# ── rule 5: duplicates and known issues ─────────────────────────────


def _same_record(candidate: Finding, finding: Finding) -> bool:
    """The stored row of the finding being graded, handed back in ``prior``."""
    if candidate is finding:
        return True
    return bool(finding.created_at) and candidate.created_at == finding.created_at


def duplicate_of(finding: Finding, prior: list[Finding]) -> str:
    """Id of an earlier finding with the same id that is already graded ``submit``."""
    for other in prior or []:
        if not isinstance(other, Finding) or _same_record(other, finding):
            continue
        if other.id == finding.id and other.grade == SUBMIT:
            return other.id
    return ""


def known_issue_class(entry: dict[str, Any]) -> str:
    """Our class for a pipeline ``vulnerability`` record; ``""`` when it cannot be told.

    An explicit ``class`` on the record wins, then its CWE ids, then the
    template's tags and the words of its id.
    """
    attrs = _as_dict(entry.get("attrs"))
    for explicit in (entry.get("class"), attrs.get("class")):
        if isinstance(explicit, str) and explicit.strip().lower() in CLASSES:
            return explicit.strip().lower()
    for cwe in _as_list(attrs.get("cwe")):
        number = re.search(r"\d+", str(cwe))
        if number is not None and int(number.group(0)) in CWE_TO_CLASS:
            return CWE_TO_CLASS[int(number.group(0))]
    tokens = {str(tag).strip().lower() for tag in _as_list(attrs.get("tags"))}
    tokens.update(re.split(r"[^a-z0-9]+", known_issue_template(entry).lower()))
    for name, markers in _TAG_CLASS:
        if tokens & markers:
            return str(name)
    return ""


def known_issue_template(entry: dict[str, Any]) -> str:
    """The scanner template id of a pipeline ``vulnerability`` record."""
    attrs = _as_dict(entry.get("attrs"))
    value = str(entry.get("value") or "").split(" ")
    return str(attrs.get("template_id") or value[0]).strip()


def known_issue_endpoint(entry: dict[str, Any]) -> str:
    """Where the scanner matched: ``attrs.matched_at``, else the last word of ``value``."""
    attrs = _as_dict(entry.get("attrs"))
    value = str(entry.get("value") or "").split(" ")
    return str(attrs.get("matched_at") or value[-1]).strip()


def known_issue_templates(finding: Finding, known_issues: list[dict[str, Any]]) -> list[str]:
    """Template ids of scanner records with the finding's class at the finding's endpoint."""
    templates: list[str] = []
    for entry in known_issues or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") not in (None, "", "vulnerability"):
            continue
        if known_issue_class(entry) != finding.vuln_class:
            continue
        if not same_endpoint(finding.endpoint, known_issue_endpoint(entry)):
            continue
        template = known_issue_template(entry) or "(unnamed)"
        if template not in templates:
            templates.append(template)
    return templates


# ── rule 6: severity cap ────────────────────────────────────────────


def _cap_applies(pattern: str, host: str) -> bool:
    """Whether a ``severity_caps`` key covers ``host``.

    A program's ``*.example.com`` means every subdomain at any depth (the
    importer writes it as ``**.example.com``); neither form covers the apex.
    """
    if pattern == host:
        return True
    for prefix in ("**.", "*."):
        if pattern.startswith(prefix):
            base = pattern[len(prefix) :]
            return bool(base) and "*" not in base and host.endswith("." + base)
    if "/" in pattern:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    return False


def severity_cap(program: dict[str, Any] | None, host: str) -> tuple[str, str]:
    """``(cap, the program's entry it comes from)`` for ``host``; ``("", "")`` when none applies.

    An exact host entry beats a wildcard, a longer wildcard beats a shorter
    one, and between equals the lower cap wins. A cap that is not one of the
    contract's severities is ignored.
    """
    caps = _as_dict(_as_dict(program).get("severity_caps"))
    if not host:
        return "", ""
    best: tuple[tuple[int, int, int], str, str] | None = None
    for raw_pattern, raw_cap in caps.items():
        pattern = str(raw_pattern).strip().lower().rstrip(".")
        cap = str(raw_cap).strip().lower()
        if not pattern or cap not in SEVERITIES or not _cap_applies(pattern, host):
            continue
        order = (int(pattern == host), len(pattern), severity_rank(cap))
        if best is None or order > best[0]:
            best = (order, cap, str(raw_pattern))
    return (best[1], best[2]) if best is not None else ("", "")


# ── the decision ────────────────────────────────────────────────────


class _Ruling:
    """Collects what the rules say; the strictest decision wins."""

    _ORDER = (SUBMIT, HOLD, DISCARD)

    def __init__(self) -> None:
        self.decision = SUBMIT
        self.reasons: list[str] = []
        self._blocking: list[str] = []

    def add(self, rule: int, text: str, *, decision: str = "", blocking: str = "") -> None:
        self.reasons.append(f"Rule {rule} ({RULES[rule]}): {text}")
        if decision and self._ORDER.index(decision) > self._ORDER.index(self.decision):
            self.decision = decision
        if blocking:
            self._blocking.append(blocking)

    def blocking(self) -> list[str]:
        return list(self._blocking) if self.decision == HOLD else []


def grade(
    finding: Finding,
    *,
    program: dict[str, Any] | None,
    scope: Any,
    known_issues: list[dict[str, Any]],
    prior: list[Finding],
    challenge: dict[str, Any] | None = None,
) -> Grade:
    """Decide ``submit``, ``hold`` or ``discard`` for ``finding`` and say why.

    ``program`` is the engagement's ``program.json`` (``None`` when it is not a
    program engagement); ``scope`` is the enforced scope (anything with
    ``allows(host) -> bool``); ``known_issues`` are pipeline ``vulnerability``
    records; ``prior`` are earlier findings. ``challenge`` is the disprover's
    standing objection (``{"verdict", "reason"}``), if there is one the
    operator has not overridden. Nothing is written.
    """
    if scope is None or not callable(getattr(scope, "allows", None)):
        raise ValueError("scope is required: a finding is not graded without the enforced scope")
    ruling = _Ruling()

    # 1. Only a finding the verifier re-proved can be submitted.
    if finding.status == Status.DISCARDED.value:
        ruling.add(
            1,
            "not exploit-verified: discarded; the verifier rejected the evidence it cites.",
            decision=DISCARD,
        )
    elif finding.status != Status.EXPLOIT_VERIFIED.value:
        ruling.add(
            1,
            f"not exploit-verified: {finding.status}; only a finding the verifier has "
            "re-proved can be submitted.",
            decision=HOLD,
            blocking=(
                f"Verify the finding: its status is {finding.status} and must be "
                f"{Status.EXPLOIT_VERIFIED.value}."
            ),
        )

    # 2. The scope as it is now, not as it was when the request was captured.
    host = endpoint_host(finding.endpoint)
    if not host:
        ruling.add(
            2,
            f"the endpoint {_short(finding.endpoint)!r} names no host, so it cannot be "
            "checked against the enforced scope.",
            decision=HOLD,
            blocking="Give the finding an absolute URL endpoint so its host can be scope-checked.",
        )
    elif not scope.allows(host):
        ruling.add(
            2,
            f"out of scope now: {host} is not allowed by the enforced scope.",
            decision=DISCARD,
        )

    # 3. Classes the program does not take, and techniques no program takes.
    invalid = _as_dict(program).get("_invalid")
    if invalid:
        ruling.add(
            3,
            f"the program record is unreadable ({_short(invalid)}), so the program's "
            "exclusions and severity caps cannot be checked.",
            decision=HOLD,
            blocking="Re-import the program scope so the program record can be read.",
        )
    for wording in excluded_matches(finding, program):
        ruling.add(
            3,
            f"the program does not accept this class: {_short(wording)!r} is on its "
            "exclusion list and this finding's class or title names it.",
            decision=DISCARD,
        )
    for technique, words, named in banned_matches(finding):
        ruling.add(
            3,
            f"{words} ({technique}) is a banned technique for every program and this "
            f"finding's class or title names it ({named!r}).",
            decision=DISCARD,
        )

    # 4. A report without a fix is not ready.
    problem = remediation_problem(finding.remediation)
    if problem:
        ruling.add(
            4,
            f"{problem}; a report must say what the owner should change.",
            decision=HOLD,
            blocking=(
                f"Write a remediation of at least {MIN_REMEDIATION_CHARS} characters that "
                "says what the owner should change."
            ),
        )

    # 5. Already submitted, or already known to the scanner.
    duplicate = duplicate_of(finding, prior)
    if duplicate:
        ruling.add(
            5,
            f"duplicate of {duplicate}, which is already graded {SUBMIT}.",
            decision=DISCARD,
        )
    for template in known_issue_templates(finding, known_issues):
        shown = _short(template)
        ruling.add(
            5,
            f"already reported by scanner template {shown}: confirm it is not a "
            "known/accepted issue.",
            decision=HOLD,
            blocking=(
                f"Confirm that scanner template {shown} does not describe a known or accepted "
                "issue, then grade again without that record."
            ),
        )

    # 6. The program pays up to a cap on this host; the decision is not changed.
    capped: str | None = None
    cap, entry = ("", "") if invalid else severity_cap(program, host)
    if cap and finding.severity in SEVERITIES:
        if severity_rank(finding.severity) < severity_rank(cap):
            capped = cap
            ruling.add(
                6,
                f"severity capped to {cap}: the program caps {_short(entry)} at {cap} and "
                f"this finding claims {finding.severity}.",
            )

    # 7. What most programs do not pay for, judged on the severity after the cap.
    effective = capped or finding.severity
    low_signal = ""
    if effective == Severity.INFO.value:
        low_signal = "severity info"
    elif finding.vuln_class == VulnClass.MISCONFIGURATION.value and effective == Severity.LOW.value:
        low_signal = "a misconfiguration at low severity"
    if low_signal:
        ruling.add(
            7,
            f"low signal: most programs do not pay for this ({low_signal}).",
            decision=HOLD,
            blocking=(
                "Show impact that justifies a higher severity, or have the operator confirm "
                "the program pays for this."
            ),
        )

    # 9. The disprover argued it is false, or could not tell; the operator decides.
    objection = challenge_text(challenge)
    if objection:
        ruling.add(9, objection, decision=HOLD, blocking=CHALLENGE_BLOCKING)

    # 8. Nothing held or discarded it.
    if ruling.decision == SUBMIT:
        ruling.add(
            8,
            "exploit-verified, in scope, not excluded, with a remediation, and neither a "
            "duplicate nor a known issue: ready to submit.",
        )
    return Grade(ruling.decision, ruling.reasons, ruling.blocking(), capped)


__all__ = [
    "BANNED_TECHNIQUES",
    "CHALLENGE_BLOCKING",
    "CHALLENGE_HOLDS",
    "CHALLENGE_STANDS",
    "CHALLENGE_VERDICTS",
    "CWE_TO_CLASS",
    "DISCARD",
    "HOLD",
    "MIN_EXCLUDED_CHARS",
    "MIN_REMEDIATION_CHARS",
    "RULES",
    "SUBMIT",
    "Grade",
    "banned_matches",
    "challenge_reason",
    "challenge_text",
    "duplicate_of",
    "endpoint_host",
    "excluded_matches",
    "grade",
    "known_issue_class",
    "known_issue_endpoint",
    "known_issue_template",
    "known_issue_templates",
    "remediation_problem",
    "same_endpoint",
    "severity_cap",
]
