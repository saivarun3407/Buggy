"""Vulnerability classes used to score the lab, and how findings map onto them."""

from __future__ import annotations

import re

# Order is the report order. The first six are the priority classes.
CLASSES = (
    "auth_session",
    "access_control",
    "ssrf",
    "business_logic",
    "api",
    "graphql",
    "injection",
    "xss",
    "file_handling",
    "csrf",
    "open_redirect",
    "crypto",
    "misconfiguration",
    "info_exposure",
)

DESCRIPTIONS = {
    "auth_session": "Authentication and session management (login bypass, JWT, reset, fixation)",
    "access_control": "Access control and IDOR / BOLA / BFLA",
    "ssrf": "Server-side request forgery",
    "business_logic": "Business-logic flaws (price, quantity, workflow abuse)",
    "api": "API-specific flaws (mass assignment, excessive data exposure, undocumented endpoints)",
    "graphql": "GraphQL-specific flaws (introspection, batching, field-level authorisation)",
    "injection": "SQL / NoSQL / command / template injection",
    "xss": "Cross-site scripting",
    "file_handling": "Upload, path traversal, file inclusion, XXE",
    "csrf": "Cross-site request forgery",
    "open_redirect": "Unvalidated redirects",
    "crypto": "Weak cryptography and hashing",
    "misconfiguration": "Security misconfiguration (CORS, headers, defaults, debug surfaces)",
    "info_exposure": "Sensitive information exposure",
}

_CWE_CLASS = {
    "auth_session": (
        287,
        288,
        290,
        294,
        295,
        303,
        304,
        306,
        307,
        308,
        345,
        347,
        384,
        521,
        522,
        613,
        620,
        640,
        798,
        1390,
    ),
    "access_control": (284, 285, 425, 566, 639, 862, 863),
    "ssrf": (918,),
    "business_logic": (20, 840, 841, 799, 837, 1284),
    "api": (213, 915),
    "injection": (74, 77, 78, 88, 89, 90, 91, 94, 95, 917, 943, 1336),
    "xss": (79, 80, 83, 87),
    "file_handling": (22, 23, 35, 73, 98, 434, 611, 776),
    "csrf": (352,),
    "open_redirect": (601,),
    "crypto": (261, 310, 311, 312, 319, 326, 327, 328, 330, 331, 338, 759, 760, 916),
    "misconfiguration": (16, 346, 693, 942, 1004, 1021, 614),
    "info_exposure": (200, 201, 209, 215, 359, 497, 532, 538, 548),
}
CWE_TO_CLASS: dict[int, str] = {}
for _name, _ids in _CWE_CLASS.items():
    for _cwe in _ids:
        CWE_TO_CLASS.setdefault(_cwe, _name)

# Title keywords, checked in order, for findings that carry no usable CWE.
_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("graphql", r"graphql|introspection"),
    ("ssrf", r"\bssrf\b|server[- ]side request"),
    ("csrf", r"\bcsrf\b|cross[- ]site request forgery"),
    ("xss", r"\bxss\b|cross[- ]site scripting"),
    ("open_redirect", r"open redirect|unvalidated redirect"),
    ("injection", r"sql ?i|sql injection|nosql|command injection|\brce\b|template injection|ssti"),
    (
        "access_control",
        r"\bidor\b|\bbola\b|\bbfla\b|access control|authori[sz]ation|privilege escalation|another user",
    ),
    (
        "auth_session",
        r"\bjwt\b|authentication|login bypass|session|password reset|brute[- ]?force|default credential|otp",
    ),
    ("api", r"mass assignment|excessive data|undocumented endpoint|shadow api"),
    (
        "business_logic",
        r"business logic|negative quantity|price manipulation|coupon|race condition|workflow",
    ),
    (
        "file_handling",
        r"file upload|path traversal|directory traversal|\blfi\b|\bxxe\b|file inclusion|null byte",
    ),
    ("crypto", r"weak hash|md5|weak crypt|insecure random"),
    ("misconfiguration", r"\bcors\b|misconfig|security header|directory listing|debug|default"),
    ("info_exposure", r"exposure|exposed|disclosure|leak|stack trace|metrics"),
)


def cwe_number(value: str | int | None) -> int | None:
    if value is None:
        return None
    match = re.search(r"(\d+)", str(value))
    return int(match.group(1)) if match else None


def classify(*, cwe: str | int | None = None, title: str = "", explicit: str = "") -> str:
    """Class for a finding: an explicit class wins, then its CWE, then title keywords."""
    if explicit in CLASSES:
        return explicit
    number = cwe_number(cwe)
    if number in CWE_TO_CLASS:
        return CWE_TO_CLASS[number]
    lowered = title.lower()
    for name, pattern in _KEYWORDS:
        if re.search(pattern, lowered):
            return name
    return "unclassified"


__all__ = ["CLASSES", "CWE_TO_CLASS", "DESCRIPTIONS", "classify", "cwe_number"]
