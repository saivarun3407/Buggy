"""High-signal secret patterns: the table the JavaScript secret scanner and recon share.

``buggy.tools.research.secret_scanner`` matches these against a script and
may check a key with its issuer; the recon pipeline's recovered-source scan
(``recovered.py``) only reports where one appears, never its value. Plain
regular expressions, no network, nothing else imported.
"""

from __future__ import annotations

import re

# High-signal, low-false-positive regexes. Each entry maps a stable
# ``pattern_name`` (used both in the output and to look up a validator) to
# a compiled pattern. Patterns with a single capture group expose the bare
# secret in group 1; the rest expose it as the whole match.

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    ),
    "aws_secret_access_key": re.compile(r"(?i)aws[^\n]{0,30}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "github_fine_grained_token": re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"
    ),
    "openai_api_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "stripe_api_key": re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "gitlab_pat": re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
    "twilio_api_key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "sendgrid_api_key": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

__all__ = ["SECRET_PATTERNS"]
