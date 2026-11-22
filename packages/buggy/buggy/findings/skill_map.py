"""Which skill files fit a lead or a technology. Fixed rules, no model.

The skills live under ``buggy/skills/standard/exploit/web/hacktricks/`` and are
named ``web-<slug>``. An agent reads them with ``skill_get``. This module only
names them: it is imported where the skill files themselves are not shipped
(the capture service), and a test checks that every name here exists.

A lead's skills come from, in this order: the probe that raised it, words in
its endpoint and description, and its bug class. Technologies recon saw map to
the ``web-tech-*`` skills.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

#: The most specific skill for each Buggy probe.
PROBE_SKILLS: dict[str, tuple[str, ...]] = {
    "idor": ("web-idor",),
    "sqli": ("web-sql-injection",),
    "ssti": ("web-ssti-server-side-template-injection",),
    "command_injection": ("web-command-injection",),
    "xss_reflected": ("web-xss-cross-site-scripting",),
    "xss_stored": ("web-xss-cross-site-scripting",),
    "xss_blind": ("web-xss-cross-site-scripting",),
    "path_traversal": ("web-file-inclusion",),
    "rfi": ("web-file-inclusion",),
    "clickjacking": ("web-clickjacking",),
    "csrf": ("web-csrf-cross-site-request-forgery",),
    "ssrf_canary": ("web-ssrf-server-side-request-forgery",),
    "open_redirect": ("web-open-redirect",),
    "numeric_boundary": ("web-business-logic-vulnerabilities", "web-bypass-payment-process"),
    "mass_assignment": ("web-mass-assignment-cwe-915",),
    "graphql_checks": ("web-graphql",),
    "cors": ("web-cors-bypass",),
    "jwt_alg_none": ("web-hacking-jwt-json-web-tokens",),
}

#: Words in a lead's endpoint or description, and the skill each one points to.
WORD_SKILLS: tuple[tuple[str, str], ...] = (
    (r"reset|forgot|recover", "web-reset-password"),
    (r"2fa|mfa|otp|totp|two.?factor", "web-2fa-bypass"),
    (r"oauth|openid|oidc|authorize|callback", "web-oauth-to-account-takeover"),
    (r"saml|sso", "web-saml-attacks"),
    (r"jwt|bearer|token", "web-hacking-jwt-json-web-tokens"),
    (r"sign.?up|register|registration", "web-registration-vulnerabilities"),
    (r"log.?in|sign.?in|session", "web-login-bypass"),
    (r"captcha", "web-captcha-bypass"),
    (r"upload|attachment|avatar|import", "web-file-upload"),
    (r"graphql", "web-graphql"),
    (r"websocket|socket\.io|/ws\b", "web-websocket-attacks"),
    (r"redirect|return_?url|next=|goto", "web-open-redirect"),
    (r"webhook", "web-webhook-security"),
    (r"\.xml|soap|wsdl", "web-xxe-xee-xml-external-entity"),
    (r"checkout|payment|coupon|order|basket|cart|price", "web-bypass-payment-process"),
    (r"admin|internal|manage|console", "web-403-and-401-bypasses"),
    (r"\.env|\.git|backup|\.bak|config|swagger|api-docs", "web-exposed-files-and-secrets"),
    (r"source map|\.map\b", "web-exposed-files-and-secrets"),
    (r"bucket|s3\.|blob\.core|storage\.googleapis", "web-cloud-storage-buckets"),
    (r"cache", "web-cache-deception"),
)

#: Paths and words that name a technology; they add its ``web-tech-*`` skill.
PATH_TECH_SKILLS: tuple[tuple[str, str], ...] = (
    (r"wp-(admin|content|json|login)|xmlrpc\.php", "web-tech-wordpress"),
    (r"/actuator\b", "web-tech-spring-actuators"),
    (r"\.php\b", "web-tech-php-tricks-esp"),
    (r"\.jsp\b|\.do\b", "web-tech-jsp"),
    (r"\.aspx?\b|\.axd\b", "web-tech-iis-internet-information-services"),
    (r"/_next/", "web-tech-nextjs"),
    (r"/manager/html|/host-manager", "web-tech-tomcat"),
    (r"/console\b.*werkzeug|__debugger__", "web-tech-werkzeug"),
    (r"/swagger|/api-docs|openapi", "web-tech-swagger-openapi-ui"),
    (r"/\.git\b", "web-tech-git"),
    (r"/cgi-bin/", "web-tech-cgi"),
    (r"/debug|/admin/|/_profiler|/server-status", "web-tech-debug-and-admin-endpoints"),
)

#: Bug class -> the skills worth reading for it, most useful first.
CLASS_SKILLS: dict[str, tuple[str, ...]] = {
    "access_control": ("web-idor", "web-403-and-401-bypasses", "web-mass-assignment-cwe-915"),
    "injection": (
        "web-sql-injection",
        "web-command-injection",
        "web-ssti-server-side-template-injection",
        "web-nosql-injection",
    ),
    "xss": ("web-xss-cross-site-scripting", "web-content-security-policy-csp-bypass"),
    "file_handling": ("web-file-inclusion", "web-file-upload"),
    "misconfiguration": ("web-clickjacking", "web-cors-bypass", "web-special-http-headers"),
    "csrf": ("web-csrf-cross-site-request-forgery",),
    "ssrf": ("web-ssrf-server-side-request-forgery",),
    "open_redirect": ("web-open-redirect",),
    "business_logic": (
        "web-business-logic-vulnerabilities",
        "web-race-condition",
        "web-bypass-payment-process",
    ),
    "api": ("web-web-api-pentesting", "web-mass-assignment-cwe-915"),
    "graphql": ("web-graphql",),
    "auth_session": (
        "web-login-bypass",
        "web-hacking-jwt-json-web-tokens",
        "web-account-takeover",
        "web-hacking-with-cookies",
    ),
    "crypto": ("web-tls-transport-security", "web-hacking-jwt-json-web-tokens"),
    "info_exposure": ("web-exposed-files-and-secrets", "web-sensitive-information-exfiltration"),
}

#: Technology names as recon reports them (lower case, substring) -> skill.
TECH_SKILLS: tuple[tuple[str, str], ...] = (
    ("wordpress", "web-tech-wordpress"),
    ("drupal", "web-tech-drupal"),
    ("joomla", "web-tech-joomla"),
    ("moodle", "web-tech-moodle"),
    ("prestashop", "web-tech-prestashop"),
    ("bolt", "web-tech-bolt-cms"),
    ("dotnetnuke", "web-tech-dotnetnuke-dnn"),
    ("sitecore", "web-tech-sitecore"),
    ("sharepoint", "web-tech-microsoft-sharepoint"),
    ("adobe experience manager", "web-tech-aem-adobe-experience-cloud"),
    ("coldfusion", "web-tech-adobe-coldfusion"),
    ("jira", "web-tech-jira"),
    ("confluence", "web-tech-jira"),
    ("grafana", "web-tech-grafana"),
    ("zabbix", "web-tech-zabbix"),
    ("roundcube", "web-tech-roundcube"),
    ("rocket.chat", "web-tech-rocket-chat"),
    ("servicenow", "web-tech-servicenow"),
    ("salesforce", "web-tech-salesforce"),
    ("artifactory", "web-tech-artifactory-hacking-guide"),
    ("proxmox", "web-tech-proxmox-ve"),
    ("vmware", "web-tech-vmware-esx-vcenter"),
    ("citrix", "web-tech-citrix-netscaler"),
    ("netscaler", "web-tech-citrix-netscaler"),
    ("fortiweb", "web-tech-fortinet-fortiweb"),
    ("traefik", "web-tech-traefik"),
    ("nginx", "web-tech-nginx"),
    ("apache tomcat", "web-tech-tomcat"),
    ("tomcat", "web-tech-tomcat"),
    ("jboss", "web-tech-jboss"),
    ("wildfly", "web-tech-jboss"),
    ("apache", "web-tech-apache"),
    ("iis", "web-tech-iis-internet-information-services"),
    ("asp.net", "web-tech-iis-internet-information-services"),
    ("telerik", "web-tech-telerik-ui-aspnet-ajax-unsafe-reflection-webresource-axd"),
    ("php", "web-tech-php-tricks-esp"),
    ("laravel", "web-tech-laravel"),
    ("symfony", "web-tech-symphony"),
    ("ruby", "web-tech-ruby-tricks"),
    ("rails", "web-tech-ruby-tricks"),
    ("perl", "web-tech-perl-tricks"),
    ("django", "web-tech-django"),
    ("flask", "web-tech-flask"),
    ("werkzeug", "web-tech-werkzeug"),
    ("gunicorn", "web-tech-wsgi"),
    ("uwsgi", "web-tech-wsgi"),
    ("express", "web-tech-nodejs-express"),
    ("node.js", "web-tech-nodejs-express"),
    ("next.js", "web-tech-nextjs"),
    ("nuxt", "web-tech-ssr-meta-frameworks"),
    ("sveltekit", "web-tech-ssr-meta-frameworks"),
    ("angular", "web-tech-angular"),
    ("react", "web-tech-react"),
    ("vue", "web-tech-vuejs"),
    ("spring", "web-tech-spring-actuators"),
    ("java", "web-tech-jsp"),
    ("cloudflare", "web-tech-uncovering-cloudflare"),
    ("supabase", "web-tech-supabase-postgrest"),
    ("postgrest", "web-tech-supabase-postgrest"),
    ("firebase", "web-firebase-realtime-database"),
    ("swagger", "web-tech-swagger-openapi-ui"),
    ("imagemagick", "web-tech-imagemagick-security"),
    ("geonetwork", "web-tech-geonetwork"),
    ("ispconfig", "web-tech-ispconfig"),
    ("meshcentral", "web-tech-meshcentral"),
    ("zoneminder", "web-tech-zoneminder-motioneye-motion"),
    ("motioneye", "web-tech-zoneminder-motioneye-motion"),
    ("veeam", "web-tech-veeam-service-provider-console"),
    ("beyondtrust", "web-tech-beyondtrust-remote-support-mrs-origin-spoofing"),
    ("tapestry", "web-tech-apache-tapestry"),
    ("h2 console", "web-tech-h2-java-sql-database"),
)

#: The index skill, offered when nothing more specific fits.
INDEX = "web-web-vulnerabilities-methodology"
MAX_SKILLS = 4

_WORDS = [(re.compile(p, re.IGNORECASE), s) for p, s in WORD_SKILLS]
_PATHS = [(re.compile(p, re.IGNORECASE), s) for p, s in PATH_TECH_SKILLS]


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def for_lead(lead: Mapping[str, Any]) -> list[str]:
    """The skills to read before working one lead, most specific first (at most four)."""
    found: list[str] = []
    source = _text(lead.get("source"))
    probe = source.split(":", 1)[1] if source.startswith("probe:") else _text(lead.get("probe"))
    found += PROBE_SKILLS.get(probe, ())
    where = f"{_text(lead.get('endpoint'))} {_text(lead.get('parameter'))}"
    words = f"{where} {_text(lead.get('title'))} {_text(lead.get('description'))}"
    found += [skill for pattern, skill in _WORDS if pattern.search(words)]
    found += [skill for pattern, skill in _PATHS if pattern.search(where)]
    cls = _text(lead.get("vuln_class")) or _text(lead.get("class"))
    found += CLASS_SKILLS.get(cls, ())
    unique = list(dict.fromkeys(found))[:MAX_SKILLS]
    return unique or [INDEX]


def for_class(vuln_class: str) -> list[str]:
    """Every skill that counts as "read for this class" (the class list plus its probes' skills)."""
    names = list(CLASS_SKILLS.get(vuln_class, ()))
    return list(dict.fromkeys(names))


def for_technologies(names: Iterable[str]) -> list[str]:
    """The ``web-tech-*`` skills for technology names recon reported (``Nginx:1.25``, ``WordPress``)."""
    found: list[str] = []
    for name in names:
        lowered = str(name).lower().split(":", 1)[0]
        for needle, skill in TECH_SKILLS:
            if needle in lowered:
                found.append(skill)
                break
    return list(dict.fromkeys(found))


def all_names() -> set[str]:
    """Every skill name this module can hand out (for the test that they all exist)."""
    names = {INDEX}
    for skills in (*PROBE_SKILLS.values(), *CLASS_SKILLS.values()):
        names.update(skills)
    names.update(skill for _p, skill in (*WORD_SKILLS, *PATH_TECH_SKILLS, *TECH_SKILLS))
    return names


__all__ = [
    "CLASS_SKILLS",
    "INDEX",
    "PROBE_SKILLS",
    "TECH_SKILLS",
    "all_names",
    "for_class",
    "for_lead",
    "for_technologies",
]
