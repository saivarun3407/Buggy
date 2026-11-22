"""Accounts Buggy creates itself, when the operator turns it on.

Registering an account changes the target, so it is a state-changing action and
stays off unless the operator writes the switch into the engagement's scope
document (``machine_enforcement.account_creation``). That written switch is the
approval: it covers only the registration and login requests of the accounts
Buggy creates, and each such request is recorded for what it is
(``approval_id = "account_creation"``, bodies redacted).

Everything here is deterministic; no model is used.

* :func:`account_creation_policy` reads the switch.
* :func:`find_signup` / :func:`find_login` recognise the sign-up and login of a
  target from an anonymous :func:`buggy.capture.crawl.crawl` and from
  recon-shaped JSON API operations. They never guess: a thing that makes
  automation impossible (a CAPTCHA, SSO only, an unknown required field, an
  email-verification wall) stops the run with a named reason.
* :func:`api_signup_candidates` / :func:`api_login_candidates` cover single-page
  applications that have no HTML form: a few JSON endpoints recon found
  (``/api/Users``, ``/rest/user/login``), each tried once. The account's own
  identifiers in the answers (its user id, its basket id) are kept for the
  user walk (:mod:`buggy.capture.journey`).
* :func:`provision` registers up to ``max_accounts`` accounts through the
  gateway's account-creation exemption, logs each in, builds a working
  ``static`` identity from the session, and stores the accounts in a
  gateway-owned file the agents cannot read, plus a copy for the operator.

Passwords are generated with :mod:`secrets` and never leave the gateway process
in any tool result.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlsplit

from buggy.capture import crawl
from buggy.capture.gateway import AccountGrant, CaptureGateway, GatewayRefusal
from buggy.capture.store import Capture
from buggy.pipeline.tools import apirecon

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

# ── stop reasons (constants, never a guess) ─────────────────────────
CAPTCHA = "CAPTCHA"
SSO_ONLY = "SSO_ONLY"
UNKNOWN_REQUIRED_FIELD = "UNKNOWN_REQUIRED_FIELD"
EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
NO_SIGNUP_FOUND = "NO_SIGNUP_FOUND"
REGISTRATION_REFUSED = "REGISTRATION_REFUSED"
LOGIN_FAILED = "LOGIN_FAILED"
NOT_ENABLED = "NOT_ENABLED"
#: An account Buggy prepared exists on paper only: a person has to finish its
#: sign-up (a CAPTCHA, an email link), after which Buggy signs in with it.
WAITING_FOR_OPERATOR = "WAITING_FOR_OPERATOR"

MAX_ACCOUNTS = 3
DEFAULT_MAX_ACCOUNTS = 2
TAG_BYTES = 4  # 8 lowercase hex characters
PASSWORD_LENGTH = 24

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TAG = "{tag}"

# Field roles.
EMAIL = "email"
USERNAME = "username"
PASSWORD = "password"
PASSWORD_CONFIRM = "password_confirm"
NAME = "name"
FIRST_NAME = "first_name"
LAST_NAME = "last_name"
TERMS = "terms"
OTHER = "other"

_PASSWORD_NAME = re.compile(r"(?<![a-z0-9])(?:password|passwd|pwd|pass)(?![a-z0-9])", re.IGNORECASE)
_CONFIRM_NAME = re.compile(
    r"(?<![a-z0-9])(?:confirm|verify|repeat|retype|re[-_ ]?enter|again|second)(?![a-z0-9])",
    re.IGNORECASE,
)
_EMAIL_NAME = re.compile(r"(?<![a-z0-9])(?:e[-_ ]?mail|email)(?![a-z0-9])", re.IGNORECASE)
_USERNAME_NAME = re.compile(
    r"(?<![a-z0-9])(?:username|user[-_ ]?name|userid|user[-_ ]?id|login|handle|nick(?:name)?|user|account)(?![a-z0-9])",
    re.IGNORECASE,
)
_FIRST_NAME = re.compile(
    r"(?<![a-z0-9])(?:first[-_ ]?name|fname|given[-_ ]?name|forename)(?![a-z0-9])", re.IGNORECASE
)
_LAST_NAME = re.compile(
    r"(?<![a-z0-9])(?:last[-_ ]?name|lname|surname|family[-_ ]?name)(?![a-z0-9])", re.IGNORECASE
)
_FULL_NAME = re.compile(
    r"(?<![a-z0-9])(?:full[-_ ]?name|display[-_ ]?name|name|realname)(?![a-z0-9])", re.IGNORECASE
)
_TERMS_NAME = re.compile(
    r"(?<![a-z0-9])(?:terms|tos|agree|accept|consent|privacy|policy|eula)(?![a-z0-9])",
    re.IGNORECASE,
)
_CAPTCHA_NAME = re.compile(
    r"(?<![a-z0-9])(?:captcha|recaptcha|h[-_]?captcha|turnstile)", re.IGNORECASE
)

_REGISTER_WORDS = (
    r"register",
    r"sign[-_ ]?up",
    r"signup",
    r"join",
    r"create[-_ ]?account",
    r"newuser",
    r"new[-_ ]?user",
)
_LOGIN_WORDS = (
    r"log[-_ ]?in",
    r"login",
    r"sign[-_ ]?in",
    r"signin",
    r"authenticate",
    r"session",
    r"token",
    r"auth",
)
_SIGNUP_PATH = (r"register", r"sign[-_ ]?up", r"signup", r"users?", r"accounts?", r"join")
_LOGIN_PATH = (r"log[-_ ]?in", r"login", r"sign[-_ ]?in", r"signin", r"auth", r"session", r"token")
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")

_CAPTCHA_MARKERS = (
    "g-recaptcha",
    "h-captcha",
    "hcaptcha",
    "cf-turnstile",
    "grecaptcha",
    "data-sitekey",
)
_SSO_MARKERS = (
    "oauth", "saml", "openid", "sso", "single sign", "continue with", "sign in with",
    "sign up with", "log in with", "/auth/google", "/auth/github", "/oauth",
)  # fmt: skip
_VERIFY_MARKERS = (
    "verify your email",
    "confirm your email",
    "verification email",
    "check your inbox",
    "confirm your account",
    "email verification",
    "activate your account",
)
_TOKEN_KEYS = (
    "token",
    "access_token",
    "accesstoken",
    "jwt",
    "id_token",
    "idtoken",
    "auth_token",
    "authtoken",
    "session_token",
)


#: Fields never sent at sign-up, whatever the form or the API description says:
#: setting one's own role or privileges is not what a normal user does.
_FORBIDDEN_FIELD = re.compile(
    r"(?<![a-z0-9])(?:roles?|admin|is[-_ ]?admin|super[-_ ]?user|is[-_ ]?staff|staff|"
    r"permissions?|privileges?|access[-_ ]?level|user[-_ ]?type)(?![a-z0-9])",
    re.IGNORECASE,
)
#: Confirmation fields sent at an API sign-up that no API description documents.
_API_CONFIRM_FIELDS = (
    "passwordRepeat",
    "password_confirmation",
    "confirmPassword",
    "repeatPassword",
)
#: Last path segments of an API sign-up and of an API login.
_SIGNUP_WORDS = frozenset({"register", "registration", "signup", "sign-up", "sign_up"})
_SIGNUP_COLLECTIONS = frozenset({"users", "accounts"})
_LOGIN_SEGMENTS = frozenset(
    {"login", "log-in", "signin", "sign-in", "sign_in", "authenticate", "session", "sessions"}
)
#: Path segments that make a URL an API URL even without an ``/api`` root.
_API_SEGMENTS = frozenset({"api", "apis", "rest", "auth", "graphql", "rpc"})
#: How many API sign-up and login endpoints are tried, one request each.
MAX_API_CANDIDATES = 3


def _word(words: tuple[str, ...]) -> re.Pattern[str]:
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(words) + r")(?![a-z0-9])", re.IGNORECASE)


_REGISTER = _word(_REGISTER_WORDS)
_LOGIN = _word(_LOGIN_WORDS)
_SIGNUP_PATH_RE = _word(_SIGNUP_PATH)
_LOGIN_PATH_RE = _word(_LOGIN_PATH)


class AccountPolicyError(ValueError):
    """The ``account_creation`` block in the scope document is malformed."""


@dataclass(frozen=True, slots=True)
class AccountPolicy:
    """The operator's switch: how Buggy may create accounts for the engagement."""

    email_template: str
    max_accounts: int = DEFAULT_MAX_ACCOUNTS

    def email_for(self, tag: str) -> str:
        return self.email_template.replace(_TAG, tag)


@dataclass(frozen=True, slots=True)
class Field:
    """One field of a sign-up or login, with the role deterministic rules give it."""

    name: str
    role: str
    value: str = ""


@dataclass(frozen=True, slots=True)
class Signup:
    """A recognised sign-up (``form``) or registration/login API (``json``)."""

    kind: str  # "form" | "json"
    method: str
    url: str  # where the registration or login is submitted
    page: str  # the HTML page to re-fetch for fresh hidden values (forms); == url for json
    fields: tuple[Field, ...]
    hidden: dict[str, str] = field(default_factory=dict)

    def role_names(self, role: str) -> list[str]:
        return [f.name for f in self.fields if f.role == role]

    def summary(self) -> dict[str, str]:
        return {"kind": self.kind, "url": self.url}


_GUESSED_SIGNUP_FIELDS: tuple[Field, ...] = (
    Field("email", EMAIL),
    Field("password", PASSWORD),
    *(Field(name, PASSWORD_CONFIRM) for name in _API_CONFIRM_FIELDS),
    Field("username", USERNAME),
    Field("name", NAME),
)
_GUESSED_LOGIN_FIELDS: tuple[Field, ...] = (Field("email", EMAIL), Field("password", PASSWORD))


@dataclass(slots=True)
class _Choice:
    """Endpoints to try in order; the first that works is kept for the next accounts."""

    candidates: list[Signup]
    exhausted: tuple[str, str] | None = None

    @property
    def first(self) -> Signup | None:
        return self.candidates[0] if self.candidates else None

    def pin(self, chosen: Signup) -> None:
        self.candidates = [chosen]

    def urls(self) -> list[str]:
        return [candidate.url for candidate in self.candidates]


# ── the switch ──────────────────────────────────────────────────────


def account_creation_policy(document: Any) -> AccountPolicy | None:
    """The engagement's account-creation switch, or ``None`` when absent or off.

    Reads ``machine_enforcement.account_creation``::

        {"enabled": true, "email_template": "<local>+{tag}@<domain>", "max_accounts": 2}

    Returns ``None`` when the block is absent or ``enabled`` is not true. Raises
    :class:`AccountPolicyError` on a malformed block (a bad template, an
    out-of-range ``max_accounts``), so a typo cannot silently disable the switch.
    """
    if not isinstance(document, dict):
        return None
    enforcement = document.get("machine_enforcement")
    if not isinstance(enforcement, dict):
        return None
    block = enforcement.get("account_creation")
    if block is None:
        return None
    if not isinstance(block, dict):
        raise AccountPolicyError("account_creation must be a JSON object")
    enabled = block.get("enabled", False)
    if not isinstance(enabled, bool):
        raise AccountPolicyError("account_creation.enabled must be a boolean")
    if not enabled:
        return None
    template = block.get("email_template")
    if not isinstance(template, str) or not template:
        raise AccountPolicyError("account_creation.email_template is required when enabled")
    if _TAG not in template:
        raise AccountPolicyError("account_creation.email_template must contain '{tag}'")
    probe = template.replace(_TAG, "tag12345")
    if not _EMAIL.match(probe):
        raise AccountPolicyError("account_creation.email_template must look like an email address")
    max_accounts = block.get("max_accounts", DEFAULT_MAX_ACCOUNTS)
    if isinstance(max_accounts, bool) or not isinstance(max_accounts, int):
        raise AccountPolicyError("account_creation.max_accounts must be an integer")
    if not 1 <= max_accounts <= MAX_ACCOUNTS:
        raise AccountPolicyError(f"account_creation.max_accounts must be 1-{MAX_ACCOUNTS}")
    allowed = {"enabled", "email_template", "max_accounts"}
    for key in block:
        if key not in allowed:
            raise AccountPolicyError(f"account_creation has an unknown field {key!r}")
    return AccountPolicy(email_template=template, max_accounts=max_accounts)


# ── recognising sign-up and login ───────────────────────────────────


def _field_type(raw: Any) -> str:
    return str(raw.get("type") or "").lower() if isinstance(raw, dict) else ""


def _role_of(name: str, kind: str, *, seen_password: bool) -> str:
    """The role of a field, from its name and input type. ``kind`` is the HTML type."""
    words = _CAMEL.sub(r"\1 \2", name)
    is_password = kind == "password" or bool(_PASSWORD_NAME.search(words))
    if is_password and (seen_password or _CONFIRM_NAME.search(words)):
        return PASSWORD_CONFIRM
    if is_password:
        return PASSWORD
    if kind == "email" or _EMAIL_NAME.search(words):
        return EMAIL
    if _FIRST_NAME.search(words):
        return FIRST_NAME
    if _LAST_NAME.search(words):
        return LAST_NAME
    if _USERNAME_NAME.search(words):
        return USERNAME
    if _FULL_NAME.search(words):
        return NAME
    if _TERMS_NAME.search(words) or (kind == "checkbox" and _TERMS_NAME.search(words)):
        return TERMS
    return OTHER


def _form_fields(raw_fields: Any) -> tuple[list[Field], dict[str, str]]:
    """Visible fields with roles, and hidden fields (name -> default value)."""
    fields: list[Field] = []
    hidden: dict[str, str] = {}
    seen_password = False
    for item in raw_fields or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name:
            continue
        kind = _field_type(item)
        value = str(item.get("value") or "")
        if kind == "hidden":
            hidden[name] = value
            continue
        if kind in ("submit", "button", "image", "reset"):
            continue
        role = _role_of(name, kind, seen_password=seen_password)
        if role in (PASSWORD, PASSWORD_CONFIRM):
            seen_password = True
        fields.append(Field(name=name, role=role, value=value))
    return fields, hidden


def _api_fields(body_fields: Any) -> list[Field]:
    fields: list[Field] = []
    seen_password = False
    for item in body_fields or []:
        name = str(item.get("name")) if isinstance(item, dict) else str(item)
        if not name:
            continue
        role = _role_of(name, "", seen_password=seen_password)
        if role in (PASSWORD, PASSWORD_CONFIRM):
            seen_password = True
        fields.append(Field(name=name, role=role))
    return fields


def _roles(fields: Sequence[Field]) -> set[str]:
    return {f.role for f in fields}


def _has_credential_pair(fields: Sequence[Field]) -> bool:
    roles = _roles(fields)
    return PASSWORD in roles and bool(roles & {EMAIL, USERNAME})


def _form_signal_text(form: dict[str, Any]) -> str:
    """Action, page and submit-button labels of a form, camelCase split into words."""
    pieces = [str(form.get("action") or ""), str(form.get("page") or "")]
    for item in form.get("fields") or []:
        if isinstance(item, dict) and _field_type(item) in ("submit", "button", "image"):
            pieces.append(str(item.get("value") or ""))
    return _CAMEL.sub(r"\1 \2", " ".join(pieces)).replace("_", " ")


def _api_text(operation: dict[str, Any]) -> str:
    url = str(operation.get("url") or "")
    parts = urlsplit(url)
    return _CAMEL.sub(r"\1 \2", f"{parts.path} {parts.query}").replace("_", " ")


def find_signup(crawl_result: Any, api_operations: Iterable[Any] = ()) -> Signup | None:
    """The target's sign-up, recognised deterministically, or ``None``.

    An HTML form (from an anonymous crawl) is a sign-up when it has a password
    field and an email or username field, and its action, page URL or submit
    label says register / sign up / signup / join / create account, or it
    carries a password-confirmation field. A form that only says login/signin
    and has no confirmation field is a login, not a sign-up. A form with a
    confirmation field is preferred. Failing a form, a JSON API operation whose
    path names users/register/signup/accounts and whose body has a password and
    an email or username is used.
    """
    forms = crawl_result.get("forms") if isinstance(crawl_result, dict) else None
    best: Signup | None = None
    best_has_confirm = False
    for form in forms or []:
        if not isinstance(form, dict):
            continue
        fields, hidden = _form_fields(form.get("fields"))
        if not _has_credential_pair(fields):
            continue
        has_confirm = PASSWORD_CONFIRM in _roles(fields)
        text = _form_signal_text(form)
        register = bool(_REGISTER.search(text))
        login = bool(_LOGIN.search(text))
        if not register and not has_confirm:
            continue  # a bare login form, or no sign-up signal at all
        if login and not register and not has_confirm:
            continue
        action = str(form.get("action") or "")
        page = str(form.get("page") or action)
        candidate = Signup(
            kind="form",
            method=str(form.get("method") or "POST").upper(),
            url=action or page,
            page=page,
            fields=tuple(fields),
            hidden=hidden,
        )
        if best is None or (has_confirm and not best_has_confirm):
            best, best_has_confirm = candidate, has_confirm
    if best is not None:
        return best
    for operation in api_operations or []:
        if not isinstance(operation, dict):
            continue
        if str(operation.get("method") or "").upper() not in ("POST", "PUT"):
            continue
        if not _SIGNUP_PATH_RE.search(_api_text(operation)):
            continue
        fields = _api_fields(operation.get("body_fields"))
        if not _has_credential_pair(fields):
            continue
        url = str(operation.get("url") or "")
        if not url:
            continue
        return Signup(
            kind="json",
            method=str(operation["method"]).upper(),
            url=url,
            page=url,
            fields=tuple(fields),
        )
    return None


def find_login(crawl_result: Any, api_operations: Iterable[Any] = ()) -> Signup | None:
    """The target's login, recognised the same deterministic way, or ``None``.

    A login has a password field and an email or username field, no
    confirmation field, and a login/signin signal (not a register signal).
    """
    forms = crawl_result.get("forms") if isinstance(crawl_result, dict) else None
    for form in forms or []:
        if not isinstance(form, dict):
            continue
        fields, hidden = _form_fields(form.get("fields"))
        if not _has_credential_pair(fields) or PASSWORD_CONFIRM in _roles(fields):
            continue
        text = _form_signal_text(form)
        if not _LOGIN.search(text) or _REGISTER.search(text):
            continue
        action = str(form.get("action") or "")
        page = str(form.get("page") or action)
        return Signup(
            kind="form",
            method=str(form.get("method") or "POST").upper(),
            url=action or page,
            page=page,
            fields=tuple(fields),
            hidden=hidden,
        )
    for operation in api_operations or []:
        if not isinstance(operation, dict):
            continue
        if str(operation.get("method") or "").upper() not in ("POST", "PUT"):
            continue
        if not _LOGIN_PATH_RE.search(_api_text(operation)):
            continue
        fields = _api_fields(operation.get("body_fields"))
        if not _has_credential_pair(fields) or PASSWORD_CONFIRM in _roles(fields):
            continue
        url = str(operation.get("url") or "")
        if not url:
            continue
        return Signup(
            kind="json",
            method=str(operation["method"]).upper(),
            url=url,
            page=url,
            fields=tuple(fields),
        )
    return None


# ── sign-up and login of an API (single-page applications) ─────────


def _last_segment(url: str) -> str:
    try:
        path = urlsplit(url).path
    except ValueError:
        return ""
    return path.rstrip("/").rsplit("/", 1)[-1].lower()


def _api_like(url: str, bases: Sequence[str] = ()) -> bool:
    """Whether a URL is an API URL: under an API root recon found, or with an api/rest/auth segment."""
    if apirecon.api_root(url) or any(
        base and url.startswith(base.rstrip("/") + "/") for base in bases
    ):
        return True
    try:
        segments = urlsplit(url).path.lower().split("/")
    except ValueError:
        return False
    return any(segment in _API_SEGMENTS for segment in segments)


def _requestable(url: str) -> bool:
    return (
        isinstance(url, str)
        and url.startswith(("http://", "https://"))
        and not apirecon.is_template(url)
        and not crawl.never_request_reason(url)
    )


def _record_attrs(record: Any) -> dict[str, Any]:
    raw = record.get("attrs") if isinstance(record, dict) else None
    return raw if isinstance(raw, dict) else {}


def api_surface(records: Any) -> dict[str, list[Any]]:
    """What recon knows about sign-up and login of an API, small enough to pass to the gateway.

    ``records`` maps a record type to the recon records (``auth_surface``,
    ``api_base``, ``endpoint``, ``api_profile``, ``api_operation``). Returns
    ``{"signup": [url], "login": [url], "api_bases": [url], "operations":
    [{"method", "url", "body_fields"}]}``: the sign-in pages recon named, the
    endpoints whose last path segment names a sign-up or a login, and the
    write operations an API description documents.
    """
    records = records if isinstance(records, dict) else {}
    signup: dict[str, None] = {}
    login: dict[str, None] = {}
    for record in records.get("auth_surface") or []:
        url = str(record.get("value") or "") if isinstance(record, dict) else ""
        kind = _record_attrs(record).get("kind")
        if kind == "signup" and _requestable(url):
            signup.setdefault(url.split("#", 1)[0])
        elif kind == "login" and _requestable(url):
            login.setdefault(url.split("#", 1)[0])
    endpoints: list[str] = []
    for kind in ("endpoint", "url"):
        for record in records.get(kind) or []:
            if isinstance(record, dict) and isinstance(record.get("value"), str):
                endpoints.append(record["value"])
    for record in records.get("api_profile") or []:
        url = _record_attrs(record).get("url")
        if isinstance(url, str) and _record_attrs(record).get("status") not in (404, 410):
            endpoints.append(url)
    for raw in endpoints:
        url = raw.split("#", 1)[0].split("?", 1)[0]
        if not _requestable(url):
            continue
        last = _last_segment(url)
        if last in _SIGNUP_WORDS or last in _SIGNUP_COLLECTIONS:
            signup.setdefault(url)
        elif last in _LOGIN_SEGMENTS:
            login.setdefault(url)
    bases = [
        str(r.get("value"))
        for r in records.get("api_base") or []
        if isinstance(r, dict) and isinstance(r.get("value"), str)
    ]
    operations: list[dict[str, Any]] = []
    for record in records.get("api_operation") or []:
        attrs = _record_attrs(record)
        method, url = str(attrs.get("method") or "").upper(), str(attrs.get("url") or "")
        fields = attrs.get("request_body_properties")
        if method in ("POST", "PUT") and url and isinstance(fields, list) and fields:
            operations.append(
                {"method": method, "url": url, "body_fields": [str(f) for f in fields][:50]}
            )
    return {
        "signup": list(signup)[:50],
        "login": list(login)[:50],
        "api_bases": bases[:50],
        "operations": operations[:200],
    }


def _surface_urls(surface: Any, key: str) -> list[str]:
    values = surface.get(key) if isinstance(surface, dict) else None
    return [v for v in values or [] if isinstance(v, str) and _requestable(v)]


def _json_endpoint(url: str, fields: tuple[Field, ...]) -> Signup:
    return Signup(kind="json", method="POST", url=url, page=url, fields=fields)


def api_signup_candidates(surface: Any) -> list[Signup]:
    """JSON sign-up endpoints to try, best first, at most :data:`MAX_API_CANDIDATES`.

    An endpoint under an API root whose path ends in a sign-up word
    (``/register``, ``/signup``) comes first, then one that ends in a
    collection of users (``/users``, ``/accounts``), then a sign-up page recon
    named that is not an API URL. The body sent is the account's email, a
    password and its usual confirmation fields, a user name and a name.
    """
    bases = _surface_urls(surface, "api_bases")
    ranked: list[tuple[int, int, str]] = []
    for index, url in enumerate(dict.fromkeys(_surface_urls(surface, "signup"))):
        last = _last_segment(url)
        if _api_like(url, bases):
            rank = 0 if last in _SIGNUP_WORDS else 1 if last in _SIGNUP_COLLECTIONS else 2
        elif last in _SIGNUP_COLLECTIONS:
            continue  # a page named /users that is not an API is a listing, not a sign-up
        else:
            rank = 3
        ranked.append((rank, index, url))
    ranked.sort()
    return [_json_endpoint(url, _GUESSED_SIGNUP_FIELDS) for _r, _i, url in ranked][
        :MAX_API_CANDIDATES
    ]


def api_login_candidates(surface: Any) -> list[Signup]:
    """JSON login endpoints to try (``/rest/user/login``, ``/api/login``, ``/auth/login``).

    Only API URLs: an HTML login page answers a JSON body with the page.
    At most :data:`MAX_API_CANDIDATES`; the body is the email and the password.
    """
    bases = _surface_urls(surface, "api_bases")
    ranked: list[tuple[int, int, str]] = []
    for index, url in enumerate(dict.fromkeys(_surface_urls(surface, "login"))):
        if not _api_like(url, bases):
            continue
        last = _last_segment(url)
        ranked.append((0 if last in ("login", "signin", "sign-in", "log-in") else 1, index, url))
    ranked.sort()
    return [_json_endpoint(url, _GUESSED_LOGIN_FIELDS) for _r, _i, url in ranked][
        :MAX_API_CANDIDATES
    ]


# ── generated credentials ───────────────────────────────────────────


def _strong_password() -> str:
    classes = (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*-_=+")
    chars = [secrets.choice(group) for group in classes]
    pool = "".join(classes)
    chars += [secrets.choice(pool) for _ in range(PASSWORD_LENGTH - len(classes))]
    # Shuffle without bias so the leading class order is not fixed.
    for index in range(len(chars) - 1, 0, -1):
        swap = secrets.randbelow(index + 1)
        chars[index], chars[swap] = chars[swap], chars[index]
    return "".join(chars)


@dataclass(slots=True)
class _Account:
    name: str
    email: str
    username: str
    password: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    #: Identifiers the target handed to this account as its own (``crawl.json_ids``).
    own_ids: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def stored(cls, name: str, entry: dict[str, Any]) -> _Account:
        ids = entry.get("own_ids")
        return cls(
            name=name,
            email=str(entry.get("email") or ""),
            username=str(entry.get("username") or ""),
            password=str(entry.get("password") or ""),
            own_ids=[i for i in ids if isinstance(i, dict)] if isinstance(ids, list) else [],
        )

    def learn_ids(self, capture: Capture, url: str) -> None:
        """Keep the identifiers an answer gives as the account's own (its user id, its basket id)."""
        try:
            document = json.loads(capture.response_body.decode("utf-8", "replace"))
        except ValueError:
            return
        words = [w.lower() for w in urlsplit(url).path.split("/") if w]
        known = {(i.get("key"), i.get("value")) for i in self.own_ids}
        for found in crawl.json_ids(document, [self.email, self.username], context=words):
            if found["own"] and (found["key"], found["value"]) not in known:
                known.add((found["key"], found["value"]))
                self.own_ids.append(found)
        del self.own_ids[50:]

    def identity_def(self) -> dict[str, Any]:
        static: dict[str, Any] = {}
        if self.headers:
            static["headers"] = dict(self.headers)
        if self.cookies:
            static["cookies"] = dict(self.cookies)
        return {
            "name": self.name,
            "role": "auto",
            "markers": [self.email, self.username],
            "static": static,
        }

    def record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "email": self.email,
            "username": self.username,
            "password": self.password,
            "identity": self.identity_def(),
            "own_ids": list(self.own_ids),
        }

    def has_session(self) -> bool:
        return bool(self.headers or self.cookies)


# ── reading responses inside the gateway process ────────────────────


def _set_cookies(capture: Capture) -> dict[str, str]:
    """Session cookies from a capture's Set-Cookie (real headers, in-process)."""
    jar: dict[str, str] = {}
    for key, value in capture.response_headers.items():
        if key.lower() != "set-cookie":
            continue
        for line in value.split("\n"):
            pair = line.split(";", 1)[0]
            name, _, cookie_value = pair.partition("=")
            if name.strip() and cookie_value.strip():
                jar[name.strip()] = cookie_value.strip()
    return jar


def _find_token(document: Any, depth: int = 0) -> str:
    """A bearer token from a JSON body: token / access_token / jwt / id_token, nested."""
    if depth > 6 or not isinstance(document, dict):
        return ""
    for key, value in document.items():
        if str(key).lower().replace("-", "_") in _TOKEN_KEYS and isinstance(value, str) and value:
            return value
    for value in document.values():
        if isinstance(value, dict):
            found = _find_token(value, depth + 1)
            if found:
                return found
    return ""


def _session_from(capture: Capture) -> tuple[dict[str, str], dict[str, str]]:
    """The headers and cookies to carry a session that a response handed out."""
    cookies = _set_cookies(capture)
    headers: dict[str, str] = {}
    try:
        document = json.loads(capture.response_body.decode("utf-8", "replace"))
    except ValueError:
        document = None
    token = _find_token(document)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers, cookies


def _content_type(capture: Capture) -> str:
    for key, value in capture.response_headers.items():
        if key.lower() == "content-type":
            return str(value).lower()
    return ""


def _response_text(capture: Capture) -> str:
    return capture.response_body.decode("utf-8", "replace")


# ── blockers on the sign-up page ────────────────────────────────────


def _signup_blocker(signup: Signup, page_body: str) -> tuple[str, str]:
    """A named stop reason for a found sign-up, or ``("", "")`` when automatable."""
    body = page_body.lower()
    if any(marker in body for marker in _CAPTCHA_MARKERS):
        return CAPTCHA, "the sign-up page carries a CAPTCHA widget"
    for field_ in signup.fields:
        if _CAPTCHA_NAME.search(field_.name):
            return CAPTCHA, f"the sign-up has a CAPTCHA field {field_.name!r}"
    for field_ in signup.fields:
        if _forbidden(field_.name) or signup.kind == "json":
            # Never sent; and a JSON API's description lists optional
            # properties too, so an unknown one there is left out, not a stop.
            continue
        if field_.role == OTHER and not field_.value.strip():
            return (
                UNKNOWN_REQUIRED_FIELD,
                f"the sign-up has a field {field_.name!r} with no known role and no default value",
            )
    return "", ""


def _sso_only(page_body: str) -> bool:
    body = page_body.lower()
    has_password = 'type="password"' in body or "type='password'" in body
    return not has_password and any(marker in body for marker in _SSO_MARKERS)


def _email_verification(capture: Capture) -> bool:
    text = _response_text(capture).lower()
    return any(marker in text for marker in _VERIFY_MARKERS)


def _forbidden(name: str) -> bool:
    """Whether a field sets a role or a privilege: it is never sent."""
    return bool(_FORBIDDEN_FIELD.search(_CAMEL.sub(r"\1 \2", name).replace("_", " ")))


def _is_html(capture: Capture) -> bool:
    kind = _content_type(capture)
    return "html" in kind or _response_text(capture)[:200].lstrip().lower().startswith("<!doctype")


def _api_ok(capture: Capture) -> bool:
    """A JSON endpoint accepted the request: 2xx, and not an HTML page (a single-page
    application answers every path with its page)."""
    status = capture.status
    return (
        not capture.error and status is not None and 200 <= status < 300 and not _is_html(capture)
    )


# ── gateway-owned storage (agents cannot read it) ───────────────────


def _write_private(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def _accounts_path(gateway: CaptureGateway, engagement: str) -> Path:
    return gateway.roots.data / "accounts" / f"{engagement}.json"


def _operator_path(gateway: CaptureGateway, engagement: str) -> Path:
    return gateway.roots.audit / engagement / "accounts-created.json"


def _load_existing(gateway: CaptureGateway, engagement: str) -> dict[str, dict[str, Any]]:
    path = _accounts_path(gateway, engagement)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for entry in document.get("accounts", []) if isinstance(document, dict) else []:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            out[entry["name"]] = entry
    return out


def _store_accounts(
    gateway: CaptureGateway, engagement: str, accounts: Sequence[dict[str, Any]]
) -> None:
    payload = {"engagement": engagement, "accounts": list(accounts)}
    _write_private(_accounts_path(gateway, engagement), payload)
    _write_private(_operator_path(gateway, engagement), payload)


# ── provisioning ────────────────────────────────────────────────────


def _value_for(field_: Field, account: _Account) -> str | None:
    """What to send for one field, or ``None`` to omit it."""
    role, tag = field_.role, account.username
    if _forbidden(field_.name):
        return None
    if role == EMAIL:
        return account.email
    if role == USERNAME:
        return account.username
    if role in (PASSWORD, PASSWORD_CONFIRM):
        return account.password
    if role == NAME:
        return f"Test {tag}"
    if role == FIRST_NAME:
        return "Test"
    if role == LAST_NAME:
        return tag
    if role == TERMS:
        return "on"
    if role == OTHER:
        return field_.value or None
    return None


def _build_body(
    signup: Signup, account: _Account, hidden: dict[str, str]
) -> tuple[str, dict[str, str]]:
    """The request body and content-type header for a registration or login."""
    if signup.kind == "json":
        payload: dict[str, Any] = {}
        for field_ in signup.fields:
            value = _value_for(field_, account)
            if value is not None:
                payload[field_.name] = True if field_.role == TERMS else value
        return json.dumps(payload), {"Content-Type": "application/json"}
    pairs: list[tuple[str, str]] = []
    for name, value in hidden.items():
        if not _forbidden(name):
            pairs.append((name, value))
    for field_ in signup.fields:
        value = _value_for(field_, account)
        if value is not None:
            pairs.append((field_.name, value))
    return urlencode(pairs), {"Content-Type": "application/x-www-form-urlencoded"}


def _fresh_form_page(
    gateway: CaptureGateway, engagement: str, page_url: str
) -> tuple[str, dict[str, str], dict[str, str]]:
    """Re-fetch a form page: its body, fresh hidden values and any session cookie.

    Anonymous GET, so no approval and no grant is needed.
    """
    capture = gateway.send(engagement, "GET", page_url, note="account sign-up page")
    body = _response_text(capture)
    hidden: dict[str, str] = {}
    parser = crawl._Page()  # noqa: SLF001 - same package, the page parser
    try:
        parser.feed(body)
        parser.close()
    except (AssertionError, ValueError):
        pass
    for form in parser.forms:
        for item in form.get("fields") or []:
            if isinstance(item, dict) and _field_type(item) == "hidden" and item.get("name"):
                hidden[str(item["name"])] = str(item.get("value") or "")
    return body, hidden, _set_cookies(capture)


def _cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def _register(
    gateway: CaptureGateway,
    engagement: str,
    grant: AccountGrant,
    signup: Signup,
    account: _Account,
) -> tuple[Capture, dict[str, str]]:
    """Send the registration request. Returns the capture and any session cookies it set."""
    hidden = dict(signup.hidden)
    carry: dict[str, str] = {}
    if signup.kind == "form":
        _body, fresh_hidden, cookies = _fresh_form_page(gateway, engagement, signup.page)
        hidden.update(fresh_hidden)
        carry = cookies
    body, headers = _build_body(signup, account, hidden)
    if carry:
        headers["Cookie"] = _cookie_header(carry)
    capture = gateway.send(
        engagement,
        signup.method,
        signup.url,
        headers=headers,
        body=body,
        note=f"register {account.name}",
        account_grant=grant,
    )
    return capture, carry


def _login(
    gateway: CaptureGateway,
    engagement: str,
    grant: AccountGrant,
    login: Signup,
    account: _Account,
) -> Capture:
    hidden = dict(login.hidden)
    carry: dict[str, str] = {}
    if login.kind == "form":
        _body, fresh_hidden, cookies = _fresh_form_page(gateway, engagement, login.page)
        hidden.update(fresh_hidden)
        carry = cookies
    body, headers = _build_body(login, account, hidden)
    if carry:
        headers["Cookie"] = _cookie_header(carry)
    return gateway.send(
        engagement,
        login.method,
        login.url,
        headers=headers,
        body=body,
        note=f"log in {account.name}",
        account_grant=grant,
    )


def _ok(capture: Capture) -> bool:
    return not capture.error and capture.status is not None and 200 <= capture.status < 400


def _verify(gateway: CaptureGateway, engagement: str, seed: str, name: str) -> bool:
    """One GET of a seed URL as the stored identity. True when it answers non-401/403."""
    try:
        capture = gateway.send(engagement, "GET", seed, identity=name, note=f"verify {name}")
    except GatewayRefusal:
        return False
    return not capture.error and capture.status is not None and capture.status not in (401, 403)


def provision(
    gateway: CaptureGateway,
    engagement: str,
    seeds: Sequence[str],
    *,
    api_operations: Iterable[Any] = (),
    api_surface: Any = None,
    count: int | None = None,
) -> dict[str, Any]:
    """Register and sign in up to ``max_accounts`` test accounts, when enabled.

    The sign-up is an HTML form found by an anonymous crawl of ``seeds``, or an
    API operation in ``api_operations``; failing both, the JSON endpoints in
    ``api_surface`` (:func:`api_surface`) are tried, a few, once each. The
    login is found the same way.

    Returns ``{"ok", "enabled", "created": [names], "reused": [names],
    "failed": [{"name", "reason", "detail"}], "signup": {"kind","url"} | None,
    "login": {"kind","url"} | None, "requests": n}``. No email, username,
    password, cookie or token appears in the result. Idempotent: an account that
    already exists and still signs in is reused; only the missing ones are
    created.
    """
    surface = api_surface if isinstance(api_surface, dict) else {}
    api_ops = [*(api_operations or []), *(surface.get("operations") or [])]
    seed_list = [str(s) for s in (seeds or []) if isinstance(s, str) and s]
    failed: list[dict[str, str]] = []
    result: dict[str, Any] = {
        "ok": False,
        "enabled": False,
        "created": [],
        "reused": [],
        "failed": failed,
        "signup": None,
        "login": None,
        "requests": 0,
    }

    scope, document = gateway.scope_for(engagement)
    try:
        policy = account_creation_policy(document)
    except AccountPolicyError as exc:
        failed.append({"name": "", "reason": NOT_ENABLED, "detail": str(exc)})
        return result
    if policy is None:
        failed.append(
            {
                "name": "",
                "reason": NOT_ENABLED,
                "detail": "account creation is off for this engagement",
            }
        )
        return result
    result["enabled"] = True

    if not seed_list:
        failed.append({"name": "", "reason": NO_SIGNUP_FOUND, "detail": "no seed URL was given"})
        return result

    before = len(gateway.store.list(engagement, limit=500))
    crawl_result = crawl.crawl(gateway, engagement, seed_list)
    signup = find_signup(crawl_result, api_ops)
    login = find_login(crawl_result, api_ops)
    signups = _Choice([signup] if signup is not None else api_signup_candidates(surface))
    logins = _Choice([login] if login is not None else api_login_candidates(surface))

    target = policy.max_accounts if count is None else max(0, min(int(count), policy.max_accounts))
    result["credentials_file"] = f"audit/{engagement}/accounts-created.json"
    if logins.first is not None:
        result["login"] = logins.first.summary()
    if signups.first is None:
        reason, detail = _no_signup_reason(gateway, engagement, crawl_result)
        failed.append({"name": "", "reason": reason, "detail": detail})
        # Buggy cannot register here, but a person can. Prepare the accounts (an
        # address, a user name and a strong password each) so that the operator
        # registers exactly those, and sign in with the ones already registered.
        _prepared_accounts(gateway, engagement, policy, logins, target, seed_list[0], result)
        result["requests"] = len(gateway.store.list(engagement, limit=500)) - before
        return result
    result["signup"] = signups.first.summary()

    grant = gateway.account_creation_grant(engagement, [*signups.urls(), *logins.urls()])

    existing = _load_existing(gateway, engagement)
    accounts: list[_Account] = []
    created: list[str] = []
    reused: list[str] = []

    # Reuse accounts that already exist and still sign in.
    for name, entry in list(existing.items())[:target]:
        account = _Account.stored(name, entry)
        if logins.candidates and _signin(gateway, engagement, grant, logins, account):
            reused.append(name)
        else:
            failed.append(
                {
                    "name": name,
                    "reason": WAITING_FOR_OPERATOR,
                    "detail": "this prepared account does not sign in yet: finish its sign-up "
                    "(or its email verification) with the values in the credentials file",
                }
            )
        accounts.append(account)

    index = 0
    while len(accounts) < target:
        index += 1
        name = f"auto{index}"
        if name in {a.name for a in accounts}:
            continue
        tag = secrets.token_hex(TAG_BYTES)
        account = _Account(
            name=name,
            email=policy.email_for(tag),
            username=f"auto{tag}",
            password=_strong_password(),
        )
        outcome = _create_one(gateway, engagement, grant, signups, logins, account)
        accounts.append(account)
        if outcome == "":
            created.append(name)
        else:
            failed.append({"name": name, "reason": outcome[0], "detail": outcome[1]})

    _store_accounts(gateway, engagement, [a.record() for a in accounts])
    if signups.first is not None:
        result["signup"] = signups.first.summary()
    if logins.first is not None:
        result["login"] = logins.first.summary()

    # Verify every account's session as the stored identity, one GET each.
    verify_seed = seed_list[0]
    for account in accounts:
        if not account.has_session():
            if account.name not in {f["name"] for f in failed}:
                failed.append(
                    {
                        "name": account.name,
                        "reason": LOGIN_FAILED,
                        "detail": "no session was obtained",
                    }
                )
            for bucket in (created, reused):
                if account.name in bucket:
                    bucket.remove(account.name)
            continue
        if not _verify(gateway, engagement, verify_seed, account.name):
            for bucket in (created, reused):
                if account.name in bucket:
                    bucket.remove(account.name)
            if account.name not in {f["name"] for f in failed}:
                failed.append(
                    {
                        "name": account.name,
                        "reason": LOGIN_FAILED,
                        "detail": "the session could not be verified against a seed URL",
                    }
                )

    result["created"] = created
    result["reused"] = reused
    result["ok"] = bool(created or reused)
    result["requests"] = len(gateway.store.list(engagement, limit=500)) - before
    return result


def _prepared_accounts(
    gateway: CaptureGateway,
    engagement: str,
    policy: AccountPolicy,
    logins: _Choice,
    target: int,
    seed: str,
    result: dict[str, Any],
) -> None:
    """Keep ``target`` prepared accounts on file and sign in those a person registered.

    Fills ``result["reused"]`` with the accounts that sign in and
    ``result["prepared"]`` with the ones still waiting for the operator.
    """
    existing = _load_existing(gateway, engagement)
    accounts: list[_Account] = [
        _Account.stored(name, entry) for name, entry in list(existing.items())[:target]
    ]
    index = 0
    while len(accounts) < target:
        index += 1
        name = f"auto{index}"
        if name in {a.name for a in accounts}:
            continue
        tag = secrets.token_hex(TAG_BYTES)
        accounts.append(
            _Account(
                name=name,
                email=policy.email_for(tag),
                username=f"auto{tag}",
                password=_strong_password(),
            )
        )
    working: list[str] = []
    if logins.candidates:
        grant = gateway.account_creation_grant(engagement, logins.urls())
        for account in accounts:
            _signin(gateway, engagement, grant, logins, account)
    _store_accounts(gateway, engagement, [a.record() for a in accounts])
    for account in accounts:
        if account.has_session() and _verify(gateway, engagement, seed, account.name):
            working.append(account.name)
    if logins.first is not None:
        result["login"] = logins.first.summary()
    result["reused"] = working
    result["prepared"] = [a.name for a in accounts if a.name not in working]
    result["ok"] = bool(working)


def _no_signup_reason(
    gateway: CaptureGateway, engagement: str, crawl_result: Any
) -> tuple[str, str]:
    """Why no sign-up could be used: SSO-only page found, or simply none."""
    pages = crawl_result.get("pages") if isinstance(crawl_result, dict) else None
    for page in pages or []:
        url = page.get("url") if isinstance(page, dict) else None
        if not isinstance(url, str) or not _SIGNUP_PATH_RE.search(urlsplit(url).path):
            continue
        try:
            capture = gateway.send(engagement, "GET", url, note="account sign-up page")
        except GatewayRefusal:
            continue
        if _sso_only(_response_text(capture)):
            return SSO_ONLY, f"{url} offers only single sign-on, with no password field"
    return NO_SIGNUP_FOUND, "no registration form or API was recognised on the crawled surface"


def _signin(
    gateway: CaptureGateway,
    engagement: str,
    grant: AccountGrant,
    logins: _Choice,
    account: _Account,
) -> bool:
    """Log the account in and record its session on ``account``. True on success.

    The login endpoints are tried in order, one request each; the first that
    hands out a session is kept for the next accounts. A JSON login must
    answer 2xx with a token in the JSON (an ``Authorization: Bearer`` header
    for the identity) or a session cookie, and not with an HTML page.
    """
    for login in list(logins.candidates):
        try:
            capture = _login(gateway, engagement, grant, login, account)
        except GatewayRefusal:
            continue
        if not (_api_ok(capture) if login.kind == "json" else _ok(capture)):
            continue
        headers, cookies = _session_from(capture)
        if not headers and not cookies:
            continue
        account.headers, account.cookies = headers, cookies
        account.learn_ids(capture, login.url)
        logins.pin(login)
        return True
    return False


def _refusal(capture: Capture, signup: Signup) -> tuple[str, str]:
    """The named reason a registration was not accepted."""
    if _email_verification(capture):
        return EMAIL_VERIFICATION, "registration asks for email verification"
    if capture.status is None:
        return REGISTRATION_REFUSED, f"registration at {signup.url} got no response"
    if signup.kind == "json" and "captcha" in _response_text(capture)[:5000].lower():
        return CAPTCHA, f"registration at {signup.url} asks for a CAPTCHA"
    if signup.kind == "json" and _is_html(capture):
        return (
            REGISTRATION_REFUSED,
            f"{signup.url} answered with an HTML page (status {capture.status}), not an API",
        )
    return REGISTRATION_REFUSED, f"registration at {signup.url} returned status {capture.status}"


def _register_any(
    gateway: CaptureGateway,
    engagement: str,
    grant: AccountGrant,
    signups: _Choice,
    account: _Account,
) -> tuple[Capture | None, tuple[str, str]]:
    """Register ``account`` at the first sign-up that accepts it, one request per endpoint.

    Returns the accepted registration's capture and ``("", "")``, or ``None``
    and the reason of the most telling refusal. When no endpoint accepted
    anything, the next accounts are not sent at all (``signups.exhausted``).
    """
    if signups.exhausted is not None:
        return None, signups.exhausted
    last: tuple[str, str] = (REGISTRATION_REFUSED, "no sign-up endpoint accepted the account")
    telling: tuple[str, str] | None = None
    for signup in list(signups.candidates):
        page_body = (
            _fresh_form_page(gateway, engagement, signup.page)[0] if signup.kind == "form" else ""
        )
        blocker = _signup_blocker(signup, page_body)
        if blocker[0]:
            return None, blocker
        try:
            capture, _carry = _register(gateway, engagement, grant, signup, account)
        except GatewayRefusal as refusal:
            last = (REGISTRATION_REFUSED, f"{signup.url} was not sent ({refusal.code})")
            continue
        if _api_ok(capture) if signup.kind == "json" else _ok(capture):
            signups.pin(signup)
            return capture, ("", "")
        last = _refusal(capture, signup)
        if last[0] in (CAPTCHA, EMAIL_VERIFICATION):
            return None, last
        # A 404, a 405 or an HTML page only says "not here"; any other answer says more.
        if telling is None and capture.status not in (404, 405) and not _is_html(capture):
            telling = last
    reason = telling or last
    if all(signup.kind == "json" for signup in signups.candidates):
        signups.exhausted = reason  # the next accounts would be refused the same way
    return None, reason


def _create_one(
    gateway: CaptureGateway,
    engagement: str,
    grant: AccountGrant,
    signups: _Choice,
    logins: _Choice,
    account: _Account,
) -> str | tuple[str, str]:
    """Register and sign in one account. ``""`` on success, else ``(reason, detail)``."""
    register_capture, reason = _register_any(gateway, engagement, grant, signups, account)
    if register_capture is None:
        return reason
    signup = signups.first
    if signup is not None and signup.kind == "json":
        account.learn_ids(register_capture, signup.url)
    # A registration may hand out the session directly.
    session_headers, session_cookies = _session_from(register_capture)
    if (session_headers or session_cookies) and not _is_html(register_capture):
        account.headers, account.cookies = session_headers, session_cookies
    if not logins.candidates:
        if account.has_session():
            return ""
        return LOGIN_FAILED, "no login form or API was found to obtain a session"
    if not _signin(gateway, engagement, grant, logins, account):
        if _email_verification(register_capture):
            return (
                EMAIL_VERIFICATION,
                "login after registration failed; email verification is likely",
            )
        if not account.has_session():
            return LOGIN_FAILED, "the account could not sign in after registration"
    return ""


def stored_own_ids(gateway: CaptureGateway, engagement: str, name: str) -> list[dict[str, Any]]:
    """The identifiers the target handed to a created account as its own (``[]`` for others)."""
    entry = _load_existing(gateway, engagement).get(name)
    ids = entry.get("own_ids") if isinstance(entry, dict) else None
    return [i for i in ids if isinstance(i, dict)] if isinstance(ids, list) else []


__all__ = [
    "CAPTCHA",
    "EMAIL_VERIFICATION",
    "LOGIN_FAILED",
    "NOT_ENABLED",
    "NO_SIGNUP_FOUND",
    "REGISTRATION_REFUSED",
    "SSO_ONLY",
    "UNKNOWN_REQUIRED_FIELD",
    "AccountPolicy",
    "AccountPolicyError",
    "Field",
    "Signup",
    "WAITING_FOR_OPERATOR",
    "account_creation_policy",
    "api_login_candidates",
    "api_signup_candidates",
    "api_surface",
    "find_login",
    "find_signup",
    "provision",
    "stored_own_ids",
]
