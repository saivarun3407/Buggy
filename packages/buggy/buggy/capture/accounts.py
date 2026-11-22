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
    count: int | None = None,
) -> dict[str, Any]:
    """Register and sign in up to ``max_accounts`` test accounts, when enabled.

    Returns ``{"ok", "enabled", "created": [names], "reused": [names],
    "failed": [{"name", "reason", "detail"}], "signup": {"kind","url"} | None,
    "login": {"kind","url"} | None, "requests": n}``. No email, username,
    password, cookie or token appears in the result. Idempotent: an account that
    already exists and still signs in is reused; only the missing ones are
    created.
    """
    api_ops = list(api_operations or [])
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

    target = policy.max_accounts if count is None else max(0, min(int(count), policy.max_accounts))
    result["credentials_file"] = f"audit/{engagement}/accounts-created.json"
    if login is not None:
        result["login"] = login.summary()
    if signup is None:
        reason, detail = _no_signup_reason(gateway, engagement, crawl_result)
        failed.append({"name": "", "reason": reason, "detail": detail})
        # Buggy cannot register here, but a person can. Prepare the accounts (an
        # address, a user name and a strong password each) so that the operator
        # registers exactly those, and sign in with the ones already registered.
        _prepared_accounts(gateway, engagement, policy, login, target, seed_list[0], result)
        result["requests"] = len(gateway.store.list(engagement, limit=500)) - before
        return result
    result["signup"] = signup.summary()

    grant = gateway.account_creation_grant(engagement, [signup.url, login.url if login else ""])

    existing = _load_existing(gateway, engagement)
    accounts: list[_Account] = []
    created: list[str] = []
    reused: list[str] = []
    stored: list[dict[str, Any]] = []

    # Reuse accounts that already exist and still sign in.
    for name, entry in list(existing.items())[:target]:
        account = _Account(
            name=name,
            email=str(entry.get("email") or ""),
            username=str(entry.get("username") or ""),
            password=str(entry.get("password") or ""),
        )
        if login is not None and _signin(gateway, engagement, grant, login, account):
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
        stored.append(account.record())

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
        outcome = _create_one(gateway, engagement, grant, signup, login, account)
        accounts.append(account)
        stored.append(account.record())
        if outcome == "":
            created.append(name)
        else:
            failed.append({"name": name, "reason": outcome[0], "detail": outcome[1]})

    _store_accounts(gateway, engagement, stored)

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
    login: Signup | None,
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
        _Account(
            name=name,
            email=str(entry.get("email") or ""),
            username=str(entry.get("username") or ""),
            password=str(entry.get("password") or ""),
        )
        for name, entry in list(existing.items())[:target]
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
    grant = gateway.account_creation_grant(engagement, [login.url]) if login is not None else None
    working: list[str] = []
    for account in accounts:
        if login is not None and grant is not None:
            _signin(gateway, engagement, grant, login, account)
    _store_accounts(gateway, engagement, [a.record() for a in accounts])
    for account in accounts:
        if account.has_session() and _verify(gateway, engagement, seed, account.name):
            working.append(account.name)
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
    login: Signup,
    account: _Account,
) -> bool:
    """Log the account in and record its session on ``account``. True on success."""
    capture = _login(gateway, engagement, grant, login, account)
    if not _ok(capture):
        return False
    headers, cookies = _session_from(capture)
    if not headers and not cookies:
        return False
    account.headers, account.cookies = headers, cookies
    return True


def _create_one(
    gateway: CaptureGateway,
    engagement: str,
    grant: AccountGrant,
    signup: Signup,
    login: Signup | None,
    account: _Account,
) -> str | tuple[str, str]:
    """Register and sign in one account. ``""`` on success, else ``(reason, detail)``."""
    _body, hidden, cookies = (
        _fresh_form_page(gateway, engagement, signup.page)
        if signup.kind == "form"
        else ("", dict(signup.hidden), {})
    )
    blocker = _signup_blocker(signup, _body)
    if blocker[0]:
        return blocker
    register_capture, carry = _register(gateway, engagement, grant, signup, account)
    session_headers, session_cookies = _session_from(register_capture)
    if not _ok(register_capture):
        if _email_verification(register_capture):
            return EMAIL_VERIFICATION, "registration asks for email verification"
        detail = (
            f"registration returned status {register_capture.status}"
            if register_capture.status is not None
            else "registration got no response"
        )
        return REGISTRATION_REFUSED, detail
    # A registration may hand out the session directly.
    if session_headers or session_cookies:
        account.headers, account.cookies = session_headers, session_cookies
    if login is None:
        if account.has_session():
            return ""
        return LOGIN_FAILED, "no login form or API was found to obtain a session"
    if not _signin(gateway, engagement, grant, login, account):
        if _email_verification(register_capture):
            return (
                EMAIL_VERIFICATION,
                "login after registration failed; email verification is likely",
            )
        if not account.has_session():
            return LOGIN_FAILED, "the account could not sign in after registration"
    return ""


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
    "account_creation_policy",
    "find_login",
    "find_signup",
    "provision",
]
