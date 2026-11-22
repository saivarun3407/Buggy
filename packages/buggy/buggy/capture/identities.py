"""Identities: test accounts the operator declares and the gateway logs in as.

Access-control bugs are found by asking the same question as two different
users. Doing that with tokens the agent holds puts credentials in the agent's
context, its sandbox and every transcript. Here the operator writes the test
accounts once, in ``<secrets root>/<engagement>/identities.json`` (a tree no
agent-facing container mounts). The gateway performs the login, keeps the
session and attaches it when a request names an identity. An agent says
``identity="alice"`` and never sees a password, a TOTP secret or a token.

* :class:`IdentityStore` reads and validates the file. :meth:`IdentityStore.public`
  is the only view meant for an agent: names, roles and owned objects.
* :class:`SessionManager` turns an identity into the headers and cookies to
  attach. A ``static`` identity carries them directly; a ``login`` identity is
  logged in through ``CaptureGateway.send`` (so the login is scope-checked,
  rate-limited and recorded like any other request) and the session is cached.
* :func:`totp` is RFC 6238 (SHA-1, 30 s, 6 digits).

Standard library only; no model or agent library is imported here.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
import os
import re
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote_plus, urlsplit

if TYPE_CHECKING:
    from buggy.capture.gateway import CaptureGateway
    from buggy.capture.store import Capture

IDENTITIES_FILE = "identities.json"
log = logging.getLogger("buggy.capture.identities")
LOGIN_PROBE = "login"
LOGIN_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})
EXTRACT_SOURCES = ("json", "cookie", "header", "regex")
# What each ``extract`` source needs besides ``name`` and ``from``.
_EXTRACT_KEY = {"json": "path", "cookie": "cookie", "header": "header", "regex": "pattern"}

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_COOKIE_NAME = re.compile(r"^[^\s;=,]+$")
# Strings unique to one account's private data. Shorter ones would match by accident.
MAX_MARKERS = 20
MARKER_MIN = 3
MARKER_MAX = 200


class IdentityError(ValueError):
    """``identities.json`` is malformed. ``field`` is the path of the offending entry.

    The message names the field and the problem and never repeats a value from
    the file: a validation error may be shown to an agent.
    """

    def __init__(self, field: str, problem: str) -> None:
        super().__init__(f"{field}: {problem}")
        self.field = field
        self.problem = problem


class UnknownIdentity(LookupError):
    """No identity of that name is declared for the engagement."""


class LoginError(RuntimeError):
    """The login did not produce a session. The message carries no credential."""


# ── TOTP (RFC 6238 over RFC 4226) ───────────────────────────────────


def _totp_key(secret: str) -> bytes:
    cleaned = re.sub(r"[\s-]", "", secret or "").upper().rstrip("=")
    if not cleaned:
        raise ValueError("TOTP secret is empty")
    try:
        return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("TOTP secret is not valid base32") from exc


def totp(secret: str, *, at: float | None = None, digits: int = 6, step: int = 30) -> str:
    """The time-based one-time password for a base32 ``secret`` at Unix time ``at``."""
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(_totp_key(secret), struct.pack(">Q", counter), "sha1").digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


# ── the declared identity ───────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class LoginRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: str


@dataclass(frozen=True, slots=True)
class Extract:
    name: str
    source: str  # one of EXTRACT_SOURCES
    key: str  # json path, cookie name, header name or regex pattern


@dataclass(frozen=True, slots=True)
class Success:
    status: int | None = None
    body_contains: str = ""


@dataclass(frozen=True, slots=True)
class Login:
    request: LoginRequest
    credentials: dict[str, str]
    extract: tuple[Extract, ...]
    apply_headers: dict[str, str]
    apply_cookies: dict[str, str]
    success: Success


@dataclass(frozen=True, slots=True)
class Identity:
    name: str
    role: str = ""
    owner_of: tuple[str, ...] = ()
    # Strings that appear only in this account's private data (an email address,
    # a display name, an account number). Never shown to an agent.
    markers: tuple[str, ...] = ()
    static_headers: dict[str, str] = field(default_factory=dict)
    static_cookies: dict[str, str] = field(default_factory=dict)
    login: Login | None = None

    @property
    def kind(self) -> str:
        return "login" if self.login is not None else "static"

    def session_header_names(self) -> tuple[str, ...]:
        """Lower-case names of every header this identity's session is carried in."""
        names = {name.lower() for name in self.static_headers}
        if self.login is not None:
            names.update(name.lower() for name in self.login.apply_headers)
        return tuple(sorted(names | {"cookie", "set-cookie"}))

    def login_header_names(self) -> tuple[str, ...]:
        """Lower-case names of the headers of the login exchange that carry a secret."""
        if self.login is None:
            return ()
        names = {
            name.lower()
            for name, value in self.login.request.headers.items()
            if _PLACEHOLDER.search(value)
        }
        names.update(e.key.lower() for e in self.login.extract if e.source == "header")
        return tuple(sorted(names | {"cookie", "set-cookie"}))

    def public(self) -> dict[str, Any]:
        # ``markers`` are left out: an agent does not need them.
        return {
            "name": self.name,
            "role": self.role,
            "owner_of": list(self.owner_of),
            "kind": self.kind,
        }


# ── validation ──────────────────────────────────────────────────────


def _obj(value: Any, path: str, allowed: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IdentityError(path, "must be an object")
    for key in value:
        if key not in allowed:
            raise IdentityError(f"{path}.{key}", f"unknown field (expected one of {list(allowed)})")
    return value


def _str(value: Any, path: str, *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise IdentityError(path, "must be a string")
    if required and not value:
        raise IdentityError(path, "must not be empty")
    return value


def _pairs(value: Any, path: str, name_rule: re.Pattern[str]) -> dict[str, str]:
    """A ``{name: value}`` object of header or cookie values."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise IdentityError(path, "must be an object of strings")
    out: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not name_rule.match(key):
            raise IdentityError(path, "has a name that is not a valid header or cookie name")
        if not isinstance(item, str):
            raise IdentityError(f"{path}.{key}", "must be a string")
        if "\r" in item or "\n" in item:
            raise IdentityError(f"{path}.{key}", "must not contain a line break")
        out[key] = item
    return out


def _parse_login(raw: Any, path: str) -> Login:
    doc = _obj(raw, path, ("request", "credentials", "extract", "apply", "success"))

    request_path = f"{path}.request"
    if "request" not in doc:
        raise IdentityError(request_path, "is required")
    request = _obj(doc["request"], request_path, ("method", "url", "headers", "body"))
    method = _str(request.get("method"), f"{request_path}.method").upper()
    if method not in LOGIN_METHODS:
        raise IdentityError(f"{request_path}.method", f"must be one of {sorted(LOGIN_METHODS)}")
    url = _str(request.get("url"), f"{request_path}.url")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise IdentityError(f"{request_path}.url", "must be an absolute http(s) URL")
    if parts.username or parts.password or _PLACEHOLDER.search(url):
        # The URL is written to the ledger and shown in capture listings.
        raise IdentityError(
            f"{request_path}.url", "must not carry credentials or placeholders; use the body"
        )
    headers = _pairs(request.get("headers"), f"{request_path}.headers", _HEADER_NAME)
    body = _str(request.get("body"), f"{request_path}.body", required=False)

    credentials_path = f"{path}.credentials"
    credentials = doc.get("credentials")
    if credentials is None:
        credentials = {}
    if not isinstance(credentials, dict):
        raise IdentityError(credentials_path, "must be an object of strings")
    for key, item in credentials.items():
        if not isinstance(key, str) or not _PLACEHOLDER.fullmatch("{" + key + "}"):
            raise IdentityError(credentials_path, "has a key that is not a plain identifier")
        if not isinstance(item, str):
            raise IdentityError(f"{credentials_path}.{key}", "must be a string")
    if "totp" in credentials:
        raise IdentityError(
            f"{credentials_path}.totp", "is computed from totp_secret; give the secret instead"
        )
    if "totp_secret" in credentials:
        try:
            _totp_key(credentials["totp_secret"])
        except ValueError as exc:
            raise IdentityError(f"{credentials_path}.totp_secret", str(exc)) from exc
    used = set(_PLACEHOLDER.findall(body))
    for value in headers.values():
        used.update(_PLACEHOLDER.findall(value))
    if "totp" in used and "totp_secret" not in credentials:
        raise IdentityError(
            f"{credentials_path}.totp_secret", "is required because the request uses {totp}"
        )
    for needed in ("username", "password"):
        if needed in used and needed not in credentials:
            raise IdentityError(
                f"{credentials_path}.{needed}",
                f"is required because the request uses {{{needed}}}",
            )

    extract_path = f"{path}.extract"
    raw_extract = doc.get("extract")
    if raw_extract is None:
        raw_extract = []
    if not isinstance(raw_extract, list):
        raise IdentityError(extract_path, "must be a list")
    extracts: list[Extract] = []
    for index, item in enumerate(raw_extract):
        item_path = f"{extract_path}[{index}]"
        if not isinstance(item, dict):
            raise IdentityError(item_path, "must be an object")
        name = _str(item.get("name"), f"{item_path}.name")
        if not _PLACEHOLDER.fullmatch("{" + name + "}"):
            raise IdentityError(f"{item_path}.name", "must be a plain identifier")
        if any(e.name == name for e in extracts):
            raise IdentityError(f"{item_path}.name", "is declared twice")
        source = item.get("from")
        if source not in EXTRACT_SOURCES:
            raise IdentityError(f"{item_path}.from", f"must be one of {list(EXTRACT_SOURCES)}")
        key_name = _EXTRACT_KEY[source]
        _obj(item, item_path, ("name", "from", key_name))
        key = _str(item.get(key_name), f"{item_path}.{key_name}")
        if source == "regex":
            try:
                re.compile(key)
            except re.error as exc:
                raise IdentityError(
                    f"{item_path}.pattern", f"is not a valid regular expression ({exc.msg})"
                ) from exc
        extracts.append(Extract(name=name, source=source, key=key))

    apply_path = f"{path}.apply"
    if "apply" not in doc:
        raise IdentityError(apply_path, "is required")
    apply = _obj(doc["apply"], apply_path, ("headers", "cookies"))
    apply_headers = _pairs(apply.get("headers"), f"{apply_path}.headers", _HEADER_NAME)
    apply_cookies = _pairs(apply.get("cookies"), f"{apply_path}.cookies", _COOKIE_NAME)
    if not apply_headers and not apply_cookies:
        raise IdentityError(apply_path, "must set at least one header or cookie")
    known = {e.name for e in extracts}
    for kind, pairs in (("headers", apply_headers), ("cookies", apply_cookies)):
        for key, value in pairs.items():
            for placeholder in _PLACEHOLDER.findall(value):
                if placeholder not in known:
                    raise IdentityError(
                        f"{apply_path}.{kind}.{key}",
                        f"uses {{{placeholder}}}, which no extract entry defines",
                    )

    success_path = f"{path}.success"
    raw_success = doc.get("success")
    success = Success()
    if raw_success is not None:
        _obj(raw_success, success_path, ("status", "body_contains"))
        status = raw_success.get("status")
        if status is not None and (
            isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599
        ):
            raise IdentityError(f"{success_path}.status", "must be an HTTP status code")
        contains = _str(
            raw_success.get("body_contains"), f"{success_path}.body_contains", required=False
        )
        if status is None and not contains:
            raise IdentityError(success_path, "must set status or body_contains")
        success = Success(status=status, body_contains=contains)

    return Login(
        request=LoginRequest(method=method, url=url, headers=headers, body=body),
        credentials=dict(credentials),
        extract=tuple(extracts),
        apply_headers=apply_headers,
        apply_cookies=apply_cookies,
        success=success,
    )


def _parse_markers(raw: Any, path: str) -> tuple[str, ...]:
    """``markers``: 1-20 strings of 3-200 characters. The messages never repeat one."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise IdentityError(path, "must be a list of strings")
    if not 1 <= len(raw) <= MAX_MARKERS:
        raise IdentityError(path, f"must list 1-{MAX_MARKERS} strings")
    out: list[str] = []
    for index, item in enumerate(raw):
        item_path = f"{path}[{index}]"
        if not isinstance(item, str):
            raise IdentityError(item_path, "must be a string")
        if not item.strip():
            raise IdentityError(item_path, "must not be empty")
        if len(item) < MARKER_MIN:
            raise IdentityError(
                item_path,
                f"must be at least {MARKER_MIN} characters (a shorter one matches by accident)",
            )
        if len(item) > MARKER_MAX:
            raise IdentityError(item_path, f"must be at most {MARKER_MAX} characters")
        if item not in out:
            out.append(item)
    return tuple(out)


def _parse_identity(raw: Any, path: str) -> Identity:
    doc = _obj(raw, path, ("name", "role", "owner_of", "markers", "static", "login"))
    name = _str(doc.get("name"), f"{path}.name")
    if not _NAME.match(name):
        raise IdentityError(f"{path}.name", "must be 1-64 characters of A-Z a-z 0-9 . _ -")
    role = _str(doc.get("role"), f"{path}.role", required=False)
    owner_of = doc.get("owner_of")
    if owner_of is None:
        owner_of = []
    if not isinstance(owner_of, list) or not all(isinstance(x, str) and x for x in owner_of):
        raise IdentityError(f"{path}.owner_of", "must be a list of non-empty strings")
    markers = _parse_markers(doc.get("markers"), f"{path}.markers")

    static_headers: dict[str, str] = {}
    static_cookies: dict[str, str] = {}
    if doc.get("static") is not None:
        static = _obj(doc["static"], f"{path}.static", ("headers", "cookies"))
        static_headers = _pairs(static.get("headers"), f"{path}.static.headers", _HEADER_NAME)
        static_cookies = _pairs(static.get("cookies"), f"{path}.static.cookies", _COOKIE_NAME)
        if not static_headers and not static_cookies:
            raise IdentityError(f"{path}.static", "must set at least one header or cookie")
    login = _parse_login(doc["login"], f"{path}.login") if doc.get("login") is not None else None
    if login is None and not static_headers and not static_cookies:
        raise IdentityError(path, "needs a static session or a login")
    return Identity(
        name=name,
        role=role,
        owner_of=tuple(owner_of),
        markers=markers,
        static_headers=static_headers,
        static_cookies=static_cookies,
        login=login,
    )


def parse_identities(document: Any) -> dict[str, Identity]:
    """Validate a parsed ``identities.json`` and return its identities by name."""
    doc = _obj(document, "identities.json", ("identities",))
    entries = doc.get("identities")
    if not isinstance(entries, list):
        raise IdentityError("identities", "must be a list")
    out: dict[str, Identity] = {}
    for index, raw in enumerate(entries):
        identity = _parse_identity(raw, f"identities[{index}]")
        if identity.name in out:
            raise IdentityError(f"identities[{index}].name", "is declared twice")
        for position, marker in enumerate(identity.markers):
            holder = next((o.name for o in out.values() if marker in o.markers), "")
            if holder:
                # A shared marker cannot tell the two accounts apart.
                raise IdentityError(
                    f"identities[{index}].markers[{position}]",
                    f"is also a marker of identity {holder!r}; a marker must be unique "
                    "to one account",
                )
        out[identity.name] = identity
    return out


def _awaits_session(definition: dict[str, Any]) -> bool:
    """Whether a created account's identity has no session yet (static, nothing to attach)."""
    static = definition.get("static")
    if not isinstance(static, dict) or definition.get("login"):
        return False
    return not static.get("headers") and not static.get("cookies")


class IdentityStore:
    """The operator's identities, read from the secrets root on every use.

    When ``accounts_root`` is given, the accounts the gateway's account-creation
    module created for the engagement are read from there too and appended after
    the operator's own. A declared identity of the same name always wins: the
    operator's file is authoritative over anything the gateway created.
    """

    def __init__(
        self,
        secrets_root: str | Path | None = None,
        *,
        accounts_root: str | Path | None = None,
    ) -> None:
        if secrets_root is None:
            secrets_root = os.environ.get("BUGGY_SECRETS_ROOT") or "/secrets"
        self.root = Path(secrets_root)
        self.accounts_root = Path(accounts_root) if accounts_root is not None else None

    def path(self, engagement: str) -> Path:
        bad = not engagement or engagement.startswith(".")
        if bad or any(ch in engagement for ch in ("/", "\\", "\x00")):
            raise IdentityError("engagement", "is not a valid engagement name")
        return self.root / engagement / IDENTITIES_FILE

    def _declared(self, engagement: str) -> dict[str, Identity]:
        path = self.path(engagement)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeDecodeError) as exc:
            raise IdentityError(IDENTITIES_FILE, f"cannot be read ({type(exc).__name__})") from exc
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            # Position only: the offending text may be a credential.
            raise IdentityError(
                IDENTITIES_FILE, f"is not valid JSON (line {exc.lineno}, column {exc.colno})"
            ) from None
        return parse_identities(document)

    def created_path(self, engagement: str) -> Path | None:
        """The gateway-owned file of accounts it created, or ``None`` when disabled."""
        if self.accounts_root is None:
            return None
        # Reuse the engagement-name validation of ``path``.
        bad = not engagement or engagement.startswith(".")
        if bad or any(ch in engagement for ch in ("/", "\\", "\x00")):
            raise IdentityError("engagement", "is not a valid engagement name")
        return self.accounts_root / f"{engagement}.json"

    def _created(self, engagement: str) -> dict[str, Identity]:
        path = self.created_path(engagement)
        if path is None:
            return {}
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeDecodeError) as exc:
            raise IdentityError(
                "accounts", f"the created-accounts file cannot be read ({type(exc).__name__})"
            ) from exc
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise IdentityError(
                "accounts",
                f"the created-accounts file is not valid JSON (line {exc.lineno})",
            ) from None
        if not isinstance(document, dict) or not isinstance(document.get("accounts"), list):
            raise IdentityError("accounts", "the created-accounts file must be an accounts list")
        out: dict[str, Identity] = {}
        for index, entry in enumerate(document["accounts"]):
            if not isinstance(entry, dict) or not isinstance(entry.get("identity"), dict):
                raise IdentityError(f"accounts[{index}]", "must carry an identity definition")
            if _awaits_session(entry["identity"]):
                # Prepared but not signed in yet (a person still has to finish the
                # sign-up): it is on file, and it is not an identity anyone can use.
                continue
            identity = _parse_identity(entry["identity"], f"accounts[{index}].identity")
            out[identity.name] = identity
        return out

    def load(self, engagement: str) -> dict[str, Identity]:
        """Every identity of the engagement by name; ``{}`` when none are declared.

        Operator-declared identities come first, then the accounts the gateway
        created; a declared name wins over a created one of the same name.
        """
        declared = self._declared(engagement)
        merged: dict[str, Identity] = dict(declared)
        try:
            created = self._created(engagement)
        except IdentityError as exc:
            # The gateway's own file must never take the operator's accounts down with it.
            log.warning("identities: the created-accounts file was ignored: %s", exc)
            created = {}
        for name, identity in created.items():
            if name not in merged:
                merged[name] = identity
        return merged

    def get(self, engagement: str, name: str) -> Identity:
        identity = self.load(engagement).get(name)
        if identity is None:
            raise UnknownIdentity(name)
        return identity

    def public(self, engagement: str) -> list[dict[str, Any]]:
        """What an agent may know: name, role, owned objects, kind. No secret, no token."""
        return [identity.public() for identity in self.load(engagement).values()]

    def markers(self, engagement: str) -> dict[str, tuple[str, ...]]:
        """Every identity's declared markers by name (``()`` when it declares none).

        Operator side only: markers are not part of :meth:`public`.
        """
        return {name: identity.markers for name, identity in self.load(engagement).items()}

    def logins_at(self, engagement: str, method: str, url: str) -> list[Identity]:
        """The identities whose declared login request is exactly ``method url``."""
        return [
            identity
            for identity in self.load(engagement).values()
            if identity.login is not None
            and identity.login.request.method == method.upper()
            and identity.login.request.url == url
        ]


# ── logging in ──────────────────────────────────────────────────────


def _render(template: str, values: dict[str, str], escape: Callable[[str], str] = str) -> str:
    """Replace ``{name}`` for the names in ``values``; anything else is left as written."""

    def swap(match: re.Match[str]) -> str:
        name = match.group(1)
        return escape(values[name]) if name in values else match.group(0)

    return _PLACEHOLDER.sub(swap, template)


def _body_escape(headers: dict[str, str]) -> Callable[[str], str]:
    """How a credential must be written inside a body of the request's content type."""
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "").lower()
    if "json" in content_type:
        return lambda value: json.dumps(value)[1:-1]
    if "x-www-form-urlencoded" in content_type:
        return quote_plus
    return str


def _header(headers: dict[str, str], name: str) -> str:
    return next((v for k, v in headers.items() if k.lower() == name.lower()), "")


def _json_path(document: Any, path: str) -> Any:
    current = document
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def extract_value(extract: Extract, capture: Capture) -> str:
    """The value one ``extract`` entry takes from a login response; ``""`` if absent."""
    body = capture.response_body.decode("utf-8", "replace")
    if extract.source == "json":
        try:
            found = _json_path(json.loads(body), extract.key)
        except ValueError:
            return ""
        if isinstance(found, bool) or not isinstance(found, (str, int, float)):
            return ""
        return str(found)
    if extract.source == "cookie":
        # The gateway keeps one Set-Cookie per line.
        for line in _header(capture.response_headers, "set-cookie").split("\n"):
            name, _, value = line.split(";", 1)[0].partition("=")
            if name.strip() == extract.key:
                return value.strip().strip('"')
        return ""
    if extract.source == "header":
        return _header(capture.response_headers, extract.key).strip()
    match = re.search(extract.key, body)
    if match is None:
        return ""
    return match.group(1) if match.groups() else match.group(0)


@dataclass(frozen=True, slots=True)
class Session:
    """What to attach to a request sent as ``identity``."""

    identity: Identity
    headers: dict[str, str]
    cookies: dict[str, str]
    login_capture_id: str = ""
    created_at: float = 0.0


class SessionManager:
    """Sessions per engagement and identity, opened on first use and reused."""

    def __init__(
        self,
        gateway: CaptureGateway,
        store: IdentityStore,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._gateway = gateway
        self._store = store
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: dict[tuple[str, str], Session] = {}

    def auth_for(self, engagement: str, name: str) -> tuple[dict[str, str], dict[str, str]]:
        """The headers and cookies of ``name``'s session, logging in if there is none.

        Raises :class:`UnknownIdentity`, :class:`IdentityError` or :class:`LoginError`.
        """
        session, _fresh = self.session_for(engagement, name)
        return dict(session.headers), dict(session.cookies)

    def session_for(self, engagement: str, name: str) -> tuple[Session, bool]:
        """The session and whether this call had to log in to get it."""
        identity = self._store.get(engagement, name)
        key = (engagement, name)
        with self._lock:
            cached = self._sessions.get(key)
            # A session opened for an older version of the declaration is not reused.
            if cached is not None and cached.identity == identity:
                return cached, False
            self._sessions.pop(key, None)
            session = self._open(engagement, identity)
            self._sessions[key] = session
            return session, identity.login is not None

    def renew(self, engagement: str, name: str, used: Session) -> Session:
        """A new session after ``used`` was rejected (401). Logs in at most once.

        If another caller already replaced ``used``, that session is returned
        and no login is performed.
        """
        key = (engagement, name)
        with self._lock:
            current = self._sessions.get(key)
            if current is not None and current is not used:
                return current
            self._sessions.pop(key, None)
            return self.session_for(engagement, name)[0]

    def invalidate(self, engagement: str = "", name: str = "") -> None:
        """Forget cached sessions: all of them, one engagement's, or one identity's."""
        with self._lock:
            for key in list(self._sessions):
                if (not engagement or key[0] == engagement) and (not name or key[1] == name):
                    del self._sessions[key]

    def _open(self, engagement: str, identity: Identity) -> Session:
        headers = dict(identity.static_headers)
        cookies = dict(identity.static_cookies)
        login = identity.login
        if login is None:
            return Session(identity, headers, cookies, created_at=self._clock())

        values = {k: v for k, v in login.credentials.items() if k != "totp_secret"}
        if "totp_secret" in login.credentials:
            values["totp"] = totp(login.credentials["totp_secret"], at=self._clock())
        request = login.request
        capture = self._gateway.send(
            engagement,
            request.method,
            request.url,
            headers={k: _render(v, values) for k, v in request.headers.items()},
            body=_render(request.body, values, _body_escape(request.headers)) or None,
            note=f"login as {identity.name}",
            probe=LOGIN_PROBE,
            internal=True,
        )
        who = f"login for identity {identity.name!r}"
        if capture.error or capture.status is None:
            raise LoginError(f"{who} got no response ({capture.id}); no session")
        expected = login.success
        if expected.status is not None and capture.status != expected.status:
            raise LoginError(
                f"{who} returned status {capture.status}, not the declared success status "
                f"{expected.status} ({capture.id}); no session"
            )
        if expected.status is None and not 200 <= capture.status < 300:
            raise LoginError(f"{who} returned status {capture.status} ({capture.id}); no session")
        if expected.body_contains and expected.body_contains not in capture.response_body.decode(
            "utf-8", "replace"
        ):
            raise LoginError(
                f"{who} response does not contain the declared success text ({capture.id}); "
                "no session"
            )
        extracted: dict[str, str] = {}
        for entry in login.extract:
            value = extract_value(entry, capture)
            if not value or "\r" in value or "\n" in value:
                raise LoginError(
                    f"{who} response has no usable {entry.source} value for extract "
                    f"{entry.name!r} ({capture.id}); no session"
                )
            extracted[entry.name] = value
        headers.update({k: _render(v, extracted) for k, v in login.apply_headers.items()})
        cookies.update({k: _render(v, extracted) for k, v in login.apply_cookies.items()})
        return Session(identity, headers, cookies, capture.id, self._clock())


__all__ = [
    "EXTRACT_SOURCES",
    "IDENTITIES_FILE",
    "LOGIN_PROBE",
    "MAX_MARKERS",
    "Extract",
    "Identity",
    "IdentityError",
    "IdentityStore",
    "Login",
    "LoginError",
    "LoginRequest",
    "Session",
    "SessionManager",
    "Success",
    "UnknownIdentity",
    "extract_value",
    "parse_identities",
    "totp",
]
