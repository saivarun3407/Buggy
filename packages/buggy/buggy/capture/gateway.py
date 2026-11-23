"""The capture gateway: scope check, approval gate, rate limit, send, record.

Order of checks for every request, each of which can stop it before a byte
leaves:

1. the engagement has an enforced scope, and the URL's host is in it; the
   operator has not halted the engagement (``buggy-cli halt``, see
   :mod:`buggy.capture.halt`), and its halt state can be read;
2. if the method can change state and the engagement requires approval, a
   human has allowed this exact request (method + URL + body);
3. the engagement's rate limit.

Only then is the request sent, and whatever happens (response, error) is
recorded with a ledger line.

A request may name an ``identity`` (see :mod:`buggy.capture.identities`). The
gateway then attaches that test account's session, logging in first if it has
none. The login is itself a request through :meth:`CaptureGateway.send`, marked
``internal``. That flag waives check 2 and nothing else, and only for a request
the operator declared as an identity's login in the secrets root: scope, the
internal-address block, the rate limit, the capture and the ledger line all
still apply, and the ledger line says ``internal_login`` where an approval id
would be.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from buggy.capture import halt as halt_switch
from buggy.capture.identities import (
    Identity,
    IdentityError,
    IdentityStore,
    LoginError,
    Session,
    SessionManager,
    UnknownIdentity,
)
from buggy.capture.store import Capture, CaptureStore, request_fingerprint, sha256_hex
from buggy.egress_guard.ledger import Ledger
from buggy.pipeline.http import RateLimiter
from buggy.pipeline.schema import as_dict, host_of
from buggy.pipeline.scope import ScopeError, ScopeFilter

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
MAX_RESPONSE = 5 * 1024 * 1024
MAX_REQUEST_BODY = 1024 * 1024
USER_AGENT = "buggy-capture/1 (authorized security testing)"
# Headers the caller may not set: they describe the connection, not the request.
_BLOCKED_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "connection",
        "transfer-encoding",
        "proxy-authorization",
        "te",
        "upgrade",
    }
)
APPROVAL_MAX_USES = 3
# One approved probe run may send at most this many requests (the largest probe sends 11).
PROBE_RUN_MAX_REQUESTS = 40
# What a capture and its ledger line carry instead of an approval id when the
# request was the gateway's own login for a declared identity.
log = logging.getLogger("buggy.capture.gateway")

INTERNAL_LOGIN = "internal_login"
# What a capture and its ledger line carry instead of an approval id when the
# request is this gateway's own registration or login for an account the
# account-creation module created (its body holds a fresh password).
ACCOUNT_CREATION = "account_creation"
REDACTED_HASH = "<redacted>"


def _collect_headers(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Response headers as a dict that keeps repeated headers.

    A response usually sets several cookies, each in its own ``Set-Cookie``.
    Those are kept one per line (a cookie's ``Expires`` contains a comma);
    any other repeated header is joined with ``", "`` as HTTP allows.
    """
    out: dict[str, str] = {}
    for key, value in items:
        existing = next((k for k in out if k.lower() == key.lower()), None)
        if existing is None:
            out[key] = value
        else:
            separator = "\n" if key.lower() == "set-cookie" else ", "
            out[existing] = out[existing] + separator + value
    return out


def _with_session(headers: dict[str, str] | None, session: Session) -> dict[str, str]:
    """The caller's headers with the identity's session on top.

    A header the session sets replaces the caller's header of the same name.
    Session cookies are merged into the caller's ``Cookie`` header, again
    winning over a caller cookie of the same name.
    """
    merged = {str(k): str(v) for k, v in (headers or {}).items()}

    def take(name: str) -> list[str]:
        return [merged.pop(k) for k in [k for k in merged if k.lower() == name.lower()]]

    for name, value in session.headers.items():
        take(name)
        merged[name] = value
    if session.cookies:
        jar: dict[str, str] = {}
        for line in take("cookie"):
            for pair in line.split(";"):
                cookie, _, value = pair.strip().partition("=")
                if cookie:
                    jar[cookie] = value
        jar.update(session.cookies)
        merged["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
    return merged


def internal_address_block(url: str, scope: ScopeFilter, document: dict[str, Any]) -> str | None:
    """Why ``url`` must not be contacted because it leads to an internal address.

    An in-scope *name* is not permission to reach whatever it resolves to: a
    DNS record pointing at a private, loopback or link-local address would
    turn the gateway into a way onto the network it runs on. Such a target is
    refused unless the address itself is in scope, or the engagement declares
    ``network.allow_private_targets`` (labs, internal assessments).

    Returns ``None`` when the request may proceed. A name that does not
    resolve is not blocked here; the request simply fails.
    """
    if as_dict(document.get("network")).get("allow_private_targets") is True:
        return None
    host = host_of(url)
    try:
        candidates = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError:
            return None
        candidates = []
        for info in infos:
            try:
                candidates.append(ipaddress.ip_address(str(info[4][0]).split("%")[0]))
            except ValueError:
                continue
    for address in candidates:
        internal = (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        )
        if internal and not scope.allows(str(address)):
            return f"{host} resolves to internal address {address}, which is not itself in scope"
    return None


class GatewayRefusal(Exception):
    """The request was not sent. ``code`` says why; ``detail`` is safe to show the agent."""

    def __init__(self, code: str, detail: str, **extra: Any) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.extra = extra

    def to_dict(self) -> dict[str, Any]:
        return {"status": "refused", "code": self.code, "detail": self.detail, **self.extra}


@dataclass(slots=True)
class ProbeGrant:
    """The operator's approval of one run of one probe or recipe. Only the gateway makes one.

    It covers the requests that run sends to the approved origin (or, for a
    recipe, to any of ``origins``, the literal origins of its steps), up to
    ``remaining``. Scope, the internal-address block and the rate limit apply
    to each of them as to any other request.
    """

    request_id: str
    engagement: str
    probe: str
    origin: str
    remaining: int = PROBE_RUN_MAX_REQUESTS
    origins: frozenset[str] = frozenset()
    cap: int = PROBE_RUN_MAX_REQUESTS


@dataclass(frozen=True, slots=True)
class AccountGrant:
    """Permission for the account-creation module to register and log in accounts.

    The gateway issues one from :meth:`CaptureGateway.account_creation_grant`
    only when the engagement's scope turns account creation on, and only for the
    exact URLs discovered for the sign-up and the accounts' logins. ``send``
    honours it for nothing but a request to one of those URLs, and re-reads the
    policy and re-checks the URL on every request. No tool argument reaches it:
    an agent cannot construct a grant this gateway issued.
    """

    engagement: str
    urls: frozenset[str]
    request_id: str


def origin_of(url: str) -> str:
    """``scheme://host[:port]`` of a URL, lower-cased; ``""`` when it has none."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}".lower()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


@dataclass(frozen=True, slots=True)
class Roots:
    """Where the gateway reads scope, approvals and identities, and writes its records."""

    control: Path
    audit: Path
    data: Path
    # Operator-written test accounts; never mounted into an agent-facing container.
    secrets: Path = Path("/secrets")

    @classmethod
    def from_env(cls) -> Roots:
        return cls(
            control=Path(os.environ.get("BUGGY_CONTROL_ROOT") or "/control"),
            audit=Path(os.environ.get("BUGGY_AUDIT_ROOT") or "/audit"),
            data=Path(os.environ.get("BUGGY_CAPTURE_DATA") or "/data/capture"),
            secrets=Path(os.environ.get("BUGGY_SECRETS_ROOT") or "/secrets"),
        )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
    except FileNotFoundError:
        pass
    return rows


class CaptureGateway:
    def __init__(
        self,
        roots: Roots,
        *,
        store: CaptureStore | None = None,
        opener: Any = None,
        sleep: Any = time.sleep,
        timeout: float = 20.0,
    ) -> None:
        self.roots = roots
        self.store = store or CaptureStore(roots.data / "captures.sqlite3")
        self._opener = opener or urllib.request.build_opener(_NoRedirect)
        self._sleep = sleep
        self._timeout = timeout
        self._lock = threading.Lock()
        self._limiters: dict[tuple[str, int], RateLimiter] = {}
        self._ledgers: dict[str, Ledger] = {}
        self.identities = IdentityStore(roots.secrets, accounts_root=roots.data / "accounts")
        self.sessions = SessionManager(self, self.identities)
        # Called with the request record when a NEW approval request is filed
        # (the capture server sets it to notify the operator). Never raises here.
        self.on_approval_request: Any = None
        self._grants: dict[str, ProbeGrant] = {}
        self._account_grants: dict[str, AccountGrant] = {}

    # ── scope / policy ──────────────────────────────────────────────

    def scope_for(self, engagement: str) -> tuple[ScopeFilter, dict[str, Any]]:
        if not engagement or "/" in engagement or engagement.startswith("."):
            raise GatewayRefusal("BAD_ENGAGEMENT", "engagement name is required")
        path = self.roots.control / engagement / "roe.json"
        try:
            scope = ScopeFilter.from_file(path)
            document = json.loads(path.read_text(encoding="utf-8"))
        except ScopeError as exc:
            raise GatewayRefusal("NO_ENFORCED_SCOPE", str(exc)) from exc
        return scope, document

    def check_halt(self, engagement: str, method: str = "", url: str = "") -> None:
        """Refuse (``HALTED``, with a ledger line) while the operator has halted the engagement.

        A halt state that exists but cannot be read is a refusal too
        (``HALT_STATE_UNREADABLE``): the gateway fails closed.
        """
        try:
            state = halt_switch.read_state(self.roots.control, engagement)
        except halt_switch.ControlStateError as exc:
            self._refused(engagement, method or "CHECK", url, "HALT_STATE_UNREADABLE")
            raise GatewayRefusal(
                "HALT_STATE_UNREADABLE",
                f"the operator's halt state for {engagement} cannot be read ({exc}); not sent",
            ) from exc
        if state.halted:
            self._refused(engagement, method or "CHECK", url, "HALTED")
            raise GatewayRefusal(
                "HALTED", f"{halt_switch.refusal_text(engagement, state)}; not sent"
            )

    @staticmethod
    def approval_required(document: dict[str, Any]) -> bool:
        """State-changing requests need a human unless the scope explicitly waives it."""
        setting = str(as_dict(document.get("approvals")).get("state_changing", "required")).lower()
        return setting != "not_required"

    def _limiter(self, engagement: str, rps: int) -> RateLimiter:
        with self._lock:
            key = (engagement, rps)
            if key not in self._limiters:
                self._limiters[key] = RateLimiter(rps, sleep=self._sleep)
            return self._limiters[key]

    def _ledger(self, engagement: str) -> Ledger:
        with self._lock:
            if engagement not in self._ledgers:
                self._ledgers[engagement] = Ledger(self.roots.audit / engagement / "captures.jsonl")
            return self._ledgers[engagement]

    # ── approvals ───────────────────────────────────────────────────

    def _approval_paths(self, engagement: str) -> tuple[Path, Path]:
        return (
            self.roots.audit / engagement / "approvals" / "requests.jsonl",
            self.roots.control / engagement / "approvals" / "decisions.jsonl",
        )

    def _approval_state(self, engagement: str, fingerprint: str, spent: Any) -> tuple[str, str]:
        """``(approved_id, pending_id)`` for a fingerprint; either may be ``""``.

        Raises ``APPROVAL_DENIED`` when the operator refused it. ``spent`` says
        whether an allowed request id has been used up.
        """
        requests_path, decisions_path = self._approval_paths(engagement)
        mine = [
            r
            for r in _read_jsonl(requests_path)
            if as_dict(r.get("metadata")).get("fingerprint") == fingerprint
        ]
        decisions = {str(d.get("request_id")): d for d in _read_jsonl(decisions_path)}
        for request in mine:
            decision = decisions.get(str(request.get("request_id")))
            if decision is None:
                continue
            request_id = str(request["request_id"])
            if str(decision.get("action")) != "allow":
                raise GatewayRefusal(
                    "APPROVAL_DENIED",
                    "the operator denied this request; do not retry it",
                    request_id=request_id,
                    operator_note=str(decision.get("operator_note") or ""),
                )
            if spent(request_id):
                continue  # this approval is spent; a new request is filed
            return request_id, ""
        pending = [r for r in mine if str(r.get("request_id")) not in decisions]
        return "", (str(pending[-1]["request_id"]) if pending else "")

    def _file_request(self, engagement: str, record: dict[str, Any]) -> None:
        requests_path, _ = self._approval_paths(engagement)
        requests_path.parent.mkdir(parents=True, exist_ok=True)
        with requests_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        if self.on_approval_request is not None:
            try:
                self.on_approval_request(record)
            except Exception:  # noqa: BLE001 - telling the operator must not change the hold
                log.warning("the approval-request hook failed", exc_info=True)

    def _check_approval(
        self, engagement: str, method: str, url: str, body: bytes, note: str, identity: str = ""
    ) -> str:
        """Return the approving request id, or raise a refusal that names the pending request.

        An approval covers one exact request sent as one identity: allowing a
        request as one test account does not allow the same request as another.
        """
        fingerprint = request_fingerprint(method, url, body)
        if identity:
            fingerprint = sha256_hex(f"{fingerprint}|identity:{identity}".encode())

        def spent(request_id: str) -> bool:
            used = sum(
                1 for c in self.store.list(engagement, limit=500) if c.approval_id == request_id
            )
            return used >= APPROVAL_MAX_USES

        approved, request_id = self._approval_state(engagement, fingerprint, spent)
        if approved:
            return approved
        if not request_id:
            request_id = f"apr-{uuid.uuid4().hex[:12]}"
            self._file_request(
                engagement,
                {
                    "kind": "approval_request",
                    "request_id": request_id,
                    "engagement_name": engagement,
                    "agent_name": "capture-gateway",
                    "tool_name": "http_send",
                    "tool_args_redacted": {
                        "method": method,
                        "url": url,
                        "body_sha256": sha256_hex(body),
                        "body_preview": body[:400].decode("utf-8", "replace"),
                        "identity": identity,
                    },
                    "matched_rule": {
                        "technique_tag": None,
                        "tool_pattern": "state-changing HTTP method",
                        "timeout_seconds": 0,
                        "default_on_timeout": "deny",
                    },
                    "reason": note or f"{method} can change state on the target",
                    "created_at": time.time(),
                    "metadata": {"fingerprint": fingerprint},
                },
            )
        raise GatewayRefusal(
            "APPROVAL_REQUIRED",
            f"{method} can change state on the target, so a human must approve this exact "
            f"request first (buggy-cli approvals allow {engagement} {request_id}). Nothing was "
            "sent. Re-send the identical request after it is approved.",
            request_id=request_id,
        )

    # ── approval of a whole probe run ───────────────────────────────

    def _used_runs_path(self, engagement: str) -> Path:
        return self.roots.audit / engagement / "approvals" / "probe-runs-used.jsonl"

    def probe_grant(
        self, engagement: str, probe: str, params: dict[str, Any], *, sends: str = ""
    ) -> ProbeGrant | None:
        """The operator's approval for one run of a state-changing probe.

        A probe uses fresh random markers on every run, so no single request of
        it can be approved in advance. What is approved instead is the run: this
        probe, on this URL, with these parameters (``identity`` among them, so a
        run approved as one test account does not cover the same run as another).
        Returns ``None`` when the engagement does not require approval; otherwise
        the grant, or a refusal that names the request the operator has to decide. One approval is one
        run: it is used up the moment the grant is issued.
        """
        scope, document = self.scope_for(engagement)
        if not self.approval_required(document):
            return None
        url = str(params.get("url") or "")
        origin = origin_of(url)
        if not origin:
            return None  # the probe itself reports the missing or malformed URL
        allowed, reason = scope.decide(url)
        if not allowed:
            self._refused(engagement, "PROBE", url, reason)
            raise GatewayRefusal(
                "OUT_OF_SCOPE",
                f"{host_of(url)!r} is not in the enforced scope ({reason}); not sent",
            )
        canonical = json.dumps(params, sort_keys=True, default=str)
        fingerprint = sha256_hex(f"probe-run|{probe}|{canonical}".encode())
        body = params.get("body")
        preview = body if isinstance(body, str) else json.dumps(body, default=str)
        return self._run_grant(
            engagement,
            probe,
            fingerprint,
            frozenset({origin}),
            PROBE_RUN_MAX_REQUESTS,
            tool_name="probe_run",
            shown={
                "probe": probe,
                "url": url,
                "method": str(params.get("method") or "").upper(),
                "parameter": str(params.get("parameter") or params.get("field") or ""),
                "location": str(params.get("location") or ""),
                "what_it_sends": sends,
                "max_requests": PROBE_RUN_MAX_REQUESTS,
                "header_names": sorted(str(k) for k in as_dict(params.get("headers"))),
                "identity": str(params.get("identity") or ""),
                "body_preview": "" if body is None else preview[:400],
                "params_sha256": sha256_hex(canonical.encode()),
            },
            reason=f"one run of the {probe} probe, which can change state on the target",
            refusal=(
                f"the {probe} probe can change state on the target, so a human must approve "
                "this run first"
            ),
            again="Run the probe again with the same parameters after it is approved",
        )

    def recipe_grant(
        self,
        engagement: str,
        name: str,
        canonical: str,
        urls: Iterable[str],
        shown: dict[str, Any],
        max_requests: int,
    ) -> ProbeGrant | None:
        """The operator's approval for one run of a state-changing recipe (``buggy.capture.recipes``).

        The same mechanism as :meth:`probe_grant`: what is approved is one run
        of this exact recipe (``canonical`` is its canonical JSON, so an edited
        recipe needs a new approval), sent to the literal origins of its step
        URLs and capped at ``max_requests``. Every step URL must be in scope
        before anything is filed. Returns ``None`` when the engagement does not
        require approval. ``shown`` is what the operator reads (no header values).
        """
        scope, document = self.scope_for(engagement)
        url_list = [str(u) for u in urls]
        for url in url_list:
            allowed, reason = scope.decide(url)
            if not allowed:
                self._refused(engagement, "RECIPE", url, reason)
                raise GatewayRefusal(
                    "OUT_OF_SCOPE",
                    f"{host_of(url)!r} is not in the enforced scope ({reason}); not sent",
                )
        if not self.approval_required(document):
            return None
        origins = frozenset(o for o in (origin_of(u) for u in url_list) if o)
        label = f"recipe:{name}"
        fingerprint = sha256_hex(f"recipe-run|{name}|{canonical}".encode())
        return self._run_grant(
            engagement,
            label,
            fingerprint,
            origins,
            max(1, int(max_requests)),
            tool_name="recipe_run",
            shown={
                **shown,
                "max_requests": max(1, int(max_requests)),
                "recipe_sha256": sha256_hex(canonical.encode()),
            },
            reason=f"one run of the recipe {name}, which can change state on the target",
            refusal=(
                f"the recipe {name} can change state on the target, so a human must approve "
                "this run first"
            ),
            again="Run the identical recipe again after it is approved",
        )

    def check_target(self, engagement: str, url: str, method: str = "") -> None:
        """Refuse (``OUT_OF_SCOPE``, with a ledger line) unless ``url``'s host is in scope.

        Sends nothing; for callers that must know every target is allowed
        before the first of several requests leaves.
        """
        scope, _document = self.scope_for(engagement)
        allowed, reason = scope.decide(url)
        if not allowed:
            self._refused(engagement, method or "CHECK", url, reason)
            raise GatewayRefusal(
                "OUT_OF_SCOPE",
                f"{host_of(url)!r} is not in the enforced scope ({reason}); not sent",
            )
        self.check_halt(engagement, method, url)

    def _run_grant(
        self,
        engagement: str,
        probe: str,
        fingerprint: str,
        origins: frozenset[str],
        cap: int,
        *,
        tool_name: str,
        shown: dict[str, Any],
        reason: str,
        refusal: str,
        again: str,
    ) -> ProbeGrant:
        """Issue the grant for an allowed run, or file (once) and refuse with the request id."""
        used_path = self._used_runs_path(engagement)

        def spent(request_id: str) -> bool:
            return any(str(u.get("request_id")) == request_id for u in _read_jsonl(used_path))

        with self._lock:
            approved, request_id = self._approval_state(engagement, fingerprint, spent)
            if approved:
                used_path.parent.mkdir(parents=True, exist_ok=True)
                with used_path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps({"request_id": approved, "probe": probe, "used_at": time.time()})
                        + "\n"
                    )
                primary = sorted(origins)[0] if origins else ""
                grant = ProbeGrant(
                    approved, engagement, probe, primary, cap, origins=origins, cap=cap
                )
                self._grants[approved] = grant
                return grant
        if not request_id:
            request_id = f"apr-{uuid.uuid4().hex[:12]}"
            self._file_request(
                engagement,
                {
                    "kind": "approval_request",
                    "request_id": request_id,
                    "engagement_name": engagement,
                    "agent_name": "capture-gateway",
                    "tool_name": tool_name,
                    "tool_args_redacted": shown,
                    "matched_rule": {
                        "technique_tag": None,
                        "tool_pattern": f"state-changing {tool_name.replace('_', ' ')}",
                        "timeout_seconds": 0,
                        "default_on_timeout": "deny",
                    },
                    "reason": reason,
                    "created_at": time.time(),
                    "metadata": {"fingerprint": fingerprint, "kind": tool_name},
                },
            )
        raise GatewayRefusal(
            "APPROVAL_REQUIRED",
            f"{refusal} (buggy-cli approvals allow {engagement} {request_id}). Nothing was sent. "
            f"{again}; one approval covers one run.",
            request_id=request_id,
        )

    def _grant_approval(
        self, grant: ProbeGrant | None, engagement: str, probe: str, url: str
    ) -> str:
        """The approval id a grant gives this request, or ``""`` when it does not cover it."""
        if (
            grant is None
            or self._grants.get(grant.request_id) is not grant
            or grant.engagement != engagement
            or grant.probe != probe
            or origin_of(url) not in (grant.origins | {grant.origin})
        ):
            return ""
        with self._lock:
            if grant.remaining <= 0:
                raise GatewayRefusal(
                    "APPROVAL_SPENT",
                    f"the approved run of {probe} has sent its {grant.cap} requests; not sent",
                    request_id=grant.request_id,
                )
            grant.remaining -= 1
        return grant.request_id

    # ── account creation ────────────────────────────────────────────

    def account_creation_grant(self, engagement: str, urls: Iterable[str]) -> AccountGrant:
        """Permission to register and log in accounts, for the URLs the module found.

        Issued only when the engagement's scope turns account creation on
        (``machine_enforcement.account_creation``), and only for ``urls`` that
        are in the enforced scope. Raises ``NOT_ENABLED`` when the switch is off,
        ``BAD_ACCOUNT_POLICY`` when the block is malformed, or ``OUT_OF_SCOPE``.
        Only the account-creation module calls this.
        """
        from buggy.capture.accounts import AccountPolicyError, account_creation_policy

        scope, document = self.scope_for(engagement)
        try:
            policy = account_creation_policy(document)
        except AccountPolicyError as exc:
            raise GatewayRefusal("BAD_ACCOUNT_POLICY", str(exc)) from exc
        if policy is None:
            raise GatewayRefusal(
                "NOT_ENABLED",
                "account creation is not enabled for this engagement in the scope document; "
                "nothing was sent",
            )
        clean: set[str] = set()
        for url in urls:
            if not url:
                continue
            allowed, reason = scope.decide(url)
            if not allowed:
                raise GatewayRefusal(
                    "OUT_OF_SCOPE",
                    f"{host_of(url)!r} is not in the enforced scope ({reason}); not sent",
                )
            clean.add(url)
        grant = AccountGrant(engagement, frozenset(clean), f"acr-{uuid.uuid4().hex[:12]}")
        self._account_grants[grant.request_id] = grant
        return grant

    def _account_creation_approval(
        self, grant: AccountGrant, engagement: str, method: str, url: str, document: dict[str, Any]
    ) -> str:
        """The approval id for an account-creation request, re-checking policy and URL.

        Raises a refusal (and records a dropped-request ledger line) when the
        grant was not issued here, the engagement differs, the policy is off or
        malformed, or the URL is not one of the grant's.
        """
        from buggy.capture.accounts import AccountPolicyError, account_creation_policy

        if (
            self._account_grants.get(grant.request_id) is not grant
            or grant.engagement != engagement
        ):
            raise GatewayRefusal(
                "NOT_A_DECLARED_LOGIN",
                "this account-creation grant was not issued for this engagement; not sent",
            )
        try:
            policy = account_creation_policy(document)
        except AccountPolicyError as exc:
            self._refused(engagement, method, url, "BAD_ACCOUNT_POLICY")
            raise GatewayRefusal("BAD_ACCOUNT_POLICY", str(exc)) from exc
        if policy is None:
            self._refused(engagement, method, url, "NOT_ENABLED")
            raise GatewayRefusal(
                "NOT_ENABLED",
                "account creation is not enabled for this engagement in the scope document; "
                "nothing was sent",
            )
        if url not in grant.urls:
            self._refused(engagement, method, url, "NOT_AN_ACCOUNT_URL")
            raise GatewayRefusal(
                "NOT_AN_ACCOUNT_URL",
                "only the discovered sign-up URL or an account's login URL may be sent under an "
                "account-creation grant; not sent",
            )
        return ACCOUNT_CREATION

    # ── sending ─────────────────────────────────────────────────────

    def send(
        self,
        engagement: str,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        note: str = "",
        probe: str = "",
        replay_of: str = "",
        identity: str = "",
        internal: bool = False,
        grant: ProbeGrant | None = None,
        account_grant: AccountGrant | None = None,
    ) -> Capture:
        """Send one request and return its capture, or raise :class:`GatewayRefusal`.

        ``identity`` names a declared test account whose session is attached
        (its headers and cookies win over the caller's of the same name). If
        that session is answered with 401 it is renewed with one login and the
        request is sent once more; both exchanges are recorded and the second
        is returned.

        ``internal`` is for the session manager's own login request and waives
        the approval hold only. It is honoured for nothing but a request the
        operator declared as an identity's login; no tool argument reaches it.

        ``grant`` is an approved probe run (:meth:`probe_grant`); only an object
        this gateway issued is honoured, and no tool argument reaches it either.

        ``account_grant`` is the account-creation module's permission
        (:meth:`account_creation_grant`); like ``internal`` it waives the
        approval hold only, for nothing but a request to the sign-up or a
        created account's login URL, and no tool argument reaches it.
        """
        return self._send(
            engagement,
            method,
            url,
            headers=headers,
            body=body,
            note=note,
            probe=probe,
            replay_of=replay_of,
            identity=identity,
            internal=internal,
            grant=grant,
            account_grant=account_grant,
        )

    def _send(
        self,
        engagement: str,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        body: bytes | str | None,
        note: str,
        probe: str,
        replay_of: str,
        identity: str,
        internal: bool = False,
        also_redact: tuple[str, ...] = (),
        grant: ProbeGrant | None = None,
        account_grant: AccountGrant | None = None,
    ) -> Capture:
        def exchange(session: Session | None) -> tuple[Capture, Session | None, bool]:
            return self._exchange(
                engagement,
                method,
                url,
                headers=headers,
                body=body,
                note=note,
                probe=probe,
                replay_of=replay_of,
                identity=identity,
                internal=internal,
                also_redact=also_redact,
                session=session,
                grant=grant,
                account_grant=account_grant,
            )

        capture, session, fresh = exchange(None)
        if session is None or session.identity.login is None or fresh or capture.status != 401:
            return capture
        # A cached session was rejected: it expired or was revoked. Log in once and
        # ask again. Every check runs again for the second request, so if it cannot
        # be sent (the login fails, an approval is spent) the 401 is the answer.
        try:
            renewed, _ = self._session(engagement, identity, rejected=session)
            return exchange(renewed)[0]
        except GatewayRefusal:
            return capture

    def _session(
        self, engagement: str, identity: str, *, rejected: Session | None = None
    ) -> tuple[Session, bool]:
        """The identity's session (and whether it is new), or a refusal safe to show."""
        try:
            if rejected is not None:
                return self.sessions.renew(engagement, identity, rejected), True
            return self.sessions.session_for(engagement, identity)
        except UnknownIdentity:
            raise GatewayRefusal(
                "UNKNOWN_IDENTITY",
                f"no identity {identity!r} is declared for this engagement; not sent",
            ) from None
        except IdentityError as exc:
            raise GatewayRefusal(
                "BAD_IDENTITIES", f"the engagement's identities file is invalid ({exc}); not sent"
            ) from exc
        except LoginError as exc:
            raise GatewayRefusal("LOGIN_FAILED", f"{exc}; the request was not sent") from exc
        except GatewayRefusal as exc:
            raise GatewayRefusal(
                "LOGIN_FAILED",
                f"the login for identity {identity!r} was refused ({exc.code}: {exc.detail}); "
                "the request was not sent",
            ) from exc

    def check_identity(self, engagement: str, identity: str) -> None:
        """Refuse (``UNKNOWN_IDENTITY`` / ``BAD_IDENTITIES``) unless ``identity`` is declared.

        Nothing is sent and no session is opened: this only reads the operator's file.
        """
        try:
            self.identities.get(engagement, identity)
        except UnknownIdentity:
            raise GatewayRefusal(
                "UNKNOWN_IDENTITY",
                f"no identity {identity!r} is declared for this engagement; not sent",
            ) from None
        except IdentityError as exc:
            raise GatewayRefusal(
                "BAD_IDENTITIES", f"the engagement's identities file is invalid ({exc}); not sent"
            ) from exc

    def _refused(self, engagement: str, method: str, url: str, reason: str) -> None:
        self._ledger(engagement).append(
            {
                "ts": time.time(),
                "event": "capture_refused",
                "engagement": engagement,
                "decision": "drop",
                "method": method,
                "url": url,
                "reason": reason,
            }
        )

    def _exchange(
        self,
        engagement: str,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        body: bytes | str | None,
        note: str,
        probe: str,
        replay_of: str,
        identity: str,
        internal: bool,
        also_redact: tuple[str, ...],
        session: Session | None,
        grant: ProbeGrant | None = None,
        account_grant: AccountGrant | None = None,
    ) -> tuple[Capture, Session | None, bool]:
        """One request through every check. Returns the capture, the session used and
        whether that session was opened (logged in) for this request."""
        method = (method or "").upper()
        if method not in ALLOWED_METHODS:
            raise GatewayRefusal("BAD_METHOD", f"method must be one of {sorted(ALLOWED_METHODS)}")
        parts = urlsplit(url or "")
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise GatewayRefusal("BAD_URL", "url must be an absolute http(s) URL")
        if parts.username or parts.password:
            raise GatewayRefusal("BAD_URL", "credentials in the URL are not accepted; use a header")
        payload = body.encode("utf-8") if isinstance(body, str) else (body or b"")
        if len(payload) > MAX_REQUEST_BODY:
            raise GatewayRefusal("BODY_TOO_LARGE", f"request body exceeds {MAX_REQUEST_BODY} bytes")
        if not isinstance(identity, str) or (identity and internal):
            raise GatewayRefusal("BAD_ARGUMENT", "identity must be a name; a login names none")
        if account_grant is not None and (internal or identity):
            raise GatewayRefusal(
                "BAD_ARGUMENT", "an account-creation request names no identity and is not internal"
            )

        scope, document = self.scope_for(engagement)
        allowed, reason = scope.decide(url)
        if not allowed:
            self._refused(engagement, method, url, reason)
            raise GatewayRefusal(
                "OUT_OF_SCOPE",
                f"{host_of(url)!r} is not in the enforced scope ({reason}); not sent",
            )

        self.check_halt(engagement, method, url)

        blocked = internal_address_block(url, scope, document)
        if blocked is not None:
            self._refused(engagement, method, url, "INTERNAL_ADDRESS")
            raise GatewayRefusal("INTERNAL_ADDRESS", f"{blocked}; not sent")

        # Who is asking. An unknown name stops here, before an approval is filed.
        logins: list[Identity] = []
        if identity:
            self.check_identity(engagement, identity)
        if internal is True:
            try:
                logins = self.identities.logins_at(engagement, method, url)
            except IdentityError as exc:
                raise GatewayRefusal(
                    "BAD_IDENTITIES",
                    f"the engagement's identities file is invalid ({exc}); not sent",
                ) from exc

        approval_id = ""
        if account_grant is not None:
            # The account-creation exemption: the module registers or logs in an
            # account the operator turned on. Policy and URL are re-checked here.
            approval_id = self._account_creation_approval(
                account_grant, engagement, method, url, document
            )
        elif internal is True and logins:
            # The one exemption from the approval hold: the operator wrote this
            # request down as a test account's login. Recorded as such below.
            approval_id = INTERNAL_LOGIN
        elif internal:
            self._refused(engagement, method, url, "NOT_A_DECLARED_LOGIN")
            raise GatewayRefusal(
                "NOT_A_DECLARED_LOGIN",
                "only a login request the operator declared for an identity of this "
                "engagement may be sent as internal; not sent",
            )
        else:
            # A request of an approved probe run is recorded under that approval,
            # whatever its method; anything else state-changing is held one by one.
            approval_id = self._grant_approval(grant, engagement, probe, url)
            if not approval_id and method not in SAFE_METHODS and self.approval_required(document):
                approval_id = self._check_approval(engagement, method, url, payload, note, identity)

        fresh = False
        redact_headers = set(also_redact)
        if identity:
            if session is None:
                session, fresh = self._session(engagement, identity)
            headers = _with_session(headers, session)
            redact_headers.update(session.identity.session_header_names())
        for login_identity in logins:
            redact_headers.update(login_identity.login_header_names())

        clean = {
            str(k): str(v)
            for k, v in (headers or {}).items()
            if str(k).lower() not in _BLOCKED_HEADERS and "\n" not in str(v) and "\r" not in str(v)
        }
        clean.setdefault("User-Agent", USER_AGENT)
        self._limiter(engagement, scope.limits.rate_limit_rps).wait()

        request = urllib.request.Request(  # noqa: S310 - scheme and scope checked above
            url,
            data=payload if payload or method not in SAFE_METHODS else None,
            method=method,
            headers=clean,
        )
        started = time.monotonic()
        status: int | None = None
        response_headers: dict[str, str] = {}
        response_body = b""
        error = ""
        try:
            with self._opener.open(request, timeout=self._timeout) as raw:
                status = raw.status
                response_headers = _collect_headers(raw.headers.items())
                response_body = raw.read(MAX_RESPONSE)
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = _collect_headers(exc.headers.items() if exc.headers else [])
            response_body = exc.read(MAX_RESPONSE) if exc.fp else b""
        except (OSError, ValueError) as exc:
            error = f"{type(exc).__name__}: {exc}"[:300]
        elapsed = (time.monotonic() - started) * 1000

        capture = self.store.add(
            engagement=engagement,
            method=method,
            url=url,
            host=host_of(url),
            request_headers=clean,
            request_body=payload,
            status=status,
            response_headers=response_headers,
            response_body=response_body,
            elapsed_ms=elapsed,
            error=error,
            note=note,
            probe=probe,
            replay_of=replay_of,
            approval_id=approval_id,
            scope_digest=scope.digest,
            identity=identity,
            redact_headers=tuple(sorted(redact_headers)),
            redact_bodies=approval_id in (INTERNAL_LOGIN, ACCOUNT_CREATION),
        )
        self._ledger(engagement).append(
            {
                "ts": capture.created_at,
                "event": "capture",
                "engagement": engagement,
                "capture_id": capture.id,
                "method": method,
                "url": url,
                "status": status,
                # A login or registration body holds a password: its hash would
                # allow offline guessing.
                "request_sha256": (
                    REDACTED_HASH
                    if approval_id in (INTERNAL_LOGIN, ACCOUNT_CREATION)
                    else capture.request_sha256
                ),
                "response_sha256": capture.response_sha256,
                "probe": probe,
                "replay_of": replay_of,
                "approval_id": approval_id,
                "identity": identity,
                "scope_sha256": scope.digest,
                "error": error,
            }
        )
        return capture, session, fresh

    def replay(self, engagement: str, capture_id: str, *, note: str = "") -> dict[str, Any]:
        """Re-send a captured request from the gateway and compare the outcomes.

        A request sent as an identity is replayed as that identity, with its
        current session. The gateway's own login exchanges are not replayable:
        only the session manager sends an account's password.
        """
        original = self.store.get(engagement, capture_id)
        if original is None:
            raise GatewayRefusal("UNKNOWN_CAPTURE", f"no capture {capture_id!r} in this engagement")
        if original.approval_id == INTERNAL_LOGIN or original.redact_bodies:
            raise GatewayRefusal(
                "LOGIN_NOT_REPLAYABLE",
                f"{capture_id} is the gateway's login for an identity and cannot be replayed; "
                "send a request with that identity instead",
            )
        fresh = self._send(
            engagement,
            original.method,
            original.url,
            headers=original.request_headers,
            body=original.request_body,
            note=note or f"replay of {capture_id}",
            probe=original.probe,
            replay_of=capture_id,
            identity=original.identity,
            also_redact=original.redact_headers,
        )
        return {
            "original": original.summary(),
            "replay": fresh.summary(),
            "same_status": original.status == fresh.status,
            "same_body": original.response_sha256 == fresh.response_sha256,
            "length_delta": fresh.response_bytes - original.response_bytes,
            "reproduced": original.status == fresh.status and not fresh.error,
        }

    def verify(self, engagement: str, capture_id: str, *, expect_host: str = "") -> dict[str, Any]:
        """Whether a capture exists, belongs to this engagement and is in the current scope."""
        capture = self.store.get(engagement, capture_id)
        if capture is None:
            return {"valid": False, "reason": "no such capture in this engagement"}
        scope, _document = self.scope_for(engagement)
        if not scope.allows(capture.url):
            return {"valid": False, "reason": "capture target is not in the enforced scope"}
        if expect_host and host_of(expect_host) != capture.host:
            return {
                "valid": False,
                "reason": f"capture is for {capture.host}, not {host_of(expect_host)}",
            }
        if capture.error or capture.status is None:
            return {"valid": False, "reason": "capture recorded a transport error, not a response"}
        return {"valid": True, "capture": capture.summary(), "host": capture.host}


__all__ = [
    "ACCOUNT_CREATION",
    "ALLOWED_METHODS",
    "INTERNAL_LOGIN",
    "SAFE_METHODS",
    "AccountGrant",
    "CaptureGateway",
    "GatewayRefusal",
    "Roots",
    "internal_address_block",
]
