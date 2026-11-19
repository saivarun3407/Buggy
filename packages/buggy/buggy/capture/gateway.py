"""The capture gateway: scope check, approval gate, rate limit, send, record.

Order of checks for every request, each of which can stop it before a byte
leaves:

1. the engagement has an enforced scope, and the URL's host is in it;
2. if the method can change state and the engagement requires approval, a
   human has allowed this exact request (method + URL + body);
3. the engagement's rate limit.

Only then is the request sent, and whatever happens (response, error) is
recorded with a ledger line.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


@dataclass(frozen=True, slots=True)
class Roots:
    """Where the gateway reads scope and approvals, and writes its records."""

    control: Path
    audit: Path
    data: Path

    @classmethod
    def from_env(cls) -> Roots:
        return cls(
            control=Path(os.environ.get("BUGGY_CONTROL_ROOT") or "/control"),
            audit=Path(os.environ.get("BUGGY_AUDIT_ROOT") or "/audit"),
            data=Path(os.environ.get("BUGGY_CAPTURE_DATA") or "/data/capture"),
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

    def _check_approval(
        self, engagement: str, method: str, url: str, body: bytes, note: str
    ) -> str:
        """Return the approving request id, or raise a refusal that names the pending request."""
        fingerprint = request_fingerprint(method, url, body)
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
            used = sum(
                1 for c in self.store.list(engagement, limit=500) if c.approval_id == request_id
            )
            if used >= APPROVAL_MAX_USES:
                continue  # this approval is spent; a new request is filed below
            return request_id
        pending = [r for r in mine if str(r.get("request_id")) not in decisions]
        if pending:
            request_id = str(pending[-1]["request_id"])
        else:
            request_id = f"apr-{uuid.uuid4().hex[:12]}"
            record = {
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
            }
            requests_path.parent.mkdir(parents=True, exist_ok=True)
            with requests_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        raise GatewayRefusal(
            "APPROVAL_REQUIRED",
            f"{method} can change state on the target, so a human must approve this exact "
            f"request first (buggy-cli approvals allow {engagement} {request_id}). Nothing was "
            "sent. Re-send the identical request after it is approved.",
            request_id=request_id,
        )

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
    ) -> Capture:
        """Send one request and return its capture, or raise :class:`GatewayRefusal`."""
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

        scope, document = self.scope_for(engagement)
        allowed, reason = scope.decide(url)
        if not allowed:
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
            raise GatewayRefusal(
                "OUT_OF_SCOPE",
                f"{host_of(url)!r} is not in the enforced scope ({reason}); not sent",
            )

        internal = internal_address_block(url, scope, document)
        if internal is not None:
            self._ledger(engagement).append(
                {
                    "ts": time.time(),
                    "event": "capture_refused",
                    "engagement": engagement,
                    "decision": "drop",
                    "method": method,
                    "url": url,
                    "reason": "INTERNAL_ADDRESS",
                }
            )
            raise GatewayRefusal("INTERNAL_ADDRESS", f"{internal}; not sent")

        approval_id = ""
        if method not in SAFE_METHODS and self.approval_required(document):
            approval_id = self._check_approval(engagement, method, url, payload, note)

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
                response_headers = {k: v for k, v in raw.headers.items()}
                response_body = raw.read(MAX_RESPONSE)
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
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
                "request_sha256": capture.request_sha256,
                "response_sha256": capture.response_sha256,
                "probe": probe,
                "replay_of": replay_of,
                "approval_id": approval_id,
                "scope_sha256": scope.digest,
                "error": error,
            }
        )
        return capture

    def replay(self, engagement: str, capture_id: str, *, note: str = "") -> dict[str, Any]:
        """Re-send a captured request from the gateway and compare the outcomes."""
        original = self.store.get(engagement, capture_id)
        if original is None:
            raise GatewayRefusal("UNKNOWN_CAPTURE", f"no capture {capture_id!r} in this engagement")
        fresh = self.send(
            engagement,
            original.method,
            original.url,
            headers=original.request_headers,
            body=original.request_body,
            note=note or f"replay of {capture_id}",
            probe=original.probe,
            replay_of=capture_id,
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
    "ALLOWED_METHODS",
    "SAFE_METHODS",
    "CaptureGateway",
    "GatewayRefusal",
    "Roots",
    "internal_address_block",
]
