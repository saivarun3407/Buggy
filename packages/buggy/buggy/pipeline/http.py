"""Scope-checked, rate-limited HTTP for the pipeline's built-in stages.

Used by the stages that are a few HTTP requests rather than a scanner binary
(JS file retrieval, OpenAPI probing, GraphQL introspection). Every request URL
is checked against the scope filter, including each redirect hop: the client
follows redirects itself and stops at the first out-of-scope ``Location``.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from buggy.pipeline.scope import ScopeFilter

USER_AGENT = "buggy-pipeline/1 (authorized security testing)"
MAX_BODY = 5 * 1024 * 1024
MAX_REDIRECTS = 3


class RateLimiter:
    """Minimum spacing between requests: ``rps`` per second, process-wide."""

    def __init__(self, rps: float, *, clock=time.monotonic, sleep=time.sleep) -> None:
        self._interval = 1.0 / rps if rps > 0 else 0.0
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> float:
        """Block until the next slot; return how long was slept."""
        if self._interval <= 0:
            return 0.0
        with self._lock:
            now = self._clock()
            start = max(now, self._next)
            self._next = start + self._interval
        delay = start - now
        if delay > 0:
            self._sleep(delay)
        return max(delay, 0.0)


@dataclass(frozen=True, slots=True)
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8", "replace"))


class OutOfScopeRequest(RuntimeError):
    """A request (or a redirect hop) pointed outside the enforced scope."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):  # noqa: D102
        return None


class ScopedHTTP:
    """``urllib`` client that refuses any URL the scope filter rejects."""

    def __init__(
        self,
        scope: ScopeFilter,
        *,
        stage: str,
        tool: str,
        limiter: RateLimiter | None = None,
        timeout: float = 15.0,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        self._scope = scope
        self._stage = stage
        self._tool = tool
        self._limiter = limiter or RateLimiter(scope.limits.rate_limit_rps)
        self._timeout = timeout
        self._opener = opener or urllib.request.build_opener(_NoRedirect)
        self.requests_sent = 0

    def _check(self, url: str) -> None:
        if urlsplit(url).scheme not in ("http", "https"):
            raise OutOfScopeRequest(f"unsupported scheme: {url}")
        if not self._scope.admit([url], stage=self._stage, tool=self._tool, direction="input"):
            raise OutOfScopeRequest(url)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response | None:
        """Send one request; ``None`` on a transport error. Raises
        :class:`OutOfScopeRequest` before anything is sent to an out-of-scope URL."""
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            self._check(current)
            self._limiter.wait()
            request = urllib.request.Request(  # noqa: S310 - scheme checked in _check
                current,
                data=body,
                method=method,
                headers={"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})},
            )
            self.requests_sent += 1
            try:
                with self._opener.open(request, timeout=self._timeout) as raw:
                    data = raw.read(MAX_BODY + 1)
                    return Response(
                        url=current,
                        status=raw.status,
                        headers={k.lower(): v for k, v in raw.headers.items()},
                        body=data[:MAX_BODY],
                        truncated=len(data) > MAX_BODY,
                    )
            except urllib.error.HTTPError as exc:
                location = exc.headers.get("Location") if exc.headers else None
                if exc.code in (301, 302, 303, 307, 308) and location:
                    current = urljoin(current, location)
                    if exc.code == 303:
                        method, body = "GET", None
                    continue
                data = exc.read(MAX_BODY + 1) if exc.fp else b""
                return Response(
                    url=current,
                    status=exc.code,
                    headers={k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])},
                    body=data[:MAX_BODY],
                    truncated=len(data) > MAX_BODY,
                )
            except (OSError, ValueError):
                return None
        return None

    def get(self, url: str, **kwargs: Any) -> Response | None:
        return self.request(url, **kwargs)

    def post_json(self, url: str, payload: Any) -> Response | None:
        return self.request(
            url,
            method="POST",
            body=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )


def fetch_passive(url: str, *, limiter: RateLimiter, timeout: float = 45.0) -> bytes | None:
    """GET a third-party *passive source* (never a target).

    Only hosts in :data:`PASSIVE_SOURCES` are reachable this way; it exists so
    certificate-transparency lookups do not need the target in the request
    path at all.
    """
    host = (urlsplit(url).hostname or "").lower()
    if urlsplit(url).scheme != "https" or host not in PASSIVE_SOURCES:
        raise OutOfScopeRequest(f"{host or url} is not an allowed passive source")
    limiter.wait()
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as raw:  # noqa: S310
            return raw.read(50 * 1024 * 1024)
    except (OSError, ValueError):
        return None


PASSIVE_SOURCES = frozenset({"crt.sh"})

__all__ = [
    "PASSIVE_SOURCES",
    "OutOfScopeRequest",
    "RateLimiter",
    "Response",
    "ScopedHTTP",
    "fetch_passive",
]
