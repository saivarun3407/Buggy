"""Callback listener for out-of-band checks (SSRF).

A probe mints a one-time token and plants ``<base_url>/c/<token>`` in a
request. If the *target* fetches it, the hit lands here with the caller's
address, and that hit is the evidence: the server made a request it was told
to make. In a lab the listener is reachable on the lab network. Against a
real program the operator must supply a base URL the target can reach
(``BUGGY_CANARY_BASE_URL``); without one the SSRF probe reports that it could
not test, rather than guessing.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class Hit:
    token: str
    at: float
    remote: str
    method: str
    path: str
    user_agent: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "at": self.at,
            "remote": self.remote,
            "method": self.method,
            "path": self.path,
            "user_agent": self.user_agent,
        }


@dataclass
class Canary:
    base_url: str = ""
    _hits: dict[str, list[Hit]] = field(default_factory=dict)
    _tokens: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _server: ThreadingHTTPServer | None = None

    @property
    def available(self) -> bool:
        return bool(self.base_url)

    def mint(self, engagement: str) -> tuple[str, str]:
        """``(token, url)`` for a new canary bound to ``engagement``."""
        token = secrets.token_hex(12)
        with self._lock:
            self._tokens[token] = engagement
            self._hits[token] = []
        return token, f"{self.base_url.rstrip('/')}/c/{token}"

    def record(self, token: str, *, remote: str, method: str, path: str, user_agent: str) -> bool:
        with self._lock:
            if token not in self._tokens:
                return False
            self._hits[token].append(
                Hit(token, time.time(), remote, method, path, user_agent[:200])
            )
            return True

    def hits(self, engagement: str, token: str) -> list[Hit]:
        with self._lock:
            if self._tokens.get(token) != engagement:
                return []
            return list(self._hits.get(token, []))

    def wait_for_hit(self, engagement: str, token: str, *, timeout: float = 8.0) -> list[Hit]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = self.hits(engagement, token)
            if found:
                return found
            time.sleep(0.2)
        return self.hits(engagement, token)

    def serve(self, host: str, port: int) -> int:
        """Start the listener; return the bound port."""
        canary = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _handle(self) -> None:
                parts = self.path.split("?", 1)[0].strip("/").split("/")
                known = False
                if len(parts) >= 2 and parts[0] == "c":
                    known = canary.record(
                        parts[1],
                        remote=self.client_address[0],
                        method=self.command,
                        path=self.path[:300],
                        user_agent=self.headers.get("User-Agent", ""),
                    )
                body = b"ok" if known else b"not found"
                self.send_response(200 if known else 404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_POST = do_HEAD = do_PUT = _handle  # noqa: N815

        self._server = ThreadingHTTPServer((host, port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return int(self._server.server_address[1])

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


__all__ = ["Canary", "Hit"]
