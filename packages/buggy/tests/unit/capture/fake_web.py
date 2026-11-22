"""A small fake origin for the probes that read bodies, cookies and framing headers.

A handler gets ``(method, url, headers, body)`` (header names lower case) and
answers ``(status, headers, body)``; headers are a list of pairs so a response
can set several cookies. A 3xx or worse comes back to the gateway as an
``HTTPError``, as from a real server.
"""

from __future__ import annotations

import io
import json
import urllib.error
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from buggy.capture.gateway import CaptureGateway, Roots

BASE = "https://app.acme.test"
Reply = tuple[int, list[tuple[str, str]], str]
Handler = Callable[[str, str, dict[str, str], bytes], Reply]
SCOPE = {"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}}
NOT_REQUIRED = {**SCOPE, "approvals": {"state_changing": "not_required"}}


class _Headers(list):
    def items(self):  # noqa: D102 - the shape urllib's message objects offer
        return list(self)


class Web:
    """Routes ``(method, path)`` to a handler; anything else is a 404."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Handler] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []

    def route(self, method: str, path: str, handler: Handler) -> None:
        self.routes[(method, path)] = handler

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data or b""
        self.seen.append((method, url, headers, body))
        handler = self.routes.get((method, urlsplit(url).path))
        status, reply, text = (
            handler(method, url, headers, body) if handler else (404, [], "not found")
        )
        if not any(k.lower() == "content-type" for k, _v in reply):
            reply = [("Content-Type", "text/html"), *reply]
        payload = text.encode()
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", _Headers(reply), io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, _Headers(reply)
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


def make(tmp_path: Path, roe: dict | None = None, identities: list | None = None):
    roots = Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(json.dumps(roe or NOT_REQUIRED))
    if identities is not None:
        (roots.secrets / "acme").mkdir(parents=True)
        (roots.secrets / "acme" / "identities.json").write_text(
            json.dumps({"identities": identities})
        )
    web = Web()
    gateway = CaptureGateway(roots, opener=web, sleep=lambda _s: None)
    return SimpleNamespace(gateway=gateway, web=web, roots=roots)


def cookie_of(headers: dict[str, str]) -> dict[str, str]:
    jar: dict[str, str] = {}
    for pair in headers.get("cookie", "").split(";"):
        name, _, value = pair.strip().partition("=")
        if name:
            jar[name] = value
    return jar
