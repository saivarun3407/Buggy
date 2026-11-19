"""Shared types and helpers for probes."""

from __future__ import annotations

import base64
import difflib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway
from buggy.capture.store import Capture


class ProbeInputError(ValueError):
    """The caller's parameters are missing or malformed."""


@dataclass
class ProbeResult:
    probe: str
    vuln_class: str
    cwe: str
    vulnerable: bool | None
    summary: str
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe": self.probe,
            "class": self.vuln_class,
            "cwe": self.cwe,
            "vulnerable": self.vulnerable,
            "summary": self.summary,
            "evidence_capture_ids": self.evidence,
            "details": self.details,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class Context:
    gateway: CaptureGateway
    engagement: str
    probe: str
    canary: Canary | None = None

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        note: str = "",
    ) -> Capture:
        return self.gateway.send(
            self.engagement, method, url, headers=headers, body=body, note=note, probe=self.probe
        )


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    name: str
    vuln_class: str
    cwe: str
    summary: str
    params: dict[str, str]
    state_changing: bool
    run: Callable[[Context, dict[str, Any]], ProbeResult]


def require(params: dict[str, Any], *names: str) -> None:
    missing = [name for name in names if params.get(name) in (None, "", {}, [])]
    if missing:
        raise ProbeInputError(f"missing required parameter(s): {', '.join(missing)}")


def headers_of(value: Any, name: str = "headers") -> dict[str, str]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ProbeInputError(f"{name} must be an object of header names to values")
    return {str(k): str(v) for k, v in value.items()}


def ok(capture: Capture) -> bool:
    return capture.status is not None and 200 <= capture.status < 300 and not capture.error


def text(capture: Capture) -> str:
    return capture.response_body.decode("utf-8", "replace")


def json_of(capture: Capture) -> Any:
    try:
        return json.loads(text(capture))
    except ValueError:
        return None


def similarity(a: Capture, b: Capture) -> float:
    """0..1 similarity of two response bodies (1.0 when identical)."""
    if a.response_sha256 == b.response_sha256:
        return 1.0
    left, right = text(a)[:20000], text(b)[:20000]
    if not left and not right:
        return 1.0
    return round(difflib.SequenceMatcher(None, left, right).quick_ratio(), 3)


def contains_value(document: Any, key: str, value: Any) -> bool:
    """Whether ``key: value`` appears anywhere in a decoded JSON document."""
    if isinstance(document, dict):
        for k, v in document.items():
            if k == key and v == value:
                return True
            if contains_value(v, key, value):
                return True
    elif isinstance(document, list):
        return any(contains_value(item, key, value) for item in document)
    return False


def set_path(document: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    """Copy of ``document`` with the dotted ``path`` set to ``value``."""
    clone = json.loads(json.dumps(document))
    cursor = clone
    parts = path.split(".")
    for part in parts[:-1]:
        if not isinstance(cursor.get(part), dict):
            cursor[part] = {}
        cursor = cursor[part]
    cursor[parts[-1]] = value
    return clone


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


__all__ = [
    "Context",
    "ProbeInputError",
    "ProbeResult",
    "ProbeSpec",
    "b64url_decode",
    "b64url_encode",
    "contains_value",
    "headers_of",
    "json_of",
    "ok",
    "require",
    "set_path",
    "similarity",
    "text",
]
