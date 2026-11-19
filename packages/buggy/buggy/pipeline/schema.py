"""The one schema every pipeline tool's output is normalised into.

A :class:`Record` is one fact about one asset:

    engagement   which engagement it belongs to
    asset        the in-scope host (or address) the fact is about
    type         what kind of fact (:class:`RecordType`)
    value        the fact itself, canonicalised so duplicates collapse
    attrs        structured detail (status code, record data, severity, ...)
    source_tool  which tool reported it, and ``tool_version``
    observed_at  when
    raw_ref      where the unparsed tool output line lives

``(engagement, type, asset, value)`` is the identity. Two tools reporting the
same subdomain produce one record with two observations.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class RecordType(StrEnum):
    SUBDOMAIN = "subdomain"
    DNS_RECORD = "dns_record"
    PORT = "port"
    HTTP_SERVICE = "http_service"
    TECHNOLOGY = "technology"
    TLS = "tls"
    HEADER = "header"
    URL = "url"
    JS_FILE = "js_file"
    ENDPOINT = "endpoint"
    API_SPEC = "api_spec"
    API_OPERATION = "api_operation"
    GRAPHQL = "graphql"
    VULNERABILITY = "vulnerability"
    SECRET = "secret"


_HOST_RE = re.compile(
    r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$"
)


def normalize_host(value: str) -> str:
    """Lower-case, strip a trailing dot and any surrounding whitespace."""
    return value.strip().rstrip(".").lower()


def is_hostname(value: str) -> bool:
    return bool(value) and len(value) <= 253 and _HOST_RE.match(value) is not None


def normalize_url(value: str) -> str:
    """Canonical form of an http(s) URL: lower-case scheme/host, default port and fragment removed."""
    parts = urlsplit(value.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".").lower()
    if not scheme or not host:
        return value.strip()
    port = parts.port
    default = {"http": 80, "https": 443}.get(scheme)
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    netloc = host if port in (None, default) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def host_of(value: str) -> str:
    """Hostname of a URL, ``host:port`` pair or bare host; ``""`` if none."""
    text = value.strip()
    if "://" in text:
        return (urlsplit(text).hostname or "").rstrip(".").lower()
    if text.startswith("["):
        return text[1:].split("]")[0].lower()
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return normalize_host(text)


def as_dict(value: Any) -> dict[str, Any]:
    """``value`` when it is a mapping, else an empty dict (for untrusted JSON)."""
    return value if isinstance(value, dict) else {}


def as_list_of(value: Any) -> list[Any]:
    """``value`` when it is a list, else an empty list."""
    return value if isinstance(value, list) else []


def record_id(engagement: str, record_type: str, asset: str, value: str) -> str:
    material = "\x1f".join((engagement, record_type, asset, value))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def content_hash(attrs: dict[str, Any]) -> str:
    canonical = json.dumps(attrs, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class Record:
    """One normalised fact. ``engagement``, ``observed_at`` and the tool
    version are stamped by the pipeline, not by the parser."""

    type: RecordType
    asset: str
    value: str
    source_tool: str
    attrs: dict[str, Any] = field(default_factory=dict)
    raw_line: int | None = None  # 1-based line in the tool's raw output

    def key(self, engagement: str) -> str:
        return record_id(engagement, self.type.value, self.asset, self.value)


@dataclass(frozen=True, slots=True)
class StoredRecord:
    """A record as read back from the store."""

    id: str
    engagement: str
    asset: str
    type: str
    value: str
    attrs: dict[str, Any]
    source_tool: str
    tool_version: str
    first_seen: float
    last_seen: float
    first_run_id: str
    last_run_id: str
    raw_ref: str
    content_hash: str
    status: str
    sources: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engagement": self.engagement,
            "asset": self.asset,
            "type": self.type,
            "value": self.value,
            "attrs": self.attrs,
            "source_tool": self.source_tool,
            "tool_version": self.tool_version,
            "sources": list(self.sources),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_run_id": self.first_run_id,
            "last_run_id": self.last_run_id,
            "raw_ref": self.raw_ref,
            "status": self.status,
        }


__all__ = [
    "Record",
    "as_dict",
    "as_list_of",
    "RecordType",
    "StoredRecord",
    "content_hash",
    "host_of",
    "is_hostname",
    "normalize_host",
    "normalize_url",
    "record_id",
]
