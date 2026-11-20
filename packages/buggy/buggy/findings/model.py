"""The one Finding schema (``board/CONTRACTS.md``), its stable id and its validation.

A finding is a claim plus machine-checkable assertions. This module owns the
shape of that record; it sends nothing and stores nothing.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from buggy.capture.gateway import ALLOWED_METHODS


class Status(StrEnum):
    CANDIDATE = "candidate"
    EXPLOIT_VERIFIED = "exploit_verified"
    SOURCE_VERIFIED = "source_verified"
    INCONCLUSIVE = "inconclusive"
    DISCARDED = "discarded"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnClass(StrEnum):
    """The 14 lab classes. A copy of ``benchmark/lab/taxonomy.py::CLASSES``.

    Product code may not import ``benchmark``; a test in ``tests/unit/benchmark``
    keeps the two lists equal.
    """

    AUTH_SESSION = "auth_session"
    ACCESS_CONTROL = "access_control"
    SSRF = "ssrf"
    BUSINESS_LOGIC = "business_logic"
    API = "api"
    GRAPHQL = "graphql"
    INJECTION = "injection"
    XSS = "xss"
    FILE_HANDLING = "file_handling"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    CRYPTO = "crypto"
    MISCONFIGURATION = "misconfiguration"
    INFO_EXPOSURE = "info_exposure"


STATUSES: tuple[str, ...] = tuple(member.value for member in Status)
# Most severe first.
SEVERITIES: tuple[str, ...] = tuple(member.value for member in Severity)
CLASSES: tuple[str, ...] = tuple(member.value for member in VulnClass)
GRADES: tuple[str, ...] = ("submit", "hold", "discard")

EXPECT_KEYS = ("status", "body_contains", "body_not_contains", "differs_from", "same_as")
ASSERTION_KEYS = ("capture_id", "identity", "expect")

MAX_ASSERTIONS = 50
MAX_TITLE = 300
MAX_TEXT = 20000
MAX_ENDPOINT = 2048
MAX_SHORT = 500
MAX_EXPECT_STRINGS = 20

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_CWE = re.compile(r"^(?:CWE-)?(\d{1,7})$", re.IGNORECASE)


class ValidationError(ValueError):
    """A finding document is malformed. ``errors`` names each offending field."""

    def __init__(self, errors: list[dict[str, str]]) -> None:
        self.errors = errors
        super().__init__("; ".join(f"{e['field']}: {e['message']}" for e in errors))

    @property
    def fields(self) -> list[str]:
        return [error["field"] for error in self.errors]


def severity_rank(severity: str) -> int:
    """0 for the most severe; larger is less severe."""
    return SEVERITIES.index(severity)


def _is_id_segment(segment: str) -> bool:
    return (segment.isascii() and segment.isdigit()) or bool(_UUID.match(segment))


def normalize_endpoint(endpoint: str) -> str:
    """Canonical form of an endpoint for identity and storage.

    Lower-case scheme and host, no credentials, no query or fragment, and every
    numeric or UUID path segment replaced with ``{id}``. A value that is not an
    absolute URL is treated as a path. The function is idempotent.
    """
    raw = (endpoint or "").strip()
    parts = urlsplit(raw)
    if parts.scheme and parts.netloc:
        host = (parts.hostname or "").lower()
        if ":" in host:
            host = f"[{host}]"
        try:
            port = f":{parts.port}" if parts.port is not None else ""
        except ValueError:
            port = ""
        prefix = f"{parts.scheme.lower()}://{host}{port}"
        path = parts.path
    else:
        prefix = ""
        path = raw.split("#", 1)[0].split("?", 1)[0]
    segments = ["{id}" if _is_id_segment(segment) else segment for segment in path.split("/")]
    return prefix + "/".join(segments)


def finding_id(engagement: str, cls: str, endpoint: str, parameter: str) -> str:
    """``F-`` + 12 hex of sha256(engagement|class|normalized endpoint|parameter)."""
    material = "|".join(
        (
            (engagement or "").strip(),
            (cls or "").strip().lower(),
            normalize_endpoint(endpoint),
            (parameter or "").strip(),
        )
    )
    return "F-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True, slots=True)
class Expect:
    """What must hold for the response to a re-sent request. Unset checks are not evaluated."""

    status: int | tuple[int, ...] | None = None
    body_contains: tuple[str, ...] = ()
    body_not_contains: tuple[str, ...] = ()
    differs_from: str = ""
    same_as: str = ""

    def statuses(self) -> tuple[int, ...]:
        if self.status is None:
            return ()
        return (self.status,) if isinstance(self.status, int) else tuple(self.status)

    def is_empty(self) -> bool:
        return not (
            self.statuses()
            or self.body_contains
            or self.body_not_contains
            or self.differs_from
            or self.same_as
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": list(self.status) if isinstance(self.status, tuple) else self.status,
            "body_contains": list(self.body_contains),
            "body_not_contains": list(self.body_not_contains),
            "differs_from": self.differs_from,
            "same_as": self.same_as,
        }


@dataclass(frozen=True, slots=True)
class Assertion:
    """One cited capture and what its fresh replay must show."""

    capture_id: str
    identity: str = ""
    expect: Expect = field(default_factory=Expect)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "identity": self.identity,
            "expect": self.expect.to_dict(),
        }


def empty_verification() -> dict[str, Any]:
    return {"at": 0.0, "replay_capture_ids": [], "reasons": []}


@dataclass(frozen=True, slots=True)
class Finding:
    """A finding exactly as ``board/CONTRACTS.md`` defines it.

    ``vuln_class`` is the contract's ``class`` (a Python keyword); ``to_dict``
    emits it under the contract name.
    """

    id: str
    engagement: str
    title: str
    vuln_class: str
    severity: str
    endpoint: str
    cwe: str = ""
    method: str = "GET"
    parameter: str = ""
    source: str = ""
    description: str = ""
    remediation: str = ""
    assertions: tuple[Assertion, ...] = ()
    status: str = Status.CANDIDATE.value
    verification: dict[str, Any] = field(default_factory=empty_verification)
    grade: str | None = None
    grade_reasons: tuple[str, ...] = ()
    created_at: float = 0.0
    updated_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engagement": self.engagement,
            "title": self.title,
            "class": self.vuln_class,
            "cwe": self.cwe,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "source": self.source,
            "description": self.description,
            "remediation": self.remediation,
            "assertions": [assertion.to_dict() for assertion in self.assertions],
            "status": self.status,
            "verification": {
                "at": float(self.verification.get("at") or 0.0),
                "replay_capture_ids": list(self.verification.get("replay_capture_ids") or []),
                "reasons": list(self.verification.get("reasons") or []),
            },
            "grade": self.grade,
            "grade_reasons": list(self.grade_reasons),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ── validation ──────────────────────────────────────────────────────


class _Errors:
    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []

    def add(self, field_name: str, message: str) -> None:
        self.items.append({"field": field_name, "message": message})


def _text(
    data: dict[str, Any],
    key: str,
    errors: _Errors,
    *,
    required: bool = False,
    limit: int = MAX_SHORT,
    default: str = "",
) -> str:
    value = data.get(key)
    if value is None or value == "":
        if required:
            errors.add(key, "is required")
        return default
    if not isinstance(value, str):
        errors.add(key, "must be a string")
        return default
    value = value.strip()
    if not value and required:
        errors.add(key, "is required")
        return default
    if len(value) > limit:
        errors.add(key, f"must be at most {limit} characters")
        return default
    return value


def _number(data: dict[str, Any], key: str, errors: _Errors) -> float:
    value = data.get(key)
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.add(key, "must be a number (epoch seconds)")
        return 0.0
    return float(value)


def _string_list(value: Any, name: str, errors: _Errors, *, limit: int) -> tuple[str, ...]:
    if value is None or value == []:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        errors.add(name, "must be a list of strings")
        return ()
    if len(value) > limit:
        errors.add(name, f"must have at most {limit} entries")
        return ()
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            # An empty string is contained in every body: it would assert nothing.
            errors.add(f"{name}[{index}]", "must be a non-empty string")
            continue
        if len(item) > MAX_SHORT:
            errors.add(f"{name}[{index}]", f"must be at most {MAX_SHORT} characters")
            continue
        out.append(item)
    return tuple(out)


def _status_code(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599


def _expect(value: Any, name: str, errors: _Errors) -> Expect:
    if not isinstance(value, dict):
        errors.add(name, "is required and must be an object")
        return Expect()
    before = len(errors.items)
    for key in value:
        if key not in EXPECT_KEYS:
            errors.add(f"{name}.{key}", f"unknown expectation; allowed: {', '.join(EXPECT_KEYS)}")

    status: int | tuple[int, ...] | None = None
    raw_status = value.get("status")
    if raw_status is not None:
        if _status_code(raw_status):
            status = raw_status
        elif (
            isinstance(raw_status, (list, tuple))
            and raw_status
            and all(_status_code(item) for item in raw_status)
        ):
            status = tuple(raw_status)
        else:
            errors.add(
                f"{name}.status",
                "must be an HTTP status code (100-599) or a non-empty list of them",
            )

    refs: dict[str, str] = {}
    for key in ("differs_from", "same_as"):
        ref = value.get(key)
        if ref is None or ref == "":
            refs[key] = ""
        elif not isinstance(ref, str) or len(ref) > MAX_SHORT:
            errors.add(f"{name}.{key}", "must be a capture id")
            refs[key] = ""
        else:
            refs[key] = ref.strip()

    expect = Expect(
        status=status,
        body_contains=_string_list(
            value.get("body_contains"), f"{name}.body_contains", errors, limit=MAX_EXPECT_STRINGS
        ),
        body_not_contains=_string_list(
            value.get("body_not_contains"),
            f"{name}.body_not_contains",
            errors,
            limit=MAX_EXPECT_STRINGS,
        ),
        differs_from=refs["differs_from"],
        same_as=refs["same_as"],
    )
    if expect.is_empty() and len(errors.items) == before:
        errors.add(name, f"must set at least one of: {', '.join(EXPECT_KEYS)}")
    return expect


def _assertions(value: Any, errors: _Errors) -> tuple[Assertion, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        errors.add("assertions", "must be a list")
        return ()
    if len(value) > MAX_ASSERTIONS:
        errors.add("assertions", f"must have at most {MAX_ASSERTIONS} entries")
        return ()
    out: list[Assertion] = []
    for index, item in enumerate(value):
        name = f"assertions[{index}]"
        if not isinstance(item, dict):
            errors.add(name, "must be an object")
            continue
        for key in item:
            if key not in ASSERTION_KEYS:
                errors.add(f"{name}.{key}", f"unknown field; allowed: {', '.join(ASSERTION_KEYS)}")
        capture_id = item.get("capture_id")
        if not isinstance(capture_id, str) or not capture_id.strip():
            errors.add(f"{name}.capture_id", "is required")
            capture_id = ""
        elif len(capture_id) > MAX_SHORT:
            errors.add(f"{name}.capture_id", "must be a capture id")
            capture_id = ""
        identity = item.get("identity")
        if identity is None:
            identity = ""
        elif not isinstance(identity, str) or len(identity) > MAX_SHORT:
            errors.add(f"{name}.identity", "must be an identity name")
            identity = ""
        expect = _expect(item.get("expect"), f"{name}.expect", errors)
        out.append(
            Assertion(capture_id=capture_id.strip(), identity=identity.strip(), expect=expect)
        )
    return tuple(out)


def _verification(value: Any, errors: _Errors) -> dict[str, Any]:
    if value is None:
        return empty_verification()
    if not isinstance(value, dict):
        errors.add("verification", "must be an object")
        return empty_verification()
    at = _number(value, "at", _Prefixed(errors, "verification."))
    lists: dict[str, list[str]] = {}
    for key in ("replay_capture_ids", "reasons"):
        raw = value.get(key)
        if raw is None:
            lists[key] = []
        elif not isinstance(raw, (list, tuple)) or not all(isinstance(item, str) for item in raw):
            errors.add(f"verification.{key}", "must be a list of strings")
            lists[key] = []
        else:
            lists[key] = list(raw)
    return {
        "at": at,
        "replay_capture_ids": lists["replay_capture_ids"],
        "reasons": lists["reasons"],
    }


class _Prefixed(_Errors):
    """Reports into another collector with a field prefix."""

    def __init__(self, parent: _Errors, prefix: str) -> None:
        super().__init__()
        self._parent = parent
        self._prefix = prefix

    def add(self, field_name: str, message: str) -> None:
        self._parent.add(self._prefix + field_name, message)


def validate(data: Any) -> Finding:
    """Build a :class:`Finding` from a contract-shaped dict, or raise :class:`ValidationError`.

    Every problem is reported against the field that has it. The id is always
    computed; a supplied id that disagrees is an error. Top-level keys the
    contract does not define are ignored; unknown keys inside an assertion or
    its ``expect`` are errors, because a misspelt expectation would silently
    assert nothing.
    """
    if not isinstance(data, dict):
        raise ValidationError([{"field": "finding", "message": "must be an object"}])
    errors = _Errors()

    engagement = _text(data, "engagement", errors, required=True, limit=128)
    if engagement and ("/" in engagement or engagement.startswith(".")):
        errors.add("engagement", "must be a plain engagement name")
    title = _text(data, "title", errors, required=True, limit=MAX_TITLE)

    vuln_class = _text(data, "class", errors, required=True).lower()
    if vuln_class and vuln_class not in CLASSES:
        errors.add("class", f"must be one of: {', '.join(CLASSES)}")

    severity = _text(data, "severity", errors, required=True).lower()
    if severity and severity not in SEVERITIES:
        errors.add("severity", f"must be one of: {', '.join(SEVERITIES)}")

    endpoint = _text(data, "endpoint", errors, required=True, limit=MAX_ENDPOINT)
    endpoint = normalize_endpoint(endpoint) if endpoint else ""

    cwe_raw = data.get("cwe")
    cwe = ""
    if isinstance(cwe_raw, int) and not isinstance(cwe_raw, bool) and cwe_raw > 0:
        cwe = f"CWE-{cwe_raw}"
    elif cwe_raw not in (None, ""):
        match = _CWE.match(cwe_raw.strip()) if isinstance(cwe_raw, str) else None
        if match is None:
            errors.add("cwe", "must look like CWE-639")
        else:
            cwe = f"CWE-{int(match.group(1))}"

    method = _text(data, "method", errors, default="GET").upper()
    if method not in ALLOWED_METHODS:
        errors.add("method", f"must be one of: {', '.join(sorted(ALLOWED_METHODS))}")

    parameter = _text(data, "parameter", errors, limit=200)
    source = _text(data, "source", errors, required=True)
    description = _text(data, "description", errors, limit=MAX_TEXT)
    remediation = _text(data, "remediation", errors, limit=MAX_TEXT)
    assertions = _assertions(data.get("assertions"), errors)

    status = _text(data, "status", errors, default=Status.CANDIDATE.value).lower()
    if status not in STATUSES:
        errors.add("status", f"must be one of: {', '.join(STATUSES)}")

    verification = _verification(data.get("verification"), errors)

    grade = data.get("grade")
    if grade == "":
        grade = None
    if grade is not None and grade not in GRADES:
        errors.add("grade", f"must be null or one of: {', '.join(GRADES)}")
        grade = None

    raw_reasons = data.get("grade_reasons")
    grade_reasons: tuple[str, ...] = ()
    if raw_reasons is not None:
        if not isinstance(raw_reasons, (list, tuple)) or not all(
            isinstance(item, str) for item in raw_reasons
        ):
            errors.add("grade_reasons", "must be a list of strings")
        else:
            grade_reasons = tuple(raw_reasons)

    created_at = _number(data, "created_at", errors)
    updated_at = _number(data, "updated_at", errors)

    computed = finding_id(engagement, vuln_class, endpoint, parameter)
    supplied = data.get("id")
    if supplied not in (None, "") and not errors.items and supplied != computed:
        errors.add("id", f"does not match the id computed from the finding ({computed})")

    if errors.items:
        raise ValidationError(errors.items)
    return Finding(
        id=computed,
        engagement=engagement,
        title=title,
        vuln_class=vuln_class,
        cwe=cwe,
        severity=severity,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        source=source,
        description=description,
        remediation=remediation,
        assertions=assertions,
        status=status,
        verification=verification,
        grade=grade,
        grade_reasons=grade_reasons,
        created_at=created_at,
        updated_at=updated_at,
    )


__all__ = [
    "ASSERTION_KEYS",
    "CLASSES",
    "EXPECT_KEYS",
    "GRADES",
    "MAX_ASSERTIONS",
    "SEVERITIES",
    "STATUSES",
    "Assertion",
    "Expect",
    "Finding",
    "Severity",
    "Status",
    "ValidationError",
    "VulnClass",
    "empty_verification",
    "finding_id",
    "normalize_endpoint",
    "severity_rank",
    "validate",
]
