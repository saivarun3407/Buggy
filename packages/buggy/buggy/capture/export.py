"""Evidence bundle: the captures behind a finding as a package a triager can check.

Three views of the same stored exchanges, plus the hashes that tie them together:

* ``evidence.har`` - HAR 1.2, opens in any browser's network panel;
* ``reproduce.sh`` - one ``curl`` command per captured request, in order;
* ``captures.json`` - the capture summaries, with each response's SHA-256;
* ``ledger-excerpt.jsonl`` - the ledger lines of those captures, byte for byte;
* ``MANIFEST.json`` - the SHA-256 of every other file, and what the bundle is.

Redaction is not decided here. With ``redact=True`` every header and body comes
from :meth:`buggy.capture.store.Capture.detail`, the same call that produces the
agent-facing ``http_capture`` view, so a bundle shows nothing that view withholds:
sensitive and session headers read ``<redacted>``, a session value the target
echoed back is scrubbed from bodies, and the gateway's own login exchange has
neither body. ``redact=False`` is the operator's view and contains credentials.

The manifest detects corruption and careless edits. It is not a signature: whoever
can rewrite a file can rewrite its hash. Provenance is the hash-chained ledger the
excerpt is cut from.

Standard library only; no request is sent from here.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from buggy import __version__
from buggy.capture.gateway import INTERNAL_LOGIN, SAFE_METHODS
from buggy.capture.store import REDACTED, Capture, CaptureStore, sha256_hex

HAR_FILE = "evidence.har"
SCRIPT_FILE = "reproduce.sh"
CAPTURES_FILE = "captures.json"
LEDGER_FILE = "ledger-excerpt.jsonl"
MANIFEST_FILE = "MANIFEST.json"
BUNDLE_FORMAT = 1
TOOL_NAME = "buggy"

# ``Capture.detail`` cuts bodies at ``body_chars``; an export wants all the store holds.
_NO_TRUNCATION = 1 << 40
# An HTTP header name (RFC 9110 token). Anything else cannot be handed to curl safely:
# ``--header '@name'`` reads a file.
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
# The finding fields a bundle repeats so a reader knows what it is evidence for.
_FINDING_FIELDS = (
    "id",
    "title",
    "class",
    "cwe",
    "severity",
    "endpoint",
    "method",
    "parameter",
    "status",
)


class ExportRefused(ValueError):
    """The bundle was not built: what was asked for does not belong to the engagement."""


# ── the view of one capture that an export may show ─────────────────


@dataclass(frozen=True, slots=True)
class _Body:
    text: str
    # "" when ``text`` is the body itself, "base64" when the body is not UTF-8 text.
    encoding: str
    # The stored bytes, or None when redaction changed the body: then ``text`` is all
    # there is to export and the original bytes must not be used.
    raw: bytes | None


@dataclass(frozen=True, slots=True)
class _View:
    request_headers: dict[str, str]
    request_body: _Body
    response_headers: dict[str, str]
    response_body: _Body


def _body(raw: bytes, shown: str) -> _Body:
    """``raw`` as an export may carry it, given the text ``Capture.detail`` shows for it.

    If redaction changed the text, only that text is exported. Otherwise nothing was
    withheld and the stored bytes are exported exactly: as text when they are UTF-8,
    base64 when they are not.
    """
    if shown != raw.decode("utf-8", "replace"):
        return _Body(shown, "", None)
    try:
        return _Body(raw.decode("utf-8"), "", raw)
    except UnicodeDecodeError:
        return _Body(base64.b64encode(raw).decode("ascii"), "base64", raw)


def _view(capture: Capture, redact: bool) -> _View:
    shown = capture.detail(body_chars=_NO_TRUNCATION, reveal_credentials=not redact)
    return _View(
        request_headers=dict(shown["request_headers"]),
        request_body=_body(capture.request_body, shown["request_body"]),
        response_headers=dict(shown["response_headers"]),
        response_body=_body(capture.response_body, shown["response_body"]),
    )


def _is_login(capture: Capture) -> bool:
    """The gateway's own login for an identity (the same test ``replay`` refuses on)."""
    return capture.redact_bodies or capture.approval_id == INTERNAL_LOGIN


def _header(headers: dict[str, str], name: str) -> str:
    return next((v for k, v in headers.items() if k.lower() == name), "")


# ── HAR ─────────────────────────────────────────────────────────────


def _har_headers(headers: dict[str, str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for name, value in headers.items():
        # The gateway keeps repeated Set-Cookie headers one per line.
        parts = value.split("\n") if name.lower() == "set-cookie" else [value]
        out.extend({"name": name, "value": part} for part in parts)
    return out


def _har_cookies(headers: dict[str, str], header: str) -> list[dict[str, str]]:
    """Cookies parsed from the headers as shown: a redacted header yields none."""
    cookies: list[dict[str, str]] = []
    for name, value in headers.items():
        if name.lower() != header or value == REDACTED:
            continue
        if header == "cookie":
            pairs = value.split(";")
        else:
            pairs = [line.split(";", 1)[0] for line in value.split("\n")]
        for pair in pairs:
            cookie, _, cookie_value = pair.strip().partition("=")
            if cookie:
                cookies.append({"name": cookie, "value": cookie_value})
    return cookies


def _har_entry(capture: Capture, redact: bool) -> dict[str, Any]:
    view = _view(capture, redact)
    started = capture.created_at - capture.elapsed_ms / 1000  # recorded when it ended
    request: dict[str, Any] = {
        "method": capture.method,
        "url": capture.url,
        "httpVersion": "HTTP/1.1",
        "cookies": _har_cookies(view.request_headers, "cookie"),
        "headers": _har_headers(view.request_headers),
        "queryString": [
            {"name": name, "value": value}
            for name, value in parse_qsl(urlsplit(capture.url).query, keep_blank_values=True)
        ],
        "headersSize": -1,
        "bodySize": len(capture.request_body),
    }
    if capture.request_body:
        post: dict[str, Any] = {
            "mimeType": _header(view.request_headers, "content-type"),
            "text": view.request_body.text,
        }
        if view.request_body.encoding:
            post["encoding"] = view.request_body.encoding
        if view.request_body.raw is None:
            post["comment"] = "redacted by the capture gateway"
        request["postData"] = post

    content: dict[str, Any] = {
        "size": capture.response_bytes,
        "mimeType": _header(view.response_headers, "content-type"),
        "text": view.response_body.text,
    }
    if view.response_body.encoding:
        content["encoding"] = view.response_body.encoding
    remarks = []
    if view.response_body.raw is None:
        remarks.append("redacted by the capture gateway")
    if capture.response_bytes > len(capture.response_body):
        remarks.append(
            f"truncated: the first {len(capture.response_body)} of {capture.response_bytes} "
            "bytes are stored; the sha256 covers all of them"
        )
    if remarks:
        content["comment"] = "; ".join(remarks)

    return {
        "startedDateTime": datetime.fromtimestamp(started, tz=UTC).isoformat(
            timespec="milliseconds"
        ),
        "time": capture.elapsed_ms,
        "request": request,
        "response": {
            "status": capture.status or 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": _har_cookies(view.response_headers, "set-cookie"),
            "headers": _har_headers(view.response_headers),
            "content": content,
            "redirectURL": _header(view.response_headers, "location"),
            "headersSize": -1,
            "bodySize": capture.response_bytes,
        },
        "cache": {},
        "timings": {"send": 0, "wait": capture.elapsed_ms, "receive": 0},
        "comment": capture.note,
        "_capture_id": capture.id,
        "_probe": capture.probe,
        "_identity": capture.identity,
        "_replay_of": capture.replay_of,
        "_response_sha256": capture.response_sha256,
        "_error": capture.error,
    }


def to_har(captures: list[Capture], *, redact: bool = True) -> dict[str, Any]:
    """The captures as a HAR 1.2 document, one entry each, in the order given.

    A body that is not UTF-8 text is carried base64-encoded (``encoding: "base64"``),
    so the stored bytes can be recovered exactly. With ``redact=True`` header values
    and bodies are the ones the agent-facing view shows.
    """
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": TOOL_NAME, "version": __version__},
            "entries": [_har_entry(capture, redact) for capture in captures],
        }
    }


# ── curl ────────────────────────────────────────────────────────────


def _comment(text: str) -> str:
    """``text`` on one line with no control characters, safe after a ``# `` in a script."""
    return " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())


def _placeholder(name: str) -> str:
    return "<" + re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_") + ">"


def _data_argument(raw: bytes) -> tuple[str, str]:
    """``(pipeline prefix, --data-binary argument)`` that makes curl send exactly ``raw``.

    Text goes on the command line, quoted. What an argument cannot carry faithfully -
    bytes that are not UTF-8, a NUL, or a leading ``@`` (curl would read a file) -
    is written by ``printf`` from octal escapes and read by curl from standard input.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None or "\x00" in text or text.startswith("@"):
        escaped = "".join(
            chr(byte) if byte < 128 and chr(byte).isalnum() else f"\\{byte:03o}" for byte in raw
        )
        return f"printf '{escaped}' | ", "@-"
    return "", shlex.quote(text)


def _curl(capture: Capture, redact: bool) -> tuple[list[str], str]:
    """``(placeholders to fill, script text)`` for one capture."""
    if redact and _is_login(capture):
        target = _comment(f"{capture.method} {capture.url}")
        return [], (
            f"# {capture.id}: login for a declared identity ({target}).\n"
            "# The capture gateway performs this login itself, with credentials only the\n"
            "# operator holds. It is not reproduced here: log in to your own test account\n"
            "# and supply its session in the placeholders of the steps that follow."
        )

    view = _view(capture, redact)
    notes: list[str] = []
    placeholders: list[str] = []
    arguments: list[str] = ["--globoff --path-as-is", f"--request {shlex.quote(capture.method)}"]
    if capture.method == "HEAD":
        arguments.append("--head")

    present = {name.lower() for name in view.request_headers}
    for name, value in view.request_headers.items():
        if not _TOKEN.fullmatch(name) or "\n" in value or "\r" in value:
            notes.append(f"# A header curl cannot send as written was left out: {_comment(name)}")
            continue
        if redact and value == REDACTED:
            value = _placeholder(name)
            if value not in placeholders:
                placeholders.append(value)
        elif redact and REDACTED in value:
            notes.append(
                f"# The {name} header held a session value; it is shown as {REDACTED} and "
                "must be restored by hand."
            )
        # ``Name;`` is how curl is told to send a header with an empty value.
        arguments.append(f"--header {shlex.quote(f'{name}: {value}' if value else f'{name};')}")
    # Headers curl would add by itself that the captured request did not carry.
    arguments.extend(
        f"--header {shlex.quote(default + ':')}"
        for default in ("Accept", "User-Agent")
        if default.lower() not in present
    )

    prefix = ""
    body = view.request_body
    if body.raw is None:
        notes.append(
            f"# The request body held a session value; it is shown as {REDACTED} and must be "
            "restored by hand."
        )
        arguments.append(f"--data-binary {shlex.quote(body.text)}")
    elif body.raw or capture.method not in SAFE_METHODS:
        # The gateway sends a (possibly empty) body with every state-changing method.
        prefix, argument = _data_argument(body.raw)
        arguments.append(f"--data-binary {argument}")
    arguments.extend(["--max-redirs 0", shlex.quote(capture.url)])

    if placeholders:
        notes.insert(0, f"# Fill in before running: {' '.join(placeholders)}")
    if redact and capture.identity:
        notes.append(
            f"# Sent as identity {_comment(capture.identity)!r}: the gateway attached that "
            "account's session."
        )
    command = prefix + "curl " + " \\\n  ".join(arguments)
    return placeholders, "\n".join([*notes, command])


def to_curl(capture: Capture, *, redact: bool = True) -> str:
    """One POSIX ``curl`` command that sends the captured request again.

    Every value is quoted with :func:`shlex.quote`. With ``redact=True`` a withheld
    header becomes a placeholder such as ``Authorization: <AUTHORIZATION>``, and the
    placeholders are listed in a comment above the command. The gateway's login for
    an identity is never written as a command when redacted: a comment says the
    gateway performs it.

    Beyond the flags the request needs, the command carries ``--globoff`` and
    ``--path-as-is`` (curl would otherwise expand ``[]{}`` and collapse ``/../`` in
    the URL) and switches off the ``Accept`` and ``User-Agent`` headers curl adds
    when the capture had none. Redirects are not followed.
    """
    return _curl(capture, redact)[1]


# ── bundle ──────────────────────────────────────────────────────────


def _json_bytes(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")


def _manifest_digest(manifest: dict[str, Any]) -> str:
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    return sha256_hex(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii"))


def _finding_summary(finding: dict[str, Any] | None, engagement: str) -> dict[str, str] | None:
    if finding is None:
        return None
    owner = finding.get("engagement")
    if owner not in (None, "", engagement):
        raise ExportRefused(
            f"finding {finding.get('id')!r} belongs to engagement {owner!r}, not {engagement!r}"
        )
    return {
        key: finding[key]
        for key in _FINDING_FIELDS
        if isinstance(finding.get(key), str) and finding[key]
    }


def _ledger_excerpt(ledger_path: Path | None, capture_ids: Iterable[str]) -> bytes:
    """The ledger lines that record these captures, exactly as they are in the file."""
    if ledger_path is None:
        return b""
    wanted = set(capture_ids)
    kept: list[bytes] = []
    try:
        lines = Path(ledger_path).read_bytes().splitlines(keepends=True)
    except FileNotFoundError:
        return b""
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("capture_id") in wanted:
            kept.append(line if line.endswith(b"\n") else line + b"\n")
    return b"".join(kept)


def _script(
    captures: list[Capture], engagement: str, finding: dict[str, str] | None, redact: bool
) -> str:
    steps: list[str] = []
    placeholders: list[str] = []
    for number, capture in enumerate(captures, start=1):
        needed, text = _curl(capture, redact)
        placeholders.extend(p for p in needed if p not in placeholders)
        title = _comment(capture.note) or _comment(f"{capture.method} {capture.url}")
        outcome = f"HTTP {capture.status}" if capture.status is not None else "no response"
        steps.append(
            f"# Step {number}: {title}\n"
            f"# {capture.id} - recorded {outcome}, response sha256 {capture.response_sha256}\n"
            f"{text}\n"
        )
    head = [
        "#!/bin/sh",
        f"# Evidence for engagement {_comment(engagement)}, written by {TOOL_NAME} {__version__}.",
    ]
    if finding:
        head.append(
            f"# Finding {_comment(finding.get('id', ''))}: {_comment(finding.get('title', ''))}"
        )
    head.append("# One curl command per captured request, in order. Run them only against a")
    head.append("# target you are authorised to test.")
    if placeholders:
        head.append("#")
        head.append("# Credentials were withheld. Replace these placeholders before running:")
        head.extend(f"#   {placeholder}" for placeholder in placeholders)
    if not redact:
        head.append("#")
        head.append("# NOT REDACTED: this script contains the credentials that were sent.")
    return "\n".join(head) + "\n\n" + "\n".join(steps)


def bundle(
    gateway_store: CaptureStore,
    engagement: str,
    capture_ids: Iterable[str],
    *,
    finding: dict[str, Any] | None = None,
    ledger_path: Path | None = None,
    redact: bool = True,
) -> dict[str, bytes]:
    """The evidence files for these captures, as ``{file name: content}``.

    The captures are looked up in ``engagement`` only. An id that is not a capture
    of that engagement - unknown, or another engagement's - raises :class:`KeyError`
    naming it. A finding that says it belongs to another engagement is refused with
    :class:`ExportRefused`. Nothing is written to disk.
    """
    ids = list(dict.fromkeys(str(capture_id) for capture_id in capture_ids))
    if not ids:
        raise ValueError("no capture ids given: there is nothing to export")
    summary = _finding_summary(finding, engagement)
    captures: list[Capture] = []
    for capture_id in ids:
        capture = gateway_store.get(engagement, capture_id)
        if capture is None:
            raise KeyError(f"no capture {capture_id!r} in engagement {engagement!r}")
        if capture.engagement != engagement:
            raise ExportRefused(
                f"capture {capture_id!r} belongs to engagement {capture.engagement!r}, "
                f"not {engagement!r}"
            )
        captures.append(capture)

    files = {
        HAR_FILE: _json_bytes(to_har(captures, redact=redact)),
        SCRIPT_FILE: _script(captures, engagement, summary, redact).encode("utf-8", "replace"),
        CAPTURES_FILE: _json_bytes(
            {"engagement": engagement, "captures": [capture.summary() for capture in captures]}
        ),
        LEDGER_FILE: _ledger_excerpt(ledger_path, ids),
    }
    manifest: dict[str, Any] = {
        "bundle_format": BUNDLE_FORMAT,
        "engagement": engagement,
        "created_at": time.time(),
        "capture_ids": ids,
        "tool": TOOL_NAME,
        "tool_version": __version__,
        "redacted": bool(redact),
        "finding": summary,
        "files": {name: sha256_hex(content) for name, content in files.items()},
    }
    manifest["manifest_sha256"] = _manifest_digest(manifest)
    files[MANIFEST_FILE] = _json_bytes(manifest)
    return files


def verify_bundle(files: dict[str, bytes]) -> list[str]:
    """What does not match the manifest; an empty list means the bundle is intact.

    Checked: every file the manifest lists is present with the listed SHA-256, no
    file is present that it does not list, and the manifest itself is byte for byte
    what was written (its own digest covers the engagement, time and capture ids).
    """
    raw = files.get(MANIFEST_FILE)
    if raw is None:
        return [f"{MANIFEST_FILE}: missing"]
    try:
        manifest = json.loads(bytes(raw).decode("utf-8"))
    except ValueError:
        return [f"{MANIFEST_FILE}: not valid JSON"]
    listed = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(listed, dict):
        return [f"{MANIFEST_FILE}: lists no files"]

    problems: list[str] = []
    try:
        untouched = _json_bytes(manifest) == bytes(raw)
        digest_ok = manifest.get("manifest_sha256") == _manifest_digest(manifest)
    except (TypeError, ValueError):
        untouched = digest_ok = False
    if not untouched or not digest_ok:
        problems.append(f"{MANIFEST_FILE}: changed since it was written")
    for name, expected in sorted(listed.items()):
        if name not in files:
            problems.append(f"{name}: missing")
        elif sha256_hex(bytes(files[name])) != expected:
            problems.append(f"{name}: sha256 does not match the manifest")
    problems.extend(
        f"{name}: not listed in the manifest"
        for name in sorted(set(files) - set(listed) - {MANIFEST_FILE})
    )
    return problems


__all__ = [
    "CAPTURES_FILE",
    "HAR_FILE",
    "LEDGER_FILE",
    "MANIFEST_FILE",
    "SCRIPT_FILE",
    "ExportRefused",
    "bundle",
    "to_curl",
    "to_har",
    "verify_bundle",
]
