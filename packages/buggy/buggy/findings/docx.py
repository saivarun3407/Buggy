"""Word report: the findings report as a ``.docx`` a defender can act on.

:func:`to_docx` renders the dict :func:`buggy.findings.report.build` returns
(the ``report_format`` 1 shape) into the bytes of an Office Open XML word
processing document. Standard library only: the package is a zip of XML
strings, written with fixed timestamps in a fixed order, so the same input gives
the same bytes.

Every string in a report may have come from a target or an agent. Each one is
stripped of the characters XML 1.0 cannot carry (a NUL in a response body
would otherwise make a file Word refuses to open) and then escaped, so no field
can add markup to the document. Long blocks are cut with a marker that says how
much is not shown.

What a proven finding's section holds: why it has its severity (one rule per
bug class in :data:`IMPACT`, filled in with facts of the finding: the
parameter, and whether the proof was sent without credentials or as a
signed-in account), the payloads with the request each was sent in, numbered
steps to reproduce, what the target answered, the evidence (capture ids and
SHA-256, the evidence folder, ``reproduce.sh``), the proof screenshot and video
when given, the remediation and the retest status.
"""

from __future__ import annotations

import io
import re
import struct
import zipfile
from datetime import UTC, datetime
from typing import Any

from buggy.capture.store import REDACTED, SENSITIVE_HEADERS
from buggy.findings.model import SEVERITIES

#: Characters of one monospace block (a payload, a response excerpt, a curl command).
MAX_BLOCK_CHARS = 6000
#: Width of an embedded screenshot at most (6 inches, in EMU).
MAX_IMAGE_EMU = 6 * 914400
_EMU_PER_PIXEL = 9525  # at 96 dpi
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

#: Why a proven finding of each class matters, as the start of a sentence. ``{where}``
#: becomes "through the parameter "q"" or "at this endpoint"; the sentence ends
#: with who could do it (without authenticating, or as a signed-in user).
IMPACT: dict[str, str] = {
    "auth_session": "an attacker can get past authentication or take over a session {where}",
    "access_control": ("a caller can read or change data that belongs to another account {where}"),
    "ssrf": (
        "an attacker can make the server send requests to addresses of their choosing, "
        "internal ones included, {where}"
    ),
    "business_logic": (
        "an attacker can break a rule the application relies on (a price, a limit, an order "
        "of steps) {where}"
    ),
    "api": "the API exposes data or an operation that should not be reachable {where}",
    "graphql": (
        "the GraphQL endpoint exposes schema, data or operations that should not be "
        "reachable {where}"
    ),
    "injection": ("an attacker can read or change database contents, or run commands, {where}"),
    "xss": (
        "an attacker can run script in another user's browser, with that user's access to "
        "the site, {where}"
    ),
    "file_handling": "an attacker can read, upload or overwrite files on the server {where}",
    "csrf": (
        "a page the attacker controls can make a signed-in user's browser perform an action "
        "{where} without the user's consent; the attack itself needs no credentials of its own"
    ),
    "open_redirect": (
        "an attacker can use a link to this site to send users to a site of their choosing {where}"
    ),
    "crypto": "data or credentials are protected with weak or misused cryptography {where}",
    "misconfiguration": "a configuration weakness lowers the application's defences {where}",
    "info_exposure": "the application discloses information an attacker can use {where}",
}

_ILLEGAL_XML = re.compile("[^\t\n\r\x20-퟿-�\U00010000-\U0010ffff]")


def clean(value: Any) -> str:
    """``value`` as text with every character XML 1.0 forbids removed."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    return _ILLEGAL_XML.sub("", text)


def _esc(value: Any) -> str:
    return (
        clean(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _cap(text: str, limit: int = MAX_BLOCK_CHARS) -> str:
    if len(text) <= limit:
        return text
    rest = len(text[limit:].encode("utf-8", "replace"))
    return text[:limit] + f"\n[… {rest} bytes not shown …]"


def _get(item: Any, key: str, default: Any = "") -> Any:
    return item.get(key, default) if isinstance(item, dict) else default


def _str(item: Any, key: str) -> str:
    return clean(_get(item, key))


def _list(item: Any, key: str) -> list[Any]:
    value = _get(item, key, [])
    return value if isinstance(value, list) else []


# ── WordprocessingML pieces ─────────────────────────────────────────


def _run(text: Any, *, bold: bool = False, mono: bool = False, italic: bool = False) -> str:
    props = ""
    if bold:
        props += "<w:b/>"
    if italic:
        props += "<w:i/>"
    if mono:
        props += '<w:rStyle w:val="CodeChar"/>'
    if props:
        props = f"<w:rPr>{props}</w:rPr>"
    pieces: list[str] = []
    for number, line in enumerate(
        clean(text).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ):
        if number:
            pieces.append("<w:br/>")
        for index, part in enumerate(line.split("\t")):
            if index:
                pieces.append("<w:tab/>")
            if part:
                pieces.append(f'<w:t xml:space="preserve">{_esc(part)}</w:t>')
    return f"<w:r>{props}{''.join(pieces)}</w:r>"


def _para(*runs: str, style: str = "") -> str:
    props = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    return f"<w:p>{props}{''.join(runs)}</w:p>"


def _text(value: Any, *, style: str = "") -> str:
    return _para(_run(value), style=style)


def _label(name: str, value: Any) -> str:
    return _para(_run(f"{name}: ", bold=True), _run(value))


def _heading(value: Any, level: int) -> str:
    return _text(value, style=f"Heading{level}")


def _code(value: Any) -> str:
    return _para(_run(_cap(clean(value)), mono=True), style="Code")


def _cell(value: Any, *, header: bool = False) -> str:
    shade = '<w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="D9E2F3"/></w:tcPr>'
    return f"<w:tc>{shade if header else ''}{_para(_run(_cap(clean(value), 2000), bold=header))}</w:tc>"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    head = (
        "<w:tr><w:trPr><w:tblHeader/></w:trPr>"
        + "".join(_cell(name, header=True) for name in headers)
        + "</w:tr>"
    )
    body = "".join("<w:tr>" + "".join(_cell(value) for value in row) + "</w:tr>" for row in rows)
    props = (
        '<w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/>'
        '<w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="0" '
        'w:lastColumn="0" w:noHBand="0" w:noVBand="1"/></w:tblPr>'
    )
    grid = "<w:tblGrid>" + "<w:gridCol/>" * len(headers) + "</w:tblGrid>"
    # A table directly followed by another table merges with it in Word: keep a paragraph after.
    return f"<w:tbl>{props}{grid}{head}{body}</w:tbl>" + _para()


def _png_size(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or not data.startswith(_PNG_SIGNATURE) or data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    return (width, height) if width > 0 and height > 0 else None


def _image(rel_id: str, number: int, size: tuple[int, int]) -> str:
    width, height = size
    cx, cy = width * _EMU_PER_PIXEL, height * _EMU_PER_PIXEL
    if cx > MAX_IMAGE_EMU:
        cx, cy = MAX_IMAGE_EMU, max(1, cy * MAX_IMAGE_EMU // cx)
    return (
        "<w:p><w:r><w:drawing>"
        f'<wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/>'
        f'<wp:docPr id="{number}" name="Proof screenshot {number}"/>'
        '<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
        '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        f'<pic:pic><pic:nvPicPr><pic:cNvPr id="{number}" name="proof{number}.png"/><pic:cNvPicPr/>'
        f'</pic:nvPicPr><pic:blipFill><a:blip r:embed="{rel_id}"/><a:stretch><a:fillRect/>'
        '</a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/>'
        f'<a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
        "</pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>"
    )


# ── what the report says ────────────────────────────────────────────


def _severity_key(item: Any) -> tuple[int, str]:
    severity = _str(item, "severity")
    rank = SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)
    return rank, _str(item, "id")


def _steps(item: Any) -> list[dict[str, Any]]:
    return [step for step in _list(item, "reproduction") if isinstance(step, dict)]


def _identities(item: Any) -> list[str]:
    return sorted({_str(step, "identity") for step in _steps(item) if _str(step, "identity")})


def _carried_credentials(item: Any) -> bool:
    for step in _steps(item):
        headers = _get(_get(step, "request", {}), "headers", {})
        if isinstance(headers, dict) and any(
            str(name).lower() in SENSITIVE_HEADERS or value == REDACTED
            for name, value in headers.items()
        ):
            return True
    return False


def proven_as(item: Any) -> str:
    """Which account the proof was sent as, in words."""
    names = _identities(item)
    if names:
        return "the test account(s) " + ", ".join(f'"{name}"' for name in names)
    if _carried_credentials(item):
        return "no declared test account; the requests carried credentials (shown redacted)"
    return "no account: the requests carried no credentials"


def severity_reason(item: Any) -> str:
    """One plain sentence: the severity and why, from :data:`IMPACT` and facts of the finding."""
    severity = _str(item, "severity")
    label = severity.capitalize() if severity else "Unrated"
    impact = IMPACT.get(_str(item, "class"))
    if impact is None:
        reasons = [clean(r) for r in _list(_get(item, "grade", {}), "reasons") if clean(r)]
        why = "; ".join(reasons) or "this is the severity the finding was filed with"
        return f"{label}: {why.rstrip('.')}."
    parameter = _str(item, "parameter")
    where = f'through the parameter "{parameter}"' if parameter else "at this endpoint"
    names = _identities(item)
    if names:
        who = "as a signed-in user; it was proven as the test account " + ", ".join(
            f'"{name}"' for name in names
        )
    elif _carried_credentials(item):
        who = "with the credentials the proof requests carried"
    else:
        who = "without authenticating"
    return f"{label}: {impact.format(where=where)} {who}."


def _omitted(part: Any, text: str) -> str:
    before = _get(part, "omitted_before", 0)
    after = _get(part, "omitted_after", 0)
    out = text
    if isinstance(before, int) and before > 0:
        out = f"[… {before} bytes not shown …]\n" + out
    if isinstance(after, int) and after > 0:
        out = out + f"\n[… {after} bytes not shown …]"
    return out


# ── the document ────────────────────────────────────────────────────


class _Media:
    def __init__(self) -> None:
        self.files: list[tuple[str, bytes]] = []

    def add(self, data: bytes) -> tuple[str, int]:
        number = len(self.files) + 1
        self.files.append((f"image{number}.png", data))
        return f"rIdImg{number}", number


def _finding(
    item: dict[str, Any],
    images: dict[str, bytes],
    videos: dict[str, str],
    media: _Media,
    engagement: str,
) -> list[str]:
    fid = _str(item, "id")
    out = [_heading(f"{fid}: {_str(item, 'title')}", 2)]
    out.append(_para(_run("Severity: ", bold=True), _run(severity_reason(item))))
    out.append(
        _table(
            ["Field", "Value"],
            [
                ["CWE", _str(item, "cwe") or "none given"],
                ["Class", _str(item, "class")],
                ["Endpoint", _str(item, "endpoint")],
                ["Method", _str(item, "method")],
                ["Parameter", _str(item, "parameter") or "none"],
                ["Proven as", proven_as(item)],
                ["Source", _str(item, "source")],
            ],
        )
    )
    if _str(item, "description"):
        out.extend([_heading("Description", 3), _text(_cap(_str(item, "description")))])

    steps = _steps(item)
    out.append(_heading("Payloads used", 3))
    with_payload = [step for step in steps if _str(step, "payload")]
    if not with_payload:
        out.append(
            _text(
                "No injected value was recorded for a named parameter: the proof is the requests "
                "exactly as listed in the steps below."
            )
        )
    for step in with_payload:
        request = _get(step, "request", {})
        out.append(
            _text(
                f"Step {_get(step, 'number', '')}: sent in {_str(request, 'method')} "
                f"{_str(request, 'url')} (capture {_str(step, 'capture_id')})"
            )
        )
        out.append(_code(_str(step, "payload")))

    out.append(_heading("Steps to reproduce", 3))
    if not steps:
        out.append(_text("No assertions are recorded."))
    for step in steps:
        out.append(_text(_str(step, "text")))
        if _str(step, "curl"):
            out.append(_code(_str(step, "curl")))

    out.append(_heading("What the target answered", 3))
    answered = False
    for step in steps:
        response = _get(step, "response", None)
        if not isinstance(response, dict):
            continue
        answered = True
        status = _get(response, "status", None)
        line = f"HTTP {status}" if isinstance(status, int) else "no response"
        where = "the verifier's replay" if _get(step, "replayed", False) else "the recorded request"
        out.append(
            _text(
                f"Step {_get(step, 'number', '')}: {line} to {where} "
                f"(capture {_str(response, 'capture_id')})."
            )
        )
        if _str(response, "match"):
            out.append(
                _para(_run("Proving text: ", bold=True), _run(_str(response, "match"), mono=True))
            )
        if _str(response, "body"):
            out.append(_code(_omitted(response, _cap(_str(response, "body")))))
    if not answered:
        for proof in _list(item, "proof"):
            answered = True
            out.append(_text(_str(proof, "status_line")))
            if _str(proof, "excerpt"):
                out.append(_code(_str(proof, "excerpt")))
    if not answered:
        out.append(_text("No response is recorded in this report."))

    out.append(_heading("Evidence", 3))
    rows: list[list[Any]] = []
    for step in steps:
        number = _get(step, "number", "")
        request = _get(step, "request", {})
        if _str(step, "capture_id"):
            rows.append(
                [
                    _str(step, "capture_id"),
                    f"step {number} request",
                    _str(request, "sha256") or "not recorded",
                ]
            )
        response = _get(step, "response", {})
        if _str(response, "capture_id") and _str(response, "capture_id") != _str(
            step, "capture_id"
        ):
            rows.append(
                [
                    _str(response, "capture_id"),
                    f"step {number} replay response",
                    _str(response, "sha256") or "not recorded",
                ]
            )
        elif _str(response, "sha256"):
            rows.append(
                [_str(step, "capture_id"), f"step {number} response", _str(response, "sha256")]
            )
    listed = {row[0] for row in rows}
    for proof in _list(item, "proof"):
        if _str(proof, "capture_id") and _str(proof, "capture_id") not in listed:
            rows.append(
                [
                    _str(proof, "capture_id"),
                    "verifier replay",
                    _str(proof, "sha256") or "not recorded",
                ]
            )
    if rows:
        out.append(_table(["Capture", "What it is", "SHA-256"], rows))
    folder = _str(item, "evidence_folder") or f"audit/{engagement}/evidence/{fid}/"
    out.append(_label("Evidence folder", folder))
    out.append(
        _label(
            "Reproduction script",
            "reproduce.sh in the evidence bundle evidence_export writes for this finding "
            "(one curl command per captured request, credentials replaced by placeholders)",
        )
    )
    image = images.get(fid)
    if image is not None:
        size = _png_size(image)
        if size is None:
            out.append(_text("The proof screenshot was not embedded: it is not a PNG image."))
        else:
            rel_id, number = media.add(image)
            out.append(_text("Proof screenshot (the first proof step of the recorded exchange):"))
            out.append(_image(rel_id, number, size))
    video = videos.get(fid)
    if video:
        out.append(
            _label(
                "Proof video",
                f"{clean(video)}: a recording of the recorded exchange rendered offline; nothing "
                "was sent to the target while it was recorded",
            )
        )

    out.append(_heading("Remediation", 3))
    out.append(_text(_cap(_str(item, "remediation")) or "None given."))
    retest = _get(item, "retest", None)
    if isinstance(retest, dict) and _str(retest, "outcome"):
        words = {
            "fixed": "fixed",
            "still_vulnerable": "still vulnerable",
            "inconclusive": "could not tell",
        }
        outcome = words.get(_str(retest, "outcome"), _str(retest, "outcome"))
        out.append(_label("Retest", f"{outcome} (retested {_str(retest, 'at')})"))
    return out


def _body(
    report: dict[str, Any], images: dict[str, bytes], videos: dict[str, str], media: _Media
) -> str:
    engagement = _str(report, "engagement")
    summary = _get(report, "summary", {})
    findings = sorted(
        (item for item in _list(report, "findings") if isinstance(item, dict)), key=_severity_key
    )
    out: list[str] = [_text(f"Security report: {engagement}", style="Title")]
    out.append(_label("Engagement", engagement))
    out.append(_label("Generated", _str(report, "generated_at")))
    out.append(_label("Testing complete", "yes" if _get(summary, "complete", False) else "no"))
    out.append(_heading("Scope", 1))
    scope = [clean(entry) for entry in _list(report, "scope")]
    out.extend(_text(f"• {entry}") for entry in scope)
    if not scope:
        out.append(_text("No scope was given to this report."))

    out.append(_heading("Summary", 1))
    if findings:
        out.append(_text(f"{len(findings)} proven finding(s): each was re-proved by the verifier."))
    else:
        out.append(_text("No vulnerability was proven: the verifier re-proved none of the claims."))
    counts = {severity: 0 for severity in SEVERITIES}
    for item in findings:
        if _str(item, "severity") in counts:
            counts[_str(item, "severity")] += 1
    out.append(_table(["Severity", "Proven findings"], [[s, str(n)] for s, n in counts.items()]))
    if findings:
        out.append(
            _table(
                ["ID", "Title", "Severity", "Class", "Endpoint"],
                [
                    [
                        _str(i, "id"),
                        _str(i, "title"),
                        _str(i, "severity"),
                        _str(i, "class"),
                        _str(i, "endpoint"),
                    ]
                    for i in findings
                ],
            )
        )

    coverage = _get(report, "coverage", None)
    if isinstance(coverage, list):
        out.append(_heading("Bug-class coverage", 1))
        out.append(
            _table(
                ["Class", "Tested", "Checks", "Findings", "Reason"],
                [
                    [
                        _str(row, "class"),
                        "yes" if _get(row, "tested", False) else "no",
                        clean(_get(row, "checks", 0)),
                        clean(_get(row, "findings", 0)),
                        _str(row, "reason"),
                    ]
                    for row in coverage
                    if isinstance(row, dict)
                ],
            )
        )

    out.append(_heading("Proven findings", 1))
    if not findings:
        out.append(_text("None. No vulnerability was exploit-verified."))
    for item in findings:
        out.extend(_finding(item, images, videos, media, engagement))

    out.append(_heading("Not proven", 1))
    out.append(
        _text(
            "These items were not re-proved by a replay. They are not findings and are listed "
            "so they can be followed up."
        )
    )
    rows: list[list[Any]] = []
    for item in _list(report, "unverified"):
        reasons = [clean(r) for r in _list(item, "verifier_reasons")]
        rows.append(
            [
                _str(item, "id"),
                _str(item, "title"),
                _str(item, "status"),
                _str(item, "severity"),
                _str(item, "class"),
                _str(item, "endpoint"),
                "; ".join(reasons) or "none given",
            ]
        )
    for item in _list(report, "leads"):
        rows.append(
            [
                _str(item, "id"),
                _str(item, "title"),
                _str(item, "status") or "candidate",
                _str(item, "severity"),
                _str(item, "class"),
                _str(item, "endpoint"),
                "not tested yet",
            ]
        )
    if rows:
        out.append(
            _table(
                [
                    "ID",
                    "Title",
                    "Status",
                    "Claimed severity",
                    "Class",
                    "Endpoint",
                    "Why not proven",
                ],
                rows,
            )
        )
    else:
        out.append(_text("None."))

    not_tested = _get(report, "not_tested", None)
    if isinstance(not_tested, list):
        out.append(_heading("Not tested, and why", 1))
        out.append(
            _table(
                ["Area", "Reason", "How to enable"],
                [
                    [_str(row, "area"), _str(row, "reason"), _str(row, "enable")]
                    for row in not_tested
                    if isinstance(row, dict)
                ],
            )
        )
    if _str(report, "method"):
        out.extend([_heading("Method", 1), _text(_str(report, "method"))])
    return "".join(out)


_NS = (
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"'
)
_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_SECTION = (
    '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" '
    'w:bottom="1134" w:left="1134" w:header="709" w:footer="709" w:gutter="0"/></w:sectPr>'
)

_STYLES = (
    _DECL + '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" '
    'w:eastAsia="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:szCs w:val="21"/>'
    '<w:lang w:val="en-GB"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr>'
    '<w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault>'
    "</w:docDefaults>"
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/>'
    "<w:qFormat/></w:style>"
    '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/>'
    '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr>'
    '<w:spacing w:after="240"/></w:pPr><w:rPr><w:b/><w:sz w:val="44"/><w:szCs w:val="44"/>'
    "</w:rPr></w:style>"
    + "".join(
        f'<w:style w:type="paragraph" w:styleId="Heading{level}"><w:name w:val="heading {level}"/>'
        '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/>'
        f'<w:spacing w:before="{360 - 80 * level}" w:after="120"/>'
        f'<w:outlineLvl w:val="{level - 1}"/></w:pPr><w:rPr><w:b/><w:sz w:val="{size}"/>'
        f'<w:szCs w:val="{size}"/></w:rPr></w:style>'
        for level, size in ((1, 32), (2, 27), (3, 23))
    )
    + '<w:style w:type="paragraph" w:customStyle="1" w:styleId="Code"><w:name w:val="Code"/>'
    '<w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="120" w:line="240" w:lineRule="auto"/>'
    '<w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/></w:pPr><w:rPr>'
    '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="17"/>'
    '<w:szCs w:val="17"/></w:rPr></w:style>'
    '<w:style w:type="character" w:customStyle="1" w:styleId="CodeChar">'
    '<w:name w:val="Code Char"/><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" '
    'w:cs="Consolas"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr></w:style>'
    '<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/>'
    '<w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/>'
    '<w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/>'
    '<w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>'
    '<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/>'
    '<w:basedOn w:val="TableNormal"/><w:pPr><w:spacing w:after="0"/></w:pPr><w:tblPr><w:tblBorders>'
    + "".join(
        f'<w:{side} w:val="single" w:sz="4" w:space="0" w:color="A6A6A6"/>'
        for side in ("top", "left", "bottom", "right", "insideH", "insideV")
    )
    + "</w:tblBorders></w:tblPr></w:style></w:styles>"
)


def _content_types() -> str:
    return (
        _DECL + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.wordprocessingml.styles+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-'
        'package.core-properties+xml"/>'
        "</Types>"
    )


_ROOT_RELS = (
    _DECL + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/officeDocument" Target="word/document.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/'
    'metadata/core-properties" Target="docProps/core.xml"/>'
    "</Relationships>"
)


def _document_rels(media: _Media) -> str:
    images = "".join(
        f'<Relationship Id="rIdImg{number}" Type="http://schemas.openxmlformats.org/'
        f'officeDocument/2006/relationships/image" Target="media/{name}"/>'
        for number, (name, _data) in enumerate(media.files, start=1)
    )
    return (
        _DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/styles" Target="styles.xml"/>' + images + "</Relationships>"
    )


def _w3cdtf(value: str) -> str:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _core(report: dict[str, Any]) -> str:
    created = _w3cdtf(_str(report, "generated_at"))
    dates = (
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>'
        if created
        else ""
    )
    return (
        _DECL
        + '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/'
        'core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>Security report: {_esc(_str(report, 'engagement'))}</dc:title>"
        "<dc:creator>buggy</dc:creator>"
        f"{dates}</cp:coreProperties>"
    )


def to_docx(
    report: dict[str, Any],
    *,
    images: dict[str, bytes] | None = None,
    videos: dict[str, str] | None = None,
) -> bytes:
    """The report as the bytes of a ``.docx`` file.

    ``images`` maps a finding id to the PNG screenshot embedded in that
    finding's section (``proof.png`` from the evidence folder); ``videos`` maps
    a finding id to the proof video's file name, which the section names.
    Nothing is read from disk and the clock is not read.
    """
    media = _Media()
    body = _body(
        report if isinstance(report, dict) else {}, dict(images or {}), dict(videos or {}), media
    )
    document = f"{_DECL}<w:document {_NS}><w:body>{body}{_SECTION}</w:body></w:document>"
    parts: list[tuple[str, bytes]] = [
        ("[Content_Types].xml", _content_types().encode("utf-8")),
        ("_rels/.rels", _ROOT_RELS.encode("utf-8")),
        ("docProps/core.xml", _core(report if isinstance(report, dict) else {}).encode("utf-8")),
        ("word/document.xml", document.encode("utf-8")),
        ("word/styles.xml", _STYLES.encode("utf-8")),
        ("word/_rels/document.xml.rels", _document_rels(media).encode("utf-8")),
        *((f"word/media/{name}", data) for name, data in media.files),
    ]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in parts:
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = (
                zipfile.ZIP_STORED if name.endswith(".png") else zipfile.ZIP_DEFLATED
            )
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return buffer.getvalue()


__all__ = [
    "IMPACT",
    "MAX_BLOCK_CHARS",
    "clean",
    "proven_as",
    "severity_reason",
    "to_docx",
]
