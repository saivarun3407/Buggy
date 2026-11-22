"""The Word report: a valid package, hostile text kept as text, and what a defender needs."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from typing import Any
from urllib.parse import quote, urlsplit
from xml.etree import ElementTree

import pytest

from buggy.capture.store import Capture, sha256_hex
from buggy.findings import report as report_module
from buggy.findings.docx import IMPACT, proven_as, severity_reason, to_docx
from buggy.findings.model import CLASSES, finding_id
from buggy.findings.report import build

ENG = "acme"
BASE = "https://app.acme.test"
GENERATED = "2026-11-22T10:00:00+00:00"
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
PAYLOAD = "' UNION SELECT password FROM users--"
HOSTILE = "]]> <w:p><w:r><w:t>injected</w:t></w:r></w:p> \x00\x01\x1b bell\x07 🐞 &amp; \ud800"
BIG = ("A" * 50_000 + "SQL syntax error" + "B" * 50_000).encode()

REQUIRED = {
    "[Content_Types].xml",
    "_rels/.rels",
    "word/document.xml",
    "word/styles.xml",
    "word/_rels/document.xml.rels",
    "docProps/core.xml",
}


def png(width: int = 4, height: int = 3) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def capture(
    capture_id: str, url: str, body: bytes, *, identity: str = "", replay_of: str = ""
) -> Capture:
    return Capture(
        id=capture_id,
        engagement=ENG,
        created_at=1_700_000_000.0,
        method="GET",
        url=url,
        host=urlsplit(url).hostname or "",
        request_headers={"Accept": "*/*"},
        request_body=b"",
        request_sha256=sha256_hex(b""),
        status=500,
        response_headers={"Content-Type": "text/html"},
        response_body=body,
        response_sha256=sha256_hex(body),
        response_bytes=len(body),
        elapsed_ms=1.0,
        error="",
        note="",
        probe="",
        replay_of=replay_of,
        approval_id="",
        scope_digest="",
        identity=identity,
    )


SQL_URL = f"{BASE}/search?q={quote(PAYLOAD)}"
IDOR_URL = f"{BASE}/api/orders/7"
CAPTURES = {
    c.id: c
    for c in (
        capture("cap-sql", SQL_URL, BIG),
        capture(
            "rp-sql", SQL_URL, BIG + HOSTILE.encode("utf-8", "surrogatepass"), replay_of="cap-sql"
        ),
        capture("cap-idor", IDOR_URL, b'{"owner":"alice"}', identity="bob"),
        capture("rp-idor", IDOR_URL, b'{"owner":"alice"}', identity="bob", replay_of="cap-idor"),
    )
}


def raw_finding(
    cls: str,
    severity: str,
    endpoint: str,
    parameter: str,
    capture_id: str,
    replay: str,
    **extra: Any,
) -> dict[str, Any]:
    identity = CAPTURES[capture_id].identity
    return {
        "id": finding_id(ENG, cls, endpoint, parameter),
        "engagement": ENG,
        "title": extra.pop("title", f"{cls} on {endpoint}"),
        "class": cls,
        "cwe": "CWE-89" if cls == "injection" else "CWE-639",
        "severity": severity,
        "endpoint": endpoint,
        "method": "GET",
        "parameter": parameter,
        "source": "agent:tester",
        "description": extra.pop("description", "found it"),
        "remediation": "Use parameterised queries.",
        "assertions": [
            {
                "capture_id": capture_id,
                "identity": identity,
                "expect": {
                    "status": 500 if cls == "injection" else 200,
                    "body_contains": ["SQL syntax"] if cls == "injection" else ["alice"],
                    "body_not_contains": [],
                    "differs_from": "",
                    "same_as": "",
                },
            }
        ],
        "status": extra.pop("status", "exploit_verified"),
        "verification": {"at": 1.0, "replay_capture_ids": [replay], "reasons": ["held"]},
        "grade": None,
        "grade_reasons": [],
        **extra,
    }


SQLI = raw_finding(
    "injection", "critical", f"{BASE}/search", "q", "cap-sql", "rp-sql", title=HOSTILE
)
IDOR = raw_finding(
    "access_control", "medium", f"{BASE}/api/orders/{{id}}", "", "cap-idor", "rp-idor"
)
UNPROVEN = raw_finding(
    "ssrf", "high", f"{BASE}/fetch", "url", "cap-idor", "rp-idor", status="inconclusive"
)
LEAD = raw_finding("xss", "low", f"{BASE}/x", "t", "cap-idor", "rp-idor", status="candidate")


def make(findings: list[dict] | None = None, **extra: Any) -> dict[str, Any]:
    report = build(
        ENG,
        [IDOR, LEAD, SQLI, UNPROVEN] if findings is None else findings,
        recon_summary=None,
        scope=[BASE],
        captures=CAPTURES.get,
        generated_at=GENERATED,
        complete=True,
    )
    report.update(extra)
    return report


def parts(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.testzip() is None
        return {name: archive.read(name) for name in archive.namelist()}


def document_text(data: bytes) -> str:
    root = ElementTree.fromstring(parts(data)["word/document.xml"])
    paragraphs = []
    for paragraph in root.iter(f"{W}p"):
        paragraphs.append("".join(t.text or "" for t in paragraph.iter(f"{W}t")))
    return "\n".join(paragraphs)


def test_the_package_has_every_required_part_and_all_xml_parses() -> None:
    files = parts(to_docx(make()))
    assert set(files) >= REQUIRED
    for name, content in files.items():
        if name.endswith((".xml", ".rels")):
            ElementTree.fromstring(content)  # raises on corrupt XML
    types = files["[Content_Types].xml"].decode()
    assert "/word/document.xml" in types and "/word/styles.xml" in types


def test_hostile_strings_survive_as_text() -> None:
    data = to_docx(make())
    xml = parts(data)["word/document.xml"].decode("utf-8")
    assert "\x00" not in xml and "\x07" not in xml and "\x1b" not in xml
    root = ElementTree.fromstring(xml)
    # The injected markup did not become a run of its own.
    assert not any((t.text or "") == "injected" for t in root.iter(f"{W}t"))
    text = document_text(data)
    assert "]]> <w:p><w:r><w:t>injected</w:t></w:r></w:p>" in text
    assert "🐞" in text and "&amp;" in text and "bell" in text


def test_a_large_body_is_cut_with_a_marker() -> None:
    text = document_text(to_docx(make()))
    assert "SQL syntax error" in text and "bytes not shown" in text
    assert "A" * 10_000 not in text


def test_findings_are_ordered_most_severe_first_and_payloads_are_present() -> None:
    report = make()
    report["findings"].reverse()  # the renderer orders them itself
    text = document_text(to_docx(report))
    first = text.index(SQLI["id"] + ":")
    second = text.index(IDOR["id"] + ":")
    assert first < second
    assert PAYLOAD in text
    assert f"sent in GET {SQL_URL}" in text


def test_severity_reason_uses_class_rules_and_who_proved_it() -> None:
    report = make()
    by_id = {item["id"]: item for item in report["findings"]}
    sqli, idor = by_id[SQLI["id"]], by_id[IDOR["id"]]
    assert severity_reason(sqli) == (
        "Critical: an attacker can read or change database contents, or run commands, "
        'through the parameter "q" without authenticating.'
    )
    assert severity_reason(idor).startswith("Medium: a caller can read or change data")
    assert 'as a signed-in user; it was proven as the test account "bob"' in severity_reason(idor)
    assert proven_as(idor) == 'the test account(s) "bob"'
    fallback = {**sqli, "class": "unknown", "grade": {"decision": "hold", "reasons": ["Rule 3."]}}
    assert severity_reason(fallback) == "Critical: Rule 3."


def test_every_bug_class_has_a_rule() -> None:
    assert set(IMPACT) == set(CLASSES)


def test_sections_evidence_and_unproven_items() -> None:
    report = make(
        coverage=[
            {"class": "xss", "tested": False, "checks": 0, "findings": 0, "reason": "no forms"}
        ],
        not_tested=[{"area": "GraphQL", "reason": "no endpoint", "enable": "add the URL"}],
    )
    text = document_text(to_docx(report, videos={SQLI["id"]: "proof.webm"}))
    for heading in (
        "Summary",
        "Bug-class coverage",
        "Proven findings",
        "Not proven",
        "Not tested, and why",
    ):
        assert heading in text.split("\n")
    assert "Testing complete: yes" in text
    assert "no forms" in text and "add the URL" in text
    assert (
        CAPTURES["rp-sql"].response_sha256 in text and "rp-sql" in text and "reproduce.sh" in text
    )
    assert f"audit/{ENG}/evidence/{SQLI['id']}/" in text
    assert "proof.webm: a recording of the recorded exchange" in text
    not_proven = text[text.index("Not proven\n") :]
    assert UNPROVEN["id"] in not_proven and LEAD["id"] in not_proven
    assert UNPROVEN["id"] not in text[text.index("Proven findings") : text.index("Not proven\n")]


def test_without_coverage_or_not_tested_those_sections_are_left_out() -> None:
    text = document_text(to_docx(make()))
    assert "Bug-class coverage" not in text and "Not tested, and why" not in text


def test_an_embedded_png_is_referenced_from_rels_and_content_types() -> None:
    image = png()
    files = parts(to_docx(make(), images={SQLI["id"]: image}))
    assert files["word/media/image1.png"] == image
    rels = files["word/_rels/document.xml.rels"].decode()
    assert 'Target="media/image1.png"' in rels and 'Id="rIdImg1"' in rels
    assert 'Extension="png" ContentType="image/png"' in files["[Content_Types].xml"].decode()
    assert 'r:embed="rIdImg1"' in files["word/document.xml"].decode()


def test_an_image_that_is_not_a_png_is_named_not_embedded() -> None:
    files = parts(to_docx(make(), images={SQLI["id"]: b"GIF89a not a png"}))
    assert not any(name.startswith("word/media/") for name in files)
    assert "not a PNG image" in document_text(to_docx(make(), images={SQLI["id"]: b"GIF89a"}))


def test_no_finding_gives_a_report_that_says_so() -> None:
    text = document_text(to_docx(make([LEAD])))
    assert "No vulnerability was proven" in text
    assert "None. No vulnerability was exploit-verified." in text


def test_output_is_deterministic() -> None:
    first = to_docx(make(), images={SQLI["id"]: png()})
    assert first == to_docx(make(), images={SQLI["id"]: png()})
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert {info.date_time for info in archive.infolist()} == {(1980, 1, 1, 0, 0, 0)}
    assert first != to_docx(make([SQLI]))


def test_report_module_reexports_to_docx() -> None:
    assert report_module.to_docx is to_docx


def test_python_docx_can_open_it_when_installed(tmp_path) -> None:
    docx = pytest.importorskip("docx")
    path = tmp_path / "report.docx"
    path.write_bytes(to_docx(make(), images={SQLI["id"]: png()}))
    opened = docx.Document(str(path))
    assert any("Proven findings" in p.text for p in opened.paragraphs)
