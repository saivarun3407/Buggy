"""Findings report: sections and counts, escaping, reproduction steps, redaction, stability.

Captures are real :class:`buggy.capture.store.Capture` records; the report reads
them through the same ``detail()`` view and ``to_curl`` an evidence bundle uses.
The HTML is checked with the standard library's parser (which tags and
attributes exist), the Markdown with a small CommonMark-faithful scan of fences,
headings and table cells, so a hostile field that broke the structure would be
seen as structure, not as text.
"""

from __future__ import annotations

import copy
import html
import json
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

import pytest

from buggy.capture.store import REDACTED, Capture, sha256_hex
from buggy.findings.model import finding_id
from buggy.findings.report import EXCERPT_CHARS, build, md_inline, to_html, to_json, to_markdown

ENG = "acme"
BASE = "https://app.acme.test"
ORDER = f"{BASE}/api/orders/1001"
SEARCH = f"{BASE}/search?q=%27"
GENERATED = "2026-11-20T12:00:00+00:00"

HOSTILE_TITLE = "<script>alert(\"x\")</script> & 'quoted' <img src=x onerror=alert(1)>"
HOSTILE_DESCRIPTION = (
    "First line <b>bold</b> & more\n# Injected heading\n| fake | table |\n\n"
    "[link](javascript:alert(1)) ```"
)
HOSTILE_BODY = (
    "You have an error in your SQL syntax near '\"' <script>steal()</script> & co\n"
    "```\n## Escaped fence heading\n````\n"
)


def capture(
    capture_id: str,
    url: str,
    *,
    method: str = "GET",
    status: int | None = 200,
    body: bytes = b"",
    identity: str = "",
    request_headers: dict[str, str] | None = None,
    response_headers: dict[str, str] | None = None,
    redact_headers: tuple[str, ...] = (),
    engagement: str = ENG,
) -> Capture:
    return Capture(
        id=capture_id,
        engagement=engagement,
        created_at=1_700_000_000.0,
        method=method,
        url=url,
        host=urlsplit(url).hostname or "",
        request_headers=request_headers or {},
        request_body=b"",
        request_sha256="",
        status=status,
        response_headers=response_headers or {},
        response_body=body,
        response_sha256=sha256_hex(body),
        response_bytes=len(body),
        elapsed_ms=12.0,
        error="",
        note="",
        probe="",
        replay_of="",
        approval_id="",
        scope_digest="",
        identity=identity,
        redact_headers=redact_headers,
    )


def finding(
    title: str,
    cls: str,
    severity: str,
    endpoint: str,
    status: str,
    *,
    parameter: str = "",
    assertions: list[dict[str, Any]] | None = None,
    replay_ids: list[str] | None = None,
    reasons: list[str] | None = None,
    description: str = "",
    remediation: str = "",
    grade: str | None = None,
    grade_reasons: list[str] | None = None,
    engagement: str = ENG,
    source: str = "agent:tester",
) -> dict[str, Any]:
    return {
        "id": finding_id(engagement, cls, endpoint, parameter),
        "engagement": engagement,
        "title": title,
        "class": cls,
        "cwe": "",
        "severity": severity,
        "endpoint": endpoint,
        "method": "GET",
        "parameter": parameter,
        "source": source,
        "description": description,
        "remediation": remediation,
        "assertions": assertions or [],
        "status": status,
        "verification": {
            "at": 1_700_000_100.0,
            "replay_capture_ids": replay_ids or [],
            "reasons": reasons or [],
        },
        "grade": grade,
        "grade_reasons": grade_reasons or [],
        "created_at": 1_700_000_000.0,
        "updated_at": 1_700_000_100.0,
    }


def expect(**values: Any) -> dict[str, Any]:
    base = {
        "status": None,
        "body_contains": [],
        "body_not_contains": [],
        "differs_from": "",
        "same_as": "",
    }
    base.update(values)
    return base


ORDER_BODY = b'{"id":1001,"owner":"alice@acme.test","total":42}'
CAPTURES: dict[str, Capture] = {
    c.id: c
    for c in (
        capture("cap-own", ORDER, body=ORDER_BODY, identity="alice"),
        capture("cap-atk", ORDER, body=ORDER_BODY, identity="bob"),
        capture("rp-own", ORDER, body=ORDER_BODY, identity="alice"),
        capture(
            "rp-atk",
            ORDER,
            body=ORDER_BODY,
            identity="bob",
            response_headers={"Content-Type": "application/json"},
        ),
        capture("cap-sql", SEARCH, status=500, body=HOSTILE_BODY.encode()),
        capture("rp-sql", SEARCH, status=500, body=HOSTILE_BODY.encode() + b"x" * 1000),
        capture("cap-other", ORDER, engagement="other-eng"),
    )
}


def lookup(capture_id: str) -> Capture | None:
    return CAPTURES.get(capture_id)


IDOR = finding(
    "IDOR on GET /api/orders/{id}",
    "access_control",
    "high",
    f"{BASE}/api/orders/{{id}}",
    "exploit_verified",
    parameter="id",
    assertions=[
        {"capture_id": "cap-own", "identity": "alice", "expect": expect(status=200)},
        {
            "capture_id": "cap-atk",
            "identity": "bob",
            "expect": expect(status=200, body_contains=["alice@"], same_as="cap-own"),
        },
    ],
    replay_ids=["rp-own", "rp-atk"],
    reasons=["all 2 assertion(s) passed on a fresh replay"],
    description="Bob reads Alice's order.",
    remediation="Check that the order belongs to the caller before returning it.",
    grade="hold",
    grade_reasons=["Rule 5 (duplicates): already reported by scanner template idor-check."],
)
SQLI = finding(
    HOSTILE_TITLE,
    "injection",
    "critical",
    f"{BASE}/search",
    "exploit_verified",
    parameter="q",
    assertions=[
        {
            "capture_id": "cap-sql",
            "identity": "",
            "expect": expect(
                status=[500, 502],
                body_contains=["SQL syntax"],
                body_not_contains=["Access denied"],
            ),
        }
    ],
    replay_ids=["rp-sql"],
    reasons=["all 1 assertion(s) passed on a fresh replay"],
    description=HOSTILE_DESCRIPTION,
    remediation="Use parameterised queries & never <concatenate> input.",
    grade="submit",
    grade_reasons=["Rule 8 (submit): ready to submit."],
)
INCONCLUSIVE = finding(
    "SSRF via url parameter",
    "ssrf",
    "high",
    f"{BASE}/fetch",
    "inconclusive",
    parameter="url",
    assertions=[{"capture_id": "cap-x", "identity": "", "expect": expect(status=200)}],
    reasons=["assertion[0] (cap-x): status 404, expected 200"],
    grade="hold",
    grade_reasons=["Rule 1 (verification): not exploit-verified: inconclusive."],
)
LEADS = [
    finding("Open redirect | next=", "open_redirect", "low", f"{BASE}/login", "candidate"),
    finding("Missing CSP header", "misconfiguration", "info", f"{BASE}/", "candidate"),
    finding(
        "Reflected XSS in search",
        "xss",
        "medium",
        f"{BASE}/search",
        "candidate",
        parameter="term",
        assertions=[{"capture_id": "cap-sql", "identity": "", "expect": expect(status=200)}],
    ),
]
DISCARDED = finding(
    "DISCARDED-MARKER claim", "api", "critical", f"{BASE}/api/x", "discarded", reasons=["gone"]
)
FIXTURE = [LEADS[0], DISCARDED, INCONCLUSIVE, IDOR, LEADS[1], SQLI, LEADS[2]]


def make(findings: list[dict[str, Any]] | None = None, **kwargs: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "recon_summary": {"hosts": 3, "note": "nuclei <run> | done"},
        "scope": [f"{BASE}", "*.acme.test"],
        "captures": lookup,
        "generated_at": GENERATED,
        "complete": True,
    }
    options.update(kwargs)
    return build(ENG, copy.deepcopy(FIXTURE if findings is None else findings), **options)


def render_all(report: dict[str, Any]) -> dict[str, str]:
    return {"md": to_markdown(report), "html": to_html(report), "json": to_json(report)}


# ── Markdown structure, read the way a CommonMark renderer reads it ──


def md_lines(markdown: str) -> list[tuple[str, str]]:
    """Every line with its kind: ``text``, ``fence`` (opens or closes code) or ``code``."""
    out: list[tuple[str, str]] = []
    fence = ""
    for line in markdown.split("\n"):
        if not fence:
            opened = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
            if opened:
                fence = opened.group(1)
            out.append((line, "fence" if opened else "text"))
        else:
            closing = re.match(r"^ {0,3}(`{3,}|~{3,})\s*$", line)
            if closing and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= len(fence):
                fence = ""
                out.append((line, "fence"))
            else:
                out.append((line, "code"))
    assert not fence, "a code fence was left open"
    return out


def md_blocks(markdown: str) -> tuple[list[str], list[str]]:
    """``(lines outside fenced code, lines inside fenced code)``; fence lines in neither."""
    lines = md_lines(markdown)
    return [ln for ln, kind in lines if kind == "text"], [
        ln for ln, kind in lines if kind == "code"
    ]


def md_headings(markdown: str) -> list[str]:
    outside, _inside = md_blocks(markdown)
    return [line for line in outside if re.match(r"^ {0,3}#{1,6}(\s|$)", line)]


def unescaped_pipes(line: str) -> int:
    count = 0
    index = 0
    while index < len(line):
        if line[index] == "\\":
            index += 2
            continue
        count += line[index] == "|"
        index += 1
    return count


def md_section(markdown: str, heading: str) -> str:
    """The lines from ``heading`` up to the next level-2 heading outside fenced code."""
    taken: list[str] = []
    inside = False
    for line, kind in md_lines(markdown):
        if kind == "text" and line.startswith("## "):
            if inside:
                break
            inside = line == heading
        if inside:
            taken.append(line)
    assert taken, f"no section {heading!r}"
    return "\n".join(taken)


# ── HTML structure ───────────────────────────────────────────────────


class Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: set[str] = set()
        self.attributes: list[tuple[str, str, str | None]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.add(tag)
        self.attributes.extend((tag, name, value) for name, value in attrs)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def parse_html(document: str) -> Collector:
    parser = Collector()
    parser.feed(document)
    parser.close()
    return parser


ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "h1", "h2", "h3", "h4", "p", "strong",
    "section", "dl", "dt", "dd", "pre", "table", "thead", "tbody", "tr", "th", "td", "ul", "li",
}  # fmt: skip
ALLOWED_ATTRIBUTES = {
    ("html", "lang"),
    ("meta", "charset"),
    ("meta", "http-equiv"),
    ("meta", "content"),
    ("meta", "name"),
    ("section", "class"),
    ("p", "class"),
}


# ── the tests ────────────────────────────────────────────────────────


class TestSectionsAndCounts:
    def test_report_dict_sorts_items_into_the_right_sections(self) -> None:
        report = make()
        assert [item["id"] for item in report["findings"]] == [SQLI["id"], IDOR["id"]]
        assert all(item["status"] == "exploit_verified" for item in report["findings"])
        assert [item["id"] for item in report["unverified"]] == [INCONCLUSIVE["id"]]
        assert report["unverified"][0]["label"].startswith("inconclusive: not proven")
        assert (
            report["unverified"][0]["verifier_reasons"] == INCONCLUSIVE["verification"]["reasons"]
        )
        # Leads by severity then id.
        assert [lead["id"] for lead in report["leads"]] == [
            LEADS[2]["id"],
            LEADS[0]["id"],
            LEADS[1]["id"],
        ]
        assert report["summary"] == {
            "complete": True,
            "verified": 2,
            "verified_by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
            "source_verified": 0,
            "inconclusive": 1,
            "candidates": 3,
            "discarded": 1,
            "other_engagement": 0,
            "unrecognised": 0,
        }
        assert report["generated_at"] == GENERATED
        assert report["scope"] == [BASE, "*.acme.test"]

    def test_markdown_has_each_section_and_keeps_unproven_items_out_of_the_proven_one(
        self,
    ) -> None:
        markdown = to_markdown(make())
        level2 = [h for h in md_headings(markdown) if h.startswith("## ")]
        assert level2 == [
            "## Summary",
            "## Method",
            "## Scope",
            "## Recon summary",
            "## Verified findings",
            "## Not proven by replay",
            "## Leads (not tested)",
            "## Discarded",
        ]
        proven = md_section(markdown, "## Verified findings")
        not_proven = md_section(markdown, "## Not proven by replay")
        leads = md_section(markdown, "## Leads (not tested)")
        for item in (IDOR, SQLI):
            assert md_inline(item["id"]) in proven
        assert md_inline(INCONCLUSIVE["id"]) not in proven
        assert md_inline(INCONCLUSIVE["id"]) in not_proven
        assert md_inline("assertion[0] (cap-x): status 404, expected 200") in not_proven
        for lead in LEADS:
            assert md_inline(lead["id"]) not in proven
            assert md_inline(lead["id"]) not in not_proven
            assert md_inline(lead["id"]) in leads
        assert "| critical | 1 |" in markdown and "| high | 1 |" in markdown
        assert "| discarded | 1 |" in markdown and "| leads (candidates) | 3 |" in markdown
        assert "1 claim(s) were discarded" in markdown

    def test_html_has_each_section_and_keeps_unproven_items_out_of_the_proven_one(self) -> None:
        document = to_html(make())
        proven = document[document.index("<h2>Verified findings</h2>") :]
        proven = proven[: proven.index("<h2>Not proven by replay</h2>")]
        rest = document[document.index("<h2>Not proven by replay</h2>") :]
        assert IDOR["id"] in proven and SQLI["id"] in proven
        assert INCONCLUSIVE["id"] not in proven and INCONCLUSIVE["id"] in rest
        for lead in LEADS:
            assert lead["id"] not in proven and lead["id"] in rest
        assert "<td>discarded</td><td>1</td>" in document
        assert "<td>inconclusive</td><td>1</td>" in document

    def test_discarded_items_appear_only_as_a_count(self) -> None:
        for name, text in render_all(make()).items():
            assert "DISCARDED-MARKER" not in text, name
            assert DISCARDED["id"] not in text, name
        assert json.loads(to_json(make()))["summary"]["discarded"] == 1

    def test_headings_say_finding_or_vulnerability_only_for_exploit_verified_items(self) -> None:
        markdown = to_markdown(make())
        named = [
            h for h in md_headings(markdown) if re.search(r"finding|vulnerab", h, re.IGNORECASE)
        ]
        assert named == ["## Verified findings"]

    def test_grades_are_shown_with_their_reasons(self) -> None:
        texts = render_all(make())
        reason = "Rule 5 (duplicates): already reported by scanner template idor-check."
        assert md_inline(reason) in texts["md"]
        assert html.escape(reason) in texts["html"]
        assert reason in texts["json"]
        assert "**Grade:** hold" in texts["md"]
        held = "Rule 1 (verification): not exploit-verified: inconclusive."
        assert md_inline(held) in md_section(texts["md"], "## Not proven by replay")

    def test_source_verified_is_listed_as_unverified_and_labelled(self) -> None:
        reviewed = finding(
            "Hard-coded key in bundle",
            "crypto",
            "high",
            f"{BASE}/static/app.js",
            "source_verified",
            reasons=["source-verified: reviewed main.js"],
            source="source:review",
        )
        report = make([reviewed])
        assert report["findings"] == []
        assert report["summary"]["verified"] == 0
        assert report["summary"]["source_verified"] == 1
        assert report["unverified"][0]["label"].startswith("source-verified")
        markdown = to_markdown(report)
        assert md_inline(reviewed["id"]) not in md_section(markdown, "## Verified findings")
        assert md_inline(report["unverified"][0]["label"]) in markdown

    def test_rows_of_another_engagement_are_left_out(self) -> None:
        foreign = finding(
            "Elsewhere", "api", "high", f"{BASE}/api/z", "exploit_verified", engagement="other"
        )
        report = make([foreign, IDOR])
        assert [item["id"] for item in report["findings"]] == [IDOR["id"]]
        assert report["summary"]["other_engagement"] == 1
        assert "Elsewhere" not in to_markdown(report)


class TestReproduction:
    def test_idor_steps_are_generated_from_its_assertions(self) -> None:
        item = next(f for f in make()["findings"] if f["id"] == IDOR["id"])
        assert [step["text"] for step in item["reproduction"]] == [
            f'1. Send GET {ORDER} as identity "alice" (capture cap-own). Expect: status is 200.',
            f'2. Send GET {ORDER} as identity "bob" (capture cap-atk). Expect: status is 200; '
            'the body contains "alice@"; the response matches capture cap-own '
            "(similarity at least 0.95).",
        ]
        assert [step["capture_id"] for step in item["reproduction"]] == ["cap-own", "cap-atk"]
        assert all("\ncurl --globoff" in step["curl"] for step in item["reproduction"])
        assert "Sent as identity 'bob'" in item["reproduction"][1]["curl"]
        assert ORDER in item["reproduction"][1]["curl"]

    def test_single_request_steps_are_generated_from_its_assertion(self) -> None:
        item = next(f for f in make()["findings"] if f["id"] == SQLI["id"])
        assert [step["text"] for step in item["reproduction"]] == [
            f"1. Send GET {SEARCH} with no named identity (capture cap-sql). Expect: status is "
            '500 or 502; the body contains "SQL syntax"; the body does not contain '
            '"Access denied".'
        ]

    def test_a_capture_the_report_cannot_see_is_named_not_invented(self) -> None:
        ghost = finding(
            "Ghost",
            "api",
            "low",
            f"{BASE}/api/ghost",
            "exploit_verified",
            assertions=[
                {"capture_id": "cap-missing", "identity": "", "expect": expect(status=200)},
                {"capture_id": "cap-other", "identity": "", "expect": expect(status=200)},
            ],
            replay_ids=["cap-other"],
        )
        item = make([ghost])["findings"][0]
        assert [step["text"] for step in item["reproduction"]] == [
            "1. Send capture cap-missing (not available to this report). Expect: status is 200.",
            "2. Send capture cap-other (not available to this report). Expect: status is 200.",
        ]
        assert item["proof"][0]["status_line"] == (
            "replay capture cap-other is not available to this report"
        )

    def test_proof_is_the_replay_status_and_the_first_characters_of_its_response(self) -> None:
        item = next(f for f in make()["findings"] if f["id"] == SQLI["id"])
        (proof,) = item["proof"]
        replay = CAPTURES["rp-sql"]
        assert proof["capture_id"] == "rp-sql"
        assert proof["status_line"] == (
            f"HTTP 500 to GET {SEARCH}, response sha256 {replay.response_sha256}"
        )
        assert proof["excerpt"] == replay.response_body.decode()[:EXCERPT_CHARS]
        assert len(proof["excerpt"]) == EXCERPT_CHARS
        assert proof["truncated"] is True


class TestEscaping:
    def test_html_carries_no_script_handler_or_external_resource(self) -> None:
        document = to_html(make())
        parsed = parse_html(document)
        assert parsed.tags <= ALLOWED_TAGS, parsed.tags - ALLOWED_TAGS
        for tag, name, _value in parsed.attributes:
            assert (tag, name) in ALLOWED_ATTRIBUTES, (tag, name)
        assert "<script" not in document.lower()
        assert "<img" not in document.lower()
        assert "url(" not in document and "@import" not in document
        assert "http-equiv" in document and "default-src 'none'" in document

    def test_hostile_text_is_escaped_in_html_and_reads_back_unchanged(self) -> None:
        document = to_html(make())
        text = "".join(parse_html(document).text)
        assert html.escape(HOSTILE_TITLE, quote=True) in document
        assert HOSTILE_TITLE in text
        # Description paragraphs, the remediation and the response excerpt read back as text.
        assert "First line <b>bold</b> & more\n# Injected heading" in text
        assert "never <concatenate> input" in text
        assert "<script>steal()</script> & co" in text
        assert "&lt;script&gt;steal()&lt;/script&gt; &amp; co" in document
        assert "<b>" not in document

    def test_hostile_text_is_unchanged_in_json(self) -> None:
        raw = to_json(make())
        loaded = json.loads(raw)
        sqli = next(f for f in loaded["findings"] if f["id"] == SQLI["id"])
        assert sqli["title"] == HOSTILE_TITLE
        assert sqli["description"] == HOSTILE_DESCRIPTION
        assert sqli["proof"][0]["excerpt"].startswith(HOSTILE_BODY)
        assert "<script>alert(" in raw and "&lt;" not in raw

    def test_markdown_fields_cannot_break_the_document_structure(self) -> None:
        markdown = to_markdown(make())
        headings = md_headings(markdown)
        assert not any("Injected" in h or "Escaped fence" in h for h in headings), headings
        outside, inside = md_blocks(markdown)
        # The excerpt's own fences and heading stayed inside the code block.
        assert "## Escaped fence heading" in inside and "```" in inside
        prose = "\n".join(outside)
        assert md_inline(HOSTILE_TITLE) in prose
        # What a renderer acts on is what is left once backslash escapes are removed:
        # no raw HTML, entity, link or code span may survive from a field.
        unescaped = re.sub(r"\\.", "", prose)
        assert "<" not in unescaped and "&" not in unescaped
        assert "](" not in unescaped and "`" not in unescaped
        # Control: the same scan does see raw HTML when it is there.
        assert "<" in re.sub(r"\\.", "", HOSTILE_TITLE)

    def test_markdown_table_cells_keep_their_column_count(self) -> None:
        leads = md_section(to_markdown(make()), "## Leads (not tested)")
        rows = [line for line in leads.split("\n") if line.startswith("|")]
        assert len(rows) == 2 + len(LEADS)
        assert {unescaped_pipes(row) for row in rows} == {8}
        assert md_inline("Open redirect | next=") in leads

    def test_md_inline_negative_control_plain_text_is_unchanged(self) -> None:
        assert md_inline("IDOR on orders") == "IDOR on orders"
        assert md_inline("a\n# b") == "a \\# b"
        assert md_inline("a | b") == "a \\| b"


class TestRedaction:
    TOKEN = "tok" + "-" + "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
    COOKIE = "sess" + "=" + "c0ffee00d00dfeedbeef1234"

    def captures(self) -> dict[str, Capture]:
        endpoint = f"{BASE}/api/me"
        authorization = "Bearer " + self.TOKEN
        echoed = f'{{"user":"alice","token":"{self.TOKEN}"}}'.encode()
        return {
            "cap-me": capture(
                "cap-me",
                endpoint,
                body=echoed,
                identity="alice",
                request_headers={"Authorization": authorization, "Accept": "application/json"},
                redact_headers=("authorization",),
            ),
            "rp-me": capture(
                "rp-me",
                endpoint,
                body=echoed,
                identity="alice",
                request_headers={"Authorization": authorization},
                response_headers={"Set-Cookie": self.COOKIE, "Content-Type": "application/json"},
                redact_headers=("authorization",),
            ),
        }

    def me(self) -> dict[str, Any]:
        return finding(
            "Token echoed",
            "info_exposure",
            "medium",
            f"{BASE}/api/me",
            "exploit_verified",
            assertions=[
                {"capture_id": "cap-me", "identity": "alice", "expect": expect(status=200)}
            ],
            replay_ids=["rp-me"],
        )

    def test_authorization_and_session_values_never_leak_in_any_format(self) -> None:
        records = self.captures()
        # Control: the fixture really holds the secrets the report must withhold.
        revealed = json.dumps(records["rp-me"].detail(reveal_credentials=True))
        assert self.TOKEN in revealed and self.COOKIE in revealed
        report = make([self.me()], captures=records.get)
        texts = render_all(report)
        for name, text in texts.items():
            assert self.TOKEN not in text, name
            assert self.COOKIE not in text, name
            assert "c0ffee00d00dfeedbeef1234" not in text, name
        item = report["findings"][0]
        assert "<AUTHORIZATION>" in item["reproduction"][0]["curl"]
        assert item["proof"][0]["response_headers"]["Set-Cookie"] == REDACTED
        assert REDACTED in item["proof"][0]["excerpt"]

    def test_a_dict_capture_has_its_credential_headers_masked_again(self) -> None:
        records = self.captures()
        # A careless caller hands over the unredacted operator view.
        raw = {key: value.detail(reveal_credentials=True) for key, value in records.items()}
        assert raw["rp-me"]["response_headers"]["Set-Cookie"] == self.COOKIE
        report = make([self.me()], captures=raw.get)
        item = report["findings"][0]
        assert item["proof"][0]["response_headers"]["Set-Cookie"] == REDACTED
        assert item["reproduction"][0]["curl"] == ""  # no curl without a Capture
        for name, text in render_all(report).items():
            assert self.COOKIE not in text, name


class TestEmptyAndStable:
    def test_empty_findings_say_nothing_was_verified_and_still_list_leads(self) -> None:
        report = make([LEADS[0], LEADS[1]], recon_summary=None, complete=False)
        assert report["findings"] == [] and report["unverified"] == []
        assert report["summary"]["verified"] == 0
        assert report["summary"]["verified_by_severity"] == dict.fromkeys(
            ("critical", "high", "medium", "low", "info"), 0
        )
        markdown = to_markdown(report)
        assert "Nothing was verified: no claim was re-proved by the verifier." in markdown
        assert "None. No vulnerability was exploit-verified." in markdown
        assert "is **not** recorded as complete" in markdown
        assert md_inline(LEADS[0]["id"]) in md_section(markdown, "## Leads (not tested)")
        document = to_html(report)
        assert "Nothing was verified" in document and LEADS[1]["id"] in document
        assert json.loads(to_json(report))["leads"][0]["id"] == LEADS[0]["id"]

    def test_nothing_at_all_is_still_a_valid_report(self) -> None:
        report = build(ENG, [], recon_summary=None, scope=[], captures=lookup, generated_at=0)
        assert report["generated_at"] == "1970-01-01T00:00:00+00:00"
        assert "No scope was given to this report." in to_markdown(report)
        assert parse_html(to_html(report)).tags <= ALLOWED_TAGS

    def test_json_round_trips_and_is_byte_stable(self) -> None:
        first = to_json(make())
        assert json.loads(first) == make()
        assert to_json(json.loads(first)) == first
        # The same findings in another order give the same bytes in every format.
        reordered = make(list(reversed(FIXTURE)))
        assert render_all(reordered) == render_all(make())
        assert first.endswith("\n") and first.isascii()

    def test_output_changes_when_the_input_does(self) -> None:
        # Control for the stability test: it is not stable because it ignores its input.
        changed = copy.deepcopy(FIXTURE)
        changed[3]["title"] = "IDOR on GET /api/orders/{id} (retitled)"
        assert to_json(make(changed)) != to_json(make())
        assert to_markdown(make(generated_at="2026-11-21T00:00:00+00:00")) != to_markdown(make())

    def test_generated_at_is_required(self) -> None:
        with pytest.raises(TypeError):
            build(ENG, [], recon_summary=None, scope=[], captures=lookup, generated_at=None)
