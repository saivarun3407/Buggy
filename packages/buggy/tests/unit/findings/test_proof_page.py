"""The proof page: a hostile recorded exchange is shown as text, never as markup.

The HTML is read back with the standard library's parser, so a target string
that broke out of its ``<pre>`` would show up as a tag or an attribute.
"""

from __future__ import annotations

import copy
import html
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urlsplit

from buggy.capture.store import Capture, sha256_hex
from buggy.findings.proof_page import RECORDED_NOTE, proof_html, proof_steps
from buggy.findings.report import build

ENG = "acme"
BASE = "https://app.acme.test"
GENERATED = "2026-11-22T10:00:00+00:00"
PAYLOAD = '"><img src=x onerror=alert(1)>'
URL = f"{BASE}/comments?text={quote(PAYLOAD)}"
STORED = "</pre><script>alert(document.cookie)</script>"
PROOF_TEXT = "onerror=alert(1)"
BODY = (
    "<html>" + "x" * 5000 + f"<p>{STORED}</p><div>{PAYLOAD}</div>" + "y" * 5000 + "</html>"
).encode()

ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "main", "section", "h1", "h2", "h3",
    "p", "dl", "dt", "dd", "pre", "mark", "span", "strong",
}  # fmt: skip
ALLOWED_ATTRIBUTES = {"lang", "charset", "http-equiv", "content", "class", "id"}


class _Parsed(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str, str]] = []
        self.text: list[str] = []
        self.marks: list[tuple[str, str]] = []
        self._mark: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend((tag, name, value or "") for name, value in attrs)
        if tag == "mark":
            self._mark = dict(attrs).get("class") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "mark":
            self._mark = None

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._mark is not None:
            self.marks.append((self._mark, data))


def parse(document: str) -> _Parsed:
    parsed = _Parsed()
    parsed.feed(document)
    parsed.close()
    return parsed


def _capture(capture_id: str, *, replay_of: str = "") -> Capture:
    return Capture(
        id=capture_id,
        engagement=ENG,
        created_at=1_700_000_000.0,
        method="GET",
        url=URL,
        host=urlsplit(URL).hostname or "",
        request_headers={"Cookie": "session=abcdefghijkl", "X-Trace": "<b>t</b>"},
        request_body=b"",
        request_sha256=sha256_hex(b""),
        status=200,
        response_headers={"Content-Type": "text/html"},
        response_body=BODY,
        response_sha256=sha256_hex(BODY),
        response_bytes=len(BODY),
        elapsed_ms=3.0,
        error="",
        note="stored comment",
        probe="",
        replay_of=replay_of,
        approval_id="",
        scope_digest="",
    )


CAPTURES = {"cap-xss": _capture("cap-xss"), "rp-xss": _capture("rp-xss", replay_of="cap-xss")}


def finding_entry() -> dict[str, Any]:
    raw = {
        "id": "F-0123456789ab",
        "engagement": ENG,
        "title": "Stored XSS <b>in</b> comments",
        "class": "xss",
        "cwe": "CWE-79",
        "severity": "high",
        "endpoint": f"{BASE}/comments",
        "method": "GET",
        "parameter": "text",
        "source": "agent:tester",
        "description": "",
        "remediation": "",
        "assertions": [
            {
                "capture_id": "cap-xss",
                "identity": "",
                "expect": {
                    "status": 200,
                    "body_contains": [PROOF_TEXT],
                    "body_not_contains": [],
                    "differs_from": "",
                    "same_as": "",
                },
            }
        ],
        "status": "exploit_verified",
        "verification": {"at": 1.0, "replay_capture_ids": ["rp-xss"], "reasons": []},
        "grade": None,
        "grade_reasons": [],
    }
    report = build(
        ENG, [raw], recon_summary=None, scope=[BASE], captures=CAPTURES.get, generated_at=GENERATED
    )
    return report["findings"][0]


def render(entry: dict[str, Any] | None = None) -> str:
    return proof_html(entry or finding_entry(), engagement=ENG, generated_at=GENERATED)


def test_title_card_states_that_nothing_is_sent_while_recording() -> None:
    parsed = parse(render())
    text = " ".join(parsed.text)
    assert RECORDED_NOTE in text
    assert "nothing is sent to the target while this is recorded" in RECORDED_NOTE
    for value in ("F-0123456789ab", "high", "xss", f"{BASE}/comments", "text"):
        assert value in text
    ids = [value for _tag, name, value in parsed.attributes if name == "id"]
    assert ids == ["title", "step-1"]


def test_hostile_target_strings_are_text_not_markup() -> None:
    document = render()
    parsed = parse(document)
    assert set(parsed.tags) <= ALLOWED_TAGS, set(parsed.tags) - ALLOWED_TAGS
    for tag, name, _value in parsed.attributes:
        assert name in ALLOWED_ATTRIBUTES, (tag, name)
        assert not name.startswith("on")
    assert "<script" not in document.lower() and "<img" not in document.lower()
    # The stored payload and the injected one are visible, as text.
    text = "".join(parsed.text)
    assert STORED in text and PAYLOAD in text
    assert html.escape(STORED) in document


def test_no_external_resource_and_a_locked_down_policy() -> None:
    document = render()
    parsed = parse(document)
    for _tag, name, value in parsed.attributes:
        assert name not in {"src", "href", "action", "srcset", "poster", "data"}
        assert not value.lower().startswith(("http:", "https:", "//"))
    assert "url(" not in document and "@import" not in document
    assert "default-src 'none'" in document


def test_payload_and_proving_text_are_highlighted() -> None:
    marks = parse(render()).marks
    assert ("payload", PAYLOAD) in marks  # the payload box
    assert ("payload", quote(PAYLOAD, safe="")) in marks or ("payload", quote(PAYLOAD)) in marks
    assert any(css == "match" and PROOF_TEXT in data for css, data in marks)


def test_a_long_body_is_cut_around_the_proving_text_with_a_marker() -> None:
    entry = finding_entry()
    response = entry["reproduction"][0]["response"]
    assert response["omitted_before"] > 0 and response["omitted_after"] > 0
    text = "".join(parse(render(entry)).text)
    assert f"[… {response['omitted_before']} bytes not shown …]" in text
    assert f"[… {response['omitted_after']} bytes not shown …]" in text
    assert "x" * 5000 not in text


def test_the_page_cuts_an_oversized_body_itself() -> None:
    entry = copy.deepcopy(finding_entry())
    response = entry["reproduction"][0]["response"]
    response.update(body="z" * 50_000 + "PROVEN" + "z" * 50_000, omitted_before=0, omitted_after=0)
    entry["reproduction"][0]["highlight"] = ["PROVEN"]
    text = "".join(parse(render(entry)).text)
    assert "bytes not shown" in text and "PROVEN" in text and len(text) < 20_000


def test_capture_ids_and_hashes_are_shown() -> None:
    text = "".join(parse(render()).text)
    assert "cap-xss" in text and "rp-xss" in text and sha256_hex(BODY) in text


def test_credentials_stay_redacted() -> None:
    assert "abcdefghijkl" not in render()


def test_output_is_deterministic_and_changes_with_input() -> None:
    assert render() == render()
    other = copy.deepcopy(finding_entry())
    other["title"] = "Another"
    assert render(other) != render()


def test_steps_are_numbered_and_fallback_to_replay_entries() -> None:
    entry = copy.deepcopy(finding_entry())
    many = [dict(entry["reproduction"][0], number=n) for n in range(1, 11)]
    entry["reproduction"] = many
    ids = [v for _t, n, v in parse(render(entry)).attributes if n == "id"]
    assert ids == ["title"] + [f"step-{n}" for n in range(1, 11)]
    entry["reproduction"] = []
    assert len(proof_steps(entry)) == len(entry["proof"]) == 1
    assert "step-1" in render(entry)


def test_an_empty_finding_still_renders() -> None:
    document = proof_html({}, engagement=ENG, generated_at=GENERATED)
    assert "No proof step is recorded" in document and RECORDED_NOTE in html.unescape(document)
