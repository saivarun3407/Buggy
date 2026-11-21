"""The ``xss_reflected`` probe against a fake origin that renders real pages.

Each fake endpoint writes the request value into a page through an encoder a
real application might use (none, ``html.escape``, a JSON string encoder, a
URL encoder, ...). No handler looks at the probe's strings: whether a context
is found vulnerable depends only on what the encoder does to the characters
and on how the response tokenizes. Every context has a vulnerable endpoint
and a safe one, so a probe that flagged any reflection would fail here.
"""

from __future__ import annotations

import html
import io
import json
import re
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, unquote, urlsplit

import pytest

from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.mcp_server import CaptureTools
from buggy.capture.probes import REGISTRY, describe, run_probe, xss
from buggy.capture.probes.xss import (
    MAX_REQUESTS,
    PAYLOADS,
    find_proof,
    find_reflections,
    payload_for,
    tokenize,
)

BASE = "https://app.acme.test"
HTML = "text/html; charset=utf-8"
MARKER = re.compile(r"bg[0-9a-f]{12}")
SHELL = (
    "<!doctype html><html><head><meta charset='utf-8'><link rel=stylesheet href=/site.css>"
    "</head><body><h1>Acme shop</h1>{{page}}<footer>&copy; Acme</footer></body></html>"
)


@dataclass
class Call:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes

    def form(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(self.body.decode(), keep_blank_values=True).items()}


@dataclass
class Reply:
    body: str
    status: int = 200
    content_type: str = HTML
    headers: dict[str, str] = field(default_factory=dict)


Handler = Callable[[Call], Reply]
Encoder = Callable[[str], str]


class Origin:
    """A fake origin: one handler per path, which chooses status, type and headers."""

    def __init__(self) -> None:
        self.pages: dict[str, Handler] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data or b""
        self.seen.append((method, url, headers, body))
        parts = urlsplit(url)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        handler = self.pages.get(parts.path) or self.pages.get("*")
        if handler is None:
            reply = Reply("not found", 404, "text/plain")
        else:
            reply = handler(Call(method, parts.path, query, headers, body))
        response_headers = dict(reply.headers)
        if reply.content_type:
            response_headers["Content-Type"] = reply.content_type
        payload = reply.body.encode()
        if reply.status >= 300:
            raise urllib.error.HTTPError(
                url, reply.status, "x", response_headers, io.BytesIO(payload)
            )
        response = io.BytesIO(payload)
        response.status, response.headers = reply.status, response_headers
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


@pytest.fixture
def env(tmp_path: Path):
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        json.dumps(
            {
                "machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]},
                "approvals": {"state_changing": "not_required"},
            }
        )
    )
    origin = Origin()
    gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
    yield SimpleNamespace(gateway=gateway, origin=origin, roots=roots)
    gateway.store.close()


def probe(env, params: dict) -> dict:
    return run_probe(env.gateway, "acme", "xss_reflected", params)


def sent(env, name: str = "q") -> list[str]:
    """The value of one query parameter in every request the origin received."""
    return [parse_qs(urlsplit(url).query)[name][0] for _m, url, _h, _b in env.origin.seen]


def check_evidence(env, result: dict) -> None:
    """Every request is evidence with a named role, and the bound holds."""
    ids = result["evidence_capture_ids"]
    details = result["details"]
    assert len(ids) == len(env.origin.seen) == details["requests_sent"] <= MAX_REQUESTS == 6
    assert details["max_requests"] == 6
    assert len(set(ids)) == len(ids)
    assert list(details["captures"].values()) == ids
    assert set(details["payloads"]) == set(details["captures"])
    for capture_id in ids:
        stored = env.gateway.store.get("acme", capture_id)
        assert stored is not None and stored.probe == "xss_reflected"
    if ids:
        assert list(details["captures"])[0] == "baseline"
    assert details["browser_confirmation"] == "not_run"
    assert "baseline" in details["control"]
    tested = [c for c in details["contexts"] if c["probe"]]
    assert [c["capture"] for c in tested] == ids[1:]
    for context in tested:
        assert details["captures"][context["probe"]] == context["capture"]
        assert details["payloads"][context["probe"]].endswith(context["payload"])


# ── encoders an application might apply ──────────────────────────────


def raw(value: str) -> str:
    return value


def text_only(value: str) -> str:
    """Encodes & < > but leaves quotes: right for element content only."""
    return html.escape(value, quote=False)


def double_quote_only(value: str) -> str:
    """Encodes & < > and the double quote, forgetting the single quote."""
    return html.escape(value, quote=False).replace('"', "&quot;")


def every_entity(value: str) -> str:
    """Encodes every non-alphanumeric character as a numeric entity."""
    return "".join(c if c.isalnum() else f"&#x{ord(c):x};" for c in value)


def json_string(value: str) -> str:
    """The inside of a JSON string: escapes the double quote and backslash, not < or '."""
    return json.dumps(value)[1:-1]


def script_safe_string(value: str) -> str:
    """A JSON string with the characters that matter inside a script block escaped too."""
    out = json.dumps(value)[1:-1]
    for char in "<>&'":
        out = out.replace(char, f"\\u{ord(char):04x}")
    return out


def identifier_only(value: str) -> str:
    return re.sub(r"\W", "", value)


def url_path(value: str) -> str:
    return quote(value, safe="/")


def strip_tags(value: str) -> str:
    return re.sub(r"<[^>]*>", "", value)


def page(template: str, encode: Encoder, **reply) -> Handler:
    """A page that writes the ``q`` parameter into ``template`` at ``{{v}}``."""

    def handler(call: Call) -> Reply:
        written = template.replace("{{v}}", encode(call.query.get("q", "")))
        return Reply(SHELL.replace("{{page}}", written), **reply)

    return handler


# ── one endpoint per context, vulnerable and safe ────────────────────


@dataclass(frozen=True)
class Case:
    name: str
    template: str
    encode: Encoder
    # (context, quote or element, verdict) of every context, in the order they are reported
    contexts: tuple[tuple[str, str, bool], ...]
    proof: str = ""  # a fragment of the reason of the vulnerable context


P = "<p>Results for {{v}}</p>"
DQ = '<form><input type="text" name="q" value="{{v}}"><button>Go</button></form>'
SQ = "<form><input type='text' name='q' value='{{v}}'></form>"
UQ = "<form><input type=text name=q value={{v}}></form>"
JS_SQ = "<script>var term = '{{v}}'; search(term);</script>"
JS_DQ = '<script>var config = {"term": "{{v}}", "page": 1};</script>'
JS_CODE = "<script>var page = {{v}}; load(page);</script>"
LINK = '<p>Signed out. <a href="{{v}}">Continue</a></p>'
COMMENT = "<p>No results.</p><!-- debug: q={{v}} -->"
TEXTAREA = '<textarea name="note" rows="3">{{v}}</textarea>'
TITLE = "<title>Search: {{v}}</title><p>Nothing found.</p>"

CASES = [
    Case("html_text/raw", P, raw, (("html_text", "", True),), "a new <"),
    Case("html_text/entity-encoded", P, html.escape, (("html_text", "", False),)),
    Case(
        "attr-double/quotes-left",
        DQ,
        text_only,
        (("attribute_quoted", '"', True),),
        "new attribute",
    ),  # fmt: skip
    Case("attr-double/attribute-encoded", DQ, html.escape, (("attribute_quoted", '"', False),)),
    Case(
        "attr-single/single-quote-left",
        SQ,
        double_quote_only,
        (("attribute_quoted", "'", True),),
        "new attribute",
    ),  # fmt: skip
    Case("attr-single/attribute-encoded", SQ, html.escape, (("attribute_quoted", "'", False),)),
    # html.escape is the wrong encoder for an unquoted attribute: a space ends the value.
    Case(
        "attr-unquoted/html-escape",
        UQ,
        html.escape,
        (("attribute_unquoted", "", True),),
        "new attribute",
    ),  # fmt: skip
    Case("attr-unquoted/every-entity", UQ, every_entity, (("attribute_unquoted", "", False),)),
    # HTML-encoding inside a script block does not stop a single quote.
    Case(
        "script-single/html-encoded",
        JS_SQ,
        text_only,
        (("script_string", "'", True),),
        "string literal was terminated",
    ),  # fmt: skip
    Case("script-single/script-safe", JS_SQ, script_safe_string, (("script_string", "'", False),)),
    # A JSON string keeps the quote in, but "</script>" still ends the block.
    Case(
        "script-double/json-string",
        JS_DQ,
        json_string,
        (("script_string", '"', True),),
        "<script> was closed",
    ),  # fmt: skip
    Case("script-double/script-safe", JS_DQ, script_safe_string, (("script_string", '"', False),)),
    Case("script-code/raw", JS_CODE, raw, (("script_code", "", True),), "statement syntax"),
    Case("script-code/identifier-only", JS_CODE, identifier_only, (("script_code", "", False),)),
    # Attribute-encoding a link target does nothing about its scheme.
    Case(
        "url/attribute-encoded-only",
        LINK,
        html.escape,
        (("attribute_quoted", '"', False), ("url_attribute", "", True)),
        "javascript: scheme",
    ),  # fmt: skip
    Case(
        "url/path-encoded",
        LINK,
        url_path,
        (("attribute_quoted", '"', False), ("url_attribute", "", False)),
    ),  # fmt: skip
    Case("comment/raw", COMMENT, raw, (("comment", "", True),), "comment was closed"),
    Case("comment/entity-encoded", COMMENT, html.escape, (("comment", "", False),)),
    Case(
        "textarea/raw", TEXTAREA, raw, (("html_text", "textarea", True),), "<textarea> was closed"
    ),  # fmt: skip
    Case("textarea/entity-encoded", TEXTAREA, html.escape, (("html_text", "textarea", False),)),
    Case("title/raw", TITLE, raw, (("html_text", "title", True),), "<title> was closed"),
    Case("title/entity-encoded", TITLE, html.escape, (("html_text", "title", False),)),
]


def _variant(context: dict) -> str:
    return context.get("quote") or context.get("element") or ""


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_each_context_vulnerable_and_safe(env, case: Case) -> None:
    env.origin.pages["/search"] = page(case.template, case.encode)
    result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
    expected = any(verdict for _c, _v, verdict in case.contexts)
    assert result["status"] == "completed" and result["vulnerable"] is expected, result
    assert result["class"] == "xss" and result["cwe"] == "CWE-79"
    details = result["details"]
    reported = [(c["context"], _variant(c), c["vulnerable"]) for c in details["contexts"]]
    assert reported == list(case.contexts)
    # The harmless marker first, then exactly one probe string per context.
    assert details["requests_sent"] == 1 + len(case.contexts)
    values = sent(env)
    assert MARKER.fullmatch(values[0]) and values[0] == details["marker"]
    for context, value in zip(details["contexts"], values[1:], strict=True):
        assert value == payload_for(context["context"], _variant(context), context["marker"])
        assert value == context["payload"] and context["marker"] != details["marker"]
    for context in details["contexts"]:
        if context["vulnerable"]:
            assert case.proof in context["reason"], context
            assert context["context"] in result["summary"]
            # The fix names the context that needs it.
            assert f"{context['context']}:" in result["remediation"]
        else:
            assert "neutralised" in context["reason"], context
    assert "contextual output encoding" in result["remediation"]
    check_evidence(env, result)


def test_the_case_table_covers_every_html_context_both_ways() -> None:
    assert len(CASES) >= 12
    seen = {(context, verdict) for case in CASES for context, _v, verdict in case.contexts}
    html_contexts = set(xss.CONTEXTS) - {"json_body"}
    assert seen == {(context, verdict) for context in html_contexts for verdict in (True, False)}


# ── reflections that are not exploitable ─────────────────────────────


class TestNotVulnerable:
    def test_json_reflection_is_not_exploitable(self, env) -> None:
        # The value comes back with its markup intact, but as JSON.
        def handler(call: Call) -> Reply:
            order = {"status": "success", "data": [{"orderId": call.query.get("q", "")}]}
            return Reply(json.dumps(order), content_type="application/json; charset=utf-8")

        env.origin.pages["/track"] = handler
        result = probe(env, {"url": f"{BASE}/track?q=5267", "parameter": "q"})
        assert result["status"] == "completed" and result["vulnerable"] is False, result
        (context,) = result["details"]["contexts"]
        assert context["context"] == "json_body" and context["vulnerable"] is False
        assert "does not render JSON as HTML" in context["reason"]
        assert "JSON" in result["summary"] and "application/json" in result["summary"]
        # Decided from the baseline alone: no markup is ever sent.
        assert len(env.origin.seen) == 1 and MARKER.fullmatch(sent(env)[0])
        check_evidence(env, result)

    def test_the_same_json_served_as_html_is_exploitable(self, env) -> None:
        # The control for the JSON rule: only the Content-Type differs.
        def handler(call: Call) -> Reply:
            return Reply(json.dumps({"orderId": call.query.get("q", "")}))

        env.origin.pages["/track"] = handler
        result = probe(env, {"url": f"{BASE}/track?q=5267", "parameter": "q"})
        assert result["vulnerable"] is True, result
        assert [c["context"] for c in result["details"]["contexts"]] == ["html_text"]

    @pytest.mark.parametrize("media_type", ["application/problem+json", "text/json"])
    def test_other_json_media_types_count_as_json(self, env, media_type: str) -> None:
        env.origin.pages["/track"] = lambda call: Reply(
            json.dumps({"detail": call.query.get("q", "")}), content_type=media_type
        )
        result = probe(env, {"url": f"{BASE}/track?q=5267", "parameter": "q"})
        assert result["vulnerable"] is False
        assert result["details"]["contexts"][0]["context"] == "json_body"

    def test_no_reflection(self, env) -> None:
        env.origin.pages["/search"] = lambda _call: Reply(
            SHELL.replace("{{page}}", "<p>12 products</p>")
        )
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["status"] == "completed" and result["vulnerable"] is False, result
        assert result["summary"].startswith("not reflected")
        assert result["details"]["contexts"] == []
        assert result["details"]["baseline"] == {"status": 200, "reflected": False}
        assert len(env.origin.seen) == 1
        check_evidence(env, result)

    def test_reflection_only_inside_an_html_comment(self, env) -> None:
        # The value is echoed nowhere but a comment, and "<" / ">" are removed
        # on the way, so the comment cannot be closed from inside.
        env.origin.pages["/search"] = page(COMMENT, lambda value: re.sub(r"[<>]", "", value))
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["status"] == "completed" and result["vulnerable"] is False, result
        (context,) = result["details"]["contexts"]
        assert context["context"] == "comment" and context["vulnerable"] is False
        assert context["where"] == ["HTML comment or declaration"]
        assert "comment" in result["summary"]
        # The marker really was in a comment both times, and no element was created.
        for capture_id in result["evidence_capture_ids"]:
            body = env.gateway.store.get("acme", capture_id).response_body.decode()
            assert re.search(r"<!-- debug: q=[^>]*bg[0-9a-f]{12}[^>]* -->", body), body
        check_evidence(env, result)

    def test_encoded_everywhere_on_a_page_with_several_reflections(self, env) -> None:
        env.origin.pages["/search"] = page(TITLE + P + DQ, html.escape)
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is False, result
        contexts = result["details"]["contexts"]
        assert [(c["context"], _variant(c)) for c in contexts] == [
            ("html_text", ""),
            ("html_text", "title"),
            ("attribute_quoted", '"'),
        ]
        assert all(c["vulnerable"] is False for c in contexts)
        assert result["details"]["baseline"]["reflections"] == 3
        check_evidence(env, result)


# ── several contexts on one page ─────────────────────────────────────


class TestSeveralContexts:
    def test_one_unencoded_context_among_encoded_ones_is_named(self, env) -> None:
        # Encoded for element content everywhere, which is not enough in the attribute.
        env.origin.pages["/search"] = page(P + DQ, text_only)
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is True, result
        verdicts = {c["context"]: c["vulnerable"] for c in result["details"]["contexts"]}
        assert verdicts == {"html_text": False, "attribute_quoted": True}
        assert "attribute_quoted:" in result["remediation"]
        assert "html_text:" not in result["remediation"]
        check_evidence(env, result)

    def test_a_breakout_elsewhere_is_not_credited_to_an_encoded_title(self, env) -> None:
        # <title> encodes, <p> does not. The title's probe string, written raw
        # into the paragraph, creates the marker element there, not after </title>.
        def handler(call: Call) -> Reply:
            value = call.query.get("q", "")
            body = f"<title>Search: {html.escape(value)}</title><p>Results for {value}</p>"
            return Reply(SHELL.replace("{{page}}", body))

        env.origin.pages["/search"] = handler
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is True, result
        verdicts = {(c["context"], _variant(c)): c["vulnerable"] for c in result["details"]["contexts"]}  # fmt: skip
        assert verdicts == {("html_text", ""): True, ("html_text", "title"): False}
        check_evidence(env, result)

    def test_a_breakout_elsewhere_is_not_credited_to_an_encoded_comment(self, env) -> None:
        def handler(call: Call) -> Reply:
            value = call.query.get("q", "")
            body = f"<p>Results for {value}</p><!-- q={html.escape(value)} -->"
            return Reply(SHELL.replace("{{page}}", body))

        env.origin.pages["/search"] = handler
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        verdicts = {c["context"]: c["vulnerable"] for c in result["details"]["contexts"]}
        assert verdicts == {"html_text": True, "comment": False}

    def test_a_filtered_code_reflection_does_not_prove_a_string_breakout(self, env) -> None:
        # The same script holds the value in a properly escaped string and as a
        # filtered identifier in code. Neither can be broken out of.
        def handler(call: Call) -> Reply:
            value = call.query.get("q", "")
            script = (
                f"<script>var term = '{script_safe_string(value)}'; "
                f"track({identifier_only(value)});</script>"
            )
            return Reply(SHELL.replace("{{page}}", script))

        env.origin.pages["/search"] = handler
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is False, result
        verdicts = {c["context"]: c["vulnerable"] for c in result["details"]["contexts"]}
        assert verdicts == {"script_string": False, "script_code": False}

    SLOTS = (
        ("html_text", P),
        ("textarea", TEXTAREA),
        ("attr_double", DQ),
        ("attr_single", SQ),
        ("attr_unquoted", UQ),
        ("script_single", JS_SQ),
        ("script_double", JS_DQ),
        ("script_code", JS_CODE),
        ("comment", COMMENT),
    )
    SAFE = {
        "html_text": html.escape,
        "textarea": html.escape,
        "attr_double": html.escape,
        "attr_single": html.escape,
        "attr_unquoted": every_entity,
        "script_single": script_safe_string,
        "script_double": script_safe_string,
        "script_code": identifier_only,
        "comment": html.escape,
    }

    def _busy_page(self, **unsafe: Encoder) -> Handler:
        """Nine distinct reflection contexts, each with its own encoder."""
        encoders = {**self.SAFE, **unsafe}

        def handler(call: Call) -> Reply:
            value = call.query.get("q", "")
            body = "".join(
                template.replace("{{v}}", encoders[slot](value)) for slot, template in self.SLOTS
            )
            return Reply(SHELL.replace("{{page}}", body))

        return handler

    def test_probes_are_capped_at_six_requests(self, env) -> None:
        env.origin.pages["/search"] = self._busy_page()
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        contexts = result["details"]["contexts"]
        assert len(contexts) == 9
        assert len(env.origin.seen) == result["details"]["requests_sent"] == 6
        assert [c["probe"] is not None for c in contexts] == [True] * 5 + [False] * 4
        assert [c["vulnerable"] for c in contexts] == [False] * 5 + [None] * 4
        assert all("request bound (6)" in c["reason"] for c in contexts[5:])
        # Four contexts were never tested, so the answer is not "safe".
        assert result["vulnerable"] is None and "cannot tell" in result["summary"]
        check_evidence(env, result)

    def test_an_untested_context_is_never_reported_as_a_finding(self, env) -> None:
        # The comment is unencoded, but it is the ninth context: out of reach of the bound.
        env.origin.pages["/search"] = self._busy_page(comment=raw)
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is None, result
        assert result["details"]["contexts"][-1]["context"] == "comment"
        assert result["details"]["contexts"][-1]["probe"] is None
        assert len(env.origin.seen) == 6

    def test_a_finding_within_the_bound_stands_whatever_was_left_untested(self, env) -> None:
        env.origin.pages["/search"] = self._busy_page(attr_double=text_only)
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is True, result
        proven = [c for c in result["details"]["contexts"] if c["vulnerable"]]
        assert [(c["context"], c["quote"]) for c in proven] == [("attribute_quoted", '"')]
        assert len(env.origin.seen) == 6
        check_evidence(env, result)

    def test_request_bound_is_enforced_by_the_sender(self, env, monkeypatch) -> None:
        env.origin.pages["/search"] = self._busy_page()
        monkeypatch.setattr(xss, "MAX_REQUESTS", 3)
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is None and len(env.origin.seen) == 3


# ── could not tell ───────────────────────────────────────────────────


class TestCannotTell:
    def test_unstable_page_that_stops_reflecting(self, env) -> None:
        # The first answer echoes the value; later answers are a different page.
        def handler(call: Call) -> Reply:
            if len(env.origin.seen) == 1:
                return Reply(SHELL.replace("{{page}}", f"<p>Results for {call.query['q']}</p>"))
            return Reply(SHELL.replace("{{page}}", "<p>Popular today: boots, sandals</p>"))

        env.origin.pages["/search"] = handler
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        (context,) = result["details"]["contexts"]
        assert context["context"] == "html_text" and context["vulnerable"] is None
        assert "not reflected in this context" in context["reason"]
        assert "unstable" in result["summary"] and result["summary"].startswith("cannot tell")
        check_evidence(env, result)

    def test_unstable_page_whose_reflection_moves_between_contexts(self, env) -> None:
        # Odd answers echo into element content, even answers into an attribute.
        def handler(call: Call) -> Reply:
            value = html.escape(call.query.get("q", ""))
            template = P if len(env.origin.seen) % 2 else DQ
            return Reply(SHELL.replace("{{page}}", template.replace("{{v}}", value)))

        env.origin.pages["/search"] = handler
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is None, result
        (context,) = result["details"]["contexts"]
        assert context["context"] == "html_text" and context["vulnerable"] is None
        check_evidence(env, result)

    def test_blocked_probe_string_is_not_a_pass(self, env) -> None:
        # A filter in front of a vulnerable page: blocking one string fixes nothing.
        vulnerable = page(P, raw)

        def handler(call: Call) -> Reply:
            if re.search(r"[<>]", call.query.get("q", "")):
                return Reply("<h1>Request blocked</h1>", 403)
            return vulnerable(call)

        env.origin.pages["/search"] = handler
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is None, result
        (context,) = result["details"]["contexts"]
        assert context["status"] == 403 and "HTTP 403" in context["reason"]
        check_evidence(env, result)

    def test_value_removed_together_with_its_tag_is_not_observed(self, env) -> None:
        # Tag stripping removes the marker along with the tag: nothing comes back to judge.
        env.origin.pages["/search"] = page(P, strip_tags)
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is None, result
        assert "drops or blocks the value" in result["summary"]

    @pytest.mark.parametrize("media_type", ["text/plain; charset=utf-8", "text/javascript"])
    def test_reflection_in_a_response_that_is_neither_html_nor_json(
        self, env, media_type: str
    ) -> None:
        env.origin.pages["/echo"] = lambda call: Reply(
            f"callback({call.query.get('q', '')})", content_type=media_type
        )
        result = probe(env, {"url": f"{BASE}/echo?q=shoes", "parameter": "q"})
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert "HTML responses only" in result["summary"]
        assert len(env.origin.seen) == 1

    def test_reflection_inside_a_script_comment_is_not_tested(self, env) -> None:
        env.origin.pages["/search"] = page("<script>// last search: {{v}}\ninit();</script>", raw)
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is None, result
        (context,) = result["details"]["contexts"]
        assert context["context"] == "script_code" and context["probe"] is None
        assert "JavaScript comment" in context["reason"] and len(env.origin.seen) == 1

    def test_failed_baseline(self, env) -> None:
        def handler(_call: Call) -> Reply:
            raise ConnectionResetError("connection reset by peer")

        env.origin.pages["/search"] = handler
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert "baseline request failed" in result["summary"]
        assert len(env.origin.seen) == 1 and result["details"]["contexts"] == []
        check_evidence(env, result)

    def test_probe_request_without_an_answer(self, env) -> None:
        vulnerable = page(P, raw)

        def handler(call: Call) -> Reply:
            if "<" in call.query.get("q", ""):
                raise TimeoutError("timed out")
            return vulnerable(call)

        env.origin.pages["/search"] = handler
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is None, result
        assert "got no answer" in result["summary"]
        check_evidence(env, result)

    def test_out_of_scope_target_is_refused_and_nothing_is_sent(self, env) -> None:
        result = probe(env, {"url": "https://other.test/search?q=shoes", "parameter": "q"})
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert result["details"]["refusal"]["code"] == "OUT_OF_SCOPE"
        assert result["evidence_capture_ids"] == [] and env.origin.seen == []

    def test_state_changing_method_waits_for_approval(self, env) -> None:
        (env.roots.control / "acme" / "roe.json").write_text(
            json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}})
        )
        result = probe(
            env,
            {
                "url": f"{BASE}/comment",
                "method": "POST",
                "location": "form",
                "parameter": "text",
                "body": "text=hello&post=7",
            },
        )
        # The run is held as a whole: one approval request, and no request sent.
        assert result["status"] == "refused" and "vulnerable" not in result, result
        assert result["code"] == "APPROVAL_REQUIRED" and result["request_id"].startswith("apr-")
        assert env.origin.seen == []


# ── where the parameter lives ────────────────────────────────────────


class TestLocations:
    def test_error_page_reflection_counts(self, env) -> None:
        # A 500 page that echoes the value is a reflection like any other.
        env.origin.pages["/item"] = page("<h2>No such item: {{v}}</h2>", raw, status=500)
        result = probe(env, {"url": f"{BASE}/item?q=17", "parameter": "q"})
        assert result["vulnerable"] is True, result
        assert result["details"]["baseline"]["status"] == 500
        check_evidence(env, result)

    @pytest.mark.parametrize("encode", [raw, html.escape], ids=["raw", "encoded"])
    def test_form_body_parameter(self, env, encode: Encoder) -> None:
        def handler(call: Call) -> Reply:
            assert call.method == "POST"
            assert call.headers["content-type"] == "application/x-www-form-urlencoded"
            fields = call.form()
            assert fields["post"] == "7"  # the other field is sent unchanged
            preview = f"<blockquote>{encode(fields.get('text', ''))}</blockquote>"
            return Reply(SHELL.replace("{{page}}", preview))

        env.origin.pages["/comment/preview"] = handler
        result = probe(
            env,
            {
                "url": f"{BASE}/comment/preview",
                "method": "POST",
                "location": "form",
                "parameter": "text",
                "body": "text=hello&post=7",
            },
        )
        assert result["vulnerable"] is (encode is raw), result
        assert result["details"]["location"] == "form" and len(env.origin.seen) == 2
        check_evidence(env, result)

    @pytest.mark.parametrize("encode", [raw, html.escape], ids=["raw", "encoded"])
    def test_json_body_parameter(self, env, encode: Encoder) -> None:
        def handler(call: Call) -> Reply:
            assert call.headers["content-type"] == "application/json"
            document = json.loads(call.body)
            assert document["page"] == 2
            name = encode(document["filter"]["name"])
            return Reply(SHELL.replace("{{page}}", f'<input name="name" value="{name}">'))

        env.origin.pages["/report"] = handler
        result = probe(
            env,
            {
                "url": f"{BASE}/report",
                "method": "POST",
                "location": "json",
                "parameter": "filter.name",
                "body": {"filter": {"name": "north"}, "page": 2},
            },
        )
        assert result["vulnerable"] is (encode is raw), result
        assert [c["context"] for c in result["details"]["contexts"]] == ["attribute_quoted"]
        check_evidence(env, result)

    @pytest.mark.parametrize("encode", [raw, html.escape], ids=["raw", "encoded"])
    def test_path_segment_parameter(self, env, encode: Encoder) -> None:
        def handler(call: Call) -> Reply:
            segment = unquote(call.path.removeprefix("/orders/").removesuffix("/status"))
            assert "/" not in call.path.removeprefix("/orders/").removesuffix("/status")
            assert call.query == {"lang": "en"}
            return Reply(SHELL.replace("{{page}}", f"<p>Order {encode(segment)} not found</p>"))

        env.origin.pages["*"] = handler
        result = probe(
            env,
            {
                "url": f"{BASE}/orders/{{id}}/status?lang=en",
                "parameter": "id",
                "location": "path",
            },
        )
        assert result["vulnerable"] is (encode is raw), result
        assert result["details"]["location"] == "path"
        # The value travels percent-encoded as one segment: it cannot change the route.
        _method, url, _headers, _body = env.origin.seen[1]
        assert urlsplit(url).path.startswith("/orders/%3Cbg") and url.endswith("/status?lang=en")
        check_evidence(env, result)

    def test_value_is_kept_in_front_of_the_marker(self, env) -> None:
        # An endpoint that only echoes well-formed order numbers.
        def handler(call: Call) -> Reply:
            value = call.query.get("q", "")
            shown = value if value.startswith("ORD-") else "invalid"
            return Reply(SHELL.replace("{{page}}", f"<p>Order {shown}</p>"))

        env.origin.pages["/order"] = handler
        without = probe(env, {"url": f"{BASE}/order?q=ORD-1", "parameter": "q"})
        assert without["vulnerable"] is False and without["summary"].startswith("not reflected")
        result = probe(env, {"url": f"{BASE}/order?q=ORD-1", "parameter": "q", "value": "ORD-"})
        assert result["vulnerable"] is True, result
        assert all(value.startswith("ORD-") for value in sent(env)[1:])

    def test_a_prefixed_link_target_is_not_a_url_context(self, env) -> None:
        # With something in front of it the value no longer chooses the scheme.
        env.origin.pages["/out"] = page('<a href="/go/{{v}}">Continue</a>', html.escape)
        result = probe(env, {"url": f"{BASE}/out?q=home", "parameter": "q"})
        assert result["vulnerable"] is False, result
        assert [c["context"] for c in result["details"]["contexts"]] == ["attribute_quoted"]

    def test_other_query_parameters_and_headers_are_preserved(self, env) -> None:
        env.origin.pages["/search"] = page(P, html.escape)
        probe(
            env,
            {
                "url": f"{BASE}/search?page=2&q=shoes&sort=price",
                "parameter": "q",
                "headers": {"Authorization": "Bearer t0ken", "Accept": "text/html"},
            },
        )
        assert len(env.origin.seen) == 2
        for _method, url, headers, _body in env.origin.seen:
            query = parse_qs(urlsplit(url).query)
            assert query["page"] == ["2"] and query["sort"] == ["price"]
            assert headers["authorization"] == "Bearer t0ken" and headers["accept"] == "text/html"


# ── response headers ─────────────────────────────────────────────────


class TestHeaders:
    def test_headers_are_reported_and_a_csp_does_not_change_the_verdict(self, env) -> None:
        policy = "default-src 'self'; script-src 'self'"
        env.origin.pages["/search"] = page(
            P,
            raw,
            headers={"Content-Security-Policy": policy, "X-Content-Type-Options": "nosniff"},
        )
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        assert result["vulnerable"] is True, result
        headers = result["details"]["response_headers"]
        assert headers["content_type"] == HTML
        assert headers["x_content_type_options"] == "nosniff"
        assert headers["csp_present"] is True and headers["content_security_policy"] == policy
        assert "does not change the verdict" in headers["note"]
        assert "Content-Security-Policy" in result["remediation"]

    def test_absent_headers_are_reported_as_absent(self, env) -> None:
        env.origin.pages["/search"] = page(P, raw, content_type="")
        result = probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        # No declared type: a browser may sniff it as HTML, so it is analysed as HTML.
        assert result["vulnerable"] is True, result
        headers = result["details"]["response_headers"]
        assert headers["content_type"] == "" and headers["x_content_type_options"] == ""
        assert headers["csp_present"] is False and headers["csp_report_only_present"] is False


# ── the tokenizer and the classifier, directly ───────────────────────

M = "bg0123456789ab"


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (f"<p>{M}</p>", [("html_text", "")]),
        (f"<p>{M.upper()}</p>", [("html_text", "")]),
        (f'<input value="{M}">', [("attribute_quoted", '"')]),
        (f"<input value='{M}'>", [("attribute_quoted", "'")]),
        (f"<input value={M}>", [("attribute_unquoted", "")]),
        (f"<input value = \"a\" title='x{M}'>", [("attribute_quoted", "'")]),
        (f"<input {M}>", [("attribute_unquoted", "")]),
        (f"<button onclick=\"go('{M}')\">", [("attribute_quoted", '"')]),
        (f"<script>var a = '{M}';</script>", [("script_string", "'")]),
        (f'<script>var a = "{M}";</script>', [("script_string", '"')]),
        (f"<script>var a = `{M}`;</script>", [("script_string", "`")]),
        (f"<script>var a = {M};</script>", [("script_code", "")]),
        (f"<script>var a = 'it\\'s'; var b = {M};</script>", [("script_code", "")]),
        (f"<script>var a = \"x\\\\\"; var b = '{M}';</script>", [("script_string", "'")]),
        (f'<script>var quote = /\'/; var b = "{M}";</script>', [("script_string", '"')]),
        (f"<script>var half = total / 2; var b = '{M}';</script>", [("script_string", "'")]),
        (f"<script>/* '{M} */ var a = 1;</script>", [("script_code", "")]),
        (f"<script type=module>var a = '{M}';</script>", [("script_string", "'")]),
        (f'<script type="application/json">{{"a": "{M}"}}</script>', [("html_text", "script")]),
        (f'<script type="text/template"><b>{M}</b></script>', [("html_text", "script")]),
        (f"<style>a::after {{ content: '{M}' }}</style>", [("html_text", "style")]),
        (f"<textarea>{M}</textarea>", [("html_text", "textarea")]),
        (f"<title>{M}</title>", [("html_text", "title")]),
        (f"<noscript><p>{M}</p></noscript>", [("html_text", "noscript")]),
        (f"<!-- {M} -->", [("comment", "")]),
        (f"<!DOCTYPE html {M}>", [("comment", "")]),
        (f'<a href="{M}">x</a>', [("url_attribute", ""), ("attribute_quoted", '"')]),
        (f'<a href="  {M}">x</a>', [("url_attribute", ""), ("attribute_quoted", '"')]),
        (f"<iframe src={M}></iframe>", [("url_attribute", ""), ("attribute_unquoted", "")]),
        (f'<form action="{M}">', [("url_attribute", ""), ("attribute_quoted", '"')]),
        (f'<a href="/search?q={M}">x</a>', [("attribute_quoted", '"')]),
        (f'<img src="{M}">', [("attribute_quoted", '"')]),  # not a script-capable URL
        (
            f'<a title="{M}">{M}</a><!-- {M} -->',
            [("attribute_quoted", '"'), ("html_text", ""), ("comment", "")],
        ),  # fmt: skip
        ("<p>nothing here</p>", []),
    ],
)
def test_reflection_contexts(document: str, expected: list[tuple[str, str]]) -> None:
    found = find_reflections(tokenize(document), M)
    assert [(reflection.context, reflection.variant) for reflection in found] == expected


@pytest.mark.parametrize(
    ("context", "variant", "document"),
    [
        ("html_text", "", f"<p>a <{M}x> b</p>"),
        ("html_text", "textarea", f"<textarea>a</textarea><{M}x></textarea>"),
        ("html_text", "title", f"<title></title><{M}x></title>"),
        ("comment", "", f"<!-- a --><{M}x> -->"),
        ("attribute_quoted", '"', f'<input value=""{M}=x">'),
        ("attribute_quoted", "'", f"<input value=''{M}=x'>"),
        ("attribute_unquoted", "", f"<input value=x {M}=x>"),
        ("url_attribute", "", f'<a href="javascript:{M}">x</a>'),
        ("url_attribute", "", f'<a href=" JavaScript:{M}">x</a>'),
        ("script_string", "'", f"<script>var a = '';{M}//</script><{M}x>';</script>"),
        ("script_string", '"', f'<script>var a = "\\";{M}//</script><{M}x>";</script>'),
        ("script_code", "", f"<script>var a = ;{M}//</script><{M}x>;</script>"),
    ],
)
def test_breakouts_are_recognised(context: str, variant: str, document: str) -> None:
    assert find_proof(context, variant, tokenize(document), M)


@pytest.mark.parametrize(
    ("context", "variant", "document"),
    [
        ("html_text", "", f"<p>a &lt;{M}x&gt; b</p>"),
        ("html_text", "", f"<textarea><{M}x></textarea>"),  # still text, not an element
        ("html_text", "", f"<!-- <{M}x> -->"),
        ("html_text", "", f"<script>var a = '<{M}x>';</script>"),
        ("html_text", "textarea", f"<textarea>&lt;/textarea&gt;&lt;{M}x&gt;</textarea>"),
        ("html_text", "title", f"<p></title><{M}x></p>"),  # a stray end tag closed nothing
        ("comment", "", f"<!-- a --&gt;&lt;{M}x&gt; -->"),
        ("comment", "", f"<p>--><{M}x></p>"),  # an element, but no comment was closed
        ("attribute_quoted", '"', f'<input value="&quot;{M}=x">'),
        ("attribute_quoted", '"', f"<input value='\"{M}=x'>"),
        ("attribute_unquoted", "", f'<input value="x {M}=x">'),
        ("url_attribute", "", f'<a href="javascript%3A{M}">x</a>'),
        ("url_attribute", "", f'<a href="/javascript:{M}">x</a>'),
        ("url_attribute", "", f'<img src="javascript:{M}">'),
        ("script_string", "'", f"<script>var a = '\\';{M}//';</script>"),
        ("script_string", "'", f"<script>var a = '&#x27;;{M}//';</script>"),
        ("script_string", "'", f'<script>var a = "\';{M}//";</script>'),
        ("script_string", "'", f"<script>// ';{M}//\n</script>"),
        ("script_string", "'", f"<script>var a = '\\u0027;{M}//\\u003c/script\\u003e';</script>"),
        ("script_code", "", f"<script>var a = {M};</script>"),
        ("script_code", "", f"<script>var a = ';{M}//';</script>"),
        ("script_code", "", f'<script type="application/json">;{M}//</script>'),
    ],
)
def test_neutralised_strings_prove_nothing(context: str, variant: str, document: str) -> None:
    assert find_proof(context, variant, tokenize(document), M) == ""


# ── inputs, registry, payload hygiene ────────────────────────────────


class TestContract:
    def test_registered_and_described(self) -> None:
        spec = REGISTRY["xss_reflected"]
        assert (spec.vuln_class, spec.cwe, spec.state_changing) == ("xss", "CWE-79", False)
        assert spec.run is xss.xss_reflected
        # Appended right after the probe before it; the existing order is untouched.
        # (Not pinned as "last": the next probe is appended after this one.)
        names = list(REGISTRY)
        assert names[:7] == [
            "jwt_alg_none", "idor", "ssrf_canary", "numeric_boundary", "mass_assignment",
            "graphql_checks", "sqli",
        ]  # fmt: skip
        assert names[7] == "xss_reflected"
        (described,) = [d for d in describe() if d["probe"] == "xss_reflected"]
        assert set(described["params"]) == {
            "url", "method", "parameter", "location", "value", "body", "headers",
        }  # fmt: skip

    def test_probe_list_and_probe_run_tools_expose_it(self, env) -> None:
        tools = CaptureTools(env.gateway, engagement="acme")
        listed = {p["probe"]: p for p in tools.probe_list()["probes"]}
        assert listed["xss_reflected"]["class"] == "xss"
        assert listed["xss_reflected"]["cwe"] == "CWE-79"
        env.origin.pages["/search"] = page(P, raw)
        result = tools.probe_run(
            "acme", "xss_reflected", json.dumps({"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        )
        assert result["vulnerable"] is True
        assert result["details"]["contexts"][0]["context"] == "html_text"
        json.dumps(result)  # the whole result is JSON-serialisable

    @pytest.mark.parametrize(
        "params",
        [
            {"url": f"{BASE}/search"},  # no parameter
            {"parameter": "q"},  # no url
            {"url": f"{BASE}/search?q=shoes", "parameter": "q", "location": "cookie"},
            {"url": f"{BASE}/search?q=shoes", "parameter": "q", "value": {"a": 1}},
            {"url": f"{BASE}/report", "parameter": "name", "location": "json", "body": "[1]"},
            {"url": f"{BASE}/report", "parameter": "name", "location": "json", "body": "{not json"},
            {"url": f"{BASE}/comment", "parameter": "text", "location": "form", "body": ["text"]},
            {"url": f"{BASE}/orders/17", "parameter": "id", "location": "path"},  # no placeholder
            {"url": f"{BASE}/orders?x={{id}}", "parameter": "id", "location": "path"},
        ],
    )
    def test_bad_input_is_an_error_and_sends_nothing(self, env, params: dict) -> None:
        result = probe(env, params)
        assert result["status"] == "error", result
        assert env.origin.seen == []

    def test_a_parameter_absent_from_the_request_is_added(self, env) -> None:
        env.origin.pages["/search"] = page(P, raw)
        result = probe(env, {"url": f"{BASE}/search?page=2", "parameter": "q"})
        assert result["vulnerable"] is True, result

    def test_every_request_carries_its_own_marker(self, env) -> None:
        env.origin.pages["/search"] = page(P + DQ + JS_SQ, html.escape)
        probe(env, {"url": f"{BASE}/search?q=shoes", "parameter": "q"})
        markers = [set(MARKER.findall(value)) for value in sent(env)]
        assert len(markers) == 4 and all(len(found) == 1 for found in markers)
        assert len(set.union(*markers)) == 4
        assert xss.new_marker() != xss.new_marker()

    def test_payloads_are_fixed_and_run_nothing(self) -> None:
        assert set(PAYLOADS) == {
            "html_text", "html_text_in_element", "attribute_quoted", "attribute_unquoted",
            "script_string", "script_code", "url_attribute", "comment",
        }  # fmt: skip
        built = [
            payload_for("html_text", "", M),
            payload_for("comment", "", M),
            payload_for("attribute_unquoted", "", M),
            payload_for("script_code", "", M),
            payload_for("url_attribute", "", M),
            *(payload_for("html_text", element, M) for element in xss.RAW_TEXT_ELEMENTS),
            *(payload_for("attribute_quoted", q, M) for q in "\"'"),
            *(payload_for("script_string", q, M) for q in "\"'`"),
        ]
        assert len(set(built)) == len(built)
        for payload in built:
            assert payload.count(M) >= 1 and len(payload) < 60
            # What is left once the marker is taken out can only be punctuation
            # and inert names: no call, no handler, no element that loads or runs.
            rest = payload.replace(M, "").lower()
            assert "(" not in rest and ")" not in rest and "\n" not in rest
            assert not re.search(r"\bon\w+\s*=", rest)
            for forbidden in ("<script", "<img", "<svg", "<iframe", "alert", "eval", "fetch",
                              "document", "window", "import", "src=", "http", "data:"):  # fmt: skip
                assert forbidden not in rest, payload
        # The only element a payload opens is named after the marker.
        opened = {name for payload in built for name in re.findall(r"<([a-z0-9]+)", payload)}
        assert opened == {f"{M}x"}
        assert payload_for("url_attribute", "", M) == f"javascript:{M}"
        assert payload_for("html_text", "", M) == f"<{M}x>"
        assert payload_for("attribute_quoted", '"', M) == f'"{M}=x'
        assert payload_for("script_string", "'", M).startswith(f"';{M}//")
