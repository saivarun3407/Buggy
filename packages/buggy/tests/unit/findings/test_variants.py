"""Fix breaking: after "fixed", retest tries read-only variants of the proof; siblings seed leads.

A fake origin answers per path and query, so a fix can block the reported
payload and miss a variant. Every request goes through a real ``CaptureGateway``.
"""

from __future__ import annotations

import html
import io
import json
import urllib.error
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from tests.unit.findings.test_verifier import ALICE, ALICE_ORDER, BOB, _roe, _set_roe

from buggy.capture.gateway import CaptureGateway, Roots
from buggy.findings import siblings, variants
from buggy.findings.retest import retest
from buggy.findings.service import FindingService
from buggy.findings.store import FindingStore

ORDER = "https://app.acme.test/api/orders/1001"
SEARCH = "https://app.acme.test/rest/products/search"
FILES = "https://app.acme.test/download"
GO = "https://app.acme.test/go"
PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"

Handler = Callable[[str, str, dict[str, str]], tuple[int, object, dict[str, str]]]


class Origin:
    """A fake origin: ``handler(method, url, headers) -> (status, body, headers)``."""

    def __init__(self) -> None:
        self.handler: Handler = lambda _m, _u, _h: (404, b"not found", {})
        self.seen: list[tuple[str, str]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        self.seen.append((method, url))
        status, payload, extra = self.handler(method, url, headers)
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
        elif isinstance(payload, str):
            payload = payload.encode()
        response_headers = {"Content-Type": "application/json", **extra}
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", response_headers, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, response_headers
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.roots = Roots(
            control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data"
        )
        _set_roe(self.roots, _roe(approvals={"state_changing": "not_required"}))
        self.site = Origin()
        self.gateway = CaptureGateway(self.roots, opener=self.site, sleep=lambda _s: None)
        self.store = FindingStore(self.roots.data / "findings.sqlite3")
        self.service = FindingService(self.store, self.gateway)

    def close(self) -> None:
        self.gateway.store.close()
        self.store.close()

    def send(self, method: str, url: str, headers: dict[str, str] | None = None):
        return self.gateway.send("acme", method, url, headers=headers or {}, note="proof")

    def prove(self, claim: dict) -> str:
        out = self.service.submit("acme", claim, "agent:hunter")
        assert out["ok"], out
        finding = out["finding"]["id"]
        verified = self.service.verify("acme", finding)["finding"]
        assert verified["status"] == "exploit_verified", verified
        self.site.seen.clear()
        return finding

    def variant_captures(self) -> list:
        return [c for c in self.gateway.store.list("acme", limit=500) if c.note == "retest-variant"]


@pytest.fixture
def env(tmp_path: Path):
    environment = Env(tmp_path)
    yield environment
    environment.close()


def _query(url: str, name: str) -> str:
    return (parse_qs(urlsplit(url).query, keep_blank_values=True).get(name) or [""])[0]


# ── IDOR ────────────────────────────────────────────────────────────


def idor_site(*, slash_open: bool = False, head_open: bool = False, neighbour_open: bool = False):
    """Alice owns order 1001. The fix refuses Bob on the exact URL only (unless noted)."""

    def handler(method: str, url: str, headers: dict[str, str]):
        auth = headers.get("authorization")
        path = urlsplit(url).path
        if path == "/api/orders/1001":
            if auth == "Bearer alice":
                return 200, ALICE_ORDER, {}
            if method == "HEAD" and head_open:
                return 200, b"", {}
            return 403, {"error": "forbidden"}, {}
        if path == "/api/orders/1001/" and slash_open and auth:
            return 200, ALICE_ORDER, {}
        if path == "/api/orders/1002" and neighbour_open and auth:
            return 200, {"id": 1002, "owner": "carol@acme.test", "items": ["kettle"]}, {}
        return 404, {"error": "not found"}, {}

    return handler


def prove_idor(env: Env) -> str:
    env.site.handler = lambda _m, _u, h: (
        (200, ALICE_ORDER, {})
        if h.get("authorization")
        else (
            401,
            {},
            {},
        )
    )
    owner = env.send("GET", ORDER, ALICE)
    attacker = env.send("GET", ORDER, BOB)
    return env.prove(
        {
            "title": "IDOR on GET /api/orders/{id}",
            "class": "access_control",
            "cwe": "CWE-639",
            "severity": "high",
            "endpoint": ORDER,
            "method": "GET",
            "parameter": "id",
            "source": "probe:idor",
            "assertions": [
                {
                    "capture_id": owner.id,
                    "expect": {"status": 200, "body_contains": ["alice@acme.test"]},
                },
                {
                    "capture_id": attacker.id,
                    "expect": {
                        "status": 200,
                        "same_as": owner.id,
                        "body_contains": ["alice@acme.test"],
                    },
                },
            ],
        }
    )


class TestIdorVariants:
    def test_a_path_form_the_fix_missed_is_a_new_linked_finding(self, env: Env) -> None:
        original = prove_idor(env)
        env.site.handler = idor_site(slash_open=True)

        out = retest(env.service, "acme", original)

        assert out["outcome"] == "variant_still_works"
        assert "fixed for the original payload" in out["reasons"][0]
        report = out["variants"]
        assert report["family"] == "idor" and report["outcome"] == "variant_works"
        assert [t["name"] for t in report["tried"]] == ["trailing_slash"]
        (new_id,) = report["new_finding_ids"]
        new = env.store.get("acme", new_id)
        assert new is not None and new.status == "candidate" and new.source == "retest:variant"
        assert original in new.description and "trailing_slash" in new.parameter
        assert new.endpoint.endswith("/api/orders/{id}/")
        assert [e["event"] for e in env.store.events("acme", original)][-2:] == [
            "variant_found",
            "retest",
        ]
        assert "variant_of" in [e["event"] for e in env.store.events("acme", new_id)]
        # Not fixed: fixed_at stays unset, and the original's status is untouched.
        assert out["fixed_at"] is None
        assert env.store.get("acme", original).status == "exploit_verified"
        # The new claim is re-provable like any other.
        assert env.service.verify("acme", new_id)["finding"]["status"] == "exploit_verified"

    def test_a_complete_fix_stays_fixed_after_every_variant_is_tried(self, env: Env) -> None:
        original = prove_idor(env)
        env.site.handler = idor_site()

        out = retest(env.service, "acme", original)

        assert out["outcome"] == "fixed" and out["fixed_at"]
        report = out["variants"]
        assert report["outcome"] == "no_variant_works" and report["new_finding_ids"] == []
        names = [t["name"] for t in report["tried"]]
        assert names[:5] == [
            "trailing_slash",
            "upper_case",
            "matrix_parameter",
            "dot_segment",
            "json_suffix",
        ]
        assert "head_method" in names and "neighbour_id_1002" in names
        sent = env.variant_captures()
        assert len(sent) <= variants.MAX_REQUESTS
        assert {c.method for c in sent} <= {"GET", "HEAD"}
        assert set(report["capture_ids"]) <= set(out["capture_ids"])

    def test_head_answering_when_get_is_refused_is_a_low_variant(self, env: Env) -> None:
        original = prove_idor(env)
        env.site.handler = idor_site(head_open=True)
        out = retest(env.service, "acme", original)
        assert out["outcome"] == "variant_still_works"
        new = env.store.get("acme", out["variants"]["new_finding_ids"][0])
        assert new.method == "HEAD" and new.severity == "low"

    def test_a_neighbouring_object_both_accounts_read_is_a_variant(self, env: Env) -> None:
        original = prove_idor(env)
        env.site.handler = idor_site(neighbour_open=True)
        out = retest(env.service, "acme", original)
        assert out["outcome"] == "variant_still_works"
        assert out["variants"]["tried"][-1]["name"] == "neighbour_id_1002"

    def test_variants_can_be_switched_off(self, env: Env) -> None:
        original = prove_idor(env)
        env.site.handler = idor_site(slash_open=True)
        out = retest(env.service, "acme", original, variants=False)
        assert out["outcome"] == "fixed" and "variants" not in out
        assert env.variant_captures() == []

    def test_still_vulnerable_tries_no_variant(self, env: Env) -> None:
        original = prove_idor(env)
        out = retest(env.service, "acme", original)
        assert out["outcome"] == "still_vulnerable" and "variants" not in out
        assert env.variant_captures() == []


# ── parameter probes ────────────────────────────────────────────────


def _search_site(*, fixed: bool) -> Handler:
    """Boolean SQL injection in ``q``; the fix handles single quotes only."""

    def handler(_method: str, url: str, _headers: dict[str, str]):
        q = _query(url, "q")
        rows = [{"id": i, "name": f"apple {i}", "price": i * 3} for i in range(1, 9)]
        for true, false in (("' AND '1'='1", "' AND '1'='2"), ('" AND "1"="1', '" AND "1"="2')):
            single = true.startswith("'")
            if fixed and single:
                continue
            if q.endswith(true):
                return 200, {"data": rows}, {}
            if q.endswith(false):
                return 200, {"data": []}, {}
        if q == "apple":
            return 200, {"data": rows}, {}
        return 200, {"data": [], "note": f"nothing for {q}"}, {}

    return handler


def prove_sqli(env: Env) -> str:
    env.site.handler = _search_site(fixed=False)
    base = env.send("GET", f"{SEARCH}?q=apple")
    true = env.send("GET", f"{SEARCH}?q=apple%27%20AND%20%271%27%3D%271")
    false = env.send("GET", f"{SEARCH}?q=apple%27%20AND%20%271%27%3D%272")
    return env.prove(
        {
            "title": "SQL injection in q",
            "class": "injection",
            "cwe": "CWE-89",
            "severity": "high",
            "endpoint": SEARCH,
            "parameter": "q",
            "source": "probe:sqli",
            "assertions": [
                {"capture_id": true.id, "expect": {"status": 200, "same_as": base.id}},
                {"capture_id": false.id, "expect": {"status": 200, "differs_from": base.id}},
            ],
        }
    )


def test_sqli_another_quote_context_still_works(env: Env) -> None:
    original = prove_sqli(env)
    env.site.handler = _search_site(fixed=True)
    out = retest(env.service, "acme", original)
    assert out["outcome"] == "variant_still_works"
    tried = out["variants"]["tried"]
    assert [t["name"] for t in tried] == ["double_quote"] and tried[0]["outcome"] == "works"
    new = env.store.get("acme", out["variants"]["new_finding_ids"][0])
    assert new.parameter == "q [variant: double_quote]" and len(new.assertions) == 3
    assert env.service.verify("acme", new.id)["finding"]["status"] == "exploit_verified"


def _page_site(*, fixed: bool) -> Handler:
    """``q`` is echoed into HTML; the fix escapes it only when it holds ``<b``."""

    def handler(_method: str, url: str, _headers: dict[str, str]):
        q = _query(url, "q")
        shown = html.escape(q) if fixed and "<b" in q.lower() else q
        return 200, f"<html><body>Results for {shown}</body></html>", {"Content-Type": "text/html"}

    return handler


def test_xss_a_tag_the_fix_does_not_escape_still_works(env: Env) -> None:
    env.site.handler = _page_site(fixed=False)
    proof = env.send("GET", f"{SEARCH}?q=%3Cb%20data-buggy%3Dbgx1%3E")
    original = env.prove(
        {
            "title": "Reflected XSS in q",
            "class": "xss",
            "severity": "medium",
            "endpoint": SEARCH,
            "parameter": "q",
            "source": "probe:xss_reflected",
            "assertions": [
                {
                    "capture_id": proof.id,
                    "expect": {"status": 200, "body_contains": ["<b data-buggy=bgx1>"]},
                },
                {"capture_id": proof.id, "expect": {"status": 200}},
            ],
        }
    )
    env.site.handler = _page_site(fixed=True)
    out = retest(env.service, "acme", original)
    assert out["outcome"] == "variant_still_works"
    names = [t["name"] for t in out["variants"]["tried"]]
    assert names[-1] == "svg_tag" and "attribute_double_quote" in names


def _file_site(*, fixed: bool) -> Handler:
    """``file`` is joined to a directory; the fix strips ``../`` once and misses ``....//``."""

    def handler(_method: str, url: str, _headers: dict[str, str]):
        name = _query(url, "file")
        if fixed:
            name = name.replace("../", "")
        if name.count("../") >= 2 and name.endswith("etc/passwd"):
            return 200, PASSWD, {"Content-Type": "text/plain"}
        return 404, "no such file", {"Content-Type": "text/plain"}

    return handler


def test_traversal_an_encoding_the_fix_misses_still_works(env: Env) -> None:
    env.site.handler = _file_site(fixed=False)
    proof = env.send("GET", f"{FILES}?file=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd")
    original = env.prove(
        {
            "title": "Path traversal in file",
            "class": "file_handling",
            "cwe": "CWE-22",
            "severity": "high",
            "endpoint": FILES,
            "parameter": "file",
            "source": "probe:path_traversal",
            "assertions": [
                {
                    "capture_id": proof.id,
                    "expect": {"status": 200, "body_contains": ["root:x:0:0:"]},
                }
            ],
        }
    )
    env.site.handler = _file_site(fixed=True)
    out = retest(env.service, "acme", original)
    assert out["outcome"] == "variant_still_works"
    assert out["variants"]["tried"][-1]["name"] == "nested_dots"


def _redirect_site(*, fixed: bool) -> Handler:
    """Redirects to ``next``; the fix refuses values starting with ``//`` or a scheme."""

    def handler(_method: str, url: str, _headers: dict[str, str]):
        target = _query(url, "next")
        if fixed and (target.startswith("//") or "://" in target):
            return 403, "refused", {"Content-Type": "text/plain"}
        return 302, "", {"Location": target}

    return handler


def test_open_redirect_a_bypass_form_the_fix_misses_still_works(env: Env) -> None:
    env.site.handler = _redirect_site(fixed=False)
    proof = env.send("GET", f"{GO}?next=%2F%2Fbgabc.example%2F")
    original = env.prove(
        {
            "title": "Open redirect in next",
            "class": "open_redirect",
            "severity": "low",
            "endpoint": GO,
            "parameter": "next",
            "source": "probe:open_redirect",
            "assertions": [{"capture_id": proof.id, "expect": {"status": 302}}],
        }
    )
    env.site.handler = _redirect_site(fixed=True)
    out = retest(env.service, "acme", original)
    assert out["outcome"] == "variant_still_works"
    assert out["variants"]["tried"][0]["name"] == "backslash"


class TestNotTried:
    def test_a_state_changing_proof_is_not_varied(self, env: Env) -> None:
        env.site.handler = lambda _m, _u, _h: (200, {"ok": True}, {})
        post = env.gateway.send("acme", "POST", SEARCH, body=b"q=1", note="proof")
        claim = {
            "title": "x",
            "class": "injection",
            "cwe": "CWE-89",
            "severity": "high",
            "endpoint": SEARCH,
            "parameter": "q",
            "source": "probe:sqli",
            "assertions": [{"capture_id": post.id, "expect": {"status": 200}}],
        }
        out = env.service.submit("acme", claim, "agent:hunter")
        finding = env.store.get("acme", out["finding"]["id"])
        report = variants.try_variants(finding, env.gateway)
        assert report.outcome == "not_tried" and "approval" in report.reasons[0]
        assert env.variant_captures() == []

    def test_a_class_without_variants_is_not_tried(self, env: Env) -> None:
        env.site.handler = lambda _m, _u, _h: (200, {"ok": True}, {})
        capture = env.send("GET", SEARCH)
        out = env.service.submit(
            "acme",
            {
                "title": "x",
                "class": "misconfiguration",
                "severity": "low",
                "endpoint": SEARCH,
                "source": "agent:hunter",
                "assertions": [{"capture_id": capture.id, "expect": {"status": 200}}],
            },
            "agent:hunter",
        )
        finding = env.store.get("acme", out["finding"]["id"])
        assert variants.try_variants(finding, env.gateway).outcome == "not_tried"


def test_query_helpers() -> None:
    url = "https://a.test/s?x=1&q=a+b&q=2"
    assert variants.query_value(url, "q") == "a b"
    assert variants.with_wire_value(url, "q", "%27") == "https://a.test/s?x=1&q=%27&q=2"
    assert variants.with_wire_value(url, "nope", "1") is None


# ── siblings ────────────────────────────────────────────────────────


RECON = {
    "endpoint": [
        {"value": "https://app.acme.test/api/Cards/{id}", "attrs": {}},
        {"value": "https://app.acme.test/api/Users/7", "attrs": {}},
        {"value": "https://app.acme.test/api/Cards/3/items", "attrs": {}},
        {"value": "https://other.acme.test/api/Notes/{id}", "attrs": {}},
        {"value": "https://app.acme.test/rest/track?q=1", "attrs": {}},
    ],
    "url": [{"value": "https://app.acme.test/api/Addresss", "attrs": {}}],
    "api_operation": [
        {
            "value": "PUT https://app.acme.test/api/Quantitys/{id}",
            "attrs": {"url": "https://app.acme.test/api/Quantitys/{id}", "method": "PUT"},
        }
    ],
    "parameter": [
        {
            "value": "q",
            "attrs": {
                "name": "q",
                "url": "https://app.acme.test/api/feedback",
                "location": "query",
            },
        }
    ],
}


class TestSiblings:
    def test_same_route_pattern_on_other_collections(self) -> None:
        finding = {
            "id": "F-1",
            "class": "access_control",
            "title": "IDOR on /api/Users/{id}",
            "endpoint": "https://app.acme.test/api/Users/5",
            "source": "probe:idor",
        }
        rows = siblings.rows(finding, RECON)
        where = [r["where"] for r in rows]
        assert where == [
            "https://app.acme.test/api/Addresss/{id}",
            "https://app.acme.test/api/Cards/{id}",
            "PUT https://app.acme.test/api/Quantitys/{id}",
            "https://app.acme.test/api/feedback/{id}",  # a known collection, like Addresss
        ]
        assert all(r["class"] == "access_control" and r["probe"] == "idor" for r in rows)
        assert all("F-1" in r["why"] and "same route pattern" in r["why"] for r in rows)

    def test_same_parameter_name_on_other_endpoints(self) -> None:
        finding = {
            "id": "F-2",
            "class": "injection",
            "title": "SQL injection in q",
            "endpoint": SEARCH,
            "parameter": "q [variant: double_quote]",
            "source": "probe:sqli",
        }
        rows = siblings.rows(finding, RECON)
        assert [r["where"] for r in rows] == [
            "https://app.acme.test/api/feedback",
            "https://app.acme.test/rest/track",
        ]
        assert all("takes parameter 'q'" in r["why"] for r in rows)

    def test_only_a_proven_finding_seeds_and_leads_go_through_the_queue(self, env: Env) -> None:
        original = prove_idor(env)
        records = {"endpoint": [{"value": "https://app.acme.test/api/invoices/{id}", "attrs": {}}]}
        out = siblings.seed(env.service, "acme", original, records)
        assert out["ok"] and out["created"] == 1
        assert out["rows"][0]["where"] == "https://app.acme.test/api/invoices/{id}"
        lead = env.store.get("acme", out["ids"][0])
        assert lead.status == "candidate" and lead.severity == "info"
        assert original in lead.description and lead.assertions == ()

        candidate = env.service.submit(
            "acme",
            {"title": "x", "class": "xss", "severity": "low", "endpoint": SEARCH, "source": "a:b"},
            "agent:hunter",
        )["finding"]["id"]
        refused = siblings.seed(env.service, "acme", candidate, records)
        assert refused == {**refused, "ok": False, "code": "NOT_PROVEN"}
        assert siblings.seed(env.service, "acme", "F-000000000000", records)["code"] == (
            "UNKNOWN_FINDING"
        )
