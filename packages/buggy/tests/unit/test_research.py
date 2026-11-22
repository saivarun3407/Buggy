"""Reading public pages for the agent without a path to the target (``buggy.research``).

No real network: DNS and the socket are replaced by fakes.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from buggy import research
from buggy.pipeline.scope import ScopeFilter
from buggy.research import NOTICE, Response, fetch

PUBLIC = "93.184.216.34"
OTHER_PUBLIC = "151.101.1.69"
TARGET_IP = "203.0.113.7"  # a documentation range: never globally routable


def scope_filter() -> ScopeFilter:
    return ScopeFilter.from_document(
        {
            "machine_enforcement": {
                "mode": "enforce",
                "in_scope": ["app.acme.test", "*.shop.example"],
                "out_of_scope": ["legacy.vendor.example"],
            }
        }
    )


class Net:
    """Fake DNS and server: ``pages[(host, target)] = Response``."""

    def __init__(self) -> None:
        self.dns: dict[str, list[str]] = {
            "docs.python.org": [PUBLIC],
            "developer.mozilla.org": [OTHER_PUBLIC],
            "app.acme.test": ["34.120.7.20"],
        }
        self.pages: dict[tuple[str, str], Response] = {}
        self.sent: list[tuple[str, str, str, int, str, dict[str, str]]] = []

    def resolve(self, host: str) -> list[str]:
        if host not in self.dns:
            raise OSError("name does not resolve")
        return self.dns[host]

    def send(
        self,
        scheme: str,
        host: str,
        address: str,
        port: int,
        target: str,
        headers: dict[str, str],
        timeout: float,
    ) -> Response:
        del timeout
        self.sent.append((scheme, host, address, port, target, headers))
        page = self.pages.get((host, target))
        if page is None:
            return Response(404, {"content-type": "text/plain"}, b"not found")
        return page


def html(body: str, title: str = "Doc") -> Response:
    page = (
        f"<html><head><title>{title}</title><style>p{{}}</style></head><body>{body}</body></html>"
    )
    return Response(200, {"content-type": "text/html; charset=utf-8"}, page.encode())


@pytest.fixture
def net() -> Net:
    return Net()


def get(net: Net, url: str, tmp_path: Path, **kwargs) -> dict:
    return fetch(
        url,
        scope=scope_filter(),
        document={"network": {"allow_private_targets": True}},
        engagement="acme",
        audit_root=tmp_path / "audit",
        resolve=net.resolve,
        send=net.send,
        **kwargs,
    )


def audit_lines(tmp_path: Path) -> list[dict]:
    path = tmp_path / "audit" / "acme" / "research.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


class TestReading:
    def test_an_html_page_is_reduced_to_readable_text(self, net: Net, tmp_path: Path) -> None:
        net.pages[("docs.python.org", "/3/library/http.html")] = html(
            "<nav>Home | Index</nav><script>steal()</script>"
            "<h1>http &mdash; HTTP modules</h1><p>Source code: <a href='/3/x.py'>x.py</a></p>"
            "<ul><li>one</li><li>two</li></ul><pre>import http\n  print(1)</pre>"
            "<a href='mailto:x@y.z'>mail</a><a href='https://peps.python.org/pep-8/'>PEP 8</a>",
            title="http — HTTP modules",
        )
        result = get(net, "https://docs.python.org/3/library/http.html#frag", tmp_path)
        assert result["ok"] is True
        assert result["notice"] == NOTICE and list(result)[0] == "notice"
        assert result["status"] == 200 and result["content_type"] == "text/html"
        assert result["title"] == "http — HTTP modules"
        text = result["text"]
        assert "# http — HTTP modules" in text
        assert "- one" in text and "- two" in text
        assert "```\nimport http\n  print(1)\n```" in text
        assert "steal()" not in text and "Home | Index" not in text and "p{}" not in text
        assert result["links"] == [
            {"text": "x.py", "href": "https://docs.python.org/3/x.py"},
            {"text": "PEP 8", "href": "https://peps.python.org/pep-8/"},
        ]
        assert result["truncated"] is False and result["bytes"] > 0
        # The checked address is the one connected to; only the URL goes out.
        scheme, host, address, port, target, headers = net.sent[0]
        assert (scheme, host, address, port, target) == (
            "https",
            "docs.python.org",
            PUBLIC,
            443,
            "/3/library/http.html",
        )
        assert headers["User-Agent"] == "buggy-research/1"
        assert not {"Cookie", "Authorization"} & set(headers)

    def test_links_are_capped(self, net: Net, tmp_path: Path) -> None:
        anchors = "".join(f"<a href='/p{i}'>p{i}</a>" for i in range(300))
        net.pages[("docs.python.org", "/")] = html(anchors)
        assert len(get(net, "https://docs.python.org/", tmp_path)["links"]) == 200

    def test_long_text_is_cut_with_a_marker(self, net: Net, tmp_path: Path) -> None:
        net.pages[("docs.python.org", "/big.txt")] = Response(
            200, {"content-type": "text/plain"}, b"a" * 5000
        )
        result = get(net, "https://docs.python.org/big.txt", tmp_path, max_bytes=1000)
        assert result["truncated"] is True
        assert result["text"].startswith("a" * 1000)
        assert "[... truncated" in result["text"]

    def test_json_is_returned_as_text(self, net: Net, tmp_path: Path) -> None:
        net.pages[("docs.python.org", "/a.json")] = Response(
            200, {"content-type": "application/json"}, b'{"a": 1}'
        )
        assert get(net, "https://docs.python.org/a.json", tmp_path)["text"] == '{"a": 1}'

    def test_a_pdf_is_not_parsed(self, net: Net, tmp_path: Path) -> None:
        net.pages[("docs.python.org", "/paper.pdf")] = Response(
            200, {"content-type": "application/pdf"}, b"%PDF-1.7 " + b"x" * 991
        )
        result = get(net, "https://docs.python.org/paper.pdf", tmp_path)
        assert result["ok"] is True and result["bytes"] == 1000
        assert "PDF of 1000 bytes" in result["text"] and "%PDF" not in result["text"]

    def test_other_content_is_not_read(self, net: Net, tmp_path: Path) -> None:
        net.pages[("docs.python.org", "/a.bin")] = Response(
            200, {"content-type": "application/octet-stream"}, b"\x00\x01"
        )
        result = get(net, "https://docs.python.org/a.bin", tmp_path)
        assert result == {"ok": False, "error": "UNSUPPORTED_CONTENT", "detail": result["detail"]}

    def test_a_redirect_to_another_public_page_is_followed(self, net: Net, tmp_path: Path) -> None:
        net.pages[("docs.python.org", "/old")] = Response(
            301, {"location": "https://developer.mozilla.org/en-US/docs/Web/HTTP"}, b""
        )
        net.pages[("developer.mozilla.org", "/en-US/docs/Web/HTTP")] = html("<p>HTTP</p>")
        result = get(net, "https://docs.python.org/old", tmp_path)
        assert result["ok"] is True
        assert result["url"] == "https://developer.mozilla.org/en-US/docs/Web/HTTP"
        assert [s[2] for s in net.sent] == [PUBLIC, OTHER_PUBLIC]

    def test_redirects_are_limited(self, net: Net, tmp_path: Path) -> None:
        for i in range(10):
            net.pages[("docs.python.org", f"/r{i}")] = Response(
                302, {"location": f"/r{i + 1}"}, b""
            )
        result = get(net, "https://docs.python.org/r0", tmp_path)
        assert result["error"] == "TOO_MANY_REDIRECTS" and len(net.sent) == 6


class TestRefusals:
    @pytest.mark.parametrize(
        "url",
        [
            "https://app.acme.test/docs",
            "https://api.shop.example/",
            "https://www.acme.test/about",  # the parent domain of an in-scope host
            "https://legacy.vendor.example/",  # an out-of-scope entry of the program
        ],
    )
    def test_the_programs_hosts_are_reached_only_through_the_gateway(
        self, net: Net, tmp_path: Path, url: str
    ) -> None:
        result = get(net, url, tmp_path)
        assert result["ok"] is False and result["error"] == "IN_SCOPE_USE_GATEWAY"
        assert "http_send" in result["detail"]
        assert net.sent == []

    def test_a_name_that_resolves_to_the_target_is_refused(self, net: Net, tmp_path: Path) -> None:
        net.dns["mirror.example.net"] = ["34.120.7.20"]
        result = get(net, "https://mirror.example.net/", tmp_path)
        assert result["error"] == "IN_SCOPE_USE_GATEWAY" and net.sent == []

    def test_a_redirect_into_scope_is_refused_mid_chain(self, net: Net, tmp_path: Path) -> None:
        net.pages[("docs.python.org", "/go")] = Response(
            302, {"location": "https://app.acme.test/admin"}, b""
        )
        result = get(net, "https://docs.python.org/go", tmp_path)
        assert result["error"] == "IN_SCOPE_USE_GATEWAY"
        assert [s[1] for s in net.sent] == ["docs.python.org"]
        line = audit_lines(tmp_path)[-1]
        assert line["status"] == "IN_SCOPE_USE_GATEWAY"
        assert line["final_url"] == "https://app.acme.test/admin"

    @pytest.mark.parametrize(
        "location",
        ["http://localhost/", "http://metadata.google.internal/", "http://intranet.corp.lan/"],
    )
    def test_a_redirect_to_an_internal_name_is_refused(
        self, net: Net, tmp_path: Path, location: str
    ) -> None:
        net.pages[("docs.python.org", "/go")] = Response(302, {"location": location}, b"")
        result = get(net, "https://docs.python.org/go", tmp_path)
        assert result["error"] == "INTERNAL_ADDRESS" and len(net.sent) == 1

    @pytest.mark.parametrize(
        "address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fd00::5", "100.64.0.9"]
    )
    def test_a_public_looking_name_that_resolves_inside_is_refused(
        self, net: Net, tmp_path: Path, address: str
    ) -> None:
        # The DNS-rebinding shape: an innocent name with a private answer.
        net.dns["innocent.example.com"] = [PUBLIC, address]
        result = get(net, "https://innocent.example.com/", tmp_path)
        assert result["error"] == "INTERNAL_ADDRESS" and net.sent == []

    def test_a_redirect_to_a_name_resolving_inside_is_refused(
        self, net: Net, tmp_path: Path
    ) -> None:
        net.dns["rebind.example.com"] = ["192.168.1.1"]
        net.pages[("docs.python.org", "/go")] = Response(
            307, {"location": "https://rebind.example.com/"}, b""
        )
        assert get(net, "https://docs.python.org/go", tmp_path)["error"] == "INTERNAL_ADDRESS"
        assert len(net.sent) == 1

    def test_allow_private_targets_does_not_open_research(self, net: Net, tmp_path: Path) -> None:
        # ``get`` passes a document that allows private targets; research ignores it.
        net.dns["lab.example.com"] = ["10.0.0.8"]
        assert get(net, "https://lab.example.com/", tmp_path)["error"] == "INTERNAL_ADDRESS"

    @pytest.mark.parametrize(
        ("url", "why"),
        [
            ("https://user:pw@docs.python.org/", "user name"),
            ("https://docs.python.org:22/", "port 22"),
            ("ftp://docs.python.org/", "http and https"),
            ("file:///etc/passwd", "http and https"),
            ("https://93.184.216.34/", "bare IP"),
            ("https://docs.python.org/" + "a" * 2000, "longer than"),
        ],
    )
    def test_bad_urls(self, net: Net, tmp_path: Path, url: str, why: str) -> None:
        result = get(net, url, tmp_path)
        assert result["error"] == "BAD_URL" and why in result["detail"], result
        assert net.sent == []

    def test_unresolvable_names_fail_without_sending(self, net: Net, tmp_path: Path) -> None:
        assert get(net, "https://nowhere.example.com/", tmp_path)["error"] == "DNS_FAILED"
        assert net.sent == []


class TestLeakGuard:
    @pytest.mark.parametrize(
        "url",
        [
            "https://docs.python.org/search?q=app.acme.test+login",
            "https://docs.python.org/q/APP.ACME.TEST",
            "https://docs.python.org/search?q=alice%40example.com",
            "https://docs.python.org/?q=" + "ab12" * 8,  # a hex run
            "https://docs.python.org/t/" + "eyJ" + "hbGciOiJIUzI1NiJ9xQ" + "z9",  # base64 + digits
            "https://app.acme.test.attacker.example/",  # the target's name inside another host
        ],
    )
    def test_urls_carrying_target_data_are_refused(
        self, net: Net, tmp_path: Path, url: str
    ) -> None:
        result = get(net, url, tmp_path)
        assert result["error"] == "LOOKS_LIKE_TARGET_DATA", result
        assert "general topic" in result["detail"]
        assert net.sent == []

    @pytest.mark.parametrize(
        "url",
        [
            "https://docs.python.org/3/howto/logging-cookbook-using-a-context-manager-for-selective-logging.html",
            "https://docs.python.org/api/org/springframework/AbstractSingletonProxyFactoryBean.html",
            "https://docs.python.org/search?q=jwt+alg+none+vulnerability&check_keywords=yes",
            "https://docs.python.org/package/@types/node",
            "https://docs.python.org/cve/CVE-2021-44228",
        ],
    )
    def test_ordinary_documentation_urls_pass(self, net: Net, tmp_path: Path, url: str) -> None:
        research.leak_check(url, research.scope_names(scope_filter()))
        assert get(net, url, tmp_path)["ok"] is True


class TestAudit:
    def test_every_call_is_one_line_without_the_body(self, net: Net, tmp_path: Path) -> None:
        net.pages[("docs.python.org", "/")] = html("<p>secret-looking body text</p>")
        get(net, "https://docs.python.org/", tmp_path)
        get(net, "https://app.acme.test/", tmp_path)
        first, second = audit_lines(tmp_path)
        assert first["url"] == "https://docs.python.org/" and first["status"] == 200
        assert first["final_url"] == "https://docs.python.org/" and first["bytes"] > 0
        assert "ts" in first and "body" not in json.dumps(first)
        assert second["status"] == "IN_SCOPE_USE_GATEWAY" and second["bytes"] == 0

    def test_an_unwritable_audit_root_does_not_fail_the_fetch(
        self, net: Net, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "audit"
        blocker.write_text("a file where the directory should be")
        net.pages[("docs.python.org", "/")] = html("<p>hi</p>")
        records: list[logging.LogRecord] = []

        class Keep(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = Keep(level=logging.WARNING)
        logging.getLogger("buggy.research").addHandler(handler)
        try:
            result = get(net, "https://docs.python.org/", tmp_path)
        finally:
            logging.getLogger("buggy.research").removeHandler(handler)
        assert result["ok"] is True
        logged = " ".join(record.getMessage() for record in records)
        assert "research audit line not written" in logged
        assert "https://docs.python.org/" in logged


def test_the_internal_rule_covers_the_gateways() -> None:
    from buggy.capture.gateway import internal_address_block  # noqa: PLC0415

    nothing_in_scope = ScopeFilter.from_document(
        {"machine_enforcement": {"mode": "enforce", "in_scope": ["only.example.test"]}}
    )
    for address in ["127.0.0.1", "10.0.0.1", "172.16.5.5", "192.168.0.1", "169.254.1.1", "::1"]:
        literal = f"[{address}]" if ":" in address else address
        assert internal_address_block(f"http://{literal}/", nothing_in_scope, {}) is not None
        assert research.is_internal_ip(address), address
    for address in ["8.8.8.8", PUBLIC, "2606:4700::1111"]:
        assert not research.is_internal_ip(address), address
    assert research.is_internal_ip(TARGET_IP)  # documentation range: not globally routable
