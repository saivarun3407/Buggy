"""The ``open_redirect``, ``path_traversal`` and ``cors`` probes against a fake origin.

The fake origin answers with real status codes and response headers (a 3xx
comes back to the gateway as an ``HTTPError`` carrying ``Location``, which the
gateway never follows). The file handlers resolve the request value against
a small in-memory file system with ``posixpath`` the way a careless server
joins paths; the redirect handlers check allow-lists the way real code does
(prefix, substring, parsed host). No handler matches on the probe's payload
strings or knows its random host.
"""

from __future__ import annotations

import io
import json
import posixpath
import re
import urllib.error
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, unquote, urlsplit

import pytest

from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.probes import REGISTRY, describe, misc, run_probe
from buggy.capture.probes.misc import (
    CORS_MAX_REQUESTS,
    MARKER_FILES,
    REDIRECT_BYPASSES,
    REDIRECT_MAX_REQUESTS,
    TRAVERSAL_MAX_REQUESTS,
    TRAVERSAL_PAYLOADS,
    browser_host,
    traversal_payload,
)

BASE = "https://app.acme.test"
Reply = tuple[int, dict[str, str], str]
Handler = Callable[[str, dict[str, str], dict[str, str]], Reply]

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
WIN_INI = "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n"
POSIX_FS = {
    "/etc/passwd": PASSWD,
    "/srv/app/files/report.txt": "Quarterly report: all good.",
    "/srv/app/files/readme": "Read me.",
}
WINDOWS_FS = {
    "/windows/win.ini": WIN_INI,
    "/inetpub/files/report.txt": "Quarterly report: all good.",
}


class Origin:
    """A fake origin that answers ``(status, headers, body)`` per path prefix."""

    def __init__(self) -> None:
        self.handlers: dict[str, Handler] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        self.seen.append((method, url, headers, request.data or b""))
        parts = urlsplit(url)
        prefix = max((p for p in self.handlers if parts.path.startswith(p)), key=len, default=None)
        if prefix is None:
            status, reply, body = 404, {}, "not found"
        else:
            query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
            raw_path = url.split("?", 1)[0].split(parts.netloc, 1)[1]
            status, reply, body = self.handlers[prefix](raw_path, query, headers)
        payload = body.encode()
        reply = {"Content-Type": "text/html", **reply}
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", reply, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, reply
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


def _roe() -> str:
    return json.dumps(
        {
            "machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]},
            "approvals": {"state_changing": "not_required"},
        }
    )


@pytest.fixture
def env(tmp_path: Path):
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(_roe())
    origin = Origin()
    gateway = CaptureGateway(roots, opener=origin, sleep=lambda _s: None)
    yield SimpleNamespace(gateway=gateway, origin=origin, roots=roots)
    gateway.store.close()


def probe(env, name: str, params: dict) -> dict:
    return run_probe(env.gateway, "acme", name, params)


def check_evidence(env, result: dict) -> None:
    """Every request is evidence with a named role, recorded for this probe, within the bound."""
    ids = result["evidence_capture_ids"]
    details = result["details"]
    bound = {"open_redirect": 6, "path_traversal": 10, "cors": 3}[result["probe"]]
    assert len(ids) == len(env.origin.seen) == details["requests_sent"] <= bound
    assert details["max_requests"] == bound
    assert list(details["captures"].values()) == ids and len(set(ids)) == len(ids)
    assert set(details["payloads"]) == set(details["captures"])
    assert details["control"]
    for capture_id in ids:
        stored = env.gateway.store.get("acme", capture_id)
        assert stored is not None and stored.probe == result["probe"]
    if ids:
        assert next(iter(details["captures"])) == "baseline"


def sent(env, name: str) -> list[str]:
    return [parse_qs(urlsplit(url).query)[name][0] for _m, url, _h, _b in env.origin.seen]


def body_of(env, result: dict, role: str) -> str:
    capture = env.gateway.store.get("acme", result["details"]["captures"][role])
    return capture.response_body.decode()


# ── open redirect ────────────────────────────────────────────────────


def redirect(location: str) -> Reply:
    return 302, {"Location": location}, f"Found. Redirecting to {location}"


def go_anywhere(_path, query, _headers) -> Reply:
    return redirect(query.get("to", "/"))


def go_same_site(_path, query, _headers) -> Reply:
    # The value only ever ends up in the query string of an on-site path.
    return redirect("/landing?next=" + quote(query.get("to", ""), safe=""))


def go_prefix_allowlist(_path, query, _headers) -> Reply:
    to = query.get("to", "")
    if to.startswith("/") and not to.startswith("//") or to.startswith("https://trusted.test"):
        return redirect(to)
    return 400, {}, "redirect target not allowed"


def go_substring_allowlist(_path, query, _headers) -> Reply:
    to = query.get("to", "")
    if "https://trusted.test/home" in to:
        return redirect(to)
    return 406, {}, f"<title>Unrecognized target URL for redirect: {to}</title>"


def go_parsed_allowlist(_path, query, _headers) -> Reply:
    to = query.get("to", "")
    if urlsplit(to).scheme == "https" and urlsplit(to).hostname == "trusted.test":
        return redirect(to)
    return 400, {}, "redirect target not allowed"


GO = {"url": f"{BASE}/go?to=/home", "parameter": "to"}
GO_TRUSTED = {"url": f"{BASE}/go?to=https://trusted.test/home", "parameter": "to"}


class TestOpenRedirect:
    def test_location_to_any_host_is_found_with_the_plain_form(self, env) -> None:
        env.origin.handlers["/go"] = go_anywhere
        result = probe(env, "open_redirect", GO)
        assert result["status"] == "completed" and result["vulnerable"] is True, result
        assert (result["class"], result["cwe"]) == ("open_redirect", "CWE-601")
        details = result["details"]
        host = details["random_host"]
        assert re.fullmatch(r"bg[0-9a-f]{12}\.example", host)
        assert details["technique"] == "plain"
        assert list(details["captures"]) == ["baseline", "plain"]
        assert sent(env, "to") == ["/home", f"https://{host}/"]
        assert details["tried"][0]["redirect_kind"] == "location"
        assert details["baseline"]["redirects"][0]["host"] == "app.acme.test"
        assert "allow-list" in result["remediation"]
        check_evidence(env, result)

    def test_host_changes_from_run_to_run(self, env) -> None:
        env.origin.handlers["/go"] = go_anywhere
        first = probe(env, "open_redirect", GO)["details"]["random_host"]
        second = probe(env, "open_redirect", GO)["details"]["random_host"]
        assert first != second

    def test_redirect_to_a_same_site_path_is_not_flagged(self, env) -> None:
        env.origin.handlers["/go"] = go_same_site
        result = probe(env, "open_redirect", GO)
        assert result["vulnerable"] is False, result
        details = result["details"]
        # The plain form was refused, so all four bypass forms were tried, and none left the site.
        assert list(details["captures"]) == [
            "baseline",
            "plain",
            *(n for n, _ in REDIRECT_BYPASSES),
        ]
        assert all(t["outcome"] == "refused" for t in details["tried"])
        assert details["technique"] is None
        check_evidence(env, result)

    def test_allowlist_that_only_the_userinfo_form_bypasses(self, env) -> None:
        env.origin.handlers["/go"] = go_prefix_allowlist
        result = probe(env, "open_redirect", GO_TRUSTED)
        assert result["vulnerable"] is True, result
        details = result["details"]
        host = details["random_host"]
        assert details["technique"] == "userinfo"
        assert "userinfo" in result["summary"]
        assert list(details["captures"]) == [
            "baseline", "plain", "scheme_relative", "missing_slashes", "userinfo",
        ]  # fmt: skip
        assert details["payloads"]["userinfo"] == f"https://trusted.test@{host}/"
        assert [t["outcome"] for t in details["tried"]] == ["refused"] * 3 + ["redirected"]
        # The allow-listed original value stays a valid, on-list redirect: not off-site.
        assert details["baseline"]["redirects"][0]["host"] == "trusted.test"
        check_evidence(env, result)

    def test_substring_allowlist_is_bypassed_by_the_fragment_form(self, env) -> None:
        env.origin.handlers["/go"] = go_substring_allowlist
        result = probe(env, "open_redirect", GO_TRUSTED)
        assert result["vulnerable"] is True, result
        details = result["details"]
        host = details["random_host"]
        assert details["technique"] == "fragment"
        assert details["payloads"]["fragment"] == f"https://{host}/#https://trusted.test/home"
        check_evidence(env, result)

    def test_allowlist_hint_is_used_by_the_bypass_forms(self, env) -> None:
        env.origin.handlers["/go"] = go_prefix_allowlist
        params = {**GO, "allowlist_hint": "https://trusted.test"}
        result = probe(env, "open_redirect", params)
        assert result["vulnerable"] is True and result["details"]["technique"] == "userinfo"
        assert result["details"]["allowed_host"] == "trusted.test"

    def test_parsed_host_allowlist_is_not_flagged(self, env) -> None:
        env.origin.handlers["/go"] = go_parsed_allowlist
        result = probe(env, "open_redirect", GO_TRUSTED)
        assert result["vulnerable"] is False, result
        assert result["details"]["requests_sent"] == REDIRECT_MAX_REQUESTS
        check_evidence(env, result)

    def test_meta_refresh_in_a_200_page_is_found(self, env) -> None:
        def handler(_path, query, _headers) -> Reply:
            to = query.get("to", "")
            page = f'<html><head><meta http-equiv="refresh" content="0; url={to}"></head></html>'
            return 200, {}, page

        env.origin.handlers["/go"] = handler
        result = probe(env, "open_redirect", GO)
        assert result["vulnerable"] is True, result
        assert result["details"]["tried"][0]["redirect_kind"] == "meta_refresh"

    def test_script_location_in_a_200_page_is_found(self, env) -> None:
        def handler(_path, query, _headers) -> Reply:
            target = json.dumps(query.get("to", "")).replace("/", "\\/")
            return 200, {}, f"<script>window.location.href = {target};</script>"

        env.origin.handlers["/go"] = handler
        result = probe(env, "open_redirect", GO)
        assert result["vulnerable"] is True, result
        assert result["details"]["tried"][0]["redirect_kind"] == "javascript"

    def test_value_only_reflected_in_a_link_is_not_a_redirect(self, env) -> None:
        def handler(_path, query, _headers) -> Reply:
            return 200, {}, f'<p>Leaving the site. <a href="{query.get("to", "")}">Continue</a></p>'

        env.origin.handlers["/go"] = handler
        result = probe(env, "open_redirect", GO)
        assert result["vulnerable"] is False, result

    def test_page_that_always_redirects_off_site_cannot_be_attributed(self, env) -> None:
        env.origin.handlers["/go"] = lambda *_a: redirect("https://ads.partner.test/landing")
        result = probe(env, "open_redirect", GO)
        assert result["vulnerable"] is None, result
        assert "already redirects" in result["summary"]
        assert list(result["details"]["captures"]) == ["baseline"]
        check_evidence(env, result)

    @pytest.mark.parametrize("failure", ["server_error", "transport"])
    def test_failed_baseline(self, env, failure: str) -> None:
        def handler(*_args) -> Reply:
            if failure == "transport":
                raise ConnectionResetError("connection reset by peer")
            return 503, {}, "maintenance"

        env.origin.handlers["/go"] = handler
        result = probe(env, "open_redirect", GO)
        assert result["vulnerable"] is None and "baseline request failed" in result["summary"]
        assert len(env.origin.seen) == 1

    def test_payload_without_an_answer_is_cannot_tell(self, env) -> None:
        def handler(_path, query, _headers) -> Reply:
            if query.get("to", "").startswith("/home"):
                return redirect("/home")
            raise TimeoutError("timed out")

        env.origin.handlers["/go"] = handler
        result = probe(env, "open_redirect", GO)
        assert result["vulnerable"] is None and "got no answer" in result["summary"]
        check_evidence(env, result)

    def test_path_parameter(self, env) -> None:
        def handler(path, _query, _headers) -> Reply:
            return redirect(unquote(path.removeprefix("/out/")))

        env.origin.handlers["/out/"] = handler
        params = {
            "url": f"{BASE}/out/{{dest}}",
            "parameter": "dest",
            "location": "path",
            "value": "/home",
        }
        result = probe(env, "open_redirect", params)
        assert result["vulnerable"] is True, result
        host = result["details"]["random_host"]
        assert env.origin.seen[1][1] == f"{BASE}/out/" + quote(f"https://{host}/", safe="")

    def test_out_of_scope_is_refused_and_nothing_is_sent(self, env) -> None:
        result = probe(env, "open_redirect", {**GO, "url": "https://other.test/go?to=/"})
        assert result["vulnerable"] is None
        assert result["details"]["refusal"]["code"] == "OUT_OF_SCOPE"
        assert env.origin.seen == []


@pytest.mark.parametrize(
    ("target", "host"),
    [
        ("/home", "app.acme.test"),
        ("home?x=https://evil.example/", "app.acme.test"),
        ("https://evil.example/", "evil.example"),
        ("HTTPS://Evil.Example:8443/x", "evil.example"),
        ("//evil.example/", "evil.example"),
        ("///evil.example/", "evil.example"),
        ("/\\evil.example/", "evil.example"),
        (" \thttps://evil.example", "evil.example"),
        ("https://trusted.test@evil.example/", "evil.example"),
        ("https://evil.example/#https://trusted.test", "evil.example"),
        ("https://evil.example/@trusted.test", "evil.example"),
        ("http:evil.example/", "evil.example"),  # another scheme than the page: a host
        ("https:evil.example/", "app.acme.test"),  # the page's own scheme: a relative path
        ("javascript:alert(1)", None),
    ],
)
def test_browser_host(target: str, host: str | None) -> None:
    assert browser_host(target, f"{BASE}/go") == host


# ── path traversal ───────────────────────────────────────────────────


def read(fs: dict[str, str], root: str, name: str) -> Reply:
    """Join like ``os.path.join`` + ``open`` would: ``..`` climbs, and stops at ``/``."""
    content = fs.get(posixpath.normpath(posixpath.join(root, name)))
    return (200, {"Content-Type": "text/plain"}, content) if content else (404, {}, "no such file")


def download_joined(_path, query, _headers) -> Reply:
    return read(POSIX_FS, "/srv/app/files", query.get("file", ""))


def download_decodes_twice(_path, query, _headers) -> Reply:
    name = query.get("file", "")
    if ".." in name:
        return 400, {}, "invalid file name"
    return read(POSIX_FS, "/srv/app/files", unquote(name))


def download_extension_check(_path, query, _headers) -> Reply:
    name = query.get("file", "")
    if not name.endswith(".txt"):
        return 400, {}, "only .txt files"
    return read(POSIX_FS, "/srv/app/files", name.split("\x00")[0])  # a C string ends at NUL


def download_basename(_path, query, _headers) -> Reply:
    return read(POSIX_FS, "/srv/app/files", posixpath.basename(query.get("file", "")))


def download_windows(_path, query, _headers) -> Reply:
    return read(WINDOWS_FS, "/inetpub/files", query.get("file", ""))


DOWNLOAD = {"url": f"{BASE}/download?file=report.txt", "parameter": "file"}


class TestPathTraversal:
    def test_joined_path_is_found_and_the_depth_reported(self, env) -> None:
        env.origin.handlers["/download"] = download_joined
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["status"] == "completed" and result["vulnerable"] is True, result
        assert (result["class"], result["cwe"]) == ("file_handling", "CWE-22")
        details = result["details"]
        # /srv/app/files is three levels deep: two ../ are not enough, four are.
        assert list(details["captures"]) == ["baseline", "passwd_d2_plain", "passwd_d4_plain"]
        assert sent(env, "file") == ["report.txt", "../../etc/passwd", "../../../../etc/passwd"]
        assert details["technique"] == "plain" and details["depth"] == 4
        assert details["file"] == "etc/passwd"
        assert details["baseline"]["markers_present"] == []
        assert "root:x:0:0:" in body_of(env, result, "passwd_d4_plain")
        assert "root:x:0:0:" not in body_of(env, result, "baseline")
        check_evidence(env, result)

    def test_second_decode_is_found_by_the_encoded_form(self, env) -> None:
        env.origin.handlers["/download"] = download_decodes_twice
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "encoded"
        assert list(details["captures"])[-1] == "passwd_d6_encoded"
        assert sent(env, "file")[-1] == "%2e%2e%2f" * 6 + "etc%2fpasswd"
        check_evidence(env, result)

    def test_extension_check_is_found_by_the_null_byte_form(self, env) -> None:
        env.origin.handlers["/download"] = download_extension_check
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "plain_null_byte" and details["extension"] == ".txt"
        assert list(details["captures"])[-1] == "passwd_d6_plain_null"
        assert sent(env, "file")[-1] == "../../../../../../etc/passwd\x00.txt"
        check_evidence(env, result)

    def test_windows_marker_is_found(self, env) -> None:
        env.origin.handlers["/download"] = download_windows
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["file"] == "windows/win.ini" and details["technique"] == "plain"
        assert list(details["captures"])[-1] == "win_ini_d6_plain"
        check_evidence(env, result)

    def test_traversal_removed_by_normalisation_is_not_flagged(self, env) -> None:
        env.origin.handlers["/download"] = download_basename
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["vulnerable"] is False, result
        details = result["details"]
        assert details["requests_sent"] == TRAVERSAL_MAX_REQUESTS == 1 + len(TRAVERSAL_PAYLOADS)
        assert all(t["marker"] is False for t in details["tried"])
        check_evidence(env, result)

    def test_page_that_always_contains_the_passwd_marker_is_not_flagged(self, env) -> None:
        def handler(_path, query, _headers) -> Reply:
            # A help page that prints an example passwd line, whatever the file.
            return 200, {}, f"<pre>Example: root:x:0:0:root:/root</pre><p>{query.get('file')}</p>"

        env.origin.handlers["/download"] = handler
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["vulnerable"] is False, result
        details = result["details"]
        assert details["baseline"]["markers_present"] == ["passwd"]
        # The passwd payloads cannot prove anything here, so only win.ini was asked for.
        assert [t["file"] for t in details["tried"]] == ["windows/win.ini"] * 3
        assert len(details["skipped"]) == 6
        assert "already contains" in result["summary"]
        check_evidence(env, result)

    def test_value_without_an_extension_skips_the_null_byte_forms(self, env) -> None:
        env.origin.handlers["/download"] = download_basename
        params = {**DOWNLOAD, "url": f"{BASE}/download?file=readme"}
        result = probe(env, "path_traversal", params)
        assert result["vulnerable"] is False, result
        assert result["details"]["extension"] is None
        assert not any(role.endswith("_null") for role in result["details"]["captures"])
        assert result["details"]["requests_sent"] == 7

    def test_path_segment_is_found_by_the_encoded_form_past_url_normalisation(self, env) -> None:
        def handler(path, _query, _headers) -> Reply:
            # The HTTP layer resolves dot segments of the raw path first, then the app decodes.
            path = posixpath.normpath(path)
            if not path.startswith("/files/"):
                return 404, {}, "no route"
            return read(POSIX_FS, "/srv/app/files", unquote(path.removeprefix("/files/")))

        env.origin.handlers["/"] = handler
        params = {
            "url": f"{BASE}/files/{{name}}",
            "parameter": "name",
            "location": "path",
            "value": "report.txt",
        }
        result = probe(env, "path_traversal", params)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "encoded"
        assert env.origin.seen[1][1] == f"{BASE}/files/../../etc/passwd"
        assert env.origin.seen[-1][1] == f"{BASE}/files/" + "%2e%2e%2f" * 6 + "etc%2fpasswd"
        check_evidence(env, result)

    def test_json_parameter(self, env) -> None:
        def handler(*_args) -> Reply:
            body = json.loads(env.origin.seen[-1][3])
            return read(POSIX_FS, "/srv/app/files", body["doc"]["name"])

        env.origin.handlers["/export"] = handler
        params = {
            "url": f"{BASE}/export",
            "method": "POST",
            "location": "json",
            "parameter": "doc.name",
            "body": {"doc": {"name": "report.txt"}},
        }
        result = probe(env, "path_traversal", params)
        assert result["vulnerable"] is True and result["details"]["depth"] == 4, result

    @pytest.mark.parametrize("failure", ["server_error", "transport"])
    def test_failed_baseline(self, env, failure: str) -> None:
        def handler(*_args) -> Reply:
            if failure == "transport":
                raise ConnectionResetError("connection reset by peer")
            return 500, {}, "boom"

        env.origin.handlers["/download"] = handler
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["vulnerable"] is None and "baseline request failed" in result["summary"]
        assert len(env.origin.seen) == 1

    def test_payload_without_an_answer_is_cannot_tell(self, env) -> None:
        def handler(_path, query, _headers) -> Reply:
            if "passwd" in query.get("file", ""):
                raise TimeoutError("timed out")
            return download_basename(_path, query, _headers)

        env.origin.handlers["/download"] = handler
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["vulnerable"] is None and "got no answer" in result["summary"]
        check_evidence(env, result)

    def test_request_bound_is_enforced_by_the_sender(self, env, monkeypatch) -> None:
        env.origin.handlers["/download"] = download_basename
        monkeypatch.setattr(misc, "TRAVERSAL_MAX_REQUESTS", 3)
        result = probe(env, "path_traversal", DOWNLOAD)
        assert result["vulnerable"] is None and "request bound (3)" in result["summary"]
        assert len(env.origin.seen) == 3


# ── CORS ─────────────────────────────────────────────────────────────


def cors_handler(policy: Callable[[str | None], dict[str, str]]) -> Handler:
    def handler(_path, _query, headers) -> Reply:
        return 200, {"Content-Type": "application/json", **policy(headers.get("origin"))}, "{}"

    return handler


def reflect(credentials: bool) -> Callable[[str | None], dict[str, str]]:
    def policy(origin: str | None) -> dict[str, str]:
        if origin is None:
            return {}
        reply = {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
        if credentials:
            reply["Access-Control-Allow-Credentials"] = "true"
        return reply

    return policy


ACCOUNT = {"url": f"{BASE}/api/account"}


class TestCors:
    def test_reflected_origin_with_credentials_is_found(self, env) -> None:
        env.origin.handlers["/api/account"] = cors_handler(reflect(credentials=True))
        result = probe(env, "cors", {**ACCOUNT, "headers": {"Authorization": "Bearer t0ken"}})
        assert result["status"] == "completed" and result["vulnerable"] is True, result
        assert (result["class"], result["cwe"]) == ("misconfiguration", "CWE-942")
        details = result["details"]
        origin = details["random_origin"]
        assert re.fullmatch(r"https://bg[0-9a-f]{12}\.example", origin)
        assert details["technique"] == "reflected_origin"
        assert list(details["captures"]) == ["baseline", "origin_random", "origin_null"]
        assert [h.get("origin") for _m, _u, h, _b in env.origin.seen] == [None, origin, "null"]
        assert all(h["authorization"] == "Bearer t0ken" for _m, _u, h, _b in env.origin.seen)
        assert all(m == "GET" for m, _u, _h, _b in env.origin.seen)
        assert details["responses"]["origin_random"]["allow_credentials"] == "true"
        check_evidence(env, result)

    def test_reflected_origin_without_credentials_is_informational(self, env) -> None:
        env.origin.handlers["/api/account"] = cors_handler(reflect(credentials=False))
        result = probe(env, "cors", ACCOUNT)
        assert result["vulnerable"] is False, result
        assert "reflected-origin-without-credentials" in result["details"]["informational"]
        check_evidence(env, result)

    def test_null_origin_with_credentials_is_found(self, env) -> None:
        def policy(origin: str | None) -> dict[str, str]:
            if origin == "null":
                return {"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"}  # fmt: skip
            return {}

        env.origin.handlers["/api/account"] = cors_handler(policy)
        result = probe(env, "cors", ACCOUNT)
        assert result["vulnerable"] is True and result["details"]["technique"] == "null_origin"

    def test_wildcard_is_informational_not_a_finding(self, env) -> None:
        env.origin.handlers["/api/account"] = cors_handler(
            lambda _o: {"Access-Control-Allow-Origin": "*"}
        )
        result = probe(env, "cors", ACCOUNT)
        assert result["vulnerable"] is False, result
        assert result["details"]["informational"] == ["wildcard-without-credentials"]
        assert "wildcard-without-credentials" in result["summary"]

    def test_fixed_allowlist_with_credentials_is_not_flagged(self, env) -> None:
        env.origin.handlers["/api/account"] = cors_handler(
            lambda _o: {
                "Access-Control-Allow-Origin": "https://app.acme.test",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        result = probe(env, "cors", ACCOUNT)
        assert result["vulnerable"] is False and result["details"]["informational"] == []

    def test_no_cors_headers_is_not_flagged(self, env) -> None:
        env.origin.handlers["/api/account"] = cors_handler(lambda _o: {})
        result = probe(env, "cors", ACCOUNT)
        assert result["vulnerable"] is False, result
        check_evidence(env, result)

    def test_origin_given_by_the_caller_is_replaced(self, env) -> None:
        env.origin.handlers["/api/account"] = cors_handler(lambda _o: {})
        probe(env, "cors", {**ACCOUNT, "headers": {"origin": "https://app.acme.test"}})
        assert env.origin.seen[0][2].get("origin") is None
        assert env.origin.seen[2][2]["origin"] == "null"

    def test_failed_baseline(self, env) -> None:
        env.origin.handlers["/api/account"] = lambda *_a: (502, {}, "bad gateway")
        result = probe(env, "cors", ACCOUNT)
        assert result["vulnerable"] is None and "baseline request failed" in result["summary"]
        assert len(env.origin.seen) == 1


# ── registry and payload hygiene ─────────────────────────────────────


class TestContract:
    def test_registered_after_the_earlier_probes(self) -> None:
        names = list(REGISTRY)
        assert names[:10] == [
            "jwt_alg_none", "idor", "ssrf_canary", "numeric_boundary", "mass_assignment",
            "graphql_checks", "sqli", "xss_reflected", "ssti", "command_injection",
        ]  # fmt: skip
        assert names[10:13] == ["open_redirect", "path_traversal", "cors"]
        expected = {
            "open_redirect": ("open_redirect", "CWE-601", misc.open_redirect),
            "path_traversal": ("file_handling", "CWE-22", misc.path_traversal),
            "cors": ("misconfiguration", "CWE-942", misc.cors),
        }
        for name, (vuln_class, cwe, run) in expected.items():
            spec = REGISTRY[name]
            assert (spec.vuln_class, spec.cwe, spec.run, spec.state_changing) == (
                vuln_class, cwe, run, False,
            )  # fmt: skip
        described = {d["probe"]: d for d in describe()}
        common = {"url", "method", "parameter", "location", "value", "body", "headers"}
        assert set(described["open_redirect"]["params"]) == common | {"allowlist_hint"}
        assert set(described["path_traversal"]["params"]) == common
        assert set(described["cors"]["params"]) == {"url", "headers"}

    @pytest.mark.parametrize("name", ["open_redirect", "path_traversal"])
    @pytest.mark.parametrize(
        "params",
        [
            {"url": f"{BASE}/go"},  # no parameter
            {"parameter": "to"},  # no url
            {"url": f"{BASE}/go", "parameter": "to"},  # no baseline value anywhere
            {"url": f"{BASE}/go?to=a", "parameter": "to", "location": "cookie"},
            {"url": f"{BASE}/go/x", "parameter": "to", "location": "path", "value": "a"},
            {"url": f"{BASE}/go/{{to}}", "parameter": "to", "location": "path"},
        ],
    )
    def test_bad_input_is_an_error_and_sends_nothing(self, env, name: str, params: dict) -> None:
        result = probe(env, name, params)
        assert result["status"] == "error", result
        assert env.origin.seen == []

    def test_cors_needs_a_url(self, env) -> None:
        assert probe(env, "cors", {})["status"] == "error"

    def test_bounds(self) -> None:
        assert REDIRECT_MAX_REQUESTS == 2 + len(REDIRECT_BYPASSES) == 6
        assert len(REDIRECT_BYPASSES) == 4
        assert TRAVERSAL_MAX_REQUESTS == 1 + len(TRAVERSAL_PAYLOADS) == 10
        assert CORS_MAX_REQUESTS == 3

    def test_traversal_payloads_only_name_the_two_marker_files(self) -> None:
        assert {path for path, _regex in MARKER_FILES.values()} == {"etc/passwd", "windows/win.ini"}
        depths = {depth for _f, depth, _e, _n in TRAVERSAL_PAYLOADS}
        assert depths <= set(range(2, 7)) and {2, 6} <= depths
        assert {e for _f, _d, e, _n in TRAVERSAL_PAYLOADS} == {"plain", "encoded"}
        assert {n for _f, _d, _e, n in TRAVERSAL_PAYLOADS} == {True, False}
        for file, depth, encoding, null_byte in TRAVERSAL_PAYLOADS:
            for wire in (True, False):
                value = traversal_payload(
                    file, depth, encoding, ".txt" if null_byte else "", wire=wire
                )
                rest = unquote(value).replace("\x00", "")
                assert rest.count("../") == depth
                assert rest.replace("../", "") in {"etc/passwd", "windows/win.ini",
                                                   "etc/passwd.txt", "windows/win.ini.txt"}  # fmt: skip
