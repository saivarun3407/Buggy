"""Evidence export: HAR, curl and the self-checking bundle built from stored captures."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import subprocess
import threading
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from buggy.capture.export import (
    CAPTURES_FILE,
    HAR_FILE,
    LEDGER_FILE,
    MANIFEST_FILE,
    SCRIPT_FILE,
    ExportRefused,
    bundle,
    to_curl,
    to_har,
    verify_bundle,
)
from buggy.capture.gateway import INTERNAL_LOGIN, CaptureGateway, GatewayRefusal, Roots
from buggy.capture.mcp_server import CaptureTools

BASE = "https://app.acme.test"
LOGIN_URL = f"{BASE}/rest/user/login"
ORDER_URL = f"{BASE}/api/orders/7"
ECHO_URL = f"{BASE}/debug/echo"
BLOB_URL = f"{BASE}/debug/blob"
UPLOAD_URL = f"{BASE}/api/upload?kind=avatar&tag=a%20b&empty="
SESSION_URL = f"{BASE}/api/session"

# Fixture secrets, built at runtime and shaped like nothing a provider issues.
ALICE_PASSWORD = "pw-of-alice-" + "correct-horse-battery"
ALICE_TOKEN = "session-of-alice-" + "0123456789abcdef"
BOB_TOKEN = "static-of-bob-" + "fedcba9876543210"
CALLER_BEARER = "callers-own-bearer-" + "1122334455667788"
CALLER_COOKIE = "callers-own-cookie-" + "8877665544332211"
CALLER_API_KEY = "callers-own-apikey-" + "a1b2c3d4e5f60718"
ISSUED_COOKIE = "issued-by-target-" + "0f1e2d3c4b5a6978"
SECRETS = (
    ALICE_PASSWORD,
    ALICE_TOKEN,
    BOB_TOKEN,
    CALLER_BEARER,
    CALLER_COOKIE,
    CALLER_API_KEY,
    ISSUED_COOKIE,
)

BINARY = b"\x89PNG\r\n\x1a\n\x00\xff\xfe" + bytes(range(256))


class _Pairs(list):
    """Response headers that can repeat a name, with the ``items()`` the gateway reads."""

    def items(self):
        return list(self)


class Origin:
    """``test_gateway.Site`` with response headers: routes give ``(status, headers, body)``."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], object] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data or b""
        self.seen.append((method, url, headers, body))
        route = self.routes.get((method, url), (404, [], b"not found"))
        status, response_headers, payload = route(headers, body) if callable(route) else route
        response_headers = _Pairs(response_headers)
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
            response_headers.append(("Content-Type", "application/json"))
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", response_headers, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, response_headers
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


def _roe(*hosts: str) -> dict:
    return {
        "machine_enforcement": {"mode": "enforce", "in_scope": list(hosts) or ["app.acme.test"]},
        "approvals": {"state_changing": "not_required"},
    }


def _identities() -> dict:
    return {
        "identities": [
            {
                "name": "alice",
                "role": "user",
                "login": {
                    "request": {
                        "method": "POST",
                        "url": LOGIN_URL,
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"email": "alice@acme.test", "password": "{password}"}',
                    },
                    "credentials": {"password": ALICE_PASSWORD},
                    "extract": [{"name": "token", "from": "json", "path": "authentication.token"}],
                    "apply": {
                        "headers": {
                            "Authorization": "Bearer {token}",
                            "X-Session-Token": "{token}",
                        },
                        "cookies": {"sid": "{token}"},
                    },
                    "success": {"status": 200},
                },
            },
            {"name": "bob", "role": "admin", "static": {"headers": {"X-Api-Token": BOB_TOKEN}}},
        ]
    }


@pytest.fixture
def env(tmp_path: Path):
    """A gateway in front of a fake origin, with two engagements and declared identities."""
    roots = Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )
    for engagement in ("acme", "other"):
        (roots.control / engagement).mkdir(parents=True)
        (roots.control / engagement / "roe.json").write_text(json.dumps(_roe()))
    (roots.secrets / "acme").mkdir(parents=True)
    (roots.secrets / "acme" / "identities.json").write_text(json.dumps(_identities()))
    site = Origin()

    def login(_headers, body):
        if json.loads(body) != {"email": "alice@acme.test", "password": ALICE_PASSWORD}:
            return 401, [], {"error": "Invalid email or password."}
        return 200, [], {"authentication": {"token": ALICE_TOKEN}}

    def echo(headers, _body):
        return 200, [], {"authorization": headers.get("authorization"), "kept": "order 7"}

    def blob(headers, _body):
        token = headers.get("x-session-token", "nobody")
        return 200, [("Content-Type", "application/octet-stream")], b"\xff\xfe" + token.encode()

    site.routes[("POST", LOGIN_URL)] = login
    site.routes[("GET", ORDER_URL)] = (200, [], {"id": 7, "owner": "alice"})
    site.routes[("GET", ECHO_URL)] = echo
    site.routes[("GET", BLOB_URL)] = blob
    site.routes[("POST", UPLOAD_URL)] = (201, [("Content-Type", "image/png")], BINARY)
    site.routes[("GET", SESSION_URL)] = (
        200,
        [
            ("Set-Cookie", f"sid={ISSUED_COOKIE}; Path=/; HttpOnly"),
            ("Set-Cookie", "theme=dark; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
            ("Content-Type", "text/plain"),
        ],
        b"signed in",
    )
    site.routes[("GET", f"{BASE}/go")] = (302, [("Location", f"{BASE}/landing")], b"")
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    yield gateway, site, roots
    gateway.store.close()


def _upload(gateway, engagement: str = "acme"):
    return gateway.send(
        engagement,
        "POST",
        UPLOAD_URL,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {CALLER_BEARER}"},
        body=json.dumps({"name": 'a "quoted" name', "lines": "one\ntwo", "price": "$5"}),
        note="upload as the caller",
    )


def _mixed_captures(gateway) -> dict[str, object]:
    """One capture of every kind the redaction mechanism treats differently."""
    out = {
        "alice_order": gateway.send("acme", "GET", ORDER_URL, identity="alice", note="alice reads"),
        "alice_echo": gateway.send("acme", "GET", ECHO_URL, identity="alice", note="echoed token"),
        "alice_blob": gateway.send("acme", "GET", BLOB_URL, identity="alice", note="binary echo"),
        "bob_order": gateway.send("acme", "GET", ORDER_URL, identity="bob", note="bob reads"),
        "caller": gateway.send(
            "acme",
            "GET",
            ORDER_URL,
            headers={
                "Authorization": f"Bearer {CALLER_BEARER}",
                "Cookie": f"session={CALLER_COOKIE}; theme=dark",
                "X-Api-Key": CALLER_API_KEY,
                "X-Session-Token": "a-value-the-caller-chose",
                "X-Trace": "kept-1",
            },
            note="caller's own credentials",
        ),
        "session": gateway.send("acme", "GET", SESSION_URL, note="target sets cookies"),
        "upload": _upload(gateway),
    }
    (out["login"],) = gateway.store.list("acme", probe="login")
    return out


# ── HAR ─────────────────────────────────────────────────────────────

_HAR_REQUIRED = {
    "log": ("version", "creator", "entries"),
    "creator": ("name", "version"),
    "entry": ("startedDateTime", "time", "request", "response", "cache", "timings"),
    "request": (
        "method",
        "url",
        "httpVersion",
        "cookies",
        "headers",
        "queryString",
        "headersSize",
        "bodySize",
    ),
    "postData": ("mimeType", "text"),
    "response": (
        "status",
        "statusText",
        "httpVersion",
        "cookies",
        "headers",
        "content",
        "redirectURL",
        "headersSize",
        "bodySize",
    ),
    "content": ("size", "mimeType"),
    "timings": ("send", "wait", "receive"),
}


def _har_problems(har: dict) -> list[str]:
    """What a HAR 1.2 reader would reject: missing required keys and wrong types."""
    problems: list[str] = []

    def need(obj, kind: str, where: str) -> bool:
        if not isinstance(obj, dict):
            problems.append(f"{where}: not an object")
            return False
        missing = [key for key in _HAR_REQUIRED[kind] if key not in obj]
        problems.extend(f"{where}: missing {key}" for key in missing)
        return not missing

    def pairs(items, where: str) -> None:
        if not isinstance(items, list):
            problems.append(f"{where}: not a list")
            return
        for item in items:
            if not (
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and isinstance(item.get("value"), str)
            ):
                problems.append(f"{where}: entry without a string name and value")

    if not need(har.get("log"), "log", "log"):
        return problems
    log = har["log"]
    if log["version"] != "1.2":
        problems.append("log.version: not 1.2")
    need(log["creator"], "creator", "log.creator")
    if not isinstance(log["entries"], list):
        return [*problems, "log.entries: not a list"]
    for index, entry in enumerate(log["entries"]):
        where = f"entries[{index}]"
        if not need(entry, "entry", where):
            continue
        try:
            if datetime.fromisoformat(entry["startedDateTime"]).tzinfo is None:
                problems.append(f"{where}.startedDateTime: no time zone")
        except (TypeError, ValueError):
            problems.append(f"{where}.startedDateTime: not ISO 8601")
        if not isinstance(entry["time"], (int, float)) or entry["time"] < 0:
            problems.append(f"{where}.time: not a non-negative number")
        need(entry["timings"], "timings", f"{where}.timings")
        if need(entry["request"], "request", f"{where}.request"):
            request = entry["request"]
            for key in ("headers", "cookies", "queryString"):
                pairs(request[key], f"{where}.request.{key}")
            if "postData" in request:
                need(request["postData"], "postData", f"{where}.request.postData")
        if need(entry["response"], "response", f"{where}.response"):
            response = entry["response"]
            if not isinstance(response["status"], int):
                problems.append(f"{where}.response.status: not an integer")
            for key in ("headers", "cookies"):
                pairs(response[key], f"{where}.response.{key}")
            need(response["content"], "content", f"{where}.response.content")
    return problems


def _har_header(section: dict, name: str) -> list[str]:
    return [h["value"] for h in section["headers"] if h["name"].lower() == name.lower()]


class TestHar:
    def test_har_has_every_key_har_1_2_requires(self, env) -> None:
        gateway, _site, _roots = env
        captures = list(_mixed_captures(gateway).values())
        captures.append(gateway.send("acme", "GET", f"{BASE}/go", note="a redirect"))
        captures.append(gateway.send("acme", "GET", f"{BASE}/missing"))
        for redact in (True, False):
            har = json.loads(json.dumps(to_har(captures, redact=redact)))  # it is plain JSON
            assert _har_problems(har) == []
            assert [e["_capture_id"] for e in har["log"]["entries"]] == [c.id for c in captures]
            assert har["log"]["creator"]["name"] == "buggy"

        # The control: the checker above does reject a document with a required key gone.
        for path in (
            ("log", "version"),
            ("log", "entries", 0, "startedDateTime"),
            ("log", "entries", 0, "request", "queryString"),
            ("log", "entries", 0, "response", "content", "mimeType"),
            ("log", "entries", -1, "response", "status"),
        ):
            broken = copy.deepcopy(har)
            parent = broken
            for step in path[:-1]:
                parent = parent[step]
            del parent[path[-1]]
            assert _har_problems(broken), path

    @pytest.mark.parametrize("redact", [True, False])
    def test_post_with_json_body_and_binary_response_round_trips(self, env, redact: bool) -> None:
        gateway, _site, _roots = env
        capture = _upload(gateway)
        text = gateway.send("acme", "GET", ORDER_URL)
        first, second = json.loads(json.dumps(to_har([capture, text], redact=redact)))["log"][
            "entries"
        ]

        request = first["request"]
        assert (request["method"], request["url"]) == ("POST", UPLOAD_URL)
        assert request["postData"]["mimeType"] == "application/json"
        assert "encoding" not in request["postData"]
        assert json.loads(request["postData"]["text"]) == {
            "name": 'a "quoted" name',
            "lines": "one\ntwo",
            "price": "$5",
        }
        assert request["postData"]["text"].encode() == capture.request_body
        assert request["bodySize"] == len(capture.request_body)
        assert request["queryString"] == [
            {"name": "kind", "value": "avatar"},
            {"name": "tag", "value": "a b"},
            {"name": "empty", "value": ""},
        ]

        response = first["response"]
        assert response["status"] == 201 and response["content"]["mimeType"] == "image/png"
        assert response["content"]["encoding"] == "base64"
        recovered = base64.b64decode(response["content"]["text"], validate=True)
        assert recovered == BINARY and response["content"]["size"] == len(BINARY)
        assert hashlib.sha256(recovered).hexdigest() == first["_response_sha256"]
        assert first["_response_sha256"] == capture.response_sha256
        assert first["comment"] == "upload as the caller"

        # A text response is carried as text, not base64.
        assert "encoding" not in second["response"]["content"]
        assert json.loads(second["response"]["content"]["text"]) == {"id": 7, "owner": "alice"}
        assert "postData" not in second["request"]

        # The one difference between the two modes is the credential.
        shown = _har_header(request, "Authorization")
        assert shown == (["<redacted>"] if redact else [f"Bearer {CALLER_BEARER}"])

    def test_cookies_and_repeated_set_cookie_headers(self, env) -> None:
        gateway, _site, _roots = env
        captures = _mixed_captures(gateway)
        plain = to_har([captures["caller"], captures["session"]], redact=False)["log"]["entries"]
        assert plain[0]["request"]["cookies"] == [
            {"name": "session", "value": CALLER_COOKIE},
            {"name": "theme", "value": "dark"},
        ]
        assert plain[1]["response"]["cookies"] == [
            {"name": "sid", "value": ISSUED_COOKIE},
            {"name": "theme", "value": "dark"},
        ]
        assert _har_header(plain[1]["response"], "Set-Cookie") == [
            f"sid={ISSUED_COOKIE}; Path=/; HttpOnly",
            "theme=dark; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
        ]
        redirect = gateway.send("acme", "GET", f"{BASE}/go")
        assert to_har([redirect])["log"]["entries"][0]["response"]["redirectURL"] == (
            f"{BASE}/landing"
        )

        hidden = to_har([captures["caller"], captures["session"]], redact=True)["log"]["entries"]
        assert _har_header(hidden[0]["request"], "Cookie") == ["<redacted>"]
        assert _har_header(hidden[1]["response"], "Set-Cookie") == ["<redacted>"]
        assert hidden[0]["request"]["cookies"] == [] and hidden[1]["response"]["cookies"] == []
        assert hidden[1]["response"]["content"]["text"] == "signed in"  # the body is kept

    def test_redacted_har_shows_exactly_what_the_agent_view_shows(self, env) -> None:
        gateway, _site, _roots = env
        tools = CaptureTools(gateway, None, "acme")
        captures = _mixed_captures(gateway)
        entries = to_har(list(captures.values()), redact=True)["log"]["entries"]
        for (name, capture), entry in zip(captures.items(), entries, strict=True):
            view = tools.http_capture("acme", capture.id, 40000)
            request_headers = {h["name"]: h["value"] for h in entry["request"]["headers"]}
            assert request_headers == view["request_headers"], name
            for header, value in view["response_headers"].items():
                assert "\n".join(_har_header(entry["response"], header)) == value, name
            content = entry["response"]["content"]
            if content.get("encoding") != "base64":
                assert content["text"] == view["response_body"], name
            if capture.request_body:
                assert entry["request"]["postData"]["text"] == view["request_body"], name

        by_name = dict(zip(captures, entries, strict=True))
        # The login exchange keeps its outcome and loses both bodies.
        login = by_name["login"]
        assert captures["login"].approval_id == INTERNAL_LOGIN
        assert login["response"]["status"] == 200 and login["_probe"] == "login"
        assert login["request"]["postData"]["text"] == "<redacted>"
        assert login["response"]["content"]["text"] == "<redacted>"
        # A token the target echoed is scrubbed; the rest of that body is evidence and stays.
        assert json.loads(by_name["alice_echo"]["response"]["content"]["text"]) == {
            "authorization": "<redacted>",
            "kept": "order 7",
        }
        # A binary body is exported byte for byte only when redaction left it alone.
        blob = by_name["alice_blob"]["response"]["content"]
        assert "encoding" not in blob and "<redacted>" in blob["text"]
        anonymous = gateway.send("acme", "GET", BLOB_URL)
        untouched = to_har([anonymous])["log"]["entries"][0]["response"]["content"]
        assert base64.b64decode(untouched["text"]) == b"\xff\xfenobody"
        # Session headers are hidden per capture: the same header name on a request the
        # caller wrote itself is the caller's own value and is shown.
        assert _har_header(by_name["alice_order"]["request"], "X-Session-Token") == ["<redacted>"]
        assert _har_header(by_name["caller"]["request"], "X-Session-Token") == [
            "a-value-the-caller-chose"
        ]
        assert _har_header(by_name["caller"]["request"], "X-Trace") == ["kept-1"]


# ── curl, executed for real ─────────────────────────────────────────


@dataclass(frozen=True)
class Received:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class _Recorder(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {name.lower(): value for name, value in self.headers.items()}
        self.server.received.append(Received(self.command, self.path, headers, body))
        payload = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _handle

    def log_message(self, *_args) -> None:
        pass


_PROXY_VARIABLES = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")


@pytest.fixture
def local(tmp_path: Path, monkeypatch):
    """A real HTTP server on 127.0.0.1 and a gateway that really sends to it."""
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    server.received = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(json.dumps(_roe("127.0.0.1")))
    gateway = CaptureGateway(roots, sleep=lambda _s: None)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield gateway, server.received, base, roots
    gateway.store.close()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _run_shell(script: str, cwd: Path, *arguments: str) -> subprocess.CompletedProcess:
    """Run ``script`` with ``sh`` and no proxy: the commands under test go to 127.0.0.1."""
    environment = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    environment.update(NO_PROXY="127.0.0.1", no_proxy="127.0.0.1", CURL_HOME=str(cwd))
    return subprocess.run(  # noqa: S603
        ["sh", *arguments, script],  # noqa: S607
        cwd=cwd,
        env=environment,
        capture_output=True,
        timeout=60,
        check=False,
    )


# urllib announces these on every request; they describe its connection, not the request.
_URLLIB_ONLY = ("accept-encoding", "connection")


def _comparable(received: Received) -> tuple[str, str, dict[str, str], bytes]:
    headers = {k: v for k, v in received.headers.items() if k not in _URLLIB_ONLY}
    return received.method, received.path, headers, received.body


TRICKY_BODY = (
    '{"single": "it\'s", "double": "say \\"hi\\"", "dollar": "$HOME ${PATH} $(id) `id`",\n'
    ' "backslash": "C:\\\\dir\\n", "bang": "!!", "percent": "100%", "unicode": "caf\u00e9 \u6f22"}\n'
    "\n  trailing lines, a tab\t and a final newline\n"
)

CURL_CASES = {
    "json body with quotes, newlines and dollars": (
        "POST",
        "/api/orders?note=a%20b&x=1",
        {"Content-Type": "application/json", "X-Quote": 'it\'s "here" $HOME `id`; a=b'},
        TRICKY_BODY.encode(),
    ),
    "body that starts like a file reference": ("PUT", "/api/file", {}, b"@/etc/hostname"),
    "body that looks like options": ("PATCH", "/api/x", {}, b"--header 'X-Injected: 1' -d @x"),
    "binary body with NUL and every byte": (
        "POST",
        "/api/blob",
        {"Content-Type": "application/octet-stream"},
        bytes(range(256)) + b"\n\n",
    ),
    "url that curl would glob or normalise": (
        "GET",
        "/a/../b/./c?ids[]=1&ids[]=2&set={x,y}&range=[1-3]&q=%24HOME",
        {"Accept": "application/json", "X-Empty": ""},
        b"",
    ),
    "delete without a body": ("DELETE", "/api/orders/7", {"Authorization": "Bearer t0ken"}, b""),
    "post without a body": ("POST", "/api/ping", {}, b""),
    "get with a body": ("GET", "/api/search", {"Content-Type": "text/plain"}, b"needle $1"),
    "head": ("HEAD", "/api/orders/7", {"User-Agent": "probe/1 (it's a test)"}, b""),
    "options": ("OPTIONS", "/api/orders", {"Origin": "https://evil.example"}, b""),
}


class TestCurlExecutes:
    @pytest.mark.parametrize("case", sorted(CURL_CASES))
    def test_curl_sends_what_the_gateway_sent(self, local, tmp_path: Path, case: str) -> None:
        gateway, received, base, _roots = local
        method, path, headers, body = CURL_CASES[case]
        capture = gateway.send("acme", method, base + path, headers=headers, body=body)
        assert capture.status == 200 and len(received) == 1

        outcome = _run_shell(to_curl(capture, redact=False), tmp_path, "-c")
        assert outcome.returncode == 0, outcome.stderr.decode()
        assert len(received) == 2
        original, repeated = received
        # What the server got from curl is what it got from the gateway ...
        assert _comparable(repeated) == _comparable(original)
        # ... and that is the request that was asked for.
        assert (repeated.method, repeated.path, repeated.body) == (method, path, body)
        for name, value in headers.items():
            assert repeated.headers[name.lower()] == value
        assert repeated.headers["host"] == base.removeprefix("http://")

    def test_the_comparison_notices_a_badly_quoted_command(self, local, tmp_path: Path) -> None:
        gateway, received, base, _roots = local
        body = "price=$HOME&note=it's `echo expanded`"
        capture = gateway.send("acme", "POST", f"{base}/cart", body=body)
        good = to_curl(capture, redact=False)
        quoted = "--data-binary 'price=$HOME&note=it'\"'\"'s `echo expanded`'"
        assert quoted in good
        # The same command with the body in double quotes, as a careless exporter would write.
        careless = good.replace(quoted, f'--data-binary "{body}"')
        assert _run_shell(careless, tmp_path, "-c").returncode == 0
        assert _run_shell(good, tmp_path, "-c").returncode == 0
        original, expanded, faithful = received
        assert expanded.body != original.body and b"$HOME" not in expanded.body
        assert _comparable(faithful) == _comparable(original)

    def test_redacted_command_runs_with_placeholders_instead_of_credentials(
        self, local, tmp_path: Path
    ) -> None:
        gateway, received, base, _roots = local
        capture = gateway.send(
            "acme",
            "POST",
            f"{base}/api/orders",
            headers={
                "Authorization": f"Bearer {CALLER_BEARER}",
                "X-Api-Key": CALLER_API_KEY,
                "Cookie": f"session={CALLER_COOKIE}",
                "X-Trace": "kept-1",
            },
            body='{"qty": 1}',
        )
        command = to_curl(capture)  # redaction is the default
        for secret in (CALLER_BEARER, CALLER_API_KEY, CALLER_COOKIE):
            assert secret not in command
        first_line = command.splitlines()[0]
        assert first_line.startswith("# Fill in before running:")
        assert set(first_line.split(":", 1)[1].split()) == {
            "<AUTHORIZATION>",
            "<X_API_KEY>",
            "<COOKIE>",
        }
        assert "--header 'Authorization: <AUTHORIZATION>'" in command
        assert "--max-redirs 0" in command and "--request POST" in command

        # It is still one valid command: the placeholders arrive as literal text.
        outcome = _run_shell(command, tmp_path, "-c")
        assert outcome.returncode == 0, outcome.stderr.decode()
        original, repeated = received
        assert repeated.headers["authorization"] == "<AUTHORIZATION>"
        assert repeated.headers["x-api-key"] == "<X_API_KEY>"
        assert repeated.headers["cookie"] == "<COOKIE>"
        assert repeated.headers["x-trace"] == "kept-1" and repeated.body == original.body
        assert list(tmp_path.glob("AUTHORIZATION*")) == []  # "<" and ">" redirected nothing

        # The control: the unredacted command does carry them.
        revealed = to_curl(capture, redact=False)
        assert "Fill in" not in revealed
        for secret in (CALLER_BEARER, CALLER_API_KEY, CALLER_COOKIE):
            assert secret in revealed

    def test_login_is_a_comment_not_a_command_when_redacted(self, env) -> None:
        gateway, _site, _roots = env
        captures = _mixed_captures(gateway)
        text = to_curl(captures["login"])
        lines = [line for line in text.splitlines() if line.strip()]
        assert lines and all(line.startswith("#") for line in lines)
        assert "gateway performs this login" in text and captures["login"].id in text
        assert ALICE_PASSWORD not in text and "password" not in text

        # The controls: any other capture is a command, and so is the login for the operator.
        assert "\ncurl " in "\n" + to_curl(captures["alice_order"])
        revealed = to_curl(captures["login"], redact=False)
        assert "\ncurl " in "\n" + revealed and ALICE_PASSWORD in revealed

    def test_identity_capture_asks_for_the_session_it_hides(self, env) -> None:
        gateway, _site, _roots = env
        captures = _mixed_captures(gateway)
        command = to_curl(captures["alice_order"])
        assert ALICE_TOKEN not in command and "identity 'alice'" in command
        for placeholder in ("<AUTHORIZATION>", "<X_SESSION_TOKEN>", "<COOKIE>"):
            assert placeholder in command.splitlines()[0]
        assert "<X_API_TOKEN>" in to_curl(captures["bob_order"])
        assert BOB_TOKEN not in to_curl(captures["bob_order"])

    def test_reproduce_script_runs_the_steps_in_order_and_notes_cannot_inject(
        self, local, tmp_path: Path
    ) -> None:
        gateway, received, base, roots = local
        marker = tmp_path / "injected"
        hostile_note = f"read the order\ntouch {marker}\n$(touch {marker}) `touch {marker}`"
        first = gateway.send("acme", "GET", f"{base}/api/orders/7", note=hostile_note)
        second = gateway.send(
            "acme", "POST", f"{base}/api/orders/7/refund", body=TRICKY_BODY, note="refund it"
        )
        third = gateway.send("acme", "DELETE", f"{base}/api/orders/7")
        files = bundle(
            gateway.store,
            "acme",
            [second.id, first.id, third.id],
            finding={
                "id": "F-0123456789ab",
                "title": f"IDOR\ntouch {marker}",
                "engagement": "acme",
            },
            ledger_path=roots.audit / "acme" / "captures.jsonl",
            redact=False,
        )
        script = tmp_path / "reproduce.sh"
        script.write_bytes(files[SCRIPT_FILE])
        text = files[SCRIPT_FILE].decode()
        assert text.startswith("#!/bin/sh\n")
        assert "# Step 1: refund it" in text and "# Step 2: read the order touch" in text
        assert f"# Step 3: DELETE {base}/api/orders/7" in text  # no note: the request names it

        outcome = _run_shell(str(script), tmp_path)
        assert outcome.returncode == 0, outcome.stderr.decode()
        assert not marker.exists()
        originals, repeats = received[:3], received[3:]
        assert [_comparable(r) for r in repeats] == [
            _comparable(originals[1]),
            _comparable(originals[0]),
            _comparable(originals[2]),
        ]

        # The control: the same note, written into a script without the sanitising, does run.
        (tmp_path / "naive.sh").write_text(f"# Step 1: {hostile_note}\n")
        assert _run_shell(str(tmp_path / "naive.sh"), tmp_path).returncode == 0
        assert marker.exists()


# ── bundle ──────────────────────────────────────────────────────────


def _ledger(roots: Roots, engagement: str = "acme") -> Path:
    return roots.audit / engagement / "captures.jsonl"


class TestBundle:
    def test_bundle_holds_the_five_files_and_describes_itself(self, env) -> None:
        gateway, _site, roots = env
        captures = _mixed_captures(gateway)
        chosen = [captures["upload"], captures["alice_order"], captures["login"]]
        ids = [c.id for c in chosen]
        finding = {
            "id": "F-0123456789ab",
            "engagement": "acme",
            "title": "IDOR on GET /api/orders/{id}",
            "class": "access_control",
            "severity": "high",
            "description": "not repeated in the bundle",
        }
        files = bundle(
            gateway.store, "acme", [*ids, ids[0]], finding=finding, ledger_path=_ledger(roots)
        )
        assert set(files) == {HAR_FILE, SCRIPT_FILE, CAPTURES_FILE, LEDGER_FILE, MANIFEST_FILE}
        assert all(isinstance(content, bytes) for content in files.values())
        assert verify_bundle(files) == []

        manifest = json.loads(files[MANIFEST_FILE])
        assert manifest["engagement"] == "acme" and manifest["capture_ids"] == ids
        assert manifest["redacted"] is True and manifest["tool_version"]
        assert chosen[-1].created_at <= manifest["created_at"]
        assert manifest["files"] == {
            name: hashlib.sha256(content).hexdigest()
            for name, content in files.items()
            if name != MANIFEST_FILE
        }
        assert manifest["finding"] == {
            "id": "F-0123456789ab",
            "title": "IDOR on GET /api/orders/{id}",
            "class": "access_control",
            "severity": "high",
        }

        listed = json.loads(files[CAPTURES_FILE])
        assert listed["engagement"] == "acme"
        assert listed["captures"] == [c.summary() for c in chosen]
        assert [c["response_sha256"] for c in listed["captures"]] == [
            hashlib.sha256(c.response_body).hexdigest() for c in chosen
        ]

        har = json.loads(files[HAR_FILE])
        assert _har_problems(har) == []
        assert [e["_capture_id"] for e in har["log"]["entries"]] == ids

        script = files[SCRIPT_FILE].decode()
        assert "Finding F-0123456789ab: IDOR on GET /api/orders/{id}" in script
        steps = [line for line in script.splitlines() if line.startswith("# Step ")]
        assert steps == [
            "# Step 1: upload as the caller",
            "# Step 2: alice reads",
            "# Step 3: login as alice",
        ]
        assert script.index(ids[0]) < script.index(ids[1]) < script.index(ids[2])

    def test_ledger_excerpt_is_the_ledger_lines_of_these_captures_verbatim(self, env) -> None:
        gateway, _site, roots = env
        captures = _mixed_captures(gateway)
        with pytest.raises(GatewayRefusal):  # a refusal writes a ledger line too
            gateway.send("acme", "GET", "https://evil.example/")
        ids = [captures["caller"].id, captures["alice_order"].id]
        files = bundle(gateway.store, "acme", ids, ledger_path=_ledger(roots))

        ledger_lines = _ledger(roots).read_bytes().splitlines(keepends=True)
        assert len(ledger_lines) > len(ids) + 1  # other captures and a refusal are in there too
        excerpt = files[LEDGER_FILE].splitlines(keepends=True)
        expected = [line for line in ledger_lines if json.loads(line).get("capture_id") in ids]
        assert excerpt == expected and len(excerpt) == 2
        assert {json.loads(line)["capture_id"] for line in excerpt} == set(ids)
        for line in excerpt:
            record = json.loads(line)
            assert record["hash"] and record["response_sha256"]

        # Without a ledger the file is there and empty, and the bundle still verifies.
        bare = bundle(gateway.store, "acme", ids)
        assert bare[LEDGER_FILE] == b"" and verify_bundle(bare) == []

    def test_no_fixture_secret_appears_in_any_file_of_a_redacted_bundle(self, env) -> None:
        gateway, _site, roots = env
        captures = _mixed_captures(gateway)
        ids = [c.id for c in captures.values()]

        def haystacks(files: dict[str, bytes]) -> dict[str, bytes]:
            """Every file, plus whatever a HAR carries base64-encoded, decoded."""
            out = dict(files)
            for index, entry in enumerate(json.loads(files[HAR_FILE])["log"]["entries"]):
                for part in (entry["request"].get("postData", {}), entry["response"]["content"]):
                    if part.get("encoding") == "base64":
                        out[f"{HAR_FILE}#{index}"] = base64.b64decode(part["text"])
            return out

        redacted = bundle(gateway.store, "acme", ids, ledger_path=_ledger(roots), redact=True)
        for name, content in haystacks(redacted).items():
            for secret in SECRETS:
                assert secret.encode() not in content, (name, secret)
        assert verify_bundle(redacted) == []
        assert json.loads(redacted[MANIFEST_FILE])["redacted"] is True
        # Redaction is the default, not something a caller has to remember.
        default = bundle(gateway.store, "acme", ids, ledger_path=_ledger(roots))
        for name in (HAR_FILE, SCRIPT_FILE, CAPTURES_FILE, LEDGER_FILE):
            assert default[name] == redacted[name], name

        # What is evidence rather than credential is still there.
        har_text = redacted[HAR_FILE].decode()
        assert "order 7" in har_text and "kept-1" in har_text and "signed in" in har_text
        script = redacted[SCRIPT_FILE].decode()
        assert "<AUTHORIZATION>" in script and "<X_API_TOKEN>" in script
        login_step = script.split(": login as alice\n")[1].split("# Step ")[0]
        assert captures["login"].id in login_step and "gateway performs this login" in login_step
        assert all(line.startswith("#") for line in login_step.splitlines() if line.strip())

        # The control: every one of those secrets is findable in the unredacted bundle,
        # so the search above was able to fail.
        revealed = haystacks(
            bundle(gateway.store, "acme", ids, ledger_path=_ledger(roots), redact=False)
        )
        for secret in SECRETS:
            assert secret.encode() in revealed[HAR_FILE], secret
        for secret in (ALICE_PASSWORD, ALICE_TOKEN, BOB_TOKEN, CALLER_BEARER, CALLER_API_KEY):
            assert secret.encode() in revealed[SCRIPT_FILE], secret
        assert json.loads(revealed[MANIFEST_FILE])["redacted"] is False
        assert b"NOT REDACTED" in revealed[SCRIPT_FILE]
        assert b"NOT REDACTED" not in redacted[SCRIPT_FILE]

    def test_manifest_hashes_verify_and_any_flipped_byte_is_detected(self, env) -> None:
        gateway, _site, roots = env
        captures = _mixed_captures(gateway)
        ids = [captures["upload"].id, captures["alice_echo"].id]
        files = bundle(gateway.store, "acme", ids, ledger_path=_ledger(roots))
        assert verify_bundle(files) == []
        assert verify_bundle(dict(files)) == []  # verifying changes nothing

        def flipped(name: str, position: int, mask: int) -> dict[str, bytes]:
            content = bytearray(files[name])
            content[position] ^= mask
            return {**files, name: bytes(content)}

        for name in (HAR_FILE, SCRIPT_FILE, CAPTURES_FILE, LEDGER_FILE):
            assert len(files[name]) > 10, name
            for position in (0, len(files[name]) // 2, len(files[name]) - 1):
                problems = verify_bundle(flipped(name, position, 0x01))
                assert problems == [f"{name}: sha256 does not match the manifest"], position
        # The manifest cannot list its own hash; every byte of it is covered all the same.
        for position in range(len(files[MANIFEST_FILE])):
            for mask in (0x01, 0x20, 0x80):
                problems = verify_bundle(flipped(MANIFEST_FILE, position, mask))
                assert any(p.startswith(f"{MANIFEST_FILE}: ") for p in problems), (
                    position,
                    mask,
                    problems,
                )

        # A changed claim with a recomputed layout is still caught by the manifest's digest.
        manifest = json.loads(files[MANIFEST_FILE])
        manifest["engagement"] = "other"
        forged = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        assert verify_bundle({**files, MANIFEST_FILE: forged}) == [
            f"{MANIFEST_FILE}: changed since it was written"
        ]

        without = {k: v for k, v in files.items() if k != CAPTURES_FILE}
        assert verify_bundle(without) == [f"{CAPTURES_FILE}: missing"]
        assert verify_bundle({**files, "extra.txt": b"x"}) == [
            "extra.txt: not listed in the manifest"
        ]
        assert verify_bundle({k: v for k, v in files.items() if k != MANIFEST_FILE}) == [
            f"{MANIFEST_FILE}: missing"
        ]
        assert verify_bundle({**files, MANIFEST_FILE: b"not json"}) == [
            f"{MANIFEST_FILE}: not valid JSON"
        ]
        assert verify_bundle({**files, MANIFEST_FILE: b"[]\n"}) == [
            f"{MANIFEST_FILE}: lists no files"
        ]

    def test_capture_of_another_engagement_is_refused(self, env) -> None:
        gateway, _site, roots = env
        mine = gateway.send("acme", "GET", ORDER_URL, note="acme's")
        theirs = gateway.send("other", "GET", ORDER_URL, note="other's")
        assert gateway.store.get("other", theirs.id) is not None

        with pytest.raises(KeyError) as refused:
            bundle(gateway.store, "acme", [theirs.id], ledger_path=_ledger(roots))
        assert theirs.id in str(refused.value) and "acme" in str(refused.value)
        with pytest.raises(KeyError):  # one foreign id spoils the whole request
            bundle(gateway.store, "acme", [mine.id, theirs.id])
        with pytest.raises(KeyError) as unknown:
            bundle(gateway.store, "acme", [mine.id, "cap-does-not-exist"])
        assert "cap-does-not-exist" in str(unknown.value)

        # The controls: each engagement gets its own capture, and only its own.
        own = bundle(gateway.store, "acme", [mine.id], ledger_path=_ledger(roots))
        assert json.loads(own[CAPTURES_FILE])["captures"][0]["note"] == "acme's"
        assert theirs.id.encode() not in b"".join(own.values())
        other = bundle(gateway.store, "other", [theirs.id], ledger_path=_ledger(roots, "other"))
        assert json.loads(other[MANIFEST_FILE])["capture_ids"] == [theirs.id]

        # A store that hands back another engagement's capture does not get it exported.
        class Careless:
            def get(self, _engagement: str, capture_id: str):
                return gateway.store.get("other", capture_id)

        with pytest.raises(ExportRefused) as leaked:
            bundle(Careless(), "acme", [theirs.id])
        assert theirs.id in str(leaked.value) and "other" in str(leaked.value)
        assert bundle(Careless(), "other", [theirs.id])  # the control for the stub

        # Nor is a finding of another engagement used to label this one's evidence.
        with pytest.raises(ExportRefused):
            bundle(gateway.store, "acme", [mine.id], finding={"id": "F-1", "engagement": "other"})
        assert bundle(gateway.store, "acme", [mine.id], finding={"id": "F-1", "engagement": "acme"})
        with pytest.raises(ValueError, match="no capture ids"):
            bundle(gateway.store, "acme", [])
