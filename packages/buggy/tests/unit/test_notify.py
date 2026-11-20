"""Notifications: what is sent, where, how often, and what never leaves.

The receiver is a real ``http.server`` on 127.0.0.1 (``Hook``); the code under
test reaches it through an opener with no proxy. A few tests use a fake opener
where the point is what the notifier asks of its opener.
"""

from __future__ import annotations

import ast
import json
import logging
import shlex
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from buggy import notify
from buggy.capture.gateway import CaptureGateway, GatewayRefusal, Roots
from buggy.cli import approvals as approvals_cli
from buggy.findings.model import Finding
from buggy.notify import (
    KINDS,
    Delivery,
    Event,
    Notifier,
    Sink,
    approval_event,
    failure_event,
    finding_event,
    recon_event,
    sanitize_url,
    scrub_text,
)
from buggy.program.gate import report_release

# The code under test must reach 127.0.0.1 directly, whatever proxy this machine has.
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({})).open


class Hook:
    """A local webhook receiver. The path picks the behaviour.

    ``/fail...`` answers 500, ``/slow...`` holds the answer until ``release``
    is set, ``/redirect...`` answers 302 to ``/landed``, anything else 200.
    """

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []
        self.release = threading.Event()
        self._lock = threading.Lock()
        hook = self

        class Handler(BaseHTTPRequestHandler):
            def _take(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with hook._lock:
                    hook.received.append(
                        {
                            "method": self.command,
                            "path": self.path,
                            "headers": {k.lower(): v for k, v in self.headers.items()},
                            "body": body,
                        }
                    )
                if self.path.startswith("/slow"):
                    hook.release.wait(10)
                status = 200
                if self.path.startswith("/fail"):
                    status = 500
                elif self.path.startswith("/redirect"):
                    status = 302
                try:
                    self.send_response(status)
                    if status == 302:
                        self.send_header("Location", "/landed")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except OSError:
                    pass  # the client gave up; that is the test

            do_POST = _take  # noqa: N815
            do_GET = _take  # noqa: N815

            def log_message(self, *_args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def at(self, path: str) -> list[dict[str, Any]]:
        with self._lock:
            return [r for r in self.received if r["path"] == path]

    def json_at(self, path: str) -> dict[str, Any]:
        (request,) = self.at(path)
        return json.loads(request["body"])

    def raw(self) -> str:
        with self._lock:
            return "\n".join(r["body"].decode("utf-8") for r in self.received)

    def close(self) -> None:
        self.release.set()
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def hook():
    receiver = Hook()
    yield receiver
    receiver.close()


@pytest.fixture
def logged():
    """Messages the module logs. Attached to its logger: ``buggy`` loggers may not propagate."""
    messages: list[str] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    handler = Collect(level=logging.WARNING)
    logger = logging.getLogger("buggy.notify")
    logger.addHandler(handler)
    yield messages
    logger.removeHandler(handler)


def _env(hook: Hook, **extra: str) -> dict[str, str]:
    return {
        "BUGGY_NOTIFY_WEBHOOK_URL": hook.url("/generic"),
        "BUGGY_NOTIFY_SLACK_WEBHOOK_URL": hook.url("/slack"),
        "BUGGY_NOTIFY_DISCORD_WEBHOOK_URL": hook.url("/discord"),
        **extra,
    }


def _event(kind: str = "approval_required", engagement: str = "acme", **fields: Any) -> Event:
    return Event(
        kind,
        engagement,
        "Approval needed: POST https://app.acme.test/api/orders",
        "Nothing was sent.",
        {"request_id": "apr-0123456789ab", "method": "POST", **fields},
        at=1700000000.0,
    )


class FakeResponse:
    def __init__(self, status: int, url: str) -> None:
        self.status, self.url, self.closed = status, url, False

    def close(self) -> None:
        self.closed = True


class FakeOpener:
    """Records what the notifier asks for. ``raises`` maps a URL to an exception to raise."""

    def __init__(self, raises: dict[str, BaseException] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.responses: list[FakeResponse] = []
        self._raises = raises or {}
        self._lock = threading.Lock()

    def __call__(self, request: urllib.request.Request, timeout: float | None = None) -> Any:
        with self._lock:
            self.calls.append(
                {
                    "url": request.full_url,
                    "method": request.get_method(),
                    "headers": {k.lower(): v for k, v in request.header_items()},
                    "body": request.data,
                    "timeout": timeout,
                }
            )
        if request.full_url in self._raises:
            raise self._raises[request.full_url]
        response = FakeResponse(204, request.full_url)
        with self._lock:
            self.responses.append(response)
        return response


# ── payload shapes ──────────────────────────────────────────────────


class TestPayloads:
    def test_each_sink_receives_its_own_shape(self, hook: Hook) -> None:
        notifier = Notifier.from_env(DIRECT, environ=_env(hook))
        deliveries = notifier.notify(_event())

        assert [(d.sink, d.ok, d.status) for d in deliveries] == [
            ("webhook", True, 200),
            ("slack", True, 200),
            ("discord", True, 200),
        ]
        assert hook.json_at("/generic") == {
            "kind": "approval_required",
            "engagement": "acme",
            "title": "Approval needed: POST https://app.acme.test/api/orders",
            "detail": "Nothing was sent.",
            "fields": {"request_id": "apr-0123456789ab", "method": "POST"},
            "at": 1700000000.0,
        }
        slack = hook.json_at("/slack")
        assert list(slack) == ["text"]
        assert slack["text"].split("\n") == [
            "*Approval needed: POST https://app.acme.test/api/orders* (acme)",
            "• Nothing was sent.",
            "• request_id: apr-0123456789ab",
            "• method: POST",
        ]
        discord = hook.json_at("/discord")
        assert list(discord) == ["content"]
        assert discord["content"].split("\n") == [
            "**Approval needed: POST https://app.acme.test/api/orders** (acme)",
            "- Nothing was sent.",
            "- request_id: apr-0123456789ab",
            "- method: POST",
        ]
        for request in hook.received:
            assert request["method"] == "POST"
            assert request["headers"]["content-type"] == "application/json"

    def test_fake_opener_sees_one_json_post_per_sink_with_a_five_second_timeout(self) -> None:
        opener = FakeOpener()
        notifier = Notifier.from_env(
            opener,
            environ={
                "BUGGY_NOTIFY_WEBHOOK_URL": "http://127.0.0.1:9/generic",
                "BUGGY_NOTIFY_SLACK_WEBHOOK_URL": "http://127.0.0.1:9/slack",
            },
        )
        deliveries = notifier.notify(_event())

        assert [d.to_dict()["ok"] for d in deliveries] == [True, True]
        by_url = {call["url"]: call for call in opener.calls}
        assert sorted(by_url) == ["http://127.0.0.1:9/generic", "http://127.0.0.1:9/slack"]
        assert set(json.loads(by_url["http://127.0.0.1:9/generic"]["body"])) == {
            "kind",
            "engagement",
            "title",
            "detail",
            "fields",
            "at",
        }
        assert set(json.loads(by_url["http://127.0.0.1:9/slack"]["body"])) == {"text"}
        assert {call["timeout"] for call in opener.calls} == {5.0}
        assert {call["method"] for call in opener.calls} == {"POST"}
        assert all(response.closed for response in opener.responses)

    def test_discord_content_is_cut_at_1900_characters(self, hook: Hook) -> None:
        notifier = Notifier.from_env(
            DIRECT, environ={"BUGGY_NOTIFY_DISCORD_WEBHOOK_URL": hook.url("/discord")}
        )
        long_fields = {f"note{i}": "word " * 59 for i in range(20)}
        big = Event("run_failed", "acme", "Run failed at recon", "detail", long_fields)
        small = Event("run_failed", "beta", "Run failed at recon", "detail", {"stage": "recon"})
        assert notifier.notify(big)[0].ok and notifier.notify(small)[0].ok

        first, second = (json.loads(r["body"])["content"] for r in hook.at("/discord"))
        assert len(first) == 1900 and first.endswith("…")
        assert first.startswith("**Run failed at recon** (acme)\n- detail\n- note0: word word")
        # Control: a short message is sent whole.
        assert second == "**Run failed at recon** (beta)\n- detail\n- stage: recon"

    def test_chat_formats_cannot_be_made_to_ping_a_channel(self, hook: Hook) -> None:
        notifier = Notifier.from_env(DIRECT, environ=_env(hook))
        noisy = Event(
            "run_failed", "acme", "<!channel> @everyone look", "<@12345> <https://x.test|y>"
        )
        notifier.notify(noisy)

        slack = hook.json_at("/slack")["text"]
        assert "<" not in slack and "&lt;!channel&gt;" in slack
        discord = hook.json_at("/discord")["content"]
        assert "@everyone" not in discord and "<@12345>" not in discord
        # Control: the generic JSON sink is not a chat and keeps the words.
        assert hook.json_at("/generic")["title"] == "<!channel> @everyone look"

    def test_commands_are_shown_as_code_in_chat(self, hook: Hook) -> None:
        notifier = Notifier.from_env(DIRECT, environ=_env(hook))
        notifier.notify(_event(allow="buggy-cli approvals allow acme apr-0123456789ab"))
        line = "allow: `buggy-cli approvals allow acme apr-0123456789ab`"
        assert f"• {line}" in hook.json_at("/slack")["text"].split("\n")
        assert f"- {line}" in hook.json_at("/discord")["content"].split("\n")
        assert hook.json_at("/generic")["fields"]["allow"] == line.split("`")[1]


# ── failure never reaches the caller ────────────────────────────────


class TestFailures:
    def test_a_failing_sink_does_not_raise_or_stop_the_others(
        self, hook: Hook, logged: list[str]
    ) -> None:
        notifier = Notifier(
            [
                Sink("webhook", hook.url("/fail")),
                Sink("slack", hook.url("/slack")),
                Sink("discord", hook.url("/discord")),
            ],
            opener=DIRECT,
        )
        deliveries = notifier.notify(_event())

        assert [(d.sink, d.ok, d.status) for d in deliveries] == [
            ("webhook", False, 500),
            ("slack", True, 200),
            ("discord", True, 200),
        ]
        assert deliveries[0].error == "HTTP 500"
        assert len(hook.at("/slack")) == 1 and len(hook.at("/discord")) == 1
        stats = notifier.stats()
        assert (stats["delivered"], stats["failed"]) == (2, 1)
        assert stats["recent_failures"][0]["sink"] == "webhook"
        assert stats["recent_failures"][0]["error"] == "HTTP 500"
        assert logged == ["notify: webhook delivery of approval_required for acme failed: HTTP 500"]

    def test_a_sink_that_does_not_answer_times_out_and_the_other_is_delivered(
        self, hook: Hook
    ) -> None:
        notifier = Notifier(
            [Sink("webhook", hook.url("/slow")), Sink("slack", hook.url("/slack"))],
            opener=DIRECT,
            timeout=0.3,
        )
        started = time.monotonic()
        deliveries = notifier.notify(_event())
        elapsed = time.monotonic() - started

        assert [(d.sink, d.ok, d.error) for d in deliveries] == [
            ("webhook", False, "timeout"),
            ("slack", True, ""),
        ]
        assert len(hook.at("/slack")) == 1
        assert elapsed < 3.0, f"notify blocked for {elapsed:.1f}s on a 0.3s timeout"

    def test_an_opener_that_ignores_its_timeout_cannot_hold_the_caller(self, hook: Hook) -> None:
        stuck = threading.Event()

        def opener(request: urllib.request.Request, timeout: float | None = None) -> Any:
            if request.full_url.endswith("/stuck"):
                stuck.wait(20)
            return DIRECT(request, timeout=timeout)

        notifier = Notifier(
            [Sink("webhook", hook.url("/stuck")), Sink("discord", hook.url("/discord"))],
            opener=opener,
            timeout=0.2,
        )
        try:
            started = time.monotonic()
            deliveries = notifier.notify(_event())
            elapsed = time.monotonic() - started
        finally:
            stuck.set()
        assert [(d.sink, d.ok, d.error) for d in deliveries] == [
            ("webhook", False, "timeout"),
            ("discord", True, ""),
        ]
        assert elapsed < 3.0

    def test_refused_connection_and_arbitrary_opener_errors_become_deliveries(self) -> None:
        # Nothing listens on the port of a server that was just closed.
        gone = Hook()
        dead_url = gone.url("/generic")
        gone.close()
        refused = Notifier([Sink("webhook", dead_url)], opener=DIRECT).notify(_event())
        assert len(refused) == 1 and refused[0].ok is False and refused[0].status is None
        assert "refused" in refused[0].error.lower()

        url = "http://127.0.0.1:9/services/T0/B0/private-part"
        opener = FakeOpener(raises={url: RuntimeError(f"boom while posting to {url}")})
        notifier = Notifier(
            [Sink("slack", url), Sink("webhook", "http://127.0.0.1:9/ok")], opener=opener
        )
        broken, fine = notifier.notify(_event())
        assert broken.ok is False and broken.error.startswith("RuntimeError: boom")
        # The webhook URL is a credential: it is not repeated in the error or the stats.
        assert "private-part" not in broken.error
        assert "private-part" not in json.dumps(notifier.stats())
        assert "private-part" not in repr(Sink("slack", url))
        assert fine.ok is True

    def test_a_redirected_post_is_reported_as_not_delivered(self, hook: Hook) -> None:
        notifier = Notifier([Sink("webhook", hook.url("/redirect"))], opener=DIRECT)
        (delivery,) = notifier.notify(_event())
        assert delivery.ok is False and "redirected" in delivery.error
        # urllib turned the POST into a GET without a body: nothing was delivered there.
        assert [r["body"] for r in hook.at("/landed")] == [b""]

    def test_notify_does_not_raise_on_a_non_event(self, hook: Hook) -> None:
        notifier = Notifier([Sink("webhook", hook.url("/generic"))], opener=DIRECT)
        (delivery,) = notifier.notify(None)  # type: ignore[arg-type]
        assert delivery == Delivery("notifier", False, error="internal error: TypeError")
        assert hook.received == []


# ── rate limit ──────────────────────────────────────────────────────


class TestRateLimit:
    def test_five_identical_events_in_a_second_give_one_delivery(self, hook: Hook) -> None:
        notifier = Notifier.from_env(
            DIRECT, environ={"BUGGY_NOTIFY_WEBHOOK_URL": hook.url("/generic")}
        )
        started = time.monotonic()
        results = [notifier.notify(_event()) for _ in range(5)]
        assert time.monotonic() - started < 1.0

        assert [len(r) for r in results] == [1, 0, 0, 0, 0]
        assert len(hook.at("/generic")) == 1
        stats = notifier.stats()
        assert stats["suppressed"] == 4 and stats["delivered"] == 1
        assert stats["suppressed_by"] == {"approval_required/acme": 4}

    def test_the_limit_is_per_kind_and_engagement_and_ends_with_the_interval(
        self, hook: Hook
    ) -> None:
        now = [1000.0]
        notifier = Notifier.from_env(
            DIRECT,
            environ={
                "BUGGY_NOTIFY_WEBHOOK_URL": hook.url("/generic"),
                "BUGGY_NOTIFY_MIN_INTERVAL_SECONDS": "30",
            },
            clock=lambda: now[0],
        )
        assert len(notifier.notify(_event())) == 1
        assert notifier.notify(_event()) == []
        # Another engagement and another kind are not duplicates.
        assert len(notifier.notify(_event(engagement="beta"))) == 1
        assert len(notifier.notify(_event(kind="run_failed"))) == 1
        now[0] += 29.9
        assert notifier.notify(_event()) == []
        now[0] += 0.2
        assert len(notifier.notify(_event())) == 1

        assert len(hook.at("/generic")) == 4
        assert notifier.stats()["suppressed"] == 2

    def test_interval_zero_turns_the_limit_off(self, hook: Hook) -> None:
        notifier = Notifier.from_env(
            DIRECT,
            environ={
                "BUGGY_NOTIFY_WEBHOOK_URL": hook.url("/generic"),
                "BUGGY_NOTIFY_MIN_INTERVAL_SECONDS": "0",
            },
        )
        assert [len(notifier.notify(_event())) for _ in range(5)] == [1] * 5
        assert len(hook.at("/generic")) == 5 and notifier.stats()["suppressed"] == 0


# ── privacy ─────────────────────────────────────────────────────────


def _gateway_hold(tmp_path: Path) -> tuple[Roots, dict[str, Any], GatewayRefusal]:
    """A real approval hold: what the gateway refuses with and what it writes down."""
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}})
    )

    def never(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("a held request must not be sent")

    opener = type("Opener", (), {"open": staticmethod(never)})()
    gateway = CaptureGateway(roots, opener=opener, sleep=lambda _s: None)
    try:
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send(
                "acme",
                "POST",
                "https://app.acme.test/api/orders/7?token=SECRET#frag",
                headers={"Authorization": "Bearer header-value-1"},
                body='{"username": "alice", "password": "hunter2"}',
                note="log in with password hunter2",
            )
    finally:
        gateway.store.close()
    lines = (roots.audit / "acme" / "approvals" / "requests.jsonl").read_text().splitlines()
    return roots, json.loads(lines[-1]), refused.value


class TestPrivacy:
    def test_gateway_hold_notifies_without_query_body_or_reason(
        self, hook: Hook, tmp_path: Path
    ) -> None:
        roots, record, refusal = _gateway_hold(tmp_path)
        # The record itself does hold what must not travel.
        assert refusal.code == "APPROVAL_REQUIRED"
        assert "token=SECRET" in record["tool_args_redacted"]["url"]
        assert "hunter2" in record["tool_args_redacted"]["body_preview"]
        assert "hunter2" in record["reason"]

        notifier = Notifier.from_env(DIRECT, environ=_env(hook))
        deliveries = notifier.notify(approval_event(record))
        assert [d.ok for d in deliveries] == [True, True, True]

        sent = hook.raw()
        for forbidden in ("SECRET", "token=", "hunter2", "alice", "frag", "header-value-1"):
            assert forbidden not in sent, forbidden
        assert record["tool_args_redacted"]["body_sha256"] not in sent
        assert record["metadata"]["fingerprint"] not in sent
        # Control: what the operator needs is there, at every sink.
        request_id = refusal.extra["request_id"]
        for path in ("/generic", "/slack", "/discord"):
            body = hook.at(path)[0]["body"].decode()
            assert "POST https://app.acme.test/api/orders/7" in body
            assert f"buggy-cli approvals allow acme {request_id}" in body
            assert f"buggy-cli approvals deny acme {request_id}" in body
        generic = hook.json_at("/generic")
        assert generic["kind"] == "approval_required" and generic["engagement"] == "acme"
        assert generic["at"] == record["created_at"]
        assert generic["fields"]["url"] == "https://app.acme.test/api/orders/7"
        # The command in the notification is the one the gateway told the agent about ...
        assert generic["fields"]["allow"] in refusal.detail
        # ... and it is a command the operator CLI accepts for this request.
        argv = shlex.split(generic["fields"]["allow"])
        assert argv[:2] == ["buggy-cli", "approvals"]
        roots_argv = ["--control-root", str(roots.control), "--audit-root", str(roots.audit)]
        assert approvals_cli.main([*roots_argv, *argv[2:]]) == 0
        decisions = roots.control / "acme" / "approvals" / "decisions.jsonl"
        decision = json.loads(decisions.read_text().splitlines()[-1])
        assert (decision["request_id"], decision["action"]) == (request_id, "allow")

    def test_report_release_hold_names_the_request_and_not_the_report(
        self, hook: Hook, tmp_path: Path
    ) -> None:
        control, audit = tmp_path / "control", tmp_path / "audit"
        text = "Steps: log in as alice with password hunter2, then open /admin?debug=1"
        held = report_release(control, audit, "acme", "F-0123456789ab", text)
        assert held["status"] == "approval_required"
        record = json.loads(
            (audit / "acme" / "approvals" / "requests.jsonl").read_text().splitlines()[-1]
        )

        event = approval_event(record)
        Notifier.from_env(DIRECT, environ=_env(hook)).notify(event)
        sent = hook.raw()
        for forbidden in ("hunter2", "alice", "debug=1", str(tmp_path)):
            assert forbidden not in sent, forbidden
        request_id = held["request_id"]
        generic = hook.json_at("/generic")
        assert generic["title"] == "Approval needed: release the report for F-0123456789ab"
        assert generic["fields"]["allow"] == f"buggy-cli approvals allow acme {request_id}"
        assert generic["fields"]["allow"] in held["detail"]
        # The draft the notification points at exists where it says.
        assert f"reports/{request_id}.md" in generic["detail"]
        assert (audit / "acme" / "reports" / f"{request_id}.md").read_text() == text

    def test_finding_event_carries_the_contract_facts_and_no_agent_text(self) -> None:
        finding = Finding(
            id="F-0123456789ab",
            engagement="acme",
            title="IDOR leaks token=SECRET for bob",
            vuln_class="access_control",
            severity="high",
            endpoint="https://app.acme.test/api/orders/{id}?token=SECRET",
            cwe="CWE-639",
            method="GET",
            parameter="id",
            description="response body contains bob@acme.test and password hunter2",
            remediation="check ownership before returning the order to the caller",
            status="exploit_verified",
            verification={"at": 1700000100.0, "replay_capture_ids": ["cap-1", "cap-2"]},
            grade="submit",
            updated_at=1700000200.0,
        )
        event = finding_event(finding)
        assert event == finding_event(finding.to_dict())
        payload = event.to_dict()
        assert payload == {
            "kind": "finding_verified",
            "engagement": "acme",
            "title": (
                "Finding verified: high access_control on GET https://app.acme.test/api/orders/{id}"
            ),
            "detail": "The finding's assertions held when its requests were re-sent.",
            "fields": {
                "finding_id": "F-0123456789ab",
                "severity": "high",
                "class": "access_control",
                "cwe": "CWE-639",
                "method": "GET",
                "endpoint": "https://app.acme.test/api/orders/{id}",
                "status": "exploit_verified",
                "grade": "submit",
                "replays": 2,
            },
            "at": 1700000100.0,
        }
        serialized = json.dumps(payload)
        for forbidden in ("SECRET", "hunter2", "bob", "IDOR leaks"):
            assert forbidden not in serialized

    def test_a_finding_that_is_not_exploit_verified_is_not_announced_as_verified(self) -> None:
        candidate = finding_event(
            {
                "id": "F-0123456789ab",
                "engagement": "acme",
                "class": "xss",
                "severity": "low",
                "endpoint": "https://app.acme.test/search",
                "method": "GET",
                "status": "candidate",
            }
        )
        assert candidate.title.startswith(
            "Finding not exploit-verified (status candidate): low xss"
        )
        assert "Finding verified" not in candidate.title
        assert candidate.fields["status"] == "candidate"

    def test_failure_event_scrubs_the_error_message(self) -> None:
        bearer = "Bearer " + "abcDEF123456" + "ghiJKL7890"
        jwt = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiJhbGljZSJ9", "c2lnbmF0dXJl"])
        error = RuntimeError(
            "GET https://user:hunter2@app.acme.test/api/me?session=SECRET failed; "
            f"Authorization: {bearer}; password=hunter2; token {jwt}"
        )
        event = failure_event("acme", "exploit", error)
        serialized = json.dumps(event.to_dict())
        for forbidden in ("hunter2", "SECRET", "session=", bearer.split()[1], jwt, "user:"):
            assert forbidden not in serialized, forbidden
        # Control: where it failed and on what is still readable.
        assert event.title == "Run failed at exploit (RuntimeError)"
        # A stage named like a secret does not get the error type redacted.
        assert failure_event("acme", "token_refresh", KeyError("k")).title == (
            "Run failed at token_refresh (KeyError)"
        )
        assert "GET https://app.acme.test/api/me failed" in event.detail
        assert event.fields == {"stage": "exploit", "error_type": "RuntimeError"}

        plain = failure_event("acme", "recon", "nuclei exited with status 2")
        assert (plain.title, plain.detail) == ("Run failed at recon", "nuclei exited with status 2")

    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "api_key",
            "accessToken",
            "Authorization",
            "session_id",
            "cookie",
            "body_preview",
            "request_body",
            "body_sha256",
            "headers",
            "query",
            "csrf",
            "private_key",
            "client_secret",
            "auth",
        ],
    )
    def test_event_rejects_fields_named_like_secrets(self, key: str) -> None:
        with pytest.raises(ValueError, match="named like a secret"):
            Event("run_failed", "acme", "t", fields={key: "x"})

    @pytest.mark.parametrize(
        "key",
        [
            "request_id",
            "method",
            "url",
            "severity",
            "class",
            "records",
            "author",
            "passed",
            "monkey",
        ],
    )
    def test_event_accepts_ordinary_field_names(self, key: str) -> None:
        assert Event("run_failed", "acme", "t", fields={key: "x"}).fields == {key: "x"}

    def test_event_rejects_structures_and_unknown_kinds_and_scrubs_strings(self) -> None:
        with pytest.raises(ValueError, match="must be a string, number or bool"):
            Event("run_failed", "acme", "t", fields={"request": {"password": "hunter2"}})
        with pytest.raises(ValueError, match="kind must be one of"):
            Event("approved", "acme", "t")
        event = Event(
            "run_failed",
            "../etc",
            "see https://app.acme.test/a?token=SECRET now",
            "line one\nline two password=hunter2",
            {"url": "https://app.acme.test/b?x=SECRET", "count": 3, "ok": True, "none": None},
        )
        assert event.engagement == "unknown"
        assert event.title == "see https://app.acme.test/a now"
        assert event.detail == "line one line two password=[redacted]"
        assert event.fields == {
            "url": "https://app.acme.test/b",
            "count": 3,
            "ok": True,
            "none": None,
        }

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "https://app.acme.test/api/orders/7?token=SECRET#frag",
                "https://app.acme.test/api/orders/7",
            ),
            ("https://user:hunter2@app.acme.test:8443/a", "https://app.acme.test:8443/a"),
            ("https://app.acme.test/a;jsessionid=ABC123/b", "https://app.acme.test/a/b"),
            ("HTTPS://APP.Acme.Test/Path", "https://app.acme.test/Path"),
            ("https://app.acme.test/api/orders/{id}", "https://app.acme.test/api/orders/{id}"),
            ("/api/orders/7?x=1", "/api/orders/7"),
            ("file:///etc/passwd", ""),
            ("javascript:alert(1)", ""),
            ("//evil.test/x", ""),
            (None, ""),
        ],
    )
    def test_sanitize_url(self, url: Any, expected: str) -> None:
        assert sanitize_url(url) == expected

    def test_sanitize_url_masks_a_token_in_the_path_and_keeps_ordinary_segments(self) -> None:
        token = "a1b2c3d4" * 5
        assert sanitize_url(f"https://app.acme.test/reset/{token}/confirm") == (
            "https://app.acme.test/reset/[redacted]/confirm"
        )
        ordinary = "https://app.acme.test/api/v1/organisations/settings/notifications"
        assert sanitize_url(ordinary) == ordinary

    def test_scrub_text_removes_credentials_and_keeps_the_engagement_name(self) -> None:
        stripe_like = "sk_" + "live_" + "0123456789abcdefABCDEF"
        assert stripe_like not in scrub_text(f"key {stripe_like} leaked")
        assert scrub_text("Cookie: sid=abc123; theme=dark") == "Cookie: [redacted]"
        assert scrub_text('{"password": "hunter2", "user": "al"}') == (
            '{"password": [redacted], "user": "al"}'
        )
        # A long engagement name with digits looks opaque; as ``keep`` it survives.
        name = "acme-production-2026-q4-external"
        command = f"buggy-cli approvals allow {name} apr-0123456789ab"
        assert scrub_text(command, keep=(name,)) == command
        assert name not in scrub_text(command)
        record = {
            "request_id": "apr-0123456789ab",
            "engagement_name": name,
            "tool_name": "http_send",
            "tool_args_redacted": {"method": "DELETE", "url": "https://app.acme.test/api/x/1"},
        }
        assert approval_event(record).fields["allow"] == command


# ── configuration ───────────────────────────────────────────────────


class TestConfiguration:
    def test_no_configuration_is_a_no_op(self) -> None:
        opener = FakeOpener()
        notifier = Notifier.from_env(opener, environ={})
        assert notifier.enabled is False and notifier.sink_names == ()
        assert notifier.notify(_event()) == []
        assert notifier.notify(None) == []  # type: ignore[arg-type]
        assert opener.calls == []
        stats = notifier.stats()
        assert (stats["delivered"], stats["failed"], stats["suppressed"]) == (0, 0, 0)

    def test_event_filter(self, hook: Hook) -> None:
        notifier = Notifier.from_env(
            DIRECT,
            environ={
                "BUGGY_NOTIFY_WEBHOOK_URL": hook.url("/generic"),
                "BUGGY_NOTIFY_EVENTS": " approval_required, RUN_FAILED ",
            },
        )
        assert notifier.events == ("approval_required", "run_failed")
        assert len(notifier.notify(_event(kind="approval_required"))) == 1
        assert len(notifier.notify(_event(kind="run_failed"))) == 1
        assert notifier.notify(_event(kind="recon_finished")) == []
        assert notifier.notify(_event(kind="finding_verified")) == []

        assert [json.loads(r["body"])["kind"] for r in hook.at("/generic")] == [
            "approval_required",
            "run_failed",
        ]
        stats = notifier.stats()
        assert stats["filtered"] == 2 and stats["suppressed"] == 0

    def test_all_kinds_are_on_by_default(self, hook: Hook) -> None:
        notifier = Notifier.from_env(
            DIRECT, environ={"BUGGY_NOTIFY_WEBHOOK_URL": hook.url("/generic")}
        )
        assert notifier.events == KINDS
        assert [len(notifier.notify(_event(kind=kind))) for kind in KINDS] == [1, 1, 1, 1]

    def test_from_env_reads_the_process_environment_with_the_default_opener(
        self, hook: Hook, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for variable in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
            monkeypatch.delenv(variable, raising=False)
        monkeypatch.setenv("no_proxy", "127.0.0.1")
        monkeypatch.setattr(urllib.request, "_opener", None)
        monkeypatch.setenv("BUGGY_NOTIFY_SLACK_WEBHOOK_URL", hook.url("/slack"))
        monkeypatch.delenv("BUGGY_NOTIFY_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("BUGGY_NOTIFY_DISCORD_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("BUGGY_NOTIFY_EVENTS", raising=False)
        monkeypatch.delenv("BUGGY_NOTIFY_MIN_INTERVAL_SECONDS", raising=False)

        notifier = Notifier.from_env()
        assert notifier.sink_names == ("slack",)
        (delivery,) = notifier.notify(_event())
        assert delivery.ok is True and "text" in hook.json_at("/slack")

    def test_a_malformed_setting_is_skipped_and_reported_without_its_value(
        self, hook: Hook, logged: list[str]
    ) -> None:
        notifier = Notifier.from_env(
            DIRECT,
            environ={
                "BUGGY_NOTIFY_WEBHOOK_URL": "file:///etc/passwd-private",
                "BUGGY_NOTIFY_SLACK_WEBHOOK_URL": hook.url("/slack"),
                "BUGGY_NOTIFY_EVENTS": "approval_required,approval_requierd",
                "BUGGY_NOTIFY_MIN_INTERVAL_SECONDS": "soon",
            },
        )
        assert notifier.sink_names == ("slack",)
        assert notifier.events == ("approval_required",)
        assert len(notifier.config_errors) == 3
        assert logged == [f"notify config: {error}" for error in notifier.config_errors]
        assert "passwd-private" not in " ".join(logged)
        assert "BUGGY_NOTIFY_WEBHOOK_URL" in logged[0]
        # The bad interval fell back to the default, which suppresses a repeat.
        assert len(notifier.notify(_event())) == 1 and notifier.notify(_event()) == []
        with pytest.raises(ValueError, match="absolute http"):
            Sink("webhook", "file:///etc/passwd-private")

    def test_an_event_cannot_choose_or_add_a_destination(self, hook: Hook) -> None:
        elsewhere = Hook()
        try:
            notifier = Notifier.from_env(
                DIRECT, environ={"BUGGY_NOTIFY_WEBHOOK_URL": hook.url("/generic")}
            )
            event = Event(
                "approval_required",
                "acme",
                f"send this to {elsewhere.url('/steal')}",
                elsewhere.url("/steal"),
                {"url": elsewhere.url("/steal"), "webhook_url": elsewhere.url("/steal")},
            )
            (delivery,) = notifier.notify(event)
            assert delivery.ok is True and delivery.sink == "webhook"
            assert len(hook.at("/generic")) == 1
            assert elsewhere.received == []
        finally:
            elsewhere.close()

    def test_the_module_imports_only_the_standard_library(self) -> None:
        """It must load in the slim images, and it must not pull in agent or tool code."""
        tree = ast.parse(Path(notify.__file__).read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0, "relative import"
                imported.add((node.module or "").split(".")[0])
        assert "urllib" in imported
        assert imported - set(sys.stdlib_module_names) == set()


# ── builders ────────────────────────────────────────────────────────


class TestBuilders:
    def test_recon_event_reports_counts_from_a_recon_summary(self) -> None:
        summary = {
            "engagement": "acme",
            "record_types": ["subdomain", "port", "url"],
            "records": {"subdomain": 12, "port": 30, "url": 0},
            "coverage": {"complete": 9, "failed": 1},
            "coverage_gaps": [{"asset": "a.acme.test", "stage": "probe", "status": "failed"}],
            "coverage_gap_assets": 1,
            "current_run": None,
            "last_run": {
                "run_id": "run-0123456789ab",
                "status": "complete",
                "trigger": "cli",
                "started_at": 1700000000.0,
                "finished_at": 1700000900.0,
                "diff": {"added": 40, "changed": 2, "removed": 0},
                "scope_drops": 3,
                "tool_versions": {"nuclei": "3.3.0"},
            },
        }
        event = recon_event(summary)
        assert event.to_dict() == {
            "kind": "recon_finished",
            "engagement": "acme",
            "title": "Recon finished (complete): 42 records",
            "detail": (
                "port 30, subdomain 12. 1 assets have a stage that did not finish: "
                "nothing found there means not checked, not clean."
            ),
            "fields": {
                "run_id": "run-0123456789ab",
                "status": "complete",
                "records": 42,
                "added": 40,
                "changed": 2,
                "removed": 0,
                "scope_drops": 3,
                "coverage_gap_assets": 1,
            },
            "at": 1700000900.0,
        }
        waiting = recon_event({**summary, "timed_out": True})
        assert waiting.title == "Recon is still running after the wait limit: 42 records so far"
        assert waiting.fields["timed_out"] is True
        empty = recon_event({"engagement": "acme", "records": {}, "last_run": None})
        assert empty.title == "Recon: 0 records, no finished run recorded"

    def test_approval_event_for_an_agent_tool_names_the_tool_and_not_its_arguments(self) -> None:
        event = approval_event(
            {
                "kind": "approval_request",
                "request_id": "req-1",
                "engagement_name": "acme",
                "agent_name": "exploit",
                "tool_name": "run_command",
                "tool_args_redacted": {"command": "curl -H 'X-Api-Key: SECRET' https://x.test"},
                "reason": "needs SECRET",
                "created_at": 1700000000.0,
            }
        )
        assert event.title == "Approval needed: tool run_command (exploit)"
        assert event.fields == {
            "request_id": "req-1",
            "tool": "run_command",
            "agent": "exploit",
            "allow": "buggy-cli approvals allow acme req-1",
            "deny": "buggy-cli approvals deny acme req-1",
            "review": "buggy-cli approvals list acme",
        }
        assert "SECRET" not in json.dumps(event.to_dict()) and "curl" not in event.detail

    def test_a_record_with_unusable_names_gives_no_command_to_paste(self) -> None:
        event = approval_event(
            {
                "request_id": "apr-1; rm -rf /",
                "engagement_name": "acme$(id)",
                "tool_name": "http_send",
                "tool_args_redacted": {"method": "POST", "url": "https://app.acme.test/x"},
            }
        )
        assert "allow" not in event.fields and "deny" not in event.fields
        assert event.fields["review"] == "buggy-cli approvals list <engagement>"
        assert event.engagement == "unknown" and event.fields["request_id"] is None
        assert "rm -rf" not in json.dumps(event.to_dict())
        assert "$(id)" not in json.dumps(event.to_dict())

    @pytest.mark.parametrize("junk", [None, {}, [], "text", 7, {"tool_args_redacted": "x"}])
    def test_builders_never_raise_on_malformed_input(self, junk: Any) -> None:
        events = [
            approval_event(junk),
            recon_event(junk),
            finding_event(junk),
            failure_event(junk, junk, junk),
        ]
        assert [event.kind for event in events] == list(KINDS)
        # Only ``failure_event`` takes the engagement as an argument; "text" is a valid name.
        named = "text" if junk == "text" else "unknown"
        assert [event.engagement for event in events] == ["unknown", "unknown", "unknown", named]
        for event in events:
            json.dumps(event.to_dict(), allow_nan=False)
