"""The ``xss_stored`` and ``xss_blind`` probes against a fake site that stores what it gets.

The fake site keeps posted comments and renders them raw, escaped, inside a
textarea, or as JSON. The "browser" that renders a blind payload is the fake
handler loading every canary URL it finds in a stored value, as an admin
page would.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from buggy.capture.canary import Canary
from buggy.capture.probes import run_probe
from buggy.capture.probes.stored import (
    BLIND_MAX_REQUESTS,
    STORED_MAX_REQUESTS,
    blind_hits,
    planted,
)
from buggy.cli.approvals import paths_for, pending

from .fake_web import BASE, SCOPE, make

CANARY = "http://canary.test"
COMMENTS = f"{BASE}/comments"
ITEMS = f"{BASE}/api/items"


class Site:
    """``POST /comments`` stores a form; ``GET /comments`` renders them in ``mode``."""

    def __init__(self, env, mode: str = "raw") -> None:
        self.env, self.mode, self.comments = env, mode, []
        env.web.route("POST", "/comments", self.post)
        env.web.route("GET", "/comments", self.page)
        env.web.route("POST", "/api/items", self.post_json)
        env.web.route("PUT", "/api/items/5", self.post_json)
        env.web.route("GET", "/api/items", self.items)
        env.web.route("GET", "/api/items/5", self.items)

    def post(self, _method, _url, _headers, body):
        fields = dict(parse_qsl(body.decode()))
        if not fields.get("author"):
            return 400, [], "author is required"
        self.comments.append(fields.get("text", ""))
        return 303, [("Location", "/comments")], ""

    def post_json(self, _method, _url, _headers, body):
        self.comments.append(json.loads(body)["name"])
        return 201, [("Content-Type", "application/json")], '{"ok": true}'

    def page(self, *_args):
        if self.mode == "raw":
            shown = "".join(f"<li>{c}</li>" for c in self.comments)
        elif self.mode == "textarea":
            shown = "".join(f"<textarea>{c}</textarea>" for c in self.comments)
        elif self.mode == "hidden":
            shown = "<li>comments are moderated</li>"
        else:
            shown = "".join(f"<li>{html.escape(c)}</li>" for c in self.comments)
        return 200, [], f"<html><ul>{shown}</ul></html>"

    def items(self, *_args):
        return 200, [("Content-Type", "application/json")], json.dumps(self.comments)


@pytest.fixture
def env(tmp_path: Path):
    made = make(tmp_path)
    made.canary = Canary(base_url=CANARY)
    yield made
    made.gateway.store.close()


def stored(env, **extra) -> dict:
    params = {
        "url": COMMENTS,
        "parameter": "text",
        "body": {"author": "tester", "text": "hello"},
        **extra,
    }
    return run_probe(env.gateway, "acme", "xss_stored", params)


def paths(env) -> list[tuple[str, str]]:
    return [(method, urlsplit(url).path) for method, url, _h, _b in env.web.seen]


class TestStored:
    def test_markup_rendered_raw_is_proven(self, env) -> None:
        Site(env, "raw")
        result = stored(env)
        assert result["vulnerable"] is True, result
        assert (result["class"], result["cwe"]) == ("xss", "CWE-79")
        details = result["details"]
        assert paths(env) == [("GET", "/comments"), ("POST", "/comments"), ("GET", "/comments")]
        assert details["pages"][0]["before_has_marker"] is False
        assert details["pages"][0]["outcome"] == "rendered"
        assert details["payload"] == f'<b data-buggy="{details["marker"]}">{details["marker"]}</b>'
        assert len(result["evidence_capture_ids"]) == 3 <= STORED_MAX_REQUESTS
        assert "<script" not in details["payload"]

    @pytest.mark.parametrize("mode", ["escaped", "textarea"])
    def test_inert_markup_is_not_flagged(self, env, mode) -> None:
        Site(env, mode)
        result = stored(env)
        assert result["vulnerable"] is False and "inert" in result["summary"], result

    def test_a_value_not_shown_on_the_readback_pages_is_negative(self, env) -> None:
        Site(env, "hidden")
        result = stored(env)
        assert result["vulnerable"] is False and "did not come back" in result["summary"]

    def test_json_only_echo_is_not_proven(self, env) -> None:
        Site(env)
        result = stored(env, url=ITEMS, location="json", parameter="name", body={"name": "x"})
        assert result["vulnerable"] is None and "not proven" in result["summary"], result
        assert "JSON" in result["summary"]
        assert result["details"]["readback_urls"] == [ITEMS]

    def test_an_update_reads_back_the_object_and_its_collection(self, env) -> None:
        Site(env, "raw")
        result = stored(
            env, url=f"{ITEMS}/5", method="PUT", location="json", parameter="name", body={}
        )
        assert result["details"]["readback_urls"] == [f"{ITEMS}/5", ITEMS]
        assert len(result["evidence_capture_ids"]) == 5

    def test_a_refused_write_cannot_tell(self, env) -> None:
        Site(env, "raw")
        result = stored(env, body={"text": "hello"})  # no author: the site answers 400
        assert result["vulnerable"] is None and "not accepted" in result["summary"]

    def test_given_readback_urls_are_used_and_bounded(self, env) -> None:
        Site(env, "raw")
        result = stored(env, readback_urls=[f"{BASE}/comments?page=1"])
        assert result["vulnerable"] is True
        too_many = stored(env, readback_urls=[f"{BASE}/r{n}" for n in range(4)])
        assert too_many["status"] == "error"

    def test_held_for_approval_and_nothing_is_sent(self, tmp_path) -> None:
        held = make(tmp_path, SCOPE)
        try:
            Site(held, "raw")
            result = stored(held)
            assert result["code"] == "APPROVAL_REQUIRED" and held.web.seen == []
            requests_path, decisions_path = paths_for(held.roots.control, held.roots.audit, "acme")
            (request,) = pending(requests_path, decisions_path)
            assert request["tool_args_redacted"]["probe"] == "xss_stored"
        finally:
            held.gateway.store.close()


# ── blind ────────────────────────────────────────────────────────────

_CANARY_URL = re.compile(re.escape(CANARY) + r"/c/([0-9a-f]+)/[si]")


def blind_site(env, *, renders: bool) -> list[str]:
    """``POST /contact``; with ``renders`` an admin's browser loads every stored canary URL."""
    stored_values: list[str] = []

    def post(_method, _url, headers, body):
        if headers.get("content-type") == "application/json":
            values = list(json.loads(body).values())
        else:
            values = [v for _k, v in parse_qsl(body.decode())]
        stored_values.extend(str(v) for v in values)
        if renders:
            for value in values:
                for token in set(_CANARY_URL.findall(str(value))):
                    env.canary.record(
                        token, remote="198.51.100.7", method="GET", path="/", user_agent="Chrome"
                    )
        return 200, [], "<p>thanks</p>"

    env.web.route("POST", "/contact", post)
    return stored_values


def blind(env, **extra) -> dict:
    params = {
        "url": f"{BASE}/contact",
        "parameters": ["message", "subject"],
        "body": {"message": "hi", "subject": "s", "email": "a@acme.test"},
        "wait_seconds": 0,
        **extra,
    }
    return run_probe(env.gateway, "acme", "xss_blind", params, canary=env.canary)


class TestBlind:
    def test_a_callback_proves_it(self, env) -> None:
        values = blind_site(env, renders=True)
        result = blind(env)
        assert result["vulnerable"] is True, result
        assert len(env.web.seen) == BLIND_MAX_REQUESTS == len(result["evidence_capture_ids"])
        tokens = result["details"]["tokens"]
        assert set(tokens) == {"message", "subject"} and len(set(tokens.values())) == 2
        assert all(CANARY in value for value in values if value not in ("a@acme.test",))
        assert result["details"]["callbacks"][0]["remote"] == "198.51.100.7"

    def test_no_callback_yet_is_undecided_and_a_late_one_is_picked_up(self, env) -> None:
        blind_site(env, renders=False)
        result = blind(env)
        assert result["vulnerable"] is None and "blind_hits" in result["summary"], result
        rows = planted(env.gateway, "acme")
        assert {row["parameter"] for row in rows} == {"message", "subject"}
        assert blind_hits(env.gateway, env.canary, "acme") == []

        # The listener restarted: a new instance learns the planted tokens again.
        later = Canary(base_url=CANARY)
        assert blind_hits(env.gateway, later, "acme") == []
        token = result["details"]["tokens"]["subject"]
        later.record(token, remote="192.0.2.1", method="GET", path="/", user_agent="Firefox")
        (hit,) = blind_hits(env.gateway, later, "acme")
        assert hit["vulnerable"] is True and hit["probe"] == "xss_blind"
        assert hit["details"]["parameter"] == "subject" and hit["url"] == f"{BASE}/contact"
        assert hit["evidence_capture_ids"] == result["evidence_capture_ids"]
        assert blind_hits(env.gateway, later, "other") == []

    def test_json_fields_are_planted(self, env) -> None:
        values = blind_site(env, renders=True)
        result = blind(env, location="json", parameters=["message"], body={"message": "x"})
        assert result["vulnerable"] is True
        assert values and "<script src=" in values[0]

    def test_without_a_listener_nothing_is_sent(self, env) -> None:
        blind_site(env, renders=True)
        params = {"url": f"{BASE}/contact", "parameter": "message", "body": {"message": "x"}}
        result = run_probe(env.gateway, "acme", "xss_blind", params)
        assert result["vulnerable"] is None and "could not test" in result["summary"]
        assert env.web.seen == [] and planted(env.gateway, "acme") == []

    def test_bad_input(self, env) -> None:
        assert blind(env, parameters=[])["status"] == "error"
        assert blind(env, parameters=[f"f{n}" for n in range(6)])["status"] == "error"
        assert env.web.seen == []
