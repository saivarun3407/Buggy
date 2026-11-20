"""``similarity`` decides "same response" for the IDOR probe, the authz matrix and the verifier."""

from __future__ import annotations

import hashlib
import json
import time
from types import SimpleNamespace

from buggy.capture.probes.base import similarity


def _capture(body: str | dict | list):
    raw = body if isinstance(body, str) else json.dumps(body)
    return SimpleNamespace(
        response_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        response_body=raw.encode(),
        response_headers={},
    )


def _profile(n: int) -> dict:
    return {
        "user": {
            "id": n,
            "email": f"user{n}@acme.test",
            "role": "customer",
            "lastLoginIp": f"10.0.{n}.7",
            "profileImage": f"/assets/{n}.png",
        }
    }


def test_two_users_own_records_of_the_same_shape_are_not_the_same() -> None:
    # The old order-insensitive text ratio scored pairs like this at 0.95 or more.
    assert similarity(_capture(_profile(21)), _capture(_profile(22))) < 0.5


def test_the_same_record_with_one_volatile_field_is_still_the_same() -> None:
    first = {"order": {"id": 7, "items": [{"sku": f"a{i}", "qty": i} for i in range(30)]}}
    second = json.loads(json.dumps(first))
    first["servedAt"], second["servedAt"] = "12:00:01", "12:00:02"
    assert similarity(_capture(first), _capture(second)) >= 0.95


def test_identical_bodies_and_two_empty_bodies_score_one() -> None:
    assert similarity(_capture(_profile(1)), _capture(_profile(1))) == 1.0
    assert similarity(_capture(""), _capture("")) == 1.0


def test_json_key_order_does_not_matter_but_values_do() -> None:
    assert similarity(_capture('{"a": 1, "b": 2}'), _capture('{"b": 2, "a": 1}')) == 1.0
    assert similarity(_capture('{"a": 1, "b": 2}'), _capture('{"a": 2, "b": 1}')) == 0.0


def test_text_is_compared_in_order() -> None:
    words = [f"w{i}" for i in range(200)]
    forward = "<p>" + " ".join(words) + "</p>"
    backward = "<p>" + " ".join(reversed(words)) + "</p>"
    assert similarity(_capture(forward), _capture(backward)) < 0.6  # same characters, other page
    changed = forward.replace("w100 ", "w100x ")
    assert similarity(_capture(forward), _capture(changed)) > 0.98


def test_json_against_html_is_low() -> None:
    assert similarity(_capture(_profile(3)), _capture("<html><body>Forbidden</body></html>")) < 0.5


def test_large_bodies_are_compared_quickly() -> None:
    page = "\n".join(f"<li>row {i} of the listing</li>" for i in range(900))
    other = page.replace("row 450 ", "row 450 changed ")
    minified = "".join(f"<i>{i}</i>" for i in range(4000))
    started = time.monotonic()
    assert similarity(_capture(page), _capture(other)) > 0.98
    assert similarity(_capture(minified), _capture(minified + "<b>x</b>")) > 0.9
    assert time.monotonic() - started < 5
