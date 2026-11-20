"""The ``sqli`` probe against OWASP Juice Shop and DVGA (both on SQLite).

Three parameters reach a concatenated SQL statement and are found: Juice
Shop's product search and login e-mail by the database's error message, and
DVGA's ``pastes(filter:)`` by the TRUE / FALSE pair. Four parameters on the
same applications are bound or hashed before they reach the statement and are
not. The probe only appends its fixed read-only payloads to a value; nothing
is extracted, the only objects involved are ones this test creates, and login
is only ever attempted with a wrong password.

Opt-in, like the other lab tests:

    BUGGY_LAB=1 uv run pytest packages/buggy/tests/lab/test_probes_injection.py -q
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from typing import Any

import pytest

from .test_probes_find_known_bugs import (
    ENGAGEMENT,
    Lab,
    _found,
    _not_found,
    lab,  # noqa: F401 - the module-scoped lab fixture
)

_SHARED = bool(os.environ.get("BUGGY_LAB_JUICE_URL") and os.environ.get("BUGGY_LAB_DVGA_URL"))

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        os.environ.get("BUGGY_LAB") != "1", reason="set BUGGY_LAB=1 to run the lab tests"
    ),
    pytest.mark.skipif(
        not _SHARED and shutil.which("docker") is None, reason="docker CLI not available"
    ),
]


def _check_evidence(lab: Lab, result: dict[str, Any]) -> None:  # noqa: F811
    """Every capture id is a real recorded request of this probe, within the bound."""
    ids = result["evidence_capture_ids"]
    details = result["details"]
    assert 2 <= len(ids) == details["requests_sent"] <= 9
    assert list(details["captures"].values()) == ids
    for capture_id in ids:
        capture = lab.gateway.store.get(ENGAGEMENT, capture_id)
        assert capture is not None and capture.probe == "sqli" and not capture.error


# ── injectable (Juice Shop: js-sqli-search, js-sqli-login) ───────────


def test_sqli_probe_finds_product_search_injection(lab: Lab) -> None:  # noqa: F811
    result = lab.probe(
        "sqli", {"url": f"{lab.juice}/rest/products/search?q=apple", "parameter": "q"}
    )
    _found(result)
    assert result["class"] == "injection" and result["cwe"] == "CWE-89"
    details = result["details"]
    # The value sits inside LIKE '%...%', which swallows the boolean pair; the
    # database's own error message, absent for a balanced '' pair, is the proof.
    assert details["technique"] == "error" and details["dbms_guess"] == "sqlite"
    assert details["payloads"]["error_quote"] == "apple'"
    assert details["payloads"]["error_control"] == "apple''"
    assert details["error"]["quote_status"] == 500
    assert details["error"]["control_status"] == 200
    assert details["error"]["control_signatures"] == []
    _check_evidence(lab, result)
    quote = lab.gateway.store.get(ENGAGEMENT, details["captures"]["error_quote"])
    assert b"SQLITE_ERROR" in quote.response_body
    control = lab.gateway.store.get(ENGAGEMENT, details["captures"]["error_control"])
    assert b"SQLITE_ERROR" not in control.response_body


@pytest.mark.parametrize(
    "headers",
    [{}, {"Accept": "application/json"}],
    ids=["html-error-page", "json-error-body"],
)
def test_sqli_probe_finds_login_injection(lab: Lab, headers: dict[str, str]) -> None:  # noqa: F811
    account = lab.juice_account()
    result = lab.probe(
        "sqli",
        {
            "url": f"{lab.juice}/rest/user/login",
            "method": "POST",
            "location": "json",
            "parameter": "email",
            # A wrong password: the baseline is a stable 401 and nobody is logged in.
            "body": {"email": account["email"], "password": "not-the-password"},
            "headers": headers,
        },
    )
    _found(result)
    details = result["details"]
    assert details["technique"] == "error" and details["dbms_guess"] == "sqlite"
    assert details["baseline"]["status"] == 401
    assert details["payloads"]["error_quote"] == account["email"] + "'"
    assert details["error"]["quote_status"] == 500
    assert details["error"]["control_status"] == 401  # two quotes: an ordinary failed login
    _check_evidence(lab, result)


# ── injectable, boolean (DVGA: dvga-sqli-pastes-filter) ──────────────

_PASTES_BY_FILTER = "query($f: String) { pastes(public: true, filter: $f) { id title content } }"
_SEARCH = "query($k: String) { search(keyword: $k) { ... on PasteObject { id title } } }"


def _own_paste(lab: Lab) -> str:  # noqa: F811
    """Create a public paste with a unique title; return the title."""
    title = f"c1-sqli-{uuid.uuid4().hex[:12]}"
    created = lab.send_json(
        "POST",
        f"{lab.dvga}/graphql",
        {
            "query": "mutation($t: String) { createPaste(title: $t, content: "
            '"sqli probe fixture", public: true) { paste { id title } } }',
            "variables": {"t": title},
        },
    )
    assert created["data"]["createPaste"]["paste"]["title"] == title, created
    return title


def test_sqli_probe_finds_graphql_filter_injection(lab: Lab) -> None:  # noqa: F811
    title = _own_paste(lab)
    result = lab.probe(
        "sqli",
        {
            "url": f"{lab.dvga}/graphql",
            "method": "POST",
            "location": "json",
            "parameter": "variables.f",
            "body": {"query": _PASTES_BY_FILTER, "variables": {"f": title}},
        },
    )
    _found(result)
    details = result["details"]
    assert details["technique"] == "boolean"
    assert details["payloads"]["boolean_true_string"] == title + "' AND '1'='1"
    (pair,) = details["boolean"]
    assert pair["true_similarity"] >= 0.95 and pair["false_similarity"] < 0.80
    _check_evidence(lab, result)
    # The TRUE condition returned this test's paste; the FALSE condition returned nothing.
    true = lab.gateway.store.get(ENGAGEMENT, details["captures"]["boolean_true_string"])
    false = lab.gateway.store.get(ENGAGEMENT, details["captures"]["boolean_false_string"])
    assert [p["title"] for p in json.loads(true.response_body)["data"]["pastes"]] == [title]
    assert json.loads(false.response_body)["data"]["pastes"] == []


def test_sqli_probe_does_not_flag_a_bound_graphql_argument(lab: Lab) -> None:  # noqa: F811
    # search(keyword:) goes through the ORM's bound LIKE: the argument is used
    # (the baseline finds the paste) but never becomes part of the statement.
    title = _own_paste(lab)
    body = {"query": _SEARCH, "variables": {"k": title}}
    baseline = lab.send_json("POST", f"{lab.dvga}/graphql", body)
    assert [p["title"] for p in baseline["data"]["search"]] == [title], baseline
    result = lab.probe(
        "sqli",
        {
            "url": f"{lab.dvga}/graphql",
            "method": "POST",
            "location": "json",
            "parameter": "variables.k",
            "body": body,
        },
    )
    _not_found(result)
    assert result["details"]["error"]["signatures"] == []
    _check_evidence(lab, result)


# ── not injectable: same application, safe parameters ────────────────


def test_sqli_probe_does_not_flag_a_parameter_the_endpoint_ignores(lab: Lab) -> None:  # noqa: F811
    result = lab.probe(
        "sqli",
        {
            "url": f"{lab.juice}/rest/admin/application-version?x=1",
            "parameter": "x",
            "allow_time": True,
        },
    )
    _not_found(result)
    details = result["details"]
    assert details["technique"] is None
    assert [pair["positive"] for pair in details["boolean"]] == [False, False]
    assert details["error"]["signatures"] == []
    # Numeric value: both boolean pairs ran, which leaves room for one delay payload.
    assert len(details["time"]["tried"]) == 1
    assert details["time"]["tried"][0]["delay_extra_ms"] < 2500
    _check_evidence(lab, result)


def test_sqli_probe_does_not_flag_a_bound_orm_filter(lab: Lab) -> None:  # noqa: F811
    # /api/Products filters by name through the ORM: the parameter IS used in a
    # query (the baseline returns the product), but as a bound value.
    url = f"{lab.juice}/api/Products?name=Apple%20Pomace"
    baseline = lab.send_json("GET", url)
    assert [p["name"] for p in baseline["data"]] == ["Apple Pomace"]
    result = lab.probe("sqli", {"url": url, "parameter": "name"})
    _not_found(result)
    assert result["details"]["error"]["signatures"] == []
    _check_evidence(lab, result)


def test_sqli_probe_does_not_flag_the_hashed_login_password(lab: Lab) -> None:  # noqa: F811
    # Same statement as the injectable email, but the password is hashed before
    # it is placed in the SQL, so no quote ever reaches the database.
    account = lab.juice_account()
    result = lab.probe(
        "sqli",
        {
            "url": f"{lab.juice}/rest/user/login",
            "method": "POST",
            "location": "json",
            "parameter": "password",
            "body": {"email": account["email"], "password": "not-the-password"},
        },
    )
    _not_found(result)
    assert result["details"]["baseline"]["status"] == 401
    _check_evidence(lab, result)


def test_sqli_probe_is_listed(lab: Lab) -> None:  # noqa: F811
    from buggy.capture.probes import describe

    (spec,) = [d for d in describe() if d["probe"] == "sqli"]
    assert spec["class"] == "injection" and spec["cwe"] == "CWE-89"
    # And it refuses to leave the lab like every other probe.
    result = lab.probe("sqli", {"url": "http://172.17.0.1/search?q=apple", "parameter": "q"})
    assert result["vulnerable"] is None
    assert result["details"]["refusal"]["code"] == "OUT_OF_SCOPE"
