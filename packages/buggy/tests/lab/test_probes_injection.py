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
import re
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


# ── xss_reflected (task C2) ──────────────────────────────────────────
#
# Neither application has a server-side reflected-HTML sink that can be broken
# out of: Juice Shop's XSS challenges are DOM-based or stored (the server
# answers with JSON or the same single-page shell), and DVGA renders user data
# in the browser. So there is no lab positive here, on purpose. What the lab
# does have is three real reflections that must NOT be reported: one into
# JSON, one into an entity-encoded error page, one into an escaped script
# string. The probe's positives are proven in the unit tests, where each
# context has a vulnerable endpoint next to the safe one.

_MARKER = r"bg[0-9a-f]{12}"


def _check_xss_evidence(lab: Lab, result: dict[str, Any]) -> None:  # noqa: F811
    """Every capture id is a real recorded request of this probe, within the bound."""
    ids = result["evidence_capture_ids"]
    details = result["details"]
    assert 1 <= len(ids) == details["requests_sent"] <= 6
    assert list(details["captures"].values()) == ids and list(details["captures"])[0] == "baseline"
    assert details["browser_confirmation"] == "not_run"
    for capture_id in ids:
        capture = lab.gateway.store.get(ENGAGEMENT, capture_id)
        assert capture is not None and capture.probe == "xss_reflected" and not capture.error
    tested = [context for context in details["contexts"] if context["probe"]]
    assert [context["capture"] for context in tested] == ids[1:]


def test_xss_probe_reports_json_reflection_as_not_exploitable(lab: Lab) -> None:  # noqa: F811
    # /rest/track-order/<id> echoes the id as "orderId" in a JSON document (the
    # page that later writes it into the DOM is a DOM XSS, out of this probe's reach).
    result = lab.probe(
        "xss_reflected",
        {"url": f"{lab.juice}/rest/track-order/{{id}}", "parameter": "id", "location": "path"},
    )
    _not_found(result)
    assert result["class"] == "xss" and result["cwe"] == "CWE-79"
    details = result["details"]
    (context,) = details["contexts"]
    assert context["context"] == "json_body" and context["vulnerable"] is False
    assert "does not render JSON as HTML" in context["reason"]
    assert "JSON" in result["summary"]
    assert details["response_headers"]["content_type"].startswith("application/json")
    assert details["response_headers"]["x_content_type_options"] == "nosniff"
    # Decided from the harmless marker alone: one request, no markup sent.
    assert details["requests_sent"] == 1 and re.fullmatch(_MARKER, details["payloads"]["baseline"])
    _check_xss_evidence(lab, result)
    # The value really is reflected, as a JSON string, in the response it was judged on.
    baseline = lab.gateway.store.get(ENGAGEMENT, details["captures"]["baseline"])
    assert baseline.status == 200
    assert json.loads(baseline.response_body)["data"][0]["orderId"] == details["marker"]


def test_xss_probe_does_not_flag_an_entity_encoded_error_page(lab: Lab) -> None:  # noqa: F811
    # /redirect?to=<unknown> answers 406 with an HTML error page that prints the
    # target twice, in <title> and in <h2>, both entity-encoded.
    result = lab.probe("xss_reflected", {"url": f"{lab.juice}/redirect?to=x", "parameter": "to"})
    _not_found(result)
    details = result["details"]
    assert details["baseline"]["status"] == 406 and details["baseline"]["reflections"] == 2
    assert details["response_headers"]["content_type"].startswith("text/html")
    by_element = {context.get("element", ""): context for context in details["contexts"]}
    assert set(by_element) == {"", "title"}
    assert all(context["context"] == "html_text" for context in details["contexts"])
    assert all(context["vulnerable"] is False for context in details["contexts"])
    assert details["requests_sent"] == 3
    _check_xss_evidence(lab, result)
    # The probe strings came back, with their angle brackets as entities and no new element.
    for context in details["contexts"]:
        body = lab.gateway.store.get(ENGAGEMENT, context["capture"]).response_body.decode()
        marker = context["marker"]
        assert f"&lt;{marker}x&gt;" in body and f"<{marker}x>" not in body


def test_xss_probe_does_not_flag_an_escaped_script_string(lab: Lab) -> None:  # noqa: F811
    # DVGA's GraphiQL page (served to a browser's Accept header) writes ?query=
    # into a double-quoted string inside a <script>, escaped for that context.
    result = lab.probe(
        "xss_reflected",
        {
            "url": f"{lab.dvga}/graphiql?query=x",
            "parameter": "query",
            "headers": {"Accept": "text/html"},
        },
    )
    _not_found(result)
    details = result["details"]
    (context,) = details["contexts"]
    assert context["context"] == "script_string" and context["quote"] == '"'
    assert context["vulnerable"] is False and context["reflections"] >= 1
    assert details["requests_sent"] == 2
    _check_xss_evidence(lab, result)
    # Neither way out worked: the quote is backslash-escaped and "<" is \u003c.
    body = lab.gateway.store.get(ENGAGEMENT, context["capture"]).response_body.decode()
    marker = context["marker"]
    assert f'\\";{marker}//\\u003c/script\\u003e' in body
    assert f"<{marker}x>" not in body


def test_xss_probe_is_listed(lab: Lab) -> None:  # noqa: F811
    from buggy.capture.probes import describe

    (spec,) = [d for d in describe() if d["probe"] == "xss_reflected"]
    assert spec["class"] == "xss" and spec["cwe"] == "CWE-79" and spec["state_changing"] is False
    # And it refuses to leave the lab like every other probe.
    result = lab.probe("xss_reflected", {"url": "http://172.17.0.1/search?q=x", "parameter": "q"})
    assert result["vulnerable"] is None
    assert result["details"]["refusal"]["code"] == "OUT_OF_SCOPE"
