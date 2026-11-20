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


# ── ssti and command_injection (task C3) ─────────────────────────────
#
# DVGA hands two GraphQL arguments to a shell: importPaste builds
# ``curl <scheme>://<host>:<port><path>``, and systemDiagnostics runs ``cmd``
# for the administrator. Both are found, by an arithmetic echo, with the
# probe aimed at the GraphQL variable that carries the argument. The same
# probe leaves alone an argument that only reaches SQL, and the diagnostics
# command when the password check stops it before the shell.
#
# Neither application evaluates a request value as a template within one
# request, so ``ssti`` has no lab positive, on purpose: here it gets two real
# negatives, and its positives are proven in the unit tests, one engine per
# syntax family.

_IMPORT_PASTE = (
    "mutation($h: String!, $o: Int, $p: String!, $s: String!) "
    "{ importPaste(host: $h, port: $o, path: $p, scheme: $s) { result } }"
)
_DIAGNOSTICS = (
    "query($u: String, $w: String, $c: String) "
    "{ systemDiagnostics(username: $u, password: $w, cmd: $c) }"
)
# DVGA's documented default administrator account.
_DVGA_ADMIN = {"u": "admin", "w": "changeme"}


def _check_execution_evidence(lab: Lab, result: dict[str, Any], bound: int) -> None:  # noqa: F811
    """Every capture id is a real recorded request of this probe, within its bound."""
    ids = result["evidence_capture_ids"]
    details = result["details"]
    assert 2 <= len(ids) == details["requests_sent"] <= bound == details["max_requests"]
    assert list(details["captures"].values()) == ids
    assert list(details["captures"])[:2] == ["baseline", "baseline_repeat"]
    for capture_id in ids:
        capture = lab.gateway.store.get(ENGAGEMENT, capture_id)
        assert capture is not None and capture.probe == result["probe"] and not capture.error


def _graphql_data(lab: Lab, result: dict[str, Any], role: str) -> Any:  # noqa: F811
    capture = lab.gateway.store.get(ENGAGEMENT, result["details"]["captures"][role])
    return json.loads(capture.response_body)["data"]


def _assert_only_the_arithmetic_echo_ran(result: dict[str, Any], value: str) -> None:
    """Found on the first payload, and that payload is the fixed echo of a multiplication."""
    details = result["details"]
    assert details["technique"] == "output" and details["separator"] == "semicolon"
    assert list(details["captures"])[2:] == ["output_semicolon", "output_control"]
    numbers = details["numbers"]
    assert 1000 <= numbers["a"] <= 9999 and 1000 <= numbers["b"] <= 9999
    assert numbers["product"] == numbers["a"] * numbers["b"]
    assert details["payloads"]["output_semicolon"] == (
        f"{value};echo $(({numbers['a']}*{numbers['b']}))"
    )
    assert details["payloads"]["output_control"] == f"{value}{numbers['control']}"
    assert "time" not in details  # no delay payload was needed


@pytest.mark.parametrize(
    ("variable", "value"), [("p", "/"), ("h", "127.0.0.1")], ids=["path", "host"]
)
def test_command_injection_probe_finds_import_paste(
    lab: Lab,  # noqa: F811
    variable: str,
    value: str,
) -> None:
    # The baseline points curl at a closed port on the container's own loopback:
    # it fails at once and prints nothing, and no other machine is contacted.
    variables = {"h": "127.0.0.1", "o": 9, "p": "/", "s": "http"}
    assert variables[variable] == value
    result = lab.probe(
        "command_injection",
        {
            "url": f"{lab.dvga}/graphql",
            "method": "POST",
            "location": "json",
            "parameter": f"variables.{variable}",
            "body": {"query": _IMPORT_PASTE, "variables": variables},
        },
    )
    _found(result)
    assert result["class"] == "injection" and result["cwe"] == "CWE-78"
    _assert_only_the_arithmetic_echo_ran(result, value)
    _check_execution_evidence(lab, result, 11)
    # The shell printed the product; with plain digits in the same place it printed nothing.
    product = str(result["details"]["numbers"]["product"])
    assert _graphql_data(lab, result, "baseline")["importPaste"]["result"] == ""
    proof = _graphql_data(lab, result, "output_semicolon")["importPaste"]["result"]
    assert proof.startswith(product)
    assert _graphql_data(lab, result, "output_control")["importPaste"]["result"] == ""


def test_command_injection_probe_finds_system_diagnostics(lab: Lab) -> None:  # noqa: F811
    result = lab.probe(
        "command_injection",
        {
            "url": f"{lab.dvga}/graphql",
            "method": "POST",
            "location": "json",
            "parameter": "variables.c",
            "body": {"query": _DIAGNOSTICS, "variables": {**_DVGA_ADMIN, "c": "whoami"}},
        },
    )
    _found(result)
    assert result["class"] == "injection" and result["cwe"] == "CWE-78"
    _assert_only_the_arithmetic_echo_ran(result, "whoami")
    _check_execution_evidence(lab, result, 11)
    # The command's own output, then one more line: the product.
    product = str(result["details"]["numbers"]["product"])
    whoami = _graphql_data(lab, result, "baseline")["systemDiagnostics"]
    assert whoami.strip() and product not in whoami
    proof = _graphql_data(lab, result, "output_semicolon")["systemDiagnostics"]
    assert proof == f"{whoami}{product}\n"
    assert product not in _graphql_data(lab, result, "output_control")["systemDiagnostics"]


def _assert_no_command_signal(result: dict[str, Any]) -> None:
    """All five echoes and all three waits were sent, and none of them did anything."""
    details = result["details"]
    assert details["technique"] is None and "separator" not in details
    assert [t["name"] for t in details["output"]] == [
        "semicolon",
        "pipe",
        "backtick",
        "subshell",
        "windows_ampersand",
    ]
    assert all(t["outcome"] == "not_evaluated" for t in details["output"])
    assert [t["name"] for t in details["time"]["tried"]] == [
        "semicolon",
        "pipe",
        "windows_ampersand",
    ]
    assert all(t["delay_extra_ms"] < 2500 for t in details["time"]["tried"])
    assert details["requests_sent"] == 10


def test_command_injection_probe_does_not_flag_the_sql_filter(lab: Lab) -> None:  # noqa: F811
    # pastes(filter:) is concatenated into SQL (the sqli test above finds it), but
    # it never reaches a shell: an injectable argument is not every kind of injectable.
    title = _own_paste(lab)
    result = lab.probe(
        "command_injection",
        {
            "url": f"{lab.dvga}/graphql",
            "method": "POST",
            "location": "json",
            "parameter": "variables.f",
            "body": {"query": _PASTES_BY_FILTER, "variables": {"f": title}},
        },
    )
    _not_found(result)
    _assert_no_command_signal(result)
    _check_execution_evidence(lab, result, 11)
    # The argument is used: the baseline found this test's paste.
    assert [p["title"] for p in _graphql_data(lab, result, "baseline")["pastes"]] == [title]


def test_command_injection_probe_does_not_flag_a_command_the_login_check_stops(
    lab: Lab,  # noqa: F811
) -> None:
    # The same cmd argument as above, with a wrong password: the resolver answers
    # before the shell is involved, so nothing is executed and nothing is flagged.
    result = lab.probe(
        "command_injection",
        {
            "url": f"{lab.dvga}/graphql",
            "method": "POST",
            "location": "json",
            "parameter": "variables.c",
            "body": {
                "query": _DIAGNOSTICS,
                "variables": {"u": "admin", "w": "not-the-password", "c": "whoami"},
            },
        },
    )
    _not_found(result)
    _assert_no_command_signal(result)
    _check_execution_evidence(lab, result, 11)
    assert _graphql_data(lab, result, "output_semicolon") == _graphql_data(lab, result, "baseline")


def test_ssti_probe_does_not_flag_a_reflecting_error_page(lab: Lab) -> None:  # noqa: F811
    # /redirect?to=<unknown> answers 406 with an HTML page that prints the target.
    # Every canary comes back as the text that was sent, never as its product.
    result = lab.probe("ssti", {"url": f"{lab.juice}/redirect?to=x", "parameter": "to"})
    _not_found(result)
    assert result["class"] == "injection" and result["cwe"] == "CWE-1336"
    details = result["details"]
    assert details["engine_family"] is None and details["baseline"]["status"] == 406
    assert [c["outcome"] for c in details["canaries"]] == ["reflected_as_text"] * 5
    assert details["requests_sent"] == 7 and "canary_control" not in details["captures"]
    _check_execution_evidence(lab, result, 8)
    numbers = details["numbers"]
    page = lab.gateway.store.get(ENGAGEMENT, details["captures"]["canary_jinja2_twig"])
    assert f"x{{{{{numbers['a']}*{numbers['b']}}}}}".encode() in page.response_body
    assert str(numbers["product"]).encode() not in page.response_body


def test_ssti_probe_does_not_flag_a_graphql_argument(lab: Lab) -> None:  # noqa: F811
    title = _own_paste(lab)
    result = lab.probe(
        "ssti",
        {
            "url": f"{lab.dvga}/graphql",
            "method": "POST",
            "location": "json",
            "parameter": "variables.f",
            "body": {"query": _PASTES_BY_FILTER, "variables": {"f": title}},
        },
    )
    _not_found(result)
    assert [c["outcome"] for c in result["details"]["canaries"]] == ["not_evaluated"] * 5
    _check_execution_evidence(lab, result, 8)


def test_execution_probes_are_listed(lab: Lab) -> None:  # noqa: F811
    from buggy.capture.probes import describe

    listed = {d["probe"]: d for d in describe()}
    assert (listed["ssti"]["class"], listed["ssti"]["cwe"]) == ("injection", "CWE-1336")
    assert listed["ssti"]["state_changing"] is False
    shell = listed["command_injection"]
    assert (shell["class"], shell["cwe"], shell["state_changing"]) == ("injection", "CWE-78", True)
    # And they refuse to leave the lab like every other probe.
    for name in ("ssti", "command_injection"):
        result = lab.probe(name, {"url": "http://172.17.0.1/lookup?host=x", "parameter": "host"})
        assert result["vulnerable"] is None
        assert result["details"]["refusal"]["code"] == "OUT_OF_SCOPE"


# ── open_redirect, path_traversal and cors (task C4) ─────────────────
#
# Juice Shop's /redirect?to= checks its allow-list with a substring test: the
# target must CONTAIN an allowed URL. The plain form, //host, https:host and
# the userinfo form are all refused (406); the fragment form puts the allowed
# URL after "#", passes the substring test and sends the browser to the
# random host. That is the known bypass, and the probe finds it.
#
# Juice Shop's /ftp/<file> null-byte read (eastere.gg%2500.md) is a file-type
# bypass inside the ftp directory, not a traversal: any value with a "/" is
# refused. So path_traversal reports False there, honestly, and does not
# claim the null-byte file read as a traversal. Neither app reads files
# outside a directory, so path_traversal has no lab positive (its positives
# are in the unit tests). Neither app allows a credentialed cross-origin read
# either: Juice Shop answers Access-Control-Allow-Origin: * (informational
# only), DVGA sends no CORS headers at all.

_ALLOWED_REDIRECT = "https://" + "github.com/juice-shop/juice-shop"  # on Juice Shop's allow-list
_RANDOM_HOST = r"bg[0-9a-f]{12}\.example"


def _check_c4_evidence(lab: Lab, result: dict[str, Any], bound: int) -> None:  # noqa: F811
    """Every capture id is a real recorded request of this probe, within its bound."""
    ids = result["evidence_capture_ids"]
    details = result["details"]
    assert 1 <= len(ids) == details["requests_sent"] <= bound == details["max_requests"]
    assert list(details["captures"].values()) == ids
    assert next(iter(details["captures"])) == "baseline" and details["control"]
    for capture_id in ids:
        capture = lab.gateway.store.get(ENGAGEMENT, capture_id)
        assert capture is not None and capture.probe == result["probe"] and not capture.error


def test_open_redirect_probe_finds_the_juice_shop_allowlist_bypass(lab: Lab) -> None:  # noqa: F811
    result = lab.probe(
        "open_redirect", {"url": f"{lab.juice}/redirect?to={_ALLOWED_REDIRECT}", "parameter": "to"}
    )
    _found(result)
    assert result["class"] == "open_redirect" and result["cwe"] == "CWE-601"
    details = result["details"]
    host = details["random_host"]
    assert re.fullmatch(_RANDOM_HOST, host)
    assert details["technique"] == "fragment"
    # The allow-listed original value redirects to its own (allowed) host: the control holds.
    assert details["baseline"]["status"] == 302
    assert [r["host"] for r in details["baseline"]["redirects"]] == ["github.com"]
    # Every other form was refused by the allow-list.
    assert [(t["form"], t["status"]) for t in details["tried"]] == [
        ("plain", 406),
        ("scheme_relative", 406),
        ("missing_slashes", 406),
        ("userinfo", 406),
        ("fragment", 302),
    ]
    proof = lab.gateway.store.get(ENGAGEMENT, details["captures"]["fragment"])
    location = next(v for k, v in proof.response_headers.items() if k.lower() == "location")
    assert location == f"https://{host}/#{_ALLOWED_REDIRECT}"
    _check_c4_evidence(lab, result, 6)


def test_open_redirect_probe_does_not_flag_a_search_parameter(lab: Lab) -> None:  # noqa: F811
    result = lab.probe(
        "open_redirect", {"url": f"{lab.juice}/rest/products/search?q=apple", "parameter": "q"}
    )
    _not_found(result)
    details = result["details"]
    assert details["requests_sent"] == 6 and details["technique"] is None
    assert all(t["outcome"] == "refused" and t["status"] == 200 for t in details["tried"])
    _check_c4_evidence(lab, result, 6)


@pytest.mark.parametrize(
    "value", ["legal.md", "eastere.gg%2500.md"], ids=["plain-file", "null-byte-file-type-bypass"]
)
def test_path_traversal_probe_does_not_claim_the_ftp_null_byte_read(
    lab: Lab,  # noqa: F811
    value: str,
) -> None:
    result = lab.probe(
        "path_traversal",
        {
            "url": f"{lab.juice}/ftp/{{file}}",
            "parameter": "file",
            "location": "path",
            "value": value,
        },
    )
    _not_found(result)
    assert result["class"] == "file_handling" and result["cwe"] == "CWE-22"
    details = result["details"]
    # The baseline really reads the file (for the second value, through the
    # file-type bypass) ...
    assert details["baseline"]["status"] == 200 and details["baseline"]["markers_present"] == []
    assert details["extension"] == ".md"
    # ... but every traversal is refused (403 for a "/", 400 for a NUL with a "/").
    assert details["requests_sent"] == 10
    assert all(t["status"] in (400, 403) and t["marker"] is False for t in details["tried"])
    _check_c4_evidence(lab, result, 10)


@pytest.mark.parametrize("app", ["juice", "dvga"])
def test_cors_probe_finds_no_credentialed_cross_origin_read(lab: Lab, app: str) -> None:  # noqa: F811
    url = {
        "juice": f"{lab.juice}/rest/products/search?q=apple",
        "dvga": f"{lab.dvga}/graphql?query=%7B__typename%7D",
    }[app]
    result = lab.probe("cors", {"url": url})
    _not_found(result)
    assert result["class"] == "misconfiguration" and result["cwe"] == "CWE-942"
    details = result["details"]
    assert list(details["captures"]) == ["baseline", "origin_random", "origin_null"]
    if app == "juice":
        assert details["informational"] == ["wildcard-without-credentials"]
        assert details["responses"]["origin_random"]["allow_origin"] == "*"
    else:
        assert details["informational"] == []
        assert details["responses"]["origin_random"]["allow_origin"] == ""
    _check_c4_evidence(lab, result, 3)


def test_c4_probes_are_listed_and_stay_in_the_lab(lab: Lab) -> None:  # noqa: F811
    from buggy.capture.probes import describe

    listed = {d["probe"]: d for d in describe()}
    assert (listed["open_redirect"]["class"], listed["open_redirect"]["cwe"]) == (
        "open_redirect",
        "CWE-601",
    )
    assert listed["path_traversal"]["class"] == "file_handling"
    assert listed["cors"]["class"] == "misconfiguration"
    for name in ("open_redirect", "path_traversal", "cors"):
        result = lab.probe(name, {"url": "http://172.17.0.1/go?to=x", "parameter": "to"})
        assert result["vulnerable"] is None
        assert result["details"]["refusal"]["code"] == "OUT_OF_SCOPE"
