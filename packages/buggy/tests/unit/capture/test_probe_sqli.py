"""The ``sqli`` probe against a fake origin backed by a real SQLite database.

The vulnerable handlers build their SQL by string concatenation and run it,
so the probe's payloads are interpreted by an actual SQL engine; the safe
handlers run the same statements with bound parameters. Nothing here matches
on the probe's payload strings except where a test says so.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

import buggy.capture.gateway as gateway_module
from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.mcp_server import CaptureTools
from buggy.capture.probes import REGISTRY, describe, injection, run_probe
from buggy.capture.probes.injection import ERROR_SIGNATURES, MAX_REQUESTS, error_signatures

from .test_gateway import Site

BASE = "https://app.acme.test"
Handler = Callable[[str, dict[str, str], dict[str, str], bytes], tuple[int, object]]


class Clock:
    """The gateway's stopwatch, advanced by the fake origin instead of by waiting."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Dispatch(dict):
    """Lets :class:`Site` route by path: every lookup resolves to the app's handler."""

    def __init__(self, app: App) -> None:
        super().__init__()
        self.app = app

    def get(self, key, default=None):
        method, url = key
        return lambda headers, body: self.app.handle(method, url, headers, body)


class App:
    """A small shop with injectable and parameterised endpoints over one SQLite database."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE products (id INTEGER, name TEXT, category TEXT)")
        self.db.executemany(
            "INSERT INTO products VALUES (?, ?, ?)",
            [
                (1, "Walnut desk organiser", "Gifts"),
                (2, "Brass letter opener", "Gifts"),
                (3, "Linen notebook, ruled", "Gifts"),
                (4, "Steel ruler 30 cm", "Tools"),
            ],
        )
        self.db.execute("CREATE TABLE users (name TEXT, pin TEXT)")
        self.db.execute("INSERT INTO users VALUES ('alice', '4821')")
        self.db.execute("CREATE TABLE visits (ref TEXT)")
        self.db.execute("INSERT INTO visits VALUES ('home')")
        # What a DBMS delay function does to the response time, without the wait.
        self.db.create_function("SLEEP", 1, self._sleep)
        self.handlers: dict[str, Handler] = {}
        self.requests = 0

    def _sleep(self, seconds: float) -> int:
        self.clock.advance(float(seconds))
        return 0

    def handle(self, method: str, url: str, headers: dict[str, str], body: bytes):
        self.requests += 1
        parts = urlsplit(url)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        handler = self.handlers.get(parts.path)
        if handler is None:
            return 404, b"not found"
        return handler(method, query, headers, body)

    def rows(self, sql: str, args: tuple = ()) -> list[tuple]:
        return self.db.execute(sql, args).fetchall()


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    clock = Clock()
    # The gateway times each request with ``time.monotonic``; give it the fake clock.
    monkeypatch.setattr(
        gateway_module,
        "time",
        SimpleNamespace(monotonic=clock.monotonic, time=time.time, sleep=time.sleep),
    )
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        json.dumps(
            {
                "machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]},
                "approvals": {"state_changing": "not_required"},
            }
        )
    )
    site = Site()
    app = App(clock)
    site.routes = _Dispatch(app)
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    yield SimpleNamespace(gateway=gateway, site=site, app=app, clock=clock, roots=roots)
    gateway.store.close()


def probe(env, params: dict) -> dict:
    return run_probe(env.gateway, "acme", "sqli", params)


def check_evidence(env, result: dict) -> None:
    """Every request is evidence, each has a named role, and the bound holds."""
    ids = result["evidence_capture_ids"]
    details = result["details"]
    assert len(ids) == len(env.site.seen) == details["requests_sent"] <= MAX_REQUESTS == 9
    assert len(set(ids)) == len(ids)
    assert list(details["captures"].values()) == ids
    assert set(details["payloads"]) == set(details["captures"])
    for capture_id in ids:
        stored = env.gateway.store.get("acme", capture_id)
        assert stored is not None and stored.probe == "sqli"
    roles = list(details["captures"])
    if ids:
        assert roles[0] == "baseline"


def names(rows: list[tuple]) -> list[str]:
    return [row[0] for row in rows]


# ── the endpoints ────────────────────────────────────────────────────


def by_category_injectable(app: App) -> Handler:
    """Concatenated SQL, errors hidden: only the result set gives it away."""

    def handler(_method, query, _headers, _body):
        try:
            rows = app.rows(
                f"SELECT name FROM products WHERE category = '{query.get('category', '')}'"
            )
        except sqlite3.Error:
            rows = []
        return 200, {"products": names(rows)}

    return handler


def by_category_safe(app: App) -> Handler:
    def handler(_method, query, _headers, _body):
        rows = app.rows(
            "SELECT name FROM products WHERE category = ?", (query.get("category", ""),)
        )
        return 200, {"products": names(rows)}

    return handler


def by_id_injectable(app: App) -> Handler:
    def handler(_method, query, _headers, _body):
        try:
            rows = app.rows(f"SELECT name FROM products WHERE id = {query.get('id', '0')}")
        except sqlite3.Error:
            rows = []
        return (200, {"product": rows[0][0]}) if rows else (404, {"error": "no such product"})

    return handler


def by_id_safe(app: App) -> Handler:
    def handler(_method, query, _headers, _body):
        rows = app.rows("SELECT name FROM products WHERE id = ?", (query.get("id", "0"),))
        return (200, {"product": rows[0][0]}) if rows else (404, {"error": "no such product"})

    return handler


def search_error_leaking(app: App) -> Handler:
    """Concatenated LIKE query that prints the database's message on failure."""

    def handler(_method, query, _headers, _body):
        try:
            rows = app.rows(f"SELECT name FROM products WHERE name LIKE '%{query.get('q', '')}%'")
        except sqlite3.Error as exc:
            return 500, f"<h1>Error: SQLITE_ERROR: {exc}</h1>".encode()
        return 200, {"status": "success", "data": names(rows)}

    return handler


def search_safe(app: App) -> Handler:
    def handler(_method, query, _headers, _body):
        rows = app.rows("SELECT name FROM products WHERE name LIKE ?", (f"%{query.get('q', '')}%",))
        return 200, {"status": "success", "data": names(rows)}

    return handler


def track_blind(app: App, *, safe: bool = False) -> Handler:
    """Runs a query and always answers the same: only the response time can differ."""

    def handler(_method, query, _headers, _body):
        ref = query.get("ref", "")
        try:
            if safe:
                app.rows("SELECT ref FROM visits WHERE ref = ?", (ref,))
            else:
                app.rows(f"SELECT ref FROM visits WHERE ref = '{ref}'")
        except sqlite3.Error:
            pass
        app.clock.advance(0.02)
        return 200, {"ok": True}

    return handler


# ── (a) boolean ──────────────────────────────────────────────────────


class TestBoolean:
    def test_string_context_is_found_by_the_true_false_pair(self, env) -> None:
        env.app.handlers["/products"] = by_category_injectable(env.app)
        result = probe(env, {"url": f"{BASE}/products?category=Gifts", "parameter": "category"})
        assert result["status"] == "completed" and result["vulnerable"] is True, result
        assert result["class"] == "injection" and result["cwe"] == "CWE-89"
        details = result["details"]
        assert details["technique"] == "boolean"
        assert list(details["captures"]) == [
            "baseline",
            "baseline_repeat",
            "boolean_true_string",
            "boolean_false_string",
        ]
        assert details["payloads"]["boolean_true_string"] == "Gifts' AND '1'='1"
        assert details["payloads"]["boolean_false_string"] == "Gifts' AND '1'='2"
        (pair,) = details["boolean"]
        assert pair["positive"] and pair["true_similarity"] >= 0.95
        assert pair["false_similarity"] < 0.80
        assert "parameterised" in result["remediation"]
        check_evidence(env, result)
        # The payloads reached the origin in the named parameter, URL-encoded.
        sent = [parse_qs(urlsplit(url).query)["category"][0] for _m, url, _h, _b in env.site.seen]
        assert sent == ["Gifts", "Gifts", "Gifts' AND '1'='1", "Gifts' AND '1'='2"]

    def test_same_endpoint_with_bound_parameters_is_not_flagged(self, env) -> None:
        env.app.handlers["/products"] = by_category_safe(env.app)
        result = probe(env, {"url": f"{BASE}/products?category=Gifts", "parameter": "category"})
        assert result["status"] == "completed" and result["vulnerable"] is False, result
        assert result["details"]["technique"] is None
        assert [p["positive"] for p in result["details"]["boolean"]] == [False]
        # baseline x2, TRUE, FALSE, quote; no control (no signature), no timing (not asked).
        assert result["details"]["requests_sent"] == 5
        check_evidence(env, result)

    def test_numeric_context_uses_the_numeric_pair(self, env) -> None:
        env.app.handlers["/item"] = by_id_injectable(env.app)
        result = probe(env, {"url": f"{BASE}/item", "parameter": "id", "value": 2})
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "boolean"
        assert details["payloads"]["boolean_true_numeric"] == "2 AND 1=1"
        assert details["payloads"]["boolean_false_numeric"] == "2 AND 1=2"
        (pair,) = details["boolean"]  # found on the first pair: the string pair is not sent
        assert pair["variant"] == "numeric" and pair["false_status"] == 404
        check_evidence(env, result)

    def test_numeric_value_on_a_parameterised_endpoint_is_not_flagged(self, env) -> None:
        env.app.handlers["/item"] = by_id_safe(env.app)
        result = probe(env, {"url": f"{BASE}/item?id=2", "parameter": "id"})
        assert result["vulnerable"] is False, result
        assert [p["variant"] for p in result["details"]["boolean"]] == ["numeric", "string"]
        assert result["details"]["requests_sent"] == 7
        check_evidence(env, result)

    def _login(self, app: App, *, safe: bool, form: bool = False) -> Handler:
        def handler(method, _query, headers, body):
            assert method == "POST"
            if form:
                assert headers["content-type"] == "application/x-www-form-urlencoded"
                fields = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            else:
                assert headers["content-type"] == "application/json"
                fields = json.loads(body)["credentials"]
            user, pin = fields.get("user", ""), fields.get("pin", "")
            try:
                if safe:
                    rows = app.rows(
                        "SELECT name FROM users WHERE name = ? AND pin = ?", (user, pin)
                    )
                else:
                    rows = app.rows(
                        f"SELECT name FROM users WHERE name = '{user}' AND pin = '{pin}'"
                    )
            except sqlite3.Error:
                rows = []
            if rows:
                return 200, {"welcome": rows[0][0], "note": "session opened for this account"}
            return 401, {"error": "invalid credentials"}

        return handler

    @pytest.mark.parametrize("safe", [False, True])
    def test_json_body_parameter(self, env, safe: bool) -> None:
        env.app.handlers["/login"] = self._login(env.app, safe=safe)
        result = probe(
            env,
            {
                "url": f"{BASE}/login",
                "method": "POST",
                "location": "json",
                "parameter": "credentials.user",
                "body": {"credentials": {"user": "alice", "pin": "4821"}},
            },
        )
        assert result["vulnerable"] is (not safe), result
        if not safe:
            (pair,) = result["details"]["boolean"]
            assert pair["true_status"] == 200 and pair["false_status"] == 401
        # The other field is sent unchanged in every request.
        assert all(json.loads(b)["credentials"]["pin"] == "4821" for *_x, b in env.site.seen)
        check_evidence(env, result)

    @pytest.mark.parametrize("safe", [False, True])
    def test_form_body_parameter(self, env, safe: bool) -> None:
        env.app.handlers["/login"] = self._login(env.app, safe=safe, form=True)
        result = probe(
            env,
            {
                "url": f"{BASE}/login",
                "method": "POST",
                "location": "form",
                "parameter": "user",
                "body": "user=alice&pin=4821",
            },
        )
        assert result["vulnerable"] is (not safe), result
        assert all(parse_qs(b.decode())["pin"] == ["4821"] for *_x, b in env.site.seen)
        check_evidence(env, result)


# ── (b) error, (e) error-like pages ──────────────────────────────────


class TestError:
    def test_error_leak_is_found_and_confirmed_by_the_two_quote_control(self, env) -> None:
        env.app.handlers["/search"] = search_error_leaking(env.app)
        result = probe(env, {"url": f"{BASE}/search?q=ruler", "parameter": "q"})
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "error" and details["dbms_guess"] == "sqlite"
        # The LIKE context swallows the boolean pair, so the error signal decides.
        assert [p["positive"] for p in details["boolean"]] == [False]
        assert list(details["captures"])[-2:] == ["error_quote", "error_control"]
        assert details["payloads"]["error_quote"] == "ruler'"
        assert details["payloads"]["error_control"] == "ruler''"
        assert details["error"]["quote_status"] == 500
        assert details["error"]["control_status"] == 200
        assert details["error"]["signatures"] and details["error"]["control_signatures"] == []
        assert details["requests_sent"] == 6
        check_evidence(env, result)

    def test_parameterised_search_is_not_flagged(self, env) -> None:
        env.app.handlers["/search"] = search_safe(env.app)
        result = probe(env, {"url": f"{BASE}/search?q=ruler", "parameter": "q"})
        assert result["vulnerable"] is False, result
        assert result["details"]["error"]["signatures"] == []
        assert "error_control" not in result["details"]["captures"]
        check_evidence(env, result)

    def test_error_like_page_for_every_input_is_not_flagged(self, env) -> None:
        # A help page that quotes DBMS error text and echoes the input, whatever it is.
        def handler(_method, query, _headers, _body):
            page = (
                "<p>Troubleshooting: 'You have an error in your SQL syntax' means the report "
                f"filter is malformed.</p><p>Your filter: {query.get('q', '')}</p>"
            )
            return 200, page.encode()

        env.app.handlers["/help"] = handler
        result = probe(env, {"url": f"{BASE}/help?q=ruler", "parameter": "q"})
        assert result["vulnerable"] is False, result
        assert result["details"]["error"]["signatures"] == []  # already in the baseline
        check_evidence(env, result)

    def test_two_quote_control_stops_a_page_that_errors_on_any_quote(self, env) -> None:
        # An input filter that rejects every quote character with an error-like page
        # that reflects the input. One quote and two quotes look the same to it.
        def handler(_method, query, _headers, _body):
            q = query.get("q", "")
            if "'" in q:
                return 400, f"ORA-01756: quoted string not properly terminated: {q}".encode()
            return 200, {"status": "success", "data": [q]}

        env.app.handlers["/filter"] = handler
        result = probe(env, {"url": f"{BASE}/filter?q=ruler", "parameter": "q"})
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        details = result["details"]
        assert details["technique"] is None
        assert details["error"]["signatures"] and details["error"]["control_signatures"]
        assert details["error"]["confirmed"] is False
        assert "one quote AND for two quotes" in result["summary"]
        check_evidence(env, result)

    def test_status_change_without_a_dbms_message_is_not_a_finding(self, env) -> None:
        def handler(_method, query, _headers, _body):
            q = query.get("q", "")
            return (500, b"Internal Server Error") if q.count("'") % 2 else (200, {"data": [q]})

        env.app.handlers["/quiet"] = handler
        result = probe(env, {"url": f"{BASE}/quiet?q=ruler", "parameter": "q"})
        assert result["vulnerable"] is False, result
        assert "without a DBMS error message" in result["details"]["error"]["note"]
        check_evidence(env, result)

    def test_signature_list_covers_five_dbms_families(self) -> None:
        assert set(ERROR_SIGNATURES) == {"sqlite", "mysql", "postgresql", "mssql", "oracle"}
        assert all(len(patterns) >= 3 for patterns in ERROR_SIGNATURES.values())

    @pytest.mark.parametrize(
        ("family", "message"),
        [
            ("sqlite", "SQLITE_ERROR: near \"'%'\": syntax error"),
            ("sqlite", "<title>Error: near &quot;&#39;%&#39;&quot;: syntax error</title>"),
            ("sqlite", "sqlite3.OperationalError: unrecognized token: \"'ruler''\""),
            ("mysql", "You have an error in your SQL syntax; check the manual that corresponds"),
            ("mysql", "Warning: mysqli_fetch_assoc() expects parameter 1 to be mysqli_result"),
            ("postgresql", 'ERROR: unterminated quoted string at or near "\'" LINE 1'),
            ("postgresql", 'org.postgresql.util.PSQLException: ERROR: syntax error at or near "x"'),
            ("mssql", "Unclosed quotation mark after the character string 'ruler''."),
            ("mssql", "System.Data.SqlClient.SqlException: Incorrect syntax near 'x'."),
            ("oracle", "ORA-01756: quoted string not properly terminated"),
            ("oracle", "ORA-00933: SQL command not properly ended"),
            # Error pages that print only a stack trace through the ORM's query runner.
            (
                "sqlite",
                "at Query.run (/app/node_modules/sequelize/lib/dialects/sqlite/query.js:183:12)",
            ),
            (
                "mysql",
                "at Query.run (/app/node_modules/sequelize/lib/dialects/mysql/query.js:52:25)",
            ),
            (
                "postgresql",
                "at Query.run (C:\\app\\node_modules\\sequelize\\lib\\dialects\\postgres\\query.js:50:25)",
            ),
        ],
    )
    def test_real_error_messages_are_recognised(self, family: str, message: str) -> None:
        assert family in {hit[0] for hit in error_signatures(message)}

    @pytest.mark.parametrize(
        "body",
        [
            '{"status":"success","data":[]}',
            "No products match O'Brien's search for \"near\" syntax.",
            "We could not find that page. Error 404.",
            "Oracle Corporation was founded in 1977; its SQL server competes with Microsoft's.",
            "at Model.findAll (/app/node_modules/sequelize/lib/model.js:1140:12)",
        ],
    )
    def test_ordinary_pages_carry_no_signature(self, body: str) -> None:
        assert error_signatures(body) == []


# ── (c) time ─────────────────────────────────────────────────────────


class TestTime:
    PARAMS = {"url": f"{BASE}/track?ref=home", "parameter": "ref", "allow_time": True}

    def test_blind_endpoint_is_found_by_delay_with_a_zero_delay_control(self, env) -> None:
        env.app.handlers["/track"] = track_blind(env.app)
        result = probe(env, self.PARAMS)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "time" and details["dbms_guess"] == "mysql"
        assert list(details["captures"])[-2:] == ["time_delay_mysql", "time_control_mysql"]
        assert "SLEEP(3)" in details["payloads"]["time_delay_mysql"]
        assert "SLEEP(0)" in details["payloads"]["time_control_mysql"]
        (tried,) = details["time"]["tried"]
        assert tried["delay_extra_ms"] >= 2500 and tried["control_extra_ms"] <= 1000
        # Boolean and error really were negative first.
        assert [p["positive"] for p in details["boolean"]] == [False]
        assert details["error"]["signatures"] == []
        check_evidence(env, result)
        # The recorded captures carry the injected clock's timings.
        delayed = env.gateway.store.get("acme", details["captures"]["time_delay_mysql"])
        assert delayed.elapsed_ms >= 3000

    def test_time_payloads_are_not_sent_unless_asked(self, env) -> None:
        env.app.handlers["/track"] = track_blind(env.app)
        result = probe(env, {k: v for k, v in self.PARAMS.items() if k != "allow_time"})
        assert result["vulnerable"] is False, result
        assert "time" not in result["details"]
        assert not any("SLEEP" in url or "pg_sleep" in url for _m, url, _h, _b in env.site.seen)
        assert result["details"]["requests_sent"] == 5
        check_evidence(env, result)

    def test_parameterised_endpoint_never_delays(self, env) -> None:
        env.app.handlers["/track"] = track_blind(env.app, safe=True)
        result = probe(env, self.PARAMS)
        assert result["vulnerable"] is False, result
        timing = result["details"]["time"]
        assert [t["dbms"] for t in timing["tried"]] == ["mysql", "postgresql", "oracle"]
        assert all(t["delay_extra_ms"] < 2500 for t in timing["tried"])
        assert result["details"]["requests_sent"] == 8  # no delay seen, so no control sent
        check_evidence(env, result)

    def test_last_dbms_family_fits_in_the_request_bound(self, env) -> None:
        # A backend where only the third family's delay function exists. This handler
        # stands in for an Oracle database, so it does look at the payload text.
        def handler(_method, query, _headers, _body):
            if "RECEIVE_MESSAGE(CHR(98),3)" in query.get("ref", ""):
                env.clock.advance(3.0)
            env.clock.advance(0.02)
            return 200, {"ok": True}

        env.app.handlers["/track"] = handler
        result = probe(env, self.PARAMS)
        assert result["vulnerable"] is True, result
        assert result["details"]["dbms_guess"] == "oracle"
        assert result["details"]["requests_sent"] == 9
        check_evidence(env, result)

    def test_slow_control_means_cannot_tell(self, env) -> None:
        # Slow for anything that is not the plain value: the delay is not caused by SLEEP(3).
        def handler(_method, query, _headers, _body):
            env.clock.advance(4.0 if "SELECT" in query.get("ref", "") else 0.02)
            return 200, {"ok": True}

        env.app.handlers["/track"] = handler
        result = probe(env, self.PARAMS)
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert result["details"]["technique"] is None
        (tried,) = result["details"]["time"]["tried"]
        assert tried["delay_extra_ms"] >= 2500 and tried["control_extra_ms"] > 1000
        check_evidence(env, result)

    def test_a_delay_below_the_threshold_is_not_a_finding(self, env) -> None:
        def handler(_method, query, _headers, _body):
            env.clock.advance(2.0 if "SELECT" in query.get("ref", "") else 0.02)
            return 200, {"ok": True}

        env.app.handlers["/track"] = handler
        result = probe(env, self.PARAMS)
        assert result["vulnerable"] is False, result
        check_evidence(env, result)

    def test_numeric_value_keeps_one_request_for_the_control(self, env) -> None:
        # 2 baselines + 2 boolean pairs + quote = 7, so one delay family and its control fit.
        def handler(_method, query, _headers, _body):
            try:
                env.app.rows(f"SELECT name FROM products WHERE id = {query.get('id', '0')}")
            except sqlite3.Error:
                pass
            env.clock.advance(0.02)
            return 200, {"ok": True}

        env.app.handlers["/seen"] = handler
        result = probe(env, {"url": f"{BASE}/seen?id=4", "parameter": "id", "allow_time": True})
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "time"
        assert details["payloads"]["time_delay_mysql"].startswith("4 AND 3=(SELECT")
        assert details["time"]["skipped_for_request_bound"] == ["postgresql", "oracle"]
        assert details["requests_sent"] == 9
        check_evidence(env, result)


# ── (f) cannot tell ──────────────────────────────────────────────────


class TestCannotTell:
    def test_unstable_page(self, env) -> None:
        def handler(_method, _query, _headers, _body):
            return 200, (chr(ord("A") + env.app.requests) * 300).encode()

        env.app.handlers["/feed"] = handler
        result = probe(env, {"url": f"{BASE}/feed?tag=news", "parameter": "tag"})
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert "unstable" in result["summary"]
        assert list(result["details"]["captures"]) == ["baseline", "baseline_repeat"]
        check_evidence(env, result)

    def test_unstable_status(self, env) -> None:
        def handler(_method, _query, _headers, _body):
            return (200 if env.app.requests % 2 else 429), b"same body"

        env.app.handlers["/feed"] = handler
        result = probe(env, {"url": f"{BASE}/feed?tag=news", "parameter": "tag"})
        assert result["vulnerable"] is None and len(env.site.seen) == 2

    @pytest.mark.parametrize("failure", ["server_error", "transport"])
    def test_failed_baseline(self, env, failure: str) -> None:
        def handler(_method, _query, _headers, _body):
            if failure == "transport":
                raise ConnectionResetError("connection reset by peer")
            return 503, b"maintenance"

        env.app.handlers["/feed"] = handler
        result = probe(env, {"url": f"{BASE}/feed?tag=news", "parameter": "tag"})
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert "baseline request failed" in result["summary"]
        assert len(env.site.seen) == 1  # nothing is injected into a broken endpoint
        check_evidence(env, result)

    def test_out_of_scope_target_is_refused_and_nothing_is_sent(self, env) -> None:
        result = probe(env, {"url": "https://other.test/products?category=Gifts", "parameter": "category"})  # fmt: skip
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert result["details"]["refusal"]["code"] == "OUT_OF_SCOPE"
        assert result["evidence_capture_ids"] == [] and env.site.seen == []

    def test_state_changing_method_waits_for_approval(self, env) -> None:
        (env.roots.control / "acme" / "roe.json").write_text(
            json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}})
        )
        result = probe(
            env,
            {
                "url": f"{BASE}/login",
                "method": "POST",
                "location": "json",
                "parameter": "user",
                "body": {"user": "alice"},
            },
        )
        assert result["vulnerable"] is None, result
        refusal = result["details"]["refusal"]
        assert refusal["code"] == "APPROVAL_REQUIRED" and refusal["request_id"].startswith("apr-")
        assert env.site.seen == []

    def test_request_bound_is_enforced_by_the_sender(self, env, monkeypatch) -> None:
        env.app.handlers["/products"] = by_category_safe(env.app)
        monkeypatch.setattr(injection, "MAX_REQUESTS", 3)
        result = probe(env, {"url": f"{BASE}/products?category=Gifts", "parameter": "category"})
        assert result["vulnerable"] is None, result
        assert "request bound" in result["summary"] and len(env.site.seen) == 3

    def test_payload_request_without_an_answer(self, env) -> None:
        safe = by_category_safe(env.app)

        def handler(method, query, headers, body):
            if "AND" in query.get("category", ""):
                raise TimeoutError("timed out")
            return safe(method, query, headers, body)

        env.app.handlers["/products"] = handler
        result = probe(env, {"url": f"{BASE}/products?category=Gifts", "parameter": "category"})
        assert result["vulnerable"] is None, result
        assert "got no answer" in result["summary"]
        check_evidence(env, result)


# ── inputs, registry, payload hygiene ────────────────────────────────


class TestContract:
    def test_registered_and_described(self) -> None:
        spec = REGISTRY["sqli"]
        assert (spec.vuln_class, spec.cwe, spec.state_changing) == ("injection", "CWE-89", False)
        assert spec.run is injection.sqli
        assert list(REGISTRY)[-1] == "sqli"  # appended, existing order untouched
        (described,) = [d for d in describe() if d["probe"] == "sqli"]
        assert {"url", "method", "parameter", "location", "value", "body", "headers"} <= set(
            described["params"]
        )

    def test_probe_list_and_probe_run_tools_expose_it(self, env) -> None:
        tools = CaptureTools(env.gateway, engagement="acme")
        listed = {p["probe"]: p for p in tools.probe_list()["probes"]}
        assert listed["sqli"]["class"] == "injection" and listed["sqli"]["cwe"] == "CWE-89"
        env.app.handlers["/products"] = by_category_injectable(env.app)
        result = tools.probe_run(
            "acme",
            "sqli",
            json.dumps({"url": f"{BASE}/products?category=Gifts", "parameter": "category"}),
        )
        assert result["vulnerable"] is True and result["details"]["technique"] == "boolean"
        json.dumps(result)  # the whole result is JSON-serialisable

    @pytest.mark.parametrize(
        "params",
        [
            {"url": f"{BASE}/products"},  # no parameter
            {"parameter": "category"},  # no url
            {"url": f"{BASE}/products", "parameter": "category"},  # no baseline value anywhere
            {"url": f"{BASE}/products?category=Gifts", "parameter": "category", "location": "cookie"},
            {"url": f"{BASE}/login", "parameter": "user", "location": "json", "body": "[1]"},
            {"url": f"{BASE}/login", "parameter": "user", "location": "json", "body": "{not json"},
            {"url": f"{BASE}/login", "parameter": "user", "location": "json", "body": {"user": None}},
            {"url": f"{BASE}/login", "parameter": "user", "location": "form", "body": ["user"]},
        ],
    )  # fmt: skip
    def test_bad_input_is_an_error_and_sends_nothing(self, env, params: dict) -> None:
        result = probe(env, params)
        assert result["status"] == "error", result
        assert env.site.seen == []

    def test_other_query_parameters_and_headers_are_preserved(self, env) -> None:
        env.app.handlers["/products"] = by_category_safe(env.app)
        probe(
            env,
            {
                "url": f"{BASE}/products?page=2&category=Gifts&sort=name",
                "parameter": "category",
                "headers": {"Authorization": "Bearer t0ken"},
            },
        )
        assert len(env.site.seen) == 5
        for _method, url, headers, _body in env.site.seen:
            query = parse_qs(urlsplit(url).query)
            assert query["page"] == ["2"] and query["sort"] == ["name"]
            assert headers["authorization"] == "Bearer t0ken"

    def test_payloads_are_fixed_bounded_and_read_only(self) -> None:
        fixed = [
            *injection.BOOLEAN_STRING,
            *injection.BOOLEAN_NUMERIC,
            injection.QUOTE,
            injection.QUOTE_PAIR,
            *(
                condition.format(seconds=seconds)
                for _family, condition in injection.TIME_CONDITIONS
                for seconds in (0, injection.DELAY_SECONDS)
            ),
        ]
        assert injection.DELAY_SECONDS == 3 and len(injection.TIME_CONDITIONS) <= 3
        for payload in fixed:
            upper = payload.upper()
            for forbidden in (
                "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "UNION", ";",
                "LOAD_FILE", "OUTFILE", "XP_", "UTL_", "COPY", "BENCHMARK", "WAITFOR",
            ):  # fmt: skip
                assert forbidden not in upper, payload
