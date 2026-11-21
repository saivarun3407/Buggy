"""Probe sweep plan: which read-only probes to run on which inputs.

Fixed rules, no network and no model. :func:`plan` reads the recon records
(``parameter``, ``http_service``, ``graphql``) and returns the probe runs that
are worth making, most valuable first, within a budget. The caller sends each
step to the capture server's ``probe_run``; a positive result is queued,
re-proven and graded there, by code.

Only what cannot change state is planned:

* query-string parameters of ``GET`` requests, never a body, a header, a
  cookie or a path segment;
* never a parameter that looks like a credential (hint ``auth-like``, or an
  example the pipeline redacted);
* only probes whose requests are read-only: ``sqli`` (no time payloads),
  ``xss_reflected``, ``ssti``, ``open_redirect``, ``path_traversal``, ``cors``
  and ``graphql_checks``. Probes that write, or that need test accounts, are
  left to a run the operator approves.

Which probe a parameter gets is decided by its hints:

==============  =====================================
``file-like``   ``path_traversal``
``url-like``    ``open_redirect``
``id-like``     ``sqli``
``numeric``     ``sqli``
(none of them)  ``sqli``, ``xss_reflected``, ``ssti``
==============  =====================================

Every live service gets one ``cors`` run and every GraphQL endpoint one
``graphql_checks`` run.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlencode, urlsplit

DEFAULT_BUDGET = 40
MAX_BUDGET = 500
#: The same parameter name on one host is probed on at most this many URLs.
MAX_URLS_PER_NAME = 2
MAX_SERVICES = 10
MAX_GRAPHQL = 5
REDACTED = "<redacted>"

#: Lower runs first. The order follows what a positive is worth.
PRIORITY: dict[str, int] = {
    "graphql_checks": 0,
    "path_traversal": 1,
    "sqli": 2,
    "ssti": 3,
    "open_redirect": 4,
    "xss_reflected": 5,
    "cors": 6,
}
TEXT_PROBES = ("sqli", "xss_reflected", "ssti")
#: A baseline value when recon saw the parameter without one.
DEFAULT_VALUE = {"path_traversal": "index.html", "open_redirect": "/", "sqli": "1"}


def _attrs(record: dict[str, Any]) -> dict[str, Any]:
    attrs = record.get("attrs")
    return attrs if isinstance(attrs, dict) else {}


def _http_url(value: Any) -> str:
    text = str(value or "").strip()
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    return text if parts.scheme in ("http", "https") and parts.hostname else ""


def probes_for(hints: list[str]) -> tuple[str, ...]:
    """The read-only probes a query parameter with these hints gets; ``()`` for a credential."""
    if "auth-like" in hints:
        return ()
    chosen: list[str] = []
    if "file-like" in hints:
        chosen.append("path_traversal")
    if "url-like" in hints:
        chosen.append("open_redirect")
    if "id-like" in hints or "numeric" in hints:
        chosen.append("sqli")
    return tuple(chosen) or TEXT_PROBES


def _query_parameters(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """GET query parameters by URL, each ``{"name", "example", "hints"}``."""
    by_url: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        attrs = _attrs(record)
        url = _http_url(attrs.get("url"))
        name = str(attrs.get("name") or "")
        method = str(attrs.get("method") or "GET").upper()
        if not url or not name or attrs.get("location") != "query" or method != "GET":
            continue
        if urlsplit(url).query or urlsplit(url).fragment:
            continue  # a parameter record's URL carries no query; anything else is not ours
        hints = [str(h) for h in attrs.get("hints") or [] if isinstance(h, str)]
        by_url[url].append(
            {"name": name, "example": str(attrs.get("example") or ""), "hints": hints}
        )
    return by_url


def _with_siblings(url: str, parameters: list[dict[str, Any]], target: str, value: str) -> str:
    """The URL with the target parameter and its siblings' known values in the query.

    A sibling whose example was redacted (a credential) is left out.
    """
    pairs = [(target, value)]
    pairs += [
        (p["name"], p["example"])
        for p in sorted(parameters, key=lambda p: p["name"])
        if p["name"] != target and p["example"] and p["example"] != REDACTED
    ]
    return f"{url}?{urlencode(pairs)}"


def _parameter_steps(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    per_name: dict[tuple[str, str, str], int] = defaultdict(int)
    by_url = _query_parameters(records)
    for url in sorted(by_url):
        host = urlsplit(url).netloc.lower()
        for parameter in sorted(by_url[url], key=lambda p: p["name"]):
            if parameter["example"] == REDACTED:
                continue
            for probe in probes_for(parameter["hints"]):
                key = (host, parameter["name"], probe)
                if per_name[key] >= MAX_URLS_PER_NAME:
                    continue
                per_name[key] += 1
                value = parameter["example"] or DEFAULT_VALUE.get(probe, "test")
                steps.append(
                    {
                        "probe": probe,
                        "host": host,
                        "params": {
                            "url": _with_siblings(url, by_url[url], parameter["name"], value),
                            "parameter": parameter["name"],
                            "method": "GET",
                            "location": "query",
                        },
                        "why": f"query parameter {parameter['name']!r}"
                        + (f" ({', '.join(parameter['hints'])})" if parameter["hints"] else ""),
                    }
                )
    return steps


def _endpoint_steps(records: list[dict[str, Any]], probe: str, cap: int, why: str) -> list[dict]:
    seen: list[str] = []
    for record in records:
        url = _http_url(_attrs(record).get("url")) or _http_url(record.get("value"))
        if url and url not in seen:
            seen.append(url)
    return [
        {
            "probe": probe,
            "host": urlsplit(url).netloc.lower(),
            "params": {"url": url},
            "why": why,
        }
        for url in sorted(seen)[:cap]
    ]


def plan(
    records: dict[str, list[dict[str, Any]]], *, budget: int = DEFAULT_BUDGET
) -> dict[str, Any]:
    """The probe runs to make, in order, and how many were left out by the budget.

    Returns ``{"steps": [{"probe", "params", "host", "why"}], "considered": n,
    "left_out": n}``. The first run of every probe on every host comes before
    anyone's second, so a small budget still touches every host.
    """
    budget = max(0, min(int(budget), MAX_BUDGET))
    steps = _endpoint_steps(
        records.get("graphql", []), "graphql_checks", MAX_GRAPHQL, "GraphQL endpoint"
    )
    steps += _parameter_steps(records.get("parameter", []))
    steps += _endpoint_steps(records.get("http_service", []), "cors", MAX_SERVICES, "live service")

    turn: dict[tuple[str, str], int] = defaultdict(int)
    ordered: list[tuple[int, int, str, int, dict[str, Any]]] = []
    for index, step in enumerate(steps):
        key = (step["host"], step["probe"])
        ordered.append((turn[key], PRIORITY[step["probe"]], step["host"], index, step))
        turn[key] += 1
    ordered.sort(key=lambda row: row[:4])
    chosen = [row[4] for row in ordered[:budget]]
    return {"steps": chosen, "considered": len(steps), "left_out": len(steps) - len(chosen)}


# ── runs that can change state: planned here, sent only after approval ──

DEFAULT_STATE_BUDGET = 15
STATE_METHODS = ("POST", "PUT", "PATCH")
#: Lower runs first.
STATE_PRIORITY: dict[str, int] = {
    "numeric_boundary": 0,
    "mass_assignment": 1,
    "sqli": 2,
    "command_injection": 3,
    "ssti": 4,
    "xss_reflected": 5,
}
#: A field with one of these words in its name carries a business quantity.
QUANTITY_WORDS = frozenset(
    {
        "quantity", "qty", "amount", "price", "total", "count", "balance", "points", "discount",
        "credit", "credits", "rate", "fee", "cost", "units", "stock", "limit",
    }
)  # fmt: skip
#: A field with one of these words in its name may reach a system command.
COMMAND_WORDS = frozenset({"host", "hostname", "ip", "domain", "cmd", "command", "exec", "ping"})
#: Fields a client should not be able to set; each must be refused or ignored.
PRIVILEGED_FIELDS: dict[str, Any] = {"role": "admin", "isAdmin": True, "admin": True}
_WORDS = re.compile(r"[A-Za-z][a-z0-9]*|[A-Z]+(?![a-z])")


def _name_words(name: str) -> set[str]:
    """The lower-cased words of a field name (``orderLines[].unitPrice`` -> order, lines, ...)."""
    return {word.lower() for word in _WORDS.findall(name.split(".")[-1])}


def _body_value(parameter: dict[str, Any]) -> Any:
    """A plausible valid value for a body field: its example, else by what its name says."""
    example = parameter["example"]
    if example and example != REDACTED:
        try:
            return int(example)
        except ValueError:
            return example
    hints = parameter["hints"]
    if "numeric" in hints or "id-like" in hints or _name_words(parameter["name"]) & QUANTITY_WORDS:
        return 1
    return "test"


def _put(body: dict[str, Any], name: str, value: Any) -> None:
    """Set a dotted field in a JSON body; ``a[].b`` becomes a one-element list of objects."""
    cursor: Any = body
    parts = name.split(".")
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        listed = part.endswith("[]")
        key = part[:-2] if listed else part
        if not key:
            return
        if listed:
            items = cursor.setdefault(key, [{}] if not last else [value])
            if last or not isinstance(items, list) or not items or not isinstance(items[0], dict):
                return
            cursor = items[0]
        elif last:
            cursor[key] = value
        else:
            nxt = cursor.setdefault(key, {})
            if not isinstance(nxt, dict):
                return
            cursor = nxt


def _body_operations(records: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Body fields by ``(method, url)`` for the methods that write."""
    operations: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        attrs = _attrs(record)
        url = _http_url(attrs.get("url"))
        name = str(attrs.get("name") or "")
        method = str(attrs.get("method") or "").upper()
        if not url or not name or attrs.get("location") != "body" or method not in STATE_METHODS:
            continue
        hints = [str(h) for h in attrs.get("hints") or [] if isinstance(h, str)]
        operations[(method, url)].append(
            {"name": name, "example": str(attrs.get("example") or ""), "hints": hints}
        )
    return operations


def _field_probes(parameter: dict[str, Any]) -> tuple[str, ...]:
    """The state-changing probes one body field gets. A credential field gets none."""
    hints, words = parameter["hints"], _name_words(parameter["name"])
    if "auth-like" in hints or parameter["example"] == REDACTED or "[]" in parameter["name"]:
        return ()
    if words & QUANTITY_WORDS:
        return ("numeric_boundary",)
    if words & COMMAND_WORDS:
        return ("command_injection", "sqli")
    if "numeric" in hints or "id-like" in hints:
        return ("sqli",)
    return ("sqli", "ssti", "xss_reflected")


def plan_state_changing(
    records: dict[str, list[dict[str, Any]]],
    *,
    budget: int = DEFAULT_STATE_BUDGET,
    identity: str = "",
) -> dict[str, Any]:
    """Probe runs on request bodies of write operations. Each needs the operator's approval.

    Read from ``parameter`` records whose location is ``body`` (API
    specifications and contracts). For every write operation a JSON body is
    built from the fields recon knows, with their examples or a value their
    name implies. Planned per operation: one ``mass_assignment`` run, and per
    field ``numeric_boundary`` (a business quantity), ``command_injection``
    (a field that names a host or a command) or the injection probes.

    Nothing here is sent by planning. The caller hands each step to
    ``probe_run``, where a run that can change state is held until the
    operator approves that run. ``identity`` (a declared test account) is put
    on every step when given, because write operations usually need a login.
    """
    budget = max(0, min(int(budget), MAX_BUDGET))
    steps: list[dict[str, Any]] = []
    for (method, url), fields in sorted(_body_operations(records.get("parameter", [])).items()):
        fields = sorted(fields, key=lambda f: f["name"])
        body: dict[str, Any] = {}
        for parameter in fields:
            if parameter["example"] != REDACTED and "auth-like" not in parameter["hints"]:
                _put(body, parameter["name"], _body_value(parameter))
        if not body:
            continue
        host = urlsplit(url).netloc.lower()
        common: dict[str, Any] = {"url": url, "method": method, "body": body}
        if identity:
            common["identity"] = identity
        steps.append(
            {
                "probe": "mass_assignment",
                "host": host,
                "params": {**common, "extra_fields": dict(PRIVILEGED_FIELDS)},
                "why": f"{method} operation that stores an object",
            }
        )
        for parameter in fields:
            for probe in _field_probes(parameter):
                params = dict(common)
                if probe == "numeric_boundary":
                    params.update({"field": parameter["name"], "values": [-1, 0]})
                else:
                    params.update({"parameter": parameter["name"], "location": "json"})
                    if probe == "sqli":
                        params["allow_time"] = False
                steps.append(
                    {
                        "probe": probe,
                        "host": host,
                        "params": params,
                        "why": f"body field {parameter['name']!r} of {method} {urlsplit(url).path}",
                    }
                )
    turn: dict[tuple[str, str], int] = defaultdict(int)
    ordered: list[tuple[int, int, str, int, dict[str, Any]]] = []
    for index, step in enumerate(steps):
        key = (step["host"], step["probe"])
        ordered.append((turn[key], STATE_PRIORITY[step["probe"]], step["host"], index, step))
        turn[key] += 1
    ordered.sort(key=lambda row: row[:4])
    chosen = [row[4] for row in ordered[:budget]]
    return {"steps": chosen, "considered": len(steps), "left_out": len(steps) - len(chosen)}


__all__ = [
    "DEFAULT_BUDGET",
    "DEFAULT_STATE_BUDGET",
    "MAX_BUDGET",
    "PRIORITY",
    "STATE_PRIORITY",
    "plan",
    "plan_state_changing",
    "probes_for",
]
