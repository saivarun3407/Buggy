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


__all__ = ["DEFAULT_BUDGET", "MAX_BUDGET", "PRIORITY", "plan", "probes_for"]
