"""Sibling search: a proven finding seeds leads on the other endpoints that look like it.

A bug is rarely alone. An IDOR proven on ``/api/Users/{id}`` is worth trying
on ``/api/Cards/{id}`` and ``/api/Addresss/{id}``; an injection proven in the
``q`` parameter is worth trying wherever else ``q`` is taken. From the recon
records (endpoints, URLs, API operations and parameters), :func:`rows` picks:

* **same route pattern**: an endpoint on the same host whose path has the
  same shape, with only the collection name before an id differing
  (``/api/Users/{id}`` -> ``/api/Cards/{id}``). A known collection without an
  id (``/api/Cards``) counts too, as ``/api/Cards/{id}``;
* **same parameter name**: another endpoint on the same host that takes a
  parameter of the same name.

Each is a row in the recon report's ranked shape (``class``, ``where``,
``why``, ``probe``) whose ``why`` names the original finding, so the existing
:func:`buggy.findings.candidates.from_ranked` turns it into a lead. A lead
still has to be proven like any other. Nothing here sends a request.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from buggy.findings.model import Finding, Status, normalize_endpoint

#: At most this many sibling leads per proven finding.
MAX_SIBLINGS = 20
ID = "{id}"
MANUAL = "http_send"

#: Recon record types whose value or ``attrs.url`` is an endpoint.
_URL_TYPES = ("endpoint", "url", "api_operation", "parameter")


def _attrs(record: dict[str, Any]) -> dict[str, Any]:
    raw = record.get("attrs")
    return raw if isinstance(raw, dict) else {}


def _known(records: dict[str, list[dict[str, Any]]]) -> dict[str, tuple[str, set[str]]]:
    """``{normalized endpoint: (method, parameter names)}`` of everything recon knows."""
    out: dict[str, tuple[str, set[str]]] = {}
    for kind in _URL_TYPES:
        for record in records.get(kind, []) or []:
            if not isinstance(record, dict):
                continue
            attrs = _attrs(record)
            url = str(attrs.get("url") or record.get("value") or "")
            if kind == "parameter":
                url = str(attrs.get("url") or "")
            if not url.startswith(("http://", "https://")):
                continue
            key = normalize_endpoint(url)
            method = str(attrs.get("method") or "GET").upper()
            names = {
                name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
            }
            if kind == "parameter" and attrs.get("name"):
                names.add(str(attrs["name"]))
            known_method, known_names = out.get(key, (method, set()))
            out[key] = (known_method if known_method != "GET" else method, known_names | names)
    return out


def _split(endpoint: str) -> tuple[str, list[str]]:
    """``(origin, path segments)`` of a normalized endpoint."""
    parts = urlsplit(endpoint)
    return f"{parts.scheme}://{parts.netloc}", parts.path.split("/")


def _same_pattern(mine: list[str], theirs: list[str]) -> bool:
    """Same shape, and only one collection name (the segment before an id) differs."""
    if len(mine) != len(theirs):
        return False
    different = [i for i, (a, b) in enumerate(zip(mine, theirs, strict=True)) if a != b]
    return (
        len(different) == 1
        and ID not in (mine[different[0]], theirs[different[0]])
        and different[0] + 1 < len(mine)
        and mine[different[0] + 1] == ID
    )


def _value(finding: Finding | dict[str, Any], key: str, attr: str = "") -> str:
    if isinstance(finding, Finding):
        return str(getattr(finding, attr or key) or "")
    return str(finding.get(key) or "")


def rows(
    finding: Finding | dict[str, Any],
    records: dict[str, list[dict[str, Any]]],
    *,
    limit: int = MAX_SIBLINGS,
) -> list[dict[str, str]]:
    """Ranked-shape lead rows for the siblings of ``finding`` among the recon ``records``."""
    vuln_class = _value(finding, "class", "vuln_class")
    endpoint = normalize_endpoint(_value(finding, "endpoint"))
    if not vuln_class or not endpoint.startswith(("http://", "https://")):
        return []
    finding_id = _value(finding, "id")
    title = _value(finding, "title") or f"{vuln_class} on {endpoint}"
    parameter = _value(finding, "parameter").split(" [variant:", 1)[0].strip()
    source = _value(finding, "source")
    probe = source.split(":", 1)[1] if source.startswith("probe:") else MANUAL
    reason = f"proven finding {finding_id} ({title})" if finding_id else f"proven {title}"
    origin, mine = _split(endpoint)
    out: list[dict[str, str]] = []
    seen = {endpoint}

    def add(where: str, method: str, why: str) -> None:
        if where in seen or len(out) >= limit:
            return
        seen.add(where)
        label = f"{method} {where}" if method and method != "GET" else where
        out.append({"class": vuln_class, "where": label, "why": why, "probe": probe})

    known = _known(records)
    if ID in mine:
        pattern = "/".join(mine)
        for key, (method, _names) in sorted(known.items()):
            their_origin, theirs = _split(key)
            if their_origin != origin:
                continue
            if _same_pattern(mine, theirs):
                add(key, method, f"same route pattern ({pattern}) as {reason}")
            elif (
                mine[-1] == ID
                and len(theirs) == len(mine) - 1
                and _same_pattern(mine, [*theirs, ID])
            ):
                add(
                    f"{key}/{ID}",
                    "GET",
                    f"same route pattern ({pattern}) as {reason}; recon knows the "
                    "collection, pick an object id from it",
                )
    if parameter:
        for key, (method, names) in sorted(known.items()):
            if _split(key)[0] == origin and parameter in names:
                add(key, method, f"takes parameter {parameter!r} like {reason}")
    return out


def seed(
    service: Any,
    engagement: str,
    finding_id: str,
    records: dict[str, list[dict[str, Any]]],
    *,
    actor: str = "siblings",
) -> dict[str, Any]:
    """Queue the sibling leads of one proven (``exploit_verified``) finding.

    Uses the existing lead path: :func:`candidates.from_ranked` then
    :func:`candidates.enqueue`. Returns the queue's answer plus ``rows``.
    """
    from buggy.findings.candidates import enqueue, from_ranked  # noqa: PLC0415

    finding = service.store.get(engagement, finding_id)
    if finding is None:
        return {"ok": False, "code": "UNKNOWN_FINDING", "detail": f"no finding {finding_id!r}"}
    if finding.status != Status.EXPLOIT_VERIFIED.value:
        return {
            "ok": False,
            "code": "NOT_PROVEN",
            "detail": f"{finding_id} is {finding.status}; only a proven finding seeds siblings",
        }
    found = rows(finding, records)
    queued = enqueue(service, from_ranked(found, engagement), actor)
    return {**queued, "rows": found}


def queue_rows(found: Iterable[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """The ``candidates_add`` items for sibling rows (the ``ranked`` key)."""
    return {"ranked": list(found)}


__all__ = ["MAX_SIBLINGS", "queue_rows", "rows", "seed"]
