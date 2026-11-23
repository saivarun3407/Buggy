"""Stage-level evaluation of one finished ``buggy hunt`` run against the lab ground truth.

Three steps, each plain code:

``collect``   read the run's files (scope, recon store, findings store, gateway
              ledger, approvals, hunt result, report, optional bridge call log)
              and reduce them to ``inputs.json``: only what scoring needs, URLs
              cut to host and path, no response bodies, no secrets.
``evaluate``  a pure function of ``inputs.json``: one row per ground-truth entry
              with five stage verdicts, a failure label for every missed entry,
              scope adherence apart from the results, and the compute used.
``render``    ``SCORECARD.md`` from ``evaluation.json`` and ``manifest.json``.

``verify`` re-runs ``evaluate`` and ``render`` from the files of a run directory
and fails when either differs from what is stored, so no number in a scorecard
can be edited by hand.

Stages, per ground-truth entry (each is judged on its own; they are not a strict
funnel, a probe can prove a bug no lead pointed at):

``recon``    a recon record of the app has a URL whose path matches the entry's
             location, or matches one of its ``pipeline_signals``.
``lead``     the findings store holds a lead or claim of the entry's class at its
             location (queued by recon, submitted by a probe, claimed by the agent).
``attempt``  a test request reached the location with the entry's method: a probe
             or recipe of the entry's class, or the agent's own request (not for an
             entry that covers a whole app); a proof also counts as an attempt.
``proof``    an exploit-verified finding fits the entry: its class and location,
             and a keyword of the entry in its title when the entry covers a whole
             app or API or the methods differ (one finding credits one entry).
``report``   that finding is in the report with the grade ``submit``.

A missed entry is labelled by the furthest stage it reached: ``not_in_recon``,
``no_lead``, ``not_attempted``, ``attempted_not_proven``, ``proven_but_held``.
``prohibited`` entries (denial of service) are never tested and never counted.
"""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import json
import re
import socket
import sqlite3
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from benchmark.lab import lab, scorer
from benchmark.lab.taxonomy import CLASSES, classify

SCHEMA_VERSION = 1
KIND = "lab-stage-eval"
INPUTS_FILE = "inputs.json"
EVALUATION_FILE = "evaluation.json"
MANIFEST_FILE = "manifest.json"
SCORECARD_FILE = "SCORECARD.md"
COMPARISON_FILE = "comparison.json"
COMPARISON_MD = "COMPARISON.md"

STAGES = ("recon", "lead", "attempt", "proof", "report")
# Furthest stage reached -> label of a missed entry. "found" reached the report.
LABELS = (
    "found",
    "proven_but_held",
    "attempted_not_proven",
    "not_attempted",
    "no_lead",
    "not_in_recon",
    "prohibited",
)
LABEL_TEXT = {
    "found": "found: proven and in the report as submit",
    "proven_but_held": "proven but held: verified, not graded submit",
    "attempted_not_proven": "attempted, not proven",
    "not_attempted": "lead queued, never tested",
    "no_lead": "seen by recon, no lead",
    "not_in_recon": "not found in recon",
    "prohibited": "prohibited (denial of service), never tested",
}

# Requests that map the application rather than test it.
CRAWL_PROBES = frozenset({"surface_crawl", "user_walk"})
# Vulnerability class of each probe tag. Mirrors buggy.capture.probes.registry
# (a unit test keeps them equal); authz_matrix is the access-control sweep.
PROBE_CLASSES = {
    "authz_matrix": "access_control",
    "clickjacking": "misconfiguration",
    "command_injection": "injection",
    "cors": "misconfiguration",
    "csrf": "csrf",
    "graphql_checks": "graphql",
    "idor": "access_control",
    "jwt_alg_none": "auth_session",
    "mass_assignment": "api",
    "numeric_boundary": "business_logic",
    "open_redirect": "open_redirect",
    "path_traversal": "file_handling",
    "rfi": "file_handling",
    "sqli": "injection",
    "ssrf_canary": "ssrf",
    "ssti": "injection",
    "xss_blind": "xss",
    "xss_reflected": "xss",
    "xss_stored": "xss",
}
# Gateway approval ids that mark the account module's own requests.
ACCOUNT_APPROVALS = frozenset({"account_creation", "internal_login"})
# Capture notes the account module writes (sign-up, log-in, session checks).
_ACCOUNT_NOTE = re.compile(r"^(register |log in |verify |account sign-up page)")
# Gateway refusals that are neither scope nor the internal-address block.
OTHER_REFUSALS = frozenset(
    {"NOT_A_DECLARED_LOGIN", "BAD_ACCOUNT_POLICY", "NOT_ENABLED", "NOT_AN_ACCOUNT_URL"}
)
INTERNAL_REFUSAL = "INTERNAL_ADDRESS"
SWEEP_KEYS = ("planned", "ran", "vulnerable", "not_vulnerable", "undecided", "refused")
LOCAL_SCOREBOARD_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
NOT_RECORDED = "not recorded"


class EvaluationError(ValueError):
    """The run's files cannot be evaluated as they stand."""


# ── small helpers ────────────────────────────────────────────────────


def _url_parts(text: str) -> tuple[str, str]:
    """(host, path) of a URL, a bare path or a bare host. Query strings are dropped."""
    text = (text or "").strip()
    if not text:
        return "", ""
    if "://" in text:
        parts = urlsplit(text)
        path = (parts.path or "/") + (f"#{parts.fragment}" if parts.fragment else "")
        return (parts.hostname or "").lower(), path
    if text.startswith("/"):
        return "", text.split("?", 1)[0]
    host, _, rest = text.partition("/")
    return host.split(":", 1)[0].lower(), "/" + rest.split("?", 1)[0]


_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+")


def _strip_queries(text: str) -> str:
    return _URL_IN_TEXT.sub(lambda m: m.group(0).split("?", 1)[0], text)


def _norm_path(path: str) -> str:
    """Path as matched against a location: ``{id}`` templates read as ``1``, no ``//``."""
    path = re.sub(r"\{[^}/]*\}", "1", path or "")
    return re.sub(r"/{2,}", "/", path)


def _loc_match(entry: scorer.Entry, path: str) -> bool:
    return bool(path) and re.search(entry.location, _norm_path(path)) is not None


def _method_ok(entry: scorer.Entry, method: str) -> bool:
    return entry.method in ("ANY", "") or not method or method.upper() == entry.method


def _classes_of(item: dict[str, Any]) -> set[str]:
    """The item's own class and the class its CWE or title points to."""
    inferred = classify(cwe=item.get("cwe") or None, title=str(item.get("title") or ""))
    return {str(item.get("class") or ""), inferred} - {"", "unclassified"}


def _keyword_hits(entry: scorer.Entry, title: str) -> int:
    lowered = title.lower()
    return sum(1 for keyword in entry.keywords if keyword in lowered)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except ValueError as exc:
        raise EvaluationError(f"{path} is not valid JSON: {exc}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sqlite_rows(path: Path, query: str, params: tuple[Any, ...]) -> list[sqlite3.Row] | None:
    """Rows of a read-only query, or ``None`` when the database is absent."""
    if not path.is_file():
        return None
    db = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    db.row_factory = sqlite3.Row
    try:
        return db.execute(query, params).fetchall()
    finally:
        db.close()


# ── collect ──────────────────────────────────────────────────────────


@functools.cache
def _attr_signals() -> tuple[tuple[str, dict[str, Any]], ...]:
    """(attribute, signal without its attribute test) for every signal that reads one."""
    out = []
    for app in scorer.available_apps():
        for entry in scorer.load_ground_truth(app):
            for signal in entry.pipeline_signals:
                if signal.get("attr"):
                    bare = {k: v for k, v in signal.items() if k not in ("attr", "attr_equals")}
                    out.append((str(signal["attr"]), bare))
    return tuple(out)


def _signal_attrs(record: dict[str, Any]) -> dict[str, Any]:
    """The attributes a ground-truth signal reads, kept only where type and value match.

    A header record keeps its value only when it is the header a signal names,
    so a session cookie never reaches ``inputs.json``.
    """
    kept: dict[str, Any] = {}
    attrs = _dict(record.get("attrs"))
    probe = {"type": record.get("type"), "value": record.get("value"), "attrs": {}}
    for name, bare in _attr_signals():
        if name in attrs and scorer._signal_matches(bare, probe):  # noqa: SLF001 - same package
            kept[name] = attrs[name]
    return kept


def _recon_inputs(data_root: Path, engagement: str) -> dict[str, Any]:
    if not (data_root / "recon.sqlite3").is_file():
        return {"available": False, "reason": "no recon.sqlite3 under the data root"}
    records, run = lab.load_store_records(data_root, engagement)
    from buggy.pipeline.store import ReconStore  # noqa: PLC0415 - needs the package

    store = ReconStore(data_root / "recon.sqlite3", read_only=True)
    try:
        drops = store.scope_drops(engagement, limit=100_000)
    finally:
        store.close()
    reduced = [
        {
            "asset": str(r.get("asset") or "").lower(),
            "type": str(r.get("type") or ""),
            "value": _strip_queries(str(r.get("value") or ""))[:240],
            "attrs": _signal_attrs(r),
        }
        for r in records
    ]
    reduced.sort(key=lambda r: (r["asset"], r["type"], r["value"]))
    return {
        "available": True,
        "run": None
        if run is None
        else {
            "id": run.get("id"),
            "status": run.get("status"),
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
        },
        "records": reduced,
        "scope_drops": dict(sorted(Counter(str(d.get("reason") or "") for d in drops).items())),
    }


def _findings_inputs(
    data_root: Path, engagement: str, report: dict[str, Any] | None
) -> dict[str, Any]:
    in_report: dict[str, str] = {}
    lead_ids: set[str] = set()
    if report:
        for item in report.get("findings") or []:
            in_report[str(item.get("id"))] = str(_dict(item.get("grade")).get("decision") or "")
        lead_ids = {str(item.get("id")) for item in report.get("leads") or []}
    rows = _sqlite_rows(
        data_root / "findings.sqlite3",
        "SELECT id, class, cwe, status, grade, source, method, endpoint, title, parameter"
        " FROM findings WHERE engagement = ? ORDER BY id",
        (engagement,),
    )
    source = "findings.sqlite3"
    items: list[dict[str, Any]] = []
    if rows is None:
        if not report:
            raise EvaluationError("neither findings.sqlite3 nor report.json is available")
        source = "report.json"
        for item in [*(report.get("findings") or []), *(report.get("leads") or [])]:
            rows_like = dict(item)
            rows_like["grade"] = _dict(item.get("grade")).get("decision")
            items.append(rows_like)
    else:
        items = [dict(row) for row in rows]
    out = []
    for item in items:
        host, path = _url_parts(str(item.get("endpoint") or ""))
        fid = str(item.get("id"))
        out.append(
            {
                "id": fid,
                "class": str(item.get("class") or ""),
                "cwe": str(item.get("cwe") or ""),
                "status": str(item.get("status") or ""),
                "grade": str(item.get("grade") or ""),
                "source": str(item.get("source") or ""),
                "method": str(item.get("method") or "").upper(),
                "host": host,
                "path": path,
                "title": str(item.get("title") or "")[:160],
                "in_report": fid in in_report,
                "report_decision": in_report.get(fid, ""),
                "report_lead": fid in lead_ids,
            }
        )
    out.sort(key=lambda f: f["id"])
    return {"source": source, "report_available": report is not None, "items": out}


def _ledger_inputs(
    audit: Path, control: Path, data_root: Path, engagement: str
) -> tuple[dict[str, Any], list[Path]]:
    from buggy.middleware._audit_sink import verify_ledger  # noqa: PLC0415
    from buggy.pipeline.scope import ScopeFilter  # noqa: PLC0415

    path = audit / "captures.jsonl"
    if not path.is_file():
        raise EvaluationError(f"no gateway ledger at {path}")
    scope = ScopeFilter.from_file(control / "roe.json")
    chain = verify_ledger(path)
    notes = {
        str(row["id"]): str(row["note"] or "")
        for row in _sqlite_rows(
            data_root / "captures.sqlite3",
            "SELECT id, note FROM captures WHERE engagement = ?",
            (engagement,),
        )
        or []
    }
    rows = []
    for raw in _read_jsonl(path):
        url = str(raw.get("url") or "")
        host, url_path = _url_parts(url)
        approval = str(raw.get("approval_id") or "")
        note = notes.get(str(raw.get("capture_id") or ""), "")
        rows.append(
            {
                "seq": raw.get("seq"),
                "ts": raw.get("ts"),
                "event": str(raw.get("event") or ""),
                "method": str(raw.get("method") or "").upper(),
                "host": host,
                "path": url_path,
                "status": raw.get("status"),
                "probe": str(raw.get("probe") or ""),
                "replay": bool(raw.get("replay_of")),
                "approval": approval
                if approval in ACCOUNT_APPROVALS or not approval
                else "approved",
                "account_note": bool(_ACCOUNT_NOTE.match(note)),
                "reason": str(raw.get("reason") or ""),
                "error": bool(raw.get("error")),
                "in_scope": scope.allows(url) if url else False,
                # Empty when the line names the scope evaluated here.
                "other_scope": ""
                if str(raw.get("scope_sha256") or "") in ("", scope.digest)
                else str(raw.get("scope_sha256")),
            }
        )
    approvals = audit / "approvals" / "requests.jsonl"
    decisions = control / "approvals" / "decisions.jsonl"
    requests = _read_jsonl(approvals)
    used = [p for p in (path, approvals, decisions, data_root / "captures.sqlite3") if p.is_file()]
    return (
        {
            "rows": rows,
            "chain": {
                "ok": chain.ok,
                "records_checked": chain.records_checked,
                "reason": chain.reason,
                "hmac_checked": False,
            },
            "scope_sha256": scope.digest,
            "approval_requests": [
                {
                    "tool": str(r.get("tool_name") or ""),
                    "method": str(_dict(r.get("tool_args_redacted")).get("method") or ""),
                    "host": _url_parts(str(_dict(r.get("tool_args_redacted")).get("url") or ""))[0],
                }
                for r in requests
            ],
            "approval_decisions": dict(
                sorted(
                    Counter(str(d.get("decision") or "") for d in _read_jsonl(decisions)).items()
                )
            ),
        },
        used,
    )


def _recipe_classes(data_root: Path, engagement: str) -> dict[str, list[str]]:
    """Classes each saved recipe tests (``recipes.sqlite3``): its own and its title's."""
    out: dict[str, list[str]] = {}
    rows = _sqlite_rows(
        data_root / "recipes.sqlite3",
        "SELECT name, recipe FROM recipes WHERE engagement = ?",
        (engagement,),
    )
    for row in rows or []:
        try:
            recipe = _dict(json.loads(row["recipe"] or "{}"))
        except ValueError:
            continue
        classes = _classes_of({"class": recipe.get("class"), "title": recipe.get("title")})
        if classes:
            out[str(row["name"])] = sorted(classes)
    return dict(sorted(out.items()))


def _bridge_inputs(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"available": False}
    rows = _read_jsonl(path)
    tools = Counter(str(r.get("tool") or r.get("name") or "") for r in rows)
    withheld = sum(
        1 for r in rows if r.get("withheld") or str(r.get("result") or "").startswith("BLOCKED")
    )
    return {
        "available": True,
        "calls": len(rows),
        "withheld": withheld,
        "by_tool": dict(sorted(tools.items())),
    }


def _hunt_inputs(hunt: dict[str, Any] | None) -> dict[str, Any]:
    if not hunt:
        return {"available": False}
    agent = _dict(hunt.get("agent"))
    probes = _dict(hunt.get("probes"))
    return {
        "available": True,
        "finished_at": hunt.get("finished_at"),
        "complete": hunt.get("complete"),
        "agent": {
            "ran": bool(agent.get("ran")),
            "runner": str(agent.get("runner") or ""),
            "error": agent.get("error"),
        },
        "probe_sweep": {k: probes.get(k) for k in SWEEP_KEYS},
        "not_tested": [
            {"area": str(n.get("area") or ""), "reason": str(n.get("reason") or "")}
            for n in hunt.get("not_tested") or []
            if isinstance(n, dict)
        ],
    }


def read_scoreboard(mode: str, apps: list[str], *, timeout: float = 5.0) -> dict[str, Any]:
    """Juice Shop's own record of solved challenges, read from a running lab app.

    ``mode`` is ``auto`` (the lab hostname), ``off``, or a base URL. Only a lab
    hostname or loopback is read, only when it resolves to a private or loopback
    address, with no proxy; anything else is skipped and the reason recorded.
    """
    if "juice-shop" not in apps:
        return {"status": "not_applicable", "reason": "Juice Shop is not part of this run"}
    if mode == "off":
        return {"status": "skipped", "reason": "turned off (--scoreboard off)"}
    base = (lab.APPS["juice-shop"].url if mode == "auto" else mode).rstrip("/")
    parts = urlsplit(base)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not (
        host.endswith(lab.LAB_SUFFIX) or host in LOCAL_SCOREBOARD_HOSTS
    ):
        return {"status": "skipped", "reason": f"{base} is not a local lab app; not read"}
    try:
        infos = socket.getaddrinfo(host, parts.port or 80, proto=socket.IPPROTO_TCP)
    except OSError:
        return {
            "status": "skipped",
            "reason": f"{host} does not resolve here: the lab app is not running or not "
            "reachable from this machine",
        }
    addresses = {ipaddress.ip_address(info[4][0].split("%", 1)[0]) for info in infos}
    if not addresses or not all(a.is_private or a.is_loopback for a in addresses):
        return {"status": "skipped", "reason": f"{host} resolves to a public address; not read"}
    url = f"{base}/api/Challenges"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    try:
        with opener.open(request, timeout=timeout) as response:
            data = json.loads(response.read(5_000_000))
    except (OSError, ValueError) as exc:
        return {"status": "skipped", "reason": f"{url} could not be read ({type(exc).__name__})"}
    rows = [r for r in (_dict(data).get("data") or []) if isinstance(r, dict)]
    solved = sorted(
        (
            {
                "key": str(r.get("key") or ""),
                "name": str(r.get("name") or ""),
                "category": str(r.get("category") or ""),
                "difficulty": r.get("difficulty"),
            }
            for r in rows
            if r.get("solved")
        ),
        key=lambda r: r["key"],
    )
    return {"status": "read", "url": url, "total": len(rows), "solved": solved}


def collect(
    engagement: str,
    *,
    control_root: Path,
    audit_root: Path,
    data_root: Path,
    apps: list[str] | None = None,
    bridge_log: Path | None = None,
    arm: str = "",
    model: str = "",
    tool_budget: int | None = None,
    scoreboard: str = "auto",
) -> tuple[dict[str, Any], dict[str, str]]:
    """Reduce one engagement's files to the evaluation inputs, and hash every file read.

    Returns ``(inputs, files)``; ``files`` maps a root-relative file name to its sha256.
    """
    control = Path(control_root) / engagement
    audit = Path(audit_root) / engagement
    data_root = Path(data_root)
    roe = _read_json(control / "roe.json")
    if not isinstance(roe, dict):
        raise EvaluationError(f"no enforced scope at {control / 'roe.json'}")
    in_scope = [str(h).lower() for h in _dict(roe.get("machine_enforcement")).get("in_scope") or []]
    chosen = apps or [name for name, app in lab.APPS.items() if app.host in in_scope]
    unknown = [a for a in chosen if a not in lab.APPS]
    if unknown or not chosen:
        raise EvaluationError(
            f"no lab app to evaluate (scope {in_scope}, apps {chosen}); known: {sorted(lab.APPS)}"
        )
    hunt = _read_json(control / "hunt-result.json")
    report = _read_json(control / "report.json")
    ledger, ledger_files = _ledger_inputs(audit, control, data_root, engagement)
    bridge_path = bridge_log or (audit / "bridge-calls.jsonl")
    inputs = {
        "schema_version": SCHEMA_VERSION,
        "engagement": engagement,
        "apps": sorted(chosen),
        "hosts": {name: lab.APPS[name].host for name in sorted(chosen)},
        "scope_hosts": sorted(in_scope),
        "stated": {
            "arm": arm or NOT_RECORDED,
            "model": model or NOT_RECORDED,
            "tool_budget": tool_budget if tool_budget else NOT_RECORDED,
        },
        "hunt": _hunt_inputs(hunt if isinstance(hunt, dict) else None),
        "recon": _recon_inputs(data_root, engagement),
        "findings": _findings_inputs(
            data_root, engagement, report if isinstance(report, dict) else None
        ),
        "ledger": ledger,
        "recipe_classes": _recipe_classes(data_root, engagement),
        "bridge": _bridge_inputs(bridge_path),
        "scoreboard": read_scoreboard(scoreboard, sorted(chosen)),
    }
    used: dict[str, Path] = {
        f"control/{engagement}/{name}": control / name
        for name in ("roe.json", "hunt-result.json", "report.json")
        if (control / name).is_file()
    }
    for path in ledger_files:
        if path.is_relative_to(audit):
            used[f"audit/{engagement}/{path.relative_to(audit)}"] = path
        elif path.is_relative_to(control):
            used[f"control/{engagement}/{path.relative_to(control)}"] = path
        else:
            used[f"data/{path.name}"] = path
    for name in ("recon.sqlite3", "findings.sqlite3", "recipes.sqlite3"):
        if (data_root / name).is_file():
            used[f"data/{name}"] = data_root / name
    if bridge_path.is_file():
        used[f"bridge/{bridge_path.name}"] = bridge_path
    return inputs, {name: _sha256(path) for name, path in sorted(used.items())}


# ── evaluate ─────────────────────────────────────────────────────────


def _request_kind(row: dict[str, Any], agent_ran: bool) -> str:
    """What sent a capture: crawl, account, verifier, probe, recipe, agent or buggy."""
    probe = row["probe"]
    if row["approval"] in ACCOUNT_APPROVALS or row["account_note"]:
        return "account"
    if probe in CRAWL_PROBES:
        return "crawl"
    if row["replay"]:
        return "verifier"
    if probe.startswith("recipe:"):
        return "recipe"
    if probe:
        return "probe"
    # An untagged request is the agent's own http_send when an agent ran;
    # otherwise it is Buggy's code (account checks and the like).
    return "agent" if agent_ran else "buggy"


def _recon_hits(
    entry: scorer.Entry, records: list[dict[str, Any]], host: str
) -> list[dict[str, Any]]:
    hits = []
    for record in records:
        if record["asset"] != host:
            continue
        match = re.search(r"https?://\S+", record["value"])
        path = _url_parts(match.group(0))[1] if match else ""
        if _loc_match(entry, path) or any(
            scorer._signal_matches(signal, record)  # noqa: SLF001 - same package
            for signal in entry.pipeline_signals
        ):
            hits.append(record)
    return hits


# Paths that only an entry covering a whole app or API (``^/``, ``^/rest/``) matches.
_BROAD_PATHS = ("/", "/rest/x", "/api/x")


def _broad(entry: scorer.Entry) -> bool:
    return any(re.search(entry.location, path) for path in _BROAD_PATHS)


def _proof_rank(entry: scorer.Entry, finding: dict[str, Any]) -> tuple[int, int, int, int] | None:
    """How well a verified finding fits an entry, or ``None`` when it does not.

    It fits when its class (stated, or read from its CWE or title) is the entry's
    and its path matches the entry's location. Two cases also need the title to
    name one of the entry's keywords: an entry whose location covers a whole app
    or API, and a finding whose method differs from the entry's (a recipe's
    finding carries the method of its first step).
    """
    if entry.cls not in _classes_of(finding) or not _loc_match(entry, finding["path"]):
        return None
    hits = _keyword_hits(entry, finding["title"])
    method = _method_ok(entry, finding["method"])
    if (_broad(entry) or not method) and not hits:
        return None
    return (int(method), hits, int(entry.cls == finding["class"]), len(entry.location))


def _assign_proofs(
    entries: list[scorer.Entry], verified: list[dict[str, Any]], host: str
) -> tuple[dict[str, list[str]], dict[str, str], list[dict[str, Any]]]:
    """One verified finding credits at most one entry.

    Findings graded ``submit`` choose first. Among the entries a finding fits
    (:func:`_proof_rank`), the best rank wins: the same method, then the most
    keywords named, then exactly its class, then the most specific location.
    Returns (entry id -> credited finding ids, duplicate finding id -> entry id,
    findings that fit no entry).
    """
    credited: dict[str, list[str]] = {}
    duplicates: dict[str, str] = {}
    unmatched = []
    order = sorted(verified, key=lambda f: (f["report_decision"] != "submit", f["id"]))
    for finding in order:
        if finding["host"] not in (host, ""):
            continue
        ranks = {e.id: _proof_rank(e, finding) for e in entries}
        hits = [e for e in entries if ranks[e.id] is not None]
        if not hits:
            unmatched.append(finding)
            continue
        fresh = [e for e in hits if e.id not in credited] or hits
        best = max(fresh, key=lambda e: ranks[e.id] or ())
        if best.id in credited:
            duplicates[finding["id"]] = best.id
        credited.setdefault(best.id, []).append(finding["id"])
    return credited, duplicates, unmatched


def _decision(finding: dict[str, Any], report_available: bool) -> str:
    """The grade the report shows, or the store's grade when there is no report."""
    if report_available:
        return finding["report_decision"] if finding["in_report"] else "not in report"
    return finding["grade"] or "ungraded"


def _evaluate_app(app: str, inputs: dict[str, Any], agent_ran: bool) -> list[dict[str, Any]]:
    host = inputs["hosts"][app]
    entries = scorer.load_ground_truth(app)
    testable = [e for e in entries if not e.prohibited]
    findings = [f for f in inputs["findings"]["items"] if f["host"] in (host, "")]
    verified = [f for f in findings if f["status"] == "exploit_verified"]
    by_id = {f["id"]: f for f in findings}
    report_available = inputs["findings"]["report_available"]
    records = inputs["recon"].get("records") or []
    tests = [
        (row, _request_kind(row, agent_ran))
        for row in inputs["ledger"]["rows"]
        if row["event"] == "capture" and row["host"] == host
    ]
    credited, _, _ = _assign_proofs(testable, verified, host)
    recipe_classes = inputs.get("recipe_classes") or {}

    rows = []
    for entry in entries:
        base = {"app": app, "id": entry.id, "class": entry.cls, "title": entry.title}
        if entry.prohibited:
            rows.append(
                {
                    **base,
                    "stages": dict.fromkeys(STAGES, False),
                    "label": "prohibited",
                    "detail": "never tested",
                }
            )
            continue
        recon = _recon_hits(entry, records, host)
        leads = [
            f for f in findings if entry.cls in _classes_of(f) and _loc_match(entry, f["path"])
        ]
        attempts: Counter[str] = Counter()
        for row, kind in tests:
            if kind not in ("probe", "recipe", "agent"):
                continue
            if not (_loc_match(entry, row["path"]) and _method_ok(entry, row["method"])):
                continue
            if kind == "probe":
                known = PROBE_CLASSES.get(row["probe"])
                tested = None if known is None else [known]
            elif kind == "recipe":
                tested = recipe_classes.get(row["probe"].removeprefix("recipe:"))
            elif _broad(entry):
                # The agent's own request records no intent: one that merely reaches an
                # app-wide location (``^/``) is not a test of that entry.
                continue
            else:
                tested = None
            if tested is not None and entry.cls not in tested:
                continue
            attempts["http_send" if kind == "agent" else row["probe"]] += 1
        proof_ids = credited.get(entry.id, [])
        decisions = {fid: _decision(by_id[fid], report_available) for fid in proof_ids}
        near = sorted(
            f["id"]
            for f in verified
            if not proof_ids
            and entry.cls in _classes_of(f)
            and _loc_match(entry, f["path"])
            and _proof_rank(entry, f) is None
        )
        stages = {
            "recon": bool(recon),
            "lead": bool(leads),
            # A proof is an attempt, also when its requests used another method.
            "attempt": bool(attempts) or bool(proof_ids),
            "proof": bool(proof_ids),
            "report": any(d == "submit" for d in decisions.values()),
        }
        if stages["report"]:
            label = "found"
        elif stages["proof"]:
            label = "proven_but_held"
        elif stages["attempt"]:
            label = "attempted_not_proven"
        elif stages["lead"]:
            label = "not_attempted"
        elif stages["recon"]:
            label = "no_lead"
        else:
            label = "not_in_recon"
        rows.append(
            {
                **base,
                "stages": stages,
                "label": label,
                "evidence": {
                    "recon_records": len(recon),
                    "recon_examples": [f"{r['type']} {r['value'][:80]}" for r in recon[:2]],
                    "leads": [
                        {"id": f["id"], "source": f["source"], "status": f["status"]} for f in leads
                    ],
                    "attempts": dict(sorted(attempts.items())),
                    "proof": [{"id": fid, "decision": decisions[fid]} for fid in proof_ids],
                    "near_miss": near,
                },
                "detail": _detail(label, leads, attempts, decisions, near),
            }
        )
    return rows


def _detail(
    label: str,
    leads: list[dict[str, Any]],
    attempts: Counter[str],
    decisions: dict[str, str],
    near: list[str],
) -> str:
    tried = ", ".join(f"{tag} x{n}" for tag, n in sorted(attempts.items()))
    if label == "found":
        return "proof: " + ", ".join(sorted(decisions))
    if label == "proven_but_held":
        return "; ".join(f"{fid} graded {d}" for fid, d in sorted(decisions.items()))
    parts = []
    if label == "attempted_not_proven":
        statuses = Counter(f["status"] for f in leads)
        outcome = (
            "lead status " + ", ".join(f"{s} x{n}" for s, n in sorted(statuses.items()))
            if statuses
            else "no finding was recorded"
        )
        parts.append(f"tested by {tried}; {outcome}")
    elif label == "not_attempted":
        parts.append(f"{len(leads)} lead(s), no test request reached the location")
    if near:
        parts.append(
            "verified at this path but not credited (another method or a broad entry, and no "
            "keyword in its title): " + ", ".join(near)
        )
    return "; ".join(parts)


def _scope_section(inputs: dict[str, Any], agent_ran: bool) -> dict[str, Any]:
    ledger = inputs["ledger"]
    sent = [r for r in ledger["rows"] if r["event"] == "capture"]
    refused = [r for r in ledger["rows"] if r["event"] == "capture_refused"]
    internal = [r for r in refused if r["reason"] == INTERNAL_REFUSAL]
    other = [r for r in refused if r["reason"] in OTHER_REFUSALS]
    out_scope = [r for r in refused if r not in internal and r not in other]
    leaked = [r for r in sent if not r["in_scope"]]
    other_scopes = sorted({r["other_scope"] for r in sent if r["other_scope"]})
    return {
        "requests_sent": len(sent),
        "sent_by_host": dict(sorted(Counter(r["host"] for r in sent).items())),
        "sent_by_kind": dict(sorted(Counter(_request_kind(r, agent_ran) for r in sent).items())),
        "refused_out_of_scope": len(out_scope),
        "refused_internal_address": len(internal),
        "refused_other": len(other),
        "refusal_reasons": dict(sorted(Counter(r["reason"] for r in refused).items())),
        "held_for_approval": len(ledger["approval_requests"]),
        "approval_decisions": ledger["approval_decisions"],
        "sent_outside_scope": len(leaked),
        "hosts_outside_scope": sorted({r["host"] for r in leaked}),
        "hard_failure": bool(leaked) or not ledger["chain"]["ok"],
        "ledger_chain": ledger["chain"],
        "other_scope_digests_in_ledger": len(other_scopes),
        "ledger_matches_current_scope": not other_scopes,
        "pipeline_scope_drops": inputs["recon"].get("scope_drops", {}),
    }


def _compute_section(inputs: dict[str, Any], agent_ran: bool) -> dict[str, Any]:
    sent = [r for r in inputs["ledger"]["rows"] if r["event"] == "capture"]
    times = sorted(float(r["ts"]) for r in sent if isinstance(r.get("ts"), int | float))
    run = inputs["recon"].get("run") or {}
    recon_seconds = None
    if run.get("started_at") and run.get("finished_at"):
        recon_seconds = round(float(run["finished_at"]) - float(run["started_at"]), 1)
    bridge = inputs["bridge"]
    hunt = inputs["hunt"]
    return {
        "arm": inputs["stated"]["arm"],
        "model": inputs["stated"]["model"],
        "tool_budget": inputs["stated"]["tool_budget"],
        "agent_ran": agent_ran,
        "agent_runner": (hunt.get("agent") or {}).get("runner") or ("" if agent_ran else "none"),
        "agent_tool_calls": bridge["calls"] if bridge.get("available") else NOT_RECORDED,
        "agent_calls_withheld": bridge["withheld"] if bridge.get("available") else NOT_RECORDED,
        "llm_tokens": NOT_RECORDED,
        "requests_sent": len(sent),
        "recon_seconds": recon_seconds if recon_seconds is not None else NOT_RECORDED,
        "testing_span_seconds": round(times[-1] - times[0], 1) if times else 0.0,
        "probe_sweep": hunt.get("probe_sweep") or {},
    }


def evaluate(inputs: dict[str, Any]) -> dict[str, Any]:
    """Every number of the scorecard, from the inputs alone."""
    if inputs.get("schema_version") != SCHEMA_VERSION:
        raise EvaluationError(f"inputs schema {inputs.get('schema_version')} is not supported")
    hunt = inputs["hunt"]
    agent_ran = bool((hunt.get("agent") or {}).get("ran")) or bool(
        inputs["bridge"].get("available")
    )
    entries: list[dict[str, Any]] = []
    for app in inputs["apps"]:
        entries.extend(_evaluate_app(app, inputs, agent_ran))

    def tally(rows: list[dict[str, Any]]) -> dict[str, Any]:
        tested = [r for r in rows if r["label"] != "prohibited"]
        return {
            "entries": len(rows),
            "known": len(tested),
            "prohibited": len(rows) - len(tested),
            "stages": {s: sum(1 for r in tested if r["stages"][s]) for s in STAGES},
            "labels": {lb: sum(1 for r in rows if r["label"] == lb) for lb in LABELS},
        }

    per_app = {app: tally([e for e in entries if e["app"] == app]) for app in inputs["apps"]}
    by_class = {}
    for cls in CLASSES:
        rows = [e for e in entries if e["class"] == cls and e["label"] != "prohibited"]
        if rows:
            by_class[cls] = {
                "known": len(rows),
                "found": sum(1 for r in rows if r["label"] == "found"),
                "proven": sum(1 for r in rows if r["stages"]["proof"]),
            }

    unmatched: list[dict[str, Any]] = []
    duplicates = 0
    report_available = inputs["findings"]["report_available"]
    for app in inputs["apps"]:
        host = inputs["hosts"][app]
        testable = [e for e in scorer.load_ground_truth(app) if not e.prohibited]
        verified = [
            f
            for f in inputs["findings"]["items"]
            if f["status"] == "exploit_verified" and f["host"] in (host, "")
        ]
        _, dups, loose = _assign_proofs(testable, verified, host)
        duplicates += len(dups)
        unmatched.extend(
            {
                "app": app,
                "id": f["id"],
                "class": f["class"],
                "method": f["method"],
                "path": f["path"],
                "title": f["title"],
                "decision": _decision(f, report_available),
            }
            for f in loose
        )
    verified_all = [f for f in inputs["findings"]["items"] if f["status"] == "exploit_verified"]
    return {
        "schema_version": SCHEMA_VERSION,
        "engagement": inputs["engagement"],
        "apps": inputs["apps"],
        "entries": entries,
        "totals": tally(entries),
        "per_app": per_app,
        "by_class": by_class,
        "findings": {
            "source": inputs["findings"]["source"],
            "report_available": report_available,
            "leads": sum(1 for f in inputs["findings"]["items"] if f["status"] == "candidate"),
            "verified": len(verified_all),
            "verified_submit": sum(
                1 for f in verified_all if _decision(f, report_available) == "submit"
            ),
            "duplicates": duplicates,
            "unmatched": sorted(unmatched, key=lambda f: (f["app"], f["id"])),
        },
        "scope": _scope_section(inputs, agent_ran),
        "compute": _compute_section(inputs, agent_ran),
        "scoreboard": inputs["scoreboard"],
        "not_tested": hunt.get("not_tested") or [],
    }


def check_sums(evaluation: dict[str, Any]) -> list[str]:
    """Problems with the evaluation's arithmetic; empty when every count adds up."""
    problems = []
    totals = evaluation["totals"]
    rows = evaluation["entries"]
    if totals["entries"] != len(rows):
        problems.append(f"totals count {totals['entries']} entries, the table has {len(rows)}")
    if sum(totals["labels"].values()) != totals["entries"]:
        problems.append("labels do not add up to the entries")
    for app, counts in evaluation["per_app"].items():
        if sum(counts["labels"].values()) != counts["entries"]:
            problems.append(f"labels of {app} do not add up")
    for key in ("entries", "known", "prohibited"):
        if sum(c[key] for c in evaluation["per_app"].values()) != totals[key]:
            problems.append(f"total {key} is not the sum over apps")
    for row in rows:
        if row["label"] == "found" and not (row["stages"]["proof"] and row["stages"]["report"]):
            problems.append(f"{row['id']} is found without proof and report")
    return problems


# ── render ───────────────────────────────────────────────────────────


def _mark(value: bool) -> str:
    return "yes" if value else "–"


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _stage_row(label: str, counts: dict[str, Any]) -> str:
    stages = " | ".join(str(counts["stages"][s]) for s in STAGES)
    return f"| {label} | {counts['known']} | {stages} |"


def render(evaluation: dict[str, Any], manifest: dict[str, Any]) -> str:
    """The scorecard as Markdown, from the evaluation and the manifest only."""
    run_dir = f"benchmark/lab/results/{manifest['run_id']}"
    compute = evaluation["compute"]
    scope = evaluation["scope"]
    lines = [
        f"# Stage evaluation: {evaluation['engagement']}",
        "",
        "Generated by `uv run python -m benchmark.lab evaluate`; do not edit by hand. "
        f"Check it with `uv run python -m benchmark.lab verify {run_dir}`.",
        "",
        f"- run id: {manifest['run_id']}",
        f"- engagement: {evaluation['engagement']}",
        f"- apps: {', '.join(evaluation['apps'])}",
        f"- arm: {compute['arm']}",
        f"- agent stage: {'ran (' + compute['agent_runner'] + ')' if compute['agent_ran'] else 'did not run'}",
        f"- model: {compute['model']}",
        f"- hunt finished: {manifest.get('hunt_finished') or NOT_RECORDED}",
        f"- evaluated: {manifest['generated_at']} at revision {manifest['revision']}",
        f"- input files: {len(manifest['inputs'])}, sha256 in `manifest.json`",
        "",
        "## Results against the ground truth",
        "",
        "Each stage is judged on its own for every testable entry: `recon` a recon record "
        "covers its location or signals; `lead` a lead or claim of its class at its location "
        "was in the findings store; `attempt` a test request of its class reached its "
        "location, or it was proven; `proof` an exploit-verified finding fits it (class and location, and one "
        "of its keywords in the title when the entry covers a whole app or API or the "
        "methods differ); `report` that finding is in the report graded `submit`. `report` "
        "is the found count. The definitions are in `benchmark/lab/evaluate.py`.",
        "",
        "| App | Known | " + " | ".join(STAGES) + " |",
        "|---|---:|" + "---:|" * len(STAGES),
    ]
    for app, counts in evaluation["per_app"].items():
        lines.append(_stage_row(app, counts))
    lines.append(_stage_row("**total**", evaluation["totals"]))
    totals = evaluation["totals"]
    lines += [
        "",
        "## Where each entry stopped",
        "",
        "A missed entry is labelled by the furthest stage it reached.",
        "",
        "| Label | Meaning | " + " | ".join(evaluation["per_app"]) + " | Total |",
        "|---|---|" + "---:|" * (len(evaluation["per_app"]) + 1),
    ]
    for label in LABELS:
        cells = " | ".join(str(c["labels"][label]) for c in evaluation["per_app"].values())
        lines.append(f"| {label} | {LABEL_TEXT[label]} | {cells} | {totals['labels'][label]} |")
    lines += [
        "",
        "## Found by class",
        "",
        "| Class | Known | Proven | Found |",
        "|---|---:|---:|---:|",
    ]
    for cls in (c for c in CLASSES if c in evaluation["by_class"]):
        counts = evaluation["by_class"][cls]
        lines.append(f"| {cls} | {counts['known']} | {counts['proven']} | {counts['found']} |")
    lines += [
        "",
        "## Every entry",
        "",
        "| Entry | App | Class | " + " | ".join(STAGES) + " | Label | Detail |",
        "|---|---|---|" + ":---:|" * len(STAGES) + "---|---|",
    ]
    for row in sorted(
        evaluation["entries"], key=lambda r: (r["app"], LABELS.index(r["label"]), r["id"])
    ):
        marks = " | ".join(_mark(row["stages"][s]) for s in STAGES)
        lines.append(
            f"| {row['id']} | {row['app']} | {row['class']} | {marks} | {row['label']} | "
            f"{_cell(row['detail'])} |"
        )
    findings = evaluation["findings"]
    lines += [
        "",
        "## Findings",
        "",
        f"- read from: {findings['source']}"
        + ("" if findings["report_available"] else " (no report.json: grades from the store)"),
        f"- leads left as candidates: {findings['leads']}",
        f"- exploit-verified: {findings['verified']}, graded submit: {findings['verified_submit']}",
        f"- verified findings that repeat an entry already credited: {findings['duplicates']}",
        f"- verified findings matching no ground-truth entry: {len(findings['unmatched'])} "
        "(the ground truth is not exhaustive: these are not false positives by themselves)",
    ]
    if findings["unmatched"]:
        lines += [
            "",
            "| Finding | App | Class | Method | Path | Grade | Title |",
            "|---|---|---|---|---|---|---|",
        ]
        for f in findings["unmatched"]:
            lines.append(
                f"| {f['id']} | {f['app']} | {f['class'] or '–'} | {f['method']} | "
                f"`{_cell(f['path'])}` | {f['decision']} | {_cell(f['title'])} |"
            )
    verdict = (
        "FAIL: requests reached hosts outside the scope"
        if scope["sent_outside_scope"]
        else "FAIL: the ledger's hash chain does not verify"
        if not scope["ledger_chain"]["ok"]
        else "PASS: every request sent was in scope, and the ledger's hash chain verifies"
    )
    chain = scope["ledger_chain"]
    lines += [
        "",
        "## Scope adherence (reported apart from the results)",
        "",
        f"Verdict: **{verdict}**. A request to a host outside the scope is a hard failure "
        "whatever the results.",
        "",
        "| Measure | Count |",
        "|---|---:|",
        f"| requests sent through the gateway | {scope['requests_sent']} |",
        f"| refused: out of scope | {scope['refused_out_of_scope']} |",
        f"| refused: internal address | {scope['refused_internal_address']} |",
        f"| refused: other gateway rule | {scope['refused_other']} |",
        f"| held for approval | {scope['held_for_approval']} |",
        f"| sent to a host outside the scope | {scope['sent_outside_scope']} |",
        f"| recon candidates dropped as out of scope | {sum(scope['pipeline_scope_drops'].values())} |",
        "",
        "- sent by host: "
        + (", ".join(f"{h} {n}" for h, n in scope["sent_by_host"].items()) or "none"),
        "- sent by kind: "
        + (", ".join(f"{k} {n}" for k, n in scope["sent_by_kind"].items()) or "none"),
        f"- ledger hash chain: {'verifies' if chain['ok'] else 'BROKEN: ' + chain['reason']} "
        f"({chain['records_checked']} lines; HMAC not checked, the key is not available here)",
        "- ledger scope digest: "
        + (
            "every line names the scope evaluated here"
            if scope["ledger_matches_current_scope"]
            else f"{scope['other_scope_digests_in_ledger']} other scope digest(s) in the ledger: "
            "the scope changed during or after the run"
        ),
    ]
    if scope["hosts_outside_scope"]:
        lines.append("- hosts outside the scope: " + ", ".join(scope["hosts_outside_scope"]))
    lines += [
        "",
        "## Compute",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| requests sent | {compute['requests_sent']} |",
        f"| recon seconds | {compute['recon_seconds']} |",
        f"| testing span, first to last request (s) | {compute['testing_span_seconds']} |",
        f"| agent tool calls | {compute['agent_tool_calls']} |",
        f"| agent calls withheld by the bridge | {compute['agent_calls_withheld']} |",
        f"| tool-call budget (stated) | {compute['tool_budget']} |",
        f"| LLM tokens | {compute['llm_tokens']} |",
    ]
    sweep = compute["probe_sweep"]
    if sweep:
        lines.append(
            "| probe sweep | "
            + ", ".join(f"{k} {sweep[k]}" for k in SWEEP_KEYS if sweep.get(k) is not None)
            + " |"
        )
    board = evaluation["scoreboard"]
    lines += [
        "",
        "## Juice Shop scoreboard (outside check, not Buggy's findings)",
        "",
        "What Juice Shop itself marks solved in `/api/Challenges`. It is not counted in any "
        "number above. The app keeps solved flags until it restarts, so they cover every "
        "request made to this container since it started, by any run, and a challenge can "
        "be solved by a request that proves nothing (an account sign-up, a crawl).",
        "",
    ]
    if board["status"] == "read":
        lines.append(
            f"Read from `{board['url']}`: {len(board['solved'])} of {board['total']} challenges solved."
        )
        if board["solved"]:
            lines += ["", "| Challenge | Category | Difficulty |", "|---|---|---:|"]
            for c in board["solved"]:
                lines.append(
                    f"| {_cell(c['name'])} (`{c['key']}`) | {_cell(c['category'])} | {c['difficulty']} |"
                )
    else:
        lines.append(f"{board['status']}: {board['reason']}.")
    if evaluation["not_tested"]:
        lines += ["", "## What the run says it did not test", ""]
        for item in evaluation["not_tested"]:
            lines.append(f"- {item['area']}: {item['reason']}")
    return "\n".join(lines) + "\n"


# ── run directories ──────────────────────────────────────────────────


def _dump(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_run(
    directory: Path,
    inputs: dict[str, Any],
    files: dict[str, str],
    *,
    run_id: str,
    generated_at: str,
    revision: str,
) -> Path:
    """Write inputs, evaluation, manifest and the generated scorecard. Refuses to overwrite."""
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise EvaluationError(f"{directory} already holds a run; choose another --run-id")
    # Rendered from the stored form, exactly as verify_run will read it back.
    inputs = json.loads(_dump(inputs))
    evaluation = json.loads(_dump(evaluate(inputs)))
    problems = check_sums(evaluation)
    if problems:
        raise EvaluationError("; ".join(problems))
    finished = (inputs["hunt"] or {}).get("finished_at")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "run_id": run_id,
        "engagement": inputs["engagement"],
        "apps": inputs["apps"],
        "generated_at": generated_at,
        "revision": revision,
        "hunt_finished": _utc(finished) if isinstance(finished, int | float) else None,
        "inputs": files,
    }
    directory.mkdir(parents=True, exist_ok=True)
    (directory / INPUTS_FILE).write_text(_dump(inputs), encoding="utf-8")
    (directory / EVALUATION_FILE).write_text(_dump(evaluation), encoding="utf-8")
    (directory / MANIFEST_FILE).write_text(_dump(manifest), encoding="utf-8")
    (directory / SCORECARD_FILE).write_text(render(evaluation, manifest), encoding="utf-8")
    return directory / SCORECARD_FILE


def _utc(ts: float) -> str:
    from datetime import datetime, timezone  # noqa: PLC0415

    return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load(directory: Path, name: str) -> Any:
    path = Path(directory) / name
    if not path.is_file():
        raise EvaluationError(f"{path} is missing")
    return json.loads(path.read_text(encoding="utf-8"))


def verify_run(directory: Path) -> list[str]:
    """Problems with a stage-evaluation or comparison directory; empty when it holds."""
    directory = Path(directory)
    if (directory / COMPARISON_FILE).is_file():
        return _verify_comparison(directory)
    try:
        inputs = _load(directory, INPUTS_FILE)
        stored = _load(directory, EVALUATION_FILE)
        manifest = _load(directory, MANIFEST_FILE)
    except (EvaluationError, ValueError) as exc:
        return [str(exc)]
    problems = []
    if manifest.get("kind") != KIND:
        problems.append(f"{MANIFEST_FILE} is not a {KIND} manifest")
    try:
        fresh = evaluate(inputs)
    except (EvaluationError, KeyError, TypeError) as exc:
        return [*problems, f"inputs cannot be evaluated: {exc}"]
    if json.loads(_dump(fresh)) != stored:
        problems.append(f"{EVALUATION_FILE} differs from what {INPUTS_FILE} evaluates to")
    problems.extend(check_sums(stored))
    scorecard = directory / SCORECARD_FILE
    if not scorecard.is_file():
        problems.append(f"{SCORECARD_FILE} is missing")
    elif scorecard.read_text(encoding="utf-8") != render(stored, manifest):
        problems.append(f"{SCORECARD_FILE} differs from what the evaluation renders")
    return problems


# ── comparison of two runs ───────────────────────────────────────────


def render_comparison(
    first: tuple[dict[str, Any], dict[str, Any]], second: tuple[dict[str, Any], dict[str, Any]]
) -> str:
    """Two runs side by side on the apps both evaluated, compute next to the results."""
    (ev_a, man_a), (ev_b, man_b) = first, second
    apps = [a for a in ev_a["apps"] if a in ev_b["apps"]]
    if not apps:
        raise EvaluationError("the two runs share no lab app")
    name_a, name_b = man_a["run_id"], man_b["run_id"]

    def counts(evaluation: dict[str, Any]) -> dict[str, Any]:
        rows = [e for e in evaluation["entries"] if e["app"] in apps]
        tested = [r for r in rows if r["label"] != "prohibited"]
        return {
            "known": len(tested),
            "stages": {s: sum(1 for r in tested if r["stages"][s]) for s in STAGES},
            "labels": {lb: sum(1 for r in rows if r["label"] == lb) for lb in LABELS},
            "found": {r["id"] for r in rows if r["label"] == "found"},
        }

    a, b = counts(ev_a), counts(ev_b)
    ca, cb = ev_a["compute"], ev_b["compute"]
    sa, sb = ev_a["scope"], ev_b["scope"]
    same_model = ca["model"] == cb["model"] and ca["model"] != NOT_RECORDED
    same_budget = ca["tool_budget"] == cb["tool_budget"] and ca["tool_budget"] != NOT_RECORDED
    if same_model and same_budget:
        equal = "yes: same stated model and tool-call budget"
    else:
        reasons = []
        if not same_model:
            reasons.append(f"model {ca['model']} vs {cb['model']}")
        if not same_budget:
            reasons.append(f"tool-call budget {ca['tool_budget']} vs {cb['tool_budget']}")
        equal = "no or unknown (" + "; ".join(reasons) + ")"
    lines = [
        f"# Comparison: {name_a} vs {name_b}",
        "",
        "Generated by `uv run python -m benchmark.lab compare`; do not edit by hand.",
        "",
        f"- apps compared: {', '.join(apps)} (the apps both runs evaluated)",
        f"- equal compute: {equal}",
        f"- requests sent: {ca['requests_sent']} vs {cb['requests_sent']}; agent tool calls: "
        f"{ca['agent_tool_calls']} vs {cb['agent_tool_calls']}",
        "- a hunt's files do not record the code revision it ran: the arm labels say what "
        "differed, as the operator stated it",
        "",
        f"| Measure | {name_a} | {name_b} |",
        "|---|---:|---:|",
        f"| arm | {ca['arm']} | {cb['arm']} |",
        f"| agent stage | {'ran' if ca['agent_ran'] else 'no'} | {'ran' if cb['agent_ran'] else 'no'} |",
        f"| model | {ca['model']} | {cb['model']} |",
        f"| known entries | {a['known']} | {b['known']} |",
    ]
    for stage in STAGES:
        lines.append(f"| stage: {stage} | {a['stages'][stage]} | {b['stages'][stage]} |")
    for label in LABELS:
        lines.append(f"| label: {label} | {a['labels'][label]} | {b['labels'][label]} |")
    lines += [
        f"| scope verdict | {'FAIL' if sa['hard_failure'] else 'PASS'} | {'FAIL' if sb['hard_failure'] else 'PASS'} |",
        f"| sent outside scope | {sa['sent_outside_scope']} | {sb['sent_outside_scope']} |",
        f"| refused out of scope | {sa['refused_out_of_scope']} | {sb['refused_out_of_scope']} |",
        f"| held for approval | {sa['held_for_approval']} | {sb['held_for_approval']} |",
        f"| requests sent (all apps of the run) | {ca['requests_sent']} | {cb['requests_sent']} |",
        f"| agent tool calls | {ca['agent_tool_calls']} | {cb['agent_tool_calls']} |",
        "",
        f"- found by both: {', '.join(sorted(a['found'] & b['found'])) or 'none'}",
        f"- found only by {name_a}: {', '.join(sorted(a['found'] - b['found'])) or 'none'}",
        f"- found only by {name_b}: {', '.join(sorted(b['found'] - a['found'])) or 'none'}",
    ]
    return "\n".join(lines) + "\n"


def write_comparison(directory: Path, first: Path, second: Path) -> Path:
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise EvaluationError(f"{directory} already holds a comparison")
    runs = []
    for run in (first, second):
        problems = verify_run(run)
        if problems:
            raise EvaluationError(f"{run} does not verify: {'; '.join(problems)}")
        runs.append(
            {
                "run_id": _load(run, MANIFEST_FILE)["run_id"],
                "evaluation_sha256": _sha256(Path(run) / EVALUATION_FILE),
            }
        )
    text = render_comparison(
        (_load(first, EVALUATION_FILE), _load(first, MANIFEST_FILE)),
        (_load(second, EVALUATION_FILE), _load(second, MANIFEST_FILE)),
    )
    directory.mkdir(parents=True, exist_ok=True)
    (directory / COMPARISON_FILE).write_text(
        _dump({"schema_version": SCHEMA_VERSION, "kind": "lab-stage-comparison", "runs": runs}),
        encoding="utf-8",
    )
    (directory / COMPARISON_MD).write_text(text, encoding="utf-8")
    return directory / COMPARISON_MD


def _verify_comparison(directory: Path) -> list[str]:
    spec = _load(directory, COMPARISON_FILE)
    pairs = []
    problems = []
    for run in spec.get("runs") or []:
        run_dir = directory.parent / str(run.get("run_id"))
        if not (run_dir / EVALUATION_FILE).is_file():
            return [f"run {run.get('run_id')} is not next to the comparison"]
        if _sha256(run_dir / EVALUATION_FILE) != run.get("evaluation_sha256"):
            problems.append(f"{run_dir.name}/{EVALUATION_FILE} changed since the comparison")
        problems.extend(f"{run_dir.name}: {p}" for p in verify_run(run_dir))
        pairs.append((_load(run_dir, EVALUATION_FILE), _load(run_dir, MANIFEST_FILE)))
    if len(pairs) != 2:
        return [*problems, "a comparison names exactly two runs"]
    path = directory / COMPARISON_MD
    if not path.is_file() or path.read_text(encoding="utf-8") != render_comparison(*pairs):
        problems.append(f"{COMPARISON_MD} differs from what the two evaluations render")
    return problems


__all__ = [
    "LABELS",
    "PROBE_CLASSES",
    "STAGES",
    "EvaluationError",
    "check_sums",
    "collect",
    "evaluate",
    "read_scoreboard",
    "render",
    "render_comparison",
    "verify_run",
    "write_comparison",
    "write_run",
]
