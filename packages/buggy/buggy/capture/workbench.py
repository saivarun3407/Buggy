"""Tool bodies for findings, candidates, memory and coordination on the capture server.

The capture server is the one process that holds the evidence gateway, so the
stores that depend on evidence live next to it: the findings store and its
verifier, the candidate queue, the lessons store and the coordination board.
Agents reach them only through these tool bodies.

Two arguments are never chosen by a model. ``engagement`` and ``actor`` are
filled in by the agent-side wrapper from the run it belongs to
(``buggy.tools.stack_mcp``); the wrapper's own tool signature does not expose
them. Everything else an agent passes is treated as untrusted input.

What these bodies will not do, whatever they are asked:

* mark a finding verified — only the verifier does, by re-running the probe
  the finding came from or by replaying its cited captures;
* trust a lesson as "verified" because the lesson says so;
* hand out a credential, a session value or the audit ledger.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from buggy.capture import accounts, authz_matrix, crawl, journey, recipes
from buggy.capture import export as evidence
from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.capture.identities import IdentityError
from buggy.capture.probes import run_probe
from buggy.capture.probes.registry import REGISTRY
from buggy.coordination import DB_FILENAME as BOARD_DB
from buggy.coordination import Board
from buggy.coordination.board import BoardError
from buggy.findings import candidates, chains, report, skill_map, verifier
from buggy.findings.model import Finding, Status
from buggy.findings.ruled_out import review_days_from_env
from buggy.findings.service import FindingService
from buggy.findings.store import FindingStore
from buggy.memory import DB_FILENAME as LESSONS_DB
from buggy.memory import LessonStore, scope_hosts_from_document
from buggy.program.record import load_program

log = logging.getLogger("buggy.capture.workbench")

FINDINGS_DB = "findings.sqlite3"
PROBE_RUNS_DB = "probe_runs.sqlite3"
RECIPES_DB = "recipes.sqlite3"
MAX_LIST = 200
MAX_BOARD_ITEMS = 200
MAX_MATRIX_REQUESTS = 300
REPORT_FORMATS = ("markdown", "html", "json")
#: Bundle files an agent may read back. The ledger excerpt is audit-root data
#: and is written for the operator only.
AGENT_BUNDLE_FILES = ("reproduce.sh", "captures.json", "MANIFEST.json")

WORKBENCH_TOOL_NAMES = (
    "finding_submit",
    "finding_get",
    "findings_list",
    "finding_verify",
    "finding_grade",
    "candidates_next",
    "candidates_add",
    "leads_ruled_out",
    "findings_chains",
    "findings_due",
    "report_build",
    "evidence_export",
    "identities_list",
    "accounts_provision",
    "authz_matrix_run",
    "owners_infer",
    "surface_crawl",
    "user_walk",
    "memory_search",
    "memory_save",
    "fact_add",
    "facts_list",
    "intent_open",
    "intent_claim",
    "intent_conclude",
    "hints_list",
    "hint_add",
    "recipe_check",
    "recipe_run",
    "recipe_save",
    "recipe_list",
    "recipe_get",
)


def _refuse(code: str, detail: str) -> GatewayRefusal:
    return GatewayRefusal(code, detail)


def _json(raw: str, name: str, kind: type, default: Any) -> Any:
    """``raw`` decoded as JSON of ``kind``; empty means ``default``."""
    if not raw or not str(raw).strip():
        return default
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _refuse("BAD_ARGUMENT", f"{name} is not valid JSON: {exc}") from exc
    if not isinstance(value, kind):
        raise _refuse("BAD_ARGUMENT", f"{name} must be a JSON {kind.__name__}")
    return value


def _ledger_note(entry: dict[str, Any]) -> dict[str, Any]:
    """What a run's result says about the ledger entry it produced."""
    return {
        "id": entry.get("id"),
        "kind": entry.get("kind"),
        "reason": entry.get("reason"),
        "retires_technique": entry.get("kind") == "ruled_out",
    }


def _actor(actor: str) -> str:
    # One token of letters, digits and _.:@- : the form every store accepts.
    name = re.sub(r"[^A-Za-z0-9_.:@-]+", "-", str(actor or "").strip()).strip("-")[:120]
    if not name:
        raise _refuse("BAD_ARGUMENT", "actor is required (it is set by the run, not by the model)")
    return name


class ProbeRuns:
    """Which probe run produced which finding, so the verifier can run it again."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS probe_runs ("
            " engagement TEXT NOT NULL, finding_id TEXT NOT NULL, probe TEXT NOT NULL,"
            " url TEXT NOT NULL, params TEXT NOT NULL, recorded_at REAL NOT NULL,"
            " PRIMARY KEY (engagement, finding_id))"
        )
        self._db.commit()

    def record(
        self, engagement: str, finding_id: str, probe: str, url: str, params: dict[str, Any]
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO probe_runs VALUES (?, ?, ?, ?, ?, ?)",
                (
                    engagement,
                    finding_id,
                    probe,
                    url,
                    json.dumps(params, sort_keys=True),
                    time.time(),
                ),
            )
            self._db.commit()

    def get(self, engagement: str, finding_id: str) -> tuple[str, str, dict[str, Any]] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT probe, url, params FROM probe_runs WHERE engagement = ? AND finding_id = ?",
                (engagement, finding_id),
            ).fetchone()
        return (row[0], row[1], json.loads(row[2])) if row else None

    def close(self) -> None:
        with self._lock:
            self._db.close()


class RecipeStore:
    """Recipes an agent saved, per engagement: canonical JSON, author, last outcome.

    Only the recipe (templates, never an extracted value) is stored.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS recipes ("
            " engagement TEXT NOT NULL, name TEXT NOT NULL, recipe TEXT NOT NULL,"
            " author TEXT NOT NULL, created_at REAL NOT NULL,"
            " last_outcome TEXT NOT NULL DEFAULT '', last_run_at REAL NOT NULL DEFAULT 0,"
            " PRIMARY KEY (engagement, name))"
        )
        self._db.commit()

    def save(self, engagement: str, recipe: recipes.Recipe, author: str) -> bool:
        """Store ``recipe`` under its name; True when it replaced a different saved recipe."""
        with self._lock:
            row = self._db.execute(
                "SELECT recipe FROM recipes WHERE engagement = ? AND name = ?",
                (engagement, recipe.name),
            ).fetchone()
            self._db.execute(
                "INSERT OR REPLACE INTO recipes VALUES (?, ?, ?, ?, ?, '', 0)",
                (engagement, recipe.name, recipe.canonical, author, time.time()),
            )
            self._db.commit()
        return row is not None and row[0] != recipe.canonical

    def has(self, engagement: str, name: str) -> bool:
        return self.get(engagement, name) is not None

    def get(self, engagement: str, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT name, recipe, author, created_at, last_outcome, last_run_at FROM recipes"
                " WHERE engagement = ? AND name = ?",
                (engagement, name),
            ).fetchone()
        return self._row(row) if row else None

    def listed(self, engagement: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT name, recipe, author, created_at, last_outcome, last_run_at FROM recipes"
                " WHERE engagement = ? ORDER BY name LIMIT ?",
                (engagement, MAX_LIST),
            ).fetchall()
        return [self._row(row) for row in rows]

    def record_outcome(self, engagement: str, recipe: recipes.Recipe, outcome: str) -> None:
        """Remember the last outcome, only for the exact recipe saved under that name."""
        with self._lock:
            self._db.execute(
                "UPDATE recipes SET last_outcome = ?, last_run_at = ?"
                " WHERE engagement = ? AND name = ? AND recipe = ?",
                (outcome, time.time(), engagement, recipe.name, recipe.canonical),
            )
            self._db.commit()

    @staticmethod
    def _row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "name": row[0],
            "recipe": json.loads(row[1]),
            "author": row[2],
            "created_at": row[3],
            "last_outcome": row[4],
            "last_run_at": row[5],
        }

    def close(self) -> None:
        with self._lock:
            self._db.close()


class Workbench:
    """Findings, candidates, memory and the board, bound to one evidence gateway."""

    def __init__(
        self,
        gateway: CaptureGateway,
        canary: Canary | None,
        engagement_of: Callable[[str], str],
        *,
        on_verified: Callable[[dict[str, Any]], None] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        roots = gateway.roots
        self.gateway = gateway
        self.canary = canary
        self._engagement = engagement_of
        self._clock = clock
        self._on_verified = on_verified
        self.roots = roots
        self.findings = FindingService(
            FindingStore(roots.data / FINDINGS_DB),
            gateway,
            sessions=gateway.sessions,
            review_days=review_days_from_env(),
        )
        self.probe_runs = ProbeRuns(roots.data / PROBE_RUNS_DB)
        self.recipes = RecipeStore(roots.data / RECIPES_DB)
        self.lessons = LessonStore(roots.data / LESSONS_DB)
        self.board = Board(roots.data / BOARD_DB)

    def close(self) -> None:
        self.findings.store.close()
        self.probe_runs.close()
        self.recipes.close()
        self.lessons.close()
        self.board.close()

    # ── plumbing ─────────────────────────────────────────────────────

    def _guard(self, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return fn()
        except GatewayRefusal as refusal:
            return refusal.to_dict()
        except BoardError as exc:
            return exc.to_dict()
        except IdentityError as exc:
            return {"error": "BAD_IDENTITIES", "detail": str(exc)}
        except evidence.ExportRefused as exc:
            return {"error": "EXPORT_REFUSED", "detail": str(exc)}
        except KeyError as exc:
            return {"error": "UNKNOWN_CAPTURE", "detail": f"no capture {exc.args[0]!r} here"}
        except (ValueError, TypeError) as exc:
            # LessonError and input validation: the message names the field. A wrong
            # argument shape (a number where a list of URLs belongs) is the caller's too.
            return {"error": "INVALID", "detail": str(exc)}

    def _scope_document(self, engagement: str) -> dict[str, Any]:
        _scope, document = self.gateway.scope_for(engagement)
        return document if isinstance(document, dict) else {}

    def _captures(self, engagement: str) -> Callable[[str], Any]:
        return lambda capture_id: self.gateway.store.get(engagement, capture_id)

    @staticmethod
    def _record(fn: Callable[[], dict[str, Any] | None]) -> dict[str, Any] | None:
        """Write to the ruled-out ledger; a ledger problem never fails the run it follows."""
        try:
            return fn()
        except (sqlite3.Error, ValueError, LookupError):
            log.warning("the ruled-out ledger could not be written", exc_info=True)
            return None

    def _roles(self, engagement: str) -> dict[str, str]:
        try:
            rows = self.gateway.identities.public(engagement)
        except (IdentityError, OSError, ValueError):
            return {}
        return {str(row.get("name")): str(row.get("role") or "") for row in rows}

    # ── probes feed the queue ────────────────────────────────────────

    def after_probe(
        self, engagement: str, probe: str, params: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        """Queue a positive probe result and remember how to run it again.

        Returns ``result`` with ``finding_id`` added when it was queued. A probe
        that did not report ``vulnerable: true`` queues nothing; why it did not
        (not vulnerable, blocked by the gateway, refused approval, a failed
        delivery) goes into the ruled-out ledger, and ``ledger`` in the result
        names the entry.
        """
        url = str(params.get("url") or "")
        entry = self._record(
            lambda: self.findings.ledger.after_probe(
                engagement, probe, params, result, lookup=self._captures(engagement)
            )
        )
        if entry:
            result = {**result, "ledger": _ledger_note(entry)}
        candidate = candidates.from_probe(
            result, engagement, url, str(params.get("parameter") or "")
        )
        if candidate is None:
            return result
        queued = candidates.enqueue(self.findings, [candidate], f"probe:{probe}")
        ids = queued.get("ids") or []
        if not ids:
            return {**result, "queue": {"queued": False, "errors": queued.get("errors")}}
        # The run's identity is part of how to run it again: the re-run is sent as
        # the same account (run_probe already put it in the params it was given).
        identity = str(result.get("identity") or "")
        recorded = {**params, "identity": identity} if identity else params
        self.probe_runs.record(engagement, ids[0], probe, url, recorded)
        return {**result, "finding_id": ids[0], "queue": {"queued": True}}

    def _prover(self, engagement: str) -> Callable[[Finding], verifier.Verification | None]:
        def prove(finding: Finding) -> verifier.Verification | None:
            recorded = self.probe_runs.get(engagement, finding.id)
            if recorded is None:
                return None
            probe, url, params = recorded
            if probe.startswith(candidates.SOURCE_RECIPE_PREFIX):
                return self._prove_by_recipe(engagement, finding, probe, url, params)
            if probe not in REGISTRY:
                return None
            return verifier.verify_by_probe(
                finding,
                probe,
                url,
                lambda: run_probe(self.gateway, engagement, probe, params, canary=self.canary),
            )

        return prove

    def _prove_by_recipe(
        self, engagement: str, finding: Finding, label: str, url: str, params: dict[str, Any]
    ) -> verifier.Verification:
        """Re-prove a recipe-sourced finding by running the exact recipe again.

        The same rule as a probe: the recorded run must be about the finding's
        endpoint, and anything but a fresh ``vulnerable: true`` (controls
        included) leaves it inconclusive. A state-changing recipe needs its own
        approval for the re-run; the reason then names the request id.
        """

        def rerun() -> dict[str, Any]:
            try:
                recipe = recipes.validate(params.get("recipe"))
            except recipes.RecipeError as exc:
                return {"vulnerable": None, "summary": f"the stored recipe is invalid ({exc})"}
            return recipes.execute(self.gateway, engagement, recipe)

        return verifier.verify_by_probe(finding, label, url, rerun)

    # ── recipes: checks the agent builds itself ──────────────────────

    def _load_recipe(self, engagement: str, recipe_json: str) -> recipes.Recipe | dict[str, Any]:
        """The validated recipe, or the agent-facing error result."""
        try:
            raw = json.loads(recipe_json) if isinstance(recipe_json, str) else recipe_json
        except json.JSONDecodeError as exc:
            return {"ok": False, "errors": [{"path": "recipe", "message": f"not JSON: {exc}"}]}
        if isinstance(raw, dict) and set(raw) == {"use"}:
            name = str(raw.get("use") or "")
            saved = self.recipes.get(engagement, name)
            if saved is None:
                raise _refuse("UNKNOWN_RECIPE", f"no saved recipe {name!r} in this engagement")
            raw = saved["recipe"]
        try:
            return recipes.validate(raw)
        except recipes.RecipeError as exc:
            return {"ok": False, "errors": [exc.to_dict()]}

    def recipe_check(self, engagement: str, recipe_json: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            self._engagement(engagement)
            return recipes.check(recipe_json)

        return self._guard(run)

    def recipe_run(self, engagement: str, recipe_json: str, actor: str) -> dict[str, Any]:
        """Validate, get the run approved if it can change state, run it, queue a positive."""

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            author = _actor(actor)
            loaded = self._load_recipe(name, recipe_json)
            if not isinstance(loaded, recipes.Recipe):
                return loaded
            result = recipes.execute(self.gateway, name, loaded)
            outcome = str(result.get("outcome") or result.get("code") or "")
            self.recipes.record_outcome(name, loaded, outcome)
            entry = self._record(
                lambda: self.findings.ledger.after_recipe(
                    name, loaded.data, result, actor=author, lookup=self._captures(name)
                )
            )
            if entry:
                result = {**result, "ledger": _ledger_note(entry)}
            return self.after_recipe(name, loaded, result, author)

        return self._guard(run)

    def after_recipe(
        self, engagement: str, recipe: recipes.Recipe, result: dict[str, Any], author: str
    ) -> dict[str, Any]:
        """Queue a positive recipe run and remember the exact recipe so the verifier re-runs it."""
        candidate = candidates.from_recipe(result, engagement, recipe.data)
        if candidate is None:
            return result
        queued = candidates.enqueue(self.findings, [candidate], recipe.probe)
        ids = queued.get("ids") or []
        if not ids:
            return {**result, "queue": {"queued": False, "errors": queued.get("errors")}}
        self.probe_runs.record(
            engagement, ids[0], recipe.probe, recipe.endpoint, {"recipe": recipe.data}
        )
        if not self.recipes.has(engagement, recipe.name):
            self.recipes.save(engagement, recipe, author)
            self.recipes.record_outcome(engagement, recipe, str(result.get("outcome") or ""))
        return {**result, "finding_id": ids[0], "queue": {"queued": True}}

    def recipe_save(self, engagement: str, recipe_json: str, actor: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            author = _actor(actor)
            try:
                recipe = recipes.parse(recipe_json)
            except recipes.RecipeError as exc:
                return {"ok": False, "errors": [exc.to_dict()]}
            replaced = self.recipes.save(name, recipe, author)
            return {
                "ok": True,
                "name": recipe.name,
                "replaced": replaced,
                "state_changing": recipe.state_changing,
                "steps": len(recipe.steps),
            }

        return self._guard(run)

    def recipe_list(self, engagement: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            rows = self.recipes.listed(self._engagement(engagement))
            return {
                "ok": True,
                "recipes": [
                    {
                        "name": row["name"],
                        "class": row["recipe"].get("class"),
                        "title": row["recipe"].get("title"),
                        "endpoint": row["recipe"].get("endpoint"),
                        "steps": len(row["recipe"].get("steps") or []),
                        "author": row["author"],
                        "created_at": row["created_at"],
                        "last_outcome": row["last_outcome"],
                        "last_run_at": row["last_run_at"],
                    }
                    for row in rows
                ],
                "count": len(rows),
            }

        return self._guard(run)

    def recipe_get(self, engagement: str, name: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            saved = self.recipes.get(self._engagement(engagement), str(name or ""))
            if saved is None:
                raise _refuse("UNKNOWN_RECIPE", f"no saved recipe {name!r} in this engagement")
            return {"ok": True, **saved}

        return self._guard(run)

    # ── findings ─────────────────────────────────────────────────────

    def finding_submit(self, engagement: str, finding_json: str, actor: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            data = _json(finding_json, "finding_json", dict, {})
            name = self._engagement(engagement)
            # An agent's own claim names the invariant it breaks and its entry point.
            return self.findings.submit(
                name, {**data, "engagement": name}, _actor(actor), require_context=True
            )

        return self._guard(run)

    def finding_get(self, engagement: str, finding_id: str) -> dict[str, Any]:
        return self._guard(lambda: self.findings.get(self._engagement(engagement), finding_id))

    def findings_list(self, engagement: str, status: str = "", grade: str = "") -> dict[str, Any]:
        def run() -> dict[str, Any]:
            listed = self.findings.list(
                self._engagement(engagement), status=status or None, grade=grade or None
            )
            rows = listed.get("findings") or []
            return {**listed, "findings": rows[:MAX_LIST], "total": len(rows)}

        return self._guard(run)

    def finding_verify(self, engagement: str, finding_id: str) -> dict[str, Any]:
        """Re-prove a finding. State-changing replays are never forced from here."""

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            before = self.findings.store.get(name, finding_id)
            outcome = self.findings.verify(
                name, finding_id, allow_state_change=False, prover=self._prover(name)
            )
            finding = outcome.get("finding") or {}
            newly = finding.get("status") == Status.EXPLOIT_VERIFIED.value and (
                before is None or before.status != Status.EXPLOIT_VERIFIED.value
            )
            if newly and self._on_verified is not None:
                try:
                    self._on_verified(finding)
                except Exception:  # noqa: BLE001 - a notifier must never fail a verification
                    log.warning("the verified-finding hook failed", exc_info=True)
            return outcome

        return self._guard(run)

    def finding_grade(
        self, engagement: str, finding_id: str, known_issues_json: str = ""
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            known = _json(known_issues_json, "known_issues_json", list, [])
            return self.findings.grade(
                name,
                finding_id,
                program=load_program(self.roots.control, name),
                known_issues=[k for k in known if isinstance(k, dict)],
            )

        return self._guard(run)

    # ── the queue ────────────────────────────────────────────────────

    def candidates_next(self, engagement: str, actor: str, limit: int = 5) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            skipped: dict[str, list[dict[str, Any]]] = {}
            rows = candidates.next_candidates(
                self.findings.store,
                self._engagement(engagement),
                limit=max(1, min(int(limit), 20)),
                claimed_by=_actor(actor),
                ledger=self.findings.ledger,
                skipped=skipped,
            )
            # The skill files to read before working each lead (skill_get), by fixed rules.
            for row in rows:
                row["skills"] = skill_map.for_lead(row)
            out: dict[str, Any] = {"ok": True, "candidates": rows, "count": len(rows)}
            if skipped:
                out["ruled_out_skipped"] = len(skipped)
                out["note"] = (
                    "Leads whose techniques were already ruled out there are not handed out; "
                    "leads_ruled_out lists them with the reasons."
                )
            return out

        return self._guard(run)

    def leads_ruled_out(self, engagement: str, query: str = "") -> dict[str, Any]:
        """What was tried and dropped, why, when and by whom; and recent failed attempts."""

        def run() -> dict[str, Any]:
            return self.findings.ledger.listed(self._engagement(engagement), str(query or "")[:200])

        return self._guard(run)

    def findings_chains(self, engagement: str) -> dict[str, Any]:
        """What each proven finding gives and needs, and the chains to test (never findings)."""

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            rows = self.findings.list(name).get("findings") or []
            return chains.chains(rows, roles=self._roles(name))

        return self._guard(run)

    def findings_due(self, engagement: str) -> dict[str, Any]:
        """Decisions whose review date has passed: ruled-out leads, held and discarded findings."""

        def run() -> dict[str, Any]:
            rows = self.findings.ledger.due(self._engagement(engagement))
            return {"ok": True, "due": rows[:MAX_LIST], "count": len(rows)}

        return self._guard(run)

    def candidates_add(self, engagement: str, items_json: str, actor: str) -> dict[str, Any]:
        """Queue leads produced by deterministic code: scanner hits and ranked surface.

        ``items_json`` is ``{"pipeline": [vulnerability records], "ranked":
        [rows of the recon report's test candidates]}``. Either key may be absent.
        """

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            items = _json(items_json, "items_json", dict, {})
            pipeline = [r for r in items.get("pipeline") or [] if isinstance(r, dict)]
            ranked = [r for r in items.get("ranked") or [] if isinstance(r, dict)]
            leads = candidates.from_pipeline(pipeline, name) + candidates.from_ranked(ranked, name)
            queued = candidates.enqueue(self.findings, leads, _actor(actor))
            return {
                **queued,
                "received": {"pipeline": len(pipeline), "ranked": len(ranked)},
                # A scanner hit with no class cannot be a finding; say how many were left out.
                "unclassified": len(pipeline) - len(candidates.from_pipeline(pipeline, name)),
            }

        return self._guard(run)

    # ── report and evidence ──────────────────────────────────────────

    def report_build(
        self,
        engagement: str,
        fmt: str = "markdown",
        recon_summary_json: str = "",
        complete: bool = False,
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            if fmt not in REPORT_FORMATS:
                raise _refuse("BAD_ARGUMENT", f"format must be one of {', '.join(REPORT_FORMATS)}")
            enforcement = self._scope_document(name).get("machine_enforcement")
            in_scope = enforcement.get("in_scope") if isinstance(enforcement, dict) else None
            rows = self.findings.list(name).get("findings") or []
            built = report.build(
                name,
                rows,
                recon_summary=_json(recon_summary_json, "recon_summary_json", dict, None),
                scope=[str(entry) for entry in in_scope or []],
                captures=lambda capture_id: self.gateway.store.get(name, capture_id),
                generated_at=self._clock(),
                complete=bool(complete),
                chains=chains.chains(rows, roles=self._roles(name)),
                due=self.findings.ledger.due(name),
            )
            render = {
                "markdown": report.to_markdown,
                "html": report.to_html,
                "json": report.to_json,
            }[fmt]
            return {"ok": True, "format": fmt, "report": render(built)}

        return self._guard(run)

    def evidence_export(
        self, engagement: str, capture_ids_json: str, finding_id: str = ""
    ) -> dict[str, Any]:
        """Write a redacted, self-checking evidence bundle for the operator.

        The bundle goes under the audit root; an agent gets the reproduction
        script, the capture summaries and the manifest, never the ledger lines.
        """

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            ids = [str(c) for c in _json(capture_ids_json, "capture_ids_json", list, []) if c]
            finding = None
            if finding_id:
                stored = self.findings.store.get(name, finding_id)
                if stored is None:
                    raise _refuse(
                        "UNKNOWN_FINDING", f"no finding {finding_id!r} in this engagement"
                    )
                finding = stored.to_dict()
                if not ids:
                    ids = [a.get("capture_id") for a in finding.get("assertions") or []]
                    ids += list((finding.get("verification") or {}).get("replay_capture_ids") or [])
                    ids = [c for c in dict.fromkeys(ids) if c]
            files = evidence.bundle(
                self.gateway.store,
                name,
                ids,
                finding=finding,
                ledger_path=self.roots.audit / name / "captures.jsonl",
                redact=True,
            )
            manifest = json.loads(files["MANIFEST.json"])
            bundle_id = "ev-" + str(manifest.get("manifest_sha256") or "")[:16]
            # Everything about one finding sits in one folder: its logs here, its
            # proof video and screenshots next to them. Loose captures get their own.
            relative = f"{finding_id}/logs" if finding_id else bundle_id
            folder = self.roots.audit / name / "evidence" / relative
            folder.mkdir(parents=True, exist_ok=True)
            for filename, content in files.items():
                (folder / filename).write_bytes(content)
            return {
                "ok": True,
                "bundle_id": bundle_id,
                "written_to": f"audit/{name}/evidence/{relative}/",
                "capture_ids": ids,
                "files": {
                    filename: files[filename].decode("utf-8", "replace")
                    for filename in AGENT_BUNDLE_FILES
                    if filename in files
                },
            }

        return self._guard(run)

    # ── identities and the authorization matrix ──────────────────────

    def identities_list(self, engagement: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            rows = self.gateway.identities.public(self._engagement(engagement))
            return {"ok": True, "identities": rows, "count": len(rows)}

        return self._guard(run)

    def accounts_provision(
        self,
        engagement: str,
        seeds_json: str,
        api_operations_json: str = "",
        count: int = 0,
        api_surface_json: str = "",
    ) -> dict[str, Any]:
        """Register and sign in test accounts, when the operator turned creation on.

        For the hunt command, not for an agent. Discovers the sign-up from an
        anonymous crawl of ``seeds_json`` (and optional recon API operations),
        or else from the JSON sign-up and login endpoints in ``api_surface_json``
        (:func:`buggy.capture.accounts.api_surface`), then registers up to the
        scope's ``max_accounts`` accounts through the gateway's account-creation
        exemption. No credential is returned.
        """

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            seeds = _json(seeds_json, "seeds_json", list, [])
            if not seeds:
                raise _refuse("BAD_ARGUMENT", "seeds_json must list at least one URL")
            api_operations = _json(api_operations_json, "api_operations_json", list, [])
            surface = _json(api_surface_json, "api_surface_json", dict, {})
            return accounts.provision(
                self.gateway,
                name,
                [str(seed) for seed in seeds],
                api_operations=api_operations,
                api_surface=surface,
                count=int(count) or None,
            )

        return self._guard(run)

    def authz_matrix_run(
        self,
        engagement: str,
        urls_json: str,
        identities_json: str = "",
        owners_json: str = "",
        max_requests: int = 120,
        inferred_json: str = "",
    ) -> dict[str, Any]:
        """``inferred_json`` lists the URLs whose owner in ``owners_json`` was inferred
        (``owners_infer``), not declared: those need an owner marker to be reported."""

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            urls = _json(urls_json, "urls_json", list, [])
            names = _json(identities_json, "identities_json", list, [])
            if not names:
                names = [row["name"] for row in self.gateway.identities.public(name)]
            inferred = _json(inferred_json, "inferred_json", list, [])
            if not all(isinstance(url, str) for url in inferred):
                raise _refuse("BAD_ARGUMENT", "inferred_json must be a JSON list of URLs")
            result = authz_matrix.run_matrix(
                self.gateway,
                self.gateway.sessions,
                name,
                urls,
                identities=names,
                owners=_json(owners_json, "owners_json", dict, None),
                max_requests=max(1, min(int(max_requests), MAX_MATRIX_REQUESTS)),
                require_marker_for=inferred,
            )
            found = [c for c in result.get("candidates") or [] if isinstance(c, dict)]
            queued = candidates.enqueue(self.findings, found, "probe:authz_matrix") if found else {}
            return {**result, "queue": {"queued": len(queued.get("ids") or []), **queued}}

        return self._guard(run)

    def owners_infer(
        self, engagement: str, reached_json: str, owned_json: str = ""
    ) -> dict[str, Any]:
        """Owners inferred from signed-in crawls. ``reached_json`` is ``{identity: [url]}``
        or the crawler's list of ``{"identity", "urls", "pages", "owned"}``. ``owned_json``
        is ``{identity: [url]}`` of objects each reached with its own identifier (the user
        walk's ``owned``). No request is sent."""

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            raw = _json(reached_json, "reached_json", object, {})
            if not isinstance(raw, (dict, list)):
                raise _refuse("BAD_ARGUMENT", "reached_json must be a JSON object or list")
            claimed = _json(owned_json, "owned_json", dict, {})
            owned: dict[str, list[Any]] = {
                str(who): urls for who, urls in claimed.items() if isinstance(urls, list)
            }
            reached: dict[str, list[Any]] = {}
            if isinstance(raw, dict):
                for who, urls in raw.items():
                    reached[str(who)] = urls if isinstance(urls, list) else []
            else:
                for entry in raw:
                    if not isinstance(entry, dict) or not isinstance(entry.get("identity"), str):
                        raise _refuse(
                            "BAD_ARGUMENT",
                            "each entry of reached_json must be an object with an identity",
                        )
                    found = reached.setdefault(entry["identity"], [])
                    for key in ("urls", "pages"):
                        if isinstance(entry.get(key), list):
                            found.extend(entry[key])
                    if isinstance(entry.get("owned"), list):
                        owned.setdefault(entry["identity"], []).extend(entry["owned"])
            markers = self.gateway.identities.markers(name)
            result = authz_matrix.infer_owners(reached, markers, owned)
            return {
                "ok": True,
                **result,
                "identities_without_markers": sorted(n for n, m in markers.items() if not m),
            }

        return self._guard(run)

    # ── the signed-in surface crawl ──────────────────────────────────

    def surface_crawl(
        self,
        engagement: str,
        seeds_json: str,
        identity: str = "",
        max_requests: int = crawl.DEFAULT_MAX_REQUESTS,
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            seeds = _json(seeds_json, "seeds_json", list, [])
            if not seeds:
                raise _refuse("BAD_ARGUMENT", "seeds_json must list at least one URL")
            if not isinstance(identity, str):
                raise _refuse("BAD_ARGUMENT", "identity must be the name of a test account")
            return {
                "ok": True,
                **crawl.crawl(
                    self.gateway,
                    name,
                    [str(seed) for seed in seeds],
                    identity=identity,
                    max_requests=max(1, min(int(max_requests), crawl.MAX_REQUESTS)),
                ),
            }

        return self._guard(run)

    def user_walk(
        self,
        engagement: str,
        seeds_json: str,
        identity: str,
        templates_json: str = "",
        max_requests: int = journey.DEFAULT_MAX_REQUESTS,
    ) -> dict[str, Any]:
        """Use the application as one test account, GET only (:func:`journey.walk`).

        For the hunt command: walks the pages and API endpoints in ``seeds_json``,
        then fills the templated endpoints in ``templates_json`` with identifiers
        the account received. Returns the crawl's fields plus ``filled``,
        ``own_data`` and ``owned``; never a response body or a credential.
        """

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            seeds = _json(seeds_json, "seeds_json", list, [])
            if not seeds:
                raise _refuse("BAD_ARGUMENT", "seeds_json must list at least one URL")
            if not isinstance(identity, str) or not identity.strip():
                raise _refuse("BAD_ARGUMENT", "identity must be the name of a test account")
            templates = _json(templates_json, "templates_json", list, [])
            return {
                "ok": True,
                **journey.walk(
                    self.gateway,
                    name,
                    [str(seed) for seed in seeds],
                    identity=identity,
                    templates=[str(t) for t in templates if isinstance(t, str)],
                    max_requests=max(1, min(int(max_requests), journey.MAX_REQUESTS)),
                ),
            }

        return self._guard(run)

    # ── lessons ──────────────────────────────────────────────────────

    def memory_search(
        self,
        engagement: str,
        query: str = "",
        classes_json: str = "",
        technologies_json: str = "",
        kind: str = "",
        limit: int = 3,
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            self._engagement(engagement)
            rows = self.lessons.search(
                query,
                classes=_json(classes_json, "classes_json", list, []),
                technologies=_json(technologies_json, "technologies_json", list, []),
                kind=kind or None,
                limit=max(1, min(int(limit), 10)),
            )
            return {"ok": True, "lessons": rows, "count": len(rows)}

        return self._guard(run)

    def memory_save(self, engagement: str, lesson_json: str, actor: str) -> dict[str, Any]:
        """Save a lesson. It is trusted only if it cites a finding the verifier proved here."""

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            lesson = _json(lesson_json, "lesson_json", dict, {})
            lesson = {k: v for k, v in lesson.items() if k not in {"trust", "verified"}}
            lesson["source_engagement"] = name
            cited = str(lesson.get("finding_id") or "")
            proven = False
            if cited:
                stored = self.findings.store.get(name, cited)
                proven = stored is not None and stored.status == Status.EXPLOIT_VERIFIED.value
                if not proven:
                    lesson.pop("finding_id", None)
            lesson_id = self.lessons.save(
                lesson,
                _actor(actor),
                verified_finding=proven,
                scope_hosts=scope_hosts_from_document(self._scope_document(name)),
            )
            return {"ok": True, "lesson": self.lessons.get(lesson_id), "trusted": proven}

        return self._guard(run)

    # ── the board ────────────────────────────────────────────────────

    def fact_add(
        self, engagement: str, text: str, actor: str, kind: str = "", evidence_json: str = ""
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            extra = {"kind": kind} if kind else {}
            return {
                "ok": True,
                "fact": self.board.add_fact(
                    self._engagement(engagement),
                    text,
                    _actor(actor),
                    evidence=_json(evidence_json, "evidence_json", list, []),
                    **extra,
                ),
            }

        return self._guard(run)

    def facts_list(self, engagement: str) -> dict[str, Any]:
        """Facts, open work and hints, newest last, capped."""

        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            facts = self.board.facts(name)
            return {
                "ok": True,
                "facts": facts[-MAX_BOARD_ITEMS:],
                "facts_total": len(facts),
                "open_work": self.board.open_work(name)[:MAX_BOARD_ITEMS],
                "hints": self.board.hints(name, limit=20),
            }

        return self._guard(run)

    def intent_open(
        self, engagement: str, text: str, from_facts_json: str, actor: str
    ) -> dict[str, Any]:
        return self._guard(
            lambda: {
                "ok": True,
                "intent": self.board.open_intent(
                    self._engagement(engagement),
                    text,
                    _json(from_facts_json, "from_facts_json", list, []),
                    _actor(actor),
                ),
            }
        )

    def intent_claim(self, engagement: str, intent_id: str, actor: str) -> dict[str, Any]:
        """Claim an intent, or renew a claim this worker already holds."""
        return self._guard(
            lambda: {
                "ok": True,
                "intent": self.board.claim(self._engagement(engagement), intent_id, _actor(actor)),
            }
        )

    def intent_conclude(
        self,
        engagement: str,
        intent_id: str,
        actor: str,
        fact_text: str,
        evidence_json: str = "",
        abandon: bool = False,
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            name, worker = self._engagement(engagement), _actor(actor)
            if abandon:
                done = self.board.abandon(name, intent_id, worker, fact_text)
            else:
                done = self.board.conclude(
                    name,
                    intent_id,
                    worker,
                    fact_text,
                    _json(evidence_json, "evidence_json", list, []),
                )
            return {"ok": True, "intent": done}

        return self._guard(run)

    def hints_list(self, engagement: str) -> dict[str, Any]:
        return self._guard(
            lambda: {"ok": True, "hints": self.board.hints(self._engagement(engagement), limit=50)}
        )

    def hint_add(self, engagement: str, text: str, actor: str) -> dict[str, Any]:
        """A hint from an agent, recorded under its own name (never as the operator)."""

        def run() -> dict[str, Any]:
            author = _actor(actor)
            if author.lower() in {"operator", "verifier"}:
                raise _refuse("BAD_ARGUMENT", "that author name is reserved")
            return {
                "ok": True,
                "hint": self.board.add_hint(self._engagement(engagement), text, author),
            }

        return self._guard(run)


def register_workbench(mcp: Any, bench: Workbench) -> None:
    """Register the workbench tools on a FastMCP server."""

    @mcp.tool()
    def finding_submit(engagement: str, finding_json: str, actor: str) -> dict[str, Any]:
        """Record a claim as a candidate finding. finding_json: title, class, severity,
        endpoint, method, parameter, description, remediation, source, invariant (the rule
        it breaks), entry_point (the request a user reaches first), and assertions
        [{capture_id, identity, expect{status, body_contains, body_not_contains,
        differs_from, same_as}}]. invariant and entry_point are required for access_control,
        business_logic and auth_session. A claim is not a finding until finding_verify
        proves it."""
        return bench.finding_submit(engagement, finding_json, actor)

    @mcp.tool()
    def finding_get(engagement: str, finding_id: str) -> dict[str, Any]:
        """One finding with its history."""
        return bench.finding_get(engagement, finding_id)

    @mcp.tool()
    def findings_list(engagement: str, status: str = "", grade: str = "") -> dict[str, Any]:
        """Findings of this engagement, optionally by status or grade."""
        return bench.findings_list(engagement, status, grade)

    @mcp.tool()
    def finding_verify(engagement: str, finding_id: str) -> dict[str, Any]:
        """Re-prove a finding independently: re-run the probe or recipe it came from, or
        re-send its cited captures and check the assertions. Only this sets exploit_verified."""
        return bench.finding_verify(engagement, finding_id)

    @mcp.tool()
    def finding_grade(
        engagement: str, finding_id: str, known_issues_json: str = ""
    ) -> dict[str, Any]:
        """Grade a finding against the program's rules: submit, hold or discard, with reasons."""
        return bench.finding_grade(engagement, finding_id, known_issues_json)

    @mcp.tool()
    def candidates_next(engagement: str, actor: str, limit: int = 5) -> dict[str, Any]:
        """The next unproven leads to work on, claimed for this worker for a while."""
        return bench.candidates_next(engagement, actor, limit)

    @mcp.tool()
    def candidates_add(engagement: str, items_json: str, actor: str) -> dict[str, Any]:
        """Queue scanner hits and ranked recon leads (used by the recon stage)."""
        return bench.candidates_add(engagement, items_json, actor)

    @mcp.tool()
    def leads_ruled_out(engagement: str, query: str = "") -> dict[str, Any]:
        """Techniques already tried and dropped here, with the reason, when and by whom
        (not vulnerable, blocked by the gateway, approval refused, verifier inconclusive,
        discarded by the grader), and recent failed attempts that retired nothing. query
        filters by words in the technique, endpoint, parameter or reason."""
        return bench.leads_ruled_out(engagement, query)

    @mcp.tool()
    def findings_chains(engagement: str) -> dict[str, Any]:
        """What each proven finding gives an attacker and needs first, and the possible chains
        (A gives what B needs). A chain is a lead to test, never a proven finding."""
        return bench.findings_chains(engagement)

    @mcp.tool()
    def findings_due(engagement: str) -> dict[str, Any]:
        """Decisions whose review date has passed: ruled-out leads and findings graded hold or
        discard. The operator extends or closes them with buggy-cli findings."""
        return bench.findings_due(engagement)

    @mcp.tool()
    def report_build(
        engagement: str, fmt: str = "markdown", recon_summary_json: str = "", complete: bool = False
    ) -> dict[str, Any]:
        """The engagement report (markdown, html or json). Only verified findings are listed
        as findings; everything else is shown as not proven."""
        return bench.report_build(engagement, fmt, recon_summary_json, complete)

    @mcp.tool()
    def evidence_export(
        engagement: str, capture_ids_json: str = "", finding_id: str = ""
    ) -> dict[str, Any]:
        """A redacted evidence bundle (HAR, curl script, manifest) for captures or a finding.
        Written for the operator; returns the reproduction script and manifest."""
        return bench.evidence_export(engagement, capture_ids_json, finding_id)

    @mcp.tool()
    def identities_list(engagement: str) -> dict[str, Any]:
        """Test accounts the operator declared: name, role and what each owns. No secrets."""
        return bench.identities_list(engagement)

    @mcp.tool()
    def accounts_provision(
        engagement: str,
        seeds_json: str,
        api_operations_json: str = "",
        count: int = 0,
        api_surface_json: str = "",
    ) -> dict[str, Any]:
        """Register and sign in test accounts when the operator turned account creation on
        in the scope document. Discovers the sign-up from an anonymous crawl of seeds_json
        (and optional recon API operations), or from the JSON sign-up and login endpoints in
        api_surface_json, registers up to max_accounts accounts, and returns names and
        reasons only — never an email, password, cookie or token. For the hunt command, not
        for agents."""
        return bench.accounts_provision(
            engagement, seeds_json, api_operations_json, count, api_surface_json
        )

    @mcp.tool()
    def authz_matrix_run(
        engagement: str,
        urls_json: str,
        identities_json: str = "",
        owners_json: str = "",
        max_requests: int = 120,
        inferred_json: str = "",
    ) -> dict[str, Any]:
        """Request each URL (GET/HEAD only) as every identity and as nobody, and report
        which objects are readable by someone who does not own them. inferred_json lists
        URLs whose owner in owners_json was inferred: those need an owner marker."""
        return bench.authz_matrix_run(
            engagement, urls_json, identities_json, owners_json, max_requests, inferred_json
        )

    @mcp.tool()
    def owners_infer(engagement: str, reached_json: str, owned_json: str = "") -> dict[str, Any]:
        """Owners of object URLs inferred from signed-in crawls: {identity: [url]} or the
        crawler's [{identity, urls, pages}]. A URL only one identity reached is a hint of
        ownership; pass those URLs as inferred_json to authz_matrix_run. owned_json is
        {identity: [url]} of objects each reached with its own id (returned under owned:
        those need no marker). Sends nothing."""
        return bench.owners_infer(engagement, reached_json, owned_json)

    @mcp.tool()
    def surface_crawl(
        engagement: str, seeds_json: str, identity: str = "", max_requests: int = 120
    ) -> dict[str, Any]:
        """Crawl same-host links breadth-first from seed URLs, GET only, optionally signed in
        as a declared identity. Never requests logout/delete-style URLs; records forms
        without submitting them. Returns pages (capture ids), URLs, forms and what it skipped."""
        return bench.surface_crawl(engagement, seeds_json, identity, max_requests)

    @mcp.tool()
    def user_walk(
        engagement: str,
        seeds_json: str,
        identity: str,
        templates_json: str = "",
        max_requests: int = journey.DEFAULT_MAX_REQUESTS,
    ) -> dict[str, Any]:
        """Use the application as one test account, GET only: walk the pages and API
        endpoints in seeds_json, then fill templated endpoints (/api/Users/{id}) with ids the
        account itself received. Returns the crawl's fields plus filled, own_data and owned.
        For the hunt command, not for agents."""
        return bench.user_walk(engagement, seeds_json, identity, templates_json, max_requests)

    @mcp.tool()
    def memory_search(
        engagement: str,
        query: str = "",
        classes_json: str = "",
        technologies_json: str = "",
        kind: str = "",
        limit: int = 3,
    ) -> dict[str, Any]:
        """Lessons from earlier engagements that match this technology or class."""
        return bench.memory_search(engagement, query, classes_json, technologies_json, kind, limit)

    @mcp.tool()
    def memory_save(engagement: str, lesson_json: str, actor: str) -> dict[str, Any]:
        """Save a reusable lesson. lesson_json: kind (guide, failure or payload), title, body,
        classes, technologies, finding_id. Secrets and target names are removed. It is trusted
        only when finding_id names a finding the verifier proved."""
        return bench.memory_save(engagement, lesson_json, actor)

    @mcp.tool()
    def fact_add(
        engagement: str, text: str, actor: str, kind: str = "", evidence_json: str = ""
    ) -> dict[str, Any]:
        """Add an observation to the shared board (append-only)."""
        return bench.fact_add(engagement, text, actor, kind, evidence_json)

    @mcp.tool()
    def facts_list(engagement: str) -> dict[str, Any]:
        """The shared board: facts, open work and hints."""
        return bench.facts_list(engagement)

    @mcp.tool()
    def intent_open(engagement: str, text: str, from_facts_json: str, actor: str) -> dict[str, Any]:
        """Open a piece of work that follows from existing facts."""
        return bench.intent_open(engagement, text, from_facts_json, actor)

    @mcp.tool()
    def intent_claim(engagement: str, intent_id: str, actor: str) -> dict[str, Any]:
        """Claim a piece of work (or renew your claim). A live claim by someone else is refused."""
        return bench.intent_claim(engagement, intent_id, actor)

    @mcp.tool()
    def intent_conclude(
        engagement: str,
        intent_id: str,
        actor: str,
        fact_text: str,
        evidence_json: str = "",
        abandon: bool = False,
    ) -> dict[str, Any]:
        """Finish work you claimed with the fact it produced, or abandon it with the reason."""
        return bench.intent_conclude(
            engagement, intent_id, actor, fact_text, evidence_json, abandon
        )

    @mcp.tool()
    def hints_list(engagement: str) -> dict[str, Any]:
        """Guidance left on the board, newest last."""
        return bench.hints_list(engagement)

    @mcp.tool()
    def hint_add(engagement: str, text: str, actor: str) -> dict[str, Any]:
        """Leave a hint for other workers."""
        return bench.hint_add(engagement, text, actor)

    @mcp.tool()
    def recipe_check(engagement: str, recipe_json: str) -> dict[str, Any]:
        """Validate a recipe (a multi-step check described as JSON) without sending anything.
        Returns {ok, state_changing, steps} or {ok: false, errors: [{path, message}]}."""
        return bench.recipe_check(engagement, recipe_json)

    @mcp.tool()
    def recipe_run(engagement: str, recipe_json: str, actor: str) -> dict[str, Any]:
        """Run a recipe through the gateway (or {"use": "<saved name>"}). A recipe with a
        state-changing step is approved as one run. vulnerable true is queued as a candidate
        (finding_id); finding_verify re-runs the recipe as its proof."""
        return bench.recipe_run(engagement, recipe_json, actor)

    @mcp.tool()
    def recipe_save(engagement: str, recipe_json: str, actor: str) -> dict[str, Any]:
        """Save a valid recipe under its name for this engagement (replaces one of that name)."""
        return bench.recipe_save(engagement, recipe_json, actor)

    @mcp.tool()
    def recipe_list(engagement: str) -> dict[str, Any]:
        """Saved recipes: name, class, title, endpoint, author and last outcome."""
        return bench.recipe_list(engagement)

    @mcp.tool()
    def recipe_get(engagement: str, name: str) -> dict[str, Any]:
        """One saved recipe in full (templates only; extracted values are never stored)."""
        return bench.recipe_get(engagement, name)


__all__ = [
    "WORKBENCH_TOOL_NAMES",
    "ProbeRuns",
    "RecipeStore",
    "Workbench",
    "register_workbench",
]
