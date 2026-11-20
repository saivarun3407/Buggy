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
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from buggy.capture import authz_matrix
from buggy.capture import export as evidence
from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway, GatewayRefusal
from buggy.capture.identities import IdentityError
from buggy.capture.probes import run_probe
from buggy.capture.probes.registry import REGISTRY
from buggy.coordination import DB_FILENAME as BOARD_DB
from buggy.coordination import Board
from buggy.coordination.board import BoardError
from buggy.findings import candidates, report, verifier
from buggy.findings.model import Finding, Status
from buggy.findings.service import FindingService
from buggy.findings.store import FindingStore
from buggy.memory import DB_FILENAME as LESSONS_DB
from buggy.memory import LessonStore, scope_hosts_from_document
from buggy.program.record import load_program

log = logging.getLogger("buggy.capture.workbench")

FINDINGS_DB = "findings.sqlite3"
PROBE_RUNS_DB = "probe_runs.sqlite3"
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
    "report_build",
    "evidence_export",
    "identities_list",
    "authz_matrix_run",
    "memory_search",
    "memory_save",
    "fact_add",
    "facts_list",
    "intent_open",
    "intent_claim",
    "intent_conclude",
    "hints_list",
    "hint_add",
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


def _actor(actor: str) -> str:
    name = " ".join(str(actor or "").split())[:120]
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
            FindingStore(roots.data / FINDINGS_DB), gateway, sessions=gateway.sessions
        )
        self.probe_runs = ProbeRuns(roots.data / PROBE_RUNS_DB)
        self.lessons = LessonStore(roots.data / LESSONS_DB)
        self.board = Board(roots.data / BOARD_DB)

    def close(self) -> None:
        self.findings.store.close()
        self.probe_runs.close()
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
        except ValueError as exc:
            # LessonError and input validation: the message names the field.
            return {"error": "INVALID", "detail": str(exc)}

    def _scope_document(self, engagement: str) -> dict[str, Any]:
        _scope, document = self.gateway.scope_for(engagement)
        return document if isinstance(document, dict) else {}

    # ── probes feed the queue ────────────────────────────────────────

    def after_probe(
        self, engagement: str, probe: str, params: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        """Queue a positive probe result and remember how to run it again.

        Returns ``result`` with ``finding_id`` added when it was queued. A probe
        that did not report ``vulnerable: true`` queues nothing.
        """
        url = str(params.get("url") or "")
        candidate = candidates.from_probe(
            result, engagement, url, str(params.get("parameter") or "")
        )
        if candidate is None:
            return result
        queued = candidates.enqueue(self.findings, [candidate], f"probe:{probe}")
        ids = queued.get("ids") or []
        if not ids:
            return {**result, "queue": {"queued": False, "errors": queued.get("errors")}}
        self.probe_runs.record(engagement, ids[0], probe, url, params)
        return {**result, "finding_id": ids[0], "queue": {"queued": True}}

    def _prover(self, engagement: str) -> Callable[[Finding], verifier.Verification | None]:
        def prove(finding: Finding) -> verifier.Verification | None:
            recorded = self.probe_runs.get(engagement, finding.id)
            if recorded is None or recorded[0] not in REGISTRY:
                return None
            probe, url, params = recorded
            return verifier.verify_by_probe(
                finding,
                probe,
                url,
                lambda: run_probe(self.gateway, engagement, probe, params, canary=self.canary),
            )

        return prove

    # ── findings ─────────────────────────────────────────────────────

    def finding_submit(self, engagement: str, finding_json: str, actor: str) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            data = _json(finding_json, "finding_json", dict, {})
            name = self._engagement(engagement)
            return self.findings.submit(name, {**data, "engagement": name}, _actor(actor))

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
            rows = candidates.next_candidates(
                self.findings.store,
                self._engagement(engagement),
                limit=max(1, min(int(limit), 20)),
                claimed_by=_actor(actor),
            )
            return {"ok": True, "candidates": rows, "count": len(rows)}

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
            built = report.build(
                name,
                self.findings.list(name).get("findings") or [],
                recon_summary=_json(recon_summary_json, "recon_summary_json", dict, None),
                scope=[str(entry) for entry in in_scope or []],
                captures=lambda capture_id: self.gateway.store.get(name, capture_id),
                generated_at=self._clock(),
                complete=bool(complete),
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
            folder = self.roots.audit / name / "evidence" / bundle_id
            folder.mkdir(parents=True, exist_ok=True)
            for filename, content in files.items():
                (folder / filename).write_bytes(content)
            return {
                "ok": True,
                "bundle_id": bundle_id,
                "written_to": f"audit/{name}/evidence/{bundle_id}/",
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

    def authz_matrix_run(
        self,
        engagement: str,
        urls_json: str,
        identities_json: str = "",
        owners_json: str = "",
        max_requests: int = 120,
    ) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            name = self._engagement(engagement)
            urls = _json(urls_json, "urls_json", list, [])
            names = _json(identities_json, "identities_json", list, [])
            if not names:
                names = [row["name"] for row in self.gateway.identities.public(name)]
            result = authz_matrix.run_matrix(
                self.gateway,
                self.gateway.sessions,
                name,
                urls,
                identities=names,
                owners=_json(owners_json, "owners_json", dict, None),
                max_requests=max(1, min(int(max_requests), MAX_MATRIX_REQUESTS)),
            )
            found = [c for c in result.get("candidates") or [] if isinstance(c, dict)]
            queued = candidates.enqueue(self.findings, found, "probe:authz_matrix") if found else {}
            return {**result, "queue": {"queued": len(queued.get("ids") or []), **queued}}

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
            saved = self.lessons.save(
                lesson,
                _actor(actor),
                verified_finding=proven,
                scope_hosts=scope_hosts_from_document(self._scope_document(name)),
            )
            return {"ok": True, "lesson": saved, "trusted": proven}

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
        endpoint, method, parameter, description, remediation, source, and assertions
        [{capture_id, identity, expect{status, body_contains, body_not_contains,
        differs_from, same_as}}]. A claim is not a finding until finding_verify proves it."""
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
        """Re-prove a finding independently: re-run the probe it came from, or re-send its
        cited captures and check the assertions. Only this sets exploit_verified."""
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
    def authz_matrix_run(
        engagement: str,
        urls_json: str,
        identities_json: str = "",
        owners_json: str = "",
        max_requests: int = 120,
    ) -> dict[str, Any]:
        """Request each URL (GET/HEAD only) as every identity and as nobody, and report
        which objects are readable by someone who does not own them."""
        return bench.authz_matrix_run(
            engagement, urls_json, identities_json, owners_json, max_requests
        )

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
        """Save a reusable technique. lesson_json: kind, title, body, classes, technologies,
        finding_id. Secrets and target names are removed. It is trusted only when finding_id
        names a finding the verifier proved."""
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


__all__ = ["WORKBENCH_TOOL_NAMES", "ProbeRuns", "Workbench", "register_workbench"]
