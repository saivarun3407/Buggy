"""Stage-level evaluation of a hunt run: stages, labels, scope, scoreboard, run directories."""

from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from benchmark.lab import __main__ as cli
from benchmark.lab import baseline, evaluate, lab

HOST = "juice-shop.lab"
BASE = f"http://{HOST}:3000"


def finding(fid: str, cls: str, method: str, path: str, title: str, **extra: Any) -> dict:
    row = {
        "id": fid,
        "class": cls,
        "cwe": "",
        "status": "exploit_verified",
        "grade": "submit",
        "source": "probe:sqli",
        "method": method,
        "host": HOST,
        "path": path,
        "title": title,
        "in_report": True,
        "report_decision": "submit",
        "report_lead": False,
    }
    row.update(extra)
    return row


def capture(path: str, *, method: str = "GET", probe: str = "", **extra: Any) -> dict:
    row = {
        "seq": 1,
        "ts": 100.0,
        "event": "capture",
        "method": method,
        "host": HOST,
        "path": path,
        "status": 200,
        "probe": probe,
        "replay": False,
        "approval": "",
        "account_note": False,
        "reason": "",
        "error": False,
        "in_scope": True,
        "other_scope": "",
    }
    row.update(extra)
    return row


def make_inputs(
    findings: list[dict] | None = None,
    rows: list[dict] | None = None,
    records: list[dict] | None = None,
    *,
    agent_ran: bool = False,
) -> dict:
    return {
        "schema_version": evaluate.SCHEMA_VERSION,
        "engagement": "lab1",
        "apps": ["juice-shop"],
        "hosts": {"juice-shop": HOST},
        "scope_hosts": [HOST],
        "stated": {"arm": "test", "model": "not recorded", "tool_budget": "not recorded"},
        "hunt": {
            "available": True,
            "finished_at": 100.0,
            "agent": {"ran": agent_ran, "runner": "claude-code" if agent_ran else ""},
            "probe_sweep": {"planned": 1, "ran": 1},
            "not_tested": [],
        },
        "recon": {
            "available": True,
            "run": {"id": "r1", "started_at": 0.0, "finished_at": 10.0},
            "records": records
            if records is not None
            else [
                {
                    "asset": HOST,
                    "type": "url",
                    "value": f"{BASE}/rest/products/search",
                    "attrs": {},
                },
                {"asset": HOST, "type": "url", "value": f"{BASE}/rest/user/login", "attrs": {}},
                {
                    "asset": HOST,
                    "type": "vulnerability",
                    "value": f"prometheus-metrics {BASE}/metrics",
                    "attrs": {},
                },
            ],
            "scope_drops": {"NOT_IN_SCOPE": 2},
        },
        "findings": {
            "source": "findings.sqlite3",
            "report_available": True,
            "items": findings if findings is not None else [],
        },
        "ledger": {
            "rows": rows if rows is not None else [],
            "chain": {"ok": True, "records_checked": 0, "reason": "", "hmac_checked": False},
            "scope_sha256": "",
            "approval_requests": [],
            "approval_decisions": {},
        },
        "recipe_classes": {},
        "bridge": {"available": False},
        "scoreboard": {"status": "skipped", "reason": "test"},
    }


def by_id(evaluation: dict) -> dict[str, dict]:
    return {row["id"]: row for row in evaluation["entries"]}


# ── stages and labels ────────────────────────────────────────────────


def test_each_entry_gets_five_stages_and_the_label_of_the_furthest_one() -> None:
    inputs = make_inputs(
        findings=[
            finding("F-1", "injection", "GET", "/rest/products/search", "injection (sqli) search"),
            finding(
                "F-2",
                "info_exposure",
                "GET",
                "/metrics",
                "Prometheus Metrics - Detect",
                report_decision="hold",
                grade="hold",
                source="pipeline:nuclei",
            ),
            finding(
                "F-3",
                "auth_session",
                "GET",
                "/rest/user/login",
                "auth session on GET /rest/user/login",
                status="candidate",
                grade="",
                in_report=False,
                report_decision="",
                source="pipeline:surface",
            ),
        ],
        rows=[capture("/rest/products/search", probe="sqli")],
    )
    result = evaluate.evaluate(inputs)
    rows = by_id(result)
    assert rows["js-sqli-search"]["label"] == "found"
    assert all(rows["js-sqli-search"]["stages"].values())
    assert rows["js-metrics-exposed"]["label"] == "proven_but_held"
    assert rows["js-metrics-exposed"]["stages"]["report"] is False
    # A lead at the location (any method), never tested.
    assert rows["js-weak-admin-password"]["label"] == "not_attempted"
    # Recon saw the login path, but no injection lead and no test.
    assert rows["js-sqli-login"]["label"] == "no_lead"
    assert rows["js-ssrf-profile-image"]["label"] == "not_in_recon"
    assert evaluate.check_sums(result) == []
    totals = result["totals"]
    assert sum(totals["labels"].values()) == totals["entries"] == 28
    assert totals["stages"]["report"] == totals["labels"]["found"] == 1


def test_attempted_not_proven_counts_only_tests_of_the_entrys_class() -> None:
    rows = [
        capture("/rest/user/login", method="POST", probe="sqli"),
        capture("/rest/user/login", method="POST", probe="xss_reflected"),
        capture("/rest/user/login", method="POST", probe="surface_crawl"),
    ]
    result = by_id(evaluate.evaluate(make_inputs(rows=rows)))
    assert result["js-sqli-login"]["label"] == "attempted_not_proven"
    assert result["js-sqli-login"]["evidence"]["attempts"] == {"sqli": 1}
    assert "sqli x1" in result["js-sqli-login"]["detail"]
    # The xss probe and the crawl are not tests of the auth entry at the same place.
    assert result["js-weak-admin-password"]["stages"]["attempt"] is False


def test_an_untagged_request_is_the_agents_only_when_an_agent_ran() -> None:
    rows = [capture("/rest/user/login", method="POST")]
    without = by_id(evaluate.evaluate(make_inputs(rows=rows)))
    assert without["js-sqli-login"]["stages"]["attempt"] is False
    with_agent = by_id(evaluate.evaluate(make_inputs(rows=rows, agent_ran=True)))
    assert with_agent["js-sqli-login"]["evidence"]["attempts"] == {"http_send": 1}
    # The agent's request to an app-wide location is no test of an app-wide entry.
    assert with_agent["js-md5-passwords"]["stages"]["attempt"] is False


def test_a_recipe_counts_for_the_classes_it_tests() -> None:
    rows = [capture("/rest/user/login", method="POST", probe="recipe:login-bypass")]
    inputs = make_inputs(rows=rows)
    inputs["recipe_classes"] = {"login-bypass": ["auth_session", "injection"]}
    result = by_id(evaluate.evaluate(inputs))
    assert result["js-sqli-login"]["evidence"]["attempts"] == {"recipe:login-bypass": 1}
    inputs["recipe_classes"] = {"login-bypass": ["xss"]}
    assert by_id(evaluate.evaluate(inputs))["js-sqli-login"]["stages"]["attempt"] is False


def test_prohibited_entries_are_labelled_and_never_counted() -> None:
    inputs = make_inputs()
    inputs["apps"] = ["dvga"]
    inputs["hosts"] = {"dvga": "dvga.lab"}
    result = evaluate.evaluate(inputs)
    rows = by_id(result)
    assert rows["dvga-batch-dos"]["label"] == "prohibited"
    assert result["totals"]["prohibited"] == 2
    assert result["totals"]["known"] == result["totals"]["entries"] - 2


# ── which finding proves which entry ─────────────────────────────────


def test_class_read_from_the_title_and_keywords_pick_the_entry() -> None:
    title = "SQL injection in login email allows authentication bypass as the first (admin)"
    inputs = make_inputs(
        findings=[finding("F-1", "auth_session", "POST", "/rest/user/login", title)]
    )
    rows = by_id(evaluate.evaluate(inputs))
    assert rows["js-sqli-login"]["label"] == "found"
    assert rows["js-weak-admin-password"]["stages"]["proof"] is False


def test_another_method_needs_a_keyword_in_the_title() -> None:
    named = finding(
        "F-1", "business_logic", "POST", "/api/BasketItems", "Basket accepts negative quantities"
    )
    unnamed = finding("F-2", "business_logic", "POST", "/api/BasketItems", "Odd item write")
    rows = by_id(evaluate.evaluate(make_inputs(findings=[named])))
    assert rows["js-negative-quantity"]["label"] == "found"
    assert rows["js-negative-quantity"]["stages"]["attempt"] is True  # a proof is an attempt
    result = evaluate.evaluate(make_inputs(findings=[unnamed]))
    row = by_id(result)["js-negative-quantity"]
    assert row["stages"]["proof"] is False
    assert row["evidence"]["near_miss"] == ["F-2"]
    assert [f["id"] for f in result["findings"]["unmatched"]] == ["F-2"]


def test_an_app_wide_entry_is_credited_only_when_the_title_names_it() -> None:
    other = finding(
        "F-1", "auth_session", "GET", "/rest/user/change-password", "Password change without old"
    )
    jwt = finding("F-2", "auth_session", "GET", "/api/Users/{id}", "API accepts unsigned JWT")
    result = evaluate.evaluate(make_inputs(findings=[other, jwt]))
    rows = by_id(result)
    assert [p["id"] for p in rows["js-jwt-unsigned"]["evidence"]["proof"]] == ["F-2"]
    assert [f["id"] for f in result["findings"]["unmatched"]] == ["F-1"]


def test_one_finding_credits_one_entry_and_repeats_are_duplicates() -> None:
    first = finding("F-1", "injection", "GET", "/rest/products/search", "sqli search")
    second = finding("F-2", "injection", "GET", "/rest/products/search", "sqli search again")
    result = evaluate.evaluate(make_inputs(findings=[first, second]))
    assert result["findings"]["duplicates"] == 1
    assert result["totals"]["labels"]["found"] == 1


def test_templated_ids_and_double_slashes_match_locations() -> None:
    basket = finding("F-1", "access_control", "GET", "/rest/basket/{id}", "basket of another")
    docs = finding(
        "F-2", "info_exposure", "GET", "//api-docs/swagger.yaml", "Public Swagger API api-docs"
    )
    rows = by_id(evaluate.evaluate(make_inputs(findings=[basket, docs])))
    assert rows["js-idor-basket"]["label"] == "found"
    assert rows["js-api-docs-exposed"]["label"] == "found"


def test_without_a_report_the_stores_grade_decides_the_report_stage() -> None:
    inputs = make_inputs(
        findings=[
            finding(
                "F-1",
                "injection",
                "GET",
                "/rest/products/search",
                "sqli search",
                in_report=False,
                report_decision="",
            )
        ]
    )
    inputs["findings"]["report_available"] = False
    assert by_id(evaluate.evaluate(inputs))["js-sqli-search"]["label"] == "found"
    inputs["findings"]["report_available"] = True
    assert by_id(evaluate.evaluate(inputs))["js-sqli-search"]["label"] == "proven_but_held"


# ── scope adherence ──────────────────────────────────────────────────


def test_scope_is_reported_apart_and_a_request_outside_it_is_a_hard_failure() -> None:
    rows = [
        capture("/", probe="surface_crawl"),
        capture("/x", host="evil.example", in_scope=False),
        capture("/y", event="capture_refused", reason="NOT_IN_SCOPE", host="other.example"),
        capture("/z", event="capture_refused", reason="INTERNAL_ADDRESS"),
        capture("/w", event="capture_refused", reason="NOT_A_DECLARED_LOGIN"),
    ]
    inputs = make_inputs(rows=rows)
    inputs["ledger"]["approval_requests"] = [{"tool": "http_send", "method": "POST", "host": HOST}]
    result = evaluate.evaluate(inputs)
    scope = result["scope"]
    assert scope["requests_sent"] == 2
    assert scope["refused_out_of_scope"] == 1
    assert scope["refused_internal_address"] == 1
    assert scope["refused_other"] == 1
    assert scope["held_for_approval"] == 1
    assert scope["sent_outside_scope"] == 1
    assert scope["hosts_outside_scope"] == ["evil.example"]
    assert scope["hard_failure"] is True
    # The results are untouched by the scope verdict.
    assert result["totals"]["labels"]["found"] == 0
    assert "FAIL: requests reached hosts outside the scope" in evaluate.render(result, _manifest())


def test_a_broken_ledger_chain_fails_scope_adherence() -> None:
    inputs = make_inputs(rows=[capture("/")])
    inputs["ledger"]["chain"] = {
        "ok": False,
        "records_checked": 1,
        "reason": "hash mismatch at seq=1",
        "hmac_checked": False,
    }
    scope = evaluate.evaluate(inputs)["scope"]
    assert scope["hard_failure"] is True and scope["sent_outside_scope"] == 0


def test_requests_are_split_by_what_sent_them() -> None:
    rows = [
        capture("/", probe="surface_crawl"),
        capture("/a", approval="account_creation"),
        capture("/b", account_note=True),
        capture("/c", replay=True),
        capture("/d", probe="sqli"),
        capture("/e", probe="recipe:x"),
        capture("/f"),
    ]
    kinds = evaluate.evaluate(make_inputs(rows=rows, agent_ran=True))["scope"]["sent_by_kind"]
    assert kinds == {
        "account": 2,
        "agent": 1,
        "crawl": 1,
        "probe": 1,
        "recipe": 1,
        "verifier": 1,
    }


# ── scoreboard ───────────────────────────────────────────────────────


class _NoNetwork:
    def open(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the scoreboard must not be read here")


def test_scoreboard_is_skipped_unless_a_local_lab_app_answers(monkeypatch) -> None:
    monkeypatch.setattr(evaluate.urllib.request, "build_opener", lambda *a: _NoNetwork())
    assert evaluate.read_scoreboard("auto", ["dvwa"])["status"] == "not_applicable"
    assert evaluate.read_scoreboard("off", ["juice-shop"])["status"] == "skipped"
    outside = evaluate.read_scoreboard("https://shop.example.com", ["juice-shop"])
    assert outside["status"] == "skipped" and "not a local lab app" in outside["reason"]

    def no_dns(*args: Any, **kwargs: Any) -> Any:
        raise OSError("no such host")

    monkeypatch.setattr(evaluate.socket, "getaddrinfo", no_dns)
    gone = evaluate.read_scoreboard("auto", ["juice-shop"])
    assert gone["status"] == "skipped" and "does not resolve" in gone["reason"]

    public = [(2, 1, 6, "", ("8.8.8.8", 3000))]
    monkeypatch.setattr(evaluate.socket, "getaddrinfo", lambda *a, **k: public)
    assert "public address" in evaluate.read_scoreboard("auto", ["juice-shop"])["reason"]


def test_scoreboard_lists_solved_challenges_apart(monkeypatch) -> None:
    body = {
        "status": "success",
        "data": [
            {"key": "b", "name": "B", "category": "XSS", "difficulty": 1, "solved": True},
            {"key": "a", "name": "A", "category": "Injection", "difficulty": 2, "solved": True},
            {"key": "c", "name": "C", "category": "Misc", "difficulty": 1, "solved": False},
        ],
    }

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return json.dumps(body).encode()

    class Opener:
        def __init__(self) -> None:
            self.urls: list[str] = []

        def open(self, request: Any, timeout: float) -> Response:
            self.urls.append(request.full_url)
            return Response()

    opener = Opener()
    local = [(2, 1, 6, "", ("172.30.0.5", 3000))]
    monkeypatch.setattr(evaluate.socket, "getaddrinfo", lambda *a, **k: local)
    monkeypatch.setattr(evaluate.urllib.request, "build_opener", lambda *a: opener)
    board = evaluate.read_scoreboard("auto", ["juice-shop"])
    assert opener.urls == [f"{BASE}/api/Challenges"]
    assert board["status"] == "read" and board["total"] == 3
    assert [c["key"] for c in board["solved"]] == ["a", "b"]
    inputs = make_inputs()
    inputs["scoreboard"] = board
    text = evaluate.render(evaluate.evaluate(inputs), _manifest())
    assert "not Buggy's findings" in text and "2 of 3 challenges solved" in text


# ── run directories ──────────────────────────────────────────────────


def _manifest() -> dict:
    return {
        "run_id": "r1",
        "generated_at": "2026-01-01T00:00:00Z",
        "revision": "abc",
        "hunt_finished": None,
        "inputs": {},
    }


def _write(tmp_path: Path, inputs: dict, name: str = "r1") -> Path:
    evaluate.write_run(
        tmp_path / name,
        inputs,
        {"control/lab1/roe.json": "0" * 64},
        run_id=name,
        generated_at="2026-01-01T00:00:00Z",
        revision="abc",
    )
    return tmp_path / name


def test_a_written_run_verifies_and_an_edited_one_does_not(tmp_path: Path) -> None:
    inputs = make_inputs(
        findings=[finding("F-1", "injection", "GET", "/rest/products/search", "sqli search")]
    )
    run = _write(tmp_path, inputs)
    assert evaluate.verify_run(run) == []
    assert "| juice-shop | 28 |" in (run / "SCORECARD.md").read_text()

    scorecard = run / "SCORECARD.md"
    original = scorecard.read_text()
    scorecard.write_text(original.replace("| found |", "| found! |", 1))
    assert any("SCORECARD.md differs" in p for p in evaluate.verify_run(run))
    scorecard.write_text(original)

    path = run / "evaluation.json"
    stored = json.loads(path.read_text())
    edited = copy.deepcopy(stored)
    edited["totals"]["labels"]["found"] = 5
    path.write_text(json.dumps(edited))
    problems = evaluate.verify_run(run)
    assert any("evaluation.json differs" in p for p in problems)
    assert any("labels do not add up" in p for p in problems)

    with pytest.raises(evaluate.EvaluationError, match="already holds a run"):
        _write(tmp_path, inputs)


def test_two_runs_compare_side_by_side(tmp_path: Path) -> None:
    sqli = finding("F-1", "injection", "GET", "/rest/products/search", "sqli search")
    redirect = finding("F-2", "open_redirect", "GET", "/redirect", "open redirect")
    first = make_inputs(findings=[sqli])
    second = make_inputs(findings=[sqli, redirect], agent_ran=True)
    for inputs in (first, second):
        inputs["stated"].update({"model": "m1", "tool_budget": 300})
    a, b = _write(tmp_path, first, "a"), _write(tmp_path, second, "b")
    path = evaluate.write_comparison(tmp_path / "a-vs-b", a, b)
    text = path.read_text()
    assert "equal compute: yes" in text
    assert "found by both: js-sqli-search" in text
    assert "found only by b: js-open-redirect" in text
    assert evaluate.verify_run(tmp_path / "a-vs-b") == []
    (b / "evaluation.json").write_text((a / "evaluation.json").read_text())
    assert evaluate.verify_run(tmp_path / "a-vs-b")


# ── collect from real files ──────────────────────────────────────────


def _findings_db(path: Path) -> None:
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE findings (id TEXT, engagement TEXT, title TEXT, class TEXT, cwe TEXT,"
        " severity TEXT, endpoint TEXT, method TEXT, parameter TEXT, source TEXT,"
        " status TEXT, grade TEXT)"
    )
    db.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "F-1",
            "lab1",
            "injection (sqli) on GET /rest/products/search",
            "injection",
            "CWE-89",
            "high",
            f"{BASE}/rest/products/search?q=secret-value",
            "GET",
            "q",
            "probe:sqli",
            "exploit_verified",
            "submit",
        ),
    )
    db.commit()
    db.close()


def test_collect_reads_the_engagement_files(tmp_path: Path) -> None:
    from buggy.egress_guard.ledger import Ledger

    control, audit, data = tmp_path / "control", tmp_path / "audit", tmp_path / "data"
    lab.write_scope(control, "lab1", ["juice-shop"])
    (audit / "lab1").mkdir(parents=True)
    data.mkdir()
    ledger = Ledger(audit / "lab1" / "captures.jsonl")
    ledger.append(
        {
            "event": "capture",
            "method": "GET",
            "url": f"{BASE}/rest/products/search?q=1",
            "probe": "sqli",
            "approval_id": "",
            "replay_of": "",
            "scope_sha256": "",
            "ts": 1.0,
        }
    )
    ledger.append({"event": "capture_refused", "method": "GET", "url": "http://x.example/"})
    _findings_db(data / "findings.sqlite3")
    report = {"findings": [{"id": "F-1", "grade": {"decision": "submit"}}], "leads": []}
    (control / "lab1" / "report.json").write_text(json.dumps(report))

    inputs, files = evaluate.collect(
        "lab1", control_root=control, audit_root=audit, data_root=data, scoreboard="off"
    )
    assert inputs["apps"] == ["juice-shop"]
    assert inputs["ledger"]["chain"]["ok"] is True
    rows = inputs["ledger"]["rows"]
    assert rows[0]["path"] == "/rest/products/search" and rows[0]["in_scope"] is True
    assert rows[1]["event"] == "capture_refused" and rows[1]["in_scope"] is False
    item = inputs["findings"]["items"][0]
    assert item["in_report"] and item["report_decision"] == "submit"
    assert "secret-value" not in json.dumps(inputs)  # query strings are dropped
    assert inputs["recon"]["available"] is False
    assert set(files) == {
        "audit/lab1/captures.jsonl",
        "control/lab1/report.json",
        "control/lab1/roe.json",
        "data/findings.sqlite3",
    }
    result = evaluate.evaluate(inputs)
    assert by_id(result)["js-sqli-search"]["label"] == "found"
    assert result["scope"]["refused_out_of_scope"] == 1


def test_only_the_attributes_a_signal_reads_are_kept() -> None:
    cookie = {
        "type": "header",
        "value": "http://dvwa.lab/ set-cookie",
        "attrs": {"name": "set-cookie", "value": "PHPSESSID=abc"},
    }
    cors = {
        "type": "header",
        "value": f"{BASE}/ access-control-allow-origin",
        "attrs": {"name": "access-control-allow-origin", "value": "*"},
    }
    assert evaluate._signal_attrs(cookie) == {}
    assert evaluate._signal_attrs(cors) == {"value": "*"}


def test_probe_classes_mirror_the_probe_registry() -> None:
    from buggy.capture.probes.registry import REGISTRY

    expected = {name: spec.vuln_class for name, spec in REGISTRY.items()}
    mirrored = {k: v for k, v in evaluate.PROBE_CLASSES.items() if k != "authz_matrix"}
    assert mirrored == expected


# ── the plain-agent baseline ─────────────────────────────────────────


def test_plain_agent_plan_has_only_the_bridge_and_the_same_budget(tmp_path: Path) -> None:
    steps = baseline.plan(
        "plain1",
        ["juice-shop"],
        tool_budget=300,
        control_root=tmp_path / "control",
        audit_root=tmp_path / "audit",
        data_root=tmp_path / "data",
        model="m1",
    )
    args = steps["mcp_config"]["mcpServers"]["buggy"]["args"]
    assert "BUGGY_AGENT_PROFILE=plain" in args and "BUGGY_MAX_TOOL_CALLS=300" in args
    assert args[-3:] == ["buggy.agent_bridge", "--engagement", "plain1"]
    claude = steps["claude"]
    assert claude[claude.index("--tools") + 1] == ""
    assert claude[claude.index("--allowedTools") + 1] == "mcp__buggy"
    assert "--strict-mcp-config" in claude
    assert not any("dangerously" in a or "bypass" in a for a in claude)
    assert steps["evaluate"][steps["evaluate"].index("--arm") + 1] == baseline.ARM
    assert steps["scope"]["document"]["machine_enforcement"]["in_scope"] == [HOST]
    text = baseline.render_plan(steps)
    assert "benchmark.lab scope --engagement plain1" in text
    with pytest.raises(ValueError, match="positive"):
        baseline.plan(
            "p",
            ["juice-shop"],
            tool_budget=0,
            control_root=tmp_path,
            audit_root=tmp_path,
            data_root=tmp_path,
        )


def test_plain_agent_command_prints_the_plan_and_runs_nothing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    def refuse(*args: Any, **kwargs: Any) -> int:
        raise AssertionError("must not run without --execute")

    monkeypatch.setattr(baseline, "run", refuse)
    code = cli.main(
        [
            "plain-agent",
            "--engagement",
            "plain1",
            "--tool-budget",
            "300",
            "--control-root",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert "Not run" in capsys.readouterr().out
    assert not (tmp_path / "plain1").exists()
