"""``buggy-cli hunt``: a URL in, an enforced scope, recon, a report, then agents."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from buggy.cli import hunt
from buggy.middleware.roe import parse_roe_document
from buggy.pipeline.scope import PipelineLimits, ScopeFilter


def _args(*argv: str):
    return hunt._build_parser().parse_args(list(argv))


def _run(tmp_path: Path, *argv: str) -> int:
    return hunt.main(
        [
            *argv,
            "--workspace-root",
            str(tmp_path / "workspace"),
            "--control-root",
            str(tmp_path / "control"),
            "--engagement-name",
            "acme",
        ]
    )


def _roe(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "control" / "acme" / "roe.json").read_text())


class TestScopeFromAUrl:
    def test_a_url_becomes_exactly_its_host_and_keeps_the_url_as_a_seed(self) -> None:
        scope = hunt.build_scope(_args("https://app.acme.test:8443/shop?x=1"))
        assert scope["in_scope"] == ["app.acme.test"]
        assert scope["document_extra"]["pipeline"]["seed_urls"] == [
            "https://app.acme.test:8443/shop?x=1"
        ]

    def test_scope_is_never_widened_unless_asked(self) -> None:
        scope = hunt.build_scope(_args("app.acme.test", "api.acme.test"))
        assert scope["in_scope"] == ["app.acme.test", "api.acme.test"]
        widened = hunt.build_scope(_args("acme.test", "--include-subdomains"))
        assert widened["in_scope"] == ["acme.test", "**.acme.test"]
        extra = hunt.build_scope(_args("acme.test", "--scope", "*.cdn.acme.test,10.1.2.0/24"))
        assert extra["in_scope"] == ["acme.test", "*.cdn.acme.test", "10.1.2.0/24"]
        assert hunt.build_scope(_args("acme.test", "--exclude", "old.acme.test"))[
            "out_of_scope"
        ] == ["old.acme.test"]

    @pytest.mark.parametrize(
        ("target", "host"),
        [
            ("http://juice-shop.lab:3000", "juice-shop.lab"),
            ("HTTPS://App.Acme.Test/", "app.acme.test"),
            ("10.0.0.5:8080", "10.0.0.5"),
            ("10.0.0.0/28", "10.0.0.0/28"),
            ("user@app.acme.test", "app.acme.test"),
        ],
    )
    def test_host_extraction(self, target: str, host: str) -> None:
        assert hunt._scope_host(target) == host

    def test_safe_defaults(self) -> None:
        scope = hunt.build_scope(_args("https://app.acme.test"))
        assert scope["rps"] == hunt.DEFAULT_RPS
        assert scope["enforcement_extra"]["sandbox_egress"] == "blocked"
        assert scope["enforcement_extra"]["min_inter_request_delay_ms"] == 100
        assert scope["document_extra"]["approvals"] == {"state_changing": "required"}
        assert scope["document_extra"]["network"] == {"allow_private_targets": False}
        assert scope["document_extra"]["pipeline"]["port_scan"] is False

    def test_lab_and_opt_ins_are_explicit(self) -> None:
        lab = hunt.build_scope(_args("http://juice-shop.lab:3000", "--lab"))
        assert lab["enforcement_extra"]["sandbox_egress"] == "scoped"
        assert lab["document_extra"]["approvals"] == {"state_changing": "not_required"}
        assert lab["document_extra"]["network"] == {"allow_private_targets": True}
        opened = hunt.build_scope(_args("app.acme.test", "--allow-sandbox-network"))
        assert opened["enforcement_extra"]["sandbox_egress"] == "scoped"
        assert opened["document_extra"]["approvals"] == {"state_changing": "required"}
        assert hunt.build_scope(_args("10.0.0.5"))["document_extra"]["network"] == {
            "allow_private_targets": True
        }
        assert hunt.build_scope(_args("a.test", "--rps", "9999"))["rps"] == hunt.MAX_RPS


class TestWhatGetsWritten:
    def test_plan_only_writes_an_enforced_scope_the_guardrail_and_pipeline_accept(
        self, tmp_path: Path
    ) -> None:
        code = _run(tmp_path, "https://app.acme.test:8443/shop", "--yes", "--plan-only")
        assert code == 0
        document = _roe(tmp_path)
        assert document["generated_by"] == "buggy-cli hunt"
        rules = parse_roe_document(document, required=True)
        assert rules.mode.value == "enforce" and rules.sandbox_blocked is True
        scope = ScopeFilter.from_document(document)
        assert scope.allows("https://app.acme.test:8443/shop")
        assert not scope.allows("https://other.acme.test/")
        limits = PipelineLimits.from_roe(rules, document)
        assert limits.rate_limit_rps == hunt.DEFAULT_RPS and limits.port_scan is False
        assert limits.seed_urls == ("https://app.acme.test:8443/shop",)
        # The agent-readable draft mirrors it.
        draft = json.loads((tmp_path / "workspace" / "acme" / "plan" / "roe.json").read_text())
        assert draft["machine_enforcement"] == document["machine_enforcement"]

    def test_nothing_is_written_without_an_authorization_answer(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        assert _run(tmp_path, "https://app.acme.test", "--plan-only") == hunt.EXIT_CONFIG
        assert not (tmp_path / "control").exists()
        assert "authorized" in capsys.readouterr().err

        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _prompt: "n")
        assert _run(tmp_path, "https://app.acme.test", "--plan-only") == hunt.EXIT_CONFIG
        assert not (tmp_path / "control").exists()

        monkeypatch.setattr("builtins.input", lambda _prompt: "y")
        assert _run(tmp_path, "https://app.acme.test", "--plan-only") == 0
        assert (tmp_path / "control" / "acme" / "roe.json").exists()

    def test_an_invalid_scope_pattern_is_refused(self, tmp_path: Path, capsys) -> None:
        code = _run(tmp_path, "app.acme.test", "--scope", "not a host!", "--yes", "--plan-only")
        assert code == hunt.EXIT_CONFIG and not (tmp_path / "control").exists()


class _FakeRecon:
    """Stands in for the read-only recon server."""

    def __init__(self, statuses: list[str], records: dict[str, list[dict]]) -> None:
        self.statuses = statuses
        self.records = records
        self.previous: dict[str, Any] | None = None
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, tool: str, engagement: str, **arguments: Any) -> dict[str, Any]:
        self.calls.append((tool, arguments))
        if tool == "recon_summary":
            status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            counts = {k: len(v) for k, v in self.records.items()} if status == "completed" else {}
            current = (
                {"run_id": "run-1", "stage": "issues", "started_at": 2e9}
                if status == "running"
                else None
            )
            last = (
                {"run_id": "run-1", "status": status, "scope_drops": 2, "started_at": 2e9}
                if status == "completed"
                else self.previous
            )
            return {
                "engagement": engagement,
                "records": counts,
                "current_run": current,
                "last_run": last,
            }
        rows = self.records.get(arguments["record_type"], [])
        start = int(arguments.get("offset") or 0)
        page = rows[start : start + 200]
        more = start + 200 < len(rows)
        return {"records": page, "truncated": more, "next_offset": start + 200 if more else None}


RECORDS: dict[str, list[dict]] = {
    "http_service": [
        {
            "type": "http_service",
            "value": "https://app.acme.test/",
            "attrs": {"status_code": 200, "title": "Acme"},
        }
    ],
    "vulnerability": [
        {
            "id": "rec-1",
            "type": "vulnerability",
            "value": "swagger-api https://app.acme.test/api-docs",
            "attrs": {
                "template_id": "swagger-api",
                "name": "Public Swagger API",
                "severity": "info",
            },
        },
        {
            "id": "rec-2",
            "type": "vulnerability",
            "value": "exposed-env https://app.acme.test/.env",
            "attrs": {
                "template_id": "exposed-env",
                "name": "Exposed .env file",
                "severity": "high",
            },
        },
    ],
    "api_operation": [
        {
            "type": "api_operation",
            "value": "GET https://app.acme.test/api/orders/{orderId}",
            "attrs": {
                "method": "GET",
                "url": "https://app.acme.test/api/orders/{orderId}",
                "auth_required": True,
            },
        }
    ],
    "graphql": [
        {
            "type": "graphql",
            "value": "https://app.acme.test/graphql",
            "attrs": {"introspection_enabled": True},
        }
    ],
}


class TestTheWholeFlow:
    def test_recon_is_watched_then_reported_and_agents_are_optional(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        recon = _FakeRecon(["none", "running", "running", "completed"], RECORDS)
        monkeypatch.setattr(hunt, "_recon", recon)
        monkeypatch.setattr(hunt, "recon_available", lambda: True)
        monkeypatch.setattr(hunt.time, "sleep", lambda _s: None)
        monkeypatch.setattr(hunt, "RECON_POLL_SECONDS", 0.0)
        code = _run(tmp_path, "https://app.acme.test", "--yes", "--no-agent")
        assert code == 0
        err = capsys.readouterr().err
        for stage in (
            "[1/4] scope enforced",
            "[2/4] recon",
            "[3/4] recon report",
            "[4/4] agents skipped",
        ):
            assert stage in err, stage
        assert "1 high" in err and "1 info" in err

        report = (tmp_path / "control" / "acme" / "recon-report.md").read_text()
        assert "No LLM was involved" in report
        assert report.index("[HIGH] Exposed .env file") < report.index("[INFO] Public Swagger API")
        assert "Do not publish API documentation" in report  # remediation for the swagger issue
        assert "| access_control | GET https://app.acme.test/api/orders/{orderId}" in report
        assert "`graphql_checks`" in report and "`idor`" in report

    def test_agents_get_a_kickoff_that_points_at_recon_and_the_gateway(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(hunt, "_recon", _FakeRecon(["completed"], RECORDS))
        monkeypatch.setattr(hunt, "recon_available", lambda: True)
        sent: dict[str, Any] = {}

        def fake_kickoff(**kwargs: Any) -> dict[str, Any]:
            sent.update(kwargs)
            return {"thread_id": "t", "event_count": 3}

        monkeypatch.setattr(hunt, "_stream_kickoff", fake_kickoff)
        monkeypatch.setattr(hunt, "model_configured", lambda: True)
        code = _run(tmp_path, "https://app.acme.test", "--yes", "--instruction", "accounts a/b")
        assert code == 0
        assert sent["engagement_name"] == "acme" and sent["assistant"] == "buggy"
        text = sent["kickoff"]
        for phrase in (
            "Recon is already done",
            "recon_query",
            "probe_run",
            "sandbox has no network path",
            "APPROVAL_REQUIRED",
            "report_record_finding",
            "accounts a/b",
        ):
            assert phrase in text, phrase

    def test_a_failed_agent_run_still_leaves_the_recon_report(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(hunt, "_recon", _FakeRecon(["completed"], RECORDS))
        monkeypatch.setattr(hunt, "recon_available", lambda: True)

        def boom(**_kwargs: Any) -> dict[str, Any]:
            raise ConnectionError("langgraph is not reachable")

        monkeypatch.setattr(hunt, "_stream_kickoff", boom)
        monkeypatch.setattr(hunt, "model_configured", lambda: True)
        assert _run(tmp_path, "https://app.acme.test", "--yes") == hunt.EXIT_INTERNAL
        assert (tmp_path / "control" / "acme" / "recon-report.md").exists()
        assert "Recon and the report above are complete" in capsys.readouterr().err

    def test_recon_wait_gives_up_at_the_timeout_and_says_so(self, monkeypatch) -> None:
        monkeypatch.setattr(hunt, "_recon", _FakeRecon(["running"], {}))
        now = [0.0]

        def tick(_seconds: float) -> None:
            now[0] += 10.0

        summary = hunt.wait_for_recon(
            "acme", timeout=25.0, poll=10.0, quiet=True, sleep=tick, clock=lambda: now[0]
        )
        assert summary["timed_out"] is True and summary["current_run"]["stage"] == "issues"

    def test_an_older_finished_run_is_not_mistaken_for_this_one(self, monkeypatch, capsys) -> None:
        recon = _FakeRecon(["none", "none", "running", "completed"], RECORDS)
        recon.previous = {"run_id": "run-0", "status": "completed", "started_at": 1000.0}
        monkeypatch.setattr(hunt, "_recon", recon)
        summary = hunt.wait_for_recon(
            "acme", timeout=600.0, since=1.5e9, poll=0.0, sleep=lambda _s: None
        )
        assert summary["last_run"]["run_id"] == "run-1" and not summary.get("timed_out")
        err = capsys.readouterr().err
        assert "waiting for the pipeline" in err and "checking for known issues" in err

    def test_without_a_reachable_recon_server_the_hunt_still_proceeds(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        assert _run(tmp_path, "https://app.acme.test", "--yes", "--no-agent") == 0
        assert "recon not watched" in capsys.readouterr().err


class TestModelCheck:
    @pytest.mark.parametrize(
        ("env", "expected"),
        [
            ({}, False),
            ({"ANTHROPIC_API_KEY": "your-anthropic-key-here"}, False),  # template placeholder
            ({"LITELLM_API_KEY": "sk-real"}, False),  # the gateway's own key is not a provider
            ({"OPENAI_API_KEY": ""}, False),
            ({"ANTHROPIC_API_KEY": "sk-ant-real-key"}, True),
            ({"BUGGY_AUTH_CLAUDE_CODE": "true"}, True),
            ({"BUGGY_AUTH_CLAUDE_CODE": "false"}, False),
            ({"OLLAMA_API_BASE": "http://host.docker.internal:11434"}, True),
        ],
    )
    def test_detection(self, env: dict, expected: bool) -> None:
        assert hunt.model_configured(env) is expected

    def test_without_a_model_the_agent_stage_is_skipped_with_the_next_step(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        monkeypatch.setattr(hunt, "model_configured", lambda: False)
        monkeypatch.setattr(hunt, "_stream_kickoff", lambda **_k: pytest.fail("run was started"))
        assert _run(tmp_path, "https://app.acme.test", "--yes") == 0
        err = capsys.readouterr().err
        assert "no model is configured" in err and "buggy onboard" in err


# ── resume, the result file and exit codes ───────────────────────────


@pytest.fixture(autouse=True)
def _isolated_stack(tmp_path: Path, monkeypatch) -> None:
    """No test reads the developer's own audit tree or a real capture server."""
    monkeypatch.delenv("BUGGY_ENGAGEMENT_AUDIT", raising=False)
    monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(tmp_path / "audit"))
    monkeypatch.delenv("BUGGY_MCP_CAPTURE_URL", raising=False)


def _roots(tmp_path: Path) -> list[str]:
    return [
        "--workspace-root",
        str(tmp_path / "workspace"),
        "--control-root",
        str(tmp_path / "control"),
    ]


def _roe_path(tmp_path: Path) -> Path:
    return tmp_path / "control" / "acme" / "roe.json"


def _result_path(tmp_path: Path) -> Path:
    return tmp_path / "control" / "acme" / "hunt-result.json"


def _result(tmp_path: Path) -> dict[str, Any]:
    return json.loads(_result_path(tmp_path).read_text())


def _fingerprint(path: Path) -> tuple[int, int, bytes]:
    """Inode, modification time and bytes: any rewrite changes at least one of them."""
    stat = path.stat()
    return stat.st_ino, stat.st_mtime_ns, path.read_bytes()


def _age(path: Path) -> None:
    """Move the file's time far into the past, so a rewrite cannot land on the same tick."""
    os.utime(path, ns=(10**18, 10**18))


def _no_prompt(monkeypatch) -> None:
    """Nobody is at the terminal, and asking is a test failure."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("the command prompted"))


ZERO = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
NO_FINDINGS = {"available": False, "exploit_verified": ZERO, "inconclusive": 0, "candidates": 0}
CLEAN_RECORDS: dict[str, list[dict]] = {"http_service": RECORDS["http_service"]}
INFO_ONLY_RECORDS: dict[str, list[dict]] = {
    "http_service": RECORDS["http_service"],
    "vulnerability": RECORDS["vulnerability"][:1],
}


def _watch(monkeypatch, statuses: list[str], records: dict[str, list[dict]]) -> _FakeRecon:
    recon = _FakeRecon(statuses, records)
    monkeypatch.setattr(hunt, "_recon", recon)
    monkeypatch.setattr(hunt, "recon_available", lambda: True)
    monkeypatch.setattr(hunt.time, "sleep", lambda _s: None)
    return recon


class _FakeCapture:
    """Stands in for the capture server's ``findings_list``."""

    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self.findings = findings
        self.calls: list[tuple[str, str]] = []

    def __call__(self, tool: str, engagement: str, **_arguments: Any) -> dict[str, Any]:
        self.calls.append((tool, engagement))
        return {"findings": self.findings}


def _finding(number: int, severity: str, status: str) -> dict[str, Any]:
    return {
        "id": f"F-{number:012x}",
        "engagement": "acme",
        "title": f"finding {number}",
        "class": "access_control",
        "severity": severity,
        "status": status,
        "grade": None,
    }


class TestResume:
    FIRST = ("https://app.acme.test", "--include-subdomains", "--rps", "7", "--no-agent")

    def test_the_same_command_line_rewrites_nothing_and_does_not_prompt(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        assert _run(tmp_path, *self.FIRST, "--yes") == 0
        draft = tmp_path / "workspace" / "acme" / "plan" / "roe.json"
        _age(_roe_path(tmp_path))
        _age(draft)
        enforced_before, draft_before = _fingerprint(_roe_path(tmp_path)), _fingerprint(draft)
        capsys.readouterr()

        _no_prompt(monkeypatch)  # and no --yes
        assert _run(tmp_path, *self.FIRST) == 0
        err = capsys.readouterr().err
        assert "resuming acme" in err and "You are about to test" not in err
        assert _fingerprint(_roe_path(tmp_path)) == enforced_before
        assert _fingerprint(draft) == draft_before
        assert "[4/4] agents skipped (--no-agent)" in err  # it did run, not just stop

    def test_the_fingerprint_does_see_a_rewrite(self, tmp_path: Path, monkeypatch) -> None:
        """Negative control for the test above: a confirmed change is a different file."""
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        assert _run(tmp_path, *self.FIRST, "--yes") == 0
        _age(_roe_path(tmp_path))
        before = _fingerprint(_roe_path(tmp_path))
        assert _run(tmp_path, *self.FIRST, "--rps", "8", "--yes") == 0
        after = _fingerprint(_roe_path(tmp_path))
        assert after[1] != before[1] and after[2] != before[2]
        assert _roe(tmp_path)["pipeline"]["rate_limit_rps"] == 8

    def test_what_is_compared_is_exactly_what_gets_written(self, tmp_path: Path) -> None:
        argv = ("https://app.acme.test", "--exclude", "old.acme.test", "--port-scan", "--lab")
        assert _run(tmp_path, *argv, "--mode", "warn", "--yes", "--plan-only") == 0
        stored = _roe(tmp_path)
        requested = hunt.requested_blocks(hunt.build_scope(_args(*argv)), "warn")
        assert tuple(requested) == hunt.COMPARED_BLOCKS
        assert {name: stored[name] for name in hunt.COMPARED_BLOCKS} == requested
        assert hunt.scope_diff(stored, requested) == []

    def test_a_changed_scope_shows_the_diff_and_is_refused_without_confirmation(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        assert _run(tmp_path, "https://app.acme.test", "--no-agent", "--yes") == 0
        draft = tmp_path / "workspace" / "acme" / "plan" / "roe.json"
        _age(_roe_path(tmp_path))
        _age(_result_path(tmp_path))

        def on_disk() -> tuple:
            return (
                _fingerprint(_roe_path(tmp_path)),
                _fingerprint(draft),
                _fingerprint(_result_path(tmp_path)),
            )

        before = on_disk()
        capsys.readouterr()

        wider = ("https://app.acme.test", "api.acme.test", "--include-subdomains", "--rps", "20")
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        assert _run(tmp_path, *wider, "--lab", "--no-agent") == hunt.EXIT_CONFIG
        err = capsys.readouterr().err
        for line in (
            "machine_enforcement.in_scope: + api.acme.test",
            "machine_enforcement.in_scope: + **.app.acme.test",
            "machine_enforcement.sandbox_egress: blocked -> scoped",
            "machine_enforcement.min_inter_request_delay_ms: 100 -> 50",
            "pipeline.rate_limit_rps: 10 -> 20",
            "approvals.state_changing: required -> not_required",
            "network.allow_private_targets: false -> true",
        ):
            assert line in err, line
        assert "the stored scope is kept" in err and "--yes" in err
        assert "[1/4]" not in err and "resuming" not in err
        assert on_disk() == before

        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _prompt: "n")
        assert _run(tmp_path, *wider, "--no-agent") == hunt.EXIT_CONFIG
        # Nothing on disk changed, in either tree, and no run was recorded.
        assert on_disk() == before

        monkeypatch.setattr("builtins.input", lambda _prompt: "y")
        assert _run(tmp_path, *wider, "--no-agent") == 0
        assert _roe(tmp_path)["machine_enforcement"]["in_scope"] == [
            "app.acme.test",
            "api.acme.test",
            "**.app.acme.test",
            "**.api.acme.test",
        ]

    @pytest.mark.parametrize(
        ("change", "field"),
        [
            (("--mode", "audit"), "machine_enforcement.mode: enforce -> audit"),
            (("--exclude", "old.acme.test"), "machine_enforcement.out_of_scope: + old.acme.test"),
            (("--allow-sandbox-network",), "machine_enforcement.sandbox_egress: blocked -> scoped"),
            (("--port-scan",), "pipeline.port_scan: false -> true"),
            (("--crawl-exclude", "/admin"), "pipeline.crawl_exclude: + /admin"),
            (("--internal",), "network.allow_private_targets: false -> true"),
            (("--lab",), "approvals.state_changing: required -> not_required"),
        ],
    )
    def test_a_difference_in_any_compared_block_needs_a_yes(
        self, tmp_path: Path, monkeypatch, capsys, change: tuple[str, ...], field: str
    ) -> None:
        assert _run(tmp_path, "https://app.acme.test", "--yes", "--plan-only") == 0
        before = _fingerprint(_roe_path(tmp_path))
        _no_prompt(monkeypatch)
        code = _run(tmp_path, "https://app.acme.test", *change, "--plan-only")
        assert code == hunt.EXIT_CONFIG
        assert field in capsys.readouterr().err
        assert _fingerprint(_roe_path(tmp_path)) == before

    def test_narrowing_is_a_change_too_and_yes_accepts_it(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        both = ("app.acme.test", "api.acme.test")
        assert _run(tmp_path, *both, "--yes", "--plan-only") == 0
        _no_prompt(monkeypatch)
        assert _run(tmp_path, "app.acme.test", "--plan-only") == hunt.EXIT_CONFIG
        assert "machine_enforcement.in_scope: - api.acme.test" in capsys.readouterr().err
        assert _roe(tmp_path)["machine_enforcement"]["in_scope"] == list(both)

        assert _run(tmp_path, "app.acme.test", "--plan-only", "--yes") == 0
        err = capsys.readouterr().err
        assert "machine_enforcement.in_scope: - api.acme.test" in err  # --yes is not silent
        assert _roe(tmp_path)["machine_enforcement"]["in_scope"] == ["app.acme.test"]

    def test_a_stored_scope_that_cannot_be_read_is_not_replaced_silently(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        _roe_path(tmp_path).parent.mkdir(parents=True)
        _roe_path(tmp_path).write_text("{ not json", encoding="utf-8")
        _no_prompt(monkeypatch)
        assert _run(tmp_path, "app.acme.test", "--plan-only") == hunt.EXIT_CONFIG
        assert "cannot be read" in capsys.readouterr().err
        assert _roe_path(tmp_path).read_text(encoding="utf-8") == "{ not json"

    def test_a_scope_written_by_another_command_is_compared_not_overwritten(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        imported = {
            "machine_enforcement": {
                "mode": "enforce",
                "in_scope": ["app.acme.test"],
                "out_of_scope": ["pay.acme.test"],
            }
        }
        _roe_path(tmp_path).parent.mkdir(parents=True)
        _roe_path(tmp_path).write_text(json.dumps(imported), encoding="utf-8")
        _no_prompt(monkeypatch)
        assert _run(tmp_path, "app.acme.test", "--plan-only") == hunt.EXIT_CONFIG
        err = capsys.readouterr().err
        assert "machine_enforcement.out_of_scope: - pay.acme.test" in err
        assert "pipeline: (not set) -> " in err
        assert _roe(tmp_path) == imported

    def test_a_resumed_run_continues_from_the_recon_that_exists(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        """The pipeline does not run again for an unchanged scope, so a resume must not wait
        for a new run; a first run must not take an older run for its own."""
        recon = _watch(monkeypatch, ["none"], RECORDS)
        recon.previous = {"run_id": "run-0", "status": "completed", "started_at": 1000.0}
        first = ("https://app.acme.test", "--no-agent", "--recon-timeout", "0")
        assert _run(tmp_path, *first, "--yes") == hunt.EXIT_INCOMPLETE
        assert _result(tmp_path)["recon"]["state"] == "timed_out"

        _no_prompt(monkeypatch)
        assert _run(tmp_path, *first) == hunt.EXIT_OK
        assert "resuming acme" in capsys.readouterr().err
        assert _result(tmp_path)["recon"]["state"] == "completed"
        assert _result(tmp_path)["complete"] is True


class TestResumeByName:
    SCOPE_FILE_AT = 7  # index of "--scope-file" in the first command line

    def _first_run(self, tmp_path: Path, monkeypatch) -> tuple[list[str], dict[str, Any]]:
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("in: files.acme.test\nout: legacy.acme.test\n", encoding="utf-8")
        argv = [
            "https://app.acme.test/shop",
            "api.acme.test",
            "--include-subdomains",
            "--scope",
            "*.cdn.acme.test",
            "--exclude",
            "pay.acme.test",
            "--scope-file",
            str(scope_file),
            "--rps",
            "7",
            "--port-scan",
            "--crawl-exclude",
            "/logout-all",
            "--allow-sandbox-network",
            "--instruction",
            "accounts a/b",
            "--timeout",
            "1234",
            "--fail-on",
            "low",
        ]
        assert argv[self.SCOPE_FILE_AT] == "--scope-file"
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        monkeypatch.setattr(hunt, "model_configured", lambda: True)
        sent: dict[str, Any] = {}

        def fake_kickoff(**kwargs: Any) -> dict[str, Any]:
            sent.clear()
            sent.update(kwargs)
            return {"thread_id": "t", "event_count": 1}

        monkeypatch.setattr(hunt, "_stream_kickoff", fake_kickoff)
        assert _run(tmp_path, *argv, "--yes") == 0
        return argv, sent

    def test_resume_reproduces_the_original_targets_and_options(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        argv, sent = self._first_run(tmp_path, monkeypatch)
        first_kickoff = dict(sent)
        assert "accounts a/b" in first_kickoff["kickoff"]
        assert first_kickoff["timeout_seconds"] == 1234
        original = hunt._build_parser().parse_args(argv)
        original_scope = hunt.build_scope(original)
        Path(argv[self.SCOPE_FILE_AT + 1]).unlink()  # a resume must not need the file again
        _age(_roe_path(tmp_path))
        before = _fingerprint(_roe_path(tmp_path))
        capsys.readouterr()
        sent.clear()

        _no_prompt(monkeypatch)
        assert hunt.main(["--resume", "acme", *_roots(tmp_path)]) == 0
        err = capsys.readouterr().err
        assert "resuming acme" in err  # the stored options rebuild the stored scope exactly
        assert _fingerprint(_roe_path(tmp_path)) == before
        assert sent == first_kickoff  # same targets, instruction, timeout and engagement

        # The parser values a resume ends up with are the ones the first command line gave.
        resumed = hunt._build_parser().parse_args(["--resume", "acme"])
        assert hunt.apply_resume(resumed, ["--resume", "acme"], tmp_path / "control") == ""
        assert hunt.build_scope(resumed) == original_scope
        assert original_scope["in_scope"][-2:] == ["*.cdn.acme.test", "files.acme.test"]
        assert original_scope["out_of_scope"] == ["pay.acme.test", "legacy.acme.test"]
        for name in (
            "targets",
            "rps",
            "include_subdomains",
            "port_scan",
            "allow_sandbox_network",
            "lab",
            "internal",
            "crawl_exclude",
            "instruction",
            "mode",
            "timeout",
            "recon_timeout",
            "fail_on",
            "fail_on_issues",
            "no_agent",
            "force_agent",
            "no_recon_wait",
        ):
            assert getattr(resumed, name) == getattr(original, name), name
        assert resumed.engagement_name == "acme"
        assert resumed.yes is False  # a confirmation is never stored

    def test_no_agent_is_reproduced_so_a_resume_never_starts_agents_on_its_own(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        monkeypatch.setattr(hunt, "model_configured", lambda: True)
        monkeypatch.setattr(hunt, "_stream_kickoff", lambda **_k: pytest.fail("run was started"))
        assert _run(tmp_path, "app.acme.test", "--no-agent", "--yes") == 0
        assert hunt.main(["--resume", "acme", *_roots(tmp_path)]) == 0
        assert "agents skipped (--no-agent)" in capsys.readouterr().err

    def test_an_option_next_to_resume_wins_and_a_scope_it_changes_needs_a_yes(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        self._first_run(tmp_path, monkeypatch)
        before = _fingerprint(_roe_path(tmp_path))
        capsys.readouterr()
        _no_prompt(monkeypatch)
        argv = ["--resume", "acme", "--rps", "20", *_roots(tmp_path)]
        assert hunt.main(argv) == hunt.EXIT_CONFIG  # the first run's --yes was not stored
        err = capsys.readouterr().err
        assert "pipeline.rate_limit_rps: 7 -> 20" in err and "in_scope" not in err
        assert _fingerprint(_roe_path(tmp_path)) == before

        assert hunt.main([*argv, "--yes", "--plan-only"]) == 0
        document = _roe(tmp_path)
        assert document["pipeline"]["rate_limit_rps"] == 20
        assert document["hunt"]["rps"] == 20 and document["hunt"]["flags"]["port_scan"] is True
        assert document["machine_enforcement"]["out_of_scope"] == [
            "pay.acme.test",
            "legacy.acme.test",
        ]

    def test_resume_refuses_what_it_cannot_reproduce(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        _no_prompt(monkeypatch)
        roots = _roots(tmp_path)
        assert hunt.main(["--resume", "acme", *roots]) == hunt.EXIT_CONFIG
        assert "there is no enforced scope" in capsys.readouterr().err
        assert not (tmp_path / "control").exists()

        assert _run(tmp_path, "app.acme.test", "--yes", "--plan-only") == 0
        assert hunt.main(["--resume", "acme", "--engagement-name", "other", *roots]) == 2
        assert "name different engagements" in capsys.readouterr().err
        for name in ("../acme", ".acme", "a/b", " "):
            assert hunt.main(["--resume", name, *roots]) == hunt.EXIT_CONFIG, name
            assert "is not an engagement name" in capsys.readouterr().err

        # A scope without the stored settings (another command wrote it) cannot be resumed.
        document = _roe(tmp_path)
        settings = document.pop("hunt")
        _roe_path(tmp_path).write_text(json.dumps(document), encoding="utf-8")
        assert hunt.main(["--resume", "acme", *roots]) == hunt.EXIT_CONFIG
        assert "holds no hunt settings" in capsys.readouterr().err

        damaged = [
            ({"targets": []}, "targets"),
            ({"rps": "fast"}, "rps"),
            ({"flags": {"lab": "yes"}}, "flags"),
            ({"options": {**settings["options"], "mode": "off"}}, "options.mode"),
            ({"options": {**settings["options"], "scope": "a.test"}}, "options.scope"),
        ]
        for damage, named in damaged:
            document["hunt"] = {**settings, **damage}
            _roe_path(tmp_path).write_text(json.dumps(document), encoding="utf-8")
            before = _fingerprint(_roe_path(tmp_path))
            assert hunt.main(["--resume", "acme", "--yes", *roots]) == hunt.EXIT_CONFIG, named
            assert f"damaged ({named})" in capsys.readouterr().err
            assert _fingerprint(_roe_path(tmp_path)) == before
        assert not _result_path(tmp_path).exists()

        # Negative control: with the settings back, the same command resumes.
        document["hunt"] = settings
        _roe_path(tmp_path).write_text(json.dumps(document), encoding="utf-8")
        assert hunt.main(["--resume", "acme", "--plan-only", *roots]) == 0

    def test_a_target_is_required_unless_resuming(self, tmp_path: Path, capsys) -> None:
        assert hunt.main(_roots(tmp_path)) == hunt.EXIT_CONFIG
        assert "name at least one target" in capsys.readouterr().err
        assert not (tmp_path / "control").exists()


class TestExitCodesAndTheResultFile:
    GATE = ("--fail-on", "high", "--fail-on-issues")
    BASE = ("https://app.acme.test", "--yes", "--no-agent")

    def test_help_documents_the_exit_codes(self, capsys) -> None:
        with pytest.raises(SystemExit) as stopped:
            hunt.main(["--help"])
        assert stopped.value.code == 0
        out = capsys.readouterr().out
        assert "exit codes:" in out and "--fail-on" in out and "--resume" in out
        for code in (hunt.EXIT_OK, hunt.EXIT_FINDINGS, hunt.EXIT_INCOMPLETE, hunt.EXIT_CONFIG):
            assert f"\n  {code} " in out, code
        codes = (hunt.EXIT_OK, hunt.EXIT_CONFIG, hunt.EXIT_INCOMPLETE, hunt.EXIT_FINDINGS)
        assert codes == (0, 2, 3, 10)

    def test_clean_is_0(self, tmp_path: Path, monkeypatch, capsys) -> None:
        _watch(monkeypatch, ["none", "running", "completed"], CLEAN_RECORDS)
        started = hunt.time.time()
        assert _run(tmp_path, *self.BASE, *self.GATE) == hunt.EXIT_OK
        result = _result(tmp_path)
        assert started <= result.pop("finished_at") <= hunt.time.time()
        assert result == {
            "engagement": "acme",
            "recon": {"state": "completed", "records": {"http_service": 1}, "scope_drops": 2},
            "issues": ZERO,
            "findings": NO_FINDINGS,
            "approvals_pending": 0,
            "agent": {"ran": False, "error": None},
            "probes": {"ran_sweep": False},
            "complete": True,
        }
        assert "hunt-result.json" in capsys.readouterr().err
        assert not list(_result_path(tmp_path).parent.glob(".hunt-result-*"))

    def test_a_high_issue_with_the_issue_gate_is_10(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        _watch(monkeypatch, ["completed"], RECORDS)
        assert _run(tmp_path, *self.BASE, *self.GATE) == hunt.EXIT_FINDINGS
        result = _result(tmp_path)
        assert result["issues"] == {**ZERO, "high": 1, "info": 1}
        assert result["complete"] is True and result["findings"] == NO_FINDINGS
        assert result["recon"]["state"] == "completed"
        assert result["recon"]["records"] == {k: len(v) for k, v in sorted(RECORDS.items())}
        assert "1 at or above high (exit 10)" in capsys.readouterr().err

    @pytest.mark.parametrize(
        ("records", "gate", "expected"),
        [
            (RECORDS, (), 0),  # no threshold: never fail
            (RECORDS, ("--fail-on", "high"), 0),  # issues count only with --fail-on-issues
            (RECORDS, ("--fail-on", "critical", "--fail-on-issues"), 0),  # high is below critical
            (RECORDS, ("--fail-on", "medium", "--fail-on-issues"), 10),
            (RECORDS, ("--fail-on", "info", "--fail-on-issues"), 10),
            (INFO_ONLY_RECORDS, ("--fail-on", "high", "--fail-on-issues"), 0),
            (INFO_ONLY_RECORDS, ("--fail-on", "low", "--fail-on-issues"), 0),
            (INFO_ONLY_RECORDS, ("--fail-on", "info", "--fail-on-issues"), 10),
        ],
    )
    def test_the_issue_gate_fires_only_at_or_above_the_threshold(
        self, tmp_path: Path, monkeypatch, records: dict, gate: tuple[str, ...], expected: int
    ) -> None:
        _watch(monkeypatch, ["completed"], records)
        assert _run(tmp_path, *self.BASE, *gate) == expected
        assert _result(tmp_path)["complete"] is True

    def test_exploit_verified_findings_gate_and_nothing_else_does(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        _watch(monkeypatch, ["completed"], CLEAN_RECORDS)
        capture = _FakeCapture(
            [
                _finding(1, "critical", "candidate"),
                _finding(2, "critical", "inconclusive"),
                _finding(3, "high", "discarded"),
                _finding(4, "critical", "source_verified"),
                _finding(5, "medium", "exploit_verified"),
                _finding(6, "medium", "exploit_verified"),
                _finding(7, "low", "exploit_verified"),
            ]
        )
        monkeypatch.setattr(hunt, "_capture", capture)
        # Unverified criticals do not count.
        assert _run(tmp_path, *self.BASE, "--fail-on", "high") == 0
        assert capture.calls == [("findings_list", "acme")]
        assert _result(tmp_path)["findings"] == {
            "available": True,
            "exploit_verified": {**ZERO, "medium": 2, "low": 1},
            "inconclusive": 1,
            "candidates": 1,
        }
        assert _run(tmp_path, *self.BASE, "--fail-on", "medium") == hunt.EXIT_FINDINGS
        assert _run(tmp_path, *self.BASE, "--fail-on", "low") == hunt.EXIT_FINDINGS
        assert _run(tmp_path, *self.BASE) == 0

        # A verified finding that cannot be ranked meets every threshold.
        capture.findings = [_finding(8, "", "exploit_verified")]
        assert _run(tmp_path, *self.BASE, "--fail-on", "critical") == hunt.EXIT_FINDINGS
        assert _result(tmp_path)["findings"]["exploit_verified"] == {**ZERO, "unknown": 1}
        capture.findings = []
        assert _run(tmp_path, *self.BASE, "--fail-on", "info") == 0
        assert _result(tmp_path)["findings"]["available"] is True

    def test_unreadable_findings_count_as_zero_and_say_so(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        _watch(monkeypatch, ["completed"], CLEAN_RECORDS)
        monkeypatch.setattr(hunt, "_capture", lambda *_a, **_k: {"error": "capture is down"})
        assert _run(tmp_path, *self.BASE, "--fail-on", "info") == 0
        result = _result(tmp_path)
        assert result["findings"] == NO_FINDINGS and result["complete"] is True

    def test_pending_approvals_are_counted_from_the_approval_files(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        requests = tmp_path / "audit" / "acme" / "approvals" / "requests.jsonl"
        requests.parent.mkdir(parents=True)
        rows = [{"request_id": f"r{n}", "tool_name": "http_send"} for n in range(3)]
        requests.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        decisions = tmp_path / "control" / "acme" / "approvals" / "decisions.jsonl"
        decisions.parent.mkdir(parents=True)
        decisions.write_text(json.dumps({"request_id": "r1", "action": "allow"}) + "\n")
        assert _run(tmp_path, *self.BASE) == 0
        result = _result(tmp_path)
        assert result["approvals_pending"] == 2
        assert result["recon"] == {"state": "not_watched", "records": {}, "scope_drops": None}

    def test_a_recon_timeout_is_3_whatever_was_found(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        _watch(monkeypatch, ["running"], RECORDS)
        verified = _FakeCapture([_finding(1, "critical", "exploit_verified")])
        monkeypatch.setattr(hunt, "_capture", verified)
        code = _run(tmp_path, *self.BASE, "--recon-timeout", "0", *self.GATE)
        assert code == hunt.EXIT_INCOMPLETE
        result = _result(tmp_path)
        assert result["complete"] is False
        assert result["recon"] == {"state": "timed_out", "records": {}, "scope_drops": None}
        assert result["issues"] == {**ZERO, "high": 1, "info": 1}  # what the store held so far
        assert result["findings"]["exploit_verified"] == {**ZERO, "critical": 1}
        assert result["agent"] == {"ran": False, "error": None}
        err = capsys.readouterr().err
        assert "incomplete       recon timed_out" in err and "--resume acme" in err

    def test_a_failed_recon_run_is_3(self, tmp_path: Path, monkeypatch) -> None:
        recon = _watch(monkeypatch, ["none"], CLEAN_RECORDS)
        recon.previous = {
            "run_id": "run-1",
            "status": "failed",
            "scope_drops": 4,
            "started_at": 2e9,
        }
        assert _run(tmp_path, *self.BASE) == hunt.EXIT_INCOMPLETE
        result = _result(tmp_path)
        assert result["complete"] is False
        assert result["recon"] == {"state": "failed", "records": {}, "scope_drops": 4}

    def test_an_agent_error_is_3(self, tmp_path: Path, monkeypatch, capsys) -> None:
        _watch(monkeypatch, ["completed"], CLEAN_RECORDS)
        monkeypatch.setattr(hunt, "model_configured", lambda: True)

        def boom(**_kwargs: Any) -> dict[str, Any]:
            raise ConnectionError("langgraph is not reachable")

        monkeypatch.setattr(hunt, "_stream_kickoff", boom)
        assert _run(tmp_path, "https://app.acme.test", "--yes") == hunt.EXIT_INCOMPLETE
        result = _result(tmp_path)
        assert result["complete"] is False
        assert result["agent"] == {
            "ran": True,
            "error": "ConnectionError: langgraph is not reachable",
        }
        assert result["recon"]["state"] == "completed" and result["issues"] == ZERO
        assert "incomplete       the agent run failed" in capsys.readouterr().err

    def test_a_finished_agent_run_is_complete(self, tmp_path: Path, monkeypatch) -> None:
        """Negative control for the test above."""
        _watch(monkeypatch, ["completed"], CLEAN_RECORDS)
        monkeypatch.setattr(hunt, "model_configured", lambda: True)
        monkeypatch.setattr(hunt, "_stream_kickoff", lambda **_k: {"event_count": 2})
        assert _run(tmp_path, "https://app.acme.test", "--yes") == 0
        result = _result(tmp_path)
        assert result["agent"] == {"ran": True, "error": None} and result["complete"] is True

    def test_a_bad_pattern_is_2_and_records_no_run(self, tmp_path: Path, monkeypatch) -> None:
        bad = ("app.acme.test", "--scope", "not a host!", "--yes", "--no-agent", *self.GATE)
        assert _run(tmp_path, *bad) == hunt.EXIT_CONFIG
        assert not (tmp_path / "control").exists()  # so there is no result file either

        # With an earlier run on disk, a refused command line leaves its result alone.
        monkeypatch.setattr(hunt, "recon_available", lambda: False)
        assert _run(tmp_path, "app.acme.test", "--yes", "--no-agent") == 0
        _age(_result_path(tmp_path))
        before = _fingerprint(_result_path(tmp_path)), _fingerprint(_roe_path(tmp_path))
        assert _run(tmp_path, *bad) == hunt.EXIT_CONFIG
        assert before == (_fingerprint(_result_path(tmp_path)), _fingerprint(_roe_path(tmp_path)))

    def test_usage_errors_are_2(self, tmp_path: Path, capsys) -> None:
        assert _run(tmp_path, "app.acme.test", "--yes", "--fail-on-issues") == hunt.EXIT_CONFIG
        assert "--fail-on-issues needs a threshold" in capsys.readouterr().err
        with pytest.raises(SystemExit) as stopped:
            _run(tmp_path, "app.acme.test", "--yes", "--fail-on", "severe")
        assert stopped.value.code == hunt.EXIT_CONFIG
        assert not (tmp_path / "control").exists()

    def test_plan_only_starts_nothing_and_records_no_run(self, tmp_path: Path) -> None:
        assert _run(tmp_path, "app.acme.test", "--yes", "--plan-only", *self.GATE) == 0
        assert _roe_path(tmp_path).exists() and not _result_path(tmp_path).exists()

    def test_a_result_that_cannot_be_written_is_not_reported_as_clean(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(hunt, "recon_available", lambda: False)

        def refuse(*_args: Any, **_kwargs: Any) -> Path:
            raise PermissionError("read-only control root")

        monkeypatch.setattr(hunt, "write_result", refuse)
        assert _run(tmp_path, *self.BASE) == hunt.EXIT_INCOMPLETE
        assert "cannot write" in capsys.readouterr().err


class TestScopeDiff:
    STORED: dict[str, Any] = {
        "machine_enforcement": {"mode": "enforce", "in_scope": ["a.test", "b.test"], "extra": 1},
        "pipeline": {"rate_limit_rps": 10},
        "approvals": {"state_changing": "required"},
        "network": {"allow_private_targets": False},
        "created": "then",
        "hunt": {"rps": 10},
    }

    def _requested(self, **blocks: Any) -> dict[str, Any]:
        base = {name: json.loads(json.dumps(self.STORED[name])) for name in hunt.COMPARED_BLOCKS}
        return {**base, **blocks}

    def test_equal_blocks_have_no_diff_whatever_else_the_document_holds(self) -> None:
        assert hunt.scope_diff(self.STORED, self._requested()) == []
        other = {**self.STORED, "created": "now", "hunt": {}}
        assert hunt.scope_diff(other, self._requested()) == []

    def test_every_kind_of_difference_is_a_line(self) -> None:
        enforcement = {"mode": "warn", "in_scope": ["b.test", "c.test"], "new": True}
        lines = hunt.scope_diff(self.STORED, self._requested(machine_enforcement=enforcement))
        assert lines == [
            "  machine_enforcement.mode: enforce -> warn",
            "  machine_enforcement.in_scope: + c.test",
            "  machine_enforcement.in_scope: - a.test",
            "  machine_enforcement.new: (not set) -> true",
            "  machine_enforcement.extra: 1 -> (not set)",
        ]
        reordered = {**self.STORED["machine_enforcement"], "in_scope": ["b.test", "a.test"]}
        assert hunt.scope_diff(self.STORED, self._requested(machine_enforcement=reordered)) == [
            "  machine_enforcement.in_scope: same entries, different order or repeats"
        ]
        without = {k: v for k, v in self.STORED.items() if k != "network"}
        assert hunt.scope_diff(without, self._requested()) == [
            '  network: (not set) -> {"allow_private_targets": false}'
        ]


# ── leads, findings reports and the kickoff ──────────────────────────────────────────


class TestLeadsAndFindingsReports:
    RECORDS = {
        "vulnerability": [{"id": "v1", "value": "CVE-2024-0001 at https://app.acme.test/x"}],
        "url": [{"asset": "app.acme.test", "value": "https://app.acme.test/api/orders/1001"}],
    }

    def test_recon_leads_are_queued_through_the_capture_server(self, monkeypatch) -> None:
        calls: list[tuple[str, str, dict]] = []

        def capture(tool, engagement, **arguments):
            calls.append((tool, engagement, arguments))
            return {"ok": True, "ids": ["F-1"], "created": 1, "merged": 0, "unclassified": 0}

        monkeypatch.setattr(hunt, "_capture", capture)
        assert hunt.queue_leads("acme", self.RECORDS)["ids"] == ["F-1"]
        ((tool, engagement, arguments),) = calls
        assert (tool, engagement, arguments["actor"]) == ("candidates_add", "acme", "recon")
        items = json.loads(arguments["items_json"])
        assert items["pipeline"] == self.RECORDS["vulnerability"]
        assert isinstance(items["ranked"], list)

    def test_findings_reports_and_sarif_are_written_from_the_servers_report(
        self, tmp_path, monkeypatch
    ) -> None:
        report = {
            "engagement": "acme",
            "findings": [],
            "unverified": [],
            "leads": [],
            "summary": {},
            "generated_at": "2026-01-01T00:00:00Z",
        }
        asked: list[tuple[str, bool]] = []

        def capture(tool, _engagement, **arguments):
            assert tool == "report_build"
            asked.append((arguments["fmt"], arguments["complete"]))
            body = {"markdown": "# report", "html": "<!doctype html>", "json": json.dumps(report)}
            return {"ok": True, "report": body[arguments["fmt"]]}

        monkeypatch.setattr(hunt, "_capture", capture)
        out = hunt.write_findings_reports(tmp_path, "acme", {"records": {"url": 3}}, complete=True)
        assert out == {"written": ["report.md", "report.html", "report.json", "findings.sarif"]}
        assert asked == [("markdown", True), ("html", True), ("json", True)]
        sarif = json.loads((tmp_path / "acme" / "findings.sarif").read_text())
        assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"] == []
        assert json.loads((tmp_path / "acme" / "report.json").read_text()) == report

    def test_an_unreachable_capture_server_is_reported_and_writes_nothing(
        self, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setattr(hunt, "_capture", lambda *_a, **_k: {"error": "capture is unreachable"})
        out = hunt.write_findings_reports(tmp_path, "acme", None, complete=False)
        assert out["written"] == [] and len(out["errors"]) == 3
        assert not (tmp_path / "acme").exists()

    def test_the_kickoff_sends_agents_to_the_queue_and_the_verifier(self) -> None:
        scope = {
            "targets": ["https://app.acme.test"],
            "enforcement_extra": {"sandbox_egress": "blocked"},
        }
        text = hunt.kickoff_text("acme", scope, recon_done=True, instruction="")
        for tool in (
            "candidates_next",
            "finding_submit",
            "finding_verify",
            "finding_grade",
            "facts_list",
            "memory_search",
            "identities_list",
            "authz_matrix_run",
            "recon_coverage",
        ):
            assert tool in text, tool
        assert "A claim is not a finding" in text

    def test_the_graph_projection_is_skipped_without_a_graph_database(self, monkeypatch) -> None:
        for name in ("BUGGY_NEO4J_URI", "BUGGY_NEO4J_USER", "BUGGY_NEO4J_PASSWORD"):
            monkeypatch.delenv(name, raising=False)
        assert hunt.project_graph("acme").startswith("skipped")
