"""``buggy-cli hunt``: a URL in, an enforced scope, recon, a report, then agents."""

from __future__ import annotations

import json
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
