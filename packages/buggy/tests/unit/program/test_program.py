"""Bounty-program engagements: official scope import and the rules that bind them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.capture.gateway import CaptureGateway, GatewayRefusal, Roots
from buggy.cli import approvals as approvals_cli
from buggy.cli import scope as scope_cli
from buggy.middleware.roe import _program_mode_error, parse_roe_document
from buggy.pipeline.scope import PipelineLimits, ScopeFilter
from buggy.program import importer
from buggy.program.gate import finding_errors, mode_error, report_release
from buggy.program.record import BASELINE_BANNED_TECHNIQUES, load_program
from buggy_core.types.roe import evaluate_command

FIXTURES = Path(__file__).parent / "fixtures"
CSV = (FIXTURES / "hackerone_scope.csv").read_text()


def _official(**overrides) -> importer.OfficialScope:
    scope = importer.from_hackerone_csv(CSV, "acme-bounty")
    for key, value in overrides.items():
        setattr(scope, key, value)
    return scope


class TestOfficialScopeImport:
    def test_hackerone_csv_becomes_an_enforce_mode_scope(self) -> None:
        roe, program, rejected = importer.build_documents(_official(), engagement="h1-acme")
        block = roe["machine_enforcement"]
        assert block["mode"] == "enforce"
        assert block["in_scope"] == [
            "app.acme-bounty.example",
            "**.api.acme-bounty.example",
            "pay.acme-bounty.example",
            "198.51.100.0/28",
        ]
        # Not eligible for submission = out of scope, never silently dropped.
        assert block["out_of_scope"] == ["blog.acme-bounty.example"]
        # A mobile app id is not a network target.
        assert program["non_network_assets"] == ["com.acme.mobile (google_play_app_id)"]
        # Over-broad or internal entries in the official data are refused, visibly.
        assert {r["asset"]: r["reason"] for r in rejected} == {
            "*.example": "wildcard over a public suffix",
            "10.20.0.0/16": "private, loopback or link-local address",
        }
        assert program["rejected_assets"] == rejected
        assert roe["approvals"] == {"state_changing": "required", "report_submission": "required"}
        assert roe["network"] == {"allow_private_targets": False}
        assert block["sandbox_egress"] == "blocked"
        assert program["source_sha256"] and program["platform"] == "hackerone"

    def test_the_result_is_what_the_guardrail_and_pipeline_enforce(self) -> None:
        roe, _program, _ = importer.build_documents(_official(), engagement="h1-acme")
        rules = parse_roe_document(roe, required=True)
        assert rules.mode.value == "enforce"
        scope = ScopeFilter.from_document(roe)
        assert scope.allows("https://app.acme-bounty.example/login")
        assert scope.allows("v2.api.acme-bounty.example")
        assert scope.allows("a.b.api.acme-bounty.example")  # a program wildcard is any depth
        assert not scope.allows("api.acme-bounty.example")  # the apex was never listed
        assert scope.allows("198.51.100.7")
        for outside in (
            "blog.acme-bounty.example",  # excluded by the program
            "acme-bounty.example",  # apex was never listed
            "evil.example",
            "10.20.0.5",
            "198.51.100.200",
        ):
            assert not scope.allows(outside), outside

    def test_default_rate_is_conservative_and_the_policy_can_only_lower_it(self) -> None:
        roe, program, _ = importer.build_documents(_official(), engagement="e")
        assert program["rate_limit"] == {
            "requests_per_second": importer.DEFAULT_RPS,
            "min_delay_ms": 200,
            "basis": "default",
        }
        limits = PipelineLimits.from_roe(parse_roe_document(roe, required=True), roe)
        assert limits.rate_limit_rps == importer.DEFAULT_RPS and limits.port_scan is False

        slow = _official(policy_delay_ms=1000)  # the program says 1 request / second
        roe, program, _ = importer.build_documents(slow, engagement="e", rps=10)
        assert program["rate_limit"]["requests_per_second"] == 1
        assert program["rate_limit"]["basis"] == "program policy"
        assert roe["machine_enforcement"]["min_inter_request_delay_ms"] == 1000
        limits = PipelineLimits.from_roe(parse_roe_document(roe, required=True), roe)
        assert limits.rate_limit_rps == 1 and limits.concurrency == 1

    @pytest.mark.parametrize("rps", [0, -1, importer.MAX_RPS + 1, 1000])
    def test_operator_cannot_exceed_the_ceiling(self, rps: int) -> None:
        with pytest.raises(importer.ScopeImportError):
            importer.build_documents(_official(), engagement="e", rps=rps)

    def test_api_payload_with_a_no_scanner_policy_makes_the_pipeline_passive(self) -> None:
        payload = {
            "platform": "bugcrowd",
            "program_handle": "acme",
            "program_url": "https://bugcrowd.com/acme",
            "program_name": "Acme",
            "in_scope": ["shop.acme-bounty.example"],
            "out_of_scope": ["status.acme-bounty.example"],
            "excluded_classes": ["Clickjacking on pages with no sensitive actions"],
            "suggested_rules": {
                "no_automated_tools": True,
                "min_inter_request_delay_ms": 500,
                "notes": ["policy appears to forbid automated scanning"],
            },
        }
        official = importer.from_intake_payload(payload, source="bugcrowd api")
        roe, program, _ = importer.build_documents(official, engagement="bc-acme", port_scan=True)
        assert roe["pipeline"]["passive_only"] is True
        assert roe["pipeline"]["port_scan"] is False  # the flag cannot override the program
        assert roe["pipeline"]["rate_limit_rps"] == 2
        rules = parse_roe_document(roe, required=True)
        target = "shop.acme-bounty.example"
        for command in (f"nuclei -u https://{target}", f"sqlmap -u https://{target}/?id=1"):
            assert not evaluate_command(command, rules).allow, command
        ids = [entry["id"] for entry in program["banned_techniques"]]
        assert "automated_scanning" in ids and "excluded_class" in ids

    def test_dos_and_social_engineering_tools_are_refused_on_every_program(self) -> None:
        roe, program, _ = importer.build_documents(_official(), engagement="e")
        rules = parse_roe_document(roe, required=True)
        target = "app.acme-bounty.example"
        for command in (
            f"slowloris {target}",
            f"hping3 -S --flood -p 443 {target}",
            f"wrk -t12 -c400 -d30s https://{target}/",
            f"gophish --target {target}",
        ):
            decision = evaluate_command(command, rules)
            assert not decision.allow, command
        ids = [entry["id"] for entry in program["banned_techniques"]]
        assert ids[: len(BASELINE_BANNED_TECHNIQUES)] == [
            "denial_of_service",
            "social_engineering",
            "physical",
            "data_exfiltration",
            "other_users",
        ]

    def test_scope_with_nothing_enforceable_is_refused(self) -> None:
        empty = _official(in_scope=["*.example", "acme mobile app", "10.0.0.0/8"])
        with pytest.raises(importer.ScopeImportError, match="no enforceable network asset"):
            importer.build_documents(empty, engagement="e")

    def test_api_errors_and_wrong_files_are_reported_not_guessed_around(self) -> None:
        with pytest.raises(importer.ScopeImportError, match="missing_credentials"):
            importer.from_intake_payload(
                {"error": "missing_credentials", "how_to": "set the token"}, source="x"
            )
        with pytest.raises(importer.ScopeImportError, match="not a HackerOne scope CSV"):
            importer.from_hackerone_csv("host,notes\napp.example,hi\n", "acme")
        with pytest.raises(importer.ScopeImportError, match="not a valid program handle"):
            importer.from_hackerone_csv(CSV, "../etc")

    def test_fetch_without_credentials_never_reaches_the_network(self, monkeypatch) -> None:
        for name in (
            "H1_API_USERNAME",
            "H1_API_TOKEN",
            "BUGCROWD_API_USERNAME",
            "BUGCROWD_API_TOKEN",
        ):
            monkeypatch.delenv(name, raising=False)

        def no_network(*_a, **_k):
            raise AssertionError("no request may be made without credentials")

        monkeypatch.setattr("buggy.tools.research.bounty_intake._get_json", no_network)
        for platform in importer.PLATFORMS:
            with pytest.raises(importer.ScopeImportError, match="set "):
                importer.fetch_official(platform, "acme")

    @pytest.mark.parametrize(
        ("asset", "ok"),
        [
            ("app.acme-bounty.example", True),
            ("*.acme-bounty.example", True),
            ("198.51.100.4", True),
            ("*", False),
            ("*.com", False),
            ("*.co.uk", False),
            ("**.acme-bounty.example", True),
            ("api.*.acme-bounty.example", False),
            ("*.*.acme-bounty.example", False),
            ("**.com", False),
            ("0.0.0.0/0", False),
            ("8.0.0.0/8", False),
            ("192.168.1.0/24", False),
            ("127.0.0.1", False),
            ("169.254.169.254", False),
            ("not a host", False),
        ],
    )
    def test_asset_classification(self, asset: str, ok: bool) -> None:
        entry, reason = importer.classify_asset(asset)
        assert (entry is not None) is ok, reason


@pytest.fixture
def roots(tmp_path: Path) -> dict[str, Path]:
    out = {name: tmp_path / name for name in ("workspace", "control", "audit", "data")}
    for path in out.values():
        path.mkdir()
    return out


def _scope(roots: dict[str, Path], *args: str) -> int:
    return scope_cli.main(
        [
            "--workspace-root",
            str(roots["workspace"]),
            "--control-root",
            str(roots["control"]),
            *args,
        ]
    )


def _import(roots: dict[str, Path], *extra: str) -> int:
    return _scope(
        roots,
        "import",
        "--platform",
        "hackerone",
        "--handle",
        "acme-bounty",
        "--csv",
        str(FIXTURES / "hackerone_scope.csv"),
        *extra,
    )


class TestScopeImportCommand:
    def test_import_writes_scope_and_program_record_after_showing_them(self, roots, capsys) -> None:
        assert _import(roots, "--yes") == 0
        directory = roots["control"] / "hackerone-acme-bounty"
        roe = json.loads((directory / "roe.json").read_text())
        program = json.loads((directory / "program.json").read_text())
        assert roe["machine_enforcement"]["mode"] == "enforce"
        assert roe["approved"]["source"] == "hackerone scope CSV (operator download)"
        assert program["engagement"] == "hackerone-acme-bounty" and program["imported_by"]
        shown = capsys.readouterr().out
        assert "app.acme-bounty.example" in shown and "blog.acme-bounty.example" in shown
        assert "REJECTED from scope: *.example" in shown
        assert "No denial of service" in shown and "every report before release" in shown
        assert load_program(roots["control"], "hackerone-acme-bounty") == program

    def test_import_needs_the_operator_to_confirm(self, roots, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        assert _import(roots) == scope_cli.EXIT_CONFIG
        assert not (roots["control"] / "hackerone-acme-bounty").exists()

    def test_api_import_without_credentials_fails_and_writes_nothing(
        self, roots, monkeypatch
    ) -> None:
        monkeypatch.delenv("H1_API_USERNAME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)
        code = _scope(roots, "import", "--platform", "hackerone", "--handle", "acme", "--yes")
        assert code == scope_cli.EXIT_CONFIG and list(roots["control"].iterdir()) == []

    def test_a_program_scope_cannot_be_hand_edited_out_of_enforce_mode(
        self, roots, tmp_path
    ) -> None:
        assert _import(roots, "--yes") == 0
        loose = tmp_path / "loose.json"
        loose.write_text(
            json.dumps(
                {"machine_enforcement": {"mode": "warn", "in_scope": ["app.acme-bounty.example"]}}
            )
        )
        slug = "hackerone-acme-bounty"
        assert _scope(roots, "set", slug, "--file", str(loose), "--yes") == scope_cli.EXIT_CONFIG
        enforced = json.loads((roots["control"] / slug / "roe.json").read_text())
        assert enforced["machine_enforcement"]["mode"] == "enforce"


class TestEnforceModeOnly:
    def test_mode_error(self) -> None:
        program = {"platform": "hackerone", "handle": "acme"}
        assert mode_error(None, "audit") is None  # not a program engagement
        assert mode_error(program, "enforce") is None
        for mode in ("audit", "warn"):
            assert "'enforce' mode only" in (mode_error(program, mode) or "")
        assert "unreadable" in (mode_error({"_invalid": "bad json"}, "enforce") or "")

    def test_a_damaged_program_record_does_not_fall_back_to_the_loose_rules(self, roots) -> None:
        directory = roots["control"] / "acme"
        directory.mkdir()
        (directory / "program.json").write_text("{not json")
        assert "_invalid" in (load_program(roots["control"], "acme") or {})
        assert load_program(roots["control"], "other") is None
        assert load_program(roots["control"], "../acme") is None

    def test_the_guardrail_refuses_a_program_engagement_that_is_not_enforced(
        self, roots, monkeypatch
    ) -> None:
        monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(roots["control"]))
        monkeypatch.setenv("BUGGY_WORKSPACE_ROOT", str(roots["workspace"]))
        assert _import(roots, "--yes", "--engagement", "acme") == 0
        state = {"engagement_name": "acme", "workspace_path": str(roots["workspace"] / "acme")}
        path = roots["control"] / "acme" / "roe.json"
        document = json.loads(path.read_text())
        assert _program_mode_error(state, parse_roe_document(document, required=True)) is None
        document["machine_enforcement"]["mode"] = "warn"
        loosened = parse_roe_document(document, required=True)
        assert "'enforce' mode only" in (_program_mode_error(state, loosened) or "")
        # An engagement that was never imported from a program is not affected.
        other = {"engagement_name": "lab", "workspace_path": str(roots["workspace"] / "lab")}
        assert _program_mode_error(other, loosened) is None


class _Origin:
    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        import io

        self.seen.append((request.get_method(), request.full_url))
        response = io.BytesIO(b"{}")
        response.status, response.headers = 200, {}
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


class TestStateChangingRequestsNeedApproval:
    def test_gateway_holds_a_post_on_an_imported_program_until_the_operator_allows_it(
        self, roots, monkeypatch
    ) -> None:
        assert _import(roots, "--yes", "--engagement", "acme") == 0
        monkeypatch.setattr(
            "buggy.capture.gateway.socket.getaddrinfo",
            lambda *_a, **_k: [(2, 1, 6, "", ("93.184.216.34", 0))],
        )
        origin = _Origin()
        gateway = CaptureGateway(
            Roots(control=roots["control"], audit=roots["audit"], data=roots["data"]),
            opener=origin,
            sleep=lambda _s: None,
        )
        try:
            url = "https://app.acme-bounty.example/api/profile"
            assert gateway.send("acme", "GET", url).status == 200
            with pytest.raises(GatewayRefusal) as held:
                gateway.send("acme", "POST", url, body='{"name":"x"}')
            assert held.value.code == "APPROVAL_REQUIRED"
            assert origin.seen == [("GET", url)]  # the POST never left
            with pytest.raises(GatewayRefusal) as outside:
                gateway.send("acme", "GET", "https://blog.acme-bounty.example/")
            assert outside.value.code == "OUT_OF_SCOPE"

            request_id = held.value.extra["request_id"]
            approvals_cli.record_decision(
                roots["control"] / "acme" / "approvals" / "decisions.jsonl", request_id, "allow"
            )
            assert gateway.send("acme", "POST", url, body='{"name":"x"}').status == 200
            # The approval covers that exact request, not a different body.
            with pytest.raises(GatewayRefusal):
                gateway.send("acme", "POST", url, body='{"name":"y","role":"admin"}')
        finally:
            gateway.store.close()


def _finding(**overrides) -> dict:
    base = {
        "title": "IDOR on /api/orders/{id} exposes another customer's order",
        "vuln_class": "idor",
        "target": "https://app.acme-bounty.example/api/orders/1002",
        "capture_ids": ["cap-owner", "cap-attacker"],
        "remediation": "Check on the server that the order belongs to the session's account "
        "before returning it; derive the owner from the session, not the URL.",
    }
    return {**base, **overrides}


def _verifier(results: dict[str, dict] | None = None):
    calls: list[tuple[str, str]] = []

    def verify(capture_id: str, target: str) -> dict:
        calls.append((capture_id, target))
        return (results or {}).get(capture_id, {"valid": True, "method": "GET", "reproduced": True})

    verify.calls = calls  # type: ignore[attr-defined]
    return verify


class TestFindingRules:
    PROGRAM = {
        "platform": "hackerone",
        "handle": "acme",
        "excluded_classes": ["Clickjacking on pages with no sensitive actions", "Self-XSS"],
    }

    def test_a_finding_with_verified_captures_and_a_remediation_is_accepted(self) -> None:
        verify = _verifier()
        assert finding_errors(_finding(), self.PROGRAM, verify) == []
        assert verify.calls == [
            ("cap-owner", "https://app.acme-bounty.example/api/orders/1002"),
            ("cap-attacker", "https://app.acme-bounty.example/api/orders/1002"),
        ]

    @pytest.mark.parametrize("remediation", ["", "   ", "TBD", "n/a", "fix it", "validate input"])
    def test_remediation_is_mandatory_and_not_a_placeholder(self, remediation: str) -> None:
        errors = finding_errors(_finding(remediation=remediation), self.PROGRAM, _verifier())
        assert any("remediation is required" in e for e in errors)

    def test_a_finding_without_a_captured_request_is_refused(self) -> None:
        for ids in (None, [], [" "]):
            errors = finding_errors(_finding(capture_ids=ids), self.PROGRAM, _verifier())
            assert any("capture_ids is required" in e for e in errors)
        errors = finding_errors(_finding(target=""), self.PROGRAM, _verifier())
        assert any("target is required" in e for e in errors)

    def test_a_capture_that_does_not_verify_or_reproduce_is_refused(self) -> None:
        verify = _verifier(
            {
                "cap-owner": {"valid": False, "reason": "capture is for other.example, not app"},
                "cap-attacker": {"valid": True, "reproduced": False, "reason": "status changed"},
            }
        )
        errors = finding_errors(_finding(), self.PROGRAM, verify)
        assert errors == [
            "capture cap-owner: capture is for other.example, not app",
            "capture cap-attacker: the request did not reproduce when re-sent (status changed)",
        ]

    def test_a_state_changing_capture_is_accepted_without_an_automatic_replay(self) -> None:
        verify = _verifier({"cap-owner": {"valid": True, "method": "POST", "reproduced": None}})
        assert finding_errors(_finding(), self.PROGRAM, verify) == []

    @pytest.mark.parametrize(
        ("title", "vuln_class", "expected"),
        [
            ("Application-layer DoS via nested query", "dos", "denial of service"),
            ("Phishing page accepted by support", "social engineering", "social engineering"),
            ("Self-XSS in profile name", "xss", "does not accept this class: Self-XSS"),
        ],
    )
    def test_banned_techniques_and_excluded_classes_are_refused(
        self, title: str, vuln_class: str, expected: str
    ) -> None:
        errors = finding_errors(
            _finding(title=title, vuln_class=vuln_class), self.PROGRAM, _verifier()
        )
        assert any(expected in e for e in errors), errors

    @pytest.mark.parametrize(
        "title",
        [
            "IDOR on GET /api/todos/{id}",  # "todos" contains "dos"
            "Stored XSS in the Kudos widget",
            "Reflected XSS on /physicalaccessories",
        ],
    )
    def test_a_banned_word_inside_another_word_does_not_refuse_a_finding(self, title: str) -> None:
        errors = finding_errors(_finding(title=title, vuln_class="xss"), self.PROGRAM, _verifier())
        assert not any("banned technique" in e for e in errors), errors

    @pytest.mark.parametrize("title", ["ReDoS in the search regex", "DDoS amplification"])
    def test_dos_variants_are_still_refused(self, title: str) -> None:
        errors = finding_errors(
            _finding(title=title, vuln_class="other"), self.PROGRAM, _verifier()
        )
        assert any("denial of service" in e for e in errors), errors


class TestReportRelease:
    def _release(self, roots, text: str, finding: str = "FIND-001") -> dict:
        return report_release(roots["control"], roots["audit"], "acme", finding, text)

    def test_a_report_is_held_until_the_operator_approves_that_exact_text(self, roots) -> None:
        first = self._release(roots, "# IDOR\n\nsteps...")
        assert first["released"] is False and first["status"] == "approval_required"
        request_id = first["request_id"]
        # The operator can read the draft, and it is in their pending list.
        draft = roots["audit"] / "acme" / "reports" / f"{request_id}.md"
        assert draft.read_text() == "# IDOR\n\nsteps..."
        requests_path, decisions_path = approvals_cli.paths_for(
            roots["control"], roots["audit"], "acme"
        )
        (pending,) = approvals_cli.pending(requests_path, decisions_path)
        assert pending["request_id"] == request_id and pending["tool_name"] == "report_submission"
        # Asking again does not file a second request.
        assert self._release(roots, "# IDOR\n\nsteps...")["request_id"] == request_id

        approvals_cli.record_decision(decisions_path, request_id, "allow", operator="olivia")
        released = self._release(roots, "# IDOR\n\nsteps...")
        assert released == {"released": True, "request_id": request_id, "approved_by": "olivia"}

        # Any edit is a different report and needs its own approval.
        edited = self._release(roots, "# IDOR\n\nsteps... plus customer data")
        assert edited["released"] is False and edited["request_id"] != request_id

    def test_a_denied_report_stays_denied(self, roots) -> None:
        first = self._release(roots, "report body")
        _requests, decisions_path = approvals_cli.paths_for(
            roots["control"], roots["audit"], "acme"
        )
        approvals_cli.record_decision(decisions_path, first["request_id"], "deny", note="too vague")
        again = self._release(roots, "report body")
        assert again["released"] is False and again["status"] == "denied"
        assert again["operator_note"] == "too vague"

    def test_the_approvals_cli_can_answer_a_report_request(self, roots, capsys) -> None:
        first = self._release(roots, "report body")
        argv = ["--control-root", str(roots["control"]), "--audit-root", str(roots["audit"])]
        assert approvals_cli.main([*argv, "list", "acme"]) == 0
        assert first["request_id"] in capsys.readouterr().out
        assert approvals_cli.main([*argv, "allow", "acme", first["request_id"]]) == 0
        assert self._release(roots, "report body")["released"] is True

    def test_no_writable_audit_root_means_no_release(self, roots, tmp_path) -> None:
        blocker = tmp_path / "file-not-dir"
        blocker.write_text("x")
        result = report_release(roots["control"], blocker, "acme", "FIND-1", "body")
        assert result["released"] is False and result["status"] == "unavailable"


class TestRulesReachTheAgent:
    def test_scope_show_carries_the_programs_binding_rules(self, roots) -> None:
        from buggy.capture.scope_server import ScopeTools

        assert _import(roots, "--yes", "--engagement", "acme") == 0
        tools = ScopeTools(roots["control"])
        shown = tools.scope_show("acme")
        assert shown["mode"] == "enforce" and shown["rate_limit_rps"] == importer.DEFAULT_RPS
        assert shown["state_changing_requests"] == "required"
        assert shown["report_release"] == "required"
        rules = " ".join(shown["banned_techniques"])
        for phrase in ("No denial of service", "No social engineering", "No data exfiltration"):
            assert phrase in rules
        info = tools.program_info("acme")
        assert info["platform"] == "hackerone" and info["requirements"]["mode"] == "enforce"
        assert tools.scope_check("acme", "https://blog.acme-bounty.example/")["in_scope"] is False
