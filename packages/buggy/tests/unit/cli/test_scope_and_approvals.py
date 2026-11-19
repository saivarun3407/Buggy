"""Operator commands that own the control root: ``scope`` and ``approvals``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.cli import approvals as approvals_cli
from buggy.cli import engage as engage_cli
from buggy.cli import scope as scope_cli
from buggy.middleware.hitl import FileBackedApprovalTransport, approval_paths


@pytest.fixture
def roots(tmp_path: Path) -> dict[str, Path]:
    out = {name: tmp_path / name for name in ("workspace", "control", "audit")}
    for path in out.values():
        path.mkdir()
    return out


def _draft(roots: dict[str, Path], block: dict, slug: str = "acme") -> Path:
    path = roots["workspace"] / slug / "plan" / "roe.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"engagement_name": slug, "machine_enforcement": block}))
    return path


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


class TestScope:
    def test_approve_promotes_the_draft_and_records_who_approved(self, roots, capsys) -> None:
        _draft(roots, {"mode": "enforce", "in_scope": ["app.acme.test"]})
        assert _scope(roots, "approve", "acme", "--yes") == 0
        enforced = json.loads((roots["control"] / "acme" / "roe.json").read_text())
        assert enforced["machine_enforcement"]["in_scope"] == ["app.acme.test"]
        assert enforced["approved"]["by"] and enforced["approved"]["at"]
        assert "app.acme.test" in capsys.readouterr().out

    def test_approve_without_confirmation_changes_nothing(self, roots, monkeypatch) -> None:
        _draft(roots, {"mode": "enforce", "in_scope": ["app.acme.test"]})
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        assert _scope(roots, "approve", "acme") == scope_cli.EXIT_CONFIG
        assert not (roots["control"] / "acme" / "roe.json").exists()

    @pytest.mark.parametrize(
        "block",
        [
            {"mode": "enforce", "in_scope": []},  # constrains nothing
            {"mode": "enforce", "in_scope": ["http://a.test/path"]},  # unsupported URL target
            {"mode": "sometimes", "in_scope": ["a.test"]},
            {"mode": "enforce", "in_scope": ["a.test"], "forbidden_command_patterns": ["("]},
        ],
    )
    def test_a_policy_the_guardrail_would_reject_cannot_be_approved(self, roots, block) -> None:
        _draft(roots, block)
        with pytest.raises(SystemExit, match="scope rejected"):
            _scope(roots, "approve", "acme", "--yes")
        assert not (roots["control"] / "acme" / "roe.json").exists()

    def test_show_says_when_only_a_draft_exists(self, roots, capsys) -> None:
        _draft(roots, {"mode": "enforce", "in_scope": ["app.acme.test"]})
        assert _scope(roots, "show", "acme") == 0
        assert "NOT ENFORCED" in capsys.readouterr().out
        _scope(roots, "approve", "acme", "--yes")
        capsys.readouterr()
        assert _scope(roots, "show", "acme") == 0
        assert "enforced scope" in capsys.readouterr().out

    def test_diff_flags_a_draft_the_agent_changed_after_approval(self, roots, capsys) -> None:
        _draft(roots, {"mode": "enforce", "in_scope": ["app.acme.test"]})
        _scope(roots, "approve", "acme", "--yes")
        assert _scope(roots, "diff", "acme") == 0
        _draft(roots, {"mode": "enforce", "in_scope": ["app.acme.test", "evil.example"]})
        assert _scope(roots, "diff", "acme") == 1
        assert "evil.example" in capsys.readouterr().out
        enforced = json.loads((roots["control"] / "acme" / "roe.json").read_text())
        assert enforced["machine_enforcement"]["in_scope"] == ["app.acme.test"]

    def test_set_installs_a_file(self, roots, tmp_path) -> None:
        source = tmp_path / "official.json"
        source.write_text(
            json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["a.test"]}})
        )
        assert _scope(roots, "set", "acme", "--file", str(source), "--yes") == 0
        assert (roots["control"] / "acme" / "roe.json").exists()


class TestEngageWritesTheEnforcedScope:
    def test_plan_only_writes_control_copy(self, roots) -> None:
        rc = engage_cli.main(
            [
                "--target", "app.acme.test",
                "--engagement-name", "acme",
                "--workspace-root", str(roots["workspace"]),
                "--control-root", str(roots["control"]),
                "--plan-only",
            ]
        )  # fmt: skip
        assert rc == 0
        draft = json.loads((roots["workspace"] / "acme" / "plan" / "roe.json").read_text())
        enforced = json.loads((roots["control"] / "acme" / "roe.json").read_text())
        assert enforced == draft
        assert enforced["machine_enforcement"]["mode"] == "enforce"

    def test_unwritable_control_root_is_an_error_not_a_silent_skip(self, roots, capsys) -> None:
        blocker = roots["control"] / "acme"
        blocker.write_text("a file where the engagement directory should be")
        rc = engage_cli.main(
            [
                "--target", "app.acme.test",
                "--engagement-name", "acme",
                "--workspace-root", str(roots["workspace"]),
                "--control-root", str(roots["control"]),
                "--plan-only",
            ]
        )  # fmt: skip
        assert rc == engage_cli.EXIT_CONFIG
        assert "operator" in capsys.readouterr().err


class TestApprovals:
    def _request(self, roots: dict[str, Path], request_id: str = "req-1") -> Path:
        path = roots["audit"] / "acme" / "approvals" / "requests.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as handle:
            handle.write(
                json.dumps(
                    {
                        "kind": "approval_request",
                        "request_id": request_id,
                        "tool_name": "bash",
                        "agent_name": "exploit",
                        "reason": "state-changing request",
                        "tool_args_redacted": {"command": "curl -X DELETE ..."},
                    }
                )
                + "\n"
            )
        return path

    def _cli(self, roots: dict[str, Path], *args: str) -> int:
        return approvals_cli.main(
            ["--control-root", str(roots["control"]), "--audit-root", str(roots["audit"]), *args]
        )

    def test_list_then_allow(self, roots, capsys) -> None:
        self._request(roots)
        assert self._cli(roots, "list", "acme") == 0
        assert "req-1" in capsys.readouterr().out
        assert self._cli(roots, "allow", "acme", "req-1", "--note", "ok on staging") == 0
        decisions = roots["control"] / "acme" / "approvals" / "decisions.jsonl"
        record = json.loads(decisions.read_text().strip())
        assert record["kind"] == "approval_decision" and record["action"] == "allow"
        assert record["operator_note"] == "ok on staging"
        capsys.readouterr()
        self._cli(roots, "list", "acme")
        assert "no pending" in capsys.readouterr().out

    def test_unknown_request_is_rejected(self, roots) -> None:
        self._request(roots)
        assert self._cli(roots, "deny", "acme", "nope") == approvals_cli.EXIT_CONFIG

    def test_transport_reads_decisions_the_cli_wrote(self, roots, monkeypatch) -> None:
        monkeypatch.setenv("BUGGY_WORKSPACE_ROOT", str(roots["workspace"]))
        monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(roots["control"]))
        monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(roots["audit"]))
        workspace = str(roots["workspace"] / "acme")
        requests_path, decisions_path = approval_paths(workspace, "acme")
        assert requests_path == roots["audit"] / "acme" / "approvals" / "requests.jsonl"
        assert decisions_path == roots["control"] / "acme" / "approvals" / "decisions.jsonl"
        # Nothing approval-related lands in the agent-writable workspace.
        assert roots["workspace"] not in decisions_path.parents

        transport = FileBackedApprovalTransport(requests_path, decisions_path)
        from buggy.middleware.hitl import ApprovalPolicyRule, ApprovalRequest

        rule = ApprovalPolicyRule(tool_pattern="bash", timeout_seconds=30)
        request = ApprovalRequest(
            request_id="req-9",
            engagement_name="acme",
            agent_name="exploit",
            tool_name="bash",
            tool_args_redacted={},
            matched_rule=rule,
            reason="test",
            created_at=0.0,
        )
        transport.submit(request)
        assert self._cli(roots, "deny", "acme", "req-9") == 0
        decision = transport.wait_for_decision("req-9", timeout=5)
        assert decision is not None and decision.action == "deny"

    def test_without_control_plane_paths_fall_back_to_workspace(self, tmp_path) -> None:
        requests_path, decisions_path = approval_paths(str(tmp_path / "ws"))
        assert requests_path.parent == decisions_path.parent == tmp_path / "ws" / "approvals"
