"""Tool-call guard: ordered rules over every argument, decoded, before execution (D5)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import ToolMessage

from buggy.cli import scope as scope_cli
from buggy.middleware._audit_sink import RoEAuditSink
from buggy.middleware.roe import RoEGuardrailMiddleware
from buggy_core.types.roe import MachineEnforcement
from buggy_core.types.roe_document import InvalidRoEError, parse_roe_document
from buggy_core.types.tool_guard import (
    MAX_DEPTH,
    MAX_STRING_LENGTH,
    GuardRule,
    compile_rules,
    decode_rounds,
    evaluate_call,
    flatten,
)

DROP = r"(?i)drop\s+table"
TARGET = "https://app.acme.test/api/search"


def _rules(*items: Any) -> tuple[GuardRule, ...]:
    rules, errors = compile_rules(list(items))
    assert errors == []
    return rules


def _http_send(body: str) -> dict[str, Any]:
    return {"method": "POST", "url": TARGET, "body": body}


# -- core: flatten / decode / evaluate ----------------------------------------------


class TestDecoding:
    def test_percent_decoding_stops_when_unchanged_and_after_three_rounds(self) -> None:
        assert decode_rounds("plain") == ["plain"]
        assert decode_rounds("DROP%2520TABLE")[:3] == [
            "DROP%2520TABLE",
            "DROP%20TABLE",
            "DROP TABLE",
        ]
        # Four layers of encoding: three rounds peel three of them, no more.
        quad = "DROP%25252520TABLE"
        assert "DROP%20TABLE" in decode_rounds(quad)
        assert "DROP TABLE" not in decode_rounds(quad)

    def test_html_entities_and_backslash_escapes_are_unescaped_once(self) -> None:
        assert "DROP TABLE" in decode_rounds("DROP&#32;TABLE")
        assert "DROP TABLE" in decode_rounds("DROP&#x20;TABLE")
        assert "DROP TABLE" in decode_rounds(r"DROP\x20TABLE")
        assert "DROP TABLE" in decode_rounds(r"DROP TABLE")


class TestEvaluateCall:
    @pytest.mark.parametrize(
        "body",
        [
            json.dumps({"q": "x'; DROP%20TABLE users;--"}),
            json.dumps({"q": "x'; DROP%2520TABLE users;--"}),
            json.dumps({"q": "x'; DROP&#32;TABLE users;--"}),
            json.dumps({"q": "x'; DROP+TABLE users;--"}),
            json.dumps({"q": "x'; DROP\\u0020TABLE users;--"}),
        ],
        ids=["urlencoded", "double-urlencoded", "html-entity", "plus", "unicode-escape"],
    )
    def test_encoded_payloads_in_a_json_body_are_caught(self, body: str) -> None:
        decision = evaluate_call("http_send", _http_send(body), _rules(DROP))
        assert decision.blocked
        assert decision.rule == "tool_guard[0]"
        assert decision.where.startswith("args.body")

    def test_negative_control_dropdown_table_is_not_blocked(self) -> None:
        body = json.dumps({"q": "dropdown table styling", "enc": "dropdown%20table"})
        assert not evaluate_call("http_send", _http_send(body), _rules(DROP)).blocked

    def test_nested_structures_are_inspected(self) -> None:
        args = {"a": [{"b": {"c": ["ok", {"d": "please DROP TABLE x"}]}}]}
        decision = evaluate_call("http_send", args, _rules(DROP))
        assert decision.blocked and decision.where.startswith("args.a[0].b.c[1].d")

    def test_json_inside_a_string_inside_json_is_inspected(self) -> None:
        # The tab is a JSON escape ("\\t") two string layers deep: only parsing the
        # nested JSON strings turns it back into whitespace.
        inner = json.dumps({"deep": "DROP\tTABLE t"})
        args = {"params_json": json.dumps({"payload": inner})}
        assert "\t" not in args["params_json"]
        decision = evaluate_call("probe_run", args, _rules(DROP))
        assert decision.blocked
        assert decision.where.startswith("args.params_json<json>.payload<json>.deep")

    def test_dict_keys_are_inspected(self) -> None:
        args = {"headers": {"X-DROP TABLE": "1"}}
        decision = evaluate_call("http_send", args, _rules(DROP))
        assert decision.blocked and "(key)" in decision.where
        assert "X-DROP TABLE" in flatten(args)

    def test_flatten_includes_the_compact_serialization(self) -> None:
        args = {"a": 1, "b": ["x"]}
        assert '{"a":1,"b":["x"]}' in flatten(args)

    def test_tool_name_is_checked(self) -> None:
        rules = _rules({"pattern": r"^dangerous_tool$", "name": "no-dangerous"})
        assert evaluate_call("dangerous_tool", {}, rules).where == "tool name"
        assert not evaluate_call("safe_tool", {}, rules).blocked

    def test_per_tool_rules_apply_only_to_the_named_tools(self) -> None:
        rules = _rules({"pattern": "DELETE", "name": "no-delete", "tools": ["http_send"]})
        args = {"method": "DELETE", "url": TARGET}
        assert evaluate_call("http_send", args, rules).blocked
        assert not evaluate_call("web_fetch", args, rules).blocked
        assert not evaluate_call("bash", {"command": "echo DELETE"}, rules).blocked

    def test_first_matching_rule_wins(self) -> None:
        rules = _rules(
            {"pattern": "nothing-here", "name": "first"},
            {"pattern": "DROP", "name": "second"},
            {"pattern": "TABLE", "name": "third"},
        )
        assert evaluate_call("bash", {"command": "DROP TABLE"}, rules).rule == "second"

    def test_no_rules_allows(self) -> None:
        assert not evaluate_call("http_send", _http_send("DROP TABLE"), ()).blocked

    def test_payload_after_the_per_string_cap_is_still_seen(self) -> None:
        body = "a" * (MAX_STRING_LENGTH * 2 + 17) + " DROP TABLE x"
        assert evaluate_call("http_send", _http_send(body), _rules(DROP)).blocked

    def test_hostile_nesting_fails_closed_instead_of_recursing(self) -> None:
        args: Any = "DROP TABLE"
        for _ in range(MAX_DEPTH + 5):
            args = {"k": args}
        decision = evaluate_call("http_send", args, _rules("never-matches"))
        assert decision.blocked and decision.rule == "tool-guard-limits"
        with pytest.raises(ValueError):
            flatten(args)

    def test_hostile_size_is_bounded_in_time(self) -> None:
        # Many strings that keep changing under every decoding round.
        args = {"items": ["%25" * 1000] * 500}
        started = time.perf_counter()
        decision = evaluate_call("http_send", args, _rules(DROP))
        assert time.perf_counter() - started < 10
        assert not decision.blocked
        # Past the cumulative-size bound the call is refused, not half-inspected.
        huge = {"items": ["x" * 1_000_000] * 5}
        assert evaluate_call("http_send", huge, _rules(DROP)).rule == "tool-guard-limits"

    def test_time_budget_fails_closed(self) -> None:
        rules = _rules({"pattern": r"(a+)+$", "name": "slow"})
        decision = evaluate_call("bash", {"command": "a" * 22 + "!"}, rules, time_budget_s=0.0)
        assert decision.blocked and decision.where == "time budget exceeded"

    def test_rules_without_a_regex_are_untouched_by_limits(self) -> None:
        # No applicable rule: nothing is inspected, so no limit can refuse the call.
        rules = _rules({"pattern": "x", "tools": ["other_tool"]})
        huge = {"items": ["x" * 1_000_000] * 5}
        assert not evaluate_call("http_send", huge, rules).blocked


class TestCompileRules:
    def test_plain_strings_mean_all_tools(self) -> None:
        (rule,) = _rules(DROP)
        assert rule.tools == ("*",) and rule.pattern == DROP

    @pytest.mark.parametrize(
        "item",
        [
            "[unclosed",
            {"pattern": "("},
            {"pattern": ""},
            {"pattern": 5},
            {"pattern": "ok", "tools": []},
            {"pattern": "ok", "tools": [""]},
            {"pattern": "ok", "tool": ["http_send"]},
            {"pattern": "ok", "name": 3},
            {"pattern": "ok", "message": ["x"]},
            {"pattern": "a" * 4097},
            7,
        ],
    )
    def test_invalid_rule_is_reported_not_skipped(self, item: Any) -> None:
        rules, errors = compile_rules(["fine", item])
        assert len(errors) == 1
        assert [r.pattern for r in rules] == ["fine"]

    def test_rule_cap(self) -> None:
        _, errors = compile_rules(["x"] * 101)
        assert errors

    def test_lenient_from_dict_keeps_a_broken_rule_and_it_blocks(self) -> None:
        rules = MachineEnforcement.from_dict({"tool_guard": [{"pattern": "("}]})
        assert len(rules.tool_guard) == 1 and rules.tool_guard[0].error
        assert evaluate_call("http_send", {"url": TARGET}, rules.tool_guard).blocked


# -- scope document validation ------------------------------------------------------


def _document(**extra: Any) -> dict[str, Any]:
    return {"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"], **extra}}


class TestDocumentValidation:
    def test_valid_rules_are_parsed_in_order(self) -> None:
        rules = parse_roe_document(
            _document(tool_guard=[DROP, {"pattern": "x", "name": "n", "tools": ["bash"]}]),
            required=True,
        )
        assert [r.name for r in rules.tool_guard] == ["tool_guard[0]", "n"]
        assert rules.tool_guard[1].tools == ("bash",)

    @pytest.mark.parametrize(
        "guard",
        [["(?i)drop\\s+table("], [{"pattern": "["}], "DROP", {"pattern": "x"}, [None], None],
        ids=["bad-regex", "bad-regex-dict", "string", "object", "null-entry", "null"],
    )
    def test_invalid_guard_block_rejects_the_scope(self, guard: Any) -> None:
        with pytest.raises(InvalidRoEError):
            parse_roe_document(_document(tool_guard=guard), required=True)

    def test_too_many_rules_in_total_rejects_the_scope(self) -> None:
        with pytest.raises(InvalidRoEError):
            parse_roe_document(
                _document(tool_guard=["a"] * 60, forbidden_command_patterns=["b"] * 41),
                required=True,
            )

    def test_absent_guard_block_is_fine(self) -> None:
        assert parse_roe_document(_document(), required=True).tool_guard == ()


# -- middleware ---------------------------------------------------------------------


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUGGY_EGRESS_DISABLE", "1")
    monkeypatch.setenv("BUGGY_ROE_REQUIRE", "0")
    monkeypatch.delenv("BUGGY_ROE_AUDIT_PATH", raising=False)


def _write(workspace: Path, block: dict[str, Any]) -> None:
    (workspace / "plan").mkdir(parents=True, exist_ok=True)
    (workspace / "plan" / "roe.json").write_text(json.dumps({"machine_enforcement": block}))


def _request(workspace: Path, tool: str, args: dict[str, Any]) -> MagicMock:
    request = MagicMock()
    request.tool = MagicMock()
    request.tool.name = tool
    request.state = {"workspace_path": str(workspace), "engagement_name": "acme"}
    request.tool_call = {"name": tool, "args": args, "id": "tc-1"}
    request.tool_call_args = args
    request.tool_call_id = "tc-1"
    return request


def _run(workspace: Path, tool: str, args: dict[str, Any]) -> tuple[Any, MagicMock, list[dict]]:
    ledger = workspace / "audit.jsonl"
    mw = RoEGuardrailMiddleware(sink=RoEAuditSink(path=ledger))
    handler = MagicMock(return_value=ToolMessage(content="executed", tool_call_id="tc-1"))
    result = mw.wrap_tool_call(_request(workspace, tool, args), handler)
    records = [json.loads(line) for line in ledger.read_text().splitlines() if line]
    return result, handler, records


def _block(**extra: Any) -> dict[str, Any]:
    return {"mode": "enforce", "in_scope": ["app.acme.test"], **extra}


class TestMiddleware:
    @pytest.mark.parametrize("encoded", ["DROP%20TABLE", "DROP%2520TABLE", "DROP&#32;TABLE"])
    def test_blocked_call_is_not_executed_and_is_ledgered(
        self, env, tmp_path: Path, encoded: str
    ) -> None:
        _write(tmp_path, _block(tool_guard=[{"pattern": DROP, "name": "no-sql-ddl"}]))
        body = json.dumps({"q": f"1; {encoded} users"})
        result, handler, records = _run(tmp_path, "http_send", _http_send(body))
        assert not handler.called
        assert "[ROE_REFUSED] code=TOOL_GUARD_BLOCKED" in result.content
        assert "no-sql-ddl" in result.content
        assert DROP not in result.content and r"drop\s+table" not in result.content
        (record,) = records
        assert record["event"] == "tool_guard_blocked"
        assert record["reason_code"] == "TOOL_GUARD_BLOCKED"
        assert record["matched_targets"] == ["no-sql-ddl"]
        assert DROP not in json.dumps(record)

    def test_negative_control_runs_and_has_no_guard_event(self, env, tmp_path: Path) -> None:
        _write(tmp_path, _block(tool_guard=[DROP]))
        body = json.dumps({"q": "dropdown table"})
        result, handler, records = _run(tmp_path, "http_send", _http_send(body))
        assert handler.called and result.content == "executed"
        assert records[0]["decision"] == "allow" and "event" not in records[0]

    def test_legacy_patterns_now_cover_every_gated_tool(self, env, tmp_path: Path) -> None:
        _write(tmp_path, _block(forbidden_command_patterns=["blocked-marker"]))
        result, handler, _ = _run(
            tmp_path, "http_send", _http_send(json.dumps({"x": "blocked%2Dmarker"}))
        )
        assert not handler.called and "TOOL_GUARD_BLOCKED" in result.content

    def test_shell_command_keeps_forbidden_command_code(self, env, tmp_path: Path) -> None:
        _write(tmp_path, _block(forbidden_command_patterns=["blocked-marker"]))
        result, handler, _ = _run(tmp_path, "bash", {"command": "printf blocked-marker"})
        assert not handler.called and "code=FORBIDDEN_COMMAND" in result.content
        # The encoded form slipped past the raw-command check; the guard catches it.
        result, handler, _ = _run(tmp_path, "bash", {"command": "printf blocked%2Dmarker"})
        assert not handler.called and "code=TOOL_GUARD_BLOCKED" in result.content

    def test_existing_scope_check_still_decides_first(self, env, tmp_path: Path) -> None:
        _write(tmp_path, _block(tool_guard=[DROP]))
        args = {"url": "https://other.example/", "body": "DROP TABLE"}
        result, handler, _ = _run(tmp_path, "http_send", args)
        assert not handler.called and "code=NOT_IN_SCOPE" in result.content

    def test_per_tool_rule_through_the_middleware(self, env, tmp_path: Path) -> None:
        _write(tmp_path, _block(tool_guard=[{"pattern": "DELETE", "tools": ["http_send"]}]))
        _, handler, _ = _run(tmp_path, "http_send", {"url": TARGET, "method": "DELETE"})
        assert not handler.called
        _, handler, _ = _run(tmp_path, "web_fetch", {"url": TARGET, "note": "DELETE"})
        assert handler.called

    def test_audit_mode_logs_but_runs(self, env, tmp_path: Path) -> None:
        _write(tmp_path, {"mode": "audit", "tool_guard": [DROP]})
        _, handler, records = _run(tmp_path, "bash", {"command": "echo DROP TABLE"})
        assert handler.called
        assert records[0]["event"] == "tool_guard_blocked"

    def test_invalid_guard_in_scope_file_refuses_gated_calls(self, env, tmp_path: Path) -> None:
        _write(tmp_path, _block(tool_guard=["(unclosed"]))
        result, handler, _ = _run(tmp_path, "http_send", {"url": TARGET})
        assert not handler.called and "code=INVALID_ROE" in result.content


# -- scope test-call ----------------------------------------------------------------


@pytest.fixture
def roots(tmp_path: Path) -> dict[str, Path]:
    out = {name: tmp_path / name for name in ("workspace", "control")}
    for path in out.values():
        path.mkdir()
    return out


def _enforce(roots: dict[str, Path], block: dict[str, Any]) -> None:
    path = roots["control"] / "acme" / "roe.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"machine_enforcement": block}))


def _test_call(roots: dict[str, Path], tool: str, args: str) -> int:
    return scope_cli.main(
        [
            "--workspace-root",
            str(roots["workspace"]),
            "--control-root",
            str(roots["control"]),
            "test-call",
            "acme",
            "--tool",
            tool,
            "--args",
            args,
        ]
    )


class TestScopeTestCall:
    def test_blocked_exit_1_names_the_rule(self, roots, capsys) -> None:
        _enforce(roots, _block(tool_guard=[{"pattern": DROP, "name": "no-sql-ddl"}]))
        body = json.dumps({"q": "DROP%2520TABLE users"})
        assert _test_call(roots, "http_send", json.dumps(_http_send(body))) == 1
        out = capsys.readouterr().out
        assert out.startswith("blocked: rule 'no-sql-ddl'")

    def test_allowed_exit_0(self, roots, capsys) -> None:
        _enforce(roots, _block(tool_guard=[DROP]))
        args = json.dumps(_http_send(json.dumps({"q": "dropdown table"})))
        assert _test_call(roots, "http_send", args) == 0
        assert capsys.readouterr().out.startswith("allowed:")

    def test_does_not_write_anything(self, roots) -> None:
        _enforce(roots, _block(tool_guard=[DROP]))
        before = sorted(p.name for p in roots["control"].rglob("*"))
        _test_call(roots, "bash", json.dumps({"command": "DROP TABLE"}))
        assert sorted(p.name for p in roots["control"].rglob("*")) == before

    @pytest.mark.parametrize("args", ["not json", "[1, 2]"])
    def test_bad_args_exit_2(self, roots, args: str) -> None:
        _enforce(roots, _block(tool_guard=[DROP]))
        assert _test_call(roots, "bash", args) == scope_cli.EXIT_CONFIG

    def test_missing_or_invalid_scope_exit_2(self, roots, capsys) -> None:
        assert _test_call(roots, "bash", "{}") == scope_cli.EXIT_CONFIG
        _enforce(roots, _block(tool_guard=["("]))
        assert _test_call(roots, "bash", "{}") == scope_cli.EXIT_CONFIG
        assert "scope rejected" in capsys.readouterr().err

    def test_set_rejects_a_scope_with_a_broken_guard(self, roots, tmp_path: Path) -> None:
        source = tmp_path / "roe.json"
        source.write_text(json.dumps({"machine_enforcement": _block(tool_guard=["("])}))
        with pytest.raises(SystemExit):
            scope_cli.main(
                [
                    "--workspace-root",
                    str(roots["workspace"]),
                    "--control-root",
                    str(roots["control"]),
                    "set",
                    "acme",
                    "--file",
                    str(source),
                    "--yes",
                ]
            )
        assert not (roots["control"] / "acme" / "roe.json").exists()


class TestBase64IsNotAHidingPlace:
    """`echo <base64> | base64 -d | sh` must not carry a forbidden command past a rule."""

    RM = r"rm\s+-rf\s+/"

    @staticmethod
    def _b64(text: str, *, urlsafe: bool = False, pad: bool = True) -> str:
        import base64

        raw = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(text.encode()).decode()
        return raw if pad else raw.rstrip("=")

    @pytest.mark.parametrize(
        ("urlsafe", "pad"), [(False, True), (False, False), (True, True), (True, False)]
    )
    def test_a_base64_encoded_command_is_caught(self, urlsafe: bool, pad: bool) -> None:
        token = self._b64("cd /tmp; rm -rf / --no-preserve-root", urlsafe=urlsafe, pad=pad)
        args = {"command": f"echo {token} | base64 -d | sh"}
        decision = evaluate_call("bash", args, _rules(self.RM))
        assert decision.blocked and decision.rule == "tool_guard[0]"

    def test_it_is_caught_inside_a_url_encoded_json_body(self) -> None:
        token = self._b64("x'; DROP TABLE users;--   padding to length")
        body = json.dumps({"q": token.replace("=", "%3D")})
        assert evaluate_call("http_send", _http_send(body), _rules(DROP)).blocked

    def test_ordinary_tokens_and_binary_blobs_are_not_blocked(self) -> None:
        import base64

        blob = base64.b64encode(bytes(range(256)) * 2).decode()  # binary: not readable text
        args = {
            "command": f"curl -H 'X-Trace: 9f8e7d6c5b4a39281706f5e4d3c2b1a0' -d '{blob}' {TARGET}",
            "note": "a_long_identifier_name_with_underscores_and-dashes",
        }
        assert not evaluate_call("bash", args, _rules(self.RM, DROP)).blocked

    def test_the_decoded_text_is_added_once_and_only_one_level_deep(self) -> None:
        inner = self._b64("rm -rf / is hidden twice over")
        outer = self._b64(f"echo {inner} | base64 -d")
        variants = decode_rounds(f"echo {outer} | base64 -d | sh")
        assert any(inner in variant for variant in variants)  # first level is revealed
        assert not any("rm -rf /" in variant for variant in variants)  # the second is not

    def test_many_tokens_are_bounded(self) -> None:
        tokens = " ".join(self._b64(f"harmless text number {i:04d}") for i in range(500))
        assert len(decode_rounds(tokens)) <= 1 + 20
