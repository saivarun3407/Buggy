"""hunt lets Buggy create test accounts only when the operator switched it on."""

from __future__ import annotations

import argparse
import json

import pytest

from buggy.cli import hunt


def args(**overrides) -> argparse.Namespace:
    values = {"create_accounts": False, "account_email": "", "lab": False}
    return argparse.Namespace(**{**values, **overrides})


class TestSwitch:
    def test_off_by_default(self) -> None:
        assert hunt._account_creation(args()) is None  # noqa: SLF001
        assert hunt._account_creation(args(account_email="me+{tag}@corp.example")) is None  # noqa: SLF001

    def test_on_with_an_address_the_operator_controls(self) -> None:
        block = hunt._account_creation(  # noqa: SLF001
            args(create_accounts=True, account_email=" me+{tag}@corp.example ")
        )
        assert block == {
            "enabled": True,
            "email_template": "me+{tag}@corp.example",
            "max_accounts": hunt.MAX_CREATED_ACCOUNTS,
        }

    def test_a_training_target_uses_the_reserved_test_domain(self) -> None:
        block = hunt._account_creation(args(create_accounts=True, lab=True))  # noqa: SLF001
        assert block is not None and block["email_template"] == hunt.LAB_ACCOUNT_EMAIL

    def test_a_real_target_needs_an_address(self) -> None:
        with pytest.raises(RuntimeError, match="--account-email"):
            hunt._account_creation(args(create_accounts=True))  # noqa: SLF001

    @pytest.mark.parametrize(
        "template",
        ["me@corp.example", "{tag}", "me+{tag}@", "me+{tag}@corp", "a b+{tag}@corp.example",
         "me@{tag}.example", "me+{tag}@corp.example, other+{tag}@corp.example"],
    )  # fmt: skip
    def test_an_unusable_pattern_is_refused(self, template: str) -> None:
        with pytest.raises(RuntimeError, match="not usable"):
            hunt._account_creation(args(create_accounts=True, account_email=template))  # noqa: SLF001

    def test_the_switch_is_written_into_the_enforced_scope_and_shown(self) -> None:
        parsed = hunt._build_parser().parse_args(  # noqa: SLF001
            [
                "https://app.acme.test",
                "--create-accounts",
                "--account-email",
                "me+{tag}@corp.example",
            ]
        )
        scope = hunt.build_scope(parsed)
        assert scope["enforcement_extra"]["account_creation"]["enabled"] is True
        shown = "\n".join(hunt._describe(scope, "enforce"))  # noqa: SLF001
        assert (
            "test accounts   Buggy may register up to 2 (emails like me+{tag}@corp.example)"
            in shown
        )
        plain = hunt.build_scope(hunt._build_parser().parse_args(["https://app.acme.test"]))  # noqa: SLF001
        assert "account_creation" not in plain["enforcement_extra"]
        assert "test accounts" not in "\n".join(hunt._describe(plain, "enforce"))  # noqa: SLF001


RECORDS = {
    "http_service": [{"value": "https://app.acme.test"}],
    "parameter": [
        {
            "attrs": {
                "name": n,
                "location": "body",
                "method": "POST",
                "url": "https://app.acme.test/api/Users",
            }
        }
        for n in ("email", "password")
    ]
    + [
        {
            "attrs": {
                "name": "q",
                "location": "query",
                "method": "GET",
                "url": "https://app.acme.test/s",
            }
        }
    ],
}


class TestStage:
    def scope(self, on: bool) -> dict:
        extra = {"sandbox_egress": "blocked"}
        if on:
            extra["account_creation"] = {"enabled": True, "email_template": "x", "max_accounts": 2}
        return {"enforcement_extra": extra}

    def run_args(self, **overrides) -> argparse.Namespace:
        return argparse.Namespace(**{"no_probes": False, "non_interactive": False, **overrides})

    def test_nothing_is_asked_without_the_switch(self, monkeypatch) -> None:
        def never(*_a, **_k):
            raise AssertionError("the gateway must not be asked")

        monkeypatch.setattr(hunt, "_capture", never)
        assert hunt._accounts_stage(self.run_args(), "acme", self.scope(False), RECORDS) is None  # noqa: SLF001
        assert (
            hunt._accounts_stage(self.run_args(no_probes=True), "acme", self.scope(True), RECORDS)
            is None
        )  # noqa: SLF001

    def test_the_gateway_is_given_the_services_and_the_write_operations(
        self, monkeypatch, capsys
    ) -> None:
        asked: list[dict] = []

        def capture(tool: str, engagement: str, **arguments) -> dict:
            assert (tool, engagement) == ("accounts_provision", "acme")
            asked.append(arguments)
            return {
                "ok": True,
                "enabled": True,
                "created": ["auto1"],
                "reused": ["auto2"],
                "failed": [],
            }

        monkeypatch.setattr(hunt, "_capture", capture)
        result = hunt._accounts_stage(self.run_args(), "acme", self.scope(True), RECORDS)  # noqa: SLF001
        assert result is not None and result["ok"] and result["created"] == ["auto1"]
        assert json.loads(asked[0]["seeds_json"]) == ["https://app.acme.test"]
        assert json.loads(asked[0]["api_operations_json"]) == [
            {
                "method": "POST",
                "url": "https://app.acme.test/api/Users",
                "body_fields": ["email", "password"],
            }
        ]
        assert "test accounts    created auto1; reused auto2" in capsys.readouterr().err

    def test_a_refusal_says_why_and_what_to_do(self, monkeypatch, capsys) -> None:
        answer = {
            "ok": False, "enabled": True, "created": [], "reused": [],
            "failed": [{"name": "auto1", "reason": "CAPTCHA", "detail": "the sign-up page has a captcha"}],
        }  # fmt: skip
        monkeypatch.setattr(hunt, "_capture", lambda *_a, **_k: answer)
        result = hunt._accounts_stage(self.run_args(), "acme", self.scope(True), RECORDS)  # noqa: SLF001
        assert result is not None and result["ok"] is False and result["reason"] == "CAPTCHA"
        err = capsys.readouterr().err
        assert "could not be created: CAPTCHA" in err and "identities.json" in err

    def test_a_gateway_without_the_tool_is_reported_not_crashed(self, monkeypatch) -> None:
        monkeypatch.setattr(hunt, "_capture", lambda *_a, **_k: {"error": "unknown tool"})
        result = hunt.run_account_creation("acme", RECORDS)
        assert result["ok"] is False and result["reason"] == "unknown tool"

    def test_no_password_or_email_can_reach_the_result(self, monkeypatch) -> None:
        leaky = {
            "created": ["auto1"],
            "reused": [],
            "failed": [],
            "email": "a@b.c",
            "password": "p",
        }
        monkeypatch.setattr(hunt, "_capture", lambda *_a, **_k: leaky)
        result = hunt.run_account_creation("acme", RECORDS)
        assert set(result) == {"ok", "enabled", "created", "reused", "failed", "reason"}
