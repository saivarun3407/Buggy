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
        assert "Register up to 2 test accounts (emails like me+{tag}@corp.example)." in shown
        plain = hunt.build_scope(hunt._build_parser().parse_args(["https://app.acme.test"]))  # noqa: SLF001
        assert "account_creation" not in plain["enforcement_extra"]
        without = "\n".join(hunt._describe(plain, "enforce"))  # noqa: SLF001
        assert "test accounts" not in without
        assert "No account creation: only accounts you give it." in without


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
        assert "not ready yet: CAPTCHA" in err and "YOUR TURN" in err

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
        assert set(result) == {
            "ok",
            "enabled",
            "created",
            "reused",
            "failed",
            "reason",
            "your_turn",
        }
        assert "a@b.c" not in str(result) and result["your_turn"] == []


class TestYourTurn:
    """Buggy does what it can; where a person is needed it says exactly what to do."""

    def steps(self, monkeypatch, answer: dict) -> list[str]:
        monkeypatch.setattr(hunt, "_capture", lambda *_a, **_k: answer)
        return hunt.run_account_creation("acme", RECORDS)["your_turn"]

    def answer(self, reason: str, **extra) -> dict:
        base = {
            "enabled": True, "created": [], "reused": [],
            "failed": [{"name": "auto1", "reason": reason, "detail": ""}],
            "signup": {"kind": "form", "url": "https://app.acme.test/register"},
            "login": {"kind": "form", "url": "https://app.acme.test/login"},
            "credentials_file": "audit/acme/accounts-created.json",
        }  # fmt: skip
        return {**base, **extra}

    def test_a_captcha_is_handed_to_the_operator_with_the_prepared_values(
        self, monkeypatch
    ) -> None:
        steps = self.steps(monkeypatch, self.answer("CAPTCHA"))
        assert steps[0] == "Sign-up needs you once: a CAPTCHA."
        assert "https://app.acme.test/register" in steps[1]
        assert "~/.buggy/audit/acme/accounts-created.json" in steps[1]
        assert steps[2].startswith("Then run: buggy hunt --resume acme")

    def test_email_verification_asks_for_the_click_only(self, monkeypatch) -> None:
        steps = self.steps(monkeypatch, self.answer("EMAIL_VERIFICATION"))
        assert "wait for email verification" in steps[0] and "click the links" in steps[1]
        assert "buggy hunt --resume acme" in steps[2]

    def test_a_prepared_account_still_waiting_repeats_the_same_step(self, monkeypatch) -> None:
        steps = self.steps(monkeypatch, self.answer("WAITING_FOR_OPERATOR"))
        assert steps and "register the accounts" in steps[1]

    def test_sso_or_no_sign_in_asks_for_sessions_instead(self, monkeypatch) -> None:
        sso = self.steps(monkeypatch, self.answer("SSO_ONLY"))
        assert "single sign-on" in sso[0] and "identities.json" in sso[1]
        blind = self.steps(monkeypatch, self.answer("NO_SIGNUP_FOUND", signup=None, login=None))
        assert "no sign-in form or API" in blind[0] and "identities.json" in blind[1]

    def test_nothing_is_asked_when_two_accounts_work_or_it_is_off(self, monkeypatch) -> None:
        working = {"enabled": True, "created": ["auto1"], "reused": ["auto2"], "failed": []}
        assert self.steps(monkeypatch, working) == []
        off = {"enabled": False, "created": [], "reused": [],
               "failed": [{"name": "", "reason": "NOT_ENABLED", "detail": ""}]}  # fmt: skip
        assert self.steps(monkeypatch, off) == []

    def test_the_run_prints_the_steps_and_lists_them_as_not_tested(
        self, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(hunt, "_capture", lambda *_a, **_k: self.answer("CAPTCHA"))
        monkeypatch.setattr(hunt, "_notify", lambda *_a, **_k: None)
        args = argparse.Namespace(
            no_probes=False, non_interactive=False, no_agent=True, force_agent=False
        )
        scope = {"enforcement_extra": {"account_creation": {"enabled": True}}}
        accounts = hunt._accounts_stage(args, "acme", scope, RECORDS)  # noqa: SLF001
        err = capsys.readouterr().err
        assert "YOUR TURN        Sign-up needs you once: a CAPTCHA." in err
        assert "    2. Then run: buggy hunt --resume acme" in err
        items = hunt.not_tested("acme", args, {"ran": 1}, {"ran": True}, accounts=accounts)
        (entry,) = [i for i in items if i["area"] == "everything behind the login"]
        assert entry["reason"] == "Sign-up needs you once: a CAPTCHA."
        assert "buggy hunt --resume acme" in entry["enable"]
