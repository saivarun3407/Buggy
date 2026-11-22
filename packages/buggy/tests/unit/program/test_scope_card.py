"""The scope is shown as four lists, and every line is backed by the stored documents."""

from __future__ import annotations

from typing import Any

from buggy.program import scope_card
from buggy.program.record import BASELINE_BANNED_TECHNIQUES


def _document(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "machine_enforcement": {
            "mode": "enforce",
            "in_scope": ["app.example.com", {"target": "**.api.example.com"}],
            "out_of_scope": ["admin.example.com"],
            "min_inter_request_delay_ms": 200,
        },
        "pipeline": {"rate_limit_rps": 5, "port_scan": False},
        "approvals": {"state_changing": "required"},
        "network": {"allow_private_targets": False},
    }
    for path, value in changes.items():
        block, _, key = path.partition("__")
        document[block][key] = value
    return document


def test_the_card_has_exactly_the_four_lists() -> None:
    card = scope_card.card(_document())

    assert set(card) == {"enforced", "in_scope", "out_of_scope", "do", "dont"}
    assert card["enforced"] is True
    assert card["in_scope"] == ["app.example.com", "**.api.example.com"]
    assert card["out_of_scope"] == ["admin.example.com", "Everything not listed as in scope."]


def test_the_default_run_asks_before_changing_data_and_creates_nothing() -> None:
    card = scope_card.card(_document())

    assert "Send at most 5 requests per second." in card["do"]
    assert "Tests that change data, only after you approve each one." in card["do"]
    assert not any("Register" in line for line in card["do"])
    assert card["dont"][:3] == list(scope_card.ALWAYS_DONT)
    assert "No port scanning." in card["dont"]
    assert "No account creation: only accounts you give it." in card["dont"]
    assert "No requests to internal addresses." in card["dont"]
    assert card["dont"][-1] == "Never approves its own request and never submits a report."


def test_a_switch_moves_its_line_from_dont_to_do() -> None:
    card = scope_card.card(
        _document(
            pipeline__port_scan=True,
            network__allow_private_targets=True,
            machine_enforcement__account_creation={
                "enabled": True,
                "email_template": "me+{tag}@example.org",
                "max_accounts": 2,
            },
        )
    )

    assert "Scan the top 100 ports." in card["do"]
    assert "Register up to 2 test accounts (emails like me+{tag}@example.org)." in card["do"]
    for gone in ("No port scanning.", "No requests to internal addresses."):
        assert gone not in card["dont"]
    assert not any("account creation" in line for line in card["dont"])


def test_a_practice_target_says_changes_run_without_asking() -> None:
    card = scope_card.card(_document(approvals__state_changing="not_required"))

    assert "Tests that change data, without asking (practice target)." in card["do"]


def test_a_program_brings_its_own_rate_limit_and_banned_techniques() -> None:
    program = {
        "rate_limit": {"requests_per_second": 2},
        "banned_techniques": [
            *BASELINE_BANNED_TECHNIQUES,
            {"id": "excluded_class", "rule": "Not accepted by the program: self-XSS"},
        ],
    }
    card = scope_card.card(_document(pipeline__passive_only=True), program)

    assert "Send at most 2 requests per second." in card["do"]
    assert card["dont"][0].startswith("No denial of service")
    assert "Not accepted by the program: self-XSS" in card["dont"]
    assert "No automated scanning: recon from passive sources only." in card["dont"]
    assert not set(scope_card.ALWAYS_DONT) & set(card["dont"])


def test_a_scope_that_is_not_enforced_says_so_first() -> None:
    document = _document(machine_enforcement__mode="audit")

    text = scope_card.render(scope_card.card(document))

    assert text.splitlines()[0].strip().startswith("NOT ENFORCED")
    assert scope_card.render(scope_card.card(_document())).splitlines()[0] == "  IN SCOPE"


def test_the_text_is_a_heading_per_list_with_one_entry_per_line() -> None:
    lines = scope_card.render(scope_card.card(_document())).splitlines()

    headings = [line.strip() for line in lines if not line.startswith("    ")]
    assert headings == ["IN SCOPE", "OUT OF SCOPE", "DO", "DON'T"]
    assert "    app.example.com" in lines
