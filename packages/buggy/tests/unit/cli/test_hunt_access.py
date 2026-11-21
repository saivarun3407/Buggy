"""hunt compares what each declared test account can read, by code, and says what it skipped."""

from __future__ import annotations

import argparse
import json

import pytest

from buggy.cli import hunt

ALICE_ORDER = "https://app.test/api/orders/1001"
BOB_ORDER = "https://app.test/api/orders/2002"
IDENTITIES = [
    {"name": "alice", "role": "user", "owner_of": [ALICE_ORDER, "https://app.test/files/*"]},
    {"name": "bob", "role": "user", "owner_of": [BOB_ORDER, "not-a-url"]},
]


class Server:
    def __init__(self, identities=None, verdicts=None, ids=None, verify="exploit_verified"):
        self.calls: list[tuple[str, dict]] = []
        self.identities = IDENTITIES if identities is None else identities
        self.verdicts = verdicts or {
            f"GET {ALICE_ORDER}": {"verdict": "broken_access"},
            f"GET {BOB_ORDER}": {"verdict": "enforced"},
        }
        self.ids = ["F-idor"] if ids is None else ids
        self.verify = verify

    def __call__(self, tool: str, engagement: str, **arguments) -> dict:
        assert engagement == "acme"
        self.calls.append((tool, arguments))
        if tool == "identities_list":
            return {"ok": True, "identities": self.identities, "count": len(self.identities)}
        if tool == "authz_matrix_run":
            return {"verdicts": self.verdicts, "skipped": [], "queue": {"ids": self.ids}}
        if tool == "finding_verify":
            return {"ok": True, "finding": {"id": arguments["finding_id"], "status": self.verify}}
        if tool == "finding_grade":
            return {"ok": True, "grade": {"decision": "submit"}}
        raise AssertionError(tool)

    def tools(self) -> list[str]:
        return [tool for tool, _arguments in self.calls]


def use(monkeypatch, server: Server) -> Server:
    monkeypatch.setattr(hunt, "_capture", server)
    return server


def test_owned_objects_are_compared_and_a_mismatch_is_proven_and_graded(monkeypatch) -> None:
    server = use(monkeypatch, Server())
    out = hunt.run_access_sweep("acme", {})
    assert server.tools() == [
        "identities_list",
        "authz_matrix_run",
        "finding_verify",
        "finding_grade",
    ]
    matrix = server.calls[1][1]
    # Only concrete object URLs are asked for: no prefix pattern, nothing that is not a URL.
    assert json.loads(matrix["urls_json"]) == [ALICE_ORDER, BOB_ORDER]
    assert matrix["max_requests"] == hunt.ACCESS_MAX_REQUESTS
    assert out["ran"] is True and out["reason"] is None
    assert (out["accounts"], out["objects"]) == (2, 2)
    assert (out["broken_access"], out["enforced"], out["inconclusive"]) == (1, 1, 0)
    assert (out["verified"], out["submit"]) == (1, 1)
    assert out["findings"] == [{"id": "F-idor", "status": "exploit_verified", "grade": "submit"}]


def test_nothing_is_sent_without_declared_accounts(monkeypatch) -> None:
    server = use(monkeypatch, Server(identities=[]))
    out = hunt.run_access_sweep("acme", {})
    assert server.tools() == ["identities_list"]
    assert out["ran"] is False and "no test accounts are declared" in out["reason"]
    assert "~/.buggy/secrets/acme/identities.json" in out["reason"]


def test_nothing_is_sent_when_no_account_owns_an_object(monkeypatch) -> None:
    accounts = [{"name": "alice", "owner_of": ["https://app.test/files/*"]}, {"name": "bob"}]
    server = use(monkeypatch, Server(identities=accounts))
    out = hunt.run_access_sweep("acme", {})
    assert server.tools() == ["identities_list"]
    assert out["ran"] is False and out["accounts"] == 2 and "owner_of" in out["reason"]


def test_an_unreadable_identities_file_is_reported_not_guessed(monkeypatch) -> None:
    def broken(tool: str, _engagement: str, **_arguments) -> dict:
        assert tool == "identities_list"
        return {"error": "BAD_IDENTITIES", "detail": "identities[0].name: must be a string"}

    monkeypatch.setattr(hunt, "_capture", broken)
    out = hunt.run_access_sweep("acme", {})
    assert out["ran"] is False and out["reason"] == "identities[0].name: must be a string"


def test_a_mismatch_that_is_not_reproduced_is_not_graded(monkeypatch) -> None:
    server = use(monkeypatch, Server(verify="inconclusive"))
    out = hunt.run_access_sweep("acme", {})
    assert "finding_grade" not in server.tools()
    assert (out["broken_access"], out["verified"], out["submit"]) == (1, 0, 0)


def test_the_object_list_is_capped(monkeypatch) -> None:
    many = [f"https://app.test/o/{n:03d}" for n in range(hunt.MAX_ACCESS_URLS + 5)]
    server = use(monkeypatch, Server(identities=[{"name": "alice", "owner_of": many}], ids=[]))
    out = hunt.run_access_sweep("acme", {})
    assert len(json.loads(server.calls[1][1]["urls_json"])) == hunt.MAX_ACCESS_URLS
    assert out["left_out"] == 5


class TestStage:
    def args(self, **overrides) -> argparse.Namespace:
        values = {"no_probes": False, "non_interactive": False}
        return argparse.Namespace(**{**values, **overrides})

    def test_prints_the_comparison(self, monkeypatch, capsys) -> None:
        use(monkeypatch, Server())
        hunt._access_stage(self.args(), "acme", {})  # noqa: SLF001
        err = capsys.readouterr().err
        assert "access control   2 owned objects asked as 2 accounts" in err
        assert "1 readable by a non-owner, 1 enforced" in err
        assert "F-idor  access_control  exploit_verified/submit" in err

    def test_says_why_it_did_not_run(self, monkeypatch, capsys) -> None:
        use(monkeypatch, Server(identities=[]))
        hunt._access_stage(self.args(), "acme", {})  # noqa: SLF001
        assert "access control   not run: no test accounts are declared" in capsys.readouterr().err

    def test_off_with_no_probes(self, monkeypatch) -> None:
        server = use(monkeypatch, Server())
        assert hunt._access_stage(self.args(no_probes=True), "acme", {}) is None  # noqa: SLF001
        assert server.calls == []


class TestNotTested:
    def args(self, **overrides) -> argparse.Namespace:
        return argparse.Namespace(**{"no_agent": True, "force_agent": False, **overrides})

    def areas(self, items: list[dict]) -> list[str]:
        return [item["area"] for item in items]

    def test_a_scanner_only_run_lists_everything_it_skipped(self) -> None:
        items = hunt.not_tested("acme", self.args(), None, None)
        assert self.areas(items) == [
            "injection, redirect, traversal and CORS probes",
            "access control between users (IDOR)",
            "business logic, authentication flows, request bodies, chained findings",
            "anything that changes state (orders, payments, account changes)",
        ]
        assert all(item["reason"] and item["enable"] for item in items)
        assert "buggy onboard" in items[2]["enable"]

    def test_what_ran_is_not_listed(self, monkeypatch) -> None:
        monkeypatch.setattr(hunt, "model_configured", lambda: True)
        items = hunt.not_tested(
            "acme", self.args(no_agent=False), {"ran": 3}, {"ran": True, "reason": None}
        )
        assert self.areas(items) == [
            "anything that changes state (orders, payments, account changes)"
        ]

    def test_the_access_reason_is_the_sweeps_own(self) -> None:
        access = {"ran": False, "reason": "no test accounts are declared; add two"}
        items = hunt.not_tested("acme", self.args(), {"ran": 1}, access)
        assert items[0]["reason"] == "no test accounts are declared; add two"

    @pytest.mark.parametrize("configured", [True, False])
    def test_agents_are_listed_only_when_they_did_not_start(self, monkeypatch, configured) -> None:
        monkeypatch.setattr(hunt, "model_configured", lambda: configured)
        items = hunt.not_tested("acme", self.args(no_agent=False), {"ran": 1}, {"ran": True})
        listed = any(item["area"].startswith("business logic") for item in items)
        assert listed is (not configured)
