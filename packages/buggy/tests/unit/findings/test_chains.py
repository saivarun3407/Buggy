"""Invariants and needs-and-gives: what a finding breaks, and which findings chain."""

from __future__ import annotations

from pathlib import Path

import pytest

from buggy.capture import recipes
from buggy.capture.probes import REGISTRY
from buggy.findings import chains
from buggy.findings.candidates import enqueue, from_probe, from_recipe
from buggy.findings.model import CLASSES, context_errors
from buggy.findings.report import build, to_html, to_markdown
from buggy.findings.service import FindingService
from buggy.findings.store import FindingStore

BASE = "https://app.acme.test"


def _finding(fid: str, source: str, cls: str, **extra) -> dict:
    return {
        "id": fid,
        "engagement": "acme",
        "title": f"title {fid}",
        "class": cls,
        "severity": extra.pop("severity", "high"),
        "endpoint": f"{BASE}/{fid}",
        "source": source,
        "status": extra.pop("status", "exploit_verified"),
        "grade": extra.pop("grade", "submit"),
        "assertions": extra.pop("assertions", []),
        **extra,
    }


class TestTables:
    def test_every_probe_and_class_has_an_invariant_and_edges(self) -> None:
        for probe in REGISTRY:
            assert chains.PROBE_INVARIANTS.get(probe), probe
            assert probe in chains.PROBE_EDGES, probe
        for cls in CLASSES:
            assert chains.CLASS_INVARIANTS.get(cls), cls
            assert cls in chains.CLASS_EDGES, cls
        used = {
            cap
            for table in (*chains.PROBE_EDGES.values(), *chains.CLASS_EDGES.values())
            for side in table.values()
            for cap in side
        }
        assert used <= set(chains.CAPABILITIES)
        assert {c for pair in chains.IMPLIES.items() for c in (pair[0], *pair[1])} <= set(
            chains.CAPABILITIES
        )

    def test_a_probe_finding_carries_the_probe_invariant(self) -> None:
        candidate = from_probe(
            {"probe": "sqli", "class": "injection", "vulnerable": True, "details": {}},
            "acme",
            f"{BASE}/search?q=1",
            "q",
        )
        assert candidate is not None
        assert candidate["invariant"] == chains.PROBE_INVARIANTS["sqli"]
        assert candidate["entry_point"] == f"GET {BASE}/search?q=1"

    def test_a_recipe_finding_uses_its_own_invariant_or_the_class(self) -> None:
        recipe = {
            "name": "order-read",
            "class": "access_control",
            "endpoint": f"{BASE}/api/orders/{{id}}",
            "steps": [{"id": "a", "method": "POST", "url": f"{BASE}/api/orders"}],
        }
        found = from_recipe({"vulnerable": True}, "acme", recipe)
        assert found is not None
        assert found["invariant"] == chains.CLASS_INVARIANTS["access_control"]
        assert found["entry_point"] == f"POST {BASE}/api/orders"
        own = from_recipe(
            {"vulnerable": True}, "acme", {**recipe, "invariant": "orders are private"}
        )
        assert own is not None and own["invariant"] == "orders are private"

    def test_a_recipe_may_declare_its_invariant(self) -> None:
        order = f"{BASE}/api/orders/1"
        raw = {
            "name": "order-read",
            "class": "access_control",
            "title": "Another account reads an order",
            "endpoint": order,
            "remediation": "Return an order only to the account that owns it.",
            "invariant": "a user can read only their own orders",
            "steps": [
                {"id": "owner", "method": "GET", "url": order, "identity": "alice"},
                {"id": "other", "method": "GET", "url": order, "identity": "bob"},
            ],
            "verdict": {
                "vulnerable_if": [{"step": "other", "status": 200}],
                "control": [{"step": "owner", "status": 200}],
            },
        }
        assert recipes.validate(raw).data["invariant"] == "a user can read only their own orders"
        assert "invariant" not in recipes.validate({**raw, "invariant": None}).data


class TestContext:
    @pytest.mark.parametrize(
        ("invariant", "entry_point", "fields"),
        [
            ("", "", ["invariant", "entry_point"]),
            ("n/a", "GET /x", ["invariant"]),
            ("short", "GET /x", ["invariant"]),
            ("a user can read only their own basket", "basket", ["entry_point"]),
            ("a user can read only their own basket", "GET /rest/basket/1", []),
        ],
    )
    def test_light_validation(self, invariant, entry_point, fields) -> None:
        assert [e["field"] for e in context_errors(invariant, entry_point)] == fields

    def test_agent_claims_of_some_classes_must_name_them(self, tmp_path: Path) -> None:
        store = FindingStore(tmp_path / "f.sqlite3")
        service = FindingService(store, gateway=None)
        claim = {
            "title": "basket of another user",
            "class": "access_control",
            "severity": "high",
            "endpoint": f"{BASE}/rest/basket/2",
            "source": "agent:hunter",
        }
        refused = service.submit("acme", claim, "hunter", require_context=True)
        assert refused["code"] == "INVALID_FINDING"
        assert {e["field"] for e in refused["errors"]} == {"invariant", "entry_point"}
        # Code paths (probes, scanners) are not held to it, and other classes are free.
        assert service.submit("acme", claim, "probe:x")["ok"]
        xss = {**claim, "class": "xss", "endpoint": f"{BASE}/hello"}
        assert service.submit("acme", xss, "hunter", require_context=True)["ok"]
        # Once the stored finding has them, a later submission need not repeat them.
        named = {
            **claim,
            "invariant": "a user can only read their own basket",
            "entry_point": f"GET {BASE}/rest/basket/2",
        }
        assert service.submit("acme", named, "hunter", require_context=True)["ok"]
        again = service.submit("acme", claim, "hunter", require_context=True)
        assert again["ok"]
        assert again["finding"]["invariant"] == "a user can only read their own basket"
        store.close()

    def test_enqueue_fills_a_probe_invariant(self, tmp_path: Path) -> None:
        store = FindingStore(tmp_path / "f.sqlite3")
        service = FindingService(store, gateway=None)
        item = {
            "engagement": "acme",
            "title": "matrix",
            "class": "access_control",
            "severity": "high",
            "endpoint": f"{BASE}/api/orders/1",
            "source": "probe:authz_matrix",
        }
        assert enqueue(service, [item], "probe:authz_matrix")["ok"]
        stored = store.list("acme")[0]
        assert stored.invariant == chains.PROBE_INVARIANTS["authz_matrix"]
        assert stored.entry_point == f"GET {BASE}/api/orders/1"  # the request as sent
        store.close()


class TestChains:
    def test_a_finding_that_gives_what_another_needs_is_a_chain_to_test(self) -> None:
        jwt = _finding("F-jwt", "probe:jwt_alg_none", "auth_session")
        idor = _finding(
            "F-idor",
            "probe:idor",
            "access_control",
            assertions=[{"capture_id": "c", "identity": "alice", "expect": {}}],
        )
        info = _finding("F-info", "agent:x", "info_exposure", severity="low")
        out = chains.chains([jwt, idor, info])
        pairs = {(c["from"], c["to"], c["capability"]) for c in out["chains"]}
        assert ("F-jwt", "F-idor", "user_session") in pairs  # via another user's session
        assert ("F-info", "F-idor", "user_identifiers") in pairs
        assert all(c["proven"] is False for c in out["chains"])
        nodes = {n["id"]: n for n in out["nodes"]}
        assert nodes["F-jwt"]["gives"] == ["other_user_session", "admin_role"]
        assert set(nodes["F-idor"]["needs"]) == {"user_session", "user_identifiers"}
        assert out["open_needs"] == []

    def test_only_proven_findings_take_part_and_open_needs_are_listed(self) -> None:
        idor = _finding("F-idor", "probe:idor", "access_control")
        unproven = _finding("F-info", "agent:x", "info_exposure", status="candidate")
        discarded = _finding("F-gql", "probe:graphql_checks", "graphql", grade="discard")
        out = chains.chains([idor, unproven, discarded])
        assert out["chains"] == []
        assert [n["id"] for n in out["nodes"]] == ["F-idor"]
        assert out["open_needs"][0]["capability"] == "user_identifiers"
        assert "info_exposure" in out["open_needs"][0]["classes_that_give_it"]

    def test_an_admin_account_proof_needs_the_admin_role(self) -> None:
        finding = _finding(
            "F-a",
            "agent:x",
            "business_logic",
            assertions=[{"capture_id": "c", "identity": "root", "expect": {}}],
        )
        assert chains.edges(finding, {"root": "admin"})["needs"] == ["user_session", "admin_role"]
        mass = _finding("F-m", "probe:mass_assignment", "business_logic")
        out = chains.chains([finding, mass], roles={"root": "admin"})
        assert {(c["from"], c["capability"]) for c in out["chains"]} == {
            ("F-m", "admin_role"),
            ("F-m", "user_session"),  # the admin role implies a logged-in user
        }

    def test_the_report_lists_chains_as_leads(self) -> None:
        jwt = _finding("F-jwt", "probe:jwt_alg_none", "auth_session")
        idor = _finding("F-idor", "probe:idor", "access_control", invariant="own orders only")
        found = chains.chains([jwt, idor])
        report = build(
            "acme",
            [jwt, idor],
            recon_summary=None,
            scope=[],
            captures=lambda _c: None,
            generated_at=0,
            chains=found,
            due=[
                {
                    "id": "L-3",
                    "kind": "held",
                    "technique": "finding",
                    "endpoint": f"{BASE}/x",
                    "parameter": "",
                    "finding_id": "F-x",
                    "reason": "graded_hold",
                    "code": "rule 7",
                    "why": "low impact",
                    "review_at": 86400,
                }
            ],
        )
        assert report["chains"] and report["chains"][0]["proven"] is False
        markdown = to_markdown(report)
        assert "## Possible chains (leads to test, not proven)" in markdown
        assert "## Due for review" in markdown and "graded\\_hold rule 7" in markdown
        assert "Invariant broken" in markdown
        page = to_html(report)
        assert "Possible chains" in page and "Due for review" in page
        bare = build(
            "acme", [], recon_summary=None, scope=[], captures=lambda _c: None, generated_at=0
        )
        assert bare["chains"] == [] and bare["due_for_review"] == []
        assert "Possible chains" not in to_markdown(bare)
