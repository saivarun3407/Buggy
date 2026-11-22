"""Planning the probe runs that can change state: fixed rules, nothing sent."""

from __future__ import annotations

import pytest

from buggy.capture.probes import REGISTRY
from buggy.capture.probes.registry import needs_run_approval
from buggy.pipeline import sweep

ORDERS = "https://shop.test/api/orders"


def field(name: str, *, url: str = ORDERS, method: str = "POST", hints=(), example=""):
    return {
        "type": "parameter",
        "attrs": {
            "name": name,
            "location": "body",
            "method": method,
            "url": url,
            "example": example,
            "hints": list(hints),
        },
    }


def steps(*records, **kwargs) -> list[dict]:
    return sweep.plan_state_changing({"parameter": list(records)}, **kwargs)["steps"]


def by_probe(plan: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for step in plan:
        out.setdefault(step["probe"], []).append(step)
    return out


def test_every_planned_run_is_one_the_gateway_holds_for_approval() -> None:
    plan = steps(
        field("quantity"), field("note"), field("host"), field("productId", hints=["id-like"])
    )
    assert plan
    for step in plan:
        spec = REGISTRY[step["probe"]]
        assert needs_run_approval(spec, step["params"]), step["probe"]


def test_a_business_quantity_gets_the_boundary_check_with_a_valid_body() -> None:
    plan = by_probe(steps(field("quantity"), field("productId", hints=["id-like"], example="7")))
    (run,) = plan["numeric_boundary"]
    assert run["params"] == {
        "url": ORDERS,
        "method": "POST",
        "body": {"productId": 7, "quantity": 1},
        "field": "quantity",
        "values": [-1, 0],
    }


def test_each_write_operation_gets_one_privileged_field_check() -> None:
    plan = by_probe(
        steps(
            field("name"),
            field("email"),
            field("name", url="https://shop.test/api/users", method="PUT"),
        )
    )
    runs = plan["mass_assignment"]
    assert sorted((r["params"]["method"], r["params"]["url"]) for r in runs) == [
        ("POST", ORDERS),
        ("PUT", "https://shop.test/api/users"),
    ]
    assert runs[0]["params"]["extra_fields"] == {"role": "admin", "isAdmin": True, "admin": True}


@pytest.mark.parametrize(
    ("name", "hints", "expected"),
    [
        ("comment", [], {"sqli", "ssti", "xss_reflected", "xss_stored"}),
        ("userId", ["id-like"], {"sqli"}),
        ("hostname", [], {"command_injection", "sqli"}),
        ("unitPrice", [], {"numeric_boundary"}),
        ("discount_amount", [], {"numeric_boundary"}),
    ],
)
def test_which_probe_a_field_gets(name: str, hints: list[str], expected: set[str]) -> None:
    plan = steps(field(name, hints=hints), budget=sweep.MAX_BUDGET)
    assert {s["probe"] for s in plan} - {"mass_assignment", "xss_blind"} == expected


def test_a_credential_is_never_probed_or_sent() -> None:
    plan = steps(
        field("password", hints=["auth-like"], example="<redacted>"),
        field("apiToken", example="<redacted>"),
        field("comment"),
        budget=sweep.MAX_BUDGET,
    )
    for step in plan:
        assert step["params"]["body"] == {"comment": "test"}
        assert step["params"].get("parameter") in (None, "comment")


def test_list_items_are_in_the_body_but_not_probed_field_by_field() -> None:
    plan = steps(
        field("orderLines[].quantity"),
        field("orderLines[].productId", hints=["id-like"]),
        field("cid"),
        budget=sweep.MAX_BUDGET,
    )
    body = plan[0]["params"]["body"]
    assert body == {"cid": "test", "orderLines": [{"productId": 1, "quantity": 1}]}
    assert {s["params"].get("parameter") or s["params"].get("field") for s in plan} == {None, "cid"}


def test_only_write_methods_and_body_fields_are_planned() -> None:
    get = field("q", method="GET")
    query = {"attrs": {"name": "q", "location": "query", "method": "POST", "url": ORDERS}}
    assert steps(get, query, {"attrs": "nope"}, {"type": "parameter"}) == []


def test_the_declared_account_is_put_on_every_run() -> None:
    plan = steps(field("quantity"), field("note"), identity="alice", budget=sweep.MAX_BUDGET)
    assert plan and all(step["params"]["identity"] == "alice" for step in plan)
    assert all("identity" not in s["params"] for s in steps(field("note")))


def test_budget_order_and_determinism() -> None:
    records = [
        field(name, url=f"https://{host}/api/x")
        for host in ("a.test", "b.test")
        for name in ("quantity", "note", "host")
    ]
    full = sweep.plan_state_changing({"parameter": records}, budget=sweep.MAX_BUDGET)
    assert full["left_out"] == 0 and full["considered"] == len(full["steps"])
    small = sweep.plan_state_changing({"parameter": records}, budget=2)
    assert len(small["steps"]) == 2 and small["left_out"] == full["considered"] - 2
    # The business-logic check goes first, and both hosts are touched before either twice.
    assert [s["probe"] for s in small["steps"]] == ["numeric_boundary", "numeric_boundary"]
    assert {s["host"] for s in small["steps"]} == {"a.test", "b.test"}
    again = sweep.plan_state_changing(
        {"parameter": list(reversed(records))}, budget=sweep.MAX_BUDGET
    )
    assert again["steps"] == full["steps"]
    assert sweep.plan_state_changing({"parameter": records}, budget=0)["steps"] == []


def test_a_posting_form_is_probed_as_a_form() -> None:
    def form_field(name: str, example: str = "") -> dict:
        return {
            "attrs": {
                "name": name,
                "location": "form",
                "method": "POST",
                "url": "https://app.test/ping",
                "example": example,
                "hints": [],
            }
        }

    plan = steps(form_field("ip"), form_field("Submit", "Submit"), budget=sweep.MAX_BUDGET)
    probes = {(s["probe"], s["params"].get("parameter")) for s in plan}
    assert ("command_injection", "ip") in probes and ("sqli", "ip") in probes
    # JSON-only checks are not planned for a form, and the form is sent as the page gave it.
    assert not {"mass_assignment", "numeric_boundary"} & {s["probe"] for s in plan}
    for step in plan:
        assert step["params"]["location"] == "form"
        assert step["params"]["body"] == {"Submit": "Submit", "ip": "localhost"}


def test_text_fields_get_stored_xss_and_one_blind_run_per_operation() -> None:
    plan = by_probe(
        steps(
            field("title"),
            field("comment"),
            field("quantity"),
            field("userId", hints=["id-like"]),
            budget=sweep.MAX_BUDGET,
        )
    )
    assert sorted(s["params"]["parameter"] for s in plan["xss_stored"]) == ["comment", "title"]
    (blind,) = plan["xss_blind"]
    assert blind["params"]["parameters"] == ["comment", "title"]
    assert blind["params"]["location"] == "json" and "parameter" not in blind["params"]
    assert "csrf" not in plan  # no signed-in account: nothing to forge


def test_a_signed_in_operation_gets_one_csrf_run() -> None:
    plan = by_probe(steps(field("note"), field("title"), identity="alice"))
    (run,) = plan["csrf"]
    assert run["params"] == {
        "url": ORDERS,
        "method": "POST",
        "body": {"note": "test", "title": "test"},
        "location": "json",
        "identity": "alice",
    }


def test_a_state_changing_get_form_is_planned_as_a_query() -> None:
    form = {
        "attrs": {
            "name": "newPassword",
            "location": "form",
            "method": "GET",
            "url": "https://app.test/change",
            "example": "",
            "hints": [],
        }
    }
    plan = by_probe(steps(form, identity="alice", budget=sweep.MAX_BUDGET))
    (run,) = plan["csrf"]
    assert run["params"]["location"] == "query" and run["params"]["state_changing"] is True
    assert run["params"]["url"] == "https://app.test/change?newPassword=test"
    assert plan["xss_blind"][0]["params"]["location"] == "query"


def test_new_state_runs_are_held_and_ordered_by_value() -> None:
    plan = steps(field("note"), identity="alice", budget=sweep.MAX_BUDGET)
    for step in plan:
        assert needs_run_approval(REGISTRY[step["probe"]], step["params"])
    assert set(sweep.STATE_PRIORITY) >= {"xss_stored", "xss_blind", "csrf"}
