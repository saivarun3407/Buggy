"""What a crawl, and the checks planned from it, must never do by themselves."""

from __future__ import annotations

import pytest

from buggy.capture.crawl import (
    form_changes_state,
    form_destructive_reason,
    never_request_reason,
)
from buggy.capture.probes import REGISTRY
from buggy.capture.probes.registry import DECLARED_FLAG, needs_run_approval
from buggy.cli import hunt
from buggy.pipeline import sweep

APP = "https://app.test"


def form(action: str, *fields: tuple[str, str], method: str = "GET") -> dict:
    return {
        "page": f"{APP}/page",
        "method": method,
        "action": f"{APP}{action}",
        "fields": [{"name": name, "value": value} for name, value in fields],
    }


@pytest.mark.parametrize(
    "url",
    [
        f"{APP}/security.php?phpids=on",
        f"{APP}/settings?waf=off",
        f"{APP}/feature?beta=enabled",
        f"{APP}/plugins/enable/3",
        f"{APP}/account?toggle=2fa",
        f"{APP}/logout",
        f"{APP}/items/5/delete",
    ],
)
def test_a_link_that_flips_a_switch_or_ends_the_session_is_never_requested(url: str) -> None:
    assert never_request_reason(url)


@pytest.mark.parametrize(
    "url",
    [f"{APP}/search?q=on+sale", f"{APP}/products?sort=price", f"{APP}/docs?page=2", f"{APP}/"],
)
def test_ordinary_links_are_followed(url: str) -> None:
    assert never_request_reason(url) == ""


class TestForms:
    def test_a_lookup_form_is_read_only(self) -> None:
        lookup = form("/vulnerabilities/sqli/", ("id", ""), ("Submit", "Submit"))
        assert form_changes_state(lookup) == "" and form_destructive_reason(lookup) == ""

    @pytest.mark.parametrize(
        "action_form",
        [
            form("/csrf/", ("password_new", ""), ("password_conf", ""), ("Change", "Change")),
            form("/profile", ("displayName", "al"), ("save", "Save")),
            form("/login", ("username", ""), ("password", "")),
            form("/cart", ("productId", "3"), ("add", "Add to basket")),
            form("/account/updateEmail", ("email", "")),
        ],
    )
    def test_a_get_form_that_acts_is_not_read_only(self, action_form: dict) -> None:
        assert form_changes_state(action_form)

    @pytest.mark.parametrize(
        "destructive",
        [
            form("/setup.php", ("create_db", "Create / Reset Database"), method="POST"),
            form("/admin/users", ("id", "4"), ("action", "delete"), method="POST"),
            form("/account", ("confirm", "Remove my account"), method="POST"),
            form("/maintenance/reset", ("ok", "OK"), method="POST"),
        ],
    )
    def test_a_destructive_form_is_named(self, destructive: dict) -> None:
        assert form_destructive_reason(destructive)


class TestCrawlRecords:
    def crawl(self) -> dict:
        return {
            "urls": [f"{APP}/search?q=x", f"{APP}/logout", f"{APP}/security.php?phpids=on"],
            "forms": [
                form("/lookup", ("id", ""), ("Submit", "Submit")),
                form("/csrf/", ("password_new", ""), ("Change", "Change")),
                form("/ping", ("ip", ""), method="POST"),
                form("/setup.php", ("create_db", "Create / Reset Database"), method="POST"),
            ],
        }

    def test_what_is_handed_on(self) -> None:
        records, dropped = hunt.crawl_records(self.crawl())
        values = [r["value"] for r in records if "attrs" not in r]
        # Links the crawler may not request are not handed to probes either.
        assert values == [f"{APP}/search?q=x", f"{APP}/lookup?id=&Submit=Submit"]
        kept = [r["attrs"]["form"][0] for r in records if "attrs" in r]
        assert [(f["method"], f["action"]) for f in kept] == [
            ("GET", f"{APP}/csrf/"),
            ("POST", f"{APP}/ping"),
        ]
        assert dropped == 1

    def test_the_read_only_sweep_never_touches_an_action_form(self) -> None:
        records, _dropped = hunt.crawl_records(self.crawl())
        fresh = hunt._new_parameters(records, set())  # noqa: SLF001
        read_only = sweep.plan({"parameter": fresh}, budget=sweep.MAX_BUDGET)["steps"]
        urls = {step["params"]["url"].partition("?")[0] for step in read_only}
        assert urls == {f"{APP}/search", f"{APP}/lookup"}

    def test_an_action_form_sent_with_get_is_planned_as_a_run_that_needs_approval(self) -> None:
        records, _dropped = hunt.crawl_records(self.crawl())
        fresh = hunt._new_parameters(records, set())  # noqa: SLF001
        writes = sweep.plan_state_changing({"parameter": fresh}, budget=sweep.MAX_BUDGET)["steps"]
        gets = [s for s in writes if s["params"]["method"] == "GET"]
        assert gets and all(s["params"]["url"].startswith(f"{APP}/csrf/?") for s in gets)
        for step in writes:
            assert needs_run_approval(REGISTRY[step["probe"]], step["params"]), step
        for step in gets:
            assert step["params"][DECLARED_FLAG] is True and "body" not in step["params"]
            assert step["params"]["location"] == "query"
        assert not any("setup.php" in s["params"]["url"] for s in writes)


def test_the_declaration_can_only_add_the_hold() -> None:
    spec = REGISTRY["xss_reflected"]
    get = {"url": f"{APP}/x?q=1", "parameter": "q"}
    assert needs_run_approval(spec, get) is False
    assert needs_run_approval(spec, {**get, DECLARED_FLAG: True}) is True
    assert needs_run_approval(spec, {**get, DECLARED_FLAG: False}) is False
    # A POST stays held whatever the caller declares.
    assert needs_run_approval(spec, {**get, "method": "POST", DECLARED_FLAG: False}) is True
