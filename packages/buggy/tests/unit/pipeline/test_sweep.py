"""The probe sweep plan: fixed rules, read-only, bounded."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

import pytest

from buggy.capture.probes import REGISTRY
from buggy.pipeline import sweep


def parameter(url: str, name: str, *, hints=(), example="", location="query", method="GET"):
    return {
        "type": "parameter",
        "value": f"{method} {url} {location}:{name}",
        "attrs": {
            "name": name,
            "location": location,
            "method": method,
            "url": url,
            "example": example,
            "hints": list(hints),
        },
    }


def steps(records: dict, **kwargs) -> list[dict]:
    return sweep.plan(records, **kwargs)["steps"]


def probes_on(plan: list[dict], name: str) -> list[str]:
    return sorted(s["probe"] for s in plan if s["params"].get("parameter") == name)


class TestWhichProbe:
    @pytest.mark.parametrize(
        ("hints", "expected"),
        [
            ([], ("sqli", "xss_reflected", "ssti")),
            (["id-like"], ("sqli",)),
            (["numeric"], ("sqli",)),
            (["file-like"], ("path_traversal", "rfi")),
            (["url-like"], ("open_redirect", "rfi")),
            (
                ["file-like", "url-like", "numeric"],
                ("path_traversal", "open_redirect", "rfi", "sqli"),
            ),
            (["auth-like"], ()),
            (["auth-like", "id-like"], ()),
        ],
    )
    def test_by_hint(self, hints: list[str], expected: tuple[str, ...]) -> None:
        assert sweep.probes_for(hints) == expected

    def test_every_planned_probe_is_registered_and_read_only(self) -> None:
        for name in sweep.PRIORITY:
            assert name in REGISTRY and REGISTRY[name].state_changing is False


class TestParameters:
    def test_a_text_parameter_gets_the_three_text_probes(self) -> None:
        plan = steps({"parameter": [parameter("https://a.test/search", "q", example="shoes")]})
        assert probes_on(plan, "q") == ["sqli", "ssti", "xss_reflected"]
        for step in plan:
            assert step["params"] == {
                "url": "https://a.test/search?q=shoes",
                "parameter": "q",
                "method": "GET",
                "location": "query",
            }

    def test_only_get_query_parameters_are_planned(self) -> None:
        url = "https://a.test/items"
        records = {
            "parameter": [
                parameter(url, "body_field", location="body", method="POST"),
                parameter(url, "posted", method="POST"),
                parameter(url, "id", location="path", hints=["id-like"]),
                parameter(url, "X-Trace", location="header"),
                parameter(url, "sid", location="cookie"),
            ]
        }
        assert steps(records) == []

    def test_a_credential_is_never_probed_or_sent_as_a_sibling(self) -> None:
        url = "https://a.test/report"
        records = {
            "parameter": [
                parameter(url, "token", hints=["auth-like"], example="<redacted>"),
                parameter(url, "signature", example="<redacted>"),
                parameter(url, "page", hints=["file-like"], example="home.html"),
            ]
        }
        plan = steps(records)
        assert sorted(s["probe"] for s in plan) == ["path_traversal", "rfi"]
        for step in plan:
            query = dict(parse_qsl(urlsplit(step["params"]["url"]).query))
            assert query == {"page": "home.html"}

    def test_siblings_keep_their_known_values(self) -> None:
        url = "https://a.test/list"
        records = {
            "parameter": [
                parameter(url, "id", hints=["id-like", "numeric"], example="7"),
                parameter(url, "lang", example="en"),
            ]
        }
        (step,) = [s for s in steps(records) if s["params"]["parameter"] == "id"]
        assert step["probe"] == "sqli"
        assert parse_qsl(urlsplit(step["params"]["url"]).query) == [("id", "7"), ("lang", "en")]

    def test_a_parameter_seen_without_a_value_gets_a_baseline(self) -> None:
        records = {
            "parameter": [
                parameter("https://a.test/a", "file", hints=["file-like"]),
                parameter("https://a.test/b", "next", hints=["url-like"]),
                parameter("https://a.test/c", "id", hints=["id-like"]),
            ]
        }
        urls = sorted((s["probe"], s["params"]["url"]) for s in steps(records))
        assert urls == [
            ("open_redirect", "https://a.test/b?next=%2F"),
            ("path_traversal", "https://a.test/a?file=index.html"),
            ("rfi", "https://a.test/a?file=index.html"),
            ("rfi", "https://a.test/b?next=index.html"),
            ("sqli", "https://a.test/c?id=1"),
        ]

    def test_one_name_is_probed_on_two_urls_of_a_host_at_most(self) -> None:
        records = {
            "parameter": [
                parameter(f"https://a.test/p{n}", "id", hints=["id-like"], example="1")
                for n in range(6)
            ]
            + [parameter("https://b.test/p", "id", hints=["id-like"], example="1")]
        }
        plan = steps(records)
        hosts = [s["host"] for s in plan]
        assert hosts.count("a.test") == sweep.MAX_URLS_PER_NAME and hosts.count("b.test") == 1

    def test_malformed_records_are_ignored(self) -> None:
        records = {
            "parameter": [
                {"type": "parameter"},
                {"attrs": "nope"},
                parameter("ftp://a.test/x", "q"),
                parameter("https://a.test/x?already=1", "q"),
                parameter("https://a.test/x", ""),
            ]
        }
        assert steps(records) == []


class TestEndpoints:
    def test_services_get_cors_and_graphql_gets_its_checks(self) -> None:
        records = {
            "http_service": [{"value": "https://a.test"}, {"value": "https://a.test"}],
            "graphql": [
                {"value": "https://a.test/graphql", "attrs": {"url": "https://a.test/graphql"}}
            ],
        }
        plan = steps(records)
        assert [(s["probe"], s["params"]) for s in plan] == [
            ("graphql_checks", {"url": "https://a.test/graphql"}),
            ("cors", {"url": "https://a.test"}),
        ]

    def test_caps(self) -> None:
        records = {
            "http_service": [{"value": f"https://s{n}.test"} for n in range(30)],
            "graphql": [{"value": f"https://g{n}.test/graphql"} for n in range(30)],
        }
        plan = steps(records, budget=sweep.MAX_BUDGET)
        names = [s["probe"] for s in plan]
        assert names.count("cors") == sweep.MAX_SERVICES
        assert names.count("graphql_checks") == sweep.MAX_GRAPHQL


class TestBudget:
    def records(self) -> dict:
        return {
            "parameter": [
                parameter(f"https://{host}/p", name, example="x")
                for host in ("a.test", "b.test")
                for name in ("q", "r", "s")
            ]
        }

    def test_budget_bounds_the_plan_and_reports_the_rest(self) -> None:
        full = sweep.plan(self.records(), budget=sweep.MAX_BUDGET)
        assert full["considered"] == len(full["steps"]) == 18 and full["left_out"] == 0
        small = sweep.plan(self.records(), budget=4)
        assert len(small["steps"]) == 4 and small["left_out"] == 14 and small["considered"] == 18

    def test_a_small_budget_still_touches_every_host_first(self) -> None:
        plan = steps(self.records(), budget=2)
        assert {s["host"] for s in plan} == {"a.test", "b.test"}
        # The most valuable probe goes first on each.
        assert {s["probe"] for s in plan} == {"sqli"}

    def test_zero_and_nonsense_budgets(self) -> None:
        assert steps(self.records(), budget=0) == []
        assert steps(self.records(), budget=-5) == []
        assert len(steps(self.records(), budget=10**9)) == 18

    def test_the_plan_is_deterministic(self) -> None:
        records = self.records()
        again = {"parameter": list(reversed(records["parameter"]))}
        assert steps(records) == steps(again)


class TestFraming:
    def test_account_admin_and_form_pages_get_one_clickjacking_run(self) -> None:
        records = {
            "auth_surface": [
                {"value": "https://a.test/account/settings", "attrs": {"kind": "account"}},
                {"value": "https://a.test/admin", "attrs": {"kind": "admin"}},
                {"value": "https://a.test/logout", "attrs": {"kind": "logout"}},
                {"value": "https://a.test/login", "attrs": {"kind": "login"}},
            ],
            "url": [
                {
                    "value": "https://a.test/profile",
                    "attrs": {"form": [{"action": "/profile/save", "method": "POST"}]},
                },
                {"value": "https://a.test/search", "attrs": {"form": [{"method": "GET"}]}},
            ],
            "parameter": [
                parameter("https://a.test/comments", "text", location="form", method="POST"),
                parameter("https://a.test/admin", "name", location="form", method="POST"),
            ],
        }
        framed = [s for s in steps(records) if s["probe"] == "clickjacking"]
        assert [s["params"] for s in framed] == [
            {"url": "https://a.test/account/settings"},
            {"url": "https://a.test/admin"},
            {"url": "https://a.test/comments"},
            {"url": "https://a.test/profile"},
        ]
        assert framed[0]["why"] == "account page"

    def test_pages_are_capped(self) -> None:
        records = {
            "auth_surface": [
                {"value": f"https://a.test/account/{n}", "attrs": {"kind": "account"}}
                for n in range(30)
            ]
        }
        framed = steps(records, budget=sweep.MAX_BUDGET)
        assert len(framed) == sweep.MAX_FRAME_PAGES


class TestTestingOrder:
    def test_probes_run_in_the_owners_order(self) -> None:
        assert sweep.PROBE_ORDER == (
            "idor", "sqli", "xss_reflected", "xss_stored", "xss_blind", "command_injection",
            "ssti", "path_traversal", "rfi", "clickjacking", "csrf", "ssrf_canary",
            "open_redirect", "numeric_boundary", "mass_assignment", "graphql_checks", "cors",
            "jwt_alg_none",
        )  # fmt: skip
        assert set(sweep.PROBE_ORDER) == set(REGISTRY)
        shuffled = [{"probe": name, "n": n} for n, name in enumerate(reversed(sweep.PROBE_ORDER))]
        shuffled.append({"probe": "sqli", "n": 99})
        ordered = sweep.by_class(shuffled)
        assert [s["probe"] for s in ordered][:3] == ["idor", "sqli", "sqli"]
        assert [s["n"] for s in ordered if s["probe"] == "sqli"] == [16, 99]  # order kept
        assert [s["probe"] for s in ordered][-1] == "jwt_alg_none"

    def test_classes_follow_the_probe_order_and_access_control_is_first(self) -> None:
        assert sweep.CLASS_ORDER[:7] == (
            "access_control", "injection", "xss", "file_handling", "misconfiguration", "csrf",
            "ssrf",
        )  # fmt: skip
        assert "csrf" not in sweep.NO_AUTOMATIC_CHECK
        unknown = sweep.by_class([{"probe": "later"}, {"probe": "idor"}])
        assert [s["probe"] for s in unknown] == ["idor", "later"]
