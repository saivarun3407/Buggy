"""hunt tests behind the login as the declared accounts, by code."""

from __future__ import annotations

import argparse
import json

from buggy.cli import hunt

APP = "https://app.test"
RECORDS = {
    "http_service": [{"value": APP}],
    "parameter": [{"value": f"GET {APP}/search query:q", "attrs": {}}],
}
CRAWLS = {
    "alice": {
        "identity": "alice",
        "requested": 14,
        "truncated": False,
        "urls": [
            f"{APP}/account",
            f"{APP}/orders/1001",
            f"{APP}/search?q=x",
            f"{APP}/invoice?id=7",
        ],
        "forms": [
            {
                "page": f"{APP}/account",
                "method": "GET",
                "action": f"{APP}/lookup",
                "fields": [{"name": "host", "value": "example.org"}, {"name": "go", "value": "Go"}],
            },
            {
                "page": f"{APP}/account",
                "method": "POST",
                "action": f"{APP}/profile",
                "fields": [{"name": "nickname", "value": "al"}],
            },
        ],
    },
    "bob": {
        "identity": "bob",
        "requested": 9,
        "truncated": True,
        "urls": [f"{APP}/account", f"{APP}/orders/2002", f"{APP}/invoice?id=7"],
        "forms": [],
    },
}


class Server:
    def __init__(self, identities=("alice", "bob"), positive=(), owners=None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.identities = [{"name": name} for name in identities]
        self.positive = set(positive)
        self.owners = owners

    def __call__(self, tool: str, engagement: str, **a) -> dict:
        assert engagement == "acme"
        self.calls.append((tool, a))
        if tool == "identities_list":
            return {"ok": True, "identities": self.identities}
        if tool in ("surface_crawl", "user_walk"):
            return CRAWLS.get(a["identity"], {"error": "LOGIN_FAILED", "detail": "login failed"})
        if tool == "probe_run":
            params = json.loads(a["params_json"])
            if params.get("method", "GET") != "GET":
                return {"status": "refused", "code": "APPROVAL_REQUIRED", "request_id": "apr-1"}
            hit = (a["probe"], params.get("parameter")) in self.positive
            out = {"status": "completed", "vulnerable": hit}
            return {**out, "finding_id": f"F-{a['probe']}-{params['parameter']}"} if hit else out
        if tool == "owners_infer":
            reached = json.loads(a["reached_json"])
            assert set(reached) == {"alice", "bob"}
            owners = self.owners
            if owners is None:
                owners = {f"{APP}/orders/1001": "alice", f"{APP}/orders/2002": "bob"}
            return {"owners": owners, "identities_without_markers": ["bob"]}
        if tool == "authz_matrix_run":
            urls = json.loads(a["urls_json"])
            assert json.loads(a["inferred_json"]) == urls
            assert json.loads(a["owners_json"]) == {u: self.owners_of(u) for u in urls}
            verdicts = {f"GET {urls[0]}": {"verdict": "broken_access"}}
            verdicts.update({f"GET {u}": {"verdict": "inconclusive"} for u in urls[1:]})
            return {"verdicts": verdicts, "queue": {"ids": ["F-idor"]}}
        if tool == "finding_verify":
            return {"finding": {"status": "exploit_verified"}}
        if tool == "finding_grade":
            return {"grade": {"decision": "submit"}}
        raise AssertionError(tool)

    def owners_of(self, url: str) -> str:
        return "alice" if url.endswith("1001") else "bob"

    def probe_runs(self) -> list[tuple[str, dict]]:
        return [
            (a["probe"], json.loads(a["params_json"])) for t, a in self.calls if t == "probe_run"
        ]


def use(monkeypatch, server: Server) -> Server:
    monkeypatch.setattr(hunt, "_capture", server)
    return server


def test_each_account_is_crawled_and_only_new_inputs_are_probed_as_that_account(
    monkeypatch,
) -> None:
    server = use(monkeypatch, Server())
    out = hunt.run_signed_in("acme", RECORDS)
    crawls = [a for tool, a in server.calls if tool == "user_walk"]
    assert [c["identity"] for c in crawls] == ["alice", "bob"]
    assert json.loads(crawls[0]["seeds_json"]) == [APP]
    runs = server.probe_runs()
    assert runs and all(params["identity"] == "alice" for _probe, params in runs)
    probed = {
        (params["url"].partition("?")[0], params["parameter"])
        for _p, params in runs
        if "parameter" in params  # a page-level check (clickjacking) has no parameter
    }
    # Recon already knew ?q= on /search; bob's crawl added nothing alice's had not.
    assert (f"{APP}/search", "q") not in probed
    assert {(f"{APP}/invoice", "id"), (f"{APP}/lookup", "host"), (f"{APP}/lookup", "go")} <= probed
    assert out["ran"] is True and out["urls_reached"] == 7
    assert [a["name"] for a in out["accounts"]] == ["alice", "bob"]
    # Bob's own order URL carries an object id: one new input, a path segment, not probed.
    assert out["accounts"][1]["truncated"] is True and out["accounts"][1]["new_inputs"] == 1


def test_a_get_form_becomes_the_url_it_would_request(monkeypatch) -> None:
    server = use(monkeypatch, Server())
    hunt.run_signed_in("acme", RECORDS)
    lookups = [p for _probe, p in server.probe_runs() if p["url"].startswith(f"{APP}/lookup?")]
    assert lookups and all("host=example.org" in p["url"] and "go=Go" in p["url"] for p in lookups)


def test_a_posting_form_is_planned_as_a_run_that_waits_for_approval(monkeypatch) -> None:
    server = use(monkeypatch, Server())
    out = hunt.run_signed_in("acme", RECORDS)
    posts = [(probe, p) for probe, p in server.probe_runs() if p.get("method") == "POST"]
    assert posts and all(
        p["url"] == f"{APP}/profile" and p["location"] == "form" for _x, p in posts
    )
    assert all(p["identity"] == "alice" for _x, p in posts)
    assert out["state"]["held_for_approval"] == len(posts) and out["state"]["vulnerable"] == 0


def test_a_positive_signed_in_probe_is_proven_and_graded(monkeypatch) -> None:
    use(monkeypatch, Server(positive={("sqli", "id")}))
    out = hunt.run_signed_in("acme", RECORDS)
    assert (out["probes"]["vulnerable"], out["probes"]["verified"], out["probes"]["submit"]) == (
        1,
        1,
        1,
    )
    assert out["probes"]["findings"][0]["id"] == "F-sqli-id"


def test_objects_one_account_reached_are_asked_for_as_the_other(monkeypatch) -> None:
    server = use(monkeypatch, Server())
    out = hunt.run_signed_in("acme", RECORDS)
    inferred = out["inferred"]
    # Bob declared no markers, so his object could never be reported and is not asked for.
    assert inferred["objects"] == 1 and inferred["broken_access"] == 1
    assert inferred["inconclusive"] == 0 and inferred["verified"] == 1
    assert inferred["without_markers"] == ["bob"]
    (matrix,) = [a for tool, a in server.calls if tool == "authz_matrix_run"]
    assert json.loads(matrix["urls_json"]) == [f"{APP}/orders/1001"]
    assert "authz_matrix_run" in [tool for tool, _a in server.calls]


def test_one_account_is_crawled_but_nothing_is_compared(monkeypatch) -> None:
    server = use(monkeypatch, Server(identities=("alice",)))
    out = hunt.run_signed_in("acme", RECORDS)
    tools = [tool for tool, _a in server.calls]
    assert out["ran"] is True and "owners_infer" not in tools and "authz_matrix_run" not in tools


def test_nothing_is_sent_without_accounts_or_services(monkeypatch) -> None:
    server = use(monkeypatch, Server(identities=()))
    out = hunt.run_signed_in("acme", RECORDS)
    assert out["ran"] is False and "no test accounts are declared" in out["reason"]
    assert [tool for tool, _a in server.calls] == ["identities_list"]
    server = use(monkeypatch, Server())
    out = hunt.run_signed_in("acme", {"parameter": []})
    assert out["ran"] is False and "no live service" in out["reason"]


def test_an_account_that_cannot_sign_in_is_named_and_the_rest_continue(monkeypatch) -> None:
    use(monkeypatch, Server(identities=("mallory", "alice")))
    out = hunt.run_signed_in("acme", RECORDS)
    assert out["ran"] is True
    assert out["accounts"][0] == {"name": "mallory", "error": "login failed"}
    assert out["accounts"][1]["name"] == "alice"


def test_at_most_three_accounts_are_used(monkeypatch) -> None:
    server = use(monkeypatch, Server(identities=("alice", "bob", "alice", "bob", "alice")))
    hunt.run_signed_in("acme", RECORDS)
    assert len([1 for tool, _a in server.calls if tool == "user_walk"]) == hunt.MAX_ACCOUNTS


def test_the_stage_prints_what_it_did_and_the_result_has_counts_only(monkeypatch, capsys) -> None:
    use(monkeypatch, Server(positive={("sqli", "id")}))
    args = argparse.Namespace(
        no_probes=False, probe_budget=None, state_probe_budget=None, non_interactive=False
    )
    result = hunt._signed_in_stage(args, "acme", RECORDS)  # noqa: SLF001
    err = capsys.readouterr().err
    assert "signed-in        2 accounts crawled: 7 URLs reached" in err
    assert "waiting for your approval (buggy-cli approvals list acme)" in err
    assert "F-sqli-id  sqli  exploit_verified/submit" in err
    assert "no markers declared for: bob" in err
    section = hunt._signed_in_result(result)  # noqa: SLF001
    assert section["ran"] is True and section["probes"]["verified"] == 1
    assert "findings" not in section["inferred"] and "findings" not in section["probes"]
    assert hunt._signed_in_stage(argparse.Namespace(no_probes=True), "acme", RECORDS) is None  # noqa: SLF001


def test_the_walk_gets_the_api_from_recon_and_owned_objects_need_no_marker(monkeypatch) -> None:
    """A single-page app: API endpoints and templates go to the walk; what an account
    reached with its own id is compared by content, even for an account without markers."""
    basket = f"{APP}/rest/basket/7"
    records = {
        **RECORDS,
        "endpoint": [{"value": f"{APP}/api/Products"}, {"value": f"{APP}/rest/basket/{{id}}"}],
    }
    walks = {
        "alice": {**CRAWLS["alice"], "owned": [], "filled": []},
        "bob": {
            **CRAWLS["bob"],
            "urls": [*CRAWLS["bob"]["urls"], basket],
            "owned": [basket],
            "filled": [{"template": f"{APP}/rest/basket/{{id}}", "url": basket, "status": 200}],
        },
    }
    calls: list[tuple[str, dict]] = []

    def server(tool: str, _engagement: str, **a) -> dict:
        calls.append((tool, a))
        if tool == "identities_list":
            return {"ok": True, "identities": [{"name": "alice"}, {"name": "bob"}]}
        if tool == "user_walk":
            return walks[a["identity"]]
        if tool == "owners_infer":
            assert json.loads(a["owned_json"]) == {"alice": [], "bob": [basket]}
            owners = {f"{APP}/orders/2002": "bob", basket: "bob"}
            return {"owners": owners, "owned": {basket: "bob"},
                    "identities_without_markers": ["bob"]}  # fmt: skip
        if tool == "authz_matrix_run":
            return {"verdicts": {basket: {"verdict": "broken_access"}}, "queue": {"ids": []}}
        if tool == "probe_run":
            return {"status": "completed", "vulnerable": False}
        raise AssertionError(tool)

    monkeypatch.setattr(hunt, "_capture", server)
    out = hunt.run_signed_in("acme", records)
    first = next(a for tool, a in calls if tool == "user_walk")
    assert json.loads(first["seeds_json"]) == [APP, f"{APP}/api/Products"]
    assert json.loads(first["templates_json"]) == [f"{APP}/rest/basket/{{id}}"]
    assert out["api_endpoints"] == 1 and out["templates"] == 1
    (matrix,) = [a for tool, a in calls if tool == "authz_matrix_run"]
    # Bob has no markers: his inferred order is not asked for, his own basket is,
    # and it is not judged as an inferred object.
    assert json.loads(matrix["urls_json"]) == [basket]
    assert json.loads(matrix["inferred_json"]) == []
    assert out["inferred"]["owned"] == 1 and out["inferred"]["broken_access"] == 1
    assert out["accounts"][1]["owned"] == 1 and out["accounts"][1]["filled_answered"] == 1
