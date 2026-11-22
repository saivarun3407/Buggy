"""Checks the agent builds itself: recipes are data, run through the gateway."""

from __future__ import annotations

import base64
import copy
import email.message
import io
import json
import re
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from buggy.capture import recipes
from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.workbench import Workbench
from buggy.cli.approvals import paths_for, pending, record_decision
from buggy.findings import verifier

BASE = "https://shop.acme.test"
ORDERS = f"{BASE}/api/orders"
USERS = ("alice", "bob")
# Built at runtime and shaped like nothing a provider issues.
TOKENS = {name: f"session-of-{name}-" + "0123456789abcdef" for name in USERS}
SCOPE = {"machine_enforcement": {"mode": "enforce", "in_scope": ["shop.acme.test"]}}
NOT_REQUIRED = {**SCOPE, "approvals": {"state_changing": "not_required"}}
# A value the target hands out that must never come back to the agent through a result.
REFERENCE = "ref-" + "9f3c2a71e4b8d605"


class Shop:
    """Orders per account. ``broken`` lets any signed-in account read any order;
    ``open_to_all`` also lets a request without credentials read one."""

    def __init__(self) -> None:
        self.orders: dict[str, dict[str, Any]] = {}
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []
        self.broken = True
        self.open_to_all = False
        self.create_status = 201

    def _who(self, headers: dict[str, str]) -> str:
        value = headers.get("authorization", "")
        return next((name for name, token in TOKENS.items() if value == f"Bearer {token}"), "")

    def handle(self, method: str, url: str, headers: dict[str, str], body: bytes):
        who = self._who(headers)
        if method == "POST" and url == ORDERS:
            if not who:
                return 401, {"error": "login required"}, {}
            if self.create_status >= 300:
                return self.create_status, {"error": "out of stock"}, {}
            data = json.loads(body or b"{}")
            number = str(100 + len(self.orders))
            self.orders[number] = {
                "id": number,
                "owner": who,
                "item": data.get("item"),
                "total": 12.5,
                "reference": REFERENCE,
            }
            return (
                201,
                {"order": self.orders[number], "note": f"reference={REFERENCE};"},
                {"X-Order-Id": number},
            )
        match = re.fullmatch(re.escape(ORDERS) + r"/(\w+)", url)
        if method == "GET" and match:
            order = self.orders.get(match.group(1))
            if order is None:
                return 404, {"error": "no such order"}, {}
            if not who and not self.open_to_all:
                return 401, {"error": "login required"}, {}
            if who and who != order["owner"] and not self.broken:
                return 403, {"error": "not yours"}, {}
            return 200, order, {}
        if method == "GET" and url.startswith(f"{BASE}/echo"):
            return 200, {"url": url, "header": headers.get("x-echo", "")}, {}
        if method == "POST" and url == f"{BASE}/echo":
            return 200, {"body": body.decode()}, {}
        return 404, {"error": "not found"}, {}

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data or b""
        self.seen.append((method, url, headers, body))
        status, payload, extra = self.handle(method, url, headers, body)
        raw = json.dumps(payload).encode()
        response_headers = {"Content-Type": "application/json", **extra}
        if status >= 300:
            message = email.message.Message()
            for key, value in response_headers.items():
                message[key] = value
            raise urllib.error.HTTPError(url, status, "x", message, io.BytesIO(raw))
        return _Response(status, raw, response_headers)


class _Response:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.status = status
        self.headers = SimpleNamespace(items=lambda: list(headers.items()))
        self._body = io.BytesIO(body)

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def _make(tmp_path: Path, roe: dict) -> SimpleNamespace:
    roots = Roots(
        control=tmp_path / "control",
        audit=tmp_path / "audit",
        data=tmp_path / "data",
        secrets=tmp_path / "secrets",
    )
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(json.dumps(roe))
    folder = roots.secrets / "acme"
    folder.mkdir(parents=True)
    (folder / "identities.json").write_text(
        json.dumps(
            {
                "identities": [
                    {
                        "name": name,
                        "static": {"headers": {"Authorization": f"Bearer {TOKENS[name]}"}},
                    }
                    for name in USERS
                ]
            }
        )
    )
    shop = Shop()
    gateway = CaptureGateway(roots, opener=shop, sleep=lambda _s: None)
    bench = Workbench(gateway, None, lambda name: name)
    return SimpleNamespace(gateway=gateway, shop=shop, roots=roots, bench=bench)


@pytest.fixture
def env(tmp_path: Path):
    made = _make(tmp_path, NOT_REQUIRED)
    yield made
    made.bench.close()
    made.gateway.store.close()


@pytest.fixture
def held(tmp_path: Path):
    """An engagement where state-changing requests need the operator's approval."""
    made = _make(tmp_path, SCOPE)
    yield made
    made.bench.close()
    made.gateway.store.close()


def order_recipe(**changes: Any) -> dict[str, Any]:
    """Alice creates an order; bob reads it; alice and nobody are the controls."""
    recipe: dict[str, Any] = {
        "name": "order-read-by-other",
        "class": "access_control",
        "title": "Another account can read an order it does not own",
        "endpoint": f"{ORDERS}/{{id}}",
        "remediation": "Return an order only to the account that owns it; answer 403 otherwise.",
        "steps": [
            {
                "id": "create",
                "method": "POST",
                "url": ORDERS,
                "identity": "alice",
                "body": {"item": "book-{{rand}}"},
                "expect": {"status": [200, 201]},
                "extract": {"order": {"from": "json", "path": "order.id"}},
            },
            {"id": "owner", "method": "GET", "url": f"{ORDERS}/{{{{order}}}}", "identity": "alice"},
            {"id": "other", "method": "GET", "url": f"{ORDERS}/{{{{order}}}}", "identity": "bob"},
            {"id": "nobody", "method": "GET", "url": f"{ORDERS}/{{{{order}}}}", "identity": ""},
        ],
        "verdict": {
            "vulnerable_if": [
                {"step": "other", "status": 200},
                {"step": "other", "same_as": "owner"},
            ],
            "control": [
                {"step": "owner", "status": 200},
                {"step": "owner", "json": "owner", "equals": "alice"},
                {"step": "nobody", "status": [401, 403]},
            ],
        },
    }
    recipe.update(changes)
    return recipe


def read_only_recipe(**changes: Any) -> dict[str, Any]:
    """Bob reads an order alice already has (no step changes state)."""
    recipe = order_recipe(name="order-read-only")
    recipe["steps"] = copy.deepcopy(recipe["steps"][1:])
    for step in recipe["steps"]:
        step["url"] = f"{ORDERS}/100"
    recipe["endpoint"] = f"{ORDERS}/100"
    recipe.update(changes)
    return recipe


def seed_order(env) -> None:
    env.shop.orders["100"] = {"id": "100", "owner": "alice", "item": "lamp", "total": 3}


def decide(env, request_id: str, action: str = "allow") -> None:
    _requests, decisions = paths_for(env.roots.control, env.roots.audit, "acme")
    record_decision(decisions, request_id, action, operator="operator")


def error_of(recipe: Any) -> tuple[str, str]:
    with pytest.raises(recipes.RecipeError) as raised:
        recipes.validate(recipe)
    return raised.value.path, raised.value.message


def run(env, recipe: dict[str, Any]) -> dict[str, Any]:
    return env.bench.recipe_run("acme", json.dumps(recipe), "hunter:t1")


# ── validation ───────────────────────────────────────────────────────


class TestValidation:
    def test_a_good_recipe_validates_and_says_it_changes_state(self) -> None:
        recipe = recipes.validate(order_recipe())
        assert recipe.state_changing and len(recipe.steps) == 4
        assert recipes.check(json.dumps(order_recipe())) == {
            "ok": True,
            "state_changing": True,
            "steps": 4,
        }
        assert recipes.check(read_only_recipe())["state_changing"] is False

    @pytest.mark.parametrize(
        ("mutate", "path", "words"),
        [
            (lambda r: r.pop("name"), "name", "a-z"),
            (lambda r: r.update(name="Bad Name"), "name", "a-z"),
            (lambda r: r.update(**{"class": "rce"}), "class", "access_control"),
            (lambda r: r.update(remediation="fix it"), "remediation", "at least 30"),
            (lambda r: r.update(extra=1), "extra", "unknown key"),
            (lambda r: r.update(steps=[]), "steps", "1-12"),
            (lambda r: r.update(steps=r["steps"] * 4), "steps", "1-12"),
            (lambda r: r["steps"][1].update(method="TRACE"), "steps[1].method", "GET"),
            (lambda r: r["steps"][2].update(bogus=True), "steps[2].bogus", "unknown key"),
            (lambda r: r["steps"][1].update(id="create"), "steps[1].id", "used twice"),
            (
                lambda r: r["steps"][0]["extract"]["order"].update({"from": "cookie"}),
                "steps[0].extract.order.from",
                "json",
            ),
            (
                lambda r: r["steps"][0]["extract"].update(x={"from": "regex", "pattern": "(a"}),
                "steps[0].extract.x.pattern",
                "does not compile",
            ),
            (
                lambda r: r["steps"][0]["extract"].update(
                    x={"from": "regex", "pattern": "a" * 201}
                ),
                "steps[0].extract.x.pattern",
                "longer than 200",
            ),
            (
                lambda r: r["steps"][0]["extract"].update(rand={"from": "status"}),
                "steps[0].extract.rand",
                "built-in",
            ),
            (
                lambda r: r["steps"][0].update(url=f"{ORDERS}/{{{{order}}}}"),
                "steps[0].url",
                "unknown variable 'order'",
            ),
            (
                lambda r: r["steps"][1].update(url=f"{ORDERS}/{{{{order|rot13}}}}"),
                "steps[1].url",
                "unknown pipe 'rot13'",
            ),
            (
                lambda r: r["steps"][1].update(url="https://{{order}}.acme.test/api/orders"),
                "steps[1].url",
                "literal",
            ),
            (
                lambda r: r["steps"][1].update(url="https://shop.acme.test{{order}}/x"),
                "steps[1].url",
                "literal",
            ),
            (lambda r: r["steps"][1].update(url="/api/orders"), "steps[1].url", "absolute"),
            (
                lambda r: r["steps"][0].update(body="x" * (64 * 1024 + 1)),
                "steps[0].body",
                "larger than",
            ),
            (
                lambda r: r["steps"][0]["body"].update(note="{{nothing}}"),
                "steps[0].body.note",
                "unknown variable 'nothing'",
            ),
            (
                lambda r: r["steps"][1].update(headers={"X-A": "{{order|nope}}"}),
                "steps[1].headers.X-A",
                "unknown pipe",
            ),
            (lambda r: r["steps"][1].update(identity=7), "steps[1].identity", "test account"),
            (lambda r: r["steps"][0].update(expect={}), "steps[0].expect", "empty"),
            (
                lambda r: r["steps"][0].update(expect={"status": 999}),
                "steps[0].expect.status",
                "100-599",
            ),
            (
                lambda r: r["verdict"]["vulnerable_if"][0].update(step="ghost"),
                "verdict.vulnerable_if[0].step",
                "must name a step",
            ),
            (
                lambda r: r["verdict"]["vulnerable_if"][1].update(same_as="other"),
                "verdict.vulnerable_if[1].same_as",
                "another step",
            ),
            (
                lambda r: r["verdict"]["control"][1].update(gt=3),
                "verdict.control[1]",
                "exactly one of equals",
            ),
            (
                lambda r: r["verdict"]["control"].append({"step": "owner", "status": 200, "x": 1}),
                "verdict.control[3].x",
                "unknown key",
            ),
            (
                lambda r: r["verdict"]["control"].extend([{"step": "owner", "status": 200}] * 16),
                "verdict",
                "at most 20",
            ),
            (
                lambda r: r.update(endpoint="https://elsewhere.acme.test/x"),
                "endpoint",
                "host one of the steps",
            ),
            (lambda r: r.update(state_changing="yes"), "state_changing", "true or false"),
        ],
    )
    def test_errors_name_the_exact_path(self, mutate, path: str, words: str) -> None:
        recipe = order_recipe()
        mutate(recipe)
        got_path, message = error_of(recipe)
        assert got_path == path, message
        assert words in message

    def test_a_recipe_without_a_control_is_refused_with_the_reason(self) -> None:
        recipe = order_recipe()
        recipe["verdict"]["control"] = []
        path, message = error_of(recipe)
        assert path == "verdict.control"
        assert "normal, expected behaviour" in message and "the page answered" in message
        recipe["verdict"].pop("control")
        assert error_of(recipe)[0] == "verdict.control"

    def test_check_reports_errors_as_data(self) -> None:
        recipe = order_recipe()
        recipe["verdict"]["control"] = []
        out = recipes.check(json.dumps(recipe))
        assert out["ok"] is False and out["errors"][0]["path"] == "verdict.control"
        assert recipes.check("{not json")["errors"][0]["path"] == "recipe"

    def test_canonical_form_ignores_key_order(self) -> None:
        recipe = order_recipe()
        shuffled = dict(reversed(list(recipe.items())))
        assert recipes.validate(recipe).canonical == recipes.validate(shuffled).canonical


# ── templating and extraction ────────────────────────────────────────


class TestTemplating:
    def test_pipes(self) -> None:
        values = {"v": 'A b/c"d'}
        assert recipes.render("{{v|urlencode}}", values) == "A%20b%2Fc%22d"
        assert recipes.render("{{ v | b64 }}", values) == base64.b64encode(b'A b/c"d').decode()
        assert recipes.render("{{v|b64url}}", {"v": "??>"}) == "Pz8-"
        assert recipes.render('{"x": "{{v|json}}"}', values) == '{"x": "A b/c\\"d"}'
        assert recipes.render("{{v|lower}}-{{v|upper}}", {"v": "Ab"}) == "ab-AB"
        assert recipes.render("{{v|lower|urlencode}}", {"v": "A B"}) == "a%20b"
        with pytest.raises(recipes.RecipeError, match="unknown variable 'w'"):
            recipes.render("{{w}}", values)

    def test_rand_is_one_token_per_run_and_values_flow_into_later_steps(self, env) -> None:
        recipe = {
            "name": "echo",
            "class": "info_exposure",
            "title": "echo",
            "endpoint": f"{BASE}/echo",
            "remediation": "Nothing to change: this recipe only exercises the template engine.",
            "steps": [
                {
                    "id": "one",
                    "method": "POST",
                    "url": f"{BASE}/echo",
                    "body": {"a": "{{rand}}", "b": "x{{rand|upper}}", "t": "{{ts}}"},
                    "extract": {
                        "first": {"from": "json", "path": "body"},
                        "code": {"from": "status"},
                        "kind": {"from": "header", "name": "content-type"},
                        "tail": {"from": "regex", "pattern": r'\\"b\\": \\"x(\w+)'},
                    },
                },
                {
                    "id": "two",
                    "method": "GET",
                    "url": f"{BASE}/echo?r={{{{rand}}}}&c={{{{code}}}}&t={{{{tail|lower}}}}",
                    "headers": {"X-Echo": "{{kind|b64}}"},
                },
            ],
            "verdict": {
                "vulnerable_if": [{"step": "two", "body_contains": "{{rand}}"}],
                "control": [{"step": "one", "status": 200}],
            },
        }
        result = run(env, recipe)
        assert result["outcome"] == "vulnerable", result
        (_m1, _u1, headers1, body1), (_m2, url2, headers2, _b2) = env.shop.seen
        sent = json.loads(body1)
        token = sent["a"]
        assert re.fullmatch(r"[a-z0-9]{8}", token) and sent["b"] == "x" + token.upper()
        assert sent["t"].isdigit() and headers1["content-type"] == "application/json"
        assert url2 == f"{BASE}/echo?r={token}&c=200&t={token}"
        assert headers2["x-echo"] == base64.b64encode(b"application/json").decode()
        assert result["variables"] == ["code", "first", "kind", "tail"]
        assert token not in json.dumps(result)
        # A fresh run gets a fresh token.
        run(env, recipe)
        assert json.loads(env.shop.seen[2][3])["a"] != token

    def test_extraction_reads_json_header_and_regex(self, env) -> None:
        recipe = order_recipe()
        recipe["steps"][0]["extract"] = {
            "order": {"from": "json", "path": "order.id"},
            "same": {"from": "header", "name": "x-order-id"},
            "again": {"from": "regex", "pattern": r'"id": "(\d+)"'},
        }
        recipe["steps"][2]["url"] = f"{ORDERS}/{{{{same}}}}"
        recipe["steps"][3]["url"] = f"{ORDERS}/{{{{again}}}}"
        result = run(env, recipe)
        assert result["outcome"] == "vulnerable", result
        assert [url for _m, url, _h, _b in env.shop.seen][1:] == [f"{ORDERS}/100"] * 3

    def test_a_missing_value_stops_the_run_as_a_precondition(self, env) -> None:
        recipe = order_recipe()
        recipe["steps"][0]["extract"] = {"order": {"from": "json", "path": "order.missing"}}
        result = run(env, recipe)
        assert result["outcome"] == "precondition_failed" and result["vulnerable"] is None
        assert "order" in result["summary"] and len(env.shop.seen) == 1


# ── running ──────────────────────────────────────────────────────────


class TestTwoAccounts:
    def test_vulnerable_only_when_bob_reads_it_and_the_controls_hold(self, env) -> None:
        result = run(env, order_recipe())
        assert result["status"] == "completed" and result["vulnerable"] is True, result
        assert result["outcome"] == "vulnerable" and result["finding_id"]
        assert [s["id"] for s in result["steps"]] == ["create", "owner", "other", "nobody"]
        assert result["evidence_capture_ids"] == [s["capture_id"] for s in result["steps"]]
        assert result["details"]["captures"]["other"] == result["steps"][2]["capture_id"]
        assert all(c["held"] for c in result["conditions"])
        assert {c["kind"] for c in result["conditions"]} == {"status", "same_as", "json"}
        # Each step went out as the account it names, through the gateway.
        auth = [h.get("authorization", "") for _m, _u, h, _b in env.shop.seen]
        assert auth == [f"Bearer {TOKENS['alice']}"] * 2 + [f"Bearer {TOKENS['bob']}", ""]
        captures = [env.gateway.store.get("acme", c) for c in result["evidence_capture_ids"]]
        assert all(c.probe == "recipe:order-read-by-other" for c in captures)
        assert captures[2].identity == "bob" and captures[3].identity == ""
        assert captures[1].note == "recipe order-read-by-other step owner"

    def test_not_vulnerable_when_bob_is_refused(self, env) -> None:
        env.shop.broken = False
        result = run(env, order_recipe())
        assert result["vulnerable"] is False and result["outcome"] == "not_vulnerable"
        assert "finding_id" not in result
        assert env.bench.findings_list("acme")["findings"] == []

    def test_a_failed_control_means_no_verdict(self, env) -> None:
        env.shop.open_to_all = True  # the unauthenticated control no longer shows a refusal
        result = run(env, order_recipe())
        assert result["vulnerable"] is None and result["outcome"] == "control_failed"
        failed = [c for c in result["conditions"] if not c["held"]]
        assert failed == [{"role": "control", "kind": "status", "step": "nobody", "held": False}]
        assert "finding_id" not in result

    def test_a_failed_expect_is_a_precondition_not_a_vulnerability(self, env) -> None:
        env.shop.create_status = 500
        result = run(env, order_recipe())
        assert result["vulnerable"] is None and result["outcome"] == "precondition_failed"
        assert result["steps"] == [
            {"id": "create", "capture_id": result["steps"][0]["capture_id"], "status": 500,
             "expect_ok": False}
        ]  # fmt: skip
        assert len(env.shop.seen) == 1 and "not a finding" in result["summary"]
        assert env.bench.findings_list("acme")["findings"] == []

    def test_an_out_of_scope_step_is_refused_before_anything_is_sent(self, env) -> None:
        recipe = read_only_recipe()
        recipe["steps"][2]["url"] = "https://other.example.test/api/orders/100"
        result = run(env, recipe)
        assert result["status"] == "refused" and result["code"] == "OUT_OF_SCOPE", result
        assert result["recipe"] == "order-read-only" and env.shop.seen == []
        ledger = (env.roots.audit / "acme" / "captures.jsonl").read_text()
        assert "other.example.test" in ledger and "capture_refused" in ledger

    def test_an_unknown_identity_is_refused_before_anything_is_sent(self, env) -> None:
        recipe = order_recipe()
        recipe["steps"][2]["identity"] = "mallory"
        result = run(env, recipe)
        assert result["code"] == "UNKNOWN_IDENTITY" and env.shop.seen == []


# ── approval ─────────────────────────────────────────────────────────


class TestApproval:
    def test_a_state_changing_recipe_is_held_until_approved_as_one_run(self, held) -> None:
        first = run(held, order_recipe())
        assert first["status"] == "refused" and first["code"] == "APPROVAL_REQUIRED", first
        assert held.shop.seen == []
        requests_path, decisions_path = paths_for(held.roots.control, held.roots.audit, "acme")
        (request,) = pending(requests_path, decisions_path)
        assert request["tool_name"] == "recipe_run"
        shown = request["tool_args_redacted"]
        assert shown["recipe"] == "order-read-by-other"
        assert [(s["method"], s["url"]) for s in shown["steps"]] == [
            ("POST", ORDERS),
            ("GET", f"{ORDERS}/{{{{order}}}}"),
            ("GET", f"{ORDERS}/{{{{order}}}}"),
            ("GET", f"{ORDERS}/{{{{order}}}}"),
        ]
        assert shown["identities"] == ["alice", "bob"]
        assert "book-{{rand}}" in shown["steps"][0]["body_preview"]
        assert shown["max_requests"] == 4 + recipes.RUN_MARGIN
        # Asking again files nothing new.
        assert run(held, order_recipe())["request_id"] == first["request_id"]
        assert len(pending(requests_path, decisions_path)) == 1

        decide(held, first["request_id"])
        done = run(held, order_recipe())
        assert done["status"] == "completed" and done["vulnerable"] is True, done
        captures = [held.gateway.store.get("acme", c) for c in done["evidence_capture_ids"]]
        assert all(c.approval_id == first["request_id"] for c in captures)

        sent = len(held.shop.seen)
        again = run(held, order_recipe())
        assert again["code"] == "APPROVAL_REQUIRED" and again["request_id"] != first["request_id"]
        assert len(held.shop.seen) == sent

    def test_header_values_are_never_shown_to_the_operator(self, held) -> None:
        recipe = order_recipe()
        secret = "hdr-" + "51a7c0e9b2d4"
        recipe["steps"][0]["headers"] = {"X-Api-Key": secret}
        run(held, recipe)
        requests_path, decisions_path = paths_for(held.roots.control, held.roots.audit, "acme")
        (request,) = pending(requests_path, decisions_path)
        assert request["tool_args_redacted"]["steps"][0]["header_names"] == ["X-Api-Key"]
        assert secret not in json.dumps(request)

    def test_an_approval_does_not_carry_to_an_edited_recipe(self, held) -> None:
        first = run(held, order_recipe())
        decide(held, first["request_id"])
        edited = order_recipe()
        edited["steps"][0]["body"] = {"item": "piano-{{rand}}"}
        other = run(held, edited)
        assert other["code"] == "APPROVAL_REQUIRED" and other["request_id"] != first["request_id"]
        assert held.shop.seen == []
        assert run(held, order_recipe())["status"] == "completed"  # the original still may run

    def test_a_denied_recipe_is_never_sent(self, held) -> None:
        first = run(held, order_recipe())
        decide(held, first["request_id"], "deny")
        assert run(held, order_recipe())["code"] == "APPROVAL_DENIED" and held.shop.seen == []

    def test_a_read_only_recipe_needs_no_approval_unless_declared(self, held) -> None:
        seed_order(held)
        assert run(held, read_only_recipe())["status"] == "completed"
        sent = len(held.shop.seen)
        declared = run(held, read_only_recipe(state_changing=True))
        assert declared["code"] == "APPROVAL_REQUIRED" and len(held.shop.seen) == sent
        assert recipes.check(read_only_recipe(state_changing=True))["state_changing"] is True

    def test_a_grant_covers_only_the_steps_count_plus_the_margin(self, held) -> None:
        recipe = recipes.validate(order_recipe())
        first = recipes.execute(held.gateway, "acme", recipe)
        decide(held, first["request_id"])
        grant = held.gateway.recipe_grant(
            "acme",
            recipe.name,
            recipe.canonical,
            [s.url for s in recipe.steps],
            recipe.approval_view(),
            recipe.max_requests(),
        )
        assert grant is not None and grant.remaining == 6 and grant.probe == recipe.probe
        grant.remaining = 1
        result = recipes.run(held.gateway, "acme", recipe, grant=grant)
        assert result["status"] == "refused" and result["code"] == "APPROVAL_SPENT", result
        assert result["step"] == "owner" and len(result["evidence_capture_ids"]) == 1


# ── secrets, queue and verification ──────────────────────────────────


class TestQueueAndVerification:
    def test_extracted_values_never_come_back(self, env) -> None:
        recipe = order_recipe()
        recipe["steps"][0]["extract"]["ref"] = {"from": "regex", "pattern": r"reference=([\w-]+);"}
        recipe["verdict"]["vulnerable_if"].append({"step": "other", "body_contains": "{{ref}}"})
        result = run(env, recipe)
        assert result["vulnerable"] is True, result
        assert REFERENCE not in json.dumps(result)
        assert result["variables"] == ["order", "ref"]
        stored = env.bench.recipe_get("acme", "order-read-by-other")
        assert stored["ok"] and REFERENCE not in json.dumps(stored)
        assert REFERENCE not in json.dumps(env.bench.recipe_list("acme"))
        finding = env.bench.finding_get("acme", result["finding_id"])
        assert REFERENCE not in json.dumps(finding)

    def test_a_queued_finding_is_verified_by_running_the_recipe_again(self, env) -> None:
        result = run(env, order_recipe())
        finding = env.bench.finding_get("acme", result["finding_id"])["finding"]
        assert (
            finding["status"] == "candidate" and finding["source"] == "recipe:order-read-by-other"
        )
        assert finding["class"] == "access_control" and finding["severity"] == "high"
        assert finding["remediation"].startswith("Return an order only")
        assert finding["method"] == "GET"
        sent = len(env.shop.seen)
        outcome = env.bench.finding_verify("acme", result["finding_id"])
        assert outcome["finding"]["status"] == "exploit_verified", outcome
        entry = outcome["verification"]["assertions"][0]
        assert entry["method"] == "probe_rerun" and entry["probe"] == "recipe:order-read-by-other"
        assert len(env.shop.seen) == sent + 4  # the whole recipe ran again

    def test_a_target_fixed_before_verification_is_not_verified(self, env) -> None:
        result = run(env, order_recipe())
        env.shop.broken = False
        outcome = env.bench.finding_verify("acme", result["finding_id"])
        assert outcome["finding"]["status"] == "inconclusive"
        assert outcome["verification"]["reasons"] == [verifier.PROBE_NOT_REPRODUCED]

    def test_a_state_changing_rerun_needs_its_own_approval(self, held) -> None:
        first = run(held, order_recipe())
        decide(held, first["request_id"])
        result = run(held, order_recipe())
        outcome = held.bench.finding_verify("acme", result["finding_id"])
        assert outcome["finding"]["status"] == "inconclusive"
        (reason,) = outcome["verification"]["reasons"]
        requests_path, decisions_path = paths_for(held.roots.control, held.roots.audit, "acme")
        (request,) = pending(requests_path, decisions_path)
        assert "APPROVAL_REQUIRED" in reason and request["request_id"] in reason
        decide(held, request["request_id"])
        verified = held.bench.finding_verify("acme", result["finding_id"])
        assert verified["finding"]["status"] == "exploit_verified", verified

    def test_a_saved_recipe_runs_by_name(self, env) -> None:
        seed_order(env)
        saved = env.bench.recipe_save("acme", json.dumps(read_only_recipe()), "hunter:t1")
        assert saved == {
            "ok": True,
            "name": "order-read-only",
            "replaced": False,
            "state_changing": False,
            "steps": 3,
        }
        listed = env.bench.recipe_list("acme")
        assert listed["count"] == 1 and listed["recipes"][0]["author"] == "hunter:t1"
        result = env.bench.recipe_run("acme", json.dumps({"use": "order-read-only"}), "hunter:t1")
        assert result["vulnerable"] is True, result
        row = env.bench.recipe_list("acme")["recipes"][0]
        assert row["last_outcome"] == "vulnerable" and row["last_run_at"] > 0
        got = env.bench.recipe_get("acme", "order-read-only")
        assert got["recipe"] == recipes.validate(read_only_recipe()).data
        missing = env.bench.recipe_run("acme", json.dumps({"use": "nope"}), "hunter:t1")
        assert missing["code"] == "UNKNOWN_RECIPE"
        assert env.bench.recipe_get("acme", "nope")["code"] == "UNKNOWN_RECIPE"
        bad = env.bench.recipe_save("acme", json.dumps({"name": "x"}), "hunter:t1")
        assert bad["ok"] is False and bad["errors"][0]["path"] == "class"

    def test_recipe_check_sends_nothing(self, env) -> None:
        assert env.bench.recipe_check("acme", json.dumps(order_recipe()))["ok"] is True
        invalid = env.bench.recipe_run("acme", json.dumps({"name": "x"}), "hunter:t1")
        assert invalid["ok"] is False and env.shop.seen == []


@pytest.mark.parametrize("pattern", ["(a+)+$", "(.*x)*y", "(\\w+\\s?)*end", "(ab*){2,}c"])
def test_a_pattern_that_can_backtrack_without_bound_is_refused(pattern: str) -> None:
    recipe = order_recipe()
    recipe["steps"][0]["extract"]["slow"] = {"from": "regex", "pattern": pattern}
    path, message = error_of(recipe)
    assert path == "steps[0].extract.slow.pattern" and "nesting repeats" in message


@pytest.mark.parametrize("pattern", ["id=(\\d+)", 'token":"([a-f0-9]{8,64})"', "(ab)+c", "a+b*"])
def test_ordinary_patterns_are_accepted(pattern: str) -> None:
    recipe = order_recipe()
    recipe["steps"][0]["extract"]["fine"] = {"from": "regex", "pattern": pattern}
    assert recipes.validate(recipe) is not None
