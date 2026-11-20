"""The candidate queue: three producers, one deduplicated list, and who takes what.

The producers are real: scanner records are parsed by the nuclei wrapper from
scanner output, probe results come from ``run_probe`` through a real
``CaptureGateway`` over a fake origin, and the ranked surface comes from
``rank_candidates``. Every probe case has a control: the same probe against a
target that does not have the flaw produces nothing, and (where the result
records something a replay can tell apart) the queued assertions stop
verifying once the target is fixed.
"""

from __future__ import annotations

import html
import io
import json
import sqlite3
import subprocess
import sys
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from buggy.capture.authz_matrix import run_matrix
from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.probes import run_probe
from buggy.capture.probes.base import b64url_decode, b64url_encode
from buggy.findings.candidates import (
    CLASS_PRIORITY,
    LEASE_SECONDS,
    PROBE_SEVERITY,
    enqueue,
    from_pipeline,
    from_probe,
    from_ranked,
    next_candidates,
    release,
)
from buggy.findings.model import CLASSES, SEVERITIES, finding_id
from buggy.findings.service import FindingService
from buggy.findings.store import FindingStore
from buggy.pipeline.report import rank_candidates
from buggy.pipeline.tools.nuclei import Nuclei

REPO_ROOT = Path(__file__).resolve().parents[5]
BASE = "https://app.acme.test"
ORDER = f"{BASE}/api/orders/1001"
INVOICE = f"{BASE}/api/invoices/2001"
ME = f"{BASE}/api/me"
CART = f"{BASE}/api/cart"
PROFILE = f"{BASE}/api/profile"
FETCH = f"{BASE}/fetch"
SEARCH = f"{BASE}/search"
STOCK = f"{BASE}/stock"
HELLO = f"{BASE}/hello"
GRAPHQL = f"{BASE}/graphql"

ALICE = {"Authorization": "Bearer alice"}
BOB = {"Authorization": "Bearer bob"}
ALICE_ORDER = {
    "id": 1001,
    "owner": "alice@acme.test",
    "items": ["thinkpad x1", "usb-c dock"],
    "card": "4111-1111-1111-1111",
    "ship_to": "1 Main Street, Springfield",
}
BOB_ORDER = {"n": 7, "who": "bob", "basket": [], "note": "Q" * 36}
# Bob's own page, which nevertheless names the owner of the order.
BOB_LEAK = {**BOB_ORDER, "shared_with": "alice@acme.test"}

# A three-part token built here; nothing a provider issues.
SIGNATURE = "fixture" + "signature"
TOKEN = ".".join(
    (
        b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()),
        b64url_encode(json.dumps({"sub": "alice"}).encode()),
        SIGNATURE,
    )
)


class Site:
    """A fake origin: one handler per path, given the parsed request."""

    def __init__(self) -> None:
        self.routes: dict[str, Callable[[SimpleNamespace], tuple]] = {}
        self.seen: list[tuple[str, str]] = []

    def open(self, request, timeout=None):  # noqa: ARG002
        method, url = request.get_method(), request.full_url
        self.seen.append((method, url))
        parts = urlsplit(url)
        handler = self.routes.get(parts.path)
        answer: tuple = (404, b"not found")
        if handler is not None:
            answer = handler(
                SimpleNamespace(
                    method=method,
                    query={k: v[0] for k, v in parse_qs(parts.query, True).items()},
                    headers={k.lower(): v for k, v in request.header_items()},
                    body=request.data or b"",
                )
            )
        status, payload, *rest = answer
        headers = {"Content-Type": rest[0] if rest else "application/json"}
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode()
        if status >= 300:
            raise urllib.error.HTTPError(url, status, "x", headers, io.BytesIO(payload))
        response = io.BytesIO(payload)
        response.status, response.headers = status, headers
        return response


class Clock:
    """The store's clock: one second per reading, or held still (``step = 0``)."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.step = 1.0

    def __call__(self) -> float:
        value = self.now
        self.now += self.step
        return value


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.roots = Roots(
            control=tmp_path / "control",
            audit=tmp_path / "audit",
            data=tmp_path / "data",
            secrets=tmp_path / "secrets",
        )
        (self.roots.control / "acme").mkdir(parents=True)
        (self.roots.control / "acme" / "roe.json").write_text(
            json.dumps(
                {
                    "machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]},
                    "approvals": {"state_changing": "not_required"},
                }
            )
        )
        self.site = Site()
        self.gateway = CaptureGateway(self.roots, opener=self.site, sleep=lambda _s: None)
        self.clock = Clock()
        self.store = FindingStore(self.roots.data / "findings.sqlite3", clock=self.clock)
        self.service = FindingService(self.store, self.gateway)

    def close(self) -> None:
        self.gateway.store.close()
        self.store.close()

    def order(self, mode: str) -> None:
        """How ``GET /api/orders/1001`` (Alice's order) answers."""

        def handler(request: SimpleNamespace) -> tuple:
            who = request.headers.get("authorization", "")
            if mode == "open":  # no access control at all
                return 200, ALICE_ORDER
            if not who:
                return 401, {"error": "login"}
            if who == "Bearer alice" or mode == "vulnerable":  # any logged-in user reads it
                return 200, ALICE_ORDER
            if mode == "per_user":  # 200 to everyone, with the caller's own data
                return 200, BOB_ORDER
            if mode == "leaky":  # the caller's own page, naming the order's owner
                return 200, BOB_LEAK
            return 403, {"error": "forbidden"}  # fixed

        self.site.routes["/api/orders/1001"] = handler

    def note(self, result: dict, fragment: str) -> str:
        """The one capture of ``result`` whose note (the probe's own label) has ``fragment``."""
        found = [
            capture_id
            for capture_id in result["evidence_capture_ids"]
            if fragment in self.gateway.store.get("acme", capture_id).note
        ]
        assert len(found) == 1, (fragment, found)
        return found[0]


@pytest.fixture
def env(tmp_path: Path):
    environment = Env(tmp_path)
    yield environment
    environment.close()


def A(capture_id: str, **expect) -> dict:  # noqa: N802
    """An assertion as the contract spells it, with ``expect`` filled in."""
    return {
        "capture_id": capture_id,
        "identity": "",
        "expect": {
            "status": None,
            "body_contains": [],
            "body_not_contains": [],
            "differs_from": "",
            "same_as": "",
            **expect,
        },
    }


def _scanner(*lines: dict) -> list[dict]:
    """Recon ``vulnerability`` records, parsed from scanner output by the nuclei wrapper."""
    raw = "\n".join(json.dumps(line) for line in lines)
    return [
        {
            "engagement": "acme",
            "type": record.type.value,
            "asset": record.asset,
            "value": record.value,
            "attrs": record.attrs,
            "source_tool": record.source_tool,
        }
        for record in Nuclei().parse(raw)
    ]


def _hit(template: str, matched_at: str, severity: str, tags: Any, **classification) -> dict:
    return {
        "template-id": template,
        "matched-at": matched_at,
        "host": BASE,
        "type": "http",
        "info": {
            "name": template.replace("-", " "),
            "severity": severity,
            "tags": tags,
            "classification": classification,
        },
    }


IDOR_HIT = _hit(
    "idor-order-read",
    f"{BASE}/api/orders/55?debug=1",
    "medium",
    ["idor"],
    **{"cwe-id": ["CWE-639"]},
)


def _ids(rows: list[dict]) -> list[str]:
    return [row["id"] for row in rows]


# ── three producers, one row ────────────────────────────────────────


class TestOneRowPerLead:
    def _agent_claim(self, env: Env) -> dict:
        seen = env.gateway.send("acme", "GET", f"{BASE}/api/orders/1001", headers=BOB, note="agent")
        return {
            "engagement": "acme",
            "title": "Bob reads Alice's order",
            "class": "access_control",
            "severity": "low",
            "endpoint": f"{BASE}/api/orders/1001?expand=items",
            "source": "agent:hunter",
            "remediation": "Check that the order belongs to the caller before returning it.",
            "assertions": [A(seen.id, status=200, body_contains=["alice@acme.test"])],
        }

    def test_the_same_idor_from_scanner_probe_and_agent_is_one_row(self, env: Env) -> None:
        env.order("vulnerable")
        scanner = from_pipeline(_scanner(IDOR_HIT), "acme")
        result = run_probe(
            env.gateway,
            "acme",
            "idor",
            {"url": ORDER, "owner_headers": ALICE, "attacker_headers": BOB},
        )
        probe = from_probe(result, "acme", ORDER)
        agent = self._agent_claim(env)
        assert len(scanner) == 1 and probe is not None
        # Three different URLs of one object type: the id is what makes them one lead.
        expected = finding_id("acme", "access_control", ORDER, "")
        assert scanner[0]["id"] == probe["id"] == expected
        assert scanner[0]["assertions"] == [] and len(probe["assertions"]) == 2
        sent = len(env.site.seen)

        out = enqueue(env.service, [*scanner, probe, agent], "queue")

        assert out == {
            "ok": True,
            "submitted": 3,
            "created": 1,
            "merged": 2,
            "ids": [expected],
            "errors": [],
        }
        assert len(env.site.seen) == sent  # queueing sends nothing
        rows = env.store.list("acme")
        assert len(rows) == 1
        row = rows[0].to_dict()
        assert row["source"] == "pipeline:nuclei | probe:idor | agent:hunter"
        assert row["assertions"] == [*probe["assertions"], *agent["assertions"]]
        # medium from the scanner, high from the probe, low from the agent.
        assert row["severity"] == "high" and row["status"] == "candidate"
        assert [e["event"] for e in env.store.events("acme", expected)] == [
            "created",
            "merged",
            "merged",
        ]
        # What was merged is replayable: the verifier re-proves all three assertions.
        verified = env.service.verify("acme", expected)
        assert verified["finding"]["status"] == "exploit_verified"
        assert len(verified["finding"]["verification"]["replay_capture_ids"]) == 3

    def test_reporting_it_again_adds_nothing(self, env: Env) -> None:
        env.order("vulnerable")
        result = run_probe(
            env.gateway,
            "acme",
            "idor",
            {"url": ORDER, "owner_headers": ALICE, "attacker_headers": BOB},
        )
        items = [*from_pipeline(_scanner(IDOR_HIT), "acme"), from_probe(result, "acme", ORDER)]
        enqueue(env.service, items, "queue")
        again = enqueue(env.service, items, "queue")
        assert again["created"] == 0 and again["merged"] == 2
        (row,) = env.store.list("acme")
        assert row.source == "pipeline:nuclei | probe:idor" and len(row.assertions) == 2

    def test_another_endpoint_or_another_class_is_another_row(self, env: Env) -> None:
        elsewhere = {**IDOR_HIT, "matched-at": f"{BASE}/api/invoices/55"}
        other_class = _hit("order-sqli", f"{BASE}/api/orders/55", "high", ["sqli"])
        out = enqueue(
            env.service, from_pipeline(_scanner(IDOR_HIT, elsewhere, other_class), "acme"), "queue"
        )
        assert out["created"] == 3 and out["merged"] == 0
        assert sorted((f.vuln_class, f.endpoint) for f in env.store.list("acme")) == [
            ("access_control", f"{BASE}/api/invoices/{{id}}"),
            ("access_control", f"{BASE}/api/orders/{{id}}"),
            ("injection", f"{BASE}/api/orders/{{id}}"),
        ]
        assert {f.source for f in env.store.list("acme")} == {"pipeline:nuclei"}

    def test_a_surface_lead_and_the_authz_matrix_meet_in_one_row(self, env: Env) -> None:
        env.order("vulnerable")
        identities = [
            {"name": name, "role": "user", "owner_of": owner_of, "static": {"headers": headers}}
            for name, owner_of, headers in (("alice", [ORDER], ALICE), ("bob", [], BOB))
        ]
        path = env.roots.secrets / "acme" / "identities.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"identities": identities}))
        leads = from_ranked(
            rank_candidates({"url": [{"type": "url", "asset": "app.acme.test", "value": ORDER}]}),
            "acme",
        )
        assert [lead["class"] for lead in leads] == ["access_control"]
        enqueue(env.service, leads, "queue")
        (lead,) = env.store.list("acme")
        assert (lead.source, lead.severity, lead.assertions) == ("pipeline:surface", "info", ())

        matrix = run_matrix(env.gateway, None, "acme", [ORDER], identities=["alice", "bob"])
        assert len(matrix["candidates"]) == 1
        out = enqueue(env.service, matrix["candidates"], "queue")

        assert out["merged"] == 1 and out["ids"] == [lead.id]
        (row,) = env.store.list("acme")
        assert row.source == "pipeline:surface | probe:authz_matrix"
        assert row.severity == "high"  # the lead's ``info`` did not lower the proven severity
        assert [a.to_dict() for a in row.assertions] == matrix["candidates"][0]["assertions"]

    def test_a_rejected_item_is_reported_and_the_rest_is_queued(self, env: Env) -> None:
        good = from_pipeline(_scanner(IDOR_HIT), "acme")[0]
        out = enqueue(
            env.service,
            [None, {**good, "class": "not-a-class"}, {"title": "no engagement"}, good],
            "queue",
        )
        assert out["ok"] is False and out["submitted"] == 1 and out["ids"] == [good["id"]]
        assert [(e["index"], e["code"]) for e in out["errors"]] == [
            (1, "INVALID_FINDING"),
            (2, "INVALID_FINDING"),
        ]
        assert out["errors"][0]["errors"][0]["field"] == "class"
        assert len(env.store.list("acme")) == 1
        # Nobody named: nothing is written.
        assert enqueue(env.service, [good], "")["errors"][0]["code"] == "BAD_ACTOR"


# ── scanner hits ────────────────────────────────────────────────────


class TestFromPipeline:
    def test_a_hit_becomes_a_candidate_without_assertions(self) -> None:
        (candidate,) = from_pipeline(_scanner(IDOR_HIT), "acme")
        assert candidate["source"] == "pipeline:nuclei"
        assert candidate["class"] == "access_control" and candidate["cwe"] == "CWE-639"
        assert candidate["severity"] == "medium" and candidate["status"] == "candidate"
        assert candidate["endpoint"] == f"{BASE}/api/orders/{{id}}"
        assert candidate["title"] == "idor order read (idor-order-read)"
        assert candidate["assertions"] == [] and candidate["parameter"] == ""

    def test_technology_detection_is_not_queued(self, env: Env) -> None:
        # Both name a class (CWE-200), so it is the technology rule that leaves them out.
        # nuclei prints the tags of the first template as one comma-separated string.
        cwe = {"cwe-id": ["CWE-200"]}
        tech = _hit("tech-detect", f"{BASE}/", "info", "discovery,tech", **cwe)
        listed = _hit("nginx-version", f"{BASE}/status", "info", ["tech", "nginx"], **cwe)
        records = _scanner(tech, listed)
        assert len(records) == 2 and records[0]["attrs"]["tags"] == ["discovery,tech"]
        assert from_pipeline(records, "acme") == []
        assert enqueue(env.service, from_pipeline(records, "acme"), "queue")["submitted"] == 0
        assert env.store.list("acme") == []

    @pytest.mark.parametrize(
        ("severity", "tags"),
        [
            ("info", "discovery,technical"),  # info, but not tagged tech
            ("info", ["nginx"]),
            ("low", "discovery,tech"),  # tagged tech, but it reports a weakness
            ("medium", ["tech", "nginx"]),
        ],
    )
    def test_only_info_and_tech_together_are_left_out(
        self, env: Env, severity: str, tags: Any
    ) -> None:
        # The same hits as above with one of the two conditions changed.
        hit = _hit("tech-detect", f"{BASE}/", severity, tags, **{"cwe-id": ["CWE-200"]})
        (candidate,) = from_pipeline(_scanner(hit), "acme")
        assert (candidate["class"], candidate["severity"]) == ("info_exposure", severity)
        assert enqueue(env.service, [candidate], "queue")["created"] == 1

    def test_what_cannot_be_placed_is_left_out(self) -> None:
        (good,) = _scanner(IDOR_HIT)
        unknown_class = _scanner(_hit("odd-banner", f"{BASE}/x", "low", ["misc"]))
        records = [
            None,
            "idor",
            {**good, "type": "url"},
            {**good, "engagement": "other"},
            {"type": "vulnerability", "value": "", "attrs": {"cwe": ["CWE-639"]}},
            *unknown_class,
        ]
        assert from_pipeline(records, "acme") == []
        assert len(from_pipeline([*records, good], "acme")) == 1

    def test_a_record_without_a_severity_is_info(self) -> None:
        (record,) = _scanner(IDOR_HIT)
        record = {**record, "attrs": {**record["attrs"], "severity": "unknown"}}
        assert from_pipeline([record], "acme")[0]["severity"] == "info"


# ── probe results ───────────────────────────────────────────────────


@dataclass
class Case:
    """One probe against one target: how to run it, and which assertions a hit supports."""

    probe: str
    params: dict
    url: str
    #: Makes the target safe.
    fix: Callable[[], None]
    #: ``(env, result) -> the assertions expected``, naming captures by the probe's own notes.
    expected: Callable[[Env, dict], list[dict]]
    parameter: str = ""
    method: str = "GET"
    canary: Canary | None = None
    #: The CWE and, for ``sqli``, the technique this target must make the probe report.
    cwe: str = ""
    technique: str = ""
    #: A change that leaves the endpoint answering 200 but ends the flaw (default: ``fix``).
    to_break: Callable[[], None] | None = None
    #: False when the result records nothing but a status the fixed target still returns.
    replay_can_tell: bool = True

    @property
    def state_changing(self) -> bool:
        return self.method != "GET"


def _idor(env: Env) -> Case:
    env.order("vulnerable")
    return Case(
        "idor",
        {"url": ORDER, "owner_headers": ALICE, "attacker_headers": BOB},
        ORDER,
        lambda: env.order("fixed"),
        lambda e, r: [
            A(e.note(r, "owner reads"), status=200),
            A(e.note(r, "other identity"), status=200, same_as=e.note(r, "owner reads")),
        ],
        cwe="CWE-639",
        to_break=lambda: env.order("per_user"),
    )


def _idor_open(env: Env) -> Case:
    env.order("open")
    return Case(
        "idor",
        {"url": ORDER, "owner_headers": ALICE, "attacker_headers": BOB},
        ORDER,
        lambda: env.order("fixed"),
        lambda e, r: [
            A(e.note(r, "owner reads"), status=200),
            A(e.note(r, "other identity"), status=200, same_as=e.note(r, "owner reads")),
            A(e.note(r, "no credentials"), status=200, same_as=e.note(r, "owner reads")),
        ],
        # Requiring a login is not enough for the claim "no credentials needed" to hold.
        cwe="CWE-862",
        to_break=lambda: env.order("vulnerable"),
    )


def _idor_markers(env: Env) -> Case:
    env.order("leaky")
    return Case(
        "idor",
        {
            "url": ORDER,
            "owner_headers": ALICE,
            "attacker_headers": BOB,
            "markers": ["alice@acme.test", "never-in-the-page"],
        },
        ORDER,
        lambda: env.order("fixed"),
        # Proved by the marker: the two pages are not alike, so nothing claims they are.
        lambda e, r: [
            A(e.note(r, "owner reads"), status=200),
            A(e.note(r, "other identity"), status=200, body_contains=["alice@acme.test"]),
        ],
        cwe="CWE-639",
        to_break=lambda: env.order("per_user"),
    )


def _jwt(env: Env) -> Case:
    state = {"unsigned_ok": True}

    def me(request: SimpleNamespace) -> tuple:
        parts = request.headers.get("authorization", "").removeprefix("Bearer ").split(".")
        if len(parts) == 3:
            algorithm = json.loads(b64url_decode(parts[0])).get("alg")
            if (algorithm == "HS256" and parts[2] == SIGNATURE) or (
                algorithm == "none" and state["unsigned_ok"]
            ):
                return 200, {"user": "alice", "email": "alice@acme.test", "plan": "team"}
        return 401, {"error": "invalid token"}

    env.site.routes["/api/me"] = me
    return Case(
        "jwt_alg_none",
        {"url": ME, "token": TOKEN},
        ME,
        lambda: state.update(unsigned_ok=False),
        lambda e, r: [
            A(e.note(r, "corrupted signature"), status=401),
            A(e.note(r, "alg=none"), status=200),
        ],
    )


def _numeric(env: Env) -> Case:
    state = {"checks": False}

    def cart(request: SimpleNamespace) -> tuple:
        data = json.loads(request.body)
        if state["checks"] and data["quantity"] <= 0:
            return 400, {"error": "quantity must be positive"}
        return 200, {"sku": data["sku"], "quantity": data["quantity"]}

    env.site.routes["/api/cart"] = cart
    return Case(
        "numeric_boundary",
        {
            "url": CART,
            "body": {"sku": "desk-1", "quantity": 1},
            "field": "quantity",
            "values": [5, -1],
        },
        CART,
        lambda: state.update(checks=True),
        # Only the out-of-range request is evidence; quantity=5 was accepted too.
        lambda e, r: [A(e.note(r, "quantity=-1"), status=200)],
        method="POST",
    )


def _mass_assignment(env: Env) -> Case:
    state = {"binds_everything": True}

    def profile(request: SimpleNamespace) -> tuple:
        data = json.loads(request.body)
        return 200, data if state["binds_everything"] else {"name": data.get("name")}

    env.site.routes["/api/profile"] = profile
    return Case(
        "mass_assignment",
        {"url": PROFILE, "body": {"name": "bob"}, "extra_fields": {"role": "admin"}},
        PROFILE,
        lambda: state.update(binds_everything=False),
        lambda e, r: [A(e.note(r, "extra field"), status=200)],
        method="POST",
        replay_can_tell=False,
    )


def _ssrf(env: Env) -> Case:
    state = {"fetches": True}
    canary = Canary(base_url="http://canary.test")

    def fetch(request: SimpleNamespace) -> tuple:
        url = json.loads(request.body)["imageUrl"]
        if state["fetches"]:
            canary.record(
                url.rsplit("/", 1)[1],
                remote="203.0.113.5",
                method="GET",
                path="/c/x",
                user_agent="x",
            )
        return 200, {"queued": True}

    env.site.routes["/fetch"] = fetch
    return Case(
        "ssrf_canary",
        {"url": FETCH, "body": {"imageUrl": "{{CANARY}}"}, "wait_seconds": 0.3},
        FETCH,
        lambda: state.update(fetches=False),
        lambda e, r: [A(e.note(r, "canary URL"), status=200)],
        method="POST",
        canary=canary,
        replay_can_tell=False,
    )


def _shop(env: Env) -> dict:
    """Two endpoints over one SQLite database, built by concatenation until ``bound``."""
    state = {"bound": False}
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE products (name TEXT, category TEXT)")
    db.executemany(
        "INSERT INTO products VALUES (?, ?)",
        [
            ("Walnut desk organiser", "Gifts"),
            ("Brass letter opener", "Gifts"),
            ("Linen notebook, ruled", "Gifts"),
            ("Steel ruler 30 cm", "Tools"),
        ],
    )

    def rows(category: str) -> list[tuple]:
        if state["bound"]:
            return db.execute(
                "SELECT name FROM products WHERE category = ?", (category,)
            ).fetchall()
        sql = f"SELECT name FROM products WHERE category = '{category}'"  # noqa: S608
        return db.execute(sql).fetchall()

    def search(request: SimpleNamespace) -> tuple:  # shows the rows, hides the error
        try:
            return 200, {"items": [name for (name,) in rows(request.query.get("category", ""))]}
        except sqlite3.Error:
            return 500, {"error": "something went wrong"}

    def stock(request: SimpleNamespace) -> tuple:  # hides the rows, shows the error
        try:
            rows(request.query.get("category", ""))
        except sqlite3.Error as exc:
            return 500, {"error": f"SQLITE_ERROR: {exc}"}
        return 200, {"status": "counted"}

    env.site.routes["/search"] = search
    env.site.routes["/stock"] = stock
    return state


def _sqli_boolean(env: Env) -> Case:
    state = _shop(env)
    return Case(
        "sqli",
        {"url": f"{SEARCH}?category=Gifts", "parameter": "category"},
        SEARCH,
        lambda: state.update(bound=True),
        lambda e, r: [
            A(e.note(r, "TRUE condition"), status=200, same_as=e.note(r, "baseline (valid")),
            A(e.note(r, "FALSE condition"), status=200, differs_from=e.note(r, "baseline (valid")),
        ],
        parameter="category",
        technique="boolean",
    )


def _sqli_error(env: Env) -> Case:
    state = _shop(env)
    return Case(
        "sqli",
        {"url": f"{STOCK}?category=Gifts", "parameter": "category"},
        STOCK,
        lambda: state.update(bound=True),
        lambda e, r: [
            A(e.note(r, "single quote"), status=500, differs_from=e.note(r, "two quotes")),
            A(e.note(r, "two quotes"), status=200),
        ],
        parameter="category",
        technique="error",
    )


def _xss(env: Env) -> Case:
    state = {"encodes": False}

    def hello(request: SimpleNamespace) -> tuple:
        name = request.query.get("name", "")
        safe = html.escape(name)
        shown = safe if state["encodes"] else name
        # Reflected twice: raw in the text (until fixed), always encoded in the attribute.
        page = f'<html><body><p>Hello {shown}</p><input value="{safe}"></body></html>'
        return 200, page, "text/html; charset=utf-8"

    env.site.routes["/hello"] = hello

    def expected(e: Env, r: dict) -> list[dict]:
        verdicts = {c["context"]: c["vulnerable"] for c in r["details"]["contexts"]}
        assert verdicts == {"html_text": True, "attribute_quoted": False}
        (proven,) = [c for c in r["details"]["contexts"] if c["vulnerable"]]
        # Only the proven context is evidence; the attribute's request was sent too.
        return [
            A(e.note(r, "html_text probe"), status=200, body_contains=[f"<{proven['marker']}x>"])
        ]

    return Case(
        "xss_reflected",
        {"url": f"{HELLO}?name=bob", "parameter": "name"},
        HELLO,
        lambda: state.update(encodes=True),
        expected,
        parameter="name",
    )


def _graphql(env: Env) -> Case:
    state = {"introspection": True}

    def graphql(request: SimpleNamespace) -> tuple:
        if "__schema" in json.loads(request.body)["query"] and state["introspection"]:
            schema = {
                "queryType": {"name": "Query", "fields": [{"name": "orders"}]},
                "mutationType": None,
                "types": [{"name": "Query"}, {"name": "Order"}],
            }
            return 200, {"data": {"__schema": schema}}
        return 200, {"errors": [{"message": "Cannot query that field."}]}

    env.site.routes["/graphql"] = graphql
    return Case(
        "graphql_checks",
        {"url": GRAPHQL},
        GRAPHQL,
        lambda: state.update(introspection=False),
        # The result records no status for any of its captures.
        lambda _e, _r: [],
        method="POST",
    )


CASES: dict[str, Callable[[Env], Case]] = {
    "idor": _idor,
    "idor_no_access_control": _idor_open,
    "idor_by_marker": _idor_markers,
    "jwt_alg_none": _jwt,
    "numeric_boundary": _numeric,
    "mass_assignment": _mass_assignment,
    "ssrf_canary": _ssrf,
    "sqli_boolean": _sqli_boolean,
    "sqli_error": _sqli_error,
    "xss_reflected": _xss,
    "graphql_checks": _graphql,
}


def _probe(env: Env, case: Case) -> dict:
    return run_probe(env.gateway, "acme", case.probe, case.params, canary=case.canary)


class TestFromProbe:
    @pytest.mark.parametrize("name", list(CASES))
    def test_a_hit_becomes_a_candidate_whose_assertions_replay(self, env: Env, name: str) -> None:
        case = CASES[name](env)
        result = _probe(env, case)
        assert result["vulnerable"] is True, result
        # The target shows the flaw the case is about, not another one.
        assert not case.cwe or result["cwe"] == case.cwe
        assert not case.technique or result["details"]["technique"] == case.technique

        candidate = from_probe(result, "acme", case.url)

        assert candidate["assertions"] == case.expected(env, result)
        assert candidate["source"] == f"probe:{case.probe}" and candidate["status"] == "candidate"
        assert candidate["class"] == result["class"] and candidate["cwe"] == result["cwe"]
        assert candidate["severity"] == PROBE_SEVERITY[result["class"]]
        assert candidate["parameter"] == case.parameter
        assert candidate["remediation"] == result["remediation"]
        assert result["summary"] in candidate["description"]
        assert candidate["id"] == finding_id("acme", result["class"], case.url, case.parameter)
        cited = {a["capture_id"] for a in candidate["assertions"]}
        assert cited <= set(result["evidence_capture_ids"])

        out = enqueue(env.service, [candidate], "queue")
        assert out["ok"] and out["ids"] == [candidate["id"]], out
        stored = env.store.get("acme", candidate["id"]).to_dict()
        assert stored["assertions"] == candidate["assertions"]
        assert stored["method"] == case.method
        sent = len(env.site.seen)  # queueing sent nothing; the verifier now re-sends
        verified = env.service.verify(
            "acme", candidate["id"], allow_state_change=case.state_changing
        )
        assert len(env.site.seen) == sent + len(candidate["assertions"])
        if candidate["assertions"]:
            assert verified["finding"]["status"] == "exploit_verified", verified
        else:  # nothing to replay: queued, never confirmed
            assert verified["finding"]["status"] == "inconclusive"
            assert verified["finding"]["verification"]["reasons"] == ["no assertions"]

    @pytest.mark.parametrize("name", [name for name in CASES if name not in ("graphql_checks",)])
    def test_once_the_target_is_fixed_the_queued_assertions_do_not_verify(
        self, env: Env, name: str
    ) -> None:
        case = CASES[name](env)
        candidate = from_probe(_probe(env, case), "acme", case.url)
        enqueue(env.service, [candidate], "queue")
        (case.to_break or case.fix)()
        verified = env.service.verify(
            "acme", candidate["id"], allow_state_change=case.state_changing
        )
        if case.replay_can_tell:
            assert verified["finding"]["status"] == "inconclusive", verified
            failed = [a for a in verified["verification"]["assertions"] if a["outcome"] == "failed"]
            assert failed and all(a["failed_checks"] for a in failed)
        else:
            # A known limit, pinned so that it is not mistaken for proof: the result records
            # only a status, the fixed target still answers with it, and the replay passes.
            assert [a["expect"] for a in candidate["assertions"]] == [A("x", status=200)["expect"]]
            assert verified["finding"]["status"] == "exploit_verified"

    @pytest.mark.parametrize("name", list(CASES))
    def test_a_target_without_the_flaw_produces_nothing(self, env: Env, name: str) -> None:
        case = CASES[name](env)
        case.fix()
        result = _probe(env, case)
        assert result["vulnerable"] is False, result
        assert from_probe(result, "acme", case.url) is None
        assert enqueue(env.service, [from_probe(result, "acme", case.url)], "queue")["ids"] == []
        assert env.store.list("acme") == []

    def test_could_not_tell_produces_nothing(self, env: Env) -> None:
        # The owner cannot read the object: the probe has nothing to compare and says so.
        env.site.routes["/api/orders/1001"] = lambda _request: (403, {"error": "forbidden"})
        result = run_probe(
            env.gateway,
            "acme",
            "idor",
            {"url": ORDER, "owner_headers": ALICE, "attacker_headers": BOB},
        )
        assert result["status"] == "completed" and result["vulnerable"] is None
        assert result["evidence_capture_ids"]  # it has evidence, and still is not a candidate
        assert from_probe(result, "acme", ORDER) is None
        out = enqueue(env.service, [from_probe(result, "acme", ORDER)], "queue")
        assert out == {
            "ok": True,
            "submitted": 0,
            "created": 0,
            "merged": 0,
            "ids": [],
            "errors": [],
        }
        assert env.store.list("acme") == []
        # Control: the very same result, had the probe said "vulnerable", is a candidate.
        assert (
            from_probe({**result, "vulnerable": True}, "acme", ORDER)["class"] == "access_control"
        )

    @pytest.mark.parametrize("verdict", [None, False, "true", 1, "missing"])
    def test_only_a_true_verdict_counts(self, verdict: Any) -> None:
        result = {
            "probe": "idor",
            "class": "access_control",
            "cwe": "CWE-639",
            "vulnerable": verdict,
        }
        if verdict == "missing":
            del result["vulnerable"]
        assert from_probe(result, "acme", ORDER) is None
        assert from_probe({**result, "vulnerable": True}, "acme", ORDER) is not None

    def test_a_refusal_or_an_error_is_not_a_result(self, env: Env) -> None:
        refused = run_probe(
            env.gateway,
            "acme",
            "idor",
            {"url": "https://evil.example/o/1", "owner_headers": ALICE, "attacker_headers": BOB},
        )
        assert refused["code"] == "OUT_OF_SCOPE"
        assert from_probe(refused, "acme", "https://evil.example/o/1") is None
        assert (
            from_probe(run_probe(env.gateway, "acme", "no-such-probe", {}), "acme", ORDER) is None
        )
        assert from_probe("vulnerable", "acme", ORDER) is None  # type: ignore[arg-type]

    def test_a_given_parameter_wins_and_an_unknown_probe_has_no_assertions(self) -> None:
        result = {
            "probe": "homemade",
            "class": "",
            "cwe": "CWE-918",
            "vulnerable": True,
            "summary": "it fetched the URL",
            "evidence_capture_ids": ["cap-1"],
            "details": {"parameter": "from_details", "captures": {"proof": "cap-1"}},
        }
        candidate = from_probe(result, "acme", FETCH, parameter="url")
        assert candidate["parameter"] == "url" and candidate["class"] == "ssrf"  # from the CWE
        assert candidate["assertions"] == [] and candidate["source"] == "probe:homemade"
        assert from_probe(result, "acme", FETCH)["parameter"] == "from_details"


# ── the ranked surface ──────────────────────────────────────────────


class TestFromRanked:
    RECORDS = {
        "url": [
            {"type": "url", "asset": "app.acme.test", "value": ORDER},
            {"type": "url", "asset": "app.acme.test", "value": f"{BASE}/fetch?url=http://x"},
        ],
        "api_operation": [
            {
                "type": "api_operation",
                "asset": "app.acme.test",
                "value": f"POST {BASE}/api/orders",
                "attrs": {
                    "url": f"{BASE}/api/orders",
                    "method": "post",
                    "request_body_types": ["application/json"],
                },
            }
        ],
    }

    def test_rows_become_low_priority_leads(self, env: Env) -> None:
        rows = rank_candidates(self.RECORDS)
        leads = from_ranked(rows, "acme")
        assert [(lead["class"], lead["method"], lead["endpoint"]) for lead in leads] == [
            ("access_control", "GET", f"{BASE}/api/orders/{{id}}"),
            ("ssrf", "GET", f"{BASE}/fetch"),
            ("api", "POST", f"{BASE}/api/orders"),
        ]
        for lead, row in zip(leads, rows, strict=True):
            assert lead["source"] == "pipeline:surface" and lead["status"] == "candidate"
            assert lead["severity"] == "info" and lead["assertions"] == []
            assert row["why"] in lead["description"] and row["probe"] in lead["description"]
        assert enqueue(env.service, leads, "queue")["created"] == 3

    def test_a_lead_never_comes_before_something_that_can_be_verified(self, env: Env) -> None:
        enqueue(env.service, from_ranked(rank_candidates(self.RECORDS), "acme"), "queue")
        asserted = _lead(1, cls="info_exposure", severity="info", asserted=True)
        enqueue(env.service, [asserted], "queue")
        assert next_candidates(env.store, "acme", limit=1)[0]["title"] == "lead 1"

    def test_rows_that_name_no_class_or_place_are_left_out(self) -> None:
        rows = [
            None,
            {"class": "weather", "where": ORDER, "why": "x", "probe": "idor"},
            {"class": "access_control", "where": "", "why": "x", "probe": "idor"},
        ]
        assert from_ranked(rows, "acme") == []
        good = {"class": "access_control", "where": ORDER, "why": "x", "probe": "idor"}
        assert len(from_ranked([*rows, good], "acme")) == 1


# ── order ───────────────────────────────────────────────────────────


def _lead(
    n: int, *, cls: str = "xss", severity: str = "low", asserted: bool = False, engagement="acme"
) -> dict:
    return {
        "engagement": engagement,
        "title": f"lead {n}",
        "class": cls,
        "severity": severity,
        "endpoint": f"{BASE}/leads/n{n}",
        "source": "agent:hunter",
        "assertions": [A(f"cap-{n}", status=200)] if asserted else [],
    }


class TestOrder:
    # (the rule, what comes first, what comes second). The second is queued FIRST and is
    # better on every later rule, so only the rule under test can put it behind.
    PAIRS = [
        (
            "with assertions before without, whatever the severity",
            {"asserted": True, "severity": "info", "cls": "info_exposure"},
            {"asserted": False, "severity": "critical", "cls": "access_control"},
        ),
        (
            "then severity, whatever the class",
            {"severity": "high", "cls": "info_exposure"},
            {"severity": "medium", "cls": "access_control"},
        ),
        (
            "severity among those with assertions too",
            {"asserted": True, "severity": "low", "cls": "xss"},
            {"asserted": True, "severity": "info", "cls": "access_control"},
        ),
        (
            "then class priority, whatever the age",
            {"severity": "high", "cls": "access_control"},
            {"severity": "high", "cls": "auth_session"},
        ),
        (
            "injection before xss",
            {"severity": "medium", "cls": "injection"},
            {"severity": "medium", "cls": "xss"},
        ),
        (
            "a class the rule names before one it does not",
            {"severity": "medium", "cls": "xss"},
            {"severity": "medium", "cls": "csrf"},
        ),
    ]

    @pytest.mark.parametrize(("rule", "first", "second"), PAIRS, ids=[p[0] for p in PAIRS])
    def test_rule(self, env: Env, rule: str, first: dict, second: dict) -> None:  # noqa: ARG002
        enqueue(env.service, [_lead(2, **second), _lead(1, **first)], "queue")
        assert [row["title"] for row in next_candidates(env.store, "acme")] == ["lead 1", "lead 2"]

    def test_oldest_first_when_everything_else_is_equal(self, env: Env) -> None:
        enqueue(env.service, [_lead(n) for n in (3, 1, 2)], "queue")
        assert [row["title"] for row in next_candidates(env.store, "acme")] == [
            "lead 3",
            "lead 1",
            "lead 2",
        ]

    def test_every_class_has_its_place(self, env: Env) -> None:
        assert list(CLASS_PRIORITY[:8]) == [
            "access_control",
            "auth_session",
            "ssrf",
            "business_logic",
            "api",
            "graphql",
            "injection",
            "xss",
        ]
        assert sorted(CLASS_PRIORITY) == sorted(CLASSES)
        leads = [_lead(n, cls=cls, severity="high") for n, cls in enumerate(sorted(CLASSES))]
        enqueue(env.service, leads, "queue")
        rows = next_candidates(env.store, "acme", limit=50)
        assert [row["class"] for row in rows] == list(CLASS_PRIORITY)

    def test_the_whole_table(self, env: Env) -> None:
        # Queued in this order; the number is the expected position. 3 and 4 differ in age only.
        table = [
            (6, {"severity": "critical", "cls": "access_control"}),
            (3, {"asserted": True, "severity": "high", "cls": "xss"}),
            (8, {"severity": "info", "cls": "access_control"}),
            (1, {"asserted": True, "severity": "critical", "cls": "info_exposure"}),
            (7, {"severity": "high", "cls": "ssrf"}),
            (2, {"asserted": True, "severity": "high", "cls": "auth_session"}),
            (5, {"asserted": True, "severity": "info", "cls": "access_control"}),
            (4, {"asserted": True, "severity": "high", "cls": "xss"}),
        ]
        enqueue(env.service, [_lead(n, **spec) for n, spec in table], "queue")
        rows = next_candidates(env.store, "acme", limit=20)
        assert [row["title"] for row in rows] == [f"lead {n}" for n in range(1, 9)]

    def test_severities_in_order(self, env: Env) -> None:
        enqueue(
            env.service, [_lead(n, severity=s) for n, s in enumerate(sorted(SEVERITIES))], "queue"
        )
        rows = next_candidates(env.store, "acme", limit=20)
        assert [row["severity"] for row in rows] == ["critical", "high", "medium", "low", "info"]

    def test_limit_engagement_and_status(self, env: Env) -> None:
        enqueue(env.service, [_lead(n, severity="high") for n in (1, 2, 3)], "queue")
        enqueue(env.service, [_lead(9, severity="critical", engagement="other")], "queue")
        assert len(next_candidates(env.store, "acme")) == 3
        assert [row["title"] for row in next_candidates(env.store, "acme", limit=2)] == [
            "lead 1",
            "lead 2",
        ]
        assert next_candidates(env.store, "acme", limit=0) == []
        assert [row["title"] for row in next_candidates(env.store, "other")] == ["lead 9"]
        # A decided finding is not in the queue any more.
        first = next_candidates(env.store, "acme", limit=1)[0]["id"]
        env.store.set_status("acme", first, "discarded", actor="verifier")
        assert [row["title"] for row in next_candidates(env.store, "acme")] == ["lead 2", "lead 3"]
        assert env.store.claim("acme", first, "agent:a", lease_seconds=LEASE_SECONDS) is None


# ── claims ──────────────────────────────────────────────────────────


class TestClaims:
    @pytest.fixture
    def queue(self, env: Env) -> list[str]:
        """Three candidates, most valuable first; the clock then stands still at 5000."""
        leads = [_lead(n, severity=s) for n, s in ((1, "critical"), (2, "high"), (3, "medium"))]
        ids = enqueue(env.service, leads, "queue")["ids"]
        env.clock.now, env.clock.step = 5000.0, 0.0
        return ids

    def _next(self, env: Env, who: str = "", limit: int = 1) -> list[str]:
        return _ids(next_candidates(env.store, "acme", limit=limit, claimed_by=who))

    def test_two_agents_do_not_get_the_same_lead(self, env: Env, queue: list[str]) -> None:
        first, second, third = queue
        (mine,) = next_candidates(env.store, "acme", limit=1, claimed_by="agent:a")
        assert mine["id"] == first and mine["claimed_by"] == "agent:a"
        assert mine["claimed_at"] == 5000.0
        assert mine["claim_expires_at"] == 5000.0 + LEASE_SECONDS == 5900.0
        assert self._next(env, "agent:b") == [second]
        # Asking again gives each its own, not the other's.
        assert self._next(env, "agent:a") == [first]
        assert self._next(env, "agent:b") == [second]
        # A caller without a name is not handed what is taken, and takes nothing itself.
        (free,) = next_candidates(env.store, "acme", limit=5)
        assert free["id"] == third and free["claimed_by"] == "" and free["claim_expires_at"] == 0.0
        assert self._next(env, limit=5) == [third]
        assert self._next(env, "agent:c", limit=5) == [third]

    def test_without_a_claim_everybody_gets_the_same_lead(self, env: Env, queue: list[str]) -> None:
        # The control: it is the claim, not the call, that hides a lead.
        assert self._next(env) == self._next(env) == [queue[0]]
        assert self._next(env, "agent:b") == [queue[0]]

    def test_a_claim_expires_after_the_lease(self, env: Env, queue: list[str]) -> None:
        first, second, third = queue
        assert self._next(env, "agent:a") == [first]
        env.clock.now = 5000.0 + LEASE_SECONDS - 1  # one second early: still a's
        assert self._next(env, limit=5) == [second, third]
        assert self._next(env, "agent:b", limit=5) == [second, third]
        env.clock.now = 5000.0 + LEASE_SECONDS
        assert self._next(env) == [first]
        assert self._next(env, "agent:b") == [first]
        # It is b's now: a cannot take it back, and everything else is b's too.
        assert self._next(env, "agent:a", limit=5) == []
        assert self._next(env, limit=5) == []

    def test_asking_again_renews_the_lease(self, env: Env, queue: list[str]) -> None:
        assert self._next(env, "agent:a") == [queue[0]]
        env.clock.now = 5000.0 + LEASE_SECONDS - 1
        assert self._next(env, "agent:a") == [queue[0]]
        env.clock.now = 5000.0 + LEASE_SECONDS + 60  # past the first lease, inside the second
        assert self._next(env, "agent:b") == [queue[1]]

    def test_release_frees_it_and_only_the_holder_can(self, env: Env, queue: list[str]) -> None:
        first, second, _third = queue
        assert self._next(env, "agent:a") == [first]
        assert release(env.store, "acme", first, "agent:b") == {
            "ok": True,
            "id": first,
            "released": False,
        }
        assert self._next(env, "agent:b") == [second]  # still a's
        assert release(env.store, "acme", first, "agent:a")["released"] is True
        assert self._next(env, "agent:b", limit=2) == [first, second]
        assert release(env.store, "acme", first, "")["code"] == "BAD_ACTOR"
        assert release(env.store, "acme", "F-000000000000", "agent:b")["released"] is False

    def test_a_merge_keeps_the_claim_and_a_claim_changes_nothing_else(
        self, env: Env, queue: list[str]
    ) -> None:
        first = queue[0]
        before = env.store.get("acme", first)
        history = len(env.store.events("acme", first))
        assert self._next(env, "agent:a") == [first]
        assert env.store.get("acme", first) == before  # not even updated_at
        assert len(env.store.events("acme", first)) == history
        # The same lead from another producer: the row is rewritten, the claim stays.
        merged = enqueue(
            env.service,
            [{**_lead(1, severity="critical", asserted=True), "source": "probe:idor"}],
            "queue",
        )
        assert merged["merged"] == 1
        assert env.store.get("acme", first).source == "agent:hunter | probe:idor"
        assert first not in self._next(env, "agent:b", limit=5)
        assert self._next(env, "agent:a") == [first]

    def test_a_store_from_before_claims_gains_them_on_open(self, tmp_path: Path) -> None:
        path = tmp_path / "old" / "findings.sqlite3"
        path.parent.mkdir()
        legacy = sqlite3.connect(path)
        # The ``findings`` table as it was before the claim columns.
        legacy.execute(
            "CREATE TABLE findings (id TEXT PRIMARY KEY, engagement TEXT NOT NULL, "
            "title TEXT NOT NULL, class TEXT NOT NULL, cwe TEXT NOT NULL DEFAULT '', "
            "severity TEXT NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'GET', "
            "parameter TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', "
            "description TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '', "
            "assertions TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'candidate', "
            "verification TEXT NOT NULL DEFAULT '{}', grade TEXT, "
            "grade_reasons TEXT NOT NULL DEFAULT '[]', created_at REAL NOT NULL, "
            "updated_at REAL NOT NULL)"
        )
        endpoint = f"{BASE}/api/orders/{{id}}"
        old_id = finding_id("acme", "access_control", endpoint, "")
        legacy.execute(
            "INSERT INTO findings (id, engagement, title, class, severity, endpoint, source, "
            "created_at, updated_at) VALUES (?, 'acme', 'old lead', 'access_control', 'high', "
            "?, 'agent:hunter', 10.0, 10.0)",
            (old_id, endpoint),
        )
        legacy.commit()
        legacy.close()

        def columns() -> set[str]:
            db = sqlite3.connect(path)
            try:
                return {row[1] for row in db.execute("PRAGMA table_info(findings)")}
            finally:
                db.close()

        assert not {"claimed_by", "claimed_at"} & columns()
        # Read-only: nothing is changed, the queue can still be read, nothing is taken.
        reader = FindingStore(path, read_only=True)
        assert _ids(next_candidates(reader, "acme")) == [old_id]
        reader.close()
        assert not {"claimed_by", "claimed_at"} & columns()

        for _ in range(2):  # opening twice adds the columns once
            store = FindingStore(path, clock=lambda: 20.0)
            assert {"claimed_by", "claimed_at"} <= columns()
            assert store.get("acme", old_id).title == "old lead"
            assert _ids(next_candidates(store, "acme", claimed_by="agent:a")) == [old_id]
            assert next_candidates(store, "acme", claimed_by="agent:b") == []
            store.close()


class TestPackage:
    def test_it_imports_without_the_agent_framework_or_the_program_package(self) -> None:
        code = (
            "import sys, buggy.findings.candidates\n"
            "banned = ('langchain', 'langchain_core', 'langgraph', 'deepagents', 'benchmark')\n"
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in banned\n"
            "             or m.startswith(('buggy.program', 'buggy.agents')))\n"
            "assert not bad, bad\n"
        )
        environment = {
            "BUGGY_SKIP_BOOT": "1",
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": ":".join(
                str(REPO_ROOT / "packages" / p) for p in ("buggy", "buggy-core")
            ),
        }
        subprocess.run([sys.executable, "-c", code], check=True, env=environment)
