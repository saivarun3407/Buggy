"""The authorization matrix finds the basket IDOR in a real Juice Shop.

Two customers are registered through the capture gateway and each puts a
product in a basket. They are declared as ``static`` identities in a secrets
root made for this test, next to a third identity whose token is not a
session at all. The matrix then asks for both baskets and for
``/rest/user/whoami`` as everybody.

Juice Shop returns any basket to any logged-in customer (ground truth
``js-idor-basket``), so each basket must come out ``broken_access`` with the
other customer as the one who received it. ``whoami`` answers every caller
with the caller's own profile, the identity without a session is refused,
and neither may be flagged.

Opt-in, like the other lab tests:

    BUGGY_LAB=1 uv run pytest packages/buggy/tests/lab/test_authz_matrix_lab.py -q
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from typing import Any

import pytest

from buggy.capture.authz_matrix import ANONYMOUS, PROBE, run_matrix
from buggy.capture.identities import IdentityStore, SessionManager

from .test_probes_find_known_bugs import ENGAGEMENT, Lab, lab  # noqa: F401 - `lab` is a fixture

_SHARED_LAB = bool(os.environ.get("BUGGY_LAB_JUICE_URL") and os.environ.get("BUGGY_LAB_DVGA_URL"))

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        os.environ.get("BUGGY_LAB") != "1", reason="set BUGGY_LAB=1 to run the lab tests"
    ),
    pytest.mark.skipif(
        not _SHARED_LAB and shutil.which("docker") is None, reason="docker CLI not available"
    ),
]


@dataclass
class Shop:
    lab: Lab
    alice: dict[str, Any]
    bob: dict[str, Any]
    whoami: str

    def basket(self, account: dict[str, Any]) -> str:
        return f"{self.lab.juice}/rest/basket/{account['bid']}"

    def matrix(self, urls: list[str], identities: list[str], **kwargs: Any) -> dict[str, Any]:
        gateway = self.lab.gateway
        return run_matrix(
            gateway, gateway.sessions, ENGAGEMENT, urls, identities=identities, **kwargs
        )

    def body(self, capture_id: str) -> str:
        capture = self.lab.gateway.store.get(ENGAGEMENT, capture_id)
        assert capture is not None
        return capture.response_body.decode("utf-8", "replace")


@pytest.fixture(scope="module")
def shop(lab: Lab, tmp_path_factory: pytest.TempPathFactory) -> Shop:  # noqa: F811
    alice, bob = lab.juice_account(), lab.juice_account()
    assert alice["bid"] != bob["bid"]
    # Something in each basket, so that the two are not alike. The lab engagement
    # needs no approval for this; the matrix itself only ever reads.
    for account, product in ((alice, 1), (bob, 24)):
        added = lab.send_json(
            "POST",
            f"{lab.juice}/api/BasketItems/",
            {"ProductId": product, "BasketId": str(account["bid"]), "quantity": 1},
            account["headers"],
        )
        assert added.get("status") == "success", added

    def customer(name: str, account: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": name,
            "role": "customer",
            "owner_of": [f"{lab.juice}/rest/basket/{account['bid']}"],
            "static": {
                "headers": {"Authorization": f"Bearer {account['token']}"},
                # whoami reads the session from this cookie, not from the header.
                "cookies": {"token": account["token"]},
            },
        }

    secrets = tmp_path_factory.mktemp("lab-secrets")
    (secrets / ENGAGEMENT).mkdir()
    (secrets / ENGAGEMENT / "identities.json").write_text(
        json.dumps(
            {
                "identities": [
                    customer("alice", alice),
                    customer("bob", bob),
                    {
                        "name": "mallory",
                        "role": "nobody",
                        "static": {"headers": {"Authorization": "Bearer not-a-token"}},
                    },
                ]
            }
        )
    )
    # The lab's gateway was built without a secrets root; give it this one.
    lab.gateway.identities = IdentityStore(secrets)
    lab.gateway.sessions = SessionManager(lab.gateway, lab.gateway.identities)
    return Shop(lab, alice, bob, f"{lab.juice}/rest/user/whoami")


def test_matrix_finds_the_basket_idor_both_ways(shop: Shop) -> None:
    mine, theirs = shop.basket(shop.alice), shop.basket(shop.bob)
    result = shop.matrix([mine, theirs, shop.whoami], ["alice", "bob", "mallory"])
    assert result["skipped"] == [] and result["skipped_identities"] == {}
    assert result["truncated"] is False

    for url, owner, other in ((mine, "alice", "bob"), (theirs, "bob", "alice")):
        verdict = result["verdicts"][url]
        assert verdict["verdict"] == "broken_access", verdict
        assert verdict["owner"] == owner  # from the identity's owner_of
        # The other customer got it. The bad token and the missing token did not.
        assert verdict["exposed_to"] == [other]
        row = result["matrix"][url]
        assert row[owner]["status"] == 200 and row[other]["status"] == 200
        assert row[other]["similarity_to_owner"] >= 0.95
        assert row["mallory"]["status"] == 401 and row[ANONYMOUS]["status"] == 401

    assert sorted(c["endpoint"] for c in result["candidates"]) == sorted([mine, theirs])
    candidate = next(c for c in result["candidates"] if c["endpoint"] == mine)
    assert candidate["class"] == "access_control" and candidate["cwe"] == "CWE-639"
    assert candidate["status"] == "candidate"
    owner, attacker = candidate["assertions"]
    assert (owner["identity"], attacker["identity"]) == ("alice", "bob")
    assert attacker["expect"]["status"] == 200
    assert attacker["expect"]["same_as"] == owner["capture_id"]
    # What bob was sent is alice's basket, product and all.
    received = json.loads(shop.body(attacker["capture_id"]))["data"]
    assert received["id"] == shop.alice["bid"]
    assert [p["id"] for p in received["Products"]] == [1]
    sent = shop.lab.gateway.store.get(ENGAGEMENT, attacker["capture_id"])
    assert sent is not None
    assert sent.identity == "bob" and sent.method == "GET" and sent.url == mine

    # The evidence can be reproduced by the gateway, as bob.
    replay = shop.lab.gateway.replay(ENGAGEMENT, attacker["capture_id"])
    assert replay["reproduced"] is True and replay["same_body"] is True

    # Neither customer's token is in what the matrix returns or in a capture's detail.
    dumped = json.dumps(result) + json.dumps(sent.detail())
    assert shop.alice["token"] not in dumped and shop.bob["token"] not in dumped


def test_whoami_is_not_a_candidate(shop: Shop) -> None:
    result = shop.matrix([shop.whoami], ["alice", "bob", "mallory"])
    assert result["candidates"] == []
    assert result["verdicts"][shop.whoami]["verdict"] not in ("broken_access", "public")
    # The endpoint did hand out private data, each caller's own, so this is a
    # real negative: there was something to flag and the matrix did not.
    row = result["matrix"][shop.whoami]
    assert shop.alice["email"] in shop.body(row["alice"]["capture_id"])
    assert shop.alice["email"] not in shop.body(row["bob"]["capture_id"])
    assert shop.bob["email"] in shop.body(row["bob"]["capture_id"])
    for nobody in ("mallory", ANONYMOUS):
        body = shop.body(row[nobody]["capture_id"])
        assert shop.alice["email"] not in body and shop.bob["email"] not in body


def test_basket_is_enforced_against_an_identity_without_a_session(shop: Shop) -> None:
    # The same basket and the same code path, but nobody with a session other than
    # the owner asks. The matrix must report what it saw: the basket was refused.
    mine = shop.basket(shop.alice)
    result = shop.matrix([mine], ["alice", "mallory"])
    assert result["verdicts"][mine]["verdict"] == "enforced", result["verdicts"][mine]
    assert result["candidates"] == []
    assert [cell["status"] for cell in result["matrix"][mine].values()] == [200, 401, 401]
    assert result["requests"] == 4  # the owner twice, mallory, no credentials


def test_matrix_only_reads(shop: Shop) -> None:
    before = {c.id for c in shop.lab.gateway.store.list(ENGAGEMENT, limit=500)}
    result = shop.matrix(
        [shop.basket(shop.alice), f"POST {shop.lab.juice}/api/BasketItems/"],
        ["alice", "bob"],
    )
    new = [c for c in shop.lab.gateway.store.list(ENGAGEMENT, limit=500) if c.id not in before]
    assert len(new) == result["requests"] == 4
    assert {c.method for c in new} == {"GET"} and {c.probe for c in new} == {PROBE}
    (skipped,) = result["skipped"]
    assert skipped["method"] == "POST" and "change state" in skipped["reason"]
