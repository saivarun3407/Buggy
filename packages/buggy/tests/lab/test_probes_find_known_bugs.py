"""Each probe finds a known bug in a real, intentionally vulnerable application.

These tests start OWASP Juice Shop and DVGA from ``docker-compose.lab.yml``
and run the probes against them through the real capture gateway, with an
enforce-mode scope that lists only those two containers. They are the "lab
test that proves the skill finds a known bug" for the six priority classes,
and the ground-truth entries they reproduce name them in ``verified_by``.

Each class also has a negative case, so a probe that answered "vulnerable"
to everything would fail here.

Opt-in (needs Docker on a Linux host, where bridge addresses are reachable):

    BUGGY_LAB=1 uv run pytest packages/buggy/tests/lab -m lab -q

``LAB_JUICE_SHOP_IMAGE`` / ``LAB_DVGA_IMAGE`` select the images (for a
registry mirror). ``BUGGY_LAB_KEEP=1`` leaves the containers running.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from buggy.capture.canary import Canary
from buggy.capture.gateway import CaptureGateway, GatewayRefusal, Roots
from buggy.capture.probes import run_probe

REPO_ROOT = Path(__file__).resolve().parents[4]
PROJECT = os.environ.get("BUGGY_LAB_PROJECT", "buggy-lab")
ENGAGEMENT = "lab-probes"

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        os.environ.get("BUGGY_LAB") != "1", reason="set BUGGY_LAB=1 to run the lab tests"
    ),
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not available"),
]


@dataclass
class Lab:
    gateway: CaptureGateway
    canary: Canary
    juice: str
    dvga: str
    roots: Roots

    def probe(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        return run_probe(self.gateway, ENGAGEMENT, name, params, canary=self.canary)

    def send_json(
        self, method: str, url: str, body: Any = None, headers: dict[str, str] | None = None
    ) -> Any:
        capture = self.gateway.send(
            ENGAGEMENT,
            method,
            url,
            headers={"Content-Type": "application/json", **(headers or {})},
            body=json.dumps(body) if body is not None else None,
        )
        try:
            return json.loads(capture.response_body)
        except ValueError:
            return {
                "_status": capture.status,
                "_text": capture.response_body.decode("utf-8", "replace")[:300],
            }

    def juice_account(self) -> dict[str, Any]:
        """Register and log in a fresh Juice Shop customer; return token, basket id, email."""
        email = f"lab-{uuid.uuid4().hex[:10]}@juice-sh.op"
        password = "Lab-" + uuid.uuid4().hex[:12]
        self.send_json(
            "POST",
            f"{self.juice}/api/Users",
            {"email": email, "password": password, "passwordRepeat": password},
        )
        auth = self.send_json(
            "POST", f"{self.juice}/rest/user/login", {"email": email, "password": password}
        )["authentication"]
        return {
            "email": email,
            "token": auth["token"],
            "bid": auth["bid"],
            "headers": {"Authorization": f"Bearer {auth['token']}"},
        }


def _compose(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    argv = [
        "docker",
        "compose",
        "-p",
        PROJECT,
        "-f",
        str(REPO_ROOT / "docker-compose.yml"),
        "-f",
        str(REPO_ROOT / "docker-compose.lab.yml"),
        *args,
    ]
    return subprocess.run(argv, cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=False)  # noqa: S603


def _container_ip(service: str) -> str:
    out = subprocess.run(  # noqa: S603, S607
        ["docker", "inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{PROJECT}_lab-net").IPAddress}}}}', f"{PROJECT}-{service}-1"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    return out.stdout.strip()


def _gateway_ip() -> str:
    out = subprocess.run(  # noqa: S603, S607
        ["docker", "network", "inspect", "-f", "{{(index .IPAM.Config 0).Subnet}}", f"{PROJECT}_lab-net"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    base = out.stdout.strip().split("/")[0].rsplit(".", 1)[0]
    return f"{base}.1"


def _wait(url: str, timeout: float = 120.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310
                if response.status < 500:
                    return True
        except OSError:
            time.sleep(2)
    return False


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    home = tmp_path_factory.mktemp("lab-home")
    env = {
        **os.environ,
        "BUGGY_HOME": str(home),
        "SANDBOX_TOKEN": os.environ.get("SANDBOX_TOKEN") or "lab-sandbox-token",
        "EGRESS_GUARD_TOKEN": os.environ.get("EGRESS_GUARD_TOKEN") or "lab-guard-token-0123456789",
    }
    dotenv = REPO_ROOT / ".env"
    created = not dotenv.exists()
    if created:
        dotenv.write_text("")
    for proxy in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        os.environ.pop(proxy, None)  # the targets are local containers
    gateway = None
    canary = Canary()
    try:
        up = _compose("up", "-d", "--no-deps", "juice-shop", "dvga", env=env)
        if up.returncode != 0:
            pytest.skip(f"could not start the lab containers:\n{up.stderr[-800:]}")
        juice = f"http://{_container_ip('juice-shop')}:3000"
        dvga = f"http://{_container_ip('dvga')}:5013"
        if not _wait(f"{juice}/rest/admin/application-version") or not _wait(f"{dvga}/"):
            pytest.skip(
                "lab containers are not reachable from the host (needs a Linux Docker host)"
            )

        roots = Roots(control=home / "control", audit=home / "audit", data=home / "capture")
        (roots.control / ENGAGEMENT).mkdir(parents=True)
        (roots.control / ENGAGEMENT / "roe.json").write_text(
            json.dumps(
                {
                    "engagement_name": ENGAGEMENT,
                    "machine_enforcement": {
                        "mode": "enforce",
                        "in_scope": [
                            juice.split("//")[1].split(":")[0],
                            dvga.split("//")[1].split(":")[0],
                        ],
                    },
                    # Local training targets: state-changing requests need no sign-off here.
                    "approvals": {"state_changing": "not_required"},
                    "pipeline": {"rate_limit_rps": 50},
                }
            )
        )
        port = canary.serve("0.0.0.0", 0)  # noqa: S104 - reachable from the lab bridge only
        canary.base_url = f"http://{_gateway_ip()}:{port}"
        gateway = CaptureGateway(roots)
        # DVGA has a hardened mode toggled by a GET link; make sure it is off
        # whatever touched the container before these tests.
        gateway.send(ENGAGEMENT, "GET", f"{dvga}/difficulty/easy")
        yield Lab(gateway, canary, juice, dvga, roots)
    finally:
        canary.close()
        if gateway is not None:
            gateway.store.close()
        if os.environ.get("BUGGY_LAB_KEEP") != "1":
            _compose("rm", "-sf", "juice-shop", "dvga", env=env)
        if created:
            dotenv.unlink(missing_ok=True)


def _found(result: dict[str, Any]) -> None:
    assert result.get("status") == "completed", result
    assert result["vulnerable"] is True, result
    assert result["evidence_capture_ids"], "a positive verdict must carry evidence"


def _not_found(result: dict[str, Any]) -> None:
    assert result.get("status") == "completed", result
    assert result["vulnerable"] is False, result


# ── scope: the lab's own boundary ────────────────────────────────────


def test_gateway_refuses_anything_outside_the_lab(lab: Lab) -> None:
    for url in (
        "https://example.com/",
        "http://169.254.169.254/latest/meta-data/",
        "http://172.17.0.1/",
    ):
        with pytest.raises(GatewayRefusal) as refused:
            lab.gateway.send(ENGAGEMENT, "GET", url)
        assert refused.value.code == "OUT_OF_SCOPE"


# ── access control / IDOR (Juice Shop: js-idor-basket) ───────────────


def test_idor_probe_finds_basket_idor(lab: Lab) -> None:
    owner, attacker = lab.juice_account(), lab.juice_account()
    assert owner["bid"] != attacker["bid"]
    result = lab.probe(
        "idor",
        {
            "url": f"{lab.juice}/rest/basket/{owner['bid']}",
            "owner_headers": owner["headers"],
            "attacker_headers": attacker["headers"],
        },
    )
    _found(result)
    assert result["class"] == "access_control" and result["cwe"] == "CWE-639"
    assert (
        result["details"]["unauthenticated_status"] == 401
    )  # it is an authz bug, not a missing login


def test_idor_probe_does_not_flag_a_rejected_identity(lab: Lab) -> None:
    owner = lab.juice_account()
    result = lab.probe(
        "idor",
        {
            "url": f"{lab.juice}/rest/basket/{owner['bid']}",
            "owner_headers": owner["headers"],
            "attacker_headers": {"Authorization": "Bearer not-a-token"},
        },
    )
    _not_found(result)


# ── authentication / session (Juice Shop: js-jwt-unsigned) ───────────


def test_jwt_probe_finds_unsigned_token_acceptance(lab: Lab) -> None:
    account = lab.juice_account()
    # /api/Users/<id> sits behind the application's JWT middleware.
    result = lab.probe(
        "jwt_alg_none",
        {"url": f"{lab.juice}/api/Users/1", "token": account["token"]},
    )
    _found(result)
    assert result["class"] == "auth_session"
    assert result["details"]["corrupted_signature_status"] == 401  # signatures ARE checked...
    assert result["details"]["unsigned_status"] == 200  # ...but alg=none skips the check


def test_jwt_probe_does_not_flag_a_route_that_binds_tokens_to_sessions(lab: Lab) -> None:
    # The basket route also requires the token to belong to a live login, so
    # the unsigned copy is rejected there. Same application, safe endpoint.
    account = lab.juice_account()
    result = lab.probe(
        "jwt_alg_none",
        {"url": f"{lab.juice}/rest/basket/{account['bid']}", "token": account["token"]},
    )
    _not_found(result)


def test_jwt_probe_cannot_tell_without_a_working_token(lab: Lab) -> None:
    # No valid token for this endpoint: the probe must say "cannot tell", not "vulnerable".
    result = lab.probe("jwt_alg_none", {"url": f"{lab.juice}/rest/basket/1", "token": "a.b.c"})
    assert result["status"] == "completed" and result["vulnerable"] is None


# ── SSRF (Juice Shop: js-ssrf-profile-image) ─────────────────────────


def test_ssrf_probe_finds_profile_image_ssrf(lab: Lab) -> None:
    account = lab.juice_account()
    result = lab.probe(
        "ssrf_canary",
        {
            "url": f"{lab.juice}/profile/image/url",
            "method": "POST",
            "headers": {
                "Cookie": f"token={account['token']}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": "imageUrl={{CANARY}}",
            "wait_seconds": 15,
        },
    )
    _found(result)
    callback = result["details"]["callbacks"][0]
    assert (
        callback["remote"] == lab.juice.split("//")[1].split(":")[0]
    )  # the hit came from the target


def test_ssrf_probe_does_not_flag_an_endpoint_that_stores_text(lab: Lab) -> None:
    account = lab.juice_account()
    result = lab.probe(
        "ssrf_canary",
        {
            "url": f"{lab.juice}/api/Feedbacks/",
            "method": "POST",
            "headers": account["headers"],
            "body": {"comment": "see {{CANARY}}", "rating": 3, "captchaId": 0, "captcha": "0"},
            "wait_seconds": 4,
        },
    )
    _not_found(result)


# ── business logic (Juice Shop: js-negative-quantity) ────────────────


def test_boundary_probe_finds_negative_quantity(lab: Lab) -> None:
    account = lab.juice_account()
    result = lab.probe(
        "numeric_boundary",
        {
            "url": f"{lab.juice}/api/BasketItems/",
            "method": "POST",
            "headers": account["headers"],
            "body": {"ProductId": 1, "BasketId": str(account["bid"]), "quantity": 1},
            "field": "quantity",
            "values": [-100],
        },
    )
    _found(result)
    assert result["details"]["accepted"][0]["echoed_in_response"] is True


def test_boundary_probe_does_not_flag_a_validated_field(lab: Lab) -> None:
    # Product reviews require authentication; without it every value is rejected.
    result = lab.probe(
        "numeric_boundary",
        {
            "url": f"{lab.juice}/api/BasketItems/",
            "method": "POST",
            "body": {"ProductId": 1, "BasketId": "1", "quantity": 1},
            "field": "quantity",
            "values": [-1, 0],
        },
    )
    _not_found(result)


# ── API: mass assignment (Juice Shop: js-mass-assignment-admin) ──────


def test_mass_assignment_probe_finds_admin_registration(lab: Lab) -> None:
    email = f"lab-admin-{uuid.uuid4().hex[:8]}@juice-sh.op"
    result = lab.probe(
        "mass_assignment",
        {
            "url": f"{lab.juice}/api/Users",
            "body": {"email": email, "password": "Lab-pass-123", "passwordRepeat": "Lab-pass-123"},
            "extra_fields": {"role": "admin"},
        },
    )
    _found(result)
    assert result["details"]["reflected_in_response"] == {"role": "admin"}


def test_mass_assignment_probe_does_not_flag_an_ignored_field(lab: Lab) -> None:
    email = f"lab-plain-{uuid.uuid4().hex[:8]}@juice-sh.op"
    result = lab.probe(
        "mass_assignment",
        {
            "url": f"{lab.juice}/api/Users",
            "body": {"email": email, "password": "Lab-pass-123", "passwordRepeat": "Lab-pass-123"},
            "extra_fields": {"labNonexistentField": "x"},
        },
    )
    _not_found(result)


# ── GraphQL (DVGA: dvga-introspection, dvga-field-suggestions, dvga-private-pastes) ──


def test_graphql_probe_finds_introspection_suggestions_and_private_data(lab: Lab) -> None:
    result = lab.probe(
        "graphql_checks",
        {
            "url": f"{lab.dvga}/graphql",
            "unauthenticated_query": "query { pastes(public: false) { id title public } }",
        },
    )
    _found(result)
    assert result["details"]["introspection_enabled"] is True
    assert result["details"]["field_suggestions"] is True
    assert result["details"]["unauthenticated_data_returned"] is True
    assert result["class"] == "access_control"


def test_graphql_probe_does_not_flag_a_rest_endpoint(lab: Lab) -> None:
    result = lab.probe("graphql_checks", {"url": f"{lab.juice}/rest/products/search?q=apple"})
    _not_found(result)


# ── evidence ─────────────────────────────────────────────────────────


def test_evidence_is_replayable_and_bound_to_the_target(lab: Lab) -> None:
    owner, attacker = lab.juice_account(), lab.juice_account()
    result = lab.probe(
        "idor",
        {
            "url": f"{lab.juice}/rest/basket/{owner['bid']}",
            "owner_headers": owner["headers"],
            "attacker_headers": attacker["headers"],
        },
    )
    attacker_capture = result["evidence_capture_ids"][1]
    verdict = lab.gateway.verify(ENGAGEMENT, attacker_capture, expect_host=lab.juice)
    assert verdict["valid"] is True
    assert lab.gateway.verify(ENGAGEMENT, attacker_capture, expect_host=lab.dvga)["valid"] is False
    replay = lab.gateway.replay(ENGAGEMENT, attacker_capture)
    assert replay["reproduced"] is True and replay["same_body"] is True

    from buggy.middleware._audit_sink import verify_ledger

    assert verify_ledger(lab.roots.audit / ENGAGEMENT / "captures.jsonl").ok


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])
