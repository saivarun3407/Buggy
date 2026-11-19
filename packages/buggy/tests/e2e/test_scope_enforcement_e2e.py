"""End-to-end scope enforcement on the real compose stack.

What runs for real:

* ``docker-compose.yml``'s ``egress-guard`` and ``sandbox`` services, with
  their shipped networks, capabilities, entrypoint, tunnel and DNS wiring
  (``docker-compose.e2e.yml`` adds two local HTTP targets and, by default,
  swaps the multi-gigabyte Kali image for a slim one running the same
  entrypoint and daemon code).
* The shipped :class:`RoEGuardrailMiddleware`, driven from this process the
  way the langgraph service drives it: it reads the operator-controlled
  ``roe.json``, provisions the guard over its control API, writes the audit
  ledger, and its tool handler executes commands through the sandbox daemon.

What is asserted: an out-of-scope request the command parser cannot see is
dropped at the network and logged; the agent cannot alter the boundary; and a
boundary that cannot be provisioned stops the run.

Opt-in (needs a Linux Docker host, where the host can reach bridge addresses):

    BUGGY_E2E=1 uv run pytest packages/buggy/tests/e2e -m e2e -q

Set ``BUGGY_E2E_NO_BUILD=1`` to use already-built images.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import ToolMessage

REPO_ROOT = Path(__file__).resolve().parents[4]
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.e2e.yml")
PROJECT = "buggy-e2e"
SLUG = "acme"

IN_SCOPE_HOST = "in-scope.test"
OUT_OF_SCOPE_HOST = "out-of-scope.test"
OUT_OF_SCOPE_IP = "172.30.251.20"
IN_MARKER = "IN-SCOPE-TARGET-OK"
OUT_MARKER = "OUT-OF-SCOPE-TARGET-REACHED"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        os.environ.get("BUGGY_E2E") != "1", reason="set BUGGY_E2E=1 to run the compose e2e tests"
    ),
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not available"),
]


@dataclass
class Stack:
    home: Path
    env: dict[str, str]
    sandbox_url: str
    sandbox_token: str
    guard_url: str
    guard_token: str
    hmac_key: str

    @property
    def control(self) -> Path:
        return self.home / "control"

    @property
    def audit(self) -> Path:
        return self.home / "audit"

    def compose(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        argv = ["docker", "compose", "-p", PROJECT]
        for name in COMPOSE_FILES:
            argv += ["-f", str(REPO_ROOT / name)]
        return subprocess.run(  # noqa: S603
            [*argv, *args], cwd=REPO_ROOT, env=self.env, capture_output=True, text=True, check=check
        )

    def guard_ledger(self) -> list[dict]:
        path = self.audit / "egress-guard" / "egress-decisions.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def flush_drops(self) -> None:
        request = urllib.request.Request(  # noqa: S310
            f"{self.guard_url}/flush-drops",
            data=b"{}",
            method="POST",
            headers={"Authorization": f"Bearer {self.guard_token}"},
        )
        with urllib.request.urlopen(request, timeout=10):  # noqa: S310
            pass


def _inspect_ip(container: str, network: str) -> str:
    out = subprocess.run(  # noqa: S603, S607
        [
            "docker",
            "inspect",
            "-f",
            f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
            container,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def _wait_http(url: str, timeout: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310
                if response.status == 200:
                    return True
        except (OSError, urllib.error.URLError):
            time.sleep(1)
    return False


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    home = tmp_path_factory.mktemp("buggy-e2e-home")
    for name in ("workspace", "control", "audit"):
        (home / name).mkdir()
    sandbox_token, guard_token, hmac_key = (secrets.token_hex(32) for _ in range(3))
    env = {
        **os.environ,
        "BUGGY_HOME": str(home),
        "BUGGY_STACK_NAME": "e2e",
        "SANDBOX_TOKEN": sandbox_token,
        "EGRESS_GUARD_TOKEN": guard_token,
        "BUGGY_STACK_MCP_TOKEN": secrets.token_hex(32),
        "BUGGY_AUDIT_HMAC_KEY": hmac_key,
    }
    # compose validates every service's env_file, including ones we never start.
    dotenv = REPO_ROOT / ".env"
    created_dotenv = not dotenv.exists()
    if created_dotenv:
        dotenv.write_text("")

    partial = Stack(home, env, "", sandbox_token, "", guard_token, hmac_key)
    services = ["egress-guard", "sandbox", "target-in", "target-out"]
    try:
        partial.compose("down", "-v", "--remove-orphans", check=False)
        if os.environ.get("BUGGY_E2E_NO_BUILD") != "1":
            partial.compose("build", "egress-guard", "sandbox")
        up = partial.compose("up", "-d", "--no-deps", "--no-build", *services, check=False)
        if up.returncode != 0:
            pytest.fail(f"compose up failed:\n{up.stderr}")

        guard_ip = _inspect_ip("buggy-e2e-egress-guard", f"{PROJECT}_buggy-net")
        sandbox_ip = _inspect_ip("buggy-e2e-sandbox", f"{PROJECT}_sandbox-net")
        partial.guard_url = f"http://{guard_ip}:9440"
        partial.sandbox_url = f"http://{sandbox_ip}:9999"
        if not _wait_http(f"{partial.guard_url}/healthz") or not _wait_http(
            f"{partial.sandbox_url}/healthz"
        ):
            logs = partial.compose("logs", "--no-color", "--tail", "60", check=False).stdout
            pytest.skip(
                "the host cannot reach the stack's bridge addresses (needs a Linux Docker "
                f"host) or the services did not start:\n{logs}"
            )
        yield partial
    finally:
        if os.environ.get("BUGGY_E2E_KEEP") != "1":
            partial.compose("down", "-v", "--remove-orphans", check=False)
        if created_dotenv:
            dotenv.unlink(missing_ok=True)


@pytest.fixture
def engagement(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Process env + state as the langgraph service has them (see docker-compose.yml)."""
    monkeypatch.setenv("BUGGY_ROE_REQUIRE", "1")
    monkeypatch.delenv("BUGGY_EGRESS_DISABLE", raising=False)
    monkeypatch.delenv("BENCHMARK_MODE", raising=False)
    monkeypatch.setenv("BUGGY_WORKSPACE_ROOT", "/workspace")
    monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(stack.control))
    monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(stack.audit))
    monkeypatch.setenv("BUGGY_AUDIT_HMAC_KEY", stack.hmac_key)
    monkeypatch.setenv("BUGGY_EGRESS_GUARD_URL", stack.guard_url)
    monkeypatch.setenv("EGRESS_GUARD_TOKEN", stack.guard_token)
    monkeypatch.setenv("SANDBOX_URL", stack.sandbox_url)
    monkeypatch.setenv("SANDBOX_TOKEN", stack.sandbox_token)
    monkeypatch.setenv("BUGGY_OSINT_EGRESS_HOSTS", "")
    return {"workspace_path": f"/workspace/{SLUG}", "engagement_name": SLUG}


def _write_roe(stack: Stack, block: dict) -> None:
    path = stack.control / SLUG / "roe.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"engagement_name": SLUG, "machine_enforcement": block}))


def _enforcing_roe(stack: Stack) -> None:
    _write_roe(stack, {"mode": "enforce", "in_scope": [IN_SCOPE_HOST]})


def _request(command: str, state: dict[str, str]) -> MagicMock:
    request = MagicMock()
    request.tool = MagicMock()
    request.tool.name = "bash"
    request.state = state
    request.tool_call = MagicMock()
    request.tool_call.args = {"command": command}
    request.tool_call.id = "tc-e2e"
    request.tool_call_args = {"command": command}
    request.tool_call_id = "tc-e2e"
    return request


def _sandbox_handler(request) -> ToolMessage:
    """What the bash tool does: run the command through the sandbox daemon."""
    from buggy.backends.factory import build_sandbox_backend

    result = build_sandbox_backend().execute(request.tool_call_args["command"], timeout=40)
    return ToolMessage(content=result.output, tool_call_id="tc-e2e")


def _run(mw, command: str, state: dict[str, str]) -> str:
    return str(mw.wrap_tool_call(_request(command, state), _sandbox_handler).content)


def _sandbox_exec(stack: Stack, command: str) -> str:
    request = urllib.request.Request(  # noqa: S310
        f"{stack.sandbox_url}/execute",
        data=json.dumps({"command": command, "timeout": 40}).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {stack.sandbox_token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return str(json.loads(response.read())["output"])


# The tests run in file order against one stack: the guard starts LOCKED and
# is provisioned by the first test that calls ``before_agent``.


def test_01_sandbox_daemon_requires_its_token(stack: Stack) -> None:
    request = urllib.request.Request(  # noqa: S310
        f"{stack.sandbox_url}/execute",
        data=b'{"command": "id"}',
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, timeout=10)  # noqa: S310
    assert excinfo.value.code == 401


def test_02_nothing_leaves_before_a_policy_is_provisioned(stack: Stack) -> None:
    output = _sandbox_exec(stack, f"curl -sS -m 5 http://{IN_SCOPE_HOST}/; echo rc=$?")
    assert IN_MARKER not in output
    output = _sandbox_exec(stack, "curl -sS -m 5 http://172.30.251.10/; echo rc=$?")
    assert IN_MARKER not in output
    assert any(
        r["event"] == "dns_refused" and r["reason"] == "no_policy" for r in stack.guard_ledger()
    )


def test_03_agent_cannot_alter_the_boundary(stack: Stack) -> None:
    output = _sandbox_exec(
        stack,
        "grep CapBnd /proc/self/status; "
        "nft list ruleset >/dev/null 2>&1; echo nft_rc=$?; "
        "nft add table inet x >/dev/null 2>&1; echo nftadd_rc=$?; "
        "ip route replace default via 172.30.250.1 >/dev/null 2>&1; echo route_rc=$?; "
        "ip link del bgtun0 >/dev/null 2>&1; echo linkdel_rc=$?; "
        "ip route | head -1",
    )
    bounding = int(output.split("CapBnd:")[1].split()[0], 16)
    assert not bounding & (1 << 12), "CAP_NET_ADMIN must not be in the bounding set"
    assert not bounding & (1 << 8), "CAP_SETPCAP must not be in the bounding set"
    for name in ("nft_rc", "nftadd_rc", "route_rc", "linkdel_rc"):
        assert f"{name}=0" not in output, output
    assert "default via 10.254.250.1 dev bgtun0" in output


def test_04_missing_scope_refuses_and_does_not_execute(stack: Stack, engagement) -> None:
    from buggy.middleware.roe import RoEGuardrailMiddleware

    (stack.control / SLUG / "roe.json").unlink(missing_ok=True)
    handler = MagicMock()
    result = RoEGuardrailMiddleware().wrap_tool_call(
        _request(f"curl http://{IN_SCOPE_HOST}/", engagement), handler
    )
    assert not handler.called
    assert "INVALID_ROE" in result.content


def test_05_provisioning_failure_aborts_the_run(stack: Stack, engagement, monkeypatch) -> None:
    from buggy.middleware.egress import EgressProvisioningError
    from buggy.middleware.roe import RoEGuardrailMiddleware

    _enforcing_roe(stack)
    monkeypatch.setenv("EGRESS_GUARD_TOKEN", "0" * 64)
    with pytest.raises(EgressProvisioningError, match="HTTP 401"):
        RoEGuardrailMiddleware().before_agent(engagement, runtime=None)
    monkeypatch.setenv("EGRESS_GUARD_TOKEN", stack.guard_token)
    monkeypatch.setenv("BUGGY_EGRESS_GUARD_URL", "http://127.0.0.1:9")
    with pytest.raises(EgressProvisioningError, match="unreachable"):
        RoEGuardrailMiddleware().before_agent(engagement, runtime=None)
    # The guard was never given a policy, so it is still closed.
    assert IN_MARKER not in _sandbox_exec(stack, f"curl -sS -m 5 http://{IN_SCOPE_HOST}/")


def test_06_in_scope_request_succeeds(stack: Stack, engagement) -> None:
    from buggy.middleware.roe import RoEGuardrailMiddleware

    _enforcing_roe(stack)
    mw = RoEGuardrailMiddleware()
    mw.before_agent(engagement, runtime=None)
    assert IN_MARKER in _run(mw, f"curl -sS -m 10 http://{IN_SCOPE_HOST}/", engagement)


def test_07_visible_out_of_scope_request_is_refused_before_execution(
    stack: Stack, engagement
) -> None:
    from buggy.middleware.roe import RoEGuardrailMiddleware

    _enforcing_roe(stack)
    mw = RoEGuardrailMiddleware()
    mw.before_agent(engagement, runtime=None)
    handler = MagicMock()
    result = mw.wrap_tool_call(
        _request(f"curl -sS http://{OUT_OF_SCOPE_HOST}/", engagement), handler
    )
    assert not handler.called
    assert "[ROE_REFUSED]" in result.content and "NOT_IN_SCOPE" in result.content


def test_08_hidden_out_of_scope_request_is_dropped_and_logged(stack: Stack, engagement) -> None:
    """The case the parser cannot catch: the target is assembled at run time."""
    from buggy.middleware.roe import RoEGuardrailMiddleware

    _enforcing_roe(stack)
    mw = RoEGuardrailMiddleware()
    mw.before_agent(engagement, runtime=None)
    before = len(stack.guard_ledger())

    by_name = _run(
        mw, 'h=$(printf "out-of-%s.test" scope); curl -sS -m 6 "http://$h/"; echo rc=$?', engagement
    )
    by_ip = _run(
        mw, 'ip=$(printf "172.30.251.%d" 20); curl -sS -m 6 "http://$ip/"; echo rc=$?', engagement
    )
    # Both commands passed the parser and really ran in the sandbox...
    assert "[ROE_REFUSED]" not in by_name and "rc=" in by_name
    assert "[ROE_REFUSED]" not in by_ip and "rc=" in by_ip
    # ...and neither reached the out-of-scope target.
    assert OUT_MARKER not in by_name and "rc=0" not in by_name
    assert OUT_MARKER not in by_ip and "rc=0" not in by_ip

    stack.flush_drops()
    new = stack.guard_ledger()[before:]
    refused = [r for r in new if r["event"] == "dns_refused" and r["qname"] == OUT_OF_SCOPE_HOST]
    dropped = [r for r in new if r["event"] == "egress_drop" and r["dst_ip"] == OUT_OF_SCOPE_IP]
    assert refused and refused[0]["reason"] == "not_in_scope"
    assert dropped, f"no egress_drop for {OUT_OF_SCOPE_IP} in {new}"
    assert dropped[0]["dport"] == 80 and dropped[0]["proto"] == "tcp"
    assert dropped[0]["engagement"] == SLUG and dropped[0]["decision"] == "drop"


def test_09_direct_and_management_paths_are_closed(stack: Stack, engagement) -> None:
    from buggy.middleware.roe import RoEGuardrailMiddleware

    _enforcing_roe(stack)
    mw = RoEGuardrailMiddleware()
    mw.before_agent(engagement, runtime=None)
    guard_ip = stack.guard_url.split("//")[1].split(":")[0]
    output = _sandbox_exec(
        stack,
        # Skip the tunnel and go out of the sandbox network's own interface.
        "curl -sS -m 4 --interface eth0 http://172.30.251.10/; echo direct_rc=$?; "
        # The guard's control API, on both of its addresses.
        f"curl -sS -m 4 http://{guard_ip}:9440/healthz; echo ctl_rc=$?; "
        "curl -sS -m 4 http://172.30.250.2:9440/healthz; echo ctl2_rc=$?",
    )
    assert IN_MARKER not in output
    for name in ("direct_rc", "ctl_rc", "ctl2_rc"):
        assert f"{name}=0" not in output, output


def test_10_scope_change_reaches_the_boundary(stack: Stack, engagement) -> None:
    from buggy.middleware.roe import RoEGuardrailMiddleware

    _enforcing_roe(stack)
    mw = RoEGuardrailMiddleware()
    mw.before_agent(engagement, runtime=None)
    # The operator adds the second host; the agent did not and cannot.
    _write_roe(stack, {"mode": "enforce", "in_scope": [IN_SCOPE_HOST, OUT_OF_SCOPE_HOST]})
    assert OUT_MARKER in _run(mw, f"curl -sS -m 10 http://{OUT_OF_SCOPE_HOST}/", engagement)
    # And removes it again.
    _enforcing_roe(stack)
    handler = MagicMock()
    result = mw.wrap_tool_call(_request(f"curl http://{OUT_OF_SCOPE_HOST}/", engagement), handler)
    assert not handler.called and "NOT_IN_SCOPE" in result.content
    hidden = _run(mw, 'h=out-of-scope; curl -sS -m 6 "http://$h.test/"; echo rc=$?', engagement)
    assert OUT_MARKER not in hidden


def test_11_ledgers_are_written_outside_the_sandbox_and_verify(stack: Stack, engagement) -> None:
    from buggy.middleware._audit_sink import iter_records, verify_ledger

    key = stack.hmac_key.encode()
    roe_ledger = stack.audit / SLUG / "roe-decisions.jsonl"
    guard_ledger = stack.audit / "egress-guard" / "egress-decisions.jsonl"
    assert verify_ledger(roe_ledger, hmac_key=key).ok
    assert verify_ledger(guard_ledger, hmac_key=key).ok
    records = list(iter_records(roe_ledger))
    assert any(r.get("event") == "egress_provisioned" for r in records)
    assert any(r.get("reason_code") == "NOT_IN_SCOPE" for r in records)
    # The sandbox has the control root read-only and no audit root at all.
    output = _sandbox_exec(
        stack,
        f"cat /control/{SLUG}/roe.json | head -c 40; echo; "
        f"echo x > /control/{SLUG}/roe.json; echo write_rc=$?; ls /audit 2>&1; echo ls_rc=$?",
    )
    assert "machine_enforcement" in output or "engagement_name" in output
    assert "write_rc=0" not in output
    assert "ls_rc=0" not in output


def test_12_blocked_sandbox_has_no_path_even_to_an_in_scope_target(
    stack: Stack, engagement
) -> None:
    """``sandbox_egress: blocked``: targets are reachable only through the gateway."""
    from buggy.middleware.roe import RoEGuardrailMiddleware

    _write_roe(stack, {"mode": "enforce", "in_scope": [IN_SCOPE_HOST], "sandbox_egress": "blocked"})
    mw = RoEGuardrailMiddleware()
    mw.before_agent(engagement, runtime=None)
    before = len(stack.guard_ledger())

    # A command that names the target is refused before it runs, with the alternative.
    visible = _run(mw, f"curl -sS -m 6 http://{IN_SCOPE_HOST}/", engagement)
    assert "SANDBOX_NETWORK_BLOCKED" in visible and "http_send" in visible
    assert IN_MARKER not in visible

    # A command that hides the target runs, and the network drops it.
    hidden = _run(
        mw, 'h=$(printf "in-%s.test" scope); curl -sS -m 6 "http://$h/"; echo rc=$?', engagement
    )
    assert "[ROE_REFUSED]" not in hidden and "rc=" in hidden
    assert IN_MARKER not in hidden and "rc=0" not in hidden
    stack.flush_drops()
    refused = [
        r
        for r in stack.guard_ledger()[before:]
        if r["event"] == "dns_refused" and r["qname"] == IN_SCOPE_HOST
    ]
    assert refused, "the guard did not log the blocked in-scope lookup"

    # Work that needs no network is unaffected.
    assert "OFFLINE" in _run(mw, "echo offline | tr a-z A-Z", engagement)

    # The operator lifts the block: the same sandbox can reach the target again.
    _enforcing_roe(stack)
    assert IN_MARKER in _run(mw, f"curl -sS -m 10 http://{IN_SCOPE_HOST}/", engagement)
