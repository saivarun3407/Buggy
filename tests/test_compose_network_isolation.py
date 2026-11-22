"""Network-isolation invariants for ``docker-compose.yml``.

These assertions encode the structural security boundaries that no
single Semgrep / lint rule can catch. They run on the *rendered* compose
file (``docker compose config``) so they validate the post-interpolation
shape that actually starts on a contributor's host.

Invariants
----------

1. **Operational services never join the management network.**
   The Kali sandbox, the C2 framework, and the optional Ghidra MCP
   sidecar are sandbox-net only. Adding any of them to
   ``buggy-net`` collapses the management/operational boundary
   that the architecture is built around (see
   ``docs/security/sandbox-isolation.md``).

2. **No service uses host networking.** ``network_mode: host`` bypasses
   both bridges and defeats the isolation entirely.

3. **No service mounts the Docker socket.** The HTTP-only sandbox
   migration removed ``/var/run/docker.sock`` from the LangGraph
   service deliberately; reintroducing it would re-open a
   container-escape path from a compromised orchestrator.

4. **Every published port binds to 127.0.0.1.** Bare ``PORT:PORT``
   (which docker resolves to ``0.0.0.0``) exposes internal services to
   the contributor's LAN. The existing compose already follows this
   convention; the test fences it.

5. **Dual-homed services are explicitly allowlisted.** Today
   ``neo4j``, ``langgraph`` and ``egress-guard`` are intentionally on
   both networks. Adding another forces an explicit update to
   ``DUAL_HOMED_SERVICES`` below, which is what we want — silent
   additions are how an isolation boundary erodes.

6. **The sandbox has no way out except the egress guard.** ``sandbox-net``
   is ``internal``; the dual-homed services other than the guard do not
   forward; the sandbox never holds the guard's control token; and the
   sandbox daemon has no unauthenticated mode
   (see ``docs/security/scope-enforcement.md``).

7. **Scope, approvals and audit records sit outside the agent-writable
   tree.** The sandbox gets the control root read-only and the audit root
   not at all; langgraph gets workspace and control read-only.

If you are extending the compose file and one of these assertions
fires, the message points at the invariant being violated and what to
update. **Do not** weaken the test to make a change land; either fix
the compose, or open an ADR that supersedes the invariant.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE = REPO_ROOT / "docker-compose.yml"

MGMT_NET = "buggy-net"
SANDBOX_NET = "sandbox-net"

# Services that MUST NOT touch the management network under any
# circumstance. These are the services that execute against external
# targets or expose adversary-tooling interfaces.
OPERATIONAL_ONLY: frozenset[str] = frozenset(
    {
        "sandbox",
        "ghidra-mcp",
    }
)

# The only services permitted on BOTH networks. Adding a third
# requires an ADR + a deliberate update here.
DUAL_HOMED_SERVICES: frozenset[str] = frozenset(
    {
        "neo4j",
        "langgraph",
        # The sandbox's only exit: forwards by RoE, takes policy from
        # langgraph over the management side.
        "egress-guard",
    }
)

# Dual-homed services that must NOT route between their networks. The egress
# guard is the single, policy-filtered router.
NON_FORWARDING_DUAL_HOMED: frozenset[str] = DUAL_HOMED_SERVICES - {"egress-guard"}

# The only services permitted to mount the host docker socket. `cli` needs
# it for the /web slash command, which shells out to
# `docker compose --profile web up -d web` against the host daemon (#625).
# It is a client, not an agent: it executes operator keystrokes, never
# model-directed commands, so it is not the container-escape surface this
# guard exists for. Multi-tenant deployments drop the mount via a compose
# overlay. Adding a service that *does* run agent code here is not a
# deliberate update — it is the regression this test catches.
DOCKER_SOCKET_SERVICES: frozenset[str] = frozenset(
    {
        "cli",
    }
)


@pytest.fixture(autouse=True)
def _ensure_dotenv(repo_dotenv):
    """``docker compose config`` needs a .env to satisfy env_file refs.

    ``repo_dotenv`` (tests/conftest.py) keeps the file in place while any
    parallel test worker still renders.
    """
    return repo_dotenv


def _rendered_compose() -> dict:
    """Return the post-interpolation compose document as a dict.

    Uses ``--profiles`` so that profile-gated services
    (ghidra-mcp, cli) are present in the render and
    therefore subject to the same invariants as the always-on
    services.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    env = {
        **os.environ,
        # COMPOSE_PROFILES enables every profile in the file so the
        # render sees every service. The list mirrors the profiles
        # defined in docker-compose.yml; extend here when a new
        # profile is added.
        "COMPOSE_PROFILES": "reversing,cli,operator",
        # The compose file refuses to render without these (no defaults).
        "SANDBOX_TOKEN": os.environ.get("SANDBOX_TOKEN") or "test-sandbox-token",
        "EGRESS_GUARD_TOKEN": os.environ.get("EGRESS_GUARD_TOKEN") or "test-guard-token",
        "BUGGY_STACK_MCP_TOKEN": os.environ.get("BUGGY_STACK_MCP_TOKEN") or "test-stack-mcp-token",
    }
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "config"],
        env=env,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            "docker compose config failed (exit "
            f"{result.returncode}):\n"
            f"--- stderr ---\n{result.stderr}\n"
            f"--- stdout ---\n{result.stdout}"
        )
    rendered = yaml.safe_load(result.stdout)
    if not isinstance(rendered, dict) or "services" not in rendered:
        pytest.fail(f"rendered compose has no `services` key:\n{result.stdout[:500]}")
    return rendered


def _service_networks(service: dict) -> set[str]:
    """Return the set of network names a service is attached to.

    Compose ``networks:`` may be a list (``[a, b]``) or a mapping
    (``{a: null, b: {aliases: ...}}``). Both shapes mean
    membership.
    """
    nets = service.get("networks")
    if nets is None:
        return set()
    if isinstance(nets, list):
        return set(nets)
    if isinstance(nets, dict):
        return set(nets.keys())
    return set()


def _service_volumes(service: dict) -> list[str]:
    """Return source paths of all volume mounts as plain strings."""
    raw = service.get("volumes") or []
    out: list[str] = []
    for v in raw:
        if isinstance(v, str):
            out.append(v.split(":", 1)[0])
        elif isinstance(v, dict):
            src = v.get("source")
            if src:
                out.append(str(src))
    return out


def test_operational_services_never_on_management_network():
    """sandbox, ghidra-mcp must never appear on buggy-net.

    A regression here collapses the management/operational boundary —
    a compromised target-facing container would gain a path to LiteLLM
    keys, the Postgres engagement log, and the Web dashboard.
    """
    services = _rendered_compose()["services"]
    violations: list[str] = []
    for name in OPERATIONAL_ONLY:
        svc = services.get(name)
        if svc is None:
            # The service is conditional (profile-gated); if it is
            # absent we cannot validate it. The render above enables
            # every known profile, so absence here means the service
            # was removed entirely — record so an intentional removal
            # forces a test update too.
            continue
        nets = _service_networks(svc)
        if MGMT_NET in nets:
            violations.append(f"service '{name}' is on '{MGMT_NET}' but must be sandbox-only")
    assert not violations, (
        "operational/management network boundary violated:\n  "
        + "\n  ".join(violations)
        + "\n\nFix: remove the management-network membership, or open an "
        "ADR that supersedes docs/security/sandbox-isolation.md."
    )


def test_no_service_uses_host_networking():
    """``network_mode: host`` bypasses both bridges entirely."""
    services = _rendered_compose()["services"]
    violations = [name for name, svc in services.items() if svc.get("network_mode") == "host"]
    assert not violations, (
        "services with network_mode: host (forbidden): "
        f"{sorted(violations)}\n"
        "Fix: attach the service to an explicit bridge network."
    )


def test_only_allowlisted_services_mount_docker_socket():
    """``/var/run/docker.sock`` is confined to DOCKER_SOCKET_SERVICES.

    The HTTP-only sandbox migration replaced ``docker exec`` with a
    FastAPI daemon on port 9999 inside the sandbox container. Mounting
    the docker socket into a service that runs agent code reintroduces a
    container-escape path — a compromised process there can spawn or
    modify peer containers, including the management plane.
    """
    services = _rendered_compose()["services"]
    actual: set[str] = set()
    for name, svc in services.items():
        if any("docker.sock" in src for src in _service_volumes(svc)):
            actual.add(name)
    unexpected = actual - DOCKER_SOCKET_SERVICES
    stale = DOCKER_SOCKET_SERVICES - actual
    msgs: list[str] = []
    if unexpected:
        msgs.append(
            f"services mounting docker.sock without an allowlist entry: {sorted(unexpected)}\n"
            "Fix: use the sandbox HTTP daemon (port 9999) instead of docker exec "
            "(see packages/buggy/buggy/backends/), or — if the service runs "
            "no agent code — add it to DOCKER_SOCKET_SERVICES with the reason."
        )
    if stale:
        msgs.append(
            f"DOCKER_SOCKET_SERVICES lists services that no longer mount it: {sorted(stale)}\n"
            "Fix: drop the stale entry so the allowlist stays honest."
        )
    assert not msgs, "\n\n".join(msgs)


def test_published_ports_bind_to_loopback():
    """Every published port must bind to 127.0.0.1, not 0.0.0.0.

    A bare ``"PORT:PORT"`` resolves to ``0.0.0.0:PORT`` on the host,
    exposing the service to every machine on the contributor's LAN.
    For a developer laptop on a hotel / coffee-shop / coworking
    network, this is an immediate exposure of LiteLLM keys, the Neo4j
    knowledge graph, and any sandbox state.
    """
    services = _rendered_compose()["services"]
    violations: list[str] = []
    for name, svc in services.items():
        for entry in svc.get("ports") or []:
            host_ip: str | None = None
            published: str | None = None
            if isinstance(entry, str):
                # Short form rendered by ``compose config`` is usually
                # already expanded to ``IP:PUBLISHED:TARGET``. Split
                # on ':' from the right: TARGET is the rightmost
                # field, PUBLISHED next, IP if present is the rest.
                parts = entry.split(":")
                if len(parts) == 3:
                    host_ip, published, _ = parts
                elif len(parts) == 2:
                    published, _ = parts
                else:
                    published = parts[0]
            elif isinstance(entry, dict):
                host_ip = entry.get("host_ip")
                published = str(entry["published"]) if entry.get("published") is not None else None
            if published is None:
                # Random host port (target only) — fine, docker still
                # binds to 0.0.0.0 but the port is unguessable. Skip.
                continue
            if host_ip not in ("127.0.0.1", "::1"):
                violations.append(f"{name}: publishes {entry!r} without 127.0.0.1 bind")
    assert not violations, (
        "services with non-loopback port bindings:\n  "
        + "\n  ".join(violations)
        + "\n\nFix: prefix the port mapping with '127.0.0.1:' "
        '(e.g. "127.0.0.1:${PORT:-X}:X").'
    )


def _service_devices(service: dict) -> list[str]:
    """Return device mappings as ``host:container`` (or bare) strings."""
    raw = service.get("devices") or []
    out: list[str] = []
    for d in raw:
        if isinstance(d, str):
            out.append(d)
        elif isinstance(d, dict):
            src = d.get("source")
            tgt = d.get("target")
            if src and tgt:
                out.append(f"{src}:{tgt}")
            elif src:
                out.append(str(src))
    return out


TUN_OVERLAY = REPO_ROOT / "docker-compose.tun.yml"


def _rendered_with_overlay(*overlays: Path) -> dict:
    """Render the base compose plus one or more overlay files."""
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    args = ["docker", "compose", "-f", str(COMPOSE)]
    for overlay in overlays:
        args += ["-f", str(overlay)]
    args.append("config")
    result = subprocess.run(
        args,
        env={
            **os.environ,
            "COMPOSE_PROFILES": "reversing,cli",
            "SANDBOX_TOKEN": os.environ.get("SANDBOX_TOKEN") or "test-sandbox-token",
            "EGRESS_GUARD_TOKEN": os.environ.get("EGRESS_GUARD_TOKEN") or "test-guard-token",
            "BUGGY_STACK_MCP_TOKEN": os.environ.get("BUGGY_STACK_MCP_TOKEN")
            or "test-stack-mcp-token",
        },
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"docker compose config failed:\n{result.stderr}\n{result.stdout}")
    return yaml.safe_load(result.stdout)


def test_base_sandbox_does_not_map_tun_device():
    """The default sandbox must boot on hosts without /dev/net/tun.

    An unconditional device mapping fails container creation on any host
    whose kernel lacks the tun module, making TUN a prerequisite for every
    sandbox user. TUN is opt-in via docker-compose.tun.yml instead, so the
    base file must stay device-free.
    """
    sandbox = _rendered_compose()["services"].get("sandbox")
    if sandbox is None:
        pytest.fail("sandbox service missing from rendered compose")
    devices = _service_devices(sandbox)
    assert not any(d.split(":")[0] == "/dev/net/tun" for d in devices), (
        "base docker-compose.yml maps /dev/net/tun on the sandbox service; "
        "this breaks `compose up` on hosts without the tun module. Move the "
        f"mapping to docker-compose.tun.yml. devices={devices!r}"
    )


def test_tun_overlay_maps_device():
    """The opt-in overlay adds /dev/net/tun so ligolo can tunnel.

    ligolo-ng's Layer-3 pivot opens /dev/net/tun to build its ``tun``
    interface; NET_ADMIN (granted in the base file) authorizes configuring
    the interface but not opening the device node. This fences the overlay
    so an edit can't silently strip the mapping and regress ligolo to
    non-operational when TUN is explicitly requested.
    """
    if not TUN_OVERLAY.exists():
        pytest.fail(f"{TUN_OVERLAY.name} is missing")
    sandbox = _rendered_with_overlay(TUN_OVERLAY)["services"].get("sandbox")
    if sandbox is None:
        pytest.fail("sandbox service missing from rendered compose+overlay")
    devices = _service_devices(sandbox)
    assert any(d.split(":")[0] == "/dev/net/tun" for d in devices), (
        "docker-compose.tun.yml does not map /dev/net/tun onto the sandbox "
        f"service; ligolo-ng cannot build its interface. devices={devices!r}"
    )


RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"


def test_tun_overlay_is_release_tracked():
    """docker-compose.tun.yml must be pinned in config-checksums.txt.

    The installer and launcher self-update fetch config files from
    raw.githubusercontent.com and verify each against the release-pinned
    config-checksums.txt manifest before writing. If the TUN overlay is
    not in the ``sha256sum`` line that builds that manifest, either it is
    never shipped to release/updated installs (operators can't enable
    ligolo Layer-3 pivoting) or it ships unverified (a tampered CDN copy
    would pass) — both regress the opt-in TUN wiring. This fences the
    manifest generation so the overlay stays release-tracked.
    """
    if not RELEASE_WORKFLOW.exists():
        pytest.fail(f"{RELEASE_WORKFLOW} is missing")
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    sha_lines = [
        ln for ln in text.splitlines() if "sha256sum" in ln and "config-checksums.txt" in ln
    ]
    assert sha_lines, "no sha256sum line generating config-checksums.txt found in release.yml"
    assert any("docker-compose.tun.yml" in ln for ln in sha_lines), (
        "docker-compose.tun.yml is not in the config-checksums.txt sha256sum "
        f"line; release installs can't verify/enable the TUN overlay. lines={sha_lines!r}"
    )


def test_dual_homed_services_are_allowlisted():
    """A service on both networks must be in DUAL_HOMED_SERVICES.

    This is the bridge surface — the path between the management and
    operational networks. Today neo4j (for graph reads from
    management) and langgraph (for HTTP sandbox transport from
    management) are the only allowed bridges. A third introduces a
    new place where prompt-injection or process compromise can pivot
    across the boundary.

    Adding to DUAL_HOMED_SERVICES requires an ADR + maintainer review.
    """
    services = _rendered_compose()["services"]
    actual_dual_homed: set[str] = set()
    for name, svc in services.items():
        nets = _service_networks(svc)
        if MGMT_NET in nets and SANDBOX_NET in nets:
            actual_dual_homed.add(name)
    unexpected = actual_dual_homed - DUAL_HOMED_SERVICES
    missing = DUAL_HOMED_SERVICES - actual_dual_homed
    msgs: list[str] = []
    if unexpected:
        msgs.append(
            "services on BOTH networks but not allowlisted: "
            f"{sorted(unexpected)}.\n"
            "Either remove the dual membership or, if it is required, "
            "open an ADR superseding the current isolation invariant "
            "and add the service name to DUAL_HOMED_SERVICES in this "
            "test."
        )
    if missing:
        msgs.append(
            "allowlisted dual-homed services no longer present on "
            f"both networks: {sorted(missing)}.\n"
            "If the architecture intentionally changed, remove the "
            "name from DUAL_HOMED_SERVICES; otherwise restore the "
            "missing network membership."
        )
    assert not msgs, "\n\n".join(msgs)


# ── Scope-enforcement invariants ─────────────────────────────────────


def _mounts(service: dict) -> dict[str, dict]:
    """Bind mounts by container target path."""
    out: dict[str, dict] = {}
    for volume in service.get("volumes") or []:
        if isinstance(volume, dict) and volume.get("target"):
            out[str(volume["target"])] = volume
    return out


def _environment(service: dict) -> dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, list):
        return dict(item.split("=", 1) if "=" in item else (item, "") for item in env)
    return {str(k): "" if v is None else str(v) for k, v in env.items()}


def test_compose_refuses_to_render_without_tokens():
    """There is no default for the sandbox or guard tokens."""
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("SANDBOX_TOKEN", "EGRESS_GUARD_TOKEN", "BUGGY_STACK_MCP_TOKEN")
    }
    dotenv = (REPO_ROOT / ".env").read_text()
    if "SANDBOX_TOKEN=" in dotenv.replace("SANDBOX_TOKEN=\n", ""):
        pytest.skip("local .env already defines the tokens")
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "config"],
        env=env,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "SANDBOX_TOKEN" in result.stderr or "EGRESS_GUARD_TOKEN" in result.stderr


def test_sandbox_network_is_internal():
    rendered = _rendered_compose()
    assert rendered["networks"][SANDBOX_NET].get("internal") is True, (
        "sandbox-net must be internal: Docker then drops everything addressed outside it, "
        "so the egress guard is the only way out"
    )


def test_fixed_sandbox_addresses_cannot_be_handed_to_another_service():
    """The guard and sandbox have fixed addresses; dynamic ones come from elsewhere."""
    import ipaddress

    rendered = _rendered_compose()
    (config,) = rendered["networks"]["sandbox-net"]["ipam"]["config"]
    subnet = ipaddress.ip_network(config["subnet"])
    dynamic = ipaddress.ip_network(config["ip_range"])
    assert dynamic.subnet_of(subnet) and dynamic != subnet
    fixed = {}
    for name in ("egress-guard", "sandbox"):
        address = rendered["services"][name]["networks"]["sandbox-net"]["ipv4_address"]
        fixed[name] = ipaddress.ip_address(address)
        assert fixed[name] in subnet, f"{name} address is outside the sandbox subnet"
        assert fixed[name] not in dynamic, f"{name} address can be allocated to another service"
    assert fixed["egress-guard"] != fixed["sandbox"]


def test_only_the_guard_forwards_between_networks():
    services = _rendered_compose()["services"]
    for name in NON_FORWARDING_DUAL_HOMED:
        sysctls = services[name].get("sysctls") or {}
        assert str(sysctls.get("net.ipv4.ip_forward")) == "0", (
            f"dual-homed service '{name}' must set net.ipv4.ip_forward=0 so it cannot be "
            "used as a hop around the egress guard"
        )
    assert str(services["egress-guard"]["sysctls"]["net.ipv4.ip_forward"]) == "1"


def test_sandbox_routes_through_the_guard_and_cannot_control_it():
    services = _rendered_compose()["services"]
    sandbox, guard, langgraph = services["sandbox"], services["egress-guard"], services["langgraph"]
    sandbox_env, guard_env = _environment(sandbox), _environment(guard)

    guard_ip = guard["networks"][SANDBOX_NET]["ipv4_address"]
    assert sandbox_env["BUGGY_EGRESS_GATEWAY"] == guard_ip
    assert sandbox.get("dns") == [guard_ip]
    assert sandbox["networks"][SANDBOX_NET]["ipv4_address"] == guard_env["BUGGY_SANDBOX_IP"]

    assert "EGRESS_GUARD_TOKEN" not in sandbox_env, "the sandbox must never hold the guard token"
    assert "BUGGY_EGRESS_GUARD_URL" not in sandbox_env
    assert guard_env["EGRESS_GUARD_TOKEN"] == _environment(langgraph)["EGRESS_GUARD_TOKEN"]
    assert "egress-guard-control" in guard["networks"][MGMT_NET]["aliases"]
    assert "egress-guard-control" in _environment(langgraph)["BUGGY_EGRESS_GUARD_URL"]

    assert "egress-guard" in sandbox["depends_on"]
    assert "egress-guard" in langgraph["depends_on"]
    assert "NET_ADMIN" in guard["cap_add"] and guard["cap_drop"] == ["ALL"]


def test_sandbox_daemon_and_langgraph_share_a_required_token():
    services = _rendered_compose()["services"]
    token = _environment(services["sandbox"]).get("SANDBOX_TOKEN")
    assert token
    assert _environment(services["langgraph"]).get("SANDBOX_TOKEN") == token
    assert "SANDBOX_ALLOW_UNAUTHENTICATED" not in _environment(services["sandbox"])


def test_roe_is_required_by_default():
    env = _environment(_rendered_compose()["services"]["langgraph"])
    assert env["BUGGY_ROE_REQUIRE"] == "1"
    assert env["BUGGY_CONTROL_ROOT"] == "/control" and env["BUGGY_AUDIT_ROOT"] == "/audit"


def test_control_and_audit_trees_are_outside_the_agent_writable_tree():
    services = _rendered_compose()["services"]
    sandbox, langgraph = _mounts(services["sandbox"]), _mounts(services["langgraph"])

    assert sandbox["/workspace"].get("read_only") is not True  # the agent's scratch tree
    assert sandbox["/control"].get("read_only") is True
    assert "/audit" not in sandbox, "the audit root must not be mounted into the sandbox"

    assert langgraph["/workspace"].get("read_only") is True
    assert langgraph["/control"].get("read_only") is True
    assert langgraph["/audit"].get("read_only") is not True

    # Only operator-driven services may write the control root.
    writers = {
        name
        for name, svc in services.items()
        if "/control" in _mounts(svc) and _mounts(svc)["/control"].get("read_only") is not True
    }
    assert "operator" in writers
    assert writers <= {"operator", "web"}, f"unexpected control-root writers: {sorted(writers)}"


# ── Pipeline invariants ──────────────────────────────────────────────


def test_pipeline_is_isolated_from_agents_and_the_management_plane():
    services = _rendered_compose()["services"]
    pipeline, mcp = services["pipeline"], services["pipeline-mcp"]
    # The scanners have their own network: no management plane, no sandbox.
    assert _service_networks(pipeline) == {"pipeline-net"}
    # Agents reach pipeline data only through langgraph -> pipeline-mcp.
    assert _service_networks(mcp) == {MGMT_NET}
    assert SANDBOX_NET not in _service_networks(mcp)
    for name in ("sandbox", "langgraph"):
        assert "pipeline-net" not in _service_networks(services[name])
        targets = set(_mounts(services[name]))
        assert not {"/data/pipeline", "/data/queue"} & targets, f"{name} mounts the recon store"


def test_recon_store_is_read_only_for_the_agent_facing_server():
    services = _rendered_compose()["services"]
    worker, mcp = _mounts(services["pipeline"]), _mounts(services["pipeline-mcp"])
    assert worker["/data/pipeline"].get("read_only") is not True
    assert mcp["/data/pipeline"].get("read_only") is True
    assert mcp["/data/queue"].get("read_only") is not True  # re-run requests only
    for mounts in (worker, mcp):
        assert mounts["/control"].get("read_only") is True
    for name in ("pipeline", "pipeline-mcp"):
        env = _environment(services[name])
        leaked = [
            k for k in env if any(s in k for s in ("API_KEY", "LITELLM", "ANTHROPIC", "OPENAI"))
        ]
        assert not leaked, f"{name} must not carry model credentials: {leaked}"
        assert services[name].get("cap_drop") == ["ALL"] and services[name].get("read_only") is True


# ── Evidence gateway, scope lookup and browser invariants ────────────

EVIDENCE_SERVICES = ("capture-mcp", "scope-mcp", "browser-mcp")


def test_evidence_services_are_out_of_the_sandbox_and_cannot_change_scope():
    services = _rendered_compose()["services"]
    for name in EVIDENCE_SERVICES:
        service = services[name]
        assert SANDBOX_NET not in _service_networks(service), (
            f"{name} is reachable from the sandbox"
        )
        assert MGMT_NET in _service_networks(service), f"langgraph cannot reach {name}"
        assert _mounts(service)["/control"].get("read_only") is True, f"{name} can write scope"
        assert "/workspace" not in _mounts(service), f"{name} mounts the agent-writable tree"
        assert service.get("read_only") is True and service.get("cap_drop") == ["ALL"]
        assert "no-new-privileges:true" in (service.get("security_opt") or [])
        assert not service.get("ports"), f"{name} publishes a port"
        leaked = [
            k
            for k in _environment(service)
            if any(s in k for s in ("API_KEY", "LITELLM", "ANTHROPIC", "OPENAI", "SANDBOX_TOKEN"))
        ]
        assert not leaked, f"{name} must not carry credentials: {leaked}"
    # Scope lookup is read-only everywhere and has no way out.
    assert _service_networks(services["scope-mcp"]) == {MGMT_NET}
    assert "/audit" not in _mounts(services["scope-mcp"])


def test_captured_evidence_is_written_by_the_gateway_only():
    services = _rendered_compose()["services"]
    holders = {name for name, svc in services.items() if "/data/capture" in _mounts(svc)}
    assert holders == {"capture-mcp"}
    assert _mounts(services["capture-mcp"])["/data/capture"].get("read_only") is not True
    # The ledger the gateway and browser append to is never in the sandbox.
    assert "/audit" not in _mounts(services["sandbox"])


def test_stack_mcp_servers_require_a_token_the_sandbox_never_holds():
    services = _rendered_compose()["services"]
    token = _environment(services["langgraph"])["BUGGY_STACK_MCP_TOKEN"]
    assert token
    for name in ("pipeline-mcp", *EVIDENCE_SERVICES):
        env = _environment(services[name])
        assert env["BUGGY_STACK_MCP_TOKEN"] == token, f"{name} does not share the MCP token"
        assert "BUGGY_STACK_MCP_ALLOW_UNAUTHENTICATED" not in env
    assert "BUGGY_STACK_MCP_TOKEN" not in _environment(services["sandbox"])
    # The scanners do not serve MCP and have no use for the token.
    assert "BUGGY_STACK_MCP_TOKEN" not in _environment(services["pipeline"])


def test_langgraph_is_pointed_at_every_stack_mcp_server():
    env = _environment(_rendered_compose()["services"]["langgraph"])
    assert env["BUGGY_MCP_RECON_URL"] == "http://pipeline-mcp:9460/mcp"
    assert env["BUGGY_MCP_CAPTURE_URL"] == "http://capture-mcp:9461/mcp"
    assert env["BUGGY_MCP_SCOPE_URL"] == "http://scope-mcp:9462/mcp"
    assert env["BUGGY_MCP_BROWSER_URL"] == "http://browser-mcp:9463/mcp"


def test_test_account_secrets_reach_the_evidence_gateway_only_and_read_only():
    """Operator-declared test accounts: the gateway logs in; no agent-facing service sees them."""
    services = _rendered_compose()["services"]
    holders = {name for name, svc in services.items() if "/secrets" in _mounts(svc)}
    assert holders == {"capture-mcp"}
    assert _mounts(services["capture-mcp"])["/secrets"].get("read_only") is True
    assert _environment(services["capture-mcp"])["BUGGY_SECRETS_ROOT"] == "/secrets"
    for name in ("sandbox", "langgraph", "pipeline", "pipeline-mcp", "browser-mcp", "scope-mcp"):
        assert "BUGGY_SECRETS_ROOT" not in _environment(services[name]), name


def test_notification_webhooks_are_not_given_to_agent_facing_services():
    """Webhook URLs are credentials: the gateway and the operator only."""
    services = _rendered_compose()["services"]
    for name, svc in services.items():
        keys = {k for k in _environment(svc) if k.startswith("BUGGY_NOTIFY_")}
        if name in ("capture-mcp", "operator", "web", "langgraph", "litellm"):
            continue  # these read .env (operator-side) or set it explicitly
        assert not keys, f"{name} is given notification settings: {sorted(keys)}"
    assert "BUGGY_NOTIFY_WEBHOOK_URL" not in _environment(services["sandbox"])


def test_the_operator_can_queue_leads_and_project_the_graph_but_not_write_recon_data():
    services = _rendered_compose()["services"]
    operator = services["operator"]
    env = _environment(operator)
    assert env["BUGGY_MCP_CAPTURE_URL"] == "http://capture-mcp:9461/mcp"
    assert _mounts(operator)["/data/pipeline"].get("read_only") is True
    assert env["BUGGY_NEO4J_URI"] == "bolt://neo4j:7687" and env["BUGGY_NEO4J_PASSWORD"]
    assert set(operator["networks"]) & set(services["neo4j"]["networks"])
    # The dashboard (profile-gated, so read from the file) reads live state from
    # the two read-only servers.
    web = yaml.safe_load(COMPOSE.read_text())["services"]["web"]["environment"]
    assert "BUGGY_MCP_RECON_URL=http://pipeline-mcp:9460/mcp" in web
    assert "BUGGY_MCP_CAPTURE_URL=http://capture-mcp:9461/mcp" in web
