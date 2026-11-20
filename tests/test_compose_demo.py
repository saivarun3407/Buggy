"""Isolation invariants for the ``buggy demo`` stack.

``buggy demo`` layers three files: ``docker-compose.lite.yml`` (recon and
report, no LLM), ``docker-compose.lab.yml`` (the practice targets and their
internal network) and ``docker-compose.demo.yml`` (the overlay that makes the
two a runnable stack). The demo puts an intentionally vulnerable application
next to the recon pipeline, so:

1. The three files render together; without the demo overlay they do not.
2. The stack is the lite stack plus exactly one target, ``juice-shop``.
3. The target publishes nothing, mounts nothing, and is on ``lab-net`` only;
   ``lab-net`` is internal (no route out).
4. The scanners reach the target: the pipeline is on ``lab-net`` and resolves
   names with Docker's resolver.
5. The query server and the operator, which hold the stack token, share no
   network with the target.
6. Every rule of the lite stack (``tests/test_compose_lite.py``) still holds,
   and the overlays change nothing in the lite services beyond rule 4.

The assertions run on the *rendered* files (``docker compose config``). Each
rule is a checker, and each checker is also run against the stack with one
more overlay that breaks it: a rule that could not fail would prove nothing.

**Do not** weaken a checker to make a change land; fix the compose files.
"""

from __future__ import annotations

import copy
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
import test_compose_lite as lite
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
LAB = REPO_ROOT / "docker-compose.lab.yml"
DEMO = REPO_ROOT / "docker-compose.demo.yml"
#: The order `buggy demo` passes them in (clients/launcher/cmd/demo.go).
DEMO_FILES = (lite.LITE, LAB, DEMO)
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

TARGET = "juice-shop"
TARGET_ALIAS = "juice-shop.lab"
LAB_NET = "lab-net"
DOCKER_RESOLVER = "127.0.0.11:53"
SERVICES = lite.SERVICES | {TARGET}
EXPECTED_NETWORKS = {
    "pipeline": {lite.PIPELINE_NET, LAB_NET},
    "pipeline-mcp": {lite.LITE_NET},
    "operator": {lite.LITE_NET},
    TARGET: {LAB_NET},
}


# ── rendering ────────────────────────────────────────────────────────


def _run_config(
    files: tuple[Path, ...], tmp_path: Path, *, token: str | None = lite.TOKEN
) -> subprocess.CompletedProcess[str]:
    """``docker compose config`` for ``files`` layered in order.

    Like the lite test's renderer: independent of the caller's shell and
    ``.env``, with model credentials present the way they would be on an
    operator's machine. Nothing is started.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    env_file = tmp_path / "interpolation.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in lite.MODEL_CREDENTIALS.items()))
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("BUGGY_", "COMPOSE_", "LITELLM", "LAB_"))
    }
    env.update(lite.MODEL_CREDENTIALS)
    env["COMPOSE_PROFILES"] = "operator"
    env["BUGGY_HOME"] = str(tmp_path / "buggy-home")
    if token is not None:
        env["BUGGY_STACK_MCP_TOKEN"] = token
    argv = ["docker", "compose", "--env-file", str(env_file)]
    argv += ["--project-directory", str(REPO_ROOT)]
    for path in files:
        argv += ["-f", str(path)]
    return subprocess.run(  # noqa: S603 - fixed argv, render only
        [*argv, "config"], env=env, cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )


def _rendered(files: tuple[Path, ...], tmp_path: Path) -> dict:
    result = _run_config(files, tmp_path)
    if result.returncode != 0:
        pytest.fail(
            f"docker compose config failed (exit {result.returncode}):\n"
            f"--- stderr ---\n{result.stderr}\n--- stdout ---\n{result.stdout}"
        )
    rendered = yaml.safe_load(result.stdout)
    if not isinstance(rendered, dict) or "services" not in rendered:
        pytest.fail(f"rendered compose has no `services` key:\n{result.stdout[:500]}")
    return rendered


def _with_defect(tmp_path: Path, overlay: str) -> dict:
    """The demo stack with one more overlay on top that breaks a rule."""
    path = tmp_path / "defect.yml"
    path.write_text(overlay, encoding="utf-8")
    return _rendered((*DEMO_FILES, path), tmp_path)


@pytest.fixture
def demo(tmp_path: Path) -> dict:
    return _rendered(DEMO_FILES, tmp_path)


# ── checkers (each returns what is wrong; empty means the rule holds) ─


def target_violations(rendered: dict) -> list[str]:
    """Rule 3: the vulnerable application is sealed in."""
    target = rendered["services"].get(TARGET)
    if target is None:
        return [f"{TARGET} is not in the stack"]
    out: list[str] = []
    if target.get("ports"):
        out.append(f"{TARGET} publishes ports: {target['ports']!r}")
    if target.get("network_mode"):
        out.append(f"{TARGET} sets network_mode {target['network_mode']!r}")
    if target.get("volumes"):
        out.append(f"{TARGET} mounts volumes: {target['volumes']!r}")
    if target.get("privileged") or target.get("cap_add"):
        out.append(f"{TARGET} has extra privileges")
    nets = lite._networks(target)
    if nets != {LAB_NET}:
        out.append(f"{TARGET} is on {sorted(nets)}, expected ['{LAB_NET}']")
    aliases = ((target.get("networks") or {}).get(LAB_NET) or {}).get("aliases") or []
    if TARGET_ALIAS not in aliases:
        out.append(f"{TARGET} has no alias {TARGET_ALIAS} on {LAB_NET}")
    lab_net = (rendered.get("networks") or {}).get(LAB_NET) or {}
    if lab_net.get("internal") is not True:
        out.append(f"{LAB_NET} is not internal")
    if lab_net.get("external"):
        out.append(f"{LAB_NET} is an external network")
    return out


def reach_violations(rendered: dict) -> list[str]:
    """Rule 4: the scanners can reach and resolve the target."""
    pipeline = rendered["services"]["pipeline"]
    out: list[str] = []
    if LAB_NET not in lite._networks(pipeline):
        out.append(f"the pipeline is not on {LAB_NET}")
    resolvers = lite._environment(pipeline).get("BUGGY_PIPELINE_DNS_RESOLVERS")
    if resolvers != DOCKER_RESOLVER:
        out.append(f"the pipeline resolves with {resolvers!r}, expected {DOCKER_RESOLVER!r}")
    return out


def network_violations(rendered: dict) -> list[str]:
    """Rule 5, and the exact network of every service."""
    services = rendered["services"]
    out = [
        f"{name} is on {sorted(lite._networks(services[name]))}, expected {sorted(nets)}"
        for name, nets in EXPECTED_NETWORKS.items()
        if name in services and lite._networks(services[name]) != nets
    ]
    target_nets = lite._networks(services.get(TARGET) or {})
    for name in ("pipeline-mcp", "operator"):
        shared = lite._networks(services[name]) & target_nets
        if shared:
            out.append(f"{name} shares {sorted(shared)} with {TARGET}")
    defined = rendered.get("networks") or {}
    if set(defined) != {lite.LITE_NET, lite.PIPELINE_NET, LAB_NET}:
        out.append(f"networks are {sorted(defined)}")
    return out


def _lite_part(rendered: dict) -> dict:
    """The rendered stack reduced to the lite services, for the lite checkers."""
    part = copy.deepcopy(rendered)
    part["services"] = {k: v for k, v in part["services"].items() if k in lite.SERVICES}
    return part


def lite_rule_violations(rendered: dict) -> list[str]:
    """Rule 6: the lite stack's own rules, on the demo stack."""
    out = lite.exposure_violations(rendered)  # every service, the target included
    part = _lite_part(rendered)
    for checker in (
        lite.store_violations,
        lite.control_violations,
        lite.credential_violations,
        lite.hardening_violations,
        lite.token_violations,
    ):
        out += checker(part)
    return out


CHECKERS = (target_violations, reach_violations, network_violations, lite_rule_violations)


# ── the demo stack ───────────────────────────────────────────────────


def test_the_three_files_render_and_the_overlay_is_what_makes_them(tmp_path: Path) -> None:
    assert _run_config(DEMO_FILES, tmp_path).returncode == 0
    # Control: without the demo overlay the lab file extends services the lite
    # stack does not have, and compose refuses the project.
    without = _run_config((lite.LITE, LAB), tmp_path)
    assert without.returncode != 0
    assert "neither an image nor a build context" in without.stderr


def test_the_stack_is_the_lite_stack_plus_one_target(demo: dict) -> None:
    assert set(demo["services"]) == SERVICES
    assert demo["services"]["operator"]["profiles"] == ["operator"]
    assert not demo["services"][TARGET].get("profiles")
    assert set(demo.get("volumes") or {}) == {"pipeline_data", "pipeline_queue"}


def test_the_target_is_sealed_in(demo: dict) -> None:
    assert target_violations(demo) == []
    target = demo["services"][TARGET]
    assert not target.get("ports")
    assert lite._networks(target) == {LAB_NET}
    assert demo["networks"][LAB_NET]["internal"] is True
    # The other two networks are the lite stack's ordinary bridges.
    for name in (lite.LITE_NET, lite.PIPELINE_NET):
        assert not demo["networks"][name].get("internal")


def test_the_pipeline_is_on_lab_net_with_dockers_resolver(demo: dict) -> None:
    assert reach_violations(demo) == []
    pipeline = demo["services"]["pipeline"]
    assert lite._networks(pipeline) == {lite.PIPELINE_NET, LAB_NET}
    assert lite._environment(pipeline)["BUGGY_PIPELINE_DNS_RESOLVERS"] == DOCKER_RESOLVER


def test_token_holders_share_no_network_with_the_target(demo: dict) -> None:
    assert network_violations(demo) == []
    services = demo["services"]
    for name in ("pipeline-mcp", "operator"):
        assert lite._environment(services[name])["BUGGY_STACK_MCP_TOKEN"] == lite.TOKEN
        assert not lite._networks(services[name]) & lite._networks(services[TARGET])
    assert "BUGGY_STACK_MCP_TOKEN" not in lite._environment(services[TARGET])


def test_the_lite_rules_still_hold(demo: dict, tmp_path: Path) -> None:
    assert lite_rule_violations(demo) == []
    # The token is still required: the demo does not render without it.
    missing = _run_config(DEMO_FILES, tmp_path, token=None)
    assert missing.returncode != 0 and lite.TOKEN_MESSAGE in missing.stderr


def test_the_overlays_change_nothing_else_in_the_lite_services(demo: dict, tmp_path: Path) -> None:
    alone = _rendered((lite.LITE,), tmp_path)["services"]
    layered = copy.deepcopy(demo["services"])
    for name in ("pipeline-mcp", "operator"):
        assert layered[name] == alone[name], f"{name} differs from the lite stack"
    # The pipeline differs by exactly the lab network and the resolver.
    pipeline = layered["pipeline"]
    assert pipeline["networks"].pop(LAB_NET) in ({}, None)
    assert pipeline["environment"].pop("BUGGY_PIPELINE_DNS_RESOLVERS") == DOCKER_RESOLVER
    assert pipeline == alone["pipeline"]


def test_the_demo_files_are_release_tracked() -> None:
    """The launcher verifies each file it syncs against config-checksums.txt."""
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    sha_lines = [
        ln for ln in text.splitlines() if "sha256sum" in ln and "config-checksums.txt" in ln
    ]
    assert sha_lines, "no sha256sum line generating config-checksums.txt found in release.yml"
    words = sha_lines[0].split()
    for path in DEMO_FILES:
        assert path.name in words, f"{path.name} is not in the config-checksums.txt line"
        assert (REPO_ROOT / path.name).is_file()
    assert "docker-compose.nonexistent.yml" not in words  # control: a real membership test


# ── every checker can fail ───────────────────────────────────────────

DEFECTS: list[tuple[str, str, Callable[[dict], list[str]]]] = [
    (
        "target publishes a port",
        'services:\n  juice-shop:\n    ports: ["3000:3000"]\n',
        target_violations,
    ),
    (
        "target publishes a loopback port",
        'services:\n  juice-shop:\n    ports: ["127.0.0.1:3000:3000"]\n',
        target_violations,
    ),
    (
        "target on a network with a route out",
        "services:\n  juice-shop:\n    networks:\n      pipeline-net: {}\n",
        target_violations,
    ),
    (
        "lab network not internal",
        "networks:\n  lab-net:\n    internal: false\n",
        target_violations,
    ),
    (
        "target mounts the docker socket",
        "services:\n  juice-shop:\n    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        target_violations,
    ),
    (
        "target without its lab alias",
        "services:\n  juice-shop:\n    networks: !override\n      lab-net: {}\n",
        target_violations,
    ),
    (
        "pipeline off the lab network",
        "services:\n  pipeline:\n    networks: !override\n      pipeline-net: {}\n",
        reach_violations,
    ),
    (
        "pipeline on public resolvers",
        "services:\n  pipeline:\n    environment:\n"
        "      - BUGGY_PIPELINE_DNS_RESOLVERS=1.1.1.1:53\n",
        reach_violations,
    ),
    (
        "query server on the lab network",
        "services:\n  pipeline-mcp:\n    networks:\n      lab-net: {}\n",
        network_violations,
    ),
    (
        "operator on the lab network",
        "services:\n  operator:\n    networks:\n      lab-net: {}\n",
        network_violations,
    ),
    (
        "target on the operator's network",
        "services:\n  juice-shop:\n    networks:\n      lite-net: {}\n",
        network_violations,
    ),
    (
        "a second target started with the stack",
        "services:\n  dvga:\n    image: example.invalid/dvga:latest\n"
        "    networks:\n      lab-net: {}\n",
        lambda rendered: sorted(set(rendered["services"]) ^ SERVICES),
    ),
    (
        "pipeline publishes a port",
        'services:\n  pipeline:\n    ports: ["9460:9460"]\n',
        lite_rule_violations,
    ),
    (
        "writable control root for the scanners",
        "services:\n  pipeline:\n    volumes:\n      - ${BUGGY_HOME:-~/.buggy}/control:/control\n",
        lite_rule_violations,
    ),
    (
        "token given to the scanners",
        "services:\n  pipeline:\n    environment:\n"
        "      - BUGGY_STACK_MCP_TOKEN=${BUGGY_STACK_MCP_TOKEN:-}\n",
        lite_rule_violations,
    ),
]


@pytest.mark.parametrize(
    ("overlay", "checker"), [d[1:] for d in DEFECTS], ids=[d[0] for d in DEFECTS]
)
def test_a_broken_stack_is_caught_by_its_rule(
    tmp_path: Path, overlay: str, checker: Callable[[dict], list[str]]
) -> None:
    broken = _with_defect(tmp_path, overlay)
    assert checker(broken), "the checker did not notice the defect"


def test_a_harmless_overlay_passes_every_rule(tmp_path: Path) -> None:
    """Control for the test above: an extra overlay is not what trips the checkers."""
    harmless = _with_defect(tmp_path, "services:\n  juice-shop:\n    mem_limit: 1g\n")
    assert set(harmless["services"]) == SERVICES
    for checker in CHECKERS:
        assert checker(harmless) == [], checker.__name__
