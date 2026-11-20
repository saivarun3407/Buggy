"""Isolation invariants for ``docker-compose.lite.yml`` (recon and report, no LLM).

The lite stack is three services: the pipeline worker, its read-only query
server and a one-off operator container. It must keep the rules the full
stack applies to those services (``tests/test_compose_network_isolation.py``):

1. Exactly those three services, the operator behind its profile.
2. Nothing is published to the host; no host networking, no Docker socket.
3. The scanners have their own network and share none with the query server.
4. The recon store is writable by the worker only.
5. The enforced scope (control root) is read-only for both servers and
   writable by the operator only.
6. The file does not render without ``BUGGY_STACK_MCP_TOKEN``; the scanners
   never hold the token.
7. No service carries a model credential.
8. Every service is hardened, and the two servers exactly as in the full file.

The assertions run on the *rendered* file (``docker compose config``), so they
see what would actually start. Each rule is a checker function, and each
checker is also run against a deliberately broken copy of the file: a rule
that could not fail would prove nothing.

The last tests check that the slim pipeline image really contains what the
operator commands import, by assembling exactly the files its Dockerfile
copies and running the commands from that tree.

**Do not** weaken a checker to make a change land; fix the compose file.
"""

from __future__ import annotations

import copy
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
LITE = REPO_ROOT / "docker-compose.lite.yml"
FULL = REPO_ROOT / "docker-compose.yml"
PIPELINE_DOCKERFILE = REPO_ROOT / "containers" / "pipeline.Dockerfile"

SERVICES = {"pipeline", "pipeline-mcp", "operator"}
SERVERS = ("pipeline", "pipeline-mcp")
PIPELINE_NET = "pipeline-net"
LITE_NET = "lite-net"

TOKEN = "test-stack-mcp-token-0123456789"  # noqa: S105 - test fixture
TOKEN_MESSAGE = (
    "BUGGY_STACK_MCP_TOKEN must be set - run scripts/ensure-stack-secrets.sh or `buggy onboard`"
)
#: What an operator's shell or .env typically holds. None of it may reach a service.
MODEL_CREDENTIALS = {
    "ANTHROPIC_API_KEY": "sk-ant-must-not-leak",
    "OPENAI_API_KEY": "sk-openai-must-not-leak",
    "LITELLM_MASTER_KEY": "sk-litellm-must-not-leak",
    "LITELLM_API_KEY": "sk-litellm-api-must-not-leak",
}
CREDENTIAL_MARKERS = ("API_KEY", "LITELLM", "ANTHROPIC", "OPENAI")
HARDENING_KEYS = (
    "cap_drop",
    "cap_add",
    "security_opt",
    "read_only",
    "tmpfs",
    "mem_limit",
    "pids_limit",
    "user",
    "privileged",
)


# ── rendering ────────────────────────────────────────────────────────


def _run_config(
    compose: Path, tmp_path: Path, *, token: str | None = TOKEN, profiles: str = "operator"
) -> subprocess.CompletedProcess[str]:
    """``docker compose config`` for ``compose``, independent of the caller's shell and .env.

    The model credentials are present both in the environment and in the
    interpolation file, as they would be on an operator's machine; the
    project's own ``.env`` is not read.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    env_file = tmp_path / "interpolation.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in MODEL_CREDENTIALS.items()))
    env = {
        k: v for k, v in os.environ.items() if not k.startswith(("BUGGY_", "COMPOSE_", "LITELLM"))
    }
    env.update(MODEL_CREDENTIALS)
    env["COMPOSE_PROFILES"] = profiles
    env["BUGGY_HOME"] = str(tmp_path / "buggy-home")
    if token is not None:
        env["BUGGY_STACK_MCP_TOKEN"] = token
    return subprocess.run(  # noqa: S603 - fixed argv
        [  # noqa: S607 - docker from PATH, as in the full-stack test
            "docker",
            "compose",
            "--env-file",
            str(env_file),
            "--project-directory",
            str(REPO_ROOT),
            "-f",
            str(compose),
            "config",
        ],
        env=env,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _rendered(compose: Path, tmp_path: Path, **kwargs: str) -> dict:
    result = _run_config(compose, tmp_path, **kwargs)
    if result.returncode != 0:
        pytest.fail(
            f"docker compose config failed (exit {result.returncode}):\n"
            f"--- stderr ---\n{result.stderr}\n--- stdout ---\n{result.stdout}"
        )
    rendered = yaml.safe_load(result.stdout)
    if not isinstance(rendered, dict) or "services" not in rendered:
        pytest.fail(f"rendered compose has no `services` key:\n{result.stdout[:500]}")
    return rendered


def _source(path: Path = LITE) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _broken(tmp_path: Path, mutate: Callable[[dict], None]) -> Path:
    """A copy of the lite file with one deliberate defect."""
    document = copy.deepcopy(_source())
    mutate(document)
    path = tmp_path / "broken.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


@pytest.fixture
def lite(tmp_path: Path) -> dict:
    return _rendered(LITE, tmp_path)


# ── readers ──────────────────────────────────────────────────────────


def _networks(service: dict) -> set[str]:
    nets = service.get("networks")
    if isinstance(nets, list):
        return set(nets)
    if isinstance(nets, dict):
        return set(nets)
    return set()


def _mounts(service: dict) -> dict[str, dict]:
    """Mounts by container target path."""
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


def _read_only(service: dict, target: str) -> bool:
    return _mounts(service)[target].get("read_only") is True


# ── checkers (each returns what is wrong; empty means the rule holds) ─


def exposure_violations(rendered: dict) -> list[str]:
    out: list[str] = []
    for name, service in rendered["services"].items():
        if service.get("ports"):
            out.append(f"{name} publishes ports: {service['ports']!r}")
        if service.get("network_mode") == "host":
            out.append(f"{name} uses host networking")
        sources = [str(v.get("source", "")) for v in _mounts(service).values()]
        if any("docker.sock" in source for source in sources):
            out.append(f"{name} mounts the Docker socket")
    return out


def network_violations(rendered: dict) -> list[str]:
    services = rendered["services"]
    expected = {"pipeline": {PIPELINE_NET}, "pipeline-mcp": {LITE_NET}, "operator": {LITE_NET}}
    out = [
        f"{name} is on {sorted(_networks(services[name]))}, expected {sorted(nets)}"
        for name, nets in expected.items()
        if name in services and _networks(services[name]) != nets
    ]
    defined = rendered.get("networks") or {}
    if set(defined) != {LITE_NET, PIPELINE_NET}:
        out.append(f"networks are {sorted(defined)}")
    for name, network in defined.items():
        if (network or {}).get("driver") != "bridge" or (network or {}).get("external"):
            out.append(f"network {name} is not a plain bridge")
    return out


def store_violations(rendered: dict) -> list[str]:
    services = rendered["services"]
    out: list[str] = []
    if _read_only(services["pipeline"], "/data/pipeline"):
        out.append("the worker cannot write the recon store")
    if not _read_only(services["pipeline-mcp"], "/data/pipeline"):
        out.append("pipeline-mcp can write the recon store")
    holders = {name for name, svc in services.items() if "/data/pipeline" in _mounts(svc)}
    if holders != set(SERVERS):
        out.append(f"the recon store is mounted by {sorted(holders)}")
    return out


def control_violations(rendered: dict) -> list[str]:
    services = rendered["services"]
    out = [
        f"{name} can write the control root"
        for name in SERVERS
        if not _read_only(services[name], "/control")
    ]
    writers = {
        name
        for name, svc in services.items()
        if "/control" in _mounts(svc) and not _read_only(svc, "/control")
    }
    if writers != {"operator"}:
        out.append(f"control-root writers are {sorted(writers)}, expected ['operator']")
    return out


def credential_violations(rendered: dict) -> list[str]:
    out: list[str] = []
    for name, service in rendered["services"].items():
        env = _environment(service)
        leaked = sorted(k for k in env if any(marker in k for marker in CREDENTIAL_MARKERS))
        leaked += sorted(f"{k} (value)" for k, v in env.items() if v in MODEL_CREDENTIALS.values())
        if leaked:
            out.append(f"{name} carries model credentials: {leaked}")
    return out


def hardening_violations(rendered: dict) -> list[str]:
    out: list[str] = []
    for name, service in rendered["services"].items():
        if service.get("cap_drop") != ["ALL"]:
            out.append(f"{name} does not drop all capabilities")
        if service.get("read_only") is not True:
            out.append(f"{name} has a writable root filesystem")
        if "no-new-privileges:true" not in (service.get("security_opt") or []):
            out.append(f"{name} allows new privileges")
        if "/tmp" not in (service.get("tmpfs") or []):  # noqa: S108 - a container path
            out.append(f"{name} has no tmpfs /tmp")
        if not service.get("mem_limit") or not service.get("pids_limit"):
            out.append(f"{name} has no memory or pid limit")
        if service.get("privileged"):
            out.append(f"{name} is privileged")
    return out


def token_violations(rendered: dict) -> list[str]:
    services = rendered["services"]
    out: list[str] = []
    for name in ("pipeline-mcp", "operator"):
        if _environment(services[name]).get("BUGGY_STACK_MCP_TOKEN") != TOKEN:
            out.append(f"{name} does not hold the stack MCP token")
    if "BUGGY_STACK_MCP_TOKEN" in _environment(services["pipeline"]):
        out.append("the scanners hold the stack MCP token")
    for name, service in services.items():
        if "BUGGY_STACK_MCP_ALLOW_UNAUTHENTICATED" in _environment(service):
            out.append(f"{name} allows unauthenticated MCP")
    return out


CHECKERS = (
    exposure_violations,
    network_violations,
    store_violations,
    control_violations,
    credential_violations,
    hardening_violations,
    token_violations,
)


# ── the lite file ────────────────────────────────────────────────────


def test_the_file_stands_alone_and_has_exactly_three_services(lite: dict, tmp_path: Path) -> None:
    assert set(lite["services"]) == SERVICES
    assert set(lite.get("volumes") or {}) == {"pipeline_data", "pipeline_queue"}
    # Rendered from this one file: it neither includes nor extends another.
    source = _source()
    assert "include" not in source
    assert not any("extends" in service for service in source["services"].values())
    # The operator is a one-off container: it is not part of a plain `up`.
    always_on = _rendered(LITE, tmp_path, profiles="")
    assert set(always_on["services"]) == set(SERVERS)
    assert lite["services"]["operator"]["profiles"] == ["operator"]


def test_nothing_is_published_to_the_host(lite: dict) -> None:
    assert exposure_violations(lite) == []


def test_the_scanners_have_their_own_network(lite: dict) -> None:
    assert network_violations(lite) == []
    services = lite["services"]
    assert _networks(services["pipeline"]) == {PIPELINE_NET}
    assert not _networks(services["pipeline"]) & _networks(services["pipeline-mcp"])
    assert not _networks(services["pipeline"]) & _networks(services["operator"])


def test_the_recon_store_is_read_only_for_the_query_server(lite: dict) -> None:
    assert store_violations(lite) == []
    queue = _mounts(lite["services"]["pipeline-mcp"])["/data/queue"]
    assert queue.get("read_only") is not True  # re-run requests only
    assert "/data/queue" not in _mounts(lite["services"]["operator"])


def test_control_is_read_only_for_the_servers_and_writable_for_the_operator(lite: dict) -> None:
    assert control_violations(lite) == []
    operator = _mounts(lite["services"]["operator"])
    for target in ("/control", "/audit", "/workspace"):
        assert operator[target].get("read_only") is not True, f"operator cannot write {target}"
        assert operator[target]["type"] == "bind"
    home = Path(operator["/control"]["source"]).parent
    for name in SERVERS:
        mounts = _mounts(lite["services"][name])
        assert mounts["/control"]["source"] == str(home / "control")
        assert not {"/audit", "/workspace"} & set(mounts), f"{name} mounts an operator tree"


def test_rendering_fails_without_the_stack_mcp_token(tmp_path: Path) -> None:
    result = _run_config(LITE, tmp_path, token=None)
    assert result.returncode != 0
    assert "BUGGY_STACK_MCP_TOKEN" in result.stderr and TOKEN_MESSAGE in result.stderr
    assert "services.pipeline-mcp" in result.stderr
    # Control: the token is the only thing that was missing.
    assert _run_config(LITE, tmp_path, token=TOKEN).returncode == 0
    # An empty token is refused like a missing one.
    assert _run_config(LITE, tmp_path, token="").returncode != 0


def test_the_token_message_is_the_full_stacks(lite: dict) -> None:
    required = re.compile(r"\$\{BUGGY_STACK_MCP_TOKEN:\?([^}]*)\}")
    full_messages = set(required.findall(FULL.read_text(encoding="utf-8")))
    lite_messages = set(required.findall(LITE.read_text(encoding="utf-8")))
    assert full_messages == {TOKEN_MESSAGE}
    assert lite_messages == full_messages
    assert token_violations(lite) == []


def test_no_service_carries_a_model_credential(lite: dict) -> None:
    assert credential_violations(lite) == []
    for name, service in _source()["services"].items():
        assert "env_file" not in service, f"{name} reads an env file"
    # Control: the checker is looking at real environments, and the token is not a "credential".
    assert _environment(lite["services"]["pipeline-mcp"])["BUGGY_STACK_MCP_TOKEN"] == TOKEN


def test_every_service_is_hardened_and_the_servers_match_the_full_stack(lite: dict) -> None:
    assert hardening_violations(lite) == []
    full, source = _source(FULL)["services"], _source()["services"]
    for name in SERVERS:
        for key in (*HARDENING_KEYS, "image", "entrypoint", "command", "volumes"):
            assert source[name].get(key) == full[name].get(key), (
                f"{name}.{key} differs from docker-compose.yml"
            )
    # The operator writes host-owned trees: root, with only the capability that needs.
    operator = lite["services"]["operator"]
    assert operator.get("cap_add") == ["DAC_OVERRIDE"]
    for name in SERVERS:
        assert not lite["services"][name].get("cap_add"), f"{name} adds capabilities"
        assert lite["services"][name].get("user") in (None, "")


def test_the_operator_is_the_slim_image_pointed_at_the_recon_server(lite: dict) -> None:
    operator = lite["services"]["operator"]
    assert operator["image"] == "buggy-pipeline:stable"
    assert operator["image"] == lite["services"]["pipeline"]["image"]
    assert operator["entrypoint"] == []
    assert operator["command"] == ["python", "-m", "buggy.cli", "--help"]
    assert operator["healthcheck"] == {"disable": True}
    env = _environment(operator)
    assert env["BUGGY_MCP_RECON_URL"] == "http://pipeline-mcp:9460/mcp"
    assert env["BUGGY_ENGAGEMENT_CONTROL"] == "/control"
    assert env["BUGGY_ENGAGEMENT_AUDIT"] == "/audit"
    assert env["BUGGY_ENGAGEMENT_WORKSPACE"] == "/workspace"
    mcp = lite["services"]["pipeline-mcp"]
    assert mcp["entrypoint"] == ["python", "-m", "buggy.pipeline.mcp_server"]
    assert _environment(mcp)["BUGGY_PIPELINE_MCP_PORT"] == "9460"


# ── every checker can fail ───────────────────────────────────────────


def _add_env(service: str, entry: str) -> Callable[[dict], None]:
    return lambda doc: doc["services"][service]["environment"].append(entry)


def _set(service: str, key: str, value: object) -> Callable[[dict], None]:
    return lambda doc: doc["services"][service].__setitem__(key, value)


def _drop(service: str, key: str) -> Callable[[dict], None]:
    return lambda doc: doc["services"][service].pop(key)


def _host_network(service: str) -> Callable[[dict], None]:
    def mutate(doc: dict) -> None:
        del doc["services"][service]["networks"]  # compose refuses both at once
        doc["services"][service]["network_mode"] = "host"

    return mutate


def _replace_volume(service: str, old: str, new: str) -> Callable[[dict], None]:
    def mutate(doc: dict) -> None:
        volumes = doc["services"][service]["volumes"]
        assert old in volumes, f"{old!r} is not a volume of {service}"
        volumes[volumes.index(old)] = new

    return mutate


CONTROL_RO = "${BUGGY_HOME:-~/.buggy}/control:/control:ro"
CONTROL_RW = "${BUGGY_HOME:-~/.buggy}/control:/control"

DEFECTS: list[tuple[str, Callable[[dict], None], Callable[[dict], list[str]]]] = [
    ("published port", _set("pipeline-mcp", "ports", ["9460:9460"]), exposure_violations),
    (
        "loopback-published port",
        _set("pipeline-mcp", "ports", ["127.0.0.1:9460:9460"]),
        exposure_violations,
    ),
    ("host networking", _host_network("operator"), exposure_violations),
    (
        "docker socket",
        lambda doc: doc["services"]["operator"]["volumes"].append(
            "/var/run/docker.sock:/var/run/docker.sock"
        ),
        exposure_violations,
    ),
    (
        "scanners on the query network",
        _set("pipeline", "networks", [PIPELINE_NET, LITE_NET]),
        network_violations,
    ),
    (
        "query server on the scanner network",
        _set("pipeline-mcp", "networks", [LITE_NET, PIPELINE_NET]),
        network_violations,
    ),
    (
        "operator on the scanner network",
        _set("operator", "networks", [LITE_NET, PIPELINE_NET]),
        network_violations,
    ),
    (
        "writable store for the query server",
        _replace_volume(
            "pipeline-mcp", "pipeline_data:/data/pipeline:ro", "pipeline_data:/data/pipeline"
        ),
        store_violations,
    ),
    (
        "store mounted into the operator",
        lambda doc: doc["services"]["operator"]["volumes"].append("pipeline_data:/data/pipeline"),
        store_violations,
    ),
    (
        "writable control for the worker",
        _replace_volume("pipeline", CONTROL_RO, CONTROL_RW),
        control_violations,
    ),
    (
        "writable control for the query server",
        _replace_volume("pipeline-mcp", CONTROL_RO, CONTROL_RW),
        control_violations,
    ),
    (
        "read-only control for the operator",
        _replace_volume("operator", CONTROL_RW, CONTROL_RO),
        control_violations,
    ),
    (
        "interpolated provider key",
        _add_env("pipeline", "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}"),
        credential_violations,
    ),
    (
        "passed-through gateway key",
        _add_env("operator", "LITELLM_MASTER_KEY"),
        credential_violations,
    ),
    (
        "provider key under another name",
        _add_env("pipeline-mcp", "MODEL_SECRET=${OPENAI_API_KEY:-}"),
        credential_violations,
    ),
    ("capabilities kept", _drop("pipeline", "cap_drop"), hardening_violations),
    ("writable root filesystem", _drop("operator", "read_only"), hardening_violations),
    ("new privileges allowed", _drop("pipeline-mcp", "security_opt"), hardening_violations),
    ("no pid limit", _drop("operator", "pids_limit"), hardening_violations),
    ("privileged", _set("pipeline", "privileged", True), hardening_violations),
    (
        "token given to the scanners",
        _add_env("pipeline", "BUGGY_STACK_MCP_TOKEN=${BUGGY_STACK_MCP_TOKEN:-}"),
        token_violations,
    ),
    (
        "unauthenticated MCP allowed",
        _add_env("pipeline-mcp", "BUGGY_STACK_MCP_ALLOW_UNAUTHENTICATED=1"),
        token_violations,
    ),
]


@pytest.mark.parametrize(
    ("mutate", "checker"), [d[1:] for d in DEFECTS], ids=[d[0] for d in DEFECTS]
)
def test_a_broken_copy_is_caught_by_its_rule(
    tmp_path: Path, mutate: Callable[[dict], None], checker: Callable[[dict], list[str]]
) -> None:
    broken = _rendered(_broken(tmp_path, mutate), tmp_path)
    assert checker(broken), f"{checker.__name__} did not notice the defect"


def test_an_untouched_copy_passes_every_rule(tmp_path: Path) -> None:
    """Control for the test above: the copy itself is not what trips the checkers."""
    copy_of_lite = _rendered(_broken(tmp_path, lambda _doc: None), tmp_path)
    for checker in CHECKERS:
        assert checker(copy_of_lite) == [], checker.__name__


def test_an_env_file_would_be_caught(tmp_path: Path) -> None:
    secrets = tmp_path / "operator.env"
    secrets.write_text("OPENAI_API_KEY=sk-from-env-file\n")
    broken = _rendered(_broken(tmp_path, _set("operator", "env_file", str(secrets))), tmp_path)
    assert credential_violations(broken)


def test_an_extra_service_would_be_caught(tmp_path: Path) -> None:
    def add_gateway(doc: dict) -> None:
        doc["services"]["litellm"] = {"image": "buggy-litellm:stable", "networks": [LITE_NET]}

    assert set(_rendered(_broken(tmp_path, add_gateway), tmp_path)["services"]) != SERVICES


def test_a_default_for_the_token_would_be_caught(tmp_path: Path) -> None:
    """The render refuses a missing token only because of ``:?``; a default would let it start."""

    def default_token(doc: dict) -> None:
        for service in doc["services"].values():
            service["environment"] = [
                entry.split(":?")[0] + ":-}" if "BUGGY_STACK_MCP_TOKEN" in entry else entry
                for entry in service["environment"]
            ]

    assert _run_config(_broken(tmp_path, default_token), tmp_path, token=None).returncode == 0
    assert _run_config(LITE, tmp_path, token=None).returncode != 0


# ── the slim image holds what the operator commands import ───────────

#: What ``containers/pipeline.Dockerfile`` installs with pip. Their dependencies come with them.
IMAGE_REQUIREMENT = re.compile(r'"(pydantic|pydantic-settings|pyyaml|mcp)[<>=!~][^"]*"')
COPY_LINE = re.compile(r"^COPY\s+(packages/\S+(?:\s+packages/\S+)*)\s+(/opt/\S+)\s*$", re.MULTILINE)

RUN_IN_IMAGE_TREE = r"""
import importlib.abc, importlib.metadata, re, runpy, sys

opt, roots, argv = sys.argv[1], sys.argv[2].split(","), sys.argv[3:]

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

allowed, todo = set(), [norm(r) for r in roots]
while todo:
    name = todo.pop()
    if name in allowed:
        continue
    allowed.add(name)
    try:
        requires = importlib.metadata.requires(name) or []
    except importlib.metadata.PackageNotFoundError:
        continue
    for requirement in requires:
        if "extra ==" in requirement:
            continue
        todo.append(norm(re.match(r"[A-Za-z0-9_.-]+", requirement).group(0)))

owners = importlib.metadata.packages_distributions()

class NotInTheImage(importlib.abc.MetaPathFinder):
    # Refuse any installed distribution the image does not have.
    def find_spec(self, fullname, path=None, target=None):
        top = fullname.split(".")[0]
        dists = {norm(d) for d in owners.get(top, [])}
        if top in ("buggy", "buggy_core") or not dists or dists & allowed:
            return None
        raise ModuleNotFoundError(f"{top} is not in the slim image", name=fullname)

sys.meta_path.insert(0, NotInTheImage())
for name in ("langchain", "langchain_core", "langgraph"):
    sys.modules[name] = None
sys.path[:] = [opt] + [p for p in sys.path if p]
sys.argv = argv
if argv[0] == "-c":
    exec(argv[1])
else:
    runpy.run_module(argv[0], run_name="__main__", alter_sys=True)
"""


def _runtime_stage() -> str:
    """The Dockerfile text of the final (runtime) stage."""
    text = PIPELINE_DOCKERFILE.read_text(encoding="utf-8")
    return text[text.rindex("\nFROM ") :]


def _image_tree(root: Path, *, without: tuple[str, ...] = ()) -> Path:
    """The first-party files the runtime stage copies to ``/opt``, laid out the same way."""
    copies = COPY_LINE.findall(_runtime_stage())
    assert copies, "no first-party COPY lines found in the runtime stage"
    for sources, destination in copies:
        if destination in without:
            continue
        target = root / destination.lstrip("/")
        for source in sources.split():
            origin = REPO_ROOT / source
            if origin.is_dir():
                shutil.copytree(origin, target, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                final = target / origin.name if destination.endswith("/") else target
                final.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(origin, final)
    return root / "opt"


def _in_image_tree(opt: Path, cwd: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    stage = _runtime_stage()
    assert "BUGGY_SKIP_BOOT=1" in stage and "PYTHONPATH=/opt" in stage
    roots = sorted(set(IMAGE_REQUIREMENT.findall(stage)))
    assert roots == ["mcp", "pydantic", "pydantic-settings", "pyyaml"]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BUGGY_", "PYTHON"))}
    return subprocess.run(  # noqa: S603 - our own interpreter and a fixed script
        [sys.executable, "-c", RUN_IN_IMAGE_TREE, str(opt), ",".join(roots), *argv],
        cwd=cwd,
        env={**env, "BUGGY_SKIP_BOOT": "1"},
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _hunt_argv(tmp_path: Path, *flags: str) -> tuple[str, ...]:
    return (
        "buggy.cli.hunt",
        "https://app.example.test",
        *flags,
        "--yes",
        "--engagement-name",
        "lite",
        "--workspace-root",
        str(tmp_path / "workspace"),
        "--control-root",
        str(tmp_path / "control"),
    )


@pytest.fixture
def image_requirements() -> None:
    for name in ("mcp", "pydantic", "pydantic-settings", "pyyaml"):
        try:
            importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            pytest.skip(f"{name} is not installed (uv sync --extra mcp)")


@pytest.mark.usefixtures("image_requirements")
def test_hunt_runs_from_exactly_what_the_slim_image_contains(tmp_path: Path) -> None:
    opt = _image_tree(tmp_path / "image")
    assert (opt / "buggy" / "cli" / "hunt.py").is_file()
    assert (opt / "buggy" / "pipeline" / "mcp_client.py").is_file()
    assert not (opt / "buggy" / "tools").exists() and not (opt / "buggy" / "middleware").exists()

    planned = _in_image_tree(opt, tmp_path, *_hunt_argv(tmp_path, "--plan-only"))
    assert planned.returncode == 0, planned.stderr
    assert "--plan-only: scope written, nothing started" in planned.stderr
    assert (tmp_path / "control" / "lite" / "roe.json").is_file()

    no_agent = _in_image_tree(opt, tmp_path, *_hunt_argv(tmp_path, "--no-agent"))
    assert no_agent.returncode == 0, no_agent.stderr
    assert "agents skipped (--no-agent)" in no_agent.stderr

    client = _in_image_tree(
        opt,
        tmp_path,
        "-c",
        "import buggy.pipeline.mcp_client as c, buggy.cli.status, buggy.pipeline.report\n"
        "from mcp import ClientSession\n"
        "from mcp.client.streamable_http import streamablehttp_client\n"
        "assert c.__file__.startswith(opt), c.__file__  # `opt` is the runner's image tree\n"
        "print(c.server_configured('recon'))",
    )
    assert client.returncode == 0, client.stderr
    assert client.stdout.strip() == "False"

    approvals = _in_image_tree(opt, tmp_path, "buggy.cli.approvals", "--help")
    assert approvals.returncode == 0, approvals.stderr


@pytest.mark.usefixtures("image_requirements")
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="buggy/cli/__main__.py imports the audit, export-transcript and telemetry commands "
    "at module load; they need buggy.middleware, buggy.runtime and buggy.telemetry, which the "
    "slim image does not have. The operator's default command therefore cannot start there "
    "until those imports are made lazy (not a file of task A3). Remove this marker then.",
)
def test_the_operators_default_command_runs_in_the_slim_image(tmp_path: Path) -> None:
    command = _source()["services"]["operator"]["command"]
    assert command[:2] == ["python", "-m"]
    opt = _image_tree(tmp_path / "image")
    result = _in_image_tree(opt, tmp_path, *command[2:])
    assert result.returncode == 0, result.stderr


@pytest.mark.usefixtures("image_requirements")
def test_the_image_tree_check_fails_when_the_image_lacks_something(tmp_path: Path) -> None:
    """Negative controls: a missing COPY, and a dependency the image does not install."""
    without_cli = _image_tree(tmp_path / "no-cli", without=("/opt/buggy/cli",))
    missing = _in_image_tree(without_cli, tmp_path, *_hunt_argv(tmp_path, "--plan-only"))
    assert missing.returncode != 0 and "No module named 'buggy.cli'" in missing.stderr
    assert not (tmp_path / "control").exists()

    without_program = _image_tree(tmp_path / "no-program", without=("/opt/buggy/program",))
    status = _in_image_tree(without_program, tmp_path, "-c", "import buggy.cli.status")
    assert status.returncode != 0 and "buggy.program" in status.stderr

    opt = _image_tree(tmp_path / "image")
    # pytest is certainly installed here (it is running this) and is not in the image.
    for module in ("pytest", "langchain_core.tools", "buggy.tools.stack_mcp"):
        blocked = _in_image_tree(opt, tmp_path, "-c", f"import {module}")
        assert blocked.returncode != 0, f"{module} imported in the image tree"
        assert "Error" in blocked.stderr
    not_in_image = _in_image_tree(opt, tmp_path, "-c", "import pytest")
    assert "pytest is not in the slim image" in not_in_image.stderr
    # What the image does install still imports.
    installed = _in_image_tree(opt, tmp_path, "-c", "import yaml, pydantic, mcp, httpx")
    assert installed.returncode == 0, installed.stderr
