"""``buggy-cli doctor``: every prerequisite of a hunt, one line and one fix each.

Docker is never touched: ``which``, the command runner, the port probe, the
disk and the RAM are fakes. The Buggy home is a real directory under
``tmp_path`` unless a test replaces the filesystem callables too.
"""

from __future__ import annotations

import json
import socket
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from buggy.cli import doctor
from buggy.cli.__main__ import main as cli_main

GB = doctor.GB

SECRETS = ["SANDBOX_TOKEN", "EGRESS_GUARD_TOKEN", "BUGGY_STACK_MCP_TOKEN"]
LITE_IMAGES = ["buggy-pipeline:stable"]
FULL_IMAGES = [
    "buggy-pipeline:stable",
    "buggy-langgraph:stable",
    "buggy-litellm:stable",
    "buggy-sandbox:stable",
    "buggy-egress-guard:stable",
    "buggy-browser:stable",
    "buggy-skillogy:stable",
]
PORTS = {
    "LANGGRAPH_PORT": 2024,
    "LITELLM_PORT": 4000,
    "NEO4J_HTTP_PORT": 7474,
    "NEO4J_BOLT_PORT": 7687,
}
FULL_ORDER = [
    "docker",
    "docker compose",
    "docker daemon",
    *(f"secret {name}" for name in SECRETS),
    *(f"image {image}" for image in FULL_IMAGES),
    *(f"port {variable}" for variable in PORTS),
    "BUGGY_HOME",
    "disk",
    "memory",
    "model",
]
LITE_ORDER = [
    "docker",
    "docker compose",
    "docker daemon",
    "secret BUGGY_STACK_MCP_TOKEN",
    "image buggy-pipeline:stable",
    "BUGGY_HOME",
    "disk",
    "model",
]


class World:
    """A healthy machine by default; each test breaks exactly one thing."""

    def __init__(self, tmp_path: Path) -> None:
        self.home = tmp_path / "buggy-home"
        self.docker_path: str | None = "/usr/bin/docker"
        self.compose: tuple[int, str] = (0, "Docker Compose version v2.27.1")
        self.daemon: tuple[int, str] = (0, "27.0.3")
        self.images: set[str] = set(FULL_IMAGES)
        self.busy_ports: set[int] = set()
        self.free_bytes = 100 * GB
        self.ram: int | None = 16 * GB
        self.commands: list[list[str]] = []
        self.port_probes: list[int] = []
        self.env: dict[str, str] = {
            "SANDBOX_TOKEN": "s" * 64,
            "EGRESS_GUARD_TOKEN": "e" * 64,
            "BUGGY_STACK_MCP_TOKEN": "m" * 64,
            "BUGGY_HOME": str(self.home),
            "ANTHROPIC_API_KEY": "real-looking-key-123",
        }

    def which(self, name: str) -> str | None:
        return self.docker_path if name == "docker" else None

    def run(self, argv: Sequence[str]) -> tuple[int, str]:
        command = list(argv)
        self.commands.append(command)
        if self.docker_path is None:
            raise AssertionError(f"docker is not installed, yet doctor ran {command}")
        if command == ["docker", "compose", "version"]:
            return self.compose
        if command == ["docker", "info", "--format", "{{.ServerVersion}}"]:
            return self.daemon
        if command[:3] == ["docker", "image", "inspect"]:
            if self.daemon[0] != 0:
                return 1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."
            image = command[-1]
            if image in self.images:
                return 0, "sha256:0123456789abcdef"
            return 1, f"Error response from daemon: No such image: {image}"
        # doctor only inspects: anything else (pull, build, up, run) is a bug.
        raise AssertionError(f"doctor ran an unexpected command: {command}")

    def free_port(self, port: int) -> bool:
        self.port_probes.append(port)
        return port not in self.busy_ports

    def effects(self) -> dict:
        return {
            "which": self.which,
            "run": self.run,
            "free_port": self.free_port,
            "disk_free": lambda _path: self.free_bytes,
            "total_ram": lambda: self.ram,
        }

    def checks(self, profile: str = "full", **overrides) -> list[doctor.Check]:
        return doctor.run_checks(self.env, profile=profile, **{**self.effects(), **overrides})

    def main(self, *argv: str, dotenv: Path | None = None, **overrides) -> int:
        return doctor.main(
            list(argv),
            environ=self.env,
            dotenv=dotenv or self.home.parent / "no-such.env",
            **{**self.effects(), **overrides},
        )


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def _by_name(checks: list[doctor.Check]) -> dict[str, doctor.Check]:
    names = [check.name for check in checks]
    assert len(names) == len(set(names)), f"duplicate check names: {names}"
    return {check.name: check for check in checks}


def _failed(checks: list[doctor.Check]) -> list[str]:
    return [check.name for check in checks if check.status == "fail"]


def _not_ok(checks: list[doctor.Check]) -> list[str]:
    return [check.name for check in checks if check.status != "ok"]


class TestEverythingPasses:
    def test_every_check_is_ok_in_the_specified_order(self, world: World) -> None:
        checks = world.checks()
        assert [check.name for check in checks] == FULL_ORDER
        assert [check.status for check in checks] == ["ok"] * len(FULL_ORDER)
        assert all(check.fix == "" for check in checks)

    def test_exit_0_and_ok_true(self, world: World, capsys: pytest.CaptureFixture[str]) -> None:
        assert world.main("--json") == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is True

    def test_it_only_inspects_docker_and_never_starts_anything(self, world: World) -> None:
        world.checks()
        assert world.commands == [
            ["docker", "compose", "version"],
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            *(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image]
                for image in FULL_IMAGES
            ),
        ]

    def test_the_home_directories_are_created_when_absent(self, world: World) -> None:
        assert not world.home.exists()
        home = _by_name(world.checks())["BUGGY_HOME"]
        assert home.status == "ok"
        for name in ("workspace", "control", "audit"):
            assert (world.home / name).is_dir()
            assert name in home.detail

    def test_existing_home_directories_are_left_alone(self, world: World) -> None:
        for name in doctor.HOME_DIRS:
            (world.home / name).mkdir(parents=True)
        (world.home / "control" / "keep.txt").write_text("operator data")
        made: list[str] = []
        home = _by_name(world.checks(make_dir=made.append))["BUGGY_HOME"]
        assert home.status == "ok"
        assert made == []
        assert "created" not in home.detail
        assert (world.home / "control" / "keep.txt").read_text() == "operator data"
        assert sorted(path.name for path in world.home.iterdir()) == [
            "audit",
            "control",
            "secrets",
            "workspace",
        ]

    def test_the_default_home_is_dot_buggy_under_home(self, world: World, tmp_path: Path) -> None:
        del world.env["BUGGY_HOME"]
        world.env["HOME"] = str(tmp_path / "user")
        home = _by_name(world.checks())["BUGGY_HOME"]
        assert home.status == "ok"
        assert (tmp_path / "user" / ".buggy" / "audit").is_dir()


class TestEachFailureInIsolation:
    def test_no_docker(self, world: World, capsys: pytest.CaptureFixture[str]) -> None:
        world.docker_path = None
        checks = _by_name(world.checks())
        assert checks["docker"].status == "fail"
        assert "install Docker" in checks["docker"].fix
        assert "docs.docker.com/get-docker" in checks["docker"].fix
        # Nothing that needs docker is reported as passing, and docker is never invoked.
        dependent = ["docker compose", "docker daemon", *(f"image {i}" for i in FULL_IMAGES)]
        assert _failed(list(checks.values())) == ["docker", *dependent]
        for name in dependent:
            assert checks[name].detail == "not checked: docker is not installed"
        assert world.commands == []
        assert world.main() == 2
        assert "FAIL" in capsys.readouterr().out

    @pytest.mark.parametrize(
        "result",
        [
            (0, "docker-compose version 1.29.2, build 5becea4c"),
            (0, "Docker Compose version v1.29.2"),
            (1, "docker: 'compose' is not a docker command.\nSee 'docker --help'"),
            (0, "something without a version"),
        ],
    )
    def test_compose_v1_or_absent(self, world: World, result: tuple[int, str]) -> None:
        world.compose = result
        checks = world.checks()
        assert _not_ok(checks) == ["docker compose"]
        compose = _by_name(checks)["docker compose"]
        assert compose.status == "fail"
        assert "Docker Compose v2 plugin" in compose.fix
        assert world.main() == 2

    @pytest.mark.parametrize(
        "output",
        [
            "Docker Compose version v2.27.1",
            "Docker Compose version 2.24.5-desktop.1",
            "Docker Compose version v5.0.0",
        ],
    )
    def test_compose_v2_or_newer_passes(self, world: World, output: str) -> None:
        world.compose = (0, output)
        assert _by_name(world.checks())["docker compose"].status == "ok"

    @pytest.mark.parametrize(
        "result",
        [
            (1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."),
            (0, ""),
        ],
    )
    def test_daemon_down(self, world: World, result: tuple[int, str]) -> None:
        world.daemon = result
        checks = _by_name(world.checks())
        assert checks["docker daemon"].status == "fail"
        assert "start Docker" in checks["docker daemon"].fix
        assert "docker info" in checks["docker daemon"].fix
        # Images cannot be verified, so they are not passed and not blamed on a missing build.
        images = [f"image {image}" for image in FULL_IMAGES]
        assert _failed(list(checks.values())) == ["docker daemon", *images]
        for name in images:
            assert checks[name].detail.startswith("not checked:")
            assert "make build-images" not in checks[name].fix
        assert not any(command[:3] == ["docker", "image", "inspect"] for command in world.commands)
        assert checks["docker compose"].status == "ok"
        assert world.main() == 2

    @pytest.mark.parametrize("secret", SECRETS)
    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_each_missing_secret(self, world: World, secret: str, value: str | None) -> None:
        if value is None:
            del world.env[secret]
        else:
            world.env[secret] = value
        checks = world.checks()
        assert _not_ok(checks) == [f"secret {secret}"]
        check = _by_name(checks)[f"secret {secret}"]
        assert check.status == "fail"
        assert secret in check.detail
        assert "scripts/ensure-stack-secrets.sh" in check.fix
        assert world.main() == 2

    def test_a_secret_value_is_never_printed(
        self, world: World, capsys: pytest.CaptureFixture[str]
    ) -> None:
        world.main("--json")
        world.main()
        output = capsys.readouterr().out
        for secret in SECRETS:
            assert world.env[secret] not in output

    @pytest.mark.parametrize("image", FULL_IMAGES)
    def test_each_missing_image(self, world: World, image: str) -> None:
        world.images.discard(image)
        checks = world.checks()
        assert _not_ok(checks) == [f"image {image}"]
        check = _by_name(checks)[f"image {image}"]
        assert check.status == "fail"
        assert "make build-images" in check.fix
        assert world.main() == 2

    def test_images_use_the_buggy_version_tag(self, world: World) -> None:
        world.env["BUGGY_VERSION"] = "1.4.2"
        checks = world.checks()
        # Only the :stable images exist in this world, so every 1.4.2 image is missing.
        assert _failed(checks) == [
            f"image {image.replace(':stable', ':1.4.2')}" for image in FULL_IMAGES
        ]
        world.images = {image.replace(":stable", ":1.4.2") for image in FULL_IMAGES}
        assert _failed(world.checks()) == []

    def test_images_use_the_registry_prefix(self, world: World) -> None:
        # An installed machine pulls ghcr.io/<owner>/buggy-*: the bare local
        # names a source build tags are not what its stack runs.
        world.env["BUGGY_IMAGE_PREFIX"] = "ghcr.io/owner/"
        assert _failed(world.checks()) == [f"image ghcr.io/owner/{image}" for image in FULL_IMAGES]
        world.images = {f"ghcr.io/owner/{image}" for image in FULL_IMAGES}
        assert _failed(world.checks()) == []

    @pytest.mark.parametrize(("variable", "port"), list(PORTS.items()))
    def test_each_busy_port(self, world: World, variable: str, port: int) -> None:
        world.busy_ports = {port}
        checks = world.checks()
        assert _not_ok(checks) == [f"port {variable}"]
        check = _by_name(checks)[f"port {variable}"]
        assert check.status == "fail"
        assert str(port) in check.detail
        assert f"set {variable} " in check.fix
        other_variables = set(PORTS) - {variable}
        assert not any(other in check.fix for other in other_variables)
        assert world.main() == 2

    def test_all_four_default_ports_are_probed(self, world: World) -> None:
        world.checks()
        assert world.port_probes == [2024, 4000, 7474, 7687]

    @pytest.mark.parametrize(("variable", "default"), list(PORTS.items()))
    def test_a_port_variable_moves_the_probe(
        self, world: World, variable: str, default: int
    ) -> None:
        moved = default + 10000
        world.env[variable] = str(moved)
        world.busy_ports = {default}
        assert _not_ok(world.checks()) == []
        assert moved in world.port_probes
        assert default not in world.port_probes

        world.busy_ports = {moved}
        check = _by_name(world.checks())[f"port {variable}"]
        assert check.status == "fail"
        assert str(moved) in check.detail
        assert f"set {variable} " in check.fix

    @pytest.mark.parametrize("value", ["http", "0", "70000", "-1", "20.24"])
    def test_a_port_variable_that_is_not_a_port_fails(self, world: World, value: str) -> None:
        world.env["LITELLM_PORT"] = value
        checks = world.checks()
        assert _not_ok(checks) == ["port LITELLM_PORT"]
        check = _by_name(checks)["port LITELLM_PORT"]
        assert "set LITELLM_PORT " in check.fix
        assert 4000 not in world.port_probes

    def test_unwritable_home(self, world: World) -> None:
        checks = world.checks(writable=lambda _path: False)
        assert _not_ok(checks) == ["BUGGY_HOME"]
        check = _by_name(checks)["BUGGY_HOME"]
        assert check.status == "fail"
        assert str(world.home) in check.fix
        assert "BUGGY_HOME" in check.fix
        assert world.main(writable=lambda _path: False) == 2

    def test_only_one_unwritable_subdirectory_is_enough_to_fail(self, world: World) -> None:
        audit = str(world.home / "audit")
        check = _by_name(world.checks(writable=lambda path: path != audit))["BUGGY_HOME"]
        assert check.status == "fail"
        assert audit in check.detail

    def test_home_that_cannot_be_created(self, world: World) -> None:
        def refuse(path: str) -> None:
            raise PermissionError(13, "Permission denied", path)

        checks = world.checks(make_dir=refuse)
        assert _not_ok(checks) == ["BUGGY_HOME"]
        check = _by_name(checks)["BUGGY_HOME"]
        assert "cannot create" in check.detail
        assert "Permission denied" in check.detail
        assert "BUGGY_HOME" in check.fix
        assert not world.home.exists()

    def test_home_under_a_regular_file_fails_on_the_real_filesystem(
        self, world: World, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "a-file"
        blocker.write_text("not a directory")
        world.env["BUGGY_HOME"] = str(blocker / "home")
        checks = world.checks()
        assert _not_ok(checks) == ["BUGGY_HOME"]
        assert world.main() == 2
        assert blocker.read_text() == "not a directory"

    def test_home_that_is_a_file_fails(self, world: World) -> None:
        world.home.write_text("oops")
        assert _by_name(world.checks())["BUGGY_HOME"].status == "fail"

    def test_too_little_disk(self, world: World) -> None:
        world.free_bytes = 10 * GB - 1
        checks = world.checks()
        assert _not_ok(checks) == ["disk"]
        check = _by_name(checks)["disk"]
        assert check.status == "fail"
        assert "10 GB" in check.detail
        assert "BUGGY_HOME" in check.fix
        assert str(world.home) in check.fix
        assert world.main() == 2

    def test_disk_that_cannot_be_measured_fails(self, world: World) -> None:
        def broken(path: str) -> int:
            raise OSError(5, "Input/output error", path)

        check = _by_name(world.checks(disk_free=broken))["disk"]
        assert check.status == "fail"
        assert "Input/output error" in check.detail


class TestWarningsDoNotFail:
    @pytest.mark.parametrize("free", [10 * GB, 15 * GB, 20 * GB - 1])
    def test_disk_between_10_and_20_gb_warns(self, world: World, free: int) -> None:
        world.free_bytes = free
        checks = world.checks()
        assert _not_ok(checks) == ["disk"]
        assert _by_name(checks)["disk"].status == "warn"
        assert world.main() == 0

    def test_disk_of_20_gb_is_ok(self, world: World) -> None:
        world.free_bytes = 20 * GB
        assert _by_name(world.checks())["disk"].status == "ok"

    @pytest.mark.parametrize("ram", [4 * GB, 8 * GB - 1, None])
    def test_low_or_unknown_ram_warns_on_full(self, world: World, ram: int | None) -> None:
        world.ram = ram
        checks = world.checks()
        assert _not_ok(checks) == ["memory"]
        assert _by_name(checks)["memory"].status == "warn"
        assert world.main() == 0

    def test_8_gb_of_ram_is_ok(self, world: World) -> None:
        world.ram = 8 * GB
        assert _by_name(world.checks())["memory"].status == "ok"

    @pytest.mark.parametrize("key", [None, "", "your-api-key-here", "sk-buggy-placeholder"])
    def test_a_missing_model_is_a_warning_and_keeps_exit_0(
        self, world: World, key: str | None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        if key is None:
            del world.env["ANTHROPIC_API_KEY"]
        else:
            world.env["ANTHROPIC_API_KEY"] = key
        checks = world.checks()
        assert _not_ok(checks) == ["model"]
        model = _by_name(checks)["model"]
        assert model.status == "warn"
        assert "recon and report still work; agents need a model" in model.detail
        assert model.fix
        assert world.main("--json") == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is True
        assert payload["checks"][-1]["status"] == "warn"

    def test_a_missing_model_does_not_hide_a_real_failure(self, world: World) -> None:
        del world.env["ANTHROPIC_API_KEY"]
        world.images.discard("buggy-sandbox:stable")
        assert world.main() == 2

    def test_a_local_ollama_endpoint_counts_as_a_model(self, world: World) -> None:
        del world.env["ANTHROPIC_API_KEY"]
        world.env["OLLAMA_API_BASE"] = "http://localhost:11434"
        assert _by_name(world.checks())["model"].status == "ok"


class TestLiteProfile:
    def test_lite_needs_neither_the_full_images_nor_the_ports(self, world: World) -> None:
        world.images = {"buggy-pipeline:stable"}
        world.busy_ports = set(PORTS.values())
        world.ram = 2 * GB
        checks = world.checks("lite")
        assert [check.name for check in checks] == LITE_ORDER
        assert _not_ok(checks) == []
        assert world.port_probes == []
        inspected = [c[-1] for c in world.commands if c[:3] == ["docker", "image", "inspect"]]
        assert inspected == LITE_IMAGES
        assert world.main("--profile", "lite") == 0

    def test_the_same_machine_is_not_ready_for_the_full_profile(self, world: World) -> None:
        world.images = {"buggy-pipeline:stable"}
        world.busy_ports = set(PORTS.values())
        failed = _failed(world.checks("full"))
        assert failed == [
            *(f"image {image}" for image in FULL_IMAGES[1:]),
            *(f"port {variable}" for variable in PORTS),
        ]
        assert world.main("--profile", "full") == 2
        assert world.main() == 2, "full is the default profile"

    def test_lite_still_requires_the_pipeline_image(self, world: World) -> None:
        world.images.discard("buggy-pipeline:stable")
        checks = world.checks("lite")
        assert _not_ok(checks) == ["image buggy-pipeline:stable"]
        assert world.main("--profile", "lite") == 2

    def test_lite_requires_only_the_secret_its_stack_uses(self, world: World) -> None:
        # docker-compose.lite.yml has no sandbox and no egress guard.
        del world.env["SANDBOX_TOKEN"]
        del world.env["EGRESS_GUARD_TOKEN"]
        assert _not_ok(world.checks("lite")) == []
        assert _not_ok(world.checks("full")) == [
            "secret SANDBOX_TOKEN",
            "secret EGRESS_GUARD_TOKEN",
        ]
        del world.env["BUGGY_STACK_MCP_TOKEN"]
        assert _not_ok(world.checks("lite")) == ["secret BUGGY_STACK_MCP_TOKEN"]

    def test_an_unknown_profile_is_rejected(self, world: World) -> None:
        with pytest.raises(ValueError, match="unknown profile"):
            world.checks("medium")
        with pytest.raises(SystemExit) as excinfo:
            world.main("--profile", "medium")
        assert excinfo.value.code == 2


class TestJsonOutput:
    @pytest.mark.parametrize(("profile", "order"), [("full", FULL_ORDER), ("lite", LITE_ORDER)])
    def test_one_entry_per_check_in_order(
        self, world: World, capsys: pytest.CaptureFixture[str], profile: str, order: list[str]
    ) -> None:
        assert world.main("--json", "--profile", profile) == 0
        payload = json.loads(capsys.readouterr().out)
        assert set(payload) == {"ok", "checks"}
        assert payload["ok"] is True
        assert [entry["name"] for entry in payload["checks"]] == order
        for entry in payload["checks"]:
            assert set(entry) == {"name", "status", "detail", "fix"}
            assert entry["status"] == "ok"

    def test_a_failure_is_ok_false_with_its_fix(
        self, world: World, capsys: pytest.CaptureFixture[str]
    ) -> None:
        world.busy_ports = {7687}
        assert world.main("--json") == 2
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is False
        assert [entry["name"] for entry in payload["checks"]] == FULL_ORDER
        bad = [entry for entry in payload["checks"] if entry["status"] != "ok"]
        assert [entry["name"] for entry in bad] == ["port NEO4J_BOLT_PORT"]
        assert bad[0]["status"] == "fail"
        assert "NEO4J_BOLT_PORT" in bad[0]["fix"]


class TestHumanOutput:
    def test_one_aligned_line_per_check(
        self, world: World, capsys: pytest.CaptureFixture[str]
    ) -> None:
        world.busy_ports = {4000}
        del world.env["ANTHROPIC_API_KEY"]
        assert world.main() == 2
        lines = capsys.readouterr().out.splitlines()
        rows = lines[: len(FULL_ORDER)]
        assert lines[len(FULL_ORDER)] == ""
        assert (
            lines[len(FULL_ORDER) + 1] == f"not ready: {len(FULL_ORDER) - 2} ok, 1 warn, 1 failed"
        )
        assert len(lines) == len(FULL_ORDER) + 2

        labels = [row.split()[0] for row in rows]
        expected = ["ok"] * len(FULL_ORDER)
        expected[FULL_ORDER.index("port LITELLM_PORT")] = "FAIL"
        expected[FULL_ORDER.index("model")] = "warn"
        assert labels == expected

        # Aligned: every name starts in the same column, every detail in the same column.
        name_column = len("FAIL") + 2
        detail_column = name_column + max(len(name) for name in FULL_ORDER) + 2
        for row, name in zip(rows, FULL_ORDER, strict=True):
            assert row[name_column:].startswith(name)
            assert row[detail_column - 1] == " "
            assert row[detail_column] != " "

        failing = rows[FULL_ORDER.index("port LITELLM_PORT")]
        assert "fix: set LITELLM_PORT " in failing
        assert "fix:" not in rows[FULL_ORDER.index("docker")]

    def test_ready_summary_when_nothing_failed(
        self, world: World, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert world.main() == 0
        out = capsys.readouterr().out
        assert out.splitlines()[-1] == f"ready: {len(FULL_ORDER)} ok, 0 warn, 0 failed"
        assert "FAIL" not in out


class TestDotEnv:
    def _strip_secrets(self, world: World) -> None:
        for secret in SECRETS:
            del world.env[secret]

    def test_values_are_read_from_dot_env(self, world: World, tmp_path: Path) -> None:
        self._strip_secrets(world)
        dotenv = tmp_path / ".env"
        dotenv.write_text(
            "# stack secrets\n"
            "\n"
            "SANDBOX_TOKEN=from-file-1\n"
            "export EGRESS_GUARD_TOKEN='from-file-2'\n"
            'BUGGY_STACK_MCP_TOKEN="from-file-3"  \n'
        )
        assert world.main(dotenv=dotenv) == 0
        # Negative control: without the file the same environment fails.
        assert world.main(dotenv=tmp_path / "absent.env") == 2

    def test_dot_env_is_taken_from_the_current_directory(
        self, world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._strip_secrets(world)
        project = tmp_path / "project"
        project.mkdir()
        (project / ".env").write_text("\n".join(f"{secret}=file-value" for secret in SECRETS))
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()

        monkeypatch.chdir(project)
        assert doctor.main([], environ=world.env, **world.effects()) == 0
        monkeypatch.chdir(elsewhere)
        assert doctor.main([], environ=world.env, **world.effects()) == 2

    def test_a_commented_out_secret_does_not_count(self, world: World, tmp_path: Path) -> None:
        del world.env["SANDBOX_TOKEN"]
        dotenv = tmp_path / ".env"
        dotenv.write_text("# SANDBOX_TOKEN=commented-out\n  #SANDBOX_TOKEN=also-commented\n")
        assert world.main(dotenv=dotenv) == 2
        dotenv.write_text("SANDBOX_TOKEN=live\n")
        assert world.main(dotenv=dotenv) == 0

    def test_real_environment_variables_win_over_dot_env(
        self, world: World, tmp_path: Path
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("LANGGRAPH_PORT=2024\nLITELLM_PORT=14000\n")
        world.busy_ports = {2024}
        # The file alone points LangGraph at the busy port.
        assert world.main(dotenv=dotenv) == 2
        assert 14000 in world.port_probes, "a value only in .env is used"
        # The real environment moves it, and wins.
        world.env["LANGGRAPH_PORT"] = "12024"
        world.port_probes.clear()
        assert world.main(dotenv=dotenv) == 0
        assert world.port_probes == [12024, 14000, 7474, 7687]

    def test_an_empty_real_variable_still_wins_over_dot_env(
        self, world: World, tmp_path: Path
    ) -> None:
        # Compose resolves it the same way: a set-but-empty variable beats the file.
        dotenv = tmp_path / ".env"
        dotenv.write_text("SANDBOX_TOKEN=from-file\n")
        world.env["SANDBOX_TOKEN"] = ""
        assert world.main(dotenv=dotenv) == 2

    def test_load_env_merges_with_the_environment_on_top(self, tmp_path: Path) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("A=file\nB=file\n")
        assert doctor.load_env({"B": "real", "C": "real"}, dotenv) == {
            "A": "file",
            "B": "real",
            "C": "real",
        }
        assert doctor.load_env({"C": "real"}, tmp_path / "absent") == {"C": "real"}

    def test_parse_env_file(self) -> None:
        text = (
            "# comment\n"
            "\n"
            "PLAIN=value\n"
            "  SPACED = padded value  \n"
            'DOUBLE="quoted # not a comment"\n'
            "SINGLE='single'\n"
            "INLINE=value # trailing comment\n"
            "HASH=abc#def\n"
            "EMPTY=\n"
            "export EXPORTED=yes\n"
            "URL=http://host:1/path?a=b\n"
            "not a key value line\n"
            "1BAD=name\n"
        )
        assert doctor.parse_env_file(text) == {
            "PLAIN": "value",
            "SPACED": "padded value",
            "DOUBLE": "quoted # not a comment",
            "SINGLE": "single",
            "INLINE": "value",
            "HASH": "abc#def",
            "EMPTY": "",
            "EXPORTED": "yes",
            "URL": "http://host:1/path?a=b",
        }


class TestDispatch:
    def test_buggy_cli_doctor_reaches_this_module(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[list[str]] = []

        def fake_main(argv: list[str]) -> int:
            seen.append(argv)
            return 2

        monkeypatch.setattr(doctor, "main", fake_main)
        assert cli_main(["doctor", "--profile", "lite", "--json"]) == 2
        assert seen == [["--profile", "lite", "--json"]]

    def test_help_documents_both_flags(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            doctor.main(["--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "--profile" in out
        assert "--json" in out


class TestRealSideEffects:
    """The defaults behind the fakes, exercised without Docker."""

    def test_a_listening_port_is_busy_and_a_closed_one_is_free(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            assert doctor._port_is_free(port) is False
        assert doctor._port_is_free(port) is True

    def test_a_bound_but_not_listening_port_is_busy(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
            holder.bind(("127.0.0.1", 0))
            assert doctor._port_is_free(holder.getsockname()[1]) is False

    def test_a_missing_command_is_an_exit_code_not_an_exception(self) -> None:
        code, output = doctor._run_command(["buggy-doctor-no-such-binary", "--version"])
        assert code == 127
        assert "buggy-doctor-no-such-binary" in output

    def test_command_output_and_failure_are_reported(self) -> None:
        assert doctor._run_command([sys.executable, "-c", "print('v2.1.0')"]) == (0, "v2.1.0")
        code, output = doctor._run_command(
            [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"]
        )
        assert (code, output) == (3, "boom")

    def test_writable_means_a_file_can_really_be_created(self, tmp_path: Path) -> None:
        assert doctor._is_writable(str(tmp_path)) is True
        assert list(tmp_path.iterdir()) == [], "the probe file is removed"
        assert doctor._is_writable(str(tmp_path / "absent")) is False

    def test_disk_free_of_a_path_that_does_not_exist_yet(self, tmp_path: Path) -> None:
        assert doctor._disk_free(str(tmp_path / "not" / "yet")) > 0

    def test_total_ram_is_a_positive_number_or_unknown(self) -> None:
        ram = doctor._total_ram()
        assert ram is None or ram > 0


class TestInContainer:
    """The operator container cannot see docker; it checks its own half only."""

    def _mounted(self, world: World, tmp_path: Path) -> None:
        for label in ("workspace", "control", "audit"):
            (tmp_path / label).mkdir()
            world.env[f"BUGGY_{label.upper()}_ROOT"] = str(tmp_path / label)

    def test_only_secrets_mounts_and_model_are_checked_and_docker_is_never_run(
        self, world: World, tmp_path: Path
    ) -> None:
        self._mounted(world, tmp_path)
        world.docker_path = None  # running docker here raises in the fake
        checks = world.checks("lite", in_container=True)
        assert [c.name for c in checks] == ["secret BUGGY_STACK_MCP_TOKEN", "mounts", "model"]
        assert _not_ok(checks) == [] and world.commands == [] and world.port_probes == []
        full = [c.name for c in world.checks("full", in_container=True)]
        assert full == [*(f"secret {name}" for name in SECRETS), "mounts", "model"]

    def test_a_missing_mount_fails_and_names_the_root(self, world: World, tmp_path: Path) -> None:
        self._mounted(world, tmp_path)
        world.env["BUGGY_CONTROL_ROOT"] = str(tmp_path / "not-mounted")
        mounts = _by_name(world.checks("lite", in_container=True))["mounts"]
        assert mounts.status == doctor.FAIL and "control root" in mounts.detail
        assert world.main("--profile", "lite", "--in-container") == 2

    def test_a_read_only_control_root_fails(self, world: World, tmp_path: Path) -> None:
        self._mounted(world, tmp_path)
        control = str(tmp_path / "control")
        mounts = _by_name(
            world.checks("lite", in_container=True, writable=lambda path: path != control)
        )["mounts"]
        assert mounts.status == doctor.FAIL and "control root" in mounts.detail

    def test_a_read_only_audit_root_is_how_the_operator_is_meant_to_see_it(
        self, world: World, tmp_path: Path
    ) -> None:
        # docker-compose.yml mounts /audit read-only into the operator container.
        self._mounted(world, tmp_path)
        audit = str(tmp_path / "audit")
        mounts = _by_name(
            world.checks("full", in_container=True, writable=lambda path: path != audit)
        )["mounts"]
        assert mounts.status == doctor.OK

    def test_the_flag_reaches_main(
        self, world: World, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._mounted(world, tmp_path)
        world.docker_path = None
        assert world.main("--profile", "lite", "--in-container", "--json") == 0
        payload = json.loads(capsys.readouterr().out)
        assert [c["name"] for c in payload["checks"]] == [
            "secret BUGGY_STACK_MCP_TOKEN",
            "mounts",
            "model",
        ]
