"""``buggy-cli doctor`` — check every prerequisite of ``buggy hunt`` before it fails late.

    buggy-cli doctor
    buggy-cli doctor --profile lite
    buggy-cli doctor --json

One line per check, each with the exact remedy when it does not pass. Exit 0
when every required check passes (warnings do not count), 2 otherwise.

The environment is ``os.environ`` overlaid on a ``.env`` in the current
directory: a real environment variable wins over the file, the way Docker
Compose resolves the same two sources.

Nothing is started, pulled or built. The only thing written is the Buggy home
(``BUGGY_HOME``, default ``~/.buggy``) and its ``workspace``, ``control`` and
``audit`` directories, which are created when absent.

Every side effect (``which``, running a command, the filesystem, sockets) is
an argument of :func:`run_checks`, so the checks are testable without Docker.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TextIO

EXIT_OK = 0
EXIT_FAILED = 2

OK = "ok"
WARN = "warn"
FAIL = "fail"

PROFILES = ("lite", "full")
DEFAULT_PROFILE = "full"

REQUIRED_SECRETS = ("SANDBOX_TOKEN", "EGRESS_GUARD_TOKEN", "BUGGY_STACK_MCP_TOKEN")
SECRETS_FIX = (
    "run scripts/ensure-stack-secrets.sh (generates the missing secrets in ./.env; "
    "existing values are kept)"
)

LITE_IMAGES = ("buggy-pipeline",)
FULL_ONLY_IMAGES = (
    "buggy-langgraph",
    "buggy-litellm",
    "buggy-sandbox",
    "buggy-egress-guard",
    "buggy-browser",
    "buggy-skillogy",
)
DEFAULT_IMAGE_TAG = "stable"
IMAGES_FIX = "run `make build-images`"

#: Host ports the full stack publishes on 127.0.0.1: (variable, default).
FULL_PORTS = (
    ("LANGGRAPH_PORT", 2024),
    ("LITELLM_PORT", 4000),
    ("NEO4J_HTTP_PORT", 7474),
    ("NEO4J_BOLT_PORT", 7687),
)

DEFAULT_HOME = "~/.buggy"
HOME_DIRS = ("workspace", "control", "audit")

#: Decimal gigabyte, so a machine sold as "8 GB" (about 7.7 GiB) meets 8 GB.
GB = 10**9
DISK_FAIL_BELOW_GB = 10
DISK_WARN_BELOW_GB = 20
RAM_WARN_BELOW_GB = 8

MODEL_WARNING = "no model configured: recon and report still work; agents need a model"
MODEL_FIX = "set a provider API key in .env (`buggy-cli auth` lists the supported providers)"

DOCKER_FIX = "install Docker Engine or Docker Desktop (https://docs.docker.com/get-docker/)"
COMPOSE_FIX = "install the Docker Compose v2 plugin (https://docs.docker.com/compose/install/)"
DAEMON_FIX = (
    "start Docker (Docker Desktop, or `sudo systemctl start docker`) and check that "
    "`docker info` works for your user"
)
RERUN_FIX = "fix the docker checks above, then run `buggy-cli doctor` again"

COMMAND_TIMEOUT_SECONDS = 20.0

_COMPOSE_VERSION = re.compile(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?")
_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")

Which = Callable[[str], str | None]
Run = Callable[[Sequence[str]], tuple[int, str]]
Exists = Callable[[str], bool]
FreePort = Callable[[int], bool]
MakeDir = Callable[[str], None]
Writable = Callable[[str], bool]
DiskFree = Callable[[str], int]
TotalRam = Callable[[], int | None]


@dataclass(frozen=True)
class Check:
    """One preflight result. ``status`` is ``ok``, ``warn`` or ``fail``."""

    name: str
    status: str
    detail: str
    fix: str = ""

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


# ── environment ──────────────────────────────────────────────────────


def parse_env_file(text: str) -> dict[str, str]:
    """``KEY=VALUE`` lines; blank lines, comments and anything else are ignored.

    A value in matching quotes is taken literally between them. An unquoted
    value ends at a ``#`` that follows whitespace, as in Docker Compose.
    """
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if match is None:
            continue
        name, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
        values[name] = value
    return values


def load_env(environ: Mapping[str, str], dotenv: Path) -> dict[str, str]:
    """The ``.env`` file (when present) with the real environment laid over it."""
    values: dict[str, str] = {}
    try:
        values.update(parse_env_file(dotenv.read_text(encoding="utf-8", errors="replace")))
    except OSError:
        pass
    values.update(environ)
    return values


def _value(env: Mapping[str, str], name: str) -> str:
    return (env.get(name) or "").strip()


def home_dir(env: Mapping[str, str]) -> Path:
    """``BUGGY_HOME`` (default ``~/.buggy``), ``~`` resolved from ``env``'s ``HOME`` first."""
    raw = _value(env, "BUGGY_HOME") or DEFAULT_HOME
    base = _value(env, "HOME")
    if base and (raw == "~" or raw.startswith("~/")):
        return Path(base) / raw[2:]
    return Path(raw).expanduser()


def required_images(profile: str, env: Mapping[str, str]) -> list[str]:
    tag = _value(env, "BUGGY_VERSION") or DEFAULT_IMAGE_TAG
    names = LITE_IMAGES if profile == "lite" else LITE_IMAGES + FULL_ONLY_IMAGES
    return [f"{name}:{tag}" for name in names]


# ── real side effects (the defaults) ─────────────────────────────────


def _run_command(argv: Sequence[str]) -> tuple[int, str]:
    """Exit code and output: stdout on success, the error text otherwise."""
    try:
        done = subprocess.run(  # noqa: S603 - fixed docker argv, never a shell
            list(argv),
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return 127, f"{argv[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {COMMAND_TIMEOUT_SECONDS:.0f}s"
    except OSError as exc:
        return 126, str(exc)
    out, err = done.stdout.strip(), done.stderr.strip()
    return done.returncode, out if done.returncode == 0 else (err or out)


def _port_is_free(port: int) -> bool:
    """Whether 127.0.0.1:``port`` (where the stack publishes) can be bound."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return False  # something answers there
    except OSError:
        pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if os.name == "posix":
            # Ignore a socket lingering in TIME_WAIT; a live listener still refuses.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _make_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def _is_writable(path: str) -> bool:
    """A real write, because permission bits do not tell the whole story."""
    try:
        with tempfile.NamedTemporaryFile(dir=path, prefix=".doctor-"):
            pass
    except OSError:
        return False
    return True


def _disk_free(path: str) -> int:
    probe = Path(path)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return shutil.disk_usage(probe).free


def _total_ram() -> int | None:
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, ValueError, OSError):
        return None


# ── checks ───────────────────────────────────────────────────────────


def _first_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[0].strip() if lines else ""


def check_docker(which: Which) -> Check:
    path = which("docker")
    if path:
        return Check("docker", OK, str(path))
    return Check("docker", FAIL, "the `docker` command is not on PATH", DOCKER_FIX)


def check_compose(run: Run) -> Check:
    code, output = run(["docker", "compose", "version"])
    line = _first_line(output)
    if code != 0:
        return Check(
            "docker compose",
            FAIL,
            f"`docker compose version` failed: {line or f'exit {code}'}",
            COMPOSE_FIX,
        )
    match = _COMPOSE_VERSION.search(output)
    if match is None:
        return Check(
            "docker compose",
            FAIL,
            f"cannot read a version from `docker compose version`: {line or '(no output)'}",
            COMPOSE_FIX,
        )
    version = ".".join(part for part in match.groups() if part is not None)
    if int(match.group(1)) < 2:
        return Check(
            "docker compose",
            FAIL,
            f"Compose v{version} found; v2 or newer is required",
            COMPOSE_FIX,
        )
    return Check("docker compose", OK, f"v{version}")


def check_daemon(run: Run) -> Check:
    code, output = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    line = _first_line(output)
    if code == 0 and line:
        return Check("docker daemon", OK, f"server {line}")
    return Check(
        "docker daemon",
        FAIL,
        f"the Docker daemon is not reachable: {line or f'exit {code}'}",
        DAEMON_FIX,
    )


def check_secret(env: Mapping[str, str], name: str) -> Check:
    if _value(env, name):
        return Check(f"secret {name}", OK, "set")
    state = "empty" if name in env else "not set"
    return Check(f"secret {name}", FAIL, f"{name} is {state}", SECRETS_FIX)


def check_image(run: Run, image: str) -> Check:
    code, output = run(["docker", "image", "inspect", "--format", "{{.Id}}", image])
    if code == 0:
        return Check(f"image {image}", OK, "present")
    return Check(
        f"image {image}",
        FAIL,
        f"not found locally ({_first_line(output) or f'exit {code}'})",
        IMAGES_FIX
        if image.endswith(f":{DEFAULT_IMAGE_TAG}")
        else f"{IMAGES_FIX} (it builds the `{DEFAULT_IMAGE_TAG}` tag: unset BUGGY_VERSION, "
        f"or tag the built images as `{image.rpartition(':')[2]}`)",
    )


def check_port(env: Mapping[str, str], variable: str, default: int, free_port: FreePort) -> Check:
    name = f"port {variable}"
    raw = _value(env, variable)
    try:
        port = int(raw) if raw else default
    except ValueError:
        port = -1
    if not 1 <= port <= 65535:
        return Check(
            name,
            FAIL,
            f"{variable}={raw!r} is not a port number",
            f"set {variable} to a free port between 1 and 65535 (default {default})",
        )
    if free_port(port):
        return Check(name, OK, f"127.0.0.1:{port} is free")
    return Check(
        name,
        FAIL,
        f"127.0.0.1:{port} is already in use",
        f"set {variable} to a free port in .env, or stop what is listening on {port} "
        "(a Buggy stack that is already running holds it)",
    )


def check_home(
    env: Mapping[str, str], *, exists: Exists, make_dir: MakeDir, writable: Writable
) -> Check:
    home = home_dir(env)
    fix = f"make {home} writable for your user, or set BUGGY_HOME to a directory you own"
    created: list[str] = []
    for path in (home, *(home / name for name in HOME_DIRS)):
        if not exists(str(path)):
            try:
                make_dir(str(path))
            except OSError as exc:
                reason = exc.strerror or str(exc) or type(exc).__name__
                return Check("BUGGY_HOME", FAIL, f"cannot create {path}: {reason}", fix)
            created.append(path.name if path != home else "the directory")
        if not writable(str(path)):
            return Check("BUGGY_HOME", FAIL, f"{path} is not a writable directory", fix)
    detail = f"{home} is writable"
    if created:
        detail += f" (created {', '.join(created)})"
    return Check("BUGGY_HOME", OK, detail)


def check_disk(env: Mapping[str, str], disk_free: DiskFree) -> Check:
    home = home_dir(env)
    fix = f"free disk space at {home}, or set BUGGY_HOME to a larger volume"
    try:
        free = disk_free(str(home))
    except OSError as exc:
        reason = exc.strerror or str(exc) or type(exc).__name__
        return Check("disk", FAIL, f"cannot read free space at {home}: {reason}", fix)
    amount = f"{free / GB:.1f} GB free at {home}"
    if free < DISK_FAIL_BELOW_GB * GB:
        return Check("disk", FAIL, f"{amount}; at least {DISK_FAIL_BELOW_GB} GB is required", fix)
    if free < DISK_WARN_BELOW_GB * GB:
        return Check("disk", WARN, f"{amount}; {DISK_WARN_BELOW_GB} GB or more is recommended", fix)
    return Check("disk", OK, amount)


def check_memory(total_ram: TotalRam) -> Check:
    fix = (
        f"give the machine (or the Docker VM) {RAM_WARN_BELOW_GB} GB of RAM, or use --profile lite"
    )
    total = total_ram()
    if total is None:
        return Check("memory", WARN, "cannot read the total RAM on this platform", fix)
    amount = f"{total / GB:.1f} GB RAM"
    if total < RAM_WARN_BELOW_GB * GB:
        return Check(
            "memory",
            WARN,
            f"{amount}; the full stack wants {RAM_WARN_BELOW_GB} GB or more",
            fix,
        )
    return Check("memory", OK, amount)


def check_model(env: Mapping[str, str]) -> Check:
    from buggy.cli.hunt import model_configured  # noqa: PLC0415 - heavy import, only when run

    if model_configured(dict(env)):
        return Check("model", OK, "a model provider is configured")
    return Check("model", WARN, MODEL_WARNING, MODEL_FIX)


def _not_checked(name: str, why: str) -> Check:
    # Never report an unverified prerequisite as passing.
    return Check(name, FAIL, f"not checked: {why}", RERUN_FIX)


def run_checks(
    env: Mapping[str, str],
    *,
    which: Which | None = None,
    run: Run | None = None,
    exists: Exists | None = None,
    free_port: FreePort | None = None,
    profile: str = DEFAULT_PROFILE,
    make_dir: MakeDir | None = None,
    writable: Writable | None = None,
    disk_free: DiskFree | None = None,
    total_ram: TotalRam | None = None,
) -> list[Check]:
    """Every preflight check for ``profile``, in a fixed order.

    ``env`` is the effective environment. Each callable defaults to the real
    side effect; tests pass fakes.
    """
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r} (expected one of {', '.join(PROFILES)})")
    which = which or shutil.which
    run = run or _run_command
    exists = exists or os.path.exists
    free_port = free_port or _port_is_free
    make_dir = make_dir or _make_dir
    writable = writable or _is_writable
    disk_free = disk_free or _disk_free
    total_ram = total_ram or _total_ram
    full = profile == "full"

    checks: list[Check] = []

    docker = check_docker(which)
    checks.append(docker)
    if docker.status == OK:
        checks.append(check_compose(run))
        daemon = check_daemon(run)
        checks.append(daemon)
        blocked = "" if daemon.status == OK else "the Docker daemon is not reachable"
    else:
        blocked = "docker is not installed"
        checks.append(_not_checked("docker compose", blocked))
        checks.append(_not_checked("docker daemon", blocked))

    checks.extend(check_secret(env, name) for name in REQUIRED_SECRETS)

    for image in required_images(profile, env):
        checks.append(
            _not_checked(f"image {image}", blocked) if blocked else check_image(run, image)
        )

    if full:
        checks.extend(
            check_port(env, variable, default, free_port) for variable, default in FULL_PORTS
        )

    checks.append(check_home(env, exists=exists, make_dir=make_dir, writable=writable))
    checks.append(check_disk(env, disk_free))
    if full:
        checks.append(check_memory(total_ram))
    checks.append(check_model(env))
    return checks


# ── output ───────────────────────────────────────────────────────────

_LABELS = {OK: "ok", WARN: "warn", FAIL: "FAIL"}


def passed(checks: Sequence[Check]) -> bool:
    """True when nothing failed. Warnings do not fail the preflight."""
    return all(check.status != FAIL for check in checks)


def render_json(checks: Sequence[Check]) -> str:
    return json.dumps(
        {"ok": passed(checks), "checks": [check.as_dict() for check in checks]}, indent=2
    )


def render_table(checks: Sequence[Check]) -> str:
    """One line per check: aligned status, name and detail, then the fix when there is one.

    The fix follows its detail directly. Padding it into a fourth column would
    push every fix as far right as the longest detail (often a long path).
    """
    status_width = max(len(label) for label in _LABELS.values())
    name_width = max((len(check.name) for check in checks), default=0)
    lines = []
    for check in checks:
        label = _LABELS.get(check.status, check.status)
        line = f"{label:<{status_width}}  {check.name:<{name_width}}  {check.detail}"
        if check.fix:
            line += f"  fix: {check.fix}"
        lines.append(line.rstrip())
    failed = sum(1 for check in checks if check.status == FAIL)
    warned = sum(1 for check in checks if check.status == WARN)
    verdict = "ready" if failed == 0 else "not ready"
    lines.append("")
    lines.append(f"{verdict}: {len(checks) - failed - warned} ok, {warned} warn, {failed} failed")
    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="buggy-cli doctor",
        description=(
            "Check every prerequisite of `buggy hunt` and print one line per check with a fix. "
            "Exit 0 when every required check passes, 2 otherwise."
        ),
    )
    parser.add_argument(
        "--profile",
        choices=PROFILES,
        default=DEFAULT_PROFILE,
        help="lite: recon pipeline only; full: the whole stack with agents (default: full)",
    )
    parser.add_argument(
        "--json", action="store_true", help='print {"ok": bool, "checks": [...]} instead of a table'
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    dotenv: Path | None = None,
    stdout: TextIO | None = None,
    which: Which | None = None,
    run: Run | None = None,
    exists: Exists | None = None,
    free_port: FreePort | None = None,
    make_dir: MakeDir | None = None,
    writable: Writable | None = None,
    disk_free: DiskFree | None = None,
    total_ram: TotalRam | None = None,
) -> int:
    """Run the preflight. The keyword arguments replace the real world in tests."""
    args = _build_parser().parse_args(argv)
    env = load_env(
        os.environ if environ is None else environ,
        Path.cwd() / ".env" if dotenv is None else dotenv,
    )
    checks = run_checks(
        env,
        which=which,
        run=run,
        exists=exists,
        free_port=free_port,
        profile=args.profile,
        make_dir=make_dir,
        writable=writable,
        disk_free=disk_free,
        total_ram=total_ram,
    )
    out = sys.stdout if stdout is None else stdout
    print(render_json(checks) if args.json else render_table(checks), file=out)
    return EXIT_OK if passed(checks) else EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
