"""Tools must still start after the sandbox drops CAP_NET_ADMIN.

Kali's nmap carries cap_net_admin as a file capability. The sandbox removes
CAP_NET_ADMIN from its bounding set so nothing an agent runs can change
routing, and the kernel then refuses to exec such a file at all. The image
strips those file capabilities; this pins the Dockerfile step and, when the
image is present locally, runs nmap under the capability set the sandbox
really has.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "containers" / "sandbox.Dockerfile"
IMAGE = "buggy-sandbox:stable"
# The sandbox service's cap_add from docker-compose.yml, minus the two the
# entrypoint drops before anything the agent controls runs (NET_ADMIN, SETPCAP).
RUNTIME_CAPS = ("NET_RAW", "NET_BIND_SERVICE", "SYS_PTRACE", "SETUID", "SETGID")


def test_the_image_build_strips_file_capabilities_the_sandbox_drops() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "setcap -r /usr/lib/nmap/nmap" in text
    # The build fails if any binary still needs CAP_NET_ADMIN to start.
    assert "grep -q cap_net_admin" in text


def _docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@pytest.fixture(scope="module")
def sandbox_image() -> str:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        pytest.skip(f"{IMAGE} is not built locally")
    return IMAGE


def _in_sandbox(image: str, script: str) -> subprocess.CompletedProcess[str]:
    caps = [flag for cap in RUNTIME_CAPS for flag in ("--cap-add", cap)]
    return _docker(
        "run", "--rm", "--network", "none", "--cap-drop", "ALL", *caps,
        "--entrypoint", "sh", image, "-c", script,
    )  # fmt: skip


def test_nmap_starts_and_can_syn_scan_without_net_admin(sandbox_image: str) -> None:
    version = _in_sandbox(sandbox_image, "nmap --version")
    assert version.returncode == 0, version.stderr
    assert "Nmap version" in version.stdout
    scan = _in_sandbox(sandbox_image, "nmap -sS -p 80 -n 127.0.0.1")
    assert scan.returncode == 0 and "80/tcp" in scan.stdout, scan.stderr


def test_no_binary_in_the_image_needs_net_admin_to_start(sandbox_image: str) -> None:
    found = _in_sandbox(sandbox_image, "getcap -r /usr /opt /bin /sbin 2>/dev/null")
    assert "cap_net_admin" not in found.stdout, found.stdout
