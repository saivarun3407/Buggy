"""Behavior tests for the Bash installer."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).parents[5]
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install.sh"


def test_stable_resolver_reads_release_payload_from_curl(tmp_path: Path) -> None:
    script_without_main = INSTALL_SCRIPT.read_text(encoding="utf-8").rsplit('\nmain "$@"', 1)[0]
    releases = [
        {
            "tag_name": "v1.2.3",
            "published_at": "2020-01-01T00:00:00Z",
            "draft": False,
            "prerelease": False,
        }
    ]
    harness = tmp_path / "resolve-stable.sh"
    harness.write_text(
        f"""{script_without_main}
curl() {{
    printf '%s' "$RELEASES_JSON"
}}
resolve_stable_soaked
""",
        encoding="utf-8",
    )
    env = os.environ | {
        "BUGGY_STABLE_SOAK_DAYS": "7",
        "RELEASES_JSON": json.dumps(releases),
    }

    completed = subprocess.run(
        ["bash", str(harness)],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )

    assert completed.stdout.strip() == "1.2.3"


def test_download_files_fetches_tun_overlay(tmp_path: Path) -> None:
    """download_files must pull docker-compose.tun.yml alongside the base
    compose file.

    The opt-in TUN overlay ships in the repo but is useless to release/
    updated installs unless the installer actually downloads it — without
    this fetch those operators can never enable ligolo-ng Layer-3 pivoting.
    A stub curl records every URL download_files requests so we can assert
    the overlay is among them.
    """
    script_without_main = INSTALL_SCRIPT.read_text(encoding="utf-8").rsplit('\nmain "$@"', 1)[0]
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    url_log = tmp_path / "curl-urls.txt"
    harness = tmp_path / "download.sh"
    harness.write_text(
        f"""{script_without_main}
RAW_BASE="https://raw.example/repo/vX"
BUGGY_VERSION="9.9.9"
# Stub network + manifest verification: record each -o download's URL and
# create the destination file so the (untested here) manifest step is a
# no-op. verify_config_manifest is overridden to skip real hashing.
curl() {{
    local url="" out=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) out="$2"; shift 2 ;;
            -*) shift ;;
            *) url="$1"; shift ;;
        esac
    done
    printf '%s\\n' "$url" >> "$URL_LOG"
    [[ -n "$out" ]] && printf 'stub' > "$out"
    return 0
}}
verify_config_manifest() {{ :; }}
download_files "{install_dir}"
""",
        encoding="utf-8",
    )
    env = os.environ | {"URL_LOG": str(url_log)}

    subprocess.run(
        ["bash", str(harness)],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )

    urls = url_log.read_text(encoding="utf-8").splitlines()
    assert "https://raw.example/repo/vX/docker-compose.tun.yml" in urls
    assert (install_dir / "docker-compose.tun.yml").is_file()

    # Every compose file in the release manifest must be downloaded: the
    # installer refuses to finish when the manifest lists a file that is not
    # on disk, so a file added to one list and not the other breaks installs.
    release = (INSTALL_SCRIPT.parent.parent / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    line = next(ln for ln in release.splitlines() if "sha256sum docker-compose.yml" in ln)
    listed = [word for word in line.split() if word.startswith("docker-compose")]
    assert {"docker-compose.lite.yml", "docker-compose.lab.yml", "docker-compose.demo.yml"} <= set(
        listed
    )
    for name in listed:
        assert f"https://raw.example/repo/vX/{name}" in urls, name
        assert (install_dir / name).is_file(), name


def _source_installer(tmp_path: Path, body: str, env: dict[str, str]) -> str:
    """Run ``body`` after sourcing the installer (without ``main``); stdout."""
    script_without_main = INSTALL_SCRIPT.read_text(encoding="utf-8").rsplit('\nmain "$@"', 1)[0]
    harness = tmp_path / "harness.sh"
    harness.write_text(f"{script_without_main}\n{body}\n", encoding="utf-8")
    base = {k: v for k, v in os.environ.items() if k not in ("BUGGY_REPO", "BUGGY_IMAGE_PREFIX")}
    completed = subprocess.run(
        ["bash", str(harness)],
        check=True,
        capture_output=True,
        env=base | env,
        text=True,
    )
    return completed.stdout


def test_installs_from_this_repository_by_default(tmp_path: Path) -> None:
    out = _source_installer(
        tmp_path, 'printf "%s|%s|%s\\n" "$REPO" "$IMAGE_PREFIX" "$RELEASE_BASE"', {}
    )
    assert out.strip() == (
        "saivarun3407/Buggy|ghcr.io/saivarun3407/"
        "|https://github.com/saivarun3407/Buggy/releases/download"
    )


def test_buggy_repo_overrides_the_repository_and_lowercases_the_registry(
    tmp_path: Path,
) -> None:
    out = _source_installer(
        tmp_path, 'printf "%s|%s\\n" "$REPO" "$IMAGE_PREFIX"', {"BUGGY_REPO": "Some-Org/Buggy"}
    )
    assert out.strip() == "Some-Org/Buggy|ghcr.io/some-org/"


def test_a_malformed_buggy_repo_is_refused(tmp_path: Path) -> None:
    script_without_main = INSTALL_SCRIPT.read_text(encoding="utf-8").rsplit('\nmain "$@"', 1)[0]
    harness = tmp_path / "harness.sh"
    harness.write_text(script_without_main, encoding="utf-8")
    completed = subprocess.run(
        ["bash", str(harness)],
        check=False,
        capture_output=True,
        env=os.environ | {"BUGGY_REPO": "evil.example/x/../y"},
        text=True,
    )
    assert completed.returncode != 0
    assert "BUGGY_REPO" in completed.stderr


def _download_with_env(tmp_path: Path, dotenv: str | None) -> Path:
    """Run download_files against a stubbed curl, with an optional existing .env."""
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    if dotenv is not None:
        (install_dir / ".env").write_text(dotenv, encoding="utf-8")
    _source_installer(
        tmp_path,
        f"""RAW_BASE="https://raw.example/repo/vX"
BUGGY_VERSION="9.9.9"
curl() {{
    local out=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) out="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    [[ -n "$out" ]] && printf 'stub' > "$out"
    return 0
}}
verify_config_manifest() {{ :; }}
download_files "{install_dir}"
""",
        {},
    )
    return install_dir


def test_an_existing_env_gets_the_registry_prefix(tmp_path: Path) -> None:
    install_dir = _download_with_env(tmp_path, "BUGGY_HOME=/x\n")
    lines = (install_dir / ".env").read_text(encoding="utf-8").splitlines()
    assert "BUGGY_IMAGE_PREFIX=ghcr.io/saivarun3407/" in lines


def test_an_operators_own_prefix_is_kept(tmp_path: Path) -> None:
    install_dir = _download_with_env(tmp_path, "BUGGY_IMAGE_PREFIX=registry.local/mirror/\n")
    text = (install_dir / ".env").read_text(encoding="utf-8")
    assert text.count("BUGGY_IMAGE_PREFIX=") == 1
    assert "BUGGY_IMAGE_PREFIX=registry.local/mirror/" in text


def test_a_fresh_install_does_not_create_env(tmp_path: Path) -> None:
    # `buggy onboard` runs only when .env is absent; the launcher records the
    # prefix on its first start instead.
    install_dir = _download_with_env(tmp_path, None)
    assert not (install_dir / ".env").exists()


def test_the_image_pull_uses_the_registry_prefix(tmp_path: Path) -> None:
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    out = _source_installer(
        tmp_path,
        f"""BUGGY_VERSION="9.9.9"
docker() {{ printf '%s|%s|%s\\n' "$BUGGY_IMAGE_PREFIX" "$BUGGY_VERSION" "$*"; }}
pull_images "{install_dir}"
""",
        {},
    )
    assert "ghcr.io/saivarun3407/|9.9.9|compose --profile cli pull" in out
