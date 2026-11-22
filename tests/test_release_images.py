"""A release publishes, from THIS repository, every image an install pulls.

An installed machine has no source tree: ``docker compose up --no-build``
there can only run images the release workflow pushed. These tests pin the
three ways that has gone wrong before:

* an image the compose files run that no release job builds (the stack
  then fails to start on every install), or that a later step — the
  verify/promote lists in release.yml, promote-stable.yml,
  release-recover.yml, pin-digests.yml — forgets;
* a workflow, script or launcher source that hard-codes another project's
  GitHub organisation or registry namespace, so a tag pushed here
  publishes (or an install downloads) somewhere else;
* the ``${BUGGY_IMAGE_PREFIX:-}`` registry prefix changing what a source
  build runs: unset, every name must be exactly the bare local name.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
FULL = REPO_ROOT / "docker-compose.yml"
LITE = REPO_ROOT / "docker-compose.lite.yml"
#: The compose files whose Buggy images an install pulls.
INSTALLED_COMPOSE = (FULL, LITE)

#: Every Buggy image line in an installed compose file has this shape.
IMAGE_LINE = re.compile(
    r"^\$\{BUGGY_IMAGE_PREFIX:-\}(buggy-[a-z0-9-]+):\$\{BUGGY_VERSION:-stable\}$"
)

#: Buggy images the compose files name that a release deliberately does not
#: publish, with the reason. Each may only be used by a profile-gated
#: service, so no default ``docker compose up`` (or the lite stack) needs it.
NOT_RELEASED = {
    # Sandbox + JDK + Ghidra for the `reversing` profile. The Ghidra archive
    # is downloaded without a pinned checksum (GHIDRA_SHA256 is empty in the
    # compose build args), so it is not signed and published as a release
    # image until that pin exists.
    "buggy-sandbox-reversing": "reversing profile; Ghidra download is not checksum-pinned",
}

PROFILES = "reversing,cli,operator,web"
#: Render-only secrets the compose files refuse to interpolate without.
RENDER_SECRETS = {
    "SANDBOX_TOKEN": "test-sandbox-token",
    "EGRESS_GUARD_TOKEN": "test-guard-token",
    "BUGGY_STACK_MCP_TOKEN": "test-stack-mcp-token",
}


# ── what the compose files run ───────────────────────────────────────


def _source_services(path: Path) -> dict[str, dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["services"]


def _buggy_images(path: Path) -> dict[str, str]:
    """Service -> Buggy image name (``buggy-<name>``) as the file declares it."""
    out: dict[str, str] = {}
    for name, service in _source_services(path).items():
        image = str(service.get("image", ""))
        if "buggy-" not in image:
            continue
        match = IMAGE_LINE.match(image)
        assert match, (
            f"{path.name}: service {name} image {image!r} is not "
            "${BUGGY_IMAGE_PREFIX:-}buggy-<name>:${BUGGY_VERSION:-stable}"
        )
        out[name] = match.group(1)
    return out


def _compose_images() -> set[str]:
    return {image for path in INSTALLED_COMPOSE for image in _buggy_images(path).values()}


# ── what the release builds ──────────────────────────────────────────


def _release() -> dict:
    return yaml.safe_load(RELEASE.read_text(encoding="utf-8"))


def _matrix_images(job: dict) -> list[str]:
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    images = [entry["image"] for entry in matrix.get("include", []) if "image" in entry]
    images += list(matrix.get("image", []))
    return images


def _build_steps(job: dict) -> list[dict]:
    return [
        step
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("docker/build-push-action@")
    ]


def _step_images(job: dict, step: dict) -> set[str]:
    """The Buggy images one build-push-action step pushes."""
    with_ = step.get("with") or {}
    target = f"{with_.get('tags', '')} {with_.get('outputs', '')}"
    if "${{ matrix.image }}" in target:
        return set(_matrix_images(job))
    return set(re.findall(r"/(buggy-[a-z0-9-]+)[:,]", target))


def _built_by_job() -> dict[str, set[str]]:
    built: dict[str, set[str]] = {}
    for name, job in _release()["jobs"].items():
        for step in _build_steps(job):
            built.setdefault(name, set()).update(_step_images(job, step))
    return built


def _built() -> set[str]:
    return set().union(*_built_by_job().values())


def _bash_arrays(text: str) -> list[set[str]]:
    """Every ``images=( ... )`` / ``images="..."`` list in a workflow."""
    lists = [set(body.split()) for body in re.findall(r"images=\(\s*(.*?)\)", text, re.S)]
    lists += [set(body.split()) for body in re.findall(r'images="([^"]*)"', text)]
    return lists


def test_compose_images_are_read() -> None:
    # Guard the guard: a parser that finds nothing would pass every test below.
    images = _compose_images()
    assert {"buggy-pipeline", "buggy-langgraph", "buggy-sandbox", "buggy-web"} <= images
    assert _buggy_images(LITE) == {
        "pipeline": "buggy-pipeline",
        "pipeline-mcp": "buggy-pipeline",
        "operator": "buggy-pipeline",
    }


def test_every_compose_image_is_built_by_a_release() -> None:
    missing = _compose_images() - _built() - set(NOT_RELEASED)
    assert not missing, f"release.yml builds no image for {sorted(missing)}"


def test_unreleased_images_are_only_on_profile_gated_services() -> None:
    for path in INSTALLED_COMPOSE:
        services = _source_services(path)
        for name, image in _buggy_images(path).items():
            if image in NOT_RELEASED:
                assert services[name].get("profiles"), (
                    f"{path.name}: {name} runs {image}, which no release publishes "
                    f"({NOT_RELEASED[image]}), yet it starts with a default `up`"
                )
    assert not set(NOT_RELEASED) & _built(), "an image listed as not released is built"


def test_release_builds_nothing_the_stack_does_not_use() -> None:
    assert _built() <= _compose_images(), sorted(_built() - _compose_images())


def test_digest_builds_are_merged_signed_and_attested() -> None:
    """Images pushed by digest (native per-platform runners) only become a
    tagged, signed manifest in the matching merge job."""
    jobs = _release()["jobs"]
    built = _built_by_job()
    assert set(_matrix_images(jobs["docker-heavy-merge"])) == built["docker-heavy"]
    for name, images in built.items():
        job = jobs[name]
        runs = " ".join(str(step.get("run", "")) for step in job.get("steps", []))
        by_digest = any(
            "push-by-digest=true" in str((step.get("with") or {}).get("outputs", ""))
            for step in _build_steps(job)
        )
        if by_digest:
            continue
        assert "cosign sign" in runs, f"{name} pushes {sorted(images)} without cosign sign"
        assert "cosign attest" in runs, (
            f"{name} pushes {sorted(images)} without an SBOM attestation"
        )
    for merge in ("docker-heavy-merge", "docker-web-merge"):
        runs = " ".join(str(step.get("run", "")) for step in jobs[merge]["steps"])
        assert "cosign sign" in runs and "cosign attest" in runs, merge


@pytest.mark.parametrize(
    "workflow",
    ["release.yml", "promote-stable.yml", "release-recover.yml", "pin-digests.yml"],
)
def test_every_image_list_names_every_built_image(workflow: str) -> None:
    lists = _bash_arrays((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    assert lists, f"{workflow}: no image list found"
    built = _built()
    for listed in lists:
        assert listed == built, (
            f"{workflow}: list {sorted(listed)} differs from the built images: "
            f"missing {sorted(built - listed)}, extra {sorted(listed - built)}"
        )


def test_the_release_gate_waits_for_every_image_job_but_not_for_pypi() -> None:
    jobs = _release()["jobs"]
    needs = set(jobs["publish-release"]["needs"])
    image_jobs = {name for name in _built_by_job() if name not in ("docker-heavy", "docker-web")}
    assert image_jobs | {"launcher"} <= needs, sorted(image_jobs - needs)
    # PyPI is opt-in: nothing may depend on it, or skipping it skips the release.
    assert jobs["publish-pypi"]["if"] == "vars.PUBLISH_PYPI == 'true'"
    for name, job in jobs.items():
        job_needs = job.get("needs", [])
        job_needs = [job_needs] if isinstance(job_needs, str) else job_needs
        assert "publish-pypi" not in job_needs, f"{name} needs the opt-in PyPI job"


# ── no other project's organisation as a target ──────────────────────

#: Places that decide where a release publishes or an install downloads.
TARGET_FILES = (
    sorted((REPO_ROOT / ".github").rglob("*.yml"))
    + sorted((REPO_ROOT / ".github").rglob("*.yaml"))
    + sorted((REPO_ROOT / "scripts").glob("*.sh"))
    + sorted((REPO_ROOT / "scripts").glob("*.ps1"))
    + sorted((REPO_ROOT / "scripts").glob("*.py"))
    + sorted((REPO_ROOT / "clients" / "launcher").rglob("*.go"))
    + [REPO_ROOT / "clients" / "launcher" / ".goreleaser.yml"]
    + sorted(REPO_ROOT.glob("docker-compose*.yml"))
    + [REPO_ROOT / ".env.example"]
)
#: A registry namespace, a repository slug or URL, or a release owner.
UPSTREAM_TARGET = re.compile(
    r"ghcr\.io/purpleailab|purpleailab/buggy|github\.com/purpleailab|owner:\s*['\"]?purpleailab",
    re.IGNORECASE,
)


def test_target_files_are_found() -> None:
    names = {path.name for path in TARGET_FILES}
    assert {"release.yml", "install.sh", "updater.go", ".goreleaser.yml"} <= names


@pytest.mark.parametrize("path", TARGET_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_no_upstream_organisation_is_a_target(path: Path) -> None:
    hits = [
        f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if UPSTREAM_TARGET.search(line)
    ]
    assert not hits, "hard-coded upstream target:\n" + "\n".join(hits)


def test_registry_paths_come_from_the_github_context() -> None:
    """Every ghcr.io path in the image workflows is derived from the
    repository owner, lower-cased (registry paths must be lower case)."""
    for workflow in ("release.yml", "promote-stable.yml", "release-recover.yml", "pin-digests.yml"):
        text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for ref in re.findall(r"ghcr\.io/[^\s\"']*", code):
            assert ref.startswith("ghcr.io/${GITHUB_REPOSITORY_OWNER,,}"), f"{workflow}: {ref}"


# ── the prefix renders exactly as before when unset ──────────────────


def _render(path: Path, prefix: str | None, profiles: str, project: Path) -> dict[str, str]:
    """Service -> rendered image for ``path``, independent of the caller's shell.

    ``project`` is the project directory: an empty one with an empty ``.env``
    (the full stack's ``env_file:``), so the render never reads, creates or
    removes the repository's own ``.env``. Image names do not depend on it.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    (project / ".env").touch()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BUGGY_", "COMPOSE_"))}
    env.update(RENDER_SECRETS)
    env["COMPOSE_PROFILES"] = profiles
    if prefix is not None:
        env["BUGGY_IMAGE_PREFIX"] = prefix
    result = subprocess.run(  # noqa: S603 - fixed argv
        [  # noqa: S607 - docker from PATH, as in the other compose tests
            "docker",
            "compose",
            "--env-file",
            os.devnull,
            "--project-directory",
            str(project),
            "-f",
            str(path),
            "config",
        ],
        env=env,
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            f"docker compose config failed (exit {result.returncode}):\n"
            f"--- stderr ---\n{result.stderr}\n--- stdout ---\n{result.stdout}"
        )
    services = yaml.safe_load(result.stdout)["services"]
    return {name: service.get("image", "") for name, service in services.items()}


@pytest.mark.parametrize(
    ("path", "profiles"), [(FULL, PROFILES), (LITE, "operator")], ids=["full", "lite"]
)
def test_images_render_unprefixed_by_default_and_prefixed_when_set(
    path: Path, profiles: str, tmp_path: Path
) -> None:
    declared = _buggy_images(path)
    unset = _render(path, None, profiles, tmp_path)
    empty = _render(path, "", profiles, tmp_path)
    prefixed = _render(path, "ghcr.io/owner/", profiles, tmp_path)

    # Unset (and explicitly empty): exactly the bare names a source build tags.
    assert set(declared) <= set(unset)
    for service, image in declared.items():
        assert unset[service] == f"{image}:stable", service
    assert empty == unset

    # Set: only the Buggy images change, and only by the prefix.
    for service, rendered in unset.items():
        if service in declared:
            assert prefixed[service] == f"ghcr.io/owner/{rendered}", service
        else:
            assert prefixed[service] == rendered, service


def test_the_lite_operator_is_the_bare_pipeline_image_by_default(tmp_path: Path) -> None:
    assert _render(LITE, None, "operator", tmp_path)["operator"] == "buggy-pipeline:stable"
