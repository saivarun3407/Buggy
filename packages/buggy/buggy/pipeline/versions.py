"""Pinned versions of every scanner the pipeline runs.

``PINNED`` is the single source of truth: ``containers/pipeline.Dockerfile``
installs exactly these (``python -m buggy.pipeline.versions --install-plan``)
and then writes a manifest of the resulting binaries' SHA-256 hashes
(``--write-manifest``). At run time :func:`verify` refuses a binary whose
hash is not the one recorded at build time, so the tool that parsed the
fixtures in the test suite is the tool that runs.

Outside the image (a developer laptop) there is no manifest; set
``BUGGY_PIPELINE_ALLOW_UNPINNED=1`` to run with whatever is on ``PATH``. The
observed version string is then recorded on every record instead.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MANIFEST = "/opt/buggy/pipeline-tools.json"


@dataclass(frozen=True, slots=True)
class PinnedTool:
    name: str
    version: str
    module: str  # ``go install <module>@<version>``
    version_args: tuple[str, ...] = ()  # how to ask the binary; () when it cannot say
    version_pattern: str = r"v?(\d+\.\d+\.\d+)"


PINNED: dict[str, PinnedTool] = {
    tool.name: tool
    for tool in (
        PinnedTool(
            "subfinder",
            "2.17.0",
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
            ("-version",),
        ),
        PinnedTool("amass", "4.2.0", "github.com/owasp-amass/amass/v4/...", ("-version",)),
        PinnedTool("dnsx", "1.3.1", "github.com/projectdiscovery/dnsx/cmd/dnsx", ("-version",)),
        PinnedTool("httpx", "1.12.0", "github.com/projectdiscovery/httpx/cmd/httpx", ("-version",)),
        PinnedTool(
            "naabu", "2.7.0", "github.com/projectdiscovery/naabu/v2/cmd/naabu", ("-version",)
        ),
        PinnedTool(
            "katana", "1.8.0", "github.com/projectdiscovery/katana/cmd/katana", ("-version",)
        ),
        PinnedTool(
            "nuclei", "3.11.1", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei", ("-version",)
        ),
        PinnedTool("gau", "2.2.4", "github.com/lc/gau/v2/cmd/gau"),
        PinnedTool("waybackurls", "0.1.0", "github.com/tomnomnom/waybackurls"),
        PinnedTool("gitleaks", "8.30.1", "github.com/zricethezav/gitleaks/v8"),
    )
}

# The vetted nuclei template set: one pinned release of the upstream
# repository, restricted further by ``tools/nuclei.py``.
NUCLEI_TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates"
NUCLEI_TEMPLATES_VERSION = "v10.5.2"
NUCLEI_TEMPLATES_DIR = "/opt/nuclei-templates"

# Tools implemented in this package (no external binary).
BUILTIN_VERSION = "builtin-1"


class ToolVersionError(RuntimeError):
    """A scanner is missing or is not the pinned build."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: str | None = None) -> dict[str, dict[str, str]]:
    manifest_path = Path(path or os.environ.get("BUGGY_PIPELINE_TOOL_MANIFEST") or DEFAULT_MANIFEST)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def observed_version(name: str, binary: str) -> str:
    """Version the binary reports, or ``""`` when it has no version flag."""
    pinned = PINNED[name]
    if not pinned.version_args:
        return ""
    try:
        proc = subprocess.run(  # noqa: S603
            [binary, *pinned.version_args], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    match = re.search(pinned.version_pattern, f"{proc.stdout}\n{proc.stderr}")
    return match.group(1) if match else ""


def allow_unpinned() -> bool:
    return os.environ.get("BUGGY_PIPELINE_ALLOW_UNPINNED", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def verify(name: str, *, manifest: dict[str, dict[str, str]] | None = None) -> tuple[str, str]:
    """Return ``(binary_path, version_label)`` for a pinned tool, or raise.

    With a build manifest the binary's SHA-256 must match it. Without one the
    reported version must equal the pin, unless unpinned runs are allowed.
    """
    if name not in PINNED:
        raise ToolVersionError(f"{name} is not a pinned pipeline tool")
    pinned = PINNED[name]
    binary = shutil.which(name)
    if binary is None:
        raise ToolVersionError(f"{name} is not installed (pinned {pinned.version})")
    entries = load_manifest() if manifest is None else manifest
    entry = entries.get(name)
    if entry:
        if entry.get("version") != pinned.version:
            raise ToolVersionError(
                f"{name}: manifest records {entry.get('version')}, code pins {pinned.version}"
            )
        actual = _sha256(Path(binary))
        if actual != entry.get("sha256"):
            raise ToolVersionError(f"{name}: binary hash does not match the build manifest")
        return binary, pinned.version
    reported = observed_version(name, binary)
    if reported == pinned.version:
        return binary, pinned.version
    if allow_unpinned():
        return binary, f"unpinned:{reported or 'unknown'}"
    raise ToolVersionError(
        f"{name}: expected pinned {pinned.version}, found {reported or 'an unidentifiable build'} "
        "and no build manifest (set BUGGY_PIPELINE_ALLOW_UNPINNED=1 to run anyway)"
    )


def write_manifest(path: str) -> dict[str, dict[str, str]]:
    """Record the hash of every pinned binary on PATH; fail if one is missing or wrong."""
    manifest: dict[str, dict[str, str]] = {}
    for name, pinned in PINNED.items():
        binary = shutil.which(name)
        if binary is None:
            raise ToolVersionError(f"{name} is not installed")
        reported = observed_version(name, binary)
        if pinned.version_args and reported != pinned.version:
            raise ToolVersionError(f"{name}: installed {reported!r}, pinned {pinned.version}")
        manifest[name] = {
            "version": pinned.version,
            "sha256": _sha256(Path(binary)),
            "path": binary,
        }
    Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def install_plan() -> list[str]:
    return [f"{tool.module}@v{tool.version}" for tool in PINNED.values()]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["--install-plan"]:
        print("\n".join(install_plan()))
        return 0
    if args[:1] == ["--write-manifest"]:
        target = args[1] if len(args) > 1 else DEFAULT_MANIFEST
        manifest = write_manifest(target)
        print(f"wrote {target}: {', '.join(sorted(manifest))}")
        return 0
    if args[:1] == ["--nuclei-templates"]:
        print(f"{NUCLEI_TEMPLATES_REPO} {NUCLEI_TEMPLATES_VERSION} {NUCLEI_TEMPLATES_DIR}")
        return 0
    print("usage: python -m buggy.pipeline.versions --install-plan | --write-manifest [path]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
