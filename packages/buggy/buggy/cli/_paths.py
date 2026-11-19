"""Host-side locations of the three engagement trees (see middleware/_control.py).

The operator CLI runs either on the host or in the ``operator`` compose
service, where the trees are bind-mounted at ``/workspace``, ``/control`` and
``/audit``. Explicit flags win, then the environment, then ``$BUGGY_HOME``.
"""

from __future__ import annotations

import os
from pathlib import Path


def buggy_home() -> Path:
    raw = os.environ.get("BUGGY_HOME")
    return Path(raw).expanduser() if raw and raw.strip() else Path.home() / ".buggy"


def _root(explicit: Path | None, env_names: tuple[str, ...], default_name: str) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    for name in env_names:
        raw = os.environ.get(name)
        if raw and raw.strip():
            return Path(raw.strip()).expanduser()
    return buggy_home() / default_name


def workspace_root(explicit: Path | None = None) -> Path:
    return _root(explicit, ("BUGGY_ENGAGEMENT_WORKSPACE", "BUGGY_WORKSPACE_ROOT"), "workspace")


def control_root(explicit: Path | None = None) -> Path:
    return _root(explicit, ("BUGGY_ENGAGEMENT_CONTROL", "BUGGY_CONTROL_ROOT"), "control")


def audit_root(explicit: Path | None = None) -> Path:
    return _root(explicit, ("BUGGY_ENGAGEMENT_AUDIT", "BUGGY_AUDIT_ROOT"), "audit")


def write_control_roe(control: Path, slug: str, document: dict) -> Path:
    """Write the enforced ``roe.json`` for ``slug`` atomically; return its path."""
    import json
    import tempfile

    directory = control / slug
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "roe.json"
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".roe-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(document, indent=2) + "\n")
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return target
