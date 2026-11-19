"""Control-plane paths — where scope, approvals and audit records live.

The engagement *workspace* (``/workspace``) is the agent's scratch tree: the
sandbox mounts it read-write and every agent tool can change it. Anything
that decides what the agent is allowed to do must therefore live somewhere
else. Three roots, three trust levels:

``/workspace``  (``BUGGY_WORKSPACE_ROOT``)
    Agent-writable. Mounted read-only into the langgraph container so
    middleware can read operator markers and planning documents, but nothing
    here is trusted as policy.

``/control``    (``BUGGY_CONTROL_ROOT``)
    Operator-written, read-only to both the langgraph and sandbox
    containers. Holds ``roe.json`` (the enforced scope) and
    ``approvals/decisions.jsonl`` (human approvals).

``/audit``      (``BUGGY_AUDIT_ROOT``)
    Written by the langgraph process and the egress guard, never mounted
    into the sandbox. Holds the RoE decision ledger, approval requests and
    the egress drop log.

Each engagement's files sit at the same relative path under every root: a
workspace of ``/workspace/acme`` maps to ``/control/acme`` and
``/audit/acme``. When the launcher binds a single engagement directly at
``/workspace`` the relative path is empty and the roots themselves are used.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

DEFAULT_WORKSPACE_ROOT = "/workspace"
DEFAULT_CONTROL_ROOT = "/control"
DEFAULT_AUDIT_ROOT = "/audit"

_SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def workspace_root() -> str:
    return os.environ.get("BUGGY_WORKSPACE_ROOT") or DEFAULT_WORKSPACE_ROOT


def control_root() -> str:
    return os.environ.get("BUGGY_CONTROL_ROOT") or DEFAULT_CONTROL_ROOT


def audit_root() -> str:
    return os.environ.get("BUGGY_AUDIT_ROOT") or DEFAULT_AUDIT_ROOT


def _relative_engagement_path(workspace_path: str | None) -> PurePosixPath | None:
    """Path of ``workspace_path`` below the workspace root.

    Returns ``None`` when the workspace is not under the root or the relative
    part would escape it. ``PurePosixPath('.')`` means "the root itself".
    """
    if not workspace_path:
        return None
    root = PurePosixPath(workspace_root())
    candidate = PurePosixPath(workspace_path)
    try:
        rel = candidate.relative_to(root)
    except ValueError:
        return None
    if any(part in ("..", "") for part in rel.parts):
        return None
    return rel


def _engagement_dirs(
    root: str, workspace_path: str | None, engagement_name: str | None
) -> list[Path]:
    """Candidate per-engagement directories under ``root``, most specific first."""
    candidates: list[Path] = []
    rel = _relative_engagement_path(workspace_path)
    if rel is not None:
        candidates.append(Path(root, *rel.parts))
    if engagement_name and _SLUG_RE.fullmatch(engagement_name):
        by_slug = Path(root) / engagement_name
        if by_slug not in candidates:
            candidates.append(by_slug)
    return candidates


def control_dir(workspace_path: str | None, engagement_name: str | None = None) -> Path | None:
    """The engagement's control directory, or ``None`` when it cannot be resolved.

    The first candidate holding a ``roe.json`` wins; otherwise the most
    specific candidate is returned so callers can name the path they expected.
    """
    candidates = _engagement_dirs(control_root(), workspace_path, engagement_name)
    for candidate in candidates:
        if (candidate / "roe.json").is_file():
            return candidate
    return candidates[0] if candidates else None


def audit_dir(workspace_path: str | None, engagement_name: str | None = None) -> Path | None:
    """The engagement's audit directory (langgraph-writable, not in the sandbox)."""
    candidates = _engagement_dirs(audit_root(), workspace_path, engagement_name)
    return candidates[0] if candidates else None


def control_roe_path(workspace_path: str | None, engagement_name: str | None = None) -> Path | None:
    directory = control_dir(workspace_path, engagement_name)
    return directory / "roe.json" if directory is not None else None


def workspace_roe_path(workspace_path: str | None) -> Path | None:
    """The agent-writable draft location. Never trusted when RoE is required."""
    if not workspace_path:
        return None
    return Path(workspace_path) / "plan" / "roe.json"


def read_roe_document(
    workspace_path: str | None, engagement_name: str | None = None
) -> dict | None:
    """The engagement's RoE document for *informational* readers.

    Prefers the operator-controlled copy and falls back to the workspace
    draft. Enforcement code must not use this: it goes through
    ``buggy.middleware.roe``, which refuses the draft when RoE is required.
    """
    import json

    for path in (
        control_roe_path(workspace_path, engagement_name),
        workspace_roe_path(workspace_path),
    ):
        if path is None:
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(document, dict):
            return document
    return None


def control_plane_available() -> bool:
    """Whether a control root is mounted in this process."""
    return Path(control_root()).is_dir()


__all__ = [
    "DEFAULT_AUDIT_ROOT",
    "DEFAULT_CONTROL_ROOT",
    "DEFAULT_WORKSPACE_ROOT",
    "audit_dir",
    "audit_root",
    "control_dir",
    "control_plane_available",
    "control_roe_path",
    "control_root",
    "read_roe_document",
    "workspace_roe_path",
    "workspace_root",
]
