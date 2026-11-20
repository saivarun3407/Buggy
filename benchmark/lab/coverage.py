"""Coverage audit: exactly one verdict per ground-truth entry, and per class.

A checkable statement of what Buggy finds deterministically in the lab, so that
nobody overstates it. Each entry gets one verdict:

``proven``    its ``verified_by`` names a lab test (under ``packages/buggy/tests/lab``)
              that exists on disk; that test runs a probe against the real app and
              asserts the bug is reported.
``pipeline``  no lab test, but the entry has ``pipeline_signals``: the deterministic
              pipeline is scored as finding it when a recon record matches one.
``backlog``   no deterministic coverage at all.
``excluded``  ``prohibited`` (denial of service): never tested, with the reason.

The four buckets must add up to the number of entries, per class and overall;
:func:`audit` raises :class:`AuditError` if they do not, and also when an entry
cites a test that does not exist.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from benchmark.lab.scorer import GROUND_TRUTH_DIR
from benchmark.lab.taxonomy import CLASSES

REPO_ROOT = Path(__file__).resolve().parents[2]
COVERAGE_MD = Path(__file__).parent / "results" / "coverage.md"
LAB_TESTS = "packages/buggy/tests/lab/"
VERDICTS = ("proven", "pipeline", "backlog", "excluded")
DATE_PREFIX = "- date: "
REVISION_PREFIX = "- revision: "


class AuditError(ValueError):
    """The ground truth cannot be audited as it stands."""


def _test_exists(node_id: str, repo_root: Path) -> str | None:
    """``None`` when ``node_id`` names an existing lab test, else why it does not."""
    path, sep, rest = node_id.partition("::")
    if not sep or not rest:
        return "is not a pytest node id (expected path::function or path::Class::function)"
    if not path.startswith(LAB_TESTS) or not path.endswith(".py"):
        return f"is not a test under {LAB_TESTS}"
    source = repo_root / path
    if not source.is_file():
        return f"names a file that does not exist: {path}"
    parts = re.sub(r"\[[^\]]*\]$", "", rest).split("::")
    if len(parts) > 2 or not parts[-1].startswith("test_"):
        return f"does not name a test function: {rest}"
    scope: list[ast.stmt] = ast.parse(source.read_text(encoding="utf-8")).body
    if len(parts) == 2:
        classes = [n for n in scope if isinstance(n, ast.ClassDef) and n.name == parts[0]]
        if not classes:
            return f"names a class that does not exist in {path}: {parts[0]}"
        scope = classes[0].body
    functions = (ast.FunctionDef, ast.AsyncFunctionDef)
    if not any(isinstance(n, functions) and n.name == parts[-1] for n in scope):
        return f"names a test that does not exist in {path}: {rest}"
    return None


def _load(app: str, ground_truth_dir: Path) -> list[dict[str, Any]]:
    path = ground_truth_dir / f"{app}.json"
    if not path.is_file():
        raise AuditError(f"no ground truth for app {app!r} in {ground_truth_dir}")
    entries = json.loads(path.read_text(encoding="utf-8"))["entries"]
    for raw in entries:
        if raw["class"] not in CLASSES:
            raise AuditError(f"{app}:{raw['id']} has unknown class {raw['class']!r}")
    return entries


def _verdict(app: str, raw: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    entry = {"app": app, "id": raw["id"], "class": raw["class"], "title": raw["title"]}
    verified_by = raw.get("verified_by")
    if verified_by:
        problem = _test_exists(verified_by, repo_root)
        if problem:
            raise AuditError(f"{app}:{raw['id']} verified_by {verified_by!r} {problem}")
    if raw.get("prohibited"):
        if verified_by:
            raise AuditError(f"{app}:{raw['id']} is prohibited but cites a test: {verified_by}")
        reason = str(raw.get("prohibited_reason") or "").strip()
        if not reason:
            raise AuditError(f"{app}:{raw['id']} is prohibited without a prohibited_reason")
        return {**entry, "verdict": "excluded", "reason": reason}
    if verified_by:
        return {**entry, "verdict": "proven", "test": verified_by}
    if raw.get("pipeline_signals"):
        return {**entry, "verdict": "pipeline", "signals": len(raw["pipeline_signals"])}
    return {**entry, "verdict": "backlog"}


def audit(
    apps: list[str],
    *,
    ground_truth_dir: Path | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """One verdict per entry of ``apps``' ground truth, and verdict counts per class."""
    gt_dir = Path(ground_truth_dir or GROUND_TRUTH_DIR)
    root = Path(repo_root or REPO_ROOT)
    entries: list[dict[str, Any]] = []
    for app in apps:
        entries.extend(_verdict(app, raw, root) for raw in _load(app, gt_dir))

    classes = {cls: dict.fromkeys(("entries", *VERDICTS), 0) for cls in CLASSES}
    for entry in entries:
        counts = classes[entry["class"]]
        counts["entries"] += 1
        counts[entry["verdict"]] += 1
    totals = {key: sum(c[key] for c in classes.values()) for key in ("entries", *VERDICTS)}
    check_sums(classes, totals, len(entries))
    return {"apps": list(apps), "classes": classes, "totals": totals, "entries": entries}


def check_sums(
    classes: dict[str, dict[str, int]], totals: dict[str, int], entry_count: int
) -> None:
    """Raise unless the four buckets add up, per class and overall, to the entry count."""
    for cls, counts in classes.items():
        if sum(counts[v] for v in VERDICTS) != counts["entries"]:
            raise AuditError(f"verdicts for {cls} do not add up: {counts}")
    if sum(c["entries"] for c in classes.values()) != entry_count:
        raise AuditError(f"classes hold {totals['entries']} of {entry_count} entries")
    for key in ("entries", *VERDICTS):
        if sum(c[key] for c in classes.values()) != totals[key]:
            raise AuditError(f"total {key} {totals[key]} is not the sum over classes")
    if sum(totals[v] for v in VERDICTS) != entry_count:
        raise AuditError(f"verdicts do not add up overall: {totals}, {entry_count} entries")


def git_revision(repo_root: Path | None = None) -> str:
    """Short HEAD, marked when the audited files differ from it."""
    root = Path(repo_root or REPO_ROOT)

    def git(*args: str) -> str:
        done = subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()

    try:
        head = git("rev-parse", "--short", "HEAD")
        dirty = git("status", "--porcelain", "--", "benchmark/lab/ground_truth", LAB_TESTS)
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return f"{head} (with uncommitted changes)" if dirty else head


def _row(label: str, counts: dict[str, int]) -> str:
    return (
        f"| {label} | {counts['entries']} | " + " | ".join(str(counts[v]) for v in VERDICTS) + " |"
    )


def render(result: dict[str, Any], *, date: str, revision: str) -> str:
    """The audit as Markdown: class x verdict counts, then every entry by verdict."""
    lines = [
        "# Lab coverage audit",
        "",
        "Generated by `uv run python -m benchmark.lab coverage --write`; do not edit by hand.",
        "",
        f"{DATE_PREFIX}{date}",
        f"{REVISION_PREFIX}{revision}",
        f"- apps: {', '.join(result['apps'])}",
        "",
        "One verdict per ground-truth entry. `proven`: a lab test runs a deterministic "
        "probe against the real app and asserts this bug is reported. `pipeline`: no lab "
        "test; the entry has `pipeline_signals`, so the pipeline is credited when a recon "
        "record matches one. `backlog`: no deterministic coverage. `excluded`: prohibited "
        "(denial of service), never tested. The four buckets add up to the entries.",
        "",
        "| Class | Entries | " + " | ".join(VERDICTS) + " |",
        "|---|---:|" + "---:|" * len(VERDICTS),
    ]
    for cls in CLASSES:
        lines.append(_row(cls, result["classes"][cls]))
    lines.append(_row("**total**", result["totals"]))
    by_verdict = {v: [e for e in result["entries"] if e["verdict"] == v] for v in VERDICTS}
    sections = (
        ("backlog", "Backlog", ("id", "app", "class", "title"), None),
        ("proven", "Proven", ("id", "app", "class", "test"), "test"),
        ("pipeline", "Pipeline only", ("id", "app", "class", "title"), None),
        ("excluded", "Excluded", ("id", "app", "class", "reason"), "reason"),
    )
    for verdict, heading, columns, last in sections:
        rows = sorted(by_verdict[verdict], key=lambda e: e["id"])
        lines += ["", f"## {heading} ({len(rows)})", ""]
        if not rows:
            lines.append("None.")
            continue
        lines.append("| " + " | ".join(columns) + " |")
        lines.append("|" + "---|" * len(columns))
        for e in rows:
            tail = f"`{e[last]}`" if last == "test" else e[last or "title"].replace("|", "\\|")
            lines.append(f"| {e['id']} | {e['app']} | {e['class']} | {tail} |")
    return "\n".join(lines) + "\n"


__all__ = [
    "COVERAGE_MD",
    "VERDICTS",
    "AuditError",
    "audit",
    "check_sums",
    "git_revision",
    "render",
]
