"""Coverage audit: one verdict per known bug, buckets that add up, and no overstatement."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

from benchmark.lab import __main__ as cli
from benchmark.lab import coverage, lab, scorer
from benchmark.lab.taxonomy import CLASSES

ALL_APPS = scorer.available_apps()
RUN_APPS = ["juice-shop", "dvga"]
README = Path(lab.__file__).parent / "results" / "README.md"


def _copy_ground_truth(tmp_path: Path) -> Path:
    target = tmp_path / "ground_truth"
    shutil.copytree(scorer.GROUND_TRUTH_DIR, target)
    return target


def _edit(gt_dir: Path, app: str, entry_id: str, **changes: Any) -> None:
    path = gt_dir / f"{app}.json"
    doc = json.loads(path.read_text())
    (entry,) = [e for e in doc["entries"] if e["id"] == entry_id]
    entry.update(changes)
    path.write_text(json.dumps(doc, indent=2))


def _verdicts(result: dict[str, Any]) -> dict[str, str]:
    return {e["id"]: e["verdict"] for e in result["entries"]}


# ── the buckets add up ───────────────────────────────────────────────


@pytest.mark.parametrize("apps", [ALL_APPS, RUN_APPS], ids=["all-apps", "juice-shop+dvga"])
def test_buckets_sum_to_totals_per_class_and_overall(apps: list[str]) -> None:
    result = coverage.audit(apps)
    known = [e for app in apps for e in scorer.load_ground_truth(app)]
    assert len(result["entries"]) == len(known)
    assert sorted(e["id"] for e in result["entries"]) == sorted(e.id for e in known)
    assert list(result["classes"]) == list(CLASSES)
    for cls, counts in result["classes"].items():
        assert counts["entries"] == sum(1 for e in known if e.cls == cls), cls
        assert sum(counts[v] for v in coverage.VERDICTS) == counts["entries"], cls
        for verdict in coverage.VERDICTS:
            listed = [e for e in result["entries"] if e["class"] == cls and e["verdict"] == verdict]
            assert len(listed) == counts[verdict], (cls, verdict)
    totals = result["totals"]
    assert totals["entries"] == len(known)
    assert sum(totals[v] for v in coverage.VERDICTS) == len(known)
    assert all(e["verdict"] in coverage.VERDICTS for e in result["entries"])


def test_sum_check_rejects_buckets_that_do_not_add_up() -> None:
    result = coverage.audit(RUN_APPS)
    classes, totals = result["classes"], result["totals"]
    coverage.check_sums(classes, totals, len(result["entries"]))  # the real audit passes
    broken = {cls: dict(c) for cls, c in classes.items()}
    broken["injection"]["backlog"] += 1
    with pytest.raises(coverage.AuditError, match="injection"):
        coverage.check_sums(broken, totals, len(result["entries"]))
    with pytest.raises(coverage.AuditError, match="entries"):
        coverage.check_sums(classes, totals, len(result["entries"]) + 1)
    with pytest.raises(coverage.AuditError, match="total proven"):
        coverage.check_sums(classes, {**totals, "proven": totals["proven"] + 1}, totals["entries"])


def test_verdicts_follow_the_ground_truth_fields() -> None:
    result = coverage.audit(ALL_APPS)
    verdicts = _verdicts(result)
    for app in ALL_APPS:
        for entry in scorer.load_ground_truth(app):
            if entry.prohibited:
                expected = "excluded"
            elif entry.verified_by:
                expected = "proven"
            elif entry.pipeline_signals:
                expected = "pipeline"
            else:
                expected = "backlog"
            assert verdicts[entry.id] == expected, entry.id
    proven = {e["id"]: e["test"] for e in result["entries"] if e["verdict"] == "proven"}
    assert proven["js-sqli-search"].endswith("::test_sqli_probe_finds_product_search_injection")
    # Pipeline signals never upgrade an entry to proven, and proven wins over pipeline.
    assert verdicts["js-cors-wildcard"] == "pipeline"
    assert verdicts["dvga-introspection"] == "proven"


def test_no_entry_cites_a_negative_control() -> None:
    # A test named for a negative (does not flag, finds no ..., cannot tell) proves nothing.
    negative = re.compile(r"does_not|_not_|_no_|cannot|not_exploitable|is_listed|refuses")
    for entry in coverage.audit(ALL_APPS)["entries"]:
        if entry["verdict"] == "proven":
            function = entry["test"].rsplit("::", 1)[-1]
            assert not negative.search(function), (entry["id"], function)
            assert entry["test"].startswith("packages/buggy/tests/lab/")


# ── verified_by must name a real lab test ────────────────────────────


@pytest.mark.parametrize(
    ("verified_by", "message"),
    [
        (
            "packages/buggy/tests/lab/test_probes_find_known_bugs.py::test_no_such_test",
            "names a test that does not exist",
        ),
        (
            "packages/buggy/tests/lab/test_no_such_file.py::test_idor_probe_finds_basket_idor",
            "names a file that does not exist",
        ),
        (
            "packages/buggy/tests/unit/benchmark/test_lab.py::TestGroundTruth::"
            "test_every_file_loads_and_uses_known_classes",
            "is not a test under packages/buggy/tests/lab/",
        ),
        (
            "packages/buggy/tests/lab/test_probes_find_known_bugs.py::NoClass::test_x",
            "names a class that does not exist",
        ),
        ("packages/buggy/tests/lab/test_probes_find_known_bugs.py", "is not a pytest node id"),
    ],
)
def test_a_missing_test_fails_the_audit(tmp_path: Path, verified_by: str, message: str) -> None:
    gt_dir = _copy_ground_truth(tmp_path)
    # The untouched copy audits exactly like the real ground truth.
    assert coverage.audit(ALL_APPS, ground_truth_dir=gt_dir) == coverage.audit(ALL_APPS)
    _edit(gt_dir, "juice-shop", "js-idor-basket", verified_by=verified_by)
    with pytest.raises(coverage.AuditError) as failed:
        coverage.audit(ALL_APPS, ground_truth_dir=gt_dir)
    assert "juice-shop:js-idor-basket" in str(failed.value)
    assert message in str(failed.value)


def test_class_qualified_and_parametrized_node_ids_resolve(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    tests = root / "packages/buggy/tests/lab"
    tests.mkdir(parents=True)
    (tests / "test_fake.py").write_text(
        "class TestShop:\n    def test_finds_it(self):\n        pass\n\n"
        "def test_top_level():\n    pass\n"
    )
    gt_dir = _copy_ground_truth(tmp_path)
    base = "packages/buggy/tests/lab/test_fake.py::"
    _edit(gt_dir, "dvwa", "dvwa-sqli", verified_by=base + "TestShop::test_finds_it")
    _edit(gt_dir, "dvwa", "dvwa-csrf", verified_by=base + "test_top_level[case-a]")
    for app in ("juice-shop", "dvga"):  # their real citations do not exist under this root
        doc = json.loads((gt_dir / f"{app}.json").read_text())
        for entry in doc["entries"]:
            entry["verified_by"] = None
        (gt_dir / f"{app}.json").write_text(json.dumps(doc))
    result = coverage.audit(ALL_APPS, ground_truth_dir=gt_dir, repo_root=root)
    verdicts = _verdicts(result)
    assert verdicts["dvwa-sqli"] == verdicts["dvwa-csrf"] == "proven"
    assert result["totals"]["proven"] == 2
    # A method of the class, cited without the class, is not a top-level test.
    _edit(gt_dir, "dvwa", "dvwa-sqli", verified_by=base + "test_finds_it")
    with pytest.raises(coverage.AuditError, match="does not exist"):
        coverage.audit(ALL_APPS, ground_truth_dir=gt_dir, repo_root=root)


# ── prohibited entries are excluded, never backlog ───────────────────


def test_prohibited_entries_are_excluded_with_a_reason() -> None:
    result = coverage.audit(ALL_APPS)
    prohibited = {e.id for app in ALL_APPS for e in scorer.load_ground_truth(app) if e.prohibited}
    assert prohibited == {
        "dvga-batch-dos",
        "dvga-deep-recursion-dos",
        "crapi-rate-limit-contact-mechanic",
    }
    for entry in result["entries"]:
        if entry["id"] in prohibited:
            assert entry["verdict"] == "excluded"
            assert "denial of service" in entry["reason"]
        else:
            assert entry["verdict"] != "excluded", entry["id"]
    assert result["totals"]["excluded"] == len(prohibited)


def test_marking_an_entry_prohibited_moves_it_out_of_backlog(tmp_path: Path) -> None:
    gt_dir = _copy_ground_truth(tmp_path)
    before = coverage.audit(ALL_APPS, ground_truth_dir=gt_dir)
    assert _verdicts(before)["js-csrf-profile"] == "backlog"
    _edit(gt_dir, "juice-shop", "js-csrf-profile", prohibited=True, prohibited_reason="test only")
    after = coverage.audit(ALL_APPS, ground_truth_dir=gt_dir)
    assert _verdicts(after)["js-csrf-profile"] == "excluded"
    assert after["classes"]["csrf"]["backlog"] == before["classes"]["csrf"]["backlog"] - 1
    assert after["classes"]["csrf"]["excluded"] == before["classes"]["csrf"]["excluded"] + 1
    assert after["totals"]["entries"] == before["totals"]["entries"]
    # Signals do not pull a prohibited entry back into the pipeline bucket either.
    _edit(gt_dir, "juice-shop", "js-cors-wildcard", prohibited=True, prohibited_reason="x")
    assert _verdicts(coverage.audit(ALL_APPS, ground_truth_dir=gt_dir))["js-cors-wildcard"] == (
        "excluded"
    )


def test_a_prohibited_entry_needs_a_reason_and_no_test(tmp_path: Path) -> None:
    gt_dir = _copy_ground_truth(tmp_path)
    _edit(gt_dir, "dvga", "dvga-batch-dos", prohibited_reason="")
    with pytest.raises(coverage.AuditError, match="dvga-batch-dos is prohibited without"):
        coverage.audit(["dvga"], ground_truth_dir=gt_dir)
    gt_dir = _copy_ground_truth(tmp_path / "second")
    cited = (
        "packages/buggy/tests/lab/test_probes_find_known_bugs.py::test_idor_probe_finds_basket_idor"
    )
    _edit(gt_dir, "dvga", "dvga-batch-dos", verified_by=cited)
    with pytest.raises(coverage.AuditError, match="prohibited but cites a test"):
        coverage.audit(["dvga"], ground_truth_dir=gt_dir)


# ── the committed report and the results README ──────────────────────


def _header(text: str, prefix: str) -> str:
    (line,) = [line for line in text.splitlines() if line.startswith(prefix)]
    return line[len(prefix) :]


def test_committed_coverage_md_equals_a_fresh_render() -> None:
    committed = coverage.COVERAGE_MD.read_text(encoding="utf-8")
    revision = _header(committed, coverage.REVISION_PREFIX)
    apps = _header(committed, "- apps: ").split(", ")
    assert apps == ALL_APPS and revision and revision != "unknown"
    fresh = coverage.render(coverage.audit(apps), date="1970-01-01", revision=revision)

    def without_date(text: str) -> list[str]:
        return [line for line in text.splitlines() if not line.startswith(coverage.DATE_PREFIX)]

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", _header(committed, coverage.DATE_PREFIX))
    assert without_date(committed) == without_date(fresh)
    assert committed != fresh  # only the date line differs, and it is really compared out


def test_results_readme_matches_the_audit() -> None:
    text = README.read_text(encoding="utf-8")
    assert "agent arms** — not run" in text
    result = coverage.audit(RUN_APPS)
    for cls in CLASSES:
        counts = result["classes"][cls]
        known = counts["entries"] - counts["excluded"]
        if not known:
            continue
        row = next(line for line in text.splitlines() if line.startswith(f"| {cls} |"))
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert cells[1] == str(known), cls
        assert cells[3] == f"{counts['proven']}/{known}", cls  # the probes column
    for label, apps in (("juice-shop, dvga", RUN_APPS), ("all four ground-truth files", ALL_APPS)):
        t = coverage.audit(apps)["totals"]
        expected = f"| {label} | {t['entries']} | " + " | ".join(
            str(t[v]) for v in coverage.VERDICTS
        )
        assert expected + " |" in text, label


# ── command line ─────────────────────────────────────────────────────


def test_cli_prints_the_table_and_writes_only_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "coverage.md"
    monkeypatch.setattr(coverage, "COVERAGE_MD", target)
    assert cli.main(["coverage", "--apps", "juice-shop,dvga"]) == 0
    out = capsys.readouterr().out
    assert "- apps: juice-shop, dvga\n" in out
    totals = coverage.audit(RUN_APPS)["totals"]
    assert f"| **total** | {totals['entries']} | {totals['proven']} |" in out
    assert "## Backlog" in out and "js-csrf-profile" in out and not target.exists()
    assert cli.main(["coverage", "--write"]) == 0
    assert "- apps: " + ", ".join(ALL_APPS) in target.read_text()
    with pytest.raises(SystemExit):
        cli.main(["coverage", "--apps", "no-such-app"])


def test_cli_reports_an_audit_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    gt_dir = _copy_ground_truth(tmp_path)
    _edit(gt_dir, "dvga", "dvga-introspection", verified_by="packages/buggy/tests/lab/x.py::test_y")
    monkeypatch.setattr(coverage, "GROUND_TRUTH_DIR", gt_dir)
    monkeypatch.setattr(cli.scorer, "available_apps", lambda: ALL_APPS)
    assert cli.main(["coverage"]) == 2
    assert "dvga:dvga-introspection" in capsys.readouterr().err
