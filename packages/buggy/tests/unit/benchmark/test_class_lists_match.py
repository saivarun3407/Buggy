"""The findings package keeps its own copy of the lab's class list; the two must stay equal.

Product code may not import ``benchmark``, so ``buggy/findings/model.py`` copies
the 14 class names. This test is what makes the copy safe: add, remove, rename
or reorder a class on one side only and it fails.
"""

from __future__ import annotations

import ast
from pathlib import Path

import buggy.findings
from benchmark.lab.taxonomy import CLASSES as LAB_CLASSES
from buggy.findings.model import CLASSES, VulnClass, validate


def test_the_two_class_lists_are_equal() -> None:
    assert len(LAB_CLASSES) == 14
    assert tuple(CLASSES) == tuple(LAB_CLASSES)  # same names, same (report) order
    assert tuple(member.value for member in VulnClass) == tuple(LAB_CLASSES)


def test_every_lab_class_is_accepted_and_nothing_else() -> None:
    claim = {
        "engagement": "acme",
        "title": "t",
        "severity": "low",
        "endpoint": "https://app.acme.test/",
        "source": "agent:x",
    }
    for name in LAB_CLASSES:
        assert validate({**claim, "class": name}).vuln_class == name
    try:
        validate({**claim, "class": "unclassified"})
    except ValueError as exc:
        assert "class" in str(exc)
    else:
        raise AssertionError("a class outside the lab list was accepted")


def test_the_findings_package_does_not_import_benchmark() -> None:
    for source in Path(buggy.findings.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert not [n for n in names if n.split(".")[0] == "benchmark"], source.name
