"""Every bug class gets a row: tested or not, how much, and why not."""

from __future__ import annotations

import json

from buggy.capture.probes import REGISTRY
from buggy.cli import hunt
from buggy.findings.model import CLASSES
from buggy.pipeline import sweep


def counts(**classes) -> dict:
    out = hunt._empty_counts()  # noqa: SLF001
    for cls, (checks, held, positive, proven) in classes.items():
        out["by_class"][cls] = {
            "checks": checks,
            "held": held,
            "positive": positive,
            "proven": proven,
        }
    return out


def row(rows: list[dict], cls: str) -> dict:
    (found,) = [r for r in rows if r["class"] == cls]
    return found


def test_every_class_of_the_findings_model_has_a_row_in_testing_order() -> None:
    rows = hunt.class_coverage({"probes": counts()}, "acme")
    assert [r["class"] for r in rows] == list(sweep.CLASS_ORDER)
    assert set(sweep.CLASS_ORDER) == set(CLASSES)


def test_the_probe_classes_are_the_registrys() -> None:
    assert {name: spec.vuln_class for name, spec in REGISTRY.items()} == sweep.PROBE_CLASS


def test_checks_run_in_the_probe_order(monkeypatch) -> None:
    seen: list[str] = []

    def capture(tool: str, _engagement: str, **arguments) -> dict:
        if tool == "probe_run":
            seen.append(arguments["probe"])
        return {"status": "completed", "vulnerable": False}

    monkeypatch.setattr(hunt, "_capture", capture)
    steps = [
        {"probe": name, "params": {"url": "https://app.test/x"}}
        for name in ("cors", "xss_reflected", "sqli", "open_redirect", "ssti", "path_traversal")
    ]
    out = hunt._run_steps("acme", {"steps": steps, "left_out": 0}, "[]")  # noqa: SLF001
    assert seen == ["sqli", "xss_reflected", "ssti", "path_traversal", "open_redirect", "cors"]
    assert seen == sorted(seen, key=sweep.PROBE_ORDER.index)
    assert out["by_class"]["injection"] == {"checks": 2, "held": 0, "positive": 0, "proven": 0}


def test_counts_are_added_over_every_stage() -> None:
    outcome = {
        "probes": counts(injection=(3, 0, 1, 1), xss=(2, 0, 0, 0)),
        "state": counts(business_logic=(2, 2, 0, 0)),
        "signed_in": {
            "ran": True,
            "probes": counts(injection=(10, 0, 3, 3)),
            "state": counts(injection=(4, 1, 1, 1), api=(1, 1, 0, 0)),
            "inferred": {"objects": 4, "broken_access": 1, "verified": 1},
        },
        "access": {"ran": True, "objects": 2, "broken_access": 1, "verified": 1},
    }
    rows = hunt.class_coverage(outcome, "acme")
    injection = row(rows, "injection")
    assert (injection["tested"], injection["checks"], injection["findings"]) == (True, 16, 5)
    assert injection["waiting_for_approval"] == 1 and injection["reason"] == ""
    access = row(rows, "access_control")
    assert (access["tested"], access["checks"], access["findings"]) == (True, 6, 2)
    assert row(rows, "xss")["findings"] == 0 and row(rows, "xss")["tested"] is True


def test_an_untested_class_says_why() -> None:
    outcome = {
        "probes": counts(),
        "state": counts(business_logic=(2, 2, 0, 0)),
        "signed_in": {"ran": False, "reason": "no test accounts are declared"},
        "access": {"ran": False, "reason": "no test accounts are declared"},
    }
    rows = hunt.class_coverage(outcome, "acme")
    held = row(rows, "business_logic")
    assert held["tested"] is False and held["waiting_for_approval"] == 2
    assert "2 checks wait for your approval (buggy-cli approvals list acme)" == held["reason"]
    assert row(rows, "access_control")["reason"] == "no test accounts are declared"
    assert "nothing behind the login was reached" in row(rows, "injection")["reason"]
    assert row(rows, "ssrf")["reason"] == sweep.NO_AUTOMATIC_CHECK["ssrf"]
    assert all(r["reason"] for r in rows if not r["tested"])


def test_a_run_without_probe_stages_says_so() -> None:
    rows = hunt.class_coverage({"probes": None}, "acme")
    assert row(rows, "xss")["reason"] == "the probe stages did not run"


def test_the_table_is_printed_and_is_in_the_result_file(capsys) -> None:
    outcome = {
        "recon": hunt.recon_outcome("completed", None),
        "issues": dict.fromkeys(hunt.SEVERITIES, 0),
        "agent": {"ran": False, "error": None},
        "probes": counts(injection=(3, 0, 1, 1)),
    }
    outcome["coverage"] = hunt.class_coverage(outcome, "acme")
    hunt.print_coverage(outcome["coverage"])
    err = capsys.readouterr().err
    assert "bug classes, in the order they were tested" in err
    assert "injection        3 checks, 1 proven" in err and "ssrf             not tested: " in err
    result = hunt.build_result("acme", outcome, {}, now=1.0)
    assert json.loads(json.dumps(result))["coverage"][0]["class"] == "access_control"
