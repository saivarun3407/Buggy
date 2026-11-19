"""Lab baseline: ground truth integrity, scoring rules, scope generation."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from benchmark.lab import agent, lab, scorer
from benchmark.lab.scorer import Entry, Finding
from benchmark.lab.taxonomy import CLASSES, classify

PRIORITY = ("auth_session", "access_control", "ssrf", "business_logic", "api", "graphql")


class TestGroundTruth:
    def test_every_file_loads_and_uses_known_classes(self) -> None:
        apps = scorer.available_apps()
        assert set(apps) == {"juice-shop", "dvga", "dvwa", "crapi"}
        ids: set[str] = set()
        for app in apps:
            entries = scorer.load_ground_truth(app)
            assert entries
            for entry in entries:
                assert entry.cls in CLASSES
                assert entry.id not in ids, f"duplicate id {entry.id}"
                ids.add(entry.id)
                re.compile(entry.location)

    def test_priority_classes_are_all_covered(self) -> None:
        covered = {e.cls for app in scorer.available_apps() for e in scorer.load_ground_truth(app)}
        assert set(PRIORITY) <= covered

    def test_denial_of_service_entries_are_prohibited(self) -> None:
        for app in scorer.available_apps():
            for entry in scorer.load_ground_truth(app):
                if re.search(r"\bdos\b|denial|unbounded|without limit", entry.title.lower()):
                    assert entry.prohibited, entry.id

    def test_verified_by_names_a_real_test(self) -> None:
        root = Path(__file__).resolve().parents[5]
        for app in scorer.available_apps():
            for entry in scorer.load_ground_truth(app):
                if entry.verified_by:
                    path, _, test = entry.verified_by.partition("::")
                    source = (root / path).read_text()
                    assert f"def {test.split('::')[-1]}" in source, entry.id


class TestTaxonomy:
    @pytest.mark.parametrize(
        ("cwe", "title", "expected"),
        [
            ("CWE-639", "", "access_control"),
            ("CWE-918", "", "ssrf"),
            (89, "", "injection"),
            ("CWE-347", "", "auth_session"),
            ("CWE-915", "", "api"),
            (None, "IDOR on basket lets a user read another user's cart", "access_control"),
            (None, "GraphQL introspection enabled", "graphql"),
            (None, "Negative quantity credits the wallet", "business_logic"),
            (None, "JWT alg=none accepted", "auth_session"),
            (None, "Something odd", "unclassified"),
        ],
    )
    def test_classify(self, cwe, title, expected) -> None:
        assert classify(cwe=cwe, title=title) == expected

    def test_explicit_class_wins(self) -> None:
        assert classify(cwe="CWE-79", title="xss", explicit="graphql") == "graphql"
        assert classify(cwe="CWE-79", explicit="not-a-class") == "xss"


GT = [
    Entry(
        "idor-basket",
        "access_control",
        "Read another basket",
        "GET",
        r"^/rest/basket/\d+",
        ("basket",),
    ),
    Entry("users-list", "access_control", "List users", "GET", r"^/api/Users/?$", ("users",)),
    Entry("ssrf-image", "ssrf", "Profile image SSRF", "POST", r"^/profile/image/url", ("image",)),
    Entry(
        "dos", "graphql", "Unbounded batching", "POST", r"^/graphql", ("batch",), prohibited=True
    ),
]


class TestScoring:
    def test_found_missed_unmatched(self) -> None:
        findings = [
            Finding(
                "IDOR on basket",
                "access_control",
                "http://juice-shop.lab:3000/rest/basket/2",
                "GET",
            ),
            Finding("Reflected XSS in search", "xss", "/search?q=1", "GET"),
        ]
        scores = scorer.score(findings, GT)
        assert scores["access_control"].to_dict() | {} == {
            "known": 2, "found": 1, "missed": 1, "unmatched": 0, "duplicates": 0, "recall": 0.5,
            "found_ids": ["idor-basket"], "missed_ids": ["users-list"], "unmatched_titles": [],
        }  # fmt: skip
        assert scores["ssrf"].missed == 1 and scores["ssrf"].found == 0
        assert scores["xss"].unmatched == 1 and scores["xss"].known == 0
        assert scorer.totals(scores) == {
            "known": 3,
            "found": 1,
            "missed": 2,
            "unmatched": 1,
            "duplicates": 0,
        }

    def test_volume_does_not_inflate_the_score(self) -> None:
        same = Finding("IDOR basket", "access_control", "/rest/basket/1", "GET")
        scores = scorer.score([same] * 5, GT)
        assert scores["access_control"].found == 1 and scores["access_control"].duplicates == 4

    def test_class_and_method_must_match(self) -> None:
        wrong_class = Finding("XSS in basket", "xss", "/rest/basket/1", "GET")
        wrong_method = Finding("SSRF", "ssrf", "/profile/image/url", "GET")
        scores = scorer.score([wrong_class, wrong_method], GT)
        assert scores["access_control"].found == 0 and scores["ssrf"].found == 0
        assert scores["xss"].unmatched == 1 and scores["ssrf"].unmatched == 1

    def test_keyword_match_only_without_an_endpoint(self) -> None:
        no_endpoint = Finding("SSRF via profile image upload", "ssrf")
        elsewhere = Finding("SSRF via profile image upload", "ssrf", "/other/path", "POST")
        assert scorer.score([no_endpoint], GT)["ssrf"].found == 1
        assert scorer.score([elsewhere], GT)["ssrf"].found == 0

    def test_prohibited_entries_are_never_counted(self) -> None:
        scores = scorer.score([], GT)
        assert "graphql" not in scores
        attempt = Finding("Batching DoS", "graphql", "/graphql", "POST")
        assert scorer.score([attempt], GT)["graphql"].to_dict()["known"] == 0
        assert scorer.score([attempt], GT)["graphql"].unmatched == 1

    def test_structured_findings_adapter(self, tmp_path: Path) -> None:
        (tmp_path / "FIND-001.json").write_text(
            json.dumps(
                {
                    "title": "Basket IDOR",
                    "cwe": "CWE-639",
                    "endpoint": "http://juice-shop.lab:3000/rest/basket/3",
                    "method": "GET",
                }
            )
        )
        (tmp_path / "FIND-002.json").write_text("{not json")
        (tmp_path / "FIND-003.json").write_text(
            json.dumps(
                {"title": "GraphQL introspection", "endpoint": "http://dvga.lab:5013/graphql"}
            )
        )
        findings = scorer.findings_from_structured(tmp_path)
        assert [(f.cls, f.method) for f in findings] == [("access_control", "GET"), ("graphql", "")]


class TestPipelineBaseline:
    RECORDS = [
        {
            "asset": "juice-shop.lab",
            "type": "vulnerability",
            "value": "prometheus-metrics http://juice-shop.lab:3000/metrics",
            "attrs": {"name": "Prometheus Metrics - Detect", "cwe": ["cwe-200"]},
        },
        {
            "asset": "juice-shop.lab",
            "type": "header",
            "value": "http://juice-shop.lab:3000/ access-control-allow-origin",
            "attrs": {"value": "*"},
        },
        {
            "asset": "juice-shop.lab",
            "type": "header",
            "value": "http://juice-shop.lab:3000/ x-frame-options",
            "attrs": {"value": "SAMEORIGIN"},
        },
        {
            "asset": "juice-shop.lab",
            "type": "url",
            "value": "http://juice-shop.lab:3000/ftp/legal.md",
            "attrs": {},
        },
        {
            "asset": "juice-shop.lab",
            "type": "vulnerability",
            "value": "some-other-template http://juice-shop.lab:3000/x",
            "attrs": {"name": "Robots.txt exposure"},
        },
        {
            "asset": "dvga.lab",
            "type": "graphql",
            "value": "http://dvga.lab:5013/graphql",
            "attrs": {"introspection_enabled": True},
        },
        {
            "asset": "evil.example",
            "type": "vulnerability",
            "value": "prometheus-metrics http://evil.example/metrics",
            "attrs": {},
        },
    ]

    def test_scores_only_what_signals_identify(self) -> None:
        result = lab.score_pipeline_records(self.RECORDS, ["juice-shop", "dvga"])
        juice = result["apps"]["juice-shop"]
        assert juice["records"] == 5
        assert juice["classes"]["info_exposure"]["found_ids"] == [
            "js-metrics-exposed",
            "js-ftp-directory",
        ]
        assert juice["classes"]["misconfiguration"]["found_ids"] == ["js-cors-wildcard"]
        assert juice["classes"]["access_control"]["found"] == 0  # needs testing, not scanning
        assert juice["classes"]["info_exposure"]["unmatched"] == 1  # the robots.txt template
        assert result["apps"]["dvga"]["classes"]["graphql"]["found_ids"] == ["dvga-introspection"]
        assert result["llm_calls"] == 0 and result["tokens"] == 0

    def test_table_marks_unrun_baselines(self) -> None:
        result = lab.score_pipeline_records(self.RECORDS, ["juice-shop", "dvga"])
        table = lab.render_table(
            {"pipeline only": result, "agent + pipeline": None}, ["juice-shop", "dvga"]
        )
        row = next(line for line in table.splitlines() if line.startswith("| graphql "))
        assert row == "| graphql | 4 | 1/4 | not run |"
        assert "| access_control |" in table and "0/6" in table


class TestLabScope:
    def test_scope_is_exactly_the_lab_hosts_in_enforce_mode(self, tmp_path: Path) -> None:
        from buggy.pipeline.scope import ScopeFilter

        path = lab.write_scope(tmp_path, "lab", ["juice-shop", "dvga"])
        scope = ScopeFilter.from_file(path)
        assert scope.allows("juice-shop.lab") and scope.allows("http://dvga.lab:5013/graphql")
        assert not scope.allows("dvwa.lab")  # not selected
        assert not scope.allows("example.com") and not scope.allows("169.254.169.254")
        assert scope.limits.ports == "3000,5013"

    def test_every_lab_host_is_local_only(self) -> None:
        assert all(app.host.endswith(".lab") for app in lab.APPS.values())

    def test_arm_without_pipeline_disables_every_stage(self) -> None:
        from buggy.pipeline.pipeline import STAGES

        roe = agent.arm_roe("lab-b", ["juice-shop"], "without-pipeline")
        assert roe["pipeline"]["disabled_stages"] == list(STAGES)
        assert (
            "disabled_stages"
            not in agent.arm_roe("lab-a", ["juice-shop"], "with-pipeline")["pipeline"]
        )
        with pytest.raises(ValueError):
            agent.arm_roe("x", ["juice-shop"], "turbo")
        assert "recon_summary" in agent.kickoff_text("lab-a", ["juice-shop"], "with-pipeline")
        assert "denial of service" in agent.kickoff_text(
            "lab-b", ["juice-shop"], "without-pipeline"
        )
