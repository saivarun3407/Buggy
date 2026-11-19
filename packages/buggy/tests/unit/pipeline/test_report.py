"""The recon report and its test-candidate ranking are plain functions of the records."""

from __future__ import annotations

from buggy.pipeline.report import MANUAL, group_issues, rank_candidates, render_report


def _record(kind: str, value: str, **attrs) -> dict:
    return {
        "id": f"{kind}-{abs(hash(value)) % 10_000}",
        "type": kind,
        "value": value,
        "attrs": attrs,
    }


def _candidates(records: dict) -> dict[str, tuple[str, str]]:
    return {c["where"]: (c["class"], c["probe"]) for c in rank_candidates(records)}


def test_identifiers_must_follow_a_collection_to_count_as_object_references() -> None:
    found = _candidates(
        {
            "endpoint": [
                _record("endpoint", "https://a.test/10"),  # a bare number from a script
                _record("endpoint", "https://a.test/api/orders/1002"),
                _record(
                    "endpoint", "https://a.test/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301/keys"
                ),
                _record("endpoint", "https://a.test/static/app.js"),
            ],
            "api_operation": [
                _record(
                    "api_operation", "GET /x", method="GET", url="https://a.test/v1/items/{itemId}"
                ),
            ],
        }
    )
    assert "https://a.test/10" not in found and "https://a.test/static/app.js" not in found
    assert found["https://a.test/api/orders/1002"] == ("access_control", "idor")
    assert found["https://a.test/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301/keys"][1] == "idor"
    assert found["GET https://a.test/v1/items/{itemId}"] == ("access_control", "idor")


def test_each_candidate_names_a_probe_that_actually_applies() -> None:
    found = _candidates(
        {
            "url": [
                _record("url", "https://a.test/login"),
                _record("url", "https://a.test/admin/config"),
                _record("url", "https://a.test/fetch?url=https://x.test/a.png"),
            ],
            "api_operation": [
                _record(
                    "api_operation",
                    "POST /orders",
                    method="POST",
                    url="https://a.test/api/orders",
                    auth_required=True,
                    request_body_types=["application/json"],
                ),
            ],
            "graphql": [_record("graphql", "https://a.test/graphql", introspection_enabled=True)],
        }
    )
    # A login page is not where an unsigned-token check applies.
    assert found["https://a.test/login"] == ("auth_session", MANUAL)
    assert found["https://a.test/admin/config"] == ("access_control", MANUAL)
    assert found["https://a.test/fetch?url=https://x.test/a.png"] == ("ssrf", "ssrf_canary")
    assert found["https://a.test/graphql"] == ("graphql", "graphql_checks")
    classes = [c["class"] for c in rank_candidates({"graphql": [], "url": []})]
    assert classes == []
    post = [
        c
        for c in rank_candidates(
            {
                "api_operation": [
                    _record(
                        "api_operation",
                        "POST /orders",
                        method="POST",
                        url="https://a.test/api/orders",
                        auth_required=True,
                        request_body_types=["application/json"],
                    )
                ]
            }
        )
    ]
    assert {(c["class"], c["probe"]) for c in post} == {
        ("api", "mass_assignment"),
        ("auth_session", "jwt_alg_none"),
    }


def test_candidates_are_ranked_and_capped() -> None:
    many = {"endpoint": [_record("endpoint", f"https://a.test/api/orders/{n}") for n in range(200)]}
    assert len(rank_candidates(many, limit=25)) == 25
    mixed = rank_candidates(
        {
            "graphql": [_record("graphql", "https://a.test/graphql")],
            "url": [
                _record("url", "https://a.test/api/users/7"),
                _record("url", "https://a.test/login"),
            ],
        }
    )
    assert [c["class"] for c in mixed] == ["access_control", "auth_session", "graphql"]


def test_issues_are_grouped_by_template_and_sorted_by_severity() -> None:
    issues = group_issues(
        [
            _record(
                "vulnerability",
                "hdr a",
                template_id="http-missing-security-headers",
                name="Missing Headers",
                severity="info",
                matched_at="https://a.test/",
            ),
            _record(
                "vulnerability",
                "hdr b",
                template_id="http-missing-security-headers",
                name="Missing Headers",
                severity="info",
                matched_at="https://b.test/",
            ),
            _record(
                "vulnerability",
                "env",
                template_id="exposed-env",
                name="Exposed .env",
                severity="high",
                matched_at="https://a.test/.env",
                cwe=["cwe-200"],
            ),
            _record("vulnerability", "odd", template_id="odd", name="Odd", severity="weird"),
        ]
    )
    assert [i["template_id"] for i in issues] == [
        "exposed-env",
        "http-missing-security-headers",
        "odd",
    ]
    assert issues[1]["locations"] == ["https://a.test/", "https://b.test/"]
    assert issues[1]["remediation"].startswith("Set the missing response header")
    assert issues[0]["cwe"] == ["CWE-200"] and issues[2]["severity"] == "unknown"


def test_report_renders_without_data_and_never_prints_secret_values() -> None:
    empty = render_report("acme", {"records": {}, "last_run": None}, {}, generated_at=0)
    assert "None reported by the scanner templates" in empty
    assert "No live web service was found" in empty and "Nothing stood out" in empty
    # No coverage in the summary: the report says so instead of implying a full check.
    assert "| Assets with incomplete coverage | not recorded |" in empty
    assert "## Not checked" in empty and "No coverage was recorded" in empty

    text = render_report(
        "acme",
        {
            "records": {"secret": 1},
            "last_run": {
                "run_id": "r1",
                "status": "completed",
                "started_at": 10.0,
                "finished_at": 70.0,
                "scope_drops": 4,
            },
        },
        {
            "secret": [
                _record(
                    "secret",
                    "AKIAEXAMPLEEXAMPLE",
                    rule_id="aws-access-token",
                    url="https://a.test/app.js",
                    match="AKIAEXAMPLEEXAMPLE",
                )
            ]
        },
        scope=["a.test"],
        generated_at=0,
    )
    assert "aws-access-token" in text and "https://a.test/app.js" in text
    assert "AKIAEXAMPLEEXAMPLE" not in text
    assert "completed, 60 s" in text and "| Candidates dropped as out of scope | 4 |" in text


def test_report_lists_coverage_gaps_by_stage_and_flags_the_issue_list() -> None:
    def summary(gaps: list[dict], **counts: int) -> dict:
        return {
            "records": {},
            "last_run": None,
            "coverage": {"complete": 0, "partial": 0, "failed": 0, "skipped": 0, **counts},
            "coverage_gaps": gaps,
            "coverage_gap_assets": len({g["asset"] for g in gaps}),
        }

    gaps = [
        {"asset": "b.test", "stage": "issues", "status": "partial", "detail": "nuclei: timed out"},
        {"asset": "a.test", "stage": "issues", "status": "failed", "detail": "nuclei: exit 2"},
        {"asset": "a.test", "stage": "port", "status": "skipped", "detail": "port scan disabled"},
    ]
    text = render_report(
        "acme", summary(gaps, complete=9, partial=1, failed=1, skipped=1), {}, generated_at=0
    )
    assert "| Assets with incomplete coverage | 2 |" in text
    section = text.split("## Not checked\n", 1)[1].split("\n## ", 1)[0]
    assert section.index("### port — port scan") < section.index("### issues — known-issue")
    assert section.index("| a.test | failed | nuclei: exit 2 |") < section.index(
        "| b.test | partial | nuclei: timed out |"
    )
    assert "| a.test | skipped | port scan disabled |" in section
    known = text.split("## Known issues\n", 1)[1].strip().splitlines()[0]
    assert known.startswith("This list is not complete: 2 asset(s)")

    # Control: stamps exist and none is a gap, so nothing is flagged.
    clean = render_report("acme", summary([], complete=12), {}, generated_at=0)
    assert "| Assets with incomplete coverage | 0 |" in clean
    assert "not complete" not in clean and "Every stage completed" in clean
    assert clean.split("## Known issues\n", 1)[1].strip().startswith("None reported")
