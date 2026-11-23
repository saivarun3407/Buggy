"""buggy-cli trace-review: fixed rules over the bridge's call log."""

from __future__ import annotations

import json
from pathlib import Path

from buggy import agent_records
from buggy.cli import trace_review


def line(seq: int, tool: str = "http_send", **fields) -> dict:
    return {
        "run": fields.pop("run", "r1"),
        "session": fields.pop("session", "s1"),
        "role": "claude_code",
        "attempt": 1,
        "seq": seq,
        "tool": tool,
        "args_digest": fields.pop("args", f"a{seq}"),
        "status": fields.pop("status", "ok"),
        "code": fields.pop("code", ""),
        "result_digest": fields.pop("result", f"r{seq}"),
        "captures": fields.pop("captures", []),
        **fields,
    }


def test_a_clean_run_has_nothing_to_say() -> None:
    result = trace_review.review([line(n) for n in range(1, 6)])
    run = result["runs"][0]
    assert run["calls"] == 5 and not run["loops"] and not run["dead_ends"] and not run["warnings"]
    assert "0 loop(s)" in trace_review.summary_line(result)


def test_the_same_call_three_times_is_a_loop_even_with_calls_between() -> None:
    lines = [line(n, args="same" if n % 2 else f"x{n}") for n in range(1, 7)]
    run = trace_review.review(lines)["runs"][0]
    assert run["loops"] == [
        {"tool": "http_send", "args_digest": "same", "count": 3, "first_seq": 1}
    ]


def test_calls_that_produce_nothing_new_are_a_dead_end() -> None:
    lines = [line(1)]
    lines += [line(n, status="refused", code="APPROVAL_REQUIRED") for n in range(2, 5)]
    lines += [line(n, result="r1") for n in range(5, 9)]  # the same answer as call 1
    lines.append(line(9))
    run = trace_review.review(lines)["runs"][0]
    assert run["dead_ends"] == [{"from_seq": 2, "to_seq": 8, "length": 7}]


def test_a_claim_citing_a_capture_no_tool_returned_is_flagged() -> None:
    lines = [
        line(1, captures=["cap-1111111111111111"]),
        line(2, tool="finding_submit", cited=["cap-1111111111111111"]),
        line(3, tool="finding_submit", cited=["cap-2222222222222222"]),
        # Captured later than the claim: still invented at the time it was made.
        line(4, captures=["cap-2222222222222222"]),
    ]
    run = trace_review.review(lines)["runs"][0]
    assert run["invented"] == [{"seq": 3, "missing": ["cap-2222222222222222"]}]
    assert any("cited captures" in warning for warning in run["warnings"])


def test_captures_seen_in_an_earlier_attempt_of_the_session_count() -> None:
    lines = [
        line(1, run="r1", captures=["cap-1111111111111111"]),
        line(1, run="r2", tool="finding_submit", cited=["cap-1111111111111111"]),
        line(1, run="r3", session="other", tool="finding_submit", cited=["cap-1111111111111111"]),
    ]
    runs = trace_review.review(lines)["runs"]
    assert [bool(run["invented"]) for run in runs] == [False, False, True]


def test_policy_refusals_that_cluster_are_a_warning() -> None:
    lines = [line(n) for n in range(1, 4)]
    lines += [line(n, status="refused", code="OUT_OF_SCOPE") for n in range(4, 8)]
    run = trace_review.review(lines)["runs"][0]
    assert run["refused"] == 4 and run["policy_refusals"] == 4 and run["refusal_spike"]
    assert run["refusal_codes"] == {"OUT_OF_SCOPE": 4}
    assert any("prompt injection" in warning for warning in run["warnings"])
    # Approvals being held are refusals but not a policy signal.
    calm = [line(n, status="refused", code="APPROVAL_REQUIRED") for n in range(1, 9)]
    assert not trace_review.review(calm)["runs"][0]["warnings"]


def test_a_long_stretch_without_progress_is_reported() -> None:
    lines = [line(n) for n in range(1, 46)]
    lines[20] = line(21, tool="finding_submit")
    run = trace_review.review(lines)["runs"][0]
    assert run["no_progress"] == []  # a submitted finding at call 21 splits it in two
    lines = [line(n) for n in range(1, 46)]
    assert trace_review.review(lines)["runs"][0]["no_progress"][0]["length"] == 45


def test_the_command_prints_text_and_json(tmp_path: Path, capsys) -> None:
    records = agent_records.RunRecords(tmp_path, "acme", run_id="r1", session="s1", role="x")
    for _ in range(3):
        records.call("http_send", {"url": "https://app.acme.test/"}, "same", started=0.0)
    assert trace_review.main(["acme", "--audit-root", str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert "loop: http_send with the same arguments 3 times" in text
    assert trace_review.main(["acme", "--audit-root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["loops"] == 1
    assert trace_review.main(["../x"]) == trace_review.EXIT_CONFIG


def test_no_log_is_not_an_error(tmp_path: Path, capsys) -> None:
    assert trace_review.main(["acme", "--audit-root", str(tmp_path)]) == 0
    assert "no agent tool calls were recorded" in capsys.readouterr().out
