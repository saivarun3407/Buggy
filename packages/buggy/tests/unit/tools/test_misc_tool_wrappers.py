"""Tests for @tool wrappers in contracts/tools.py, evidence/tools.py, cloud/tools.py.

Focuses on the JSON output shapes and error paths that are NOT covered by the
existing helper tests (test_cloud.py, test_patterns_slither.py, test_evidence.py).
All external IO is mocked so the suite runs fully offline.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

# ── contracts/tools.py wrappers ────────────────────────────────────────────


class TestSolidityScantool:
    """solidity_scan @tool — JSON output shape."""

    def test_happy_path_returns_json_list(self) -> None:
        from buggy.tools.contracts.tools import solidity_scan

        result = solidity_scan.invoke(
            {"source": "function auth() public { require(tx.origin == owner); }"}
        )
        data = json.loads(result)
        assert isinstance(data, list)
        # at least one finding (tx.origin rule)
        assert len(data) >= 1
        first = data[0]
        assert "id" in first
        assert "rule" in first
        assert "severity" in first
        assert "line" in first
        assert "snippet" in first

    def test_clean_source_returns_empty_list(self) -> None:
        from buggy.tools.contracts.tools import solidity_scan

        result = solidity_scan.invoke({"source": "// solidity comment only"})
        data = json.loads(result)
        assert data == []

    def test_multiple_findings_ordered_by_line(self) -> None:
        from buggy.tools.contracts.tools import solidity_scan

        src = (
            "// line 1\n"
            "function a() public { require(tx.origin == owner); }\n"
            "function b() public { address s = ecrecover(h, v, r, x); }\n"
        )
        result = solidity_scan.invoke({"source": src})
        findings = json.loads(result)
        lines = [f["line"] for f in findings]
        assert lines == sorted(lines)


class TestSolidityScantoolFile:
    """solidity_scan_file @tool — reads file and returns JSON dict with 'findings' key."""

    def test_reads_file_and_returns_findings(self, tmp_path: Path) -> None:
        from buggy.tools.contracts.tools import solidity_scan_file

        sol = tmp_path / "contract.sol"
        sol.write_text("function f() public { require(tx.origin == owner); }", encoding="utf-8")
        result = solidity_scan_file.invoke({"path": str(sol)})
        data = json.loads(result)
        assert data["file"] == str(sol)
        assert isinstance(data["count"], int)
        assert isinstance(data["findings"], list)
        assert data["count"] == len(data["findings"])
        assert data["count"] >= 1

    def test_missing_file_returns_error_key(self, tmp_path: Path) -> None:
        from buggy.tools.contracts.tools import solidity_scan_file

        result = solidity_scan_file.invoke({"path": str(tmp_path / "nonexistent.sol")})
        data = json.loads(result)
        assert "error" in data

    def test_clean_sol_file_count_zero(self, tmp_path: Path) -> None:
        from buggy.tools.contracts.tools import solidity_scan_file

        sol = tmp_path / "clean.sol"
        sol.write_text("// pragma solidity ^0.8.0;\n", encoding="utf-8")
        result = solidity_scan_file.invoke({"path": str(sol)})
        data = json.loads(result)
        assert data["count"] == 0
        assert data["findings"] == []


class TestSlitherIngestTool:
    """slither_ingest @tool — reads file and ingests into KG."""

    def test_missing_file_returns_error(self, tmp_path: Path) -> None:
        from buggy.tools.contracts.tools import slither_ingest

        result = slither_ingest.invoke({"path": str(tmp_path / "missing.json")})
        data = json.loads(result)
        assert "error" in data

    # ``test_valid_slither_json_returns_ingested_and_stats`` /
    # ``test_empty_detectors_returns_zero`` previously patched
    # ``buggy.tools.contracts.tools._load`` / ``_save`` to inject
    # a ``KnowledgeGraph``. After ``slither.py`` was rewritten to write
    # directly through ``KGStore.record_observations``, those symbols
    # no longer exist on the module. They are reintroduced in a
    # dedicated KGStore-mock-based test PR — see the Slither RFC §4.4.


class TestFoundryToolWrappers:
    """foundry_reentrancy_test, foundry_access_test, foundry_flashloan_test."""

    def test_reentrancy_tool_returns_path_and_source(self) -> None:
        from buggy.tools.contracts.tools import foundry_reentrancy_test

        result = foundry_reentrancy_test.invoke(
            {"target": "Vault", "function": "withdraw", "target_path": "src/Vault.sol"}
        )
        data = json.loads(result)
        assert "path" in data
        assert "source" in data
        assert data["path"].endswith(".t.sol")
        assert "withdraw" in data["source"]

    def test_access_test_tool_returns_path_and_source(self) -> None:
        from buggy.tools.contracts.tools import foundry_access_test

        result = foundry_access_test.invoke({"target": "Token", "function": "mint"})
        data = json.loads(result)
        assert "path" in data
        assert "source" in data
        assert "mint" in data["source"]

    def test_flashloan_test_tool_returns_path_and_source(self) -> None:
        from buggy.tools.contracts.tools import foundry_flashloan_test

        result = foundry_flashloan_test.invoke({"target": "Pool"})
        data = json.loads(result)
        assert "path" in data
        assert "source" in data
        assert "executeOperation" in data["source"]

    def test_contract_tools_list_has_six_items(self) -> None:
        from buggy.tools.contracts.tools import CONTRACT_TOOLS

        assert len(CONTRACT_TOOLS) == 6


# ── evidence/tools.py wrappers ─────────────────────────────────────────────


class TestExportSessionAsciicastTool:
    """export_session_asciicast @tool output shapes."""

    def test_successful_export_returns_status_exported(self, tmp_path: Path) -> None:
        from buggy.tools.evidence.tools import export_session_asciicast

        log = tmp_path / ".tmux-logs" / "mysession.log"
        log.parent.mkdir(parents=True)
        log.write_text("cmd output\n", encoding="utf-8")

        evidence_dir = tmp_path / "evidence" / "recordings"
        evidence_dir.mkdir(parents=True)

        with patch("buggy.tools.evidence.tools._workspace", return_value=tmp_path):
            result = export_session_asciicast.invoke(
                {
                    "session_name": "mysession",
                    "pipe_pane_log_path": "",
                    "title": "Test Session",
                }
            )

        data = json.loads(result)
        assert data["status"] == "exported"
        assert "session_name" in data

    def test_explicit_log_path_used_when_provided(self, tmp_path: Path) -> None:
        from buggy.tools.evidence.tools import export_session_asciicast

        log = tmp_path / "custom.log"
        log.write_text("output line\n", encoding="utf-8")
        evidence_dir = tmp_path / "evidence" / "recordings"
        evidence_dir.mkdir(parents=True)

        with patch("buggy.tools.evidence.tools._workspace", return_value=tmp_path):
            result = export_session_asciicast.invoke(
                {
                    "session_name": "s1",
                    "pipe_pane_log_path": str(log),
                    "title": "",
                }
            )

        data = json.loads(result)
        assert data["status"] == "exported"

    def test_missing_log_returns_error_key(self, tmp_path: Path) -> None:
        from buggy.tools.evidence.tools import export_session_asciicast

        evidence_dir = tmp_path / "evidence" / "recordings"
        evidence_dir.mkdir(parents=True)

        with patch("buggy.tools.evidence.tools._workspace", return_value=tmp_path):
            result = export_session_asciicast.invoke(
                {
                    "session_name": "nope",
                    "pipe_pane_log_path": str(tmp_path / "nonexistent.log"),
                    "title": "",
                }
            )

        data = json.loads(result)
        assert "error" in data


class TestListSessionRecordingsTool:
    """list_session_recordings @tool output shapes."""

    def test_empty_dir_returns_count_zero(self, tmp_path: Path) -> None:
        from buggy.tools.evidence.tools import list_session_recordings

        recordings_dir = tmp_path / "evidence" / "recordings"
        recordings_dir.mkdir(parents=True)

        with patch("buggy.tools.evidence.tools._workspace", return_value=tmp_path):
            result = list_session_recordings.invoke({})

        data = json.loads(result)
        assert data["count"] == 0
        assert data["recordings"] == []

    def test_lists_manifests_correctly(self, tmp_path: Path) -> None:
        from buggy.tools.evidence.tools import list_session_recordings

        recordings_dir = tmp_path / "evidence" / "recordings"
        recordings_dir.mkdir(parents=True)
        (recordings_dir / "a.cast.manifest.json").write_text(
            json.dumps({"session_name": "a", "duration_seconds": 1.5}),
            encoding="utf-8",
        )
        (recordings_dir / "b.cast.manifest.json").write_text(
            json.dumps({"session_name": "b", "duration_seconds": 2.0}),
            encoding="utf-8",
        )

        with patch("buggy.tools.evidence.tools._workspace", return_value=tmp_path):
            result = list_session_recordings.invoke({})

        data = json.loads(result)
        assert data["count"] == 2
        names = sorted(m["session_name"] for m in data["recordings"])
        assert names == ["a", "b"]

    def test_evidence_tools_list_has_four_items(self) -> None:
        from buggy.tools.evidence.tools import EVIDENCE_TOOLS

        assert len(EVIDENCE_TOOLS) == 4
