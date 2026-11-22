"""Tests for @tool wrappers in contracts/tools.py, evidence/tools.py, cloud/tools.py.

Focuses on the JSON output shapes and error paths that are NOT covered by the
existing helper tests (test_cloud.py, test_patterns_slither.py, test_evidence.py).
All external IO is mocked so the suite runs fully offline.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

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
