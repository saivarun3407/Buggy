"""gitleaks — secret scanning of fetched JS files and listed public repositories.

Always run with ``--redact``: the recon store records that a secret exists,
its rule, location and fingerprint, never the secret itself.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from buggy.pipeline.schema import Record, RecordType, host_of
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation


class Gitleaks:
    name = "gitleaks"
    passive = True  # reads local files / a cloned repository only

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        """``inputs`` is ``[mode, path]`` with mode ``dir`` or ``git``."""
        mode, target = inputs
        if mode not in ("dir", "git"):
            raise ValueError(f"gitleaks mode must be 'dir' or 'git', not {mode!r}")
        report = workdir / f"gitleaks-{mode}-report.json"
        return Invocation(
            argv=[
                binary,
                mode,
                target,
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--redact",
                "--no-banner",
                "--exit-code",
                "0",
                "--log-level",
                "error",
                "--max-target-megabytes",
                "20",
            ],  # fmt: skip
            output_file=report,
            timeout=1800,
        )

    def parse(
        self, raw: str, *, sources: dict[str, str] | None = None, asset: str = ""
    ) -> Iterator[Record]:
        """Secret records. ``sources`` maps a scanned file name to the URL it came from."""
        try:
            findings = json.loads(raw or "[]")
        except json.JSONDecodeError:
            return
        if not isinstance(findings, list):
            return
        for finding in findings:
            if not isinstance(finding, dict) or not finding.get("RuleID"):
                continue
            file_name = str(finding.get("File") or "")
            origin = (sources or {}).get(Path(file_name).name, "")
            location = origin or file_name
            record_asset = host_of(origin) if origin else asset
            if not record_asset:
                continue
            line = finding.get("StartLine")
            commit = str(finding.get("Commit") or "")
            where = f"{location}:{line}" + (f"@{commit[:12]}" if commit else "")
            yield Record(
                type=RecordType.SECRET,
                asset=record_asset,
                value=f"{finding['RuleID']} {where}",
                source_tool=self.name,
                attrs={
                    "rule_id": str(finding["RuleID"]),
                    "description": str(finding.get("Description") or "")[:300],
                    "location": location,
                    "line": line,
                    "commit": commit,
                    "entropy": finding.get("Entropy"),
                    "fingerprint": str(finding.get("Fingerprint") or ""),
                    "redacted": True,
                },
            )
