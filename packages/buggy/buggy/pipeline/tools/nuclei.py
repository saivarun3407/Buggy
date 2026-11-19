"""nuclei — known-issue scanning with a vetted template set.

"Vetted" means three things, all fixed in code rather than left to defaults:

* one pinned release of the upstream templates
  (``versions.NUCLEI_TEMPLATES_VERSION``), installed in the image;
* only the directories in :data:`TEMPLATE_DIRS`;
* nothing tagged with :data:`EXCLUDED_TAGS`, no DAST/fuzz/code/headless
  templates, no out-of-band interaction server, and no redirect following
  (a redirect could carry a request to a host the scope filter never saw).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from buggy.pipeline.schema import Record, RecordType, as_dict, host_of
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation, as_list, iter_jsonl, write_lines
from buggy.pipeline.versions import NUCLEI_TEMPLATES_DIR

TEMPLATE_DIRS = (
    "http/exposures",
    "http/misconfiguration",
    "http/exposed-panels",
    "http/technologies",
    "http/cves",
    "http/vulnerabilities",
    "http/takeovers",
    "ssl",
)

# Denial of service, anything that mutates state or guesses credentials.
EXCLUDED_TAGS = (
    "dos",
    "fuzz",
    "fuzzing",
    "intrusive",
    "brute-force",
    "bruteforce",
    "default-login",
    "creds-stuffing",
    "bypass",
)

SEVERITIES = ("info", "low", "medium", "high", "critical")


class Nuclei:
    name = "nuclei"
    passive = False

    def __init__(
        self, templates_dir: str = NUCLEI_TEMPLATES_DIR, resolvers: tuple[str, ...] = ()
    ) -> None:
        self._templates = Path(templates_dir)
        self._resolvers = resolvers

    def template_paths(self) -> list[str]:
        return [str(self._templates / directory) for directory in TEMPLATE_DIRS]

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        targets = write_lines(workdir / "nuclei-targets.txt", inputs)
        severities = [s for s in limits.nuclei_severities if s in SEVERITIES] or ["low"]
        argv = [binary, "-l", str(targets), "-jsonl", "-silent", "-duc", "-ni", "-dr", "-or", "-ot"]
        for path in self.template_paths():
            argv += ["-t", path]
        argv += [
            "-pt", "http,ssl",
            "-etags", ",".join(EXCLUDED_TAGS),
            "-severity", ",".join(severities),
            "-rl", str(limits.rate_limit_rps),
            "-c", str(max(1, min(limits.concurrency, 25))),
            "-bs", str(max(1, min(limits.concurrency, 25))),
            "-timeout", "10",
            "-retries", "1",
        ]  # fmt: skip
        if self._resolvers:
            # nuclei takes its resolver list as a file.
            resolvers = write_lines(workdir / "nuclei-resolvers.txt", list(self._resolvers))
            argv += ["-r", str(resolvers)]
        return Invocation(argv=argv, timeout=4 * 3600)

    def parse(self, raw: str) -> Iterator[Record]:
        for line, obj in iter_jsonl(raw):
            template_id = str(obj.get("template-id") or "")
            matched_at = str(obj.get("matched-at") or obj.get("url") or obj.get("host") or "")
            if not template_id or not matched_at:
                continue
            asset = host_of(matched_at) or host_of(str(obj.get("host") or ""))
            if not asset:
                continue
            info = as_dict(obj.get("info"))
            classification = as_dict(info.get("classification"))
            matcher = str(obj.get("matcher-name") or "")
            attrs: dict[str, Any] = {
                "template_id": template_id,
                "name": str(info.get("name") or ""),
                "severity": str(info.get("severity") or "unknown").lower(),
                "tags": as_list(info.get("tags"))[:30],
                "matched_at": matched_at,
                "matcher_name": matcher,
                "type": str(obj.get("type") or ""),
                "description": str(info.get("description") or "").strip()[:600],
                "reference": as_list(info.get("reference"))[:5],
                "cve": as_list(classification.get("cve-id")),
                "cwe": as_list(classification.get("cwe-id")),
                "cvss_score": classification.get("cvss-score"),
                "extracted": as_list(obj.get("extracted-results"))[:10],
            }
            yield Record(
                type=RecordType.VULNERABILITY,
                asset=asset,
                value=" ".join(part for part in (template_id, matcher, matched_at) if part),
                source_tool=self.name,
                attrs={k: v for k, v in attrs.items() if v not in (None, "", [])},
                raw_line=line,
            )
