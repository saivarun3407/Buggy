"""subfinder — passive subdomain enumeration."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from buggy.pipeline.schema import Record, RecordType, is_hostname, normalize_host
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation, as_list, iter_jsonl, write_lines


class Subfinder:
    name = "subfinder"
    passive = True

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        roots = write_lines(workdir / "subfinder-roots.txt", inputs)
        return Invocation(
            argv=[
                binary,
                "-dL",
                str(roots),
                "-oJ",
                "-cs",
                "-silent",
                "-duc",
                "-rl",
                str(limits.rate_limit_rps),
                "-timeout",
                "30",
                "-max-time",
                "10",
            ],  # fmt: skip
            timeout=900,
        )

    def parse(self, raw: str) -> Iterator[Record]:
        for line, obj in iter_jsonl(raw):
            host = normalize_host(str(obj.get("host") or ""))
            if not is_hostname(host):
                continue
            yield Record(
                type=RecordType.SUBDOMAIN,
                asset=host,
                value=host,
                source_tool=self.name,
                attrs={
                    "root": normalize_host(str(obj.get("input") or "")),
                    "sources": sorted(set(as_list(obj.get("sources") or obj.get("source")))),
                },
                raw_line=line,
            )
