"""gau and waybackurls — historical URLs from public web archives.

Both are passive: they query archive indexes, never the target. Archive
indexes hold a lot of junk (truncated URLs, other hosts sharing a suffix), so
the stage's scope filter does the real work on their output.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

from buggy.pipeline.schema import Record, RecordType, host_of, normalize_url
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation, iter_jsonl
from buggy.pipeline.tools.katana import is_javascript

_MAX_URL = 2048


def _url_record(candidate: str, source_tool: str, line: int) -> Record | None:
    text = candidate.strip()
    if not text or len(text) > _MAX_URL or urlsplit(text).scheme not in ("http", "https"):
        return None
    url = normalize_url(text)
    asset = host_of(url)
    if not asset:
        return None
    return Record(
        type=RecordType.JS_FILE if is_javascript(url) else RecordType.URL,
        asset=asset,
        value=url,
        source_tool=source_tool,
        attrs={"archived": True},
        raw_line=line,
    )


class Gau:
    name = "gau"
    passive = True

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        return Invocation(
            argv=[
                binary,
                "--json",
                "--threads",
                str(max(1, min(limits.concurrency, 5))),
                "--providers",
                "wayback,commoncrawl,otx,urlscan",
                "--timeout",
                "45",
                "--retries",
                "2",
                *inputs,
            ],  # fmt: skip
            timeout=1800,
        )

    def parse(self, raw: str) -> Iterator[Record]:
        for line, obj in iter_jsonl(raw):
            record = _url_record(str(obj.get("url") or ""), self.name, line)
            if record is not None:
                yield record


class Waybackurls:
    name = "waybackurls"
    passive = True

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        # Hosts arrive on stdin; -no-subs keeps each query to the host asked for.
        return Invocation(argv=[binary, "-no-subs"], stdin="\n".join(inputs) + "\n", timeout=1800)

    def parse(self, raw: str) -> Iterator[Record]:
        for number, line in enumerate(raw.splitlines(), start=1):
            record = _url_record(line, self.name, number)
            if record is not None:
                yield record
