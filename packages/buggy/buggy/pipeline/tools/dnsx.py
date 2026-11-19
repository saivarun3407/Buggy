"""dnsx — DNS resolution and records (A / AAAA / CNAME / MX / TXT / NS)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from buggy.pipeline.schema import Record, RecordType, is_hostname, normalize_host
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation, as_list, iter_jsonl, write_lines

RECORD_FIELDS = ("a", "aaaa", "cname", "mx", "txt", "ns")


class Dnsx:
    name = "dnsx"
    # DNS queries go to public resolvers, not to the target's hosts.
    passive = True

    def __init__(self, resolvers: tuple[str, ...] = ()) -> None:
        self._resolvers = resolvers

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        hosts = write_lines(workdir / "dnsx-hosts.txt", inputs)
        argv = [
            binary,
            "-l", str(hosts),
            "-a", "-aaaa", "-cname", "-mx", "-txt", "-ns",
            "-resp", "-json", "-omit-raw", "-silent", "-duc",
            "-rl", str(max(limits.rate_limit_rps, 1) * 5),
            "-t", str(max(limits.concurrency, 1)),
            "-retry", "2",
        ]  # fmt: skip
        if self._resolvers:
            argv += ["-r", ",".join(self._resolvers)]
        return Invocation(argv=argv, timeout=900)

    def parse(self, raw: str) -> Iterator[Record]:
        for line, obj in iter_jsonl(raw):
            host = normalize_host(str(obj.get("host") or ""))
            if not is_hostname(host):
                continue
            for kind in RECORD_FIELDS:
                for data in as_list(obj.get(kind)):
                    value = data.strip() if kind == "txt" else normalize_host(data)
                    if not value:
                        continue
                    yield Record(
                        type=RecordType.DNS_RECORD,
                        asset=host,
                        value=f"{kind.upper()} {value}",
                        source_tool=self.name,
                        attrs={
                            "rtype": kind.upper(),
                            "data": value,
                            "rcode": str(obj.get("status_code") or ""),
                        },
                        raw_line=line,
                    )
