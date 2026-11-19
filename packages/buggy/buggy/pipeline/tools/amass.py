"""amass (v4) — passive enumeration.

amass 4 prints relationship triples instead of bare names::

    www.example.com (FQDN) --> cname_record --> example.com (FQDN)
    example.com (FQDN) --> a_record --> 93.184.216.34 (IPAddress)

Every ``(FQDN)`` node is a discovered name. Address, netblock and ASN nodes
are ignored: resolution belongs to the DNS stage, which records its own
evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from buggy.pipeline.schema import Record, RecordType, is_hostname, normalize_host
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation, write_lines

_NODE = re.compile(r"(\S+) \((\w+)\)")


class Amass:
    name = "amass"
    passive = True

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        roots = write_lines(workdir / "amass-roots.txt", inputs)
        output = workdir / "amass-out.txt"
        return Invocation(
            argv=[
                binary,
                "enum",
                "-passive",
                "-df",
                str(roots),
                "-o",
                str(output),
                "-dir",
                str(workdir / "amass-db"),
                "-silent",
                "-nocolor",
                "-timeout",
                "10",
            ],  # fmt: skip
            output_file=output,
            timeout=900,
        )

    def parse(self, raw: str) -> Iterator[Record]:
        seen: set[str] = set()
        for number, line in enumerate(raw.splitlines(), start=1):
            for name, kind in _NODE.findall(line):
                if kind != "FQDN":
                    continue
                host = normalize_host(name)
                if host in seen or not is_hostname(host):
                    continue
                seen.add(host)
                yield Record(
                    type=RecordType.SUBDOMAIN,
                    asset=host,
                    value=host,
                    source_tool=self.name,
                    attrs={},
                    raw_line=number,
                )
