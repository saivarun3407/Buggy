"""naabu — TCP port discovery (connect scan, so no raw-socket privileges)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from buggy.pipeline.schema import Record, RecordType, normalize_host
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation, iter_jsonl, write_lines

_TOP_PORTS = {"top-100": "100", "top-1000": "1000"}


class Naabu:
    name = "naabu"
    passive = False

    def __init__(self, resolvers: tuple[str, ...] = ()) -> None:
        self._resolvers = resolvers

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        hosts = write_lines(workdir / "naabu-hosts.txt", inputs)
        argv = [binary, "-list", str(hosts)]
        if limits.ports in _TOP_PORTS:
            argv += ["-top-ports", _TOP_PORTS[limits.ports]]
        else:
            argv += ["-p", limits.ports]
        argv += [
            "-json", "-silent", "-duc",
            "-scan-type", "c",
            "-rate", str(limits.rate_limit_rps),
            "-c", str(limits.concurrency),
            "-retries", "1",
        ]  # fmt: skip
        if self._resolvers:
            argv += ["-r", ",".join(self._resolvers)]
        return Invocation(argv=argv, timeout=3600)

    def parse(self, raw: str) -> Iterator[Record]:
        for line, obj in iter_jsonl(raw):
            try:
                port = int(obj.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if not 0 < port < 65536:
                continue
            ip = str(obj.get("ip") or "")
            # With an address as input there is no "host" key.
            asset = normalize_host(str(obj.get("host") or ip))
            if not asset:
                continue
            protocol = str(obj.get("protocol") or "tcp").lower()
            yield Record(
                type=RecordType.PORT,
                asset=asset,
                value=f"{port}/{protocol}",
                source_tool=self.name,
                attrs={"port": port, "protocol": protocol, "ip": ip},
                raw_line=line,
            )
