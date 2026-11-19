"""Certificate transparency via crt.sh (built in; no binary).

One HTTPS request per enumeration root to crt.sh, a third-party log search.
Nothing is sent to the target. ``name_value`` holds every SAN of a
certificate, newline separated; wildcard entries (``*.acme.com``) name no
host and are skipped.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from urllib.parse import quote

from buggy.pipeline.schema import Record, RecordType, is_hostname, normalize_host

NAME = "crtsh"


def query_url(root: str) -> str:
    return f"https://crt.sh/?q={quote('%.' + root, safe='')}&output=json"


def parse(raw: str, *, root: str = "") -> Iterator[Record]:
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return
    if not isinstance(entries, list):
        return
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        names = str(entry.get("name_value") or "").split("\n")
        names.append(str(entry.get("common_name") or ""))
        for name in names:
            host = normalize_host(name)
            if not host or "*" in host or host in seen or not is_hostname(host):
                continue
            seen.add(host)
            yield Record(
                type=RecordType.SUBDOMAIN,
                asset=host,
                value=host,
                source_tool=NAME,
                attrs={"root": root} if root else {},
            )
