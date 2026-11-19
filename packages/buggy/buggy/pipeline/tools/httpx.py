"""httpx — live HTTP services, technology, TLS and response headers.

One probe yields the records of two pipeline stages: the live service
(stage 3) and its fingerprint (stage 4). Redirects are not followed, so a
probe never lands on a host the scope filter did not approve; the
``Location`` value is kept for later stages to filter.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from buggy.pipeline.schema import Record, RecordType, host_of, normalize_url
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation, as_list, iter_jsonl, write_lines

# Response headers worth a record of their own (security posture and stack
# disclosure). httpx reports header names lower-cased with underscores.
SECURITY_HEADERS = (
    "content_security_policy",
    "strict_transport_security",
    "x_frame_options",
    "x_content_type_options",
    "referrer_policy",
    "permissions_policy",
    "access_control_allow_origin",
    "access_control_allow_credentials",
    "set_cookie",
    "server",
    "x_powered_by",
    "www_authenticate",
)

_TLS_FIELDS = (
    "tls_version",
    "cipher",
    "subject_cn",
    "subject_an",
    "subject_dn",
    "issuer_cn",
    "issuer_dn",
    "not_before",
    "not_after",
    "self_signed",
    "mismatched",
    "expired",
    "wildcard_certificate",
)


class Httpx:
    name = "httpx"
    passive = False

    def __init__(self, resolvers: tuple[str, ...] = ()) -> None:
        self._resolvers = resolvers

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        targets = write_lines(workdir / "httpx-targets.txt", inputs)
        extra = ["-r", ",".join(self._resolvers)] if self._resolvers else []
        return Invocation(
            argv=[
                binary,
                "-l",
                str(targets),
                "-json",
                "-silent",
                "-duc",
                "-sc",
                "-title",
                "-td",
                "-server",
                "-ip",
                "-cname",
                "-ct",
                "-cl",
                "-location",
                "-method",
                "-tls-grab",
                "-irh",
                "-ob",
                "-rl",
                str(limits.rate_limit_rps),
                "-t",
                str(limits.concurrency),
                "-timeout",
                "10",
                "-retries",
                "1",
                *extra,
            ],  # fmt: skip
            timeout=3600,
        )

    def parse(self, raw: str) -> Iterator[Record]:
        for line, obj in iter_jsonl(raw):
            if obj.get("failed") is True or not obj.get("url"):
                continue
            url = normalize_url(str(obj["url"]))
            # ``input`` is what the pipeline asked for; the asset is its host.
            asset = host_of(str(obj.get("input") or "")) or host_of(url)
            if not asset:
                continue
            yield Record(
                type=RecordType.HTTP_SERVICE,
                asset=asset,
                value=url,
                source_tool=self.name,
                attrs=_service_attrs(obj),
                raw_line=line,
            )
            for tech in as_list(obj.get("tech")):
                name, _, version = tech.partition(":")
                yield Record(
                    type=RecordType.TECHNOLOGY,
                    asset=asset,
                    value=f"{url} {name}",
                    source_tool=self.name,
                    attrs={"url": url, "name": name, "version": version},
                    raw_line=line,
                )
            tls = obj.get("tls")
            if isinstance(tls, dict) and tls.get("probe_status") is not False:
                fingerprint = (tls.get("fingerprint_hash") or {}).get("sha256", "")
                yield Record(
                    type=RecordType.TLS,
                    asset=asset,
                    value=f"{url} {fingerprint or tls.get('subject_cn', '')}",
                    source_tool=self.name,
                    attrs={
                        "url": url,
                        "sha256": fingerprint,
                        **{k: tls[k] for k in _TLS_FIELDS if k in tls},
                    },
                    raw_line=line,
                )
            headers = obj.get("header")
            if isinstance(headers, dict):
                for key in SECURITY_HEADERS:
                    if key in headers:
                        name = key.replace("_", "-")
                        yield Record(
                            type=RecordType.HEADER,
                            asset=asset,
                            value=f"{url} {name}",
                            source_tool=self.name,
                            attrs={"url": url, "name": name, "value": str(headers[key])[:2000]},
                            raw_line=line,
                        )


def _service_attrs(obj: dict[str, Any]) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "scheme": obj.get("scheme"),
        "port": _int(obj.get("port")),
        "status_code": obj.get("status_code"),
        "title": obj.get("title", ""),
        "webserver": obj.get("webserver", ""),
        "content_type": obj.get("content_type", ""),
        "content_length": obj.get("content_length"),
        "location": obj.get("location", ""),
        "ip": obj.get("host_ip") or obj.get("host", ""),
        "a": as_list(obj.get("a")),
        "cname": as_list(obj.get("cname")),
        "cdn": obj.get("cdn_name", "") if obj.get("cdn") else "",
    }
    return {key: value for key, value in attrs.items() if value not in (None, "", [])}


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
