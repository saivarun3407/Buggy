"""katana — crawl live services for URLs, JS files and forms.

``-fs fqdn`` keeps the crawler on the host it was given; the stage filters
every reported URL against the scope again, because the crawler's idea of
"same host" is not the engagement's scope.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

from buggy.pipeline.schema import Record, RecordType, as_dict, host_of, normalize_url
from buggy.pipeline.scope import PipelineLimits
from buggy.pipeline.tools.base import Invocation, iter_jsonl, write_lines

STATIC_EXTENSIONS = (
    "png,jpg,jpeg,gif,svg,ico,webp,bmp,woff,woff2,ttf,eot,otf,mp4,mp3,avi,mov,webm,css,pdf,zip"
)


def is_javascript(url: str, content_type: str = "") -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith((".js", ".mjs")) or "javascript" in content_type.lower()


class Katana:
    name = "katana"
    passive = False

    def __init__(self, resolvers: tuple[str, ...] = ()) -> None:
        self._resolvers = resolvers

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation:
        urls = write_lines(workdir / "katana-urls.txt", inputs)
        extra = ["-r", ",".join(self._resolvers)] if self._resolvers else []
        for pattern in limits.crawl_exclude:
            extra += ["-cos", pattern]
        return Invocation(
            argv=[
                binary,
                "-list",
                str(urls),
                "-jsonl",
                "-silent",
                "-duc",
                "-d",
                str(limits.crawl_depth),
                "-jc",
                "-fs",
                "fqdn",
                "-ef",
                STATIC_EXTENSIONS,
                "-or",
                "-ob",
                "-rl",
                str(limits.rate_limit_rps),
                "-c",
                str(limits.concurrency),
                "-p",
                "1",
                "-ct",
                "10m",
                "-timeout",
                "10",
                *extra,
            ],  # fmt: skip
            timeout=3600,
        )

    def parse(self, raw: str) -> Iterator[Record]:
        for line, obj in iter_jsonl(raw):
            request = obj.get("request")
            if not isinstance(request, dict) or not request.get("endpoint"):
                continue
            endpoint = str(request["endpoint"])
            if urlsplit(endpoint).scheme not in ("http", "https"):
                continue
            url = normalize_url(endpoint)
            asset = host_of(url)
            if not asset:
                continue
            response = as_dict(obj.get("response"))
            headers = as_dict(response.get("headers"))
            content_type = str(headers.get("Content-Type") or headers.get("content-type") or "")
            attrs = {
                "method": str(request.get("method") or "GET").upper(),
                "status_code": response.get("status_code"),
                "content_type": content_type,
                "found_in": str(request.get("source") or ""),
                "tag": str(request.get("tag") or ""),
            }
            yield Record(
                type=RecordType.JS_FILE if is_javascript(url, content_type) else RecordType.URL,
                asset=asset,
                value=url,
                source_tool=self.name,
                attrs={k: v for k, v in attrs.items() if v not in (None, "")},
                raw_line=line,
            )
