"""Shared pieces of a pipeline tool wrapper.

A wrapper does two things and nothing else: build an ``argv`` list from
scope-filtered inputs and program limits, and parse the tool's raw output
into :class:`~buggy.pipeline.schema.Record` objects. It never decides what is
in scope and never touches the store; the stage does both around it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from buggy.pipeline.schema import Record
from buggy.pipeline.scope import PipelineLimits


@dataclass(frozen=True, slots=True)
class Invocation:
    """How to run a tool once."""

    argv: list[str]
    stdin: str | None = None
    # Some tools only write to a file; the runner then reads it as the raw output.
    output_file: Path | None = None
    timeout: float = 900.0


class ToolWrapper(Protocol):
    name: str
    passive: bool  # True: talks only to third-party data sources, never to a target

    def invocation(
        self, binary: str, inputs: list[str], limits: PipelineLimits, workdir: Path
    ) -> Invocation: ...

    def parse(self, raw: str) -> Iterator[Record]: ...


def write_lines(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path


def iter_jsonl(raw: str) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(line_number, object)`` for each JSON-object line; skip anything else.

    Scanners interleave banners and warnings with results when a flag is
    missed or an upstream is down; a parser must survive that, not crash.
    """
    for number, line in enumerate(raw.splitlines(), start=1):
        text = line.strip()
        if not text.startswith("{"):
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield number, obj


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


__all__ = ["Invocation", "ToolWrapper", "as_list", "iter_jsonl", "write_lines"]
