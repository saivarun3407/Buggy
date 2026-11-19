"""Score findings against a lab application's ground truth, per vulnerability class.

Three numbers per class, defined so they cannot be gamed by volume:

``found``      ground-truth entries matched by at least one finding
``missed``     ground-truth entries no finding matched
``unmatched``  findings that match no ground-truth entry

An unmatched finding is a *candidate* false positive, not a proven one: these
applications contain more bugs than any list. It is reported separately and
needs a human look. Entries marked ``prohibited`` (denial of service) are
excluded from every count: the agent is not allowed to test them.

A finding matches an entry when both name the same class and either the
finding's endpoint matches the entry's location pattern, or (when the finding
has no usable endpoint) one of the entry's keywords appears in its title.
Several findings matching one entry count once as ``found`` and the rest as
``duplicates``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from benchmark.lab.taxonomy import CLASSES, classify

GROUND_TRUTH_DIR = Path(__file__).parent / "ground_truth"


@dataclass(frozen=True, slots=True)
class Entry:
    id: str
    cls: str
    title: str
    method: str
    location: str
    keywords: tuple[str, ...]
    prohibited: bool = False
    verified_by: str | None = None
    pipeline_signals: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    """A reported issue, reduced to what scoring needs."""

    title: str
    cls: str
    endpoint: str = ""
    method: str = ""
    ref: str = ""


@dataclass
class ClassScore:
    known: int = 0
    found: int = 0
    missed: int = 0
    unmatched: int = 0
    duplicates: int = 0
    found_ids: list[str] = field(default_factory=list)
    missed_ids: list[str] = field(default_factory=list)
    unmatched_titles: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float | None:
        return self.found / self.known if self.known else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "known": self.known,
            "found": self.found,
            "missed": self.missed,
            "unmatched": self.unmatched,
            "duplicates": self.duplicates,
            "recall": None if self.recall is None else round(self.recall, 3),
            "found_ids": self.found_ids,
            "missed_ids": self.missed_ids,
            "unmatched_titles": self.unmatched_titles,
        }


def load_ground_truth(app: str) -> list[Entry]:
    document = json.loads((GROUND_TRUTH_DIR / f"{app}.json").read_text(encoding="utf-8"))
    entries = []
    for raw in document["entries"]:
        if raw["class"] not in CLASSES:
            raise ValueError(f"{app}:{raw['id']} has unknown class {raw['class']!r}")
        re.compile(raw["location"])
        entries.append(
            Entry(
                id=raw["id"],
                cls=raw["class"],
                title=raw["title"],
                method=raw.get("method", "ANY"),
                location=raw["location"],
                keywords=tuple(k.lower() for k in raw.get("keywords", [])),
                prohibited=bool(raw.get("prohibited", False)),
                verified_by=raw.get("verified_by"),
                pipeline_signals=tuple(raw.get("pipeline_signals", [])),
            )
        )
    return entries


def available_apps() -> list[str]:
    return sorted(path.stem for path in GROUND_TRUTH_DIR.glob("*.json"))


def _path_of(endpoint: str) -> str:
    """Path (plus fragment route) of an endpoint given as a URL or a bare path."""
    text = endpoint.strip()
    if not text:
        return ""
    if "://" in text:
        parts = urlsplit(text)
        return (parts.path or "/") + (f"#{parts.fragment}" if parts.fragment else "")
    return text if text.startswith("/") else "/" + text


def _matches(finding: Finding, entry: Entry) -> bool:
    if finding.cls != entry.cls:
        return False
    if (
        entry.method not in ("ANY", "")
        and finding.method
        and finding.method.upper() != entry.method
    ):
        return False
    path = _path_of(finding.endpoint)
    if path:
        return re.search(entry.location, path) is not None
    title = finding.title.lower()
    return any(keyword in title for keyword in entry.keywords)


def score(findings: list[Finding], entries: list[Entry]) -> dict[str, ClassScore]:
    """Per-class scores. Every class with a ground-truth entry or a finding appears."""
    scores: dict[str, ClassScore] = {}
    testable = [e for e in entries if not e.prohibited]
    for entry in testable:
        scores.setdefault(entry.cls, ClassScore()).known += 1
    matched: set[str] = set()
    for finding in findings:
        bucket = scores.setdefault(finding.cls, ClassScore())
        hits = [e for e in testable if _matches(finding, e)]
        if not hits:
            bucket.unmatched += 1
            bucket.unmatched_titles.append(finding.title[:120])
            continue
        fresh = [e for e in hits if e.id not in matched]
        if not fresh:
            bucket.duplicates += 1
            continue
        # One finding credits one entry: the most specific location pattern.
        best = max(fresh, key=lambda e: len(e.location))
        matched.add(best.id)
    for entry in testable:
        bucket = scores[entry.cls]
        if entry.id in matched:
            bucket.found += 1
            bucket.found_ids.append(entry.id)
        else:
            bucket.missed += 1
            bucket.missed_ids.append(entry.id)
    return scores


# ── adapters ─────────────────────────────────────────────────────────


def findings_from_structured(directory: Path) -> list[Finding]:
    """Agent findings from ``findings/FIND-*.json`` (``emit_structured_finding``)."""
    out: list[Finding] = []
    for path in sorted(Path(directory).glob("FIND-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        title = str(data.get("title") or "")
        out.append(
            Finding(
                title=title,
                cls=classify(
                    cwe=data.get("cwe"), title=title, explicit=str(data.get("class") or "")
                ),
                endpoint=str(data.get("endpoint") or data.get("target") or ""),
                method=str(data.get("method") or ""),
                ref=path.name,
            )
        )
    return out


def _signal_matches(signal: dict[str, Any], record: dict[str, Any]) -> bool:
    if signal.get("type") and record.get("type") != signal["type"]:
        return False
    value = str(record.get("value") or "")
    if "value_contains" in signal and signal["value_contains"] not in value:
        return False
    if "value_regex" in signal and not re.search(signal["value_regex"], value):
        return False
    if "attr" in signal:
        actual = (record.get("attrs") or {}).get(signal["attr"])
        if "attr_equals" in signal and actual != signal["attr_equals"]:
            return False
    return True


def score_pipeline(records: list[dict[str, Any]], entries: list[Entry]) -> dict[str, ClassScore]:
    """What the deterministic pipeline surfaces on its own, with no agent.

    A ground-truth entry counts as found when a pipeline record matches one of
    its ``pipeline_signals``. Entries without signals are things only testing
    can show; they count as missed here by design. ``unmatched`` is the number
    of pipeline vulnerability/secret records that correspond to no entry.
    """
    scores: dict[str, ClassScore] = {}
    testable = [e for e in entries if not e.prohibited]
    credited: set[int] = set()
    for entry in testable:
        bucket = scores.setdefault(entry.cls, ClassScore())
        bucket.known += 1
        hit = False
        for index, record in enumerate(records):
            if any(_signal_matches(signal, record) for signal in entry.pipeline_signals):
                hit = True
                credited.add(index)
        if hit:
            bucket.found += 1
            bucket.found_ids.append(entry.id)
        else:
            bucket.missed += 1
            bucket.missed_ids.append(entry.id)
    for index, record in enumerate(records):
        if record.get("type") in ("vulnerability", "secret") and index not in credited:
            attrs = record.get("attrs") or {}
            title = str(attrs.get("name") or attrs.get("rule_id") or record.get("value") or "")
            cls = classify(
                cwe=(attrs.get("cwe") or [None])[0] if isinstance(attrs.get("cwe"), list) else None,
                title=title,
            )
            bucket = scores.setdefault(cls, ClassScore())
            bucket.unmatched += 1
            bucket.unmatched_titles.append(title[:120])
    return scores


def totals(scores: dict[str, ClassScore]) -> dict[str, int]:
    return {
        key: sum(getattr(s, key) for s in scores.values())
        for key in ("known", "found", "missed", "unmatched", "duplicates")
    }


__all__ = [
    "ClassScore",
    "Entry",
    "Finding",
    "available_apps",
    "findings_from_structured",
    "load_ground_truth",
    "score",
    "score_pipeline",
    "totals",
]
