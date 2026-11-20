"""Wildcard DNS: tell names that are real from names a wildcard record answers.

A zone with ``*.acme.test`` answers for *every* name under it, so each
subdomain an enumerator guessed or found in an old certificate "resolves" and
would be stored, probed and crawled as if it were a host. The check is the
usual one: resolve a few random names that cannot exist. If all of them come
back with the same non-empty address set, the zone is a wildcard zone and that
set is what a made-up name looks like; a name is kept only when it looks
different, is the root itself, or was named by the operator.

Everything here is a pure function over ``resolve(names) -> {name: addresses}``;
the pipeline passes its own DNS path (dnsx) in. No network code, no model call.
"""

from __future__ import annotations

import secrets
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

#: Reason written to the scope-drop log for a name dropped by :func:`filter_names`.
REASON = "wildcard_dns"

PROBE_COUNT = 3
LABEL_LENGTH = 16
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

#: ``resolve(names) -> {name: addresses}``; a name with no answer may be absent.
Resolve = Callable[[list[str]], Mapping[str, Collection[str]]]


@dataclass(frozen=True, slots=True)
class WildcardInfo:
    """What the random probes said about one root."""

    root: str
    is_wildcard: bool
    addresses: frozenset[str] = frozenset()  # what a made-up name resolves to


def probe_names(root: str, n: int = PROBE_COUNT, rng: Any = secrets) -> list[str]:
    """``n`` distinct random 16-character labels under ``root``.

    ``rng`` only needs ``choice``: the ``secrets`` module by default, a seeded
    ``random.Random`` where the names must be reproducible.
    """
    names: list[str] = []
    while len(names) < n:
        label = "".join(rng.choice(_ALPHABET) for _ in range(LABEL_LENGTH))
        name = f"{label}.{root}"
        if name not in names:
            names.append(name)
    return names


def detect(
    root: str, resolve: Resolve, *, n: int = PROBE_COUNT, rng: Any = secrets
) -> WildcardInfo:
    """Probe ``root`` with ``n`` random names.

    Wildcard means: every probe resolved, and all to the same address set.
    Anything else is "not a wildcard" — including probes that resolve to sets
    that differ from one another (a wildcard behind rotating addresses). With
    no single set to compare against, no name could be told apart from a
    made-up one, so nothing is dropped rather than something real.
    """
    names = probe_names(root, n, rng)
    answers = resolve(names)
    seen = {frozenset(answers.get(name) or ()) for name in names}
    if len(seen) == 1:
        (addresses,) = seen
        if addresses:
            return WildcardInfo(root, True, addresses)
    return WildcardInfo(root, False)


def _under(name: str, root: str) -> bool:
    return name.endswith("." + root)


def filter_names(
    names: Iterable[str],
    info: WildcardInfo,
    resolved: Mapping[str, Collection[str]],
    explicit: Collection[str] = (),
) -> tuple[list[str], list[str]]:
    """Split ``names`` into ``(kept, dropped)``, both in the order given.

    Under a wildcard zone a name is dropped only when its address set equals
    the wildcard's. Kept regardless: the root itself, names outside the root,
    and names in ``explicit`` (hosts the scope or the seed URLs name outright).
    Outside a wildcard zone everything is kept.
    """
    kept: list[str] = []
    dropped: list[str] = []
    for name in names:
        if (
            info.is_wildcard
            and _under(name, info.root)
            and name not in explicit
            and frozenset(resolved.get(name) or ()) == info.addresses
        ):
            dropped.append(name)
        else:
            kept.append(name)
    return kept, dropped


def suspected(
    names: Iterable[str],
    root: str,
    resolved: Mapping[str, Collection[str]],
    explicit: Collection[str] = (),
) -> bool:
    """Whether the answers under ``root`` are worth a wildcard probe.

    True when a name :func:`filter_names` could drop shares its address set
    with at least one other name: a wildcard gives every made-up name the same
    answer, so a flood always looks like this. A zone where every name has its
    own addresses is left alone and costs no probe queries. The price: a
    single wildcard-only name with no twin in the same batch is not caught.
    """
    sets = {name: frozenset(resolved.get(name) or ()) for name in names}
    shared = Counter(addresses for addresses in sets.values() if addresses)
    return any(
        shared[addresses] > 1 and _under(name, root) and name not in explicit
        for name, addresses in sets.items()
    )


__all__ = [
    "LABEL_LENGTH",
    "PROBE_COUNT",
    "REASON",
    "WildcardInfo",
    "detect",
    "filter_names",
    "probe_names",
    "suspected",
]
