"""Opt-in subdomain guessing: names no passive source lists, resolved through dnsx.

Off by default. A program turns it on with ``pipeline.subdomain_guess: true``
(it is DNS brute force, which some programs ban). Two kinds of names:

* common labels (``data/subdomain_words.txt``) under each enumeration root;
* permutations of the hosts already found: ``api`` gives ``api-dev``,
  ``dev-api``, ``api2``; ``app1`` gives ``app2`` (the altdns / dnsgen idea).

Every name must pass the scope filter before it is resolved. Two made-up
labels are resolved with the batch: names that answer only with the
addresses those made-up names get are a wildcard's echo and are dropped.
Pure code: resolving is a callback.
"""

from __future__ import annotations

import re
import secrets
import string
from collections.abc import Callable, Iterable
from pathlib import Path

NAME = "subdomain_guess"
DATA = Path(__file__).with_name("data")
#: Names guessed per enumeration root.
MAX_GUESSES = 1500
#: Words a found label is combined with.
MUTATIONS = (
    "dev", "staging", "stage", "test", "qa", "uat", "prod", "beta", "internal", "admin",
    "api", "v2", "old", "new", "demo", "preprod", "sandbox",
)  # fmt: skip
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMBER = re.compile(r"^(.*?)(\d+)$")


def words() -> list[str]:
    try:
        text = (DATA / "subdomain_words.txt").read_text(encoding="utf-8")
    except OSError:
        return []
    return [w.strip().lower() for w in text.splitlines() if w.strip() and not w.startswith("#")]


def _first_labels(root: str, hosts: Iterable[str]) -> list[str]:
    labels: list[str] = []
    for host in hosts:
        host = host.lower().rstrip(".")
        if host.endswith("." + root):
            labels.append(host[: -len(root) - 1].split(".")[0])
    return list(dict.fromkeys(label for label in labels if _LABEL.match(label)))


def permutations(label: str) -> list[str]:
    """``api`` -> ``api-dev``, ``dev-api``, ``apidev``, ``api2``; ``app1`` -> ``app2``, ``app0``."""
    out = []
    for word in MUTATIONS:
        if word != label:
            out += [f"{label}-{word}", f"{word}-{label}", f"{label}{word}"]
    number = _NUMBER.match(label)
    if number:
        head, digits = number.group(1), int(number.group(2))
        out += [f"{head}{n}" for n in (digits - 1, digits + 1, digits + 2) if n >= 0]
    else:
        out += [f"{label}2", f"{label}1"]
    return out


def candidates(
    root: str,
    known: Iterable[str],
    *,
    allowed: Callable[[str], bool],
    limit: int = MAX_GUESSES,
) -> list[str]:
    """Names to try under ``root``: permutations of found labels first, then common
    labels. Known hosts and names ``allowed`` refuses are left out."""
    ordered = list(dict.fromkeys(h.lower().rstrip(".") for h in known))
    known_set = set(ordered)
    labels = _first_labels(root, ordered)
    tried = [p for label in labels for p in permutations(label)] + words()
    out: list[str] = []
    for label in dict.fromkeys(tried):
        if not _LABEL.match(label):
            continue
        name = f"{label}.{root}"
        if name in known_set or not allowed(name):
            continue
        out.append(name)
        if len(out) >= limit:
            break
    return out


def canaries(root: str) -> list[str]:
    """Two made-up names under ``root``: what a wildcard answers for any name."""
    alphabet = string.ascii_lowercase + string.digits
    return [
        "zz" + "".join(secrets.choice(alphabet) for _ in range(14)) + "." + root for _ in range(2)
    ]


def keep(answers: dict[str, set[str]], probes: Iterable[str]) -> list[str]:
    """Names that resolved to something a made-up name did not resolve to."""
    probes = list(probes)
    echo: set[str] = set()
    for probe in probes:
        echo |= answers.get(probe, set())
    return sorted(
        name
        for name, addresses in answers.items()
        if name not in probes and addresses and not addresses <= echo
    )


__all__ = ["MAX_GUESSES", "NAME", "candidates", "canaries", "keep", "permutations", "words"]
