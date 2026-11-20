"""Coordination between workers through shared state instead of messages.

``board`` is a small SQLite store of append-only facts, intents that workers
claim with a heartbeat lease, and hints. Workers read the board, claim an
intent, and write what they found back as a fact.

Standard library only; no model or agent library is imported here.
"""

from buggy.coordination.board import (
    ABANDONED_PREFIX,
    DB_FILENAME,
    DEFAULT_INTENT_TIMEOUT,
    FACT_KINDS,
    HINT_AUTHORS,
    INTENT_STATUSES,
    MAX_FACT_CHARS,
    MAX_HINT_CHARS,
    MAX_INTENT_CHARS,
    REOPENED_PREFIX,
    Board,
    BoardError,
    Closed,
    Conflict,
    Fact,
    Hint,
    Intent,
    NotClaimer,
    NotFound,
    normalise_intent_text,
)

__all__ = [
    "ABANDONED_PREFIX",
    "DB_FILENAME",
    "DEFAULT_INTENT_TIMEOUT",
    "FACT_KINDS",
    "HINT_AUTHORS",
    "INTENT_STATUSES",
    "MAX_FACT_CHARS",
    "MAX_HINT_CHARS",
    "MAX_INTENT_CHARS",
    "REOPENED_PREFIX",
    "Board",
    "BoardError",
    "Closed",
    "Conflict",
    "Fact",
    "Hint",
    "Intent",
    "NotClaimer",
    "NotFound",
    "normalise_intent_text",
]
