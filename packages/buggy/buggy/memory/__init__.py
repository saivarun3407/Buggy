"""Memory that outlives an engagement.

``lessons`` is a small SQLite store of technique notes (what worked, what
failed, payloads) shared across engagements. Lessons are scrubbed of
credentials and target hostnames before they are written, and only a lesson
tied to a verified finding is trusted.

Standard library only; no model or agent library is imported here.
"""

from buggy.memory.lessons import (
    DB_FILENAME,
    KINDS,
    MAX_BODY_CHARS,
    MAX_LESSONS,
    UNVERIFIED,
    VERIFIED,
    Lesson,
    LessonError,
    LessonStore,
    fts5_available,
    scope_hosts_from_document,
    scrub,
)

__all__ = [
    "DB_FILENAME",
    "KINDS",
    "MAX_BODY_CHARS",
    "MAX_LESSONS",
    "UNVERIFIED",
    "VERIFIED",
    "Lesson",
    "LessonError",
    "LessonStore",
    "fts5_available",
    "scope_hosts_from_document",
    "scrub",
]
