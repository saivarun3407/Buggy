"""Fact / intent / hint board: append-only facts, claim leases, atomic conclusions,
completion and reopening, races between workers, and isolation between engagements."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from buggy.coordination import board as board_module
from buggy.coordination.board import (
    DB_FILENAME,
    DEFAULT_INTENT_TIMEOUT,
    MAX_FACT_CHARS,
    Board,
    BoardError,
    Closed,
    Conflict,
    NotClaimer,
    NotFound,
    normalise_intent_text,
)

ENG = "acme"


class Clock:
    """A clock the test sets; it does not move on its own."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def _open(tmp_path: Path, **kwargs: Any) -> Board:
    kwargs.setdefault("clock", Clock())
    return Board(tmp_path / DB_FILENAME, **kwargs)


def _raw(tmp_path: Path) -> sqlite3.Connection:
    """A second, independent connection to the board file (autocommit)."""
    return sqlite3.connect(tmp_path / DB_FILENAME, isolation_level=None, timeout=30)


def _count(tmp_path: Path, table: str) -> int:
    db = _raw(tmp_path)
    try:
        return int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608
    finally:
        db.close()


def _claimed_intent(board: Board, engagement: str = ENG, worker: str = "w1") -> str:
    """One fact, one intent from it, claimed by ``worker``. Returns the intent id."""
    fact = board.add_fact(engagement, "login form at /login", "recon")
    intent = board.open_intent(engagement, "test the login form for SQLi", [fact["id"]], "recon")
    board.claim(engagement, intent["id"], worker)
    return intent["id"]


# ── facts ───────────────────────────────────────────────────────────────


def test_fact_round_trip_and_ids_count_up(tmp_path: Path) -> None:
    board = _open(tmp_path)
    first = board.add_fact(
        ENG, "  admin panel at /admin  ", "agent:recon", evidence=["cap-1", "rec-9", "cap-1"]
    )
    second = board.add_fact(ENG, "the task: find access-control bugs", "operator", kind="origin")

    assert first["id"] == "f0001" and second["id"] == "f0002"
    assert first == {
        "id": "f0001",
        "engagement": ENG,
        "text": "admin panel at /admin",
        "kind": "observation",
        "evidence": ["cap-1", "rec-9"],
        "created_by": "agent:recon",
        "created_at": 1_000.0,
        "duplicate": False,
    }
    stored = board.get_fact(ENG, "f0001")
    assert stored == {key: value for key, value in first.items() if key != "duplicate"}
    assert [fact["id"] for fact in board.facts(ENG)] == ["f0001", "f0002"]
    assert [fact["id"] for fact in board.facts(ENG, kind="origin")] == ["f0002"]
    assert board.get_fact(ENG, "f0003") is None
    assert board.get_fact(ENG, "1") is None
    json.dumps(board.facts(ENG))  # JSON-serialisable


def test_duplicate_fact_text_returns_the_same_id_and_changes_nothing(tmp_path: Path) -> None:
    board = _open(tmp_path)
    first = board.add_fact(ENG, "JWT is signed with HS256", "agent:a", evidence=["cap-1"])
    again = board.add_fact(
        ENG, "JWT is signed with HS256", "agent:b", kind="result", evidence=["cap-2"]
    )
    different = board.add_fact(ENG, "JWT is signed with HS256.", "agent:b")  # not exact

    assert again["id"] == first["id"] == "f0001"
    assert again["duplicate"] is True and first["duplicate"] is False
    # The first fact is untouched by the repeat.
    assert again["kind"] == "observation"
    assert again["evidence"] == ["cap-1"]
    assert again["created_by"] == "agent:a"
    assert different["id"] == "f0002" and different["duplicate"] is False
    assert _count(tmp_path, "facts") == 2


def test_facts_are_append_only(tmp_path: Path) -> None:
    board = _open(tmp_path)
    board.add_fact(ENG, "an observation", "agent")

    # No call on the board changes or removes a fact...
    public = [name for name in dir(Board) if not name.startswith("_")]
    mutators = [
        name
        for name in public
        if "fact" in name and any(verb in name for verb in ("update", "delete", "remove", "edit"))
    ]
    assert mutators == []
    assert {"add_fact", "get_fact", "facts"} <= set(public)
    assert [name for name in public if "fact" in name] == ["add_fact", "facts", "get_fact"]

    # ...a returned fact is a copy...
    board.facts(ENG)[0]["text"] = "rewritten"
    assert board.get_fact(ENG, "f0001")["text"] == "an observation"

    # ...and the file itself refuses to rewrite or drop one, whoever asks.
    db = _raw(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("UPDATE facts SET text = 'rewritten'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM facts")
        # Negative control: the same connection can still append.
        db.execute(
            "INSERT INTO facts (engagement, n, text, kind, created_by, created_at) "
            "VALUES ('acme', 2, 'appended', 'observation', 'raw', 1.0)"
        )
    finally:
        db.close()
    assert [fact["text"] for fact in board.facts(ENG)] == ["an observation", "appended"]


def test_invalid_facts_are_refused(tmp_path: Path) -> None:
    board = _open(tmp_path)
    with pytest.raises(BoardError, match="longer than 500"):
        board.add_fact(ENG, "x" * (MAX_FACT_CHARS + 1), "agent")
    with pytest.raises(BoardError, match="required"):
        board.add_fact(ENG, "   ", "agent")
    with pytest.raises(BoardError, match="kind"):
        board.add_fact(ENG, "a fact", "agent", kind="rumour")
    with pytest.raises(BoardError, match="complete"):
        board.add_fact(ENG, "we are done", "agent", kind="goal")
    with pytest.raises(BoardError, match="created_by"):
        board.add_fact(ENG, "a fact", "")
    with pytest.raises(BoardError, match="engagement"):
        board.add_fact("../other", "a fact", "agent")
    with pytest.raises(BoardError, match="evidence"):
        board.add_fact(ENG, "a fact", "agent", evidence=["cap 1"])
    with pytest.raises(BoardError, match="evidence"):
        board.add_fact(ENG, "a fact", "agent", evidence=[7])  # type: ignore[list-item]
    assert _count(tmp_path, "facts") == 0
    # Negative control: the limit itself is accepted.
    assert board.add_fact(ENG, "x" * MAX_FACT_CHARS, "agent")["id"] == "f0001"


# ── intents ─────────────────────────────────────────────────────────────


def test_intent_must_reference_existing_facts(tmp_path: Path) -> None:
    board = _open(tmp_path)
    board.add_fact(ENG, "login form at /login", "recon")

    with pytest.raises(NotFound, match="f0002"):
        board.open_intent(ENG, "try SQLi", ["f0001", "f0002"], "recon")
    with pytest.raises(NotFound, match="i0001"):
        board.open_intent(ENG, "try SQLi", ["i0001"], "recon")
    with pytest.raises(BoardError, match="at least one"):
        board.open_intent(ENG, "try SQLi", [], "recon")
    with pytest.raises(BoardError, match="strings"):
        board.open_intent(ENG, "try SQLi", [1], "recon")  # type: ignore[list-item]
    assert board.intents(ENG) == []

    intent = board.open_intent(ENG, "try SQLi", ["f0001"], "recon")
    assert intent == {
        "id": "i0001",
        "engagement": ENG,
        "text": "try SQLi",
        "from_facts": ["f0001"],
        "to_fact": None,
        "creator": "recon",
        "worker": None,
        "last_heartbeat_at": None,
        "status": "open",
        "created_at": 1_000.0,
        "lease_expires_at": None,
        "expired": False,
        "duplicate": False,
    }
    json.dumps(intent)


def test_multi_source_intent_keeps_all_sources(tmp_path: Path) -> None:
    board = _open(tmp_path)
    for text in ("user ids are sequential", "GET /api/orders/{id} has no owner check", "c"):
        board.add_fact(ENG, text, "recon")

    intent = board.open_intent(ENG, "read another user's order", ["f0002", "f0001"], "planner")
    assert intent["from_facts"] == ["f0002", "f0001"]
    assert board.get_intent(ENG, intent["id"])["from_facts"] == ["f0002", "f0001"]
    assert board.snapshot(ENG)["intents"][0]["from_facts"] == ["f0002", "f0001"]

    # Sources survive the whole life of the intent.
    board.claim(ENG, intent["id"], "w1")
    done = board.conclude(ENG, intent["id"], "w1", "order 7 of bob readable as alice", ["cap-3"])
    assert done["intent"]["from_facts"] == ["f0002", "f0001"]


def test_near_duplicate_open_intent_returns_the_existing_one(tmp_path: Path) -> None:
    board = _open(tmp_path)
    board.add_fact(ENG, "login form at /login", "recon")
    board.add_fact(ENG, "search box at /search", "recon")

    first = board.open_intent(ENG, "Test the login form for SQLi", ["f0001", "f0002"], "a")
    same = board.open_intent(ENG, "  test the LOGIN form   for sqli. ", ["f0002", "f0001"], "b")
    assert same["id"] == first["id"] and same["duplicate"] is True
    assert same["creator"] == "a" and same["text"] == "Test the login form for SQLi"
    assert len(board.intents(ENG)) == 1

    # Negative controls: other text, or other sources, is other work.
    other_text = board.open_intent(ENG, "test the login form for XSS", ["f0001", "f0002"], "b")
    other_sources = board.open_intent(ENG, "test the login form for SQLi", ["f0001"], "b")
    assert other_text["id"] == "i0002" and other_text["duplicate"] is False
    assert other_sources["id"] == "i0003" and other_sources["duplicate"] is False

    # A claimed intent is still unfinished work: asking again returns it.
    board.claim(ENG, first["id"], "w1")
    assert (
        board.open_intent(ENG, "test the login form for sqli", ["f0001", "f0002"], "c")["id"]
        == (first["id"])
    )

    # Once it is finished, the same proposal is new work.
    board.conclude(ENG, first["id"], "w1", "login is not injectable")
    fresh = board.open_intent(ENG, "test the login form for sqli", ["f0001", "f0002"], "c")
    assert fresh["id"] == "i0004" and fresh["duplicate"] is False


def test_normalise_intent_text_keeps_meaningful_differences() -> None:
    assert normalise_intent_text("  Fuzz   /API/users. ") == "fuzz /api/users"
    assert normalise_intent_text("id > 1") != normalise_intent_text("id < 1")
    assert normalise_intent_text("/api/a") != normalise_intent_text("/api/b")


# ── claim / heartbeat / lease ───────────────────────────────────────────


def test_second_worker_conflicts_while_live_and_succeeds_after_expiry(tmp_path: Path) -> None:
    clock = Clock(1_000.0)
    board = _open(tmp_path, clock=clock)
    assert board.intent_timeout == DEFAULT_INTENT_TIMEOUT == 600.0
    board.add_fact(ENG, "login form at /login", "recon")
    intent_id = board.open_intent(ENG, "test login", ["f0001"], "recon")["id"]

    claimed = board.claim(ENG, intent_id, "w1")
    assert claimed["status"] == "claimed" and claimed["worker"] == "w1"
    assert claimed["last_heartbeat_at"] == 1_000.0
    assert claimed["lease_expires_at"] == 1_600.0 and claimed["expired"] is False

    clock.now = 1_599.9
    with pytest.raises(Conflict) as refused:
        board.claim(ENG, intent_id, "w2")
    assert refused.value.code == "conflict"
    assert refused.value.intent_id == intent_id
    assert refused.value.worker == "w1"
    assert refused.value.lease_expires_at == 1_600.0
    json.dumps(refused.value.to_dict())
    assert board.get_intent(ENG, intent_id)["worker"] == "w1"  # the refusal changed nothing

    clock.now = 1_600.0  # the lease has run out
    taken = board.claim(ENG, intent_id, "w2")
    assert taken["worker"] == "w2" and taken["last_heartbeat_at"] == 1_600.0

    # The worker that lost the intent cannot heartbeat its way back in.
    with pytest.raises(NotClaimer):
        board.heartbeat(ENG, intent_id, "w1")
    with pytest.raises(Conflict):
        board.claim(ENG, intent_id, "w1")


def test_now_argument_overrides_the_clock(tmp_path: Path) -> None:
    board = _open(tmp_path, clock=Clock(50.0), intent_timeout=10)
    board.add_fact(ENG, "a", "recon")
    intent_id = board.open_intent(ENG, "do a", ["f0001"], "recon")["id"]

    board.claim(ENG, intent_id, "w1", now=100.0)
    with pytest.raises(Conflict):
        board.claim(ENG, intent_id, "w2", 109.9)
    assert board.claim(ENG, intent_id, "w2", 110.0)["worker"] == "w2"
    with pytest.raises(BoardError, match="now"):
        board.claim(ENG, intent_id, "w2", float("nan"))


def test_heartbeat_and_reclaim_extend_the_lease(tmp_path: Path) -> None:
    clock = Clock(0.0)
    board = _open(tmp_path, clock=clock, intent_timeout=600)
    board.add_fact(ENG, "a", "recon")
    intent_id = board.open_intent(ENG, "do a", ["f0001"], "recon")["id"]
    board.claim(ENG, intent_id, "w1")

    clock.now = 500.0
    assert board.heartbeat(ENG, intent_id, "w1")["lease_expires_at"] == 1_100.0
    clock.now = 700.0  # past the first lease, inside the renewed one
    with pytest.raises(Conflict):
        board.claim(ENG, intent_id, "w2")

    clock.now = 1_000.0  # the same worker claiming again is a heartbeat
    again = board.claim(ENG, intent_id, "w1")
    assert again["worker"] == "w1" and again["lease_expires_at"] == 1_600.0
    clock.now = 1_599.0
    with pytest.raises(Conflict):
        board.claim(ENG, intent_id, "w2")
    clock.now = 1_600.0
    assert board.claim(ENG, intent_id, "w2")["worker"] == "w2"


def test_heartbeat_needs_a_claim_and_release_reopens(tmp_path: Path) -> None:
    board = _open(tmp_path)
    board.add_fact(ENG, "a", "recon")
    intent_id = board.open_intent(ENG, "do a", ["f0001"], "recon")["id"]

    with pytest.raises(NotClaimer, match="not claimed"):
        board.heartbeat(ENG, intent_id, "w1")
    with pytest.raises(NotFound):
        board.claim(ENG, "i0099", "w1")
    with pytest.raises(NotFound):
        board.claim(ENG, "f0001", "w1")

    board.claim(ENG, intent_id, "w1")
    with pytest.raises(NotClaimer):
        board.release(ENG, intent_id, "w2")
    assert board.get_intent(ENG, intent_id)["worker"] == "w1"

    released = board.release(ENG, intent_id, "w1")
    assert released["status"] == "open" and released["worker"] is None
    assert released["last_heartbeat_at"] is None
    assert board.claim(ENG, intent_id, "w2")["worker"] == "w2"  # no waiting for a lease


# ── conclude / abandon ──────────────────────────────────────────────────


def test_only_the_claimer_can_conclude(tmp_path: Path) -> None:
    board = _open(tmp_path)
    intent_id = _claimed_intent(board, worker="w1")

    with pytest.raises(NotClaimer, match="w2 does not hold it"):
        board.conclude(ENG, intent_id, "w2", "login is injectable", ["cap-1"])
    assert _count(tmp_path, "facts") == 1
    assert board.get_intent(ENG, intent_id)["status"] == "claimed"

    done = board.conclude(ENG, intent_id, "w1", "login is injectable via username", ["cap-1"])
    assert done["fact"]["id"] == "f0002"
    assert done["fact"]["kind"] == "result" and done["fact"]["created_by"] == "w1"
    assert done["fact"]["evidence"] == ["cap-1"] and done["fact"]["duplicate"] is False
    assert done["intent"]["status"] == "concluded"
    assert done["intent"]["to_fact"] == "f0002" and done["intent"]["worker"] == "w1"
    assert board.get_fact(ENG, "f0002")["text"] == "login is injectable via username"
    json.dumps(done)

    # A finished intent takes no further calls.
    for call in (
        lambda: board.conclude(ENG, intent_id, "w1", "again"),
        lambda: board.claim(ENG, intent_id, "w2"),
        lambda: board.heartbeat(ENG, intent_id, "w1"),
        lambda: board.release(ENG, intent_id, "w1"),
        lambda: board.abandon(ENG, intent_id, "w1", "changed my mind"),
    ):
        with pytest.raises(Closed):
            call()
    assert _count(tmp_path, "facts") == 2


def test_unclaimed_intent_cannot_be_concluded(tmp_path: Path) -> None:
    board = _open(tmp_path)
    board.add_fact(ENG, "a", "recon")
    intent_id = board.open_intent(ENG, "do a", ["f0001"], "recon")["id"]
    with pytest.raises(NotClaimer, match="not claimed"):
        board.conclude(ENG, intent_id, "recon", "done without claiming")
    assert _count(tmp_path, "facts") == 1
    assert board.get_intent(ENG, intent_id)["to_fact"] is None


def test_conclude_after_takeover_is_refused_but_expired_holder_may_finish(tmp_path: Path) -> None:
    clock = Clock(0.0)
    board = _open(tmp_path, clock=clock, intent_timeout=100)
    board.add_fact(ENG, "a", "recon")
    board.add_fact(ENG, "b", "recon")
    kept = board.open_intent(ENG, "do a", ["f0001"], "recon")["id"]
    lost = board.open_intent(ENG, "do b", ["f0002"], "recon")["id"]
    board.claim(ENG, kept, "w1")
    board.claim(ENG, lost, "w1")

    clock.now = 500.0  # both leases ran out; only one was taken over
    board.claim(ENG, lost, "w2")
    with pytest.raises(NotClaimer):
        board.conclude(ENG, lost, "w1", "b is done")
    assert board.conclude(ENG, kept, "w1", "a is done")["intent"]["status"] == "concluded"


def test_conclude_is_atomic_when_the_link_fails_after_the_fact_write(tmp_path: Path) -> None:
    board = _open(tmp_path)
    intent_id = _claimed_intent(board)  # f0001, i0001 claimed by w1
    db = _raw(tmp_path)
    # Fail the intent update. The message tells whether the new fact was already
    # written inside the transaction, i.e. that the failure sits between the two.
    db.execute(
        """
        CREATE TRIGGER fail_link BEFORE UPDATE ON intents WHEN NEW.status = 'concluded'
        BEGIN
            SELECT RAISE(ABORT, 'failed after the fact write')
             WHERE (SELECT COUNT(*) FROM facts WHERE engagement = NEW.engagement) = 2;
            SELECT RAISE(ABORT, 'failed before the fact write');
        END
        """
    )

    with pytest.raises(sqlite3.IntegrityError, match="failed after the fact write"):
        board.conclude(ENG, intent_id, "w1", "login is injectable", ["cap-1"])

    # Neither half is stored, as seen by the board and by another connection.
    assert [fact["id"] for fact in board.facts(ENG)] == ["f0001"]
    assert db.execute("SELECT COUNT(*) FROM facts").fetchone()[0] == 1
    intent = board.get_intent(ENG, intent_id)
    assert intent["status"] == "claimed" and intent["to_fact"] is None
    assert intent["worker"] == "w1"

    # Negative control: without the fault the same call stores both, and the
    # failed attempt did not burn the fact id.
    db.execute("DROP TRIGGER fail_link")
    db.close()
    done = board.conclude(ENG, intent_id, "w1", "login is injectable", ["cap-1"])
    assert done["fact"]["id"] == "f0002" and done["intent"]["to_fact"] == "f0002"
    assert _count(tmp_path, "facts") == 2


def test_conclude_is_atomic_when_the_fact_write_fails(tmp_path: Path) -> None:
    board = _open(tmp_path)
    intent_id = _claimed_intent(board)
    db = _raw(tmp_path)
    db.execute(
        "CREATE TRIGGER fail_fact BEFORE INSERT ON facts WHEN NEW.kind = 'result' "
        "BEGIN SELECT RAISE(ABORT, 'fact write failed'); END"
    )
    db.close()

    with pytest.raises(sqlite3.IntegrityError, match="fact write failed"):
        board.conclude(ENG, intent_id, "w1", "login is injectable")
    with pytest.raises(sqlite3.IntegrityError, match="fact write failed"):
        board.abandon(ENG, intent_id, "w1", "no injection point")

    intent = board.get_intent(ENG, intent_id)
    assert intent["status"] == "claimed" and intent["to_fact"] is None
    assert _count(tmp_path, "facts") == 1
    # The board still works after the rolled-back calls.
    assert board.add_fact(ENG, "another observation", "recon")["id"] == "f0002"


def test_conclude_with_existing_fact_text_links_to_that_fact(tmp_path: Path) -> None:
    board = _open(tmp_path)
    intent_id = _claimed_intent(board)
    known = board.add_fact(ENG, "login is not injectable", "agent:a", evidence=["cap-1"])

    done = board.conclude(ENG, intent_id, "w1", "login is not injectable", ["cap-2"])
    assert done["fact"]["id"] == known["id"] and done["fact"]["duplicate"] is True
    assert done["intent"]["to_fact"] == known["id"]
    assert board.get_fact(ENG, known["id"])["evidence"] == ["cap-1"]  # the fact is unchanged
    assert _count(tmp_path, "facts") == 2


def test_abandon_remembers_the_dead_end(tmp_path: Path) -> None:
    clock = Clock(0.0)
    board = _open(tmp_path, clock=clock, intent_timeout=100)
    for text in ("a", "b", "c"):
        board.add_fact(ENG, text, "recon")
    held = board.open_intent(ENG, "do a", ["f0001"], "recon")["id"]
    unclaimed = board.open_intent(ENG, "do b", ["f0002"], "recon")["id"]
    board.claim(ENG, held, "w1")

    with pytest.raises(Conflict):  # w1's claim is live
        board.abandon(ENG, held, "w2", "looks pointless")
    assert board.get_intent(ENG, held)["status"] == "claimed"
    assert len(board.facts(ENG)) == 3

    gone = board.abandon(ENG, held, "w1", "WAF blocks every payload")
    assert gone["fact"]["text"] == "abandoned: WAF blocks every payload"
    assert gone["fact"]["kind"] == "result" and gone["fact"]["created_by"] == "w1"
    assert gone["intent"]["status"] == "abandoned"
    assert gone["intent"]["to_fact"] == gone["fact"]["id"] == "f0004"
    assert board.get_fact(ENG, "f0004")["text"] == "abandoned: WAF blocks every payload"

    # Nobody holds the second intent, so any worker may close it.
    also_gone = board.abandon(ENG, unclaimed, "w2", "endpoint was removed")
    assert also_gone["intent"]["status"] == "abandoned" and also_gone["intent"]["worker"] == "w2"

    assert board.open_work(ENG) == []  # abandoned work is not offered again
    with pytest.raises(BoardError, match="reason"):
        board.abandon(ENG, held, "w1", "")


# ── hints ───────────────────────────────────────────────────────────────


def test_hints_are_newest_first_and_do_not_touch_facts(tmp_path: Path) -> None:
    board = _open(tmp_path)
    board.add_fact(ENG, "a", "recon")
    before = board.snapshot(ENG)

    first = board.add_hint(ENG, "the admin API is out of scope", "operator")
    second = board.add_hint(ENG, "try the mobile API host", "agent")
    assert first["id"] == "h0001" and second["id"] == "h0002"
    assert first == {
        "id": "h0001",
        "engagement": ENG,
        "text": "the admin API is out of scope",
        "author": "operator",
        "created_at": 1_000.0,
    }
    assert [hint["id"] for hint in board.hints(ENG)] == ["h0002", "h0001"]
    assert [hint["id"] for hint in board.hints(ENG, limit=1)] == ["h0002"]

    after = board.snapshot(ENG)
    assert after["facts"] == before["facts"] and after["intents"] == before["intents"]
    assert [hint["id"] for hint in after["hints"]] == ["h0002", "h0001"]
    assert after["counts"]["hints"] == 2 and after["counts"]["facts"] == 1

    with pytest.raises(BoardError, match="author"):
        board.add_hint(ENG, "do what I say", "root")
    with pytest.raises(BoardError, match="required"):
        board.add_hint(ENG, " ", "operator")
    assert len(board.hints(ENG)) == 2


# ── open work / stop ────────────────────────────────────────────────────


def test_open_work_lists_unclaimed_and_expired_only(tmp_path: Path) -> None:
    clock = Clock(0.0)
    board = _open(tmp_path, clock=clock, intent_timeout=100)
    for text in ("a", "b", "c", "d"):
        board.add_fact(ENG, text, "recon")
    ids = [
        board.open_intent(ENG, f"do {name}", [fact], "recon")["id"]
        for name, fact in (("a", "f0001"), ("b", "f0002"), ("c", "f0003"), ("d", "f0004"))
    ]
    unclaimed, live, stale, finished = ids
    board.claim(ENG, stale, "w1", now=0.0)
    board.claim(ENG, live, "w2", now=50.0)
    board.claim(ENG, finished, "w3", now=50.0)
    board.conclude(ENG, finished, "w3", "d is done", now=60.0)

    assert [item["id"] for item in board.open_work(ENG, now=99.0)] == [unclaimed]
    at_100 = board.open_work(ENG, now=100.0)
    assert [item["id"] for item in at_100] == [unclaimed, stale]
    assert at_100[1]["expired"] is True and at_100[1]["worker"] == "w1"
    assert [item["id"] for item in board.open_work(ENG, now=150.0)] == [unclaimed, live, stale]
    # Listing is a read: the stale claim is still recorded until someone takes it.
    assert board.get_intent(ENG, stale, now=150.0)["status"] == "claimed"


def test_stop_clears_claims_and_open_work_lists_them(tmp_path: Path) -> None:
    board = _open(tmp_path)
    for text in ("a", "b", "c"):
        board.add_fact(ENG, text, "recon")
    first = board.open_intent(ENG, "do a", ["f0001"], "recon")["id"]
    second = board.open_intent(ENG, "do b", ["f0002"], "recon")["id"]
    finished = board.open_intent(ENG, "do c", ["f0003"], "recon")["id"]
    board.claim(ENG, first, "w1")
    board.claim(ENG, second, "w2")
    board.claim(ENG, finished, "w3")
    board.conclude(ENG, finished, "w3", "c is done")

    assert board.open_work(ENG) == []  # everything unfinished is held
    with pytest.raises(Conflict):
        board.claim(ENG, first, "w9")

    stopped = board.stop(ENG)
    assert stopped == {"engagement": ENG, "released": [first, second]}

    work = board.open_work(ENG)
    assert [item["id"] for item in work] == [first, second]
    assert all(item["status"] == "open" and item["worker"] is None for item in work)
    assert board.claim(ENG, first, "w9")["worker"] == "w9"  # no lease to wait out
    with pytest.raises(NotClaimer):
        board.heartbeat(ENG, second, "w2")  # the old claim is gone
    # Finished work is not reopened by a stop.
    concluded = board.get_intent(ENG, finished)
    assert concluded["status"] == "concluded" and concluded["worker"] == "w3"
    assert board.stop(ENG)["released"] == [first]  # only w9's new claim was left


# ── complete / reopen ───────────────────────────────────────────────────


def test_complete_then_reopen_then_complete_again(tmp_path: Path) -> None:
    board = _open(tmp_path)
    board.add_fact(ENG, "find an account takeover", "operator", kind="origin")
    board.add_fact(ENG, "password reset token is predictable", "w1", kind="result")
    assert board.snapshot(ENG)["complete"] is False

    with pytest.raises(NotFound):  # a completion must rest on facts that exist
        board.complete(ENG, "w1", ["f0009"], "took over bob's account")
    with pytest.raises(BoardError, match="at least one"):
        board.complete(ENG, "w1", [], "took over bob's account")
    with pytest.raises(BoardError, match="own summary"):
        board.complete(ENG, "w1", ["f0001"], "password reset token is predictable")
    with pytest.raises(BoardError, match="nothing to reopen"):
        board.reopen(ENG, "not done")
    untouched = board.snapshot(ENG)
    assert untouched["complete"] is False and untouched["counts"]["facts"] == 2
    assert untouched["intents"] == []

    done = board.complete(
        ENG, "w1", ["f0001", "f0002"], "took over bob's account", evidence=["cap-7"]
    )
    assert done["fact"]["id"] == "f0003" and done["fact"]["kind"] == "goal"
    assert done["fact"]["text"] == "took over bob's account"
    assert done["fact"]["evidence"] == ["cap-7"]
    assert done["intent"]["status"] == "concluded" and done["intent"]["to_fact"] == "f0003"
    assert done["intent"]["from_facts"] == ["f0001", "f0002"]
    assert done["intent"]["worker"] == "w1" and done["intent"]["creator"] == "w1"
    snap = board.snapshot(ENG)
    assert snap["complete"] is True and snap["goal_fact"] == "f0003"
    assert snap["goal_intent"] == done["intent"]["id"]
    assert snap["counts"]["facts_by_kind"]["goal"] == 1
    assert snap["counts"]["open_work"] == 0

    with pytest.raises(Closed, match="already complete"):
        board.complete(ENG, "w2", ["f0001"], "also done, differently")
    assert board.snapshot(ENG)["counts"]["facts"] == 3

    # The verifier overturns the completion.
    reopened = board.reopen(ENG, "the reset token only worked for the tester's own account")
    assert reopened["complete"] is False and reopened["overturned_goal"] == "f0003"
    assert reopened["fact"]["id"] == "f0004"
    assert reopened["fact"]["text"] == (
        "reopened: the reset token only worked for the tester's own account"
    )
    assert reopened["fact"]["created_by"] == "verifier"
    assert reopened["intent"]["status"] == "open"
    assert reopened["intent"]["from_facts"] == ["f0003", "f0004"]

    snap = board.snapshot(ENG)
    assert snap["complete"] is False and snap["goal_fact"] is None and snap["reopened"] == 1
    # The overturned goal is still on the board; nothing was erased.
    assert [fact["id"] for fact in snap["facts"]] == ["f0001", "f0002", "f0003", "f0004"]
    assert board.get_fact(ENG, "f0003")["kind"] == "goal"
    assert [item["id"] for item in board.open_work(ENG)] == [reopened["intent"]["id"]]
    with pytest.raises(BoardError, match="nothing to reopen"):
        board.reopen(ENG, "again")

    # The rework is claimed and concluded like any other intent, then completed anew.
    board.claim(ENG, reopened["intent"]["id"], "w2")
    fixed = board.conclude(ENG, reopened["intent"]["id"], "w2", "token of bob predicted", ["cap-9"])
    second = board.complete(ENG, "w2", [fixed["fact"]["id"]], "took over bob's account for real")
    snap = board.snapshot(ENG)
    assert snap["complete"] is True and snap["goal_fact"] == second["fact"]["id"] == "f0006"
    assert snap["reopened"] == 1
    assert snap["counts"]["facts_by_kind"] == {
        "observation": 1,
        "result": 2,
        "origin": 1,
        "goal": 2,
    }


def test_snapshot_reports_the_board_and_counts(tmp_path: Path) -> None:
    clock = Clock(0.0)
    board = _open(tmp_path, clock=clock, intent_timeout=100)
    empty = board.snapshot(ENG)
    assert empty["facts"] == [] and empty["intents"] == [] and empty["hints"] == []
    assert empty["complete"] is False and empty["counts"]["open_work"] == 0

    for text in ("a", "b", "c"):
        board.add_fact(ENG, text, "recon")
    open_id = board.open_intent(ENG, "do a", ["f0001"], "recon")["id"]
    claimed_id = board.open_intent(ENG, "do b", ["f0002"], "recon")["id"]
    done_id = board.open_intent(ENG, "do c", ["f0003"], "recon")["id"]
    board.claim(ENG, claimed_id, "w1")
    board.claim(ENG, done_id, "w2")
    board.conclude(ENG, done_id, "w2", "c is done")
    board.add_hint(ENG, "mind the rate limit", "operator")

    snap = board.snapshot(ENG, now=10.0)
    json.dumps(snap)
    assert [fact["id"] for fact in snap["facts"]] == ["f0001", "f0002", "f0003", "f0004"]
    assert [intent["id"] for intent in snap["intents"]] == [open_id, claimed_id, done_id]
    assert snap["counts"] == {
        "facts": 4,
        "facts_by_kind": {"observation": 3, "result": 1, "origin": 0, "goal": 0},
        "intents": 3,
        "intents_by_status": {"open": 1, "claimed": 1, "concluded": 1, "abandoned": 0},
        "open_work": 1,
        "hints": 1,
    }
    assert board.snapshot(ENG, now=100.0)["counts"]["open_work"] == 2  # w1's lease ran out
    assert [item["id"] for item in board.intents(ENG, status="claimed")] == [claimed_id]


def test_board_survives_reopening_the_file(tmp_path: Path) -> None:
    board = _open(tmp_path)
    intent_id = _claimed_intent(board)
    board.close()

    again = _open(tmp_path)
    assert again.get_intent(ENG, intent_id)["worker"] == "w1"
    assert again.add_fact(ENG, "next fact", "recon")["id"] == "f0002"
    with pytest.raises(Conflict):
        again.claim(ENG, intent_id, "w2")


# ── concurrency ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("own_connection", [False, True], ids=["one-board", "board-per-worker"])
def test_eight_workers_race_for_one_intent_and_exactly_one_wins(
    tmp_path: Path, own_connection: bool
) -> None:
    shared = _open(tmp_path)
    shared.add_fact(ENG, "login form at /login", "recon")
    intent_id = shared.open_intent(ENG, "test login", ["f0001"], "recon")["id"]
    workers = [f"w{index}" for index in range(8)]
    boards = {
        worker: (_open(tmp_path, clock=Clock()) if own_connection else shared) for worker in workers
    }
    start = threading.Barrier(len(workers))
    won: list[str] = []
    lost: list[str] = []
    errors: list[BaseException] = []
    guard = threading.Lock()

    def race(worker: str) -> None:
        try:
            start.wait(timeout=10)
            boards[worker].claim(ENG, intent_id, worker)
        except Conflict as conflict:
            with guard:
                lost.append(conflict.worker)
        except BaseException as error:  # noqa: BLE001 - reported below
            with guard:
                errors.append(error)
        else:
            with guard:
                won.append(worker)

    threads = [threading.Thread(target=race, args=(worker,)) for worker in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == []
    assert len(won) == 1
    assert len(lost) == 7
    assert set(lost) == {won[0]}  # every loser was told who holds it
    assert shared.get_intent(ENG, intent_id)["worker"] == won[0]


def test_concurrent_fact_writers_get_distinct_ids_and_one_per_text(tmp_path: Path) -> None:
    boards = [_open(tmp_path) for _ in range(8)]
    start = threading.Barrier(len(boards))
    ids: list[tuple[str, str]] = []
    errors: list[BaseException] = []
    guard = threading.Lock()

    def write(index: int) -> None:
        try:
            start.wait(timeout=10)
            own = boards[index].add_fact(ENG, f"observation {index}", f"w{index}")
            same = boards[index].add_fact(ENG, "everyone saw this", f"w{index}")
            with guard:
                ids.append((own["id"], same["id"]))
        except BaseException as error:  # noqa: BLE001 - reported below
            with guard:
                errors.append(error)

    threads = [threading.Thread(target=write, args=(index,)) for index in range(len(boards))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == []
    assert len({own for own, _ in ids}) == 8  # no id was handed out twice
    assert len({same for _, same in ids}) == 1  # the shared text is one fact
    facts = boards[0].facts(ENG)
    assert [fact["id"] for fact in facts] == [f"f{n:04d}" for n in range(1, 10)]


# ── engagement isolation ────────────────────────────────────────────────


def test_ids_and_reads_never_cross_engagements(tmp_path: Path) -> None:
    board = _open(tmp_path)
    a_fact = board.add_fact("acme", "acme: login form at /login", "recon")
    a_extra = board.add_fact("acme", "acme: admin panel at /admin", "recon")
    b_fact = board.add_fact("globex", "globex: GraphQL endpoint at /graphql", "recon")
    same_text_a = board.add_fact("acme", "shared wording", "recon")
    same_text_b = board.add_fact("globex", "shared wording", "recon")

    # Ids are numbered per engagement.
    assert a_fact["id"] == b_fact["id"] == "f0001"
    assert a_extra["id"] == "f0002" and same_text_a["id"] == "f0003"
    assert same_text_b["id"] == "f0002" and same_text_b["duplicate"] is False

    # The same id reads a different fact in each engagement.
    assert board.get_fact("acme", "f0001")["text"] == "acme: login form at /login"
    assert board.get_fact("globex", "f0001")["text"] == "globex: GraphQL endpoint at /graphql"
    assert board.get_fact("globex", "f0003") is None  # exists only in acme
    assert board.get_fact("initech", "f0001") is None

    # An intent cannot be built on another engagement's fact.
    with pytest.raises(NotFound, match="f0003"):
        board.open_intent("globex", "use acme's fact", ["f0003"], "recon")

    a_intent = board.open_intent("acme", "test the endpoint", ["f0001"], "recon")
    b_intent = board.open_intent("globex", "test the endpoint", ["f0001"], "recon")
    assert a_intent["id"] == b_intent["id"] == "i0001"
    assert b_intent["duplicate"] is False  # same words and ids, different engagement

    # A claim, a stop and a completion in one engagement leave the other alone.
    board.claim("acme", "i0001", "w1")
    assert board.claim("globex", "i0001", "w2")["worker"] == "w2"
    assert board.get_intent("acme", "i0001")["worker"] == "w1"
    board.stop("acme")
    assert board.get_intent("acme", "i0001")["status"] == "open"
    assert board.get_intent("globex", "i0001")["worker"] == "w2"
    assert board.open_work("globex") == []

    board.add_hint("acme", "acme only hint", "operator")
    board.complete("acme", "w1", ["f0001"], "acme is done")
    done = board.conclude("globex", "i0001", "w2", "globex: introspection is on")
    assert done["fact"]["id"] == "f0003"

    acme = board.snapshot("acme")
    globex = board.snapshot("globex")
    assert acme["complete"] is True and globex["complete"] is False
    assert {fact["engagement"] for fact in acme["facts"]} == {"acme"}
    assert {fact["engagement"] for fact in globex["facts"]} == {"globex"}
    assert {intent["engagement"] for intent in acme["intents"]} == {"acme"}
    assert {intent["engagement"] for intent in globex["intents"]} == {"globex"}
    assert [hint["id"] for hint in acme["hints"]] == ["h0001"] and globex["hints"] == []
    assert not any("globex" in fact["text"] for fact in acme["facts"])
    assert not any("acme" in json.dumps(item) for item in globex["facts"] + globex["intents"])
    assert board.facts("initech") == [] and board.snapshot("initech")["counts"]["facts"] == 0
    with pytest.raises(BoardError, match="nothing to reopen"):
        board.reopen("globex", "acme's completion is not globex's")


# ── module boundaries ───────────────────────────────────────────────────


def test_module_is_standard_library_only() -> None:
    source = Path(board_module.__file__).read_text(encoding="utf-8")
    imported = {
        line.split()[1].split(".")[0]
        for line in source.splitlines()
        if line.startswith(("import ", "from "))
    }
    assert imported <= {
        "__future__",
        "collections",
        "contextlib",
        "dataclasses",
        "json",
        "math",
        "pathlib",
        "re",
        "sqlite3",
        "threading",
        "time",
        "typing",
        "unicodedata",
    }
    assert "journal_mode" not in source  # rollback journal: the SQLite default is kept


def test_board_file_uses_the_rollback_journal(tmp_path: Path) -> None:
    board = _open(tmp_path)
    board.add_fact(ENG, "a", "recon")
    db = _raw(tmp_path)
    try:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    finally:
        db.close()
    assert (tmp_path / DB_FILENAME).is_file()
