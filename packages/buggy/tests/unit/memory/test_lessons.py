"""Lessons store: round trip, ranking, trust, scrubbing, limits and the LIKE fallback."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from buggy.memory import lessons as lessons_module
from buggy.memory.lessons import (
    DB_FILENAME,
    MAX_BODY_CHARS,
    Lesson,
    LessonError,
    LessonStore,
    fts5_available,
    scope_hosts_from_document,
    scrub,
)


def _must[T](value: T | None) -> T:
    """``value``, asserted present."""
    assert value is not None
    return value


class Clock:
    """A clock the test moves; every reading is later than the one before."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


def _open(tmp_path: Path, **kwargs: Any) -> LessonStore:
    kwargs.setdefault("clock", Clock())
    return LessonStore(tmp_path / DB_FILENAME, **kwargs)


def _lesson(title: str, body: str = "", **fields: Any) -> dict[str, Any]:
    return {
        "kind": "guide",
        "title": title,
        "body": body or f"Technique notes for {title}.",
        **fields,
    }


def _files_bytes(directory: Path) -> bytes:
    """Every byte SQLite left in the directory (database, journal, WAL)."""
    return b"\n".join(path.read_bytes() for path in sorted(directory.iterdir()) if path.is_file())


# ── round trip ──────────────────────────────────────────────────────────


def test_save_then_get_and_search_round_trip(tmp_path: Path) -> None:
    store = _open(tmp_path)
    lesson_id = store.save(
        {
            "kind": "guide",
            "title": "GraphQL introspection maps the schema",
            "body": "Send the __schema query first; field names reveal admin mutations.",
            "classes": ["GraphQL", "info_exposure"],
            "technologies": ["GraphQL", " Express "],
            "source_engagement": "juice",
            "finding_id": "F-0123456789ab",
        },
        "agent:recon",
        verified_finding=True,
    )

    stored = store.get(lesson_id)
    assert stored is not None
    assert stored["id"] == lesson_id and lesson_id.startswith("L-")
    assert stored["kind"] == "guide"
    assert stored["title"] == "GraphQL introspection maps the schema"
    assert stored["body"] == "Send the __schema query first; field names reveal admin mutations."
    assert stored["classes"] == ["graphql", "info_exposure"]
    assert stored["technologies"] == ["graphql", "express"]
    assert stored["source_engagement"] == "juice"
    assert stored["finding_id"] == "F-0123456789ab"
    assert stored["trust"] == "verified"
    assert stored["saved_by"] == "agent:recon"
    assert stored["uses"] == 0 and stored["last_used_at"] is None
    assert stored["created_at"] > 0

    found = store.search("introspection")
    assert [item["id"] for item in found] == [lesson_id]
    assert found[0]["body"] == stored["body"]
    json.dumps(found)  # JSON-serialisable
    json.dumps(stored)
    assert store.get("L-000000000000") is None
    assert store.search("nosuchwordanywhere") == []


def test_lessons_survive_reopening_the_file(tmp_path: Path) -> None:
    store = _open(tmp_path)
    lesson_id = store.save(
        _lesson("JWT alg none accepted", finding_id="F-1"), "op", verified_finding=True
    )
    store.close()

    reopened = _open(tmp_path)
    assert reopened.count() == 1
    assert [item["id"] for item in reopened.search("alg none")] == [lesson_id]


def test_invalid_lessons_are_refused(tmp_path: Path) -> None:
    store = _open(tmp_path)
    with pytest.raises(LessonError, match="kind"):
        store.save(_lesson("x", kind="rumour"), "agent")
    with pytest.raises(LessonError, match="title"):
        store.save({"kind": "guide", "title": " ", "body": "b"}, "agent")
    with pytest.raises(LessonError, match="body"):
        store.save({"kind": "guide", "title": "t", "body": ""}, "agent")
    with pytest.raises(LessonError, match="actor"):
        store.save(_lesson("x"), "")
    with pytest.raises(LessonError, match="kind"):
        store.search("x", kind="rumour")
    assert store.count() == 0


def test_same_lesson_saved_twice_is_one_row(tmp_path: Path) -> None:
    store = _open(tmp_path)
    first = store.save(_lesson("NoSQL operator injection in login"), "agent:a")
    second = store.save(_lesson("NoSQL operator injection in login"), "agent:b")
    other = store.save(_lesson("NoSQL operator injection in search"), "agent:a")
    assert first == second
    assert other != first
    assert store.count() == 2


# ── ranking ─────────────────────────────────────────────────────────────


def test_verified_graphql_lesson_outranks_unverified_one(tmp_path: Path) -> None:
    store = _open(tmp_path)
    verified = store.save(
        _lesson("Batch aliases to bypass rate limits", technologies=["graphql"], finding_id="F-1"),
        "integrator",
        verified_finding=True,
    )
    # Saved later, so recency alone would put it first.
    unverified = store.save(
        _lesson("Deep recursion query stalls the resolver", technologies=["graphql"]),
        "agent:web",
    )

    ranked = store.search(technologies=["graphql"], include_unverified=True)
    assert [item["id"] for item in ranked] == [verified, unverified]
    assert ranked[0]["trust"] == "verified" and ranked[1]["trust"] == "unverified"
    assert ranked[0]["score"] == pytest.approx(ranked[1]["score"] + 1.0)


def test_without_the_verified_bonus_the_newer_lesson_wins(tmp_path: Path) -> None:
    """Control for the test above: equal trust, so the tie goes to recency."""
    store = _open(tmp_path)
    older = store.save(_lesson("Batch aliases", technologies=["graphql"]), "agent:web")
    newer = store.save(_lesson("Deep recursion", technologies=["graphql"]), "agent:web")

    ranked = store.search(technologies=["graphql"], include_unverified=True)
    assert [item["id"] for item in ranked] == [newer, older]
    assert ranked[0]["score"] == ranked[1]["score"]


def test_technology_weighs_two_class_one_and_unrelated_lessons_are_left_out(
    tmp_path: Path,
) -> None:
    store = _open(tmp_path)

    def save(title: str, **fields: Any) -> str:
        return store.save(_lesson(title, finding_id="F-1", **fields), "op", verified_finding=True)

    both = save("both", technologies=["graphql", "express"], classes=["access_control"])
    tech = save("tech only", technologies=["graphql"])
    cls = save("class only", classes=["access_control"])
    unrelated = save("unrelated", technologies=["wordpress"], classes=["xss"])

    ranked = store.search(technologies=["GraphQL", "express"], classes=["access_control"], limit=10)
    assert [item["id"] for item in ranked] == [both, tech, cls]
    assert [item["score"] for item in ranked] == [6.0, 3.0, 2.0]  # 2/tech + 1/class + 1 verified
    assert unrelated not in {item["id"] for item in ranked}


def test_default_search_hides_unverified_lessons(tmp_path: Path) -> None:
    store = _open(tmp_path)
    unverified = store.save(_lesson("Prototype pollution via merge"), "agent:web")
    verified = store.save(
        _lesson("Prototype pollution via query parser", finding_id="F-2"),
        "integrator",
        verified_finding=True,
    )

    assert [item["id"] for item in store.search("prototype pollution")] == [verified]
    assert {item["id"] for item in store.search()} == {verified}  # no query: still hidden
    shown = store.search("prototype pollution", include_unverified=True)
    assert {item["id"] for item in shown} == {verified, unverified}


def test_kind_filter(tmp_path: Path) -> None:
    store = _open(tmp_path)
    guide = store.save(_lesson("SSTI probe guide", kind="guide"), "agent")
    failure = store.save(_lesson("SSTI probe blocked by WAF", kind="failure"), "agent")
    payload = store.save(_lesson("SSTI probe string", kind="payload", body="{{7*7}}"), "agent")

    def ids(kind: str | None) -> set[str]:
        found = store.search("ssti", kind=kind, include_unverified=True, limit=10)
        return {item["id"] for item in found}

    assert ids(None) == {guide, failure, payload}
    assert ids("failure") == {failure}
    assert ids("payload") == {payload}


def test_returned_lessons_count_a_use_and_others_do_not(tmp_path: Path) -> None:
    clock = Clock()
    store = _open(tmp_path, clock=clock)
    hit = store.save(_lesson("CORS reflects arbitrary origin"), "agent")
    miss = store.save(_lesson("Open redirect on logout"), "agent")

    first = store.search("cors", include_unverified=True)
    assert first[0]["id"] == hit and first[0]["uses"] == 1
    assert first[0]["last_used_at"] == clock.now
    store.search("cors", include_unverified=True)

    assert _must(store.get(hit))["uses"] == 2
    assert _must(store.get(hit))["last_used_at"] == clock.now
    assert _must(store.get(miss))["uses"] == 0 and _must(store.get(miss))["last_used_at"] is None
    # A lesson the default search hides is not counted either.
    store.search("cors")
    assert _must(store.get(hit))["uses"] == 2


# ── trust ───────────────────────────────────────────────────────────────


def test_agent_supplied_trust_is_ignored(tmp_path: Path) -> None:
    store = _open(tmp_path)
    as_dict = store.save(
        _lesson("Forged trust in a dict", trust="verified", finding_id="F-9", uses=99, id="L-x"),
        "agent:web",
    )
    as_object = store.save(
        Lesson(kind="guide", title="Forged trust in a Lesson", body="b", trust="verified"),
        "agent:web",
    )
    truthy = store.save(
        _lesson("Truthy is not True", finding_id="F-9"),
        "agent:web",
        verified_finding="yes",  # type: ignore[arg-type]
    )

    for lesson_id in (as_dict, as_object, truthy):
        stored = store.get(lesson_id)
        assert stored is not None and stored["trust"] == "unverified"
    assert _must(store.get(as_dict))["uses"] == 0 and as_dict != "L-x"
    assert store.search("trust") == []  # hidden like any unverified lesson
    assert store.stats()["verified"] == 0


def test_only_the_verified_finding_flag_makes_a_lesson_verified(tmp_path: Path) -> None:
    store = _open(tmp_path)
    lesson_id = store.save(
        _lesson("Mass assignment sets role", finding_id="F-abc"),
        "integrator",
        verified_finding=True,
    )
    assert _must(store.get(lesson_id))["trust"] == "verified"
    assert [item["id"] for item in store.search("mass assignment")] == [lesson_id]

    with pytest.raises(LessonError, match="finding_id"):
        store.save(_lesson("No finding named"), "integrator", verified_finding=True)
    assert store.count() == 1


def test_resaving_cannot_downgrade_or_retag_a_verified_lesson(tmp_path: Path) -> None:
    store = _open(tmp_path)
    lesson_id = store.save(
        _lesson("IDOR on order id", technologies=["express"], finding_id="F-1"),
        "integrator",
        verified_finding=True,
    )
    again = store.save(
        _lesson("IDOR on order id", technologies=["wordpress", "graphql"], finding_id="F-fake"),
        "agent:web",
    )

    stored = store.get(lesson_id)
    assert stored is not None
    assert again == lesson_id and store.count() == 1
    assert stored["trust"] == "verified"
    assert stored["technologies"] == ["express"]
    assert stored["finding_id"] == "F-1" and stored["saved_by"] == "integrator"
    assert store.search(technologies=["wordpress"]) == []


def test_verified_resave_promotes_an_unverified_lesson(tmp_path: Path) -> None:
    store = _open(tmp_path)
    lesson_id = store.save(_lesson("IDOR on basket id", technologies=["express"]), "agent:web")
    assert store.search(technologies=["express"]) == []

    promoted = store.save(
        _lesson("IDOR on basket id", technologies=["angular"], finding_id="F-7"),
        "integrator",
        verified_finding=True,
    )
    stored = store.get(lesson_id)
    assert stored is not None
    assert promoted == lesson_id and store.count() == 1
    assert stored["trust"] == "verified" and stored["finding_id"] == "F-7"
    assert stored["technologies"] == ["express", "angular"]
    assert [item["id"] for item in store.search(technologies=["angular"])] == [lesson_id]


# ── scrubbing ───────────────────────────────────────────────────────────

SCOPE = ["*.acme-corp.test", "acme-corp.test", "portal.globex.test", "198.51.100.0/28"]

BEARER = "9f8e7d6c5b4a39281706f5e4d3c2b1a0ffee77"
JWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
JWT_PAYLOAD = "eyJzdWIiOiJib2JAYWNtZSIsInJvbGUiOiJhZG1pbiJ9"
JWT_SIGNATURE = "c2lnbmF0dXJlLXZhbHVlLWZvci10ZXN0"
JWT = f"{JWT_HEADER}.{JWT_PAYLOAD}.{JWT_SIGNATURE}"
PASSWORD = "Hunter2!zebra"
JSON_PASSWORD = "Tr0ub4dor&3x"
PROSE_PASSWORD = "Winter2026!!"
COOKIE = "s%3AkJ8sQ2xZpL0mN4.vB7cR9tY1uW3"
SESSION_COOKIE = "q1w2e3r4t5y6u7i8"
API_KEY = "AbCd1234EfGh5678IjKl"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
URL_PASSWORD = "s3cretPw99"

SECRETS = [
    BEARER,
    JWT,
    JWT_HEADER,
    JWT_PAYLOAD,
    JWT_SIGNATURE,
    PASSWORD,
    JSON_PASSWORD,
    PROSE_PASSWORD,
    COOKIE,
    SESSION_COOKIE,
    API_KEY,
    AWS_KEY,
    URL_PASSWORD,
]
HOSTNAMES = ["acme-corp.test", "portal.globex.test", "globex", "198.51.100.7"]

MARKER = "zzmarkerkeptverbatimzz"

DIRTY_BODY = f"""\
{MARKER}: replay the order request as another user.
GET https://shop.acme-corp.test/api/orders/7 with Authorization: Bearer {BEARER}
Old session token {JWT} still works after logout.
Login was POST /rest/login email=bob@acme-corp.test&password={PASSWORD}
JSON form: {{"password": "{JSON_PASSWORD}", "user": "bob"}}; the admin password is {PROSE_PASSWORD}
Cookie: connect.sid={COOKIE}; lang=en
curl -b 'PHPSESSID={SESSION_COOKIE}' https://admin:{URL_PASSWORD}@PORTAL.Globex.Test:8443/export
x-api-key: {API_KEY} and the leaked AWS id {AWS_KEY}
Internal host API.Staging.ACME-CORP.test resolves to 198.51.100.7.
"""


def test_secrets_and_scope_hostnames_never_reach_the_database_file(tmp_path: Path) -> None:
    store = _open(tmp_path)
    lesson_id = store.save(
        {
            "kind": "failure",
            "title": f"IDOR at shop.acme-corp.test with token={BEARER}",
            "body": DIRTY_BODY,
            "classes": ["access_control", "portal.globex.test"],
            "technologies": ["express", "shop.acme-corp.test", f"sid={SESSION_COOKIE}"],
            "source_engagement": "eng-042",
            "finding_id": "F-00aa11bb22cc",
        },
        "agent:web",
        scope_hosts=SCOPE,
    )
    # Exercise the read and index paths as well, then flush everything to disk.
    returned = store.search("order request", include_unverified=True)
    assert [item["id"] for item in returned] == [lesson_id]
    store.close()

    raw = _files_bytes(tmp_path)
    lowered = raw.lower()
    # The check can see stored text: the harmless marker is in the file.
    assert MARKER.encode() in raw
    for secret in SECRETS:
        assert secret.encode() not in raw, f"secret survived in the database: {secret}"
    for hostname in HOSTNAMES:
        assert hostname.encode() not in lowered, f"target survived in the database: {hostname}"

    visible = json.dumps(returned)
    for needle in SECRETS:
        assert needle not in visible
    for hostname in HOSTNAMES:
        assert hostname not in visible.lower()
    stored = returned[0]
    assert "<target>" in stored["body"] and "<target>" in stored["title"]
    assert "<redacted>" in stored["body"] and "<jwt>" in stored["body"]
    assert stored["technologies"] == ["express"]
    assert stored["classes"] == ["access_control"]
    # Technique survives: what was done is still readable.
    assert "replay the order request as another user" in stored["body"]
    assert "/api/orders/7" in stored["body"]
    assert "still works after logout" in stored["body"]


def test_the_byte_search_finds_a_secret_that_was_not_scrubbed(tmp_path: Path) -> None:
    """Control: the same file search does find the fixture secrets when a row is
    written past ``save`` - so their absence above is the scrubber's doing."""
    store = _open(tmp_path)
    store.save(_lesson("placeholder"), "agent")
    store.close()

    db = sqlite3.connect(tmp_path / DB_FILENAME)
    db.execute(
        "INSERT INTO lessons (id, kind, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
        ("L-raw", "guide", "raw", DIRTY_BODY, 1.0),
    )
    db.commit()
    db.close()

    raw = _files_bytes(tmp_path)
    for secret in SECRETS:
        assert secret.encode() in raw
    assert b"shop.acme-corp.test" in raw and b"198.51.100.7" in raw


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"Authorization: Bearer {BEARER}", BEARER),
        (f'headers = {{"Authorization": "Bearer {BEARER}"}}', BEARER),
        (f"send Bearer {BEARER} to the API", BEARER),
        ("Authorization: Basic YWRtaW46aHVudGVyMg==", "YWRtaW46aHVudGVyMg=="),
        ("try Basic YWRtaW46aHVudGVyMg== on /admin", "YWRtaW46aHVudGVyMg=="),
        (f"token {JWT} is accepted", JWT_PAYLOAD),
        (f"unsigned {JWT_HEADER}.{JWT_PAYLOAD}. passes", JWT_PAYLOAD),
        (f"password={PASSWORD}", PASSWORD),
        (f"Password: {PASSWORD}", PASSWORD),
        (f"passwd = '{PASSWORD}'", PASSWORD),
        (f'{{"client_secret":"{API_KEY}"}}', API_KEY),
        (f"the password is {PROSE_PASSWORD}", PROSE_PASSWORD),
        (f"/reset?token={API_KEY}&next=/", API_KEY),
        (f"Cookie: session={SESSION_COOKIE}; theme=dark", SESSION_COOKIE),
        (f"Set-Cookie: connect.sid={COOKIE}; HttpOnly", COOKIE),
        (f"JSESSIONID={SESSION_COOKIE}", SESSION_COOKIE),
        (f"curl --cookie sid={SESSION_COOKIE} /me", SESSION_COOKIE),
        (f"X-API-Key: {API_KEY}", API_KEY),
        (f"api_key={API_KEY}", API_KEY),
        (f"key id {AWS_KEY} was in the bundle", AWS_KEY),
        ("ghp" + "_abcdefghijklmnopqrstuvwxyz0123456789 in .env", "ghp_abcdefghijklmnopqrstuvwxyz"),
        # Built at runtime so no key-shaped literal is committed.
        ("sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" + " in main.js", "4eC39HqLyjWDarjtT1zdp7dc"),
        ("md5 session 5d41402abc4b2a76b9719d911017c592", "5d41402abc4b2a76b9719d911017c592"),
        (
            "blob A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2 leaked",
            "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2",
        ),
        (f"ftp://deploy:{URL_PASSWORD}@files.example.net/x", URL_PASSWORD),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz\n-----END RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEAxyz",
        ),
    ],
)
def test_scrub_removes_each_credential_shape(text: str, secret: str) -> None:
    assert secret in text  # the fixture really contains it
    cleaned = scrub(text)
    assert secret not in cleaned
    assert "<redacted>" in cleaned or "<jwt>" in cleaned


@pytest.mark.parametrize(
    "text",
    [
        "Send the introspection query with __schema; alias batching bypasses rate limits.",
        "Use Bearer authentication; a Bearer token from a low-privilege user is enough.",
        "Basic authentication is offered on /admin but the password is not checked.",
        "bypass: change the id in /api/orders/{id}; inside=ok; class: access_control",
        "Payload: ' OR 1=1-- and {{7*7}} and <script>alert(1)</script>",
        "JWT with alg none is accepted when the signature segment is empty.",
        "The session cookie lacks HttpOnly; steal it with document.cookie.",
        "Port 8443 on 10.0.0.5 and version 4.17.21 of lodash, CVE-2021-23337.",
    ],
)
def test_scrub_leaves_technique_text_alone(text: str) -> None:
    assert scrub(text, SCOPE) == text


def test_scrub_replaces_scope_targets_and_only_those() -> None:
    text = (
        "https://shop.acme-corp.test/a, ACME-CORP.TEST, portal.globex.test:8443, "
        "bob@mail.acme-corp.test, 198.51.100.7 and 198.51.100.15; "
        "not notacme-corp.test, globex.test, www.example.org, 198.51.100.16 or 203.0.113.9"
    )
    assert scrub(text, SCOPE) == (
        "https://<target>/a, <target>, <target>:8443, "
        "bob@<target>, <target> and <target>; "
        "not notacme-corp.test, globex.test, www.example.org, 198.51.100.16 or 203.0.113.9"
    )
    # Without a scope nothing is treated as a target.
    assert scrub(text) == text


def test_scrub_accepts_every_scope_entry_shape() -> None:
    scope = [
        "https://pay.initech.test:8443/checkout",
        {"target": "api-*.initech.test", "type": "domain-glob"},
        "juice-shop:3000",
        "*.test",
        "2001:db8::/32",
        None,
        "",
    ]
    text = (
        "pay.initech.test api-eu.initech.test http://juice-shop:3000/rest "
        "db.internal.test 2001:db8::1 2001:dead::1 and a test of juice-shopping"
    )
    assert scrub(text, scope) == (
        "<target> <target> http://<target>:3000/rest "
        "<target> <target> 2001:dead::1 and a test of juice-shopping"
    )


def test_scope_hosts_from_document() -> None:
    document = {
        "machine_enforcement": {
            "mode": "enforce",
            "in_scope": ["*.acme-corp.test", {"target": "198.51.100.0/28", "type": "cidr"}],
            "out_of_scope": ["hr.acme-corp.test", "*.acme-corp.test"],
            "forbidden_destinations": ["169.254.169.254"],
        }
    }
    hosts = scope_hosts_from_document(document)
    assert hosts == ["*.acme-corp.test", "198.51.100.0/28", "hr.acme-corp.test"]
    assert scope_hosts_from_document({}) == []
    assert scope_hosts_from_document(None) == []
    assert scrub("see hr.acme-corp.test and 198.51.100.3", hosts) == "see <target> and <target>"


# ── limits and eviction ─────────────────────────────────────────────────


def test_body_limit(tmp_path: Path) -> None:
    store = _open(tmp_path)
    at_limit = ("technique " * 200)[:-1] + "s"
    assert len(at_limit) == MAX_BODY_CHARS
    exact = store.save(_lesson("at the limit", body=at_limit), "agent")
    assert _must(store.get(exact))["body"] == at_limit
    assert len(_must(store.get(exact))["body"]) == MAX_BODY_CHARS == 2000
    with pytest.raises(LessonError, match="2000"):
        store.save(_lesson("over the limit", body=at_limit + "s"), "agent")
    # Scrubbing can lengthen a body ("a.io" -> "<target>"); the stored one still fits.
    grown = store.save(
        _lesson("grows when scrubbed", body="a.io " * 400), "agent", scope_hosts=["a.io"]
    )
    assert len(_must(store.get(grown))["body"]) <= MAX_BODY_CHARS
    assert "a.io" not in _must(store.get(grown))["body"]
    assert store.count() == 2


def test_search_limit(tmp_path: Path) -> None:
    store = _open(tmp_path)
    ids = [
        store.save(
            _lesson(f"Cache poisoning variant {n}", technologies=["nginx"], finding_id="F-1"),
            "op",
            verified_finding=True,
        )
        for n in range(6)
    ]
    newest_first = list(reversed(ids))

    assert [item["id"] for item in store.search("cache poisoning")] == newest_first[:3]
    assert [item["id"] for item in store.search("cache poisoning", limit=1)] == newest_first[:1]
    assert len(store.search("cache poisoning", limit=5)) == 5
    assert len(store.search("cache poisoning", limit=100)) == 6
    assert [item["id"] for item in store.for_engagement(["nginx"])] == newest_first[:5]


def test_eviction_takes_the_oldest_unverified_first(tmp_path: Path) -> None:
    store = _open(tmp_path, max_lessons=3)
    oldest_verified = store.save(
        _lesson("verified and oldest", finding_id="F-1"), "op", verified_finding=True
    )
    old_unverified = store.save(_lesson("unverified old"), "agent")
    new_unverified = store.save(_lesson("unverified new"), "agent")
    assert store.count() == 3

    fourth = store.save(_lesson("unverified newest"), "agent")
    assert store.count() == 3
    assert store.get(old_unverified) is None  # the oldest unverified went
    assert store.get(oldest_verified) is not None  # older still, but verified
    assert store.get(new_unverified) is not None and store.get(fourth) is not None
    found = store.search("unverified", include_unverified=True, limit=10)
    assert {item["id"] for item in found} == {new_unverified, fourth}
    if store.fts:  # the evicted lesson left the index too, not just the table
        store.close()
        db = sqlite3.connect(tmp_path / DB_FILENAME)
        assert db.execute("SELECT COUNT(*) FROM lessons_fts").fetchone()[0] == 3
        assert (
            db.execute("SELECT COUNT(*) FROM lessons_fts WHERE lessons_fts MATCH 'old'").fetchone()[
                0
            ]
            == 0
        )
        db.close()


def test_eviction_when_every_lesson_is_verified(tmp_path: Path) -> None:
    store = _open(tmp_path, max_lessons=2)
    first = store.save(_lesson("verified one", finding_id="F-1"), "op", verified_finding=True)
    second = store.save(_lesson("verified two", finding_id="F-2"), "op", verified_finding=True)

    # An unverified lesson never displaces a verified one.
    with pytest.raises(LessonError, match="full"):
        store.save(_lesson("unverified latecomer"), "agent")
    assert store.count() == 2
    assert store.get(first) is not None and store.get(second) is not None

    # A verified one replaces the oldest verified.
    third = store.save(_lesson("verified three", finding_id="F-3"), "op", verified_finding=True)
    assert store.count() == 2
    assert store.get(first) is None
    assert store.get(second) is not None and store.get(third) is not None
    # Saving a lesson that is already stored needs no room.
    assert store.save(_lesson("verified two"), "agent") == second
    assert store.stats() == {
        "fts": store.fts,
        "lessons": 2,
        "verified": 2,
        "unverified": 0,
        "max_lessons": 2,
    }


def test_default_capacity_is_five_thousand(tmp_path: Path) -> None:
    assert lessons_module.MAX_LESSONS == 5000
    assert _open(tmp_path).stats()["max_lessons"] == 5000
    with pytest.raises(ValueError):
        _open(tmp_path, max_lessons=0)


# ── briefing ────────────────────────────────────────────────────────────


def test_for_engagement_briefs_on_matching_verified_lessons(tmp_path: Path) -> None:
    store = _open(tmp_path)

    def save(title: str, verified: bool = True, **fields: Any) -> str:
        if verified:
            fields["finding_id"] = "F-1"
        return store.save(_lesson(title, **fields), "op", verified_finding=verified)

    graphql = save("graphql batching", technologies=["graphql"], classes=["graphql"])
    express = save("express qs parsing", technologies=["express"])
    by_class = save("jwt confusion", kind="failure", classes=["auth_session"])
    save("wordpress xmlrpc", technologies=["wordpress"])
    save("graphql rumour", verified=False, technologies=["graphql", "express"])

    briefing = store.for_engagement(["GraphQL", "Express"], ["auth_session"])
    assert [item["id"] for item in briefing] == [express, graphql, by_class]
    assert all(item["trust"] == "verified" for item in briefing)
    assert _must(store.get(graphql))["uses"] == 1
    json.dumps(briefing)

    assert store.for_engagement(["express"], limit=1)[0]["id"] == express
    assert store.for_engagement(["django"]) == []
    assert store.for_engagement([], []) == []  # nothing known, nothing to brief


# ── FTS and the LIKE fallback ───────────────────────────────────────────


def _seed(store: LessonStore) -> dict[str, str]:
    def save(key: str, title: str, body: str, **fields: Any) -> tuple[str, str]:
        lesson = _lesson(title, body, finding_id="F-1", **fields)
        return key, store.save(lesson, "op", verified_finding=True)

    return dict(
        [
            save(
                "introspection",
                "GraphQL introspection exposes the schema",
                "Query __schema to list types; introspection was left on in production.",
                technologies=["graphql"],
            ),
            save(
                "batching",
                "GraphQL alias batching",
                "Many login mutations in one request bypass the limiter.",
                technologies=["graphql"],
            ),
            save(
                "sqli",
                "Boolean SQL injection in search",
                "The q parameter is concatenated into a LIKE clause.",
                technologies=["express", "sqlite"],
            ),
        ]
    )


def test_fts_is_reported_and_used_when_available(tmp_path: Path) -> None:
    probe = sqlite3.connect(":memory:")
    if not fts5_available(probe):
        pytest.skip("this SQLite build has no FTS5")
    store = _open(tmp_path)
    assert store.fts is True and store.stats()["fts"] is True
    ids = _seed(store)
    tables = {
        row[0]
        for row in sqlite3.connect(tmp_path / DB_FILENAME).execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    assert "lessons_fts" in tables
    assert store.search("introspection")[0]["id"] == ids["introspection"]
    # Query text is data, not FTS syntax.
    assert [item["id"] for item in store.search('"introspection" OR NOT (')] == [
        ids["introspection"]
    ]
    # Punctuation alone is an empty query (newest lessons), not a syntax error.
    assert len(store.search("* : ^ \" ' ( ) -")) == 3


def test_forced_like_fallback_returns_the_same_top_result(tmp_path: Path) -> None:
    like_dir, fts_dir = tmp_path / "like", tmp_path / "fts"
    like_store = _open(like_dir, fts=False)
    assert like_store.fts is False and like_store.stats()["fts"] is False
    like_ids = _seed(like_store)
    tables = {
        row[0]
        for row in sqlite3.connect(like_dir / DB_FILENAME).execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    assert "lessons_fts" not in tables  # the fallback really ran without an index

    for query, expected in [
        ("introspection", "introspection"),
        ("limiter", "batching"),
        ("injection", "sqli"),
        ("INTROSPECTION", "introspection"),
    ]:
        top = like_store.search(query)
        assert top and top[0]["id"] == like_ids[expected], query
    assert like_store.search("nosuchwordanywhere") == []
    # A LIKE wildcard in a query is literal text: "_" finds the one lesson that
    # has an underscore ("__schema"), not every lesson.
    assert [item["id"] for item in like_store.search("_")] == [like_ids["introspection"]]
    # More query terms found means a higher score.
    two_terms = like_store.search("alias batching limiter schema", limit=3)
    assert two_terms[0]["id"] == like_ids["batching"]
    assert two_terms[0]["score"] > two_terms[1]["score"]

    if not fts5_available(sqlite3.connect(":memory:")):
        pytest.skip("this SQLite build has no FTS5 to compare with")
    fts_store = _open(fts_dir)
    assert fts_store.fts is True
    fts_ids = _seed(fts_store)
    assert fts_ids == like_ids  # ids are content-derived, so the stores are comparable
    for query in ("introspection", "limiter", "injection"):
        assert fts_store.search(query)[0]["id"] == like_store.search(query)[0]["id"], query


def test_missing_fts5_is_detected_at_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class NoFts(sqlite3.Connection):
        def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
            if "fts5" in sql.lower():
                raise sqlite3.OperationalError("no such module: fts5")
            return super().execute(sql, *args)

    assert fts5_available(sqlite3.connect(":memory:", factory=NoFts)) is False

    monkeypatch.setattr(lessons_module, "fts5_available", lambda db: False)
    store = _open(tmp_path)  # fts=None: detect
    assert store.fts is False and store.stats()["fts"] is False
    ids = _seed(store)
    assert store.search("introspection")[0]["id"] == ids["introspection"]
    with pytest.raises(LessonError, match="FTS5"):
        _open(tmp_path / "other", fts=True)


def test_index_catches_up_after_the_file_was_written_in_like_mode(tmp_path: Path) -> None:
    if not fts5_available(sqlite3.connect(":memory:")):
        pytest.skip("this SQLite build has no FTS5")
    with_index = _open(tmp_path)
    ids = _seed(with_index)
    with_index.close()

    without_index = _open(tmp_path, fts=False, max_lessons=3)
    # The store is full, so this verified save replaces the oldest verified
    # lesson (introspection) - an eviction and an insert the index does not see.
    added = without_index.save(
        _lesson("Path traversal in the download handler", finding_id="F-5"),
        "op",
        verified_finding=True,
    )
    without_index.close()

    reopened = _open(tmp_path, max_lessons=3)
    assert reopened.fts is True
    assert reopened.search("introspection") == []  # evicted while the index was off
    assert [item["id"] for item in reopened.search("traversal")] == [added]
    assert reopened.search("limiter")[0]["id"] == ids["batching"]
