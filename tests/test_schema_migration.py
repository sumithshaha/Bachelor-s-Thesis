"""
Guard tests for automatic schema migration of an EXISTING database.

WHY THIS FILE EXISTS
--------------------
Every table in server.py is created with CREATE TABLE IF NOT EXISTS. On a
database that already has the table, that statement does nothing whatsoever --
so a column added to the CREATE statement reaches every NEW database and never
reaches an OLD one.

That gap was live on the deployed relay. The VM's database was created by a
build whose `messages` table had no `frame` column. Starting a ratchet-era
build against it succeeded: the connection opened, the missing TABLES were
created, and the log said "Listening on wss://...". Nothing indicated a
problem. The failure only arrived at the first stored message:

    OperationalError: table messages has no column named frame

which on a live relay means every offline message fails, with a startup that
looked perfectly healthy. The old mitigation was a manual ALTER TABLE in a
deployment runbook -- which works exactly until the one time someone skips it.

Storage._ensure_table_columns() closes that. These tests exist so it stays
closed: they are written against the observable behaviour (what columns exist,
what inserts succeed) rather than against the implementation, so a future
rewrite of the migration is free to change how it works but not what it
guarantees.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from server import Storage  # noqa: E402


# The exact schema the cPouta VM's database was created with, reproduced from
# the deployed copy of server.py. Two tables, and neither of the columns that
# arrived later.
LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    nick    TEXT PRIMARY KEY,
    pubkey  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sender      TEXT NOT NULL,
    recipient   TEXT NOT NULL,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    ts          INTEGER NOT NULL
);
"""


def _columns(path: Path, table: str) -> set[str]:
    db = sqlite3.connect(path)
    try:
        return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    finally:
        db.close()


@pytest.fixture
def legacy_db(tmp_path: Path) -> Path:
    """A database with the pre-ratchet schema and one row in each table."""
    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    db.executescript(LEGACY_SCHEMA)
    db.execute("INSERT INTO users VALUES (?, ?)", ("olduser", b"\x01" * 32))
    db.execute(
        "INSERT INTO messages (sender, recipient, nonce, ciphertext, ts) "
        "VALUES (?, ?, ?, ?, ?)",
        ("alice", "bob", b"\x00" * 24, b"\xde\xad\xbe\xef", 1_700_000_000),
    )
    db.commit()
    db.close()
    return path


def test_legacy_database_is_missing_the_frame_column(legacy_db: Path) -> None:
    """The premise. If this ever fails, the fixture stopped being legacy."""
    assert "frame" not in _columns(legacy_db, "messages")


def test_opening_a_legacy_database_adds_the_frame_column(
        legacy_db: Path) -> None:
    """Storage() alone must be enough -- no manual ALTER, no runbook step."""
    storage = Storage(str(legacy_db))
    try:
        assert "frame" in _columns(legacy_db, "messages")
    finally:
        storage.close()


def test_opening_a_legacy_database_adds_the_credential_columns(
        legacy_db: Path) -> None:
    """The pre-existing users migration must keep working alongside the new one."""
    storage = Storage(str(legacy_db))
    try:
        cols = _columns(legacy_db, "users")
        assert {"pw_verifier", "pw_salt", "dob_verifier"} <= cols
    finally:
        storage.close()


def test_existing_rows_survive_migration(legacy_db: Path) -> None:
    """ADD COLUMN must not disturb data. Old rows get NULL in the new column."""
    storage = Storage(str(legacy_db))
    try:
        db = sqlite3.connect(legacy_db)
        try:
            row = db.execute(
                "SELECT sender, recipient, ciphertext, frame FROM messages"
            ).fetchone()
        finally:
            db.close()
        assert row[0] == "alice"
        assert row[1] == "bob"
        assert row[2] == b"\xde\xad\xbe\xef"
        assert row[3] is None, "a pre-ratchet row must read back as frame=NULL"
    finally:
        storage.close()


def test_storing_a_message_works_after_migration(legacy_db: Path) -> None:
    """The actual failure this prevents.

    Before the migration existed, this insert raised

        OperationalError: table messages has no column named frame

    on the live relay, for every message that had to be stored for an offline
    recipient -- after a startup that had reported no problem at all.
    """
    storage = Storage(str(legacy_db))
    try:
        msg_id = storage.save_message(
            "alice", "bob", b"\x01" * 24, b"ciphertext", 1_700_000_001,
            frame='{"cipher":"xchacha","n":1}',
        )
        assert isinstance(msg_id, int)
    finally:
        storage.close()


def test_migration_is_idempotent(legacy_db: Path) -> None:
    """Reopening must not re-run the ALTER, which would raise 'duplicate column'."""
    Storage(str(legacy_db)).close()
    Storage(str(legacy_db)).close()
    storage = Storage(str(legacy_db))
    try:
        cols = [row[1] for row in sqlite3.connect(legacy_db)
                .execute("PRAGMA table_info(messages)")]
        assert cols.count("frame") == 1, "the column was added more than once"
    finally:
        storage.close()


def test_file_meta_gains_final_seen(tmp_path: Path) -> None:
    """The second late column, on a table shaped without it."""
    path = tmp_path / "partial.db"
    db = sqlite3.connect(path)
    db.executescript(LEGACY_SCHEMA + """
        CREATE TABLE IF NOT EXISTS file_meta (
            msg_id      TEXT PRIMARY KEY,
            sender      TEXT NOT NULL,
            recipient   TEXT NOT NULL,
            envelope    TEXT NOT NULL,
            ts          INTEGER NOT NULL
        );
    """)
    db.commit()
    db.close()

    storage = Storage(str(path))
    try:
        assert "final_seen" in _columns(path, "file_meta")
    finally:
        storage.close()


def test_fresh_database_needs_no_migration(tmp_path: Path) -> None:
    """A new database must come out complete from the CREATE statements alone.

    This is the test that would catch someone "fixing" a missing column by
    adding it to _LATE_COLUMNS and forgetting the CREATE statement. The
    migration is a safety net for old databases, not the definition of the
    schema.
    """
    path = tmp_path / "fresh.db"
    storage = Storage(str(path))
    try:
        assert "frame" in _columns(path, "messages")
        assert "final_seen" in _columns(path, "file_meta")
        assert {"pw_verifier", "pw_salt", "dob_verifier"} <= _columns(path, "users")
    finally:
        storage.close()


def test_every_late_column_is_also_in_the_create_statements(
        tmp_path: Path) -> None:
    """Structural check: the two definitions of the schema must agree.

    _LATE_COLUMNS names columns that older databases lack. Every one of them
    must ALSO appear in the CREATE TABLE statements, or a fresh database would
    be built without it and then immediately 'migrated' -- which would mean the
    CREATE statements are no longer the source of truth for the schema.
    """
    path = tmp_path / "fresh2.db"
    storage = Storage(str(path))
    try:
        for table, wanted in Storage._LATE_COLUMNS.items():
            present = _columns(path, table)
            missing = set(wanted) - present
            assert not missing, (
                f"{table} is missing {sorted(missing)} on a FRESH database: "
                "the column was added to _LATE_COLUMNS but not to the "
                "CREATE TABLE statement"
            )
    finally:
        storage.close()


# ==========================================================================
# Edge cases: partial migrations, unknown columns, concurrent opens, and the
# read-only failure surface. These cover the states a real deployed database
# can reach that the happy-path tests above do not: a database caught halfway
# between schema versions, one a FUTURE build has already extended, two
# connections open at once, and a database that cannot be written.
# ==========================================================================

def test_partial_migration_adds_only_the_missing_column(tmp_path: Path) -> None:
    """A database where messages ALREADY has 'frame' but file_meta lacks
    'final_seen' must gain only the one that is missing, and must not error on
    the one that is present.

    This is the realistic mid-upgrade state: a database written by a build that
    had one late column but not the other. `ADD COLUMN` on an existing column
    would raise 'duplicate column name', so the per-column guard has to be
    exact.
    """
    path = tmp_path / "partial.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE users (nick TEXT PRIMARY KEY, pubkey BLOB NOT NULL);
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL,
            recipient TEXT NOT NULL, nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL, ts INTEGER NOT NULL,
            frame TEXT
        );
        CREATE TABLE file_meta (
            msg_id TEXT PRIMARY KEY, sender TEXT NOT NULL,
            recipient TEXT NOT NULL, envelope TEXT NOT NULL, ts INTEGER NOT NULL
        );
    """)
    db.commit()
    db.close()

    storage = Storage(str(path))
    try:
        assert "frame" in _columns(path, "messages")        # was already there
        assert "final_seen" in _columns(path, "file_meta")  # newly added
        # messages must still have exactly one 'frame' column (not duplicated).
        cols = [row[1] for row in sqlite3.connect(path)
                .execute("PRAGMA table_info(messages)")]
        assert cols.count("frame") == 1
    finally:
        storage.close()


def test_unknown_future_column_does_not_break_migration(tmp_path: Path) -> None:
    """A database a LATER build extended -- with a column this build has never
    heard of -- must still open, gain its own missing columns, and keep the
    unknown one.

    Forward compatibility: rolling back to an older relay after a newer one
    touched the database must not corrupt or crash it. `ADD COLUMN` only ever
    adds; it never inspects or removes what it did not create.
    """
    path = tmp_path / "future.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE users (nick TEXT PRIMARY KEY, pubkey BLOB NOT NULL);
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL,
            recipient TEXT NOT NULL, nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL, ts INTEGER NOT NULL,
            some_future_column TEXT
        );
    """)
    db.execute(
        "INSERT INTO messages (sender, recipient, nonce, ciphertext, ts, "
        "some_future_column) VALUES (?, ?, ?, ?, ?, ?)",
        ("a", "b", b"\x00" * 24, b"x", 1, "future data"),
    )
    db.commit()
    db.close()

    storage = Storage(str(path))
    try:
        cols = _columns(path, "messages")
        assert "frame" in cols, "our own column was not added"
        assert "some_future_column" in cols, "the unknown column was lost"
        # the pre-existing row and its future data survived untouched
        row = sqlite3.connect(path).execute(
            "SELECT some_future_column, frame FROM messages").fetchone()
        assert row[0] == "future data"
        assert row[1] is None
    finally:
        storage.close()


def test_two_storages_on_the_same_file_both_open(tmp_path: Path) -> None:
    """Opening the same database from two Storage instances must not deadlock
    or raise on the migration.

    The migration runs in __init__, so a second open re-runs the guarded
    ALTER pass. Because every column already exists by then, it must be a
    clean no-op rather than a 'duplicate column' error or a lock timeout.
    """
    path = tmp_path / "concurrent.db"
    first = Storage(str(path))
    try:
        second = Storage(str(path))
        try:
            assert "frame" in _columns(path, "messages")
        finally:
            second.close()
    finally:
        first.close()


def test_migration_on_readonly_database_surfaces_an_error(tmp_path: Path) -> None:
    """A database that cannot be written must fail LOUDLY, not silently.

    If the file (or its directory) is read-only, the ALTER cannot run. The
    right behaviour is a surfaced exception at open time -- a clear, immediate
    failure -- rather than a Storage that appears fine and then errors on the
    first write. We assert only that opening a legacy-schema, read-only
    database raises; the exact exception type is SQLite's to choose.
    """
    import os
    import stat

    path = tmp_path / "readonly.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE users (nick TEXT PRIMARY KEY, pubkey BLOB NOT NULL);
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL,
            recipient TEXT NOT NULL, nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL, ts INTEGER NOT NULL
        );
    """)
    db.commit()
    db.close()

    # Make the file read-only. On POSIX this reliably blocks the write; if the
    # platform still allows it (some CI as root), skip rather than assert a
    # false negative.
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    if os.access(path, os.W_OK):
        storage = Storage(str(path))
        storage.close()
        pytest.skip("filesystem ignores the read-only bit (running as root?)")

    with pytest.raises(sqlite3.Error):
        Storage(str(path))
