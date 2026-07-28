"""
test_birthday.py -- the birthday requirement for new accounts.

The birthday is stored the same way as the password: as an irreversible
Argon2id verifier, never as a date. These tests pin that down, because the
difference between "we store a hash of the birthday" and "we store the
birthday" is the difference between a hashed credential and a database of
personal data under the GDPR.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))

from server import Storage  # noqa: E402

SERVER_SRC = (REPO_ROOT / "server" / "server.py").read_text(encoding="utf-8")


@pytest.fixture()
def storage(tmp_path):
    """
    pytest's tmp_path rather than tempfile.TemporaryDirectory().

    TemporaryDirectory deletes eagerly on exit and RAISES if a file is locked,
    which turned a Windows file-locking detail into six red tests. tmp_path is
    cleaned lazily by pytest and tolerates a directory it cannot remove yet.
    The database is closed explicitly either way -- that is the actual fix; the
    fixture change only stops a leak becoming a cascade.
    """
    st = Storage(str(tmp_path / "birthday.db"))
    try:
        yield st
    finally:
        st.close()


# --------------------------------------------------------------------------
# Schema and migration
# --------------------------------------------------------------------------

def test_fresh_database_has_the_column(storage):
    cols = {r[1] for r in storage._db.execute("PRAGMA table_info(users)")}
    assert "dob_verifier" in cols


def test_legacy_database_is_migrated(tmp_path):
    """
    A database written before birthdays existed must gain the column on
    startup, not crash. This is the upgrade path for the live cPouta relay.
    """
    db_path = tmp_path / "legacy.db"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE users (nick TEXT PRIMARY KEY, pubkey BLOB)")
    con.execute("INSERT INTO users VALUES ('olduser', X'AABB')")
    con.commit()
    con.close()

    st = Storage(str(db_path))                       # triggers the migration
    try:
        cols = {r[1] for r in st._db.execute("PRAGMA table_info(users)")}
        assert "dob_verifier" in cols

        # The pre-existing account survives, with a NULL birthday meaning
        # "registered before birthdays were required".
        assert st.get_dob_verifier("olduser") is None
        assert st.get_key("olduser") == b"\xaa\xbb"
    finally:
        st.close()


# --------------------------------------------------------------------------
# Storage behaviour
# --------------------------------------------------------------------------

def test_round_trip(storage):
    storage.save_key("alice", b"\x01" * 32)
    storage.set_dob_verifier("alice", b"\x42" * 32)
    assert storage.get_dob_verifier("alice") == b"\x42" * 32


def test_unknown_nick_returns_none(storage):
    assert storage.get_dob_verifier("nobody") is None


def test_account_without_a_birthday_reads_as_none(storage):
    storage.save_key("legacy", b"\x02" * 32)
    assert storage.get_dob_verifier("legacy") is None


# --------------------------------------------------------------------------
# The properties that matter
# --------------------------------------------------------------------------

def test_no_plaintext_birthday_column_exists(storage):
    """
    Guard against a well-meaning future change that adds a readable date
    column. If someone needs the date itself, that is a decision that should be
    made deliberately and defended, not arrived at by accident.
    """
    cols = {r[1].lower() for r in storage._db.execute("PRAGMA table_info(users)")}
    for forbidden in ("dob", "birthday", "birth_date", "birthdate", "date_of_birth"):
        assert forbidden not in cols, (
            f"users.{forbidden} would store a birthday in readable form; "
            "only the irreversible dob_verifier should exist."
        )


def test_new_password_protected_accounts_are_refused_without_a_birthday():
    """
    The enforcement exists, is scoped to NEW accounts, and uses its own close
    code so the client can explain the cause precisely.
    """
    assert "birthday required for new accounts" in SERVER_SRC
    assert "code=4003" in SERVER_SRC
    # Scoped to new nicks only: an existing account must never be locked out.
    assert "not nick_exists" in SERVER_SRC


def test_the_server_never_sends_the_birthday_verifier_to_a_client():
    """
    dob_verifier must only ever be READ from an incoming message and WRITTEN to
    storage. If it were ever placed into an outgoing frame, the relay would
    become an offline brute-force oracle for a very small search space.
    """
    for line in SERVER_SRC.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "dob_verifier" not in stripped:
            continue
        # Any line mentioning it must not be building an outbound payload.
        assert not any(
            marker in stripped
            for marker in ('"type"', "insert(", "json.dumps", "send(")
        ), f"dob_verifier appears in what looks like an outbound frame: {stripped}"
