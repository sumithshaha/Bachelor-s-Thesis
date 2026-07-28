"""
test_sqlite_lifecycle.py -- databases must not outlive the test that opened one.

This exists because of a platform difference that hid a real leak for months.
POSIX lets you unlink a file that is still open; Windows does not. So a Storage
that never closed its connection was invisible on Linux and fatal on Windows:

    PermissionError: [WinError 32] The process cannot access the file
    because it is being used by another process

and then, once a leaked handle had made one pytest tmp_path run directory
undeletable, every later test that merely asked for tmp_path failed at setup
with WinError 5 -- in modules that had nothing to do with the leak.

The lesson worth keeping is that "green on my machine" was true and useless
here. These tests assert the property that makes both platforms work: the
handle is released, and it is released BEFORE anything tries to delete the file.
"""

from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))

from server import Storage  # noqa: E402


# --------------------------------------------------------------------------
# The API
# --------------------------------------------------------------------------

def test_close_releases_the_connection(tmp_path):
    st = Storage(str(tmp_path / "a.db"))
    st.save_key("alice", b"\x01" * 32)
    st.close()
    with pytest.raises(sqlite3.ProgrammingError):
        st.get_key("alice")


def test_close_is_idempotent(tmp_path):
    """Teardown paths can run twice; closing twice must not raise."""
    st = Storage(str(tmp_path / "b.db"))
    st.close()
    st.close()


def test_storage_works_as_a_context_manager(tmp_path):
    with Storage(str(tmp_path / "c.db")) as st:
        st.save_key("bob", b"\x02" * 32)
        assert st.get_key("bob") == b"\x02" * 32
    with pytest.raises(sqlite3.ProgrammingError):
        st.get_key("bob")


def test_close_all_closes_every_open_database(tmp_path):
    handles = [Storage(str(tmp_path / f"m{i}.db")) for i in range(3)]
    Storage.close_all()
    for st in handles:
        with pytest.raises(sqlite3.ProgrammingError):
            st.get_key("nobody")


def test_the_file_can_be_deleted_once_closed(tmp_path):
    """
    The property Windows actually enforces. Deleting an open file succeeds on
    Linux, so this passes either way here -- but if close() ever stopped
    releasing the handle, the assertion above it would fail first, and this
    documents what that failure would mean on the platform that cares.
    """
    path = tmp_path / "d.db"
    st = Storage(str(path))
    st.save_key("carol", b"\x03" * 32)
    st.close()
    path.unlink()
    assert not path.exists()


# --------------------------------------------------------------------------
# The ordering invariant, in the harnesses that own a database and a directory
# --------------------------------------------------------------------------

RELAY_HARNESSES = [
    ("test_real_tls.py", "_storage.close()", "_tmpdir.cleanup()"),
    ("test_verification_relay.py", "storage.close()", None),
]


@pytest.mark.parametrize("module,close_call,cleanup_call",
                         RELAY_HARNESSES,
                         ids=[m for m, _, _ in RELAY_HARNESSES])
def test_relay_harness_closes_its_database(module, close_call, cleanup_call):
    """
    Each harness that starts a relay must close the database in its teardown,
    and must do so BEFORE removing the directory holding it. Getting that order
    wrong is precisely what produced WinError 32.
    """
    src = (REPO_ROOT / "tests" / module).read_text(encoding="utf-8")
    exit_idx = src.index("async def __aexit__")
    body = src[exit_idx:exit_idx + 900]

    assert close_call in body, (
        f"{module}: the relay harness never closes its database in __aexit__"
    )
    if cleanup_call:
        assert body.index(close_call) < body.index(cleanup_call), (
            f"{module}: the directory is removed before the database is "
            f"closed; on Windows that raises WinError 32"
        )


def test_the_suite_has_an_autouse_database_teardown():
    """
    conftest.py must close databases after every test. Relying on each module to
    remember would reproduce the original bug the first time somebody forgot.
    """
    conftest = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert "autouse=True" in conftest
    assert "Storage.close_all()" in conftest


def test_temporary_directories_holding_databases_tolerate_locks():
    """
    Any TemporaryDirectory that will contain a .db must be created with
    ignore_cleanup_errors, because it deletes eagerly and RAISES otherwise --
    turning a transient lock into a red test rather than a warning.
    """
    src = (REPO_ROOT / "tests" / "test_real_tls.py").read_text(encoding="utf-8")
    for m in re.finditer(r"TemporaryDirectory\(([^)]*)\)", src):
        window = src[m.end():m.end() + 300]
        if ".db" in window:
            assert "ignore_cleanup_errors" in m.group(1), (
                "a TemporaryDirectory that holds a database was created "
                "without ignore_cleanup_errors"
            )
