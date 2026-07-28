"""
conftest.py -- shared teardown for the whole suite.

WHY THIS EXISTS
---------------
Every test that starts a relay opens a SQLite database, and until recently
nothing ever closed one. On Linux that is harmless: an open file can still be
unlinked, so temporary directories clean up and the suite is green.

On Windows an open handle blocks deletion, and the suite failed in two ways at
once:

    PermissionError: [WinError 32] The process cannot access the file
    because it is being used by another process
        ... on tmp\\birthday.db, tmp\\tls_test.db

    PermissionError: [WinError 5] Access is denied:
    'C:\\Users\\...\\AppData\\Local\\Temp\\pytest-of-<user>'

The second is the more confusing of the two, and it is a CASCADE rather than an
independent fault. pytest keeps the last few tmp_path run directories and
deletes older ones on the next run. Once a leaked handle made one of those
undeletable, the base directory itself could no longer be maintained, and every
later test that merely ASKED for tmp_path failed during setup -- in modules that
had nothing to do with the original leak.

The fixture below closes every database at the end of each test, so no handle
outlives the test that opened it. It is autouse deliberately: relying on each
module to remember would reproduce the same bug the first time somebody forgot.
"""

from __future__ import annotations

import gc
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))

from server import Storage  # noqa: E402


@pytest.fixture(autouse=True)
def _close_databases_after_each_test():
    """Close every SQLite connection opened during the test."""
    yield
    Storage.close_all()
    # sqlite3 releases the file handle when the connection object is finalised;
    # close_all() covers the ones we know about, and the collection sweeps up
    # any connection held only by a cycle. Cheap, and it makes teardown
    # deterministic rather than dependent on when the collector next runs.
    gc.collect()
