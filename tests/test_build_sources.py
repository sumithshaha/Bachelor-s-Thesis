"""
test_build_sources.py -- every client source must be in the build.

WHY THIS EXISTS

x3dh.cpp was added to client/src/ and not to client/CMakeLists.txt. Nothing
complained: the header resolved, every file that used it compiled, and the
failure appeared only at LINK time as a wall of undefined symbols on both
Windows and Android. The code was correct throughout; only the build list was
wrong.

The sandbox tests that exercise the crypto could not have caught it, because
they name the .cpp files on the compiler command line themselves. A build-system
omission is invisible to a test that supplies its own file list -- so this checks
the build list itself, which is the only thing that was actually broken.
"""
from __future__ import annotations

import os
import re

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "client", "src")
_CMAKE = os.path.join(_ROOT, "client", "CMakeLists.txt")

# Files deliberately excluded from the target. Platform sources that CMake adds
# conditionally belong here with a reason, so an omission has to be argued for
# rather than merely happening.
_INTENTIONALLY_ABSENT: dict[str, str] = {}


def _cmake_text() -> str:
    assert os.path.exists(_CMAKE), f"missing {_CMAKE}"
    with open(_CMAKE, encoding="utf-8") as f:
        return f.read()


def _sources() -> list[str]:
    assert os.path.isdir(_SRC), f"missing {_SRC}"
    return sorted(f for f in os.listdir(_SRC) if f.endswith((".cpp", ".h")))


def test_client_src_is_not_empty():
    """A guard on the guard: if the directory scan silently returned nothing,
    every check below would pass vacuously."""
    assert len(_sources()) > 10


@pytest.mark.parametrize("name", _sources())
def test_every_client_source_is_in_the_build(name):
    if name in _INTENTIONALLY_ABSENT:
        pytest.skip(_INTENTIONALLY_ABSENT[name])
    text = _cmake_text()
    assert f"src/{name}" in text, (
        f"client/src/{name} is not listed in client/CMakeLists.txt.\n"
        "A source that compiles but is never linked fails only at link time, "
        "with undefined symbols that point at the CALLER rather than at the "
        "missing file. Add it to the target, or record it in "
        "_INTENTIONALLY_ABSENT with the reason."
    )


def test_x3dh_specifically_is_built():
    """The regression this file was written for, pinned by name so it cannot be
    lost in a parametrised sweep."""
    text = _cmake_text()
    for f in ("src/x3dh.cpp", "src/x3dh.h"):
        assert f in text, f"{f} must be in the build target"


def test_the_check_would_catch_a_removal():
    """Confirm the assertion actually depends on the file being listed -- a test
    that passes for the wrong reason is worse than no test."""
    text = _cmake_text().replace("src/x3dh.cpp", "src/NOT_LISTED.cpp")
    assert "src/x3dh.cpp" not in text


def test_no_source_is_listed_twice():
    """A duplicate entry compiles the translation unit twice and can produce
    duplicate-symbol errors that look nothing like their cause."""
    text = _cmake_text()
    for name in _sources():
        # Count only list entries, not mentions inside comments.
        entries = re.findall(rf"^\s*src/{re.escape(name)}\s*$", text, re.M)
        assert len(entries) <= 1, f"src/{name} is listed {len(entries)} times"
