"""
test_suite_hygiene.py -- the parts of tests/ that pytest never touches.

Seventeen of the thirty-seven files in this folder are pytest modules. The other
twenty -- standalone harnesses, vector generators, the MITM instrument, the
reference oracles and two Markdown guides -- are run by hand, or not at all. A
review that counts only `test_*.py` therefore misses most of the directory, and
that is exactly what happened: none of them had ever been checked.

They had rotted quietly:

  * tests/mitm_relay.py, the Tier-A MITM instrument, is a near-copy of
    server.py. It had NOT tracked a single change made to the real relay, so it
    no longer spoke the same protocol. Most seriously it lacked the
    verify_resync branch, meaning a verification episode could stall during an
    experiment for a reason that had nothing to do with the attack under study
    -- the instrument distorting its own measurement.

  * RATCHET_TESTING.md gave three paths for the reference oracles that no longer
    existed; the files had moved into reference_oracles/ and the guide had not.

Neither would ever fail a test, because nothing ran them. These checks are cheap
and mechanical, and they turn silent rot into a red line.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS = REPO_ROOT / "tests"
SERVER = REPO_ROOT / "server" / "server.py"


def _dispatch_types(path: Path) -> set[str]:
    return set(re.findall(r'mtype == "([a-z_]+)"',
                          path.read_text(encoding="utf-8", errors="replace")))


# --------------------------------------------------------------------------
# The MITM instrument must stay faithful to the relay it imitates
# --------------------------------------------------------------------------

def test_mitm_relay_speaks_the_same_protocol_as_the_server():
    """
    An instrument that has drifted from the system under test measures the
    drift. Every message type the real relay dispatches must also be dispatched
    here, or a client talking to the MITM relay behaves differently for reasons
    unrelated to the experiment.
    """
    real = _dispatch_types(SERVER)
    fake = _dispatch_types(TESTS / "mitm_relay.py")
    missing = sorted(real - fake)
    assert not missing, (
        "tests/mitm_relay.py does not handle these types, which server.py does: "
        f"{missing}. The MITM experiment would silently drop them."
    )


def test_mitm_relay_closes_its_database():
    """
    Same Windows file-locking rule as the real relay: an unclosed SQLite handle
    makes the database file undeletable. See tests/test_sqlite_lifecycle.py.
    """
    src = (TESTS / "mitm_relay.py").read_text(encoding="utf-8", errors="replace")
    assert "def close(self)" in src, "mitm_relay.Storage has no close()"


# --------------------------------------------------------------------------
# Nothing in tests/ may be syntactically dead
# --------------------------------------------------------------------------

def _standalone_python() -> list[Path]:
    """Every .py in tests/ that pytest does NOT collect."""
    return sorted(p for p in TESTS.rglob("*.py")
                  if not p.name.startswith("test_") and p.name != "conftest.py")


# The helper scripts that belong in tests/, BY NAME.
#
# _standalone_python() above is a glob, and the family it parametrises has the
# same property the guides' glob had: dropping a file into tests/ does not fail
# anything, it ADDS a test. The suite quietly grows, tests/README.md's total no
# longer matches, and the only symptom is two red tests naming README.md -- so a
# misplaced file reads as a documentation error. That has now happened twice in
# a row with the same file: tools/sync_test_readme.py placed in tests/ instead.
#
# These are helpers only. Test modules are excluded by _standalone_python(), so
# adding a new test_*.py needs no entry here and this list stays stable.
KNOWN_HELPERS = {
    "e2ee_redteam.py",
    "gen_x3dh_vectors.py",
    "live_harness.py",
    "make_ratchet_vectors.py",
    "make_vector.py",
    "mitm_relay.py",
    "pcs_lifecycle_verify.py",
    "pcs_logic_model.py",
    "ratchet.py",
    "ratchet_cli.py",
    "reference_oracles/_ref_ratchet.py",
    "x3dh.py",
}


# Helpers that belong somewhere else in this repository. A stray whose name is
# listed here is a misplaced file rather than a new helper, and the failure can
# say where it goes instead of guessing.
MISPLACED_HELPERS = {
    "sync_test_readme.py": "tools",
}


def test_helper_scripts_are_the_known_set():
    """A stray helper in tests/ must fail by name, not by inflating a count."""
    found = {str(p.relative_to(TESTS)).replace("\\", "/")
             for p in _standalone_python()}

    strays = sorted(found - KNOWN_HELPERS)
    # Say WHERE a misplaced file goes, not merely that it is unexpected.
    #
    # The first version of this check inferred "misplaced" from a copy already
    # existing in tools/. That inference only holds once the file is in the
    # right place, which is exactly when nobody needs telling -- and when the
    # only copy is the one in tests/, it fell through to "if deliberate, add to
    # KNOWN_HELPERS". That is the opposite of the right advice: following it
    # would have written the wrong layout into the allowlist and made the
    # mistake permanent. A check that gives confident wrong guidance is worse
    # than one that stays quiet.
    #
    # So the destination is stated outright for the files that have one.
    hints = []
    for s in strays:
        dest = MISPLACED_HELPERS.get(Path(s).name)
        if dest:
            here = "already there too; delete this copy" \
                if (REPO_ROOT / dest / Path(s).name).is_file() \
                else "move it there"
            hints.append(f"{s} belongs in {dest} ({here})")
        else:
            hints.append(f"{s} -- if deliberate, add it to KNOWN_HELPERS")
    assert not strays, (
        "unexpected helper script(s) in tests/, where pytest collects every "
        "non-test .py file as a test of its own: " + "; ".join(hints)
    )

    vanished = sorted(KNOWN_HELPERS - found)
    assert not vanished, (
        f"helper script(s) missing from tests/: {vanished}. Each is referenced "
        f"by the suite or the guides; if one was retired deliberately, drop it "
        f"from KNOWN_HELPERS in the same change."
    )


@pytest.mark.parametrize("path", _standalone_python(),
                         ids=lambda p: str(p.relative_to(TESTS)))
def test_standalone_script_still_parses(path: Path):
    """
    These are never imported by the suite, so a syntax error introduced during
    a refactor would sit undetected until the day somebody needed the script --
    which, for a thesis instrument, is the worst possible moment.

    Parsing is a weak check; it will not catch a broken import or a renamed
    function. It is chosen deliberately: importing them would execute
    module-level code, and several open sockets or write files. A cheap check
    that runs is worth more than a thorough one that does not.
    """
    ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))


# --------------------------------------------------------------------------
# The guides must point at files that exist
# --------------------------------------------------------------------------

DOCS = sorted(TESTS.glob("*.md"))

# The guides this suite expects to find, BY NAME.
#
# DOCS above is a glob, and a glob has a property that is easy to miss: deleting
# a guide does not fail anything, it removes a test. The suite gets quieter as
# the project loses documents. That is exactly backwards, and it has already
# happened once -- three of these four went missing and the only symptom was
# tests/README.md appearing to overstate the total, which reads like a
# bookkeeping error in the README rather than three deleted files.
#
# Naming them turns a silent shrink into a named failure. A guide that is
# genuinely retired should be removed from this tuple in the same commit that
# deletes it, which is the deliberate decision the census test below asks for
# everywhere else in this directory.
REQUIRED_DOCS = (
    "E2EE_REDTEAM_PLAN.md",
    "RATCHET_TESTING.md",
    "README.md",
    "TESTS_INTEGRATION.md",
)


def test_every_required_guide_is_present():
    """The guides are part of the deliverable, not incidental files."""
    present = {p.name for p in TESTS.glob("*.md")}
    missing = sorted(set(REQUIRED_DOCS) - present)
    assert not missing, (
        f"tests/ is missing these guides: {missing}. They are referenced by "
        f"this suite and by the thesis; if one was retired deliberately, drop "
        f"it from REQUIRED_DOCS in the same change."
    )


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_documented_paths_exist(doc: Path):
    """
    A guide that names a file which has moved is worse than no guide: the reader
    assumes their setup is wrong rather than the instructions. Placeholders in
    angle brackets are skipped, being obviously not literal paths.
    """
    text = doc.read_text(encoding="utf-8", errors="replace")
    referenced = set(re.findall(r"tests/[A-Za-z0-9_./-]*\.(?:py|cpp|md)", text))
    missing = sorted(r for r in referenced
                     if "<" not in r and not (REPO_ROOT / r).exists())
    assert not missing, f"{doc.name} references files that do not exist: {missing}"


def test_reference_oracles_are_present():
    """
    The oracles are the independent implementations the ratchet is checked
    against. Losing one silently would remove a cross-check while leaving every
    test green, which is the most dangerous kind of gap.
    """
    oracles = TESTS / "reference_oracles"
    for name in ("_ref_ratchet.py", "_ref_interop_recv.cpp", "interop_ratchet.cpp"):
        assert (oracles / name).is_file(), f"missing reference oracle: {name}"


def test_every_file_in_tests_is_accounted_for():
    """
    A census. If a file appears in tests/ that fits none of the known
    categories, this fails and asks for a deliberate decision about it, rather
    than letting an orphan accumulate unnoticed.
    """
    known_suffixes = {".py", ".cpp", ".md", ".json", ".txt"}
    strays = [p.relative_to(TESTS) for p in TESTS.rglob("*")
              if p.is_file()
              and "__pycache__" not in p.parts
              and p.suffix not in known_suffixes]
    assert not strays, f"unclassified files in tests/: {strays}"


# --------------------------------------------------------------------------
# Generators must RUN, not merely parse
# --------------------------------------------------------------------------
#
# test_standalone_script_still_parses above is deliberately weak: it only
# compiles the file. That weakness was demonstrated immediately. The Tier 2
# vector generator parsed perfectly while being thoroughly broken -- it
# referenced ratchet.CIPHER_TAG, a constant removed when ratchet.py gained
# hybrid-cipher support, and it built headers without the cipher field that
# decrypt() now requires. Two separate API drifts, both invisible to a parse.
#
# The generator is cheap and side-effect-light, so it can simply be run. That
# also gives the Python half of Tier 2 coverage in the ordinary pytest run,
# on machines with no C++ compiler at all.

def test_ratchet_vector_generator_runs_and_self_checks(tmp_path):
    """
    Build a five-message session and replay it. This is Tier 2 minus the C++
    half: it proves the vector is complete and self-consistent, which is the
    precondition for the cross-language check being meaningful at all.
    """
    import subprocess
    import sys as _sys

    result = subprocess.run(
        [_sys.executable, str(TESTS / "make_ratchet_vectors.py"), "--check"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, (
        "tests/make_ratchet_vectors.py failed. It is the Tier 2 vector "
        f"generator and nothing else exercises it.\n{result.stdout}\n{result.stderr}"
    )
    assert "messages decrypted, all match" in result.stdout, result.stdout


def test_the_vector_matches_the_cipher_the_cpp_oracle_expects():
    """
    The Tier 2 oracle hardcodes one cipher tag. A vector built under a
    different one fails across the language boundary for a reason that has
    nothing to do with correctness, which is the most misleading kind of
    failure.
    """
    oracle = (TESTS / "reference_oracles" / "_ref_interop_recv.cpp").read_text(
        encoding="utf-8", errors="replace")
    m = re.search(r'kCipherTag\s*=\s*"([^"]+)"', oracle)
    assert m, "could not find kCipherTag in the C++ oracle"
    expected = m.group(1)

    gen = (TESTS / "make_ratchet_vectors.py").read_text(encoding="utf-8")
    assert "CIPHER_XCHACHA" in gen, (
        "the generator does not pin a cipher explicitly"
    )
    ratchet_src = (TESTS / "ratchet.py").read_text(encoding="utf-8")
    m2 = re.search(r'CIPHER_XCHACHA\s*=\s*"([^"]+)"', ratchet_src)
    assert m2 and m2.group(1) == expected, (
        f"generator pins CIPHER_XCHACHA={m2.group(1) if m2 else '?'} but the "
        f"C++ oracle expects {expected}"
    )


# --------------------------------------------------------------------------
# The interop runner must agree with the product build about libsodium
# --------------------------------------------------------------------------
#
# run_interop.sh compiles the C++ oracles, so it has to find libsodium the same
# way client/CMakeLists.txt does. An earlier version did not: it treated
# client/third_party/libsodium as a desktop library because one of its folders
# is called x86_64. That folder is an ANDROID NDK ABI name -- CMakeLists indexes
# the directory by CMAKE_ANDROID_ARCH_ABI -- and the archives inside are ELF.
# MinGW skipped them silently and reported every libsodium symbol as undefined,
# which looks like a missing library rather than a wrong one.

RUN_INTEROP = REPO_ROOT / "run_interop.sh"
CLIENT_CMAKE = REPO_ROOT / "client" / "CMakeLists.txt"


@pytest.mark.skipif(not RUN_INTEROP.exists(), reason="run_interop.sh not present")
def test_interop_runner_uses_the_same_windows_sodium_as_cmake():
    """Both must point at the MinGW build, and must allow the same override."""
    cmake = CLIENT_CMAKE.read_text(encoding="utf-8", errors="replace")
    script = RUN_INTEROP.read_text(encoding="utf-8", errors="replace")

    m = re.search(r'set\(SODIUM_ROOT\s+"([^"]+)"\s+CACHE', cmake)
    assert m, "could not find the Windows SODIUM_ROOT default in CMakeLists.txt"
    default_root = m.group(1)

    assert default_root in script, (
        f"run_interop.sh does not use the same Windows libsodium root as the "
        f"product build ({default_root}). If they disagree, the harness can "
        f"link a different library from the application it is validating."
    )
    assert "SODIUM_ROOT" in script, "the script does not honour a SODIUM_ROOT override"


@pytest.mark.skipif(not RUN_INTEROP.exists(), reason="run_interop.sh not present")
def test_interop_runner_does_not_treat_the_android_libs_as_desktop():
    """
    client/third_party/libsodium may be MENTIONED (the script explains why it is
    unsuitable) but must never be used as an include or library path.
    """
    script = RUN_INTEROP.read_text(encoding="utf-8", errors="replace")
    for bad in ('-I' + "client/third_party/libsodium",
                '-L' + "client/third_party/libsodium",
                'client/third_party/libsodium/x86_64/libsodium.a"'):
        assert bad not in script, (
            f"run_interop.sh uses {bad}; that path holds Android NDK archives "
            f"and cannot be linked by a desktop compiler."
        )


def test_vendored_libsodium_is_android_only():
    """
    Pin the fact that caused the confusion, so anyone reading the tests learns
    it without repeating the diagnosis. These folder names are Android ABIs.
    """
    vendored = REPO_ROOT / "client" / "third_party" / "libsodium"
    if not vendored.is_dir():
        pytest.skip("vendored libsodium not present in this checkout")
    abis = {d.name for d in vendored.iterdir() if d.is_dir() and d.name != "include"}
    assert abis <= {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}, (
        f"unexpected folders under third_party/libsodium: {sorted(abis)}"
    )
    cmake = CLIENT_CMAKE.read_text(encoding="utf-8", errors="replace")
    assert "CMAKE_ANDROID_ARCH_ABI" in cmake, (
        "third_party/libsodium is expected to be indexed by Android ABI"
    )


@pytest.mark.skipif(not RUN_INTEROP.exists(), reason="run_interop.sh not present")
def test_interop_runner_never_puts_a_windows_path_on_PATH():
    """
    Git Bash resolves PATH entries in POSIX form. A "C:/..." entry is silently
    ignored -- not rejected, ignored -- so the directory it names is simply
    absent. That is how the libsodium DLL directory went missing while the
    script reported it as configured, and the resulting failure surfaced as an
    empty reply from a child process rather than as a missing DLL.
    """
    script = RUN_INTEROP.read_text(encoding="utf-8", errors="replace")
    for line in script.splitlines():
        code = line.split("#", 1)[0]
        if "export PATH=" not in code:
            continue
        assert not re.search(r'export PATH="[A-Za-z]:', code), (
            f"a Windows-form path is exported onto PATH: {line.strip()}"
        )
        # A literal drive letter is the obvious case; the one that actually
        # happened was a VARIABLE holding a Windows path. SODIUM_BIN and
        # SODIUM_ROOT come straight from CMake-style "C:/..." values, so they
        # must pass through the converter before reaching PATH.
        for var in ("SODIUM_BIN", "SODIUM_ROOT"):
            if var in code:
                assert "to_posix" in code, (
                    f"${var} is put on PATH without POSIX conversion: "
                    f"{line.strip()}"
                )
    assert "to_posix" in script, (
        "the script has no POSIX conversion helper for Windows paths"
    )


@pytest.mark.skipif(not RUN_INTEROP.exists(), reason="run_interop.sh not present")
def test_interop_preflight_executes_the_probe():
    """
    Linking proves the import library was found; only running proves the DLL is
    there too. A preflight that merely links lets a missing runtime DLL through
    to the harness, where it looks like a protocol bug.
    """
    script = RUN_INTEROP.read_text(encoding="utf-8", errors="replace")
    probe_idx = script.index("preflight()")
    body = script[probe_idx:probe_idx + 2500]
    assert '"$BUILD_DIR/_probe$EXE" >/dev/null' in body, (
        "preflight() links the probe but never runs it"
    )


# --------------------------------------------------------------------------
# Documented numbers must match reality
# --------------------------------------------------------------------------
#
# tests/README.md carries a total and a per-module table. Both have now been
# corrected by hand three times, each time only because someone happened to
# notice. A count in a document is a claim, and an unchecked claim in a testing
# guide is worse than no claim: it teaches the reader that the guide is
# approximate, which is exactly the habit a thesis reader should not acquire.

README_MD = TESTS / "README.md"


def _collected_counts() -> dict[str, int]:
    """Ask pytest what actually exists, rather than trusting a stored number."""
    import subprocess
    import sys as _sys

    r = subprocess.run(
        [_sys.executable, "-m", "pytest", str(TESTS), "-q", "--collect-only"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
    )
    counts: dict[str, int] = {}
    for line in r.stdout.splitlines():
        if "::" not in line:
            continue
        mod = line.split("::", 1)[0].split("/")[-1].split("\\")[-1]
        if mod.startswith("test_"):
            counts[mod] = counts.get(mod, 0) + 1
    return counts


@pytest.mark.skipif(not README_MD.exists(), reason="tests/README.md not present")
def test_readme_total_matches_the_suite():
    counts = _collected_counts()
    total = sum(counts.values())
    text = README_MD.read_text(encoding="utf-8", errors="replace")

    claimed = {int(m) for m in re.findall(r"\*\*(\d+) tests across", text)}
    claimed |= {int(m) for m in re.findall(r"`(\d+) passed`", text)}
    assert claimed, "README.md states no total at all"
    wrong = sorted(c for c in claimed if c != total)
    assert not wrong, (
        f"README.md claims {wrong} tests; the suite collects {total}."
    )


@pytest.mark.skipif(not README_MD.exists(), reason="tests/README.md not present")
def test_readme_lists_every_module_with_the_right_count():
    counts = _collected_counts()
    text = README_MD.read_text(encoding="utf-8", errors="replace")

    rows = dict()
    for name, num in re.findall(r"\|\s*`(test_[a-z0-9_]+\.py)`\s*\|\s*(\d+)\s*\|", text):
        rows[name] = int(num)

    missing = sorted(set(counts) - set(rows))
    assert not missing, f"README.md's table omits these modules: {missing}"

    wrong = {m: (rows[m], counts[m]) for m in rows if m in counts and rows[m] != counts[m]}
    assert not wrong, (
        "README.md's table disagrees with the suite "
        f"(module: documented -> actual): {wrong}"
    )


# The two tests above guard themselves with skipif when README.md is absent;
# this one read it unconditionally, so a tree without the guides did not report
# "documentation missing" -- it raised a raw FileNotFoundError from inside
# pathlib, three frames deep, in a module whose siblings had skipped quietly.
# That is what a source archive packaged without tests/*.md looked like when its
# own suite was run against it, and the traceback said nothing about the cause.
# Guarded the same way as its siblings, so the three tests that read this file
# now behave identically when it is not there.
@pytest.mark.skipif(not README_MD.exists(), reason="tests/README.md not present")
@pytest.mark.skipif(not (TESTS / "RATCHET_TESTING.md").exists(),
                    reason="tests/RATCHET_TESTING.md not present")
def test_the_one_click_runners_are_documented():
    """
    A command nobody can find is a command nobody runs. run_interop.sh existed
    for a while without appearing in either guide.
    """
    readme = README_MD.read_text(encoding="utf-8", errors="replace")
    ratchet = (TESTS / "RATCHET_TESTING.md").read_text(encoding="utf-8", errors="replace")
    for doc, name in ((readme, "README.md"), (ratchet, "RATCHET_TESTING.md")):
        assert "run_interop.sh" in doc, f"{name} never mentions run_interop.sh"
        assert "run_tests.sh" in doc, f"{name} never mentions run_tests.sh"
