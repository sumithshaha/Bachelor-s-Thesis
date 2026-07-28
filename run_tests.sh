#!/usr/bin/env bash
# run_tests.sh -- one command to install dependencies and run the ChatE2EE tests.
# Works in Git Bash (MINGW64) on Windows and in bash on Linux/macOS.
#
#   bash run_tests.sh              # install deps, run the red-team harness, then
#                                  # the WHOLE test suite (pytest tests/)
#   bash run_tests.sh --fast       # skip the slower self-hosting tests; run only
#                                  # the quick offline crypto/unit tests
#   bash run_tests.sh --no-install # skip 'pip install' (dependencies already present)
#
# The whole suite is expected to pass with zero failures. The async tests spin up
# their OWN in-process relay, so no external server is needed; they bind fixed
# localhost ports (8791, 8799, ...), so don't run them while something else holds
# those ports.
set -eu

# Always operate from the repo root (this script's own directory), whatever the
# current working directory is.
cd "$(dirname "$0")"

# --- Pick a Python 3 launcher: 'python', then the Windows 'py' launcher, then
#     'python3'. The version probe skips the Microsoft Store stub, which is not a
#     real interpreter, and falls through to 'py'.
PY=""
for cand in python py python3; do
  if command -v "$cand" >/dev/null 2>&1 \
     && "$cand" -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" >/dev/null 2>&1; then
    PY="$cand"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "ERROR: no Python 3 found on PATH." >&2
  echo "Install it from https://python.org/downloads and tick 'Add python.exe to PATH'." >&2
  exit 1
fi
echo ">> Using Python: $($PY --version 2>&1)  [$PY]"

# --- Record the environment ---------------------------------------------------
# A result is only reproducible if you can say what produced it. Printing the
# versions here means the saved output of a run identifies its own environment,
# so a later failure can be attributed to the code or to a dependency that moved
# under it -- rather than being unattributable a year after the fact.
#
# A pre-release interpreter is called out explicitly. Betas and release
# candidates are legitimate to develop against, but a reported result should say
# so rather than leave the reader to notice.
echo ">> Environment:"
"$PY" - <<'PYVER'
import platform, sys
v = sys.version_info
tag = "" if v.releaselevel == "final" else f"   <-- PRE-RELEASE ({v.releaselevel}{v.serial})"
print(f"     python          {platform.python_version()}  on {sys.platform}{tag}")
for mod, name in (("cryptography", "cryptography"), ("nacl", "pynacl"),
                  ("pytest", "pytest"), ("pytest_asyncio", "pytest-asyncio"),
                  ("websockets", "websockets")):
    try:
        m = __import__(mod)
        print(f"     {name:<15} {getattr(m, '__version__', '?')}")
    except ImportError:
        print(f"     {name:<15} NOT INSTALLED")
PYVER

INSTALL=1
FAST=0
for arg in "$@"; do
  case "$arg" in
    --no-install) INSTALL=0 ;;
    --fast)       FAST=1 ;;
    -h|--help)
      sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

if [ "$INSTALL" -eq 1 ]; then
  echo ">> Installing dependencies from requirements.txt ..."
  "$PY" -m pip install -r requirements.txt
fi

# --- Lab certificate authority ------------------------------------------------
# tests/test_real_tls.py runs a genuine TLS handshake against the real relay and
# needs pki/server.crt + pki/server.key to exist. Generating it here (only when
# it is missing) keeps the suite self-contained: a fresh checkout runs green with
# one command, and the TLS tests never quietly skip. Re-running is a no-op
# because the generator keeps an existing root.
if [ ! -f pki/server.crt ] || [ ! -f pki/server.key ]; then
  echo ""
  echo ">> Generating the lab certificate authority (first run only) ..."
  "$PY" tools/make_demo_pki.py >/dev/null || {
    echo "!! Could not generate the lab PKI; TLS tests will skip." >&2
  }
fi

echo ""
echo ">> Red-team harness (drives crypto_core.py + file_crypto.py):"
PYTHONPATH=server "$PY" tests/e2ee_redteam.py

echo ""
if [ "$FAST" -eq 1 ]; then
  echo ">> Quick tests only (--fast): offline crypto/unit tests:"
  # Only the fast, self-contained modules -- and only those actually present, so
  # this works whether or not the advanced modules have been added yet.
  CANDIDATE_TESTS="
    tests/test_crypto.py
    tests/test_ratchet.py
    tests/test_post_compromise.py
    tests/test_safety_number.py
    tests/test_x3dh.py
    tests/test_ratchet_fuzz.py
    tests/test_security_invariants.py
    tests/test_file_e2ee_advanced.py
  "
  FAST_TESTS=""
  for t in $CANDIDATE_TESTS; do
    [ -f "$t" ] && FAST_TESTS="$FAST_TESTS $t"
  done
  if [ -z "$FAST_TESTS" ]; then
    echo "!! No quick test files found under tests/." >&2
    exit 1
  fi
  # shellcheck disable=SC2086  # intentional word-splitting of the file list
  "$PY" -m pytest $FAST_TESTS -v
else
  echo ">> Whole test suite (pytest tests/):"
  # The async tests spin up their own in-process relay, so the whole folder runs
  # green with no external server -- needs pytest-asyncio + websockets, both in
  # requirements.txt.
  "$PY" -m pytest tests/ -v
fi

echo ""
echo ""
echo ">> Cross-language proofs (Python <-> C++) are a separate command,"
echo "   because they need a C++ compiler:"
echo "       bash run_interop.sh"
echo ""
echo ">> Done."
