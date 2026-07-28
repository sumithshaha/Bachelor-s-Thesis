#!/usr/bin/env bash
#
# run_interop.sh -- the cross-language proofs, in one command.
#
#     bash run_interop.sh
#
# Runs the three procedures that RATCHET_TESTING.md describes as manual
# multi-step recipes:
#
#   Tier 2  Sequence interop      Python encrypts a 5-message session; an
#                                 independent C++ implementation decrypts it.
#   Tier 3  Live bidirectional    Python and C++ hold a real conversation,
#           harness               direction alternating every turn so a DH
#                                 ratchet fires on each one.
#   Hybrid  AES-256-GCM with an   The same conversation with one side on
#           XChaCha20 fallback    AES-256-GCM and the other on XChaCha20,
#                                 each decrypting the other by reading the
#                                 cipher tag.
#
# WHY THIS SCRIPT EXISTS
# ----------------------
# These were documented as commands to type by hand: compile two C++ files with
# the right include and library flags, then invoke the harness four different
# ways. Every step is easy to get subtly wrong, and none of it was reachable
# from pytest -- so the strongest evidence in the whole project was also the
# least likely to be re-run. Evidence nobody re-runs decays into a claim.
#
# Selective use:
#     bash run_interop.sh --tier2      only the sequence interop
#     bash run_interop.sh --tier3      only the live harness
#     bash run_interop.sh --hybrid     only the mixed-cipher matrix
#     bash run_interop.sh --keep       leave the built binaries in place
#
set -u

cd "$(dirname "$0")"

RUN_T2=1; RUN_T3=1; RUN_HY=1; KEEP=0
if [ $# -gt 0 ]; then
  RUN_T2=0; RUN_T3=0; RUN_HY=0
  for arg in "$@"; do
    case "$arg" in
      --tier2)  RUN_T2=1 ;;
      --tier3)  RUN_T3=1 ;;
      --hybrid) RUN_HY=1 ;;
      --keep)   KEEP=1 ;;
      --all)    RUN_T2=1; RUN_T3=1; RUN_HY=1 ;;
      *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
  done
  # --keep on its own still means "run everything".
  if [ "$RUN_T2$RUN_T3$RUN_HY" = "000" ]; then RUN_T2=1; RUN_T3=1; RUN_HY=1; fi
fi

BUILD_DIR="build-interop"
PASS=0
FAIL=0
SKIP=0

ok()   { echo "   PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "   FAIL  $*"; FAIL=$((FAIL+1)); }
note() { echo "         $*"; }

banner() {
  echo ""
  echo "=========================================================================="
  echo "$*"
  echo "=========================================================================="
}

# --------------------------------------------------------------------------
# Toolchain discovery
# --------------------------------------------------------------------------

# Python. Same probe order as run_tests.sh, and the same reason: on Windows the
# bare name 'python' can resolve to the Microsoft Store stub, which is not an
# interpreter and exits without running anything.
PY=""
for cand in python python3 py; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c "import sys; sys.exit(0)" >/dev/null 2>&1; then PY="$cand"; break; fi
  fi
done
if [ -z "$PY" ]; then
  echo "No usable Python found. Install Python 3.10+ and re-run." >&2
  exit 1
fi

# Platform. MSYS/MinGW (Git Bash) reports MINGW64_NT-... from uname.
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1; EXE=".exe" ;;
  *)                    IS_WINDOWS=0; EXE="" ;;
esac

# C++ compiler. On Windows the Qt installation ships MinGW, and it is usually
# not on PATH in Git Bash, so look for it where Qt puts it before giving up.
CXX=""
if command -v g++ >/dev/null 2>&1; then
  CXX="g++"
elif command -v clang++ >/dev/null 2>&1; then
  CXX="clang++"
elif [ "$IS_WINDOWS" -eq 1 ]; then
  for c in /c/Qt/Tools/mingw*/bin/g++.exe /c/Qt/Tools/mingw*_64/bin/g++.exe; do
    [ -x "$c" ] && { CXX="$c"; break; }
  done
fi

# libsodium. Where it lives is NOT a guess: client/CMakeLists.txt already
# states it for each platform, and this script now follows the same rules so the
# harness and the product build cannot disagree.
#
#   Windows  C:/libsodium/libsodium-win64   (from libsodium-1.0.20-stable-mingw
#            .tar.gz), linking lib/libsodium.dll.a and needing bin/libsodium-26
#            .dll at runtime. Overridable with SODIUM_ROOT, exactly as CMake
#            allows.
#   Linux    system libsodium (libsodium-dev)
#   macOS    system libsodium (brew), including the Homebrew prefix on ARM
#
# NOT client/third_party/libsodium. That directory is ANDROID ONLY: CMakeLists
# indexes it by CMAKE_ANDROID_ARCH_ABI, so "x86_64" there means the Android
# x86_64 emulator ABI, not desktop Windows. Its archives are ELF objects. An
# earlier version of this script mistook that folder for a desktop build, and
# MinGW's linker did what it always does with an incompatible archive: skipped
# it silently and reported every libsodium symbol as undefined, which reads like
# a missing library rather than a wrong one.
SODIUM_INC=""
SODIUM_LIB=""
SODIUM_SRC=""
SODIUM_BIN=""
ANDROID_ONLY_DIR="client/third_party/libsodium"

if [ "$IS_WINDOWS" -eq 1 ]; then
  : "${SODIUM_ROOT:=C:/libsodium/libsodium-win64}"
  # Accept the Windows form and the Git Bash form of the same path.
  for root in "$SODIUM_ROOT" "$(echo "$SODIUM_ROOT" | sed 's|^\([A-Za-z]\):|/\L\1|')"; do
    if [ -f "$root/include/sodium.h" ] && [ -f "$root/lib/libsodium.dll.a" ]; then
      SODIUM_INC="-I$root/include"
      SODIUM_LIB="$root/lib/libsodium.dll.a"
      SODIUM_BIN="$root/bin"
      SODIUM_SRC="$root"
      break
    fi
  done
else
  for inc in /usr/include /usr/local/include /opt/homebrew/include; do
    if [ -f "$inc/sodium.h" ]; then
      SODIUM_INC="-I$inc"
      SODIUM_SRC="system ($inc)"
      break
    fi
  done
  if [ -n "$SODIUM_SRC" ]; then
    SODIUM_LIB="-lsodium"
    [ -d /opt/homebrew/lib ] && SODIUM_LIB="-L/opt/homebrew/lib -lsodium"
  fi
fi

banner "ChatE2EE  --  cross-language interop, one command"
echo "   python        $($PY --version 2>&1)   [$PY]"
if [ -n "$CXX" ]; then
  echo "   c++           $($CXX --version 2>&1 | head -1)"
  echo "                 [$CXX]"
else
  echo "   c++           NOT FOUND"
fi
echo "   libsodium     ${SODIUM_SRC:-NOT FOUND}"

# Everything below needs both. Skipping is the honest outcome when the
# toolchain is absent -- but say exactly what to install, because a bare
# "skipped" teaches nobody anything.
if [ -z "$CXX" ] || [ -z "$SODIUM_SRC" ]; then
  echo ""
  echo "   Cannot run the cross-language proofs: a C++ toolchain and libsodium"
  echo "   are both required."
  echo ""
  if [ "$IS_WINDOWS" -eq 1 ]; then
    if [ -z "$CXX" ]; then
      echo "     Compiler: Qt ships MinGW, but Git Bash does not see it. Either"
      echo "     add it to PATH for this shell:"
      echo '       export PATH="/c/Qt/Tools/mingw1310_64/bin:$PATH"'
      echo "     (this script also looks there automatically)."
      echo ""
    fi
    if [ -z "$SODIUM_SRC" ]; then
      echo "     libsodium: the DESKTOP build is not present. client/CMakeLists.txt"
      echo "     expects the MinGW tarball extracted to C:/libsodium:"
      echo ""
      echo "       1. download libsodium-1.0.20-stable-mingw.tar.gz"
      echo "       2. extract so that this file exists:"
      echo "            C:/libsodium/libsodium-win64/include/sodium.h"
      echo "       3. re-run, or point at another location:"
      echo '            SODIUM_ROOT=/d/libs/libsodium-win64 bash run_interop.sh'
      echo ""
      if [ -d "$ANDROID_ONLY_DIR" ]; then
        echo "     NOTE: $ANDROID_ONLY_DIR exists, but it is"
        echo "     ANDROID only -- its arm64-v8a and x86_64 folders are NDK ABI"
        echo "     names holding ELF archives. MinGW cannot link them; it skips"
        echo "     them and every libsodium symbol appears undefined."
      fi
    fi
  else
    echo "     Debian/Ubuntu:  sudo apt-get install g++ libsodium-dev"
    echo "     macOS:          brew install libsodium"
  fi
  echo ""
  echo "   The pure-Python parts of the suite are unaffected: bash run_tests.sh"
  exit 0
fi

# --------------------------------------------------------------------------
# Build the two C++ endpoints
# --------------------------------------------------------------------------

REF_RECV="$BUILD_DIR/ref_recv$EXE"
CLI_CPP="$BUILD_DIR/ratchet_cli_cpp$EXE"

build() {
  src="$1"; out="$2"; label="$3"
  printf "   building %-22s" "$label"
  # shellcheck disable=SC2086
  if $CXX -std=c++17 -O2 $STATIC_FLAGS $SODIUM_INC "$src" $SODIUM_LIB \
        -o "$out" 2> "$BUILD_DIR/$label.log"; then
    echo "ok"
    return 0
  fi
  # A toolchain without static GCC runtime libraries is unusual but possible.
  # Retry without them rather than failing: the DLL copy and PATH below still
  # give the binary what it needs.
  # shellcheck disable=SC2086
  if [ -n "$STATIC_FLAGS" ] && \
     $CXX -std=c++17 -O2 $SODIUM_INC "$src" $SODIUM_LIB \
        -o "$out" 2>> "$BUILD_DIR/$label.log"; then
    echo "ok (dynamic runtime)"
    return 0
  fi
  echo "FAILED"
  # Show the FIRST lines, not an arbitrary slice. A linker reports its warnings
  # before the resulting errors, and the warning is usually the real cause --
  # "skipping incompatible ..." explains a hundred undefined references that
  # otherwise look like a missing library.
  sed 's/^/           /' "$BUILD_DIR/$label.log" | head -8
  if grep -qi "skipping incompatible" "$BUILD_DIR/$label.log"; then
    echo "           ^ the archive exists but is built for another platform."
  fi
  return 1
}

# PREFLIGHT. Three lines of C++ that only call sodium_init(). If the toolchain
# and libsodium do not fit together, this fails in a second and says so plainly,
# instead of the failure surfacing as a wall of undefined references from a
# 400-line source file where the cause is invisible.
preflight() {
  cat > "$BUILD_DIR/_probe.cpp" <<'PROBE'
#include <sodium.h>
int main() { return sodium_init() < 0 ? 1 : 0; }
PROBE
  printf "   checking libsodium links   "
  # shellcheck disable=SC2086
  if $CXX -std=c++17 $STATIC_FLAGS $SODIUM_INC "$BUILD_DIR/_probe.cpp" $SODIUM_LIB \
        -o "$BUILD_DIR/_probe$EXE" 2> "$BUILD_DIR/_probe.log"; then
    # LINKING IS NOT ENOUGH. On Windows a program links against an import
    # library and then fails to start if the matching DLL is absent at run
    # time. Executing the probe is what distinguishes "builds" from "works",
    # and skipping that step is exactly how a missing libsodium-26.dll reached
    # the harness disguised as a protocol failure.
    if "$BUILD_DIR/_probe$EXE" >/dev/null 2>> "$BUILD_DIR/_probe.log"; then
      echo "ok"
      rm -f "$BUILD_DIR/_probe$EXE" "$BUILD_DIR/_probe.cpp"
      return 0
    fi
    echo "LINKS BUT WILL NOT RUN"
    echo ""
    echo "   The probe compiled and linked, but the resulting program could not"
    echo "   start. On Windows that almost always means a DLL is missing at run"
    echo "   time -- linking uses the import library, starting needs the DLL."
    echo ""
    echo "   Expected next to the binary, or on PATH:"
    echo "     libsodium-26.dll        (from $SODIUM_BIN)"
    echo "     libstdc++-6.dll, libgcc_s_seh-1.dll, libwinpthread-1.dll"
    echo "     (from $(dirname "$CXX"))"
    echo ""
    sed 's/^/     /' "$BUILD_DIR/_probe.log" | tail -5
    return 1
  fi
  echo "FAILED"
  echo ""
  echo "   libsodium was found at:"
  echo "     $SODIUM_SRC"
  echo "   but a program that does nothing except call sodium_init() will not"
  echo "   link against it. The compiler and the library do not match."
  echo ""
  sed 's/^/     /' "$BUILD_DIR/_probe.log" | head -6
  echo ""
  if grep -qi "skipping incompatible" "$BUILD_DIR/_probe.log"; then
    echo "   The linker said 'skipping incompatible', which means the archive is"
    echo "   for a different platform -- typically an Android or Linux build"
    echo "   being offered to MinGW."
  elif grep -qi "undefined reference to .sodium_init" "$BUILD_DIR/_probe.log"; then
    echo "   Every symbol is undefined, which is what MinGW reports when it"
    echo "   silently skipped an incompatible archive. Check that SODIUM_ROOT"
    echo "   points at a MinGW build of libsodium, not an Android or MSVC one."
  fi
  echo ""
  echo "   Expected (per client/CMakeLists.txt):"
  echo "     C:/libsodium/libsodium-win64/include/sodium.h"
  echo "     C:/libsodium/libsodium-win64/lib/libsodium.dll.a"
  echo "   from libsodium-1.0.20-stable-mingw.tar.gz"
  return 1
}

banner "Compiling the independent C++ implementations"

# RUNTIME DEPENDENCIES ON WINDOWS.
#
# A MinGW-built executable needs DLLs that linking alone does not supply:
#
#   libsodium-26.dll                     from $SODIUM_ROOT/bin
#   libstdc++-6.dll, libgcc_s_seh-1.dll,
#   libwinpthread-1.dll                  from the compiler's own bin directory
#
# Neither directory is necessarily on PATH: this script finds g++ by globbing
# under C:/Qt/Tools, so the compiler's bin was never on PATH to begin with.
# Without them Windows refuses to start the process (0xC0000135), the child dies
# before reading a byte, and the harness reports an empty reply or EINVAL on
# stdin -- a failure that looks like a protocol bug and is not one.
#
# Two independent belts, because either alone has failed before:
#   * link the GCC runtime statically, removing three of the four DLLs;
#   * copy libsodium-26.dll next to the binaries, exactly as CMake does for
#     appChatE2EE.exe.
# PATH is also extended, but in POSIX form -- a "C:/..." entry in a Git Bash
# PATH is silently ignored, which is precisely how the first attempt failed.
to_posix() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -u "$1" 2>/dev/null || echo "$1"
  else
    # Fallback for a shell without cygpath. The drive letter is lowercased
    # because MSYS mounts drives as /c, /d and so on.
    _d=$(printf '%s' "$1" | cut -c1 | tr 'A-Z' 'a-z')
    _r=$(printf '%s' "$1" | cut -c3-)
    printf '/%s%s\n' "$_d" "$_r"
  fi
}

STATIC_FLAGS=""
if [ "$IS_WINDOWS" -eq 1 ]; then
  STATIC_FLAGS="-static-libgcc -static-libstdc++"
  if [ -n "$SODIUM_BIN" ] && [ -d "$SODIUM_BIN" ]; then
    export PATH="$(to_posix "$SODIUM_BIN"):$PATH"
  fi
  CXX_BIN_DIR="$(dirname "$CXX")"
  case "$CXX_BIN_DIR" in
    /*) export PATH="$CXX_BIN_DIR:$PATH" ;;
  esac
fi

mkdir -p "$BUILD_DIR"

# Windows resolves a DLL from the executable's own directory first, so a copy
# here is more reliable than any PATH arrangement. client/CMakeLists.txt does
# the same thing for appChatE2EE.exe; doing it differently in the harness would
# only invent a second way to get it wrong.
if [ "$IS_WINDOWS" -eq 1 ] && [ -n "$SODIUM_BIN" ] && [ -d "$SODIUM_BIN" ]; then
  for dll in libsodium-26.dll libsodium-23.dll; do
    if [ -f "$SODIUM_BIN/$dll" ]; then
      cp -f "$SODIUM_BIN/$dll" "$BUILD_DIR/" 2>/dev/null \
        && echo "   copied $dll next to the binaries"
    fi
  done
fi

preflight || exit 1

BUILD_OK=1
if [ "$RUN_T2" -eq 1 ]; then
  build tests/reference_oracles/_ref_interop_recv.cpp "$REF_RECV" "ref_recv" || BUILD_OK=0
fi
if [ "$RUN_T3" -eq 1 ] || [ "$RUN_HY" -eq 1 ]; then
  build tests/ratchet_cli.cpp "$CLI_CPP" "ratchet_cli_cpp" || BUILD_OK=0
fi
if [ "$BUILD_OK" -eq 0 ]; then
  echo ""
  echo "   Compilation failed. Full output is in $BUILD_DIR/*.log"
  exit 1
fi

# --------------------------------------------------------------------------
# Tier 2 -- Sequence interop
# --------------------------------------------------------------------------

if [ "$RUN_T2" -eq 1 ]; then
  banner "Tier 2  --  Sequence interop (Python encrypts, C++ decrypts)"
  note "A ratchet is stateful, so one message proves little. This runs a"
  note "five-message session through the Python schedule and hands the"
  note "transcript to a C++ implementation that shares no code with it."
  echo ""

  if "$PY" tests/make_ratchet_vectors.py --check > "$BUILD_DIR/t2_python.log" 2>&1; then
    ok "python self-replay: $(grep -o '[0-9]* messages decrypted.*' "$BUILD_DIR/t2_python.log" | head -1)"
  else
    bad "python could not produce or replay the session vector"
    sed 's/^/           /' "$BUILD_DIR/t2_python.log" | head -10
  fi

  if [ -f tests/ratchet_vector.txt ]; then
    if "$REF_RECV" tests/ratchet_vector.txt > "$BUILD_DIR/t2_cpp.log" 2>&1; then
      ok "$(grep -o 'RATCHET INTEROP OK.*' "$BUILD_DIR/t2_cpp.log" | head -1)"
    else
      bad "C++ could not decrypt the Python session"
      sed 's/^/           /' "$BUILD_DIR/t2_cpp.log" | head -10
    fi
  else
    bad "tests/ratchet_vector.txt was not produced"
  fi
fi

# --------------------------------------------------------------------------
# Tier 3 -- Live bidirectional harness
# --------------------------------------------------------------------------

LIVE_N=0
live() {
  label="$1"; shift
  LIVE_N=$((LIVE_N+1))
  logf="$BUILD_DIR/live_$LIVE_N.log"
  if "$PY" tests/live_harness.py "$@" > "$logf" 2>&1; then
    detail="$(grep -o '[0-9]*/[0-9]* turns[^\"]*' "$logf" | head -1)"
    [ -z "$detail" ] && detail="$(grep -io 'live interop ok.*' "$logf" | head -1)"
    ok "$label  ${detail:+--  $detail}"
  else
    bad "$label"
    sed 's/^/           /' "$logf" | tail -12
  fi
}

if [ "$RUN_T3" -eq 1 ]; then
  banner "Tier 3  --  Live bidirectional harness"
  note "Direction alternates every turn, so a DH ratchet fires on each one."
  note "Mixing the languages is the cross-language proof."
  echo ""
  live "python  <-> python" --alice "$PY tests/ratchet_cli.py" --bob "$PY tests/ratchet_cli.py" --turns 8
  live "python  <-> c++   " --alice "$PY tests/ratchet_cli.py" --bob "$CLI_CPP" --turns 8
  live "c++     <-> python" --alice "$CLI_CPP" --bob "$PY tests/ratchet_cli.py" --turns 8
fi

# --------------------------------------------------------------------------
# Hybrid cipher matrix
# --------------------------------------------------------------------------

if [ "$RUN_HY" -eq 1 ]; then
  banner "Hybrid cipher  --  AES-256-GCM with an XChaCha20-Poly1305 fallback"
  note "The mixed row is the decisive one: one side encrypts every message"
  note "with AES-256-GCM and the other with XChaCha20-Poly1305, in a single"
  note "conversation, each decrypting the other purely by reading the tag."
  echo ""
  live "python AES      <-> c++ AES     " \
       --alice "$PY tests/ratchet_cli.py" --alice-cipher aes \
       --bob   "$CLI_CPP"                 --bob-cipher   aes   --turns 6
  live "python XChaCha  <-> c++ XChaCha " \
       --alice "$PY tests/ratchet_cli.py" --alice-cipher xchacha \
       --bob   "$CLI_CPP"                 --bob-cipher   xchacha --turns 6
  live "c++ AES         <-> python XChaCha (MIXED)" \
       --alice "$CLI_CPP"                 --alice-cipher aes \
       --bob   "$PY tests/ratchet_cli.py" --bob-cipher   xchacha --turns 6
  live "python auto     <-> c++ auto (probe-driven)" \
       --alice "$PY tests/ratchet_cli.py" --alice-cipher auto \
       --bob   "$CLI_CPP"                 --bob-cipher   auto  --turns 6
fi

# --------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tier 4: X3DH vector conformance (C++ port vs the Python reference)
#
# The ratchet is proven by running two implementations against each other. X3DH
# cannot be, because the agreement happens once, before any message exists. So
# it is proven against frozen vectors instead: tests/x3dh_vectors.json fixes
# every private key, and the C++ port must reproduce both shared secrets, the
# deterministic Ed25519 signature, and the derived X25519 keys byte for byte.
#
# Builds with the same bare toolchain as the tiers above -- no Qt. An earlier
# version parsed the vectors with QJsonDocument and gated on pkg-config, which
# skipped silently on Windows because Qt ships no .pc files there.
# ---------------------------------------------------------------------------
echo
echo "=========================================================================="
echo "Tier 4  --  X3DH vector conformance"
echo "=========================================================================="
echo "         The agreement happens once, before any message exists, so it"
echo "         cannot be proven by two implementations talking. It is pinned to"
echo "         fixed vectors instead: same keys in, same secrets out."
echo

mkdir -p "$BUILD_DIR"
X3DH_BIN="$BUILD_DIR/x3dh_vectors_check"
if $CXX -std=c++17 -O2 -DHAVE_SODIUM $STATIC_FLAGS -I client/src $SODIUM_INC \
      tools/x3dh_vectors_check.cpp client/src/x3dh.cpp $SODIUM_LIB \
      -o "$X3DH_BIN" 2>"$BUILD_DIR/x3dh_build.log"
then
  if "$X3DH_BIN" tests/x3dh_vectors.json; then
    ok "X3DH VECTORS OK: C++ port reproduces the Python reference byte for byte"
  else
    bad "X3DH vector mismatch -- the C++ port and the reference disagree"
  fi
else
  bad "X3DH vector check failed to build -- see $BUILD_DIR/x3dh_build.log"
  sed -n '1,20p' "$BUILD_DIR/x3dh_build.log"
fi

# --------------------------------------------------------------------------

banner "Summary"
echo "   passed   $PASS"
echo "   failed   $FAIL"
[ "$SKIP" -gt 0 ] && echo "   skipped  $SKIP"
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "   All cross-language proofs green. Logs kept in $BUILD_DIR/ so the"
  echo "   transcripts can go into the evaluation chapter."
else
  echo "   Something failed. The per-check logs in $BUILD_DIR/ hold the full"
  echo "   output, including the frame transcripts."
fi

if [ "$KEEP" -eq 0 ]; then
  rm -f "$REF_RECV" "$CLI_CPP"
fi
