#!/usr/bin/env python3
"""
check_publish_safety.py -- read the working tree the way GitHub will.

    python tools/check_publish_safety.py

Run this before the first push, and again before every push after that. It
exits 0 when the tree is safe to publish and 1 when it is not, so it also works
as a pre-commit hook or a CI step.

WHY THIS EXISTS
---------------
A .gitignore only protects files that were never committed. It does nothing
about a file already in the index, and nothing at all if the file is not named
what you think it is named -- this project shipped its rules in a file called
`gitignore`, with no leading dot, for long enough that four private keys, a
15 MB virtualenv and a database travelled inside every archive. Git reports no
error for an ignore file it does not read. The failure is completely silent and
looks exactly like a working setup.

So this script does not trust the ignore rules. It walks the actual bytes on
disk and answers two separate questions:

    1. Is this file dangerous?          -- decided by name AND by content
    2. Would git actually exclude it?   -- decided by asking git, not by
                                           reading .gitignore and hoping

The second question is the one that matters. A dangerous file that git ignores
is a non-event. A dangerous file that git does NOT ignore is one `git add .`
away from being public and, once pushed, permanent: rewriting history does not
recall a key that a crawler already indexed. Treat any private key that has
been pushed as compromised and reissue it, rather than deleting the commit and
hoping.

WHAT IS CHECKED
---------------
Secrets are matched on content as well as on filename, because the filename is
the part an author controls and therefore the part that goes wrong. A PEM
private key is recognised by its header no matter what it is called.

Everything else -- build output, virtualenvs, caches, IDE state, databases --
is a size and noise problem rather than a safety problem, and is reported
separately so the two never compete for attention.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# What counts as dangerous
# --------------------------------------------------------------------------

# Byte sequences that identify a private key regardless of the file's name.
# Checked against the first few KiB of every readable file, so a key saved as
# `notes.txt` is still caught.
#
# The markers are ASSEMBLED at runtime from two halves rather than written out
# whole. Written whole, this file would contain every string it searches for
# and would flag ITSELF on the first run -- a false positive that teaches the
# reader to skim past the SECRETS section, which is the one section that must
# never be skimmed. The alternative, excluding this file by name, would mean a
# key genuinely pasted in here went unreported. Splitting the literal keeps the
# check honest in both directions.
_B = b"-----BEGIN "
_E = b"-----"
SECRET_MARKERS: tuple[bytes, ...] = (
    _B + b"PRIVATE KEY" + _E,
    _B + b"RSA PRIVATE KEY" + _E,
    _B + b"EC PRIVATE KEY" + _E,
    _B + b"DSA PRIVATE KEY" + _E,
    _B + b"OPENSSH PRIVATE KEY" + _E,
    _B + b"PGP PRIVATE KEY BLOCK" + _E,
    _B + b"ENCRYPTED PRIVATE KEY" + _E,
)

# Suffixes that are private keys by convention. Kept separate from the content
# check because an empty or truncated key file still must not be published, and
# because .ekey is this project's own long-term identity format, which is raw
# bytes with no PEM header to match on.
SECRET_SUFFIXES: dict[str, str] = {
    ".key": "private key by convention",
    ".pem": "may be a private key or a chain",
    ".ekey": "a user's long-term X25519/Ed25519 private identity",
    ".p12": "PKCS#12 bundle -- contains a private key",
    ".pfx": "PKCS#12 bundle -- contains a private key",
    ".jks": "Java keystore -- contains a private key",
    ".keystore": "Android signing keystore",
}

# Exact names worth naming individually, because seeing the name is the whole
# explanation.
SECRET_NAMES: dict[str, str] = {
    "id_rsa": "an SSH private key",
    "id_ed25519": "an SSH private key",
    "id_ecdsa": "an SSH private key",
    "thesis.key": "the cPouta SSH private key",
    ".env": "commonly holds credentials",
}

# Noise: large, machine-specific or regenerable. Not a safety problem.
NOISE_DIRS: dict[str, str] = {
    ".venv": "virtualenv -- regenerate with pip install -r requirements.txt",
    "venv": "virtualenv -- regenerate with pip install -r requirements.txt",
    "__pycache__": "Python bytecode cache",
    ".pytest_cache": "pytest cache",
    ".qtcreator": "Qt Creator per-machine state (absolute paths, kit ids)",
    "build-interop": "interop build output -- regenerate with run_interop.sh",
    ".idea": "IDE state",
    ".vscode": "IDE state",
}

NOISE_SUFFIXES: dict[str, str] = {
    ".pyc": "compiled Python",
    ".pyo": "compiled Python",
    ".o": "object file",
    ".obj": "object file",
    ".exe": "built binary",
    ".dll": "built binary",
    ".so": "built binary",
    ".a": "static library",
    ".apk": "built Android package",
    ".aab": "built Android bundle",
    ".db": "SQLite database -- account names, public keys, timing metadata",
    ".db-wal": "SQLite write-ahead log",
    ".db-shm": "SQLite shared-memory index",
    ".user": "Qt Creator per-user project settings",
}

# Directories never walked at all.
SKIP_WALK = {".git"}

# Files that look dangerous by suffix but are deliberately published. The
# client's embedded trust anchor is a CERTIFICATE -- the public half of the
# root -- and the client cannot verify a lab relay without it.
ALLOWED: dict[str, str] = {
    "client/pki/demo-ca.crt": "public root certificate, compiled into the client on purpose",
}

# Prefixes that are large binaries but are REQUIRED BUILD INPUTS, not build
# output. libsodium cross-compiled for the Android ABIs cannot be regenerated
# from anything in this repository, so excluding it would leave every Android
# build with stubbed crypto -- the client would register an empty public key
# and the relay would refuse it. They are committed on purpose; .gitignore
# carries a matching negation rule. libsodium is ISC-licensed, so redistributing
# the compiled archive is permitted.
ALLOWED_PREFIXES: tuple[str, ...] = (
    "client/third_party/libsodium/",
)

CONTENT_PEEK = 8192          # bytes read from each file for the marker scan
LARGE_FILE_BYTES = 1_000_000  # report anything above this as a size concern


# --------------------------------------------------------------------------
# Asking git what it would actually do
# --------------------------------------------------------------------------

def git_available() -> bool:
    """True when this tree is a git repository and git is on PATH."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def git_ignored(paths: list[str]) -> set[str]:
    """
    The subset of `paths` git would exclude.

    Asked with `git check-ignore --stdin`, which consults the real rule set --
    .gitignore at every level, .git/info/exclude and the global core.excludesFile
    -- rather than re-implementing the matching here. Re-implementing it is how
    you get a checker that agrees with itself and disagrees with git.
    """
    if not paths:
        return set()
    try:
        r = subprocess.run(
            ["git", "check-ignore", "--stdin"],
            cwd=REPO_ROOT, input="\n".join(paths),
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    # Exit status 0 = some paths matched, 1 = none matched. Both are normal;
    # anything else means git could not answer and we must not assume "ignored".
    if r.returncode not in (0, 1):
        return set()
    return {line.strip() for line in r.stdout.splitlines() if line.strip()}


def git_tracked() -> set[str]:
    """
    Paths already in the index.

    This is the set .gitignore cannot help with: once a file is tracked, ignore
    rules are not consulted for it at all, and it keeps being committed.
    """
    try:
        r = subprocess.run(
            ["git", "ls-files"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if r.returncode != 0:
        return set()
    return {line.strip() for line in r.stdout.splitlines() if line.strip()}


# --------------------------------------------------------------------------
# Walking the tree
# --------------------------------------------------------------------------

def has_secret_marker(path: Path) -> str | None:
    """The PEM header found in this file, or None."""
    try:
        with path.open("rb") as fh:
            head = fh.read(CONTENT_PEEK)
    except OSError:
        return None
    for marker in SECRET_MARKERS:
        if marker in head:
            return marker.decode("ascii", "replace")
    return None


def scan() -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, int]]]:
    """Return (secrets, noise, large_files) as lists of (relpath, reason)."""
    secrets: list[tuple[str, str]] = []
    noise: list[tuple[str, str]] = []
    large: list[tuple[str, int]] = []

    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_WALK]
        here = Path(dirpath)

        # Report a noise directory once, by name, instead of listing every file
        # inside it. A virtualenv is thousands of entries and one decision.
        for d in list(dirnames):
            if d in NOISE_DIRS:
                rel = (here / d).relative_to(REPO_ROOT).as_posix()
                noise.append((rel + "/", NOISE_DIRS[d]))
                dirnames.remove(d)

        for name in filenames:
            fp = here / name
            rel = fp.relative_to(REPO_ROOT).as_posix()

            if rel in ALLOWED or rel.startswith(ALLOWED_PREFIXES):
                continue

            # --- dangerous by content (checked first: a name can lie) --------
            marker = has_secret_marker(fp)
            if marker:
                secrets.append((rel, f"contains {marker}"))
                continue

            # --- dangerous by name ------------------------------------------
            if name in SECRET_NAMES:
                secrets.append((rel, SECRET_NAMES[name]))
                continue
            suffix = fp.suffix.lower()
            if suffix in SECRET_SUFFIXES:
                secrets.append((rel, SECRET_SUFFIXES[suffix]))
                continue

            # --- noise ------------------------------------------------------
            if suffix in NOISE_SUFFIXES:
                noise.append((rel, NOISE_SUFFIXES[suffix]))
                continue

            try:
                size = fp.stat().st_size
            except OSError:
                continue
            if size > LARGE_FILE_BYTES:
                large.append((rel, size))

    secrets.sort()
    noise.sort()
    large.sort(key=lambda t: -t[1])
    return secrets, noise, large


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def rule(char: str = "=") -> str:
    return char * 74


def report(secrets, noise, large, use_git: bool) -> int:
    all_paths = [p for p, _ in secrets] + [p.rstrip("/") for p, _ in noise]
    ignored = git_ignored(all_paths) if use_git else set()
    tracked = git_tracked() if use_git else set()

    def status(rel: str) -> tuple[str, bool]:
        """(human status, is_exposed)."""
        if not use_git:
            return "NOT IN GIT (cannot check)", True
        bare = rel.rstrip("/")
        if bare in tracked:
            return "TRACKED -- already in the index", True
        if bare in ignored:
            return "ignored by git", False
        return "NOT IGNORED", True

    print(rule())
    print("ChatE2EE -- pre-publication safety check")
    print(rule())
    print(f"  tree      {REPO_ROOT}")
    print(f"  git       {'yes' if use_git else 'no -- run `git init` first for a full check'}")
    print()

    exposed_secrets: list[tuple[str, str, str]] = []
    exposed_noise: list[tuple[str, str, str]] = []

    # ---- secrets ---------------------------------------------------------
    print("SECRETS")
    print(rule("-"))
    if not secrets:
        print("  none found.")
    for rel, why in secrets:
        st, exposed = status(rel)
        flag = "!!" if exposed else "ok"
        print(f"  {flag}  {rel}")
        print(f"        {why}")
        print(f"        {st}")
        if exposed:
            exposed_secrets.append((rel, why, st))
    print()

    # ---- noise -----------------------------------------------------------
    print("BUILD OUTPUT, CACHES AND LOCAL DATA")
    print(rule("-"))
    if not noise:
        print("  none found.")
    for rel, why in noise:
        st, exposed = status(rel)
        flag = "->" if exposed else "ok"
        print(f"  {flag}  {rel:<44} {why}")
        if exposed:
            exposed_noise.append((rel, why, st))
    print()

    # ---- size ------------------------------------------------------------
    if large:
        print("LARGE FILES (over 1 MB)")
        print(rule("-"))
        for rel, size in large[:15]:
            print(f"      {size/1_000_000:>6.1f} MB  {rel}")
        print()

    # ---- verdict ---------------------------------------------------------
    print(rule())
    if not exposed_secrets and not exposed_noise:
        print("SAFE TO PUBLISH")
        print(rule())
        print("  Every secret and build artefact found is excluded by git.")
        print("  Verify the ignore file is genuinely being read:")
        print("      git check-ignore -v pki/ca.key server/server.key")
        print("  Two lines of output naming .gitignore means the rules are live.")
        return 0

    print("NOT SAFE TO PUBLISH")
    print(rule())

    if exposed_secrets:
        print()
        print("  These are secrets that git would publish. Deal with them first.")
        print()
        for rel, _, st in exposed_secrets:
            print(f"    {rel}   [{st}]")
        print()
        print("  Remove them from the working tree:")
        print()
        for rel, _, _ in exposed_secrets:
            print(f"      rm '{rel}'")
        print()
        print("  If any are TRACKED, they are in the index and possibly in a")
        print("  commit already. Untrack, then confirm the ignore rule catches")
        print("  them from now on:")
        print()
        for rel, _, st in exposed_secrets:
            if "TRACKED" in st:
                print(f"      git rm --cached '{rel}'")
        print()
        print("  A key that has ever been pushed to a public repository is")
        print("  compromised. Reissue it -- do not merely delete the commit.")
        print("  For this project that means: regenerate the lab CA with")
        print("  tools/make_demo_pki.py, and reissue the relay certificate on")
        print("  the VM with certbot.")

    if exposed_noise:
        print()
        print("  These are not dangerous, only large and machine-specific:")
        print()
        for rel, why, _ in exposed_noise:
            print(f"    {rel:<44} {why}")
        print()
        print("  Delete them, or add matching rules to .gitignore.")

    print()
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Check the working tree for anything that must not be published.")
    ap.add_argument("--quiet", action="store_true",
                    help="print only the verdict line and exit status")
    args = ap.parse_args()

    use_git = git_available()
    secrets, noise, large = scan()

    if args.quiet:
        all_paths = [p for p, _ in secrets] + [p.rstrip("/") for p, _ in noise]
        ignored = git_ignored(all_paths) if use_git else set()
        tracked = git_tracked() if use_git else set()
        bad = [p for p, _ in secrets
               if not use_git or p in tracked or p not in ignored]
        if bad:
            print(f"NOT SAFE TO PUBLISH: {len(bad)} exposed secret(s)")
            return 1
        print("SAFE TO PUBLISH")
        return 0

    return report(secrets, noise, large, use_git)


if __name__ == "__main__":
    sys.exit(main())
