"""
test_repo_hygiene.py -- the repository must stay publishable and its
documentation must stay true.

WHY THIS EXISTS
---------------
Documentation rots silently. Nothing fails when a guide names a test count that
moved, a hostname that changed, or a file that was renamed -- the reader simply
follows an instruction that no longer works and concludes the project is broken.
For a repository whose stated purpose is that other people can reproduce it,
that failure mode is as real as a bug.

Three specific rots have already happened here and are each pinned below:

  * A document told the reader to run a manual `cp` after generating the lab
    certificate authority. Skipping it failed a test, so the generator now does
    the copy itself -- and this module checks that it still does.

  * `.gitignore` excludes `*.a` as build output, which also excluded the
    cross-compiled libsodium archives that the Android build cannot be built
    without. The negation that re-includes them is load-bearing and easy to
    delete by accident.

  * The ignore rules once lived in a file named `gitignore`, with no leading
    dot, so none of them applied and private keys travelled inside every
    archive. Git reports nothing for an ignore file it never reads.

Everything here runs on the source tree. Nothing needs a network or a build.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories whose contents are not authored by this project.
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache",
             "node_modules", "build-interop", "third_party"}


def _iter_markdown() -> list[Path]:
    """Every markdown document that belongs to this project."""
    out: list[Path] = []
    for p in REPO_ROOT.rglob("*.md"):
        if any(part in SKIP_DIRS for part in p.relative_to(REPO_ROOT).parts):
            continue
        if "site-packages" in p.as_posix():
            continue
        out.append(p)
    return sorted(out)


# NOTE: deliberately NOT a module-level constant consumed by parametrize.
# See test_every_relative_link_resolves for why the test count must not depend
# on how many documents exist.


# ==========================================================================
# Documentation links
# ==========================================================================

# [text](target) -- captures the target only.
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def _relative_link_targets(doc: Path) -> list[str]:
    """Local link targets in `doc`, excluding URLs and pure anchors."""
    text = doc.read_text(encoding="utf-8", errors="replace")

    # Fenced code blocks contain example commands and illustrative paths that
    # are not links to anything. Strip them before matching so a shell snippet
    # cannot produce a phantom broken link.
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)

    targets = []
    for raw in LINK_RE.findall(text):
        target = raw.split()[0].strip()          # drop an optional "title"
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        targets.append(target.split("#", 1)[0])  # drop any anchor
    return [t for t in targets if t]


def test_every_relative_link_resolves():
    """
    A link to a file that does not exist sends the reader nowhere, and is
    exactly what happens when a document is renamed or moved.

    ONE test over every document, deliberately, rather than one test per
    document via parametrize. Parametrizing made this module's test count a
    function of how many markdown files happened to exist, so adding or
    removing any document silently changed the total -- and then broke
    test_suite_hygiene.py's README count guards, which is a confusing way to
    be told that a file moved. Documentation must not be able to alter the
    size of the suite.

    Reporting every broken link at once is also the more useful failure: a
    misplaced file usually breaks several documents, and seeing them together
    identifies the file rather than the links.
    """
    broken: dict[str, list[str]] = {}
    for doc in _iter_markdown():
        missing = [t for t in _relative_link_targets(doc)
                   if not (doc.parent / t).resolve().exists()]
        if missing:
            broken[doc.relative_to(REPO_ROOT).as_posix()] = missing

    assert not broken, (
        "these documents link to files that do not exist:\n"
        + "\n".join(f"  {doc}\n      -> {', '.join(t)}"
                     for doc, t in sorted(broken.items()))
        + "\n\nA link broken in several documents at once usually means one "
          "file is in the wrong place, not that many links are wrong. Check "
          "where the TARGET actually is before editing any link."
    )


def test_readme_exists_and_points_at_the_entry_documents():
    """
    The front page is the only document most readers will open. It must route
    them onward, or the rest of docs/ is undiscoverable.
    """
    readme = REPO_ROOT / "README.md"
    assert readme.exists(), "the repository has no top-level README.md"

    text = readme.read_text(encoding="utf-8")
    for expected in ("docs/GETTING_STARTED.md", "docs/ARCHITECTURE.md",
                     "tests/README.md", "SECURITY.md"):
        assert expected in text, f"README.md does not link to {expected}"


def test_no_document_claims_the_manual_certificate_copy_is_required():
    """
    `cp pki/ca.crt client/pki/demo-ca.crt` used to be a manual step that a
    reader had to perform for the TLS tests to pass. The generator now does it.
    A document reintroducing the manual instruction would send readers back to
    a step that is no longer necessary -- and imply the automatic one is absent.
    """
    offenders = []
    for doc in _iter_markdown():
        text = doc.read_text(encoding="utf-8", errors="replace")
        if re.search(r"cp\s+pki/ca\.crt\s+client/pki/demo-ca\.crt", text):
            offenders.append(doc.relative_to(REPO_ROOT).as_posix())
    assert not offenders, (
        "these documents still instruct a manual copy of the lab root, which "
        f"tools/make_demo_pki.py now performs itself: {offenders}"
    )


# ==========================================================================
# .gitignore -- the rules that keep this publishable
# ==========================================================================

def _gitignore_text() -> str:
    p = REPO_ROOT / ".gitignore"
    if not p.exists():
        pytest.fail(
            ".gitignore is missing from the repository root.\n"
            "Without it, `git add .` publishes pki/ca.key, pki/server.key, "
            "server/server.key, the SQLite databases and a 15 MB virtualenv.\n"
            "Note that Windows Explorer's 'Send to > Compressed folder' drops "
            "dotfiles, so an archive round-trip can delete this file silently."
        )
    return p.read_text(encoding="utf-8")


@pytest.mark.parametrize("rule", ["pki/", "*.key", "*.pem", "*.db", ".venv/",
                                  "__pycache__/"])
def test_gitignore_excludes_secrets_and_local_data(rule: str):
    assert rule in _gitignore_text(), (
        f".gitignore no longer contains the rule {rule!r}"
    )


def test_gitignore_reincludes_the_android_libsodium_archives():
    """
    `*.a` is a build-output rule, but client/third_party/libsodium/<abi>/
    libsodium.a is build INPUT that nothing here can regenerate. Without the
    negation, a clean clone builds an Android package with stubbed cryptography:
    the client registers a zero-length public key and the relay rejects it at
    login, which looks nothing like a missing file.
    """
    text = _gitignore_text()
    assert "!client/third_party/libsodium/**/*.a" in text, (
        "the negation re-including the Android libsodium archives is gone; "
        "the `*.a` rule will exclude them and Android builds will have "
        "stubbed crypto"
    )


def test_the_committed_client_trust_anchor_is_a_certificate_not_a_key():
    """
    client/pki/demo-ca.crt is committed deliberately -- it is the PUBLIC half of
    the lab root, and the client cannot verify a lab relay without it. This
    guards against a private key ever taking its place.
    """
    anchor = REPO_ROOT / "client" / "pki" / "demo-ca.crt"
    if not anchor.exists():
        pytest.skip("client/pki/demo-ca.crt not generated yet")

    body = anchor.read_text(encoding="utf-8", errors="replace")
    assert "BEGIN CERTIFICATE" in body, "the committed trust anchor is not a certificate"
    assert "PRIVATE KEY" not in body, (
        "client/pki/demo-ca.crt contains a PRIVATE KEY. This file is committed; "
        "a private key here would be published."
    )


# ==========================================================================
# The lab CA generator keeps the client anchor in step
# ==========================================================================

def _make_scratch_repo(tmp_path: Path) -> Path:
    """
    A miniature tree with just enough structure for make_demo_pki.py to run:
    it derives every path from its own location, so tools/ and client/pki/ are
    all it needs.
    """
    (tmp_path / "tools").mkdir()
    (tmp_path / "client" / "pki").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "tools" / "make_demo_pki.py",
                 tmp_path / "tools" / "make_demo_pki.py")
    return tmp_path


def _run_generator(scratch: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(scratch / "tools" / "make_demo_pki.py"), *args],
        capture_output=True, text=True, timeout=180,
    )


def test_generator_installs_the_root_into_the_client(tmp_path):
    """
    The reproduction blocker this guards: pki/ is gitignored, so a fresh clone
    generates its own root, which then does not match the committed
    client/pki/demo-ca.crt -- and test_real_tls.py fails on the very first
    command a new user runs, for a reason that looks like a code fault.
    """
    scratch = _make_scratch_repo(tmp_path)
    stale = scratch / "client" / "pki" / "demo-ca.crt"
    stale.write_text("-----BEGIN CERTIFICATE-----\nstale\n-----END CERTIFICATE-----\n")

    r = _run_generator(scratch)
    assert r.returncode == 0, f"generator failed:\n{r.stdout}\n{r.stderr}"

    generated = (scratch / "pki" / "ca.crt").read_bytes()
    assert stale.read_bytes() == generated, (
        "make_demo_pki.py created a new root but left client/pki/demo-ca.crt "
        "stale, so the client would not trust the relay it just issued for"
    )


def test_generator_can_be_told_not_to_touch_the_client(tmp_path):
    """The automatic copy must remain opt-out, not compulsory."""
    scratch = _make_scratch_repo(tmp_path)
    stale = scratch / "client" / "pki" / "demo-ca.crt"
    marker = "-----BEGIN CERTIFICATE-----\nuntouched\n-----END CERTIFICATE-----\n"
    stale.write_text(marker)

    r = _run_generator(scratch, "--no-install-client-root")
    assert r.returncode == 0, f"generator failed:\n{r.stdout}\n{r.stderr}"
    assert stale.read_text() == marker, (
        "--no-install-client-root still overwrote the client trust anchor"
    )


def test_generator_never_writes_a_private_key_outside_pki(tmp_path):
    """
    Only pki/ may hold private keys. Anything the generator writes elsewhere is
    a candidate for being committed, because only pki/ is excluded wholesale.
    """
    scratch = _make_scratch_repo(tmp_path)
    r = _run_generator(scratch)
    assert r.returncode == 0, f"generator failed:\n{r.stdout}\n{r.stderr}"

    marker = "-----BEGIN " + "PRIVATE KEY" + "-----"
    leaked = []
    for p in scratch.rglob("*"):
        if not p.is_file() or p.parent.name == "pki":
            continue
        try:
            if marker in p.read_text(encoding="utf-8", errors="ignore"):
                leaked.append(p.relative_to(scratch).as_posix())
        except OSError:
            continue
    assert not leaked, f"private key material written outside pki/: {leaked}"


# ==========================================================================
# The publication safety check
# ==========================================================================

CHECKER = REPO_ROOT / "tools" / "check_publish_safety.py"


def _run_checker(root: Path) -> subprocess.CompletedProcess:
    """
    Run the checker that lives INSIDE `root`.

    The checker derives the tree it scans from its own __file__, not from the
    working directory, so pointing at the original script would scan the real
    repository no matter what cwd said -- which is exactly the mistake this
    helper existed to make once already.
    """
    script = root / "tools" / "check_publish_safety.py"
    assert script.exists(), f"no checker at {script}"
    return subprocess.run(
        [sys.executable, str(script)],
        cwd=root, capture_output=True, text=True, timeout=180,
    )


def test_publish_checker_exists_and_runs():
    assert CHECKER.exists(), "tools/check_publish_safety.py is missing"
    r = _run_checker(REPO_ROOT)
    # 0 = safe, 1 = findings. Anything else means it crashed.
    assert r.returncode in (0, 1), (
        f"the checker exited {r.returncode}:\n{r.stdout}\n{r.stderr}"
    )


def test_publish_checker_finds_a_key_hiding_under_an_innocuous_name(tmp_path):
    """
    The filename is the part an author controls, and therefore the part that
    goes wrong. Detection has to be by content.
    """
    scratch = tmp_path / "repo"
    (scratch / "tools").mkdir(parents=True)
    shutil.copy2(CHECKER, scratch / "tools" / "check_publish_safety.py")

    disguised = scratch / "meeting-notes.txt"
    disguised.write_text(
        "-----BEGIN " + "RSA PRIVATE KEY" + "-----\nAAAA\n"
        "-----END " + "RSA PRIVATE KEY" + "-----\n"
    )

    r = _run_checker(scratch)
    assert r.returncode == 1, "a private key named meeting-notes.txt was not reported"
    assert "meeting-notes.txt" in r.stdout


def test_publish_checker_does_not_report_itself(tmp_path):
    """
    The checker searches for strings that would, written out whole, appear in
    its own source. A tool that always reports one false positive teaches the
    reader to skim the section that must never be skimmed.
    """
    scratch = tmp_path / "repo"
    (scratch / "tools").mkdir(parents=True)
    shutil.copy2(CHECKER, scratch / "tools" / "check_publish_safety.py")

    r = _run_checker(scratch)
    assert r.returncode == 0, (
        "the checker reported findings in a tree containing only itself:\n"
        f"{r.stdout}"
    )
    assert "check_publish_safety.py" not in r.stdout.split("SECRETS")[-1].split("BUILD OUTPUT")[0]


def test_publish_checker_allows_the_public_trust_anchor(tmp_path):
    """
    client/pki/demo-ca.crt must not be flagged: it is a certificate, committed
    on purpose, and the client is useless for lab connections without it.
    """
    scratch = tmp_path / "repo"
    (scratch / "tools").mkdir(parents=True)
    (scratch / "client" / "pki").mkdir(parents=True)
    shutil.copy2(CHECKER, scratch / "tools" / "check_publish_safety.py")

    real = REPO_ROOT / "client" / "pki" / "demo-ca.crt"
    if not real.exists():
        pytest.skip("client/pki/demo-ca.crt not generated yet")
    shutil.copy2(real, scratch / "client" / "pki" / "demo-ca.crt")

    r = _run_checker(scratch)
    assert r.returncode == 0, (
        f"the public trust anchor was reported as unsafe:\n{r.stdout}"
    )
