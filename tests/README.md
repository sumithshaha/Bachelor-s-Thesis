# Running the ChatE2EE test suite

**497 tests across 33 modules.** Everything below runs on Windows (Git Bash),
Linux and macOS with no build tools: every dependency ships as a compiled wheel.

---

## Quick start

From the repository root — `chat-e2ee/`, the folder containing `run_tests.sh`:

```bash
bash run_tests.sh
```

That single command installs dependencies, generates the lab certificate
authority if it is missing, runs the red-team harness, then runs every test.
Expect roughly two minutes and a final line reading `497 passed`.

On Windows use **Git Bash**, not PowerShell or `cmd`. Right-click the
`chat-e2ee` folder and choose *Git Bash Here*.

### Useful variations

| Command | What it does |
|---|---|
| `bash run_tests.sh` | Everything: install, PKI, red-team harness, full suite |
| `bash run_tests.sh --no-install` | Skip `pip install` when dependencies are already present |
| `bash run_tests.sh --fast` | Offline crypto and unit tests only; skips the slower socket tests |

---

## Step by step, if you prefer to drive it yourself

### 1. Check Python

```bash
python --version
```

Any Python 3.10 or newer works. If `python` is not found, try `py --version` or
`python3 --version`; `run_tests.sh` probes all three in that order and skips the
Microsoft Store stub, which is not a real interpreter.

### 2. Install the dependencies

```bash
python -m pip install -r requirements.txt
```

Five packages: `cryptography`, `pynacl`, `pytest`, `pytest-asyncio`,
`websockets`. Needed once per machine.

### 3. Generate the lab certificate authority

```bash
python tools/make_demo_pki.py
```

`tests/test_real_tls.py` performs genuine TLS handshakes and needs
`pki/server.crt` and `pki/server.key`. Without them those 14 tests **skip
rather than fail**, which is easy to miss — so do this before reading any
result as a pass. Re-running is harmless: an existing root is kept.

### 4. Run everything

```bash
python -m pytest tests/ -v
```

### 5. Run one module while you work on it

```bash
python -m pytest tests/test_bilateral_gate.py -v
```

Add `-k` to narrow further, and `-x` to stop at the first failure:

```bash
python -m pytest tests/ -k "verify" -v
python -m pytest tests/ -x
```

---

## What each module covers

### Cryptographic core

| Module | Tests | Covers |
|---|---:|---|
| `test_ratchet.py` | 19 | Double Ratchet against the reference vectors |
| `test_ratchet_fuzz.py` | 69 | Randomised message ordering, loss, reordering, replay |
| `test_crypto.py` | 7 | X25519 agreement, AEAD encrypt/decrypt |
| `test_x3dh.py` | 7 | Four-DH X3DH agreement, single-use one-time prekeys |
| `test_safety_number.py` | 4 | Safety-number derivation and stability |
| `test_post_compromise.py` | 44 | Rekey ping/pong, pong debt, kick timer, PCS recovery |

### Transport and relay

| Module | Tests | Covers |
|---|---:|---|
| `test_real_tls.py` | 21 | Real TLS handshakes; an attacker with their own CA is refused; .qrc hygiene on source only |
| `test_integration.py` | 1 | The relay sees only ciphertext |
| `test_robustness.py` | 5 | Malformed frames, nickname collisions, oversized input |
| `test_verification_relay.py` | 6 | verifyack store-and-forward, verify_resync live-only |
| `test_protocol_dispatch.py` | 11 | Every type the client sends has a server handler |
| `test_birthday.py` | 8 | Birthday stored as a verifier, never as a date |
| `test_untrusted_frames.py` | 16 | The binary chunk and msg parsers, driven with hostile input |
| `test_close_codes.py` | 7 | Account close codes 4000/4001/4002: eviction, name lock, bad password |
| `test_prekey_dispatch.py` | 9 | X3DH publish_prekeys / get_bundle; one-time prekeys are single-use |
| `test_x3dh_vectors.py` | 18 | Fixed X3DH conformance vectors; the C++ and Python sides must agree |
| `test_broadcast_resilience.py` | 5 | One dead socket must not stop presence or log delivery to the rest |
| `test_message_actions.py` | 12 | delete/reaction store-and-forward, typing live-only; from is overridden |
| `test_log_stream.py` | 12 | The streamed server log reaches each client exactly once; one shared format |
| `test_localization_parity.py` | 8 | Every UI string exists in all three languages, with no orphans or duplicates |
| `test_self_addressing.py` | 13 | A user is never its own peer: self-excluded key dump, self-addressed frames refused |
| `test_identity_key_type.py` | 10 | Every key-delivery frame states whether it carries Ed25519 or X25519 |

### Files

| Module | Tests | Covers |
|---|---:|---|
| `test_file_sharing.py` | 3 | Chunked transfer end to end |
| `test_file_e2ee_advanced.py` | 7 | Per-file random keys, forward secrecy |
| `test_security_invariants.py` | 18 | Properties that must hold across the whole system |

### Client-side invariants

| Module | Tests | Covers |
|---|---:|---|
| `test_bilateral_gate.py` | 27 | No transfer until both parties verify; trust-anchor scoping |
| `test_qml_shadowing.py` | 14 | QML declarations that would stop the app loading |
| `test_sqlite_lifecycle.py` | 9 | Databases must not outlive the test that opened one |
| `test_schema_migration.py` | 13 | An existing database gains later columns; partial, future, concurrent, read-only |
| `test_handshake_noise_filter.py` | 15 | A bare TCP scan OR a plain HTTP request logs one line, not a traceback; real errors keep theirs; live-socket proof |
| `test_suite_hygiene.py` | 32 | The 20 files in `tests/` that pytest never collects |
| `test_build_sources.py` | 29 | Every source the build lists exists and is reachable |
| `test_repo_hygiene.py` | 18 | Documentation links resolve; the ignore rules still exclude keys and re-include the Android libsodium archives; the lab CA generator keeps the client trust anchor in step; the publication safety check works |

These two read the C++ and QML source rather than executing it, because the Qt
client cannot be compiled in a Python test run. That is weaker than running the
code, and worth being honest about — but not cosmetic: both guard failure modes
that have actually occurred, and `test_qml_shadowing.py` exists because two
separate shadowed members each stopped the application starting on both
platforms, with the cause visible only in logcat.

---

## Cross-language proofs -- `run_interop.sh`

`pytest` covers the Python implementation. Proving the **C++** implementation
agrees with it needs a compiler, so it lives in its own command:

```bash
bash run_interop.sh
```

Ten checks across four tiers:

| Tier | Checks | What it establishes |
|---|---:|---|
| 2 — sequence interop | 2 | Python encrypts a five-message session; an independent C++ implementation decrypts it |
| 3 — live bidirectional | 3 | Python and C++ hold a real conversation in three pairings, direction alternating each turn so a DH ratchet fires every time |
| Hybrid cipher | 4 | The same conversation with AES-256-GCM, with XChaCha20-Poly1305, mixed, and probe-driven. The **mixed** row is the decisive one |
| 4 — X3DH vectors | 1 | Fixed conformance vectors (21 internal assertions). The agreement happens before any message exists, so it cannot be shown by two implementations talking |

Narrow it with `--tier2`, `--tier3` or `--hybrid`; keep the binaries with
`--keep`. Logs stay in `build-interop/`.

With no C++ toolchain it skips cleanly and says what to install. On Windows it
needs `C:/libsodium/libsodium-win64` from the MinGW tarball, the same location
`client/CMakeLists.txt` uses; override with `SODIUM_ROOT=... bash run_interop.sh`.
See `RATCHET_TESTING.md` for why `-lsodium` is not enough there.

---

## The red-team harness

Separate from pytest, because it prints an argued narrative rather than
assertions:

```bash
PYTHONPATH=server python tests/e2ee_redteam.py
```

Three experiments against the real `crypto_core.py` and `file_crypto.py`:
a passive relay learns nothing; an active man-in-the-middle is caught by the
safety number; old file keys do not open new files. Useful as thesis material
because the output reads as an argument rather than a pass/fail list.

---

## Reading a result

A clean run ends with:

```
497 passed in ~110s
```

A clean run has **no warnings**. The deprecation notices that used to appear
from `ssl.TLSVersion.TLSv1_1` are now silenced at the point of use, because
setting a deprecated value is exactly what that test intends to do.

**Watch for `skipped`.** A skip is a silent gap, not a pass. Two causes:

- **`14 skipped`, all TLS.** The lab PKI is missing — step 3 above. This is the
  one that matters, because it means the TLS tests never ran at all.
- **One skip in `test_schema_migration.py`.** Expected only when running as
  **root** on Linux: that test needs the filesystem to honour the read-only bit,
  which root bypasses. Under a normal user account it passes, and the run reads
  `497 passed`.

### If something fails

```bash
python -m pytest tests/<module>.py -v -l --tb=long
```

`-l` shows local variables at the failure point; `--tb=long` gives the full
traceback.

Two things worth checking before suspecting the code:

- **Port conflicts.** The socket tests bind fixed ports (8791, 8799, 8811–8813,
  8821). A relay left running from a demo will collide. Stop it and retry.
- **Stale `pki/`.** If certificate tests fail oddly, delete the `pki/` folder and
  re-run `python tools/make_demo_pki.py`. Remember the client embeds the ROOT,
  so replacing the root means rebuilding the client.

---

## Before a demonstration

```bash
bash run_tests.sh 2>&1 | tee test-run.txt
```

`tee` keeps a copy of the output. A dated `497 passed` alongside the red-team
narrative is more persuasive evidence than a screenshot of the application
working, because it shows the failure cases were checked too.

The header of this file states the count, and it is easy for that to drift as
modules are added. It is generated rather than typed:

```bash
python tools/sync_test_readme.py --check    # report only
python tools/sync_test_readme.py --fix      # rewrite the counts
```

Counts come from pytest **collection**, not from counting `def test_` lines,
because most of the large modules are parametrised.
