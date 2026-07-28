# Ratchet Test and Interop Strategy

This is the verification plan for the forward-secrecy / post-compromise-security
work specified in `forward-secrecy-architecture.md`. It answers two questions
that a ratchet must answer and that "the messages arrive" does not:

1. **Do the security properties actually hold?** A ratchet can encrypt and
   decrypt correctly while providing neither forward secrecy nor
   post-compromise security. The property tests are written to *fail* if either
   is absent.
2. **Do the Python reference and the C++ client still agree across a ratcheting
   session?** A stateful protocol can pass a single-message interop check yet
   diverge once the chains advance. The interop check therefore spans a whole
   session.

A note on what is reference and what is product. To make this strategy runnable
and self-checking, it includes a **reference ratchet** (`_ref_ratchet.py`) and a
**self-contained C++ receiver** (`_ref_interop_recv.cpp`). These are the test
oracle: known-good sides the strategy is validated against. They are not the
code you submit. The product ratchet lives in `server/crypto_core.py` and
`client/src/cryptobox.cpp`, is yours to write and own, and is driven by the same
tests and the same vector (`interop_ratchet.cpp`). Verify the reference against
the Signal *Double Ratchet* specification rather than trusting it.

---

## Files

| File | Role | Runs where |
|------|------|------------|
| `tests/reference_oracles/_ref_ratchet.py` | Reference Double Ratchet (oracle): Route A init, KDF_RK/KDF_CK, DH ratchet, skipped-key store, XChaCha20-Poly1305 with header as AD. | Python |
| `tests/test_ratchet.py` | Property suite: correctness, forward secrecy, post-compromise security, out-of-order, bounds, header integrity, and a teeth meta-test. | `pytest` |
| `tests/make_ratchet_vectors.py` | Generates a one-directional session vector (`ratchet_vector.json` + `.txt`); `--check` replays it in Python. | Python |
| `tests/reference_oracles/_ref_interop_recv.cpp` | Self-contained C++/libsodium receiver: decrypts the Python session. Independent cross-language oracle. | C++ |
| `tests/reference_oracles/interop_ratchet.cpp` | Production interop consumer: drives the **CryptoBox** ratchet API with the same vector. | C++ (after you implement the ratchet) |

---

## Running the tests -- one command

Everything below runs from the repo root with a single command:

```bash
bash run_tests.sh
```

It works in Git Bash (MINGW64) on Windows and in bash on Linux/macOS. In order it
picks a Python 3 launcher (`python`, then the Windows `py` launcher, then
`python3`), installs the dependencies from `requirements.txt` (`cryptography`,
`pynacl`, `pytest`, `pytest-asyncio`, `websockets`), runs the end-to-end red-team
harness (`tests/e2ee_redteam.py`), and then runs the whole test folder:

```bash
python -m pytest tests/ -v
```

The whole folder is green with **no external server**: the async tests
(`test_integration.py`, `test_robustness.py`, `test_file_sharing.py`) spin up
their own in-process relay via `websockets`, so nothing has to be started first.
They do bind fixed localhost ports (`8791`, `8799`, ...), so don't run the suite
while something else is holding those ports.

**Flags.**

| Invocation | Effect |
|------------|--------|
| `bash run_tests.sh` | Install deps, run the harness, then the whole `pytest tests/`. |
| `bash run_tests.sh --fast` | Skip the slower self-hosting server tests; run only the quick, offline crypto/unit modules (`test_crypto`, `test_ratchet`, `test_post_compromise`, `test_safety_number`, `test_x3dh`, `test_ratchet_fuzz`, `test_security_invariants`, `test_file_e2ee_advanced`) -- the fast inner loop while iterating on the crypto. |
| `bash run_tests.sh --no-install` | Skip `pip install` (dependencies already present). |
| `bash run_tests.sh --help` | Print the usage summary. |

`--fast` runs only the files that are actually present, so it works whether or
not the advanced modules have been added yet. Flags combine, e.g.
`bash run_tests.sh --fast --no-install`. To run one file directly,
`python -m pytest tests/<file>.py -v` also works: each test file puts `server/`
on its own import path, so no `PYTHONPATH` or `conftest.py` is needed.

---

## Tiers 2 and 3 -- also one command

The cross-language work below (Tier 2, Tier 3 and the hybrid-cipher matrix) used
to be a sequence of commands to type by hand: compile two C++ files with the
right include and library flags, then invoke the harness four different ways.
That is now:

```bash
bash run_interop.sh
```

It finds the compiler and libsodium, builds both C++ endpoints, runs all nine
checks and prints a summary. `--tier2`, `--tier3` and `--hybrid` narrow it;
`--keep` leaves the binaries in place. Logs land in `build-interop/` so the frame
transcripts can go straight into the evaluation chapter.

A run with no C++ toolchain skips cleanly and says what to install rather than
failing. The pure-Python parts of Tier 2 are covered by `pytest` regardless, so
a machine without a compiler still checks the vector generator.

**Why the manual commands below are still here.** They document what the script
does, and they are what you reach for when debugging one specific step. They are
not the recommended route.

---

## Tier 1 -- Property tests (prove the properties hold)

`tests/test_ratchet.py`, ten tests. The security-relevant ones:

- **`test_forward_secrecy`** -- deliver messages 0,1,2 in order, snapshot the
  receiver's state (an attacker capturing it at that instant), then attempt to
  decrypt message 1 from the snapshot. It must fail: the chain key that produced
  message 1's key has been overwritten and discarded. *Passing means past
  messages are unrecoverable from present state.*
- **`test_post_compromise_security`** -- run healthy turns, snapshot the
  receiver, then continue for several bidirectional turns (each introducing
  fresh ephemeral DH keys that postdate the snapshot). A message sent well after
  healing must be undecryptable by the stale snapshot while the real receiver
  reads it fine. *Passing means a compromise heals once the parties keep
  talking.*
- **`test_delayed_message_across_a_dh_ratchet`** and
  **`test_out_of_order_within_a_chain`** -- reordered and DH-ratchet-straddling
  messages still decrypt, via the bounded skipped-key store.
- **`test_skip_bound_is_enforced`** -- a header claiming a message number beyond
  `MAX_SKIP` is rejected, not honoured (DoS bound).
- **`test_header_is_authenticated`** / **`test_ciphertext_tampering_is_rejected`**
  -- flipping the header or the ciphertext causes authentication failure,
  because the AEAD binds the header as associated data.

- **`test_strategy_has_teeth`** -- the meta-test. It breaks `kdf_ck` (every
  message reuses one key) and asserts the forward-secrecy check then *fails*.
  This is the evidence that the suite is not vacuous: it catches a real
  regression rather than passing regardless.

Run:
```bash
pytest tests/test_ratchet.py -v
```

When the product ratchet exists, copy these tests against it (import the product
module instead of `_ref_ratchet`) so the same properties are proven for the code
you ship, and fold the count into Testing-chapter Table 4.1.

---

## Tier 2 -- Sequence interop (prove Python and C++ agree across a session)

The original single-message interop is extended to a sequence, because a ratchet
is stateful.

```bash
# Python (Alice) encrypts a 5-message session and self-checks it:
python tests/make_ratchet_vectors.py --check
#   -> [python replay] 5 messages decrypted, all match.

# Independent C++ (Bob) decrypts the same session.
# Linux / macOS:
g++ -std=c++17 tests/reference_oracles/_ref_interop_recv.cpp -lsodium -o ref_recv
./ref_recv tests/ratchet_vector.txt
#   -> RATCHET INTEROP OK: 5/5 messages decrypted by C++ from the Python session
```

What this proves across the language boundary: the Route A bootstrap
(`SK = derive_shared_key`), the first DH ratchet step on the receiver, the
symmetric chain across many messages, XChaCha20-Poly1305, and header parsing
with the header bound as associated data. This is the direct generalisation of
your existing `make_vector.py` / `interop.cpp` check from one message to a run.

**Scope, stated honestly.** A static vector is one-directional and therefore
verifies a single sending chain and the first DH ratchet. It does *not* exercise
multi-step DH ratchets or healing across the language boundary -- those are
covered for the implementation by Tier 1, and for cross-language behaviour by
Tier 3.

When the product ratchet exists, `tests/reference_oracles/interop_ratchet.cpp` runs the same
vector through `CryptoBox` (it expects a small responder-init and ratchet-decrypt
API, documented at the top of that file). A green run is the cross-language proof
for the code you ship.

---

## Tier 3 -- Live bidirectional harness (implemented and verified)

Proves multi-step DH ratchets and healing *across languages*, which a static
one-directional vector cannot reach: each DH step depends on a fresh ephemeral
key the other side generates, so the two implementations must hold a real
conversation. Files:

| File | Role |
|------|------|
| `tests/ratchet_cli.py` | Python endpoint wrapping the product schedule (`server/ratchet.py`). |
| `tests/ratchet_cli.cpp` | Self-contained C++/libsodium endpoint (oracle), same schedule. |
| `tests/live_harness.py` | Driver: owns the identities, spawns two endpoints, shuttles each FRAME, asserts every decrypt matches. |

The driver alternates direction every message, so each turn forces a DH ratchet
on the receiver -- repeated ratchet steps and healing, end to end. Either side
may be Python or C++; mixing them is the cross-language proof.

```bash
# Linux / macOS:
g++ -std=c++17 tests/ratchet_cli.cpp -lsodium -o ratchet_cli_cpp

# Python <-> C++, eight bidirectional turns:
python tests/live_harness.py     --alice "python3 tests/ratchet_cli.py"     --bob   "./ratchet_cli_cpp" --turns 8
#   -> LIVE INTEROP OK: 8/8 turns, bidirectional, ...py <-> ./ratchet_cli_cpp
```

Verified in all of Python<->Python, Python<->C++, and C++<->Python. The `dh`
value changes every turn in the transcript -- the visible signature of a DH
ratchet firing on each direction change.

To run the SAME harness against your product C++ ratchet rather than the oracle,
wrap `CryptoBox` in a CLI that speaks the four-line protocol above (`SEND`,
`RECV`, `FRAME`, `PLAIN`) and pass it as `--alice`/`--bob`. That is the strongest
cross-language proof for the code you ship.

---

## Building the C++ endpoints on Windows

`-lsodium` does not work under MinGW, and the failure is misleading: the linker
finds no usable library, skips it silently, and reports every libsodium symbol
as undefined -- which reads as a missing library rather than a wrong one.

Three things differ from the Linux commands above.

**1. libsodium comes from the MinGW tarball, not the vendored folder.**
`client/CMakeLists.txt` expects `C:/libsodium/libsodium-win64`, extracted from
`libsodium-1.0.20-stable-mingw.tar.gz`. Link the import library by path:

```bash
SODIUM=C:/libsodium/libsodium-win64
g++ -std=c++17 -I"$SODIUM/include" \
    tests/ratchet_cli.cpp "$SODIUM/lib/libsodium.dll.a" \
    -static-libgcc -static-libstdc++ -o ratchet_cli_cpp.exe
```

`client/third_party/libsodium` is **Android only**. Its `arm64-v8a` and `x86_64`
folders are NDK ABI names holding ELF archives; CMake indexes that directory by
`CMAKE_ANDROID_ARCH_ABI`. MinGW cannot link them.

**2. The binary needs DLLs at run time.** Linking uses the import library;
*starting* needs `libsodium-26.dll`, which lives in `$SODIUM/bin`. Copy it next
to the executable, exactly as CMake does for `appChatE2EE.exe`. Without it
Windows refuses to start the process and the harness reports an empty reply --
a failure that looks like a protocol bug and is not one.

**3. `-static-libgcc -static-libstdc++`** removes the dependency on
`libstdc++-6.dll`, `libgcc_s_seh-1.dll` and `libwinpthread-1.dll`, which live in
the compiler's own `bin` directory and are usually not on a Git Bash PATH.

`run_interop.sh` does all three. This section exists so the reasoning is on the
record, not so anyone has to follow it.

---

## Mapping to the thesis

- **Testing chapter.** Tier 1 extends the automated suite; add a row group to
  Table 4.1 for the ratchet property tests and update the total. Tier 2 extends
  the cross-language interoperability section from one message to a session.
  The teeth meta-test is worth a sentence: it is the answer to "how do you know
  the tests would catch a broken ratchet?"
- **Limitations / threats to validity.** The Tier 2 scope note (one-directional
  static vector) and the bootstrap caveat from the architecture (Route A's first
  message) belong here, stated plainly.
- **`docs/BUILD.md`.** Add the Tier 2 commands next to the existing interop
  recipe.

The reflection on what this verification establishes, and what it does not,
remains yours to write.

---

## Hybrid cipher: AES-256-GCM with an explicit XChaCha20-Poly1305 fallback

The message AEAD is negotiated **per message** rather than fixed. Each message
carries a `cipher` tag in its header (`a256gcm-r1` or `xc20p1305-r1`); the sender
chooses, the receiver follows the tag. The tag is folded into the AEAD associated
data, so it cannot be flipped undetected.

**Selection policy.** The sender uses AES-256-GCM where hardware AES is reported
and XChaCha20-Poly1305 otherwise. On the C++ client this is libsodium's
`crypto_aead_aes256gcm_is_available()`. This is the clean resolution of the
Chapter 4 finding: the Windows/MinGW desktop, whose probe returns 0, simply
selects XChaCha20 — no undefined behaviour, no hardware dependency — while a
device with genuine AES acceleration (the phone) uses AES-256-GCM. Both ciphers
are present on both ends, so a desktop talking to a phone interoperates whichever
each side picks.

**Why "AES-only with automatic fallback" is not what this is.** There is no
silent fallback in libsodium; AES-256-GCM there has no software path and is
undefined to call when the probe is 0. A real fallback therefore requires
XChaCha20 implemented on *both* ends plus the per-message tag — which is exactly
this hybrid. It is not "AES only"; it is "AES where available, XChaCha20
otherwise, stated explicitly in every message."

**Cipher cross-language detail.** AES-256-GCM is byte-identical between the
Python side (cryptography / OpenSSL, which always has a software path) and the
C++ side (libsodium, hardware-gated) — verified directly: identical key, nonce,
AAD and plaintext produce identical ciphertext+tag.

**Verified matrix** (live harness, bidirectional, DH ratchet every turn):

| Alice | Bob | Result |
|-------|-----|--------|
| Python AES | C++ AES | 6/6 |
| Python XChaCha20 | C++ XChaCha20 | 6/6 |
| C++ AES | Python XChaCha20 (mixed) | 6/6 |
| Python auto | C++ auto (probe-driven) | 6/6 |

The mixed row is the decisive one: one side encrypts every message with
AES-256-GCM and the other with XChaCha20-Poly1305, in a single conversation, each
decrypting the other purely by reading the cipher tag.

```bash
# Linux / macOS:
g++ -std=c++17 tests/ratchet_cli.cpp -lsodium -o ratchet_cli_cpp
# mixed-cipher bidirectional conversation:
python tests/live_harness.py \
    --alice "./ratchet_cli_cpp"        --alice-cipher aes \
    --bob   "python3 tests/ratchet_cli.py" --bob-cipher xchacha --turns 6
```

The property suite (`test_ratchet.py`, now 19 tests) runs forward secrecy and the
round-trip under **both** ciphers, authenticates the cipher tag, and covers a
sender switching cipher mid-conversation.
