# ChatE2EE

A cross-platform, end-to-end encrypted chat application. Qt 6 / QML client for
Windows, Linux and Android; Python asyncio WebSocket relay. The relay carries
ciphertext it cannot read.

Bachelor's thesis project, Software Engineering, Tampere University of Applied
Sciences (TAMK).

---

## What this is, in one paragraph

Transport encryption (TLS) protects a message between a client and a server,
but the server still sees plaintext. ChatE2EE closes that gap: messages are
encrypted on the sending device and decrypted only on the receiving one, so the
relay handles sealed envelopes and never holds a key that opens them. The
cryptography follows the Signal Protocol design — **X3DH** for initial key
agreement and a **Double Ratchet** for message keys — implemented twice, once in
C++ against libsodium and once in Python, with conformance vectors pinning the
two implementations to identical output.

The interesting engineering claim is not "it encrypts things". It is that the
security properties are **checked rather than asserted**: 512 automated tests,
a cross-language conformance suite, and a red-team harness that reproduces the
man-in-the-middle attack the safety-number check is supposed to catch, and then
catches it.

---

## Try it in about ten minutes

You need Python 3.10+ and a terminal. This runs the relay and proves the
encryption without building the Qt client at all.

```bash
git clone <this-repo-url> chat-e2ee
cd chat-e2ee

python -m pip install -r requirements.txt
python tools/make_demo_pki.py          # generates your own lab certificate authority

bash run_tests.sh                      # 512 tests, about two minutes
```

To watch the encryption happen:

```bash
PYTHONPATH=server python tests/e2ee_redteam.py
```

That prints three experiments against the real cryptographic code: a passive
relay learns nothing, an active man-in-the-middle succeeds but is detected by
the safety number, and old file keys do not open new files.

For the full application — two chat windows talking to each other — follow
**[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)**. It assumes nothing and
takes about half an hour, most of which is Qt installing.

---

## Documentation

Start at **[docs/README.md](docs/README.md)**, which routes you to the right
document. The short version:

| I want to… | Read |
|---|---|
| Get it running, start to finish | [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) |
| Understand how it fits together | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Build the client | [docs/BUILD.md](docs/BUILD.md) · [docs/QT_CREATOR_GUIDE.md](docs/QT_CREATOR_GUIDE.md) |
| Fix something that went wrong | [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |
| Run and understand the tests | [tests/README.md](tests/README.md) |
| Deploy the relay to a server | [docs/DEPLOY_START_HERE.md](docs/DEPLOY_START_HERE.md) |
| Understand the TLS setup | [docs/TLS_WITHOUT_HOSTING.md](docs/TLS_WITHOUT_HOSTING.md) |
| Read the security claims and limits | [SECURITY.md](SECURITY.md) |

---

## What it does

**Messaging.** Real-time text between named users, with edit, delete, reactions,
typing indicators, read state, and message history that survives restarts.
Messages to an offline peer are queued and delivered on reconnect.

**File transfer.** Chunked, encrypted end to end, with a fresh random key per
file delivered through the ratchet — so files inherit the same forward secrecy
as text rather than being encrypted under a long-term key.

**Identity and verification.** Each user has a long-term Ed25519 identity.
Before a conversation is allowed, both parties compare a **safety number**
derived from the two identities. This is the step that makes the relay
untrusted: without it, a malicious relay could substitute its own keys and read
everything.

**Forward secrecy and post-compromise security.** The Double Ratchet advances
keys with every message, so a stolen key does not decrypt earlier traffic
(forward secrecy). A rekey heartbeat forces a fresh DH ratchet after a period of
one-way traffic, so a compromised session heals once the attacker stops
(post-compromise security).

**Local security.** App lock with PIN, biometric login via Android
`BiometricPrompt` or Windows Hello, and `FLAG_SECURE` to keep the app out of the
Android recents screenshot. Passwords and recovery answers are stored as Argon2id
verifiers, never as recoverable values.

**Interface.** QML across desktop and mobile from one source tree, in English,
Finnish and Swedish.

---

## How it is put together

```
 Android client                Windows / Linux client
 (Qt 6 QML + C++)              (Qt 6 QML + C++)
        |                              |
        |   wss://  (TLS 1.2+)         |
        +---------------+--------------+
                        |
              Python asyncio relay
              (websockets, SQLite)
                        |
                   [ ciphertext only ]
```

The relay authenticates users, keeps a public-key directory, tracks presence,
and stores undelivered frames. It never sees a plaintext message body and never
holds a private key belonging to a user. What it necessarily does see is
metadata: who talks to whom, when, and roughly how much. That limit is real and
is discussed honestly in [SECURITY.md](SECURITY.md).

| Layer | Choice |
|---|---|
| Key agreement | X3DH (Ed25519 identity, signed prekey, one-time prekeys) |
| Message keys | Double Ratchet, X25519, HKDF-SHA256 |
| Content cipher | AES-256-GCM, with XChaCha20-Poly1305 as an interoperable alternative |
| Password storage | Argon2id verifiers |
| Crypto library | libsodium 1.0.18+ (C++), `cryptography` + PyNaCl (Python reference) |
| Transport | WebSocket over TLS, certificate chain and hostname strictly verified |
| Storage | SQLite (WAL) on both client and relay |

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Repository map

```
client/            Qt 6 client
  src/             C++: ratchet, X3DH, storage, transport, platform glue
  qml/             QML: login, chat, message delegate, user list, lock screen
  android/         Manifest and Java helpers (biometrics, notifications, service)
  pki/             demo-ca.crt — the lab root, compiled into the binary
  third_party/     libsodium cross-compiled for the Android ABIs
server/
  server.py        The relay
  crypto_core.py   Python reference ratchet — the C++ side is checked against it
  file_crypto.py   Python reference for file encryption
  prekey_store.py  X3DH prekey pool
  deploy/          Provisioning scripts and the systemd unit
tests/             512 tests across 33 modules, plus the red-team harness
tools/             Lab CA generator, publication safety check, source checkers
docs/              Everything in the table above
run_tests.sh       One command: dependencies, PKI, harness, full suite
run_interop.sh     One command: the Python↔C++ cross-language proofs
```

---

## Verifying it works

Three independent commands, each answering a different question.

```bash
bash run_tests.sh      # does the system behave correctly?      512 tests
bash run_interop.sh    # do C++ and Python agree byte for byte?  10 checks
PYTHONPATH=server python tests/e2ee_redteam.py   # does the encryption hold up?
```

`run_tests.sh` takes about two minutes. Every async test starts its own relay in
process, so nothing needs to be running first. `run_interop.sh` needs a C++
compiler and libsodium; without them it skips cleanly and says what to install.

A note on honesty, since this is a thesis artefact: two of the 33 test modules
(`test_qml_shadowing.py`, `test_build_sources.py`) read the C++ and QML source
rather than executing it, because the Qt client cannot be compiled inside a
Python test run. That is weaker evidence than running the code and is labelled
as such in [tests/README.md](tests/README.md) — but both guard failure modes
that actually occurred and stopped the application from starting.

---

## Requirements

| Component | Needs |
|---|---|
| Relay | Python 3.10+; `websockets` is the only runtime dependency |
| Test suite | Python 3.10+ and `requirements.txt` (five packages, all prebuilt wheels) |
| Desktop client | Qt 6.5+ (developed on 6.11), C++17 compiler, CMake 3.21+, libsodium 1.0.18+ |
| Android client | The above plus an Android kit (NDK + SDK) in Qt Creator |
| Cross-language proofs | A C++ compiler and libsodium headers |

The Android package is `fi.tamk.chate2ee` and declares six permissions:
`INTERNET`, `USE_BIOMETRIC`, `POST_NOTIFICATIONS`, `VIBRATE`,
`FOREGROUND_SERVICE` and `FOREGROUND_SERVICE_DATA_SYNC`.

---

## Scope and limitations

Stated plainly, because a security project that only lists its strengths is not
being evaluated honestly.

- **Metadata is not protected.** The relay sees who talks to whom, when, and
  message sizes. Hiding that needs a different architecture.
- **Safety-number verification is manual.** The end-to-end guarantee against a
  hostile relay rests on users actually comparing the number. The app requires
  it before allowing a conversation, but it cannot make the comparison for them.
- **One relay, no federation.** Users must agree on a server.
- **No group chat.** One-to-one only.
- **Not audited.** This is student work implementing a well-specified protocol,
  and it should be read as a study of that protocol rather than as software to
  trust with anything that matters.
- **The lab certificate authority is for demonstration.** It exists so that a
  relay on a laptop can be reached over genuinely verified TLS without buying a
  domain. See [docs/TLS_WITHOUT_HOSTING.md](docs/TLS_WITHOUT_HOSTING.md).

---

## Licence

MIT — see [LICENSE](LICENSE).

The application links Qt 6 (LGPL-3.0 or commercial) and libsodium (ISC), and
neither is relicensed by this project. The compiled libsodium archives under
`client/third_party/libsodium/` are redistributed under the ISC licence.

---

## Academic context

Written as a Bachelor's thesis in Software Engineering at TAMK. The thesis text
itself is not part of this repository; this is the software it describes,
published so that the results can be reproduced and reviewed.

If you are reproducing this for review, [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)
is the intended entry point, and [tests/README.md](tests/README.md) explains what
each part of the test suite is evidence *for*.
