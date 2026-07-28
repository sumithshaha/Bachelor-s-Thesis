# Build reference

Prerequisites, exact commands, and the platform-specific parts that go wrong.
For a guided first run see [GETTING_STARTED.md](GETTING_STARTED.md); for the
same build through Qt Creator's dialogs see
[QT_CREATOR_GUIDE.md](QT_CREATOR_GUIDE.md).

---

## Prerequisites

| Component | Requires |
|---|---|
| Relay | Python 3.10+. `websockets` is the **only** runtime dependency |
| Test suite | Python 3.10+ and `requirements.txt` — five packages, all prebuilt wheels |
| Desktop client | Qt **6.5+** (developed on 6.11), a C++17 compiler, CMake 3.21+, libsodium 1.0.18+ |
| Android client | The above plus an Android kit (NDK + SDK) and OpenSSL for Android |
| Cross-language proofs | A C++ compiler and libsodium **headers** |

Qt modules used: `Quick`, `QuickControls2`, `WebSockets`, `Sql`, `PrintSupport`,
plus `Widgets` on desktop only (the tray-icon notifications need it; the Android
build uses a JNI path instead).

> **libsodium 1.0.18 is genuinely enough.** Key derivation is a hand-written
> HKDF-SHA256 over `crypto_auth_hmacsha256`, so the `crypto_kdf_hkdf_*` API
> introduced in 1.0.19 is not required.

---

## Relay

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# websockets is the relay's ONLY runtime dependency. cryptography and pynacl
# belong to crypto_core.py and file_crypto.py, the Python reference
# implementations used by the tests. server.py imports neither, so a
# production VM does not need them.
pip install 'websockets>=13,<17'
```

### Running it

```bash
# Development, no TLS, loopback only:
python server.py --host 127.0.0.1 --port 8765

# Development WITH real, strictly-verified TLS against the lab authority:
python ../tools/make_demo_pki.py       # once
python server.py --demo-tls
# then connect the client to wss://localhost:8765

# Production, with a certificate from a public authority:
python server.py --host 0.0.0.0 --port 8765 \
    --cert /etc/letsencrypt/live/YOURHOST/fullchain.pem \
    --key  /etc/letsencrypt/live/YOURHOST/privkey.pem

# Preflight a certificate without binding a port. Exit status 0 means THIS
# user can read and load THESE files -- the check that separates "works as
# root" from "works under systemd":
python server.py --check-tls
```

All options:

| Flag | Default | Purpose |
|---|---|---|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `8765` | Bind port |
| `--db` | `chat.db` | SQLite path |
| `--cert` / `--key` | — | TLS certificate and private key |
| `--demo-tls` | off | Serve the lab certificate from `pki/` |
| `--check-tls` | off | Load the certificate, report, exit |

Certificate paths may also come from `CHATE2EE_TLS_CERT` and `CHATE2EE_TLS_KEY`
in the environment, which is how the systemd unit supplies them without editing
the command line.

> **On the removal of `ignoreSslErrors()`.** Earlier revisions used a self-signed
> `CN=localhost` certificate together with a handler that forgave the resulting
> errors on loopback. Both are gone. That connection was encrypted but
> *unauthenticated*, which is half of what TLS is for and precisely the half that
> stops someone in the network path presenting their own certificate. It was
> replaced by the lab authority in `tools/make_demo_pki.py`: the client builds
> and validates a real chain, checks the hostname against the SAN list, and
> refuses the connection if any of it fails — exactly as it does against a
> public authority. See [TLS_WITHOUT_HOSTING.md](TLS_WITHOUT_HOSTING.md).
>
> `server/server.crt` and `server/server.key` are the orphaned pair from that
> era. No code references them. Delete both — an ignored file is still a file on
> your disk, and one of them is a private key.

### Deploying to a server

[DEPLOY_START_HERE.md](DEPLOY_START_HERE.md) is the path;
[DEPLOY_CPOUTA.md](DEPLOY_CPOUTA.md) is the long-form runbook. The outline, for
a VM whose floating IP is `a.b.c.d`:

```bash
# 1. Open TCP 80 (certbot's HTTP-01 challenge) and 8765 in the security group.
#    Port 80 must be open again at RENEWAL time, 60 days later.

# 2. DNS: sslip.io resolves a-b-c-d.sslip.io to a.b.c.d, so no domain is
#    needed. For 86.50.230.46 the hostname is 86-50-230-46.sslip.io.

# 3. Rehearse against staging (free, unlimited), then issue for real.
sudo bash deploy/bootstrap_cpouta.sh --email you@tuni.fi

# 4. Install the relay and the service (idempotent; safe to re-run).
sudo bash deploy/install_cpouta.sh --domain a-b-c-d.sslip.io
```

> **The relay reads its certificate once, at startup.** `make_ssl_context()`
> calls `load_cert_chain()` before `serve()`, and the resulting `SSLContext`
> lives for the life of the process — there is no reload path. A renewed
> certificate therefore does not reach a running relay until something restarts
> it. `server/deploy/chate2ee-cert-deploy.sh` is a certbot deploy hook that
> forces the restart, and it also solves a permissions problem:
> `/etc/letsencrypt/live` is `0700 root:root`, so an unprivileged service user
> cannot read `privkey.pem` from there at all.

---

## Desktop client

### libsodium

**Linux (Debian/Ubuntu):**

```bash
sudo apt install libsodium-dev
```

**macOS:**

```bash
brew install libsodium
```

**Windows (MinGW):** `client/CMakeLists.txt` expects the prebuilt MinGW tarball
extracted to `C:/libsodium`, so that `C:/libsodium/libsodium-win64/include/sodium.h`
exists. Get `libsodium-1.0.20-stable-mingw.tar.gz` from the
[libsodium releases](https://github.com/jedisct1/libsodium/releases). Override
the location with `-DSODIUM_ROOT=...` if you keep it elsewhere. A post-build
step copies `libsodium-26.dll` next to the executable automatically.

> **The two platforms fail differently, and it matters.** On Windows a missing
> libsodium is a CMake `FATAL_ERROR` naming the path it searched. On Linux and
> macOS the lookup is a `find_library` that does **not** fail: `HAVE_SODIUM` is
> simply left undefined, the cryptography compiles to stubs, and the build
> succeeds. The application then starts, registers a zero-length public key, and
> is rejected by the relay at login. **If the app builds but you cannot log in,
> check the CMake output for libsodium before anything else.**

### The lab trust anchor

```bash
python tools/make_demo_pki.py
```

This must be done **before** configuring CMake. It writes `pki/` and installs the
public root at `client/pki/demo-ca.crt`, which `client/pki.qrc` compiles into the
binary as `:/pki/demo-ca.crt`.

Look for this line during configuration:

```
-- Lab CA embedded from client/pki/demo-ca.crt
```

A warning instead means the anchor is absent. The build still succeeds, but every
`wss://` connection to a loopback or LAN relay will fail verification — by
design, since the alternative would be falling back to unverified TLS.

The root is compiled in, so **changing it requires a rebuild**. Re-issuing only
the leaf (`--leaf-only`) does not, because the client trusts the root.

### Build

```bash
cmake -S client -B client/build -DCMAKE_PREFIX_PATH=/path/to/Qt/6.11.0/gcc_64
cmake --build client/build
./client/build/appChatE2EE
```

Or open `client/CMakeLists.txt` in Qt Creator and press Build.

> **Adding a source file:** every `.cpp` under `client/src/` must be listed in
> `client/CMakeLists.txt`. Omitting one still compiles — the header resolves and
> the file builds in isolation — and fails only at link time as a wall of
> undefined symbols. `tests/test_build_sources.py` checks this.

---

## Android client

1. Install an Android kit through the Qt Maintenance Tool (NDK + SDK).
2. Run **Set Up SDK** in Qt Creator so OpenSSL for Android is installed. Qt does
   not ship it, and without it `wss://` fails at runtime with
   *"No functional TLS backend was found"*. `CMakeLists.txt` includes it from
   `%LOCALAPPDATA%/Android/Sdk/android_openssl/android_openssl.cmake`; edit that
   path if your SDK lives elsewhere.
3. Select the Android kit and build. `androiddeployqt` packages the APK, reading
   `client/android/AndroidManifest.xml`.

libsodium for Android is already cross-compiled and committed under
`client/third_party/libsodium/<abi>/libsodium.a` for `arm64-v8a` and `x86_64`,
so no cross-compile is needed. Confirm during configuration:

```
-- Android libsodium: linking .../third_party/libsodium/arm64-v8a/libsodium.a
```

A warning there means the archive was not found for your ABI and the crypto will
be **stubbed** — the app will build, start, and then be rejected at login.

> `.gitignore` excludes `*.a` as build output, so the repository carries an
> explicit negation (`!client/third_party/libsodium/**/*.a`) to keep these
> archives tracked. If they are missing from your clone, check that rule
> survived. They cannot be regenerated from anything in this repository.

**Package and permissions.** The application id is `fi.tamk.chate2ee`. Six
permissions are declared:

| Permission | For |
|---|---|
| `INTERNET` | The relay connection |
| `USE_BIOMETRIC` | Fingerprint / device-credential login |
| `POST_NOTIFICATIONS` | Message notifications (API 33+) |
| `VIBRATE` | Notification feedback |
| `FOREGROUND_SERVICE` | Staying connected while backgrounded |
| `FOREGROUND_SERVICE_DATA_SYNC` | The service type matching the above |

No camera, no location, no contacts, no storage.

> If AES-256-GCM hardware is unavailable, `crypto_aead_aes256gcm_is_available()`
> returns 0 and the hybrid design falls back to XChaCha20-Poly1305. The
> cross-language proofs include a mixed row where one side uses each, so the
> fallback is exercised rather than assumed.

---

## Verifying the build

Three commands, three different questions.

```bash
bash run_tests.sh                                 # behaviour: 512 tests
bash run_interop.sh                               # C++/Python agreement: 10 checks
PYTHONPATH=server python tests/e2ee_redteam.py    # does the encryption hold up?
```

### `run_tests.sh`

Picks an interpreter (`python`, then `py`, then `python3`), prints the
environment, installs `requirements.txt`, generates the lab PKI if it is missing,
runs the red-team harness, then the whole suite. Works in Git Bash on Windows and
in bash elsewhere.

| Invocation | Effect |
|---|---|
| `bash run_tests.sh` | Everything. Roughly two minutes, ending `512 passed` |
| `bash run_tests.sh --fast` | Offline crypto and unit tests only; skips the socket tests |
| `bash run_tests.sh --no-install` | Skip `pip install` when dependencies are present |

No external server is needed — the async tests start their own relay in process.
They bind fixed ports (8791, 8799, 8811–8813, 8821), so nothing else may hold
those.

To drive pytest directly:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

See [../tests/README.md](../tests/README.md) for what each module covers.

### `run_interop.sh`

Ten checks proving the C++ and Python implementations agree: Tier 2 sequence
interop (2), Tier 3 live bidirectional harness (3), the hybrid cipher matrix
including the mixed row (4), and Tier 4 X3DH vector conformance (1).

Narrow it with `--tier2`, `--tier3` or `--hybrid`; keep the binaries with
`--keep`. Logs stay in `build-interop/`. Without a C++ toolchain it skips
cleanly and says what to install. On Windows it needs
`C:/libsodium/libsodium-win64` — the same place `client/CMakeLists.txt` uses —
overridable with `SODIUM_ROOT=... bash run_interop.sh`.

See [../tests/RATCHET_TESTING.md](../tests/RATCHET_TESTING.md) for the strategy
behind the tiers.
