# Build instructions

This document explains how to build and run the two halves of the project: the
Python server and the Qt/QML client.

## Prerequisites

| Component | Needs |
|-----------|-------|
| Server | Python 3.10+ and the `websockets` and `cryptography` packages |
| Client | Qt 6.5 or newer (developed on 6.11.0), a C++17 compiler, CMake 3.21+, and libsodium |
| Android client | The above plus the Android NDK and an Android Qt kit in Qt Creator |

## Server

```bash
cd server
python3 -m venv .venv && source .venv/bin/activate
pip install websockets cryptography

# Development: run without TLS on localhost.
python server.py --host 127.0.0.1 --port 8765

# Development WITH TLS on localhost. First make a self-signed certificate:
#   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
#       -days 365 -nodes -subj "/CN=localhost"
# then run with it, and connect the client to wss://localhost:8765:
python server.py --host 127.0.0.1 --port 8765 --cert cert.pem --key key.pem

# Production on a cPouta VM: obtain a certificate with certbot first, then:
python server.py --host 0.0.0.0 --port 8765 \
    --cert /etc/letsencrypt/live/YOURHOST/fullchain.pem \
    --key  /etc/letsencrypt/live/YOURHOST/privkey.pem
```

> **Note on the self-signed certificate:** because you signed it yourself, the
> client will not trust it automatically. The Qt client handles this: its
> `onSslErrors()` handler forgives the expected self-signed errors, but only
> when connecting to localhost, and stays strict for every real server. Connect
> using `wss://localhost:8765` (the name `localhost` must match the
> certificate's `/CN=localhost`).

### Obtaining a TLS certificate on cPouta

The server needs a domain name pointing at the VM's floating IP. Once DNS
resolves:

```bash
sudo certbot certonly --standalone -d yourhost.example.fi
```

This needs TCP port 80 open during the challenge and port 8765 (or 443) open
for the running service. CSC's cPouta security groups control this.

## Desktop client (Linux / Windows / macOS)

libsodium must be discoverable by CMake. On Debian/Ubuntu:

```bash
sudo apt install libsodium-dev
```

Then build with Qt Creator (open `client/CMakeLists.txt`) or from the command
line:

```bash
cd client
cmake -S . -B build -DCMAKE_PREFIX_PATH=/path/to/Qt/6.11.0/gcc_64
cmake --build build
./build/appChatE2EE
```

> Note on libsodium versions: the code derives keys with a hand-written
> HKDF-SHA256 built on `crypto_auth_hmacsha256`, so it works on libsodium
> 1.0.18 and newer. It does not require the `crypto_kdf_hkdf_*` API that only
> appeared in 1.0.19.

## Android client

1. Install an Android kit through the Qt Maintenance Tool (NDK + SDK).
2. Provide libsodium for Android. The simplest route is to build libsodium for
   the target ABI (arm64-v8a) and point CMake at it, or use a prebuilt package.
3. Select the Android kit in Qt Creator and build. `androiddeployqt` packages
   the APK automatically, reading `client/android/AndroidManifest.xml`.
4. The only permission requested is `INTERNET`.

> If AES-256-GCM hardware is unavailable on the target device,
> `crypto_aead_aes256gcm_is_available()` returns 0. A production build should
> fall back to XChaCha20-Poly1305 in that case; this is noted as future work.

## Running the tests

```bash
cd <project root>
pip install pytest pytest-asyncio
python -m pytest tests/ -v
```

## Reproducing the cross-language interop check

The file `tests/interop.cpp` (and the matching helper in
`server/crypto_core.py`) demonstrate that the C++ and Python sides implement
identical encryption:

```bash
# Python encrypts a message and prints a test vector...
python tests/make_vector.py > vec.json
# ...and C++ decrypts it.
g++ -std=c++17 tests/interop.cpp -lsodium -o interop
./interop <bob_priv> <alice_pub> <nonce> <ct>
```
