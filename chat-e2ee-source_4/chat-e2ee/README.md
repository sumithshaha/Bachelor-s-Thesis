# Chat Application with Encrypted Messaging

A cross-platform real-time chat application with **true end-to-end
encryption**, built as a Bachelor's thesis project at Tampere University of
Applied Sciences (TAMK).

- **Client:** Qt 6 / QML, targeting desktop (Windows, Linux, macOS) and Android
- **Server:** Python (`websockets` + `asyncio`), with TLS
- **Transport:** WebSockets over TLS (`wss://`)
- **Encryption:** X25519 key exchange → HKDF-SHA256 → AES-256-GCM

## The core idea

The server is treated as an untrusted relay. It routes and stores messages,
tracks who is online, and hands out users' public keys, but it **never sees a
single byte of plaintext**. Every message is encrypted on the sender's device
and only decrypted on the recipient's device. If the server were seized, all
anyone would find is ciphertext.

This is the difference between *transport* encryption (TLS, which protects the
link to the server but leaves the server able to read everything) and
*end-to-end* encryption (which excludes the server entirely). Both are used
here: TLS protects the connection, and E2EE protects the message contents.

## Features

- Login with a nickname (identity is a long-term key pair generated on-device)
- Real-time messaging over WebSockets
- Live online-user list with presence updates
- Message history persisted in SQLite (as ciphertext)
- End-to-end encryption with per-message authenticated encryption
- Key-fingerprint display ("safety numbers") to detect man-in-the-middle

## Layout

```
server/         Python WebSocket server
  server.py         the relay, presence tracking, SQLite, key directory
  crypto_core.py    reference implementation of the E2EE scheme
  demo_proof.py     prints proof that the server only sees ciphertext
client/         Qt 6 / QML client
  src/              C++ backend (WebSocket, models, crypto)
  qml/              the user interface
  android/          Android manifest
tests/          automated tests + cross-language interop check
docs/           build instructions
```

## Quick start

```bash
# 1. Start the server (development, no TLS)
cd server && python server.py --host 127.0.0.1 --port 8765

# 2. Build and run the client (see docs/BUILD.md for full detail)
cd client && cmake -S . -B build && cmake --build build && ./build/appChatE2EE

# 3. Run the tests
python -m pytest tests/ -v
```

See `docs/BUILD.md` for platform-specific build notes, TLS setup on CSC
cPouta, and how to reproduce the cross-language interop check.

## A note on scope

The encryption scheme uses long-term (static) keys. This gives confidentiality,
integrity, and sender authentication, but **not forward secrecy**: if a private
key is stolen, past messages encrypted to it can be read. Achieving forward
secrecy requires a ratcheting protocol such as Signal's Double Ratchet, which
is discussed in the thesis as future work. The static-key design is the same
trade-off the Threema messenger makes, and it is appropriate for the scope of a
Bachelor's thesis.
