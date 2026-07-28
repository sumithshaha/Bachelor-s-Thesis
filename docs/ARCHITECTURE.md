# Architecture

How the pieces fit, and why they are arranged this way. If you want to run the
application, read [GETTING_STARTED.md](GETTING_STARTED.md) first — this document
assumes you have seen it working.

---

## The central constraint

Every design decision here follows from one rule: **the relay must be able to do
its job without being able to read anything.**

That rules out the obvious architecture, in which the server holds accounts,
stores messages and hands them to whoever authenticates. It forces the
cryptography onto the endpoints, which in turn forces the relay to be much
dumber than it would otherwise be — it moves opaque blobs, tracks who is
online, and stores what it could not deliver. It never holds a key that opens
anything.

The consequence worth stating early: **the relay is not trusted, so it must not
need to be.** That is why safety-number verification exists, and why it is a
required step rather than an optional one.

---

## Components

```
┌─────────────────────────┐          ┌─────────────────────────┐
│  Client (Android)       │          │  Client (Windows/Linux) │
│                         │          │                         │
│  QML interface          │          │  QML interface          │
│  ─────────────          │          │  ─────────────          │
│  ChatClient   transport │          │  ChatClient   transport │
│  CryptoBox    ratchet   │          │  CryptoBox    ratchet   │
│  X3dh         agreement │          │  X3dh         agreement │
│  FileCrypto   files     │          │  FileCrypto   files     │
│  HistoryStore SQLite    │          │  HistoryStore SQLite    │
│  AppLock      biometric │          │  AppLock      Hello/PIN │
└───────────┬─────────────┘          └───────────┬─────────────┘
            │                                    │
            │        wss://  — TLS 1.2+          │
            │   chain and hostname verified      │
            └────────────────┬───────────────────┘
                             │
                ┌────────────┴────────────┐
                │  Relay (server.py)      │
                │                         │
                │  accounts (Argon2id)    │
                │  public-key directory   │
                │  presence               │
                │  store-and-forward      │
                │  prekey pool            │
                │  SQLite (WAL)           │
                └─────────────────────────┘
                    sees: ciphertext,
                    sender, recipient,
                    timing, size
```

### Client

Qt 6 with QML for the interface and C++ for everything else, one source tree for
all platforms. The C++ side splits by responsibility:

| Unit | Responsibility |
|---|---|
| `chatclient.cpp/.h` | Transport, protocol, session lifecycle, orchestration |
| `cryptobox.cpp/.h` | Double Ratchet: chains, message keys, skipped-key handling |
| `x3dh.cpp/.h` | Initial key agreement. No Qt dependency — plain `std::vector` |
| `filecrypto.cpp/.h` | Chunked file encryption |
| `historystore.cpp/.h` | Local SQLite history, sealed at rest |
| `localization.cpp/.h` | English, Finnish and Swedish string tables |
| `applock.cpp/.h` | PIN, Windows Hello, Android biometric gate |
| `logbuffer.cpp/.h` | In-app diagnostic log ring |
| `usermodel`, `messagemodel` | Qt models backing the QML lists |

`chatclient.cpp` is much the largest of these. It carries the protocol state
machine, and the awkward parts of a real system live there: reconnection,
out-of-order delivery, peers who change identity, verification episodes that
stall, and outbound messages that must be held rather than dropped.

Android additionally has four small Java classes under
`client/android/src/fi/tamk/chate2ee/` for biometrics, notifications and the
foreground service, reached through JNI.

### Relay

A single Python file, `server/server.py`, on `asyncio` and the `websockets`
library. Its whole runtime dependency list is `websockets`.

It handles registration and login against Argon2id verifiers, publishes a
directory of users' public identity keys, tracks presence, relays frames between
connected users, stores frames for users who are offline, and holds the pool of
one-time prekeys that X3DH consumes.

It does not decrypt, and it has no key material that would let it.

### Python reference implementation

`server/crypto_core.py` and `server/file_crypto.py` implement the same ratchet
and file encryption in Python. They are **not used by the relay**. They exist so
the C++ implementation has something independent to be checked against — see
*Two implementations* below.

---

## The life of a message

1. **Session setup, once per pair.** The sender fetches the recipient's prekey
   bundle from the relay: long-term identity key, signed prekey, and a one-time
   prekey if any remain. X3DH performs three or four Diffie-Hellman operations
   over these and derives a shared secret. The one-time prekey is consumed, so a
   replay of the same opener fails rather than silently succeeding.

2. **Ratchet initialisation.** The shared secret seeds the Double Ratchet's root
   chain. The responder's first ratchet key is its **signed prekey**, not its
   long-term identity key — using the identity key would leave a long-lived key
   in the ratchet and undermine forward secrecy.

3. **Encryption.** Each message derives a fresh message key from the sending
   chain. The chain advances, so the key that encrypted this message cannot be
   reconstructed from later state. Content is sealed with AES-256-GCM or
   XChaCha20-Poly1305; the header states which, so the two ends need not agree in
   advance.

4. **Transport.** The client sends a JSON frame naming the recipient and carrying
   the ciphertext and ratchet header. TLS protects it in transit; the relay reads
   only the routing fields.

5. **Relay.** If the recipient is connected, the frame is forwarded. If not, it
   is stored and delivered on their next login. The relay overwrites the `from`
   field with the authenticated nickname, so a client cannot claim to be someone
   else.

6. **Decryption.** The recipient advances its receiving chain to the message
   number in the header, deriving and retaining any skipped keys so
   out-of-order and delayed messages still open. Retention is bounded — an
   unbounded store of skipped keys would quietly void forward secrecy.

7. **Storage.** The plaintext is written to the local SQLite history, sealed
   under a device-local key.

### Ratchet advance

Two ratchets turn. The **symmetric** ratchet advances a chain key per message,
which gives forward secrecy within a chain. The **Diffie-Hellman** ratchet
introduces fresh entropy whenever the direction of conversation changes, which
is what allows a compromised session to recover.

A conversation that only flows one way never changes direction, so the DH
ratchet would never turn. The client therefore forces it: after
**8 messages** in one direction, or **15 minutes** idle, it sends a `rekey-ping`
and the peer answers `rekey-pong`. That exchange turns the DH ratchet and
restores post-compromise security. The obligation to answer a ping is tracked as
a debt that survives a rekey, because a pong owed on an old chain is still owed
on a new one.

Signed prekeys rotate every **7 days**, with the previous key retained for a
further **2 days** so bundles already in flight still open. The retired private
key is wiped with `sodium_memzero`.

---

## The safety number

Two users' identity keys are sorted, concatenated, hashed with SHA-256, and the
first 30 bytes rendered as six five-digit groups. Sorting is what makes both
sides compute the same value from opposite viewpoints.

```
12345 67890 11223 34455 66778 89900
```

Both users compare this out of band — in person, over the phone, any channel the
relay does not control — and each then confirms **on their own device**.

This is the entire defence against a hostile relay. A relay that substitutes its
own keys can read everything, and the *only* signal available to the users is
that their two numbers differ. `tests/e2ee_redteam.py` performs exactly that
attack and then catches it, which is the clearest way to see why the step
matters.

Because the guarantee depends on it, the client will not send until the local
user has verified. Messages to an unverified or offline peer are **queued, not
dropped**, and flush once verification completes or the peer reconnects.

---

## Files

Files are chunked, and each chunk is encrypted. The important detail is the key:
each transfer generates a **fresh random key**, which is delivered to the
recipient inside a `keyenc` field in the `file_init` frame — that is, through
the ratchet.

An earlier design derived the file key from the long-term identity, which meant
an attacker who later stole that identity could decrypt every file ever sent.
Routing a random key through the ratchet gives files the same forward secrecy and
post-compromise security as text. `tests/e2ee_redteam.py` demonstrates the
difference between the two designs directly.

---

## Transport security

The client verifies TLS strictly: full chain validation and a hostname check,
with no exception path. The `ignoreSslErrors()` call that earlier made
development convenient has been removed, because a connection that is encrypted
but unauthenticated is exactly the connection a man in the middle wants.

That strictness creates a practical problem — no public authority will issue a
certificate for `localhost` — which is solved by a small private authority
generated by `tools/make_demo_pki.py`. Its root is compiled into the client as a
Qt resource and scoped to loopback and LAN addresses. Public hosts still validate
against the system trust store. The verification is genuine in both cases; only
the authority differs. [TLS_WITHOUT_HOSTING.md](TLS_WITHOUT_HOSTING.md) covers
the design and its limits.

---

## Two implementations, checked against each other

The ratchet exists twice: in C++ against libsodium, and in Python against
`cryptography` and PyNaCl. This is deliberate. A single implementation can only
be checked against its own assumptions; two independent ones disagree wherever
either has misread the specification.

`run_interop.sh` runs ten checks across four tiers:

| Tier | What it establishes |
|---|---|
| 2 | Python encrypts a five-message session; C++ decrypts it |
| 3 | Both hold a live bidirectional conversation, direction alternating each turn so a DH ratchet fires every time |
| Hybrid | The same conversation with one side on AES-256-GCM and the other on XChaCha20-Poly1305, each reading the other's cipher tag |
| 4 | X3DH pinned to fixed vectors — the agreement happens before any message exists, so it cannot be proven by two implementations talking |

The mixed-cipher row is the decisive one for the hybrid design, and Tier 4
exists because agreement cannot be demonstrated conversationally.

---

## Data at rest

**On the client.** Message history is SQLite, sealed under a device-local key.
The long-term identity is stored in a versioned format; v2 wraps the private key
rather than storing it raw. App lock adds a PIN, Windows Hello or Android
biometric gate, and `FLAG_SECURE` keeps the app out of the recents screenshot.

**On the relay.** SQLite in WAL mode, holding accounts, public keys, presence
metadata and undelivered ciphertext. Passwords and recovery answers are Argon2id
verifiers — the relay cannot recover either, only check a candidate. The schema
migrates itself forward on startup, so deploying a newer relay onto an existing
database does not fail on the first stored message.

---

## What the relay unavoidably sees

Worth stating plainly, because it is the honest limit of the design:

- who is registered, and their public identity keys
- who is online, and when
- who sends to whom, at what time
- how large each message and file is

Message and file **contents** are never available to it. Hiding the metadata
would require a fundamentally different architecture — mixing, padding, cover
traffic — which is out of scope here and named as such in
[../SECURITY.md](../SECURITY.md).
