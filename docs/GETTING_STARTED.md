# Getting started

This is the document to follow if you have just cloned the repository and want
to see the application working. It goes from nothing to two chat windows talking
to each other over verified TLS.

It is written for someone who has not seen the project before. Every step says
what you should see, so you can tell whether it worked before moving on — most
of the time people lose here is spent several steps past the one that actually
failed.

**Rough timings.** Stage 1 takes about ten minutes. Stage 2 takes about five.
Stage 3 depends almost entirely on how long Qt takes to install, which is
usually 20–40 minutes and mostly unattended.

---

## Before you start

| You need | Version | Notes |
|---|---|---|
| Python | 3.10 or newer | For the relay and the tests |
| Git | any | To clone |
| A terminal | — | On Windows use **Git Bash**, not PowerShell or `cmd` |
| Qt + Qt Creator | 6.5 or newer | **Stage 3 only.** Developed on 6.11 |
| A C++17 compiler | — | **Stage 3 only.** Comes with the Qt installer |
| libsodium | 1.0.18 or newer | **Stage 3 only.** See Stage 3, step 2 |

Stages 1 and 2 need only Python. You can get most of the way through this
document, including proof that the encryption works, before installing Qt.

> **Windows users: use Git Bash.** The shell scripts (`run_tests.sh`,
> `run_interop.sh`) are bash. Right-click the project folder and choose
> *Git Bash Here*. PowerShell will fail on the first line and the error will not
> obviously say why.

---

## Stage 1 — The relay and the test suite

### 1.1 Clone and enter the project

```bash
git clone <this-repo-url> chat-e2ee
cd chat-e2ee
```

Everything below is run from this folder — the one containing `run_tests.sh`.

### 1.2 Check your Python

```bash
python --version
```

If `python` is not found, try `py --version` (Windows) or `python3 --version`.
Use whichever works; `run_tests.sh` probes all three in that order.

> A pre-release interpreter (a `b` or `rc` in the version, for example
> `3.15.0b4`) will run everything correctly, but for a result you intend to cite
> it is worth using a stable release so the environment can be identified later.
> `run_tests.sh` prints the interpreter version and flags pre-releases
> explicitly for exactly this reason.

### 1.3 Install the dependencies

```bash
python -m pip install -r requirements.txt
```

Five packages: `cryptography`, `pynacl`, `pytest`, `pytest-asyncio`,
`websockets`. All ship as prebuilt wheels, so no compiler is needed and this
should take well under a minute.

If you want the exact versions a recorded run used rather than the newest
compatible ones, use `requirements-lock.txt` instead.

### 1.4 Generate your own lab certificate authority

```bash
python tools/make_demo_pki.py
```

This creates `pki/` containing a root CA and a relay certificate, and copies the
**public** root into `client/pki/demo-ca.crt` so the client will trust it.

**Why this exists.** The client verifies TLS properly — it checks the
certificate chain and the hostname, and refuses the connection if either fails.
That is the correct behaviour, but it means you cannot just point it at a relay
on your laptop, because no public authority will issue a certificate for
`localhost`. So the project ships a generator for a small private authority
whose root is compiled into the client. The verification performed is genuine;
only the authority is local. [TLS_WITHOUT_HOSTING.md](TLS_WITHOUT_HOSTING.md)
explains the design.

**Why it must be your own.** `pki/` is deliberately excluded from version
control, because it contains `ca.key` — the key that can mint certificates this
application trusts. Every checkout therefore generates its own. Running the
script a second time keeps the existing root and re-issues only the leaf, which
is what you want.

You should see, near the end of the output:

```
  client trust anchor installed: .../client/pki/demo-ca.crt
```

If it instead says **updated**, and you have already built the client, rebuild
it — the root is compiled in as a Qt resource, so an existing binary still
carries the old one.

### 1.5 Run the tests

```bash
bash run_tests.sh
```

This installs dependencies if needed, generates the PKI if it is missing, runs
the red-team harness, then runs the whole suite. It takes roughly two minutes.

**What you should see at the end:**

```
512 passed in ~110s
```

**What to check if the number is different:**

- **Any `skipped`.** A skip is a silent gap, not a pass. The usual cause is a
  missing `pki/` — go back to 1.4. One environment-dependent skip in
  `test_schema_migration.py` is expected if you are running as **root** on
  Linux, because the test needs the filesystem to honour the read-only bit;
  running as a normal user, it passes.
- **Failures mentioning ports.** The socket tests bind fixed ports (8791, 8799,
  8811–8813, 8821). Something else is holding one. Stop it and re-run.

Full detail on what each module covers is in [../tests/README.md](../tests/README.md).

---

## Stage 2 — Watch the encryption work, without the app

This is the fastest way to see the point of the project, and it needs no Qt.

```bash
PYTHONPATH=server python tests/e2ee_redteam.py
```

Three experiments run against the same cryptographic code the application uses:

1. **A passive relay.** Everything the server can see is printed. It is
   ciphertext, and it stays ciphertext.
2. **An active man-in-the-middle.** The attack is actually carried out — the
   relay substitutes its own keys and reads the conversation — and then the
   safety-number comparison detects it. This is the experiment worth
   understanding, because it shows precisely which human step the guarantee
   depends on.
3. **File transfer.** Old file keys do not open new files.

The output is written as an argument rather than a pass/fail list, which makes
it useful material for a report.

There is also a smaller demonstration that runs a real message through a real
relay:

```bash
python server/demo_proof.py
```

It prints, side by side, what the user typed and what the server saw.

---

## Stage 3 — Build and run the client

### 3.1 Install Qt

Get the Qt Online Installer from [qt.io](https://www.qt.io/download-qt-installer).
Under your Qt 6.x version, tick:

- **Desktop** kit (MinGW on Windows, GCC on Linux, clang on macOS)
- **Qt WebSockets** — easy to miss, and the project will not configure without it
- **Android** kit, only if you want the phone build

Qt Creator comes with the installer.

> The project requires Qt **6.5** or newer (`find_package(Qt6 6.5 ...)`), and
> was developed on 6.11. The modules used are Quick, QuickControls2, WebSockets,
> Sql and PrintSupport, plus Widgets on desktop for the tray-icon notifications.

### 3.2 Make libsodium findable

This is the step that most often goes wrong, so it is worth doing deliberately.

**Windows (MinGW).** `CMakeLists.txt` expects the prebuilt MinGW tarball
extracted to `C:/libsodium`, so that `C:/libsodium/libsodium-win64/include/sodium.h`
exists. Download `libsodium-1.0.20-stable-mingw.tar.gz` from the
[libsodium releases](https://github.com/jedisct1/libsodium/releases) and extract
it there. If you keep it elsewhere, pass the path:

```bash
cmake -S client -B client/build -DSODIUM_ROOT=D:/libs/libsodium-win64
```

If it is not found, CMake stops with a clear `FATAL_ERROR` naming the path it
looked in — this one fails loudly rather than silently.

**Linux.** `sudo apt install libsodium-dev` — CMake finds it automatically.

**macOS.** `brew install libsodium`.

> On Linux and macOS the lookup is a `find_library` that does **not** fail the
> build when it misses. Instead the `HAVE_SODIUM` definition is left undefined
> and the cryptography compiles to stubs. The application then builds and runs,
> but registers an empty public key and the relay rejects it at login. If the
> app builds but you cannot log in, check the CMake output for libsodium first.

### 3.3 Configure and build

**In Qt Creator:** *File → Open File or Project*, choose `client/CMakeLists.txt`,
select your Desktop kit, and press Build. [QT_CREATOR_GUIDE.md](QT_CREATOR_GUIDE.md)
walks through this with the dialogs described.

**From the command line:**

```bash
cmake -S client -B client/build -DCMAKE_PREFIX_PATH=/path/to/Qt/6.11.0/gcc_64
cmake --build client/build
```

Watch the configure output for this line:

```
-- Lab CA embedded from client/pki/demo-ca.crt
```

If you instead see a **warning** that `demo-ca.crt` was not found, you skipped
step 1.4. The client will build, but every `wss://` connection to a lab relay
will fail certificate verification — by design.

### 3.4 Start the relay

In a terminal, from the project root, leave this running:

```bash
python server/server.py --demo-tls
```

You should see the certificate it is actually serving, then:

```
INFO  Listening on wss://0.0.0.0:8765
```

If it says `WARNING Running WITHOUT TLS`, the certificate did not load — check
that `pki/server.crt` and `pki/server.key` exist.

> `--demo-tls` serves the lab certificate from `pki/`. For a plain unencrypted
> relay during development, use `--host 127.0.0.1 --port 8765` with no TLS
> flags, and connect the client to `ws://` rather than `wss://`.

### 3.5 Run two clients and talk

Start the application twice — two separate windows, two separate users.

In each window:

1. Leave the server field at its default, **`wss://localhost:8765`**.
2. Choose a nickname, a password and a date of birth, and register.
3. Do the same in the second window with a different nickname.

Each will now see the other in the user list.

### 3.6 Verify the safety number

Before the first message is allowed, both sides must confirm the safety number.
Open the peer's details in each window and compare the numbers shown. They must
match; then each user confirms **on their own device**.

This is not a formality — it is the step that makes the relay untrusted. If a
malicious relay had substituted its own keys, the two numbers would differ, and
that difference is the only signal the users get. Stage 2's second experiment
demonstrates exactly this.

Once both have confirmed, messages and files flow.

---

## Stage 4 — Optional: the Android build

You need the Android kit installed through the Qt Maintenance Tool (NDK + SDK),
and Qt Creator's *Set Up SDK* step completed so that OpenSSL for Android is
present — Qt does not ship it, and without it `wss://` fails at runtime with
"No functional TLS backend was found".

The cross-compiled libsodium archives for `arm64-v8a` and `x86_64` are committed
under `client/third_party/libsodium/`, so no cross-compile is needed. Watch for
this line in the CMake output:

```
-- Android libsodium: linking .../third_party/libsodium/arm64-v8a/libsodium.a
```

A **warning** there instead means the archive was not found and the crypto will
be stubbed — the app will start and then fail at login.

### Reaching the relay from the phone

Two options.

**Over USB, with the relay on your computer.** `adb reverse` maps the phone's
`localhost:8765` to your machine's, so the phone can use the same URL as the
desktop and the certificate's `localhost` name still matches:

```bash
adb reverse tcp:8765 tcp:8765
```

Then start the relay with `python server/server.py --demo-tls` and connect the
phone to `wss://localhost:8765`.

**Over Wi-Fi, both on the same network.** The lab certificate already includes
your machine's LAN address in its subject-alternative names at the time you
generated it. Connect the phone to `wss://<your-LAN-IP>:8765`. If your address
has changed since, re-issue just the leaf — this keeps the root, so **no client
rebuild is needed**:

```bash
python tools/make_demo_pki.py --leaf-only --ip 192.168.1.42
```

You will also need to allow inbound TCP 8765 through your firewall.

---

## Where to go next

- Something failed → [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- How it works internally → [ARCHITECTURE.md](ARCHITECTURE.md)
- What the tests actually prove → [../tests/README.md](../tests/README.md)
- Running the relay on a real server → [DEPLOY_START_HERE.md](DEPLOY_START_HERE.md)
- The security claims, and their limits → [../SECURITY.md](../SECURITY.md)
