# The easy guide: running the app, one small step at a time

This guide starts from the very beginning. It does not assume you remember
anything between steps, and it explains *why* you are doing each thing rather
than only what to type. Take it slowly — you cannot break anything by going
carefully.

If you are already comfortable with terminals and build systems,
[GETTING_STARTED.md](GETTING_STARTED.md) covers the same ground faster.

Read **The big picture** first. It makes everything after it make sense.

---

## The big picture

The project is **two programs that talk to each other**:

1. **The server** — think of it as a *post office*. It does not read letters. It
   takes a sealed envelope from one person and carries it to another, and keeps
   a list of who is currently in the building (online).

2. **The client** — the *app a person uses*: the window with the login box and
   the messages. Each person runs their own copy.

For a chat to happen you need the post office running first, then **two people**
— two copies of the client — so there is someone to talk to.

Here is the whole point of the project in one sentence:

> The two people lock their messages before sending, and only the other person
> can unlock them — so the post office carries sealed envelopes it can never
> open.

That is what *end-to-end encryption* means. Keep that picture in your head;
everything below serves it.

We will go in this order, easiest first:

- **Stage 1** — start the server.
- **Stage 2** — watch the encryption work, with no app at all. A two-minute win.
- **Stage 3** — build and run the real app on your computer.
- **Stage 4** — have two app windows chat with each other.
- **Stage 5** — optional: put the app on an Android phone.

Stages 1 and 2 need only Python. You can do both before installing Qt, which is
the slow part.

---

## Words you will see

You do not need to memorise these — just glance at them so they are not
strange later.

- **Terminal** (also *command line*, *console*): a text window where you type
  commands instead of clicking. On Windows, use **Git Bash** — it comes with
  Git, and you open it by right-clicking a folder and choosing *Git Bash Here*.
  PowerShell and `cmd` will not run this project's scripts.
- **Python** — the language the server is written in. Install once.
- **Qt** (say "cute") — the toolkit the app is built with. Comes with **Qt
  Creator**, where you press the build button.
- **libsodium** — the small library that does the actual locking and unlocking.
  The app needs it, and it is the step people most often miss, so it gets a loud
  reminder when we reach it.
- **Building** (or *compiling*) — turning written code into a program you can
  run. You press a button; the computer does the work.
- **Certificate** — the thing that proves a server is who it says it is. This is
  separate from the message encryption, and Stage 1 explains why the project has
  its own.

---

## Stage 1 — Start the server

The server has no window and no buttons. It runs quietly in a terminal.

### 1.1 Get the code and check Python

```bash
git clone <this-repo-url> chat-e2ee
cd chat-e2ee
python --version
```

Any Python 3.10 or newer is fine. If `python` is not found, try `py --version`
or `python3 --version` and use whichever answers.

### 1.2 Install what it needs

```bash
python -m pip install -r requirements.txt
```

Five packages. They all arrive ready-built, so this is quick and needs no
compiler.

> The server itself only needs one of them (`websockets`). The other four are
> for the tests and for the Python copy of the encryption code, which exists so
> the C++ version has something independent to be checked against.

### 1.3 Make your own certificate authority

```bash
python tools/make_demo_pki.py
```

**What this is for.** The app checks server certificates properly — it verifies
the chain and the hostname, and refuses to connect if either is wrong. That is
correct behaviour, and it is what stops somebody in the middle pretending to be
your server. But it creates a practical problem: no real certificate company
will issue a certificate for `localhost`, so a server on your own laptop has
nothing valid to present.

The answer is a small certificate authority of your own. This script creates
one, and puts its **public** half where the app can find it. The checking the
app does is completely genuine; only the authority is local.

> **This is not the same as turning the checks off.** An earlier version of this
> project did use a self-signed certificate together with code that forgave the
> resulting errors on localhost. Both were removed: a connection that is
> encrypted but *unverified* is exactly the connection an attacker wants. If you
> read that in an older document, it no longer applies.

Near the end of the output you will see:

```
client trust anchor installed: .../client/pki/demo-ca.crt
```

That is the public half being put in place for the app to compile in.

### 1.4 Start it

```bash
python server/server.py --demo-tls
```

You want to see it report the certificate it is holding, then:

```
Listening on wss://0.0.0.0:8765
```

Leave this terminal running. `wss://` is the secure form; `ws://` would be the
unencrypted one.

> If it says `WARNING Running WITHOUT TLS`, the certificate did not load — go
> back to 1.3.

---

## Stage 2 — See the encryption work, with no app

This is the quickest way to see the point of the whole project. Open a **second**
terminal in the same folder, leaving the server running in the first.

```bash
PYTHONPATH=server python tests/e2ee_redteam.py
```

Three experiments run against the same encryption code the app uses:

1. **A nosy server.** Everything the server can see is printed. It is scrambled,
   and it stays scrambled.
2. **A cheating server.** The attack is actually performed — the server swaps in
   its own keys and reads the conversation — and is then caught by the *safety
   number*. This is the one worth reading carefully, because it shows exactly
   which step the protection depends on.
3. **Files.** Old file keys do not open new files.

There is also a smaller one that sends a real message through the real server:

```bash
python server/demo_proof.py
```

It prints what the user typed next to what the server saw.

### While you are here: run the tests

```bash
bash run_tests.sh
```

About two minutes, ending in a line reading `497 passed`. If you see anything
*skipped*, that is a silent gap rather than a pass — the usual cause is skipping
step 1.3.

---

## Stage 3 — Build and run the app

### 3.1 Install Qt

Get the Qt Online Installer from [qt.io](https://www.qt.io/download-qt-installer).
Under your Qt 6 version, tick:

- the **Desktop** kit (on Windows choose the **MinGW** one)
- **Qt WebSockets** — easy to miss, and the project will not configure without it
- the **Android** kit, only if you want Stage 5

This is the slow part: usually 20–40 minutes, mostly unattended.

### 3.2 libsodium — the step people miss

**This is the one to be careful about.** The two platforms fail differently.

- **Linux:** `sudo apt install libsodium-dev`. Done.
- **macOS:** `brew install libsodium`. Done.
- **Windows:** download `libsodium-1.0.20-stable-mingw.tar.gz` from the
  [libsodium releases page](https://github.com/jedisct1/libsodium/releases) and
  extract it to `C:/libsodium`, so that this file exists:

  ```
  C:/libsodium/libsodium-win64/include/sodium.h
  ```

  *(An older version of this guide suggested a tool called vcpkg. That is not
  what the project looks for — use the tarball above.)*

> **Why this matters so much.** On Windows, a missing libsodium stops the build
> with a clear error, which is the friendly case. On Linux and macOS it does
> **not** stop the build — the encryption quietly compiles to do-nothing stubs,
> the app builds and starts, and then the server refuses your login because the
> app sent an empty key. So: **if the app builds but you cannot log in, suspect
> libsodium before anything else.**

### 3.3 Open and build

1. Launch **Qt Creator**.
2. **File → Open File or Project…** and choose `client/CMakeLists.txt`.
3. Pick your **Desktop** kit and click **Configure Project**.
4. Look at the CMake output for this line:

   ```
   -- Lab CA embedded from client/pki/demo-ca.crt
   ```

   A *warning* instead means you skipped step 1.3, and the app will refuse to
   connect to your server.
5. Press the green **Run** button. The login window appears.

---

## Stage 4 — Two windows, one conversation

Start the app a second time, so you have two windows side by side.

In each window:

1. Leave the server box at **`wss://localhost:8765`**.
2. Pick a nickname, a password and a date of birth, and register.
3. Use a *different* nickname in the second window.

Each window now lists the other person.

### The safety number

Before the first message is allowed, both sides must confirm a **safety number**
— six groups of five digits, calculated from the two people's keys.

Open the other person's details in each window and compare. They must match.
Then each user confirms **on their own device**.

This is not a formality. It is the whole defence against a cheating server: a
server that swapped the keys cannot make the two numbers agree, and that
mismatch is the only warning the users get. Experiment 2 in Stage 2 shows this
happening.

Once both have confirmed, messages and files flow.

> Messages you type before verifying are **held, not thrown away** — they send
> once verification finishes.

---

## Stage 5 — The phone (optional)

You need the **Android** kit installed, and Qt Creator's *Set Up SDK* step
completed so that OpenSSL for Android is present. Qt does not include it, and
without it the phone cannot make secure connections at all.

libsodium for Android is already included in the project, so there is nothing to
build. Check the CMake output says `Android libsodium: linking ...` — a warning
there means the encryption would be stubbed and login will fail.

Switch the kit selector (bottom left) to the Android kit, connect a phone with
USB debugging enabled, and press **Run**.

### Getting the phone to reach your computer

The phone cannot use `localhost` to mean your computer — on the phone that means
the phone. Two ways round it:

**Over the USB cable** (simplest):

```bash
adb reverse tcp:8765 tcp:8765
```

That makes the phone's `localhost:8765` point at your computer's, so you can
type the same `wss://localhost:8765` and the certificate still matches.

**Over Wi-Fi**, with both on the same network: use your computer's network
address, like `wss://192.168.1.20:8765`. If that address has changed since you
made your certificate, refresh just the certificate — no rebuild needed:

```bash
python tools/make_demo_pki.py --leaf-only --ip 192.168.1.20
```

The app asks for six permissions: internet, biometrics, notifications, vibration
and two for staying connected in the background. No camera, location, contacts
or storage.

---

## When something goes wrong

| What you see | What it usually means | What to do |
|---|---|---|
| `bash: ... not found`, or odd syntax errors | You are in PowerShell or `cmd` | Use **Git Bash** |
| Tests say `14 skipped` | No certificate authority yet | Run step 1.3 |
| CMake cannot find `WebSockets` | The module was not ticked in the installer | Re-run the Qt Maintenance Tool and add it |
| App builds, but login is refused | libsodium missing (Linux/macOS) | Step 3.2, then re-run CMake |
| CMake warns about `demo-ca.crt` | Step 1.3 not done | Run it, then re-run CMake |
| App will not connect, certificate error | The app was built before your current certificate | Rebuild the app |
| The phone cannot connect | `localhost` means the phone | Use `adb reverse`, or your computer's network address |
| Cannot type a message | Safety number not confirmed on *your* device | Compare and confirm it |

A longer list, organised the same way, is in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## Where to go next

- The faster version of this guide → [GETTING_STARTED.md](GETTING_STARTED.md)
- How it all works inside → [ARCHITECTURE.md](ARCHITECTURE.md)
- What the encryption does and does not protect → [../SECURITY.md](../SECURITY.md)
- What the tests prove → [../tests/README.md](../tests/README.md)
