# The Easy Guide: How to Run Your Chat App, One Small Step at a Time

This guide explains everything from the very beginning. I will not assume you
remember anything between steps, and I will tell you *why* you are doing each
thing, not just what to type. Take it slowly. There is no rush, and you cannot
break anything by going carefully.

Read the part called **"The big picture"** first. It will make all the other
steps make sense.

---

## The big picture (read this first)

Your project is really **two programs that talk to each other**:

1. **The server.** Think of it as a *post office*. It does not read letters. It
   just takes a sealed envelope from one person and carries it to another. It
   also keeps a list of who is currently "in the building" (online).

2. **The client.** This is the *app a person uses* — the window with the login
   box and the chat messages. Each person runs their own copy.

For a chat to happen, you need the **post office running first**, and then **two
people** (two copies of the client app) so they have someone to talk to.

Here is the most important idea in your whole project, in one sentence:

> The two people lock their messages before sending, and only the other person
> has the key to unlock them — so the post office (the server) carries sealed
> envelopes it can never open.

That is what "end-to-end encryption" means. The server moves the message but
can never read it. Keep that picture in your head; everything below serves it.

We will do things in this order, easiest first:

- **Stage 1:** Start the server (the post office).
- **Stage 2:** Watch the encryption work *without any app yet* — a 2-minute win.
- **Stage 3:** Build and run the real app on your computer.
- **Stage 4:** Have two app windows chat with each other.
- **Stage 5:** (Later, optional) Put the app on an Android phone.

---

## Before we start: a few words you will see

You do not need to memorise these. Just glance at them so they are not scary
later.

- **Terminal** (also called *command line* or *console*): a plain text window
  where you type commands instead of clicking buttons. On Windows it is called
  *Command Prompt* or *PowerShell*; on Mac it is called *Terminal*; on Linux it
  is also *Terminal*.
- **Python:** the language the server is written in. You install it once.
- **Qt** (say it like the word "cute"): the toolkit the app is built with. You
  install it once. It comes with a program called **Qt Creator**, which is where
  you press the build button.
- **libsodium:** a small helper that does the actual locking and unlocking
  (the encryption). The app needs it. Installing it is the one step people most
  often forget, so I will remind you loudly when we get there.
- **Building** (or *compiling*): turning the written code into a program you can
  actually run. You press a button; the computer does the work.

---

## Stage 1 — Start the server (the post office)

The server has no window and no buttons. It just runs quietly in a terminal.

**Step 1.1 — Check Python is installed.**
Open a terminal and type this, then press Enter:

```
python3 --version
```

If it prints something like `Python 3.12.1`, you are good. If it says
"command not found", install Python from **python.org** first, then come back.
(On Windows you might need to type `python` instead of `python3`.)

**Step 1.2 — Go into the server folder.**
In the terminal, move into the project's `server` folder. If you unzipped the
project onto your Desktop, it looks something like this:

```
cd Desktop/chat-e2ee/server
```

`cd` means "change directory" — it is how you walk into a folder in a terminal.

**Step 1.3 — Make a clean little workspace for the server's helpers.**
Type these two lines, one at a time:

```
python3 -m venv .venv
```

Then, to switch into that workspace:

- On **Windows**, type: `.venv\Scripts\activate`
- On **Mac or Linux**, type: `source .venv/bin/activate`

*Why:* this makes a private box (`.venv`) for the server's helper packages, so
they do not get mixed up with the rest of your computer. After this, you should
see `(.venv)` at the start of your terminal line. That is normal and good.

**Step 1.4 — Install the two helpers the server needs.**

```
pip install websockets cryptography
```

`websockets` is what keeps the connection open so messages can arrive at any
time. `cryptography` is the locking-and-unlocking helper for the server's tests.

**Step 1.5 — Start the server.**

```
python server.py --host 127.0.0.1 --port 8765
```

You should see a line that says it is **listening on `ws://127.0.0.1:8765`**.
That address is just "this same computer, door number 8765." 

**Leave this terminal window open.** The post office is now open for business.
If you close it, the post office shuts. We will open *new* terminal windows for
everything else.

---

## Stage 2 — See the magic work (a 2-minute win, no app needed)

Before building the whole app, let us prove the encryption actually works. This
is the quickest way to feel good about the project, and the result is a great
screenshot for your thesis.

**Step 2.1 — Open a *second* terminal window** (leave the server running in the
first one).

**Step 2.2 — Go into the server folder again and switch into the workspace**
(same as steps 1.2 and 1.3 above).

**Step 2.3 — Run the little proof program:**

```
python demo_proof.py
```

**What you will see, and why it matters:** the program pretends to be two people
— Alice and Bob. Alice types a secret sentence. The program shows you three
things:

1. What Alice typed (the real message).
2. What the **server** saw as it carried the message — a jumble of random
   letters and numbers. **This is the proof: the post office cannot read the
   letter.**
3. What Bob unlocked at the other end — Alice's real message again.

If you see the secret sentence at the start and end, but only jumble in the
middle, the encryption is working exactly as it should. That is the heart of
your whole thesis, shown in one screen.

---

## Stage 3 — Build and run the real app on your computer

Now the app with the actual window. This part uses **Qt Creator**.

**Step 3.1 — Install Qt (if you have not already).**
Go to **qt.io**, download the **Qt Online Installer**, and run it. When it asks
what to install, make sure these are ticked under your Qt 6 version:

- the **Desktop** kit (this is the version for computers),
- the **Qt WebSockets** module ← *people forget this one; the app will not
  build without it*,
- and the **Android** kit *only if* you plan to do Stage 5 later.

Qt Creator (the program you click in) comes along with this automatically.

**Step 3.2 — Install libsodium (THE STEP PEOPLE FORGET).**
This is the locking-and-unlocking helper. If you skip it, here is the sneaky
part: **the app will still build and open — but messages will never unlock.**
So if later your messages refuse to appear, this is almost always the reason.

- **Windows:** the easiest way is a tool called *vcpkg*. Install vcpkg, then
  type `vcpkg install libsodium`. (Stage 3.4 shows where to tell Qt about it.)
- **Mac:** install a tool called *Homebrew* if you do not have it, then type
  `brew install libsodium`.
- **Linux (Ubuntu/Debian):** just type `sudo apt install libsodium-dev`. Done —
  Qt will find it by itself.

**Step 3.3 — Open the project in Qt Creator.**
Open **Qt Creator**. Click **File → Open File or Project…**. Find the project
and choose the file at `client/CMakeLists.txt`. (That file is the app's recipe —
it tells Qt how to build everything.)

**Step 3.4 — Pick the kit and configure.**
Qt Creator will ask which **kit** to use. Tick your **Desktop** kit (it will
have a name like "Desktop Qt 6.11.0"). Then click **Configure Project**.

*Windows + vcpkg only:* click **Projects** on the left, find the CMake settings,
and add a setting called `CMAKE_TOOLCHAIN_FILE` pointing to vcpkg's file
(something like `C:/vcpkg/scripts/buildsystems/vcpkg.cmake`). Then re-run CMake.
This is just telling Qt where you put libsodium.

**Step 3.5 — Watch the messages at the bottom.**
Qt Creator will show some text as it gets ready. You are hoping it finishes with
no red error. If it complains about **WebSockets**, that module is missing — go
back to Step 3.1 and add it with the Qt installer.

**Step 3.6 — Press the green Run button** (the triangle ▶, or press Ctrl+R).
After a short wait, the app's **login window** should appear on your screen. You
built it!

---

## Stage 4 — Make two windows chat with each other

A chat needs two people. So you will run the app twice.

**Step 4.1 — Log in as the first person.**
In the app window, type the nickname **alice**. For the server address, type:

```
ws://127.0.0.1:8765
```

(That is the post-office address from Stage 1.) Click login.

**Step 4.2 — Open a second copy of the app.**
The easiest way: use your file manager (Finder / File Explorer) to find the
built program in the project's `build` folder and double-click it to open a
second window. Now you have two app windows side by side.

**Step 4.3 — Log in as the second person.**
In the second window, type the nickname **bob** and the **same** server address,
and log in.

**Step 4.4 — Chat!**
Each window should now show the other person in the online list. Click the other
name, type a message, and send it. It appears in the other window almost
instantly.

**Step 4.5 — Peek at the post office.**
Look back at the *first terminal* (the server). You will see lines like
`RELAY alice -> bob ciphertext=...`. The server is moving your messages — but
notice it only ever shows jumble, never your words. That is your encryption,
working live.

**Step 4.6 — Try the safety check (the anti-spy feature).**
In the chat, tap the little **key icon** at the top. A "safety number" appears.
Open it in both windows for the same conversation: the numbers should **match**.
If two real people ever did this by reading the numbers aloud on a phone call, a
match proves nobody is secretly listening in. A mismatch would be the warning
sign of a spy in the middle.

---

## Stage 4.5 — Turning on TLS for localhost (optional but nice to show)

Everything so far used a plain `ws://` connection. TLS adds the padlock layer —
the same kind of encryption a website uses. Remember the big picture: your
messages are *already* sealed end-to-end, so on your own computer TLS does not
add much real secrecy. But setting it up correctly is worth showing in your
thesis, because it proves you have two independent layers of protection working
together.

A real website's certificate is signed by a company your computer already
trusts. On localhost there is no such company, so you make your own certificate
— this is called a **self-signed certificate**. Your computer will not trust it
at first, and that is expected, not a mistake.

**Step 4.5.1 — Make the certificate.**
In a terminal, inside the `server` folder, run this one long command:

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

This creates two files: `cert.pem` (the certificate, safe to share) and
`key.pem` (the private key, keep it secret). If your terminal says `openssl` is
not found: on Windows, run the command from inside *Git Bash*, which includes
openssl.

**Step 4.5.2 — Start the server with TLS.**

```
python server.py --host 127.0.0.1 --port 8765 --cert cert.pem --key key.pem
```

The server now speaks `wss://` (the secure version) instead of `ws://`.

**Step 4.5.3 — Connect the client to the secure address.**
In the app's login box, use the same name that is written in the certificate,
which is `localhost`:

```
wss://localhost:8765
```

Use `localhost`, not `127.0.0.1`, so the name matches the certificate.

**Step 4.5.4 — What happens, and why it just works.**
The app has special handling built in (in `chatclient.cpp`). When it connects
to localhost and meets your self-signed certificate, it recognises the
expected "I made this myself" warnings and forgives *only those*, *only on
localhost*. Against any real server it stays strict and would refuse a bad
certificate. So the connection goes through on your machine without you turning
off any safety.

**Step 4.5.5 — If it refuses to connect.**
The app prints every certificate warning to Qt Creator's **Application Output**
pane, on lines starting with `[TLS DEBUG]`. If the connection fails, look there:
you will see a code such as `QSslError::SelfSignedCertificate`. If the code
shown is not already in the forgiven list inside `onSslErrors()`, add that one
line and rebuild. Once it connects, you can delete the `[TLS DEBUG]` loop — it
is only there to help during setup.

---

## Stage 5 — Putting it on an Android phone (do this LAST)

This is the trickiest stage, so save it for when everything above already works.
Do not start here.

**Step 5.1 — Add the Android tools.**
In the Qt installer (the Maintenance Tool), make sure the **Android** kit and
the **Android NDK** are installed. In Qt Creator, the menu
**Edit → Preferences → Devices → Android** will put a green tick next to things
that are ready and warn you about anything missing.

**Step 5.2 — Get libsodium for the phone.**
A phone has a different kind of chip than a computer, so it needs its own copy
of libsodium built for `arm64-v8a` (that is the phone's chip type). This is the
fiddliest part of the whole project. Give yourself time and patience here.

**Step 5.3 — Switch to the Android kit.**
In Qt Creator, bottom-left, there is a kit selector. Switch it from Desktop to
the **Android** kit. Qt Creator will get ready again.

**Step 5.4 — Connect a phone or start an emulator.**
Plug in an Android phone with "USB debugging" turned on, or start a phone
emulator inside Qt Creator.

**Step 5.5 — Press Run.**
Qt packages everything into an **APK** (an Android app file), installs it on the
phone, and opens it. The app asks for only one permission: internet access.

**Step 5.6 — IMPORTANT: the phone cannot use `127.0.0.1`.**
To the phone, `127.0.0.1` means "the phone itself," not your computer. So the
phone cannot find the server that way. Instead, use your computer's address on
the local network (something like `ws://192.168.1.20:8765`), or better, the real
internet address of your cPouta server (`wss://...`). The `BUILD.md` file has
the full cPouta setup.

---

## When something goes wrong — a calm checklist

Almost every problem is one of these five. Find your symptom and try the fix.

| What you see | What it usually means | What to do |
|---|---|---|
| Qt says something about **WebSockets** when configuring | The WebSockets module was not installed | Re-open the Qt installer and add "Qt WebSockets", then try again |
| The app opens, but messages **never appear / never unlock** | libsodium was not installed when you built | Install libsodium (Step 3.2), then re-run CMake in Qt Creator |
| Android build fails with **"unknown command qt_add_android_permission"** | Your Qt is older than 6.8.1 | Nothing to fix — the project already handles this automatically |
| The **phone cannot connect** to the server | You used `127.0.0.1`, which the phone reads as itself | Use the computer's network IP or the `wss://` cPouta address |
| Messages work on the **computer but not the phone** | That phone's chip lacks AES-GCM hardware | This is a known limit; noted as future work in the thesis |

---

## One last reassurance

You do **not** have to do all five stages today. The honest order of importance
is:

1. **Stages 1 and 2** give you a working, screenshot-worthy result in a few
   minutes. Do these first.
2. **Stages 3 and 4** give you the real app running on your computer. This is
   the main deliverable.
3. **Stage 5** (Android) is a bonus. If it fights you near the deadline, it is
   completely fine to show the desktop version and describe Android as future
   work — that is an honest and respectable thing to write.

Go one small step at a time, and re-read "The big picture" whenever you feel
lost. You have got this.
