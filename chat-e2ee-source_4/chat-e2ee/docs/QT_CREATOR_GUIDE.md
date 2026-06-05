# Step-by-step: building and running the client in Qt Creator

This guide walks through getting the application running from a clean machine,
clicking through Qt Creator rather than the command line. It is the companion
to `BUILD.md`, which has the command-line equivalents and the cPouta server
notes. Follow this if you want the shortest path to seeing the app run.

There are two halves to run: the **Python server** (start this first) and the
**Qt client** (build and run this second, twice, so two users can chat).

---

## Part 0 — What you need installed

| Tool | Version | Where to get it |
|------|---------|-----------------|
| Python | 3.10 or newer | python.org, or already on Linux/macOS |
| Qt | 6.8 or newer (6.11 was used here) | Qt Online Installer (qt.io) |
| Qt Creator | bundled with Qt | comes with the installer |
| A C++ compiler | C++17 | MSVC on Windows, GCC/Clang on Linux, Xcode on macOS |
| CMake | 3.21+ | bundled with Qt Creator |
| libsodium | 1.0.18 or newer | see Part 2 — this is the one that trips people up |

When you run the Qt installer, make sure you tick, under your Qt 6.x version:
the **Desktop** kit (MSVC or GCC), the **Qt WebSockets** module, and — if you
want the Android build — the **Android** kit. WebSockets is easy to forget and
the project will not configure without it.

---

## Part 1 — Start the server

The server has no GUI; run it in a terminal.

```bash
cd server
python3 -m venv .venv
# Windows:        .venv\Scripts\activate
# Linux / macOS:  source .venv/bin/activate
pip install websockets cryptography

# Development mode: no TLS, listening on your own machine.
python server.py --host 127.0.0.1 --port 8765
```

You should see `Listening on ws://127.0.0.1:8765`. Leave this running. For a
real deployment over `wss://` with a certificate, see the cPouta section in
`BUILD.md`.

> **Tip:** before touching Qt at all, you can prove the server and the
> encryption work by opening a second terminal and running
> `python server/demo_proof.py`. It sends one encrypted message through the
> server and prints, side by side, what the user typed and the ciphertext the
> server saw. This is also the screenshot worth putting in the thesis.

---

## Part 2 — Make libsodium findable (the common stumbling block)

The client does its encryption with libsodium. CMake looks for it with
`find_library`. **If it is not found, the project still builds — but encryption
is silently disabled** (the code is wrapped in `#ifdef HAVE_SODIUM`). So if the
app runs but messages never decrypt, this is almost certainly why. When CMake
finds libsodium it prints nothing special, but the compile defines `HAVE_SODIUM`
and the crypto is active.

- **Linux (Ubuntu/Debian):** `sudo apt install libsodium-dev` — done, CMake
  finds it automatically.
- **macOS:** `brew install libsodium`.
- **Windows:** the simplest route is vcpkg:
  ```
  vcpkg install libsodium
  ```
  then pass vcpkg's toolchain file to CMake (Part 3 shows where).
- **Android:** you need libsodium compiled for the phone's ABI (`arm64-v8a`).
  Either build it from source against the Android NDK, or drop a prebuilt
  `libsodium.so` and its headers somewhere CMake can see. This is the fiddliest
  step; budget time for it.

---

## Part 3 — Open and build the desktop client

1. Launch **Qt Creator**.
2. **File → Open File or Project…** and select `client/CMakeLists.txt`.
3. Qt Creator asks which **kit** to configure with. Tick your **Desktop** kit
   (e.g. "Desktop Qt 6.11.0 MSVC2022 64-bit") and click **Configure Project**.
4. *(Windows + vcpkg only)* go to **Projects → Build → CMake** and add, under
   "Initial Configuration", a variable
   `CMAKE_TOOLCHAIN_FILE` =
   `C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake`, then re-run CMake.
5. Watch the **General Messages** / CMake output. You want to see the
   configuration finish without an error about a missing Qt component. If it
   complains about `WebSockets`, your Qt install is missing that module —
   re-run the Qt Maintenance Tool and add it.
6. Press the green **Run** button (or Ctrl+R). The login window should appear.

---

## Part 4 — Chat with yourself (two clients, one machine)

A chat needs two people, so run the client twice:

1. With the app already running once, in Qt Creator's bottom toolbar make sure
   the build is done, then launch a second copy directly from the build folder
   (e.g. double-click `build/appChatE2EE` on Linux, or the `.exe` on Windows).
   Running two instances from the file manager is easier than two Run buttons.
2. In the first window, log in with the nickname **alice** and the server
   address `ws://127.0.0.1:8765`.
3. In the second window, log in as **bob**, same server.
4. Each should now see the other appear in the online-user list. Select the
   other person and send a message. It should arrive in real time.
5. Look back at the **server terminal**: you will see lines like
   `RELAY alice -> bob ciphertext=...`. The server is moving your messages
   without ever printing their text — that is the end-to-end encryption working.
6. Tap the key icon in the chat header to see the **safety number**. If you open
   it in both windows for the same conversation, the numbers match — that is the
   man-in-the-middle check.

---

## Part 5 — Building for Android (optional, do this last)

1. In the Qt installer / Maintenance Tool, make sure the **Android** kit, the
   **Android NDK**, and a JDK are installed. Qt Creator's
   **Edit → Preferences → Devices → Android** page will flag anything missing.
2. Provide libsodium for `arm64-v8a` (see Part 2) and make sure CMake can find
   it for the Android kit.
3. In Qt Creator, switch the active kit (bottom-left kit selector) to the
   **Android** kit. CMake reconfigures.
4. Connect a phone with USB debugging on, or start an emulator.
5. Press **Run**. `androiddeployqt` builds the APK, using
   `client/android/AndroidManifest.xml` (which requests only the INTERNET
   permission), installs it, and launches it.
6. For the phone to reach the server, it cannot use `127.0.0.1` — that means
   the phone itself. Use the server machine's LAN IP (e.g.
   `ws://192.168.1.20:8765`) or, better, the real `wss://` cPouta address.

> **If the build fails on an older Qt:** the CMake guards the
> `qt_add_android_permission()` call (it only exists in Qt 6.8.1+), so on older
> Qt the INTERNET permission comes from the manifest instead. Either way the
> permission is requested.

> **If messages send but never decrypt on the phone:** the device may lack
> AES-256-GCM hardware. `crypto_aead_aes256gcm_is_available()` returns 0 on such
> devices. Switching the cipher to XChaCha20-Poly1305 fixes it and is noted as
> future work in the thesis.

---

## Part 6 — Confirm your build is correct (interop check)

If you want certainty that your compiled client encrypts exactly the way the
server expects, reproduce the cross-language check:

```bash
# Python encrypts a message and prints the keys + ciphertext as JSON:
python tests/make_vector.py > vec.json

# Compile the tiny C++ harness (same crypto path as the client):
g++ -std=c++17 tests/interop.cpp -lsodium -o interop

# Feed it Bob's private key, Alice's public key, the nonce and ciphertext
# from vec.json. It should print: Cross-language interop works!
./interop <bob_priv> <alice_pub> <nonce> <ct>
```

If that prints the decrypted message, your toolchain's libsodium and the
Python `cryptography` library agree byte-for-byte, which is the property the
whole application depends on.

---

## Troubleshooting summary

| Symptom | Most likely cause | Fix |
|---------|-------------------|-----|
| CMake error about `WebSockets` | Qt WebSockets module not installed | add it via Qt Maintenance Tool |
| App builds, messages never decrypt | libsodium not found at configure time | install libsodium, re-run CMake, check for `HAVE_SODIUM` |
| Android: "unknown command qt_add_android_permission" | Qt older than 6.8.1 | already guarded in CMake; permission falls back to the manifest |
| Phone can't connect to server | used `127.0.0.1` | use the server's LAN IP or the cPouta `wss://` address |
| Messages decrypt on desktop but not phone | no AES-GCM hardware on device | switch cipher to XChaCha20-Poly1305 (future work) |
