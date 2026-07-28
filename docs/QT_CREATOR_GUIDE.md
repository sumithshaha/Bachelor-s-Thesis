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
| Qt | 6.5 or newer (6.11 was used here) | Qt Online Installer (qt.io) |
| Qt Creator | bundled with Qt | comes with the installer |
| A C++ compiler | C++17 | **MinGW** on Windows, GCC/Clang on Linux, Xcode on macOS |
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
# websockets is the relay's ONLY runtime dependency.
pip install 'websockets>=13,<17'

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

The client does its encryption with libsodium, and the two platforms fail
differently — which is worth knowing before you lose an evening to it.

On **Linux and macOS**, CMake looks for it with `find_library`, and that lookup
does **not** fail the build when it misses. `HAVE_SODIUM` is left undefined, the
cryptography compiles to stubs, and everything builds cleanly. The application
then starts, registers a zero-length public key, and is rejected by the relay
at login. **If the app builds but you cannot log in, suspect this first.**

On **Windows**, a missing libsodium is a hard `FATAL_ERROR` at configuration
time, naming the path it searched. That is the friendlier failure.

When it is found, CMake prints nothing special on Linux/macOS; the sign of
success is simply that login works.

- **Linux (Ubuntu/Debian):** `sudo apt install libsodium-dev` — done, CMake
  finds it automatically.
- **macOS:** `brew install libsodium`.
- **Windows (MinGW):** `client/CMakeLists.txt` looks for the prebuilt **MinGW
  tarball**, not vcpkg. Download `libsodium-1.0.20-stable-mingw.tar.gz` from the
  [libsodium releases](https://github.com/jedisct1/libsodium/releases) and
  extract it to `C:/libsodium`, so that this path exists:

  ```
  C:/libsodium/libsodium-win64/include/sodium.h
  ```

  If you keep it somewhere else, set `SODIUM_ROOT` in the kit's CMake
  configuration (Part 3 shows where) rather than moving the folder. A
  post-build step copies `libsodium-26.dll` next to the executable for you.

  This is the one case that fails *loudly*: CMake stops with a `FATAL_ERROR`
  naming the path it searched.
- **Android:** nothing to do. libsodium is already cross-compiled for
  `arm64-v8a` and `x86_64` and committed under
  `client/third_party/libsodium/`. Confirm it during configuration by looking
  for `Android libsodium: linking ...` in the CMake output; a *warning* there
  means the archive was not found and the crypto will be stubbed.

---

## Part 3 — Open and build the desktop client

1. Launch **Qt Creator**.
2. **File → Open File or Project…** and select `client/CMakeLists.txt`.
3. Qt Creator asks which **kit** to configure with. Tick your **Desktop** kit
   (on Windows, e.g. "Desktop Qt 6.11.0 MinGW 64-bit") and click
   **Configure Project**.
4. *(Windows only, if libsodium is not at `C:/libsodium`)* go to
   **Projects → Build → CMake**, and under "Initial Configuration" add a
   variable `SODIUM_ROOT` (type PATH) pointing at your extracted
   `libsodium-win64` folder. Then re-run CMake.
5. Watch the **General Messages** / CMake output. Three lines are worth finding:

   - configuration finishing with no error about a missing Qt component. If it
     complains about `WebSockets`, your Qt install is missing that module —
     re-run the Qt Maintenance Tool and add it;
   - `Lab CA embedded from client/pki/demo-ca.crt`. A *warning* instead means
     you have not run `python tools/make_demo_pki.py` yet, and every `wss://`
     connection to a local relay will fail certificate verification;
   - on an Android kit, `Android libsodium: linking ...`. A *warning* there
     means the crypto will be stubbed and login will be rejected.
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
5. Press **Run**. `androiddeployqt` builds the APK from
   `client/android/AndroidManifest.xml`, installs it, and launches it. Six
   permissions are declared: `INTERNET`, `USE_BIOMETRIC`,
   `POST_NOTIFICATIONS`, `VIBRATE`, `FOREGROUND_SERVICE` and
   `FOREGROUND_SERVICE_DATA_SYNC`. No camera, location, contacts or storage.
6. For the phone to reach a relay on your computer, `127.0.0.1` will not work —
   on the phone that means the phone. Two options:

   - **USB:** `adb reverse tcp:8765 tcp:8765` maps the phone's
     `localhost:8765` to your machine's, so `wss://localhost:8765` works and
     the lab certificate's `localhost` name still matches.
   - **Wi-Fi:** use your machine's LAN address,
     `wss://192.168.1.20:8765`. The lab leaf includes that address in its SANs
     as of when you generated it; if it has changed since, re-issue the leaf
     with `python tools/make_demo_pki.py --leaf-only --ip <new-ip>` (no rebuild
     needed — the root is unchanged).

   A deployed relay works too: `wss://<a-b-c-d>.sslip.io:8765`.

> **If the build fails on an older Qt:** the CMake guards the
> `qt_add_android_permission()` call (it only exists in Qt 6.8.1+), so on Qt
> 6.5–6.7 the permissions come from the manifest instead. Either way they are
> requested.

> **If login is rejected on the phone:** check the CMake output for
> `Android libsodium: linking ...`. A warning instead means the archive for
> your ABI was not found, the cryptography is stubbed, and the client is
> registering a zero-length public key.

> **If messages send but never decrypt on the phone:** the device may lack
> AES-256-GCM hardware, in which case `crypto_aead_aes256gcm_is_available()`
> returns 0. The hybrid design covers this: the cipher is named in the message
> header, so a device on XChaCha20-Poly1305 interoperates with one on
> AES-256-GCM. `run_interop.sh` exercises exactly that mixed pairing.

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
