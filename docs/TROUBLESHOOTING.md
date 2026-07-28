# Troubleshooting

Organised by what you actually see, not by which component is at fault — when
something goes wrong you know the symptom, not the cause.

Most entries here exist because the failure happened and the error message
pointed somewhere other than the problem.

---

## Setting up

### `bash: run_tests.sh: command not found`, or syntax errors on the first line

You are in PowerShell or `cmd`. These are bash scripts. On Windows, right-click
the project folder and choose **Git Bash Here**.

### `python: command not found`

Try `py --version` (Windows) or `python3 --version`. `run_tests.sh` probes all
three in order and skips the Microsoft Store stub, which reports as Python but
is not an interpreter.

### `pip install` fails trying to compile something

Every dependency ships as a prebuilt wheel, so this normally means pip could not
find a wheel for your interpreter — usually a very new pre-release version. Use a
stable Python 3.10–3.13 release.

---

## Running the tests

### One test fails: `client/pki/demo-ca.crt is a DIFFERENT root from pki/ca.crt`

Your client's compiled-in trust anchor and your generated authority have drifted
apart. Fix:

```bash
python tools/make_demo_pki.py
```

It copies the current public root into `client/pki/demo-ca.crt` automatically.
**If the output says the anchor was *updated* and you have already built the
client, rebuild it** — the certificate is compiled in as a Qt resource, so a file
change on disk does nothing until the resource is recompiled.

### Some tests are *skipped*

A skip is a silent gap, not a pass. Two causes:

- **`14 skipped`, all TLS.** `pki/` is missing. Run `python tools/make_demo_pki.py`.
- **One skip in `test_schema_migration.py`.** Expected when running as **root**
  on Linux: the test needs the filesystem to honour the read-only bit, which root
  bypasses. As a normal user it passes.

### Failures mentioning ports, `EADDRINUSE`, or connection refused

The socket tests bind fixed ports: 8791, 8799, 8811–8813, 8821. A relay left
running from an earlier demonstration collides with them. Stop it and re-run.

### Certificate tests fail in confusing ways

Delete `pki/` and regenerate:

```bash
rm -rf pki && python tools/make_demo_pki.py
```

Remember this creates a **new root**, so rebuild the client afterwards.

### `README.md` says one number and pytest collects another

Regenerate the counts from the suite itself:

```bash
python tools/sync_test_readme.py --fix
```

`--check` reports without writing, which is the form to use in CI.

---

## Building the client

### CMake: `libsodium not found at C:/libsodium/libsodium-win64`

Windows expects the prebuilt MinGW tarball extracted so that
`C:/libsodium/libsodium-win64/include/sodium.h` exists. Download
`libsodium-1.0.20-stable-mingw.tar.gz` from the
[libsodium releases](https://github.com/jedisct1/libsodium/releases). If you keep
it elsewhere:

```bash
cmake -S client -B client/build -DSODIUM_ROOT=D:/libs/libsodium-win64
```

This one fails loudly, which is the good case. The Linux/macOS path does not —
see the next entry.

### The app builds and runs, but login fails

Almost always libsodium missing on Linux or macOS. There the lookup is a
`find_library` that does **not** fail the build: `HAVE_SODIUM` is left undefined,
the cryptography compiles to stubs, the client registers a zero-length public
key, and the relay rejects it.

```bash
sudo apt install libsodium-dev      # Debian/Ubuntu
brew install libsodium              # macOS
```

Then re-run CMake configuration, not just the build.

### CMake cannot find `Qt6::WebSockets`

The WebSockets module was not ticked in the Qt installer. Re-run the Qt
Maintenance Tool and add it under your Qt version.

### Linker errors naming X3DH symbols

A `.cpp` was added under `client/src/` but not listed in `client/CMakeLists.txt`.
The header resolves and the file compiles in isolation, so this only appears at
link time as a wall of undefined symbols. `tests/test_build_sources.py` checks
for exactly this.

### CMake warning: `client/pki/demo-ca.crt not found`

You skipped the PKI step. The client builds, but every `wss://` connection to a
lab relay fails verification by design. Run `python tools/make_demo_pki.py` and
re-run CMake configuration.

---

## Running the application

### The client cannot connect, certificate verification fails

Work through these in order:

1. Is the relay actually running, and did it print `Listening on wss://...`?
2. Did it print `WARNING Running WITHOUT TLS`? Then it has no certificate —
   `pki/server.crt` or `pki/server.key` is missing.
3. Does the client's URL scheme match? `wss://` needs TLS; a relay started
   without TLS flags needs `ws://`.
4. Was the client built **after** the current root was generated? If the root
   changed since the build, the binary still carries the old one.

### The phone cannot reach a relay on my computer

Two working approaches:

**Over USB.** `adb reverse tcp:8765 tcp:8765` maps the phone's `localhost:8765`
to your machine's, so `wss://localhost:8765` works on the phone and the
certificate's `localhost` name still matches.

**Over Wi-Fi.** Connect to `wss://<your-LAN-IP>:8765`. The lab leaf includes your
LAN address in its SANs *as of when you generated it*. If your address has
changed, re-issue just the leaf — the root is untouched, so **no rebuild**:

```bash
python tools/make_demo_pki.py --leaf-only --ip 192.168.1.42
```

Also allow inbound TCP 8765 through your firewall.

### Android: "No functional TLS backend was found"

Qt does not ship OpenSSL for Android. Run **Set Up SDK** in Qt Creator so
`android_openssl` is installed; `client/CMakeLists.txt` includes it from
`%LOCALAPPDATA%/Android/Sdk/android_openssl/android_openssl.cmake`. If your SDK
is elsewhere, edit that include path.

### Android: builds fine, then rejected at login

Check the CMake output for:

```
-- Android libsodium: linking .../third_party/libsodium/arm64-v8a/libsodium.a
```

A **warning** instead means the archive was not found for your ABI and the crypto
is stubbed. The archives are committed under `client/third_party/libsodium/`;
if they are missing from your clone, `.gitignore`'s `*.a` rule may be excluding
them — the repository carries an explicit negation to re-include them, so
confirm your `.gitignore` has it.

### I cannot send a message — the composer is blocked

The safety number has not been verified on **your** device. Open the peer's
details, compare the number with theirs out of band, and confirm. Messages
composed before verification are queued rather than discarded, and flush once
you verify.

### The peer never sees my verification

Verification acknowledgements are stored and forwarded, so an offline peer
receives yours when they next log in. If both sides are online and it still
stalls, the recovery path is `verify_resync`, sent automatically on login.
Logging out and back in on one side triggers it.

### Messages to an offline user seem to vanish

They are queued in the local outbox, persisted to SQLite, and flushed on
reconnect. Check the in-app diagnostic log (overflow menu) for the outbox flush.

---

## Deploying

### `Permission denied (publickey)` when you know the key is right

You used `sudo ssh` or `sudo scp`. They then act as **root** and look in
`/root/.ssh/`, not yours. Never `sudo` either command — see
[DEPLOY_START_HERE.md](DEPLOY_START_HERE.md), step 0.

### `Load key: Permission denied`, and `chmod` says "Operation not permitted"

An earlier `sudo ssh` left the key root-owned:

```bash
sudo chown "$USER:$USER" ~/thesis.key
chmod 600 ~/thesis.key
```

If the key lives under `/mnt/c`, move it to your WSL home first — the Windows
filesystem ignores `chmod`, so the mode never actually changes.

### `scp`: "path canonicalization failed"

Modern OpenSSH will not create the destination directory. Create it first:

```bash
ssh -i ~/thesis.key ubuntu@<VM-IP> 'mkdir -p /tmp/chate2ee-deploy'
```

### Certificate issuance fails

Re-run `bootstrap_cpouta.sh`. Its staging rehearsal costs nothing against rate
limits and names which of the three usual causes applies: port 80 closed in the
security group, floating IP not associated, or hostname not matching the address.

### The certificate renewed but clients still see the old one

The relay loads its certificate once at startup and has no reload path.
`chate2ee-cert-deploy.sh` is the certbot deploy hook that restarts the service;
confirm it is installed, or restart manually:

```bash
sudo systemctl restart wsserver
```

### Log timestamps are hours off

The VM is on UTC. Set the clock and timezone:

```bash
sudo bash server/deploy/fix_clock.sh
```

### `diagnose_ssh.sh`

When SSH itself is the problem, this checks key location (flagging `/mnt/c`
paths where `chmod` is ignored), permissions, ownership, load-ability and live
authentication, and names the exact fault:

```bash
bash server/deploy/diagnose_ssh.sh ~/thesis.key ubuntu@<VM-IP>
```

---

## Still stuck

The application has a diagnostic log screen in the overflow menu, which shows
client logs and streams the relay's own log alongside them. That combined view
is usually the fastest way to see which side gave up first.

On the relay: `sudo journalctl -u wsserver -f`.
