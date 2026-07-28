# Rebuilding the relay on a cPouta VM, with a real TLS certificate

**Situation:** the previous VM has been deleted. This is a from-scratch
rebuild — new instance, new floating IP, new hostname, new certificate, empty
database. Nothing from the old instance carries over, and nothing needs to:
every hostname-specific value is now derived at deploy time rather than baked
into a script.

**Service layout:** relay at `/opt/wsserver/`, systemd unit `wsserver.service`,
listening on `:8765`.

**Status of this document:** every command was run in a sandbox against the
actual `server/server.py` from this repository, including a full rehearsal of
the rebuild against a *different* floating IP to prove nothing is hardcoded.
Where something needs the real VM, I say so and give the check that tells you
it worked.

---

## What the deleted VM actually cost you

Less than it looks like, and it is worth knowing exactly what before you start
apologising to anyone.

### Gone

- **The relay's account table.** Nickname registrations, password verifiers
  and birthday verifiers all lived in `chat.db` on that instance.
- **Anything queued but undelivered** — offline messages, in-flight file
  transfers, delivery cursors.
- **The Let's Encrypt certificate and its private key.** Both were on the VM.
- **The floating IP**, if it was released, and therefore the old
  `<your-hostname>` name.

### Not gone

- **Every client's message history.** History is stored per-user in SQLite on
  each device. The relay never held plaintext and was never the archive.
- **Every client's identity key.** These are generated and kept client-side.
- **Safety numbers, and therefore verification state.** A safety number is
  derived from the two parties' identity public keys, not from anything the
  server holds. Peers who had verified each other still match after the
  rebuild — nobody has to re-verify, and nobody will see a spurious "identity
  changed" warning.
- **Ratchet state for existing conversations**, which is client-side. Sessions
  continue rather than restarting.

### The one thing to tell your users

Nicknames are reserved **first-come, key-locked**, and that reservation lived
only in the server database. With the database gone, every nickname is free
again — so a returning user with their original identity key can simply
register the same nickname and get it back.

There is a wrinkle worth knowing before someone hits it. To the new server
every account is a *new* registration, which means the birthday requirement
applies to all of them: `hello` without a `dob_verifier` on a
password-protected registration is refused with close code **4003**. A user
who registered before that rule existed was never asked for a birthday and
will be now. That is correct behaviour, not a bug, but it will look like one
if it arrives unexplained.

The corresponding risk is that a nickname is now claimable by *whoever asks
first*. On a relay with a handful of known users that is a footnote; it is
worth one sentence in the thesis as a property of the design rather than an
accident.

### About the old certificate

You cannot revoke it — revocation needs either the private key or the ACME
account key, and both went with the VM. In practice this matters very little:
the private key was destroyed along with everything else, so the certificate
cannot be presented by anyone. It simply expires.

The one thing that *would* matter is if that private key had been copied off
the VM at some point — into a backup, or an uploaded archive. Worth checking
your own archives once, and then not worrying about it again.

---

## 0. Three things that would have bitten you (all now fixed in code)

I found these by reading the current `server/` folder and rehearsing the
upgrade in a sandbox. They are ordered by how much damage they do.

### 0.1 Your live database did not migrate itself completely (now fixed in code)

The copy of the server currently running on the VM is
`server/server.py (hosted on cPouta VM).txt` — 510 lines, dated 31 May. The
copy in the repository is 1672 lines. In that gap the `messages` table gained
a `frame` column, which carries the ratchet header (`cipher`, `dh`, `pn`, `n`)
that a receiver needs to advance its ratchet.

`Storage.__init__` migrates the `users` table with explicit `ALTER TABLE`
statements in `_ensure_cred_columns()`. It does **not** migrate `messages`,
because that table is only ever created by `CREATE TABLE IF NOT EXISTS`, and
that statement does nothing at all to a table that already exists.

I built a database with the 31 May schema and started the current server
against it. The result:

```
users              -> ['nick', 'pubkey', 'pw_verifier', 'pw_salt', 'dob_verifier']   <- migrated
messages           -> ['id', 'sender', 'recipient', 'nonce', 'ciphertext', 'ts']     <- NOT migrated
file_meta          -> ['msg_id', 'sender', 'recipient', 'envelope', 'ts', 'final_seen']
signed_prekeys     -> ['nick', 'spk_pub', 'spk_sig', 'updated']
one_time_prekeys   -> ['nick', 'opk_id', 'opk_pub']
delivery_cursor    -> ['recipient', 'last_id']
```

The server **starts cleanly** and logs `Listening on wss://...`. Nothing looks
wrong. The failure arrives later, at the first message that has to be stored:

```
OperationalError: table messages has no column named frame
```

That is the worst possible shape for a bug on a live service — a green
startup, then breakage under real use.

**This is now fixed in the code rather than in this document.**
`Storage._ensure_table_columns()` performs the `ALTER TABLE` on startup,
driven by a `_LATE_COLUMNS` table, exactly as `_ensure_cred_columns()` already
did for `users`. Opening the relay against the VM's database is now enough:

```
INFO  SCHEMA migrated: added messages.frame (TEXT)
INFO  SCHEMA migrated: added file_meta.final_seen (INTEGER NOT NULL DEFAULT 0)
```

It is a silent no-op on the second start and on a fresh database, and existing
rows are untouched — a pre-ratchet message simply reads back with
`frame = NULL`, which is what the code already expects from older builds.

The previous version of this runbook told you to run the `ALTER` by hand
before starting the new build. That works right up until the once it doesn't,
and a step you have to remember is not a migration — it is a trap with
documentation attached. `tests/test_schema_migration.py` (9 tests) now locks
the behaviour in; with the migration disabled, 5 of those 9 fail.

On a rebuilt VM the database starts empty, so this cannot bite you now. It
still matters the moment you deploy a code change onto a relay that has been
running and collecting data.

### 0.2 Certificate renewal will not reach the running process

`make_ssl_context()` calls `ctx.load_cert_chain(certfile, keyfile)` once, in
`amain()`, before `serve()`. The `SSLContext` then lives for the life of the
process. There is no SNI callback and no file watch, so when certbot renews in
60 days and writes new files, **the running relay keeps serving the old
certificate from memory** until something restarts it.

Left alone, this ends with a relay serving an expired certificate while
`certbot certificates` cheerfully reports everything as valid. The certbot deploy hook installed in
stage 2 is what closes it.

Two things now make the gap visible rather than silent, because a hook that
fails silently leaves you exactly where you started:

- **Startup reports the certificate the process is actually holding**, via
  `log_certificate()` — subject, issuer, SAN, chain length and days remaining,
  as a `WARNING` under 21 days and an `ERROR` once expired. If the journal
  says 4 days on a relay restarted last night, the renewal pipeline is broken
  and you can see it without waiting for a client to fail.
- **`server.py --check-tls`** answers the same question on demand, without
  binding a port or touching the database.

### 0.3 Three private keys are in the uploaded archive

```
server/server.key   1732 bytes   the old self-signed localhost key
pki/server.key      1704 bytes   the lab relay leaf key
pki/ca.key          2484 bytes   the lab CERTIFICATE AUTHORITY root key
```

The third one is the serious one, and your own ignore file says why better
than I can: anyone holding `pki/ca.key` can mint a certificate that **every
build of the client which embeds the matching root will trust**. Re-issuing a
leaf is routine; replacing the root means rebuilding and redistributing the
client to every device.

The cause is mechanical and easy to fix. Your ignore file is named
`gitignore`. Git only reads `.gitignore` — with the leading dot. The file has
therefore never excluded anything, which is why `pki/`, `server/server.key`,
`server/.venv/` (15 MB), `server/demo.db`, `server/__pycache__/`,
`.pytest_cache/`, `build-interop/` and `interop.exe` are all still in a 28 MB
archive.

A corrected `.gitignore` ships with this change set. Install it, remove the
old one, and then **verify it is actually being read** — Git gives no warning
for an ignore file it never opens, so the failure looks identical to success:

```bash
cd <repo root>
rm -f gitignore                 # the version Git was never reading
git rm -r --cached pki server/server.key server/demo.db 2>/dev/null || true

git check-ignore -v pki/ca.key server/server.key
```

Two lines of output naming `.gitignore` means the rules are live. No output
means they are not. I ran that check against the delivered file and it matches
`pki/ca.key`, `pki/server.key`, `server/server.key` and `server/.venv`.

Then regenerate the lab CA (`python tools/make_demo_pki.py`) and rebuild the
client so it embeds the new root. Treat the old root as burned.

While you are there: `server/server.crt` and `server/server.key` are an
orphaned self-signed `CN=localhost` pair from 31 May. Nothing in the code
references them any more — only a stale line in `docs/BUILD.md` does, and that
line now gives wrong advice, because the `ignoreSslErrors()` path it depends on
was removed. Delete both files.

---

## 1. What the server folder actually needs at runtime

I traced the imports rather than trusting the existing documentation, which
overstates this.

| File | Role on the VM | Third-party imports |
|---|---|---|
| `server.py` | the relay itself | `websockets` |
| `prekey_store.py` | X3DH prekey pool, imported by `server.py` | none (stdlib `sqlite3`) |
| `crypto_core.py` | canonical Python ratchet reference — **tests only** | `cryptography`, `pynacl` |
| `file_crypto.py` | file-transfer reference — **tests only** | `cryptography`, `pynacl` |
| `demo_proof.py` | thesis demonstration script — **not a service** | `websockets` + the above |

So the production VM needs exactly two files and one package:
`server.py`, `prekey_store.py`, and `websockets>=13,<17`. The floor of 13
matters because the code imports `websockets.asyncio.server`, which older
releases do not provide.

`docs/BUILD.md` currently says `pip install websockets cryptography`. That is
not wrong so much as imprecise — it installs a dependency the relay never
imports, and omits `pynacl`, which the modules that *do* need `cryptography`
also need. Keeping the VM to the true runtime set means less to audit and less
to patch.

---

## 2. Create the instance

In the Pouta web console (https://pouta.csc.fi):

1. **Compute → Instances → Launch Instance.** Ubuntu 22.04 or 24.04 LTS;
   `standard.small` is ample for a relay whose job is to move small ciphertext
   frames. Select your SSH key pair at launch — you cannot add one afterwards
   without console gymnastics.
2. **Network → Floating IPs → Allocate IP to Project**, then **Associate** it
   with the new instance. Write the address down; it determines your hostname,
   your certificate and the URL your clients type.
3. **Network → Security Groups → Manage Rules**, and add:

| Direction | Protocol | Port | Remote | Why |
|---|---|---|---|---|
| Ingress | TCP | 22 | your IP, ideally | SSH |
| Ingress | TCP | 80 | 0.0.0.0/0 | certbot's HTTP-01 challenge |
| Ingress | TCP | 8765 | 0.0.0.0/0 | the relay |

Port 80 is the one people forget, and it is not just for today: certbot renews
unattended in 60 days and needs it again then. Leave it open.

Confirm from your laptop — not from the VM, since a local check passes even
when the security group is blocking the whole internet:

```bash
nc -vz <FLOATING_IP> 22
nc -vz <FLOATING_IP> 80
```

---

## 3. Copy the code up

Only the `server/` directory is needed. Everything the relay imports lives
there, plus the deployment scripts.

```bash
cd <repo root>
scp -r server/ ubuntu@<FLOATING_IP>:/tmp/chate2ee-deploy/
ssh ubuntu@<FLOATING_IP>
cd /tmp/chate2ee-deploy
```

---

## 4. Stage 1 — bootstrap the bare VM

```bash
sudo bash deploy/bootstrap_cpouta.sh --email your.name@tuni.fi
```

This installs `python3-venv`, `sqlite3`, `curl`, `dnsutils` and certbot;
works out the hostname; checks DNS; rehearses issuance against the Let's
Encrypt **staging** servers; and only then issues for real.

**On the hostname.** The script detects your floating IP by asking an external
service what address your request came from, then derives
`a-b-c-d.sslip.io` and asks you to confirm it against the Pouta console. It
cannot read the address off the interface: on cPouta a floating IP is NAT'd, so
the VM only ever sees a private `192.168.x.x` address on its own NIC. Ask
certbot to certify a private address and Let's Encrypt will refuse, correctly,
because it cannot reach it. If detection fails or you would rather be explicit:

```bash
sudo bash deploy/bootstrap_cpouta.sh --domain 128-214-9-77.sslip.io --email you@tuni.fi
```

**On the dry run.** It exercises DNS, inbound port 80 and the full challenge
flow against real Let's Encrypt infrastructure, and costs nothing against the
rate limit. If it fails, the cause is almost always one of three things, and
the script says so: port 80 closed in the security group, the floating IP not
associated, or the hostname not matching the address. Fix and re-run freely —
that is the whole point of a rehearsal.

Two things this script deliberately will not do. It will not open the security
group, because that is a cloud-console action the VM has no authority over.
And it will not probe port 80 by connecting to itself: from inside the VM the
sslip.io name resolves to the *floating* IP, so such a probe needs NAT
hairpinning, which OpenStack frequently does not support — it would report
failure on a perfectly good VM. The dry run is the authoritative test, so
that is what is used.

---

## 5. Stage 2 — install the relay

```bash
sudo bash deploy/install_cpouta.sh
sudo systemctl enable --now wsserver
journalctl -u wsserver -f
```

Ten guarded steps: hostname, interpreter and SQLite version checks, the service
user, the directory layout, a WAL-aware database backup, a private virtual
environment, the two code files, `/etc/default/chate2ee`, the systemd unit and
certbot deploy hook, and the TLS preflight as the service user. **Safe to
re-run** — that is how you ship a code change later.

It is split from stage 1 on purpose. Stage 1 touches shared machine state — apt,
certbot, your Let's Encrypt account — and normally runs once in a VM's life.
Stage 2 runs on every deployment. Merging them would re-execute the risky
once-only parts every time you pushed a fix, which is how a routine deploy
becomes an outage.

### What the two supporting files do

**`/etc/default/chate2ee`** holds the hostname, written by the installer:

```
CHATE2EE_DOMAIN=128-214-9-77.sslip.io
CHATE2EE_SERVICE=wsserver
CHATE2EE_USER=wsserver
CHATE2EE_TLS_DIR=/opt/wsserver/tls
```

The certbot deploy hook reads it rather than carrying a hostname of its own.
That is the difference between rebuilding by re-running a script and rebuilding
by remembering to edit one — and a hook still pointing at a dead instance's
hostname would copy nothing at all, silently, leaving the relay on a
certificate that quietly expires. With no config present the hook refuses
loudly instead, which I verified.

**The certbot deploy hook** solves two problems at once:

1. *Permissions.* `/etc/letsencrypt/live` and `/etc/letsencrypt/archive` are
   mode `0700 root:root`, so the unprivileged service user cannot read
   `privkey.pem` there — it cannot even see it. The hook copies both files to
   `/opt/wsserver/tls/` with ownership the service can read.
2. *Renewal never reaching the process.* `make_ssl_context()` calls
   `load_cert_chain()` once, before `serve()`, and that `SSLContext` lives for
   the life of the process. No SNI callback, no file watch. When certbot renews,
   the running relay keeps presenting the certificate it read at startup until
   something restarts it. The hook forces that restart.

Test the whole path now rather than discovering it in 60 days:

```bash
sudo certbot renew --dry-run          # watch journalctl -u wsserver -f
systemctl list-timers | grep certbot
```

---

## 6. Point the clients at the new host

The client hardcodes nothing — `LoginPage.qml` defaults to
`wss://localhost:8765` and the host is typed in. So there is no rebuild
needed, only a new URL:

```
wss://<your-new-hostname>:8765
```

Because the name is a public DNS name rather than a loopback or RFC 1918
address, `isLabHost()` returns false and the client validates against the
system trust store alone — a real chain, a real hostname check, no exceptions.
The lab CA in `pki/` grants no authority over this host, which is exactly the
scoping the design intends.

---

## 7. Verify — five checks, in order

**0. The preflight passes as the service user.** Run this *before*
`systemctl enable`, because it isolates the one failure that looks like
something else — starting by hand as root works, starting under systemd does
not, and both present as "the server won't come up":

```bash
sudo -u wsserver \
  CHATE2EE_TLS_CERT=/opt/wsserver/tls/fullchain.pem \
  CHATE2EE_TLS_KEY=/opt/wsserver/tls/privkey.pem \
  /opt/wsserver/.venv/bin/python /opt/wsserver/server.py --check-tls
```

Exit status 0 with `OK: this user can serve TLS with these files` is what you
want. It reports subject, issuer, SAN, chain length and days remaining, and
names the certbot permissions case explicitly if it hits it. No port is bound
and no database is touched.

**1. The relay says it is encrypted.** Anything else means the certificate did
not load and it silently fell back to plain `ws://`:

```bash
journalctl -u wsserver -n 30 --no-pager
# want:  INFO  TLS certificate: subject commonName=<your-hostname>
#        INFO  TLS certificate: issuer  ... Let's Encrypt ...
#        INFO  TLS certificate: expires in 89.x days (notAfter ...)
#        INFO  Listening on wss://0.0.0.0:8765
# NOT:   WARNING  Running WITHOUT TLS - development only!
# NOT:   ERROR    TLS certificate EXPIRED ...
```

The expiry line is the one to keep an eye on over the months the VM is up. It
reports what **this process is holding**, not what is on disk, so a number that
stops going back up to ~89 after a renewal means the deploy hook is not firing.

**2. The handshake completes and the chain validates**, from your laptop:

```bash
openssl s_client -connect <your-hostname>:8765 \
    -servername <your-hostname> </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

**3. The relay answers over `wss://`.** This is the check that distinguishes
"TLS terminates" from "the application actually works". It uses `auth_begin`,
the one frame the server handles before login, so it needs no account. Run it
anywhere with `websockets` installed:

```python
import asyncio, json, ssl, websockets

async def main():
    ctx = ssl.create_default_context()          # verification ON, public CAs
    uri = "wss://<your-hostname>:8765"
    async with websockets.connect(uri, ssl=ctx) as ws:
        await ws.send(json.dumps({"type": "auth_begin", "nick": "smoketest"}))
        print(json.loads(await asyncio.wait_for(ws.recv(), 5)))

asyncio.run(main())
```

Expect `{'type': 'auth_salt', 'nick': 'smoketest', 'salt': None}`. I ran this
exact exchange against this exact `server.py` in the sandbox, over verified TLS,
and that is the reply it produced.

**4. A real message survives storage.** No earlier check substitutes for this
one: it is the only one that exercises the write path end to end. Log in with two clients,
send a message to a peer who is **offline** so the relay must write it to
`messages`, then bring the peer online and confirm delivery. Watch for
`OperationalError` in the journal throughout.

---

## 8. Rollback

Keep this short enough to execute under pressure:

```bash
sudo systemctl stop wsserver
sudo cp /opt/wsserver/server.py.pre-deploy /opt/wsserver/server.py
sudo systemctl start wsserver
```

The database needs no rollback for the schema change. The added `frame` column
is invisible to the old code, which never names it, and the added tables are
inert to it. Restoring `chat.db.pre-deploy` is only for genuine corruption —
and remember to restore the `-wal` and `-shm` sidecars with it, or you will
restore a database to a state its journal disagrees with.

---

## 9. Three things worth naming in the thesis

None of these is a defect. All three are consequences of choices made
deliberately, and an examiner who spots them will ask.

**The Qt client does not use the X3DH prekey path.** This is the one I would
prioritise. `server/prekey_store.py`, the server's `publish_prekeys` and
`get_bundle` handlers, `tests/x3dh.py` and `tests/test_x3dh.py` implement and
exercise X3DH properly — 52 references across the Python side. The Qt client
has **zero**: no file under `client/` mentions prekeys or X3DH at all. It
fetches a peer's long-term identity key with `getkey` and performs the initial
DH against that directly.

That is a coherent design, and for a relay where both parties register their
identity key it works. But it means the shipping application does not have the
property X3DH exists to provide: the ability to start a session with a peer who
is offline, using prekeys they published in advance, with the initial message
protected by an ephemeral rather than only a long-term key. The practical
consequence is weaker forward secrecy for the very first message of a
conversation.

Nothing needs fixing before the deadline — the deployment is unaffected, and
the Python implementation is real and tested. What matters is that the write-up
describes the boundary accurately: X3DH is implemented and verified in the
reference implementation and supported by the relay, while the Qt client uses
direct identity-key agreement. Claiming X3DH as a property of the *application*
would be the kind of overstatement an examiner tends to find, and it is
entirely avoidable by saying which component does what.

**The log stream is shared.** `broadcast_logs_forever()` sends the relay's log
ring to *every* logged-in client, and the file's own comment is candid that
this is metadata: nicknames, who is online, who relayed to whom, sizes,
timings. No plaintext and no keys can appear there — the server holds neither —
but on a multi-user public deployment, user A sees that user B logged in. The
comment already frames this as demo behaviour; the thesis should say so
explicitly next to the always-on client log viewer, rather than leaving a
reader to notice it. If you would rather not defend it at all, gating the
`server_log` frame on an allow-list of nicknames is a small change.

**The relay is unauthenticated at the transport layer.** Anyone who can reach
port 8765 can open a socket and register a nickname. That is the untrusted
key-server model the design is built on and it is the correct choice — but it
means the deployment is exposed for as long as it is up, and "it is only a
student project" is not an access control. Watch `journalctl -u wsserver` for
`REJECT` lines during the period the VM is public.

---

## 10. Capture the evidence early this time

The previous VM is gone and so is anything that was only demonstrable while it
was running. Do not let that happen twice. As soon as the relay is up, capture:

1. The certificate chain as served, which is unreproducible once the VM goes:

   ```bash
   openssl s_client -connect <hostname>:8765 -servername <hostname> </dev/null 2>/dev/null \
     | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
   ```

2. A screenshot of the client's TLS summary showing the Let's Encrypt issuer.
3. `journalctl -u wsserver` covering a start, a message exchange and a
   `certbot renew --dry-run`.
4. A screenshot of the Pouta security group rules.

Put these in the thesis appendix now, not later. A figure showing a real public
CA validating a real hostname is the evidence that the TLS chapter rests on,
and it takes two minutes while the VM exists and is impossible afterwards.

When the VM is eventually deleted for real:

- Export anything wanted from `chat.db`, checkpointing first so the WAL
  sidecars are folded in:
  `sqlite3 chat.db "PRAGMA wal_checkpoint(TRUNCATE);"`.
- Revoke the certificate rather than letting it lapse, **while you still have
  the key**:
  `sudo certbot revoke --cert-path /etc/letsencrypt/live/<hostname>/fullchain.pem`.
  Once the instance is gone this is no longer possible — which is exactly the
  situation you are in with the previous one.
- Confirm the lab CA path still works end to end, because after the VM it is
  the only demonstration you have. `docs/TLS_WITHOUT_HOSTING.md` covers it.

---

## Appendix — what I verified, and what I could not

I would rather you knew which parts of this are tested and which are reasoned,
so you can aim your own testing at the right places.

**Run against the modified `server/server.py`, in a Linux sandbox:**

| Check | Result |
|---|---|
| `python -m py_compile` on `server.py`, `prekey_store.py`, `mitm_relay.py` | clean |
| Full test suite, before my changes | 295 passed |
| Full test suite, after my changes + the new module | **304 passed** |
| `tests/test_schema_migration.py` with the migration deliberately disabled | 5 of 9 fail — the guards genuinely bite |
| Start against a database with the 31 May schema | `SCHEMA migrated: added messages.frame` / `added file_meta.final_seen` |
| Legacy row after migration | preserved, reads back `frame = NULL` |
| `save_message(..., frame=...)` on that database | succeeds (it raised `OperationalError` before) |
| Second start on the same database | no migration lines — idempotent |
| Fresh database | no migration lines; columns present from the CREATE statements |
| Plain start, no TLS | `WARNING Running WITHOUT TLS`, then `Listening on ws://` |
| `--cert` / `--key` | `Listening on wss://`, TLS 1.3 / AES-256-GCM negotiated |
| `CHATE2EE_TLS_CERT` / `CHATE2EE_TLS_KEY` | identical result — the unit's path works |
| `auth_begin` round trip over verified `wss://` | `{'type': 'auth_salt', ...}` |
| Startup log, healthy certificate | subject / issuer / SAN / chain / days remaining |
| Startup log, expired certificate | `ERROR TLS certificate EXPIRED 6.0 days ago` |
| `--check-tls`, healthy certificate | exit 0, full report |
| `--check-tls`, no certificate configured | exit 2, lists the three ways to supply one |
| `--check-tls`, mismatched cert and key | exit 1, `KEY_VALUES_MISMATCH` plus the two openssl commands to compare them |
| `--check-tls`, expired certificate | exit 1, `EXPIRED 6.0 days ago` |
| `--check-tls` as `wsserver` against `/etc/letsencrypt/live` | exit 1, correctly reported as a permission, not a missing file |
| `--check-tls` as `wsserver` against the hook's copy | exit 0 |
| Relay running as `wsserver`, serving the hook-installed certificate | `Listening on wss://`, round trip succeeded |
| Files created next to the database | `chat.db`, `-wal`, `-shm` — why `ReadWritePaths` names the directory |
| `bash -n` on both shell scripts | no syntax errors |
| `install_cpouta.sh`, full run | steps 1–9 complete; degrades cleanly where systemd is absent |
| `systemd-analyze verify` on `wsserver.service` | passed |
| The deploy hook against a real `/etc/letsencrypt/live/` layout | installs 0644 / 0640 owned by the service user |
| The deploy hook with `RENEWED_LINEAGE` for another certificate | correctly no-ops |
| `git check-ignore -v` against the new `.gitignore` | matches `pki/ca.key`, `pki/server.key`, `server/server.key`, `server/.venv` |
| `sslip_name`, `valid_ipv4`, `is_private_ipv4` helpers | correct, including 172.16–31 vs 172.32 boundary |
| `detect_public_ip` against the live internet | returned this sandbox's real public address |
| `check_dns` against a real sslip.io name | resolved correctly, and caught a deliberate mismatch |
| Full installer run against a **different** floating IP (`128.214.9.77`) | all 10 steps clean; nothing hostname-specific was hardcoded |
| Generated `/etc/default/chate2ee` | correct domain written |
| Deploy hook reading that config | copied the certificate for the new host |
| Deploy hook with the config removed | refuses loudly, exit 1 — does not silently no-op |
| Relay run on the rebuilt layout | `Listening on wss://`, verified round trip |

**Two bugs of my own that this testing caught**, both found by trying failure
cases rather than the happy path — worth recording because they are the reason
the appendix above is worth anything:

1. My first `describe_certificate()` used `load_verify_locations` +
   `get_ca_certs()`. Clean public API, worked perfectly — and returned nothing
   at all for an expired certificate, because OpenSSL will not add an expired
   certificate to a trust store. An expiry check that goes quiet exactly when
   the certificate expires is worse than no check. Replaced with a decoder that
   makes no validity judgement, with the public route kept as a fallback.
2. My first permissions check used `os.path.exists()`, which reported
   certbot's private key as "does not exist" — because a user who cannot
   traverse a `0700` directory cannot stat what is inside it either. That would
   send you hunting for a missing file instead of a permission. It now opens
   the file and distinguishes `PermissionError` from `FileNotFoundError`.

**Not verified, because it needs the VM or the internet:**

- The cPouta security group rules, and therefore whether port 80 is genuinely
  reachable from outside at issuance and at renewal time.
- Actual certbot issuance against Let's Encrypt. The dry run in stage 1 is your
  equivalent, and `certbot renew --dry-run` after stage 2 is worth running while
  watching `journalctl -u wsserver -f` for the restart.
- Live `systemctl` behaviour. `systemd-analyze verify` accepted the unit, but
  the sandbox has no running systemd, so the hardening directives
  (`ProtectSystem=strict`, `SystemCallFilter=@system-service`) were not
  exercised against the real relay. If it fails to start with a cryptic error,
  comment out the hardening block, confirm it runs, then reinstate the
  directives one at a time.
- Anything about the Qt client, which cannot be compiled here.
