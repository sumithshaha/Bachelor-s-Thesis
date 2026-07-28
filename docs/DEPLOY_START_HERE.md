# Deploying the relay to a server

This document covers putting the relay on a real internet-facing machine with a
genuine, publicly-trusted TLS certificate. It is written against CSC's **cPouta**
(the Finnish academic cloud, free for students), but nothing here is specific to
cPouta beyond the security-group step — any Ubuntu VM with a public IP works the
same way.

**You do not need this to run the application.** A relay on your own machine
with the lab certificate is enough for development and for a demonstration; see
[GETTING_STARTED.md](GETTING_STARTED.md). Deploy to a server when you want the
two clients on *different* networks, or a certificate from a public authority
rather than a local one.

[DEPLOY_CPOUTA.md](DEPLOY_CPOUTA.md) is the long-form runbook with the reasoning
behind each step, rollback procedure and verification detail. This document is
the path through it.

---

## The shape of it

Two stages, both scripted and both safe to re-run:

1. **`bootstrap_cpouta.sh`** — prepares a bare VM and obtains the certificate.
   Installs `python3-venv`, `sqlite3`, `curl`, `dnsutils` and certbot; works out
   the hostname from the floating IP; rehearses issuance against Let's Encrypt's
   **staging** servers at no rate-limit cost; then issues the real certificate.
2. **`install_cpouta.sh`** — installs the relay itself. Ten guarded steps: the
   service user, the directory layout, a WAL-aware database backup, a private
   virtual environment, the code, `/etc/default/chate2ee`, the systemd unit, the
   certbot renewal hook, and a TLS preflight run *as the service user*.

The staging rehearsal is the part worth appreciating. Let's Encrypt rate-limits
failed issuance, so a misconfigured first attempt can lock you out for hours.
The rehearsal is free and unlimited, and it names which of the three usual causes
applies: port 80 closed, floating IP not associated, or hostname not matching.

---

## No domain name required

`sslip.io` resolves any hostname of the form `a-b-c-d.sslip.io` to the address
`a.b.c.d`. So a VM at `86.50.230.46` is reachable as `86-50-230-46.sslip.io`,
and Let's Encrypt will issue a certificate for that name because it is a real
DNS name that really resolves to the machine.

That is the whole trick: a publicly-trusted certificate, on a real hostname, for
free, without buying a domain.

---

## Step 0 — Work from your WSL home, and never `sudo` your ssh

Two rules, both learned the hard way. They are short, and skipping either costs
an afternoon.

### Copy the working directory to your WSL home first

On Windows, work from your **WSL home directory** (`~`), not from `/mnt/c/...`.

The Windows filesystem does not carry Unix permissions. `chmod 600` on a file
under `/mnt/c` appears to succeed and changes nothing, so an SSH key stored
there is silently world-readable and OpenSSH refuses it — with an error about
permissions on a file whose permissions you have just set correctly. Copying the
tree into `~` first makes the whole class of problem disappear.

```bash
cp -r /mnt/c/Users/<you>/path/to/chat-e2ee ~/
cd ~/chat-e2ee
```

Your SSH key must live in the WSL home too, with the right mode:

```bash
chmod 600 ~/thesis.key
```

### Never put `sudo` in front of `ssh` or `scp`

This is the single most expensive mistake available here, so it gets its own
heading.

`ssh` and `scp` act **as the user who runs them**. Prefixing `sudo` makes them
act as *root*, which means:

- They look for the key at `/root/.ssh/`, not yours, and fail with
  `Permission denied (publickey)` even though your key is perfect.
- Any file they create is owned by root. This is how `~/thesis.key` ends up
  root-owned, after which plain `chmod` gives *"Operation not permitted"* and
  non-sudo `ssh` fails with *"Load key: Permission denied"* — two errors that
  point away from the actual cause.
- Worst case, a copy partially succeeds from the wrong context. One recorded run
  silently transferred 3 of 11 files.

`sudo` belongs only to commands that change the VM, and only once you are
already on it.

If a key has already been left root-owned, take it back:

```bash
sudo chown "$USER:$USER" ~/thesis.key
chmod 600 ~/thesis.key

# Must print a key line, WITHOUT sudo:
ssh-keygen -y -f ~/thesis.key >/dev/null && echo "key is yours and readable"
```

If that still fails, the bundled diagnostic checks location, permissions,
ownership, load-ability and live authentication, and names the exact fault:

```bash
bash server/deploy/diagnose_ssh.sh ~/thesis.key ubuntu@<VM-IP>
```

---

## Step 1 — Open the ports

In the Pouta web console (<https://pouta.csc.fi>): **Network → Security Groups →
your group → Manage Rules**. Three ingress rules:

| Protocol | Port | Remote | Why |
|---|---|---|---|
| TCP | 22 | your IP, ideally | SSH |
| TCP | 80 | 0.0.0.0/0 | certbot's HTTP-01 challenge |
| TCP | 8765 | 0.0.0.0/0 | the relay |

Port 80 is the one people forget, and it is needed **again at renewal**, sixty
days later, unattended. Leave it open.

Check from your own machine — a check run on the VM passes even when the
security group is blocking everyone else:

```bash
nc -vz <VM-IP> 80
nc -vz <VM-IP> 8765
```

---

## Step 2 — Copy the code up

```bash
HOST=ubuntu@<VM-IP>

# Modern scp will not create the destination, so make it first:
ssh -i ~/thesis.key "$HOST" 'rm -rf /tmp/chate2ee-deploy && mkdir -p /tmp/chate2ee-deploy'

# Copy the server tree — as yourself, no sudo:
scp -i ~/thesis.key -r server/ "$HOST":/tmp/chate2ee-deploy/
```

Confirm it arrived intact before going further:

```bash
ssh -i ~/thesis.key "$HOST" \
  'wc -c /tmp/chate2ee-deploy/server/server.py; ls /tmp/chate2ee-deploy/server/deploy/'
```

`deploy/` must list `bootstrap_cpouta.sh`, `install_cpouta.sh`,
`chate2ee-common.sh`, `chate2ee-cert-deploy.sh`, `diagnose_ssh.sh`,
`fix_clock.sh` and `wsserver.service`. A short file count here means you copied
from the wrong folder — check that before blaming the scripts.

Only `server/` is needed on the VM. The relay's sole runtime dependency is
`websockets`; `cryptography` and `pynacl` belong to the Python reference
implementations, which are used by the tests and not by `server.py`.

---

## Step 3 — Bootstrap, install, start

Now you are on the VM, and `sudo` is correct — this is real administration of
the server.

```bash
ssh -i ~/thesis.key ubuntu@<VM-IP>
cd /tmp/chate2ee-deploy/server

sudo bash deploy/bootstrap_cpouta.sh --email you@tuni.fi
sudo bash deploy/install_cpouta.sh --domain <a-b-c-d>.sslip.io

sudo systemctl enable --now wsserver
sudo journalctl -u wsserver -f
```

Both scripts detect the hostname themselves; `--domain` states it explicitly,
which is worth doing so a misdetection fails loudly rather than issuing a
certificate for the wrong name.

The `--email` address receives expiry warnings from Let's Encrypt. Without one,
registration succeeds but you get no warning before a certificate lapses.

**In the journal you want:**

```
INFO  TLS certificate: subject commonName=<your-hostname>
INFO  TLS certificate: issuer  ... Let's Encrypt ...
INFO  TLS certificate: expires in 89.x days ...
INFO  Listening on wss://0.0.0.0:8765
```

**Not** `WARNING Running WITHOUT TLS` (the certificate did not load) and **not**
`ERROR TLS certificate EXPIRED` (renewal is broken).

`install_cpouta.sh` is idempotent, so re-running it is how you ship a later code
change. After any change:

```bash
sudo systemctl restart wsserver
```

---

## Step 4 — Verify, then point the clients

Two checks worth doing before you trust it.

```bash
# On the VM: the preflight passes as the SERVICE user, not as root.
sudo -u wsserver \
  CHATE2EE_TLS_CERT=/opt/wsserver/tls/fullchain.pem \
  CHATE2EE_TLS_KEY=/opt/wsserver/tls/privkey.pem \
  /opt/wsserver/.venv/bin/python /opt/wsserver/server.py --check-tls

# From your own machine: the chain validates against a public authority.
openssl s_client -connect <a-b-c-d>.sslip.io:8765 \
    -servername <a-b-c-d>.sslip.io </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

The `--check-tls` preflight is the check that separates *"works as root"* from
*"works under systemd"*. `/etc/letsencrypt/live` is `0700 root:root`, so an
unprivileged service user cannot read `privkey.pem` from there at all — which is
why `chate2ee-cert-deploy.sh` exists as a certbot deploy hook.

Then set the client's server field to:

```
wss://<a-b-c-d>.sslip.io:8765
```

Because that is a public DNS name rather than a loopback address, the client
validates against the **system trust store** with a real hostname check, with no
lab certificate involved.

> **The relay reads its certificate once, at startup.** There is no reload path:
> `load_cert_chain()` runs before `serve()` and the resulting context lives for
> the life of the process. A renewed certificate therefore does not reach a
> running relay until something restarts it. `chate2ee-cert-deploy.sh` is the
> certbot deploy hook that forces that restart.

---

## Step 5 — Capture the evidence now

A certificate chain served by a real host is not reproducible once the VM is
gone, and student cloud allocations expire. Do this the day it works:

1. The `openssl s_client` output from step 4.
2. A screenshot of the client connected, showing the Let's Encrypt issuer.
3. `journalctl -u wsserver` across a start, a message exchange, and a
   `sudo certbot renew --dry-run`.
4. A screenshot of the security group rules.

---

## Quick reference

Working notes, condensed. Read the sections above before using these — the
`sudo`/`ssh` rule in particular is not obvious from the commands alone.

Replace `<VM-IP>` with your address, `<a-b-c-d>` with the dashed form of it, and
`you@tuni.fi` with your own address.

```bash
# ---- Preparation -------------------------------------------------------
# Copy the working directory to your WSL home FIRST, or permission
# problems will follow. The SSH key must live in the WSL home too,
# with chmod 600.
cp -r /mnt/c/Users/<you>/path/to/chat-e2ee ~/
cd ~/chat-e2ee
chmod 600 ~/thesis.key

# ---- Copy the code up --------------------------------------------------
# NOTE: no sudo on ssh or scp. They act as YOU; sudo makes them act as
# root, looks for the key in /root/.ssh, and leaves root-owned files.
ssh -i ~/thesis.key ubuntu@<VM-IP> \
    'rm -rf /tmp/chate2ee-deploy && mkdir -p /tmp/chate2ee-deploy'
scp -i ~/thesis.key -r server/ ubuntu@<VM-IP>:/tmp/chate2ee-deploy/

# ---- On the VM: sudo IS correct from here ------------------------------
ssh -i ~/thesis.key ubuntu@<VM-IP>
cd /tmp/chate2ee-deploy/server
sudo bash deploy/bootstrap_cpouta.sh --email you@tuni.fi
sudo bash deploy/install_cpouta.sh --domain <a-b-c-d>.sslip.io
sudo systemctl enable --now wsserver
sudo systemctl restart wsserver          # after any later code change
sudo journalctl -u wsserver -f           # watch the log

# ---- Client URLs -------------------------------------------------------
# Deployed relay:
wss://<a-b-c-d>.sslip.io:8765

# ---- Local relay instead, phone over USB -------------------------------
adb reverse tcp:8765 tcp:8765            # phone's localhost -> your machine
python server/server.py --demo-tls       # lab certificate
# then connect the phone to:
wss://localhost:8765
```

`adb reverse` works with the lab certificate because the generated leaf lists
`localhost`, `127.0.0.1` and `::1` among its subject-alternative names — so the
hostname check passes on the phone exactly as it does on the desktop.

---

## If something goes wrong

- SSH or `scp` refuses you → `bash server/deploy/diagnose_ssh.sh ~/thesis.key ubuntu@<VM-IP>`
- Timestamps in the log look wrong → `sudo bash deploy/fix_clock.sh` sets NTP and `Europe/Helsinki`
- Certificate issuance fails → re-run the bootstrap; the staging rehearsal names the cause and costs nothing
- Anything else → [TROUBLESHOOTING.md](TROUBLESHOOTING.md), then [DEPLOY_CPOUTA.md](DEPLOY_CPOUTA.md) for the long form
