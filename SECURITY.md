# Security

What this project claims, what it does not, and how the claims are checked.

> **Status.** This is a Bachelor's thesis project. It implements a well-specified
> protocol carefully and checks it thoroughly, but it has not been independently
> audited and should be read as a study of the protocol rather than as software
> to trust with anything that matters.

---

## Threat model

### Defended against

**A curious or compromised relay.** The relay is treated as untrusted. It routes
ciphertext and holds no key that opens it. Even with full access to the server,
its database and its logs, an attacker gets no message content.

**A network attacker.** TLS with strict chain and hostname verification protects
the transport. There is no exception path — no `ignoreSslErrors()`, no
"accept invalid certificate on localhost" branch — because a connection that is
encrypted but unauthenticated is the connection a man in the middle wants.

**An attacker who steals keys later.** The Double Ratchet advances key material
with every message, so a key captured today does not open yesterday's traffic
(forward secrecy). Skipped-message keys are retained only within a bounded
window; unbounded retention would quietly undo this.

**An attacker who stops.** A rekey heartbeat forces a Diffie-Hellman ratchet
after 8 one-way messages or 15 minutes idle, so a session that was compromised
recovers once the attacker loses access (post-compromise security). Without
this, a one-way conversation would never turn its DH ratchet and would never
heal.

**A relay that substitutes keys.** This is the interesting case, because the
protocol alone cannot stop it — a relay controls the key directory, so it can
hand each party its own key and sit in the middle. What it cannot do is make the
resulting **safety numbers** match. Verification is therefore required before a
conversation is allowed, and the guarantee rests on users actually performing
the comparison.

### Not defended against

Stated plainly, because a security project that lists only its strengths has not
been honestly evaluated.

**Metadata.** The relay necessarily sees who is registered, who is online, who
talks to whom, when, and how large each message is. Hiding this needs a
different architecture — mixing, padding, cover traffic — and is out of scope.

**A compromised endpoint.** If the device is compromised, messages are readable
as the user reads them. App lock and at-rest sealing raise the cost of casual
access to an unlocked device; they do not resist an attacker with code execution
on it.

**Users who skip verification.** The application requires the safety-number step
before a conversation opens, but it cannot verify that a human genuinely compared
the numbers rather than tapping through. This is the residual risk of the whole
design and it is inherent, not an implementation gap.

**Denial of service.** A relay can refuse to deliver. It cannot read, but it can
withhold.

**Traffic analysis, group messaging, federation.** Not attempted. One-to-one, one
relay.

---

## How the claims are checked

Three commands, each answering a different question. All are reproducible from a
clean clone.

```bash
bash run_tests.sh                                 # 497 tests, 33 modules
bash run_interop.sh                               # 10 cross-language checks
PYTHONPATH=server python tests/e2ee_redteam.py    # three attack experiments
```

The red-team harness is the one worth reading rather than merely running. It
**carries out** the man-in-the-middle attack — the relay substitutes keys and
reads the conversation — and then detects it with the safety-number comparison.
Demonstrating the break and the detection together is more informative than
asserting that the detection works.

Several test modules exist because a specific failure actually occurred and was
not caught by anything else: unbounded skipped-key retention, a rekey ping storm
to offline peers, a self-addressed relay frame, an identity key stored without
its Ed25519→X25519 conversion. Each is now pinned by a test that fails if the
defect returns. `tests/TESTS_INTEGRATION.md` describes how the suite itself was
checked for the failure mode where tests pass without testing anything.

---

## Key material in this repository

**No private key belonging to a deployment should ever be committed here.**

`.gitignore` excludes `pki/`, `*.key`, `*.pem`, `*.ekey`, and `*.db`. Two
consequences follow, and both are deliberate:

- **Every checkout generates its own lab certificate authority.** Run
  `python tools/make_demo_pki.py`. It creates `pki/`, and copies the *public*
  root into `client/pki/demo-ca.crt` so the client trusts it.
- **`client/pki/demo-ca.crt` is committed on purpose.** It is a certificate, not
  a key — the public half of a root, compiled into the binary as a trust anchor.
  Publishing it is what makes the lab TLS demonstration reproducible.

### Before publishing

```bash
python tools/check_publish_safety.py
```

This scans the working tree for private keys **by content as well as by
filename**, so a key saved under an innocuous name is still found, and then asks
`git check-ignore` what git would actually do rather than reading `.gitignore`
and assuming. It exits non-zero when the tree is unsafe, so it also works as a
pre-commit hook or a CI step.

The reason it asks git rather than trusting the ignore file: this project once
shipped its rules in a file named `gitignore`, with no leading dot. Git reads
only `.gitignore`, so none of the rules applied — and git reports no error for
an ignore file it never reads. The failure is silent and looks exactly like a
working setup.

### If a key is exposed

A private key that has been pushed to a public repository is compromised, even
if the commit is deleted minutes later. Rewriting history does not recall a key
that has already been fetched or indexed. Reissue rather than hide:

- **Lab CA** (`pki/ca.key`) — delete `pki/`, run `python tools/make_demo_pki.py`,
  and rebuild every client, because the root is compiled in.
- **Relay certificate on a server** — `sudo certbot renew --force-renewal`, then
  restart the service.
- **SSH key** — remove the public half from `~/.ssh/authorized_keys` on the VM
  and generate a new pair.

### Why this matters more for a shared repository

The intended audience for this repository is classmates who will **clone it,
build it and run it**. The lab root is compiled into every client built from
this source. If the matching private key were public, every one of those builds
would trust a key that anyone could also hold — so any attacker on the same
network could present a valid-looking certificate for a lab relay and the client
would accept it without complaint.

That would silently remove the transport-security property the project sets out
to demonstrate, in the builds of the people the repository exists for. It is
also entirely avoidable: regenerating the authority is one command and takes a
few seconds.

---

## Reporting a problem

This is student coursework rather than deployed software, so there is no formal
disclosure process. If you find something while reviewing it, please open an
issue — or, for anything you would rather not post publicly, contact the author
through the university.
