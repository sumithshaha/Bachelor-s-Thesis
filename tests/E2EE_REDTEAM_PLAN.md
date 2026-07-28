# ChatE2EE — end-to-end encryption red-team plan

This is a security evaluation of your own application: a structured attempt to
break the central claim, with a pass/fail criterion for each experiment and a
pointer to where the defence lives in your code. It now covers **file transfers
as well as text**, because files were changed to deliver their key over the
ratchet and so carry the same guarantees. Run the experiments, record what you
observe, and write the findings into your Discussion/Results **in your own
words** — the plan and the tooling are engineering scaffolding, not thesis
prose.

**The claim under test:** *the relay server can never read message contents —
text or file.*

The relay is, by your own design (`server.py`: "the untrusted key-server
model"), the least-trusted component: it routes ciphertext and it is the public-
key directory. So the sharpest adversary is the relay operator itself. The
experiments escalate from a passive relay to an active one, then cover files,
the network, the endpoint, and metadata.

---

## The adversaries (threat model)

| # | Adversary | Capability | What it tests | Defence in your code |
|---|-----------|-----------|---------------|----------------------|
| 1 | Honest-but-curious relay | Reads/stores every frame and file chunk; holds both public keys | Content secrecy against a passive server | Double Ratchet + AEAD for text; secretstream for file bulk; server only ever sees nonce+ciphertext / opaque chunks (`crypto_core.ratchet_encrypt`, `file_crypto.encrypt_file`, `server.py` `messages` / `file_meta` / `file_chunks`) |
| 2 | Malicious relay (MITM) | Also lies in the key directory; substitutes keys and relays in the middle | Whether substitution is *possible* and whether it is *detected* — for text and file keys alike | Out-of-band safety number (`CryptoBox::safetyNumber` / `crypto_core.safety_number`) + the verification gate |
| 3 | Passive network eavesdropper | Sniffs the wire between client and relay | Transport confidentiality + defence-in-depth of the inner layer | TLS (Let's Encrypt) over the WebSocket; inner AEAD/secretstream underneath |
| 4 | Endpoint / at-rest + one-time compromise | Snapshots ratchet state or a key at time *t* | Forward secrecy (past stays safe) and post-compromise security (future heals) — **now for files too** | Ratchet chain/DH steps (`kdf_ck`/`kdf_rk`/`_dh_ratchet`); random per-file key delivered via ratchet; `test_post_compromise.py`, `pcs_lifecycle_verify.py` |
| 5 | Metadata observer (the relay, honestly) | Sees who/when/size even when content is opaque | The *limits* of E2EE — an honest evaluation must state these | None by design; document it |

All five adversaries apply to **file transfers** as well as text. Since a file's
per-file key is now random and delivered inside `file_init.keyenc` as an ordinary
ratchet frame, the file's key confidentiality reduces to the ratchet's: a passive
relay sees only opaque chunks plus an opaque `keyenc`; an active MITM that
substitutes an identity key breaks the file-key delivery exactly as it breaks a
text message, and the same safety number detects it; and the file key inherits
the ratchet's forward secrecy and post-compromise security.

---

## Experiments 1–3 — runnable now, against your real crypto

`tests/e2ee_redteam.py` drives `server/crypto_core.py` and `server/file_crypto.py`
directly (nothing mocked) and runs all three experiments. From the repo:

```bash
cd chat-e2ee/server && python3 ../tests/e2ee_redteam.py
# or:  cd chat-e2ee && PYTHONPATH=server python3 tests/e2ee_redteam.py
```

Dependencies are the server's own: `cryptography` and `pynacl`.

**Experiment 1 (passive relay, text).** The harness prints the exact frame the
relay stores — `cipher`, `nonce`, `ciphertext`, no plaintext anywhere — then has
the server try to decrypt it with everything a curious operator could reach
(including `HKDF(pub_alice ‖ pub_bob)`, i.e. public data only). Every attempt
returns `InvalidTag`; the recipient, holding the private key, decrypts fine.

> **Pass = E2EE holds:** the relay cannot read the message. This is the positive
> result that backs your central claim.

**Experiment 2 (active MITM, text).** The relay hands each party Mallory's public
key in place of the peer's, then decrypts and re-encrypts in the middle. The
harness shows Mallory reading the message in the clear and Bob receiving it none
the wiser — **then** prints the safety number each screen would show. Alice's and
Bob's numbers differ from each other and from the honest value.

> **Pass = break reproduced AND caught:** a malicious relay *can* read messages,
> but only if the users skip verification; the safety number diverges under
> substitution, so an out-of-band comparison detects the MITM. The entire E2EE
> guarantee reduces to that one human check — which is exactly why the app gates
> the conversation on it.

**Experiment 3 (file transfer).** The harness encrypts a ~96 KB "file" with a
**random** per-file key using the real `file_crypto` secretstream, then delivers
that key over the ratchet inside a `file_init.keyenc` object — exactly what the
client now puts on the wire. It shows:

- **The relay is blind.** It stores `keyenc` (the ratchet-encrypted key) and the
  secretstream chunks, and both attempts to read them — recovering the key from
  `keyenc` with public-derived material, and decrypting the chunks with a guessed
  key — are rejected.
- **The recipient recovers the key over the ratchet** and decrypts the file to a
  byte-identical `sha256`; a truncated stream is still rejected (`TAG_FINAL`
  missing), so bulk integrity holds.
- **Forward secrecy, old vs new.** Under the *old* design the file key was
  `HKDF(static identity secret, msg_id)`, so anyone who later stole an identity
  key could re-derive every file's key — the harness shows that re-derivation
  succeeding. Under the *new* design the key is random and delivered via the
  ratchet, so the same attacker cannot re-derive it.

> **Pass = files match text:** content secrecy against the relay, integrity, and
> forward secrecy / PCS — the last of which the static-key design lacked. MITM
> detection for files is identical to Experiment 2 (the file key rides the
> ratchet), so it is not re-run.

---

## File transfers — what changed and why

Previously a file's symmetric key was derived from the **static X25519 identity
shared secret** (`HKDF(shared, msg_id)`). That key is a deterministic function of
the long-term identity keys, so a one-time compromise of an identity key exposed
every file, past and future — no forward secrecy, no post-compromise security,
even though text had both.

The fix keeps the secretstream bulk encryption unchanged and changes only the
key's source and delivery: the file is encrypted under a **random** per-file key
(`FileCrypto::randomKey()`), and that key is delivered to the recipient **through
the ratchet** (`encryptFor` / `decryptFrom`), hex-encoded inside the
`file_init.keyenc` object. The file's key confidentiality now reduces to the
ratchet's, so files inherit forward secrecy and PCS. The server stores the full
`file_init` envelope verbatim, so `keyenc` rides along for offline delivery with
no server change; the receive path applies the same `dh:n` replay-dedup and heal
that text uses.

---

## Experiment 2, live — MITM on your two real devices

The harness proves the **read** half in simulation. To prove the **detection**
half on real hardware — Windows client + S24 Ultra client against a running
relay — stand up a *malicious copy* of your relay that substitutes keys, and
watch the safety numbers on the two screens fail to match. This is exactly what
`server/mitm_relay.py` does (env-gated behind `E2EE_MITM=1`); its run procedure
is in that file's header. Because the file key now rides the ratchet, the same
malicious relay also breaks file transfers between the two victims, and the same
safety-number mismatch flags it.

> The Tier-A instrument only substitutes keys, so it demonstrates **detection**.
> It does not decrypt live traffic — for that the relay would also have to run two
> ratchet endpoints (one per victim) with `crypto_core`, decrypting each inbound
> frame (text or file `keyenc`) and re-encrypting outbound. The harness already
> proves the read half definitively, so Tier-A live is usually enough.

---

## Experiment — passive network eavesdropper

Point one client at the relay and capture the traffic you (legitimately) control:

- **On the relay host**, capture the listening port, e.g.
  `sudo tcpdump -i any -w /tmp/e2ee.pcap 'port 8765'`, exchange a few messages and
  send a file, then open the capture in Wireshark.

**Expected:** with TLS on, the WebSocket payload is a TLS record — opaque. Even if
you terminate or strip TLS (e.g. point the client at a plain `ws://` logging proxy
you run), the *inner* frames are still opaque: ratchet `{header, nonce,
ciphertext}` for text and, for files, the `keyenc` ciphertext plus secretstream
chunks. Content stays encrypted either way. That is the defence-in-depth story —
TLS protects metadata-in-transit and the server's endpoint identity; the E2EE
layer protects content regardless of the transport.

> **Pass:** no plaintext (text or file) recoverable from the wire with or without
> TLS.

---

## Experiment — endpoint / at-rest, forward secrecy, PCS

Two properties an attacker who briefly compromises a device should *not* get,
**now for files as well as text**:

- **Forward secrecy:** capturing a key (or chain state) at time *t* must not
  decrypt messages — or files — from *before* *t*.
- **Post-compromise security:** after a compromise, once a DH ratchet step
  happens, *future* messages and files must become unreadable to the attacker
  again.

You already have the oracles for text: `tests/test_post_compromise.py` and
`tests/pcs_lifecycle_verify.py`. For files, Experiment 3 in the harness shows the
concrete forward-secrecy contrast (old static key re-derivable vs new random key
not). Run them, and add one explicit adversary case: grab a message key
mid-conversation, advance the ratchet, and assert that key fails to decrypt both
an earlier and a later ciphertext.

```bash
cd chat-e2ee && PYTHONPATH=server python3 -m pytest tests/test_post_compromise.py -v
```

> **Pass:** a stolen key decrypts only its own message — not the ones on either
> side of it, and not a file whose key rode a different ratchet frame. The
> relevant machinery is `kdf_ck` (chain keys are one-way), `_dh_ratchet` (new DH
> secret per step), the deletion of message keys after use, and — for files — the
> random per-file key delivered as a single ratchet frame.

---

## Experiment — metadata (the honest limit)

Even with content perfectly opaque, the relay necessarily learns *routing*: which
nicknames are online, who relayed to whom, message sizes and timings, and — for
files — the filename and size carried in `file_init` and the chunk count.
`server.py` logs exactly this and streams it to the Log screen — it is metadata,
never content or keys. This is not a break; it is the boundary of what E2EE
promises, and a credible evaluation states it plainly alongside the positive
results.

> **Finding:** ChatE2EE hides *what* is said or sent, not *that* two parties
> exchanged something or *how much*. Mitigations (padding, cover traffic,
> sealed-sender, encrypted filenames) are out of scope and belong in future-work.

---

## Writing it up

The verdict the harness and these experiments support: **content secrecy against
the server is real for both text and files, and it rests on one assumption — that
users verify the safety number.** The ratchet, AEAD, and secretstream are sound;
files now deliver their key over the ratchet, so they share its forward secrecy
and post-compromise security; the residual risk is the human key-verification
step and the metadata the relay must see. When you put this into your thesis,
phrase the analysis and conclusions yourself — that is the part that must be your
own writing.
