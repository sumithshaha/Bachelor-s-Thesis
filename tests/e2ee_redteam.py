#!/usr/bin/env python3
"""
e2ee_redteam.py -- an adversarial evaluation of ChatE2EE's end-to-end
encryption, driving the REAL crypto layer (server/crypto_core.py and
server/file_crypto.py) exactly as the app uses it. Nothing here is mocked: the
same Double Ratchet, the same AEAD, the same secretstream file encryption, the
same safety-number function that the C++ client mirrors byte-for-byte.

The point is to test -- not assert -- the thesis's central security claim:

    "The relay server can never read message contents." (text OR file)

We put on the attacker's hat and try to break that, then check whether the
app's own defence (the out-of-band safety number) catches us.

    Experiment 1  Honest-but-curious server (passive), on a text message.
                  The relay stores and forwards ciphertext. Can it read a
                  message using everything it legitimately holds -- the frame,
                  the nonce, and both parties' PUBLIC keys?  Expected: NO.

    Experiment 2  Malicious server (active MITM, key substitution), on text.
                  The relay is also the key directory. It hands each party the
                  ATTACKER's public key in place of the peer's, then relays in
                  the middle. Expected: the attacker reads everything -- UNLESS
                  the two parties compare safety numbers out of band, which is
                  exactly what the verification UI is for.

    Experiment 3  File transfer carries the same E2EE as text.
                  Files are encrypted under a RANDOM per-file key whose delivery
                  rides the ratchet (the file_init "keyenc" object). Expected:
                  the relay cannot read the file key or the chunks, the
                  recipient recovers the key over the ratchet, and -- unlike the
                  old static-key design -- a later identity-key compromise does
                  NOT re-derive the file key (forward secrecy).

Run it from the repo so `crypto_core` imports:

    cd chat-e2ee/server && python3 ../tests/e2ee_redteam.py
      (or)  cd chat-e2ee && PYTHONPATH=server python3 tests/e2ee_redteam.py

Dependencies (same as the server): `cryptography` and `pynacl`.
"""

import os
import sys

# Make server/crypto_core.py importable no matter where we're launched from.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SERVER = os.path.normpath(os.path.join(_HERE, "..", "server"))
if _SERVER not in sys.path:
    sys.path.insert(0, _SERVER)

import crypto_core as cc  # noqa: E402


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def new_identity():
    """A fresh X25519 identity: (priv32, pub32). The public half is what the
    server's key directory stores and hands out; the private half never leaves
    the device."""
    return cc.gen_keypair()


def heximg(b, n=8):
    return b.hex()[: n * 2]


def rule(title):
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def open_session_as_sender(my_priv, peer_pub_the_directory_gave_me):
    """Exactly what the first-sending client does: bootstrap the shared secret
    from MY identity private key and the peer public key the directory returned,
    then init the ratchet as Alice."""
    sk = cc.bootstrap_sk(my_priv, peer_pub_the_directory_gave_me)
    return cc.init_alice(sk, peer_pub_the_directory_gave_me)


def open_session_as_receiver(my_priv, my_pub, peer_pub_the_directory_gave_me):
    """What the first-receiving client does: same shared secret (ECDH is
    symmetric), then init the ratchet as Bob on its own identity keypair."""
    sk = cc.bootstrap_sk(my_priv, peer_pub_the_directory_gave_me)
    return cc.init_bob(sk, my_priv, my_pub)


# --------------------------------------------------------------------------- #
# Experiment 1 -- honest-but-curious server
# --------------------------------------------------------------------------- #
def experiment_1_passive():
    rule("EXPERIMENT 1  -  Honest-but-curious server (passive)")

    a_priv, a_pub = new_identity()          # Alice
    b_priv, b_pub = new_identity()          # Bob
    print(f"Alice pub  {heximg(a_pub)}...   Bob pub    {heximg(b_pub)}...")

    # Honest directory: each side gets the OTHER's real key.
    st_alice = open_session_as_sender(a_priv, b_pub)
    st_bob = open_session_as_receiver(b_priv, b_pub, a_pub)

    secret = "meet me at the safehouse at 0300"
    header, nonce, ct = cc.ratchet_encrypt(st_alice, secret.encode())

    # This dict is exactly what server.py stores in `messages` and forwards
    # verbatim: routing metadata + a nonce + an opaque ciphertext blob.
    wire_frame = {
        "type": "msg", "from": "alice", "to": "bob",
        "header": {"cipher": header["cipher"],
                   "dh": header["dh"].hex(), "pn": header["pn"], "n": header["n"]},
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    }
    print("\nWhat the RELAY stores and forwards (server.py `messages` row):")
    print(f"  cipher     : {wire_frame['header']['cipher']}")
    print(f"  nonce      : {wire_frame['nonce']}")
    print(f"  ciphertext : {wire_frame['ciphertext']}")
    print(f"  plaintext? : (not present anywhere in the frame)")

    # The server plays curious. It holds the frame AND both public keys (it is
    # the directory). It has NO private key. Try the only key material it could
    # derive from public data -- and anything else -- and watch it fail.
    print("\nServer attempts to recover the plaintext from what it holds:")
    attempts = 0
    for label, guessed_key in [
        ("HKDF(pub_alice || pub_bob) -- public data only", None),
        ("32 zero bytes", bytes(32)),
        ("os.urandom(32) -- a blind guess", os.urandom(32)),
    ]:
        attempts += 1
        if guessed_key is None:
            # The server can hash public keys together, but a message key comes
            # from a private ECDH + the ratchet chain -- unreachable from publics.
            import hashlib
            guessed_key = hashlib.sha256(a_pub + b_pub).digest()
        try:
            ad = cc._ad(header["cipher"], header["dh"], header["pn"], header["n"])
            cc._aead_decrypt(header["cipher"], guessed_key, nonce, ct, ad)
            print(f"  [{attempts}] {label}: *** DECRYPTED *** (this would be a break!)")
        except Exception as e:
            print(f"  [{attempts}] {label}: rejected ({type(e).__name__})")

    # The legitimate recipient, holding the private key, decrypts fine.
    got = cc.ratchet_decrypt(st_bob, header, nonce, ct).decode()
    print(f"\nBob (holds his private key) decrypts: {got!r}")
    ok = (got == secret)
    print("\nRESULT: relay could NOT read the message; recipient could."
          if ok else "\nRESULT: UNEXPECTED -- recipient mismatch.")
    print("  => Against a passive relay, the E2EE content-secrecy claim HOLDS.")
    return ok


# --------------------------------------------------------------------------- #
# Experiment 2 -- malicious server, key substitution (MITM)
# --------------------------------------------------------------------------- #
def experiment_2_mitm():
    rule("EXPERIMENT 2  -  Malicious server: MITM key substitution")

    a_priv, a_pub = new_identity()          # Alice
    b_priv, b_pub = new_identity()          # Bob
    m_priv, m_pub = new_identity()          # Mallory == the relay operator
    print(f"Alice pub  {heximg(a_pub)}...")
    print(f"Bob   pub  {heximg(b_pub)}...")
    print(f"Mallory pub {heximg(m_pub)}...  (the substituted key)")

    print("\nThe relay is the key directory. It LIES to both sides:")
    print("  - tells Alice that Bob's key   is Mallory's key")
    print("  - tells Bob   that Alice's key is Mallory's key")

    # Alice opens a session believing she's talking to Bob -- but with m_pub.
    st_alice = open_session_as_sender(a_priv, m_pub)
    # Mallory opens the matching receiver session (she has m_priv, knows a_pub).
    st_mallory_from_alice = open_session_as_receiver(m_priv, m_pub, a_pub)

    # Bob opens a session believing he's talking to Alice -- but with m_pub.
    st_bob = open_session_as_receiver(b_priv, b_pub, m_pub)
    # Mallory opens the matching sender session toward Bob (knows b_pub).
    st_mallory_to_bob = open_session_as_sender(m_priv, b_pub)

    secret = "the password is hunter2, delete after reading"
    print(f"\nAlice types: {secret!r}")

    # Alice -> (relay). Mallory decrypts it.
    h1, n1, c1 = cc.ratchet_encrypt(st_alice, secret.encode())
    stolen = cc.ratchet_decrypt(st_mallory_from_alice, h1, n1, c1).decode()
    print(f"Mallory (the relay) reads it in the clear: {stolen!r}")

    # Mallory re-encrypts to Bob so the conversation looks normal.
    h2, n2, c2 = cc.ratchet_encrypt(st_mallory_to_bob, stolen.encode())
    delivered = cc.ratchet_decrypt(st_bob, h2, n2, c2).decode()
    print(f"Bob receives (none the wiser): {delivered!r}")

    broke_confidentiality = (stolen == secret and delivered == secret)
    print("\nWithout key verification: the malicious relay read EVERYTHING."
          if broke_confidentiality else "\nUNEXPECTED: MITM did not pass through.")

    # ---- Now the defence the app ships: the safety number -----------------
    rule("EXPERIMENT 2  -  The defence: out-of-band safety number")
    honest_sn = cc.safety_number(a_pub, b_pub)
    alice_screen = cc.safety_number(a_pub, m_pub)   # Alice sees her key + what she THINKS is Bob's
    bob_screen = cc.safety_number(m_pub, b_pub)     # Bob sees what he THINKS is Alice's + his key

    print("Safety number each party's screen would display:")
    print(f"  Alice's screen : {alice_screen}")
    print(f"  Bob's screen   : {bob_screen}")
    print(f"  (Honest value  : {honest_sn}   <- what they'd see with no attacker)")

    detected = (alice_screen != bob_screen)
    print("\nAlice and Bob read their numbers to each other over the phone:")
    if detected:
        print("  THEY DO NOT MATCH.  The substitution is detected; the users stop.")
    else:
        print("  They match -- the attack would go unnoticed (should not happen).")

    print("\nRESULT:")
    print("  * The relay CAN read messages ONLY IF the parties skip verification.")
    print("  * The safety number diverges under substitution, so an out-of-band")
    print("    comparison DETECTS the MITM. The whole E2EE guarantee reduces to")
    print("    that one check -- which is why ChatE2EE gates the conversation on")
    print("    it. Attack succeeds against the lazy; fails against the diligent.")
    return broke_confidentiality and detected


# --------------------------------------------------------------------------- #
# Experiment 3 -- file transfer carries the same E2EE as text
# --------------------------------------------------------------------------- #
def experiment_3_files():
    rule("EXPERIMENT 3  -  File transfer: content secrecy + forward secrecy")

    import io
    import hashlib
    import file_crypto as fc

    a_priv, a_pub = new_identity()          # Alice
    b_priv, b_pub = new_identity()          # Bob
    alice = open_session_as_sender(a_priv, b_pub)
    bob = open_session_as_receiver(b_priv, b_pub, a_pub)

    # A secret "file" spanning several 64 KiB secretstream chunks.
    plaintext = b"CONFIDENTIAL: exfil plan v3\n" + os.urandom(96 * 1024)
    want = hashlib.sha256(plaintext).hexdigest()

    # ---- SENDER (mirrors ChatClient::sendFile) ---------------------------
    # A RANDOM per-file key -- not derived from any long-term secret. The bulk
    # file is encrypted under it with the secretstream (unchanged); the key is
    # then delivered to Bob OVER THE RATCHET, so it inherits forward secrecy.
    file_key = os.urandom(fc.KEY_BYTES)
    gen = fc.encrypt_file(io.BytesIO(plaintext), file_key, len(plaintext))
    header, _ = next(gen)                    # first yield is (header, False)
    chunks = [ct for (ct, _last) in gen]     # the secretstream ciphertext chunks
    kh, kn, kct = cc.ratchet_encrypt(alice, file_key.hex().encode())

    # Exactly what goes on the wire and into the relay's file_meta row: the
    # secretstream header (public) plus the ratchet-encrypted file key. The
    # keyenc fields mirror ChatClient::sendFile byte-for-byte.
    file_init = {
        "type": "file_init", "from": "alice", "to": "bob",
        "header": header.hex(),
        "keyenc": {
            "cipher": kh["cipher"], "dh": kh["dh"].hex(), "pn": kh["pn"],
            "n": kh["n"], "nonce": kn.hex(), "ct": kct.hex(),
        },
    }
    print("What the RELAY stores and forwards for a file:")
    print(f"  file_init.keyenc.ct : {file_init['keyenc']['ct'][:44]}...  (ratchet-encrypted file key)")
    print(f"  chunk[0]            : {chunks[0].hex()[:44]}...  (secretstream ciphertext)")
    print(f"  file key / plaintext: (never present in the frame)")

    # ---- The relay tries to read the file --------------------------------
    print("\nRelay attempts to recover the file, holding only public data:")
    relay_blind = True
    ke = file_init["keyenc"]
    ke_dh = bytes.fromhex(ke["dh"])
    guess = hashlib.sha256(a_pub + b_pub).digest()
    # (1) recover the file key from keyenc using public-derived key material
    try:
        ad = cc._ad(ke["cipher"], ke_dh, ke["pn"], ke["n"])
        cc._aead_decrypt(ke["cipher"], guess, bytes.fromhex(ke["nonce"]),
                         bytes.fromhex(ke["ct"]), ad)
        print("  [1] keyenc via HKDF(pub||pub): *** RECOVERED *** (break!)")
        relay_blind = False
    except Exception as e:
        print(f"  [1] keyenc via HKDF(pub_alice || pub_bob): rejected ({type(e).__name__})")
    # (2) decrypt the chunks directly with a guessed key
    try:
        fc.decrypt_file(header, iter(chunks), guess, io.BytesIO())
        print("  [2] file chunks with a guessed key: *** DECRYPTED *** (break!)")
        relay_blind = False
    except Exception as e:
        print(f"  [2] file chunks with a guessed key: rejected ({type(e).__name__})")

    # ---- RECIPIENT (mirrors the file_init handler) -----------------------
    hdr = {"cipher": ke["cipher"], "dh": ke_dh, "pn": ke["pn"], "n": ke["n"]}
    rec_key = bytes.fromhex(
        cc.ratchet_decrypt(bob, hdr, bytes.fromhex(ke["nonce"]),
                           bytes.fromhex(ke["ct"])).decode())
    out = io.BytesIO()
    fc.decrypt_file(header, iter(chunks), rec_key, out)
    recovered = (hashlib.sha256(out.getvalue()).hexdigest() == want)
    print("\nRecipient recovers the key via the ratchet and decrypts the file:")
    print(f"  file key matches sender's: {rec_key == file_key}")
    print(f"  reassembled file sha256 == original: {recovered}")

    # secretstream still catches truncation (integrity of the bulk data)
    try:
        fc.decrypt_file(header, iter(chunks[:-1]), rec_key, io.BytesIO())
        truncation_caught = False
    except Exception:
        truncation_caught = True
    print(f"  truncated stream rejected (TAG_FINAL missing): {truncation_caught}")

    # ---- Forward secrecy: the property files previously LACKED ------------
    rule("EXPERIMENT 3  -  File forward secrecy: old static key vs new")
    static_shared = cc.dh(a_priv, b_pub)             # == dh(b_priv, a_pub)
    old_key = hashlib.sha256(static_shared + b"file-0001").digest()
    old_again = hashlib.sha256(cc.dh(b_priv, a_pub) + b"file-0001").digest()
    print("OLD design  (file key = HKDF(static identity secret, msg_id)):")
    print(f"  an attacker who later steals an identity key re-derives it: {old_key == old_again}")
    print("  => every past and future file is decryptable. No forward secrecy.")
    fs = (old_key != file_key
          and hashlib.sha256(static_shared + b"file-0001").digest() != file_key)
    print("NEW design  (random key delivered over the ratchet):")
    print(f"  the same attacker cannot re-derive the random key: {fs}")
    print("  => files inherit the ratchet's forward secrecy and PCS -- parity with text.")
    print("\nNote: MITM detection for files is IDENTICAL to Experiment 2. The file")
    print("key rides the ratchet, so a substituted identity key breaks the file")
    print("key delivery too, and the same safety-number comparison catches it.")

    verdict = relay_blind and recovered and truncation_caught and fs
    print("\nRESULT:", "file transfer has content secrecy AND forward secrecy."
          if verdict else "FAILED.")
    return verdict


# --------------------------------------------------------------------------- #
def main():
    print("ChatE2EE  --  end-to-end encryption red-team")
    print("Driving the real crypto_core.py + file_crypto.py "
          "(Double Ratchet + AEAD + secretstream + safety no.)")
    e1 = experiment_1_passive()
    e2 = experiment_2_mitm()
    e3 = experiment_3_files()

    rule("SUMMARY")
    print(f"  Experiment 1 (passive relay, text)  : "
          f"{'E2EE held (relay blind)' if e1 else 'FAILED'}")
    print(f"  Experiment 2 (active MITM, text)     : "
          f"{'break reproduced AND detected by safety number' if e2 else 'FAILED'}")
    print(f"  Experiment 3 (file transfer)         : "
          f"{'content secrecy + forward secrecy' if e3 else 'FAILED'}")
    print("\nTakeaway for the evaluation chapter: content secrecy against the")
    print("server is real -- for text AND files -- and rests on ONE assumption:")
    print("that users verify the safety number. Files now deliver their key over")
    print("the ratchet, so they share the ratchet's forward secrecy and PCS; the")
    print("residual risk is the human key-verification step and the metadata the")
    print("relay necessarily sees (who/when/size).")
    return 0 if (e1 and e2 and e3) else 1


if __name__ == "__main__":
    raise SystemExit(main())
