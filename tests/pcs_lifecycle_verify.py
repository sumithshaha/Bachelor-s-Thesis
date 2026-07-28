"""
Verify that a FORCED rekey round-trip on session resumption reestablishes
post-compromise security across the three lifecycle events Sumith asked about
(user switching / screen lock / logging out), using the project's OWN reference
ratchet crypto_core.py (which mirrors the C++ CryptoBox byte-for-byte).

Threat model: an attacker CAPTURES Alice's full ratchet State at time T (the
compromise). Thereafter the attacker passively derives Alice's SENDING-chain
message keys and tries to read every message Alice sends. PCS is "reestablished"
the instant Alice's sending chain is re-rooted on a fresh DH keypair the attacker
never saw -- at which point the attacker can no longer derive the message key.

A lifecycle event (logout->login restore, screen-lock, background->resume) is
modelled as pickling Alice's State and reloading it byte-identically -- exactly
what persistAllSessions()/restoreAllSessions() and the per-user session blob do.
The restored chain is the SAME chain, so on its own it grants NO healing. The fix
under test fires ONE rekey ping->pong round-trip right after the resumption.
"""
import os, pickle, sys
import crypto_core as cc

def attacker_capture(alice):
    """Snapshot exactly what a state compromise gives: Alice's send-chain key,
    her current ratchet public key, send counter, and cipher policy."""
    return {"CKs": alice.CKs, "DHs_pub": alice.DHs_pub, "Ns": alice.Ns}

def attacker_try_read(cap, header, nonce, ct):
    """Passively derive Alice's send-chain message key and attempt decryption.
    Returns True if the attacker can still read it (PCS NOT yet healed)."""
    if header["dh"] != cap["DHs_pub"]:
        # Alice re-rooted her sending chain on a NEW ratchet key the attacker
        # never captured -> the attacker cannot derive this message's key.
        return False
    # Same ratchet key as at capture: advance the copied chain in lockstep.
    ck = cap["CKs"]
    n_target = header["n"]
    # Fast-forward the copied chain to this message index, then take its key.
    # (kdf_ck is deterministic, so the attacker stays perfectly in step.)
    ck_local = cap["CKs"]
    for i in range(cap["Ns"], n_target + 1):
        ck_local, mk = cc.kdf_ck(ck_local)
    cap["CKs"] = ck_local
    cap["Ns"] = n_target + 1
    ad = cc._ad(header["cipher"], header["dh"], header["pn"], header["n"])
    try:
        cc._aead_decrypt(header["cipher"], mk, nonce, ct, ad)
        return True
    except Exception:
        return False

def establish():
    """Deterministic-initiator handshake, matching the C++ role rule."""
    a_id = cc.Identity.generate()
    b_id = cc.Identity.generate()
    # Alice is the initiator (sends first); Bob is the responder.
    sk_a = cc.bootstrap_sk(a_id.private_bytes(), b_id.public_bytes())
    sk_b = cc.bootstrap_sk(b_id.private_bytes(), a_id.public_bytes())
    assert sk_a == sk_b, "shared secret mismatch"
    alice = cc.init_alice(sk_a, b_id.public_bytes())
    bob   = cc.init_bob(sk_b, b_id.private_bytes(), b_id.public_bytes())
    return alice, bob

def a_to_b(alice, bob, text):
    h, nonce, ct = cc.ratchet_encrypt(alice, text.encode())
    pt = cc.ratchet_decrypt(bob, h, nonce, ct)
    assert pt == text.encode()
    return h, nonce, ct

def rekey_round_trip(alice, bob):
    """One ping->pong, exactly as chatclient transmitRekey + the receive-side
    auto-pong do: Alice pings, Bob decrypts+pongs, Alice decrypts the pong."""
    # ping (Alice -> Bob): ordinary ratchet frame, swallowed by Bob
    hp, np_, cp = cc.ratchet_encrypt(alice, b"\x01__chate2ee_rekey_ping__")
    cc.ratchet_decrypt(bob, hp, np_, cp)          # Bob swallows, advances CKr
    # pong (Bob -> Alice): ordinary ratchet frame, swallowed by Alice
    hq, nq, cq = cc.ratchet_encrypt(bob, b"\x01__chate2ee_rekey_pong__")
    cc.ratchet_decrypt(alice, hq, nq, cq)         # Alice DH-ratchets here
    return True

def lifecycle_restore(state):
    """persist -> (process gone) -> restore: byte-identical chain resurrected."""
    return pickle.loads(pickle.dumps(state))

def run_scenario(name, do_heal, msgs_before=20, msgs_after=10, one_way=True):
    alice, bob = establish()
    # Warm the channel. One-way (the hard case) unless one_way=False.
    for i in range(3):
        a_to_b(alice, bob, f"warm {i}")
        if not one_way:
            # Bob occasionally replies (two-way) -- makes healing even easier.
            hb, nb, cb = cc.ratchet_encrypt(bob, f"reply {i}".encode())
            cc.ratchet_decrypt(alice, hb, nb, cb)

    # ---- COMPROMISE: attacker captures Alice's state right here (time T) ----
    for i in range(msgs_before):
        a_to_b(alice, bob, f"pre {i}")
    cap = attacker_capture(alice)

    # ---- LIFECYCLE EVENT: pickle + restore the SAME chain (lock/switch/logout)
    alice = lifecycle_restore(alice)
    bob   = lifecycle_restore(bob)

    # ---- THE FIX UNDER TEST: force a rekey round-trip on resumption ----
    if do_heal:
        rekey_round_trip(alice, bob)

    # ---- Post-resumption traffic; can the attacker still read Alice's sends? --
    read_after_heal = 0
    for i in range(msgs_after):
        h, nonce, ct = cc.ratchet_encrypt(alice, f"post {i}".encode())
        cc.ratchet_decrypt(bob, h, nonce, ct)     # Bob still decrypts fine
        if attacker_try_read(cap, h, nonce, ct):
            read_after_heal += 1

    healed = (read_after_heal == 0)
    status = "HEALED (attacker locked out)" if healed else \
             f"STILL COMPROMISED (attacker read {read_after_heal}/{msgs_after})"
    print(f"  [{'PASS' if (healed == do_heal) else 'FAIL'}] {name}: {status}")
    return healed == do_heal

if __name__ == "__main__":
    print("Reference ratchet:", cc.__file__)
    print("Cipher policy:", cc.select_cipher())
    print()
    ok = True
    print("BASELINE (no resume-heal) -- a same-chain resumption must NOT heal:")
    ok &= run_scenario("logout->login (restore only)", do_heal=False)
    print()
    print("WITH resume-heal (the fix) -- must reestablish PCS after each event:")
    ok &= run_scenario("user switch / same-user re-login", do_heal=True)
    ok &= run_scenario("screen lock -> unlock",            do_heal=True)
    ok &= run_scenario("Android background -> resume",     do_heal=True)
    ok &= run_scenario("two-way conversation resume",      do_heal=True, one_way=False)
    print()
    # Stress: many independent sessions, random burst sizes, one-way + two-way.
    import random
    random.seed(1234)
    trials = 400
    passed = 0
    for t in range(trials):
        r = run_scenario.__wrapped__ if hasattr(run_scenario, "__wrapped__") else run_scenario
        before = random.randint(1, 40)
        after  = random.randint(1, 20)
        ow     = random.random() < 0.5
        # capture output silently by redirecting
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            good = run_scenario(f"trial{t}", do_heal=True, msgs_before=before,
                                msgs_after=after, one_way=ow)
        passed += 1 if good else 0
    print(f"STRESS: {passed}/{trials} randomized resume-heal trials reestablished PCS")
    ok &= (passed == trials)
    print()
    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
    sys.exit(0 if ok else 1)
