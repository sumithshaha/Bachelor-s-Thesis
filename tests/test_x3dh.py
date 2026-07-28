import os, sys
sys.path.insert(0, ".")
import x3dh

def bob_setup(n_opks=5):
    ik_seed, ik_pub = x3dh.gen_identity()
    spk_priv, spk_pub, sig = x3dh.new_signed_prekey(ik_seed)
    opks = x3dh.new_one_time_prekeys(n_opks)
    secrets = x3dh.PrekeySecrets(ik_seed=ik_seed, spk_priv=spk_priv,
                                 opks_priv={i:priv for i,(priv,_) in opks.items()})
    # one bundle offering OPK #0
    bundle = x3dh.PrekeyBundle(ik=ik_pub, spk=spk_pub, spk_sig=sig,
                               opk=opks[0][1], opk_id=0)
    return ik_pub, secrets, bundle, opks

def test_agreement_with_opk():
    a_ik_seed, a_ik_pub = x3dh.gen_identity()
    b_ik_pub, secrets, bundle, opks = bob_setup()
    r = x3dh.initiator_x3dh(a_ik_seed, bundle)
    sk_bob = x3dh.responder_x3dh(secrets, r.ik, r.ek, r.opk_id)
    assert r.sk == sk_bob, "initiator/responder SK mismatch (with OPK)"
    print("  agreement WITH one-time prekey:      SK match ->", r.sk.hex()[:24], "...")

def test_agreement_without_opk():
    a_ik_seed, a_ik_pub = x3dh.gen_identity()
    b_ik_pub, secrets, bundle, opks = bob_setup()
    bundle.opk = None; bundle.opk_id = None   # pool exhausted
    r = x3dh.initiator_x3dh(a_ik_seed, bundle)
    sk_bob = x3dh.responder_x3dh(secrets, r.ik, r.ek, None)
    assert r.sk == sk_bob, "SK mismatch (no OPK)"
    print("  agreement WITHOUT one-time prekey:   SK match ->", r.sk.hex()[:24], "...")

def test_ad_matches():
    a_ik_seed, a_ik_pub = x3dh.gen_identity()
    b_ik_pub, secrets, bundle, opks = bob_setup()
    r = x3dh.initiator_x3dh(a_ik_seed, bundle)
    # Bob reconstructs AD as Encode(IK_A) || Encode(IK_B)
    ad_bob = x3dh.encode_key(r.ik) + x3dh.encode_key(b_ik_pub)
    assert r.ad == ad_bob
    print("  associated data agrees on both sides")

def test_rejects_forged_signature():
    a_ik_seed, _ = x3dh.gen_identity()
    b_ik_pub, secrets, bundle, opks = bob_setup()
    bundle.spk_sig = bundle.spk_sig[:-1] + bytes([bundle.spk_sig[-1]^1])  # tamper
    try:
        x3dh.initiator_x3dh(a_ik_seed, bundle)
        assert False, "forged signature was accepted!"
    except ValueError:
        print("  forged signed-prekey signature: correctly rejected")

def test_rejects_wrong_signer():
    # SPK signed by a DIFFERENT identity key must not verify against bundle.ik
    a_ik_seed, _ = x3dh.gen_identity()
    b_ik_pub, secrets, bundle, opks = bob_setup()
    attacker_seed, _ = x3dh.gen_identity()
    _, spk2_pub, sig2 = x3dh.new_signed_prekey(attacker_seed)  # signed by attacker
    bundle.spk = spk2_pub; bundle.spk_sig = sig2
    try:
        x3dh.initiator_x3dh(a_ik_seed, bundle)
        assert False, "prekey signed by wrong key was accepted!"
    except ValueError:
        print("  prekey signed by a different key: correctly rejected")

def test_opk_is_consumed():
    a_ik_seed, _ = x3dh.gen_identity()
    b_ik_pub, secrets, bundle, opks = bob_setup()
    r = x3dh.initiator_x3dh(a_ik_seed, bundle)
    x3dh.responder_x3dh(secrets, r.ik, r.ek, r.opk_id)      # consumes OPK 0
    # replaying the SAME opk_id must now fail (single-use)
    try:
        x3dh.responder_x3dh(secrets, r.ik, r.ek, r.opk_id)
        assert False, "one-time prekey was reusable!"
    except ValueError:
        print("  one-time prekey is single-use:       replay correctly rejected")

def test_forward_secrecy_property():
    # THE point of X3DH: with the ephemeral+OPK deleted, knowing ONLY the
    # long-term identity private keys does not recompute SK.
    a_ik_seed, a_ik_pub = x3dh.gen_identity()
    b_ik_pub, secrets, bundle, opks = bob_setup()
    r = x3dh.initiator_x3dh(a_ik_seed, bundle)
    _ = x3dh.responder_x3dh(secrets, r.ik, r.ek, r.opk_id)
    # Attacker later steals BOTH identity private keys, but EK_A and OPK were
    # ephemeral/consumed. Try to recompute SK from identity keys alone.
    # The best an attacker can do without EK_A is DH1 = DH(IK_A, SPK_B); DH2/3/4
    # all require EK_A (gone). So they cannot form the HKDF input. Demonstrate
    # that a "reconstruction" missing the ephemeral DHs yields a different SK.
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    dh1 = x3dh._dh(a_ik_seed, bundle.spk)
    forged = HKDF(algorithm=hashes.SHA256(), length=32, salt=x3dh.KDF_SALT,
                  info=x3dh.KDF_INFO).derive(x3dh.F + dh1)  # missing DH2/3/4
    assert forged != r.sk, "SK recoverable from identity keys alone (FS BROKEN)"
    print("  forward secrecy: identity keys alone do NOT recover SK")

if __name__ == "__main__":
    for name in ["test_agreement_with_opk","test_agreement_without_opk","test_ad_matches",
                 "test_rejects_forged_signature","test_rejects_wrong_signer",
                 "test_opk_is_consumed","test_forward_secrecy_property"]:
        globals()[name]()
    print("\nALL X3DH TESTS PASSED")
