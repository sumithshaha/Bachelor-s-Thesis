#!/usr/bin/env python3
"""
gen_x3dh_vectors.py -- freeze the X3DH reference into language-neutral vectors.

WHY THIS EXISTS

The C++ client cannot be compiled inside the Python test run, so a C++ X3DH
implementation cannot be checked against tests/x3dh.py the way the ratchet is
checked by run_interop.sh. Without a fixed target, a port is written against a
reading of the reference rather than against its bytes -- and an X3DH that is
subtly wrong does not fail loudly. It produces a shared secret that differs from
the peer's, which surfaces much later as an undecryptable first message and is
very hard to attribute.

These vectors remove the guesswork. Every value below is derived from FIXED
keys, so the whole agreement is deterministic and can be reproduced in any
language. A C++ port is correct exactly when it reproduces `sk` byte for byte
for each case.

WHAT IS AND IS NOT DETERMINISTIC

  * SK derivation is fully deterministic given the keys: the four DHs and the
    HKDF have no randomness. These are the vectors that matter.
  * XEdDSA SIGNING is randomised (a 64-byte nonce Z), so a signature cannot be
    frozen as an expected output. VERIFICATION is deterministic, so a fixed
    signature is included for the port to verify, plus a corrupted one it must
    reject.

A NOTE THE PORT AUTHOR MUST READ

tests/x3dh.py implements XEdDSA with its own Ed25519 arithmetic and says so:
"not claimed to be byte-compatible with any other XEdDSA implementation". A C++
port therefore CANNOT use a stock library signature routine and expect a match --
libsodium's crypto_sign is RFC 8032 Ed25519, which is a different construction
from this hash_1 prefix and sign-bit convention. Either port this file's
arithmetic exactly (using crypto_core_ed25519_* from libsodium 1.0.20), or
change BOTH sides to a standard scheme. The signature vectors below exist to
make that decision testable rather than assumed.
"""
from __future__ import annotations

import binascii
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from x3dh import (  # noqa: E402
    PrekeyBundle,
    PrekeySecrets,
    _dh,
    _kdf,
    _pub_from_priv,
    encode_key,
    identity_public,
    identity_to_x25519_private,
    identity_to_x25519_public,
    initiator_x3dh,
    responder_x3dh,
    sign,
    verify,
    F,
    KDF_INFO,
    KDF_SALT,
)

H = lambda b: binascii.hexlify(b).decode()          # noqa: E731
U = lambda s: binascii.unhexlify(s)                 # noqa: E731

# Fixed private keys. Any 32 bytes are a valid X25519 private key, so these are
# simply chosen to be obvious in a hex dump and are not secret in any sense.
IK_A_SEED = U("a0" * 32)   # Ed25519 identity seed
IK_B_SEED = U("b0" * 32)   # Ed25519 identity seed
SPK_B_PRIV = U("c0" * 32)
OPK_B_PRIV = U("d0" * 32)
EK_A_PRIV = U("e0" * 32)


def _sk_with_fixed_ek(ik_a_x, ek_priv, bundle_ik_x, bundle_spk, bundle_opk):
    """The initiator's SK, computed with a FIXED ephemeral key.

    initiator_x3dh() generates its own ephemeral internally, which is correct
    for real use and useless for a vector. The DH order here mirrors that
    function exactly: DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B),
    DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) when a one-time prekey is used.
    """
    dh = (_dh(ik_a_x, bundle_spk)
          + _dh(ek_priv, bundle_ik_x)
          + _dh(ek_priv, bundle_spk))
    if bundle_opk is not None:
        dh += _dh(ek_priv, bundle_opk)
    return _kdf(dh)


def build():
    ik_a_pub = identity_public(IK_A_SEED)          # Ed25519 public
    ik_b_pub = identity_public(IK_B_SEED)          # Ed25519 public
    ik_a_x = identity_to_x25519_private(IK_A_SEED)
    ik_b_x = identity_to_x25519_public(ik_b_pub)
    spk_b_pub = _pub_from_priv(SPK_B_PRIV)
    opk_b_pub = _pub_from_priv(OPK_B_PRIV)
    ek_a_pub = _pub_from_priv(EK_A_PRIV)

    sk_with_opk = _sk_with_fixed_ek(ik_a_x, EK_A_PRIV,
                                    ik_b_x, spk_b_pub, opk_b_pub)
    sk_no_opk = _sk_with_fixed_ek(ik_a_x, EK_A_PRIV,
                                  ik_b_x, spk_b_pub, None)

    # A signature the port must VERIFY (signing is randomised, so the bytes are
    # frozen here rather than expected as output), and the same signature with
    # one bit flipped, which the port must REJECT.
    sig = sign(IK_B_SEED, spk_b_pub)
    bad = bytearray(sig)
    bad[0] ^= 0x01

    return {
        "description": "X3DH conformance vectors for the ChatE2EE C++ port. "
                       "A port is correct when it reproduces every `sk` "
                       "byte for byte from the given private keys.",
        "constants": {
            "F": H(F),
            "kdf_salt": H(KDF_SALT),
            "kdf_info": KDF_INFO.decode(),
            "kdf": "HKDF-SHA256, length 32, over F || DH1 || DH2 || DH3 [|| DH4]",
            "dh_order": ["DH(IK_A, SPK_B)", "DH(EK_A, IK_B)",
                         "DH(EK_A, SPK_B)", "DH(EK_A, OPK_B) if OPK offered"],
        },
        "identity_seeds": {"ik_a": H(IK_A_SEED), "ik_b": H(IK_B_SEED)},
        # The birational map has two halves. Storing both, for both identities,
        # keeps a port from having to guess which one a field holds.
        "derived_x25519_priv": {
            "ik_a": H(identity_to_x25519_private(IK_A_SEED)),
            "ik_b": H(identity_to_x25519_private(IK_B_SEED)),
        },
        "derived_x25519_pub": {
            "ik_a": H(identity_to_x25519_public(ik_a_pub)),
            "ik_b": H(identity_to_x25519_public(ik_b_pub)),
        },
        "private_keys": {
            "spk_b": H(SPK_B_PRIV), "opk_b": H(OPK_B_PRIV),
            "ek_a": H(EK_A_PRIV),
        },
        "public_keys": {
            "ik_a": H(ik_a_pub), "ik_b": H(ik_b_pub),
            "spk_b": H(spk_b_pub), "opk_b": H(opk_b_pub),
            "ek_a": H(ek_a_pub),
        },
        "cases": [
            {"name": "with_one_time_prekey", "opk": True, "sk": H(sk_with_opk)},
            {"name": "without_one_time_prekey", "opk": False, "sk": H(sk_no_opk)},
        ],
        "associated_data": {
            "definition": "Encode(IK_A) || Encode(IK_B), raw 32-byte publics",
            "value": H(encode_key(ik_a_pub) + encode_key(ik_b_pub)),
        },
        "signature": {
            "scheme": "RFC 8032 Ed25519, detached. Byte-identical to "
                      "libsodium crypto_sign_detached and to cryptography's "
                      "Ed25519PrivateKey.sign for the same seed and message. "
                      "Ed25519 signing IS deterministic, so unlike the previous "
                      "XEdDSA scheme this signature is a reproducible OUTPUT, "
                      "not merely something to verify.",
            "signer_seed": H(IK_B_SEED),
            "signer_public_key": H(ik_b_pub),
            "message": H(spk_b_pub),
            "valid_signature": H(sig),
            "corrupted_signature_must_reject": H(bytes(bad)),
        },
    }


if __name__ == "__main__":
    vec = build()

    # Self-check before writing: the frozen SKs must agree with what the real
    # initiator/responder functions produce, and the two roles must agree with
    # each other. A vector file that does not match its own reference is worse
    # than none, because a port would be validated against a fiction.
    ik_b_pub = U(vec["public_keys"]["ik_b"])
    spk_b_pub = U(vec["public_keys"]["spk_b"])
    opk_b_pub = U(vec["public_keys"]["opk_b"])
    ek_a_pub = U(vec["public_keys"]["ek_a"])
    ik_a_pub = U(vec["public_keys"]["ik_a"])

    secrets = PrekeySecrets(ik_seed=IK_B_SEED, spk_priv=SPK_B_PRIV,
                            opks_priv={7: OPK_B_PRIV})

    resp_with = responder_x3dh(secrets, ik_a_pub, ek_a_pub, 7)
    assert H(resp_with) == vec["cases"][0]["sk"], "responder disagrees (with OPK)"

    secrets2 = PrekeySecrets(ik_seed=IK_B_SEED, spk_priv=SPK_B_PRIV, opks_priv={})
    resp_without = responder_x3dh(secrets2, ik_a_pub, ek_a_pub, None)
    assert H(resp_without) == vec["cases"][1]["sk"], "responder disagrees (no OPK)"

    # And a full live round trip with a random ephemeral, to prove the frozen
    # vectors describe the same agreement the real API performs.
    bundle = PrekeyBundle(ik=ik_b_pub, spk=spk_b_pub,
                          spk_sig=sign(IK_B_SEED, spk_b_pub),
                          opk=opk_b_pub, opk_id=7)
    res = initiator_x3dh(IK_A_SEED, bundle)
    live = responder_x3dh(
        PrekeySecrets(ik_seed=IK_B_SEED, spk_priv=SPK_B_PRIV,
                      opks_priv={7: OPK_B_PRIV}),
        res.ik, res.ek, res.opk_id)
    assert res.sk == live, "live initiator/responder disagree"

    assert verify(ik_b_pub, spk_b_pub, U(vec["signature"]["valid_signature"]))
    assert sign(IK_B_SEED, spk_b_pub) == U(vec["signature"]["valid_signature"]), \
        "Ed25519 is deterministic: re-signing must reproduce the frozen bytes"
    assert not verify(
        ik_b_pub, spk_b_pub, U(vec["signature"]["corrupted_signature_must_reject"]))

    out = os.path.join(os.path.dirname(__file__), "x3dh_vectors.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(vec, f, indent=2, sort_keys=False)
        f.write("\n")
    print("self-check passed; wrote", out)
