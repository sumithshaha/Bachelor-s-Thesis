"""
test_x3dh_vectors.py -- pin the X3DH reference to its frozen vectors.

tests/x3dh.py is the specification the C++ client will be ported from. A port is
checked by reproducing the shared secrets in tests/x3dh_vectors.json byte for
byte, so those vectors are only meaningful while the reference still produces
them. If someone edits x3dh.py -- reorders the DHs, changes the info string,
alters the F prefix -- every one of these tests fails, which is the point: the
port's target must not move silently underneath it.

Regenerate deliberately with `python tests/gen_x3dh_vectors.py`, and expect the
C++ side to be re-verified when you do.
"""
from __future__ import annotations

import binascii
import json
import os

import pytest

from x3dh import (
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

_HERE = os.path.dirname(__file__)
_U = binascii.unhexlify
_H = lambda b: binascii.hexlify(b).decode()          # noqa: E731


@pytest.fixture(scope="module")
def vec():
    path = os.path.join(_HERE, "x3dh_vectors.json")
    assert os.path.exists(path), (
        "x3dh_vectors.json is missing; run `python tests/gen_x3dh_vectors.py`")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------- #
# The constants a port has to match before any DH is even attempted
# --------------------------------------------------------------------------- #
def test_constants_match_the_reference(vec):
    assert _U(vec["constants"]["F"]) == F
    assert _U(vec["constants"]["kdf_salt"]) == KDF_SALT
    assert vec["constants"]["kdf_info"].encode() == KDF_INFO


def test_x25519_public_keys_derive_from_their_private_keys(vec):
    for name, priv in vec["private_keys"].items():
        assert _H(_pub_from_priv(_U(priv))) == vec["public_keys"][name], name


def test_identity_publics_derive_from_their_seeds(vec):
    for name, seed in vec["identity_seeds"].items():
        assert _H(identity_public(_U(seed))) == vec["public_keys"][name], name


def test_ed25519_to_x25519_conversion_is_consistent(vec):
    """The private and public halves of the birational map must land on the same
    X25519 keypair. If they did not, one side of every DH would be wrong."""
    for name in ("ik_a", "ik_b"):
        seed = _U(vec["identity_seeds"][name])
        x_priv = identity_to_x25519_private(seed)
        x_pub = identity_to_x25519_public(_U(vec["public_keys"][name]))
        assert _H(x_priv) == vec["derived_x25519_priv"][name], name
        assert _H(x_pub) == vec["derived_x25519_pub"][name], name
        # The two halves must agree: the public derived from the Ed25519 public
        # must equal the public of the private derived from the seed.
        assert _pub_from_priv(x_priv) == x_pub, name


def test_a_non_ed25519_public_key_is_rejected(vec):
    """A bundle carrying a malformed identity must fail conversion rather than
    silently producing some other point."""
    with pytest.raises(ValueError):
        identity_to_x25519_public(b"\x00" * 31)


# --------------------------------------------------------------------------- #
# The shared secret: the values a C++ port must reproduce
# --------------------------------------------------------------------------- #
def _sk(vec, with_opk: bool) -> bytes:
    p, q = vec["private_keys"], vec["public_keys"]
    xs, xp = vec["derived_x25519_priv"], vec["derived_x25519_pub"]
    dh = (_dh(_U(xs["ik_a"]), _U(q["spk_b"]))
          + _dh(_U(p["ek_a"]), _U(xp["ik_b"]))
          + _dh(_U(p["ek_a"]), _U(q["spk_b"])))
    if with_opk:
        dh += _dh(_U(p["ek_a"]), _U(q["opk_b"]))
    return _kdf(dh)


@pytest.mark.parametrize("case_index,with_opk", [(0, True), (1, False)])
def test_initiator_shared_secret_matches_vector(vec, case_index, with_opk):
    case = vec["cases"][case_index]
    assert case["opk"] is with_opk
    assert _H(_sk(vec, with_opk)) == case["sk"], case["name"]


@pytest.mark.parametrize("case_index,opk_id", [(0, 7), (1, None)])
def test_responder_derives_the_same_secret(vec, case_index, opk_id):
    p, q = vec["private_keys"], vec["public_keys"]
    secrets = PrekeySecrets(
        ik_seed=_U(vec["identity_seeds"]["ik_b"]), spk_priv=_U(p["spk_b"]),
        opks_priv={7: _U(p["opk_b"])} if opk_id is not None else {})
    got = responder_x3dh(secrets, _U(q["ik_a"]), _U(q["ek_a"]), opk_id)
    assert _H(got) == vec["cases"][case_index]["sk"]


def test_the_two_cases_differ(vec):
    """Offering a one-time prekey must change the secret; if it did not, DH4
    would be contributing nothing and the pool would be decorative."""
    assert vec["cases"][0]["sk"] != vec["cases"][1]["sk"]


def test_associated_data_is_the_two_identity_keys(vec):
    q = vec["public_keys"]
    ad = encode_key(_U(q["ik_a"])) + encode_key(_U(q["ik_b"]))
    assert _H(ad) == vec["associated_data"]["value"]
    assert len(ad) == 64


# --------------------------------------------------------------------------- #
# Signature verification (signing is randomised, so only verify is pinned)
# --------------------------------------------------------------------------- #
def test_frozen_signature_verifies(vec):
    x = vec["signature"]
    assert verify(_U(x["signer_public_key"]), _U(x["message"]),
                  _U(x["valid_signature"]))


def test_signing_is_deterministic_and_reproduces_the_frozen_bytes(vec):
    """RFC 8032 Ed25519 has no signing nonce, so a correct C++ port must emit
    these exact bytes -- not merely verify them. This is the property the old
    XEdDSA scheme lacked, and it is what makes the signature a testable output."""
    x = vec["signature"]
    assert _H(sign(_U(x["signer_seed"]), _U(x["message"]))) == x["valid_signature"]


def test_corrupted_signature_is_rejected(vec):
    x = vec["signature"]
    assert not verify(_U(x["signer_public_key"]), _U(x["message"]),
                             _U(x["corrupted_signature_must_reject"]))


def test_signature_from_a_different_key_is_rejected(vec):
    """The whole point of signing the prekey: a bundle assembled by the relay,
    or by anyone other than the identity keyholder, must not verify."""
    p, q = vec["private_keys"], vec["public_keys"]
    forged = sign(_U(vec["identity_seeds"]["ik_a"]), _U(q["spk_b"]))  # A, not B
    assert not verify(_U(q["ik_b"]), _U(q["spk_b"]), forged)


def test_initiator_rejects_a_bundle_with_a_bad_signature(vec):
    p, q = vec["private_keys"], vec["public_keys"]
    bundle = PrekeyBundle(ik=_U(q["ik_b"]), spk=_U(q["spk_b"]),
                          spk_sig=_U(vec["signature"]["corrupted_signature_must_reject"]),
                          opk=_U(q["opk_b"]), opk_id=7)
    with pytest.raises(ValueError):
        initiator_x3dh(_U(vec["identity_seeds"]["ik_a"]), bundle)


# --------------------------------------------------------------------------- #
# A live round trip, to prove the frozen vectors describe the real API
# --------------------------------------------------------------------------- #
def test_live_round_trip_agrees(vec):
    p, q = vec["private_keys"], vec["public_keys"]
    bundle = PrekeyBundle(ik=_U(q["ik_b"]), spk=_U(q["spk_b"]),
                          spk_sig=sign(_U(vec["identity_seeds"]["ik_b"]), _U(q["spk_b"])),
                          opk=_U(q["opk_b"]), opk_id=7)
    res = initiator_x3dh(_U(vec["identity_seeds"]["ik_a"]), bundle)
    secrets = PrekeySecrets(ik_seed=_U(vec["identity_seeds"]["ik_b"]),
                            spk_priv=_U(p["spk_b"]),
                            opks_priv={7: _U(p["opk_b"])})
    assert responder_x3dh(secrets, res.ik, res.ek, res.opk_id) == res.sk


def test_one_time_prekey_is_single_use(vec):
    """A replayed opk_id must fail rather than silently derive a second time --
    reuse would hand two sessions the same DH4 contribution."""
    p, q = vec["private_keys"], vec["public_keys"]
    secrets = PrekeySecrets(ik_seed=_U(vec["identity_seeds"]["ik_b"]),
                            spk_priv=_U(p["spk_b"]),
                            opks_priv={7: _U(p["opk_b"])})
    responder_x3dh(secrets, _U(q["ik_a"]), _U(q["ek_a"]), 7)
    with pytest.raises(ValueError):
        responder_x3dh(secrets, _U(q["ik_a"]), _U(q["ek_a"]), 7)
