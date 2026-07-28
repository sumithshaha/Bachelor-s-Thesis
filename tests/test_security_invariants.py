"""
Security-invariant tests for the canonical Double Ratchet (server/crypto_core.py).

These do not test "does it encrypt and decrypt" -- a ratchet with no security at
all passes that. Each test names one guarantee and is written to FAIL if that
guarantee is missing:

  * forward secrecy        -- state captured AFTER a message cannot read a
                              message sent BEFORE it (past traffic stays safe
                              even if the device is later seized).
  * post-compromise sec.   -- state captured at an instant cannot read messages
                              sent after fresh DH ratchet steps (the session
                              heals itself once new DH secrets are mixed in).
  * header authentication  -- the AEAD tag binds the header (dh / pn / n), so
                              flipping any of them is rejected, not silently
                              accepted on the wrong chain.
  * ciphertext integrity   -- flipping a ciphertext or nonce byte is rejected.
  * cross-session isolation-- a frame from one conversation cannot be decrypted
                              by an unrelated conversation.

`test_checks_have_teeth` deliberately feeds an UNtampered frame and asserts it
succeeds, so the negative tests above are known to be exercising a live path and
not passing vacuously.

Pure Python: needs `cryptography` and `pynacl`.
"""
import copy
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "server"))
import crypto_core as cc  # noqa: E402
from crypto_core import CIPHER_AES, CIPHER_XCHACHA  # noqa: E402
from nacl.exceptions import CryptoError  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402

AEAD_FAIL = (CryptoError, InvalidTag, ValueError)
BOTH_CIPHERS = [CIPHER_AES, CIPHER_XCHACHA]


def _fresh_pair():
    a_priv, a_pub = cc.gen_keypair()
    b_priv, b_pub = cc.gen_keypair()
    alice = cc.init_alice(cc.bootstrap_sk(a_priv, b_pub), b_pub)
    bob = cc.init_bob(cc.bootstrap_sk(b_priv, a_pub), b_priv, b_pub)
    return alice, bob


def _flip(b: bytes, i: int = 0) -> bytes:
    ba = bytearray(b)
    ba[i] ^= 0x01
    return bytes(ba)


# --------------------------------------------------------------------------- #
# Forward secrecy
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_forward_secrecy_state_after_cannot_read_before(cipher):
    """Bob reads m0, m1, m2 in order; a snapshot of Bob taken AFTER m2 can no
    longer read m0. If message keys were retained (no forward secrecy) this
    would wrongly succeed."""
    alice, bob = _fresh_pair()
    frames = [cc.ratchet_encrypt(alice, f"m{i}".encode(), cipher=cipher) for i in range(3)]
    for header, nonce, ct in frames:
        cc.ratchet_decrypt(bob, header, nonce, ct)

    bob_after = cc.snapshot(bob)          # attacker seizes the device here
    h0, n0, c0 = frames[0]
    with pytest.raises(AEAD_FAIL):
        cc.ratchet_decrypt(bob_after, h0, n0, c0)


# --------------------------------------------------------------------------- #
# Post-compromise security
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_post_compromise_snapshot_cannot_read_after_heal(cipher):
    """Bob's entire state is stolen at time t. After several fresh DH ratchet
    round-trips, Alice sends a message the real Bob reads -- but the stolen
    snapshot cannot, because the new chain is rooted in DH secrets generated
    after the compromise."""
    alice, bob = _fresh_pair()
    h, n, c = cc.ratchet_encrypt(alice, b"hello", cipher=cipher)
    cc.ratchet_decrypt(bob, h, n, c)

    stolen = cc.snapshot(bob)             # full compromise of Bob

    # Heal: several complete round-trips, each mixing in fresh DH material.
    for _ in range(3):
        h, n, c = cc.ratchet_encrypt(bob, b"b->a", cipher=cipher)
        cc.ratchet_decrypt(alice, h, n, c)
        h, n, c = cc.ratchet_encrypt(alice, b"a->b", cipher=cipher)
        cc.ratchet_decrypt(bob, h, n, c)

    # A message sent after the heal.
    h, n, c = cc.ratchet_encrypt(alice, b"SECRET after heal", cipher=cipher)
    assert cc.ratchet_decrypt(bob, h, n, c) == b"SECRET after heal"   # real Bob reads it

    with pytest.raises(AEAD_FAIL):        # the thief's stale state cannot
        cc.ratchet_decrypt(copy.deepcopy(stolen), h, n, c)


# --------------------------------------------------------------------------- #
# Header authentication (the AEAD tag binds dh / pn / n)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field", ["dh", "pn", "n"])
@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_header_field_tamper_is_rejected(field, cipher):
    """Flipping an authenticated header field must be rejected -- otherwise a
    relay could redirect a frame onto the wrong chain or replay position."""
    alice, bob = _fresh_pair()
    header, nonce, ct = cc.ratchet_encrypt(alice, b"authentic", cipher=cipher)
    bad = dict(header)
    if field == "dh":
        bad["dh"] = _flip(header["dh"])
    else:
        bad[field] = header[field] + 1
    with pytest.raises(AEAD_FAIL):
        cc.ratchet_decrypt(bob, bad, nonce, ct)


# --------------------------------------------------------------------------- #
# Ciphertext / nonce integrity
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("what", ["ct", "nonce"])
@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_ciphertext_or_nonce_tamper_is_rejected(what, cipher):
    alice, bob = _fresh_pair()
    header, nonce, ct = cc.ratchet_encrypt(alice, b"do not touch", cipher=cipher)
    if what == "ct":
        ct = _flip(ct)
    else:
        nonce = _flip(nonce)
    with pytest.raises(AEAD_FAIL):
        cc.ratchet_decrypt(bob, header, nonce, ct)


# --------------------------------------------------------------------------- #
# Cross-session isolation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_cross_session_isolation(cipher):
    """A frame from one conversation is meaningless to an unrelated one -- keys
    are per-session, not global."""
    _, bob_other = _fresh_pair()
    alice, _ = _fresh_pair()
    header, nonce, ct = cc.ratchet_encrypt(alice, b"for my own peer", cipher=cipher)
    with pytest.raises(AEAD_FAIL):
        cc.ratchet_decrypt(bob_other, header, nonce, ct)


# --------------------------------------------------------------------------- #
# Meta: the negative tests are not vacuous
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_checks_have_teeth(cipher):
    """An UNtampered frame on the right session decrypts -- proving the failures
    above come from the tampering, not from a path that always raises."""
    alice, bob = _fresh_pair()
    header, nonce, ct = cc.ratchet_encrypt(alice, b"genuine", cipher=cipher)
    assert cc.ratchet_decrypt(bob, header, nonce, ct) == b"genuine"
