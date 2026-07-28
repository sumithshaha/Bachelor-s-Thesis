"""
Tests for the cryptographic core.

These tests do three things:

  1. Prove the happy path: a message encrypted for a peer round-trips back to
     the original plaintext.
  2. Prove the integrity guarantee: tampering with a single byte of the
     ciphertext causes decryption to fail loudly instead of returning garbage.
  3. Check our X25519 implementation against the official test vector from
     RFC 7748, so we know we are computing the same curve operation the rest
     of the world is.

Run with:  pytest -v test_crypto.py
"""

import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

# Make the server package importable when tests run from the tests/ folder.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from crypto_core import (  # noqa: E402
    Identity,
    Envelope,
    derive_shared_key,
    encrypt,
    decrypt,
)


def test_two_parties_derive_the_same_key():
    """The whole scheme rests on this: Alice and Bob, starting from different
    private keys, must arrive at an identical shared key."""
    alice = Identity.generate()
    bob = Identity.generate()

    key_a = derive_shared_key(alice, bob.public_bytes())
    key_b = derive_shared_key(bob, alice.public_bytes())

    assert key_a == key_b
    assert len(key_a) == 32  # 256-bit key for AES-256


def test_message_round_trip():
    alice = Identity.generate()
    bob = Identity.generate()
    key_a = derive_shared_key(alice, bob.public_bytes())
    key_b = derive_shared_key(bob, alice.public_bytes())

    message = "Hei Bob! Tämä on salainen viesti. 🔒"
    envelope = encrypt(key_a, message)
    recovered = decrypt(key_b, envelope)

    assert recovered == message


def test_each_message_has_a_unique_nonce():
    """Encrypting the same text twice must not produce the same ciphertext,
    otherwise an observer could tell that a message was repeated."""
    alice = Identity.generate()
    bob = Identity.generate()
    key = derive_shared_key(alice, bob.public_bytes())

    e1 = encrypt(key, "same text")
    e2 = encrypt(key, "same text")

    assert e1.nonce != e2.nonce
    assert e1.ciphertext != e2.ciphertext


def test_tampering_is_detected():
    """Flip one bit of the ciphertext and decryption must raise, not return
    wrong data. This is the integrity guarantee of AES-GCM."""
    alice = Identity.generate()
    bob = Identity.generate()
    key = derive_shared_key(alice, bob.public_bytes())

    envelope = encrypt(key, "important")
    tampered = bytearray(envelope.ciphertext)
    tampered[0] ^= 0x01  # flip the lowest bit of the first byte
    bad = Envelope(envelope.nonce, bytes(tampered))

    with pytest.raises(InvalidTag):
        decrypt(key, bad)


def test_wrong_key_cannot_decrypt():
    """A third party (Eve) with her own key pair must not be able to read a
    message meant for Bob."""
    alice = Identity.generate()
    bob = Identity.generate()
    eve = Identity.generate()

    key_ab = derive_shared_key(alice, bob.public_bytes())
    envelope = encrypt(key_ab, "for Bob's eyes only")

    key_ae = derive_shared_key(eve, alice.public_bytes())
    with pytest.raises(InvalidTag):
        decrypt(key_ae, envelope)


def test_associated_data_is_authenticated():
    """The sender/recipient names can be bound to the ciphertext as associated
    data. Changing them must break decryption, which stops an attacker from
    re-addressing a captured message."""
    alice = Identity.generate()
    bob = Identity.generate()
    key = derive_shared_key(alice, bob.public_bytes())

    aad = b"alice->bob"
    envelope = encrypt(key, "hello", associated_data=aad)

    # Correct AAD works.
    assert decrypt(key, envelope, associated_data=aad) == "hello"

    # Tampered AAD fails.
    with pytest.raises(InvalidTag):
        decrypt(key, envelope, associated_data=b"alice->eve")


def test_rfc7748_x25519_vector():
    """Check our X25519 against the first test vector in RFC 7748, section 5.2.

    Given a scalar and a u-coordinate, the curve multiplication must produce
    the published output. This proves we are interoperable with every other
    correct X25519 implementation, including the C++ client's.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    scalar = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd"
        "62144c0ac1fc5a18506a2244ba449ac4"
    )
    u_coord = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c"
        "726624ec26b3353b10a903a6d0ab1c4c"
    )
    expected = bytes.fromhex(
        "c3da55379de9c6908e94ea4df28d084f"
        "32eccf03491c71f754b4075577a28552"
    )

    priv = X25519PrivateKey.from_private_bytes(scalar)
    pub = X25519PublicKey.from_public_bytes(u_coord)
    shared = priv.exchange(pub)

    assert shared == expected
