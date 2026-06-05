"""
The cryptographic core of the chat application.

This module implements the end-to-end encryption scheme in pure Python using
the `cryptography` library. It exists for two reasons:

  1. It is the reference implementation. The behaviour defined here is the
     contract that the C++/QML client must match byte-for-byte, so that a
     message encrypted by one can be decrypted by the other.
  2. It is what the automated tests exercise. Testing the crypto in Python is
     far easier than testing it through the Qt UI, and because both sides
     follow the same specification, confidence in the Python version carries
     over to the client.

The scheme in one paragraph: each user owns a long-term X25519 key pair. To
send a message from Alice to Bob, Alice combines her private key with Bob's
public key using X25519 (Elliptic-Curve Diffie-Hellman) to obtain a shared
secret that only the two of them can compute. That secret is passed through
HKDF-SHA256 to derive a 256-bit key, and the message is then sealed with
AES-256-GCM, which provides both confidentiality and integrity. A fresh random
96-bit nonce is used for every message.

What this scheme provides: confidentiality, integrity, and authentication of
the sender. What it does NOT provide: forward secrecy (a stolen long-term key
decrypts old messages). That trade-off is discussed in the thesis; it is the
same trade-off the Threema messenger makes.

Author: Sumith Shaha
Course: Bachelor's Thesis, TAMK, 2026
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Domain-separation string fed into HKDF. Changing this value changes every
# derived key, so it doubles as a protocol version tag.
HKDF_INFO = b"tamk-chat-e2ee-v1"
KEY_LEN = 32   # AES-256 -> 32-byte key
NONCE_LEN = 12  # AES-GCM standard nonce length (96 bits)


@dataclass
class Identity:
    """A user's long-term key pair.

    The private key never leaves the device it was created on. The public key
    is uploaded to the server so other users can encrypt messages to us.
    """

    private_key: X25519PrivateKey

    @classmethod
    def generate(cls) -> "Identity":
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Identity":
        return cls(X25519PrivateKey.from_private_bytes(raw))

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        """The raw 32-byte public key, in the encoding defined by RFC 7748."""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def derive_shared_key(
    my_identity: Identity, peer_public: bytes
) -> bytes:
    """Run X25519 with our private key and the peer's public key, then HKDF.

    Both parties compute the SAME shared secret here: X25519 has the property
    that ECDH(my_priv, your_pub) == ECDH(your_priv, my_pub). HKDF then turns
    that raw secret into a uniformly random 256-bit key suitable for AES.
    """
    peer_key = X25519PublicKey.from_public_bytes(peer_public)
    shared_secret = my_identity.private_key.exchange(peer_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)


@dataclass
class Envelope:
    """What actually travels over the wire: a nonce and a ciphertext.

    Neither field reveals anything about the plaintext to an observer who does
    not hold the shared key - and the server never holds it.
    """

    nonce: bytes
    ciphertext: bytes

    def to_hex(self) -> dict[str, str]:
        return {"nonce": self.nonce.hex(), "ct": self.ciphertext.hex()}

    @classmethod
    def from_hex(cls, d: dict[str, str]) -> "Envelope":
        return cls(bytes.fromhex(d["nonce"]), bytes.fromhex(d["ct"]))


def encrypt(
    shared_key: bytes, plaintext: str, associated_data: bytes = b""
) -> Envelope:
    """Seal a message with AES-256-GCM under the shared key.

    A fresh random nonce is generated every time. With a 96-bit random nonce
    the chance of a repeat is negligible for the message volumes a chat app
    sees, and nonce reuse is the one mistake that breaks GCM, so we never
    derive it from anything predictable.
    """
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(shared_key).encrypt(
        nonce, plaintext.encode("utf-8"), associated_data
    )
    return Envelope(nonce, ct)


def decrypt(
    shared_key: bytes, envelope: Envelope, associated_data: bytes = b""
) -> str:
    """Open a sealed message.

    If the ciphertext or the associated data has been tampered with, AES-GCM
    raises an exception here rather than returning wrong plaintext. That is the
    'integrity' half of authenticated encryption.
    """
    pt = AESGCM(shared_key).decrypt(
        envelope.nonce, envelope.ciphertext, associated_data
    )
    return pt.decode("utf-8")


def safety_number(pub_a: bytes, pub_b: bytes) -> str:
    """Compute the conversation safety number from two raw 32-byte public keys.

    This is the reference implementation that the C++ client's
    CryptoBox::safetyNumber mirrors byte-for-byte (verified by a cross-language
    interop test). It defends against a man-in-the-middle on the key exchange:
    because the server is the one handing out public keys, a malicious server
    could give Alice its own key instead of Bob's and silently relay-and-read
    everything. There is no purely technical fix - the server is the key
    authority - so instead we make the attack *detectable*. Alice and Bob each
    compute this number and compare it over a channel the server does not
    control (a phone call, in person). Matching numbers mean the keys are
    genuine; a mismatch is the signature of an interception.

    The two keys are sorted before hashing so the function is symmetric: Alice
    feeding (mine, Bob's) and Bob feeding (mine, Alice's) hash the identical
    ordered bytes and therefore see the identical number. The output is six
    groups of five decimal digits - short enough to read aloud, while forging a
    second key pair that yields the same digits is computationally infeasible.

    This is the same idea as Signal's "safety numbers" and WhatsApp's "security
    codes".
    """
    if len(pub_a) != 32 or len(pub_b) != 32:
        raise ValueError("public keys must be 32 bytes")
    import hashlib

    lo, hi = sorted([pub_a, pub_b])
    digest = hashlib.sha256(lo + hi).digest()
    groups = []
    for g in range(6):
        chunk = int.from_bytes(digest[g * 4 : g * 4 + 4], "big") % 100000
        groups.append(str(chunk).rjust(5, "0"))
    return " ".join(groups)
