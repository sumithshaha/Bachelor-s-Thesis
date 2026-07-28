"""
x3dh.py -- Extended Triple Diffie-Hellman (X3DH) initial key agreement.

This is the asynchronous handshake that establishes the shared secret two users
start their Double Ratchet from when one of them is offline: the recipient
publishes a prekey bundle (an identity key, a signed prekey, and a pool of
one-time prekeys), and the initiator combines several Diffie-Hellmans into one
shared secret. It is the reference the server's prekey pool
(server/prekey_store.py) and the client's bundle handling are built around.

SIGNING SCHEME -- CHANGED
-------------------------
This module previously signed the prekey with XEdDSA, implemented here with
hand-written Ed25519 arithmetic. That version carried the warning that its bytes
were "not claimed to be byte-compatible with any other XEdDSA implementation",
and it was not: libsodium's crypto_sign is RFC 8032 Ed25519, a different
construction with a different challenge hash and sign-bit convention. A C++ port
reaching for the obvious library call would have produced signatures this module
rejected, and the failure would have surfaced as an undecryptable first message
rather than as a signature error.

The identity key is now an Ed25519 SIGNING key, and the X25519 agreement key is
DERIVED from it with the standard birational map (libsodium's
crypto_sign_ed25519_pk_to_curve25519 / _sk_to_curve25519). One published key
therefore does both jobs, which is the arrangement Signal itself uses.

Both languages now use stock, well-tested implementations:

  * Python signs and verifies with `cryptography` (RFC 8032 Ed25519) and calls
    libsodium through PyNaCl only for the two conversion functions.
  * C++ signs with libsodium's crypto_sign_detached / crypto_sign_verify_detached
    and converts with crypto_sign_ed25519_*_to_curve25519.

These are byte-identical by construction, and tests/test_x3dh_vectors.py pins it
with fixed vectors rather than leaving it to trust. Roughly 150 lines of bespoke
curve arithmetic are gone with it.

DESIGN
------
  * The IDENTITY key is Ed25519 (32-byte public). Its X25519 counterpart, used
    for the Diffie-Hellmans, is derived deterministically and never published
    separately.
  * The SIGNED PREKEY and ONE-TIME PREKEYS are ordinary X25519 keys; only the
    identity needs to sign.
  * SK = HKDF-SHA256( F || DH1 || DH2 || DH3 [|| DH4] ) with the constants
    below, where DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B),
    DH3 = DH(EK_A, SPK_B), and DH4 = DH(EK_A, OPK_B) when a one-time prekey is
    offered. IK_A and IK_B there mean the DERIVED X25519 keys.

Needs `cryptography` (X25519, Ed25519, HKDF) and `pynacl` (the conversion).
"""
from __future__ import annotations

from dataclasses import dataclass

import nacl.bindings as _sodium
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


# --------------------------------------------------------------------------- #
# X3DH domain-separation constants
# --------------------------------------------------------------------------- #
# F: for Curve25519, X3DH prepends 32 bytes of 0xFF to the DH concatenation.
F = b"\xff" * 32
KDF_SALT = b"\x00" * 32                 # zero salt, one hash length (SHA-256)
KDF_INFO = b"tamk-chat-x3dh-v1"


# --------------------------------------------------------------------------- #
# X25519 helpers (the four DHs)
# --------------------------------------------------------------------------- #
def _priv_bytes(sk: X25519PrivateKey) -> bytes:
    return sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _pub_bytes(pk: X25519PublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def gen_key() -> tuple[bytes, bytes]:
    """A fresh X25519 keypair as (priv32, pub32)."""
    sk = X25519PrivateKey.generate()
    return _priv_bytes(sk), _pub_bytes(sk.public_key())


def _pub_from_priv(priv: bytes) -> bytes:
    return _pub_bytes(X25519PrivateKey.from_private_bytes(priv).public_key())


def _dh(priv: bytes, pub: bytes) -> bytes:
    """Raw X25519 Diffie-Hellman between a private and a public key."""
    return X25519PrivateKey.from_private_bytes(priv).exchange(
        X25519PublicKey.from_public_bytes(pub)
    )


def encode_key(pub: bytes) -> bytes:
    """Encode(PK) as used in the associated data. Both sides encode identically;
    the 32-byte public key is used directly."""
    return bytes(pub)


# --------------------------------------------------------------------------- #
# Identity: an Ed25519 signing key with a derived X25519 agreement key
# --------------------------------------------------------------------------- #
def gen_identity() -> tuple[bytes, bytes]:
    """A fresh Ed25519 identity as (seed32, public32).

    The 32-byte seed is what a device stores; libsodium's 64-byte secret key and
    the X25519 counterpart are both derived from it, so there is exactly one
    secret at rest.
    """
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, pub


def identity_public(seed: bytes) -> bytes:
    """The Ed25519 public key for an identity seed."""
    return (Ed25519PrivateKey.from_private_bytes(seed)
            .public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def identity_to_x25519_private(seed: bytes) -> bytes:
    """The X25519 private key derived from an Ed25519 identity seed.

    libsodium expects its own 64-byte secret-key layout (seed || public), which
    crypto_sign_seed_keypair produces from the seed.
    """
    _pk, sk64 = _sodium.crypto_sign_seed_keypair(seed)
    return _sodium.crypto_sign_ed25519_sk_to_curve25519(sk64)


def identity_to_x25519_public(ed_pub: bytes) -> bytes:
    """The X25519 public key derived from an Ed25519 identity public key.

    Raises ValueError for a public key that is not a valid Ed25519 point, which
    is the correct response to a malformed or hostile bundle.
    """
    try:
        return _sodium.crypto_sign_ed25519_pk_to_curve25519(ed_pub)
    except Exception as exc:                      # libsodium returns -1
        raise ValueError(f"not a convertible Ed25519 public key: {exc}") from exc


# --------------------------------------------------------------------------- #
# Signing: stock RFC 8032 Ed25519, byte-identical to libsodium
# --------------------------------------------------------------------------- #
def sign(seed: bytes, message: bytes) -> bytes:
    """Detached 64-byte Ed25519 signature. Identical bytes to libsodium's
    crypto_sign_detached for the same seed and message."""
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def verify(ed_pub: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a detached Ed25519 signature. Returns False rather than raising,
    so a caller can treat a bad bundle as data rather than as an exception."""
    if len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(ed_pub).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------- #
# Prekeys
# --------------------------------------------------------------------------- #
def new_signed_prekey(ik_seed: bytes) -> tuple[bytes, bytes, bytes]:
    """A fresh signed prekey: (spk_priv, spk_pub, ed25519_sig_over_spk_pub).

    The prekey itself is X25519 (it is an agreement key); the signature over it
    is made with the Ed25519 identity.
    """
    spk_priv, spk_pub = gen_key()
    return spk_priv, spk_pub, sign(ik_seed, spk_pub)


def new_one_time_prekeys(n: int) -> dict[int, tuple[bytes, bytes]]:
    """A pool of `n` one-time prekeys as {opk_id: (priv, pub)}."""
    return {i: gen_key() for i in range(n)}


@dataclass
class PrekeySecrets:
    """The recipient's PRIVATE prekey material (never leaves the device)."""
    ik_seed: bytes
    spk_priv: bytes
    opks_priv: dict[int, bytes]          # {opk_id: priv}; entries are single-use


@dataclass
class PrekeyBundle:
    """The recipient's PUBLIC bundle, as served by the key directory. Mutable so
    a caller can model an exhausted pool (opk=None) or a tampered signature."""
    ik: bytes
    spk: bytes
    spk_sig: bytes
    opk: bytes | None = None
    opk_id: int | None = None


@dataclass
class InitiatorResult:
    """What the initiator derives and must transmit alongside its first message:
    the shared secret, its own identity and ephemeral publics, which one-time
    prekey it consumed, and the associated data both sides bind to."""
    sk: bytes
    ik: bytes
    ek: bytes
    opk_id: int | None
    ad: bytes


# --------------------------------------------------------------------------- #
# The agreement
# --------------------------------------------------------------------------- #
def _kdf(dh_concat: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=KDF_SALT, info=KDF_INFO
    ).derive(F + dh_concat)


def initiator_x3dh(a_ik_seed: bytes, bundle: PrekeyBundle) -> InitiatorResult:
    """Run X3DH as the initiator (the party that is online and sending first).

    Verifies the signed prekey against the bundle's identity key first -- a
    bundle whose SPK signature is forged, or was signed by a different key, is
    rejected with ValueError."""
    if not verify(bundle.ik, bundle.spk, bundle.spk_sig):
        raise ValueError("signed-prekey signature does not verify against IK")

    a_ik_pub = identity_public(a_ik_seed)
    a_ik_x = identity_to_x25519_private(a_ik_seed)
    b_ik_x = identity_to_x25519_public(bundle.ik)
    ek_priv, ek_pub = gen_key()

    dh1 = _dh(a_ik_x, bundle.spk)            # DH(IK_A, SPK_B)
    dh2 = _dh(ek_priv, b_ik_x)               # DH(EK_A, IK_B)
    dh3 = _dh(ek_priv, bundle.spk)           # DH(EK_A, SPK_B)
    dh_concat = dh1 + dh2 + dh3
    if bundle.opk is not None:
        dh_concat += _dh(ek_priv, bundle.opk)  # DH(EK_A, OPK_B)

    sk = _kdf(dh_concat)
    ad = encode_key(a_ik_pub) + encode_key(bundle.ik)
    return InitiatorResult(sk=sk, ik=a_ik_pub, ek=ek_pub,
                           opk_id=bundle.opk_id, ad=ad)


def responder_x3dh(secrets: PrekeySecrets, ik_a: bytes, ek_a: bytes,
                   opk_id: int | None) -> bytes:
    """Run X3DH as the responder, from the initiator's identity and ephemeral
    publics and the one-time prekey id it claims to have used.

    The one-time prekey is SINGLE-USE: it is removed from `secrets.opks_priv`
    here, so replaying the same opk_id raises ValueError."""
    a_ik_x = identity_to_x25519_public(ik_a)
    b_ik_x = identity_to_x25519_private(secrets.ik_seed)

    dh1 = _dh(secrets.spk_priv, a_ik_x)      # DH(SPK_B, IK_A)
    dh2 = _dh(b_ik_x, ek_a)                  # DH(IK_B, EK_A)
    dh3 = _dh(secrets.spk_priv, ek_a)        # DH(SPK_B, EK_A)
    dh_concat = dh1 + dh2 + dh3
    if opk_id is not None:
        opk_priv = secrets.opks_priv.pop(opk_id, None)   # consume it
        if opk_priv is None:
            raise ValueError(f"one-time prekey {opk_id} unknown or already used")
        dh_concat += _dh(opk_priv, ek_a)     # DH(OPK_B, EK_A)

    return _kdf(dh_concat)
