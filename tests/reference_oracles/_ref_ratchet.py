"""
Reference Double Ratchet -- TEST ORACLE, not the product implementation.

Why this file exists
--------------------
A test strategy that "proves forward secrecy and post-compromise security hold"
needs a concrete ratchet to exercise, and the cross-language interop check needs
a known-good side to generate vectors. This module is that oracle. It is written
to be read alongside the Signal Foundation's *Double Ratchet* specification
(Perrin & Marlinspike): the field names, KDF_RK/KDF_CK split, the DH-ratchet
step and the skipped-key store all follow it.

It is deliberately NOT the implementation you submit. The product ratchet lives
in the application (server/crypto_core.py and client/src/cryptobox.cpp) and is
yours to write and own; this oracle is part of the test harness. Verify it
against the specification rather than trusting it -- that is the point of a
reference.

Primitives match the rest of the project:
  * X25519                      -- cryptography (same curve as crypto_core.py)
  * HKDF-SHA256 / HMAC-SHA256   -- cryptography
  * XChaCha20-Poly1305 (IETF)   -- libsodium via PyNaCl, byte-identical to the
                                   C++ client's libsodium and to the file path
"""
from __future__ import annotations

import os
from copy import deepcopy
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, hmac
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
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as NONCE_LEN,
    crypto_aead_xchacha20poly1305_ietf_decrypt as _xdec,
    crypto_aead_xchacha20poly1305_ietf_encrypt as _xenc,
)

# Domain-separation strings. INFO_SK matches crypto_core.HKDF_INFO so the
# bootstrap secret is exactly derive_shared_key()'s output (Route A in the
# architecture). INFO_ROOT separates the root-chain KDF from everything else.
INFO_SK = b"tamk-chat-e2ee-v1"
INFO_ROOT = b"tamk-chat-ratchet-root-v1"
CIPHER_TAG = b"xc20p1305-r1"
MAX_SKIP = 1000  # bound on out-of-order / not-yet-arrived messages


# --------------------------------------------------------------------------- #
# Primitive helpers
# --------------------------------------------------------------------------- #
def gen_keypair() -> tuple[bytes, bytes]:
    """Return (private32, public32) for a fresh X25519 ratchet key."""
    p = X25519PrivateKey.generate()
    priv = p.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = p.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def dh(priv32: bytes, pub32: bytes) -> bytes:
    """X25519(our private, their public)."""
    return X25519PrivateKey.from_private_bytes(priv32).exchange(
        X25519PublicKey.from_public_bytes(pub32)
    )


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Root-key KDF. salt = current root key, IKM = DH output. -> (RK', CK')."""
    okm = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=rk, info=INFO_ROOT
    ).derive(dh_out)
    return okm[:32], okm[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Chain-key KDF, one message at a time. -> (CK_next, message_key)."""

    def mac(key: bytes, b: bytes) -> bytes:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(b)
        return h.finalize()

    return mac(ck, b"\x02"), mac(ck, b"\x01")


def bootstrap_sk(my_priv: bytes, peer_pub: bytes) -> bytes:
    """The initial shared secret SK (Route A): exactly derive_shared_key()."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=INFO_SK
    ).derive(dh(my_priv, peer_pub))


def _ad(dh_pub: bytes, pn: int, n: int) -> bytes:
    """Associated data = the serialized header, so the AEAD tag binds it."""
    return CIPHER_TAG + dh_pub + pn.to_bytes(4, "big") + n.to_bytes(4, "big")


# --------------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------------- #
@dataclass
class State:
    DHs_priv: bytes | None = None
    DHs_pub: bytes | None = None
    DHr_pub: bytes | None = None
    RK: bytes | None = None
    CKs: bytes | None = None
    CKr: bytes | None = None
    Ns: int = 0
    Nr: int = 0
    PN: int = 0
    MKSKIPPED: dict[tuple[bytes, int], bytes] = field(default_factory=dict)


def init_alice(sk: bytes, peer_ratchet_pub: bytes) -> State:
    """First sender. peer_ratchet_pub is Bob's identity key (Route A)."""
    s = State()
    s.DHs_priv, s.DHs_pub = gen_keypair()
    s.DHr_pub = peer_ratchet_pub
    s.RK, s.CKs = kdf_rk(sk, dh(s.DHs_priv, s.DHr_pub))
    return s


def init_bob(sk: bytes, my_ratchet_priv: bytes, my_ratchet_pub: bytes) -> State:
    """First receiver, bootstrapped on its own identity keypair (Route A)."""
    s = State()
    s.DHs_priv, s.DHs_pub = my_ratchet_priv, my_ratchet_pub
    s.RK = sk
    return s


# --------------------------------------------------------------------------- #
# Ratchet operations (follow the Double Ratchet spec)
# --------------------------------------------------------------------------- #
def encrypt(s: State, plaintext: bytes) -> tuple[dict, bytes, bytes]:
    s.CKs, mk = kdf_ck(s.CKs)
    header = {"dh": s.DHs_pub, "pn": s.PN, "n": s.Ns}
    nonce = os.urandom(NONCE_LEN)
    ct = _xenc(plaintext, _ad(s.DHs_pub, s.PN, s.Ns), nonce, mk)
    s.Ns += 1
    return header, nonce, ct


def _skip(s: State, until: int) -> None:
    if s.Nr + MAX_SKIP < until:
        raise ValueError("too many skipped messages")
    if s.CKr is not None:
        while s.Nr < until:
            s.CKr, mk = kdf_ck(s.CKr)
            s.MKSKIPPED[(s.DHr_pub, s.Nr)] = mk
            s.Nr += 1


def _dh_ratchet(s: State, dh_pub: bytes) -> None:
    s.PN = s.Ns
    s.Ns = 0
    s.Nr = 0
    s.DHr_pub = dh_pub
    s.RK, s.CKr = kdf_rk(s.RK, dh(s.DHs_priv, s.DHr_pub))
    s.DHs_priv, s.DHs_pub = gen_keypair()
    s.RK, s.CKs = kdf_rk(s.RK, dh(s.DHs_priv, s.DHr_pub))


def decrypt(s: State, header: dict, nonce: bytes, ct: bytes) -> bytes:
    dh_pub, pn, n = header["dh"], header["pn"], header["n"]
    ad = _ad(dh_pub, pn, n)

    # 1. A key we stored earlier for a message that arrived late / out of order.
    skipped = s.MKSKIPPED.pop((dh_pub, n), None)
    if skipped is not None:
        return _xdec(ct, ad, nonce, skipped)

    # 2. A ratchet key we have not seen: skip the rest of the old receiving
    #    chain (up to pn) and perform a DH ratchet step.
    if dh_pub != s.DHr_pub:
        _skip(s, pn)
        _dh_ratchet(s, dh_pub)

    # 3. Skip forward within the (possibly new) receiving chain, then derive.
    _skip(s, n)
    s.CKr, mk = kdf_ck(s.CKr)
    s.Nr += 1
    return _xdec(ct, ad, nonce, mk)  # raises nacl.exceptions.CryptoError on fail


def snapshot(s: State) -> State:
    """A deep copy, standing in for an attacker who captures state at an instant."""
    return deepcopy(s)
