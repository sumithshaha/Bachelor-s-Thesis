"""
Double Ratchet for the chat application -- the Python reference/product schedule.

This is the message-key schedule that gives the protocol forward secrecy and
post-compromise security, replacing the single static per-peer key that
crypto_core.derive_shared_key() produced. It is the authoritative Python
implementation: the C++ client (client/src/cryptobox.cpp) mirrors it byte-for-
byte, and the tests in tests/test_ratchet.py exercise it.

Read this alongside the Signal Foundation's *Double Ratchet* specification
(Perrin & Marlinspike). The names below (RK, CKs/CKr, Ns/Nr/PN, DHs/DHr,
KDF_RK/KDF_CK, the skipped-key store) are taken from it so the two can be read
side by side. The two properties come from one discipline:

  * forward secrecy        -- each message key comes from a ONE-WAY step
    (KDF_CK), and the old chain key is discarded, so a key that leaks today
    cannot reconstruct yesterday's keys.
  * post-compromise security -- each time the conversation turns, a fresh DH
    exchange is folded into the root key (KDF_RK), so once an attacker stops
    observing, the next ratchet step locks them back out.

Primitives match the rest of the project: X25519 + HKDF-SHA256 (cryptography),
and XChaCha20-Poly1305 (libsodium via PyNaCl) -- the same AEAD the file path
already uses, with no hardware-AES dependency.

Initialisation follows "Route A": the initial shared secret is exactly
derive_shared_key()'s output, and the peer's long-term identity key serves as
its initial ratchet key. The first message therefore inherits the pre-ratchet
properties of the static scheme until the first DH step heals it; full X3DH with
prekeys would close that gap.

Author: Sumith Shaha -- Bachelor's Thesis, TAMK, 2026
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as _XNONCE,
    crypto_aead_xchacha20poly1305_ietf_decrypt as _xchacha_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt as _xchacha_encrypt,
)

# AES-256-GCM here comes from the cryptography library (OpenSSL), which -- unlike
# libsodium -- always has a constant-time software path, so Python can always run
# it. The C++ client uses libsodium's crypto_aead_aes256gcm_*, gated on the
# hardware probe; the two are byte-identical for the same key/nonce/AAD.

# Reuse the existing static scheme for the Route A bootstrap secret.
from crypto_core import Identity, derive_shared_key

INFO_SK = b"tamk-chat-e2ee-v1"  # matches crypto_core.HKDF_INFO (SK == derive_shared_key)
INFO_ROOT = b"tamk-chat-ratchet-root-v1"  # domain-separates the root-chain KDF
# Two ciphers, two header tags. The tag is per message, travels in the header,
# and is folded into the AEAD associated data so it cannot be flipped undetected.
CIPHER_AES = "a256gcm-r1"        # AES-256-GCM, 12-byte nonce
CIPHER_XCHACHA = "xc20p1305-r1"  # XChaCha20-Poly1305, 24-byte nonce
_NONCE_LEN = {CIPHER_AES: 12, CIPHER_XCHACHA: _XNONCE}  # _XNONCE == 24


def hardware_aes_available() -> bool:
    """The cipher-selection signal. In Python (OpenSSL) AES-GCM always works, so
    the reference can prefer it; the C++ client decides this with libsodium's
    crypto_aead_aes256gcm_is_available(), which returns 0 on the Windows/MinGW
    desktop -- so that endpoint will select XChaCha20, sidestepping the very
    hardware-detection fragility documented in the testing chapter."""
    return True


def select_cipher() -> str:
    """The send-side policy: AES-256-GCM where hardware AES is reported, else
    XChaCha20-Poly1305. Receivers honour whatever tag a message carries, so the
    two ends need not agree in advance."""
    return CIPHER_AES if hardware_aes_available() else CIPHER_XCHACHA


def _aead_encrypt(cipher: str, key: bytes, nonce: bytes, pt: bytes, ad: bytes) -> bytes:
    if cipher == CIPHER_AES:
        return AESGCM(key).encrypt(nonce, pt, ad)
    return _xchacha_encrypt(pt, ad, nonce, key)


def _aead_decrypt(cipher: str, key: bytes, nonce: bytes, ct: bytes, ad: bytes) -> bytes:
    if cipher == CIPHER_AES:
        return AESGCM(key).decrypt(nonce, ct, ad)  # raises InvalidTag on failure
    return _xchacha_decrypt(ct, ad, nonce, key)    # raises CryptoError on failure
MAX_SKIP = 1000  # ceiling on out-of-order / not-yet-arrived messages (DoS bound)


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #
def gen_keypair() -> tuple[bytes, bytes]:
    """A fresh X25519 ratchet keypair as (private32, public32)."""
    p = X25519PrivateKey.generate()
    return (
        p.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        p.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


def dh(priv32: bytes, pub32: bytes) -> bytes:
    """X25519(our private, their public). Commutative, so both sides agree."""
    return X25519PrivateKey.from_private_bytes(priv32).exchange(
        X25519PublicKey.from_public_bytes(pub32)
    )


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Root KDF: HKDF(salt=root key, IKM=DH output) -> (new root key, chain key)."""
    okm = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=rk, info=INFO_ROOT
    ).derive(dh_out)
    return okm[:32], okm[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Chain KDF, one message at a time -> (next chain key, message key).

    HMAC with distinct one-byte constants. It is one-way: given the next chain
    key you cannot recover this message key or the previous chain key -- which
    is precisely the forward-secrecy guarantee at the per-message level.
    """

    def mac(key: bytes, b: bytes) -> bytes:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(b)
        return h.finalize()

    return mac(ck, b"\x02"), mac(ck, b"\x01")


def bootstrap_sk(my_priv: bytes, peer_pub: bytes) -> bytes:
    """Route A initial secret: literally derive_shared_key()'s output."""
    return derive_shared_key(Identity.from_private_bytes(my_priv), peer_pub)


def _ad(cipher: str, dh_pub: bytes, pn: int, n: int) -> bytes:
    """Associated data = serialized header (cipher tag included), so the AEAD tag
    authenticates the whole header -- the cipher choice cannot be tampered with."""
    return cipher.encode() + dh_pub + pn.to_bytes(4, "big") + n.to_bytes(4, "big")


# --------------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------------- #
@dataclass
class State:
    DHs_priv: bytes | None = None   # our current ratchet keypair
    DHs_pub: bytes | None = None
    DHr_pub: bytes | None = None    # peer's latest ratchet public key
    RK: bytes | None = None         # root key
    CKs: bytes | None = None        # sending chain key
    CKr: bytes | None = None        # receiving chain key
    Ns: int = 0                     # number of messages sent in this sending chain
    Nr: int = 0                     # number expected next in the receiving chain
    PN: int = 0                     # length of the previous sending chain
    MKSKIPPED: dict[tuple[bytes, int], bytes] = field(default_factory=dict)


def init_alice(sk: bytes, peer_ratchet_pub: bytes) -> State:
    """The party that sends first. peer_ratchet_pub is the peer's identity key."""
    s = State()
    s.DHs_priv, s.DHs_pub = gen_keypair()
    s.DHr_pub = peer_ratchet_pub
    s.RK, s.CKs = kdf_rk(sk, dh(s.DHs_priv, s.DHr_pub))
    return s


def init_bob(sk: bytes, my_ratchet_priv: bytes, my_ratchet_pub: bytes) -> State:
    """The party that receives first, bootstrapped on its own identity keypair."""
    s = State()
    s.DHs_priv, s.DHs_pub = my_ratchet_priv, my_ratchet_pub
    s.RK = sk
    return s


# --------------------------------------------------------------------------- #
# Operations (Double Ratchet)
# --------------------------------------------------------------------------- #
def encrypt(s: State, plaintext: bytes, cipher: str | None = None) -> tuple[dict, bytes, bytes]:
    """Encrypt one message. `cipher` defaults to the send-side policy
    (select_cipher); pass CIPHER_AES or CIPHER_XCHACHA to force one."""
    if cipher is None:
        cipher = select_cipher()
    s.CKs, mk = kdf_ck(s.CKs)
    header = {"cipher": cipher, "dh": s.DHs_pub, "pn": s.PN, "n": s.Ns}
    nonce = os.urandom(_NONCE_LEN[cipher])
    ct = _aead_encrypt(cipher, mk, nonce, plaintext, _ad(cipher, s.DHs_pub, s.PN, s.Ns))
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
    cipher, dh_pub, pn, n = header["cipher"], header["dh"], header["pn"], header["n"]
    ad = _ad(cipher, dh_pub, pn, n)

    mk = s.MKSKIPPED.pop((dh_pub, n), None)
    if mk is not None:
        return _aead_decrypt(cipher, mk, nonce, ct, ad)

    if dh_pub != s.DHr_pub:
        _skip(s, pn)
        _dh_ratchet(s, dh_pub)

    _skip(s, n)
    s.CKr, mk = kdf_ck(s.CKr)
    s.Nr += 1
    return _aead_decrypt(cipher, mk, nonce, ct, ad)


def snapshot(s: State) -> State:
    """Deep copy -- stands in for an attacker capturing state at an instant."""
    return deepcopy(s)
