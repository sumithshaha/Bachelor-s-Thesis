"""
The cryptographic core of the chat application.

This module implements the end-to-end encryption scheme in Python and serves two
roles: it is the reference implementation that the C++/QML client mirrors
byte-for-byte, and it is what the automated tests exercise.

It now contains two layers:

  * The original static scheme -- a long-term X25519 identity per user, an X25519
    Diffie-Hellman to a shared secret, HKDF-SHA256 to a 256-bit key, and an AEAD.
    This is kept as `derive_shared_key` + `encrypt`/`decrypt`; it is the bootstrap
    for the ratchet and the path the original single-message interop check uses.

  * A Double Ratchet (Perrin & Marlinspike) layered on top, providing the two
    properties the static scheme lacked:
      - forward secrecy: each message key comes from a one-way step (KDF_CK) and
        the old chain key is discarded, so a key compromised today cannot recover
        yesterday's messages;
      - post-compromise security: each time the conversation turns, a fresh DH is
        folded into the root key (KDF_RK), so once an attacker stops observing,
        the next ratchet step locks them back out.
    The message AEAD is hybrid and chosen per message: AES-256-GCM where hardware
    AES is reported, XChaCha20-Poly1305 otherwise, with the choice carried in the
    header and authenticated. The ratchet API is `ratchet_encrypt`/`ratchet_decrypt`.

Initialisation follows "Route A": the initial shared secret is exactly
`derive_shared_key`'s output, and the peer's long-term identity key serves as its
initial ratchet key. The first message therefore inherits the pre-ratchet
properties of the static scheme until the first DH step heals it; full X3DH with
prekeys would close that gap.

Author: Sumith Shaha -- TAMK, 2026
"""
from __future__ import annotations

import os
from copy import deepcopy
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as _XNONCE,
    crypto_aead_xchacha20poly1305_ietf_decrypt as _xchacha_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt as _xchacha_encrypt,
)

# Domain-separation string fed into HKDF for the static scheme. Changing it
# changes every derived key, so it doubles as a protocol-version tag.
HKDF_INFO = b"tamk-chat-e2ee-v1"
KEY_LEN = 32   # AES-256 -> 32-byte key
NONCE_LEN = 12  # AES-GCM standard nonce length (96 bits)


# =========================================================================== #
# Identity (long-term key pair)
# =========================================================================== #
@dataclass
class Identity:
    """A user's long-term key pair. The private key never leaves the device; the
    public key is uploaded so others can encrypt to us (and is the ratchet's
    initial DH key for the peer)."""

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
        """The raw 32-byte public key, in the RFC 7748 encoding."""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def derive_shared_key(my_identity: Identity, peer_public: bytes) -> bytes:
    """X25519 with our private key and the peer's public key, then HKDF.

    Both parties compute the SAME 32 bytes (ECDH is symmetric). In the ratchet
    this is the Route A initial shared secret (see `bootstrap_sk`); on its own it
    is the key for the legacy static `encrypt`/`decrypt`.
    """
    peer_key = X25519PublicKey.from_public_bytes(peer_public)
    shared_secret = my_identity.private_key.exchange(peer_key)
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=HKDF_INFO
    ).derive(shared_secret)


# =========================================================================== #
# Legacy static scheme (pre-ratchet). Retained for bootstrap + original interop.
# =========================================================================== #
@dataclass
class Envelope:
    """What the static scheme puts on the wire: a nonce and a ciphertext."""

    nonce: bytes
    ciphertext: bytes

    def to_hex(self) -> dict[str, str]:
        return {"nonce": self.nonce.hex(), "ct": self.ciphertext.hex()}

    @classmethod
    def from_hex(cls, d: dict[str, str]) -> "Envelope":
        return cls(bytes.fromhex(d["nonce"]), bytes.fromhex(d["ct"]))


def encrypt(shared_key: bytes, plaintext: str, associated_data: bytes = b"") -> Envelope:
    """Legacy static-key AES-256-GCM seal. A fresh random 96-bit nonce each time."""
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(shared_key).encrypt(nonce, plaintext.encode("utf-8"), associated_data)
    return Envelope(nonce, ct)


def decrypt(shared_key: bytes, envelope: Envelope, associated_data: bytes = b"") -> str:
    """Legacy static-key AES-256-GCM open. Raises on tamper or wrong key."""
    pt = AESGCM(shared_key).decrypt(
        envelope.nonce, envelope.ciphertext, associated_data
    )
    return pt.decode("utf-8")


# =========================================================================== #
# Double Ratchet -- forward secrecy + post-compromise security
# =========================================================================== #
INFO_SK = HKDF_INFO  # the bootstrap secret IS derive_shared_key's output
INFO_ROOT = b"tamk-chat-ratchet-root-v1"  # domain-separates the root-chain KDF

# Two ciphers, two header tags. The tag is per message, travels in the header,
# and is folded into the AEAD associated data so it cannot be flipped undetected.
CIPHER_AES = "a256gcm-r1"        # AES-256-GCM, 12-byte nonce
CIPHER_XCHACHA = "xc20p1305-r1"  # XChaCha20-Poly1305, 24-byte nonce
_NONCE_LEN = {CIPHER_AES: 12, CIPHER_XCHACHA: _XNONCE}  # _XNONCE == 24
MAX_SKIP = 1000  # bound on out-of-order / not-yet-arrived messages (DoS bound)


def hardware_aes_available() -> bool:
    """The cipher-selection signal. In Python (OpenSSL) AES-GCM always works, so
    the reference can prefer it; the C++ client decides this with libsodium's
    crypto_aead_aes256gcm_is_available(), which returns 0 on the Windows/MinGW
    desktop -- so that endpoint will select XChaCha20, sidestepping the very
    hardware-detection fragility documented in the testing chapter."""
    return True


def select_cipher() -> str:
    """Send-side policy: AES-256-GCM where hardware AES is reported, else
    XChaCha20-Poly1305. Receivers honour whatever tag a message carries."""
    return CIPHER_AES if hardware_aes_available() else CIPHER_XCHACHA


def _aead_encrypt(cipher: str, key: bytes, nonce: bytes, pt: bytes, ad: bytes) -> bytes:
    if cipher == CIPHER_AES:
        return AESGCM(key).encrypt(nonce, pt, ad)
    return _xchacha_encrypt(pt, ad, nonce, key)


def _aead_decrypt(cipher: str, key: bytes, nonce: bytes, ct: bytes, ad: bytes) -> bytes:
    if cipher == CIPHER_AES:
        return AESGCM(key).decrypt(nonce, ct, ad)  # raises InvalidTag on failure
    return _xchacha_decrypt(ct, ad, nonce, key)    # raises CryptoError on failure


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

    HMAC with distinct one-byte constants. One-way: given the next chain key you
    cannot recover this message key -- the per-message forward-secrecy guarantee.
    """

    def mac(key: bytes, b: bytes) -> bytes:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(b)
        return h.finalize()

    return mac(ck, b"\x02"), mac(ck, b"\x01")


def bootstrap_sk(my_priv: bytes, peer_pub: bytes) -> bytes:
    """Route A initial secret: literally derive_shared_key's output."""
    return derive_shared_key(Identity.from_private_bytes(my_priv), peer_pub)


def _ad(cipher: str, dh_pub: bytes, pn: int, n: int) -> bytes:
    """Associated data = serialized header (cipher tag included), so the AEAD tag
    authenticates the whole header -- the cipher choice cannot be tampered with."""
    return cipher.encode() + dh_pub + pn.to_bytes(4, "big") + n.to_bytes(4, "big")


@dataclass
class State:
    DHs_priv: bytes | None = None   # our current ratchet keypair
    DHs_pub: bytes | None = None
    DHr_pub: bytes | None = None    # peer's latest ratchet public key
    RK: bytes | None = None         # root key
    CKs: bytes | None = None        # sending chain key
    CKr: bytes | None = None        # receiving chain key
    Ns: int = 0                     # messages sent in this sending chain
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


def ratchet_encrypt(
    s: State, plaintext: bytes, cipher: str | None = None
) -> tuple[dict, bytes, bytes]:
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


def ratchet_decrypt(s: State, header: dict, nonce: bytes, ct: bytes) -> bytes:
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


# =========================================================================== #
# Safety number (unchanged) -- detect a man-in-the-middle on the key exchange
# =========================================================================== #
def safety_number(pub_a: bytes, pub_b: bytes) -> str:
    """Conversation safety number from two raw 32-byte public keys, sorted so both
    sides derive the identical value; six groups of five decimal digits, compared
    out-of-band. The C++ client's CryptoBox::safetyNumber mirrors this byte-for-byte.
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
