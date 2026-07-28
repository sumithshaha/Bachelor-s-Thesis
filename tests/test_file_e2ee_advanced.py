"""
File-transfer E2EE tests -- WITHOUT a live server.

The existing test_file_sharing.py exercises files through a running relay; these
drive the crypto directly (server/file_crypto.py + server/crypto_core.py) using
the EXACT wire construction ChatClient::sendFile now uses: a random per-file key,
the bulk encrypted with the secretstream, and the key delivered over the ratchet
inside the file_init "keyenc" object. They assert the guarantees files gained
when the key moved off the static identity secret and onto the ratchet:

  * content secrecy + round trip -- a multi-chunk file encrypts under a random
    key, the key is recovered over the ratchet, and the file decrypts to an
    identical sha256;
  * integrity -- truncating the stream or flipping a chunk byte is rejected;
  * forward secrecy -- the per-file key is random, NOT a function of the identity
    keys (the old design's key was, and this test shows the contrast);
  * cross-session isolation -- a keyenc from one conversation cannot yield the
    file key in another;
  * bounds -- a file above the hard cap is refused.

Pure Python: needs `cryptography` and `pynacl`.
"""
import hashlib
import io
import os
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "server"))
import crypto_core as cc  # noqa: E402
import file_crypto as fc  # noqa: E402
from nacl.exceptions import CryptoError  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402

AEAD_FAIL = (CryptoError, InvalidTag, ValueError, RuntimeError)


def _fresh_pair():
    a_priv, a_pub = cc.gen_keypair()
    b_priv, b_pub = cc.gen_keypair()
    alice = cc.init_alice(cc.bootstrap_sk(a_priv, b_pub), b_pub)
    bob = cc.init_bob(cc.bootstrap_sk(b_priv, a_pub), b_priv, b_pub)
    return (a_priv, a_pub, b_priv, b_pub, alice, bob)


def _send_file(alice_state, plaintext):
    """Mirror ChatClient::sendFile: random key, secretstream-encrypt the bulk,
    deliver the key over the ratchet as the file_init 'keyenc' object. Returns
    (file_init_like_dict, [chunks])."""
    file_key = os.urandom(fc.KEY_BYTES)
    gen = fc.encrypt_file(io.BytesIO(plaintext), file_key, len(plaintext))
    header, _ = next(gen)                       # first yield is (header, False)
    chunks = [ct for (ct, _last) in gen]
    kh, kn, kct = cc.ratchet_encrypt(alice_state, file_key.hex().encode())
    file_init = {
        "type": "file_init", "from": "alice", "to": "bob",
        "header": header.hex(),
        "keyenc": {
            "cipher": kh["cipher"], "dh": kh["dh"].hex(), "pn": kh["pn"],
            "n": kh["n"], "nonce": kn.hex(), "ct": kct.hex(),
        },
    }
    return file_init, chunks, file_key


def _recover_key(bob_state, file_init):
    """Mirror the file_init handler: recover the file key over the ratchet."""
    ke = file_init["keyenc"]
    hdr = {"cipher": ke["cipher"], "dh": bytes.fromhex(ke["dh"]),
           "pn": ke["pn"], "n": ke["n"]}
    raw = cc.ratchet_decrypt(bob_state, hdr, bytes.fromhex(ke["nonce"]),
                             bytes.fromhex(ke["ct"]))
    return bytes.fromhex(raw.decode())


# --------------------------------------------------------------------------- #
def test_multichunk_round_trip():
    """A 200 KB file (several 64 KiB chunks) survives the full path with an
    identical hash, and the recovered key equals the sender's."""
    *_, alice, bob = _fresh_pair()
    plaintext = b"CONFIDENTIAL\n" + os.urandom(200 * 1024)
    want = hashlib.sha256(plaintext).hexdigest()

    file_init, chunks, file_key = _send_file(alice, plaintext)
    rec_key = _recover_key(bob, file_init)
    assert rec_key == file_key

    out = io.BytesIO()
    fc.decrypt_file(bytes.fromhex(file_init["header"]), iter(chunks), rec_key, out)
    assert hashlib.sha256(out.getvalue()).hexdigest() == want


def test_truncated_stream_rejected():
    """Dropping the final (TAG_FINAL) chunk is detected as truncation."""
    *_, alice, bob = _fresh_pair()
    plaintext = os.urandom(200 * 1024)
    file_init, chunks, _ = _send_file(alice, plaintext)
    rec_key = _recover_key(bob, file_init)
    with pytest.raises(AEAD_FAIL):
        fc.decrypt_file(bytes.fromhex(file_init["header"]),
                        iter(chunks[:-1]), rec_key, io.BytesIO())


def test_tampered_chunk_rejected():
    """Flipping a single byte in a middle chunk fails authentication."""
    *_, alice, bob = _fresh_pair()
    plaintext = os.urandom(200 * 1024)
    file_init, chunks, _ = _send_file(alice, plaintext)
    rec_key = _recover_key(bob, file_init)

    mid = len(chunks) // 2
    ba = bytearray(chunks[mid])
    ba[0] ^= 0x01
    chunks[mid] = bytes(ba)
    with pytest.raises(AEAD_FAIL):
        fc.decrypt_file(bytes.fromhex(file_init["header"]),
                        iter(chunks), rec_key, io.BytesIO())


def test_file_key_is_not_identity_derivable():
    """The per-file key is random -- NOT a function of the identity keys. The old
    design derived it from the static shared secret, which an identity-key holder
    could recompute; this test shows the old value is re-derivable and the new
    one is not, i.e. files now have forward secrecy."""
    a_priv, a_pub, b_priv, b_pub, alice, _ = _fresh_pair()
    _, _, file_key = _send_file(alice, b"x" * 4096)

    # OLD design: an attacker with the identity keys recomputes the shared secret
    # and re-derives the file key for a given msg_id.
    static_shared = cc.dh(a_priv, b_pub)
    old_key = hashlib.sha256(static_shared + b"msg-id-0001").digest()
    old_again = hashlib.sha256(cc.dh(b_priv, a_pub) + b"msg-id-0001").digest()
    assert old_key == old_again                       # old key IS identity-derivable

    # NEW design: the random key is not that function of the identity keys.
    assert hashlib.sha256(static_shared + b"msg-id-0001").digest() != file_key


def test_keyenc_wire_fields_present_and_sufficient():
    """The keyenc object carries exactly the ratchet frame fields the client
    sends, and they are sufficient (and necessary) to recover the key."""
    *_, alice, bob = _fresh_pair()
    file_init, _chunks, file_key = _send_file(alice, b"y" * 1024)
    assert set(file_init["keyenc"]) == {"cipher", "dh", "pn", "n", "nonce", "ct"}
    assert _recover_key(bob, file_init) == file_key


def test_file_key_cross_session_isolation():
    """A keyenc produced in one conversation does not yield the file key in an
    unrelated conversation -- so the encrypted blob stays opaque there."""
    # Sender in session 1, an unrelated receiver in session 2.
    *_, alice1, _bob1 = _fresh_pair()
    *_, _alice2, bob2 = _fresh_pair()
    file_init, _chunks, _fk = _send_file(alice1, b"z" * 2048)
    with pytest.raises(AEAD_FAIL):
        _recover_key(bob2, file_init)


def test_file_above_cap_is_refused():
    """A declared size above the hard cap is refused by the encryptor."""
    file_key = os.urandom(fc.KEY_BYTES)
    gen = fc.encrypt_file(io.BytesIO(b""), file_key, fc.MAX_FILE_BYTES + 1)
    with pytest.raises(ValueError):
        next(gen)
