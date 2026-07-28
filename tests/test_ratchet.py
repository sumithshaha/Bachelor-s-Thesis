"""
Ratchet property tests.

The point of these tests is not merely that messages encrypt and decrypt -- a
broken ratchet can do that while providing neither security property. Each test
below is written so that it FAILS if the property it names is absent:

  * forward secrecy      -- state captured *after* a message cannot read messages
                            sent *before* it.
  * post-compromise sec. -- state captured at an instant cannot read messages
                            sent after enough fresh DH ratchet steps.
  * out-of-order safety  -- reordered / delayed messages still decrypt, via the
                            bounded skipped-key store.
  * header integrity     -- the AEAD tag binds the header, so tampering fails.

`test_strategy_has_teeth` deliberately breaks the ratchet and asserts that the
forward-secrecy check then fails -- evidence that these tests are not vacuous.

These run against the product schedule in server/ratchet.py.
"""
import pytest

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "server"))
import ratchet as R          # the product schedule (server/ratchet.py)
from nacl.exceptions import CryptoError
from cryptography.exceptions import InvalidTag

AEAD_FAIL = (CryptoError, InvalidTag, ValueError)  # XChaCha / AES / bound failures
BOTH_CIPHERS = [R.CIPHER_AES, R.CIPHER_XCHACHA]


# --------------------------------------------------------------------------- #
# Fixtures: a freshly initialised Alice/Bob pair (Route A bootstrap).
# --------------------------------------------------------------------------- #
def fresh_pair():
    a_priv, a_pub = R.gen_keypair()
    b_priv, b_pub = R.gen_keypair()
    sk = R.bootstrap_sk(a_priv, b_pub)
    assert sk == R.bootstrap_sk(b_priv, a_pub)  # both sides agree on SK
    alice = R.init_alice(sk, b_pub)
    bob = R.init_bob(sk, b_priv, b_pub)
    return alice, bob


# --------------------------------------------------------------------------- #
# Functional correctness
# --------------------------------------------------------------------------- #
def test_single_direction_chain():
    alice, bob = fresh_pair()
    msgs = [f"message {i}".encode() for i in range(5)]
    for m in msgs:
        h, nonce, ct = R.encrypt(alice, m)
        assert R.decrypt(bob, h, nonce, ct) == m


def test_bidirectional_conversation_dh_ratchets_both_ways():
    alice, bob = fresh_pair()
    # A->B, B->A, A->B, B->A ... each turn forces a DH ratchet on the receiver.
    h, n, c = R.encrypt(alice, b"a0")
    assert R.decrypt(bob, h, n, c) == b"a0"
    h, n, c = R.encrypt(bob, b"b0")
    assert R.decrypt(alice, h, n, c) == b"b0"
    h, n, c = R.encrypt(alice, b"a1")
    assert R.decrypt(bob, h, n, c) == b"a1"
    h, n, c = R.encrypt(bob, b"b1")
    assert R.decrypt(alice, h, n, c) == b"b1"


def test_out_of_order_within_a_chain():
    alice, bob = fresh_pair()
    frames = [R.encrypt(alice, f"m{i}".encode()) for i in range(5)]
    # Deliver in a scrambled order; all must still decrypt correctly.
    for i in (0, 2, 1, 4, 3):
        h, n, c = frames[i]
        assert R.decrypt(bob, h, n, c) == f"m{i}".encode()


def test_delayed_message_across_a_dh_ratchet():
    alice, bob = fresh_pair()
    # Alice sends a0,a1 but a1 is delayed. Bob replies, Alice ratchets and sends
    # a2 in a new chain; then the delayed a1 finally arrives. It must decrypt.
    h0, n0, c0 = R.encrypt(alice, b"a0")
    h1, n1, c1 = R.encrypt(alice, b"a1")  # will be delayed
    assert R.decrypt(bob, h0, n0, c0) == b"a0"
    hb, nb, cb = R.encrypt(bob, b"b0")
    assert R.decrypt(alice, hb, nb, cb) == b"b0"  # Alice DH-ratchets here
    h2, n2, c2 = R.encrypt(alice, b"a2")
    assert R.decrypt(bob, h2, n2, c2) == b"a2"   # Bob skips a1, stores its key
    assert R.decrypt(bob, h1, n1, c1) == b"a1"   # delayed a1 recovered later


# --------------------------------------------------------------------------- #
# Forward secrecy
# --------------------------------------------------------------------------- #
def _fs_holds(alice, bob) -> bool:
    """True iff a snapshot taken AFTER message k cannot read message k-1."""
    frames = [R.encrypt(alice, f"m{i}".encode()) for i in range(4)]
    for i in (0, 1, 2):  # deliver 0,1,2 in order
        h, n, c = frames[i]
        assert R.decrypt(bob, h, n, c) == f"m{i}".encode()
    stolen = R.snapshot(bob)  # attacker captures Bob's state right here
    h1, n1, c1 = frames[1]  # an already-consumed past message
    try:
        R.decrypt(stolen, h1, n1, c1)
        return False  # past message was recoverable -> NO forward secrecy
    except AEAD_FAIL:
        return True  # past key is gone -> forward secrecy holds


def test_forward_secrecy():
    alice, bob = fresh_pair()
    assert _fs_holds(alice, bob), "captured state must not decrypt past messages"


# --------------------------------------------------------------------------- #
# Post-compromise security
# --------------------------------------------------------------------------- #
def test_post_compromise_security():
    alice, bob = fresh_pair()
    # A few healthy turns, then the attacker captures Bob's full state.
    for _ in range(2):
        h, n, c = R.encrypt(alice, b"x")
        R.decrypt(bob, h, n, c)
        h, n, c = R.encrypt(bob, b"y")
        R.decrypt(alice, h, n, c)
    stolen = R.snapshot(bob)

    # The conversation continues for several more bidirectional turns. Each turn
    # introduces fresh ephemeral DH keys that postdate the capture.
    last = None
    for k in range(4):
        h, n, c = R.encrypt(alice, f"after-{k}".encode())
        assert R.decrypt(bob, h, n, c) == f"after-{k}".encode()  # real Bob is fine
        last = (h, n, c, f"after-{k}".encode())
        h, n, c = R.encrypt(bob, b"reply")
        R.decrypt(alice, h, n, c)

    # The stale captured state cannot read a message sent well after healing.
    h, n, c, expected = last
    with pytest.raises(AEAD_FAIL):
        R.decrypt(stolen, h, n, c)


# --------------------------------------------------------------------------- #
# Bounds and integrity
# --------------------------------------------------------------------------- #
def test_skip_bound_is_enforced():
    alice, bob = fresh_pair()
    h, n, c = R.encrypt(alice, b"hello")
    forged = dict(h)
    forged["n"] = R.MAX_SKIP + 50  # claim a wildly future message number
    with pytest.raises(ValueError):
        R.decrypt(bob, forged, n, c)


def test_header_is_authenticated():
    alice, bob = fresh_pair()
    h, n, c = R.encrypt(alice, b"hello")
    tampered = dict(h)
    tampered["n"] = h["n"] + 1  # flip the header; AD no longer matches
    with pytest.raises(AEAD_FAIL):
        R.decrypt(bob, tampered, n, c)


def test_ciphertext_tampering_is_rejected():
    alice, bob = fresh_pair()
    h, n, c = R.encrypt(alice, b"hello")
    c = bytearray(c)
    c[0] ^= 0x01  # flip one bit of ciphertext
    with pytest.raises(AEAD_FAIL):
        R.decrypt(bob, h, n, bytes(c))


# --------------------------------------------------------------------------- #
# Meta-test: prove the suite has teeth
# --------------------------------------------------------------------------- #
def test_strategy_has_teeth(monkeypatch):
    """A correct ratchet passes the FS check; a broken one must fail it.

    We replace kdf_ck with a non-advancing version (every message reuses the
    same key). Under that regression a captured state CAN read past messages,
    so _fs_holds() returns False -- demonstrating test_forward_secrecy would
    catch the break rather than passing vacuously.
    """
    a, b = fresh_pair()
    assert _fs_holds(a, b) is True  # correct implementation

    monkeypatch.setattr(R, "kdf_ck", lambda ck: (ck, ck))  # break one-wayness
    a, b = fresh_pair()
    assert _fs_holds(a, b) is False  # the check now fails, as it should



# --------------------------------------------------------------------------- #
# Hybrid cipher (AES-256-GCM <-> XChaCha20-Poly1305)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_round_trip_under_each_cipher(cipher):
    alice, bob = fresh_pair()
    for i in range(4):
        m = f"msg {i} via {cipher}".encode()
        h, n, c = R.encrypt(alice, m, cipher=cipher)
        assert h["cipher"] == cipher
        assert R.decrypt(bob, h, n, c) == m


@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_forward_secrecy_under_each_cipher(cipher):
    alice, bob = fresh_pair()
    frames = [R.encrypt(alice, f"m{i}".encode(), cipher=cipher) for i in range(4)]
    for i in (0, 1, 2):
        h, n, c = frames[i]
        assert R.decrypt(bob, h, n, c) == f"m{i}".encode()
    stolen = R.snapshot(bob)
    h1, n1, c1 = frames[1]
    with pytest.raises(AEAD_FAIL):
        R.decrypt(stolen, h1, n1, c1)


def test_sender_may_switch_cipher_mid_conversation():
    """A sender whose hardware availability changes flips cipher; the receiver
    follows via the per-message tag with no renegotiation."""
    alice, bob = fresh_pair()
    plan = [R.CIPHER_AES, R.CIPHER_AES, R.CIPHER_XCHACHA, R.CIPHER_AES, R.CIPHER_XCHACHA]
    for i, cipher in enumerate(plan):
        m = f"switch {i}".encode()
        h, n, c = R.encrypt(alice, m, cipher=cipher)
        assert h["cipher"] == cipher
        assert R.decrypt(bob, h, n, c) == m


def test_mixed_directions_use_independent_ciphers():
    """Alice on AES, Bob on XChaCha, in one conversation -- each direction's tag
    governs its own messages."""
    alice, bob = fresh_pair()
    h, n, c = R.encrypt(alice, b"a0", cipher=R.CIPHER_AES)
    assert R.decrypt(bob, h, n, c) == b"a0"
    h, n, c = R.encrypt(bob, b"b0", cipher=R.CIPHER_XCHACHA)
    assert R.decrypt(alice, h, n, c) == b"b0"
    h, n, c = R.encrypt(alice, b"a1", cipher=R.CIPHER_AES)
    assert R.decrypt(bob, h, n, c) == b"a1"


@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_cipher_tag_is_authenticated(cipher):
    """Flipping the cipher tag in the header must break authentication, because
    the tag is part of the associated data."""
    alice, bob = fresh_pair()
    h, n, c = R.encrypt(alice, b"hello", cipher=cipher)
    forged = dict(h)
    forged["cipher"] = (
        R.CIPHER_XCHACHA if cipher == R.CIPHER_AES else R.CIPHER_AES
    )
    with pytest.raises(AEAD_FAIL):
        R.decrypt(bob, forged, n, c)


def test_selection_policy_prefers_aes_when_hardware_present(monkeypatch):
    monkeypatch.setattr(R, "hardware_aes_available", lambda: True)
    assert R.select_cipher() == R.CIPHER_AES
    monkeypatch.setattr(R, "hardware_aes_available", lambda: False)
    assert R.select_cipher() == R.CIPHER_XCHACHA
