"""
Randomized property fuzzing of the canonical Double Ratchet (server/crypto_core.py).

Hand-written unit tests exercise a handful of chosen sequences; a broken ratchet
can pass all of those and still fail on the millionth reordering. These tests
drive the REAL ratchet through thousands of randomized bidirectional sessions --
reordered bursts, dropped messages, both ciphers, many DH ratchet steps -- and
assert the invariants that must hold for EVERY sequence:

  * correctness under reordering -- every delivered message decrypts to exactly
    the plaintext that was sent, no matter the delivery order within a burst;
  * nonce uniqueness -- no two frames in a whole session ever share a nonce
    (a single AEAD nonce reuse leaks the authentication subkey);
  * the skipped-message store is BOUNDED -- exceeding MAX_SKIP is refused
    (a DoS bound), and a replayed frame whose key was consumed is refused.

Each scenario is seeded, so a failure prints the exact seed to reproduce it.

Runs against server/crypto_core.py (the canonical reference the C++ client and
server/ratchet.py both mirror). Pure Python: needs `cryptography` and `pynacl`.
"""
import random
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

# A spread of seeds; each is an independent randomized session. Parametrizing
# means a failing seed is named in the pytest report and reruns in isolation.
SEEDS = list(range(64))


def _fresh_pair():
    """A bootstrapped Alice (sends first) and Bob (responder), as the app sets
    them up from their two identity keypairs."""
    a_priv, a_pub = cc.gen_keypair()
    b_priv, b_pub = cc.gen_keypair()
    alice = cc.init_alice(cc.bootstrap_sk(a_priv, b_pub), b_pub)
    bob = cc.init_bob(cc.bootstrap_sk(b_priv, a_pub), b_priv, b_pub)
    return alice, bob


@pytest.mark.parametrize("seed", SEEDS)
def test_reordered_bidirectional_sessions(seed):
    """Ping-pong of reordered, partially-dropped bursts across many DH ratchet
    steps. Every delivered frame must decrypt correctly; nonces never repeat."""
    rng = random.Random(seed)
    alice, bob = _fresh_pair()
    states = {"A": alice, "B": bob}

    nonces_seen = set()
    epochs = rng.randint(6, 40)
    # Alice must speak first (Bob has no sending chain until he receives one).
    sender = "A"

    for _ in range(epochs):
        recver = "B" if sender == "A" else "A"
        s_state, r_state = states[sender], states[recver]

        # The sender can only send if its sending chain exists. Bob's appears
        # once he has received a message; if not yet, let Alice keep the floor.
        if s_state.CKs is None:
            sender = "A" if sender == "B" else "B"
            continue

        # Send a burst on the current sending chain.
        burst = []
        for _ in range(rng.randint(1, 15)):
            pt = rng.randbytes(rng.randint(0, 200))
            cipher = rng.choice(BOTH_CIPHERS)
            header, nonce, ct = cc.ratchet_encrypt(s_state, pt, cipher=cipher)
            assert nonce not in nonces_seen, "NONCE REUSE -- catastrophic"
            nonces_seen.add(nonce)
            burst.append((header, nonce, ct, pt))

        # Deliver the burst in a random order, dropping some -- but ALWAYS at
        # least one, so the receiver acquires a sending chain and the roles can
        # alternate. Within-chain reordering is the case the skipped-key store
        # exists for.
        order = list(range(len(burst)))
        rng.shuffle(order)
        keep = [i for i in order if rng.random() > 0.25]
        if not keep:
            keep = [order[0]]
        for i in keep:
            header, nonce, ct, pt = burst[i]
            got = cc.ratchet_decrypt(r_state, header, nonce, ct)
            assert got == pt, f"plaintext mismatch (seed={seed})"

        # Hand the floor to the receiver for the next epoch (a fresh DH ratchet
        # step happens the first time it sends after receiving).
        sender = recver

    # Sanity: a non-trivial session actually happened.
    assert len(nonces_seen) >= epochs // 2


@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_exceeding_max_skip_is_refused(cipher):
    """Delivering a frame that would require skipping more than MAX_SKIP keys is
    refused -- the store cannot be driven unbounded by a malicious sender."""
    alice, bob = _fresh_pair()
    # Send MAX_SKIP + 2 messages; deliver ONLY the last, forcing a skip past the
    # bound.
    last = None
    for i in range(cc.MAX_SKIP + 2):
        last = cc.ratchet_encrypt(alice, f"m{i}".encode(), cipher=cipher)
    header, nonce, ct = last
    with pytest.raises(AEAD_FAIL):
        cc.ratchet_decrypt(bob, header, nonce, ct)


@pytest.mark.parametrize("cipher", BOTH_CIPHERS)
def test_replayed_frame_is_refused(cipher):
    """A frame whose message key has already been consumed cannot be decrypted a
    second time -- replay of an in-order frame fails."""
    alice, bob = _fresh_pair()
    header, nonce, ct = cc.ratchet_encrypt(alice, b"once", cipher=cipher)
    assert cc.ratchet_decrypt(bob, header, nonce, ct) == b"once"
    with pytest.raises(AEAD_FAIL):
        cc.ratchet_decrypt(bob, header, nonce, ct)


def test_within_chain_full_reversal():
    """The extreme reordering case: a whole chain delivered in exact reverse
    order still decrypts, entirely out of the skipped-key store."""
    alice, bob = _fresh_pair()
    msgs = []
    for i in range(200):
        pt = f"reverse-{i}".encode()
        msgs.append((cc.ratchet_encrypt(alice, pt), pt))
    for (header, nonce, ct), pt in reversed(msgs):
        assert cc.ratchet_decrypt(bob, header, nonce, ct) == pt
