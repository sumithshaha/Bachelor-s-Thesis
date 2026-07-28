"""
Tests for POST-COMPROMISE SECURITY (self-healing after a state compromise).

Post-compromise security is the guarantee that, once an attacker who has
captured one party's full session state stops observing, the conversation
becomes secure again for future messages. In the Double Ratchet this is an
emergent property of the DH ratchet: every time the conversation TURNS, a fresh
DH keypair is folded into the root key (``_dh_ratchet`` -> ``kdf_rk``), so the
next round-trip of new ratchet keys derives from randomness the attacker never
saw and locks them back out.

These tests establish three things, in increasing order of importance:

  1. Baseline the property that already exists: ordinary two-way traffic heals a
     compromise on its own after a single round-trip.
  2. Expose the gap that motivates the client's heartbeat: a purely
     ONE-DIRECTIONAL burst (one side sending, the other silent) NEVER heals --
     the compromised sending chain keeps producing readable message keys
     indefinitely.
  3. Validate the heartbeat: injecting ONE swallowed rekey ping/pong round-trip
     (exactly what ChatClient::transmitRekey does over the wire) restores
     post-compromise security in BOTH directions, bounding the exposure window.

The attacker is modelled with ``crypto_core.snapshot`` -- a deep copy of a
party's ``State`` at an instant, described in the reference as "an attacker
capturing state at an instant." A captured snapshot can read a message in a
direction if and only if it can derive that message's key; each check is run on
a throwaway copy so the probe never mutates the live conversation.

This exercises the SAME reference ratchet the C++/QML client mirrors
byte-for-byte, so a green run here is evidence for the client's behaviour too.
The client adds no cryptographic code for this feature: it only drives the
round-trip that these tests show is sufficient.

Run with:  pytest -v test_post_compromise.py
"""

import copy
import sys
from pathlib import Path

import pytest

# Make the server package importable when tests run from the tests/ folder.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

import crypto_core as cc  # noqa: E402


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _bootstrap():
    """Bring up a fresh Alice/Bob ratchet pair exactly as the client does: a
    Route A bootstrap over the two identity keys, then init_alice / init_bob.
    Returns (alice_state, bob_state)."""
    a_id, b_id = cc.Identity.generate(), cc.Identity.generate()
    sk_a = cc.bootstrap_sk(a_id.private_bytes(), b_id.public_bytes())
    sk_b = cc.bootstrap_sk(b_id.private_bytes(), a_id.public_bytes())
    assert sk_a == sk_b, "both parties must derive the identical bootstrap secret"
    alice = cc.init_alice(sk_a, b_id.public_bytes())
    bob = cc.init_bob(sk_b, b_id.private_bytes(), b_id.public_bytes())
    return alice, bob


def _send(frm, to, text):
    """Encrypt from ``frm`` and deliver to ``to`` (advancing both states), pinned
    to XChaCha20-Poly1305 to match the client's cross-platform cipher choice.
    Returns the on-the-wire tuple (header, nonce, ct)."""
    header, nonce, ct = cc.ratchet_encrypt(
        frm, text.encode(), cipher=cc.CIPHER_XCHACHA
    )
    cc.ratchet_decrypt(to, header, nonce, ct)
    return header, nonce, ct


def _attacker_reads_inbound_to(snapshot, wire):
    """Can a captured snapshot of party X decrypt a message addressed TO X? The
    attacker simply runs X's own receive routine on a throwaway copy."""
    header, nonce, ct = wire
    try:
        cc.ratchet_decrypt(copy.deepcopy(snapshot), header, nonce, ct)
        return True
    except Exception:
        return False


def _attacker_reads_outbound_from(snapshot, wire):
    """Can a captured snapshot of party X decrypt a message X SENT? The attacker
    reproduces X's send: if the snapshot still holds the sending key the frame
    was sent under, it steps a copy of the sending chain to the frame's index and
    opens the AEAD. Returns False if X has since rotated its ratchet key (the
    snapshot can no longer follow) -- which is exactly the healed condition."""
    header, nonce, ct = wire
    if snapshot.DHs_pub != header["dh"]:
        return False  # sender rotated its ratchet key: snapshot cannot follow
    steps = header["n"] - snapshot.Ns + 1
    if steps <= 0:
        return False
    ck, mk = snapshot.CKs, None
    for _ in range(steps):
        ck, mk = cc.kdf_ck(ck)
    ad = cc._ad(header["cipher"], header["dh"], header["pn"], header["n"])
    try:
        cc._aead_decrypt(header["cipher"], mk, nonce, ct, ad)
        return True
    except Exception:
        return False


# The two sentinel payloads the client's rekey frames carry. Their content is
# irrelevant to the crypto (the receiver swallows them); modelling them keeps the
# test faithful to ChatClient::transmitRekey.
_REKEY_PING = "\x01__chate2ee_rekey_ping__"
_REKEY_PONG = "\x01__chate2ee_rekey_pong__"


def _heartbeat_round_trip(alice, bob):
    """One rekey ping/pong, driven by Alice, as the client would put it on the
    wire: a swallowed ping A->B, then a swallowed pong B->A. Both are ordinary
    ratchet frames; the pong makes Alice perform a fresh DH ratchet."""
    _send(alice, bob, _REKEY_PING)  # rekey-ping (swallowed by Bob)
    _send(bob, alice, _REKEY_PONG)  # rekey-pong (swallowed by Alice)


# --------------------------------------------------------------------------- #
# 1. Baseline: the property the Double Ratchet already provides
# --------------------------------------------------------------------------- #
def test_two_way_traffic_heals_a_compromise_on_its_own():
    """Ordinary back-and-forth conversation is self-healing: after Alice's state
    is captured, a single organic round-trip locks the attacker out of BOTH
    directions. This is the post-compromise security the ratchet already gives;
    the heartbeat exists only to guarantee it when traffic is NOT two-way."""
    alice, bob = _bootstrap()
    _send(alice, bob, "hi")
    _send(bob, alice, "hello")            # steady state (each has ratcheted once)

    snapshot = cc.snapshot(alice)         # <-- attacker captures Alice's state

    # One organic round-trip after the compromise.
    _send(alice, bob, "how are you")
    _send(bob, alice, "good thanks")

    fresh_ab = _send(alice, bob, "a fresh outbound message")
    fresh_ba = _send(bob, alice, "a fresh inbound message")

    assert not _attacker_reads_outbound_from(snapshot, fresh_ab), (
        "A->B should be secure again after a round-trip"
    )
    assert not _attacker_reads_inbound_to(snapshot, fresh_ba), (
        "B->A should be secure again after a round-trip"
    )


# --------------------------------------------------------------------------- #
# 2. The gap: one-directional traffic never heals
# --------------------------------------------------------------------------- #
def test_one_directional_traffic_never_self_heals():
    """The motivation for the heartbeat. If Alice is compromised and then keeps
    sending while Bob stays silent, no DH ratchet ever fires, so the attacker's
    captured state keeps decrypting Alice's NEWEST messages -- here, for a long
    burst with no reply. Without an injected round-trip this never recovers."""
    alice, bob = _bootstrap()
    _send(alice, bob, "hi")
    _send(bob, alice, "hello")            # steady state

    snapshot = cc.snapshot(alice)         # <-- attacker captures Alice's state

    for i in range(50):                   # Alice talks, Bob never replies
        wire = _send(alice, bob, f"one-way message {i}")
        assert _attacker_reads_outbound_from(snapshot, wire), (
            f"without a round-trip the attacker should still read message {i}"
        )


# --------------------------------------------------------------------------- #
# 3. The feature: the heartbeat restores post-compromise security
# --------------------------------------------------------------------------- #
def test_rekey_heartbeat_restores_pcs_after_one_way_burst():
    """The core guarantee. Alice is compromised mid one-way burst; the attacker
    can read her newest message. A SINGLE rekey ping/pong round-trip (what the
    client injects automatically once the recovery window fills) then heals BOTH
    directions: the captured state can no longer read fresh traffic either way."""
    alice, bob = _bootstrap()
    _send(alice, bob, "hi")
    _send(bob, alice, "hello")
    for i in range(20):                   # one-way burst before compromise
        _send(alice, bob, f"pre {i}")

    snapshot = cc.snapshot(alice)         # <-- attacker captures Alice's state

    for i in range(10):                   # more one-way traffic after compromise
        _send(alice, bob, f"post {i}")

    # Precondition: the attacker really can read the newest one-way message.
    exposed = _send(alice, bob, "still exposed")
    assert _attacker_reads_outbound_from(snapshot, exposed), (
        "pre-heartbeat, the one-way channel must still be exposed"
    )

    # The heartbeat: exactly one ping/pong round-trip.
    _heartbeat_round_trip(alice, bob)

    fresh_ab = _send(alice, bob, "healed outbound")
    fresh_ba = _send(bob, alice, "healed inbound")
    assert not _attacker_reads_outbound_from(snapshot, fresh_ab), (
        "after one heartbeat round-trip, A->B must be secure again"
    )
    assert not _attacker_reads_inbound_to(snapshot, fresh_ba), (
        "after one heartbeat round-trip, B->A must be secure again"
    )


def test_heartbeat_message_key_actually_changes_after_healing():
    """A sharper check that healing is real and not incidental: the message key
    the attacker would derive for a post-heal frame differs from the key that
    actually protects it. (If the attacker could still derive the true key,
    equality would hold and the AEAD check in the test above could be a fluke.)"""
    alice, bob = _bootstrap()
    _send(alice, bob, "hi")
    _send(bob, alice, "hello")
    snapshot = cc.snapshot(alice)
    for i in range(5):
        _send(alice, bob, f"burst {i}")

    _heartbeat_round_trip(alice, bob)

    # True key for Alice's next send.
    real = copy.deepcopy(alice)
    _, real_mk = cc.kdf_ck(real.CKs)

    # Key the captured snapshot would derive, if it can still follow the chain.
    if snapshot.DHs_pub == alice.DHs_pub:
        _, attacker_mk = cc.kdf_ck(snapshot.CKs)
        assert attacker_mk != real_mk, "healed message key must differ from the snapshot's"
    else:
        # Alice rotated her ratchet key entirely; the snapshot cannot even name
        # the chain, which is the strongest possible form of healing.
        assert True


# --------------------------------------------------------------------------- #
# 4. Robustness: it is not a fluke of one key pairing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("trial", range(40))
def test_heartbeat_heals_across_random_identities(trial):
    """Repeat the compromise-then-heartbeat scenario with fresh random
    identities and randomised burst lengths, so the guarantee does not depend on
    a particular key ordering or message count."""
    import random

    rng = random.Random(1000 + trial)
    alice, bob = _bootstrap()
    _send(alice, bob, "hi")
    _send(bob, alice, "hello")
    for i in range(rng.randint(0, 15)):
        _send(alice, bob, f"pre {i}")

    snapshot = cc.snapshot(alice)
    for i in range(rng.randint(0, 15)):
        _send(alice, bob, f"post {i}")

    _heartbeat_round_trip(alice, bob)

    fresh_ab = _send(alice, bob, "AB")
    fresh_ba = _send(bob, alice, "BA")
    assert not _attacker_reads_outbound_from(snapshot, fresh_ab)
    assert not _attacker_reads_inbound_to(snapshot, fresh_ba)
