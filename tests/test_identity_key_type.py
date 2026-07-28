"""
test_identity_key_type.py -- every door a published identity key comes through
must state WHICH KIND of key it is.

WHY THIS MODULE EXISTS
----------------------
Safety-number verification was completely broken between a version 2 (Ed25519)
account and any peer that learned its key through the single-key frames rather
than the login directory dump, and nothing in the suite noticed. The bug was not
in the safety number itself -- test_safety_number.py already pins symmetry,
sensitivity and format, and all of it passed -- but in the KEY DISTRIBUTION path
feeding it.

A version 2 account publishes its Ed25519 identity key, because that is the key
a prekey bundle's signature verifies against. Peers derive the X25519 agreement
key from it themselves. Both kinds are 32 bytes, so a client cannot tell them
apart by inspection: the relay must say which it is serving. It does so in three
places, and only two of them ever did:

    frame            field          before this fix
    ---------------  -------------  ------------------------------------------
    "keys"  (dump)   "key_types"    present
    "key_update"     "ik_type"      present
    "key"   (getkey) "ik_type"      MISSING -- the on-demand path, which is the
                                    one used when a stored offline frame arrives
                                    for a peer whose key is not held yet

A client that reads an Ed25519 key as X25519 derives a different agreement key,
and therefore a DIFFERENT safety number from its peer. The two users compare
their numbers, the numbers do not match, and verification cannot be completed by
anyone -- which is exactly the reported symptom, online and offline.

These tests drive the real ChatServer over real WebSockets. Nothing is mocked.
They assert the invariant at the protocol boundary rather than re-testing the
safety-number function, because the function was never the part that was wrong.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
import websockets
from websockets.asyncio.server import serve

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from crypto_core import safety_number                      # noqa: E402
from server import ChatServer, Storage                     # noqa: E402
from x3dh import identity_to_x25519_public                 # noqa: E402

from nacl.signing import SigningKey                        # noqa: E402

PORT = 8871


# ---------------------------------------------------------------------------
# The client's rule, transcribed. This mirrors CryptoBox::agreementKeyFor in
# client/src/cryptobox.cpp byte for byte: an "ed25519" key is converted, an
# "x25519" or absent type is taken as already being an agreement key, and an
# unknown type is never guessed at.
# ---------------------------------------------------------------------------
def agreement_key_for(published: bytes, ik_type: str | None) -> bytes:
    if len(published) != 32:
        raise ValueError("identity key must be 32 bytes")
    if ik_type == "ed25519":
        return identity_to_x25519_public(published)
    if ik_type in (None, "", "x25519"):
        return published
    raise ValueError(f"unknown ik_type {ik_type!r}")


class V2Identity:
    """A version 2 account: an Ed25519 signing key, publishing the Ed25519
    public key and deriving the X25519 agreement key from it -- exactly what
    CryptoBox does for a v2 identity."""

    def __init__(self) -> None:
        self._sk = SigningKey.generate()

    @property
    def published(self) -> bytes:
        return bytes(self._sk.verify_key)

    @property
    def agreement(self) -> bytes:
        return identity_to_x25519_public(self.published)


async def _drain(ws, seconds: float = 0.4) -> list[dict]:
    out: list[dict] = []
    loop = asyncio.get_event_loop()
    deadline = loop.time() + seconds
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError):
            break
        if isinstance(raw, bytes):
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            pass
    return out


async def _login(uri: str, nick: str, ident: V2Identity):
    ws = await websockets.connect(uri)
    await ws.send(json.dumps({
        "type": "hello",
        "nick": nick,
        "pubkey": ident.published.hex(),
        "ik_type": "ed25519",
    }))
    frames = await _drain(ws)
    return ws, frames


def _first(frames, typ):
    for f in frames:
        if f.get("type") == typ:
            return f
    return None


# ===========================================================================


@pytest.mark.asyncio
async def test_every_key_delivery_path_states_the_type(tmp_path):
    """The dump, the push and the on-demand reply must each say which kind of
    identity key they are serving -- and the type must be the truth."""
    storage = Storage(str(tmp_path / "ktype.db"))
    server = ChatServer(storage)
    alice, bob = V2Identity(), V2Identity()

    async with serve(server.handle, "127.0.0.1", PORT):
        uri = f"ws://127.0.0.1:{PORT}"

        # Alice first. She is online and therefore receives the PUSH when Bob
        # arrives; Bob, arriving second, receives the DUMP. That asymmetry is
        # the whole bug: which client got which frame decided whether its copy
        # of the other's key was usable.
        ws_a, _ = await _login(uri, "alice", alice)
        ws_b, bob_login = await _login(uri, "bob", bob)

        # 1. The bulk directory dump Bob received on login.
        dump = _first(bob_login, "keys")
        assert dump is not None, "no directory dump on login"
        assert dump["keys"]["alice"] == alice.published.hex()
        assert dump["key_types"]["alice"] == "ed25519", (
            "the dump must tag alice's key as ed25519")

        # 2. The unsolicited push Alice received when Bob logged in.
        push = _first(await _drain(ws_a), "key_update")
        assert push is not None, "no key_update push to the already-online peer"
        assert push["nick"] == "bob"
        assert push["pubkey"] == bob.published.hex()
        assert push.get("ik_type") == "ed25519", (
            "the key_update push must tag the key type")

        # 3. The on-demand reply. THIS is the one that carried no type, so a
        #    client had nothing to convert by and fell back to reading an
        #    Ed25519 key as though it were an agreement key.
        await ws_b.send(json.dumps({"type": "getkey", "nick": "alice"}))
        reply = _first(await _drain(ws_b), "key")
        assert reply is not None, "no reply to getkey"
        assert reply["pubkey"] == alice.published.hex()
        assert reply.get("ik_type") == "ed25519", (
            "the getkey reply must tag the key type -- without it the "
            "on-demand path (used for offline delivery) guesses")

        await ws_a.close()
        await ws_b.close()


@pytest.mark.asyncio
async def test_both_sides_derive_the_same_safety_number(tmp_path):
    """The property the user actually depends on: whatever route each side
    learned the other's key by, the two numbers must agree."""
    storage = Storage(str(tmp_path / "sn.db"))
    server = ChatServer(storage)
    alice, bob = V2Identity(), V2Identity()

    async with serve(server.handle, "127.0.0.1", PORT):
        uri = f"ws://127.0.0.1:{PORT}"
        ws_a, _ = await _login(uri, "alice", alice)
        ws_b, bob_login = await _login(uri, "bob", bob)

        # Bob learned alice through the DUMP.
        dump = _first(bob_login, "keys")
        bob_view_of_alice = agreement_key_for(
            bytes.fromhex(dump["keys"]["alice"]),
            dump["key_types"]["alice"])

        # Alice learned bob through the PUSH.
        push = _first(await _drain(ws_a), "key_update")
        alice_view_of_bob = agreement_key_for(
            bytes.fromhex(push["pubkey"]), push.get("ik_type"))

        # Each side holds the other's true agreement key...
        assert bob_view_of_alice == alice.agreement
        assert alice_view_of_bob == bob.agreement

        # ...so the numbers they show their users are the same string.
        alice_number = safety_number(alice.agreement, alice_view_of_bob)
        bob_number = safety_number(bob.agreement, bob_view_of_alice)
        assert alice_number == bob_number

        # And the on-demand route agrees with the other two.
        await ws_b.send(json.dumps({"type": "getkey", "nick": "alice"}))
        reply = _first(await _drain(ws_b), "key")
        on_demand = agreement_key_for(
            bytes.fromhex(reply["pubkey"]), reply.get("ik_type"))
        assert on_demand == alice.agreement
        assert safety_number(bob.agreement, on_demand) == bob_number

        await ws_a.close()
        await ws_b.close()


@pytest.mark.asyncio
async def test_untagged_key_would_break_verification(tmp_path):
    """A deliberate mutation, so this module fails if the tag is ever dropped
    again rather than passing vacuously.

    Reading the published Ed25519 key as though it were an agreement key -- what
    a client does when the relay omits the type -- must produce a DIFFERENT
    number from the peer's. This is the defect, reproduced on purpose.
    """
    storage = Storage(str(tmp_path / "mutate.db"))
    server = ChatServer(storage)
    alice, bob = V2Identity(), V2Identity()

    async with serve(server.handle, "127.0.0.1", PORT):
        uri = f"ws://127.0.0.1:{PORT}"
        ws_a, _ = await _login(uri, "alice", alice)
        ws_b, bob_login = await _login(uri, "bob", bob)

        reply_key = bytes.fromhex(
            _first(bob_login, "keys")["keys"]["alice"])

        correct = agreement_key_for(reply_key, "ed25519")
        untagged = agreement_key_for(reply_key, None)   # the old behaviour

        assert correct != untagged
        alice_number = safety_number(alice.agreement, bob.agreement)
        assert safety_number(bob.agreement, correct) == alice_number
        assert safety_number(bob.agreement, untagged) != alice_number

        await ws_a.close()
        await ws_b.close()


# ===========================================================================
#  A RELAY THAT STATES NOTHING
#
#  The tests above assume the relay tags its keys. A deployed relay running a
#  build older than the X3DH work does not: it omits "key_types" entirely while
#  its users publish Ed25519 identities, and the client's legacy fallback --
#  "no type means x25519" -- then stores the wrong form for every peer. Both
#  screens show a safety number derived from mismatched key forms, so they never
#  agree; the verifyack binding fails in both directions, so the gate never
#  closes. Online and offline alike, because both read the same map.
#
#  The same relay hands over what is needed to detect it. Self-exclusion from
#  the directory arrived with "key_types", so a relay missing the field also
#  sends the requester its OWN entry -- and the client knows both forms of its
#  own key locally. Comparing them settles which form this relay publishes.
# ===========================================================================


def stale_relay_dump(directory: dict[str, V2Identity], requester: str) -> dict:
    """What a pre-X3DH relay sends: published (Ed25519) keys, no "key_types",
    and the requester's own entry left in."""
    return {
        "type": "keys",
        "keys": {nick: ident.published.hex()
                 for nick, ident in directory.items()},
        # no "key_types"
    }


def infer_untagged_form(dump: dict, me: str, mine: V2Identity) -> str:
    """The client's rule, transcribed from the "keys" handler in
    client/src/chatclient.cpp."""
    if "key_types" in dump:
        return "stated"
    entry = dump["keys"].get(me)
    if entry is None:
        return "unknown"          # nothing to calibrate against
    if entry == mine.published.hex():
        return "ed25519"          # relay publishes Ed25519 and tags nothing
    if entry == mine.agreement.hex():
        return "x25519"           # genuinely a legacy X25519 relay
    return "unknown"


def read_dump(dump: dict, me: str, mine: V2Identity) -> dict[str, bytes]:
    """m_peerKeys as the patched client would build it."""
    inferred = infer_untagged_form(dump, me, mine)
    types = dump.get("key_types", {})
    out = {}
    for nick, published in dump["keys"].items():
        if nick == me:
            continue              # we are not our own peer
        ik_type = types.get(nick) or (
            inferred if inferred in ("ed25519", "x25519") else None)
        out[nick] = agreement_key_for(bytes.fromhex(published), ik_type)
    return out


def test_a_stale_relay_is_detected_from_our_own_entry():
    alice, bob = V2Identity(), V2Identity()
    dump = stale_relay_dump({"alice": alice, "bob": bob}, "alice")
    assert infer_untagged_form(dump, "alice", alice) == "ed25519"


def test_the_requester_is_not_stored_as_its_own_peer():
    alice, bob = V2Identity(), V2Identity()
    dump = stale_relay_dump({"alice": alice, "bob": bob}, "alice")
    assert "alice" not in read_dump(dump, "alice", alice)


def test_both_sides_agree_against_a_stale_relay():
    """The property that was broken: two devices, one un-updated relay, one
    safety number."""
    alice, bob = V2Identity(), V2Identity()
    directory = {"alice": alice, "bob": bob}

    alice_view = read_dump(stale_relay_dump(directory, "alice"), "alice", alice)
    bob_view = read_dump(stale_relay_dump(directory, "bob"), "bob", bob)

    assert alice_view["bob"] == bob.agreement
    assert bob_view["alice"] == alice.agreement
    assert (safety_number(alice.agreement, alice_view["bob"])
            == safety_number(bob.agreement, bob_view["alice"]))


def test_the_old_reading_really_did_break_it():
    """A deliberate mutation: without the inference, the same dump produces two
    different numbers. Keeps the test above from passing vacuously."""
    alice, bob = V2Identity(), V2Identity()
    dump_a = stale_relay_dump({"alice": alice, "bob": bob}, "alice")
    legacy_view_of_bob = agreement_key_for(
        bytes.fromhex(dump_a["keys"]["bob"]), None)   # the pre-fix reading
    assert legacy_view_of_bob != bob.agreement
    assert (safety_number(alice.agreement, legacy_view_of_bob)
            != safety_number(bob.agreement, alice.agreement))


def test_a_genuinely_legacy_x25519_relay_is_not_misread():
    """No false positive. A relay serving X25519 agreement keys untagged must
    keep the legacy reading -- inferring Ed25519 there would break a case that
    works today."""
    alice, bob = V2Identity(), V2Identity()
    dump = {
        "type": "keys",
        "keys": {"alice": alice.agreement.hex(), "bob": bob.agreement.hex()},
    }
    assert infer_untagged_form(dump, "alice", alice) == "x25519"
    assert read_dump(dump, "alice", alice)["bob"] == bob.agreement


def test_a_relay_that_states_types_is_left_alone():
    """When the relay does its job the inference must not engage at all."""
    alice, bob = V2Identity(), V2Identity()
    dump = {
        "type": "keys",
        "keys": {"bob": bob.published.hex()},
        "key_types": {"bob": "ed25519"},
    }
    assert infer_untagged_form(dump, "alice", alice) == "stated"
    assert read_dump(dump, "alice", alice)["bob"] == bob.agreement


# --- the C++ must actually carry the rule ----------------------------------

CHATCLIENT = REPO_ROOT / "client" / "src" / "chatclient.cpp"


def test_the_client_applies_the_inference_on_both_key_paths():
    src = CHATCLIENT.read_text(encoding="utf-8", errors="replace")
    assert src.count("m_relayServesUntaggedEd") >= 4, (
        "the learned relay convention is not consulted on both the bulk dump "
        "and the single-key path"
    )
    assert "if (!m_nick.isEmpty() && peer == m_nick)" in src, (
        "the directory loop no longer skips the requester's own entry"
    )
