"""
test_verification_relay.py -- the two frames the bilateral gate depends on.

The send gate refuses to move text or files until BOTH parties have confirmed
the safety number. Each side learns of the other's confirmation from a
'verifyack', and a side whose ack was ignored (because it attested a
since-replaced identity) is prompted to resend by a 'verify_resync'.

That makes these two frames load-bearing. If a verifyack is lost, a
conversation never opens. If a verify_resync is lost, a conversation that has
stalled can never recover -- which is exactly what happened while server.py had
no branch for it and logged "Unknown message type: 'verify_resync'" instead.

The two have DELIBERATELY different delivery semantics, and the tests below pin
that difference:

  * verifyack   is a durable FACT      -> store-and-forward, survives offline
  * verify_resync is a transient ASK   -> live-only, dropped if nobody is there

These run against the real ChatServer over real websockets. Nothing is mocked.
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

from crypto_core import Identity           # noqa: E402
from server import ChatServer, Storage     # noqa: E402

PORT = 8821


async def _drain(ws, seconds: float = 0.25) -> list[dict]:
    """Collect whatever the server pushes, then stop. Returns parsed frames."""
    out: list[dict] = []
    deadline = asyncio.get_event_loop().time() + seconds
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError):
            break
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            pass
    return out


async def _login(uri: str, nick: str, ident: Identity):
    ws = await websockets.connect(uri)
    await ws.send(json.dumps({
        "type": "hello", "nick": nick, "pubkey": ident.public_bytes().hex(),
    }))
    await _drain(ws)          # discard the key dump / presence / history burst
    return ws


class _Relay:
    def __init__(self, tmp_path, port=PORT):
        self.db = str(Path(tmp_path) / "verify.db")
        self.port = port

    async def __aenter__(self):
        self.storage = Storage(self.db)
        self.server = ChatServer(self.storage)
        self._ctx = serve(self.server.handle, "localhost", self.port)
        self._srv = await self._ctx.__aenter__()
        self.uri = f"ws://localhost:{self.port}"
        return self

    async def __aexit__(self, *exc):
        await self._ctx.__aexit__(*exc)
        self.storage.close()      # release the file before pytest reaps tmp_path


# --------------------------------------------------------------------------
# verifyack: a durable fact
# --------------------------------------------------------------------------

async def test_verifyack_reaches_an_online_peer(tmp_path):
    async with _Relay(tmp_path) as r:
        alice, bob = Identity.generate(), Identity.generate()
        bob_ws = await _login(r.uri, "bob", bob)
        alice_ws = await _login(r.uri, "alice", alice)
        await _drain(bob_ws)

        await alice_ws.send(json.dumps({
            "type": "verifyack", "to": "bob",
            "peer_identity": bob.public_bytes().hex(),
        }))
        frames = await _drain(bob_ws, 0.5)

        acks = [f for f in frames if f.get("type") == "verifyack"]
        assert acks, f"bob never received the verifyack; saw {[f.get('type') for f in frames]}"
        assert acks[0]["from"] == "alice"

        await alice_ws.close()
        await bob_ws.close()


async def test_verifyack_survives_the_peer_being_offline(tmp_path):
    """
    THE POINT OF STORE-AND-FORWARD. Bob is logged out when Alice confirms. If
    the ack were dropped, Bob's half of the gate could never open and the
    conversation would be permanently stuck -- with no user-visible cause.
    """
    async with _Relay(tmp_path) as r:
        alice, bob = Identity.generate(), Identity.generate()

        # Bob registers, then leaves.
        bob_ws = await _login(r.uri, "bob", bob)
        await bob_ws.close()
        await asyncio.sleep(0.1)

        alice_ws = await _login(r.uri, "alice", alice)
        await alice_ws.send(json.dumps({
            "type": "verifyack", "to": "bob",
            "peer_identity": bob.public_bytes().hex(),
        }))
        await asyncio.sleep(0.2)

        # Bob returns and must be told.
        bob_ws2 = await websockets.connect(r.uri)
        await bob_ws2.send(json.dumps({
            "type": "hello", "nick": "bob", "pubkey": bob.public_bytes().hex(),
        }))
        frames = await _drain(bob_ws2, 0.6)

        acks = [f for f in frames if f.get("type") == "verifyack"]
        assert acks, (
            "bob logged back in and was never told alice had verified him; "
            f"saw {[f.get('type') for f in frames]}"
        )
        assert acks[0]["from"] == "alice"

        await alice_ws.close()
        await bob_ws2.close()


async def test_the_sender_cannot_forge_the_from_field(tmp_path):
    """
    Anti-spoofing. The authoritative sender is the authenticated nick, never
    whatever the frame claims -- otherwise anyone could make a peer believe a
    third party had verified them, and open a gate that should stay shut.
    """
    async with _Relay(tmp_path) as r:
        alice, bob = Identity.generate(), Identity.generate()
        bob_ws = await _login(r.uri, "bob", bob)
        alice_ws = await _login(r.uri, "alice", alice)
        await _drain(bob_ws)

        await alice_ws.send(json.dumps({
            "type": "verifyack", "to": "bob", "from": "mallory",
            "peer_identity": bob.public_bytes().hex(),
        }))
        frames = await _drain(bob_ws, 0.5)

        acks = [f for f in frames if f.get("type") == "verifyack"]
        assert acks, "no verifyack arrived at all"
        assert acks[0]["from"] == "alice", (
            f"spoofed sender survived the relay: {acks[0]['from']}"
        )

        await alice_ws.close()
        await bob_ws.close()


# --------------------------------------------------------------------------
# verify_resync: a transient ask
# --------------------------------------------------------------------------

async def test_verify_resync_reaches_an_online_peer(tmp_path):
    """The regression. This frame used to be dropped as an unknown type."""
    async with _Relay(tmp_path) as r:
        alice, bob = Identity.generate(), Identity.generate()
        bob_ws = await _login(r.uri, "bob", bob)
        alice_ws = await _login(r.uri, "alice", alice)
        await _drain(bob_ws)

        await alice_ws.send(json.dumps({"type": "verify_resync", "to": "bob"}))
        frames = await _drain(bob_ws, 0.5)

        got = [f for f in frames if f.get("type") == "verify_resync"]
        assert got, f"verify_resync never arrived; saw {[f.get('type') for f in frames]}"
        assert got[0]["from"] == "alice"

        await alice_ws.close()
        await bob_ws.close()


async def test_verify_resync_is_not_replayed_to_a_returning_peer(tmp_path):
    """
    Live-only, by design. A resync is a request rather than an attestation:
    stale the moment it is missed, and emitted once per peer on every login, so
    persisting them would accumulate without bound. Nothing is lost, because a
    peer that comes back emits its own resyncs and recovers the episode from the
    other direction.
    """
    async with _Relay(tmp_path) as r:
        alice, bob = Identity.generate(), Identity.generate()

        bob_ws = await _login(r.uri, "bob", bob)
        await bob_ws.close()
        await asyncio.sleep(0.1)

        alice_ws = await _login(r.uri, "alice", alice)
        await alice_ws.send(json.dumps({"type": "verify_resync", "to": "bob"}))
        await asyncio.sleep(0.2)

        bob_ws2 = await websockets.connect(r.uri)
        await bob_ws2.send(json.dumps({
            "type": "hello", "nick": "bob", "pubkey": bob.public_bytes().hex(),
        }))
        frames = await _drain(bob_ws2, 0.5)

        assert not [f for f in frames if f.get("type") == "verify_resync"], (
            "a verify_resync was stored and replayed; it is meant to be ephemeral"
        )

        await alice_ws.close()
        await bob_ws2.close()


async def test_verification_frames_require_authentication(tmp_path):
    """Neither frame may be sent before a hello."""
    async with _Relay(tmp_path) as r:
        for mtype in ("verifyack", "verify_resync"):
            ws = await websockets.connect(r.uri)
            await ws.send(json.dumps({"type": mtype, "to": "bob"}))
            frames = await _drain(ws, 0.4)
            errors = [f for f in frames
                      if f.get("type") == "error"
                      or "log in" in json.dumps(f).lower()]
            assert errors, f"{mtype} was accepted without logging in: {frames}"
            await ws.close()
