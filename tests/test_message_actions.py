"""
test_message_actions.py -- delete, reaction, and typing: three delivery rules.

Three small control frames sit on top of the message relay, and each has a
DELIBERATELY different delivery rule that the client depends on:

  * delete   (retract a message)  -- store-and-forward: an offline recipient
                                     must still learn the message was retracted,
                                     so it is queued and replayed on next login.
  * reaction (agree / disagree)   -- store-and-forward, same as delete: a quick
                                     acknowledgement that must survive offline.
  * typing   (typing / idle hint) -- LIVE ONLY: an offline peer has no use for a
                                     stale "was typing", so it is relayed to an
                                     online recipient and otherwise dropped.

All three share the anti-spoofing rule of the text path: the `from` field is
advisory and is overwritten with the socket's authenticated identity.

None of these had a dedicated test. The conversation-level tests never send
them, so a regression -- a delete that stops surviving offline, a typing hint
that starts getting persisted and replays a phantom indicator, a spoofable
`from` -- would be invisible to the rest of the suite. Each rule below was
confirmed against the running server. Nothing is mocked.
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

from crypto_core import Identity            # noqa: E402
from server import ChatServer, Storage      # noqa: E402

PORT = 8871


async def _drain(ws, seconds: float = 0.4) -> list[dict]:
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
    """Log in and return the socket, discarding the initial burst."""
    ws = await websockets.connect(uri)
    await ws.send(json.dumps({
        "type": "hello", "nick": nick, "pubkey": ident.public_bytes().hex(),
    }))
    await _drain(ws, 0.3)
    return ws


async def _login_collecting(uri: str, nick: str, ident: Identity):
    """Log in and return (socket, all_frames) -- for asserting on the replay.

    The login burst (key dump, presence, and any store-and-forward replay)
    arrives over a short window; a single short drain can close before the
    replayed frames land, so this collects across several reads.
    """
    ws = await websockets.connect(uri)
    await ws.send(json.dumps({
        "type": "hello", "nick": nick, "pubkey": ident.public_bytes().hex(),
    }))
    frames: list[dict] = []
    for _ in range(5):
        frames += await _drain(ws, 0.4)
    return ws, frames


def _of_type(frames, typ):
    return [f for f in frames if f.get("type") == typ]


class _Relay:
    def __init__(self, tmp_path, port=PORT):
        self.db = str(Path(tmp_path) / "actions.db")
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
        self.storage.close()


# ==========================================================================
# delete -- store-and-forward
# ==========================================================================

async def test_delete_reaches_an_online_recipient(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        bob = await _login(r.uri, "bob", Identity.generate())
        await _drain(bob)

        await alice.send(json.dumps({
            "type": "delete", "from": "alice", "to": "bob", "mid": "m-1",
        }))
        dels = _of_type(await _drain(bob, 0.5), "delete")
        assert dels, "bob did not receive the delete"
        assert dels[0]["mid"] == "m-1"
        assert dels[0]["from"] == "alice"
        await alice.close()
        await bob.close()


async def test_delete_survives_the_recipient_being_offline(tmp_path):
    """THE STORE-AND-FORWARD POINT.

    Bob is offline when Alice retracts. The retraction must be queued and
    replayed on Bob's next login -- otherwise Bob would keep showing a message
    the sender has taken back.
    """
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        # bob never connected; send to him offline.
        await alice.send(json.dumps({
            "type": "delete", "from": "alice", "to": "bob", "mid": "gone",
        }))
        await asyncio.sleep(0.3)

        bob, frames = await _login_collecting(r.uri, "bob", Identity.generate())
        dels = _of_type(frames, "delete")
        assert dels, f"delete not replayed on login; saw {[f.get('type') for f in frames]}"
        assert dels[0]["mid"] == "gone"
        await alice.close()
        await bob.close()


async def test_delete_spoofed_from_is_overridden(tmp_path):
    """The authenticated identity wins, exactly as for a text message."""
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        bob = await _login(r.uri, "bob", Identity.generate())
        await _drain(bob)

        await alice.send(json.dumps({
            "type": "delete", "from": "mallory", "to": "bob", "mid": "m-2",
        }))
        dels = _of_type(await _drain(bob, 0.5), "delete")
        assert dels and dels[0]["from"] == "alice", "spoofed sender not overridden"
        await alice.close()
        await bob.close()


# ==========================================================================
# reaction -- store-and-forward, carries a 'kind'
# ==========================================================================

async def test_reaction_reaches_an_online_recipient_with_its_kind(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        bob = await _login(r.uri, "bob", Identity.generate())
        await _drain(bob)

        await alice.send(json.dumps({
            "type": "reaction", "from": "alice", "to": "bob",
            "mid": "m-1", "kind": "up",
        }))
        rx = _of_type(await _drain(bob, 0.5), "reaction")
        assert rx, "bob did not receive the reaction"
        assert rx[0]["kind"] == "up"
        assert rx[0]["mid"] == "m-1"
        await alice.close()
        await bob.close()


async def test_reaction_survives_offline_recipient(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        await alice.send(json.dumps({
            "type": "reaction", "from": "alice", "to": "bob",
            "mid": "m-7", "kind": "down",
        }))
        await asyncio.sleep(0.3)

        bob, frames = await _login_collecting(r.uri, "bob", Identity.generate())
        rx = _of_type(frames, "reaction")
        assert rx, "reaction not replayed on login"
        assert rx[0]["kind"] == "down"
        await alice.close()
        await bob.close()


async def test_reaction_retraction_empty_kind_is_carried(tmp_path):
    """An empty kind (retract a reaction) must relay too, not be dropped."""
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        bob = await _login(r.uri, "bob", Identity.generate())
        await _drain(bob)

        await alice.send(json.dumps({
            "type": "reaction", "from": "alice", "to": "bob",
            "mid": "m-1", "kind": "",
        }))
        rx = _of_type(await _drain(bob, 0.5), "reaction")
        assert rx, "an empty-kind reaction (retraction) was not delivered"
        assert rx[0]["kind"] == ""
        await alice.close()
        await bob.close()


# ==========================================================================
# typing -- live only, never stored
# ==========================================================================

async def test_typing_reaches_an_online_recipient(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        bob = await _login(r.uri, "bob", Identity.generate())
        await _drain(bob)

        await alice.send(json.dumps({
            "type": "typing", "from": "alice", "to": "bob", "state": "typing",
        }))
        ty = _of_type(await _drain(bob, 0.5), "typing")
        assert ty, "bob did not receive the typing hint"
        assert ty[0]["state"] == "typing"
        await alice.close()
        await bob.close()


async def test_typing_to_offline_recipient_is_dropped_not_stored(tmp_path):
    """THE LIVE-ONLY POINT.

    A typing hint sent while Bob is offline must NOT be stored, or Bob would
    get a phantom "was typing" replayed on login. After Bob connects, he must
    receive no typing frame at all.
    """
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        # bob offline
        await alice.send(json.dumps({
            "type": "typing", "from": "alice", "to": "bob", "state": "typing",
        }))
        await asyncio.sleep(0.3)

        bob, frames = await _login_collecting(r.uri, "bob", Identity.generate())
        assert _of_type(frames, "typing") == [], \
            "a typing hint was persisted and replayed -- it must be live-only"
        await alice.close()
        await bob.close()


async def test_typing_spoofed_from_is_overridden(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        bob = await _login(r.uri, "bob", Identity.generate())
        await _drain(bob)

        await alice.send(json.dumps({
            "type": "typing", "from": "eve", "to": "bob", "state": "typing",
        }))
        ty = _of_type(await _drain(bob, 0.5), "typing")
        assert ty and ty[0]["from"] == "alice", "spoofed sender not overridden"
        await alice.close()
        await bob.close()


# ==========================================================================
# shared: login gate
# ==========================================================================

@pytest.mark.parametrize("frame", [
    {"type": "delete", "to": "bob", "mid": "x"},
    {"type": "reaction", "to": "bob", "mid": "x", "kind": "up"},
    {"type": "typing", "to": "bob", "state": "typing"},
])
async def test_action_before_login_is_refused(tmp_path, frame):
    """None of the three may be sent by an anonymous socket."""
    async with _Relay(tmp_path) as r:
        ws = await websockets.connect(r.uri)          # no hello
        await ws.send(json.dumps(frame))
        errs = [f["reason"] for f in await _drain(ws)
                if f.get("type") == "error"]
        assert any("log in" in e for e in errs), (frame["type"], errs)
        await ws.close()
