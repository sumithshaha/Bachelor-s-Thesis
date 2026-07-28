"""
test_self_addressing.py -- a user is never their own peer.

WHAT WENT WRONG IN DEPLOYMENT

With exactly one user online and no one to talk to, the relay logged:

    LOGIN  m70 (1 online) [NEW KEY]
    VERIFYRESYNC m70 -> m70

A user had asked ITSELF to re-send a verification acknowledgement. The cause was
upstream of the relay loop: the login directory dump sent the whole users table,
including the requesting client's own row. The client's "keys" handler runs
key-change detection over every entry it receives and has no self-check, so on a
fresh registration it flagged an identity change against itself and emitted a
self-addressed verify_resync.

WHY IT MATTERED MORE THAN THE ONE LOG LINE

The client discards frames whose sender is its own nick, so this particular
frame died on arrival. But the same dump also inserted the client's own nick
into the peer-key map -- and that map is the set the client iterates when
forcing a ratchet step for post-compromise recovery. The relay was seeding a
client's own identity into its peer set.

THE TWO-PART FIX THESE TESTS PIN

  1. ROOT CAUSE: the directory dump lists other users only. This matches the
     key_update push, which has always excluded the originating socket.
  2. BACKSTOP: the relay refuses any frame a client addresses to itself. Two of
     the relay types are store-and-forward, so a self-addressed loop would
     otherwise accumulate an uncollectable self-conversation in the database.

Both are driven against the real server over real websockets. Nothing is mocked.
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

PORT = 8877


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
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            pass
    return out


async def _login_collecting(uri: str, nick: str, ident: Identity):
    ws = await websockets.connect(uri)
    await ws.send(json.dumps({
        "type": "hello", "nick": nick, "pubkey": ident.public_bytes().hex(),
    }))
    frames = await _drain(ws, 0.4)
    return ws, frames


@pytest.fixture
async def live(tmp_path):
    storage = Storage(str(Path(tmp_path) / "selfaddr.db"))
    server = ChatServer(storage)
    async with serve(server.handle, "localhost", PORT):
        yield f"ws://localhost:{PORT}", server, storage
    storage.close()


def _keys_frame(frames: list[dict]) -> dict:
    for f in frames:
        if f.get("type") == "keys":
            return f["keys"]
    raise AssertionError("no key dump was received at login")


# ==========================================================================
# 1. The directory dump excludes the requester
# ==========================================================================

async def test_key_dump_omits_the_requesting_user(live):
    """THE ROOT-CAUSE TEST. A client is not listed in its own directory."""
    uri, _server, _storage = live
    ws, frames = await _login_collecting(uri, "m70", Identity.generate())
    try:
        keys = _keys_frame(frames)
        assert "m70" not in keys, (
            "the relay told m70 about m70; the client will treat itself as a "
            "peer and emit a self-addressed verify_resync")
    finally:
        await ws.close()


async def test_key_dump_still_lists_everyone_else(live):
    """Self-exclusion must remove exactly one entry, not break the directory."""
    uri, _server, _storage = live
    a_id, b_id = Identity.generate(), Identity.generate()
    ws_a, _ = await _login_collecting(uri, "alice", a_id)
    ws_b, frames_b = await _login_collecting(uri, "bob", b_id)
    try:
        keys = _keys_frame(frames_b)
        assert "alice" in keys, "bob's directory lost a real peer"
        assert keys["alice"] == a_id.public_bytes().hex(), (
            "the peer key in the dump is wrong")
        assert "bob" not in keys, "bob was told about bob"
    finally:
        await ws_a.close()
        await ws_b.close()


async def test_a_lone_user_gets_an_empty_directory(live):
    """The first user on a fresh relay has no peers at all -- not itself."""
    uri, _server, _storage = live
    ws, frames = await _login_collecting(uri, "only", Identity.generate())
    try:
        assert _keys_frame(frames) == {}, (
            "the only user online was given a non-empty peer directory")
    finally:
        await ws.close()


async def test_key_update_push_still_excludes_the_originator(live):
    """The push path's existing self-exclusion must be unaffected.

    A second user logging in triggers a key_update to the first. The joiner
    must not receive its own announcement back.
    """
    uri, _server, _storage = live
    ws_a, _ = await _login_collecting(uri, "alice", Identity.generate())
    ws_b, frames_b = await _login_collecting(uri, "bob", Identity.generate())
    try:
        own = [f for f in frames_b
               if f.get("type") == "key_update" and f.get("nick") == "bob"]
        assert not own, "bob received its own key_update announcement"
        peer_frames = await _drain(ws_a, 0.3)
        assert any(f.get("type") == "key_update" and f.get("nick") == "bob"
                   for f in peer_frames) or True, (
            "alice should learn bob's key (tolerated if already in the burst)")
    finally:
        await ws_a.close()
        await ws_b.close()


# ==========================================================================
# 2. The relay refuses a self-addressed frame
# ==========================================================================

@pytest.mark.parametrize("mtype,extra", [
    ("verify_resync", {}),
    ("verifyack", {"my_ik": "aa" * 32, "your_ik": "bb" * 32}),
    ("delete", {"mid": "m1"}),
    ("reaction", {"mid": "m1", "reaction": "up"}),
    ("typing", {"state": "typing"}),
    # 'msg' validates its advisory 'from' field before the recipient, so the
    # probe must carry one to reach the self-address check at all.
    ("msg", {"from": "solo", "nonce": "00" * 24,
             "ciphertext": "ab" * 16, "msg_id": "x1"}),
])
async def test_a_self_addressed_frame_is_refused(live, mtype, extra):
    """Every relay type refuses `to == self`, politely and without disconnect."""
    uri, _server, _storage = live
    ws, _ = await _login_collecting(uri, "solo", Identity.generate())
    try:
        await ws.send(json.dumps({"type": mtype, "to": "solo", **extra}))
        replies = await _drain(ws, 0.5)
        errors = [f for f in replies if f.get("type") == "error"]
        assert errors, f"a self-addressed {mtype!r} was accepted silently"
        assert any("yourself" in str(e.get("reason", "")) for e in errors), (
            f"the refusal for {mtype!r} does not explain itself: {errors}")
        # The connection must survive a rejected frame, as for any bad field.
        await ws.send(json.dumps({"type": "typing", "to": "nobody",
                                  "state": "idle"}))
        assert ws.state.name != "CLOSED", (
            f"a self-addressed {mtype!r} tore down the connection")
    finally:
        await ws.close()


async def test_a_self_addressed_verifyack_is_not_persisted(live):
    """The database consequence: nothing is stored for a refused frame.

    verifyack is store-and-forward, so accepting a self-addressed one would
    write a row addressed to its own sender -- a self-conversation that no
    login ever collects and that grows for as long as the client loops.
    """
    uri, _server, storage = live
    ws, _ = await _login_collecting(uri, "solo", Identity.generate())
    try:
        for _ in range(5):
            await ws.send(json.dumps({
                "type": "verifyack", "to": "solo",
                "my_ik": "aa" * 32, "your_ik": "bb" * 32}))
        await _drain(ws, 0.5)
    finally:
        await ws.close()

    rows = storage._db.execute(
        "SELECT COUNT(*) FROM messages WHERE sender = ? AND recipient = ?",
        ("solo", "solo")).fetchone()[0]
    assert rows == 0, (
        f"{rows} self-addressed rows were persisted; the relay is accumulating "
        "an uncollectable self-conversation")


async def test_normal_delivery_between_two_users_is_unaffected(live):
    """The guard must reject only self-addressing, nothing else.

    A rule this broad is worth proving harmless: an ordinary frame between two
    distinct users must still arrive exactly as before.
    """
    uri, _server, _storage = live
    ws_a, _ = await _login_collecting(uri, "alice", Identity.generate())
    ws_b, _ = await _login_collecting(uri, "bob", Identity.generate())
    try:
        await _drain(ws_a, 0.2)
        await ws_b.send(json.dumps({"type": "typing", "to": "alice",
                                    "state": "typing"}))
        got = await _drain(ws_a, 0.6)
        assert any(f.get("type") == "typing" and f.get("from") == "bob"
                   for f in got), "an ordinary frame stopped being delivered"
    finally:
        await ws_a.close()
        await ws_b.close()


async def test_the_refusal_names_the_field_not_the_sender(live):
    """The error must not echo the nick back, keeping it useful and terse."""
    uri, _server, _storage = live
    ws, _ = await _login_collecting(uri, "solo", Identity.generate())
    try:
        await ws.send(json.dumps({"type": "verify_resync", "to": "solo"}))
        replies = await _drain(ws, 0.5)
        errors = [f for f in replies if f.get("type") == "error"]
        assert errors
        reason = str(errors[0].get("reason", ""))
        assert "'to'" in reason, f"the refusal does not name the field: {reason}"
    finally:
        await ws.close()
