"""
Robustness and adversarial tests for the chat server.

Where test_integration.py checks that the system works when everyone behaves,
this file checks that the server stays up and stays safe when clients DON'T
behave: malformed frames, missing fields, wrong-length keys, messages sent
before logging in, and attempts to impersonate another sender. A security
project has to defend against hostile input, not just demonstrate the happy
path, so these tests exist to back up the robustness claims made in the thesis.

The single most important property here is that no malformed frame ever
disconnects a client or crashes the handler. Each bad frame should earn a
single, specific 'error' reply and otherwise be ignored.

Run with:  pytest -v test_robustness.py
"""

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest
import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from crypto_core import Identity, derive_shared_key, encrypt, decrypt, Envelope  # noqa: E402
from server import ChatServer, Storage  # noqa: E402
from websockets.asyncio.server import serve  # noqa: E402


async def _drain(ws, timeout=0.15):
    """Swallow any frames already queued on a socket so a later recv() sees
    only the frame we are actually interested in."""
    while True:
        try:
            await asyncio.wait_for(ws.recv(), timeout=timeout)
        except asyncio.TimeoutError:
            return


async def _next_of_type(ws, mtype, timeout=1.0):
    """Return the next frame of a given type, or None if it never arrives."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            frame = json.loads(
                await asyncio.wait_for(ws.recv(), timeout=end - time.time()))
        except (asyncio.TimeoutError, Exception):
            return None
        if frame.get("type") == mtype:
            return frame
    return None


# Each tuple is (label, raw_frame_or_dict, expected_substring_in_error).
MALFORMED_FRAMES = [
    ("non-JSON text", "}{not json", "malformed JSON"),
    ("JSON array not object", "[1, 2, 3]", "must be a JSON object"),
    ("hello without pubkey", {"type": "hello", "nick": "x"}, "pubkey"),
    ("hello without nick", {"type": "hello", "pubkey": "aa" * 32}, "nick"),
    ("hello null nick", {"type": "hello", "nick": None, "pubkey": "aa" * 32}, "nick"),
    ("pubkey wrong length", {"type": "hello", "nick": "x", "pubkey": "aa" * 10}, "32 bytes"),
    ("pubkey bad hex", {"type": "hello", "nick": "x", "pubkey": "ZZ"}, "valid hex"),
    ("getkey without nick", {"type": "getkey"}, "nick"),
    ("unknown type", {"type": "banana"}, "unknown message type"),
    ("no type field", {"foo": "bar"}, "unknown message type"),
]


@pytest.mark.asyncio
async def test_malformed_frames_get_clean_errors(tmp_path):
    """Every malformed frame should return a structured error AND leave the
    connection open and usable afterwards."""
    storage = Storage(str(tmp_path / "r.db"))
    server = ChatServer(storage)
    async with serve(server.handle, "localhost", 8791):
        uri = "ws://localhost:8791"
        for label, frame, expected in MALFORMED_FRAMES:
            ws = await websockets.connect(uri)
            raw = frame if isinstance(frame, str) else json.dumps(frame)
            await ws.send(raw)
            reply = await _next_of_type(ws, "error", timeout=0.5)
            assert reply is not None, f"{label}: no error reply"
            assert expected in reply["reason"], (
                f"{label}: expected {expected!r} in {reply['reason']!r}")
            # The connection must still be alive: a valid hello now succeeds.
            await ws.send(json.dumps({
                "type": "hello", "nick": f"u_{label[:4]}",
                "pubkey": Identity.generate().public_bytes().hex()}))
            keys = await _next_of_type(ws, "keys", timeout=0.5)
            assert keys is not None, f"{label}: connection unusable after error"
            await ws.close()


@pytest.mark.asyncio
async def test_message_before_login_is_rejected(tmp_path):
    """An anonymous socket must not be able to inject messages."""
    storage = Storage(str(tmp_path / "r.db"))
    server = ChatServer(storage)
    async with serve(server.handle, "localhost", 8792):
        ws = await websockets.connect("ws://localhost:8792")
        await ws.send(json.dumps({
            "type": "msg", "from": "ghost", "to": "someone",
            "nonce": "00" * 12, "ct": "00" * 16, "ts": 1}))
        reply = await _next_of_type(ws, "error", timeout=0.5)
        assert reply is not None and "log in" in reply["reason"]
        await ws.close()


@pytest.mark.asyncio
async def test_sender_cannot_be_spoofed(tmp_path):
    """A client that logs in as 'alice' but stamps a message 'from: mallory'
    must have the sender overridden to its real, authenticated identity."""
    storage = Storage(str(tmp_path / "r.db"))
    server = ChatServer(storage)
    async with serve(server.handle, "localhost", 8793):
        uri = "ws://localhost:8793"
        alice, bob = Identity.generate(), Identity.generate()

        bob_ws = await websockets.connect(uri)
        await bob_ws.send(json.dumps({
            "type": "hello", "nick": "bob",
            "pubkey": bob.public_bytes().hex()}))
        await _drain(bob_ws)

        alice_ws = await websockets.connect(uri)
        await alice_ws.send(json.dumps({
            "type": "hello", "nick": "alice",
            "pubkey": alice.public_bytes().hex()}))
        await _drain(alice_ws)

        # Alice lies about who she is.
        key = derive_shared_key(alice, bob.public_bytes())
        env = encrypt(key, "spoof attempt")
        await alice_ws.send(json.dumps({
            "type": "msg", "from": "mallory", "to": "bob",
            "nonce": env.nonce.hex(), "ct": env.ciphertext.hex(), "ts": 1}))

        delivered = await _next_of_type(bob_ws, "msg", timeout=1.0)
        assert delivered is not None
        # The server must have corrected the forged sender.
        assert delivered["from"] == "alice", "sender spoofing was not blocked"
        await alice_ws.close()
        await bob_ws.close()


@pytest.mark.asyncio
async def test_offline_message_is_stored_and_replayed(tmp_path):
    """A message to an offline user is persisted and replayed when that user
    later logs in - nothing is silently dropped."""
    storage = Storage(str(tmp_path / "r.db"))
    server = ChatServer(storage)
    async with serve(server.handle, "localhost", 8794):
        uri = "ws://localhost:8794"
        alice, carol = Identity.generate(), Identity.generate()

        alice_ws = await websockets.connect(uri)
        await alice_ws.send(json.dumps({
            "type": "hello", "nick": "alice",
            "pubkey": alice.public_bytes().hex()}))
        await _drain(alice_ws)

        # Carol is not connected. Send to her anyway.
        key = derive_shared_key(alice, carol.public_bytes())
        env = encrypt(key, "for carol when she returns")
        await alice_ws.send(json.dumps({
            "type": "msg", "from": "alice", "to": "carol",
            "nonce": env.nonce.hex(), "ct": env.ciphertext.hex(), "ts": 1}))
        await asyncio.sleep(0.2)

        # Carol logs in and should receive the stored ciphertext as history.
        carol_ws = await websockets.connect(uri)
        await carol_ws.send(json.dumps({
            "type": "hello", "nick": "carol",
            "pubkey": carol.public_bytes().hex()}))
        replayed = await _next_of_type(carol_ws, "msg", timeout=1.0)
        assert replayed is not None, "offline message was not replayed"

        # And it must still decrypt correctly after its round trip through SQLite.
        carol_key = derive_shared_key(carol, alice.public_bytes())
        text = decrypt(carol_key, Envelope.from_hex(replayed))
        assert text == "for carol when she returns"
        await alice_ws.close()
        await carol_ws.close()


@pytest.mark.asyncio
async def test_duplicate_login_kicks_old_session(tmp_path):
    """Logging in twice with the same nick should disconnect the stale session
    so presence never lists a ghost."""
    storage = Storage(str(tmp_path / "r.db"))
    server = ChatServer(storage)
    async with serve(server.handle, "localhost", 8795):
        uri = "ws://localhost:8795"
        ident = Identity.generate()

        first = await websockets.connect(uri)
        await first.send(json.dumps({
            "type": "hello", "nick": "alice",
            "pubkey": ident.public_bytes().hex()}))
        await _drain(first)

        second = await websockets.connect(uri)
        await second.send(json.dumps({
            "type": "hello", "nick": "alice",
            "pubkey": ident.public_bytes().hex()}))
        await asyncio.sleep(0.3)

        # The first socket should now be closed by the server.
        with pytest.raises(Exception):
            await asyncio.wait_for(first.recv(), timeout=0.5)
        await second.close()
