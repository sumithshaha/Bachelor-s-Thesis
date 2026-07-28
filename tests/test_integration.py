"""
Integration test: end-to-end message flow through a real server.

This is the test that backs up the central claim of the thesis. It starts the
actual server, connects two clients (Alice and Bob), has Alice send Bob an
encrypted message, and then checks two things:

  1. Bob can decrypt the message and read it. (The system works.)
  2. The text the server logged and stored is NOT the plaintext. (The system
     is end-to-end encrypted: the server is blind to content.)

The second assertion is what separates this design from an ordinary TLS-only
chat application, where the server would see every message in the clear.

Run with:  pytest -v test_integration.py
"""

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest
import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from crypto_core import Identity, derive_shared_key, encrypt, decrypt  # noqa: E402
from server import ChatServer, Storage  # noqa: E402
from websockets.asyncio.server import serve  # noqa: E402


SECRET_MESSAGE = "Meet me at the harbour at midnight"


@pytest.mark.asyncio
async def test_server_only_sees_ciphertext(tmp_path, capsys):
    # ---- Start a real server on a throwaway in-memory-ish database --------
    db_path = str(tmp_path / "test.db")
    storage = Storage(db_path)
    server = ChatServer(storage)

    async with serve(server.handle, "localhost", 8799) as _:
        uri = "ws://localhost:8799"

        # ---- Both users create identities --------------------------------
        alice = Identity.generate()
        bob = Identity.generate()

        # ---- Bob logs in and waits for messages --------------------------
        bob_ws = await websockets.connect(uri)
        await bob_ws.send(json.dumps({
            "type": "hello", "nick": "bob",
            "pubkey": bob.public_bytes().hex(),
        }))
        # Drain Bob's initial keys/presence frames.
        await asyncio.sleep(0.1)
        while True:
            try:
                await asyncio.wait_for(bob_ws.recv(), timeout=0.1)
            except asyncio.TimeoutError:
                break

        # ---- Alice logs in -----------------------------------------------
        alice_ws = await websockets.connect(uri)
        await alice_ws.send(json.dumps({
            "type": "hello", "nick": "alice",
            "pubkey": alice.public_bytes().hex(),
        }))
        await asyncio.sleep(0.1)
        # Drain Alice's frames too.
        while True:
            try:
                await asyncio.wait_for(alice_ws.recv(), timeout=0.1)
            except asyncio.TimeoutError:
                break

        # ---- Alice encrypts for Bob and sends ----------------------------
        key_a = derive_shared_key(alice, bob.public_bytes())
        envelope = encrypt(key_a, SECRET_MESSAGE)
        await alice_ws.send(json.dumps({
            "type": "msg", "from": "alice", "to": "bob",
            "nonce": envelope.nonce.hex(),
            "ct": envelope.ciphertext.hex(),
            "ts": int(time.time() * 1000),
        }))

        # ---- Bob receives and decrypts -----------------------------------
        # Bob may receive presence updates (Alice coming online) before the
        # actual message, so skip frames until the message arrives.
        received = None
        for _ in range(10):
            raw = await asyncio.wait_for(bob_ws.recv(), timeout=2.0)
            frame = json.loads(raw)
            if frame.get("type") == "msg":
                received = frame
                break
        assert received is not None, "Bob never received the message"
        assert received["from"] == "alice"

        from crypto_core import Envelope
        key_b = derive_shared_key(bob, alice.public_bytes())
        recovered = decrypt(key_b, Envelope.from_hex(received))

        # 1. The system works: Bob reads the original text.
        assert recovered == SECRET_MESSAGE

        await alice_ws.close()
        await bob_ws.close()

    # ---- 2. The server never saw the plaintext ---------------------------
    # Check what the server logged to stdout/stderr during the exchange.
    captured = capsys.readouterr()
    assert SECRET_MESSAGE not in captured.out
    assert SECRET_MESSAGE not in captured.err

    # Check what the server persisted to the database: ciphertext only.
    import sqlite3
    rows = sqlite3.connect(db_path).execute(
        "SELECT ciphertext FROM messages").fetchall()
    assert len(rows) == 1
    stored = rows[0][0]
    assert SECRET_MESSAGE.encode("utf-8") not in stored
    # The stored bytes should be indistinguishable from random.
    assert len(stored) == len(SECRET_MESSAGE) + 16  # plaintext + GCM tag
