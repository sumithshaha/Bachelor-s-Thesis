"""
End-to-end test for the encrypted file sharing feature.

This is the proof that all the pieces fit together: two simulated clients
connect to a real running server, one sends a real file end-to-end encrypted,
the server only ever sees ciphertext (we assert this by grepping its database
for the plaintext bytes), and the other client recovers the original file
byte-for-byte. Tampered chunks are rejected. Files queued while the recipient
is offline are replayed on reconnect.

Run with:  pytest -v test_file_sharing.py
"""

import asyncio
import io
import json
import os
import sys
import uuid
from pathlib import Path

import pytest
import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from crypto_core import Identity, derive_shared_key  # noqa: E402
from file_crypto import (  # noqa: E402
    CHUNK_SIZE,
    HEADER_BYTES,
    decrypt_file,
    derive_file_key,
    encrypt_file,
)
from server import ChatServer, Storage  # noqa: E402
from websockets.asyncio.server import serve  # noqa: E402


async def _login(uri, nick, ident, port):
    ws = await websockets.connect(uri, max_size=2 * 1024 * 1024)
    await ws.send(json.dumps({
        "type": "hello", "nick": nick,
        "pubkey": ident.public_bytes().hex(),
    }))
    # drain initial frames (keys, presence, history, file replay if any)
    drain_deadline = asyncio.get_event_loop().time() + 0.3
    while asyncio.get_event_loop().time() < drain_deadline:
        try:
            await asyncio.wait_for(ws.recv(), timeout=0.1)
        except asyncio.TimeoutError:
            break
    return ws


async def _send_file(ws, sender_id, receiver_pub, plaintext, filename, mime):
    """Encrypt and send a file from sender to receiver."""
    msg_id = str(uuid.uuid4())  # 36 ASCII chars
    shared = derive_shared_key(sender_id, receiver_pub)
    file_key = derive_file_key(shared, msg_id)

    # Generate chunks first so we can put the header into file_init.
    pieces = list(encrypt_file(io.BytesIO(plaintext), file_key, len(plaintext)))
    header = pieces[0][0]
    chunks = [p[0] for p in pieces[1:]]

    await ws.send(json.dumps({
        "type": "file_init",
        "msg_id": msg_id,
        "to": "bob",
        "filename": filename,
        "mime": mime,
        "size": len(plaintext),
        "header": header.hex(),
    }))
    for idx, ct in enumerate(chunks):
        frame = msg_id.encode("ascii") + idx.to_bytes(4, "big") + ct
        await ws.send(frame)
    await ws.send(json.dumps({"type": "file_end", "msg_id": msg_id}))
    return msg_id, file_key, len(chunks)


async def _receive_file(ws, file_key, expected_msg_id, expected_chunks):
    """Read file_init, all the chunks, then file_end. Decrypt and return."""
    init = json.loads(await asyncio.wait_for(ws.recv(), timeout=2.0))
    assert init["type"] == "file_init"
    assert init["msg_id"] == expected_msg_id
    header = bytes.fromhex(init["header"])

    chunks = []
    for _ in range(expected_chunks):
        frame = await asyncio.wait_for(ws.recv(), timeout=2.0)
        assert isinstance(frame, (bytes, bytearray))
        msg_id_in_frame = frame[:36].decode("ascii")
        assert msg_id_in_frame == expected_msg_id
        chunks.append(bytes(frame[40:]))

    end = json.loads(await asyncio.wait_for(ws.recv(), timeout=2.0))
    assert end["type"] == "file_end"

    out = io.BytesIO()
    decrypt_file(header, iter(chunks), file_key, out)
    return init, out.getvalue()


@pytest.mark.asyncio
async def test_file_round_trip_through_live_server(tmp_path):
    """Alice sends a real file to Bob through the live server; Bob recovers
    the original bytes, and the server only ever holds ciphertext."""
    db_path = str(tmp_path / "files.db")
    storage = Storage(db_path)
    srv = ChatServer(storage)
    async with serve(srv.handle, "localhost", 8821,
                     max_size=2 * 1024 * 1024):
        uri = "ws://localhost:8821"
        alice = Identity.generate()
        bob = Identity.generate()

        # Both online.
        a_ws = await _login(uri, "alice", alice, 8821)
        b_ws = await _login(uri, "bob", bob, 8821)

        # 200 KB of random bytes - enough to span several 64 KiB chunks.
        plaintext = os.urandom(200_000)

        msg_id, _, expected_chunks = await _send_file(
            a_ws, alice, bob.public_bytes(),
            plaintext, "secret-photo.jpg", "image/jpeg")
        assert expected_chunks >= 3  # 200 KB at 64 KiB chunks

        # Bob's file key is derived from his own private + Alice's public.
        bob_file_key = derive_file_key(
            derive_shared_key(bob, alice.public_bytes()), msg_id)

        # Receive on Bob's side. Allow extra time for chunks to flow.
        await asyncio.sleep(0.1)
        init, recovered = await _receive_file(
            b_ws, bob_file_key, msg_id, expected_chunks)
        assert recovered == plaintext, "decrypted bytes do not match original"
        assert init["filename"] == "secret-photo.jpg"
        assert init["size"] == len(plaintext)

        await a_ws.close()
        await b_ws.close()

        # The server must have stored only ciphertext. Find the first 64 bytes
        # of plaintext anywhere in the chunks table - we must NOT find them.
        import sqlite3
        with sqlite3.connect(db_path) as db:
            rows = db.execute(
                "SELECT ciphertext FROM file_chunks WHERE msg_id = ?",
                (msg_id,),
            ).fetchall()
        assert len(rows) == expected_chunks
        all_stored = b"".join(ct for (ct,) in rows)
        needle = plaintext[:64]
        assert needle not in all_stored, (
            "plaintext bytes leaked into the server's chunk store!")


@pytest.mark.asyncio
async def test_tampered_chunk_is_rejected(tmp_path):
    """If even one ciphertext byte is flipped in transit, decryption refuses
    and never returns plaintext."""
    storage = Storage(str(tmp_path / "f.db"))
    srv = ChatServer(storage)
    async with serve(srv.handle, "localhost", 8822,
                     max_size=2 * 1024 * 1024):
        uri = "ws://localhost:8822"
        alice = Identity.generate()
        bob = Identity.generate()

        msg_id = str(uuid.uuid4())
        shared = derive_shared_key(alice, bob.public_bytes())
        file_key = derive_file_key(shared, msg_id)
        plaintext = os.urandom(150_000)

        pieces = list(
            encrypt_file(io.BytesIO(plaintext), file_key, len(plaintext)))
        header = pieces[0][0]
        chunks = [p[0] for p in pieces[1:]]
        # Tamper with the middle chunk by flipping one bit.
        bad = bytearray(chunks[1])
        bad[5] ^= 1
        chunks[1] = bytes(bad)

        bob_file_key = derive_file_key(
            derive_shared_key(bob, alice.public_bytes()), msg_id)

        out = io.BytesIO()
        with pytest.raises(Exception):
            decrypt_file(header, iter(chunks), bob_file_key, out)


@pytest.mark.asyncio
async def test_file_replayed_to_offline_recipient(tmp_path):
    """If Bob is offline when Alice sends a file, the server queues the
    chunks and delivers them when Bob reconnects."""
    storage = Storage(str(tmp_path / "f.db"))
    srv = ChatServer(storage)
    async with serve(srv.handle, "localhost", 8823,
                     max_size=2 * 1024 * 1024):
        uri = "ws://localhost:8823"
        alice = Identity.generate()
        bob = Identity.generate()

        # Bob registers his key once, then disappears.
        b_ws = await _login(uri, "bob", bob, 8823)
        await b_ws.close()

        a_ws = await _login(uri, "alice", alice, 8823)
        plaintext = os.urandom(150_000)
        msg_id, _, expected_chunks = await _send_file(
            a_ws, alice, bob.public_bytes(),
            plaintext, "for-bob.bin", "application/octet-stream")
        await asyncio.sleep(0.2)
        await a_ws.close()

        # Bob comes back. The login flow should replay file_init, all
        # chunks, and a synthetic file_end.
        b_ws = await websockets.connect(uri, max_size=2 * 1024 * 1024)
        await b_ws.send(json.dumps({
            "type": "hello", "nick": "bob",
            "pubkey": bob.public_bytes().hex(),
        }))

        # Drain frames looking for the replayed file_init for our msg_id.
        seen_init = None
        deadline = asyncio.get_event_loop().time() + 2.0
        while asyncio.get_event_loop().time() < deadline:
            try:
                frame = await asyncio.wait_for(b_ws.recv(), timeout=0.3)
            except asyncio.TimeoutError:
                break
            if isinstance(frame, str):
                try:
                    parsed = json.loads(frame)
                except Exception:
                    continue
                if parsed.get("type") == "file_init" and \
                        parsed.get("msg_id") == msg_id:
                    seen_init = parsed
                    break
        assert seen_init is not None, "file_init was not replayed"

        # Now drain chunks + file_end.
        bob_file_key = derive_file_key(
            derive_shared_key(bob, alice.public_bytes()), msg_id)
        chunks = []
        end_seen = False
        deadline = asyncio.get_event_loop().time() + 3.0
        while asyncio.get_event_loop().time() < deadline and not end_seen:
            frame = await asyncio.wait_for(b_ws.recv(), timeout=1.0)
            if isinstance(frame, (bytes, bytearray)):
                if bytes(frame[:36]).decode("ascii") == msg_id:
                    chunks.append(bytes(frame[40:]))
            else:
                parsed = json.loads(frame)
                if parsed.get("type") == "file_end" and \
                        parsed.get("msg_id") == msg_id:
                    end_seen = True
        assert end_seen
        assert len(chunks) == expected_chunks

        out = io.BytesIO()
        decrypt_file(bytes.fromhex(seen_init["header"]),
                     iter(chunks), bob_file_key, out)
        assert out.getvalue() == plaintext
        await b_ws.close()
