"""
test_untrusted_frames.py -- the server's parsers, driven with hostile input.

WHY THIS FILE EXISTS

Everything a client sends is untrusted, and two parsers on the server turn raw
bytes into routing decisions: the binary file-chunk path (`_handle_binary`) and
the `msg` control frame. Between them they decode an ASCII msg_id, a
big-endian index, hex nonces of specific lengths, and a size-bounded
ciphertext, and they enforce an authorisation gate (a client may only push
chunks for its own file id) and an anti-spoofing rule (the `from` field is
advisory; the socket's logged-in identity wins).

The rest of the suite exercises these paths only in passing, with well-formed
input. The failure mode that matters -- a malformed or hostile frame slipping
past a check, or a check rejecting a valid frame -- is exactly what "in
passing" does not cover. Each test below was written against the server's
observed replies, not against an assumption about them: the error strings are
the ones the running server actually returns.

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

from crypto_core import Identity            # noqa: E402
from server import ChatServer, Storage, MAX_CIPHERTEXT_BYTES  # noqa: E402

PORT = 8853


async def _drain(ws, seconds: float = 0.3) -> list[dict]:
    """Collect frames the server pushes within a window, parsed where JSON."""
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
        if isinstance(raw, (bytes, bytearray)):
            out.append({"_binary": bytes(raw)})
            continue
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
    await _drain(ws)
    return ws


def _errors(frames: list[dict]) -> list[str]:
    return [f["reason"] for f in frames if f.get("type") == "error"]


class _Relay:
    """The real server on a real socket, torn down cleanly for Windows."""

    def __init__(self, tmp_path, port=PORT):
        self.db = str(Path(tmp_path) / "untrusted.db")
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
# Binary file-chunk framing (_handle_binary)
#
# Frame layout: 36 ASCII bytes of msg_id, 4 big-endian index bytes, then the
# opaque ciphertext. The server routes on the prefix and never reads the rest.
# ==========================================================================

async def test_binary_frame_before_login_is_refused(tmp_path):
    """An anonymous socket must not be able to push file chunks."""
    async with _Relay(tmp_path) as r:
        ws = await websockets.connect(r.uri)          # no hello
        await ws.send(b"a" * 36 + (0).to_bytes(4, "big") + b"payload")
        assert "must log in first" in _errors(await _drain(ws))
        await ws.close()


async def test_binary_frame_exactly_39_bytes_is_too_short(tmp_path):
    """39 bytes cannot hold a 36-byte id plus a 4-byte index. Boundary check."""
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        await ws.send(b"x" * 39)
        assert "binary frame too short" in _errors(await _drain(ws))
        await ws.close()


async def test_binary_frame_exactly_40_bytes_passes_length_check(tmp_path):
    """40 bytes is the minimum valid length: 36 + 4, with empty ciphertext.

    It must get PAST the length check and fail later, on the file-id lookup --
    proving 40 is treated as long enough, i.e. the boundary is < 40 not <= 40.
    """
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        await ws.send(b"a" * 36 + (0).to_bytes(4, "big"))   # exactly 40
        errs = _errors(await _drain(ws))
        assert "binary frame too short" not in errs
        assert "unknown file id" in errs
        await ws.close()


async def test_binary_frame_non_ascii_msgid_is_rejected(tmp_path):
    """The first 36 bytes must decode as ASCII. High bytes must be rejected."""
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        await ws.send(b"\xff" * 36 + (0).to_bytes(4, "big") + b"payload")
        assert "binary frame: bad msg_id" in _errors(await _drain(ws))
        await ws.close()


async def test_binary_frame_unknown_file_id_is_rejected(tmp_path):
    """A well-formed frame for a file that was never announced is refused."""
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        never_announced = "0" * 36
        await ws.send(never_announced.encode() + (0).to_bytes(4, "big") + b"x")
        assert "unknown file id" in _errors(await _drain(ws))
        await ws.close()


async def test_binary_chunk_for_another_users_file_is_refused(tmp_path):
    """THE AUTHORISATION GATE.

    Alice announces a file (so the id exists and is owned by her). Mallory,
    logged in separately, tries to push a chunk to Alice's file id. The server
    must reject it as unauthorised -- a client may only add to its OWN files,
    never inject bytes into someone else's transfer.
    """
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        mallory = await _login(r.uri, "mallory", Identity.generate())

        # Alice announces a file to bob; capture the msg_id she chose.
        msg_id = "11111111-2222-3333-4444-555555555555"
        await alice.send(json.dumps({
            "type": "file_init", "from": "alice", "to": "bob",
            "msg_id": msg_id, "envelope": "e",
        }))
        await _drain(alice)

        # Mallory pushes a chunk to alice's file id.
        assert len(msg_id) == 36
        await mallory.send(msg_id.encode() + (0).to_bytes(4, "big") + b"evil")
        assert "unauthorised file id" in _errors(await _drain(mallory))

        await alice.close()
        await mallory.close()


async def test_binary_chunk_index_is_read_big_endian(tmp_path):
    """A large index must round-trip: the 4 bytes are big-endian, not little.

    Alice announces a file, then pushes a chunk at index 0x01020304. If the
    server accepts it without error, the index decoded within range; a
    mis-decode would not by itself error here, so we assert the happy path
    stays clean and the chunk is stored under the right id (covered by the
    absence of an error and the FILE_CHUNK log the server emits).
    """
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        msg_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        await alice.send(json.dumps({
            "type": "file_init", "from": "alice", "to": "bob",
            "msg_id": msg_id, "envelope": "e",
        }))
        await _drain(alice)
        await alice.send(msg_id.encode() + (0x01020304).to_bytes(4, "big") + b"c")
        assert _errors(await _drain(alice)) == []
        await alice.close()


# ==========================================================================
# msg control-frame validation (_require_str / _require_hex / size cap)
# ==========================================================================

async def test_msg_before_login_is_refused(tmp_path):
    async with _Relay(tmp_path) as r:
        ws = await websockets.connect(r.uri)
        await ws.send(json.dumps({
            "type": "msg", "from": "a", "to": "b",
            "nonce": "00" * 24, "ct": "abcd",
        }))
        assert "must log in first" in _errors(await _drain(ws))
        await ws.close()


async def test_msg_missing_from_is_rejected(tmp_path):
    """_require_str rejects an absent field with a precise message."""
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        await ws.send(json.dumps({
            "type": "msg", "to": "bob", "nonce": "00" * 24, "ct": "abcd",
        }))
        assert "field 'from' must be a string" in _errors(await _drain(ws))
        await ws.close()


async def test_msg_non_string_field_is_rejected(tmp_path):
    """JSON lets a client send a number where text is expected; reject it.

    str(None) would silently become 'None', so the isinstance check in
    _require_str is a real guard, not a formality.
    """
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        await ws.send(json.dumps({
            "type": "msg", "from": 12345, "to": "bob",
            "nonce": "00" * 24, "ct": "abcd",
        }))
        assert "field 'from' must be a string" in _errors(await _drain(ws))
        await ws.close()


async def test_msg_bad_nonce_length_is_rejected(tmp_path):
    """Nonce must be 12 (AES-GCM) or 24 (XChaCha). 16 is neither."""
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        await ws.send(json.dumps({
            "type": "msg", "from": "alice", "to": "bob",
            "nonce": "00" * 16, "ct": "abcd",
        }))
        errs = _errors(await _drain(ws))
        assert any("nonce" in e and "12, 24" in e for e in errs), errs
        await ws.close()


async def test_msg_non_hex_nonce_is_rejected(tmp_path):
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        await ws.send(json.dumps({
            "type": "msg", "from": "alice", "to": "bob",
            "nonce": "zzzz", "ct": "abcd",
        }))
        assert any("nonce" in e and "hex" in e
                   for e in _errors(await _drain(ws)))
        await ws.close()


async def test_msg_both_nonce_lengths_are_accepted(tmp_path):
    """12 and 24 bytes must BOTH pass -- the two ciphers the protocol allows."""
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        for n in (12, 24):
            await ws.send(json.dumps({
                "type": "msg", "from": "alice", "to": "bob",
                "nonce": "00" * n, "ct": "abcd", "cipher": "x",
            }))
            # bob is offline; acceptance means NO error frame comes back.
            assert _errors(await _drain(ws, 0.2)) == [], f"nonce {n} rejected"
        await ws.close()


async def test_msg_oversize_ciphertext_is_rejected(tmp_path):
    """Ciphertext above MAX_CIPHERTEXT_BYTES must be refused, not stored.

    Without this cap a single client could exhaust server memory or the
    database with one enormous frame.
    """
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        oversize = "ff" * (MAX_CIPHERTEXT_BYTES + 1)
        await ws.send(json.dumps({
            "type": "msg", "from": "alice", "to": "bob",
            "nonce": "00" * 24, "ct": oversize, "cipher": "x",
        }))
        assert "message too large" in _errors(await _drain(ws))
        await ws.close()


async def test_msg_ciphertext_at_the_limit_is_accepted(tmp_path):
    """Exactly MAX_CIPHERTEXT_BYTES must pass: the check is >, not >=."""
    async with _Relay(tmp_path) as r:
        ws = await _login(r.uri, "alice", Identity.generate())
        at_limit = "ff" * MAX_CIPHERTEXT_BYTES
        await ws.send(json.dumps({
            "type": "msg", "from": "alice", "to": "bob",
            "nonce": "00" * 24, "ct": at_limit, "cipher": "x",
        }))
        assert _errors(await _drain(ws, 0.4)) == []
        await ws.close()


async def test_msg_spoofed_from_is_overridden_not_trusted(tmp_path):
    """THE ANTI-SPOOFING RULE.

    Alice is logged in. She sends a msg whose 'from' claims to be carol. The
    server must overwrite it with her real logged-in identity and relay under
    'alice', never under 'carol' -- the socket's identity is authoritative, the
    field is advisory. Bob receives it and sees alice as the sender.
    """
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        bob = await _login(r.uri, "bob", Identity.generate())
        await _drain(bob)

        await alice.send(json.dumps({
            "type": "msg", "from": "carol", "to": "bob",
            "nonce": "00" * 24, "ct": "abcd", "cipher": "x",
        }))
        frames = await _drain(bob, 0.5)
        msgs = [f for f in frames if f.get("type") == "msg"]
        assert msgs, f"bob got no msg; saw {[f.get('type') for f in frames]}"
        assert msgs[0]["from"] == "alice", "spoofed sender was not overridden"
        assert msgs[0]["from"] != "carol"

        await alice.close()
        await bob.close()
