"""
test_prekey_dispatch.py -- the X3DH prekey server, over the wire.

The cryptographic correctness of X3DH lives in test_x3dh.py. This module covers
the SERVER side of it: the two frames that let a client publish its prekey
bundle (`publish_prekeys`) and another client fetch it (`get_bundle`), together
with the property that makes X3DH asynchronous -- a one-time prekey is consumed
on fetch, so two initiators never receive the same one.

That single-use property is the load-bearing one. If the server ever handed the
same one-time prekey to two requesters, the forward secrecy X3DH provides for
the first message would be undermined for one of them. The tests below pin it,
along with the surrounding contract: the publish acknowledgement and its
counts, the bundle shape, the empty-pool and unknown-user cases, the login
gate, and rejection of malformed prekeys.

Every expected reply was confirmed against the running server. Nothing is
mocked.
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

PORT = 8863


async def _drain(ws, seconds: float = 0.3) -> list[dict]:
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
    await _drain(ws)
    return ws


def _first(frames, typ):
    for f in frames:
        if f.get("type") == typ:
            return f
    return None


class _Relay:
    def __init__(self, tmp_path, port=PORT):
        self.db = str(Path(tmp_path) / "prekeys.db")
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


async def _publish(ws, *, spk="11" * 32, spk_sig="22" * 64, opks=None):
    await ws.send(json.dumps({
        "type": "publish_prekeys", "spk": spk, "spk_sig": spk_sig,
        "opks": opks if opks is not None else {},
    }))


# ==========================================================================
# publish_prekeys
# ==========================================================================

async def test_publish_returns_ack_with_counts(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        await _publish(alice, opks={"1": "aa" * 32, "2": "bb" * 32})
        ack = _first(await _drain(alice), "prekeys_ack")
        assert ack is not None, "no prekeys_ack returned"
        assert ack["added"] == 2
        assert ack["remaining"] == 2
        await alice.close()


async def test_publish_before_login_is_refused(tmp_path):
    async with _Relay(tmp_path) as r:
        ws = await websockets.connect(r.uri)
        await _publish(ws, opks={"1": "aa" * 32})
        errs = [f["reason"] for f in await _drain(ws) if f.get("type") == "error"]
        assert any("log in" in e for e in errs), errs
        await ws.close()


async def test_publish_malformed_one_time_prekey_is_rejected(tmp_path):
    """A one-time prekey of the wrong length must be refused as a batch."""
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        await _publish(alice, opks={"1": "aa" * 16})   # 16 bytes, not 32
        errs = [f["reason"] for f in await _drain(alice)
                if f.get("type") == "error"]
        assert any("one-time prekey" in e or "malformed" in e for e in errs), errs
        await alice.close()


async def test_publish_non_object_opks_is_rejected(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        await alice.send(json.dumps({
            "type": "publish_prekeys", "spk": "11" * 32, "spk_sig": "22" * 64,
            "opks": ["not", "an", "object"],
        }))
        errs = [f["reason"] for f in await _drain(alice)
                if f.get("type") == "error"]
        assert any("object" in e for e in errs), errs
        await alice.close()


async def test_publish_bad_spk_length_is_rejected(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        await alice.send(json.dumps({
            "type": "publish_prekeys", "spk": "11" * 16,   # 16, must be 32
            "spk_sig": "22" * 64, "opks": {},
        }))
        errs = [f["reason"] for f in await _drain(alice)
                if f.get("type") == "error"]
        assert errs, "a 16-byte signed prekey was accepted"
        await alice.close()


# ==========================================================================
# get_bundle
# ==========================================================================

async def test_bundle_has_the_expected_shape(tmp_path):
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        await _publish(alice, opks={"1": "aa" * 32})
        await _drain(alice)

        bob = await _login(r.uri, "bob", Identity.generate())
        await bob.send(json.dumps({"type": "get_bundle", "nick": "alice"}))
        frame = _first(await _drain(bob), "bundle")
        assert frame is not None
        bundle = frame["bundle"]
        assert bundle is not None, "alice published, so a bundle must come back"
        for field in ("ik", "spk", "spk_sig", "opk", "opk_id"):
            assert field in bundle, f"bundle missing {field}"
        await alice.close()
        await bob.close()


async def test_one_time_prekey_is_consumed_on_fetch(tmp_path):
    """THE SINGLE-USE PROPERTY.

    Two distinct one-time prekeys are published. Two fetches must hand out
    DIFFERENT ones -- never the same prekey twice -- because each is consumed
    when claimed.
    """
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        await _publish(alice, opks={"1": "aa" * 32, "2": "bb" * 32})
        await _drain(alice)

        bob = await _login(r.uri, "bob", Identity.generate())

        await bob.send(json.dumps({"type": "get_bundle", "nick": "alice"}))
        first = _first(await _drain(bob), "bundle")["bundle"]["opk"]

        await bob.send(json.dumps({"type": "get_bundle", "nick": "alice"}))
        second = _first(await _drain(bob), "bundle")["bundle"]["opk"]

        assert first is not None and second is not None
        assert first != second, "the SAME one-time prekey was handed out twice"
        await alice.close()
        await bob.close()


async def test_bundle_opk_is_null_once_the_pool_is_empty(tmp_path):
    """After every one-time prekey is claimed, further bundles still serve --
    with a null opk, so a session can still start on the signed prekey alone."""
    async with _Relay(tmp_path) as r:
        alice = await _login(r.uri, "alice", Identity.generate())
        await _publish(alice, opks={"1": "aa" * 32})   # exactly one
        await _drain(alice)

        bob = await _login(r.uri, "bob", Identity.generate())
        # First fetch drains the only OPK.
        await bob.send(json.dumps({"type": "get_bundle", "nick": "alice"}))
        await _drain(bob)
        # Second fetch: bundle still present, opk now null.
        await bob.send(json.dumps({"type": "get_bundle", "nick": "alice"}))
        bundle = _first(await _drain(bob), "bundle")["bundle"]
        assert bundle is not None, "the signed prekey bundle must still serve"
        assert bundle["opk"] is None, "opk should be exhausted"
        await alice.close()
        await bob.close()


async def test_bundle_for_user_without_prekeys_is_null(tmp_path):
    """A user who never published prekeys yields a null bundle, not an error."""
    async with _Relay(tmp_path) as r:
        bob = await _login(r.uri, "bob", Identity.generate())
        await bob.send(json.dumps({"type": "get_bundle", "nick": "ghost"}))
        frame = _first(await _drain(bob), "bundle")
        assert frame is not None
        assert frame["bundle"] is None
        await bob.close()
