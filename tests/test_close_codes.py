"""
test_close_codes.py -- the account state machine, by the codes it closes with.

The relay signals four distinct account-security outcomes through WebSocket
close codes, and the client relies on the specific code to show the right
message:

    4000  logged in elsewhere   -- same nick + same key opened a second socket;
                                   the OLDER socket is dropped so no ghost
                                   session lingers.
    4001  username reserved      -- the nick is bound to a DIFFERENT identity
                                   key; first-come, key-locked, permanent.
    4002  bad password           -- a returning protected account supplied the
                                   wrong Argon2id verifier; closed BEFORE any
                                   history or key dump, so a wrong password
                                   learns nothing.
    4003  birthday required      -- a NEW password-protected account without a
                                   birthday verifier (covered in test_birthday).

4003 is exercised elsewhere. This module pins the other three against the real
server, because a regression here is silent to every existing test -- the
conversation-level tests all use fresh, uncontested nicks -- and yet it governs
whether an attacker can take a name, whether a wrong password leaks anything,
and whether a re-login evicts the stale session.

Each expected code below was confirmed against the running server, not assumed.
Nothing is mocked.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
import websockets
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))

from crypto_core import Identity            # noqa: E402
from server import ChatServer, Storage      # noqa: E402

PORT = 8857


async def _drain(ws, seconds: float = 0.3) -> None:
    deadline = asyncio.get_event_loop().time() + seconds
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            await asyncio.wait_for(ws.recv(), timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError):
            break
        except ConnectionClosed:
            break


async def _close_code(ws, seconds: float = 1.5):
    """Read until the socket closes; return (code, reason) or None if it stays."""
    deadline = asyncio.get_event_loop().time() + seconds
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return None
        try:
            await asyncio.wait_for(ws.recv(), timeout=remaining)
        except ConnectionClosed as exc:
            # Prefer the non-deprecated accessor (websockets >= 13.1); the
            # received close frame carries the code and reason. Fall back to
            # the attributes on older releases.
            rcvd = getattr(exc, "rcvd", None)
            if rcvd is not None:
                return rcvd.code, rcvd.reason
            return exc.code, exc.reason
        except (asyncio.TimeoutError, TimeoutError):
            return None


def _hello(nick: str, ident: Identity, **extra) -> str:
    frame = {"type": "hello", "nick": nick, "pubkey": ident.public_bytes().hex()}
    frame.update(extra)
    return json.dumps(frame)


class _Relay:
    def __init__(self, tmp_path, port=PORT):
        self.db = str(Path(tmp_path) / "closecodes.db")
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
# 4000 -- logged in elsewhere
# ==========================================================================

async def test_second_login_same_key_evicts_the_first_with_4000(tmp_path):
    """Same nick + same identity key on a new socket drops the old one.

    Without this, a dropped-then-reconnected client would leave a ghost in the
    presence list. The OLD socket must receive 4000.
    """
    async with _Relay(tmp_path) as r:
        ident = Identity.generate()
        first = await websockets.connect(r.uri)
        await first.send(_hello("alice", ident))
        await _drain(first)

        second = await websockets.connect(r.uri)
        await second.send(_hello("alice", ident))
        await _drain(second)

        result = await _close_code(first)
        assert result is not None, "the first socket was not closed"
        code, reason = result
        assert code == 4000, f"expected 4000, got {code} ({reason!r})"

        await second.close()


async def test_the_surviving_session_stays_online(tmp_path):
    """After eviction, the NEW socket is the live one and can still act."""
    async with _Relay(tmp_path) as r:
        ident = Identity.generate()
        first = await websockets.connect(r.uri)
        await first.send(_hello("alice", ident))
        await _drain(first)
        second = await websockets.connect(r.uri)
        await second.send(_hello("alice", ident))
        await _drain(second)
        await _close_code(first)

        # second is still usable: a getkey round-trips without the socket dying.
        await second.send(json.dumps({"type": "getkey", "nick": "alice"}))
        assert await _close_code(second, 0.4) is None, "surviving socket closed"
        await second.close()


# ==========================================================================
# 4001 -- username reserved (first-come, key-locked)
# ==========================================================================

async def test_same_nick_different_key_is_rejected_with_4001(tmp_path):
    """A nick is permanently bound to the first key that claimed it.

    A second identity trying the same name must be refused with 4001, whether
    or not the original owner is online.
    """
    async with _Relay(tmp_path) as r:
        owner = Identity.generate()
        w1 = await websockets.connect(r.uri)
        await w1.send(_hello("bob", owner))
        await _drain(w1)
        await w1.close()                     # owner goes offline

        intruder = Identity.generate()       # different key, same nick
        w2 = await websockets.connect(r.uri)
        await w2.send(_hello("bob", intruder))

        result = await _close_code(w2)
        assert result is not None, "intruder socket was not closed"
        code, reason = result
        assert code == 4001, f"expected 4001, got {code} ({reason!r})"


async def test_same_nick_same_key_is_allowed_to_return(tmp_path):
    """The ORIGINAL owner returning with the SAME key must NOT be refused.

    The reservation locks the name to a key, not to a session -- a same-device
    reinstall that kept the key has to be able to log back in.
    """
    async with _Relay(tmp_path) as r:
        owner = Identity.generate()
        w1 = await websockets.connect(r.uri)
        await w1.send(_hello("bob", owner))
        await _drain(w1)
        await w1.close()

        w2 = await websockets.connect(r.uri)
        await w2.send(_hello("bob", owner))     # same key
        # Not a 4001; the socket stays open and online.
        assert await _close_code(w2, 0.5) is None, "the owner was wrongly refused"
        await w2.close()


# ==========================================================================
# 4002 -- bad password (and what it must NOT leak)
# ==========================================================================

def _register_with_password(tmp_path):
    """Seed a Storage directly with a password-protected account.

    Building the account through Storage rather than the wire keeps the test
    focused on the LOGIN check: we control the stored verifier exactly.
    """
    st = Storage(str(Path(tmp_path) / "closecodes.db"))
    ident = Identity.generate()
    st.save_key("carol", ident.public_bytes())
    st.set_credential("carol", b"\x11" * 32, b"salt-bytes")
    st.close()
    return ident


async def test_returning_account_wrong_password_is_closed_with_4002(tmp_path):
    """A wrong verifier on a protected account closes with 4002."""
    ident = _register_with_password(tmp_path)
    async with _Relay(tmp_path) as r:
        ws = await websockets.connect(r.uri)
        await ws.send(_hello(
            "carol", ident,
            pw_verifier=("22" * 32),        # WRONG verifier
            pw_salt="73616c742d6279746573",
        ))
        result = await _close_code(ws)
        assert result is not None, "socket was not closed on bad password"
        code, reason = result
        assert code == 4002, f"expected 4002, got {code} ({reason!r})"


async def test_wrong_password_leaks_no_history_or_keydump(tmp_path):
    """THE POINT OF CLOSING BEFORE ONLINE.

    The server must reject a wrong password BEFORE it sends the key dump,
    presence, or any history. So between the bad hello and the close, the
    client must receive NOTHING except possibly an error frame -- never a
    'key', 'key_update', 'presence', or message frame.
    """
    ident = _register_with_password(tmp_path)
    async with _Relay(tmp_path) as r:
        ws = await websockets.connect(r.uri)
        await ws.send(_hello(
            "carol", ident,
            pw_verifier=("22" * 32), pw_salt="73616c742d6279746573",
        ))
        leaked = []
        try:
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                try:
                    frame = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if frame.get("type") in {"key", "key_update", "presence",
                                         "msg", "server_log"}:
                    leaked.append(frame.get("type"))
        except ConnectionClosed:
            pass
        except (asyncio.TimeoutError, TimeoutError):
            pass
        assert leaked == [], f"a wrong password leaked frames: {leaked}"


async def test_correct_password_is_accepted(tmp_path):
    """The matching verifier must let the account in -- the check is not a wall.

    Guards against a 4002 that fires on everything, which would pass the
    rejection tests above while locking every user out.
    """
    ident = _register_with_password(tmp_path)
    async with _Relay(tmp_path) as r:
        ws = await websockets.connect(r.uri)
        await ws.send(_hello(
            "carol", ident,
            pw_verifier=("11" * 32),        # the CORRECT stored verifier
            pw_salt="73616c742d6279746573",
        ))
        assert await _close_code(ws, 0.6) is None, "correct password was refused"
        await ws.close()
