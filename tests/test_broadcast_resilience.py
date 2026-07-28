"""
test_broadcast_resilience.py -- one dead socket must not silence the rest.

The server fans two kinds of frame out to every connected client: the presence
list (`broadcast_presence`) and the streamed server log
(`broadcast_logs_forever`). Both iterate the online map and send to each socket.
The hazard is obvious once stated: if one client's socket has died and its
`send` raises, a naive loop would abort and every client after it in the
iteration would miss the frame -- so a single stale connection could freeze
presence updates or the log stream for everyone else.

The server guards this by catching `ConnectionClosed` per send. These tests pin
that guarantee: a broadcast steps over a dead socket and still reaches every
healthy one. They drive the real methods with controllable sockets rather than
real network peers, because the property under test is the loop's resilience,
not the wire -- and a fake socket lets us make exactly one peer fail on demand.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))

from server import (ChatServer, Storage,           # noqa: E402
                    LOG_RING, LOG_FLUSH_INTERVAL)
from websockets.exceptions import ConnectionClosed  # noqa: E402


class _FakeSocket:
    """A stand-in for a client connection with controllable send behaviour."""

    def __init__(self, name: str, *, dead: bool = False) -> None:
        self.name = name
        self.dead = dead
        self.received: list[str] = []

    async def send(self, payload: str) -> None:
        if self.dead:
            # Exactly what a closed websocket raises when you send to it.
            raise ConnectionClosed(None, None)
        self.received.append(payload)


@pytest.fixture
def server(tmp_path):
    storage = Storage(str(Path(tmp_path) / "broadcast.db"))
    srv = ChatServer(storage)
    yield srv
    storage.close()


# ==========================================================================
# broadcast_presence
# ==========================================================================

async def test_presence_reaches_healthy_sockets_despite_a_dead_one(server):
    """A dead socket in the middle of the map must not stop the others."""
    good_a = _FakeSocket("a")
    dead = _FakeSocket("dead", dead=True)
    good_b = _FakeSocket("b")
    # Insertion order matters: 'dead' sits BETWEEN the two good ones, so if the
    # loop aborted on the failure, good_b (after it) would be starved.
    server.online = {"a": good_a, "dead": dead, "b": good_b}

    await server.broadcast_presence()

    assert len(good_a.received) == 1, "socket before the dead one missed it"
    assert len(good_b.received) == 1, "socket AFTER the dead one was starved"
    assert dead.received == []


async def test_presence_payload_lists_all_online_nicks(server):
    """Sanity on the content: the frame names every online user, sorted."""
    server.online = {
        "charlie": _FakeSocket("charlie"),
        "alice": _FakeSocket("alice"),
        "bob": _FakeSocket("bob"),
    }
    await server.broadcast_presence()

    frame = json.loads(server.online["alice"].received[0])
    assert frame["type"] == "presence"
    assert frame["users"] == ["alice", "bob", "charlie"]  # sorted


async def test_presence_with_every_socket_dead_does_not_raise(server):
    """If ALL sockets are dead the method must still return cleanly."""
    server.online = {
        "x": _FakeSocket("x", dead=True),
        "y": _FakeSocket("y", dead=True),
    }
    # No assertion beyond "this does not raise": the point is that a fully
    # stale map degrades quietly rather than throwing out of the broadcaster.
    await server.broadcast_presence()


async def test_presence_with_no_one_online_is_a_noop(server):
    server.online = {}
    await server.broadcast_presence()   # must not raise


# ==========================================================================
# broadcast_logs_forever (one drain cycle)
# ==========================================================================

async def test_log_broadcast_skips_a_dead_socket(server):
    """The log streamer must also step over a dead socket.

    We prime the log ring with a pending line, put a dead socket between two
    healthy ones, run the forever-loop just long enough for a single flush,
    then cancel it. The healthy sockets must have received the batch.
    """
    good_a = _FakeSocket("a")
    dead = _FakeSocket("dead", dead=True)
    good_b = _FakeSocket("b")
    server.online = {"a": good_a, "dead": dead, "b": good_b}

    # Prime the ring through the REAL logging path, so the entry has the same
    # shape the flusher will actually meet in production (a dict carrying seq,
    # level and the formatted line). The previous version of this test appended
    # a bare string straight into an internal deque, which meant it never
    # exercised the real entry shape at all.
    logging.getLogger("chat-server").info("test line")

    # Every socket starts with no cursor. A client with no cursor is treated as
    # already current (it is about to be given a login snapshot), so set each
    # one back to the start explicitly -- this test is about the fan-out loop,
    # and we want all three sockets to have something owed to them.
    for sock in (good_a, dead, good_b):
        server._log_cursor[sock] = 0

    task = asyncio.create_task(server.broadcast_logs_forever())
    # Let at least one flush interval elapse, then stop the loop.
    await asyncio.sleep(LOG_FLUSH_INTERVAL * 2 + 0.2)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert good_a.received, "healthy socket before the dead one got no log"
    assert good_b.received, "healthy socket AFTER the dead one got no log"
    # And what they got is a server_log frame carrying the line.
    frame = json.loads(good_a.received[0])
    assert frame["type"] == "server_log"
    assert any("test line" in entry["line"] for entry in frame["lines"])
