"""
test_log_stream.py -- the relay's log stream reaches each client exactly once.

WHAT WENT WRONG IN DEPLOYMENT

The relay streams its own log to every logged-in client so the in-app Log screen
shows the server's runtime without an SSH session. It did so along two paths
that did not know about each other:

  * a per-login SNAPSHOT of the whole ring, and
  * a live BATCH, popped about once a second from a second deque, 'pending'.

'pending' was only drained while somebody was online. Before the first login it
therefore still held every line since startup -- the very lines the snapshot had
just sent. The first client to log in received the entire log twice: once as its
snapshot, then a second later as its first live batch. The deployed relay showed
exactly this, the startup TLS block through LOGIN duplicated in the Log screen.

THE PROPERTY THESE TESTS PIN

Every ring entry now carries a monotonic 'seq' and every connection has its own
cursor. Delivery to a client is therefore at-most-once, whatever order logins
and batches occur in, and independently per client.

These tests drive the real ChatServer methods with controllable sockets: the
property under test is the bookkeeping between snapshot and broadcast, not the
wire, and a fake socket lets us observe precisely what each client was sent.
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

from server import (ChatServer, Storage, LOG_RING,      # noqa: E402
                    LOG_FLUSH_INTERVAL, LOG_BATCH_MAX)
from websockets.exceptions import ConnectionClosed      # noqa: E402


class _FakeSocket:
    """A client connection that records every frame sent to it."""

    def __init__(self, name: str, *, dead: bool = False) -> None:
        self.name = name
        self.dead = dead
        self.received: list[str] = []

    async def send(self, payload: str) -> None:
        if self.dead:
            raise ConnectionClosed(None, None)
        self.received.append(payload)

    def log_lines(self) -> list[str]:
        """Every server_log line this socket received, snapshot and live."""
        out: list[str] = []
        for raw in self.received:
            frame = json.loads(raw)
            if frame.get("type") == "server_log":
                out.extend(entry["line"] for entry in frame["lines"])
        return out


@pytest.fixture
def server(tmp_path):
    storage = Storage(str(Path(tmp_path) / "logstream.db"))
    srv = ChatServer(storage)
    yield srv
    storage.close()


async def _run_one_flush(server: ChatServer) -> None:
    """Run the broadcaster long enough for at least one flush, then stop it."""
    task = asyncio.create_task(server.broadcast_logs_forever())
    await asyncio.sleep(LOG_FLUSH_INTERVAL * 2 + 0.2)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ==========================================================================
# The duplication bug itself
# ==========================================================================

async def test_snapshot_then_batch_delivers_each_line_once(server):
    """THE REGRESSION TEST for the observed duplicate Log screen.

    Reproduces the deployed sequence exactly: lines accumulate while nobody is
    online, then the first client logs in (snapshot) and the broadcaster runs.
    Under the old dual-deque design every one of those lines arrived twice.
    """
    log = logging.getLogger("chat-server")
    for i in range(5):
        log.info("startup line %d", i)

    sock = _FakeSocket("first")
    server.online = {"first": sock}
    await server.send_log_snapshot(sock)     # the login snapshot
    await _run_one_flush(server)             # the live batch that followed

    lines = sock.log_lines()
    for i in range(5):
        marker = f"startup line {i}"
        hits = [ln for ln in lines if marker in ln]
        assert len(hits) == 1, (
            f"{marker!r} was delivered {len(hits)} times, expected exactly one"
            " -- the snapshot and the live batch overlap again")


async def test_lines_logged_after_the_snapshot_still_arrive(server):
    """De-duplication must not become under-delivery.

    Suppressing the overlap is only correct if genuinely NEW lines still reach
    the client. A cursor set too far ahead would pass the test above while
    silently dropping everything after login.
    """
    logging.getLogger("chat-server").info("before the snapshot")
    sock = _FakeSocket("c")
    server.online = {"c": sock}
    await server.send_log_snapshot(sock)

    logging.getLogger("chat-server").info("after the snapshot")
    await _run_one_flush(server)

    lines = sock.log_lines()
    assert any("before the snapshot" in ln for ln in lines), "snapshot lost"
    assert any("after the snapshot" in ln for ln in lines), (
        "a line logged after login never reached the client")


async def test_repeated_flushes_do_not_resend(server):
    """A quiet relay must not re-send the same lines on every pass."""
    logging.getLogger("chat-server").info("said once")
    sock = _FakeSocket("c")
    server.online = {"c": sock}
    await server.send_log_snapshot(sock)
    await _run_one_flush(server)
    await _run_one_flush(server)
    await _run_one_flush(server)

    hits = [ln for ln in sock.log_lines() if "said once" in ln]
    assert len(hits) == 1, f"line re-sent on later passes ({len(hits)} copies)"


# ==========================================================================
# Independence between clients
# ==========================================================================

async def test_a_late_joiner_does_not_replay_lines_to_the_early_client(server):
    """Two clients, two cursors.

    The old shared queue meant one client's delivery consumed lines for
    everyone. Here the second client's login must not cause the first to
    receive anything twice, nor rob it of anything.
    """
    log = logging.getLogger("chat-server")
    early = _FakeSocket("early")
    server.online = {"early": early}
    await server.send_log_snapshot(early)

    log.info("shared line one")
    await _run_one_flush(server)

    late = _FakeSocket("late")
    server.online["late"] = late
    await server.send_log_snapshot(late)
    log.info("shared line two")
    await _run_one_flush(server)

    early_lines = early.log_lines()
    assert len([ln for ln in early_lines if "shared line one" in ln]) == 1
    assert len([ln for ln in early_lines if "shared line two" in ln]) == 1
    late_lines = late.log_lines()
    assert len([ln for ln in late_lines if "shared line two" in ln]) == 1, (
        "the late joiner missed or duplicated a line logged after it arrived")


async def test_a_dead_socket_does_not_stall_another_clients_cursor(server):
    """A failing send must not advance a cursor or block the healthy client."""
    logging.getLogger("chat-server").info("fan-out line")
    good = _FakeSocket("good")
    dead = _FakeSocket("dead", dead=True)
    server.online = {"dead": dead, "good": good}
    server._log_cursor[good] = 0
    server._log_cursor[dead] = 0
    await _run_one_flush(server)

    assert any("fan-out line" in ln for ln in good.log_lines()), (
        "a dead socket earlier in the iteration silenced a healthy client")


# ==========================================================================
# Bookkeeping hygiene
# ==========================================================================

async def test_cursor_map_is_pruned_when_a_client_goes_away(server):
    """The cursor map must not grow without bound as clients come and go."""
    sock = _FakeSocket("transient")
    server.online = {"transient": sock}
    await server.send_log_snapshot(sock)
    assert sock in server._log_cursor

    server.online = {}                 # the client disconnected
    another = _FakeSocket("other")
    server.online = {"other": another}
    server._log_cursor[another] = 0
    logging.getLogger("chat-server").info("prompt a pass")
    await _run_one_flush(server)

    assert sock not in server._log_cursor, (
        "a departed client's cursor was left behind; the map leaks")


async def test_a_batch_is_capped_and_the_remainder_follows(server):
    """More lines than one batch holds must be delivered across passes.

    The cursor advances only as far as what was actually sent, so the overflow
    is carried to the next pass rather than skipped.
    """
    log = logging.getLogger("chat-server")
    sock = _FakeSocket("c")
    server.online = {"c": sock}
    server._log_cursor[sock] = LOG_RING.head_seq
    total = LOG_BATCH_MAX + 25
    for i in range(total):
        log.info("bulk %d", i)

    await _run_one_flush(server)
    await _run_one_flush(server)

    # The cap governs the size of a single frame, so assert on each frame.
    for raw in sock.received:
        frame = json.loads(raw)
        if frame.get("type") == "server_log" and not frame.get("snapshot"):
            assert len(frame["lines"]) <= LOG_BATCH_MAX, (
                f"a live batch carried {len(frame['lines'])} lines, "
                f"over the {LOG_BATCH_MAX} cap")

    lines = sock.log_lines()
    assert any("bulk %d" % (total - 1) in ln for ln in lines), (
        "the lines beyond the first batch were never delivered")
    assert len(lines) == len(set(lines)), "the overflow pass re-sent lines"
    delivered = [ln for ln in lines if "bulk " in ln]
    assert len(delivered) == total, (
        f"expected all {total} lines exactly once, got {len(delivered)}")


async def test_ring_entries_carry_a_monotonic_sequence(server):
    """The mechanism itself: seq must increase and never repeat."""
    log = logging.getLogger("chat-server")
    before = LOG_RING.head_seq
    for i in range(4):
        log.info("seq probe %d", i)
    after = LOG_RING.head_seq
    assert after == before + 4, "the ring did not advance once per record"

    seqs = [e["seq"] for e in LOG_RING.ring]
    assert seqs == sorted(seqs), "ring entries are out of sequence order"
    assert len(seqs) == len(set(seqs)), "a sequence number was reused"


async def test_snapshot_sets_the_cursor_even_with_an_empty_ring(server):
    """A client that logs in before anything is logged must still be tracked.

    Without this, its cursor would be absent and the first pass could hand it
    the whole backlog as a "first" batch -- the original bug in miniature.
    """
    LOG_RING.ring.clear()
    sock = _FakeSocket("c")
    server.online = {"c": sock}
    await server.send_log_snapshot(sock)
    assert sock in server._log_cursor, "no cursor recorded for a fresh client"


# ==========================================================================
# The unified log format (journal and client Log screen must agree)
# ==========================================================================

async def test_streamed_lines_carry_the_full_date(server):
    """A Log screen showing bare clock times cannot span midnight honestly.

    The deployed relay's screen put a 03:54 startup block directly above a
    23:28 login with nothing to reveal they were two days apart. Every streamed
    line must therefore carry its date.
    """
    logging.getLogger("chat-server").info("dated line")
    sock = _FakeSocket("c")
    server.online = {"c": sock}
    await server.send_log_snapshot(sock)

    line = next(ln for ln in sock.log_lines() if "dated line" in ln)
    import re
    assert re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\b", line), (
        f"streamed line has no full date: {line!r}")


async def test_streamed_lines_name_the_logger(server):
    """Relay lines must be distinguishable from library lines at a glance."""
    logging.getLogger("chat-server").info("ours")
    logging.getLogger("websockets.server").info("theirs")
    sock = _FakeSocket("c")
    server.online = {"c": sock}
    await server.send_log_snapshot(sock)

    lines = sock.log_lines()
    assert any("[chat-server]" in ln and "ours" in ln for ln in lines)
    assert any("[websockets.server]" in ln and "theirs" in ln for ln in lines)


def test_both_destinations_share_one_format() -> None:
    """The journal copy and the streamed copy must render a record identically.

    They were separate format strings, each missing what the other had. Reading
    one against the other while debugging then meant translating between them.
    """
    import server as S
    console = next(h for h in logging.getLogger().handlers
                   if isinstance(h, logging.StreamHandler)
                   and not isinstance(h, S._LogRing))
    assert console.formatter._fmt == LOG_RING.formatter._fmt, (
        "the journal and the client Log screen use different formats again")
    assert console.formatter.datefmt == LOG_RING.formatter.datefmt
