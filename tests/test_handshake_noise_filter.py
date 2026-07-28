"""
Guard tests for the handshake-noise log filter.

WHY THIS FILE EXISTS

A relay on a public port is probed constantly -- scanners, uptime monitors, a
browser pointed at https://host:8765, TCP-only health checks. Each opens a TCP
connection and never speaks the WebSocket handshake, and the websockets library
logs that as a ~30-line ERROR traceback on the `websockets.server` logger:

    ERROR  opening handshake failed
    Traceback (most recent call last):
      ...
    websockets.exceptions.InvalidMessage: did not receive a valid HTTP request

That is alarming to read and, in volume, buries real errors.
`_HandshakeNoiseFilter` collapses exactly that benign case to a single INFO
line. The whole value of the filter is that it is SURGICAL -- it must quieten
the scan noise and nothing else. These tests exist to prove both halves of that
promise stay true: the benign case is collapsed, and every genuine error keeps
its traceback and its ERROR level.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from server import _HandshakeNoiseFilter  # noqa: E402
from websockets.exceptions import InvalidMessage  # noqa: E402


def _record_for(exc: BaseException | None, msg: str,
                level: int = logging.ERROR) -> logging.LogRecord:
    """Build a LogRecord carrying exc as exc_info, the way logging does."""
    exc_info = None
    if exc is not None:
        exc_info = (type(exc), exc, exc.__traceback__)
    return logging.LogRecord(
        name="websockets.server", level=level, pathname=__file__, lineno=1,
        msg=msg, args=(), exc_info=exc_info)


def _wrapped_invalid_message() -> InvalidMessage:
    """An InvalidMessage chained from EOFError, exactly as websockets raises it."""
    try:
        try:
            raise EOFError("stream ends after 0 bytes, before end of line")
        except EOFError as underlying:
            raise InvalidMessage("did not receive a valid HTTP request") \
                from underlying
    except InvalidMessage as exc:
        return exc


def test_benign_handshake_failure_is_collapsed_to_info() -> None:
    """The exact log line from the deployed journal must become one INFO line."""
    f = _HandshakeNoiseFilter()
    rec = _record_for(_wrapped_invalid_message(), "opening handshake failed")

    assert f.filter(rec) is True          # the record is kept, not dropped
    assert rec.levelno == logging.INFO    # downgraded from ERROR
    assert rec.levelname == "INFO"
    assert rec.exc_info is None           # traceback removed
    assert "handshake" in rec.getMessage()


def test_bare_eoferror_is_collapsed() -> None:
    """A bare EOFError (client closed before sending anything) is also benign."""
    f = _HandshakeNoiseFilter()
    rec = _record_for(EOFError("stream ends after 0 bytes"),
                      "opening handshake failed")

    assert f.filter(rec) is True
    assert rec.levelno == logging.INFO
    assert rec.exc_info is None


def test_connection_error_is_collapsed() -> None:
    """A dropped connection during the handshake is benign noise too."""
    f = _HandshakeNoiseFilter()
    rec = _record_for(ConnectionResetError("peer reset"),
                      "opening handshake failed")

    assert f.filter(rec) is True
    assert rec.levelno == logging.INFO


def test_real_handler_failure_keeps_its_traceback() -> None:
    """A genuine fault in our handler must NOT be touched -- traceback and all.

    This is the half of the promise that matters most: the filter narrows
    noise, it never hides a real problem. If this ever fails, the filter has
    become dangerous.
    """
    f = _HandshakeNoiseFilter()
    rec = _record_for(ValueError("something genuinely broke"),
                      "connection handler failed")

    assert f.filter(rec) is True
    assert rec.levelno == logging.ERROR   # unchanged
    assert rec.levelname == "ERROR"
    assert rec.exc_info is not None       # traceback preserved
    assert rec.exc_info[0] is ValueError


def test_non_benign_handshake_error_keeps_its_traceback() -> None:
    """An unexpected exception on the handshake path is still a real error.

    "opening handshake failed" is the message for the benign case, but the same
    message could accompany a genuine bug. The filter keys on the EXCEPTION
    TYPE, not the message, so a ValueError under that message stays ERROR.
    """
    f = _HandshakeNoiseFilter()
    rec = _record_for(ValueError("a real bug during the handshake"),
                      "opening handshake failed")

    assert f.filter(rec) is True
    assert rec.levelno == logging.ERROR
    assert rec.exc_info is not None


def test_error_without_exception_is_untouched() -> None:
    """An ERROR with no exc_info cannot be the handshake case; leave it alone."""
    f = _HandshakeNoiseFilter()
    rec = _record_for(None, "some other error", level=logging.ERROR)

    assert f.filter(rec) is True
    assert rec.levelno == logging.ERROR


def test_info_records_pass_through_unchanged() -> None:
    """Ordinary INFO logging must be completely unaffected."""
    f = _HandshakeNoiseFilter()
    rec = _record_for(None, "LOGIN alice (1 online)", level=logging.INFO)

    before = rec.getMessage()
    assert f.filter(rec) is True
    assert rec.levelno == logging.INFO
    assert rec.getMessage() == before


def test_invalid_message_not_wrapped_is_still_collapsed() -> None:
    """An InvalidMessage raised on its own (no __cause__) is still benign."""
    f = _HandshakeNoiseFilter()
    rec = _record_for(InvalidMessage("did not receive a valid HTTP request"),
                      "opening handshake failed")

    assert f.filter(rec) is True
    assert rec.levelno == logging.INFO
    assert rec.exc_info is None


# ==========================================================================
# Live end-to-end: the unit tests above prove the filter's DECISION; this
# proves the WIRING. A real bare-TCP connection to a running server must, with
# the filter attached to the real `websockets.server` logger, produce exactly
# one collapsed INFO line and no traceback -- the scenario from the deployed
# journal. If the filter were ever attached to the wrong logger, or not
# attached at all, the unit tests would still pass and only this would fail.
# ==========================================================================

import asyncio          # noqa: E402

import pytest           # noqa: E402
from websockets.asyncio.server import serve   # noqa: E402


class _CaptureHandler(logging.Handler):
    """Collect emitted records (after filters run) for inspection."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


async def _bare_tcp_poke(host: str, port: int) -> None:
    """Open a TCP connection and close it without speaking anything.

    This is what a port scanner or a plain TCP health check does, and it is the
    exact condition that produced the 30-line traceback in the journal.

    WHY asyncio.open_connection AND NOT A HAND-ROLLED SOCKET

    This used to build an AF_INET socket itself and call
    `loop.sock_connect(sock, (host, port))`. That works on Linux and fails on
    Windows with `OSError: [WinError 10022] An invalid argument was supplied`,
    because the two event loops do different amounts of work for you:

      * Linux uses the selector loop, whose sock_connect RESOLVES the address
        before connecting, so a hostname is fine.
      * Windows uses the proactor loop, whose sock_connect hands the address
        straight to the overlapped ConnectEx call. ConnectEx needs a numeric
        sockaddr of the socket's own family, so a hostname string is rejected
        outright -- hence WSAEINVAL.

    There is a second hazard the hand-rolled version could not see. "localhost"
    on a dual-stack machine resolves to BOTH ::1 and 127.0.0.1, and the test
    server binds both (its startup logs two "server listening on" lines). A
    socket pinned to AF_INET cannot connect to an address that resolved to ::1.

    open_connection resolves the name, picks a family that matches, and behaves
    identically on both platforms -- so the test exercises the server's
    behaviour rather than the host's socket API. Closing immediately, without
    writing, is what makes it a bare poke.
    """
    _reader, writer = await asyncio.open_connection(host, port)
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        # The peer may drop the connection first; either way it is closed.
        pass


async def test_live_bare_tcp_connection_logs_one_line_no_traceback(tmp_path):
    """End-to-end: a real probe against a real server yields one INFO line.

    The filter is installed on the module logger at import time, so a running
    ChatServer already has it. We attach a capture handler to the same logger,
    poke the port with a bare TCP connection, and assert the resulting record
    is the collapsed INFO line with no traceback.
    """
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
    from server import ChatServer, Storage        # noqa: E402

    port = 8859
    ws_logger = logging.getLogger("websockets.server")
    cap = _CaptureHandler()
    ws_logger.addHandler(cap)
    previous_level = ws_logger.level
    ws_logger.setLevel(logging.INFO)
    try:
        storage = Storage(str(Path(tmp_path) / "noise.db"))
        server = ChatServer(storage)
        async with serve(server.handle, "localhost", port):
            await _bare_tcp_poke("localhost", port)
            await asyncio.sleep(0.4)          # let conn_handler log it
    finally:
        ws_logger.removeHandler(cap)
        ws_logger.setLevel(previous_level)
        storage.close()

    # Find any record that came from the handshake path.
    handshake = [r for r in cap.records
                 if "handshake" in r.getMessage().lower()
                 or "before completing" in r.getMessage()]
    assert handshake, (
        "no handshake record captured; the probe may not have reached the "
        "server, or the library changed how it logs")
    for rec in handshake:
        assert rec.levelno == logging.INFO, (
            f"handshake noise logged at {rec.levelname}, not INFO -- the "
            "filter is not wired to this logger")
        assert rec.exc_info is None, "a traceback survived the filter"
        assert "before completing the WebSocket handshake" in rec.getMessage()


async def test_live_real_connection_still_works_alongside_the_filter(tmp_path):
    """The filter must not disturb legitimate connections.

    A proper WebSocket client connecting to the same server must complete its
    handshake and get a normal response -- proving the noise filter narrows
    only the failure path and leaves working connections untouched.
    """
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
    import json
    import websockets
    from crypto_core import Identity               # noqa: E402
    from server import ChatServer, Storage          # noqa: E402

    port = 8860
    storage = Storage(str(Path(tmp_path) / "noise2.db"))
    server = ChatServer(storage)
    try:
        async with serve(server.handle, "localhost", port):
            ws = await websockets.connect(f"ws://localhost:{port}")
            await ws.send(json.dumps({
                "type": "hello", "nick": "alice",
                "pubkey": Identity.generate().public_bytes().hex(),
            }))
            # A working handshake yields at least one frame (key dump/presence).
            raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
            assert raw, "a legitimate client got no response"
            await ws.close()
    finally:
        storage.close()


# ==========================================================================
# The plain-HTTP case (InvalidUpgrade)
#
# The deployed relay's journal showed a SECOND kind of handshake noise the
# original filter did not recognise. A client that speaks perfectly good HTTP,
# but asks for an ordinary response rather than a WebSocket upgrade, makes the
# library answer 426 Upgrade Required (one tidy INFO line of its own) and THEN
# raise InvalidUpgrade out of the handshake -- which surfaced as:
#
#     ERROR  opening handshake failed
#     Traceback (most recent call last):
#       ... ~15 lines ...
#     websockets.exceptions.InvalidUpgrade: invalid Connection header: close
#
# That is a browser pointed at https://host:8765/, curl, or an HTTP health
# check: routine traffic on a public port, and not something the relay did
# wrong. InvalidUpgrade is NOT a subclass of InvalidMessage, so the original
# _BENIGN tuple could not match it and the traceback went through.
#
# These tests pin both halves of the fix: the case is now collapsed, it is
# collapsed to a message that says what actually happened (nothing was "closed
# before completing" -- the request was answered), and the exception types that
# signal an attack or a fault still keep their tracebacks.
# ==========================================================================

from websockets.exceptions import (InvalidUpgrade, SecurityError,   # noqa: E402
                                   InvalidOrigin)


def test_invalid_upgrade_is_collapsed_to_one_info_line() -> None:
    """The exact exception from the deployed journal loses its traceback."""
    filt = _HandshakeNoiseFilter()
    rec = _record_for(InvalidUpgrade("Connection", "close"),
                      "opening handshake failed")
    assert filt.filter(rec) is True
    assert rec.levelno == logging.INFO, "still logged as an error"
    assert rec.exc_info is None, "a traceback survived the filter"
    assert rec.exc_text is None


def test_invalid_upgrade_message_describes_what_actually_happened() -> None:
    """Accuracy: this case is NOT a connection closed early.

    The peer completed a valid HTTP request and received a proper 426. Reusing
    the bare-TCP wording would put a false statement in the log, and this log is
    read as evidence. The two benign cases must therefore read differently.
    """
    filt = _HandshakeNoiseFilter()

    http = _record_for(InvalidUpgrade("Connection", "close"),
                       "opening handshake failed")
    filt.filter(http)
    http_msg = http.getMessage()

    bare = _record_for(_wrapped_invalid_message(), "opening handshake failed")
    filt.filter(bare)
    bare_msg = bare.getMessage()

    assert "426" in http_msg and "HTTP" in http_msg
    assert "closed before completing" not in http_msg, (
        "the plain-HTTP case is described as an early close, which is untrue")
    assert "closed before completing" in bare_msg
    assert http_msg != bare_msg, "the two benign cases are indistinguishable"


def test_security_error_still_keeps_its_traceback() -> None:
    """An oversized-header probe is an attack signal, not routine noise.

    SecurityError shares a base class with InvalidUpgrade (both descend from
    InvalidHandshake), so a filter widened carelessly -- by matching the base
    rather than the two specific cases -- would swallow it. It must not.
    """
    filt = _HandshakeNoiseFilter()
    rec = _record_for(SecurityError("header too long"),
                      "opening handshake failed")
    filt.filter(rec)
    assert rec.levelno == logging.ERROR, "a security probe was downgraded"
    assert rec.exc_info is not None, "a security probe lost its traceback"


def test_invalid_origin_still_keeps_its_traceback() -> None:
    """A real WebSocket client refused by policy is worth seeing in full.

    InvalidOrigin descends from InvalidHeader, exactly as InvalidUpgrade does,
    so this pins that the fix matched InvalidUpgrade specifically and did not
    reach up to the shared parent.
    """
    filt = _HandshakeNoiseFilter()
    rec = _record_for(InvalidOrigin("http://evil.example"),
                      "opening handshake failed")
    filt.filter(rec)
    assert rec.levelno == logging.ERROR, "a policy refusal was downgraded"
    assert rec.exc_info is not None, "a policy refusal lost its traceback"


async def test_live_plain_http_request_logs_no_traceback(tmp_path):
    """End to end: a real HTTP GET on the WebSocket port, over a real socket.

    This is the deployed scenario reproduced exactly -- `Connection: close`,
    which is what an ordinary HTTP client sends -- proving the filter is wired
    to the logger the live handshake path actually uses, not just correct in
    isolation.
    """
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
    from server import ChatServer, Storage          # noqa: E402

    port = 8861
    storage = Storage(str(Path(tmp_path) / "noise3.db"))
    server_obj = ChatServer(storage)
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    cap = _Capture()
    logging.getLogger().addHandler(cap)
    try:
        async with serve(server_obj.handle, "localhost", port):
            reader, writer = await asyncio.open_connection("localhost", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                         b"Connection: close\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(400), timeout=2.0)
            writer.close()
            await asyncio.sleep(0.4)
    finally:
        logging.getLogger().removeHandler(cap)
        storage.close()

    handshake = [r for r in records if "handshake" in str(r.msg).lower()
                 or "426" in str(r.msg)]
    assert handshake, "the plain HTTP probe produced no log record at all"
    assert not any(r.levelno >= logging.ERROR for r in handshake), (
        "a plain HTTP request still logs at ERROR: "
        f"{[r.getMessage() for r in handshake if r.levelno >= logging.ERROR]}")
    assert not any(r.exc_info for r in handshake), "a traceback survived"
