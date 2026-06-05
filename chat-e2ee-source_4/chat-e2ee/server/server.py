"""
End-to-end encrypted chat server.

This server is deliberately "dumb" about message contents. It performs three
jobs only:

  1. It keeps a directory of public keys so that any user can look up the
     public key of any other user (the untrusted key-server model).
  2. It tracks who is currently online and tells everyone when that changes
     (presence).
  3. It relays and stores message envelopes. Every envelope contains a nonce
     and a ciphertext blob that the server can neither read nor modify without
     detection.

The important design point for the thesis: the server never has access to a
private key and never sees a single byte of plaintext. If this machine were
seized or its operator turned malicious, the only thing they would find in the
database is ciphertext.

Author: Sumith Shaha
Course: Bachelor's Thesis, TAMK, 2026
"""

import argparse
import asyncio
import json
import logging
import signal
import sqlite3
import ssl
import time
from pathlib import Path

from websockets.asyncio.server import serve, ServerConnection
from websockets.exceptions import ConnectionClosed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("chat-server")

# An encrypted chat message should never be huge; capping the ciphertext size
# stops a single client from exhausting server memory or the database with one
# enormous frame. 64 KiB of ciphertext comfortably covers any text message.
MAX_CIPHERTEXT_BYTES = 64 * 1024


class _ValidationError(Exception):
    """Raised when an incoming frame is missing a field or has a bad value.

    It is caught inside the per-frame loop and turned into a polite error reply
    so that a single malformed frame never disconnects the client.
    """


def _require_str(msg: dict, field: str) -> str:
    """Pull a required string field out of a frame, or reject the frame.

    Using a helper keeps the handler readable and guarantees the same error
    wording everywhere. The isinstance check matters because JSON lets a client
    send a number or null where we expect text, and str(None) would otherwise
    silently become the string 'None'.
    """
    value = msg.get(field)
    if not isinstance(value, str):
        raise _ValidationError(f"field {field!r} must be a string")
    return value


def _require_hex(msg: dict, field: str, expected_len: int | None = None) -> bytes:
    """Pull a required hex-encoded byte field, decode it, and length-check it.

    expected_len, when given, is the number of *bytes* the decoded value must
    have - for example a nonce is always 12 bytes and an X25519 public key is
    always 32. Catching a wrong length here means the crypto layer is never
    handed something malformed.
    """
    raw = _require_str(msg, field)
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        raise _ValidationError(f"field {field!r} is not valid hex")
    if expected_len is not None and len(data) != expected_len:
        raise _ValidationError(
            f"field {field!r} must be {expected_len} bytes, got {len(data)}")
    return data


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
class Storage:
    """Thin wrapper around an SQLite database.

    Two tables are used. 'users' is the public-key directory; it maps a
    nickname to the raw 32-byte X25519 public key that the client uploaded
    when it first logged in. 'messages' is the history of ciphertext
    envelopes. Note that no column anywhere holds plaintext.
    """

    def __init__(self, path: str) -> None:
        # check_same_thread=False is safe here because every call happens on
        # the single asyncio event-loop thread; we never touch the connection
        # from a background thread.
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                nick    TEXT PRIMARY KEY,
                pubkey  BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sender      TEXT NOT NULL,
                recipient   TEXT NOT NULL,
                nonce       BLOB NOT NULL,
                ciphertext  BLOB NOT NULL,
                ts          INTEGER NOT NULL
            );

            -- File transfers are split across two tables. 'file_meta' carries
            -- the per-file announcement (the encrypted JSON envelope produced
            -- by 'file_init'), while 'file_chunks' stores each ciphertext
            -- chunk in order. The server never decrypts either table; it
            -- holds the chunks only long enough to relay them to an offline
            -- recipient when they reconnect. The (msg_id, chunk_index) primary
            -- key lets us replay in the exact order the sender produced.
            CREATE TABLE IF NOT EXISTS file_meta (
                msg_id      TEXT PRIMARY KEY,
                sender      TEXT NOT NULL,
                recipient   TEXT NOT NULL,
                envelope    TEXT NOT NULL,   -- the full file_init JSON frame
                ts          INTEGER NOT NULL,
                final_seen  INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS file_chunks (
                msg_id       TEXT NOT NULL,
                chunk_index  INTEGER NOT NULL,
                ciphertext   BLOB NOT NULL,
                PRIMARY KEY (msg_id, chunk_index)
            );
            CREATE INDEX IF NOT EXISTS idx_file_meta_recipient
                ON file_meta(recipient);
            """
        )
        self._db.commit()

    def save_key(self, nick: str, pubkey: bytes) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO users (nick, pubkey) VALUES (?, ?)",
            (nick, pubkey),
        )
        self._db.commit()

    def get_key(self, nick: str) -> bytes | None:
        row = self._db.execute(
            "SELECT pubkey FROM users WHERE nick = ?", (nick,)
        ).fetchone()
        return row[0] if row else None

    def all_keys(self) -> dict[str, str]:
        rows = self._db.execute("SELECT nick, pubkey FROM users").fetchall()
        return {nick: pubkey.hex() for nick, pubkey in rows}

    def save_message(
        self, sender: str, recipient: str, nonce: bytes, ct: bytes, ts: int
    ) -> None:
        self._db.execute(
            "INSERT INTO messages (sender, recipient, nonce, ciphertext, ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (sender, recipient, nonce, ct, ts),
        )
        self._db.commit()

    def history_for(self, nick: str, limit: int = 50) -> list[dict]:
        """Return the most recent envelopes that 'nick' is party to.

        The client still has to decrypt these locally; the server is simply
        handing back the ciphertext it stored earlier.
        """
        rows = self._db.execute(
            "SELECT sender, recipient, nonce, ciphertext, ts FROM messages "
            "WHERE sender = ? OR recipient = ? "
            "ORDER BY id DESC LIMIT ?",
            (nick, nick, limit),
        ).fetchall()
        rows.reverse()  # oldest first for display
        return [
            {
                "type": "msg",
                "from": sender,
                "to": recipient,
                "nonce": nonce.hex(),
                "ct": ct.hex(),
                "ts": ts,
            }
            for sender, recipient, nonce, ct, ts in rows
        ]

    # ----------------------------------------------------------------------
    # File transfer storage
    # ----------------------------------------------------------------------
    # Files travel as a small JSON header (file_init), a stream of binary
    # ciphertext chunks, and a JSON terminator (file_end). The server queues
    # the whole thing in SQLite when the recipient is offline and replays it
    # on reconnect, in exactly the same way it does for text messages.

    def save_file_init(
        self, msg_id: str, sender: str, recipient: str,
        envelope_json: str, ts: int,
    ) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO file_meta "
            "(msg_id, sender, recipient, envelope, ts, final_seen) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            (msg_id, sender, recipient, envelope_json, ts),
        )
        self._db.commit()

    def save_file_chunk(
        self, msg_id: str, chunk_index: int, ciphertext: bytes,
    ) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO file_chunks "
            "(msg_id, chunk_index, ciphertext) VALUES (?, ?, ?)",
            (msg_id, chunk_index, ciphertext),
        )
        self._db.commit()

    def mark_file_complete(self, msg_id: str) -> None:
        """Record that the sender sent file_end. Used so a reconnecting
        recipient only sees fully-arrived files in their backlog."""
        self._db.execute(
            "UPDATE file_meta SET final_seen = 1 WHERE msg_id = ?",
            (msg_id,),
        )
        self._db.commit()

    def file_owner(self, msg_id: str) -> tuple[str, str] | None:
        """Return (sender, recipient) for a file, or None if unknown.

        Used to authorise chunk and file_end frames: only the original sender
        is allowed to add chunks to a file that is already in flight.
        """
        row = self._db.execute(
            "SELECT sender, recipient FROM file_meta WHERE msg_id = ?",
            (msg_id,),
        ).fetchone()
        return (row[0], row[1]) if row else None

    def pending_files_for(self, nick: str) -> list[dict]:
        """Return queued files for an offline-now-online recipient.

        Each entry contains the original file_init envelope and the ordered
        ciphertext chunks, ready for replay. We only return fully-arrived
        transfers (final_seen = 1) so a recipient never sees a half-sent
        file with no final tag, which decryption would correctly refuse.
        """
        meta_rows = self._db.execute(
            "SELECT msg_id, envelope FROM file_meta "
            "WHERE recipient = ? AND final_seen = 1 "
            "ORDER BY ts ASC",
            (nick,),
        ).fetchall()
        result = []
        for msg_id, envelope in meta_rows:
            chunk_rows = self._db.execute(
                "SELECT chunk_index, ciphertext FROM file_chunks "
                "WHERE msg_id = ? ORDER BY chunk_index ASC",
                (msg_id,),
            ).fetchall()
            result.append({
                "msg_id": msg_id,
                "envelope": envelope,
                "chunks": [(idx, ct) for idx, ct in chunk_rows],
            })
        return result


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------
class ChatServer:
    def __init__(self, storage: Storage) -> None:
        self.storage = storage
        # Maps an online nickname to its live WebSocket connection.
        self.online: dict[str, ServerConnection] = {}

    async def broadcast_presence(self) -> None:
        """Tell every connected client the current list of online users."""
        payload = json.dumps(
            {"type": "presence", "users": sorted(self.online.keys())}
        )
        # Copy the values so a disconnect during iteration cannot corrupt
        # the loop.
        for ws in list(self.online.values()):
            try:
                await ws.send(payload)
            except ConnectionClosed:
                pass

    async def _send_error(self, ws: ServerConnection, reason: str) -> None:
        """Tell a client that its last frame was rejected, without dropping it.

        Returning a structured error rather than letting an exception bubble up
        is what keeps one malformed frame from tearing down the whole
        connection. The client can log or ignore it; either way the session
        survives.
        """
        try:
            await ws.send(json.dumps({"type": "error", "reason": reason}))
        except ConnectionClosed:
            pass

    async def _handle_binary(
        self, ws: ServerConnection, nick: str | None, data: bytes,
    ) -> None:
        """Route one binary frame (an encrypted file chunk).

        A binary frame is structured so the server can route it without ever
        looking at the ciphertext: the first 36 bytes are the ASCII msg_id
        (a UUID string, e.g. '550e8400-e29b-41d4-a716-446655440000'), the
        next 4 bytes are the big-endian chunk index, and the rest is the
        opaque encrypted chunk produced by secretstream. The server reads
        the prefix to find the recipient, stores the chunk for offline
        replay, and forwards the *entire* frame as-is so the recipient
        receives exactly what the sender produced.
        """
        if nick is None:
            await self._send_error(ws, "must log in first")
            return
        if len(data) < 40:
            await self._send_error(ws, "binary frame too short")
            return
        try:
            msg_id = data[:36].decode("ascii")
        except UnicodeDecodeError:
            await self._send_error(ws, "binary frame: bad msg_id")
            return
        chunk_index = int.from_bytes(data[36:40], "big")
        ciphertext = data[40:]

        # Look up the sender/recipient from the earlier file_init. This also
        # gates the request: a client cannot push chunks for someone else's
        # file id, only their own. The server still does not inspect the
        # ciphertext - it only checks that this client is allowed to add to
        # this file.
        owner = self.storage.file_owner(msg_id)
        if owner is None:
            await self._send_error(ws, "unknown file id")
            return
        sender, recipient = owner
        if sender != nick:
            await self._send_error(ws, "unauthorised file id")
            return

        self.storage.save_file_chunk(msg_id, chunk_index, ciphertext)
        log.info("FILE_CHUNK %s -> %s  msg_id=%s idx=%d ct=%d B",
                 sender, recipient, msg_id, chunk_index, len(ciphertext))

        # Relay to the recipient if they are online; otherwise the chunk
        # stays in SQLite until they reconnect.
        target_ws = self.online.get(recipient)
        if target_ws is not None:
            await target_ws.send(data)

    async def handle(self, ws: ServerConnection) -> None:
        """Per-connection coroutine. One of these runs for each client.

        Every frame is treated as untrusted. A client may be buggy, may be on a
        flaky connection that corrupts data, or may be hostile, so each frame
        is validated field by field before anything is done with it. A frame
        that fails validation earns a single 'error' reply and is then dropped;
        it never raises out of the loop, because doing so would disconnect the
        user. This defensive posture is the server-side counterpart to the
        authenticated-encryption checks the clients perform.

        Frames come in two flavours: text frames carry JSON control messages
        (hello, msg, file_init, file_end, getkey, presence) and binary frames
        carry one encrypted file chunk each. A binary chunk is prefixed with a
        fixed 36-byte header so the server can route it without ever looking
        at the ciphertext: 36 ASCII bytes of msg_id (a UUID string) followed
        by a 4-byte big-endian chunk index. Everything after that prefix is
        opaque to the server.
        """
        nick: str | None = None
        try:
            async for raw in ws:
                # ---- Binary frame path: a file chunk ---------------------
                # Binary frames never carry JSON; they are dispatched to a
                # dedicated handler that can fail fast on malformed prefixes
                # without trying to parse the bytes as text.
                if isinstance(raw, (bytes, bytearray)):
                    await self._handle_binary(ws, nick, bytes(raw))
                    continue

                # ---- Text frame path: a JSON control message -------------
                # Guard the entire per-frame body. Anything unexpected becomes
                # a logged warning plus an error reply, not a dead connection.
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    log.warning("Ignoring non-JSON frame")
                    await self._send_error(ws, "malformed JSON")
                    continue

                if not isinstance(msg, dict):
                    await self._send_error(ws, "frame must be a JSON object")
                    continue

                mtype = msg.get("type")

                try:
                    # ---- 1. Login / key upload --------------------------
                    if mtype == "hello":
                        new_nick = _require_str(msg, "nick").strip()
                        if not new_nick:
                            await self._send_error(ws, "empty nickname")
                            continue
                        if len(new_nick) > 64:
                            await self._send_error(ws, "nickname too long")
                            continue
                        pubkey = _require_hex(msg, "pubkey", expected_len=32)

                        # If this nickname is already online on another
                        # socket, drop the old one. This stops a stale ghost
                        # session from lingering in the presence list.
                        existing = self.online.get(new_nick)
                        if existing is not None and existing is not ws:
                            try:
                                await existing.close(
                                    code=4000, reason="logged in elsewhere")
                            except ConnectionClosed:
                                pass

                        nick = new_nick
                        self.storage.save_key(nick, pubkey)
                        self.online[nick] = ws
                        log.info("LOGIN  %s (%d online)",
                                 nick, len(self.online))

                        await ws.send(json.dumps(
                            {"type": "keys", "keys": self.storage.all_keys()}))
                        for env in self.storage.history_for(nick):
                            await ws.send(json.dumps(env))

                        # Replay any complete files that arrived while this
                        # user was offline. We send the original file_init
                        # JSON first, then each ciphertext chunk as a binary
                        # frame, then a synthetic file_end so the client knows
                        # the replay is complete and can finalise the file.
                        # Order matters: secretstream insists on chunks being
                        # decrypted in the same order they were encrypted.
                        for f in self.storage.pending_files_for(nick):
                            await ws.send(f["envelope"])
                            msg_id_bytes = f["msg_id"].encode("ascii")
                            for idx, ct in f["chunks"]:
                                frame = (
                                    msg_id_bytes
                                    + idx.to_bytes(4, "big")
                                    + ct
                                )
                                await ws.send(frame)
                            await ws.send(json.dumps({
                                "type": "file_end",
                                "msg_id": f["msg_id"],
                            }))

                        await self.broadcast_presence()

                    # ---- 2. Public-key lookup ---------------------------
                    elif mtype == "getkey":
                        target = _require_str(msg, "nick")
                        key = self.storage.get_key(target)
                        await ws.send(json.dumps({
                            "type": "key",
                            "nick": target,
                            "pubkey": key.hex() if key else None,
                        }))

                    # ---- 3. Encrypted message relay ---------------------
                    elif mtype == "msg":
                        # A message may only be sent once the sender has
                        # identified itself with a hello. This stops anonymous
                        # sockets from injecting traffic.
                        if nick is None:
                            await self._send_error(ws, "must log in first")
                            continue

                        sender = _require_str(msg, "from")
                        recipient = _require_str(msg, "to")
                        # The 'from' field is advisory; the authoritative
                        # identity is the nick this socket logged in with. We
                        # overwrite it so a client cannot spoof another sender.
                        if sender != nick:
                            log.warning("Sender %r overridden to %r",
                                        sender, nick)
                            sender = nick
                            msg["from"] = nick
                            raw = json.dumps(msg)

                        nonce = _require_hex(msg, "nonce", expected_len=12)
                        ct = _require_hex(msg, "ct")
                        if len(ct) > MAX_CIPHERTEXT_BYTES:
                            await self._send_error(ws, "message too large")
                            continue
                        ts = int(msg.get("ts") or time.time() * 1000)

                        self.storage.save_message(
                            sender, recipient, nonce, ct, ts)
                        log.info(
                            "RELAY  %s -> %s  ciphertext=%s...(%d bytes)",
                            sender, recipient, ct.hex()[:24], len(ct))

                        target_ws = self.online.get(recipient)
                        if target_ws is not None:
                            await target_ws.send(raw)
                        # If the recipient is offline the ciphertext still sits
                        # in the database and will be replayed at their next
                        # login, so nothing is lost.

                    # ---- 4. File transfer announcement ------------------
                    # file_init carries the encrypted file metadata (filename,
                    # MIME, size) and the secretstream header. The server
                    # keeps it so an offline recipient can be told about
                    # pending files the moment they reconnect, and it
                    # forwards it immediately to an online recipient so they
                    # can prepare to receive the chunks that follow.
                    elif mtype == "file_init":
                        if nick is None:
                            await self._send_error(ws, "must log in first")
                            continue
                        msg_id = _require_str(msg, "msg_id")
                        recipient = _require_str(msg, "to")
                        # Same anti-spoofing rule as for text messages: the
                        # sender field is overwritten with the authenticated
                        # nickname so a client cannot impersonate anyone else.
                        msg["from"] = nick
                        raw = json.dumps(msg)
                        ts = int(msg.get("ts") or time.time() * 1000)
                        self.storage.save_file_init(
                            msg_id, nick, recipient, raw, ts)
                        log.info("FILE_INIT  %s -> %s  msg_id=%s",
                                 nick, recipient, msg_id)
                        target_ws = self.online.get(recipient)
                        if target_ws is not None:
                            await target_ws.send(raw)

                    # ---- 5. File transfer terminator --------------------
                    # file_end marks the stream as complete and triggers the
                    # 'final_seen' flag so the offline-replay logic only
                    # serves fully-arrived files. Only the original sender
                    # may close their own transfer.
                    elif mtype == "file_end":
                        if nick is None:
                            await self._send_error(ws, "must log in first")
                            continue
                        msg_id = _require_str(msg, "msg_id")
                        owner = self.storage.file_owner(msg_id)
                        if owner is None or owner[0] != nick:
                            await self._send_error(
                                ws, "unknown or unauthorised file id")
                            continue
                        self.storage.mark_file_complete(msg_id)
                        log.info("FILE_END   %s msg_id=%s", nick, msg_id)
                        target_ws = self.online.get(owner[1])
                        if target_ws is not None:
                            await target_ws.send(raw)

                    else:
                        log.warning("Unknown message type: %r", mtype)
                        await self._send_error(
                            ws, f"unknown message type: {mtype!r}")

                except _ValidationError as e:
                    # One bad field: reject this frame, keep the connection.
                    log.warning("Rejected %s frame: %s", mtype, e)
                    await self._send_error(ws, str(e))

        except ConnectionClosed:
            pass
        finally:
            if nick and self.online.get(nick) is ws:
                del self.online[nick]
                log.info("LOGOUT %s (%d online)", nick, len(self.online))
                await self.broadcast_presence()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def make_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


async def amain(args: argparse.Namespace) -> None:
    storage = Storage(args.db)
    server = ChatServer(storage)

    ssl_ctx = None
    if args.cert and args.key:
        ssl_ctx = make_ssl_context(args.cert, args.key)
        scheme = "wss"
    else:
        scheme = "ws"
        log.warning("Running WITHOUT TLS - development only!")

    # Allow Ctrl-C to stop the loop cleanly.
    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    try:
        loop.add_signal_handler(signal.SIGINT, stop.set_result, None)
        loop.add_signal_handler(signal.SIGTERM, stop.set_result, None)
    except NotImplementedError:
        pass  # Windows does not support add_signal_handler for these.

    async with serve(server.handle, args.host, args.port, ssl=ssl_ctx):
        log.info("Listening on %s://%s:%d", scheme, args.host, args.port)
        await stop
    log.info("Server stopped.")


def main() -> None:
    p = argparse.ArgumentParser(description="E2EE chat server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--db", default="chat.db")
    p.add_argument("--cert", help="Path to TLS certificate (fullchain.pem)")
    p.add_argument("--key", help="Path to TLS private key (privkey.pem)")
    args = p.parse_args()
    asyncio.run(amain(args))


if __name__ == "__main__":
    main()
