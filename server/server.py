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
import collections
import contextvars
import json
import logging
import os
import signal
import sqlite3
import ssl
import weakref
import time
from pathlib import Path

from websockets.asyncio.server import serve, ServerConnection
from websockets.exceptions import (
    ConnectionClosed, InvalidMessage, InvalidUpgrade)

from prekey_store import PrekeyStore

# ---------------------------------------------------------------------------
# LOGGING -- deep capture + live streaming to clients ("server logs in the
# client's Log screen").
#
# Every record ANY logger in this process produces -- our own chat-server
# lines, plus the websockets and asyncio library internals down to DEBUG
# (frame-by-frame "> TEXT ..."/"< TEXT ..." traces, ping/pong keepalives,
# handshakes) -- is captured by the _LogRing handler below into a bounded
# ring. The ChatServer streams that ring to every logged-in client: a
# snapshot of recent lines right after login, then live batches about once a
# second (see broadcast_logs_forever). The client mirrors each line into its
# in-app Log screen under a [server] tag, so the relay's runtime is visible
# on-device with no SSH session.
#
# Both handlers sit at INFO -- policy: NECESSARY ONLY. The client's Log
# screen and the systemd journal both show the relay's own operational
# lines (LOGIN / REGISTER / PREKEYS / FILE_CHUNK / REJECT / warnings) and
# nothing below that. The websockets and asyncio library internals -- the
# frame-by-frame "> TEXT ..."/"< TEXT ..." traces, ping/pong keepalives and
# handshake chatter -- live at DEBUG and are therefore no longer captured or
# streamed. Raising the root logger to INFO (below) means those DEBUG
# records are never even formatted, so the cost is removed, not just hidden.
#
# FEEDBACK-LOOP SAFETY (retained as defence-in-depth): SENDING a log batch is
# itself websocket traffic. At INFO that send is a DEBUG record and is
# already below the ring's level, so it cannot loop; but if the depth is ever
# raised back to DEBUG for a debugging session, the loop would return. The
# _IN_LOG_FLUSH guard closes it unconditionally: it is a contextvar set inside
# the broadcast task only, so every record emitted while that task is awaiting
# its sends carries the flag (asyncio gives each task its own context) and is
# dropped by _LogRing.emit() before it can re-enter the ring. Records from
# every OTHER task -- real chat traffic, logins, errors -- are unaffected.
#
# PRIVACY (deliberate): these lines are relay METADATA -- nicknames, who is
# online, who relayed to whom, sizes, timings. The server never holds
# plaintext or private keys, so no log line can contain them; but every
# logged-in client does see the same shared stream. That is the requested
# always-on behaviour for this development/demo deployment; call it out in
# the thesis next to the always-on client log viewer.
# ---------------------------------------------------------------------------

LOG_RING_MAX = 400          # lines kept for the login snapshot
LOG_BATCH_MAX = 200         # max lines per live batch frame
LOG_FLUSH_INTERVAL = 1.0    # seconds between live batches

# ONE format, used by BOTH log destinations -- the systemd journal (via the
# console handler) and the client's in-app Log screen (via _LogRing).
#
# They used to differ, and each was missing something the other had. The journal
# format carried the date but dropped the logger name, so an operational line
# from the relay could not be told apart from one emitted by the websockets
# library. The ring format carried the logger name and milliseconds but dropped
# the DATE -- which made a client's Log screen genuinely ambiguous: the deployed
# relay's screen showed a "03:54:51" startup block sitting directly above a
# "23:28:26" login, with nothing to reveal that they were two DAYS apart.
#
# A relay that runs for months, whose log is read next to certificate dates
# ("notAfter Oct 22 ..."), and whose entries cross midnight, must not force the
# reader to guess the day. Milliseconds are kept because relay latency is
# measured by comparing the server's timestamp against the client's own; the
# logger name is kept because separating our lines from library lines is the
# first thing anyone does when reading this log.
#
# systemd renders the journal copy in the machine's local zone; run
# `journalctl -u wsserver --utc` to read it in UTC regardless of that zone. The
# startup "Clock:" line states both, once, so the zone is never in doubt.
_LOG_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-7s [%(name)s] %(message)s"
_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# True only inside the log-broadcast task; see loop-safety note above.
_IN_LOG_FLUSH: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "in_log_flush", default=False)


class _LogRing(logging.Handler):
    """Captures every record into one bounded, sequence-numbered ring.

    THE DUPLICATE-LINE BUG THIS DESIGN REPLACES

    The ring used to be paired with a second deque, 'pending', which the
    broadcast task drained destructively. Two independent delivery paths read
    from the two deques and neither knew what the other had sent:

      * send_log_snapshot() sent the whole ring to a client at login;
      * broadcast_logs_forever() popped 'pending' and sent that to everyone.

    'pending' was only drained while at least one client was online, so before
    the FIRST login it still held every line since startup -- exactly the same
    lines the snapshot had just sent. That client therefore received the entire
    log twice: once as its snapshot, then again a second later as the first
    live batch. The deployed relay showed precisely this, every line from the
    startup TLS block through LOGIN appearing in duplicate in the client's Log
    screen. A client logging in mid-stream hit a smaller version of the same
    overlap.

    THE FIX

    One ring, and every entry carries a monotonically increasing 'seq'. Each
    connection remembers the last seq it has been sent (ChatServer._log_cursor).
    A snapshot sets that cursor to the ring's tail; the broadcaster then sends
    each client only the entries beyond ITS OWN cursor. A line can therefore be
    delivered to a given client exactly once, whatever order logins and batches
    happen in, and with any number of clients online.

    'seq' is process-lifetime monotonic and never reused, so a cursor cannot be
    confused by ring eviction: an old cursor simply selects everything still
    resident, which is the correct behaviour for a client that has been quiet
    longer than the ring is deep.

    emit() only formats and appends -- it never touches the network -- so it is
    safe to call from any logging site, including inside websockets' own
    internals.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)   # necessary-only: no library DEBUG
        # Same format as the console handler (see _LOG_FORMAT): the client's Log
        # screen and the systemd journal must show a line identically, or
        # comparing the two while debugging means translating between formats.
        self.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
        self.ring: collections.deque = collections.deque(maxlen=LOG_RING_MAX)
        self._seq = 0

    def emit(self, record: logging.LogRecord) -> None:
        if _IN_LOG_FLUSH.get():
            return                      # the flusher's own traffic: drop
        try:
            line = self.format(record)
        except Exception:               # a formatter error must never recurse
            return
        self._seq += 1
        # 'seq' is additive: older clients read only 'line'/'level' and ignore
        # it, so no client rebuild is needed to benefit from the de-duplication.
        self.ring.append({"seq": self._seq, "level": record.levelname,
                          "line": line})

    @property
    def head_seq(self) -> int:
        """Sequence number of the most recent entry (0 when nothing logged)."""
        return self._seq

    def since(self, cursor: int, limit: int) -> list:
        """Up to 'limit' entries newer than 'cursor', oldest first."""
        return [e for e in self.ring if e["seq"] > cursor][:limit]


_console = logging.StreamHandler()
_console.setLevel(logging.INFO)
# Same format as the client-streamed copy -- see _LOG_FORMAT above for why the
# two were unified and what each was previously missing.
_console.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))


class _HandshakeNoiseFilter(logging.Filter):
    """Quieten the traceback a bare TCP connection produces on a public port.

    WHAT THIS ADDRESSES

    A relay exposed on a public port is probed constantly: port scanners,
    uptime monitors, a browser that someone points at https://host:8765, load
    balancers doing a TCP-only health check. Each of these opens a TCP
    connection and then does NOT speak the WebSocket handshake -- it sends
    nothing and closes, or sends bytes that are not an HTTP request line. The
    websockets library treats that as an error and, at
    `asyncio/server.py` conn_handler, logs it on the `websockets.server`
    logger as:

        ERROR  opening handshake failed
        Traceback (most recent call last):
          ... ~30 lines ...
        websockets.exceptions.InvalidMessage: did not receive a valid HTTP request

    That is thirty lines of stack trace for a completely routine non-event. In
    the deployed journal it appeared once between startup and the first login
    -- harmless, but alarming to read and enough of it would bury real errors.

    WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT DO

    It recognises EXACTLY the benign case -- an `InvalidMessage` (the client
    never completed the opening handshake) or a bare `EOFError`/`ConnectionError`
    underneath it -- and rewrites that one record into a single INFO line with
    no traceback. Every other error on the `websockets.server` logger,
    including "connection handler failed" (a real fault in our handler) and any
    handshake exception that is NOT one of these expected types, is passed
    through untouched, traceback and all. The filter narrows noise; it never
    hides a genuine problem.

    A filter is the right tool rather than raising the logger's level or
    detaching it: level-raising would also silence real errors from the same
    logger, and this leaves the library's own logging intact for everything
    that matters.
    """

    #: The peer opened TCP and then never spoke a valid HTTP request at all:
    #: it sent nothing and closed, or sent bytes that are not a request line.
    _NEVER_SPOKE_HTTP = (InvalidMessage, EOFError, ConnectionError)

    #: The peer DID send a well-formed HTTP request, but an ordinary one rather
    #: than a WebSocket upgrade -- no `Upgrade: websocket`, or (as observed in
    #: the deployed journal) `Connection: close`. This is a browser pointed at
    #: https://host:8765/, `curl`, or an HTTP health check. The library answers
    #: it correctly with 426 Upgrade Required -- which it logs on its own as a
    #: tidy one-line INFO -- and then ALSO raises InvalidUpgrade out of the
    #: handshake, producing the second, noisy record this filter rewrites.
    #:
    #: Kept separate from _NEVER_SPOKE_HTTP so the collapsed line can say which
    #: of the two actually happened. "Closed before completing the handshake"
    #: would be untrue here: nothing was closed early, the request was answered.
    _PLAIN_HTTP = (InvalidUpgrade,)

    #: What is deliberately NOT in either tuple, and why it keeps its traceback:
    #:   SecurityError      -- headers over the size limit; a resource-exhaustion
    #:                         probe, not routine noise. Worth seeing in full.
    #:   InvalidOrigin      -- a real WebSocket client refused by origin policy;
    #:                         a policy decision, not background scanning.
    #:   everything else    -- including "connection handler failed", which means
    #:                         a fault in OUR handler.
    #: Widening past the two tuples above would start hiding faults.

    def _benign_summary(self, exc: BaseException | None) -> str | None:
        """Return a one-line replacement message, or None to leave the record.

        Walks the cause/context chain because websockets raises the outer
        exception "from" an underlying one -- an InvalidMessage sits on top of
        an EOFError, for instance -- so the type that identifies the case may be
        a link or two down. The plain-HTTP test comes first at each link so a
        chain carrying both classifies as the more specific of the two.
        """
        seen: set[int] = set()
        while exc is not None and id(exc) not in seen:
            if isinstance(exc, self._PLAIN_HTTP):
                return ("plain HTTP request on the WebSocket port, answered "
                        "426 Upgrade Required (likely a browser, scanner or "
                        "health check)")
            if isinstance(exc, self._NEVER_SPOKE_HTTP):
                return ("connection closed before completing the WebSocket "
                        "handshake (likely a scan or health check)")
            seen.add(id(exc))
            exc = exc.__cause__ or exc.__context__
        return None

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.ERROR and record.exc_info:
            summary = self._benign_summary(record.exc_info[1])
            if summary is not None:
                # Collapse to one line, drop the traceback, lower the level so
                # it does not read as an error or trip error-based alerting.
                record.msg = summary
                record.args = ()
                record.exc_info = None
                record.exc_text = None
                record.levelno = logging.INFO
                record.levelname = "INFO"
        return True


# Attach to the library logger the handshake path uses. This does not touch our
# own 'chat-server' logger, and it is additive: the record still flows to the
# console and the log ring, just rewritten when it matches the benign case.
logging.getLogger("websockets.server").addFilter(_HandshakeNoiseFilter())

LOG_RING = _LogRing()

_root = logging.getLogger()
_root.setLevel(logging.INFO)            # capture depth: INFO and up (necessary only)
_root.addHandler(_console)              # journal view: INFO and up
_root.addHandler(LOG_RING)              # client view: INFO and up (same policy)

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


def _require_hex(msg: dict, field: str, expected_len=None) -> bytes:
    """Pull a required hex-encoded byte field, decode it, and length-check it.

    expected_len may be a single int, or a container of acceptable byte-lengths.
    The message nonce is no longer a fixed 12 bytes: AES-256-GCM uses 12 and
    XChaCha20-Poly1305 uses 24, so the caller passes {12, 24} and the actual
    cipher is authenticated inside the AEAD anyway. An X25519 key is still 32.
    """
    raw = _require_str(msg, field)
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        raise _ValidationError(f"field {field!r} is not valid hex")
    if expected_len is not None:
        allowed = {expected_len} if isinstance(expected_len, int) else set(expected_len)
        if len(data) not in allowed:
            ordered = sorted(allowed)
            want = (f"{ordered[0]} bytes" if len(ordered) == 1
                    else "one of " + ", ".join(str(x) for x in ordered) + " bytes")
            raise _ValidationError(
                f"field {field!r} must be {want}, got {len(data)}")
    return data


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
# Every Storage that has been constructed and not yet garbage-collected. Weak,
# so registration never extends an object's lifetime.
_OPEN_STORAGES: "weakref.WeakSet" = weakref.WeakSet()


class Storage:
    """Thin wrapper around an SQLite database.

    Two tables are used. 'users' is the public-key directory; it maps a
    nickname to the raw 32-byte X25519 public key that the client uploaded
    when it first logged in. 'messages' is the history of ciphertext
    envelopes. Note that no column anywhere holds plaintext.

    LIFECYCLE. Until recently this class opened a SQLite connection and never
    closed it. On Linux that is invisible: an open file can still be unlinked,
    so temporary directories clean up regardless. On Windows it is not, because
    an open handle blocks deletion, and the test suite failed with

        PermissionError: [WinError 32] The process cannot access the file
        because it is being used by another process

    on every temporary database. Worse, the leftover locked files then jammed
    pytest's own tmp_path base directory, so unrelated tests failed at setup
    with WinError 5. close() and the registry below make shutdown explicit.
    """

    def __init__(self, path: str) -> None:
        # check_same_thread=False is safe here because every call happens on
        # the single asyncio event-loop thread; we never touch the connection
        # from a background thread.
        self._db = sqlite3.connect(path, check_same_thread=False)
        # Registered so close_all() can shut every open database down
        # deterministically. A WeakSet keeps no object alive.
        _OPEN_STORAGES.add(self)
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                nick    TEXT PRIMARY KEY,
                pubkey  BLOB NOT NULL,
                -- PASSWORD AUTHENTICATION (Design B, zero-knowledge).
                -- The server NEVER sees the password, not even encrypted. What
                -- it stores here is an Argon2id VERIFIER: an irreversible hash
                -- the client derives from the password with a client-held salt
                -- and a domain-separation tweak, uploaded ONCE at registration.
                -- On every later login the client re-derives the same value and
                -- the server compares the two byte-for-byte. A seized database
                -- yields only this Argon2id output, from which the password
                -- cannot be recovered -- exactly the property the message store
                -- already has for ciphertext. The password's REAL job happens
                -- entirely on the device: it wraps (encrypts) the user's X25519
                -- private key at rest via a SEPARATE Argon2id derivation, so the
                -- server never participates in that at all. Both columns are
                -- nullable so a database written by an older, password-less build
                -- still opens; a NULL verifier means "legacy account, not yet
                -- password-protected", handled explicitly in the hello path.
                pw_verifier BLOB,
                pw_salt     BLOB,
                -- Birthday, stored the SAME way as the password: never as a
                -- date, only as an irreversible Argon2id verifier the client
                -- derives from the normalised date under this account's salt.
                --
                -- A date of birth is personal data under the GDPR, and this
                -- relay is deployed in an EU university context, so keeping a
                -- plaintext birthday column would create a real obligation for
                -- no benefit: the server never needs to READ the date, only to
                -- confirm that a client which already knows it derived the same
                -- value. Hashing it means a seized database yields no birthdays.
                --
                -- Nullable, so accounts created before this column existed still
                -- open; NULL means "registered before birthdays were required".
                dob_verifier BLOB
            );
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sender      TEXT NOT NULL,
                recipient   TEXT NOT NULL,
                nonce       BLOB NOT NULL,
                ciphertext  BLOB NOT NULL,
                ts          INTEGER NOT NULL,
                -- The complete message frame as JSON. With the ratchet, a
                -- message carries a header (cipher, dh, pn, n) the receiver
                -- needs to advance its ratchet; storing the whole frame and
                -- replaying it verbatim means the relay never has to know which
                -- fields the crypto layer uses, and offline delivery still
                -- decrypts. Nullable for rows written by older builds.
                frame       TEXT
            );

            -- Per-recipient delivery cursor: the highest message id the server
            -- has already handed to this recipient (live or via replay). On
            -- login we replay only messages newer than this, so a returning
            -- user is not re-sent what they already received. SAFE BY DESIGN:
            -- if a cursor is missing it defaults to 0 (replay everything), so
            -- this can never lose a message -- at worst it re-sends, which the
            -- client's own duplicate suppression then drops.
            CREATE TABLE IF NOT EXISTS delivery_cursor (
                recipient   TEXT PRIMARY KEY,
                last_id     INTEGER NOT NULL
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

        # Bring an older users table up to the current schema (adds the two
        # password-verifier columns if this database predates them). No-op on a
        # fresh database and on every restart after the first.
        self._ensure_cred_columns()

        # Same treatment for the tables that gained columns later. This has to
        # be a separate ALTER pass for the same reason as the one above:
        # CREATE TABLE IF NOT EXISTS does NOTHING to a table that already
        # exists, so a database written by an older build keeps its old shape
        # no matter how the CREATE statement is edited.
        self._ensure_table_columns()

        # Concurrent access hygiene: WAL lets readers and a writer coexist, and
        # a busy timeout makes a contended write wait rather than error. These
        # also make the prekey pool's atomic claim robust under load.
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=30000")
        self._db.commit()

        # X3DH prekey bundle storage (signed prekeys + one-time prekey pool),
        # layered on this same connection. See prekey_store.py.
        self.prekeys = PrekeyStore(self._db)
        self.prekeys.create_tables()

    def save_key(self, nick: str, pubkey: bytes,
                 ik_type: str | None = None) -> None:
        """Store a user's identity public key and, from the X3DH work onwards,
        WHICH KIND of key it is.

        Both kinds are 32 bytes, so a client receiving one cannot tell them
        apart by inspection, and guessing is not an option: an Ed25519 key read
        as X25519 produces a Diffie-Hellman the peer will never match, and the
        conversation simply fails to decrypt with nothing to point at. The type
        is therefore recorded explicitly and served alongside the key.

        NULL means x25519 -- the legacy interpretation, which is what every row
        written before this column existed holds.
        """
        self._db.execute(
            "INSERT OR REPLACE INTO users (nick, pubkey, ik_type) VALUES (?, ?, ?)",
            (nick, pubkey, ik_type),
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

    def all_key_types(self) -> dict[str, str]:
        """{nick: "ed25519" | "x25519"} for every user.

        Served as a SEPARATE object beside the existing "keys" map rather than
        by changing that map's shape, so a client built before X3DH keeps
        parsing the directory exactly as it always did and simply ignores the
        addition.
        """
        rows = self._db.execute("SELECT nick, ik_type FROM users").fetchall()
        return {nick: (t or "x25519") for nick, t in rows}

    def key_type(self, nick: str) -> str:
        row = self._db.execute(
            "SELECT ik_type FROM users WHERE nick = ?", (nick,)).fetchone()
        return (row[0] or "x25519") if row else "x25519"

    # ----------------------------------------------------------------------
    # Password authentication (Design B verifier storage)
    # ----------------------------------------------------------------------
    # The server's whole role in authentication is to store, and later compare,
    # an irreversible Argon2id verifier plus the client-held salt used to derive
    # it. It performs NO hashing itself and never sees the password: the client
    # does the Argon2id work and uploads only the result. That keeps the server
    # blind, consistent with how it already treats message ciphertext.

    def _ensure_cred_columns(self) -> None:
        """Add pw_verifier / pw_salt to an OLD users table if missing.

        A database created by a pre-password build has a users table with only
        (nick, pubkey). CREATE TABLE IF NOT EXISTS will not alter it, so we add
        the columns here with ALTER TABLE, guarded by a check of the existing
        schema so this is a no-op on a fresh (already-correct) database and on
        every subsequent startup. SQLite ALTER TABLE ADD COLUMN is safe and
        cheap, and the new columns default to NULL for every existing row --
        i.e. every legacy account is marked "not yet password-protected".
        """
        cols = {
            row[1]
            for row in self._db.execute("PRAGMA table_info(users)").fetchall()
        }
        if "pw_verifier" not in cols:
            self._db.execute("ALTER TABLE users ADD COLUMN pw_verifier BLOB")
        if "pw_salt" not in cols:
            self._db.execute("ALTER TABLE users ADD COLUMN pw_salt BLOB")
        if "dob_verifier" not in cols:
            self._db.execute("ALTER TABLE users ADD COLUMN dob_verifier BLOB")
        if "ik_type" not in cols:
            # Which kind of identity key the pubkey column holds. Added rather
            # than inferred: both kinds are 32 bytes, so an existing database
            # cannot be examined to find out, and every row that predates this
            # column is x25519 by definition -- which NULL already says.
            self._db.execute("ALTER TABLE users ADD COLUMN ik_type TEXT")
        self._db.commit()

    # ----------------------------------------------------------------------
    # Schema migration for tables OTHER than users
    # ----------------------------------------------------------------------
    # WHY THIS EXISTS
    #
    # Every table in this file is created with CREATE TABLE IF NOT EXISTS. That
    # is exactly right for a fresh database and completely inert on an existing
    # one: if the table is already there, SQLite does nothing at all, no matter
    # what columns the CREATE statement now names. So a column added to the
    # statement above reaches a NEW database and never reaches a database that
    # was created before the column was written.
    #
    # That gap is quiet in the worst way. The server starts, logs
    # "Listening on wss://...", and looks completely healthy -- because opening
    # the database and creating the missing TABLES both succeed. The failure
    # only arrives at the first row that uses the missing COLUMN:
    #
    #     OperationalError: table messages has no column named frame
    #
    # On the live relay that means every stored (offline) message fails, while
    # startup gave no hint anything was wrong. The previous deployment relied
    # on someone remembering to run the ALTER by hand from a runbook before
    # starting the new build. That works right up until the once it doesn't,
    # and a step you must remember is not a migration -- it is a trap with
    # documentation attached.
    #
    # ADD COLUMN is the one ALTER that is safe to run unconditionally here: it
    # is O(1) in SQLite (it rewrites the schema, not the rows), the added
    # column is NULL for every existing row, and every column below is
    # deliberately nullable so old rows stay valid. Guarding on PRAGMA
    # table_info makes it a genuine no-op on the second and every later start.
    #
    # This deliberately does NOT try to be a general migration framework. It
    # handles exactly one kind of change -- "a nullable column was added" --
    # and anything else (a renamed column, a changed type, a new NOT NULL) has
    # to be thought about rather than automated.

    #: table -> {column: SQL type declaration}. Nullable columns only.
    _LATE_COLUMNS: dict[str, dict[str, str]] = {
        # Added with the Double Ratchet: the complete message frame as JSON,
        # carrying the header (cipher, dh, pn, n) a receiver needs to advance
        # its ratchet. Without it, offline delivery cannot decrypt.
        "messages": {"frame": "TEXT"},
        # Added so the relay can tell a fully-received file from a transfer
        # that was cut off mid-flight.
        "file_meta": {"final_seen": "INTEGER NOT NULL DEFAULT 0"},
    }

    def _ensure_table_columns(self) -> None:
        """Add any late-arriving nullable columns to pre-existing tables.

        Returns nothing and raises nothing on a healthy database. Each ALTER
        is logged at INFO, because a schema change on a production relay is
        precisely the kind of event that should appear in the journal rather
        than happening invisibly.
        """
        for table, wanted in self._LATE_COLUMNS.items():
            rows = self._db.execute(
                f"PRAGMA table_info({table})").fetchall()
            if not rows:
                # The table does not exist yet. That is not an error: the
                # CREATE statements above have already run, so this can only
                # mean the table is genuinely new, in which case it was just
                # created with every column present.
                continue
            have = {row[1] for row in rows}
            for column, decl in wanted.items():
                if column in have:
                    continue
                self._db.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
                log.info("SCHEMA migrated: added %s.%s (%s)",
                         table, column, decl)
        self._db.commit()

    def get_credential(self, nick: str) -> tuple[bytes | None, bytes | None]:
        """Return (pw_verifier, pw_salt) for a nick, each None if unset.

        Both being None means either the nick does not exist yet, or it exists
        but predates password protection (a legacy account). The caller
        distinguishes those two cases with get_key(), which is non-None only for
        an existing nick.
        """
        row = self._db.execute(
            "SELECT pw_verifier, pw_salt FROM users WHERE nick = ?", (nick,)
        ).fetchone()
        if row is None:
            return (None, None)
        return (row[0], row[1])

    def set_credential(
        self, nick: str, verifier: bytes, salt: bytes
    ) -> None:
        """Store (or replace) a nick's Argon2id verifier and its salt.

        Called once when a brand-new account registers, and again only if the
        user deliberately changes their password (the client re-derives a fresh
        verifier and salt and re-uploads). The row must already exist -- the key
        is saved first in the hello path -- so this is a plain UPDATE.
        """
        self._db.execute(
            "UPDATE users SET pw_verifier = ?, pw_salt = ? WHERE nick = ?",
            (verifier, salt, nick),
        )
        self._db.commit()

    def close(self) -> None:
        """Close the database. Safe to call more than once."""
        try:
            self._db.close()
        except Exception:                       # already closed, or mid-teardown
            pass

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @classmethod
    def close_all(cls) -> None:
        """
        Close every Storage still open in this process.

        Used by the test suite's teardown so that no SQLite handle outlives the
        test that created it. That matters only on Windows, but it matters a
        great deal there: a single leaked handle makes a temporary directory
        undeletable and the failure surfaces in a completely unrelated test.
        """
        for storage in list(_OPEN_STORAGES):
            storage.close()

    def get_dob_verifier(self, nick: str) -> bytes | None:
        """Return the stored birthday verifier for a nick, or None if unset.

        None means either the nick does not exist, or it was registered before
        birthdays were required. Callers distinguish those with get_key().

        This value is NEVER sent to a client. Returning it -- or even confirming
        a guess against it before authentication -- would turn the relay into an
        oracle for brute-forcing birthdays, which are a small search space
        (roughly thirty thousand plausible dates for an adult, often far fewer
        for a known person). The verifier exists so the account record is
        complete, not so the server can answer questions about it.
        """
        row = self._db.execute(
            "SELECT dob_verifier FROM users WHERE nick = ?", (nick,)
        ).fetchone()
        return None if row is None else row[0]

    def set_dob_verifier(self, nick: str, verifier: bytes) -> None:
        """Store a nick's birthday verifier. The row must already exist."""
        self._db.execute(
            "UPDATE users SET dob_verifier = ? WHERE nick = ?",
            (verifier, nick),
        )
        self._db.commit()

    def save_message(
        self, sender: str, recipient: str, nonce: bytes, ct: bytes, ts: int,
        frame: str | None = None,
    ) -> int:
        """Store a message frame and return its new row id.

        The id lets the live-delivery path advance the recipient's delivery
        cursor to exactly this message when it is relayed live, so it is not
        replayed again on the recipient's next login (Option 2).
        """
        cur = self._db.execute(
            "INSERT INTO messages "
            "(sender, recipient, nonce, ciphertext, ts, frame) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sender, recipient, nonce, ct, ts, frame),
        )
        self._db.commit()
        return int(cur.lastrowid)

    def delivery_cursor(self, recipient: str) -> int:
        """Highest message id already delivered to 'recipient' (0 if none)."""
        row = self._db.execute(
            "SELECT last_id FROM delivery_cursor WHERE recipient = ?",
            (recipient,),
        ).fetchone()
        return int(row[0]) if row else 0

    def advance_cursor(self, recipient: str, last_id: int) -> None:
        """Move the recipient's delivery cursor forward to 'last_id'.

        Never moves backward: a concurrent live delivery may already have set a
        higher cursor, so we keep the maximum.
        """
        self._db.execute(
            "INSERT INTO delivery_cursor (recipient, last_id) VALUES (?, ?) "
            "ON CONFLICT(recipient) DO UPDATE SET last_id = MAX(last_id, excluded.last_id)",
            (recipient, last_id),
        )
        self._db.commit()

    def history_for(self, nick: str, limit: int = 50) -> list[dict]:
        """Return envelopes 'nick' is party to that they have NOT yet received.

        Only messages with id greater than the recipient's delivery cursor are
        returned (Option 2: do not re-deliver what was already sent live). The
        cursor is advanced to the newest id returned, so a subsequent login does
        not replay these again. SAFE: a missing cursor is 0, so nothing is ever
        skipped on first login.
        """
        cursor = self.delivery_cursor(nick)
        rows = self._db.execute(
            "SELECT id, sender, recipient, nonce, ciphertext, ts, frame FROM messages "
            "WHERE (sender = ? OR recipient = ?) AND id > ? "
            "ORDER BY id ASC LIMIT ?",
            (nick, nick, cursor, limit),
        ).fetchall()
        out = []
        max_id = cursor
        for mid, sender, recipient, nonce, ct, ts, frame in rows:
            max_id = max(max_id, int(mid))
            if frame:  # ratchet-era row: replay the exact frame, header included
                try:
                    out.append(json.loads(frame))
                    continue
                except (ValueError, TypeError):
                    pass  # fall through to the legacy reconstruction
            out.append({
                "type": "msg", "from": sender, "to": recipient,
                "nonce": nonce.hex(), "ct": ct.hex(), "ts": ts,
            })
        if max_id > cursor:
            self.advance_cursor(nick, max_id)
        return out

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

    def pending_files_for(
        self, nick: str, have_ids: set[str] | None = None
    ) -> list[dict]:
        """Return queued files for an offline-now-online recipient.

        Each entry contains the original file_init envelope and the ordered
        ciphertext chunks, ready for replay. We only return fully-arrived
        transfers (final_seen = 1) so a recipient never sees a half-sent
        file with no final tag, which decryption would correctly refuse.

        'have_ids' is the set of file msg_ids the client reported (in its hello
        "have_files") as ALREADY received. Those are skipped, so a client is not
        re-sent files it already holds -- which stops the phantom re-transfer on
        every login. A client whose data was wiped reports an empty set, so every
        file is returned and the transfers survive the wipe, as intended.
        """
        have_ids = have_ids or set()
        meta_rows = self._db.execute(
            "SELECT msg_id, envelope FROM file_meta "
            "WHERE recipient = ? AND final_seen = 1 "
            "ORDER BY ts ASC",
            (nick,),
        ).fetchall()
        result = []
        for msg_id, envelope in meta_rows:
            if msg_id in have_ids:
                continue  # client already has this file; do not replay it
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
        # Per-connection high-water mark into LOG_RING, keyed by the socket
        # rather than the nick so a reconnect under the same nick starts clean.
        # Pruned to the online set on every broadcast pass, so it cannot grow.
        self._log_cursor: dict[ServerConnection, int] = {}

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

    async def broadcast_logs_forever(self) -> None:
        """Stream captured log lines to every logged-in client, forever.

        Runs as a single background task started in amain(). About once a
        second it sends each online client the ring entries beyond THAT
        CLIENT'S OWN cursor, as one "server_log" frame; the client mirrors them
        into its Log screen.

        PER-CLIENT CURSORS, NOT A SHARED DRAINED QUEUE. Each connection has its
        own high-water mark in self._log_cursor, so what one client has already
        received never affects another, and a line a client got in its login
        snapshot is never sent to it again. That is what removes the duplicate
        delivery described in _LogRing's docstring -- previously the snapshot
        and the first live batch overlapped completely for the first client to
        log in, which showed up as every line appearing twice in its Log screen.

        The whole body runs with _IN_LOG_FLUSH set in THIS task's context, so
        the DEBUG records the websockets library emits for these very sends are
        dropped by _LogRing.emit() -- the loop-safety guarantee described at the
        top of the file.

        The cursor map is pruned to exactly the current online set on every
        pass, so a disconnected client cannot leak an entry even if the socket
        went away between the disconnect path and here.
        """
        _IN_LOG_FLUSH.set(True)
        while True:
            await asyncio.sleep(LOG_FLUSH_INTERVAL)
            if not self.online:
                continue
            live = set(self.online.values())
            # Prune first: self-healing, so no disconnect path can leak here.
            for gone in [w for w in self._log_cursor if w not in live]:
                del self._log_cursor[gone]
            head = LOG_RING.head_seq
            for ws in list(self.online.values()):
                cursor = self._log_cursor.get(ws, head)
                if cursor >= head:
                    self._log_cursor[ws] = cursor
                    continue                    # nothing new for this client
                batch = LOG_RING.since(cursor, LOG_BATCH_MAX)
                if not batch:
                    self._log_cursor[ws] = head
                    continue
                try:
                    await ws.send(json.dumps(
                        {"type": "server_log", "lines": batch}))
                except ConnectionClosed:
                    continue    # leave the cursor; the prune above clears it
                # Advance only on a successful send, and only as far as what was
                # actually sent -- a batch capped at LOG_BATCH_MAX leaves the
                # remainder to be picked up on the next pass rather than lost.
                self._log_cursor[ws] = batch[-1]["seq"]

    async def send_log_snapshot(self, ws: ServerConnection) -> None:
        """Send the recent server-log ring to one just-logged-in client.

        Called from the hello path right after the key dump, so the client's
        Log screen starts populated with what the relay was doing BEFORE this
        login (including this login's own handling). Runs in the connection's
        task -- WITHOUT the flush guard -- so the records this send produces
        are themselves captured and will reach everyone in the next live
        batch; that is fine (they are ordinary traffic), only the broadcast
        task's own sends must be suppressed to break the feedback loop.

        Setting this connection's cursor to the ring head is what makes the
        snapshot and the live stream disjoint: the broadcaster will only ever
        send this client lines logged AFTER the snapshot it just received.

        The cursor is set even when the ring is empty or the send fails, so a
        client can never be handed the whole backlog a second time as its
        "first" live batch.
        """
        self._log_cursor[ws] = LOG_RING.head_seq
        snapshot = list(LOG_RING.ring)
        if not snapshot:
            return
        try:
            await ws.send(json.dumps(
                {"type": "server_log", "lines": snapshot, "snapshot": True}))
        except ConnectionClosed:
            pass

    def _recipient(self, msg: dict, nick: str) -> str:
        """Resolve and validate the "to" field of a relay frame.

        Beyond the ordinary type check, this refuses a frame a client addresses
        to ITSELF. A relay has nothing to do with such a frame: the sender is
        the recipient, so "delivery" would mean echoing it back, and the client
        discards anything whose sender is its own nick anyway.

        It is refused rather than quietly dropped because a self-addressed frame
        is always a defect worth surfacing -- and because two of the types would
        otherwise leave a trace. 'verifyack' and 'delete' are store-and-forward:
        they persist into the messages table, so a client looping self-addressed
        acks would grow a permanent self-conversation in the relay's database
        that no one ever collects. 'msg' would do the same with ciphertext.

        The root cause of the one occurrence observed in deployment is fixed
        separately, by excluding a client's own entry from its directory dump.
        This guard is the backstop: it holds even for a client that computes a
        recipient some other way, or a hostile one that does it deliberately.

        Raising _ValidationError gives the standard behaviour for a bad field --
        a polite error reply on the same connection, which stays open.
        """
        recipient = _require_str(msg, "to")
        if recipient == nick:
            raise _ValidationError(
                "'to' must be another user, not yourself")
        return recipient

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
                    # ---- 0. Pre-login salt fetch (password portability) --
                    # THE FIX for "Passwords mismatch even though the password
                    # is correct". The Argon2id VERIFIER the client sends in its
                    # hello is a function of (password, salt). Previously the
                    # salt lived only in the registering device's QSettings, so
                    # a SECOND device (or the same device after that setting was
                    # overwritten) derived its verifier under a DIFFERENT salt
                    # and could never match the stored one -- a correct password
                    # was rejected with 'password mismatch'.
                    #
                    # The salt is not a secret: it is a public parameter of the
                    # hash whose entire purpose is to be stored next to the
                    # verifier (this server already keeps it in users.pw_salt).
                    # So the client may now ask for it BEFORE authenticating:
                    #
                    #   client: {"type": "auth_begin", "nick": "<name>"}
                    #   server: {"type": "auth_salt",  "nick": "<name>",
                    #            "salt": "<hex>" | null}
                    #
                    # 'salt' is the stored salt for an account that has a
                    # password, or null when there is no stored credential (new
                    # nick, or a legacy password-less account) -- the client
                    # then derives under a fresh salt exactly as before. With
                    # the server's salt in hand, EVERY device that knows the
                    # correct password derives the SAME verifier, so logins
                    # match regardless of which device registered.
                    #
                    # Notes:
                    #   * Deliberately answerable before (and without) a hello:
                    #     it reveals only whether a nickname has a password set,
                    #     never the verifier itself, which stays irreversible.
                    #   * Fully backward compatible: an older client simply
                    #     never sends auth_begin and behaves exactly as before.
                    if mtype == "auth_begin":
                        ab_nick = _require_str(msg, "nick").strip()
                        if not ab_nick or len(ab_nick) > 64:
                            await self._send_error(ws, "bad nickname")
                            continue
                        _ab_verifier, ab_salt = \
                            self.storage.get_credential(ab_nick)
                        await ws.send(json.dumps({
                            "type": "auth_salt",
                            "nick": ab_nick,
                            "salt": (bytes(ab_salt).hex()
                                     if ab_salt is not None else None),
                        }))
                        continue

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
                        # X3DH: which kind of identity key this is. Absent means
                        # x25519, so a client that predates X3DH keeps working
                        # unchanged. Anything else is rejected rather than
                        # stored, because a value the directory cannot describe
                        # would leave peers guessing -- the exact failure this
                        # field exists to remove.
                        ik_type = msg.get("ik_type") or "x25519"
                        if ik_type not in ("x25519", "ed25519"):
                            await self._send_error(ws, "unknown ik_type")
                            continue

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

                        # STRICT USERNAME RESERVATION (first-come, key-locked).
                        # A nickname is permanently bound to the FIRST identity key
                        # that registered it. If the server already holds a key for
                        # this nick and the incoming key is DIFFERENT, this is not
                        # the original owner (a different device, or the owner after
                        # a data wipe that regenerated the identity) -- reject the
                        # login outright rather than overwriting the registration.
                        # This guarantees each username maps to exactly one identity
                        # for the life of the server database, whether or not the
                        # owner is currently online. NOTE (by explicit design): this
                        # means a nick can NEVER be reclaimed with a new key once
                        # taken -- reclaiming after a wipe requires a new nickname.
                        # The same key re-registering (the original owner returning,
                        # including after a same-device reinstall that kept the key)
                        # is allowed and falls through to the normal path.
                        reserved_key = self.storage.get_key(nick)
                        if reserved_key is not None and reserved_key != pubkey:
                            log.info(
                                "REJECT %s: nickname is reserved to a different "
                                "identity key (have %s..., got %s...)",
                                nick, reserved_key.hex()[:16], pubkey.hex()[:16])
                            await self._send_error(
                                ws,
                                "This username is already registered to a "
                                "different identity on this server. Usernames are "
                                "permanent: please choose a different name.")
                            # Close the socket so the client cannot proceed under a
                            # nickname it does not own. A distinct close code lets
                            # the client show a clear 'name taken' message.
                            try:
                                await ws.close(
                                    code=4001, reason="username reserved")
                            except ConnectionClosed:
                                pass
                            return

                        # PASSWORD AUTHENTICATION (Design B, zero-knowledge).
                        # The password itself is NEVER transmitted. The client
                        # sends, at most, an Argon2id VERIFIER (hex) and the salt
                        # it was derived under. The server only stores and later
                        # compares that verifier; it cannot recover the password
                        # from it and never tries. Four cases, decided by whether
                        # the nick already exists (get_key) and whether it already
                        # carries a verifier (get_credential):
                        #
                        #   1. NEW nick + verifier supplied  -> registration:
                        #      remember the verifier+salt, then proceed.
                        #   2. NEW nick + NO verifier         -> a password-less
                        #      client (older build, or a caller that opted out):
                        #      allowed, account simply has no password. Keeps the
                        #      server backward-compatible and never forces a
                        #      password on a client that did not send one.
                        #   3. EXISTING nick WITH a stored verifier -> returning
                        #      user: the supplied verifier MUST match the stored
                        #      one, else reject with a distinct close code (4002)
                        #      BEFORE anything is marked online or any history is
                        #      sent. A wrong password therefore learns nothing.
                        #   4. EXISTING nick with NO stored verifier (legacy
                        #      account, pre-password) -> accept, and if a verifier
                        #      is now supplied, UPGRADE the account by storing it,
                        #      so the next login is protected. This lets an old
                        #      account adopt a password without losing its name.
                        #
                        # Note the ordering: this runs AFTER the strict key
                        # reservation (so a stolen-name attempt with the wrong key
                        # is still rejected first, as before) but BEFORE the nick
                        # is added to self.online or sent its key dump and history
                        # (so a wrong password never yields a single byte).
                        # Birthday verifier, required for NEW password-protected
                        # accounts (see the enforcement block below). Optional in
                        # the message so that a legacy client's login to an
                        # EXISTING account is unaffected.
                        supplied_dob = None
                        if "dob_verifier" in msg:
                            supplied_dob = _require_hex(msg, "dob_verifier")

                        supplied_verifier = None
                        supplied_salt = None
                        if "pw_verifier" in msg:
                            # Verifier length is a client convention (Argon2id raw
                            # output, 32 bytes here); we do not hard-fail on an
                            # unexpected length, we just require valid hex, since
                            # the server only ever compares bytes for equality.
                            supplied_verifier = _require_hex(msg, "pw_verifier")
                            supplied_salt = _require_hex(msg, "pw_salt")

                        stored_verifier, _stored_salt = \
                            self.storage.get_credential(nick)
                        nick_exists = reserved_key is not None

                        # BIRTHDAY REQUIREMENT.
                        #
                        # Every NEW password-protected account must supply a
                        # birthday verifier. This is scoped deliberately:
                        #
                        #   * only NEW nicks -- an existing account logging in
                        #     again is never asked for it, so nobody is locked
                        #     out of an account created before this rule;
                        #   * only password-protected registrations -- the
                        #     documented password-less compatibility path
                        #     (case 2 below) is left exactly as it was, because
                        #     tightening it would break older clients for a
                        #     value the server cannot use anyway.
                        #
                        # A distinct close code makes the cause unambiguous in
                        # the client, rather than surfacing as a generic refusal.
                        if (not nick_exists
                                and supplied_verifier is not None
                                and supplied_dob is None):
                            log.info("register refused, no birthday: %s", nick)
                            await ws.close(
                                code=4003,
                                reason="birthday required for new accounts")
                            return

                        if nick_exists and stored_verifier is not None:
                            # Case 3: returning protected account -- must verify.
                            # constant-ish time compare; hmac.compare_digest
                            # avoids a byte-by-byte early-exit timing signal.
                            import hmac as _hmac
                            ok = (supplied_verifier is not None
                                  and _hmac.compare_digest(
                                      bytes(stored_verifier),
                                      bytes(supplied_verifier)))
                            if not ok:
                                log.info("REJECT %s: password mismatch", nick)
                                await self._send_error(
                                    ws, "Incorrect password for this username.")
                                try:
                                    await ws.close(
                                        code=4002, reason="bad password")
                                except ConnectionClosed:
                                    pass
                                return
                        elif nick_exists and stored_verifier is None:
                            # Case 4: legacy account. Accept; upgrade if able.
                            # The key row already exists, so set_credential's
                            # UPDATE will land once save_key (below) has run --
                            # but the row is already present from the original
                            # registration, so we can store immediately.
                            if supplied_verifier is not None:
                                self.storage.set_credential(
                                    nick, supplied_verifier, supplied_salt)
                                log.info("UPGRADE %s: password set on a "
                                         "previously password-less account", nick)
                        # else: nick is new -- registration (case 1) or a
                        # password-less new account (case 2). The verifier, if
                        # any, is stored just after save_key below, once the row
                        # exists.

                        # KEY-CHANGE DETECTION + PEER NOTIFICATION (options a+b).
                        # save_key does INSERT OR REPLACE; with the reservation
                        # check above, the only key that ever reaches it for an
                        # existing nick is the SAME key (owner returning), so the
                        # stored registration is effectively immutable. A truly new
                        # nick registers here for the first time. We still compute
                        # key_changed for the notify path, though under strict
                        # reservation it can only be false for an existing nick.
                        prev_key = self.storage.get_key(nick)
                        self.storage.save_key(nick, pubkey, ik_type)
                        # Case 1 completion: a brand-new account that supplied a
                        # verifier now has its (nick, pubkey) row, so store the
                        # verifier+salt against it. (Cases 3 and 4 were fully
                        # handled above; case 2 supplied no verifier, so there is
                        # nothing to store and the account stays password-less.)
                        if prev_key is None and supplied_verifier is not None:
                            self.storage.set_credential(
                                nick, supplied_verifier, supplied_salt)
                            log.info("REGISTER %s: password verifier stored", nick)
                            # The birthday verifier is stored alongside it. Its
                            # presence was already enforced above, so reaching
                            # here with None is not possible for a new
                            # password-protected account.
                            if supplied_dob is not None:
                                self.storage.set_dob_verifier(nick, supplied_dob)
                                log.info("REGISTER %s: birthday verifier stored",
                                         nick)
                        key_changed = (prev_key is not None
                                       and prev_key != pubkey)
                        # A brand-NEW identity (the server has never seen this
                        # nick) is, from the perspective of an ALREADY-ONLINE
                        # peer, exactly as unknown as a CHANGED one: that peer
                        # received its roster snapshot before this nick existed,
                        # so it holds no key for this nick at all. It must be told
                        # the current key now, or it will compute the safety
                        # number / ratchet role against a missing or late-arriving
                        # key and transiently disagree with this client -- the
                        # "safety numbers don't match whenever a new client joins"
                        # bug. So we push key_update for a new key as well as a
                        # changed one; only an UNCHANGED re-announce (same nick,
                        # same key, e.g. a plain reconnect) needs no push, since
                        # peers already hold that key.
                        key_is_new = (prev_key is None)
                        notify_peers = key_changed or key_is_new
                        self.online[nick] = ws
                        log.info("LOGIN  %s (%d online)%s",
                                 nick, len(self.online),
                                 " [KEY CHANGED]" if key_changed
                                 else " [NEW KEY]" if key_is_new else "")

                        # SELF-EXCLUSION. The directory dump lists the OTHER
                        # users, never the requester. Sending a client its own
                        # entry made it treat itself as a peer: its "keys"
                        # handler runs key-change detection over every entry
                        # with no self-check, so on a fresh registration it
                        # flagged an identity change against ITSELF and emitted
                        # a self-addressed verify_resync -- the deployed
                        # relay's "VERIFYRESYNC m70 -> m70" line, logged with
                        # exactly one user online. The client discards frames
                        # whose sender is itself, so nothing came of it, but it
                        # also inserted its own nick into m_peerKeys, which is
                        # the set reestablishPcsForAll() iterates when forcing a
                        # ratchet step -- so the relay was seeding a self-peer
                        # into post-compromise recovery as well.
                        #
                        # The key_update push a few lines below has always
                        # excluded the originating socket; this makes the bulk
                        # dump agree with it. Verified against the client: it
                        # never reads its own entry back out of the dump (it
                        # holds its own key locally, from CryptoBox), so this
                        # removes work rather than information -- and needs no
                        # client rebuild, since it only makes the map smaller.
                        directory = {other: key
                                     for other, key in self.storage.all_keys().items()
                                     if other != nick}
                        await ws.send(json.dumps(
                            {"type": "keys", "keys": directory,
                             "key_types": {
                                 k: v for k, v
                                 in self.storage.all_key_types().items()
                                 if k in directory}}))

                        # SERVER LOGS -> CLIENT LOG SCREEN: seed this client
                        # with the recent server-side log ring immediately, so
                        # its in-app Log screen shows the relay's runtime from
                        # login onward; live lines follow from the broadcast
                        # task about once a second.
                        await self.send_log_snapshot(ws)
                        # Deliver the FULL stored backlog for this returning user,
                        # not just the first batch. history_for() returns up to 50
                        # envelopes at a time and advances the per-user delivery
                        # cursor, so a single call left any messages beyond 50
                        # undelivered until the user happened to log in again --
                        # which, combined with the client's flush timing, surfaced
                        # as "offline messages never arrive". Loop until a batch
                        # comes back empty so the whole backlog drains in this one
                        # login. The iteration cap is a safety valve against an
                        # unexpectedly non-advancing cursor (400 * 50 = 20000
                        # messages, far beyond any real backlog) so a pathological
                        # case cannot spin forever.
                        for _ in range(400):
                            batch = self.storage.history_for(nick)
                            if not batch:
                                break
                            for env in batch:
                                await ws.send(json.dumps(env))

                        # Notify all other online clients of this client's current
                        # key when it is new OR changed (see above), so they update
                        # their cached key and (for a change) re-establish the
                        # session against the new identity immediately, rather than
                        # waiting for a manual getkey or reconnect. The client
                        # handles a "key_update" exactly like a single "key" reply,
                        # so a new-key push simply teaches peers the key with no
                        # spurious safety-number banner (their key-change detection
                        # only flags when a PREVIOUS key differs).
                        if notify_peers:
                            notice = json.dumps({
                                "type": "key_update",
                                "nick": nick,
                                "pubkey": pubkey.hex(),
                                "ik_type": ik_type,
                            })
                            for other_nick, other_ws in list(self.online.items()):
                                if other_ws is ws:
                                    continue
                                try:
                                    await other_ws.send(notice)
                                except ConnectionClosed:
                                    pass

                        # Replay any complete files that arrived while this
                        # user was offline. We send the original file_init
                        # JSON first, then each ciphertext chunk as a binary
                        # frame, then a synthetic file_end so the client knows
                        # the replay is complete and can finalise the file.
                        # Order matters: secretstream insists on chunks being
                        # decrypted in the same order they were encrypted.
                        #
                        # The client's hello lists the file msg_ids it ALREADY
                        # holds ("have_files"); we skip those so a client is never
                        # re-sent a file it already has (the fix for phantom file
                        # transfers on every login). A client whose data was wiped
                        # sends an empty list, so every file is replayed and the
                        # transfers survive the wipe, as intended.
                        have_files_raw = msg.get("have_files", [])
                        have_ids = {
                            str(x) for x in have_files_raw
                        } if isinstance(have_files_raw, list) else set()
                        for f in self.storage.pending_files_for(nick, have_ids):
                            # PHANTOM-FAILURE FIX (Issue #1): mark the replayed
                            # file_init as a REPLAY. A file queued under a previous
                            # identity pairing can no longer be decrypted by a
                            # recipient whose identity has since changed (the
                            # per-file key derives from a shared secret that no
                            # longer exists), so its chunks fail the AEAD tag. That
                            # is expected for a stale offline file -- but without a
                            # marker the client cannot tell it apart from a live
                            # transfer and surfaces "File transfer failed:
                            # authentication failure" on every login. Tagging the
                            # envelope lets the client SILENTLY DROP a replayed file
                            # that fails to decrypt, while still reporting a genuine
                            # failure on a live transfer. We parse the stored
                            # envelope, add the flag, and re-serialize; if it is not
                            # valid JSON for any reason, fall back to sending it
                            # verbatim so replay is never broken by this.
                            envelope_out = f["envelope"]
                            try:
                                env_obj = json.loads(f["envelope"])
                                env_obj["replayed"] = True
                                envelope_out = json.dumps(env_obj)
                            except (ValueError, TypeError):
                                pass
                            await ws.send(envelope_out)
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
                        # "ik_type" must ride along. Both kinds of identity key
                        # are 32 bytes, so a client cannot tell an Ed25519 key
                        # from an X25519 one by inspection, and a wrong reading
                        # produces a Diffie-Hellman the peer never matches and a
                        # safety number that never agrees. The key_update push
                        # has always carried the type; this reply did not, which
                        # left the on-demand path -- the one used when a stored
                        # offline frame arrives for a peer whose key is not yet
                        # held -- guessing.
                        await ws.send(json.dumps({
                            "type": "key",
                            "nick": target,
                            "pubkey": key.hex() if key else None,
                            "ik_type": self.storage.key_type(target),
                        }))

                    # ---- 2b. X3DH: publish this user's prekey bundle -----
                    elif mtype == "publish_prekeys":
                        # A client uploads its signed prekey (+ signature) and a
                        # batch of one-time prekeys. Requires an established
                        # session (hello first), so prekeys are bound to a nick.
                        if nick is None:
                            await self._send_error(
                                ws, "must log in before publishing prekeys")
                            continue
                        spk_pub = _require_hex(msg, "spk", expected_len=32)
                        spk_sig = _require_hex(msg, "spk_sig", expected_len=64)
                        ts = int(msg.get("ts") or time.time() * 1000)
                        self.storage.prekeys.set_signed_prekey(
                            nick, spk_pub, spk_sig, ts)

                        # One-time prekeys: a JSON object {opk_id: opk_pub_hex}.
                        opks_in = msg.get("opks") or {}
                        if not isinstance(opks_in, dict):
                            await self._send_error(ws, "opks must be an object")
                            continue
                        prekeys: dict[int, bytes] = {}
                        try:
                            for oid, pub_hex in opks_in.items():
                                pub = bytes.fromhex(pub_hex)
                                if len(pub) != 32:
                                    raise ValueError("bad one-time prekey length")
                                prekeys[int(oid)] = pub
                        except (ValueError, TypeError):
                            await self._send_error(ws, "malformed one-time prekeys")
                            continue
                        added = self.storage.prekeys.add_one_time_prekeys(
                            nick, prekeys)
                        remaining = self.storage.prekeys.one_time_prekey_count(nick)
                        log.info("PREKEYS %s published spk + %d OPKs (pool=%d)",
                                 nick, added, remaining)
                        await ws.send(json.dumps({
                            "type": "prekeys_ack",
                            "added": added,
                            "remaining": remaining,
                        }))

                    # ---- 2c. X3DH: fetch a peer's prekey bundle ----------
                    elif mtype == "get_bundle":
                        # Serve a bundle for `nick`: identity key + signed prekey
                        # + one claimed one-time prekey (or null if pool empty).
                        # Claiming an OPK consumes it (single-use). The requester
                        # verifies the signature itself; the server is blind.
                        target = _require_str(msg, "nick")
                        identity = self.storage.get_key(target)
                        bundle = self.storage.prekeys.get_bundle(target, identity)
                        await ws.send(json.dumps({
                            "type": "bundle",
                            "nick": target,
                            "bundle": bundle,   # null if no prekeys published yet
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
                        recipient = self._recipient(msg, nick)
                        # The 'from' field is advisory; the authoritative
                        # identity is the nick this socket logged in with. We
                        # overwrite it so a client cannot spoof another sender.
                        if sender != nick:
                            log.warning("Sender %r overridden to %r",
                                        sender, nick)
                            sender = nick
                            msg["from"] = nick
                            raw = json.dumps(msg)

                        # Nonce length depends on the cipher named in the
                        # header: 12 for AES-256-GCM, 24 for XChaCha20-Poly1305.
                        # The cipher itself is authenticated inside the AEAD.
                        nonce = _require_hex(msg, "nonce", expected_len={12, 24})
                        ct = _require_hex(msg, "ct")
                        if len(ct) > MAX_CIPHERTEXT_BYTES:
                            await self._send_error(ws, "message too large")
                            continue
                        ts = int(msg.get("ts") or time.time() * 1000)

                        # Persist the WHOLE frame (header included) and relay it
                        # verbatim, so an offline recipient can still advance
                        # their ratchet. The relay reads none of it.
                        msg_id = self.storage.save_message(
                            sender, recipient, nonce, ct, ts, frame=raw)
                        log.info(
                            "RELAY  %s -> %s  cipher=%s ciphertext=%s...(%d bytes)",
                            sender, recipient, msg.get("cipher", "?"),
                            ct.hex()[:24], len(ct))

                        target_ws = self.online.get(recipient)
                        if target_ws is not None:
                            await target_ws.send(raw)
                            # Delivered live: advance the recipient's cursor so
                            # this message is NOT replayed on their next login
                            # (Option 2 -- server-side no-re-deliver). If the
                            # send failed the exception propagates and the cursor
                            # is not advanced, so the message replays later --
                            # fail-safe toward delivery.
                            self.storage.advance_cursor(recipient, msg_id)
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
                        recipient = self._recipient(msg, nick)
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

                    # ---- 6. Message deletion (retract for everyone) -----
                    # A 'delete' frame names a message id the sender is
                    # retracting. It carries no ciphertext -- only the id -- so
                    # the relay handles it like a text message: forward it live
                    # if the recipient is online, and store-and-forward it so an
                    # offline recipient retracts their copy on next login. We
                    # persist it in the same messages table (frame included) so
                    # the existing history_for replay delivers it; the recipient
                    # applies the tombstone and the delete frame then simply sits
                    # delivered like any other message.
                    elif mtype == "delete":
                        if nick is None:
                            await self._send_error(ws, "must log in first")
                            continue
                        recipient = self._recipient(msg, nick)
                        mid = _require_str(msg, "mid")
                        # Anti-spoofing: authoritative sender is the logged-in
                        # nick, exactly as for text messages.
                        msg["from"] = nick
                        raw = json.dumps(msg)
                        ts = int(msg.get("ts") or time.time() * 1000)
                        # Reuse the message store so the retraction is queued for
                        # an offline recipient and replayed on their next login.
                        # nonce/ciphertext are empty: a delete has no payload.
                        msg_id = self.storage.save_message(
                            nick, recipient, b"", b"", ts, frame=raw)
                        log.info("DELETE %s -> %s  mid=%s", nick, recipient, mid)
                        target_ws = self.online.get(recipient)
                        if target_ws is not None:
                            await target_ws.send(raw)
                            # Delivered live: advance the cursor so this delete is
                            # not replayed again on the recipient's next login,
                            # exactly as for a live text message.
                            self.storage.advance_cursor(recipient, msg_id)

                    # ---- 6b. Message reaction (agree / disagree) --------
                    # A 'reaction' is a quick agree/disagree on a specific
                    # message, addressed by its stable mid -- Threema's discreet
                    # acknowledgement. Like a 'delete' it carries NO ciphertext:
                    # only the target 'mid' and a 'kind' ("up" | "down" | "" to
                    # retract). We relay it live to an online recipient and
                    # store-and-forward it (empty nonce/ciphertext, full frame
                    # preserved) so an offline recipient applies it on next
                    # login. The authenticated sender is forced into 'from',
                    # exactly as for text messages and deletes. Purely additive
                    # and backward compatible: an older client never sends this
                    # type, and an unknown type is ignored by the receiver.
                    elif mtype == "reaction":
                        if nick is None:
                            await self._send_error(ws, "must log in first")
                            continue
                        recipient = self._recipient(msg, nick)
                        mid = _require_str(msg, "mid")
                        # Anti-spoofing: the authoritative sender is the
                        # logged-in nick, exactly as for text and deletes.
                        msg["from"] = nick
                        raw = json.dumps(msg)
                        ts = int(msg.get("ts") or time.time() * 1000)
                        # Reuse the message store so the reaction is queued for
                        # an offline recipient and replayed on their next login;
                        # nonce/ciphertext are empty, as for a delete.
                        msg_id = self.storage.save_message(
                            nick, recipient, b"", b"", ts, frame=raw)
                        kind = str(msg.get("kind") or "")
                        log.info("REACTION %s -> %s  mid=%s kind=%s",
                                 nick, recipient, mid, kind)
                        target_ws = self.online.get(recipient)
                        if target_ws is not None:
                            await target_ws.send(raw)
                            # Delivered live: advance the cursor so this reaction
                            # is not replayed again on the recipient's next
                            # login, exactly as for a live text message.
                            self.storage.advance_cursor(recipient, msg_id)

                    # ---- 7. Typing / sending indicator (ephemeral) ------
                    # A 'typing' frame is a transient presence hint ("typing" /
                    # "sending_file" / "idle"). It is intentionally NOT stored:
                    # an offline peer has no use for a stale "was typing", and
                    # persisting it would replay a phantom indicator on login.
                    # So we relay it ONLY to a currently-online recipient and
                    # drop it otherwise. Nothing touches the database.
                    elif mtype == "typing":
                        if nick is None:
                            await self._send_error(ws, "must log in first")
                            continue
                        recipient = self._recipient(msg, nick)
                        # Anti-spoofing: force the authenticated sender.
                        msg["from"] = nick
                        raw = json.dumps(msg)
                        target_ws = self.online.get(recipient)
                        if target_ws is not None:
                            await target_ws.send(raw)
                        # Offline recipient: silently drop. Ephemeral by design.

                    # ---- 8a. Bilateral verification RESYNC --------------
                    # A 'verify_resync' asks the recipient: "if you have already
                    # verified me, please send your verifyack again." The client
                    # emits one per known peer on login, because an ack that was
                    # bound to a since-replaced identity is ignored by the
                    # receiver and would otherwise leave BOTH sides waiting on
                    # each other forever.
                    #
                    # This matters much more now that the send gate is bilateral.
                    # Until this handler existed the server logged
                    #   WARNING Unknown message type: 'verify_resync'
                    # and dropped the frame, so the one mechanism that recovers a
                    # stalled verification episode never reached the peer. Two
                    # users could each be waiting for an ack that could not be
                    # requested.
                    #
                    # LIVE-ONLY, deliberately, unlike 'verifyack'. This is a
                    # request rather than a fact: it carries no attestation and
                    # is worthless once stale. The client sends one per peer per
                    # login, so store-and-forwarding them would accumulate
                    # unboundedly for a user with many contacts. Nothing is lost
                    # by dropping it for an offline peer, because that peer emits
                    # its own resyncs when it next logs in, which recovers the
                    # episode from the other direction.
                    elif mtype == "verify_resync":
                        if nick is None:
                            await self._send_error(ws, "must log in first")
                            continue
                        recipient = self._recipient(msg, nick)
                        # Anti-spoofing: the authoritative sender is the
                        # logged-in nick, exactly as for text, delete and
                        # verifyack. A client cannot ask a peer to re-ack
                        # somebody else.
                        msg["from"] = nick
                        target_ws = self.online.get(recipient)
                        if target_ws is not None:
                            await target_ws.send(json.dumps(msg))
                            log.info("VERIFYRESYNC %s -> %s", nick, recipient)
                        # Offline recipient: silently drop. Ephemeral by design.

                    # ---- 8. Bilateral verification ack ------------------
                    # A 'verifyack' tells the recipient that the sender has
                    # verified their safety number, so the recipient's half of the
                    # both-parties-verified gate can open. It carries no ciphertext
                    # -- only the two identity keys the client checks -- so, exactly
                    # like a 'delete', we relay it live if the recipient is online
                    # and store-and-forward it so an offline recipient receives it
                    # on their next login. It is persisted in the messages table
                    # (frame included, empty nonce/ciphertext) so history_for
                    # replays it verbatim; the recipient binds it to the current
                    # keys and ignores a stale one. Purely additive and backward
                    # compatible: an older client simply never sends this type.
                    elif mtype == "verifyack":
                        if nick is None:
                            await self._send_error(ws, "must log in first")
                            continue
                        recipient = self._recipient(msg, nick)
                        # Anti-spoofing: the authoritative sender is the logged-in
                        # nick, exactly as for text messages and deletes.
                        msg["from"] = nick
                        raw = json.dumps(msg)
                        ts = int(msg.get("ts") or time.time() * 1000)
                        # Reuse the message store so the ack is queued for an
                        # offline recipient and replayed on their next login. No
                        # payload: nonce/ciphertext are empty, as for a delete.
                        msg_id = self.storage.save_message(
                            nick, recipient, b"", b"", ts, frame=raw)
                        log.info("VERIFYACK %s -> %s", nick, recipient)
                        target_ws = self.online.get(recipient)
                        if target_ws is not None:
                            await target_ws.send(raw)
                            # Delivered live: advance the cursor so this ack is not
                            # replayed again on the recipient's next login.
                            self.storage.advance_cursor(recipient, msg_id)

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
            # Release this socket's log cursor whatever happened -- including a
            # connection that never completed a login and so was never in
            # self.online. The broadcaster prunes too, but dropping it here
            # keeps the map exact rather than eventually-exact.
            self._log_cursor.pop(ws, None)
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


# The number of days left on the certificate below which startup logs a
# warning instead of an informational line. Let's Encrypt issues for 90 days
# and certbot renews at 30 days remaining, so anything under 21 means renewal
# has already been failing for more than a week and nobody has noticed.
CERT_WARN_DAYS = 21


def describe_certificate(certfile: str) -> dict | None:
    """Read the LEAF certificate out of a PEM file, using only the stdlib.

    WHY NOT THE `cryptography` PACKAGE
    ----------------------------------
    The relay's entire runtime dependency footprint is one package,
    `websockets`. `crypto_core.py` and `file_crypto.py` need `cryptography`
    and `pynacl`, but those are the Python reference implementations used by
    the test suite -- they are not imported by the server and have no business
    being installed on a production VM. Adding a dependency here purely to
    print a date would double the relay's supply chain for a log line.

    WHY NOT `load_verify_locations` + `get_ca_certs`
    -----------------------------------------------
    That was the first implementation, and it is a neat trick: those two are
    fully public API, and feeding a leaf certificate to a trust store reads
    back every parsed field. I wrote it, then tested it against a deliberately
    expired certificate and it returned nothing at all.

    The reason is that OpenSSL will not add an EXPIRED certificate to a trust
    store -- reasonably, since the store's purpose is to hold things worth
    trusting. So `get_ca_certs()` came back empty and this function returned
    None precisely in the case it exists to report on. A certificate-expiry
    check that goes quiet when the certificate expires is worse than no check,
    because it looks like everything is fine.

    `_ssl._test_decode_cert` decodes without any validity judgement, which is
    what a diagnostic needs. It is private API, and that is a real cost -- so
    the public route is kept as a fallback, and every failure path returns
    None rather than raising. The worst case if a future Python drops the
    private function is that the relay logs one line less.

    A `fullchain.pem` holds the leaf AND the issuing intermediate. Both
    decoders return the first certificate, and in a chain the first is the
    leaf by definition -- but the file is split explicitly anyway so that this
    does not rest on an implementation detail.

    Returns None on any failure. This is diagnostic output: it must never be
    the reason a relay refuses to start.
    """
    try:
        import re
        import tempfile

        with open(certfile, "r", encoding="ascii", errors="ignore") as fh:
            text = fh.read()

        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            text, re.S)
        if not blocks:
            return None

        leaf = None
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                    "w", suffix=".pem", delete=False) as tmp:
                tmp.write(blocks[0] + "\n")
                tmp_path = tmp.name

            # Preferred: decodes regardless of validity dates.
            try:
                import _ssl
                leaf = _ssl._test_decode_cert(tmp_path)
            except Exception:
                leaf = None

            # Fallback on the public API, for the day the private one goes
            # away. Silently yields nothing for an expired certificate, which
            # is why it is second rather than first.
            if leaf is None:
                probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                probe.load_verify_locations(cafile=tmp_path)
                parsed = probe.get_ca_certs()
                leaf = parsed[0] if parsed else None
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        if not leaf:
            return None

        def _flatten(rdn) -> str:
            # get_ca_certs() returns names as a tuple of tuples of pairs.
            out = []
            for part in rdn or ():
                for pair in part:
                    if len(pair) == 2:
                        out.append(f"{pair[0]}={pair[1]}")
            return ", ".join(out)

        not_after = leaf.get("notAfter")
        days_left = None
        if not_after:
            days_left = (ssl.cert_time_to_seconds(not_after)
                         - time.time()) / 86400.0

        return {
            "subject": _flatten(leaf.get("subject")),
            "issuer": _flatten(leaf.get("issuer")),
            "not_after": not_after,
            "days_left": days_left,
            "chain_length": len(blocks),
            "san": ", ".join(
                f"{kind}:{value}"
                for kind, value in leaf.get("subjectAltName", ())),
        }
    except Exception:
        # Deliberately broad: a malformed certificate, an unreadable temp
        # directory or an OpenSSL build that dislikes something in the file
        # must all degrade to "no description available", never to a crash.
        return None


def log_certificate(certfile: str) -> None:
    """Log what the relay is about to serve, and warn if it expires soon.

    This closes a real gap. `make_ssl_context()` calls `load_cert_chain()`
    ONCE, before serve(), and the resulting SSLContext lives for the life of
    the process -- there is no SNI callback and no file watch. When certbot
    renews, the running relay keeps presenting the certificate it read at
    startup until something restarts it. The deploy hook
    (server/deploy/chate2ee-cert-deploy.sh) exists to force that restart, but
    if the hook is ever missing or fails, nothing else says so: `certbot
    certificates` reports the NEW file as valid while the relay serves the OLD
    one from memory.

    Printing the expiry the process is ACTUALLY holding, at every start, makes
    that state observable. If the journal says 4 days remaining on a relay that
    was restarted last night, the renewal pipeline is broken and you can see it
    without reproducing a client failure first.
    """
    info = describe_certificate(certfile)
    if info is None:
        log.warning("TLS certificate loaded from %s "
                    "(could not parse it for reporting)", certfile)
        return

    log.info("TLS certificate: subject %s", info["subject"] or "(none)")
    log.info("TLS certificate: issuer  %s", info["issuer"] or "(none)")
    if info["san"]:
        log.info("TLS certificate: names   %s", info["san"])
    log.info("TLS certificate: chain    %d certificate(s) in %s",
             info["chain_length"], certfile)

    days = info["days_left"]
    if days is None:
        return
    if days < 0:
        log.error("TLS certificate EXPIRED %.1f days ago (notAfter %s) -- "
                  "clients will refuse to connect", -days, info["not_after"])
    elif days < CERT_WARN_DAYS:
        log.warning("TLS certificate expires in %.1f days (notAfter %s) -- "
                    "check 'systemctl list-timers | grep certbot' and "
                    "'certbot renew --dry-run'", days, info["not_after"])
    else:
        log.info("TLS certificate: expires in %.1f days (notAfter %s)",
                 days, info["not_after"])


# The lab PKI lives in <repo>/pki/, produced by tools/make_demo_pki.py.
# server.py sits in <repo>/server/, so the repo root is one level up.
_REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_TLS_CERT = _REPO_ROOT / "pki" / "server.crt"
DEMO_TLS_KEY = _REPO_ROOT / "pki" / "server.key"


def resolve_tls_paths(args: argparse.Namespace) -> tuple[str | None, str | None]:
    """
    Work out which certificate and key to serve, in a fixed order of precedence:

      1. --cert / --key given explicitly           (the cPouta / Let's Encrypt case)
      2. --demo-tls                                (the lab CA in pki/)
      3. CHATE2EE_TLS_CERT / CHATE2EE_TLS_KEY      (systemd or CI, no CLI edits)
      4. nothing                                   -> plain ws://, development only

    Keeping this in one function means there is a single place that decides
    whether the relay is encrypted, which is easier to reason about (and to
    write about) than TLS configuration scattered across the entry point.
    """
    if args.cert and args.key:
        return args.cert, args.key

    if getattr(args, "demo_tls", False):
        if not (DEMO_TLS_CERT.exists() and DEMO_TLS_KEY.exists()):
            raise SystemExit(
                "--demo-tls was given but the lab certificate is missing:\n"
                f"    expected {DEMO_TLS_CERT}\n"
                f"    expected {DEMO_TLS_KEY}\n\n"
                "Generate it first:\n"
                "    python tools/make_demo_pki.py"
            )
        return str(DEMO_TLS_CERT), str(DEMO_TLS_KEY)

    env_cert = os.environ.get("CHATE2EE_TLS_CERT")
    env_key = os.environ.get("CHATE2EE_TLS_KEY")
    if env_cert and env_key:
        return env_cert, env_key

    return None, None


def _username() -> str:
    """Best-effort name for the current uid, for diagnostics only.

    The pwd module is POSIX-only and this file must still import on Windows,
    where the whole certbot question does not arise -- hence the local import
    and the fallback.
    """
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return "unknown"


def check_tls(args: argparse.Namespace) -> int:
    """Preflight the certificate and exit. Returns a process exit status.

    WHY A SEPARATE MODE RATHER THAN JUST STARTING THE SERVER
    -------------------------------------------------------
    The failure this catches is a permissions failure, and permissions
    failures are the ones that look like something else. certbot writes its
    private key into /etc/letsencrypt/live/<domain>/, and both that directory
    and /etc/letsencrypt/archive/ are mode 0700 root:root -- so a relay
    running as an unprivileged service user simply cannot read it. Started
    from an interactive root shell everything works; started by systemd as
    the service user it does not, and the two look identical from the outside
    ("the server won't come up").

    Running

        sudo -u wsserver /opt/wsserver/.venv/bin/python server.py --check-tls

    answers exactly one question -- can THIS user read and load THESE files --
    with no port binding, no database, and no side effects. It is the check to
    run before `systemctl enable`, and again after any certbot change.
    """
    if not (args.cert and args.key):
        print("No TLS certificate configured.")
        print()
        print("resolve_tls_paths() found nothing, so the relay would start in")
        print("plain ws:// mode. Supply one of:")
        print("  --cert PATH --key PATH")
        print("  --demo-tls                       (the lab CA in pki/)")
        print("  CHATE2EE_TLS_CERT / CHATE2EE_TLS_KEY in the environment")
        return 2

    print(f"certificate : {args.cert}")
    print(f"private key : {args.key}")
    print()

    # Open each file for real rather than asking os.path.exists(). The two
    # answers differ in exactly the case this check exists for: certbot's
    # /etc/letsencrypt/live is mode 0700, and a user who cannot traverse a
    # directory cannot stat what is inside it either -- so exists() returns
    # False for a file that is demonstrably there. Reporting that as "does not
    # exist" would send you looking for a missing file instead of a permission,
    # which is the opposite of helpful. open() distinguishes them properly:
    # PermissionError and FileNotFoundError are different exceptions.
    for label, path in (("certificate", args.cert), ("private key", args.key)):
        try:
            with open(path, "rb") as fh:
                fh.read(1)
        except FileNotFoundError:
            print(f"FAIL: {label} does not exist: {path}")
            return 1
        except PermissionError:
            print(f"FAIL: {label} is not readable by uid {os.getuid()}"
                  f" ({_username()}): {path}")
            print()
            print("This is the certbot permissions case, and it is the single")
            print("most common reason this service starts by hand as root and")
            print("then fails under systemd. /etc/letsencrypt/live and")
            print("/etc/letsencrypt/archive are mode 0700 root:root, so an")
            print("unprivileged service user cannot read privkey.pem there --")
            print("and cannot even see it, which is why a path check alone")
            print("would have called this a missing file.")
            print()
            print("Install server/deploy/chate2ee-cert-deploy.sh as a certbot")
            print("deploy hook. It copies both files somewhere this user can")
            print("read, and restarts the service so a RENEWED certificate")
            print("actually reaches the running process -- which it otherwise")
            print("never would, because the SSLContext is built once at start.")
            return 1
        except OSError as exc:
            print(f"FAIL: {label} could not be read: {exc}")
            return 1

    try:
        make_ssl_context(args.cert, args.key)
    except ssl.SSLError as exc:
        print(f"FAIL: OpenSSL refused the pair: {exc}")
        print()
        print("The usual cause is a certificate and key that do not match --")
        print("for example a fullchain.pem from one issuance and a privkey.pem")
        print("left over from an earlier one. Compare the two public keys:")
        print(f"  openssl x509 -in {args.cert} -noout -pubkey | openssl sha256")
        print(f"  openssl pkey  -in {args.key} -pubout        | openssl sha256")
        return 1
    except OSError as exc:
        print(f"FAIL: could not load the certificate chain: {exc}")
        return 1

    info = describe_certificate(args.cert)
    if info is None:
        print("OK: the pair loads, but the certificate could not be parsed")
        print("    for reporting. That is unusual -- inspect it by hand:")
        print(f"      openssl x509 -in {args.cert} -noout -text")
        return 0

    print(f"subject     : {info['subject'] or '(none)'}")
    print(f"issuer      : {info['issuer'] or '(none)'}")
    print(f"names (SAN) : {info['san'] or '(none)'}")
    print(f"chain       : {info['chain_length']} certificate(s)")
    print(f"notAfter    : {info['not_after']}")

    days = info["days_left"]
    if days is None:
        print()
        print("OK: usable now; expiry could not be determined.")
        return 0
    if days < 0:
        print(f"expires in  : EXPIRED {-days:.1f} days ago")
        print()
        print("FAIL: clients will refuse this certificate. Renew it:")
        print("  sudo certbot renew --force-renewal")
        return 1

    print(f"expires in  : {days:.1f} days")
    print()
    if days < CERT_WARN_DAYS:
        print(f"WARNING: under {CERT_WARN_DAYS} days remain. certbot renews at")
        print("30 days, so renewal has probably been failing for a while:")
        print("  systemctl list-timers | grep certbot")
        print("  sudo certbot renew --dry-run")
    print("OK: this user can serve TLS with these files.")
    return 0


async def amain(args: argparse.Namespace) -> None:
    storage = Storage(args.db)
    server = ChatServer(storage)

    ssl_ctx = None
    if args.cert and args.key:
        ssl_ctx = make_ssl_context(args.cert, args.key)
        scheme = "wss"
        # Report what this process is actually holding. See log_certificate()
        # for why a startup line matters more here than it looks: the context
        # is built once and never reloaded, so this is the only moment the
        # relay's real certificate state is observable.
        log_certificate(args.cert)
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
        # State the clock reference once, at startup. Log timestamps render in
        # the machine's local zone, so a reader who is unsure whether the VM is
        # on UTC or local time -- the exact confusion behind a clock that looks
        # "hours off" -- can settle it from this line instead of guessing.
        _local = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        _utc = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        log.info("Clock: local %s  |  UTC %s", _local, _utc)
        # LOG STREAMING: start the single background task that batches the
        # captured log ring out to every logged-in client about once a second
        # (see ChatServer.broadcast_logs_forever). create_task() copies the
        # CURRENT context, in which _IN_LOG_FLUSH is still False; the task
        # then sets the flag inside its own copy, so the loop-safety guard
        # applies to that task alone and to nothing started here afterwards.
        log_task = asyncio.create_task(server.broadcast_logs_forever())
        try:
            await stop
        finally:
            # Orderly shutdown: cancel the streamer and let the cancellation
            # surface before the server context closes, so we never leak a
            # task into interpreter teardown.
            log_task.cancel()
            try:
                await log_task
            except asyncio.CancelledError:
                pass
    log.info("Server stopped.")


def main() -> None:
    p = argparse.ArgumentParser(description="E2EE chat server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--db", default="chat.db")
    p.add_argument("--cert", help="Path to TLS certificate (fullchain.pem)")
    p.add_argument("--key", help="Path to TLS private key (privkey.pem)")
    p.add_argument("--demo-tls", action="store_true",
                   help="Serve the lab CA certificate from pki/ (generate it with "
                        "tools/make_demo_pki.py). This is real, strictly-verified "
                        "TLS -- the client validates the chain against the lab "
                        "root and checks the hostname, exactly as it does against "
                        "a public CA.")
    p.add_argument("--check-tls", action="store_true",
                   help="Preflight: resolve the certificate paths, load the "
                        "chain, report subject/issuer/expiry, then exit "
                        "without binding a port. Exit status 0 means this "
                        "user can serve TLS with these files. Run it as the "
                        "service user before enabling the unit.")
    args = p.parse_args()
    args.cert, args.key = resolve_tls_paths(args)

    if args.check_tls:
        raise SystemExit(check_tls(args))

    asyncio.run(amain(args))


if __name__ == "__main__":
    main()
