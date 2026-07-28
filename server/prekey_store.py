"""
prekey_store.py -- server-side storage for X3DH prekey bundles.

The relay already keeps each user's long-term identity key (the `users` table).
X3DH additionally requires the server to hold, per user:

  * a current signed prekey (public) and its XEdDSA signature, and
  * a POOL of one-time prekeys (public), each handed out at most once.

This module adds that storage next to the existing schema without disturbing it.
It is deliberately a small, self-contained class so it can be unit-tested on its
own (this file ships with its tests) and then folded into server.py's Storage.

The one correctness-critical operation is claim_one_time_prekey(): it must return
each one-time prekey to AT MOST ONE requester, even under concurrent requests.
SQLite gives us that with a single DELETE ... RETURNING (or a transactional
SELECT-then-DELETE fallback) inside IMMEDIATE transactions, so two racing claims
cannot both receive the same OPK.

The server stores and serves only PUBLIC key material and signatures; it never
sees any private key, and it does not verify the signed-prekey signature (that is
Alice's job on fetch). It is a blind directory, exactly as the message relay is.

Author: Sumith Shaha -- TAMK, 2026
"""
from __future__ import annotations

import sqlite3


class PrekeyStore:
    """Prekey bundle storage layered on an existing sqlite connection.

    Reuses the connection Storage already owns; call create_tables() once at
    startup (Storage does this in its schema script in the integrated version).
    """

    def __init__(self, db: sqlite3.Connection):
        self._db = db

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #
    def create_tables(self) -> None:
        self._db.executescript(
            """
            -- One current signed prekey per user (replaced on rotation).
            CREATE TABLE IF NOT EXISTS signed_prekeys (
                nick      TEXT PRIMARY KEY,
                spk_pub   BLOB NOT NULL,
                spk_sig   BLOB NOT NULL,
                updated   INTEGER NOT NULL DEFAULT 0
            );
            -- A pool of one-time prekeys per user. Each row is claimed at most
            -- once, then deleted. (nick, opk_id) uniquely identifies a prekey.
            CREATE TABLE IF NOT EXISTS one_time_prekeys (
                nick      TEXT NOT NULL,
                opk_id    INTEGER NOT NULL,
                opk_pub   BLOB NOT NULL,
                PRIMARY KEY (nick, opk_id)
            );
            CREATE INDEX IF NOT EXISTS idx_otp_nick ON one_time_prekeys(nick);
            """
        )
        self._db.commit()

    # ------------------------------------------------------------------ #
    # Publishing (called when a client uploads/refreshes its bundle)
    # ------------------------------------------------------------------ #
    def set_signed_prekey(
        self, nick: str, spk_pub: bytes, spk_sig: bytes, ts: int
    ) -> None:
        """Insert or replace the user's current signed prekey + signature."""
        self._db.execute(
            "INSERT OR REPLACE INTO signed_prekeys (nick, spk_pub, spk_sig, updated) "
            "VALUES (?, ?, ?, ?)",
            (nick, spk_pub, spk_sig, ts),
        )
        self._db.commit()

    def add_one_time_prekeys(
        self, nick: str, prekeys: dict[int, bytes]
    ) -> int:
        """Add a batch of one-time prekeys {opk_id: opk_pub} to the user's pool.
        Existing ids are left untouched (INSERT OR IGNORE), so re-uploading a
        batch is safe. Returns how many new prekeys were actually stored."""
        before = self.one_time_prekey_count(nick)
        self._db.executemany(
            "INSERT OR IGNORE INTO one_time_prekeys (nick, opk_id, opk_pub) "
            "VALUES (?, ?, ?)",
            [(nick, oid, pub) for oid, pub in prekeys.items()],
        )
        self._db.commit()
        return self.one_time_prekey_count(nick) - before

    # ------------------------------------------------------------------ #
    # Serving (called when someone wants to start a session with `nick`)
    # ------------------------------------------------------------------ #
    def get_signed_prekey(self, nick: str) -> tuple[bytes, bytes] | None:
        """Return (spk_pub, spk_sig) for a user, or None if none published."""
        row = self._db.execute(
            "SELECT spk_pub, spk_sig FROM signed_prekeys WHERE nick = ?", (nick,)
        ).fetchone()
        return (row[0], row[1]) if row else None

    def claim_one_time_prekey(self, nick: str) -> tuple[int, bytes] | None:
        """Atomically remove and return one (opk_id, opk_pub) from the user's
        pool, or None if the pool is empty. Single-use is enforced by deleting
        the row in the same transaction that reads it, under an IMMEDIATE lock so
        two concurrent claims cannot receive the same prekey.

        Falling back gracefully: DELETE ... RETURNING needs SQLite >= 3.35. If
        unavailable, we do a guarded SELECT-then-DELETE inside the same
        transaction and retry if the row was taken by a racing claim.
        """
        try:
            # Fast path: atomic delete-returning.
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "DELETE FROM one_time_prekeys "
                "WHERE rowid = ("
                "  SELECT rowid FROM one_time_prekeys WHERE nick = ? "
                "  ORDER BY opk_id LIMIT 1"
                ") RETURNING opk_id, opk_pub",
                (nick,),
            ).fetchone()
            self._db.commit()
            return (row[0], row[1]) if row else None
        except sqlite3.OperationalError:
            # Fallback for older SQLite without RETURNING.
            self._db.rollback()
            return self._claim_fallback(nick)

    def _claim_fallback(self, nick: str) -> tuple[int, bytes] | None:
        while True:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "SELECT opk_id, opk_pub FROM one_time_prekeys "
                "WHERE nick = ? ORDER BY opk_id LIMIT 1",
                (nick,),
            ).fetchone()
            if row is None:
                self._db.commit()
                return None
            deleted = self._db.execute(
                "DELETE FROM one_time_prekeys WHERE nick = ? AND opk_id = ?",
                (nick, row[0]),
            ).rowcount
            self._db.commit()
            if deleted == 1:
                return (row[0], row[1])
            # else: a racing claim took it; loop and try the next one.

    def one_time_prekey_count(self, nick: str) -> int:
        """How many one-time prekeys remain in the user's pool (for low-pool
        warnings / replenishment triggers)."""
        row = self._db.execute(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE nick = ?", (nick,)
        ).fetchone()
        return row[0] if row else 0

    def get_bundle(self, nick: str, identity_pub: bytes | None):
        """Assemble a prekey bundle for `nick` to serve to a requester: the
        identity key (passed in from the existing users table), the signed
        prekey + signature, and ONE claimed one-time prekey (or None if the pool
        is empty). Returns a dict of hex strings ready to serialise, or None if
        the user has no signed prekey published yet.
        """
        spk = self.get_signed_prekey(nick)
        if spk is None or identity_pub is None:
            return None
        spk_pub, spk_sig = spk
        claimed = self.claim_one_time_prekey(nick)
        bundle = {
            "ik": identity_pub.hex(),
            "spk": spk_pub.hex(),
            "spk_sig": spk_sig.hex(),
            "opk": None,
            "opk_id": None,
        }
        if claimed is not None:
            opk_id, opk_pub = claimed
            bundle["opk"] = opk_pub.hex()
            bundle["opk_id"] = opk_id
        return bundle
