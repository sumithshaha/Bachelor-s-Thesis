// ============================================================================
//  historystore.cpp
//
//  STATUS: faithful, NOT compiled against the Qt toolchain here. The text/file/
//  system handling is unchanged from your working version; the additions are
//  the 'sessions' table and its four accessors, which mirror the existing SQL
//  style. Build and test before relying on it.
// ============================================================================
#include "historystore.h"

#include <QDateTime>
#include <QDir>
#include <QDebug>
#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>

HistoryStore::~HistoryStore()
{
    closeIfOpen();
}

void HistoryStore::closeIfOpen()
{
    if (m_db.isOpen())
        m_db.close();
    // Remove the named connection so a later open() with the same user does
    // not warn about a duplicate connection name.
    if (!m_connName.isEmpty()) {
        m_db = QSqlDatabase();  // drop our handle before removeDatabase()
        QSqlDatabase::removeDatabase(m_connName);
        m_connName.clear();
    }
    m_ready = false;
}

bool HistoryStore::open(const QString &baseDir, const QString &localUser)
{
    // Re-opening (e.g. logging in as a different user) tears down any previous
    // connection first.
    closeIfOpen();

    // Sanitise the nickname so it is safe in a file name and a connection name.
    QString safe;
    for (const QChar &c : localUser) {
        if (c.isLetterOrNumber() || c == '_' || c == '-')
            safe.append(c);
        else
            safe.append('_');
    }
    if (safe.isEmpty())
        safe = "default";

    m_connName = "local_history_" + safe;

    // Make sure the base directory actually exists BEFORE opening the database.
    // This is the fix for a silent, total history failure: QSqlDatabase::open()
    // fails if the file's parent directory does not exist, after which open()
    // returned false, m_ready stayed false, and every addTextRow()/rowsForPeer()
    // no-opped -- so nothing was ever written and every conversation rendered
    // blank on switch and on restart. mkpath() is idempotent and cheap.
    QDir().mkpath(baseDir);

    const QString dbPath = baseDir + "/history_" + safe + ".db";

    m_db = QSqlDatabase::addDatabase("QSQLITE", m_connName);
    m_db.setDatabaseName(dbPath);
    if (!m_db.open()) {
        // Surface WHY the open failed instead of discarding it. Previously this
        // returned false with no trace, so a persistent open failure was
        // invisible and looked like "history just does not work".
        qWarning() << "[HISTORY] open FAILED for" << dbPath
                   << "-- error:" << m_db.lastError().text();
        return false;
    }
    qDebug() << "[HISTORY] opened" << dbPath;

    QSqlQuery q(m_db);
    // One table holds every kind of conversation row. The 'kind' column
    // distinguishes text / file / system; columns not relevant to a kind are
    // left empty.
    const bool ok = q.exec(
        "CREATE TABLE IF NOT EXISTS history ("
        "  id        INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  peer      TEXT NOT NULL,"
        "  kind      TEXT NOT NULL,"
        "  sender    TEXT,"
        "  ts        INTEGER NOT NULL,"
        "  mine      INTEGER NOT NULL DEFAULT 0,"
        "  nonce_hex TEXT,"
        "  ct_hex    TEXT,"
        "  msg_id    TEXT,"
        "  filename  TEXT,"
        "  mime      TEXT,"
        "  size      INTEGER,"
        "  localpath TEXT,"
        "  systext   TEXT"
        ")");
    if (!ok)
        return false;

    q.exec("CREATE INDEX IF NOT EXISTS idx_history_peer "
           "ON history(peer, id)");

    // Ratchet session state, one opaque blob per peer. Stored separately from
    // the conversation rows because it is mutable, single-valued per peer, and
    // never displayed -- it exists solely so a conversation can keep ratcheting
    // after a restart. peer_id holds the peer identity public key (hex) the
    // session is bound to, so on restart the identity can be reloaded and the
    // session's identity stamp validated before use.
    const bool okSess = q.exec(
        "CREATE TABLE IF NOT EXISTS sessions ("
        "  peer       TEXT PRIMARY KEY,"
        "  blob       BLOB NOT NULL,"
        "  peer_id    TEXT,"
        "  updated    INTEGER NOT NULL,"
        "  sent_since INTEGER NOT NULL DEFAULT 0"
        ")");
    if (!okSess)
        return false;

    // Offline outbox: messages, files, and re-bootstrap handshakes the user
    // composed while the socket was not connected, awaiting a live connection to
    // be encrypted and sent. This persists them across restarts so nothing
    // composed offline is lost if the app is closed before it reconnects. 'kind'
    // is 'text', 'file', or 'handshake'. For text, 'body' holds the plaintext
    // (sealed at rest is not required here because it is short-lived and the
    // on-disk history already stores the sealed copy; still, to avoid ANY
    // plaintext on disk, 'body' stores the locally-sealed nonce||ct hex pair
    // joined by a colon -- see the client). For file, 'srcpath' holds the source
    // file URL/path to stream at flush time; nothing is encrypted until send, so
    // the ratchet/identity binding is exactly as if it were sent live on
    // reconnect. For handshake, both 'body' and 'srcpath' are NULL -- the frame's
    // body is a fixed sentinel encrypted at flush time, so only peer + ts are
    // needed. Ordered by id so the queue drains FIFO.
    //
    // IDENTITY STAMP (fix for the "phantom file after reinstall/switch" bug):
    // each row records the local IDENTITY (our own identity public key, hex) in
    // force when it was queued. A file row's source path is plaintext and opens
    // under ANY identity, so without this stamp a file queued under a PREVIOUS
    // identity would be silently re-sent as a brand-new transfer after a
    // reinstall or user switch -- arriving at the peer as a file they never
    // requested. On restore the client drops any row whose stamp does not match
    // the current identity (see ChatClient::restoreOutbox), mirroring how the
    // text path already drops rows it cannot locally-open under the new key.
    // Existing databases created before this column are migrated just below.
    const bool okOut = q.exec(
        "CREATE TABLE IF NOT EXISTS outbox ("
        "  id       INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  kind     TEXT NOT NULL,"          // 'text'|'file'|'handshake'|'verifyack'
        "  peer     TEXT NOT NULL,"
        "  body     TEXT,"                   // text: sealed 'nonceHex:ctHex';
                                             // verifyack: verified peer identity hex
        "  srcpath  TEXT,"                   // file: source path/URL to stream
        "  identity TEXT,"                   // our identity pubkey hex when queued
        "  mid      TEXT,"                   // text: the stable message id minted
        "  ts       INTEGER NOT NULL"        //   at queue time (see enqueueOutboxText)
        ")");
    if (!okOut)
        return false;

    // Migration: add the 'identity' column to an outbox table created by an
    // earlier build that lacked it. SQLite has no "ADD COLUMN IF NOT EXISTS", so
    // probe table_info and add it only when missing. Pre-existing rows get a NULL
    // identity, which restoreOutbox() treats as "unknown identity" and, for
    // safety, drops for FILE rows (a file we cannot attribute to the current
    // identity must not be auto-re-sent), while text/handshake keep their
    // existing behaviour.
    {
        bool hasIdentity = false;
        QSqlQuery info(m_db);
        if (info.exec(QStringLiteral("PRAGMA table_info(outbox)"))) {
            while (info.next()) {
                if (info.value(1).toString() == QLatin1String("identity")) {
                    hasIdentity = true;
                    break;
                }
            }
        }
        if (!hasIdentity) {
            QSqlQuery alter(m_db);
            alter.exec(QStringLiteral(
                "ALTER TABLE outbox ADD COLUMN identity TEXT"));
        }
    }

    // Migration: add the 'mid' column to an outbox table created before message
    // deletion existed, so a text message queued offline keeps the same stable
    // id from queue through the flush that finally sends it. Guarded exactly
    // like the identity migration above. Pre-existing rows get NULL, which
    // restoreOutbox() treats as "no id" -- flushOutbox then mints one at send,
    // matching the old behaviour for those legacy rows.
    {
        bool hasMid = false;
        QSqlQuery info(m_db);
        if (info.exec(QStringLiteral("PRAGMA table_info(outbox)"))) {
            while (info.next()) {
                if (info.value(1).toString() == QLatin1String("mid")) {
                    hasMid = true;
                    break;
                }
            }
        }
        if (!hasMid) {
            QSqlQuery alter(m_db);
            alter.exec(QStringLiteral(
                "ALTER TABLE outbox ADD COLUMN mid TEXT"));
        }
    }

    // Durable record of file transfers this client has FULLY RECEIVED and
    // finalized. It exists to stop the server re-replaying already-delivered
    // files on every login (the "phantom file transfer on every reconnect" bug):
    // on hello the client reports these msg_ids as "have_files", and the server
    // omits them from the offline replay. Because this table lives in the
    // client's own database, it is wiped together with the app's data -- which is
    // exactly the desired "files survive a data wipe" behaviour: after a wipe
    // have_files is empty, so the server re-sends everything, and the client
    // re-records each file here as it arrives again.
    const bool okRecv = q.exec(
        "CREATE TABLE IF NOT EXISTS received_files ("
        "  msg_id   TEXT PRIMARY KEY,"        // server-assigned file id
        "  peer     TEXT,"                    // sender nick (informational)
        "  ts       INTEGER NOT NULL"         // when we recorded receipt
        ")");
    if (!okRecv)
        return false;

    // Reactions: one row per (message, side). 'who' is "me" or "peer", so each
    // side has at most one reaction per message; the composite primary key
    // (msg_id, who) makes setReaction a plain INSERT OR REPLACE and a retract a
    // DELETE. 'peer' is denormalised onto the row so a whole conversation's
    // reactions load in one indexed query when the chat is opened. This table is
    // additive: an older database simply does not have it, and CREATE TABLE IF
    // NOT EXISTS makes first-run creation and every later open() idempotent.
    const bool okReact = q.exec(
        "CREATE TABLE IF NOT EXISTS reactions ("
        "  msg_id TEXT NOT NULL,"             // the reacted message's stable id
        "  who    TEXT NOT NULL,"             // "me" | "peer"
        "  peer   TEXT NOT NULL,"             // conversation partner (for lookup)
        "  kind   TEXT NOT NULL,"             // "up" | "down"
        "  PRIMARY KEY (msg_id, who)"
        ")");
    if (!okReact)
        return false;
    q.exec("CREATE INDEX IF NOT EXISTS idx_reactions_peer "
           "ON reactions(peer)");

    // Persisted bilateral verification. One row per peer, holding the two
    // identity keys the gate reasons about. Additive and idempotent exactly
    // like the tables above, so an older database gains it on first open and
    // nothing needs migrating.
    const bool okVerif = q.exec(
        "CREATE TABLE IF NOT EXISTS verification ("
        "  peer          TEXT PRIMARY KEY,"   // conversation partner
        "  peer_identity TEXT NOT NULL DEFAULT '',"  // their key I confirmed
        "  my_identity   TEXT NOT NULL DEFAULT '',"  // my key they attested
        "  ts            INTEGER NOT NULL DEFAULT 0"
        ")");
    if (!okVerif)
        return false;

    // Migration: a database created before peer_id existed has a sessions table
    // without that column. ALTER TABLE ADD COLUMN is idempotent-safe here only
    // if we guard it, so we check the column set first and add it if missing.
    // Any pre-existing rows get a NULL peer_id, which loadPeerIdentity returns
    // as empty -- forcing a clean re-bootstrap for those peers, which is the
    // correct behaviour for sessions saved before this fix.
    {
        bool hasPeerId = false;
        QSqlQuery info(m_db);
        if (info.exec("PRAGMA table_info(sessions)")) {
            while (info.next()) {
                if (info.value(1).toString() == QLatin1String("peer_id")) {
                    hasPeerId = true;
                    break;
                }
            }
        }
        if (!hasPeerId)
            q.exec("ALTER TABLE sessions ADD COLUMN peer_id TEXT");
    }

    // Migration: the post-compromise-security heartbeat persists its per-peer
    // one-way send counter (ChatClient::m_sentSinceRatchet) alongside the
    // session, so the 32-message rekey threshold survives an Android process
    // KILL mid-burst -- the ratchet chain was already made durable across the
    // background/kill cycle, and this makes its heal accounting durable too. A
    // database created before this column gets it with DEFAULT 0, which simply
    // starts those peers' recovery windows from zero on the next launch (never
    // incorrect: at worst one more message is exposed before the first heal).
    {
        bool hasSentSince = false;
        QSqlQuery info(m_db);
        if (info.exec("PRAGMA table_info(sessions)")) {
            while (info.next()) {
                if (info.value(1).toString() == QLatin1String("sent_since")) {
                    hasSentSince = true;
                    break;
                }
            }
        }
        if (!hasSentSince)
            q.exec("ALTER TABLE sessions ADD COLUMN sent_since INTEGER NOT NULL "
                   "DEFAULT 0");
    }

    // Migration: message deletion adds a 'deleted' flag to history rows so a
    // tombstone ("This message was deleted") survives a restart. A database
    // created before this feature has no such column; add it if missing,
    // defaulting to 0 (not deleted) for every existing row. Guarded exactly
    // like the peer_id migration above so re-running open() is safe.
    {
        bool hasDeleted = false;
        QSqlQuery info(m_db);
        if (info.exec("PRAGMA table_info(history)")) {
            while (info.next()) {
                if (info.value(1).toString() == QLatin1String("deleted")) {
                    hasDeleted = true;
                    break;
                }
            }
        }
        if (!hasDeleted)
            q.exec("ALTER TABLE history ADD COLUMN deleted INTEGER NOT NULL "
                   "DEFAULT 0");
    }

    // Migration: message editing adds an 'edited' flag to text rows so the
    // "edited" marker survives a restart. A database created before this feature
    // has no such column; add it if missing, defaulting to 0 for every existing
    // row. Guarded exactly like the 'deleted' migration above so re-running
    // open() is safe.
    {
        bool hasEdited = false;
        QSqlQuery info(m_db);
        if (info.exec("PRAGMA table_info(history)")) {
            while (info.next()) {
                if (info.value(1).toString() == QLatin1String("edited")) {
                    hasEdited = true;
                    break;
                }
            }
        }
        if (!hasEdited)
            q.exec("ALTER TABLE history ADD COLUMN edited INTEGER NOT NULL "
                   "DEFAULT 0");
    }

    m_ready = true;
    return true;
}

bool HistoryStore::addTextRow(const QString &peer, const QString &sender,
                              const QString &nonceHex, const QString &ctHex,
                              qint64 ts, bool mine, const QString &msgId)
{
    if (!m_ready)
        return false;
    QSqlQuery q(m_db);
    // Reuse the existing msg_id column (added originally for file rows) to hold
    // a text message's stable id too, so a stored text message can be located
    // and tombstoned after a restart. No schema change is needed -- the column
    // already exists and is simply NULL for legacy text rows.
    q.prepare(
        "INSERT INTO history "
        "(peer, kind, sender, ts, mine, nonce_hex, ct_hex, msg_id) "
        "VALUES (?, 'text', ?, ?, ?, ?, ?, ?)");
    q.addBindValue(peer);
    q.addBindValue(sender);
    q.addBindValue(ts);
    q.addBindValue(mine ? 1 : 0);
    q.addBindValue(nonceHex);
    q.addBindValue(ctHex);
    q.addBindValue(msgId.isEmpty() ? QVariant() : QVariant(msgId));
    return q.exec();
}

bool HistoryStore::addFileRow(const QString &peer, const QString &sender,
                              const QString &msgId, const QString &filename,
                              const QString &mime, qint64 size,
                              const QString &localPath, qint64 ts, bool mine)
{
    if (!m_ready)
        return false;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO history "
        "(peer, kind, sender, ts, mine, msg_id, filename, mime, size, localpath) "
        "VALUES (?, 'file', ?, ?, ?, ?, ?, ?, ?, ?)");
    q.addBindValue(peer);
    q.addBindValue(sender);
    q.addBindValue(ts);
    q.addBindValue(mine ? 1 : 0);
    q.addBindValue(msgId);
    q.addBindValue(filename);
    q.addBindValue(mime);
    q.addBindValue(static_cast<qlonglong>(size));
    q.addBindValue(localPath);
    return q.exec();
}

// DEFENSIVE DEDUP WINDOW for system rows. If an identical system line for the
// SAME peer was already stored within this many milliseconds, a repeat is
// treated as noise and dropped instead of written. This is a belt-and-braces
// backstop at the storage layer so that NO caller -- however buggy upstream --
// can ever flood the history table with a runaway of identical system messages.
// The motivating case is the safety-number-warning storm that wrote ~8000
// identical rows in ~2 minutes (~41/sec). The window is deliberately generous:
// no human-meaningful system notice (a key-change warning, a "verified by both
// parties" line, a decrypt-failure notice) legitimately recurs this fast, so a
// real message is never lost, while any tight re-emission loop collapses to one
// row per window. Tune here if a slower runaway ever needs catching.
static constexpr qint64 kSystemDedupWindowMs = 5000;

bool HistoryStore::addSystemRow(const QString &peer, const QString &text,
                                qint64 ts)
{
    if (!m_ready)
        return false;

    // DEFENSIVE DEDUP -- two stateless guards, evaluated against the table
    // itself so they hold across restarts with no in-memory cache to seed.
    // Together they ensure NO caller can flood the history with a runaway of
    // identical system messages, whatever the cause or however long it runs.
    // The motivating case is the safety-number-warning storm that wrote ~8000
    // identical rows in ~2 minutes (~41/sec). The match is always on the EXACT
    // systext, so a different notice -- or the same notice about another peer,
    // whose text carries a different name -- is never suppressed. Nothing in the
    // app counts system rows, so collapsing duplicates is display hygiene only
    // and cannot affect any logic.
    {
        // Guard A -- collapse an unbroken RUN of the same line to ONE row. If
        // the most recent row for this peer is already this exact system line,
        // drop the repeat outright, with NO time bound. During any re-emission
        // loop the newest row IS that line, so an 8000x storm becomes a single
        // row and stays one for as long as the loop runs. This is the hard cap.
        // A legitimate repeat still gets through the moment ANY other row (a
        // message, a file, a different notice) is logged for the peer in
        // between, because then the newest row is no longer this identical line.
        QSqlQuery lastq(m_db);
        lastq.prepare("SELECT kind, systext FROM history WHERE peer = ? "
                      "ORDER BY id DESC LIMIT 1");
        lastq.addBindValue(peer);
        if (lastq.exec() && lastq.next()
            && lastq.value(0).toString() == QStringLiteral("system")
            && lastq.value(1).toString() == text)
            return true;   // identical to the peer's most recent row

        // Guard B -- debounce the same line within a short window even when a
        // DIFFERENT row was logged in between (e.g. two notices alternating in a
        // loop, which Guard A alone would not collapse). If an identical line
        // for this peer was stored within kSystemDedupWindowMs, drop the repeat.
        // Suppress only when the new row is at-or-after the last identical one
        // AND within the window; an EARLIER incoming ts (clock skew / out-of-
        // order delivery) gives a negative delta and is kept, which is safe.
        QSqlQuery winq(m_db);
        winq.prepare("SELECT ts FROM history "
                     "WHERE peer = ? AND kind = 'system' AND systext = ? "
                     "ORDER BY id DESC LIMIT 1");
        winq.addBindValue(peer);
        winq.addBindValue(text);
        if (winq.exec() && winq.next()) {
            const qint64 delta = ts - winq.value(0).toLongLong();
            if (delta >= 0 && delta < kSystemDedupWindowMs)
                return true;
        }
    }

    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO history (peer, kind, sender, ts, mine, systext) "
        "VALUES (?, 'system', '', ?, 0, ?)");
    q.addBindValue(peer);
    q.addBindValue(ts);
    q.addBindValue(text);
    return q.exec();
}

bool HistoryStore::markDeleted(const QString &msgId)
{
    if (!m_ready || msgId.isEmpty())
        return false;
    QSqlQuery q(m_db);
    // Flag every row carrying this stable id as deleted. Matching on msg_id
    // covers both text rows (whose id addTextRow now stores) and file rows.
    // Setting deleted = 1 is idempotent; a mid not present affects no rows,
    // which is not an error. The row itself is preserved so the tombstone keeps
    // its place in the conversation after a restart.
    q.prepare("UPDATE history SET deleted = 1 WHERE msg_id = ?");
    q.addBindValue(msgId);
    return q.exec();
}

bool HistoryStore::updateTextRow(const QString &msgId, const QString &nonceHex,
                                 const QString &ctHex)
{
    if (!m_ready || msgId.isEmpty())
        return false;
    QSqlQuery q(m_db);
    // Replace the sealed body and flag the row as edited. Restricted to text
    // rows (kind = 'text') so a stray id can never rewrite a file or system row.
    // A tombstoned row is left alone: once a message is deleted for everyone it
    // is not editable. numRowsAffected() > 0 tells the caller a row really was
    // updated, so an inbound edit whose original the peer never held can fall
    // back to inserting it fresh instead of silently vanishing.
    q.prepare("UPDATE history SET nonce_hex = ?, ct_hex = ?, edited = 1 "
              "WHERE msg_id = ? AND kind = 'text' AND deleted = 0");
    q.addBindValue(nonceHex);
    q.addBindValue(ctHex);
    q.addBindValue(msgId);
    if (!q.exec())
        return false;
    return q.numRowsAffected() > 0;
}

// ---------------------------------------------------------------------------
// Message reactions
// ---------------------------------------------------------------------------
bool HistoryStore::setReaction(const QString &peer, const QString &mid,
                               const QString &who, const QString &kind)
{
    if (!m_ready || mid.isEmpty() || who.isEmpty())
        return false;
    QSqlQuery q(m_db);
    if (kind.isEmpty()) {
        // A cleared reaction is removed, not stored as an empty string, so
        // reactionsForPeer never has to filter blanks and a retract truly
        // erases the row.
        q.prepare("DELETE FROM reactions WHERE msg_id = ? AND who = ?");
        q.addBindValue(mid);
        q.addBindValue(who);
        return q.exec();
    }
    // Insert or replace this side's single reaction on the message. The
    // (msg_id, who) primary key means a changed reaction overwrites the old one
    // in place rather than accumulating rows.
    q.prepare("INSERT OR REPLACE INTO reactions (msg_id, who, peer, kind) "
              "VALUES (?, ?, ?, ?)");
    q.addBindValue(mid);
    q.addBindValue(who);
    q.addBindValue(peer);
    q.addBindValue(kind);
    return q.exec();
}

QList<HistoryStore::ReactionRow>
HistoryStore::reactionsForPeer(const QString &peer) const
{
    QList<ReactionRow> out;
    if (!m_ready)
        return out;
    QSqlQuery q(m_db);
    q.prepare("SELECT msg_id, who, kind FROM reactions WHERE peer = ?");
    q.addBindValue(peer);
    if (!q.exec())
        return out;
    while (q.next()) {
        ReactionRow r;
        r.mid  = q.value(0).toString();
        r.who  = q.value(1).toString();
        r.kind = q.value(2).toString();
        out.append(r);
    }
    return out;
}

QList<StoredRow> HistoryStore::rowsForPeer(const QString &peer, int limit) const
{
    QList<StoredRow> out;
    if (!m_ready)
        return out;

    QSqlQuery q(m_db);
    // msg_id and deleted are read for ALL kinds now: msg_id holds the stable id
    // for both text and file rows (so a restored row can be tombstoned), and
    // deleted drives the "This message was deleted" placeholder after a restart.
    q.prepare(
        "SELECT kind, sender, ts, mine, nonce_hex, ct_hex, "
        "       msg_id, filename, mime, size, localpath, systext, deleted, "
        "       edited "
        "FROM history WHERE peer = ? ORDER BY id ASC LIMIT ?");
    q.addBindValue(peer);
    q.addBindValue(limit);
    if (!q.exec())
        return out;

    while (q.next()) {
        StoredRow r;
        r.peer = peer;
        const QString kind = q.value(0).toString();
        r.sender   = q.value(1).toString();
        r.ts       = q.value(2).toLongLong();
        r.mine     = q.value(3).toInt() != 0;
        r.deleted  = q.value(12).toInt() != 0;
        r.edited   = q.value(13).toInt() != 0;
        if (kind == "text") {
            r.nonceHex = q.value(4).toString();
            r.ctHex    = q.value(5).toString();
            r.mid      = q.value(6).toString();   // stable id for text rows
        } else if (kind == "file") {
            r.isFile    = true;
            r.msgId     = q.value(6).toString();
            r.mid       = r.msgId;                // files: id == msgId
            r.filename  = q.value(7).toString();
            r.mime      = q.value(8).toString();
            r.size      = q.value(9).toLongLong();
            r.localPath = q.value(10).toString();
        } else { // system
            r.system     = true;
            r.systemText = q.value(11).toString();
        }
        out.append(r);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Ratchet session persistence
// ---------------------------------------------------------------------------
bool HistoryStore::saveSession(const QString &peer, const QByteArray &blob,
                               const QString &peerIdentityHex,
                               int sentSinceRatchet)
{
    if (!m_ready)
        return false;
    QSqlQuery q(m_db);
    // INSERT OR REPLACE keeps exactly one row per peer (peer is PRIMARY KEY).
    // sent_since MUST be written on every save: INSERT OR REPLACE rewrites the
    // whole row, so a column left out of the list would revert to its DEFAULT 0
    // -- which, since this runs after every encrypt/decrypt, would silently wipe
    // the post-compromise counter on every message. The caller passes the current
    // in-memory value so the persisted count always tracks the live one.
    q.prepare(
        "INSERT OR REPLACE INTO sessions (peer, blob, peer_id, updated, "
        "sent_since) VALUES (?, ?, ?, ?, ?)");
    q.addBindValue(peer);
    q.addBindValue(blob);
    q.addBindValue(peerIdentityHex);
    q.addBindValue(static_cast<qlonglong>(QDateTime::currentMSecsSinceEpoch()));
    q.addBindValue(sentSinceRatchet);
    return q.exec();
}

int HistoryStore::loadSentSince(const QString &peer) const
{
    if (!m_ready)
        return 0;
    QSqlQuery q(m_db);
    q.prepare("SELECT sent_since FROM sessions WHERE peer = ?");
    q.addBindValue(peer);
    if (!q.exec() || !q.next())
        return 0;
    return q.value(0).toInt();
}

QByteArray HistoryStore::loadSession(const QString &peer) const
{
    if (!m_ready)
        return {};
    QSqlQuery q(m_db);
    q.prepare("SELECT blob FROM sessions WHERE peer = ?");
    q.addBindValue(peer);
    if (!q.exec() || !q.next())
        return {};
    return q.value(0).toByteArray();
}

QString HistoryStore::loadPeerIdentity(const QString &peer) const
{
    if (!m_ready)
        return {};
    QSqlQuery q(m_db);
    q.prepare("SELECT peer_id FROM sessions WHERE peer = ?");
    q.addBindValue(peer);
    if (!q.exec() || !q.next())
        return {};
    return q.value(0).toString();
}

QStringList HistoryStore::sessionPeers() const
{
    QStringList peers;
    if (!m_ready)
        return peers;
    QSqlQuery q(m_db);
    if (!q.exec("SELECT peer FROM sessions"))
        return peers;
    while (q.next())
        peers << q.value(0).toString();
    return peers;
}

bool HistoryStore::clearSession(const QString &peer)
{
    if (!m_ready)
        return false;
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM sessions WHERE peer = ?");
    q.addBindValue(peer);
    return q.exec();
}

// ---------------------------------------------------------------------------
// Offline outbox persistence
// ---------------------------------------------------------------------------
qint64 HistoryStore::enqueueOutboxText(const QString &peer,
                                       const QString &sealedBody, qint64 ts,
                                       const QString &identityHex,
                                       const QString &mid)
{
    if (!m_ready)
        return -1;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO outbox (kind, peer, body, srcpath, identity, mid, ts) "
        "VALUES ('text', ?, ?, NULL, ?, ?, ?)");
    q.addBindValue(peer);
    q.addBindValue(sealedBody);
    q.addBindValue(identityHex);
    q.addBindValue(mid.isEmpty() ? QVariant() : QVariant(mid));
    q.addBindValue(ts);
    if (!q.exec())
        return -1;
    return q.lastInsertId().toLongLong();
}

qint64 HistoryStore::enqueueOutboxFile(const QString &peer,
                                       const QString &srcPath, qint64 ts,
                                       const QString &identityHex)
{
    if (!m_ready)
        return -1;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO outbox (kind, peer, body, srcpath, identity, ts) "
        "VALUES ('file', ?, NULL, ?, ?, ?)");
    q.addBindValue(peer);
    q.addBindValue(srcPath);
    q.addBindValue(identityHex);
    q.addBindValue(ts);
    if (!q.exec())
        return -1;
    return q.lastInsertId().toLongLong();
}

qint64 HistoryStore::enqueueOutboxHandshake(const QString &peer, qint64 ts,
                                            const QString &identityHex)
{
    // A re-bootstrap handshake carries no payload: its body is a fixed sentinel
    // encrypted at flush time (ChatClient::transmitHandshake), so we persist only
    // the peer and timestamp (plus the identity stamp) with kind 'handshake' and
    // NULL body/srcpath. On the next connection, loadOutbox() returns this row and
    // flushOutbox() encrypts and sends it exactly as if the confirmation had
    // happened online -- keeping the "ratchet advances only for a frame put on the
    // wire" invariant intact. The identity stamp lets restoreOutbox() drop a
    // handshake queued under a now-superseded identity, so a stale re-bootstrap is
    // never emitted after a reinstall/switch.
    if (!m_ready)
        return -1;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO outbox (kind, peer, body, srcpath, identity, ts) "
        "VALUES ('handshake', ?, NULL, NULL, ?, ?)");
    q.addBindValue(peer);
    q.addBindValue(identityHex);
    q.addBindValue(ts);
    if (!q.exec())
        return -1;
    return q.lastInsertId().toLongLong();
}

qint64 HistoryStore::enqueueOutboxVerifyAck(const QString &peer, qint64 ts,
                                            const QString &identityHex,
                                            const QString &verifiedPeerIdentityHex)
{
    // A bilateral-verification ack persisted while offline. It has no message
    // payload, so we reuse the 'body' column to hold the peer identity (hex) that
    // was verified -- ChatClient::flushOutbox reads it back to stamp the ack with
    // the exact key that was confirmed and to drop the ack if the peer rekeyed in
    // the meantime. Stored with kind 'verifyack' and NULL srcpath; the 'identity'
    // stamp is our own identity when queued, so restore can drop an ack queued
    // under a now-superseded local identity.
    if (!m_ready)
        return -1;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO outbox (kind, peer, body, srcpath, identity, ts) "
        "VALUES ('verifyack', ?, ?, NULL, ?, ?)");
    q.addBindValue(peer);
    q.addBindValue(verifiedPeerIdentityHex);
    q.addBindValue(identityHex);
    q.addBindValue(ts);
    if (!q.exec())
        return -1;
    return q.lastInsertId().toLongLong();
}

QList<HistoryStore::OutboxRow> HistoryStore::loadOutbox() const
{
    QList<OutboxRow> out;
    if (!m_ready)
        return out;
    QSqlQuery q(m_db);
    // Oldest first: the queue drains in the order messages/files were composed.
    if (!q.exec("SELECT id, kind, peer, body, srcpath, identity, mid, ts "
                "FROM outbox ORDER BY id ASC"))
        return out;
    while (q.next()) {
        OutboxRow r;
        r.id       = q.value(0).toLongLong();
        r.kind     = q.value(1).toString();
        r.peer     = q.value(2).toString();
        r.body     = q.value(3).toString();
        r.srcPath  = q.value(4).toString();
        r.identity = q.value(5).toString();   // may be NULL/empty for legacy rows
        r.mid      = q.value(6).toString();   // may be NULL/empty for legacy rows
        r.ts       = q.value(7).toLongLong();
        out.append(r);
    }
    return out;
}

bool HistoryStore::deleteOutboxRow(qint64 id)
{
    if (!m_ready)
        return false;
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM outbox WHERE id = ?");
    q.addBindValue(id);
    return q.exec();
}

void HistoryStore::purgeOutbox()
{
    // Delete EVERY queued outbox row for this user's database. Used when the
    // local identity is being replaced (user switch / reinstall handled in
    // ChatClient), where any queued text/file/handshake belongs to the OUTGOING
    // identity and must never be auto-sent under the new one -- most importantly
    // a queued FILE, whose plaintext source path would otherwise be re-sent as a
    // brand-new transfer to a peer who never requested it. restoreOutbox() also
    // drops identity-mismatched rows defensively on load; this is the explicit,
    // eager purge at the moment of the switch so nothing lingers in the DB.
    if (!m_ready)
        return;
    QSqlQuery q(m_db);
    q.exec(QStringLiteral("DELETE FROM outbox"));
}

void HistoryStore::recordReceivedFile(const QString &msgId,
                                      const QString &peer, qint64 ts)
{
    if (!m_ready || msgId.isEmpty())
        return;
    QSqlQuery q(m_db);
    // INSERT OR IGNORE: msg_id is the primary key, so re-recording the same file
    // (e.g. a duplicate file_end) is a harmless no-op rather than an error.
    q.prepare("INSERT OR IGNORE INTO received_files (msg_id, peer, ts) "
              "VALUES (?, ?, ?)");
    q.addBindValue(msgId);
    q.addBindValue(peer);
    q.addBindValue(ts);
    q.exec();
}

QStringList HistoryStore::receivedFileIds() const
{
    QStringList ids;
    if (!m_ready)
        return ids;
    QSqlQuery q(m_db);
    if (q.exec("SELECT msg_id FROM received_files")) {
        while (q.next())
            ids << q.value(0).toString();
    }
    return ids;
}

// ---------------------------------------------------------------------------
// Persisted bilateral verification
//
// Two independent columns updated by two independent events, so an UPSERT that
// touched both would clobber whichever fact the current event does not know.
// Each writer therefore updates only its own column and leaves the other
// intact; a row is created with the other column empty if this is the first of
// the two events to occur.
// ---------------------------------------------------------------------------

bool HistoryStore::recordVerifiedPeerIdentity(const QString &peer,
                                              const QString &peerIdentityHex,
                                              qint64 ts)
{
    if (!isReady() || peer.isEmpty() || peerIdentityHex.isEmpty())
        return false;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO verification (peer, peer_identity, my_identity, ts) "
        "VALUES (?, ?, '', ?) "
        "ON CONFLICT(peer) DO UPDATE SET peer_identity = excluded.peer_identity,"
        " ts = excluded.ts"));
    q.addBindValue(peer);
    q.addBindValue(peerIdentityHex);
    q.addBindValue(ts);
    return q.exec();
}

bool HistoryStore::recordPeerAttestedMyIdentity(const QString &peer,
                                                const QString &myIdentityHex,
                                                qint64 ts)
{
    if (!isReady() || peer.isEmpty() || myIdentityHex.isEmpty())
        return false;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO verification (peer, peer_identity, my_identity, ts) "
        "VALUES (?, '', ?, ?) "
        "ON CONFLICT(peer) DO UPDATE SET my_identity = excluded.my_identity,"
        " ts = excluded.ts"));
    q.addBindValue(peer);
    q.addBindValue(myIdentityHex);
    q.addBindValue(ts);
    return q.exec();
}

QHash<QString, QString> HistoryStore::loadVerifiedPeerIdentities() const
{
    QHash<QString, QString> out;
    if (!isReady())
        return out;
    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral(
            "SELECT peer, peer_identity FROM verification "
            "WHERE peer_identity <> ''")))
        return out;
    while (q.next())
        out.insert(q.value(0).toString(), q.value(1).toString());
    return out;
}

QHash<QString, QString> HistoryStore::loadPeerAttestations() const
{
    QHash<QString, QString> out;
    if (!isReady())
        return out;
    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral(
            "SELECT peer, my_identity FROM verification "
            "WHERE my_identity <> ''")))
        return out;
    while (q.next())
        out.insert(q.value(0).toString(), q.value(1).toString());
    return out;
}

bool HistoryStore::clearVerification(const QString &peer)
{
    if (!isReady() || peer.isEmpty())
        return false;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("DELETE FROM verification WHERE peer = ?"));
    q.addBindValue(peer);
    return q.exec();
}

// ---------------------------------------------------------------------------
// X3DH prekey privates. A single row -- this database is already per local user,
// so the account is implied and no key column is needed beyond a fixed id.
// ---------------------------------------------------------------------------
bool HistoryStore::savePrekeys(const QByteArray &blob)
{
    if (!isReady())
        return false;
    QSqlQuery q(m_db);
    q.exec("CREATE TABLE IF NOT EXISTS prekeys ("
           "  id   INTEGER PRIMARY KEY CHECK (id = 1),"
           "  blob BLOB NOT NULL)");
    q.prepare(QStringLiteral(
        "INSERT INTO prekeys (id, blob) VALUES (1, ?) "
        "ON CONFLICT(id) DO UPDATE SET blob = excluded.blob"));
    q.addBindValue(blob);
    return q.exec();
}

QByteArray HistoryStore::loadPrekeys() const
{
    if (!isReady())
        return QByteArray();
    QSqlQuery q(m_db);
    q.exec("CREATE TABLE IF NOT EXISTS prekeys ("
           "  id   INTEGER PRIMARY KEY CHECK (id = 1),"
           "  blob BLOB NOT NULL)");
    if (!q.exec(QStringLiteral("SELECT blob FROM prekeys WHERE id = 1")))
        return QByteArray();
    if (!q.next())
        return QByteArray();
    return q.value(0).toByteArray();
}
