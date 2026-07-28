#ifndef HISTORYSTORE_H
#define HISTORYSTORE_H

#include <QList>
#include <QStringList>
#include <QHash>
#include <QString>
#include <QSqlDatabase>

// HistoryStore is the client's own local cache of conversations, kept in a
// small SQLite database in the app's data directory. It exists so that a
// conversation survives both switching to another peer and restarting the
// app - the in-memory MessageModel holds only the conversation currently on
// screen, so without this store everything would vanish on a peer switch.
//
// Text rows are stored as CIPHERTEXT, never plaintext. With the ratchet, the
// stored ciphertext is NOT the wire ciphertext (whose key the ratchet discards
// for forward secrecy and could never be re-derived), but a re-encryption under
// a STATIC local key derived from the user's own identity key -- see
// CryptoBox::localSeal / localOpen. That keeps history re-displayable across
// restarts while still never writing plaintext to disk. This class stays
// crypto-free: it stores the nonce/ct hex it is handed and hands them back.
//
// File rows store only metadata plus the temp path of the decrypted copy.
//
// Ratchet sessions: because the Double Ratchet is stateful, a conversation's
// session (keys + counters + skipped-message keys) must survive a restart, or
// the next inbound frame after relaunch cannot be decrypted. The 'sessions'
// table persists one opaque, already-serialized blob per peer (produced by
// CryptoBox::exportSession); this class treats it as bytes and never inspects it.
//
// IMPORTANT (the bug an earlier version fixes): the database is opened PER LOCAL
// USER. open() takes the local user's own nickname, derives a per-user file name
// and a per-user connection name, so two instances on one machine never collide.

struct StoredRow {
    QString peer;       // the other party in this conversation
    QString sender;     // who sent this row (nick), or empty for system
    qint64  ts = 0;     // ms since epoch
    bool    mine = false;
    bool    system = false;

    // Text rows: locally-sealed envelope (empty for file/system rows)
    QString nonceHex;
    QString ctHex;

    // File rows (isFile == true)
    bool    isFile = false;
    QString msgId;
    QString filename;
    QString mime;
    qint64  size = 0;
    QString localPath;

    // System rows: the literal text to show (system == true)
    QString systemText;

    // The stable message id (UUID) for a text or file row, carried so the
    // MessageModel row it is replayed into can later be addressed for deletion.
    // Empty for system rows. For file rows this equals msgId above; it is kept
    // as a separate field so the replay code has one uniform "stable id" to read.
    QString mid;
    // Whether this row was tombstoned (delete-for-me or delete-for-everyone).
    // When true the replay inserts a deleted row so the "This message was
    // deleted" placeholder shows after a restart, exactly as it did live.
    bool    deleted = false;
    // Whether this TEXT row was edited in place. When true the replay flips the
    // "edited" marker on after inserting the (already updated) text, so an edit
    // survives a restart. Only ever true for text rows.
    bool    edited = false;
};

class HistoryStore
{
public:
    HistoryStore() = default;
    ~HistoryStore();

    // Open (creating if needed) a SQLite database dedicated to ONE local user.
    //   baseDir   - a writable directory (e.g. AppDataLocation)
    //   localUser - the nickname this client logged in as
    // The actual file is baseDir/history_<localUser>.db and the Qt connection
    // name is "local_history_<localUser>". Safe to call again on re-login.
    // Returns false if the database cannot be opened.
    bool open(const QString &baseDir, const QString &localUser);

    bool isReady() const { return m_ready; }

    // Append rows. Each returns false on a database error.
    // addTextRow now also records the message's stable id (msgId) so a stored
    // text message can be located and tombstoned on restart -- it is written
    // into the existing msg_id column (previously used only by file rows), so
    // no schema change is needed for it. May be empty for legacy callers.
    bool addTextRow(const QString &peer, const QString &sender,
                    const QString &nonceHex, const QString &ctHex,
                    qint64 ts, bool mine, const QString &msgId = QString());
    bool addFileRow(const QString &peer, const QString &sender,
                    const QString &msgId, const QString &filename,
                    const QString &mime, qint64 size,
                    const QString &localPath, qint64 ts, bool mine);
    bool addSystemRow(const QString &peer, const QString &text, qint64 ts);

    // Mark a stored message (text or file) as deleted, so the tombstone
    // survives a restart: the row is kept but flagged, and rowsForPeer returns
    // it with 'deleted' set for the fixed "This message was deleted" rendering.
    // Idempotent. Matches on the msg_id column, which now holds the stable id
    // for both text and file rows. Returns false on a database error (a mid not
    // present is not an error -- the UPDATE simply affects no rows).
    bool markDeleted(const QString &msgId);

    // Replace the sealed body of a stored TEXT row (identified by its stable
    // msg_id) with a newly sealed nonce/ct pair and set its edited flag, so an
    // edited message shows its new wording -- and the "edited" marker -- after a
    // restart. Matches on the msg_id column with kind = 'text'. Returns true only
    // if a row was actually updated (so the caller can tell when the peer never
    // held the original, e.g. an edit that arrived before the first copy, and
    // fall back to inserting it fresh). Returns false on a database error or when
    // no matching text row exists.
    bool updateTextRow(const QString &msgId, const QString &nonceHex,
                       const QString &ctHex);

    // Load every stored row for one peer, oldest first, for replay into the
    // MessageModel when that conversation is opened.
    QList<StoredRow> rowsForPeer(const QString &peer, int limit = 500) const;

    // ---- Message reactions --------------------------------------------
    // Persist (or clear) one side's reaction on a message so it survives a
    // restart and can be re-applied when the conversation is reopened. 'who' is
    // "me" (this device's own reaction) or "peer" (the other party's); the pair
    // (mid, who) is unique, so a new value replaces the old. 'kind' is "up",
    // "down", or "" -- an empty kind DELETES the row (a retracted reaction). The
    // 'peer' is stored so reactionsForPeer can fetch a whole conversation's
    // reactions in one query. Returns false on a database error.
    bool setReaction(const QString &peer, const QString &mid,
                     const QString &who, const QString &kind);

    // One stored reaction: which message, which side, and the value. 'who' is
    // "me" or "peer"; 'kind' is "up" or "down" (cleared reactions are deleted,
    // never stored, so kind is never empty here).
    struct ReactionRow {
        QString mid;
        QString who;
        QString kind;
    };

    // Every stored reaction for one peer's conversation, for re-application into
    // the MessageModel after the message rows have been replayed on open.
    QList<ReactionRow> reactionsForPeer(const QString &peer) const;

    // ---- Ratchet session persistence -----------------------------------
    // Store (insert or replace) the opaque session blob for a peer, together
    // with the peer's identity public key (hex) that the session is bound to and
    // the peer's current post-compromise one-way send counter. Called after every
    // encrypt/decrypt, since each advances the ratchet. The identity is stored so
    // that, on restart, it can be reloaded into CryptoBox BEFORE the session blob,
    // letting the session's identity stamp be validated (see
    // CryptoBox::importSession). sentSinceRatchet is stored so the rekey threshold
    // survives a process kill; it must be passed on every save because INSERT OR
    // REPLACE rewrites the whole row. Returns false on a database error.
    bool saveSession(const QString &peer, const QByteArray &blob,
                     const QString &peerIdentityHex, int sentSinceRatchet);
    // The stored session blob for a peer, or an empty QByteArray if none.
    QByteArray loadSession(const QString &peer) const;

    // X3DH prekey PRIVATES, one blob per local user. Kept here rather than in
    // settings because it is secret material that belongs with the account's
    // other secrets, and because losing it strands every conversation a peer
    // started from a bundle the relay had already served.
    bool savePrekeys(const QByteArray &blob);
    QByteArray loadPrekeys() const;
    // The stored peer identity key (hex) a session is bound to, or empty if
    // none. Loaded before the session on restart so the stamp can be checked.
    QString loadPeerIdentity(const QString &peer) const;
    // The stored post-compromise one-way send counter for a peer (0 if none).
    // Restored into ChatClient::m_sentSinceRatchet at login so the 32-message
    // rekey threshold survives an Android process kill mid-burst.
    int loadSentSince(const QString &peer) const;
    // Every peer for which a session blob is stored, so they can be restored
    // into CryptoBox at login.
    QStringList sessionPeers() const;
    // Forget a peer's session (e.g. on an explicit reset). Returns false on
    // a database error.
    bool clearSession(const QString &peer);

    // ---- Offline outbox persistence ------------------------------------
    // Queue a text message composed while offline. 'body' is the locally-sealed
    // 'nonceHex:ctHex' pair (never plaintext on disk). 'identityHex' is our own
    // identity public key (hex) in force now, stamped on the row so restore can
    // drop it if the identity later changes. Returns the new row id, or -1 on
    // error, so the in-memory queue can carry the id and delete the row once the
    // message is actually sent.
    // 'mid' is the stable message id minted at queue time, stored so that a
    // message composed offline keeps the SAME id when flushOutbox() finally
    // sends it -- so a delete made before it was ever sent still addresses it.
    qint64 enqueueOutboxText(const QString &peer, const QString &sealedBody,
                             qint64 ts, const QString &identityHex,
                             const QString &mid = QString());
    // Queue a file composed while offline. 'srcPath' is the source file path/URL
    // to stream at flush time (nothing is encrypted until send). 'identityHex'
    // stamps the queuing identity so a file queued under a previous identity is
    // never auto-re-sent after a reinstall/switch (the phantom-file fix). Returns
    // the new row id, or -1 on error.
    qint64 enqueueOutboxFile(const QString &peer, const QString &srcPath,
                             qint64 ts, const QString &identityHex);
    // Queue a re-bootstrap HANDSHAKE composed while offline. A handshake carries
    // no payload -- only the peer, a timestamp, and the queuing identity stamp --
    // because its body is a fixed sentinel encrypted at flush time (see
    // ChatClient::transmitHandshake). It is persisted so that a safety-number
    // confirmation made while disconnected still re-establishes the conversation
    // on the next connection, even across a restart, exactly like an offline
    // text/file. The identity stamp lets restore drop a handshake queued under a
    // superseded identity. Returns the new row id, or -1 on error, so the
    // in-memory queue can delete the row once the handshake is actually sent.
    // Stored with kind 'handshake' and NULL body/srcpath.
    qint64 enqueueOutboxHandshake(const QString &peer, qint64 ts,
                                  const QString &identityHex);

    // Queue a bilateral-verification "I verified you" ACK composed while offline.
    // Like a handshake it carries no message payload, but it DOES carry the peer
    // identity (hex) that was verified, reused into the 'body' column, so a drained
    // ack attests the exact key the user confirmed rather than whatever key is
    // current at flush time. 'identityHex' is our own identity stamp when queued
    // (lets restore drop an ack queued under a superseded local identity). Stored
    // with kind 'verifyack', body = verifiedPeerIdentityHex, and NULL srcpath.
    // Returns the new row id, or -1 on error.
    qint64 enqueueOutboxVerifyAck(const QString &peer, qint64 ts,
                                  const QString &identityHex,
                                  const QString &verifiedPeerIdentityHex);
    // One queued outbox row, returned oldest-first for FIFO draining on connect.
    struct OutboxRow {
        qint64  id = 0;
        QString kind;      // "text" | "file" | "handshake" | "verifyack"
        QString peer;
        QString body;      // text: sealed 'nonceHex:ctHex'
        QString srcPath;   // file: source path/URL
        QString identity;  // our identity pubkey hex when queued (empty = legacy)
        QString mid;       // text: stable id minted at queue (empty = legacy/none)
        qint64  ts = 0;
    };
    // ---- Persisted bilateral verification ------------------------------
    // A safety-number confirmation is a decision the USER made about a specific
    // peer identity key. Before this table it lived only in memory and was
    // cleared on logout, so every subsequent login re-opened a verification
    // episode for peers that were already mutually verified and prompted the
    // user again. The record is per local user (this database already is), and
    // it stores the two facts the gate needs:
    //
    //   peer_identity -- the peer public key this user actually confirmed;
    //   my_identity   -- the local public key the peer attested (their ack).
    //
    // Storing the KEYS rather than a boolean is what keeps the fix safe. The
    // banner is suppressed only when the key now in force is byte-identical to
    // the key that was verified; any genuine rekey differs and still warns.
    bool recordVerifiedPeerIdentity(const QString &peer,
                                    const QString &peerIdentityHex,
                                    qint64 ts);
    bool recordPeerAttestedMyIdentity(const QString &peer,
                                      const QString &myIdentityHex,
                                      qint64 ts);
    // peer -> the peer identity hex this user confirmed (empty map if none).
    QHash<QString, QString> loadVerifiedPeerIdentities() const;
    // peer -> the local identity hex that peer attested (empty map if none).
    QHash<QString, QString> loadPeerAttestations() const;
    // Forget both facts for one peer. Called when the peer's key genuinely
    // changes, so an old confirmation can never vouch for a new key.
    bool clearVerification(const QString &peer);

    // Every queued row, oldest first, so the client can restore and drain the
    // outbox on the next connection (including after a restart).
    QList<OutboxRow> loadOutbox() const;
    // Remove a queued row once it has been sent (or is being dropped). Returns
    // false on a database error.
    bool deleteOutboxRow(qint64 id);
    // Delete ALL queued outbox rows for this user's database. Used when the local
    // identity is being replaced (user switch / reinstall), so no row queued
    // under the outgoing identity is ever auto-sent under the new one -- in
    // particular a queued FILE, which would otherwise be re-transmitted as a
    // brand-new transfer the peer never requested (the phantom-file fix).
    void purgeOutbox();

    // Record that a file transfer (identified by the server-assigned msg_id) has
    // been FULLY received and finalized by this client. Idempotent: recording the
    // same msg_id twice is harmless (INSERT OR IGNORE). Used so the server can be
    // told, on the next login, which files we already have and need not resend.
    void recordReceivedFile(const QString &msgId, const QString &peer, qint64 ts);
    // All file msg_ids this client has recorded as received. Sent in the hello
    // frame as "have_files" so the server omits them from the offline replay.
    // After a data wipe this is empty (the table was wiped), so the server
    // re-sends every file -- the intended "files survive a data wipe" behaviour.
    QStringList receivedFileIds() const;

    // Close this user's history database and release its Qt connection, WITHOUT
    // deleting the underlying file. Used on logout so the next login() can open
    // the (possibly different) next user's database cleanly; re-opening the same
    // user later works because the named connection has been dropped. This is the
    // public, intent-named entry point; the actual teardown is the private
    // closeIfOpen() helper below (also used by open() and the destructor).
    void close() { closeIfOpen(); }

private:
    void closeIfOpen();

    QSqlDatabase m_db;
    QString m_connName;     // the unique Qt connection name we registered
    bool    m_ready = false;
};

#endif // HISTORYSTORE_H
