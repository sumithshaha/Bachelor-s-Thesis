#ifndef HISTORYSTORE_H
#define HISTORYSTORE_H

#include <QList>
#include <QString>
#include <QSqlDatabase>

// HistoryStore is the client's own local cache of conversations, kept in a
// small SQLite database in the app's data directory. It exists so that a
// conversation survives both switching to another peer and restarting the
// app - the in-memory MessageModel holds only the conversation currently on
// screen, so without this store everything would vanish on a peer switch.
//
// Design choice for the thesis: text rows are stored as CIPHERTEXT (the same
// nonce + ct envelope that travelled over the wire), never as plaintext. The
// row is decrypted only when it is loaded back into the model for display.
//
// File rows store only metadata plus the temp path of the decrypted copy.
//
// IMPORTANT (the bug this version fixes): the database is opened PER LOCAL
// USER. When two clients run on one machine for testing, they must not share
// one database file, or each would see the other's rows under the wrong key.
// open() therefore takes the local user's own nickname, derives a per-user
// file name from it, and uses a per-user connection name so two instances in
// the same process never collide.

struct StoredRow {
    QString peer;       // the other party in this conversation
    QString sender;     // who sent this row (nick), or empty for system
    qint64  ts = 0;     // ms since epoch
    bool    mine = false;
    bool    system = false;

    // Text rows: ciphertext envelope (empty for file/system rows)
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
    // name is "local_history_<localUser>", so two clients on one machine each
    // get their own store. Safe to call again on re-login. Returns false if
    // the database cannot be opened.
    bool open(const QString &baseDir, const QString &localUser);

    bool isReady() const { return m_ready; }

    // Append rows. Each returns false on a database error.
    bool addTextRow(const QString &peer, const QString &sender,
                    const QString &nonceHex, const QString &ctHex,
                    qint64 ts, bool mine);
    bool addFileRow(const QString &peer, const QString &sender,
                    const QString &msgId, const QString &filename,
                    const QString &mime, qint64 size,
                    const QString &localPath, qint64 ts, bool mine);
    bool addSystemRow(const QString &peer, const QString &text, qint64 ts);

    // Load every stored row for one peer, oldest first, for replay into the
    // MessageModel when that conversation is opened.
    QList<StoredRow> rowsForPeer(const QString &peer, int limit = 500) const;

private:
    void closeIfOpen();

    QSqlDatabase m_db;
    QString m_connName;     // the unique Qt connection name we registered
    bool    m_ready = false;
};

#endif // HISTORYSTORE_H
