#include "historystore.h"

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
    const QString dbPath = baseDir + "/history_" + safe + ".db";

    m_db = QSqlDatabase::addDatabase("QSQLITE", m_connName);
    m_db.setDatabaseName(dbPath);
    if (!m_db.open())
        return false;

    QSqlQuery q(m_db);
    // One table holds every kind of row. The 'kind' column distinguishes
    // text / file / system; columns not relevant to a kind are left empty.
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

    m_ready = true;
    return true;
}

bool HistoryStore::addTextRow(const QString &peer, const QString &sender,
                              const QString &nonceHex, const QString &ctHex,
                              qint64 ts, bool mine)
{
    if (!m_ready)
        return false;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO history (peer, kind, sender, ts, mine, nonce_hex, ct_hex) "
        "VALUES (?, 'text', ?, ?, ?, ?, ?)");
    q.addBindValue(peer);
    q.addBindValue(sender);
    q.addBindValue(ts);
    q.addBindValue(mine ? 1 : 0);
    q.addBindValue(nonceHex);
    q.addBindValue(ctHex);
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

bool HistoryStore::addSystemRow(const QString &peer, const QString &text,
                                qint64 ts)
{
    if (!m_ready)
        return false;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO history (peer, kind, sender, ts, mine, systext) "
        "VALUES (?, 'system', '', ?, 0, ?)");
    q.addBindValue(peer);
    q.addBindValue(ts);
    q.addBindValue(text);
    return q.exec();
}

QList<StoredRow> HistoryStore::rowsForPeer(const QString &peer, int limit) const
{
    QList<StoredRow> out;
    if (!m_ready)
        return out;

    QSqlQuery q(m_db);
    q.prepare(
        "SELECT kind, sender, ts, mine, nonce_hex, ct_hex, "
        "       msg_id, filename, mime, size, localpath, systext "
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
        if (kind == "text") {
            r.nonceHex = q.value(4).toString();
            r.ctHex    = q.value(5).toString();
        } else if (kind == "file") {
            r.isFile    = true;
            r.msgId     = q.value(6).toString();
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
