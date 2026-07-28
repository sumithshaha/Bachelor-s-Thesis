#include "messagemodel.h"

MessageModel::MessageModel(QObject *parent) : QAbstractListModel(parent) {}

int MessageModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return m_messages.size();
}

QString MessageModel::rowMid(const Message &m)
{
    // Text rows carry an explicit mid; file rows are addressed by their msgId.
    // System rows have neither and are therefore never deletable.
    if (!m.mid.isEmpty())
        return m.mid;
    if (m.isFile)
        return m.msgId;
    return QString();
}

QVariant MessageModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_messages.size())
        return {};
    const Message &m = m_messages.at(index.row());
    switch (role) {
    case SenderRole:    return m.sender;
    // A tombstoned row shows the fixed placeholder instead of its (now cleared)
    // body. Kept here, in the single place the view reads text, so every code
    // path that populated the row -- live, history replay, offline -- renders
    // the tombstone identically without each having to special-case it.
    case TextRole:      return m.deleted
                                ? QStringLiteral("This message was deleted")
                                : m.text;
    case TimestampRole: return QDateTime::fromMSecsSinceEpoch(m.ts)
            .toString("yyyy-MM-dd HH:mm:ss");
    case IsMineRole:    return m.mine;
    case IsSystemRole:  return m.system;
    // File-message roles. For text rows isFile is false and the other file
    // fields are empty/zero, which is fine - the QML delegate switches on
    // isFile to choose between the text and file row layouts. A DELETED file
    // row reports isFile=false so the delegate falls back to the plain text
    // (tombstone) layout and never tries to render the stripped attachment.
    case IsFileRole:    return m.deleted ? false : m.isFile;
    case MsgIdRole:     return m.msgId;
    case FilenameRole:  return m.filename;
    case MimeRole:      return m.deleted ? QString() : m.mime;
    case SizeRole:      return m.size;
    case LocalPathRole: return m.deleted ? QString() : m.localPath;
    // Deletion roles.
    case MidRole:       return rowMid(m);
    case IsDeletedRole: return m.deleted;
    // Reaction roles. A tombstone reports no reactions so the delegate never
    // renders a badge on a "This message was deleted" placeholder.
    case MyReactionRole:   return m.deleted ? QString() : m.myReaction;
    case PeerReactionRole: return m.deleted ? QString() : m.peerReaction;
    // A tombstoned row is never shown as "edited": the placeholder replaces its
    // body, so an old edit marker would be meaningless.
    case IsEditedRole:     return m.deleted ? false : m.edited;
    default:            return {};
    }
}

QHash<int, QByteArray> MessageModel::roleNames() const
{
    // These names are exactly what the QML delegate uses (model.sender,
    // model.text, and so on).
    return {
            {SenderRole,    "sender"},
            {TextRole,      "text"},
            {TimestampRole, "timestamp"},
            {IsMineRole,    "isMine"},
            {IsSystemRole,  "isSystem"},
            // File-message roles
            {IsFileRole,    "isFile"},
            {MsgIdRole,     "msgId"},
            {FilenameRole,  "filename"},
            {MimeRole,      "mime"},
            {SizeRole,      "size"},
            {LocalPathRole, "localPath"},
            // Deletion roles
            {MidRole,       "mid"},
            {IsDeletedRole, "isDeleted"},
            // Reaction roles
            {MyReactionRole,   "myReaction"},
            {PeerReactionRole, "peerReaction"},
            // Edit role
            {IsEditedRole,     "isEdited"},
            };
}

void MessageModel::addMessage(const QString &sender, const QString &text,
                              qint64 tsMillis, bool mine, const QString &mid)
{
    // beginInsertRows / endInsertRows tell any attached view exactly which
    // row appeared, so the ListView can animate it in without a full refresh.
    beginInsertRows(QModelIndex(), m_messages.size(), m_messages.size());
    Message m;
    m.sender = sender;
    m.text   = text;
    m.ts     = tsMillis;
    m.mine   = mine;
    m.system = false;
    m.mid    = mid;
    m_messages.append(m);
    endInsertRows();
}

void MessageModel::addSystem(const QString &text)
{
    beginInsertRows(QModelIndex(), m_messages.size(), m_messages.size());
    Message m;
    m.text   = text;
    m.ts     = QDateTime::currentMSecsSinceEpoch();
    m.mine   = false;
    m.system = true;
    m_messages.append(m);
    endInsertRows();
}

void MessageModel::appendFileMessage(const QString &sender,
                                     const QString &recipient,
                                     const QString &msgId,
                                     const QString &filename,
                                     const QString &mime,
                                     qint64 size,
                                     const QString &localPath,
                                     bool isOutgoing,
                                     qint64 tsMillis)
{
    // recipient is captured for future per-conversation routing; the current
    // single-conversation view does not display it but the parameter is kept
    // so the API does not have to change later.
    Q_UNUSED(recipient);

    Message m;
    m.sender    = sender;
    m.text      = QString();   // file rows have no text body
    // Use the supplied timestamp (from stored history) when given; fall back
    // to "now" only for a brand-new live transfer that passes 0.
    m.ts        = (tsMillis > 0) ? tsMillis
                                 : QDateTime::currentMSecsSinceEpoch();
    m.mine      = isOutgoing;
    m.system    = false;
    m.isFile    = true;
    m.msgId     = msgId;       // doubles as the deletion id for file rows
    m.filename  = filename;
    m.mime      = mime;
    m.size      = size;
    m.localPath = localPath;

    beginInsertRows(QModelIndex(), m_messages.size(), m_messages.size());
    m_messages.append(m);
    endInsertRows();
}

void MessageModel::clear()
{
    beginResetModel();
    m_messages.clear();
    endResetModel();
}

// ---------------------------------------------------------------------------
// Message deletion
// ---------------------------------------------------------------------------
int MessageModel::indexOfMid(const QString &mid) const
{
    if (mid.isEmpty())
        return -1;
    for (int i = 0; i < m_messages.size(); ++i) {
        if (rowMid(m_messages.at(i)) == mid)
            return i;
    }
    return -1;
}

bool MessageModel::markDeletedByMid(const QString &mid)
{
    const int row = indexOfMid(mid);
    if (row < 0)
        return false;
    Message &m = m_messages[row];
    if (m.deleted)
        return true;               // already a tombstone; idempotent
    // Tombstone in place: clear the body and strip any attachment, but keep the
    // row and its position. The 'deleted' flag drives the placeholder text and
    // the suppression of file/image content in data().
    m.deleted   = true;
    m.text.clear();
    m.localPath.clear();
    m.mime.clear();
    m.filename.clear();
    // A deleted message carries no reactions; drop both slots so no badge
    // lingers on the tombstone.
    m.myReaction.clear();
    m.peerReaction.clear();
    // Notify the view that just this row changed, across every role the
    // tombstone affects, so the delegate re-renders as the placeholder.
    const QModelIndex idx = index(row, 0);
    emit dataChanged(idx, idx, {TextRole, IsFileRole, MimeRole,
                                FilenameRole, LocalPathRole, IsDeletedRole,
                                MyReactionRole, PeerReactionRole});
    return true;
}

QString MessageModel::midAt(int row) const
{
    if (row < 0 || row >= m_messages.size())
        return QString();
    return rowMid(m_messages.at(row));
}

bool MessageModel::isMineAt(int row) const
{
    if (row < 0 || row >= m_messages.size())
        return false;
    return m_messages.at(row).mine;
}

// ---------------------------------------------------------------------------
// Message reactions
// ---------------------------------------------------------------------------
bool MessageModel::applyReaction(const QString &mid, bool mine,
                                 const QString &kind)
{
    const int row = indexOfMid(mid);
    if (row < 0)
        return false;                 // not in the conversation on screen
    Message &m = m_messages[row];
    if (m.deleted)
        return false;                 // a tombstone carries no reaction
    // Only "up", "down", or "" are meaningful; anything else is treated as a
    // clear so a malformed/unknown value can never wedge a stuck badge.
    const QString k = (kind == QLatin1String("up")
                       || kind == QLatin1String("down")) ? kind : QString();
    if (mine)
        m.myReaction = k;
    else
        m.peerReaction = k;
    const QModelIndex idx = index(row, 0);
    emit dataChanged(idx, idx,
                     {mine ? MyReactionRole : PeerReactionRole});
    return true;
}

// ---------------------------------------------------------------------------
// Message editing / resending
// ---------------------------------------------------------------------------
bool MessageModel::editTextByMid(const QString &mid, const QString &newText)
{
    const int row = indexOfMid(mid);
    if (row < 0)
        return false;                 // not in the conversation on screen
    Message &m = m_messages[row];
    // Only a live text row can be edited: never a file, a system note, or a
    // tombstone. This mirrors the delegate, which only offers Edit on such rows,
    // but is enforced here too so an inbound edit for the wrong kind is a no-op.
    if (m.isFile || m.system || m.deleted)
        return false;
    m.text = newText;
    m.edited = true;
    const QModelIndex idx = index(row, 0);
    emit dataChanged(idx, idx, {TextRole, IsEditedRole});
    return true;
}

bool MessageModel::markEditedByMid(const QString &mid)
{
    const int row = indexOfMid(mid);
    if (row < 0)
        return false;
    Message &m = m_messages[row];
    if (m.isFile || m.system || m.deleted)
        return false;
    if (m.edited)
        return true;                  // already marked; nothing to change
    m.edited = true;
    const QModelIndex idx = index(row, 0);
    emit dataChanged(idx, idx, {IsEditedRole});
    return true;
}

bool MessageModel::isFileAt(int row) const
{
    if (row < 0 || row >= m_messages.size())
        return false;
    return m_messages.at(row).isFile;
}

QString MessageModel::textAt(int row) const
{
    if (row < 0 || row >= m_messages.size())
        return QString();
    const Message &m = m_messages.at(row);
    if (m.isFile || m.system)
        return QString();
    return m.text;
}
