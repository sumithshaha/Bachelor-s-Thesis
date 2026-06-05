#include "messagemodel.h"

MessageModel::MessageModel(QObject *parent) : QAbstractListModel(parent) {}

int MessageModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return m_messages.size();
}

QVariant MessageModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_messages.size())
        return {};
    const Message &m = m_messages.at(index.row());
    switch (role) {
    case SenderRole:    return m.sender;
    case TextRole:      return m.text;
    case TimestampRole: return QDateTime::fromMSecsSinceEpoch(m.ts)
            .toString("yyyy-MM-dd HH:mm:ss");
    case IsMineRole:    return m.mine;
    case IsSystemRole:  return m.system;
    // File-message roles. For text rows isFile is false and the other file
    // fields are empty/zero, which is fine - the QML delegate switches on
    // isFile to choose between the text and file row layouts.
    case IsFileRole:    return m.isFile;
    case MsgIdRole:     return m.msgId;
    case FilenameRole:  return m.filename;
    case MimeRole:      return m.mime;
    case SizeRole:      return m.size;
    case LocalPathRole: return m.localPath;
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
            };
}

void MessageModel::addMessage(const QString &sender, const QString &text,
                              qint64 tsMillis, bool mine)
{
    // beginInsertRows / endInsertRows tell any attached view exactly which
    // row appeared, so the ListView can animate it in without a full refresh.
    beginInsertRows(QModelIndex(), m_messages.size(), m_messages.size());
    m_messages.append({sender, text, tsMillis, mine, false});
    endInsertRows();
}

void MessageModel::addSystem(const QString &text)
{
    beginInsertRows(QModelIndex(), m_messages.size(), m_messages.size());
    m_messages.append({QString(), text,
                       QDateTime::currentMSecsSinceEpoch(), false, true});
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
    m.msgId     = msgId;
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