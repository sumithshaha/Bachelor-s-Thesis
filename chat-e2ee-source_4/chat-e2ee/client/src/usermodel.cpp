#include "usermodel.h"

UserModel::UserModel(QObject *parent) : QAbstractListModel(parent) {}

int UserModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return m_users.size();
}

QVariant UserModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_users.size())
        return {};

    const QString &name = m_users.at(index.row());
    switch (role) {
    case NameRole:   return name;
    case IsSelfRole: return name == m_self;
    case UnreadRole: return m_unread.value(name, 0);
    default:         return {};
    }
}

QHash<int, QByteArray> UserModel::roleNames() const
{
    return {
        {NameRole,   "name"},
        {IsSelfRole, "isSelf"},
        {UnreadRole, "unread"},
    };
}

void UserModel::setUsers(const QStringList &names)
{
    // A presence update replaces the entire list, so a model reset is the
    // simplest correct approach here. Note we do NOT touch m_unread, so the
    // unread badges persist across presence changes.
    beginResetModel();
    m_users = names;
    m_users.sort(Qt::CaseInsensitive);
    endResetModel();
}

void UserModel::refreshRowFor(const QString &name)
{
    const int row = m_users.indexOf(name);
    if (row < 0)
        return;  // peer not currently in the online list; nothing to repaint
    const QModelIndex idx = index(row, 0);
    emit dataChanged(idx, idx, {UnreadRole});
}

void UserModel::incrementUnread(const QString &peer)
{
    m_unread[peer] = m_unread.value(peer, 0) + 1;
    refreshRowFor(peer);
}

void UserModel::clearUnread(const QString &peer)
{
    if (m_unread.value(peer, 0) == 0)
        return;
    m_unread[peer] = 0;
    refreshRowFor(peer);
}
