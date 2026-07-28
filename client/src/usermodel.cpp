#include "usermodel.h"

// STATUS: faithful fix against your real usermodel.{h,cpp}. Straightforward
// list-model logic; NOT compiled against the Qt toolchain here -- build and run
// once. The change: users are remembered across presence updates and carry an
// online/offline flag, so offline peers stay visible and selectable (and can
// therefore be sent messages/files, which the server stores until they return).

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
    case OnlineRole: return m_online.contains(name);
    default:         return {};
    }
}

QHash<int, QByteArray> UserModel::roleNames() const
{
    return {
        {NameRole,   "name"},
        {IsSelfRole, "isSelf"},
        {UnreadRole, "unread"},
        {OnlineRole, "online"},
    };
}

void UserModel::insertUserSorted(const QString &name)
{
    // Insert `name` keeping the list case-insensitively sorted, with the correct
    // begin/endInsertRows so the view updates incrementally (no full reset).
    int row = 0;
    while (row < m_users.size()
           && m_users.at(row).compare(name, Qt::CaseInsensitive) < 0)
        ++row;
    beginInsertRows(QModelIndex(), row, row);
    m_users.insert(row, name);
    endInsertRows();
}

void UserModel::ensureUser(const QString &name)
{
    if (name.isEmpty() || m_users.contains(name))
        return;
    insertUserSorted(name);      // added as offline (not in m_online)
}

void UserModel::setOnlineUsers(const QStringList &names)
{
    // Merge, don't replace. Add any newly-seen users; recompute the online set;
    // repaint rows whose online state changed. Offline users REMAIN in the list.
    const QSet<QString> nowOnline(names.begin(), names.end());

    // 1) Add users we have never seen before (they arrive online).
    for (const QString &n : names) {
        if (!m_users.contains(n))
            insertUserSorted(n);
    }

    // 2) Figure out which rows changed online-state, and update the set.
    const QSet<QString> wasOnline = m_online;
    m_online = nowOnline;

    // 3) Repaint exactly the rows whose online flag flipped (came online or
    //    went offline). Everyone stays in the list either way.
    QSet<QString> changed = wasOnline;
    changed.unite(nowOnline);
    changed.subtract(wasOnline & nowOnline);   // symmetric difference
    for (const QString &n : changed)
        refreshRowFor(n);
}

void UserModel::setSelfName(const QString &name)
{
    m_self = name;
    // Make sure we appear in our own list, and refresh our row if present.
    ensureUser(name);
    refreshRowFor(name);
}

void UserModel::refreshRowFor(const QString &name)
{
    const int row = m_users.indexOf(name);
    if (row < 0)
        return;
    const QModelIndex idx = index(row, 0);
    emit dataChanged(idx, idx, {UnreadRole, OnlineRole, IsSelfRole});
}

void UserModel::incrementUnread(const QString &peer)
{
    ensureUser(peer);            // a message can arrive from someone not yet listed
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