#ifndef USERMODEL_H
#define USERMODEL_H

#include <QAbstractListModel>
#include <QHash>
#include <QStringList>

// UserModel holds the list of users who are currently online. The server
// sends a fresh, complete list every time someone joins or leaves (a
// "presence" update), and this model simply reflects that list to the UI.
//
// It also tracks an unread count per peer, so the user list can show a badge
// when a message or file arrives for a conversation that is not currently on
// screen. The unread counts are kept in a separate hash keyed by nickname,
// deliberately NOT in the name list, so that a presence update (which resets
// the list) does not wipe the counts.

class UserModel : public QAbstractListModel
{
    Q_OBJECT
public:
    enum Roles {
        NameRole = Qt::UserRole + 1,
        IsSelfRole,
        UnreadRole
    };

    explicit UserModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    // Replace the whole list with the names from a presence update.
    void setUsers(const QStringList &names);
    // Whose name in the list is "me", so the UI can mark it.
    void setSelfName(const QString &name) { m_self = name; }

    // Unread bookkeeping. incrementUnread() bumps the badge for a peer and
    // refreshes just that row; clearUnread() zeroes it (called when the user
    // opens that conversation).
    void incrementUnread(const QString &peer);
    void clearUnread(const QString &peer);

private:
    // Emit a dataChanged for one peer's row so only the badge repaints.
    void refreshRowFor(const QString &name);

    QStringList m_users;
    QString m_self;
    // peer nickname -> unread count. Survives setUsers() resets on purpose.
    QHash<QString, int> m_unread;
};

#endif // USERMODEL_H
