#ifndef USERMODEL_H
#define USERMODEL_H

#include <QAbstractListModel>
#include <QHash>
#include <QSet>
#include <QStringList>

// UserModel holds the list of users known to this client. Historically it held
// ONLY those currently online (a presence update replaced the whole list), but
// that made offline users disappear from the contact list -- and a user you
// cannot see is a user you cannot message. Now the model REMEMBERS every user
// it has ever seen and tracks online/offline as a per-user flag, so an offline
// peer stays in the list (shown as offline) and remains selectable. Messages to
// an offline peer are stored by the server and delivered on their next login
// (offline delivery), so being able to select and send to them is exactly the
// behaviour we want.
//
// Unread counts are kept in a separate hash keyed by nickname so presence
// changes never wipe them; the online/offline flag is tracked the same way.

class UserModel : public QAbstractListModel
{
    Q_OBJECT
public:
    enum Roles {
        NameRole = Qt::UserRole + 1,
        IsSelfRole,
        UnreadRole,
        OnlineRole            // NEW: whether this user is currently online
    };

    explicit UserModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    // Update who is ONLINE from a presence update. Users not in `names` are
    // marked offline but KEPT in the list; users in `names` new to us are added.
    // (Renamed intent from the old "replace the whole list" setUsers.)
    void setOnlineUsers(const QStringList &names);

    // Is this user currently connected to the relay? Presence is already
    // tracked here for the online dot in the user list; post-compromise
    // security needs the same fact, because a rekey round-trip cannot be
    // completed by a peer who is not there. Cheap set lookup, const, safe to
    // call from the send path.
    bool isOnline(const QString &name) const { return m_online.contains(name); }

    // Ensure a user exists in the list even if we have not seen a presence entry
    // for them yet (e.g. a peer we have prior history with). Added as offline if
    // unknown. Safe to call repeatedly.
    void ensureUser(const QString &name);

    // Whose name in the list is "me", so the UI can mark it.
    void setSelfName(const QString &name);

    void incrementUnread(const QString &peer);
    void clearUnread(const QString &peer);

private:
    void refreshRowFor(const QString &name);
    void insertUserSorted(const QString &name);

    QStringList m_users;                 // every user we know (online or not)
    QString m_self;
    QHash<QString, int> m_unread;        // peer -> unread count (survives updates)
    QSet<QString> m_online;              // which of m_users are currently online
};

#endif // USERMODEL_H