#ifndef MESSAGEMODEL_H
#define MESSAGEMODEL_H

#include <QAbstractListModel>
#include <QDateTime>

// MessageModel is the list of chat messages shown in the conversation view.
//
// It is a QAbstractListModel, which is Qt's standard way of feeding a list of
// structured items to a QML view (ListView). Rather than building strings in
// QML, the C++ side owns the data and exposes named roles (sender, text, etc.)
// that the QML delegate reads. This keeps the UI declarative and the data in
// one place.
class MessageModel : public QAbstractListModel
{
    Q_OBJECT
public:
    enum Roles {
        SenderRole = Qt::UserRole + 1,
        TextRole,
        TimestampRole,
        IsMineRole,
        IsSystemRole,
        // File-message specific roles. A row is either a text row (the
        // original five roles above carry the data) or a file row (these
        // roles are valid and IsFileRole returns true).
        IsFileRole,
        MsgIdRole,
        FilenameRole,
        MimeRole,
        SizeRole,
        LocalPathRole
    };

    explicit MessageModel(QObject *parent = nullptr);

    // The three functions every read-only list model must implement.
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    // Append a message that we sent or received.
    void addMessage(const QString &sender, const QString &text,
                    qint64 tsMillis, bool mine);

    // Append a system note ("Bob joined", "decryption failed", ...).
    void addSystem(const QString &text);

    // Append a file message (sent or received). Distinguished from a text
    // message by isFile = true on the row, and carries the metadata the QML
    // delegate needs to render a file row (paperclip + filename + size, or
    // an inline image preview when mime starts with "image/").
    void appendFileMessage(const QString &sender, const QString &recipient,
                           const QString &msgId, const QString &filename,
                           const QString &mime, qint64 size,
                           const QString &localPath, bool isOutgoing,
                           qint64 tsMillis = 0);

    void clear();

private:
    struct Message {
        QString sender;
        QString text;
        qint64 ts;
        bool mine;
        bool system;
        // File-message fields (only meaningful when isFile == true)
        bool isFile = false;
        QString msgId;
        QString filename;
        QString mime;
        qint64 size = 0;
        QString localPath;
    };

    QList<Message> m_messages;
};

#endif // MESSAGEMODEL_H