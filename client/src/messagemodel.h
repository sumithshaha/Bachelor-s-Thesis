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
        LocalPathRole,
        // Message-deletion roles. Every text and file row now carries a stable
        // MidRole (a UUID minted at send time and agreed by both devices) so a
        // specific message can be addressed for deletion locally and, for
        // delete-for-everyone, on the peer's device too. IsDeletedRole is true
        // once a row has been tombstoned; the delegate then shows the fixed
        // "This message was deleted" text (italic, muted) instead of the body,
        // and suppresses any file/image content. System rows never carry a mid
        // and are never deletable.
        MidRole,
        IsDeletedRole,
        // Reaction roles. Each 1:1 message carries at most one reaction from
        // each side: MyReactionRole is this device's own agree/disagree on the
        // row, PeerReactionRole is the other party's. Each is "up" (agree),
        // "down" (disagree), or "" (none). The delegate renders a small badge
        // per non-empty side. Kept as two fixed slots (not a general emoji-count
        // map) because the conversation is one-to-one, which keeps the model,
        // the wire frame, and the persistence trivial.
        MyReactionRole,
        PeerReactionRole,
        // Edit role. True once a TEXT row has been edited in place (the sender
        // changed its wording and both devices replaced the body). The delegate
        // renders a small muted "edited" marker beside the timestamp, exactly as
        // mainstream messengers do, so a changed message is honestly flagged
        // rather than silently rewritten. Only text rows are edited; file and
        // system rows never carry it.
        IsEditedRole
    };

    explicit MessageModel(QObject *parent = nullptr);

    // The three functions every read-only list model must implement.
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    // Append a message that we sent or received. 'mid' is the stable message id
    // (UUID) shared by both devices; it is what the deletion paths address. May
    // be empty only for legacy/system-like inserts that are never deleted.
    void addMessage(const QString &sender, const QString &text,
                    qint64 tsMillis, bool mine, const QString &mid = QString());

    // Append a system note ("Bob joined", "decryption failed", ...).
    // Q_INVOKABLE so QML can call it directly (ChatPage.qml calls
    // ChatClient.messages.addSystem(...) on the decrypt-failure / key-change
    // paths). Without the marker the meta-object does not expose it and QML
    // throws "Property 'addSystem' ... is not a function".
    Q_INVOKABLE void addSystem(const QString &text);

    // Append a file message (sent or received). Distinguished from a text
    // message by isFile = true on the row, and carries the metadata the QML
    // delegate needs to render a file row (paperclip + filename + size, or
    // an inline image preview when mime starts with "image/"). 'msgId' doubles
    // as the row's stable deletion id (files already have a UUID, so no separate
    // mid is needed).
    void appendFileMessage(const QString &sender, const QString &recipient,
                           const QString &msgId, const QString &filename,
                           const QString &mime, qint64 size,
                           const QString &localPath, bool isOutgoing,
                           qint64 tsMillis = 0);

    // Q_INVOKABLE for the same reason as addSystem: some QML paths clear the
    // conversation directly. Harmless to expose and prevents an identical
    // "not a function" error if a delegate or handler calls it.
    Q_INVOKABLE void clear();

    // ---- Message deletion ---------------------------------------------
    // Look up the row index of a message by its stable id, or -1 if this model
    // does not currently hold it (e.g. the conversation on screen is a different
    // peer). Q_INVOKABLE so the QML long-press handler can ask "is this mine to
    // act on?" and so the client can locate a row to tombstone on an inbound
    // delete. Matches both text (MidRole) and file (MsgIdRole) rows.
    Q_INVOKABLE int indexOfMid(const QString &mid) const;

    // Replace the row identified by 'mid' with a tombstone in place: its text
    // becomes empty, its deleted flag is set, and any file/image content is
    // dropped so the delegate renders the fixed "This message was deleted"
    // placeholder. The row is NOT removed -- WhatsApp-style, the tombstone stays
    // visible in position. No-op (returns false) if the mid is not in this model.
    // Q_INVOKABLE so both the local long-press path and the inbound-delete path
    // can call it; the client also persists the tombstone to history separately.
    Q_INVOKABLE bool markDeletedByMid(const QString &mid);

    // The stable id of the row at 'row', or empty if out of range / a system
    // row. Q_INVOKABLE so the QML delegate can hand the id back to the client
    // when the user picks "delete for everyone" (which must transmit it).
    Q_INVOKABLE QString midAt(int row) const;

    // Whether the row at 'row' was sent by us. Q_INVOKABLE so the long-press
    // menu can offer "delete for everyone" only on our own messages (you cannot
    // retract someone else's message for them -- matching WhatsApp/Signal).
    Q_INVOKABLE bool isMineAt(int row) const;

    // ---- Message reactions --------------------------------------------
    // Set (or clear) a reaction on the row identified by 'mid'. 'mine' picks
    // which slot is written: true = this device's own reaction, false = the
    // peer's. 'kind' is "up", "down", or "" to remove. Returns false if the mid
    // is not in this model (e.g. a different conversation is on screen) or the
    // row is a tombstone (a deleted message carries no reaction). Emits
    // dataChanged for the affected slot so the delegate re-renders the badge.
    // Q_INVOKABLE so the client can apply both our own reactions (echoed
    // instantly) and inbound ones, and so a delegate could apply an optimistic
    // local update.
    Q_INVOKABLE bool applyReaction(const QString &mid, bool mine,
                                   const QString &kind);

    // ---- Message editing / resending ----------------------------------
    // Replace the TEXT of the row identified by 'mid' with 'newText' in place and
    // set its edited flag, so the delegate shows the new wording plus an "edited"
    // marker. Returns false if the mid is not in this model (a different
    // conversation is on screen), or the row is a file / system / tombstoned row
    // (only a live text row can be edited). Emits dataChanged for the text and
    // edited roles so the bubble re-renders. Q_INVOKABLE so the client can apply
    // both our own edit (echoed instantly) and the peer's inbound edit.
    Q_INVOKABLE bool editTextByMid(const QString &mid, const QString &newText);

    // Set only the edited flag on the row identified by 'mid' WITHOUT changing
    // its text. Used when replaying history on restart: the stored (already
    // edited) text is inserted normally, then this flips the marker on. Returns
    // false if the mid is not in this model. Q_INVOKABLE for symmetry.
    Q_INVOKABLE bool markEditedByMid(const QString &mid);

    // Whether the row at 'row' is a file row. Q_INVOKABLE so the client can tell,
    // when the user asks to RESEND a message, whether to re-stream the original
    // file or re-encrypt the text. Out-of-range returns false.
    Q_INVOKABLE bool isFileAt(int row) const;

    // The plaintext of the text row at 'row', or empty for a file / system /
    // out-of-range row. Q_INVOKABLE so the client can read the words to resend.
    Q_INVOKABLE QString textAt(int row) const;

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
        // Deletion fields. 'mid' is the stable id for text rows (files use
        // msgId, which indexOfMid/midAt fall back to). 'deleted' drives the
        // tombstone rendering.
        QString mid;
        bool deleted = false;
        // Reactions: this device's own agree/disagree on the row, and the
        // peer's. Each is "up", "down", or "" (none). A tombstoned row clears
        // both (a deleted message cannot carry a reaction).
        QString myReaction;
        QString peerReaction;
        // Whether this text row has been edited in place (drives the "edited"
        // marker). Only ever true on a text row; files/system rows leave it false.
        bool edited = false;
    };

    // The effective stable id of a message row: its text 'mid' if present,
    // otherwise the file 'msgId'. System rows have neither. Centralised so
    // indexOfMid, midAt and markDeletedByMid all agree.
    static QString rowMid(const Message &m);

    QList<Message> m_messages;
};

#endif // MESSAGEMODEL_H
