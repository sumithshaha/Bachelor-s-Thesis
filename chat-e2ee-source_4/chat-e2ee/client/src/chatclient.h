#ifndef CHATCLIENT_H
#define CHATCLIENT_H

#include <QFile>
#include <QObject>
#include <QTimer>
#include <QUrl>
#include <QWebSocket>
#include <qqmlintegration.h>

#include <memory>

#include "cryptobox.h"
#include "filecrypto.h"
#include "historystore.h"
#include "messagemodel.h"
#include "usermodel.h"

// ChatClient is the single object that the QML UI talks to. It owns the
// WebSocket connection to the server, the encryption box, and the two list
// models (messages and online users).
//
// The split of responsibilities is: QML handles *what the screen looks like*,
// ChatClient handles *what happens* (connecting, encrypting, sending,
// receiving, reconnecting). QML calls the Q_INVOKABLE methods (login, send)
// and reacts to the signals (connectionStateChanged, errorOccurred); it never
// touches the socket or the crypto directly.

class ChatClient : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    // Properties are the values QML can bind to and that update the UI
    // automatically whenever they change.
    Q_PROPERTY(bool connected READ isConnected NOTIFY connectionStateChanged)
    Q_PROPERTY(QString myNickname READ myNickname NOTIFY loggedIn)
    Q_PROPERTY(QString myFingerprint READ myFingerprint NOTIFY loggedIn)
    Q_PROPERTY(MessageModel *messages READ messages CONSTANT)
    Q_PROPERTY(UserModel *users READ users CONSTANT)
    Q_PROPERTY(QString activePeer READ activePeer WRITE setActivePeer
                   NOTIFY activePeerChanged)

public:
    explicit ChatClient(QObject *parent = nullptr);

    bool isConnected() const { return m_connected; }
    QString myNickname() const { return m_nick; }
    QString myFingerprint() const;
    MessageModel *messages() { return &m_messages; }
    UserModel *users() { return &m_users; }
    QString activePeer() const { return m_activePeer; }
    void setActivePeer(const QString &peer);

    // ---- Methods callable from QML --------------------------------------
    // Connect to the server and log in with a chosen nickname.
    Q_INVOKABLE void login(const QString &serverUrl, const QString &nickname);
    // Remember the base directory for the local history database. Called once
    // at startup from main(). The database itself is opened per-user in
    // login(), once the nickname is known.
    Q_INVOKABLE void openHistory(const QString &baseDir);
    // Send a plaintext message to the currently active peer. The plaintext is
    // encrypted here and only the ciphertext leaves the device.
    Q_INVOKABLE void sendMessage(const QString &plaintext);
    // Disconnect cleanly.
    Q_INVOKABLE void logout();
    // The safety number for my conversation with a peer, for out-of-band
    // verification against a man-in-the-middle on the key exchange.
    Q_INVOKABLE QString safetyNumberWith(const QString &peer) const;

    // ---- File transfer methods (QML-callable) --------------------------
    // Send a local file to the active peer. localFileUrl is whatever the
    // QML FileDialog yields - on desktop it is file://..., on Android it
    // may be content://... and Qt's QFile transparently handles both. The
    // file is encrypted with the streaming AEAD (FileCrypto) and pushed
    // chunk by chunk over the WebSocket as binary frames. Progress is
    // reported via the fileSendProgress signal.
    Q_INVOKABLE void sendFile(const QUrl &localFileUrl);
    // Save a received file to a user-chosen location.
    Q_INVOKABLE bool saveReceivedFile(const QString &msgId,
                                      const QUrl &destinationUrl);

signals:
    void connectionStateChanged();
    void loggedIn();
    void activePeerChanged();
    void errorOccurred(const QString &message);

    // Emitted whenever the peer-key directory changes (the bulk dump at login,
    // or a single getkey reply arriving later). QML safety-number bindings
    // depend on this so they recompute once the peer's key is present, and the
    // server-frame handler relies on it to replay any pending file_init/msg
    // frames that were waiting on a key.
    void peerKeysChanged();

    // ---- File transfer signals -----------------------------------------
    // Emitted as a file is being sent or received, so QML can show a bar.
    // fraction is in [0.0, 1.0].
    void fileSendProgress(const QString &msgId, double fraction);
    void fileReceiveProgress(const QString &msgId, double fraction);
    // Emitted once a complete file has finished arriving and decrypting.
    // localPath is where the temporary decrypted copy lives until the user
    // either saves it elsewhere or closes the conversation.
    void fileReceived(const QString &msgId, const QString &fromNick,
                      const QString &filename, const QString &mime,
                      qint64 size, const QString &localPath);
    // Emitted if a file we were receiving failed to decrypt (tamper,
    // truncation, wrong key). The msgId identifies which transfer.
    void fileReceiveFailed(const QString &msgId, const QString &reason);

private slots:
    void onConnected();
    void onDisconnected();
    void onTextMessageReceived(const QString &message);
    void onBinaryMessageReceived(const QByteArray &data);
    void onSslErrors(const QList<QSslError> &errors);
    void tryReconnect();

private:
    void handleServerFrame(const QString &raw);
    void uploadPublicKey();
    void requestKeyFor(const QString &peer);
    // Re-feed any frames (text or file_init) that arrived before we held
    // this sender's public key, now that the key is available.
    void replayPendingFrames(const QString &nick);

    QWebSocket m_socket;
    CryptoBox m_crypto;
    MessageModel m_messages;
    UserModel m_users;

    QString m_nick;
    QUrl m_serverUrl;
    QString m_activePeer;
    bool m_connected = false;

    // Reconnection uses exponential back-off: 1s, 2s, 4s ... capped at 30s.
    QTimer m_reconnectTimer;
    int m_reconnectDelayMs = 1000;
    bool m_intentionalClose = false;

    // Peers whose public key we already have, so we know when we can encrypt.
    QHash<QString, QString> m_peerKeys;  // nick -> pubkey hex

    // Frames received before we held the sender's key, stashed by sender
    // nick and replayed once the key arrives. Without this, the first
    // file_init (or msg) from a peer whose key we have not yet fetched is
    // dropped, and a file transfer silently fails until the conversation
    // has been opened at least once.
    QHash<QString, QStringList> m_pendingFrames;  // sender nick -> raw frames

    // Local per-conversation history (SQLite). Stores text as ciphertext
    // and file rows as metadata; replayed into the model on peer switch.
    HistoryStore m_history;

    // Base directory remembered at startup (openHistory); used to open the
    // per-user history database in login() once the nickname is known.
    QString m_historyBaseDir;

    // Replay every stored row for a peer into the (freshly cleared) message
    // model, decrypting text rows as we go. Called from setActivePeer().
    void loadConversation(const QString &peer);

    // ---- File transfer state -------------------------------------------
    // One entry per outgoing transfer that is currently mid-send. Lives
    // only between the file_init we emitted and the file_end we will emit
    // once the last chunk has flushed.
    struct OutgoingFile {
        QString msgId;
        QString recipient;
        QString filename;
        QString mime;
        qint64 totalBytes = 0;
        qint64 sentBytes = 0;
        int nextChunkIndex = 0;
        QFile file;                 // owned, opened read-only
        FileCrypto crypto;
    };
    QHash<QString, std::shared_ptr<OutgoingFile>> m_outgoing;

    // One entry per incoming transfer that is mid-receive. The temp file
    // accumulates decrypted plaintext as chunks arrive in order; on
    // file_end it is closed and surfaced to QML via fileReceived(...).
    struct IncomingFile {
        QString msgId;
        QString sender;
        QString filename;
        QString mime;
        qint64 expectedSize = 0;
        qint64 receivedBytes = 0;
        int nextChunkIndex = 0;
        std::unique_ptr<QFile> file;  // owned, opened write-only
        QString localPath;
        FileCrypto crypto;
    };
    QHash<QString, std::shared_ptr<IncomingFile>> m_incoming;

    // After a file finishes arriving, its decrypted temp path is kept here
    // keyed by msgId so saveReceivedFile() can copy it out to a user-chosen
    // location later, after the IncomingFile entry has been cleared.
    QHash<QString, QString> m_receivedFilePaths;  // msgId -> temp localPath

    // Pump out the next chunk of an outgoing transfer. Called repeatedly
    // until the file is fully sent. Kept as a separate method so a future
    // change to back-pressure based on QWebSocket::bytesToWrite() is easy.
    void pumpOutgoingFile(const std::shared_ptr<OutgoingFile> &out);
};

#endif // CHATCLIENT_H