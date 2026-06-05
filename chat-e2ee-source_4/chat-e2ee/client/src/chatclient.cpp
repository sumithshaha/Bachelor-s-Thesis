#include "chatclient.h"

#include <QDateTime>
#include <QDebug>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QDir>
#include <QFile>

ChatClient::ChatClient(QObject *parent) : QObject(parent)
{
    connect(&m_socket, &QWebSocket::connected,
            this, &ChatClient::onConnected);
    connect(&m_socket, &QWebSocket::disconnected,
            this, &ChatClient::onDisconnected);
    connect(&m_socket, &QWebSocket::textMessageReceived,
            this, &ChatClient::onTextMessageReceived);
    connect(&m_socket, &QWebSocket::binaryMessageReceived,
            this, &ChatClient::onBinaryMessageReceived);
    connect(&m_socket,
            QOverload<const QList<QSslError> &>::of(&QWebSocket::sslErrors),
            this, &ChatClient::onSslErrors);

    m_reconnectTimer.setSingleShot(true);
    connect(&m_reconnectTimer, &QTimer::timeout,
            this, &ChatClient::tryReconnect);
}

void ChatClient::openHistory(const QString &baseDir)
{
    // The database is per-user and the user is not known until login(), so
    // here we only remember the base directory. The actual open happens in
    // login() once we have a nickname. This is the fix for two clients on one
    // machine sharing (and corrupting) a single history file.
    m_historyBaseDir = baseDir;
}

QString ChatClient::myFingerprint() const
{
    // A display-only fingerprint of my own key (paired with itself), shown on
    // my profile so I can recognise my own identity. The security-relevant
    // check is always the pairwise safetyNumberWith(peer), never this value on
    // its own - a single key cannot be compared against anything.
    return CryptoBox::safetyNumber(m_crypto.publicKeyHex(),
                                   m_crypto.publicKeyHex());
}

void ChatClient::setActivePeer(const QString &peer)
{
    if (m_activePeer == peer)
        return;
    m_activePeer = peer;

    if (!peer.isEmpty()) {
        // Make sure we have a shared key ready for this conversation.
        if (m_peerKeys.contains(peer))
            m_crypto.ensureSharedKey(peer, m_peerKeys.value(peer));
        else
            requestKeyFor(peer);

        // This conversation is now on screen: clear its unread badge and
        // replay its stored history into the message model. C++ now owns
        // repopulation, so the QML peer-switch handler must NOT call
        // messages.clear() any more (see ChatPage.qml).
        m_users.clearUnread(peer);
        loadConversation(peer);
    } else {
        // No peer selected (the self view): just empty the list.
        m_messages.clear();
    }

    emit activePeerChanged();
}

void ChatClient::loadConversation(const QString &peer)
{
    // Rebuild the on-screen conversation from the local history store. Text
    // rows were stored as ciphertext and are decrypted here for display;
    // file rows carry metadata + a temp path; system rows are literal text.
    m_messages.clear();
    const QList<StoredRow> rows = m_history.rowsForPeer(peer);
    for (const StoredRow &r : rows) {
        if (r.system) {
            m_messages.addSystem(r.systemText);
        } else if (r.isFile) {
            m_messages.appendFileMessage(r.sender, m_nick,
                                         r.msgId, r.filename, r.mime,
                                         r.size, r.localPath, r.mine,
                                         r.ts);
        } else {
            // Text row: decrypt the stored ciphertext for display. We need the
            // shared key with this peer; ensureSharedKey is idempotent. If the
            // key has not arrived yet (e.g. just after a restart) decryptFrom
            // returns empty and the row shows blank until reselected - a known
            // limitation documented in the thesis.
            if (m_peerKeys.contains(peer))
                m_crypto.ensureSharedKey(peer, m_peerKeys.value(peer));
            const QString plaintext =
                m_crypto.decryptFrom(peer, r.nonceHex, r.ctHex);
            m_messages.addMessage(r.sender, plaintext, r.ts, r.mine);
        }
    }
}

void ChatClient::login(const QString &serverUrl, const QString &nickname)
{
    m_nick = nickname.trimmed();
    m_serverUrl = QUrl(serverUrl);
    m_users.setSelfName(m_nick);

    // Open this user's own history database now that we know the nickname.
    // Each local user gets a separate file (history_<nick>.db), so two
    // clients running on one machine never read or clobber each other's rows.
    if (!m_historyBaseDir.isEmpty())
        m_history.open(m_historyBaseDir, m_nick);

    // Load an existing identity for this nickname, or create a new one. The
    // private key lives in the app's private data directory and never leaves.
    const QString dir =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    const QString keyPath = dir + "/" + m_nick + ".key";
    if (!m_crypto.loadIdentity(keyPath)) {
        m_crypto.generateIdentity();
        m_crypto.saveIdentity(keyPath);
    }

    m_intentionalClose = false;
    m_socket.open(m_serverUrl);
}

void ChatClient::logout()
{
    m_intentionalClose = true;
    m_reconnectTimer.stop();
    m_socket.close();
}

void ChatClient::onConnected()
{
    m_connected = true;
    m_reconnectDelayMs = 1000;  // reset back-off on a successful connect
    emit connectionStateChanged();
    uploadPublicKey();
    emit loggedIn();
}

void ChatClient::onDisconnected()
{
    m_connected = false;
    emit connectionStateChanged();
    if (!m_intentionalClose) {
        // Schedule a reconnect with the current back-off delay.
        m_messages.addSystem(
            QStringLiteral("Connection lost. Reconnecting..."));
        m_reconnectTimer.start(m_reconnectDelayMs);
    }
}

void ChatClient::tryReconnect()
{
    // Grow the delay for next time, capped at 30 seconds.
    m_reconnectDelayMs = qMin(m_reconnectDelayMs * 2, 30000);
    m_socket.open(m_serverUrl);
}

void ChatClient::onSslErrors(const QList<QSslError> &errors)
{
    // --- DEVELOPMENT DEBUG: remove before production ----------------------
    // This prints the exact error code and human-readable text for every TLS
    // error Qt reports. When you first connect to your self-signed localhost
    // certificate, watch the Application Output pane in Qt Creator: it will
    // show you precisely which QSslError codes your platform produces. If the
    // localhost connection still fails after the forgiveness logic below, the
    // cause is almost always an error code that is not yet in the forgiven
    // list - copy the code printed here into that list and rebuild. Delete
    // this loop once everything works, because leaking error detail to a log
    // is not something a finished application should do.
    for (const QSslError &e : errors)
        qDebug() << "[TLS DEBUG] code:" << e.error()
                 << "message:" << e.errorString();
    // ----------------------------------------------------------------------

    // TLS certificate verification. The default and only safe behaviour for a
    // real deployment is to surface every error and refuse to connect, because
    // a certificate error against a real server may mean someone is
    // intercepting the connection.
    //
    // Local development is the one justified exception. When we connect to
    // localhost we are using a self-signed certificate we made ourselves, so
    // the verification will always fail with "self-signed certificate" and
    // "certificate is not trusted" - these are expected, not an attack. We
    // forgive ONLY those specific errors and ONLY when the host is localhost,
    // so the strict checking stays fully in force for every real server.
    const QString host = m_serverUrl.host();
    const bool isLocalhost =
        (host == QLatin1String("localhost") ||
         host == QLatin1String("127.0.0.1") ||
         host == QLatin1String("::1"));

    if (isLocalhost) {
        QList<QSslError> expected;
        for (const QSslError &e : errors) {
            if (e.error() == QSslError::SelfSignedCertificate ||
                e.error() == QSslError::CertificateUntrusted ||
                e.error() == QSslError::HostNameMismatch) {
                expected << e;
            }
        }
        // ignoreSslErrors(list) forgives only the errors we pass in; any other
        // error would still stop the connection. If every error we saw was one
        // of the expected self-signed ones, the connection proceeds.
        if (expected.size() == errors.size()) {
            m_socket.ignoreSslErrors(expected);
            return;
        }
    }

    // Anything else: report it and let the connection fail.
    QStringList msgs;
    for (const QSslError &e : errors)
        msgs << e.errorString();
    emit errorOccurred(QStringLiteral("TLS error: ") + msgs.join("; "));
}

void ChatClient::uploadPublicKey()
{
    QJsonObject hello{
                      {"type", "hello"},
                      {"nick", m_nick},
                      {"pubkey", m_crypto.publicKeyHex()},
                      };
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(hello).toJson(QJsonDocument::Compact)));
}

void ChatClient::requestKeyFor(const QString &peer)
{
    QJsonObject req{{"type", "getkey"}, {"nick", peer}};
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));
}

void ChatClient::replayPendingFrames(const QString &nick)
{
    // Pull out any frames stashed for this sender and re-feed them through the
    // normal handler. We take and clear the list first so that if a frame still
    // cannot be processed it is not stashed-and-replayed in an infinite loop:
    // by the time we are called the key is present, so the contains() guards in
    // the msg / file_init branches will now pass.
    if (!m_pendingFrames.contains(nick))
        return;
    const QStringList frames = m_pendingFrames.take(nick);
    for (const QString &raw : frames)
        handleServerFrame(raw);
}

void ChatClient::sendMessage(const QString &plaintext)
{
    if (m_activePeer.isEmpty()) {
        emit errorOccurred(QStringLiteral("Select someone to chat with first."));
        return;
    }
    if (!m_peerKeys.contains(m_activePeer)) {
        // We do not have the peer's key yet; ask and let the user retry.
        requestKeyFor(m_activePeer);
        emit errorOccurred(QStringLiteral("Fetching encryption key, try again."));
        return;
    }

    QString nonceHex, ctHex;
    if (!m_crypto.encryptFor(m_activePeer, plaintext, nonceHex, ctHex)) {
        emit errorOccurred(QStringLiteral("Encryption failed."));
        return;
    }

    const qint64 ts = QDateTime::currentMSecsSinceEpoch();
    QJsonObject msg{
                    {"type", "msg"},
                    {"from", m_nick},
                    {"to", m_activePeer},
                    {"nonce", nonceHex},
                    {"ct", ctHex},
                    {"ts", ts},
                    };
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact)));

    // Show our own message immediately (optimistic UI). We display the
    // plaintext we just typed; it was never sent in the clear.
    m_messages.addMessage(m_nick, plaintext, ts, true);
    // Persist the ciphertext envelope locally (keyed by recipient) so the
    // conversation survives a peer switch and a restart. Never plaintext.
    m_history.addTextRow(m_activePeer, m_nick, nonceHex, ctHex, ts, true);
}

void ChatClient::onTextMessageReceived(const QString &message)
{
    handleServerFrame(message);
}

void ChatClient::handleServerFrame(const QString &raw)
{
    const QJsonObject obj =
        QJsonDocument::fromJson(raw.toUtf8()).object();
    const QString type = obj.value("type").toString();

    if (type == "presence") {
        QStringList names;
        for (const QJsonValue &v : obj.value("users").toArray())
            names << v.toString();
        m_users.setUsers(names);

    } else if (type == "keys") {
        // The initial directory dump on login.
        const QJsonObject keys = obj.value("keys").toObject();
        for (auto it = keys.begin(); it != keys.end(); ++it)
            m_peerKeys.insert(it.key(), it.value().toString());
        // Peer keys just landed: tell QML so the safety-number header recomputes.
        emit peerKeysChanged();
        // Any frames that were waiting on these keys can now be processed.
        for (auto it = keys.begin(); it != keys.end(); ++it)
            replayPendingFrames(it.key());

    } else if (type == "key") {
        // A single key we asked for.
        const QString nick = obj.value("nick").toString();
        const QString pub = obj.value("pubkey").toString();
        if (!pub.isEmpty()) {
            m_peerKeys.insert(nick, pub);
            m_crypto.ensureSharedKey(nick, pub);
            // This peer's key is now present: recompute the safety number.
            emit peerKeysChanged();
            // And process anything that was waiting on this key.
            replayPendingFrames(nick);
        }

    } else if (type == "msg") {
        const QString from = obj.value("from").toString();
        const QString to = obj.value("to").toString();
        const QString nonce = obj.value("nonce").toString();
        const QString ct = obj.value("ct").toString();
        const qint64 ts = static_cast<qint64>(obj.value("ts").toDouble());

        // Figure out which peer this conversation is with. If the message is
        // addressed to us, the peer is the sender; if it is our own message
        // echoed back from history, the peer is the recipient.
        const QString peer = (from == m_nick) ? to : from;

        // Make sure we can decrypt: we need the sender's public key. If we do
        // not have it yet, stash this frame and fetch the key; replayPendingFrames
        // will re-feed it once the key arrives, rather than losing the message.
        if (!m_peerKeys.contains(peer)) {
            m_pendingFrames[peer].append(raw);
            requestKeyFor(peer);
            return;
        }
        m_crypto.ensureSharedKey(peer, m_peerKeys.value(peer));
        const QString plaintext = m_crypto.decryptFrom(peer, nonce, ct);
        if (!plaintext.isEmpty() || true) {
            // Only show messages for the conversation we are looking at, or
            // route them to the right place; here we display when the peer
            // matches the active conversation.
            const bool mine = (from == m_nick);
            // Always persist (keyed by the conversation peer), as ciphertext.
            m_history.addTextRow(peer, from, nonce, ct, ts, mine);
            if (peer == m_activePeer) {
                m_messages.addMessage(from, plaintext, ts, mine);
            } else if (!mine) {
                // Arrived for a conversation not on screen: bump the badge.
                m_users.incrementUnread(peer);
            }
        }

    } else if (type == "file_init") {
        // The sender is announcing an incoming file. Set up an IncomingFile
        // entry so the binary chunks that follow have somewhere to land. The
        // field names here must match exactly what sendFile() puts on the
        // wire: msg_id, from, to, filename, mime, size, header.
        const QString msgId    = obj.value("msg_id").toString();
        const QString from     = obj.value("from").toString();
        const QString filename = obj.value("filename").toString();
        const QString mime     = obj.value("mime").toString();
        const qint64  size     = static_cast<qint64>(obj.value("size").toDouble());
        const QByteArray header =
            QByteArray::fromHex(obj.value("header").toString().toLatin1());

        // We need the sender's key to derive the same per-file key they used.
        // If we do not have it yet, stash this file_init and fetch the key;
        // replayPendingFrames re-feeds it once the key arrives. Previously this
        // dropped the transfer, so a file from a peer whose key we had not yet
        // fetched never arrived until that conversation had been opened.
        if (!m_peerKeys.contains(from)) {
            m_pendingFrames[from].append(raw);
            requestKeyFor(from);
            return;
        }
        QByteArray shared = m_crypto.sharedSecretWith(m_peerKeys.value(from));
        QByteArray fileKey = FileCrypto::deriveFileKey(shared, msgId);

        auto in = std::make_shared<IncomingFile>();
        in->msgId          = msgId;
        in->sender         = from;
        in->filename       = filename;
        in->mime           = mime;
        in->expectedSize   = size;
        in->nextChunkIndex = 0;

        // Initialise the streaming decryptor with the header the sender placed
        // in the file_init envelope. If this fails the header was corrupt.
        if (!in->crypto.initPull(fileKey, header)) {
            emit fileReceiveFailed(msgId, tr("could not start decryption"));
            return;
        }

        // Write decrypted plaintext to a temp file under the app's data dir.
        // It stays there until the user chooses to Save it elsewhere.
        const QString dir =
            QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(dir);
        in->localPath = dir + "/" + msgId + "_" + filename;
        in->file = std::make_unique<QFile>(in->localPath);
        if (!in->file->open(QIODevice::WriteOnly)) {
            emit fileReceiveFailed(msgId, tr("could not open temp file"));
            return;
        }
        m_incoming.insert(msgId, in);

    } else if (type == "file_end") {
        // Normally the TAG_FINAL chunk already closed the file inside
        // onBinaryMessageReceived(); this branch is a safety net for a
        // transfer that ended without a final-tagged chunk.
        const QString msgId = obj.value("msg_id").toString();
        auto it = m_incoming.find(msgId);
        if (it != m_incoming.end()) {
            auto in = *it;
            if (in->file && in->file->isOpen()) {
                in->file->flush();
                in->file->close();
                m_receivedFilePaths.insert(msgId, in->localPath);
                emit fileReceived(msgId, in->sender, in->filename, in->mime,
                                  in->receivedBytes, in->localPath);
                // Only show the file row if we are currently viewing the
                // conversation it belongs to - mirrors the text path's
                // (peer == m_activePeer) guard. The file is still received,
                // decrypted, and saved to a temp path regardless; this only
                // controls whether a row appears in the on-screen list.
                // Persist the received file row (metadata + temp path).
                m_history.addFileRow(in->sender, in->sender, msgId,
                                     in->filename, in->mime, in->receivedBytes,
                                     in->localPath,
                                     QDateTime::currentMSecsSinceEpoch(),
                                     /*mine=*/false);
                if (in->sender == m_activePeer) {
                    m_messages.appendFileMessage(in->sender, m_nick,
                                                 msgId, in->filename, in->mime,
                                                 in->receivedBytes, in->localPath,
                                                 /*isOutgoing=*/false);
                } else {
                    // Off-screen: bump the badge and drop a system line into
                    // that peer's stored history so it is visible on open.
                    m_users.incrementUnread(in->sender);
                    m_history.addSystemRow(in->sender,
                                           QStringLiteral("\xF0\x9F\x93\x8E %1 sent you a file: %2")
                                               .arg(in->sender, in->filename),
                                           QDateTime::currentMSecsSinceEpoch());
                }
            }
            m_incoming.remove(msgId);
        }

    } else if (type == "error") {
        emit errorOccurred(obj.value("reason").toString());
    }
}

QString ChatClient::safetyNumberWith(const QString &peer) const
{
    // The verifiable number is always pairwise: it combines my own public key
    // with the peer's. If we do not yet hold the peer's key there is nothing to
    // verify against, so we return an empty string and the UI hides the option.
    if (!m_peerKeys.contains(peer))
        return QString();
    return CryptoBox::safetyNumber(m_crypto.publicKeyHex(),
                                   m_peerKeys.value(peer));
}

// ============================================================================
// File transfer
// ============================================================================
//
// Files are encrypted with FileCrypto (libsodium secretstream, see
// filecrypto.cpp for the rationale) and sent as a small JSON file_init
// envelope, a stream of binary WebSocket frames carrying one ciphertext
// chunk each, and a file_end JSON terminator. The server never sees
// plaintext - it relays the binary frames and stores them if the recipient
// is offline. The receiving client mirrors the structure: it sees the
// file_init, allocates an IncomingFile entry, decrypts chunks as they
// arrive, and once file_end (or a TAG_FINAL chunk) closes the stream it
// emits fileReceived() so QML can display the result.
//
// Binary frame format on the wire:
//   bytes  0..35  = ASCII msg_id (a UUID string, 36 chars)
//   bytes 36..39  = big-endian uint32 chunk_index
//   bytes 40..end = secretstream ciphertext chunk (plaintext + 17 B AEAD tag)
// This prefix lets the server route by msg_id without looking at the
// ciphertext, and lets the receiver reassemble chunks even if they arrive
// slightly out of order (secretstream itself rejects out-of-order chunks,
// which is the correct safety behaviour).

#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMimeDatabase>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QUuid>

void ChatClient::sendFile(const QUrl &localFileUrl)
{
    if (!m_connected) {
        emit errorOccurred(tr("Not connected"));
        return;
    }
    if (m_activePeer.isEmpty()) {
        emit errorOccurred(tr("Pick someone to send to first"));
        return;
    }
    if (!m_peerKeys.contains(m_activePeer)) {
        emit errorOccurred(tr("Don't have %1's key yet").arg(m_activePeer));
        return;
    }

    auto out = std::make_shared<OutgoingFile>();
    // QFile accepts both file:// (desktop) and content:// (Android SAF) URIs.
    out->file.setFileName(localFileUrl.toLocalFile().isEmpty()
                              ? localFileUrl.toString()
                              : localFileUrl.toLocalFile());
    if (!out->file.open(QIODevice::ReadOnly)) {
        emit errorOccurred(tr("Could not open %1").arg(out->file.fileName()));
        return;
    }
    out->totalBytes = out->file.size();
    if (out->totalBytes <= 0
        || out->totalBytes > FileCrypto::MAX_FILE_BYTES) {
        emit errorOccurred(tr("File too large or empty (max 50 MB)"));
        return;
    }

    out->msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    out->recipient = m_activePeer;
    QFileInfo fi(out->file.fileName());
    out->filename = fi.fileName();
    out->mime = QMimeDatabase().mimeTypeForFile(fi).name();

    // Derive the file key from the existing X25519 shared secret with this
    // peer. The HKDF info string in FileCrypto includes the msg_id, so each
    // file has its own key even if many files share the same shared secret.
    QByteArray shared = m_crypto.sharedSecretWith(
        m_peerKeys.value(m_activePeer));
    QByteArray fileKey = FileCrypto::deriveFileKey(shared, out->msgId);
    if (!out->crypto.initPush(fileKey)) {
        emit errorOccurred(tr("Crypto init failed"));
        return;
    }

    // Send the file_init JSON. The server stores this envelope verbatim and
    // forwards it to the recipient, who uses it to set up their own
    // decryption state.
    QJsonObject init;
    init["type"] = "file_init";
    init["msg_id"] = out->msgId;
    init["from"] = m_nick;
    init["to"] = out->recipient;
    init["filename"] = out->filename;
    init["mime"] = out->mime;
    init["size"] = double(out->totalBytes);
    init["header"] = QString::fromLatin1(out->crypto.header().toHex());
    m_socket.sendTextMessage(QJsonDocument(init).toJson(QJsonDocument::Compact));

    m_outgoing.insert(out->msgId, out);
    pumpOutgoingFile(out);
}

void ChatClient::pumpOutgoingFile(const std::shared_ptr<OutgoingFile> &out)
{
    // Send chunks until the file is done. Each chunk is one binary frame.
    // We keep this synchronous because Qt's QWebSocket already buffers
    // efficiently; if you ever push files large enough that this stalls
    // the UI thread, move the read+encrypt off to a worker and post the
    // sendBinaryMessage call back here.
    QByteArray idAscii = out->msgId.toLatin1();  // 36 bytes
    while (!out->file.atEnd()) {
        QByteArray chunk = out->file.read(FileCrypto::CHUNK_SIZE);
        const bool isLast = out->file.atEnd();
        QByteArray ct = out->crypto.encryptChunk(chunk, isLast);
        if (ct.isEmpty()) {
            emit errorOccurred(tr("Encryption error during send"));
            m_outgoing.remove(out->msgId);
            return;
        }
        // Frame = id (36) + big-endian chunk_index (4) + ciphertext.
        QByteArray frame;
        frame.reserve(40 + ct.size());
        frame.append(idAscii);
        const quint32 idx = quint32(out->nextChunkIndex++);
        frame.append(char((idx >> 24) & 0xff));
        frame.append(char((idx >> 16) & 0xff));
        frame.append(char((idx >>  8) & 0xff));
        frame.append(char( idx        & 0xff));
        frame.append(ct);
        m_socket.sendBinaryMessage(frame);

        out->sentBytes += chunk.size();
        emit fileSendProgress(out->msgId,
                              double(out->sentBytes) / double(out->totalBytes));
    }
    // file_end terminator (a text JSON frame).
    QJsonObject end;
    end["type"] = "file_end";
    end["msg_id"] = out->msgId;
    m_socket.sendTextMessage(QJsonDocument(end).toJson(QJsonDocument::Compact));

    out->file.close();
    // Also surface this in our own message list as an outgoing file row.
    m_messages.appendFileMessage(m_nick, out->recipient,
                                 out->msgId, out->filename, out->mime,
                                 out->totalBytes, /*localPath=*/QString(),
                                 /*isOutgoing=*/true);
    // Persist the sent-file row locally (keyed by recipient). We keep no local
    // path for our own sent files - the original lives wherever the user has it.
    m_history.addFileRow(out->recipient, m_nick, out->msgId, out->filename,
                         out->mime, out->totalBytes, /*localPath=*/QString(),
                         QDateTime::currentMSecsSinceEpoch(), /*mine=*/true);
    m_outgoing.remove(out->msgId);
}

void ChatClient::onBinaryMessageReceived(const QByteArray &data)
{
    // Binary frames carry exactly one encrypted file chunk. We must already
    // have seen a matching file_init (which sits in m_incoming); otherwise
    // it is a stray frame and we drop it. Authentication is enforced by
    // secretstream itself - a chunk produced by anyone without the file
    // key will fail to decrypt.
    if (data.size() < 40) return;
    QString msgId = QString::fromLatin1(data.constData(), 36);
    auto it = m_incoming.find(msgId);
    if (it == m_incoming.end()) return;
    auto in = *it;
    quint32 idx = (quint8(data[36]) << 24)
                  | (quint8(data[37]) << 16)
                  | (quint8(data[38]) <<  8)
                  |  quint8(data[39]);
    if (int(idx) != in->nextChunkIndex) {
        // secretstream insists on in-order delivery; if our WebSocket
        // reordered (it shouldn't, but defensively) we fail this file.
        emit fileReceiveFailed(msgId, tr("chunk order mismatch"));
        m_incoming.remove(msgId);
        return;
    }
    in->nextChunkIndex++;

    QByteArray ct = data.mid(40);
    bool isFinal = false;
    QByteArray pt = in->crypto.decryptChunk(ct, &isFinal);
    if (pt.isNull()) {
        emit fileReceiveFailed(msgId, tr("authentication failure"));
        m_incoming.remove(msgId);
        return;
    }
    in->file->write(pt);
    in->receivedBytes += pt.size();
    emit fileReceiveProgress(msgId,
                             in->expectedSize > 0
                                 ? double(in->receivedBytes) / double(in->expectedSize)
                                 : 0.0);

    if (isFinal) {
        in->file->flush();
        in->file->close();
        m_receivedFilePaths.insert(msgId, in->localPath);
        emit fileReceived(msgId, in->sender, in->filename, in->mime,
                          in->receivedBytes, in->localPath);
        // Only show the file row if we are currently viewing the conversation
        // it belongs to - mirrors the text path's (peer == m_activePeer)
        // guard. The file is still received, decrypted, and saved to a temp
        // path regardless; this only controls whether a row appears on screen.
        // Persist the received file row (metadata + temp path).
        m_history.addFileRow(in->sender, in->sender, msgId, in->filename,
                             in->mime, in->receivedBytes, in->localPath,
                             QDateTime::currentMSecsSinceEpoch(),
                             /*mine=*/false);
        if (in->sender == m_activePeer) {
            m_messages.appendFileMessage(in->sender, m_nick,
                                         msgId, in->filename, in->mime,
                                         in->receivedBytes, in->localPath,
                                         /*isOutgoing=*/false);
        } else {
            // Off-screen: bump the badge and drop a system line into that
            // peer's stored history so it is visible when opened.
            m_users.incrementUnread(in->sender);
            m_history.addSystemRow(in->sender,
                                   QStringLiteral("\xF0\x9F\x93\x8E %1 sent you a file: %2")
                                       .arg(in->sender, in->filename),
                                   QDateTime::currentMSecsSinceEpoch());
        }
        m_incoming.remove(msgId);
    }
}

bool ChatClient::saveReceivedFile(const QString &msgId, const QUrl &dest)
{
    // The decrypted file was written to a temp path when it finished arriving;
    // we recorded that path in m_receivedFilePaths keyed by msgId. Saving is
    // then just a copy to the user's chosen destination.
    if (!m_receivedFilePaths.contains(msgId)) {
        emit errorOccurred(tr("That file is no longer available to save."));
        return false;
    }
    const QString tempPath = m_receivedFilePaths.value(msgId);

    // dest comes from the QML save FileDialog; on desktop it is a file:// URL.
    const QString destPath = dest.toLocalFile();
    if (destPath.isEmpty()) {
        emit errorOccurred(tr("Invalid save location."));
        return false;
    }

    // QFile::copy refuses to overwrite, so clear any existing target first.
    if (QFile::exists(destPath))
        QFile::remove(destPath);

    if (!QFile::copy(tempPath, destPath)) {
        emit errorOccurred(tr("Could not save the file to %1").arg(destPath));
        return false;
    }
    return true;
}