#ifndef FILECRYPTO_H
#define FILECRYPTO_H

#include <QByteArray>
#include <QObject>
#include <QString>

#ifdef HAVE_SODIUM
#include <sodium.h>
#endif

// FileCrypto wraps libsodium's secretstream API for chunked file encryption.
//
// Chat messages use AES-256-GCM with one nonce per message - that works
// because each message is encrypted as a single self-contained unit. Files
// are different: we split them into chunks so the whole file never has to
// sit in memory, and managing one-nonce-per-chunk under AES-GCM is the kind
// of thing that goes wrong in subtle and catastrophic ways. Reusing an
// AES-GCM nonce even once leaks the authentication subkey.
//
// libsodium provides crypto_secretstream_xchacha20poly1305 for exactly this
// case. It encrypts a sequence of chunks under one key, manages the nonces
// internally, authenticates each chunk on its own, and tags the last chunk
// with TAG_FINAL so a truncated stream is detectable. We use the same 32-byte
// key the existing X25519+HKDF path produces, with a different HKDF info
// string so the file key is bound to this specific file and direction.
//
// The C++ output must match the Python reference (server/file_crypto.py)
// byte-for-byte. Cross-language interop is what makes the design work.
class FileCrypto : public QObject
{
    Q_OBJECT

public:
    // Sizes that the protocol depends on. Re-exported as named constants
    // so call sites read clearly. Both sides must agree on chunk size.
    static constexpr int CHUNK_SIZE = 64 * 1024;     // 64 KiB plaintext per chunk
    static constexpr int HEADER_BYTES = 24;          // secretstream header
    static constexpr int KEY_BYTES = 32;             // 256-bit symmetric key
    static constexpr int TAG_BYTES = 17;             // per-chunk authentication tag
    static constexpr qint64 MAX_FILE_BYTES =
        50LL * 1024 * 1024;                          // 50 MB hard cap

    explicit FileCrypto(QObject *parent = nullptr);

    // Derive the symmetric key for one file from the existing X25519 shared
    // secret. The info string ties the key to this file id so even if two
    // users share many files, each has its own key. msgId is the UUID we
    // also put in the file_init JSON envelope.
    static QByteArray deriveFileKey(const QByteArray &sharedSecret,
                                    const QString &msgId);

    // ---- Sender side: encrypt a stream of chunks --------------------
    //
    // Usage:
    //   FileCrypto fc;
    //   if (!fc.initPush(fileKey)) return false;
    //   QByteArray header = fc.header();    // include in file_init JSON
    //   send file_init JSON ...
    //   for each plaintext chunk:
    //       QByteArray ct = fc.encryptChunk(chunk, isLast);
    //       send binary frame: msgIdBytes + chunkIndex + ct
    //   send file_end JSON ...
    bool initPush(const QByteArray &fileKey);
    QByteArray header() const { return m_header; }
    QByteArray encryptChunk(const QByteArray &plaintext, bool isLast);

    // ---- Receiver side: decrypt a stream of chunks ------------------
    //
    // Usage:
    //   FileCrypto fc;
    //   if (!fc.initPull(fileKey, headerFromFileInit)) return false;
    //   for each ciphertext chunk received:
    //       QByteArray pt = fc.decryptChunk(ct, &isFinal);
    //       if (pt.isNull()) return error;     // auth failure
    //       write pt to file
    //       if (isFinal) break;
    //   if (!fc.sawFinal()) return error;      // truncation
    bool initPull(const QByteArray &fileKey, const QByteArray &header);
    // Returns plaintext on success, or a null QByteArray on auth failure.
    // *isFinal is set to true if the chunk was tagged TAG_FINAL.
    QByteArray decryptChunk(const QByteArray &ciphertext, bool *isFinal);
    bool sawFinal() const { return m_sawFinal; }

    bool hasCrypto() const;

private:
#ifdef HAVE_SODIUM
    crypto_secretstream_xchacha20poly1305_state m_state;
#endif
    QByteArray m_header;
    bool m_initialized = false;
    bool m_sawFinal = false;
};

#endif // FILECRYPTO_H
