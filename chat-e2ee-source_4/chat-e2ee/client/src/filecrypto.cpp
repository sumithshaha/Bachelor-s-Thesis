#include "filecrypto.h"

#include <QCryptographicHash>
#include <QDebug>
#include <cstring>

// Domain-separation string for the file key, paired with the message id.
// MUST match the Python reference: f"tamk-chat-file-v1|{msg_id}".encode().
static const char *kFileHkdfPrefix = "tamk-chat-file-v1|";

FileCrypto::FileCrypto(QObject *parent) : QObject(parent)
{
#ifdef HAVE_SODIUM
    std::memset(&m_state, 0, sizeof m_state);
#endif
}

bool FileCrypto::hasCrypto() const
{
#ifdef HAVE_SODIUM
    return true;
#else
    return false;
#endif
}

#ifdef HAVE_SODIUM
// HKDF-SHA256 (RFC 5869) built from HMAC-SHA256, identical to the helper in
// cryptobox.cpp. We re-implement it here rather than share to keep the two
// files independent - it is only a few lines and the file is easier to read
// and explain when self-contained. Both the message AEAD and the file AEAD
// derive their keys with the same HKDF construction; only the info string
// differs.
static void hkdfSha256(const unsigned char *ikm, size_t ikmLen,
                       const unsigned char *info, size_t infoLen,
                       unsigned char *okm, size_t okmLen)
{
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    unsigned char zeroSalt[crypto_auth_hmacsha256_KEYBYTES] = {0};
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, zeroSalt, sizeof zeroSalt);
    crypto_auth_hmacsha256_update(&st, ikm, ikmLen);
    crypto_auth_hmacsha256_final(&st, prk);

    unsigned char t[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_init(&st, prk, sizeof prk);
    crypto_auth_hmacsha256_update(&st, info, infoLen);
    const unsigned char counter = 0x01;
    crypto_auth_hmacsha256_update(&st, &counter, 1);
    crypto_auth_hmacsha256_final(&st, t);

    std::memcpy(okm, t, okmLen <= sizeof t ? okmLen : sizeof t);
    sodium_memzero(prk, sizeof prk);
    sodium_memzero(t, sizeof t);
}
#endif

QByteArray FileCrypto::deriveFileKey(const QByteArray &sharedSecret,
                                     const QString &msgId)
{
#ifdef HAVE_SODIUM
    // Build the HKDF info string. The Python side does:
    //     f"tamk-chat-file-v1|{msg_id}".encode("utf-8")
    // We do exactly the same here. ASCII UUIDs round-trip safely as UTF-8.
    QByteArray info = QByteArray(kFileHkdfPrefix) + msgId.toUtf8();

    QByteArray key(KEY_BYTES, Qt::Uninitialized);
    hkdfSha256(
        reinterpret_cast<const unsigned char *>(sharedSecret.constData()),
        sharedSecret.size(),
        reinterpret_cast<const unsigned char *>(info.constData()),
        info.size(),
        reinterpret_cast<unsigned char *>(key.data()),
        KEY_BYTES);
    return key;
#else
    Q_UNUSED(sharedSecret);
    Q_UNUSED(msgId);
    return QByteArray();
#endif
}

bool FileCrypto::initPush(const QByteArray &fileKey)
{
#ifdef HAVE_SODIUM
    if (fileKey.size() != KEY_BYTES) {
        qWarning() << "FileCrypto::initPush: key wrong size"
                   << fileKey.size();
        return false;
    }
    m_header.resize(HEADER_BYTES);
    if (crypto_secretstream_xchacha20poly1305_init_push(
            &m_state,
            reinterpret_cast<unsigned char *>(m_header.data()),
            reinterpret_cast<const unsigned char *>(fileKey.constData())) != 0) {
        qWarning() << "secretstream init_push failed";
        m_header.clear();
        return false;
    }
    m_initialized = true;
    m_sawFinal = false;
    return true;
#else
    Q_UNUSED(fileKey);
    return false;
#endif
}

QByteArray FileCrypto::encryptChunk(const QByteArray &plaintext, bool isLast)
{
#ifdef HAVE_SODIUM
    if (!m_initialized) {
        qWarning() << "FileCrypto::encryptChunk before initPush";
        return QByteArray();
    }
    // The ciphertext is the plaintext plus the secretstream ABYTES overhead
    // (17 bytes: 16-byte Poly1305 tag + 1 tag-type byte). We pre-allocate.
    QByteArray ct(plaintext.size() + TAG_BYTES, Qt::Uninitialized);
    unsigned long long ctlen = 0;
    const unsigned char tag = isLast
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    if (crypto_secretstream_xchacha20poly1305_push(
            &m_state,
            reinterpret_cast<unsigned char *>(ct.data()), &ctlen,
            reinterpret_cast<const unsigned char *>(plaintext.constData()),
            plaintext.size(),
            nullptr, 0,  // no additional data
            tag) != 0) {
        qWarning() << "secretstream push failed";
        return QByteArray();
    }
    ct.resize(int(ctlen));
    return ct;
#else
    Q_UNUSED(plaintext);
    Q_UNUSED(isLast);
    return QByteArray();
#endif
}

bool FileCrypto::initPull(const QByteArray &fileKey, const QByteArray &header)
{
#ifdef HAVE_SODIUM
    if (fileKey.size() != KEY_BYTES || header.size() != HEADER_BYTES) {
        qWarning() << "FileCrypto::initPull: bad sizes"
                   << fileKey.size() << header.size();
        return false;
    }
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &m_state,
            reinterpret_cast<const unsigned char *>(header.constData()),
            reinterpret_cast<const unsigned char *>(fileKey.constData())) != 0) {
        qWarning() << "secretstream init_pull failed - bad header or key";
        return false;
    }
    m_initialized = true;
    m_sawFinal = false;
    return true;
#else
    Q_UNUSED(fileKey);
    Q_UNUSED(header);
    return false;
#endif
}

QByteArray FileCrypto::decryptChunk(const QByteArray &ciphertext, bool *isFinal)
{
#ifdef HAVE_SODIUM
    if (isFinal) *isFinal = false;
    if (!m_initialized) {
        qWarning() << "FileCrypto::decryptChunk before initPull";
        return QByteArray();
    }
    if (ciphertext.size() < TAG_BYTES) {
        return QByteArray();
    }
    QByteArray pt(ciphertext.size() - TAG_BYTES, Qt::Uninitialized);
    unsigned long long ptlen = 0;
    unsigned char tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &m_state,
            reinterpret_cast<unsigned char *>(pt.data()), &ptlen, &tag,
            reinterpret_cast<const unsigned char *>(ciphertext.constData()),
            ciphertext.size(),
            nullptr, 0) != 0) {
        // Authentication failed. Returning a null QByteArray signals the
        // error - never garbage plaintext.
        return QByteArray();
    }
    pt.resize(int(ptlen));
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        m_sawFinal = true;
        if (isFinal) *isFinal = true;
    }
    return pt;
#else
    Q_UNUSED(ciphertext);
    if (isFinal) *isFinal = false;
    return QByteArray();
#endif
}
