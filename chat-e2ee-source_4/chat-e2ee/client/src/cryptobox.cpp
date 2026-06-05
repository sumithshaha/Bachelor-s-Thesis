#include "cryptobox.h"

#include <QCryptographicHash>
#include <QDebug>
#include <QFile>

#ifdef HAVE_SODIUM
#include <sodium.h>
#endif

// Domain-separation string. Must match HKDF_INFO in the Python reference so
// that keys derived on either side are identical.
static const char *kHkdfInfo = "tamk-chat-e2ee-v1";

#ifdef HAVE_SODIUM
// HKDF-SHA256 (RFC 5869) built directly from HMAC-SHA256.
//
// libsodium gained dedicated crypto_kdf_hkdf_sha256_* functions only in
// version 1.0.19. Many systems (including Ubuntu 24.04 LTS) still ship
// 1.0.18, so to keep the client portable we implement HKDF ourselves from the
// HMAC-SHA256 primitive that every libsodium version provides. The output is
// identical to Python's cryptography.hazmat HKDF with salt=None, which is what
// the reference implementation and the automated tests use; this has been
// verified to match byte-for-byte.
//
// Because we only ever need a single 32-byte key (one HMAC block is 32 bytes),
// the Expand step needs just one iteration, which keeps this short.
static void hkdfSha256(const unsigned char *ikm, size_t ikmLen,
                       const unsigned char *info, size_t infoLen,
                       unsigned char *okm, size_t okmLen)
{
    // Extract: PRK = HMAC-SHA256(salt, IKM). salt=None on the Python side maps
    // to an all-zero key of the hash block-length, which is exactly what an
    // empty key expands to in HMAC.
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    unsigned char zeroSalt[crypto_auth_hmacsha256_KEYBYTES] = {0};
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, zeroSalt, sizeof zeroSalt);
    crypto_auth_hmacsha256_update(&st, ikm, ikmLen);
    crypto_auth_hmacsha256_final(&st, prk);

    // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01). One block of 32 bytes is
    // enough for an AES-256 key, so we stop here.
    unsigned char t[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_init(&st, prk, sizeof prk);
    crypto_auth_hmacsha256_update(&st, info, infoLen);
    const unsigned char counter = 0x01;
    crypto_auth_hmacsha256_update(&st, &counter, 1);
    crypto_auth_hmacsha256_final(&st, t);

    memcpy(okm, t, okmLen <= sizeof t ? okmLen : sizeof t);
    sodium_memzero(prk, sizeof prk);
    sodium_memzero(t, sizeof t);
}
#endif

CryptoBox::CryptoBox(QObject *parent) : QObject(parent)
{
#ifdef HAVE_SODIUM
    if (sodium_init() < 0) {
        qFatal("libsodium failed to initialise");
    }
    // B1b runtime check: confirm AES-256-GCM is actually usable on this
    // device. On ARM it needs the ARMv8 crypto extensions; the symbol existing
    // in the linked archive is necessary but NOT sufficient - it must return 1
    // here, on the real CPU. If this logs 0 on the phone, AES-GCM is
    // unavailable and message encryption (which uses crypto_aead_aes256gcm_*)
    // will fail; the fix in that case is to switch messages to
    // XChaCha20-Poly1305. On desktop and most post-2016 hardware this is 1.
    qDebug() << "[CRYPTO] sodium_init ok; AES256-GCM available ="
             << crypto_aead_aes256gcm_is_available();
#endif
}

void CryptoBox::generateIdentity()
{
#ifdef HAVE_SODIUM
    m_privateKey.resize(crypto_scalarmult_curve25519_BYTES); // 32
    m_publicKey.resize(crypto_scalarmult_curve25519_BYTES);  // 32
    // A Curve25519 private key is 32 random bytes (with clamping handled by
    // the scalarmult function). The public key is the scalar multiplication of
    // the base point by the private key.
    randombytes_buf(m_privateKey.data(), m_privateKey.size());
    crypto_scalarmult_curve25519_base(
        reinterpret_cast<unsigned char *>(m_publicKey.data()),
        reinterpret_cast<const unsigned char *>(m_privateKey.constData()));
#endif
}

bool CryptoBox::loadIdentity(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    m_privateKey = f.readAll();
    f.close();
    if (m_privateKey.size() != 32)
        return false;
#ifdef HAVE_SODIUM
    m_publicKey.resize(32);
    crypto_scalarmult_curve25519_base(
        reinterpret_cast<unsigned char *>(m_publicKey.data()),
        reinterpret_cast<const unsigned char *>(m_privateKey.constData()));
#endif
    return true;
}

bool CryptoBox::saveIdentity(const QString &path) const
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly))
        return false;
    f.write(m_privateKey);
    f.close();
    // On a real deployment the file permissions should be restricted to the
    // owner; on Android the app's private storage already provides this.
    return true;
}

QString CryptoBox::publicKeyHex() const
{
    return QString::fromLatin1(m_publicKey.toHex());
}

bool CryptoBox::ensureSharedKey(const QString &peerName,
                                const QString &peerPubHex)
{
#ifdef HAVE_SODIUM
    QByteArray peerPub = QByteArray::fromHex(peerPubHex.toLatin1());
    if (peerPub.size() != 32)
        return false;

    // Step 1: X25519 Diffie-Hellman. Multiply our private key by the peer's
    // public key to get a shared secret. The peer, doing the mirror operation,
    // arrives at the same 32 bytes.
    QByteArray sharedSecret(crypto_scalarmult_BYTES, Qt::Uninitialized);
    if (crypto_scalarmult(
            reinterpret_cast<unsigned char *>(sharedSecret.data()),
            reinterpret_cast<const unsigned char *>(m_privateKey.constData()),
            reinterpret_cast<const unsigned char *>(peerPub.constData())) != 0) {
        return false;
    }

    // Step 2: HKDF-SHA256 to turn the raw secret into a clean 256-bit key.
    // We build HKDF directly from HMAC-SHA256 (RFC 5869) rather than the
    // crypto_kdf_hkdf_* convenience API, because that API only exists in
    // libsodium 1.0.19+, whereas crypto_auth_hmacsha256 is available
    // everywhere. With salt=None the salt is 32 zero bytes, which matches the
    // Python reference and was confirmed by the cross-language interop test.
    QByteArray key(crypto_aead_aes256gcm_KEYBYTES, Qt::Uninitialized); // 32
    hkdfSha256(
        reinterpret_cast<const unsigned char *>(sharedSecret.constData()),
        sharedSecret.size(),
        reinterpret_cast<const unsigned char *>(kHkdfInfo), qstrlen(kHkdfInfo),
        reinterpret_cast<unsigned char *>(key.data()), key.size());

    m_sharedKeys.insert(peerName, key);
    sodium_memzero(sharedSecret.data(), sharedSecret.size());
    return true;
#else
    Q_UNUSED(peerName);
    Q_UNUSED(peerPubHex);
    return false;
#endif
}

QByteArray CryptoBox::sharedSecretWith(const QString &peerName) const
{
    // The shared secret was already computed and cached by ensureSharedKey().
    // We return a copy so callers can pass it to HKDF without touching the
    // private cache. If no shared key was ever derived for this peer we
    // return an empty QByteArray; callers must check before use.
    //
    // Used by the file-sharing path in ChatClient::sendFile(), where the
    // returned 32 bytes are fed into FileCrypto's per-file HKDF along with
    // a file-specific info string, so each file gets its own key even when
    // many files travel between the same pair of users.
    return m_sharedKeys.value(peerName);
}

bool CryptoBox::encryptFor(const QString &peerName, const QString &plaintext,
                           QString &nonceHexOut, QString &ctHexOut) const
{
#ifdef HAVE_SODIUM
    if (!m_sharedKeys.contains(peerName))
        return false;
    const QByteArray key = m_sharedKeys.value(peerName);
    const QByteArray pt = plaintext.toUtf8();

    QByteArray nonce(crypto_aead_aes256gcm_NPUBBYTES, Qt::Uninitialized); // 12
    randombytes_buf(nonce.data(), nonce.size());

    QByteArray ct(pt.size() + crypto_aead_aes256gcm_ABYTES, Qt::Uninitialized);
    unsigned long long ctLen = 0;
    crypto_aead_aes256gcm_encrypt(
        reinterpret_cast<unsigned char *>(ct.data()), &ctLen,
        reinterpret_cast<const unsigned char *>(pt.constData()), pt.size(),
        nullptr, 0,           // no associated data in this basic version
        nullptr,              // nsec is always null for this construction
        reinterpret_cast<const unsigned char *>(nonce.constData()),
        reinterpret_cast<const unsigned char *>(key.constData()));
    ct.resize(static_cast<int>(ctLen));

    nonceHexOut = QString::fromLatin1(nonce.toHex());
    ctHexOut = QString::fromLatin1(ct.toHex());
    return true;
#else
    Q_UNUSED(peerName); Q_UNUSED(plaintext);
    Q_UNUSED(nonceHexOut); Q_UNUSED(ctHexOut);
    return false;
#endif
}

QString CryptoBox::decryptFrom(const QString &peerName, const QString &nonceHex,
                               const QString &ctHex)
{
#ifdef HAVE_SODIUM
    if (!m_sharedKeys.contains(peerName)) {
        emit decryptionFailed(peerName);
        return QString();
    }
    const QByteArray key = m_sharedKeys.value(peerName);
    const QByteArray nonce = QByteArray::fromHex(nonceHex.toLatin1());
    const QByteArray ct = QByteArray::fromHex(ctHex.toLatin1());

    QByteArray pt(ct.size(), Qt::Uninitialized);
    unsigned long long ptLen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            reinterpret_cast<unsigned char *>(pt.data()), &ptLen,
            nullptr,
            reinterpret_cast<const unsigned char *>(ct.constData()), ct.size(),
            nullptr, 0,
            reinterpret_cast<const unsigned char *>(nonce.constData()),
            reinterpret_cast<const unsigned char *>(key.constData())) != 0) {
        // Authentication failed: the message was tampered with, or the key is
        // wrong. We refuse to return any plaintext.
        emit decryptionFailed(peerName);
        return QString();
    }
    pt.resize(static_cast<int>(ptLen));
    return QString::fromUtf8(pt);
#else
    Q_UNUSED(peerName); Q_UNUSED(nonceHex); Q_UNUSED(ctHex);
    return QString();
#endif
}

QString CryptoBox::safetyNumber(const QString &pubKeyHexA,
                                const QString &pubKeyHexB)
{
    // Decode both 32-byte public keys.
    QByteArray a = QByteArray::fromHex(pubKeyHexA.toLatin1());
    QByteArray b = QByteArray::fromHex(pubKeyHexB.toLatin1());
    if (a.size() != 32 || b.size() != 32)
        return QStringLiteral("(unavailable)");

    // Sort the two keys so that both participants hash the same ordered input
    // and therefore arrive at the same number. Without this, Alice (hashing
    // her-key + Bob-key) and Bob (hashing his-key + Alice-key) would compute
    // different values and the comparison would be meaningless. This symmetry
    // trick is exactly what makes Signal's safety numbers work.
    const QByteArray lo = (a < b) ? a : b;
    const QByteArray hi = (a < b) ? b : a;

    QByteArray combined;
    combined.append(lo);
    combined.append(hi);

    const QByteArray hash =
        QCryptographicHash::hash(combined, QCryptographicHash::Sha256);

    // Render the first 24 bytes as six groups of five decimal digits. Each
    // group is a 4-byte chunk reduced modulo 100000. Six groups (~99 bits of
    // the hash surfaced through 30 digits) is short enough to read aloud yet
    // far too large to forge a collision against in practice. This matches the
    // Python reference and has been confirmed identical byte-for-byte.
    QString out;
    for (int g = 0; g < 6; ++g) {
        quint32 v =
            (static_cast<quint32>(static_cast<quint8>(hash.at(g * 4))) << 24) |
            (static_cast<quint32>(static_cast<quint8>(hash.at(g * 4 + 1))) << 16) |
            (static_cast<quint32>(static_cast<quint8>(hash.at(g * 4 + 2))) << 8) |
            (static_cast<quint32>(static_cast<quint8>(hash.at(g * 4 + 3))));
        v %= 100000;
        out += QString::number(v).rightJustified(5, '0');
        if (g < 5)
            out += ' ';
    }
    return out;
}