#ifndef CRYPTOBOX_H
#define CRYPTOBOX_H

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QString>

// CryptoBox wraps the end-to-end encryption primitives for the client.
//
// It mirrors, byte-for-byte, the scheme in the Python reference module
// (server/crypto_core.py): a long-term X25519 key pair per user, an X25519
// Diffie-Hellman exchange to obtain a shared secret with a peer, HKDF-SHA256
// to derive a 256-bit key, and AES-256-GCM (or, where AES hardware is absent,
// XChaCha20-Poly1305) for authenticated encryption.
//
// All the heavy lifting is done by libsodium. The class deliberately keeps the
// private key private: there is no getter that returns it, and it is only ever
// written to local storage in the user's own profile.
//
// The design choice to do crypto in C++ rather than QML is intentional. QML
// (JavaScript) has no constant-time primitives and no safe place to hold key
// material, so anything security-sensitive lives here and QML only ever sees
// already-encrypted envelopes or already-decrypted text.
class CryptoBox : public QObject
{
    Q_OBJECT
public:
    explicit CryptoBox(QObject *parent = nullptr);

    // Create a brand-new identity (key pair). Called on first run.
    void generateIdentity();

    // Load / save the long-term private key from the user's profile so the
    // same identity persists across restarts.
    bool loadIdentity(const QString &path);
    bool saveIdentity(const QString &path) const;

    // The raw 32-byte public key, hex-encoded, ready to upload to the server.
    QString publicKeyHex() const;

    // Derive (and cache) the shared key for a peer given the peer's public key
    // in hex. Returns true if the peer key was valid.
    bool ensureSharedKey(const QString &peerName, const QString &peerPubHex);

    // Return the raw 32-byte shared secret for a peer (must have called
    // ensureSharedKey() first). Used as HKDF input material for deriving
    // per-file keys in the file-sharing path. Returns an empty QByteArray
    // if no shared key is cached for that peer.
    QByteArray sharedSecretWith(const QString &peerName) const;

    // Encrypt plaintext for a known peer. Produces a hex nonce and hex
    // ciphertext via the out-parameters. Returns false if no shared key is
    // known for that peer yet.
    bool encryptFor(const QString &peerName, const QString &plaintext,
                    QString &nonceHexOut, QString &ctHexOut) const;

    // Decrypt a message that arrived from a peer. Returns the plaintext, or an
    // empty string and emits decryptionFailed() if authentication fails.
    QString decryptFrom(const QString &peerName, const QString &nonceHex,
                        const QString &ctHex);

    // A safety number for a conversation, in the style of Signal's safety
    // numbers / WhatsApp's security codes. It is computed from BOTH parties'
    // public keys, sorted so that each side derives the identical value, and
    // is meant to be compared out-of-band (read aloud over a call, scanned in
    // person). A matching number tells the two users that no man-in-the-middle
    // has substituted a key during the exchange; a mismatch is a red flag.
    //
    // It takes both keys precisely because a number derived from only one key
    // could not be compared: the two users would be looking at different
    // values. Sorting the keys first makes the function symmetric.
    static QString safetyNumber(const QString &pubKeyHexA,
                                const QString &pubKeyHexB);

signals:
    void decryptionFailed(const QString &peerName);

private:
    QByteArray m_privateKey;  // 32 bytes, secret
    QByteArray m_publicKey;   // 32 bytes, public

    // Cache of derived 32-byte shared keys, keyed by peer nickname.
    QHash<QString, QByteArray> m_sharedKeys;
};

#endif // CRYPTOBOX_H