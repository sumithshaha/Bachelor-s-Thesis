// ============================================================================
//  cryptobox.cpp  --  implementation of the ratchet-backed CryptoBox.
//
//  STATUS: ported faithfully from VERIFIED reference code -- the C++ ratchet in
//  tests/ratchet_cli.cpp (compiled and proven to interoperate with the Python
//  reference across both ciphers) and server/crypto_core.py (run, 19 tests
//  green). It has NOT been compiled against the Qt 6 toolchain / Android NDK.
//  Build and test on the real toolchain before trusting it. See the checklist
//  at the end of this file.
//
//  The cryptographic helpers below (hkdf, kdfRk, kdfCk, dhFn, genKeypair, the
//  AEAD dispatch, the associated-data layout, the cipher tags and INFO strings)
//  are transcribed from ratchet_cli.cpp so that this client and the Python
//  reference derive identical keys and ciphertexts.
// ============================================================================
#include "cryptobox.h"
#include <QDateTime>
#include "x3dh.h"

#include <QCryptographicHash>
#include <QDataStream>
#include <QDebug>
#include <QFile>

#ifdef HAVE_SODIUM
#include <sodium.h>
#include <cstring>
#endif

// Domain-separation strings. MUST match crypto_core.py exactly.
static const char *kHkdfInfo = "tamk-chat-e2ee-v1";        // HKDF_INFO / INFO_SK
static const char *kRootInfo = "tamk-chat-ratchet-root-v1"; // INFO_ROOT
// Static key for sealing local history at rest (independent of the ratchet).
static const char *kLocalInfo = "tamk-chat-local-history-v1";

// Per-message cipher tags (also carried in the wire header and folded into AD).
static const char *kCipherAes = "a256gcm-r1";        // AES-256-GCM, 12-byte nonce
static const char *kCipherXchacha = "xc20p1305-r1";  // XChaCha20-Poly1305, 24-byte nonce

static const quint32 kMaxSkip = 1000;  // bound on skipped (out-of-order) messages

// FORWARD SECRECY: bound on the TOTAL number of banked skipped message keys.
//
// kMaxSkip above bounds a single gap. It does not bound the store, and the two
// are not the same thing. A banked key is only erased when the message it
// belongs to actually arrives; a message that is never delivered -- the sender
// went offline mid-run, the frame was dropped -- leaves its key in the store
// permanently, and persistSession() writes the store to disk. Forward secrecy
// is the claim that a device compromised today cannot decrypt traffic captured
// yesterday, and it holds only because the keys that encrypted that traffic no
// longer exist. Retaining them indefinitely voids the claim for exactly the
// messages an attacker is most likely to have captured but never seen
// delivered.
//
// The Double Ratchet specification requires deletion bounded by count or by
// time (Perrin & Marlinspike, 2016, section 2.6). This is the count bound. Two
// full gaps' worth is generous: it tolerates the largest legitimate
// out-of-order burst on the current chain and the same again on the chain being
// superseded, which is the widest window a genuine reordering can span.
static const int kMaxSkippedTotal = 2 * int(kMaxSkip);

#ifdef HAVE_SODIUM
// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) from HMAC-SHA256, arbitrary output length.
//
// libsodium's dedicated crypto_kdf_hkdf_sha256_* arrived in 1.0.19; older
// systems ship 1.0.18, so we build HKDF from the HMAC-SHA256 primitive every
// version provides. Output matches Python's cryptography.hazmat HKDF with the
// same salt/info -- verified byte-for-byte by the cross-language tests.
//
// salt == nullptr maps to an all-zero key of the hash block length, matching
// salt=None on the Python side.
// ---------------------------------------------------------------------------
static void hkdf(const unsigned char *salt, size_t saltLen,
                 const unsigned char *ikm, size_t ikmLen,
                 const unsigned char *info, size_t infoLen,
                 unsigned char *okm, size_t okmLen)
{
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    unsigned char zero[crypto_auth_hmacsha256_KEYBYTES] = {0};
    crypto_auth_hmacsha256_state st;

    // Extract: PRK = HMAC(salt, IKM).
    if (salt == nullptr) { salt = zero; saltLen = sizeof zero; }
    crypto_auth_hmacsha256_init(&st, salt, saltLen);
    crypto_auth_hmacsha256_update(&st, ikm, ikmLen);
    crypto_auth_hmacsha256_final(&st, prk);

    // Expand: T(i) = HMAC(PRK, T(i-1) || info || i), concatenated until okmLen.
    unsigned char t[crypto_auth_hmacsha256_BYTES];
    size_t tLen = 0;
    size_t done = 0;
    unsigned char counter = 1;
    while (done < okmLen) {
        crypto_auth_hmacsha256_init(&st, prk, sizeof prk);
        if (tLen) crypto_auth_hmacsha256_update(&st, t, tLen);
        crypto_auth_hmacsha256_update(&st, info, infoLen);
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t);
        tLen = sizeof t;
        const size_t take = (okmLen - done < tLen) ? (okmLen - done) : tLen;
        memcpy(okm + done, t, take);
        done += take;
        ++counter;
    }
    sodium_memzero(prk, sizeof prk);
    sodium_memzero(t, sizeof t);
}

// X25519(our private, their public).
static QByteArray dhFn(const QByteArray &priv, const QByteArray &pub)
{
    QByteArray out(crypto_scalarmult_BYTES, Qt::Uninitialized);
    // crypto_scalarmult is declared warn_unused_result: it returns -1 when the
    // result is a low-order (degenerate) point -- i.e. an all-zero shared
    // secret that must never be used. Check it, zero the buffer on failure, and
    // return empty so callers do not proceed with a bad DH result.
    if (crypto_scalarmult(
            reinterpret_cast<unsigned char *>(out.data()),
            reinterpret_cast<const unsigned char *>(priv.constData()),
            reinterpret_cast<const unsigned char *>(pub.constData())) != 0) {
        sodium_memzero(out.data(), out.size());
        return QByteArray();
    }
    return out;
}

// Fresh X25519 ratchet keypair.
static void genKeypair(QByteArray &priv, QByteArray &pub)
{
    priv.resize(crypto_scalarmult_SCALARBYTES);
    pub.resize(crypto_scalarmult_BYTES);
    randombytes_buf(priv.data(), priv.size());
    crypto_scalarmult_base(reinterpret_cast<unsigned char *>(pub.data()),
                           reinterpret_cast<const unsigned char *>(priv.constData()));
}

// Root KDF: HKDF(salt = root key, IKM = DH output, info = INFO_ROOT) -> 64 bytes
// split into (new root key, chain key).
static void kdfRk(const QByteArray &rk, const QByteArray &dhOut,
                  QByteArray &rkOut, QByteArray &ckOut)
{
    unsigned char okm[64];
    hkdf(reinterpret_cast<const unsigned char *>(rk.constData()), rk.size(),
         reinterpret_cast<const unsigned char *>(dhOut.constData()), dhOut.size(),
         reinterpret_cast<const unsigned char *>(kRootInfo), strlen(kRootInfo),
         okm, sizeof okm);
    rkOut = QByteArray(reinterpret_cast<char *>(okm), 32);
    ckOut = QByteArray(reinterpret_cast<char *>(okm + 32), 32);
    sodium_memzero(okm, sizeof okm);
}

// Chain KDF: one message step. HMAC with constant bytes; one-way, so the next
// chain key cannot recover this message key (forward secrecy).
static void kdfCk(const QByteArray &ck, QByteArray &ckNextOut, QByteArray &mkOut)
{
    unsigned char next[crypto_auth_hmacsha256_BYTES];
    unsigned char mk[crypto_auth_hmacsha256_BYTES];
    const unsigned char c2 = 0x02, c1 = 0x01;
    crypto_auth_hmacsha256(next, &c2, 1,
                           reinterpret_cast<const unsigned char *>(ck.constData()));
    crypto_auth_hmacsha256(mk, &c1, 1,
                           reinterpret_cast<const unsigned char *>(ck.constData()));
    ckNextOut = QByteArray(reinterpret_cast<char *>(next), 32);
    mkOut = QByteArray(reinterpret_cast<char *>(mk), 32);
    sodium_memzero(next, sizeof next);
    sodium_memzero(mk, sizeof mk);
}

// Associated data = cipher tag || dh || pn(4, big-endian) || n(4, big-endian).
static QByteArray adBytes(const QByteArray &cipher, const QByteArray &dhPub,
                          quint32 pn, quint32 n)
{
    QByteArray a = cipher;
    a.append(dhPub);
    for (int s = 24; s >= 0; s -= 8) a.append(char((pn >> s) & 0xff));
    for (int s = 24; s >= 0; s -= 8) a.append(char((n >> s) & 0xff));
    return a;
}

static size_t nonceLenFor(const QByteArray &cipher)
{
    return cipher == kCipherAes ? crypto_aead_aes256gcm_NPUBBYTES
                                : crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
}

static QByteArray aeadEncrypt(const QByteArray &cipher, const QByteArray &key,
                              const QByteArray &nonce, const QByteArray &pt,
                              const QByteArray &ad)
{
    const auto *p = reinterpret_cast<const unsigned char *>(pt.constData());
    const auto *a = reinterpret_cast<const unsigned char *>(ad.constData());
    const auto *nn = reinterpret_cast<const unsigned char *>(nonce.constData());
    const auto *k = reinterpret_cast<const unsigned char *>(key.constData());
    unsigned long long clen = 0;
    if (cipher == kCipherAes) {
        QByteArray ct(pt.size() + crypto_aead_aes256gcm_ABYTES, Qt::Uninitialized);
        crypto_aead_aes256gcm_encrypt(
            reinterpret_cast<unsigned char *>(ct.data()), &clen,
            p, pt.size(), a, ad.size(), nullptr, nn, k);
        ct.resize(int(clen));
        return ct;
    }
    QByteArray ct(pt.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES, Qt::Uninitialized);
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char *>(ct.data()), &clen,
        p, pt.size(), a, ad.size(), nullptr, nn, k);
    ct.resize(int(clen));
    return ct;
}

// Returns true on success; false on authentication failure.
static bool aeadDecrypt(const QByteArray &cipher, const QByteArray &key,
                        const QByteArray &nonce, const QByteArray &ct,
                        const QByteArray &ad, QByteArray &ptOut)
{
    const auto *c = reinterpret_cast<const unsigned char *>(ct.constData());
    const auto *a = reinterpret_cast<const unsigned char *>(ad.constData());
    const auto *nn = reinterpret_cast<const unsigned char *>(nonce.constData());
    const auto *k = reinterpret_cast<const unsigned char *>(key.constData());
    QByteArray pt(ct.size(), Qt::Uninitialized);
    unsigned long long plen = 0;
    int rc;
    if (cipher == kCipherAes)
        rc = crypto_aead_aes256gcm_decrypt(
            reinterpret_cast<unsigned char *>(pt.data()), &plen, nullptr,
            c, ct.size(), a, ad.size(), nn, k);
    else
        rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char *>(pt.data()), &plen, nullptr,
            c, ct.size(), a, ad.size(), nn, k);
    if (rc != 0) return false;
    pt.resize(int(plen));
    ptOut = pt;
    return true;
}

// Key into the skipped-message store: DHr_pub || n(4, big-endian).
static QByteArray skipKey(const QByteArray &dhPub, quint32 n)
{
    QByteArray k = dhPub;
    for (int s = 24; s >= 0; s -= 8) k.append(char((n >> s) & 0xff));
    return k;
}

// Route A bootstrap secret: HKDF over the X25519 of our private and the peer's
// identity public key, with INFO_SK -- identical to crypto_core.derive_shared_key.
static QByteArray bootstrapSk(const QByteArray &myPriv, const QByteArray &peerPub)
{
    QByteArray ss = dhFn(myPriv, peerPub);
    unsigned char okm[32];
    hkdf(nullptr, 0,
         reinterpret_cast<const unsigned char *>(ss.constData()), ss.size(),
         reinterpret_cast<const unsigned char *>(kHkdfInfo), strlen(kHkdfInfo),
         okm, sizeof okm);
    QByteArray k(reinterpret_cast<char *>(okm), 32);
    sodium_memzero(okm, sizeof okm);
    return k;
}

// FORWARD SECRECY: destroy banked keys that can no longer be legitimately used.
//
// Skipped keys are stored under (DHr_pub || n), so each entry names the ratchet
// generation it belongs to. After a DH ratchet step the generation before last
// is unreachable: the peer has moved on twice, so no message can still arrive
// under it. Those keys are pure liability -- they decrypt captured traffic and
// nothing else -- and before this purge they survived every ratchet step and
// were written to disk on every persistSession().
//
// Keeping the current and the immediately previous generation is deliberate,
// not incidental: a message sent just before the peer ratcheted may legitimately
// arrive just after, and dropping the previous generation would lose it.
static void purgeUnreachableSkipped(RatchetSession &s,
                                    const QByteArray &keepCurrent,
                                    const QByteArray &keepPrevious)
{
    for (auto it = s.skipped.begin(); it != s.skipped.end(); ) {
        const QByteArray gen = it.key().left(keepCurrent.size());
        if (gen == keepCurrent || (!keepPrevious.isEmpty() && gen == keepPrevious)) {
            ++it;
            continue;
        }
        // Wipe the key material itself, not just the map entry: erase() releases
        // the buffer but does not scrub it, and a released buffer is readable
        // until it is reused.
        QByteArray dead = it.value();
        sodium_memzero(dead.data(), dead.size());
        it = s.skipped.erase(it);
    }
}

// FORWARD SECRECY: enforce the total cap, oldest generation first.
//
// The purge above bounds the store to two generations, which is normally
// sufficient. This is the backstop for the pathological case -- a peer that
// never ratchets while sending a very long run with gaps -- where a single
// generation could grow without limit. Entries from the superseded generation
// are dropped before any from the live one, so the keys most likely to still be
// needed are the last to go.
static void enforceSkippedCap(RatchetSession &s, const QByteArray &keepCurrent)
{
    if (s.skipped.size() <= kMaxSkippedTotal)
        return;
    for (auto it = s.skipped.begin();
         it != s.skipped.end() && s.skipped.size() > kMaxSkippedTotal; ) {
        if (it.key().left(keepCurrent.size()) == keepCurrent) { ++it; continue; }
        QByteArray dead = it.value();
        sodium_memzero(dead.data(), dead.size());
        it = s.skipped.erase(it);
    }
    // Still over after shedding the old generation: shed from the live one too.
    for (auto it = s.skipped.begin();
         it != s.skipped.end() && s.skipped.size() > kMaxSkippedTotal; ) {
        QByteArray dead = it.value();
        sodium_memzero(dead.data(), dead.size());
        it = s.skipped.erase(it);
    }
}

// Advance the receiving chain to `until`, banking skipped message keys.
static bool skipTo(RatchetSession &s, quint32 until)
{
    if (s.Nr + kMaxSkip < until) return false;  // DoS bound
    if (!s.CKr.isEmpty()) {
        while (s.Nr < until) {
            QByteArray ckNext, mk;
            kdfCk(s.CKr, ckNext, mk);
            s.CKr = ckNext;
            s.skipped.insert(skipKey(s.DHr_pub, s.Nr), mk);
            ++s.Nr;
        }
        // Banking a long gap can push the store past its bound in one call, so
        // the cap is enforced here as well as at the ratchet step.
        enforceSkippedCap(s, s.DHr_pub);
    }
    return true;
}

// A DH ratchet step on receiving a new peer ratchet key.
static void dhRatchet(RatchetSession &s, const QByteArray &dhPub)
{
    // The generation we are leaving behind. Keys older than this can never be
    // used again and are destroyed below.
    const QByteArray supersededGen = s.DHr_pub;

    s.PN = s.Ns;
    s.Ns = 0;
    s.Nr = 0;
    s.DHr_pub = dhPub;
    s.haveDHr = true;
    kdfRk(s.RK, dhFn(s.DHs_priv, s.DHr_pub), s.RK, s.CKr);
    genKeypair(s.DHs_priv, s.DHs_pub);
    kdfRk(s.RK, dhFn(s.DHs_priv, s.DHr_pub), s.RK, s.CKs);

    // Now that the generation has advanced, destroy every banked key that
    // belongs to a generation older than the one just superseded.
    purgeUnreachableSkipped(s, s.DHr_pub, supersededGen);
    enforceSkippedCap(s, s.DHr_pub);
}
#endif  // HAVE_SODIUM

// ============================================================================
//  Construction
// ============================================================================
CryptoBox::CryptoBox(QObject *parent) : QObject(parent)
{
#ifdef HAVE_SODIUM
    if (sodium_init() < 0)
        qFatal("libsodium failed to initialise");
    // Runtime AES-256-GCM probe. This is the cipher-selection signal: 1 => this
    // build sends AES-256-GCM, 0 => it sends XChaCha20-Poly1305. On the
    // Windows/MinGW desktop this typically logs 0 (a libsodium runtime-detection
    // limitation), which is fine -- the hybrid simply uses XChaCha20 there.
    qDebug() << "[CRYPTO] sodium_init ok; AES256-GCM available ="
             << crypto_aead_aes256gcm_is_available();
#else
    qWarning() << "[CRYPTO] built WITHOUT libsodium (HAVE_SODIUM undefined):"
               << "encryption is unavailable.";
#endif
}

// ============================================================================
//  Identity  (unchanged behaviour from the original implementation)
// ============================================================================
// ---------------------------------------------------------------------------
// Bridging between the Qt types used throughout this class and the Qt-free
// X3DH module. Kept trivial and local: the crypto module deliberately knows
// nothing about Qt, so the conversion lives on this side of the boundary.
// ---------------------------------------------------------------------------
#ifdef HAVE_SODIUM
static X3DH::Bytes toBytes(const QByteArray &b)
{
    return X3DH::Bytes(reinterpret_cast<const unsigned char *>(b.constData()),
                       reinterpret_cast<const unsigned char *>(b.constData())
                           + b.size());
}

static QByteArray fromBytes(const X3DH::Bytes &b)
{
    return QByteArray(reinterpret_cast<const char *>(b.data()), int(b.size()));
}

// Populate the X25519 pair the rest of this class uses from a version 2
// Ed25519 seed. This is the single point that makes the migration invisible to
// every existing caller: after it runs, m_privateKey / m_publicKey hold exactly
// the kind of key they always held, so the ratchet, the safety number and
// dhFn need no changes at all.
bool CryptoBox::deriveAgreementKeysFromSeed()
{
    const X3DH::Bytes seed = toBytes(m_identitySeed);
    const X3DH::Bytes edPub = X3DH::identityPublic(seed);
    const X3DH::Bytes xPriv = X3DH::identityToX25519Private(seed);
    X3DH::Bytes xPub;
    if (edPub.empty() || xPriv.empty()
        || !X3DH::identityToX25519Public(edPub, xPub)) {
        qWarning() << "[IDENTITY] failed to derive agreement keys from seed";
        return false;
    }
    m_edPublicKey = fromBytes(edPub);
    m_privateKey  = fromBytes(xPriv);
    m_publicKey   = fromBytes(xPub);
    return true;
}
#endif

void CryptoBox::generateIdentity()
{
#ifdef HAVE_SODIUM
    // VERSION 2: the identity is an Ed25519 signing key. The 32-byte seed is
    // the only secret stored; the signing key, the Ed25519 public key and the
    // X25519 agreement pair are all derived from it, so there is exactly one
    // thing to protect at rest.
    X3DH::Bytes seed, edPub;
    if (!X3DH::generateIdentity(seed, edPub)) {
        qWarning() << "[IDENTITY] Ed25519 identity generation FAILED";
        return;
    }
    m_identitySeed = fromBytes(seed);
    sodium_memzero(seed.data(), seed.size());
    if (!deriveAgreementKeysFromSeed()) {
        m_identitySeed.clear();
        return;
    }
    m_identityVersion = 2;
    qDebug() << "[IDENTITY] generated v2 (Ed25519) identity"
             << "| ed pub" << m_edPublicKey.toHex().left(16)
             << "| derived x25519 pub" << m_publicKey.toHex().left(16);
#endif
}

QString CryptoBox::edPublicKeyHex() const
{
    return QString::fromUtf8(m_edPublicKey.toHex());
}

QByteArray CryptoBox::signWithIdentity(const QByteArray &message) const
{
#ifdef HAVE_SODIUM
    if (m_identityVersion != 2 || m_identitySeed.isEmpty())
        return QByteArray();     // a v1 identity has no signing key
    return fromBytes(X3DH::sign(toBytes(m_identitySeed), toBytes(message)));
#else
    Q_UNUSED(message);
    return QByteArray();
#endif
}

bool CryptoBox::verifyIdentitySignature(const QByteArray &edPub,
                                        const QByteArray &message,
                                        const QByteArray &sig)
{
#ifdef HAVE_SODIUM
    return X3DH::verify(toBytes(edPub), toBytes(message), toBytes(sig));
#else
    Q_UNUSED(edPub); Q_UNUSED(message); Q_UNUSED(sig);
    return false;
#endif
}

// ===========================================================================
//  X3DH prekeys
//
//  The signed prekey is the part of a bundle the relay could otherwise forge.
//  Signing it with the identity is what binds the bundle to the keyholder, and
//  verifying that signature -- on the client, never on the relay -- is what makes
//  the bundle usable. Everything below exists to make those two steps possible
//  and to keep the private halves in one place.
// ===========================================================================

bool CryptoBox::generatePrekeys(int opkCount)
{
#ifdef HAVE_SODIUM
    if (!hasX3dhIdentity()) {
        qWarning() << "[PREKEYS] refusing to generate: identity is version"
                   << m_identityVersion << "and cannot sign";
        return false;
    }
    if (opkCount < 0) opkCount = 0;

    X3DH::Bytes spkPriv, spkPub, sig;
    if (!X3DH::newSignedPrekey(toBytes(m_identitySeed), spkPriv, spkPub, sig)) {
        qWarning() << "[PREKEYS] signed prekey generation FAILED";
        return false;
    }
    // Retain the key we are replacing. A peer may already hold a bundle built
    // from it and send its opener at any moment; wiping the private half here
    // would make that message permanently undecryptable. It is destroyed later
    // by dropExpiredPreviousPrekey().
    if (!m_spkPriv.isEmpty()) {
        if (!m_prevSpkPriv.isEmpty())
            sodium_memzero(m_prevSpkPriv.data(), m_prevSpkPriv.size());
        m_prevSpkPriv = m_spkPriv;
        m_prevSpkPub  = m_spkPub;
        m_prevSpkRetiredMs = QDateTime::currentMSecsSinceEpoch();
    }
    m_spkPriv = fromBytes(spkPriv);
    m_spkPub  = fromBytes(spkPub);
    m_spkSig  = fromBytes(sig);
    m_spkCreatedMs = QDateTime::currentMSecsSinceEpoch();
    sodium_memzero(spkPriv.data(), spkPriv.size());

    // Ids continue from where the last pool stopped rather than restarting at
    // zero. A relay that still holds an old pool would otherwise be asked to
    // store a new key under an id it already knows, and the responder would
    // consume the wrong private half.
    m_opkPriv.clear();
    for (int i = 0; i < opkCount; ++i) {
        X3DH::Bytes priv, pub;
        if (!X3DH::newOneTimePrekey(priv, pub)) return false;
        m_opkPriv.insert(m_nextOpkId++, fromBytes(priv));
        sodium_memzero(priv.data(), priv.size());
    }
    qDebug() << "[PREKEYS] generated signed prekey" << m_spkPub.toHex().left(16)
             << "and" << m_opkPriv.size() << "one-time prekeys";
    return true;
#else
    Q_UNUSED(opkCount);
    return false;
#endif
}

QString CryptoBox::signedPrekeyPublicHex() const
{
    return QString::fromUtf8(m_spkPub.toHex());
}

QString CryptoBox::signedPrekeySignatureHex() const
{
    return QString::fromUtf8(m_spkSig.toHex());
}

QMap<quint32, QString> CryptoBox::oneTimePrekeyPublicsHex() const
{
    QMap<quint32, QString> out;
#ifdef HAVE_SODIUM
    for (auto it = m_opkPriv.cbegin(); it != m_opkPriv.cend(); ++it) {
        // Recompute the public from the private rather than storing both: one
        // copy of each secret, and no way for the two to drift apart.
        QByteArray pub(crypto_scalarmult_BYTES, Qt::Uninitialized);
        crypto_scalarmult_base(
            reinterpret_cast<unsigned char *>(pub.data()),
            reinterpret_cast<const unsigned char *>(it.value().constData()));
        out.insert(it.key(), QString::fromUtf8(pub.toHex()));
    }
#endif
    return out;
}

bool CryptoBox::agreementKeyFor(const QByteArray &publishedKey,
                                const QString &ikType, QByteArray &out)
{
#ifdef HAVE_SODIUM
    if (publishedKey.size() != 32)
        return false;
    if (ikType == QLatin1String("ed25519")) {
        X3DH::Bytes x;
        if (!X3DH::identityToX25519Public(toBytes(publishedKey), x))
            return false;
        out = fromBytes(x);
        return true;
    }
    if (ikType.isEmpty() || ikType == QLatin1String("x25519")) {
        out = publishedKey;          // legacy: already an agreement key
        return true;
    }
    return false;                    // an unknown type is never guessed at
#else
    Q_UNUSED(publishedKey); Q_UNUSED(ikType); Q_UNUSED(out);
    return false;
#endif
}

bool CryptoBox::verifyBundle(const QByteArray &ik, const QByteArray &spk,
                             const QByteArray &spkSig)
{
    // The bundle arrives as JSON from an untrusted relay, so the shapes are
    // checked before the signature: a short key would otherwise reach libsodium.
    if (ik.size() != 32 || spk.size() != 32 || spkSig.size() != 64)
        return false;
    return verifyIdentitySignature(ik, spk, spkSig);
}

QByteArray CryptoBox::takeOneTimePrekey(quint32 id)
{
    auto it = m_opkPriv.find(id);
    if (it == m_opkPriv.end())
        return QByteArray();          // unknown, or already consumed
    const QByteArray priv = it.value();
    m_opkPriv.erase(it);              // SINGLE USE
    return priv;
}

// Serialised layout: magic || version || spkPriv(32) || sig(64) || nextId(4) ||
// count(4) || count * (id(4) || priv(32)). Fixed widths throughout, so a short
// or padded blob is rejected by the length check rather than misparsed.
static const char kPrekeyMagic[8] = {'C','E','2','E','P','K','E','Y'};
// v1: spk + pool. v2 adds the creation time and the retained previous prekey,
// without which a restart would forget both the rotation clock and the key that
// answers in-flight bundles.
static const quint8 kPrekeyVersionV1 = 0x01;
static const quint8 kPrekeyVersion   = 0x02;

qint64 CryptoBox::signedPrekeyAgeMs(qint64 nowMs) const
{
    if (m_spkPriv.isEmpty() || m_spkCreatedMs <= 0)
        return -1;
    return nowMs - m_spkCreatedMs;
}

bool CryptoBox::rotateSignedPrekeyIfDue(qint64 maxAgeMs, qint64 nowMs)
{
    if (!hasX3dhIdentity() || m_spkPriv.isEmpty())
        return false;
    qint64 age = signedPrekeyAgeMs(nowMs);
    if (age < 0) {
        // The stored time is in the FUTURE, so the device clock has moved
        // backwards -- a timezone fix, an NTP correction, a user changing the
        // date. Left alone this is permanent: the age stays negative and the
        // prekey never rotates again, silently turning an ephemeral key back
        // into a permanent one. Re-stamp to now and treat it as fresh; rotating
        // a little late is a far smaller problem than never rotating.
        qWarning() << "[PCS] signed prekey timestamp is in the future by"
                   << (-age) << "ms -- clock moved backwards; re-stamping";
        m_spkCreatedMs = nowMs;
        age = 0;
    }
    if (age < maxAgeMs)
        return false;

    // Rotate the signed prekey but KEEP the one-time pool. The two have
    // different lifetimes: a one-time prekey is destroyed the moment it is
    // used, while the signed prekey is used by every session until it rotates.
    // Regenerating the pool here would throw away unused keys the relay is
    // still handing out, and every peer holding one would be unable to open a
    // session at all.
    const QMap<quint32, QByteArray> keepPool = m_opkPriv;
    const quint32 keepNextId = m_nextOpkId;
    if (!generatePrekeys(0))
        return false;
    m_opkPriv   = keepPool;
    m_nextOpkId = keepNextId;

    qDebug() << "[PCS] rotated signed prekey after" << (age / 1000)
             << "s | new" << m_spkPub.toHex().left(16)
             << "| previous retained for in-flight bundles";
    return true;
}

bool CryptoBox::dropExpiredPreviousPrekey(qint64 graceMs, qint64 nowMs)
{
    if (m_prevSpkPriv.isEmpty())
        return false;
    if (nowMs - m_prevSpkRetiredMs < graceMs)
        return false;
    // Wipe rather than merely release: the whole reason to drop it is that a
    // device compromise after this point must not yield the old key, and a
    // freed buffer is readable until it is reused.
    sodium_memzero(m_prevSpkPriv.data(), m_prevSpkPriv.size());
    m_prevSpkPriv.clear();
    m_prevSpkPub.clear();
    m_prevSpkRetiredMs = 0;
    qDebug() << "[PCS] destroyed the previous signed prekey; a compromise from"
             << "here on cannot open sessions opened against it";
    return true;
}

// ===========================================================================
//  X3DH session establishment
//
//  This is where the forward-secrecy gap closes. The legacy bootstrap derived
//  the root key from DH(our identity, their identity) -- two permanent keys --
//  and made the RESPONDER's initial ratchet keypair its own identity keypair.
//  Anyone who later obtained that identity private key could recompute the
//  first DH step of every conversation and decrypt its opening run.
//
//  Under X3DH the root key comes from four Diffie-Hellmans, three of which
//  involve an ephemeral the initiator discards immediately, and the responder's
//  initial ratchet keypair is its SIGNED PREKEY: rotatable, and deletable once
//  rotated. Compromising the identity key no longer recovers anything, because
//  the identity key is only one of four contributions and never acts as a
//  ratchet key.
// ===========================================================================

bool CryptoBox::beginX3dhSession(const QString &peer, const QByteArray &peerIk,
                                 const QByteArray &peerSpk,
                                 const QByteArray &peerSpkSig,
                                 const QByteArray &peerOpk, qint32 opkId,
                                 QByteArray &ikAOut, QByteArray &ekAOut,
                                 qint32 &opkIdOut)
{
#ifdef HAVE_SODIUM
    if (!hasX3dhIdentity()) {
        qWarning() << "[X3DH] cannot initiate: identity is version"
                   << m_identityVersion;
        return false;
    }

    // The agreement itself is delegated to the X3DH module rather than repeated
    // here. That module is pinned byte for byte to the Python reference by
    // tests/x3dh_vectors.json; a second copy of the four DHs and the KDF in this
    // file would be a second thing to keep in step, and the first version of
    // this function did exactly that before it was rewritten. One
    // implementation, one set of vectors.
    X3DH::Bundle b;
    b.ik     = toBytes(peerIk);
    b.spk    = toBytes(peerSpk);
    b.spkSig = toBytes(peerSpkSig);
    if (!peerOpk.isEmpty()) { b.opk = toBytes(peerOpk); b.opkId = opkId; }

    X3DH::InitiatorResult r;
    if (!X3DH::initiator(toBytes(m_identitySeed), b, r)) {
        // initiator() verifies the signed prekey before computing anything, so
        // this also covers a bundle the relay assembled itself.
        qWarning() << "[X3DH] initiator agreement REFUSED for" << peer
                   << "-- bad bundle signature or malformed key";
        return false;
    }

    const QByteArray sk = fromBytes(r.sk);
    if (sk.size() != 32)
        return false;

    // Double Ratchet initialisation, initiator side. Structurally identical to
    // the legacy path -- fresh sending keypair, one root step -- except that DHr
    // is the peer's SIGNED PREKEY rather than their identity key.
    RatchetSession s;
    genKeypair(s.DHs_priv, s.DHs_pub);
    s.DHr_pub = peerSpk;
    s.haveDHr = true;
    kdfRk(sk, dhFn(s.DHs_priv, s.DHr_pub), s.RK, s.CKs);
    m_sessions.insert(peer, s);

    ikAOut   = fromBytes(r.ik);
    ekAOut   = fromBytes(r.ek);
    opkIdOut = peerOpk.isEmpty() ? -1 : opkId;
    qDebug() << "[X3DH] INITIATOR session for" << peer
             << "| spk" << peerSpk.toHex().left(16)
             << "| opk" << (peerOpk.isEmpty() ? "none" : "used")
             << "| sk" << sk.toHex().left(16);
    return true;
#else
    Q_UNUSED(peer); Q_UNUSED(peerIk); Q_UNUSED(peerSpk); Q_UNUSED(peerSpkSig);
    Q_UNUSED(peerOpk); Q_UNUSED(opkId);
    Q_UNUSED(ikAOut); Q_UNUSED(ekAOut); Q_UNUSED(opkIdOut);
    return false;
#endif
}

bool CryptoBox::acceptX3dhSession(const QString &peer, const QByteArray &ikA,
                                  const QByteArray &ekA, qint32 opkId,
                                  const QByteArray &spkUsed)
{
#ifdef HAVE_SODIUM
    if (!hasX3dhIdentity() || m_spkPriv.isEmpty()) {
        qWarning() << "[X3DH] cannot respond: no signing identity or no prekeys";
        return false;
    }
    // SINGLE USE. Taking the prekey here is what makes a replayed header fail:
    // the second attempt finds nothing and refuses rather than deriving the
    // same DH4 contribution into a second session.
    QByteArray opkPriv;
    if (opkId >= 0) {
        opkPriv = takeOneTimePrekey(quint32(opkId));
        if (opkPriv.isEmpty()) {
            qWarning() << "[X3DH] header from" << peer << "names one-time prekey"
                       << opkId << "which is unknown or already consumed";
            return false;
        }
    }

    // WHICH signed prekey did the initiator agree against? After a rotation we
    // hold two, and the wrong one yields a well-formed secret that simply fails
    // to decrypt -- a silent, hard-to-attribute failure. The header names it, so
    // the choice is made by matching rather than by trying.
    QByteArray useSpkPriv = m_spkPriv;
    if (!spkUsed.isEmpty()) {
        if (spkUsed == m_spkPub) {
            useSpkPriv = m_spkPriv;
        } else if (!m_prevSpkPub.isEmpty() && spkUsed == m_prevSpkPub) {
            useSpkPriv = m_prevSpkPriv;
            qDebug() << "[PCS] opener from" << peer
                     << "was built from our previous signed prekey; answering"
                     << "with the retained key";
        } else {
            qWarning() << "[X3DH] opener from" << peer
                       << "names a signed prekey we do not hold"
                       << spkUsed.toHex().left(16)
                       << "-- it has already been rotated out and destroyed";
            // Put the one-time prekey back: it was not actually consumed by a
            // session, and discarding it here would leak pool entries on every
            // stale opener.
            if (opkId >= 0 && !opkPriv.isEmpty())
                m_opkPriv.insert(quint32(opkId), opkPriv);
            return false;
        }
    }

    X3DH::Bytes skb;
    if (!X3DH::responder(toBytes(m_identitySeed), toBytes(useSpkPriv),
                         toBytes(opkPriv), toBytes(ikA), toBytes(ekA), skb)) {
        qWarning() << "[X3DH] responder agreement FAILED for" << peer;
        return false;
    }
    const QByteArray sk = fromBytes(skb);

    // Double Ratchet initialisation, responder side. The SIGNED PREKEY is our
    // initial ratchet keypair -- this is the line that closes the forward-secrecy
    // gap, because it is ephemeral where the identity key was permanent.
    RatchetSession s;
    // The ratchet keypair must be the SAME signed prekey the agreement used,
    // not necessarily the current one -- otherwise a session opened against the
    // previous prekey would ratchet from a key the initiator never saw.
    s.DHs_priv = useSpkPriv;
    s.DHs_pub  = (useSpkPriv == m_spkPriv) ? m_spkPub : m_prevSpkPub;
    s.RK = sk;
    s.haveDHr = false;
    m_sessions.insert(peer, s);

    qDebug() << "[X3DH] RESPONDER session for" << peer
             << "| opk" << (opkId >= 0 ? QString::number(opkId)
                                       : QStringLiteral("none"))
             << "| sk" << sk.toHex().left(16);
    return true;
#else
    Q_UNUSED(peer); Q_UNUSED(ikA); Q_UNUSED(ekA); Q_UNUSED(opkId);
    return false;
#endif
}

QByteArray CryptoBox::serialisePrekeys() const
{
    if (m_spkPriv.isEmpty())
        return QByteArray();
    QByteArray out;
    QDataStream ds(&out, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::BigEndian);
    ds.writeRawData(kPrekeyMagic, int(sizeof kPrekeyMagic));
    ds << quint8(kPrekeyVersion);
    ds.writeRawData(m_spkPriv.constData(), m_spkPriv.size());
    ds.writeRawData(m_spkSig.constData(), m_spkSig.size());
    ds << qint64(m_spkCreatedMs);
    ds << qint64(m_prevSpkRetiredMs);
    ds << quint32(m_prevSpkPriv.size());
    if (!m_prevSpkPriv.isEmpty()) {
        ds.writeRawData(m_prevSpkPriv.constData(), m_prevSpkPriv.size());
        ds.writeRawData(m_prevSpkPub.constData(), m_prevSpkPub.size());
    }
    ds << quint32(m_nextOpkId);
    ds << quint32(m_opkPriv.size());
    for (auto it = m_opkPriv.cbegin(); it != m_opkPriv.cend(); ++it) {
        ds << quint32(it.key());
        ds.writeRawData(it.value().constData(), it.value().size());
    }
    return out;
}

bool CryptoBox::restorePrekeys(const QByteArray &blob)
{
#ifdef HAVE_SODIUM
    if (blob.size() < int(sizeof kPrekeyMagic) + 1 + 32 + 64 + 8)
        return false;
    QDataStream ds(blob);
    ds.setByteOrder(QDataStream::BigEndian);
    char magic[sizeof kPrekeyMagic];
    if (ds.readRawData(magic, int(sizeof magic)) != int(sizeof magic)
        || memcmp(magic, kPrekeyMagic, sizeof magic) != 0)
        return false;
    quint8 ver = 0;
    ds >> ver;
    if (ver != kPrekeyVersion && ver != kPrekeyVersionV1)
        return false;

    QByteArray spkPriv(32, Qt::Uninitialized), sig(64, Qt::Uninitialized);
    if (ds.readRawData(spkPriv.data(), 32) != 32) return false;
    if (ds.readRawData(sig.data(), 64) != 64) return false;
    qint64 created = 0, retired = 0;
    QByteArray prevPriv, prevPub;
    if (ver >= kPrekeyVersion) {
        quint32 prevLen = 0;
        ds >> created >> retired >> prevLen;
        if (prevLen == 32) {
            prevPriv.resize(32); prevPub.resize(32);
            if (ds.readRawData(prevPriv.data(), 32) != 32) return false;
            if (ds.readRawData(prevPub.data(), 32) != 32) return false;
        } else if (prevLen != 0) {
            return false;
        }
    }
    quint32 nextId = 0, count = 0;
    ds >> nextId >> count;

    QMap<quint32, QByteArray> pool;
    for (quint32 i = 0; i < count; ++i) {
        quint32 id = 0;
        ds >> id;
        QByteArray priv(32, Qt::Uninitialized);
        if (ds.readRawData(priv.data(), 32) != 32) return false;
        pool.insert(id, priv);
    }
    if (ds.status() != QDataStream::Ok)
        return false;

    m_spkPriv   = spkPriv;
    m_spkSig    = sig;
    m_nextOpkId = nextId;
    m_opkPriv   = pool;
    // A v1 blob has no timestamp. Treat it as created NOW rather than at the
    // epoch: dating it 1970 would trip the age check on the next tick and
    // rotate immediately, discarding a perfectly good prekey on every upgrade.
    m_spkCreatedMs      = (ver >= kPrekeyVersion && created > 0)
                              ? created : QDateTime::currentMSecsSinceEpoch();
    m_prevSpkPriv       = prevPriv;
    m_prevSpkPub        = prevPub;
    m_prevSpkRetiredMs  = retired;
    // Recompute the signed prekey public rather than trusting a stored copy,
    // so the public can never disagree with the private it is meant to match.
    m_spkPub.resize(crypto_scalarmult_BYTES);
    crypto_scalarmult_base(
        reinterpret_cast<unsigned char *>(m_spkPub.data()),
        reinterpret_cast<const unsigned char *>(m_spkPriv.constData()));
    qDebug() << "[PREKEYS] restored signed prekey" << m_spkPub.toHex().left(16)
             << "and" << m_opkPriv.size() << "one-time prekeys";
    return true;
#else
    Q_UNUSED(blob);
    return false;
#endif
}

bool CryptoBox::loadIdentity(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    const QByteArray raw = f.readAll();
    f.close();
#ifdef HAVE_SODIUM
    // VERSION 2 plain record: magic || version || 32-byte Ed25519 seed. A bare
    // 32-byte file has no header at all and is a VERSION 1 identity written by
    // an earlier build; both must load, which is the whole point of tagging the
    // new format rather than quietly changing what 32 bytes mean.
    static const char kPlainMagic[8] = {'C','E','2','E','E','I','D','P'};
    if (raw.size() == int(sizeof kPlainMagic) + 1 + crypto_scalarmult_SCALARBYTES
        && memcmp(raw.constData(), kPlainMagic, sizeof kPlainMagic) == 0) {
        const quint8 ver = quint8(raw.at(int(sizeof kPlainMagic)));
        if (ver != 2) {
            qWarning() << "[IDENTITY] unknown plain identity version" << ver;
            return false;
        }
        m_identitySeed = raw.mid(int(sizeof kPlainMagic) + 1,
                                 crypto_scalarmult_SCALARBYTES);
        if (!deriveAgreementKeysFromSeed()) { m_identitySeed.clear(); return false; }
        m_identityVersion = 2;
        qDebug() << "[IDENTITY] loaded v2 (Ed25519) identity from" << path;
        return true;
    }

    if (raw.size() != crypto_scalarmult_SCALARBYTES)
        return false;
    // VERSION 1: a raw X25519 private key. It still works, on the legacy
    // bootstrap. It cannot be upgraded in place -- the Ed25519 -> X25519 map runs
    // one way only -- so hasX3dhIdentity() will report false and X3DH is simply
    // not attempted for this account until the user regenerates.
    m_privateKey = raw;
    m_publicKey.resize(crypto_scalarmult_BYTES);
    crypto_scalarmult_base(
        reinterpret_cast<unsigned char *>(m_publicKey.data()),
        reinterpret_cast<const unsigned char *>(m_privateKey.constData()));
    m_identitySeed.clear();
    m_edPublicKey.clear();
    m_identityVersion = 1;
    qDebug() << "[IDENTITY] loaded v1 (legacy X25519) identity from" << path
             << "-- X3DH unavailable until this identity is regenerated";
    return true;
#else
    return false;
#endif
}

bool CryptoBox::saveIdentity(const QString &path) const
{
#ifdef HAVE_SODIUM
    // A v2 identity is written with a magic and a version so it can never be
    // mistaken for the bare 32-byte v1 file, which is the same length.
    static const char kPlainMagic[8] = {'C','E','2','E','E','I','D','P'};
    QByteArray blob;
    if (m_identityVersion == 2 && !m_identitySeed.isEmpty()) {
        blob.append(kPlainMagic, int(sizeof kPlainMagic));
        blob.append(static_cast<char>(2));
        blob.append(m_identitySeed);
    } else {
        blob = m_privateKey;                 // legacy v1 layout, unchanged
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    const qint64 n = f.write(blob);
    f.flush();
    f.close();
    return n == blob.size();
#else
    Q_UNUSED(path);
    return false;
#endif
}

QString CryptoBox::publicKeyHex() const
{
    return QString::fromLatin1(m_publicKey.toHex());
}

// ===========================================================================
//  Design B: password-wrapped identity + server verifier
//
//  Two independent Argon2id derivations share the password as input but nothing
//  else, so neither can be used to attack the other:
//    * the KEY-WRAPPING key       -- derived under kWrapCtx + the wrap salt --
//      encrypts the private key at rest (crypto_secretbox).
//    * the SERVER VERIFIER        -- derived under kVerifyCtx + the verify salt
//      -- is uploaded and compared by the server; it is an Argon2id output, so
//      the password cannot be recovered from it.
//  Different salts AND different context tags guarantee independence: even the
//  same password yields two unrelated 32-byte values.
//
//  Argon2id parameters use libsodium's INTERACTIVE limits (matching the Python
//  server test): a good balance for an interactive login on a phone/desktop.
//  The on-disk wrapped-identity format is:
//      magic[8] = "CE2EEID1"
//      version  = 0x01 (1 byte)
//      salt     = crypto_pwhash_SALTBYTES (16)
//      nonce    = crypto_secretbox_NONCEBYTES (24)
//      ct       = sealed private key (32 + crypto_secretbox_MACBYTES)
// ===========================================================================
#ifdef HAVE_SODIUM
static const char  kWrapMagic[8]   = {'C','E','2','E','E','I','D','1'};
// 0x01 = the sealed payload is a raw X25519 private key (legacy accounts).
// 0x02 = the sealed payload is a 32-byte Ed25519 seed (X3DH-capable).
// Both payloads are 32 bytes, so the container layout is identical and only the
// interpretation differs -- which is exactly why the version byte has to be read
// rather than assumed.
static const quint8 kWrapVersionLegacy = 0x01;
static const quint8 kWrapVersion       = 0x02;
// Domain-separation tags folded into each Argon2id input so the wrap key and
// the verifier are independent even under an identical password + salt. They
// are prepended to the password bytes before hashing.
static const char *kWrapCtx        = "tamk-chat-idkey-wrap-v1";
static const char *kVerifyCtx      = "tamk-chat-pw-verify-v1";

// Argon2id -> 32 bytes, over (ctx || password) with the given 16-byte salt.
// Prepending the context tag domain-separates the two derivations. Returns
// false on a sodium failure (e.g. out-of-memory for the memory-hard function).
static bool argon2id32(const char *ctx,
                       const QByteArray &password,
                       const unsigned char *salt,
                       unsigned char out[32])
{
    QByteArray input(ctx);
    input.append(password);
    if (crypto_pwhash(
            out, 32,
            input.constData(), static_cast<unsigned long long>(input.size()),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(input.data(), input.size());
        return false;
    }
    sodium_memzero(input.data(), input.size());
    return true;
}
#endif

bool CryptoBox::saveIdentityEncrypted(const QString &path,
                                      const QString &password) const
{
#ifdef HAVE_SODIUM
    if (m_privateKey.size() != crypto_scalarmult_SCALARBYTES) {
        qWarning() << "[IDENTITY-ENC] refusing to save: no identity loaded";
        return false;
    }
    const QByteArray pw = password.toUtf8();

    // Fresh random salt for the wrapping derivation.
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);

    // Derive the wrapping key.
    unsigned char wrapKey[crypto_secretbox_KEYBYTES];
    if (!argon2id32(kWrapCtx, pw, salt, wrapKey)) {
        qWarning() << "[IDENTITY-ENC] Argon2id (wrap) failed";
        return false;
    }

    // Seal the private key.
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    QByteArray ct(m_privateKey.size() + crypto_secretbox_MACBYTES,
                  Qt::Uninitialized);
    // Seal the SEED for a v2 identity -- it is the only secret, and the X25519
    // key can always be re-derived from it. A v1 identity has no seed, so its
    // raw private key is sealed exactly as before.
    const QByteArray &secret =
        (m_identityVersion == 2 && !m_identitySeed.isEmpty()) ? m_identitySeed
                                                              : m_privateKey;
    crypto_secretbox_easy(
        reinterpret_cast<unsigned char *>(ct.data()),
        reinterpret_cast<const unsigned char *>(secret.constData()),
        secret.size(), nonce, wrapKey);
    sodium_memzero(wrapKey, sizeof wrapKey);

    // Assemble [magic|version|salt|nonce|ct] and write it.
    QByteArray blob;
    blob.append(kWrapMagic, sizeof kWrapMagic);
    blob.append(static_cast<char>(
        (m_identityVersion == 2 && !m_identitySeed.isEmpty())
            ? kWrapVersion : kWrapVersionLegacy));
    blob.append(reinterpret_cast<const char *>(salt), sizeof salt);
    blob.append(reinterpret_cast<const char *>(nonce), sizeof nonce);
    blob.append(ct);

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "[IDENTITY-ENC] open FAILED for" << path
                   << "error:" << f.errorString();
        return false;
    }
    const qint64 n = f.write(blob);
    f.flush();
    f.close();
    qDebug() << "[IDENTITY-ENC] wrote" << n << "bytes (encrypted identity) to"
             << path;
    return n == blob.size();
#else
    Q_UNUSED(path); Q_UNUSED(password);
    return false;
#endif
}

bool CryptoBox::loadIdentityEncrypted(const QString &path,
                                      const QString &password)
{
#ifdef HAVE_SODIUM
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    const QByteArray blob = f.readAll();
    f.close();

    // Validate the fixed-size header.
    const int headerLen = static_cast<int>(sizeof kWrapMagic) + 1
                          + crypto_pwhash_SALTBYTES
                          + crypto_secretbox_NONCEBYTES;
    const int minCt = crypto_scalarmult_SCALARBYTES + crypto_secretbox_MACBYTES;
    if (blob.size() < headerLen + minCt)
        return false;
    if (memcmp(blob.constData(), kWrapMagic, sizeof kWrapMagic) != 0)
        return false;
    const quint8 version =
        static_cast<quint8>(blob.at(static_cast<int>(sizeof kWrapMagic)));
    if (version != kWrapVersion && version != kWrapVersionLegacy)
        return false;

    int off = static_cast<int>(sizeof kWrapMagic) + 1;
    const unsigned char *salt =
        reinterpret_cast<const unsigned char *>(blob.constData() + off);
    off += crypto_pwhash_SALTBYTES;
    const unsigned char *nonce =
        reinterpret_cast<const unsigned char *>(blob.constData() + off);
    off += crypto_secretbox_NONCEBYTES;
    const QByteArray ct = blob.mid(off);

    // Re-derive the wrapping key and open the box. A wrong password fails here.
    const QByteArray pw = password.toUtf8();
    unsigned char wrapKey[crypto_secretbox_KEYBYTES];
    if (!argon2id32(kWrapCtx, pw, salt, wrapKey)) {
        qWarning() << "[IDENTITY-ENC] Argon2id (wrap) failed on load";
        return false;
    }
    QByteArray priv(crypto_scalarmult_SCALARBYTES, Qt::Uninitialized);
    const int rc = crypto_secretbox_open_easy(
        reinterpret_cast<unsigned char *>(priv.data()),
        reinterpret_cast<const unsigned char *>(ct.constData()),
        ct.size(), nonce, wrapKey);
    sodium_memzero(wrapKey, sizeof wrapKey);
    if (rc != 0) {
        // Wrong password (or a tampered file): the MAC did not verify. Load
        // nothing and report failure -- the identity key is NOT recoverable
        // without the correct password, which is the whole point of Design B.
        sodium_memzero(priv.data(), priv.size());
        qDebug() << "[IDENTITY-ENC] open failed (wrong password or tampered)";
        return false;
    }

    // Interpret the sealed 32 bytes according to the version byte. Version 2 is
    // an Ed25519 seed, from which the X25519 pair below is derived; version 1 is
    // that X25519 private key directly.
    if (version == kWrapVersion) {
        m_identitySeed = priv;
        if (!deriveAgreementKeysFromSeed()) {
            sodium_memzero(m_identitySeed.data(), m_identitySeed.size());
            m_identitySeed.clear();
            return false;
        }
        m_identityVersion = 2;
        qDebug() << "[IDENTITY-ENC] loaded v2 (Ed25519) identity"
                 << "| ed pub" << m_edPublicKey.toHex().left(16);
        return true;
    }

    m_identitySeed.clear();
    m_edPublicKey.clear();
    m_identityVersion = 1;
    qDebug() << "[IDENTITY-ENC] loaded v1 (legacy X25519) identity"
             << "-- X3DH unavailable until this identity is regenerated";
    m_privateKey = priv;
    m_publicKey.resize(crypto_scalarmult_BYTES);
    crypto_scalarmult_base(
        reinterpret_cast<unsigned char *>(m_publicKey.data()),
        reinterpret_cast<const unsigned char *>(m_privateKey.constData()));
    qDebug() << "[IDENTITY-ENC] identity unlocked, public ="
             << m_publicKey.toHex().left(16) << "...";
    return true;
#else
    Q_UNUSED(path); Q_UNUSED(password);
    return false;
#endif
}

bool CryptoBox::isEncryptedIdentityFile(const QString &path)
{
#ifdef HAVE_SODIUM
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    QByteArray head = f.read(static_cast<int>(sizeof kWrapMagic) + 1);
    f.close();
    if (head.size() < static_cast<int>(sizeof kWrapMagic) + 1)
        return false;
    if (memcmp(head.constData(), kWrapMagic, sizeof kWrapMagic) != 0)
        return false;
    return static_cast<quint8>(head.at(static_cast<int>(sizeof kWrapMagic)))
           == kWrapVersion;
#else
    Q_UNUSED(path);
    return false;
#endif
}

bool CryptoBox::deriveVerifier(const QString &password,
                               QString &verifierHexOut, QString &saltHexOut)
{
#ifdef HAVE_SODIUM
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);
    unsigned char verifier[32];
    if (!argon2id32(kVerifyCtx, password.toUtf8(), salt, verifier))
        return false;
    verifierHexOut = QString::fromLatin1(
        QByteArray(reinterpret_cast<const char *>(verifier), 32).toHex());
    saltHexOut = QString::fromLatin1(
        QByteArray(reinterpret_cast<const char *>(salt), sizeof salt).toHex());
    sodium_memzero(verifier, sizeof verifier);
    return true;
#else
    Q_UNUSED(password); Q_UNUSED(verifierHexOut); Q_UNUSED(saltHexOut);
    return false;
#endif
}

QString CryptoBox::deriveVerifierWithSalt(const QString &password,
                                          const QString &saltHex)
{
#ifdef HAVE_SODIUM
    const QByteArray salt = QByteArray::fromHex(saltHex.toLatin1());
    if (salt.size() != crypto_pwhash_SALTBYTES)
        return QString();
    unsigned char verifier[32];
    if (!argon2id32(kVerifyCtx, password.toUtf8(),
                    reinterpret_cast<const unsigned char *>(salt.constData()),
                    verifier))
        return QString();
    QString out = QString::fromLatin1(
        QByteArray(reinterpret_cast<const char *>(verifier), 32).toHex());
    sodium_memzero(verifier, sizeof verifier);
    return out;
#else
    Q_UNUSED(password); Q_UNUSED(saltHex);
    return QString();
#endif
}

// ============================================================================
//  Ratchet session bootstrap
// ============================================================================
bool CryptoBox::ensureSharedKey(const QString &peerName, const QString &peerPubHex)
{
    const QByteArray pub = QByteArray::fromHex(peerPubHex.toLatin1());
#ifdef HAVE_SODIUM
    if (pub.size() != crypto_scalarmult_BYTES) {
        qWarning() << "[CRYPTO] ensureSharedKey: bad peer key for" << peerName;
        return false;
    }
#else
    if (pub.size() != 32)
        return false;
#endif

    // Key-change resilience: detect whether this peer's identity key CHANGED
    // from what we previously recorded. If it did, any existing ratchet session
    // was bootstrapped from the OLD key and can no longer agree with the peer --
    // leaving it in place makes the safety number (new key) and the session
    // (old key) disagree, so every decrypt fails silently. We drop the stale
    // session so sessionFor() rebuilds a fresh one from the new key, and return
    // true so the caller can also clear the PERSISTED session.
    const auto existingIdIt = m_peerIdentity.find(peerName);
    const bool hadKey = (existingIdIt != m_peerIdentity.end());
    const bool keyChanged = hadKey && (existingIdIt.value() != pub);

    m_peerIdentity.insert(peerName, pub);  // remember (new) identity key

    if (keyChanged) {
        if (m_sessions.remove(peerName) > 0) {
            qWarning() << "[CRYPTO] peer" << peerName
                       << "identity key changed; stale ratchet session dropped."
                       << "Messaging re-establishes on the next message;"
                       << "in-flight messages under the old key are unrecoverable.";
        }
        return true;   // signal the change to the caller
    }
    return false;      // unchanged, or first time seeing this peer: no reset
}

// True if we currently hold a ratchet session for this peer (possibly stale
// until the next message rebuilds it). Lets the caller/UI reason about state.
bool CryptoBox::hasSessionFor(const QString &peerName) const
{
    return m_sessions.contains(peerName);
}

// Discard the in-memory ratchet session for a peer, if any, so the next
// encrypt/decrypt re-bootstraps a fresh chain from the peer's CURRENT identity
// key. Used by the confirm-safety-number path: ensureSharedKey has already
// recorded the new identity and dropped the stale session at the moment the key
// changed, but this gives the client an explicit, intention-revealing call to
// guarantee a clean bootstrap at confirm time regardless of how we got here
// (e.g. if a session was somehow re-created in between). m_peerIdentity is left
// untouched, so the fresh bootstrap uses the new key. Returns whether a session
// was actually removed.
bool CryptoBox::dropSession(const QString &peerName)
{
    return m_sessions.remove(peerName) > 0;
}

// Wipe every scrap of in-memory cryptographic state so a different user can log
// in on the same CryptoBox instance without inheriting the previous user's
// sessions or identity. See the header for the full rationale (the "conversations
// fail after switching users" bug: a session bootstrapped from user A's private
// key cannot decrypt anything once user B is logged in, because the bootstrap
// secret X25519(privkey, peerPub) no longer matches). We clear the ratchet
// sessions, the peer-identity map, and our own keypair. Nothing on disk is
// touched -- switching back restores the previous user's sessions through the
// normal login path -- and login() reloads/regenerates the identity right after
// this runs, so an empty keypair here is transient and safe.
void CryptoBox::resetForNewUser()
{
    m_sessions.clear();
    m_peerIdentity.clear();
    m_privateKey.clear();
    m_publicKey.clear();
    qDebug() << "[CRYPTO] resetForNewUser: cleared all in-memory sessions, peer "
                "identities, and identity keypair.";
}

// Record a peer identity key with no side effects (see the header). Used by the
// restore path to seed m_peerIdentity before importSession validates the stamp.
bool CryptoBox::setPeerIdentity(const QString &peerName, const QString &peerPubHex)
{
    const QByteArray pub = QByteArray::fromHex(peerPubHex.toLatin1());
#ifdef HAVE_SODIUM
    if (pub.size() != crypto_scalarmult_BYTES)
        return false;
#else
    if (pub.size() != 32)
        return false;
#endif
    m_peerIdentity.insert(peerName, pub);
    return true;
}

// The identity key (hex) we currently hold for a peer, or empty if none.
QString CryptoBox::peerIdentityHex(const QString &peerName) const
{
    const auto it = m_peerIdentity.find(peerName);
    if (it == m_peerIdentity.end())
        return QString();
    return QString::fromLatin1(it.value().toHex());
}

QByteArray CryptoBox::sharedSecretWith(const QString &peerPubHex) const
{
    const QByteArray pub = QByteArray::fromHex(peerPubHex.toLatin1());
#ifdef HAVE_SODIUM
    if (m_privateKey.isEmpty() || pub.size() != crypto_scalarmult_BYTES)
        return {};
    return bootstrapSk(m_privateKey, pub);
#else
    Q_UNUSED(pub);
    return {};
#endif
}

RatchetSession *CryptoBox::sessionFor(const QString &peerName, bool *ok)
{
    if (ok) *ok = false;
    auto existing = m_sessions.find(peerName);
    if (existing != m_sessions.end()) {
        if (ok) *ok = true;
        return &existing.value();
    }
#ifdef HAVE_SODIUM
    auto idIt = m_peerIdentity.find(peerName);
    if (idIt == m_peerIdentity.end() || m_privateKey.isEmpty())
        return nullptr;  // need the peer's identity key (call ensureSharedKey)
    const QByteArray peerPub = idIt.value();
    const QByteArray sk = bootstrapSk(m_privateKey, peerPub);

    // DETERMINISTIC ROLE (the fix for two-initiators divergence). The bootstrap
    // role is NOT chosen from whether this side is sending or receiving -- that
    // made two peers who both send first (e.g. both confirm a changed safety
    // number, each auto-initiating a handshake) BOTH become initiator, so
    // neither could decrypt the other's opening frame and the conversation
    // silently died. Instead both sides compare the two identity public keys and
    // agree, with no coordination, that the numerically smaller key is the
    // initiator (Alice) and the larger is the responder (Bob). Because the
    // comparison is over the same two keys on both ends, exactly one side is
    // Alice and one is Bob, every time.
    const bool amInitiator =
        (memcmp(m_publicKey.constData(), peerPub.constData(),
                crypto_scalarmult_BYTES) < 0);

    // DIAGNOSTIC (temporary): the bootstrap shared secret and the identity keys
    // it was derived from. sk MUST be identical on both sides (it is a plain
    // X25519 agreement of the two identity keys). If the two peers print
    // different sk, the identity-key exchange is the bug -- the peerPub one side
    // holds does not match the other side's actual public key. The role is now
    // derived from the key comparison, so the two ends MUST print opposite roles.
    qDebug() << "[BOOTSTRAP] role" << (amInitiator ? "INIT" : "RESP")
             << "peer" << peerName
             << "myPub" << m_publicKey.toHex().left(16)
             << "peerPub" << peerPub.toHex().left(16)
             << "sk" << sk.toHex().left(16);

    RatchetSession s;
    if (amInitiator) {
        // Alice: fresh sending keypair; peer identity key is the initial DHr;
        // RK/CKs from the first root step. Alice can send immediately.
        genKeypair(s.DHs_priv, s.DHs_pub);
        s.DHr_pub = peerPub;
        s.haveDHr = true;
        kdfRk(sk, dhFn(s.DHs_priv, s.DHr_pub), s.RK, s.CKs);
    } else {
        // Bob: bootstrap on our own identity keypair; root key = SK; the first
        // inbound message's header supplies DHr and triggers the DH ratchet.
        // NOTE: Bob has NO sending chain (CKs is empty) until that first DH
        // ratchet fires, so encryptFor() must detect a Bob session with empty
        // CKs and report "not ready to send" rather than derive from an empty
        // chain -- see encryptFor()'s responder-not-ready guard.
        s.DHs_priv = m_privateKey;
        s.DHs_pub = m_publicKey;
        s.RK = sk;
        s.haveDHr = false;
    }
    auto inserted = m_sessions.insert(peerName, s);
    if (ok) *ok = true;
    return &inserted.value();
#else
    return nullptr;
#endif
}

// True if WE are the deterministic initiator for this peer: our identity public
// key sorts before the peer's. Mirrors the comparison in sessionFor() exactly,
// so the client's "should I transmit the re-bootstrap handshake?" decision and
// the actual bootstrap role can never disagree. Returns false if we do not yet
// hold the peer's identity key (nothing to compare) -- treat as "cannot initiate
// yet". Also returns false in a no-sodium build.
bool CryptoBox::amInitiatorFor(const QString &peerName) const
{
#ifdef HAVE_SODIUM
    const auto it = m_peerIdentity.find(peerName);
    if (it == m_peerIdentity.end() || m_privateKey.isEmpty()) {
        // DIAGNOSTIC (temporary, user-switch investigation): we cannot decide a
        // role because we hold no identity for this peer yet. This is the crux
        // of the new-peer-after-switch case: if this prints, the caller does not
        // yet know the peer's key, so no handshake can be initiated toward them.
        qDebug() << "[ROLE] amInitiatorFor(" << peerName
                 << ") -> UNKNOWN (no peer identity held yet; havePriv="
                 << !m_privateKey.isEmpty() << ")";
        return false;
    }
    const bool init =
        memcmp(m_publicKey.constData(), it.value().constData(),
               crypto_scalarmult_BYTES) < 0;
    // DIAGNOSTIC (temporary, user-switch investigation): the exact role and the
    // two keys that decided it. Compare this line ACROSS the two devices for the
    // same peer pairing: they MUST print opposite roles (one INIT, one RESP). If
    // both print the same role, the role comparison is using mismatched keys --
    // e.g. one side holds a stale identity for the other -- which is exactly the
    // "nobody opens the channel" stall after a user switch.
    qDebug() << "[ROLE] amInitiatorFor(" << peerName << ") ->"
             << (init ? "INITIATOR" : "RESPONDER")
             << "| myPub" << m_publicKey.toHex().left(16)
             << "| peerPub" << it.value().toHex().left(16);
    return init;
#else
    Q_UNUSED(peerName);
    return false;
#endif
}

// ============================================================================
//  Encrypt / decrypt (ratchet)
// ============================================================================
bool CryptoBox::encryptFor(const QString &peerName, const QString &plaintext,
                           QString &cipherOut, QString &dhHexOut,
                           quint32 &pnOut, quint32 &nOut,
                           QString &nonceHexOut, QString &ctHexOut,
                           bool *notReady)
{
    if (notReady) *notReady = false;
#ifdef HAVE_SODIUM
    bool ok = false;
    RatchetSession *s = sessionFor(peerName, &ok);
    if (!ok || !s)
        return false;

    // RESPONDER-NOT-READY guard (deterministic-role fix). With roles fixed by
    // identity-key comparison, this side may be the responder (Bob), whose
    // sending chain (CKs) does not exist until the initiator's first frame
    // triggers a DH ratchet. Deriving a message key from an empty CKs would
    // produce an unusable frame the peer can never decrypt -- the very kind of
    // silent divergence this whole change exists to prevent. So if there is no
    // sending chain yet, do NOT encrypt: report "not ready" so the caller queues
    // the plaintext and retries once the initiator's opening frame has arrived
    // (at which point dhRatchet has populated CKs and sending works normally).
    if (s->CKs.isEmpty()) {
        if (notReady) *notReady = true;
        return false;
    }

    // Per-message cipher selection: AES-256-GCM where hardware AES is reported,
    // XChaCha20-Poly1305 otherwise.
    // CIPHER PINNING (cross-platform fix): choose XChaCha20-Poly1305
    // UNCONDITIONALLY, not based on this machine's hardware AES support.
    // Previously this picked AES-256-GCM when the local CPU offered it and
    // XChaCha20 otherwise -- so a desktop without hardware AES used XChaCha20
    // while an Android device WITH hardware AES used AES-GCM, and neither could
    // decrypt the other's frames (the two ends disagreed on the algorithm).
    // XChaCha20-Poly1305 is provided in software by libsodium on every platform,
    // needs no hardware support, and both ends can always agree on it.
    const QByteArray cipher = QByteArray(kCipherXchacha);

    QByteArray ckNext, mk;
    kdfCk(s->CKs, ckNext, mk);
    s->CKs = ckNext;

    const quint32 pn = s->PN, n = s->Ns;
    // DIAGNOSTIC (temporary): sender's cipher + message-key for this frame.
    // Compare against the receiver's [MK-RX] for the same n -- if the keys match
    // but decrypt fails, it is an AEAD/cipher/AD mismatch; if the keys differ,
    // it is a key-derivation/session mismatch.
    qDebug() << "[MK-TX] n" << n << "cipher" << cipher
             << "mk" << mk.toHex().left(16)
             << "DHs_pub" << s->DHs_pub.toHex().left(16)
             << "aesAvail" << (crypto_aead_aes256gcm_is_available() ? 1 : 0);
    QByteArray nonce(int(nonceLenFor(cipher)), Qt::Uninitialized);
    randombytes_buf(nonce.data(), nonce.size());
    const QByteArray ad = adBytes(cipher, s->DHs_pub, pn, n);
    const QByteArray ct = aeadEncrypt(cipher, mk, nonce, plaintext.toUtf8(), ad);
    ++s->Ns;

    cipherOut = QString::fromLatin1(cipher);
    dhHexOut = QString::fromLatin1(s->DHs_pub.toHex());
    pnOut = pn;
    nOut = n;
    nonceHexOut = QString::fromLatin1(nonce.toHex());
    ctHexOut = QString::fromLatin1(ct.toHex());
    sodium_memzero(mk.data(), mk.size());
    return true;
#else
    Q_UNUSED(peerName); Q_UNUSED(plaintext);
    Q_UNUSED(cipherOut); Q_UNUSED(dhHexOut); Q_UNUSED(pnOut);
    Q_UNUSED(nOut); Q_UNUSED(nonceHexOut); Q_UNUSED(ctHexOut);
    return false;
#endif
}

QString CryptoBox::decryptFrom(const QString &peerName, const QString &cipher,
                               const QString &dhHex, quint32 pn, quint32 n,
                               const QString &nonceHex, const QString &ctHex)
{
#ifdef HAVE_SODIUM
    bool ok = false;
    RatchetSession *s = sessionFor(peerName, &ok);
    if (!ok || !s) {
        emit decryptionFailed(peerName);
        return {};
    }
    const QByteArray cb = cipher.toLatin1();
    const QByteArray dhPub = QByteArray::fromHex(dhHex.toLatin1());
    const QByteArray nonce = QByteArray::fromHex(nonceHex.toLatin1());
    const QByteArray ct = QByteArray::fromHex(ctHex.toLatin1());
    const QByteArray ad = adBytes(cb, dhPub, pn, n);

    // 1) A skipped (out-of-order) message we already banked the key for.
    //    This path is already non-destructive to the CHAIN state: it consumes
    //    a stored key and, only on success, erases exactly that entry. A failed
    //    authentication here leaves the session completely untouched.
    const QByteArray sk = skipKey(dhPub, n);
    auto skIt = s->skipped.find(sk);
    if (skIt != s->skipped.end()) {
        QByteArray mk = skIt.value();
        QByteArray pt;
        const bool good = aeadDecrypt(cb, mk, nonce, ct, ad, pt);
        sodium_memzero(mk.data(), mk.size());
        if (!good) { emit decryptionFailed(peerName); return {}; }
        s->skipped.erase(skIt);
        return QString::fromUtf8(pt);
    }

    // ------------------------------------------------------------------------
    // NON-DESTRUCTIVE RATCHET STEP (the fix for out-of-order / replayed frames)
    //
    // The steps below (skip the tail of the old chain, perform a DH ratchet,
    // advance the receiving chain, derive the message key) MUTATE the session:
    // they step the root key, replace our sending keypair, reset counters and
    // bank skipped keys. Previously they were applied DIRECTLY to *s BEFORE the
    // AEAD tag was checked -- so a single stale or replayed frame that failed to
    // authenticate had ALREADY rewritten the live session, and every genuine
    // frame that followed then derived keys from a corrupted chain and failed
    // too. With the server replaying a backlog after reconnect (many old frames,
    // out of order, from earlier ratchet generations) this turned one bad frame
    // into a permanently dead conversation -- exactly the "files work, text does
    // not" symptom, since files never touch this chain state.
    //
    // The fix is transactional: run the whole step on a COPY of the session,
    // authenticate the ciphertext with the copy's message key, and only if it
    // authenticates do we commit the copy back over *s. A frame that fails to
    // decrypt (a duplicate the client-side dedup missed, a frame from a
    // generation we have already moved past, or an outright forgery) now leaves
    // the real session byte-for-byte unchanged, so later good frames still
    // decrypt. RatchetSession is a plain value type (QByteArrays + a QHash), so
    // copying and assigning it is a correct deep copy.
    // ------------------------------------------------------------------------
    RatchetSession work = *s;   // transactional working copy

    // 2) A new peer ratchet key => skip the tail of the old chain, then ratchet.
    if (!work.haveDHr || dhPub != work.DHr_pub) {
        if (!skipTo(work, pn)) { emit decryptionFailed(peerName); return {}; }
        dhRatchet(work, dhPub);
    }

    // 3) Advance to this message's index within the current receiving chain.
    if (!skipTo(work, n)) { emit decryptionFailed(peerName); return {}; }

    QByteArray ckNext, mk;
    kdfCk(work.CKr, ckNext, mk);
    work.CKr = ckNext;
    ++work.Nr;

    // DIAGNOSTIC (temporary): receiver's cipher + message-key for this frame.
    qDebug() << "[MK-RX] n" << n << "cipher" << cb
             << "mk" << mk.toHex().left(16)
             << "hdrDH" << dhPub.toHex().left(16)
             << "aesAvail" << (crypto_aead_aes256gcm_is_available() ? 1 : 0);

    QByteArray pt;
    const bool good = aeadDecrypt(cb, mk, nonce, ct, ad, pt);
    sodium_memzero(mk.data(), mk.size());
    if (!good) {
        // Authentication failed: DISCARD the working copy so the live session
        // is left untouched, and report the failure. This is what makes stray
        // and replayed frames harmless instead of session-destroying.
        emit decryptionFailed(peerName);
        return {};
    }

    // Authenticated: commit the advanced state back to the live session.
    *s = work;
    return QString::fromUtf8(pt);
#else
    Q_UNUSED(peerName); Q_UNUSED(cipher); Q_UNUSED(dhHex);
    Q_UNUSED(pn); Q_UNUSED(n); Q_UNUSED(nonceHex); Q_UNUSED(ctHex);
    emit decryptionFailed(peerName);
    return {};
#endif
}

// ============================================================================
//  Safety number  (unchanged: SHA-256 of the two sorted identity keys ->
//  six groups of five decimal digits)
// ============================================================================
QString CryptoBox::safetyNumber(const QString &pubKeyHexA,
                                const QString &pubKeyHexB)
{
    QByteArray a = QByteArray::fromHex(pubKeyHexA.toLatin1());
    QByteArray b = QByteArray::fromHex(pubKeyHexB.toLatin1());
    if (a.size() != 32 || b.size() != 32)
        return QString();

    // Sort so both sides derive the identical value.
    if (memcmp(a.constData(), b.constData(), 32) > 0)
        a.swap(b);

    QByteArray both = a + b;
    const QByteArray digest =
        QCryptographicHash::hash(both, QCryptographicHash::Sha256);

    QStringList groups;
    for (int g = 0; g < 6; ++g) {
        quint32 v = (static_cast<quint8>(digest[g * 4]) << 24) |
                    (static_cast<quint8>(digest[g * 4 + 1]) << 16) |
                    (static_cast<quint8>(digest[g * 4 + 2]) << 8) |
                    (static_cast<quint8>(digest[g * 4 + 3]));
        v %= 100000u;
        groups << QString::number(v).rightJustified(5, QLatin1Char('0'));
    }
    return groups.join(QLatin1Char(' '));
}

// ============================================================================
//  Local-history sealing (static key) + ratchet session (de)serialization
// ============================================================================
bool CryptoBox::localSeal(const QString &plaintext,
                          QString &nonceHexOut, QString &ctHexOut) const
{
#ifdef HAVE_SODIUM
    if (m_privateKey.isEmpty())
        return false;
    unsigned char lk[32];
    hkdf(nullptr, 0,
         reinterpret_cast<const unsigned char *>(m_privateKey.constData()),
         m_privateKey.size(),
         reinterpret_cast<const unsigned char *>(kLocalInfo), strlen(kLocalInfo),
         lk, sizeof lk);
    const QByteArray pt = plaintext.toUtf8();
    QByteArray nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, Qt::Uninitialized);
    randombytes_buf(nonce.data(), nonce.size());
    QByteArray ct(pt.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES,
                  Qt::Uninitialized);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char *>(ct.data()), &clen,
        reinterpret_cast<const unsigned char *>(pt.constData()), pt.size(),
        nullptr, 0, nullptr,
        reinterpret_cast<const unsigned char *>(nonce.constData()), lk);
    ct.resize(int(clen));
    sodium_memzero(lk, sizeof lk);
    nonceHexOut = QString::fromLatin1(nonce.toHex());
    ctHexOut = QString::fromLatin1(ct.toHex());
    return true;
#else
    Q_UNUSED(plaintext); Q_UNUSED(nonceHexOut); Q_UNUSED(ctHexOut);
    return false;
#endif
}

QString CryptoBox::localOpen(const QString &nonceHex, const QString &ctHex) const
{
#ifdef HAVE_SODIUM
    if (m_privateKey.isEmpty())
        return {};
    unsigned char lk[32];
    hkdf(nullptr, 0,
         reinterpret_cast<const unsigned char *>(m_privateKey.constData()),
         m_privateKey.size(),
         reinterpret_cast<const unsigned char *>(kLocalInfo), strlen(kLocalInfo),
         lk, sizeof lk);
    const QByteArray nonce = QByteArray::fromHex(nonceHex.toLatin1());
    const QByteArray ct = QByteArray::fromHex(ctHex.toLatin1());
    QByteArray pt(ct.size(), Qt::Uninitialized);
    unsigned long long plen = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char *>(pt.data()), &plen, nullptr,
        reinterpret_cast<const unsigned char *>(ct.constData()), ct.size(),
        nullptr, 0,
        reinterpret_cast<const unsigned char *>(nonce.constData()), lk);
    sodium_memzero(lk, sizeof lk);
    if (rc != 0)
        return {};
    pt.resize(int(plen));
    return QString::fromUtf8(pt);
#else
    Q_UNUSED(nonceHex); Q_UNUSED(ctHex);
    return {};
#endif
}

QByteArray CryptoBox::exportSession(const QString &peerName) const
{
    auto it = m_sessions.find(peerName);
    if (it == m_sessions.end())
        return {};
    const RatchetSession &s = it.value();

    // Identity stamp: the exact (my identity public key, peer identity public
    // key) pair this session was bootstrapped from. It is written into the blob
    // so that importSession() can REFUSE to restore a session whose binding no
    // longer matches the current identities -- e.g. after either side reset or
    // regenerated its identity key. Without this, a restart reloads a session
    // from SQLite into m_sessions, sessionFor() then sees an existing entry and
    // never re-bootstraps (so [BOOTSTRAP] never prints), and the first frame is
    // encrypted/decrypted against a chain the peer is not on -- the "no new
    // session after restart, first message fails" symptom. The peer identity may
    // be absent (empty) if we never recorded it; that is fine, it just means the
    // stamp cannot match on import and a clean re-bootstrap is forced.
    const QByteArray peerId = m_peerIdentity.value(peerName);

    QByteArray blob;
    QDataStream ds(&blob, QIODevice::WriteOnly);
    ds.setVersion(QDataStream::Qt_6_0);
    ds << quint8(2);  // format version (2 adds the identity stamp)
    ds << m_publicKey << peerId;   // identity stamp: (mine, peer's)
    ds << s.DHs_priv << s.DHs_pub << s.DHr_pub << s.RK << s.CKs << s.CKr;
    ds << s.Ns << s.Nr << s.PN << s.haveDHr;
    ds << quint32(s.skipped.size());
    for (auto i = s.skipped.cbegin(); i != s.skipped.cend(); ++i)
        ds << i.key() << i.value();
    return blob;
}

bool CryptoBox::importSession(const QString &peerName, const QByteArray &blob)
{
    if (blob.isEmpty())
        return false;
    QDataStream ds(blob);
    ds.setVersion(QDataStream::Qt_6_0);
    quint8 ver = 0;
    ds >> ver;

    // Only version 2 (identity-stamped) blobs are accepted. A version-1 blob
    // from before this fix has no stamp and cannot be validated, so we reject
    // it: the session is dropped, sessionFor() re-bootstraps cleanly on the next
    // message, and [BOOTSTRAP] prints again. This means the FIRST run after this
    // update discards any previously stored sessions once -- which is exactly
    // the healthy behaviour, since those old sessions are the stale ones causing
    // the restart failure. From then on, stamped sessions round-trip normally.
    if (ver != 2)
        return false;

    QByteArray stampMine, stampPeer;
    ds >> stampMine >> stampPeer;

    RatchetSession s;
    ds >> s.DHs_priv >> s.DHs_pub >> s.DHr_pub >> s.RK >> s.CKs >> s.CKr;
    ds >> s.Ns >> s.Nr >> s.PN >> s.haveDHr;
    quint32 nskip = 0;
    ds >> nskip;
    for (quint32 i = 0; i < nskip; ++i) {
        QByteArray k, v;
        ds >> k >> v;
        s.skipped.insert(k, v);
    }
    if (ds.status() != QDataStream::Ok)
        return false;

    // VALIDATE THE STAMP against the identities in force right now. The stored
    // "mine" must equal our current public key, and the stored "peer" must equal
    // the peer identity we currently hold (recorded via ensureSharedKey). If
    // either differs -- an identity was regenerated, or we do not yet hold the
    // peer's key -- the session is stale/unbindable: reject it so a fresh one is
    // bootstrapped from the current keys instead of resurrecting a dead chain.
    const QByteArray curPeerId = m_peerIdentity.value(peerName);
    if (stampMine != m_publicKey)
        return false;
    if (curPeerId.isEmpty() || stampPeer != curPeerId)
        return false;

    m_sessions.insert(peerName, s);
    return true;
}

// ============================================================================
//  BUILD-AND-TEST CHECKLIST (because this file has not been compiled here)
// ----------------------------------------------------------------------------
//  1. Compile with HAVE_SODIUM defined and libsodium linked (see CMake note).
//  2. Confirm <QStringList> is available (pulled in via <QString> on Qt 6, but
//     add #include <QStringList> if your build complains in safetyNumber()).
//  3. First-message sanity: have the desktop talk to itself (two identities),
//     send and receive, and confirm round-trips for both ciphers. The desktop
//     probe is 0, so it will send XChaCha20; force-test AES by running against
//     a build/host where the probe is 1, or temporarily hard-code the tag.
//  4. Cross-check against the reference: a frame produced by ratchet_cli.cpp /
//     crypto_core.py must decrypt here and vice versa (the live harness already
//     proves the reference interoperates; this port must join that matrix).
//  5. AES-GCM is UNDEFINED to call when the probe is 0 -- never force the AES
//     path on a build whose probe returns 0.
//  6. Session lifetime: m_sessions lives in memory only. Without the
//     historystore 'sessions' table (separate change), sessions reset on
//     restart and in-flight conversations will fail to decrypt afterwards.
// ============================================================================
