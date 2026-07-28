#ifndef CRYPTOBOX_H
#define CRYPTOBOX_H

// ============================================================================
//  cryptobox.h  --  end-to-end encryption for the client, now with a ratchet.
//
//  STATUS: ported faithfully from the VERIFIED reference code
//          (server/crypto_core.py and tests/ratchet_cli.cpp, both run and
//          tested) but NOT YET COMPILED against the Qt 6 toolchain / Android
//          NDK. Treat as a draft to build and test on the real toolchain
//          before use. The cryptographic logic mirrors the reference
//          byte-for-byte; the Qt plumbing needs your compiler's confirmation.
//
//  CryptoBox wraps the encryption primitives. It mirrors server/crypto_core.py:
//  a long-term X25519 identity per user, an X25519 + HKDF-SHA256 Route A
//  bootstrap, then a Double Ratchet giving forward secrecy and post-compromise
//  security. The message AEAD is hybrid and chosen per message: AES-256-GCM
//  where libsodium reports hardware AES (crypto_aead_aes256gcm_is_available()
//  == 1), XChaCha20-Poly1305 otherwise -- so the Windows/MinGW desktop, whose
//  probe returns 0, transparently uses XChaCha20 while a phone uses AES-GCM,
//  and the per-message cipher tag lets the two interoperate.
//
//  All heavy lifting is libsodium. The private key never leaves this class.
// ============================================================================

#include <QByteArray>
#include <QMap>
#include <QHash>
#include <QObject>
#include <QString>

// Per-peer Double Ratchet session state. Field names follow the Signal
// Double Ratchet specification so the two can be read side by side.
struct RatchetSession {
    QByteArray DHs_priv, DHs_pub;            // our current ratchet keypair
    QByteArray DHr_pub;                      // peer's latest ratchet public key
    QByteArray RK, CKs, CKr;                 // root, sending, receiving chain keys
    quint32 Ns = 0, Nr = 0, PN = 0;          // counters
    bool haveDHr = false;                    // whether DHr_pub is set yet
    // Skipped message keys for out-of-order delivery, keyed by (DHr_pub || n).
    QHash<QByteArray, QByteArray> skipped;
};

class CryptoBox : public QObject
{
    Q_OBJECT
public:
    explicit CryptoBox(QObject *parent = nullptr);

    // --- Identity (unchanged from the original) ---
    // Generate a fresh VERSION 2 identity: an Ed25519 signing key, from which
    // the X25519 agreement key used by the ratchet is derived. Replaces any
    // identity currently loaded, so the caller must expect a new public key and
    // therefore a new safety number with every peer.
    void generateIdentity();

    // ---- identity version and X3DH availability -------------------------
    // 1 = legacy raw X25519 private key (pre-X3DH accounts).
    // 2 = Ed25519 seed, with the X25519 agreement key derived from it.
    // 0 = no identity loaded.
    int identityVersion() const { return m_identityVersion; }

    // True when the loaded identity can sign, i.e. it is version 2. X3DH needs
    // a signature over the signed prekey, so a version 1 account cannot take
    // part and must fall back to the legacy bootstrap.
    bool hasX3dhIdentity() const { return m_identityVersion == 2
                                         && !m_identitySeed.isEmpty(); }

    // The Ed25519 identity public key, hex. Empty for a version 1 identity.
    // This is what a version 2 account publishes to the relay; the X25519 key
    // the ratchet uses is derived from it by anyone who holds it.
    QString edPublicKeyHex() const;

    // Sign with the identity key. The seed never leaves this class -- callers
    // ask for a signature rather than for the key, so there is one place that
    // can touch it. Empty on failure or on a version 1 identity.
    QByteArray signWithIdentity(const QByteArray &message) const;

    // Verify a detached signature against an Ed25519 identity public key. Free
    // of any loaded state, so it can check a peer's bundle before trusting it.
    static bool verifyIdentitySignature(const QByteArray &edPub,
                                        const QByteArray &message,
                                        const QByteArray &sig);

    // ---- X3DH prekeys ---------------------------------------------------
    // Generate a fresh signed prekey and a pool of `opkCount` one-time prekeys.
    // The signed prekey is signed with the identity, so a peer can tell it came
    // from the keyholder and not from the relay. Requires a version 2 identity;
    // returns false otherwise. Replaces any pool currently held.
    bool generatePrekeys(int opkCount = 32);

    // True once generatePrekeys() (or restorePrekeys()) has produced a pool.
    bool hasPrekeys() const { return !m_spkPriv.isEmpty(); }

    // The public halves, hex, for the publish_prekeys frame.
    QString signedPrekeyPublicHex() const;
    QString signedPrekeySignatureHex() const;
    // {opk_id -> public hex}, the "opks" object of the publish frame.
    QMap<quint32, QString> oneTimePrekeyPublicsHex() const;
    int oneTimePrekeyCount() const { return m_opkPriv.size(); }

    // Check a peer's bundle before any key agreement: the signed prekey must
    // carry a signature by the bundle's own identity key. This is the check
    // that stops the relay -- which serves the bundle -- from substituting a
    // prekey of its own, so it must happen before the prekey is used for
    // anything. Sizes are validated too, since the bundle arrives as untrusted
    // JSON from the network.
    static bool verifyBundle(const QByteArray &ik, const QByteArray &spk,
                             const QByteArray &spkSig);

    // Turn a PUBLISHED identity key into the X25519 key the ratchet needs.
    // A version 2 account publishes its Ed25519 key, so the agreement key is
    // derived from it; a version 1 account publishes the X25519 key directly.
    // Both are 32 bytes and cannot be told apart by inspection, which is why
    // `ikType` is carried on the wire rather than guessed at. Returns false for
    // a malformed key or an unknown type -- never a silently wrong answer.
    static bool agreementKeyFor(const QByteArray &publishedKey,
                                const QString &ikType, QByteArray &out);

    // The signed prekey's private half, needed by the responder side of X3DH.
    QByteArray signedPrekeyPrivate() const { return m_spkPriv; }

    // Consume a one-time prekey by id. SINGLE USE: the entry is removed, so a
    // replayed id returns empty rather than deriving the same DH4 twice.
    QByteArray takeOneTimePrekey(quint32 id);

    // ---- signed prekey rotation (post-compromise security) --------------
    // The signed prekey is the responder's INITIAL RATCHET KEY, so its lifetime
    // bounds how long a compromise of it stays useful. Moving off the identity
    // key achieved nothing on its own: a signed prekey that never rotates is
    // just a second permanent key. Rotation is what makes it ephemeral in
    // practice rather than only in principle.
    //
    // Returns true if a rotation happened. Age is passed in so the caller owns
    // the policy and tests can drive it without waiting.
    bool rotateSignedPrekeyIfDue(qint64 maxAgeMs, qint64 nowMs);

    // Destroy the retained previous signed prekey once the grace period has
    // passed. Until this runs, a compromise of the device still yields the old
    // key, so it is called on the same schedule as rotation rather than left to
    // chance.
    bool dropExpiredPreviousPrekey(qint64 graceMs, qint64 nowMs);

    // Age of the current signed prekey, milliseconds. -1 if there is none.
    qint64 signedPrekeyAgeMs(qint64 nowMs) const;
    bool hasPreviousSignedPrekey() const { return !m_prevSpkPriv.isEmpty(); }

    // ---- X3DH session establishment -------------------------------------
    // INITIATOR. Open a session from a peer's bundle, which the caller must have
    // VERIFIED first (CryptoBox::verifyBundle). Returns the three values the
    // first message has to carry so the peer can derive the same secret:
    // our Ed25519 identity, the fresh ephemeral, and which one-time prekey was
    // consumed (-1 if the pool was empty).
    //
    // This replaces the legacy bootstrap, and the difference is the whole point
    // of the exercise: the root key comes from four Diffie-Hellmans over
    // EPHEMERAL material rather than one over two permanent identity keys, and
    // the peer's signed prekey -- not their identity key -- becomes the initial
    // ratchet key.
    bool beginX3dhSession(const QString &peer, const QByteArray &peerIk,
                          const QByteArray &peerSpk,
                          const QByteArray &peerSpkSig,
                          const QByteArray &peerOpk, qint32 opkId,
                          QByteArray &ikAOut, QByteArray &ekAOut,
                          qint32 &opkIdOut);

    // RESPONDER. Open a session from the header of an incoming first message.
    // Consumes the named one-time prekey, so a replayed header fails rather
    // than deriving the same secret twice.
    // `spkUsed` is the signed prekey PUBLIC the initiator agreed against, taken
    // from the opener header. It is carried explicitly rather than guessed:
    // after a rotation we may hold two, and deriving with the wrong one yields a
    // plausible-looking secret that simply fails to decrypt, with nothing to
    // point at. An empty value means a peer that predates rotation, and the
    // current prekey is assumed.
    bool acceptX3dhSession(const QString &peer, const QByteArray &ikA,
                           const QByteArray &ekA, qint32 opkId,
                           const QByteArray &spkUsed = QByteArray());

    // Opaque blob of the prekey PRIVATES, for the client to persist. Without it
    // a restart would leave the account unable to answer any bundle the relay
    // has already served, which strands every conversation started while it was
    // offline -- exactly the case X3DH exists to handle.
    QByteArray serialisePrekeys() const;
    bool restorePrekeys(const QByteArray &blob);
    bool loadIdentity(const QString &path);
    bool saveIdentity(const QString &path) const;
    QString publicKeyHex() const;

    // ---- Design B: password-wrapped identity at rest -------------------
    // The plain saveIdentity() above writes the raw 32-byte private key to disk.
    // Design B never does that: the private key is stored ENCRYPTED under a key
    // derived from the user's login password via Argon2id (crypto_pwhash), so a
    // stolen device or a copied data directory yields only ciphertext. These
    // methods are the password path; the raw ones remain for in-memory use and
    // for migrating a legacy plaintext key file.
    //
    // saveIdentityEncrypted: derive a 32-byte wrapping key from `password` with
    // Argon2id over a FRESH random salt, seal the current private key with
    // crypto_secretbox under it, and write [magic|version|salt|nonce|ct] to
    // `path`. Requires an identity to be loaded (generateIdentity or a prior
    // load). Returns false on any failure (no identity, bad path, sodium error).
    bool saveIdentityEncrypted(const QString &path,
                               const QString &password) const;

    // loadIdentityEncrypted: read the wrapped file at `path`, re-derive the
    // wrapping key from `password` and the stored salt, and open the secretbox.
    // On success the private/public key pair is loaded into memory and true is
    // returned. A WRONG PASSWORD makes the secretbox open fail and returns false
    // WITHOUT loading anything -- so even a malicious server that waved the user
    // through cannot yield the identity key; the math simply does not produce it.
    // Returns false too on a malformed/short file or a version mismatch.
    bool loadIdentityEncrypted(const QString &path,
                               const QString &password);

    // True if `path` looks like a Design B wrapped-identity file (correct magic
    // and a known version), so the client can tell a wrapped key from a legacy
    // raw key file and from no file at all. Does not need the password. A cheap
    // header read; returns false if the file is absent or unrecognised.
    static bool isEncryptedIdentityFile(const QString &path);

    // ---- Design B: the server-side password verifier -------------------
    // The verifier is what the server stores and compares -- an irreversible
    // Argon2id output that proves knowledge of the password without revealing
    // it. It is derived from the SAME password but under a DIFFERENT salt and a
    // domain-separation tweak than the key-wrapping derivation, so possessing
    // the verifier can never help unwrap the identity key: the two derivations
    // are cryptographically independent even though they share a secret input.
    //
    // deriveVerifier: produce (verifierHex, saltHex) for a FRESH random salt.
    // Called at registration; both values are uploaded to the server (the salt
    // so the same verifier can be re-derived on a future device, the verifier so
    // the server can store it). Returns false on a sodium error.
    static bool deriveVerifier(const QString &password,
                               QString &verifierHexOut, QString &saltHexOut);

    // deriveVerifierWithSalt: re-derive the verifier for a KNOWN salt (hex),
    // used at LOGIN when the salt was chosen at registration. Returns the
    // verifier hex, or empty on a bad salt or sodium error. The server compares
    // this against the stored verifier.
    static QString deriveVerifierWithSalt(const QString &password,
                                          const QString &saltHex);

    // Record a peer's long-term identity public key (hex). This is the material
    // a ratchet session is bootstrapped from (Route A). It remembers the
    // identity key for lazy session creation. KEY-CHANGE RESILIENCE: if the key
    // DIFFERS from one previously recorded for this peer, any existing ratchet
    // session (built from the old key, now unable to agree) is dropped and true
    // is returned, so the caller can also clear the persisted session. Returns
    // false if the key is unchanged, first-seen, or not a valid 32-byte hex.
    bool ensureSharedKey(const QString &peerName, const QString &peerPubHex);

    // Record a peer's identity public key (hex) WITHOUT any of the key-change
    // detection or session-dropping that ensureSharedKey performs. This exists
    // for the restore path: at login we must load each peer's stored identity
    // into m_peerIdentity BEFORE importSession() runs, so that importSession can
    // validate the persisted session's identity stamp against it. Using
    // ensureSharedKey there would be wrong -- it is designed for a live key from
    // a server frame and would misfire its change logic during a cold restore.
    // Returns false if the hex is not a valid 32-byte key; true otherwise.
    bool setPeerIdentity(const QString &peerName, const QString &peerPubHex);

    // The identity public key (hex) we currently hold for a peer, or an empty
    // string if none is recorded. Lets the client persist the exact identity a
    // session is bound to, so it can be reloaded before the session on restart.
    QString peerIdentityHex(const QString &peerName) const;

    // True if we currently hold a (possibly stale) ratchet session for a peer.
    bool hasSessionFor(const QString &peerName) const;

    // Discard any ratchet session we currently hold for a peer, forcing a fresh
    // bootstrap on the next encrypt/decrypt. This is the in-memory counterpart
    // to clearing the persisted session: it is used when the user CONFIRMS a
    // safety-number change, so the very next frame re-bootstraps a clean chain
    // from the peer's new identity key rather than resuming the (now dead) old
    // one. Returns true if a session was actually removed, false if none was
    // held. m_peerIdentity is left intact -- the new identity key stays recorded
    // so the fresh bootstrap uses it. No-op-safe to call when no session exists.
    bool dropSession(const QString &peerName);

    // Wipe ALL in-memory cryptographic state -- every ratchet session, the whole
    // peer-identity map, and our own identity keypair -- returning this CryptoBox
    // to its just-constructed condition. Used when SWITCHING USERS: logout()
    // followed by a login() as a DIFFERENT nickname must not let the previous
    // user's sessions or identity linger, or the new user would attempt to
    // decrypt against chains bootstrapped from someone else's private key (every
    // such decrypt fails, since the bootstrap secret no longer matches). This
    // clears only memory; nothing on disk is touched, so switching BACK to a
    // previous user still restores their sessions via the normal login restore
    // path. login() re-loads or regenerates the identity immediately afterward,
    // so leaving the keypair empty here is safe.
    void resetForNewUser();

    // The Route A bootstrap secret with a peer, derived from the peer's identity
    // public key (hex). Used by the file-sharing path for per-file key
    // derivation. NOTE: files therefore still key off the static bootstrap
    // secret and do not yet inherit ratchet forward secrecy -- a deliberate,
    // documented interim (see the architecture, file-path section).
    QByteArray sharedSecretWith(const QString &peerPubHex) const;

    // Encrypt plaintext for a peer with the ratchet. Fills the message header
    // (cipher/dh/pn/n) and the nonce + ciphertext as hex. Creates the session
    // lazily on first use, choosing the bootstrap ROLE deterministically from the
    // two identity keys (see sessionFor / amInitiatorFor) rather than from who
    // sends first -- so two peers who both send first (e.g. both confirm a key
    // change) do not both bootstrap as initiator and diverge.
    //
    // RESPONDER-NOT-READY: a responder (Bob) has no sending chain until the
    // initiator's first frame triggers a DH ratchet. If this peer is the
    // responder and no sending chain exists yet, encryptFor CANNOT produce a
    // valid frame. It then returns false AND sets *notReady = true (when notReady
    // is non-null), signalling the caller to QUEUE the plaintext and retry once
    // the initiator's opening frame has arrived -- rather than dropping it or, far
    // worse, sending an unusable frame. A false return with *notReady = false (or
    // notReady null) is a genuine failure (e.g. peer identity not yet recorded).
    // On success returns true and leaves *notReady false.
    bool encryptFor(const QString &peerName, const QString &plaintext,
                    QString &cipherOut, QString &dhHexOut,
                    quint32 &pnOut, quint32 &nOut,
                    QString &nonceHexOut, QString &ctHexOut,
                    bool *notReady = nullptr);

    // True if, for this peer, WE are the deterministic initiator (Alice) of the
    // ratchet bootstrap -- i.e. our identity public key sorts before the peer's.
    // Both sides compute this identically from the same two keys, with no
    // dependence on who sends first, so exactly one side is the initiator and the
    // other the responder. The client uses this to decide who transmits the
    // re-bootstrap handshake after a safety-number confirmation: the initiator
    // sends, the responder drops its session and waits for the initiator's frame.
    // Returns false if we do not yet hold the peer's identity key (nothing to
    // compare against), which the caller should treat as "cannot initiate yet".
    bool amInitiatorFor(const QString &peerName) const;

    // Decrypt a ratchet message from a peer. Creates the session lazily as the
    // responder on first use. Returns plaintext, or an empty string and emits
    // decryptionFailed() on authentication failure.
    QString decryptFrom(const QString &peerName, const QString &cipher,
                        const QString &dhHex, quint32 pn, quint32 n,
                        const QString &nonceHex, const QString &ctHex);

    // Safety number (unchanged): a symmetric fingerprint of both identity keys,
    // compared out-of-band to detect a man-in-the-middle on the key exchange.
    static QString safetyNumber(const QString &pubKeyHexA,
                                const QString &pubKeyHexB);

    // Seal / open text for AT-REST local history under a STATIC key derived from
    // our own identity key (not the ratchet), so stored rows survive restarts
    // without ever being plaintext on disk. localOpen returns empty on failure.
    bool localSeal(const QString &plaintext,
                   QString &nonceHexOut, QString &ctHexOut) const;
    QString localOpen(const QString &nonceHex, const QString &ctHex) const;

    // Serialize / restore a peer's ratchet session as an opaque blob, for
    // persistence across restarts. exportSession returns empty if no session
    // exists for the peer; importSession returns false on a malformed blob.
    QByteArray exportSession(const QString &peerName) const;
    bool importSession(const QString &peerName, const QByteArray &blob);

signals:
    void decryptionFailed(const QString &peerName);

private:
    // Get or create the session for a peer. On first creation the bootstrap ROLE
    // is decided DETERMINISTICALLY from the two identity keys (our public key vs
    // the peer's, by memcmp): the smaller is the initiator (Alice), the larger
    // the responder (Bob). This does NOT depend on whether this side is sending
    // or receiving, so two peers who both send first do not both become
    // initiator (the divergence that broke re-bootstrap after a mutual key-change
    // confirmation). Thereafter the DH ratchet evolves the session regardless.
    // Sets *ok. Returns nullptr if the peer identity or our private key is absent.
    RatchetSession *sessionFor(const QString &peerName, bool *ok);

    // VERSION 2 identity material. m_identitySeed is the 32-byte Ed25519 seed
    // and the only secret at rest; m_edPublicKey is its public half. Both are
    // empty for a version 1 identity, which is how hasX3dhIdentity() tells them
    // apart. The X25519 pair below is DERIVED from the seed for version 2, so
    // every existing caller keeps seeing the keys it always saw.
    // Derive m_privateKey / m_publicKey (X25519) from m_identitySeed. The one
    // place that bridges a v2 identity to everything downstream.
    bool deriveAgreementKeysFromSeed();

    // X3DH prekey material. Only the private halves are kept -- the publics are
    // recomputed on demand, so there is one copy of each secret.
    QByteArray m_spkPriv;                    // signed prekey private (32)
    QByteArray m_spkPub;                     // signed prekey public (32)
    QByteArray m_spkSig;                     // our signature over m_spkPub (64)
    qint64     m_spkCreatedMs = 0;           // when the current SPK was made

    // POST-COMPROMISE SECURITY: the PREVIOUS signed prekey, kept briefly after
    // a rotation. A peer who fetched our old bundle while we were offline may
    // send its opener at any moment; destroying the private half the instant we
    // rotate would leave that message permanently undecryptable, so it is
    // retained for a grace period and then destroyed for good.
    QByteArray m_prevSpkPriv;
    QByteArray m_prevSpkPub;
    qint64     m_prevSpkRetiredMs = 0;       // when it stopped being current
    QMap<quint32, QByteArray> m_opkPriv;     // {id -> one-time prekey private}
    quint32    m_nextOpkId = 0;              // ids are never reused

    QByteArray m_identitySeed;    // 32 bytes, secret, Ed25519 seed (v2 only)
    QByteArray m_edPublicKey;     // 32 bytes, public, Ed25519 (v2 only)
    int        m_identityVersion = 0;   // 0 none, 1 legacy X25519, 2 Ed25519

    QByteArray m_privateKey;   // 32 bytes, secret
    QByteArray m_publicKey;    // 32 bytes, public

    QHash<QString, QByteArray> m_peerIdentity;   // peer nick -> identity pubkey (32 B)
    QHash<QString, RatchetSession> m_sessions;   // peer nick -> ratchet session
};

#endif // CRYPTOBOX_H
