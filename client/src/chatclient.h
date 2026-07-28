#ifndef CHATCLIENT_H
#define CHATCLIENT_H

#include <QSet>
#include <QFile>
#include <QObject>
#include <QTimer>
#include <QUrl>
#include <QWebSocket>
#include <qqmlintegration.h>

// TLS TRUST ANCHORS. The lab certificate authority (tools/make_demo_pki.py)
// lets the application demonstrate real, strictly-verified TLS with no paid
// hosting and no public CA. QSslConfiguration is returned by value from
// sslConfigurationFor(), and QSslCertificate is stored in a QList, so both need
// their full definitions here rather than a forward declaration.
#include <QSslCertificate>
#include <QSslConfiguration>

class QQmlEngine;
class QJSEngine;

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
//
// NOTE (ratchet integration, build-and-test required): message encryption now
// uses the Double Ratchet in CryptoBox, so each text frame carries a header
// (cipher/dh/pn/n). Local history is stored re-encrypted under a static local
// key (CryptoBox::localSeal) rather than as the wire ciphertext, and each peer's
// ratchet session is persisted via HistoryStore so a conversation survives a
// restart. These paths have not been compiled here; verify on your toolchain.

class ChatClient : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    // Properties are the values QML can bind to and that update the UI
    // automatically whenever they change.
    Q_PROPERTY(bool connected READ isConnected NOTIFY connectionStateChanged)
    Q_PROPERTY(QString myNickname READ myNickname NOTIFY loggedIn)
    Q_PROPERTY(QString myFingerprint READ myFingerprint NOTIFY loggedIn)
    Q_PROPERTY(MessageModel *messages READ messages CONSTANT)
    Q_PROPERTY(UserModel *users READ users CONSTANT)
    Q_PROPERTY(QString activePeer READ activePeer WRITE setActivePeer
                   NOTIFY activePeerChanged)
    // The last nickname / server URL used to log in successfully, persisted via
    // QSettings and read back by the login screen to pre-fill its fields. Both
    // are notified by loggedIn so a binding refreshes after each login; before
    // any login they read whatever the previous run stored (empty on first run).
    Q_PROPERTY(QString lastNickname READ lastNickname NOTIFY loggedIn)
    Q_PROPERTY(QString lastServerUrl READ lastServerUrl NOTIFY loggedIn)

    // TLS EVIDENCE. A human-readable description of the transport security
    // actually negotiated on the current connection: protocol version, cipher
    // suite, who issued the server's certificate, and which trust anchor
    // validated it. It is filled in on every successful connect and cleared on
    // disconnect.
    //
    // The reason this is a UI-visible property rather than a log line is that
    // "is the transport really secure?" is a question the application should be
    // able to answer on demand, to the user, without attaching a debugger. It
    // also gives the thesis a screenshot that shows the negotiated parameters
    // instead of merely asserting them.
    Q_PROPERTY(QString tlsSummary READ tlsSummary NOTIFY tlsSummaryChanged)

    // PER-USER THEME: the index of the colour preset this user has chosen, so
    // each person who logs in on this device gets their own look. It is stored
    // in QSettings keyed on the nickname ("theme/<nick>"), exactly like the two
    // login fields above, and notified by loggedIn (so the whole UI re-colours
    // the instant a user logs in) and by themeChanged (so choosing a preset from
    // the in-app picker recolours live). If a user has NEVER chosen a preset, the
    // getter returns a deterministic default derived from their nickname, so two
    // different users still start with two different accents rather than an
    // identical default. QML reads this to select window.pal, and writes it via
    // setThemeIndex() from the theme picker.
    Q_PROPERTY(int themeIndex READ themeIndex WRITE setThemeIndex
                   NOTIFY themeChanged)

    // DARK / LIGHT MODE: whether the UI uses the dark colour set (true) or the
    // light one (false). Unlike themeIndex this is stored APP-WIDE, not per
    // nickname ("ui/darkMode" in QSettings): screen brightness is a device
    // preference, like the OS light/dark setting, rather than something that
    // should change when a different account signs in on the same device.
    // Defaults to true (dark) so the app's original look is unchanged on first
    // run. QML binds window.dark to this and writes it from the overflow menu's
    // "Dark mode" switch; darkModeChanged drives the live recolour.
    Q_PROPERTY(bool darkMode READ darkMode WRITE setDarkMode
                   NOTIFY darkModeChanged)

public:
    explicit ChatClient(QObject *parent = nullptr);

    // The QML engine calls this to construct the single ChatClient instance
    // (registered via QML_ELEMENT + QML_SINGLETON). It performs the same
    // startup the old main() did -- opening the history database -- so the
    // singleton is ready the moment QML first references it. This replaces the
    // fragile rootContext()->setContextProperty("chat", ...) approach, which
    // failed to propagate into components loaded from the compiled QML module
    // (every `chat.X` came through as null).
    static ChatClient *create(QQmlEngine *qmlEngine, QJSEngine *jsEngine);

    bool isConnected() const { return m_connected; }
    QString myNickname() const { return m_nick; }
    QString myFingerprint() const;
    MessageModel *messages() { return &m_messages; }
    UserModel *users() { return &m_users; }
    QString activePeer() const { return m_activePeer; }
    void setActivePeer(const QString &peer);

    // Read-only accessors for the last-used login values (see the matching
    // Q_PROPERTY above). Implemented in the .cpp because they read QSettings
    // rather than a member. Used by LoginPage.qml to pre-fill its fields.
    QString lastNickname() const;
    QString lastServerUrl() const;

    // TLS EVIDENCE: see the tlsSummary property above. Empty while disconnected.
    QString tlsSummary() const { return m_tlsSummary; }

    // The chosen theme-preset index for the CURRENT user (m_nick), read from
    // QSettings. Returns a deterministic nickname-derived default when the user
    // has not chosen one, so distinct users start with distinct accents. Before
    // any login m_nick is empty and this returns preset 0.
    int themeIndex() const;
    // Set and persist the current user's theme preset, then emit themeChanged so
    // the UI recolours immediately. Q_INVOKABLE so the in-app theme picker can
    // call it. A no-op (but still emits) if m_nick is empty. The number of
    // available presets lives in QML (Main.qml); this side stores whatever index
    // QML hands it, so adding presets never requires a C++ change.
    Q_INVOKABLE void setThemeIndex(int index);

    // The app-wide dark/light flag, read from QSettings ("ui/darkMode"),
    // defaulting to true (dark) so first run looks exactly as before. Persisted
    // across restarts and shared by all accounts on the device.
    bool darkMode() const;
    // Set and persist the dark/light flag, then emit darkModeChanged so the UI
    // recolours immediately. Q_INVOKABLE so the overflow-menu switch can toggle
    // it directly.
    Q_INVOKABLE void setDarkMode(bool dark);

    // ---- Export a conversation to a file -------------------------------
    // Write the FULL stored conversation with `peer` to a human-readable file on
    // disk, in either plain text or PDF. This reads the same locally-sealed rows
    // loadConversation() replays, decrypting each text row with the static local
    // key (CryptoBox::localOpen) -- so what is exported is the plaintext the user
    // already sees, never the on-disk ciphertext and never a ratchet key. Every
    // line is stamped with its precise local date and time (yyyy-MM-dd HH:mm:ss);
    // file rows are rendered as a "sent a file: name (size)" line; tombstoned
    // rows export the same "This message was deleted" placeholder shown in-app;
    // system rows are included, labelled, so the transcript is faithful.
    //   peer   - the conversation to export.
    //   format - "txt" or "pdf" (case-insensitive); anything else defaults txt.
    //   destUrl- where to write, a file:// URL from the QML Save dialog.
    // Emits exportFinished(peer, path) on success or errorOccurred() on failure
    // (including "nothing to export" when the conversation is empty). The PDF
    // path needs Qt's printsupport module (QTextDocument -> QPrinter); see the
    // build note in the .cpp. Q_INVOKABLE so the overflow menu can call it after
    // the user picks a destination.
    Q_INVOKABLE void exportConversation(const QString &peer,
                                        const QString &format,
                                        const QUrl &destUrl);

    // ---- Android notifications / shortcuts -----------------------------
    // Called from the Android JNI bridge (AndroidNotifier) when the user taps a
    // message notification or a home-screen shortcut for 'peer': it opens that
    // conversation. Runs on the Qt thread (the JNI callback marshals onto it),
    // so it can safely touch the models. On desktop it is simply never called.
    // Public (not a QML invokable) because its caller is native code, not QML.
    void openConversationFromNotification(const QString &peer);

    // Create a home-screen shortcut (Android) for the CURRENTLY active peer, so
    // the user can jump straight back into this conversation from the launcher.
    // Q_INVOKABLE so the overflow menu can offer it. No-op with a gentle message
    // off Android or when no peer is active. The labels are localized here.
    Q_INVOKABLE void createConversationShortcut();

    // A compact human-readable byte size ("12 B", "3.4 KB", "1.2 MB", "1.2 GB").
    // Static and public so both the export path and the Android file-received
    // notification format sizes identically. Locale-independent by design.
    static QString humanReadableSize(qint64 bytes);

    // ---- Methods callable from QML --------------------------------------
    // Connect to the server and LOG IN to an EXISTING account with a password
    // (Design B). The local encrypted identity file is opened with `password`
    // (Argon2id-unwrapped); a wrong password fails locally before the socket is
    // even opened, and the derived server verifier authenticates to the relay.
    // Fails with a clear message if no local identity exists for this nickname
    // (the user should Register instead). The three-argument form is the real
    // one; see also registerAccount() for creating a new account.
    Q_INVOKABLE void login(const QString &serverUrl, const QString &nickname,
                           const QString &password);

    // REGISTER a brand-new account (Design B). Generates a fresh identity,
    // wraps its private key at rest under `password` (Argon2id + secretbox),
    // derives the server verifier, and connects -- the server stores the
    // verifier on first registration. Fails with a clear message if a local
    // encrypted identity ALREADY exists for this nickname (the user should Log
    // in instead), or if the server rejects the name as taken by another
    // identity. Distinct from login() so the UI can offer separate Register /
    // Log in actions, as chosen for the thesis demo.
    Q_INVOKABLE void registerAccount(const QString &serverUrl,
                                     const QString &nickname,
                                     const QString &password,
                                     const QString &birthday = QString());

    // ---- Password recovery ("Forgotten password?") ----------------------
    //
    // WHAT THIS CAN AND CANNOT DO. The server stores an irreversible Argon2id
    // verifier, so a forgotten password can never be retrieved FROM THE SERVER
    // -- by this client, by an administrator, or by anyone who seizes the
    // database. That is the property the whole design rests on and it is not
    // negotiable.
    //
    // What CAN be done is what a browser or password manager does: if this
    // device already holds the password in the biometric-gated login vault
    // (Android Keystore / Windows DPAPI, enrolled after a confirmed login),
    // then proving presence to the OS can release it for display. So this is
    // recovery from THIS DEVICE, not from the account.
    //
    // Consequences the UI must state honestly:
    //   * it works only where biometric login was enrolled beforehand;
    //   * on a fresh device nothing can reveal the password, which is correct
    //     behaviour rather than a gap.
    //
    // The birthday is a secondary check only. It is verified locally against a
    // stored verifier BEFORE the OS prompt; it is deliberately not the security
    // boundary, because a date of birth is a small and often public secret. The
    // biometric is the boundary.
    Q_INVOKABLE void recoverPassword(const QString &serverUrl,
                                     const QString &nickname,
                                     const QString &birthday);

    // Whether "Forgotten password?" can do anything for this nickname on this
    // device: a login vault is enrolled AND a birthday verifier was recorded.
    // QML uses it to explain up front rather than failing after the user types.
    Q_INVOKABLE bool passwordRecoveryAvailable(const QString &nickname) const;

    // Normalise a typed date to ISO yyyy-MM-dd, or return an empty string if it
    // is not a valid date. Exposed so QML can validate the field as it is typed
    // instead of discovering the problem only on submit.
    Q_INVOKABLE QString normalizeBirthday(const QString &birthday) const;

    // True if an ENCRYPTED (Design B) identity file already exists locally for
    // `nickname`, so the login screen can steer the user toward Log in vs
    // Register and warn on the wrong action. Searches the same candidate
    // directories login() does. Does not need the password. A legacy RAW key
    // file also counts (it will be migrated to encrypted on the next login).
    Q_INVOKABLE bool hasLocalIdentity(const QString &nickname) const;

    // Remember the base directory for the local history database. Called once
    // at startup from main(). The database itself is opened per-user in
    // login(), once the nickname is known.
    Q_INVOKABLE void openHistory(const QString &baseDir);
    // Send a plaintext message to the currently active peer. The plaintext is
    // encrypted here and only the ciphertext leaves the device.
    // Ask the relay for a peer's X3DH prekey bundle. The reply arrives as one
    // of the three bundle* signals above.
    Q_INVOKABLE void requestBundle(const QString &peer);

    Q_INVOKABLE void sendMessage(const QString &plaintext);
    // Disconnect cleanly.
    Q_INVOKABLE void logout();

    // ---- App lock (feature 2): PIN + biometric -------------------------
    // The app lock is DELIBERATELY SEPARATE from the login password. The login
    // password wraps the identity key at rest (the strong cryptographic
    // boundary); the PIN only gates the ALREADY-RUNNING, already-unlocked UI
    // when the app is backgrounded and returns, like a phone's lock screen over
    // a session that is already decrypted in memory. So the PIN is a short
    // convenience secret and is NEVER able to decrypt the identity key -- if the
    // process is actually killed, the user must re-enter the full password.
    // This split is intentional: a 4-6 digit PIN must not become the weakest
    // link protecting the whole account.
    //
    // isLocked drives a full-screen lock overlay in QML (a Loader in Main.qml).
    // It is true whenever a PIN is set AND the app has been locked (on suspend,
    // or explicitly), and cleared by a correct PIN or a successful biometric.
    Q_PROPERTY(bool isLocked READ isLocked NOTIFY lockStateChanged)
    Q_PROPERTY(bool hasPin READ hasPin NOTIFY pinStateChanged)
    // Whether the platform can offer biometric (fingerprint) unlock right now.
    // Android: BiometricManager reports an enrolled fingerprint. Windows:
    // depends on the experimental Windows Hello path compiling and Hello being
    // configured. Desktop/Linux: false. QML shows the fingerprint button only
    // when this is true.
    Q_PROPERTY(bool biometricAvailable READ biometricAvailable
                   NOTIFY lockStateChanged)

    bool isLocked() const { return m_locked; }
    bool hasPin() const;
    bool biometricAvailable() const;

    // ---- Lock enablement (platform-aware, feature: native unlock) ------
    // The single source of truth for "is the app lock turned on", stored in
    // QSettings ("lock/enabled"). This is DISTINCT from hasPin(): under the
    // OS-credential model, ANDROID has no app-PIN at all (the device
    // credential/biometric IS the authenticator), so "locked" cannot key off an
    // app-PIN there. Lock-on-startup and auto-lock key off THIS flag.
    //   * Android: enabling the lock only sets this flag; unlock goes through
    //     the OS BiometricPrompt (fingerprint/face + device PIN). No app-PIN.
    //   * Windows: enabling the lock sets this flag AND (via setPin) stores an
    //     app-PIN verifier used as the Windows Hello FALLBACK.
    Q_PROPERTY(bool lockEnabled READ lockEnabled NOTIFY pinStateChanged)
    bool lockEnabled() const;
    // Turn the app lock on or off. On Android 'pin' is ignored (OS credential is
    // used); on Windows a non-empty 'pin' is stored as the Hello fallback. When
    // enabling on Windows with an empty pin the call fails with a message (a
    // fallback is required there). Disabling clears everything and unlocks.
    Q_INVOKABLE void setLockEnabled(bool enabled, const QString &pin = QString());

    // True on this platform, the app uses the OS credential as the primary
    // unlock (Android always; Windows when Hello is available). QML reads this
    // to decide whether to show the app-PIN entry (Windows fallback / no Hello)
    // or only the "unlock with device" affordance (Android / Hello present).
    Q_PROPERTY(bool usesOsCredential READ usesOsCredential NOTIFY lockStateChanged)
    bool usesOsCredential() const;

    // FORGOT PIN / RESET: clear the lock after the user proves identity with
    // their LOGIN PASSWORD (the root of trust that wraps the identity key). On
    // success the lock is turned off and unlocked, so the user can set it up
    // afresh. Returns true if the password was correct and the reset applied.
    // Works on both platforms. The password is verified by attempting to unlock
    // the on-disk encrypted identity for the current (or last) nickname.
    Q_INVOKABLE bool resetLockWithPassword(const QString &password);

    // Set (or change) the app-unlock PIN. Stores only an Argon2id verifier of
    // the PIN (the SAME primitive as the password verifier, never the PIN
    // itself), salted, in QSettings. An empty pin CLEARS the lock entirely.
    // Emits pinStateChanged. Q_INVOKABLE for the settings UI.
    Q_INVOKABLE void setPin(const QString &pin);
    // Verify a PIN against the stored verifier; on success clears isLocked and
    // returns true, else returns false (the overlay stays and can show an
    // error). Q_INVOKABLE for the lock screen.
    Q_INVOKABLE bool verifyPin(const QString &pin);
    // Remove the PIN lock (equivalent to setPin("")). Q_INVOKABLE.
    Q_INVOKABLE void clearPin();
    // Lock the app now (show the overlay) if a PIN is set. Called on app
    // suspend and available to a manual "Lock now" menu item. No-op if no PIN.
    Q_INVOKABLE void lockNow();
    // Ask the platform to show the biometric prompt. On success the native
    // callback calls back in and clears the lock; on failure/cancel the PIN
    // entry remains. No-op where biometrics are unavailable. Q_INVOKABLE for
    // the lock screen's fingerprint button.
    Q_INVOKABLE void requestBiometricUnlock();

    // Called by the native biometric bridge (AppLock/BiometricHelper) when the
    // user authenticates successfully. Clears the lock on the Qt thread.
    // MUST be Q_INVOKABLE: applock.cpp reaches it via
    // QMetaObject::invokeMethod(client, "onBiometricSucceeded", QueuedConnection),
    // which looks the method up BY NAME in the meta-object. A plain (non-slot,
    // non-invokable) method is NOT in the meta-object, so that lookup silently
    // fails -- which is exactly why a successful fingerprint did nothing. Marking
    // it invokable registers it so the queued call actually reaches it on the Qt
    // thread. (The name-based marshalling is required because the callback
    // arrives on an Android binder / WinRT thread, not the Qt thread.)
    Q_INVOKABLE void onBiometricSucceeded();

    // ---- Biometric / Windows Hello LOGIN (feature, separate from app lock) --
    // This lets a RETURNING user log in by proving presence to the OS instead of
    // typing their password. It is DISTINCT from the app lock above: the app
    // lock re-guards an already-logged-in session, whereas this authenticates
    // the login itself. Because the password is the cryptographic root of trust
    // (it unwraps the identity key at rest), biometrics cannot replace it -- the
    // password is stored wrapped by the platform credential store (Android
    // Keystore / Windows DPAPI) and released only after a successful biometric/
    // Hello check, then fed into the ordinary login(). The wrapping lives in the
    // AppLock bridge; ChatClient only drives the flow and runs login() on the
    // recovered password. All calls are safe/no-op on a platform without it.

    // Whether biometric/Hello login can be offered on this device at all
    // (hardware present and, on Windows, the Hello path compiled and available).
    // QML shows the enroll checkbox only when this is true.
    Q_PROPERTY(bool biometricLoginAvailable READ biometricLoginAvailable
                   NOTIFY biometricLoginChanged)
    bool biometricLoginAvailable() const;

    // Whether a wrapped login password is already stored for 'nick' (the user
    // enrolled biometric login for that account on this device). QML shows the
    // "Log in with Hello / fingerprint" button only when this is true.
    Q_INVOKABLE bool hasBiometricLogin(const QString &nick) const;

    // Begin a biometric/Hello login for 'nick' against 'serverUrl'. Stashes the
    // server URL, shows the OS prompt via AppLock; on success the recovered
    // password arrives at onBiometricLoginUnlocked() and login() runs. On
    // failure/cancel nothing happens and the password field remains usable.
    Q_INVOKABLE void biometricLogin(const QString &serverUrl,
                                    const QString &nick);

    // Ask that biometric login be ENROLLED for the account being logged into
    // right now, using 'password'. Called from the login screen when the user
    // ticks the enroll checkbox: the password is held transiently and the vault
    // is written only once the server CONFIRMS the login (in the key-dump
    // handler), so a wrong password never enrolls. Cleared on logout.
    Q_INVOKABLE void requestBiometricLoginEnroll(const QString &password);

    // Forget the wrapped login password for 'nick' (turn biometric login off).
    Q_INVOKABLE void disableBiometricLogin(const QString &nick);

    // Called by the AppLock bridge (Android JNI / Windows worker) when a
    // biometric login succeeds and the stored password has been recovered. Runs
    // the ordinary login() with the stashed server URL. MUST be Q_INVOKABLE:
    // the bridge reaches it by name via a queued QMetaObject::invokeMethod from
    // a non-Qt thread, exactly like onBiometricSucceeded().
    Q_INVOKABLE void onBiometricLoginUnlocked(const QString &nick,
                                              const QString &password);

    // The safety number for my conversation with a peer, for out-of-band
    // verification against a man-in-the-middle on the key exchange.
    Q_INVOKABLE QString safetyNumberWith(const QString &peer) const;

    // SECURITY: true if this peer's key changed and the user has not yet
    // re-verified. QML uses this to show the warning banner.
    Q_INVOKABLE bool hasUnverifiedKeyChange(const QString &peer) const;

    // The user re-verified the safety number after a key change; clear the
    // warning (the session was already re-established; this only dismisses it).
    Q_INVOKABLE void acknowledgeKeyChange(const QString &peer);

    // POST-COMPROMISE SECURITY: force an immediate self-healing rekey with a peer
    // (send a rekey-ping now, provoking a round-trip that folds fresh DH keys into
    // the ratchet in both directions). The automatic heartbeat makes this
    // unnecessary in normal use, but it is a useful manual control and the natural
    // hook for a live demonstration ("re-establish a secure session now"). No-op
    // if we are not connected or hold no established session for the peer. Wire a
    // button to it in QML with, e.g., onClicked: chatClient.forceRekey(peerNick).
    Q_INVOKABLE void forceRekey(const QString &peer);

    // BILATERAL VERIFICATION (both-parties-verified gate). After a safety-number
    // change or a first contact, the conversation may not carry messages until
    // BOTH sides have confirmed the safety number. This is true while the peer is
    // still in a verification episode that has NOT yet been resolved on both
    // sides -- i.e. either I have not confirmed, or the peer has not told me they
    // confirmed. QML binds the composer's enabled state to this so text AND file
    // sending are disabled until the episode completes. A peer that was never
    // flagged is never blocked, so steady-state conversations are unaffected.
    Q_INVOKABLE bool conversationBlocked(const QString &peer) const;

    // True when I have already confirmed the safety number and am only waiting
    // for the PEER to confirm on their device. QML uses this to show a calm
    // "waiting for the other person" banner (no action button) while the composer
    // stays disabled via conversationBlocked(). False once the peer confirms.
    Q_INVOKABLE bool awaitingPeerVerification(const QString &peer) const;

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

    // ---- Message deletion ----------------------------------------------
    // Delete a message only on THIS device. The row is tombstoned locally (the
    // "This message was deleted" placeholder replaces it) and the tombstone is
    // persisted to history so it survives a restart, but NOTHING is sent to the
    // peer -- their copy is untouched. Works on any message in the open
    // conversation, ours or the peer's. 'mid' is the row's stable id (from
    // model.mid in the delegate). No-op if the mid is not in the current model.
    Q_INVOKABLE void deleteForMe(const QString &mid);

    // Delete a message for BOTH sides (retract). Only valid for our OWN
    // messages -- you cannot retract someone else's. This tombstones our local
    // copy AND transmits a small "delete" frame to the peer so their copy is
    // tombstoned too; if the peer is offline the server stores and forwards it
    // on their next login, exactly like a text message. 'mid' is the row's
    // stable id. No-op if the mid is not in the current model or is not ours.
    Q_INVOKABLE void deleteForEveryone(const QString &mid);

    // ---- Message editing / resending -----------------------------------
    // Edit the wording of one of OUR OWN text messages in the open conversation.
    // The new text is echoed into our view immediately, re-sealed and persisted
    // to history so the change survives a restart, and -- because the edited body
    // IS secret -- ENCRYPTED THROUGH THE RATCHET and sent to the peer as an
    // ordinary message frame carrying "edit_of": <mid>, which the peer applies in
    // place rather than showing as a new bubble. 'mid' is the row's stable id
    // (model.mid in the delegate). Editing is ONLINE-ONLY and requires a live
    // sending chain: stepping the ratchet for a frame we could not actually
    // transmit would desynchronise the two chains (the same reason sendMessage
    // queues when offline), and an edit has no natural retry point, so rather
    // than risk a silent divergence we refuse when offline / not-ready and leave
    // the message unchanged, telling the user to retry once connected. No-op if
    // the mid is not in the current model, is not ours, is a file/tombstone, or
    // 'newText' is empty (an empty edit is ignored; use delete instead).
    Q_INVOKABLE void editMessage(const QString &mid, const QString &newText);

    // Resend one of OUR OWN messages in the open conversation as a BRAND-NEW
    // message (a fresh stable id, a new bubble on both sides) -- the natural
    // companion to editing: edit changes a message in place, resend sends it
    // again. For a TEXT row this re-encrypts the same words via sendMessage(); for
    // a FILE row it re-streams the ORIGINAL source file via sendFile(), using the
    // source path remembered when the file was first sent this session (see
    // m_sentFileSources). Resending inherits sendMessage()/sendFile()'s offline
    // handling, so a resend composed while disconnected is queued and delivered
    // on reconnect. 'mid' is the row's stable id. No-op if the mid is not in the
    // current model or is not ours; a file whose original source is no longer
    // available (e.g. after a restart, or a moved file) reports a gentle message
    // asking the user to attach it again.
    Q_INVOKABLE void resendMessage(const QString &mid);

    // ---- Message reactions ---------------------------------------------
    // Set (or clear) OUR reaction on a message in the open conversation.
    // 'mid' is the row's stable id (model.mid in the delegate); 'kind' is "up"
    // (agree), "down" (disagree), or "" to remove our reaction. The reaction is
    // echoed into our own view immediately and persisted to history so it
    // survives a restart, then transmitted as a small "reaction" frame the peer
    // applies to their copy. Like a typing hint it carries no ciphertext (the
    // mid is not secret and the peer already holds the message); like a delete
    // the server relays it live and store-and-forwards it to an offline peer.
    // Tapping the same reaction again passes "" to toggle it off. No-op if the
    // mid is not in the current model.
    Q_INVOKABLE void sendReaction(const QString &mid, const QString &kind);

    // ---- Typing / sending indicator ------------------------------------
    // Tell the ACTIVE peer that we are composing. 'sendingFile' distinguishes
    // "typing a message" from "sending a file" so the peer can show the right
    // wording. This is a lightweight, EPHEMERAL notification: it is relayed only
    // to a live peer and never stored, so an offline peer never receives a stale
    // "was typing". Called from the QML composer on text change and at the start
    // of a file send. Internally debounced -- calling it repeatedly only re-arms
    // the idle timer; an explicit idle ("stopped typing") is sent when the timer
    // lapses or a message is actually sent. No-op if there is no active peer or
    // no connection.
    Q_INVOKABLE void notifyTyping(bool sendingFile = false);

signals:
    void connectionStateChanged();

    // Emitted when the TLS session description changes: once per successful
    // connect (filled in) and once per disconnect (cleared).
    void tlsSummaryChanged();

    // Password recovery outcome. passwordRevealed carries the plaintext for
    // display and nothing else: it is never logged, never stored, and never
    // sent anywhere. passwordRecoveryFailed carries an already-localised reason.
    void passwordRevealed(const QString &password);
    void passwordRecoveryFailed(const QString &reason);
    void loggedIn();

    // X3DH bundle results. Three outcomes, kept distinct on purpose: a verified
    // bundle, no bundle published (legitimate -- the peer predates X3DH), and a
    // bundle that FAILED verification, which is an attack signal and must never
    // be conflated with the second.
    void bundleReady(const QString &peer, const QByteArray &ik,
                     const QByteArray &spk, const QByteArray &opk,
                     qint32 opkId);
    void bundleUnavailable(const QString &peer);
    void bundleRejected(const QString &peer);
    // Emitted by logout() once the socket is closed, the message model cleared,
    // the active peer reset, and the per-user history DB closed. Main.qml reacts
    // by popping the StackView back to the login page. The identity key and the
    // history database FILES are left intact on disk, so logging back in as the
    // same nickname restores the full conversation history and ratchet sessions.
    void loggedOut();
    void activePeerChanged();
    void errorOccurred(const QString &message);

    // Emitted whenever the peer-key directory changes (the bulk dump at login,
    // or a single getkey reply arriving later). QML safety-number bindings
    // depend on this so they recompute once the peer's key is present, and the
    // server-frame handler relies on it to replay any pending file_init/msg
    // frames that were waiting on a key.
    void peerKeysChanged();

    // SECURITY: emitted when a peer's identity key CHANGES from one we had
    // previously seen -- i.e. the safety number no longer matches. Innocent
    // (reinstall / new device) OR a man-in-the-middle, which the safety number
    // exists to catch. UI must surface this prominently; distinct from the
    // transient errorOccurred(). `peer` is the affected conversation.
    void safetyNumberChanged(const QString &peer);

    // PER-USER THEME: emitted when the current user's chosen theme preset
    // changes (via setThemeIndex from the in-app picker). The themeIndex
    // Q_PROPERTY lists this as its NOTIFY, so window.pal in QML re-evaluates and
    // the entire UI recolours live without a restart. loggedIn also refreshes it,
    // so switching users likewise re-colours to the new user's saved preset.
    void themeChanged();

    // DARK / LIGHT MODE: emitted when the app-wide brightness flip is toggled
    // (via setDarkMode from the overflow-menu switch). The darkMode Q_PROPERTY
    // lists this as its NOTIFY, so window.dark in QML re-evaluates and every
    // screen recolours live without a restart.
    void darkModeChanged();

    // ---- App lock (feature 2) signals ----------------------------------
    // Emitted when the lock overlay should appear or disappear (isLocked and
    // biometricAvailable list this as their NOTIFY), so the Main.qml Loader
    // shows/hides the LockScreen live.
    void lockStateChanged();
    // Emitted when a PIN is set or cleared (hasPin lists this as its NOTIFY), so
    // the settings UI updates its "PIN lock: on/off" state without a restart.
    void pinStateChanged();
    // Emitted when biometric/Hello login is enrolled or disabled (and, nominally,
    // when availability could change). biometricLoginAvailable lists this as its
    // NOTIFY, and the login screen re-reads hasBiometricLogin() on it, so the
    // "Log in with Hello / fingerprint" button appears/disappears live.
    void biometricLoginChanged();

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

    // EXPORT: emitted after a conversation has been successfully written to
    // disk by exportConversation(). 'peer' is the conversation exported and
    // 'path' the local filesystem path written, so QML can show a confirmation
    // ("Saved conversation with X to Y"). Failure is reported via errorOccurred.
    void exportFinished(const QString &peer, const QString &path);

    // ---- Message deletion / typing signals -----------------------------
    // Emitted after a message has been tombstoned (locally, or because a peer
    // retracted it), so any QML that wants to react (e.g. flash the row) can.
    // 'mid' is the affected message's stable id. The MessageModel is already
    // updated by the time this fires; this is purely a hook.
    void messageDeleted(const QString &peer, const QString &mid);

    // Emitted when a reaction on a message changes -- either one we sent or one
    // received from the peer. 'peer' is the conversation partner and 'mid' the
    // affected message. The MessageModel already emits dataChanged for the row,
    // which refreshes the open conversation on its own; this signal is provided
    // so other QML (e.g. a contact-list affordance) can react if desired.
    void reactionChanged(const QString &peer, const QString &mid);

    // Emitted when a message's text is edited in place -- either our own edit or
    // the peer's inbound one. 'peer' is the conversation partner and 'mid' the
    // affected message. The MessageModel already emits dataChanged for the row,
    // refreshing the open conversation on its own; this is a hook for other QML.
    void messageEdited(const QString &peer, const QString &mid);

    // ---- Typing / sending indicator ------------------------------------
    // Emitted when the ACTIVE conversation's peer starts or stops composing.
    // 'state' is one of "typing", "sending_file", or "idle". QML binds the
    // conversation-view indicator to this. 'peer' names whose state changed so
    // a late frame for a peer we have since navigated away from can be ignored.
    void peerTypingChanged(const QString &peer, const QString &state);

    // Same information as peerTypingChanged, but for the CONTACT LIST badge:
    // emitted for ANY peer (not only the active one), carrying whether that peer
    // is currently composing. UserListPanel binds a live badge to this so a
    // "typing…" hint shows next to a contact even when their conversation is not
    // open. 'active' is true for typing/sending, false for idle.
    void peerActivityChanged(const QString &peer, bool active);

private slots:
    void onConnected();
    void onDisconnected();
    void onTextMessageReceived(const QString &message);
    void onBinaryMessageReceived(const QByteArray &data);
    void onSslErrors(const QList<QSslError> &errors);
    void tryReconnect();

    // LIFECYCLE (Android): react to the OS moving the app between the
    // foreground and the background. Connected to
    // QGuiApplication::applicationStateChanged in the constructor. On
    // Suspended/Inactive we flush all live ratchet sessions to disk BEFORE
    // Android's Doze can freeze or kill the process mid-state; on Active we
    // re-import them so a session that was saved on the way out is resumed
    // rather than lazily re-bootstrapped from scratch (a re-bootstrap on one
    // side while the peer keeps the old chain is exactly what diverges the
    // ratchet and makes text -- but not files -- silently fail to decrypt).
    void onApplicationStateChanged(Qt::ApplicationState state);

private:
    void handleServerFrame(const QString &raw);
    void uploadPublicKey();

    // ---- Password auth handshake (device-independent verifier) ----------
    // beginAuthHandshake(): called from onConnected() for a fresh login or
    // register. If a password is pending it asks the server for this account's
    // stored salt (auth_begin) and arms m_authSaltTimer as an old-server
    // fallback; the actual hello is sent when the auth_salt reply arrives (or
    // the timer lapses). For a reconnect with a verifier already derived it
    // sends the hello straight away.
    void beginAuthHandshake();
    // deriveVerifierLocally(): the pre-existing behaviour -- derive the verifier
    // from the pending password under the salt saved in QSettings (or a fresh
    // salt if none). Used as the fallback when the server does not answer
    // auth_begin (an older server), so logins still work against it.
    void deriveVerifierLocally();
    // completeHello(): build and send the hello (with any derived verifier) and
    // then run the post-connect steps (Android channels/service, flushOutbox).
    // Reached either immediately (reconnect) or after the salt exchange.
    void completeHello();

    // ---- Design B identity establishment (shared by login/register) -----
    // The single place that opens or creates the password-wrapped identity for
    // `nick`, reusing the robust candidate-directory search and verify-and-
    // fallback save the raw path used. `isRegister` selects the mode:
    //   * register: FAIL if an encrypted identity already exists for the nick
    //     (caller reports "name taken locally"); otherwise generate a fresh
    //     identity and save it wrapped under `password`, migrating a legacy raw
    //     key file if one is present.
    //   * login: FAIL if NO identity exists (caller reports "please register");
    //     otherwise open the encrypted file with `password` -- a wrong password
    //     fails here, before the socket opens. A legacy RAW key file is loaded
    //     and immediately re-wrapped (migrated) under `password`.
    // On success the identity is loaded into m_crypto and true is returned; the
    // caller then derives the server verifier and opens the socket. On failure
    // it emits errorOccurred with a clear message and returns false.
    bool establishIdentity(const QString &nick, const QString &password,
                           bool isRegister);

    // The directory search shared by establishIdentity and hasLocalIdentity:
    // the de-duplicated, priority-ordered writable dirs the identity may live
    // in. Static-ish (depends only on QStandardPaths), so both callers agree on
    // where to look.
    QStringList identityDirs() const;

    void requestKeyFor(const QString &peer);
    // Re-feed any frames (text or file_init) that arrived before we held
    // this sender's public key, now that the key is available.
    void replayPendingFrames(const QString &nick);
    // Persist a peer's ratchet session to local history after it advances
    // (called after every encrypt/decrypt). No-op if history is not open.
    void persistSession(const QString &peer);

    // Persist EVERY peer's ratchet session at once. Used by the lifecycle hook
    // when the app is about to be suspended, so no advanced-but-unsaved chain
    // state is lost if Android then kills the process. No-op if history is not
    // open. (persistSession saves one peer; this saves all known sessions.)
    void persistAllSessions();

    // Restore every persisted ratchet session from disk into CryptoBox. Used at
    // login and when the app returns to the foreground, so a session saved on
    // suspend is RESUMED rather than re-bootstrapped. No-op if history is not
    // open.
    void restoreAllSessions();

    // OUTBOX (the core divergence fix): messages AND files the user composed
    // while the socket was NOT connected. Text is NOT encrypted yet -- encrypting
    // would step the ratchet for a frame that never reaches the wire, burning a
    // message key the peer can never consume and permanently desynchronising the
    // two chains. Files are likewise NOT encrypted until send: a file key derives
    // from the static identity secret, and streaming at send time (not compose
    // time) means the file is keyed to the identity in force when it actually
    // goes out -- correct even if the identity changed while offline. Both are
    // held here and sent in flushOutbox() once the socket is genuinely connected,
    // and both are persisted so nothing composed offline is lost across a
    // restart.
    // Returns the stable message id minted for the queued text, so the caller
    // can echo the message into the model under the SAME id (keeping the
    // offline echo, the persisted row, and the eventual wire frame in agreement
    // and the message deletable at once).
    QString queueOutbox(const QString &peer, const QString &plaintext, qint64 ts);
    // Queue a file for the given peer, composed while offline. Only the source
    // path is stored (nothing is encrypted until flush). Persisted so it
    // survives a restart; re-sent on the next connection.
    void queueOutboxFile(const QString &peer, const QUrl &localFileUrl, qint64 ts);
    void flushOutbox();
    // Load any persisted outbox rows from a previous run into the in-memory
    // queue at login, so messages/files composed offline before a close are
    // re-sent once the connection returns. Called from login().
    void restoreOutbox();

    // SECURITY: record + surface a peer's key change (persistent notice +
    // signal), marking them unverified until the user re-verifies.
    void flagKeyChange(const QString &peer);

    // SECURITY (user switching / re-bootstrap): emit a re-bootstrap "handshake"
    // frame to a peer, or queue it if offline. Called from acknowledgeKeyChange()
    // once the user has CONFIRMED a changed safety number and m_crypto.dropSession
    // has cleared the stale chain. When the socket is connected it encrypts a
    // fixed sentinel via encryptFor() -- which lazily re-bootstraps a fresh chain
    // from the peer's NEW identity key and steps the ratchet exactly once -- and
    // sends a "msg" tagged "kind":"handshake"; the peer decrypts it to advance its
    // own chain, then swallows it silently (no bubble). When the socket is NOT
    // connected it enqueues a "handshake" PendingOut (peer + ts only) so the same
    // frame is emitted on reconnect via flushOutbox(). Either way the ratchet only
    // advances for a frame actually put on the wire, so the confirming side and
    // the peer stay in step -- the invariant that fixed the screen-lock desync.
    void sendOrQueueHandshake(const QString &peer);

    // Encrypt the sentinel and transmit a "msg" with "kind":"handshake" to peer
    // over the live socket, then persist the advanced session. Precondition: the
    // socket is connected and we hold the peer's key. Returns false (and sends
    // nothing) if encryptFor() fails, so the caller can requeue. The single
    // source of truth for how a handshake is put on the wire, shared by the
    // online path in sendOrQueueHandshake() and the drain path in flushOutbox().
    bool transmitHandshake(const QString &peer);

    // POST-COMPROMISE SECURITY heartbeat helpers (see the m_sentSinceRatchet
    // block below for the full rationale).
    //
    // transmitRekey(): the single place a rekey frame goes on the wire. Encrypts
    // a fixed sentinel with the ratchet (stepping the send chain exactly once, on
    // a frame that truly goes out) and sends a "msg" tagged "kind":"rekey-ping"
    // or "rekey-pong" that the peer decrypts -- advancing/ratcheting its chain --
    // then swallows. isPong selects the tag; a ping asks for a pong, a pong
    // answers one and asks for nothing. Precondition: an established, sendable
    // session with the peer and a connected socket. Returns false without sending
    // if encryption reports the session is not ready (e.g. a responder with no
    // sending chain yet) or otherwise fails -- callers simply skip and let the
    // next trigger retry. Persists the advanced session on success.
    bool transmitRekey(const QString &peer, bool isPong);

    // markRekeyPingSent(): record that a rekey-ping just went out to a peer.
    // Sets m_rekeyOutstanding, stamps m_rekeyPingSentAt with now, and (only for a
    // FRESH ping -- the peer was not already in flight) resets that peer's timeout
    // re-send budget. Also arms the kick timer so a pong that never comes back is
    // detected and the ping re-sent (see the LOST-PONG RECOVERY note and
    // kickRekey()). Every place that sends a fresh ping calls this instead of
    // inserting into m_rekeyOutstanding directly, so the lost-pong timeout is
    // armed uniformly no matter which trigger fired the ping.
    void markRekeyPingSent(const QString &peer);

    // noteOutboundTo(): called once for each USER TEXT message put on the wire to
    // a peer (the live send and the offline-drain send). Increments the peer's
    // unhealed-message counter and, if it has crossed kPcsRekeyAfterMessages and
    // no ping is in flight and we are connected with an established session, fires
    // a rekey-ping. Not called for files or control frames.
    void noteOutboundTo(const QString &peer);

    // noteInboundFrom(): called once for each authenticated inbound frame FROM a
    // peer (never our own history echo). Resets the peer's unhealed counter and
    // clears any in-flight ping -- an inbound frame is the turn that heals our
    // side, so the window restarts from zero.
    void noteInboundFrom(const QString &peer);

    // resetPcsFor(): drop ALL post-compromise-security accounting for ONE peer.
    // Called wherever a peer's ratchet session is dropped and re-bootstrapped
    // from a new identity -- i.e. every place dropSession(peer) is invoked: a
    // remote key change (the peer switched users / reinstalled / re-registered,
    // handled in the "keys" and "key_update" frame branches) and the local
    // confirmation of that change (acknowledgeKeyChange). The PCS state is bound
    // to a SPECIFIC chain: m_rekeyOutstanding says "a rekey-ping is in flight on
    // THIS chain", and m_sentSinceRatchet counts one-way messages on THIS chain.
    // When the chain is torn down and rebuilt, both are stale and MUST be
    // cleared in lockstep with the crypto session (dropSession) and the persisted
    // session (HistoryStore::clearSession). Leaving m_rekeyOutstanding set is the
    // bug behind "post-compromise security does not work after user switching":
    // if a ping was outstanding at the moment of the switch (the common case --
    // we were sending one-way to an idle/offline peer, hit the threshold, sent a
    // ping, and the peer switched before answering), the guard
    // !m_rekeyOutstanding.contains(peer) stays true forever on the FRESH session,
    // so no future rekey-ping is ever emitted and the heartbeat silently dies for
    // that peer. Clearing both entries restores a clean recovery window on the
    // re-bootstrapped chain. (The whole-map reset in logout() already covers a
    // LOCAL user switch; this covers the per-peer re-bootstrap of a REMOTE one.)
    void resetPcsFor(const QString &peer);

    // kickRekey(): the retry driver behind m_rekeyKickTimer. Re-attempts every
    // rekey action that is still pending -- a ping for any peer that has crossed
    // the one-way threshold (or has unhealed messages) with no ping in flight, and
    // a pong for every peer in m_pongOwed -- and re-arms the kick timer only if
    // something still could not be sent. This is what makes a rekey lost to the
    // transient post-switch re-bootstrap window complete on its own within a few
    // seconds rather than waiting for the 15-minute idle backstop.
    void kickRekey();

    // sendOwedPongIfReady(): if we owe this peer a pong and our sending chain is
    // now alive, send it and clear the debt. Called from the receive path right
    // after a frame from the peer is decrypted (that inbound frame is exactly what
    // brings a responder's sending chain to life), so an owed pong goes out the
    // instant it becomes possible instead of on the next kick tick.
    void sendOwedPongIfReady(const QString &peer);

    // reestablishPcsForAll(): force a rekey ping->pong with EVERY peer we still
    // hold an established chain with, called at each lifecycle RESUMPTION where
    // the same chain is restored/continued -- a reconnect (completeHello, which
    // also covers a same-user log out then log back in) and an app-lock UNLOCK
    // (onBiometricSucceeded / verifyPin). This is what makes post-compromise
    // security actually kick in after user switching, screen lock, and logout,
    // rather than waiting for the 32-message / 15-minute heartbeat: the round-
    // trip re-roots each sending chain on a fresh DH keypair no prior attacker
    // saw. Peers that are flagged (unconfirmed identity change) or still behind
    // the both-parties-verified gate are skipped -- they must not be sent to
    // until verified, and their re-bootstrap heals them anyway. A peer that
    // cannot be reached this instant is parked in m_healPending and retried by
    // kickRekey()/the next connect. 'reason' is for the log only.
    void reestablishPcsForAll(const char *reason);

    // clearPcsState(): drop ALL post-compromise-security accounting and stop its
    // timers. Called from logout() (a full session end / user switch): the
    // one-way counters, in-flight pings, owed pongs, and pending lifecycle heals
    // are per-user and non-persistent, so a later login (same or different user)
    // simply starts fresh windows. This is the full-teardown counterpart to
    // resetPcsFor(), which scrubs a SINGLE peer on a session re-bootstrap.
    void clearPcsState();

    // BILATERAL VERIFICATION helpers. A "verifyack" is a small PLAINTEXT control
    // frame (its own top-level type, like "delete"/"typing") that tells the peer
    // "I have verified your safety number", so their half of the both-verified
    // gate can open. It carries NO ciphertext and NEVER steps the ratchet -- so it
    // cannot cause the chain desync that undelivered ratchet frames once did -- and
    // it is store-and-forwarded by the server exactly like a "delete", so an
    // offline peer still receives it on their next login.
    //
    // sendOrQueueVerifyAck(): emit the verifyack live if connected, otherwise
    // queue it (persisted, kind "verifyack") so flushOutbox() re-sends it on the
    // next connection. Called from acknowledgeKeyChange() whenever the user
    // confirms a safety number -- ALWAYS, for both the initiator and the responder
    // (unlike the crypto handshake, which only the deterministic initiator sends).
    void sendOrQueueVerifyAck(const QString &peer);

    // transmitVerifyAck(): the single place a verifyack goes on the wire. Stamps
    // OUR current identity ("ik") and the identity we verified for the peer
    // ("peer_ik"), so the recipient accepts it only for the keys currently in
    // force -- a verifyack attesting a superseded identity is stale and ignored.
    // 'verifiedPeerIdentity' is the peer identity we verified: for a live send it
    // is the peer's current key; for a drained offline row it is the key captured
    // when the user confirmed, so a peer that rekeyed in between is not wrongly
    // told we verified their new key. Precondition: the socket is connected.
    // Returns false without sending if not connected, so the caller can requeue.
    bool transmitVerifyAck(const QString &peer,
                           const QString &verifiedPeerIdentity);

    // maybeResendVerifyAck(): re-send a verifyack that may have deadlocked.
    // If we have verified this peer and are still awaiting their side
    // (m_verifyAckResend holds them) and we have just ADOPTED a newer/changed
    // identity for them, our previous ack likely attested a now-superseded key
    // and was silently ignored on their end. Re-send the ack bound to the key we
    // now hold so their bilateral gate can finally open. No-op if we do not owe a
    // re-send, if the episode is already resolved, or if we have not verified
    // them (nothing to attest). Safe to call from every key-adoption site.
    void maybeResendVerifyAck(const QString &peer);

    // sendVerifyResync(): ask a peer to RE-SEND their verifyack. Sent when we
    // (re-)enter a verification episode for a peer: if that peer had already
    // verified us -- possibly under this same, unchanged identity, and possibly
    // an ack that we never recorded because it crossed our re-flag or was dropped
    // in a transient window -- they answer by re-emitting their verifyack, which
    // unblocks our half of the gate. A peer that has NOT verified us simply
    // ignores it. Plaintext control frame, server-relayed by "to", no ratchet
    // step. This is the request half; on receipt (type "verify_resync") a peer
    // replies via sendOrQueueVerifyAck if it currently considers us verified.
    void sendVerifyResync(const QString &peer);

    // Complete a verification episode if BOTH sides have now confirmed: I have
    // verified (peer not in m_unverifiedKeyChange) AND the peer has told me they
    // verified (peer in m_peerVerified). Removes the peer from m_pendingBilateral
    // (unblocking the conversation), appends the completion system line, notifies
    // QML, and drains any queued messages. Idempotent and order-independent: safe
    // to call from both the acknowledge path and the verifyack-receipt path.
    void tryResolveBilateral(const QString &peer);

    // ---- TLS: trust anchors and strict verification --------------------
    // The application can be pointed at two very different kinds of relay:
    //
    //   * a PUBLIC one (the cPouta VM), whose certificate chains to a public
    //     CA already present in the operating system's trust store; and
    //   * a LAB one (a laptop on the same Wi-Fi, or localhost), whose
    //     certificate chains to the private root produced by
    //     tools/make_demo_pki.py and compiled into this binary.
    //
    // Both are verified strictly. The lab root is NOT trusted globally -- it is
    // added only when the host being dialled is a loopback or private-network
    // address (see isLabHost), so a public relay is still validated by the
    // public PKI alone and the lab anchor grants no authority over the
    // internet. That scoping is the whole reason this is safe to ship.

    // Opens m_socket after installing the correct SSL configuration for
    // m_serverUrl. Every connect and reconnect goes through here, so there is
    // no path that opens a socket with the wrong trust settings.
    void openSocketWithTls();

    // Builds the configuration for one URL: VerifyPeer, a TLS 1.2 floor, and
    // the lab anchors appended to the system CAs when the host is a lab host.
    QSslConfiguration sslConfigurationFor(const QUrl &url) const;

    // Loads the lab root(s): the certificate compiled in at :/pki/demo-ca.crt,
    // plus an optional extra PEM path from QSettings("tls/labCaPath") for
    // anyone who regenerates the root and does not want to rebuild. Cached
    // after the first call because it touches the filesystem.
    static QList<QSslCertificate> labTrustAnchors();

    // True when the URL points at loopback or an RFC 1918 / link-local / ULA
    // address -- i.e. somewhere on this machine or this Wi-Fi.
    static bool isLabHost(const QUrl &url);

    // Reads back what the completed handshake actually negotiated and stores it
    // in m_tlsSummary. Called from onConnected().
    void describeTlsSession();

    QWebSocket m_socket;
    CryptoBox m_crypto;
    MessageModel m_messages;
    UserModel m_users;

    QString m_nick;
    QUrl m_serverUrl;
    QString m_activePeer;
    bool m_connected = false;

    // TLS EVIDENCE: human-readable description of the current handshake.
    QString m_tlsSummary;

    // ---- Password recovery state ---------------------------------------
    // When true, the next successful vault release is DISPLAYED rather than
    // used to log in. This is the entire difference between the two flows, and
    // keeping it to a flag means the Android Java bridge and the Windows WinRT
    // path need no changes at all: both already deliver to
    // onBiometricLoginUnlocked(), which branches on this.
    bool m_revealOnly = false;

    // Birthday verifier derived at registration and sent once in the hello.
    QString m_pendingDobVerifierHex;

    // Persist / verify the local birthday verifier used by recoverPassword().
    void storeBirthdayVerifier(const QString &nick, const QString &isoDate);
    bool checkBirthday(const QString &nick, const QString &isoDate) const;

    // ---- App lock (feature 2) state ------------------------------------
    // Whether the lock overlay is currently showing. Set by lockNow() (on app
    // suspend or an explicit lock) when a PIN is configured; cleared by a
    // correct PIN or a successful biometric. Never true when no PIN is set.
    bool m_locked = false;

    // Whether a user is CURRENTLY logged in (a live, decrypted, in-memory
    // session exists). Set true when loggedIn() is emitted (onConnected) and
    // cleared when loggedOut() is emitted (logout). The app lock exists to
    // re-guard THIS session -- the already-decrypted identity, open
    // conversations and history -- so it must only engage while a session is
    // active. It must NEVER show over the login screen: at a cold launch nothing
    // is decrypted yet (the identity is encrypted at rest and needs the login
    // password), so a lock there would guard nothing and, because Android
    // auto-fires the biometric prompt, would drop the user straight onto the
    // login page after a pointless fingerprint tap. lockNow() therefore checks
    // this, and the constructor no longer starts locked. Fix for "fingerprint on
    // Android takes me to the initial Login and Register screen".
    bool m_sessionActive = false;

    // ---- Biometric / Hello LOGIN transient state -----------------------
    // Set by biometricLogin() so onBiometricLoginUnlocked() knows which server
    // to log into once the OS releases the recovered password (the nick comes
    // back with the callback). Not secret; cleared implicitly on the next login.
    QString m_bioLoginServerUrl;
    // Set by requestBiometricLoginEnroll() when the user ticks "enable Hello /
    // fingerprint login" on the login screen. The password is held ONLY in
    // memory and ONLY until the server confirms the login (the key-dump handler
    // then writes the vault and clears this) or logout() clears it -- so a
    // rejected password is never enrolled and the password never lingers.
    QString m_bioEnrollPassword;
    bool m_bioEnrollPending = false;

    // Design B credential carried across the connection lifetime.
    // login()/registerAccount() stash the PASSWORD here (not on disk, only in
    // memory for the duration of the session) so that EVERY (re)connect can
    // re-derive the verifier and re-authenticate. This is the fix for the
    // reconnect death-spiral: previously only the FIRST hello carried a
    // verifier, so an automatic reconnect sent none, the server rejected it
    // (close 4002), and the client reconnected into the same rejection forever.
    // The password is cleared in logout() (never persisted); the derived
    // verifier/salt below are recomputed per connect and cleared after each
    // hello, so the irreversible verifier does not linger longer than needed.
    QString m_pendingPassword;
    QString m_pendingVerifierHex;
    QString m_pendingSaltHex;
    // True while this connection is a fresh REGISTRATION (so the hello includes
    // the verifier to be stored), false for a normal login (hello includes the
    // verifier to be COMPARED). Both send the same fields; the flag only affects
    // logging and a belt-and-braces re-send of the salt. Reset after hello.
    bool m_registering = false;
    // Single-shot fallback for the pre-hello salt fetch (auth_begin/auth_salt).
    // On connect we ask the server for this account's stored salt so every
    // device derives the SAME verifier from the correct password. If the server
    // is older and never answers, this timer fires and we fall back to the
    // local-salt derivation, so an out-of-date server still works.
    QTimer m_authSaltTimer;

    // Reconnection uses exponential back-off: 1s, 2s, 4s ... capped at 30s.
    QTimer m_reconnectTimer;
    int m_reconnectDelayMs = 1000;
    bool m_intentionalClose = false;

    // ---- Typing / sending indicator state ------------------------------
    // OUTGOING side: notifyTyping() is debounced so we do not flood the peer
    // with a frame per keystroke. On the first keystroke we send one "typing"
    // (or "sending_file") frame and arm this single-shot timer; each further
    // keystroke only RE-ARMS it. When it lapses (the user paused) we send one
    // "idle" frame. Sending a message also cancels it and sends "idle". The
    // last state we sent is remembered so we do not send duplicate frames.
    QTimer m_typingTimer;                 // single-shot, ~4s, re-armed per keystroke
    QString m_typingPeer;                 // peer we last told we were typing
    QString m_lastTypingStateSent;        // "typing" | "sending_file" | "idle" | ""
    static constexpr int kTypingIdleMs = 4000;  // silence after which we go idle

    // INCOMING side: which peers are currently composing, so a late "idle" for a
    // peer we navigated away from is still applied, and so the contact-list
    // badge can be driven independently of the open conversation. Keyed by peer
    // nick -> their current state string ("typing"/"sending_file"); a peer not
    // in the map is idle. Cleared for a peer on idle, on logout, and on their
    // going offline (a disconnected peer cannot still be typing).
    QHash<QString, QString> m_peerTyping;

    // Peers whose public key we already have, so we know when we can encrypt.
    QHash<QString, QString> m_peerKeys;  // nick -> pubkey hex

    // Client-side duplicate suppression for received text frames. The server
    // stores every message and replays it on login (offline delivery); a
    // message can therefore arrive twice -- once live, once as replay -- and
    // the ratchet correctly refuses the second copy because each message key is
    // single-use (forward secrecy), which surfaced as a failed decrypt. We
    // record which (ratchet-key, n) frames we have already successfully
    // decrypted per peer and silently drop exact duplicates BEFORE they reach
    // the ratchet. Keyed by peer -> set of (dhHex + ":" + n), because n resets
    // whenever the peer's DH ratchet key rotates, so n alone is not unique.
    QHash<QString, QSet<QString>> m_seenFrames;  // peer -> {"<dhHex>:<n>"}

    // POST-COMPROMISE SECURITY (self-healing heartbeat) -------------------
    // The Double Ratchet already provides post-compromise security: every time
    // the conversation TURNS, a fresh DH keypair is folded into the root key
    // (CryptoBox::dhRatchet), so once an attacker who captured one party's state
    // stops observing, the next round-trip of new ratchet keys locks them back
    // out. That healing is emergent but PASSIVE -- it only happens when the
    // direction of traffic changes. A long one-directional burst (one side
    // sending, the other silent) or a long idle gap therefore never self-heals:
    // the compromised sending chain keeps producing readable keys indefinitely.
    // This heartbeat makes the property ACTIVE and bounded. It counts how many
    // text messages we have sent to each peer since we last heard back from them
    // (m_sentSinceRatchet); when that crosses kPcsRekeyAfterMessages, or when the
    // idle backstop timer fires with unhealed sent messages outstanding, we send
    // a tiny "rekey-ping" -- an ordinary ratchet frame the peer decrypts and
    // SWALLOWS (no bubble, no history, no badge), exactly like the re-bootstrap
    // handshake. The peer answers with a "rekey-pong". That single round-trip
    // makes both sides perform a fresh DH ratchet step, restoring
    // post-compromise security in BOTH directions (verified against the
    // reference ratchet: one ping/pong heals an attacker's captured state). The
    // whole mechanism rides the existing msg/outbox path and the untouched
    // ratchet -- no cryptographic code changes and no server changes.
    //
    // m_sentSinceRatchet: peer nick -> count of TEXT messages we have sent since
    // the last authenticated inbound frame from that peer. Control frames
    // (handshake/verifyack/rekey) and files (which do not step the ratchet) are
    // NOT counted. Reset to 0 by noteInboundFrom() on any inbound frame from the
    // peer -- an inbound frame is precisely the turn that heals our side.
    QHash<QString, int> m_sentSinceRatchet;

    // Peers to whom we have sent a rekey-ping and are awaiting the matching
    // rekey-pong. Guards against sending a second ping while one is in flight
    // (and against a sustained one-way burst spamming pings): cleared when any
    // inbound frame from the peer arrives (noteInboundFrom), which includes the
    // pong itself. No persistence -- a restart simply starts a fresh window.
    QSet<QString> m_rekeyOutstanding;

    // Idle backstop: fires periodically while connected and, for any peer with
    // unhealed sent messages (m_sentSinceRatchet > 0) and no ping in flight,
    // sends a rekey-ping. This closes the low-volume-then-idle gap that the
    // message-count trigger alone would miss (a handful of one-way messages, then
    // silence). Started on connect, stopped on logout; it no-ops when nothing is
    // outstanding, so a quiescent conversation generates no traffic.
    QTimer m_rekeyTimer;

    // Send a rekey-ping after this many one-way TEXT messages to a peer. This is
    // the post-compromise recovery bound: after a state compromise, at most this
    // many further one-directional messages can be exposed before a forced
    // round-trip heals the channel. Smaller = stronger PCS but more control
    // traffic on one-way bursts; in normal two-way chat organic replies heal the
    // channel long before this is reached, so pings rarely fire.
    // POST-COMPROMISE SECURITY: how many messages may be sent without the DH
    // ratchet turning before the heartbeat forces a step.
    //
    // Lowered from 32 to 8 on log evidence. A live session showed the sending
    // counter climb 0..32 under a single ratchet key and the receiving counter
    // do the same, so sixty-six messages crossed the wire under two chains that
    // never turned; the heartbeat then fired exactly once, at the threshold.
    // The heartbeat was working -- the threshold was simply the whole exposure
    // window, because a one-way run never turns the ratchet on its own.
    //
    // The window matters more here than in a design with full X3DH, because the
    // BOOTSTRAP chains are derived from long-term identity keys (see the note in
    // CryptoBox::sessionFor): until the first DH step, the chain in force is not
    // protected by any ephemeral secret. Shortening the window shortens exactly
    // that exposure.
    //
    // Eight is a deliberate trade rather than a round number: each forced step
    // costs one extra frame and one message key, so at eight the heartbeat adds
    // about 12% overhead to a sustained one-way run while cutting the unhealed
    // span by a factor of four. A ping is only sent to a peer who is verified,
    // online and within its resend budget, so the cost is not paid against peers
    // who cannot answer.
    // Replenish the one-time prekey pool when the relay reports this few left.
    // The relay hands them out and never returns them, so a pool allowed to
    // reach zero silently downgrades every later first contact to the weaker
    // three-DH agreement -- a failure with no symptom the user could notice.
    // How long a signed prekey may serve before it is replaced, and how long
    // the replaced one is kept so bundles already in circulation can still be
    // answered. Seven days and two days follow the usual practice: long enough
    // that rotation is not chatty, short enough that a compromised prekey stops
    // being useful quickly, and a grace period comfortably longer than any
    // plausible gap between fetching a bundle and sending the first message.
    static constexpr qint64 kSpkMaxAgeMs = 7LL * 24 * 60 * 60 * 1000;
    static constexpr qint64 kSpkGraceMs  = 2LL * 24 * 60 * 60 * 1000;

    static constexpr int kPrekeyLowWaterMark = 8;
    // How many to publish at a time.
    static constexpr int kPrekeyBatchSize = 32;

    static constexpr int kPcsRekeyAfterMessages = 8;

    // Idle backstop period (ms). While connected, peers with unhealed sent
    // messages are re-keyed at most this often even if the message-count
    // threshold is never reached. 15 minutes balances a tight recovery window
    // against background traffic/battery on the phone.
    static constexpr int kPcsRekeyIdleMs = 15 * 60 * 1000;

    // ------------------------------------------------------------------------
    // RELIABILITY (the fix for "after user-switching the 32nd one-way message's
    // rekey does not complete -- no pong, round-trip stalls"). Both the ping and
    // the pong are best-effort: transmitRekey() returns false, WITHOUT sending,
    // whenever the ratchet is momentarily not sendable -- most importantly during
    // the brief window right after a user switch, when the session has just been
    // re-bootstrapped and a responder's sending chain is not yet alive (its CKs
    // is created only when the initiator's opening frame arrives). Before this
    // change a ping/pong lost to that transient state was retried only by the
    // 15-minute idle backstop or by the NEXT outbound text -- and a one-way burst
    // that STOPS exactly at the threshold has no next text, so the heal stalled
    // for up to 15 minutes and looked like "it does not work". These two members
    // make the round-trip self-complete in seconds instead:
    //
    // m_pongOwed: peers whose rekey-ping we received and decrypted but could not
    // answer immediately (transmitRekey for the pong returned not-ready). We owe
    // them a pong; it is retried by the kick timer below and, proactively, the
    // moment our sending chain comes alive on the next inbound frame. Cleared on
    // a successful pong, on logout, and on a session re-bootstrap (resetPcsFor).
    QSet<QString> m_pongOwed;

    // Short one-shot retry timer. Armed whenever a ping OR a pong could not be
    // sent right now (a transient not-ready), it re-attempts every pending rekey
    // action -- pings still owed under the message-count/idle rule, and pongs in
    // m_pongOwed -- and re-arms itself only while work remains, so it falls silent
    // as soon as everything has been sent. This is the fast path the 15-minute
    // backstop cannot be: it turns a transient re-bootstrap race into a sub-5-
    // second recovery without generating traffic on a healthy, quiescent channel.
    QTimer m_rekeyKickTimer;

    // Retry period (ms) for m_rekeyKickTimer. Short enough that a rekey lost to
    // the post-switch re-bootstrap window completes almost immediately, long
    // enough that a peer that is simply unreachable is not retried in a tight
    // loop (each attempt is one small frame, and the loop stops once sent).
    static constexpr int kPcsRekeyKickMs = 3000;

    // Bound on consecutive kick retries, so a degenerate state that can never
    // send (e.g. a responder whose peer never opens the channel) cannot re-arm
    // the timer forever. After this many failed passes kickRekey() gives up and
    // resets; the idle backstop and the next inbound/outbound event still cover
    // it. kPcsRekeyKickMs * this ~= 24s, ample for any re-bootstrap to settle.
    static constexpr int kPcsRekeyKickMaxTries = 8;

    // Consecutive kick passes that ended with work still un-sendable. Reset to 0
    // by kickRekey() the moment a pass clears everything (or hits the cap).
    int m_rekeyKickTries = 0;

    // LOST-PONG RECOVERY (the fix for "after 32 one-way texts from the Android
    // client, PCS did not start"). A rekey-ping we SENT is cleared from
    // m_rekeyOutstanding ONLY by an inbound frame from the peer -- normally the
    // matching pong. On the phone, Doze severs the WebSocket exactly when the app
    // is backgrounded, and the pong always travels back to US, the sender: so the
    // Android sender is precisely the side whose pong can be dropped in flight. In
    // a genuinely ONE-WAY conversation the peer sends nothing else, so no other
    // inbound frame ever clears the flag -- it sticks forever, and every rekey
    // trigger (count threshold, idle backstop, reconnect-heal) skips a peer that
    // is "already in flight". Post-compromise security is then silenced for that
    // peer permanently. (The desktop sender never hits this: its socket is stable,
    // so its pong reliably returns.) These members give a SENT ping a timeout and
    // a bounded re-send -- the symmetric counterpart of the m_pongOwed retry that
    // already covers the other direction -- so a lost pong re-arms the heal
    // instead of disabling it. All in-memory and non-persistent, like the rest of
    // the PCS accounting; cleared alongside m_rekeyOutstanding.
    //
    // m_rekeyPingSentAt: peer -> ms-since-epoch of the most recent ping send. An
    // entry exists exactly while a ping is outstanding (paired with
    // m_rekeyOutstanding). kickRekey() re-sends once this is older than
    // kPcsRekeyPongTimeoutMs.
    QHash<QString, qint64> m_rekeyPingSentAt;

    // m_rekeyPingResends: peer -> how many times the CURRENT outstanding ping has
    // been re-sent after a pong timeout. Reset to 0 when a fresh ping cycle starts
    // (markRekeyPingSent); incremented on each timeout re-send in kickRekey().
    QHash<QString, int> m_rekeyPingResends;

    // A ping whose pong has not returned within this long is treated as lost and
    // re-sent. Comfortably longer than a healthy round-trip, far shorter than the
    // idle backstop, so the one-way heal completes in seconds rather than never.
    static constexpr qint64 kPcsRekeyPongTimeoutMs = 8000;

    // Bound on consecutive timeout re-sends of one outstanding ping, so a peer
    // that is genuinely gone is not pinged forever. Past this, the in-flight flag
    // is released so the ordinary count/idle/reconnect triggers can start a fresh
    // cycle. kPcsRekeyPongTimeoutMs * this ~= 40s of retry before giving up.
    static constexpr int kPcsRekeyPingMaxResends = 5;

    // POST-COMPROMISE SECURITY, lifecycle heal ----------------------------
    // Peers we want to proactively rekey because a live session just RESUMED
    // after an event during which the device may have been in someone else's
    // hands -- a reconnect (dropped socket, an Android background/screen-lock
    // freeze, or a SAME-user log out then log back in) or an app-lock UNLOCK.
    // Each such resumption restores the SAME ratchet chain from disk, so on its
    // own it grants NO healing: a compromise captured before the event is still
    // valid. reestablishPcsForAll() therefore forces one rekey ping->pong per
    // established peer, folding fresh DH entropy into the chain so security is
    // reestablished for future messages -- the post-compromise guarantee applied
    // to these three lifecycle moments rather than only to the 32-message /
    // 15-minute bounds. A peer that cannot be reached the instant we resume
    // (chain not sendable yet, or momentarily disconnected) is remembered here
    // and retried by kickRekey() / the next connect, so the heal is guaranteed
    // rather than best-effort-and-forgotten. Peers whose IDENTITY changed while
    // we were away are handled by the keys/key_update re-bootstrap (itself
    // PCS-fresh) and are never added here. Cleared on logout via clearPcsState().
    QSet<QString> m_healPending;

    // SECURITY: peers whose identity key changed and whom the user has not yet
    // re-verified. Drives the warning banner; cleared by acknowledgeKeyChange().
    QSet<QString> m_unverifiedKeyChange;

    // BILATERAL VERIFICATION (both-parties-verified gate) -----------------
    // m_unverifiedKeyChange above tracks whether *I* have verified. These two
    // track the peer's half and the overall episode:
    //
    //   m_peerVerified    -- peers who have told me, via a "verifyack" control
    //                        frame bound to the identity I currently hold, that
    //                        THEY have verified my safety number. Insertion is
    //                        idempotent; a fresh key change removes the peer (the
    //                        old confirmation is void for the new identity).
    //
    //   m_pendingBilateral -- peers currently in a verification episode that is
    //                        not yet resolved on BOTH sides. A peer enters on
    //                        flagKeyChange() and leaves via tryResolveBilateral()
    //                        once I have verified AND m_peerVerified holds them.
    //                        sendMessage()/sendFile() block while a peer is here.
    //                        A peer that was never flagged is never here, so
    //                        steady-state conversations bypass the gate entirely.
    //
    // Neither set is persisted: on login the key handlers re-detect a genuine
    // key change and re-flag (repopulating both), while a fully re-established
    // peer (session identity stamp matches the current key) is treated as
    // verified -- so a restart self-heals any stuck bilateral state rather than
    // leaving the conversation permanently blocked, consistent with the rest of
    // the app's self-healing-on-restart design.
    // PERSISTED VERIFICATION (fix: repeated safety-number prompts).
    // peer -> the peer identity hex the USER actually confirmed. Restored from
    // HistoryStore at login, so a confirmation survives logout, user switching
    // and application restart. The gate compares the key now in force against
    // this value: identical means already verified and no banner; different
    // means a genuine rekey and the banner is raised exactly as before.
    // Publish this account's prekey bundle if it has none, is low, or `force`.
    void publishPrekeysIfNeeded(bool force = false);

    // Peers' PUBLISHED Ed25519 identity keys, for verifying their prekey
    // bundles. Absent for a version 1 peer, which is how the client knows not
    // to attempt X3DH with them. The X25519 agreement keys the ratchet uses
    // live in m_peerKeys as they always have.
    // The opener values for a session we initiated but have not yet sent on.
    // Held only until the first frame goes out. spkUsed names the signed prekey
    // the agreement ran against: the peer may rotate between serving the bundle
    // and receiving the opener, and then holds two with no way to tell which we
    // used -- the wrong one derives a well-formed secret that fails to decrypt.
    struct X3dhHeader { QByteArray ikA; QByteArray ekA; qint32 opkId = -1;
                        QByteArray spkUsed; };
    QHash<QString, X3dhHeader> m_pendingX3dhHeader;

    QHash<QString, QByteArray> m_peerEdKeys;

    // True once the login dump has shown that this relay publishes Ed25519
    // identity keys without stating so. Learned from the relay's own entry for
    // us (see the "keys" handler) and then applied to every untagged key from
    // the same relay, including the single-key frames an offline peer's key
    // arrives by. Cleared on user switch, because the next login may be to a
    // different server.
    bool m_relayServesUntaggedEd = false;

    QHash<QString, QString> m_verifiedPeerIdentity;

    QSet<QString> m_peerVerified;
    QSet<QString> m_pendingBilateral;

    // Frames received before we held the sender's key, stashed by sender
    // nick and replayed once the key arrives. Without this, the first
    // file_init (or msg) from a peer whose key we have not yet fetched is
    // dropped, and a file transfer silently fails until the conversation
    // has been opened at least once.
    QHash<QString, QStringList> m_pendingFrames;  // sender nick -> raw frames

    // RE-BOOTSTRAP LOOP BREAKER (safety-number deadlock fix).
    // The receive-side "newer identity than we hold" guard (see the "msg"
    // branch) adopts a handshake's stated identity `ik`, re-requests the
    // authoritative key from the server, stashes the frame, and replays it once
    // the key lands. That is correct ONCE, but if the key the server returns and
    // the handshake's `ik` never converge, each replay re-detects a mismatch and
    // re-stashes/re-requests forever -- the thousands of repeated
    // "[REBOOTSTRAP] ... adopting it and re-fetching" lines seen on device. This
    // map records, per peer, the `ik` we have ALREADY adopted-and-re-requested,
    // so the guard fires at most once per distinct identity: if a replayed
    // handshake still carries an `ik` we have already adopted (i.e. it now equals
    // the key we hold), we stop re-fetching and let the frame bootstrap/decrypt
    // normally instead of looping. The one-shot is keyed by the ADOPTED IDENTITY
    // VALUE, so a genuinely NEW key re-arms it on its own (a handshake stating a
    // different `ik` is not "already adopted"). It is therefore deliberately NOT
    // cleared on every observed key change: clearing it there is both redundant
    // AND the cause of a livelock -- when a replayed/stale offline handshake
    // asserts an `ik` the server never confirms, clearing re-arms the one-shot so
    // the SAME `ik` adopts-and-refetches on every replay while the server's
    // (differing) authoritative key re-triggers the change path, spinning an
    // unbounded adopt->refetch->flag->verify_resync storm. Leaving it set lets the
    // handshake converge branch drop the stale frame after exactly one round.
    QHash<QString, QString> m_rebootstrapAdopted;  // peer -> last adopted ik hex

    // VERIFY_RESYNC THROTTLE (storm guard). sendVerifyResync() is a best-effort
    // "please re-ack" nudge; sending it more than once in a short window is never
    // useful. This coalesces repeats per peer so that even if some future code
    // path over-triggers it, it can never flood the wire/log the way the earlier
    // re-bootstrap livelock did (hundreds of thousands of identical resyncs in one
    // session). peer -> monotonic ms timestamp of the last resync we actually sent.
    QHash<QString, qint64> m_lastVerifyResyncMs;

    // VERIFYACK RE-SEND SET (bilateral-verification deadlock fix).
    // A verifyack attests the peer identity we verified (`peer_ik`) and is
    // accepted by the peer only while it still matches THEIR current identity. If
    // our ack was produced against a view of the peer's identity that was
    // superseded moments later (the two sides' key-change/adoption events
    // interleaving after a logout/switch-user/re-register), the peer silently
    // ignores it -- and because we have already cleared our own
    // m_unverifiedKeyChange, we never naturally re-send, so the peer waits for an
    // ack that never comes and the conversation halts. Membership here means: we
    // have verified this peer and sent an ack, but the episode is not yet
    // resolved, so if we later ADOPT a newer identity for this peer we must
    // re-send the verifyack bound to that newest identity. Removed once the
    // episode resolves (tryResolveBilateral) or the peer is no longer pending.
    QSet<QString> m_verifyAckResend;

    // WHICH OF MY IDENTITIES EACH PEER HAS ATTESTED (mutual-deadlock fix).
    // The bilateral gate opens only when the peer has verified MY CURRENT
    // identity. A verifyack we accept always attests our current key (the accept
    // rule enforces it), so when we accept one we record here: peer -> the hex of
    // OUR identity they attested. Unlike m_peerVerified, this survives a re-flag.
    // Its purpose is to make the gate order-independent and re-flag-safe: if we
    // later re-enter a verification episode for this peer WITHOUT our identity
    // having changed (e.g. a spurious re-flag after a logout/switch-user, where
    // the safety number is unchanged), the peer already attested this exact
    // identity and will not naturally re-ack -- so we must honour their standing
    // attestation instead of waiting forever. If our identity DID change, the
    // stored value will not equal our new key, so the attestation is correctly
    // treated as void and a fresh ack is required. Cleared per peer on logout.
    QHash<QString, QString> m_peerVerifiedForIdentity;  // peer -> my attested id

    // OUTBOX: messages and files composed while the socket was not connected,
    // awaiting a live connection to be sent. Text is held with its plaintext
    // (never encrypted until transmission, so the ratchet is not stepped for an
    // undelivered frame). Files are held by SOURCE PATH only and streamed at send
    // time. Every entry mirrors a persisted 'outbox' row (dbId) so it survives a
    // restart; dbId lets flushOutbox() delete exactly that row once sent. Drained
    // oldest-first by flushOutbox() on reconnect.
    struct PendingOut {
        qint64  dbId = -1;         // persisted outbox row id (-1 if not stored)
        QString kind;              // "text" | "file" | "handshake" | "verifyack"
        QString peer;
        QString plaintext;         // text only
        QString srcPath;           // file only (source path/URL to stream)
        QString peerIdentity;      // verifyack only: the peer identity (hex) that
                                   // was verified when the ack was queued, so a
                                   // drained offline ack attests the key that was
                                   // actually confirmed rather than whatever key
                                   // is current at flush time (see flushOutbox).
        QString mid;               // text only: the stable id minted at queue
                                   // time, so the offline echo, the persisted
                                   // history row, and the eventual wire frame
                                   // all share ONE id and the message stays
                                   // deletable once it is finally sent.
        qint64  ts = 0;
        // A "handshake" entry carries only peer + ts: no plaintext, no srcPath.
        // It represents a re-bootstrap frame the user triggered by CONFIRMING a
        // changed safety number while offline. On flush it encrypts a fixed
        // sentinel via encryptFor() (stepping the ratchet exactly once, on a
        // frame that truly goes out) and sends a "msg" tagged "kind":"handshake"
        // that the peer decrypts to advance its chain and then silently
        // swallows -- never rendered as a bubble. This keeps the whole feature
        // on the existing msg/outbox path, so the server is untouched and the
        // "ratchet only advances for a frame put on the wire" invariant holds.
    };
    QList<PendingOut> m_outbox;

    // Re-entrancy guard for flushOutbox(). flushOutbox() is now called both from
    // onConnected() AND from the receive path (when an inbound frame brings a
    // peer's chain alive, so queued messages can finally be sent). Sending a
    // frame can, in some socket configurations, pump further queued signal
    // handling; this flag ensures a second flushOutbox() entered while one is
    // already draining returns immediately instead of double-sending an item.
    // Set true for the duration of the drain loop, cleared on exit.
    bool m_flushInProgress = false;

    // Local per-conversation history (SQLite). Text rows are stored as
    // ciphertext re-encrypted under a static local key (never the wire
    // ciphertext, which the ratchet discards), file rows as metadata, and the
    // ratchet session per peer; all replayed/restored on login and peer switch.
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
        // PHANTOM-FAILURE FIX (Issue #1): true when this transfer came from a
        // server REPLAY (an offline-queued file re-sent on login), as opposed to
        // a LIVE transfer from a currently-connected peer. A replayed file that
        // was queued under a superseded identity pairing can no longer be
        // decrypted, and its AEAD failure is expected -- so when a replayed file
        // fails to decrypt we drop it SILENTLY (no "authentication failure"
        // message), whereas a live transfer's failure is still surfaced.
        bool replayed = false;
    };
    QHash<QString, std::shared_ptr<IncomingFile>> m_incoming;

    // After a file finishes arriving, its decrypted temp path is kept here
    // keyed by msgId so saveReceivedFile() can copy it out to a user-chosen
    // location later, after the IncomingFile entry has been cleared.
    QHash<QString, QString> m_receivedFilePaths;  // msgId -> temp localPath

    // Source URL of each file WE have sent this session, keyed by its msgId, so
    // resendMessage() can re-stream the exact original. We deliberately do not
    // persist our own sent-file source paths (the original lives wherever the
    // user keeps it -- see the file-send path), so this map is in-memory only:
    // resend works within the running session (the common "the transfer failed,
    // send it again" case) and, after a restart, reports that the source is no
    // longer available and asks the user to re-attach.
    QHash<QString, QUrl> m_sentFileSources;  // msgId -> original source URL

    // Pump out the next chunk of an outgoing transfer. Called repeatedly
    // until the file is fully sent. Kept as a separate method so a future
    // change to back-pressure based on QWebSocket::bytesToWrite() is easy.
    void pumpOutgoingFile(const std::shared_ptr<OutgoingFile> &out);

    // ---- Typing / sending indicator helpers ----------------------------
    // Send a typing-state frame to 'peer' if it differs from the last state we
    // sent that peer, and remember it. 'state' is "typing"/"sending_file"/"idle".
    // Debouncing and timer management live in notifyTyping(); this just puts one
    // frame on the wire (only when connected) and avoids duplicate sends.
    void sendTypingState(const QString &peer, const QString &state);

    // Apply an INBOUND typing-state for 'peer' to our local view: update the
    // per-peer map and emit peerTypingChanged (for the open conversation) and
    // peerActivityChanged (for the contact-list badge). 'state' idle clears the
    // entry. Centralised so the msg-receive path, an explicit typing frame, a
    // peer going offline, and logout all drive the indicator identically.
    void setPeerTyping(const QString &peer, const QString &state);
};

#endif // CHATCLIENT_H
