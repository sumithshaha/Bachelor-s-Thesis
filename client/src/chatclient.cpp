#include "chatclient.h"

#include <QQmlEngine>
#include <QStandardPaths>
#include <QDir>

#include <QDateTime>
#include <QDebug>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryFile>
#include <QSettings>
#include <QUrl>
#include <QTextStream>
#include <QLocale>
#include <QLoggingCategory>
#include <utility>

#include <QAbstractSocket>
#include <QDate>
#include <QCryptographicHash>
#include <QSslConfiguration>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslSocket>
#include <QHostAddress>
#include "localization.h"

// SERVER LOG MIRROR. Lines the relay streams to us (type "server_log") are
// re-emitted through Qt's logging framework under this category, so they take
// the exact same path as every local trace: through the deepLogHandler in
// main.cpp into BOTH the console/logcat and the in-app Log screen, formatted
// with the same timestamp/level head and tagged [server]. Re-logging (instead
// of appending straight to LogBuffer) keeps a single pipeline, keeps the
// console/logcat complete, and cannot loop: receiving a server line only
// writes locally -- nothing is ever sent back to the relay.
Q_LOGGING_CATEGORY(lcServer, "server")
#include "androidnotifier.h"
#include "desktopnotifier.h"
#include "applock.h"

// EXPORT (PDF): rendering a QTextDocument to PDF uses QPrinter, which lives in
// Qt's OPTIONAL printsupport module. We include it only if it is actually
// available in this build, so the file still compiles when printsupport has not
// yet been added to the project; when it is missing, exportConversation() falls
// back to a clear "PDF not available in this build" message instead of failing
// to compile. To ENABLE PDF, add printsupport to the build:
//   * qmake  (.pro):     QT += printsupport
//   * CMake:             find_package(Qt6 REQUIRED COMPONENTS PrintSupport)
//                        target_link_libraries(<target> PRIVATE Qt6::PrintSupport)
// TXT export needs none of this and always works.
#if __has_include(<QPrinter>)
#  include <QPrinter>
#  include <QTextDocument>
#  include <QPageLayout>
#  include <QPageSize>
#  include <QMarginsF>
#  define CHATE2EE_HAVE_PRINTSUPPORT 1
#else
#  define CHATE2EE_HAVE_PRINTSUPPORT 0
#endif

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

    // AUTH SALT FALLBACK: on connect we ask the server for this account's stored
    // password salt (auth_begin) so every device derives the SAME verifier from
    // the correct password. If the server is an older build that does not answer
    // auth_salt, this single-shot timer lapses and we fall back to deriving the
    // verifier from the salt we hold locally, then send the hello -- so an
    // out-of-date server keeps working exactly as before.
    m_authSaltTimer.setSingleShot(true);
    connect(&m_authSaltTimer, &QTimer::timeout, this, [this]() {
        if (m_pendingPassword.isEmpty())
            return;   // salt reply already handled this connect
        qDebug() << "[AUTH] no auth_salt reply; using locally stored salt";
        deriveVerifierLocally();
        completeHello();
    });

    // TYPING INDICATOR: a single-shot timer that fires when the user has paused
    // for kTypingIdleMs after their last keystroke, at which point we tell the
    // peer we have gone idle so their "typing…" indicator clears. notifyTyping()
    // re-arms it on every keystroke, so it only fires during a genuine pause.
    m_typingTimer.setSingleShot(true);
    connect(&m_typingTimer, &QTimer::timeout, this, [this]() {
        if (!m_typingPeer.isEmpty())
            sendTypingState(m_typingPeer, QStringLiteral("idle"));
    });

    // POST-COMPROMISE SECURITY idle backstop. A repeating (not single-shot) timer
    // that, while connected, sends a rekey-ping to any peer that has unhealed sent
    // messages outstanding but no ping in flight -- closing the "a few one-way
    // messages, then silence" gap the message-count trigger would otherwise miss.
    // It is started on connect and stopped on logout; here we only set the period
    // and wire the handler. A quiescent conversation (nothing sent since the last
    // turn) generates no traffic because the per-peer counter is zero.
    m_rekeyTimer.setInterval(kPcsRekeyIdleMs);
    connect(&m_rekeyTimer, &QTimer::timeout, this, [this]() {
        if (m_socket.state() != QAbstractSocket::ConnectedState)
            return;
        // Copy the keys first: transmitRekey() can, in principle, re-enter map
        // mutation via signal handling, so we do not iterate the live hash.
        const QList<QString> peers = m_sentSinceRatchet.keys();
        for (const QString &peer : peers) {
            if (m_sentSinceRatchet.value(peer) > 0
                && !m_rekeyOutstanding.contains(peer)
                && !m_unverifiedKeyChange.contains(peer)
                && !m_pendingBilateral.contains(peer)
                && m_crypto.hasSessionFor(peer)) {
                if (transmitRekey(peer, /*isPong=*/false)) {
                    markRekeyPingSent(peer);
                } else {
                    m_rekeyKickTries = 0;       // fresh trigger: full retry budget
                    m_rekeyKickTimer.start();   // transient: retry promptly
                }
            }
        }
        // Any pongs we still owe (peer pinged us but our chain was not yet
        // sendable) are retried here too, so the idle backstop also closes them.
        if (!m_pongOwed.isEmpty()) {
            m_rekeyKickTries = 0;
            m_rekeyKickTimer.start();
        }
    });

    // POST-COMPROMISE SECURITY reliability: the short retry timer that re-attempts
    // a ping or pong lost to a transient not-ready state (typically the brief
    // re-bootstrap window right after a user switch). Single-shot: kickRekey()
    // re-arms it only while some rekey action still could not be sent, so it stops
    // on its own once the round-trip completes and never runs on a quiescent
    // channel. See kickRekey() and the m_pongOwed / m_rekeyKickTimer rationale.
    m_rekeyKickTimer.setSingleShot(true);
    m_rekeyKickTimer.setInterval(kPcsRekeyKickMs);
    connect(&m_rekeyKickTimer, &QTimer::timeout, this, &ChatClient::kickRekey);

    // LIFECYCLE (Android): learn when the OS backgrounds/foregrounds the app.
    // qApp is a QGuiApplication here (see main.cpp). On desktop this signal
    // still fires (e.g. on minimise/focus changes) and the handler is a
    // harmless no-op when there is nothing to flush, so the same code path is
    // correct on both platforms without #ifdefs.
    if (qApp) {
        connect(qApp, &QGuiApplication::applicationStateChanged,
                this, &ChatClient::onApplicationStateChanged);
    }

    // APP LOCK: the app does NOT start locked at a cold launch. The lock exists
    // to re-guard an ALREADY-LOGGED-IN, in-memory session (open conversations,
    // decrypted history); at construction no one has logged in yet, so there is
    // nothing decrypted to guard -- the identity is still encrypted at rest and
    // the user must supply the login password (the real root of trust) before
    // any of it is readable. Starting locked here put the lock overlay over the
    // login screen, and because Android auto-fires the biometric prompt, a
    // fingerprint tap simply revealed the login page underneath -- exactly the
    // "fingerprint takes me back to Login/Register" report. The lock instead
    // engages only while a session is live: on an explicit "Lock now", and (on
    // Android) when the app is backgrounded while logged in, re-showing on the
    // next foreground. See lockNow(), which is gated on m_sessionActive.
    m_locked = false;
}

// Static factory the QML engine invokes to build the singleton (see the header).
// Mirrors the setup the old main() performed before it exposed the controller.
ChatClient *ChatClient::create(QQmlEngine *, QJSEngine *)
{
    // BUILD MARKER: if this exact line does NOT appear at the very top of the
    // Application Output when you launch, then the binary being RUN is not the
    // binary just BUILT (a stale build artifact or wrong run configuration), and
    // no source change will take effect until that is resolved. This is the
    // definitive test for "my edits are not showing up / no [HISTORY] line".
    qDebug() << "[BUILD] ChatE2EE client start -- history-diagnostic build v3";

    auto *c = new ChatClient();
    const QString dataDir =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dataDir);
    qDebug() << "[HISTORY] create(): AppDataLocation resolved to"
             << (dataDir.isEmpty() ? QStringLiteral("(EMPTY!)") : dataDir);
    c->openHistory(dataDir);

    // ANDROID: register this instance as the one the JNI notification/shortcut
    // callbacks drive, then tell the Java activity the native side is ready so
    // any deep link that arrived during a cold launch is delivered now. Both
    // are no-ops off Android. Also post a file-received notification by
    // connecting the existing fileReceived signal here -- cleaner than editing
    // the two deeply-nested file-finalize branches, and it fires for every
    // completed inbound file. We notify only for files from the peer (fromNick
    // is the sender) that are not in the focused conversation.
    AndroidNotifier::setClient(c);
    // APP LOCK: register this same instance as the one the biometric success
    // callback (BiometricHelper.onAuthSucceeded -> applock.cpp) drives, so a
    // successful fingerprint actually clears the lock. Without this the callback
    // finds a null client and the fingerprint prompt appears to do nothing.
    // No-op-safe off Android (the pointer is simply stored and unused).
    AppLock::setClient(c);
    // APP LOCK (Android background privacy): when the lock is enabled, mark the
    // window FLAG_SECURE so the app's contents are excluded from the recent-apps
    // thumbnail and blocked from screenshots while it sits in the background. This
    // is the other half of "the lock works in the background": the app-state hook
    // re-locks on suspend, and this stops the last frame leaking in the task
    // switcher before the lock screen is shown on return. No-op off Android.
    AppLock::setSecure(c->lockEnabled());
    QObject::connect(c, &ChatClient::fileReceived, c,
        [c](const QString &, const QString &fromNick, const QString &filename,
            const QString &mime, qint64 size, const QString &) {
            Q_UNUSED(mime);
            if (fromNick == c->m_activePeer)
                return;   // focused conversation: the in-app row is enough
            const QString title =
                Localization::instance()->t("notif.newFileTitle").arg(fromNick);
            const QString body =
                Localization::instance()->t("notif.newFileBody")
                    .arg(filename, ChatClient::humanReadableSize(size));
            AndroidNotifier::notifyMessage(title, body, fromNick);
            DesktopNotifier::notify(title, body, fromNick);
        });
    AndroidNotifier::signalNativeReady();

    return c;
}

void ChatClient::openHistory(const QString &baseDir)
{
    // The database is per-user and the user is not known until login(), so
    // here we only remember the base directory. The actual open happens in
    // login() once we have a nickname. This is the fix for two clients on one
    // machine sharing (and corrupting) a single history file.
    m_historyBaseDir = baseDir;
}

// ===========================================================================
//  App lock (feature 2): a short PIN that gates the running UI, plus optional
//  biometric unlock. Deliberately SEPARATE from the login password:
//    * The login PASSWORD wraps the identity key at rest (strong boundary).
//    * The PIN only re-guards an ALREADY-UNLOCKED, in-memory session when the
//      app is backgrounded and returns -- like a phone lock screen over a
//      session that is already decrypted. It is NEVER able to decrypt the
//      identity key: if the process is killed, the password is required again.
//  So the PIN is stored only as an Argon2id VERIFIER (the same irreversible
//  primitive the server uses for the password), never in a form that can key
//  anything. A 4-6 digit PIN can therefore be convenient without becoming the
//  weakest link that protects the account's cryptographic identity.
//
//  Storage keys (QSettings, app-wide -- the lock is a device preference, like
//  dark mode, not a per-account secret):
//    lock/pinVerifier : hex Argon2id verifier of the PIN
//    lock/pinSalt     : hex salt the verifier was derived under
// ===========================================================================
bool ChatClient::hasPin() const
{
    QSettings s;
    return !s.value(QStringLiteral("lock/pinVerifier")).toString().isEmpty()
        && !s.value(QStringLiteral("lock/pinSalt")).toString().isEmpty();
}

void ChatClient::setPin(const QString &pin)
{
    QSettings s;
    if (pin.isEmpty()) {
        // Empty PIN clears the lock entirely.
        s.remove(QStringLiteral("lock/pinVerifier"));
        s.remove(QStringLiteral("lock/pinSalt"));
        if (m_locked) { m_locked = false; emit lockStateChanged(); }
        emit pinStateChanged();
        qDebug() << "[LOCK] PIN cleared";
        return;
    }
    // Derive a fresh Argon2id verifier + salt for the PIN (same primitive as the
    // password verifier, but an entirely separate secret and store).
    QString vHex, sHex;
    if (!CryptoBox::deriveVerifier(pin, vHex, sHex)) {
        emit errorOccurred(Localization::instance()->t("err.pinSetFailed"));
        return;
    }
    s.setValue(QStringLiteral("lock/pinVerifier"), vHex);
    s.setValue(QStringLiteral("lock/pinSalt"), sHex);
    emit pinStateChanged();
    qDebug() << "[LOCK] PIN set";
}

// ---- Lock enablement (platform-aware) --------------------------------------
bool ChatClient::lockEnabled() const
{
    QSettings s;
    return s.value(QStringLiteral("lock/enabled"), false).toBool();
}

bool ChatClient::usesOsCredential() const
{
#ifdef Q_OS_ANDROID
    // Android delegates unlock ENTIRELY to the OS credential (fingerprint/face +
    // the device PIN/pattern/password, offered by a single BiometricPrompt).
    // There is no app-PIN on Android under this model, so the OS credential is
    // the SOLE authenticator and QML shows no app-PIN field.
    return true;
#else
    // Desktop: this flag means "the OS credential is the ONLY way in". On desktop
    // it never is -- a custom app-PIN is ALWAYS set when the lock is enabled, and
    // Windows Hello (when present) is offered as an ADDITIONAL, convenience unlock
    // ALONGSIDE that PIN, never instead of it. So this is false on every desktop,
    // and QML reads biometricAvailable() SEPARATELY to decide whether to also show
    // the Windows Hello button next to the always-present PIN entry.
    //
    // (Bug fixed here: this previously returned biometricAvailable(), so on a
    // Hello-capable machine the settings toggle tried to enable the lock with an
    // EMPTY PIN -- but the Windows enable path requires a PIN as the Hello
    // fallback, so the call failed with "pinRequired" and the lock could not be
    // turned on at all. That is why the feature was "unavailable" on Windows.)
    return false;
#endif
}

void ChatClient::setLockEnabled(bool enabled, const QString &pin)
{
    QSettings s;
    if (!enabled) {
        // Turn the lock OFF entirely: clear the flag AND any app-PIN, and
        // unlock. Symmetric with the old setPin("") clear.
        s.setValue(QStringLiteral("lock/enabled"), false);
        s.remove(QStringLiteral("lock/pinVerifier"));
        s.remove(QStringLiteral("lock/pinSalt"));
        if (m_locked) { m_locked = false; emit lockStateChanged(); }
        emit pinStateChanged();
        AppLock::setSecure(false);   // stop blanking the task-switcher preview
        qDebug() << "[LOCK] lock disabled";
        return;
    }

#ifdef Q_OS_ANDROID
    // Android: the OS credential is the authenticator; no app-PIN is stored.
    // We only require that the device HAS a usable credential/biometric.
    if (!biometricAvailable()) {
        emit errorOccurred(Localization::instance()->t("err.noDeviceCredential"));
        return;
    }
    s.setValue(QStringLiteral("lock/enabled"), true);
    // Ensure no stale app-PIN lingers from a previous build.
    s.remove(QStringLiteral("lock/pinVerifier"));
    s.remove(QStringLiteral("lock/pinSalt"));
    emit pinStateChanged();
    AppLock::setSecure(true);   // blank the task-switcher preview while locked
    qDebug() << "[LOCK] lock enabled (Android OS credential)";
#else
    // Windows/desktop: a custom app-PIN is ALWAYS the primary way in, and Windows
    // Hello (when present) is offered as an ADDITIONAL unlock alongside it -- so a
    // PIN is required here regardless of whether Hello is available (satisfying
    // "Windows Hello and/or custom app PIN"). The PIN is stored only as an
    // Argon2id verifier, never in the clear, and never unlocks the identity key.
    if (pin.isEmpty()) {
        emit errorOccurred(Localization::instance()->t("err.pinRequired"));
        return;
    }
    QString vHex, sHex;
    if (!CryptoBox::deriveVerifier(pin, vHex, sHex)) {
        emit errorOccurred(Localization::instance()->t("err.pinSetFailed"));
        return;
    }
    s.setValue(QStringLiteral("lock/pinVerifier"), vHex);
    s.setValue(QStringLiteral("lock/pinSalt"), sHex);
    s.setValue(QStringLiteral("lock/enabled"), true);
    emit pinStateChanged();
    AppLock::setSecure(true);   // no-op on desktop; keeps the state symmetric
    qDebug() << "[LOCK] lock enabled (Windows: app-PIN + Windows Hello if present)";
#endif
}

bool ChatClient::resetLockWithPassword(const QString &password)
{
    // FORGOT PIN: the login PASSWORD is the root of trust (it wraps the identity
    // key), so proving it lets the user clear the lock and start over. We verify
    // the password by attempting to unlock the on-disk ENCRYPTED identity for
    // the current nickname (or the last-used one, if we are locked at startup
    // before a login). A throwaway CryptoBox is used so the live identity and
    // session state are never disturbed by the check.
    QString nick = m_nick;
    if (nick.isEmpty()) {
        QSettings s;
        nick = s.value(QStringLiteral("login/lastNickname")).toString();
    }
    if (nick.isEmpty()) {
        emit errorOccurred(Localization::instance()->t("err.resetNoAccount"));
        return false;
    }

    // Find the encrypted identity file for this nick in the same candidate dirs
    // establishIdentity uses.
    const QString ekeyName = nick + ".ekey";
    QString encPath;
    for (const QString &d : identityDirs()) {
        const QString p = d + "/" + ekeyName;
        if (QFile::exists(p) && CryptoBox::isEncryptedIdentityFile(p)) {
            encPath = p;
            break;
        }
    }
    if (encPath.isEmpty()) {
        emit errorOccurred(Localization::instance()->t("err.resetNoAccount"));
        return false;
    }

    // Verify the password by opening the wrapped identity in a throwaway box.
    CryptoBox probe;
    if (!probe.loadIdentityEncrypted(encPath, password)) {
        emit errorOccurred(Localization::instance()->t("err.wrongPassword"));
        return false;
    }

    // Correct password: clear the lock entirely and unlock. The user can then
    // re-enable it (and, on Windows, set a new fallback PIN) from settings.
    QSettings s;
    s.setValue(QStringLiteral("lock/enabled"), false);
    s.remove(QStringLiteral("lock/pinVerifier"));
    s.remove(QStringLiteral("lock/pinSalt"));
    if (m_locked) { m_locked = false; emit lockStateChanged(); }
    emit pinStateChanged();
    AppLock::setSecure(false);   // lock is off now: allow the preview again
    qDebug() << "[LOCK] lock reset via login password for" << nick;
    return true;
}

bool ChatClient::verifyPin(const QString &pin)
{
    QSettings s;
    const QString storedV = s.value(QStringLiteral("lock/pinVerifier")).toString();
    const QString storedS = s.value(QStringLiteral("lock/pinSalt")).toString();
    if (storedV.isEmpty() || storedS.isEmpty())
        return false;   // no PIN configured -> nothing to verify
    const QString candidate = CryptoBox::deriveVerifierWithSalt(pin, storedS);
    // Constant-time comparison of the two hex verifier strings via libsodium's
    // sodium_memcmp, which does not short-circuit on the first differing byte
    // (avoiding a timing side channel). Equal length is required by sodium_memcmp,
    // so we check that first; both are hex encodings of a fixed 32-byte value.
    bool ok = false;
    if (!candidate.isEmpty() && candidate.size() == storedV.size()) {
        const QByteArray a = candidate.toLatin1();
        const QByteArray b = storedV.toLatin1();
#ifdef HAVE_SODIUM
        ok = (sodium_memcmp(a.constData(), b.constData(),
                            static_cast<size_t>(a.size())) == 0);
#else
        ok = (a == b);
#endif
    }
    if (ok) {
        if (m_locked) {
            m_locked = false;
            emit lockStateChanged();
            // POST-COMPROMISE SECURITY, lifecycle heal: same rationale as the
            // biometric unlock path -- a legitimate unlock after the app was
            // locked forces a rekey round-trip so security is reestablished for
            // future messages even when the socket stayed alive across the lock.
            reestablishPcsForAll("unlock/pin");
        }
        qDebug() << "[LOCK] PIN accepted";
    } else {
        qDebug() << "[LOCK] PIN rejected";
    }
    return ok;
}

void ChatClient::clearPin()
{
    setPin(QString());   // empty == clear
}

void ChatClient::lockNow()
{
    if (!lockEnabled())
        return;   // lock not enabled; nothing to show
    if (!m_sessionActive)
        return;   // no logged-in session to guard -- never lock over the login
                  // screen. Without this, backgrounding the app (Android) or an
                  // errant lock before login would show the lock over LoginPage,
                  // and unlocking would just reveal the login page again.
    if (!m_locked) {
        m_locked = true;
        emit lockStateChanged();
        qDebug() << "[LOCK] locked";
    }
}

bool ChatClient::biometricAvailable() const
{
    return AppLock::biometricAvailable();
}

void ChatClient::requestBiometricUnlock()
{
    if (!m_locked || !lockEnabled())
        return;
    // Delegates to the platform bridge; on success the native side calls
    // onBiometricSucceeded() back on the Qt thread. On Android this shows the OS
    // prompt offering fingerprint/face AND the device PIN; on Windows it shows
    // Windows Hello.
    AppLock::requestUnlock(this);
}

void ChatClient::onBiometricSucceeded()
{
    if (m_locked) {
        m_locked = false;
        emit lockStateChanged();
        qDebug() << "[LOCK] biometric accepted";
        // POST-COMPROMISE SECURITY, lifecycle heal. The app was LOCKED -- the
        // device was in an untrusted state, and on desktop the socket stayed
        // alive across the lock, so no reconnect fires to trigger the heal. Now
        // that a legitimate unlock has happened, force a rekey round-trip with
        // every established peer so security is reestablished for future
        // messages, exactly as after a reconnect. No-op if nothing is
        // established or we are momentarily offline (the kick timer covers it).
        reestablishPcsForAll("unlock/biometric");
    }
}

// ---- Biometric / Windows Hello LOGIN --------------------------------------
// Thin drivers over the AppLock bridge; the actual wrapping/unwrapping and the
// OS prompt live there (Android Keystore / Windows DPAPI + Hello). See the
// header for how this differs from the app lock.

bool ChatClient::biometricLoginAvailable() const
{
    return AppLock::loginAvailable();
}

bool ChatClient::hasBiometricLogin(const QString &nick) const
{
    return AppLock::hasLoginEnrolled(nick.trimmed());
}

// ---------------------------------------------------------------------------
// Password recovery ("Forgotten password?")
// ---------------------------------------------------------------------------
//
// The honest description of what happens here, because it is easy to overstate:
// nothing is recovered from the account. The password is retrieved from THIS
// DEVICE's biometric-gated vault, which only exists if the user previously
// logged in successfully and opted in. On any other device the answer is "not
// possible", and that is the correct answer rather than a missing feature.
//
// The server cannot help even in principle: it holds an Argon2id verifier, an
// irreversible hash. Building a server-side reveal would mean storing passwords
// recoverably, which would defeat the purpose of hashing them at all.

QString ChatClient::normalizeBirthday(const QString &birthday) const
{
    // Accept the formats a Finnish, Swedish or English speaker would plausibly
    // type, and reduce them to one canonical ISO form before hashing. Without
    // this, "3.5.1999" and "1999-05-03" would derive different verifiers and a
    // user who typed their own birthday correctly would be told it was wrong.
    const QString in = birthday.trimmed();
    if (in.isEmpty())
        return QString();

    static const char *formats[] = {
        "yyyy-MM-dd", "d.M.yyyy", "dd.MM.yyyy",
        "d/M/yyyy", "dd/MM/yyyy", "yyyy/MM/dd", "d-M-yyyy",
    };
    for (const char *f : formats) {
        const QDate d = QDate::fromString(in, QString::fromLatin1(f));
        if (d.isValid()) {
            // Reject dates that cannot belong to a living user. This is a
            // sanity check on typing, not a security control.
            const QDate today = QDate::currentDate();
            if (d > today || d.year() < 1900)
                return QString();
            return d.toString(QStringLiteral("yyyy-MM-dd"));
        }
    }
    return QString();
}

void ChatClient::storeBirthdayVerifier(const QString &nick, const QString &isoDate)
{
    QString vHex, sHex;
    if (!CryptoBox::deriveVerifier(isoDate, vHex, sHex))
        return;
    QSettings st;
    st.setValue(QStringLiteral("recovery/%1/dobVerifier").arg(nick), vHex);
    st.setValue(QStringLiteral("recovery/%1/dobSalt").arg(nick), sHex);
    st.sync();
}

bool ChatClient::checkBirthday(const QString &nick, const QString &isoDate) const
{
    QSettings st;
    const QString storedV =
        st.value(QStringLiteral("recovery/%1/dobVerifier").arg(nick)).toString();
    const QString storedS =
        st.value(QStringLiteral("recovery/%1/dobSalt").arg(nick)).toString();
    if (storedV.isEmpty() || storedS.isEmpty())
        return false;

    const QString candidate =
        CryptoBox::deriveVerifierWithSalt(isoDate, storedS);
    if (candidate.isEmpty() || candidate.size() != storedV.size())
        return false;

    // Constant-time comparison. The attacker in the realistic threat model
    // already holds the device, so this is defence in depth rather than the
    // main control -- but a comparison that returns early on the first wrong
    // character is a bad habit to leave in security code.
    quint8 diff = 0;
    const QByteArray a = candidate.toLatin1();
    const QByteArray b = storedV.toLatin1();
    for (int i = 0; i < a.size(); ++i)
        diff |= static_cast<quint8>(a[i] ^ b[i]);
    return diff == 0;
}

bool ChatClient::passwordRecoveryAvailable(const QString &nickname) const
{
    const QString n = nickname.trimmed();
    if (n.isEmpty())
        return false;
    if (!AppLock::hasLoginEnrolled(n))
        return false;   // nothing in the vault on this device
    QSettings st;
    return !st.value(QStringLiteral("recovery/%1/dobVerifier").arg(n))
                .toString().isEmpty();
}

void ChatClient::recoverPassword(const QString &serverUrl,
                                 const QString &nickname,
                                 const QString &birthday)
{
    const QString n = nickname.trimmed();
    if (n.isEmpty()) {
        emit passwordRecoveryFailed(tr("Please enter your username."));
        return;
    }

    const QString iso = normalizeBirthday(birthday);
    if (iso.isEmpty()) {
        emit passwordRecoveryFailed(
            tr("That is not a valid date. Use the form 1999-05-03."));
        return;
    }

    // RATE LIMIT. A birthday is a small secret: a few tens of thousands of
    // plausible dates, and far fewer for someone the attacker knows. It is
    // never the security boundary here (the OS prompt is), but throttling
    // guesses costs nothing and keeps the weak factor from being free to grind.
    QSettings st;
    const QString failKey  = QStringLiteral("recovery/%1/failures").arg(n);
    const QString untilKey = QStringLiteral("recovery/%1/lockedUntil").arg(n);
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 lockedUntil = st.value(untilKey, 0).toLongLong();
    if (now < lockedUntil) {
        const qint64 mins = (lockedUntil - now + 59) / 60;
        emit passwordRecoveryFailed(
            tr("Too many attempts. Try again in %1 minute(s).").arg(mins));
        return;
    }

    if (!AppLock::hasLoginEnrolled(n)) {
        // The honest message. Anything vaguer would imply the account could be
        // recovered elsewhere, which it cannot.
        emit passwordRecoveryFailed(
            tr("This device cannot recover that password. Recovery works only "
               "on a device where you previously logged in and switched on "
               "fingerprint or Windows Hello sign-in. The server never stores "
               "your password, so it cannot be looked up."));
        return;
    }

    if (!checkBirthday(n, iso)) {
        const int failures = st.value(failKey, 0).toInt() + 1;
        st.setValue(failKey, failures);
        if (failures >= 5) {
            st.setValue(untilKey, now + 15 * 60);
            st.setValue(failKey, 0);
            st.sync();
            emit passwordRecoveryFailed(
                tr("Too many attempts. Try again in 15 minutes."));
            return;
        }
        st.sync();
        emit passwordRecoveryFailed(
            tr("The username and date of birth do not match."));
        return;
    }

    // The birthday matched. Reset the counter and hand over to the OS: from
    // here the platform prompt is the actual gate.
    st.setValue(failKey, 0);
    st.remove(untilKey);
    st.sync();

    m_revealOnly = true;
    m_bioLoginServerUrl = serverUrl.trimmed().isEmpty() ? lastServerUrl()
                                                        : serverUrl.trimmed();
    qDebug() << "[RECOVERY] birthday verified for" << n
             << "- requesting device authentication";
    AppLock::loginWithBiometric(this, m_bioLoginServerUrl, n);
}

void ChatClient::biometricLogin(const QString &serverUrl, const QString &nick)
{
    const QString n = nick.trimmed();
    if (n.isEmpty() || serverUrl.trimmed().isEmpty())
        return;
    if (!AppLock::hasLoginEnrolled(n))
        return;   // nothing enrolled for this account; leave password login
    // Remember the server URL for the callback; the OS prompt is asynchronous
    // and onBiometricLoginUnlocked() will run login() with it on success.
    m_bioLoginServerUrl = serverUrl.trimmed();
    qDebug() << "[LOGIN] biometric login requested for" << n;
    AppLock::loginWithBiometric(this, m_bioLoginServerUrl, n);
}

void ChatClient::requestBiometricLoginEnroll(const QString &password)
{
    // Hold the password only in memory; it is written to the platform vault
    // only once the server confirms the login (in the "keys" handler), so a
    // rejected password never enrolls. Cleared in logout() as a backstop.
    m_bioEnrollPassword = password;
    m_bioEnrollPending = !password.isEmpty();
    // DIAGNOSTIC (temporary): confirms the login screen asked to enrol. If this
    // does NOT appear when you tick the box and press Log in / Register, the
    // QML wiring is not calling through; if it DOES appear but no
    // "[LOGIN] biometric login enrolled after confirmed login" follows, the
    // login was not confirmed (server rejected / no keys dump) or the flag was
    // cleared by a disconnect first.
    qDebug() << "[LOGIN] enroll requested; pending =" << m_bioEnrollPending;
}

void ChatClient::disableBiometricLogin(const QString &nick)
{
    AppLock::clearLogin(nick.trimmed());
    emit biometricLoginChanged();
    qDebug() << "[LOGIN] biometric login disabled for" << nick.trimmed();
}

void ChatClient::onBiometricLoginUnlocked(const QString &nick,
                                          const QString &password)
{
    // The OS released the stored password after a successful biometric/Hello
    // check. Run the ordinary login with the server URL stashed by
    // biometricLogin(). A wrong/empty recovery is ignored (login() would fail
    // locally anyway); the user can still type their password.
    if (password.isEmpty()) {
        if (m_revealOnly) {
            m_revealOnly = false;
            emit passwordRecoveryFailed(
                tr("The device released nothing. Please try again."));
        }
        return;
    }

    // RECOVERY BRANCH. The OS has just proved the user's presence and released
    // the vault copy. In recovery we DISPLAY it instead of logging in. The flag
    // is cleared first so any later biometric login behaves normally even if
    // the user abandons this screen.
    if (m_revealOnly) {
        m_revealOnly = false;
        qDebug() << "[RECOVERY] vault released for" << nick
                 << "- revealing to the user (not logging in)";
        // Deliberately NOT logged, not stored, not sent. It goes to the UI and
        // nowhere else.
        emit passwordRevealed(password);
        return;
    }

    const QString url = m_bioLoginServerUrl.isEmpty()
                            ? lastServerUrl() : m_bioLoginServerUrl;
    const QString n = nick.trimmed().isEmpty() ? m_nick : nick.trimmed();
    if (url.isEmpty() || n.isEmpty())
        return;
    qDebug() << "[LOGIN] biometric login unlocked; logging in as" << n;
    login(url, n, password);
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

QString ChatClient::lastNickname() const
{
    // The nickname used at the last successful login (written in login()).
    // Empty on first run; the login screen leaves its placeholder showing then.
    QSettings settings;
    return settings.value(QStringLiteral("login/lastNickname")).toString();
}

QString ChatClient::lastServerUrl() const
{
    // The server address string used at the last successful login. Empty on
    // first run, in which case the login screen keeps its own default value.
    QSettings settings;
    return settings.value(QStringLiteral("login/lastServerUrl")).toString();
}

// ---- PER-USER THEME -----------------------------------------------------
// The number of colour presets defined in Main.qml. Kept here ONLY to clamp a
// nickname-derived default into range; QML owns the actual preset table, and
// setThemeIndex() stores whatever index QML sends without consulting this, so
// adding a preset in QML needs no change here. If you add presets and want the
// auto-assigned defaults to spread across all of them, bump this to match.
static constexpr int kThemePresetCount = 6;

int ChatClient::themeIndex() const
{
    // If the CURRENT user has explicitly chosen a preset, return it. The key is
    // per-nickname ("theme/<nick>") so every user on this device keeps their own
    // choice independently, exactly as lastNickname is per-device.
    if (!m_nick.isEmpty()) {
        QSettings settings;
        const QString key = QStringLiteral("theme/") + m_nick;
        if (settings.contains(key)) {
            bool ok = false;
            const int v = settings.value(key).toInt(&ok);
            if (ok && v >= 0 && v < kThemePresetCount)
                return v;
        }
    }

    // No stored choice (a brand-new user, or none logged in yet): derive a
    // STABLE default from the nickname so two different users get two different
    // accents on first login, while the SAME nickname always maps to the same
    // colour. A simple FNV-1a-style hash over the UTF-8 bytes, reduced modulo the
    // preset count. Empty nickname (pre-login) maps to preset 0.
    if (m_nick.isEmpty())
        return 0;
    quint32 h = 2166136261u;
    const QByteArray bytes = m_nick.toUtf8();
    for (unsigned char c : bytes) {
        h ^= c;
        h *= 16777619u;
    }
    return int(h % quint32(kThemePresetCount));
}

void ChatClient::setThemeIndex(int index)
{
    // Persist the CURRENT user's choice and recolour the UI live. No-op on the
    // store if nobody is logged in (no nickname to key on), but we still emit so
    // any transient binding refreshes. We do not clamp to kThemePresetCount here
    // beyond a sanity floor, so QML remains the single source of truth for how
    // many presets exist; a negative index is ignored as clearly invalid.
    if (index < 0)
        return;
    if (!m_nick.isEmpty()) {
        QSettings settings;
        settings.setValue(QStringLiteral("theme/") + m_nick, index);
    }
    emit themeChanged();
}

bool ChatClient::darkMode() const
{
    // App-wide (not per-nickname): brightness is a device preference. Defaults
    // to true so the first-run look is the original dark theme.
    QSettings settings;
    return settings.value(QStringLiteral("ui/darkMode"), true).toBool();
}

void ChatClient::setDarkMode(bool dark)
{
    if (dark == darkMode())
        return;                       // no change; avoid a redundant recolour
    QSettings settings;
    settings.setValue(QStringLiteral("ui/darkMode"), dark);
    emit darkModeChanged();
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
            // Text row: stored re-sealed under our static local key (derived
            // from our identity key). localOpen returns empty if the row cannot
            // be authenticated -- which happens for rows written under a PREVIOUS
            // identity key (e.g. after an identity reset / desync recovery),
            // since the at-rest key changed with the identity. Do NOT add a
            // blank bubble in that case: show a small placeholder so the user
            // understands an older message exists but can no longer be read.
            const QString plaintext =
                m_crypto.localOpen(r.nonceHex, r.ctHex);
            if (!plaintext.isEmpty()) {
                // Pass the stable id so a RESTORED text message is still
                // addressable for delete / react / edit / resend after a restart
                // (previously the mid was dropped here, so those actions silently
                // did nothing on reopened conversations). Then, if it was edited,
                // light its "edited" marker to match how it looked live.
                m_messages.addMessage(r.sender, plaintext, r.ts, r.mine, r.mid);
                if (r.edited)
                    m_messages.markEditedByMid(r.mid);
            } else {
                m_messages.addSystem(
                    Localization::instance()->t("sys.cannotDecrypt"));
            }
        }
    }

    // Reactions are stored separately (keyed by message id) and re-applied here,
    // AFTER every message row has been replayed, so each badge lands on its row
    // regardless of the order the reactions were originally received. "me" is
    // our own reaction, "peer" the other party's; a mid no longer present (e.g.
    // whose message was never stored) is simply skipped by applyReaction.
    const QList<HistoryStore::ReactionRow> reacts =
        m_history.reactionsForPeer(peer);
    for (const HistoryStore::ReactionRow &r : reacts) {
        m_messages.applyReaction(r.mid, r.who == QLatin1String("me"), r.kind);
    }
}

void ChatClient::login(const QString &serverUrl, const QString &nickname,
                       const QString &password)
{
    m_nick = nickname.trimmed();
    m_serverUrl = QUrl(serverUrl);
    m_users.setSelfName(m_nick);
    m_registering = false;

    // Remember these credentials for next time so the login screen can pre-fill
    // them (see lastNickname()/lastServerUrl()). We store the RAW server string
    // as the user typed it (not the parsed QUrl) so it round-trips verbatim.
    // Nothing secret is stored here -- the nickname and server address are not
    // secrets; the identity PRIVATE key is never written to QSettings, only to
    // the verified key file handled below.
    {
        QSettings settings;
        settings.setValue(QStringLiteral("login/lastNickname"), m_nick);
        settings.setValue(QStringLiteral("login/lastServerUrl"), serverUrl);
    }

    // Open this user's own history database now that we know the nickname.
    // Each local user gets a separate file (history_<nick>.db), so two
    // clients running on one machine never read or clobber each other's rows.
    //
    // DEFENSIVE (blank-history fix): previously this was guarded by
    //   if (!m_historyBaseDir.isEmpty()) m_history.open(...);
    // with no else and no logging, so if m_historyBaseDir was ever empty (e.g.
    // AppDataLocation resolved empty in create(), or openHistory() never ran),
    // open() was SILENTLY NEVER CALLED -- no table was created, every read/write
    // no-opped, and history was blank on every peer and every login, with NOTHING
    // in the log to show why. We now (1) fall back to resolving the base dir here
    // if it is empty, (2) log exactly what we resolved and what open() returned,
    // and (3) surface a visible message if it still fails.
    QString baseDir = m_historyBaseDir;
    if (baseDir.isEmpty()) {
        const QList<QStandardPaths::StandardLocation> locs{
            QStandardPaths::AppDataLocation,
            QStandardPaths::AppLocalDataLocation,
            QStandardPaths::AppConfigLocation,
            QStandardPaths::GenericDataLocation
        };
        for (const auto loc : locs) {
            const QString d = QStandardPaths::writableLocation(loc);
            if (!d.isEmpty()) { baseDir = d; break; }
        }
        qWarning() << "[HISTORY] m_historyBaseDir was empty; resolved base dir to"
                   << (baseDir.isEmpty() ? QStringLiteral("(still empty!)")
                                         : baseDir);
    }

    if (!baseDir.isEmpty()) {
        QDir().mkpath(baseDir);
        const bool opened = m_history.open(baseDir, m_nick);
    // RESTORE PERSISTED VERIFICATION (fix: repeated safety-number prompts).
    // These two maps are the user's own confirmation and the peer's attestation.
    // They were previously in-memory only, so every logout discarded them and the
    // next login re-opened an episode for an already-verified peer. Reloading
    // them here, immediately after the per-user database opens and before any
    // key dump is processed, is what makes the short-circuit in the key handlers
    // able to see that this exact key was already confirmed.
    if (opened && m_history.isReady()) {
        m_verifiedPeerIdentity = m_history.loadVerifiedPeerIdentities();
        const QHash<QString, QString> attest = m_history.loadPeerAttestations();
        for (auto it = attest.cbegin(); it != attest.cend(); ++it)
            m_peerVerifiedForIdentity.insert(it.key(), it.value());
        // A peer who attested the identity we still hold has verified us; that
        // half of the gate is satisfied and must not be re-requested.
        const QString mine = m_crypto.publicKeyHex();
        for (auto it = attest.cbegin(); it != attest.cend(); ++it)
            if (!mine.isEmpty() && it.value() == mine)
                m_peerVerified.insert(it.key());
        qDebug() << "[VERIFY] restored" << m_verifiedPeerIdentity.size()
                 << "confirmed peer key(s) and" << attest.size()
                 << "peer attestation(s) from disk";
    }
        qDebug() << "[HISTORY] login: open(" << baseDir << "," << m_nick
                 << ") ->" << (opened ? "OK" : "FAILED")
                 << "isReady =" << m_history.isReady();
        if (!opened) {
            m_messages.addSystem(
                Localization::instance()->t("sys.historyOpenFailed"));
            emit errorOccurred(
                Localization::instance()->t("err.historyOpenFailed"));
        }
    } else {
        qWarning() << "[HISTORY] login: NO writable base directory found; "
                      "history cannot be opened.";
        m_messages.addSystem(
            Localization::instance()->t("sys.noStorage"));
    }

    // ---- PERMANENT IDENTITY (Threema-style, verify-and-fallback) -----------
    // The identity key pair must be generated ONCE and reused for the life of
    // the installation, so a given nickname is a stable, permanent identity
    // across restarts on BOTH desktop and Android.
    //
    // Investigation established, from device logs, that on the Android target the
    // key was written to the correct private path and read back true WITHIN a
    // run (`[IDENTITY-SAVE] ... exists now? true`), yet a fresh process found it
    // absent (`[IDENTITY-CHECK] ... exists? false`) at the SAME path with the
    // SAME nickname. That eliminates a path or nickname mismatch: the file is
    // simply not surviving the process boundary in that one location. Rather than
    // depend on a single location, we now:
    //
    //   (1) Build a PRIORITISED LIST of candidate directories.
    //   (2) On first run, write the key to a candidate and immediately VERIFY it
    //       by reading it back through a FRESH QFile handle; keep the first
    //       location whose write survives that round-trip, and log which won.
    //   (3) On later runs, SEARCH the same list (highest priority first) for an
    //       existing key and load it. Because we always try locations in the same
    //       order, the run that saved and the run that loads agree on where to
    //       look.
    //
    // This is robust to whichever environmental cause is behind the Android
    // disappearance (data cleared per launch, file-engine redirection, or a
    // scoped-storage discard): if a location does not persist, its write fails
    // the read-back and we move on; the surviving location is used consistently.
    //
    // DESIGN B: the private key is stored ENCRYPTED under `password` (Argon2id
    // + secretbox). establishIdentity() performs the open-or-create against the
    // candidate directories, reusing the same verify-and-fallback persistence
    // the raw path used, but through saveIdentityEncrypted/loadIdentityEncrypted.
    // For a LOGIN a wrong password fails inside it (the secretbox will not open),
    // so we stop before touching the socket. It also migrates a legacy raw key.
    if (!establishIdentity(m_nick, password, /*isRegister=*/false)) {
        // establishIdentity already emitted a clear errorOccurred (wrong
        // password, or no local account -> please register). Do not proceed to
        // open the socket; there is no usable identity.
        return;
    }

    // Stash the PASSWORD for the auth handshake. We no longer derive the
    // verifier eagerly here: onConnected() -> beginAuthHandshake() first asks
    // the server for this account's stored SALT (auth_begin) so the verifier we
    // send is derived under the SAME salt on every device, which is what makes a
    // correct password match regardless of which device registered. The password
    // is held only in memory and cleared in logout(); it is never written to
    // disk. If the server does not answer (older build), we fall back to the
    // salt saved locally in QSettings -- see deriveVerifierLocally().
    m_pendingPassword = password;
    m_pendingVerifierHex.clear();
    m_pendingSaltHex.clear();

    // Restore any ratchet sessions saved in a previous run, so conversations
    // that were mid-flight can keep decrypting after a restart. Must happen
    // after the identity is loaded and after history is open.
    restoreAllSessions();

    // Restore any offline outbox (messages/files composed while disconnected in
    // a previous run) so they are re-sent once the connection returns. Also
    // after history is open; the actual send happens in flushOutbox() on connect.
    restoreOutbox();

    m_intentionalClose = false;
    openSocketWithTls();
}

// ---- Design B: register a brand-new account --------------------------------
void ChatClient::registerAccount(const QString &serverUrl,
                                 const QString &nickname,
                                 const QString &password,
                                 const QString &birthday)
{
    m_nick = nickname.trimmed();

    // BIRTHDAY (required for every new account).
    //
    // Derived into an irreversible Argon2id verifier with its own random salt,
    // exactly like the password. Two copies are kept and neither is the date:
    //
    //   * the verifier goes to the server once, in the hello, so the account
    //     record is complete (the server refuses a new password-protected
    //     account without it, close code 4003);
    //   * the verifier AND its salt are kept locally, because the
    //     "Forgotten password?" check runs on the device. Checking it against
    //     the server instead would turn the relay into an oracle for guessing
    //     birthdays, which is a very small search space.
    //
    // The date itself is never written anywhere, in either place.
    m_pendingDobVerifierHex.clear();
    const QString isoDob = normalizeBirthday(birthday);
    if (!isoDob.isEmpty()) {
        QString dobVerifierHex, dobSaltHex;
        if (CryptoBox::deriveVerifier(isoDob, dobVerifierHex, dobSaltHex)) {
            m_pendingDobVerifierHex = dobVerifierHex;
            QSettings st;
            st.setValue(QStringLiteral("recovery/%1/dobVerifier").arg(m_nick),
                        dobVerifierHex);
            st.setValue(QStringLiteral("recovery/%1/dobSalt").arg(m_nick),
                        dobSaltHex);
            st.sync();
            qDebug() << "[AUTH] birthday verifier recorded for" << m_nick;
        } else {
            qWarning() << "[AUTH] could not derive a birthday verifier";
        }
    } else if (!birthday.trimmed().isEmpty()) {
        qWarning() << "[AUTH] birthday could not be parsed; not recorded";
    }

    m_serverUrl = QUrl(serverUrl);
    m_users.setSelfName(m_nick);
    m_registering = true;

    // Persist the login fields for pre-fill, exactly as login() does. Nothing
    // secret here -- the nickname and server address are not secrets, and the
    // password is never written anywhere in plaintext.
    {
        QSettings settings;
        settings.setValue(QStringLiteral("login/lastNickname"), m_nick);
        settings.setValue(QStringLiteral("login/lastServerUrl"), serverUrl);
    }

    // Open this user's history DB now that we know the nickname (same resilient
    // resolution login() uses). Kept identical so both entry points behave the
    // same with respect to storage.
    QString baseDir = m_historyBaseDir;
    if (baseDir.isEmpty()) {
        const QList<QStandardPaths::StandardLocation> locs{
            QStandardPaths::AppDataLocation,
            QStandardPaths::AppLocalDataLocation,
            QStandardPaths::AppConfigLocation,
            QStandardPaths::GenericDataLocation
        };
        for (const auto loc : locs) {
            const QString d = QStandardPaths::writableLocation(loc);
            if (!d.isEmpty()) { baseDir = d; break; }
        }
    }
    if (!baseDir.isEmpty()) {
        QDir().mkpath(baseDir);
        const bool opened = m_history.open(baseDir, m_nick);
    // RESTORE PERSISTED VERIFICATION (fix: repeated safety-number prompts).
    // These two maps are the user's own confirmation and the peer's attestation.
    // They were previously in-memory only, so every logout discarded them and the
    // next login re-opened an episode for an already-verified peer. Reloading
    // them here, immediately after the per-user database opens and before any
    // key dump is processed, is what makes the short-circuit in the key handlers
    // able to see that this exact key was already confirmed.
    if (opened && m_history.isReady()) {
        m_verifiedPeerIdentity = m_history.loadVerifiedPeerIdentities();
        const QHash<QString, QString> attest = m_history.loadPeerAttestations();
        for (auto it = attest.cbegin(); it != attest.cend(); ++it)
            m_peerVerifiedForIdentity.insert(it.key(), it.value());
        // A peer who attested the identity we still hold has verified us; that
        // half of the gate is satisfied and must not be re-requested.
        const QString mine = m_crypto.publicKeyHex();
        for (auto it = attest.cbegin(); it != attest.cend(); ++it)
            if (!mine.isEmpty() && it.value() == mine)
                m_peerVerified.insert(it.key());
        qDebug() << "[VERIFY] restored" << m_verifiedPeerIdentity.size()
                 << "confirmed peer key(s) and" << attest.size()
                 << "peer attestation(s) from disk";
    }
        qDebug() << "[HISTORY] register: open(" << baseDir << "," << m_nick
                 << ") ->" << (opened ? "OK" : "FAILED");
        if (!opened)
            emit errorOccurred(
                Localization::instance()->t("err.historyOpenFailed"));
    }

    // Create the wrapped identity. FAILS if one already exists for this nick,
    // steering the user to Log in instead.
    if (!establishIdentity(m_nick, password, /*isRegister=*/true))
        return;   // establishIdentity emitted a clear message; do not connect.

    // Derive a FRESH server verifier + salt for the new account and remember the
    // salt locally so a future login (or another device) can re-derive the same
    // verifier. Both are sent in the hello; the server stores them on first
    // registration. Registration is the one case that legitimately mints a new
    // salt (the account does not exist yet), so we derive here directly rather
    // than fetching a salt that is not there. We ALSO stash the password so that
    // an automatic reconnect during this session can re-authenticate (the fix
    // for the reconnect rejection loop): on reconnect the account now exists, so
    // beginAuthHandshake() will fetch the salt we just registered and re-derive
    // the identical verifier.
    m_pendingPassword = password;
    {
        QString vHex, sHex;
        if (CryptoBox::deriveVerifier(password, vHex, sHex)) {
            m_pendingVerifierHex = vHex;
            m_pendingSaltHex = sHex;
            QSettings settings;
            settings.setValue(QStringLiteral("auth/verifierSalt/") + m_nick,
                              sHex);
        } else {
            emit errorOccurred(
                Localization::instance()->t("err.registerFailed"));
            return;
        }
    }

    restoreAllSessions();   // none for a new account, but harmless + symmetric
    restoreOutbox();

    m_intentionalClose = false;
    openSocketWithTls();
}

// ---- Design B: shared identity open-or-create ------------------------------
QStringList ChatClient::identityDirs() const
{
    QStringList candidateDirs;
    candidateDirs << QStandardPaths::writableLocation(
                         QStandardPaths::AppDataLocation)
                  << QStandardPaths::writableLocation(
                         QStandardPaths::AppLocalDataLocation)
                  << QStandardPaths::writableLocation(
                         QStandardPaths::AppConfigLocation)
                  << QStandardPaths::writableLocation(
                         QStandardPaths::GenericDataLocation);
    QStringList dirs;
    for (const QString &d : candidateDirs)
        if (!d.isEmpty() && !dirs.contains(d))
            dirs << d;
    return dirs;
}

bool ChatClient::hasLocalIdentity(const QString &nickname) const
{
    const QString nick = nickname.trimmed();
    if (nick.isEmpty())
        return false;
    const QString ekey = nick + ".ekey";   // Design B encrypted key
    const QString rkey = nick + ".key";     // legacy raw key (migrated on login)
    for (const QString &d : identityDirs()) {
        if (QFile::exists(d + "/" + ekey)) return true;
        if (QFile::exists(d + "/" + rkey)) return true;
    }
    return false;
}

bool ChatClient::establishIdentity(const QString &nick,
                                   const QString &password,
                                   bool isRegister)
{
    const QString ekeyName = nick + ".ekey";   // encrypted (Design B)
    const QString rkeyName = nick + ".key";     // legacy raw
    const QStringList dirs = identityDirs();

    // Locate an existing encrypted key, or a legacy raw key, in priority order.
    QString existingEnc, existingRaw;
    for (const QString &d : dirs) {
        const QString ep = d + "/" + ekeyName;
        if (existingEnc.isEmpty() && QFile::exists(ep)
            && CryptoBox::isEncryptedIdentityFile(ep))
            existingEnc = ep;
        const QString rp = d + "/" + rkeyName;
        if (existingRaw.isEmpty() && QFile::exists(rp))
            existingRaw = rp;
    }

    qDebug() << "[IDENTITY-CHECK] nick =" << nick
             << "| register =" << isRegister
             << "| encrypted =" << (existingEnc.isEmpty() ? "(none)" : existingEnc)
             << "| legacyRaw =" << (existingRaw.isEmpty() ? "(none)" : existingRaw);

    // ---- REGISTER -----------------------------------------------------------
    if (isRegister) {
        if (!existingEnc.isEmpty() || !existingRaw.isEmpty()) {
            // A local identity already exists: registration would either clash
            // with it or silently mint a second one. Tell the user to log in.
            emit errorOccurred(
                Localization::instance()->t("err.accountExistsLocally"));
            return false;
        }
        // Fresh identity, then save it ENCRYPTED to the first location whose
        // write survives a fresh-handle read-back (same crux as the raw path).
        m_crypto.generateIdentity();
        QString savedTo;
        for (const QString &d : dirs) {
            QDir().mkpath(d);
            const QString p = d + "/" + ekeyName;
            if (!m_crypto.saveIdentityEncrypted(p, password)) {
                qWarning() << "[IDENTITY] encrypted save failed at" << p
                           << "-- trying next";
                continue;
            }
            // Verify persistence AND that the password round-trips, using a
            // throwaway CryptoBox so the live identity is untouched.
            CryptoBox probe;
            if (probe.loadIdentityEncrypted(p, password)
                && probe.publicKeyHex() == m_crypto.publicKeyHex()) {
                savedTo = p;
                qDebug() << "[IDENTITY] created + saved encrypted identity at"
                         << p << "(verified) public =" << m_crypto.publicKeyHex();
                break;
            }
            qWarning() << "[IDENTITY] wrote encrypted key to" << p
                       << "but read-back verification FAILED -- trying next";
        }
        if (savedTo.isEmpty()) {
            emit errorOccurred(
                Localization::instance()->t("err.identityNotPersisted"));
            return false;
        }
        return true;
    }

    // ---- LOGIN --------------------------------------------------------------
    // Prefer an existing encrypted key.
    if (!existingEnc.isEmpty()) {
        if (m_crypto.loadIdentityEncrypted(existingEnc, password)) {
            qDebug() << "[IDENTITY] unlocked encrypted identity from"
                     << existingEnc << "public =" << m_crypto.publicKeyHex();
            return true;
        }
        // The file exists but the password did not open it: WRONG PASSWORD.
        // Do NOT regenerate or overwrite -- the account is intact, the password
        // was simply wrong.
        emit errorOccurred(Localization::instance()->t("err.wrongPassword"));
        return false;
    }

    // No encrypted key. Migrate a legacy RAW key if present: load it, re-wrap it
    // under the new password, write the encrypted file, and remove the raw one.
    if (!existingRaw.isEmpty()) {
        if (!m_crypto.loadIdentity(existingRaw)) {
            emit errorOccurred(
                Localization::instance()->t("err.identityUnreadable"));
            return false;
        }
        // Re-wrap under the password beside the raw file.
        const QString encPath =
            QFileInfo(existingRaw).absolutePath() + "/" + ekeyName;
        if (m_crypto.saveIdentityEncrypted(encPath, password)) {
            CryptoBox probe;
            if (probe.loadIdentityEncrypted(encPath, password)
                && probe.publicKeyHex() == m_crypto.publicKeyHex()) {
                QFile::remove(existingRaw);   // retire the plaintext key
                qDebug() << "[IDENTITY] migrated legacy raw key to encrypted at"
                         << encPath;
                return true;
            }
        }
        // Migration write failed: keep the raw key (do not lose the identity),
        // but proceed with the loaded identity for THIS session so the user is
        // not locked out; next login will retry the migration.
        qWarning() << "[IDENTITY] legacy->encrypted migration could not be "
                      "persisted; continuing this session with the loaded key.";
        return true;
    }

    // Nothing exists for this nick: the user has no account here.
    emit errorOccurred(Localization::instance()->t("err.noAccountHere"));
    return false;
}

void ChatClient::logout()
{
    // Log out cleanly and return to the login screen. This tears down the LIVE
    // session (socket, on-screen state, open DB handle) but PRESERVES everything
    // persisted on disk -- the identity key file and the per-user history
    // database -- so logging back in as the same nickname restores the full
    // conversation history and all ratchet sessions. This is deliberately NOT a
    // "delete my account" action; it is a session end.
    //
    // Order matters:
    //   1. Mark the close intentional and stop the reconnect timer, so
    //      onDisconnected() does NOT schedule a reconnect (it checks this flag).
    //   2. Close the socket.
    //   3. Clear the on-screen conversation and reset the active peer, so no
    //      previous user's messages linger behind the login screen.
    //   4. Close the per-user history DB handle, so a subsequent login() can
    //      open the (possibly different) next user's database cleanly. The
    //      FILE is left on disk untouched.
    //   5. Emit loggedOut() so Main.qml pops the StackView back to login.
    m_intentionalClose = true;
    m_reconnectTimer.stop();
    m_socket.close();

    // ANDROID: stop the foreground service -- the user is leaving the session,
    // so the process no longer needs to be kept resident, and the ongoing
    // notification should disappear. No-op off Android.
    AndroidNotifier::stopService();

    // TYPING INDICATOR teardown: stop the idle timer and forget all typing
    // state, ours and every peer's, so a stale "typing…" never lingers behind
    // the login screen or leaks into the next user's session. We do not try to
    // send a final "idle" -- the socket is already closing.
    m_typingTimer.stop();
    m_typingPeer.clear();
    m_lastTypingStateSent.clear();
    m_peerTyping.clear();

    // On-screen state: empty the message list and drop the active-peer
    // selection (with the notify so any bindings update).
    m_messages.clear();
    if (!m_activePeer.isEmpty()) {
        m_activePeer.clear();
        emit activePeerChanged();
    }

    // Close (but do NOT delete) this user's history database, releasing the
    // connection so the next login() can open a fresh one. close() is the public
    // wrapper around HistoryStore's internal teardown (closeIfOpen), which also
    // drops the named connection so re-opening the same user later does not warn
    // about a duplicate connection name. The FILE is left on disk untouched.
    m_history.close();

    // FULL IN-MEMORY RESET FOR USER SWITCHING (the fix for "conversations fail
    // after switching users"). ChatClient is a QML singleton, so the SAME
    // instance is reused when a different person logs in after logout. Every
    // per-user table below therefore survives logout unless we clear it, and any
    // that carries over corrupts the next user's session:
    //
    //   * m_crypto holds ratchet sessions + peer identities bootstrapped from
    //     THIS user's private key. If User B inherits them, every decrypt is
    //     attempted against a chain keyed to User A's identity and fails silently
    //     (haveKey/hasSession true, but decrypt empty -- exactly the reported
    //     symptom). resetForNewUser() wipes sessions, peer identities, and the
    //     keypair; login() reloads/regenerates the identity immediately after.
    //   * m_peerKeys / m_peerIdentity map peer nicks to keys as seen by THIS
    //     user; stale entries would mismatch the next user's view.
    //   * m_seenFrames is the per-peer dedup set; carrying it over could wrongly
    //     drop the next user's first frames.
    //   * m_pendingFrames are frames stashed awaiting a key under THIS user.
    //   * m_outbox holds queued sends; the persisted copies live in THIS user's
    //     history DB and are reloaded by restoreOutbox() when they log back in,
    //     so dropping the in-memory queue here loses nothing and prevents a
    //     queued message from being sent from the WRONG user's session. We do
    //     NOT purge the persisted outbox here: a same-user logout/login must keep
    //     its offline queue, and restoreOutbox() already applies an IDENTITY
    //     GUARD on load -- dropping any file/handshake row whose identity stamp
    //     does not match the identity actually in force at the next login. That
    //     is the precise point at which a cross-identity row (a file queued by a
    //     previous user, the phantom-file cause) is discarded, without endanger-
    //     ing a legitimate same-user queue.
    //   * m_unverifiedKeyChange, and the in-flight file maps, are likewise
    //     per-user and must not leak across a switch.
    //
    // Nothing on disk is touched, so switching BACK to a previous user restores
    // their identity, history, and sessions through the normal login path.
    m_crypto.resetForNewUser();
    m_peerKeys.clear();
    // The published Ed25519 forms are the same per-user directory cache as
    // m_peerKeys and go with it. Leaving them behind let a previous user's
    // entry outlive the switch, which the bundle-binding check above would then
    // measure a new user's peer against.
    m_peerEdKeys.clear();
    // Learned per connection, not per install: the next login may be to a relay
    // that states its key types perfectly well.
    m_relayServesUntaggedEd = false;
    m_seenFrames.clear();
    m_pendingFrames.clear();
    m_outbox.clear();
    m_unverifiedKeyChange.clear();
    // POST-COMPROMISE SECURITY: stop the idle backstop and the short retry timer
    // and drop all per-peer rekey accounting, including any pongs we still owed
    // and any lifecycle heals we had parked. These are per-user, in-memory, and
    // non-persistent: a later login (same or different user) simply starts fresh
    // windows, so nothing is lost by clearing them and nothing must survive a
    // switch. clearPcsState() is the full-teardown counterpart to resetPcsFor().
    clearPcsState();
    // BILATERAL VERIFICATION: per-user gate state must not leak across a switch.
    m_peerVerified.clear();
    m_pendingBilateral.clear();
    // Deadlock-fix bookkeeping is likewise per-user and in-memory: the
    // re-bootstrap one-shot markers and the verifyack-resend set start empty for
    // the next user (a switch-back re-establishes them through the normal login
    // + key-dump path).
    m_rebootstrapAdopted.clear();
    m_verifyAckResend.clear();
    m_peerVerifiedForIdentity.clear();
    m_verifiedPeerIdentity.clear();
    m_lastVerifyResyncMs.clear();
    m_outgoing.clear();
    m_incoming.clear();
    m_receivedFilePaths.clear();
    m_flushInProgress = false;

    // CREDENTIAL WIPE: the password was held in memory only to let automatic
    // reconnects during THIS session re-authenticate. The session is over, so
    // clear it (and any derived verifier) and stop a pending salt fetch. Nothing
    // here was ever on disk.
    m_pendingPassword.clear();
    m_pendingVerifierHex.clear();
    m_pendingSaltHex.clear();
    m_authSaltTimer.stop();

    // Backstop: if a biometric-login enroll was pending but the login never
    // reached the confirmed-login hook (e.g. the server rejected the password
    // and closed the socket, routing us here), drop the held password so it is
    // never enrolled and never lingers in memory.
    m_bioEnrollPending = false;
    m_bioEnrollPassword.clear();

    // Connection state may already have flipped via onDisconnected(); make sure
    // QML sees us as disconnected regardless of close timing.
    if (m_connected) {
        m_connected = false;
        emit connectionStateChanged();
    }

    // The live session is over: the lock must not engage over the login screen.
    // (This also covers the auth-rejection path, where onDisconnected() calls
    // logout() after a 4000/4001/4002 close.) If the app happened to be locked,
    // clear it so the user is returned to a clean login page, not a lock overlay.
    m_sessionActive = false;
    if (m_locked) {
        m_locked = false;
        emit lockStateChanged();
    }

    emit loggedOut();
}

void ChatClient::onConnected()
{
    m_connected = true;
    m_reconnectDelayMs = 1000;  // reset back-off on a successful connect
    emit connectionStateChanged();

    // TLS EVIDENCE: the handshake has completed by the time this slot runs, so
    // the negotiated protocol, cipher and peer certificate can now be read back
    // and published. Reaching here at all over wss:// already means the chain
    // and hostname verified, because onSslErrors() never ignores anything -- a
    // failed verification aborts the connection instead of arriving here.
    describeTlsSession();

    // AUTH FIRST. We do NOT send the hello immediately any more. If a password
    // is pending (a fresh login/register, or a reconnect that still holds the
    // password), beginAuthHandshake() asks the server for this account's stored
    // salt so the verifier we send is derived under the SAME salt on every
    // device -- the fix for "correct password rejected". The hello then goes out
    // in completeHello(), reached when the salt reply arrives (or, against an
    // older server, when the fallback timer lapses). With no pending password
    // (e.g. a legacy password-less account) beginAuthHandshake() sends the hello
    // straight away.
    //
    // loggedIn() is emitted here as before so the UI advances to the chat page
    // on connect; a subsequent auth rejection (wrong password / reserved name /
    // signed in elsewhere) is surfaced by onDisconnected() with a clear message.
    // A live session now exists, so the app lock may engage (on background /
    // explicit lock). Setting this on every connect is idempotent: a transient
    // reconnect re-affirms it, and it is cleared only by logout(). This is what
    // lets the lock guard the session while never appearing over the login page.
    m_sessionActive = true;
    emit loggedIn();

    // POST-COMPROMISE SECURITY: rotate the signed prekey if it is old, and
    // destroy the previous one once nothing can still be using it. The signed
    // prekey is the responder's INITIAL RATCHET KEY, so its lifetime bounds how
    // long a compromise of it stays useful -- moving off the identity key bought
    // nothing on its own, because a signed prekey that never rotates is simply a
    // second permanent key.
    if (m_crypto.hasX3dhIdentity() && m_crypto.hasPrekeys()) {
        const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
        const bool rotated =
            m_crypto.rotateSignedPrekeyIfDue(kSpkMaxAgeMs, nowMs);
        const bool dropped =
            m_crypto.dropExpiredPreviousPrekey(kSpkGraceMs, nowMs);
        if (rotated || dropped) {
            if (m_history.isReady())
                m_history.savePrekeys(m_crypto.serialisePrekeys());
            // A rotated prekey must reach the relay, or peers keep fetching a
            // bundle built from the key we just retired.
            if (rotated)
                publishPrekeysIfNeeded(/*force=*/true);
        }
    }

    // X3DH: make sure this account has a prekey bundle on the relay. Publishing
    // happens after login because the relay binds prekeys to the authenticated
    // nick, and it happens on EVERY login because the relay hands out one-time
    // prekeys and never gets them back -- a pool left to drain to empty silently
    // downgrades every new conversation to the weaker no-OPK agreement.
    publishPrekeysIfNeeded();

    // POST-COMPROMISE SECURITY: begin the idle backstop timer now that a live
    // session exists. It is a REPEATING timer, stopped only on logout, so once it
    // is running it must NOT be restarted on a reconnect: QTimer::start() on a
    // running timer resets its countdown, and on the phone -- where Doze causes
    // frequent reconnects -- restarting it on every connect perpetually deferred
    // the 15-minute backstop so it could never fire (leaving a low-volume one-way
    // conversation un-healed until the next full message-count trigger). Starting
    // it only when it is not already active preserves a steady 15-minute cadence
    // across reconnects. The handler no-ops when no peer has unhealed sent
    // messages and when the socket is momentarily down, so a free-running timer is
    // harmless on quiescent or briefly-disconnected conversations.
    if (!m_rekeyTimer.isActive())
        m_rekeyTimer.start();

    // RELIABILITY: a rekey (ping or owed pong) that could not be sent because the
    // socket had dropped should retry NOW that we are back, not after the 15-minute
    // idle backstop. Kick a retry pass if any rekey work is pending; it no-ops and
    // does not re-arm when there is nothing to do.
    if (!m_pongOwed.isEmpty() || !m_sentSinceRatchet.isEmpty()) {
        m_rekeyKickTries = 0;
        m_rekeyKickTimer.start();
    }

    beginAuthHandshake();
}

void ChatClient::beginAuthHandshake()
{
    if (!m_pendingPassword.isEmpty()) {
        // Ask the server for the salt this account's verifier must be derived
        // under. The hello is deferred until the reply (onAuthSalt via the
        // handleServerFrame "auth_salt" branch) or the fallback timer.
        QJsonObject req{{"type", "auth_begin"}, {"nick", m_nick}};
        m_socket.sendTextMessage(
            QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));
        qDebug() << "[AUTH] auth_begin sent for" << m_nick
                 << "-- awaiting salt";
        m_authSaltTimer.start(3000);   // old-server fallback
        return;
    }
    // No password on this account (legacy password-less login): nothing to
    // derive, so proceed straight to the hello.
    completeHello();
}

void ChatClient::deriveVerifierLocally()
{
    // Fallback derivation used when the server does not answer auth_begin (an
    // older server): derive the verifier from the pending password under the
    // salt saved in QSettings at registration, or a fresh salt if none exists
    // (a legacy account adding a password, which the server then stores). This
    // is exactly the behaviour login() had before the salt exchange was added,
    // so an out-of-date server keeps working.
    if (m_pendingPassword.isEmpty())
        return;
    QSettings settings;
    const QString saltKey = QStringLiteral("auth/verifierSalt/") + m_nick;
    const QString storedSalt = settings.value(saltKey).toString();
    if (!storedSalt.isEmpty()) {
        m_pendingVerifierHex =
            CryptoBox::deriveVerifierWithSalt(m_pendingPassword, storedSalt);
        m_pendingSaltHex = storedSalt;
    } else {
        QString vHex, sHex;
        if (CryptoBox::deriveVerifier(m_pendingPassword, vHex, sHex)) {
            m_pendingVerifierHex = vHex;
            m_pendingSaltHex = sHex;
            settings.setValue(saltKey, sHex);
        }
    }
}

void ChatClient::completeHello()
{
    // Stop the fallback timer in case it is still pending (the salt reply won
    // the race). Then send the hello with whatever verifier we derived.
    m_authSaltTimer.stop();
    uploadPublicKey();

    // ANDROID: now that we are genuinely connected, (re)create the notification
    // channels with the localized names (the language is known by now) and start
    // the foreground service so the OS keeps this process -- and thus the socket
    // and ratchet -- alive when the app is backgrounded, which is what lets
    // background messages be decrypted and shown with content. Both are no-ops
    // off Android. ensureChannels is idempotent, so calling it on every connect
    // is harmless and keeps the channel names in the current language.
    {
        Localization *loc = Localization::instance();
        AndroidNotifier::ensureChannels(loc->t("notif.channelName"),
                                        loc->t("notif.serviceRunning"),
                                        loc->t("notif.serviceBody"));
        AndroidNotifier::startService(loc->t("notif.serviceRunning"),
                                      loc->t("notif.serviceBody"));
    }
    // The socket is genuinely connected now: encrypt and send anything the user
    // composed while offline. Doing it here (and ONLY here) guarantees the
    // ratchet advances solely for frames that actually go out over a live
    // socket, which is what keeps the two ends' chains in step.
    flushOutbox();

    // POST-COMPROMISE SECURITY, lifecycle heal. We have just (re)authenticated on
    // a live socket. If this is a RECONNECT (dropped socket, an Android
    // background/screen-lock freeze) or a SAME-user log out then log back in, the
    // ratchet chains were restored byte-identically from disk -- so a compromise
    // captured before the interruption is still valid until fresh DH entropy is
    // folded in. Force a rekey round-trip with every established peer now, so
    // security is reestablished immediately rather than after the 32-message /
    // 15-minute heartbeat. On a brand-new login there are no established chains
    // yet, so this is a no-op; the very first message to a peer bootstraps a fresh
    // chain and is inherently PCS-fresh anyway.
    reestablishPcsForAll("reconnect/relogin");
}

void ChatClient::onDisconnected()
{
    m_connected = false;
    emit connectionStateChanged();

    // The TLS description belongs to the session that just ended; leaving it on
    // screen would claim a secure transport that no longer exists. A failure
    // message set by onSslErrors() is deliberately preserved, because that is
    // the one case where the user needs to know WHY the connection dropped.
    if (!m_tlsSummary.startsWith(QStringLiteral("TLS verification FAILED"))) {
        m_tlsSummary.clear();
        emit tlsSummaryChanged();
    }

    // A salt exchange in flight is now moot; stop its timer so it cannot fire
    // against a dead socket.
    m_authSaltTimer.stop();

    // AUTH REJECTION HANDLING (the other half of the reconnect-loop fix). The
    // server closes with a distinct code when a hello is refused:
    //   4000  signed in on another device
    //   4001  username reserved to a different identity
    //   4002  wrong password
    // These are PERMANENT for this attempt -- reconnecting would send the same
    // (or, worse, a verifier-less) hello and be refused identically, which is
    // exactly the endless reject/reconnect loop that made "conversations fail"
    // on the desktop. So on any of these we do NOT reconnect: we surface one
    // clear message and return the UI to the login screen via logout().
    const int code = static_cast<int>(m_socket.closeCode());
    if (code == 4000 || code == 4001 || code == 4002) {
        qDebug() << "[AUTH] server rejected login, close code" << code
                 << "-- not reconnecting";
        emit errorOccurred(Localization::instance()->t("err.loginRejected"));
        logout();
        return;
    }

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
    openSocketWithTls();
}

// ---------------------------------------------------------------------------
// TLS: trust anchors, strict verification, and evidence
// ---------------------------------------------------------------------------
//
// This section replaced an earlier approach that connected to localhost with a
// self-signed certificate and then called ignoreSslErrors() to make the
// resulting complaints go away. That worked, but it demonstrated only half of
// TLS: the traffic was encrypted, yet nothing checked WHO was on the other end,
// which is the half that stops an attacker in the network path from simply
// presenting their own certificate.
//
// The replacement is a private certificate authority generated by
// tools/make_demo_pki.py. Its root is compiled into this binary as a trust
// anchor, and the relay serves a leaf signed by that root. Verification is then
// switched fully ON: the chain is built and checked, the signature is checked,
// the validity dates are checked, and the hostname is matched against the
// certificate's SubjectAlternativeName. Nothing is ignored anywhere.
//
// A certificate authority is not a special kind of institution; it is a key
// pair whose public half some client has decided to trust ahead of time. A
// public CA is trusted because the OS vendor shipped it in the system store.
// This root is trusted because the application carries it. The protocol
// behaviour, the chain building and the failure modes are identical -- which is
// exactly why this is a faithful demonstration and not a shortcut.

QList<QSslCertificate> ChatClient::labTrustAnchors()
{
    // Cached: this touches the resource system and possibly the filesystem, and
    // it is consulted on every connect and reconnect. The contents cannot change
    // during a run (the compiled-in copy is fixed, and the optional override
    // path is read once), so caching costs nothing in correctness.
    static QList<QSslCertificate> cached;
    static bool loaded = false;
    if (loaded)
        return cached;
    loaded = true;

    // Primary source: the root compiled into the binary. Shipping it inside the
    // executable rather than reading a file next to it means it cannot be
    // swapped out by dropping a different file into the application directory.
    QFile embedded(QStringLiteral(":/pki/demo-ca.crt"));
    if (embedded.open(QIODevice::ReadOnly)) {
        const QList<QSslCertificate> certs =
            QSslCertificate::fromData(embedded.readAll(), QSsl::Pem);
        for (const QSslCertificate &c : certs)
            if (!c.isNull())
                cached << c;
        embedded.close();
    }

    // Optional override: a PEM path in QSettings. This exists so that
    // regenerating the root (tools/make_demo_pki.py --force) does not force a
    // client rebuild during development. It is empty unless explicitly set, and
    // it ADDS an anchor rather than replacing the compiled-in one.
    QSettings settings;
    const QString extra =
        settings.value(QStringLiteral("tls/labCaPath")).toString().trimmed();
    if (!extra.isEmpty()) {
        QFile f(extra);
        if (f.open(QIODevice::ReadOnly)) {
            const QList<QSslCertificate> certs =
                QSslCertificate::fromData(f.readAll(), QSsl::Pem);
            for (const QSslCertificate &c : certs)
                if (!c.isNull() && !cached.contains(c))
                    cached << c;
            f.close();
            qDebug() << "[TLS] extra lab anchor loaded from" << extra;
        } else {
            qWarning() << "[TLS] tls/labCaPath set but unreadable:" << extra;
        }
    }

    if (cached.isEmpty()) {
        qWarning() << "[TLS] no lab trust anchor is available. Connections to a "
                      "local or LAN relay will fail verification. Generate one "
                      "with tools/make_demo_pki.py and rebuild.";
    } else {
        for (const QSslCertificate &c : std::as_const(cached))
            qDebug() << "[TLS] lab anchor:" << c.subjectInfo(QSslCertificate::CommonName)
                     << "sha256:"
                     << c.digest(QCryptographicHash::Sha256).toHex(':').toUpper();
    }
    return cached;
}

bool ChatClient::isLabHost(const QUrl &url)
{
    // Scoping rule for the private anchor. It applies ONLY to hosts that are on
    // this machine or on the local network, because that is the only place the
    // lab relay can be. A public hostname is therefore always validated against
    // the public PKI alone, and the presence of the lab root grants no
    // authority over any internet host.
    const QString host = url.host().trimmed();
    if (host.isEmpty())
        return false;

    if (host.compare(QLatin1String("localhost"), Qt::CaseInsensitive) == 0)
        return true;

    QHostAddress addr(host);
    if (addr.isNull())
        return false;   // a DNS name that is not "localhost": treat as public

    if (addr.isLoopback())
        return true;

    // The private ranges are tested explicitly rather than via
    // QHostAddress::isPrivateUse(), which only exists from Qt 6.6 onwards --
    // this file must still compile against the 6.5 minimum declared in
    // CMakeLists.txt. Writing the masks out also makes the policy auditable at
    // a glance, which matters for a decision about what to trust.
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 v4 = addr.toIPv4Address();
        if ((v4 & 0xFF000000u) == 0x0A000000u) return true;   // 10.0.0.0/8
        if ((v4 & 0xFFF00000u) == 0xAC100000u) return true;   // 172.16.0.0/12
        if ((v4 & 0xFFFF0000u) == 0xC0A80000u) return true;   // 192.168.0.0/16
        if ((v4 & 0xFFFF0000u) == 0xA9FE0000u) return true;   // 169.254.0.0/16
        return false;
    }

    if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
        // Unique local addresses, fc00::/7 -- the IPv6 equivalent of RFC 1918.
        const Q_IPV6ADDR v6 = addr.toIPv6Address();
        if ((v6[0] & 0xFE) == 0xFC)
            return true;
        return addr.isLinkLocal();   // fe80::/10
    }

    return false;
}

QSslConfiguration ChatClient::sslConfigurationFor(const QUrl &url) const
{
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();

    // These two lines are the substance of the change. VerifyPeer means the
    // certificate chain MUST validate or the handshake fails; it is also Qt's
    // default for clients, and it is set explicitly here so that the intent is
    // visible in the code rather than inherited silently.
    cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);

    // Refuse everything below TLS 1.2, matching the floor the relay sets in
    // server.py's make_ssl_context(). Both ends stating the same minimum means
    // a downgrade cannot be negotiated even if one side were misconfigured.
    cfg.setProtocol(QSsl::TlsV1_2OrLater);

    if (isLabHost(url)) {
        const QList<QSslCertificate> anchors = labTrustAnchors();
        if (!anchors.isEmpty()) {
            // APPEND to the system CAs rather than replacing them. Replacing
            // would mean a lab build could no longer validate anything public,
            // and would make the two modes behave differently for no reason.
            QList<QSslCertificate> cas = cfg.caCertificates();
            for (const QSslCertificate &c : anchors)
                if (!cas.contains(c))
                    cas << c;
            cfg.setCaCertificates(cas);
            qDebug() << "[TLS] lab trust anchor active for" << url.host();
        }
    }

    return cfg;
}

void ChatClient::openSocketWithTls()
{
    // Single funnel for every connect and reconnect. Applying the configuration
    // immediately before open() matters because QWebSocket reads it at that
    // moment, and because m_serverUrl can change between attempts (the user may
    // log out and point the app at a different relay).
    if (m_serverUrl.scheme().compare(QLatin1String("wss"), Qt::CaseInsensitive) == 0)
        m_socket.setSslConfiguration(sslConfigurationFor(m_serverUrl));

    m_socket.open(m_serverUrl);
}

void ChatClient::describeTlsSession()
{
    // Read back what was actually negotiated, so the application can state its
    // transport security as fact rather than as intent.
    if (m_serverUrl.scheme().compare(QLatin1String("wss"), Qt::CaseInsensitive) != 0) {
        m_tlsSummary = QStringLiteral("Not encrypted (ws://) - development only");
        qWarning() << "[TLS]" << m_tlsSummary;
        emit tlsSummaryChanged();
        return;
    }

    const QSslConfiguration cfg = m_socket.sslConfiguration();
    const QSslCipher cipher = cfg.sessionCipher();
    const QSslCertificate peer = cfg.peerCertificate();

    QString protocol;
    switch (cfg.sessionProtocol()) {
    case QSsl::TlsV1_2:      protocol = QStringLiteral("TLS 1.2"); break;
    case QSsl::TlsV1_3:      protocol = QStringLiteral("TLS 1.3"); break;
    case QSsl::UnknownProtocol: protocol = QStringLiteral("unknown"); break;
    default:                 protocol = QStringLiteral("other"); break;
    }

    const QString issuer = peer.isNull()
        ? QStringLiteral("(no peer certificate)")
        : peer.issuerInfo(QSslCertificate::CommonName).join(QStringLiteral(", "));
    const QString subject = peer.isNull()
        ? QString()
        : peer.subjectInfo(QSslCertificate::CommonName).join(QStringLiteral(", "));
    const QString fp = peer.isNull()
        ? QString()
        : QString::fromLatin1(
              peer.digest(QCryptographicHash::Sha256).toHex(':').toUpper());
    const QString anchor = isLabHost(m_serverUrl)
        ? QStringLiteral("lab root CA (compiled in)")
        : QStringLiteral("public CA (system trust store)");

    m_tlsSummary =
        QStringLiteral("%1, %2\nserver: %3\nissued by: %4\ntrust anchor: %5\n"
                       "certificate SHA-256: %6\nbackend: %7")
            .arg(protocol,
                 cipher.isNull() ? QStringLiteral("unknown cipher") : cipher.name(),
                 subject, issuer, anchor, fp,
                 QSslSocket::activeBackend());

    // One compact line for the log stream, and the full block for the UI.
    qDebug().noquote() << "[TLS]" << protocol << cipher.name()
                       << "| issuer:" << issuer
                       << "| anchor:" << anchor
                       << "| backend:" << QSslSocket::activeBackend();

    emit tlsSummaryChanged();
}

void ChatClient::onSslErrors(const QList<QSslError> &errors)
{
    // NOTHING IS IGNORED HERE, AND NOTHING SHOULD EVER BE ADDED THAT DOES.
    //
    // Reaching this slot means verification failed. With the lab certificate
    // authority in place there is no longer any legitimate reason for a demo or
    // development connection to produce certificate errors, so an error now
    // carries real information: either the relay is serving a certificate that
    // does not chain to a trusted root, or the hostname does not match, or a
    // certificate has expired -- or someone is genuinely interposing.
    //
    // The previous implementation forgave SelfSignedCertificate,
    // CertificateUntrusted and HostNameMismatch when the host was localhost.
    // That is exactly the behaviour this project should be able to argue
    // against, so the exception is gone.
    QStringList msgs;
    for (const QSslError &e : errors) {
        qWarning() << "[TLS] verification failed:" << e.error() << e.errorString();
        msgs << e.errorString();
    }

    // A targeted hint for the most likely cause during a lab demo, since the
    // raw Qt message ("The certificate is self-signed, and untrusted") does not
    // point at the fix.
    if (isLabHost(m_serverUrl) && labTrustAnchors().isEmpty()) {
        msgs << QStringLiteral(
            "no lab trust anchor is compiled in - run tools/make_demo_pki.py, "
            "copy pki/ca.crt to client/pki/demo-ca.crt, and rebuild");
    }

    m_tlsSummary = QStringLiteral("TLS verification FAILED: ") + msgs.join(QStringLiteral("; "));
    emit tlsSummaryChanged();
    emit errorOccurred(QStringLiteral("TLS error: ") + msgs.join(QStringLiteral("; ")));
}


void ChatClient::uploadPublicKey()
{
    // Tell the server which offline files we ALREADY have, so it does not replay
    // them to us again (the fix for phantom file transfers on every login). This
    // list comes from our own database; after a data wipe it is empty, so the
    // server re-sends every file -- the intended "files survive a data wipe"
    // behaviour. In steady state it lists everything we hold, so the server sends
    // nothing and no duplicate transfer notifications appear.
    QJsonArray haveFiles;
    for (const QString &id : m_history.receivedFileIds())
        haveFiles.append(id);

    // IDENTITY PUBLICATION. A version 2 account publishes its Ed25519 key, not
    // the X25519 one derived from it. That is what X3DH needs: the signed
    // prekey in a bundle is signed with the identity, and only the Ed25519 key
    // can verify that signature. Peers derive the agreement key from it
    // themselves, so one published key does both jobs.
    //
    // "ik_type" travels with it because both kinds are 32 bytes and a peer
    // cannot tell them apart. Guessing is not an option -- an Ed25519 key read
    // as X25519 yields a Diffie-Hellman the peer never matches, and the
    // conversation just fails to decrypt with nothing to point at. A version 1
    // account sends "x25519" and behaves exactly as before.
    const bool v2 = m_crypto.hasX3dhIdentity();
    QJsonObject hello{
                      {"type", "hello"},
                      {"nick", m_nick},
                      {"pubkey", v2 ? m_crypto.edPublicKeyHex()
                                    : m_crypto.publicKeyHex()},
                      {"ik_type", v2 ? QStringLiteral("ed25519")
                                     : QStringLiteral("x25519")},
                      {"have_files", haveFiles},
                      };

    // DESIGN B credential: include the Argon2id verifier + salt when we have one
    // derived for this connect (set by beginAuthHandshake/onAuthSalt, or the
    // local-salt fallback). The server stores it on first registration and
    // compares it on every later login, rejecting a mismatch with close code
    // 4002 BEFORE sending any keys or history. The password itself is never
    // here -- only the irreversible verifier.
    if (!m_pendingVerifierHex.isEmpty() && !m_pendingSaltHex.isEmpty()) {
        hello.insert("pw_verifier", m_pendingVerifierHex);
        hello.insert("pw_salt", m_pendingSaltHex);
        // Sent only on a REGISTER. A returning user is never asked for a
        // birthday, so an existing account can never be locked out by this.
        if (m_registering && !m_pendingDobVerifierHex.isEmpty())
            hello.insert("dob_verifier", m_pendingDobVerifierHex);
        qDebug() << "[AUTH] hello carries" << (m_registering ? "REGISTER" : "LOGIN")
                 << "verifier for" << m_nick;
    }
    // Clear only the per-connect DERIVED copies so the irreversible verifier
    // does not linger; the PASSWORD stays in m_pendingPassword so an automatic
    // reconnect can re-derive and re-authenticate (the reconnect-loop fix). The
    // password is wiped only in logout(). m_registering is reset here because a
    // reconnect is never a fresh registration.
    m_pendingVerifierHex.clear();
    m_pendingSaltHex.clear();
    m_registering = false;

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

void ChatClient::persistSession(const QString &peer)
{
    // Save a peer's ratchet session after it advances (called from the send and
    // receive paths). The session is stored as an opaque blob in local history,
    // alongside the peer identity it is bound to, so a conversation can keep
    // ratcheting across an app restart and the stored session can be validated
    // against that identity on reload.
    if (m_history.isReady())
        m_history.saveSession(peer, m_crypto.exportSession(peer),
                              m_crypto.peerIdentityHex(peer),
                              m_sentSinceRatchet.value(peer, 0));
}

void ChatClient::persistAllSessions()
{
    // Flush every peer we currently hold a session for. Called from the
    // lifecycle hook when the app is about to be suspended, so that no advanced-
    // but-unsaved chain state is lost if Android subsequently kills the process
    // while it is in the background. We iterate the peers we know a key for --
    // exportSession() returns empty for any without a live session, and
    // saveSession() on an empty blob is a harmless no-op guarded below.
    if (!m_history.isReady())
        return;
    for (auto it = m_peerKeys.cbegin(); it != m_peerKeys.cend(); ++it) {
        const QString &peer = it.key();
        const QByteArray blob = m_crypto.exportSession(peer);
        if (!blob.isEmpty())
            m_history.saveSession(peer, blob, m_crypto.peerIdentityHex(peer),
                                  m_sentSinceRatchet.value(peer, 0));
    }
}

void ChatClient::restoreAllSessions()
{
    // Re-import every persisted ratchet session from disk into CryptoBox, so a
    // session saved on the way to the background (or in a previous run) is
    // RESUMED rather than lazily re-bootstrapped from the identity keys. A
    // re-bootstrap on one side while the peer keeps ratcheting the old session
    // is precisely what desynchronises the two chains and makes text -- but not
    // files -- silently fail. Restoring the saved state keeps both ends in step.
    if (!m_history.isReady())
        return;
    const QStringList peers = m_history.sessionPeers();
    for (const QString &peer : peers) {
        // ORDER MATTERS. importSession() validates the stored session's identity
        // stamp against the peer identity CryptoBox currently holds. At login
        // that identity is not yet known (it arrives later, in the server's
        // key/keys frames), so we must first seed it from what we persisted
        // alongside the session. setPeerIdentity() records it with no side
        // effects; then importSession() can check the stamp and either resume
        // the session (identities match) or reject it (identities changed) so a
        // clean bootstrap happens on the next message. Skip peers whose stored
        // identity is missing/invalid -- their session cannot be validated and
        // is left for a fresh bootstrap.
        const QString peerId = m_history.loadPeerIdentity(peer);
        if (!peerId.isEmpty())
            m_crypto.setPeerIdentity(peer, peerId);
        const bool imported =
            m_crypto.importSession(peer, m_history.loadSession(peer));
        if (!imported) {
            // The stored session failed validation -- almost always because it
            // was saved under an identity that no longer exists (during the
            // period before identity persistence was fixed, a fresh identity was
            // generated every launch, so every session was stamped with a key
            // that is now dead). importSession() correctly rejects such a
            // session, but if we leave the row in the database it is re-loaded
            // and re-rejected on EVERY restart, so the conversation can never
            // recover. Clearing it here makes the recovery self-healing: the
            // dead session is removed once, and the next message bootstraps a
            // fresh chain against the now-permanent identities. Sessions saved
            // from this point on carry a matching stamp and restore normally.
            qDebug() << "[SESSION] stored session for" << peer
                     << "failed validation (stale identity stamp) -- clearing "
                        "it so a fresh session is bootstrapped on the next "
                        "message.";
            m_history.clearSession(peer);
        } else {
            qDebug() << "[SESSION] restored persistent session for" << peer;
            // POST-COMPROMISE SECURITY: restore this peer's one-way send counter
            // so the 32-message rekey threshold survives a process kill mid-burst.
            // Only for a session that actually imported -- a rejected (stale)
            // session bootstraps fresh and starts from zero. qMax avoids
            // REGRESSING a counter that is already higher in memory:
            // restoreAllSessions also runs on foreground return, where the live
            // count can be a message or two ahead of the last persisted value, and
            // we must never move the recovery window backwards.
            const int savedCount = m_history.loadSentSince(peer);
            if (savedCount > 0)
                m_sentSinceRatchet[peer] =
                    qMax(m_sentSinceRatchet.value(peer, 0), savedCount);
        }
        // Surface peers we already have history with as (offline) contacts, so
        // the user can reopen those conversations and send even before a
        // presence update arrives -- messages are delivered on reconnect.
        m_users.ensureUser(peer);
    }
}

QString ChatClient::queueOutbox(const QString &peer, const QString &plaintext,
                                qint64 ts)
{
    // Hold a message the user composed while offline. It is kept in memory as
    // plaintext (NOT encrypted -- encrypting would step the ratchet for a frame
    // we cannot yet transmit) and mirrored to local history sealed under the
    // static local key, so nothing typed offline is lost across a restart. It is
    // ALSO persisted to the outbox table (again sealed, never plaintext on disk)
    // so that if the app is closed before reconnecting, the message is re-sent on
    // the next run. The persisted row id is carried in memory so flushOutbox()
    // can delete exactly that row once the message is actually sent.
    // Mint the stable id now, at queue time, so the offline echo below, the
    // persisted history row, and the wire frame that flushOutbox() eventually
    // sends all share ONE id -- making an offline-composed message deletable the
    // moment it lands, and keeping the delete addressable across a restart.
    const QString mid =
        QUuid::createUuid().toString(QUuid::WithoutBraces);

    QString histNonce, histCt;
    const bool sealed = m_crypto.localSeal(plaintext, histNonce, histCt);
    if (sealed)
        m_history.addTextRow(peer, m_nick, histNonce, histCt, ts, /*mine=*/true,
                             mid);

    qint64 dbId = -1;
    if (sealed && m_history.isReady()) {
        // Store the sealed 'nonceHex:ctHex' pair as the outbox body, so no
        // plaintext is ever written to disk for the queued copy either.
        const QString sealedBody = histNonce + QLatin1Char(':') + histCt;
        dbId = m_history.enqueueOutboxText(peer, sealedBody, ts,
                                           m_crypto.publicKeyHex());
    }

    PendingOut po;
    po.dbId      = dbId;
    po.kind      = QStringLiteral("text");
    po.peer      = peer;
    po.plaintext = plaintext;
    po.mid       = mid;
    po.ts        = ts;
    m_outbox.append(po);

    return mid;
}

void ChatClient::queueOutboxFile(const QString &peer, const QUrl &localFileUrl,
                                 qint64 ts)
{
    // Queue a file composed offline. We persist ONLY the source path -- nothing
    // is encrypted until flushOutbox() streams it at send time, so the file is
    // keyed to the identity in force when it actually goes out. QFile accepts
    // both file:// (desktop) and content:// (Android SAF) forms, so we keep the
    // URL's string form as given.
    const QString srcPath = localFileUrl.toLocalFile().isEmpty()
                                ? localFileUrl.toString()
                                : localFileUrl.toLocalFile();

    qint64 dbId = -1;
    if (m_history.isReady())
        dbId = m_history.enqueueOutboxFile(peer, srcPath, ts,
                                           m_crypto.publicKeyHex());

    PendingOut po;
    po.dbId    = dbId;
    po.kind    = QStringLiteral("file");
    po.peer    = peer;
    po.srcPath = srcPath;
    po.ts      = ts;
    m_outbox.append(po);
}

void ChatClient::restoreOutbox()
{
    // Load any queued rows persisted in a previous run into the in-memory queue,
    // so messages/files composed offline before the app was closed are re-sent
    // on the next connection. Called from login(), before the socket opens; the
    // actual send happens in flushOutbox() from onConnected(). Ordered oldest
    // first by the store, so composition order is preserved.
    if (!m_history.isReady())
        return;
    const QList<HistoryStore::OutboxRow> rows = m_history.loadOutbox();
    for (const HistoryStore::OutboxRow &r : rows) {
        PendingOut po;
        po.dbId = r.id;
        po.kind = r.kind;
        po.peer = r.peer;
        po.ts   = r.ts;
        if (r.kind == QLatin1String("text")) {
            // The body is the sealed 'nonceHex:ctHex' pair; unseal it back to
            // plaintext for sending. If it cannot be opened (e.g. stored under a
            // previous identity key), drop the row -- it cannot be sent meaningfully.
            const int colon = r.body.indexOf(QLatin1Char(':'));
            if (colon > 0) {
                const QString nonceHex = r.body.left(colon);
                const QString ctHex    = r.body.mid(colon + 1);
                const QString plain    = m_crypto.localOpen(nonceHex, ctHex);
                if (!plain.isEmpty()) {
                    po.plaintext = plain;
                    po.mid       = r.mid;   // keep the queued id (empty = legacy)
                    m_outbox.append(po);
                    continue;
                }
            }
            // Unopenable: remove the dead row so it does not linger forever.
            if (r.id >= 0)
                m_history.deleteOutboxRow(r.id);
        } else if (r.kind == QLatin1String("file")) {
            // IDENTITY GUARD (phantom-file fix): a file row's source path is
            // plaintext and would open under ANY identity, so -- unlike the text
            // branch, which self-invalidates when localOpen fails under a new key
            // -- a file queued under a PREVIOUS identity must be explicitly
            // dropped here, or it would be re-sent on reconnect as a brand-new
            // transfer to a peer who never requested it. Keep the row ONLY if its
            // stamp matches our CURRENT identity. A legacy row (empty stamp, from
            // a build before the column existed) is also dropped for files,
            // because we cannot prove it belongs to this identity and a wrongful
            // re-send is exactly the bug we are closing.
            const QString mine = m_crypto.publicKeyHex();
            if (!r.identity.isEmpty() && r.identity == mine) {
                po.srcPath = r.srcPath;
                m_outbox.append(po);
            } else {
                qWarning() << "[OUTBOX] dropping file row queued under a "
                              "different/unknown identity -- not re-sending"
                           << "(peer" << r.peer << ", stampEmpty"
                           << r.identity.isEmpty() << ")";
                if (r.id >= 0)
                    m_history.deleteOutboxRow(r.id);
            }
        } else if (r.kind == QLatin1String("handshake")) {
            // A re-bootstrap handshake persisted while offline (the user
            // confirmed a changed safety number, then closed the app before
            // reconnecting). It carries no body/srcPath -- only peer + ts -- so
            // there is nothing to unseal; restore it as-is and flushOutbox()
            // will encrypt the sentinel and emit it on reconnect.
            //
            // IDENTITY GUARD: a handshake re-bootstraps a chain from OUR current
            // identity. One queued under a superseded identity is meaningless now
            // (and could stall the peer with a bootstrap they cannot match), so
            // keep it ONLY if its stamp matches the current identity. Legacy
            // (empty-stamp) handshake rows are allowed through: they predate the
            // stamp and re-establishing is safe/idempotent, whereas a wrongful
            // file re-send is not.
            const QString mine = m_crypto.publicKeyHex();
            if (r.identity.isEmpty() || r.identity == mine) {
                m_outbox.append(po);
            } else {
                qWarning() << "[OUTBOX] dropping handshake row queued under a "
                              "superseded identity" << "(peer" << r.peer << ")";
                if (r.id >= 0)
                    m_history.deleteOutboxRow(r.id);
            }
        } else if (r.kind == QLatin1String("verifyack")) {
            // A "I verified you" ack persisted while offline. It carries no
            // message text: the body column is REUSED to hold the peer identity
            // (hex) that was verified, so a later flush attests the exact key the
            // user confirmed rather than whatever key is current at send time.
            // The identity stamp is OUR identity when the ack was queued.
            //
            // IDENTITY GUARD: a verifyack asserts a verification WE performed under
            // a specific local identity, so one queued under a now-superseded local
            // identity is meaningless -- keep it ONLY if the stamp matches (legacy
            // empty-stamp rows are allowed through, as for handshakes, since
            // re-affirming a verification is safe and idempotent).
            const QString mine = m_crypto.publicKeyHex();
            if (r.identity.isEmpty() || r.identity == mine) {
                po.peerIdentity = r.body;   // the verified peer identity (hex)
                m_outbox.append(po);
            } else {
                qWarning() << "[OUTBOX] dropping verifyack row queued under a "
                              "superseded identity" << "(peer" << r.peer << ")";
                if (r.id >= 0)
                    m_history.deleteOutboxRow(r.id);
            }
        }
    }
}

void ChatClient::flushOutbox()
{
    // Drain the offline outbox now that a send may be possible. Text messages
    // are encrypted (stepping the ratchet) and sent; files are streamed via the
    // normal send path; handshakes are emitted via transmitHandshake(). This is
    // called from onConnected() AND from the receive path when an inbound frame
    // brings a peer's chain alive (see the outbox-drain trigger in
    // handleServerFrame). Every ratchet step here corresponds to a frame
    // actually handed to a live socket -- the invariant that keeps the two ends'
    // chains synchronised.
    //
    // RE-ENTRANCY GUARD: because we may now be entered from the receive path,
    // and sending can pump further handling, refuse to run a second drain while
    // one is already in progress -- otherwise an item could be sent twice. The
    // in-progress flag is set for the whole loop and cleared on every exit path.
    if (m_flushInProgress)
        return;

    // We take and clear the list up front so an item that genuinely cannot be
    // sent does not get retried in a tight loop; it is either requeued (transient
    // reason: connection dropped again, or key not yet known) or dropped with a
    // visible error (permanent reason: encryption failed, or a queued file's
    // source is gone). Each successfully-sent item's persisted outbox row is
    // deleted so it is not re-sent on a future restart.
    if (m_outbox.isEmpty())
        return;

    m_flushInProgress = true;
    const QList<PendingOut> pending = m_outbox;
    m_outbox.clear();

    for (const PendingOut &m : pending) {
        if (m_socket.state() != QAbstractSocket::ConnectedState) {
            // Connection dropped again mid-flush: requeue the remainder (this
            // one included) and stop; the next onConnected() will resume. The
            // persisted row is left in place so it also survives a restart.
            m_outbox.append(m);
            continue;
        }
        if (!m_peerKeys.contains(m.peer)) {
            // Still no key for this peer: ask for it and requeue this item so a
            // later flush (after the key arrives) can send it. Row left in place.
            requestKeyFor(m.peer);
            m_outbox.append(m);
            continue;
        }

        // UNILATERAL GATE (offline-composed items). Hold a queued TEXT or FILE only
        // while *I* have not yet verified this peer (peer in m_unverifiedKeyChange)
        // -- the same gate sendMessage()/sendFile() enforce for live composition.
        // Requeue it (the persisted row is left in place) so the flush that
        // acknowledgeKeyChange() triggers the moment I verify delivers it in order.
        // Once I have verified, the item goes out even if the PEER has not verified
        // me and is offline -- the server store-and-forwards it. This decoupling
        // from the peer's verification (previously gated on m_pendingBilateral) is
        // what lets an offline peer finally receive queued messages/files. HANDSHAKE
        // and VERIFYACK frames are deliberately exempt regardless: a handshake
        // re-establishes the crypto chain and a verifyack tells the peer we
        // verified, so they must always be allowed through.
        if ((m.kind == QLatin1String("text")
             || m.kind == QLatin1String("file"))
            && conversationBlocked(m.peer)) {
            m_outbox.append(m);
            continue;
        }

        if (m.kind == QLatin1String("file")) {
            // Offline-composed file: verify the source still exists, then stream
            // it through the normal send path exactly as a live send would. If
            // the source was moved or deleted while we were offline, we cannot
            // send it: surface an error and drop it (including its persisted row).
            const QUrl url = QUrl::fromLocalFile(m.srcPath);
            const QString localPath = url.toLocalFile().isEmpty()
                                          ? m.srcPath
                                          : url.toLocalFile();
            if (!QFile::exists(localPath)) {
                emit errorOccurred(
                    QStringLiteral("A queued file to %1 can no longer be found "
                                   "and was not sent: %2")
                        .arg(m.peer, m.srcPath));
                if (m.dbId >= 0)
                    m_history.deleteOutboxRow(m.dbId);
                continue;   // dropped
            }
            // sendFile targets the active peer, so point it at this item's peer
            // for the duration of the send, then restore the selection.
            const QString savedPeer = m_activePeer;
            m_activePeer = m.peer;
            sendFile(QUrl::fromLocalFile(localPath));
            m_activePeer = savedPeer;
            if (m.dbId >= 0)
                m_history.deleteOutboxRow(m.dbId);   // sent: remove persisted row
            continue;
        }

        if (m.kind == QLatin1String("handshake")) {
            // Offline-composed re-bootstrap handshake (the user confirmed a
            // changed safety number while disconnected). Emit it now on the live
            // socket via the shared transmit path: this encrypts the sentinel --
            // re-bootstrapping a clean chain from the peer's current identity key
            // and stepping the ratchet exactly once -- and sends a "msg" tagged
            // "kind":"handshake" that the peer decrypts and swallows. If the
            // encrypt fails, requeue this one item and move on (do not drop it,
            // so the re-establishment is not silently lost). On success, delete
            // the persisted row so it is not re-emitted on a future restart.
            if (!transmitHandshake(m.peer)) {
                m_outbox.append(m);   // transient: retry on the next flush
                continue;
            }
            if (m.dbId >= 0)
                m_history.deleteOutboxRow(m.dbId);
            continue;
        }

        if (m.kind == QLatin1String("verifyack")) {
            // Offline-composed "I verified you" ack (the user confirmed a safety
            // number while disconnected, then reconnected). If the peer has
            // REKEYED since the user confirmed, the identity we verified no longer
            // matches the peer's current key: emitting the ack would attest a key
            // we never actually verified, so DROP it -- the fresh key change
            // re-flags the peer and a new ack is sent when the user re-verifies.
            // Otherwise emit it now, stamping the exact identity that was verified.
            if (m.peerIdentity.isEmpty()
                || m.peerIdentity != m_peerKeys.value(m.peer)) {
                qWarning() << "[VERIFY] dropping queued verifyack to" << m.peer
                           << "-- verified identity superseded before send.";
                if (m.dbId >= 0)
                    m_history.deleteOutboxRow(m.dbId);
                continue;
            }
            if (!transmitVerifyAck(m.peer, m.peerIdentity)) {
                m_outbox.append(m);   // transient (socket dropped): retry later
                continue;
            }
            if (m.dbId >= 0)
                m_history.deleteOutboxRow(m.dbId);
            continue;
        }

        // Text item.
        QString cipher, dhHex, nonceHex, ctHex;
        quint32 pn = 0, n = 0;
        bool notReady = false;
        if (!m_crypto.encryptFor(m.peer, m.plaintext,
                                 cipher, dhHex, pn, n, nonceHex, ctHex,
                                 &notReady)) {
            if (notReady) {
                // RESPONDER-NOT-READY (deterministic-role fix): we are the
                // responder for this peer and our sending chain does not exist
                // yet (the initiator's opening frame has not arrived). This is
                // transient, NOT a failure: requeue this item in memory (its
                // persisted row stays on disk) so a later flush -- after the
                // initiator's handshake establishes our chain -- sends it. Do NOT
                // drop it and do NOT delete its row.
                m_outbox.append(m);
                continue;
            }
            emit errorOccurred(
                QStringLiteral("Could not encrypt a queued message to %1.")
                    .arg(m.peer));
            if (m.dbId >= 0)
                m_history.deleteOutboxRow(m.dbId);   // permanent failure: drop
            continue;   // do not wedge the whole queue
        }
        QJsonObject msg{
                        {"type", "msg"},
                        {"from", m_nick},
                        {"to", m.peer},
                        // Reuse the id minted when this message was queued so the
                        // offline echo, the stored row, and this wire frame all
                        // agree and the message stays deletable. Legacy queued
                        // rows (from before the feature) carry no id; mint one now
                        // so at least the peer's copy is addressable.
                        {"mid", m.mid.isEmpty()
                                    ? QUuid::createUuid()
                                          .toString(QUuid::WithoutBraces)
                                    : m.mid},
                        {"cipher", cipher},
                        {"dh", dhHex},
                        {"pn", static_cast<double>(pn)},
                        {"n", static_cast<double>(n)},
                        {"nonce", nonceHex},
                        {"ct", ctHex},
                        {"ts", m.ts},
                        };
        m_socket.sendTextMessage(
            QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact)));
        // The plaintext was already echoed and locally persisted when it was
        // queued; here we persist the now-advanced ratchet session and delete
        // the persisted outbox row so it is not re-sent on a future restart.
        persistSession(m.peer);
        // POST-COMPROMISE SECURITY: a drained text frame counts toward the
        // recovery window exactly like a live send.
        noteOutboundTo(m.peer);
        if (m.dbId >= 0)
            m_history.deleteOutboxRow(m.dbId);
    }

    // Drain complete. Clear the re-entrancy guard so a later trigger (a new
    // connect, or another inbound frame that advances a chain) can flush again.
    // Any items the loop requeued into m_outbox above remain for that next
    // flush. This is the single exit path after the flag was set, so clearing it
    // here covers every case.
    m_flushInProgress = false;
}

void ChatClient::onApplicationStateChanged(Qt::ApplicationState state)
{
    // Android moves us through these states around a screen lock / app switch.
    // The crucial transition is INTO the background: Doze can freeze or kill the
    // process shortly after, so we must get all live ratchet state onto disk
    // FIRST. Coming back to the foreground, we re-import so a session saved on
    // suspend is resumed, not re-bootstrapped.
    //
    // PLATFORM NOTE (desktop lock fix). This whole hook is gated to Android.
    // On Windows, Qt::ApplicationInactive fires on EVERY focus loss -- clicking
    // another window, opening a menu, alt-tabbing -- so running lockNow() here
    // made the desktop app re-lock itself constantly and, combined with the
    // reconnect issue, made conversations appear to "break after a while". The
    // desktop lock is therefore driven only by an explicit "Lock now" (never by
    // focus changes, and no longer by a cold-start lock -- the app no longer
    // starts locked, since there is no live session to guard before login).
    // Per-message persistence (persistSession in the send/receive
    // paths) already keeps ratchet state safe on desktop, so nothing is lost by
    // not flushing here. On Android the process really can be frozen/killed in
    // the background, so the flush-and-lock behaviour is kept exactly as before.
#ifdef Q_OS_ANDROID
    switch (state) {
    case Qt::ApplicationSuspended:
    case Qt::ApplicationInactive:
        // About to be backgrounded/frozen: flush everything now.
        persistAllSessions();
        // APP LOCK (feature 2): re-guard the running UI the moment we leave the
        // foreground, so returning to the app shows the lock screen before any
        // conversation is visible. No-op if the user has not enabled the lock.
        lockNow();
        break;
    case Qt::ApplicationActive:
        // Returned to the foreground: make sure our in-memory sessions match
        // what is on disk (harmless if nothing changed).
        restoreAllSessions();
        break;
    case Qt::ApplicationHidden:
    default:
        break;
    }
#else
    Q_UNUSED(state);
#endif
}

// ---------------------------------------------------------------------------
// X3DH prekey publication and bundle fetch
// ---------------------------------------------------------------------------

void ChatClient::publishPrekeysIfNeeded(bool force)
{
    if (m_socket.state() != QAbstractSocket::ConnectedState)
        return;
    if (!m_crypto.hasX3dhIdentity()) {
        // A version 1 identity has no signing key, so it cannot produce a
        // signed prekey. Silent by design: this account simply keeps using the
        // legacy bootstrap until the user regenerates their identity.
        return;
    }

    // Restore a pool from disk before making a new one. Regenerating on every
    // start would orphan every bundle the relay has already served, so any peer
    // who fetched one while we were offline could never be answered.
    if (!m_crypto.hasPrekeys() && m_history.isReady()) {
        const QByteArray blob = m_history.loadPrekeys();
        if (!blob.isEmpty() && m_crypto.restorePrekeys(blob))
            qDebug() << "[PREKEYS] restored pool from disk;"
                     << m_crypto.oneTimePrekeyCount() << "one-time prekeys left";
    }

    const bool needNew = force || !m_crypto.hasPrekeys()
                         || m_crypto.oneTimePrekeyCount() <= kPrekeyLowWaterMark;
    if (!needNew)
        return;
    if (!m_crypto.generatePrekeys(kPrekeyBatchSize)) {
        qWarning() << "[PREKEYS] generation failed; X3DH unavailable this session";
        return;
    }
    // Persist BEFORE publishing. The relay may serve a bundle the instant it is
    // accepted, and a crash between the send and the write would leave a bundle
    // in circulation whose private half we no longer hold.
    if (m_history.isReady())
        m_history.savePrekeys(m_crypto.serialisePrekeys());

    QJsonObject opks;
    const auto pubs = m_crypto.oneTimePrekeyPublicsHex();
    for (auto it = pubs.cbegin(); it != pubs.cend(); ++it)
        opks.insert(QString::number(it.key()), it.value());

    const QJsonObject frame{
        {"type",    "publish_prekeys"},
        {"spk",     m_crypto.signedPrekeyPublicHex()},
        {"spk_sig", m_crypto.signedPrekeySignatureHex()},
        {"ts",      static_cast<double>(QDateTime::currentMSecsSinceEpoch())},
        {"opks",    opks},
    };
    m_socket.sendTextMessage(QString::fromUtf8(
        QJsonDocument(frame).toJson(QJsonDocument::Compact)));
    qDebug() << "[PREKEYS] published signed prekey and" << opks.size()
             << "one-time prekeys";
}

void ChatClient::requestBundle(const QString &peer)
{
    if (peer.isEmpty() || peer == m_nick)
        return;                       // never fetch our own bundle
    if (m_socket.state() != QAbstractSocket::ConnectedState) {
        qWarning() << "[X3DH] cannot fetch a bundle for" << peer
                   << "-- not connected";
        return;
    }
    const QJsonObject frame{{"type", "get_bundle"}, {"nick", peer}};
    m_socket.sendTextMessage(QString::fromUtf8(
        QJsonDocument(frame).toJson(QJsonDocument::Compact)));
    qDebug() << "[X3DH] requested prekey bundle for" << peer;
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

    // SECURITY GATE (delivery HELD until *I* have verified). After a safety-number
    // change or a first contact, a message must not be encrypted to a key I have
    // not confirmed -- but it must not be DROPPED either. So while I am still
    // unverified for this peer, HOLD it: queue it (persisted, sealed at rest, echoed
    // optimistically) exactly like an offline message. acknowledgeKeyChange()
    // drains the outbox the moment I verify, so the message goes out then -- even if
    // the peer is OFFLINE and has not verified me (the server store-and-forwards it;
    // the peer decrypts on return). This is the UNILATERAL gate: I gate on my own
    // verification only, never on the peer's, so an offline peer's inability to
    // verify me can no longer strand my messages. The "encrypt nothing to an
    // unverified key" invariant still holds, because I only reach the encrypt path
    // below after I have verified the key. See conversationBlocked() for the full
    // rationale.
    if (conversationBlocked(m_activePeer)) {
        const qint64 hts = QDateTime::currentMSecsSinceEpoch();
        const QString qmid = queueOutbox(m_activePeer, plaintext, hts);
        m_messages.addMessage(m_nick, plaintext, hts, true, qmid);
        // Two different states, two different messages: telling someone to
        // "verify" when they already have is confusing, and they would have no
        // idea what action is expected of them.
        emit errorOccurred(
            m_unverifiedKeyChange.contains(m_activePeer)
                ? QStringLiteral("%1's safety number isn't verified yet -- your "
                                 "message is queued and will send once BOTH of "
                                 "you have verified.").arg(m_activePeer)
                : QStringLiteral("Waiting for %1 to verify your safety number "
                                 "too -- your message is queued and will send "
                                 "as soon as they do.").arg(m_activePeer));
        return;
    }

    const qint64 ts = QDateTime::currentMSecsSinceEpoch();

    // CONNECTION GUARD (the core divergence fix). Encrypting a message STEPS the
    // ratchet: it consumes a one-time message key and increments the send
    // counter. If we then fail to actually transmit the frame -- because the
    // socket is not connected (Android Doze after a screen lock severs the
    // WebSocket; a reconnect is in flight) -- that message key is burned but the
    // peer never receives the frame that would consume it. The two chains
    // desynchronise permanently: the peer's next frame carries an index behind
    // our advanced receive state, and the receiving chain only ratchets forward,
    // so every subsequent message silently fails to decrypt. (Files keep working
    // because they key off the static identity secret, not this chain -- which is
    // exactly the "files fine, text broken after screen lock" symptom.)
    //
    // So: only encrypt when the socket is genuinely connected. Otherwise queue
    // the PLAINTEXT and return; flushOutbox() will encrypt and send it in order
    // once onConnected() fires. The ratchet is therefore stepped only for frames
    // that are truly put on the wire.
    if (m_socket.state() != QAbstractSocket::ConnectedState) {
        const QString qmid = queueOutbox(m_activePeer, plaintext, ts);
        // Optimistic echo + local persistence, same as the online path, so the
        // user sees their message and it survives a restart. It is NOT encrypted
        // for the peer yet; that happens on flush. Echo under the SAME id that
        // was queued so the message is deletable at once and stays addressable
        // when flushOutbox() later sends it under that id.
        m_messages.addMessage(m_nick, plaintext, ts, true, qmid);
        emit errorOccurred(
            QStringLiteral("Offline: message queued, will send on reconnect."));
        return;
    }

    // DIAGNOSTIC (temporary, user-switch investigation): the complete send-time
    // picture for this peer. This is the key line for the "new peer after switch
    // cannot chat" case: it shows our deterministic role, whether we already hold
    // a session, and whether the peer is brand-new. Expected healthy first-send
    // to a NEW peer: if we are INITIATOR, hasSession may be false but encryptFor
    // below bootstraps and succeeds; if we are RESPONDER, encryptFor returns
    // notReady (we cannot open the channel) and the message queues -- which means
    // SOMETHING must make us send once the initiator opens. If BOTH devices log
    // RESPONDER for each other, neither opens the channel and the chat stalls
    // with no error -- the bug. Compare this line across the two devices.
    qDebug() << "[SEND] peer" << m_activePeer
             << "| amInitiator" << m_crypto.amInitiatorFor(m_activePeer)
             << "| hasSession" << m_crypto.hasSessionFor(m_activePeer)
             << "| haveKey" << m_peerKeys.contains(m_activePeer)
             << "| unverified" << hasUnverifiedKeyChange(m_activePeer);

    QString cipher, dhHex, nonceHex, ctHex;
    quint32 pn = 0, n = 0;
    bool notReady = false;
    if (!m_crypto.encryptFor(m_activePeer, plaintext,
                             cipher, dhHex, pn, n, nonceHex, ctHex, &notReady)) {
        if (notReady) {
            // RESPONDER-NOT-READY (deterministic-role fix). We are the responder
            // (Bob) for this peer and our sending chain does not exist yet -- it
            // is created only when the initiator's opening frame arrives. Rather
            // than drop the message or send an unusable frame, QUEUE it: the same
            // outbox that holds offline messages will re-encrypt and send it once
            // the initiator's handshake has established our chain. We echo it
            // optimistically (as the offline path does) so the user sees it, and
            // it is persisted so it survives a restart in this window too.
            // DIAGNOSTIC (temporary, user-switch investigation): responder cannot
            // open the channel. If the peer never sends us an opening frame, this
            // message stays queued forever -- the stall. This confirms we are the
            // responder waiting on an initiator that may also be waiting on us.
            qDebug() << "[SEND] peer" << m_activePeer
                     << "-> RESPONDER-NOT-READY: queued, awaiting peer's opening "
                        "frame. If peer is also responder, channel will STALL.";
            const QString qmid = queueOutbox(m_activePeer, plaintext, ts);
            m_messages.addMessage(m_nick, plaintext, ts, true, qmid);
            emit errorOccurred(
                QStringLiteral("Re-establishing secure session\u2026 message "
                               "queued, will send once the channel is ready."));
            return;
        }
        emit errorOccurred(QStringLiteral("Encryption failed."));
        return;
    }

    // Mint the message's stable id NOW, before it goes on the wire, so both
    // this device and the peer address the identical message when either side
    // deletes it. It rides in the "mid" field the peer reads on receipt and is
    // written to our local echo and history so a later delete can locate it.
    const QString mid =
        QUuid::createUuid().toString(QUuid::WithoutBraces);

    QJsonObject msg{
                    {"type", "msg"},
                    {"from", m_nick},
                    {"to", m_activePeer},
                    {"mid", mid},
                    {"cipher", cipher},
                    {"dh", dhHex},
                    {"pn", static_cast<double>(pn)},
                    {"n", static_cast<double>(n)},
                    {"nonce", nonceHex},
                    {"ct", ctHex},
                    {"ts", ts},
                    };
    // X3DH OPENER: ride the header on the FIRST frame to this peer and then
    // forget it. take() removes the entry, so it goes out exactly once -- a
    // header repeated on a later frame would ask a peer whose ratchet has
    // already moved on to re-derive the initial secret.
    if (m_pendingX3dhHeader.contains(m_activePeer)) {
        const X3dhHeader hdr = m_pendingX3dhHeader.take(m_activePeer);
        msg.insert("ik_a", QString::fromUtf8(hdr.ikA.toHex()));
        msg.insert("ek_a", QString::fromUtf8(hdr.ekA.toHex()));
        msg.insert("opk_id", static_cast<double>(hdr.opkId));
        // Name the signed prekey we agreed against. The peer may have rotated
        // between serving the bundle and receiving this frame, in which case it
        // holds two and cannot tell which we used -- the wrong one derives a
        // well-formed secret that simply fails to decrypt.
        msg.insert("spk_used", QString::fromUtf8(hdr.spkUsed.toHex()));
        qDebug() << "[X3DH] attaching opener header to the first frame for"
                 << m_activePeer;
    }

    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact)));

    // Sending a message means we are no longer typing: cancel the debounce and
    // tell the peer we are idle, so their "typing…" indicator clears at once
    // rather than lingering until the idle timer would have lapsed.
    sendTypingState(m_activePeer, QStringLiteral("idle"));

    // Show our own message immediately (optimistic UI). We display the
    // plaintext we just typed; it was never sent in the clear. The mid is
    // carried so the delegate can offer delete on this row right away.
    m_messages.addMessage(m_nick, plaintext, ts, true, mid);

    // Persist locally. The WIRE ciphertext is unrecoverable later (the ratchet
    // discards its key for forward secrecy), so we store the plaintext RE-SEALED
    // under a static local key (CryptoBox::localSeal) -- still never plaintext on
    // disk, but decryptable across restarts. The mid is stored too so a delete
    // survives a restart. Then persist the advanced session.
    QString histNonce, histCt;
    if (m_crypto.localSeal(plaintext, histNonce, histCt))
        m_history.addTextRow(m_activePeer, m_nick, histNonce, histCt, ts, true,
                             mid);
    persistSession(m_activePeer);
    // POST-COMPROMISE SECURITY: this text frame advanced our sending chain on a
    // frame the peer has not yet answered. Count it toward the recovery window
    // and fire a rekey-ping if the window is now full.
    noteOutboundTo(m_activePeer);
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

    if (type == "auth_salt") {
        // Reply to auth_begin: the server sent the salt this account's verifier
        // must be derived under (or null when the account has no stored
        // password). Deriving under the SERVER's salt is what makes a correct
        // password produce the SAME verifier on every device -- the fix for the
        // spurious "password mismatch". If the reply arrives after the fallback
        // timer already fired (m_pendingPassword cleared), ignore it.
        if (m_pendingPassword.isEmpty())
            return;
        const QJsonValue saltVal = obj.value("salt");
        if (saltVal.isString() && !saltVal.toString().isEmpty()) {
            // Existing protected account: derive under the server's salt and
            // cache it locally so a later offline/old-server login still matches.
            const QString serverSalt = saltVal.toString();
            m_pendingVerifierHex =
                CryptoBox::deriveVerifierWithSalt(m_pendingPassword, serverSalt);
            m_pendingSaltHex = serverSalt;
            QSettings settings;
            settings.setValue(QStringLiteral("auth/verifierSalt/") + m_nick,
                              serverSalt);
            qDebug() << "[AUTH] derived verifier under server salt for" << m_nick;
        } else {
            // No stored credential yet (new account, or legacy password-less):
            // fall back to the local salt (fresh if none), exactly as a first
            // registration would. The server stores what we send.
            deriveVerifierLocally();
            qDebug() << "[AUTH] server has no salt for" << m_nick
                     << "-- using local/fresh salt";
        }
        completeHello();
        return;
    }

    if (type == "presence") {
        QStringList names;
        for (const QJsonValue &v : obj.value("users").toArray())
            names << v.toString();
        // Mark who is online but KEEP offline users in the list, so an offline
        // peer stays selectable and can still be sent messages/files (the
        // server stores them and delivers on the peer's next login).
        m_users.setOnlineUsers(names);

        // TYPING INDICATOR: a peer that just went offline cannot still be
        // composing, so clear any lingering "typing…" we were showing for anyone
        // no longer in the online set. Iterate over a copy of the keys because
        // setPeerTyping mutates m_peerTyping.
        if (!m_peerTyping.isEmpty()) {
            const QSet<QString> onlineNow(names.begin(), names.end());
            const QList<QString> typingPeers = m_peerTyping.keys();
            for (const QString &p : typingPeers) {
                if (!onlineNow.contains(p))
                    setPeerTyping(p, QStringLiteral("idle"));
            }
        }

    } else if (type == "prekeys_ack") {
        // The relay reports how many one-time prekeys it accepted and how many
        // it now holds. Worth logging: a pool that is not being replenished is
        // invisible from the client otherwise, and the consequence -- new
        // conversations quietly losing the DH4 contribution -- is exactly the
        // kind of silent downgrade that never announces itself.
        const int added = obj.value("added").toInt();
        const int remaining = obj.value("remaining").toInt();
        qDebug() << "[PREKEYS] relay accepted" << added
                 << "one-time prekeys; pool now" << remaining;
        if (remaining <= kPrekeyLowWaterMark) {
            qWarning() << "[PREKEYS] pool is low (" << remaining
                       << ") -- topping up";
            publishPrekeysIfNeeded(/*force=*/true);
        }

    } else if (type == "bundle") {
        // A peer's X3DH prekey bundle. The relay assembled it, so nothing in it
        // is trusted until the signed prekey verifies against the identity key
        // the bundle itself carries. That check is the whole point of the signed
        // prekey: without it the relay could serve a prekey of its own and read
        // the first message of every conversation it brokered.
        const QString who = obj.value("nick").toString();
        const QJsonValue bv = obj.value("bundle");
        if (!bv.isObject()) {
            qWarning() << "[X3DH] no bundle published for" << who
                       << "-- falling back to the legacy bootstrap";
            emit bundleUnavailable(who);
            return;
        }
        const QJsonObject b = bv.toObject();
        const QByteArray ik  = QByteArray::fromHex(b.value("ik").toString().toUtf8());
        const QByteArray spk = QByteArray::fromHex(b.value("spk").toString().toUtf8());
        const QByteArray sig = QByteArray::fromHex(b.value("spk_sig").toString().toUtf8());

        // BIND THE BUNDLE TO THE DIRECTORY IDENTITY, before trusting the
        // signature inside it. verifyBundle() below proves only that the bundle
        // is INTERNALLY consistent -- that its signed prekey verifies against
        // the identity key the bundle itself carries. A relay that wanted to
        // read the first message of a conversation it brokered could satisfy
        // that on its own: mint an identity, sign a prekey of its own with it,
        // and serve the pair. What it cannot forge is the identity the peer
        // PUBLISHED, which every other client already holds and which the user
        // verifies as a safety number. So require the bundle's identity to be
        // that key.
        //
        // Compared against the Ed25519 form when we hold it (the exact bytes),
        // and otherwise against the derived agreement key, which is what
        // m_peerKeys holds for every peer we know at all. If we hold neither we
        // have never heard of this peer, so there is nothing to anchor to; that
        // is logged rather than enforced, because refusing there would break a
        // legitimate first contact rather than stop an attack.
        {
            const QByteArray knownEd = m_peerEdKeys.value(who);
            bool bound = true;
            if (!knownEd.isEmpty()) {
                bound = (ik == knownEd);
            } else if (m_peerKeys.contains(who)) {
                QByteArray derived;
                bound = CryptoBox::agreementKeyFor(
                            ik, QStringLiteral("ed25519"), derived)
                        && QString::fromUtf8(derived.toHex())
                               == m_peerKeys.value(who);
            } else {
                qWarning() << "[X3DH] bundle for" << who
                           << "cannot be bound to a published identity "
                              "(no directory key held yet)";
                bound = true;   // nothing to compare against; see above
            }
            if (!bound) {
                qWarning() << "[X3DH] REJECTED bundle for" << who
                           << "-- its identity key is NOT the one this peer "
                              "published; the relay may be substituting a "
                              "bundle of its own";
                emit errorOccurred(
                    tr("Rejected a key bundle for %1 that does not match their "
                       "published identity.").arg(who));
                emit bundleRejected(who);
                return;
            }
        }

        if (!CryptoBox::verifyBundle(ik, spk, sig)) {
            // Do NOT fall back silently. A bundle that fails to verify is not a
            // missing bundle: it is a bundle someone assembled, and continuing
            // on the legacy path would hide that from the user entirely.
            qWarning() << "[X3DH] REJECTED bundle for" << who
                       << "-- signed prekey does not verify against its identity key";
            emit errorOccurred(tr("Rejected a malformed key bundle for %1.").arg(who));
            emit bundleRejected(who);
            return;
        }

        const bool haveOpk = b.value("opk").isString();
        const QByteArray opk = haveOpk
            ? QByteArray::fromHex(b.value("opk").toString().toUtf8())
            : QByteArray();
        const qint32 opkId = haveOpk ? qint32(b.value("opk_id").toInt(-1)) : -1;
        if (haveOpk && opk.size() != 32) {
            qWarning() << "[X3DH] bundle for" << who
                       << "carries a malformed one-time prekey; ignoring it";
            emit bundleReady(who, ik, spk, QByteArray(), -1);
            return;
        }
        qDebug() << "[X3DH] verified bundle for" << who
                 << "| ik" << ik.toHex().left(16)
                 << "| spk" << spk.toHex().left(16)
                 << "| one-time prekey" << (haveOpk ? "yes" : "none (pool empty)");

        // Open the session now and remember the three header values. They must
        // ride on the FIRST message we send, and only that one: once the peer
        // has answered, both chains exist and repeating the header would invite
        // them to re-derive a session that is already past its first ratchet.
        QByteArray ikA, ekA;
        qint32 usedOpk = -1;
        if (m_crypto.beginX3dhSession(who, ik, spk, sig, opk, opkId,
                                      ikA, ekA, usedOpk)) {
            X3dhHeader hdr;
            hdr.ikA = ikA;
            hdr.ekA = ekA;
            hdr.opkId = usedOpk;
            hdr.spkUsed = spk;
            m_pendingX3dhHeader.insert(who, hdr);
            persistSession(who);
            // The session exists but has never carried a frame. Drain anything
            // queued for this peer so the opener actually goes out.
            if (m_socket.state() == QAbstractSocket::ConnectedState
                && !m_outbox.isEmpty())
                flushOutbox();
        }
        emit bundleReady(who, ik, spk, opk, opkId);

    } else if (type == "keys") {
        // The initial directory dump on login.
        const QJsonObject keys = obj.value("keys").toObject();
        // Which kind of key each directory entry holds. Absent for a relay that
        // predates X3DH, and absent per-entry for a peer that predates it, so
        // the default is the legacy interpretation in both cases.
        const QJsonObject keyTypes = obj.value("key_types").toObject();

        // WHICH FORM OF KEY THIS RELAY PUBLISHES -- established from evidence
        // rather than assumed.
        //
        // A version 2 account publishes its ED25519 identity key, and peers
        // derive the X25519 agreement key from it. A relay that carries the
        // X3DH work states which kind each entry holds in "key_types"; one that
        // predates it says nothing, and the client then falls back to the
        // legacy reading -- "no type means x25519" -- which is correct for a
        // relay old enough to have only ever seen X25519 identities, and WRONG
        // for a relay old enough to lack the field while its users are all
        // publishing Ed25519. That second case is not hypothetical: it is what
        // a deployed relay looks like when the client has been updated and the
        // server has not. Every safety number computed against it is derived
        // from an Ed25519 key on one side and an X25519 key on the other, so
        // the two screens can never agree and no user can ever complete a
        // verification -- online or offline, because both paths read the same
        // map.
        //
        // The relay that has this problem hands over the calibration sample
        // needed to detect it. Self-exclusion from the directory dump was added
        // in the same body of work as "key_types", so a relay missing the field
        // also sends the requester its OWN entry -- and we know both forms of
        // our own key locally, from CryptoBox. Comparing the two settles the
        // question outright: if the relay's idea of our key is our Ed25519 key,
        // then this relay publishes Ed25519 keys and tags none of them, and
        // that applies to every entry in the dump, not just ours.
        //
        // Nothing here is trusted that was not already: the relay could serve
        // any value it liked in either form. This only stops the client
        // MISREADING a value the relay served honestly.
        const bool relayStatesTypes = obj.contains(QStringLiteral("key_types"));
        if (!relayStatesTypes && !m_nick.isEmpty() && keys.contains(m_nick)) {
            const QString mine = keys.value(m_nick).toString();
            const QString myEd = m_crypto.edPublicKeyHex();
            const QString myAgree = m_crypto.publicKeyHex();
            if (!myEd.isEmpty()
                    && mine.compare(myEd, Qt::CaseInsensitive) == 0) {
                if (!m_relayServesUntaggedEd) {
                    m_relayServesUntaggedEd = true;
                    qWarning() << "[KEYS] this relay does not state key types "
                                  "and publishes Ed25519 identities (its entry "
                                  "for us is our Ed25519 key, not our agreement "
                                  "key) -- reading every untagged entry as "
                                  "Ed25519. The relay is running a build that "
                                  "predates X3DH; updating it removes the "
                                  "guesswork.";
                    emit errorOccurred(
                        tr("This server is running an old relay build. "
                           "Verification still works, but updating the server "
                           "is recommended."));
                }
            } else if (!myAgree.isEmpty()
                       && mine.compare(myAgree, Qt::CaseInsensitive) == 0) {
                // Old enough to include us, but serving agreement keys: the
                // legacy reading is the right one. Say so, so the log
                // distinguishes "checked and legacy" from "never checked".
                m_relayServesUntaggedEd = false;
                qDebug() << "[KEYS] relay states no key types and publishes "
                            "agreement keys -- legacy reading confirmed "
                            "against our own entry";
            }
        }

        // BIOMETRIC LOGIN ENROLL (confirmed-login hook): the server only sends
        // this key dump AFTER a successful hello, so reaching here means the
        // password was accepted. If the user asked to enable biometric/Hello
        // login on this login, write the vault NOW (never before -- a rejected
        // password closes the socket via logout() first, which clears the
        // pending flag, so a wrong password can never enroll). Cleared after so
        // it fires once per opt-in.
        if (m_bioEnrollPending && !m_bioEnrollPassword.isEmpty()
                && !m_nick.isEmpty()) {
            AppLock::enrollLogin(this, m_nick, m_bioEnrollPassword);
            m_bioEnrollPending = false;
            m_bioEnrollPassword.clear();
            emit biometricLoginChanged();
            qDebug() << "[LOGIN] biometric login enrolled after confirmed login";
        } else {
            // DIAGNOSTIC (temporary): the confirmed-login hook ran but no enroll
            // was pending -- normal for a login without the opt-in ticked. If you
            // ticked the box and see this instead of the "enrolled" line above,
            // the pending flag was lost before the key dump arrived.
            qDebug() << "[LOGIN] keys dump: no enroll pending (pending ="
                     << m_bioEnrollPending << ", nick set =" << !m_nick.isEmpty()
                     << ")";
        }

        for (auto it = keys.begin(); it != keys.end(); ++it) {
            const QString peer = it.key();

            // WE ARE NOT OUR OWN PEER. A relay that predates self-exclusion
            // sends us our own entry, and this loop has no self-check: it ran
            // key-change detection against our own identity, flagged it, and
            // emitted a self-addressed verify_resync -- the "VERIFYRESYNC
            // azx1 -> azx1" the relay logs with one user online. Nothing came
            // of the frame, because the far side discards a message from
            // itself, but our own nick was left in m_peerKeys, which is the
            // set reestablishPcsForAll() walks when forcing a ratchet step.
            // The server-side fix is already written; this makes the client
            // correct against a relay that has not received it yet.
            if (!m_nick.isEmpty() && peer == m_nick)
                continue;

            const QString published = it.value().toString();
            // The stated type when there is one; otherwise what the relay's
            // own entry for us showed this relay to be publishing.
            QString ikType = keyTypes.value(peer).toString();
            if (ikType.isEmpty() && m_relayServesUntaggedEd)
                ikType = QStringLiteral("ed25519");

            // CONVERT ONCE, HERE. Everything downstream -- m_peerKeys, the
            // ratchet, ensureSharedKey, the safety number -- deals in X25519
            // agreement keys and always has. Doing the conversion at the single
            // point where a published key enters the client means none of that
            // code changes, and there is exactly one place where the two kinds
            // of key can be confused rather than one per call site.
            QByteArray agree;
            if (!CryptoBox::agreementKeyFor(
                    QByteArray::fromHex(published.toUtf8()), ikType, agree)) {
                qWarning() << "[KEYS] peer" << peer
                           << "published an unusable identity key (type"
                           << (ikType.isEmpty() ? QStringLiteral("absent")
                                                : ikType)
                           << ") -- skipping; no session will be opened";
                continue;
            }
            const QString pub = QString::fromUtf8(agree.toHex());

            // Keep the PUBLISHED key too. It is what a prekey bundle is signed
            // with, so bundle verification needs the Ed25519 form, while the
            // ratchet needs the derived one. Storing both keeps each caller
            // honest about which it is asking for.
            if (ikType == QLatin1String("ed25519"))
                m_peerEdKeys.insert(peer, QByteArray::fromHex(published.toUtf8()));
            else
                m_peerEdKeys.remove(peer);

            // DIAGNOSTIC (temporary, user-switch investigation): for EACH peer
            // the server reports, log whether we already knew them, what key we
            // held, and whether we have a session. This is the line that reveals
            // the new-peer-after-switch case: when a genuinely new identity (e.g.
            // "User G") appears, this prints knewPeer=false / hadSession=false,
            // so NONE of the key-change logic below fires (there is nothing to
            // compare against) and the pairing relies purely on the deterministic
            // role + first frame. Compare across both devices for the pairing.
            qDebug() << "[KEYS] peer" << peer
                     << "| knewPeer" << m_peerKeys.contains(peer)
                     << "| oldKey" << (m_peerKeys.contains(peer)
                                           ? m_peerKeys.value(peer).left(16)
                                           : QStringLiteral("(none)"))
                     << "| newKey" << pub.left(16)
                     << "| hadSession" << m_crypto.hasSessionFor(peer)
                     << "| heldIdentity" << (m_crypto.peerIdentityHex(peer).isEmpty()
                                                 ? QStringLiteral("(none)")
                                                 : m_crypto.peerIdentityHex(peer).left(16));

            m_peerKeys.insert(peer, pub);

            // USER-SWITCHING KEY-CHANGE DETECTION (Parts A+B+C). Before
            // ensureSharedKey() runs -- it OVERWRITES the held identity with the
            // server's key -- capture two things: the identity the (possibly
            // restored) session is currently bound to, and whether a restored
            // session exists at all. After a user switch, restoreAllSessions()
            // imported this user's persisted session and seeded its stamped peer
            // identity; if the peer re-keyed while this user was logged out, the
            // server's key now differs from that stamp and the restored session
            // is STALE -- it must be dropped and the change surfaced, or the
            // conversation silently fails to decrypt (the reported symptom) with
            // no banner to fix it.
            const QString priorIdentity = m_crypto.peerIdentityHex(peer);
            const bool hadRestoredSession = m_crypto.hasSessionFor(peer);

            // Key-change resilience: ensureSharedKey drops the stale in-memory
            // session and returns true when the key differs from one it already
            // held; we then also clear the PERSISTED session so the old one does
            // not return on restart.
            const bool keyChanged = m_crypto.ensureSharedKey(peer, pub);

            // A restored session is stale if we held an identity stamp for it
            // that does not match the server's current key. This catches the
            // user-switch case that ensureSharedKey's own comparison can miss --
            // e.g. when the change is relative to a session restored from disk
            // rather than one seen live this session.
            const bool restoredSessionStale =
                hadRestoredSession
                && !priorIdentity.isEmpty()
                && priorIdentity != pub;

            // NEW-PEER DETECTION (fix for "new peer cannot chat", option ii).
            // The logs proved a genuinely new identity (e.g. "User G") gets its
            // key here but NOTHING ever opens the channel: the deterministic
            // responder queues and stalls forever, and the initiator never sends
            // an opening frame because a new peer is not a key CHANGE and so no
            // handshake is triggered. The fix is to treat a brand-new peer like a
            // key change: flag it for verification, and -- once the user confirms
            // -- acknowledgeKeyChange()'s existing logic makes the deterministic
            // INITIATOR send the opening handshake (the responder drops and waits
            // for it). That opens the channel and the queued message flushes via
            // the outbox-drain trigger already in place.
            //
            // "Genuinely new" must be distinguished from "known peer whose session
            // is about to be restored", or we would flag every peer on every
            // login. The discriminator is: we hold NO in-memory session, NO prior
            // identity, AND there is NO persisted session on disk (loadSession
            // empty). A previously-verified peer always has a persisted session,
            // so this fires ONLY for an identity we have never established a
            // ratchet with. hadRestoredSession/priorIdentity were captured BEFORE
            // ensureSharedKey ran, so they reflect the pre-frame state correctly.
            const bool havePersistedSession =
                m_history.isReady()
                && !m_history.loadSession(peer).isEmpty();
            const bool newPeer =
                !hadRestoredSession
                && priorIdentity.isEmpty()
                && !havePersistedSession
                && !m_unverifiedKeyChange.contains(peer);  // don't double-flag

            // ALREADY-VERIFIED SHORT-CIRCUIT (fix: repeated prompts). If the
            // user has previously confirmed EXACTLY the key that just arrived,
            // there is nothing to verify and no episode to open. Without this a
            // logout wiped the in-memory record and the next login re-flagged an
            // established peer, prompting again for an unchanged number -- the
            // reported defect. The comparison is against the stored key, so a
            // genuine rekey still differs and still warns.
            const bool alreadyVerifiedThisKeyA =
                !pub.isEmpty()
                && m_verifiedPeerIdentity.value(peer) == pub;
            if (alreadyVerifiedThisKeyA && !keyChanged && !restoredSessionStale) {
                qDebug() << "[FLAG] peer" << peer
                         << "| suppressed: this exact key was already verified";
            } else if (keyChanged || restoredSessionStale || newPeer) {
                // Clear the stale session ONLY for a genuine key change or a
                // stale restored session -- those must drop the old chain so a
                // clean one re-bootstraps. For a PURE new peer we must NOT clear
                // anything: there is no stale chain to remove, and -- critically
                // -- clearing the persisted session would erase the very signal
                // (havePersistedSession) that marks this peer as "known" once
                // they are confirmed, causing them to be re-detected as new on
                // every subsequent login. That self-erasing loop is what broke
                // steady-state messaging (established peers wrongly re-flagged,
                // sends blocked by the verify-gate). So the clear is gated to the
                // change/stale cases; the new-peer case only raises the banner.
                if (keyChanged || restoredSessionStale) {
                    m_crypto.dropSession(peer);
                    if (m_history.isReady())
                        m_history.clearSession(peer);
                    // NOTE: we deliberately do NOT clear m_rebootstrapAdopted
                    // here. The one-shot is keyed by the ADOPTED IDENTITY VALUE
                    // (alreadyAdopted := m_rebootstrapAdopted.value(peer) == ik),
                    // so a genuinely NEW key re-arms it on its own -- its `ik`
                    // differs from the stored value. Clearing on every key change
                    // is redundant AND was the direct cause of the re-bootstrap
                    // livelock: when a replayed/stale offline handshake asserts an
                    // `ik` the server never confirms, clearing re-armed the
                    // one-shot so the SAME `ik` adopted-and-refetched on every
                    // replay while the server's differing authoritative key
                    // re-entered this very block -- an unbounded
                    // adopt->refetch->flag->verify_resync storm (hundreds of
                    // thousands of iterations in one session). Leaving the one-shot
                    // set lets the handshake converge branch below drop the stale
                    // frame after exactly one round; a real later re-key (a
                    // different `ik`) still re-arms it naturally.
                    // The PEER's key changed, so any prior attestation of OUR
                    // identity came from the OLD keyholder; the new keyholder has
                    // not attested us. Void it so the gate genuinely requires a
                    // fresh mutual verification under the new key (never honour an
                    // old attestation for a changed peer key).
                    m_peerVerifiedForIdentity.remove(peer);
                    // The stored confirmation attests the OLD peer key. It must
                    // not vouch for the new one, so drop it from memory and from
                    // disk together -- leaving it on disk would let a restart
                    // resurrect a confirmation the user never gave for this key.
                    m_verifiedPeerIdentity.remove(peer);
                    if (m_history.isReady())
                        m_history.clearVerification(peer);
                    // POST-COMPROMISE SECURITY: the chain this peer's rekey
                    // accounting referred to no longer exists. Reset it in lock-
                    // step with the crypto/persisted session so a stale in-flight
                    // ping flag cannot block rekeys on the re-bootstrapped chain
                    // (the "PCS stops after user switching" bug -- see resetPcsFor).
                    resetPcsFor(peer);
                }
                // SECURITY (Part C-i / option ii): surface the change so the user
                // verifies the safety number before the conversation opens. For a
                // changed key this is the "re-verify" banner; for a brand-new peer
                // it is the "verify this new contact before your first message"
                // banner. Confirming runs acknowledgeKeyChange(), which makes the
                // deterministic initiator open the channel.
                qDebug() << "[FLAG] peer" << peer
                         << "| reason" << (keyChanged ? "keyChanged"
                                           : restoredSessionStale ? "staleRestored"
                                           : "newPeer");
                flagKeyChange(peer);
            }
            // DEADLOCK GUARD: having just adopted this peer's current key, re-send
            // any verifyack we owe them. If our earlier ack attested a superseded
            // identity and was ignored, this one -- bound to the key now in force
            // -- lets their bilateral gate finally open. No-op unless we owe one.
            maybeResendVerifyAck(peer);
        }
        // Peer keys just landed: tell QML so the safety-number header recomputes.
        emit peerKeysChanged();
        // Any frames that were waiting on these keys can now be processed.
        for (auto it = keys.begin(); it != keys.end(); ++it)
            replayPendingFrames(it.key());

        // OUTBOX FLUSH (fix for offline-composed messages stuck after reconnect).
        // On a FRESH login the completeHello() flush ran BEFORE any key arrived,
        // so every queued item requeued itself for want of a key. Now that the
        // bulk key dump has populated m_peerKeys, drain the outbox so those queued
        // messages/files are actually sent. Previously the only other trigger was
        // the receive-path drain, which fires ONLY when an INCOMING message
        // decrypts -- so a user who reconnected with just OUTGOING messages queued
        // (and received nothing) saw them sit undelivered until the next reconnect.
        // flushOutbox() is re-entrancy guarded and its own bilateral guard holds
        // any flagged peer's items, so calling it here is safe.
        if (m_socket.state() == QAbstractSocket::ConnectedState
            && !m_outbox.isEmpty())
            flushOutbox();

    } else if (type == "key" || type == "key_update") {
        // A single key. "key" is our own on-demand getkey reply; "key_update" is
        // an UNSOLICITED push from the server telling us a peer reconnected with a
        // DIFFERENT identity key (reinstall, data wipe, new device). Both carry
        // {nick, pubkey} and are handled identically here: the new-key detection
        // below drops any stale session for that peer and raises the safety-number
        // banner, so a changed identity can never silently break decryption. The
        // key_update push is what fixes the stale-key stall -- without it, a peer
        // that changed keys would leave us computing a mismatched ratchet role and
        // failing to decrypt until we happened to reconnect or re-request the key.
        const QString nick = obj.value("nick").toString();
        const QString published = obj.value("pubkey").toString();
        // Which kind of key this is -- the same tag the bulk "keys" dump
        // carries per peer in "key_types". The relay stamps it on both the
        // unsolicited "key_update" push and (since the matching server fix) the
        // "key" reply to getkey. Absent means the legacy interpretation --
        // UNLESS the login dump already showed this relay to be publishing
        // untagged Ed25519 keys, in which case that is what this frame holds
        // too. This is the path an OFFLINE peer's key arrives by, when a stored
        // frame is replayed for someone whose key is not held yet, so it must
        // read the relay the same way the dump did or the two disagree about
        // the same peer.
        QString ikType = obj.value("ik_type").toString();
        if (ikType.isEmpty() && m_relayServesUntaggedEd)
            ikType = QStringLiteral("ed25519");
        if (!published.isEmpty()) {
            // CONVERT HERE, exactly as the bulk "keys" handler does.
            //
            // This is the second and last door through which a published
            // identity key enters the client, and for a long time it was the
            // one that did not convert. A version 2 account publishes its
            // ED25519 key; everything downstream -- m_peerKeys, the ratchet,
            // ensureSharedKey, and above all the safety number -- deals in
            // X25519 agreement keys. Storing the published key verbatim
            // therefore poisoned the pairing for whichever side learned the
            // other's key through this frame rather than the login dump, which
            // is simply whoever was online first. The two devices then computed
            // DIFFERENT safety numbers (nothing to compare), each rejected the
            // other's verifyack as an identity mismatch (the gate never closed),
            // and the ratchet agreed on nothing. One conversion, at the door.
            QByteArray agree;
            if (!CryptoBox::agreementKeyFor(
                    QByteArray::fromHex(published.toUtf8()), ikType, agree)) {
                // An unknown or malformed key type is never guessed at: a wrong
                // guess yields a well-formed secret that merely fails, which is
                // the class of failure nobody can attribute. Keep whatever we
                // already hold and say so.
                qWarning() << "[KEY] peer" << nick
                           << "published an unusable identity key (type"
                           << (ikType.isEmpty() ? QStringLiteral("absent")
                                                : ikType)
                           << ") -- ignoring this update; the key already held "
                              "stands";
                return;
            }
            const QString pub = QString::fromUtf8(agree.toHex());

            // Keep the PUBLISHED form too when it is an Ed25519 identity. A
            // prekey bundle is signed with that key, so bundle verification
            // needs it, while the ratchet needs the derived one. Same
            // bookkeeping the bulk handler does -- without it, a peer learned
            // through this frame had no entry and its bundle could not be bound
            // to the directory.
            if (ikType == QLatin1String("ed25519"))
                m_peerEdKeys.insert(nick, QByteArray::fromHex(published.toUtf8()));
            else
                m_peerEdKeys.remove(nick);

            // DIAGNOSTIC: mirror the bulk handler's "[KEYS]" line. This path
            // used to log nothing at all, which is precisely how a key of the
            // wrong kind sat in m_peerKeys unnoticed -- the logs showed a
            // "[FLAG] ... newPeer" with no preceding key line to explain it.
            qDebug() << "[KEY] peer" << nick
                     << "| ikType" << (ikType.isEmpty() ? QStringLiteral("absent")
                                                        : ikType)
                     << "| published" << published.left(16)
                     << "| agreement" << pub.left(16)
                     << "| knewPeer" << m_peerKeys.contains(nick)
                     << "| oldKey" << (m_peerKeys.contains(nick)
                                           ? m_peerKeys.value(nick).left(16)
                                           : QStringLiteral("(none)"));

            m_peerKeys.insert(nick, pub);
            // Same user-switching detection as the "keys" handler above: capture
            // the restored session's stamp BEFORE ensureSharedKey overwrites it,
            // so a session that is stale relative to the server's current key is
            // dropped and the change is surfaced rather than silently failing.
            const QString priorIdentity = m_crypto.peerIdentityHex(nick);
            const bool hadRestoredSession = m_crypto.hasSessionFor(nick);

            const bool keyChanged = m_crypto.ensureSharedKey(nick, pub);

            const bool restoredSessionStale =
                hadRestoredSession
                && !priorIdentity.isEmpty()
                && priorIdentity != pub;

            // NEW-PEER DETECTION (see the "keys" handler for the full rationale,
            // option ii): a genuinely new identity -- no in-memory session, no
            // prior identity, no persisted session on disk -- is flagged for
            // verification so confirming it opens the channel via the initiator.
            const bool havePersistedSession =
                m_history.isReady()
                && !m_history.loadSession(nick).isEmpty();
            const bool newPeer =
                !hadRestoredSession
                && priorIdentity.isEmpty()
                && !havePersistedSession
                && !m_unverifiedKeyChange.contains(nick);

            // ALREADY-VERIFIED SHORT-CIRCUIT (fix: repeated prompts). If the
            // user has previously confirmed EXACTLY the key that just arrived,
            // there is nothing to verify and no episode to open. Without this a
            // logout wiped the in-memory record and the next login re-flagged an
            // established peer, prompting again for an unchanged number -- the
            // reported defect. The comparison is against the stored key, so a
            // genuine rekey still differs and still warns.
            const bool alreadyVerifiedThisKeyB =
                !pub.isEmpty()
                && m_verifiedPeerIdentity.value(nick) == pub;
            if (alreadyVerifiedThisKeyB && !keyChanged && !restoredSessionStale) {
                qDebug() << "[FLAG] peer" << nick
                         << "| suppressed: this exact key was already verified";
            } else if (keyChanged || restoredSessionStale || newPeer) {
                // See the "keys" handler for the full rationale: clear the stale
                // session ONLY for a genuine key change or stale restored
                // session, NEVER for a pure new peer -- clearing a new peer's
                // (nonexistent) persisted session would erase the "known" signal
                // and cause endless re-flagging that blocks steady-state sends.
                if (keyChanged || restoredSessionStale) {
                    m_crypto.dropSession(nick);
                    if (m_history.isReady())
                        m_history.clearSession(nick);
                    // Deliberately NOT cleared here -- see the bulk "keys" branch
                    // and the m_rebootstrapAdopted declaration. The one-shot is
                    // keyed by identity value, so a genuine new key re-arms it on
                    // its own; clearing on every change re-armed it for a SAME-`ik`
                    // replay and was the cause of the adopt->refetch->flag->
                    // verify_resync livelock. Leaving it set lets the handshake
                    // converge branch drop a stale replayed handshake after one
                    // round.
                    // The peer's key changed: void any prior attestation of our
                    // identity (it came from the old keyholder). See the bulk
                    // "keys" branch for the full rationale.
                    m_peerVerifiedForIdentity.remove(nick);
                    // The stored confirmation attests the OLD peer key; it must
                    // not vouch for the new one. Drop it from memory and disk.
                    m_verifiedPeerIdentity.remove(nick);
                    if (m_history.isReady())
                        m_history.clearVerification(nick);
                    // POST-COMPROMISE SECURITY: same as the bulk "keys" branch --
                    // the old chain is gone, so clear this peer's rekey window in
                    // lockstep so a leftover in-flight ping flag cannot disable
                    // the heartbeat on the re-bootstrapped chain (see resetPcsFor).
                    resetPcsFor(nick);
                }
                qDebug() << "[FLAG] peer" << nick
                         << "| reason" << (keyChanged ? "keyChanged"
                                           : restoredSessionStale ? "staleRestored"
                                           : "newPeer");
                flagKeyChange(nick);   // SECURITY: warn on key change / new peer
            }
            // DEADLOCK GUARD: adopting this peer's current key is exactly when a
            // previously-ignored verifyack can be usefully re-sent (bound to the
            // key now in force). No-op unless we owe one (see maybeResendVerifyAck).
            maybeResendVerifyAck(nick);
            // This peer's key is now present: recompute the safety number.
            emit peerKeysChanged();
            // And process anything that was waiting on this key.
            replayPendingFrames(nick);

            // OUTBOX FLUSH: same reason as the bulk "keys" handler. A queued item
            // may have been waiting only for THIS peer's key -- e.g. a getkey we
            // issued from an earlier flush that requeued for want of the key, or a
            // key_update push after the peer reconnected. Drain now so it is sent
            // without needing an incoming message to trigger the receive-path
            // drain first. Guarded + re-entrancy-safe as above.
            if (m_socket.state() == QAbstractSocket::ConnectedState
                && !m_outbox.isEmpty())
                flushOutbox();
        }

    } else if (type == "msg") {
        const QString from = obj.value("from").toString();
        const QString to = obj.value("to").toString();
        const QString cipher = obj.value("cipher").toString();
        const QString dhHex  = obj.value("dh").toString();
        const quint32 pn = static_cast<quint32>(obj.value("pn").toDouble());
        const quint32 n  = static_cast<quint32>(obj.value("n").toDouble());
        const QString nonce = obj.value("nonce").toString();
        const QString ct = obj.value("ct").toString();
        const qint64 ts = static_cast<qint64>(obj.value("ts").toDouble());

        // SECURITY (user switching / re-bootstrap): a "handshake" frame is a
        // normal ratchet "msg" the peer sent when they CONFIRMED our changed
        // safety number, purely to make the re-established chain live before
        // either side types. It MUST still be decrypted -- that is what advances
        // (or lazily re-bootstraps) our receiving chain to match theirs -- but
        // its decrypted sentinel is meaningless and is SWALLOWED: no bubble, no
        // history row, no unread badge. Recognising this one field is the entire
        // reason the frame does not render as a blank message. The field rides
        // inside the msg envelope the server already relays opaquely, so no
        // server change is involved.
        const QString kind = obj.value("kind").toString();
        const bool isHandshake = (kind == QLatin1String("handshake"));
        // POST-COMPROMISE SECURITY control frames. Both are ordinary ratchet
        // "msg" frames that must be DECRYPTED (that is what advances -- and, when
        // the sender's key is new, DH-ratchets -- our chain, which is the whole
        // point) but whose sentinel payload is meaningless and is SWALLOWED, just
        // like a handshake. A rekey-ping additionally provokes a rekey-pong reply
        // so the round-trip completes; a rekey-pong answers our ping and asks for
        // nothing further (so the exchange terminates). Recognising these fields
        // is the only reason the frames do not surface as blank messages.
        const bool isRekeyPing = (kind == QLatin1String("rekey-ping"));
        const bool isRekeyPong = (kind == QLatin1String("rekey-pong"));

        // Figure out which peer this conversation is with. If the message is
        // addressed to us, the peer is the sender; if it is our own message
        // echoed back from history, the peer is the recipient.
        const QString peer = (from == m_nick) ? to : from;

        // X3DH OPENER. A first message from a peer who initiated through our
        // prekey bundle carries the three values we need to derive the same
        // secret. It must be handled BEFORE the frame reaches the ratchet,
        // because there is no session yet for the ratchet to use -- this is what
        // creates it. Absent fields mean an ordinary frame, or a peer still on
        // the legacy bootstrap, and the old path is left untouched.
        if (from != m_nick && obj.contains("ik_a") && obj.contains("ek_a")
            && !m_crypto.hasSessionFor(peer)) {
            const QByteArray ikA =
                QByteArray::fromHex(obj.value("ik_a").toString().toUtf8());
            const QByteArray ekA =
                QByteArray::fromHex(obj.value("ek_a").toString().toUtf8());
            const qint32 opkId = qint32(obj.value("opk_id").toInt(-1));
            const QByteArray spkUsed =
                QByteArray::fromHex(obj.value("spk_used").toString().toUtf8());
            if (m_crypto.acceptX3dhSession(peer, ikA, ekA, opkId, spkUsed)) {
                persistSession(peer);
                // The pool shrank by one, so write it back before anything else
                // can fail: a consumed prekey that survives a restart would let
                // a replayed opener establish a second session.
                if (m_history.isReady())
                    m_history.savePrekeys(m_crypto.serialisePrekeys());
                qDebug() << "[X3DH] accepted opener from" << peer;
            } else {
                qWarning() << "[X3DH] REJECTED opener from" << peer
                           << "-- replayed prekey or malformed header";
                return;
            }
        }

        // SELF-ECHO: never feed our OWN messages back through the RECEIVING
        // ratchet. The relay replays stored frames to both parties, so every
        // message we sent returns with from == m_nick. Such a frame carries OUR
        // sending DH key in its header, so handing it to the receiving chain
        // makes that chain perform a DH step against our own key and derive
        // message keys the peer never produced -- corrupting the very chain the
        // peer's next real message needs. It can also never yield plaintext (we
        // hold no receiving chain for our own sends), which is why the log shows
        // thirty consecutive frames with decryptEmpty true and willDisplay false.
        // The messages are already in local history, so nothing is lost by
        // ignoring the echo, and the receiving chain stays in step.
        if (from == m_nick) {
            qDebug() << "[RX] ignoring self-echo of our own message to" << peer
                     << "(already in local history; must not touch the "
                        "receiving chain).";
            return;
        }

        // We need the sender's identity key to bootstrap the ratchet session.
        // If we do not have it yet, stash this frame and fetch the key;
        // replayPendingFrames re-feeds it once the key arrives.
        if (!m_peerKeys.contains(peer)) {
            m_pendingFrames[peer].append(raw);
            requestKeyFor(peer);
            return;
        }

        // SAFETY-NUMBER-RACE FIX (Bug 1): a handshake carries the sender's
        // CURRENT identity key in "ik". The whole point of the handshake is to
        // re-bootstrap a chain from the sender's NEW identity after a key change,
        // and BOTH the bootstrap and the deterministic initiator/responder role
        // depend on each side holding the other's CURRENT key. If this handshake
        // arrived BEFORE the server's key_update carrying that same new key, the
        // key we hold for the sender (m_peerKeys[peer]) is STALE -- decrypting and
        // bootstrapping now would build our responder session against the old key
        // and, worse, could make us pick the same ratchet role as the sender, so
        // the two chains never agree and the safety numbers differ (the reported
        // intermittent failure). Guard against it: if the frame's "ik" differs
        // from the key we currently hold, our key is stale. Record the new key
        // immediately (it is authenticated in the sense that the following decrypt
        // must still succeed under the re-bootstrapped chain), request a fresh
        // copy from the server as the authoritative source, stash this frame, and
        // let replayPendingFrames() re-feed it once the key is confirmed. Only
        // handshakes carry "ik"; ordinary frames omit it and skip this guard.
        // SELF-AUTHORED FRAME GUARD (fix: session poisoned with our own key).
        // The relay replays stored frames to BOTH parties, so our OWN handshakes
        // come back to us with from == m_nick. Their "ik" stamp is OUR identity,
        // not the peer's. Adopting it made m_peerKeys[peer] equal to our own
        // public key and bootstrapped a session against ourselves -- visible in
        // the log as "role RESP peer m75 myPub d88ba732... peerPub d88ba732...",
        // after which the entire replayed conversation failed to decrypt and the
        // peer was re-flagged as changed, prompting the user to verify a second
        // time. An identity may only ever be learned from a frame the PEER sent.
        const bool selfAuthored = (from == m_nick);
        if (isHandshake && !selfAuthored) {
            const QString ik = obj.value("ik").toString();
            if (!ik.isEmpty() && ik != m_peerKeys.value(peer)) {
                // The handshake states an identity different from the one we
                // hold. Adopt it -- but ONLY re-fetch-and-stash if we have not
                // already adopted this exact identity for this peer. Without this
                // one-shot guard, a handshake whose `ik` never converges with the
                // server's authoritative key re-triggers the mismatch on every
                // replay and loops forever (the repeated "[REBOOTSTRAP] adopting"
                // storm). The first time we see a given `ik`, we record it, adopt
                // it, and re-request the authoritative copy; if the SAME `ik`
                // comes back after we already adopted it, we fall through and let
                // the frame bootstrap/decrypt against the adopted key instead of
                // re-fetching again.
                const bool alreadyAdopted =
                    (m_rebootstrapAdopted.value(peer) == ik);
                if (!alreadyAdopted) {
                    qWarning() << "[REBOOTSTRAP] handshake from" << peer
                               << "carries a NEWER identity than we hold "
                                  "(key_update race); adopting it and re-fetching "
                                  "before bootstrap.";
                    // Remember we adopted THIS identity so a replay of the same
                    // frame does not re-fetch again. The one-shot is keyed by this
                    // value, so a genuinely different `ik` later re-arms it on its
                    // own -- we no longer clear it on key change (that re-armed a
                    // same-`ik` replay and caused the livelock; see below).
                    m_rebootstrapAdopted.insert(peer, ik);
                    // Adopt the sender's stated current identity so the imminent
                    // re-bootstrap uses it; ensureSharedKey drops any stale
                    // session bound to the old key and flags the change.
                    m_peerKeys.insert(peer, ik);
                    m_crypto.ensureSharedKey(peer, ik);
                    // Ask the server for the authoritative copy too, then replay.
                    m_pendingFrames[peer].append(raw);
                    requestKeyFor(peer);
                    emit peerKeysChanged();
                    return;
                }
                // Already adopted this identity once. The one-shot re-fetch above
                // has since completed, so m_peerKeys[peer] now holds the SERVER's
                // AUTHORITATIVE key for this peer. Two outcomes:
                //
                //   * Server AGREES with this handshake's `ik` (the key_update
                //     race resolved as expected -- `ik` really was the peer's new
                //     key and the server has caught up). Make the crypto session
                //     hold it and fall through to bootstrap/decrypt this frame.
                //
                //   * Server DISAGREES (`ik` != the authoritative key). This
                //     handshake asserts a SUPERSEDED identity -- almost always a
                //     replayed/stale offline handshake queued from before the
                //     peer's latest re-key. The server is authoritative, so we do
                //     NOT re-adopt `ik` and do NOT re-fetch (re-fetching would only
                //     return the same authoritative key and spin the
                //     adopt->refetch->flag->verify_resync loop forever). Instead we
                //     KEEP the authoritative key and DROP this stale control frame.
                //     Dropping loses nothing user-visible: a handshake is a swallowed
                //     control frame, and our own send path opens the channel against
                //     the authoritative key (store-and-forwarded if the peer is
                //     offline). The peer will re-handshake with its current identity
                //     when it next comes online, and that key will match the server.
                const QString authoritative = m_peerKeys.value(peer);
                if (ik != authoritative) {
                    qWarning() << "[REBOOTSTRAP] handshake from" << peer
                               << "restates a SUPERSEDED identity that disagrees "
                                  "with the server's authoritative key; dropping "
                                  "this stale control frame and keeping the "
                                  "authoritative key (loop broken).";
                    return;
                }
                qWarning() << "[REBOOTSTRAP] handshake from" << peer
                           << "restates the identity the server confirmed; "
                              "bootstrapping without re-fetch (loop broken).";
                m_crypto.ensureSharedKey(peer, ik);
            }
        }
        // Client-side duplicate suppression: the server replays stored messages
        // on login (offline delivery), so a frame can arrive twice -- once live,
        // once as replay. Each ratchet message key is single-use, so the second
        // copy would fail to decrypt and (before this guard) surface as an error
        // and a lost conversation. Identify a frame by its ratchet key + index
        // (dhHex + ":" + n); n resets when the DH key rotates, so both are
        // needed. If we have already decrypted this exact frame, drop it quietly.
        const QString frameKey = dhHex + ":" + QString::number(n);
        // DIAGNOSTIC (temporary): show every received text frame and whether the
        // dedup guard is about to drop it. If a FIRST message is being dropped
        // here, dedup is the bug; if it passes to decrypt, the ratchet is.
        const bool willDrop = m_seenFrames.value(peer).contains(frameKey);
        qDebug() << "[RX] from" << from << "to" << to << "peer" << peer
                 << "activePeer" << m_activePeer
                 << "n" << n << "pn" << pn << "frameKey" << frameKey
                 << "dedupWillDrop" << willDrop
                 << "haveKey" << m_peerKeys.contains(peer)
                 << "hasSession" << m_crypto.hasSessionFor(peer);
        if (willDrop) {
            // Already delivered this exact frame; ignore the duplicate.
            return;
        }

        m_crypto.ensureSharedKey(peer, m_peerKeys.value(peer));
        const QString plaintext =
            m_crypto.decryptFrom(peer, cipher, dhHex, pn, n, nonce, ct);
        // DIAGNOSTIC (temporary): did the ratchet decrypt this text frame? A
        // control frame (handshake or rekey ping/pong) is decrypted but never
        // displayed, so it is excluded from willDisplay.
        const bool isControlFrame = isHandshake || isRekeyPing || isRekeyPong;
        qDebug() << "[RX-DECRYPT] from" << from << "peer" << peer
                 << "kind" << (kind.isEmpty() ? QStringLiteral("text") : kind)
                 << "decryptEmpty" << plaintext.isEmpty()
                 << "willDisplay" << (!isControlFrame && !plaintext.isEmpty()
                                      && peer == m_activePeer);
        // Act only on a successful decrypt. (The old "|| true" forced display
        // even on failure; decryptFrom now emits decryptionFailed() and returns
        // empty on a bad frame.)
        if (!plaintext.isEmpty()) {
            // Record this frame as delivered so a later replay is suppressed.
            // This applies to handshakes too: the server may replay the
            // handshake frame on a future reconnect, and we must drop that
            // duplicate rather than step the ratchet for it a second time.
            m_seenFrames[peer].insert(frameKey);

            // POST-COMPROMISE SECURITY: an authenticated frame FROM THE PEER
            // (not our own history echo) is the conversational turn that heals
            // our side -- the decrypt above advanced, and where the peer's key
            // was new DH-ratcheted, our chain with fresh randomness the attacker
            // never saw. Reset the recovery window and clear any in-flight ping.
            // This covers text, handshakes, and rekey frames uniformly.
            if (from != m_nick)
                noteInboundFrom(peer);

            // RELIABILITY: if we owed this peer a pong (an earlier ping arrived
            // before our sending chain was alive) and THIS inbound frame is what
            // revived it -- most often the initiator's re-bootstrap handshake
            // after a user switch -- clear the debt now. Skipped when this frame
            // is itself the ping: that case is answered directly in the branch
            // below, so draining here too would send a redundant pong.
            if (from != m_nick && !isRekeyPing)
                sendOwedPongIfReady(peer);

            if (isHandshake) {
                // SECURITY (re-bootstrap): the decrypt above already did its one
                // job -- advancing/re-bootstrapping our receiving chain so it
                // agrees with the peer's re-established chain. The sentinel
                // plaintext is meaningless: SWALLOW it. No bubble, no history
                // row, no unread badge. We DO persist the now-advanced session,
                // so the re-established chain survives a restart. From here, the
                // very next ordinary message decrypts on the fresh chain.
                persistSession(peer);
            } else if (isRekeyPing) {
                // POST-COMPROMISE SECURITY: a rekey-ping from the peer. The
                // decrypt above already advanced/ratcheted our chain -- SWALLOW
                // the sentinel (no bubble/history/badge) and persist the advanced
                // session. Then answer with a rekey-pong so the ROUND-TRIP
                // completes: our pong carries our current key to the peer and
                // provokes nothing further, and when they process it their side
                // ratchets too -- restoring post-compromise security in both
                // directions. We never reply to our own replayed ping (from !=
                // m_nick). If the pong CANNOT go out this instant -- our sending
                // chain is not yet alive (a responder whose chain the initiator's
                // opener has not revived) or we are momentarily disconnected --
                // transmitRekey returns false WITHOUT sending; rather than drop
                // the answer (leaving the peer's ping forever unanswered, the
                // "pong is not sent" stall reported after a user switch) we RECORD
                // the debt and arm the retry, so the pong goes out the moment the
                // chain revives (sendOwedPongIfReady) or on the next kick tick.
                persistSession(peer);
                if (from != m_nick) {
                    // GUARANTEE A DEDICATED PONG. Every ping from the peer incurs
                    // a pong debt that is recorded FIRST and unconditionally, then
                    // paid immediately if possible. Recording before sending means
                    // nothing that happens in between -- a concurrent key-update
                    // that re-bootstraps the session, a momentary disconnect -- can
                    // lose the obligation: the debt is discharged ONLY by a pong
                    // actually going on the wire (sendOwedPongIfReady / kickRekey
                    // remove it on a confirmed send, and resetPcsFor no longer
                    // clears it). If it cannot be paid this instant it stays owed
                    // and every trigger (next inbound, reconnect, idle backstop,
                    // and the kick timer, which now refuses to give up while a pong
                    // is owed on a live session) retries until it is sent -- so a
                    // ping is never left without its dedicated pong.
                    m_pongOwed.insert(peer);
                    sendOwedPongIfReady(peer);          // pay it now if we can
                    if (m_pongOwed.contains(peer)) {    // still owed -> drive retry
                        m_rekeyKickTries = 0;           // fresh trigger: full budget
                        m_rekeyKickTimer.start();
                        qDebug() << "[PCS] rekey-ping from" << peer
                                 << "but chain not sendable yet; pong owed,"
                                    " will retry until sent.";
                    }
                }
            } else if (isRekeyPong) {
                // POST-COMPROMISE SECURITY: a rekey-pong answering our ping. The
                // round-trip is complete and this side is healed (noteInboundFrom
                // above already reset the window and cleared the in-flight ping).
                // SWALLOW the sentinel and persist the advanced session. Nothing
                // more to send -- the exchange terminates here.
                persistSession(peer);
            } else {
                const bool mine = (from == m_nick);
                // The sender stamped this message with a stable id in "mid"; keep
                // it so a later delete (from either side) can locate this exact
                // row in the model and in history. (Legacy peers that predate the
                // feature omit it; the row is then simply not individually
                // deletable, which is harmless.)
                const QString mid = obj.value("mid").toString();
                // EDIT frame: an ordinary encrypted message that the sender tagged
                // with "edit_of" = the stable id of an EARLIER message. It is
                // decrypted exactly like any message (the ratchet advanced above),
                // but instead of a new bubble it REPLACES that message's body in
                // place. We re-seal the new plaintext into the SAME history row so
                // the edit -- and its "edited" marker -- survive a restart. If we
                // never held the original (updateTextRow updated no row: the edit
                // arrived before the first copy, or that message predates history),
                // we fall back to inserting it as a fresh message so nothing is
                // lost. An edit refines an existing message, so -- like a reaction
                // or a delete -- it raises no notification and no unread badge.
                const QString editOf = obj.value("edit_of").toString();
                if (!editOf.isEmpty()) {
                    QString eNonce, eCt;
                    const bool sealed =
                        m_crypto.localSeal(plaintext, eNonce, eCt);
                    const bool updated =
                        sealed && m_history.updateTextRow(editOf, eNonce, eCt);
                    if (updated) {
                        // no-op if that conversation is not currently on screen;
                        // the persisted edit is picked up when it is next opened.
                        m_messages.editTextByMid(editOf, plaintext);
                        emit messageEdited(peer, editOf);
                    } else {
                        // Original unknown: store and show the edited text as a
                        // new message under that id (best effort).
                        if (sealed)
                            m_history.addTextRow(peer, from, eNonce, eCt, ts,
                                                 mine, editOf);
                        if (peer == m_activePeer)
                            m_messages.addMessage(from, plaintext, ts, mine,
                                                  editOf);
                        else if (!mine)
                            m_users.incrementUnread(peer);
                    }
                    persistSession(peer);
                } else {
                // A message arriving from the peer means they are no longer
                // typing: clear any "typing…" state we were showing for them.
                if (!mine)
                    setPeerTyping(peer, QStringLiteral("idle"));
                // Persist the plaintext re-sealed under the static local key, not
                // the wire ciphertext (unrecoverable post-ratchet); save session.
                QString histNonce, histCt;
                if (m_crypto.localSeal(plaintext, histNonce, histCt))
                    m_history.addTextRow(peer, from, histNonce, histCt, ts, mine,
                                         mid);
                persistSession(peer);
                if (peer == m_activePeer) {
                    m_messages.addMessage(from, plaintext, ts, mine, mid);
                } else if (!mine) {
                    // Arrived for a conversation not on screen: bump the badge.
                    m_users.incrementUnread(peer);
                }
                // ANDROID NOTIFICATION: an incoming message from the peer (never
                // our own echo) posts a status-bar notification carrying the
                // sender and the DECRYPTED text -- possible because the
                // foreground service kept this process, and thus the ratchet,
                // alive to decrypt it. Off Android this is a no-op. We do not
                // notify for a message in the conversation already open and
                // focused, to avoid a redundant buzz; incrementUnread above
                // handles the not-open case visually, and the notification
                // reinforces it. Notifying regardless of foreground/background is
                // deliberate: Android decides whether to surface a heads-up based
                // on whether the app is focused, so we always post and let the OS
                // present it appropriately.
                if (!mine && peer != m_activePeer) {
                    AndroidNotifier::notifyMessage(
                        Localization::instance()->t("notif.newMessageTitle")
                            .arg(from),
                        plaintext,
                        peer);
                    DesktopNotifier::notify(
                        Localization::instance()->t("notif.newMessageTitle")
                            .arg(from),
                        plaintext,
                        peer);
                }
                }
            }

            // OUTBOX-DRAIN TRIGGER (fix for "queued messages never sent"). A
            // frame we just decrypted may have brought this peer's ratchet chain
            // ALIVE -- most importantly, if we are the responder (Bob) for a
            // re-established session, THIS inbound frame (the initiator's
            // handshake or first message) is exactly what created our sending
            // chain. Any messages the user queued while we had no sending chain
            // (encryptFor reported "not ready") are sitting in m_outbox with
            // nothing to send them: flushOutbox() is otherwise only called from
            // onConnected(), which already fired. So drain the outbox now that a
            // send may be possible. flushOutbox() is guarded against re-entrancy
            // and re-queues anything still not sendable, so calling it here is
            // safe even when the queue is empty or the chain is not ready yet.
            if (!m_outbox.isEmpty()
                && m_socket.state() == QAbstractSocket::ConnectedState)
                flushOutbox();
        }

    } else if (type == "verify_resync") {
        // The peer is asking us to RE-SEND our verifyack (see sendVerifyResync).
        // This arrives when the peer (re-)entered a verification episode for us
        // and needs our attestation again -- e.g. their copy of our ack was lost
        // or wiped by a re-flag under an unchanged identity. We re-send our
        // verifyack ONLY if we currently consider this peer verified from our
        // side (we have verified them AND are not ourselves still flagged for
        // them); otherwise there is nothing to attest and we ignore the request,
        // exactly as the peer expects. This never opens our own gate and never
        // steps the ratchet.
        const QString from = obj.value("from").toString();
        const QString to   = obj.value("to").toString();
        if (from == m_nick || to != m_nick)
            return;
        const QString peer = from;
        // Re-emit our verifyack ONLY if the conversation is FULLY resolved on our
        // side: we hold the peer's key, we are not still required to verify them
        // (not in m_unverifiedKeyChange), AND we are not ourselves mid-episode for
        // them (not in m_pendingBilateral). That last condition is what makes this
        // safe: we never re-attest while our own verification of the peer is
        // unsettled -- in that case the normal acknowledge flow sends the ack when
        // the user confirms. A peer we have fully verified gets a harmless,
        // idempotent re-ack; anyone else is ignored, exactly as they expect.
        const bool fullyVerifiedThem =
            m_peerKeys.contains(peer)
            && !m_unverifiedKeyChange.contains(peer)
            && !m_pendingBilateral.contains(peer);
        if (fullyVerifiedThem) {
            qWarning().noquote()
                << "[VERIFY] got verify_resync from" << peer
                << "-- re-sending our verifyack (conversation resolved on our side).";
            sendOrQueueVerifyAck(peer);
        } else {
            qWarning().noquote()
                << "[VERIFY] got verify_resync from" << peer
                << "-- ignoring (our side is not a settled verification).";
        }

    } else if (type == "verifyack") {
        // BILATERAL VERIFICATION: the peer is telling us THEY have verified our
        // safety number, so our half of the both-verified gate can open. This is
        // a plaintext control frame (no ciphertext, no ratchet step) that the
        // server relays live and store-and-forwards to an offline recipient,
        // exactly like a "delete". It is accepted only when bound to the keys
        // currently in force on BOTH ends, so a stale ack -- from an identity that
        // has since changed again -- cannot wrongly open the gate.
        const QString from = obj.value("from").toString();
        const QString to   = obj.value("to").toString();
        // history_for replays stored frames to BOTH parties, so our OWN verifyack
        // comes back to us on a later login. Ignore anything we sent, or anything
        // not addressed to us.
        if (from == m_nick || to != m_nick)
            return;
        const QString peer = from;

        // We need the sender's identity key to bind the ack to their current
        // identity. If we do not hold it yet, stash the frame and fetch the key;
        // replayPendingFrames() re-feeds it (through this same handler) once the
        // key arrives -- the same mechanism msg/file_init use.
        if (!m_peerKeys.contains(peer)) {
            m_pendingFrames[peer].append(raw);
            requestKeyFor(peer);
            return;
        }

        const QString senderIk  = obj.value("ik").toString();      // peer's identity
        const QString verifiedIk = obj.value("peer_ik").toString(); // identity they verified (should be OURS)
        // Accept only if the ack comes from the peer's CURRENT identity (the key
        // we hold and will verify against) AND attests OUR CURRENT identity (not a
        // superseded one). Either mismatch means the ack is stale -- an identity
        // changed again since it was produced -- so ignore it. Causal ordering
        // (the key_update that carries a changed key is sent before any verifyack
        // the peer produces afterwards) guarantees the matching key reaches us
        // first, so in practice this only drops genuinely stale/duplicate acks.
        if (senderIk.isEmpty() || senderIk != m_peerKeys.value(peer)
            || verifiedIk.isEmpty() || verifiedIk != m_crypto.publicKeyHex()) {
            // NAME THE REASON. Four separate conditions reach this line and
            // the message named none of them, so an ack dropped because the
            // relay served the wrong FORM of a key looked exactly like one
            // dropped because a key had genuinely changed. Telling them apart
            // meant reasoning backwards from key fragments in unrelated log
            // lines. These are public keys, so printing them costs nothing.
            QString why;
            if (senderIk.isEmpty())
                why = QStringLiteral("the ack carries no sender identity");
            else if (senderIk != m_peerKeys.value(peer))
                why = QStringLiteral("sender identity %1 is not the key we hold "
                                     "for them (%2)")
                          .arg(senderIk.left(16),
                               m_peerKeys.contains(peer)
                                   ? m_peerKeys.value(peer).left(16)
                                   : QStringLiteral("(none held)"));
            else if (verifiedIk.isEmpty())
                why = QStringLiteral("the ack attests no identity of ours");
            else
                why = QStringLiteral("it attests %1, but our current identity "
                                     "is %2")
                          .arg(verifiedIk.left(16),
                               m_crypto.publicKeyHex().left(16));
            qDebug() << "[VERIFY] ignoring verifyack from" << peer << "--" << why;
            return;
        }

        const bool wasNew = !m_peerVerified.contains(peer);
        m_peerVerified.insert(peer);
        // Remember that this peer attested our CURRENT identity. The accept rule
        // above guarantees verifiedIk == our current public key, so record that
        // key. This survives a future re-flag and lets an unchanged-identity
        // re-flag honour the standing attestation instead of deadlocking.
        m_peerVerifiedForIdentity.insert(peer, m_crypto.publicKeyHex());

        // If the peer confirmed BEFORE we did (we are still flagged), the red
        // warning banner stays up until we verify; add a one-off line nudging us.
        // If we had already verified, tryResolveBilateral() below completes the
        // episode and writes the "both parties" line instead (no duplicate line).
        if (wasNew
            && m_pendingBilateral.contains(peer)
            && m_unverifiedKeyChange.contains(peer)) {
            const QString line =
                QStringLiteral("%1 verified your safety number. Verify %1 to "
                               "start exchanging messages.").arg(peer);
            if (peer == m_activePeer)
                m_messages.addSystem(line);
            if (m_history.isReady())
                m_history.addSystemRow(peer, line,
                                       QDateTime::currentMSecsSinceEpoch());
            emit safetyNumberChanged(peer);   // refresh QML bindings
        }

        tryResolveBilateral(peer);

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

        // PHANTOM-FAILURE FIX (Issue #1): is this a server REPLAY of an
        // offline-queued file, or a LIVE transfer? The server tags a replayed
        // file_init with "replayed": true. A replayed file queued under a
        // superseded identity pairing can no longer be decrypted, and such a
        // failure is expected and must be handled SILENTLY (no error message),
        // whereas a live transfer's failure is worth surfacing to the user.
        const bool replayed = obj.value("replayed").toBool(false);

        // We need the sender's key to derive the same per-file key they used.
        // If we do not have it yet, stash this file_init and fetch the key;
        // replayPendingFrames re-feeds it once the key arrives. Previously this
        // dropped the transfer, so a file from a peer whose key we had not yet
        // fetched never arrived until that conversation had been opened.
        if (!m_peerKeys.contains(from)) {
            // For a REPLAYED file we do NOT chase the key: a stale offline file
            // is exactly the case that cannot be decrypted, and stashing it would
            // only defer the same silent drop. Drop it now, quietly.
            if (replayed) {
                qDebug() << "[FILE] dropping replayed file_init from" << from
                         << "-- no key held; stale offline file, ignored.";
                return;
            }
            m_pendingFrames[from].append(raw);
            requestKeyFor(from);
            return;
        }
        // Recover the random per-file key the sender delivered OVER THE RATCHET
        // (the "keyenc" object), using the same ratchet decrypt path text uses --
        // so the file key inherits forward secrecy and PCS. A file_init without
        // keyenc is an unsupported legacy/static-key transfer: we no longer derive
        // keys from the static identity secret, so drop it (silently if this is a
        // stale replay).
        const QJsonObject keyenc = obj.value("keyenc").toObject();
        if (keyenc.isEmpty()) {
            if (!replayed)
                emit fileReceiveFailed(msgId, tr("unsupported file format"));
            else
                qDebug() << "[FILE] replayed file_init without keyenc from" << from
                         << "-- legacy static-key transfer; dropped.";
            return;
        }
        const QString kCipher = keyenc.value("cipher").toString();
        const QString kDh     = keyenc.value("dh").toString();
        const quint32 kPn     = static_cast<quint32>(keyenc.value("pn").toDouble());
        const quint32 kN      = static_cast<quint32>(keyenc.value("n").toDouble());
        const QString kNonce  = keyenc.value("nonce").toString();
        const QString kCt     = keyenc.value("ct").toString();

        // RATCHET-FRAME DEDUP (same as the text path): the server replays an
        // offline-queued file_init, so its key frame can arrive twice -- once
        // live, once as replay. Each ratchet message key is single-use, so
        // decrypting the same key frame twice would step the receiving chain a
        // second time and desynchronise it. Identify the frame by dh:n and, if we
        // have already consumed it, this whole file is a duplicate -- drop it.
        const QString keyFrameKey = kDh + QLatin1Char(':') + QString::number(kN);
        if (m_seenFrames.value(from).contains(keyFrameKey)) {
            qDebug() << "[FILE] duplicate file_init (key frame already seen) from"
                     << from << "-- dropping.";
            return;
        }

        m_crypto.ensureSharedKey(from, m_peerKeys.value(from));
        const QString fileKeyHex =
            m_crypto.decryptFrom(from, kCipher, kDh, kPn, kN, kNonce, kCt);
        if (fileKeyHex.isEmpty()) {
            if (!replayed)
                emit fileReceiveFailed(msgId, tr("could not recover file key"));
            else
                qDebug() << "[FILE] replayed file" << msgId
                         << "key undecryptable (stale pairing); dropped.";
            return;
        }
        // The key frame decrypted: record it so a later replay is suppressed, and
        // treat it as an authenticated inbound frame from the peer -- it heals our
        // side (resets the recovery window / clears any in-flight ping) exactly
        // like a text frame, and we persist the advanced session.
        m_seenFrames[from].insert(keyFrameKey);
        if (from != m_nick)
            noteInboundFrom(from);
        persistSession(from);
        QByteArray fileKey = QByteArray::fromHex(fileKeyHex.toLatin1());

        auto in = std::make_shared<IncomingFile>();
        in->msgId          = msgId;
        in->sender         = from;
        in->filename       = filename;
        in->mime           = mime;
        in->expectedSize   = size;
        in->nextChunkIndex = 0;
        in->replayed       = replayed;

        // Initialise the streaming decryptor with the header the sender placed
        // in the file_init envelope. If this fails the header was corrupt -- or,
        // for a replayed file, simply un-derivable under our current identity, in
        // which case we drop it silently rather than alarming the user.
        if (!in->crypto.initPull(fileKey, header)) {
            if (!replayed)
                emit fileReceiveFailed(msgId, tr("could not start decryption"));
            else
                qDebug() << "[FILE] replayed file" << msgId
                         << "cannot init decryption (stale pairing); dropped.";
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
                // Durably record that we now have this file, so the server omits
                // it from the offline replay on our next login (stops the phantom
                // re-transfer on every reconnect). See onBinaryMessageReceived for
                // the same call on the normal TAG_FINAL finalization path.
                m_history.recordReceivedFile(msgId, in->sender,
                                             QDateTime::currentMSecsSinceEpoch());
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

    } else if (type == "delete") {
        // Inbound retraction (delete-for-everyone from the peer). Tombstone the
        // named message in the open conversation (if shown) and in history, so
        // the "This message was deleted" placeholder replaces it here too and
        // survives a restart. No decryption is involved: the frame only names a
        // message id that we already hold. The 'from' field is the peer whose
        // message is being retracted; we verify it is addressed to us implicitly
        // (the server only relays frames addressed to us). We do not require the
        // conversation to be open -- history is always tombstoned by mid.
        const QString from = obj.value("from").toString();
        const QString mid  = obj.value("mid").toString();
        if (!mid.isEmpty()) {
            m_messages.markDeletedByMid(mid);   // no-op if that convo not open
            m_history.markDeleted(mid);          // persist the tombstone
            // If the retracted message was in a conversation not on screen, the
            // unread badge (if any) is left as-is: a retraction should not add a
            // notification. Nothing else to do.
            emit messageDeleted(from, mid);
        }

    } else if (type == "reaction") {
        // Inbound reaction from the peer (an agree/disagree on one of our -- or
        // their own -- messages). Like a delete it names a message id we already
        // hold and carries no ciphertext. We persist it against the peer's slot
        // and apply it to the open conversation if that chat is on screen; if it
        // is not, the persisted value is picked up when the conversation is next
        // opened. The server only relays frames addressed to us, and 'from' is
        // the authenticated reactor. An empty kind is a retraction, which
        // setReaction erases and applyReaction clears.
        const QString from = obj.value("from").toString();
        const QString mid  = obj.value("mid").toString();
        const QString kind = obj.value("kind").toString();
        if (!from.isEmpty() && !mid.isEmpty()) {
            m_history.setReaction(from, mid, QStringLiteral("peer"), kind);
            m_messages.applyReaction(mid, /*mine=*/false, kind); // no-op if closed
            emit reactionChanged(from, mid);
        }

    } else if (type == "typing") {
        // Inbound typing / sending indicator. Ephemeral: apply it to our live
        // view and to the contact-list badge, but never store it. A peer that is
        // "typing" or "sending_file" lights the indicator; "idle" clears it.
        // setPeerTyping emits both the conversation-view and contact-list
        // signals, so this works whether or not that peer's chat is open.
        const QString from  = obj.value("from").toString();
        const QString state = obj.value("state").toString();
        if (!from.isEmpty())
            setPeerTyping(from, state);

    } else if (type == "server_log") {
        // SERVER LOGS IN THE LOG SCREEN. The relay captures every record its
        // own logging produces (its chat-server lines plus the websockets/
        // asyncio library internals at DEBUG depth) into a bounded ring and
        // streams them to every logged-in client: a snapshot of the recent
        // ring right after login, then live batches about once a second. Each
        // element of "lines" is {"level": <python level name>, "line": <the
        // fully formatted record, carrying the SERVER's own timestamp>}.
        //
        // We re-emit each line under the "server" logging category at the
        // matching Qt severity (see lcServer at the top of this file), which
        // lands it in the Log screen AND the console with the standard head:
        //
        //   12:04:31.882 I [server] <lambda> (chatclient.cpp:NNNN)
        //       12:04:31.117 INFO [chat-server] LOGIN m7 (2 online)
        //
        // -- outer time = when this client received it, inner time = when the
        // server wrote it, so relay latency is even visible. .noquote() keeps
        // the line verbatim instead of a C-escaped quoted string.
        //
        // PRIVACY (deliberate, thesis-visible): the relay's logs are METADATA
        // -- who is online, who relayed a frame to whom, sizes, timings. They
        // never contain plaintext or keys (the server never has either), but
        // every logged-in client does see the same shared diagnostic stream.
        // That is exactly the requested always-on behaviour for this
        // development/demo build; note it in the thesis alongside the
        // always-on client log viewer.
        const QJsonArray lines = obj.value("lines").toArray();
        for (const QJsonValue &v : lines) {
            const QJsonObject rec = v.toObject();
            const QString line = rec.value("line").toString();
            if (line.isEmpty())
                continue;
            const QString level = rec.value("level").toString();
            if (level == QLatin1String("DEBUG"))
                qCDebug(lcServer).noquote() << line;
            else if (level == QLatin1String("WARNING"))
                qCWarning(lcServer).noquote() << line;
            else if (level == QLatin1String("ERROR")
                     || level == QLatin1String("CRITICAL"))
                qCCritical(lcServer).noquote() << line;
            else
                qCInfo(lcServer).noquote() << line;
        }

    } else if (type == "error") {
        emit errorOccurred(obj.value("reason").toString());
    }
}

void ChatClient::flagKeyChange(const QString &peer)
{
    // LATCH (fix for the duplicate safety-number-warning flood). A single
    // UNRESOLVED key-change episode must raise the banner and write the warning
    // line EXACTLY ONCE. Without this guard, a peer whose identity key keeps
    // arriving -- e.g. a device that fails to persist its identity and so
    // regenerates a NEW key on every reconnect, making the server push a fresh
    // "key_update" each time, or a reconnect storm -- re-enters here on every
    // push and appends another identical "safety number CHANGED" row. That is
    // exactly what filled one conversation's history with thousands of duplicate
    // warnings in ~2 minutes (~41 rows/sec). If we are ALREADY inside an
    // unverified episode for this peer, keep the bilateral gate shut and refresh
    // the QML binding, but do NOT write another system row. A genuinely NEW
    // change AFTER the user has verified still warns once, because
    // acknowledgeKeyChange()/tryResolveBilateral() clear m_unverifiedKeyChange
    // when the episode resolves -- so this only suppresses the redundant repeats
    // WITHIN one still-open episode, never a legitimate first warning.
    const bool alreadyFlagged = m_unverifiedKeyChange.contains(peer);

    m_unverifiedKeyChange.insert(peer);
    // BILATERAL VERIFICATION: entering (or remaining in) a verification episode.
    // The conversation is blocked until BOTH sides confirm.
    m_pendingBilateral.insert(peer);
    // MUTUAL-DEADLOCK FIX: do NOT blindly discard the peer's prior verification.
    // The rule is only that the peer must have attested our CURRENT identity. If
    // they already attested exactly the identity we hold right now (recorded in
    // m_peerVerifiedForIdentity), their attestation is still valid -- this is the
    // spurious-re-flag case after a logout/switch-user where the safety number is
    // UNCHANGED, and the peer will not naturally re-ack. Keeping them in
    // m_peerVerified lets our half resolve as soon as we verify, instead of both
    // sides waiting forever for an ack the other already sent. If our identity
    // actually CHANGED, the stored value differs from our new key, so the stale
    // attestation is correctly cleared and a fresh ack is required.
    if (m_peerVerifiedForIdentity.value(peer) != m_crypto.publicKeyHex()) {
        m_peerVerified.remove(peer);
        // We no longer hold a valid attestation for our current identity, so ask
        // the peer to re-send their verifyack. If they have verified us they
        // re-emit it (unblocking us); if not, they ignore the request. This also
        // covers the case where their earlier ack was dropped before we ever
        // recorded it. Best-effort: only meaningful while connected.
        sendVerifyResync(peer);
    }
    // else: the peer already attested our current identity -- keep m_peerVerified
    // as-is so tryResolveBilateral() can complete the moment we verify.

    if (alreadyFlagged) {
        // Episode already open: the banner is up and the warning already
        // recorded. Refresh bindings only -- suppress the duplicate row.
        emit safetyNumberChanged(peer);
        return;
    }

    const QString notice =
        QStringLiteral("\u26A0\uFE0F Security warning: %1's safety number has "
                       "CHANGED. This can happen if they reinstalled the app or "
                       "switched device -- but it can also mean someone is "
                       "intercepting your messages. Verify the new safety number "
                       "with %1 over a trusted channel before continuing.")
            .arg(peer);
    if (peer == m_activePeer)
        m_messages.addSystem(notice);
    if (m_history.isReady())
        m_history.addSystemRow(peer, notice,
                               QDateTime::currentMSecsSinceEpoch());
    emit safetyNumberChanged(peer);
}

bool ChatClient::hasUnverifiedKeyChange(const QString &peer) const
{
    return m_unverifiedKeyChange.contains(peer);
}

void ChatClient::acknowledgeKeyChange(const QString &peer)
{
    // The user has CONFIRMED a changed safety number for this peer (the "I've
    // verified it" action on the warning banner). Beyond dismissing the warning,
    // this now actively RE-ESTABLISHES the conversation so both ends are back on
    // a single, agreed ratchet chain built from the peer's NEW identity key:
    //
    //   1. Clear MY unverified flag (dismiss the warning banner).
    //   2. Append a system line: the WAITING line if the peer has not confirmed
    //      yet, or -- once BOTH sides have confirmed -- the "verified by both
    //      parties" line (written by tryResolveBilateral). History is kept intact,
    //      so earlier messages remain visible above.
    //   3. Drop the stale in-memory ratchet chain (m_crypto.dropSession). The
    //      new identity key was already recorded when the change was detected
    //      (ensureSharedKey), so the NEXT encrypt/decrypt re-bootstraps a clean
    //      chain from it. dropSession is idempotent -- harmless if the change
    //      handler already removed the session.
    //   4. Tell the peer WE have verified, via a "verifyack" control frame, so
    //      their half of the both-verified gate can open (sent live or queued).
    //   5. Auto-initiate the crypto re-establishment: put a fresh "handshake"
    //      frame on the wire (or queue it if offline) so the session is LIVE
    //      before either party types -- but ONLY as the deterministic initiator.
    //   6. Try to complete the episode: if the peer already confirmed, unblock
    //      the conversation now; otherwise stay blocked until their verifyack.
    //
    // BILATERAL: this is only MY confirmation. The conversation stays blocked
    // (m_pendingBilateral) until the peer's verifyack also arrives -- steps 4 and
    // 6 drive the peer-facing half of the gate. If the peer was not actually
    // flagged, do nothing (no spurious handshake / verifyack).

    // DIAGNOSTIC (temporary, "confirm does nothing" investigation). Proves this
    // slot is actually reached from the QML "I've verified" button and prints the
    // exact bilateral state at entry. Tap the button ONCE on a CLEAN rebuild:
    //   * If the "[confirm] tapped ..." toast does NOT appear, the tap never
    //     reached C++ -- a stale/mismatched build (the new Q_INVOKABLE methods are
    //     registered by moc, which incremental builds can skip) or QML wiring, NOT
    //     a logic bug below. A clean reconfigure fixes the stale-build case.
    //   * If it DOES appear but the banner stays, the guard returned because the
    //     flag was already clear (a stale banner) -- now handled non-silently.
    //   * If it appears and the banner clears but a message still will not send,
    //     that is the by-design both-must-verify HOLD; check the PEER's device.
    // Remove this block and the post-guard line once the confirm flow is proven.
    qWarning().noquote()
        << "[confirm] acknowledgeKeyChange ENTER  peer=" << peer
        << " flagged=" << m_unverifiedKeyChange.contains(peer)
        << " peerVerified=" << m_peerVerified.contains(peer)
        << " pendingBilateral=" << m_pendingBilateral.contains(peer)
        << " amInitiator=" << m_crypto.amInitiatorFor(peer)
        << " connected=" << (m_socket.state() == QAbstractSocket::ConnectedState);
    emit errorOccurred(
        QStringLiteral("[confirm] tapped for %1 (flagged=%2)")
            .arg(peer.isEmpty() ? QStringLiteral("(none)") : peer)
            .arg(m_unverifiedKeyChange.contains(peer) ? QStringLiteral("yes")
                                                      : QStringLiteral("no")));

    if (!m_unverifiedKeyChange.remove(peer)) {
        // The peer was NOT flagged at tap time. The button is only shown while
        // flagged, so reaching here means the banner was STALE -- its QML binding
        // reads a non-notifying invokable and can lag behind the set. Rather than
        // returning silently (which is exactly the "nothing happens" symptom),
        // refresh the QML gate bindings so the stale banner corrects itself, and
        // re-check resolution in case only the peer's half was still outstanding.
        qWarning().noquote()
            << "[confirm] peer" << peer
            << "was NOT flagged at tap -- refreshing UI (stale banner) and "
               "re-checking bilateral resolution.";
        emit safetyNumberChanged(peer);
        tryResolveBilateral(peer);
        return;
    }
    qWarning().noquote()
        << "[confirm] guard passed -- running acknowledge body for" << peer;

    // (2) System line. If the PEER has not yet confirmed, append an informational
    // line noting that -- but it no longer says sending is blocked, because the
    // gate is now UNILATERAL: having verified the peer, I may send immediately (my
    // messages are store-and-forwarded to the peer even while they are offline and
    // have not verified me). If the peer has ALREADY confirmed, we skip this line
    // because tryResolveBilateral() below completes the episode and writes the
    // "verified by both parties" line instead (so the two never both appear).
    // History is kept intact -- no boundary marker, no clear -- so earlier messages
    // remain visible above.
    if (!m_peerVerified.contains(peer)) {
        const QString waitingLine =
            QStringLiteral("You verified %1's safety number. You can send messages "
                           "now; they'll be delivered when %1 is online. (%1 hasn't "
                           "verified your safety number yet.)")
                .arg(peer);
        if (peer == m_activePeer)
            m_messages.addSystem(waitingLine);
        if (m_history.isReady())
            m_history.addSystemRow(peer, waitingLine,
                                   QDateTime::currentMSecsSinceEpoch());
    }

    // (3) Force a clean chain on the next frame. The new identity is already in
    // m_peerIdentity (recorded by ensureSharedKey when the change was seen), so
    // encryptFor()/decryptFrom() will re-bootstrap from it. Clearing any
    // persisted stale session too, so a restart does not resurrect the old one.
    m_crypto.dropSession(peer);
    if (m_history.isReady())
        m_history.clearSession(peer);
    // POST-COMPROMISE SECURITY: this is the LOCAL side confirming the peer's
    // identity change (the peer switched users / reinstalled). We are tearing the
    // old chain down here too, so drop this peer's rekey accounting in lockstep --
    // otherwise a rekey-ping left outstanding on the OLD chain would keep the
    // heartbeat permanently silenced on the re-established one (see resetPcsFor).
    resetPcsFor(peer);

    // BILATERAL VERIFICATION: tell the peer that WE have verified their safety
    // number, so THEIR half of the both-verified gate can open. Sent live if
    // connected, otherwise queued (persisted) and re-sent on reconnect; the
    // server store-and-forwards it to an offline peer. This is a plaintext
    // control frame carrying only our identities -- it never steps the ratchet,
    // so it is independent of (and safe alongside) the crypto handshake below.
    // ALWAYS sent, for BOTH the initiator and the responder: both must attest
    // before the conversation opens.
    sendOrQueueVerifyAck(peer);

    // DEADLOCK GUARD: if the peer has NOT yet told us they verified, our ack is
    // the only thing that can open their gate -- and if the identities were mid-
    // flux when it was produced, the peer may silently ignore it as stale. Record
    // that we owe a re-send so that the next time we adopt a newer/changed
    // identity for this peer (via a key_update or a handshake's stated ik) we
    // re-emit the ack bound to that current key (see maybeResendVerifyAck). If
    // the peer had ALREADY acked us, there is nothing to break, so we do not arm.
    if (!m_peerVerified.contains(peer))
        m_verifyAckResend.insert(peer);
    else
        m_verifyAckResend.remove(peer);

    // Notify QML so the safety-number header/banner bindings recompute against
    // the new state (warning banner dismissed; a "waiting for the other person"
    // banner appears if the peer has not confirmed yet).
    emit safetyNumberChanged(peer);

    // (4) Auto-initiate the re-establishment -- but ONLY if we are the
    // deterministic INITIATOR for this peer. With roles fixed by identity-key
    // comparison (CryptoBox::amInitiatorFor / sessionFor), exactly one side is
    // the initiator (Alice) and one the responder (Bob). Only Alice can open the
    // re-established chain, because Bob has no sending chain until Alice's first
    // frame arrives. If BOTH sides transmitted here, both would bootstrap as
    // initiator and neither could decrypt the other -- the exact divergence that
    // broke this feature. So:
    //   * Initiator: transmit (live now if connected, queued if offline). This is
    //     the frame that makes the ratchet live before either side types.
    //   * Responder: transmit NOTHING. dropSession above already cleared the
    //     stale chain; the next inbound frame (the initiator's handshake) will
    //     bootstrap a fresh responder session and populate our sending chain, at
    //     which point we can reply. If the user tries to type before that frame
    //     arrives, encryptFor() reports "not ready" and the message is queued
    //     (see sendMessage()), then flushed once the chain comes alive.
    if (m_crypto.amInitiatorFor(peer)) {
        sendOrQueueHandshake(peer);
    } else {
        qDebug() << "[REBOOTSTRAP] responder role for" << peer
                 << "-- not transmitting; awaiting initiator's handshake.";
    }

    // UNILATERAL SEND (offline delivery). Now that WE have verified this peer's
    // safety number, our half of the gate is satisfied: anything we HELD for them
    // while we were still unverified may go out -- even though the peer has not
    // verified US yet and may be OFFLINE. The server store-and-forwards it and the
    // peer decrypts on return. Waiting here for the peer's reciprocal verifyack
    // (the old behaviour, which gated on m_pendingBilateral) made it impossible to
    // message an offline peer at all, because their ack can never arrive while they
    // are logged out -- the reported "cannot send to offline users" bug. Draining
    // now delivers the initiator direction immediately; a responder's held items
    // remain correctly queued until the peer's handshake opens the chain. The
    // handshake queued above (if we are the initiator) was already put on the wire
    // live, so it precedes these items in the peer's offline queue. Re-entrancy-safe.
    if (m_socket.state() == QAbstractSocket::ConnectedState
        && !m_outbox.isEmpty())
        flushOutbox();

    // BILATERAL VERIFICATION: if the peer ALREADY told us they verified (their
    // verifyack arrived before we confirmed), the episode is now complete on both
    // sides -- unblock the conversation. Otherwise we stay in m_pendingBilateral
    // until the peer's verifyack arrives (the "verifyack" receive branch calls
    // tryResolveBilateral() again at that point).
    tryResolveBilateral(peer);
}

// ============================================================================
// Bilateral verification (both-parties-verified gate)
// ============================================================================

bool ChatClient::conversationBlocked(const QString &peer) const
{
    // BILATERAL SEND GATE. Nothing -- text or file -- moves between two parties
    // until EACH of them has independently confirmed the safety number.
    //
    // Two conditions, and both must be clear:
    //   * m_unverifiedKeyChange -- I have not confirmed the peer's number yet;
    //   * m_pendingBilateral    -- the episode is still open, which after
    //                              tryResolveBilateral() can only mean the PEER
    //                              has not confirmed mine.
    //
    // tryResolveBilateral() removes a peer from m_pendingBilateral precisely
    // when both sides have confirmed, so this single predicate expresses the
    // whole rule and there is no second place for the two to drift apart.
    //
    // THIS REVERSES AN EARLIER DECISION, DELIBERATELY. The gate was made
    // unilateral to fix "cannot send to an offline user": a peer who is logged
    // out cannot send a verifyack, so their half of the episode never resolved
    // and messages sat forever. That failure mode returns with this change, and
    // it is inherent rather than a defect -- if both parties must confirm, then
    // a party who is not there cannot confirm. What makes it acceptable is that
    // nothing is DROPPED: sendMessage() and sendFile() queue into the persisted
    // outbox, and tryResolveBilateral() flushes it the moment the episode
    // resolves. The user is told their message is held and why.
    //
    // The security argument for the stricter gate: verifying the peer's key is
    // what makes it safe for me to encrypt TO them, but it says nothing about
    // whether THEY have authenticated ME. Until they have, they cannot tell my
    // messages from an impersonator's. Refusing to transmit until the
    // authentication is mutual means no ciphertext is ever produced for a
    // channel that only one end has authenticated.
    //
    // A peer never flagged is never in either set, so steady-state
    // conversations that were already mutually verified are untouched.
    return m_unverifiedKeyChange.contains(peer)
        || m_pendingBilateral.contains(peer);
}

bool ChatClient::awaitingPeerVerification(const QString &peer) const
{
    // True precisely when I have confirmed but the peer has not yet: the peer is
    // still in an episode (m_pendingBilateral) and I am no longer the one who has
    // to act (peer not in m_unverifiedKeyChange). QML shows the calm "waiting for
    // the other person" banner for this state, distinct from the red "verify the
    // new safety number" banner shown while hasUnverifiedKeyChange() is true.
    return m_pendingBilateral.contains(peer)
        && !m_unverifiedKeyChange.contains(peer);
}

void ChatClient::sendOrQueueVerifyAck(const QString &peer)
{
    if (peer.isEmpty())
        return;

    const qint64 ts = QDateTime::currentMSecsSinceEpoch();
    // The identity we are attesting we verified for this peer -- captured NOW, so
    // that even if it is queued and the peer rekeys before it is sent, the drain
    // path can tell the ack is stale and drop it rather than attest a key we never
    // verified (see flushOutbox's verifyack branch).
    const QString verifiedPeerIdentity = m_peerKeys.value(peer);

    // Offline (or the socket is down): queue a verifyack entry (persisted, reusing
    // the outbox body column to hold the verified peer identity) and let
    // flushOutbox() emit it once the socket is live. A verifyack carries no
    // ciphertext and does not touch the ratchet, so unlike a handshake it does not
    // need the peer's key to be SENT -- the server routes it by "to" -- but we
    // still capture the verified identity for the stale-key guard.
    if (m_socket.state() != QAbstractSocket::ConnectedState) {
        qint64 dbId = -1;
        if (m_history.isReady())
            dbId = m_history.enqueueOutboxVerifyAck(peer, ts,
                                                    m_crypto.publicKeyHex(),
                                                    verifiedPeerIdentity);
        PendingOut po;
        po.dbId         = dbId;
        po.kind         = QStringLiteral("verifyack");
        po.peer         = peer;
        po.peerIdentity = verifiedPeerIdentity;
        po.ts           = ts;
        m_outbox.append(po);
        return;
    }

    // Online: send immediately. If the send somehow fails, fall back to queueing
    // so the peer is still eventually told we verified.
    if (!transmitVerifyAck(peer, verifiedPeerIdentity)) {
        qint64 dbId = -1;
        if (m_history.isReady())
            dbId = m_history.enqueueOutboxVerifyAck(peer, ts,
                                                    m_crypto.publicKeyHex(),
                                                    verifiedPeerIdentity);
        PendingOut po;
        po.dbId         = dbId;
        po.kind         = QStringLiteral("verifyack");
        po.peer         = peer;
        po.peerIdentity = verifiedPeerIdentity;
        po.ts           = ts;
        m_outbox.append(po);
    }
}

bool ChatClient::transmitVerifyAck(const QString &peer,
                                   const QString &verifiedPeerIdentity)
{
    if (peer.isEmpty()
        || m_socket.state() != QAbstractSocket::ConnectedState)
        return false;

    // "ik" is OUR current identity (so the peer can bind the ack to the key they
    // hold for us); "peer_ik" is the identity of the peer that we verified (so the
    // peer accepts it only if it still matches THEIR current identity -- an ack
    // attesting a superseded identity is stale and ignored on receipt). No
    // ciphertext, no ratchet step: this frame is pure signalling.
    QJsonObject ack{
                    {"type", "verifyack"},
                    {"from", m_nick},
                    {"to", peer},
                    {"ik", m_crypto.publicKeyHex()},
                    {"peer_ik", verifiedPeerIdentity},
                    {"ts", QDateTime::currentMSecsSinceEpoch()},
                    };
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(ack).toJson(QJsonDocument::Compact)));
    return true;
}

void ChatClient::sendVerifyResync(const QString &peer)
{
    // Ask the peer to re-send their verifyack (see the header). No-op if we are
    // not connected -- this is a best-effort nudge, and the other convergence
    // paths (resend-on-adoption, and a fresh manual verify) still apply. We stamp
    // our current identity so the peer can bind their re-ack to the key we hold.
    if (peer.isEmpty()
        || m_socket.state() != QAbstractSocket::ConnectedState)
        return;
    // STORM GUARD: coalesce repeats. A resync is a best-effort nudge; sending it
    // more than once every few seconds is never useful, and doing so unbounded is
    // exactly what the earlier re-bootstrap livelock did. If we sent one to this
    // peer within the window, skip -- the peer either already got it or will on the
    // next genuine trigger. (The structural one-shot fix already prevents the loop;
    // this is defence in depth so no future path can flood.)
    constexpr qint64 kVerifyResyncMinIntervalMs = 3000;
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const qint64 lastMs = m_lastVerifyResyncMs.value(peer, 0);
    if (lastMs != 0 && (nowMs - lastMs) < kVerifyResyncMinIntervalMs)
        return;
    m_lastVerifyResyncMs.insert(peer, nowMs);
    QJsonObject req{
                    {"type", "verify_resync"},
                    {"from", m_nick},
                    {"to", peer},
                    {"ik", m_crypto.publicKeyHex()},
                    {"ts", QDateTime::currentMSecsSinceEpoch()},
                    };
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));
    qWarning().noquote()
        << "[VERIFY] sent verify_resync to" << peer
        << "(asking them to re-ack if they have verified us).";
}

void ChatClient::maybeResendVerifyAck(const QString &peer)
{
    // Re-send a verifyack that may have been silently ignored because it
    // attested a since-superseded view of the peer's identity. We only owe a
    // re-send when ALL of the following hold:
    //   * we recorded that we owe one for this peer   (m_verifyAckResend),
    //   * the episode is still open                    (m_pendingBilateral),
    //   * we HAVE verified our side already            (not in m_unverifiedKeyChange),
    //   * the peer has not yet been recorded as verified to us (m_peerVerified),
    //   * and we actually hold a current key for them to attest.
    // Binding the fresh ack to the key we now hold lets the peer -- who ignored
    // the stale one and would otherwise wait forever -- finally open their gate.
    if (!m_verifyAckResend.contains(peer))
        return;
    if (!m_pendingBilateral.contains(peer))
        return;
    if (m_unverifiedKeyChange.contains(peer))
        return;                       // our side not verified: nothing to attest
    if (m_peerVerified.contains(peer))
        return;                       // peer already acked us: no deadlock to break
    if (!m_peerKeys.contains(peer))
        return;                       // no key to bind the ack to yet

    qWarning().noquote()
        << "[VERIFY] re-sending verifyack to" << peer
        << "bound to newly-adopted identity (breaking a possible stale-ack "
           "deadlock).";
    // sendOrQueueVerifyAck captures the peer identity we now hold, so the resent
    // ack attests the peer's CURRENT key -- exactly what their receive-side guard
    // is waiting to match.
    sendOrQueueVerifyAck(peer);
}

void ChatClient::tryResolveBilateral(const QString &peer)
{
    // Complete a verification episode only when it is resolved on BOTH sides:
    //   * the peer is actually in an episode          (m_pendingBilateral),
    //   * I have verified                             (not in m_unverifiedKeyChange),
    //   * the peer has told me they verified          (in m_peerVerified).
    // Until all three hold, leave the peer blocked. Idempotent and
    // order-independent: safe to call from the acknowledge path and the
    // verifyack-receipt path, more than once.
    if (!m_pendingBilateral.contains(peer))
        return;                                    // no active episode
    if (m_unverifiedKeyChange.contains(peer))
        return;                                    // I have not verified yet
    if (!m_peerVerified.contains(peer))
        return;                                    // peer has not verified yet

    m_pendingBilateral.remove(peer);
    // Episode resolved: we no longer owe a verifyack re-send for this peer.
    m_verifyAckResend.remove(peer);
    // PERSIST the resolution. Both halves are now true for the keys currently in
    // force, and both must survive logout -- otherwise the next login re-opens
    // this same episode and asks the user to confirm a number they have already
    // confirmed. Recording the KEYS (not a flag) keeps a later genuine rekey
    // detectable: a different key simply will not match these values.
    {
        const QString peerIdentity = m_peerKeys.value(peer);
        const qint64  nowMs = QDateTime::currentMSecsSinceEpoch();
        if (!peerIdentity.isEmpty()) {
            m_verifiedPeerIdentity.insert(peer, peerIdentity);
            if (m_history.isReady())
                m_history.recordVerifiedPeerIdentity(peer, peerIdentity, nowMs);
        }
        m_peerVerifiedForIdentity.insert(peer, m_crypto.publicKeyHex());
        if (m_history.isReady())
            m_history.recordPeerAttestedMyIdentity(peer, m_crypto.publicKeyHex(),
                                                   nowMs);
    }
    // POST-COMPROMISE SECURITY: the gate is open again, so a rekey ping for this
    // peer can now actually be answered. Clear the retry accounting that was
    // frozen while the conversation was blocked (see the gate check in
    // markRekeyPingSent) rather than leaving a stale budget behind.
    m_rekeyOutstanding.remove(peer);

    const QString bothLine =
        QStringLiteral("Safety number verified by both parties on %1 \u2014 you "
                       "can now send messages.")
            .arg(QDateTime::currentDateTime().toString(
                     QStringLiteral("yyyy-MM-dd")));
    if (peer == m_activePeer)
        m_messages.addSystem(bothLine);
    if (m_history.isReady())
        m_history.addSystemRow(peer, bothLine,
                               QDateTime::currentMSecsSinceEpoch());

    // Recompute the QML gate bindings (composer/banners) and drain anything the
    // user queued for this peer while the conversation was blocked.
    emit safetyNumberChanged(peer);
    if (!m_outbox.isEmpty()
        && m_socket.state() == QAbstractSocket::ConnectedState)
        flushOutbox();
}

// SECURITY (user switching / re-bootstrap): emit or queue the re-bootstrap
// handshake for a peer. See the header for the full rationale. The rule that
// keeps both chains in step is simple and is enforced here: a handshake is only
// ever encrypted at the moment it is actually sent -- never at confirm time if
// we are offline -- so the ratchet advances only for a frame truly put on the
// wire, exactly as text and files already behave.
void ChatClient::sendOrQueueHandshake(const QString &peer)
{
    if (peer.isEmpty())
        return;

    const qint64 ts = QDateTime::currentMSecsSinceEpoch();

    // Offline, or we do not yet hold the peer's key: queue a handshake entry and
    // let flushOutbox() emit it once the socket is live (and the key is known).
    // We do NOT encrypt anything here -- encrypting now would step the ratchet
    // for a frame that never reaches the wire, the precise mistake that
    // desynchronised the chains after a screen lock.
    if (m_socket.state() != QAbstractSocket::ConnectedState
        || !m_peerKeys.contains(peer)) {
        if (!m_peerKeys.contains(peer))
            requestKeyFor(peer);

        qint64 dbId = -1;
        if (m_history.isReady())
            dbId = m_history.enqueueOutboxHandshake(peer, ts,
                                                    m_crypto.publicKeyHex());

        PendingOut po;
        po.dbId = dbId;
        po.kind = QStringLiteral("handshake");
        po.peer = peer;
        po.ts   = ts;
        m_outbox.append(po);
        return;
    }

    // Online and we hold the key: send immediately. If the encrypt somehow
    // fails, fall back to queueing so the re-establishment is not silently lost.
    if (!transmitHandshake(peer)) {
        qint64 dbId = -1;
        if (m_history.isReady())
            dbId = m_history.enqueueOutboxHandshake(peer, ts,
                                                    m_crypto.publicKeyHex());
        PendingOut po;
        po.dbId = dbId;
        po.kind = QStringLiteral("handshake");
        po.peer = peer;
        po.ts   = ts;
        m_outbox.append(po);
    }
}

// The single place that puts a handshake frame on the wire. Encrypts a fixed
// sentinel with the ratchet (which lazily re-bootstraps a fresh chain from the
// peer's current identity key and steps the send chain exactly once), sends a
// "msg" tagged "kind":"handshake", and persists the advanced session. Returns
// false without sending if encryption fails, so the caller can requeue.
bool ChatClient::transmitHandshake(const QString &peer)
{
    // A fixed, non-empty sentinel plaintext. Its content is irrelevant -- the
    // receiver swallows it without displaying -- but a stable, non-empty value
    // keeps the AEAD and the ratchet step identical to a normal text frame, so
    // no special-casing is needed in encryptFor(). It never appears on screen.
    static const QString kHandshakeSentinel =
        QStringLiteral("\x01__chate2ee_rebootstrap__");

    QString cipher, dhHex, nonceHex, ctHex;
    quint32 pn = 0, n = 0;
    bool notReady = false;
    if (!m_crypto.encryptFor(peer, kHandshakeSentinel,
                             cipher, dhHex, pn, n, nonceHex, ctHex, &notReady)) {
        // We only call this as the deterministic INITIATOR (see
        // acknowledgeKeyChange / flushOutbox), and the initiator always has a
        // sending chain immediately after bootstrap -- so notReady should never
        // be true here. If it somehow is, that signals a role-logic error worth
        // seeing rather than hiding; log it. Either way we return false so the
        // caller requeues rather than sending an unusable frame.
        if (notReady) {
            qWarning() << "[REBOOTSTRAP] transmitHandshake: initiator reported "
                          "NOT READY for" << peer
                       << "-- unexpected; handshake will be requeued.";
        }
        return false;
    }

    QJsonObject msg{
                    {"type", "msg"},
                    {"from", m_nick},
                    {"to", peer},
                    {"kind", "handshake"},   // receiver decrypts then swallows
                    // SAFETY-NUMBER-RACE FIX (Bug 1): stamp the handshake with OUR
                    // current identity public key. The re-bootstrap chain and the
                    // deterministic initiator/responder role are both derived from
                    // the two identity keys, so they are only correct when BOTH
                    // sides hold each other's CURRENT key. After a reinstall, this
                    // handshake (built from our new key) can outrun the server's
                    // key_update carrying that same new key to the peer -- leaving
                    // the peer to evaluate its role against our OLD key and,
                    // depending on how the keys sort, pick the SAME role we did
                    // (both initiator / both responder), so neither chain agrees
                    // and the safety numbers differ. By carrying "ik", the peer
                    // can compare it to the key it currently holds for us: if they
                    // differ, the peer knows its key is stale, stashes this frame,
                    // and requests the fresh key BEFORE bootstrapping -- closing
                    // the race deterministically instead of relying on which frame
                    // happens to arrive first. See the "msg" receive handler.
                    {"ik", m_crypto.publicKeyHex()},
                    {"cipher", cipher},
                    {"dh", dhHex},
                    {"pn", static_cast<double>(pn)},
                    {"n", static_cast<double>(n)},
                    {"nonce", nonceHex},
                    {"ct", ctHex},
                    {"ts", QDateTime::currentMSecsSinceEpoch()},
                    };
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact)));

    // The chain advanced for a frame we actually sent: persist it so a restart
    // resumes from here rather than re-bootstrapping again.
    persistSession(peer);
    return true;
}

// ============================================================================
//  Post-compromise security -- self-healing rekey heartbeat
//
//  The Double Ratchet already gives post-compromise security: each time the
//  conversation turns, CryptoBox folds a fresh DH keypair into the root key, so
//  after a state compromise the next round-trip of new ratchet keys locks the
//  attacker back out. But that healing is PASSIVE -- it only happens on a
//  direction change. A long one-directional burst or idle gap therefore never
//  self-heals. These helpers make the property ACTIVE and bounded by driving a
//  round-trip on demand, using only the existing ratchet and the same swallowed
//  control-frame mechanism as the re-bootstrap handshake -- no crypto changes,
//  no server changes. Verified against the reference ratchet: a single rekey
//  ping/pong restores security in BOTH directions after a compromise.
// ============================================================================

// The single place a rekey frame goes on the wire. Mirrors transmitHandshake:
// encrypt a fixed sentinel with the ratchet (stepping the send chain once, on a
// frame that truly goes out) and send a "msg" tagged rekey-ping / rekey-pong
// that the peer decrypts -- advancing/ratcheting its chain -- then swallows.
// Unlike the handshake this does NOT carry an "ik": a rekey is only ever sent on
// an ALREADY-established session (both sides already hold each other's current
// identity key), so the key-update race that motivated "ik" cannot apply, and it
// does NOT require the deterministic-initiator role -- either side may ping or
// pong. Returns false without sending if encryptFor reports the session is not
// ready (e.g. a responder whose sending chain does not exist yet) or otherwise
// fails; callers simply skip and let the next trigger retry.
bool ChatClient::transmitRekey(const QString &peer, bool isPong)
{
    // A fixed, non-empty sentinel -- distinct per direction only for clarity in a
    // packet trace; the content is irrelevant because the receiver swallows it.
    // A stable, non-empty value keeps the AEAD and the ratchet step identical to
    // a normal text frame, so encryptFor needs no special-casing.
    static const QString kRekeyPingSentinel =
        QStringLiteral("\x01__chate2ee_rekey_ping__");
    static const QString kRekeyPongSentinel =
        QStringLiteral("\x01__chate2ee_rekey_pong__");

    // POST-COMPROMISE SECURITY, GATE INTERACTION. The two directions are treated
    // differently, deliberately.
    //
    // A PING is suppressed while the conversation is gated. A gated peer cannot
    // answer -- their reply would have to cross their own closed gate -- so the
    // ping can only time out and be re-sent. That is exactly the ~9 s run of
    // identically sized frames in the relay log: a heartbeat addressed to a peer
    // structurally unable to respond. The heartbeat is re-armed by
    // tryResolveBilateral() the moment the episode resolves, which is the first
    // instant healing can actually succeed.
    //
    // A PONG is NEVER suppressed. Its plaintext is a fixed sentinel, so it is not
    // user content and the gate's argument -- no ciphertext for a channel only one
    // end has authenticated -- does not apply to it; handshakes and verifyacks are
    // already exempt for the same reason. Blocking it would stall post-compromise
    // healing during precisely the episode in which the channel is most suspect,
    // and would leave the peer's ping permanently unanswered. Our receiving chain
    // has already ratcheted on their ping by the time we get here, so refusing the
    // reply only leaves the recovery half-finished.
    if (!isPong && conversationBlocked(peer))
        return false;

    // AN OFFLINE PEER IS NEVER PINGED (fix: unbounded heartbeat to an absent
    // peer). Post-compromise healing completes only on a round trip: our ping
    // must reach the peer and their pong must come back, and only then has the
    // DH ratchet stepped in both directions. A peer who is not connected can do
    // neither, so every ping addressed to them is pure cost --
    //
    //   * it consumes a sending-chain message key the peer will never consume,
    //   * it leaves a stored frame on the relay that is replayed at their next
    //     login, so a long absence accumulates a queue of stale pings, and
    //   * on a handset it wakes the radio for nothing.
    //
    // The relay log shows exactly this: a peer that never logged in during the
    // session received roughly twenty pings, the five-resend budget being
    // exhausted and then immediately re-armed for a fresh cycle, over and over.
    // The budget was working; what was missing was any check that an answer was
    // possible at all.
    //
    // Presence is the correct re-arm trigger rather than a timer: the instant
    // the peer connects, the relay pushes presence, and the next count, idle or
    // lifecycle trigger pings them then -- which is the first moment healing can
    // actually succeed. Nothing is lost by waiting, because a channel carrying
    // no traffic has nothing to heal.
    if (!isPong && !m_users.isOnline(peer)) {
        qDebug() << "[PCS] skipping rekey-ping to" << peer
                 << "-- peer is offline; healing needs a round trip and will be"
                    " retried when they reconnect.";
        return false;
    }

    QString cipher, dhHex, nonceHex, ctHex;
    quint32 pn = 0, n = 0;
    bool notReady = false;
    if (!m_crypto.encryptFor(peer,
                             isPong ? kRekeyPongSentinel : kRekeyPingSentinel,
                             cipher, dhHex, pn, n, nonceHex, ctHex, &notReady)) {
        // notReady here just means we are a responder with no sending chain yet
        // (the peer's opening frame has not arrived) -- there is nothing to heal
        // on a channel that has not carried a message, so skipping is correct and
        // silent. Any other failure is likewise non-fatal for a best-effort
        // heartbeat: return false and let the next trigger try again.
        return false;
    }

    QJsonObject msg{
                    {"type", "msg"},
                    {"from", m_nick},
                    {"to", peer},
                    {"kind", isPong ? "rekey-pong" : "rekey-ping"},
                    {"cipher", cipher},
                    {"dh", dhHex},
                    {"pn", static_cast<double>(pn)},
                    {"n", static_cast<double>(n)},
                    {"nonce", nonceHex},
                    {"ct", ctHex},
                    {"ts", QDateTime::currentMSecsSinceEpoch()},
                    };
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact)));

    // The chain advanced for a frame we actually sent: persist it.
    persistSession(peer);
    return true;
}

// Record that a rekey-ping just went out to 'peer' and arm the lost-pong
// timeout. See the header (LOST-PONG RECOVERY) and kickRekey().
void ChatClient::markRekeyPingSent(const QString &peer)
{
    if (peer.isEmpty())
        return;
    // A FRESH ping (the peer was not already in flight) starts a new re-send
    // budget. A timeout-driven re-send in kickRekey() keeps counting up and does
    // NOT call this, so it never resets the budget mid-cycle.
    if (!m_rekeyOutstanding.contains(peer))
        m_rekeyPingResends[peer] = 0;
    m_rekeyOutstanding.insert(peer);
    m_rekeyPingSentAt[peer] = QDateTime::currentMSecsSinceEpoch();
    // Make sure the retry driver is running so a pong that never comes back is
    // detected: kickRekey() re-sends the ping while its pong is overdue and, past
    // the cap, releases the flag so the count/idle/reconnect triggers restart.
    if (!m_rekeyKickTimer.isActive())
        m_rekeyKickTimer.start();
}

// Count one USER TEXT frame sent to a peer and, if the recovery window is now
// full and no ping is in flight, fire a rekey-ping. Called from the live send
// and the offline-drain send only -- never for files (which do not step the
// ratchet) or control frames.
void ChatClient::noteOutboundTo(const QString &peer)
{
    if (peer.isEmpty())
        return;
    const int count = ++m_sentSinceRatchet[peer];
    if (count >= kPcsRekeyAfterMessages
        && !m_rekeyOutstanding.contains(peer)
        && m_socket.state() == QAbstractSocket::ConnectedState
        && m_crypto.hasSessionFor(peer)) {
        // Window full and the peer has not answered in that span: force a
        // round-trip. Mark the ping outstanding so a sustained one-way burst does
        // not send another until this one is answered (noteInboundFrom clears it
        // when the pong -- or any inbound frame -- arrives).
        if (transmitRekey(peer, /*isPong=*/false)) {
            markRekeyPingSent(peer);
            qDebug() << "[PCS] recovery window full for" << peer
                     << "after" << count
                     << "one-way messages; sent rekey-ping.";
        } else {
            // Transient not-ready (e.g. the session was just re-bootstrapped by a
            // user switch and our sending chain is not alive yet). We did NOT mark
            // it outstanding, so the condition still holds; arm the short retry so
            // the ping goes out within seconds instead of waiting for the idle
            // backstop -- and, crucially, so a one-way burst that STOPS at the
            // threshold (no further text to retry on) still heals. This is the fix
            // for "the 32nd one-way message's rekey never completes after a switch".
            qDebug() << "[PCS] recovery window full for" << peer << "after" << count
                     << "one-way messages, but chain not sendable yet; will retry.";
            m_rekeyKickTries = 0;       // fresh trigger: full retry budget
            m_rekeyKickTimer.start();
        }
    }
}

// An authenticated inbound frame from a peer heals our side: reset the recovery
// window and clear any in-flight ping. Called from the "msg" receive path for
// every frame whose sender is the peer (not our own history echo).
void ChatClient::noteInboundFrom(const QString &peer)
{
    if (peer.isEmpty())
        return;
    m_sentSinceRatchet[peer] = 0;
    m_rekeyOutstanding.remove(peer);
    // The in-flight ping (if any) has been answered by this inbound frame -- the
    // pong itself in the common case -- so drop its lost-pong timeout bookkeeping.
    m_rekeyPingSentAt.remove(peer);
    m_rekeyPingResends.remove(peer);
}

// Drop all post-compromise-security accounting for one peer. Called at every
// point the peer's ratchet session is torn down and re-bootstrapped from a new
// identity (see the header for the full rationale and the user-switching bug it
// fixes). Both entries are bound to the OLD chain: an in-flight rekey-ping
// (m_rekeyOutstanding) and the one-way message count (m_sentSinceRatchet) are
// meaningless on the fresh chain, and a leftover "outstanding" flag would block
// every future rekey-ping to this peer. Removing the entries restarts the
// recovery window cleanly; the very next trigger (count threshold or idle timer)
// then fires normally on the re-established session. Clearing an absent entry is
// a harmless no-op, so this is safe to call unconditionally beside dropSession().
void ChatClient::resetPcsFor(const QString &peer)
{
    if (peer.isEmpty())
        return;
    m_sentSinceRatchet.remove(peer);
    m_rekeyOutstanding.remove(peer);
    // The in-flight ping was bound to the OLD chain; drop its lost-pong timeout
    // bookkeeping in lockstep so nothing leaks onto the re-bootstrapped chain.
    m_rekeyPingSentAt.remove(peer);
    m_rekeyPingResends.remove(peer);
    // NOTE: m_pongOwed is deliberately NOT cleared here. The one-way counter and
    // an in-flight ping are bound to the OLD chain and are meaningless after a
    // re-bootstrap, but a pong we owe the peer is an obligation to COMPLETE a
    // round-trip THEY started -- and it is satisfied just as well on the fresh
    // chain (a pong is a valid rekey on whatever session is current). Clearing it
    // here was silently dropping pongs whenever a key-update re-bootstrapped the
    // session between the peer's ping and our pong -- a large part of why pings
    // outnumbered pongs in the frame trace. Leaving the debt in place lets the
    // next drain (the re-bootstrap handshake's inbound, or the kick) send it on
    // the new chain. It is still cleared on a full logout via clearPcsState().
    qDebug() << "[PCS] reset recovery window for" << peer
             << "(session re-bootstrapped; any owed pong preserved).";
}

// Retry driver for m_rekeyKickTimer: re-attempt every rekey action still pending
// -- an owed ping for any peer past the one-way threshold with none in flight,
// and every owed pong -- and re-arm the timer only while something still could
// not be sent. This is what lets a rekey lost to the transient post-switch
// re-bootstrap window complete within a few seconds instead of waiting for the
// 15-minute idle backstop, closing the "32nd one-way message never gets a pong"
// stall. It sends nothing on a healthy, quiescent channel: with no unhealed
// messages and no owed pongs there is simply nothing to do.
void ChatClient::kickRekey()
{
    if (m_socket.state() != QAbstractSocket::ConnectedState)
        return;   // onConnected() re-arms the idle backstop; retry resumes then
    bool stillPending = false;

    // (0) OUTSTANDING pings still awaiting a pong. On the phone, Doze can drop the
    // peer's pong in flight -- it travels back to us, the sender, and the Android
    // sender is exactly the side whose socket Doze severs. In a ONE-WAY
    // conversation the peer sends nothing else, so no other inbound frame ever
    // clears the in-flight flag: without this the flag, and thus post-compromise
    // security, would stick forever (the "PCS did not start after 32 one-way
    // texts from Android" bug). Re-send a ping whose pong is overdue, up to a cap;
    // past the cap release the flag so the count / idle / reconnect-heal triggers
    // can start a fresh cycle rather than being permanently blocked.
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const QList<QString> inFlight = m_rekeyOutstanding.values();
    for (const QString &peer : inFlight) {
        const qint64 sentAt = m_rekeyPingSentAt.value(peer, 0);
        if (sentAt == 0 || nowMs - sentAt < kPcsRekeyPongTimeoutMs)
            continue;   // still inside the round-trip window: keep waiting
        if (m_rekeyPingResends.value(peer, 0) >= kPcsRekeyPingMaxResends) {
            // Unanswered across the whole budget: the peer is unreachable or gone.
            // Release the in-flight flag and its bookkeeping so a later outbound
            // text, the idle backstop, or a reconnect-heal retries from scratch
            // instead of being blocked by a ping that will never be answered.
            m_rekeyOutstanding.remove(peer);
            m_rekeyPingSentAt.remove(peer);
            m_rekeyPingResends.remove(peer);
            // The fresh cycle can no longer spin: transmitRekey refuses a ping
            // to an offline or gated peer, so releasing the flag re-arms the
            // heartbeat without re-sending anything until the peer is genuinely
            // reachable again.
            qDebug() << "[PCS] rekey-ping to" << peer << "unanswered after"
                     << kPcsRekeyPingMaxResends
                     << "re-sends; releasing in-flight flag. A new ping is sent"
                        " only once the peer is online again.";
            continue;
        }
        if (m_crypto.hasSessionFor(peer)
            && transmitRekey(peer, /*isPong=*/false)) {
            m_rekeyPingSentAt[peer] = nowMs;
            m_rekeyPingResends[peer] = m_rekeyPingResends.value(peer, 0) + 1;
            qDebug() << "[PCS] pong overdue from" << peer
                     << "-- re-sent rekey-ping (attempt"
                     << m_rekeyPingResends.value(peer) << "of"
                     << kPcsRekeyPingMaxResends << ").";
        }
        // Re-sent or briefly not sendable, a ping is still awaiting its pong: the
        // keep-alive at the end holds the timer open to re-check on the next tick.
    }

    // (1) Pings owed by the message-count / idle rule but not yet on the wire.
    const QList<QString> peers = m_sentSinceRatchet.keys();
    for (const QString &peer : peers) {
        if (m_sentSinceRatchet.value(peer) > 0
            && !m_rekeyOutstanding.contains(peer)
            && !m_unverifiedKeyChange.contains(peer)
            && !m_pendingBilateral.contains(peer)
            && m_crypto.hasSessionFor(peer)) {
            if (transmitRekey(peer, /*isPong=*/false)) {
                markRekeyPingSent(peer);
                qDebug() << "[PCS] kick: sent deferred rekey-ping to" << peer;
            } else {
                stillPending = true;   // chain still not sendable; try again
            }
        }
    }

    // (2) Pongs we owe because a ping arrived before our chain was sendable.
    const QList<QString> owed = m_pongOwed.values();
    for (const QString &peer : owed) {
        if (m_crypto.hasSessionFor(peer)
            && transmitRekey(peer, /*isPong=*/true)) {
            m_pongOwed.remove(peer);
            qDebug() << "[PCS] kick: sent deferred rekey-pong to" << peer;
        } else {
            stillPending = true;
        }
    }

    // (3) Lifecycle heals parked by reestablishPcsForAll() when the chain was not
    // sendable at the instant we resumed (reconnect / same-user re-login / app
    // unlock). Fire the rekey-ping now if the chain is alive and the peer is not
    // in flight or behind a closed verification gate; on success the round-trip
    // reestablishes post-compromise security on the resumed chain.
    const QList<QString> heal = m_healPending.values();
    for (const QString &peer : heal) {
        if (m_unverifiedKeyChange.contains(peer)
            || m_pendingBilateral.contains(peer)
            || m_rekeyOutstanding.contains(peer)) {
            // Gate closed, or a ping is already healing this chain: the heal is
            // either unnecessary or must wait for verification. Drop the parked
            // request; the re-bootstrap (for a flagged peer) heals it anyway.
            m_healPending.remove(peer);
            continue;
        }
        if (m_crypto.hasSessionFor(peer)
            && transmitRekey(peer, /*isPong=*/false)) {
            markRekeyPingSent(peer);
            m_healPending.remove(peer);
            qDebug() << "[PCS] kick: sent deferred lifecycle rekey-ping to" << peer;
        } else {
            stillPending = true;   // chain not sendable yet; retry under the cap
        }
    }

    // A pong is a PROMISE we must keep, so as long as one is still owed to a peer
    // we currently hold a session for, keep retrying WITHOUT the give-up cap: the
    // only reason such a send fails is a briefly-not-sendable chain right after a
    // re-bootstrap, which always resolves within moments. (An owed pong to a peer
    // we have NO session for cannot be sent yet; it is left quietly for the
    // re-bootstrap handshake's inbound to drain, and does NOT spin the timer, so a
    // vanished peer cannot make it tick forever.) Owed PINGS remain best-effort
    // and stay under the cap, so a peer that never opens the channel cannot make
    // pings tick forever either.
    bool pongPromiseOutstanding = false;
    const QList<QString> owedNow = m_pongOwed.values();
    for (const QString &peer : owedNow) {
        if (m_crypto.hasSessionFor(peer)) {
            pongPromiseOutstanding = true;
            break;
        }
    }

    // Keep the timer alive while ANY ping is still outstanding: section (0) needs
    // a tick to re-send an overdue ping (still under the cap) OR to release one
    // that has reached the cap. Using "outstanding is non-empty" rather than
    // "some peer is under the cap" is deliberate -- the latter would stop the
    // timer the instant a peer hit the cap, one tick before section (0) could
    // release it, stranding the flag forever. Once section (0) has cleared the
    // last outstanding ping this is false and the timer stops (unless an owed pong
    // still needs it). Like a pong promise, it does not count against the kick
    // budget; the per-ping bound (kPcsRekeyPingMaxResends) governs give-up here.
    const bool pingAwaitingPong = !m_rekeyOutstanding.isEmpty();

    if (pongPromiseOutstanding || pingAwaitingPong) {
        m_rekeyKickTries = 0;           // never abandon a payable pong / awaited pong
        m_rekeyKickTimer.start();
    } else if (stillPending && ++m_rekeyKickTries < kPcsRekeyKickMaxTries) {
        m_rekeyKickTimer.start();
    } else {
        if (stillPending)
            qDebug() << "[PCS] kick: giving up after" << m_rekeyKickTries
                     << "retries; idle backstop / next event will cover it.";
        m_rekeyKickTries = 0;
    }
}

// If we owe this peer a pong and our sending chain is now alive, send it now and
// clear the debt. Called from the receive path right after a frame from the peer
// decrypts -- that inbound frame is precisely what brings a responder's sending
// chain to life -- so an owed pong goes out the instant it becomes possible.
void ChatClient::sendOwedPongIfReady(const QString &peer)
{
    if (peer.isEmpty() || !m_pongOwed.contains(peer))
        return;
    if (m_socket.state() == QAbstractSocket::ConnectedState
        && m_crypto.hasSessionFor(peer)
        && transmitRekey(peer, /*isPong=*/true)) {
        m_pongOwed.remove(peer);
        qDebug() << "[PCS] sent owed rekey-pong to" << peer
                 << "(sending chain now live).";
    }
}

// POST-COMPROMISE SECURITY, lifecycle heal. Force a rekey ping->pong with every
// peer we still hold an established chain with. Called at each point a live
// session RESUMES on the SAME chain -- a reconnect (completeHello, which also
// covers a same-user log out then log back in) and an app-lock UNLOCK
// (onBiometricSucceeded / verifyPin). A restored chain is byte-identical to the
// one in force before the event, so on its own it heals nothing; this round-trip
// re-roots each sending chain on a fresh DH keypair, reestablishing security for
// future messages after user switching, screen lock, and logout -- immediately,
// instead of waiting for the 32-message / 15-minute heartbeat. Verified against
// the reference ratchet: a single ping->pong locks out an attacker who captured
// the pre-resumption state, even on a purely one-way conversation.
void ChatClient::reestablishPcsForAll(const char *reason)
{
    // The established set is exactly the peers whose key we hold AND for whom a
    // ratchet session exists; deriving it from m_peerKeys avoids a CryptoBox
    // accessor and never invents a peer we have not actually keyed.
    const QList<QString> peers = m_peerKeys.keys();
    for (const QString &peer : peers) {
        if (peer.isEmpty())
            continue;
        if (!m_crypto.hasSessionFor(peer))
            continue;   // no chain to heal (never messaged / already torn down)
        // A rekey-ping is a message: it must not cross a closed verification
        // gate. Skip peers whose identity change is not yet re-verified and
        // peers still behind the both-parties-verified gate -- their pending
        // re-bootstrap is itself PCS-fresh, so nothing is lost by not pinging.
        if (m_unverifiedKeyChange.contains(peer)
            || m_pendingBilateral.contains(peer))
            continue;
        // A ping already in flight on this chain heals it; do not stack another.
        if (m_rekeyOutstanding.contains(peer))
            continue;
        if (m_socket.state() == QAbstractSocket::ConnectedState
            && transmitRekey(peer, /*isPong=*/false)) {
            markRekeyPingSent(peer);
            m_healPending.remove(peer);
            qDebug() << "[PCS] lifecycle heal (" << reason
                     << "): sent rekey-ping to" << peer;
        } else {
            // Not sendable this instant (chain not alive yet right after a
            // restore, or momentarily disconnected). Remember it and let the
            // kick timer / next connect drain it, so the heal is guaranteed.
            m_healPending.insert(peer);
            qDebug() << "[PCS] lifecycle heal (" << reason
                     << "): deferred rekey-ping to" << peer << "(not sendable yet).";
        }
    }
    // If anything was deferred, drive the short retry so it goes out in seconds.
    if (!m_healPending.isEmpty()) {
        m_rekeyKickTries = 0;
        m_rekeyKickTimer.start();
    }
}

// Full post-compromise-security teardown for a session end / user switch. The
// single-peer counterpart resetPcsFor() runs on a re-bootstrap; this clears the
// lot on logout. All of it is per-user, in-memory, and non-persistent, so a
// later login simply starts fresh windows.
void ChatClient::clearPcsState()
{
    m_rekeyTimer.stop();
    m_rekeyKickTimer.stop();
    m_sentSinceRatchet.clear();
    m_rekeyOutstanding.clear();
    m_rekeyPingSentAt.clear();
    m_rekeyPingResends.clear();
    m_pongOwed.clear();
    m_healPending.clear();
    m_rekeyKickTries = 0;
}

// Manual / demonstration trigger: force an immediate self-healing round-trip
// with a peer. No-op unless we are connected and hold an established session.
void ChatClient::forceRekey(const QString &peer)
{
    if (peer.isEmpty()
        || m_socket.state() != QAbstractSocket::ConnectedState
        || !m_crypto.hasSessionFor(peer)) {
        qDebug() << "[PCS] forceRekey ignored for" << peer
                 << "-- need a connected, established session.";
        return;
    }
    if (m_rekeyOutstanding.contains(peer))
        return;   // one already in flight; the pong will complete the round-trip
    if (transmitRekey(peer, /*isPong=*/false)) {
        markRekeyPingSent(peer);
        qDebug() << "[PCS] forceRekey: sent rekey-ping to" << peer;
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
    if (m_activePeer.isEmpty()) {
        emit errorOccurred(tr("Pick someone to send to first"));
        return;
    }

    // SECURITY GATE (delivery HELD until *I* have verified). Files obey the same
    // UNILATERAL gate as text: hold only while I have not confirmed this peer's
    // safety number (peer in m_unverifiedKeyChange), never on the peer's
    // verification of me. The file is queued (persisted; nothing is encrypted until
    // it actually streams, so it is keyed to the verified identity in force at send
    // time) and acknowledgeKeyChange() drains it the moment I verify -- delivering
    // it to an OFFLINE peer via the server's store-and-forward, which the old
    // both-verified gate (m_pendingBilateral) could never do. flushOutbox() filters
    // still-unverified peers BEFORE it calls sendFile() for a queued file, so this
    // branch is reached only for a LIVE, user-initiated send -- there is no re-queue
    // loop.
    if (conversationBlocked(m_activePeer)) {
        const QString localPath = localFileUrl.toLocalFile().isEmpty()
                                      ? localFileUrl.toString()
                                      : localFileUrl.toLocalFile();
        if (!QFile::exists(localPath)) {
            emit errorOccurred(tr("Could not find %1").arg(localPath));
            return;
        }
        queueOutboxFile(m_activePeer, localFileUrl,
                        QDateTime::currentMSecsSinceEpoch());
        emit errorOccurred(
            tr("%1's safety number isn't verified yet -- the file is queued and "
               "will send once you verify.").arg(m_activePeer));
        return;
    }

    // OFFLINE QUEUEING: if the socket is not connected, do NOT reject the file.
    // Queue it (persisted) and return; flushOutbox() streams it on reconnect,
    // exactly as it does for text messages composed offline. We do not require
    // the peer's key here -- flushOutbox() fetches it and requeues if it is not
    // yet known, mirroring the text path. Nothing is encrypted until send, so a
    // queued file is keyed to the identity in force when it actually goes out.
    //
    // Guard against re-queueing during a flush: flushOutbox() calls sendFile()
    // for queued files, and by then the socket IS connected, so this branch is
    // not taken and the normal send proceeds.
    if (!m_connected || m_socket.state() != QAbstractSocket::ConnectedState) {
        // Verify the source is readable now, so we can give immediate feedback
        // rather than only discovering a missing file at flush time.
        const QString localPath = localFileUrl.toLocalFile().isEmpty()
                                      ? localFileUrl.toString()
                                      : localFileUrl.toLocalFile();
        if (!QFile::exists(localPath)) {
            emit errorOccurred(tr("Could not find %1").arg(localPath));
            return;
        }
        queueOutboxFile(m_activePeer, localFileUrl,
                        QDateTime::currentMSecsSinceEpoch());
        emit errorOccurred(
            tr("Offline: file queued, will send on reconnect."));
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
    // Remember the source so resendMessage() can re-stream this exact file later
    // this session. Keyed by the msgId, which is also the file row's stable id.
    m_sentFileSources.insert(out->msgId, localFileUrl);
    QFileInfo fi(out->file.fileName());
    out->filename = fi.fileName();
    out->mime = QMimeDatabase().mimeTypeForFile(fi).name();

    // A random per-file key for the bulk secretstream. Unlike the old key --
    // HKDF(static identity secret, msg_id), which anyone who later compromised
    // the identity could re-derive -- this key is random and is delivered to the
    // recipient THROUGH THE RATCHET below, so the file's key confidentiality
    // reduces to the ratchet's: files get the same forward secrecy and
    // post-compromise security as text.
    QByteArray fileKey = FileCrypto::randomKey();
    if (fileKey.isEmpty() || !out->crypto.initPush(fileKey)) {
        emit errorOccurred(tr("Crypto init failed"));
        return;
    }

    // Encrypt the file key as a RATCHET message (hex-encoded, exactly like a text
    // frame). This advances our sending chain by one message, so the file
    // participates in the ratchet just as a text message does. If our sending
    // chain is not alive yet (we are the responder and the initiator's opening
    // frame has not arrived), encryptFor reports notReady -- queue the file and
    // let flushOutbox() stream it once the channel is up, mirroring the text and
    // offline paths. Any other failure is a hard error.
    QString kCipher, kDh, kNonce, kCt;
    quint32 kPn = 0, kN = 0;
    bool notReady = false;
    if (!m_crypto.encryptFor(out->recipient,
                             QString::fromLatin1(fileKey.toHex()),
                             kCipher, kDh, kPn, kN, kNonce, kCt, &notReady)) {
        out->file.close();
        m_sentFileSources.remove(out->msgId);
        if (notReady) {
            queueOutboxFile(out->recipient, localFileUrl,
                            QDateTime::currentMSecsSinceEpoch());
            emit errorOccurred(
                tr("Re-establishing secure session\u2026 file queued, will send "
                   "once the channel is ready."));
        } else {
            emit errorOccurred(tr("Crypto init failed"));
        }
        return;
    }

    // Send the file_init JSON. The server stores this envelope verbatim and
    // forwards it to the recipient, who uses it to set up their own decryption
    // state. "keyenc" is the ratchet-encrypted file key; the recipient
    // ratchet-decrypts it to recover the key. The secretstream "header" is public
    // (a nonce, not a secret) and is authenticated by the stream itself, so it
    // stays in the clear.
    QJsonObject init;
    init["type"] = "file_init";
    init["msg_id"] = out->msgId;
    init["from"] = m_nick;
    init["to"] = out->recipient;
    init["filename"] = out->filename;
    init["mime"] = out->mime;
    init["size"] = double(out->totalBytes);
    init["header"] = QString::fromLatin1(out->crypto.header().toHex());
    QJsonObject keyenc;
    keyenc["cipher"] = kCipher;
    keyenc["dh"]     = kDh;
    keyenc["pn"]     = double(kPn);
    keyenc["n"]      = double(kN);
    keyenc["nonce"]  = kNonce;
    keyenc["ct"]     = kCt;
    init["keyenc"] = keyenc;
    m_socket.sendTextMessage(QJsonDocument(init).toJson(QJsonDocument::Compact));

    // The file key frame is an outbound ratchet frame the peer has not yet
    // answered: persist the advanced session and count it toward the
    // post-compromise recovery window, exactly as a text send does.
    persistSession(out->recipient);
    noteOutboundTo(out->recipient);

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
        // PHANTOM-FAILURE FIX (Issue #1): a REPLAYED file (offline-queued, re-sent
        // on login) that was sealed under a superseded identity pairing cannot be
        // decrypted -- its AEAD tag fails here. That is expected for a stale file,
        // so drop it SILENTLY: no "authentication failure" message, no history
        // row. A LIVE transfer failing here is genuinely worth surfacing, so it
        // still emits the error.
        if (in->replayed)
            qDebug() << "[FILE] replayed file" << msgId
                     << "failed AEAD (stale pairing); dropped silently.";
        else
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
        // Durably record that we now have this file, so the server omits it from
        // the offline replay on our next login. This is the NORMAL finalization
        // path (TAG_FINAL chunk); the file_end handler does the same as a safety
        // net for transfers that end without a final-tagged chunk.
        m_history.recordReceivedFile(msgId, in->sender,
                                     QDateTime::currentMSecsSinceEpoch());
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

// ---------------------------------------------------------------------------
// Message deletion
// ---------------------------------------------------------------------------
void ChatClient::deleteForMe(const QString &mid)
{
    // Local-only deletion: tombstone the row in the model (if the conversation
    // is on screen) and in history (so it survives a restart). Nothing is sent
    // to the peer -- their copy is untouched. Works on any message, ours or
    // theirs. We do not know from the mid alone which peer the row belongs to
    // when it is not the active conversation, so we tombstone the active model
    // (a no-op if the row is not there) and always tombstone history by mid.
    if (mid.isEmpty())
        return;
    m_messages.markDeletedByMid(mid);          // no-op if not in the open convo
    m_history.markDeleted(mid);                 // persist the tombstone
    emit messageDeleted(m_activePeer, mid);
}

void ChatClient::deleteForEveryone(const QString &mid)
{
    // Retract for both sides. Only valid for our OWN message: the model tells us
    // whether the addressed row is ours. We tombstone locally exactly as
    // delete-for-me does, AND send a "delete" frame the peer applies to their
    // copy. The server relays and (for an offline peer) stores-and-forwards it
    // like a text message, so the retraction is not lost if they are away.
    if (mid.isEmpty())
        return;
    const int row = m_messages.indexOfMid(mid);
    if (row < 0) {
        // The row is not in the open conversation, so we cannot confirm it is
        // ours to retract. Fall back to a local-only delete rather than risk
        // retracting someone else's message.
        m_history.markDeleted(mid);
        emit messageDeleted(m_activePeer, mid);
        return;
    }
    if (!m_messages.isMineAt(row)) {
        // Not our message: we cannot retract it for everyone. Downgrade to a
        // local delete so the action still does something sensible.
        emit errorOccurred(
            QStringLiteral("You can only delete your own messages for everyone; "
                           "this was removed just on this device."));
        deleteForMe(mid);
        return;
    }

    // Tombstone locally first, so the sender sees the effect immediately.
    m_messages.markDeletedByMid(mid);
    m_history.markDeleted(mid);

    // Transmit the retraction. No ciphertext -- the id is not secret and the
    // peer already holds the message being retracted; the frame just names it.
    if (m_socket.state() == QAbstractSocket::ConnectedState) {
        QJsonObject del{
            {"type", "delete"},
            {"from", m_nick},
            {"to", m_activePeer},
            {"mid", mid},
            {"ts", QDateTime::currentMSecsSinceEpoch()},
        };
        m_socket.sendTextMessage(
            QString::fromUtf8(QJsonDocument(del).toJson(QJsonDocument::Compact)));
    } else {
        // Offline: the peer's copy will not be retracted until we can send. We
        // keep this simple and do NOT persist delete frames to the outbox -- a
        // retraction that failed to send can be re-issued by the user. Surface a
        // gentle note so they know the peer's copy is not yet gone.
        emit errorOccurred(
            QStringLiteral("Deleted here. The other device will be updated when "
                           "you are back online and you delete it again."));
    }
    emit messageDeleted(m_activePeer, mid);
}

// ---------------------------------------------------------------------------
// Message reactions
// ---------------------------------------------------------------------------
void ChatClient::sendReaction(const QString &mid, const QString &kind)
{
    if (mid.isEmpty())
        return;
    // Normalise to the only three meaningful values so a stray kind can never
    // be stored or transmitted; anything else is treated as a clear.
    const QString k = (kind == QLatin1String("up")
                       || kind == QLatin1String("down")) ? kind : QString();

    // Echo into our own view immediately (optimistic) and persist so it
    // survives a restart. m_activePeer is the conversation the tapped message
    // belongs to; applyReaction is a no-op if the row is not on screen, which
    // does not normally happen here because the user tapped a visible message.
    m_messages.applyReaction(mid, /*mine=*/true, k);
    m_history.setReaction(m_activePeer, mid, QStringLiteral("me"), k);
    emit reactionChanged(m_activePeer, mid);

    // Transmit to the peer. No ciphertext: the mid is not secret and the peer
    // already holds the message being reacted to; the frame only names it and
    // the reaction kind. Matching delete-for-everyone, we transmit only when
    // connected. A reaction is cosmetic, so an unsent one is NOT queued to the
    // outbox -- it is applied locally now and reaches the peer the next time we
    // react while online.
    if (m_socket.state() == QAbstractSocket::ConnectedState) {
        QJsonObject react{
            {"type", "reaction"},
            {"from", m_nick},
            {"to", m_activePeer},
            {"mid", mid},
            {"kind", k},
            {"ts", QDateTime::currentMSecsSinceEpoch()},
        };
        m_socket.sendTextMessage(
            QString::fromUtf8(
                QJsonDocument(react).toJson(QJsonDocument::Compact)));
    }
}

// ---------------------------------------------------------------------------
// Message editing / resending
// ---------------------------------------------------------------------------
void ChatClient::editMessage(const QString &mid, const QString &newText)
{
    if (mid.isEmpty() || m_activePeer.isEmpty())
        return;
    const QString text = newText.trimmed();
    if (text.isEmpty()) {
        // An empty edit is not a delete; ignore it and point the user at delete.
        emit errorOccurred(
            tr("An edited message can't be empty. Use delete to remove it."));
        return;
    }

    // The target must be one of OUR OWN live text messages in the open
    // conversation. indexOfMid is -1 if a different chat is on screen; the row
    // must be ours (you cannot edit the peer's message), a text row (a file is
    // resent, not edited), and not a tombstone (a retracted message is gone).
    const int row = m_messages.indexOfMid(mid);
    if (row < 0)
        return;
    if (!m_messages.isMineAt(row)) {
        emit errorOccurred(tr("You can only edit your own messages."));
        return;
    }
    if (m_messages.isFileAt(row)) {
        emit errorOccurred(
            tr("A file can't be edited. Use Resend to send it again."));
        return;
    }
    const bool isDeleted = m_messages.data(m_messages.index(row, 0),
                                           MessageModel::IsDeletedRole).toBool();
    if (isDeleted)
        return;

    if (!m_peerKeys.contains(m_activePeer)) {
        requestKeyFor(m_activePeer);
        emit errorOccurred(tr("Fetching encryption key, try again."));
        return;
    }
    // An edit transmits a NEW ciphertext body, so it is a text transfer and is
    // gated exactly like sendMessage(): the BILATERAL rule applies, and nothing
    // moves until both parties have confirmed the safety number. Gating the
    // first send but not the edit would leave an obvious hole -- the edit path
    // could deliver arbitrary new text to a peer who never authenticated us.
    //
    // Unlike sendMessage() this REFUSES rather than queues: an edit is not worth
    // holding, has no later message to retry on, and the user can simply edit
    // again once the conversation opens.
    if (conversationBlocked(m_activePeer)) {
        emit errorOccurred(
            m_unverifiedKeyChange.contains(m_activePeer)
                ? tr("Verify %1's safety number first, then edit.")
                      .arg(m_activePeer)
                : tr("%1 has not verified your safety number yet, so edits "
                     "cannot be sent.").arg(m_activePeer));
        return;
    }

    // ONLINE-ONLY (divergence guard). Encrypting the new body STEPS the ratchet;
    // doing that for a frame we cannot actually transmit would desynchronise the
    // two chains -- the same hazard sendMessage() avoids by queuing plaintext
    // when offline -- and an edit has no later message to retry on. So we require
    // a live socket and a ready sending chain, and we mutate NOTHING (neither the
    // visible bubble nor history) until the frame is genuinely on the wire. On
    // failure the message is left exactly as it was and the user is asked to
    // retry, so the two sides can never silently diverge.
    if (m_socket.state() != QAbstractSocket::ConnectedState) {
        emit errorOccurred(
            tr("You're offline -- reconnect to edit this message."));
        return;
    }

    QString cipher, dhHex, nonceHex, ctHex;
    quint32 pn = 0, n = 0;
    bool notReady = false;
    if (!m_crypto.encryptFor(m_activePeer, text,
                             cipher, dhHex, pn, n, nonceHex, ctHex, &notReady)) {
        if (notReady) {
            emit errorOccurred(
                tr("Re-establishing secure session -- try the edit again in a "
                   "moment."));
            return;
        }
        emit errorOccurred(tr("Encryption failed."));
        return;
    }

    // An ordinary ratchet "msg" frame, tagged as an EDIT of an existing message
    // via "edit_of". It carries the original stable id so the peer replaces that
    // message's body in place instead of showing a new bubble; the encrypted "ct"
    // is the new wording, which the peer decrypts exactly like any message. The
    // frame rides the same envelope the server relays opaquely -- no server
    // change. (An offline peer receives it via store-and-forward on next login.)
    const qint64 ts = QDateTime::currentMSecsSinceEpoch();
    QJsonObject msg{
        {"type", "msg"},
        {"from", m_nick},
        {"to", m_activePeer},
        {"mid", mid},
        {"edit_of", mid},
        {"cipher", cipher},
        {"dh", dhHex},
        {"pn", static_cast<double>(pn)},
        {"n", static_cast<double>(n)},
        {"nonce", nonceHex},
        {"ct", ctHex},
        {"ts", ts},
    };
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact)));

    // The frame is out; now converge OUR OWN copy. Replace the visible bubble's
    // text (and light its "edited" marker) and re-seal the new body into the SAME
    // history row so the edit survives a restart. Persist the advanced session.
    m_messages.editTextByMid(mid, text);
    QString histNonce, histCt;
    if (m_crypto.localSeal(text, histNonce, histCt))
        m_history.updateTextRow(mid, histNonce, histCt);
    persistSession(m_activePeer);
    emit messageEdited(m_activePeer, mid);
}

void ChatClient::resendMessage(const QString &mid)
{
    if (mid.isEmpty() || m_activePeer.isEmpty())
        return;
    const int row = m_messages.indexOfMid(mid);
    if (row < 0)
        return;                        // not in the conversation on screen
    if (!m_messages.isMineAt(row)) {
        emit errorOccurred(tr("You can only resend your own messages."));
        return;
    }

    if (m_messages.isFileAt(row)) {
        // Re-stream the ORIGINAL file as a BRAND-NEW transfer (a fresh msgId and
        // bubble on both sides). For file rows mid == msgId, which is how the
        // source was keyed when the file was first sent this session. sendFile()
        // re-validates that the source still exists/opens and reports its own
        // error, and inherits the offline-queue path, so a resend is robust.
        const QUrl src = m_sentFileSources.value(mid);
        if (src.isEmpty()) {
            emit errorOccurred(
                tr("The original file is no longer available to resend (it was "
                   "sent in an earlier session). Please attach it again."));
            return;
        }
        sendFile(src);
    } else {
        // Re-encrypt the same words as a new message. sendMessage() mints a fresh
        // id, echoes a new bubble, and handles the pending-verify / offline /
        // not-ready cases exactly as a normal send would.
        const QString text = m_messages.textAt(row);
        if (text.isEmpty())
            return;
        sendMessage(text);
    }
}

// ---------------------------------------------------------------------------
// Typing / sending indicator
// ---------------------------------------------------------------------------
void ChatClient::notifyTyping(bool sendingFile)
{
    // Debounced outbound typing notification. The FIRST call (or a change of
    // kind, e.g. from typing to sending_file) sends one frame; subsequent calls
    // only re-arm the idle timer so we do not emit a frame per keystroke. When
    // the timer lapses we send one "idle". There is nothing to say if there is
    // no active peer or no connection.
    if (m_activePeer.isEmpty()
        || m_socket.state() != QAbstractSocket::ConnectedState)
        return;

    const QString state = sendingFile ? QStringLiteral("sending_file")
                                      : QStringLiteral("typing");
    m_typingPeer = m_activePeer;
    // Send only on a state change (first keystroke, or typing<->sending_file),
    // relying on sendTypingState's own de-duplication.
    sendTypingState(m_activePeer, state);
    // (Re-)arm the single-shot idle timer. Each keystroke pushes the idle back.
    m_typingTimer.start(kTypingIdleMs);
}

void ChatClient::sendTypingState(const QString &peer, const QString &state)
{
    // Put one typing-state frame on the wire, but only if it differs from the
    // last state we told this peer -- so we never send "typing, typing, typing".
    // Ephemeral: no history, no outbox; the server relays it only to a live peer.
    if (peer.isEmpty())
        return;
    if (state == m_lastTypingStateSent && peer == m_typingPeer)
        return;
    m_lastTypingStateSent = state;
    m_typingPeer = peer;
    if (m_socket.state() != QAbstractSocket::ConnectedState)
        return;
    QJsonObject t{
        {"type", "typing"},
        {"from", m_nick},
        {"to", peer},
        {"state", state},
    };
    m_socket.sendTextMessage(
        QString::fromUtf8(QJsonDocument(t).toJson(QJsonDocument::Compact)));
}

void ChatClient::setPeerTyping(const QString &peer, const QString &state)
{
    // Apply an inbound typing-state to our local view. "idle" clears the entry;
    // anything else records it. We always emit both signals so the conversation
    // view and the contact-list badge stay in sync, regardless of which peer is
    // currently open.
    if (peer.isEmpty())
        return;
    const bool active = (state != QLatin1String("idle") && !state.isEmpty());
    if (active)
        m_peerTyping.insert(peer, state);
    else
        m_peerTyping.remove(peer);
    emit peerTypingChanged(peer, active ? state : QStringLiteral("idle"));
    emit peerActivityChanged(peer, active);
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

    // Desktop: the Save dialog returns a file:// URL, so toLocalFile() gives a
    // real path and we use the efficient streaming QFile::copy exactly as before
    // (this branch is unchanged, so desktop behaviour is identical).
    const QString destPath = dest.toLocalFile();
    if (!destPath.isEmpty()) {
        // QFile::copy refuses to overwrite, so clear any existing target first.
        if (QFile::exists(destPath))
            QFile::remove(destPath);
        if (!QFile::copy(tempPath, destPath)) {
            emit errorOccurred(tr("Could not save the file to %1").arg(destPath));
            return false;
        }
        return true;
    }

    // Android: the Storage Access Framework returns a content:// URL, whose
    // toLocalFile() is empty. The old code treated that as "Invalid save
    // location" and gave up, leaving the empty document the framework had already
    // created -- the same failure that affected chat export. Qt's Android file
    // engine lets QFile write to the content:// URI string, so we stream the
    // decrypted temp file into it in chunks (streaming, not readAll(), so a large
    // received file is not loaded wholly into memory).
    const QString uri = dest.toString();
    if (uri.isEmpty()) {
        emit errorOccurred(tr("Invalid save location."));
        return false;
    }
    QFile in(tempPath);
    if (!in.open(QIODevice::ReadOnly)) {
        emit errorOccurred(tr("That file is no longer available to save."));
        return false;
    }
    QFile out(uri);
    if (!out.open(QIODevice::WriteOnly)) {
        in.close();
        emit errorOccurred(tr("Could not save the file to the chosen location."));
        return false;
    }
    bool ok = true;
    char buf[64 * 1024];
    qint64 r;
    while ((r = in.read(buf, sizeof(buf))) > 0) {
        if (out.write(buf, r) != r) { ok = false; break; }
    }
    if (r < 0)
        ok = false;
    out.close();
    in.close();
    if (!ok) {
        emit errorOccurred(tr("Could not save the file to the chosen location."));
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Export a conversation to a human-readable file (TXT or PDF)
// ---------------------------------------------------------------------------
namespace {
// A compact, locale-independent human size ("12 B", "3.4 KB", "1.2 MB"), so the
// exported "sent a file" line reads naturally. Kept local to this file.
QString humanSize(qint64 bytes)
{
    // Delegates to the single public formatter so txt/pdf export and the
    // Android notification never disagree on how a size reads.
    return ChatClient::humanReadableSize(bytes);
}

// Escape the five XML/HTML metacharacters so message text is safe to place into
// the HTML we hand QTextDocument for PDF rendering. Without this, a message
// containing '<' or '&' would corrupt the layout or drop characters.
QString htmlEscape(const QString &s)
{
    QString out;
    out.reserve(s.size());
    for (const QChar &c : s) {
        switch (c.unicode()) {
        case '&':  out += QStringLiteral("&amp;");  break;
        case '<':  out += QStringLiteral("&lt;");   break;
        case '>':  out += QStringLiteral("&gt;");   break;
        case '"':  out += QStringLiteral("&quot;"); break;
        case '\'': out += QStringLiteral("&#39;");  break;
        default:   out += c;                        break;
        }
    }
    return out;
}

// Write `bytes` to the destination the user picked in the Save dialog, handling
// desktop and Android transparently. This is the crux of the Android export fix.
//
//   * Desktop: the dialog returns a file:// URL, so QUrl::toLocalFile() yields a
//     real filesystem path that we open and overwrite.
//
//   * Android: the Storage Access Framework returns a content:// URL. The
//     framework has ALREADY created an empty document at that location, and
//     QUrl::toLocalFile() returns an empty string for a content:// scheme. The
//     old code treated that empty string as "invalid location", bailed out, and
//     left the empty document behind -- which is exactly the "empty PDF/TXT with
//     no contents" symptom. Qt's Android file engine lets QFile open a content://
//     URI *string* directly, so here we write the bytes straight into the SAF
//     document instead of demanding a local path.
//
// Returns true on success; on failure fills *err with a human-readable reason.
bool writeToChosenDestination(const QUrl &destUrl, const QByteArray &bytes,
                              QString *err)
{
    const QString localPath = destUrl.toLocalFile();   // empty for content://
    if (!localPath.isEmpty()) {
        QFile f(localPath);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            if (err) *err = f.errorString();
            return false;
        }
        const qint64 n = f.write(bytes);
        f.close();
        if (n != bytes.size()) {
            if (err) *err = QStringLiteral("could not write all data to %1")
                                .arg(localPath);
            return false;
        }
        return true;
    }

    // Non-local URL -- on Android this is the content:// document from the SAF.
    const QString uri = destUrl.toString();
    if (uri.isEmpty()) {
        if (err) *err = QStringLiteral("no destination was chosen");
        return false;
    }
    QFile f(uri);
    // WriteOnly maps to the SAF "w" mode, which truncates the (freshly created,
    // already-empty) document, so we do not add QIODevice::Truncate here: some
    // content providers reject the truncate open mode, and it is unnecessary.
    if (!f.open(QIODevice::WriteOnly)) {
        if (err) *err = f.errorString().isEmpty()
                            ? QStringLiteral("could not open the chosen location")
                            : f.errorString();
        return false;
    }
    const qint64 n = f.write(bytes);
    f.close();
    if (n != bytes.size()) {
        if (err) *err = QStringLiteral("could not write all data to the chosen "
                                       "location");
        return false;
    }
    return true;
}
} // namespace

void ChatClient::exportConversation(const QString &peer,
                                    const QString &format,
                                    const QUrl &destUrl)
{
    Localization *loc = Localization::instance();

    if (peer.isEmpty()) {
        emit errorOccurred(loc->t("export.empty").arg(peer));
        return;
    }

    // Read the SAME rows the conversation view replays. rowsForPeer returns them
    // oldest-first; text rows are locally-sealed and decrypted here exactly as
    // loadConversation() does, so we export the plaintext the user already sees,
    // never the at-rest ciphertext and never a ratchet key.
    const QList<StoredRow> rows = m_history.rowsForPeer(peer, /*limit*/ 100000);
    if (rows.isEmpty()) {
        emit errorOccurred(loc->t("export.empty").arg(peer));
        return;
    }

    // Validate we have SOME destination. We deliberately do NOT require a local
    // file path here: on Android the Save dialog hands us a content:// URL whose
    // toLocalFile() is empty, and writeToChosenDestination() below knows how to
    // write to it. (The previous code required a local path and so aborted on
    // Android, leaving the empty file the framework had pre-created.) A readable
    // local path, when there is one, is used only for the "saved to" message.
    if (destUrl.isEmpty()) {
        emit errorOccurred(loc->t("export.failed").arg(tr("no destination was chosen")));
        return;
    }
    const QString shownPath = destUrl.toLocalFile();  // real path on desktop; "" on Android

    const QString me = m_nick.isEmpty() ? tr("me") : m_nick;
    const QString nowStamp =
        QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    const QString wantPdf = format.trimmed().toLower();
    const bool asPdf = (wantPdf == QStringLiteral("pdf"));

    // Build one "line record" per row: a precise timestamp, a sender label, and
    // the body. This intermediate form feeds BOTH the txt writer and the PDF
    // (HTML) builder, so the two formats never drift apart in content.
    struct Line {
        QString ts;       // yyyy-MM-dd HH:mm:ss
        QString who;      // sender label ("" for system)
        QString body;     // already-resolved text
        bool system = false;
        bool deleted = false;
    };
    QList<Line> lines;
    lines.reserve(rows.size());

    for (const StoredRow &r : rows) {
        Line ln;
        ln.ts = QDateTime::fromMSecsSinceEpoch(r.ts)
                    .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        if (r.system) {
            ln.system = true;
            ln.who    = loc->t("export.systemLabel");
            ln.body   = r.systemText;
        } else {
            ln.who     = r.mine ? me : (r.sender.isEmpty() ? peer : r.sender);
            ln.deleted = r.deleted;
            if (r.deleted) {
                ln.body = loc->t("msg.deleted");
            } else if (r.isFile) {
                ln.body = loc->t("export.sentFile")
                              .arg(r.filename, humanSize(r.size));
            } else {
                // Decrypt the locally-sealed text row, exactly as the view does.
                const QString plain = m_crypto.localOpen(r.nonceHex, r.ctHex);
                ln.body = plain.isEmpty()
                              ? loc->t("sys.cannotDecrypt")
                              : plain;
            }
        }
        lines.append(ln);
    }

    // ---- PDF branch ----------------------------------------------------
    if (asPdf) {
#if CHATE2EE_HAVE_PRINTSUPPORT
        // Compose the conversation as HTML and let QTextDocument lay it out and
        // print it to PDF -- clean word-wrapping with no manual page math.
        //
        // WHY THE TEXT WAS TINY, AND THE FIX. The previous HTML set NO font sizes
        // at all, so every element fell back to QTextDocument's default (~9pt).
        // Printed to a HighResolution (~1200 DPI) QPrinter, that default renders
        // physically minuscule. The cure is twofold and used throughout below:
        //   1. A real default font with an explicit POINT size on the document
        //      (setDefaultFont). Points are a physical unit (1pt = 1/72 inch), so
        //      they print at the same real size regardless of the printer's DPI --
        //      unlike pixels, which shrink as DPI rises.
        //   2. Every size in the CSS is given in pt as well, and the message text
        //      is set BOLD and large (14pt) so it is strong and easy to read on
        //      paper, with a coloured, bold sender name and a muted timestamp so
        //      the bold bodies stand out rather than competing. Colours are fixed
        //      print-friendly values (dark ink on white), independent of the app
        //      theme, so the page is always legible.
        const QString titleColor  = QStringLiteral("#0b7c72");  // teal, header + "me"
        const QString peerColor   = QStringLiteral("#3b3b7a");  // indigo, the peer
        const QString bodyColor   = QStringLiteral("#111418");  // near-black ink
        const QString metaColor   = QStringLiteral("#6b7280");  // muted meta
        const QString stampColor  = QStringLiteral("#9aa0a6");  // muted timestamp
        const QString mutedItalic = QStringLiteral("#9aa0a6");  // deleted/system

        QString html;
        html += QStringLiteral("<html><head></head>"
                               "<body style=\"font-family:'Segoe UI',"
                               "Helvetica,Arial,sans-serif;\">");
        // Big, bold, coloured title.
        html += QStringLiteral("<h1 style=\"font-size:23pt;font-weight:bold;"
                               "color:%1;margin:0 0 2pt 0;\">%2</h1>")
                    .arg(titleColor,
                         htmlEscape(loc->t("export.headerTitle").arg(peer)));
        // Participants + export time, muted, directly under the title.
        html += QStringLiteral("<p style=\"font-size:11pt;color:%1;"
                               "margin:0 0 8pt 0;\">%2<br/>%3</p>"
                               "<hr/>")
                    .arg(metaColor,
                         htmlEscape(loc->t("export.headerParticipants")
                                        .arg(me, peer)),
                         htmlEscape(loc->t("export.headerExported")
                                        .arg(nowStamp)));

        for (const Line &ln : lines) {
            const QString stamp =
                QStringLiteral("<span style=\"font-size:10pt;color:%1;"
                               "font-family:'Consolas',monospace;\">[%2]</span>")
                    .arg(stampColor, htmlEscape(ln.ts));
            if (ln.system) {
                html += QStringLiteral(
                            "<p style=\"font-size:13pt;margin:5pt 0;\">%1 "
                            "<i style=\"color:%2;font-weight:bold;\">%3</i></p>")
                            .arg(stamp, mutedItalic, htmlEscape(ln.body));
            } else {
                // "My" messages carry the accent colour on the name; the peer's a
                // contrasting indigo. Both bold, so who-said-what is scannable.
                const QString whoColor = (ln.who == me) ? titleColor : peerColor;
                const QString who =
                    QStringLiteral("<span style=\"font-size:13pt;color:%1;"
                                   "font-weight:bold;\">%2:</span>")
                        .arg(whoColor, htmlEscape(ln.who));
                // The message body itself: large and BOLD (the "extremely bold"
                // ask), in near-black; a deleted tombstone stays muted italic.
                const QString body = ln.deleted
                    ? QStringLiteral("<span style=\"font-size:14pt;color:%1;"
                                     "font-style:italic;\">%2</span>")
                          .arg(mutedItalic, htmlEscape(ln.body))
                    : QStringLiteral("<span style=\"font-size:14pt;color:%1;"
                                     "font-weight:bold;\">%2</span>")
                          .arg(bodyColor, htmlEscape(ln.body));
                html += QStringLiteral("<p style=\"font-size:13pt;"
                                       "margin:5pt 0;\">%1 %2 %3</p>")
                            .arg(stamp, who, body);
            }
        }
        html += QStringLiteral("</body></html>");

        QTextDocument doc;
        // (1) above: an explicit point-size default font. This is the single most
        // important line for readable output -- it sets the physical base size so
        // nothing falls back to the tiny ~9pt default when printed at high DPI.
        QFont exportFont(QStringLiteral("Segoe UI"));
        exportFont.setPointSizeF(13.0);
        doc.setDefaultFont(exportFont);
        doc.setHtml(html);

        // QPrinter writes PDF to a real filesystem path -- it cannot target an
        // Android content:// URI. So we always render to a private temporary file
        // first (the app cache is writable on every platform with no permission),
        // then hand the resulting bytes to writeToChosenDestination(), which
        // copies them to the user's chosen location (a real path on desktop, or
        // the SAF content:// document on Android). This makes PDF export work on
        // Android for the first time while leaving desktop behaviour identical.
        QTemporaryFile tmp(QDir::tempPath() +
                           QStringLiteral("/chate2ee-export-XXXXXX.pdf"));
        tmp.setAutoRemove(true);
        if (!tmp.open()) {
            emit errorOccurred(loc->t("export.failed")
                                   .arg(tr("could not create a temporary file")));
            return;
        }
        const QString tmpPath = tmp.fileName();
        tmp.close();                   // let QPrinter open it by name

        QPrinter printer(QPrinter::HighResolution);
        printer.setOutputFormat(QPrinter::PdfFormat);
        printer.setOutputFileName(tmpPath);
        // Comfortable, even margins so the (now larger) text has room to breathe.
        printer.setPageMargins(QMarginsF(16, 16, 16, 16),
                               QPageLayout::Millimeter);
        doc.print(&printer);           // writes the PDF to the temp file

        // QPrinter has no boolean success return for PDF; verify the temp file
        // now exists and is non-empty as a practical check.
        QFileInfo fi(tmpPath);
        if (!fi.exists() || fi.size() == 0) {
            emit errorOccurred(loc->t("export.failed")
                                   .arg(tr("PDF could not be written")));
            return;
        }

        // Read the rendered PDF back and place it at the user's destination.
        QByteArray pdfBytes;
        {
            QFile in(tmpPath);
            if (!in.open(QIODevice::ReadOnly)) {
                emit errorOccurred(loc->t("export.failed").arg(in.errorString()));
                return;
            }
            pdfBytes = in.readAll();
            in.close();
        }

        QString werr;
        if (!writeToChosenDestination(destUrl, pdfBytes, &werr)) {
            emit errorOccurred(loc->t("export.failed").arg(werr));
            return;
        }
        emit exportFinished(peer, shownPath);
        return;
#else
        // printsupport is not in this build: tell the user plainly and stop,
        // rather than silently writing a txt with a .pdf name.
        emit errorOccurred(loc->t("export.failed")
                               .arg(tr("PDF export is not available in this "
                                       "build (printsupport module missing)")));
        return;
#endif
    }

    // ---- TXT branch ----------------------------------------------------
    // Build the whole document into an in-memory string, then write it through
    // writeToChosenDestination() so the SAME path handles a desktop file:// path
    // and an Android content:// URI. (Previously this opened QFile on the empty
    // toLocalFile() path, which failed silently on Android.)
    // Line ending: the old code opened the file with QIODevice::Text, which
    // translated "\n" to the platform convention at write time (CRLF on Windows,
    // LF elsewhere). We now build the bytes ourselves, so reproduce that exactly
    // -- at compile time, since each target is built for its own platform -- to
    // keep desktop output byte-identical and avoid a "single long line in old
    // Notepad" regression on Windows.
#if defined(Q_OS_WIN)
    const QString NL = QStringLiteral("\r\n");
#else
    const QString NL = QStringLiteral("\n");
#endif
    QString text;
    {
        QTextStream ts(&text);   // stream into the string (UTF-16 in memory)

        // A .txt file carries NO font information, so how large or bold the text
        // looks is decided entirely by whatever opens it (Notepad, an editor, a
        // phone viewer) -- nothing written here can change the on-screen size.
        // The most we can do for readability is a clean, well-framed layout: a
        // boxed header, aligned metadata, and a clear separator before the body.
        // (To make the text itself bigger, the reader zooms in their viewer --
        // e.g. Ctrl + mouse wheel, or Ctrl + '+', in most editors.)
        const QString rule = QString(60, QLatin1Char('='));
        const QString thin = QString(60, QLatin1Char('-'));

        // Framed header block.
        ts << rule << NL;
        ts << QStringLiteral("  ") << loc->t("export.headerTitle").arg(peer) << NL;
        ts << rule << NL;
        ts << QStringLiteral("  ") << loc->t("export.headerParticipants")
                                          .arg(me, peer) << NL;
        ts << QStringLiteral("  ") << loc->t("export.headerExported")
                                          .arg(nowStamp) << NL;
        ts << thin << NL;
        ts << NL;   // a blank line so the transcript does not butt against the rule

        for (const Line &ln : lines) {
            if (ln.system)
                ts << '[' << ln.ts << "] " << ln.who << ' ' << ln.body << NL;
            else
                ts << '[' << ln.ts << "] " << ln.who << ": " << ln.body << NL;
        }
        ts.flush();
    }

    QString werr;
    if (!writeToChosenDestination(destUrl, text.toUtf8(), &werr)) {
        emit errorOccurred(loc->t("export.failed").arg(werr));
        return;
    }

    emit exportFinished(peer, shownPath);
}


// ---------------------------------------------------------------------------
// Human-readable byte size (shared by export and Android notifications)
// ---------------------------------------------------------------------------
QString ChatClient::humanReadableSize(qint64 bytes)
{
    if (bytes < 1024)
        return QStringLiteral("%1 B").arg(bytes);
    double v = double(bytes) / 1024.0;
    if (v < 1024.0)
        return QStringLiteral("%1 KB").arg(v, 0, 'f', 1);
    v /= 1024.0;
    if (v < 1024.0)
        return QStringLiteral("%1 MB").arg(v, 0, 'f', 1);
    v /= 1024.0;
    return QStringLiteral("%1 GB").arg(v, 0, 'f', 1);
}

// ---------------------------------------------------------------------------
// Android: open a conversation from a tapped notification / shortcut
// ---------------------------------------------------------------------------
void ChatClient::openConversationFromNotification(const QString &peer)
{
    // Called on the Qt thread (the JNI callback marshalled onto it). Make sure
    // the peer exists in the model, then make it active -- setActivePeer owns
    // clearing and replaying that conversation's history, exactly as tapping the
    // contact would. Clearing its unread badge is implicit in opening it.
    if (peer.isEmpty())
        return;
    m_users.ensureUser(peer);
    setActivePeer(peer);
    // Clear any lingering notification for this peer now that it is open.
    AndroidNotifier::cancelForPeer(peer);
}

// ---------------------------------------------------------------------------
// Android: pin a home-screen shortcut for the active conversation
// ---------------------------------------------------------------------------
void ChatClient::createConversationShortcut()
{
    Localization *loc = Localization::instance();
    if (m_activePeer.isEmpty()) {
        emit errorOccurred(loc->t("conv.pickContact"));
        return;
    }
    // Labels: short is the peer name; long is a friendlier phrase. Both are
    // localized via the export/participants style keys we already ship.
    const QString shortLabel = m_activePeer;
    const QString longLabel  =
        loc->t("conv.chattingWith").arg(m_activePeer);
    const bool ok = AndroidNotifier::createShortcut(m_activePeer,
                                                    shortLabel, longLabel);
    if (!ok) {
        // Off Android, or the launcher refused/does not support pinning.
        emit errorOccurred(loc->t("shortcut.unsupported"));
    }
}
