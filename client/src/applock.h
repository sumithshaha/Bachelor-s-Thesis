#ifndef APPLOCK_H
#define APPLOCK_H

// ============================================================================
//  applock.h  --  the C++ side of biometric (fingerprint) app unlocking.
//
//  A small static bridge from ChatClient to the platform's biometric prompt,
//  matching the shape of AndroidNotifier: every method is a no-op / false on a
//  platform that cannot offer biometrics, so ChatClient calls these
//  unconditionally and any build is unaffected.
//
//  This bridge is about biometrics on TWO fronts:
//    (1) the fingerprint convenience UNLOCK of an already-logged-in session
//        (the original app lock -- requestUnlock/biometricAvailable below), and
//    (2) biometric/Hello LOGIN: releasing a stored login password after the OS
//        proves the user's presence, so a returning user taps Hello /
//        fingerprint instead of typing their password (the *Login vault* block
//        at the bottom -- enrollLogin/loginWithBiometric/hasLoginEnrolled/
//        clearLogin). This is deliberately SEPARATE from (1): the login
//        password is the cryptographic root of trust (it unwraps the identity
//        key at rest), so biometrics cannot replace it -- they can only gate
//        the release of a copy that is bound to the platform's own credential
//        store (Windows DPAPI, Android Keystore). See the Login vault block.
//
//  The PIN of the app LOCK -- setting it, verifying it, and the lock STATE --
//  lives entirely in ChatClient (stored as an Argon2id verifier in QSettings),
//  so the lock works with a PIN alone even where no biometric hardware/API is
//  present. The login-vault password wrapping, by contrast, is owned by this
//  bridge because it must live in the platform credential store, not QSettings.
//
//  Platform support:
//    * Android: uses AndroidX BiometricPrompt + BiometricManager through the
//      Java helper fi.tamk.chate2ee.BiometricHelper (invoked via QJniObject).
//      BiometricPrompt transparently offers fingerprint AND falls back to the
//      device PIN/pattern/password, so "fingerprint" here means "device
//      biometric or credential", which is what users expect. On success the
//      Java side calls the JNI callback
//      Java_fi_tamk_chate2ee_BiometricHelper_onAuthSucceeded, implemented in
//      applock.cpp, which forwards to ChatClient::onBiometricSucceeded() on the
//      Qt thread.
//    * Windows: an EXPERIMENTAL, clearly-flagged Windows Hello path via the
//      WinRT UserConsentVerifier API. It is compiled ONLY when the WinRT
//      headers are actually present (guarded by __has_include), because that
//      API is awkward to reach from a Qt/MinGW build and often will not
//      compile there. When it is not available, biometricAvailable() returns
//      false and the app simply uses the PIN -- exactly as on any other
//      desktop. This keeps the build robust: the Windows-Hello attempt can
//      never break compilation.
//    * Everything else (Linux/macOS desktop): no biometrics; PIN only.
//
//  STATUS: faithful, build-and-test-required. The Android path needs the
//  AndroidX biometric dependency (added in the Gradle/CMake notes) and testing
//  on the real S24 Ultra; the Windows Hello path is best-effort and may compile
//  to a no-op on MinGW. Not compiled here.
// ============================================================================

#include <QString>

class ChatClient;   // forward declaration; the .cpp wires the callback to it

class AppLock
{
public:
    // Register the single ChatClient the biometric callback should drive on a
    // successful authentication. Called once from ChatClient::create(). On a
    // platform without biometrics this merely stores the pointer (harmless).
    static void setClient(ChatClient *client);
    static ChatClient *client();

    // Whether a biometric unlock can be offered RIGHT NOW:
    //   * Android: BiometricManager.canAuthenticate(...) reports success (a
    //     fingerprint/credential is enrolled).
    //   * Windows: the experimental Hello path compiled AND
    //     UserConsentVerifier reports the device is available.
    //   * Otherwise: false.
    // ChatClient exposes this to QML so the fingerprint button only shows when
    // it can actually do something.
    static bool biometricAvailable();

    // Show the platform biometric prompt. 'title'/'subtitle' are localized
    // strings ChatClient passes for the system dialog. Returns immediately; the
    // result is delivered asynchronously: on success the native side calls
    // ChatClient::onBiometricSucceeded() on the Qt thread, on failure/cancel
    // nothing happens and the PIN entry remains. No-op where unavailable.
    //
    // The overload taking a ChatClient* is what ChatClient calls (passing
    // itself); it records the client and shows the prompt with default
    // localized strings resolved inside. The title/subtitle overload is used
    // when the caller wants to supply its own strings.
    static void requestUnlock(ChatClient *client);
    static void requestUnlock(const QString &title, const QString &subtitle);

    // Mark or clear the app window as SECURE. On Android this sets/clears
    // FLAG_SECURE, which excludes the app from the recent-apps thumbnail and
    // blocks screenshots/screen recording while set -- so a conversation left on
    // screen is not exposed in the task switcher after the app is backgrounded
    // (the lock screen is only shown once the app is resumed). Called by
    // ChatClient when the app lock is enabled/disabled and at startup. A safe
    // no-op on every non-Android platform (desktop has no such preview).
    static void setSecure(bool secure);

    // ======================================================================
    //  Login vault (feature: biometric / Windows Hello LOGIN)
    //
    //  Lets a returning user log in by proving presence to the OS instead of
    //  typing their password. The password itself is NOT re-derivable from
    //  biometrics; it is wrapped at rest by the platform credential store and
    //  released only after a successful biometric/Hello authentication:
    //    * Android: an AES-GCM key in the Android Keystore created with
    //      setUserAuthenticationRequired(true) and used only inside a
    //      BiometricPrompt.CryptoObject (fingerprint OR device PIN). The key
    //      never leaves the TEE and is auto-invalidated when a new fingerprint
    //      is enrolled. Wrapping/unwrapping is done in Java (BiometricHelper).
    //    * Windows: DPAPI (CryptProtectData, tied to the current Windows user)
    //      wraps the password into QSettings; retrieval is gated by a Windows
    //      Hello UserConsentVerifier check. Compiled only where the raw WinRT
    //      headers are present (same guard as the unlock path); elsewhere every
    //      method is a safe no-op and loginAvailable() returns false, so the UI
    //      simply never offers biometric login.
    //    * Everything else: no-op / false (password login only).
    //
    //  All methods are safe to call unconditionally on any platform.
    // ======================================================================

    // Whether biometric/Hello LOGIN can be offered on this device right now:
    //   * Android: a fingerprint or device credential is usable (same probe as
    //     the unlock path).
    //   * Windows: the experimental Hello path compiled AND Hello is available.
    //   * Otherwise: false.
    static bool loginAvailable();

    // Whether a wrapped login password is already stored for 'nick' on this
    // device (i.e. the user has enrolled biometric login for that account).
    // QML reads this to decide whether to show the "Log in with Hello /
    // fingerprint" button. False on a platform without a login vault.
    static bool hasLoginEnrolled(const QString &nick);

    // Enroll biometric login for 'nick': wrap 'password' in the platform
    // credential store so a later biometric/Hello check can release it. Called
    // AFTER a confirmed password login (ChatClient does this from the server's
    // key-dump handler, so a rejected password never enrolls). On Android this
    // shows a one-time BiometricPrompt to authorise the Keystore encrypt; on
    // Windows it wraps with DPAPI silently. 'client' is recorded so the (rare)
    // asynchronous Android callback can be routed. No-op where unavailable.
    static void enrollLogin(ChatClient *client, const QString &nick,
                            const QString &password);

    // Begin a biometric/Hello LOGIN for 'nick' against 'serverUrl'. Shows the
    // OS prompt; on success the recovered password is delivered asynchronously
    // to ChatClient::onBiometricLoginUnlocked(nick, password) on the Qt thread,
    // which then runs the normal login(). On failure/cancel nothing happens and
    // the password fields remain. No-op where unavailable or not enrolled.
    static void loginWithBiometric(ChatClient *client,
                                   const QString &serverUrl,
                                   const QString &nick);

    // Forget the wrapped login password for 'nick' (disable biometric login):
    // deletes the Keystore key/blob on Android, the DPAPI blob in QSettings on
    // Windows. Safe if nothing is stored. No-op where unavailable.
    static void clearLogin(const QString &nick);

private:
    static ChatClient *s_client;
};

#endif // APPLOCK_H
