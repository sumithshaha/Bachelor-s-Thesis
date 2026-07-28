package fi.tamk.chate2ee;

// ============================================================================
//  BiometricHelper.java
//
//  The Java side of the app's fingerprint / device-credential unlock. It uses
//  the PLATFORM biometric API (android.hardware.biometrics.*), which ships in
//  the Android OS from API 28, rather than the AndroidX support library -- so
//  it needs NO external Gradle dependency and cannot fail to resolve on a Qt
//  build. The app's minSdk is 28, exactly where the platform BiometricPrompt
//  became available.
//
//  It exposes two static methods the C++ AppLock bridge calls (unchanged
//  signatures, so the C++ side does not change):
//    * canAuthenticate(Context) -> boolean  : is a biometric currently usable?
//    * authenticate(Activity, title, subtitle) : show the system prompt; on
//      success call the native onAuthSucceeded(), which the C++ side forwards
//      to ChatClient::onBiometricSucceeded() on the Qt thread. On error/cancel
//      nothing happens and the app's own PIN remains the way in.
//
//  API-level handling:
//    * BiometricPrompt itself: API 28+ (always available at minSdk 28).
//    * BiometricManager.canAuthenticate(): API 29+. On API 28 exactly we fall
//      back to the deprecated FingerprintManager availability check, guarded so
//      it is only referenced on 28. Either way a false result just means the
//      app uses its PIN, so a conservative "no" is always safe.
//    * setDeviceCredentialAllowed / setAllowedAuthenticators evolved across 29
//      /30; to stay dependency-free and robust we do NOT request the device
//      credential through the prompt (the app has its own PIN for that), so we
//      avoid those cross-version setters entirely.
//
//  STATUS: faithful, build-and-test-required. Biometric behaviour varies across
//  Android 13/14 and OEM skins (Samsung One UI on the S24 Ultra included); test
//  on the real device. Not compiled against the NDK here.
// ============================================================================

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.WindowManager;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class BiometricHelper {

    private BiometricHelper() { }

    // Native callback implemented on the C++ side (applock.cpp). Called only on
    // a SUCCESSFUL authentication.
    private static native void onAuthSucceeded();

    // ---- called from C++ (AppLock::biometricAvailable) --------------------
    // Returns true only if a biometric can be used right now. Any uncertainty or
    // older API is treated as "no", so the app safely falls back to its PIN.
    // Three API tiers, each using the form that is non-deprecated for it:
    //   * API 30+ (R): canAuthenticate(int authenticators) -- the current form.
    //   * API 29 (Q):  canAuthenticate() no-arg -- the ONLY form on 29, so it is
    //                  correct to use there despite being deprecated later.
    //   * API 28 (P):  FingerprintManager -- the only availability probe on 28;
    //                  isolated in a @SuppressWarnings helper so its unavoidable
    //                  deprecation is silenced ONLY there, not app-wide.
    public static boolean canAuthenticate(Context context) {
        if (context == null)
            return false;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {   // API 30+
                BiometricManager bm =
                        context.getSystemService(BiometricManager.class);
                if (bm == null)
                    return false;
                // NATIVE PIN: accept EITHER a biometric OR the device credential
                // (the phone's PIN/pattern/password), so the lock is usable via
                // the device PIN even with no fingerprint enrolled -- which is
                // the whole point of delegating to the OS credential.
                return bm.canAuthenticate(
                        BiometricManager.Authenticators.BIOMETRIC_WEAK
                        | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                        == BiometricManager.BIOMETRIC_SUCCESS;
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {  // 29
                return canAuthenticateApi29(context);
            } else {   // API 28
                return canAuthenticateApi28(context);
            }
        } catch (Throwable t) {
            // Any OEM quirk or permission issue -> treat as unavailable.
            return false;
        }
    }

    // API 29 only: the no-argument canAuthenticate() is the sole form available
    // on Q (the int-authenticators overload arrived in R). It is deprecated in
    // later APIs, so we call it ONLY here, under a guard, with the deprecation
    // suppressed narrowly rather than app-wide.
    @SuppressWarnings("deprecation")
    private static boolean canAuthenticateApi29(Context context) {
        BiometricManager bm = context.getSystemService(BiometricManager.class);
        return bm != null
                && bm.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
    }

    // API 28 only: BiometricManager has no canAuthenticate() until API 29, so on
    // P the only availability probe is FingerprintManager, which is itself
    // deprecated. minSdk is 28, so this branch must exist; the deprecation is
    // unavoidable and suppressed here alone.
    @SuppressWarnings("deprecation")
    private static boolean canAuthenticateApi28(Context context) {
        android.hardware.fingerprint.FingerprintManager fm =
                (android.hardware.fingerprint.FingerprintManager)
                        context.getSystemService(Context.FINGERPRINT_SERVICE);
        return fm != null
                && fm.isHardwareDetected()
                && fm.hasEnrolledFingerprints();
    }

    // ---- called from C++ (AppLock::setSecure) -----------------------------
    // Toggle FLAG_SECURE on the activity's window. When set, Android excludes the
    // app from the recent-apps thumbnail and blocks screenshots / screen
    // recording, so a backgrounded conversation is not exposed in the task
    // switcher before the lock screen is shown on return. Must touch the window on
    // the UI thread. Safe to call repeatedly with the same value, and safe if the
    // window is momentarily unavailable (it simply does nothing that time).
    public static void setSecure(final Activity activity, final boolean secure) {
        if (activity == null)
            return;
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override public void run() {
                try {
                    if (secure) {
                        activity.getWindow().addFlags(
                                WindowManager.LayoutParams.FLAG_SECURE);
                    } else {
                        activity.getWindow().clearFlags(
                                WindowManager.LayoutParams.FLAG_SECURE);
                    }
                } catch (Throwable t) {
                    // Non-fatal: the lock still works; only the task-switcher
                    // preview is not blanked if this fails.
                }
            }
        });
    }

    // ---- called from C++ (AppLock::requestUnlock) -------------------------
    // Build and show the platform BiometricPrompt on the UI thread. Needs only
    // an Activity (not a FragmentActivity), so it works with QtActivity and its
    // subclass directly.
    public static void authenticate(final Activity activity,
                                    final String title,
                                    final String subtitle) {
        if (activity == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
            return;   // P == API 28
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override public void run() {
                try {
                    showPrompt(activity, title, subtitle);
                } catch (Throwable t) {
                    // If the prompt cannot be built, silently give up; the PIN
                    // entry in the lock screen remains available.
                }
            }
        });
    }

    private static void showPrompt(Activity activity, String title,
                                   String subtitle) {
        BiometricPrompt.Builder builder = new BiometricPrompt.Builder(activity)
                .setTitle(title != null ? title : "Unlock")
                .setSubtitle(subtitle != null ? subtitle : "");

        // NATIVE PIN + FINGERPRINT (delegate to the OS credential): allow the
        // DEVICE CREDENTIAL (the phone's own PIN / pattern / password) as well
        // as the biometric, so ONE OS-managed prompt offers fingerprint/face AND
        // the device PIN. This is what makes "native Android PIN unlock" work
        // without the app holding a PIN of its own. The API to request this
        // differs by version, and CRUCIALLY: when a device-credential fallback
        // is enabled you must NOT also set a negative button (the OS supplies
        // the credential button itself, and setting both throws).
        boolean credentialEnabled = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {          // API 30+
            builder.setAllowedAuthenticators(
                    android.hardware.biometrics.BiometricManager
                            .Authenticators.BIOMETRIC_WEAK
                    | android.hardware.biometrics.BiometricManager
                            .Authenticators.DEVICE_CREDENTIAL);
            credentialEnabled = true;
        } else {                                                        // 28-29
            // setDeviceCredentialAllowed is the pre-R way to allow the device
            // PIN as a fallback. Deprecated in R (superseded by the call above),
            // so referenced only on <R and suppressed narrowly.
            credentialEnabled = setDeviceCredentialAllowedCompat(builder);
        }

        // Only add a manual Cancel button if NO device-credential fallback is
        // active (otherwise the OS provides the fallback control and a negative
        // button would be rejected).
        if (!credentialEnabled) {
            builder.setNegativeButton(
                    "Cancel",
                    activity.getMainExecutor(),
                    (dialog, which) -> { /* dismiss; lock screen remains */ });
        }

        BiometricPrompt prompt = builder.build();
        CancellationSignal cancel = new CancellationSignal();

        BiometricPrompt.AuthenticationCallback callback =
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(
                            BiometricPrompt.AuthenticationResult result) {
                        // Success via fingerprint/face OR the device PIN: clear
                        // the lock through the C++/Qt side.
                        onAuthSucceeded();
                    }

                    @Override
                    public void onAuthenticationError(int errorCode,
                                                      CharSequence errString) {
                        // Cancel or a hard error: do nothing, lock screen stays.
                    }

                    // onAuthenticationFailed (one non-matching attempt) is not
                    // overridden: the prompt lets the user retry, so we wait.
                };

        prompt.authenticate(cancel, activity.getMainExecutor(), callback);
    }

    // Pre-R (API 28-29) way to allow the device credential as a fallback in the
    // biometric prompt. setDeviceCredentialAllowed is deprecated in R (replaced
    // by setAllowedAuthenticators), so it is referenced only here, on <R, with
    // the deprecation suppressed narrowly. Returns true if it was applied.
    @SuppressWarnings("deprecation")
    private static boolean setDeviceCredentialAllowedCompat(
            BiometricPrompt.Builder builder) {
        try {
            builder.setDeviceCredentialAllowed(true);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    // ========================================================================
    //  Login vault: biometric / device-credential LOGIN (feature, separate
    //  from the app unlock above).
    //
    //  Lets a returning user log in by proving presence to the OS instead of
    //  typing their password. The password is wrapped with an AES-256-GCM key
    //  held in the ANDROID KEYSTORE, created with setUserAuthenticationRequired
    //  (true) so the OS only permits the key to be USED inside a
    //  BiometricPrompt.CryptoObject after a successful authentication. The key
    //  material never leaves the TEE/StrongBox; only the wrapped bytes (IV +
    //  ciphertext) are stored, in a private SharedPreferences file. A new
    //  fingerprint enrollment invalidates the key (setInvalidatedByBiometric-
    //  Enrollment), which we detect and treat as "not enrolled" so the user
    //  falls back to their password.
    //
    //  CRITICAL: a CryptoObject-backed key requires a STRONG (Class 3) biometric
    //  or the device credential -- a WEAK biometric CANNOT authorise a Keystore
    //  crypto operation. So both the key (AUTH_BIOMETRIC_STRONG |
    //  AUTH_DEVICE_CREDENTIAL) and the prompt (BIOMETRIC_STRONG |
    //  DEVICE_CREDENTIAL) use STRONG here, unlike the app-unlock prompt above,
    //  which only needs presence and so accepts WEAK. On the S24 Ultra the
    //  fingerprint sensor is Class 3, so fingerprint OR the device PIN both work.
    //
    //  STATUS: faithful, build-and-test-required. Keystore/BiometricPrompt
    //  CryptoObject behaviour varies across OEM skins; test on the real device,
    //  especially the new-fingerprint-invalidation path.
    // ========================================================================

    private static final String KEY_ALIAS = "chate2ee_login_key";
    private static final String PREFS = "chate2ee_biologin";
    private static final String P_NICK = "nick";
    private static final String P_IV = "iv";
    private static final String P_CT = "ct";
    private static final int GCM_TAG_BITS = 128;
    // DIAGNOSTIC (temporary): logcat tag for the biometric-login flow, mirroring
    // the "[LOGIN]" qDebug lines on the C++/Windows side so the Android path is
    // equally debuggable. Filter logcat on this tag to trace enroll/login.
    private static final String TAG = "ChatE2EE-Login";

    // Native callback implemented on the C++ side (applock.cpp). Called with the
    // decrypted login password after a SUCCESSFUL biometric login; the C++ side
    // forwards it to ChatClient::onBiometricLoginUnlocked() on the Qt thread.
    private static native void onLoginUnlocked(String password);

    // Success callback for a CryptoObject prompt: receives the AUTHORISED cipher
    // (from the AuthenticationResult) so the crypto op runs on the exact cipher
    // the OS just unlocked.
    private interface CryptoSuccess { void run(Cipher cipher) throws Exception; }

    // ---- called from C++ (AppLock::hasLoginEnrolled) ----------------------
    // True if a wrapped password is stored for 'nick' AND the Keystore key still
    // exists. Any uncertainty -> false, so the app offers password login.
    public static boolean hasLoginEnrolled(Context context, String nick) {
        if (context == null || nick == null)
            return false;
        try {
            SharedPreferences p =
                    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            String storedNick = p.getString(P_NICK, null);
            if (storedNick == null || !storedNick.equals(nick)) {
                Log.i(TAG, "hasLoginEnrolled(" + nick + ") = false (stored nick = "
                        + storedNick + ")");
                return false;
            }
            if (p.getString(P_IV, null) == null
                    || p.getString(P_CT, null) == null) {
                Log.i(TAG, "hasLoginEnrolled(" + nick + ") = false (no stored blob)");
                return false;
            }
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            boolean hasKey = ks.containsAlias(KEY_ALIAS);
            // DIAGNOSTIC (temporary): what the login screen sees when deciding
            // whether to offer the fingerprint/PIN button. blob present but
            // hasKey=false means the Keystore key was lost (e.g. cleared) while
            // the prefs survived -> the button is correctly hidden.
            Log.i(TAG, "hasLoginEnrolled(" + nick + ") = " + hasKey
                    + " (blob present, keystore alias = " + hasKey + ")");
            return hasKey;
        } catch (Throwable t) {
            Log.w(TAG, "hasLoginEnrolled(" + nick + ") threw; treating as false", t);
            return false;
        }
    }

    // ---- called from C++ (AppLock::enrollLogin) ---------------------------
    // Wrap 'password' under a fresh Keystore key after a one-time BiometricPrompt
    // authorises the encrypt, and store the wrapped bytes for 'nick'. Called only
    // after a confirmed password login, so a rejected password never enrolls.
    public static void enrollLogin(final Activity activity, final String nick,
                                   final String password, final String title,
                                   final String subtitle) {
        if (activity == null || nick == null || password == null)
            return;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
            return;   // P == API 28
        try {
            SecretKey key = createLoginKey();
            final Cipher cipher = getGcmCipher();
            cipher.init(Cipher.ENCRYPT_MODE, key);
            Log.i(TAG, "enrollLogin(" + nick + "): key created, showing enroll prompt");
            runCryptoPrompt(activity, cipher, title, subtitle,
                    new CryptoSuccess() {
                        @Override public void run(Cipher c) throws Exception {
                            byte[] iv = c.getIV();
                            byte[] ct = c.doFinal(
                                    password.getBytes(StandardCharsets.UTF_8));
                            SharedPreferences p = activity.getSharedPreferences(
                                    PREFS, Context.MODE_PRIVATE);
                            // commit() (synchronous) rather than apply() so the
                            // wrapped blob is durably on disk before we report
                            // success -- the Android parallel to settings.sync()
                            // on the Windows side. The data is tiny, so the
                            // main-thread write is negligible.
                            boolean ok = p.edit()
                                    .putString(P_NICK, nick)
                                    .putString(P_IV,
                                            Base64.encodeToString(iv, Base64.NO_WRAP))
                                    .putString(P_CT,
                                            Base64.encodeToString(ct, Base64.NO_WRAP))
                                    .commit();
                            Log.i(TAG, "enrollLogin(" + nick + "): enrolled (ct = "
                                    + ct.length + " bytes, commit = " + ok + ")");
                        }
                    });
        } catch (Throwable t) {
            // Enroll failed (no strong biometric, keystore error, cancel):
            // leave biometric login un-enrolled; password login remains.
            Log.w(TAG, "enrollLogin(" + nick + ") failed; not enrolled", t);
        }
    }

    // ---- called from C++ (AppLock::loginWithBiometric) --------------------
    // Show the prompt (fingerprint OR device PIN), unlock the Keystore key,
    // decrypt the stored password, and hand it back via onLoginUnlocked(). If a
    // new fingerprint was enrolled since, the key is invalid: clear the vault and
    // give up quietly so the user logs in with their password and can re-enable.
    public static void loginWithBiometric(final Activity activity,
                                          final String nick, final String title,
                                          final String subtitle) {
        if (activity == null || nick == null
                || Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
            return;
        try {
            SharedPreferences p = activity.getSharedPreferences(
                    PREFS, Context.MODE_PRIVATE);
            String storedNick = p.getString(P_NICK, null);
            String ivB64 = p.getString(P_IV, null);
            String ctB64 = p.getString(P_CT, null);
            if (storedNick == null || !storedNick.equals(nick)
                    || ivB64 == null || ctB64 == null) {
                Log.i(TAG, "loginWithBiometric(" + nick
                        + "): no matching stored blob; nothing to do");
                return;
            }
            final byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
            final byte[] ct = Base64.decode(ctB64, Base64.NO_WRAP);

            SecretKey key = loadLoginKey();
            if (key == null) {
                Log.w(TAG, "loginWithBiometric(" + nick + "): keystore key missing");
                return;
            }
            final Cipher cipher = getGcmCipher();
            try {
                cipher.init(Cipher.DECRYPT_MODE, key,
                        new GCMParameterSpec(GCM_TAG_BITS, iv));
            } catch (KeyPermanentlyInvalidatedException inv) {
                // A new fingerprint was enrolled: the key is gone. Clear the
                // stale vault so hasLoginEnrolled() reports false next time.
                Log.w(TAG, "loginWithBiometric(" + nick + "): key invalidated by "
                        + "new biometric enrollment; clearing vault");
                clearLogin(activity, nick);
                return;
            }
            Log.i(TAG, "loginWithBiometric(" + nick + "): showing login prompt");
            runCryptoPrompt(activity, cipher, title, subtitle,
                    new CryptoSuccess() {
                        @Override public void run(Cipher c) throws Exception {
                            byte[] pt = c.doFinal(ct);
                            Log.i(TAG, "loginWithBiometric(" + nick
                                    + "): decrypted; handing password to native");
                            onLoginUnlocked(new String(pt, StandardCharsets.UTF_8));
                        }
                    });
        } catch (Throwable t) {
            // Any failure: leave the user on the login screen with password entry.
            Log.w(TAG, "loginWithBiometric(" + nick + ") failed", t);
        }
    }

    // ---- called from C++ (AppLock::clearLogin) ----------------------------
    // Delete the Keystore key and the stored wrapped password for 'nick'.
    public static void clearLogin(Context context, String nick) {
        try {
            if (context != null) {
                context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                        .edit().clear().apply();
            }
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(KEY_ALIAS))
                ks.deleteEntry(KEY_ALIAS);
        } catch (Throwable t) {
            // Best-effort; nothing more to do.
        }
    }

    // Create a FRESH AES-256-GCM Keystore key for the login vault (deleting any
    // previous one so a re-enroll always binds to the current password). The key
    // requires user authentication for every use, via a CryptoObject, and is
    // invalidated if a new fingerprint is enrolled.
    private static SecretKey createLoginKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS))
            ks.deleteEntry(KEY_ALIAS);
        KeyGenerator kg = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {   // API 30+
            // Authorise the key with EITHER a strong biometric OR the device
            // credential; timeout 0 == authenticate for every single use.
            b.setUserAuthenticationParameters(0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                    | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        } else {
            // Pre-30 legacy per-use auth via CryptoObject with a strong
            // biometric. Untested here (the target device is API 34); kept so
            // the minSdk-28 build is complete.
            setLegacyPerUseAuth(b);
        }
        kg.init(b.build());
        return kg.generateKey();
    }

    // Pre-R (API 28-29) way to require authentication for EVERY use of the key
    // via a CryptoObject: setUserAuthenticationValidityDurationSeconds(-1).
    // That method is deprecated in R (superseded by setUserAuthentication-
    // Parameters, used on 30+ above), so it is referenced only here, on <R, with
    // the deprecation suppressed narrowly rather than app-wide -- exactly the
    // pattern used for the other version-specific setters in this file. Removes
    // the "setUserAuthenticationValidityDurationSeconds(int) has been deprecated"
    // build warning.
    @SuppressWarnings("deprecation")
    private static void setLegacyPerUseAuth(KeyGenParameterSpec.Builder b) {
        b.setUserAuthenticationValidityDurationSeconds(-1);
    }

    private static SecretKey loadLoginKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return (SecretKey) ks.getKey(KEY_ALIAS, null);
    }

    private static Cipher getGcmCipher() throws Exception {
        return Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_GCM + "/"
                + KeyProperties.ENCRYPTION_PADDING_NONE);   // AES/GCM/NoPadding
    }

    // Show a BiometricPrompt bound to 'cipher' via a CryptoObject on the UI
    // thread, and run 'onSuccess' with the AUTHORISED cipher on success. Uses a
    // STRONG biometric OR the device credential (required for a Keystore crypto
    // key); no negative button is added when the credential fallback is active
    // (the OS supplies that control, and setting both throws).
    private static void runCryptoPrompt(final Activity activity,
                                        final Cipher cipher, final String title,
                                        final String subtitle,
                                        final CryptoSuccess onSuccess) {
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override public void run() {
                try {
                    BiometricPrompt.Builder builder =
                            new BiometricPrompt.Builder(activity)
                                    .setTitle(title != null ? title : "Log in")
                                    .setSubtitle(subtitle != null ? subtitle : "");
                    boolean credentialEnabled = false;
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {   // 30+
                        builder.setAllowedAuthenticators(
                                BiometricManager.Authenticators.BIOMETRIC_STRONG
                                | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
                        credentialEnabled = true;
                    }
                    if (!credentialEnabled) {
                        builder.setNegativeButton(
                                "Cancel", activity.getMainExecutor(),
                                (dialog, which) -> { /* password entry remains */ });
                    }
                    BiometricPrompt prompt = builder.build();
                    CancellationSignal cancel = new CancellationSignal();
                    BiometricPrompt.AuthenticationCallback callback =
                            new BiometricPrompt.AuthenticationCallback() {
                                @Override
                                public void onAuthenticationSucceeded(
                                        BiometricPrompt.AuthenticationResult result) {
                                    try {
                                        Cipher c = (result.getCryptoObject() != null)
                                                ? result.getCryptoObject().getCipher()
                                                : cipher;
                                        onSuccess.run(c);
                                    } catch (Throwable t) {
                                        // Auth succeeded but the crypto op failed
                                        // (e.g. GCM tag mismatch, key state):
                                        // give up; password entry remains.
                                        Log.w(TAG, "crypto op failed after "
                                                + "successful auth", t);
                                    }
                                }

                                @Override
                                public void onAuthenticationError(
                                        int errorCode, CharSequence errString) {
                                    // Cancel, lockout, no-credential, hardware
                                    // unavailable, etc. The code is the key
                                    // diagnostic for a prompt that "does nothing".
                                    Log.w(TAG, "auth error " + errorCode + ": "
                                            + errString);
                                }
                            };
                    prompt.authenticate(new BiometricPrompt.CryptoObject(cipher),
                            cancel, activity.getMainExecutor(), callback);
                } catch (Throwable t) {
                    // Prompt could not be built: password entry remains.
                    Log.w(TAG, "could not build/show biometric prompt", t);
                }
            }
        });
    }
}
