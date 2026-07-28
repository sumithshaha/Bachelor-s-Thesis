package fi.tamk.chate2ee;

// ============================================================================
//  ChatService.java
//
//  A foreground Service whose ONLY job is to keep the app's process alive while
//  it is in the background, so that Qt's thread -- and with it the live
//  WebSocket connection and the in-memory Double Ratchet state -- keeps running.
//  That is what lets an incoming message be decrypted and shown with its sender
//  and content even when the UI is not in the foreground (the requirement you
//  chose). Android will not kill a process that has a running foreground
//  service with an ongoing notification.
//
//  WHAT THIS SERVICE DOES NOT DO:
//   * It performs NO cryptography and holds NO keys. The real ChatClient (C++)
//     in the same process still receives and decrypts messages exactly as
//     before; this service merely prevents that process from being killed. A
//     separate service with its OWN decryption would be wrong -- it would have
//     no ratchet state and could only show content-less "New message" alerts.
//   * It does not create its own connection. There is one ChatClient, one
//     socket; the service just keeps the whole process resident.
//
//  Lifecycle: ChatClient starts this service (via AndroidNotifier) on login and
//  stops it on logout. startForeground() must be called within a few seconds of
//  the service starting or Android throws, so we call it immediately in
//  onStartCommand with the ongoing notification NotificationHelper builds.
//
//  The persistent notification is LOW importance and silent (its own channel),
//  so it never buzzes; only real incoming messages, on the high-importance
//  message channel, alert the user.
// ============================================================================

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class ChatService extends Service {

    // A fixed notification id for the ongoing foreground notification. Distinct
    // from the per-peer message notification ids (which are peer-hash based).
    private static final int FOREGROUND_ID = 42;

    // Intent extras the starter may pass so the ongoing notification's text can
    // be localized by the C++ side (which knows the active language). Falls back
    // to English defaults if absent.
    public static final String EXTRA_TITLE = "svc_title";
    public static final String EXTRA_TEXT  = "svc_text";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String title = "Encrypted Chat is running";
        String text  = "Connected \u2014 you'll be notified of new messages.";
        if (intent != null) {
            if (intent.hasExtra(EXTRA_TITLE))
                title = intent.getStringExtra(EXTRA_TITLE);
            if (intent.hasExtra(EXTRA_TEXT))
                text = intent.getStringExtra(EXTRA_TEXT);
        }

        // Make sure the (silent, low) service channel exists before we post on
        // it. ensureChannels is idempotent, so re-creating is harmless.
        NotificationHelper.ensureChannels(
                this, "Messages", "Running",
                "Keeps the encrypted chat connected in the background.");

        // Promote to a foreground service with the ongoing notification. This is
        // the call that keeps the process alive.
        startForeground(FOREGROUND_ID,
                NotificationHelper.buildServiceNotification(this, title, text));

        // START_STICKY: if Android does kill us under extreme memory pressure,
        // it will try to recreate the service (without the original intent),
        // which re-establishes the foreground state. The app process being
        // recreated will re-run Qt startup and reconnect.
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        // Remove the ongoing notification when the service stops (logout).
        // minSdk is 28 (Qt 6.11 default), so STOP_FOREGROUND_REMOVE is always
        // available and the deprecated stopForeground(boolean) is never needed.
        stopForeground(Service.STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    // This is a started service, not a bound one; nothing binds to it.
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
