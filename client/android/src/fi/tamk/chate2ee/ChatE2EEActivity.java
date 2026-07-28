package fi.tamk.chate2ee;

// ============================================================================
//  ChatE2EEActivity.java
//
//  A thin subclass of Qt's QtActivity. The Qt/C++/QML application still runs
//  exactly as before inside this activity; subclassing only lets us add three
//  Android-specific things that a plain QtActivity cannot do:
//
//    1. Create the notification channels early (before any notification is
//       posted), and request the POST_NOTIFICATIONS runtime permission on
//       Android 13+ (without it, notifications are silently dropped).
//    2. Receive the deep-link intents fired by home-screen shortcuts and by
//       tapping a message notification (chate2ee://open?peer=X), and forward
//       the peer name to the C++ side so it opens that conversation.
//    3. Provide the Context the C++ AndroidNotifier needs to start the
//       foreground service and post notifications.
//
//  The bridge to C++ is a single native method, onOpenConversation(String),
//  implemented on the C++ side (AndroidNotifier). When Qt loads the app's
//  native library this JNI symbol resolves; we guard the call so that if the
//  native side is not ready yet (very early startup) the pending peer is
//  stashed and delivered once Qt has loaded.
// ============================================================================

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;

import org.qtproject.qt.android.bindings.QtActivity;

public class ChatE2EEActivity extends QtActivity {

    // Request code for the POST_NOTIFICATIONS permission dialog (13+).
    private static final int REQ_POST_NOTIFICATIONS = 3001;

    // If a deep-link arrives before the Qt native library has finished loading
    // (and thus before onOpenConversation can be resolved), we remember the peer
    // here and deliver it from onNativeReady(), which the C++ side calls once it
    // is up. Without this, a cold launch from a shortcut could drop the target.
    private static String sPendingPeer = null;
    // Set true once the C++ side signals it is ready to receive conversation
    // opens (see nativeReady()).
    private static boolean sNativeReady = false;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Create the notification channels up front. The channel display names
        // are passed from strings so they can be localized; here we use simple
        // defaults, and the C++ side re-creates them with localized names on
        // login (ensureChannels is idempotent).
        NotificationHelper.ensureChannels(
                this,
                "Messages",
                "Running",
                "Keeps the encrypted chat connected in the background.");

        // On Android 13+ the app must hold POST_NOTIFICATIONS at runtime or all
        // notifications are dropped. Ask once, here.
        maybeRequestNotificationPermission();

        // A launch from a shortcut or a tapped notification delivers its intent
        // to onCreate (cold start) OR onNewIntent (already running). Handle the
        // cold-start case here.
        handleDeepLink(getIntent());
    }

    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // Keep getIntent() consistent for anything that reads it later.
        setIntent(intent);
        handleDeepLink(intent);
    }

    // Ask for POST_NOTIFICATIONS on 13+ if we do not already hold it. On older
    // Android the permission does not exist and notifications need no runtime
    // grant, so this is a no-op there.
    private void maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU)
            return;
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED)
            return;
        requestPermissions(
                new String[]{Manifest.permission.POST_NOTIFICATIONS},
                REQ_POST_NOTIFICATIONS);
    }

    // Parse a chate2ee://open?peer=<peer> intent and forward the peer to C++.
    // Ignores any intent that is not one of our deep links (e.g. the normal
    // launcher MAIN intent), so a plain app launch is unaffected.
    private void handleDeepLink(Intent intent) {
        if (intent == null)
            return;
        final Uri data = intent.getData();
        if (data == null)
            return;
        if (!NotificationHelper.DEEPLINK_SCHEME.equals(data.getScheme()))
            return;
        final String peer = data.getQueryParameter("peer");
        if (peer == null || peer.isEmpty())
            return;

        // Clearing the notification for this peer as we open the conversation is
        // the expected behaviour (the alert has served its purpose).
        NotificationHelper.cancelForPeer(this, peer);

        deliverPeerToNative(peer);
    }

    // Deliver a peer to the C++ side if it is ready; otherwise stash it.
    private void deliverPeerToNative(String peer) {
        if (sNativeReady) {
            try {
                onOpenConversation(peer);
            } catch (UnsatisfiedLinkError e) {
                // Native symbol not resolved yet after all; stash and retry.
                sPendingPeer = peer;
            }
        } else {
            sPendingPeer = peer;
        }
    }

    // Called FROM C++ (AndroidNotifier) once the app's native side is up and
    // onOpenConversation can be handled. Delivers any peer that arrived early.
    // Declared static and looked up by JNI name, so it can be invoked before an
    // instance method would be convenient.
    public static void nativeReady() {
        sNativeReady = true;
        if (sPendingPeer != null) {
            final String peer = sPendingPeer;
            sPendingPeer = null;
            try {
                onOpenConversation(peer);
            } catch (UnsatisfiedLinkError e) {
                // Extremely unlikely here; drop rather than crash.
                sPendingPeer = peer;
            }
        }
    }

    // The JNI bridge to C++: implemented on the native side (AndroidNotifier),
    // which forwards the peer to ChatClient to open that conversation on the Qt
    // thread. Static so both the instance path and nativeReady() can call it.
    public static native void onOpenConversation(String peer);
}
