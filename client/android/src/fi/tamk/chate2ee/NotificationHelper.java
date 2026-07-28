package fi.tamk.chate2ee;

// ============================================================================
//  NotificationHelper.java
//
//  The Java side of the app's Android notifications and home-screen shortcuts.
//  It does the actual platform work that the C++ AndroidNotifier (via JNI)
//  asks for: creating the notification channel, posting a per-message
//  notification with sound + vibration, and pinning a conversation shortcut to
//  the launcher.
//
//  WHY JAVA (not pure JNI from C++)?
//  Building a Notification.Builder or a ShortcutInfo field-by-field over JNI is
//  verbose and error-prone (dozens of reflective calls, easy to get a signature
//  wrong). A small Java helper the C++ calls into with plain strings is far
//  clearer to read and to explain in the thesis, and it keeps all the Android
//  API-level branching (channels on O+, POST_NOTIFICATIONS on 13+, pinned
//  shortcuts on 26+) in one place.
//
//  IMPORTANT (E2EE): this class never sees ciphertext or keys. The C++
//  ChatClient has ALREADY decrypted the message by the time it calls
//  postMessage(); we are handed the plaintext title/body purely to display.
//  Nothing here touches the crypto path.
//
//  All methods are static and take the Context explicitly, so they can be
//  called from the C++ side (which passes the current Activity/Service as the
//  Context) without this class holding any state of its own.
// ============================================================================

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.graphics.drawable.Icon;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

import java.util.Arrays;

public final class NotificationHelper {

    private NotificationHelper() {}   // static-only

    // The channel through which per-message notifications are posted. One
    // channel for message alerts (sound + vibration), created once and reused.
    public static final String MESSAGE_CHANNEL_ID = "chate2ee_messages";
    // A SEPARATE, silent low-importance channel for the ongoing foreground-
    // service notification, so the "app is running" notice never buzzes or
    // dings -- only real incoming messages do.
    public static final String SERVICE_CHANNEL_ID = "chate2ee_service";

    // Deep-link scheme used by home-screen shortcuts. Tapping a shortcut opens
    // the app with this data URI; ChatE2EEActivity reads the "peer" query
    // parameter and asks the C++ side to open that conversation.
    public static final String DEEPLINK_SCHEME = "chate2ee";
    public static final String DEEPLINK_HOST   = "open";

    // ----------------------------------------------------------------------
    //  Channels
    // ----------------------------------------------------------------------
    // Create both channels if they do not exist. Safe to call repeatedly
    // (createNotificationChannel is idempotent for the same id). No-op below
    // Android O, where channels do not exist and importance is per-notification.
    public static void ensureChannels(Context ctx, String messageChannelName,
                                      String serviceChannelName,
                                      String serviceChannelDesc) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O)
            return;
        NotificationManager nm =
                ctx.getSystemService(NotificationManager.class);
        if (nm == null)
            return;

        // Message channel: high importance so it heads-up, with sound + vibrate.
        NotificationChannel msg = new NotificationChannel(
                MESSAGE_CHANNEL_ID,
                messageChannelName,
                NotificationManager.IMPORTANCE_HIGH);
        msg.enableVibration(true);
        msg.setVibrationPattern(new long[]{0, 250, 120, 250});
        msg.enableLights(true);
        // Use the user's default notification sound.
        msg.setSound(Settings.System.DEFAULT_NOTIFICATION_URI, null);
        nm.createNotificationChannel(msg);

        // Service channel: LOW importance, silent, for the persistent ongoing
        // notification that keeps the process alive. No sound, no vibration.
        NotificationChannel svc = new NotificationChannel(
                SERVICE_CHANNEL_ID,
                serviceChannelName,
                NotificationManager.IMPORTANCE_LOW);
        svc.setDescription(serviceChannelDesc);
        svc.setSound(null, null);
        svc.enableVibration(false);
        nm.createNotificationChannel(svc);
    }

    // ----------------------------------------------------------------------
    //  Posting a message / file notification
    // ----------------------------------------------------------------------
    // Post (or update) a notification for an incoming message or file. Tapping
    // it opens the conversation with 'peer' via the same deep-link the
    // shortcuts use. The notification id is derived from the peer name so
    // successive messages from the same peer REPLACE rather than stack, which
    // matches how a chat app should behave (one entry per conversation).
    //
    //   title  - already-localized, already-decrypted (e.g. "New message from Bob")
    //   body   - already-decrypted message text or file description
    //   peer   - the conversation to open on tap
    public static void postMessage(Context ctx, String title, String body,
                                   String peer) {
        NotificationManager nm =
                ctx.getSystemService(NotificationManager.class);
        if (nm == null)
            return;

        // Build the tap intent: open our activity with a chate2ee://open?peer=X
        // data URI. FLAG_ACTIVITY_SINGLE_TOP so an already-running app is reused
        // (onNewIntent) rather than a second instance launched.
        Intent tap = new Intent(ctx, ChatE2EEActivity.class);
        tap.setAction(Intent.ACTION_VIEW);
        tap.setData(buildDeepLink(peer));
        tap.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP
                   | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            piFlags |= PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pi = PendingIntent.getActivity(
                ctx, peer.hashCode(), tap, piFlags);

        // minSdk is 28 (Qt 6.11 default), so the channel constructor is always
        // available and importance/sound/vibration come from the channel itself
        // (see ensureChannels). The deprecated no-channel constructor,
        // setPriority, and setDefaults are therefore not needed at all.
        Notification.Builder b =
                new Notification.Builder(ctx, MESSAGE_CHANNEL_ID);

        b.setContentTitle(title)
         .setContentText(body)
         .setAutoCancel(true)
         .setContentIntent(pi)
         // A system icon so we need no drawable resource in this Qt project;
         // stat_notify_chat is always present in the platform.
         .setSmallIcon(android.R.drawable.stat_notify_chat)
         // Expandable long-text style for longer messages.
         .setStyle(new Notification.BigTextStyle().bigText(body));

        nm.notify(peer.hashCode(), b.build());
    }

    // Build a foreground-service notification: ongoing, low priority, silent,
    // not dismissible. Returned to ChatService which passes it to
    // startForeground(). Tapping it opens the app (no specific peer).
    public static Notification buildServiceNotification(Context ctx,
                                                        String title,
                                                        String text) {
        Intent open = new Intent(ctx, ChatE2EEActivity.class);
        open.setAction(Intent.ACTION_MAIN);
        open.addCategory(Intent.CATEGORY_LAUNCHER);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);

        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            piFlags |= PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pi = PendingIntent.getActivity(ctx, 0, open, piFlags);

        // minSdk 28: always use the channel constructor. The SERVICE_CHANNEL_ID
        // channel is created LOW-importance and silent in ensureChannels, so the
        // deprecated setPriority(PRIORITY_LOW) is unnecessary.
        Notification.Builder b =
                new Notification.Builder(ctx, SERVICE_CHANNEL_ID);

        b.setContentTitle(title)
         .setContentText(text)
         .setOngoing(true)
         .setContentIntent(pi)
         // Consistent chat glyph for the ongoing "running" notice (previously a
         // stray Bluetooth icon). A monochrome system silhouette renders cleanly
         // in the status bar on every Android version.
         .setSmallIcon(android.R.drawable.stat_notify_chat);

        return b.build();
    }

    // ----------------------------------------------------------------------
    //  Home-screen shortcut for a conversation
    // ----------------------------------------------------------------------
    // Pin a shortcut for 'peer' to the launcher, if the launcher supports
    // pinning (Android 26+). Tapping it opens the app straight into that
    // conversation via the deep link. On success returns true. If pinning is
    // unsupported or refused, returns false so the C++ side can inform the user.
    public static boolean createConversationShortcut(Context ctx, String peer,
                                                     String shortLabel,
                                                     String longLabel) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O)
            return false;
        ShortcutManager sm = ctx.getSystemService(ShortcutManager.class);
        if (sm == null || !sm.isRequestPinShortcutSupported())
            return false;

        Intent open = new Intent(ctx, ChatE2EEActivity.class);
        open.setAction(Intent.ACTION_VIEW);
        open.setData(buildDeepLink(peer));

        ShortcutInfo.Builder sb = new ShortcutInfo.Builder(ctx, "peer_" + peer)
                .setShortLabel(shortLabel)
                .setLongLabel(longLabel)
                .setIcon(Icon.createWithResource(
                        ctx, android.R.drawable.sym_action_chat))
                .setIntent(open);

        ShortcutInfo info = sb.build();

        // A callback intent is optional; passing null means we do not need to
        // be told when the pin completes. Some launchers show their own
        // confirmation UI.
        return sm.requestPinShortcut(info, null);
    }

    // ----------------------------------------------------------------------
    //  Helpers
    // ----------------------------------------------------------------------
    // Build the chate2ee://open?peer=<peer> URI used by both notifications and
    // shortcuts. The peer is URL-encoded so names with spaces/symbols survive.
    private static Uri buildDeepLink(String peer) {
        return new Uri.Builder()
                .scheme(DEEPLINK_SCHEME)
                .authority(DEEPLINK_HOST)
                .appendQueryParameter("peer", peer)
                .build();
    }

    // Cancel a conversation's notification (e.g. when the user opens that chat,
    // so the alert clears). Keyed by the same peer-hash id postMessage uses.
    public static void cancelForPeer(Context ctx, String peer) {
        NotificationManager nm =
                ctx.getSystemService(NotificationManager.class);
        if (nm != null)
            nm.cancel(peer.hashCode());
    }
}
