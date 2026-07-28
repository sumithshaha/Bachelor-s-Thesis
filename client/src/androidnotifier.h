#ifndef ANDROIDNOTIFIER_H
#define ANDROIDNOTIFIER_H

// ============================================================================
//  androidnotifier.h  --  the C++ side of Android notifications & shortcuts.
//
//  A small static bridge from ChatClient to the Java helpers
//  (NotificationHelper / ChatService / ChatE2EEActivity) via Qt's JNI wrapper
//  (QJniObject). Every method is a no-op on non-Android platforms (guarded by
//  Q_OS_ANDROID), so ChatClient can call these unconditionally and the desktop
//  build is completely unaffected -- the calls compile to nothing.
//
//  Responsibilities:
//    * startService / stopService  -- run the foreground service on login /
//      logout so the process (and thus the socket + ratchet) stays alive in the
//      background, which is what lets background messages be decrypted.
//    * notifyMessage / notifyFile  -- post a per-conversation notification with
//      sender + content. ChatClient calls these AFTER it has decrypted the
//      incoming message, so only plaintext crosses into Java; no keys, ever.
//    * createShortcut              -- pin a home-screen shortcut for a peer.
//    * signalNativeReady           -- tell the Java activity the native side is
//      up, so any deep-link that arrived during cold start is delivered.
//
//  The reverse direction (a tapped notification / shortcut opening a
//  conversation) is the JNI function Java_fi_tamk_chate2ee_ChatE2EEActivity_
//  onOpenConversation, implemented in androidnotifier.cpp, which forwards the
//  peer to the single ChatClient instance on the Qt thread.
//
//  STATUS: faithful, build-and-test-required. Android foreground-service and
//  notification behaviour varies across Android 13/14 and OEM skins (test on
//  the real S24 Ultra). Not compiled against the NDK here.
// ============================================================================

#include <QString>

class ChatClient;   // forward declaration; the .cpp wires the callback to it

class AndroidNotifier
{
public:
    // Register the single ChatClient the JNI callback should drive when a
    // notification/shortcut deep-link opens a conversation. Called once from
    // ChatClient::create(). On non-Android this simply stores the pointer
    // (harmless and unused).
    static void setClient(ChatClient *client);
    static ChatClient *client();

    // Start / stop the foreground service. 'title' and 'text' are the localized
    // strings for the ongoing notification (ChatClient passes Loc-resolved
    // text). No-op off Android.
    static void startService(const QString &title, const QString &text);
    static void stopService();

    // Post a notification for an incoming message. 'title' and 'body' are
    // already localized and already decrypted; 'peer' is the conversation to
    // open on tap. No-op off Android.
    static void notifyMessage(const QString &title, const QString &body,
                              const QString &peer);

    // Ensure the channels exist with localized names (called on login once the
    // language is known). Idempotent. No-op off Android.
    static void ensureChannels(const QString &messageChannelName,
                               const QString &serviceChannelName,
                               const QString &serviceChannelDesc);

    // Pin a home-screen shortcut for 'peer'. 'shortLabel'/'longLabel' are
    // localized. Returns true if the launcher accepted the pin request, false
    // if unsupported/refused (or off Android). ChatClient surfaces the result.
    static bool createShortcut(const QString &peer, const QString &shortLabel,
                               const QString &longLabel);

    // Clear a peer's notification (e.g. when its conversation is opened in-app).
    static void cancelForPeer(const QString &peer);

    // Tell the Java activity the native side is ready to receive conversation
    // opens, flushing any deep-link that arrived during cold start. Called once
    // from ChatClient::create(). No-op off Android.
    static void signalNativeReady();

private:
    static ChatClient *s_client;
};

#endif // ANDROIDNOTIFIER_H
