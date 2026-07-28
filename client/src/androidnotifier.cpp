#include "androidnotifier.h"

#include <QString>

// The single ChatClient the JNI callback drives. Set once from
// ChatClient::create(). Kept even on non-Android (unused there) so the class
// has one definition everywhere.
ChatClient *AndroidNotifier::s_client = nullptr;

void AndroidNotifier::setClient(ChatClient *client) { s_client = client; }
ChatClient *AndroidNotifier::client() { return s_client; }

// ============================================================================
//  Android implementation
// ============================================================================
#ifdef Q_OS_ANDROID

#include <QJniObject>
#include <QJniEnvironment>
#include <QCoreApplication>
#include <QMetaObject>
#include <jni.h>

#include "chatclient.h"

// The fully-qualified JNI class names of our Java helpers.
static const char *kActivityClass =
    "fi/tamk/chate2ee/ChatE2EEActivity";
static const char *kHelperClass =
    "fi/tamk/chate2ee/NotificationHelper";
static const char *kServiceClass =
    "fi/tamk/chate2ee/ChatService";

// The current Android Activity (the QtActivity/ChatE2EEActivity instance), used
// as the Context for notification and shortcut calls. QtAndroidPrivate/
// QNativeInterface provides it. Returns an invalid QJniObject if unavailable.
static QJniObject currentActivity()
{
    return QNativeInterface::QAndroidApplication::context();
}

void AndroidNotifier::ensureChannels(const QString &messageChannelName,
                                     const QString &serviceChannelName,
                                     const QString &serviceChannelDesc)
{
    QJniObject ctx = currentActivity();
    if (!ctx.isValid())
        return;
    QJniObject::callStaticMethod<void>(
        kHelperClass,
        "ensureChannels",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;"
        "Ljava/lang/String;)V",
        ctx.object(),
        QJniObject::fromString(messageChannelName).object<jstring>(),
        QJniObject::fromString(serviceChannelName).object<jstring>(),
        QJniObject::fromString(serviceChannelDesc).object<jstring>());
}

void AndroidNotifier::startService(const QString &title, const QString &text)
{
    QJniObject ctx = currentActivity();
    if (!ctx.isValid())
        return;

    // Build an Intent(context, ChatService.class), put the localized title/text
    // as extras, and start it as a foreground service. On Android 8+ we must use
    // startForegroundService (the service then calls startForeground within a
    // few seconds, which ChatService.onStartCommand does). The ChatService class
    // object is obtained via Class.forName so we need no compile-time handle.
    QJniObject intent("android/content/Intent",
                      "(Landroid/content/Context;Ljava/lang/Class;)V",
                      ctx.object(),
                      QJniObject::callStaticObjectMethod(
                          "java/lang/Class", "forName",
                          "(Ljava/lang/String;)Ljava/lang/Class;",
                          QJniObject::fromString("fi.tamk.chate2ee.ChatService")
                              .object<jstring>())
                          .object<jclass>());

    // Put the localized ongoing-notification strings as extras.
    intent.callObjectMethod(
        "putExtra",
        "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
        QJniObject::fromString(QStringLiteral("svc_title")).object<jstring>(),
        QJniObject::fromString(title).object<jstring>());
    intent.callObjectMethod(
        "putExtra",
        "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
        QJniObject::fromString(QStringLiteral("svc_text")).object<jstring>(),
        QJniObject::fromString(text).object<jstring>());

    // API 26+: startForegroundService; below that: startService.
    const jint sdk = QJniObject::getStaticField<jint>(
        "android/os/Build$VERSION", "SDK_INT");
    if (sdk >= 26) {
        ctx.callObjectMethod(
            "startForegroundService",
            "(Landroid/content/Intent;)Landroid/content/ComponentName;",
            intent.object());
    } else {
        ctx.callObjectMethod(
            "startService",
            "(Landroid/content/Intent;)Landroid/content/ComponentName;",
            intent.object());
    }
}

void AndroidNotifier::stopService()
{
    QJniObject ctx = currentActivity();
    if (!ctx.isValid())
        return;
    QJniObject intent("android/content/Intent",
                      "(Landroid/content/Context;Ljava/lang/Class;)V",
                      ctx.object(),
                      QJniObject::callStaticObjectMethod(
                          "java/lang/Class", "forName",
                          "(Ljava/lang/String;)Ljava/lang/Class;",
                          QJniObject::fromString("fi.tamk.chate2ee.ChatService")
                              .object<jstring>())
                          .object<jclass>());
    ctx.callMethod<jboolean>(
        "stopService",
        "(Landroid/content/Intent;)Z",
        intent.object());
}

void AndroidNotifier::notifyMessage(const QString &title, const QString &body,
                                    const QString &peer)
{
    QJniObject ctx = currentActivity();
    if (!ctx.isValid())
        return;
    QJniObject::callStaticMethod<void>(
        kHelperClass,
        "postMessage",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;"
        "Ljava/lang/String;)V",
        ctx.object(),
        QJniObject::fromString(title).object<jstring>(),
        QJniObject::fromString(body).object<jstring>(),
        QJniObject::fromString(peer).object<jstring>());
}

bool AndroidNotifier::createShortcut(const QString &peer,
                                     const QString &shortLabel,
                                     const QString &longLabel)
{
    QJniObject ctx = currentActivity();
    if (!ctx.isValid())
        return false;
    const jboolean ok = QJniObject::callStaticMethod<jboolean>(
        kHelperClass,
        "createConversationShortcut",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;"
        "Ljava/lang/String;)Z",
        ctx.object(),
        QJniObject::fromString(peer).object<jstring>(),
        QJniObject::fromString(shortLabel).object<jstring>(),
        QJniObject::fromString(longLabel).object<jstring>());
    return ok == JNI_TRUE;
}

void AndroidNotifier::cancelForPeer(const QString &peer)
{
    QJniObject ctx = currentActivity();
    if (!ctx.isValid())
        return;
    QJniObject::callStaticMethod<void>(
        kHelperClass,
        "cancelForPeer",
        "(Landroid/content/Context;Ljava/lang/String;)V",
        ctx.object(),
        QJniObject::fromString(peer).object<jstring>());
}

void AndroidNotifier::signalNativeReady()
{
    // Tell the Java activity the native side is ready, so any deep link that
    // arrived during cold start is delivered now.
    QJniObject::callStaticMethod<void>(kActivityClass, "nativeReady", "()V");
}

// ---------------------------------------------------------------------------
//  JNI callback: Java -> C++ when a notification/shortcut opens a conversation.
//
//  ChatE2EEActivity.onOpenConversation(String) is declared `native`; this is
//  its implementation. It is called on the Android UI thread, so we must NOT
//  touch ChatClient (which lives on the Qt thread) directly. We marshal onto
//  the Qt thread with QMetaObject::invokeMethod(..., Qt::QueuedConnection),
//  setting the active peer there.
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT void JNICALL
Java_fi_tamk_chate2ee_ChatE2EEActivity_onOpenConversation(
    JNIEnv *env, jclass /*clazz*/, jstring peer)
{
    if (!peer)
        return;
    const char *utf = env->GetStringUTFChars(peer, nullptr);
    const QString peerName = QString::fromUtf8(utf);
    env->ReleaseStringUTFChars(peer, utf);

    ChatClient *c = AndroidNotifier::client();
    if (!c || peerName.isEmpty())
        return;

    // Hop to the Qt thread: setActivePeer touches models and must run there.
    QMetaObject::invokeMethod(
        c,
        [c, peerName]() { c->openConversationFromNotification(peerName); },
        Qt::QueuedConnection);
}

#else  // ---- non-Android: every method is a no-op --------------------------

void AndroidNotifier::ensureChannels(const QString &, const QString &,
                                     const QString &) {}
void AndroidNotifier::startService(const QString &, const QString &) {}
void AndroidNotifier::stopService() {}
void AndroidNotifier::notifyMessage(const QString &, const QString &,
                                    const QString &) {}
bool AndroidNotifier::createShortcut(const QString &, const QString &,
                                     const QString &) { return false; }
void AndroidNotifier::cancelForPeer(const QString &) {}
void AndroidNotifier::signalNativeReady() {}

#endif // Q_OS_ANDROID
