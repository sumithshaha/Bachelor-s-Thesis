#ifndef DESKTOPNOTIFIER_H
#define DESKTOPNOTIFIER_H

// ============================================================================
//  desktopnotifier.h  --  the DESKTOP counterpart of AndroidNotifier.
//
//  On Android, incoming-message notifications are posted through the Java
//  NotificationHelper (via AndroidNotifier + JNI), kept alive by a foreground
//  service. That whole path is a no-op on desktop, so before this class the
//  Windows build showed NO notifications at all.
//
//  This class fills that gap using Qt's QSystemTrayIcon, which renders native
//  toasts on Windows (and works on Linux/macOS too). It intentionally mirrors
//  AndroidNotifier's shape -- static methods, safe to call unconditionally --
//  so ChatClient posts to BOTH from the same place: whichever platform it is on,
//  exactly one of them does the work and the other compiles to nothing.
//
//    * init(rootWindow)  -- create the tray icon once (given the main window so
//      a clicked notification can raise + focus it). Call after the QML engine
//      has produced its root window. No-op on Android / where no system tray is
//      available.
//    * notify(title, body, peer)  -- show one native notification. 'title' and
//      'body' are already localized and already DECRYPTED by ChatClient (no keys
//      or ciphertext ever reach this layer, exactly as on the Android side).
//      'peer' is remembered so clicking the toast opens that conversation.
//
//  Everything is compiled out on Android (guarded by Q_OS_ANDROID), and also
//  degrades to a no-op if the Qt build has no QSystemTrayIcon, so it never
//  affects the mobile build and never fails a headless one.
//
//  STATUS: build-and-test-required. Not compiled against the Qt toolchain here;
//  QSystemTrayIcon::showMessage routing to the Windows Action Center should be
//  verified on the real desktop build.
// ============================================================================

#include <QString>

class QObject;

class DesktopNotifier
{
public:
    // Create the tray icon and remember the main window to raise when a
    // notification is clicked. Pass the QML root object (the ApplicationWindow).
    // No-op on Android and where no system tray is present. Idempotent.
    static void init(QObject *rootWindow);

    // Show a desktop notification for an incoming message/file. No-op on Android
    // (the JNI path is used there) and if init() found no usable tray.
    static void notify(const QString &title, const QString &body,
                       const QString &peer);

    // True if a desktop tray notification channel is actually available (tray
    // created). False on Android or where no system tray exists.
    static bool available();
};

#endif // DESKTOPNOTIFIER_H
