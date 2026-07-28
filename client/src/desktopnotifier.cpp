#include "desktopnotifier.h"

// The real implementation is compiled ONLY on desktop and only when the Qt
// build actually provides QSystemTrayIcon (it lives in Qt Widgets, which the
// CMake links for the non-Android target). On Android, or a headless build
// without it, every method below collapses to a no-op so the mobile build is
// completely unaffected and ChatClient can keep calling these unconditionally.
#include <QtGlobal>
#if !defined(Q_OS_ANDROID) && __has_include(<QSystemTrayIcon>)
#  define CHATE2EE_DESKTOP_TRAY 1
#else
#  define CHATE2EE_DESKTOP_TRAY 0
#endif

#if CHATE2EE_DESKTOP_TRAY

#include <QSystemTrayIcon>
#include <QIcon>
#include <QGuiApplication>
#include <QWindow>

#include "androidnotifier.h"   // AndroidNotifier::client() -> the ChatClient
#include "chatclient.h"        // openConversationFromNotification(peer)

namespace {
QSystemTrayIcon *g_tray   = nullptr;   // owned for the app lifetime
QWindow         *g_window = nullptr;    // main window, to raise on click
QString          g_lastPeer;            // conversation to open when a toast is clicked

// The app icon we set on the tray and each notification. Falls back to the
// application-wide window icon (set in main()) if the resource is missing.
QIcon appIcon()
{
    QIcon ic(QStringLiteral(":/icons/chate2ee-256.png"));
    if (ic.isNull())
        ic = QGuiApplication::windowIcon();
    return ic;
}

// Bring the main window to the front: un-minimize, show, raise, focus. This is
// what a user expects when they click a chat notification.
void raiseMainWindow()
{
    if (!g_window)
        return;
    // Un-minimize if needed, preserving any maximized state. NOTE: QWindow's
    // singular windowState()/setWindowState() use a PLAIN Qt::WindowState enum,
    // so a bitmask expression on them collapses to int and will not convert back
    // to Qt::WindowState -- that was the build error. The plural QFlags API
    // (windowStates()/setWindowStates()) composes cleanly, and setFlag/testFlag
    // avoid any enum/int ambiguity entirely.
    Qt::WindowStates states = g_window->windowStates();
    if (states.testFlag(Qt::WindowMinimized)) {
        states.setFlag(Qt::WindowMinimized, false);
        g_window->setWindowStates(states);
    }
    g_window->show();
    g_window->raise();
    g_window->requestActivate();
}
} // namespace

void DesktopNotifier::init(QObject *rootWindow)
{
    g_window = qobject_cast<QWindow *>(rootWindow);

    // No tray (e.g. a bare Linux session) -> notifications simply won't show,
    // but the app is otherwise unaffected.
    if (!QSystemTrayIcon::isSystemTrayAvailable())
        return;
    if (g_tray)
        return;   // already initialised

    g_tray = new QSystemTrayIcon(appIcon(), qApp);
    g_tray->setToolTip(QStringLiteral("ChatE2EE"));

    // Clicking the notification balloon opens the conversation it was about and
    // brings the window forward.
    QObject::connect(g_tray, &QSystemTrayIcon::messageClicked, qApp, []() {
        raiseMainWindow();
        if (!g_lastPeer.isEmpty() && AndroidNotifier::client())
            AndroidNotifier::client()->openConversationFromNotification(g_lastPeer);
    });
    // Clicking the tray icon itself just brings the window forward.
    QObject::connect(g_tray, &QSystemTrayIcon::activated, qApp,
                     [](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Trigger
            || reason == QSystemTrayIcon::DoubleClick)
            raiseMainWindow();
    });

    g_tray->show();
}

void DesktopNotifier::notify(const QString &title, const QString &body,
                             const QString &peer)
{
    if (!g_tray)
        return;   // init() found no tray, or was never called
    g_lastPeer = peer;
    // Native toast. 8 s is long enough to read but not intrusive; the OS may
    // clamp this. The icon keeps the notification on-brand.
    g_tray->showMessage(title, body, appIcon(), 8000);
}

bool DesktopNotifier::available() { return g_tray != nullptr; }

#else  // ---- Android / no-tray build: every method is a no-op ---------------

void DesktopNotifier::init(QObject *) {}
void DesktopNotifier::notify(const QString &, const QString &, const QString &) {}
bool DesktopNotifier::available() { return false; }

#endif // CHATE2EE_DESKTOP_TRAY
