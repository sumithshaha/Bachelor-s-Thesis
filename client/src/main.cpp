#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include <QIcon>

// APPLICATION TYPE (desktop vs Android).
//   * Desktop: QApplication (from Qt Widgets). QSystemTrayIcon -- how the
//     desktop notifications are shown (see desktopnotifier.cpp) -- requires a
//     QApplication, so the desktop build uses it. QApplication IS-A
//     QGuiApplication, so every existing call below is unchanged.
//   * Android: QGuiApplication, exactly as before. The Android build links no
//     Qt Widgets and uses the Java/JNI notification path instead, so the mobile
//     build is completely unaffected by the desktop notification feature.
#ifdef Q_OS_ANDROID
#  include <QGuiApplication>
#else
#  include <QApplication>
#endif

#include <QtGlobal>
#include <QDateTime>
#include <QString>
#include <QMutex>
#include <QVector>
#include <QPair>
#include <QLoggingCategory>

#include "chatclient.h"
#include "messagemodel.h"
#include "usermodel.h"
#include "desktopnotifier.h"
#include "logbuffer.h"

// ============================================================================
//  DEEP DIAGNOSTIC LOGGING  ---------------------------------------------------
//
//  Every qDebug/qInfo/qWarning/qCritical (including the app's [LOCK] and
//  ratchet/user-switch DIAGNOSTIC traces) is routed through the handler below
//  so it appears in BOTH places at runtime:
//
//    1. The platform console / logcat  -- we chain to Qt's DEFAULT handler
//       first, so anything that printed before still prints, unchanged.
//    2. The in-app Log screen           -- we mirror a richly formatted copy of
//       each record into the LogBuffer singleton (see logbuffer.h), which a
//       ListView renders live.
//
//  The format is intentionally VERBOSE ("extended probing"): local time with
//  milliseconds, the level, the logging category, the function, and file:line,
//  then the message. Example:
//
//    21:50:45.123 D [default] ChatClient::onTextFrame (chatclient.cpp:2670)
//        [LOCK] biometric accepted
//
//  ORDERING: the handler is installed at the very top of main(), before the QML
//  engine constructs the LogBuffer singleton (which is created lazily the first
//  time QML references the type). Records that arrive in that early window are
//  held in a small pre-buffer and drained into the LogBuffer the instant it
//  exists, so the in-app view is complete from the first line. The pre-buffer
//  is bounded so a failure to ever create the UI cannot grow memory.
// ============================================================================

namespace {

// Guards the early pre-buffer only. Not held while chaining to the default
// handler or while calling LogBuffer::append (which does its own thread hop).
QMutex g_preMutex;
QVector<QPair<QString, QString>> g_preBuffer;   // (formatted line, level tag)
bool    g_preDrained = false;
constexpr int kPreBufferMax = 2000;

QtMessageHandler g_defaultHandler = nullptr;

QString levelTag(QtMsgType type)
{
    switch (type) {
    case QtDebugMsg:    return QStringLiteral("debug");
    case QtInfoMsg:     return QStringLiteral("info");
    case QtWarningMsg:  return QStringLiteral("warning");
    case QtCriticalMsg: return QStringLiteral("critical");
    case QtFatalMsg:    return QStringLiteral("fatal");
    }
    return QStringLiteral("debug");
}


// Build the verbose one-line (plus wrapped message) record for the in-app view.
QString formatRecord(QtMsgType type, const QMessageLogContext &ctx,
                     const QString &msg)
{
    // EXACT PARITY WITH THE CONSOLE.
    //
    // This used to build a bespoke two-line record:
    //
    //     14:22:07.913 W [default] void ChatClient::onSslErrors(...) (chatclient.cpp:1560)
    //         [TLS] verification failed: ...
    //
    // which was informative but was NOT what Qt Creator's Application Output,
    // or `adb logcat`, actually showed. Comparing a screenshot of the in-app
    // Log screen against a pasted console log meant mentally translating
    // between two different layouts, and a line copied out of the app did not
    // match the line a reader would search for in the console.
    //
    // qFormatLogMessage() is the very function Qt's own default handler uses to
    // turn a record into text. Calling it here means the in-app Log screen
    // renders each line byte-for-byte identically to the console, including
    // Qt's default pattern
    //
    //     %{if-category}%{category}: %{endif}%{message}
    //
    // which is why a categorised record appears as
    //
    //     qt.qml.invalidOverride: qrc:/.../LoginPage.qml:569:9: Duplicate method name
    //
    // while an uncategorised qDebug() from this application appears bare:
    //
    //     [CRYPTO] sodium_init ok; AES256-GCM available = 0
    //
    // It also picks up QT_MESSAGE_PATTERN automatically. So anyone who wants
    // timestamps, thread ids, or source locations back can ask for them without
    // a rebuild, and the console and the in-app screen change together and stay
    // in agreement:
    //
    //     set QT_MESSAGE_PATTERN=%{time hh:mm:ss.zzz} %{type} %{category}: %{message}
    //
    // The QtMsgType is still recorded separately by the caller (levelTag) so the
    // Log screen can colour warnings and criticals; that is presentation, and it
    // does not alter the text.
    return qFormatLogMessage(type, ctx, msg);
}

void deepLogHandler(QtMsgType type, const QMessageLogContext &ctx,
                    const QString &msg)
{
    // 1. Preserve existing behaviour: hand the raw record to Qt's default
    //    handler so it still reaches stdout / logcat exactly as before.
    if (g_defaultHandler)
        g_defaultHandler(type, ctx, msg);

    // 2. Mirror a verbose copy into the in-app log.
    const QString line = formatRecord(type, ctx, msg);
    const QString lvl  = levelTag(type);

    if (LogBuffer *lb = LogBuffer::instance()) {
        // The buffer exists. If we still have early records queued, flush them
        // first (once), preserving order, then append this one.
        bool drainNow = false;
        {
            QMutexLocker lock(&g_preMutex);
            if (!g_preDrained && !g_preBuffer.isEmpty())
                drainNow = true;
        }
        if (drainNow) {
            QVector<QPair<QString, QString>> pending;
            {
                QMutexLocker lock(&g_preMutex);
                pending.swap(g_preBuffer);
                g_preDrained = true;
            }
            for (const auto &rec : pending)
                lb->append(rec.first, rec.second);
        } else {
            QMutexLocker lock(&g_preMutex);
            g_preDrained = true;   // nothing queued: mark drained so we stop checking
        }
        lb->append(line, lvl);
    } else {
        // The singleton is not up yet. Hold the record so the in-app view can
        // show it retroactively. Bounded: drop the oldest if we somehow never
        // build the UI.
        QMutexLocker lock(&g_preMutex);
        if (g_preBuffer.size() >= kPreBufferMax)
            g_preBuffer.removeFirst();
        g_preBuffer.append(qMakePair(line, lvl));
    }

    // 3. Match Qt's own contract: a fatal message must still abort.
    if (type == QtFatalMsg)
        abort();
}

} // namespace

// Application entry point.
//
// The UI controller (ChatClient) is exposed to QML as a SINGLETON, registered
// via QML_ELEMENT + QML_SINGLETON in chatclient.h and constructed by
// ChatClient::create(). QML references it by type after `import ChatE2EE` (see
// the .qml files, which use `ChatClient.<property>`). This replaces the old
// rootContext()->setContextProperty("chat", &client) approach, which did not
// propagate into components loaded from the compiled QML module -- every
// `chat.X` came through as null, leaving the whole UI unbound.
int main(int argc, char *argv[])
{
    // Install the deep-logging handler FIRST, before anything can log, so no
    // startup record is missed. install returns the prior (default) handler,
    // which our handler chains to for console/logcat output.
    g_defaultHandler = qInstallMessageHandler(deepLogHandler);

    // ------------------------------------------------------------------
    // QT RUNTIME LOGS -- policy: NECESSARY ONLY. By default Qt already
    // suppresses debug output for its OWN categories (the built-in rule is
    // effectively qt.*.debug=false), so without any rules the handler above
    // sees the app's own qDebug lines and nothing from Qt's internals. We
    // make that intent explicit and robust here rather than relying on the
    // implicit default:
    //
    //   * qt.*.debug=false / qt.*.info=false -- keep Qt's internal
    //     per-subsystem firehose (scene-graph batching, per-frame dirty
    //     regions, every pointer/touch event, text-shaping passes, QML GC
    //     sweeps, QPA plumbing, network/TLS trace) OUT of the stream. These
    //     categories emit thousands of lines a second while rendering and
    //     would bury every line anyone actually reads.
    //   * default.debug=true -- KEEP the app's own diagnostics: the [BUILD]
    //     banner, [LOCK], the ratchet / user-switch traces, etc.
    //   * server.debug=true  -- KEEP the streamed relay-server mirror (the
    //     [server] lines re-emitted by chatclient.cpp).
    //
    // WARNINGS AND CRITICALS ARE NOT TOUCHED: Qt enables warning/critical for
    // every category by default, so genuine problems -- QML binding errors,
    // TLS/certificate warnings, network failures -- still reach both the
    // console/logcat and the in-app Log screen. Only the low-value debug/info
    // firehose is removed.
    //
    // To go deep again for a one-off experiment, run with the environment
    // variable QT_LOGGING_RULES="*.debug=true"; the environment overrides
    // these programmatic rules by design, so no rebuild is needed.
    //
    // Placed BEFORE the QApplication is constructed so the very first
    // startup records are already governed by this policy.
    QLoggingCategory::setFilterRules(QStringLiteral(
        "qt.*.debug=false\n"      // no Qt-internal per-subsystem debug firehose
        "qt.*.info=false\n"       // nor Qt-internal info chatter
        "default.debug=true\n"    // app's own diagnostics: [BUILD], [LOCK], ratchet, user-switch
        "server.debug=true"       // the streamed relay-server mirror ([server] lines)
        ));

#ifdef Q_OS_ANDROID
    QGuiApplication app(argc, argv);
#else
    QApplication app(argc, argv);   // QApplication: needed by QSystemTrayIcon
#endif
    app.setOrganizationName("TAMK");
    app.setApplicationName("ChatE2EE");
    // The app icon: window title bar, taskbar/dock, the desktop tray icon, and
    // each desktop notification all use it. Bundled as a Qt resource (see
    // CMakeLists.txt). On Android the launcher icon is used instead, so this is
    // simply harmless there.
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/chate2ee-256.png")));

    // Material style gives a clean look that adapts well to both desktop and
    // Android without per-platform tweaking.
    QQuickStyle::setStyle("Material");

    QQmlApplicationEngine engine;
    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreationFailed,
        &app, []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);

    // The ChatClient singleton is created lazily by the engine (via
    // ChatClient::create) the first time QML references the type, so there is
    // no controller to construct or expose here.
    engine.loadFromModule("ChatE2EE", "Main");

    // DESKTOP NOTIFICATIONS: create the system-tray icon now that the root
    // window exists, handing it that window so a clicked notification can raise
    // and focus the app. No-op on Android and where no system tray is available.
    QObject *root = engine.rootObjects().isEmpty()
                        ? nullptr
                        : engine.rootObjects().first();
    DesktopNotifier::init(root);

    return app.exec();
}
