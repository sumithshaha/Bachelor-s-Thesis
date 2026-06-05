#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QStandardPaths>
#include <QDir>

#include "chatclient.h"
#include "messagemodel.h"
#include "usermodel.h"

// Application entry point.
//
// The job here is small: create the Qt application, make a ChatClient (the
// controller the whole UI hangs off), open the local history database, expose
// the controller to QML as a context property, and load the main QML file.
// Everything visible to the user is defined in QML; everything that *does*
// something lives in the C++ classes.

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    app.setOrganizationName("TAMK");
    app.setApplicationName("ChatE2EE");

    // Material style gives a clean look that adapts well to both desktop and
    // Android without per-platform tweaking.
    QQuickStyle::setStyle("Material");

    QQmlApplicationEngine engine;

    // One shared controller for the whole UI.
    ChatClient client;

    // Open the local per-conversation history database. It lives in the app's
    // writable data directory so it persists across restarts. Text rows are
    // stored as ciphertext; see HistoryStore for the rationale.
    const QString dataDir =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dataDir);
    client.openHistory(dataDir);

    engine.rootContext()->setContextProperty("chat", &client);

    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreationFailed,
        &app, []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);

    engine.loadFromModule("ChatE2EE", "Main");

    return app.exec();
}
