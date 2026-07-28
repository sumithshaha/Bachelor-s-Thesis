#ifndef LOGBUFFER_H
#define LOGBUFFER_H

// ============================================================================
//  logbuffer.h  --  in-app, always-on diagnostic log sink.
//
//  WHY THIS EXISTS
//  The app is instrumented with deep probing traces (qDebug/qWarning/qInfo,
//  including the [LOCK] and ratchet/user-switch DIAGNOSTIC lines). Until now
//  those went ONLY to the platform console -- stdout on desktop, logcat on
//  Android -- so they were invisible unless you attached a debugger or ran
//  `adb logcat`. This class makes every one of those lines visible in two
//  places AT RUNTIME, exactly as requested:
//
//    1. The platform console / logcat, unchanged. The message handler
//       installed in main.cpp forwards every record to Qt's DEFAULT handler
//       first, so nothing that used to print stops printing.
//    2. A live in-app "Log screen" (see ChatPage.qml). Every record is also
//       appended here, and this object IS a QAbstractListModel, so a ListView
//       renders the running tail and auto-follows new lines.
//
//  DESIGN
//    * QML SINGLETON, same mechanism as ChatClient: QML_ELEMENT + QML_SINGLETON,
//      constructed once by the engine via LogBuffer::create(). QML refers to it
//      as `LogBuffer` after `import ChatE2EE`. There is exactly one buffer for
//      the whole process.
//    * The C++ message handler (main.cpp) is global and may fire from ANY
//      thread (Qt logging is not confined to the GUI thread; the WebSocket and
//      history code can log from workers). append() therefore marshals onto the
//      object's own thread with a queued invocation before mutating the model,
//      so the model is only ever touched on the GUI thread -- required by
//      QAbstractItemModel. Calling append() from the GUI thread still works
//      (the queued call simply runs on the next event-loop pass).
//    * BOUNDED. The buffer is a ring capped at kMaxLines (default 5000). Old
//      lines roll off the front so a long-running session cannot grow memory
//      without limit. removingFirst + append is expressed to the model as the
//      correct begin/endRemoveRows / begin/endInsertRows pairs.
//    * SELF-CONTAINED. No dependency on ChatClient or any app type, so it can
//      be constructed and receive records from the very first line of main(),
//      before the UI (or a login) exists.
//
//  PRIVACY / THESIS NOTE
//    This surfaces internal diagnostics (lock state transitions, ratchet
//    bookkeeping, connection events) in the UI. It never prints key material or
//    plaintext beyond whatever the existing trace lines already emit, but it
//    DOES make those existing traces user-visible. That is the opposite of the
//    standing "strip the temporary DIAGNOSTIC probes before submission" task,
//    so treat an always-on log viewer as a development/demo aid and decide
//    deliberately whether it ships in the final thesis artifact.
//
//  STATUS: build-and-test-required. Not compiled against the Qt toolchain here.
// ============================================================================

#include <QAbstractListModel>
#include <QStringList>
#include <QQmlEngine>

class LogBuffer : public QAbstractListModel
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

    // Number of lines currently held (for a "N lines" header in the UI and to
    // let QML enable/disable the Clear/Copy actions on an empty buffer).
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    enum Roles {
        LineRole = Qt::UserRole + 1,  // the full formatted log line (string)
        LevelRole                     // "debug"|"info"|"warning"|"critical"|"fatal"
    };
    Q_ENUM(Roles)

    explicit LogBuffer(QObject *parent = nullptr);

    // The engine builds the one instance. We also stash a process-wide pointer
    // (instance()) so the global message handler in main.cpp can reach the same
    // object the QML singleton is showing.
    static LogBuffer *create(QQmlEngine *, QJSEngine *);
    static LogBuffer *instance();

    // ---- QAbstractListModel ------------------------------------------------
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    int count() const { return m_lines.size(); }

    // Append one already-formatted record. Thread-safe: if called off the GUI
    // thread it re-posts to the GUI thread before mutating the model. 'level'
    // is one of the strings listed under LevelRole.
    void append(const QString &line, const QString &level);

    // ---- Actions used by the Log screen ------------------------------------
    // Wipe the buffer (the "Clear" button).
    Q_INVOKABLE void clear();
    // The whole buffer joined by newlines, for the "Copy all" button
    // (QML puts it on the clipboard). Returns newest-last, reading order.
    Q_INVOKABLE QString asText() const;

signals:
    void countChanged();
    // Emitted after each successful append so the Log screen can auto-scroll to
    // the bottom only when a new line actually arrives.
    void appended();

private:
    // Does the real model mutation; always runs on the GUI thread.
    void appendOnGui(const QString &line, const QString &level);

    static constexpr int kMaxLines = 5000;

    QStringList m_lines;   // formatted text, oldest at index 0
    QStringList m_levels;  // parallel level tags, same indexing

    static LogBuffer *s_instance;
};

#endif // LOGBUFFER_H
