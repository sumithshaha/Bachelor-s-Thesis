#include "logbuffer.h"

#include <QThread>
#include <QMetaObject>
#include <QCoreApplication>

// The one process-wide instance, set by create(). The global message handler in
// main.cpp reads this to reach the same object QML is displaying.
LogBuffer *LogBuffer::s_instance = nullptr;

LogBuffer::LogBuffer(QObject *parent)
    : QAbstractListModel(parent)
{
}

LogBuffer *LogBuffer::create(QQmlEngine *, QJSEngine *)
{
    // The QML engine owns the returned instance. We keep a raw pointer for the
    // message handler; it is valid for the lifetime of the engine, which is the
    // lifetime of the app. QML_SINGLETON guarantees create() is called at most
    // once, so s_instance is assigned exactly once.
    if (!s_instance)
        s_instance = new LogBuffer;
    // Do NOT let the JS engine garbage-collect the singleton.
    QQmlEngine::setObjectOwnership(s_instance, QQmlEngine::CppOwnership);
    return s_instance;
}

LogBuffer *LogBuffer::instance()
{
    return s_instance;
}

int LogBuffer::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return m_lines.size();
}

QVariant LogBuffer::data(const QModelIndex &index, int role) const
{
    const int r = index.row();
    if (r < 0 || r >= m_lines.size())
        return {};
    switch (role) {
    case LineRole:            return m_lines.at(r);
    case LevelRole:           return m_levels.at(r);
    case Qt::DisplayRole:     return m_lines.at(r);   // convenience
    default:                  return {};
    }
}

QHash<int, QByteArray> LogBuffer::roleNames() const
{
    return {
        { LineRole,  QByteArrayLiteral("line")  },
        { LevelRole, QByteArrayLiteral("level") },
    };
}

void LogBuffer::append(const QString &line, const QString &level)
{
    // The Qt logging framework can invoke the message handler from any thread
    // (network/history workers log too). QAbstractItemModel mutations MUST
    // happen on the thread that owns the model -- the GUI thread here. If we are
    // already on that thread, mutate directly; otherwise queue the mutation.
    if (QThread::currentThread() == this->thread()) {
        appendOnGui(line, level);
    } else {
        QMetaObject::invokeMethod(
            this,
            [this, line, level]() { appendOnGui(line, level); },
            Qt::QueuedConnection);
    }
}

void LogBuffer::appendOnGui(const QString &line, const QString &level)
{
    // Roll the oldest line off the front once we are at capacity, expressed to
    // any attached view as a proper remove-then-insert so it never reads a
    // stale row count.
    if (m_lines.size() >= kMaxLines) {
        beginRemoveRows(QModelIndex(), 0, 0);
        m_lines.removeFirst();
        m_levels.removeFirst();
        endRemoveRows();
    }

    const int row = m_lines.size();
    beginInsertRows(QModelIndex(), row, row);
    m_lines.append(line);
    m_levels.append(level);
    endInsertRows();

    emit countChanged();
    emit appended();
}

void LogBuffer::clear()
{
    if (m_lines.isEmpty())
        return;
    beginResetModel();
    m_lines.clear();
    m_levels.clear();
    endResetModel();
    emit countChanged();
}

QString LogBuffer::asText() const
{
    return m_lines.join(QLatin1Char('\n'));
}
