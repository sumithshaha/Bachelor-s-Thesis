/****************************************************************************
** Meta object code from reading C++ file 'chatclient.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.11.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../src/chatclient.h"
#include <QtCore/qmetatype.h>
#include <QtCore/QList>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'chatclient.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 69
#error "This file was generated using the moc from 6.11.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN10ChatClientE_t {};
} // unnamed namespace

template <> constexpr inline auto ChatClient::qt_create_metaobjectdata<qt_meta_tag_ZN10ChatClientE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "ChatClient",
        "QML.Element",
        "auto",
        "connectionStateChanged",
        "",
        "loggedIn",
        "activePeerChanged",
        "errorOccurred",
        "message",
        "peerKeysChanged",
        "fileSendProgress",
        "msgId",
        "fraction",
        "fileReceiveProgress",
        "fileReceived",
        "fromNick",
        "filename",
        "mime",
        "size",
        "localPath",
        "fileReceiveFailed",
        "reason",
        "onConnected",
        "onDisconnected",
        "onTextMessageReceived",
        "onBinaryMessageReceived",
        "data",
        "onSslErrors",
        "QList<QSslError>",
        "errors",
        "tryReconnect",
        "login",
        "serverUrl",
        "nickname",
        "openHistory",
        "baseDir",
        "sendMessage",
        "plaintext",
        "logout",
        "safetyNumberWith",
        "peer",
        "sendFile",
        "QUrl",
        "localFileUrl",
        "saveReceivedFile",
        "destinationUrl",
        "connected",
        "myNickname",
        "myFingerprint",
        "messages",
        "MessageModel*",
        "users",
        "UserModel*",
        "activePeer"
    };

    QtMocHelpers::UintData qt_methods {
        // Signal 'connectionStateChanged'
        QtMocHelpers::SignalData<void()>(3, 4, QMC::AccessPublic, QMetaType::Void),
        // Signal 'loggedIn'
        QtMocHelpers::SignalData<void()>(5, 4, QMC::AccessPublic, QMetaType::Void),
        // Signal 'activePeerChanged'
        QtMocHelpers::SignalData<void()>(6, 4, QMC::AccessPublic, QMetaType::Void),
        // Signal 'errorOccurred'
        QtMocHelpers::SignalData<void(const QString &)>(7, 4, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 8 },
        }}),
        // Signal 'peerKeysChanged'
        QtMocHelpers::SignalData<void()>(9, 4, QMC::AccessPublic, QMetaType::Void),
        // Signal 'fileSendProgress'
        QtMocHelpers::SignalData<void(const QString &, double)>(10, 4, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 11 }, { QMetaType::Double, 12 },
        }}),
        // Signal 'fileReceiveProgress'
        QtMocHelpers::SignalData<void(const QString &, double)>(13, 4, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 11 }, { QMetaType::Double, 12 },
        }}),
        // Signal 'fileReceived'
        QtMocHelpers::SignalData<void(const QString &, const QString &, const QString &, const QString &, qint64, const QString &)>(14, 4, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 11 }, { QMetaType::QString, 15 }, { QMetaType::QString, 16 }, { QMetaType::QString, 17 },
            { QMetaType::LongLong, 18 }, { QMetaType::QString, 19 },
        }}),
        // Signal 'fileReceiveFailed'
        QtMocHelpers::SignalData<void(const QString &, const QString &)>(20, 4, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 11 }, { QMetaType::QString, 21 },
        }}),
        // Slot 'onConnected'
        QtMocHelpers::SlotData<void()>(22, 4, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onDisconnected'
        QtMocHelpers::SlotData<void()>(23, 4, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onTextMessageReceived'
        QtMocHelpers::SlotData<void(const QString &)>(24, 4, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::QString, 8 },
        }}),
        // Slot 'onBinaryMessageReceived'
        QtMocHelpers::SlotData<void(const QByteArray &)>(25, 4, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::QByteArray, 26 },
        }}),
        // Slot 'onSslErrors'
        QtMocHelpers::SlotData<void(const QList<QSslError> &)>(27, 4, QMC::AccessPrivate, QMetaType::Void, {{
            { 0x80000000 | 28, 29 },
        }}),
        // Slot 'tryReconnect'
        QtMocHelpers::SlotData<void()>(30, 4, QMC::AccessPrivate, QMetaType::Void),
        // Method 'login'
        QtMocHelpers::MethodData<void(const QString &, const QString &)>(31, 4, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 32 }, { QMetaType::QString, 33 },
        }}),
        // Method 'openHistory'
        QtMocHelpers::MethodData<void(const QString &)>(34, 4, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 35 },
        }}),
        // Method 'sendMessage'
        QtMocHelpers::MethodData<void(const QString &)>(36, 4, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 37 },
        }}),
        // Method 'logout'
        QtMocHelpers::MethodData<void()>(38, 4, QMC::AccessPublic, QMetaType::Void),
        // Method 'safetyNumberWith'
        QtMocHelpers::MethodData<QString(const QString &) const>(39, 4, QMC::AccessPublic, QMetaType::QString, {{
            { QMetaType::QString, 40 },
        }}),
        // Method 'sendFile'
        QtMocHelpers::MethodData<void(const QUrl &)>(41, 4, QMC::AccessPublic, QMetaType::Void, {{
            { 0x80000000 | 42, 43 },
        }}),
        // Method 'saveReceivedFile'
        QtMocHelpers::MethodData<bool(const QString &, const QUrl &)>(44, 4, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 11 }, { 0x80000000 | 42, 45 },
        }}),
    };
    QtMocHelpers::UintData qt_properties {
        // property 'connected'
        QtMocHelpers::PropertyData<bool>(46, QMetaType::Bool, QMC::DefaultPropertyFlags, 0),
        // property 'myNickname'
        QtMocHelpers::PropertyData<QString>(47, QMetaType::QString, QMC::DefaultPropertyFlags, 1),
        // property 'myFingerprint'
        QtMocHelpers::PropertyData<QString>(48, QMetaType::QString, QMC::DefaultPropertyFlags, 1),
        // property 'messages'
        QtMocHelpers::PropertyData<MessageModel*>(49, 0x80000000 | 50, QMC::DefaultPropertyFlags | QMC::EnumOrFlag | QMC::Constant),
        // property 'users'
        QtMocHelpers::PropertyData<UserModel*>(51, 0x80000000 | 52, QMC::DefaultPropertyFlags | QMC::EnumOrFlag | QMC::Constant),
        // property 'activePeer'
        QtMocHelpers::PropertyData<QString>(53, QMetaType::QString, QMC::DefaultPropertyFlags | QMC::Writable | QMC::StdCppSet, 2),
    };
    QtMocHelpers::UintData qt_enums {
    };
    QtMocHelpers::UintData qt_constructors {};
    QtMocHelpers::ClassInfos qt_classinfo({
            {    1,    2 },
    });
    return QtMocHelpers::metaObjectData<ChatClient, void>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums, qt_constructors, qt_classinfo);
}
Q_CONSTINIT const QMetaObject ChatClient::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10ChatClientE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10ChatClientE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN10ChatClientE_t>.metaTypes,
    nullptr
} };

void ChatClient::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<ChatClient *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->connectionStateChanged(); break;
        case 1: _t->loggedIn(); break;
        case 2: _t->activePeerChanged(); break;
        case 3: _t->errorOccurred((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1]))); break;
        case 4: _t->peerKeysChanged(); break;
        case 5: _t->fileSendProgress((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<double>>(_a[2]))); break;
        case 6: _t->fileReceiveProgress((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<double>>(_a[2]))); break;
        case 7: _t->fileReceived((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[4])),(*reinterpret_cast<std::add_pointer_t<qint64>>(_a[5])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[6]))); break;
        case 8: _t->fileReceiveFailed((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2]))); break;
        case 9: _t->onConnected(); break;
        case 10: _t->onDisconnected(); break;
        case 11: _t->onTextMessageReceived((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1]))); break;
        case 12: _t->onBinaryMessageReceived((*reinterpret_cast<std::add_pointer_t<QByteArray>>(_a[1]))); break;
        case 13: _t->onSslErrors((*reinterpret_cast<std::add_pointer_t<QList<QSslError>>>(_a[1]))); break;
        case 14: _t->tryReconnect(); break;
        case 15: _t->login((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[2]))); break;
        case 16: _t->openHistory((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1]))); break;
        case 17: _t->sendMessage((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1]))); break;
        case 18: _t->logout(); break;
        case 19: { QString _r = _t->safetyNumberWith((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 20: _t->sendFile((*reinterpret_cast<std::add_pointer_t<QUrl>>(_a[1]))); break;
        case 21: { bool _r = _t->saveReceivedFile((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QUrl>>(_a[2])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        default: ;
        }
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
        case 13:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
            case 0:
                *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType::fromType< QList<QSslError> >(); break;
            }
            break;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)()>(_a, &ChatClient::connectionStateChanged, 0))
            return;
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)()>(_a, &ChatClient::loggedIn, 1))
            return;
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)()>(_a, &ChatClient::activePeerChanged, 2))
            return;
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)(const QString & )>(_a, &ChatClient::errorOccurred, 3))
            return;
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)()>(_a, &ChatClient::peerKeysChanged, 4))
            return;
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)(const QString & , double )>(_a, &ChatClient::fileSendProgress, 5))
            return;
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)(const QString & , double )>(_a, &ChatClient::fileReceiveProgress, 6))
            return;
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)(const QString & , const QString & , const QString & , const QString & , qint64 , const QString & )>(_a, &ChatClient::fileReceived, 7))
            return;
        if (QtMocHelpers::indexOfMethod<void (ChatClient::*)(const QString & , const QString & )>(_a, &ChatClient::fileReceiveFailed, 8))
            return;
    }
    if (_c == QMetaObject::RegisterPropertyMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 3:
            *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< MessageModel* >(); break;
        case 4:
            *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< UserModel* >(); break;
        }
    }
    if (_c == QMetaObject::ReadProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast<bool*>(_v) = _t->isConnected(); break;
        case 1: *reinterpret_cast<QString*>(_v) = _t->myNickname(); break;
        case 2: *reinterpret_cast<QString*>(_v) = _t->myFingerprint(); break;
        case 3: *reinterpret_cast<MessageModel**>(_v) = _t->messages(); break;
        case 4: *reinterpret_cast<UserModel**>(_v) = _t->users(); break;
        case 5: *reinterpret_cast<QString*>(_v) = _t->activePeer(); break;
        default: break;
        }
    }
    if (_c == QMetaObject::WriteProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 5: _t->setActivePeer(*reinterpret_cast<QString*>(_v)); break;
        default: break;
        }
    }
}

const QMetaObject *ChatClient::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ChatClient::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10ChatClientE_t>.strings))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int ChatClient::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 22)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 22;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 22)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 22;
    }
    if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::BindableProperty
            || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void ChatClient::connectionStateChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void ChatClient::loggedIn()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void ChatClient::activePeerChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}

// SIGNAL 3
void ChatClient::errorOccurred(const QString & _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 3, nullptr, _t1);
}

// SIGNAL 4
void ChatClient::peerKeysChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 4, nullptr);
}

// SIGNAL 5
void ChatClient::fileSendProgress(const QString & _t1, double _t2)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 5, nullptr, _t1, _t2);
}

// SIGNAL 6
void ChatClient::fileReceiveProgress(const QString & _t1, double _t2)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 6, nullptr, _t1, _t2);
}

// SIGNAL 7
void ChatClient::fileReceived(const QString & _t1, const QString & _t2, const QString & _t3, const QString & _t4, qint64 _t5, const QString & _t6)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 7, nullptr, _t1, _t2, _t3, _t4, _t5, _t6);
}

// SIGNAL 8
void ChatClient::fileReceiveFailed(const QString & _t1, const QString & _t2)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 8, nullptr, _t1, _t2);
}
QT_WARNING_POP
