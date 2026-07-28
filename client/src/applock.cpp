// ============================================================================
//  applock.cpp  --  implementation of the biometric-unlock bridge.
//
//  Mirrors androidnotifier.cpp: a static client pointer, Android calls through
//  QJniObject into the Java BiometricHelper, a JNI callback forwards a
//  successful authentication back to ChatClient on the Qt thread, and every
//  path is a safe no-op on a platform that cannot do biometrics.
//
//  STATUS: faithful, build-and-test-required. See applock.h for the platform
//  matrix and caveats (Android needs the AndroidX biometric dependency; the
//  Windows Hello path is experimental and may compile to a no-op on MinGW).
// ============================================================================
#include "applock.h"
#include "chatclient.h"
#include "localization.h"

#include <QDebug>
#include <QMetaObject>

#ifdef Q_OS_ANDROID
#include <QJniObject>
#include <QJniEnvironment>
#include <QCoreApplication>
#endif

// The single ChatClient the biometric callback drives.
ChatClient *AppLock::s_client = nullptr;

void AppLock::setClient(ChatClient *client) { s_client = client; }
ChatClient *AppLock::client() { return s_client; }

// ---------------------------------------------------------------------------
//  Login-vault callback state (file-static, shared by both platforms)
//
//  A biometric/Hello LOGIN recovers the password asynchronously (an Android JNI
//  callback, or a Windows worker thread that finishes after the Hello dialog).
//  When it completes we must run ChatClient::onBiometricLoginUnlocked(nick,
//  password), so we remember which account the in-flight login is for. The
//  server URL is remembered by ChatClient itself (biometricLogin stashes it),
//  so only the nick needs to survive here. Overwritten on each loginWithBiometric
//  call; there is only ever one login in flight at a time (the login screen is
//  modal to the user).
// ---------------------------------------------------------------------------
static QString s_loginNick;

// ---------------------------------------------------------------------------
//  Android
// ---------------------------------------------------------------------------
#ifdef Q_OS_ANDROID

static const char *kBiometricHelper = "fi/tamk/chate2ee/BiometricHelper";

bool AppLock::biometricAvailable()
{
    // BiometricHelper.canAuthenticate(Context) -> boolean. The activity is the
    // context. Any JNI failure is treated as "unavailable".
    QJniObject activity = QNativeInterface::QAndroidApplication::context();
    if (!activity.isValid())
        return false;
    jboolean ok = QJniObject::callStaticMethod<jboolean>(
        kBiometricHelper, "canAuthenticate",
        "(Landroid/content/Context;)Z", activity.object());
    return ok == JNI_TRUE;
}

void AppLock::requestUnlock(ChatClient *client)
{
    if (client)
        s_client = client;
    requestUnlock(Localization::instance()->t("lock.biometricTitle"),
                  Localization::instance()->t("lock.biometricSubtitle"));
}

void AppLock::requestUnlock(const QString &title, const QString &subtitle)
{
    QJniObject activity = QNativeInterface::QAndroidApplication::context();
    if (!activity.isValid()) {
        qWarning() << "[LOCK] no Android activity; cannot show biometric prompt";
        return;
    }
    QJniObject jTitle = QJniObject::fromString(title);
    QJniObject jSubtitle = QJniObject::fromString(subtitle);
    // BiometricHelper.authenticate(Activity, String title, String subtitle).
    // It must run on the Android UI thread; the Java helper marshals onto it.
    QJniObject::callStaticMethod<void>(
        kBiometricHelper, "authenticate",
        "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;)V",
        activity.object(), jTitle.object(), jSubtitle.object());
}

// JNI callback: Java calls this when authentication SUCCEEDS. It hops onto the
// Qt thread (via a queued invocation) and clears the lock through ChatClient.
extern "C" JNIEXPORT void JNICALL
Java_fi_tamk_chate2ee_BiometricHelper_onAuthSucceeded(JNIEnv *, jobject)
{
    // DIAGNOSTIC (temporary): confirms the JNI callback fired at all. If this
    // line does NOT appear in logcat after a successful fingerprint, the break
    // is on the Java side (the native method not resolving); if it DOES appear
    // but the lock stays, the break is the invokeMethod below.
    qDebug() << "[LOCK] JNI onAuthSucceeded fired; client ="
             << (AppLock::client() ? "set" : "NULL");
    ChatClient *c = AppLock::client();
    if (!c)
        return;
    // Marshal onto the Qt/GUI thread: the callback arrives on an Android
    // binder/UI thread, and touching QObject state must happen on the thread
    // that owns it. invokeMethod returns false if the method is not found in the
    // meta-object (the bug that was fixed by making onBiometricSucceeded
    // Q_INVOKABLE); we log that so any regression is immediately visible.
    const bool queued = QMetaObject::invokeMethod(
        c, "onBiometricSucceeded", Qt::QueuedConnection);
    // DIAGNOSTIC (temporary): false here means the method name did not resolve.
    qDebug() << "[LOCK] invokeMethod(onBiometricSucceeded) queued =" << queued;
}

// Set/clear FLAG_SECURE on the activity window so backgrounded content is not
// shown in the recent-apps preview (and screenshots are blocked) while the lock
// is enabled. BiometricHelper.setSecure marshals onto the Android UI thread.
void AppLock::setSecure(bool secure)
{
    QJniObject activity = QNativeInterface::QAndroidApplication::context();
    if (!activity.isValid()) {
        qWarning() << "[LOCK] no Android activity; cannot set FLAG_SECURE";
        return;
    }
    QJniObject::callStaticMethod<void>(
        kBiometricHelper, "setSecure",
        "(Landroid/app/Activity;Z)V",
        activity.object(), static_cast<jboolean>(secure));
    qDebug() << "[LOCK] FLAG_SECURE set to" << secure;
}

// ---- Login vault (Android: Keystore + BiometricPrompt.CryptoObject) --------
// The wrapping/unwrapping lives in Java (BiometricHelper) because the AES-GCM
// key must live in the Android Keystore and be used only inside a CryptoObject.
// These bridges just marshal the calls; the recovered password comes back via
// the onLoginUnlocked JNI callback below.

bool AppLock::loginAvailable()
{
    // Same probe as the unlock path: a fingerprint OR device credential is
    // usable. The login key itself additionally requires a STRONG biometric or
    // the device credential (enforced by the Keystore); if only a WEAK biometric
    // is present the Keystore encrypt will fail at enroll and we fall back to
    // password login, so a slightly-too-permissive "true" here is safe.
    return biometricAvailable();
}

bool AppLock::hasLoginEnrolled(const QString &nick)
{
    QJniObject activity = QNativeInterface::QAndroidApplication::context();
    if (!activity.isValid())
        return false;
    QJniObject jNick = QJniObject::fromString(nick);
    jboolean ok = QJniObject::callStaticMethod<jboolean>(
        kBiometricHelper, "hasLoginEnrolled",
        "(Landroid/content/Context;Ljava/lang/String;)Z",
        activity.object(), jNick.object());
    return ok == JNI_TRUE;
}

void AppLock::enrollLogin(ChatClient *client, const QString &nick,
                          const QString &password)
{
    if (client)
        s_client = client;
    QJniObject activity = QNativeInterface::QAndroidApplication::context();
    if (!activity.isValid()) {
        qWarning() << "[LOGIN] no Android activity; cannot enroll biometric login";
        return;
    }
    QJniObject jNick = QJniObject::fromString(nick);
    QJniObject jPassword = QJniObject::fromString(password);
    QJniObject jTitle = QJniObject::fromString(
        Localization::instance()->t("lock.bioEnrollTitle"));
    QJniObject jSubtitle = QJniObject::fromString(
        Localization::instance()->t("lock.bioEnrollSubtitle"));
    // BiometricHelper.enrollLogin(Activity, nick, password, title, subtitle):
    // shows a one-time BiometricPrompt to authorise the Keystore encrypt, then
    // stores the wrapped blob. Runs on the UI thread inside the helper.
    QJniObject::callStaticMethod<void>(
        kBiometricHelper, "enrollLogin",
        "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;"
        "Ljava/lang/String;Ljava/lang/String;)V",
        activity.object(), jNick.object(), jPassword.object(),
        jTitle.object(), jSubtitle.object());
    qDebug() << "[LOGIN] biometric login enroll requested for" << nick;
}

void AppLock::loginWithBiometric(ChatClient *client,
                                 const QString &serverUrl,
                                 const QString &nick)
{
    Q_UNUSED(serverUrl);   // ChatClient remembers the server URL itself
    if (client)
        s_client = client;
    s_loginNick = nick;
    QJniObject activity = QNativeInterface::QAndroidApplication::context();
    if (!activity.isValid()) {
        qWarning() << "[LOGIN] no Android activity; cannot show biometric login";
        return;
    }
    QJniObject jNick = QJniObject::fromString(nick);
    QJniObject jTitle = QJniObject::fromString(
        Localization::instance()->t("lock.bioLoginTitle"));
    QJniObject jSubtitle = QJniObject::fromString(
        Localization::instance()->t("lock.bioLoginSubtitle"));
    // BiometricHelper.loginWithBiometric(Activity, nick, title, subtitle): shows
    // the OS prompt (fingerprint OR device PIN), unlocks the Keystore key,
    // decrypts the stored password, and calls onLoginUnlocked(password) on
    // success.
    QJniObject::callStaticMethod<void>(
        kBiometricHelper, "loginWithBiometric",
        "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;"
        "Ljava/lang/String;)V",
        activity.object(), jNick.object(), jTitle.object(), jSubtitle.object());
}

void AppLock::clearLogin(const QString &nick)
{
    QJniObject activity = QNativeInterface::QAndroidApplication::context();
    if (!activity.isValid())
        return;
    QJniObject jNick = QJniObject::fromString(nick);
    QJniObject::callStaticMethod<void>(
        kBiometricHelper, "clearLogin",
        "(Landroid/content/Context;Ljava/lang/String;)V",
        activity.object(), jNick.object());
    qDebug() << "[LOGIN] biometric login cleared for" << nick;
}

// JNI callback: Java calls this when a biometric LOGIN authentication succeeds
// and the stored password has been decrypted. It hops onto the Qt thread and
// hands the recovered password to ChatClient, which runs the normal login().
extern "C" JNIEXPORT void JNICALL
Java_fi_tamk_chate2ee_BiometricHelper_onLoginUnlocked(JNIEnv *env, jobject,
                                                      jstring password)
{
    qDebug() << "[LOGIN] JNI onLoginUnlocked fired; client ="
             << (AppLock::client() ? "set" : "NULL");
    ChatClient *c = AppLock::client();
    if (!c || !password)
        return;
    const char *utf = env->GetStringUTFChars(password, nullptr);
    const QString pw = QString::fromUtf8(utf);
    env->ReleaseStringUTFChars(password, utf);
    // Marshal onto the Qt/GUI thread. onBiometricLoginUnlocked(nick, password)
    // MUST be Q_INVOKABLE for this to resolve (same requirement as
    // onBiometricSucceeded). It uses the server URL ChatClient stashed when
    // biometricLogin() was called.
    const bool queued = QMetaObject::invokeMethod(
        c, "onBiometricLoginUnlocked", Qt::QueuedConnection,
        Q_ARG(QString, s_loginNick), Q_ARG(QString, pw));
    qDebug() << "[LOGIN] invokeMethod(onBiometricLoginUnlocked) queued =" << queued;
}

#else  // ---- non-Android ----------------------------------------------------

// ===========================================================================
//  Windows Hello (EXPERIMENTAL, build-and-test-required)
//
//  This talks to the WinRT UserConsentVerifier API through its ABI DIRECTLY,
//  rather than through the C++/WinRT projection headers (<winrt/...>). Those
//  headers are frequently absent or unusable on a Qt/MinGW toolchain, which is
//  why the previous __has_include(<winrt/...>) guard was always false and the
//  Hello option never appeared. The raw-ABI approach needs only the Windows SDK
//  COM/RoApi headers (roapi.h, inspectable.h, winstring.h) that MinGW-w64 does
//  ship, and it loads the three combase.dll entry points it needs at runtime,
//  so there is nothing extra to link. When even those headers are missing the
//  whole thing compiles to the same safe no-op as before (PIN only), so the
//  build can never break.
//
//  Threading: the WinRT calls run on a detached background thread that
//  initialises its own multithreaded apartment, so the Qt GUI thread is NEVER
//  blocked (the old projection code called .get() on the GUI thread, which
//  would freeze the UI). The window handle is captured on the GUI thread first
//  and passed in. On success we hop back to the ChatClient via a queued
//  invokeMethod, exactly like the Android JNI callback.
// ===========================================================================
#if defined(Q_OS_WIN) && __has_include(<roapi.h>) && \
    __has_include(<inspectable.h>) && __has_include(<winstring.h>)
#define APPLOCK_HAVE_WINDOWS_HELLO 1

#include <windows.h>
#include <wincrypt.h>          // DATA_BLOB + DPAPI (CryptProtectData) prototypes
#include <roapi.h>
#include <inspectable.h>
#include <winstring.h>
#include <unknwn.h>
#include <thread>
#include <string>
#include <QtGlobal>
#include <QGuiApplication>
#include <QWindow>
#include <QSettings>           // stores the DPAPI-wrapped password blob at rest
#include <QByteArray>

namespace {

// ---- WinRT class id and the interface GUIDs we call through -----------------
// The runtime class whose factory/statics we activate.
static const wchar_t *kUcvClass =
    L"Windows.Security.Credentials.UI.UserConsentVerifier";

// IUserConsentVerifierStatics {AF4F3F91-564C-4DDC-B8B5-973447627C65}: the
// activation-factory interface exposing CheckAvailabilityAsync /
// RequestVerificationAsync.
static const GUID IID_IUserConsentVerifierStatics = {
    0xAF4F3F91, 0x564C, 0x4DDC,
    { 0xB8, 0xB5, 0x97, 0x34, 0x47, 0x62, 0x7C, 0x65 } };

// IUserConsentVerifierInterop {39E050C3-4E74-441A-8DC0-B81104DF949C}: lets a
// desktop (Win32) app drive the verification against a specific HWND, which is
// what a Qt window is. This is the desktop-friendly entry point.
static const GUID IID_IUserConsentVerifierInterop = {
    0x39E050C3, 0x4E74, 0x441A,
    { 0x8D, 0xC0, 0xB8, 0x11, 0x04, 0xDF, 0x94, 0x9C } };

// IAsyncOperation<UserConsentVerificationResult>
// {FD596FFD-2318-558F-9DBE-D21DF43764A5} (parameterised-interface GUID).
static const GUID IID_IAsyncOperation_Result = {
    0xFD596FFD, 0x2318, 0x558F,
    { 0x9D, 0xBE, 0xD2, 0x1D, 0xF4, 0x37, 0x64, 0xF5 } };

// IAsyncOperation<UserConsentVerifierAvailability>
// {DDD384F3-D818-5D83-AB4B-32119C28587C}.
static const GUID IID_IAsyncOperation_Availability = {
    0xDDD384F3, 0xD818, 0x5D83,
    { 0xAB, 0x4B, 0x32, 0x11, 0x9C, 0x28, 0x58, 0x7C } };

// IAsyncInfo {00000036-0000-0000-C000-000000000046}: the base of every WinRT
// async operation, giving us Status so we can poll to completion.
static const GUID IID_IAsyncInfo = {
    0x00000036, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

enum AsyncStatus_ { AS_Started = 0, AS_Completed = 1,
                    AS_Canceled = 2, AS_Error = 3 };

// UserConsentVerificationResult::Verified == 0; Availability::Available == 0.
enum { UCV_Verified = 0, UCV_Available = 0 };

// ---- combase.dll entry points, resolved at runtime -------------------------
// Declared as pointers so nothing needs to be link-time resolved; if any is
// missing we simply behave as "Hello unavailable".
typedef HRESULT (WINAPI *PFN_RoInitialize)(int);
typedef HRESULT (WINAPI *PFN_RoGetActivationFactory)(HSTRING, REFIID, void **);
typedef HRESULT (WINAPI *PFN_WindowsCreateString)(const wchar_t *, UINT32, HSTRING *);
typedef HRESULT (WINAPI *PFN_WindowsDeleteString)(HSTRING);

struct ComboApi {
    HMODULE lib = nullptr;
    PFN_RoInitialize RoInitialize = nullptr;
    PFN_RoGetActivationFactory RoGetActivationFactory = nullptr;
    PFN_WindowsCreateString WindowsCreateString = nullptr;
    PFN_WindowsDeleteString WindowsDeleteString = nullptr;
    bool ok() const {
        return lib && RoInitialize && RoGetActivationFactory
            && WindowsCreateString && WindowsDeleteString;
    }
};

static ComboApi loadComboApi()
{
    ComboApi a;
    a.lib = LoadLibraryW(L"combase.dll");
    if (!a.lib)
        return a;
    a.RoInitialize = reinterpret_cast<PFN_RoInitialize>(
        reinterpret_cast<void *>(GetProcAddress(a.lib, "RoInitialize")));
    a.RoGetActivationFactory = reinterpret_cast<PFN_RoGetActivationFactory>(
        reinterpret_cast<void *>(GetProcAddress(a.lib, "RoGetActivationFactory")));
    a.WindowsCreateString = reinterpret_cast<PFN_WindowsCreateString>(
        reinterpret_cast<void *>(GetProcAddress(a.lib, "WindowsCreateString")));
    a.WindowsDeleteString = reinterpret_cast<PFN_WindowsDeleteString>(
        reinterpret_cast<void *>(GetProcAddress(a.lib, "WindowsDeleteString")));
    return a;
}

// Minimal vtable shapes. WinRT interfaces are COM: the first three slots are
// IUnknown (QueryInterface/AddRef/Release), the next three IInspectable
// (GetIids/GetRuntimeClassName/GetTrustLevel), then the interface's own methods
// in declaration order. We only lay out enough slots to reach the calls we use.

struct IInspectableVtbl {
    HRESULT (WINAPI *QueryInterface)(void *, REFIID, void **);
    ULONG   (WINAPI *AddRef)(void *);
    ULONG   (WINAPI *Release)(void *);
    HRESULT (WINAPI *GetIids)(void *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(void *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(void *, int *);
};
struct IInspectableObj { IInspectableVtbl *lpVtbl; };

// IAsyncInfo: IInspectable + get_Id/get_Status/get_ErrorCode/Cancel/Close.
struct IAsyncInfoVtbl {
    IInspectableVtbl base;
    HRESULT (WINAPI *get_Id)(void *, unsigned *);
    HRESULT (WINAPI *get_Status)(void *, int *);
    HRESULT (WINAPI *get_ErrorCode)(void *, HRESULT *);
    HRESULT (WINAPI *Cancel)(void *);
    HRESULT (WINAPI *Close)(void *);
};
struct IAsyncInfoObj { IAsyncInfoVtbl *lpVtbl; };

// IAsyncOperation<T>: IInspectable + put_Completed/get_Completed/GetResults.
// For an enum T, GetResults writes an int.
struct IAsyncOperationVtbl {
    IInspectableVtbl base;
    HRESULT (WINAPI *put_Completed)(void *, void *);
    HRESULT (WINAPI *get_Completed)(void *, void **);
    HRESULT (WINAPI *GetResults)(void *, int *);
};
struct IAsyncOperationObj { IAsyncOperationVtbl *lpVtbl; };

// IUserConsentVerifierStatics: IInspectable + CheckAvailabilityAsync /
// RequestVerificationAsync (both return IAsyncOperation*).
struct IUcvStaticsVtbl {
    IInspectableVtbl base;
    HRESULT (WINAPI *CheckAvailabilityAsync)(void *, void **);
    HRESULT (WINAPI *RequestVerificationAsync)(void *, HSTRING, void **);
};
struct IUcvStaticsObj { IUcvStaticsVtbl *lpVtbl; };

// IUserConsentVerifierInterop: IInspectable +
// RequestVerificationForWindowAsync(HWND, HSTRING, REFIID, void**).
struct IUcvInteropVtbl {
    IInspectableVtbl base;
    HRESULT (WINAPI *RequestVerificationForWindowAsync)(
        void *, HWND, HSTRING, REFIID, void **);
};
struct IUcvInteropObj { IUcvInteropVtbl *lpVtbl; };

static inline void relInsp(void *p) {
    if (p) reinterpret_cast<IInspectableObj *>(p)->lpVtbl->Release(p);
}

// Poll an IAsyncOperation to completion, then read its enum result. Returns
// the int result, or a negative value on any failure. capMs bounds the wait.
static int awaitEnumResult(void *op, const ComboApi &api, int capMs)
{
    Q_UNUSED(api);
    if (!op)
        return -1;
    void *info = nullptr;
    auto *o = reinterpret_cast<IInspectableObj *>(op);
    if (FAILED(o->lpVtbl->QueryInterface(op, IID_IAsyncInfo, &info)) || !info)
        return -1;
    auto *ai = reinterpret_cast<IAsyncInfoObj *>(info);
    int waited = 0;
    for (;;) {
        int status = AS_Started;
        if (FAILED(ai->lpVtbl->get_Status(info, &status))) {
            relInsp(info);
            return -1;
        }
        if (status == AS_Completed)
            break;
        if (status == AS_Error || status == AS_Canceled) {
            relInsp(info);
            return -1;
        }
        if (waited >= capMs) {   // timed out; cancel and give up
            ai->lpVtbl->Cancel(info);
            relInsp(info);
            return -1;
        }
        Sleep(25);
        waited += 25;
    }
    relInsp(info);
    int result = -1;
    auto *ao = reinterpret_cast<IAsyncOperationObj *>(op);
    if (FAILED(ao->lpVtbl->GetResults(op, &result)))
        return -1;
    return result;
}

// Fetch the UserConsentVerifier statics factory. Caller releases it.
static IUcvStaticsObj *getStatics(const ComboApi &api)
{
    HSTRING cls = nullptr;
    if (FAILED(api.WindowsCreateString(
            kUcvClass, (UINT32)wcslen(kUcvClass), &cls)) || !cls)
        return nullptr;
    void *statics = nullptr;
    HRESULT hr = api.RoGetActivationFactory(
        cls, IID_IUserConsentVerifierStatics, &statics);
    api.WindowsDeleteString(cls);
    if (FAILED(hr) || !statics)
        return nullptr;
    return reinterpret_cast<IUcvStaticsObj *>(statics);
}

// True if Windows Hello (or a device credential) is available right now. Runs
// on the CALLING thread but is quick and bounded; used off the GUI thread from
// biometricAvailable() below only after initialising an apartment there.
static bool checkAvailabilityBlocking(const ComboApi &api)
{
    IUcvStaticsObj *st = getStatics(api);
    if (!st)
        return false;
    void *op = nullptr;
    HRESULT hr = st->lpVtbl->CheckAvailabilityAsync(st, &op);
    bool available = false;
    if (SUCCEEDED(hr) && op) {
        const int r = awaitEnumResult(op, api, 2000);
        available = (r == UCV_Available);
        relInsp(op);
    }
    st->lpVtbl->base.Release(st);
    return available;
}

// Run a Windows Hello verification against 'hwnd' with the message 'wtitle',
// synchronously on the CALLING thread (intended to be a detached worker with
// its own MTA), and return true iff the user was verified. This is the SAME
// interop-then-windowless-fallback logic as requestUnlock's Windows path,
// including the interopShown guard that stops Hello firing twice, factored out
// so the biometric-LOGIN path can reuse it WITHOUT touching the proven unlock
// path. The caller owns RoInitialize on this thread.
static bool runHelloVerification(HWND hwnd, const std::wstring &wtitle,
                                 const ComboApi &api)
{
    HSTRING msg = nullptr;
    if (FAILED(api.WindowsCreateString(
            wtitle.c_str(), (UINT32)wtitle.size(), &msg)))
        return false;

    int verified = -1;
    bool interopShown = false;   // see requestUnlock for the full rationale

    HSTRING cls = nullptr;
    if (SUCCEEDED(api.WindowsCreateString(
            kUcvClass, (UINT32)wcslen(kUcvClass), &cls)) && cls) {
        void *interop = nullptr;
        HRESULT hr = api.RoGetActivationFactory(
            cls, IID_IUserConsentVerifierInterop, &interop);
        api.WindowsDeleteString(cls);
        if (SUCCEEDED(hr) && interop) {
            auto *io = reinterpret_cast<IUcvInteropObj *>(interop);
            void *op = nullptr;
            hr = io->lpVtbl->RequestVerificationForWindowAsync(
                interop, hwnd, msg, IID_IAsyncOperation_Result, &op);
            if (SUCCEEDED(hr) && op) {
                interopShown = true;   // outcome is now final; never re-prompt
                verified = awaitEnumResult(op, api, 120000);
                relInsp(op);
            }
            io->lpVtbl->base.Release(interop);
        }
    }

    if (!interopShown) {
        IUcvStaticsObj *st = getStatics(api);
        if (st) {
            void *op = nullptr;
            HRESULT hr = st->lpVtbl->RequestVerificationAsync(st, msg, &op);
            if (SUCCEEDED(hr) && op) {
                verified = awaitEnumResult(op, api, 120000);
                relInsp(op);
            }
            st->lpVtbl->base.Release(st);
        }
    }

    api.WindowsDeleteString(msg);
    return verified == UCV_Verified;
}

// ---- DPAPI wrap/unwrap (login vault at rest) -------------------------------
// CryptProtectData ties the ciphertext to the current Windows USER account, so
// a blob copied to another account or machine cannot be unwrapped. crypt32.dll
// is loaded at runtime (like combase) so nothing new needs linking; if it is
// unavailable both helpers return empty and biometric login simply never works
// on that machine. CRYPTPROTECT_UI_FORBIDDEN keeps DPAPI from ever showing UI
// (the Hello prompt is the only prompt the user should see).

typedef BOOL (WINAPI *PFN_CryptProtectData)(
    DATA_BLOB *, LPCWSTR, DATA_BLOB *, PVOID, void *, DWORD, DATA_BLOB *);
typedef BOOL (WINAPI *PFN_CryptUnprotectData)(
    DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, void *, DWORD, DATA_BLOB *);

struct Crypt32Api {
    HMODULE lib = nullptr;
    PFN_CryptProtectData CryptProtectData = nullptr;
    PFN_CryptUnprotectData CryptUnprotectData = nullptr;
    bool ok() const { return lib && CryptProtectData && CryptUnprotectData; }
};

static Crypt32Api loadCrypt32()
{
    Crypt32Api a;
    a.lib = LoadLibraryW(L"crypt32.dll");
    if (!a.lib)
        return a;
    a.CryptProtectData = reinterpret_cast<PFN_CryptProtectData>(
        reinterpret_cast<void *>(GetProcAddress(a.lib, "CryptProtectData")));
    a.CryptUnprotectData = reinterpret_cast<PFN_CryptUnprotectData>(
        reinterpret_cast<void *>(GetProcAddress(a.lib, "CryptUnprotectData")));
    return a;
}

static QByteArray dpapiWrap(const QByteArray &plain)
{
    Crypt32Api api = loadCrypt32();
    if (!api.ok())
        return QByteArray();
    DATA_BLOB in{};
    in.cbData = (DWORD)plain.size();
    in.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(plain.constData()));
    DATA_BLOB out{};
    QByteArray result;
    if (api.CryptProtectData(&in, L"chate2ee-login", nullptr, nullptr, nullptr,
                             CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        result = QByteArray(reinterpret_cast<const char *>(out.pbData),
                            (int)out.cbData);
        if (out.pbData)
            LocalFree(out.pbData);
    }
    return result;
}

static QByteArray dpapiUnwrap(const QByteArray &blob)
{
    Crypt32Api api = loadCrypt32();
    if (!api.ok() || blob.isEmpty())
        return QByteArray();
    DATA_BLOB in{};
    in.cbData = (DWORD)blob.size();
    in.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(blob.constData()));
    DATA_BLOB out{};
    QByteArray result;
    if (api.CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                               CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        result = QByteArray(reinterpret_cast<const char *>(out.pbData),
                            (int)out.cbData);
        if (out.pbData) {
            SecureZeroMemory(out.pbData, out.cbData);   // scrub the plaintext
            LocalFree(out.pbData);
        }
    }
    return result;
}

// QSettings keys for the wrapped password blob and the enrolled flag, per nick.
static QString vaultBlobKey(const QString &nick)
{ return QStringLiteral("biologin/") + nick + QStringLiteral("/blob"); }
static QString vaultOnKey(const QString &nick)
{ return QStringLiteral("biologin/") + nick + QStringLiteral("/on"); }

} // namespace
#endif // Q_OS_WIN && raw WinRT headers present

bool AppLock::biometricAvailable()
{
#ifdef APPLOCK_HAVE_WINDOWS_HELLO
    // Cache the (stable) answer after the first successful query so QML can bind
    // to it cheaply. A negative cache is not kept, so a machine that gains a
    // credential later will start offering Hello without a restart.
    static int cached = -1;   // -1 unknown, 0 no, 1 yes
    if (cached == 1)
        return true;
    ComboApi api = loadComboApi();
    if (!api.ok())
        return false;
    bool result = false;
    // Do the WinRT work on a short-lived thread with its own MTA so we never
    // touch the GUI thread's apartment state.
    std::thread t([&]() {
        api.RoInitialize(1 /* RO_INIT_MULTITHREADED */);
        result = checkAvailabilityBlocking(api);
    });
    t.join();
    if (result)
        cached = 1;
    return result;
#else
    return false;
#endif
}

void AppLock::requestUnlock(ChatClient *client)
{
    if (client)
        s_client = client;
    requestUnlock(Localization::instance()->t("lock.biometricTitle"),
                  Localization::instance()->t("lock.biometricSubtitle"));
}

void AppLock::requestUnlock(const QString &title, const QString &subtitle)
{
    Q_UNUSED(subtitle);
#ifdef APPLOCK_HAVE_WINDOWS_HELLO
    // Capture the top-level window handle on the GUI thread FIRST (touching
    // QWindow off the GUI thread is not allowed). The interop API verifies
    // against this HWND so the Hello dialog is correctly parented and modal.
    HWND hwnd = nullptr;
    const auto windows = QGuiApplication::topLevelWindows();
    for (QWindow *w : windows) {
        if (w && w->isVisible()) {
            hwnd = reinterpret_cast<HWND>(w->winId());
            break;
        }
    }
    if (!hwnd)
        hwnd = GetForegroundWindow();

    const std::wstring wtitle = title.toStdWString();

    // Run the prompt on a detached thread so the GUI thread keeps painting. On
    // success we marshal back to ChatClient via a queued invocation, exactly
    // like the Android JNI callback path.
    std::thread([hwnd, wtitle]() {
        ComboApi api = loadComboApi();
        if (!api.ok())
            return;
        api.RoInitialize(1 /* RO_INIT_MULTITHREADED */);

        HSTRING msg = nullptr;
        if (FAILED(api.WindowsCreateString(
                wtitle.c_str(), (UINT32)wtitle.size(), &msg)))
            return;

        int verified = -1;

        // Did we actually START an interop prompt (a Hello dialog is now on
        // screen)? This is the gate for the fallback below. It is deliberately
        // NOT the same test as "verified < 0": the interop path can show its
        // prompt and STILL come back with a negative code (a transient WinRT
        // error, an AS_Error status, or a GetResults hiccup on the hand-rolled
        // ABI) even after the user has seen -- and answered -- the dialog. If we
        // fell back on "verified < 0" in that case, we would pop Windows Hello a
        // SECOND time for a single click. So once an interop prompt has been
        // shown, its outcome (verified / cancelled / error) is FINAL and we
        // never show another prompt; the windowless fallback runs ONLY when the
        // interop prompt was never started at all (older Windows, or the interop
        // factory could not be obtained). Fix for "Windows Hello fires twice".
        bool interopShown = false;

        // Prefer the desktop interop (verify against our HWND). Fall back to the
        // statics' windowless RequestVerificationAsync ONLY if the interop prompt
        // could not be shown -- see interopShown above.
        HSTRING cls = nullptr;
        if (SUCCEEDED(api.WindowsCreateString(
                kUcvClass, (UINT32)wcslen(kUcvClass), &cls)) && cls) {
            void *interop = nullptr;
            HRESULT hr = api.RoGetActivationFactory(
                cls, IID_IUserConsentVerifierInterop, &interop);
            api.WindowsDeleteString(cls);
            if (SUCCEEDED(hr) && interop) {
                auto *io = reinterpret_cast<IUcvInteropObj *>(interop);
                void *op = nullptr;
                hr = io->lpVtbl->RequestVerificationForWindowAsync(
                    interop, hwnd, msg, IID_IAsyncOperation_Result, &op);
                if (SUCCEEDED(hr) && op) {
                    // A prompt is now on screen; whatever it returns is final.
                    interopShown = true;
                    verified = awaitEnumResult(op, api, 120000);
                    relInsp(op);
                }
                io->lpVtbl->base.Release(interop);
            }
        }

        if (!interopShown) {
            // Interop prompt was never shown -> safe to show the windowless one.
            // This is a genuine fallback (one prompt total), not a second prompt.
            IUcvStaticsObj *st = getStatics(api);
            if (st) {
                void *op = nullptr;
                HRESULT hr =
                    st->lpVtbl->RequestVerificationAsync(st, msg, &op);
                if (SUCCEEDED(hr) && op) {
                    verified = awaitEnumResult(op, api, 120000);
                    relInsp(op);
                }
                st->lpVtbl->base.Release(st);
            }
        }

        api.WindowsDeleteString(msg);

        if (verified == UCV_Verified) {
            ChatClient *c = AppLock::client();
            if (c)
                QMetaObject::invokeMethod(c, "onBiometricSucceeded",
                                          Qt::QueuedConnection);
        } else {
            qWarning() << "[LOCK] Windows Hello not verified (result ="
                       << verified << "); PIN remains available.";
        }
    }).detach();
#else
    Q_UNUSED(title);
    // No biometric backend on this platform: nothing to do. The PIN entry in
    // the lock screen remains the way in.
    qDebug() << "[LOCK] biometric unlock requested but unavailable on this "
                "platform; PIN only.";
#endif
}

// Desktop has no task-switcher preview to blank, so this is a pure no-op. Kept
// so ChatClient can call AppLock::setSecure() unconditionally on any platform.
void AppLock::setSecure(bool /*secure*/) { }

// ---- Login vault (Windows: DPAPI-wrapped password gated by Windows Hello) ---
// Real implementation only where the raw WinRT headers were present (so a Hello
// gate actually exists); otherwise every method is the same safe no-op as the
// unlock path, and loginAvailable() is false so the UI never offers it.

bool AppLock::loginAvailable()
{
#ifdef APPLOCK_HAVE_WINDOWS_HELLO
    // Offer biometric login exactly when Windows Hello is usable.
    return biometricAvailable();
#else
    return false;
#endif
}

bool AppLock::hasLoginEnrolled(const QString &nick)
{
#ifdef APPLOCK_HAVE_WINDOWS_HELLO
    QSettings settings;
    const bool on = settings.value(vaultOnKey(nick), false).toBool();
    const int blobSize = settings.value(vaultBlobKey(nick)).toByteArray().size();
    // DIAGNOSTIC (temporary): shows exactly what the login screen sees when it
    // decides whether to offer the Hello button. If this reports on=false /
    // blob=0 for the nick you enrolled, the enrol write never persisted (check
    // for a "[LOGIN] Windows Hello login enrolled" line on the PREVIOUS run);
    // if it reports on=true / blob>0 but the button still does not show,
    // biometricLoginAvailable is false (Hello not detected).
    qDebug() << "[LOGIN] hasLoginEnrolled(" << nick << ") on =" << on
             << "blob =" << blobSize;
    return on && blobSize > 0;
#else
    Q_UNUSED(nick);
    return false;
#endif
}

void AppLock::enrollLogin(ChatClient *client, const QString &nick,
                          const QString &password)
{
    if (client)
        s_client = client;
#ifdef APPLOCK_HAVE_WINDOWS_HELLO
    // The password was just verified by a successful login, so no Hello prompt
    // is needed here -- we simply wrap it with DPAPI (bound to this Windows
    // user) and store it. The Hello gate is applied at LOGIN time, in
    // loginWithBiometric below.
    const QByteArray wrapped = dpapiWrap(password.toUtf8());
    if (wrapped.isEmpty()) {
        // DIAGNOSTIC (temporary): DPAPI could not wrap the password. If you see
        // this, crypt32.dll / CryptProtectData did not resolve or failed; the
        // vault is not written and the Hello button will not appear next time.
        qWarning() << "[LOGIN] DPAPI wrap failed; biometric login not enrolled";
        return;
    }
    QSettings settings;
    settings.setValue(vaultBlobKey(nick), wrapped);
    settings.setValue(vaultOnKey(nick), true);
    settings.sync();   // flush to the registry NOW, before the app can exit
    qDebug() << "[LOGIN] Windows Hello login enrolled for" << nick
             << "(blob =" << wrapped.size() << "bytes, sync ="
             << settings.status() << ")";
#else
    Q_UNUSED(nick);
    Q_UNUSED(password);
#endif
}

void AppLock::loginWithBiometric(ChatClient *client,
                                 const QString &serverUrl,
                                 const QString &nick)
{
    Q_UNUSED(serverUrl);   // ChatClient remembers the server URL itself
    if (client)
        s_client = client;
    s_loginNick = nick;
#ifdef APPLOCK_HAVE_WINDOWS_HELLO
    // Read the wrapped blob on the GUI thread (QSettings), then run the Hello
    // prompt on a detached worker so the UI keeps painting. Only after Hello
    // verifies do we DPAPI-unwrap and hand the password back to ChatClient.
    QSettings settings;
    const QByteArray wrapped = settings.value(vaultBlobKey(nick)).toByteArray();
    if (wrapped.isEmpty()) {
        qWarning() << "[LOGIN] no wrapped password for" << nick
                   << "; biometric login unavailable";
        return;
    }

    // Capture the top-level window handle on the GUI thread FIRST.
    HWND hwnd = nullptr;
    const auto windows = QGuiApplication::topLevelWindows();
    for (QWindow *w : windows) {
        if (w && w->isVisible()) {
            hwnd = reinterpret_cast<HWND>(w->winId());
            break;
        }
    }
    if (!hwnd)
        hwnd = GetForegroundWindow();

    const std::wstring wtitle =
        Localization::instance()->t("lock.bioLoginTitle").toStdWString();
    const QString capturedNick = nick;

    std::thread([hwnd, wtitle, wrapped, capturedNick]() {
        ComboApi api = loadComboApi();
        if (!api.ok())
            return;
        api.RoInitialize(1 /* RO_INIT_MULTITHREADED */);

        if (!runHelloVerification(hwnd, wtitle, api)) {
            qWarning() << "[LOGIN] Windows Hello not verified; password login "
                          "remains available.";
            return;
        }

        // Verified: unwrap the password and run the normal login on the Qt
        // thread. The plaintext lives only for this call and is scrubbed by
        // dpapiUnwrap's SecureZeroMemory on the DPAPI-owned buffer; the QString
        // copy is released when this lambda returns.
        const QByteArray pw = dpapiUnwrap(wrapped);
        if (pw.isEmpty()) {
            qWarning() << "[LOGIN] DPAPI unwrap failed after Hello; "
                          "password login remains available.";
            return;
        }
        ChatClient *c = AppLock::client();
        if (!c)
            return;
        QMetaObject::invokeMethod(
            c, "onBiometricLoginUnlocked", Qt::QueuedConnection,
            Q_ARG(QString, capturedNick),
            Q_ARG(QString, QString::fromUtf8(pw)));
    }).detach();
#else
    Q_UNUSED(nick);
    qDebug() << "[LOGIN] biometric login requested but Hello unavailable; "
                "password login only.";
#endif
}

void AppLock::clearLogin(const QString &nick)
{
#ifdef APPLOCK_HAVE_WINDOWS_HELLO
    QSettings settings;
    settings.remove(vaultBlobKey(nick));
    settings.remove(vaultOnKey(nick));
    qDebug() << "[LOGIN] Windows Hello login cleared for" << nick;
#else
    Q_UNUSED(nick);
#endif
}

#endif  // Q_OS_ANDROID
