#include "localization.h"

#include <QCoreApplication>
#include <QSettings>

// The single app-wide instance. Created by create() (the QML singleton factory)
// and returned to C++ callers by instance(). We keep a file-static pointer so
// ChatClient can localize system strings through the very same object the UI
// uses, guaranteeing they never disagree about the active language.
static Localization *g_instance = nullptr;

Localization::Localization(QObject *parent) : QObject(parent)
{
    buildDictionaries();

    // Restore the persisted language (defaults to English on first run). Stored
    // app-wide (not per-nickname): the chrome language is a device preference,
    // like the OS language, rather than something that should change when you
    // switch accounts on the same phone.
    QSettings settings;
    const int stored = settings.value("ui/language",
                                       static_cast<int>(English)).toInt();
    if (stored >= English && stored <= Swedish)
        m_lang = static_cast<Language>(stored);
}

Localization *Localization::create(QQmlEngine *, QJSEngine *)
{
    // QML owns the singleton's lifetime. Construct once; hand the same pointer
    // to instance() so both worlds share it.
    if (!g_instance)
        g_instance = new Localization();
    // QML takes ownership; ensure it is not garbage-collected from JS.
    QJSEngine::setObjectOwnership(g_instance, QJSEngine::CppOwnership);
    return g_instance;
}

Localization *Localization::instance()
{
    // If C++ asks first (unlikely -- QML instantiates the singleton very early),
    // build it on demand so instance() is never null.
    if (!g_instance)
        g_instance = new Localization();
    return g_instance;
}

void Localization::setLanguage(Language lang)
{
    if (lang == m_lang)
        return;
    m_lang = lang;
    QSettings settings;
    settings.setValue("ui/language", static_cast<int>(lang));
    emit languageChanged();
}

QString Localization::nameOf(Language lang)
{
    // Each language's name IN ITSELF, so the picker reads naturally to a speaker
    // of that language.
    switch (lang) {
    case English: return QStringLiteral("English");
    case Finnish: return QStringLiteral("Suomi");
    case Swedish: return QStringLiteral("Svenska");
    }
    return QStringLiteral("English");
}

const QHash<QString, QString> &Localization::mapFor(Language lang) const
{
    switch (lang) {
    case Finnish: return m_fi;
    case Swedish: return m_sv;
    case English:
    default:      return m_en;
    }
}

QString Localization::t(const QString &key) const
{
    return tIn(m_lang, key);
}

QString Localization::tIn(Language lang, const QString &key) const
{
    const QHash<QString, QString> &m = mapFor(lang);
    auto it = m.find(key);
    if (it != m.end())
        return it.value();
    // Fall back to English, then to the raw key, so a missing translation is
    // visible and never blank.
    auto en = m_en.find(key);
    if (en != m_en.end())
        return en.value();
    return key;
}

void Localization::buildDictionaries()
{
    // ---- English (also the fallback map) -------------------------------
    // Keys are short, stable tokens. Group by area for readability. Any string
    // shown to the user -- menu items, dialog titles/bodies, button labels, AND
    // the system messages emitted from C++ -- has a key here.
    m_en = {
        // Header / connection
        { "online",            "online" },
        { "reconnecting",      "reconnecting\u2026" },
        // Overflow menu
        { "menu.viewSafety",   "View safety number" },
        { "menu.theme",        "Theme\u2026" },
        { "menu.language",     "Language\u2026" },
        { "menu.darkMode",     "Dark mode" },
        { "menu.switchUser",   "Switch user\u2026" },
        { "menu.logout",       "Log out" },
        { "menu.export",       "Export chat\u2026" },
        { "menu.shortcut",     "Add to home screen\u2026" },
        { "menu.logs",         "Diagnostic log\u2026" },
        // Diagnostic log screen (always-on deep probing traces)
        { "log.title",         "Diagnostic log" },
        { "log.lines",         "lines" },
        { "log.empty",         "No log lines captured yet." },
        { "log.copyAll",       "Copy all" },
        { "log.clear",         "Clear" },
        { "log.close",         "Close" },
        // Language picker
        { "lang.title",        "Language" },
        { "lang.hint",         "Choose the app language. Your choice is saved on this device." },
        // Theme picker
        { "theme.title",       "Theme" },
        { "theme.hint",        "Pick a colour theme. Your choice is saved for \"%1\" on this device." },
        // Contact list
        { "contacts.title",    "Contacts" },
        { "contacts.you",      "you" },
        { "contacts.offline",  "offline" },
        { "contacts.typing",   "typing\u2026" },
        { "contacts.sendingFile", "sending a file\u2026" },
        // Conversation
        { "conv.chattingWith", "Chatting with %1" },
        { "conv.isTyping",     "%1 is typing\u2026" },
        { "conv.isSendingFile","%1 is sending a file\u2026" },
        { "conv.pickContact",  "Pick a contact to start a private conversation." },
        { "conv.emptyHint",    "Pick someone to chat with" },
        // Composer
        { "composer.type",     "Type a message\u2026" },
        { "composer.confirmFirst", "Confirm the safety-number change to continue\u2026" },
        { "composer.send",     "Send" },
        { "composer.attachTip","Send a file or image" },
        // Deletion
        { "msg.deleted",       "This message was deleted" },
        { "menu.deleteForMe",  "Delete for me" },
        { "menu.deleteForEveryone", "Delete for everyone" },
        { "menu.reactAgree",    "Agree" },
        { "menu.reactDisagree", "Disagree" },
        { "menu.reactRemove",   "Remove reaction" },
        // Editing / resending
        { "menu.edit",          "Edit" },
        { "menu.resend",        "Resend" },
        { "msg.edited",         "edited" },
        { "edit.title",         "Edit message" },
        { "edit.hint",          "The new text is encrypted and updated on both sides. You need to be online to edit." },
        // Login
        { "login.title",       "Encrypted Chat" },
        { "login.server",      "Server URL" },
        { "login.nickname",    "Nickname" },
        { "login.connect",     "Connect" },
        { "login.connecting",  "Connecting\u2026" },
        // ---- Password auth (feature 1) + app lock (feature 2) ----
        { "login.password",        "Password" },
        { "login.passwordHint",    "Choose a strong password" },
        { "login.passwordHintLogin","Enter your password" },
        { "login.register",        "Register" },
        { "login.login",           "Log in" },
        { "login.haveAccount",     "Already have an account? Log in" },
        { "login.needAccount",     "New here? Register" },
        { "login.pwHelp",          "Your password encrypts your identity key on this device. The server never sees it." },
        // ---- Date of birth + password recovery ------------------------
        // The birthday is collected at REGISTRATION only and is never stored as
        // a date, on the device or on the server: both keep an irreversible
        // Argon2id verifier. Recovery reveals the password held in this
        // device's biometric vault; it cannot retrieve anything from the
        // server, which holds only a hash.
        { "login.birthday",        "Date of birth" },
        { "login.birthdayHint",    "1999-05-03" },
        { "login.birthdayHelp",    "Required to create a new account. Stored only as an irreversible hash, never as a date." },
        { "login.birthdayInvalid", "That date is not valid. Use the form 1999-05-03." },
        { "login.forgot",          "Forgotten password?" },
        { "recover.title",         "Recover your password" },
        { "recover.titleRevealed", "Your password" },
        { "recover.introHello",    "Enter your username and date of birth. You will then be asked to confirm with Windows Hello." },
        { "recover.introBio",      "Enter your username and date of birth. You will then be asked to confirm with your fingerprint or device PIN." },
        { "recover.user",          "Username" },
        { "recover.dobHint",       "Date of birth, e.g. 1999-05-03" },
        { "recover.submit",        "Submit" },
        { "recover.waiting",       "Waiting for authentication\u2026" },
        { "recover.warning",       "Anyone who can see this screen can see your password. Close this as soon as you have noted it down." },
        { "recover.back",          "Return to sign in" },
        { "recover.close",         "Close" },
        // Biometric / Windows Hello LOGIN (feature). Wording is chosen per
        // platform in QML (usesOsCredential -> Android fingerprint/PIN wording;
        // otherwise Windows Hello wording). The lock.bio* strings are the OS
        // prompt title/subtitle passed to Windows Hello and the Android prompt.
        { "login.helloLogin",      "Log in with Windows Hello" },
        { "login.bioLogin",        "Log in with fingerprint or PIN" },
        { "login.enableHello",     "Enable Windows Hello login next time" },
        { "login.enableBio",       "Enable fingerprint / PIN login next time" },
        { "lock.bioLoginTitle",    "Log in to Encrypted Chat" },
        { "lock.bioLoginSubtitle", "Confirm your identity to log in" },
        { "lock.bioEnrollTitle",   "Enable fingerprint login" },
        { "lock.bioEnrollSubtitle","Confirm to save your login for next time" },
        { "err.wrongPassword",     "Incorrect password. Your account was not changed." },
        { "err.noAccountHere",     "No account found on this device for that name. Please Register first." },
        { "err.accountExistsLocally","An account with that name already exists on this device. Please Log in instead." },
        { "err.identityNotPersisted","Your identity could not be saved to persistent storage and may not survive a restart on this device." },
        { "err.identityUnreadable","Could not read your saved identity. Please restart the app; your key was not changed." },
        { "err.registerFailed",    "Registration failed while preparing your credentials. Please try again." },
        { "err.loginRejected",     "The server ended this session (wrong password, reserved username, or signed in on another device). Please log in again." },
        { "err.pinSetFailed",      "Could not set the PIN. Please try again." },
        { "err.noDeviceCredential","No device lock is set up. Please set a screen lock (PIN, pattern, or fingerprint) in your device settings first." },
        { "err.pinRequired",       "A fallback PIN is required. Please enter one." },
        { "err.resetNoAccount",    "No account was found on this device to verify your password against." },
        { "lock.unlockDevice",     "Unlock with device" },
        { "lock.unlockHello",      "Unlock with Windows Hello" },
        { "lock.orEnterPin",       "\u2014 or enter your PIN \u2014" },
        { "lock.forgotPin",        "Forgot PIN?" },
        { "lock.resetTitle",       "Reset lock" },
        { "lock.resetPrompt",      "Enter your account password to reset the app lock." },
        { "settings.enableLock",   "Enable app lock" },
        { "settings.disableLock",  "Disable app lock" },
        { "settings.lockUsesDevice","Unlock uses your device screen lock (fingerprint, face, or PIN)." },
        { "settings.lockUsesHello","Unlock uses Windows Hello, with your app PIN as a fallback." },
        { "settings.lockUsesPin",  "Unlock uses your app PIN." },
        { "err.nameReserved",      "This username is already registered to a different identity. Please choose another name." },
        { "err.badPassword",       "Incorrect password for this username." },
        { "lock.title",            "Locked" },
        { "lock.enterPin",         "Enter PIN" },
        { "lock.wrongPin",         "Wrong PIN, try again" },
        { "lock.unlock",           "Unlock" },
        { "lock.useFingerprint",   "Use fingerprint" },
        { "lock.biometricTitle",   "Unlock Encrypted Chat" },
        { "lock.biometricSubtitle","Confirm your identity to continue" },
        { "settings.appLock",      "App lock (PIN)" },
        { "settings.setPin",       "Set / change PIN" },
        { "settings.removePin",    "Remove PIN" },
        { "settings.pinOn",        "PIN lock is on" },
        { "settings.pinOff",       "PIN lock is off" },
        { "settings.newPin",       "New PIN" },
        { "settings.confirmPin",   "Confirm PIN" },
        { "settings.currentPin",   "Current PIN" },
        { "settings.wrongCurrentPin","Current PIN is incorrect" },
        { "settings.pinMismatch",  "PINs do not match" },
        { "settings.lockNow",      "Lock now" },
        { "common.cancel",         "Cancel" },
        { "common.save",           "Save" },
        // Logout / switch confirmations
        { "logout.title",      "Log out?" },
        { "logout.body",       "You'll return to the login screen. Your identity and message history stay on this device, so logging back in as \"%1\" restores everything." },
        { "switch.title",      "Switch user?" },
        { "switch.body",       "This returns to the login screen so someone else can sign in under their own name. \"%1\"'s identity and messages stay saved on this device, so you can switch back later and everything will be here." },
        // Safety number dialog / banner
        { "safety.titlePeer",  "Safety number with %1" },
        { "safety.titleSelf",  "Your safety number" },
        { "safety.comparePeer","Compare these numbers with %1 over a call or in person.\nIf they match on both devices, no one is intercepting your keys." },
        { "safety.selectHint", "Select a contact to see the safety number you share with them." },
        { "safety.bannerTitle","\u26A0\uFE0F %1 may be a different person or device" },
        { "safety.bannerBody", "%1's safety number changed. This happens when they reinstall, switch device, or a different person takes over this name -- but it can also mean someone is intercepting your messages. Compare the new safety number with %1 over a call or in person, then confirm the switch to continue. You cannot send messages until you do." },
        { "safety.view",       "View safety number" },
        { "safety.confirm",    "I've verified \u2014 confirm & switch" },
        // Export
        { "export.title",      "Export conversation with %1" },
        { "export.pdf",        "PDF document (*.pdf)" },
        { "export.txt",        "Text file (*.txt)" },
        { "export.done",       "Saved conversation with %1 to %2" },
        { "export.saved",      "Conversation with %1 saved." },
        { "export.empty",      "There are no messages with %1 to export yet." },
        { "export.failed",     "Could not save the export: %1" },
        { "export.headerTitle","Conversation with %1" },
        { "export.headerExported", "Exported %1" },
        { "export.headerParticipants", "Participants: %1 and %2" },
        { "export.sentFile",   "sent a file: %1 (%2)" },
        { "export.systemLabel","(system)" },
        // Notifications (shown in the Android status bar; localized too)
        { "notif.newMessageTitle", "New message from %1" },
        { "notif.newFileTitle",    "New file from %1" },
        { "notif.newFileBody",     "%1 (%2)" },
        { "notif.channelName",     "Messages" },
        { "notif.serviceRunning",  "Encrypted Chat is running" },
        { "notif.serviceBody",     "Connected \u2014 you'll be notified of new messages." },
        { "shortcut.unsupported",  "A home-screen shortcut could not be created on this device." },
        // System messages emitted by ChatClient
        { "sys.cannotDecrypt", "\U0001F512 An earlier message can no longer be decrypted (it was stored under a previous identity key)." },
        { "sys.historyOpenFailed", "History could not be opened; messages will not be saved this session." },
        { "sys.noStorage",     "No writable storage location was found; message history is disabled this session." },
        { "err.historyOpenFailed", "Local history could not be opened; your messages will not be stored on this device." },
        { "sys.fileFailed",    "File transfer failed: %1" },
        { "sys.reason.startDecrypt", "could not start decryption" },
        { "sys.reason.openTemp",     "could not open temp file" },
    };

    // ---- Finnish (suomi) ------------------------------------------------
    m_fi = {
        { "online",            "verkossa" },
        { "reconnecting",      "yhdist\u00e4t\u00e4\u00e4n uudelleen\u2026" },
        { "menu.viewSafety",   "N\u00e4yt\u00e4 turvanumero" },
        { "menu.theme",        "Teema\u2026" },
        { "menu.language",     "Kieli\u2026" },
        { "menu.darkMode",     "Tumma tila" },
        { "menu.switchUser",   "Vaihda k\u00e4ytt\u00e4j\u00e4\u00e4\u2026" },
        { "menu.logout",       "Kirjaudu ulos" },
        { "menu.export",       "Vie keskustelu\u2026" },
        { "menu.shortcut",     "Lis\u00e4\u00e4 aloitusn\u00e4ytt\u00f6\u00f6n\u2026" },
        { "menu.logs",         "Diagnostiikkaloki\u2026" },
        // Diagnostic log screen (always-on deep probing traces)
        { "log.title",         "Diagnostiikkaloki" },
        { "log.lines",         "rivi\u00e4" },
        { "log.empty",         "Ei viel\u00e4 lokirivej\u00e4." },
        { "log.copyAll",       "Kopioi kaikki" },
        { "log.clear",         "Tyhjenn\u00e4" },
        { "log.close",         "Sulje" },
        { "lang.title",        "Kieli" },
        { "lang.hint",         "Valitse sovelluksen kieli. Valintasi tallennetaan t\u00e4h\u00e4n laitteeseen." },
        { "theme.title",       "Teema" },
        { "theme.hint",        "Valitse v\u00e4riteema. Valintasi tallennetaan k\u00e4ytt\u00e4j\u00e4lle \"%1\" t\u00e4h\u00e4n laitteeseen." },
        { "contacts.title",    "Yhteystiedot" },
        { "contacts.you",      "sin\u00e4" },
        { "contacts.offline",  "poissa verkosta" },
        { "contacts.typing",   "kirjoittaa\u2026" },
        { "contacts.sendingFile", "l\u00e4hett\u00e4\u00e4 tiedostoa\u2026" },
        { "conv.chattingWith", "Keskustelu k\u00e4ytt\u00e4j\u00e4n %1 kanssa" },
        { "conv.isTyping",     "%1 kirjoittaa\u2026" },
        { "conv.isSendingFile","%1 l\u00e4hett\u00e4\u00e4 tiedostoa\u2026" },
        { "conv.pickContact",  "Aloita yksityinen keskustelu valitsemalla yhteystieto." },
        { "conv.emptyHint",    "Valitse kenen kanssa keskustelet" },
        { "composer.type",     "Kirjoita viesti\u2026" },
        { "composer.confirmFirst", "Vahvista turvanumeron muutos jatkaaksesi\u2026" },
        { "composer.send",     "L\u00e4het\u00e4" },
        { "composer.attachTip","L\u00e4het\u00e4 tiedosto tai kuva" },
        { "msg.deleted",       "T\u00e4m\u00e4 viesti poistettiin" },
        { "menu.deleteForMe",  "Poista minulta" },
        { "menu.deleteForEveryone", "Poista kaikilta" },
        { "menu.reactAgree",    "Samaa mielt\u00e4" },
        { "menu.reactDisagree", "Eri mielt\u00e4" },
        { "menu.reactRemove",   "Poista reaktio" },
        // Editing / resending
        { "menu.edit",          "Muokkaa" },
        { "menu.resend",        "L\u00e4het\u00e4 uudelleen" },
        { "msg.edited",         "muokattu" },
        { "edit.title",         "Muokkaa viesti\u00e4" },
        { "edit.hint",          "Uusi teksti salataan ja p\u00e4ivitet\u00e4\u00e4n molemmille osapuolille. Muokkaaminen edellytt\u00e4\u00e4 verkkoyhteytt\u00e4." },
        { "login.title",       "Salattu keskustelu" },
        { "login.server",      "Palvelimen osoite" },
        { "login.nickname",    "Nimimerkki" },
        { "login.connect",     "Yhdist\u00e4" },
        { "login.connecting",  "Yhdistet\u00e4\u00e4n\u2026" },
        // ---- Password auth (feature 1) + app lock (feature 2) ----
        { "login.password",        "Salasana" },
        { "login.passwordHint",    "Valitse vahva salasana" },
        { "login.passwordHintLogin","Sy\u00f6t\u00e4 salasanasi" },
        { "login.register",        "Rekister\u00f6idy" },
        { "login.login",           "Kirjaudu" },
        { "login.haveAccount",     "Onko sinulla jo tili? Kirjaudu" },
        { "login.needAccount",     "Uusi t\u00e4\u00e4ll\u00e4? Rekister\u00f6idy" },
        { "login.pwHelp",          "Salasanasi salaa henkil\u00f6llisyysavaimesi t\u00e4ll\u00e4 laitteella. Palvelin ei koskaan n\u00e4e sit\u00e4." },
        // ---- Syntym\u00e4aika + salasanan palautus ------------------------
        { "login.birthday",        "Syntym\u00e4aika" },
        { "login.birthdayHint",    "1999-05-03" },
        { "login.birthdayHelp",    "Vaaditaan uuden tilin luomiseen. Tallennetaan vain peruuttamattomana tiivisteen\u00e4, ei koskaan p\u00e4iv\u00e4m\u00e4\u00e4r\u00e4n\u00e4." },
        { "login.birthdayInvalid", "P\u00e4iv\u00e4m\u00e4\u00e4r\u00e4 ei kelpaa. K\u00e4yt\u00e4 muotoa 1999-05-03." },
        { "login.forgot",          "Unohtuiko salasana?" },
        { "recover.title",         "Palauta salasanasi" },
        { "recover.titleRevealed", "Salasanasi" },
        { "recover.introHello",    "Anna k\u00e4ytt\u00e4j\u00e4tunnuksesi ja syntym\u00e4aikasi. Sinua pyydet\u00e4\u00e4n sitten vahvistamaan Windows Hellolla." },
        { "recover.introBio",      "Anna k\u00e4ytt\u00e4j\u00e4tunnuksesi ja syntym\u00e4aikasi. Sinua pyydet\u00e4\u00e4n sitten vahvistamaan sormenj\u00e4ljell\u00e4 tai laitteen PIN-koodilla." },
        { "recover.user",          "K\u00e4ytt\u00e4j\u00e4tunnus" },
        { "recover.dobHint",       "Syntym\u00e4aika, esim. 1999-05-03" },
        { "recover.submit",        "L\u00e4het\u00e4" },
        { "recover.waiting",       "Odotetaan tunnistautumista\u2026" },
        { "recover.warning",       "Kuka tahansa, joka n\u00e4kee t\u00e4m\u00e4n ruudun, n\u00e4kee salasanasi. Sulje heti kun olet kirjannut sen yl\u00f6s." },
        { "recover.back",          "Takaisin kirjautumiseen" },
        { "recover.close",         "Sulje" },
        // Biometric / Windows Hello LOGIN (feature).
        { "login.helloLogin",      "Kirjaudu Windows Hellolla" },
        { "login.bioLogin",        "Kirjaudu sormenj\u00e4ljell\u00e4 tai PIN-koodilla" },
        { "login.enableHello",     "Ota Windows Hello -kirjautuminen k\u00e4ytt\u00f6\u00f6n ensi kerralla" },
        { "login.enableBio",       "Ota sormenj\u00e4lki- tai PIN-kirjautuminen k\u00e4ytt\u00f6\u00f6n ensi kerralla" },
        { "lock.bioLoginTitle",    "Kirjaudu salattuun keskusteluun" },
        { "lock.bioLoginSubtitle", "Vahvista henkil\u00f6llisyytesi kirjautuaksesi" },
        { "lock.bioEnrollTitle",   "Ota sormenj\u00e4lkikirjautuminen k\u00e4ytt\u00f6\u00f6n" },
        { "lock.bioEnrollSubtitle","Vahvista tallentaaksesi kirjautumisen ensi kertaa varten" },
        { "err.wrongPassword",     "V\u00e4\u00e4r\u00e4 salasana. Tili\u00e4si ei muutettu." },
        { "err.noAccountHere",     "T\u00e4lt\u00e4 laitteelta ei l\u00f6ytynyt tili\u00e4 t\u00e4ll\u00e4 nimell\u00e4. Rekister\u00f6idy ensin." },
        { "err.accountExistsLocally","T\u00e4ll\u00e4 nimell\u00e4 on jo tili t\u00e4ll\u00e4 laitteella. Kirjaudu sen sijaan sis\u00e4\u00e4n." },
        { "err.identityNotPersisted","Henkil\u00f6llisyytt\u00e4si ei voitu tallentaa pysyv\u00e4\u00e4n muistiin, eik\u00e4 se v\u00e4ltt\u00e4m\u00e4tt\u00e4 s\u00e4ily uudelleenk\u00e4ynnistyksess\u00e4 t\u00e4ll\u00e4 laitteella." },
        { "err.identityUnreadable","Tallennettua henkil\u00f6llisyytt\u00e4 ei voitu lukea. K\u00e4ynnist\u00e4 sovellus uudelleen; avaintasi ei muutettu." },
        { "err.registerFailed",    "Rekister\u00f6inti ep\u00e4onnistui tunnistetietoja valmisteltaessa. Yrit\u00e4 uudelleen." },
        { "err.loginRejected",     "Palvelin p\u00e4\u00e4tti istunnon (v\u00e4\u00e4r\u00e4 salasana, varattu k\u00e4ytt\u00e4j\u00e4nimi tai kirjautuminen toisella laitteella). Kirjaudu uudelleen." },
        { "err.pinSetFailed",      "PIN-koodia ei voitu asettaa. Yrit\u00e4 uudelleen." },
        { "err.noDeviceCredential","Laitteen lukitusta ei ole m\u00e4\u00e4ritetty. Aseta ensin n\u00e4yt\u00f6n lukitus (PIN, kuvio tai sormenj\u00e4lki) laitteen asetuksissa." },
        { "err.pinRequired",       "Vara-PIN vaaditaan. Sy\u00f6t\u00e4 PIN-koodi." },
        { "err.resetNoAccount",    "T\u00e4lt\u00e4 laitteelta ei l\u00f6ytynyt tili\u00e4, jota vastaan salasana voitaisiin varmentaa." },
        { "lock.unlockDevice",     "Avaa laitteella" },
        { "lock.unlockHello",      "Avaa Windows Hellolla" },
        { "lock.orEnterPin",       "\u2014 tai sy\u00f6t\u00e4 PIN \u2014" },
        { "lock.forgotPin",        "Unohditko PINin?" },
        { "lock.resetTitle",       "Nollaa lukitus" },
        { "lock.resetPrompt",      "Sy\u00f6t\u00e4 tilisi salasana nollataksesi sovelluslukon." },
        { "settings.enableLock",   "Ota sovelluslukko k\u00e4ytt\u00f6\u00f6n" },
        { "settings.disableLock",  "Poista sovelluslukko k\u00e4yt\u00f6st\u00e4" },
        { "settings.lockUsesDevice","Avaus k\u00e4ytt\u00e4\u00e4 laitteesi n\u00e4yt\u00f6nlukitusta (sormenj\u00e4lki, kasvot tai PIN)." },
        { "settings.lockUsesHello","Avaus k\u00e4ytt\u00e4\u00e4 Windows Helloa, ja sovelluksen PIN toimii varana." },
        { "settings.lockUsesPin",  "Avaus k\u00e4ytt\u00e4\u00e4 sovelluksen PIN-koodia." },
        { "err.nameReserved",      "T\u00e4m\u00e4 k\u00e4ytt\u00e4j\u00e4nimi on jo rekister\u00f6ity toiselle henkil\u00f6llisyydelle. Valitse toinen nimi." },
        { "err.badPassword",       "V\u00e4\u00e4r\u00e4 salasana t\u00e4lle k\u00e4ytt\u00e4j\u00e4nimelle." },
        { "lock.title",            "Lukittu" },
        { "lock.enterPin",         "Sy\u00f6t\u00e4 PIN" },
        { "lock.wrongPin",         "V\u00e4\u00e4r\u00e4 PIN, yrit\u00e4 uudelleen" },
        { "lock.unlock",           "Avaa lukitus" },
        { "lock.useFingerprint",   "K\u00e4yt\u00e4 sormenj\u00e4lke\u00e4" },
        { "lock.biometricTitle",   "Avaa Salattu keskustelu" },
        { "lock.biometricSubtitle","Vahvista henkil\u00f6llisyytesi jatkaaksesi" },
        { "settings.appLock",      "Sovelluslukko (PIN)" },
        { "settings.setPin",       "Aseta / vaihda PIN" },
        { "settings.removePin",    "Poista PIN" },
        { "settings.pinOn",        "PIN-lukko on p\u00e4\u00e4ll\u00e4" },
        { "settings.pinOff",       "PIN-lukko on pois p\u00e4\u00e4lt\u00e4" },
        { "settings.newPin",       "Uusi PIN" },
        { "settings.confirmPin",   "Vahvista PIN" },
        { "settings.currentPin",   "Nykyinen PIN" },
        { "settings.wrongCurrentPin","Nykyinen PIN on virheellinen" },
        { "settings.pinMismatch",  "PIN-koodit eiv\u00e4t t\u00e4sm\u00e4\u00e4" },
        { "settings.lockNow",      "Lukitse nyt" },
        { "common.cancel",         "Peruuta" },
        { "common.save",           "Tallenna" },
        { "logout.title",      "Kirjaudutaanko ulos?" },
        { "logout.body",       "Palaat kirjautumisruutuun. Henkil\u00f6llisyytesi ja viestihistoriasi s\u00e4ilyv\u00e4t t\u00e4ss\u00e4 laitteessa, joten kirjautumalla takaisin nimell\u00e4 \"%1\" saat kaiken takaisin." },
        { "switch.title",      "Vaihdetaanko k\u00e4ytt\u00e4j\u00e4\u00e4?" },
        { "switch.body",       "T\u00e4m\u00e4 palaa kirjautumisruutuun, jotta joku toinen voi kirjautua omalla nimell\u00e4\u00e4n. K\u00e4ytt\u00e4j\u00e4n \"%1\" henkil\u00f6llisyys ja viestit s\u00e4ilyv\u00e4t t\u00e4ss\u00e4 laitteessa, joten voit vaihtaa takaisin my\u00f6hemmin." },
        { "safety.titlePeer",  "Turvanumero k\u00e4ytt\u00e4j\u00e4n %1 kanssa" },
        { "safety.titleSelf",  "Oma turvanumerosi" },
        { "safety.comparePeer","Vertaa n\u00e4it\u00e4 numeroita k\u00e4ytt\u00e4j\u00e4n %1 kanssa puhelimitse tai kasvotusten.\nJos ne t\u00e4sm\u00e4\u00e4v\u00e4t molemmissa laitteissa, kukaan ei sieppaa avaimiasi." },
        { "safety.selectHint", "Valitse yhteystieto n\u00e4hd\u00e4ksesi h\u00e4nen kanssaan jaetun turvanumeron." },
        { "safety.bannerTitle","\u26A0\uFE0F %1 voi olla eri henkil\u00f6 tai laite" },
        { "safety.bannerBody", "K\u00e4ytt\u00e4j\u00e4n %1 turvanumero muuttui. N\u00e4in tapahtuu, kun h\u00e4n asentaa sovelluksen uudelleen, vaihtaa laitetta tai joku toinen ottaa t\u00e4m\u00e4n nimen -- mutta se voi my\u00f6s tarkoittaa, ett\u00e4 joku sieppaa viestej\u00e4si. Vertaa uutta turvanumeroa k\u00e4ytt\u00e4j\u00e4n %1 kanssa puhelimitse tai kasvotusten ja vahvista sitten jatkaaksesi. Et voi l\u00e4hett\u00e4\u00e4 viestej\u00e4 ennen sit\u00e4." },
        { "safety.view",       "N\u00e4yt\u00e4 turvanumero" },
        { "safety.confirm",    "Olen vahvistanut \u2014 vahvista ja vaihda" },
        { "export.title",      "Vie keskustelu k\u00e4ytt\u00e4j\u00e4n %1 kanssa" },
        { "export.pdf",        "PDF-asiakirja (*.pdf)" },
        { "export.txt",        "Tekstitiedosto (*.txt)" },
        { "export.done",       "Keskustelu k\u00e4ytt\u00e4j\u00e4n %1 kanssa tallennettiin sijaintiin %2" },
        { "export.saved",      "Keskustelu k\u00e4ytt\u00e4j\u00e4n %1 kanssa tallennettu." },
        { "export.empty",      "K\u00e4ytt\u00e4j\u00e4n %1 kanssa ei ole viel\u00e4 viestej\u00e4 viet\u00e4v\u00e4ksi." },
        { "export.failed",     "Vienti\u00e4 ei voitu tallentaa: %1" },
        { "export.headerTitle","Keskustelu k\u00e4ytt\u00e4j\u00e4n %1 kanssa" },
        { "export.headerExported", "Viety %1" },
        { "export.headerParticipants", "Osallistujat: %1 ja %2" },
        { "export.sentFile",   "l\u00e4hetti tiedoston: %1 (%2)" },
        { "export.systemLabel","(j\u00e4rjestelm\u00e4)" },
        { "notif.newMessageTitle", "Uusi viesti k\u00e4ytt\u00e4j\u00e4lt\u00e4 %1" },
        { "notif.newFileTitle",    "Uusi tiedosto k\u00e4ytt\u00e4j\u00e4lt\u00e4 %1" },
        { "notif.newFileBody",     "%1 (%2)" },
        { "notif.channelName",     "Viestit" },
        { "notif.serviceRunning",  "Salattu keskustelu on k\u00e4ynniss\u00e4" },
        { "notif.serviceBody",     "Yhdistetty \u2014 saat ilmoituksen uusista viesteist\u00e4." },
        { "shortcut.unsupported",  "Aloitusn\u00e4yt\u00f6n pikakuvaketta ei voitu luoda t\u00e4ss\u00e4 laitteessa." },
        { "sys.cannotDecrypt", "\U0001F512 Aiempaa viesti\u00e4 ei voitu en\u00e4\u00e4 purkaa (se tallennettiin aiemmalla henkil\u00f6llisyysavaimella)." },
        { "sys.historyOpenFailed", "Historiaa ei voitu avata; viestej\u00e4 ei tallenneta t\u00e4ss\u00e4 istunnossa." },
        { "sys.noStorage",     "Kirjoitettavaa tallennussijaintia ei l\u00f6ytynyt; viestihistoria on poissa k\u00e4yt\u00f6st\u00e4 t\u00e4ss\u00e4 istunnossa." },
        { "err.historyOpenFailed", "Paikallista historiaa ei voitu avata; viestej\u00e4si ei tallenneta t\u00e4h\u00e4n laitteeseen." },
        { "sys.fileFailed",    "Tiedoston siirto ep\u00e4onnistui: %1" },
        { "sys.reason.startDecrypt", "purkua ei voitu aloittaa" },
        { "sys.reason.openTemp",     "v\u00e4liaikaistiedostoa ei voitu avata" },
    };

    // ---- Swedish (svenska) ----------------------------------------------
    m_sv = {
        { "online",            "uppkopplad" },
        { "reconnecting",      "\u00e5teransluter\u2026" },
        { "menu.viewSafety",   "Visa s\u00e4kerhetsnummer" },
        { "menu.theme",        "Tema\u2026" },
        { "menu.language",     "Spr\u00e5k\u2026" },
        { "menu.darkMode",     "M\u00f6rkt l\u00e4ge" },
        { "menu.switchUser",   "Byt anv\u00e4ndare\u2026" },
        { "menu.logout",       "Logga ut" },
        { "menu.export",       "Exportera chatt\u2026" },
        { "menu.shortcut",     "L\u00e4gg till p\u00e5 startsk\u00e4rmen\u2026" },
        { "menu.logs",         "Diagnostiklogg\u2026" },
        // Diagnostic log screen (always-on deep probing traces)
        { "log.title",         "Diagnostiklogg" },
        { "log.lines",         "rader" },
        { "log.empty",         "Inga loggrader har f\u00e5ngats \u00e4nnu." },
        { "log.copyAll",       "Kopiera alla" },
        { "log.clear",         "Rensa" },
        { "log.close",         "St\u00e4ng" },
        { "lang.title",        "Spr\u00e5k" },
        { "lang.hint",         "V\u00e4lj appspr\u00e5k. Ditt val sparas p\u00e5 den h\u00e4r enheten." },
        { "theme.title",       "Tema" },
        { "theme.hint",        "V\u00e4lj ett f\u00e4rgtema. Ditt val sparas f\u00f6r \"%1\" p\u00e5 den h\u00e4r enheten." },
        { "contacts.title",    "Kontakter" },
        { "contacts.you",      "du" },
        { "contacts.offline",  "fr\u00e5nkopplad" },
        { "contacts.typing",   "skriver\u2026" },
        { "contacts.sendingFile", "skickar en fil\u2026" },
        { "conv.chattingWith", "Chattar med %1" },
        { "conv.isTyping",     "%1 skriver\u2026" },
        { "conv.isSendingFile","%1 skickar en fil\u2026" },
        { "conv.pickContact",  "V\u00e4lj en kontakt f\u00f6r att starta en privat konversation." },
        { "conv.emptyHint",    "V\u00e4lj vem du vill chatta med" },
        { "composer.type",     "Skriv ett meddelande\u2026" },
        { "composer.confirmFirst", "Bekr\u00e4fta \u00e4ndringen av s\u00e4kerhetsnumret f\u00f6r att forts\u00e4tta\u2026" },
        { "composer.send",     "Skicka" },
        { "composer.attachTip","Skicka en fil eller bild" },
        { "msg.deleted",       "Det h\u00e4r meddelandet raderades" },
        { "menu.deleteForMe",  "Radera f\u00f6r mig" },
        { "menu.deleteForEveryone", "Radera f\u00f6r alla" },
        { "menu.reactAgree",    "H\u00e5ller med" },
        { "menu.reactDisagree", "H\u00e5ller inte med" },
        { "menu.reactRemove",   "Ta bort reaktion" },
        // Editing / resending
        { "menu.edit",          "Redigera" },
        { "menu.resend",        "Skicka igen" },
        { "msg.edited",         "redigerad" },
        { "edit.title",         "Redigera meddelande" },
        { "edit.hint",          "Den nya texten krypteras och uppdateras hos b\u00e5da parter. Du m\u00e5ste vara online f\u00f6r att redigera." },
        { "login.title",       "Krypterad chatt" },
        { "login.server",      "Serveradress" },
        { "login.nickname",    "Smeknamn" },
        { "login.connect",     "Anslut" },
        { "login.connecting",  "Ansluter\u2026" },
        // ---- Password auth (feature 1) + app lock (feature 2) ----
        { "login.password",        "L\u00f6senord" },
        { "login.passwordHint",    "V\u00e4lj ett starkt l\u00f6senord" },
        { "login.passwordHintLogin","Ange ditt l\u00f6senord" },
        { "login.register",        "Registrera" },
        { "login.login",           "Logga in" },
        { "login.haveAccount",     "Har du redan ett konto? Logga in" },
        { "login.needAccount",     "Ny h\u00e4r? Registrera" },
        { "login.pwHelp",          "Ditt l\u00f6senord krypterar din identitetsnyckel p\u00e5 den h\u00e4r enheten. Servern ser det aldrig." },
        // ---- F\u00f6delsedatum + l\u00f6senords\u00e5terst\u00e4llning -------------------
        { "login.birthday",        "F\u00f6delsedatum" },
        { "login.birthdayHint",    "1999-05-03" },
        { "login.birthdayHelp",    "Kr\u00e4vs f\u00f6r att skapa ett nytt konto. Lagras endast som en o\u00e5terkallelig hash, aldrig som ett datum." },
        { "login.birthdayInvalid", "Datumet \u00e4r ogiltigt. Anv\u00e4nd formen 1999-05-03." },
        { "login.forgot",          "Gl\u00f6mt l\u00f6senordet?" },
        { "recover.title",         "\u00c5terst\u00e4ll ditt l\u00f6senord" },
        { "recover.titleRevealed", "Ditt l\u00f6senord" },
        { "recover.introHello",    "Ange ditt anv\u00e4ndarnamn och f\u00f6delsedatum. Du ombeds sedan bekr\u00e4fta med Windows Hello." },
        { "recover.introBio",      "Ange ditt anv\u00e4ndarnamn och f\u00f6delsedatum. Du ombeds sedan bekr\u00e4fta med fingeravtryck eller enhetens PIN." },
        { "recover.user",          "Anv\u00e4ndarnamn" },
        { "recover.dobHint",       "F\u00f6delsedatum, t.ex. 1999-05-03" },
        { "recover.submit",        "Skicka" },
        { "recover.waiting",       "V\u00e4ntar p\u00e5 autentisering\u2026" },
        { "recover.warning",       "Alla som ser den h\u00e4r sk\u00e4rmen ser ditt l\u00f6senord. St\u00e4ng s\u00e5 snart du har antecknat det." },
        { "recover.back",          "Tillbaka till inloggning" },
        { "recover.close",         "St\u00e4ng" },
        // Biometric / Windows Hello LOGIN (feature).
        { "login.helloLogin",      "Logga in med Windows Hello" },
        { "login.bioLogin",        "Logga in med fingeravtryck eller PIN" },
        { "login.enableHello",     "Aktivera Windows Hello-inloggning n\u00e4sta g\u00e5ng" },
        { "login.enableBio",       "Aktivera fingeravtrycks- eller PIN-inloggning n\u00e4sta g\u00e5ng" },
        { "lock.bioLoginTitle",    "Logga in i Krypterad chatt" },
        { "lock.bioLoginSubtitle", "Bekr\u00e4fta din identitet f\u00f6r att logga in" },
        { "lock.bioEnrollTitle",   "Aktivera fingeravtrycksinloggning" },
        { "lock.bioEnrollSubtitle","Bekr\u00e4fta f\u00f6r att spara din inloggning till n\u00e4sta g\u00e5ng" },
        { "err.wrongPassword",     "Fel l\u00f6senord. Ditt konto \u00e4ndrades inte." },
        { "err.noAccountHere",     "Inget konto hittades p\u00e5 den h\u00e4r enheten f\u00f6r det namnet. Registrera dig f\u00f6rst." },
        { "err.accountExistsLocally","Ett konto med det namnet finns redan p\u00e5 den h\u00e4r enheten. Logga in ist\u00e4llet." },
        { "err.identityNotPersisted","Din identitet kunde inte sparas i best\u00e4ndig lagring och kanske inte \u00f6verlever en omstart p\u00e5 den h\u00e4r enheten." },
        { "err.identityUnreadable","Kunde inte l\u00e4sa din sparade identitet. Starta om appen; din nyckel \u00e4ndrades inte." },
        { "err.registerFailed",    "Registreringen misslyckades n\u00e4r dina uppgifter f\u00f6rbereddes. F\u00f6rs\u00f6k igen." },
        { "err.loginRejected",     "Servern avslutade sessionen (fel l\u00f6senord, reserverat anv\u00e4ndarnamn eller inloggning p\u00e5 en annan enhet). Logga in igen." },
        { "err.pinSetFailed",      "Det gick inte att st\u00e4lla in PIN-koden. F\u00f6rs\u00f6k igen." },
        { "err.noDeviceCredential","Inget enhetsl\u00e5s \u00e4r inst\u00e4llt. St\u00e4ll f\u00f6rst in ett sk\u00e4rml\u00e5s (PIN, m\u00f6nster eller fingeravtryck) i enhetens inst\u00e4llningar." },
        { "err.pinRequired",       "En reserv-PIN kr\u00e4vs. Ange en PIN-kod." },
        { "err.resetNoAccount",    "Inget konto hittades p\u00e5 den h\u00e4r enheten att verifiera ditt l\u00f6senord mot." },
        { "lock.unlockDevice",     "L\u00e5s upp med enheten" },
        { "lock.unlockHello",      "L\u00e5s upp med Windows Hello" },
        { "lock.orEnterPin",       "\u2014 eller ange din PIN \u2014" },
        { "lock.forgotPin",        "Gl\u00f6mt PIN?" },
        { "lock.resetTitle",       "\u00c5terst\u00e4ll l\u00e5s" },
        { "lock.resetPrompt",      "Ange ditt kontol\u00f6senord f\u00f6r att \u00e5terst\u00e4lla appl\u00e5set." },
        { "settings.enableLock",   "Aktivera appl\u00e5s" },
        { "settings.disableLock",  "Inaktivera appl\u00e5s" },
        { "settings.lockUsesDevice","Uppl\u00e5sning anv\u00e4nder enhetens sk\u00e4rml\u00e5s (fingeravtryck, ansikte eller PIN)." },
        { "settings.lockUsesHello","Uppl\u00e5sning anv\u00e4nder Windows Hello, med din app-PIN som reserv." },
        { "settings.lockUsesPin",  "Uppl\u00e5sning anv\u00e4nder din app-PIN." },
        { "err.nameReserved",      "Det h\u00e4r anv\u00e4ndarnamnet \u00e4r redan registrerat till en annan identitet. V\u00e4lj ett annat namn." },
        { "err.badPassword",       "Fel l\u00f6senord f\u00f6r det h\u00e4r anv\u00e4ndarnamnet." },
        { "lock.title",            "L\u00e5st" },
        { "lock.enterPin",         "Ange PIN" },
        { "lock.wrongPin",         "Fel PIN, f\u00f6rs\u00f6k igen" },
        { "lock.unlock",           "L\u00e5s upp" },
        { "lock.useFingerprint",   "Anv\u00e4nd fingeravtryck" },
        { "lock.biometricTitle",   "L\u00e5s upp Krypterad chatt" },
        { "lock.biometricSubtitle","Bekr\u00e4fta din identitet f\u00f6r att forts\u00e4tta" },
        { "settings.appLock",      "Appl\u00e5s (PIN)" },
        { "settings.setPin",       "St\u00e4ll in / \u00e4ndra PIN" },
        { "settings.removePin",    "Ta bort PIN" },
        { "settings.pinOn",        "PIN-l\u00e5s \u00e4r p\u00e5" },
        { "settings.pinOff",       "PIN-l\u00e5s \u00e4r av" },
        { "settings.newPin",       "Ny PIN" },
        { "settings.confirmPin",   "Bekr\u00e4fta PIN" },
        { "settings.currentPin",   "Nuvarande PIN" },
        { "settings.wrongCurrentPin","Nuvarande PIN \u00e4r felaktig" },
        { "settings.pinMismatch",  "PIN-koderna matchar inte" },
        { "settings.lockNow",      "L\u00e5s nu" },
        { "common.cancel",         "Avbryt" },
        { "common.save",           "Spara" },
        { "logout.title",      "Logga ut?" },
        { "logout.body",       "Du kommer tillbaka till inloggningssk\u00e4rmen. Din identitet och meddelandehistorik stannar p\u00e5 den h\u00e4r enheten, s\u00e5 att logga in igen som \"%1\" \u00e5terst\u00e4ller allt." },
        { "switch.title",      "Byt anv\u00e4ndare?" },
        { "switch.body",       "Detta \u00e5terg\u00e5r till inloggningssk\u00e4rmen s\u00e5 att n\u00e5gon annan kan logga in med sitt eget namn. \"%1\":s identitet och meddelanden stannar p\u00e5 den h\u00e4r enheten, s\u00e5 du kan byta tillbaka senare." },
        { "safety.titlePeer",  "S\u00e4kerhetsnummer med %1" },
        { "safety.titleSelf",  "Ditt s\u00e4kerhetsnummer" },
        { "safety.comparePeer","J\u00e4mf\u00f6r dessa nummer med %1 via ett samtal eller personligen.\nOm de matchar p\u00e5 b\u00e5da enheterna avlyssnar ingen dina nycklar." },
        { "safety.selectHint", "V\u00e4lj en kontakt f\u00f6r att se s\u00e4kerhetsnumret ni delar." },
        { "safety.bannerTitle","\u26A0\uFE0F %1 kan vara en annan person eller enhet" },
        { "safety.bannerBody", "%1:s s\u00e4kerhetsnummer \u00e4ndrades. Detta h\u00e4nder n\u00e4r n\u00e5gon installerar om, byter enhet eller n\u00e4r en annan person tar \u00f6ver namnet -- men det kan ocks\u00e5 betyda att n\u00e5gon avlyssnar dina meddelanden. J\u00e4mf\u00f6r det nya s\u00e4kerhetsnumret med %1 via ett samtal eller personligen och bekr\u00e4fta sedan f\u00f6r att forts\u00e4tta. Du kan inte skicka meddelanden f\u00f6rr\u00e4n du g\u00f6r det." },
        { "safety.view",       "Visa s\u00e4kerhetsnummer" },
        { "safety.confirm",    "Jag har verifierat \u2014 bekr\u00e4fta och byt" },
        { "export.title",      "Exportera konversation med %1" },
        { "export.pdf",        "PDF-dokument (*.pdf)" },
        { "export.txt",        "Textfil (*.txt)" },
        { "export.done",       "Konversationen med %1 sparades till %2" },
        { "export.saved",      "Konversationen med %1 sparad." },
        { "export.empty",      "Det finns inga meddelanden med %1 att exportera \u00e4nnu." },
        { "export.failed",     "Kunde inte spara exporten: %1" },
        { "export.headerTitle","Konversation med %1" },
        { "export.headerExported", "Exporterad %1" },
        { "export.headerParticipants", "Deltagare: %1 och %2" },
        { "export.sentFile",   "skickade en fil: %1 (%2)" },
        { "export.systemLabel","(system)" },
        { "notif.newMessageTitle", "Nytt meddelande fr\u00e5n %1" },
        { "notif.newFileTitle",    "Ny fil fr\u00e5n %1" },
        { "notif.newFileBody",     "%1 (%2)" },
        { "notif.channelName",     "Meddelanden" },
        { "notif.serviceRunning",  "Krypterad chatt k\u00f6rs" },
        { "notif.serviceBody",     "Ansluten \u2014 du meddelas om nya meddelanden." },
        { "shortcut.unsupported",  "En genv\u00e4g p\u00e5 startsk\u00e4rmen kunde inte skapas p\u00e5 den h\u00e4r enheten." },
        { "sys.cannotDecrypt", "\U0001F512 Ett tidigare meddelande kan inte l\u00e4ngre dekrypteras (det lagrades med en tidigare identitetsnyckel)." },
        { "sys.historyOpenFailed", "Historiken kunde inte \u00f6ppnas; meddelanden sparas inte den h\u00e4r sessionen." },
        { "sys.noStorage",     "Ingen skrivbar lagringsplats hittades; meddelandehistoriken \u00e4r inaktiverad den h\u00e4r sessionen." },
        { "err.historyOpenFailed", "Den lokala historiken kunde inte \u00f6ppnas; dina meddelanden lagras inte p\u00e5 den h\u00e4r enheten." },
        { "sys.fileFailed",    "Fil\u00f6verf\u00f6ringen misslyckades: %1" },
        { "sys.reason.startDecrypt", "kunde inte starta dekryptering" },
        { "sys.reason.openTemp",     "kunde inte \u00f6ppna tempfil" },
    };
}
