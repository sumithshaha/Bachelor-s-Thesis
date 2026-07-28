#ifndef LOCALIZATION_H
#define LOCALIZATION_H

// ============================================================================
//  localization.h  --  runtime-reactive UI language for QML *and* C++.
//
//  WHY NOT Qt's tr() / qsTr()?
//  Qt's built-in translation (tr in C++, qsTr in QML, backed by .ts/.qm files)
//  resolves each string against the *currently installed* QTranslator at the
//  moment the string is evaluated. Installing a different QTranslator at
//  runtime does NOT automatically re-evaluate strings already shown -- in QML
//  you must additionally fire QQmlEngine::retranslate(), and every qsTr() call
//  site must be re-run, which is fragile across loaded Components. For a menu
//  that flips English <-> suomi <-> svenska *live*, that path is awkward.
//
//  THIS APPROACH INSTEAD:
//  A single QObject singleton exposes
//     * a `language` Q_PROPERTY (an enum: English / Finnish / Swedish) with a
//       NOTIFY signal, persisted in QSettings, and
//     * Q_INVOKABLE tIn(language, key) returning the string for a GIVEN language,
//       plus t(key) for the active one (used from C++).
//  In QML, every visible string is bound as
//       tIn(Localization.language, "send")
//  -- and the crucial detail is that the binding EXPRESSION itself reads the
//  notifying `language` property (by passing it as the first argument). QML's
//  binding system records dependencies only on the properties read *while it
//  evaluates the expression*, so this is what makes Qt re-evaluate the binding
//  the instant the language changes, relabelling the whole UI with no restart.
//
//  IMPORTANT PITFALL: a bare `t("send")` binding does NOT refresh on a language
//  change. t() reads the active language *inside C++*, which the QML engine
//  never sees, so no dependency on `language` is captured and the label stays
//  frozen at whatever it was when first shown. That was the original bug: the
//  language menu's checkmarks (which read `language` directly) moved, but no
//  label re-translated. Passing `language` into tIn(...) at each call site is
//  the fix. In C++, Localization::instance().t("...") is called wherever we
//  emit a user-facing system string, so freshly created strings localize in the
//  language active at that moment.
//
//  Keys, not English text, are the lookup tokens (so "send" -> the right word
//  in each language) -- this keeps call sites stable if the English wording is
//  later tweaked, and makes a missing translation obvious (it falls back to the
//  key itself, and to English, rather than silently showing the wrong thing).
//
//  STATUS: faithful, build-and-test-required. Straightforward QObject; not
//  compiled against the Qt toolchain here.
// ============================================================================

#include <QHash>
#include <QObject>
#include <QQmlEngine>
#include <QString>

class Localization : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

    // The active language. QML binds to this (directly or via t()); writing it
    // persists the choice and re-labels the UI live. Exposed as an int-backed
    // enum so QML can say Loc.language === Localization.Finnish and set it from
    // the language menu.
    Q_PROPERTY(Language language READ language WRITE setLanguage
                       NOTIFY languageChanged)
    // Convenience for the menu: the human-readable, ALWAYS-native name of each
    // language ("English", "Suomi", "Svenska") regardless of the active one, so
    // the picker shows each option in its own tongue.
    Q_PROPERTY(QString languageName READ languageName NOTIFY languageChanged)

public:
    enum Language {
        English = 0,
        Finnish = 1,
        Swedish = 2
    };
    Q_ENUM(Language)

    // The QML singleton factory. One instance for the whole app; C++ reaches the
    // same object through instance() so system strings localize identically.
    static Localization *create(QQmlEngine *, QJSEngine *);
    static Localization *instance();

    Language language() const { return m_lang; }
    void setLanguage(Language lang);

    QString languageName() const { return nameOf(m_lang); }

    // The localized string for a key in the ACTIVE language. Falls back to the
    // English string, then to the key itself, if a translation is missing --
    // never returns empty for a known key, and makes a typo visible rather than
    // silent. Q_INVOKABLE so QML delegates/menus call Loc.t("key").
    Q_INVOKABLE QString t(const QString &key) const;

    // Like t(), but for a specific language rather than the active one. Used by
    // the export path, which may want a fixed header language, and available if
    // a screen ever needs to show two languages at once. Not commonly needed.
    Q_INVOKABLE QString tIn(Language lang, const QString &key) const;

    // The native display name of a language ("English" / "Suomi" / "Svenska").
    // Static so the menu can label options without an instance in hand.
    static QString nameOf(Language lang);

signals:
    // Fired whenever the language changes. QML bindings that call t() depend on
    // this (through the language property) and re-evaluate; ChatClient connects
    // to it to re-emit its own "reload the open conversation" trigger so system
    // messages already on screen switch language too.
    void languageChanged();

private:
    explicit Localization(QObject *parent = nullptr);

    // Build the per-language dictionaries once, in the constructor. Kept in code
    // (not .qm files) so the whole feature is self-contained and easy to read,
    // extend, and explain -- add a key to all three maps and it is available
    // everywhere via t("newKey"). The English map also serves as the fallback.
    void buildDictionaries();

    Language m_lang = English;
    // key -> translated string, one map per language.
    QHash<QString, QString> m_en;
    QHash<QString, QString> m_fi;
    QHash<QString, QString> m_sv;

    const QHash<QString, QString> &mapFor(Language lang) const;
};

#endif // LOCALIZATION_H
