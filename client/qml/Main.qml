import QtQuick
import QtQuick.Controls.Material
import QtQuick.Window
import ChatE2EE
// Localization is a C++ QML singleton (see localization.h), registered in the
// same ChatE2EE module as ChatClient. Every visible string is looked up as
// App.Localization.tIn(App.Localization.language, "key"). The binding reads the
// notifying `language` property directly, so QML re-evaluates it the instant the
// language changes -- switching English/suomi/svenska relabels the whole UI with
// no restart. (Reading `language` in the expression is essential: a bare
// t("key") call would read the active language inside C++, which the QML binding
// system cannot observe, so those bindings would never refresh.)
import ChatE2EE as App

// Main.qml is the root of the user interface. It is deliberately thin: it sets
// up the window, the global theme, and a StackView that shows either the login
// page or the chat page. All the real screens live in their own files.
//
// RESTYLE NOTES (build-and-test-required -- not compiled here):
//   * PER-USER THEMING. Instead of a single fixed palette, there is now a small
//     table of colour PRESETS (themes[]). The active preset is chosen by
//     ChatClient.themeIndex -- a per-nickname value the C++ side persists in
//     QSettings, defaulting to a stable nickname-derived preset so every user
//     starts with their own accent. window.pal is a computed lookup into the
//     active preset, so every screen that reads window.pal.* recolours the
//     instant a user logs in or picks a preset, with NO change in those screens.
//   * RESPONSIVE. window.isPhone is true on a narrow (portrait-phone) width.
//     ChatPage uses it to switch between the desktop side-by-side layout and a
//     phone full-screen list -> conversation layout, which fixes the clipped
//     header/banner/composer seen on the S24 Ultra in portrait.
//   * Login -> push ChatPage on onLoggedIn; ChatPage -> pop on onLoggedOut.
//
// VISUAL PASS (this revision): the palette now also exposes a few DERIVED roles
// (accentHi, shadow, glass, dangerHi) computed from the existing ten so that
// gradients, soft shadows, and gloss highlights are consistent across every
// screen without touching the per-preset colour table. The old flat error
// footer is now a floating, rounded, animated TOAST that slides in from the top.

ApplicationWindow {
    id: window
    width: 420
    height: 720
    visible: true
    title: "Encrypted Chat"

    // EAGER DIAGNOSTIC LOG INIT.
    // The LogBuffer singleton (the in-app "Log screen" backing store) is created
    // lazily the first time QML references it. The Log screen itself lives on
    // the chat page, which only loads after login -- so without this touch, the
    // very early startup traces (build marker, history open, first connection
    // attempts) would sit in main.cpp's pre-buffer until then. Referencing
    // LogBuffer here constructs it at window creation, so its message-handler
    // pre-buffer drains immediately and the in-app log is live from the login
    // screen onward. `void(...)` keeps this a pure side-effecting touch.
    Component.onCompleted: void(LogBuffer.count)

    // ---- Responsive breakpoint -----------------------------------------
    // True when the window is narrow enough that a two-column layout would be
    // cramped -- i.e. a phone in portrait. 560 logical px is a comfortable
    // threshold: the S24 Ultra in portrait (~384 logical px wide) is well below
    // it, while a desktop window or a tablet/landscape phone is above it and
    // keeps the richer side-by-side layout. Bound to width, so rotating the
    // device or resizing the desktop window switches layouts live.
    readonly property bool isPhone: width < 560

    // ---- Dark / light mode ---------------------------------------------
    // The active brightness. Each preset below defines BOTH a dark and a light
    // colour set; window.pal selects one based on this flag, so toggling it
    // recolours the whole UI live (every screen reads window.pal.* and so needs
    // no change). Persisted app-wide by the backend (ChatClient.darkMode), like
    // the language: brightness is a device preference, not a per-account one.
    // The overflow menu's "Dark mode" switch writes ChatClient.darkMode, whose
    // NOTIFY (darkModeChanged) drives this binding.
    readonly property bool dark: ChatClient.darkMode

    // ---- Theme presets --------------------------------------------------
    // Each preset is a full colour set. All share a DARK, readable base family
    // (text is always high-contrast off-white on a deep surface) so no preset is
    // ever unreadable; what changes per preset is the SURFACE tint and, above
    // all, the ACCENT -- the signature colour on buttons, the send button, the
    // presence dot, "my" chat bubbles, and the login lockup. The order here IS
    // the index space stored by ChatClient.themeIndex, so do not reorder without
    // understanding that a user's saved choice is an index into this list. To
    // add a preset, append here (and see kThemePresetCount in chatclient.cpp if
    // you want auto-assigned defaults to use it too). Keep the field set
    // identical across presets -- window.pal depends on every key existing.
    // Each preset now carries a DARK set (the fields directly on the object, so
    // existing dark colours are byte-for-byte unchanged) AND a nested `light`
    // set with the SAME field names but bright, high-contrast values (dark text
    // on a near-white surface, the accent darkened just enough to stay legible
    // on white). window.pal picks the dark fields or the light ones based on
    // window.dark, so a preset keeps its signature accent identity in both
    // brightnesses. Keep the field set identical across every preset and across
    // its light variant -- window.pal depends on every key existing in both.
    readonly property var themes: [
        {   // 0 - Teal (the original slate + cyan-teal signature)
            name: "Teal",
            base:      "#0f141b", surface:   "#161d27", surfaceHi: "#1e2733",
            line:      "#273240", text:      "#e8edf2", textDim:   "#8a97a6",
            accent:    "#2fd6c3", accentDim: "#1c8f84",
            danger:    "#e5484d", online:    "#3ddc84",
            light: {
                base:      "#f4f7f8", surface:   "#ffffff", surfaceHi: "#e9eef0",
                line:      "#d3dade", text:      "#12242a", textDim:   "#5a6b72",
                accent:    "#0e9e90", accentDim: "#0a746a",
                danger:    "#c62828", online:    "#1f9d57"
            }
        },
        {   // 1 - Indigo
            name: "Indigo",
            base:      "#0f1220", surface:   "#171a2b", surfaceHi: "#1f2438",
            line:      "#2a3050", text:      "#e9ebf5", textDim:   "#9098bd",
            accent:    "#7c8cff", accentDim: "#4d5bc0",
            danger:    "#e5484d", online:    "#3ddc84",
            light: {
                base:      "#f5f6fb", surface:   "#ffffff", surfaceHi: "#e9ebf6",
                line:      "#d5d9ec", text:      "#161a2e", textDim:   "#5c628a",
                accent:    "#4453d6", accentDim: "#2f3ba6",
                danger:    "#c62828", online:    "#1f9d57"
            }
        },
        {   // 2 - Violet
            name: "Violet",
            base:      "#160f1d", surface:   "#20172a", surfaceHi: "#2a1f38",
            line:      "#3a2a4d", text:      "#f0e9f5", textDim:   "#a790bd",
            accent:    "#c07cff", accentDim: "#8b4dc0",
            danger:    "#e5484d", online:    "#3ddc84",
            light: {
                base:      "#f9f5fb", surface:   "#ffffff", surfaceHi: "#efe9f6",
                line:      "#e0d5ec", text:      "#241730", textDim:   "#715c8a",
                accent:    "#9a44d6", accentDim: "#6f2fa6",
                danger:    "#c62828", online:    "#1f9d57"
            }
        },
        {   // 3 - Rose
            name: "Rose",
            base:      "#1b0f14", surface:   "#27161d", surfaceHi: "#331e27",
            line:      "#402730", text:      "#f5e8ed", textDim:   "#bd8a97",
            accent:    "#ff6f91", accentDim: "#c04a63",
            danger:    "#ff5252", online:    "#3ddc84",
            light: {
                base:      "#fbf5f7", surface:   "#ffffff", surfaceHi: "#f6e9ee",
                line:      "#ecd5dd", text:      "#301720", textDim:   "#8a5c69",
                accent:    "#d6446a", accentDim: "#a62f4d",
                danger:    "#c62828", online:    "#1f9d57"
            }
        },
        {   // 4 - Amber
            name: "Amber",
            base:      "#1a140c", surface:   "#261d10", surfaceHi: "#322715",
            line:      "#40331e", text:      "#f5efe6", textDim:   "#bda98a",
            accent:    "#ffb74d", accentDim: "#c0863a",
            danger:    "#e5484d", online:    "#3ddc84",
            light: {
                base:      "#fbf8f3", surface:   "#ffffff", surfaceHi: "#f6f0e6",
                line:      "#ece2d0", text:      "#302512", textDim:   "#8a7a5c",
                accent:    "#b9781a", accentDim: "#8a5910",
                danger:    "#c62828", online:    "#1f9d57"
            }
        },
        {   // 5 - Emerald
            name: "Emerald",
            base:      "#0d1a12", surface:   "#10261a", surfaceHi: "#153322",
            line:      "#1e402d", text:      "#e6f5ec", textDim:   "#8abda0",
            accent:    "#34d399", accentDim: "#1f8f6b",
            danger:    "#e5484d", online:    "#3ddc84",
            light: {
                base:      "#f3fbf6", surface:   "#ffffff", surfaceHi: "#e6f6ec",
                line:      "#d0ece0", text:      "#123020", textDim:   "#5c8a70",
                accent:    "#12a06e", accentDim: "#0d7450",
                danger:    "#c62828", online:    "#1f9d57"
            }
        }
    ]

    // The active preset index, clamped defensively into range in case a stored
    // value ever falls outside the current preset list.
    readonly property int themeIdx: {
        var i = ChatClient.themeIndex
        if (i < 0 || i >= themes.length)
            return 0
        return i
    }
    readonly property var theme: themes[themeIdx]

    // ---- One palette, referenced everywhere (window.pal.*) --------------
    // Computed from the active preset AND the active brightness. Each role reads
    // the preset's LIGHT sub-object when window.dark is false, otherwise the
    // preset's own (dark) fields. Every screen reads window.pal.<role>, so none
    // of them needs to know about presets OR brightness -- swapping themeIndex or
    // toggling dark swaps every colour in this one place. The ten role names are
    // unchanged from the original single palette, so existing bindings keep
    // working verbatim. `src` centralises the dark-or-light choice so all ten
    // roles agree on which set they are reading.
    //
    // The DERIVED roles below (accentHi, shadow, glass, dangerHi) are NOT stored
    // per preset -- they are computed from the ten base roles plus the brightness
    // flag, so the whole visual system (accent gradients, soft drop shadows, and
    // gloss highlights) stays coherent for every preset in both brightnesses
    // without adding a single colour to the table above.
    readonly property QtObject pal: QtObject {
        readonly property var src: window.dark ? window.theme
                                               : window.theme.light
        readonly property color base:      src.base
        readonly property color surface:   src.surface
        readonly property color surfaceHi: src.surfaceHi
        readonly property color line:      src.line
        readonly property color text:      src.text
        readonly property color textDim:   src.textDim
        readonly property color accent:    src.accent
        readonly property color accentDim: src.accentDim
        readonly property color danger:    src.danger
        readonly property color online:    src.online

        // ---- Derived (computed) roles -----------------------------------
        // A lifted tint of the accent for the TOP of accent gradients (buttons,
        // "my" bubbles, badges), giving a soft light-from-above sheen.
        readonly property color accentHi: Qt.lighter(accent, window.dark ? 1.16 : 1.06)
        // A brighter danger for the top of warning gradients.
        readonly property color dangerHi: Qt.lighter(danger, window.dark ? 1.14 : 1.05)
        // A single soft shadow colour, deeper in dark mode where surfaces are
        // near-black and a subtle black cast reads, gentler and slightly cool in
        // light mode so cards lift off the page without a muddy grey halo.
        readonly property color shadow: window.dark ? Qt.rgba(0, 0, 0, 0.50)
                                                     : Qt.rgba(0.06, 0.10, 0.15, 0.16)
        // A translucent white used for the thin gloss highlight along the top of
        // raised elements; stronger on dark surfaces, faint on light ones.
        readonly property color glass: Qt.rgba(1, 1, 1, window.dark ? 0.12 : 0.45)
    }

    color: pal.base

    // Follow the brightness flag so Material's own controls (ripples, menu
    // backgrounds, text-field cursors) match the palette rather than staying
    // dark on a light theme.
    Material.theme: window.dark ? Material.Dark : Material.Light
    Material.accent: pal.accent
    Material.background: pal.base
    Material.foreground: pal.text
    Material.primary: pal.accent

    // A StackView lets us push the chat page on top of the login page once the
    // user has logged in, and pop back on logout. On Android the back gesture
    // maps naturally onto this stack.
    StackView {
        id: stack
        anchors.fill: parent
        initialItem: loginPage
    }

    // ---- App lock overlay (feature 2) ----------------------------------
    // A full-screen lock that sits ABOVE the StackView whenever the app is
    // locked (a PIN is set and the app has been backgrounded or explicitly
    // locked). Because it is a sibling drawn after the StackView with a filled
    // anchor and an opaque background, it covers whatever screen is beneath --
    // so no conversation is visible until the user enters the PIN or passes the
    // fingerprint prompt. It is only instantiated while locked (active binding),
    // so it costs nothing when unlocked. ChatClient.isLocked drives it live via
    // its lockStateChanged NOTIFY.
    Loader {
        id: lockLoader
        anchors.fill: parent
        active: ChatClient.isLocked
        visible: active
        z: 9999
        sourceComponent: LockScreen {}
    }

    Component {
        id: loginPage
        LoginPage {
            onLoginRequested: function(url, nick, password) {
                ChatClient.login(url, nick, password)
            }
            onRegisterRequested: function(url, nick, password, birthday) {
                ChatClient.registerAccount(url, nick, password, birthday)
            }
        }
    }

    Component {
        id: chatPage
        ChatPage {
            // ChatPage emits this when the user taps Log out. The backend has
            // already torn down the socket/session by then; we just return to
            // the login screen, which will re-prefill the last nickname.
            onLogoutRequested: {
                ChatClient.logout()
            }
        }
    }

    // When the C++ side reports a successful login, move to the chat page.
    Connections {
        target: ChatClient
        function onLoggedIn() {
            if (stack.depth === 1)
                stack.push(chatPage)
        }
        // When the backend confirms logout (socket closed, model cleared,
        // history DB closed -- identity and history PRESERVED on disk), pop
        // back to the login page.
        function onLoggedOut() {
            if (stack.depth > 1)
                stack.pop(null)   // back to initialItem (login)
        }
    }

    // ---- Global status TOAST (floats at the TOP) -----------------------
    // Backend errors and status messages surface here. It is a sibling of the
    // StackView drawn ABOVE it (like the lock overlay below). It was previously
    // an ApplicationWindow footer docked at the BOTTOM, where on a phone it sat
    // beneath the on-screen keyboard and the gesture/navigation bar and was
    // extremely easy to miss (the "errors appear too low to read" problem). Now
    // it is a floating, rounded CARD near the top: it slides down and fades in,
    // carries a colour-coded icon chip (a warning triangle for errors, a check
    // for success), rests on a soft drop shadow, and auto-dismisses after a few
    // seconds. Tapping it dismisses it immediately. z is 9000 -- above all page
    // content but BELOW the lock overlay (9999), so a PIN prompt is never
    // covered by a stray toast. The single show(tone, text) entry point keeps
    // the two Connections handlers below trivial.
    Item {
        id: errorBar
        z: 9000
        visible: false
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 14
        height: 0

        // "error" -> danger colours + warning glyph; "success" -> green + check.
        property string tone: "error"
        property string toastText: ""
        readonly property bool isError: tone === "error"

        // Central entry point. Sets the tone and text, makes the toast visible,
        // replays the slide-in, and (re)starts the auto-dismiss timer. Both
        // Connections handlers below call this and nothing else.
        function show(t, text) {
            tone = t
            toastText = text
            visible = true
            slideIn.stop()
            slideY.y = -18
            card.opacity = 0
            slideIn.start()
            errorTimer.restart()
        }
        function dismiss() { visible = false }

        // The card itself is inset from the window edges so it reads as a
        // floating pill rather than a full-width bar.
        Item {
            id: cardWrap
            anchors.horizontalCenter: parent.horizontalCenter
            width: Math.min(window.width - 24, 460)
            height: card.height
            transform: Translate { id: slideY; y: -18 }

            // Soft layered shadow: two offset, low-opacity rounded rectangles
            // stacked under the card fake a blurred drop shadow with no external
            // effects module (the whole project avoids GraphicalEffects).
            Rectangle {
                anchors.fill: card
                anchors.topMargin: 6
                anchors.leftMargin: 2
                anchors.rightMargin: 2
                radius: card.radius + 2
                color: window.pal.shadow
                opacity: card.opacity
            }
            Rectangle {
                anchors.fill: card
                anchors.topMargin: 2
                radius: card.radius
                color: window.pal.shadow
                opacity: card.opacity * 0.7
            }

            Rectangle {
                id: card
                width: parent.width
                height: Math.max(52, toastLabel.implicitHeight + 24)
                radius: 14
                // A vertical tone gradient (brighter on top) gives the toast a
                // little depth without a heavy flat block of colour.
                gradient: Gradient {
                    GradientStop {
                        position: 0.0
                        color: errorBar.isError ? window.pal.dangerHi : "#37b866"
                    }
                    GradientStop {
                        position: 1.0
                        color: errorBar.isError ? window.pal.danger : "#2e7d32"
                    }
                }

                // A thin gloss highlight along the very top edge.
                Rectangle {
                    anchors.top: parent.top
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.topMargin: 1
                    anchors.leftMargin: 10
                    anchors.rightMargin: 10
                    height: 1
                    radius: 1
                    color: Qt.rgba(1, 1, 1, 0.28)
                }

                Row {
                    anchors.fill: parent
                    anchors.leftMargin: 12
                    anchors.rightMargin: 14
                    spacing: 12

                    // Colour-coded icon chip on the leading edge.
                    Rectangle {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 30; height: 30
                        radius: 9
                        color: Qt.rgba(0, 0, 0, 0.22)
                        Label {
                            anchors.centerIn: parent
                            text: errorBar.isError ? "\u26A0" : "\u2713"
                            color: "white"
                            font.pixelSize: 16
                            font.bold: true
                        }
                    }

                    Label {
                        id: toastLabel
                        width: parent.width - 30 - 12
                        anchors.verticalCenter: parent.verticalCenter
                        text: errorBar.toastText
                        color: "white"
                        font.pixelSize: 13
                        font.weight: Font.DemiBold
                        wrapMode: Text.WordWrap
                        maximumLineCount: 4
                        elide: Text.ElideRight
                    }
                }
            }

            // Tap anywhere on the toast to dismiss it right away.
            MouseArea {
                anchors.fill: card
                onClicked: errorBar.dismiss()
            }
        }

        // Slide-down + fade-in on show. Runs the translate and the opacity
        // together so the card eases into place.
        ParallelAnimation {
            id: slideIn
            NumberAnimation {
                target: slideY; property: "y"
                from: -18; to: 0; duration: 260; easing.type: Easing.OutCubic
            }
            NumberAnimation {
                target: card; property: "opacity"
                from: 0; to: 1; duration: 220; easing.type: Easing.OutQuad
            }
        }

        Timer {
            id: errorTimer
            interval: 4000
            onTriggered: errorBar.dismiss()
        }
    }

    Connections {
        target: ChatClient
        function onErrorOccurred(message) {
            errorBar.show("error", message)
        }
        // Export success. exportConversation() emits exportFinished(peer, path).
        // 'path' is a real filesystem path on desktop and empty on Android (where
        // the file was written into a Storage Access Framework document we cannot
        // name), so show the location only when we actually have one. Reusing the
        // same toast in green gives the user visible confirmation the file was
        // written -- previously this signal had no handler, so a successful export
        // was silent.
        function onExportFinished(peer, path) {
            errorBar.show("success",
                (path && path.length > 0)
                    ? App.Localization.tIn(App.Localization.language, "export.done")
                          .arg(peer).arg(path)
                    : App.Localization.tIn(App.Localization.language, "export.saved")
                          .arg(peer))
        }
    }
}
