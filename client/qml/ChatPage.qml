import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Dialogs
import ChatE2EE
// Localization singleton (see localization.h): every visible string is looked
// up as App.Localization.tIn(App.Localization.language, "key"). Reading the
// notifying `language` property *inside the binding expression* is what makes
// QML re-evaluate the binding when the language changes, so the whole UI
// relabels live. (A plain t("key") call would NOT do this: QML only tracks
// property reads that happen in the expression, and t() reads the active
// language inside C++ where the binding system cannot see it.)
import ChatE2EE as App
// The main chat screen, shown after login. Header shows who you are, the
// connection state, and the safety number for the active conversation, plus an
// overflow menu with "Switch user", "Log out", and now a theme picker. Below is
// the contact list beside the running conversation on wide screens, OR a
// full-screen list-then-conversation flow on a narrow phone.
//
// RESTYLE NOTES (build-and-test-required -- not compiled here):
//   * RESPONSIVE LAYOUT (fixes the portrait clipping on the S24 Ultra). The old
//     top-level RowLayout gave the fixed 128 px contact column a third of a
//     phone's width, squeezing the conversation -- so the safety-number banner,
//     the header, and the composer were cut off. Now:
//       - Wide (window.isPhone == false): unchanged side-by-side layout.
//       - Narrow (phone portrait): the contact list is FULL WIDTH; tapping a
//         contact reveals the conversation FULL WIDTH with a back arrow in the
//         header to return to the list. Everything gets the whole width, so
//         nothing clips.
//   * BIGGER COMPOSER. The message TextField now has a comfortable minimum
//     height, real padding, and grows to multiple lines -- easy to tap and type
//     on a phone, instead of the tiny default single-line box.
//   * PER-USER THEME PICKER added to the overflow menu (themeDialog), calling
//     ChatClient.setThemeIndex. The whole UI recolours live.
//   * All existing bindings/signals preserved verbatim: keyRefresh counter, the
//     peer-switch handler that must NOT call messages.clear(), the addSystem
//     file-failure wiring, the safety-number banner + send gate, both FileDialogs.

Page {
    id: root

    // Emitted when the user chooses Log out from the header menu.
    signal logoutRequested()

    background: Rectangle { color: window.pal.base }

    // ---- Avatar helpers (shared look with the contact list) ------------
    // A stable string-hash -> hue mapping so a nickname always gets the same
    // avatar tint, and its uppercased first letter as the monogram. Used for the
    // current user's chip in the header.
    function avatarColor(nm) {
        var h = 0
        for (var i = 0; i < nm.length; ++i)
            h = (h * 31 + nm.charCodeAt(i)) % 360
        return Qt.hsla(h / 360.0,
                       window.dark ? 0.42 : 0.55,
                       window.dark ? 0.48 : 0.52,
                       1.0)
    }
    function monogram(nm) {
        return nm.length > 0 ? nm.charAt(0).toUpperCase() : "?"
    }

    // Bumped whenever peer keys change (see Connections{onPeerKeysChanged}
    // below). The safety-number bindings reference it purely so they have a
    // reactive dependency to re-evaluate once a peer's key has arrived.
    property int keyRefresh: 0

    // TYPING INDICATOR: the live "typing…" / "sending a file…" line for the
    // OPEN conversation. Empty when the active peer is idle. Driven by the
    // Connections{onPeerTypingChanged} block below, filtered to the active peer
    // so a typing frame from a different conversation does not show here (that
    // one lights the contact-list badge instead). It is cleared whenever the
    // active peer changes.
    property string typingText: ""

    // FILE-TRANSFER PROGRESS (0.0-1.0) for the OPEN conversation's progress bar.
    // Driven by the top-level Connections{onFileSendProgress/onFileReceiveProgress}
    // block below. The progress bar itself (transferBar) lives INSIDE the
    // conversation-view Component, a separate QML scope whose ids are not visible
    // to that top-level Connections -- referencing `transferBar` from there threw
    // "ReferenceError: transferBar is not defined" and silently broke the bar.
    // Routing progress through this root property fixes that: the handlers write
    // root.transferProgress (always in scope), and transferBar.value binds to it
    // (a child in the same file can always read the root id's properties).
    property real transferProgress: 0.0

    // PHONE NAVIGATION STATE: on a narrow screen we show either the contact list
    // or the conversation, one at a time. This is true when the conversation
    // should be on screen (a peer is active AND we have "drilled in"). On a wide
    // screen it is unused -- both panels are always visible. Selecting a contact
    // sets it true; the header back arrow sets it false to return to the list.
    property bool showConversationOnPhone: false

    // SWITCH USER / block-until-verified: true when the ACTIVE peer's safety
    // number has changed and the user has not yet confirmed it. hasUnverifiedKeyChange
    // is a plain invokable (not a NOTIFYing property), so we cannot bind to it
    // directly and have it stay current; instead we recompute this flag whenever
    // the relevant signals fire (safetyNumberChanged / activePeerChanged), exactly
    // as the warning banner does. It drives the warning banner and the composer
    // placeholder hint -- the composer itself stays USABLE, and a message sent to
    // an unverified key is HELD (queued) by the backend's send gate in
    // ChatClient::sendMessage until both sides verify, rather than being blocked.
    property bool activePeerUnverified:
        ChatClient.activePeer.length > 0
        && ChatClient.hasUnverifiedKeyChange(ChatClient.activePeer)

    // UNILATERAL SEND GATE: true only while *I* have not yet verified this peer
    // (the backend now gates on my verification alone, never on the peer's). It
    // does NOT disable the composer. Messages/files composed while I am unverified
    // are HELD (queued) and flushed the moment I verify -- delivered even to an
    // OFFLINE peer via the server's store-and-forward, so nothing is lost and the
    // peer no longer has to be online-and-verified for me to send. Retained to
    // drive informational UI; recomputed on the same signals as activePeerUnverified.
    property bool conversationBlocked:
        ChatClient.activePeer.length > 0
        && ChatClient.conversationBlocked(ChatClient.activePeer)

    // True when I have already verified and am only waiting for the peer to verify
    // on their device. Drives the calm "waiting for the other person" banner. Purely
    // informational: because I have verified, my messages send normally (delivered
    // to the peer when they are online) -- they are NOT held for the peer's
    // verification. Only the pre-verification state (activePeerUnverified) holds.
    property bool awaitingPeerVerification:
        ChatClient.activePeer.length > 0
        && ChatClient.awaitingPeerVerification(ChatClient.activePeer)

    Connections {
        target: ChatClient
        function onSafetyNumberChanged(peer) {
            root.activePeerUnverified =
                ChatClient.activePeer.length > 0
                && ChatClient.hasUnverifiedKeyChange(ChatClient.activePeer)
            root.conversationBlocked =
                ChatClient.activePeer.length > 0
                && ChatClient.conversationBlocked(ChatClient.activePeer)
            root.awaitingPeerVerification =
                ChatClient.activePeer.length > 0
                && ChatClient.awaitingPeerVerification(ChatClient.activePeer)
        }
        function onActivePeerChanged() {
            root.activePeerUnverified =
                ChatClient.activePeer.length > 0
                && ChatClient.hasUnverifiedKeyChange(ChatClient.activePeer)
            root.conversationBlocked =
                ChatClient.activePeer.length > 0
                && ChatClient.conversationBlocked(ChatClient.activePeer)
            root.awaitingPeerVerification =
                ChatClient.activePeer.length > 0
                && ChatClient.awaitingPeerVerification(ChatClient.activePeer)
            // Switching conversations clears any typing line from the previous
            // peer; the new peer's line reappears only if a fresh typing frame
            // arrives for them.
            root.typingText = ""
            // On a phone, when the backend changes the active peer (e.g. restore
            // or a programmatic switch), drill into the conversation so the user
            // sees it; clearing the peer returns to the list.
            if (window.isPhone)
                root.showConversationOnPhone = (ChatClient.activePeer.length > 0)
        }
        // TYPING INDICATOR (conversation view): update the live line, but only
        // for the conversation currently open. A frame for any other peer is
        // ignored here (it drives the contact-list badge via UserListPanel's own
        // Connections). "sending_file" and "typing" map to friendly wording;
        // "idle" clears the line.
        function onPeerTypingChanged(peer, state) {
            // Only the open conversation's typing line lives here; a frame for
            // any other peer is ignored (it drives the contact-list badge).
            if (peer !== ChatClient.activePeer)
                return
            if (state === "typing")
                root.typingText = ChatClient.activePeer + " is typing\u2026"
            else if (state === "sending_file")
                root.typingText = ChatClient.activePeer + " is sending a file\u2026"
            else
                root.typingText = ""
        }
    }

    header: Rectangle {
        implicitHeight: 60
        color: window.pal.surface

        // Divider under the header: a hairline plus a faint accent-tinted glow
        // that fades out across the width, giving the bar a subtle signature edge
        // rather than a flat grey line.
        Rectangle {
            anchors.bottom: parent.bottom
            width: parent.width
            height: 1
            gradient: Gradient {
                orientation: Gradient.Horizontal
                GradientStop { position: 0.0; color: window.pal.accent }
                GradientStop { position: 0.6; color: window.pal.line }
                GradientStop { position: 1.0; color: window.pal.line }
            }
            opacity: 0.6
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 6
            spacing: 8

            // ---- Phone back arrow (return from conversation to list) ------
            // Only present on a phone while the conversation is showing. Tapping
            // it clears the drill-in flag so the full-width contact list returns.
            // Deselecting the peer would also work, but keeping the peer selected
            // means returning to it is instant and preserves unread behaviour.
            ToolButton {
                id: backButton
                visible: window.isPhone && root.showConversationOnPhone
                Layout.preferredWidth: visible ? 40 : 0
                text: "\u2039"                    // single left angle
                font.pixelSize: 26
                onClicked: root.showConversationOnPhone = false
                contentItem: Label {
                    text: backButton.text
                    color: window.pal.text
                    font.pixelSize: 26
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }

            // ---- Current-user avatar (monogram + live connection dot) ------
            Item {
                Layout.preferredWidth: 36
                Layout.preferredHeight: 36
                Layout.alignment: Qt.AlignVCenter
                Rectangle {
                    anchors.fill: parent
                    radius: width / 2
                    color: root.avatarColor(ChatClient.myNickname)
                    Rectangle {
                        anchors.fill: parent
                        radius: width / 2
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: Qt.rgba(1, 1, 1, 0.18) }
                            GradientStop { position: 0.55; color: Qt.rgba(1, 1, 1, 0.0) }
                        }
                    }
                    Label {
                        anchors.centerIn: parent
                        text: root.monogram(ChatClient.myNickname)
                        color: "white"
                        font.pixelSize: 15
                        font.weight: Font.DemiBold
                    }
                }
                // Connection dot, ringed in the header colour.
                Rectangle {
                    width: 12; height: 12; radius: 6
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    anchors.rightMargin: -1
                    anchors.bottomMargin: -1
                    color: window.pal.surface
                    Rectangle {
                        anchors.centerIn: parent
                        width: 8; height: 8; radius: 4
                        color: ChatClient.connected ? window.pal.online
                                                     : window.pal.textDim
                    }
                }
            }

            ColumnLayout {
                spacing: 3
                Label {
                    text: ChatClient.myNickname
                    color: window.pal.text
                    font.bold: true
                    font.pixelSize: 16
                }
                // Connection state as a small rounded pill: a dot plus the
                // online/reconnecting word, tinted by the live connection state.
                Rectangle {
                    implicitWidth: connRow.implicitWidth + 14
                    implicitHeight: connRow.implicitHeight + 6
                    radius: height / 2
                    color: ChatClient.connected
                           ? Qt.rgba(window.pal.online.r, window.pal.online.g,
                                     window.pal.online.b, window.dark ? 0.16 : 0.12)
                           : window.pal.surfaceHi
                    RowLayout {
                        id: connRow
                        anchors.centerIn: parent
                        spacing: 5
                        Rectangle {
                            width: 6; height: 6; radius: 3
                            Layout.alignment: Qt.AlignVCenter
                            color: ChatClient.connected ? window.pal.online
                                                         : window.pal.textDim
                        }
                        Label {
                            text: ChatClient.connected ? App.Localization.tIn(App.Localization.language, "online")
                                                 : App.Localization.tIn(App.Localization.language, "reconnecting")
                            color: ChatClient.connected ? window.pal.online
                                                        : window.pal.textDim
                            font.pixelSize: 11
                            font.weight: Font.Medium
                        }
                    }
                }
            }

            Item { Layout.fillWidth: true }

            // Pairwise safety number for the active conversation (falls back to
            // my own fingerprint when no peer is selected). Monospace: this is
            // the signature security element of the app. Hidden on a phone while
            // the contact list is showing (there is no active conversation to
            // fingerprint yet, and it keeps the list header uncluttered).
            // Pairwise safety number for the active conversation shown as a
            // tappable, accent-outlined monospace chip -- the signature security
            // element of the app given a distinct, pill-shaped home.
            Rectangle {
                visible: !(window.isPhone && !root.showConversationOnPhone)
                Layout.maximumWidth: window.isPhone ? 128 : 168
                implicitWidth: fpChipLabel.implicitWidth + 18
                implicitHeight: 26
                radius: height / 2
                color: window.dark ? Qt.rgba(window.pal.accent.r, window.pal.accent.g,
                                             window.pal.accent.b, 0.12)
                                   : Qt.rgba(window.pal.accent.r, window.pal.accent.g,
                                             window.pal.accent.b, 0.10)
                border.width: 1
                border.color: Qt.rgba(window.pal.accent.r, window.pal.accent.g,
                                      window.pal.accent.b, 0.45)
                Label {
                    id: fpChipLabel
                    anchors.centerIn: parent
                    width: parent.width - 16
                    text: (root.keyRefresh, ChatClient.activePeer.length > 0)
                          ? "\uD83D\uDD12 " + ChatClient.safetyNumberWith(ChatClient.activePeer)
                          : "\uD83D\uDD11 " + ChatClient.myFingerprint
                    color: window.pal.accent
                    font.family: "monospace"
                    font.pixelSize: 11
                    elide: Text.ElideRight
                }
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: fingerprintDialog.open()
                }
            }

            // ---- Overflow menu (theme, switch user, log out) ------------
            ToolButton {
                id: menuButton
                text: "\u22EE"                    // vertical ellipsis
                font.pixelSize: 20
                onClicked: headerMenu.open()
                contentItem: Label {
                    text: menuButton.text
                    color: window.pal.text
                    font.pixelSize: 20
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }

                Menu {
                    id: headerMenu
                    // IN-SCENE POPUP (fix for the "white strip hanging off the
                    // window edge" bug). Qt 6.10/6.11 changed the desktop
                    // default for Menu/Dialog to Popup.Window: each popup is
                    // rendered in its OWN top-level native window instead of
                    // inside the ApplicationWindow's scene. All the geometry in
                    // this file (x/y relative to items, widths derived from
                    // root.width, the modal dim) was written for in-scene
                    // popups, so under the new default a popup can end up as a
                    // detached white surface floating beside -- or mostly OFF --
                    // the app window, overlapping even the native title bar and
                    // ignoring the modal dim (the screenshot symptom: a
                    // full-height white sliver at the right edge). Forcing
                    // Popup.Item restores the pre-6.10 behaviour everywhere:
                    // popups render inside the window, are clipped by it, and
                    // sit under the Overlay dim exactly as designed. Applied to
                    // EVERY Menu and Dialog in the app.
                    popupType: Popup.Item
                    // Right-align the menu under its button. With no x the menu
                    // opens at the button's LEFT edge and grows rightward -- but
                    // the button is the last thing in the header, so the menu
                    // used to overflow past the window's right edge. Anchoring
                    // its right edge to the button's keeps it fully inside.
                    x: parent.width - width
                    y: menuButton.height

                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.viewSafety")
                        onTriggered: fingerprintDialog.open()
                    }
                    MenuItem {
                        // PER-USER THEME: open the preset picker. The chosen
                        // preset is saved per-nickname by the backend and the UI
                        // recolours live.
                        text: App.Localization.tIn(App.Localization.language, "menu.theme")
                        onTriggered: themeDialog.open()
                    }

                    // ---- LANGUAGE submenu (English / Suomi / Svenska) -------
                    // Each item sets Loc.language; because every visible string
                    // is Loc.t(...), the whole UI relabels live on selection. The
                    // active language is check-marked. Labels here are the
                    // languages' OWN names, so the menu is legible whatever the
                    // current language.
                    Menu {
                        id: languageMenu
                        popupType: Popup.Item   // in-scene, see headerMenu
                        title: App.Localization.tIn(App.Localization.language, "menu.language")

                        MenuItem {
                            text: "English"
                            checkable: true
                            checked: App.Localization.language === App.Localization.English
                            onTriggered: App.Localization.language = App.Localization.English
                        }
                        MenuItem {
                            text: "Suomi"
                            checkable: true
                            checked: App.Localization.language === App.Localization.Finnish
                            onTriggered: App.Localization.language = App.Localization.Finnish
                        }
                        MenuItem {
                            text: "Svenska"
                            checkable: true
                            checked: App.Localization.language === App.Localization.Swedish
                            onTriggered: App.Localization.language = App.Localization.Swedish
                        }
                    }

                    // ---- DARK / LIGHT MODE toggle ---------------------------
                    // A checkable item bound to ChatClient.darkMode. Toggling it
                    // flips window.dark (bound to the same property) and the whole
                    // UI recolours live. Persisted app-wide by the backend.
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.darkMode")
                        checkable: true
                        checked: ChatClient.darkMode
                        onTriggered: ChatClient.darkMode = checked
                    }

                    // ---- EXPORT the current conversation --------------------
                    // Enabled only when a conversation is open. Opens a small
                    // dialog to choose TXT or PDF, which then opens the system
                    // Save dialog. Disabled (greyed) with no active peer.
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.export")
                        enabled: ChatClient.activePeer.length > 0
                        onTriggered: exportChoiceDialog.open()
                    }

                    // ---- CREATE HOME-SCREEN SHORTCUT (Android) --------------
                    // Pins the active conversation to the launcher so the user
                    // can reopen it directly. Enabled only with a peer active. On
                    // desktop the backend call is a no-op that surfaces a gentle
                    // "not supported" message, so the item is harmless there.
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.shortcut")
                        enabled: ChatClient.activePeer.length > 0
                        onTriggered: ChatClient.createConversationShortcut()
                    }

                    // ---- APP LOCK (native unlock): enable / disable --------
                    // On Android (and Windows with Hello) the OS credential is
                    // the authenticator, so enabling is a direct toggle. On
                    // Windows WITHOUT Hello a fallback PIN is required, so we
                    // open the fallback-PIN dialog to enable. Disabling always
                    // clears the lock. "Lock now" shows the lock immediately.
                    MenuItem {
                        text: ChatClient.lockEnabled
                              ? App.Localization.tIn(App.Localization.language, "settings.disableLock")
                              : App.Localization.tIn(App.Localization.language, "settings.enableLock")
                        onTriggered: {
                            if (ChatClient.lockEnabled) {
                                ChatClient.setLockEnabled(false, "")
                            } else if (ChatClient.usesOsCredential) {
                                // Android / Windows-with-Hello: enable directly,
                                // the OS credential is the unlock.
                                ChatClient.setLockEnabled(true, "")
                            } else {
                                // Windows without Hello: need a fallback PIN.
                                pinDialog.open()
                            }
                        }
                    }
                    // A short line explaining what unlock will use, so the user
                    // knows whether it's their device lock or an app PIN.
                    MenuItem {
                        enabled: false
                        height: ChatClient.lockEnabled ? implicitHeight : 0
                        visible: ChatClient.lockEnabled
                        text: ChatClient.usesOsCredential
                              ? App.Localization.tIn(App.Localization.language, "settings.lockUsesDevice")
                              : (ChatClient.biometricAvailable
                                 ? App.Localization.tIn(App.Localization.language, "settings.lockUsesHello")
                                 : App.Localization.tIn(App.Localization.language, "settings.lockUsesPin"))
                    }
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "settings.lockNow")
                        enabled: ChatClient.lockEnabled
                        onTriggered: ChatClient.lockNow()
                    }

                    // ---- DIAGNOSTIC LOG viewer -----------------------------
                    // Opens the always-on in-app log. It carries THREE streams
                    // through one pipeline (the qInstallMessageHandler in
                    // main.cpp feeding LogBuffer): the app's own deep probes
                    // (the [LOCK]/ratchet DIAGNOSTIC lines), Qt's OWN runtime
                    // categories (qt.qpa/network/TLS/QML, opened by the filter
                    // rules in main.cpp), and the relay's server-side log,
                    // which the server streams to every logged-in client and
                    // chatclient.cpp re-emits under the [server] tag. The
                    // count in the label is the live number of captured lines.
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.logs")
                              + " (" + LogBuffer.count + ")"
                        onTriggered: logDialog.open()
                    }

                    MenuSeparator {}
                    MenuItem {
                        // SWITCH USER (sense 1): log out the current identity and
                        // return to the login screen so a DIFFERENT person can sign
                        // in under their own nickname. Mechanically this is the same
                        // teardown as Log out -- the backend preserves this user's
                        // identity key and history on disk, so switching back later
                        // restores everything -- but it is framed and confirmed as
                        // "switch to a different account" rather than "end session".
                        text: App.Localization.tIn(App.Localization.language, "menu.switchUser")
                        onTriggered: switchUserConfirm.open()
                    }
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.logout")
                        onTriggered: logoutConfirm.open()
                    }
                }
            }
        }
    }

    // ---- Log-out confirmation ------------------------------------------
    // Logout keeps identity + history; the same nickname logs back in with
    // everything intact. We still confirm, because it drops the live socket.
    Dialog {
        id: logoutConfirm
        popupType: Popup.Item   // in-scene, see headerMenu
        anchors.centerIn: parent
        modal: true
        title: App.Localization.tIn(App.Localization.language, "logout.title")
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: root.logoutRequested()

        Label {
            width: Math.min(root.width - 80, 280)
            wrapMode: Text.WordWrap
            color: window.pal.text
            text: "You'll return to the login screen. Your identity and message "
                + "history stay on this device, so logging back in as \""
                + ChatClient.myNickname + "\" restores everything."
        }
    }

    // ---- APP LOCK fallback-PIN setup (Windows without Hello) -----------
    // Reached only when enabling the lock on a platform where the OS credential
    // is NOT the authenticator (Windows without Windows Hello configured). Two
    // fields (new + confirm) must match; on OK we enable the lock with this PIN
    // as the fallback via ChatClient.setLockEnabled(true, pin). The PIN is stored
    // only as an Argon2id verifier and never unlocks the identity key. Changing
    // or removing it later is done by disabling the lock (password-resettable)
    // and re-enabling, so no separate current-PIN gate is needed here.
    Dialog {
        id: pinDialog
        popupType: Popup.Item   // in-scene, see headerMenu
        anchors.centerIn: parent
        modal: true
        padding: 20
        title: App.Localization.tIn(App.Localization.language, "settings.enableLock")
        standardButtons: Dialog.Cancel | Dialog.Ok

        // SOLID, SELF-DRAWN DIALOG SURFACE.
        // The visual bug this fixes: with the default Material `TextField`, the
        // OUTLINED container border is a rectangle whose top edge is notched to
        // seat the floating placeholder ("New PIN"/"Confirm PIN"). When a custom
        // text `color` is applied and the field sits in a tight dialog, that
        // notch does not clear, so the border STROKE runs straight through the
        // label text -- the "straight lines crossing the box" seen on device.
        // The cure is to stop relying on the Material outline+floating-label at
        // all: draw each field as the app's own boxed input (background: null on
        // the field, a rounded Rectangle around it, exactly like the composer),
        // and put each field's caption on its OWN line ABOVE the box, where no
        // stroke can ever cross it. We also give the Dialog a plain rounded
        // background so its title sits cleanly above the fields with real space,
        // never merging with a field frame.
        background: Rectangle {
            radius: 16
            color: window.pal.surface
            border.width: 1
            border.color: window.pal.line
        }
        header: Label {
            text: pinDialog.title
            color: window.pal.text
            font.pixelSize: 20
            font.bold: true
            elide: Label.ElideRight
            leftPadding: 20
            rightPadding: 20
            topPadding: 18
            bottomPadding: 6
        }

        onOpened: {
            newPin.text = ""
            confirmPin.text = ""
            pinMismatch.visible = false
            newPin.forceActiveFocus()
        }
        onAccepted: {
            if (newPin.text.length > 0 && newPin.text === confirmPin.text) {
                ChatClient.setLockEnabled(true, newPin.text)
            } else {
                pinMismatch.visible = true
                pinDialog.open()   // re-open: new/confirm mismatch
            }
        }

        ColumnLayout {
            width: Math.min(root.width - 80, 300)
            spacing: 14

            // ---- New PIN: caption ABOVE the box, then the boxed field --------
            Label {
                text: App.Localization.tIn(App.Localization.language, "settings.newPin")
                color: window.pal.textDim
                font.pixelSize: 12
                Layout.fillWidth: true
            }
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 46
                radius: 12
                color: Qt.rgba(window.pal.text.r, window.pal.text.g,
                               window.pal.text.b, window.dark ? 0.07 : 0.05)
                border.width: newPin.activeFocus ? 2 : 1
                border.color: newPin.activeFocus
                              ? window.pal.accent
                              : window.pal.line
                TextField {
                    id: newPin
                    anchors.fill: parent
                    verticalAlignment: TextInput.AlignVCenter
                    leftPadding: 12
                    rightPadding: 12
                    background: null   // the parent Rectangle IS the box
                    echoMode: TextInput.Password
                    inputMethodHints: Qt.ImhDigitsOnly
                    color: window.pal.text
                    Material.accent: window.pal.accent
                    onTextChanged: pinMismatch.visible = false
                    Keys.onReturnPressed: confirmPin.forceActiveFocus()
                }
            }

            // ---- Confirm PIN: same boxed pattern ----------------------------
            Label {
                text: App.Localization.tIn(App.Localization.language, "settings.confirmPin")
                color: window.pal.textDim
                font.pixelSize: 12
                Layout.fillWidth: true
                Layout.topMargin: 2
            }
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 46
                radius: 12
                color: Qt.rgba(window.pal.text.r, window.pal.text.g,
                               window.pal.text.b, window.dark ? 0.07 : 0.05)
                border.width: confirmPin.activeFocus ? 2 : 1
                border.color: confirmPin.activeFocus
                              ? window.pal.accent
                              : window.pal.line
                TextField {
                    id: confirmPin
                    anchors.fill: parent
                    verticalAlignment: TextInput.AlignVCenter
                    leftPadding: 12
                    rightPadding: 12
                    background: null
                    echoMode: TextInput.Password
                    inputMethodHints: Qt.ImhDigitsOnly
                    color: window.pal.text
                    Material.accent: window.pal.accent
                    onTextChanged: pinMismatch.visible = false
                    Keys.onReturnPressed: pinDialog.accept()
                }
            }

            Label {
                id: pinMismatch
                text: App.Localization.tIn(App.Localization.language, "settings.pinMismatch")
                color: window.pal.danger
                font.pixelSize: 12
                visible: false
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
        }
    }

    // ---- DIAGNOSTIC LOG screen -----------------------------------------
    // A live, always-on view of the app's deep probing traces. THREE streams
    // merge here through one pipeline -- the qInstallMessageHandler in main.cpp
    // feeding the LogBuffer singleton, which this ListView renders:
    //
    //   1. The app's own lines: every qDebug/qInfo/qWarning/qCritical (the
    //      [LOCK] lock/biometric lines, the ratchet and user-switch DIAGNOSTIC
    //      probes, connection events, ...).
    //   2. Qt's OWN runtime categories -- qt.qpa window/platform plumbing,
    //      qt.network/TLS (the wss handshake to the relay), QML engine and
    //      module resolution -- opened by the setFilterRules block in main.cpp
    //      ("extremely deep extended probing"), minus a few per-frame
    //      render/input firehoses excluded there so this view stays readable.
    //   3. The SERVER's log, tagged [server]: the relay streams its own ring
    //      (chat-server lines plus websockets/asyncio internals at DEBUG) to
    //      every logged-in client -- a snapshot at login, then live batches
    //      about once a second -- and chatclient.cpp re-emits each line
    //      through this same pipeline, so relay activity is visible on-device
    //      with no SSH session.
    //
    // Every record ALSO still reaches the console/logcat unchanged (the
    // handler chains to Qt's default first), so nothing that printed before
    // stops printing.
    //
    // The list auto-scrolls to the newest line only while the user is already
    // at (or near) the bottom; if they scroll up to read history, incoming
    // lines no longer yank the view down. "Copy all" puts the whole buffer on
    // the clipboard; "Clear" empties it.
    Dialog {
        id: logDialog
        popupType: Popup.Item   // in-scene, see headerMenu
        modal: true

        // SIZED AGAINST THE OVERLAY, NOT THE PAGE.
        //
        // The dialog used to take its size from `root`, the ChatPage. On the
        // desktop those are close enough to the same thing. On Android they are
        // not: the page can extend beneath the status and navigation bars, so
        // `root.height - 24` was taller than the area the user can actually
        // see, and centring inside it pushed the footer -- the row with Copy,
        // Clear and Close -- off the bottom of the screen. The buttons were
        // rendered; they were simply below the visible region.
        //
        // Overlay.overlay is the popup layer, which matches the window's
        // content area, so measuring against it keeps the whole dialog on
        // screen. The extra navBarGap on Android clears the gesture/navigation
        // bar, which overlaps the content area on modern devices.
        //
        // NOT named bottomInset. Popup declares topInset/bottomInset/leftInset/
        // rightInset as FINAL properties, and redeclaring a FINAL property is a
        // hard load error, not a warning:
        //     qt.qml.propertyCache.append: Final member bottomInset is
        //         overridden in class Dialog_QMLTYPE_36_QML_72
        //     ChatPage.qml:764:9: Cannot override FINAL property
        // The component then fails to instantiate, which takes the whole
        // application down rather than just this dialog.
        readonly property real availW: Overlay.overlay ? Overlay.overlay.width  : root.width
        readonly property real availH: Overlay.overlay ? Overlay.overlay.height : root.height
        readonly property real edgeGap:   Qt.platform.os === "android" ? 16 : 12
        readonly property real navBarGap: Qt.platform.os === "android" ? 28 : 0

        width:  Math.min(availW - edgeGap * 2, 900)
        height: Math.min(availH - edgeGap * 2 - navBarGap, 1200)
        x: (availW - width) / 2
        y: Math.max(edgeGap, (availH - height - navBarGap) / 2)
        padding: 0

        background: Rectangle {
            radius: 16
            color: window.pal.surface
            border.width: 1
            border.color: window.pal.line
        }

        // Whether the list is pinned to the bottom (auto-follow). Kept true
        // while the user is within a small slack of the end; set by the
        // ListView's own position tracking below.
        property bool followTail: true

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 14
            spacing: 10

            // ---- Header: title + live line count + actions ------------------
            RowLayout {
                Layout.fillWidth: true
                spacing: 8

                Label {
                    text: App.Localization.tIn(App.Localization.language, "log.title")
                    color: window.pal.text
                    font.pixelSize: 18
                    font.bold: true
                    Layout.fillWidth: true
                    elide: Label.ElideRight
                }
                Label {
                    text: LogBuffer.count + " "
                          + App.Localization.tIn(App.Localization.language, "log.lines")
                    color: window.pal.textDim
                    font.pixelSize: 12
                }
            }

            // ---- The log tail ----------------------------------------------
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                // The log area is the ONLY part allowed to absorb or give up
                // space. Without a minimum it can be squeezed to nothing on a
                // short screen; without being the sole filler, it would compete
                // with the footer and win, which is how the buttons vanished.
                Layout.minimumHeight: 96
                radius: 12
                color: window.dark ? Qt.rgba(0, 0, 0, 0.28)
                                   : Qt.rgba(0, 0, 0, 0.05)
                border.width: 1
                border.color: window.pal.line
                clip: true

                ListView {
                    id: logView
                    anchors.fill: parent
                    anchors.margins: 8
                    clip: true
                    model: LogBuffer
                    spacing: 2
                    // Cheap, smooth scrolling for a long buffer.
                    cacheBuffer: 400
                    boundsBehavior: Flickable.StopAtBounds

                    // Placeholder when nothing has been captured yet.
                    Label {
                        anchors.centerIn: parent
                        visible: LogBuffer.count === 0
                        text: App.Localization.tIn(App.Localization.language, "log.empty")
                        color: window.pal.textDim
                        font.pixelSize: 13
                    }

                    delegate: Label {
                        width: ListView.view.width
                        text: model.line
                        color: (model.level === "warning"
                                || model.level === "critical"
                                || model.level === "fatal")
                               ? window.pal.danger
                               : window.pal.text
                        wrapMode: Text.Wrap
                        textFormat: Text.PlainText
                        font.family: "monospace"
                        font.pixelSize: 12
                        opacity: (model.level === "debug") ? 0.92 : 1.0
                    }

                    // AUTO-FOLLOW: after the model grows, jump to the end only
                    // if the user was already near the bottom. We recompute the
                    // "near bottom" flag whenever the user moves the view.
                    onContentYChanged: {
                        var slack = 60
                        logDialog.followTail =
                            (contentY + height >= contentHeight - slack)
                    }
                    Connections {
                        target: LogBuffer
                        function onAppended() {
                            if (logDialog.followTail)
                                logView.positionViewAtEnd()
                        }
                    }
                    // On open, always start pinned to the newest line.
                    Component.onCompleted: positionViewAtEnd()
                }
            }

            // ---- Footer actions --------------------------------------------
            // A Flow, not a RowLayout. Three buttons plus a stretching spacer
            // cannot fit side by side on a phone, and a RowLayout does not wrap:
            // it compresses its children until the labels are clipped and the
            // last button is pushed past the right edge. The labels are
            // localised, and the Finnish and Swedish strings are longer than the
            // English ones, so the English layout fitting proved nothing.
            //
            // Flow keeps every button at its natural size and moves the ones
            // that do not fit onto the next line. On a desktop that is a single
            // row exactly as before; on a phone it becomes two, and the dialog
            // grows to suit because the Flow reports its real implicit height.
            Flow {
                Layout.fillWidth: true
                Layout.bottomMargin: logDialog.navBarGap
                spacing: 8

                Button {
                    text: App.Localization.tIn(App.Localization.language, "log.copyAll")
                    enabled: LogBuffer.count > 0
                    onClicked: {
                        logClipboardHelper.text = LogBuffer.asText()
                        logClipboardHelper.selectAll()
                        logClipboardHelper.copy()
                    }
                }
                Button {
                    text: App.Localization.tIn(App.Localization.language, "log.clear")
                    enabled: LogBuffer.count > 0
                    onClicked: LogBuffer.clear()
                }
                Button {
                    text: App.Localization.tIn(App.Localization.language, "log.close")
                    onClicked: logDialog.close()
                }
            }
        }

        // When the dialog is shown, snap to the tail and resume following.
        onOpened: {
            logDialog.followTail = true
            logView.positionViewAtEnd()
        }

        // Off-screen text control used only as a clipboard bridge for "Copy
        // all": QML has no direct clipboard API, but a TextEdit's copy() puts
        // its selected text on the system clipboard. It is 0-sized and never
        // interactive.
        TextEdit {
            id: logClipboardHelper
            visible: false
            width: 0
            height: 0
        }
    }

    // ---- Edit a message ------------------------------------------------
    // Opened from a text bubble's long-press "Edit". Pre-filled with the current
    // wording (set by the delegate's onEditRequested); confirming re-encrypts the
    // new text and updates the message in place on both devices. targetMid is the
    // stable id of the message being edited. Editing is online-only on the
    // backend, so an offline attempt is refused with a toast rather than silently
    // diverging the two sides.
    Dialog {
        id: editDialog
        popupType: Popup.Item   // in-scene, see headerMenu
        property string targetMid: ""
        anchors.centerIn: parent
        modal: true
        title: App.Localization.tIn(App.Localization.language, "edit.title")
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: {
            var t = editField.text.trim()
            if (editDialog.targetMid.length > 0 && t.length > 0)
                ChatClient.editMessage(editDialog.targetMid, t)
        }

        ColumnLayout {
            width: Math.min(root.width - 80, 340)
            spacing: 10

            TextArea {
                id: editField
                Layout.fillWidth: true
                Layout.preferredHeight: Math.max(72, implicitHeight)
                wrapMode: TextArea.Wrap
                color: window.pal.text
                Material.accent: window.pal.accent
                selectByMouse: true
                // Enter confirms; Shift+Enter inserts a newline, matching the
                // composer's convention.
                Keys.onReturnPressed: function(event) {
                    if (event.modifiers & Qt.ShiftModifier) {
                        event.accepted = false
                    } else {
                        event.accepted = true
                        editDialog.accept()
                    }
                }
            }
            Label {
                text: App.Localization.tIn(App.Localization.language, "edit.hint")
                color: window.pal.textDim
                font.pixelSize: 11
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                opacity: 0.85
            }
        }
    }

    // ---- Switch-user confirmation (sense 1) ----------------------------
    // Same teardown as Log out -- the backend preserves this user's identity key
    // and history on disk -- but framed as handing the app to a DIFFERENT person.
    // Accepting emits the same logoutRequested() the backend already handles,
    // returning to the login screen where the new user types their own nickname.
    // The current user's data is untouched, so they can switch back later and
    // find everything intact.
    Dialog {
        id: switchUserConfirm
        popupType: Popup.Item   // in-scene, see headerMenu
        anchors.centerIn: parent
        modal: true
        title: App.Localization.tIn(App.Localization.language, "switch.title")
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: root.logoutRequested()

        Label {
            width: Math.min(root.width - 80, 280)
            wrapMode: Text.WordWrap
            color: window.pal.text
            text: "This returns to the login screen so someone else can sign in "
                + "under their own name. \"" + ChatClient.myNickname + "\"'s "
                + "identity and messages stay saved on this device, so you can "
                + "switch back later and everything will be here."
        }
    }

    // ---- PER-USER THEME picker -----------------------------------------
    // Lists the presets defined in Main.qml (window.themes). Each row shows the
    // preset's name and a swatch of its accent; tapping applies it immediately
    // via ChatClient.setThemeIndex, which persists it for THIS user and emits
    // themeChanged so window.pal (and the whole UI) recolours live. The current
    // preset is marked. Closing needs no "save" -- selection applies on tap.
    Dialog {
        id: themeDialog
        popupType: Popup.Item   // in-scene, see headerMenu
        anchors.centerIn: parent
        modal: true
        title: App.Localization.tIn(App.Localization.language, "theme.title")
        standardButtons: Dialog.Close
        width: Math.min(root.width - 48, 340)

        ColumnLayout {
            width: parent.width
            spacing: 4

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: window.pal.textDim
                font.pixelSize: 12
                text: "Pick a colour theme. Your choice is saved for \""
                      + ChatClient.myNickname + "\" on this device."
            }

            Repeater {
                model: window.themes
                delegate: ItemDelegate {
                    Layout.fillWidth: true
                    highlighted: index === ChatClient.themeIndex
                    onClicked: ChatClient.setThemeIndex(index)

                    contentItem: RowLayout {
                        spacing: 12
                        // Accent swatch for this preset.
                        Rectangle {
                            width: 22; height: 22; radius: 6
                            color: modelData.accent
                            border.color: window.pal.line
                            border.width: 1
                        }
                        Label {
                            Layout.fillWidth: true
                            text: modelData.name
                            color: window.pal.text
                            font.pixelSize: 14
                            font.bold: index === ChatClient.themeIndex
                        }
                        // Check mark on the active preset.
                        Label {
                            visible: index === ChatClient.themeIndex
                            text: "\u2713"
                            color: window.pal.accent
                            font.pixelSize: 16
                            font.bold: true
                        }
                    }
                }
            }
        }
    }

    // ==================================================================
    //  BODY -- responsive.
    //  The contact list and the conversation are defined ONCE, as reusable
    //  components, then placed by whichever layout the width calls for:
    //    * wide  : side by side (list fixed width, conversation fills).
    //    * phone : one at a time, each full width; the header back arrow and
    //              showConversationOnPhone flag switch between them.
    //  Defining them as Components avoids duplicating the (substantial)
    //  conversation subtree, so there is a single source of truth for both.
    // ==================================================================

    // ---- The contact list panel (reused by both layouts) ---------------
    Component {
        id: contactListComponent
        UserListPanel {
            onPeerSelected: function(name) {
                // Setting activePeer triggers setActivePeer() in C++, which owns
                // repopulation: it clears the model and replays this peer's
                // stored history via loadConversation(). We must NOT call
                // ChatClient.messages.clear() here -- doing so would race that
                // reload and leave the conversation blank.
                ChatClient.activePeer = name
                // On a phone, drill into the conversation full-screen.
                if (window.isPhone)
                    root.showConversationOnPhone = true
            }
        }
    }

    // ---- The conversation panel (reused by both layouts) ---------------
    Component {
        id: conversationComponent
        ColumnLayout {
            spacing: 0

            Label {
                visible: ChatClient.activePeer.length > 0
                text: App.Localization.tIn(App.Localization.language, "conv.chattingWith").arg(ChatClient.activePeer)
                color: window.pal.textDim
                padding: 10
                font.pixelSize: 12
            }

            // ---- TYPING INDICATOR (conversation view) ------------------
            // A live "… is typing / sending a file" line just under the header.
            // Bound to root.typingText, which the Connections block keeps current
            // for the active peer only. Reserves no vertical space when idle
            // (height collapses) so the layout does not jump as it appears and
            // clears. The animated dots are a subtle three-phase opacity pulse.
            Item {
                Layout.fillWidth: true
                visible: root.typingText.length > 0
                implicitHeight: visible ? typingPill.implicitHeight + 8 : 0

                // A soft peer-side pill so the typing hint matches the bubble
                // styling rather than floating as bare text on the background.
                Rectangle {
                    id: typingPill
                    anchors.left: parent.left
                    anchors.leftMargin: 12
                    anchors.verticalCenter: parent.verticalCenter
                    radius: height / 2
                    color: window.pal.surfaceHi
                    border.width: 1
                    border.color: window.pal.line
                    implicitWidth: typingRow.implicitWidth + 24
                    implicitHeight: typingRow.implicitHeight + 12

                    RowLayout {
                        id: typingRow
                        anchors.centerIn: parent
                        spacing: 6

                        Label {
                            text: root.typingText
                            color: window.pal.accent
                            font.pixelSize: 12
                            font.italic: true
                        }
                        // Three pulsing dots, offset in phase, for a lively hint.
                        Row {
                            spacing: 3
                            Layout.alignment: Qt.AlignVCenter
                            Repeater {
                                model: 3
                                Rectangle {
                                    width: 5; height: 5; radius: 2.5
                                    color: window.pal.accent
                                    opacity: 0.3
                                    SequentialAnimation on opacity {
                                        running: root.typingText.length > 0
                                        loops: Animation.Infinite
                                        PauseAnimation { duration: index * 160 }
                                        NumberAnimation {
                                            to: 1.0; duration: 300
                                            easing.type: Easing.InOutQuad
                                        }
                                        NumberAnimation {
                                            to: 0.3; duration: 300
                                            easing.type: Easing.InOutQuad
                                        }
                                        PauseAnimation { duration: (2 - index) * 160 }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ---- SECURITY: safety-number-changed warning banner --------
            // A floating, rounded danger CARD rather than a full-bleed bar: soft
            // drop shadow, a warning icon chip, and a danger gradient. ALL of the
            // verification logic, visibility bindings, and the acknowledgeKeyChange
            // call are preserved verbatim -- only the framing is restyled.
            Item {
                id: keyChangeBanner
                Layout.fillWidth: true
                Layout.leftMargin: 10
                Layout.rightMargin: 10
                Layout.topMargin: 8
                visible: ChatClient.activePeer.length > 0
                         && ChatClient.hasUnverifiedKeyChange(ChatClient.activePeer)
                implicitHeight: keyCard.height

                Connections {
                    target: ChatClient
                    function onSafetyNumberChanged(peer) {
                        if (peer === ChatClient.activePeer)
                            keyChangeBanner.visible =
                                ChatClient.hasUnverifiedKeyChange(ChatClient.activePeer)
                    }
                    function onActivePeerChanged() {
                        keyChangeBanner.visible =
                            ChatClient.activePeer.length > 0
                            && ChatClient.hasUnverifiedKeyChange(ChatClient.activePeer)
                    }
                }

                // Soft drop shadow under the card.
                Rectangle {
                    anchors.fill: keyCard
                    anchors.topMargin: 4
                    radius: 16
                    color: window.pal.shadow
                    opacity: 0.5
                }

                Rectangle {
                    id: keyCard
                    width: parent.width
                    height: bannerCol.implicitHeight + 24
                    radius: 14
                    gradient: Gradient {
                        GradientStop { position: 0.0; color: window.pal.dangerHi }
                        GradientStop { position: 1.0; color: window.pal.danger }
                    }
                    // Top gloss line.
                    Rectangle {
                        anchors.top: parent.top
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.topMargin: 1
                        anchors.leftMargin: 12
                        anchors.rightMargin: 12
                        height: 1
                        color: Qt.rgba(1, 1, 1, 0.28)
                    }

                    ColumnLayout {
                        id: bannerCol
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.margins: 14
                        spacing: 8

                        // Title row: a warning icon chip beside the headline.
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 10
                            Rectangle {
                                Layout.preferredWidth: 30
                                Layout.preferredHeight: 30
                                Layout.alignment: Qt.AlignTop
                                radius: 9
                                color: Qt.rgba(0, 0, 0, 0.22)
                                Label {
                                    anchors.centerIn: parent
                                    text: "\u26A0"
                                    color: "white"
                                    font.pixelSize: 16
                                    font.bold: true
                                }
                            }
                            Label {
                                Layout.fillWidth: true
                                Layout.alignment: Qt.AlignVCenter
                                wrapMode: Text.WordWrap
                                color: "white"
                                font.bold: true
                                font.pixelSize: 14
                                text: ChatClient.activePeer +
                                      " may be a different person or device"
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            color: "white"
                            font.pixelSize: 12
                            lineHeight: 1.2
                            text: ChatClient.activePeer + "'s safety number changed. "
                                  + "This happens when they reinstall, switch device, "
                                  + "or a different person takes over this name -- but it "
                                  + "can also mean someone is intercepting your messages. "
                                  + "Compare the new safety number with " + ChatClient.activePeer
                                  + " over a call or in person, then confirm the switch to "
                                  + "continue. You cannot send messages until you do."
                        }
                        // Buttons wrap to their own full-width rows on a phone so
                        // their labels are never clipped; side by side on wide.
                        GridLayout {
                            Layout.fillWidth: true
                            columns: window.isPhone ? 1 : 2
                            rowSpacing: 8
                            columnSpacing: 8

                            Button {
                                id: keyViewButton
                                Layout.fillWidth: window.isPhone
                                Layout.preferredHeight: 40
                                text: "View safety number"
                                contentItem: Label {
                                    text: "View safety number"
                                    color: "white"
                                    font.weight: Font.Medium
                                    horizontalAlignment: Text.AlignHCenter
                                    verticalAlignment: Text.AlignVCenter
                                }
                                background: Rectangle {
                                    radius: 10
                                    color: keyViewButton.down ? Qt.rgba(1, 1, 1, 0.16)
                                                              : "transparent"
                                    border.width: 1.5
                                    border.color: Qt.rgba(1, 1, 1, 0.7)
                                }
                                onClicked: fingerprintDialog.open()
                            }
                            Button {
                                id: keyConfirmButton
                                Layout.fillWidth: window.isPhone
                                Layout.preferredHeight: 40
                                text: "I've verified \u2014 confirm & switch"
                                highlighted: true
                                contentItem: Label {
                                    text: "I've verified \u2014 confirm & switch"
                                    color: window.pal.danger
                                    font.weight: Font.DemiBold
                                    horizontalAlignment: Text.AlignHCenter
                                    verticalAlignment: Text.AlignVCenter
                                }
                                background: Rectangle {
                                    radius: 10
                                    color: keyConfirmButton.down ? Qt.rgba(1, 1, 1, 0.85)
                                                                 : "white"
                                }
                                onClicked: ChatClient.acknowledgeKeyChange(ChatClient.activePeer)
                            }
                        }
                    }
                }
            }

            // ---- BILATERAL VERIFICATION: waiting-for-peer banner -------
            // Shown after I have verified, while the peer has NOT yet verified on
            // their device. Calm and informational (not the red warning). The
            // composer stays USABLE: anything sent now is HELD (queued) by the
            // backend and delivered the moment the peer confirms, at which point
            // tryResolveBilateral() clears the state, safetyNumberChanged fires,
            // this banner hides, and the held messages flush out in order.
            Item {
                id: awaitingPeerBanner
                Layout.fillWidth: true
                Layout.leftMargin: 10
                Layout.rightMargin: 10
                Layout.topMargin: 8
                visible: ChatClient.activePeer.length > 0
                         && root.awaitingPeerVerification
                implicitHeight: awaitingCard.height

                Connections {
                    target: ChatClient
                    function onSafetyNumberChanged(peer) {
                        awaitingPeerBanner.visible =
                            ChatClient.activePeer.length > 0
                            && root.awaitingPeerVerification
                    }
                    function onActivePeerChanged() {
                        awaitingPeerBanner.visible =
                            ChatClient.activePeer.length > 0
                            && root.awaitingPeerVerification
                    }
                }

                // Soft drop shadow under the card.
                Rectangle {
                    anchors.fill: awaitingCard
                    anchors.topMargin: 4
                    radius: 16
                    color: window.pal.shadow
                    opacity: 0.4
                }

                Rectangle {
                    id: awaitingCard
                    width: parent.width
                    height: awaitingCol.implicitHeight + 24
                    radius: 14
                    color: window.pal.surfaceHi
                    border.width: 1
                    border.color: window.pal.line

                    // A rounded accent strip on the leading edge for a gentle
                    // "info" cue.
                    Rectangle {
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        anchors.topMargin: 6
                        anchors.bottomMargin: 6
                        anchors.leftMargin: 6
                        width: 3
                        radius: 1.5
                        color: window.pal.accent
                    }

                    ColumnLayout {
                        id: awaitingCol
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.leftMargin: 18
                        anchors.rightMargin: 14
                        spacing: 6

                        // Title row: an hourglass icon chip beside the headline.
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 10
                            Rectangle {
                                Layout.preferredWidth: 30
                                Layout.preferredHeight: 30
                                Layout.alignment: Qt.AlignVCenter
                                radius: 9
                                color: Qt.rgba(window.pal.accent.r, window.pal.accent.g,
                                               window.pal.accent.b, 0.15)
                                Label {
                                    anchors.centerIn: parent
                                    text: "\u23F3"
                                    font.pixelSize: 15
                                }
                            }
                            Label {
                                Layout.fillWidth: true
                                Layout.alignment: Qt.AlignVCenter
                                wrapMode: Text.WordWrap
                                color: window.pal.text
                                font.bold: true
                                font.pixelSize: 14
                                text: "Waiting for " + ChatClient.activePeer
                                      + " to verify"
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            color: window.pal.textDim
                            font.pixelSize: 12
                            lineHeight: 1.2
                            text: "You verified the safety number, so your messages "
                                  + "send normally \u2014 they'll reach "
                                  + ChatClient.activePeer
                                  + " as soon as they're online. "
                                  + ChatClient.activePeer
                                  + " hasn't verified you on their device yet; that's "
                                  + "their step and doesn't hold up your messages."
                        }
                        Button {
                            id: awaitingViewButton
                            Layout.alignment: Qt.AlignLeft
                            Layout.topMargin: 2
                            Layout.preferredHeight: 34
                            text: "View safety number"
                            contentItem: Label {
                                text: "View safety number"
                                color: window.pal.accent
                                font.weight: Font.DemiBold
                                font.pixelSize: 12
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                                leftPadding: 8
                                rightPadding: 8
                            }
                            background: Rectangle {
                                radius: 9
                                color: awaitingViewButton.down
                                       ? Qt.rgba(window.pal.accent.r, window.pal.accent.g,
                                                 window.pal.accent.b, 0.14)
                                       : "transparent"
                                border.width: 1.5
                                border.color: window.pal.accent
                            }
                            onClicked: fingerprintDialog.open()
                        }
                    }
                }
            }

            // ---- Empty-state when no peer is chosen --------------------
            // Only meaningful on a wide screen -- on a phone, "no peer" simply
            // shows the contact list instead of this panel.
            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: ChatClient.activePeer.length === 0

                ColumnLayout {
                    anchors.centerIn: parent
                    spacing: 14
                    width: Math.min(parent.width - 48, 300)

                    // Haloed padlock lockup, matching the login / lock screens, so
                    // the empty conversation reads as a calm, on-brand resting
                    // state rather than a lone dim glyph.
                    Item {
                        Layout.alignment: Qt.AlignHCenter
                        width: 72; height: 72
                        Rectangle {
                            anchors.centerIn: parent
                            width: 108; height: 108; radius: 30
                            color: window.pal.accent
                            opacity: 0.05
                        }
                        Rectangle {
                            anchors.centerIn: parent
                            width: 90; height: 90; radius: 24
                            color: window.pal.accent
                            opacity: 0.08
                        }
                        Rectangle {
                            anchors.fill: parent
                            radius: 18
                            gradient: Gradient {
                                GradientStop { position: 0.0; color: window.pal.surfaceHi }
                                GradientStop { position: 1.0; color: window.pal.surface }
                            }
                            border.width: 1
                            border.color: window.pal.line
                            Label {
                                anchors.centerIn: parent
                                text: "\uD83D\uDD10"
                                font.pixelSize: 34
                                opacity: 0.85
                            }
                        }
                    }
                    Label {
                        text: App.Localization.tIn(App.Localization.language, "conv.pickContact")
                        color: window.pal.textDim
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }

            ListView {
                id: messageView
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: ChatClient.activePeer.length > 0
                clip: true
                spacing: 6
                model: ChatClient.messages
                delegate: MessageDelegate {
                    onSaveFileRequested: function(msgId, filename) {
                        saveDialog.pendingMsgId = msgId
                        saveDialog.currentFile = "file:///" + filename
                        saveDialog.open()
                    }
                    // Deletion: route the delegate's request to the client. A
                    // local-only delete and a retract-for-everyone are distinct
                    // client calls; the delegate has already decided which the
                    // user picked (and only offers "for everyone" on own rows).
                    onDeleteRequested: function(mid, forEveryone) {
                        if (forEveryone)
                            ChatClient.deleteForEveryone(mid)
                        else
                            ChatClient.deleteForMe(mid)
                    }
                    // Reaction: the delegate has already decided the kind
                    // ("up" / "down" / "" to clear); the client echoes it into
                    // our view, persists it, and sends it to the peer.
                    onReactRequested: function(mid, kind) {
                        ChatClient.sendReaction(mid, kind)
                    }
                    // Edit: open the editor pre-filled with the message's current
                    // text; on confirm the client re-encrypts the new wording and
                    // updates it in place on both sides. Only our own text rows
                    // reach here (the delegate hides Edit otherwise).
                    onEditRequested: function(mid, currentText) {
                        editDialog.targetMid = mid
                        editField.text = currentText
                        editDialog.open()
                        editField.forceActiveFocus()
                    }
                    // Resend: send the same message again as a brand-new one. The
                    // client re-encrypts text or re-streams the original file.
                    onResendRequested: function(mid) {
                        ChatClient.resendMessage(mid)
                    }
                }
                ScrollBar.vertical: ScrollBar { id: vbar }

                // ---- AUTOSCROLL (Issue #3) --------------------------------
                // New messages should bring themselves into view. Two subtleties
                // are handled here:
                //   1. TIMING. positionViewAtEnd() called directly in
                //      onCountChanged often runs BEFORE the freshly-added,
                //      variable-height MessageDelegate has been laid out, so it
                //      lands short and the newest bubble sits just below the fold.
                //      Deferring with Qt.callLater() runs it after layout settles,
                //      so it reliably reaches the true bottom.
                //   2. STICKINESS. We only auto-scroll when the user is already
                //      near the bottom (atYEnd, or within a small threshold). If
                //      they have scrolled UP to read earlier messages, a new
                //      arrival must NOT yank them back down -- that would make
                //      history unreadable. When they are at the bottom (the normal
                //      case, including right after sending), it sticks.
                property bool atBottom: true

                function scrollToEnd() {
                    positionViewAtEnd()
                }

                // Track whether the view is currently at (or very near) the end,
                // sampled as the user scrolls, so we know whether to stick.
                onContentYChanged: {
                    // 8 px of slack so "practically at the bottom" still counts.
                    atBottom = atYEnd
                             || (contentHeight - (contentY + height) < 8)
                }

                // A new message arrived (or history loaded). If we were at the
                // bottom, defer a scroll-to-end until the new delegate is laid
                // out; otherwise leave the user where they are.
                onCountChanged: {
                    if (atBottom)
                        Qt.callLater(scrollToEnd)
                }

                // When the total content height changes (e.g. a bubble's text
                // wraps to more lines, or an image preview finishes loading and
                // grows), keep the bottom pinned if we were already there.
                onContentHeightChanged: {
                    if (atBottom)
                        Qt.callLater(scrollToEnd)
                }

                // When switching INTO a conversation, always start at the newest
                // message (C++ repopulates the model on activePeer change).
                Connections {
                    target: ChatClient
                    function onActivePeerChanged() {
                        messageView.atBottom = true
                        Qt.callLater(messageView.scrollToEnd)
                    }
                }
            }

            // ---- A thin progress bar shown during a file transfer ------
            // A slim, rounded accent-gradient bar on a muted track, inset to
            // match the floating cards. The value/visibility contract is
            // unchanged (onFileSendProgress / onFileReceiveProgress drive it).
            ProgressBar {
                id: transferBar
                Layout.fillWidth: true
                Layout.leftMargin: 10
                Layout.rightMargin: 10
                Layout.topMargin: 2
                visible: value > 0.0 && value < 1.0
                from: 0.0
                to: 1.0
                // Driven by root.transferProgress (see the property's declaration);
                // the backend's file-transfer signals update that property from the
                // top-level Connections, which cannot see this id directly.
                value: root.transferProgress
                padding: 0
                background: Rectangle {
                    implicitHeight: 5
                    radius: 2.5
                    color: window.pal.surfaceHi
                }
                contentItem: Item {
                    implicitHeight: 5
                    Rectangle {
                        width: transferBar.visualPosition * parent.width
                        height: parent.height
                        radius: 2.5
                        gradient: Gradient {
                            orientation: Gradient.Horizontal
                            GradientStop { position: 0.0; color: window.pal.accentDim }
                            GradientStop { position: 1.0; color: window.pal.accent }
                        }
                    }
                }
            }

            // ---- Composer (enlarged, multi-line) ----------------------
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: composerRow.implicitHeight + 20
                color: window.pal.surface
                Rectangle {
                    anchors.top: parent.top
                    width: parent.width; height: 1
                    color: window.pal.line
                }

                RowLayout {
                    id: composerRow
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 10

                    Button {
                        id: attachButton
                        Layout.preferredHeight: 46
                        Layout.preferredWidth: 46
                        Layout.alignment: Qt.AlignBottom
                        // The composer stays USABLE during a verification episode:
                        // a message/file composed while I have not yet verified the
                        // peer is HELD (queued) by the backend and flushed the moment
                        // I verify -- delivered even to an offline peer via
                        // store-and-forward, never dropped. Once I have verified,
                        // sending is immediate and the peer's own verification never
                        // gates it. So enable on an active peer alone; the banner +
                        // placeholder communicate the pre-verification hold.
                        enabled: ChatClient.activePeer.length > 0
                        onClicked: openDialog.open()
                        contentItem: Label {
                            text: "\uD83D\uDCCE"
                            font.pixelSize: 20
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                            opacity: attachButton.enabled ? 1.0 : 0.4
                        }
                        // A rounded, accent-tinted tile that deepens on hover /
                        // press, replacing the flat default so the attach action
                        // reads as a proper button.
                        background: Rectangle {
                            radius: 12
                            color: !attachButton.enabled
                                   ? "transparent"
                                   : attachButton.down
                                     ? Qt.rgba(window.pal.accent.r, window.pal.accent.g,
                                               window.pal.accent.b, 0.22)
                                     : attachButton.hovered
                                       ? Qt.rgba(window.pal.accent.r, window.pal.accent.g,
                                                 window.pal.accent.b, 0.14)
                                       : Qt.rgba(window.pal.accent.r, window.pal.accent.g,
                                                 window.pal.accent.b, 0.08)
                            Behavior on color { ColorAnimation { duration: 120 } }
                        }
                        ToolTip.visible: hovered
                        ToolTip.text: App.Localization.tIn(App.Localization.language, "composer.attachTip")
                    }

                    // The message field. Scrollable, grows from one line up to a
                    // few lines, with a comfortable minimum height and padding so
                    // it is easy to tap and read on a phone. This replaces the
                    // tiny default single-line TextField.
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignBottom
                        radius: 12
                        color: window.pal.base
                        border.color: input.activeFocus ? window.pal.accent
                                                        : window.pal.line
                        border.width: 1
                        // Grow with the text between a 1-line minimum and a
                        // ~5-line maximum, then the inner Flickable scrolls.
                        implicitHeight: Math.max(48,
                                        Math.min(inputArea.implicitHeight + 20, 140))

                        ScrollView {
                            id: inputArea
                            anchors.fill: parent
                            anchors.margins: 4
                            clip: true

                            TextArea {
                                id: input
                                wrapMode: TextArea.Wrap
                                color: window.pal.text
                                font.pixelSize: 15
                                leftPadding: 10
                                rightPadding: 10
                                topPadding: 8
                                bottomPadding: 8
                                background: null   // the parent Rectangle IS the box
                                placeholderText:
                                    ChatClient.activePeer.length === 0
                                        ? "Pick someone to chat with"
                                        : root.activePeerUnverified
                                            ? "Type a message (held until you verify)\u2026"
                                            : "Type a message\u2026"
                                placeholderTextColor: window.pal.textDim
                                // Enabled on an active peer alone. A message typed
                                // while I have not yet verified this peer is HELD
                                // (queued) and flushed the moment I verify -- sent
                                // even to an offline peer via store-and-forward,
                                // never dropped -- so the field must stay usable.
                                // Once I have verified, sending is immediate; the
                                // peer's own verification never gates my sending.
                                enabled: ChatClient.activePeer.length > 0
                                Material.accent: window.pal.accent
                                // TYPING INDICATOR: tell the peer we are
                                // composing on each change. notifyTyping() is
                                // debounced in C++ -- it sends one "typing" frame
                                // and re-arms an idle timer, so this fires per
                                // keystroke cheaply. We only signal when there is
                                // actually text, so clearing the field (e.g.
                                // after send) does not emit a spurious "typing".
                                onTextChanged: {
                                    if (input.text.length > 0)
                                        ChatClient.notifyTyping(false)
                                }
                                // Enter sends; Shift+Enter inserts a newline. On a
                                // touch keyboard the Send button is the primary path,
                                // but this keeps desktop parity with the old field.
                                Keys.onReturnPressed: function(event) {
                                    if (event.modifiers & Qt.ShiftModifier) {
                                        event.accepted = false   // newline
                                    } else {
                                        event.accepted = true
                                        if (sendButton.enabled)
                                            sendButton.clicked()
                                    }
                                }
                            }
                        }
                    }

                    Button {
                        id: sendButton
                        Layout.preferredHeight: 46
                        Layout.alignment: Qt.AlignBottom
                        text: App.Localization.tIn(App.Localization.language, "composer.send")
                        highlighted: true
                        // Enabled on non-empty text alone. A send to an unverified/
                        // rekeyed peer is HELD (queued) and delivered once both
                        // sides verify -- see attachButton -- so blocking the button
                        // would only lose the very messages we want to hold.
                        enabled: input.text.trim().length > 0
                        onClicked: {
                            ChatClient.sendMessage(input.text.trim())
                            input.clear()
                        }
                        contentItem: Label {
                            text: sendButton.text
                            color: sendButton.enabled ? window.pal.base
                                                       : window.pal.textDim
                            font.pixelSize: 15
                            font.weight: Font.DemiBold
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        // Raised accent gradient with a thin gloss edge, flattening
                        // to accentDim on press; muted when disabled.
                        background: Rectangle {
                            radius: 12
                            implicitWidth: 76
                            color: !sendButton.enabled ? window.pal.surfaceHi
                                   : sendButton.down    ? window.pal.accentDim
                                                        : "transparent"
                            gradient: (sendButton.enabled && !sendButton.down)
                                      ? sendGrad : null
                            Gradient {
                                id: sendGrad
                                GradientStop { position: 0.0; color: window.pal.accentHi }
                                GradientStop { position: 1.0; color: window.pal.accent }
                            }
                            Behavior on color { ColorAnimation { duration: 120 } }
                            Rectangle {
                                visible: sendButton.enabled && !sendButton.down
                                anchors.top: parent.top
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.topMargin: 1
                                anchors.leftMargin: 8
                                anchors.rightMargin: 8
                                height: 1
                                color: Qt.rgba(1, 1, 1, 0.28)
                            }
                        }
                    }
                }
            }
        }
    }

    // ==================================================================
    //  The responsive placement of the two components above.
    // ==================================================================

    // ---- WIDE (desktop / landscape): side by side ----------------------
    RowLayout {
        anchors.fill: parent
        visible: !window.isPhone
        spacing: 0

        Loader {
            active: !window.isPhone
            sourceComponent: contactListComponent
            Layout.preferredWidth: 150
            Layout.fillHeight: true
        }

        Rectangle { Layout.fillHeight: true; width: 1; color: window.pal.line }

        Loader {
            active: !window.isPhone
            sourceComponent: conversationComponent
            Layout.fillWidth: true
            Layout.fillHeight: true
        }
    }

    // ---- PHONE (portrait): one panel at a time, full width -------------
    // The contact list fills the screen; tapping a contact drills into the
    // conversation full-width; the header back arrow returns to the list. Only
    // one Loader is active at a time so the off-screen subtree is not built.
    Item {
        anchors.fill: parent
        visible: window.isPhone

        Loader {
            anchors.fill: parent
            active: window.isPhone && !root.showConversationOnPhone
            sourceComponent: contactListComponent
        }

        Loader {
            anchors.fill: parent
            active: window.isPhone && root.showConversationOnPhone
            sourceComponent: conversationComponent
        }
    }

    // ---- File chooser for SENDING --------------------------------------
    FileDialog {
        id: openDialog
        title: "Choose a file to send"
        fileMode: FileDialog.OpenFile
        onAccepted: ChatClient.sendFile(selectedFile)
    }

    // ---- File chooser for SAVING a received file -----------------------
    FileDialog {
        id: saveDialog
        property string pendingMsgId: ""
        title: "Save file as"
        fileMode: FileDialog.SaveFile
        onAccepted: {
            if (pendingMsgId.length > 0)
                ChatClient.saveReceivedFile(pendingMsgId, selectedFile)
            pendingMsgId = ""
        }
    }

    // ---- EXPORT: choose the format (TXT or PDF) ------------------------
    // Opened from the overflow menu's "Export chat" item (enabled only when a
    // conversation is open). Picking a format opens the system Save dialog with
    // a sensible default filename; the write happens in exportConversation once
    // the user confirms a destination. defaultBase() is a method ON THE DIALOG
    // (not a child item) so it is in scope for both format buttons.
    Dialog {
        id: exportChoiceDialog
        popupType: Popup.Item   // in-scene, see headerMenu
        anchors.centerIn: parent
        modal: true
        width: Math.min(root.width - 48, 320)
        title: App.Localization.tIn(App.Localization.language, "export.title").arg(ChatClient.activePeer)
        standardButtons: Dialog.Cancel

        // "chat-with-<peer>-<YYYYMMDD-HHMM>" -- the extension is appended per
        // format when the save dialog opens.
        function defaultBase() {
            var d = new Date()
            function p(n) { return (n < 10 ? "0" : "") + n }
            var stamp = "" + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate())
                      + "-" + p(d.getHours()) + p(d.getMinutes())
            return "chat-with-" + ChatClient.activePeer + "-" + stamp
        }

        // Open the system Save dialog for a given format, with the right filter
        // and default filename. Kept as a method so both buttons share it.
        function beginSave(fmt, ext) {
            exportSaveDialog.chosenFormat = fmt
            exportSaveDialog.nameFilters =
                [ fmt === "pdf" ? App.Localization.tIn(App.Localization.language, "export.pdf")
                                : App.Localization.tIn(App.Localization.language, "export.txt") ]
            exportSaveDialog.currentFile =
                "file:///" + exportChoiceDialog.defaultBase() + ext
            exportChoiceDialog.close()
            exportSaveDialog.open()
        }

        ColumnLayout {
            width: parent.width
            spacing: 10

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: window.pal.textDim
                font.pixelSize: 12
                text: App.Localization.tIn(App.Localization.language, "export.title").arg(ChatClient.activePeer)
            }

            Button {
                Layout.fillWidth: true
                highlighted: true
                text: App.Localization.tIn(App.Localization.language, "export.txt")
                onClicked: exportChoiceDialog.beginSave("txt", ".txt")
            }
            Button {
                Layout.fillWidth: true
                text: App.Localization.tIn(App.Localization.language, "export.pdf")
                onClicked: exportChoiceDialog.beginSave("pdf", ".pdf")
            }
        }
    }

    // ---- EXPORT: the system Save dialog -------------------------------
    // One SaveFile dialog reused for both formats; chosenFormat carries which
    // the user picked so onAccepted calls exportConversation with the right one.
    FileDialog {
        id: exportSaveDialog
        property string chosenFormat: "txt"
        title: App.Localization.tIn(App.Localization.language, "export.title").arg(ChatClient.activePeer)
        fileMode: FileDialog.SaveFile
        onAccepted: {
            if (ChatClient.activePeer.length > 0)
                ChatClient.exportConversation(ChatClient.activePeer,
                                              chosenFormat, selectedFile)
        }
    }

    // ---- React to file-transfer signals from the backend --------------
    // These write root.transferProgress (in scope here); transferBar, which lives
    // in the conversation-view Component, binds its value to that property. See
    // the transferProgress declaration above for why the id cannot be touched
    // directly from this top-level Connections.
    Connections {
        target: ChatClient
        function onPeerKeysChanged() { root.keyRefresh++ }
        function onFileSendProgress(msgId, fraction) {
            root.transferProgress = fraction
        }
        function onFileReceiveProgress(msgId, fraction) {
            root.transferProgress = fraction
        }
        function onFileReceiveFailed(msgId, reason) {
            ChatClient.messages.addSystem("File transfer failed: " + reason)
            root.transferProgress = 0.0
        }
    }

    // Dialog that shows the safety number for the CURRENT conversation, large
    // enough to read aloud.
    Dialog {
        id: fingerprintDialog
        popupType: Popup.Item   // in-scene, see headerMenu
        anchors.centerIn: parent
        modal: true
        width: Math.min(root.width - 48, 340)
        title: ChatClient.activePeer.length > 0
               ? App.Localization.tIn(App.Localization.language, "safety.titlePeer").arg(ChatClient.activePeer)
               : App.Localization.tIn(App.Localization.language, "safety.titleSelf")
        standardButtons: Dialog.Ok
        ColumnLayout {
            width: parent.width
            spacing: 12
            Label {
                color: window.pal.text
                text: ChatClient.activePeer.length > 0
                      ? "Compare these numbers with " + ChatClient.activePeer +
                        " over a call or in person.\nIf they match on both devices, no one is intercepting your keys."
                      : "Select a contact to see the safety number you share with them."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: fpNumber.implicitHeight + 24
                radius: 10
                color: window.pal.base
                border.color: window.pal.line
                border.width: 1
                Label {
                    id: fpNumber
                    anchors.centerIn: parent
                    width: parent.width - 24
                    horizontalAlignment: Text.AlignHCenter
                    text: (root.keyRefresh, ChatClient.activePeer.length > 0)
                          ? ChatClient.safetyNumberWith(ChatClient.activePeer)
                          : ChatClient.myFingerprint
                    color: window.pal.accent
                    font.pixelSize: 20
                    font.family: "monospace"
                    wrapMode: Text.WrapAnywhere
                }
            }
        }
    }
}
