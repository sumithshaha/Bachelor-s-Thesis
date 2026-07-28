import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts
import ChatE2EE
import ChatE2EE as App

// The panel down the left side that lists people you can chat with. It shows
// EVERYONE the client knows -- online and offline -- so that an offline peer
// stays selectable and you can still send them messages/files (the server
// stores them and delivers on the peer's next login: offline delivery).
//
// Online state is shown per row (offline users are dimmed and labelled), driven
// by the model.online role. Tapping a name selects that person as the active
// conversation partner. Each row also shows an unread badge when a message or
// file arrives for a peer who is not the active conversation.
//
// RESTYLE NOTES (build-and-test-required -- not compiled here):
//   * Every contact now has a circular MONOGRAM AVATAR, tinted by a stable hash
//     of the name (so a given person keeps the same colour), with a small
//     presence dot in the corner. The row is a two-line layout: the name, and a
//     secondary line that reads "typing..." (accent) when the peer is composing,
//     otherwise "Online" / "Offline". The selected conversation is marked with a
//     rounded, accent-tinted highlight rather than the flat Material bar.
//   * The unread badge and all the typing-map plumbing are unchanged.

Pane {
    id: root
    padding: 0
    signal peerSelected(string name)

    property string selectedName: ""

    // TYPING BADGE: which peers are currently composing, as a name -> true map,
    // so each row can show a live "typing..." hint next to a contact even when
    // that conversation is not open. Maintained by the Connections block below
    // from the client's peerActivityChanged signal. A JS object is used (rather
    // than a Set) because QML property bindings re-evaluate cleanly on
    // reassignment; we replace the whole object so the rows update.
    property var typingPeers: ({})

    Connections {
        target: ChatClient
        // active=true when the peer starts typing/sending, false when idle. We
        // clone the map and reassign so bindings that read typingPeers[name]
        // re-evaluate. Rows reference (root.typingTick, ...) too, so a change is
        // always observed even though nested-object mutation is not reactive.
        function onPeerActivityChanged(peer, active) {
            var m = root.typingPeers
            if (active)
                m[peer] = true
            else
                delete m[peer]
            root.typingPeers = m
            root.typingTick++
        }
    }
    // Bumped on every typing change so per-row bindings have a reactive
    // dependency to re-evaluate (nested JS-object mutation alone is not
    // observed by QML). Mirrors the keyRefresh idiom used in ChatPage.
    property int typingTick: 0

    // ---- Avatar tint from the name -------------------------------------
    // A cheap, stable string hash mapped onto a hue, so every contact gets a
    // distinct-but-consistent avatar colour. Saturation/lightness are tuned per
    // brightness so monograms stay legible on both dark and light panels.
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

    // Themed panel background (was a fixed Material grey, which ignored the
    // per-user theme). window.pal.surface tracks the active preset.
    background: Rectangle { color: window.pal.surface }

    Column {
        anchors.fill: parent

        // ---- Panel header ------------------------------------------------
        Item {
            width: parent.width
            height: 46
            Label {
                anchors.left: parent.left
                anchors.leftMargin: 14
                anchors.verticalCenter: parent.verticalCenter
                // The list now includes offline contacts, so "Online" is no
                // longer an accurate header; "Contacts" reflects what is shown.
                text: App.Localization.tIn(App.Localization.language, "contacts.title")
                color: window.pal.text
                font.pixelSize: 13
                font.weight: Font.DemiBold
                font.letterSpacing: 0.4
            }
            // Hairline under the header.
            Rectangle {
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                height: 1
                color: window.pal.line
            }
        }

        ListView {
            id: list
            width: parent.width
            height: parent.height - 46
            clip: true
            model: ChatClient.users
            spacing: 2
            delegate: ItemDelegate {
                id: row
                width: ListView.view.width
                height: 62
                padding: 0
                // Do not let the user "chat with themselves".
                enabled: !model.isSelf
                // SWITCH USER (sense 2): highlight the row that is the ACTUAL
                // active conversation, read from the backend (ChatClient.activePeer)
                // rather than only a locally-remembered name. setActivePeer() can
                // change the active peer from the C++ side (e.g. on restore), and
                // binding the highlight to the authoritative value keeps "which
                // user am I talking to" unambiguous and always in sync.
                highlighted: model.name === ChatClient.activePeer
                onClicked: {
                    root.selectedName = model.name
                    root.peerSelected(model.name)
                }

                readonly property bool rowTyping:
                    (root.typingTick, root.typingPeers[model.name] === true)

                // ---- Selection / hover highlight --------------------------
                // A rounded, inset pill: an accent tint for the active
                // conversation, a faint surface tint on hover, transparent
                // otherwise. Replaces the flat, full-bleed Material highlight.
                background: Rectangle {
                    anchors.fill: parent
                    anchors.margins: 5
                    anchors.rightMargin: 7
                    anchors.leftMargin: 7
                    radius: 12
                    color: window.pal.accent
                    opacity: row.highlighted ? (window.dark ? 0.18 : 0.14)
                                             : (row.hovered ? (window.dark ? 0.08 : 0.06)
                                                            : 0.0)
                    Behavior on opacity { NumberAnimation { duration: 120 } }
                    // A slim accent bar on the leading edge of the active row.
                    Rectangle {
                        visible: row.highlighted
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        anchors.margins: 6
                        width: 3
                        radius: 1.5
                        color: window.pal.accent
                        opacity: 1.0
                    }
                }

                contentItem: RowLayout {
                    spacing: 12
                    anchors.fill: parent
                    anchors.leftMargin: 16
                    anchors.rightMargin: 14

                    // ---- Avatar -------------------------------------------
                    Item {
                        Layout.preferredWidth: 40
                        Layout.preferredHeight: 40
                        Layout.alignment: Qt.AlignVCenter
                        // Offline contacts (and self) read at reduced strength,
                        // so the online/offline state is legible at a glance while
                        // everyone stays selectable.
                        opacity: (model.isSelf || model.online) ? 1.0 : 0.55

                        Rectangle {
                            id: avatar
                            anchors.fill: parent
                            radius: width / 2
                            color: root.avatarColor(model.name)
                            // A soft top gloss on the circle.
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
                                text: root.monogram(model.name)
                                color: "white"
                                font.pixelSize: 17
                                font.weight: Font.DemiBold
                            }
                        }

                        // Presence dot in the bottom-right corner, ringed in the
                        // panel colour so it stands off the avatar.
                        Rectangle {
                            visible: !model.isSelf
                            width: 13; height: 13
                            radius: 6.5
                            anchors.right: parent.right
                            anchors.bottom: parent.bottom
                            anchors.rightMargin: -1
                            anchors.bottomMargin: -1
                            color: window.pal.surface
                            Rectangle {
                                anchors.centerIn: parent
                                width: 9; height: 9
                                radius: 4.5
                                color: model.online ? window.pal.online
                                                    : window.pal.textDim
                            }
                        }
                    }

                    // ---- Name + secondary line ----------------------------
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter
                        spacing: 2

                        Label {
                            Layout.fillWidth: true
                            text: model.isSelf ? (model.name + "  ("
                                  + App.Localization.tIn(App.Localization.language, "contacts.you") + ")")
                                               : model.name
                            color: window.pal.text
                            font.pixelSize: 14
                            font.weight: row.highlighted ? Font.DemiBold : Font.Medium
                            elide: Text.ElideRight
                        }
                        // Secondary line: a live "typing..." when composing,
                        // otherwise the online/offline word. Self shows nothing
                        // secondary.
                        Label {
                            Layout.fillWidth: true
                            visible: !model.isSelf
                            text: row.rowTyping
                                  ? App.Localization.tIn(App.Localization.language, "contacts.typing")
                                  : (model.online
                                     ? App.Localization.tIn(App.Localization.language, "online")
                                     : App.Localization.tIn(App.Localization.language, "contacts.offline"))
                            color: row.rowTyping ? window.pal.accent
                                                 : (model.online ? window.pal.online
                                                                 : window.pal.textDim)
                            font.pixelSize: 11
                            font.italic: row.rowTyping
                            elide: Text.ElideRight
                        }
                    }

                    // ---- Unread badge (beautiful) -------------------------
                    // A polished "pill" showing the number of unread texts + files
                    // for this contact (each arrival bumps it; opening the
                    // conversation clears it). model.unread already sums BOTH texts
                    // and files, so the count is "everything new from this person".
                    // A perfect circle for a single digit, growing into a pill for
                    // two or three, capped at "99+". Hidden at zero and while the
                    // peer is typing (the secondary line shows that instead).
                    //
                    // The look: a soft accent HALO breathes slowly behind the pill
                    // so an unread contact catches the eye without a harsh blink;
                    // the pill itself is a vertical accent gradient (brighter at the
                    // top) with a thin glossy highlight and a faint drop-shadow on
                    // the digits; and it gives a small scale "pop" the instant the
                    // count changes. All themed off the active preset's accent.
                    Item {
                        id: unreadWrap
                        readonly property bool showBadge: model.unread > 0 && !row.rowTyping
                        Layout.alignment: Qt.AlignVCenter
                        Layout.preferredWidth: showBadge ? badge.width : 0
                        Layout.preferredHeight: badge.height

                        opacity: showBadge ? 1 : 0
                        Behavior on opacity {
                            NumberAnimation { duration: 150; easing.type: Easing.OutQuad }
                        }

                        // Soft glow behind the pill. Declared BEFORE the pill so it
                        // draws underneath it. It breathes between faint and soft
                        // while there are unread items -- a slow, low-amplitude
                        // pulse that is noticeable but never distracting. Stops when
                        // the badge is hidden.
                        Rectangle {
                            id: halo
                            anchors.centerIn: badge
                            width: badge.width + 16
                            height: badge.height + 16
                            radius: height / 2
                            color: window.pal.accent
                            antialiasing: true
                            visible: unreadWrap.showBadge
                            opacity: 0.0
                            SequentialAnimation on opacity {
                                running: unreadWrap.showBadge
                                loops: Animation.Infinite
                                NumberAnimation {
                                    to: 0.30; duration: 950
                                    easing.type: Easing.InOutSine
                                }
                                NumberAnimation {
                                    to: 0.06; duration: 950
                                    easing.type: Easing.InOutSine
                                }
                            }
                        }

                        // The pill itself.
                        Rectangle {
                            id: badge
                            anchors.centerIn: parent
                            height: 24
                            width: Math.max(height, badgeText.implicitWidth + 16)
                            radius: height / 2
                            antialiasing: true
                            border.width: 1
                            border.color: window.pal.accentDim
                            gradient: Gradient {
                                GradientStop {
                                    position: 0.0
                                    color: Qt.lighter(window.pal.accent, 1.25)
                                }
                                GradientStop {
                                    position: 1.0
                                    color: window.pal.accentDim
                                }
                            }

                            // Thin glossy highlight along the top half for a subtle
                            // 3D "lift". Purely decorative.
                            Rectangle {
                                anchors.top: parent.top
                                anchors.topMargin: 2
                                anchors.horizontalCenter: parent.horizontalCenter
                                width: parent.width - 8
                                height: parent.height / 2 - 2
                                radius: height / 2
                                color: "white"
                                opacity: 0.20
                            }

                            // Faint drop-shadow of the digits, one pixel below, so
                            // the count stays crisp on lighter accents.
                            Label {
                                anchors.centerIn: parent
                                anchors.verticalCenterOffset: 1
                                text: badgeText.text
                                color: "black"
                                opacity: 0.22
                                font: badgeText.font
                            }
                            Label {
                                id: badgeText
                                anchors.centerIn: parent
                                text: model.unread > 99 ? "99+" : model.unread
                                color: "white"
                                font.pixelSize: 13
                                font.bold: true
                            }

                            // Pop on every change to the count (0->1 on first
                            // arrival, and 1->2->3... as more pile up), but only
                            // while the badge is actually shown, so clearing to
                            // zero does not animate.
                            property int popCount: model.unread
                            onPopCountChanged: if (unreadWrap.showBadge) popAnim.restart()
                            SequentialAnimation {
                                id: popAnim
                                NumberAnimation {
                                    target: badge; property: "scale"
                                    to: 1.25; duration: 120; easing.type: Easing.OutQuad
                                }
                                NumberAnimation {
                                    target: badge; property: "scale"
                                    to: 1.0; duration: 160; easing.type: Easing.OutBack
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
