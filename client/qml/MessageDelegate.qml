import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts
import ChatE2EE
import ChatE2EE as App

// MessageDelegate decides how a single row in the message list looks. Cases:
// a system note (centred, faint), a text bubble (accent right / surface left),
// and a file bubble -- which shows an inline image preview when the file is an
// image, or a file row with a Save button otherwise.
//
// RESTYLE NOTES (build-and-test-required -- not compiled here):
//   * Bubbles use the shared palette (window.pal.*). "Mine" is now a VERTICAL
//     accent GRADIENT (a lifted accentHi at the top easing to the accent at the
//     bottom) with dark text; the peer's is a raised surface with a hairline
//     border and light text. Each bubble carries a small "tail": three rounded
//     corners plus one tight corner on the side nearest its sender (Qt 6.7+
//     per-corner radius), the classic speech-bubble silhouette. A soft, blur-
//     free drop shadow (two stacked low-opacity rounded rectangles) lifts every
//     bubble off the background -- no GraphicalEffects module needed, matching
//     the rest of the project.
//   * The image-source gating fix is preserved EXACTLY: source is gated on the
//     same isImage check as visibility, so a non-image file is never fed to the
//     image decoder. The preview now sits in a rounded, bordered frame.
//   * A received file is shown as a tidy attachment CHIP (a document glyph in an
//     accent-tinted tile, the filename, and the size) with a compact rounded
//     Save button. saveFileRequested(msgId, filename) is preserved verbatim.
//
// MESSAGE DELETION (unchanged behaviour, restyled):
//   * A long-press (or right-click) on a bubble opens a context menu. Every
//     message offers "Delete for me"; only our OWN messages also offer "Delete
//     for everyone". The delegate does not act itself -- it emits
//     deleteRequested(mid, forEveryone) up to ChatPage, which calls the client.
//   * A tombstoned row (model.isDeleted) renders a fixed, italic, muted
//     "This message was deleted" placeholder: no bubble accent emphasis, no
//     file/image content, no Save button, no long-press menu. The model already
//     substitutes the placeholder text and suppresses file roles when deleted,
//     so the delegate mainly needs to drop the interactive affordances.
Item {
    id: delegate
    width: ListView.view ? ListView.view.width : 0
    implicitHeight: content.implicitHeight + 8

    signal saveFileRequested(string msgId, string filename)
    // Emitted when the user chooses a deletion action from the long-press menu.
    // forEveryone=false is a local-only delete; true is a retract-for-both.
    // ChatPage handles this and calls the appropriate ChatClient method.
    signal deleteRequested(string mid, bool forEveryone)
    // Emitted when the user picks an agree / disagree (or "remove reaction")
    // from the long-press menu. kind is "up", "down", or "" to clear. ChatPage
    // routes this to ChatClient.sendReaction, which echoes it locally and sends
    // it to the peer.
    signal reactRequested(string mid, string kind)
    // Emitted when the user chooses Edit on one of their OWN text messages. The
    // delegate hands over the message id and its CURRENT text so ChatPage can
    // pre-fill the edit box; on confirm ChatPage calls ChatClient.editMessage.
    signal editRequested(string mid, string currentText)
    // Emitted when the user chooses Resend on one of their OWN messages (text or
    // file). ChatPage routes this to ChatClient.resendMessage, which sends the
    // same content again as a brand-new message.
    signal resendRequested(string mid)

    readonly property bool mine: model.isMine
    readonly property bool deleted: model.isDeleted === true

    // ---- System note ---------------------------------------------------
    // A centred, faint chip rather than bare text, so status lines (safety
    // number changes, "file transfer failed", and the like) read as a distinct
    // divider between messages instead of floating loosely in the transcript.
    Item {
        visible: model.isSystem
        anchors.horizontalCenter: parent.horizontalCenter
        width: parent.width
        implicitHeight: model.isSystem ? sysChip.implicitHeight + 10 : 0

        Rectangle {
            id: sysChip
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.verticalCenter: parent.verticalCenter
            width: Math.min(delegate.width - 48, sysLabel.implicitWidth + 24)
            implicitHeight: sysLabel.implicitHeight + 12
            radius: height / 2
            color: window.pal.surfaceHi
            border.width: 1
            border.color: window.pal.line
            opacity: 0.92

            Label {
                id: sysLabel
                anchors.centerIn: parent
                width: parent.width - 20
                horizontalAlignment: Text.AlignHCenter
                text: model.text
                color: window.pal.textDim
                font.pixelSize: 11
                font.italic: true
                wrapMode: Text.WordWrap
            }
        }
    }

    // ---- A chat bubble -------------------------------------------------
    Row {
        id: content
        visible: !model.isSystem
        anchors.right: delegate.mine ? parent.right : undefined
        anchors.left: delegate.mine ? undefined : parent.left
        anchors.rightMargin: 12
        anchors.leftMargin: 12

        Item {
            // A wrapper sized to the bubble so the shadow rectangles can be
            // anchored to it behind the bubble without affecting its layout.
            id: bubbleBox
            implicitWidth: bubble.implicitWidth
            implicitHeight: bubble.implicitHeight

            // ---- Soft drop shadow (two stacked offset rounds) ----------
            // Blur-free depth: a wider, fainter round sits lowest and a tighter,
            // slightly stronger one above it, so the bubble appears to float a
            // couple of pixels off the background. Suppressed on tombstones,
            // which are meant to look flat and inert.
            Rectangle {
                visible: !delegate.deleted
                anchors.fill: bubble
                anchors.topMargin: 5
                anchors.leftMargin: 1
                anchors.rightMargin: 1
                radius: 16
                color: window.pal.shadow
                opacity: 0.55
            }
            Rectangle {
                visible: !delegate.deleted
                anchors.fill: bubble
                anchors.topMargin: 2
                radius: 16
                color: window.pal.shadow
                opacity: 0.7
            }

            Rectangle {
                id: bubble
                // Per-corner radius (Qt 6.7+, available on the project's Qt 6.11)
                // gives the speech-bubble tail: rounded everywhere except the
                // bottom corner on the sender's side. A tombstone stays fully,
                // evenly rounded and flat.
                radius: 16
                bottomRightRadius: (!delegate.deleted && delegate.mine) ? 5 : 16
                bottomLeftRadius:  (!delegate.deleted && !delegate.mine) ? 5 : 16

                implicitWidth: Math.min(bubbleColumn.implicitWidth + 22,
                                        delegate.width * 0.78)
                implicitHeight: bubbleColumn.implicitHeight + 16

                // A tombstone uses a flat, muted surface regardless of sender, so
                // a deleted message does not keep the accent emphasis of a live
                // one. A live "mine" bubble is a vertical accent gradient; the
                // peer's is a single raised surface tone.
                color: delegate.deleted ? window.pal.surface
                                        : (delegate.mine ? "transparent"
                                                         : window.pal.surfaceHi)
                gradient: (!delegate.deleted && delegate.mine)
                          ? mineGradient : null

                Gradient {
                    id: mineGradient
                    GradientStop { position: 0.0; color: window.pal.accentHi }
                    GradientStop { position: 1.0; color: window.pal.accent }
                }

                // A hairline border: on the peer's bubble it defines the edge
                // against the background; on a tombstone it is a faint outline.
                border.width: (delegate.mine && !delegate.deleted) ? 0 : 1
                border.color: delegate.deleted ? window.pal.line
                                               : window.pal.line

                readonly property color bodyText: delegate.mine && !delegate.deleted
                                                  ? window.pal.base
                                                  : window.pal.text
                readonly property color metaText: delegate.mine && !delegate.deleted
                                                  ? window.pal.base
                                                  : window.pal.textDim

                // A thin gloss highlight along the top of "my" bubble, echoing
                // the light-from-above sheen used on buttons and badges.
                Rectangle {
                    visible: delegate.mine && !delegate.deleted
                    anchors.top: parent.top
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.topMargin: 1
                    anchors.leftMargin: 10
                    anchors.rightMargin: 10
                    height: 1
                    color: Qt.rgba(1, 1, 1, 0.22)
                }

                // Long-press / right-click to open the deletion menu. Disabled
                // for a row that is already a tombstone (nothing left to delete)
                // and for system rows (this bubble is not shown for them anyway).
                MouseArea {
                    anchors.fill: parent
                    enabled: !delegate.deleted
                    acceptedButtons: Qt.LeftButton | Qt.RightButton
                    onPressAndHold: if (!delegate.deleted) deleteMenu.open()
                    onClicked: function(mouse) {
                        if (mouse.button === Qt.RightButton && !delegate.deleted)
                            deleteMenu.open()
                    }
                }

                Menu {
                    id: deleteMenu
                    // IN-SCENE POPUP: Qt 6.10/6.11's desktop default renders
                    // Menus/Dialogs as separate top-level windows, which can
                    // float detached from (or mostly outside) the app window.
                    // Popup.Item restores the in-window behaviour this layout
                    // was written for. Same fix as headerMenu in ChatPage.qml.
                    popupType: Popup.Item
                    // ---- Edit / Resend (own messages) ------------------
                    // Edit is offered only on our OWN text messages (a file's
                    // bytes can't be edited); Resend is offered on any of our own
                    // messages, text or file. Both are hidden on the peer's rows
                    // and on tombstones. Kept at the top of the menu because they
                    // are the most common "I made a mistake" follow-ups.
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.edit")
                        visible: delegate.mine && !model.isFile && !delegate.deleted
                        height: visible ? implicitHeight : 0
                        onTriggered: delegate.editRequested(model.mid, model.text)
                    }
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.resend")
                        visible: delegate.mine && !delegate.deleted
                        height: visible ? implicitHeight : 0
                        onTriggered: delegate.resendRequested(model.mid)
                    }
                    MenuSeparator {
                        visible: delegate.mine && !delegate.deleted
                        height: visible ? implicitHeight : 0
                    }
                    MenuItem {
                        text: App.Localization.tIn(App.Localization.language, "menu.deleteForMe")
                        onTriggered: delegate.deleteRequested(model.mid, false)
                    }
                    MenuItem {
                        // Only our own messages can be retracted for everyone.
                        text: App.Localization.tIn(App.Localization.language, "menu.deleteForEveryone")
                        visible: delegate.mine
                        height: visible ? implicitHeight : 0
                        onTriggered: delegate.deleteRequested(model.mid, true)
                    }

                    MenuSeparator {}

                    // Quick agree / disagree -- a discreet acknowledgement.
                    // Available on any message (ours or the peer's). Retapping the
                    // same one and then "Remove reaction" clears it.
                    MenuItem {
                        text: "\uD83D\uDC4D " + App.Localization.tIn(App.Localization.language, "menu.reactAgree")
                        onTriggered: delegate.reactRequested(model.mid, "up")
                    }
                    MenuItem {
                        text: "\uD83D\uDC4E " + App.Localization.tIn(App.Localization.language, "menu.reactDisagree")
                        onTriggered: delegate.reactRequested(model.mid, "down")
                    }
                    MenuItem {
                        // Only offered once we have actually reacted to this row.
                        text: App.Localization.tIn(App.Localization.language, "menu.reactRemove")
                        visible: model.myReaction === "up" || model.myReaction === "down"
                        height: visible ? implicitHeight : 0
                        onTriggered: delegate.reactRequested(model.mid, "")
                    }
                }

                ColumnLayout {
                    id: bubbleColumn
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 5

                    // ---- Tombstone (deleted rows) ------------------------
                    // Shown instead of any body/file content when the row has been
                    // deleted. The model returns the "This message was deleted"
                    // text in model.text and reports isFile=false when deleted, so
                    // the ordinary text label below would already show the
                    // placeholder; this dedicated label just styles it (italic,
                    // muted) and keeps the intent obvious in the delegate.
                    RowLayout {
                        visible: delegate.deleted
                        spacing: 6
                        Layout.fillWidth: true
                        Label {
                            text: "\uD83D\uDEAB"
                            font.pixelSize: 12
                            opacity: 0.7
                        }
                        Label {
                            text: model.text   // "This message was deleted"
                            color: bubble.metaText
                            opacity: 0.85
                            font.italic: true
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }

                    // ---- Text body (non-file, non-deleted rows) ----------
                    Label {
                        visible: !model.isFile && !delegate.deleted
                        text: model.text
                        color: bubble.bodyText
                        font.pixelSize: 14
                        lineHeight: 1.15
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    // ---- Image preview (image-mime file rows) ------------
                    // Framed in a rounded, bordered tile so it reads as a proper
                    // inline photo. The Image's `source` MUST stay gated on the
                    // same image-mime check as visibility -- an Image loads its
                    // source even while invisible, so feeding a non-image file to
                    // the decoder throws "Unsupported image format" and can break
                    // the surrounding ListView layout. A deleted row never shows a
                    // preview (the model suppresses the file roles); the extra
                    // !delegate.deleted guard makes that explicit.
                    Rectangle {
                        id: imgFrame
                        readonly property bool isImage:
                            !delegate.deleted
                            && model.isFile
                            && model.mime.indexOf("image/") === 0
                            && model.localPath.length > 0
                        visible: isImage
                        radius: 12
                        color: Qt.rgba(0, 0, 0, 0.18)
                        border.width: 1
                        border.color: delegate.mine ? Qt.rgba(0, 0, 0, 0.18)
                                                    : window.pal.line
                        clip: true
                        Layout.preferredWidth: Math.min(imagePreview.implicitWidth + 8,
                                                        delegate.width * 0.62)
                        Layout.preferredHeight: imagePreview.paintedHeight + 8
                        Layout.maximumHeight: 260
                        Layout.fillWidth: true

                        Image {
                            id: imagePreview
                            anchors.fill: parent
                            anchors.margins: 4
                            visible: imgFrame.isImage
                            source: imgFrame.isImage ? "file:///" + model.localPath : ""
                            fillMode: Image.PreserveAspectFit
                            asynchronous: true
                        }
                    }

                    // ---- File row (attachment chip) ----------------------
                    // A tidy card: a document glyph in an accent-tinted tile, the
                    // filename in bold, and the human-readable size beneath.
                    Rectangle {
                        visible: model.isFile && !delegate.deleted && !imgFrame.isImage
                        Layout.fillWidth: true
                        implicitHeight: fileRow.implicitHeight + 14
                        radius: 10
                        color: delegate.mine ? Qt.rgba(0, 0, 0, 0.16)
                                             : window.pal.surface
                        border.width: 1
                        border.color: delegate.mine ? Qt.rgba(0, 0, 0, 0.14)
                                                    : window.pal.line

                        RowLayout {
                            id: fileRow
                            anchors.fill: parent
                            anchors.margins: 7
                            spacing: 10

                            // Document glyph in a tinted tile.
                            Rectangle {
                                Layout.preferredWidth: 34
                                Layout.preferredHeight: 34
                                Layout.alignment: Qt.AlignVCenter
                                radius: 8
                                color: delegate.mine
                                       ? Qt.rgba(1, 1, 1, 0.18)
                                       : window.pal.accent
                                Label {
                                    anchors.centerIn: parent
                                    text: "\uD83D\uDCC4"
                                    font.pixelSize: 17
                                }
                            }

                            ColumnLayout {
                                spacing: 1
                                Layout.fillWidth: true
                                Label {
                                    text: model.filename
                                    color: bubble.bodyText
                                    font.bold: true
                                    font.pixelSize: 13
                                    elide: Text.ElideMiddle
                                    Layout.fillWidth: true
                                    Layout.maximumWidth: delegate.width * 0.48
                                }
                                Label {
                                    text: {
                                        var b = model.size;
                                        if (b < 1024) return b + " B";
                                        if (b < 1024 * 1024)
                                            return (b / 1024).toFixed(1) + " KB";
                                        return (b / (1024 * 1024)).toFixed(1) + " MB";
                                    }
                                    color: bubble.metaText
                                    opacity: 0.8
                                    font.pixelSize: 10
                                }
                            }
                        }
                    }

                    // ---- Save button (files I received) ------------------
                    // A compact, rounded, accent-outlined button rather than the
                    // bare flat default, so a received file has an obvious,
                    // tappable action.
                    Button {
                        id: saveButton
                        visible: model.isFile && !model.isMine && !delegate.deleted
                        Layout.alignment: Qt.AlignRight
                        Layout.preferredHeight: 32
                        padding: 0
                        onClicked: delegate.saveFileRequested(model.msgId,
                                                              model.filename)
                        contentItem: RowLayout {
                            spacing: 6
                            Item { Layout.preferredWidth: 4 }
                            Label {
                                text: "\u2B07"   // down arrow
                                color: window.pal.accent
                                font.pixelSize: 13
                            }
                            Label {
                                text: "Save\u2026"
                                color: window.pal.accent
                                font.pixelSize: 12
                                font.weight: Font.DemiBold
                            }
                            Item { Layout.preferredWidth: 4 }
                        }
                        background: Rectangle {
                            radius: 8
                            implicitWidth: 78
                            color: saveButton.down ? Qt.rgba(0, 0, 0, 0.12)
                                                   : "transparent"
                            border.width: 1.5
                            border.color: window.pal.accent
                        }
                    }

                    // ---- Reaction badges --------------------------------
                    // Small agree/disagree pills under the content: the peer's
                    // reaction and our own, each shown only when set. A deleted row
                    // reports both as empty (the model suppresses them), so nothing
                    // renders on a tombstone. The translucent fill is chosen to read
                    // on both the accent (mine) and surface (peer) bubble colours.
                    Flow {
                        Layout.fillWidth: true
                        spacing: 5
                        visible: model.peerReaction === "up" || model.peerReaction === "down"
                                 || model.myReaction === "up" || model.myReaction === "down"

                        Rectangle {
                            visible: model.peerReaction === "up" || model.peerReaction === "down"
                            radius: height / 2
                            color: delegate.mine ? Qt.rgba(0, 0, 0, 0.20)
                                                 : Qt.rgba(0, 0, 0, 0.16)
                            border.width: 1
                            border.color: delegate.mine ? Qt.rgba(0, 0, 0, 0.14)
                                                        : window.pal.line
                            implicitWidth: peerChip.implicitWidth + 14
                            implicitHeight: peerChip.implicitHeight + 6
                            Label {
                                id: peerChip
                                anchors.centerIn: parent
                                text: model.peerReaction === "up" ? "\uD83D\uDC4D" : "\uD83D\uDC4E"
                                font.pixelSize: 12
                            }
                        }
                        Rectangle {
                            // Our own reaction, given a thin accent outline so it
                            // is distinguishable from the peer's at a glance.
                            visible: model.myReaction === "up" || model.myReaction === "down"
                            radius: height / 2
                            color: delegate.mine ? Qt.rgba(0, 0, 0, 0.28)
                                                 : Qt.rgba(0, 0, 0, 0.10)
                            border.width: 1
                            border.color: delegate.mine ? Qt.rgba(1, 1, 1, 0.30)
                                                        : window.pal.accent
                            implicitWidth: myChip.implicitWidth + 14
                            implicitHeight: myChip.implicitHeight + 6
                            Label {
                                id: myChip
                                anchors.centerIn: parent
                                text: model.myReaction === "up" ? "\uD83D\uDC4D" : "\uD83D\uDC4E"
                                font.pixelSize: 12
                            }
                        }
                    }

                    // ---- Timestamp (with a tiny encryption cue) ---------
                    // A small lock glyph beside the time quietly reinforces that
                    // every bubble was end-to-end encrypted, without a noisy
                    // per-message label. Muted and right-aligned.
                    RowLayout {
                        Layout.alignment: Qt.AlignRight
                        spacing: 4
                        // A small, muted "edited" note when this text message was
                        // changed in place -- honest about the edit without
                        // shouting, exactly as mainstream messengers show it.
                        Label {
                            visible: model.isEdited === true && !delegate.deleted
                            text: App.Localization.tIn(App.Localization.language, "msg.edited")
                            color: bubble.metaText
                            opacity: 0.7
                            font.pixelSize: 9
                            font.italic: true
                        }
                        Label {
                            visible: !delegate.deleted
                            text: "\uD83D\uDD12"
                            color: bubble.metaText
                            opacity: 0.6
                            font.pixelSize: 9
                        }
                        Label {
                            text: model.timestamp
                            color: bubble.metaText
                            opacity: 0.78
                            font.pixelSize: 9
                        }
                    }
                }
            }
        }
    }
}
