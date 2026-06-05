import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Dialogs

// The main chat screen, shown after login. It has a header showing who you
// are and the safety number for the active conversation, a row combining the
// online-user list with the running conversation, and a composer at the
// bottom for typing a message and attaching a file.

Page {
    id: root

    // Bumped whenever peer keys change (see Connections{onPeerKeysChanged}
    // below). The safety-number bindings reference it purely so they have a
    // reactive dependency to re-evaluate on once a peer's key has arrived;
    // QML only re-runs a binding when a property it reads changes, and the
    // raw safetyNumberWith() call alone gave it nothing to react to.
    property int keyRefresh: 0

    header: ToolBar {
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 12
            anchors.rightMargin: 12

            ColumnLayout {
                spacing: 0
                Label {
                    text: chat.myNickname
                    font.bold: true
                    font.pixelSize: 16
                }
                Label {
                    text: chat.connected ? "online" : "reconnecting..."
                    font.pixelSize: 11
                    opacity: 0.7
                }
            }

            Item { Layout.fillWidth: true }

            // When chatting with someone, show the PAIRWISE safety number for
            // that conversation - the value that should match on both devices.
            // When no peer is selected, fall back to my own identity
            // fingerprint so the header is never empty.
            Label {
                text: (root.keyRefresh, chat.activePeer.length > 0)
                      ? "🔒 " + chat.safetyNumberWith(chat.activePeer)
                      : "🔑 me: " + chat.myFingerprint
                font.pixelSize: 11
                opacity: 0.6
                MouseArea {
                    anchors.fill: parent
                    onClicked: fingerprintDialog.open()
                }
            }
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // ---- Left: the list of people online ----------------------------
        UserListPanel {
            Layout.preferredWidth: 120
            Layout.fillHeight: true
            onPeerSelected: function(name) {
                // Setting activePeer triggers setActivePeer() in C++, which now
                // owns repopulation: it clears the model and replays this
                // peer's stored history via loadConversation(). We must NOT
                // call chat.messages.clear() here as well - doing so would race
                // that reload and leave the conversation blank.
                chat.activePeer = name
            }
        }

        ToolSeparator { Layout.fillHeight: true; padding: 0 }

        // ---- Right: the conversation ------------------------------------
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            Label {
                visible: chat.activePeer.length > 0
                text: "Chatting with " + chat.activePeer
                padding: 8
                font.pixelSize: 13
                opacity: 0.8
            }

            ListView {
                id: messageView
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                spacing: 6
                model: chat.messages
                delegate: MessageDelegate {
                    // When a received-file row asks to be saved, remember which
                    // file and open the save dialog.
                    onSaveFileRequested: function(msgId, filename) {
                        saveDialog.pendingMsgId = msgId
                        saveDialog.currentFile = "file:///" + filename
                        saveDialog.open()
                    }
                }
                onCountChanged: positionViewAtEnd()
                ScrollBar.vertical: ScrollBar {}
            }

            // ---- A thin progress bar shown during a file transfer --------
            ProgressBar {
                id: transferBar
                Layout.fillWidth: true
                visible: value > 0.0 && value < 1.0
                from: 0.0
                to: 1.0
                value: 0.0
            }

            // ---- The composer --------------------------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.margins: 8
                spacing: 8

                // Attach-a-file button (the paperclip).
                Button {
                    text: "\uD83D\uDCCE"
                    enabled: chat.activePeer.length > 0
                    onClicked: openDialog.open()
                    ToolTip.visible: hovered
                    ToolTip.text: "Send a file or image"
                }

                TextField {
                    id: input
                    Layout.fillWidth: true
                    placeholderText: chat.activePeer.length > 0
                        ? "Type a message..."
                        : "Pick someone to chat with"
                    enabled: chat.activePeer.length > 0
                    onAccepted: sendButton.clicked()
                }

                Button {
                    id: sendButton
                    text: "Send"
                    highlighted: true
                    enabled: input.text.trim().length > 0
                    onClicked: {
                        chat.sendMessage(input.text.trim())
                        input.clear()
                    }
                }
            }
        }
    }

    // ---- File chooser for SENDING --------------------------------------
    FileDialog {
        id: openDialog
        title: "Choose a file to send"
        fileMode: FileDialog.OpenFile
        onAccepted: chat.sendFile(selectedFile)
    }

    // ---- File chooser for SAVING a received file -----------------------
    FileDialog {
        id: saveDialog
        property string pendingMsgId: ""
        title: "Save file as"
        fileMode: FileDialog.SaveFile
        onAccepted: {
            if (pendingMsgId.length > 0)
                chat.saveReceivedFile(pendingMsgId, selectedFile)
            pendingMsgId = ""
        }
    }

    // ---- React to file-transfer signals from the backend ---------------
    Connections {
        target: chat
        // A peer key arrived (login dump or getkey reply): nudge the reactive
        // counter so the safety-number bindings above recompute and the digits
        // appear. This is what fixes the intermittently-blank safety number.
        function onPeerKeysChanged() { root.keyRefresh++ }
        function onFileSendProgress(msgId, fraction) {
            transferBar.value = fraction
        }
        function onFileReceiveProgress(msgId, fraction) {
            transferBar.value = fraction
        }
        function onFileReceiveFailed(msgId, reason) {
            chat.messages.addSystem("File transfer failed: " + reason)
            transferBar.value = 0.0
        }
    }

    // Dialog that shows the safety number for the CURRENT conversation, large
    // enough to read aloud. The number is derived from both my key and the
    // active peer's key, so the same digits appear on both screens only if no
    // one has tampered with the key exchange.
    Dialog {
        id: fingerprintDialog
        anchors.centerIn: parent
        modal: true
        title: chat.activePeer.length > 0
               ? "Safety number with " + chat.activePeer
               : "Your safety number"
        standardButtons: Dialog.Ok
        ColumnLayout {
            spacing: 12
            Label {
                text: chat.activePeer.length > 0
                      ? "Compare these numbers with " + chat.activePeer +
                        " over a call or in person.\nIf they match on both devices, no one is intercepting your keys."
                      : "Select a contact to see the safety number you share with them."
                wrapMode: Text.WordWrap
                Layout.preferredWidth: 280
            }
            Label {
                text: (root.keyRefresh, chat.activePeer.length > 0)
                      ? chat.safetyNumberWith(chat.activePeer)
                      : chat.myFingerprint
                font.pixelSize: 20
                font.family: "monospace"
                Layout.alignment: Qt.AlignHCenter
            }
        }
    }
}
