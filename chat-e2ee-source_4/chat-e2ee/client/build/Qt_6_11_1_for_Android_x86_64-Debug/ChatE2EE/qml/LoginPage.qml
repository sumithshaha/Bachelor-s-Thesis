import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts

// The login screen. The user picks a nickname and a server address, taps
// "Connect", and we hand those values up to Main.qml, which calls the backend.
// There is no password here by design: identity in this prototype is the
// long-term key pair generated on the device, not a server-side account.

Page {
    id: root
    signal loginRequested(string url, string nick)

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width - 64, 360)
        spacing: 24

        Label {
            text: "Encrypted Chat"
            font.pixelSize: 32
            font.bold: true
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: "Messages are end-to-end encrypted.\nThe server never sees them."
            horizontalAlignment: Text.AlignHCenter
            opacity: 0.7
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }

        TextField {
            id: nickField
            placeholderText: "Choose a nickname"
            Layout.fillWidth: true
            // Allow Enter to submit from the nickname field.
            onAccepted: connectButton.clicked()
        }

        TextField {
            id: serverField
            placeholderText: "Server address"
            text: "wss://localhost:8765"
            Layout.fillWidth: true
        }

        Button {
            id: connectButton
            text: "Connect"
            highlighted: true
            Layout.fillWidth: true
            enabled: nickField.text.trim().length > 0
                     && serverField.text.trim().length > 0
            onClicked: root.loginRequested(serverField.text.trim(),
                                           nickField.text.trim())
        }
    }
}
