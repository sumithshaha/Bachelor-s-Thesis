import QtQuick
import QtQuick.Controls.Material

// The panel down the left side that lists everyone currently online. Tapping a
// name selects that person as the active conversation partner; the page above
// reacts by switching the message view to that peer.
//
// Each row now also shows an unread badge: when a message or file arrives for
// a peer who is not the active conversation, UserModel increments that peer's
// unread count and this badge appears. Opening the conversation clears it.

Pane {
    id: root
    padding: 0
    signal peerSelected(string name)

    property string selectedName: ""

    Material.background: Material.color(Material.Grey, Material.Shade900)

    Column {
        anchors.fill: parent

        Label {
            text: "Online"
            font.pixelSize: 12
            font.bold: true
            opacity: 0.7
            padding: 10
        }

        ListView {
            id: list
            width: parent.width
            height: parent.height - 40
            clip: true
            model: chat.users
            delegate: ItemDelegate {
                width: ListView.view.width
                // Do not let the user "chat with themselves".
                enabled: !model.isSelf
                highlighted: model.name === root.selectedName
                text: model.isSelf ? (model.name + " (you)") : model.name
                onClicked: {
                    root.selectedName = model.name
                    root.peerSelected(model.name)
                }

                // ---- Unread badge -----------------------------------------
                // model.unread is 0 when there is nothing new; the badge is
                // hidden in that case. It sits at the trailing edge of the row.
                Rectangle {
                    visible: model.unread > 0
                    anchors.right: parent.right
                    anchors.rightMargin: 10
                    anchors.verticalCenter: parent.verticalCenter
                    width: Math.max(18, badgeText.implicitWidth + 10)
                    height: 18
                    radius: 9
                    color: Material.accent
                    Label {
                        id: badgeText
                        anchors.centerIn: parent
                        text: model.unread > 99 ? "99+" : model.unread
                        color: "white"
                        font.pixelSize: 11
                        font.bold: true
                    }
                }
            }
        }
    }
}
