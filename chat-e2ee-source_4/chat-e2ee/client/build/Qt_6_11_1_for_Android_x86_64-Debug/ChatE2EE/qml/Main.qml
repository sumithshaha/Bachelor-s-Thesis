import QtQuick
import QtQuick.Controls.Material
import QtQuick.Window

// Main.qml is the root of the user interface. It is deliberately thin: it sets
// up the window, a few global theme choices, and a StackView that shows either
// the login page or the chat page. All the real screens live in their own
// files.

ApplicationWindow {
    id: window
    width: 420
    height: 720
    visible: true
    title: "Encrypted Chat"

    Material.theme: Material.Dark
    Material.accent: Material.Teal

    // A StackView lets us push the chat page on top of the login page once the
    // user has logged in, and pop back if they log out. On Android the back
    // gesture maps naturally onto this stack.
    StackView {
        id: stack
        anchors.fill: parent
        initialItem: loginPage
    }

    Component {
        id: loginPage
        LoginPage {
            onLoginRequested: function(url, nick) {
                chat.login(url, nick)
            }
        }
    }

    Component {
        id: chatPage
        ChatPage {}
    }

    // When the C++ side reports a successful login, move to the chat page.
    Connections {
        target: chat
        function onLoggedIn() {
            if (stack.depth === 1)
                stack.push(chatPage)
        }
    }

    // Surface any error from the backend as a simple banner.
    footer: ToolBar {
        id: errorBar
        visible: false
        Material.background: Material.color(Material.Red)
        Label {
            id: errorLabel
            anchors.centerIn: parent
            color: "white"
        }
        Timer {
            id: errorTimer
            interval: 4000
            onTriggered: errorBar.visible = false
        }
    }

    Connections {
        target: chat
        function onErrorOccurred(message) {
            errorLabel.text = message
            errorBar.visible = true
            errorTimer.restart()
        }
    }
}
