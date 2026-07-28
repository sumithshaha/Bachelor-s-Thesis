import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts
import ChatE2EE
import ChatE2EE as App

// LockScreen.qml -- the app-lock overlay (native unlock).
//
// Shown by the Loader in Main.qml whenever ChatClient.isLocked is true. It is a
// full-screen, opaque panel. Which unlock affordances appear is driven by two
// independent facts, NOT a single mode, so desktop can offer BOTH at once:
//
//   * ChatClient.biometricAvailable -> show the OS-credential button. On Android
//     this is "Unlock with device" (fingerprint/face + the device PIN) and, when
//     the OS credential is the SOLE authenticator (usesOsCredential), the prompt
//     is auto-triggered on appear. On Windows it is "Unlock with Windows Hello",
//     shown ALONGSIDE the PIN entry (not auto-triggered, so the user can choose
//     Hello or the PIN).
//
//   * ChatClient.hasPin -> show the custom app-PIN entry (Argon2id verifier). On
//     Android there is no app-PIN so this is hidden; on desktop a PIN is always
//     set when the lock is enabled, so it is always shown. The user types it and
//     ChatClient.verifyPin checks it in constant time.
//
// So: Android shows the device button only; desktop shows the PIN entry always,
// plus the Windows Hello button when Hello is available -- "Windows Hello and/or
// custom app PIN". Either way the lock only re-guards an already-unlocked,
// in-memory session; it never touches the identity key. A "Forgot PIN?" link
// resets the lock after the user proves their LOGIN PASSWORD (the root of trust).
//
// RESTYLE NOTES (build-and-test-required -- not compiled here): themed via
// window.pal like every other screen, matching the login screen's gradient
// backdrop, haloed padlock lockup, and raised accent unlock button.

Item {
    id: lock
    anchors.fill: parent

    // Opaque gradient background so nothing behind the lock is visible.
    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: window.pal.base }
            GradientStop {
                position: 1.0
                color: window.dark ? Qt.darker(window.pal.base, 1.18)
                                    : Qt.darker(window.pal.base, 1.03)
            }
        }
    }

    // On appear, if the OS credential is the SOLE authenticator (Android) and a
    // biometric/credential is actually enrolled, trigger the prompt immediately so
    // the common case is a single tap of the sensor. On desktop we do NOT auto-pop
    // Windows Hello: the PIN entry is always there too, so the user chooses. If no
    // credential is enrolled on Android, we skip the doomed prompt and leave the
    // "Forgot PIN?" reset as the way in.
    Component.onCompleted: {
        if (ChatClient.usesOsCredential && ChatClient.biometricAvailable)
            ChatClient.requestBiometricUnlock()
    }

    // LAYOUT SAFETY -- see the same block in LoginPage.qml. This column is
    // shorter than the login form, but it grows a device-unlock button, a PIN
    // field, an error line and the reset link, and the PIN field raises the
    // soft keyboard over the lower half of the screen. Centring it with no way
    // to scroll made the reset link unreachable in exactly the same way.
    readonly property real formPad: 24
    readonly property real keyboardInset:
        Qt.inputMethod.visible
        ? Math.max(0, Qt.inputMethod.keyboardRectangle.height
                      / Math.max(1, Screen.devicePixelRatio))
        : 0

    Flickable {
        id: lockFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: lockColumn.y + lockColumn.height + root.formPad
                       + root.keyboardInset
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick

        ScrollBar.vertical: ScrollBar {
            policy: lockFlick.contentHeight > lockFlick.height
                    ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff
        }

        ColumnLayout {
            id: lockColumn
            width: Math.max(0, Math.min(lockFlick.width - 64, 340))
            x: (lockFlick.width - width) / 2
            y: Math.max(root.formPad,
                        (lockFlick.height - root.keyboardInset - height) / 2)
            spacing: 22

            // Padlock lockup with a concentric accent halo, echoing the login
            // screen's motif.
            Item {
                Layout.alignment: Qt.AlignHCenter
                width: 72; height: 72

                Rectangle {
                    anchors.centerIn: parent
                    width: 112; height: 112; radius: 32
                    color: window.pal.accent
                    opacity: 0.06
                }
                Rectangle {
                    anchors.centerIn: parent
                    width: 92; height: 92; radius: 26
                    color: window.pal.accent
                    opacity: 0.10
                }
                Rectangle {
                    anchors.fill: parent
                    radius: 18
                    gradient: Gradient {
                        GradientStop { position: 0.0; color: window.pal.surfaceHi }
                        GradientStop { position: 1.0; color: window.pal.surface }
                    }
                    border.color: window.pal.accent
                    border.width: 1.5
                    Label {
                        anchors.centerIn: parent
                        text: "\uD83D\uDD12"
                        font.pixelSize: 34
                    }
                }
            }

            Label {
                text: App.Localization.tIn(App.Localization.language, "lock.title")
                color: window.pal.text
                font.pixelSize: 24
                font.weight: Font.DemiBold
                Layout.alignment: Qt.AlignHCenter
            }

            // ===== OS-CREDENTIAL BUTTON (Android device / Windows Hello) ====
            // Shown whenever a biometric/OS-credential unlock is possible: Android
            // (fingerprint/face + device PIN) and Windows when Hello is set up. On
            // Windows it sits ABOVE the always-present PIN entry, so the user picks
            // Hello or the PIN. Tapping it (re)invokes the OS prompt.
            Button {
                id: deviceUnlockButton
                visible: ChatClient.biometricAvailable
                text: ChatClient.usesOsCredential
                      ? App.Localization.tIn(App.Localization.language, "lock.unlockDevice")
                      : App.Localization.tIn(App.Localization.language, "lock.unlockHello")
                highlighted: true
                Layout.fillWidth: true
                Layout.preferredHeight: 48
                onClicked: ChatClient.requestBiometricUnlock()
                contentItem: Label {
                    text: deviceUnlockButton.text
                    color: window.pal.base
                    font.pixelSize: 15
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    radius: 12
                    color: deviceUnlockButton.down ? window.pal.accentDim : "transparent"
                    gradient: deviceUnlockButton.down ? null : deviceGrad
                    Gradient {
                        id: deviceGrad
                        GradientStop { position: 0.0; color: window.pal.accentHi }
                        GradientStop { position: 1.0; color: window.pal.accent }
                    }
                    Behavior on color { ColorAnimation { duration: 120 } }
                    Rectangle {
                        visible: !deviceUnlockButton.down
                        anchors.top: parent.top
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.topMargin: 1
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        height: 1
                        color: Qt.rgba(1, 1, 1, 0.28)
                    }
                }
            }

            // Divider between the Windows Hello button and the PIN entry, shown only
            // when BOTH are present (desktop with Hello) so it is clear they are two
            // alternative ways in.
            Label {
                visible: ChatClient.biometricAvailable && ChatClient.hasPin
                text: App.Localization.tIn(App.Localization.language, "lock.orEnterPin")
                color: window.pal.textDim
                font.pixelSize: 12
                Layout.alignment: Qt.AlignHCenter
            }

            // ===== APP-PIN ENTRY (desktop) =================================
            // Shown whenever a custom app-PIN is set (hasPin). On desktop a PIN is
            // always set when the lock is enabled, so this is the always-available way
            // in, with Windows Hello above it as an optional convenience. On Android
            // hasPin is false (no app-PIN in that model), so it stays hidden there.
            // A rounded framed field, matching the composer box, replaces the bare
            // underline TextField.
            Rectangle {
                id: pinFrame
                visible: ChatClient.hasPin
                Layout.fillWidth: true
                Layout.preferredHeight: 52
                radius: 12
                color: window.pal.surface
                border.width: 1.5
                border.color: pinField.activeFocus ? window.pal.accent : window.pal.line
                Behavior on border.color { ColorAnimation { duration: 120 } }

                TextField {
                    id: pinField
                    anchors.fill: parent
                    anchors.margins: 2
                    verticalAlignment: TextInput.AlignVCenter
                    placeholderText: App.Localization.tIn(App.Localization.language, "lock.enterPin")
                    placeholderTextColor: window.pal.textDim
                    echoMode: TextInput.Password
                    inputMethodHints: Qt.ImhDigitsOnly
                    horizontalAlignment: TextInput.AlignHCenter
                    color: window.pal.text
                    font.pixelSize: 20
                    font.letterSpacing: 4
                    background: null   // the parent Rectangle is the frame
                    Material.accent: window.pal.accent
                    onAccepted: if (unlockButton.enabled) unlockButton.clicked()
                    onTextChanged: errorLabel.visible = false
                }
            }

            Label {
                id: errorLabel
                visible: false
                text: App.Localization.tIn(App.Localization.language, "lock.wrongPin")
                color: window.pal.danger
                font.pixelSize: 12
                Layout.alignment: Qt.AlignHCenter
            }

            Button {
                id: unlockButton
                visible: ChatClient.hasPin
                text: App.Localization.tIn(App.Localization.language, "lock.unlock")
                highlighted: true
                Layout.fillWidth: true
                Layout.preferredHeight: 48
                enabled: pinField.text.length > 0
                onClicked: {
                    if (ChatClient.verifyPin(pinField.text)) {
                        pinField.text = ""
                        // isLocked flips to false in the backend; the Loader hides.
                    } else {
                        errorLabel.visible = true
                        pinField.text = ""
                        pinField.forceActiveFocus()
                    }
                }
                contentItem: Label {
                    text: unlockButton.text
                    color: unlockButton.enabled ? window.pal.base : window.pal.textDim
                    font.pixelSize: 15
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    radius: 12
                    color: !unlockButton.enabled ? window.pal.surfaceHi
                           : unlockButton.down   ? window.pal.accentDim
                                                 : "transparent"
                    gradient: (unlockButton.enabled && !unlockButton.down)
                              ? unlockGrad : null
                    Gradient {
                        id: unlockGrad
                        GradientStop { position: 0.0; color: window.pal.accentHi }
                        GradientStop { position: 1.0; color: window.pal.accent }
                    }
                    Behavior on color { ColorAnimation { duration: 120 } }
                    Rectangle {
                        visible: unlockButton.enabled && !unlockButton.down
                        anchors.top: parent.top
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.topMargin: 1
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        height: 1
                        color: Qt.rgba(1, 1, 1, 0.28)
                    }
                }
            }

            // ===== Forgot PIN / reset (both modes) ==========================
            // Resets the lock after the user proves their LOGIN PASSWORD.
            Button {
                id: forgotButton
                text: App.Localization.tIn(App.Localization.language, "lock.forgotPin")
                flat: true
                Layout.alignment: Qt.AlignHCenter
                // A 13px label plus the style's padding lands near 30px high, under
                // every published minimum for a touch target. Sized explicitly, as
                // on the login screen, so the link can actually be hit.
                Layout.preferredHeight: 44
                Layout.bottomMargin: 4
                leftPadding: 12
                rightPadding: 12
                onClicked: resetDialog.open()
                contentItem: Label {
                    text: forgotButton.text
                    color: window.pal.textDim
                    font.pixelSize: 13
                    horizontalAlignment: Text.AlignHCenter
                }
            }
        }
    }

    // ---- Password-reset dialog -----------------------------------------
    // "Forgot PIN": enter the account password; on success ChatClient clears the
    // lock (isLocked -> false, the overlay hides) and the lock is turned off, so
    // the user can re-enable it fresh from settings.
    Dialog {
        id: resetDialog
        // popupType: Popup.Item is required. Qt 6.10 changed the default to
        // Popup.Window, which renders a popup as a separate native window --
        // off-screen on Android. ChatPage's comment states the rule as "applied
        // to EVERY Menu and Dialog in the app"; this was the one that was
        // missed, and it is the dialog "Forgot PIN?" opens, so the lock screen
        // had no working way out.
        popupType: Popup.Item
        anchors.centerIn: parent
        // Bounded like the login screen's recovery sheet. A Dialog with no width
        // takes its content's, which on a narrow phone runs past both edges.
        width: Math.min(lock.width - 48, 420)
        modal: true
        title: App.Localization.tIn(App.Localization.language, "lock.resetTitle")
        standardButtons: Dialog.Cancel | Dialog.Ok
        onOpened: { resetPw.text = ""; resetWrong.visible = false;
                    resetPw.forceActiveFocus() }
        onAccepted: {
            if (!ChatClient.resetLockWithPassword(resetPw.text)) {
                resetWrong.visible = true
                resetPw.text = ""
                resetPw.forceActiveFocus()
                resetDialog.open()   // reject: keep dialog up
            }
        }
        ColumnLayout {
            width: Math.min(lock.width - 100, 300)
            spacing: 12
            Label {
                text: App.Localization.tIn(App.Localization.language, "lock.resetPrompt")
                color: window.pal.text
                font.pixelSize: 13
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            TextField {
                id: resetPw
                Layout.fillWidth: true
                placeholderText: App.Localization.tIn(App.Localization.language, "login.password")
                echoMode: TextInput.Password
                color: window.pal.text
                Material.accent: window.pal.accent
                onTextChanged: resetWrong.visible = false
            }
            Label {
                id: resetWrong
                text: App.Localization.tIn(App.Localization.language, "err.wrongPassword")
                color: window.pal.danger
                font.pixelSize: 12
                visible: false
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
        }
    }
}
