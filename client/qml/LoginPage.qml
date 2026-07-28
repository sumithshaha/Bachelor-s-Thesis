import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts
import ChatE2EE
import ChatE2EE as App

// The login screen. The user picks a nickname, a server address, and a
// password, then either Registers a new account or Logs in to an existing one.
// Two distinct actions are offered by design (chosen for the thesis demo):
// Register creates a fresh identity wrapped under the password; Log in unlocks
// an existing local identity and authenticates.
//
// PASSWORD (Design B): the password never leaves the device as a secret -- it
// encrypts the X25519 identity private key at rest (Argon2id + secretbox) and
// derives an irreversible verifier the server compares. So "the server never
// sees a single byte it shouldn't" holds for credentials too. See
// ChatClient.registerAccount / ChatClient.login (both take the password).
//
// RESTYLE NOTES (build-and-test-required -- not compiled here):
//   * A soft vertical gradient backdrop and a concentric accent HALO behind the
//     padlock lockup give the screen depth without any external effects module.
//   * The primary Log in button is a raised accent GRADIENT with a gloss edge;
//     Register is a refined outline; the returning-user biometric/Hello button
//     is an outline that fills on press. Field logic is unchanged.
//   * The last-used nickname and server URL are pre-filled from the backend
//     (ChatClient.lastNickname / ChatClient.lastServerUrl).
//   * loginRequested(url, nick, password) and registerRequested(url, nick,
//     password) are the two backend entry points, wired in Main.qml.

Page {
    id: root
    // Two distinct actions, both carrying the password (Design B).
    signal loginRequested(string url, string nick, string password)
    signal registerRequested(string url, string nick, string password, string birthday)

    // LAYOUT SAFETY. The form is taller than a phone screen: lockup, blurb,
    // three fields with help text, the date of birth, the opt-in checkbox, two
    // 48px buttons and the returning-user button come to roughly 830 logical
    // pixels, against 832 of usable height on the target device BEFORE the
    // status bar, the navigation bar or the keyboard take their share. Centring
    // a column that tall overflows it equally at BOTH ends, which is why the
    // padlock was clipped at the top and the last controls sat jammed against
    // the bottom edge with no way to reach them.
    //
    // formPad is the breathing room kept above and below the form so no control
    // is ever flush against a screen edge (or an Android gesture bar).
    readonly property real formPad: 24

    // KEYBOARD INSET. When the soft keyboard is up it covers the lower part of
    // the window, and Qt does not move a Page out of its way. Reserving the
    // keyboard's height as extra scrollable content lets the user reach every
    // control while typing instead of having the form disappear behind it.
    //
    // keyboardRectangle is reported in device pixels on Android, so it is
    // divided by the device pixel ratio to reach the logical pixels this scene
    // is measured in. If a platform ever reports it in logical pixels already,
    // the division makes the reserve too SMALL rather than too large -- and too
    // small merely means slightly less slack, whereas too large would leave a
    // permanent empty gap. The error is deliberately biased to the harmless
    // side. Zero on desktop, where the keyboard is physical.
    readonly property real keyboardInset:
        Qt.inputMethod.visible
        ? Math.max(0, Qt.inputMethod.keyboardRectangle.height
                      / Math.max(1, Screen.devicePixelRatio))
        : 0

    // Gradient backdrop: a gentle top-to-bottom wash off the base colour so the
    // screen is not a single flat block. Subtle in both brightnesses.
    background: Rectangle {
        gradient: Gradient {
            GradientStop { position: 0.0; color: window.pal.base }
            GradientStop {
                position: 1.0
                color: window.dark ? Qt.darker(window.pal.base, 1.18)
                                    : Qt.darker(window.pal.base, 1.03)
            }
        }
    }

    // Prefill once when the page becomes ready. Guarded so an empty stored
    // value leaves the placeholder visible instead of blanking the field.
    Component.onCompleted: {
        var n = (typeof ChatClient.lastNickname === "string")
                ? ChatClient.lastNickname : ""
        if (n.length > 0)
            nickField.text = n
        var u = (typeof ChatClient.lastServerUrl === "string")
                ? ChatClient.lastServerUrl : ""
        if (u.length > 0)
            serverField.text = u
        // First arrival (app launch): if the returning user has fingerprint /
        // PIN (Android) or Windows Hello (desktop) login enrolled, offer it
        // automatically once the screen has painted.
        autoBioTimer.restart()
    }

    // AUTO-PROMPT on RETURN to the login screen. Both "Switch user" and "Log
    // out" pop back to this page (the StackView's initialItem), which does NOT
    // re-run Component.onCompleted -- so we watch the attached StackView.status:
    // when this page becomes the Active (current) item again, offer the enrolled
    // biometric / Hello login automatically, exactly as on launch. The OS prompt
    // is cancelable, so a user switching to a DIFFERENT account simply dismisses
    // it and types the new nickname.
    StackView.onStatusChanged: {
        if (StackView.status === StackView.Active)
            autoBioTimer.restart()
    }

    // Single guarded entry point for showing the OS login prompt, shared by the
    // manual button and the auto-prompt so ONE activation (physical or automatic)
    // yields exactly ONE prompt -- two overlapping calls would pop Windows Hello
    // twice (the historical double-prompt bug). Disarms on use and re-arms
    // shortly after, so a deliberate later retry still works. The conditions are
    // re-checked here at fire time because the user may have edited the fields
    // between the trigger and this call.
    property bool bioArmed: true
    function triggerBioLogin() {
        if (!bioArmed)
            return
        var nick = nickField.text.trim()
        if (nick.length === 0 || serverField.text.trim().length === 0)
            return
        if (!ChatClient.biometricLoginAvailable
                || !ChatClient.hasBiometricLogin(nick))
            return
        bioArmed = false
        bioRearmTimer.restart()
        ChatClient.biometricLogin(serverField.text.trim(), nick)
    }
    Timer {
        id: bioRearmTimer
        interval: 1200
        onTriggered: root.bioArmed = true
    }
    // A short delay lets the screen paint and the prefill settle before the
    // system prompt appears, so it does not race the page transition.
    Timer {
        id: autoBioTimer
        interval: 350
        onTriggered: root.triggerBioLogin()
    }

    // SCROLLABLE FORM. Everything below used to be a bare centred column, so
    // any content that did not fit was simply unreachable -- there was nothing
    // to scroll. Wrapping it in a Flickable costs nothing when the form fits
    // (contentHeight equals the viewport, so it never moves) and is the whole
    // difference between a usable and an unusable screen when it does not.
    Flickable {
        id: formFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: formColumn.y + formColumn.height + root.formPad
                       + root.keyboardInset
        // Match ChatPage's message list: no rubber-band overshoot, so the form
        // cannot be dragged away from its edges and left there.
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick

        // Visible only when there is something to scroll to, so the ordinary
        // desktop case is unchanged.
        ScrollBar.vertical: ScrollBar {
            policy: formFlick.contentHeight > formFlick.height
                    ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff
        }

        ColumnLayout {
            id: formColumn
            width: Math.max(0, Math.min(formFlick.width - 64, 360))
            // Horizontally centred always. Vertically centred only while the
            // form FITS: once it is taller than the viewport (a short window, a
            // phone, or the keyboard eating the lower half) it anchors to the
            // top instead, so the overflow all falls below where it can be
            // scrolled to, rather than half of it disappearing off the top.
            x: (formFlick.width - width) / 2
            y: Math.max(root.formPad,
                        (formFlick.height - root.keyboardInset - height) / 2)
            spacing: 22

            // ---- Signature lockup ------------------------------------------
            ColumnLayout {
                Layout.alignment: Qt.AlignHCenter
                spacing: 12

                // A framed monospace padlock with a soft concentric HALO. The halo
                // is three stacked rounded squares of decreasing opacity behind the
                // tile -- a blur-free glow that ties into the accent identity.
                Item {
                    Layout.alignment: Qt.AlignHCenter
                    width: 66; height: 66

                    Rectangle {
                        anchors.centerIn: parent
                        width: 104; height: 104; radius: 30
                        color: window.pal.accent
                        opacity: 0.06
                    }
                    Rectangle {
                        anchors.centerIn: parent
                        width: 86; height: 86; radius: 24
                        color: window.pal.accent
                        opacity: 0.10
                    }
                    Rectangle {
                        id: lockTile
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
                            font.pixelSize: 30
                        }
                    }
                }

                Label {
                    text: App.Localization.tIn(App.Localization.language, "login.title")
                    color: window.pal.text
                    font.pixelSize: 30
                    font.weight: Font.DemiBold
                    font.letterSpacing: 0.5
                    Layout.alignment: Qt.AlignHCenter
                }

                // Monospace tagline -- reads like a key fingerprint, reinforcing
                // the security identity without a marketing sentence.
                Label {
                    text: "end-to-end encrypted \u00B7 zero-knowledge relay"
                    color: window.pal.accent
                    font.family: "monospace"
                    font.pixelSize: 11
                    opacity: 0.85
                    Layout.alignment: Qt.AlignHCenter
                }
            }

            Label {
                text: "Messages are encrypted on your device. The server relays them without ever seeing their contents."
                color: window.pal.textDim
                horizontalAlignment: Text.AlignHCenter
                font.pixelSize: 12
                lineHeight: 1.2
                Layout.fillWidth: true
                Layout.topMargin: 4
                wrapMode: Text.WordWrap
            }

            // ---- Nickname --------------------------------------------------
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 6
                Label {
                    text: App.Localization.tIn(App.Localization.language, "login.nickname")
                    color: window.pal.textDim
                    font.pixelSize: 11
                    font.capitalization: Font.AllUppercase
                    font.letterSpacing: 1.0
                }
                TextField {
                    id: nickField
                    placeholderText: "Choose a nickname"
                    color: window.pal.text
                    Layout.fillWidth: true
                    Material.accent: window.pal.accent
                    onAccepted: if (loginButton.enabled) loginButton.clicked()
                }
            }

            // ---- Server ----------------------------------------------------
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 6
                Label {
                    text: "Server"
                    color: window.pal.textDim
                    font.pixelSize: 11
                    font.capitalization: Font.AllUppercase
                    font.letterSpacing: 1.0
                }
                TextField {
                    id: serverField
                    placeholderText: "wss://host:port"
                    text: "wss://localhost:8765"
                    color: window.pal.text
                    font.family: "monospace"
                    font.pixelSize: 13
                    Layout.fillWidth: true
                    Material.accent: window.pal.accent
                    onAccepted: if (loginButton.enabled) loginButton.clicked()
                }
            }

            // ---- Password --------------------------------------------------
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 6
                // Caption row: the field's own label on the left, the recovery link
                // on the right.
                //
                // "Forgotten password?" used to be the second-to-last control on
                // the page, below both action buttons -- the part of a form a phone
                // screen runs out of room for first, so in practice it appeared
                // jammed against the bottom edge and was awkward to hit. It belongs
                // beside the field it is about: it is now always on screen with the
                // password input, which is where a user who cannot remember their
                // password is already looking.
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8

                    Label {
                        text: App.Localization.tIn(App.Localization.language, "login.password")
                        color: window.pal.textDim
                        font.pixelSize: 11
                        font.capitalization: Font.AllUppercase
                        font.letterSpacing: 1.0
                        Layout.alignment: Qt.AlignVCenter
                    }

                    Item { Layout.fillWidth: true }

                    Button {
                        id: forgotButton
                        flat: true
                        text: App.Localization.tIn(App.Localization.language, "login.forgot")
                        // A 44px target with real horizontal padding. The button
                        // previously took its height from a 13px label plus the
                        // style's own padding, which lands near 30px -- under every
                        // published minimum for a touch target, and the other half
                        // of "really hard to click".
                        Layout.preferredHeight: 44
                        Layout.alignment: Qt.AlignVCenter
                        leftPadding: 10
                        rightPadding: 10
                        onClicked: {
                            recoverDialog.prepare()
                            recoverDialog.open()
                        }
                        contentItem: Label {
                            text: forgotButton.text
                            color: window.pal.accent
                            font.pixelSize: 13
                            font.underline: forgotButton.hovered
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        background: Rectangle {
                            radius: 10
                            color: forgotButton.down ? window.pal.surfaceHi
                                                     : "transparent"
                        }
                    }
                }
                TextField {
                    id: passwordField
                    placeholderText: (typeof ChatClient.hasLocalIdentity === "function"
                                      && ChatClient.hasLocalIdentity(nickField.text.trim()))
                                     ? App.Localization.tIn(App.Localization.language, "login.passwordHintLogin")
                                     : App.Localization.tIn(App.Localization.language, "login.passwordHint")
                    echoMode: TextInput.Password
                    color: window.pal.text
                    Layout.fillWidth: true
                    Material.accent: window.pal.accent
                    onAccepted: if (loginButton.enabled) loginButton.clicked()
                }
                // A one-line reassurance that the password is zero-knowledge.
                Label {
                    text: App.Localization.tIn(App.Localization.language, "login.pwHelp")
                    color: window.pal.textDim
                    font.pixelSize: 10
                    lineHeight: 1.15
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    opacity: 0.8
                }

                // ---- Date of birth (required to REGISTER) ------------------
                // Needed only when creating an account. A returning user never
                // supplies it, so nobody with an existing account is affected.
                //
                // It is never stored as a date: the client derives an Argon2id
                // verifier from it, sends that to the server, and keeps a copy
                // locally so "Forgotten password?" can check it without asking
                // the server (which would make the relay a guessing oracle).
                Label {
                    text: App.Localization.tIn(App.Localization.language, "login.birthday")
                    color: window.pal.textDim
                    font.pixelSize: 11
                    font.capitalization: Font.AllUppercase
                    font.letterSpacing: 1.0
                }
                TextField {
                    id: birthdayField
                    placeholderText: App.Localization.tIn(App.Localization.language, "login.birthdayHint")
                    inputMethodHints: Qt.ImhDate
                    color: window.pal.text
                    Layout.fillWidth: true
                    Material.accent: window.pal.accent
                    readonly property bool valid:
                        text.trim().length === 0
                        || ChatClient.normalizeBirthday(text) !== ""
                    onAccepted: if (loginButton.enabled) loginButton.clicked()
                }
                Label {
                    text: birthdayField.valid
                          ? App.Localization.tIn(App.Localization.language, "login.birthdayHelp")
                          : App.Localization.tIn(App.Localization.language, "login.birthdayInvalid")
                    color: birthdayField.valid ? window.pal.textDim : window.pal.accent
                    font.pixelSize: 10
                    lineHeight: 1.15
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    opacity: 0.85
                }

                // ---- Enable biometric / Hello login (opt-in) ---------------
                // Shown only where the platform can do it AND it is not already on
                // for this nickname. When ticked, the just-typed password is held in
                // memory and -- once THIS login is CONFIRMED by the server -- wrapped
                // by the OS credential store (Android Keystore / Windows DPAPI) so
                // the next login can be a fingerprint / Hello tap. Nothing is stored
                // if the login is rejected. See ChatClient.requestBiometricLoginEnroll.
                CheckBox {
                    id: enrollBioCheck
                    visible: ChatClient.biometricLoginAvailable
                             && !ChatClient.hasBiometricLogin(nickField.text.trim())
                    Material.accent: window.pal.accent
                    Layout.fillWidth: true
                    Layout.topMargin: 2
                    // The control MUST carry the text itself. With an empty `text`
                    // the Material style treats the checkbox as label-less and
                    // CENTRES its indicator in the control's whole width -- which,
                    // on a fillWidth checkbox, drops the tick right on top of the
                    // caption (the "green check sitting in the middle of the words"
                    // bug). Setting `text` makes the style left-align the indicator;
                    // the custom contentItem below then renders that same text,
                    // dimmed and offset past the indicator, so tick and caption no
                    // longer overlap.
                    text: ChatClient.usesOsCredential
                          ? App.Localization.tIn(App.Localization.language, "login.enableBio")
                          : App.Localization.tIn(App.Localization.language, "login.enableHello")
                    contentItem: Label {
                        text: enrollBioCheck.text
                        color: window.pal.textDim
                        font.pixelSize: 11
                        verticalAlignment: Text.AlignVCenter
                        wrapMode: Text.WordWrap
                        leftPadding: enrollBioCheck.indicator.width + enrollBioCheck.spacing
                    }
                }
            }

            // ---- Actions: Log in / Register --------------------------------
            // Two distinct buttons, as chosen for the demo. Both require a nickname,
            // server, and password. Register creates a new account; Log in unlocks
            // an existing one. The backend reports a clear message on the wrong
            // choice, so a mistaken tap is self-explaining rather than silent.
            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 6
                spacing: 12

                Button {
                    id: loginButton
                    text: App.Localization.tIn(App.Localization.language, "login.login")
                    highlighted: true
                    Layout.fillWidth: true
                    Layout.preferredHeight: 48
                    enabled: nickField.text.trim().length > 0
                             && serverField.text.trim().length > 0
                             && passwordField.text.length > 0
                    onClicked: {
                        // If the user opted in, record the enroll intent BEFORE the
                        // login starts so the backend wraps the password only once
                        // the server confirms this login.
                        if (enrollBioCheck.visible && enrollBioCheck.checked)
                            ChatClient.requestBiometricLoginEnroll(passwordField.text)
                        root.loginRequested(serverField.text.trim(),
                                            nickField.text.trim(),
                                            passwordField.text)
                    }
                    contentItem: Label {
                        text: loginButton.text
                        color: loginButton.enabled ? window.pal.base
                                                    : window.pal.textDim
                        font.pixelSize: 15
                        font.weight: Font.DemiBold
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    // Raised accent gradient with a gloss edge on top, flattening to
                    // accentDim on press.
                    background: Rectangle {
                        radius: 12
                        color: !loginButton.enabled ? window.pal.surfaceHi
                               : loginButton.down   ? window.pal.accentDim
                                                     : "transparent"
                        gradient: (loginButton.enabled && !loginButton.down)
                                  ? loginGrad : null
                        Gradient {
                            id: loginGrad
                            GradientStop { position: 0.0; color: window.pal.accentHi }
                            GradientStop { position: 1.0; color: window.pal.accent }
                        }
                        Behavior on color { ColorAnimation { duration: 120 } }

                        Rectangle {
                            visible: loginButton.enabled && !loginButton.down
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

                Button {
                    id: registerButton
                    text: App.Localization.tIn(App.Localization.language, "login.register")
                    Layout.fillWidth: true
                    Layout.preferredHeight: 48
                    enabled: nickField.text.trim().length > 0
                             && serverField.text.trim().length > 0
                             && passwordField.text.length > 0
                             && birthdayField.text.trim().length > 0
                             && birthdayField.valid
                    onClicked: {
                        // A brand-new user's FIRST sign-in is a Register, so the
                        // enroll opt-in must be honoured here too -- otherwise the
                        // ticked "enable Hello / fingerprint login" box was ignored
                        // when the account was first created, and biometric login
                        // was never enrolled. The server sends the same key dump
                        // after a successful register as after a login, so the
                        // confirmed-login enroll hook fires either way.
                        if (enrollBioCheck.visible && enrollBioCheck.checked)
                            ChatClient.requestBiometricLoginEnroll(passwordField.text)
                        root.registerRequested(serverField.text.trim(),
                                               nickField.text.trim(),
                                               passwordField.text,
                                               birthdayField.text.trim())
                    }
                    contentItem: Label {
                        text: registerButton.text
                        color: registerButton.enabled ? window.pal.accent
                                                       : window.pal.textDim
                        font.pixelSize: 15
                        font.weight: Font.DemiBold
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    background: Rectangle {
                        radius: 12
                        color: registerButton.down ? window.pal.surfaceHi : "transparent"
                        border.width: 1.5
                        border.color: registerButton.enabled ? window.pal.accent
                                                              : window.pal.surfaceHi
                        Behavior on border.color { ColorAnimation { duration: 120 } }
                    }
                }
            }

            // ---- Forgotten password? ---------------------------------------
            // The recovery link now lives in the PASSWORD caption row above, beside
            // the field it concerns, rather than at the foot of the page where the
            // screen ran out of room for it. It is still always visible, for the
            // reason it always was: a user who has forgotten their password needs
            // to be TOLD whether recovery is possible on this device, and hiding
            // the button would leave them with no explanation at all.

            // ---- Log in with Hello / fingerprint (returning user) ----------
            // Shown only when biometric login is ENROLLED for the entered nickname.
            // Tapping proves presence to the OS (Windows Hello, or the Android
            // fingerprint/PIN prompt); on success the stored password is released
            // and the normal login runs -- no password typing required. The label
            // follows the platform (usesOsCredential is true only on Android).
            Button {
                id: bioLoginButton
                visible: ChatClient.biometricLoginAvailable
                         && ChatClient.hasBiometricLogin(nickField.text.trim())
                Layout.fillWidth: true
                Layout.preferredHeight: 46
                enabled: nickField.text.trim().length > 0
                         && serverField.text.trim().length > 0
                // Both a manual tap and the automatic prompt go through the SAME
                // guarded entry point (root.triggerBioLogin), so one shared arming
                // flag prevents a tap and an auto-fire from popping the OS prompt
                // twice. The function re-checks enrollment/fields and disarms itself.
                onClicked: root.triggerBioLogin()
                contentItem: RowLayout {
                    spacing: 8
                    Item { Layout.fillWidth: true }
                    Label {
                        text: "\uD83D\uDD10"   // closed lock with key: the login motif
                        font.pixelSize: 16
                    }
                    Label {
                        text: ChatClient.usesOsCredential
                              ? App.Localization.tIn(App.Localization.language, "login.bioLogin")
                              : App.Localization.tIn(App.Localization.language, "login.helloLogin")
                        color: bioLoginButton.enabled ? window.pal.accent
                                                      : window.pal.textDim
                        font.pixelSize: 14
                        font.weight: Font.DemiBold
                        verticalAlignment: Text.AlignVCenter
                    }
                    Item { Layout.fillWidth: true }
                }
                background: Rectangle {
                    radius: 12
                    color: bioLoginButton.down ? window.pal.surface : "transparent"
                    border.width: 1.5
                    border.color: bioLoginButton.enabled ? window.pal.accent
                                                         : window.pal.surfaceHi
                    Behavior on border.color { ColorAnimation { duration: 120 } }
                }
            }
        }
    }

    // =====================================================================
    //  Password recovery sheet ("Forgotten password?")
    //
    //  WHAT THIS DOES, STATED PLAINLY: it does not recover the password from
    //  the account. The server holds only an irreversible Argon2id verifier,
    //  so no message to it could ever return a password. What this does is
    //  release the copy held in THIS DEVICE's biometric vault (Android
    //  Keystore / Windows Hello + DPAPI), which exists only if the user
    //  previously logged in here and switched fingerprint/Hello sign-in on.
    //
    //  The date of birth is checked locally first, then the OS prompt runs.
    //  The OS prompt is the real gate; the birthday is a secondary check.
    //
    //  popupType: Popup.Item is required. Qt 6.10 changed the default to
    //  Popup.Window, which renders this off-screen on Android.
    // =====================================================================
    Dialog {
        id: recoverDialog
        popupType: Popup.Item
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(root.width - 48, 420)
        padding: 20
        closePolicy: Popup.CloseOnEscape

        // Holds the revealed password while the sheet is open. Cleared on
        // close so it does not linger in QML memory any longer than the user
        // is actually looking at it.
        property string revealed: ""
        property string errorText: ""
        property bool busy: false

        // NOT named reset(). Dialog inherits a reset() SIGNAL (the one emitted
        // by a DialogButtonBox.Reset button), and declaring a function of the
        // same name is an invalid override -- Qt reports
        //   "Duplicate method name: invalid override of property change signal
        //    or superclass signal"
        // and the component fails to load. The other inherited Dialog signals
        // to avoid here are accepted, rejected, applied, discarded and
        // helpRequested.
        function prepare() {
            revealed = ""
            errorText = ""
            busy = false
            recUser.text = nickField.text.trim()
            recDob.text = ""
        }

        onClosed: {
            revealed = ""
            errorText = ""
        }

        background: Rectangle {
            radius: 16
            color: window.pal.surface
            border.width: 1
            border.color: window.pal.surfaceHi
        }

        contentItem: ColumnLayout {
            spacing: 12

            // TITLE ROW, with a close control on the right.
            //
            // This sheet had no visible way out of its first step. The only
            // exit was closePolicy: Popup.CloseOnEscape -- a key with no
            // on-screen affordance, and one that Android does not have at all
            // (the system back button arrives as Qt.Key_Back, which Popup does
            // not treat as Escape). So on a phone the dialog could not be
            // dismissed by any means, and on the desktop only by guessing.
            //
            // The state that made it plain is the one a user in trouble
            // actually reaches: recovery is refused on a device that never
            // enrolled Hello, the explanation appears, Submit stays disabled
            // because it gates on the fields rather than on whether anything
            // can come of pressing it -- and there is no button left to press.
            // A modal with no exit in its failure state is a trap.
            RowLayout {
                Layout.fillWidth: true
                spacing: 8

                Label {
                    text: recoverDialog.revealed.length > 0
                          ? App.Localization.tIn(App.Localization.language, "recover.titleRevealed")
                          : App.Localization.tIn(App.Localization.language, "recover.title")
                    color: window.pal.text
                    font.pixelSize: 18
                    font.weight: Font.DemiBold
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                }

                Button {
                    id: recoverCloseButton
                    flat: true
                    // Sized like every other touch target in this file rather
                    // than to the glyph. It stays visually light because the
                    // background is transparent until pressed, so a 44px hit
                    // area does not read as a 44px button.
                    Layout.preferredWidth: 44
                    Layout.preferredHeight: 44
                    Layout.alignment: Qt.AlignVCenter
                    onClicked: recoverDialog.close()
                    contentItem: Label {
                        text: "\u2715"          // MULTIPLICATION X
                        color: recoverCloseButton.hovered ? window.pal.text
                                                          : window.pal.textDim
                        font.pixelSize: 16
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    background: Rectangle {
                        radius: 10
                        color: recoverCloseButton.down ? window.pal.surfaceHi
                                                       : "transparent"
                    }
                    ToolTip.visible: recoverCloseButton.hovered
                    ToolTip.text: App.Localization.tIn(App.Localization.language,
                                                       "recover.close")
                }
            }

            // ---------- Step 1: identify ----------
            ColumnLayout {
                visible: recoverDialog.revealed.length === 0
                spacing: 8
                Layout.fillWidth: true

                Label {
                    text: ChatClient.usesOsCredential
                          ? App.Localization.tIn(App.Localization.language, "recover.introBio")
                          : App.Localization.tIn(App.Localization.language, "recover.introHello")
                    color: window.pal.textDim
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                TextField {
                    id: recUser
                    placeholderText: App.Localization.tIn(App.Localization.language, "recover.user")
                    color: window.pal.text
                    Layout.fillWidth: true
                    Material.accent: window.pal.accent
                }
                TextField {
                    id: recDob
                    placeholderText: App.Localization.tIn(App.Localization.language, "recover.dobHint")
                    inputMethodHints: Qt.ImhDate
                    color: window.pal.text
                    Layout.fillWidth: true
                    Material.accent: window.pal.accent
                    onAccepted: if (submitRecover.enabled) submitRecover.clicked()
                }

                Label {
                    visible: recoverDialog.errorText.length > 0
                    text: recoverDialog.errorText
                    color: window.pal.accent
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                // The pair reads like the Log in / Register pair on the
                // form behind it: the way out on the left, the action on the
                // right. Submit can be disabled -- and is, in the failure
                // state -- so the way out must never be.
                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: 2
                    spacing: 10

                    Button {
                        id: cancelRecover
                        text: App.Localization.tIn(App.Localization.language, "recover.back")
                        Layout.fillWidth: true
                        Layout.preferredHeight: 44
                        // Never gated on anything. Whatever state the sheet is
                        // in, including one where nothing can be submitted,
                        // this returns to the sign-in screen.
                        onClicked: recoverDialog.close()
                        contentItem: Label {
                            text: cancelRecover.text
                            color: window.pal.textDim
                            font.pixelSize: 14
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                            elide: Text.ElideRight
                        }
                        background: Rectangle {
                            radius: 12
                            color: cancelRecover.down ? window.pal.surfaceHi
                                                      : "transparent"
                            border.width: 1
                            border.color: window.pal.surfaceHi
                        }
                    }

                    Button {
                        id: submitRecover
                        text: recoverDialog.busy ? App.Localization.tIn(App.Localization.language, "recover.waiting")
                                                 : App.Localization.tIn(App.Localization.language, "recover.submit")
                        Layout.fillWidth: true
                        Layout.preferredHeight: 44
                        enabled: !recoverDialog.busy
                                 && recUser.text.trim().length > 0
                                 && recDob.text.trim().length > 0
                        onClicked: {
                            recoverDialog.errorText = ""
                            recoverDialog.busy = true
                            ChatClient.recoverPassword(serverField.text.trim(),
                                                       recUser.text.trim(),
                                                       recDob.text.trim())
                        }
                    }
                }
            }

            // ---------- Step 2: reveal ----------
            ColumnLayout {
                visible: recoverDialog.revealed.length > 0
                spacing: 10
                Layout.fillWidth: true

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 56
                    radius: 12
                    color: window.pal.surfaceHi
                    border.width: 1
                    border.color: window.pal.accent
                    TextInput {
                        anchors.fill: parent
                        anchors.margins: 14
                        text: recoverDialog.revealed
                        readOnly: true
                        selectByMouse: true
                        color: window.pal.text
                        font.pixelSize: 17
                        font.family: "monospace"
                        verticalAlignment: TextInput.AlignVCenter
                    }
                }

                Label {
                    text: App.Localization.tIn(App.Localization.language, "recover.warning")
                    color: window.pal.textDim
                    font.pixelSize: 11
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                Button {
                    text: App.Localization.tIn(App.Localization.language, "recover.back")
                    Layout.fillWidth: true
                    Layout.preferredHeight: 44
                    onClicked: {
                        passwordField.text = ""
                        nickField.text = recUser.text.trim()
                        recoverDialog.close()
                    }
                }
            }
        }

        // Outcomes from ChatClient. The password arrives here and is placed in
        // a read-only field; it is never written to settings or to the log.
        Connections {
            target: ChatClient
            function onPasswordRevealed(password) {
                recoverDialog.busy = false
                recoverDialog.errorText = ""
                recoverDialog.revealed = password
                if (!recoverDialog.opened)
                    recoverDialog.open()
            }
            function onPasswordRecoveryFailed(reason) {
                recoverDialog.busy = false
                recoverDialog.errorText = reason
            }
        }
    }
}
