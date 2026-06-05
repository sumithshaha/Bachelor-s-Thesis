import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts

// MessageDelegate decides how a single row in the message list looks. Cases:
// a system note (centred, faint), a text bubble (teal right / grey left), and
// a file bubble - which shows an inline image preview when the file is an
// image, or a file row with a Save button otherwise.
//
// The delegate reads the named roles the C++ MessageModel exposes
// (model.text, model.isMine, model.isFile, model.filename, model.mime,
// model.size, model.localPath, model.msgId).

Item {
    id: delegate
    width: ListView.view ? ListView.view.width : 0
    implicitHeight: content.implicitHeight + 4

    // Emitted upward when the user taps Save on a received file, so ChatPage
    // can open a save dialog. Carries the msgId and a suggested filename.
    signal saveFileRequested(string msgId, string filename)

    // ---- System note -----------------------------------------------------
    Label {
        visible: model.isSystem
        anchors.horizontalCenter: parent.horizontalCenter
        text: model.text
        font.pixelSize: 11
        font.italic: true
        opacity: 0.6
        padding: 4
    }

    // ---- A chat bubble ---------------------------------------------------
    Row {
        id: content
        visible: !model.isSystem
        anchors.right: model.isMine ? parent.right : undefined
        anchors.left: model.isMine ? undefined : parent.left
        anchors.margins: 8

        Rectangle {
            id: bubble
            radius: 12
            color: model.isMine ? Material.accent
                                 : Material.color(Material.Grey, Material.Shade800)
            implicitWidth: Math.min(bubbleColumn.implicitWidth + 20,
                                    delegate.width * 0.75)
            implicitHeight: bubbleColumn.implicitHeight + 14

            ColumnLayout {
                id: bubbleColumn
                anchors.fill: parent
                anchors.margins: 8
                spacing: 4

                // ---- Text message body (only for non-file rows) ----------
                Label {
                    visible: !model.isFile
                    text: model.text
                    color: "white"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                // ---- Image preview (file row whose mime is an image) -----
                // Loaded directly from the decrypted temp file on disk. The
                // "file:///" prefix is required for QML to read a local path.
                Image {
                    visible: model.isFile
                             && model.mime.indexOf("image/") === 0
                             && model.localPath.length > 0
                    source: (model.isFile && model.localPath.length > 0)
                            ? "file:///" + model.localPath
                            : ""
                    fillMode: Image.PreserveAspectFit
                    Layout.preferredWidth: Math.min(implicitWidth,
                                                    delegate.width * 0.6)
                    Layout.maximumHeight: 240
                    Layout.fillWidth: true
                    asynchronous: true
                }

                // ---- File row (paperclip + filename + size, for any file) -
                RowLayout {
                    visible: model.isFile
                    spacing: 8
                    Layout.fillWidth: true

                    Label {
                        text: "\uD83D\uDCCE"   // paperclip emoji
                        font.pixelSize: 16
                    }
                    ColumnLayout {
                        spacing: 0
                        Label {
                            text: model.filename
                            color: "white"
                            font.bold: true
                            elide: Text.ElideMiddle
                            Layout.maximumWidth: delegate.width * 0.5
                        }
                        Label {
                            // Human-readable size.
                            text: {
                                var b = model.size;
                                if (b < 1024) return b + " B";
                                if (b < 1024 * 1024)
                                    return (b / 1024).toFixed(1) + " KB";
                                return (b / (1024 * 1024)).toFixed(1) + " MB";
                            }
                            color: "white"
                            opacity: 0.7
                            font.pixelSize: 10
                        }
                    }
                }

                // ---- Save button (only for files I received) -------------
                Button {
                    visible: model.isFile && !model.isMine
                    text: "Save\u2026"
                    flat: true
                    Layout.alignment: Qt.AlignRight
                    onClicked: delegate.saveFileRequested(model.msgId,
                                                          model.filename)
                }

                // ---- Timestamp (always shown) ----------------------------
                Label {
                    text: model.timestamp
                    color: "white"
                    opacity: 0.6
                    font.pixelSize: 9
                    Layout.alignment: Qt.AlignRight
                }
            }
        }
    }
}
