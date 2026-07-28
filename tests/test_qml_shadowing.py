"""
test_qml_shadowing.py -- QML declarations must not shadow inherited members.

WHY THIS EXISTS
---------------
Twice in a row, a custom member declared inside a Dialog collided with a member
Dialog already inherits from Popup, and each time the whole application failed
to start:

    function reset()                -> Dialog has a reset() SIGNAL
       "Duplicate method name: invalid override of property change signal or
        superclass signal"

    property real bottomInset       -> Popup has a FINAL bottomInset property
       "Cannot override FINAL property"

Neither is caught by the compiler. QML resolves these at load time, so the build
succeeds, the application launches, the engine fails to construct the root
component, and main() returns -1. On Android that looks like an instant crash
with the real reason buried in logcat.

The reserved names below were read from the live QMetaObject of a
QtQuick.Controls Dialog on Qt 6.11.1 -- the same version this project builds
against -- rather than copied from documentation, so the list matches what the
runtime will actually enforce.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
QML_DIR = REPO_ROOT / "client" / "qml"

# Popup/Dialog properties declared FINAL. Redeclaring any of these is a hard
# load error. The insets and paddings are the easy ones to hit by accident,
# because they are exactly the names a developer reaches for when adding
# platform spacing.
FINAL_PROPERTIES = {
    "activeFocus", "anchors", "availableHeight", "availableWidth", "background",
    "bottomInset", "bottomMargin", "bottomPadding", "clip", "closePolicy",
    "contentChildren", "contentHeight", "contentItem", "contentWidth", "dim",
    "enabled", "enter", "exit", "focus", "font", "footer", "header", "height",
    "horizontalPadding", "implicitBackgroundHeight", "implicitBackgroundWidth",
    "implicitContentHeight", "implicitContentWidth", "implicitFooterHeight",
    "implicitFooterWidth", "implicitHeaderHeight", "implicitHeaderWidth",
    "implicitHeight", "implicitWidth", "leftInset", "leftMargin", "leftPadding",
    "locale", "margins", "mirrored", "modal", "opacity", "opened", "padding",
    "parent", "popupType", "result", "rightInset", "rightMargin",
    "rightPadding", "scale", "spacing", "standardButtons", "title", "topInset",
    "topMargin", "topPadding", "transformOrigin", "verticalPadding", "visible",
    "width", "x", "y", "z",
}

# Signals. A JavaScript function of the same name is an invalid override.
# The button signals (accepted/rejected/applied/reset/discarded/helpRequested)
# are the plausible ones to collide with; the *Changed signals are listed for
# completeness because a property named e.g. "opened" would generate one.
DIALOG_SIGNALS = {
    "aboutToHide", "aboutToShow", "accepted", "applied", "closed", "discarded",
    "helpRequested", "opened", "rejected", "reset",
}

# Types whose bodies we inspect. All of them inherit Popup's member set.
POPUP_TYPES = ("Dialog", "Popup", "Menu", "ToolTip")

DECL_RE = re.compile(
    r"^\s*(?:readonly\s+|default\s+|required\s+)*property\s+\S+\s+([A-Za-z_]\w*)"
    r"|^\s*function\s+([A-Za-z_]\w*)\s*\(")


def _members_declared_directly_in_popups(text: str):
    """
    Yield (line_no, kind, name) for members declared at the top level of a
    Dialog/Popup/Menu/ToolTip body.

    Brace counting is crude but sufficient here: it only needs to know when it
    is exactly one level inside a popup block, and the project's QML is
    conventionally formatted. Strings and comments are skipped so a brace inside
    either cannot throw the depth off.
    """
    lines = text.split("\n")
    stack = []          # depth at which each open popup block started
    depth = 0
    in_block_comment = False

    for n, raw in enumerate(lines, start=1):
        line = raw
        if in_block_comment:
            if "*/" in line:
                line = line.split("*/", 1)[1]
                in_block_comment = False
            else:
                continue
        if "/*" in line:
            before, _, rest = line.partition("/*")
            if "*/" in rest:
                line = before + rest.split("*/", 1)[1]
            else:
                line = before
                in_block_comment = True
        line = line.split("//", 1)[0]
        line = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
        line = re.sub(r"'(?:[^'\\]|\\.)*'", "''", line)

        opens_popup = any(re.search(rf"\b{t}\s*\{{", line) for t in POPUP_TYPES)

        if stack and depth == stack[-1] + 1:
            m = DECL_RE.match(raw.split("//", 1)[0])
            if m:
                name = m.group(1) or m.group(2)
                kind = "property" if m.group(1) else "function"
                yield n, kind, name

        for ch in line:
            if ch == "{":
                depth += 1
                if opens_popup:
                    stack.append(depth - 1)
                    opens_popup = False
            elif ch == "}":
                if stack and depth == stack[-1] + 1:
                    stack.pop()
                depth -= 1


def _qml_files():
    return sorted(QML_DIR.glob("*.qml"))


@pytest.mark.parametrize("qml", _qml_files(), ids=lambda p: p.name)
def test_no_popup_member_is_shadowed(qml: Path):
    text = qml.read_text(encoding="utf-8", errors="replace")
    problems = []
    for line_no, kind, name in _members_declared_directly_in_popups(text):
        if kind == "property" and name in FINAL_PROPERTIES:
            problems.append(
                f"{qml.name}:{line_no} declares 'property {name}', which "
                f"redeclares Popup's FINAL '{name}'. Qt refuses to load the "
                f"component: 'Cannot override FINAL property'."
            )
        if kind == "function" and name in DIALOG_SIGNALS:
            problems.append(
                f"{qml.name}:{line_no} declares 'function {name}()', which "
                f"shadows the inherited Dialog.{name}() signal: 'Duplicate "
                f"method name: invalid override of ... superclass signal'."
            )
    assert not problems, "\n".join(problems)


def test_the_two_historical_regressions_stay_fixed():
    """Name the specific defects, so a revert is reported unambiguously."""
    chat = (QML_DIR / "ChatPage.qml").read_text(encoding="utf-8", errors="replace")
    login = (QML_DIR / "LoginPage.qml").read_text(encoding="utf-8", errors="replace")
    assert "property real bottomInset" not in chat, (
        "ChatPage.qml redeclares Popup's FINAL bottomInset again"
    )
    assert "function reset(" not in login, (
        "LoginPage.qml declares function reset() again, shadowing Dialog.reset()"
    )


def test_the_checker_actually_detects_a_shadow():
    """
    A guard that has never fired proves nothing, so exercise it on a synthetic
    body containing both historical defects.
    """
    sample = """
    Dialog {
        id: d
        readonly property real bottomInset: 28
        function reset() { }
        readonly property real navBarGap: 28
        function prepare() { }
    }
    """
    found = {(k, n) for _, k, n in _members_declared_directly_in_popups(sample)}
    assert ("property", "bottomInset") in found
    assert ("function", "reset") in found
    assert ("property", "navBarGap") in found
    assert ("function", "prepare") in found


# --------------------------------------------------------------------------
# Popups must render INSIDE the window
# --------------------------------------------------------------------------
#
# Qt 6.10 changed Popup's default popupType to Popup.Window, so a Dialog or
# Menu that does not say otherwise becomes a separate native window. On Android
# that lands off-screen: the dialog opens, takes the input focus, and is not
# visible anywhere. It is invisible to the compiler and to every Python test
# that does not read the QML, and the failure looks like the application
# hanging rather than like a layout bug.
#
# ChatPage.qml states the rule as "applied to EVERY Menu and Dialog in the
# app". This test is what makes that sentence true, rather than a comment that
# was accurate on the day it was written -- LockScreen.qml's reset dialog had
# already drifted out of compliance, and it was the dialog behind "Forgot PIN?".
#
# FileDialog is excluded deliberately: it comes from QtQuick.Dialogs, is a
# native platform dialog, and has no popupType property at all.

POPUP_TYPES = ("Dialog", "Menu", "Popup", "ToolTip")
NATIVE_DIALOGS = ("FileDialog", "FolderDialog", "ColorDialog", "FontDialog",
                  "MessageDialog")


def _popup_declarations(text: str):
    """(line number, type, id) for every Controls popup declared in a file."""
    out = []
    lines = text.split("\n")
    for i, line in enumerate(lines):
        m = re.match(r"\s*([A-Z][A-Za-z]*)\s*\{\s*$", line)
        if not m:
            continue
        kind = m.group(1)
        if kind in NATIVE_DIALOGS or kind not in POPUP_TYPES:
            continue
        ident = ""
        for probe in lines[i + 1:i + 40]:
            mid = re.match(r"\s*id:\s*([A-Za-z_][A-Za-z0-9_]*)", probe)
            if mid:
                ident = mid.group(1)
                break
        out.append((i + 1, kind, ident))
    return out


@pytest.mark.parametrize("qml_file", sorted(QML_DIR.glob("*.qml")),
                         ids=lambda p: p.name)
def test_every_popup_declares_an_in_scene_popup_type(qml_file):
    text = qml_file.read_text(encoding="utf-8", errors="replace")
    lines = text.split("\n")

    offenders = []
    for lineno, kind, ident in _popup_declarations(text):
        # popupType is a direct property of the declaration, so look only at
        # the block's own lines -- until the indentation returns to or below
        # that of the declaration itself.
        decl_indent = len(lines[lineno - 1]) - len(lines[lineno - 1].lstrip())
        body = []
        for probe in lines[lineno:]:
            if probe.strip() and (len(probe) - len(probe.lstrip())) <= decl_indent:
                break
            body.append(probe)
        # Match the PROPERTY ASSIGNMENT, not the word. Several of these blocks
        # carry a comment explaining why popupType is set, and a substring
        # search happily accepts the comment as if it were the property -- so
        # deleting the real line would leave this test passing. That false
        # negative was found by mutating the source and watching the test stay
        # green, which is the only way such a hole ever shows itself.
        declared = any(
            re.match(r"\s*popupType\s*:", b) and not b.lstrip().startswith("//")
            for b in body
        )
        if not declared:
            offenders.append(f"{kind} {ident or '(no id)'} at line {lineno}")

    assert not offenders, (
        f"{qml_file.name}: these popups do not set popupType, so on Qt 6.10+ "
        f"they become separate native windows and land off-screen on Android: "
        f"{offenders}"
    )
