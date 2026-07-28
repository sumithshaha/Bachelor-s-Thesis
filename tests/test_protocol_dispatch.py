"""
test_protocol_dispatch.py -- every message the client sends must be handled.

WHY THIS EXISTS
---------------
The client emitted 'verify_resync' on every login, once per known peer. The
server had no branch for it, so it logged

    WARNING [chat-server] Unknown message type: 'verify_resync'

and dropped the frame. Nothing crashed and no test failed, because the relay
degrades silently: an unknown type is simply ignored.

That silence was expensive. verify_resync is the mechanism that recovers a
STALLED verification episode -- it asks a peer to re-send a verifyack that was
ignored because it attested a since-replaced identity. With the send gate now
bilateral, losing it means both users can sit waiting for an acknowledgement
that neither can request. The gate is exactly as strong as its recovery path.

So this module cross-checks the two sides of the protocol at the source level.
It is crude compared with an integration test, but it catches the whole class
of "one side speaks a word the other never learned" in a single assertion, and
it costs nothing to run.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))

SERVER_SRC = (REPO_ROOT / "server" / "server.py").read_text(encoding="utf-8")
CLIENT_SRC = (REPO_ROOT / "client" / "src" / "chatclient.cpp").read_text(
    encoding="utf-8", errors="replace")


def handled_types() -> set[str]:
    """Message types the server dispatches on."""
    return set(re.findall(r'mtype == "([a-z_]+)"', SERVER_SRC))


def sent_types() -> set[str]:
    """Message types the client puts on the wire."""
    pattern = r'"type"\]?\s*[,=]\s*(?:QStringLiteral\()?"([a-z_]+)"'
    return set(re.findall(pattern, CLIENT_SRC))


def test_every_type_the_client_sends_has_a_server_handler():
    sent = sent_types()
    handled = handled_types()
    assert sent, "extracted no message types from the client -- check the regex"

    missing = sorted(sent - handled)
    assert not missing, (
        "The client sends these types but server.py has no branch for them, so "
        f"the relay will silently drop them: {missing}\n"
        "Add an 'elif mtype == ...' branch, or stop sending the type."
    )


def test_verify_resync_is_handled():
    """The specific regression: the resync request must reach the peer."""
    assert "verify_resync" in handled_types(), (
        "server.py dropped verify_resync, which is how a stalled bilateral "
        "verification episode is recovered."
    )


def test_verify_resync_is_anti_spoofed():
    """
    The sender named in the frame must be the authenticated nick, exactly as
    for text, delete and verifyack. Otherwise one user could ask a peer to
    re-attest somebody else's identity.
    """
    idx = SERVER_SRC.index('elif mtype == "verify_resync"')
    block = SERVER_SRC[idx:idx + 1800]
    assert 'msg["from"] = nick' in block, (
        "verify_resync does not overwrite the 'from' field with the "
        "authenticated nick"
    )
    assert "must log in first" in block, (
        "verify_resync is reachable before authentication"
    )


def test_verify_resync_is_not_stored_and_forwarded():
    """
    Deliberately live-only. It is a request, not an attestation: worthless once
    stale, and emitted once per peer per login, so persisting it would grow
    without bound for a user with many contacts. An offline peer recovers the
    episode from its own side on next login.
    """
    idx = SERVER_SRC.index('elif mtype == "verify_resync"')
    block = SERVER_SRC[idx:idx + 1800]
    assert "save_message" not in block, (
        "verify_resync is being persisted; it is meant to be ephemeral"
    )


def test_verifyack_is_still_stored_and_forwarded():
    """
    The contrast that makes the design coherent: the ACK is a durable fact and
    must survive the recipient being offline, so it keeps using the message
    store. If this ever changes, the bilateral gate would stop opening for a
    peer who was offline when the ack was sent.
    """
    idx = SERVER_SRC.index('elif mtype == "verifyack"')
    block = SERVER_SRC[idx:idx + 1800]
    assert "save_message" in block


@pytest.mark.parametrize("signal", [
    "reset", "accepted", "rejected", "applied", "discarded", "helpRequested",
])
def test_qml_does_not_shadow_inherited_dialog_signals(signal):
    """
    QtQuick.Controls Dialog inherits these SIGNALS. Declaring a JavaScript
    function of the same name inside a Dialog is an invalid override: Qt reports
    "Duplicate method name: invalid override of property change signal or
    superclass signal" at load time and the component fails to instantiate.

    This bit the recovery sheet, which originally declared function reset().
    The failure is easy to miss because it appears as a qt.qml.invalidOverride
    line in the application output rather than as a build error.
    """
    qml = (REPO_ROOT / "client" / "qml" / "LoginPage.qml").read_text(
        encoding="utf-8", errors="replace")
    assert f"function {signal}(" not in qml, (
        f"LoginPage.qml declares function {signal}(), which shadows the "
        f"inherited Dialog.{signal}() signal."
    )
