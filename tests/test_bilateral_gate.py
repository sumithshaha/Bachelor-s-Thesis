"""
test_bilateral_gate.py -- the rule that no data moves until BOTH sides verify.

The requirement: unless each party has independently confirmed the safety
number, no text and no file may pass between them, in any direction, on any
platform pairing.

The gate lives in the Qt client, which cannot be compiled here, so these are
source-level assertions over chatclient.cpp. That is weaker than executing the
code, but it is not merely cosmetic: the failure mode this guards against is a
future edit adding a fifth transfer path, or relaxing one of the four existing
ones back to the earlier unilateral rule, and every one of those shows up as a
change in the text asserted below. The same technique caught two real QML
load failures (see test_qml_shadowing.py).

Where a property CAN be executed -- the trust-anchor scoping masks -- the
constants are parsed out of the C++ and exercised against a boundary table, so
the test follows the source rather than restating it.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CPP = (REPO_ROOT / "client" / "src" / "chatclient.cpp").read_text(
    encoding="utf-8", errors="replace")


def _body(signature: str, limit: int = 6000) -> str:
    """Return the body of the function with this signature.

    The window used to be a fixed character budget, which made every assertion
    in this module quietly dependent on how long the function happened to be:
    tryResolveBilateral grew past its 3000-character allowance and the
    "resolution drains the outbox" test began failing even though the flush was
    still there, 197 characters beyond the cut. A test that reports a defect
    which is not in the code is worse than no test, so the body is now delimited
    the way the compiler delimits it -- by matching braces from the signature's
    opening brace. `limit` is kept as a floor for the fallback so existing call
    sites remain valid.
    """
    idx = CPP.index(signature)
    open_brace = CPP.find("{", idx)
    if open_brace == -1:
        return CPP[idx:idx + limit]
    depth = 0
    for pos in range(open_brace, len(CPP)):
        ch = CPP[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return CPP[idx:pos + 1]
    return CPP[idx:idx + limit]


# --------------------------------------------------------------------------
# 1. The predicate itself
# --------------------------------------------------------------------------

def test_conversation_blocked_requires_both_sides():
    """
    Blocked while EITHER half is outstanding: my own confirmation
    (m_unverifiedKeyChange) or the peer's (m_pendingBilateral, which
    tryResolveBilateral clears only when both have confirmed).
    """
    body = _body("bool ChatClient::conversationBlocked(const QString &peer) const")
    ret = body[body.index("return"):body.index(";", body.index("return"))]
    assert "m_unverifiedKeyChange.contains(peer)" in ret
    assert "m_pendingBilateral.contains(peer)" in ret
    assert "||" in ret, "the two conditions must be OR-ed, not AND-ed"


def test_resolution_requires_both_sides_and_drains_the_outbox():
    """
    An episode ends only when both halves are in. It must also flush, or held
    messages would sit in the outbox until some unrelated event moved them.
    """
    body = _body("void ChatClient::tryResolveBilateral(const QString &peer)", 3000)
    assert "if (!m_pendingBilateral.contains(peer))" in body
    assert "if (m_unverifiedKeyChange.contains(peer))" in body
    assert "if (!m_peerVerified.contains(peer))" in body
    assert "m_pendingBilateral.remove(peer)" in body
    assert "flushOutbox()" in body, "resolution does not drain queued items"


# --------------------------------------------------------------------------
# 2. Every path that moves data
# --------------------------------------------------------------------------

TRANSFER_PATHS = [
    ("void ChatClient::sendMessage(const QString &plaintext)", "text"),
    ("void ChatClient::sendFile(const QUrl &localFileUrl)", "file"),
    ("void ChatClient::flushOutbox()", "queued items"),
    ("void ChatClient::editMessage(const QString &mid, const QString &newText)",
     "message edits"),
]


@pytest.mark.parametrize("signature,what", TRANSFER_PATHS,
                         ids=[w for _, w in TRANSFER_PATHS])
def test_transfer_path_consults_the_gate(signature, what):
    """
    Each path must ask conversationBlocked(), not re-implement the rule. An
    edit transmits a new ciphertext body, so it counts: gating the first send
    but not the edit would let arbitrary new text reach a peer who never
    authenticated us.
    """
    assert "conversationBlocked(" in _body(signature), (
        f"the {what} path does not consult the bilateral gate"
    )


def test_no_transfer_path_kept_the_old_unilateral_rule():
    """
    The gate was briefly unilateral (own verification only). Any transfer path
    testing m_unverifiedKeyChange directly instead of calling the predicate
    would silently reinstate that, since the peer's half would go unchecked.
    """
    offenders = []
    for signature, what in TRANSFER_PATHS:
        body = _body(signature, 2500)
        for m in re.finditer(r"if \(m_unverifiedKeyChange\.contains\([^)]*\)\) \{", body):
            offenders.append(f"{what}: {m.group(0)}")
    assert not offenders, (
        "these transfer paths gate on own verification alone:\n  "
        + "\n  ".join(offenders)
    )


# --------------------------------------------------------------------------
# 3. Hold, do not drop
# --------------------------------------------------------------------------

def test_blocked_text_is_queued_rather_than_discarded():
    """
    A blocked message must survive. Dropping it would lose user data for a
    security condition the user can still resolve a moment later.
    """
    body = _body("void ChatClient::sendMessage(const QString &plaintext)", 2500)
    gate = body[body.index("if (conversationBlocked(m_activePeer))"):]
    assert "queueOutbox(" in gate[:900], "blocked text is not queued"


def test_control_frames_are_exempt_from_the_outbox_gate():
    """
    Handshakes and verifyacks must always pass. A handshake re-establishes the
    crypto chain and a verifyack is how the gate opens: blocking them would
    make the gate unopenable -- a deadlock rather than a safeguard.
    """
    body = _body("void ChatClient::flushOutbox()", 4000)

    # Isolate the CONDITION of the blocking if-statement, not the prose around
    # it: the surrounding comment legitimately discusses handshakes, and an
    # assertion that cannot tell code from commentary tests nothing.
    start = body.index('if ((m.kind == QLatin1String("text")')
    condition = body[start:body.index(") {", start) + 1]

    kinds = set(re.findall(r'm\.kind == QLatin1String\("([a-z_]+)"\)', condition))
    assert kinds == {"text", "file"}, (
        f"the outbox gate blocks these kinds: {sorted(kinds)}. It must block "
        "exactly text and file; blocking a handshake would stop the crypto "
        "chain re-establishing, and blocking a verifyack would make the gate "
        "unopenable -- a deadlock rather than a safeguard."
    )
    assert "conversationBlocked(m.peer)" in condition


# --------------------------------------------------------------------------
# 4. Trust-anchor scoping, driven by the constants in the source
# --------------------------------------------------------------------------

def _parse_ipv4_masks() -> list[tuple[int, int]]:
    """Pull the (mask, value) pairs out of ChatClient::isLabHost()."""
    body = _body("bool ChatClient::isLabHost(const QUrl &url)", 3000)
    pairs = re.findall(r"\(v4 & (0x[0-9A-Fa-f]+)u\) == (0x[0-9A-Fa-f]+)u", body)
    return [(int(m, 16), int(v, 16)) for m, v in pairs]


def test_the_private_ranges_are_the_expected_ones():
    """10/8, 172.16/12, 192.168/16 and link-local 169.254/16, and nothing else."""
    got = set(_parse_ipv4_masks())
    expected = {
        (0xFF000000, 0x0A000000),   # 10.0.0.0/8
        (0xFFF00000, 0xAC100000),   # 172.16.0.0/12
        (0xFFFF0000, 0xC0A80000),   # 192.168.0.0/16
        (0xFFFF0000, 0xA9FE0000),   # 169.254.0.0/16
    }
    assert got == expected, f"unexpected mask set: {sorted(got)}"


BOUNDARY_TABLE = [
    # (address, private?)  -- adjacent addresses either side of every range
    ("10.0.0.5", True), ("10.255.255.254", True),
    ("9.255.255.255", False), ("11.0.0.1", False),
    ("172.16.0.1", True), ("172.31.255.254", True),
    ("172.15.0.1", False), ("172.32.0.1", False),
    ("192.168.1.42", True), ("192.168.255.255", True),
    ("192.167.1.1", False), ("192.169.1.1", False),
    ("169.254.10.1", True), ("169.253.0.1", False),
    ("86.50.22.138", False),          # the public cPouta relay
    ("8.8.8.8", False),
]


@pytest.mark.parametrize("addr,is_private", BOUNDARY_TABLE,
                         ids=[a for a, _ in BOUNDARY_TABLE])
def test_lab_anchor_scope_boundaries(addr, is_private):
    """
    The private trust anchor must apply to loopback and local networks only.
    If it applied everywhere, whoever holds the lab CA key could mint a
    certificate for any public host and this client would accept it.
    """
    masks = _parse_ipv4_masks()
    v4 = int(ipaddress.ip_address(addr))
    matched = any((v4 & m) == val for m, val in masks)
    assert matched == is_private, (
        f"{addr}: source masks say private={matched}, expected {is_private}"
    )


def test_public_hostnames_never_get_the_lab_anchor():
    """A DNS name that is not 'localhost' is treated as public, not resolved."""
    body = _body("bool ChatClient::isLabHost(const QUrl &url)", 3000)
    assert "if (addr.isNull())" in body and "return false" in body, (
        "a non-literal hostname must fall through to 'public'"
    )
    assert 'QLatin1String("localhost")' in body
