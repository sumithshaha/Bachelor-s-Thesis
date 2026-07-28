// =============================================================================
// Ratchet interop consumer (production side).
//
// This is the cross-language check for YOUR ratchet. Unlike _ref_interop_recv.cpp
// (a self-contained oracle), this file drives the product implementation in
// client/src/cryptobox.cpp: it asks CryptoBox to initialise a Bob session and to
// decrypt each message of a Python-generated session vector. If every message
// comes back correct, the C++ client and the Python reference agree byte-for-byte
// across a ratcheting session.
//
// It is written against the small API the architecture specifies CryptoBox to
// expose for ratchet sessions. Implement that API, then build and run:
//
//   (link this against your CryptoBox sources + libsodium, e.g. a small CMake
//    target or:)
//   g++ -std=c++17 tests/interop_ratchet.cpp client/src/cryptobox.cpp \
//       -I client/src -I <libsodium-include> <libsodium.a> -o interop_ratchet
//   ./interop_ratchet tests/ratchet_vector.txt
//
// Expected CryptoBox additions (names are suggestions; match your design):
//
//   // Initialise a receiving (Bob) session for `peer`, Route A bootstrap:
//   //   SK   = derive_shared_key(myIdentityPriv, peerIdentityPub)
//   //   DHs  = my identity keypair,  RK = SK
//   bool CryptoBox::initRatchetSessionAsResponder(
//            const QString &peer, const QByteArray &peerIdentityPubKey);
//
//   // Decrypt one ratchet message. header carries dh/pn/n; ad binding is done
//   // inside. Returns plaintext, or empty + decryptionFailed() on auth error.
//   QString CryptoBox::ratchetDecrypt(
//            const QString &peer,
//            const QByteArray &dhPub, quint32 pn, quint32 n,
//            const QByteArray &nonce, const QByteArray &ciphertext);
//
// Because this consumer plays Bob for a one-directional vector, only the
// receiving path is exercised here; the live harness in RATCHET_TESTING.md
// drives both directions.
// =============================================================================
#include "cryptobox.h"   // your product CryptoBox

#include <QByteArray>
#include <QFile>
#include <QString>
#include <QStringList>
#include <QTextStream>

#include <cstdio>

static QByteArray hx(const QString &s) { return QByteArray::fromHex(s.toLatin1()); }

int main(int argc, char **argv) {
    if (argc != 2) {
        std::printf("usage: %s <ratchet_vector.txt>\n", argv[0]);
        return 1;
    }
    QFile f(argv[1]);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        std::printf("cannot open %s\n", argv[1]);
        return 1;
    }
    QTextStream in(&f);

    QByteArray alicePub, bobPriv, bobPub;
    struct Msg { QByteArray dh, nonce, ct, pt; quint32 pn = 0, n = 0; };
    QList<Msg> msgs;

    while (!in.atEnd()) {
        const QStringList t = in.readLine().split(' ', Qt::SkipEmptyParts);
        if (t.isEmpty()) continue;
        if (t[0] == "ALICE_PUB") alicePub = hx(t[1]);
        else if (t[0] == "BOB_PRIV") bobPriv = hx(t[1]);
        else if (t[0] == "BOB_PUB") bobPub = hx(t[1]);
        else if (t[0] == "MSG") {
            Msg m;
            m.dh = hx(t[1]); m.pn = t[2].toUInt(); m.n = t[3].toUInt();
            m.nonce = hx(t[4]); m.ct = hx(t[5]); m.pt = hx(t[6]);
            msgs.append(m);
        }
    }

    CryptoBox crypto;
    // Load Bob's identity from the vector so the bootstrap SK matches Python.
    // (Provide a test-only loader, or reuse loadIdentity from a temp key file.)
    crypto.loadIdentityFromRaw(bobPriv);  // <- small test helper to add

    const QString peer = QStringLiteral("alice");
    if (!crypto.initRatchetSessionAsResponder(peer, alicePub)) {
        std::printf("session init failed\n");
        return 1;
    }

    int ok = 0;
    for (const Msg &m : msgs) {
        const QString got =
            crypto.ratchetDecrypt(peer, m.dh, m.pn, m.n, m.nonce, m.ct);
        const QString want = QString::fromUtf8(m.pt);
        if (got != want) {
            std::printf("MISMATCH at n=%u: got \"%s\"\n",
                        m.n, got.toUtf8().constData());
            return 1;
        }
        std::printf("  n=%u  OK  \"%s\"\n", m.n, got.toUtf8().constData());
        ++ok;
    }
    std::printf("RATCHET INTEROP OK: %d/%lld messages decrypted by CryptoBox\n",
                ok, static_cast<long long>(msgs.size()));
    return 0;
}
