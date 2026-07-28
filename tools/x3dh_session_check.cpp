// x3dh_session_check.cpp -- establish a real session through X3DH and exchange
// messages, then check the property the whole exercise was for.
#include "cryptobox.h"
#include "x3dh.h"
#include <QByteArray>
#include <QTextStream>
#include <sodium.h>

static int F = 0;
static QTextStream o(stdout);
static void t(const QString &l, bool c)
{ o << (c ? "   PASS  " : "   FAIL  ") << l << "\n"; if (!c) ++F; }

int main()
{
    if (sodium_init() < 0) return 2;
    o << "X3DH session establishment\n\n";

    // Bob is offline: he has published a bundle and nothing more.
    CryptoBox bob;   bob.generateIdentity();   bob.generatePrekeys(4);
    CryptoBox alice; alice.generateIdentity(); alice.generatePrekeys(4);

    const QByteArray bIk  = QByteArray::fromHex(bob.edPublicKeyHex().toUtf8());
    const QByteArray bSpk = QByteArray::fromHex(bob.signedPrekeyPublicHex().toUtf8());
    const QByteArray bSig = QByteArray::fromHex(bob.signedPrekeySignatureHex().toUtf8());
    const auto pool = bob.oneTimePrekeyPublicsHex();
    const quint32 opkId = pool.firstKey();
    const QByteArray bOpk = QByteArray::fromHex(pool.value(opkId).toUtf8());

    o << "initiator opens a session from the bundle\n";
    t("bundle verifies", CryptoBox::verifyBundle(bIk, bSpk, bSig));
    QByteArray ikA, ekA; qint32 usedOpk = -1;
    t("beginX3dhSession succeeds",
      alice.beginX3dhSession("bob", bIk, bSpk, bSig, bOpk, qint32(opkId),
                             ikA, ekA, usedOpk));
    t("header carries our Ed25519 identity",
      QString::fromUtf8(ikA.toHex()) == alice.edPublicKeyHex());
    t("header carries a 32-byte ephemeral", ekA.size() == 32);
    t("header names the consumed one-time prekey", usedOpk == qint32(opkId));
    t("a session now exists", alice.hasSessionFor("bob"));

    o << "\na tampered bundle is refused\n";
    {
        CryptoBox c; c.generateIdentity(); c.generatePrekeys(1);
        QByteArray badSig = bSig; badSig[0] = badSig[0] ^ 0x01;
        QByteArray i2, e2; qint32 o2 = -1;
        t("bad signature stops the agreement",
          !c.beginX3dhSession("bob", bIk, bSpk, badSig, bOpk, qint32(opkId),
                              i2, e2, o2));
        t("no session was created", !c.hasSessionFor("bob"));
    }

    o << "\nresponder derives the same secret from the header\n";
    t("acceptX3dhSession succeeds",
      bob.acceptX3dhSession("alice", ikA, ekA, usedOpk));
    t("bob has a session", bob.hasSessionFor("alice"));
    t("the one-time prekey was consumed", bob.oneTimePrekeyCount() == 3);
    t("a replayed header is refused",
      !bob.acceptX3dhSession("alice", ikA, ekA, usedOpk));

    o << "\nthe two sides can actually talk\n";
    {
        QString cipher, dh, nonce, ct; quint32 pn = 0, n = 0;
        t("alice encrypts",
          alice.encryptFor("bob", "hello over X3DH", cipher, dh, pn, n, nonce, ct));
        const QString got = bob.decryptFrom("alice", cipher, dh, pn, n, nonce, ct);
        t("bob decrypts to the same plaintext", got == "hello over X3DH");

        // And back the other way, which is what fires the first DH ratchet step.
        QString c2, d2, n2, t2; quint32 pn2 = 0, nn2 = 0;
        t("bob replies", bob.encryptFor("alice", "and back", c2, d2, pn2, nn2, n2, t2));
        t("alice decrypts the reply",
          alice.decryptFrom("bob", c2, d2, pn2, nn2, n2, t2) == "and back");
    }


    o << "\n" << (F == 0 ? "ALL SESSION CHECKS PASSED"
                         : QString("%1 CHECK(S) FAILED").arg(F)) << "\n";
    return F ? 1 : 0;
}
