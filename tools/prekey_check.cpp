// prekey_check.cpp -- exercise signed-prekey generation, bundle verification,
// one-time prekey consumption and persistence, against the real CryptoBox.
#include "cryptobox.h"
#include "x3dh.h"
#include <QByteArray>
#include <QTextStream>
#include <sodium.h>

static int gFail = 0;
static QTextStream out(stdout);
static void t(const QString &l, bool c)
{ out << (c ? "   PASS  " : "   FAIL  ") << l << "\n"; if (!c) ++gFail; }

int main()
{
    if (sodium_init() < 0) return 2;
    out << "X3DH prekeys\n\n";

    CryptoBox v1;                       // legacy identity: must refuse
    out << "a version 1 identity cannot publish prekeys\n";
    t("generatePrekeys refuses without a signing key", !v1.generatePrekeys(4));
    t("hasPrekeys stays false", !v1.hasPrekeys());

    CryptoBox a;
    a.generateIdentity();
    out << "\ngeneration\n";
    t("generatePrekeys succeeds", a.generatePrekeys(8));
    t("hasPrekeys", a.hasPrekeys());
    t("pool size is 8", a.oneTimePrekeyCount() == 8);
    t("signed prekey public is 32 bytes",
      QByteArray::fromHex(a.signedPrekeyPublicHex().toUtf8()).size() == 32);
    t("signature is 64 bytes",
      QByteArray::fromHex(a.signedPrekeySignatureHex().toUtf8()).size() == 64);
    t("publics map has 8 entries", a.oneTimePrekeyPublicsHex().size() == 8);

    const QByteArray ik  = QByteArray::fromHex(a.edPublicKeyHex().toUtf8());
    const QByteArray spk = QByteArray::fromHex(a.signedPrekeyPublicHex().toUtf8());
    const QByteArray sig = QByteArray::fromHex(a.signedPrekeySignatureHex().toUtf8());

    out << "\nbundle verification\n";
    t("our own bundle verifies", CryptoBox::verifyBundle(ik, spk, sig));
    QByteArray badSig = sig; badSig[0] = badSig[0] ^ 0x01;
    t("a tampered signature is rejected",
      !CryptoBox::verifyBundle(ik, spk, badSig));
    QByteArray badSpk = spk; badSpk[0] = badSpk[0] ^ 0x01;
    t("a substituted signed prekey is rejected",
      !CryptoBox::verifyBundle(ik, badSpk, sig));
    CryptoBox relay; relay.generateIdentity(); relay.generatePrekeys(1);
    t("a bundle signed by another identity is rejected",
      !CryptoBox::verifyBundle(
          ik, QByteArray::fromHex(relay.signedPrekeyPublicHex().toUtf8()),
          QByteArray::fromHex(relay.signedPrekeySignatureHex().toUtf8())));
    t("a short identity key is rejected",
      !CryptoBox::verifyBundle(ik.left(31), spk, sig));

    out << "\none-time prekeys are single use\n";
    {
        const auto pubs = a.oneTimePrekeyPublicsHex();
        const quint32 id = pubs.firstKey();
        const QByteArray priv = a.takeOneTimePrekey(id);
        t("first take returns a 32-byte private", priv.size() == 32);
        t("pool shrank to 7", a.oneTimePrekeyCount() == 7);
        t("a replayed id returns empty", a.takeOneTimePrekey(id).isEmpty());
        t("an unknown id returns empty", a.takeOneTimePrekey(9999).isEmpty());
        // The private taken must be the one whose public was advertised.
        QByteArray derived(crypto_scalarmult_BYTES, Qt::Uninitialized);
        crypto_scalarmult_base(
            reinterpret_cast<unsigned char *>(derived.data()),
            reinterpret_cast<const unsigned char *>(priv.constData()));
        t("the private matches the advertised public",
          QString::fromUtf8(derived.toHex()) == pubs.value(id));
    }

    out << "\npersistence\n";
    {
        const QByteArray blob = a.serialisePrekeys();
        t("serialises to a non-empty blob", !blob.isEmpty());
        CryptoBox b; b.generateIdentity();
        t("restores", b.restorePrekeys(blob));
        t("signed prekey public survives",
          b.signedPrekeyPublicHex() == a.signedPrekeyPublicHex());
        t("signature survives",
          b.signedPrekeySignatureHex() == a.signedPrekeySignatureHex());
        t("pool size survives", b.oneTimePrekeyCount() == a.oneTimePrekeyCount());
        t("a consumed id is still gone after a restart",
          b.takeOneTimePrekey(a.oneTimePrekeyPublicsHex().firstKey()).size() == 32);
        QByteArray truncated = blob.left(blob.size() - 5);
        CryptoBox c;
        t("a truncated blob is rejected", !c.restorePrekeys(truncated));
        QByteArray corrupt = blob; corrupt[0] = 'X';
        CryptoBox d;
        t("a blob with a bad magic is rejected", !d.restorePrekeys(corrupt));
    }

    out << "\nids are never reused across regeneration\n";
    {
        CryptoBox e; e.generateIdentity();
        e.generatePrekeys(3);
        const auto first = e.oneTimePrekeyPublicsHex().keys();
        e.generatePrekeys(3);
        const auto second = e.oneTimePrekeyPublicsHex().keys();
        bool overlap = false;
        for (quint32 k : second) if (first.contains(k)) overlap = true;
        t("a second pool shares no ids with the first", !overlap);
    }

    out << "\n" << (gFail == 0 ? "ALL PREKEY CHECKS PASSED"
                               : QString("%1 CHECK(S) FAILED").arg(gFail)) << "\n";
    return gFail == 0 ? 0 : 1;
}
