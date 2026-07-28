// spk_rotation_check.cpp -- signed prekey rotation, retention and retirement.
#include "cryptobox.h"
#include <QByteArray>
#include <QDateTime>
#include <QTextStream>
#include <sodium.h>
static int F=0; static QTextStream o(stdout);
static void t(const QString&l,bool c){o<<(c?"   PASS  ":"   FAIL  ")<<l<<"\n"; if(!c)++F;}

static bool openAgainst(CryptoBox &alice, CryptoBox &bob, const QString &who,
                        const QByteArray &spk, const QByteArray &sig,
                        QByteArray &ikA, QByteArray &ekA, qint32 &opk,
                        bool useOpk)
{
    const QByteArray bIk = QByteArray::fromHex(bob.edPublicKeyHex().toUtf8());
    QByteArray o1; qint32 id = -1;
    if (useOpk) {
        const auto pool = bob.oneTimePrekeyPublicsHex();
        if (!pool.isEmpty()) { id = qint32(pool.firstKey());
                               o1 = QByteArray::fromHex(pool.value(quint32(id)).toUtf8()); }
    }
    return alice.beginX3dhSession(who, bIk, spk, sig, o1, id, ikA, ekA, opk);
}

int main()
{
    if (sodium_init() < 0) return 2;
    o << "signed prekey rotation\n\n";

    CryptoBox bob; bob.generateIdentity(); bob.generatePrekeys(6);
    // AFTER generation: the prekey's creation time is stamped inside
    // generatePrekeys(), so a clock read taken before it would make every age
    // negative and nothing would ever look due.
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const QByteArray spk0 = QByteArray::fromHex(bob.signedPrekeyPublicHex().toUtf8());
    const QByteArray sig0 = QByteArray::fromHex(bob.signedPrekeySignatureHex().toUtf8());

    o << "policy\n";
    t("a fresh prekey is not due", !bob.rotateSignedPrekeyIfDue(60000, now));
    t("age is tracked", bob.signedPrekeyAgeMs(now + 5000) >= 5000);
    t("no previous key yet", !bob.hasPreviousSignedPrekey());

    // Alice fetches the bundle while Bob is offline, and does not send yet.
    CryptoBox alice; alice.generateIdentity(); alice.generatePrekeys(2);
    QByteArray ikA, ekA; qint32 usedOpk = -1;
    t("alice opens a session from the CURRENT bundle",
      openAgainst(alice, bob, "bob", spk0, sig0, ikA, ekA, usedOpk, true));

    o << "\nrotation, with the old key retained\n";
    const int poolBefore = bob.oneTimePrekeyCount();
    t("rotation fires once due", bob.rotateSignedPrekeyIfDue(0, now + 1));
    const QByteArray spk1 = QByteArray::fromHex(bob.signedPrekeyPublicHex().toUtf8());
    t("the signed prekey actually changed", spk1 != spk0);
    t("the previous key is retained", bob.hasPreviousSignedPrekey());
    t("the one-time pool is NOT discarded by a rotation",
      bob.oneTimePrekeyCount() == poolBefore);

    o << "\nthe in-flight opener still works\n";
    t("opener naming the OLD prekey is accepted",
      bob.acceptX3dhSession("alice", ikA, ekA, usedOpk, spk0));
    {
        QString c,d,n,ct; quint32 pn=0,nn=0;
        t("alice encrypts", alice.encryptFor("bob","after rotation",c,d,pn,nn,n,ct));
        t("bob decrypts with the retained key",
          bob.decryptFrom("alice",c,d,pn,nn,n,ct) == "after rotation");
    }

    o << "\na new session uses the new prekey\n";
    {
        CryptoBox carol; carol.generateIdentity(); carol.generatePrekeys(2);
        const QByteArray sig1 = QByteArray::fromHex(bob.signedPrekeySignatureHex().toUtf8());
        QByteArray i2,e2; qint32 o2=-1;
        t("carol opens against the NEW bundle",
          openAgainst(carol, bob, "bob", spk1, sig1, i2, e2, o2, true));
        t("bob accepts naming the new prekey",
          bob.acceptX3dhSession("carol", i2, e2, o2, spk1));
        QString c,d,n,ct; quint32 pn=0,nn=0;
        carol.encryptFor("bob","hello",c,d,pn,nn,n,ct);
        t("and they can talk", bob.decryptFrom("carol",c,d,pn,nn,n,ct) == "hello");
    }

    o << "\nretirement destroys the old key\n";
    t("not dropped inside the grace period",
      !bob.dropExpiredPreviousPrekey(3600000, now + 2));
    t("dropped once the grace period passes",
      bob.dropExpiredPreviousPrekey(0, now + 3));
    t("it is really gone", !bob.hasPreviousSignedPrekey());
    {
        CryptoBox dave; dave.generateIdentity(); dave.generatePrekeys(1);
        QByteArray i3,e3; qint32 o3=-1;
        openAgainst(dave, bob, "bob", spk0, sig0, i3, e3, o3, false);
        const int poolNow = bob.oneTimePrekeyCount();
        t("an opener naming the destroyed key is REFUSED",
          !bob.acceptX3dhSession("dave", i3, e3, o3, spk0));
        t("and the one-time pool was not leaked by the refusal",
          bob.oneTimePrekeyCount() == poolNow);
    }

    o << "\nrotation state survives a restart\n";
    {
        CryptoBox e; e.generateIdentity(); e.generatePrekeys(3);
        e.rotateSignedPrekeyIfDue(0, QDateTime::currentMSecsSinceEpoch() + 1);
        const QByteArray blob = e.serialisePrekeys();
        CryptoBox g; g.generateIdentity();
        t("restores", g.restorePrekeys(blob));
        t("the retained previous key survives", g.hasPreviousSignedPrekey());
        t("the rotation clock survives",
          g.signedPrekeyAgeMs(QDateTime::currentMSecsSinceEpoch()) >= 0);
    }

    o << "\n" << (F==0?"ALL ROTATION CHECKS PASSED":QString("%1 FAILED").arg(F)) << "\n";
    return F?1:0;
}
