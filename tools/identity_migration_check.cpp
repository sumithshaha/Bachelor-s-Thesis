// ---------------------------------------------------------------------------
// identity_migration_check.cpp -- exercise the versioned identity end to end.
//
// The identity change is the foundation the rest of X3DH stands on, and its two
// failure modes are both silent: a v2 record misread as v1 would hand the
// ratchet 32 bytes of Ed25519 seed as if they were an X25519 private key, and a
// v1 record misread as v2 would derive a key from something that is not a seed.
// Neither throws. Both would surface much later as an undecryptable message.
// ---------------------------------------------------------------------------
#include "cryptobox.h"
#include "x3dh.h"

#include <QByteArray>
#include <QFile>
#include <QTemporaryDir>
#include <QTextStream>
#include <sodium.h>

static int gFail = 0;
static QTextStream out(stdout);

static void t(const QString &label, bool cond)
{
    out << (cond ? "   PASS  " : "   FAIL  ") << label << "\n";
    if (!cond) ++gFail;
}

int main()
{
    if (sodium_init() < 0) { out << "sodium init failed\n"; return 2; }
    QTemporaryDir dir;
    const QString plain = dir.filePath("id.bin");
    const QString enc   = dir.filePath("id.enc");

    out << "versioned identity migration\n\n";

    out << "generate a version 2 identity\n";
    CryptoBox a;
    a.generateIdentity();
    t("version is 2", a.identityVersion() == 2);
    t("X3DH is available", a.hasX3dhIdentity());
    t("Ed25519 public is 32 bytes",
      QByteArray::fromHex(a.edPublicKeyHex().toUtf8()).size() == 32);
    t("derived X25519 public is 32 bytes",
      QByteArray::fromHex(a.publicKeyHex().toUtf8()).size() == 32);
    t("Ed25519 and X25519 publics differ",
      a.edPublicKeyHex() != a.publicKeyHex());

    out << "\nthe derived key matches the reference module\n";
    {
        const QByteArray edPub = QByteArray::fromHex(a.edPublicKeyHex().toUtf8());
        X3DH::Bytes want;
        const bool okc = X3DH::identityToX25519Public(
            X3DH::Bytes(reinterpret_cast<const unsigned char *>(edPub.constData()),
                        reinterpret_cast<const unsigned char *>(edPub.constData())
                            + edPub.size()), want);
        t("conversion succeeds", okc);
        t("CryptoBox's X25519 public equals the map of its Ed25519 public",
          okc && QString::fromUtf8(
              QByteArray(reinterpret_cast<const char *>(want.data()),
                         int(want.size())).toHex()) == a.publicKeyHex());
    }

    out << "\nsigning\n";
    {
        const QByteArray msg("signed prekey bytes");
        const QByteArray sig = a.signWithIdentity(msg);
        t("signature is 64 bytes", sig.size() == 64);
        t("verifies against our own Ed25519 public",
          CryptoBox::verifyIdentitySignature(
              QByteArray::fromHex(a.edPublicKeyHex().toUtf8()), msg, sig));
        QByteArray bad = sig; bad[0] = bad[0] ^ 0x01;
        t("a corrupted signature is rejected",
          !CryptoBox::verifyIdentitySignature(
              QByteArray::fromHex(a.edPublicKeyHex().toUtf8()), msg, bad));
        CryptoBox other; other.generateIdentity();
        t("a signature by another identity is rejected",
          !CryptoBox::verifyIdentitySignature(
              QByteArray::fromHex(a.edPublicKeyHex().toUtf8()), msg,
              other.signWithIdentity(msg)));
    }

    out << "\nplain round trip\n";
    {
        t("save", a.saveIdentity(plain));
        CryptoBox b;
        t("load", b.loadIdentity(plain));
        t("version survives", b.identityVersion() == 2);
        t("Ed25519 public survives", b.edPublicKeyHex() == a.edPublicKeyHex());
        t("derived X25519 public survives", b.publicKeyHex() == a.publicKeyHex());
        t("can still sign after reload",
          CryptoBox::verifyIdentitySignature(
              QByteArray::fromHex(b.edPublicKeyHex().toUtf8()),
              QByteArray("x"), b.signWithIdentity(QByteArray("x"))));
    }

    out << "\nencrypted round trip\n";
    {
        t("save encrypted", a.saveIdentityEncrypted(enc, "correct horse"));
        CryptoBox c;
        t("wrong password is refused",
          !c.loadIdentityEncrypted(enc, "wrong horse"));
        t("nothing is loaded after a refusal", c.identityVersion() == 0);
        CryptoBox d;
        t("right password loads", d.loadIdentityEncrypted(enc, "correct horse"));
        t("version survives", d.identityVersion() == 2);
        t("Ed25519 public survives", d.edPublicKeyHex() == a.edPublicKeyHex());
        t("derived X25519 public survives", d.publicKeyHex() == a.publicKeyHex());
    }

    out << "\nlegacy version 1 record still loads\n";
    {
        // A bare 32-byte file is exactly what an older build wrote.
        const QString legacy = dir.filePath("legacy.bin");
        QByteArray raw(crypto_scalarmult_SCALARBYTES, Qt::Uninitialized);
        randombytes_buf(raw.data(), size_t(raw.size()));
        QFile f(legacy);
        f.open(QIODevice::WriteOnly); f.write(raw); f.close();

        CryptoBox e;
        t("loads", e.loadIdentity(legacy));
        t("reported as version 1", e.identityVersion() == 1);
        t("X3DH correctly unavailable", !e.hasX3dhIdentity());
        t("no Ed25519 public is invented", e.edPublicKeyHex().isEmpty());
        t("cannot sign", e.signWithIdentity(QByteArray("x")).isEmpty());
        // The legacy X25519 public must be the base point times the raw key --
        // i.e. read as a private key, NOT as a seed.
        QByteArray want(crypto_scalarmult_BYTES, Qt::Uninitialized);
        crypto_scalarmult_base(
            reinterpret_cast<unsigned char *>(want.data()),
            reinterpret_cast<const unsigned char *>(raw.constData()));
        t("v1 key is interpreted as X25519, not as a seed",
          e.publicKeyHex() == QString::fromUtf8(want.toHex()));
    }

    out << "\n" << (gFail == 0 ? "ALL IDENTITY CHECKS PASSED"
                               : QString("%1 CHECK(S) FAILED").arg(gFail)) << "\n";
    return gFail == 0 ? 0 : 1;
}
