#include "cryptobox.h"
#include "x3dh.h"
#include <QTextStream>
#include <sodium.h>
static int F=0; static QTextStream o(stdout);
static void t(const QString&l,bool c){o<<(c?"   PASS  ":"   FAIL  ")<<l<<"\n"; if(!c)++F;}
int main(){
  sodium_init();
  o<<"published key -> agreement key\n\n";
  CryptoBox a; a.generateIdentity();
  const QByteArray ed = QByteArray::fromHex(a.edPublicKeyHex().toUtf8());
  QByteArray out;
  t("ed25519 converts", CryptoBox::agreementKeyFor(ed,"ed25519",out));
  t("result equals the identity's own X25519 public",
    QString::fromUtf8(out.toHex())==a.publicKeyHex());
  QByteArray x(32,0); randombytes_buf(x.data(),32);
  t("x25519 passes through unchanged",
    CryptoBox::agreementKeyFor(x,"x25519",out) && out==x);
  t("absent type is treated as legacy x25519",
    CryptoBox::agreementKeyFor(x,"",out) && out==x);
  t("an unknown type is refused, not guessed",
    !CryptoBox::agreementKeyFor(x,"p256",out));
  t("a short key is refused", !CryptoBox::agreementKeyFor(ed.left(31),"ed25519",out));
  t("ed25519 read as x25519 gives a DIFFERENT key (why the tag is needed)",
    CryptoBox::agreementKeyFor(ed,"x25519",out) && QString::fromUtf8(out.toHex())!=a.publicKeyHex());
  o<<"\n"<<(F==0?"ALL CHECKS PASSED":QString("%1 FAILED").arg(F))<<"\n"; return F?1:0;
}
