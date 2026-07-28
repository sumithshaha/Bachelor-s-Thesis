#include "x3dh.h"

#ifdef HAVE_SODIUM
#include <sodium.h>
#endif

#include <cstring>

namespace X3DH {

Bytes fromHex(const std::string &hex)
{
    Bytes out;
    if (hex.size() % 2) return out;
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return Bytes();
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

std::string toHex(const Bytes &b)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (unsigned char c : b) { s.push_back(d[c >> 4]); s.push_back(d[c & 15]); }
    return s;
}

#ifdef HAVE_SODIUM

namespace {

// X3DH domain separation. NOTE the info string differs from the ratchet's
// ("tamk-chat-e2ee-v1"): the two derivations must not share a label, or a secret
// from one context could stand in for the other.
const char kX3dhInfo[] = "tamk-chat-x3dh-v1";

// For Curve25519, X3DH prepends 32 bytes of 0xFF to the DH concatenation.
const unsigned char kF[32] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
};

// HKDF-SHA256 from HMAC, matching the helper in cryptobox.cpp.
//
// The Python reference passes a 32-byte ZERO salt where this passes nullptr.
// Those are equivalent: HMAC pads any key shorter than the block length with
// zeros, so both become the same 64 zero bytes. Verified against Python before
// this port was written rather than assumed.
void hkdf(const unsigned char *salt, size_t saltLen,
          const unsigned char *ikm, size_t ikmLen,
          const unsigned char *info, size_t infoLen,
          unsigned char *okm, size_t okmLen)
{
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    unsigned char zero[crypto_auth_hmacsha256_KEYBYTES] = {0};
    crypto_auth_hmacsha256_state st;

    if (salt == nullptr) { salt = zero; saltLen = sizeof zero; }
    crypto_auth_hmacsha256_init(&st, salt, saltLen);
    crypto_auth_hmacsha256_update(&st, ikm, ikmLen);
    crypto_auth_hmacsha256_final(&st, prk);

    unsigned char t[crypto_auth_hmacsha256_BYTES];
    size_t tLen = 0, done = 0;
    unsigned char counter = 1;
    while (done < okmLen) {
        crypto_auth_hmacsha256_init(&st, prk, sizeof prk);
        if (tLen) crypto_auth_hmacsha256_update(&st, t, tLen);
        crypto_auth_hmacsha256_update(&st, info, infoLen);
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t);
        tLen = sizeof t;
        const size_t take = (okmLen - done < tLen) ? (okmLen - done) : tLen;
        memcpy(okm + done, t, take);
        done += take;
        ++counter;
    }
    sodium_memzero(prk, sizeof prk);
    sodium_memzero(t, sizeof t);
}

// X25519(our private, their public). Empty on a degenerate (low-order) result,
// which must never be fed into the KDF.
Bytes dh(const Bytes &priv, const Bytes &pub)
{
    if (priv.size() != size_t(kX25519Bytes) || pub.size() != size_t(kX25519Bytes))
        return Bytes();
    Bytes out(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(out.data(), priv.data(), pub.data()) != 0) {
        sodium_memzero(out.data(), out.size());
        return Bytes();
    }
    return out;
}

// libsodium's 64-byte Ed25519 secret key (seed || public) for a 32-byte seed.
bool secretKeyFromSeed(const Bytes &seed, Bytes &sk64, Bytes &pk32)
{
    if (seed.size() != size_t(kSeedBytes)) return false;
    sk64.assign(crypto_sign_SECRETKEYBYTES, 0);
    pk32.assign(crypto_sign_PUBLICKEYBYTES, 0);
    return crypto_sign_seed_keypair(pk32.data(), sk64.data(), seed.data()) == 0;
}

Bytes kdf(const Bytes &dhConcat)
{
    Bytes ikm(kF, kF + sizeof kF);
    ikm.insert(ikm.end(), dhConcat.begin(), dhConcat.end());
    Bytes out(32);
    hkdf(nullptr, 0, ikm.data(), ikm.size(),
         reinterpret_cast<const unsigned char *>(kX3dhInfo), strlen(kX3dhInfo),
         out.data(), out.size());
    sodium_memzero(ikm.data(), ikm.size());
    return out;
}

}  // namespace

bool generateIdentity(Bytes &seedOut, Bytes &edPubOut)
{
    seedOut.assign(kSeedBytes, 0);
    randombytes_buf(seedOut.data(), seedOut.size());
    Bytes sk64;
    if (!secretKeyFromSeed(seedOut, sk64, edPubOut)) {
        sodium_memzero(seedOut.data(), seedOut.size());
        seedOut.clear();
        return false;
    }
    sodium_memzero(sk64.data(), sk64.size());
    return true;
}

Bytes identityPublic(const Bytes &seed)
{
    Bytes sk64, pk32;
    if (!secretKeyFromSeed(seed, sk64, pk32)) return Bytes();
    sodium_memzero(sk64.data(), sk64.size());
    return pk32;
}

Bytes identityToX25519Private(const Bytes &seed)
{
    Bytes sk64, pk32;
    if (!secretKeyFromSeed(seed, sk64, pk32)) return Bytes();
    Bytes out(crypto_scalarmult_SCALARBYTES);
    const int rc = crypto_sign_ed25519_sk_to_curve25519(out.data(), sk64.data());
    sodium_memzero(sk64.data(), sk64.size());
    if (rc != 0) { sodium_memzero(out.data(), out.size()); return Bytes(); }
    return out;
}

bool identityToX25519Public(const Bytes &edPub, Bytes &out)
{
    if (edPub.size() != size_t(kEdPubBytes)) return false;
    out.assign(crypto_scalarmult_BYTES, 0);
    // Returns -1 for a point not on the main subgroup. Reject rather than
    // proceed: such a bundle is malformed or hostile.
    if (crypto_sign_ed25519_pk_to_curve25519(out.data(), edPub.data()) != 0) {
        out.clear();
        return false;
    }
    return true;
}

Bytes sign(const Bytes &seed, const Bytes &message)
{
    Bytes sk64, pk32;
    if (!secretKeyFromSeed(seed, sk64, pk32)) return Bytes();
    Bytes sig(crypto_sign_BYTES);
    unsigned long long sigLen = 0;
    const int rc = crypto_sign_detached(sig.data(), &sigLen,
                                        message.data(), message.size(),
                                        sk64.data());
    sodium_memzero(sk64.data(), sk64.size());
    if (rc != 0 || sigLen != crypto_sign_BYTES) return Bytes();
    return sig;
}

bool verify(const Bytes &edPub, const Bytes &message, const Bytes &sig)
{
    if (edPub.size() != size_t(kEdPubBytes) || sig.size() != size_t(kSigBytes))
        return false;
    return crypto_sign_verify_detached(sig.data(), message.data(),
                                       message.size(), edPub.data()) == 0;
}

bool newSignedPrekey(const Bytes &ikSeed, Bytes &spkPriv, Bytes &spkPub,
                     Bytes &sigOut)
{
    spkPriv.assign(crypto_scalarmult_SCALARBYTES, 0);
    spkPub.assign(crypto_scalarmult_BYTES, 0);
    randombytes_buf(spkPriv.data(), spkPriv.size());
    crypto_scalarmult_base(spkPub.data(), spkPriv.data());
    sigOut = sign(ikSeed, spkPub);
    return !sigOut.empty();
}

bool newOneTimePrekey(Bytes &priv, Bytes &pub)
{
    priv.assign(crypto_scalarmult_SCALARBYTES, 0);
    pub.assign(crypto_scalarmult_BYTES, 0);
    randombytes_buf(priv.data(), priv.size());
    crypto_scalarmult_base(pub.data(), priv.data());
    return true;
}

bool initiatorWithEphemeral(const Bytes &aIkSeed, const Bundle &bundle,
                            const Bytes &ekPriv, InitiatorResult &out)
{
    // The signature check comes FIRST, before any DH. An unsigned or wrongly
    // signed bundle is the relay substituting keys, and computing with it would
    // establish a session with the attacker.
    if (!verify(bundle.ik, bundle.spk, bundle.spkSig)) return false;

    const Bytes aIkPub = identityPublic(aIkSeed);
    const Bytes aIkX   = identityToX25519Private(aIkSeed);
    Bytes bIkX;
    if (aIkPub.empty() || aIkX.empty()
        || !identityToX25519Public(bundle.ik, bIkX))
        return false;
    if (ekPriv.size() != size_t(kX25519Bytes)) return false;

    Bytes ekPub(crypto_scalarmult_BYTES);
    crypto_scalarmult_base(ekPub.data(), ekPriv.data());

    const Bytes dh1 = dh(aIkX,   bundle.spk);   // DH(IK_A, SPK_B)
    const Bytes dh2 = dh(ekPriv, bIkX);         // DH(EK_A, IK_B)
    const Bytes dh3 = dh(ekPriv, bundle.spk);   // DH(EK_A, SPK_B)
    if (dh1.empty() || dh2.empty() || dh3.empty()) return false;

    Bytes concat = dh1;
    concat.insert(concat.end(), dh2.begin(), dh2.end());
    concat.insert(concat.end(), dh3.begin(), dh3.end());
    if (!bundle.opk.empty()) {
        const Bytes dh4 = dh(ekPriv, bundle.opk);   // DH(EK_A, OPK_B)
        if (dh4.empty()) return false;
        concat.insert(concat.end(), dh4.begin(), dh4.end());
    }

    out.sk = kdf(concat);
    out.ik = aIkPub;
    out.ek = ekPub;
    out.ad = aIkPub;                                   // Encode(IK_A) ...
    out.ad.insert(out.ad.end(), bundle.ik.begin(), bundle.ik.end());  // ... || Encode(IK_B)
    out.opkId = bundle.opk.empty() ? -1 : bundle.opkId;

    sodium_memzero(concat.data(), concat.size());
    return !out.sk.empty();
}

bool initiator(const Bytes &aIkSeed, const Bundle &bundle, InitiatorResult &out)
{
    Bytes ekPriv(crypto_scalarmult_SCALARBYTES);
    randombytes_buf(ekPriv.data(), ekPriv.size());
    const bool ok = initiatorWithEphemeral(aIkSeed, bundle, ekPriv, out);
    sodium_memzero(ekPriv.data(), ekPriv.size());
    return ok;
}

bool responder(const Bytes &bIkSeed, const Bytes &spkPriv, const Bytes &opkPriv,
               const Bytes &ikA, const Bytes &ekA, Bytes &skOut)
{
    Bytes aIkX;
    if (!identityToX25519Public(ikA, aIkX)) return false;
    const Bytes bIkX = identityToX25519Private(bIkSeed);
    if (bIkX.empty()) return false;

    const Bytes dh1 = dh(spkPriv, aIkX);   // DH(SPK_B, IK_A)
    const Bytes dh2 = dh(bIkX,    ekA);    // DH(IK_B, EK_A)
    const Bytes dh3 = dh(spkPriv, ekA);    // DH(SPK_B, EK_A)
    if (dh1.empty() || dh2.empty() || dh3.empty()) return false;

    Bytes concat = dh1;
    concat.insert(concat.end(), dh2.begin(), dh2.end());
    concat.insert(concat.end(), dh3.begin(), dh3.end());
    if (!opkPriv.empty()) {
        const Bytes dh4 = dh(opkPriv, ekA);   // DH(OPK_B, EK_A)
        if (dh4.empty()) return false;
        concat.insert(concat.end(), dh4.begin(), dh4.end());
    }

    skOut = kdf(concat);
    sodium_memzero(concat.data(), concat.size());
    return !skOut.empty();
}

#else   // !HAVE_SODIUM

bool generateIdentity(Bytes &, Bytes &)                        { return false; }
Bytes identityPublic(const Bytes &)                            { return {}; }
Bytes identityToX25519Private(const Bytes &)                   { return {}; }
bool identityToX25519Public(const Bytes &, Bytes &)            { return false; }
Bytes sign(const Bytes &, const Bytes &)                       { return {}; }
bool verify(const Bytes &, const Bytes &, const Bytes &)       { return false; }
bool newSignedPrekey(const Bytes &, Bytes &, Bytes &, Bytes &) { return false; }
bool newOneTimePrekey(Bytes &, Bytes &)                        { return false; }
bool initiatorWithEphemeral(const Bytes &, const Bundle &, const Bytes &,
                            InitiatorResult &)                 { return false; }
bool initiator(const Bytes &, const Bundle &, InitiatorResult &) { return false; }
bool responder(const Bytes &, const Bytes &, const Bytes &, const Bytes &,
               const Bytes &, Bytes &)                         { return false; }

#endif  // HAVE_SODIUM

}  // namespace X3DH
