// =============================================================================
// Ratchet interop oracle (receive side) -- TEST HARNESS, not the product code.
//
// Proves that an independent C++/libsodium implementation decrypts a complete
// ratcheting session produced by the Python reference (tests/make_ratchet_
// vectors.py). It implements just the receiver half of the Double Ratchet --
// Route A bootstrap, the first DH ratchet step, the KDF_CK symmetric chain, and
// XChaCha20-Poly1305 with the header bound as associated data -- which is what a
// one-directional vector exercises.
//
// This mirrors the cryptography in client/src/cryptobox.cpp using the SAME
// libsodium primitives (crypto_scalarmult, HMAC-SHA256 HKDF as in the existing
// interop.cpp, crypto_aead_xchacha20poly1305_ietf). When you implement the
// product ratchet in CryptoBox, tests/interop_ratchet.cpp drives THAT code with
// the same vector; this file is the reference oracle that the vector is known to
// satisfy.
//
// Build (host libsodium):
//   g++ -std=c++17 tests/_ref_interop_recv.cpp -lsodium -o ref_recv
// Run:
//   ./ref_recv tests/ratchet_vector.txt
// =============================================================================
#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

static const char *kInfoSk = "tamk-chat-e2ee-v1";
static const char *kInfoRoot = "tamk-chat-ratchet-root-v1";
static const char *kCipherTag = "xc20p1305-r1";

static Bytes fromHex(const std::string &h) {
    Bytes out(h.size() / 2);
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = (unsigned char)std::stoi(h.substr(i * 2, 2), nullptr, 16);
    return out;
}

// HMAC-SHA256 one-shot.
static Bytes hmac(const Bytes &key, const Bytes &msg) {
    Bytes out(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    crypto_auth_hmacsha256_update(&st, msg.data(), msg.size());
    crypto_auth_hmacsha256_final(&st, out.data());
    return out;
}

// HKDF-SHA256 (RFC 5869). length is 32 or 64; salt may be empty (-> zero key).
static Bytes hkdf(const Bytes &salt, const Bytes &ikm, const std::string &info,
                  size_t length) {
    Bytes realSalt = salt.empty() ? Bytes(crypto_auth_hmacsha256_KEYBYTES, 0) : salt;
    Bytes prk = hmac(realSalt, ikm);
    Bytes okm;
    Bytes t;
    unsigned char counter = 1;
    while (okm.size() < length) {
        Bytes input = t;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        t = hmac(prk, input);
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(length);
    return okm;
}

static Bytes dh(const Bytes &priv, const Bytes &pub) {
    Bytes out(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(out.data(), priv.data(), pub.data()) != 0) {
        printf("scalarmult failed\n");
        exit(1);
    }
    return out;
}

// KDF_RK: HKDF(salt=RK, ikm=DH) -> 64 bytes -> (RK', CK').
static void kdf_rk(const Bytes &rk, const Bytes &dhOut, Bytes &rkOut, Bytes &ckOut) {
    Bytes okm = hkdf(rk, dhOut, kInfoRoot, 64);
    rkOut.assign(okm.begin(), okm.begin() + 32);
    ckOut.assign(okm.begin() + 32, okm.end());
}

// KDF_CK -> (CK_next, message_key).
static void kdf_ck(const Bytes &ck, Bytes &ckNext, Bytes &mk) {
    ckNext = hmac(ck, Bytes{0x02});
    mk = hmac(ck, Bytes{0x01});
}

// Associated data = cipher tag || dh(32) || pn(4 BE) || n(4 BE).
static Bytes ad(const Bytes &dhPub, unsigned pn, unsigned n) {
    Bytes a(kCipherTag, kCipherTag + strlen(kCipherTag));
    a.insert(a.end(), dhPub.begin(), dhPub.end());
    for (int s = 24; s >= 0; s -= 8) a.push_back((pn >> s) & 0xff);
    for (int s = 24; s >= 0; s -= 8) a.push_back((n >> s) & 0xff);
    return a;
}

struct Msg {
    Bytes dh, nonce, ct, expectPt;
    unsigned pn = 0, n = 0;
};

int main(int argc, char **argv) {
    if (sodium_init() < 0) { printf("sodium init failed\n"); return 1; }
    if (argc != 2) { printf("usage: %s <ratchet_vector.txt>\n", argv[0]); return 1; }

    std::ifstream in(argv[1]);
    if (!in) { printf("cannot open %s\n", argv[1]); return 1; }

    Bytes alicePub, bobPriv, bobPub;
    std::vector<Msg> msgs;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string tag;
        ss >> tag;
        if (tag == "ALICE_PUB") { std::string h; ss >> h; alicePub = fromHex(h); }
        else if (tag == "BOB_PRIV") { std::string h; ss >> h; bobPriv = fromHex(h); }
        else if (tag == "BOB_PUB") { std::string h; ss >> h; bobPub = fromHex(h); }
        else if (tag == "MSG") {
            Msg m;
            std::string dhH, nonceH, ctH, ptH;
            ss >> dhH >> m.pn >> m.n >> nonceH >> ctH >> ptH;
            m.dh = fromHex(dhH); m.nonce = fromHex(nonceH);
            m.ct = fromHex(ctH); m.expectPt = fromHex(ptH);
            msgs.push_back(m);
        }
    }

    // --- Route A: SK = HKDF(DH(bob_priv, alice_pub)), then init Bob ---
    Bytes sk = hkdf(Bytes{}, dh(bobPriv, alicePub), kInfoSk, 32);
    Bytes RK = sk;                 // Bob: RK = SK
    Bytes DHs_priv = bobPriv;      // Bob's bootstrap ratchet keypair = identity
    Bytes DHr_pub;                 // unknown until first message
    Bytes CKr;                     // no receiving chain yet
    bool haveDHr = false;

    int ok = 0;
    for (const Msg &m : msgs) {
        // New ratchet key from Alice -> perform the receive-side DH ratchet.
        if (!haveDHr || m.dh != DHr_pub) {
            DHr_pub = m.dh;
            haveDHr = true;
            kdf_rk(RK, dh(DHs_priv, DHr_pub), RK, CKr);  // receiving half
            // (A full ratchet would also generate a new DHs and a sending chain
            //  here; the receiver does not need them to decrypt.)
        }
        Bytes ckNext, mk;
        kdf_ck(CKr, ckNext, mk);
        CKr = ckNext;

        Bytes a = ad(m.dh, m.pn, m.n);
        std::vector<unsigned char> pt(m.ct.size());
        unsigned long long ptLen = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                pt.data(), &ptLen, nullptr,
                m.ct.data(), m.ct.size(),
                a.data(), a.size(),
                m.nonce.data(), mk.data()) != 0) {
            printf("DECRYPT FAILED at message n=%u (authentication error)\n", m.n);
            return 1;
        }
        pt.resize(ptLen);
        std::string got((char *)pt.data(), pt.size());
        std::string want((char *)m.expectPt.data(), m.expectPt.size());
        if (got != want) {
            printf("MISMATCH at n=%u: got \"%s\"\n", m.n, got.c_str());
            return 1;
        }
        printf("  n=%u  OK  \"%s\"\n", m.n, got.c_str());
        ++ok;
    }
    printf("RATCHET INTEROP OK: %d/%zu messages decrypted by C++ "
           "from the Python session\n", ok, msgs.size());
    return 0;
}
