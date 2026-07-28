// =============================================================================
// Live-harness endpoint (C++) -- TEST ORACLE, not the product code.
//
// A self-contained, full (send + receive) Double Ratchet built on libsodium,
// speaking the same line protocol as tests/ratchet_cli.py. It lets the driver
// run a real bidirectional conversation between a Python endpoint and this C++
// endpoint, exercising multi-step DH ratchets and healing ACROSS LANGUAGES.
//
// It implements the same schedule as server/ratchet.py with identical KDFs,
// domain strings, associated-data layout and AEAD, so the two interoperate
// byte-for-byte. It is the cross-language reference oracle; the product ratchet
// lives in client/src/cryptobox.cpp and is what you ship. (The harness can also
// drive the product via a thin CryptoBox CLI -- see RATCHET_TESTING.md.)
//
// The driver delivers messages in order, so no skipped-key store is needed here.
//
// Build:  g++ -std=c++17 tests/ratchet_cli.cpp -lsodium -o ratchet_cli_cpp
// Launch: ./ratchet_cli_cpp <role> <own_priv_hex> <own_pub_hex> <peer_pub_hex>
// =============================================================================
#include <sodium.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

static const char *kInfoSk = "tamk-chat-e2ee-v1";
static const char *kInfoRoot = "tamk-chat-ratchet-root-v1";
static const char *kCipherAes = "a256gcm-r1";
static const char *kCipherXchacha = "xc20p1305-r1";

static Bytes fromHex(const std::string &h) {
    Bytes o(h.size() / 2);
    for (size_t i = 0; i < o.size(); ++i)
        o[i] = (unsigned char)std::stoi(h.substr(i * 2, 2), nullptr, 16);
    return o;
}
static std::string toHex(const unsigned char *p, size_t n) {
    static const char *d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
static std::string toHex(const Bytes &b) { return toHex(b.data(), b.size()); }

static Bytes hmac(const Bytes &key, const Bytes &msg) {
    Bytes out(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    crypto_auth_hmacsha256_update(&st, msg.data(), msg.size());
    crypto_auth_hmacsha256_final(&st, out.data());
    return out;
}
static Bytes hkdf(const Bytes &salt, const Bytes &ikm, const std::string &info,
                  size_t length) {
    Bytes rsalt = salt.empty() ? Bytes(crypto_auth_hmacsha256_KEYBYTES, 0) : salt;
    Bytes prk = hmac(rsalt, ikm), okm, t;
    unsigned char counter = 1;
    while (okm.size() < length) {
        Bytes in = t;
        in.insert(in.end(), info.begin(), info.end());
        in.push_back(counter++);
        t = hmac(prk, in);
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(length);
    return okm;
}
static Bytes dh(const Bytes &priv, const Bytes &pub) {
    Bytes o(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(o.data(), priv.data(), pub.data()) != 0) { std::exit(1); }
    return o;
}
static void kdf_rk(const Bytes &rk, const Bytes &dhOut, Bytes &rkOut, Bytes &ckOut) {
    Bytes okm = hkdf(rk, dhOut, kInfoRoot, 64);
    rkOut.assign(okm.begin(), okm.begin() + 32);
    ckOut.assign(okm.begin() + 32, okm.end());
}
static void kdf_ck(const Bytes &ck, Bytes &ckNext, Bytes &mk) {
    ckNext = hmac(ck, Bytes{0x02});
    mk = hmac(ck, Bytes{0x01});
}
static Bytes ad(const std::string &cipher, const Bytes &dhPub, uint32_t pn, uint32_t n) {
    Bytes a(cipher.begin(), cipher.end());
    a.insert(a.end(), dhPub.begin(), dhPub.end());
    for (int s = 24; s >= 0; s -= 8) a.push_back((pn >> s) & 0xff);
    for (int s = 24; s >= 0; s -= 8) a.push_back((n >> s) & 0xff);
    return a;
}

// Nonce length by cipher.
static size_t nonceLen(const std::string &cipher) {
    return cipher == kCipherAes ? crypto_aead_aes256gcm_NPUBBYTES
                                : crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
}

// AEAD dispatch. Returns false on auth failure (decrypt) / never fails (encrypt).
static Bytes aeadEncrypt(const std::string &cipher, const Bytes &key,
                         const Bytes &nonce, const Bytes &pt, const Bytes &a) {
    if (cipher == kCipherAes) {
        std::vector<unsigned char> ct(pt.size() + crypto_aead_aes256gcm_ABYTES);
        unsigned long long clen = 0;
        crypto_aead_aes256gcm_encrypt(ct.data(), &clen, pt.data(), pt.size(),
                                      a.data(), a.size(), nullptr,
                                      nonce.data(), key.data());
        ct.resize(clen);
        return ct;
    }
    std::vector<unsigned char> ct(pt.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &clen, pt.data(), pt.size(),
                                               a.data(), a.size(), nullptr,
                                               nonce.data(), key.data());
    ct.resize(clen);
    return ct;
}
static bool aeadDecrypt(const std::string &cipher, const Bytes &key,
                        const Bytes &nonce, const Bytes &ct, const Bytes &a,
                        Bytes &pt) {
    pt.resize(ct.size());
    unsigned long long plen = 0;
    int rc;
    if (cipher == kCipherAes)
        rc = crypto_aead_aes256gcm_decrypt(pt.data(), &plen, nullptr, ct.data(),
                                           ct.size(), a.data(), a.size(),
                                           nonce.data(), key.data());
    else
        rc = crypto_aead_xchacha20poly1305_ietf_decrypt(pt.data(), &plen, nullptr,
                                                        ct.data(), ct.size(),
                                                        a.data(), a.size(),
                                                        nonce.data(), key.data());
    if (rc != 0) return false;
    pt.resize(plen);
    return true;
}
static void genKeypair(Bytes &priv, Bytes &pub) {
    priv.resize(32);
    pub.resize(32);
    randombytes_buf(priv.data(), 32);
    crypto_scalarmult_base(pub.data(), priv.data());  // X25519 base point
}

struct State {
    Bytes DHs_priv, DHs_pub, DHr_pub, RK, CKs, CKr;
    uint32_t Ns = 0, Nr = 0, PN = 0;
    bool haveDHr = false;
};

static void dhRatchet(State &s, const Bytes &dhPub) {
    s.PN = s.Ns;
    s.Ns = 0;
    s.Nr = 0;
    s.DHr_pub = dhPub;
    s.haveDHr = true;
    kdf_rk(s.RK, dh(s.DHs_priv, s.DHr_pub), s.RK, s.CKr);
    genKeypair(s.DHs_priv, s.DHs_pub);
    kdf_rk(s.RK, dh(s.DHs_priv, s.DHr_pub), s.RK, s.CKs);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;
    if (argc < 5 || argc > 6) {
        std::fprintf(stderr, "usage: %s <role> <priv> <pub> <peer_pub> [auto|aes|xchacha]\n", argv[0]);
        return 1;
    }
    std::string role = argv[1];
    Bytes ownPriv = fromHex(argv[2]), ownPub = fromHex(argv[3]),
          peerPub = fromHex(argv[4]);
    // Cipher selection policy: libsodium's hardware probe by default; the C++
    // desktop's probe returns 0 -> it would select XChaCha20. argv[5] overrides
    // (auto|aes|xchacha) so the harness can drive each path deterministically.
    std::string force = (argc >= 6) ? argv[5] : "auto";
    auto pickCipher = [&]() -> std::string {
        if (force == "aes") return kCipherAes;
        if (force == "xchacha") return kCipherXchacha;
        return crypto_aead_aes256gcm_is_available() ? kCipherAes : kCipherXchacha;
    };

    State s;
    Bytes sk = hkdf(Bytes{}, dh(ownPriv, peerPub), kInfoSk, 32);  // == derive_shared_key
    if (role == "alice") {
        genKeypair(s.DHs_priv, s.DHs_pub);
        s.DHr_pub = peerPub;
        s.haveDHr = true;
        kdf_rk(sk, dh(s.DHs_priv, s.DHr_pub), s.RK, s.CKs);
    } else {  // bob
        s.DHs_priv = ownPriv;
        s.DHs_pub = ownPub;
        s.RK = sk;
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream ss(line);
        std::string cmd;
        ss >> cmd;
        if (cmd == "SEND") {
            std::string ptH;
            ss >> ptH;
            Bytes pt = fromHex(ptH);
            std::string cipher = pickCipher();
            Bytes ckNext, mk;
            kdf_ck(s.CKs, ckNext, mk);
            s.CKs = ckNext;
            uint32_t pn = s.PN, n = s.Ns;
            Bytes nonce(nonceLen(cipher));
            randombytes_buf(nonce.data(), nonce.size());
            Bytes a = ad(cipher, s.DHs_pub, pn, n);
            Bytes ct = aeadEncrypt(cipher, mk, nonce, pt, a);
            s.Ns++;
            std::cout << "FRAME " << cipher << " " << toHex(s.DHs_pub) << " " << pn
                      << " " << n << " " << toHex(nonce) << " " << toHex(ct)
                      << "\n" << std::flush;
        } else if (cmd == "RECV") {
            std::string cipher, dhH, nonceH, ctH;
            uint32_t pn, n;
            ss >> cipher >> dhH >> pn >> n >> nonceH >> ctH;
            Bytes dhPub = fromHex(dhH), nonce = fromHex(nonceH), ct = fromHex(ctH);
            if (!s.haveDHr || dhPub != s.DHr_pub) dhRatchet(s, dhPub);
            Bytes ckNext, mk;
            kdf_ck(s.CKr, ckNext, mk);
            s.CKr = ckNext;
            s.Nr++;
            Bytes a = ad(cipher, dhPub, pn, n);
            Bytes pt;
            if (!aeadDecrypt(cipher, mk, nonce, ct, a, pt))
                std::cout << "FAIL\n" << std::flush;
            else
                std::cout << "PLAIN " << toHex(pt) << "\n" << std::flush;
        } else if (cmd == "BYE") {
            break;
        }
    }
    return 0;
}
