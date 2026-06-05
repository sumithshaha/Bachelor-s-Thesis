// Interop harness: prove the C++ client crypto matches the Python reference.
//   1. X25519 scalar multiplication -> shared secret
//   2. HKDF-SHA256 (RFC 5869, from HMAC) -> 256-bit key
//   3. AES-256-GCM -> decrypt
#include <sodium.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static const char *kHkdfInfo = "tamk-chat-e2ee-v1";

static std::vector<unsigned char> fromHex(const std::string &hex) {
    std::vector<unsigned char> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = (unsigned char)std::stoi(hex.substr(i * 2, 2), nullptr, 16);
    return out;
}

// HKDF-SHA256 producing a 32-byte key. salt=None -> 32 zero bytes.
static void hkdfSha256_32(const unsigned char *ikm, size_t ikmLen,
                          const char *info, unsigned char outKey[32]) {
    unsigned char salt[crypto_auth_hmacsha256_KEYBYTES] = {0};
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, sizeof salt);
    crypto_auth_hmacsha256_update(&st, ikm, ikmLen);
    crypto_auth_hmacsha256_final(&st, prk);

    unsigned char counter = 0x01;
    crypto_auth_hmacsha256_init(&st, prk, sizeof prk);
    crypto_auth_hmacsha256_update(&st,
        reinterpret_cast<const unsigned char *>(info), strlen(info));
    crypto_auth_hmacsha256_update(&st, &counter, 1);
    crypto_auth_hmacsha256_final(&st, outKey);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) { printf("sodium init failed\n"); return 1; }
    if (argc != 5) {
        printf("usage: %s <bob_priv> <alice_pub> <nonce> <ct>\n", argv[0]);
        return 1;
    }
    auto bobPriv  = fromHex(argv[1]);
    auto alicePub = fromHex(argv[2]);
    auto nonce    = fromHex(argv[3]);
    auto ct       = fromHex(argv[4]);

    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared, bobPriv.data(), alicePub.data()) != 0) {
        printf("scalarmult failed\n"); return 1;
    }
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    hkdfSha256_32(shared, sizeof shared, kHkdfInfo, key);

    std::vector<unsigned char> pt(ct.size());
    unsigned long long ptLen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            pt.data(), &ptLen, nullptr,
            ct.data(), ct.size(), nullptr, 0,
            nonce.data(), key) != 0) {
        printf("DECRYPT FAILED (authentication error)\n");
        return 1;
    }
    printf("%.*s\n", (int)ptLen, pt.data());
    return 0;
}
