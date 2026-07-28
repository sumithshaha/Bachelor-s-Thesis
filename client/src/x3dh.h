#ifndef X3DH_H
#define X3DH_H

// ---------------------------------------------------------------------------
// x3dh.h -- Extended Triple Diffie-Hellman initial key agreement.
//
// A direct port of tests/x3dh.py, which is the specification. Correctness is not
// a matter of reading that file carefully: tests/x3dh_vectors.json fixes every
// private key so the agreement is deterministic, and this port is correct
// exactly when tools/x3dh_vectors_check reproduces every value byte for byte.
//
// NO Qt DEPENDENCY. This module is plain C++17 over std::vector<unsigned char>
// and libsodium. That is deliberate: the interop harness builds its C++ with a
// bare g++ and libsodium, and an earlier version of this file used QByteArray
// purely out of habit, which made the vector check unbuildable on Windows --
// Qt ships no pkg-config files there, so the tier silently skipped. Cryptography
// with no reason to know about a GUI toolkit should not depend on one.
//
// SIGNING. The identity key is Ed25519 and signing is stock RFC 8032 via
// libsodium's crypto_sign_detached. The earlier reference used a bespoke XEdDSA
// whose bytes no library reproduces; that is why this port can use the obvious
// call and the previous design could not.
//
// AGREEMENT. The four Diffie-Hellmans are X25519. The identity's X25519
// counterpart is DERIVED from the Ed25519 key with libsodium's birational map,
// so one published key both signs and agrees.
//
// The module holds no session state and does not touch CryptoBox, so it can be
// compiled and checked on its own, before the identity migration is attempted.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <vector>

namespace X3DH {

using Bytes = std::vector<unsigned char>;

// Sizes, named so call sites do not carry bare numbers.
constexpr int kSeedBytes     = 32;   // Ed25519 identity seed (what we store)
constexpr int kEdPubBytes    = 32;   // Ed25519 identity public
constexpr int kEdSecretBytes = 64;   // libsodium layout: seed || public
constexpr int kX25519Bytes   = 32;   // any X25519 key, private or public
constexpr int kSigBytes      = 64;   // detached Ed25519 signature

// The recipient's public bundle, exactly as the relay serves it.
struct Bundle {
    Bytes   ik;          // Ed25519 identity public (32)
    Bytes   spk;         // X25519 signed prekey public (32)
    Bytes   spkSig;      // Ed25519 signature over spk (64)
    Bytes   opk;         // X25519 one-time prekey public (32), empty if none
    int32_t opkId = -1;  // id of that prekey, -1 when none was offered
};

// What the initiator derives and must transmit with its first message.
struct InitiatorResult {
    Bytes   sk;          // 32-byte shared secret: the ratchet's root input
    Bytes   ik;          // our Ed25519 identity public
    Bytes   ek;          // our X25519 ephemeral public
    Bytes   ad;          // associated data: Encode(IK_A) || Encode(IK_B)
    int32_t opkId = -1;
};

// --- identity -------------------------------------------------------------
// A fresh Ed25519 identity. The 32-byte seed is the only secret at rest; the
// 64-byte libsodium secret key and the X25519 counterpart both derive from it.
bool generateIdentity(Bytes &seedOut, Bytes &edPubOut);

// The Ed25519 public key for a seed. Empty on bad input.
Bytes identityPublic(const Bytes &seed);

// The X25519 private key derived from an identity seed. Empty on bad input.
Bytes identityToX25519Private(const Bytes &seed);

// The X25519 public key derived from an Ed25519 identity public key. Returns
// false for a key that is not a convertible Ed25519 point, which is the correct
// response to a malformed or hostile bundle rather than a silent wrong answer.
bool identityToX25519Public(const Bytes &edPub, Bytes &out);

// --- signing (RFC 8032, deterministic) ------------------------------------
// Detached 64-byte signature. Byte-identical to Python's
// Ed25519PrivateKey.sign for the same seed and message; Ed25519 has no signing
// nonce, so this is a reproducible output and the vectors pin its bytes.
Bytes sign(const Bytes &seed, const Bytes &message);

// Verify a detached signature. False rather than a throw, so a caller can treat
// a bad bundle as data.
bool verify(const Bytes &edPub, const Bytes &message, const Bytes &sig);

// --- prekeys --------------------------------------------------------------
// A fresh signed prekey. The prekey is X25519 (it is an agreement key); the
// signature over it is made with the Ed25519 identity.
bool newSignedPrekey(const Bytes &ikSeed, Bytes &spkPriv, Bytes &spkPub,
                     Bytes &sigOut);

// A fresh one-time prekey.
bool newOneTimePrekey(Bytes &priv, Bytes &pub);

// --- the agreement --------------------------------------------------------
// Run X3DH as the initiator. Verifies the signed prekey against the bundle's
// identity key BEFORE computing any DH -- that check is what stops the relay
// serving a bundle of its own making, so it must not be skipped or deferred.
// Returns false on a bad signature, a malformed key, or a degenerate DH.
bool initiator(const Bytes &aIkSeed, const Bundle &bundle, InitiatorResult &out);

// As above but with a caller-supplied ephemeral, so a test can be deterministic.
// Production code should call initiator(), which generates its own.
bool initiatorWithEphemeral(const Bytes &aIkSeed, const Bundle &bundle,
                            const Bytes &ekPriv, InitiatorResult &out);

// Run X3DH as the responder, from the initiator's Ed25519 identity public and
// X25519 ephemeral public. Pass an empty opkPriv when the initiator used no
// one-time prekey. The CALLER consumes the one-time prekey exactly once -- this
// function does not own the pool, and reuse would hand two sessions the same
// DH4 contribution.
bool responder(const Bytes &bIkSeed, const Bytes &spkPriv, const Bytes &opkPriv,
               const Bytes &ikA, const Bytes &ekA, Bytes &skOut);

// --- small helpers, useful at Qt call sites and in tests ------------------
Bytes fromHex(const std::string &hex);
std::string toHex(const Bytes &b);

}  // namespace X3DH

#endif  // X3DH_H
