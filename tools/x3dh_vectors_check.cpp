// ---------------------------------------------------------------------------
// x3dh_vectors_check.cpp -- prove the C++ X3DH port matches the Python reference.
//
// The C++ client cannot be compiled inside the Python test run, so client/src/
// x3dh.cpp cannot be checked against tests/x3dh.py the way the ratchet is. This
// closes that gap: it reads tests/x3dh_vectors.json, whose keys are all fixed,
// and requires the port to reproduce every value byte for byte.
//
// An X3DH that is subtly wrong does not fail loudly -- it derives a shared secret
// the peer does not share, which surfaces much later as an undecryptable first
// message and is very hard to attribute. This turns that into a named failure.
//
// NO Qt. An earlier version parsed the vectors with QJsonDocument, which made
// this unbuildable on Windows because Qt ships no pkg-config files there and the
// tier silently skipped. The vector file has a fixed, flat shape, so a tiny
// scoped string lookup is enough and the binary builds with the same bare
// toolchain as the rest of the interop harness.
//
// Build (from the repository root):
//   g++ -std=c++17 -DHAVE_SODIUM -I client/src \
//       tools/x3dh_vectors_check.cpp client/src/x3dh.cpp \
//       -lsodium -o build-interop/x3dh_vectors_check
//
// Run:  ./build-interop/x3dh_vectors_check [path/to/x3dh_vectors.json]
// Exit status 0 means every vector matched.
// ---------------------------------------------------------------------------
#include "x3dh.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using X3DH::Bytes;

static int gFail = 0;

// --- minimal, scope-aware JSON string lookup -------------------------------
// The vectors are flat objects of hex strings, but several key names (ik_a,
// ik_b) appear in more than one object, so a naive search would read the wrong
// one. Look up the section first, then the key after it.
static std::string field(const std::string &doc, const std::string &section,
                         const std::string &key)
{
    const std::string sMark = "\"" + section + "\"";
    size_t at = doc.find(sMark);
    if (at == std::string::npos) return {};
    const std::string kMark = "\"" + key + "\"";
    at = doc.find(kMark, at);
    if (at == std::string::npos) return {};
    at = doc.find(':', at + kMark.size());
    if (at == std::string::npos) return {};
    const size_t open = doc.find('"', at);
    if (open == std::string::npos) return {};
    const size_t close = doc.find('"', open + 1);
    if (close == std::string::npos) return {};
    return doc.substr(open + 1, close - open - 1);
}

// Value of `key` inside the n-th object of the "cases" array.
static std::string caseField(const std::string &doc, int n, const std::string &key)
{
    size_t at = doc.find("\"cases\"");
    if (at == std::string::npos) return {};
    for (int i = 0; i <= n; ++i) {
        at = doc.find('{', at);
        if (at == std::string::npos) return {};
        if (i < n) at = doc.find('}', at);
        if (at == std::string::npos) return {};
    }
    const size_t end = doc.find('}', at);
    const std::string obj = doc.substr(at, end - at);
    const std::string kMark = "\"" + key + "\"";
    size_t k = obj.find(kMark);
    if (k == std::string::npos) return {};
    k = obj.find(':', k + kMark.size());
    const size_t open = obj.find_first_not_of(" \t\n\r", k + 1);
    if (open == std::string::npos) return {};
    if (obj[open] == '"') {
        const size_t close = obj.find('"', open + 1);
        return obj.substr(open + 1, close - open - 1);
    }
    const size_t stop = obj.find_first_of(",\n}", open);
    std::string raw = obj.substr(open, stop - open);
    while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\r')) raw.pop_back();
    return raw;                                     // true / false / number
}

static void check(const std::string &label, const Bytes &got,
                  const std::string &expectHex)
{
    const std::string g = X3DH::toHex(got);
    if (!expectHex.empty() && g == expectHex) {
        std::cout << "   PASS  " << label << "\n";
    } else {
        std::cout << "   FAIL  " << label << "\n"
                  << "         expected " << expectHex << "\n"
                  << "         got      " << g << "\n";
        ++gFail;
    }
}

static void checkBool(const std::string &label, bool got, bool expect)
{
    if (got == expect) {
        std::cout << "   PASS  " << label << "\n";
    } else {
        std::cout << "   FAIL  " << label << " (expected "
                  << (expect ? "true" : "false") << ")\n";
        ++gFail;
    }
}

int main(int argc, char **argv)
{
    const std::string path = (argc > 1) ? argv[1] : "tests/x3dh_vectors.json";
    std::ifstream f(path);
    if (!f) {
        std::cout << "cannot open " << path
                  << "\n(run from the repository root, or pass the path)\n";
        return 2;
    }
    std::stringstream ss; ss << f.rdbuf();
    const std::string doc = ss.str();

    const Bytes ikASeed  = X3DH::fromHex(field(doc, "identity_seeds", "ik_a"));
    const Bytes ikBSeed  = X3DH::fromHex(field(doc, "identity_seeds", "ik_b"));
    const std::string ikAPubHex = field(doc, "public_keys", "ik_a");
    const std::string ikBPubHex = field(doc, "public_keys", "ik_b");
    const Bytes ikAPub   = X3DH::fromHex(ikAPubHex);
    const Bytes ikBPub   = X3DH::fromHex(ikBPubHex);
    const Bytes spkB     = X3DH::fromHex(field(doc, "public_keys", "spk_b"));
    const Bytes opkB     = X3DH::fromHex(field(doc, "public_keys", "opk_b"));
    const Bytes ekAPub   = X3DH::fromHex(field(doc, "public_keys", "ek_a"));
    const Bytes ekAPriv  = X3DH::fromHex(field(doc, "private_keys", "ek_a"));
    const Bytes spkBPriv = X3DH::fromHex(field(doc, "private_keys", "spk_b"));
    const Bytes opkBPriv = X3DH::fromHex(field(doc, "private_keys", "opk_b"));

    if (ikASeed.empty() || ikBPub.empty() || spkB.empty()) {
        std::cout << "vector file did not parse as expected\n";
        return 2;
    }

    std::cout << "X3DH vector conformance  --  " << path << "\n\n";

    std::cout << "identity and conversion\n";
    check("Ed25519 public from seed (A)", X3DH::identityPublic(ikASeed), ikAPubHex);
    check("Ed25519 public from seed (B)", X3DH::identityPublic(ikBSeed), ikBPubHex);
    check("derived X25519 private (A)", X3DH::identityToX25519Private(ikASeed),
          field(doc, "derived_x25519_priv", "ik_a"));
    check("derived X25519 private (B)", X3DH::identityToX25519Private(ikBSeed),
          field(doc, "derived_x25519_priv", "ik_b"));
    Bytes xa, xb;
    checkBool("convert Ed25519 public (A)", X3DH::identityToX25519Public(ikAPub, xa), true);
    check("derived X25519 public (A)", xa, field(doc, "derived_x25519_pub", "ik_a"));
    checkBool("convert Ed25519 public (B)", X3DH::identityToX25519Public(ikBPub, xb), true);
    check("derived X25519 public (B)", xb, field(doc, "derived_x25519_pub", "ik_b"));
    Bytes junk;
    checkBool("reject a non-convertible public key",
              X3DH::identityToX25519Public(Bytes(31, 0), junk), false);

    std::cout << "\nsignature (RFC 8032 Ed25519, deterministic)\n";
    const std::string sigHex = field(doc, "signature", "valid_signature");
    const std::string badHex = field(doc, "signature", "corrupted_signature_must_reject");
    check("signature reproduces frozen bytes", X3DH::sign(ikBSeed, spkB), sigHex);
    checkBool("frozen signature verifies",
              X3DH::verify(ikBPub, spkB, X3DH::fromHex(sigHex)), true);
    checkBool("corrupted signature rejected",
              X3DH::verify(ikBPub, spkB, X3DH::fromHex(badHex)), false);
    checkBool("signature by the wrong identity rejected",
              X3DH::verify(ikBPub, spkB, X3DH::sign(ikASeed, spkB)), false);

    std::cout << "\nshared secret\n";
    for (int i = 0; i < 2; ++i) {
        const std::string name = caseField(doc, i, "name");
        const std::string skHex = caseField(doc, i, "sk");
        const bool withOpk = (caseField(doc, i, "opk") == "true");
        if (name.empty() || skHex.empty()) {
            std::cout << "   FAIL  case " << i << " missing from the vector file\n";
            ++gFail;
            continue;
        }

        X3DH::Bundle b;
        b.ik = ikBPub;
        b.spk = spkB;
        b.spkSig = X3DH::sign(ikBSeed, spkB);
        if (withOpk) { b.opk = opkB; b.opkId = 7; }

        X3DH::InitiatorResult r;
        if (!X3DH::initiatorWithEphemeral(ikASeed, b, ekAPriv, r)) {
            std::cout << "   FAIL  initiator(" << name << ") returned false\n";
            ++gFail;
        } else {
            check("initiator sk  -- " + name, r.sk, skHex);
            check("ephemeral pub -- " + name, r.ek, field(doc, "public_keys", "ek_a"));
        }

        Bytes sk;
        if (!X3DH::responder(ikBSeed, spkBPriv, withOpk ? opkBPriv : Bytes(),
                             ikAPub, ekAPub, sk)) {
            std::cout << "   FAIL  responder(" << name << ") returned false\n";
            ++gFail;
        } else {
            check("responder sk  -- " + name, sk, skHex);
        }
    }

    std::cout << "\nassociated data and bundle rejection\n";
    {
        X3DH::Bundle b;
        b.ik = ikBPub; b.spk = spkB; b.spkSig = X3DH::sign(ikBSeed, spkB);
        b.opk = opkB;  b.opkId = 7;
        X3DH::InitiatorResult r;
        if (X3DH::initiatorWithEphemeral(ikASeed, b, ekAPriv, r))
            check("AD = Encode(IK_A) || Encode(IK_B)", r.ad,
                  field(doc, "associated_data", "value"));
        else { std::cout << "   FAIL  initiator failed for the AD check\n"; ++gFail; }

        X3DH::Bundle bad;
        bad.ik = ikBPub; bad.spk = spkB; bad.spkSig = X3DH::fromHex(badHex);
        X3DH::InitiatorResult r2;
        checkBool("initiator refuses a bundle with a bad signature",
                  X3DH::initiatorWithEphemeral(ikASeed, bad, ekAPriv, r2), false);
    }

    std::cout << "\n"
              << (gFail == 0 ? "ALL VECTORS MATCHED"
                             : std::to_string(gFail) + " CHECK(S) FAILED")
              << "\n";
    return gFail == 0 ? 0 : 1;
}
