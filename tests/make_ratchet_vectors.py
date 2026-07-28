"""
Generate a cross-language interop vector for a *ratcheting session*.

The original interop check (tests/make_vector.py) proved one message. A ratchet
is stateful, so the check must span a sequence. This script runs the reference
ratchet as Alice, encrypts an ordered run of messages to Bob, and writes the
session so another implementation (the C++ consumer) can initialise Bob and
decrypt the whole run, confirming byte-for-byte agreement on:

  * the Route A bootstrap (SK = derive_shared_key),
  * the first DH ratchet step on the receiver,
  * the symmetric chain (KDF_CK) across many messages,
  * XChaCha20-Poly1305 with the header bound as associated data,
  * header parsing (dh / pn / n).

Scope: this vector is one-directional (Alice -> Bob, a single sending chain),
which is what a static vector can verify deterministically. Multi-step DH
ratchets and healing are proven in tests/test_ratchet.py and, for full
bidirectional cross-language behaviour, by the live harness described in
RATCHET_TESTING.md.

Outputs two files:
  ratchet_vector.json  -- readable, self-describing (for Python / inspection)
  ratchet_vector.txt   -- flat, dependency-free (for the C++ consumer)

Usage:
  python tests/make_ratchet_vectors.py          # writes the two files
  python tests/make_ratchet_vectors.py --check   # writes, then replays in Python
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
import ratchet as R

MESSAGES = [
    "Cross-language interop works!",
    "Second message, same sending chain.",
    "Third -- the symmetric ratchet keeps advancing.",
    "Fourth, still forward-secret.",
    "Fifth and last.",
]


def build() -> dict:
    a_priv, a_pub = R.gen_keypair()
    b_priv, b_pub = R.gen_keypair()
    sk = R.bootstrap_sk(a_priv, b_pub)
    alice = R.init_alice(sk, b_pub)

    transcript = []
    for text in MESSAGES:
        # cipher= is explicit: the Tier 2 oracle hardcodes xc20p1305-r1, so a
        # vector built under whatever the local default happens to be would
        # fail across the language boundary for a reason that has nothing to
        # do with correctness.
        header, nonce, ct = R.encrypt(alice, text.encode("utf-8"),
                                      cipher=R.CIPHER_XCHACHA)
        transcript.append(
            {
                # ratchet.py gained hybrid-cipher support, so the header now
                # carries the cipher tag and decrypt() requires it. Recording it
                # per message keeps the vector self-describing.
                "cipher": header["cipher"],
                "dh": header["dh"].hex(),
                "pn": header["pn"],
                "n": header["n"],
                "nonce": nonce.hex(),
                "ct": ct.hex(),
                "expect_pt": text,
            }
        )

    # The consumer plays Bob: it needs Bob's identity keypair and Alice's public
    # key to recompute SK (Route A), then decrypts the transcript in order.
    return {
        "version": "ratchet-interop-v1",
        # R.CIPHER_TAG was removed when ratchet.py gained hybrid-cipher
        # support; the constants are now CIPHER_AES / CIPHER_XCHACHA, and they
        # are str rather than bytes, so there is nothing left to decode.
        #
        # XChaCha20-Poly1305 is the right one here: the Tier 2 oracle
        # (reference_oracles/_ref_interop_recv.cpp) hardcodes "xc20p1305-r1",
        # and the vector must match what that independent implementation reads.
        "cipher": R.CIPHER_XCHACHA,
        "info_sk": R.INFO_SK.decode(),
        "info_root": R.INFO_ROOT.decode(),
        "direction": "alice->bob",
        "alice_identity_pub": a_pub.hex(),
        "bob_identity_priv": b_priv.hex(),
        "bob_identity_pub": b_pub.hex(),
        "transcript": transcript,
    }


def write_flat(v: dict, path: Path) -> None:
    lines = [
        f"ALICE_PUB {v['alice_identity_pub']}",
        f"BOB_PRIV {v['bob_identity_priv']}",
        f"BOB_PUB {v['bob_identity_pub']}",
    ]
    for m in v["transcript"]:
        lines.append(
            "MSG {dh} {pn} {n} {nonce} {ct} {pt}".format(
                dh=m["dh"], pn=m["pn"], n=m["n"], nonce=m["nonce"], ct=m["ct"],
                pt=m["expect_pt"].encode("utf-8").hex(),
            )
        )
    path.write_text("\n".join(lines) + "\n")


def replay_in_python(v: dict) -> None:
    """Independent confirmation that the vector is complete and self-consistent:
    initialise Bob purely from the vector and decrypt every message."""
    b_priv = bytes.fromhex(v["bob_identity_priv"])
    b_pub = bytes.fromhex(v["bob_identity_pub"])
    a_pub = bytes.fromhex(v["alice_identity_pub"])
    sk = R.bootstrap_sk(b_priv, a_pub)
    bob = R.init_bob(sk, b_priv, b_pub)
    for m in v["transcript"]:
        header = {"cipher": m["cipher"], "dh": bytes.fromhex(m["dh"]),
                  "pn": m["pn"], "n": m["n"]}
        pt = R.decrypt(bob, header, bytes.fromhex(m["nonce"]), bytes.fromhex(m["ct"]))
        got = pt.decode("utf-8")
        assert got == m["expect_pt"], f"mismatch: {got!r} != {m['expect_pt']!r}"
    print(f"[python replay] {len(v['transcript'])} messages decrypted, all match.")


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    vector = build()
    (here / "ratchet_vector.json").write_text(json.dumps(vector, indent=2))
    write_flat(vector, here / "ratchet_vector.txt")
    print("wrote ratchet_vector.json and ratchet_vector.txt")
    if "--check" in sys.argv:
        replay_in_python(vector)
