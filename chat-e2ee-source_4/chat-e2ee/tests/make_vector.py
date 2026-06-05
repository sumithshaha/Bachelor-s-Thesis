"""
Produce a test vector for the C++ interop check.

Generates two identities, encrypts a message as Alice, and prints the keys and
ciphertext as JSON so the C++ harness (interop.cpp) can decrypt it as Bob.
This is the script referenced in docs/BUILD.md.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
from crypto_core import Identity, derive_shared_key, encrypt

alice = Identity.generate()
bob = Identity.generate()
key = derive_shared_key(alice, bob.public_bytes())
env = encrypt(key, "Cross-language interop works!")

print(json.dumps({
    "alice_priv": alice.private_bytes().hex(),
    "alice_pub":  alice.public_bytes().hex(),
    "bob_priv":   bob.private_bytes().hex(),
    "bob_pub":    bob.public_bytes().hex(),
    "nonce":      env.nonce.hex(),
    "ct":         env.ciphertext.hex(),
}, indent=2))
