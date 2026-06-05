"""
Demonstration script for the thesis.

This is not a test; it is a small scripted scenario that produces the kind of
visible evidence you can screenshot and put in the thesis. It runs the real
server in the background, sends one encrypted message through it, and prints a
side-by-side comparison of:

  - what Alice actually wrote (plaintext, known only to the clients), and
  - what the server saw and stored (ciphertext).

Run with:  python demo_proof.py
"""

import asyncio
import json
import sys
import time
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent))

from crypto_core import Identity, derive_shared_key, encrypt, decrypt, Envelope
from server import ChatServer, Storage
from websockets.asyncio.server import serve


async def main() -> None:
    storage = Storage("demo.db")
    server = ChatServer(storage)

    async with serve(server.handle, "localhost", 8801):
        uri = "ws://localhost:8801"
        alice = Identity.generate()
        bob = Identity.generate()

        bob_ws = await websockets.connect(uri)
        await bob_ws.send(json.dumps({
            "type": "hello", "nick": "bob", "pubkey": bob.public_bytes().hex()}))
        await asyncio.sleep(0.2)
        # drain
        while True:
            try:
                await asyncio.wait_for(bob_ws.recv(), timeout=0.1)
            except asyncio.TimeoutError:
                break

        alice_ws = await websockets.connect(uri)
        await alice_ws.send(json.dumps({
            "type": "hello", "nick": "alice", "pubkey": alice.public_bytes().hex()}))
        await asyncio.sleep(0.2)
        while True:
            try:
                await asyncio.wait_for(alice_ws.recv(), timeout=0.1)
            except asyncio.TimeoutError:
                break

        plaintext = "The launch code is 1947-ALPHA"
        key_a = derive_shared_key(alice, bob.public_bytes())
        env = encrypt(key_a, plaintext)
        wire = {
            "type": "msg", "from": "alice", "to": "bob",
            "nonce": env.nonce.hex(), "ct": env.ciphertext.hex(),
            "ts": int(time.time() * 1000),
        }
        await alice_ws.send(json.dumps(wire))

        received = None
        for _ in range(10):
            raw = await asyncio.wait_for(bob_ws.recv(), timeout=2.0)
            frame = json.loads(raw)
            if frame.get("type") == "msg":
                received = frame
                break

        key_b = derive_shared_key(bob, alice.public_bytes())
        recovered = decrypt(key_b, Envelope.from_hex(received))

        print("\n" + "=" * 64)
        print("  END-TO-END ENCRYPTION DEMONSTRATION")
        print("=" * 64)
        print(f"\n  Alice typed       : {plaintext!r}")
        print(f"\n  --- What travels over the wire / through the server ---")
        print(f"  from              : {wire['from']}")
        print(f"  to                : {wire['to']}")
        print(f"  nonce  (hex)      : {wire['nonce']}")
        print(f"  ciphertext (hex)  : {wire['ct']}")
        print(f"\n  The server stored and forwarded the bytes above.")
        print(f"  Nowhere in them does the plaintext appear.")
        print(f"\n  Bob decrypted     : {recovered!r}")
        print(f"\n  Match             : {recovered == plaintext}")
        print("=" * 64 + "\n")

        await alice_ws.close()
        await bob_ws.close()


if __name__ == "__main__":
    asyncio.run(main())
