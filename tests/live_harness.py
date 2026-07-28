"""
Tier 3 -- live bidirectional interop harness.

Runs a REAL conversation between two ratchet endpoints in separate processes,
alternating direction every message. Because each direction change triggers a DH
ratchet on the receiving side, a multi-turn run exercises repeated DH ratchet
steps and post-compromise healing end to end -- the part a static one-directional
vector cannot reach.

Either endpoint may be the Python CLI (tests/ratchet_cli.py, wrapping the product
schedule server/ratchet.py) or the C++ CLI (tests/ratchet_cli.cpp, the libsodium
oracle). Mixing them is the cross-language proof.

The driver owns the identities, spawns both endpoints, shuttles each FRAME from
sender to receiver, and asserts every decrypted plaintext matches what was sent.

Usage:
  python tests/live_harness.py \
      --alice "python3 tests/ratchet_cli.py" \
      --bob   "./ratchet_cli_cpp" \
      --turns 8

The driver appends the four key arguments (role, own_priv, own_pub, peer_pub) to
each endpoint command.
"""
from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
import ratchet as R  # only for key generation; endpoints do all the crypto


def spawn(cmd, role, own_priv, own_pub, peer_pub, force="auto"):
    argv = shlex.split(cmd) + [role, own_priv.hex(), own_pub.hex(), peer_pub.hex(), force]
    return subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered
    )


def send(proc, line: str) -> None:
    proc.stdin.write(line + "\n")
    proc.stdin.flush()


def read(proc) -> str:
    return proc.stdout.readline().strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alice", default="python3 tests/ratchet_cli.py")
    ap.add_argument("--bob", default="python3 tests/ratchet_cli.py")
    ap.add_argument("--turns", type=int, default=8)
    ap.add_argument("--alice-cipher", default="auto")  # auto|aes|xchacha
    ap.add_argument("--bob-cipher", default="auto")
    args = ap.parse_args()

    # Identities (long-term). Each endpoint re-derives the shared secret itself.
    a_priv, a_pub = R.gen_keypair()
    b_priv, b_pub = R.gen_keypair()

    alice = spawn(args.alice, "alice", a_priv, a_pub, b_pub, args.alice_cipher)
    bob = spawn(args.bob, "bob", b_priv, b_pub, a_pub, args.bob_cipher)

    endpoints = {"alice": alice, "bob": bob}
    label = {"alice": args.alice.split()[-1], "bob": args.bob.split()[-1]}
    print(f"alice = {args.alice!r}")
    print(f"bob   = {args.bob!r}\n")

    ok = 0
    try:
        for i in range(args.turns):
            sender, receiver = ("alice", "bob") if i % 2 == 0 else ("bob", "alice")
            text = f"turn {i} from {sender}"
            send(endpoints[sender], "SEND " + text.encode().hex())
            frame = read(endpoints[sender])
            assert frame.startswith("FRAME"), f"sender did not emit FRAME: {frame!r}"
            _, cipher, dh, pn, n, nonce, ct = frame.split()
            send(endpoints[receiver], f"RECV {cipher} {dh} {pn} {n} {nonce} {ct}")
            reply = read(endpoints[receiver])
            assert reply.startswith("PLAIN"), f"decrypt failed at turn {i}: {reply!r}"
            got = bytes.fromhex(reply.split()[1]).decode()
            assert got == text, f"mismatch at turn {i}: {got!r} != {text!r}"
            print(f"  turn {i:2d}  {sender:>5} -> {receiver:<5}  "
                  f"[{cipher:>12}]  \"{got}\"   (n={n})")
            ok += 1
    finally:
        for p in endpoints.values():
            try:
                send(p, "BYE")
            except Exception:
                pass
            p.wait(timeout=5)

    print(f"\nLIVE INTEROP OK: {ok}/{args.turns} turns, bidirectional, "
          f"{label['alice']} <-> {label['bob']}")
    return 0 if ok == args.turns else 1


if __name__ == "__main__":
    raise SystemExit(main())
