"""
Live-harness endpoint (Python). Wraps the product ratchet (server/ratchet.py)
and speaks a tiny line protocol over stdin/stdout so the driver
(tests/live_harness.py) can make it converse with another endpoint -- Python or
C++ -- in real time.

Launch (the driver does this for you):
  python tests/ratchet_cli.py <role> <own_priv_hex> <own_pub_hex> <peer_pub_hex>
    role = alice (sends first) | bob (receives first)

Protocol (one command per line, one reply per line, all hex is lowercase):
  SEND <plaintext_hex>                         -> FRAME <dh> <pn> <n> <nonce> <ct>
  RECV <dh> <pn> <n> <nonce> <ct>              -> PLAIN <plaintext_hex>  | FAIL
  BYE                                          -> (exit)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
import ratchet as R
from nacl.exceptions import CryptoError
from cryptography.exceptions import InvalidTag


def main() -> None:
    role, own_priv, own_pub, peer_pub = (
        sys.argv[1],
        bytes.fromhex(sys.argv[2]),
        bytes.fromhex(sys.argv[3]),
        bytes.fromhex(sys.argv[4]),
    )
    force = sys.argv[5] if len(sys.argv) >= 6 else "auto"  # auto|aes|xchacha
    forced = {"aes": R.CIPHER_AES, "xchacha": R.CIPHER_XCHACHA}.get(force)
    sk = R.bootstrap_sk(own_priv, peer_pub)
    if role == "alice":
        st = R.init_alice(sk, peer_pub)          # peer identity key = initial DHr
    else:
        st = R.init_bob(sk, own_priv, own_pub)   # own identity keypair = initial DHs

    out = sys.stdout
    for line in sys.stdin:
        parts = line.split()
        if not parts:
            continue
        cmd = parts[0]
        if cmd == "SEND":
            header, nonce, ct = R.encrypt(st, bytes.fromhex(parts[1]), cipher=forced)
            out.write(
                "FRAME {cipher} {dh} {pn} {n} {nonce} {ct}\n".format(
                    cipher=header["cipher"], dh=header["dh"].hex(),
                    pn=header["pn"], n=header["n"], nonce=nonce.hex(), ct=ct.hex(),
                )
            )
            out.flush()
        elif cmd == "RECV":
            cipher = parts[1]
            dh = bytes.fromhex(parts[2])
            pn, n = int(parts[3]), int(parts[4])
            nonce, ct = bytes.fromhex(parts[5]), bytes.fromhex(parts[6])
            try:
                pt = R.decrypt(st, {"cipher": cipher, "dh": dh, "pn": pn, "n": n}, nonce, ct)
                out.write("PLAIN " + pt.hex() + "\n")
            except (CryptoError, InvalidTag, ValueError):
                out.write("FAIL\n")
            out.flush()
        elif cmd == "BYE":
            return


if __name__ == "__main__":
    main()
