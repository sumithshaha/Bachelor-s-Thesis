#!/usr/bin/env python3
"""
make_demo_pki.py -- generate the ChatE2EE lab certificate authority.

WHY THIS EXISTS
---------------
Until now the project demonstrated TLS in two very different ways:

  * against the cPouta relay, with a real Let's Encrypt certificate that the
    operating system's trust store validates properly; and
  * against localhost, with a SELF-SIGNED leaf that the client could only
    accept by calling ignoreSslErrors() -- i.e. by switching verification off.

The second one is not a faithful demonstration of TLS. It proves the traffic is
encrypted, but it proves nothing about authentication, which is half of what
TLS is for. When the cPouta VM is deleted, that weak path would have been the
only one left.

This script removes that problem by making the lab its own certificate
authority. It produces:

  pki/ca.crt      the ROOT certificate  (public -- this is what the client trusts)
  pki/ca.key      the ROOT private key  (SECRET -- never leaves this machine)
  pki/server.crt  the relay's LEAF certificate, signed by the root
  pki/server.key  the relay's private key

The client embeds ca.crt as a trust anchor and then performs completely normal,
completely strict verification: it builds the chain leaf -> root, checks the
signature, checks the validity dates, and checks that the hostname it dialled
appears in the certificate's SubjectAlternativeName. Nothing is ignored. The
handshake either verifies or the connection fails, exactly as with a public CA.

The honest framing for the thesis is this: a certificate authority is not a
special kind of organisation, it is a key pair whose public half a client has
decided to trust in advance. Let's Encrypt is trusted because the operating
system vendor put it in the trust store. This root is trusted because the
application puts it in its own trust store. The cryptography, the chain
building, the hostname matching and the failure modes are identical.

WHAT IS DELIBERATELY *NOT* CLAIMED
----------------------------------
This root is trusted only by this application. It is not, and must not be,
installed into the operating system trust store, and it gives no authority over
anything outside the lab. That is the correct scope: a single-purpose anchor.

USAGE
-----
  python tools/make_demo_pki.py
      Create the root (once) and issue a leaf for localhost + every local IP
      address found on this machine.

  python tools/make_demo_pki.py --leaf-only
      Keep the existing root, re-issue only the leaf. Use this when your LAN
      address changes (new Wi-Fi, DHCP lease) -- the client does NOT need
      rebuilding, because it trusts the root, not the leaf.

  python tools/make_demo_pki.py --ip 192.168.1.42 --dns relay.lab
      Add extra addresses/names to the leaf, on top of the auto-detected ones.

  python tools/make_demo_pki.py --show
      Print what is currently on disk: subjects, dates, SANs, fingerprints.

Requires only 'cryptography', which is already in requirements.txt.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import socket
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover - guidance path only
    sys.exit(
        "The 'cryptography' package is required.\n"
        "Install it with:  python -m pip install -r requirements.txt"
    )


# --------------------------------------------------------------------------
# Layout and policy constants
# --------------------------------------------------------------------------

# Everything lands in <repo>/pki/. tools/ is one level below the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = REPO_ROOT / "pki"

CA_CERT = PKI_DIR / "ca.crt"
CA_KEY = PKI_DIR / "ca.key"
LEAF_CERT = PKI_DIR / "server.crt"
LEAF_KEY = PKI_DIR / "server.key"

# The PUBLIC half of the root, in the location the client compiles in via
# client/pki.qrc. This copy is committed to the repository deliberately: it is
# a certificate, not a key, and the client is useless for lab connections
# without it.
#
# WHY THIS IS SYNCHRONISED AUTOMATICALLY
# --------------------------------------
# pki/ is excluded from version control because it holds ca.key. A fresh clone
# therefore has NO root and generates its own on first run -- which is correct
# and is the point. But the committed client/pki/demo-ca.crt is then a root
# from somebody else's machine, and the two no longer match.
#
# That produced a failing test on the very first command a new user ran
# (tests/test_real_tls.py::test_lab_root_is_embedded_and_is_the_current_root),
# for a reason that looks like a code fault and is not. The instruction to run
# `cp pki/ca.crt client/pki/demo-ca.crt` was printed under NEXT STEPS, but a
# printed instruction that must be followed for the suite to pass is a step
# that should not have been manual.
CLIENT_ROOT = REPO_ROOT / "client" / "pki" / "demo-ca.crt"

# The root outlives the thesis by a wide margin so the demonstration keeps
# working with no maintenance at all. The leaf is shorter-lived because that is
# what real deployments do, but still long enough that nobody has to think
# about it. Both are re-issuable in one command.
CA_DAYS = 7300      # 20 years
LEAF_DAYS = 3650    # 10 years

# RSA rather than an elliptic curve, purely for maximum interoperability: Qt on
# Windows may use either the OpenSSL or the Schannel TLS backend depending on
# what is installed, and Android uses OpenSSL. RSA-2048/3072 is accepted
# without argument by every one of them. The choice has no bearing on the
# protocol behaviour being demonstrated.
CA_KEY_BITS = 3072
LEAF_KEY_BITS = 2048

# A distinguished, obviously-non-public name, so that if this certificate ever
# turns up somewhere unexpected it is immediately identifiable as the lab root.
CA_COMMON_NAME = "ChatE2EE Lab Root CA"
CA_ORG = "ChatE2EE Thesis Lab (not a public CA)"
LEAF_COMMON_NAME = "ChatE2EE Relay"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _utcnow() -> _dt.datetime:
    """Timezone-aware UTC 'now', valid on modern Python without deprecation."""
    return _dt.datetime.now(_dt.timezone.utc)


def detect_local_ips() -> list[str]:
    """
    Find this machine's own IPv4 addresses, so the leaf certificate covers the
    address a phone on the same Wi-Fi will actually dial.

    Two independent probes are used because neither is reliable alone:

      1. Opening a UDP socket "towards" a public address and asking the kernel
         which local address it would use. No packet is ever sent -- connect()
         on UDP only sets the peer -- so this works without any traffic, but it
         does need a route to exist.
      2. Resolving our own hostname, which catches machines with several
         interfaces but can return stale or loopback entries.

    Everything is wrapped defensively: this must not fail on a laptop that is
    completely offline, which is exactly the situation the script exists for.
    """
    found: list[str] = []

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 9))  # never contacted; UDP connect() sends nothing
            found.append(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass

    try:
        for entry in socket.gethostbyname_ex(socket.gethostname())[2]:
            found.append(entry)
    except OSError:
        pass

    # Keep only sane, non-loopback IPv4 literals, preserving discovery order.
    out: list[str] = []
    for cand in found:
        try:
            addr = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if addr.is_loopback or addr.version != 4:
            continue
        if cand not in out:
            out.append(cand)
    return out


def sslip_name(ipv4: str) -> str:
    """
    Turn 192.168.1.42 into 192-168-1-42.sslip.io.

    sslip.io is a free public DNS service that resolves any address encoded in
    the hostname straight back to that address, including private ones. Adding
    these names costs nothing and buys a convenience: when the demo machine
    does have internet, the phone can dial a real DNS *name* rather than a bare
    IP, which is the more representative case for a TLS demonstration because
    hostname verification then exercises a DNS SAN rather than an IP SAN.

    It is strictly a bonus. The IP SANs below make the whole thing work with no
    DNS at all, which is why the offline case is fully covered.
    """
    return ipv4.replace(".", "-") + ".sslip.io"


def build_san_list(extra_ips: list[str], extra_dns: list[str]) -> tuple[list, list[str]]:
    """
    Assemble the SubjectAlternativeName entries and a human-readable summary.

    Modern TLS ignores the certificate's Common Name entirely for hostname
    matching -- only the SAN counts -- so getting this list right is what makes
    strict verification pass without any exceptions being made anywhere.
    """
    dns_names: list[str] = ["localhost"]
    ip_addrs: list[str] = ["127.0.0.1", "::1"]

    for ip in detect_local_ips() + extra_ips:
        if ip not in ip_addrs:
            ip_addrs.append(ip)

    for ip in list(ip_addrs):
        try:
            if ipaddress.ip_address(ip).version == 4 and not ipaddress.ip_address(ip).is_loopback:
                name = sslip_name(ip)
                if name not in dns_names:
                    dns_names.append(name)
        except ValueError:
            pass

    for name in extra_dns:
        if name not in dns_names:
            dns_names.append(name)

    san: list = [x509.DNSName(n) for n in dns_names]
    for ip in ip_addrs:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            print(f"  ! skipping unparseable address: {ip}")

    summary = [f"DNS:{n}" for n in dns_names] + [f"IP:{i}" for i in ip_addrs]
    return san, summary


def fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint, colon-separated, the way OpenSSL prints it."""
    raw = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in raw)


def _write_secret(path: Path, data: bytes) -> None:
    """
    Write a private key and make it owner-readable only where the platform
    supports it. On Windows the chmod is a no-op, which is why the printed
    warning matters more than the permission bits.
    """
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Certificate creation
# --------------------------------------------------------------------------

def create_root() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate the self-signed root CA: the single trust anchor of the lab."""
    print(f"  generating {CA_KEY_BITS}-bit root key (this takes a few seconds)...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=CA_KEY_BITS)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORG),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FI"),
    ])

    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)                       # self-signed: issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))   # tolerate clock skew
        .not_valid_after(now + _dt.timedelta(days=CA_DAYS))
        # A CA must say so. path_length=0 means it may sign end-entity
        # certificates but no further CAs -- the narrowest useful authority.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def create_leaf(ca_key: rsa.RSAPrivateKey,
                ca_cert: x509.Certificate,
                san: list) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate the relay's certificate and sign it with the root."""
    print(f"  generating {LEAF_KEY_BITS}-bit relay key...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=LEAF_KEY_BITS)

    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, LEAF_COMMON_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORG),
        ]))
        .issuer_name(ca_cert.subject)               # signed BY the root
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=LEAF_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        # SERVER_AUTH: this certificate is for identifying a server, and for
        # nothing else. A client that checks EKU (they all do) enforces this.
        .add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]),
                       critical=False)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        # Ties this certificate to the exact root key that signed it, which is
        # what lets a verifier build the chain unambiguously.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


# --------------------------------------------------------------------------
# Disk I/O
# --------------------------------------------------------------------------

def save_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    _write_secret(path, key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def save_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_root() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = serialization.load_pem_private_key(CA_KEY.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    return key, cert


def describe(path: Path, label: str) -> None:
    """Print the interesting fields of a certificate already on disk."""
    if not path.exists():
        print(f"{label}: (not present)")
        return
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    print(f"{label}: {path}")
    print(f"  subject      : {cert.subject.rfc4514_string()}")
    print(f"  issuer       : {cert.issuer.rfc4514_string()}")
    print(f"  valid from   : {cert.not_valid_before_utc:%Y-%m-%d %H:%M UTC}")
    print(f"  valid until  : {cert.not_valid_after_utc:%Y-%m-%d %H:%M UTC}")
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        parts = [f"DNS:{n}" for n in san.get_values_for_type(x509.DNSName)]
        parts += [f"IP:{i}" for i in san.get_values_for_type(x509.IPAddress)]
        print(f"  SAN          : {', '.join(parts)}")
    except x509.ExtensionNotFound:
        print("  SAN          : (none)")
    print(f"  SHA-256      : {fingerprint(cert)}")


# --------------------------------------------------------------------------
# Keeping the client's embedded trust anchor in step with the root
# --------------------------------------------------------------------------

def sync_client_root(enabled: bool) -> bool:
    """
    Make client/pki/demo-ca.crt equal to pki/ca.crt.

    Returns True when the client copy was CHANGED, because that is the case in
    which the client must be rebuilt -- the certificate is compiled into the
    binary as a Qt resource, so editing the file on disk changes nothing until
    the resource is recompiled.

    Only the public certificate is ever copied. ca.key stays in pki/ and is
    never written anywhere else.
    """
    if not CA_CERT.exists():
        return False

    new = CA_CERT.read_bytes()

    if not enabled:
        print("\n  --no-install-client-root given: client/pki/demo-ca.crt was NOT")
        print("  updated. If the root changed, copy it yourself and rebuild:")
        print("      cp pki/ca.crt client/pki/demo-ca.crt")
        return False

    current = CLIENT_ROOT.read_bytes() if CLIENT_ROOT.exists() else None
    if current == new:
        print(f"\n  client trust anchor already current: {CLIENT_ROOT}")
        return False

    CLIENT_ROOT.parent.mkdir(parents=True, exist_ok=True)
    CLIENT_ROOT.write_bytes(new)

    verb = "updated" if current is not None else "installed"
    print(f"\n  client trust anchor {verb}: {CLIENT_ROOT}")
    print("  " + "-" * 66)
    print("  REBUILD THE CLIENT. The root is compiled in as a Qt resource")
    print("  (client/pki.qrc -> :/pki/demo-ca.crt), so a running or already-built")
    print("  binary still carries the OLD root and will reject this relay's")
    print("  certificate with a verification error that looks like a bug.")
    print("  Rebuild both targets you use: desktop and Android.")
    print("  " + "-" * 66)
    return True


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate the ChatE2EE lab certificate authority.")
    ap.add_argument("--leaf-only", action="store_true",
                    help="reuse the existing root; re-issue only the relay leaf")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing root CA (invalidates every client "
                         "that embedded the old one)")
    ap.add_argument("--ip", action="append", default=[],
                    help="extra IP address to include in the leaf SAN (repeatable)")
    ap.add_argument("--dns", action="append", default=[],
                    help="extra DNS name to include in the leaf SAN (repeatable)")
    ap.add_argument("--show", action="store_true",
                    help="print what is already on disk and exit")
    ap.add_argument("--no-install-client-root", action="store_true",
                    help="do not copy the public root to client/pki/demo-ca.crt "
                         "(the copy is normally kept in step automatically, "
                         "because a mismatch fails the TLS tests)")
    args = ap.parse_args()

    if args.show:
        describe(CA_CERT, "Root CA")
        print()
        describe(LEAF_CERT, "Relay leaf")
        return 0

    PKI_DIR.mkdir(parents=True, exist_ok=True)

    # ---- Root -----------------------------------------------------------
    root_exists = CA_CERT.exists() and CA_KEY.exists()

    if root_exists and not args.force and not args.leaf_only:
        print("Root CA already exists -- keeping it (this is almost always what")
        print("you want, because the client embeds it). Re-issuing the leaf only.")
        print("Use --force to deliberately replace the root.")
        args.leaf_only = True

    if args.leaf_only and not root_exists:
        print("ERROR: --leaf-only was given but no root CA exists yet.")
        print("Run the script with no arguments first.")
        return 1

    if args.leaf_only:
        ca_key, ca_cert = load_root()
        print(f"Using existing root CA: {CA_CERT}")
    else:
        print("Creating root CA...")
        ca_key, ca_cert = create_root()
        save_cert(CA_CERT, ca_cert)
        save_key(CA_KEY, ca_key)
        print(f"  wrote {CA_CERT}")
        print(f"  wrote {CA_KEY}   <-- SECRET")

    # ---- Leaf -----------------------------------------------------------
    san, summary = build_san_list(args.ip, args.dns)
    print("\nIssuing relay certificate for:")
    for entry in summary:
        print(f"  {entry}")

    leaf_key, leaf_cert = create_leaf(ca_key, ca_cert, san)
    save_cert(LEAF_CERT, leaf_cert)
    save_key(LEAF_KEY, leaf_key)
    print(f"\n  wrote {LEAF_CERT}")
    print(f"  wrote {LEAF_KEY}   <-- SECRET")

    # ---- Report ---------------------------------------------------------
    print("\n" + "=" * 68)
    print("Root CA SHA-256 fingerprint (this is the trust anchor):")
    print("  " + fingerprint(ca_cert))
    print("Relay leaf SHA-256 fingerprint:")
    print("  " + fingerprint(leaf_cert))
    print("=" * 68)

    # Keep the client's compiled-in anchor equal to the root we just used.
    # Done here, after both certificates exist, so the message about rebuilding
    # appears next to the fingerprints it refers to.
    client_changed = sync_client_root(not args.no_install_client_root)
    print("""
NEXT STEPS

  1. Rebuild the client IF the line above said the trust anchor was
     installed or updated. The root is compiled in, so a rebuild is what
     actually delivers it. Re-issuing only the LEAF (--leaf-only) never
     needs a rebuild, because the client trusts the root, not the leaf.

  2. Start the relay with the lab certificate:

         python server/server.py --demo-tls

  3. Connect the client to  wss://localhost:8765  (desktop) or
     wss://<your-LAN-IP>:8765  (phone on the same Wi-Fi).

SECURITY NOTE

  pki/ca.key is the key that can mint certificates this application will
  trust. Keep it on this machine, never commit it, and never put it in a
  zip you send to anyone -- including me. The .gitignore added alongside
  this script already excludes the whole pki/ directory.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
