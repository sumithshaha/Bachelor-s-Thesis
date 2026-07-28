# Demonstrating real TLS after the server is gone

**Status:** implemented and tested. Requires one clean rebuild of the client.

This document explains how ChatE2EE demonstrates genuine, strictly-verified TLS
on a laptop and a phone, with no hosting, no public certificate authority, no
recurring cost and no expiry to manage — and why that demonstration is faithful
rather than a shortcut.

---

## 1. The problem

The relay has been running on a CSC cPouta virtual machine at
`86-50-230-46.sslip.io:8765` with a Let's Encrypt certificate. That VM is
scheduled for deletion on **14 November 2026**. After that date there is no
public host, no public DNS name, and therefore no way to obtain a
publicly-trusted certificate — a public CA will only issue for a domain you
demonstrably control.

The obvious fallback was already in the codebase: run the relay on `localhost`
with a self-signed certificate. But look at what that actually did.

```cpp
// The OLD behaviour, now removed:
if (isLocalhost) {
    // forgive SelfSignedCertificate, CertificateUntrusted, HostNameMismatch
    m_socket.ignoreSslErrors(expected);
}
```

That connection was encrypted, but **nothing verified who was on the other
end**. Authentication is half of what TLS is for, and it is the half that stops
an attacker in the network path from simply presenting their own certificate.
Demonstrating TLS with verification disabled and calling it a secure transport
would be the weakest claim in the whole project — and it would have become the
*only* claim available after 14 November.

## 2. The idea

A certificate authority is not a special kind of institution. **It is a key pair
whose public half some client has decided to trust in advance.**

Let's Encrypt is trusted by your laptop because Microsoft, Google or Mozilla put
its root certificate into the operating system's trust store. That is the entire
mechanism. There is no further magic.

So: generate a root key pair, put its public certificate into the application's
own trust store, and sign the relay's certificate with it. The client then does
completely ordinary, completely strict verification:

- it builds the chain from the relay's leaf certificate up to the root;
- it checks the signature at each step;
- it checks that both certificates are within their validity window;
- it checks that the hostname it dialled appears in the leaf's
  `SubjectAlternativeName`;
- and if **any** of that fails, the connection is refused.

The protocol behaviour, the chain building, the hostname matching and the
failure modes are identical to the Let's Encrypt case. The only thing that
differs is the provenance of the trust anchor.

### What this is not

It would be dishonest to claim more than the design delivers, so, explicitly:

- This root is trusted **only by this application**. It is not installed into
  the operating system trust store and must not be.
- It grants **no authority over anything on the internet**. The client scopes it
  to loopback and local-network addresses (see §5).
- It is not a substitute for a public CA in a real deployment, where users
  cannot be expected to obtain your root out of band.

What it *is*: a correct, single-purpose PKI that exercises the real TLS stack
end to end. For demonstrating and testing transport security, that is precisely
equivalent.

---

## 3. What was built

| File | Purpose |
|---|---|
| `tools/make_demo_pki.py` | Generates the root CA and the relay leaf certificate. |
| `server/server.py` | New `--demo-tls` flag and `resolve_tls_paths()`. |
| `client/src/chatclient.cpp` / `.h` | Trust anchor, strict verification, TLS evidence. |
| `client/pki.qrc`, `client/pki/demo-ca.crt` | Compiles the root into the binary. |
| `client/CMakeLists.txt` | Optional resource hook for the above. |
| `tests/test_real_tls.py` | Ten tests over real handshakes, including attack cases. |
| `.gitignore` | Keeps `pki/` and every private key out of the repository. |

### Certificate parameters

| | Root CA | Relay leaf |
|---|---|---|
| Key | RSA-3072 | RSA-2048 |
| Validity | 20 years | 10 years |
| `basicConstraints` | `CA:TRUE, pathlen:0` | `CA:FALSE` |
| `keyUsage` | `keyCertSign`, `cRLSign` | `digitalSignature`, `keyEncipherment` |
| `extendedKeyUsage` | — | `serverAuth` only |
| SAN | — | `localhost`, `127.0.0.1`, `::1`, LAN IPs, `sslip.io` names |

`pathlen:0` means the root may sign end-entity certificates but **not** further
CAs — the narrowest authority that still works. RSA rather than an elliptic
curve purely for interoperability: Qt on Windows may use either the OpenSSL or
the Schannel backend depending on what is installed, and RSA is accepted without
argument by all of them.

Ten-year leaves are longer than a public CA would ever issue (the CA/Browser
Forum caps at ~398 days, and browsers enforce it). Qt, OpenSSL and Python's
`ssl` do not enforce that limit, so this is safe here — and it is a deliberate
trade: the demonstration must keep working unattended for years. Re-issuing a
leaf is one command if you would rather keep them short.

---

## 4. How to use it

### First time (once)

```bash
# 1. Generate the certificate authority. This also installs the PUBLIC root
#    at client/pki/demo-ca.crt, so it gets compiled into the binary.
python tools/make_demo_pki.py

# 2. Clean rebuild the client, for BOTH targets you use (Windows MinGW and
#    Android arm64-v8a). The root is a compiled-in Qt resource, so an
#    existing binary still carries the previous one.
```

The generator reports which of the two things it did:

```
client trust anchor installed: .../client/pki/demo-ca.crt   <- first run
client trust anchor updated:   .../client/pki/demo-ca.crt   <- root replaced, REBUILD
client trust anchor already current: ...                    <- nothing to do
```

Only *installed* and *updated* require a rebuild. Pass
`--no-install-client-root` if you want to manage the copy yourself.

### Every time you demonstrate

```bash
# Start the relay with the lab certificate:
python server/server.py --demo-tls
```

Then connect the client to `wss://localhost:8765`.

### From the phone, over Wi-Fi

The phone and the laptop must be on the same network. Find the laptop's LAN
address, re-issue the leaf to cover it, and open the firewall:

```bash
# Windows: find the address
ipconfig                      # look for IPv4 Address, e.g. 192.168.1.42

# Re-issue the leaf for it (the ROOT is untouched, so NO client rebuild)
python tools/make_demo_pki.py --leaf-only --ip 192.168.1.42

# Allow inbound 8765 through Windows Firewall (run as Administrator, once)
netsh advfirewall firewall add rule name="ChatE2EE relay" ^
      dir=in action=allow protocol=TCP localport=8765
```

On the phone, connect to `wss://192.168.1.42:8765`.

This is the key ergonomic property of the design: **the client trusts the root,
not the leaf.** Your DHCP address changes every time you join a different
network, and re-issuing the leaf takes one command and no rebuild.

If the laptop has internet at the time, `wss://192-168-1-42.sslip.io:8765` also
works — `sslip.io` is a free public DNS service that resolves any address
encoded in the hostname straight back to that address. The generator adds those
names to the SAN automatically. It is a convenience only; the IP SANs make the
whole thing work with no DNS at all, which is why the offline case is fully
covered.

### Checking what you got

The client publishes a `tlsSummary` property showing the negotiated protocol,
cipher suite, certificate issuer, active trust anchor, certificate fingerprint
and Qt TLS backend. You can also check from the command line:

```bash
openssl s_client -connect localhost:8765 -CAfile pki/ca.crt -servername localhost
```

Look for `Verify return code: 0 (ok)`. During development this reported TLS 1.3
with `TLS_AES_256_GCM_SHA384`.

---

## 5. How the client scopes the anchor

Adding a private root to the trust store would be careless if it applied
everywhere: whoever holds the root key could then mint a certificate for any
public hostname and this client would accept it. So the anchor is scoped by
destination.

`ChatClient::isLabHost()` returns true only for:

- `localhost` and any loopback address (`127.0.0.0/8`, `::1`)
- RFC 1918 private ranges: `10/8`, `172.16/12`, `192.168/16`
- link-local: `169.254/16`, `fe80::/10`
- IPv6 unique-local: `fc00::/7`

Everything else — including `86-50-230-46.sslip.io` and any public IP — is
validated against the system trust store **alone**. The masks are written out
explicitly rather than using `QHostAddress::isPrivateUse()`, both because that
method only exists from Qt 6.6 (the project declares a 6.5 minimum) and because
a trust decision should be auditable at a glance.

All 27 boundary cases were checked, including the addresses immediately either
side of each private range (`172.15.0.1` / `172.32.0.1`, `192.167.1.1` /
`192.169.1.1`, `9.255.255.255` / `11.0.0.1`).

### `onSslErrors` no longer forgives anything

With a working CA there is no longer any legitimate reason for a demo
connection to produce certificate errors. So reaching that slot now carries real
information — a mis-issued certificate, a wrong hostname, an expired
certificate, or genuine interception — and the connection is refused with the
reason surfaced to the user. The `isLocalhost` exception is gone.

---

## 6. What the tests prove

`tests/test_real_tls.py` runs the project's own relay (`ChatServer`) behind the
project's own TLS setup (`make_ssl_context`) over a real socket. Nothing is
mocked and nothing is ignored.

The important point is that a *working* TLS connection looks identical whether
verification is on or off. The difference is only visible in what happens when
something is wrong — so most of the assertions are failure cases.

| Test | What it establishes |
|---|---|
| `test_strict_verification_succeeds_against_lab_root` | The connection completes with `CERT_REQUIRED` and hostname checking on. |
| `test_negotiated_parameters_are_modern` | TLS 1.2/1.3, an AEAD cipher, ≥128-bit, and the peer really is the relay leaf. |
| `test_certificate_covers_localhost_in_san` | The positive test passes for the right reason (SAN, not Common Name). |
| `test_client_without_the_lab_root_is_rejected` | **Control.** Verification is genuinely on, not disabled somewhere. |
| `test_attacker_with_their_own_ca_is_rejected` | **The central assertion.** See below. |
| `test_hostname_mismatch_is_rejected` | Hostname verification is active — the exact check the old code suppressed. |
| `test_obsolete_tls_versions_are_refused` | The TLS 1.2 floor holds; no downgrade. |
| `test_root_is_a_constrained_ca` | Root is a CA and cannot mint sub-CAs. |
| `test_leaf_is_not_a_ca_and_is_server_auth_only` | Leaf cannot sign; `serverAuth` only. |
| `test_leaf_chains_to_the_root_and_is_in_date` | Issuer linkage and signature verified independently of any TLS stack. |

**The central assertion**, in plain terms: the test builds a complete second
certificate authority, uses it to sign a certificate that correctly names
`localhost`, is properly formed and is in date — and serves it. The only thing
wrong with that certificate is that it chains to a root the client does not
trust. The client **refuses the connection**.

That is the whole security argument. Impersonating the relay requires the lab
root's private key, not merely the ability to generate certificates.

Result: **194 passed** (the previous 184 plus these 10), from a clean checkout,
via `bash run_tests.sh`. The suite now generates the PKI automatically on first
run, so the TLS tests never silently skip.

### Relationship to the end-to-end encryption

TLS and the Double Ratchet protect different things, and it is worth being
precise about the layering:

- **TLS** protects the hop between client and relay. It stops a network
  observer, and it authenticates the relay.
- **The Double Ratchet** protects message content from *the relay itself*.

The red-team harness (`tests/e2ee_redteam.py`) already demonstrates that even a
fully malicious relay learns nothing from message content. So TLS here is
defence in depth rather than the primary confidentiality mechanism — which is
also why a lab CA is a perfectly adequate demonstration vehicle. Nothing about
the security of message content depends on which CA signed the transport.

---

## 7. Timeline

**Now until 14 November 2026** — nothing changes. The cPouta relay keeps working
with its Let's Encrypt certificate, validated against the system trust store
exactly as before. The lab CA sits alongside it, used only for local and LAN
connections. You can demonstrate either.

**Do before 14 November:**

1. Generate the CA and rebuild the client once, so the root is embedded.
2. Run one full demonstration against `wss://localhost:8765` and one from the
   phone over Wi-Fi, and confirm both connect with verification on.
3. Capture the evidence you want for the thesis: the `tlsSummary` panel, the
   `openssl s_client` output showing `Verify return code: 0 (ok)`, and the
   passing test run.
4. Rotate the cPouta TLS key — see §8.

**After 14 November** — run `python server/server.py --demo-tls` on your laptop
and point the client at `wss://localhost:8765` or your LAN address. That is the
entire migration. Nothing expires until 2036 (leaf) and 2046 (root).

---

## 8. Security notes

**`pki/ca.key` is the most sensitive file in the project.** Anyone holding it
can mint certificates that any build of this client embedding the matching root
will trust. It stays on the machine that issues certificates. It is excluded by
`.gitignore`, and it must never go into a zip — including one sent to me.

**`server/server.key` has repeatedly appeared in uploaded archives.** It is
present again in the current upload. That is the cPouta relay's live TLS private
key. Treat it as compromised: rotate it on the VM and reissue the certificate
rather than assuming nobody noticed. This costs nothing and takes a few minutes
with `certbot`.

**Only the public root is embedded in the client.** `client/pki/demo-ca.crt`
contains the certificate, never the key. It is compiled into the binary rather
than read from a file beside the executable so it cannot be swapped by dropping
a different file into the application directory.

---

## 9. Troubleshooting

**"The certificate is self-signed, and untrusted"**
The client has no embedded root. Check that `client/pki/demo-ca.crt` exists,
re-run CMake (it prints `Lab CA embedded from client/pki/demo-ca.crt` when the
resource is picked up), and do a clean rebuild.

**"The host name did not match any of the valid hosts"**
The leaf does not cover the address you dialled. Re-issue it:
`python tools/make_demo_pki.py --leaf-only --ip <the address>`.

**Phone cannot reach the relay at all (timeout, not a TLS error)**
Network, not certificates. Confirm both devices are on the same Wi-Fi, that the
relay is bound to `0.0.0.0` (the default), and that the firewall rule from §4
exists. Some networks — university and guest Wi-Fi especially — isolate clients
from each other; a phone hotspot with the laptop joined to it is the reliable
fallback.

**Android: "No functional TLS backend was found"**
Qt does not ship OpenSSL for Android. `CMakeLists.txt` already includes
`android_openssl.cmake`; if that path is wrong the build prints a warning. Re-run
*Set Up SDK* in Qt Creator or hard-code the path.

**Windows: verification fails but the certificate looks right**
Check which TLS backend Qt chose — the `tlsSummary` panel reports it. Both
OpenSSL and Schannel honour an added CA, but if you see something unexpected
there, that is the first thing to investigate.

**Re-issuing did not help**
Confirm the relay actually reloaded: it must be restarted after the leaf
changes. `python tools/make_demo_pki.py --show` prints what is currently on disk.

---

## 10. A note on the thesis text

This document is repository documentation. You are welcome to draw on the
reasoning in §2 and §6 when you write, but the **Introduction, Discussion and
Abstract must be your own writing** under TAMK's maturity test rules. The
material here is deliberately explanatory rather than thesis-shaped for that
reason.
