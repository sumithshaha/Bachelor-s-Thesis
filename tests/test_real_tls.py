"""
test_real_tls.py -- proof that the lab certificate authority gives a REAL,
strictly-verified TLS channel, not a demonstration with the checks turned off.

WHY THIS TEST MATTERS FOR THE THESIS
------------------------------------
A chat application can claim "the transport is TLS" and mean two completely
different things:

  (a) the bytes are encrypted, but the client accepts whatever certificate it is
      handed -- so anyone able to sit in the path can present their own
      certificate and read everything; or
  (b) the bytes are encrypted AND the client cryptographically verifies that it
      is talking to the intended server, refusing to continue otherwise.

Only (b) is TLS as it is actually meant to be deployed. The difference is not
visible by looking at a working connection -- both look identical when nothing
is attacking them. It is only visible in what happens when something IS wrong.
So this module deliberately spends most of its assertions on failure cases.

Every test below runs the project's OWN relay (server.ChatServer) behind the
project's OWN TLS setup (server.make_ssl_context), over a real socket, with a
real handshake. Nothing is mocked and nothing is ignored.

Run with:  pytest -v tests/test_real_tls.py
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import ipaddress
import ssl
import sys
import warnings
import tempfile
from pathlib import Path

import pytest
import websockets
from websockets.asyncio.server import serve

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from server import ChatServer, Storage, make_ssl_context  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


PKI_DIR = REPO_ROOT / "pki"
CA_CERT = PKI_DIR / "ca.crt"
LEAF_CERT = PKI_DIR / "server.crt"
LEAF_KEY = PKI_DIR / "server.key"

# Ports chosen to sit clear of the ones the other async tests bind (8791, 8799).
PORT_GOOD = 8811
PORT_ROGUE = 8812

pytestmark = pytest.mark.skipif(
    not (CA_CERT.exists() and LEAF_CERT.exists() and LEAF_KEY.exists()),
    reason="lab PKI not generated yet -- run: python tools/make_demo_pki.py",
)


# --------------------------------------------------------------------------
# Fixtures and helpers
# --------------------------------------------------------------------------

def _client_ctx_trusting(cafile: Path) -> ssl.SSLContext:
    """
    Build a client context configured the way the Qt client is configured:
    verification REQUIRED, hostname checking ON, and one extra trust anchor.

    This mirrors ChatClient::sslConfigurationFor() exactly. If this context can
    connect, the Qt client can; if it refuses, the Qt client refuses.
    """
    ctx = ssl.create_default_context(cafile=str(cafile))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _client_ctx_system_only() -> ssl.SSLContext:
    """A client that trusts only the public CAs -- i.e. has never seen our root."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _make_rogue_pki(tmp: Path) -> tuple[Path, Path]:
    """
    Create an entirely separate certificate authority and use it to sign a
    certificate that CLAIMS to be 'localhost'.

    This is the attacker model that matters. A network attacker who can redirect
    the connection does not need to break any cryptography -- they only need the
    client to accept a certificate they generated. This function builds exactly
    such a certificate: it is well-formed, correctly signed, in-date, and names
    the right host. The ONLY thing wrong with it is that it chains to a root the
    client does not trust. A correctly-configured client must refuse it.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Root CA")])
    now = _dt.datetime.now(_dt.timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    crt = tmp / "rogue.crt"
    key = tmp / "rogue.key"
    crt.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return crt, key


class _Relay:
    """Runs the project's real relay behind a real TLS listener."""

    def __init__(self, certfile: Path, keyfile: Path, port: int):
        self.certfile, self.keyfile, self.port = certfile, keyfile, port
        self._server = None
        self._tmpdir = None

    async def __aenter__(self):
        # ignore_cleanup_errors: on Windows a directory can briefly remain
        # locked after the handle is closed. The database IS closed in
        # __aexit__ below -- this only stops a slow filesystem from turning
        # teardown into a test failure.
        self._tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._storage = Storage(str(Path(self._tmpdir.name) / "tls_test.db"))
        chat = ChatServer(self._storage)
        ctx = make_ssl_context(str(self.certfile), str(self.keyfile))
        self._server = await serve(chat.handle, "localhost", self.port, ssl=ctx)
        return self

    async def __aexit__(self, *exc):
        self._server.close()
        await self._server.wait_closed()
        # Close the database BEFORE removing the directory that contains it.
        # Getting this order wrong is what produced WinError 32.
        self._storage.close()
        self._tmpdir.cleanup()


# --------------------------------------------------------------------------
# 1. The positive case: strict verification SUCCEEDS against the lab root
# --------------------------------------------------------------------------

async def test_strict_verification_succeeds_against_lab_root():
    """
    The connection completes with hostname checking on and verification
    required. No error is ignored anywhere in this test.
    """
    async with _Relay(LEAF_CERT, LEAF_KEY, PORT_GOOD):
        ctx = _client_ctx_trusting(CA_CERT)
        async with websockets.connect(f"wss://localhost:{PORT_GOOD}", ssl=ctx) as ws:
            assert ws.protocol.state.name == "OPEN"


async def test_negotiated_parameters_are_modern():
    """
    Confirm the handshake actually negotiated a modern protocol and an AEAD
    cipher suite -- i.e. this is a current TLS channel, not a museum piece.
    """
    async with _Relay(LEAF_CERT, LEAF_KEY, PORT_GOOD):
        ctx = _client_ctx_trusting(CA_CERT)
        reader, writer = await asyncio.open_connection(
            "localhost", PORT_GOOD, ssl=ctx, server_hostname="localhost")
        sslobj = writer.get_extra_info("ssl_object")
        version = sslobj.version()
        cipher, proto, bits = sslobj.cipher()
        peer = sslobj.getpeercert()
        writer.close()
        await writer.wait_closed()

        assert version in ("TLSv1.2", "TLSv1.3"), f"unexpected protocol {version}"
        assert bits >= 128
        assert "GCM" in cipher or "CHACHA20" in cipher, f"not an AEAD suite: {cipher}"
        # The certificate the client verified really is our relay leaf.
        subject = {k: v for rdn in peer["subject"] for k, v in rdn}
        assert subject["commonName"] == "ChatE2EE Relay"


async def test_certificate_covers_localhost_in_san():
    """
    Hostname verification is driven by SubjectAlternativeName, never by the
    Common Name in modern TLS. Assert the SAN really carries the names, so the
    positive test above is passing for the right reason.
    """
    cert = x509.load_pem_x509_certificate(LEAF_CERT.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    assert "localhost" in dns
    assert "127.0.0.1" in ips


# --------------------------------------------------------------------------
# 2. The negative cases: verification must FAIL when it should
# --------------------------------------------------------------------------

async def test_client_without_the_lab_root_is_rejected():
    """
    A client that has not been given the lab root refuses the connection. This
    is the control: it shows the positive test passes because of the trust
    anchor, and not because verification is quietly disabled somewhere.
    """
    async with _Relay(LEAF_CERT, LEAF_KEY, PORT_GOOD):
        ctx = _client_ctx_system_only()
        with pytest.raises(ssl.SSLCertVerificationError):
            async with websockets.connect(f"wss://localhost:{PORT_GOOD}", ssl=ctx):
                pass


async def test_attacker_with_their_own_ca_is_rejected():
    """
    THE CENTRAL SECURITY ASSERTION.

    An attacker runs a relay presenting a valid, in-date certificate that names
    'localhost' correctly -- but signed by their own CA. The client trusting our
    lab root rejects it. Impersonating the relay therefore requires the lab root
    private key, not merely the ability to make certificates.
    """
    with tempfile.TemporaryDirectory() as tmp:
        rogue_crt, rogue_key = _make_rogue_pki(Path(tmp))
        async with _Relay(rogue_crt, rogue_key, PORT_ROGUE):
            ctx = _client_ctx_trusting(CA_CERT)
            with pytest.raises(ssl.SSLCertVerificationError):
                async with websockets.connect(f"wss://localhost:{PORT_ROGUE}", ssl=ctx):
                    pass


async def test_hostname_mismatch_is_rejected():
    """
    Even with the correct root and a genuine certificate, dialling a name the
    certificate does not cover must fail. This proves hostname verification is
    switched on -- the exact check the old ignoreSslErrors() path suppressed.
    """
    async with _Relay(LEAF_CERT, LEAF_KEY, PORT_GOOD):
        ctx = _client_ctx_trusting(CA_CERT)
        with pytest.raises(ssl.SSLCertVerificationError):
            await asyncio.open_connection(
                "localhost", PORT_GOOD, ssl=ctx,
                server_hostname="wrong-name.invalid")


async def test_obsolete_tls_versions_are_refused():
    """
    The relay sets a TLS 1.2 floor. A client that will speak nothing newer than
    TLS 1.1 cannot connect. Skipped where the local Python or OpenSSL no longer
    offers TLS 1.1 at all, in which case the point is moot anyway.

    THE EXCEPTION LIST MATTERS. Python currently emits

        DeprecationWarning: ssl.TLSVersion.TLSv1 is deprecated
        DeprecationWarning: ssl.TLSVersion.TLSv1_1 is deprecated

    which is the interpreter announcing that these enum members are on their way
    out. When they are finally removed, referring to them raises AttributeError,
    NOT ValueError or OSError -- so a guard listing only those two would let the
    test ERROR on a future Python instead of skipping. AttributeError is caught
    here for that reason. It is a small thing, but a suite that breaks on the
    next interpreter is a suite nobody can re-run to check the thesis.

    The warning itself is silenced locally because setting a deprecated value is
    exactly what this test intends to do; leaving it to surface would train the
    reader to ignore warnings, which is the opposite of useful.
    """
    async with _Relay(LEAF_CERT, LEAF_KEY, PORT_GOOD):
        ctx = _client_ctx_trusting(CA_CERT)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        except (AttributeError, ValueError, OSError):
            pytest.skip("this Python/OpenSSL no longer offers TLS 1.1 at all")

        with pytest.raises((ssl.SSLError, OSError)):
            await asyncio.open_connection(
                "localhost", PORT_GOOD, ssl=ctx, server_hostname="localhost")


# --------------------------------------------------------------------------
# 3. Structural checks on the PKI itself
# --------------------------------------------------------------------------

def test_root_is_a_constrained_ca():
    """The root must be marked as a CA, and must not be able to mint sub-CAs."""
    ca = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0


def test_leaf_is_not_a_ca_and_is_server_auth_only():
    """
    The relay certificate must not be usable to sign other certificates, and
    must be marked for server authentication only.
    """
    leaf = x509.load_pem_x509_certificate(LEAF_CERT.read_bytes())
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False

    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    oids = [o.dotted_string for o in eku]
    assert oids == ["1.3.6.1.5.5.7.3.1"]  # id-kp-serverAuth, and nothing else

    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is False


def test_leaf_chains_to_the_root_and_is_in_date():
    """Issuer linkage and validity window, checked independently of any TLS stack."""
    ca = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    leaf = x509.load_pem_x509_certificate(LEAF_CERT.read_bytes())

    assert leaf.issuer == ca.subject

    now = _dt.datetime.now(_dt.timezone.utc)
    for cert, label in ((ca, "root"), (leaf, "leaf")):
        assert cert.not_valid_before_utc <= now, f"{label} is not yet valid"
        assert cert.not_valid_after_utc > now, f"{label} has expired"

    # The signature on the leaf really was made by the root's private key.
    ca.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf.signature_hash_algorithm,
    )


# --------------------------------------------------------------------------
# 4. The trust anchor must actually reach the binary
# --------------------------------------------------------------------------
#
# A correct certificate is useless if the build cannot embed it. These tests
# exist because of a real build failure: the .qrc that carries the root
# certificate contained a doubled hyphen inside its XML comment, which the XML
# specification forbids. rcc parses .qrc files with a strict XML reader, so
# `rcc --list` failed and CMake configuration aborted with
# "The rcc list process failed for ... client/pki.qrc".
#
# That is a slow, confusing failure to diagnose from a CMake call stack, and it
# is trivially detectable here, so it is checked at test time instead.

import xml.etree.ElementTree as ET  # noqa: E402

CLIENT_DIR = REPO_ROOT / "client"


def _is_inside_build_tree(path: Path) -> bool:
    """True when this path lies inside build OUTPUT rather than source.

    WHY THIS EXISTS

    The .qrc checks below exist to catch a defect in a resource file we WROTE,
    before rcc rejects it at build time. Qt's own CMake integration also
    GENERATES .qrc files into the build directory -- `qt_add_qml_module`
    produces `<target>_qml_module_dir_map.qrc`, among others -- and those are
    build products, not sources.

    Scanning them is wrong in three separate ways:

      1. A file produced BY the build cannot protect the build. There is
         nothing to catch early; if it were malformed the build that wrote it
         would already have failed.
      2. It maps a DIRECTORY, by design -- a "dir map" -- so an is_file()
         assertion on its entries is false for a perfectly healthy project.
      3. It records absolute, machine-specific paths, so the result depends on
         one developer's directory layout and on whether a build happens to be
         present and current.

    Together those meant the suite went red exactly when the project was at its
    most complete: a clean checkout passed, and building the Windows client
    made `test_qrc_referenced_files_exist` fail with a path pointing into
    `client/build/Desktop_Debug/`. The check was reporting the state of the
    build directory, not the health of the source.

    Detection uses two independent signals so a build tree is recognised
    whether or not it has been configured yet:

      * CMakeCache.txt in an ancestor -- the definitive marker of a configured
        CMake build tree, wherever it was placed and whatever it is called.
      * a path component under client/ beginning with "build" -- the
        conventional layout (client/build/..., and Qt Creator's
        build-<project>-<kit> directories), which covers a tree that has been
        partially cleaned or not yet configured.

    Only the part of the path BELOW client/ is examined for the name test, so
    a directory called "build" somewhere above the repository cannot make the
    whole scan vanish.
    """
    for parent in path.parents:
        if (parent / "CMakeCache.txt").is_file():
            return True
        if parent == REPO_ROOT:
            break
    try:
        relative = path.relative_to(CLIENT_DIR)
    except ValueError:
        return False
    # DIRECTORY components only. Using every part would also match the file
    # name, so a hand-written resource legitimately called "buildinfo.qrc"
    # sitting in client/ would be mistaken for build output and skipped.
    return any(part.lower().startswith("build")
               for part in relative.parent.parts)


def _all_qrc_files() -> list[Path]:
    """Every .qrc we maintain by hand -- never one the build generated."""
    return sorted(q for q in CLIENT_DIR.rglob("*.qrc")
                  if not _is_inside_build_tree(q))


def _missing_entries(qrc: Path) -> list[str]:
    """Entries a .qrc lists that do not resolve to an existing file.

    Split out from the test so the rule can be exercised against a synthetic
    .qrc -- otherwise a check that silently stopped finding anything would
    still look green.
    """
    try:
        root = ET.parse(qrc).getroot()
    except ET.ParseError:
        return []          # reported by the well-formedness test instead
    missing = []
    for qresource in root.findall("qresource"):
        for entry in qresource.findall("file"):
            text = (entry.text or "").strip()
            if not (qrc.parent / text).resolve().is_file():
                missing.append(text)
    return missing


def test_every_qrc_is_well_formed_xml():
    """
    Every Qt resource file must parse as XML. This is exactly the check rcc
    performs, so a failure here is a build failure waiting to happen.
    """
    qrcs = _all_qrc_files()
    if not qrcs:
        pytest.skip("no .qrc files in client/")

    for qrc in qrcs:
        try:
            ET.parse(qrc)
        except ET.ParseError as exc:
            pytest.fail(
                f"{qrc.relative_to(REPO_ROOT)} is not well-formed XML: {exc}\n"
                "rcc will reject this and CMake configuration will fail with "
                "'The rcc list process failed'. A common cause is a doubled "
                "hyphen used as a prose dash inside an XML comment, which the "
                "XML specification does not allow."
            )


def test_no_doubled_hyphen_inside_qrc_comments():
    """
    Catch the specific defect directly, with a message that names the fix.

    Checking this separately from well-formedness means the diagnostic is
    precise: a generic 'invalid token at line 2' does not tell you that the
    problem is a dash in a comment.
    """
    for qrc in _all_qrc_files():
        text = qrc.read_text(encoding="utf-8", errors="replace")
        for block in text.split("<!--")[1:]:
            body = block.split("-->")[0]
            assert "--" not in body, (
                f"{qrc.relative_to(REPO_ROOT)} has a doubled hyphen inside an "
                f"XML comment. XML forbids this and rcc will refuse the file. "
                f"Rewrite the wording without it."
            )


def test_qrc_referenced_files_exist():
    """
    Every file a .qrc lists must exist relative to that .qrc, or rcc fails at
    build time with 'Cannot find file'.
    """
    for qrc in _all_qrc_files():
        missing = _missing_entries(qrc)
        assert not missing, (
            f"{qrc.relative_to(REPO_ROOT)} references {missing}, which do not "
            f"exist. rcc will fail at build time with 'Cannot find file'."
        )


def test_lab_root_is_embedded_and_is_the_current_root():
    """
    The certificate compiled into the client must be the SAME root the relay's
    leaf chains to. If these drift apart, every lab connection fails
    verification with an error that looks like a code bug but is not.
    """
    embedded = CLIENT_DIR / "pki" / "demo-ca.crt"
    if not embedded.exists():
        pytest.skip("client/pki/demo-ca.crt not installed yet")

    client_root = x509.load_pem_x509_certificate(embedded.read_bytes())
    issuing_root = x509.load_pem_x509_certificate(CA_CERT.read_bytes())

    assert client_root.fingerprint(hashes.SHA256()) == \
        issuing_root.fingerprint(hashes.SHA256()), (
            "client/pki/demo-ca.crt is a DIFFERENT root from pki/ca.crt. "
            "Copy pki/ca.crt to client/pki/demo-ca.crt and rebuild."
        )

    leaf = x509.load_pem_x509_certificate(LEAF_CERT.read_bytes())
    assert leaf.issuer == client_root.subject, (
        "the relay leaf was not issued by the root embedded in the client"
    )

# ==========================================================================
# The .qrc scan must look at SOURCE only -- and must still have teeth
#
# Building the Windows client made test_qrc_referenced_files_exist fail:
#
#   client\build\Desktop_Debug\ChatE2EE\appChatE2EE_qml_module_dir_map.qrc
#   references 'C:/.../client/build/Desktop_Debug/ChatE2EE', which does not exist.
#
# That file is generated by qt_add_qml_module, maps a directory rather than a
# file, and records an absolute path into the build tree. Checking it told us
# nothing about the source and turned the suite red for a healthy project.
#
# Excluding a whole category of file from a check is exactly the kind of change
# that can quietly disable it, so the tests below pin BOTH halves: build output
# is skipped, and the check still catches a genuinely missing source file.
# ==========================================================================

def test_source_qrc_files_are_still_found():
    """The exclusion must not empty the list.

    If it did, all three .qrc tests would pass vacuously and the defect they
    were written for -- a doubled hyphen in a comment, which stops CMake
    configuring -- would sail straight through.
    """
    found = _all_qrc_files()
    assert found, (
        "no source .qrc files found; the build-tree exclusion is too broad and "
        "the .qrc checks are now testing nothing")
    names = {q.name for q in found}
    assert {"icons.qrc", "pki.qrc"} <= names, (
        f"the hand-maintained .qrc files are missing from the scan: {names}")


def test_generated_qrc_inside_a_build_directory_is_excluded():
    """The exact path from the failure, plus the Qt Creator layout."""
    for relative in [
        "build/Desktop_Debug/ChatE2EE/appChatE2EE_qml_module_dir_map.qrc",
        "build/Desktop_Release/.rcc/generated.qrc",
        "build-ChatE2EE-Android_arm64_v8a-Debug/x.qrc",
    ]:
        assert _is_inside_build_tree(CLIENT_DIR / relative), (
            f"{relative} was treated as a source file")


def test_hand_written_qrc_files_are_not_excluded():
    """The name test must key on a path COMPONENT, not a substring.

    A resource file legitimately called something like 'buildinfo.qrc' sitting
    directly in client/ is source, not output.
    """
    for relative in ["icons.qrc", "pki.qrc", "qml/assets.qrc",
                     "buildinfo.qrc"]:
        assert not _is_inside_build_tree(CLIENT_DIR / relative), (
            f"{relative} was wrongly treated as build output")


def test_a_configured_cmake_tree_is_detected_by_its_cache(tmp_path):
    """CMakeCache.txt identifies a build tree whatever it is named."""
    tree = tmp_path / "out-of-source-dir"
    (tree / "nested").mkdir(parents=True)
    (tree / "CMakeCache.txt").write_text("# CMake cache\n", encoding="utf-8")
    assert _is_inside_build_tree(tree / "nested" / "generated.qrc")
    plain = tmp_path / "plain"
    plain.mkdir()
    assert not _is_inside_build_tree(plain / "hand_written.qrc")


def test_the_existence_check_still_catches_a_missing_file(tmp_path):
    """TEETH. A source .qrc naming a file that is not there must be caught."""
    qrc = tmp_path / "broken.qrc"
    qrc.write_text(
        "<RCC><qresource prefix='/'>"
        "<file>definitely_not_here.png</file>"
        "</qresource></RCC>", encoding="utf-8")
    assert _missing_entries(qrc) == ["definitely_not_here.png"], (
        "the existence check no longer detects a missing file")


def test_the_existence_check_accepts_a_file_that_is_present(tmp_path):
    """Control: no false positive on a correct .qrc."""
    (tmp_path / "real.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    qrc = tmp_path / "good.qrc"
    qrc.write_text(
        "<RCC><qresource prefix='/'><file>real.png</file></qresource></RCC>",
        encoding="utf-8")
    assert _missing_entries(qrc) == []


def test_a_directory_entry_would_still_be_reported_in_source(tmp_path):
    """A DIRECTORY named in a hand-written .qrc is a genuine mistake.

    Skipping generated dir-maps must not make the rule tolerant of a directory
    entry in a file we actually wrote -- rcc rejects that too.
    """
    (tmp_path / "a_directory").mkdir()
    qrc = tmp_path / "dir.qrc"
    qrc.write_text(
        "<RCC><qresource prefix='/'><file>a_directory</file></qresource></RCC>",
        encoding="utf-8")
    assert _missing_entries(qrc) == ["a_directory"]
