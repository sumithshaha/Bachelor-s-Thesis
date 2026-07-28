"""
Streaming file encryption for the chat application.

For chat messages we use AES-256-GCM with one nonce per message - that is fine
because each message is encrypted as a single, complete unit. Files are
different: they are encrypted in chunks so the whole file never has to sit in
memory at once, and that introduces a problem AES-GCM does not solve well. The
nonce in AES-GCM must never repeat under the same key, and once you are
encrypting many chunks under one key the bookkeeping to keep nonces unique
becomes error-prone. Reusing a nonce even once is catastrophic - it leaks the
authentication subkey and likely the plaintext too.

Libsodium provides a primitive built for exactly this case:
crypto_secretstream_xchacha20poly1305. It encrypts a sequence of chunks under a
single key, manages the nonces internally, authenticates each chunk
independently, and detects out-of-order chunks or truncation. The last chunk is
tagged TAG_FINAL so the receiver can tell the stream ended cleanly and was not
cut short by an attacker. We use the same 32-byte key we already derive from
X25519 + HKDF-SHA256, just with a file-specific HKDF info string so the file
key is bound to this file and direction.

This module is the Python reference; the Qt/C++ client calls the corresponding
libsodium functions and must produce byte-identical output to interoperate.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_KEYBYTES,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_state,
)


# Chunk size used by both ends. 64 KiB is a deliberate compromise: small enough
# that a phone never holds much in memory and the progress bar moves smoothly,
# large enough that the per-chunk overhead (17 bytes of authentication tag plus
# the WebSocket frame header) is negligible. Both client and server must agree.
CHUNK_SIZE = 64 * 1024

# A hard cap on file size in this build. 50 MB covers high-resolution images,
# PDFs, and short videos while keeping memory and transfer time bounded on
# mobile devices. Documented in the thesis as a design choice, not a limitation
# of the protocol itself - secretstream itself imposes no practical limit.
MAX_FILE_BYTES = 50 * 1024 * 1024

# Sizes that the protocol depends on, re-exported for clarity.
KEY_BYTES = crypto_secretstream_xchacha20poly1305_KEYBYTES        # 32
HEADER_BYTES = crypto_secretstream_xchacha20poly1305_HEADERBYTES  # 24


def derive_file_key(shared_secret: bytes, msg_id: str) -> bytes:
    """Derive the symmetric key for one file from the X25519 shared secret.

    The info string ties the key to this specific file id, so even if two users
    share the same long-term X25519 shared secret across many files, each file
    transfer uses a distinct key. This costs nothing - HKDF is cheap - and it
    means a compromise of one file's key reveals nothing about the others.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=None,
        info=f"tamk-chat-file-v1|{msg_id}".encode("utf-8"),
    ).derive(shared_secret)


@dataclass
class FileMeta:
    """The plaintext metadata about a file transfer.

    On the wire the JSON envelope wraps an *encrypted* form of this so the
    server never learns the filename or MIME type - only the size, which is
    inevitably visible from the byte count, and the recipient, which the
    server needs in order to route.
    """
    msg_id: str
    filename: str
    mime: str
    size: int


def encrypt_file(
    plaintext_stream: BinaryIO,
    file_key: bytes,
    total_size: int,
) -> Iterator[Tuple[bytes, bool]]:
    """Encrypt a file as a stream of secretstream chunks.

    Yields (ciphertext_chunk, is_last) tuples. The caller is responsible for
    putting the secretstream header (returned via the first yield, with the
    sentinel value (header, False) where 'header' has len HEADER_BYTES) into
    the file_init JSON frame and sending each ciphertext chunk as a binary
    WebSocket frame.

    The first yielded value is special: it is the secretstream header bytes,
    with is_last=False but ciphertext that is exactly HEADER_BYTES long. The
    next iteration begins the actual chunks.
    """
    if len(file_key) != KEY_BYTES:
        raise ValueError(f"file_key must be {KEY_BYTES} bytes")
    if total_size > MAX_FILE_BYTES:
        raise ValueError(
            f"file too large: {total_size} > {MAX_FILE_BYTES}")

    state = crypto_secretstream_xchacha20poly1305_state()
    header = crypto_secretstream_xchacha20poly1305_init_push(state, file_key)
    yield (header, False)  # header is not a chunk; receiver consumes it first

    sent = 0
    while True:
        chunk = plaintext_stream.read(CHUNK_SIZE)
        sent += len(chunk)
        is_last = sent >= total_size or len(chunk) < CHUNK_SIZE
        tag = (crypto_secretstream_xchacha20poly1305_TAG_FINAL
               if is_last
               else crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
        ciphertext = crypto_secretstream_xchacha20poly1305_push(
            state, chunk, None, tag)
        yield (ciphertext, is_last)
        if is_last:
            return


def decrypt_file(
    header: bytes,
    ciphertext_chunks: Iterator[bytes],
    file_key: bytes,
    output_stream: BinaryIO,
) -> int:
    """Decrypt a secretstream into output_stream.

    Returns the number of plaintext bytes written. Raises if any chunk fails
    authentication or if the stream ends without a TAG_FINAL chunk - the
    latter means the file was truncated, which is exactly the attack
    secretstream is designed to detect.
    """
    if len(file_key) != KEY_BYTES:
        raise ValueError(f"file_key must be {KEY_BYTES} bytes")
    if len(header) != HEADER_BYTES:
        raise ValueError(f"header must be {HEADER_BYTES} bytes")

    state = crypto_secretstream_xchacha20poly1305_state()
    crypto_secretstream_xchacha20poly1305_init_pull(state, header, file_key)

    written = 0
    saw_final = False
    for ct in ciphertext_chunks:
        plaintext, tag = crypto_secretstream_xchacha20poly1305_pull(
            state, ct, None)
        output_stream.write(plaintext)
        written += len(plaintext)
        if tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL:
            saw_final = True
            break

    if not saw_final:
        # The stream ended without a TAG_FINAL chunk - either the sender
        # forgot to mark the last chunk or, more worryingly, an attacker
        # truncated the stream. Either way we refuse to treat the file as
        # complete.
        raise ValueError("incomplete file stream: no TAG_FINAL chunk")

    return written


__all__ = [
    "CHUNK_SIZE",
    "MAX_FILE_BYTES",
    "KEY_BYTES",
    "HEADER_BYTES",
    "FileMeta",
    "derive_file_key",
    "encrypt_file",
    "decrypt_file",
]
