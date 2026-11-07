"""Shared cryptography: password key derivation and chunked authenticated file encryption.

Primitives (all from the `cryptography` package):
  - scrypt            password -> master key (memory-hard, slows down guessing)
  - HKDF-SHA256       master key -> independent sub-keys
  - AES-256-GCM       authenticated encryption

Encrypted blob format (one per file):
    MAGIC(4) | VERSION(1) | BLOB_ID(16)          header, also used as AAD
    then repeated:  LEN(4, big-endian) | CIPHERTEXT(LEN)
Each chunk's nonce is an 11-byte counter + 1 "last chunk" flag byte, so chunks
cannot be reordered, dropped, or truncated without decryption failing.
"""

from __future__ import annotations

import hashlib
import os
import struct
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from safedatatransfer.common.hashing import CHUNK_SIZE

BLOB_MAGIC = b"SDTB"
BLOB_VERSION = 1
BLOB_ID_LEN = 16
HEADER_LEN = len(BLOB_MAGIC) + 1 + BLOB_ID_LEN
MAX_CIPHER_CHUNK = CHUNK_SIZE + 16

MIN_PASSWORD_LEN = 12

_COMMON = {"password", "passwort", "qwertz", "qwerty", "123456", "letmein", "iloveyou",
           "admin", "welcome", "secret", "geheim", "monkey", "dragon", "abc123", "usbstick"}


def normalize_password(pw: str) -> str:
    """NFC form: 'é' typed as one character or as 'e' + accent gives the same key."""
    return unicodedata.normalize("NFC", pw)


def password_problem(pw: str) -> str | None:
    """Why a new password is too weak, or None. A long passphrase of words is best."""
    if len(pw) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters (a few words work well)."
    if len(set(pw)) < 6:
        return "Password repeats too few different characters."
    low = pw.lower()
    if any(w in low for w in _COMMON) and len(pw) < 20:
        return "Password contains a very common word; make it longer or use other words."
    if low in ("0123456789abcdefghijklmnopqrstuvwxyz"[:len(low)], "1234567890"[:len(low)]):
        return "Password is a simple sequence."
    return None


class DecryptionError(Exception):
    """Wrong password, or data was modified/corrupted."""


@dataclass(frozen=True)
class ScryptParams:
    salt: bytes
    n: int = 2**17  # ~128 MiB of memory per guess
    r: int = 8
    p: int = 1


def derive_master_key(password: str, params: ScryptParams) -> bytes:
    kdf = Scrypt(salt=params.salt, length=32, n=params.n, r=params.r, p=params.p)
    return kdf.derive(password.encode("utf-8"))


def hkdf(key: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key)


def _chunk_nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def encrypt_stream(fin: BinaryIO, fout: BinaryIO, key: bytes, blob_id: bytes) -> str:
    """Encrypt fin into fout. Returns SHA-256 of the plaintext."""
    aes = AESGCM(key)
    header = BLOB_MAGIC + bytes([BLOB_VERSION]) + blob_id
    fout.write(header)
    h = hashlib.sha256()
    counter = 0
    chunk = fin.read(CHUNK_SIZE)
    while True:
        nxt = fin.read(CHUNK_SIZE) if chunk else b""
        last = not nxt
        h.update(chunk)
        ct = aes.encrypt(_chunk_nonce(counter, last), chunk, header)
        fout.write(struct.pack(">I", len(ct)) + ct)
        if last:
            break
        chunk, counter = nxt, counter + 1
    return h.hexdigest()


def decrypt_stream(fin: BinaryIO, fout: BinaryIO | None, key: bytes) -> str:
    """Decrypt fin into fout (or just verify when fout is None). Returns plaintext SHA-256."""
    aes = AESGCM(key)
    header = fin.read(HEADER_LEN)
    if len(header) != HEADER_LEN or not header.startswith(BLOB_MAGIC) or header[4] != BLOB_VERSION:
        raise DecryptionError("Not an sdt encrypted blob.")
    h = hashlib.sha256()
    counter = 0
    while True:
        raw_len = fin.read(4)
        if len(raw_len) != 4:
            raise DecryptionError("Blob is truncated.")
        (n,) = struct.unpack(">I", raw_len)
        if n > MAX_CIPHER_CHUNK:
            raise DecryptionError("Blob chunk too large.")
        ct = fin.read(n)
        if len(ct) != n:
            raise DecryptionError("Blob is truncated.")
        last = fin.peek(1)[:1] == b"" if hasattr(fin, "peek") else _at_eof(fin)
        try:
            pt = aes.decrypt(_chunk_nonce(counter, last), ct, header)
        except InvalidTag as e:
            raise DecryptionError("Wrong password or the data was modified.") from e
        h.update(pt)
        if fout is not None:
            fout.write(pt)
        if last:
            return h.hexdigest()
        counter += 1


def _at_eof(f: BinaryIO) -> bool:
    pos = f.tell()
    f.seek(0, os.SEEK_END)
    end = f.tell()
    f.seek(pos)
    return pos == end


def blob_id_from_file(path: Path) -> bytes:
    with open(path, "rb") as f:
        header = f.read(HEADER_LEN)
    return header[5:]


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, data: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(data[:12], data[12:], aad)
    except InvalidTag as e:
        raise DecryptionError("Wrong password or the data was modified.") from e
