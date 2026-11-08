"""sdt-drop/1: authenticated, encrypted file transfer over any TCP socket.

Security comes from this layer, not from the link (Wi-Fi Direct or LAN):

1. The receiver shows a one-time code. The sender types it.
2. SPAKE2 (a password-authenticated key exchange) turns the code into a shared key.
   A network attacker learns nothing about the code and gets exactly one guess;
   the receiver stops after any failed attempt.
3. Both sides prove they derived the same key (HMAC key confirmation).
4. Everything afterwards — file names, sizes, contents — is AES-256-GCM encrypted,
   separate key per direction, counter nonces (no reordering/replay/truncation).
5. The receiver must accept the offer before any file is written, and every file's
   SHA-256 is verified before it is moved into place.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import struct
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from spake2 import SPAKE2_A, SPAKE2_B

from safedatatransfer.common import winfs
from safedatatransfer.common.crypto import hkdf
from safedatatransfer.common.text import clean_text  # noqa: F401  (re-exported)
from safedatatransfer.common.hashing import CHUNK_SIZE

PROTO = b"sdt-drop/1"
ID_SENDER = b"sdt-drop sender"
ID_RECEIVER = b"sdt-drop receiver"
TCP_PORT = 47802

MAX_HANDSHAKE_FRAME = 4096
# Data frames are at most CHUNK_SIZE; control frames (the file list) can be larger.
# Only used after the code was verified, so only the real peer can send big frames.
MAX_FRAME = 32 << 20
MAX_FILES = 100_000
T_JSON = b"J"
T_DATA = b"D"


class ProtocolError(Exception):
    pass


class WrongCode(ProtocolError):
    pass


class Rejected(ProtocolError):
    pass


# ---------------------------------------------------------------- codes

def new_code() -> str:
    """6-digit one-time code shown as '482-913'. Safe because SPAKE2 allows one online guess."""
    n = secrets.randbelow(10**6)
    return f"{n // 1000:03d}-{n % 1000:03d}"


def normalize_code(code: str) -> bytes:
    digits = re.sub(r"\D", "", code)
    if len(digits) != 6:
        raise ValueError("The code has 6 digits, e.g. 482-913.")
    return digits.encode()


# ---------------------------------------------------------------- framing

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("Connection closed by peer.")
        buf += chunk
    return bytes(buf)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_frame(sock: socket.socket, max_len: int) -> bytes:
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > max_len:
        raise ProtocolError("Frame too large.")
    return _recv_exact(sock, n)


# ---------------------------------------------------------------- secure channel

class SecureChannel:
    def __init__(self, sock: socket.socket, send_key: bytes, recv_key: bytes):
        self.sock = sock
        self._tx = AESGCM(send_key)
        self._rx = AESGCM(recv_key)
        self._tx_n = 0
        self._rx_n = 0

    def _send(self, kind: bytes, body: bytes) -> None:
        nonce = self._tx_n.to_bytes(12, "big")
        self._tx_n += 1
        send_frame(self.sock, self._tx.encrypt(nonce, kind + body, None))

    def _recv(self) -> tuple[bytes, bytes]:
        frame = recv_frame(self.sock, MAX_FRAME)
        nonce = self._rx_n.to_bytes(12, "big")
        self._rx_n += 1
        try:
            pt = self._rx.decrypt(nonce, frame, None)
        except InvalidTag as e:
            raise ProtocolError("Message failed authentication (tampering?).") from e
        return pt[:1], pt[1:]

    def send_json(self, obj: dict) -> None:
        self._send(T_JSON, json.dumps(obj).encode("utf-8"))

    def send_data(self, data: bytes) -> None:
        self._send(T_DATA, data)

    def recv_json(self, expected_type: str | None = None) -> dict:
        kind, body = self._recv()
        if kind != T_JSON:
            raise ProtocolError("Expected a control message.")
        msg = _parse_json(body)
        if expected_type and msg.get("type") != expected_type:
            if msg.get("type") == "error":
                raise ProtocolError(f"Peer error: {clean_text(str(msg.get('message')))}")
            raise ProtocolError(f"Expected {expected_type!r}, got {clean_text(str(msg.get('type')))!r}.")
        return msg

    def recv_any(self) -> tuple[bytes, bytes]:
        return self._recv()


def _parse_json(body: bytes) -> dict:
    try:
        msg = json.loads(body)
    except ValueError as e:
        raise ProtocolError("Malformed control message.") from e
    if not isinstance(msg, dict):
        raise ProtocolError("Malformed control message.")
    return msg


def _derive(key: bytes) -> tuple[bytes, bytes, bytes]:
    material = hkdf(key, PROTO + b" keys", 96)
    return material[:32], material[32:64], material[64:]  # s->r, r->s, confirm


def handshake_sender(sock: socket.socket, code: str) -> SecureChannel:
    s = SPAKE2_A(normalize_code(code), idA=ID_SENDER, idB=ID_RECEIVER)
    send_frame(sock, PROTO + b"\n" + s.start())
    reply = recv_frame(sock, MAX_HANDSHAKE_FRAME)
    if not reply.startswith(PROTO + b"\n"):
        raise ProtocolError("Peer is not an sdt receiver.")
    try:
        key = s.finish(reply[len(PROTO) + 1:])
    except Exception as e:  # spake2 raises on malformed messages
        raise ProtocolError(f"Bad handshake: {e}") from e
    k_s2r, k_r2s, k_conf = _derive(key)
    send_frame(sock, hmac.new(k_conf, b"sender", hashlib.sha256).digest())
    theirs = recv_frame(sock, MAX_HANDSHAKE_FRAME)
    if not hmac.compare_digest(theirs, hmac.new(k_conf, b"receiver", hashlib.sha256).digest()):
        raise WrongCode("Wrong code (or someone is interfering). Nothing was sent.")
    return SecureChannel(sock, k_s2r, k_r2s)


def handshake_receiver(sock: socket.socket, code: str) -> SecureChannel:
    hello = recv_frame(sock, MAX_HANDSHAKE_FRAME)
    if not hello.startswith(PROTO + b"\n"):
        raise ProtocolError("Peer is not an sdt sender.")
    s = SPAKE2_B(normalize_code(code), idA=ID_SENDER, idB=ID_RECEIVER)
    send_frame(sock, PROTO + b"\n" + s.start())
    try:
        key = s.finish(hello[len(PROTO) + 1:])
    except Exception as e:
        raise ProtocolError(f"Bad handshake: {e}") from e
    k_s2r, k_r2s, k_conf = _derive(key)
    theirs = recv_frame(sock, MAX_HANDSHAKE_FRAME)
    if not hmac.compare_digest(theirs, hmac.new(k_conf, b"sender", hashlib.sha256).digest()):
        raise WrongCode("Sender used the wrong code.")
    send_frame(sock, hmac.new(k_conf, b"receiver", hashlib.sha256).digest())
    return SecureChannel(sock, k_r2s, k_s2r)


# ---------------------------------------------------------------- file selection

@dataclass
class OutgoingFile:
    local: Path
    rel: str  # forward-slash relative path presented to the receiver
    size: int


def collect_files(paths: list[Path], log: Callable[[str], None] = print) -> list[OutgoingFile]:
    """Files to send. Inside folders, links/junctions are NOT followed: a junction could
    point at e.g. C:\\Users and silently send files you never picked."""
    from safedatatransfer.usb_vault.transfer import scan_tree

    out: list[OutgoingFile] = []
    for p in paths:
        p = Path(p).absolute()
        if p.is_file():
            out.append(OutgoingFile(p, p.name, p.stat().st_size))
        elif p.is_dir():
            scan = scan_tree(p)
            if scan.errors:
                raise ProtocolError("Cannot read part of the folder: " + "; ".join(scan.errors[:3]))
            for link in scan.links:
                log(f"  skipped link {link} (links inside folders are not followed)")
            for f in sorted(scan.files):
                rel = PurePosixPath(p.name, *f.relative_to(p).parts).as_posix()
                out.append(OutgoingFile(f, rel, f.stat().st_size))
        else:
            raise FileNotFoundError(p)
    return out


_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
             *(f"{dev}{i}" for dev in ("COM", "LPT") for i in (*"0123456789", "¹", "²", "³"))}


def _visible_only(part: str) -> str:
    # Control/format characters (incl. right-to-left override, which can disguise
    # "invoice‮fdp.exe" as "invoiceexe.pdf") are replaced in saved names.
    return "".join("_" if unicodedata.category(ch)[0] == "C" else ch for ch in part)


def safe_relpath(rel: str) -> Path:
    """Turn a peer-supplied path into a safe relative path (no traversal, no drive letters)."""
    parts = []
    for part in rel.split("/"):
        part = _visible_only(_BAD_CHARS.sub("_", part)).strip().rstrip(" .")
        if part in ("", ".", ".."):
            raise ProtocolError(f"Unsafe file name from sender: {clean_text(rel)!r}")
        if part.split(".")[0].rstrip(" ").upper() in _RESERVED:
            part = "_" + part
        parts.append(part[:200])
    if not parts or len(parts) > 32:
        raise ProtocolError(f"Unsafe file name from sender: {clean_text(rel)!r}")
    return Path(*parts)


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    for i in range(1, 10000):
        cand = path.with_name(f"{path.stem} ({i}){path.suffix}")
        if not cand.exists():
            return cand
    raise ProtocolError(f"Too many files named {path.name}")


# ---------------------------------------------------------------- send / receive

Log = Callable[[str], None]
Progress = Callable[[int, int], None]  # (bytes done, bytes total)


def check_offer_size(files: list[OutgoingFile]) -> None:
    """Fail early, with a clear message, if the file list is too big for one transfer."""
    if len(files) > MAX_FILES:
        raise ProtocolError(f"Too many files for one transfer ({len(files):,}; at most "
                            f"{MAX_FILES:,}). Put them into a zip file or send them in parts.")
    approx = sum(len(f.rel.encode("utf-8")) + 40 for f in files) + 200
    if approx > MAX_FRAME - 1024:
        raise ProtocolError("The file list is too long for one transfer. Put the files into "
                            "a zip file or send them in parts.")


def send_files(ch: SecureChannel, files: list[OutgoingFile], sender_name: str, log: Log = print,
               progress: Progress | None = None) -> None:
    check_offer_size(files)
    ch.send_json({
        "type": "offer", "sender": sender_name,
        "files": [{"path": f.rel, "size": f.size} for f in files],
    })
    log("Waiting for the receiver to accept...")
    ch.sock.settimeout(300)
    reply = ch.recv_json()
    if reply.get("type") != "accept":
        raise Rejected("The receiver declined.")
    ch.sock.settimeout(60)
    total = sum(f.size for f in files)
    done = 0
    for i, f in enumerate(files):
        ch.send_json({"type": "file", "index": i})
        h = hashlib.sha256()
        sent = 0
        with open(f.local, "rb") as fin:
            while chunk := fin.read(CHUNK_SIZE):
                h.update(chunk)
                ch.send_data(chunk)
                sent += len(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
        if sent != f.size:
            raise ProtocolError(f"{f.rel} changed size while sending.")
        ch.send_json({"type": "file_end", "sha256": h.hexdigest()})
        log(f"  sent {f.rel}")
    ch.send_json({"type": "done"})
    ack = ch.recv_json("ok")
    log(f"Receiver confirmed {ack.get('received')} files.")


def receive_files(
    ch: SecureChannel, dest: Path, accept: Callable[[dict], bool], log: Log = print,
    max_total: int = 1 << 40, progress: Progress | None = None,
) -> list[Path]:
    offer = ch.recv_json("offer")
    files = offer.get("files")
    if not isinstance(files, list) or len(files) > MAX_FILES \
            or not all(isinstance(f, dict) for f in files):
        raise ProtocolError("Offer is malformed.")
    try:
        planned = [(safe_relpath(str(f["path"])), int(f["size"])) for f in files]
    except (KeyError, TypeError, ValueError) as e:
        raise ProtocolError("Offer is malformed.") from e
    total = sum(s for _, s in planned)
    if any(size < 0 for _, size in planned) or total > max_total:
        raise ProtocolError("Offer has invalid sizes.")
    # Show the receiver exactly what will be written, with peer text made printable.
    shown = {"sender": clean_text(str(offer.get("sender", "?")), 64),
             "files": [{"path": rel.as_posix(), "size": size} for rel, size in planned]}
    probe = dest
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    free = shutil.disk_usage(probe).free
    if total > free:
        ch.send_json({"type": "reject"})
        raise Rejected(f"Not enough space: the offer needs {total:,} bytes, {free:,} are free.")
    if not accept(shown):
        ch.send_json({"type": "reject"})
        raise Rejected("You declined the transfer.")
    ch.send_json({"type": "accept"})

    dest.mkdir(parents=True, exist_ok=True)
    winfs.set_not_indexed(dest)
    dest_real = dest.resolve()
    received: list[Path] = []
    done = 0
    for index, (rel, size) in enumerate(planned):
        start = ch.recv_json("file")
        if start.get("index") != index:
            raise ProtocolError("Files arrived out of order.")
        # Defence in depth: rel is already sanitized, but a junction placed inside dest
        # (by someone else) must not redirect received files to another folder.
        if not (dest / rel).parent.resolve().is_relative_to(dest_real):
            raise ProtocolError(f"{rel} would be written outside {dest} (link in the folder?).")
        final = _unique(dest / rel)
        final.parent.mkdir(parents=True, exist_ok=True)
        tmp = final.with_name(f".{final.name}.{secrets.token_hex(4)}.sdt-partial")
        h = hashlib.sha256()
        got = 0
        try:
            with open(tmp, "wb") as fout:
                while True:
                    kind, body = ch.recv_any()
                    if kind == T_DATA:
                        got += len(body)
                        if got > size:
                            raise ProtocolError(f"{rel} is larger than announced.")
                        h.update(body)
                        fout.write(body)
                        done += len(body)
                        if progress:
                            progress(done, total)
                        continue
                    if kind != T_JSON:
                        raise ProtocolError("Unexpected message during file.")
                    end = _parse_json(body)
                    if end.get("type") != "file_end":
                        raise ProtocolError("Unexpected message during file.")
                    break
                fout.flush()
                os.fsync(fout.fileno())
            if got != size or not hmac.compare_digest(str(end.get("sha256", "")).encode(),
                                                     h.hexdigest().encode()):
                raise ProtocolError(f"{rel} failed verification.")
            winfs.set_not_indexed(tmp)      # keep it out of the Windows Search database
            winfs.mark_from_other_pc(tmp)   # SmartScreen / Protected View apply, like a download
            os.replace(tmp, final)
        except BaseException:
            winfs.discard(tmp)
            raise
        received.append(final)
        log(f"  received {final.relative_to(dest)}")
    ch.recv_json("done")
    ch.send_json({"type": "ok", "received": len(received)})
    return received
