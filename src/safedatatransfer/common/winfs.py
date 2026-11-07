"""Small Windows file-system helpers (ctypes only, no admin rights needed).

- UncachedReader:     read a file straight from the disk, bypassing the Windows file cache,
                      so "verify" really checks what is stored, not a copy in RAM.
- set_not_indexed:    keep plaintext out of the Windows Search index.
- mark_from_other_pc: add the "Mark of the Web" so SmartScreen / Office Protected View
                      treat a received file as coming from outside this PC.
- cloud_folder:       detect OneDrive/Dropbox/... folders, where plaintext would be uploaded.
- cluster_size:       allocation unit of a volume (to overwrite file slack too).
- discard:            best-effort overwrite + delete of a partial plaintext file.
"""

from __future__ import annotations

import ctypes
import os
import secrets
import sys
from pathlib import Path

FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
_CLOUD_NAMES = {"dropbox", "google drive", "googledrive", "my drive", "icloud drive",
                "iclouddrive", "nextcloud", "pcloud drive", "mega"}


def _k32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = ctypes.c_void_p
    k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                              ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    k.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                           ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.VirtualAlloc.restype = ctypes.c_void_p
    k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    k.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    k.GetFileAttributesW.restype = ctypes.c_uint32
    k.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    k.GetDiskFreeSpaceW.argtypes = [ctypes.c_wchar_p] + [ctypes.POINTER(ctypes.c_uint32)] * 4
    return k


# ---------------------------------------------------------------- uncached reads

class UncachedReader:
    """Minimal binary reader (read/peek) that bypasses the OS cache (FILE_FLAG_NO_BUFFERING)."""

    BLOCK = 1 << 20  # multiple of every sector size; buffer is page-aligned by VirtualAlloc

    def __init__(self, path: str | os.PathLike):
        self._k = _k32()
        flags = 0x20000000 | 0x08000000  # NO_BUFFERING | SEQUENTIAL_SCAN
        h = self._k.CreateFileW(str(path), 0x80000000, 1, None, 3, flags, None)
        if h in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        self._h = h
        self._buf = self._k.VirtualAlloc(None, self.BLOCK, 0x3000, 0x04)
        if not self._buf:
            self._k.CloseHandle(h)
            raise MemoryError("VirtualAlloc failed")
        self._pending = bytearray()
        self._eof = False

    def _fill(self) -> None:
        got = ctypes.c_uint32()
        if not self._k.ReadFile(self._h, self._buf, self.BLOCK, ctypes.byref(got), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if got.value == 0:
            self._eof = True
        else:
            self._pending += ctypes.string_at(self._buf, got.value)

    def read(self, n: int = -1) -> bytes:
        while (n < 0 or len(self._pending) < n) and not self._eof:
            self._fill()
        if n < 0:
            n = len(self._pending)
        out = bytes(self._pending[:n])
        del self._pending[:n]
        return out

    def peek(self, n: int = 1) -> bytes:
        while len(self._pending) < n and not self._eof:
            self._fill()
        return bytes(self._pending[:n])

    def close(self) -> None:
        if self._h is not None:
            self._k.VirtualFree(self._buf, 0, 0x8000)
            self._k.CloseHandle(self._h)
            self._h = None

    def __enter__(self) -> "UncachedReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def open_for_verify(path: Path):
    """(reader, uncached?) Prefer reading past the Windows cache; fall back to a normal open."""
    if sys.platform == "win32":
        try:
            return UncachedReader(path), True
        except (OSError, MemoryError):
            pass
    return open(path, "rb"), False


# ---------------------------------------------------------------- attributes / marks

def set_not_indexed(path: str | os.PathLike) -> None:
    """Ask Windows Search not to index this file/folder (contents would persist in its database)."""
    if sys.platform != "win32":
        return
    k = _k32()
    attrs = k.GetFileAttributesW(str(path))
    if attrs != 0xFFFFFFFF:
        k.SetFileAttributesW(str(path), attrs | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)


def mark_from_other_pc(path: str | os.PathLike) -> None:
    """Add the Zone.Identifier stream (ZoneId=3), like a browser download. Best effort:
    FAT/exFAT have no streams, so nothing happens there."""
    if sys.platform != "win32":
        return
    try:
        with open(f"{path}:Zone.Identifier", "w", encoding="ascii") as f:
            f.write("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=sdt-drop://local\r\n")
    except OSError:
        pass


class _StreamData(ctypes.Structure):
    _fields_ = [("size", ctypes.c_longlong), ("name", ctypes.c_wchar * (260 + 36))]


def list_streams(path: str | os.PathLike) -> list[tuple[str, int]]:
    """Extra NTFS data streams of a file ("alternate data streams") as (name, size).
    They hold data invisible in Explorer; FAT/exFAT have none, so this returns []."""
    if sys.platform != "win32":
        return []
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.FindFirstStreamW.restype = ctypes.c_void_p
    k.FindFirstStreamW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    k.FindNextStreamW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k.FindClose.argtypes = [ctypes.c_void_p]
    data = _StreamData()
    h = k.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
    if h in (None, ctypes.c_void_p(-1).value):
        return []  # no streams, or the file system has none
    out = []
    try:
        while True:
            name = data.name  # ":name:$DATA"; the main stream is "::$DATA"
            if name != "::$DATA" and name.endswith(":$DATA"):
                out.append((name[1:-len(":$DATA")], int(data.size)))
            if not k.FindNextStreamW(h, ctypes.byref(data)):
                break
    finally:
        k.FindClose(h)
    return out


def cloud_folder(path: str | os.PathLike) -> str | None:
    """Name of the cloud-sync folder that contains path (OneDrive, Dropbox, ...), else None."""
    p = Path(path).resolve()
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        root = os.environ.get(var)
        if root:
            try:
                if p.is_relative_to(Path(root).resolve()):
                    return f"OneDrive ({root})"
            except (OSError, ValueError):
                pass
    for part in p.parts[1:]:
        low = part.lower()
        if low.startswith("onedrive") or low in _CLOUD_NAMES:
            return part
    return None


def filesystem(path: str | os.PathLike) -> str:
    """'FAT32', 'exFAT', 'NTFS', ... of the volume holding path ('' if unknown)."""
    if sys.platform != "win32":
        return ""
    fs = ctypes.create_unicode_buffer(64)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(Path(path).resolve().anchor), None, 0, None, None, None, fs, 64)
    return fs.value if ok else ""


def slack_cluster(path: str | os.PathLike) -> int:
    """Cluster size if file slack can be overwritten safely in place (FAT/exFAT), else 0.
    (On NTFS tiny files live inside the file table, so growing them moves data instead.)"""
    return cluster_size(path) if filesystem(path).upper() in ("FAT", "FAT32", "EXFAT") else 0


def cluster_size(path: str | os.PathLike, default: int = 4096) -> int:
    if sys.platform != "win32":
        return default
    spc, bps, free, total = (ctypes.c_uint32() for _ in range(4))
    root = Path(path).resolve().anchor
    if _k32().GetDiskFreeSpaceW(root, ctypes.byref(spc), ctypes.byref(bps),
                                ctypes.byref(free), ctypes.byref(total)):
        return max(512, spc.value * bps.value)
    return default


def discard(path: Path) -> None:
    """Overwrite a (partial plaintext) file with random bytes, then delete it. Best effort."""
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as f:
            left = size
            while left > 0:
                n = min(1 << 20, left)
                f.write(secrets.token_bytes(n))
                left -= n
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
