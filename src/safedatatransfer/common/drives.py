"""Windows drive enumeration via the Win32 API (ctypes, no dependencies)."""

from __future__ import annotations

import ctypes
import os
import string
import struct
import sys
from dataclasses import dataclass

DRIVE_TYPES = {
    0: "unknown",
    1: "no_root",
    2: "removable",
    3: "fixed",
    4: "remote",
    5: "cdrom",
    6: "ramdisk",
}

SEM_FAILCRITICALERRORS = 0x0001

BUS_TYPES = {
    0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "IEEE 1394", 5: "SSA",
    6: "Fibre Channel", 7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA",
    12: "SD card", 13: "MMC", 14: "Virtual", 15: "File-backed virtual",
    16: "Storage Spaces", 17: "NVMe", 18: "SCM", 19: "UFS",
}

VOLUME_FLAGS = {
    0x00000001: "case-sensitive names",
    0x00000002: "case-preserved names",
    0x00000004: "Unicode names",
    0x00000008: "ACLs (permissions)",
    0x00000010: "file compression",
    0x00000020: "disk quotas",
    0x00000040: "sparse files",
    0x00008000: "volume is compressed",
    0x00010000: "object IDs",
    0x00020000: "EFS encryption",
    0x00040000: "alternate data streams",
    0x00080000: "READ-ONLY volume",
}

IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
DEVICE_PREFIX = "\\\\.\\"  # \\.\E: opens the volume device


class DriveError(Exception):
    pass


@dataclass(frozen=True)
class Drive:
    letter: str  # "E:"
    type: str  # "removable", "fixed", ...
    label: str
    filesystem: str
    serial: int
    total_bytes: int
    free_bytes: int
    is_system: bool
    flags: int = 0
    max_component: int = 0

    @property
    def root(self) -> str:
        return self.letter + "\\"


def _require_windows() -> None:
    if sys.platform != "win32":
        raise DriveError("Drive handling is only implemented for Windows.")


def normalize_letter(value: str) -> str:
    """Turn 'e', 'E:', 'E:\\' into 'E:'."""
    v = value.strip().rstrip("\\/").rstrip(":").upper()
    if len(v) != 1 or v not in string.ascii_uppercase:
        raise DriveError(f"Not a drive letter: {value!r}")
    return v + ":"


def system_drive() -> str:
    """Drive Windows is installed on. Asked from Windows itself (an environment variable
    could be missing or changed); %SystemDrive% only as a fallback."""
    if sys.platform == "win32":
        buf = ctypes.create_unicode_buffer(261)
        if ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, 261) and buf.value[1:2] == ":":
            return normalize_letter(buf.value[:2])
    return normalize_letter(os.environ.get("SystemDrive", "C:"))


def _query(letter: str) -> Drive | None:
    k32 = ctypes.windll.kernel32
    root = letter + "\\"
    dtype = DRIVE_TYPES.get(k32.GetDriveTypeW(root), "unknown")
    if dtype == "remote":
        # Network drives are never wiped, and asking an unreachable server for volume
        # details can hang for a long time. List them without querying.
        return Drive(letter=letter, type=dtype, label="", filesystem="", serial=0,
                     total_bytes=0, free_bytes=0, is_system=False)

    label = ctypes.create_unicode_buffer(261)
    fs = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_uint32()
    max_len = ctypes.c_uint32()
    flags = ctypes.c_uint32()
    if not k32.GetVolumeInformationW(
        root, label, 261, ctypes.byref(serial), ctypes.byref(max_len),
        ctypes.byref(flags), fs, 261,
    ):
        return None  # empty card reader slot, unmounted, etc.

    free_caller = ctypes.c_uint64()
    total = ctypes.c_uint64()
    free_total = ctypes.c_uint64()
    k32.GetDiskFreeSpaceExW(
        root, ctypes.byref(free_caller), ctypes.byref(total), ctypes.byref(free_total)
    )
    return Drive(
        letter=letter,
        type=dtype,
        label=label.value,
        filesystem=fs.value,
        serial=serial.value,
        total_bytes=total.value,
        free_bytes=free_total.value,
        is_system=(letter == system_drive()),
        flags=flags.value,
        max_component=max_len.value,
    )


def list_drives() -> list[Drive]:
    _require_windows()
    k32 = ctypes.windll.kernel32
    old_mode = k32.SetErrorMode(SEM_FAILCRITICALERRORS)  # no "insert disk" popups
    try:
        mask = k32.GetLogicalDrives()
        drives = []
        for i, ch in enumerate(string.ascii_uppercase):
            if mask & (1 << i):
                d = _query(ch + ":")
                if d is not None:
                    drives.append(d)
        return drives
    finally:
        k32.SetErrorMode(old_mode)


def get_drive(value: str) -> Drive:
    """Query just this one letter (fast; never blocked by other, slow drives)."""
    letter = normalize_letter(value)
    _require_windows()
    k32 = ctypes.windll.kernel32
    old_mode = k32.SetErrorMode(SEM_FAILCRITICALERRORS)
    try:
        if k32.GetLogicalDrives() & (1 << (ord(letter[0]) - ord("A"))):
            d = _query(letter)
            if d is not None:
                return d
    finally:
        k32.SetErrorMode(old_mode)
    raise DriveError(f"Drive {letter} not found or not ready.")


@dataclass(frozen=True)
class DeviceInfo:
    vendor: str
    product: str
    revision: str
    hw_serial: str
    bus: str
    removable_media: bool
    disk_number: int | None
    partition_number: int | None
    bytes_per_sector: int
    cluster_bytes: int


def _kernel32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)  # private instance: safe argtypes
    k.CreateFileW.restype = ctypes.c_void_p
    k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                              ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    k.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                                  ctypes.c_void_p, ctypes.c_uint32,
                                  ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    return k


def device_info(letter: str) -> DeviceInfo | None:
    """Hardware details for the disk behind a drive letter (read-only query, no admin)."""
    _require_windows()
    letter = normalize_letter(letter)
    k = _kernel32()
    spc, bps, free_c, total_c = (ctypes.c_uint32() for _ in range(4))
    ctypes.windll.kernel32.GetDiskFreeSpaceW(letter + "\\", ctypes.byref(spc), ctypes.byref(bps),
                                             ctypes.byref(free_c), ctypes.byref(total_c))
    handle = k.CreateFileW(DEVICE_PREFIX + letter, 0, 3, None, 3, 0, None)  # 0 access = query only
    if handle in (None, ctypes.c_void_p(-1).value):
        return None
    try:
        query = struct.pack("<III", 0, 0, 0)  # StorageDeviceProperty, PropertyStandardQuery
        buf = ctypes.create_string_buffer(2048)
        got = ctypes.c_uint32()
        if not k.DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY, query, len(query),
                                 buf, len(buf), ctypes.byref(got), None):
            return None
        raw = buf.raw[: got.value]
        removable = bool(raw[10]) if len(raw) > 10 else False
        offsets = struct.unpack_from("<IIIII", raw, 12) if len(raw) >= 32 else (0,) * 5

        def text(off: int) -> str:
            if not off or off >= len(raw):
                return ""
            return raw[off: raw.index(b"\0", off)].decode("ascii", "replace").strip()

        number = ctypes.create_string_buffer(12)
        disk = part = None
        if k.DeviceIoControl(handle, IOCTL_STORAGE_GET_DEVICE_NUMBER, None, 0,
                             number, 12, ctypes.byref(got), None):
            _, disk, part = struct.unpack("<III", number.raw)
        return DeviceInfo(
            vendor=text(offsets[0]), product=text(offsets[1]), revision=text(offsets[2]),
            hw_serial=text(offsets[3]), bus=BUS_TYPES.get(offsets[4], f"type {offsets[4]}"),
            removable_media=removable, disk_number=disk, partition_number=part,
            bytes_per_sector=bps.value, cluster_bytes=spc.value * bps.value,
        )
    finally:
        k.CloseHandle(handle)


def volume_features(flags: int) -> list[str]:
    return [name for bit, name in VOLUME_FLAGS.items() if flags & bit]


def drive_details(drive: Drive) -> list[tuple[str, str]]:
    """Every piece of information we can get about a drive, as (label, value) rows."""
    used = drive.total_bytes - drive.free_bytes
    pct = (used / drive.total_bytes * 100) if drive.total_bytes else 0
    rows = [
        ("Drive", drive.root),
        ("Label", drive.label or "(none)"),
        ("Windows type", drive.type + ("  [SYSTEM DRIVE]" if drive.is_system else "")),
        ("File system", drive.filesystem),
        ("Volume serial", f"{drive.serial >> 16:04X}-{drive.serial & 0xFFFF:04X}"),
        ("Capacity", f"{human_size(drive.total_bytes)}  ({drive.total_bytes:,} bytes)"),
        ("Used", f"{human_size(used)}  ({pct:.1f}%)"),
        ("Free", f"{human_size(drive.free_bytes)}  ({drive.free_bytes:,} bytes)"),
        ("Max name length", str(drive.max_component)),
    ]
    try:
        dev = device_info(drive.letter)
    except (DriveError, OSError):
        dev = None
    if dev:
        rows += [
            ("Device", " ".join(x for x in (dev.vendor, dev.product) if x) or "(unknown)"),
            ("Firmware rev.", dev.revision or "-"),
            ("Hardware serial", dev.hw_serial or "-"),
            ("Bus", dev.bus),
            ("Removable media", "yes" if dev.removable_media else "no"),
            ("Physical disk", "-" if dev.disk_number is None
             else rf"\\.\PhysicalDrive{dev.disk_number}, partition {dev.partition_number}"),
            ("Sector / cluster", f"{dev.bytes_per_sector} B / {human_size(dev.cluster_bytes)}"),
        ]
    rows.append(("Features", ", ".join(volume_features(drive.flags)) or "-"))
    return rows


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{n} B"
