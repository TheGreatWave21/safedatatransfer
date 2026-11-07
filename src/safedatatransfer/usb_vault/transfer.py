"""Shared types for walking a USB drive and reporting what was transferred.

Files are never copied in plaintext; see vault.py for the encrypted copy + verify.

Walking is link-safe: symlinks and junctions (NTFS "reparse points") are never followed.
A junction on a stick can point anywhere, e.g. C:\\Users, and following it would copy or
wipe files that are not on the stick at all.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

# Windows-managed folder on a drive that we never copy or wipe (normally not even readable).
SKIP_DIRS = {"system volume information"}

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass
class FileEntry:
    path: str  # relative, forward slashes
    size: int
    sha256: str
    mtime: float = 0.0
    streams: tuple = ()  # hidden NTFS data streams: ((name, size, sha256), ...)


@dataclass
class TransferResult:
    source: str
    destination: str
    started: str
    finished: str = ""
    files: list[FileEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)  # not followed, not copied
    blob_sizes: dict[str, int] = field(default_factory=dict)  # vault files written + sizes

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)


def is_link(path: str | os.PathLike) -> bool:
    """True for symlinks, junctions and any other reparse point. Never follows the link."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(
        getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


@dataclass
class Scan:
    files: list[Path] = field(default_factory=list)
    dirs: list[Path] = field(default_factory=list)   # real folders below root (not links)
    links: list[Path] = field(default_factory=list)  # links/junctions (file or folder)
    errors: list[str] = field(default_factory=list)  # folders that could not be read


def scan_tree(root: Path) -> Scan:
    """Everything under root without following links. Unreadable folders are reported."""
    root = Path(root)
    scan = Scan()

    def on_error(e: OSError) -> None:
        scan.errors.append(f"{e.filename}: cannot read folder ({e.strerror or e})")

    for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
        here = Path(dirpath)
        keep = []
        for d in dirnames:
            p = here / d
            if d.lower() in SKIP_DIRS and here == root:
                continue
            if is_link(p):
                scan.links.append(p)
            else:
                keep.append(d)
                scan.dirs.append(p)
        dirnames[:] = keep  # never descend into links
        for name in filenames:
            p = here / name
            (scan.links if is_link(p) else scan.files).append(p)
    # Only real symlinks/junctions may be treated as "just a pointer, remove the entry".
    # Other reparse points (cloud placeholders, deduplicated or archived files, ...) hold
    # data of their own: they are reported as errors, so they are never wiped uncopied.
    for p in list(scan.links):
        tag = _reparse_tag(p)
        if tag not in (None, IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT):
            scan.links.remove(p)
            scan.errors.append(f"{p}: special file (reparse tag {tag:#x}) that sdt cannot "
                               "copy safely; nothing will be wiped")
    return scan


IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003  # junction
IO_REPARSE_TAG_SYMLINK = 0xA000000C


def _reparse_tag(path: Path) -> int | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode):
        return IO_REPARSE_TAG_SYMLINK
    return getattr(st, "st_reparse_tag", None) or None


def iter_source_files(root: Path):
    """Yield every real file under root (links are not followed)."""
    yield from scan_tree(root).files
