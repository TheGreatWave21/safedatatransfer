"""Erase data on a USB drive. Needs no admin rights and runs no external programs.

Methods:
  quick (default) - overwrite every file with random bytes (on FAT/exFAT up to the end of
                    its last cluster, so the slack behind the file goes too), rename it to a
                    random name, delete it, then overwrite the deleted directory entries
                    that still hold the old names. Free space is not touched.
  fill  (opt-in)  - quick + overwrite ALL free space: fill the drive with random data until
                    it is full, flush it to the hardware, then delete the filler files. This
                    also covers data from files that were deleted earlier. Only runs when the
                    user explicitly picks it.

Honest limitation: USB flash drives use wear levelling and keep spare blocks the OS
cannot address, so no software overwrite can *guarantee* every old block is gone.
For truly secret data, keep it encrypted on the stick (BitLocker To Go / VeraCrypt)
so erasing the key is enough, or physically destroy the stick after evacuation.
"""

from __future__ import annotations

import errno
import os
import secrets
import shutil
import stat
import time
from pathlib import Path
from typing import Callable

from safedatatransfer.common import winfs
from safedatatransfer.common.drives import human_size
from safedatatransfer.common.hashing import CHUNK_SIZE
from safedatatransfer.usb_vault.transfer import is_link, scan_tree

METHODS = ("quick", "fill")  # "quick" is the default; "fill" only when explicitly chosen

FILL_BLOCK = 4 * 1024 * 1024        # bytes per write while filling free space
FILL_FILE_MAX = 1024 * 1024 * 1024  # 1 GiB per filler file (FAT32 caps files at 4 GiB)
MIN_BLOCK = 4096

Progress = Callable[[int, int], None]


class OutsideRootError(OSError):
    """A file to be wiped turned out not to be inside the folder/drive being wiped."""


def check_inside(path: Path, root_resolved: Path, root_dev: int) -> None:
    """Last line of defence, right before anything is overwritten: the file must really be
    inside root and on the same volume. Catches any bug or race that would otherwise send
    the wipe somewhere else (e.g. a folder swapped for a junction after the scan)."""
    real = Path(path).resolve()
    if not real.is_relative_to(root_resolved):
        raise OutsideRootError(f"{path} resolves to {real}, outside {root_resolved}; not touched")
    if os.lstat(path).st_dev != root_dev:
        raise OutsideRootError(f"{path} is on another volume; not touched")


def overwrite_and_delete(path: Path, passes: int = 1, cluster: int = 0) -> bool:
    """Overwrite with random bytes, truncate, rename randomly, delete. Returns True if the
    data was overwritten, False if only this name was removed (hard link, see below).

    With cluster > 0 the overwrite runs to the end of the file's last cluster, so old data
    in the "slack" behind the end of the file (left over from earlier files) is gone too.
    That space already belongs to the file, so nothing extra is allocated."""
    if is_link(path):  # never open a link: that would overwrite whatever it points to
        raise OSError(f"{path} is a link; refusing to overwrite its target")
    if os.lstat(path).st_nlink > 1:
        # An NTFS hard link: the same data has another name, maybe outside this folder.
        # Remove only this name; the data is overwritten when its last name is wiped.
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        os.unlink(path)
        return False
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)  # clear read-only
    # Hidden NTFS data streams would otherwise be deleted with the file, unoverwritten.
    for name, ssize in winfs.list_streams(path):
        with open(f"{path}:{name}", "r+b", buffering=0) as s:
            for _ in range(passes):
                s.seek(0)
                left = ssize
                while left > 0:
                    n = min(CHUNK_SIZE, left)
                    s.write(secrets.token_bytes(n))
                    left -= n
                os.fsync(s.fileno())
    size = path.stat().st_size
    span = -(-size // cluster) * cluster if cluster > 0 else size
    with open(path, "r+b", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            remaining = size
            while remaining > 0:  # the file's own data
                n = min(CHUNK_SIZE, remaining)
                f.write(secrets.token_bytes(n))
                remaining -= n
            os.fsync(f.fileno())  # data overwritten on the device before the file grows
            if span > size:  # the slack behind it
                try:
                    f.write(secrets.token_bytes(span - size))
                except OSError as e:
                    if not _is_disk_full(e):
                        raise
            os.fsync(f.fileno())
        f.truncate(0)
        os.fsync(f.fileno())
    # Rename first so the original file name does not linger in the directory entry.
    scrambled = path.with_name(secrets.token_hex(8))
    os.replace(path, scrambled)
    scrambled.unlink()
    return True


def remove_link(path: Path) -> None:
    """Delete a symlink/junction itself. Its target (maybe on another drive) is untouched."""
    if os.path.isdir(path):
        os.rmdir(path)  # on Windows this removes the junction/dir-symlink, not the target
    else:
        os.unlink(path)


def wipe_files(
    root: Path, *, passes: int = 1, dry_run: bool = False, log: Callable[[str], None] = print,
    progress: Progress | None = None, cluster: int | None = None,
    abort_check: Callable[[], str | None] | None = None, only: set[str] | None = None,
) -> list[str]:
    """Overwrite and delete every file under root, then remove the empty folders.

    Links/junctions are removed as entries but never followed, so nothing outside root
    can be touched. Returns a list of error messages (empty means success).

    abort_check() is called every couple of seconds; if it returns a reason (e.g. "a
    different stick is now at E:"), the wipe stops at once. With `only` (relative paths,
    forward slashes), just those files are wiped and everything else is left alone.
    """
    root = Path(root)
    scan = scan_tree(root)
    errors: list[str] = list(scan.errors)
    for e in scan.errors:
        log(f"  ERROR {e}")
    if only is not None:
        scan.files = [p for p in scan.files if p.relative_to(root).as_posix() in only]
        scan.links = [p for p in scan.links if p.relative_to(root).as_posix() in only]
    root_resolved = root.resolve()
    root_dev = os.stat(root).st_dev
    last_check = time.monotonic()
    if cluster is None:
        cluster = winfs.slack_cluster(root)
    # Directory slots used by every name, per folder, measured BEFORE anything is deleted.
    slots: dict[Path, int] = {}
    for p in (*scan.files, *scan.links, *scan.dirs):
        slots[p.parent] = slots.get(p.parent, 0) + _name_slots(p.name)
    total = len(scan.files)
    done = 0
    if progress:
        progress(0, total)
    for p in scan.files:
        if dry_run:
            log(f"[dry-run] would wipe {p}")
            continue
        if abort_check and time.monotonic() - last_check > 2:
            last_check = time.monotonic()
            reason = abort_check()
            if reason:
                errors.append(f"wipe stopped: {reason}")
                log(f"  STOPPED: {reason}")
                return errors
        try:
            check_inside(p, root_resolved, root_dev)
            if overwrite_and_delete(p, passes, cluster):
                log(f"  wiped {p.relative_to(root)}")
            else:
                log(f"  removed name {p.relative_to(root)} (hard link: its data has another "
                    "name, overwritten when that one is wiped)")
        except OutsideRootError as e:
            errors.append(str(e))
            log(f"  STOPPED: {e}")
            return errors  # something is badly wrong: touch nothing else
        except OSError as e:
            errors.append(f"{p}: {e}")
            log(f"  ERROR {p}: {e}")
        done += 1
        if progress:
            progress(done, total)
    for link in scan.links:
        if dry_run:
            log(f"[dry-run] would remove link {link} (its target is not touched)")
            continue
        try:
            remove_link(link)
            log(f"  removed link {link.relative_to(root)} (target not touched)")
        except OSError as e:
            errors.append(f"{link}: {e}")
            log(f"  ERROR {link}: {e}")
    if dry_run:
        log(f"[dry-run] would scrub old file names in {len(slots)} folders")
        return errors
    scrubbed = 0
    for d in sorted(scan.dirs, key=lambda d: len(d.parts), reverse=True):  # deepest first
        scrubbed += scrub_names(d, slots.get(d, 0))
        if only is not None and any(d.iterdir()):
            continue  # still holds files we were told to leave alone
        try:
            os.chmod(d, stat.S_IWRITE | stat.S_IREAD)  # a read-only folder can't be removed
            scrambled = d.with_name(secrets.token_hex(8))
            os.replace(d, scrambled)
            scrambled.rmdir()
        except OSError as e:
            errors.append(f"{d}: {e}")
    scrubbed += scrub_names(root, slots.get(root, 0))
    if scrubbed:
        log(f"  scrubbed {scrubbed} old directory entries (original file names)")
    return errors


def _name_slots(name: str) -> int:
    # FAT: one 32-byte entry per 13 characters of a long name + the short entry.
    # exFAT needs per 15 characters + 2. Overestimating is harmless.
    return -(-len(name) // 13) + 2


def scrub_names(directory: Path, slots: int) -> int:
    """Overwrite the deleted directory entries that still hold the original file names.

    FAT/exFAT only mark deleted entries as free; the old name stays readable until the slot
    is reused. Windows reuses free slots first, so creating (then deleting) that many empty
    files with random short names overwrites them. Best effort, writes no file data."""
    made: list[Path] = []
    try:
        for _ in range(slots):
            p = directory / f"{secrets.token_hex(4).upper()}.SDT"  # 8.3 name: exactly 1 slot
            try:
                with open(p, "xb"):
                    pass
            except FileExistsError:
                continue
            except OSError:
                break
            made.append(p)
    finally:
        for p in made:
            try:
                p.unlink()
            except OSError:
                pass
    return len(made)


# ---------------------------------------------------------------- free space

def _is_disk_full(e: OSError) -> bool:
    # ERROR_HANDLE_DISK_FULL = 39, ERROR_DISK_FULL = 112
    return e.errno == errno.ENOSPC or getattr(e, "winerror", None) in (39, 112)


def _write_block(f, data: bytes) -> int:
    """One raw write; returns how many bytes were written. (Separate so tests can simulate a full disk.)"""
    return f.write(data) or 0


def wipe_free_space(
    drive_root: str | Path, *, dry_run: bool = False, log: Callable[[str], None] = print,
    progress: Progress | None = None, max_bytes: int | None = None,
) -> int:
    """Overwrite all free space with random data, then delete the filler. Returns 0 on success.

    max_bytes limits how much is written (for tests); normally the whole free space is used.
    """
    root = Path(drive_root)
    free = shutil.disk_usage(root).free
    target = free if max_bytes is None else min(free, max_bytes)
    if dry_run:
        log(f"[dry-run] would overwrite {human_size(free)} of free space with random data")
        return 0

    log(f"Overwriting {human_size(target)} of free space with random data "
        "(the drive will look full for a while)...")
    filler = root / f".sdt-wipe-{secrets.token_hex(4)}"
    filler.mkdir()
    written = 0
    block = FILL_BLOCK
    index = 0
    full = False
    if progress:
        progress(0, target)
    try:
        while not full and written < target:
            path = filler / f"{index:05d}.bin"
            index += 1
            try:
                f = open(path, "wb", buffering=0)
            except OSError as e:
                if _is_disk_full(e):
                    break
                raise
            with f:
                in_file = 0
                while in_file < FILL_FILE_MAX and written < target:
                    n = min(block, target - written, FILL_FILE_MAX - in_file)
                    try:
                        w = _write_block(f, os.urandom(n))
                    except OSError as e:
                        if not _is_disk_full(e):
                            raise
                        w = 0
                    written += w
                    in_file += w
                    if progress:
                        progress(written, target)
                    if w < n:  # disk is (nearly) full: fill the last gaps with smaller writes
                        if block <= MIN_BLOCK:
                            full = True
                            break
                        block = max(MIN_BLOCK, block // 16)
                try:
                    os.fsync(f.fileno())  # make sure the random data really reaches the stick
                except OSError as e:
                    if not _is_disk_full(e):
                        raise
        log(f"  overwrote {human_size(written)} of free space")
        if progress:
            progress(target, target)
        return 0
    finally:
        for p in filler.iterdir():
            p.unlink()
        filler.rmdir()
        log("  removed filler files")
