"""High-level usb_vault operations used by the CLI, with all safety checks."""

from __future__ import annotations

import getpass
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from safedatatransfer.common.drives import (
    Drive, DriveError, device_info, get_drive, human_size, list_drives, system_drive,
)
from safedatatransfer.usb_vault import vault, wipe
from safedatatransfer.common.text import clean_text, safe_print
from safedatatransfer.usb_vault.transfer import is_link, scan_tree

DEFAULT_DEST_ROOT = Path.home() / "Downloads" / "usb-vault"


class SafetyError(Exception):
    pass


def check_wipe_allowed(drive: Drive, *, allow_fixed: bool, dest: Path | None = None) -> None:
    if drive.is_system:
        raise SafetyError(f"{drive.letter} is the system drive. Refusing.")
    if drive.type != "removable" and not (allow_fixed and drive.type == "fixed"):
        raise SafetyError(
            f"{drive.letter} is a '{drive.type}' drive, not 'removable'. "
            "Some USB SSDs report as fixed — pass --allow-fixed if you are sure."
        )
    if dest is not None and _same_volume(dest, drive):
        raise SafetyError("The destination folder is on the drive being wiped.")
    for where in (sys.prefix, sys.base_prefix, Path(__file__).parent):
        if _same_volume(Path(where), drive):
            raise SafetyError(f"sdt (or its Python) is running from {drive.letter}. "
                              "Run it from your PC, not from the stick you want to wipe.")
    if _on_system_disk(drive):
        raise SafetyError(f"{drive.letter} is on the same physical disk as Windows. Refusing.")


def _on_system_disk(drive: Drive) -> bool:
    try:
        mine, system = device_info(drive.letter), device_info(system_drive())
    except (DriveError, OSError):
        return False
    return bool(mine and system and mine.disk_number is not None
                and mine.disk_number == system.disk_number)


def drive_identity(drive: Drive) -> tuple:
    """What must stay the same for 'this is still the stick the user confirmed'."""
    try:
        dev = device_info(drive.letter)
    except (DriveError, OSError):
        dev = None
    return (drive.serial, drive.total_bytes, drive.filesystem,
            dev.hw_serial if dev else None, dev.disk_number if dev else None)


def still_same_drive(drive: Drive, identity: tuple | None = None) -> str | None:
    """None if the same stick is still at drive.letter, else the reason it is not."""
    try:
        now = get_drive(drive.letter)
    except DriveError:
        return f"{drive.letter} is no longer connected."
    if drive_identity(now) != (identity or drive_identity(drive)):
        return f"A different drive is now at {drive.letter}."
    return None


def _same_volume(path: Path, drive: Drive) -> bool:
    """Is path on drive? Checks the letter AND the volume serial of the nearest existing
    folder, so mount folders (e.g. C:/mnt/stick) and subst/junction tricks are caught too."""
    path = Path(path).resolve()
    if path.drive.upper() == drive.letter:
        return True
    probe = path
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        return (os.stat(probe).st_dev & 0xFFFFFFFF) == drive.serial
    except OSError:
        return False


def check_passes(passes: int) -> None:
    if not 1 <= passes <= 35:
        raise ValueError("--passes must be between 1 and 35.")


def confirm_wipe(drive: Drive) -> bool:
    scan = scan_tree(Path(drive.root))
    size = 0
    for p in scan.files:
        try:
            size += p.stat().st_size
        except OSError:
            pass
    print()
    print(f"  !!! ABOUT TO PERMANENTLY ERASE {drive.letter}  "
          f"label='{clean_text(drive.label, 40)}'  {human_size(drive.total_bytes)}  "
          f"serial={drive.serial:08X}")
    print(f"      {len(scan.files):,} files ({human_size(size)}) in {len(scan.dirs):,} folders "
          "will be destroyed.")
    expected = f"WIPE {drive.letter}"
    answer = input(f"  Type '{expected}' to continue: ").strip()
    return answer.upper() == expected


def ask_new_password() -> str:
    print("The copy is encrypted. Choose a vault password — without it the files are lost.")
    while True:
        pw = getpass.getpass("  New vault password: ")
        try:
            vault.check_password(pw)
        except vault.VaultError as e:
            print(f"  {e}")
            continue
        if getpass.getpass("  Repeat password: ") == pw:
            return pw
        print("  Passwords did not match.")


def ask_password() -> str:
    return getpass.getpass("Vault password: ")


def default_destination(drive: Drive) -> Path:
    # No volume label in the folder name: the name is visible without the password.
    # (The label is stored inside the encrypted manifest.)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return DEFAULT_DEST_ROOT / f"vault_{stamp}"


def cmd_list(show_all: bool) -> int:
    drives = list_drives()
    if not show_all:
        drives = [d for d in drives if d.type == "removable"]
    if not drives:
        print("No removable drives found. Use --all to show every drive.")
        return 0
    print(f"{'Drive':6} {'Type':10} {'FS':6} {'Size':>10} {'Free':>10}  Label")
    for d in drives:
        tag = " (system)" if d.is_system else ""
        print(f"{d.letter:6} {d.type:10} {d.filesystem:6} {human_size(d.total_bytes):>10} "
              f"{human_size(d.free_bytes):>10}  {d.label}{tag}")
    return 0


def _encrypt_copy(drive: Drive, dest: Path, dry_run: bool):
    password = "dry-run-password" if dry_run else ask_new_password()
    print(f"Encrypting {drive.root} -> {dest}")
    result = vault.create_vault(Path(drive.root), dest, password,
                                source_label=drive.label, dry_run=dry_run, log=safe_print)
    print(f"\n{len(result.files)} files, {human_size(result.total_bytes)}, "
          f"{len(result.errors)} errors")
    if result.links:
        print(f"{len(result.links)} links/junctions were not followed (they point elsewhere).")
    return result


def cmd_copy(letter: str, dest: Path | None, dry_run: bool) -> int:
    drive = get_drive(letter)
    dest = dest or default_destination(drive)
    check_destination(dest)
    result = _encrypt_copy(drive, dest, dry_run)
    if result.ok and not dry_run:
        print(f"Open it later with:  sdt vault open \"{result.destination}\"")
    return 0 if result.ok else 1


def _percent_printer():
    last = -1

    def show(done: int, total: int) -> None:
        nonlocal last
        pct = int(done * 100 / total) if total else 100
        if pct != last:
            last = pct
            print(f"\r  free space: {pct:3d}%", end="\n" if pct >= 100 else "", flush=True)
    return show


def do_wipe(drive: Drive, method: str, passes: int, dry_run: bool, *, log=safe_print,
            progress=None, verified: list | None = None, identity: tuple | None = None,
            vault_result=None) -> int:
    """Wipe drive. Re-checks, right before touching anything (i.e. after the user typed the
    confirmation), that the very same stick is still there (`identity` from when it was
    chosen). With `vault_result` (the evacuation's copy), checks the vault is still fully
    there. With `verified` (the files just copied into a vault), first re-reads the
    whole stick and refuses to wipe if anything is not exactly what is in the vault.
    During the wipe the stick's identity is checked every few seconds; afterwards it
    checks that the stick really is empty."""
    reason = still_same_drive(drive, identity)
    if reason:
        log(f"NOT wiping: {reason}")
        return 1
    if vault_result is not None and not dry_run:
        reason = vault.vault_still_present(Path(vault_result.destination), vault_result.blob_sizes)
        if reason:
            log(f"NOT wiping: the vault is not complete any more: {reason}")
            return 1
    if verified is not None:
        problems = vault.unverified_files(Path(drive.root), verified, rehash=not dry_run, log=log)
        if problems:
            log(f"NOT wiping: {len(problems)} items on {drive.letter} are not safely in the vault:")
            for msg in problems[:20]:
                log(f"  {msg}")
            if len(problems) > 20:
                log(f"  ... and {len(problems) - 20} more")
            log("Run evacuate again to include them.")
            return 1
    errors = wipe.wipe_files(Path(drive.root), passes=passes, dry_run=dry_run,
                             log=log, progress=progress,
                             abort_check=lambda: still_same_drive(drive, identity))
    if errors:
        log(f"{len(errors)} files could not be wiped; stopping before the free-space step.")
        return 1
    if not dry_run:
        left = scan_tree(Path(drive.root))
        leftovers = [*left.files, *left.links, *left.dirs]
        if leftovers or left.errors:
            log(f"Check after wipe: {len(leftovers)} items are still on {drive.letter}:")
            for p in leftovers[:20]:
                log(f"  {p}")
            for e in left.errors[:5]:
                log(f"  {e}")
            return 1
        log(f"Check after wipe: {drive.letter} is empty.")
    if method == "fill":
        reason = still_same_drive(drive, identity)
        if reason:
            log(f"NOT filling free space: {reason}")
            return 1
        code = wipe.wipe_free_space(drive.root, dry_run=dry_run, log=log,
                                    progress=progress or _percent_printer())
        if not dry_run:
            left = [p for p in Path(drive.root).iterdir() if p.name.startswith(".sdt-wipe-")]
            if left:
                log(f"Check after fill: filler folder {left[0]} is still there; delete it.")
                return 1
            log("Check after fill: the filler files are gone.")
        return code
    return 0


_do_wipe = do_wipe


def check_no_vaults(drive: Drive, allow_vault: bool) -> None:
    """A stick that holds an sdt vault is most likely the wrong stick (the backup!)."""
    found = vault.find_vaults_under(Path(drive.root))
    if found and not allow_vault:
        raise SafetyError(f"{drive.letter} holds an sdt vault ({found[0]}). That is probably "
                          "your backup, not the stick to erase. Refusing. "
                          "(Pass --allow-vault if you really mean it.)")


def check_destination(dest: Path) -> None:
    """Refuse vault locations that Windows may clear on its own."""
    d = Path(dest).absolute()
    temps = {Path(p).resolve() for p in (tempfile.gettempdir(), os.environ.get("TEMP"),
                                         os.environ.get("TMP")) if p}
    resolved = d.resolve()
    if any(resolved.is_relative_to(t) for t in temps):
        raise SafetyError(f"{dest} is in a temporary folder, which Windows (Storage Sense, "
                          "Disk Cleanup) may empty on its own. Choose another destination.")
    if any(part.lower() == "$recycle.bin" for part in d.parts):
        raise SafetyError(f"{dest} is inside a Recycle Bin. Choose another destination.")


def prove_password(vault_dir: Path, tries: int = 3) -> bool:
    """Before the original is erased: can the user still open the new vault?"""
    print("\nBefore anything is erased: type the vault password once more, to prove you can "
          "open the vault.")
    for i in range(tries):
        try:
            vault.load_manifest(vault_dir, getpass.getpass("  Vault password: "))
            print("  Password works.")
            return True
        except vault.VaultError:
            print(f"  That does not open the vault ({tries - i - 1} tries left).")
    return False


def cmd_wipe(letter: str, method: str, passes: int, allow_fixed: bool, dry_run: bool,
             allow_vault: bool = False) -> int:
    drive = get_drive(letter)
    identity = drive_identity(drive)
    check_wipe_allowed(drive, allow_fixed=allow_fixed)
    check_passes(passes)
    check_no_vaults(drive, allow_vault)
    if not dry_run and not confirm_wipe(drive):
        print("Aborted. Nothing was erased.")
        return 1
    return _do_wipe(drive, method, passes, dry_run, identity=identity)


def cmd_evacuate(
    letter: str, dest: Path | None, method: str, passes: int, allow_fixed: bool, dry_run: bool,
    allow_vault: bool = False,
) -> int:
    drive = get_drive(letter)
    identity = drive_identity(drive)
    dest = dest or default_destination(drive)
    check_wipe_allowed(drive, allow_fixed=allow_fixed, dest=dest)
    check_destination(dest)
    check_passes(passes)
    check_no_vaults(drive, allow_vault)

    print("Step 1/2: encrypted copy + verify")
    result = _encrypt_copy(drive, dest, dry_run)
    if not result.ok:
        print("Copy was NOT fully verified. The drive will NOT be wiped.")
        return 1

    # Make sure the same stick is still plugged in before erasing it.
    reason = still_same_drive(drive, identity)
    if reason:
        print(f"{reason} Not wiping.")
        return 1
    if not dry_run and not prove_password(Path(result.destination)):
        print("Not wiping: the vault could not be opened with the password you typed. "
              "Your files are in the vault and still on the stick.")
        return 1

    print(f"\nStep 2/2: wipe {drive.letter} (method={method}, passes={passes})")
    if not dry_run and not confirm_wipe(drive):
        print("Aborted. Your files are in the vault, the drive was not erased.")
        return 1
    # do_wipe checks the identity once more, after the confirmation was typed.
    return _do_wipe(drive, method, passes, dry_run, verified=result.files, identity=identity,
                    vault_result=result)


def cmd_info(letter: str, scan: bool = False) -> int:
    from safedatatransfer.common.drives import drive_details
    from safedatatransfer.usb_vault.transfer import iter_source_files

    drive = get_drive(letter)
    for k, v in drive_details(drive):
        print(f"{k:>17}  {v}")
    if drive.type == "removable" or scan:
        count = size = 0
        for f in iter_source_files(Path(drive.root)):
            try:
                size += f.stat().st_size
                count += 1
            except OSError:
                pass
        print(f"{'Contents':>17}  {count:,} files, {human_size(size)}")
    else:
        print(f"{'Contents':>17}  not counted for '{drive.type}' drives (add --scan, can be slow)")
    try:
        check_wipe_allowed(drive, allow_fixed=False)
        print(f"{'Can be wiped':>17}  yes")
    except SafetyError as e:
        print(f"{'Can be wiped':>17}  no: {e}")
    return 0


def cmd_vault_info(vault_dir: Path) -> int:
    for k, v in vault.vault_info(vault_dir):
        print(f"{k:>16}  {v}")
    return 0


def cmd_vault_list(vault_dir: Path) -> int:
    manifest = vault.load_manifest(vault_dir, ask_password())
    files = vault.manifest_summary(manifest)
    safe_print(f"Source: {manifest['source']}  label='{manifest['label']}'  {manifest['finished']}")
    if manifest.get("_note"):
        print(f"WARNING: {manifest['_note']}. Make a fresh copy of this vault soon.")
    for f in files:
        print(f"  {human_size(f.size):>10}  {clean_text(f.path, 1000)}")
    print(f"{len(files)} files, {human_size(sum(f.size for f in files))}")
    return 0


def cmd_vault_shred(folder: Path, assume_yes: bool = False) -> int:
    """Overwrite and delete a folder that `vault open` created (plaintext copy)."""
    folder = Path(folder).absolute()
    listed = vault.read_marker(folder)
    if listed is None or is_link(folder):
        raise SafetyError(f"{folder} was not created by `sdt vault open` "
                          f"(no valid {vault.OPENED_MARKER} inside). Refusing.")
    folder = folder.resolve()
    if folder.parent == folder or folder == Path.home().resolve():
        raise SafetyError("Refusing to shred a drive root or your user folder.")
    present = {p.relative_to(folder).as_posix() for p in scan_tree(folder).files}
    mine = present & listed
    foreign = sorted(present - listed - {vault.OPENED_MARKER})
    print(f"  !!! ABOUT TO OVERWRITE AND DELETE {len(mine):,} decrypted files in {folder}")
    if foreign:
        print(f"  {len(foreign)} other files in it were NOT written by `vault open` and are "
              "left alone, e.g.:")
        for f in foreign[:5]:
            safe_print(f"      {f}")
    print("  Note: on SSDs, as on USB sticks, overwriting cannot reach every old copy.")
    if not assume_yes and input("  Type 'SHRED' to continue: ").strip().upper() != "SHRED":
        print("Aborted.")
        return 1
    errors = wipe.wipe_files(folder, log=safe_print, only=mine)
    if not errors:
        if foreign:
            print(f"Kept {len(foreign)} files that were not from the vault; the marker stays.")
        else:
            wipe.overwrite_and_delete(folder / vault.OPENED_MARKER)
            try:
                folder.rmdir()
            except OSError as e:
                errors.append(f"{folder}: {e}")
    print(f"{len(errors)} errors")
    return 0 if not errors else 1


def cmd_vault_open(vault_dir: Path, out: Path | None, allow_cloud: bool = False) -> int:
    vault_dir = Path(vault_dir).resolve()  # so "." or a trailing slash work too
    out = out or vault_dir.with_name(vault_dir.name + "_opened")
    print(f"Decrypting {vault_dir} -> {out}")
    print("  Note: the decrypted copy is plaintext. When done:  sdt vault shred \"" f"{out}\"")
    cloud = vault.winfs.cloud_folder(out)
    if cloud and not allow_cloud:
        raise vault.VaultError(f"{out} is inside {cloud}: the decrypted files would be uploaded "
                               "to the cloud. Use --out with another folder (or --allow-cloud).")
    errors = vault.open_vault(vault_dir, out, ask_password(), allow_cloud=allow_cloud,
                              log=safe_print)
    print(f"\n{len(errors)} errors")
    return 0 if not errors else 1
