# safedatatransfer

Two tools in one CLI (`sdt`), each in its own folder. Everything they write or send is encrypted.

| Part | Folder | What it does |
|---|---|---|
| **USB vault** | `src/safedatatransfer/usb_vault/` | Copies everything off a USB stick into an **encrypted vault**, verifies it, then erases the stick |
| **Local drop** | `src/safedatatransfer/local_drop/` | AirDrop-style transfer between Windows PCs over **Wi-Fi Direct** (no router), with a one-time code and end-to-end encryption |

Shared code (encryption, hashing, drive detection) is in `src/safedatatransfer/common/`.

## Start

The only thing you need is **Python 3.10+** (`winget install Python.Python.3.13`). Then:

```powershell
.\sdt            # opens the interactive UI
.\sdt usb list   # or any CLI command
```

`sdt.cmd` creates a private environment in `.venv` on first run (about 1–2 minutes) and
installs everything **there**. Nothing is installed system-wide, and later starts are instant.
To remove everything, delete the folder.

`sdt.cmd` runs Python in isolated mode (`-I`). Python files in the folder you start it from,
for example the root of an untrusted stick, are never imported.

Dependencies (inside `.venv` only): `cryptography`, `spake2`, `textual` (UI), and the
`winrt-*` packages for Wi-Fi Direct. `sdt.cmd` installs the **exact versions** listed in
`constraints.txt` (and a pinned build tool in `pyproject.toml`), and only prebuilt wheels, so a new (possibly compromised) release is
never pulled in silently and no third-party build scripts run.

## Interactive UI

Run `sdt` with no arguments. Everything is keyboard-driven, and the mouse works too.

| Key | Action |
|---|---|
| `1` `2` `3` | Drives / Vaults / Activity tab |
| `↑ ↓ ← →` `tab` | move through lists, the file tree and panels |
| `c` / `e` / `w` | encrypted copy / evacuate (copy → verify → wipe) / wipe the selected drive |
| `h` | SHA-256 of the selected file |
| `u` / `o` / `l` / `p` | unlock a vault (list all files) / open (decrypt) it / lock / add a vault from elsewhere |
| `d` | DRY-RUN mode: simulate everything, write nothing |
| `a` / `r` / `b` | show all drives / refresh / hide the banner |
| `?` / `q` | help / quit |

What you can see in the UI:
- **Drives:** USB sticks are detected the moment they're plugged in or removed. For each one:
  label, file system, volume serial, capacity/used/free, vendor and model, firmware, hardware
  serial, bus (USB/SD/…), physical disk number, sector and cluster size, file-system features,
  file and folder counts, largest file, top file types, newest change, and whether it may be
  wiped.
- **Files:** browse the stick as a tree. Each file shows its size, created/modified/accessed
  times, attributes and (with `h`) its SHA-256.
- **Vaults:** details readable without the password (KDF parameters, salt, file count,
  size), and after unlocking every file with its size, date and SHA-256.
- **Activity:** live progress bar and a log of every step.

The same information is available as plain text: `sdt usb info E:` and `sdt vault info DIR`.

## Part 1: USB vault (CLI)

```powershell
sdt usb list                              # find your stick, e.g. E:
sdt usb info E:                           # every detail about it
sdt usb evacuate E: --dry-run             # show what would happen
sdt usb evacuate E:                       # encrypt -> ~/Downloads/usb-vault/..., verify, wipe
sdt usb evacuate E: --dest F:\vault       # put the vault on your other USB stick
sdt usb copy E:                           # encrypted copy only, no wipe
sdt usb wipe E: --method quick            # wipe only

sdt vault list  "C:\...\usb-vault\vault_20261101-120000"           # see what's inside
sdt vault open  "C:\...\usb-vault\vault_20261101-120000"           # decrypt back to normal files
sdt vault shred "C:\...\usb-vault\vault_20261101-120000_opened"    # remove the decrypted copy
```

What `evacuate` does:
1. Asks you for a vault password, typed twice: at least 12 characters, no very common
   word, no simple pattern. A few random words work well.
2. Checks that the destination has enough free space, then encrypts every file into the
   vault. **Nothing is written in plaintext**: file contents, names and folder structure
   are all encrypted. Hidden NTFS data streams ("alternate data streams") are copied too.
3. Decrypts every file again, read **past the Windows cache** straight from the
   destination disk, and compares SHA-256 with the original, so a faulty disk is noticed.
   **If any file fails, nothing is wiped.**
4. Checks that it is still the same stick: volume serial, size, file system, hardware
   serial and disk number.
5. Asks you to type the vault password **once more**, to prove you can open the new vault.
   If you can't (3 tries), nothing is wiped.
6. Asks you to type `WIPE E:`, showing how many files and how much data will be destroyed,
   then checks the stick once more (in case it was swapped) and that every file of the
   vault is still there (e.g. the destination stick wasn't unplugged).
7. **Reads the whole stick again** (past the cache) and compares every file's SHA-256 with
   the vault. Anything new, changed or unreadable stops the wipe, even an edit that kept
   the file's size and timestamp.
8. Wipes with the selected method:
   - `quick` (default): overwrite each file with random data. On FAT32/exFAT this goes up
     to the end of the file's last cluster, so leftovers of older files in that slack go
     too. Then rename it to a random name and delete it. Finally, overwrite the deleted
     directory entries that still hold the **original file names**, by creating and
     removing empty placeholder files. Free space is **not** touched.
   - `fill` (**only when you choose it**, `--method fill`): `quick` + fill all free space with
     random data, flush it to the stick, then delete the filler. The stick ends up empty.
     This also erases traces of files deleted earlier.

   Hidden NTFS data streams are overwritten before their file is deleted.
   Neither method needs admin rights or runs external programs.
9. Checks that the stick really is empty and reports anything that is left.

Safety rules:
- never touches the system drive; only `removable` drives unless you pass `--allow-fixed`;
- refuses if the vault would be on the drive being wiped (checked by volume serial, so
  mount folders and `subst` drives are caught too);
- **links and junctions are never followed.** An NTFS stick can contain a junction that
  points at e.g. `C:\Users`; it is neither copied nor wiped through, only the link entry
  itself is removed;
- `evacuate` only wipes when the stick holds exactly the files that were verified in the
  vault. A file that appeared or changed after the copy stops the wipe;
- a folder that cannot be read makes the copy fail, so nothing unread is ever wiped;
- refuses a stick that sdt itself (or its Python) runs from, and anything on the same
  physical disk as Windows;
- refuses a stick that holds an sdt vault (probably your backup; `--allow-vault` overrides);
- refuses vault destinations in a Temp folder or a Recycle Bin, which Windows may empty;
- while wiping, re-checks every few seconds that it is still the same stick, and stops if
  not; right before each file it checks the file is really inside the stick;
- a file with a second name (NTFS hard link) only loses that name; its data is overwritten
  when its last name is wiped.

`sdt vault shred` only destroys the files that `vault open` wrote (they are listed in the
folder's `.sdt-opened` marker). Files you added to the folder later are left alone.

The default vault folder name (`vault_<date>`) doesn't contain the stick's label. The
label is stored inside the encrypted manifest.

`$RECYCLE.BIN` on the stick is copied and wiped like any other folder (deleted files are
often the secret ones). Only `System Volume Information` (managed by Windows) is skipped.

**Vault encryption:** scrypt (n=2¹⁸, ~256 MB and ~0.5 s per guess; older vaults keep
their own setting) turns the password into a key;
HKDF derives a separate key per file; AES-256-GCM in 1 MiB chunks, so any change,
truncation or reordering is detected. **If you forget the password, the data is gone.**
The password is Unicode-normalized, so the same password typed on another keyboard or PC
(e.g. `ü` entered as one or as two characters) still opens the vault.

Layout: `vault.json` (salt, not secret) · `manifest.enc` and an identical
`manifest.backup.enc` (encrypted file list; if one copy gets damaged the other is used,
and `sdt vault list` warns you) · `blobs/<random>.enc` (one per file or data stream).
Blob sizes still roughly reveal file sizes. A vault whose copy was interrupted shows up
as `INCOMPLETE` in `sdt vault info`.

`sdt vault open` writes **plaintext** files, so it:
- refuses OneDrive/Dropbox/Google Drive folders, where the files would be uploaded,
  unless you pass `--allow-cloud`;
- marks the folder and files "do not index", so Windows Search doesn't keep their contents;
- overwrites partially written files before deleting them, if something fails;
- leaves a `.sdt-opened` marker, so that `sdt vault shred FOLDER` can overwrite and delete
  the folder when you're done. `shred` refuses any folder without that marker.

### Limitation of wiping

USB flash drives move data around internally (wear levelling) and keep spare blocks
that Windows cannot reach. No software overwrite can **guarantee** that every old copy
of the data is gone. For super-secret data:
- keep the data **encrypted** on the stick too (BitLocker To Go or VeraCrypt), so erasing it means the key is gone, and/or
- **physically destroy** the stick after evacuating it.

## Part 2: Local drop

```powershell
sdt drop receive            # on the receiving PC: shows a name like sdt-4821 and a code like 482-913
sdt drop send file.pdf      # on the sending PC: finds it, asks for the code
```

The receiver shows up nearby under a random name (`sdt-4821`), not your PC's name; pick
your own with `--name`. Wi-Fi Direct pairings made for a transfer are removed again when
it ends, so Windows doesn't keep trusting the other device.

See [docs/local-drop.md](docs/local-drop.md) for how it works, the security design and
first-run notes (firewall, pairing).

## Tests

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

## License

MIT, see [LICENSE](LICENSE). Use at your own risk: read the "Limitation of wiping"
section before trusting any wipe with secret data.
