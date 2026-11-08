<h1 align="center">safedatatransfer</h1>

<p align="center">
  <b>Empty a USB stick into an encrypted vault, verify it, wipe it.<br>
  Send files between two Windows PCs with no router, no cloud, no account.</b>
</p>

<p align="center">
  <a href="https://pypi.org/p/safedatatransfer"><img src="https://img.shields.io/pypi/v/safedatatransfer" alt="PyPI"></a>
  <a href="https://github.com/TheGreatWave21/safedatatransfer/releases/latest"><img src="https://img.shields.io/github/v/release/TheGreatWave21/safedatatransfer" alt="Release"></a>
  <img src="https://img.shields.io/pypi/pyversions/safedatatransfer" alt="Python">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6" alt="Windows">
  <a href="https://github.com/TheGreatWave21/safedatatransfer/blob/main/LICENSE"><img src="https://img.shields.io/github/license/TheGreatWave21/safedatatransfer" alt="License: MIT"></a>
</p>

```powershell
pipx install safedatatransfer

sdt usb evacuate E:       # USB stick -> encrypted vault -> verified -> stick wiped
sdt drop receive          # PC 1: shows a code like 482-913
sdt drop send report.pdf  # PC 2: type the code, done
```

## About

`sdt` is one small command-line tool (with a keyboard-driven UI) that does two things:

- 🔐 **USB vault:** copies **everything** off a USB stick into an encrypted vault (AES-256-GCM, scrypt), checks every file, then wipes the stick.
- 📡 **Local drop:** AirDrop-style transfer between two Windows PCs over **Wi-Fi Direct**, protected by a 6-digit one-time code and end-to-end encryption.

What makes it different:

- ✅ **Nothing is wiped until every file is verified.** It decrypts the vault again, reads it straight from the disk past the Windows cache, and re-reads the stick before wiping.
- 🧷 **Hard to wipe the wrong thing.** It refuses the system disk, a swapped stick, a stick that holds your vault, and links or junctions that point elsewhere.
- 🙈 **Nothing in plaintext.** File contents, names and folder structure are all encrypted.
- 🔥 **No firewall changes, no admin rights, no open ports** while waiting for a sender.
- 📦 **Installs nothing system-wide.** Delete the folder and it's gone.

## Install

You need **Python 3.10+** (`winget install Python.Python.3.13`).

**With pipx** (recommended: it gets its own private environment):

```powershell
pipx install safedatatransfer
sdt
```

**Without installing:** download the [latest release](https://github.com/TheGreatWave21/safedatatransfer/releases/latest) source zip, unpack it, and run:

```powershell
.\sdt
```

On the first run, `sdt.cmd` creates a private `.venv` (1–2 minutes), and installs the **exact pinned versions** from `constraints.txt` there, prebuilt wheels only. It runs Python in isolated mode, so Python files on an untrusted stick are never imported.

<details>
<summary>Install a downloaded wheel by hand</summary>

Each [release](https://github.com/TheGreatWave21/safedatatransfer/releases) lists the SHA-256 of its files.

```powershell
Get-FileHash .\safedatatransfer-0.1.0-py3-none-any.whl     # compare with the release notes
py -m venv $HOME\sdt-env
& $HOME\sdt-env\Scripts\python -I -m pip install --only-binary=:all: .\safedatatransfer-0.1.0-py3-none-any.whl
& $HOME\sdt-env\Scripts\sdt --version
```
</details>

## Usage

### Empty a USB stick

```powershell
sdt usb list                  # find your stick, e.g. E:
sdt usb evacuate E: --dry-run # show what would happen, write nothing
sdt usb evacuate E:           # encrypt -> ~/Downloads/usb-vault/..., verify, wipe
```

<details>
<summary>More USB and vault commands</summary>

```powershell
sdt usb info E:                         # every detail about the stick
sdt usb evacuate E: --dest F:\vault     # put the vault on your other USB stick
sdt usb copy E:                         # encrypted copy only, no wipe
sdt usb wipe E: --method quick          # wipe only
sdt usb wipe E: --method fill           # wipe + fill free space (only when you ask for it)

sdt vault list  "C:\...\usb-vault\vault_20261101-120000"           # see what's inside
sdt vault open  "C:\...\usb-vault\vault_20261101-120000"           # decrypt back to normal files
sdt vault shred "C:\...\usb-vault\vault_20261101-120000_opened"    # remove the decrypted copy
```
</details>

### Send files to another PC

```powershell
sdt drop receive          # on the receiving PC: shows a name like sdt-4821 and a code like 482-913
sdt drop send file.pdf    # on the sending PC: finds it, asks for the code
```

Both PCs only need Wi-Fi switched **on**; they don't need to be on the same network. See [docs/local-drop.md](https://github.com/TheGreatWave21/safedatatransfer/blob/main/docs/local-drop.md) for the security design and first-run notes.

### Interactive UI

Run `sdt` with no arguments. You can watch sticks appear when you plug them in, browse their files, unlock vaults, and follow progress live.

| Key | Action |
|---|---|
| `1` `2` `3` | Drives / Vaults / Activity tab |
| `c` / `e` / `w` | encrypted copy / evacuate (copy → verify → wipe) / wipe |
| `u` / `o` / `l` / `p` | unlock a vault / open (decrypt) it / lock / add a vault from elsewhere |
| `h` | SHA-256 of the selected file |
| `d` | DRY-RUN mode: simulate everything, write nothing |
| `a` / `r` / `b` | show all drives / refresh / hide the banner |
| `?` / `q` | help / quit |

The UI locks unlocked vaults after 10 minutes without input.

## How `evacuate` works

1. **Password:** you type it twice. It must be at least 12 characters, with no very common word and no simple pattern. A few random words work well.
2. **Encrypt:** it checks for free space, then encrypts every file (and hidden NTFS data streams) into the vault.
3. **Verify:** it decrypts every file again, read past the Windows cache, and compares SHA-256 with the original. **If any file fails, nothing is wiped.**
4. **Same stick?** It checks volume serial, size, file system, hardware serial and disk number.
5. **Prove the password:** you type it once more (3 tries), so you can't lock yourself out.
6. **Confirm:** you type `WIPE E:`. It shows how many files and how much data will be destroyed, then checks the stick and the vault files once more.
7. **Re-read:** it reads the whole stick again and compares every SHA-256 with the vault. Anything new, changed or unreadable stops the wipe.
8. **Wipe:**
   - `quick` (default): each file is overwritten with random data, renamed, and deleted. On FAT32/exFAT this includes the slack space at the end of the file's last cluster. Old directory entries that still hold the original file names are overwritten too. Free space is **not** touched.
   - `fill` (**only with `--method fill`**): everything `quick` does, plus all free space is filled with random data and then freed again. This also erases traces of files deleted earlier.
9. **Check:** it confirms the stick is really empty and reports anything left.

<details>
<summary><b>All safety rules</b></summary>

- Never touches the system drive, or anything on the same physical disk as Windows.
- Only `removable` drives, unless you pass `--allow-fixed`.
- Refuses if the vault would be on the drive being wiped. This is checked by volume serial, so mount folders and `subst` drives are caught too.
- **Links and junctions are never followed.** A junction on the stick that points at e.g. `C:\Users` is neither copied nor wiped through; only the link itself is removed.
- Only wipes when the stick holds exactly the files that were verified. A file that appeared or changed after the copy stops the wipe, even if its size and timestamp stayed the same.
- A folder that can't be read makes the copy fail, so nothing unread is ever wiped.
- Refuses a stick that sdt itself (or its Python) runs from.
- Refuses a stick that holds an sdt vault (probably your backup; `--allow-vault` overrides).
- Refuses vault destinations in a Temp folder or a Recycle Bin, which Windows may empty.
- While wiping, it re-checks every few seconds that it's still the same stick and stops if not. Right before each file, it checks the file really is inside the stick.
- A file with a second name (NTFS hard link) only loses that name; its data is overwritten when its last name is wiped.
- `$RECYCLE.BIN` is copied and wiped like any other folder (deleted files are often the secret ones). Only `System Volume Information` is skipped.
- The default vault name (`vault_<date>`) doesn't contain the stick's label; the label is stored inside the encrypted manifest.
</details>

<details>
<summary><b>Vault format and encryption</b></summary>

- **Key:** scrypt (n=2¹⁸, about 256 MB and 0.5 s per guess) turns the password into a key. Older vaults keep their own setting.
- **Per-file keys:** HKDF derives a separate key for each file.
- **Encryption:** AES-256-GCM in 1 MiB chunks, so any change, truncation or reordering is detected.
- **Passwords** are Unicode-normalized, so the same password typed on another keyboard still works.
- **If you forget the password, the data is gone.**

| File | Contents |
|---|---|
| `vault.json` | salt and KDF settings (not secret) |
| `manifest.enc` + `manifest.backup.enc` | encrypted file list, stored twice; if one is damaged, the other is used and `sdt vault list` warns you |
| `blobs/<random>.enc` | one per file or data stream |

Blob sizes still roughly reveal file sizes. An interrupted copy shows up as `INCOMPLETE` in `sdt vault info`.

`sdt vault open` writes **plaintext**, so it:
- refuses OneDrive, Dropbox and Google Drive folders unless you pass `--allow-cloud`;
- only writes into an empty or new folder;
- marks the files "do not index" for Windows Search;
- overwrites partially written files before deleting them;
- leaves a `.sdt-opened` marker. `sdt vault shred` refuses any folder without it, and only destroys the files that `open` wrote.
</details>

<details>
<summary><b>Local drop security</b></summary>

- **Code:** a 6-digit code checked with SPAKE2. An attacker gets one guess per session, and recorded traffic doesn't help.
- **Encryption:** everything is end-to-end encrypted with AES-256-GCM, including file names and sizes.
- **No open ports while waiting.** After the link is up, only the PC at the other end can connect, and only once.
- **Random name:** the receiver advertises a random name (`sdt-4821`), not your PC's name.
- **Approval:** you see the file list and must type `y` before anything is saved.
- **File names** are sanitized: no `..`, no reserved names, no invisible right-to-left tricks.
- **Received files** get the "Mark of the Web", like browser downloads.
- **Pairing:** Wi-Fi Direct pairings made for a transfer are removed afterwards.

Full details: [docs/local-drop.md](https://github.com/TheGreatWave21/safedatatransfer/blob/main/docs/local-drop.md).
</details>

## Limitation of wiping

USB flash drives move data around internally (wear levelling) and keep spare blocks that Windows can't reach. **No software overwrite can guarantee** that every old copy is gone. For really secret data:

- keep the data **encrypted** on the stick too (BitLocker To Go or VeraCrypt), so wiping it means the key is gone, and/or
- **physically destroy** the stick after evacuating it.

## Status

The USB vault is tested on real sticks and `subst` drives. Local drop's protocol is covered by automated tests. A real PC-to-PC Wi-Fi Direct transfer still needs testing with two PCs. Feedback and issues are welcome.

<details>
<summary>Project layout and tests</summary>

| Folder | Contents |
|---|---|
| `src/safedatatransfer/usb_vault/` | copy, verify, vault, wipe |
| `src/safedatatransfer/local_drop/` | protocol, Wi-Fi Direct and LAN links |
| `src/safedatatransfer/common/` | encryption, hashing, drive detection |
| `src/safedatatransfer/tui/` | interactive UI |

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```
</details>

## License

[MIT](https://github.com/TheGreatWave21/safedatatransfer/blob/main/LICENSE). Use at your own risk, and read [Limitation of wiping](#limitation-of-wiping) before trusting any wipe with secret data.
