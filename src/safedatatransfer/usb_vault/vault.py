"""Encrypted vault: where evacuated USB data is stored. Nothing is written in plaintext.

Layout:
    <vault>/vault.json        scrypt salt + parameters (not secret)
    <vault>/manifest.enc      encrypted JSON: original paths, sizes, SHA-256, blob ids
    <vault>/blobs/<id>.enc    one encrypted blob per file (random names, no metadata)

File names, folder structure and sizes are only visible after unlocking the manifest.
(Blob sizes on disk still roughly reveal file sizes.)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable

from safedatatransfer.common import crypto, winfs
from safedatatransfer.usb_vault.transfer import FileEntry, TransferResult, scan_tree

VAULT_FILE = "vault.json"
MANIFEST_FILE = "manifest.enc"
MANIFEST_BACKUP = "manifest.backup.enc"  # identical copy, used if the main one is damaged
BLOB_DIR = "blobs"
MANIFEST_AAD = b"sdt-vault-manifest-v1"
OPENED_MARKER = ".sdt-opened"  # put in folders written by open_vault; `vault shred` needs it


class VaultError(Exception):
    pass


Progress = Callable[[int, int], None]  # (bytes_done, bytes_total)


class _CountingReader:
    """Wraps a file so every read reports progress."""

    def __init__(self, f, on_bytes: Callable[[int], None]):
        self._f, self._on = f, on_bytes

    def read(self, n: int = -1) -> bytes:
        data = self._f.read(n)
        self._on(len(data))
        return data


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _keys(password: str, params: crypto.ScryptParams) -> tuple[bytes, bytes]:
    master = crypto.derive_master_key(password, params)
    return crypto.hkdf(master, b"sdt-vault manifest"), master


def _file_key(master: bytes, blob_id: bytes) -> bytes:
    return crypto.hkdf(master, b"sdt-vault file " + blob_id)


# Placeholder for dry runs: nothing is encrypted or written, so it is never used as a key.
DRY_RUN_PASSWORD = "dry-run-password"


def check_password(password: str) -> None:
    """Rules for NEW vault passwords (any existing vault still opens with its password)."""
    problem = crypto.password_problem(password)
    if problem:
        raise VaultError(problem)


def create_vault(
    source: Path,
    vault_dir: Path,
    password: str,
    *,
    source_label: str = "",
    dry_run: bool = False,
    log: Callable[[str], None] = print,
    scrypt_n: int = 2**18,  # ~256 MiB of memory and ~0.5 s per password guess
    progress: Progress | None = None,
) -> TransferResult:
    """Encrypt every file under source into a new vault, then decrypt-verify each blob."""
    if not dry_run:  # a dry run writes nothing, so its placeholder password is not checked
        check_password(password)
    source = source.resolve()
    vault_dir = vault_dir.resolve()
    if vault_dir == source or vault_dir.is_relative_to(source):
        raise ValueError("Destination must not be inside the source.")

    result = TransferResult(
        source=str(source), destination=str(vault_dir),
        started=datetime.now(timezone.utc).isoformat(),
    )
    scan = scan_tree(source)
    for err in scan.errors:
        result.errors.append(err)
        log(f"  ERROR {err}")
    for link in scan.links:
        rel = link.relative_to(source).as_posix()
        result.links.append(rel)
        log(f"  note: {rel} is a link/junction to somewhere else; not followed, not copied")
    # Enough room at the destination? Better to refuse now than fail half-way through.
    needed = 1 << 20
    for src in scan.files:
        try:
            size = src.stat().st_size + sum(s for _, s in winfs.list_streams(src))
        except OSError:
            continue
        needed += size + (size // crypto.CHUNK_SIZE + 2) * 20 + crypto.HEADER_LEN + 4096
    probe = vault_dir
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    free = shutil.disk_usage(probe).free
    if needed > free:
        raise VaultError(f"Not enough space at {probe}: the vault needs about "
                         f"{needed / 2**20:,.0f} MiB, only {free / 2**20:,.0f} MiB are free.")

    if dry_run:
        for src in scan.files:
            rel = src.relative_to(source)
            log(f"[dry-run] would encrypt {rel}")
            st = src.stat()
            result.files.append(FileEntry(rel.as_posix(), st.st_size, "", st.st_mtime, tuple(
                (n, s, "") for n, s in winfs.list_streams(src))))
        return result

    params = crypto.ScryptParams(salt=os.urandom(16), n=scrypt_n)
    # Unicode-normalized, so the same password typed on another keyboard/PC still works.
    manifest_key, master = _keys(crypto.normalize_password(password), params)
    blobs = vault_dir / BLOB_DIR
    blobs.mkdir(parents=True, exist_ok=False)
    (vault_dir / VAULT_FILE).write_text(json.dumps({
        "format": "sdt-vault", "version": 1,
        "kdf": {"name": "scrypt", "n": params.n, "r": params.r, "p": params.p,
                "salt": _b64(params.salt)},
    }, indent=2), encoding="utf-8")

    sources = scan.files
    total = 0
    for src in sources:
        try:
            total += src.stat().st_size * 2  # encrypt pass + verify pass
        except OSError:
            pass
    done = 0

    def advance(n: int) -> None:
        nonlocal done
        done += n
        if progress:
            progress(done, total)

    advance(0)
    warned_cache = False

    def encrypt_one(path: str) -> tuple[str, str]:
        """Encrypt one file (or one data stream "file:name") into a new blob, then verify
        the blob by decrypting it again straight from the disk. Returns (blob, sha256)."""
        nonlocal warned_cache
        blob_id = secrets.token_bytes(crypto.BLOB_ID_LEN)
        blob_path = blobs / (blob_id.hex() + ".enc")
        key = _file_key(master, blob_id)
        with open(path, "rb") as fin, open(blob_path, "wb") as fout:
            digest = crypto.encrypt_stream(_CountingReader(fin, advance), fout, key, blob_id)
            fout.flush()
            os.fsync(fout.fileno())
        # Bypass the Windows cache, so a faulty destination disk is noticed.
        reader, uncached = winfs.open_for_verify(blob_path)
        with reader as fin:
            if crypto.decrypt_stream(fin, None, key) != digest:
                raise crypto.DecryptionError("verification hash mismatch")
        if not uncached and not warned_cache:
            warned_cache = True
            log("  note: this destination cannot be read past the Windows cache; "
                "verification used the cache")
        result.blob_sizes[f"{BLOB_DIR}/{blob_id.hex()}.enc"] = blob_path.stat().st_size
        return blob_id.hex(), digest

    entries: list[dict] = []
    for src in sources:
        rel = src.relative_to(source)
        try:
            before = src.stat()
            blob, src_hash = encrypt_one(str(src))
            # Hidden NTFS data streams travel with the file (FAT/exFAT have none).
            streams = []
            for name, _size in winfs.list_streams(src):
                s_blob, s_hash = encrypt_one(f"{src}:{name}")
                s_size = os.stat(f"{src}:{name}").st_size
                streams.append({"name": name, "size": s_size, "sha256": s_hash, "blob": s_blob})
                log(f"  + data stream {rel}:{name}")
            st = src.stat()
            if (st.st_size, st.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
                raise OSError("file changed while it was being copied; run again")
            advance(st.st_size)
            result.files.append(FileEntry(
                rel.as_posix(), st.st_size, src_hash, st.st_mtime,
                tuple((s["name"], s["size"], s["sha256"]) for s in streams)))
            entry = {"path": rel.as_posix(), "size": st.st_size, "sha256": src_hash,
                     "mtime": st.st_mtime, "blob": blob}
            if streams:
                entry["streams"] = streams
            entries.append(entry)
            log(f"  ok {rel}")
        except (OSError, crypto.DecryptionError) as e:
            result.errors.append(f"{rel}: {e}")
            log(f"  ERROR {rel}: {e}")

    result.finished = datetime.now(timezone.utc).isoformat()
    manifest = {"source": str(source), "label": source_label, "started": result.started,
                "finished": result.finished, "files": entries, "errors": result.errors}
    sealed = crypto.seal(manifest_key, json.dumps(manifest).encode("utf-8"), MANIFEST_AAD)
    # Two copies, each written atomically: one damaged byte in the only manifest would
    # make every file name unrecoverable.
    for name in (MANIFEST_FILE, MANIFEST_BACKUP):
        tmp = vault_dir / (name + ".tmp")
        with open(tmp, "wb") as f:
            f.write(sealed)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, vault_dir / name)
    # Prove both copies read back (from the disk, not the cache) before anyone wipes anything.
    for name in (MANIFEST_FILE, MANIFEST_BACKUP):
        reader, _ = winfs.open_for_verify(vault_dir / name)
        with reader as f:
            data = f.read(-1)
        try:
            ok = json.loads(crypto.unseal(manifest_key, data, MANIFEST_AAD))["files"] == entries
        except (crypto.DecryptionError, ValueError):
            ok = False
        if not ok:
            result.errors.append(f"{name}: verification failed")
        result.blob_sizes[name] = len(sealed)
    return result


def vault_still_present(vault_dir: Path, blob_sizes: dict[str, int]) -> str | None:
    """Right before a wipe: is every file of the new vault still there, with its size?
    (E.g. the vault was written to another USB stick that has been unplugged since.)
    Returns None if all is well, else the reason."""
    if not blob_sizes:
        return "nothing was recorded for the vault"
    for rel, size in blob_sizes.items():
        p = Path(vault_dir) / rel
        try:
            if p.stat().st_size != size:
                return f"{p} has changed size since it was verified"
        except OSError:
            return f"{p} is no longer reachable (is the destination still connected?)"
    return None


def find_vaults_under(root: Path) -> list[Path]:
    """sdt vaults stored somewhere under root (e.g. on a stick that is about to be wiped)."""
    return sorted({p.parent for p in scan_tree(root).files
                   if p.name == VAULT_FILE and (p.parent / BLOB_DIR).is_dir()})


def read_meta(vault_dir: Path) -> dict:
    """vault.json, with a clear error for a wrong folder or a damaged file (no password needed).
    Callers check this before asking for the password."""
    vault_dir = Path(vault_dir)
    if not vault_dir.exists():
        raise VaultError(f"{vault_dir} does not exist.")
    if not vault_dir.is_dir():
        raise VaultError(f"{vault_dir} is a file. Give the vault folder (the one with "
                         f"{VAULT_FILE} in it).")
    meta_file = vault_dir / VAULT_FILE
    if not meta_file.is_file():
        raise VaultError(f"{vault_dir} is not an sdt vault: it has no {VAULT_FILE}.")
    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
    except OSError as e:
        raise VaultError(f"Cannot read {meta_file}: {e.strerror or e}") from e
    except ValueError as e:
        raise VaultError(f"{meta_file} is damaged (not valid JSON).") from e
    if not isinstance(meta, dict) or meta.get("format") != "sdt-vault":
        raise VaultError(f"{meta_file} is not an sdt vault file.")
    if meta.get("version") != 1:
        raise VaultError(f"Unsupported vault version {meta.get('version')!r}: "
                         "it was made by a newer sdt.")
    return meta


def check_open_target(out_dir: Path, *, allow_cloud: bool = False) -> None:
    """Where open_vault may write plaintext. Checked before the password is asked."""
    out_dir = Path(out_dir)
    cloud = winfs.cloud_folder(out_dir)
    if cloud and not allow_cloud:
        raise VaultError(f"{out_dir} is inside {cloud}: the decrypted files would be uploaded "
                         "to the cloud. Choose another folder (or pass --allow-cloud).")
    # Only a new or empty folder: it gets the marker that lets `vault shred` destroy it, so
    # it must never be a folder with other files in it (e.g. Documents).
    if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
        raise VaultError(f"{out_dir} already exists and is not empty. Choose a new folder.")


def _unlock(vault_dir: Path, password: str) -> tuple[dict, bytes]:
    meta = read_meta(vault_dir)
    params = _kdf_params(meta)
    copies = []
    for name in (MANIFEST_FILE, MANIFEST_BACKUP):
        try:
            copies.append((name, (vault_dir / name).read_bytes()))
        except OSError:
            pass
    if not copies:
        raise VaultError(f"{vault_dir} has no manifest (the copy was interrupted?).")
    # New vaults use the NFC form of the password; very old ones may use the raw form.
    candidates = [crypto.normalize_password(password)]
    if password not in candidates:
        candidates.append(password)
    for pw in candidates:
        manifest_key, master = _keys(pw, params)
        for name, data in copies:
            try:
                manifest = json.loads(crypto.unseal(manifest_key, data, MANIFEST_AAD))
            except (crypto.DecryptionError, ValueError):
                continue
            if name != MANIFEST_FILE:
                manifest["_note"] = "main manifest damaged; opened from the backup copy"
            return manifest, master
    raise VaultError("Wrong password, or the vault was modified.")


def _kdf_params(meta: dict) -> crypto.ScryptParams:
    """Read and sanity-check the KDF settings, so a tampered vault.json cannot make
    unlocking eat all memory or use a uselessly weak setting."""
    try:
        k = meta["kdf"]
        n, r, p = int(k["n"]), int(k["r"]), int(k["p"])
        salt = base64.b64decode(k["salt"], validate=True)
    except (KeyError, TypeError, ValueError) as e:
        raise VaultError(f"vault.json has invalid key-derivation settings: {e}") from e
    valid = (k.get("name") == "scrypt" and n & (n - 1) == 0 and 2**14 <= n <= 2**20
             and 1 <= r <= 16 and 1 <= p <= 4 and len(salt) >= 16)
    if not valid:
        raise VaultError("vault.json has unexpected key-derivation settings (modified?).")
    return crypto.ScryptParams(salt=salt, n=n, r=r, p=p)


def _disk_sha256(path: str) -> str:
    """SHA-256 of what is really stored (read past the Windows cache when possible)."""
    h = hashlib.sha256()
    reader, _ = winfs.open_for_verify(Path(path))
    with reader as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def unverified_files(root: Path, verified: list[FileEntry], *, rehash: bool = False,
                     log: Callable[[str], None] | None = None) -> list[str]:
    """Files under root that are NOT exactly as verified in the vault (new, changed, or
    unreadable). Used right before a wipe: only data that is safely in the vault may go.

    rehash=True also reads every file again from the stick and compares its SHA-256 with
    the vault, so even an edit that kept size and timestamp is caught."""
    known = {f.path: f for f in verified}
    root = Path(root)
    scan = scan_tree(root)
    problems = list(scan.errors)
    if rehash and log:
        log(f"Re-reading {len(scan.files)} files from the stick to compare with the vault...")
    for p in scan.files:
        rel = p.relative_to(root).as_posix()
        f = known.get(rel)
        try:
            st = p.stat()
            if f is None:
                problems.append(f"{rel}: not in the vault (new file?)")
                continue
            if st.st_size != f.size or st.st_mtime != f.mtime:
                problems.append(f"{rel}: changed after it was copied")
                continue
            streams = winfs.list_streams(p)
            if sorted((n, s) for n, s in streams) != sorted((n, s) for n, s, _ in f.streams):
                problems.append(f"{rel}: its hidden data streams changed after the copy")
                continue
            if rehash:
                if _disk_sha256(str(p)) != f.sha256:
                    problems.append(f"{rel}: content on the stick differs from the vault")
                    continue
                want = {n: h for n, _, h in f.streams}
                if any(_disk_sha256(f"{p}:{n}") != want[n] for n, _ in streams):
                    problems.append(f"{rel}: a data stream differs from the vault")
        except OSError as e:
            problems.append(f"{rel}: {e}")
    return problems


def load_manifest(vault_dir: Path, password: str) -> dict:
    return _unlock(Path(vault_dir), password)[0]


def _safe_relpath(path: str) -> Path:
    parts = PurePosixPath(path).parts
    if not parts or any(p in ("", ".", "..") or ":" in p or "\\" in p for p in parts) \
            or PurePosixPath(path).is_absolute():
        raise VaultError(f"Unsafe path in manifest: {path!r}")
    return Path(*parts)


def open_vault(
    vault_dir: Path, out_dir: Path, password: str, *, log: Callable[[str], None] = print,
    progress: Progress | None = None, allow_cloud: bool = False,
) -> list[str]:
    """Decrypt every file into out_dir and verify its SHA-256. Returns error messages.

    The output is plaintext, so: refuses cloud-synced folders (OneDrive, Dropbox, ...)
    unless allow_cloud, marks everything "do not index" for Windows Search, and
    overwrites partial files before deleting them."""
    vault_dir = Path(vault_dir)
    out_dir = Path(out_dir)
    check_open_target(out_dir, allow_cloud=allow_cloud)
    manifest, master = _unlock(vault_dir, password)
    out_dir.mkdir(parents=True, exist_ok=True)
    winfs.set_not_indexed(out_dir)
    # The marker lists every file this will write (and its temporary name), written BEFORE
    # decrypting: `vault shred` destroys exactly these, even after an interruption, and
    # leaves anything you add to the folder later alone.
    planned = []
    for e in manifest["files"]:
        rel = _safe_relpath(e["path"]).as_posix()
        planned += [rel, rel + ".sdt-partial"]
    write_marker(out_dir, planned)
    errors: list[str] = []
    total = sum(int(e["size"]) for e in manifest["files"])
    done = 0
    if progress:
        progress(0, total)
    for e in manifest["files"]:
        rel = _safe_relpath(e["path"])
        dst = out_dir / rel
        tmp = dst.with_name(dst.name + ".sdt-partial")
        try:
            if dst.exists():
                raise VaultError("already exists, not overwriting")
            dst.parent.mkdir(parents=True, exist_ok=True)
            winfs.set_not_indexed(dst.parent)
            blob_id = bytes.fromhex(e["blob"])
            with open(vault_dir / BLOB_DIR / (e["blob"] + ".enc"), "rb") as fin, \
                    open(tmp, "wb") as fout:
                got = crypto.decrypt_stream(fin, fout, _file_key(master, blob_id))
            if got != e["sha256"]:
                raise VaultError("hash mismatch")
            stream_errors = _restore_streams(vault_dir, master, e.get("streams", []), tmp)
            winfs.set_not_indexed(tmp)
            os.replace(tmp, dst)
            os.utime(dst, (e["mtime"], e["mtime"]))
            for msg in stream_errors:
                errors.append(f"{rel}:{msg}")
                log(f"  ERROR {rel}:{msg}")
            log(f"  ok {rel}")
        except (OSError, VaultError, crypto.DecryptionError) as err:
            winfs.discard(tmp)  # partial plaintext: overwrite, then delete
            errors.append(f"{rel}: {err}")
            log(f"  ERROR {rel}: {err}")
        done += int(e["size"])
        if progress:
            progress(done, total)
    return errors


def write_marker(folder: Path, files: list[str]) -> None:
    data = {"sdt": "opened-vault", "note": "Decrypted by sdt. Remove with: sdt vault shred "
            "<this folder>. Only the files listed here are destroyed.", "files": files}
    (folder / OPENED_MARKER).write_text(json.dumps(data, indent=1), encoding="utf-8")


def read_marker(folder: Path) -> set[str] | None:
    """Files `vault open` wrote into folder, or None if folder has no valid sdt marker."""
    try:
        data = json.loads((folder / OPENED_MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("sdt") != "opened-vault" \
            or not isinstance(data.get("files"), list):
        return None
    return {str(f) for f in data["files"]}


def _restore_streams(vault_dir: Path, master: bytes, streams: list[dict], target: Path) -> list[str]:
    """Write a file's hidden NTFS data streams back. Needs an NTFS destination."""
    errors = []
    for s in streams:
        name = str(s.get("name", ""))
        if not name or any(c in name for c in ':\\/\x00') or len(name) > 255:
            errors.append(f"{name!r}: unsafe stream name, skipped")
            continue
        try:
            with open(vault_dir / BLOB_DIR / (s["blob"] + ".enc"), "rb") as fin, \
                    open(f"{target}:{name}", "wb") as fout:
                got = crypto.decrypt_stream(fin, fout, _file_key(master, bytes.fromhex(s["blob"])))
            if got != s["sha256"]:
                raise VaultError("hash mismatch")
        except (OSError, VaultError, crypto.DecryptionError, KeyError, ValueError) as err:
            errors.append(f"{name}: data stream not restored ({err}; the destination must be NTFS)")
    return errors


def manifest_summary(manifest: dict) -> list[FileEntry]:
    return [FileEntry(e["path"], e["size"], e["sha256"], e.get("mtime", 0.0))
            for e in manifest["files"]]



def vault_info(vault_dir: Path) -> list[tuple[str, str]]:
    """Everything readable about a vault WITHOUT the password."""
    vault_dir = Path(vault_dir)
    meta = read_meta(vault_dir)
    blobs = list((vault_dir / BLOB_DIR).glob("*.enc"))
    manifests = [m for m in (MANIFEST_FILE, MANIFEST_BACKUP) if (vault_dir / m).is_file()]
    on_disk = (sum(b.stat().st_size for b in blobs)
               + sum((vault_dir / m).stat().st_size for m in manifests))
    if not manifests:
        state = "INCOMPLETE: no manifest (the copy was interrupted); cannot be opened"
    elif len(manifests) == 1 and MANIFEST_FILE in manifests and blobs:
        state = "1 manifest copy (made by an older sdt)"
    else:
        state = f"{len(manifests)} manifest copies"
    # Shown only when the settings are valid: a tampered vault.json must not crash `info`.
    try:
        params = _kdf_params(meta)
        kdf = f"scrypt  N=2^{params.n.bit_length() - 1}  r={params.r}  p={params.p}"
        salt = meta["kdf"]["salt"]
    except VaultError as e:
        kdf, salt = f"INVALID: {e}", "?"
    created = datetime.fromtimestamp((vault_dir / VAULT_FILE).stat().st_mtime)
    return [
        ("Vault", str(vault_dir)),
        ("Format", f"{meta.get('format')} v{meta.get('version')}"),
        ("Created", created.strftime("%Y-%m-%d %H:%M:%S")),
        ("Encrypted files", str(len(blobs))),
        ("State", state),
        ("Size on disk", f"{on_disk:,} bytes"),
        ("Key derivation", kdf),
        ("Salt", str(salt)),
        ("Cipher", "AES-256-GCM, 1 MiB chunks, HKDF-SHA256 key per file"),
    ]


def find_vaults(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    found = [d for d in root.iterdir() if (d / VAULT_FILE).is_file()]
    return sorted(found, key=lambda d: (d / VAULT_FILE).stat().st_mtime, reverse=True)
