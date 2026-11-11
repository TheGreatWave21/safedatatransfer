"""A damaged vault must never give back wrong data silently.

Each case damages a copy of a real vault (flipped bytes, cut or added data, moved chunks,
swapped or missing files, edited vault.json/manifest) and opens it. Rule for every case:
  - a file in the output is byte-for-byte the original, and
  - every file that is missing from the output is reported as an error (or opening fails
    with a clear VaultError/DecryptionError), and
  - no partial plaintext is left behind."""

import contextlib
import functools
import getpass
import io
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from safedatatransfer import cli
from safedatatransfer.common import crypto
from safedatatransfer.usb_vault import vault

PW = "correct horse battery"
MiB = 1 << 20


def _records(blob: bytes) -> tuple[bytes, list[bytes]]:
    """Split a blob into its header and its chunk records (LEN + ciphertext)."""
    header, pos, recs = blob[:crypto.HEADER_LEN], crypto.HEADER_LEN, []
    while pos < len(blob):
        (n,) = struct.unpack(">I", blob[pos:pos + 4])
        recs.append(blob[pos:pos + 4 + n])
        pos += 4 + n
    return header, recs


def _flip(data: bytes, i: int) -> bytes:
    i %= len(data)
    return data[:i] + bytes([data[i] ^ 0x01]) + data[i + 1:]


class VaultDamageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        t = cls.t = Path(cls._tmp.name)
        src = cls.src = t / "src"
        (src / "sub").mkdir(parents=True)
        cls.originals = {
            "big.bin": bytes(range(256)) * (10 * 1024 + 7),  # ~2.5 MiB: 3 chunks
            "small.txt": b"hello vault",
            "empty.dat": b"",
            "sub/exact.bin": b"\xab" * MiB,  # exactly one full chunk
        }
        for rel, data in cls.originals.items():
            (src / rel).write_bytes(data)
        cls.good = t / "good"
        vault.create_vault(src, cls.good, PW, log=lambda *_: None)
        cls.other = t / "other"  # a second vault with the same password, other salt
        vault.create_vault(src, cls.other, PW, log=lambda *_: None)
        manifest = vault.load_manifest(cls.good, PW)
        cls.blob_of = {e["path"]: cls.good / vault.BLOB_DIR / (e["blob"] + ".enc")
                       for e in manifest["files"]}
        # scrypt once per (password, salt) instead of once per case
        cls._keys = mock.patch.object(vault, "_keys", functools.cache(vault._keys))
        cls._keys.start()

    @classmethod
    def tearDownClass(cls):
        cls._keys.stop()
        cls._tmp.cleanup()

    def setUp(self):
        self.n = 0

    # ------------------------------------------------------------------ the rule

    def copy(self) -> Path:
        self.n += 1
        d = self.t / f"case_{self._testMethodName}_{self.n}"
        shutil.copytree(self.good, d)
        return d

    def blob(self, v: Path, rel: str) -> Path:
        return v / vault.BLOB_DIR / self.blob_of[rel].name

    def check(self, v: Path, label: str, *, must_fail: str | None = None):
        """Open the damaged vault v and apply the rule. must_fail: a file that must be reported."""
        out = self.t / f"out_{v.name}"
        with self.subTest(case=label):
            try:
                errors = vault.open_vault(v, out, PW, log=lambda *_: None)
            except (vault.VaultError, crypto.DecryptionError):
                errors = None  # refused as a whole: fine, if nothing was written
            written = {p.relative_to(out).as_posix(): p.read_bytes()
                       for p in out.rglob("*") if p.is_file()} if out.exists() else {}
            written.pop(vault.OPENED_MARKER, None)
            self.assertFalse([p for p in written if p.endswith(".sdt-partial")],
                             "partial plaintext left behind")
            for rel, data in written.items():
                self.assertEqual(data, self.originals[rel], f"{rel}: WRONG DATA given back")
            if errors is None:
                self.assertEqual(written, {}, "refused, but files were written")
                return
            reported = {e.split(":", 1)[0].replace("\\", "/") for e in errors}
            for rel in self.originals:
                if rel not in written:
                    self.assertIn(rel, reported, f"{rel} missing but not reported")
            if must_fail:
                self.assertIn(must_fail, reported, f"damage to {must_fail} not detected")

    # ------------------------------------------------------------------ blobs

    def test_flipped_bytes_in_blobs(self):
        for rel in self.originals:
            size = self.blob_of[rel].stat().st_size
            for pos in sorted({0, 4, 5, 20, 21, 24, 25, size // 2, size - 17, size - 1}):
                v = self.copy()
                b = self.blob(v, rel)
                b.write_bytes(_flip(b.read_bytes(), pos))
                self.check(v, f"{rel} byte {pos}", must_fail=rel)

    def test_cut_and_extended_blobs(self):
        for rel in self.originals:
            data = self.blob_of[rel].read_bytes()
            header, recs = _records(data)
            variants = {
                "empty": b"",
                "header only": header,
                "cut by 1": data[:-1],
                "cut in half": data[:len(data) // 2],
                "extra byte": data + b"\x00",
                "last chunk twice": data + recs[-1],
            }
            if len(recs) > 1:
                variants.update({
                    "last chunk dropped": header + b"".join(recs[:-1]),
                    "first chunk dropped": header + b"".join(recs[1:]),
                    "chunks swapped": header + recs[1] + recs[0] + b"".join(recs[2:]),
                    "first chunk twice": header + recs[0] + b"".join(recs),
                })
            for name, damaged in variants.items():
                v = self.copy()
                self.blob(v, rel).write_bytes(damaged)
                self.check(v, f"{rel} {name}", must_fail=rel)

    def test_missing_swapped_and_foreign_blobs(self):
        v = self.copy()
        self.blob(v, "small.txt").unlink()
        self.check(v, "missing blob", must_fail="small.txt")

        v = self.copy()  # two blobs swapped
        a, b = self.blob(v, "small.txt"), self.blob(v, "big.bin")
        da, db = a.read_bytes(), b.read_bytes()
        a.write_bytes(db)
        b.write_bytes(da)
        self.check(v, "blobs swapped", must_fail="small.txt")

        v = self.copy()  # the same file's blob from another vault (other key)
        m = vault.load_manifest(self.other, PW)
        foreign = {e["path"]: e["blob"] for e in m["files"]}["small.txt"]
        self.blob(v, "small.txt").write_bytes(
            (self.other / vault.BLOB_DIR / (foreign + ".enc")).read_bytes())
        self.check(v, "blob from another vault", must_fail="small.txt")

        v = self.copy()
        shutil.rmtree(v / vault.BLOB_DIR)
        self.check(v, "no blobs folder")

    # ------------------------------------------------------------------ manifest + vault.json

    def test_damaged_manifests(self):
        main, backup = vault.MANIFEST_FILE, vault.MANIFEST_BACKUP
        for name, damage in {
            "main flipped": lambda v: (v / main).write_bytes(_flip((v / main).read_bytes(), 40)),
            "main deleted": lambda v: (v / main).unlink(),
            "main cut": lambda v: (v / main).write_bytes((v / main).read_bytes()[:30]),
        }.items():
            v = self.copy()
            damage(v)
            self.check(v, name)
            m = vault.load_manifest(v, PW)  # opened from the backup, and says so
            self.assertIn("backup", m.get("_note", ""), name)

        for name, damage in {
            "both flipped": lambda v: [(v / f).write_bytes(_flip((v / f).read_bytes(), 40))
                                       for f in (main, backup)],
            "both deleted": lambda v: [(v / f).unlink() for f in (main, backup)],
            "both from another vault": lambda v: [shutil.copy(self.other / f, v / f)
                                                  for f in (main, backup)],
        }.items():
            v = self.copy()
            damage(v)
            self.check(v, name)
            with self.subTest(case=name), self.assertRaises(vault.VaultError):
                vault.load_manifest(v, PW)

    def test_damaged_vault_json(self):
        def edit(fn):
            def go(v):
                meta = json.loads((v / vault.VAULT_FILE).read_text(encoding="utf-8"))
                fn(meta)
                (v / vault.VAULT_FILE).write_text(json.dumps(meta), encoding="utf-8")
            return go

        other_salt = json.loads((self.other / vault.VAULT_FILE).read_text())["kdf"]["salt"]
        cases = {
            "salt from another vault": edit(lambda m: m["kdf"].__setitem__("salt", other_salt)),
            "weaker scrypt": edit(lambda m: m["kdf"].__setitem__("n", 2**10)),
            "absurd scrypt": edit(lambda m: m["kdf"].__setitem__("n", 2**40)),
            "kdf missing": edit(lambda m: m.pop("kdf")),
            "kdf not a dict": edit(lambda m: m.__setitem__("kdf", "scrypt")),
            "salt not base64": edit(lambda m: m["kdf"].__setitem__("salt", "!!!")),
            "n not a number": edit(lambda m: m["kdf"].__setitem__("n", "big")),
            "version 2": edit(lambda m: m.__setitem__("version", 2)),
            "a list": lambda v: (v / vault.VAULT_FILE).write_text("[1, 2]"),
            "garbage": lambda v: (v / vault.VAULT_FILE).write_bytes(b"\xff\xfe\x00junk"),
            "deleted": lambda v: (v / vault.VAULT_FILE).unlink(),
        }
        for name, damage in cases.items():
            v = self.copy()
            damage(v)
            self.check(v, name)
            with self.subTest(case=f"{name}: refused"):
                with self.assertRaises((vault.VaultError, crypto.DecryptionError)):
                    vault.load_manifest(v, PW)
            with self.subTest(case=f"{name}: info"):
                try:
                    rows = dict(vault.vault_info(v))
                except vault.VaultError:
                    continue  # a clear refusal is fine; any other exception is a bug
                if name in ("weaker scrypt", "absurd scrypt", "kdf missing", "kdf not a dict",
                            "salt not base64", "n not a number"):
                    self.assertTrue(rows["Key derivation"].startswith("INVALID"), rows)

    # ------------------------------------------------------------------ the CLI

    def test_cli_reports_damage(self):
        v = self.copy()
        b = self.blob(v, "big.bin")
        b.write_bytes(_flip(b.read_bytes(), 3 * MiB // 2))
        out_dir = self.t / "cli_out"
        buf = io.StringIO()
        with mock.patch.object(getpass, "getpass", lambda *_a, **_k: PW), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = cli.main(["vault", "open", str(v), "--out", str(out_dir)])
        text = buf.getvalue()
        self.assertEqual(rc, 1, text)
        self.assertIn("ERROR big.bin", text)
        self.assertIn("1 errors", text)
        self.assertFalse((out_dir / "big.bin").exists())
        self.assertEqual((out_dir / "small.txt").read_bytes(), b"hello vault")


if __name__ == "__main__":
    unittest.main()
