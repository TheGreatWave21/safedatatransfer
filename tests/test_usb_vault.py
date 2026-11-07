import tempfile
import unittest
from pathlib import Path

from safedatatransfer.cli import build_parser
from safedatatransfer.common.drives import Drive, normalize_letter
from safedatatransfer.usb_vault import vault, wipe
from safedatatransfer.usb_vault.commands import SafetyError, check_wipe_allowed
from safedatatransfer.usb_vault.wipe import wipe_files

PW = "correct horse battery"
FAST = 2**14  # weaker scrypt only to keep tests fast


def _quiet(_msg: str) -> None:
    pass


def _make_tree(root: Path) -> None:
    (root / "sub" / "deeper").mkdir(parents=True)
    (root / "a.txt").write_text("hello")
    (root / "sub" / "b.bin").write_bytes(bytes(range(256)) * 5000)
    (root / "sub" / "deeper" / "c.txt").write_text("secret")
    (root / "System Volume Information").mkdir()
    (root / "System Volume Information" / "skip.dat").write_text("x")


def _drive(**kw) -> Drive:
    base = dict(letter="E:", type="removable", label="STICK", filesystem="FAT32",
                serial=1, total_bytes=1, free_bytes=1, is_system=False)
    base.update(kw)
    return Drive(**base)


class VaultTests(unittest.TestCase):
    def _vault(self, t: str):
        src, dst = Path(t) / "src", Path(t) / "vault"
        src.mkdir()
        _make_tree(src)
        result = vault.create_vault(src, dst, PW, log=_quiet, scrypt_n=FAST)
        return src, dst, result

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as t:
            src, dst, result = self._vault(t)
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(len(result.files), 3)  # system folder skipped
            out = Path(t) / "out"
            self.assertEqual(vault.open_vault(dst, out, PW, log=_quiet), [])
            for f in result.files:
                self.assertEqual((out / f.path).read_bytes(), (src / f.path).read_bytes())

    def test_nothing_readable_on_disk(self):
        with tempfile.TemporaryDirectory() as t:
            _, dst, _ = self._vault(t)
            for f in dst.rglob("*"):
                if f.is_file():
                    data = f.read_bytes()
                    for secret in (b"secret", b"hello", b"c.txt", b"deeper"):
                        self.assertNotIn(secret, data, f)

    def test_wrong_password(self):
        with tempfile.TemporaryDirectory() as t:
            _, dst, _ = self._vault(t)
            with self.assertRaises(vault.VaultError):
                vault.load_manifest(dst, "wrong password!")

    def test_tampered_blob_detected(self):
        with tempfile.TemporaryDirectory() as t:
            _, dst, _ = self._vault(t)
            blob = max((dst / "blobs").iterdir(), key=lambda p: p.stat().st_size)
            data = bytearray(blob.read_bytes())
            data[100] ^= 1
            blob.write_bytes(bytes(data))
            errors = vault.open_vault(dst, Path(t) / "out", PW, log=_quiet)
            self.assertEqual(len(errors), 1)
            self.assertFalse(any((Path(t) / "out").rglob("*.bin")))

    def test_short_password_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(vault.VaultError):
                vault.create_vault(Path(t), Path(t).parent / "x", "short", log=_quiet)

    def test_dest_inside_source_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ValueError):
                vault.create_vault(Path(t), Path(t) / "inside", PW, log=_quiet)

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            src, dst = Path(t) / "src", Path(t) / "dst"
            src.mkdir()
            _make_tree(src)
            vault.create_vault(src, dst, PW, dry_run=True, log=_quiet)
            self.assertFalse(dst.exists())


class WipeTests(unittest.TestCase):
    def test_wipe_files_removes_everything_but_system_dirs(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _make_tree(root)
            errors = wipe_files(root, passes=2, log=_quiet)
            self.assertEqual(errors, [])
            remaining = sorted(p.name for p in root.iterdir())
            self.assertEqual(remaining, ["System Volume Information"])

    def test_wipe_dry_run_keeps_files(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _make_tree(root)
            wipe_files(root, dry_run=True, log=_quiet)
            self.assertTrue((root / "a.txt").exists())


class FreeSpaceTests(unittest.TestCase):
    def test_fills_then_removes_filler(self):
        with tempfile.TemporaryDirectory() as t:
            seen = []
            code = wipe.wipe_free_space(t, max_bytes=9 * 1024 * 1024, log=_quiet,
                                        progress=lambda d, tot: seen.append((d, tot)))
            self.assertEqual(code, 0)
            self.assertEqual(list(Path(t).iterdir()), [])  # filler removed
            self.assertEqual(seen[-1][0], seen[-1][1])
            self.assertGreaterEqual(max(d for d, _ in seen), 9 * 1024 * 1024)

    def test_disk_full_is_handled(self):
        """Simulate a stick that is full after 6 MiB: must stop cleanly, not crash."""
        limit = 6 * 1024 * 1024
        written = {"n": 0}
        real = wipe._write_block

        def fake(f, data):
            room = limit - written["n"]
            if room <= 0:
                raise OSError(28, "No space left on device")
            chunk = data[:room]
            written["n"] += len(chunk)
            return real(f, chunk)

        wipe._write_block = fake
        try:
            with tempfile.TemporaryDirectory() as t:
                code = wipe.wipe_free_space(t, max_bytes=50 * 1024 * 1024, log=_quiet)
                self.assertEqual(code, 0)
                self.assertEqual(written["n"], limit)
                self.assertEqual(list(Path(t).iterdir()), [])
        finally:
            wipe._write_block = real

    def test_filler_removed_on_error(self):
        real = wipe._write_block

        def boom(f, data):
            raise OSError(5, "I/O error")

        wipe._write_block = boom
        try:
            with tempfile.TemporaryDirectory() as t:
                with self.assertRaises(OSError):
                    wipe.wipe_free_space(t, max_bytes=1024 * 1024, log=_quiet)
                self.assertEqual(list(Path(t).iterdir()), [])
        finally:
            wipe._write_block = real

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            wipe.wipe_free_space(t, dry_run=True, log=_quiet)
            self.assertEqual(list(Path(t).iterdir()), [])


class SafetyTests(unittest.TestCase):
    def test_refuses_system_drive(self):
        with self.assertRaises(SafetyError):
            check_wipe_allowed(_drive(letter="C:", is_system=True), allow_fixed=True)

    def test_refuses_fixed_without_flag(self):
        with self.assertRaises(SafetyError):
            check_wipe_allowed(_drive(type="fixed"), allow_fixed=False)
        check_wipe_allowed(_drive(type="fixed"), allow_fixed=True)

    def test_refuses_dest_on_same_drive(self):
        with self.assertRaises(SafetyError):
            check_wipe_allowed(_drive(), allow_fixed=False, dest=Path("E:/backup"))

    def test_normalize_letter(self):
        for v in ("e", "E:", "e:\\", " E "):
            self.assertEqual(normalize_letter(v), "E:")


class CliTests(unittest.TestCase):
    def test_parser(self):
        args = build_parser().parse_args(["usb", "evacuate", "E:", "--method", "quick"])
        self.assertEqual((args.area, args.cmd, args.method), ("usb", "evacuate", "quick"))


if __name__ == "__main__":
    unittest.main()
