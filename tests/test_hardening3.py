"""Regression tests for the third hardening sweep."""

import io
import os
import socket
import sys
import tempfile
import unittest
import unicodedata
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from safedatatransfer.common import drives, winfs
from safedatatransfer.common.text import safe_print
from safedatatransfer.local_drop import commands as drop
from safedatatransfer.usb_vault import vault, wipe

PW = "correct horse battery"
FAST = 2**14


def _quiet(_m: str) -> None:
    pass


def _ntfs_streams_supported(folder: Path) -> bool:
    probe = folder / "probe.txt"
    probe.write_text("x")
    try:
        with open(f"{probe}:s", "w") as f:
            f.write("y")
        return winfs.list_streams(probe) == [("s", 1)]
    except OSError:
        return False
    finally:
        probe.unlink()


class VaultTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.t = Path(self._tmp.name)
        self.src = self.t / "stick"
        self.src.mkdir()
        (self.src / "a.txt").write_text("hello world")
        self.v = self.t / "vault"

    def tearDown(self):
        self._tmp.cleanup()

    def make(self, pw=PW):
        r = vault.create_vault(self.src, self.v, pw, log=_quiet, scrypt_n=FAST)
        self.assertTrue(r.ok, r.errors)
        return r


class ManifestBackupTests(VaultTestBase):
    def test_damaged_main_manifest_falls_back_to_backup(self):
        self.make()
        m = self.v / vault.MANIFEST_FILE
        data = bytearray(m.read_bytes())
        data[40] ^= 0xFF
        m.write_bytes(bytes(data))
        manifest = vault.load_manifest(self.v, PW)
        self.assertEqual([f["path"] for f in manifest["files"]], ["a.txt"])
        self.assertIn("backup", manifest["_note"])

    def test_no_manifest_is_reported(self):
        self.make()
        (self.v / vault.MANIFEST_FILE).unlink()
        (self.v / vault.MANIFEST_BACKUP).unlink()
        with self.assertRaises(vault.VaultError):
            vault.load_manifest(self.v, PW)
        self.assertIn("INCOMPLETE", dict(vault.vault_info(self.v))["State"])


class UnicodePasswordTests(VaultTestBase):
    def test_decomposed_and_composed_forms_both_open(self):
        composed = "Grüße aus Köln 2026!"
        decomposed = unicodedata.normalize("NFD", composed)
        self.assertNotEqual(composed, decomposed)
        self.make(decomposed)
        self.assertEqual(len(vault.load_manifest(self.v, composed)["files"]), 1)


class RehashTests(VaultTestBase):
    def test_same_size_same_time_edit_is_caught(self):
        result = self.make()
        f = self.src / "a.txt"
        st = f.stat()
        f.write_text("HELLO WORLD")  # same length
        os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))  # and the old timestamp
        self.assertEqual(vault.unverified_files(self.src, result.files), [])  # metadata looks fine
        problems = vault.unverified_files(self.src, result.files, rehash=True)
        self.assertEqual(len(problems), 1)
        self.assertIn("differs", problems[0])


class FreeSpaceTests(VaultTestBase):
    def test_refuses_when_destination_too_small(self):
        fake = mock.Mock(free=1000)
        with mock.patch.object(vault.shutil, "disk_usage", return_value=fake):
            with self.assertRaises(vault.VaultError):
                vault.create_vault(self.src, self.v, PW, log=_quiet, scrypt_n=FAST)
        self.assertFalse(self.v.exists())


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class StreamTests(VaultTestBase):
    def setUp(self):
        super().setUp()
        if not _ntfs_streams_supported(self.t):
            self.skipTest("temp folder is not on NTFS")
        with open(f"{self.src / 'a.txt'}:hidden", "w") as f:
            f.write("secret in a stream")

    def test_stream_is_copied_and_restored(self):
        r = self.make()
        self.assertEqual(r.files[0].streams[0][:2], ("hidden", 18))
        out = self.t / "out"
        self.assertEqual(vault.open_vault(self.v, out, PW, log=_quiet), [])
        self.assertEqual(Path(f"{out / 'a.txt'}:hidden").read_text(), "secret in a stream")

    def test_new_stream_after_copy_blocks_wipe(self):
        r = self.make()
        f = self.src / "a.txt"
        st = f.stat()
        with open(f"{f}:late", "w") as s:
            s.write("added later")
        self.assertEqual(len(vault.unverified_files(self.src, r.files)), 1)  # mtime changed
        os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))  # even with the old timestamp:
        self.assertIn("stream", vault.unverified_files(self.src, r.files)[0])

    def test_wipe_overwrites_streams(self):
        written = []
        real_open = open

        def spy(path, mode="r", *a, **k):
            if ":hidden" in str(path) and "+" in mode:
                written.append(path)
            return real_open(path, mode, *a, **k)

        with mock.patch("builtins.open", spy):
            self.assertEqual(wipe.wipe_files(self.src, log=_quiet, cluster=0), [])
        self.assertEqual(len(written), 1)
        self.assertEqual(list(self.src.iterdir()), [])


class DropNameTests(unittest.TestCase):
    def test_default_name_is_not_the_pc_name(self):
        name = drop.receiver_name(None)
        self.assertRegex(name, r"^sdt-\d{4}$")
        self.assertNotIn(socket.gethostname().lower(), name.lower())

    def test_partial_name_must_be_unique(self):
        peers = [drop.Peer("sdt-4821", "lan", lan=mock.Mock(host="1")),
                 drop.Peer("sdt-4822", "lan", lan=mock.Mock(host="2"))]
        self.assertEqual(drop._pick(peers, "sdt-4821").name, "sdt-4821")
        with self.assertRaises(drop.protocol.ProtocolError):
            drop._pick(peers, "sdt-48")


class DriveQueryTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows only")
    def test_system_drive_and_missing_letter(self):
        self.assertRegex(drives.system_drive(), r"^[A-Z]:$")
        free = [c for c in "ZYXWVUTSRQ" if not os.path.exists(c + ":\\")]
        if free:
            with self.assertRaises(drives.DriveError):
                drives.get_drive(free[0])


class OutputTests(unittest.TestCase):
    def test_safe_print_strips_escape_codes(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            safe_print("wiped \x1b]0;pwned\x07 file‮gnp.exe")
        out = buf.getvalue()
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)


if __name__ == "__main__":
    unittest.main()
