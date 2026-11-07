"""Regression tests for the fourth (consistency) pass."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from safedatatransfer.usb_vault import commands, transfer, vault, wipe

PW = "correct horse battery"


def _quiet(_m: str) -> None:
    pass


class OpenIntoExistingFolderTests(unittest.TestCase):
    def test_open_refuses_non_empty_folder_so_shred_cannot_hit_it(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "src").mkdir()
            (t / "src" / "a.txt").write_text("x")
            vault.create_vault(t / "src", t / "v", PW, log=_quiet, scrypt_n=2**14)
            docs = t / "Documents"
            docs.mkdir()
            (docs / "my thesis.docx").write_text("precious")
            with self.assertRaises(vault.VaultError):
                vault.open_vault(t / "v", docs, PW, log=_quiet)
            self.assertFalse((docs / vault.OPENED_MARKER).exists())
            with self.assertRaises(commands.SafetyError):
                commands.cmd_vault_shred(docs, assume_yes=True)
            self.assertEqual((docs / "my thesis.docx").read_text(), "precious")
            empty = t / "empty"
            empty.mkdir()
            self.assertEqual(vault.open_vault(t / "v", empty, PW, log=_quiet), [])


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class ReadOnlyFolderTests(unittest.TestCase):
    def test_read_only_hidden_system_folders_are_wiped(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "DCIM" / "100CANON").mkdir(parents=True)
            (root / "DCIM" / "100CANON" / "IMG_0001.JPG").write_bytes(b"jpeg")
            for p in (root / "DCIM", root / "DCIM" / "100CANON"):
                subprocess.run(["attrib", "+r", "+h", "+s", str(p)], check=True,
                               capture_output=True)
            self.assertEqual(wipe.wipe_files(root, log=_quiet, cluster=0), [])
            self.assertEqual(list(root.iterdir()), [])


class SpecialReparsePointTests(unittest.TestCase):
    def test_non_link_reparse_point_stops_copy_and_wipe(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            special = root / "cloud placeholder.docx"
            special.write_text("data that lives elsewhere")
            with mock.patch.object(transfer, "is_link", lambda p: Path(p) == special), \
                    mock.patch.object(transfer, "_reparse_tag",
                                      lambda p: 0x9000001A if Path(p) == special else None):
                scan = transfer.scan_tree(root)
            self.assertEqual(scan.links, [])
            self.assertEqual(len(scan.errors), 1)
            self.assertIn("special file", scan.errors[0])


if __name__ == "__main__":
    unittest.main()
