"""Regression tests for the security hardening (links, pre-wipe check, input validation)."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from safedatatransfer.common.drives import Drive
from safedatatransfer.local_drop import protocol as p
from safedatatransfer.usb_vault import vault
from safedatatransfer.usb_vault.commands import SafetyError, check_wipe_allowed
from safedatatransfer.usb_vault.transfer import is_link, scan_tree
from safedatatransfer.usb_vault.wipe import wipe_files

PW = "correct horse battery"
FAST = 2**14


def _quiet(_m: str) -> None:
    pass


def _junction(link: Path, target: Path) -> bool:
    """Create a directory junction (no admin needed). False if not possible here."""
    if sys.platform != "win32":
        return False
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True)
    return r.returncode == 0 and is_link(link)


class LinkSafetyTests(unittest.TestCase):
    """A junction on a stick can point at C:\\Users. It must never be followed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        t = Path(self._tmp.name)
        self.stick, self.outside = t / "stick", t / "outside"
        self.stick.mkdir()
        self.outside.mkdir()
        (self.outside / "precious.txt").write_text("do not touch")
        (self.stick / "own.txt").write_text("stick data")
        if not _junction(self.stick / "link", self.outside):
            self.skipTest("cannot create junctions here")

    def tearDown(self):
        self._tmp.cleanup()

    def test_scan_does_not_follow(self):
        scan = scan_tree(self.stick)
        self.assertEqual([f.name for f in scan.files], ["own.txt"])
        self.assertEqual([lk.name for lk in scan.links], ["link"])

    def test_wipe_never_touches_link_target(self):
        errors = wipe_files(self.stick, log=_quiet)
        self.assertEqual(errors, [])
        self.assertEqual((self.outside / "precious.txt").read_text(), "do not touch")
        self.assertEqual(list(self.stick.iterdir()), [])  # link entry itself is gone

    def test_copy_does_not_follow(self):
        result = vault.create_vault(self.stick, self.stick.parent / "v", PW,
                                    log=_quiet, scrypt_n=FAST)
        self.assertTrue(result.ok)
        self.assertEqual([f.path for f in result.files], ["own.txt"])
        self.assertEqual(result.links, ["link"])


class PreWipeCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        t = Path(self._tmp.name)
        self.stick = t / "stick"
        self.stick.mkdir()
        (self.stick / "a.txt").write_text("one")
        self.result = vault.create_vault(self.stick, t / "v", PW, log=_quiet, scrypt_n=FAST)

    def tearDown(self):
        self._tmp.cleanup()

    def test_unchanged_is_ok(self):
        self.assertEqual(vault.unverified_files(self.stick, self.result.files), [])

    def test_new_file_blocks_wipe(self):
        (self.stick / "late.txt").write_text("arrived after the copy")
        problems = vault.unverified_files(self.stick, self.result.files)
        self.assertEqual(len(problems), 1)
        self.assertIn("late.txt", problems[0])

    def test_changed_file_blocks_wipe(self):
        (self.stick / "a.txt").write_text("one, edited")
        self.assertIn("changed", vault.unverified_files(self.stick, self.result.files)[0])


class VaultMetaTests(unittest.TestCase):
    def test_tampered_kdf_settings_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "s"
            src.mkdir()
            (src / "x").write_text("x")
            v = Path(t) / "v"
            vault.create_vault(src, v, PW, log=_quiet, scrypt_n=FAST)
            meta = json.loads((v / vault.VAULT_FILE).read_text())
            meta["kdf"]["n"] = 2**30  # would need 1 TiB of memory
            (v / vault.VAULT_FILE).write_text(json.dumps(meta))
            with self.assertRaises(vault.VaultError):
                vault.load_manifest(v, PW)


class DestinationVolumeTests(unittest.TestCase):
    def test_same_volume_by_serial_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            serial = os.stat(t).st_dev & 0xFFFFFFFF
            drive = Drive(letter="Q:", type="removable", label="", filesystem="FAT32",
                          serial=serial, total_bytes=1, free_bytes=1, is_system=False)
            # Different letter, same volume (like a mount folder): must still be refused.
            with self.assertRaises(SafetyError):
                check_wipe_allowed(drive, allow_fixed=False, dest=Path(t) / "new" / "vault")


class NameSanitizingTests(unittest.TestCase):
    def test_bidi_override_and_controls_replaced(self):
        rel = p.safe_relpath("invoice\u202efdp.exe")
        self.assertNotIn("\u202e", str(rel))
        self.assertTrue(str(rel).endswith(".exe"))
        self.assertNotIn("\x1b", p.clean_text("evil\x1b[2J name"))

    def test_reserved_names(self):
        for name in ("CON .txt", "com¹.log", "CONOUT$", "lpt0"):
            self.assertTrue(str(p.safe_relpath(name)).startswith("_"), name)

    def test_trailing_dots_and_spaces(self):
        self.assertEqual(str(p.safe_relpath("a .")), "a")


class MalformedOfferTests(unittest.TestCase):
    def _run(self, offer):
        a, b = socket.socketpair()
        a.settimeout(5)
        b.settimeout(5)
        err = {}

        def sender():
            try:
                ch = p.handshake_sender(a, "123-456")
                ch.send_json(offer)
            except Exception as e:  # receiver hangs up
                err["s"] = e

        t = threading.Thread(target=sender)
        t.start()
        try:
            ch = p.handshake_receiver(b, "123-456")
            with tempfile.TemporaryDirectory() as d:
                p.receive_files(ch, Path(d), lambda o: True, log=_quiet)
        finally:
            a.close()
            b.close()
            t.join(5)

    def test_bad_offers_raise_protocol_error(self):
        for offer in ({"type": "offer", "files": "nope"},
                      {"type": "offer", "files": [{"path": "a"}]},
                      {"type": "offer", "files": [{"path": "a", "size": "x"}]},
                      {"type": "offer", "files": [{"path": "a", "size": 10**30}]}):
            with self.assertRaises(p.ProtocolError, msg=str(offer)):
                self._run(offer)


if __name__ == "__main__":
    unittest.main()
