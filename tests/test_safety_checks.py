"""Tests for the extra safety checks around destructive operations."""

import itertools
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from safedatatransfer.usb_vault import commands, transfer, vault, wipe

PW = "correct horse battery"
FAST = 2**14


def _quiet(_m: str) -> None:
    pass


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.t = Path(self._tmp.name)
        self.stick = self.t / "stick"
        self.stick.mkdir()
        self.outside = self.t / "outside.txt"
        self.outside.write_text("must survive")

    def tearDown(self):
        self._tmp.cleanup()


class ContainmentTests(Base):
    def test_file_outside_root_stops_the_wipe(self):
        (self.stick / "a.txt").write_text("x")
        fake = transfer.Scan(files=[self.outside, self.stick / "a.txt"])
        with mock.patch.object(wipe, "scan_tree", return_value=fake):
            errors = wipe.wipe_files(self.stick, log=_quiet, cluster=0)
        self.assertTrue(any("outside" in e for e in errors))
        self.assertEqual(self.outside.read_text(), "must survive")
        self.assertTrue((self.stick / "a.txt").exists())  # stopped: nothing else touched


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class HardLinkTests(Base):
    def test_hard_link_to_outside_file_only_loses_its_name(self):
        try:
            os.link(self.outside, self.stick / "alias.txt")
        except OSError:
            self.skipTest("hard links not supported here")
        logs = []
        self.assertEqual(wipe.wipe_files(self.stick, log=logs.append, cluster=0), [])
        self.assertEqual(self.outside.read_text(), "must survive")
        self.assertFalse((self.stick / "alias.txt").exists())
        self.assertTrue(any("hard link" in m for m in logs))


class NormalFileTests(Base):
    def test_normal_file_is_overwritten_not_just_unlinked(self):
        f = self.stick / "a.txt"
        f.write_text("secret")
        self.assertIs(wipe.overwrite_and_delete(f), True)
        (self.stick / "b.txt").write_text("secret")
        logs = []
        wipe.wipe_files(self.stick, log=logs.append, cluster=0)
        self.assertTrue(any(m.startswith("  wiped b.txt") for m in logs), logs)
        self.assertFalse(any("hard link" in m for m in logs))


class AbortDuringWipeTests(Base):
    def test_swapped_stick_stops_wipe(self):
        for i in range(5):
            (self.stick / f"f{i}.txt").write_text("x")
        clock = itertools.count(0, 10)  # every check is "2+ seconds later"
        with mock.patch.object(wipe.time, "monotonic", lambda: next(clock)):
            errors = wipe.wipe_files(self.stick, log=_quiet, cluster=0,
                                     abort_check=lambda: "a different drive is now at E:")
        self.assertIn("wipe stopped", errors[-1])
        self.assertEqual(len(list(self.stick.iterdir())), 5)  # nothing was wiped


class VaultPresenceTests(Base):
    def test_missing_blob_is_noticed(self):
        (self.stick / "a.txt").write_text("hello")
        r = vault.create_vault(self.stick, self.t / "v", PW, log=_quiet, scrypt_n=FAST)
        self.assertIsNone(vault.vault_still_present(self.t / "v", r.blob_sizes))
        blob = next((self.t / "v" / vault.BLOB_DIR).iterdir())
        blob.unlink()
        self.assertIn("no longer reachable", vault.vault_still_present(self.t / "v", r.blob_sizes))

    def test_vault_on_stick_is_found(self):
        (self.stick / "a.txt").write_text("hello")
        vault.create_vault(self.stick, self.t / "v", PW, log=_quiet, scrypt_n=FAST)
        other = self.t / "other_stick"
        other.mkdir()
        os.replace(self.t / "v", other / "backup")
        self.assertEqual(vault.find_vaults_under(other), [other / "backup"])
        self.assertEqual(vault.find_vaults_under(self.stick), [])


class DestinationTests(unittest.TestCase):
    def test_temp_and_recycle_bin_refused(self):
        with self.assertRaises(commands.SafetyError):
            commands.check_destination(Path(tempfile.gettempdir()) / "vault_x")
        with self.assertRaises(commands.SafetyError):
            commands.check_destination(Path("F:/$RECYCLE.BIN/S-1-5/vault_x"))
        commands.check_destination(Path.home() / "Downloads" / "usb-vault" / "vault_x")


class ShredOnlyOwnFilesTests(Base):
    def test_files_added_after_open_are_kept(self):
        (self.stick / "sub").mkdir()
        (self.stick / "sub" / "a.txt").write_text("from vault")
        vault.create_vault(self.stick, self.t / "v", PW, log=_quiet, scrypt_n=FAST)
        out = self.t / "opened"
        self.assertEqual(vault.open_vault(self.t / "v", out, PW, log=_quiet), [])
        (out / "sub" / "my notes.txt").write_text("written later by me")
        with mock.patch("builtins.print"):
            self.assertEqual(commands.cmd_vault_shred(out, assume_yes=True), 0)
        self.assertFalse((out / "sub" / "a.txt").exists())
        self.assertEqual((out / "sub" / "my notes.txt").read_text(), "written later by me")

    def test_shred_everything_when_nothing_was_added(self):
        (self.stick / "a.txt").write_text("from vault")
        vault.create_vault(self.stick, self.t / "v", PW, log=_quiet, scrypt_n=FAST)
        out = self.t / "opened"
        vault.open_vault(self.t / "v", out, PW, log=_quiet)
        with mock.patch("builtins.print"):
            self.assertEqual(commands.cmd_vault_shred(out, assume_yes=True), 0)
        self.assertFalse(out.exists())


class ProvePasswordTests(Base):
    def test_wrong_password_three_times_means_no_wipe(self):
        (self.stick / "a.txt").write_text("hello")
        vault.create_vault(self.stick, self.t / "v", PW, log=_quiet, scrypt_n=FAST)
        with mock.patch("builtins.print"), \
                mock.patch.object(commands.getpass, "getpass", return_value="wrong password!"):
            self.assertFalse(commands.prove_password(self.t / "v"))
        with mock.patch("builtins.print"), \
                mock.patch.object(commands.getpass, "getpass", return_value=PW):
            self.assertTrue(commands.prove_password(self.t / "v"))


if __name__ == "__main__":
    unittest.main()
