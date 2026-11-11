"""The CLI with wrong input: a clear one-line error, exit code 1, no traceback, and never a
password prompt (or a radio search) before the input is known to be usable."""

import contextlib
import getpass
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from safedatatransfer import cli
from safedatatransfer.common.drives import Drive
from safedatatransfer.local_drop import commands as drop
from safedatatransfer.usb_vault import commands as usb
from safedatatransfer.usb_vault import vault

PW = "correct horse battery"


def _no_prompt(*_a, **_k):
    raise AssertionError("asked for input although the command must fail first")


class CliErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        t = cls.t = Path(cls._tmp.name)
        src = t / "src"
        src.mkdir()
        (src / "a.txt").write_text("a")
        vault.create_vault(src, t / "v", PW, log=lambda *_: None)
        (t / "bad").mkdir()
        (t / "bad" / "vault.json").write_text("{not json")
        (t / "other").mkdir()
        (t / "other" / "vault.json").write_text('{"format": "something-else"}')
        (t / "empty").mkdir()
        (t / "file.txt").write_text("x")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def run_cli(self, *args) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(getpass, "getpass", _no_prompt), \
                mock.patch("builtins.input", _no_prompt), \
                mock.patch.object(drop, "_discover", _no_prompt), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main([str(a) for a in args])
        return rc, (out.getvalue() + err.getvalue()).strip()

    def assertFails(self, args, message):
        rc, text = self.run_cli(*args)
        self.assertEqual(rc, 1, text)
        self.assertNotIn("Traceback", text)
        self.assertIn(message, text)

    def test_vault_commands_check_the_folder_before_the_password(self):
        t = self.t
        for cmd in ("info", "list", "open"):
            with self.subTest(cmd=cmd):
                self.assertFails(["vault", cmd, t / "nope"], "does not exist")
                self.assertFails(["vault", cmd, t / "file.txt"], "is a file")
                self.assertFails(["vault", cmd, t / "empty"], "has no vault.json")
                self.assertFails(["vault", cmd, t / "bad"], "is damaged (not valid JSON)")
                self.assertFails(["vault", cmd, t / "other"], "is not an sdt vault file")

    def test_vault_open_checks_out_before_the_password(self):
        self.assertFails(["vault", "open", self.t / "v", "--out", self.t / "src"],
                         "already exists and is not empty")

    def test_copy_into_the_stick_is_refused_before_the_password(self):
        src = self.t / "src"

        class FakeDrive(Drive):
            @property
            def root(self) -> str:
                return str(src) + "\\"

        d = FakeDrive(letter="E:", type="removable", label="T", filesystem="FAT32", serial=1,
                      total_bytes=10**9, free_bytes=10**8, is_system=False)
        with mock.patch.object(usb, "get_drive", lambda letter: d), \
                mock.patch.object(usb, "check_destination", lambda dest: None), \
                mock.patch.object(usb, "drive_identity", lambda drive: ()):
            self.assertFails(["usb", "copy", "E:", "--dest", src / "vault"],
                             "Destination must not be inside the source.")
            self.assertFails(["usb", "evacuate", "E:", "--dest", src / "vault"],
                             "Destination must not be inside the source.")

    def test_drop_send_errors(self):
        t = self.t
        self.assertFails(["drop", "send", t / "nope.txt"], "Not found:")
        self.assertFails(["drop", "send", t / "empty"], "Nothing to send.")
        # A mistyped --code fails before any search for receivers.
        self.assertFails(["drop", "send", t / "file.txt", "--via", "lan", "--code", "abc"],
                         "The code has 6 digits")

    def test_drop_receive_into_a_file_is_refused_at_once(self):
        # receiver_name runs right after the destination check: if the check were missing,
        # this fails at once instead of advertising and waiting forever.
        with mock.patch.object(drop, "receiver_name", _no_prompt):
            self.assertFails(["drop", "receive", "--dest", self.t / "file.txt"],
                             "is a file, not a folder")

    def test_drive_letter_errors(self):
        for bad in ("", "1", r"C:\Windows", r"\\server\share"):
            with self.subTest(drive=bad):
                self.assertFails(["usb", "info", bad], "Not a drive letter")

    def test_system_drive_is_never_wiped(self):
        import os
        system = os.environ.get("SystemDrive", "C:")
        for cmd in ("wipe", "evacuate"):
            with self.subTest(cmd=cmd):
                self.assertFails(["usb", cmd, system], "is the system drive. Refusing.")


if __name__ == "__main__":
    unittest.main()
