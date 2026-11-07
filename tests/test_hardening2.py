"""Regression tests for the second hardening sweep."""

import asyncio
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from safedatatransfer.common import crypto, winfs
from safedatatransfer.common.drives import Drive
from safedatatransfer.local_drop import protocol as p
from safedatatransfer.usb_vault import commands, vault, wipe
from safedatatransfer.usb_vault.transfer import is_link

PW = "correct horse battery"
FAST = 2**14


def _quiet(_m: str) -> None:
    pass


def _drive(**kw) -> Drive:
    base = dict(letter="Q:", type="removable", label="STICK", filesystem="FAT32",
                serial=0x1234ABCD, total_bytes=8 << 30, free_bytes=1, is_system=False)
    base.update(kw)
    return Drive(**base)


class SlackAndNamesTests(unittest.TestCase):
    def test_overwrite_reaches_end_of_cluster(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "x.txt"
            f.write_bytes(b"secret")  # 6 bytes in a 4096-byte cluster
            asked = []
            real = wipe.secrets.token_bytes
            with mock.patch.object(wipe.secrets, "token_bytes",
                                   side_effect=lambda n: asked.append(n) or real(n)):
                wipe.overwrite_and_delete(f, 1, cluster=4096)
            self.assertEqual(sum(asked[:2]), 4096)  # data + slack, before the random name
            self.assertFalse(f.exists())

    def test_names_are_scrubbed_and_nothing_left(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "sub").mkdir()
            for i in range(5):
                (root / "sub" / f"a very long secret file name {i}.docx").write_text("x")
            logs = []
            self.assertEqual(wipe.wipe_files(root, log=logs.append, cluster=0), [])
            self.assertEqual(list(root.iterdir()), [])
            self.assertTrue(any("scrubbed" in m for m in logs))


class DriveIdentityTests(unittest.TestCase):
    def test_swapped_stick_is_detected(self):
        chosen = _drive()
        with mock.patch.object(commands, "device_info", return_value=None):
            identity = commands.drive_identity(chosen)
            with mock.patch.object(commands, "get_drive", return_value=_drive(serial=0x99)):
                self.assertIn("different drive", commands.still_same_drive(chosen, identity))
            with mock.patch.object(commands, "get_drive", return_value=_drive()):
                self.assertIsNone(commands.still_same_drive(chosen, identity))

    def test_refuses_drive_that_runs_sdt(self):
        serial = os.stat(sys.prefix).st_dev & 0xFFFFFFFF
        with mock.patch.object(commands, "device_info", return_value=None):
            with self.assertRaises(commands.SafetyError):
                commands.check_wipe_allowed(_drive(serial=serial), allow_fixed=False)


class PasswordRuleTests(unittest.TestCase):
    def test_rules(self):
        for bad in ("short", "aaaaaaaaaaaaaaa", "password12345", "123456789012"):
            self.assertIsNotNone(crypto.password_problem(bad), bad)
        self.assertIsNone(crypto.password_problem(PW))


class PlaintextOutputTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.t = Path(self._tmp.name)
        src = self.t / "src"
        src.mkdir()
        (src / "a.txt").write_text("hello")
        self.v = self.t / "v"
        vault.create_vault(src, self.v, PW, log=_quiet, scrypt_n=FAST)

    def tearDown(self):
        self._tmp.cleanup()

    def test_refuses_cloud_folder(self):
        with self.assertRaises(vault.VaultError):
            vault.open_vault(self.v, self.t / "OneDrive" / "out", PW, log=_quiet)
        self.assertEqual(vault.open_vault(self.v, self.t / "OneDrive" / "out", PW, log=_quiet,
                                          allow_cloud=True), [])

    def test_open_marks_not_indexed_then_shred(self):
        out = self.t / "out"
        self.assertEqual(vault.open_vault(self.v, out, PW, log=_quiet), [])
        if sys.platform == "win32":
            attrs = os.stat(out / "a.txt").st_file_attributes
            self.assertTrue(attrs & winfs.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        with mock.patch("builtins.print"):
            self.assertEqual(commands.cmd_vault_shred(out, assume_yes=True), 0)
        self.assertFalse(out.exists())

    def test_shred_refuses_other_folders(self):
        other = self.t / "my documents"
        other.mkdir()
        (other / "keep.txt").write_text("mine")
        with self.assertRaises(commands.SafetyError):
            commands.cmd_vault_shred(other, assume_yes=True)
        self.assertTrue((other / "keep.txt").exists())


class VerifyTests(unittest.TestCase):
    def test_uncached_reader_matches(self):
        with tempfile.TemporaryDirectory() as t:
            for size in (0, 1, 4095, 4096, (1 << 20) + 3):
                f = Path(t) / f"f{size}"
                data = os.urandom(size)
                f.write_bytes(data)
                reader, _ = winfs.open_for_verify(f)
                with reader as r:
                    self.assertEqual(r.read(-1), data)


class DropTests(unittest.TestCase):
    def test_sender_skips_junctions(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "send").mkdir()
            (t / "send" / "pick.txt").write_text("chosen")
            (t / "private").mkdir()
            (t / "private" / "secret.txt").write_text("never send")
            r = subprocess.run(["cmd", "/c", "mklink", "/J", str(t / "send" / "j"),
                                str(t / "private")], capture_output=True)
            if r.returncode or not is_link(t / "send" / "j"):
                self.skipTest("cannot create junctions here")
            files = p.collect_files([t / "send"], log=_quiet)
            self.assertEqual([f.rel for f in files], ["send/pick.txt"])

    def test_received_file_is_marked(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            src = t / "in.exe"
            src.write_bytes(b"MZ fake")
            a, b = socket.socketpair()
            a.settimeout(5)
            b.settimeout(5)

            def sender():
                try:
                    p.send_files(p.handshake_sender(a, "111-222"), p.collect_files([src]), "pc",
                                 log=_quiet)
                finally:
                    a.close()

            th = threading.Thread(target=sender)
            th.start()
            try:
                got = p.receive_files(p.handshake_receiver(b, "111-222"), t / "dest",
                                      lambda o: True, log=_quiet)
            finally:
                b.close()
                th.join(5)
            if sys.platform == "win32":
                zone = Path(f"{got[0]}:Zone.Identifier").read_text()
                self.assertIn("ZoneId=3", zone)


class CrashOutputTests(unittest.TestCase):
    def test_crash_report_has_no_locals(self):
        try:
            from rich.console import Console
            from safedatatransfer.tui.app import SdtApp
        except ImportError:
            self.skipTest("textual not installed")

        class Boom(SdtApp):
            BINDINGS = [("z", "boom", "")]

            def action_boom(self):
                secret_pw = "-".join(["hunter2", "VERY", "SECRET"])  # noqa: F841 runtime value
                raise RuntimeError("boom")

            def _fatal_error(self):
                super()._fatal_error()
                captured.extend(self._exit_renderables)  # before Textual prints + clears them

        captured = []
        app = Boom(vault_root=Path("nonexistent"), drive_source=lambda: [])

        async def run():
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.3)
                await pilot.press("z")
                await pilot.pause(0.3)

        with self.assertRaises(RuntimeError):
            asyncio.run(run())
        console = Console(record=True, width=120, file=io.StringIO())
        for r in captured:
            console.print(r)
        text = console.export_text()
        self.assertIn("boom", text)
        self.assertNotIn("hunter2-VERY-SECRET", text)


if __name__ == "__main__":
    unittest.main()
