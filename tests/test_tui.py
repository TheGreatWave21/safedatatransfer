import asyncio
import tempfile
import unittest
from pathlib import Path

try:
    from textual.widgets import TabbedContent

    from safedatatransfer.tui.app import SdtApp
    HAVE_TEXTUAL = True
except ImportError:
    HAVE_TEXTUAL = False

from safedatatransfer.usb_vault import vault

PW = "correct horse battery"


@unittest.skipUnless(HAVE_TEXTUAL, "textual not installed")
class TimestampTests(unittest.TestCase):
    def test_drive_root_timestamp_does_not_crash(self):
        from safedatatransfer.tui.app import _ts
        # Windows reports drive roots (e.g. D:\) with FILETIME 0 = 1601-01-01.
        self.assertEqual(_ts(-11644473600.0), "-")
        self.assertEqual(_ts(0), "-")
        self.assertRegex(_ts(1_700_000_000), r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")


@unittest.skipUnless(HAVE_TEXTUAL, "textual not installed")
class WipeDialogTests(unittest.TestCase):
    def test_default_wipe_does_not_fill_free_space(self):
        from safedatatransfer.common.drives import Drive
        from safedatatransfer.tui.modals import PlanModal

        drive = Drive(letter="E:", type="removable", label="STICK", filesystem="FAT32",
                      serial=1, total_bytes=1, free_bytes=1, is_system=False)
        results = []

        async def run():
            app = SdtApp(vault_root=Path("nonexistent"), drive_source=lambda: [])
            async with app.run_test(size=(140, 44)) as pilot:
                await pilot.pause(0.2)
                app.push_screen(PlanModal("wipe", drive, None, dry_run=False), results.append)
                await pilot.pause(0.3)
                await pilot.press("enter")  # accept the defaults
                await pilot.pause(0.3)

        asyncio.run(run())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].method, "quick")


@unittest.skipUnless(HAVE_TEXTUAL, "textual not installed")
class TuiTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        t = Path(self._tmp.name)
        src = t / "src"
        src.mkdir()
        (src / "a.txt").write_text("hello")
        self.root = t / "vaults"
        vault.create_vault(src, self.root / "v1", PW, log=lambda m: None, scrypt_n=2**14)

    def tearDown(self):
        self._tmp.cleanup()

    def test_tabs_dialog_keys_and_unlock(self):
        async def run():
            app = SdtApp(vault_root=self.root, drive_source=lambda: [])
            async with app.run_test(size=(140, 44)) as pilot:
                await pilot.pause(0.3)
                tabs = app.query_one(TabbedContent)
                for key, name in (("2", "vaults"), ("3", "activity"), ("1", "drives"), ("2", "vaults")):
                    await pilot.press(key)
                    await pilot.pause(0.2)
                    self.assertEqual(tabs.active, name)
                await pilot.press("u")
                await pilot.pause(0.3)
                await pilot.press("q")  # typed into the password box: must not quit
                await pilot.pause(0.1)
                self.assertTrue(app.is_running)
                await pilot.press("backspace")
                for ch in PW:
                    await pilot.press("space" if ch == " " else ch)
                await pilot.press("enter")
                for _ in range(30):
                    await pilot.pause(0.1)
                    if app.unlocked:
                        break
                self.assertEqual(len(app.unlocked), 1)
                manifest = next(iter(app.unlocked.values()))
                self.assertEqual([f["path"] for f in manifest["files"]], ["a.txt"])
                await pilot.press("w")  # no drive: must only warn, not open a dialog
                await pilot.pause(0.2)
                self.assertEqual(type(app.screen).__name__, "Screen")

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
