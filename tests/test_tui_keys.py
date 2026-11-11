"""Every key on every tab, and every dialog flow, pressed for real in the UI.

Bugs once hid in UI paths that tests never pressed (c/e/w did nothing at all), so this file
drives the app the way a person does: real keys, real dialogs, real vault files.
The USB stick is a temp folder; nothing outside the temp folder is touched."""

import asyncio
import gc
import tempfile
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

try:
    from textual.widgets import Input

    from safedatatransfer.common import drives as drives_mod
    from safedatatransfer.common.drives import Drive
    from safedatatransfer.local_drop import commands as drop
    from safedatatransfer.tui import app as app_mod
    HAVE_TEXTUAL = True
except ImportError:
    HAVE_TEXTUAL = False

from safedatatransfer.usb_vault import vault

PW = "correct horse battery"
KEYS = ["h", "r", "a", "b", "d", "l", "x", "k", "s", "u", "o", "p", "f", "g", "c", "e", "w",
        "question_mark"]


def _quiet(*_):
    pass


@unittest.skipUnless(HAVE_TEXTUAL, "textual not installed")
class KeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        t = Path(cls._tmp.name)
        cls.stick = t / "stick"
        (cls.stick / "sub").mkdir(parents=True)
        (cls.stick / "a.txt").write_text("hello")
        (cls.stick / "sub" / "b.bin").write_bytes(b"x" * 5000)
        cls.vroot = t / "vaults"
        cls.other = t / "elsewhere" / "v2"
        vault.create_vault(cls.stick, cls.vroot / "v1", PW, log=_quiet)
        vault.create_vault(cls.stick, cls.other, PW, log=_quiet)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self.t = Path(tempfile.mkdtemp(dir=self._tmp.name))
        stick = self.stick

        class FakeDrive(Drive):
            @property
            def root(self) -> str:
                return str(stick) + "\\"

        self.drive = FakeDrive(letter="E:", type="removable", label="TEST", filesystem="FAT32",
                               serial=7, total_bytes=10**9, free_bytes=9 * 10**8, is_system=False)
        self.polls = 0
        for p in (mock.patch.object(drives_mod, "device_info",
                                    side_effect=drives_mod.DriveError("no device")),
                  mock.patch.object(drop, "DEFAULT_DEST", self.t / "inbox"),
                  mock.patch.object(app_mod, "check_destination", lambda dest: None)):
            p.start()
            self.addCleanup(p.stop)

    def _source(self):
        self.polls += 1
        return [self.drive]

    def run_app(self, steps):
        """Run steps(app, pilot, h); fail on 'coroutine was never awaited' (= a flow that never ran)."""
        notes: list[tuple[str, str]] = []

        async def go():
            app = app_mod.SdtApp(vault_root=self.vroot, drive_source=self._source)
            orig = app.notify

            def rec(message, *a, **k):
                notes.append((k.get("severity", "information"), str(message)))
                return orig(message, *a, **k)
            app.notify = rec
            async with app.run_test(size=(150, 46)) as pilot:
                await pilot.pause(0.8)
                await steps(app, pilot, _Helper(app, pilot, notes))

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            asyncio.run(go())
            gc.collect()
        never = [str(x.message) for x in w if "never awaited" in str(x.message)]
        self.assertEqual(never, [])
        return notes

    # ------------------------------------------------------------------ every key

    def test_every_key_reacts_on_every_tab(self):
        silent = []

        async def steps(app, pilot, h):
            for tab in ("1", "2", "3", "4"):
                await pilot.press(tab)
                await pilot.pause(0.3)
                for key in KEYS:
                    before, n0, polls0 = h.state(), len(h.notes), self.polls
                    await pilot.press(key)
                    await pilot.pause(0.25)
                    if h.state() == before and len(h.notes) == n0 and self.polls == polls0:
                        silent.append(f"tab {tab}: {key}")
                    await h.close_dialogs()
                    if key in ("d", "a", "b"):  # toggles: switch back
                        await pilot.press(key)
                        await pilot.pause(0.2)
            await pilot.press("q")
            await pilot.pause(0.5)
            self.assertFalse(app.is_running)

        self.run_app(steps)
        self.assertEqual(silent, [], "keys that did nothing visible")

    # ------------------------------------------------------------------ vaults

    def test_unlock_lock_add_and_open(self):
        out = self.t / "opened"

        async def steps(app, pilot, h):
            await pilot.press("2")
            await h.dialog("u", "PasswordModal", "wrong password")
            await h.wait(lambda: any(s == "error" for s, _ in h.notes))
            self.assertEqual(app.unlocked, {})
            await h.dialog("u", "PasswordModal", PW)
            await h.wait(lambda: app.unlocked)
            self.assertEqual(len(app.unlocked), 1)
            await pilot.press("l")
            await pilot.pause(0.3)
            self.assertEqual(app.unlocked, {})

            await h.dialog("p", "PathModal", str(self.t))  # not a vault
            await h.dialog("p", "PathModal", str(self.other))
            await pilot.pause(0.3)
            self.assertIn(self.other.resolve(), app.extra_vaults)

            app.selected_vault = self.vroot / "v1"
            await h.dialog("o", "PathModal", str(out))
            await h.answer("PasswordModal", PW)
            await h.wait(lambda: not app.busy and (out / "a.txt").exists())
            await h.dialog("o", "PathModal", str(out))  # same folder again: refused
            await h.answer("PasswordModal", PW)
            await h.wait(lambda: not app.busy)

        notes = self.run_app(steps)
        self.assertIn(("error", "Wrong password, or the vault was modified."), notes)
        self.assertTrue(any(s == "error" and m.startswith("No vault.json in") for s, m in notes))
        self.assertEqual((out / "a.txt").read_text(), "hello")
        self.assertEqual((out / "sub" / "b.bin").read_bytes(), b"x" * 5000)

    # ------------------------------------------------------------------ drive flows

    def test_copy_dry_and_real(self):
        dry_dest, real_dest = self.t / "dry", self.t / "real"

        async def steps(app, pilot, h):
            await pilot.press("d")  # dry-run on
            await h.dialog("c", "PlanModal", str(dry_dest))
            await h.wait(lambda: not app.busy and h.screen() == "Screen", 20)
            await pilot.press("d")  # live
            await h.dialog("c", "PlanModal", str(real_dest))
            await h.answer("PasswordModal", PW, "#pw1")
            await h.answer("PasswordModal", PW, "#pw2")
            await h.wait(lambda: not app.busy and h.screen() == "Screen", 30)
            await h.dialog("c", "PlanModal", str(self.stick / "vault"))  # inside the source
            await h.wait(lambda: not app.busy and h.screen() == "Screen")

        notes = self.run_app(steps)
        self.assertFalse(dry_dest.exists())
        self.assertEqual(len(vault.load_manifest(real_dest, PW)["files"]), 2)
        self.assertIn(("error", "Destination must not be inside the source."), notes)

    def test_other_dialog_during_copy_does_not_cancel_it(self):
        # u during a copy once cancelled the copy's flow: the UI then stayed "busy" forever.
        dest = self.t / "copy"
        real_create = vault.create_vault

        def slow_create(*a, **k):
            time.sleep(1.5)
            return real_create(*a, **k)

        async def steps(app, pilot, h):
            await h.dialog("c", "PlanModal", str(dest))
            await h.answer("PasswordModal", PW, "#pw1")
            await h.answer("PasswordModal", PW, "#pw2")
            await h.wait(lambda: app.busy)
            await pilot.press("u")  # unlock dialog while the copy runs
            await h.wait(lambda: h.screen() == "PasswordModal")
            await pilot.press("escape")
            await h.wait(lambda: not app.busy, 30)

        with mock.patch.object(app_mod.vault, "create_vault", slow_create):
            notes = self.run_app(steps)
        self.assertTrue(any(m.startswith("2 files,") for _, m in notes), notes)  # result shown
        self.assertTrue((dest / "vault.json").exists())

    def test_wipe_refused_when_the_stick_is_gone(self):
        # The fake E: is not a real drive, so the "same stick still there?" check must refuse.
        async def steps(app, pilot, h):
            await h.dialog("w", "PlanModal", None)
            await h.wait(lambda: not app.busy and h.screen() == "Screen")

        notes = self.run_app(steps)
        self.assertIn(("error", "E: is no longer connected. Not wiping."), notes)
        self.assertTrue((self.stick / "a.txt").exists())

    def test_hash_file(self):
        async def steps(app, pilot, h):
            await pilot.press("h")  # nothing selected
            app.current_file = self.stick / "a.txt"
            await pilot.press("h")
            await h.wait(lambda: app.hashes)

        notes = self.run_app(steps)
        self.assertIn(("warning", "Select a file in the FILES tree first."), notes)

    # ------------------------------------------------------------------ drop

    def test_drop_list_and_receive_stop(self):
        def fake_receive(dest, via, allow_cloud, name, hooks):
            hooks.on_ready("sdt-1", "111-222", dest)
            while not hooks.cancelled():
                time.sleep(0.05)
            raise drop.Cancelled()

        async def steps(app, pilot, h):
            await pilot.press("4")
            for p in (self.stick / "a.txt", self.stick / "a.txt", self.t / "nope.txt",
                      f'"{self.stick / "sub"}"'):
                await h.dialog("f", "PathModal", str(p))
            self.assertEqual(app.send_paths, [(self.stick / "a.txt").resolve(),
                                              (self.stick / "sub").resolve()])
            await pilot.press("x")
            self.assertEqual(app.send_paths, [])
            await h.dialog("g", "PathModal", str(self.stick / "a.txt"))  # a file, not a folder
            await h.dialog("g", "PathModal", str(self.t / "inbox"))
            await h.wait(lambda: app.drop_running == "receiving")
            await pilot.press("g")  # already busy
            await pilot.press("c")
            await pilot.press("k")
            await h.wait(lambda: not app.drop_running)

        with mock.patch.object(drop, "receive", fake_receive):
            notes = self.run_app(steps)
        msgs = [m for _, m in notes]
        self.assertTrue(any(m.startswith("Not found:") for m in msgs))
        self.assertTrue(any(m.endswith("is a file, not a folder.") for m in msgs))
        self.assertGreaterEqual(msgs.count("Busy: receiving"), 2)
        self.assertIn("receiving stopped", msgs)


class _Helper:
    def __init__(self, app, pilot, notes):
        self.app, self.pilot, self.notes = app, pilot, notes

    def screen(self) -> str:
        return type(self.app.screen).__name__

    def state(self):
        a = self.app
        return (a.query_one("TabbedContent").active, self.screen(), a.dry_run, a.show_all,
                a.busy, a.query_one("#top").display, len(a.query_one("#log").lines),
                len(a.unlocked), len(a.send_paths))

    async def wait(self, cond, timeout=10.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cond():
                return
            await self.pilot.pause(0.1)
        raise AssertionError("condition not reached")

    async def answer(self, modal: str, text: str | None, field: str | None = None):
        await self.wait(lambda: self.screen() == modal)
        if text is not None:
            inp = self.app.screen.query_one(field) if field else self.app.screen.query(Input).first()
            inp.value = text
            inp.focus()
        await self.pilot.press("enter")
        await self.pilot.pause(0.4)

    async def dialog(self, key: str, modal: str, text: str | None):
        await self.pilot.press(key)
        await self.answer(modal, text)

    async def close_dialogs(self):
        for _ in range(3):
            if self.screen() != "Screen":
                await self.pilot.press("escape")
                await self.pilot.pause(0.2)


if __name__ == "__main__":
    unittest.main()
