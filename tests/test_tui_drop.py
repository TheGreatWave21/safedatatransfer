"""The Drop tab in the UI: dialogs, decline-by-default, Stop, dry-run.

The radio part (drop.send / drop.receive) is replaced by fakes that drive the same hooks
the real transfer uses; the protocol itself is covered in test_local_drop.py."""

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    from textual.widgets import Static

    from safedatatransfer.local_drop import commands as drop
    from safedatatransfer.tui.app import SdtApp
    from safedatatransfer.tui.modals import AcceptModal, CodeModal
    HAVE_TEXTUAL = True
except ImportError:
    HAVE_TEXTUAL = False

OFFER = {"sender": "LAPTOP", "files": [{"path": "report.pdf", "size": 1234}]}


def _status(app) -> str:
    return str(app.query_one("#drop-status", Static).render())


@unittest.skipUnless(HAVE_TEXTUAL, "textual not installed")
class DropTabTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.t = Path(self._tmp.name)
        self.dest = self.t / "inbox"
        self.patch = mock.patch.object(drop, "DEFAULT_DEST", self.dest)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self._tmp.cleanup()

    def run_app(self, steps):
        async def go():
            app = SdtApp(vault_root=self.t / "vaults", drive_source=lambda: [])
            async with app.run_test(size=(150, 46)) as pilot:
                await pilot.pause(0.3)
                await steps(app, pilot)
        asyncio.run(go())

    async def wait_for(self, pilot, cond, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cond():
                return
            await pilot.pause(0.1)
        raise AssertionError("condition not reached")

    def test_receive_shows_code_and_accept_works(self):
        seen = {}

        def fake_receive(dest, via, allow_cloud, name, hooks):
            seen["via"] = via
            hooks.on_ready("sdt-4821", "482-913", dest)
            seen["accepted"] = hooks.ask_accept(OFFER)
            return [dest / "report.pdf"] if seen["accepted"] else []

        async def steps(app, pilot):
            await pilot.press("4")
            await pilot.press("g")
            await pilot.pause(0.3)
            await pilot.press("enter")  # keep the default folder
            await self.wait_for(pilot, lambda: isinstance(app.screen, AcceptModal))
            info = str(app.query_one("#recv-info", Static).render())
            self.assertIn("sdt-4821", info)
            self.assertIn("482-913", info)
            await pilot.click("#ok")
            await self.wait_for(pilot, lambda: "received 1" in _status(app))

        with mock.patch.object(drop, "receive", fake_receive):
            self.run_app(steps)
        self.assertEqual(seen, {"via": "wifi-direct", "accepted": True})

    def test_enter_alone_declines(self):
        seen = {}

        def fake_receive(dest, via, allow_cloud, name, hooks):
            seen["accepted"] = hooks.ask_accept(OFFER)
            raise drop.protocol.Rejected("You declined the transfer.")

        async def steps(app, pilot):
            await pilot.press("g")
            await pilot.pause(0.3)
            await pilot.press("enter")
            await self.wait_for(pilot, lambda: isinstance(app.screen, AcceptModal))
            await pilot.press("enter")  # focus starts on Decline
            await self.wait_for(pilot, lambda: "declined" in _status(app))

        with mock.patch.object(drop, "receive", fake_receive):
            self.run_app(steps)
        self.assertEqual(seen, {"accepted": False})

    def test_send_asks_for_code(self):
        f = self.t / "a.txt"
        f.write_text("hello")
        seen = {}

        def fake_send(paths, to, via, host, code, hooks):
            seen["paths"] = paths
            seen["code"] = hooks.ask_code()
            return len(paths)

        async def steps(app, pilot):
            await pilot.press("f")
            await pilot.pause(0.3)
            app.screen.query_one("#path").value = str(f)
            await pilot.press("enter")
            await pilot.pause(0.3)
            self.assertEqual(app.send_paths, [f.resolve()])
            await pilot.press("s")
            await self.wait_for(pilot, lambda: isinstance(app.screen, CodeModal))
            for ch in "482913":
                await pilot.press(ch)
            await pilot.press("enter")
            await self.wait_for(pilot, lambda: "sent 1" in _status(app))

        with mock.patch.object(drop, "send", fake_send):
            self.run_app(steps)
        self.assertEqual(seen, {"paths": [f.resolve()], "code": "482-913"})

    def test_stop_while_waiting(self):
        def fake_receive(dest, via, allow_cloud, name, hooks):
            hooks.on_ready("sdt-1111", "111-222", dest)
            while not hooks.cancelled():
                time.sleep(0.05)
            raise drop.Cancelled()

        async def steps(app, pilot):
            await pilot.press("g")
            await pilot.pause(0.3)
            await pilot.press("enter")
            await self.wait_for(pilot, lambda: app.drop_running == "receiving"
                                and "111-222" in str(app.query_one("#recv-info", Static).render()))
            await pilot.press("k")
            await self.wait_for(pilot, lambda: "stopped" in _status(app))
            self.assertEqual(app.busy, "")
            self.assertIn("Not receiving", str(app.query_one("#recv-info", Static).render()))

        with mock.patch.object(drop, "receive", fake_receive):
            self.run_app(steps)

    def test_dry_run_refuses_drop(self):
        called = []

        async def steps(app, pilot):
            await pilot.press("d")  # DRY-RUN on
            await pilot.press("g")
            await pilot.pause(0.4)
            self.assertFalse(app.drop_running)

        with mock.patch.object(drop, "receive", lambda *a: called.append(a)):
            self.run_app(steps)
        self.assertEqual(called, [])

    def test_send_needs_files(self):
        async def steps(app, pilot):
            await pilot.press("s")
            await pilot.pause(0.3)
            self.assertFalse(app.drop_running)

        with mock.patch.object(drop, "send", lambda *a: self.fail("must not send")):
            self.run_app(steps)


if __name__ == "__main__":
    unittest.main()
