"""The shared send/receive core with Hooks (used by both CLI and UI), end to end over
127.0.0.1. No Wi-Fi Direct: the sender is given the address directly, like --host."""

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from safedatatransfer.local_drop import commands as drop


class HooksEndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.t = Path(self._tmp.name)
        self.src = self.t / "src"
        self.src.mkdir()
        (self.src / "a.txt").write_bytes(b"hello" * 1000)
        (self.src / "sub").mkdir()
        (self.src / "sub" / "b.bin").write_bytes(bytes(range(256)) * 4000)
        self.dest = self.t / "inbox"

    def tearDown(self):
        self._tmp.cleanup()

    def _receiver(self, server, code, accept, out):
        conn, _ = server.accept()
        server.close()
        progress = []
        try:
            out["files"] = drop._receive_on(conn, code, self.dest, drop.Hooks(
                log=lambda m: None, ask_accept=accept,
                progress=lambda d, t: progress.append((d, t))))
        except Exception as e:  # reported to the test thread
            out["error"] = e
        out["progress"] = progress

    def _run(self, accept, sender_code="482-913"):
        server = socket.create_server(("127.0.0.1", 0))
        port = server.getsockname()[1]
        out: dict = {}
        th = threading.Thread(target=self._receiver, args=(server, "482-913", accept, out))
        th.start()
        logs, progress = [], []
        hooks = drop.Hooks(log=logs.append, ask_code=lambda: sender_code,
                           progress=lambda d, t: progress.append((d, t)))
        try:
            result = drop.send([self.src], None, "wifi-direct", f"127.0.0.1:{port}", None, hooks)
        except Exception as e:
            result = e
        th.join(10)
        return result, out, logs, progress

    def test_files_arrive_with_progress(self):
        result, out, logs, progress = self._run(accept=lambda offer: True)
        self.assertEqual(result, 2)
        self.assertNotIn("error", out)
        self.assertEqual((self.dest / "src" / "a.txt").read_bytes(), b"hello" * 1000)
        self.assertEqual((self.dest / "src" / "sub" / "b.bin").read_bytes(), bytes(range(256)) * 4000)
        total = 5000 + 256 * 4000
        self.assertEqual(progress[-1], (total, total))
        self.assertEqual(out["progress"][-1], (total, total))
        self.assertTrue(any("code verified" in m for m in logs))

    def test_decline_writes_nothing(self):
        result, out, _, _ = self._run(accept=lambda offer: False)
        self.assertIsInstance(result, drop.protocol.Rejected)
        self.assertIsInstance(out.get("error"), drop.protocol.Rejected)
        self.assertFalse(self.dest.exists())

    def test_wrong_code_fails(self):
        result, out, _, _ = self._run(accept=lambda offer: True, sender_code="111-111")
        self.assertIsInstance(result, Exception)
        self.assertIn("error", out)
        self.assertFalse(self.dest.exists())

    def test_empty_code_cancels(self):
        result, _, _, _ = self._run(accept=lambda offer: True, sender_code=None)
        self.assertIsInstance(result, drop.Cancelled)

    def test_stop_during_transfer_leaves_no_partial_file(self):
        big = self.src / "big.bin"
        big.write_bytes(b"x" * (5 << 20))  # several 1 MiB chunks
        server = socket.create_server(("127.0.0.1", 0))
        port = server.getsockname()[1]
        out: dict = {}
        th = threading.Thread(target=self._receiver,
                              args=(server, "482-913", lambda offer: True, out))
        th.start()
        stop = threading.Event()

        def progress(done, total):
            if done >= (2 << 20):
                stop.set()  # the user presses Stop after ~2 MiB

        hooks = drop.Hooks(log=lambda m: None, ask_code=lambda: "482-913",
                           progress=progress, cancelled=stop.is_set)
        with self.assertRaises(drop.Cancelled):
            drop.send([big], None, "wifi-direct", f"127.0.0.1:{port}", None, hooks)
        th.join(10)
        self.assertIn("error", out)  # the receiver noticed the sender stopped
        leftovers = [p for p in self.dest.rglob("*") if p.is_file()] if self.dest.exists() else []
        self.assertEqual(leftovers, [], "no partial or unverified file may remain")

    def test_stop_while_accept_question_is_open_counts_as_stopped(self):
        stop = threading.Event()

        def accept(offer):
            stop.set()  # Stop pressed while the dialog was open; the dialog returns "no"
            return False

        server = socket.create_server(("127.0.0.1", 0))
        port = server.getsockname()[1]
        out: dict = {}

        def receiver():
            conn, _ = server.accept()
            server.close()
            try:
                drop._receive_on(conn, "482-913", self.dest, drop.Hooks(
                    log=lambda m: None, ask_accept=accept, cancelled=stop.is_set))
            except Exception as e:
                out["error"] = e

        th = threading.Thread(target=receiver)
        th.start()
        try:
            drop.send([self.src], None, "wifi-direct", f"127.0.0.1:{port}", None,
                      drop.Hooks(log=lambda m: None, ask_code=lambda: "482-913"))
        except Exception:
            pass
        th.join(10)
        self.assertIsInstance(out.get("error"), drop.Cancelled)
        self.assertFalse(self.dest.exists())

    def test_nothing_to_send(self):
        empty = self.t / "empty"
        empty.mkdir()
        with self.assertRaises(drop.protocol.ProtocolError):
            drop.send([empty], None, "wifi-direct", "127.0.0.1:1", "000-000", drop.Hooks())


if __name__ == "__main__":
    unittest.main()
