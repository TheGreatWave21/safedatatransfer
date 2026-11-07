import socket
import tempfile
import threading
import unittest
from pathlib import Path

from safedatatransfer.local_drop import protocol as p


def _quiet(_m: str) -> None:
    pass


class Transfer:
    """Run sender and receiver on two ends of a socketpair."""

    def __init__(self, files, sender_code, receiver_code, accept=True, tamper=False):
        self.files, self.sender_code, self.receiver_code = files, sender_code, receiver_code
        self.accept, self.tamper = accept, tamper
        self.sender_error = self.receiver_error = None
        self.received = []

    def _sender(self, sock):
        try:
            ch = p.handshake_sender(sock, self.sender_code)
            if self.tamper:
                orig = p.send_frame

                def flip(s, payload):
                    if len(payload) > 1000:
                        payload = payload[:500] + bytes([payload[500] ^ 1]) + payload[501:]
                    orig(s, payload)
                p.send_frame = flip
                try:
                    p.send_files(ch, self.files, "tester", log=_quiet)
                finally:
                    p.send_frame = orig
            else:
                p.send_files(ch, self.files, "tester", log=_quiet)
        except Exception as e:
            self.sender_error = e
        finally:
            sock.close()

    def run(self, dest: Path):
        a, b = socket.socketpair()
        a.settimeout(10)
        b.settimeout(10)
        t = threading.Thread(target=self._sender, args=(a,))
        t.start()
        try:
            ch = p.handshake_receiver(b, self.receiver_code)
            self.received = p.receive_files(ch, dest, lambda offer: self.accept, log=_quiet)
        except Exception as e:
            self.receiver_error = e
        finally:
            b.close()
            t.join(10)
        return self


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        src = self.tmp / "src"
        (src / "folder" / "sub").mkdir(parents=True)
        (src / "a.txt").write_text("hello")
        (src / "folder" / "big.bin").write_bytes(b"x" * (3 * 1024 * 1024 + 7))
        (src / "folder" / "sub" / "empty").write_bytes(b"")
        self.files = p.collect_files([src / "a.txt", src / "folder"])
        self.dest = self.tmp / "dest"

    def tearDown(self):
        self._tmp.cleanup()

    def test_success(self):
        r = Transfer(self.files, "123-456", "123456").run(self.dest)
        self.assertIsNone(r.receiver_error)
        self.assertIsNone(r.sender_error)
        self.assertEqual((self.dest / "a.txt").read_text(), "hello")
        self.assertEqual((self.dest / "folder" / "big.bin").stat().st_size, 3 * 1024 * 1024 + 7)
        self.assertTrue((self.dest / "folder" / "sub" / "empty").exists())

    def test_wrong_code(self):
        r = Transfer(self.files, "111-111", "222-222").run(self.dest)
        self.assertIsInstance(r.receiver_error, p.WrongCode)
        self.assertFalse(self.dest.exists())

    def test_rejected(self):
        r = Transfer(self.files, "123-456", "123-456", accept=False).run(self.dest)
        self.assertIsInstance(r.receiver_error, p.Rejected)
        self.assertIsInstance(r.sender_error, p.Rejected)
        self.assertFalse(self.dest.exists())

    def test_tampering_detected_and_partial_removed(self):
        r = Transfer(self.files, "123-456", "123-456", tamper=True).run(self.dest)
        self.assertIsInstance(r.receiver_error, p.ProtocolError)
        leftovers = [f for f in self.dest.rglob("*") if f.is_file() and f.name != "a.txt"]
        self.assertEqual(leftovers, [])

    def test_duplicate_names_not_overwritten(self):
        self.dest.mkdir()
        (self.dest / "a.txt").write_text("existing")
        Transfer(self.files, "123-456", "123-456").run(self.dest)
        self.assertEqual((self.dest / "a.txt").read_text(), "existing")
        self.assertEqual((self.dest / "a (1).txt").read_text(), "hello")


class ReceiverExposureTests(unittest.TestCase):
    """The receiver takes one connection, only from the linked PC, then closes its port."""

    def _server(self):
        server = socket.create_server(("127.0.0.1", 0))  # loopback only: no firewall prompt
        return server, server.getsockname()[1]

    def test_accepts_linked_peer_then_closes_port(self):
        from safedatatransfer.local_drop.commands import _accept_one
        server, port = self._server()
        client = socket.create_connection(("127.0.0.1", port))
        conn = _accept_one(server, "127.0.0.1")
        conn.close()
        client.close()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)

    def test_ignores_other_addresses(self):
        from safedatatransfer.local_drop import commands
        server, port = self._server()
        old = commands.ACCEPT_TIMEOUT
        commands.ACCEPT_TIMEOUT = 1.5
        try:
            client = socket.create_connection(("127.0.0.1", port))
            with self.assertRaises(p.ProtocolError):
                commands._accept_one(server, "10.99.99.99")  # only this IP may connect
            client.close()
        finally:
            commands.ACCEPT_TIMEOUT = old


class SafePathTests(unittest.TestCase):
    def test_traversal_rejected(self):
        for bad in ("../x", "a/../../x", "", "a//b", "./x"):
            with self.assertRaises(p.ProtocolError, msg=bad):
                p.safe_relpath(bad)

    def test_sanitized(self):
        self.assertEqual(p.safe_relpath("C:\\Windows\\x"), Path("C__Windows_x"))
        self.assertEqual(p.safe_relpath("con.txt"), Path("_con.txt"))
        self.assertEqual(p.safe_relpath("dir/file.txt"), Path("dir", "file.txt"))

    def test_codes(self):
        code = p.new_code()
        self.assertRegex(code, r"^\d{3}-\d{3}$")
        self.assertEqual(p.normalize_code("12 34-56"), b"123456")
        with self.assertRaises(ValueError):
            p.normalize_code("123")


if __name__ == "__main__":
    unittest.main()
