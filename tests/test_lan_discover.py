"""LAN discovery must ignore malformed replies instead of crashing the sender."""

import json
import socket
import threading
import unittest

from safedatatransfer.local_drop import lan


class LanDiscoverTests(unittest.TestCase):
    def test_bad_replies_are_ignored(self):
        try:
            fake = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fake.bind(("127.0.0.1", lan.DISCOVERY_PORT))
        except OSError:
            self.skipTest("discovery port in use")
        fake.settimeout(3)
        good = json.dumps({"sdt": 1, "name": "sdt-7777", "port": 47802}).encode()

        def reply():
            try:
                _, addr = fake.recvfrom(256)
                for bad in (b"[1, 2]", b"42", b"\"text\"", b"not json",
                            json.dumps({"sdt": 1, "name": "x", "port": 99999}).encode()):
                    fake.sendto(bad, addr)
                fake.sendto(good, addr)
            except OSError:
                pass

        th = threading.Thread(target=reply)
        th.start()
        try:
            peers = lan.discover(timeout=1.5)
        finally:
            th.join(5)
            fake.close()
        self.assertEqual([p.name for p in peers], ["sdt-7777"])


if __name__ == "__main__":
    unittest.main()
