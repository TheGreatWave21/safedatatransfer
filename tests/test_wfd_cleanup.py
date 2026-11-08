"""Wi-Fi Direct clean-up: a failed start never leaves this PC advertising, and timeouts
give a clear message instead of an empty one."""

import unittest
from unittest import mock

from safedatatransfer.local_drop import wifidirect


@unittest.skipUnless(wifidirect.AVAILABLE, "winrt not installed")
class AdvertiserCleanup(unittest.TestCase):
    def test_failed_start_stops_everything(self):
        async def boom(self_):
            raise wifidirect.WifiDirectError("advertising aborted")

        with mock.patch.object(wifidirect.Advertiser, "_start", boom):
            adv = wifidirect.Advertiser("sdt-0000", log=lambda m: None)
            with self.assertRaises(wifidirect.WifiDirectError):
                adv.start()
        self.assertTrue(adv._stopped)
        self.assertFalse(adv._lt._thread.is_alive())
        adv.stop()  # a second stop is harmless

    def test_start_timeout_is_a_clear_error(self):
        with mock.patch.object(wifidirect._LoopThread, "run", side_effect=TimeoutError()):
            adv = wifidirect.Advertiser("sdt-0000", log=lambda m: None)
            with self.assertRaises(wifidirect.WifiDirectError) as ctx:
                adv.start()
        self.assertIn("did not start", str(ctx.exception))
        self.assertTrue(adv._stopped)

    def test_connect_timeout_is_a_clear_error(self):
        conn = wifidirect.Connector()
        try:
            with mock.patch.object(conn._lt, "run", side_effect=TimeoutError()):
                with self.assertRaises(wifidirect.WifiDirectError) as ctx:
                    conn.connect(wifidirect.WfdPeer("sdt-1234", "id"))
            self.assertIn("sdt-1234", str(ctx.exception))
            self.assertIn("did not come up", str(ctx.exception))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
