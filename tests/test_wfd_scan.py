"""Wi-Fi Direct receiver search: late information elements, early stop, --to waiting.

Windows' device watcher is replaced by a fake that fires Added/Updated events from
another thread, like the real one does."""

import threading
import time
import unittest
from unittest import mock

from safedatatransfer.local_drop import commands, wifidirect


class FakeInfo:
    def __init__(self, dev_id, sdt_name=None):
        self.id = dev_id
        self.sdt_name = sdt_name

    def update(self, upd):
        self.sdt_name = upd.sdt_name


class FakeUpdate:
    def __init__(self, dev_id, sdt_name):
        self.id = dev_id
        self.sdt_name = sdt_name


class FakeWatcher:
    """events: list of (delay_s, kind, obj) with kind 'added' / 'updated'."""

    def __init__(self, events):
        self.events = events
        self.handlers = {}
        self.stopped = False

    def add_added(self, h): self.handlers["added"] = h
    def add_updated(self, h): self.handlers["updated"] = h
    def add_removed(self, h): self.handlers["removed"] = h
    def add_enumeration_completed(self, h): pass

    def start(self):
        def run():
            t0 = time.monotonic()
            for delay, kind, obj in self.events:
                time.sleep(max(0.0, delay - (time.monotonic() - t0)))
                if self.stopped:
                    return
                self.handlers[kind](self, obj)
        threading.Thread(target=run, daemon=True).start()

    def stop(self):
        self.stopped = True


def make_device_information(watcher, lookup=None):
    class FakeDeviceInformation:
        @staticmethod
        def create_watcher(_selector, _props):
            return watcher

        @staticmethod
        async def create_from_id_async(dev_id, _props):
            if lookup and dev_id in lookup:
                return lookup[dev_id]
            raise OSError("not found")
    return FakeDeviceInformation


class ScanTests(unittest.TestCase):
    def scan(self, events, lookup=None, **kw):
        watcher = FakeWatcher(events)
        with mock.patch.object(wifidirect, "_require"), \
             mock.patch.object(wifidirect, "WiFiDirectDevice", create=True), \
             mock.patch.object(wifidirect, "WiFiDirectDeviceSelectorType", create=True), \
             mock.patch.object(wifidirect, "DeviceInformation",
                               make_device_information(watcher, lookup), create=True), \
             mock.patch.object(wifidirect, "_peer_name", lambda info: info.sdt_name):
            conn = wifidirect.Connector()
            try:
                t0 = time.monotonic()
                peers = conn.scan(**kw)
                return peers, time.monotonic() - t0
            finally:
                conn._lt.close()

    def test_name_that_arrives_in_a_later_update_is_found(self):
        # The old scanner ignored Updated events and lost this receiver.
        peers, _ = self.scan([(0.1, "added", FakeInfo("dev1")),
                              (0.6, "updated", FakeUpdate("dev1", "sdt-4821"))],
                             timeout=5, settle=1)
        self.assertEqual([p.name for p in peers], ["sdt-4821"])

    def test_stops_early_once_a_receiver_is_found(self):
        peers, took = self.scan([(0.1, "added", FakeInfo("dev1", "sdt-1111"))],
                                timeout=20, settle=1)
        self.assertEqual(len(peers), 1)
        self.assertLess(took, 5)

    def test_slow_receiver_is_still_found(self):
        # Shows up after several seconds (older adapters), well after the old 6 s... scaled down.
        peers, _ = self.scan([(2.5, "added", FakeInfo("dev1", "sdt-2222"))],
                             timeout=6, settle=1)
        self.assertEqual([p.name for p in peers], ["sdt-2222"])

    def test_gives_up_after_timeout(self):
        peers, took = self.scan([(0.1, "added", FakeInfo("tv", None))], timeout=2, settle=1)
        self.assertEqual(peers, [])
        self.assertLess(took, 6)

    def test_direct_lookup_finds_elements_that_never_arrived(self):
        peers, _ = self.scan([(0.1, "added", FakeInfo("dev1"))],
                             lookup={"dev1": FakeInfo("dev1", "sdt-3333")},
                             timeout=5, settle=1)
        self.assertEqual([p.name for p in peers], ["sdt-3333"])

    def test_with_to_keeps_waiting_for_that_receiver(self):
        done = lambda peers: any(commands._matches(p.name, "sdt-5555") for p in peers)
        peers, _ = self.scan([(0.1, "added", FakeInfo("a", "sdt-4444")),
                              (2.0, "added", FakeInfo("b", "sdt-5555"))],
                             timeout=6, settle=0.5, done=done)
        self.assertIn("sdt-5555", [p.name for p in peers])

    def test_removed_device_is_dropped(self):
        peers, _ = self.scan([(0.1, "added", FakeInfo("a", "sdt-6666")),
                              (0.2, "removed", FakeUpdate("a", None))],
                             timeout=2, settle=1)
        self.assertEqual(peers, [])


if __name__ == "__main__":
    unittest.main()
