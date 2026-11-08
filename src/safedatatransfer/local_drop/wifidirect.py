"""Wi-Fi Direct link (PC-to-PC, no router) via the Windows Runtime API.

This module only creates the radio link and finds the peer's IP address on it.
The link's own pairing is "push button" and is NOT what keeps data safe — the
one-time code + encryption in protocol.py does that, on top of this link.

Receiver: advertise with an sdt-specific information element, accept incoming
          Wi-Fi Direct connections.
Sender:   scan for devices carrying that element, pair + connect, then open a
          TCP socket to the receiver's IP on the new link.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Any, Callable, Coroutine

from safedatatransfer.local_drop.protocol import clean_text

try:
    from winrt.windows.devices.enumeration import (
        DeviceInformation, DevicePairingProtectionLevel, DevicePairingResultStatus,
    )
    from winrt.windows.devices.wifidirect import (
        WiFiDirectAdvertisementListenStateDiscoverability as Discoverability,
        WiFiDirectAdvertisementPublisher, WiFiDirectAdvertisementPublisherStatus as PubStatus,
        WiFiDirectConfigurationMethod,
        WiFiDirectConnectionListener, WiFiDirectConnectionParameters, WiFiDirectDevice,
        WiFiDirectDeviceSelectorType, WiFiDirectInformationElement, WiFiDirectPairingProcedure,
    )
    from winrt.windows.storage.streams import DataReader, DataWriter
    AVAILABLE = True
    IMPORT_ERROR = ""
except ImportError as _e:  # not Windows, or winrt packages missing
    AVAILABLE = False
    IMPORT_ERROR = str(_e)

# Vendor-specific information element that marks an sdt receiver.
OUI = b"SDT"
OUI_TYPE = 0x01
IE_PREFIX = b"sdt-drop/1|"
IE_PROPERTY = "System.Devices.WiFiDirect.InformationElements"

SCAN_TIMEOUT = 30.0  # seconds the sender looks for receivers at most
SCAN_SETTLE = 4.0    # ...and at least, so several nearby receivers can show up


class WifiDirectError(Exception):
    pass


@dataclass(frozen=True)
class WfdPeer:
    name: str
    device_id: str


def _require() -> None:
    if not AVAILABLE:
        raise WifiDirectError(f"Wi-Fi Direct support is not installed ({IMPORT_ERROR}).")


# ---------------------------------------------------------------- buffers

def _to_buffer(data: bytes):
    w = DataWriter()
    w.write_bytes(data)
    return w.detach_buffer()


def _from_buffer(buf) -> bytes:
    if buf is None:
        return b""
    try:
        return bytes(memoryview(buf))
    except TypeError:
        reader = DataReader.from_buffer(buf)
        out = bytearray(buf.length)
        reader.read_bytes(out)
        return bytes(out)


def _sdt_elements(name: str):
    """Build an IVector<WiFiDirectInformationElement> containing our vendor IE."""
    value = IE_PREFIX + name.encode("utf-8")[:200]
    body = OUI + bytes([OUI_TYPE]) + value
    raw = bytes([221, len(body)]) + body  # 221 = vendor-specific element
    return WiFiDirectInformationElement.create_from_buffer(_to_buffer(raw))


def _named(found: dict[str, Any]) -> list[WfdPeer]:
    """The sdt receivers among the devices found so far (others have no sdt element)."""
    peers = []
    for dev_id, info in list(found.items()):
        name = _peer_name(info)
        if name is not None:
            peers.append(WfdPeer(name, dev_id))
    return peers


def _peer_name(info) -> str | None:
    try:
        elements = WiFiDirectInformationElement.create_from_device_information(info)
    except OSError:
        return None
    for ie in elements or []:
        if _from_buffer(ie.oui) == OUI and ie.oui_type == OUI_TYPE:
            value = _from_buffer(ie.value)
            if value.startswith(IE_PREFIX):
                return clean_text(value[len(IE_PREFIX):].decode("utf-8", "replace") or info.name, 64)
    return None


# ---------------------------------------------------------------- event loop thread

class _LoopThread:
    """A background asyncio loop so blocking CLI code can call WinRT coroutines."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._thread.start()

    def run(self, coro: Coroutine[Any, Any, Any], timeout: float | None = None) -> Any:
        fut: Future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut.result(timeout)

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)


# ---------------------------------------------------------------- pairing

def _connection_params() -> Any:
    params = WiFiDirectConnectionParameters()
    params.preference_ordered_configuration_methods.append(WiFiDirectConfigurationMethod.PUSH_BUTTON)
    params.preferred_pairing_procedure = WiFiDirectPairingProcedure.GROUP_OWNER_NEGOTIATION
    return params


async def _ensure_paired(info) -> bool:
    """Pair if needed. Returns True if WE created the pairing (so we remove it later)."""
    if info.pairing.is_paired:
        return False
    custom = info.pairing.custom
    token = custom.add_pairing_requested(lambda _s, args: args.accept())
    try:
        kinds = WiFiDirectConnectionParameters.get_device_pairing_kinds(
            WiFiDirectConfigurationMethod.PUSH_BUTTON)
        result = await custom.pair_with_protection_level_and_settings_async(
            kinds, DevicePairingProtectionLevel.DEFAULT, _connection_params())
    finally:
        custom.remove_pairing_requested(token)
    if result.status not in (DevicePairingResultStatus.PAIRED,
                             DevicePairingResultStatus.ALREADY_PAIRED):
        raise WifiDirectError(f"Wi-Fi Direct pairing failed: {result.status!r}")
    return result.status == DevicePairingResultStatus.PAIRED


async def _unpair(infos: list) -> None:
    """Remove pairings made during this session, so Windows does not keep trusting the
    other device afterwards. Best effort."""
    for info in infos:
        try:
            await info.pairing.unpair_async()
        except Exception:
            pass


def _forget(lt: "_LoopThread", infos: list) -> None:
    if infos:
        try:
            lt.run(_unpair(infos), timeout=15)
        except Exception:
            pass


# ---------------------------------------------------------------- receiver side

class Advertiser:
    """Make this PC visible as an sdt receiver and accept Wi-Fi Direct links."""

    def __init__(self, name: str, log: Callable[[str], None] = print,
                 on_link: Callable[[str, str], None] | None = None):
        """on_link(local_ip, remote_ip) is called when a Wi-Fi Direct link is up."""
        _require()
        self.name = name
        self.log = log
        self.on_link = on_link
        self._lt = _LoopThread()
        self._devices: list[Any] = []  # keep references, or Windows drops the link
        self._publisher = None
        self._listener = None
        self._token = None
        self._linked = False
        self._paired_here: list[Any] = []

    def start(self) -> "Advertiser":
        self._lt.run(self._start(), timeout=15)
        return self

    async def _start(self) -> None:
        loop = asyncio.get_running_loop()
        self._listener = WiFiDirectConnectionListener()

        def on_request(_sender, args):
            request = args.get_connection_request()
            asyncio.run_coroutine_threadsafe(self._accept(request), loop)

        self._token = self._listener.add_connection_requested(on_request)
        self._publisher = WiFiDirectAdvertisementPublisher()
        adv = self._publisher.advertisement
        # INTENSIVE: listen more often, so slower adapters find us. Only while waiting
        # for a sender; advertising stops as soon as a link is up.
        adv.listen_state_discoverability = Discoverability.INTENSIVE
        adv.information_elements = _sdt_elements(self.name)
        self._publisher.start()
        for _ in range(50):
            status = self._publisher.status
            if status == PubStatus.STARTED:
                return
            if status == PubStatus.ABORTED:
                break
            await asyncio.sleep(0.1)
        raise WifiDirectError(f"Wi-Fi Direct advertising did not start "
                              f"(status {self._publisher.status!r}). Is Wi-Fi turned on?")

    async def _accept(self, request) -> None:
        info = request.device_information
        if self._linked:  # one link per receive session; ignore everyone else
            self.log("  Wi-Fi Direct: ignored another connection request (already linked)")
            return
        self._linked = True  # set before awaiting: this loop runs one callback at a time
        try:
            self.log(f"  Wi-Fi Direct: connection request from {clean_text(info.name, 64)}")
            if await _ensure_paired(info):
                self._paired_here.append(info)
            device = await WiFiDirectDevice.from_id_async(info.id)
            self._devices.append(device)
            for _ in range(100):  # the link needs a moment to get IP addresses
                pairs = device.get_connection_endpoint_pairs()
                if pairs:
                    break
                await asyncio.sleep(0.2)
            else:
                self.log("  Wi-Fi Direct: link came up without an IP address")
                self._linked = False
                return
            local = pairs[0].local_host_name.display_name
            remote = pairs[0].remote_host_name.display_name
            self.log(f"  Wi-Fi Direct: link up ({local} <-> {remote})")
            try:
                self._publisher.stop()  # no longer visible to anyone else nearby
            except Exception:
                pass
            if self.on_link:
                self.on_link(local, remote)
        except Exception as e:  # never crash the receiver from a callback
            self._linked = False
            self.log(f"  Wi-Fi Direct: could not accept link: {e}")

    def stop(self) -> None:
        try:
            if self._publisher is not None:
                self._publisher.stop()
            if self._listener is not None and self._token is not None:
                self._listener.remove_connection_requested(self._token)
            for d in self._devices:
                d.close()
        finally:
            _forget(self._lt, self._paired_here)
            self._lt.close()


# ---------------------------------------------------------------- sender side

class Connector:
    """Scan for sdt receivers over Wi-Fi Direct and connect to one."""

    def __init__(self) -> None:
        _require()
        self._lt = _LoopThread()
        self._device = None  # keep alive for the whole transfer
        self._paired_here: list[Any] = []

    def scan(self, timeout: float = SCAN_TIMEOUT, settle: float = SCAN_SETTLE,
             done: Callable[[list[WfdPeer]], bool] | None = None,
             on_wait: Callable[[int], None] | None = None) -> list[WfdPeer]:
        """Look for sdt receivers for up to `timeout` seconds.

        Stops early once `done(peers)` is true (default: at least one receiver found)
        and at least `settle` seconds have passed, so several nearby receivers can show
        up before the list is used. Wi-Fi Direct discovery is slow on some (older)
        adapters, so a short fixed scan misses receivers that are really there."""
        return self._lt.run(self._scan(timeout, settle, done or bool, on_wait),
                            timeout=timeout + 30)

    async def _scan(self, timeout: float, settle: float,
                    done: Callable[[list[WfdPeer]], bool],
                    on_wait: Callable[[int], None] | None) -> list[WfdPeer]:
        loop = asyncio.get_running_loop()
        selector = WiFiDirectDevice.get_device_selector(WiFiDirectDeviceSelectorType.ASSOCIATION_ENDPOINT)
        watcher = DeviceInformation.create_watcher(selector, [IE_PROPERTY])
        found: dict[str, Any] = {}

        def apply_update(upd) -> None:
            info = found.get(upd.id)
            if info is not None:
                try:
                    info.update(upd)
                except Exception:
                    pass

        # Windows often reports a device first WITHOUT its information elements and adds
        # them in a later Updated event; ignoring updates loses receivers that are there.
        watcher.add_added(lambda _w, info: loop.call_soon_threadsafe(found.__setitem__, info.id, info))
        watcher.add_updated(lambda _w, upd: loop.call_soon_threadsafe(apply_update, upd))
        watcher.add_removed(lambda _w, upd: loop.call_soon_threadsafe(found.pop, upd.id, None))
        watcher.add_enumeration_completed(lambda _w, _a: None)
        watcher.start()
        start = loop.time()
        rechecked: set[str] = set()
        next_note = 10
        try:
            while True:
                await asyncio.sleep(0.5)
                elapsed = loop.time() - start
                peers = _named(found)
                if (peers and elapsed >= settle and done(peers)) or elapsed >= timeout:
                    break
                if elapsed >= settle:
                    # Ask Windows directly for devices whose elements never arrived.
                    for dev_id in [i for i in found if i not in rechecked][:5]:
                        rechecked.add(dev_id)
                        try:
                            fresh = await asyncio.wait_for(
                                DeviceInformation.create_from_id_async(dev_id, [IE_PROPERTY]), 3)
                            found[dev_id] = fresh
                        except Exception:
                            pass
                if on_wait and elapsed >= next_note:
                    on_wait(int(elapsed))
                    next_note += 10
        finally:
            watcher.stop()
        return _named(found)

    def connect(self, peer: WfdPeer, timeout: float = 60.0) -> str:
        """Bring up the link and return the receiver's IP address on it."""
        return self._lt.run(self._connect(peer), timeout=timeout)

    async def _connect(self, peer: WfdPeer) -> str:
        info = await DeviceInformation.create_from_id_async(peer.device_id)
        if await _ensure_paired(info):
            self._paired_here.append(info)
        self._device = await WiFiDirectDevice.from_id_async(info.id)
        for _ in range(100):
            pairs = self._device.get_connection_endpoint_pairs()
            if pairs:
                return pairs[0].remote_host_name.display_name
            await asyncio.sleep(0.2)
        raise WifiDirectError("Wi-Fi Direct link came up but no IP address was assigned.")

    def close(self) -> None:
        try:
            if self._device is not None:
                self._device.close()
        finally:
            _forget(self._lt, self._paired_here)
            self._lt.close()
