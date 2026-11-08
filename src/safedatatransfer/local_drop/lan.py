"""Same-network discovery (fallback when Wi-Fi Direct is not available).

Discovery is unauthenticated on purpose: it only tells the sender *where* to connect.
Who is on the other end is proven by the one-time code in protocol.py.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass

from safedatatransfer.local_drop.protocol import clean_text

DISCOVERY_PORT = 47801
PROBE = b"SDT-DROP-DISCOVER/1"


@dataclass(frozen=True)
class LanPeer:
    name: str
    host: str
    port: int


class DiscoveryResponder:
    """Answers discovery probes while a receiver is waiting."""

    def __init__(self, name: str, tcp_port: int):
        self._reply = json.dumps({"sdt": 1, "name": name, "port": tcp_port}).encode()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Exclusive on Windows: no other program can bind the same port and read probes.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("", DISCOVERY_PORT))
        self._sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "DiscoveryResponder":
        self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(256)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            if data == PROBE:
                try:
                    self._sock.sendto(self._reply, addr)
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()


def discover(timeout: float = 2.0) -> list[LanPeer]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.3)
    peers: dict[tuple[str, int], LanPeer] = {}
    try:
        deadline = time.monotonic() + timeout
        next_probe = 0.0
        while time.monotonic() < deadline:
            if time.monotonic() >= next_probe:
                for target in ("255.255.255.255", "127.0.0.1"):
                    try:
                        sock.sendto(PROBE, (target, DISCOVERY_PORT))
                    except OSError:
                        pass
                next_probe = time.monotonic() + 0.7
            try:
                data, (host, _) = sock.recvfrom(1024)
                info = json.loads(data)
                if isinstance(info, dict) and info.get("sdt") == 1:
                    port = int(info["port"])
                    if not 1 <= port <= 65535:
                        continue
                    peer = LanPeer(clean_text(str(info["name"]), 64), host, port)
                    peers[(peer.name, peer.port)] = peer
            except (TimeoutError, socket.timeout):
                continue
            except (ValueError, KeyError, OSError):
                continue
    finally:
        sock.close()
    return list(peers.values())
