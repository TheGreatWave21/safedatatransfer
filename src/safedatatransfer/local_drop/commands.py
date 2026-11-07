"""CLI entry points for local_drop.

Network exposure, by design:
  - Default (Wi-Fi Direct): the receiver opens NO port until a direct PC-to-PC link
    exists, then listens only on that link's own IP address, accepts only the PC at the
    other end of the link, takes exactly one connection, and closes.
  - `--via lan` (opt-in): listens on the normal network. Only use it on networks you trust.
  - The sender never listens; it only makes outgoing connections.
"""

from __future__ import annotations

import queue
import secrets
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from safedatatransfer.common import winfs
from safedatatransfer.common.drives import human_size
from safedatatransfer.local_drop import lan, protocol, wifidirect

DEFAULT_DEST = Path.home() / "Downloads" / "sdt-drop"
VIA = ("wifi-direct", "lan")
ACCEPT_TIMEOUT = 120  # seconds the port stays open after the link is up

FIREWALL_NOTE = (
    "Windows may ask once whether Python may accept connections. Allowing it is safe here:\n"
    "the port only exists while you receive, and only on the direct link to the other PC."
)


@dataclass
class Peer:
    name: str
    via: str  # "wifi-direct" or "lan"
    lan: lan.LanPeer | None = None
    wfd: wifidirect.WfdPeer | None = None

    def label(self) -> str:
        where = "Wi-Fi Direct" if self.via == "wifi-direct" else f"network {self.lan.host}"
        return f"{self.name}  ({where})"


def _this_pc() -> str:
    return socket.gethostname()


# ---------------------------------------------------------------- discovery

def _discover(via: str, connector: wifidirect.Connector | None) -> list[Peer]:
    if via == "lan":
        return [Peer(p.name, "lan", lan=p) for p in lan.discover()]
    return [Peer(p.name, "wifi-direct", wfd=p) for p in connector.scan()]


def _connector(via: str) -> wifidirect.Connector | None:
    if via == "lan":
        return None
    try:
        return wifidirect.Connector()
    except wifidirect.WifiDirectError as e:
        raise wifidirect.WifiDirectError(
            f"{e}\nWi-Fi Direct is needed for the default mode. "
            "On a network you trust you can use --via lan instead.") from e


def cmd_peers(via: str) -> int:
    connector = _connector(via)
    try:
        print("Looking for receivers (they must be running `sdt drop receive`)...")
        peers = _discover(via, connector)
    finally:
        if connector:
            connector.close()
    if not peers:
        print("None found.")
        return 1
    for p in peers:
        print(f"  {p.label()}")
    return 0


def _pick(peers: list[Peer], to: str | None) -> Peer:
    if to:
        # Exact name first. A partial name must match exactly one receiver, so a nearby
        # device with a similar name ("sdt-48" vs "sdt-4821") is never picked by accident.
        matches = [p for p in peers if p.name.lower() == to.lower()] or \
            [p for p in peers if p.name.lower().startswith(to.lower())]
        if not matches:
            raise protocol.ProtocolError(f"No receiver named {to!r} found.")
        if len(matches) > 1:
            names = ", ".join(p.label() for p in matches)
            raise protocol.ProtocolError(f"{to!r} matches several receivers ({names}); "
                                         "use the full name.")
        return matches[0]
    if len(peers) == 1:
        return peers[0]
    for i, p in enumerate(peers, 1):
        print(f"  [{i}] {p.label()}")
    while True:
        choice = input("Send to which number? ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(peers):
            return peers[int(choice) - 1]


def _connect_tcp(host: str, port: int, attempts: int = 30) -> socket.socket:
    last: OSError | None = None
    for _ in range(attempts):  # the receiver opens its port only once the link is up
        try:
            return socket.create_connection((host, port), timeout=10)
        except OSError as e:
            last = e
            time.sleep(1)
    raise protocol.ProtocolError(f"Could not connect to {host}:{port}: {last}")


# ---------------------------------------------------------------- send

def cmd_send(paths: list[Path], to: str | None, via: str, host: str | None, code: str | None) -> int:
    files = protocol.collect_files(paths)
    total = sum(f.size for f in files)
    print(f"Sending {len(files)} files, {human_size(total)}")

    connector = None
    try:
        if host:
            h, _, port = host.partition(":")
            target_host, target_port = h, int(port or protocol.TCP_PORT)
        else:
            connector = _connector(via)
            print("Looking for receivers...")
            peers = _discover(via, connector)
            if not peers:
                print("No receivers found. Is `sdt drop receive` running on the other PC"
                      + (" with --via lan?" if via == "lan" else "?"))
                return 1
            peer = _pick(peers, to)
            print(f"-> {peer.label()}")
            if peer.via == "wifi-direct":
                print("Bringing up the direct Wi-Fi link (Windows may show a pairing prompt the first time)...")
                target_host, target_port = connector.connect(peer.wfd), protocol.TCP_PORT
            else:
                target_host, target_port = peer.lan.host, peer.lan.port

        sock = _connect_tcp(target_host, target_port)
        with sock:
            code = code or input("Code shown on the receiver: ")
            ch = protocol.handshake_sender(sock, code)
            print("Secure channel established (code verified).")
            protocol.send_files(ch, files, _this_pc())
        print("Done.")
        return 0
    finally:
        if connector:
            connector.close()


# ---------------------------------------------------------------- receive

def _ask_accept(offer: dict) -> bool:
    files = offer.get("files", [])
    total = sum(int(f.get("size", 0)) for f in files)
    print(f"\n{offer.get('sender', '?')!s:.64} wants to send {len(files)} files ({human_size(total)}):")
    for f in files[:20]:
        print(f"  {human_size(int(f.get('size', 0))):>10}  {str(f.get('path'))[:120]}")
    if len(files) > 20:
        print(f"  ... and {len(files) - 20} more")
    return input("Accept? [y/N] ").strip().lower() in ("y", "yes")


def _accept_one(server: socket.socket, allowed_ip: str | None) -> socket.socket:
    """Wait for one connection (from allowed_ip only, if given), then close the port."""
    server.settimeout(0.5)
    deadline = time.monotonic() + ACCEPT_TIMEOUT
    try:
        while time.monotonic() < deadline:
            try:
                conn, addr = server.accept()
            except (TimeoutError, socket.timeout):
                continue
            if allowed_ip is None or addr[0] == allowed_ip:
                print(f"Connection from {addr[0]}")
                return conn
            print(f"Ignored a connection from {addr[0]} (not the linked PC).")
            conn.close()
        raise protocol.ProtocolError("The sender did not connect in time.")
    finally:
        server.close()  # port closed as soon as we have our one connection


def _wait_for_link(links: "queue.Queue[tuple[str, str]]") -> tuple[str, str]:
    while True:  # short timeouts keep Ctrl+C responsive
        try:
            return links.get(timeout=0.5)
        except queue.Empty:
            continue


def receiver_name(name: str | None) -> str:
    """What the receiver shows to everyone nearby. Default: a random 'sdt-1234', so the
    PC's own name (often the owner's name) is not broadcast."""
    if name:
        return protocol.clean_text(name, 32)
    return f"sdt-{secrets.randbelow(9000) + 1000}"


def cmd_receive(dest: Path | None, via: str, allow_cloud: bool = False,
                name: str | None = None) -> int:
    dest = dest or DEFAULT_DEST
    cloud = winfs.cloud_folder(dest)
    if cloud and not allow_cloud:
        raise protocol.ProtocolError(f"{dest} is inside {cloud}: received files would be uploaded "
                                     "to the cloud. Use --dest with another folder (or --allow-cloud).")
    name = receiver_name(name)
    code = protocol.new_code()

    if via == "lan":
        print("WARNING: --via lan listens on your normal network. Use it only on a network you trust.")
        responder = lan.DiscoveryResponder(name, protocol.TCP_PORT).start()
        try:
            server = socket.create_server(("0.0.0.0", protocol.TCP_PORT))
            print(f"Receiving as '{name}' on the local network. Files go to {dest}")
            print(f"\n    Code:  {code}\n")
            print(FIREWALL_NOTE.replace("on the direct link to the other PC", "on this network"))
            conn = _accept_one(server, None)
        finally:
            responder.stop()
        return _receive_on(conn, code, dest)

    links: "queue.Queue[tuple[str, str]]" = queue.Queue()
    advertiser = wifidirect.Advertiser(name, on_link=lambda local, remote: links.put((local, remote)))
    advertiser.start()
    try:
        print(f"Visible as '{name}' over Wi-Fi Direct. Files go to {dest}")
        print(f"\n    Code:  {code}\n")
        print("Tell the sender this code in person. No port is open yet. Press Ctrl+C to stop.")
        local_ip, remote_ip = _wait_for_link(links)
        print(FIREWALL_NOTE)
        server = socket.create_server((local_ip, protocol.TCP_PORT))
        conn = _accept_one(server, remote_ip)
        return _receive_on(conn, code, dest)
    finally:
        advertiser.stop()


def _receive_on(conn: socket.socket, code: str, dest: Path) -> int:
    with conn:
        conn.settimeout(120)
        ch = protocol.handshake_receiver(conn, code)
        print("Code verified, secure channel established.")
        received = protocol.receive_files(ch, dest, _ask_accept)
    print(f"Received {len(received)} files into {dest}")
    return 0
