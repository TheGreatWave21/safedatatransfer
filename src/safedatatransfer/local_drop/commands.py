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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

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


class Cancelled(Exception):
    """The user stopped the transfer (UI)."""


@dataclass
class Hooks:
    """How a transfer talks to the user. The CLI uses print/input; the UI uses dialogs.

    All of them are called from the thread that runs the transfer."""
    log: Callable[[str], None] = print
    ask_code: Callable[[], str | None] = lambda: input("Code shown on the receiver: ")
    choose: Callable[[list["Peer"]], "Peer | None"] | None = None  # None: CLI prompt
    ask_accept: Callable[[dict], bool] | None = None                # None: CLI prompt
    on_ready: Callable[[str, str, Path], None] | None = None        # receiver: name, code, dest
    progress: Callable[[int, int], None] | None = None
    cancelled: Callable[[], bool] = field(default=lambda: False)

    def check(self) -> None:
        if self.cancelled():
            raise Cancelled()


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

def _matches(name: str, to: str) -> bool:
    return name.lower() == to.lower() or name.lower().startswith(to.lower())


def _discover(via: str, connector: wifidirect.Connector | None, to: str | None = None,
              log: Callable[[str], None] = print,
              cancelled: Callable[[], bool] | None = None) -> list[Peer]:
    if via == "lan":
        return [Peer(p.name, "lan", lan=p) for p in lan.discover()]
    # With --to, keep looking until that receiver shows up (not just any receiver).
    done = (lambda peers: any(_matches(p.name, to) for p in peers)) if to else None
    found = connector.scan(
        done=done, cancelled=cancelled,
        on_wait=lambda s: log(f"  still looking... ({s} s; Wi-Fi Direct can take up to "
                              f"{int(wifidirect.SCAN_TIMEOUT)} s)"))
    return [Peer(p.name, "wifi-direct", wfd=p) for p in found]


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
            [p for p in peers if _matches(p.name, to)]
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


def _connect_tcp(host: str, port: int, attempts: int = 30,
                 cancelled: Callable[[], bool] | None = None) -> socket.socket:
    last: OSError | None = None
    for _ in range(attempts):  # the receiver opens its port only once the link is up
        if cancelled and cancelled():
            raise Cancelled()
        try:
            return socket.create_connection((host, port), timeout=10)
        except OSError as e:
            last = e
            time.sleep(1)
    raise protocol.ProtocolError(f"Could not connect to {host}:{port}: {last}")


# ---------------------------------------------------------------- send

def send(paths: list[Path], to: str | None, via: str, host: str | None, code: str | None,
         hooks: Hooks) -> int:
    """Send files. Returns the number of files sent."""
    log = hooks.log
    files = protocol.collect_files(paths, log)
    if not files:
        raise protocol.ProtocolError("Nothing to send.")
    total = sum(f.size for f in files)
    log(f"Sending {len(files)} files, {human_size(total)}")

    connector = None
    try:
        if host:
            h, _, port = host.partition(":")
            target_host, target_port = h, int(port or protocol.TCP_PORT)
        else:
            connector = _connector(via)
            log("Looking for receivers...")
            peers = _discover(via, connector, to, log, hooks.cancelled)
            hooks.check()
            if not peers:
                raise NoReceivers(
                    "No receivers found. Is `sdt drop receive` running on the other PC"
                    + (" with --via lan?" if via == "lan" else
                       "? Is Wi-Fi turned on on both PCs? Moving them closer and "
                       "trying again often helps."))
            if to or hooks.choose is None:
                peer = _pick(peers, to)
            else:
                peer = peers[0] if len(peers) == 1 else hooks.choose(peers)
                if peer is None:
                    raise Cancelled()
            log(f"-> {peer.label()}")
            if peer.via == "wifi-direct":
                log("Bringing up the direct Wi-Fi link (Windows may show a pairing prompt the first time)...")
                target_host, target_port = connector.connect(peer.wfd), protocol.TCP_PORT
            else:
                target_host, target_port = peer.lan.host, peer.lan.port
            hooks.check()

        sock = _connect_tcp(target_host, target_port, cancelled=hooks.cancelled)
        with sock:
            code = code or hooks.ask_code()
            if not code:
                raise Cancelled()
            ch = protocol.handshake_sender(sock, code)
            log("Secure channel established (code verified).")
            protocol.send_files(ch, files, _this_pc(), log, hooks.progress)
        log("Done.")
        return len(files)
    finally:
        if connector:
            connector.close()


class NoReceivers(protocol.ProtocolError):
    pass


def cmd_send(paths: list[Path], to: str | None, via: str, host: str | None, code: str | None) -> int:
    try:
        send(paths, to, via, host, code, Hooks())
    except NoReceivers as e:
        print(e)
        return 1
    return 0


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


def _accept_one(server: socket.socket, allowed_ip: str | None,
                log: Callable[[str], None] = print,
                cancelled: Callable[[], bool] | None = None) -> socket.socket:
    """Wait for one connection (from allowed_ip only, if given), then close the port."""
    server.settimeout(0.5)
    deadline = time.monotonic() + ACCEPT_TIMEOUT
    try:
        while time.monotonic() < deadline:
            if cancelled and cancelled():
                raise Cancelled()
            try:
                conn, addr = server.accept()
            except (TimeoutError, socket.timeout):
                continue
            if allowed_ip is None or addr[0] == allowed_ip:
                log(f"Connection from {addr[0]}")
                return conn
            log(f"Ignored a connection from {addr[0]} (not the linked PC).")
            conn.close()
        raise protocol.ProtocolError("The sender did not connect in time.")
    finally:
        server.close()  # port closed as soon as we have our one connection


def _wait_for_link(links: "queue.Queue[tuple[str, str]]",
                   cancelled: Callable[[], bool] | None = None) -> tuple[str, str]:
    while True:  # short timeouts keep Ctrl+C (and the UI's Stop) responsive
        if cancelled and cancelled():
            raise Cancelled()
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


def check_receive_dest(dest: Path, allow_cloud: bool) -> None:
    cloud = winfs.cloud_folder(dest)
    if cloud and not allow_cloud:
        raise protocol.ProtocolError(f"{dest} is inside {cloud}: received files would be uploaded "
                                     "to the cloud. Use --dest with another folder (or --allow-cloud).")


def receive(dest: Path | None, via: str, allow_cloud: bool, name: str | None,
            hooks: Hooks) -> list[Path]:
    """Receive one transfer. Returns the files written."""
    log = hooks.log
    dest = dest or DEFAULT_DEST
    check_receive_dest(dest, allow_cloud)
    name = receiver_name(name)
    code = protocol.new_code()

    if via == "lan":
        log("WARNING: --via lan listens on your normal network. Use it only on a network you trust.")
        responder = lan.DiscoveryResponder(name, protocol.TCP_PORT).start()
        try:
            server = socket.create_server(("0.0.0.0", protocol.TCP_PORT))
            log(f"Receiving as '{name}' on the local network. Files go to {dest}")
            if hooks.on_ready:
                hooks.on_ready(name, code, dest)
            log(FIREWALL_NOTE.replace("on the direct link to the other PC", "on this network"))
            conn = _accept_one(server, None, log, hooks.cancelled)
        finally:
            responder.stop()
        return _receive_on(conn, code, dest, hooks)

    links: "queue.Queue[tuple[str, str]]" = queue.Queue()
    advertiser = wifidirect.Advertiser(name, log=log,
                                       on_link=lambda local, remote: links.put((local, remote)))
    advertiser.start()
    try:
        log(f"Visible as '{name}' over Wi-Fi Direct. Files go to {dest}")
        if hooks.on_ready:
            hooks.on_ready(name, code, dest)
        log("Tell the sender this code in person. No port is open yet.")
        local_ip, remote_ip = _wait_for_link(links, hooks.cancelled)
        log(FIREWALL_NOTE)
        server = socket.create_server((local_ip, protocol.TCP_PORT))
        conn = _accept_one(server, remote_ip, log, hooks.cancelled)
        return _receive_on(conn, code, dest, hooks)
    finally:
        advertiser.stop()


def _receive_on(conn: socket.socket, code: str, dest: Path, hooks: Hooks) -> list[Path]:
    with conn:
        conn.settimeout(120)
        ch = protocol.handshake_receiver(conn, code)
        hooks.log("Code verified, secure channel established.")
        received = protocol.receive_files(ch, dest, hooks.ask_accept or _ask_accept, hooks.log,
                                          progress=hooks.progress)
    hooks.log(f"Received {len(received)} files into {dest}")
    return received


def cmd_receive(dest: Path | None, via: str, allow_cloud: bool = False,
                name: str | None = None) -> int:
    def ready(_name: str, code: str, _dest: Path) -> None:
        print(f"\n    Code:  {code}\n")
        print("Press Ctrl+C to stop.")
    receive(dest, via, allow_cloud, name, Hooks(on_ready=ready))
    return 0
