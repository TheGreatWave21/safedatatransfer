"""`sdt` command-line interface.

    sdt                           full-screen interactive UI (keyboard driven)
    sdt usb list                  show removable drives
    sdt usb info E:               every detail about a drive (hardware, volume, contents)
    sdt usb copy E:               encrypted copy + verify of everything on E:
    sdt usb wipe E:               erase E:
    sdt usb evacuate E:           encrypted copy + verify, then erase (the main workflow)

    sdt vault info DIR            vault details readable without the password
    sdt vault list DIR            show what is inside an encrypted vault
    sdt vault open DIR            decrypt a vault back into normal files
    sdt vault shred DIR           overwrite + delete such a decrypted folder

    sdt drop receive              wait for files (shows a one-time code)
    sdt drop send FILE...         send files to a nearby PC
    sdt drop peers                list nearby receivers
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from safedatatransfer import __version__
from safedatatransfer.common.drives import DriveError
from safedatatransfer.common.crypto import DecryptionError
from safedatatransfer.local_drop import commands as drop
from safedatatransfer.local_drop.protocol import ProtocolError
from safedatatransfer.local_drop.wifidirect import WifiDirectError
from safedatatransfer.usb_vault import commands as usb
from safedatatransfer.usb_vault.vault import VaultError
from safedatatransfer.usb_vault.wipe import METHODS


def _add_wipe_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--method", choices=METHODS, default="quick",
                   help="quick (default): overwrite and delete the files only. "
                        "fill: also fill all free space with random data, then remove the filler "
                        "(only when you choose it). Neither needs admin rights.")
    p.add_argument("--passes", type=int, default=1, help="overwrite passes per file (default 1)")
    p.add_argument("--allow-fixed", action="store_true",
                   help="allow USB drives that Windows reports as 'fixed' (e.g. USB SSDs)")
    p.add_argument("--allow-vault", action="store_true",
                   help="allow erasing a stick that holds an sdt vault (normally refused: "
                        "it is probably your backup)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sdt", description="Safe data transfer tools.")
    parser.add_argument("--version", action="version", version=f"sdt {__version__}")
    top = parser.add_subparsers(dest="area")

    top.add_parser("ui", help="full-screen interactive UI (same as running sdt with no arguments)")

    # ---- Part 1: usb ----
    p_usb = top.add_parser("usb", help="USB vault: copy, verify and wipe USB sticks")
    usb_sub = p_usb.add_subparsers(dest="cmd", required=True)

    p = usb_sub.add_parser("list", help="list removable drives")
    p.add_argument("--all", action="store_true", help="show every drive, not just removable")

    p = usb_sub.add_parser("info", help="every detail about a drive")
    p.add_argument("drive", help="drive letter, e.g. E:")
    p.add_argument("--scan", action="store_true",
                   help="also count files on non-removable drives (slow on big disks)")

    p = usb_sub.add_parser("copy", help="encrypted copy + verify (no wipe)")
    p.add_argument("drive", help="drive letter, e.g. E:")
    p.add_argument("--dest", type=Path, help="destination folder (default ~/Downloads/usb-vault/...)")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would happen; write and erase nothing")

    p = usb_sub.add_parser("wipe", help="erase a drive (asks for confirmation)")
    p.add_argument("drive", help="drive letter, e.g. E:")
    _add_wipe_options(p)
    p.add_argument("--dry-run", action="store_true",
                   help="show what would happen; write and erase nothing")

    p = usb_sub.add_parser("evacuate", help="encrypted copy + verify, then erase the drive")
    p.add_argument("drive", help="drive letter, e.g. E:")
    p.add_argument("--dest", type=Path, help="destination folder (default ~/Downloads/usb-vault/...)")
    _add_wipe_options(p)
    p.add_argument("--dry-run", action="store_true",
                   help="show what would happen; write and erase nothing")

    p_vault = top.add_parser("vault", help="open encrypted vaults made by `sdt usb`")
    vault_sub = p_vault.add_subparsers(dest="cmd", required=True)
    p = vault_sub.add_parser("info", help="vault details that need no password")
    p.add_argument("vault", type=Path, help="vault folder (the one with vault.json)")
    p = vault_sub.add_parser("list", help="list files in a vault")
    p.add_argument("vault", type=Path, help="vault folder (the one with vault.json)")
    p = vault_sub.add_parser("open", help="decrypt a vault into a folder")
    p.add_argument("vault", type=Path, help="vault folder (the one with vault.json)")
    p.add_argument("--out", type=Path, help="output folder (default: <vault>_opened)")
    p.add_argument("--allow-cloud", action="store_true",
                   help="allow a OneDrive/Dropbox/... folder (plaintext would be uploaded)")
    p = vault_sub.add_parser("shred", help="overwrite + delete a folder made by `vault open`")
    p.add_argument("folder", type=Path, help="folder made by `sdt vault open`")

    # ---- Part 2: drop ----
    p_drop = top.add_parser("drop", help="Local drop: secure AirDrop-style transfer")
    drop_sub = p_drop.add_subparsers(dest="cmd", required=True)
    via_help = ("wifi-direct (default): direct PC-to-PC link, no port on your networks; "
                "lan: normal network, only for networks you trust")
    p = drop_sub.add_parser("send", help="send files or folders to a nearby PC")
    p.add_argument("paths", nargs="+", type=Path, help="files and folders to send")
    p.add_argument("--to", help="receiver name (default: ask if more than one)")
    p.add_argument("--via", choices=drop.VIA, default="wifi-direct", help=via_help)
    p.add_argument("--host", help="skip discovery, connect to HOST[:PORT]")
    p.add_argument("--code", help="the receiver's code (default: ask; typing it here leaves it "
                                  "in your shell history, harmless once used)")
    p = drop_sub.add_parser("receive", help="wait for incoming files")
    p.add_argument("--dest", type=Path, help="default ~/Downloads/sdt-drop")
    p.add_argument("--via", choices=drop.VIA, default="wifi-direct", help=via_help)
    p.add_argument("--allow-cloud", action="store_true",
                   help="allow a OneDrive/Dropbox/... destination (files would be uploaded)")
    p.add_argument("--name", help="name shown to senders nearby (default: random, e.g. sdt-4821; "
                                  "your PC's name is not broadcast)")
    p = drop_sub.add_parser("peers", help="list nearby receivers")
    p.add_argument("--via", choices=drop.VIA, default="wifi-direct", help=via_help)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.area in (None, "ui"):
        try:
            from safedatatransfer import tui
            return tui.run()
        except ImportError as e:
            print(f"The interactive UI needs Textual ({e}). Start sdt via sdt.cmd, which installs "
                  "everything into .venv automatically.", file=sys.stderr)
            return 1
    try:
        if args.area == "usb":
            if args.cmd == "list":
                return usb.cmd_list(args.all)
            if args.cmd == "info":
                return usb.cmd_info(args.drive, args.scan)
            if args.cmd == "copy":
                return usb.cmd_copy(args.drive, args.dest, args.dry_run)
            if args.cmd == "wipe":
                return usb.cmd_wipe(args.drive, args.method, args.passes,
                                    args.allow_fixed, args.dry_run, args.allow_vault)
            if args.cmd == "evacuate":
                return usb.cmd_evacuate(args.drive, args.dest, args.method, args.passes,
                                        args.allow_fixed, args.dry_run, args.allow_vault)
        if args.area == "vault":
            if args.cmd == "info":
                return usb.cmd_vault_info(args.vault)
            if args.cmd == "list":
                return usb.cmd_vault_list(args.vault)
            if args.cmd == "open":
                return usb.cmd_vault_open(args.vault, args.out, args.allow_cloud)
            if args.cmd == "shred":
                return usb.cmd_vault_shred(args.folder)
        if args.area == "drop":
            if args.cmd == "send":
                return drop.cmd_send(args.paths, args.to, args.via, args.host, args.code)
            if args.cmd == "receive":
                return drop.cmd_receive(args.dest, args.via, args.allow_cloud, args.name)
            if args.cmd == "peers":
                return drop.cmd_peers(args.via)
    except (DriveError, usb.SafetyError, ValueError, VaultError, DecryptionError,
            ProtocolError, WifiDirectError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
