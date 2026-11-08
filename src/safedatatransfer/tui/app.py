"""The sdt full-screen app: drives, vaults and live activity, all from the keyboard."""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
import time
from collections import Counter
from concurrent.futures import Future, TimeoutError as FutureTimeout
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

from rich.markup import escape
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable, DirectoryTree, Footer, Header, ProgressBar, RichLog, Static, TabbedContent,
    TabPane, Tree,
)
from textual.worker import get_current_worker

from safedatatransfer import __version__
from safedatatransfer.common.drives import (
    Drive, DriveError, drive_details, human_size, list_drives,
)
from safedatatransfer.common.hashing import CHUNK_SIZE
from safedatatransfer.local_drop import commands as drop
from safedatatransfer.tui import visuals
from safedatatransfer.tui.modals import (
    METHOD_INFO, AcceptModal, CodeModal, ConfirmWipeModal, HelpModal, PasswordModal, PathModal,
    PeerModal, PlanModal,
)
from safedatatransfer.usb_vault import vault
from safedatatransfer.usb_vault.commands import (
    DEFAULT_DEST_ROOT, SafetyError, check_wipe_allowed, default_destination, do_wipe,
    check_destination, check_no_vaults, drive_identity, still_same_drive,
)
from safedatatransfer.usb_vault.transfer import SKIP_DIRS, is_link

FILE_ATTRS = [
    (stat.FILE_ATTRIBUTE_READONLY, "read-only"), (stat.FILE_ATTRIBUTE_HIDDEN, "hidden"),
    (stat.FILE_ATTRIBUTE_SYSTEM, "system"), (stat.FILE_ATTRIBUTE_ARCHIVE, "archive"),
    (stat.FILE_ATTRIBUTE_COMPRESSED, "compressed"), (stat.FILE_ATTRIBUTE_ENCRYPTED, "EFS-encrypted"),
    (stat.FILE_ATTRIBUTE_SPARSE_FILE, "sparse"), (stat.FILE_ATTRIBUTE_REPARSE_POINT, "link/reparse"),
] if hasattr(stat, "FILE_ATTRIBUTE_READONLY") else []


def _ts(t: float) -> str:
    """Format a timestamp; '-' for missing/invalid ones (drive roots report 1601-01-01)."""
    if not t or t <= 0:
        return "-"
    try:
        return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "-"


def _err(e: BaseException) -> str:
    """Error text for the user; some errors (e.g. timeouts) have an empty message."""
    return str(e) or type(e).__name__


def _path_size(p: Path, limit: int = 20000) -> int:
    """Size of a file, or of a folder's files (links not followed; stops counting after
    `limit` files so a huge folder doesn't freeze the UI)."""
    try:
        if p.is_file():
            return p.stat().st_size
        total = 0
        for i, (root, dirs, files) in enumerate(os.walk(p, followlinks=False)):
            dirs[:] = [d for d in dirs if not is_link(Path(root, d))]  # incl. junctions
            for f in files:
                try:
                    total += os.stat(os.path.join(root, f), follow_symlinks=False).st_size
                except OSError:
                    pass
            if i > limit:
                break
        return total
    except OSError:
        return 0


def _kv_table(rows: Iterable[tuple[str, str | Text]], key_style: str = "bold cyan") -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style=key_style, no_wrap=True, justify="right")
    t.add_column(overflow="fold")
    for k, v in rows:
        t.add_row(k, v if isinstance(v, Text) else Text(str(v)))
    return t


class DriveTree(DirectoryTree):
    """File browser for the selected drive, hiding Windows' own system folders."""

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        return [p for p in paths if p.name.lower() not in SKIP_DIRS]


class SdtApp(App):
    TITLE = "SDT"
    SUB_TITLE = "safe data transfer"

    CSS = """
    Screen { background: $background; }
    #top { height: 8; padding: 0 1; }
    #logo { width: 27; padding: 1 0 0 0; }
    #tagline { width: 1fr; padding: 2 2 0 2; }
    #status { width: 44; border: round $primary; padding: 0 1; }
    #top.hidden { display: none; }
    TabbedContent { height: 1fr; }
    TabPane { padding: 0; }
    .panel { border: round $primary 60%; padding: 0 1; background: $surface; }
    .panel:focus-within { border: round $accent; }
    #drives-left { width: 52%; }
    #drive-table { height: auto; max-height: 9; border: round $primary 60%; background: $surface; }
    #drive-table:focus { border: round $accent; }
    #drive-meter { height: 3; border: round $primary 60%; padding: 0 1; background: $surface; }
    #drive-info-scroll { height: 1fr; }
    #tree { height: 2fr; border: round $primary 60%; background: $surface; }
    #tree:focus { border: round $accent; }
    #file-info-scroll { height: 1fr; min-height: 8; }
    #empty { content-align: center middle; height: 1fr; color: $text-muted; }
    #vaults-left { width: 45%; }
    #vault-table { height: 1fr; border: round $primary 60%; background: $surface; }
    #vault-table:focus, #vault-files:focus { border: round $accent; }
    #vault-info-scroll { height: auto; max-height: 12; }
    #vault-summary { height: auto; }
    #vault-files { height: 1fr; border: round $primary 60%; background: $surface; }
    #activity-head { height: 3; padding: 0 1; border: round $primary 60%; }
    #progress-label { width: 1fr; }
    #progress { width: 60; }
    #log { height: 1fr; border: round $primary 60%; background: $surface; }
    #drop-send { width: 55%; }
    #send-list { height: 1fr; border: round $primary 60%; background: $surface; }
    #send-list:focus { border: round $accent; }
    #send-hint, #recv-hint { height: auto; padding: 0 1; color: $text-muted; }
    #recv-info { height: 1fr; }
    #drop-foot { height: 3; padding: 0 1; border: round $primary 60%; }
    #drop-status { width: 1fr; }
    #drop-progress { width: 50; }

    /* dialogs */
    ModalScreen { align: center middle; background: $background 70%; }
    #dialog { width: 84; max-width: 95%; height: auto; max-height: 90%; padding: 1 2;
              border: thick $accent; background: $surface; }
    #dialog.danger { border: thick $error; }
    #dialog.wide { width: 100; height: 90%; }
    #dialog > * { margin-bottom: 1; }
    .dialog-title { text-style: bold; color: $accent; }
    #dialog.danger .dialog-title { color: $error; }
    .hint { color: $text-muted; height: auto; }
    .error { color: $error; height: auto; }
    .row { height: 3; }
    .row Label { padding: 1 0; }
    #passes { width: 8; }
    .buttons { height: 3; align-horizontal: right; margin-bottom: 0; }
    .buttons Button { margin-left: 2; }
    """

    BINDINGS = [
        Binding("1", "tab('drives')", "Drives"),
        Binding("2", "tab('vaults')", "Vaults"),
        Binding("3", "tab('activity')", "Activity"),
        Binding("4", "tab('drop')", "Drop"),
        Binding("c", "copy", "Copy"),
        Binding("e", "evacuate", "Evacuate"),
        Binding("w", "wipe", "Wipe"),
        Binding("u", "unlock", "Unlock"),
        Binding("o", "open_vault", "Open vault"),
        Binding("d", "toggle_dry_run", "Dry-run"),
        Binding("question_mark", "help", "Help", key_display="?"),
        Binding("q", "quit", "Quit"),
        Binding("h", "hash_file", "Hash file", show=False),
        Binding("a", "toggle_all", "All drives", show=False),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("l", "lock", "Lock", show=False),
        Binding("p", "add_vault", "Add vault", show=False),
        Binding("b", "toggle_banner", "Banner", show=False),
        Binding("f", "drop_add", "Add file", show=False),
        Binding("x", "drop_clear", "Clear list", show=False),
        Binding("s", "drop_send", "Send", show=False),
        Binding("g", "drop_receive", "Receive", show=False),
        Binding("k", "drop_stop", "Stop", show=False),
    ]

    dry_run: reactive[bool] = reactive(False)
    busy: reactive[str] = reactive("")

    def __init__(self, vault_root: Path = DEFAULT_DEST_ROOT,
                 drive_source: Callable[[], list[Drive]] = list_drives):
        super().__init__()
        self.vault_root = vault_root
        self.drive_source = drive_source
        self.drives: list[Drive] = []
        self.show_all = False
        self.selected: str | None = None
        self.drive_stats: dict[str, dict] = {}
        self.drive_detail_rows: dict[str, list[tuple[str, str]]] = {}
        self.extra_vaults: list[Path] = []
        self.vaults: list[Path] = []
        self.selected_vault: Path | None = None
        self.unlocked: dict[Path, dict] = {}
        self.hashes: dict[tuple[str, int, float], str] = {}
        self.current_file: Path | None = None
        self.phase = 0.0
        self._last_drive_sig: tuple = ()
        self._progress_t = 0.0
        self._last_input = time.monotonic()
        self.send_paths: list[Path] = []
        self.drop_running = ""

    # ------------------------------------------------------------ privacy

    AUTO_LOCK_SECONDS = 600  # unlocked vault listings are forgotten after 10 idle minutes

    def on_key(self, _event) -> None:
        self._last_input = time.monotonic()

    def on_click(self, _event) -> None:
        self._last_input = time.monotonic()

    def _auto_lock(self) -> None:
        # A local drop can wait for a sender for a long time; locking only forgets the
        # file list, so it is safe (and wanted) while a drop is running.
        if self.unlocked and (not self.busy or self.drop_running) and \
                time.monotonic() - self._last_input > self.AUTO_LOCK_SECONDS:
            self.action_lock()
            self.log_line("vaults locked automatically after 10 minutes without input")

    def _fatal_error(self) -> None:
        """Crash report WITHOUT local variables: Textual's default prints them, which could
        put a vault password or decrypted file names into the terminal scrollback."""
        from rich.segment import Segments
        from rich.traceback import Traceback

        self.bell()
        tb = Traceback(show_locals=False, width=None)
        self._exit_renderables.append(Segments(self.console.render(tb, self.console.options)))
        self._close_messages_no_wait()

    # ------------------------------------------------------------ layout

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="top"):
            yield Static(visuals.logo(), id="logo")
            yield Static(visuals.tagline(0), id="tagline")
            yield Static(id="status")
        with TabbedContent(initial="drives"):
            with TabPane("① Drives", id="drives"):
                with Horizontal():
                    with Vertical(id="drives-left"):
                        yield DataTable(id="drive-table", cursor_type="row", zebra_stripes=True)
                        yield Static(id="drive-meter")
                        with VerticalScroll(id="drive-info-scroll", classes="panel"):
                            yield Static(id="drive-info")
                    with Vertical(id="drives-right"):
                        yield Static("", id="empty")
                        yield DriveTree(Path.home(), id="tree")
                        with VerticalScroll(id="file-info-scroll", classes="panel"):
                            yield Static(id="file-info")
            with TabPane("② Vaults", id="vaults"):
                with Horizontal():
                    with Vertical(id="vaults-left"):
                        yield DataTable(id="vault-table", cursor_type="row", zebra_stripes=True)
                        with VerticalScroll(id="vault-info-scroll", classes="panel"):
                            yield Static(id="vault-info")
                    with Vertical(id="vaults-right"):
                        yield Static(id="vault-summary", classes="panel")
                        yield DataTable(id="vault-files", cursor_type="row", zebra_stripes=True)
            with TabPane("③ Activity", id="activity"):
                with Horizontal(id="activity-head"):
                    yield Static("idle", id="progress-label")
                    yield ProgressBar(id="progress", show_eta=True)
                yield RichLog(id="log", markup=True, wrap=True, max_lines=5000)
            with TabPane("④ Drop", id="drop"):
                with Horizontal():
                    with Vertical(id="drop-send"):
                        yield DataTable(id="send-list", cursor_type="row", zebra_stripes=True)
                        yield Static(id="send-hint")
                    with Vertical(id="drop-recv", classes="panel"):
                        yield Static(id="recv-info")
                        yield Static(id="recv-hint")
                with Horizontal(id="drop-foot"):
                    yield Static("idle", id="drop-status")
                    yield ProgressBar(id="drop-progress", show_eta=True)
        yield Footer()

    def on_mount(self) -> None:
        self.theme = "tokyo-night"
        self.query_one("#drive-table").border_title = "USB DRIVES"
        self.query_one("#drive-meter").border_title = "USAGE"
        self.query_one("#drive-info-scroll").border_title = "DRIVE DETAILS"
        self.query_one("#tree").border_title = "FILES"
        self.query_one("#file-info-scroll").border_title = "FILE DETAILS"
        self.query_one("#vault-table").border_title = f"VAULTS  {self.vault_root}"
        self.query_one("#vault-info-scroll").border_title = "VAULT (no password needed)"
        self.query_one("#vault-summary").border_title = "CONTENTS"
        self.query_one("#vault-files").border_title = "FILES IN VAULT"
        self.query_one("#log").border_title = "LOG"
        self.query_one("#send-list").border_title = "SEND  (f add · x clear · s send)"
        self.query_one("#drop-recv").border_title = "RECEIVE  (g start · k stop)"
        sl = self.query_one("#send-list", DataTable)
        sl.add_columns("File or folder", "Size")
        self._render_send_list()
        self._render_receive_idle()
        dt = self.query_one("#drive-table", DataTable)
        dt.add_columns(" ", "Drive", "Label", "Size", "FS", "Used")
        vt = self.query_one("#vault-table", DataTable)
        vt.add_columns("Vault", "Created", "Files", "On disk")
        ft = self.query_one("#vault-files", DataTable)
        ft.add_columns("Path", "Size", "Modified", "SHA-256")
        self.query_one("#tree").display = False
        self.log_line(f"[b]sdt {__version__}[/b] started. Press [b]?[/b] for keys.")
        self.set_interval(0.12, self._tick_banner)
        self.set_interval(2.0, self.poll_drives)
        self.set_interval(15.0, self._auto_lock)
        self.poll_drives()
        self.load_vaults()
        self._update_status()
        self.query_one("#drive-table").focus()

    # ------------------------------------------------------------ cosmetics

    def _tick_banner(self) -> None:
        try:
            if not self.query_one("#top").display:
                return
        except NoMatches:  # app is shutting down
            return
        self.phase += 0.06
        self.query_one("#logo", Static).update(visuals.logo(self.phase))
        self.query_one("#tagline", Static).update(visuals.tagline(self.phase))

    def _update_status(self) -> None:
        mode = Text(" DRY-RUN ", style="bold black on yellow") if self.dry_run \
            else Text(" LIVE ", style="bold white on red")
        removable = sum(d.type == "removable" for d in self.drives)
        state = Text(f"● {self.busy}", style="bold yellow") if self.busy \
            else Text("● idle", style="green")
        rows = [
            ("MODE", mode),
            ("DRIVES", Text(f"{removable} removable" + (" · showing all" if self.show_all else ""))),
            ("VAULTS", Text(f"{len(self.vaults)} found")),
            ("STATUS", state),
            ("CRYPTO", Text("AES-256-GCM · scrypt", style="dim")),
        ]
        self.query_one("#status", Static).update(_kv_table(rows, "bold magenta"))
        self.query_one("#status").border_title = "SYSTEM"

    def watch_dry_run(self) -> None:
        if self.is_mounted:
            self._update_status()

    def watch_busy(self) -> None:
        if self.is_mounted:
            self._update_status()

    def log_line(self, msg: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.query_one("#log", RichLog).write(f"[dim]{stamp}[/dim] {msg}")

    def _set_progress(self, done: int, total: int) -> None:
        bar = self.query_one("#progress", ProgressBar)
        bar.update(total=max(total, 1), progress=done)

    # ------------------------------------------------------------ drives

    @work(thread=True, exclusive=True, group="poll", exit_on_error=False)
    def poll_drives(self) -> None:
        try:
            drives = self.drive_source()
        except (DriveError, OSError) as e:
            self.call_from_thread(self.log_line, f"[red]drive scan failed: {escape(str(e))}[/red]")
            return
        sig = tuple((d.letter, d.serial, d.free_bytes, d.label) for d in drives)
        if sig != self._last_drive_sig:
            self.call_from_thread(self._apply_drives, drives, sig)

    def _visible(self, drives: list[Drive]) -> list[Drive]:
        return drives if self.show_all else [d for d in drives if d.type == "removable"]

    def _apply_drives(self, drives: list[Drive], sig: tuple) -> None:
        old = {d.letter: d.serial for d in self._visible(self.drives)}
        first_scan = not self._last_drive_sig
        self._last_drive_sig = sig
        self.drives = drives
        visible = self._visible(drives)
        if not first_scan:
            for d in visible:
                if old.get(d.letter) != d.serial:
                    self.notify(f"{d.letter} {d.label or ''} — {human_size(d.total_bytes)}",
                                title="USB drive connected")
                    self.log_line(f"[green]drive connected[/green] {d.letter} {escape(d.label)}")
            for letter in set(old) - {d.letter for d in visible}:
                self.notify(f"{letter} was removed", title="USB drive removed", severity="warning")
                self.log_line(f"[yellow]drive removed[/yellow] {letter}")
        dt = self.query_one("#drive-table", DataTable)
        dt.clear()
        for d in visible:
            used = (d.total_bytes - d.free_bytes) / d.total_bytes if d.total_bytes else 0
            icon = Text("⛔", style="red") if d.is_system else \
                Text("🔌" if d.type == "removable" else "💽")
            dt.add_row(icon, Text(d.letter, style="bold"), d.label or "—", human_size(d.total_bytes),
                       d.filesystem, visuals.mini_bar(used), key=d.letter)
        letters = [d.letter for d in visible]
        if self.selected in letters:
            dt.move_cursor(row=letters.index(self.selected))
            self._show_drive(self.selected, rescan=False)
        elif letters:
            dt.move_cursor(row=0)
            self._show_drive(letters[0])
        else:
            self.selected = None
            self._show_no_drive()
        self._update_status()

    def _show_no_drive(self) -> None:
        self.query_one("#tree").display = False
        empty = self.query_one("#empty", Static)
        empty.display = True
        empty.update(Text.assemble(
            ("\n\n  🔌  No USB drive detected\n\n", "bold"),
            ("  Plug one in — it is detected automatically.\n", ""),
            ("  Press ", "dim"), ("a", "bold"), (" to show all drives.", "dim")))
        self.query_one("#drive-meter", Static).update("")
        self.query_one("#drive-info", Static).update(Text("No drive selected.", style="dim"))
        self.query_one("#file-info", Static).update("")

    @on(DataTable.RowHighlighted, "#drive-table")
    def _drive_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and event.row_key.value != self.selected:
            self._show_drive(event.row_key.value)

    def _drive(self, letter: str | None) -> Drive | None:
        return next((d for d in self.drives if d.letter == letter), None)

    def _show_drive(self, letter: str, rescan: bool = True) -> None:
        drive = self._drive(letter)
        if drive is None:
            return
        changed = letter != self.selected
        self.selected = letter
        used = (drive.total_bytes - drive.free_bytes) / drive.total_bytes if drive.total_bytes else 0
        meter = visuals.usage_bar(used, 30)
        meter.append(f"   {human_size(drive.total_bytes - drive.free_bytes)} used · "
                     f"{human_size(drive.free_bytes)} free", style="dim")
        self.query_one("#drive-meter", Static).update(meter)
        self.query_one("#empty").display = False
        tree = self.query_one("#tree", DriveTree)
        tree.display = True
        if changed or rescan:
            tree.path = Path(drive.root)
            self.query_one("#file-info", Static).update(
                Text("Move through the tree to see every detail of a file.", style="dim"))
        self._render_drive_info(letter)
        if changed or rescan:
            self.scan_drive(drive)

    def _render_drive_info(self, letter: str) -> None:
        drive = self._drive(letter)
        if drive is None:
            return
        rows: list[tuple[str, str | Text]] = list(self.drive_detail_rows.get(letter) or [
            ("Drive", drive.root), ("Label", drive.label or "(none)"), ("…", "reading hardware info")])
        stats = self.drive_stats.get(letter)
        if stats is None:
            rows.append(("Contents", Text("scanning…", style="yellow")))
        else:
            rows += [
                ("Files", f"{stats['files']:,}"),
                ("Folders", f"{stats['dirs']:,}"),
                ("Data", human_size(stats["bytes"]) + (" (scan incomplete)" if stats.get("partial") else "")),
                ("Hidden files", f"{stats['hidden']:,}"),
                ("Largest file", stats["largest"]),
                ("Top types", stats["types"]),
                ("Newest change", stats["newest"]),
            ]
        try:
            check_wipe_allowed(drive, allow_fixed=False)
            rows.append(("Wipe allowed", Text("yes", style="bold green")))
        except SafetyError as e:
            rows.append(("Wipe allowed", Text(f"no — {e}", style="bold red")))
        self.query_one("#drive-info", Static).update(_kv_table(rows))

    @work(thread=True, exclusive=True, group="scan", exit_on_error=False)
    def scan_drive(self, drive: Drive) -> None:
        try:
            self._scan_drive(drive)
        except Exception as e:
            self.call_from_thread(self.log_line,
                                  f"[red]scan of {drive.letter} stopped: {escape(str(e))}[/red]")

    def _scan_drive(self, drive: Drive) -> None:
        worker = get_current_worker()
        details = drive_details(drive)
        self.drive_detail_rows[drive.letter] = details
        self.call_from_thread(self._render_drive_info, drive.letter)
        files = dirs = total = hidden = 0
        largest: tuple[int, str] = (0, "-")
        newest = 0.0
        types: Counter[str] = Counter()
        partial = False
        last_push = time.monotonic()
        for dirpath, dirnames, filenames in os.walk(drive.root):
            if worker.is_cancelled:
                return
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS
                           and not is_link(os.path.join(dirpath, d))]  # never follow junctions
            dirs += len(dirnames)
            for name in filenames:
                try:
                    st = os.stat(os.path.join(dirpath, name))
                except OSError:
                    partial = True
                    continue
                files += 1
                total += st.st_size
                newest = max(newest, st.st_mtime)
                if getattr(st, "st_file_attributes", 0) & 2:
                    hidden += 1
                if st.st_size > largest[0]:
                    largest = (st.st_size, os.path.relpath(os.path.join(dirpath, name), drive.root))
                types[os.path.splitext(name)[1].lower() or "(none)"] += 1
            if time.monotonic() - last_push > 0.5:
                last_push = time.monotonic()
                self.drive_stats[drive.letter] = self._stats(files, dirs, total, hidden, largest,
                                                             types, newest, True)
                self.call_from_thread(self._render_drive_info, drive.letter)
        self.drive_stats[drive.letter] = self._stats(files, dirs, total, hidden, largest, types,
                                                     newest, partial)
        self.call_from_thread(self._render_drive_info, drive.letter)

    @staticmethod
    def _stats(files, dirs, total, hidden, largest, types, newest, partial) -> dict:
        return {
            "files": files, "dirs": dirs, "bytes": total, "hidden": hidden, "partial": partial,
            "largest": f"{largest[1]} ({human_size(largest[0])})" if largest[0] else "-",
            "types": ", ".join(f"{ext} ×{n}" for ext, n in types.most_common(6)) or "-",
            "newest": _ts(newest) if newest else "-",
        }

    # ------------------------------------------------------------ files

    @on(Tree.NodeHighlighted, "#tree")
    def _file_highlighted(self, event: Tree.NodeHighlighted) -> None:
        data = event.node.data
        if data is not None and hasattr(data, "path"):
            self.current_file = Path(data.path)
            try:
                self._render_file_info(self.current_file)
            except Exception as e:  # never let one odd file crash the app
                self.query_one("#file-info", Static).update(
                    Text(f"Could not read details: {e}", style="red"))

    def _render_file_info(self, path: Path) -> None:
        try:
            st = path.stat()
        except OSError as e:
            self.query_one("#file-info", Static).update(Text(f"Cannot read: {e}", style="red"))
            return
        is_dir = stat.S_ISDIR(st.st_mode)
        attrs = getattr(st, "st_file_attributes", 0)
        created = getattr(st, "st_birthtime", st.st_ctime)
        rows: list[tuple[str, str | Text]] = [
            ("Name", path.name or str(path)),
            ("Path", str(path)),
            ("Type", "folder" if is_dir else (path.suffix.lower() or "file")),
        ]
        if not is_dir:
            rows.append(("Size", f"{human_size(st.st_size)}  ({st.st_size:,} bytes)"))
        rows += [
            ("Created", _ts(created)),
            ("Modified", _ts(st.st_mtime)),
            ("Accessed", _ts(st.st_atime)),
            ("Attributes", ", ".join(n for bit, n in FILE_ATTRS if attrs & bit) or "-"),
        ]
        if not is_dir:
            digest = self.hashes.get((str(path), st.st_size, st.st_mtime))
            rows.append(("SHA-256", Text(digest, style="green") if digest
                         else Text("press h to compute", style="dim")))
        else:
            try:
                rows.append(("Entries", f"{sum(1 for _ in os.scandir(path)):,}"))
            except OSError:
                pass
        self.query_one("#file-info", Static).update(_kv_table(rows))

    def action_hash_file(self) -> None:
        if self.current_file is None or not self.current_file.is_file():
            self.notify("Select a file in the FILES tree first.", severity="warning")
            return
        self.hash_file(self.current_file)

    @work(thread=True, group="hash", exit_on_error=False)
    def hash_file(self, path: Path) -> None:
        try:
            self._hash_file(path)
        except OSError as e:
            self.call_from_thread(self.log_line, f"[red]cannot hash {escape(str(path))}: {escape(str(e))}[/red]")
            self.call_from_thread(self.notify, str(e), title="Hash failed", severity="error")

    def _hash_file(self, path: Path) -> None:
        st = path.stat()
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        self.hashes[(str(path), st.st_size, st.st_mtime)] = h.hexdigest()
        self.call_from_thread(self.log_line, f"sha256 {h.hexdigest()}  {escape(str(path))}")
        if self.current_file == path:
            self.call_from_thread(self._render_file_info, path)

    # ------------------------------------------------------------ vaults

    def load_vaults(self) -> None:
        found = vault.find_vaults(self.vault_root)
        self.vaults = found + [v for v in self.extra_vaults if v not in found]
        vt = self.query_one("#vault-table", DataTable)
        vt.clear()
        for v in self.vaults:
            try:
                info = dict(vault.vault_info(v))
            except (OSError, ValueError, KeyError):
                continue
            vt.add_row(Text(("🔓 " if v in self.unlocked else "🔒 ") + v.name, style="bold"),
                       info["Created"], info["Encrypted files"],
                       human_size(int(info["Size on disk"].split()[0].replace(",", ""))),
                       key=str(v))
        if not self.vaults:
            self.query_one("#vault-info", Static).update(Text(
                f"No vaults yet in {self.vault_root}.\nMake one with c (copy) or e (evacuate), "
                "or press p to add one from elsewhere.", style="dim"))
            self._render_vault_contents(None)
        self._update_status()

    @on(DataTable.RowHighlighted, "#vault-table")
    def _vault_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if not event.row_key:
            return
        self.selected_vault = Path(event.row_key.value)
        try:
            rows = vault.vault_info(self.selected_vault)
        except (OSError, ValueError, KeyError) as e:
            rows = [("Error", str(e))]
        self.query_one("#vault-info", Static).update(_kv_table(rows))
        self._render_vault_contents(self.selected_vault)

    def _render_vault_contents(self, v: Path | None) -> None:
        summary = self.query_one("#vault-summary", Static)
        table = self.query_one("#vault-files", DataTable)
        table.clear()
        manifest = self.unlocked.get(v) if v else None
        if manifest is None:
            summary.update(Text.assemble(("🔒 Locked. ", "bold yellow"),
                                         ("Press ", "dim"), ("u", "bold"),
                                         (" to unlock and see every file inside.", "dim")))
            return
        total = sum(int(e["size"]) for e in manifest["files"])
        summary.update(_kv_table([
            ("Source", manifest.get("source", "?")),
            ("Label", manifest.get("label") or "(none)"),
            ("Started", manifest.get("started", "?")),
            ("Finished", manifest.get("finished", "?")),
            ("Files", f"{len(manifest['files']):,}  ({human_size(total)})"),
            ("Errors", Text(str(len(manifest.get("errors", []))),
                            style="red" if manifest.get("errors") else "green")),
        ]))
        for e in manifest["files"]:
            table.add_row(e["path"], human_size(int(e["size"])), _ts(float(e.get("mtime", 0))),
                          Text(e["sha256"], style="dim"))

    def _need_vault(self) -> Path | None:
        if self.selected_vault is None:
            self.notify("Select a vault first (tab 2).", severity="warning")
            self.action_tab("vaults")
        return self.selected_vault

    def action_unlock(self) -> None:
        if (v := self._need_vault()) is not None:
            self.unlock_flow(v)

    @work(exclusive=True, group="ui")
    async def unlock_flow(self, v: Path) -> dict | None:
        if v in self.unlocked:
            return self.unlocked[v]
        pw = await self.push_screen_wait(PasswordModal(new=False, subject=str(v)))
        if pw is None:
            return None
        try:
            manifest = await asyncio.to_thread(vault.load_manifest, v, pw)
        except vault.VaultError as e:
            self.notify(str(e), title="Unlock failed", severity="error")
            return None
        self.unlocked[v] = manifest
        self.log_line(f"[green]unlocked[/green] {escape(v.name)}: {len(manifest['files'])} files")
        if manifest.get("_note"):
            self.notify(f"{manifest['_note']}. Make a fresh copy of this vault soon.",
                        title="Vault damaged", severity="warning", timeout=15)
        self.load_vaults()
        self._render_vault_contents(v)
        return manifest

    def action_lock(self) -> None:
        self.unlocked.clear()
        self.load_vaults()
        if self.selected_vault:
            self._render_vault_contents(self.selected_vault)
        self.notify("All vaults locked.")

    def action_open_vault(self) -> None:
        if self.busy:
            self.notify(f"Busy: {self.busy}", severity="warning")
            return
        if (v := self._need_vault()) is not None:
            self.open_flow(v)

    @work(exclusive=True, group="ui")
    async def open_flow(self, v: Path) -> None:
        out = await self.push_screen_wait(PathModal(
            "OPEN VAULT", "Decrypt into this folder (files will be PLAINTEXT):",
            str(v.with_name(v.name + "_opened"))))
        if out is None:
            return
        pw = await self.push_screen_wait(PasswordModal(new=False, subject=str(v)))
        if pw is None:
            return
        self._begin(f"opening {v.name}")
        try:
            errors = await self._in_thread(
                lambda log, prog: vault.open_vault(v, out, pw, log=log, progress=prog))
        except (vault.VaultError, OSError) as e:
            self.notify(str(e), title="Open failed", severity="error")
            self._end(f"[red]open failed:[/red] {escape(_err(e))}")
            return
        if errors:
            self._end(f"[red]{len(errors)} files failed to decrypt/verify[/red]")
        else:
            self._end(f"[green]vault opened into[/green] {escape(str(out))} — delete it securely when done")
            self.notify(f"Decrypted into {out}", title="Vault opened")

    def action_add_vault(self) -> None:
        self.add_vault_flow()

    @work(exclusive=True, group="ui")
    async def add_vault_flow(self) -> None:
        p = await self.push_screen_wait(PathModal("ADD VAULT", "Folder that contains vault.json:"))
        if p is None:
            return
        if not (p / vault.VAULT_FILE).is_file():
            self.notify(f"No {vault.VAULT_FILE} in {p}", severity="error")
            return
        self.extra_vaults.append(p.resolve())
        self.load_vaults()
        self.action_tab("vaults")

    # ------------------------------------------------------------ operations

    def _begin(self, what: str) -> None:
        self.busy = what
        self.action_tab("activity")
        self.query_one("#progress-label", Static).update(Text(f"▶ {what}", style="bold yellow"))
        self._set_progress(0, 1)
        self.log_line(f"[b yellow]▶ {escape(what)}[/b yellow]")

    def _end(self, msg: str) -> None:
        self.busy = ""
        self.query_one("#progress-label", Static).update(Text.from_markup(f"■ {msg}"))
        self.log_line(msg)

    async def _in_thread(self, fn):
        """Run fn(log, progress) in a thread, streaming its output into the Activity tab."""
        def log(msg: str) -> None:
            self.call_from_thread(self.log_line, escape(msg))

        def prog(done: int, total: int) -> None:
            now = time.monotonic()
            if done >= total or now - self._progress_t > 0.1:
                self._progress_t = now
                self.call_from_thread(self._set_progress, done, total)

        return await asyncio.to_thread(fn, log, prog)

    def _need_drive(self) -> Drive | None:
        if self.busy:
            self.notify(f"Busy: {self.busy}", severity="warning")
            return None
        drive = self._drive(self.selected)
        if drive is None:
            self.notify("Select a USB drive first (tab 1).", severity="warning")
            self.action_tab("drives")
        return drive

    def action_copy(self) -> None:
        if (d := self._need_drive()) is not None:
            self.drive_flow("copy", d)

    def action_evacuate(self) -> None:
        if (d := self._need_drive()) is not None:
            self.drive_flow("evacuate", d)

    def action_wipe(self) -> None:
        if (d := self._need_drive()) is not None:
            self.drive_flow("wipe", d)

    @work(exclusive=True, group="ui")
    async def _prove_password(self, vault_dir: Path, tries: int = 3) -> bool:
        """Before the original is erased: can the user still open the new vault?"""
        for i in range(tries):
            pw = await self.push_screen_wait(PasswordModal(
                new=False, subject=f"Before erasing: prove you can open the new vault "
                                   f"({tries - i} tries left)"))
            if pw is None:
                return False
            try:
                await asyncio.to_thread(vault.load_manifest, vault_dir, pw)
                self.log_line("[green]vault password confirmed[/green]")
                return True
            except vault.VaultError:
                self.notify("That password does not open the new vault.", severity="error")
        return False

    async def drive_flow(self, kind: str, drive: Drive) -> None:
        dry = self.dry_run
        if kind != "copy" and drive.is_system:
            self.notify("That is the system drive. Refusing.", severity="error")
            return
        identity = await asyncio.to_thread(drive_identity, drive)  # the stick the user chose
        plan = await self.push_screen_wait(PlanModal(
            kind, drive, default_destination(drive) if kind != "wipe" else None, dry))
        if plan is None:
            return
        try:
            if kind != "copy":
                check_wipe_allowed(drive, allow_fixed=plan.allow_fixed, dest=plan.dest)
                await asyncio.to_thread(check_no_vaults, drive, False)
            if kind != "wipe":
                check_destination(plan.dest)
        except SafetyError as e:
            self.notify(str(e), title="Refused", severity="error", timeout=15)
            return

        if kind in ("copy", "evacuate"):
            pw = "dry-run-password" if dry else await self.push_screen_wait(
                PasswordModal(new=True, subject=f"New vault for {drive.letter} {drive.label}"))
            if pw is None:
                return
            self._begin(f"{'dry-run ' if dry else ''}encrypting {drive.letter} → vault")
            try:
                result = await self._in_thread(lambda log, prog: vault.create_vault(
                    Path(drive.root), plan.dest, pw, source_label=drive.label, dry_run=dry,
                    log=log, progress=prog))
            except (OSError, ValueError, vault.VaultError) as e:
                self._end(f"[red]copy failed:[/red] {escape(_err(e))}")
                self.notify(str(e), title="Copy failed", severity="error")
                return
            summary = f"{len(result.files):,} files, {human_size(result.total_bytes)}"
            if not result.ok:
                self._end(f"[red]{len(result.errors)} errors — copy NOT verified, drive NOT wiped[/red]")
                self.notify("Copy was not fully verified. Nothing was wiped.", severity="error")
                return
            self._end(f"[green]✔ encrypted + verified[/green] {summary}"
                      + ("" if dry else f" → {escape(str(plan.dest))}"))
            if not dry:
                self.load_vaults()
            if kind == "copy":
                self.notify(summary, title="Encrypted copy verified")
                return

        # ---- wipe (evacuate step 2, or wipe alone)
        reason = await asyncio.to_thread(still_same_drive, drive, identity)
        if reason:
            self.notify(f"{reason} Not wiping.", severity="error")
            return
        if kind == "evacuate" and not dry and not await self._prove_password(Path(result.destination)):
            self._end("[red]not wiping: the vault could not be opened with the password typed[/red]"
                      " — your files are in the vault and still on the stick")
            return
        if not dry:
            stats = self.drive_stats.get(drive.letter)
            ok = await self.push_screen_wait(ConfirmWipeModal(
                drive, self.drive_detail_rows.get(drive.letter) or drive_details(drive),
                METHOD_INFO[plan.method][0], stats["files"] if stats else None))
            if not ok:
                self.log_line("wipe cancelled — nothing was erased")
                return
        self._begin(f"{'dry-run ' if dry else ''}wiping {drive.letter} ({plan.method})")
        try:
            code = await self._in_thread(lambda log, prog: do_wipe(
                drive, plan.method, plan.passes, dry, log=log, progress=prog,
                verified=result.files if kind == "evacuate" else None, identity=identity,
                vault_result=result if kind == "evacuate" else None))
        except OSError as e:
            self.log_line(f"[red]wipe error:[/red] {escape(str(e))}")
            code = 1
        if code == 0:
            self._end(f"[green]✔ wipe finished[/green] {drive.letter}")
            self.notify(f"{drive.letter} wiped ({plan.method})", title="Done")
        else:
            self._end(f"[red]wipe ended with errors (code {code})[/red] — see log")
            self.notify("Wipe reported errors. Check the Activity log.", severity="error")
        self.drive_stats.pop(drive.letter, None)
        self._last_drive_sig = ()
        self.poll_drives()

    # ------------------------------------------------------------ local drop

    def _render_send_list(self) -> None:
        table = self.query_one("#send-list", DataTable)
        table.clear()
        total = 0
        for p in self.send_paths:
            size = _path_size(p)
            total += size
            table.add_row(Text(str(p)), Text(human_size(size) + ("" if p.is_file() else "  (folder)")))
        hint = self.query_one("#send-hint", Static)
        if not self.send_paths:
            hint.update("Press [b]f[/b] to add a file or folder. You can drag it from Explorer "
                        "into the box. Then press [b]s[/b] to send.")
        else:
            hint.update(f"{len(self.send_paths)} item(s), {human_size(total)}. Press [b]s[/b] to "
                        "send. The other PC must be receiving (tab 4, key [b]g[/b]).")

    def _render_receive_idle(self) -> None:
        self.query_one("#recv-info", Static).update(Text.from_markup(
            "\n[b]Not receiving.[/b]\n\nPress [b]g[/b] to receive files from another PC.\n"
            "This PC then shows a name and a 6-digit code.\n\n"
            "[dim]No port is opened until the other PC connects over Wi-Fi Direct,\n"
            "and only that PC can connect, once.[/dim]"))
        self.query_one("#recv-hint", Static).update(
            f"[dim]Files are saved to {escape(str(drop.DEFAULT_DEST))} unless you choose "
            "another folder.[/dim]")

    def _show_code(self, name: str, code: str, dest: Path) -> None:
        t = Text()
        t.append("\nVisible as\n", style="dim")
        t.append(f"  {name}\n\n", style="bold cyan")
        t.append("Code\n", style="dim")
        t.append(f"  {code}  \n\n", style="bold black on yellow")
        t.append("Tell the sender this code in person.\n", style="bold")
        t.append("Never read it out over the phone or send it in a chat.\n\n", style="dim")
        t.append(f"Saving to {dest}\n", style="dim")
        t.append("Press k to stop.", style="dim")
        self.query_one("#recv-info", Static).update(t)
        self.query_one("#recv-hint", Static).update("[yellow]● waiting for a sender…[/yellow]")

    def _drop_status(self, msg: str) -> None:
        self.query_one("#drop-status", Static).update(Text(msg[:200]))

    def _drop_progress(self, done: int, total: int) -> None:
        self.query_one("#drop-progress", ProgressBar).update(total=max(total, 1), progress=done)

    def _drop_finished(self, msg: str, ok: bool) -> None:
        self.drop_running = ""
        self.busy = ""
        self.log_line(msg)
        self.query_one("#drop-status", Static).update(Text.from_markup(f"■ {msg}"))
        self._render_receive_idle()
        if ok:
            self.notify(Text.from_markup(msg).plain, title="Local drop")
        elif "stopped" in msg or "declined" in msg:
            self.notify(Text.from_markup(msg).plain, title="Local drop", severity="warning")
        else:
            self.notify(Text.from_markup(msg).plain, title="Local drop", severity="error", timeout=12)

    def _ask(self, screen: ModalScreen, cancelled: Callable[[], bool]):
        """Show a dialog from the transfer thread and wait for the answer.
        Returns None if the transfer is stopped while the dialog is open."""
        fut: Future = Future()
        self.call_from_thread(self.push_screen, screen, fut.set_result)
        while True:
            try:
                return fut.result(timeout=0.5)
            except FutureTimeout:
                if cancelled():
                    try:
                        self.call_from_thread(screen.dismiss, None)
                    except Exception:
                        pass  # already closed
                    return None

    def _drop_hooks(self, dest: Path | None = None) -> drop.Hooks:
        worker = get_current_worker()
        cancelled = lambda: worker.is_cancelled  # noqa: E731
        last = [0.0]

        def log(msg: str) -> None:
            self.call_from_thread(self.log_line, escape(msg))
            first = msg.strip().splitlines()
            if first:
                self.call_from_thread(self._drop_status, first[0])

        def prog(done: int, total: int) -> None:
            now = time.monotonic()
            if done >= total or now - last[0] > 0.1:
                last[0] = now
                self.call_from_thread(self._drop_progress, done, total)

        return drop.Hooks(
            log=log, progress=prog, cancelled=cancelled,
            ask_code=lambda: self._ask(CodeModal(), cancelled),
            choose=lambda peers: self._ask(PeerModal(peers), cancelled),
            ask_accept=lambda offer: bool(self._ask(AcceptModal(offer, dest or drop.DEFAULT_DEST),
                                                    cancelled)),
            on_ready=lambda name, code, d: self.call_from_thread(self._show_code, name, code, d),
        )

    def _can_drop(self) -> bool:
        if self.busy:
            self.notify(f"Busy: {self.busy}", severity="warning")
            return False
        if self.dry_run:
            self.notify("DRY-RUN is on. Press d to switch to LIVE mode to send or receive.",
                        severity="warning")
            return False
        return True

    def _drop_begin(self, what: str) -> None:
        self.drop_running = what
        self.busy = what
        self._drop_progress(0, 1)
        self.query_one("#drop-status", Static).update(Text(f"▶ {what}", style="bold yellow"))
        self.log_line(f"[b yellow]▶ {escape(what)}[/b yellow]")

    def action_drop_add(self) -> None:
        self.action_tab("drop")
        self._drop_add()

    @work(exclusive=True, group="ui")
    async def _drop_add(self) -> None:
        p = await self.push_screen_wait(PathModal(
            "ADD TO SEND LIST", "File or folder to send (type a path, or drag it from Explorer here):"))
        if p is None:
            return
        if not p.exists():
            self.notify(f"Not found: {p}", severity="error")
            return
        if is_link(p):
            self.notify("That is a link/junction. Add the real file or folder instead.",
                        severity="error")
            return
        p = p.resolve()
        if p not in self.send_paths:
            self.send_paths.append(p)
        self._render_send_list()

    def action_drop_clear(self) -> None:
        if self.drop_running:
            self.notify("Stop the transfer first (k).", severity="warning")
            return
        self.send_paths.clear()
        self._render_send_list()

    def action_drop_send(self) -> None:
        self.action_tab("drop")
        if not self.send_paths:
            self.notify("Add files first (f).", severity="warning")
            return
        if self._can_drop():
            self._drop_begin(f"sending {len(self.send_paths)} item(s)")
            self._drop_send(list(self.send_paths))

    @work(thread=True, exclusive=True, group="drop", exit_on_error=False)
    def _drop_send(self, paths: list[Path]) -> None:
        try:
            n = drop.send(paths, None, "wifi-direct", None, None, self._drop_hooks())
            self.call_from_thread(self._drop_finished, f"[green]✔ sent {n} file(s)[/green]", True)
        except drop.Cancelled:
            self.call_from_thread(self._drop_finished, "sending stopped", False)
        except drop.protocol.Rejected as e:
            self.call_from_thread(self._drop_finished, f"[yellow]{escape(str(e))}[/yellow]", False)
        except Exception as e:  # shown to the user, never a crash
            self.call_from_thread(self._drop_finished,
                                  f"[red]sending failed:[/red] {escape(_err(e))}", False)

    def action_drop_receive(self) -> None:
        self.action_tab("drop")
        if self._can_drop():
            self._drop_receive_start()

    @work(exclusive=True, group="ui")
    async def _drop_receive_start(self) -> None:
        dest = await self.push_screen_wait(PathModal(
            "RECEIVE FILES", "Save received files in this folder:", str(drop.DEFAULT_DEST)))
        if dest is None or not self._can_drop():
            return
        dest = dest.resolve()
        if dest.exists() and not dest.is_dir():
            self.notify(f"{dest} is a file, not a folder.", severity="error")
            return
        try:
            drop.check_receive_dest(dest, allow_cloud=False)
        except drop.protocol.ProtocolError as e:
            self.notify(str(e), title="Refused", severity="error", timeout=12)
            return
        self._drop_begin("receiving")
        self._drop_receive(dest)

    @work(thread=True, exclusive=True, group="drop", exit_on_error=False)
    def _drop_receive(self, dest: Path) -> None:
        try:
            got = drop.receive(dest, "wifi-direct", False, None, self._drop_hooks(dest))
            self.call_from_thread(self._drop_finished,
                                  f"[green]✔ received {len(got)} file(s)[/green] → {escape(str(dest))}",
                                  True)
        except drop.Cancelled:
            self.call_from_thread(self._drop_finished, "receiving stopped", False)
        except drop.protocol.Rejected as e:
            self.call_from_thread(self._drop_finished, f"[yellow]{escape(str(e))}[/yellow]", False)
        except Exception as e:  # shown to the user, never a crash
            self.call_from_thread(self._drop_finished,
                                  f"[red]receiving failed:[/red] {escape(_err(e))}", False)

    def action_drop_stop(self) -> None:
        if not self.drop_running:
            return
        self.workers.cancel_group(self, "drop")
        self.query_one("#drop-status", Static).update(Text("stopping…", style="yellow"))

    # ------------------------------------------------------------ misc actions

    _OWN_ACTIONS = {"tab", "copy", "evacuate", "wipe", "unlock", "open_vault", "toggle_dry_run",
                    "help", "quit", "hash_file", "toggle_all", "refresh", "lock", "add_vault",
                    "toggle_banner", "drop_add", "drop_clear", "drop_send", "drop_receive",
                    "drop_stop"}

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        # While a dialog is open, its keys must never trigger app actions (e.g. q = quit).
        if action in self._OWN_ACTIONS and isinstance(self.screen, ModalScreen):
            return False
        return True

    TAB_FOCUS = {"drives": "#drive-table", "vaults": "#vault-table", "activity": "#log",
                 "drop": "#send-list"}

    def action_tab(self, name: str) -> None:
        # TabbedContent follows focus, so focus must move into the new tab too,
        # otherwise it jumps straight back to the tab that still holds focus.
        self.query_one(TabbedContent).active = name
        self.query_one(self.TAB_FOCUS[name]).focus()

    @on(TabbedContent.TabActivated)
    def _tab_clicked(self, event: TabbedContent.TabActivated) -> None:
        pane = event.pane.id
        focused = self.focused
        if pane in self.TAB_FOCUS and (focused is None or pane not in
                                       {a.id for a in focused.ancestors_with_self}):
            self.query_one(self.TAB_FOCUS[pane]).focus()

    def action_toggle_dry_run(self) -> None:
        self.dry_run = not self.dry_run
        self.notify("DRY-RUN on: nothing will be written or erased." if self.dry_run
                    else "LIVE mode: operations are real.",
                    severity="warning" if not self.dry_run else "information")

    def action_toggle_all(self) -> None:
        self.show_all = not self.show_all
        self._last_drive_sig = ()
        self.poll_drives()

    def action_refresh(self) -> None:
        self._last_drive_sig = ()
        if self.selected:
            self.drive_stats.pop(self.selected, None)
        self.poll_drives()
        self.load_vaults()

    def action_toggle_banner(self) -> None:
        top = self.query_one("#top")
        top.display = not top.display

    def action_help(self) -> None:
        self.push_screen(HelpModal())
