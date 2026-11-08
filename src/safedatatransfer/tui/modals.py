"""Pop-up dialogs: plan an operation, enter passwords, confirm a wipe, help."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button, Checkbox, Input, Label, OptionList, RadioButton, RadioSet, Static,
)

from safedatatransfer.common.crypto import MIN_PASSWORD_LEN, password_problem
from safedatatransfer.common.drives import Drive, human_size

METHOD_INFO = {
    "quick": ("Quick  (default)", "Overwrite every file with random data, scramble its name, delete it. Free space is not touched."),
    "fill": ("Quick + fill free space", "Also fills ALL free space with random data, then deletes the filler (the stick ends up empty). Erases traces of files deleted earlier. Takes as long as filling the stick once."),
}


def _drive_line(drive: Drive) -> Text:
    t = Text()
    t.append(f" {drive.letter} ", style="bold reverse")
    t.append(f"  {drive.label or '(no label)'}", style="bold")
    t.append(f"   {human_size(drive.total_bytes)} {drive.filesystem}   serial {drive.serial:08X}",
             style="dim")
    return t


# ---------------------------------------------------------------- plan

@dataclass
class Plan:
    dest: Path | None
    method: str
    passes: int
    allow_fixed: bool


class PlanModal(ModalScreen[Plan | None]):
    """Choose destination / wipe method before an operation starts."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, kind: str, drive: Drive, default_dest: Path | None, dry_run: bool):
        super().__init__()
        self.kind, self.drive, self.default_dest, self.dry_run = kind, drive, default_dest, dry_run

    def compose(self) -> ComposeResult:
        titles = {"copy": "ENCRYPTED COPY", "evacuate": "EVACUATE  (copy → verify → wipe)",
                  "wipe": "WIPE DRIVE"}
        with Vertical(id="dialog", classes="danger" if self.kind != "copy" else ""):
            yield Static(Text(titles[self.kind], style="bold"), classes="dialog-title")
            yield Static(_drive_line(self.drive))
            if self.dry_run:
                yield Static(Text("DRY-RUN: nothing will be written or erased.", style="bold yellow"))
            if self.kind in ("copy", "evacuate"):
                yield Label("Vault destination folder (will be created, encrypted):")
                yield Input(str(self.default_dest), id="dest")
            if self.kind in ("evacuate", "wipe"):
                yield Label("Wipe method:")
                with RadioSet(id="method"):
                    for key, (label, _desc) in METHOD_INFO.items():
                        yield RadioButton(label, value=(key == "quick"), id=f"m-{key}")
                yield Static(id="method-desc", classes="hint")
                with Horizontal(classes="row"):
                    yield Label("Overwrite passes per file: ")
                    yield Input("1", id="passes", restrict=r"[0-9]*", max_length=2)
                if self.drive.type == "fixed" and not self.drive.is_system:
                    yield Checkbox("This 'fixed' drive really is my USB drive (USB SSD)", id="fixed")
            with Horizontal(classes="buttons"):
                yield Button("Start  ⏎", variant="error" if self.kind != "copy" else "primary", id="ok")
                yield Button("Cancel  esc", id="cancel")

    def on_mount(self) -> None:
        self._show_desc("quick")
        first = self.query("Input")
        if first:
            first.first().focus()

    def _show_desc(self, key: str) -> None:
        for w in self.query("#method-desc"):
            w.update(Text(METHOD_INFO[key][1], style="italic"))

    @on(RadioSet.Changed, "#method")
    def _method_changed(self, event: RadioSet.Changed) -> None:
        self._show_desc(event.pressed.id.removeprefix("m-"))

    @on(Input.Submitted)
    @on(Button.Pressed, "#ok")
    def _submit(self) -> None:
        dest = None
        if self.query("#dest"):
            raw = self.query_one("#dest", Input).value.strip().strip('"')
            if not raw:
                self.notify("Choose a destination folder.", severity="error")
                return
            dest = Path(raw).expanduser()
            if dest.exists() and not self.dry_run:
                self.notify("That folder already exists. Pick a new one.", severity="error")
                return
        method, passes = "quick", 1
        if self.query("#method"):
            pressed = self.query_one("#method", RadioSet).pressed_button
            method = pressed.id.removeprefix("m-") if pressed else "quick"
            passes = max(1, min(35, int(self.query_one("#passes", Input).value or "1")))
        allow_fixed = bool(self.query("#fixed")) and self.query_one("#fixed", Checkbox).value
        self.dismiss(Plan(dest, method, passes, allow_fixed))

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------- password

def _strength(pw: str) -> Text:
    classes = sum(bool(any(f(c) for c in pw)) for f in (str.islower, str.isupper, str.isdigit,
                                                         lambda c: not c.isalnum()))
    score = min(4, len(pw) // 4 + classes - 1) if pw else 0
    names = ["too short", "weak", "okay", "good", "strong"]
    colors = ["red", "red", "yellow", "green", "bold green"]
    if len(pw) < MIN_PASSWORD_LEN:
        score = 0
    t = Text("strength ")
    t.append("■" * (score + 1), style=colors[score])
    t.append("□" * (4 - score), style="grey35")
    t.append(f"  {names[score]}  ({len(pw)} chars)", style=colors[score])
    return t


class PasswordModal(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, new: bool, subject: str = ""):
        super().__init__()
        self.new, self.subject = new, subject

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            title = "CHOOSE VAULT PASSWORD" if self.new else "UNLOCK VAULT"
            yield Static(Text(title, style="bold"), classes="dialog-title")
            if self.subject:
                yield Static(Text(self.subject, style="dim"))
            if self.new:
                yield Static(Text("Without this password the files cannot be recovered. "
                                  "Nobody can reset it.", style="yellow"))
            yield Input(password=True, placeholder="password", id="pw1")
            if self.new:
                yield Static(_strength(""), id="strength")
                yield Input(password=True, placeholder="repeat password", id="pw2")
            yield Static(id="error", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("OK  ⏎", variant="primary", id="ok")
                yield Button("Cancel  esc", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#pw1", Input).focus()

    @on(Input.Changed, "#pw1")
    def _changed(self, event: Input.Changed) -> None:
        if self.new:
            self.query_one("#strength", Static).update(_strength(event.value))

    @on(Input.Submitted, "#pw1")
    def _next(self) -> None:
        if self.new:
            self.query_one("#pw2", Input).focus()
        else:
            self._submit()

    @on(Input.Submitted, "#pw2")
    @on(Button.Pressed, "#ok")
    def _submit(self) -> None:
        pw = self.query_one("#pw1", Input).value
        err = self.query_one("#error", Static)
        if self.new:
            problem = password_problem(pw)
            if problem:
                err.update(problem)
                return
            if pw != self.query_one("#pw2", Input).value:
                err.update("Passwords do not match.")
                self.query_one("#pw2", Input).value = ""
                self.query_one("#pw2", Input).focus()
                return
        elif not pw:
            return
        self.dismiss(pw)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------- confirm wipe

class ConfirmWipeModal(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, drive: Drive, details: list[tuple[str, str]], method: str, file_count: int | None):
        super().__init__()
        self.drive, self.details, self.method, self.file_count = drive, details, method, file_count
        self.expected = f"WIPE {drive.letter}"

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="danger"):
            yield Static(Text("⚠  PERMANENT ERASE  ⚠", style="bold white on red", justify="center"),
                         classes="dialog-title")
            table = Table.grid(padding=(0, 2))
            table.add_column(style="bold red")
            table.add_column()
            for k, v in self.details:
                if k in ("Drive", "Label", "Capacity", "Device", "Hardware serial", "Volume serial", "Bus"):
                    table.add_row(k, Text(v))
            table.add_row("Method", self.method)
            if self.file_count is not None:
                table.add_row("Files", f"{self.file_count:,} will be destroyed")
            yield Static(table)
            yield Label(Text.assemble("Type ", (self.expected, "bold reverse"), " to erase this drive:"))
            yield Input(placeholder=self.expected, id="confirm")
            with Horizontal(classes="buttons"):
                yield Button("ERASE", variant="error", id="ok", disabled=True)
                yield Button("Cancel  esc", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#confirm", Input).focus()

    @on(Input.Changed, "#confirm")
    def _changed(self, event: Input.Changed) -> None:
        self.query_one("#ok", Button).disabled = event.value.strip().upper() != self.expected

    @on(Input.Submitted, "#confirm")
    @on(Button.Pressed, "#ok")
    def _submit(self) -> None:
        if self.query_one("#confirm", Input).value.strip().upper() == self.expected:
            self.dismiss(True)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(False)


# ---------------------------------------------------------------- path input

class PathModal(ModalScreen[Path | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, prompt: str, default: str = ""):
        super().__init__()
        self.title_text, self.prompt, self.default = title, prompt, default

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(Text(self.title_text, style="bold"), classes="dialog-title")
            yield Label(self.prompt)
            yield Input(self.default, id="path")
            with Horizontal(classes="buttons"):
                yield Button("OK  ⏎", variant="primary", id="ok")
                yield Button("Cancel  esc", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#path", Input).focus()

    @on(Input.Submitted)
    @on(Button.Pressed, "#ok")
    def _submit(self) -> None:
        raw = self.query_one("#path", Input).value.strip().strip('"')
        if raw:
            self.dismiss(Path(raw).expanduser())

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------- local drop

class CodeModal(ModalScreen[str | None]):
    """Sender: type the 6-digit code shown on the receiver."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, receiver: str = ""):
        super().__init__()
        self.receiver = receiver

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(Text("ENTER THE CODE", style="bold"), classes="dialog-title")
            yield Label("Type the 6-digit code that the receiving PC shows"
                        + (f" ({self.receiver})" if self.receiver else "") + ":")
            yield Input(placeholder="123-456", id="code", restrict=r"[0-9 -]*", max_length=9)
            yield Static("Only someone who sees the receiver's screen knows this code. "
                         "A wrong code stops the transfer.", classes="hint")
            with Horizontal(classes="buttons"):
                yield Button("Connect  ⏎", variant="primary", id="ok", disabled=True)
                yield Button("Cancel  esc", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#code", Input).focus()

    def _digits(self) -> str:
        return "".join(c for c in self.query_one("#code", Input).value if c.isdigit())

    @on(Input.Changed, "#code")
    def _changed(self, _event: Input.Changed) -> None:
        self.query_one("#ok", Button).disabled = len(self._digits()) != 6

    @on(Input.Submitted, "#code")
    @on(Button.Pressed, "#ok")
    def _submit(self) -> None:
        d = self._digits()
        if len(d) == 6:
            self.dismiss(f"{d[:3]}-{d[3:]}")

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class PeerModal(ModalScreen[object | None]):
    """Sender: several receivers are nearby, pick one."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, peers: list):
        super().__init__()
        self.peers = peers

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(Text("SEND TO WHICH PC?", style="bold"), classes="dialog-title")
            yield Label("Several receivers are nearby. Pick the name the other PC shows:")
            # Text(): names come from nearby devices; never interpret them as markup.
            yield OptionList(*[Text(p.label()) for p in self.peers], id="peers")
            with Horizontal(classes="buttons"):
                yield Button("Cancel  esc", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#peers", OptionList).focus()

    @on(OptionList.OptionSelected, "#peers")
    def _picked(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(self.peers[event.option_index])

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class AcceptModal(ModalScreen[bool]):
    """Receiver: someone wants to send these files. Decline is the default."""

    BINDINGS = [Binding("escape", "decline", "Decline")]

    def __init__(self, offer: dict, dest: Path):
        super().__init__()
        self.offer, self.dest = offer, dest

    def compose(self) -> ComposeResult:
        files = self.offer.get("files", [])
        total = sum(int(f.get("size", 0)) for f in files)
        with Vertical(id="dialog", classes="wide"):
            yield Static(Text("INCOMING FILES", style="bold"), classes="dialog-title")
            head = Table.grid(padding=(0, 2))
            head.add_column(style="bold cyan", justify="right")
            head.add_column()
            head.add_row("From", Text(str(self.offer.get("sender", "?"))))
            head.add_row("Files", f"{len(files):,}  ({human_size(total)})")
            head.add_row("Save to", Text(str(self.dest)))
            yield Static(head)
            listing = Table(show_header=False, box=None, padding=(0, 2), expand=True)
            listing.add_column(justify="right", style="dim", width=10)
            listing.add_column(overflow="fold")
            for f in files[:500]:
                listing.add_row(human_size(int(f.get("size", 0))), Text(str(f.get("path"))))
            if len(files) > 500:
                listing.add_row("", f"... and {len(files) - 500:,} more")
            with VerticalScroll():
                yield Static(listing)
            yield Static("Names are shown exactly as they will be saved. Existing files are "
                         "never overwritten. Only accept files you expect.", classes="hint")
            with Horizontal(classes="buttons"):
                yield Button("Accept", variant="success", id="ok")
                yield Button("Decline  esc", variant="error", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()  # Enter alone never accepts

    @on(Button.Pressed, "#ok")
    def _accept(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#cancel")
    def action_decline(self) -> None:
        self.dismiss(False)


# ---------------------------------------------------------------- help

HELP_KEYS = [
    ("Navigation", [
        ("1 / 2 / 3 / 4", "Drives / Vaults / Activity / Drop tab"),
        ("↑ ↓  ← →", "move in lists and the file tree (expand/collapse folders)"),
        ("tab / shift+tab", "move between panels"),
        ("enter", "open folder / choose"),
        ("esc", "close a dialog"),
    ]),
    ("USB drives", [
        ("c", "encrypted copy of the selected drive into a new vault"),
        ("e", "evacuate: encrypted copy → verify → wipe"),
        ("w", "wipe the selected drive"),
        ("h", "compute SHA-256 of the selected file"),
        ("a", "show all drives (not only removable)"),
        ("r", "refresh now (drives are also auto-detected)"),
    ]),
    ("Vaults", [
        ("u", "unlock the selected vault and list every file inside"),
        ("o", "open (decrypt) the selected vault into a folder"),
        ("l", "lock: forget the unlocked file list"),
        ("p", "add a vault from another folder"),
    ]),
    ("Local drop (tab 4)", [
        ("f", "add a file or folder to send (you can drag it from Explorer)"),
        ("x", "clear the send list"),
        ("s", "send the list to another PC over Wi-Fi Direct"),
        ("g", "receive: show a name and a code, wait for a sender"),
        ("k", "stop sending / receiving"),
    ]),
    ("General", [
        ("d", "toggle DRY-RUN (simulate everything, write nothing)"),
        ("b", "show / hide the banner"),
        ("?", "this help"),
        ("q", "quit"),
    ]),
]

HELP_NOTES = """\
[b]How evacuate keeps you safe[/b]
 1. Every file is encrypted into the vault (contents, names and folders).
 2. Every blob is decrypted again from disk and its SHA-256 compared to the original.
 3. If anything failed, the drive is NOT wiped.
 4. The stick's identity (serial, size, hardware serial) is re-checked, and
    again after you confirm, so a swapped stick is never erased.
 5. You must type [b]WIPE <letter>[/b]. The system drive is always refused.
 6. Only files exactly as verified in the vault are wiped; anything new or
    changed stops the wipe. Links/junctions are never followed.

[b]Wiping[/b] needs no admin rights and runs no external programs.
 quick: every file (incl. FAT/exFAT cluster slack) is overwritten with random
 data, renamed randomly, deleted; old names in the folder entries are scrubbed.
 fill (only if you choose it): quick + the whole free space is filled with
 random data, flushed to the stick, then the filler is deleted.

[b]Privacy[/b]
 Unlocked vault lists are forgotten after 10 minutes without input (or press l).
 Decrypted folders are kept out of Windows Search; cloud folders are refused.

[b]Encryption[/b]
 scrypt (N=2^18 for new vaults, r=8, p=1) → master key · HKDF → one key per file
 AES-256-GCM in 1 MiB chunks; reordering, truncation or edits are detected.

[b]Limitation[/b]
 Flash drives remap blocks internally (wear levelling). No software can
 guarantee every old block is gone. For truly secret data keep it encrypted
 on the stick (BitLocker To Go / VeraCrypt) or physically destroy the stick.
"""


class HelpModal(ModalScreen[None]):
    BINDINGS = [Binding("escape,q,question_mark", "close", "Close")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="wide"):
            yield Static(Text("KEYS & INFO", style="bold"), classes="dialog-title")
            with VerticalScroll():
                for section, keys in HELP_KEYS:
                    table = Table(title=section, title_style="bold magenta", title_justify="left",
                                  show_header=False, box=None, padding=(0, 2), expand=True)
                    table.add_column(style="bold cyan", width=18)
                    table.add_column()
                    for k, d in keys:
                        table.add_row(k, d)
                    yield Static(table)
                yield Static(HELP_NOTES)
            yield Static(Text("esc to close", style="dim", justify="center"))

    def action_close(self) -> None:
        self.dismiss(None)
