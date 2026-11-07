"""Banner, gradients and bars — the purely cosmetic parts of the TUI."""

from __future__ import annotations

import math

from rich.text import Text

LOGO = [
    "███████╗██████╗ ████████╗",
    "██╔════╝██╔══██╗╚══██╔══╝",
    "███████╗██║  ██║   ██║   ",
    "╚════██║██║  ██║   ██║   ",
    "███████║██████╔╝   ██║   ",
    "╚══════╝╚═════╝    ╚═╝   ",
]

# Cycling palette (tokyo-night-ish): blue -> purple -> pink -> cyan -> blue
PALETTE = [(122, 162, 247), (187, 154, 247), (247, 118, 142), (125, 207, 255)]


def _mix(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> str:
    r, g, bl = (int(x + (y - x) * t) for x, y in zip(a, b))
    return f"#{r:02x}{g:02x}{bl:02x}"


def palette_color(pos: float) -> str:
    """Color at position pos (any float; wraps around the palette)."""
    pos %= len(PALETTE)
    i = int(pos)
    return _mix(PALETTE[i], PALETTE[(i + 1) % len(PALETTE)], pos - i)


def logo(phase: float = 0.0) -> Text:
    """The SDT logo with a diagonal gradient; change `phase` to animate it."""
    text = Text(no_wrap=True)
    width = max(len(line) for line in LOGO)
    for row, line in enumerate(LOGO):
        for col, ch in enumerate(line):
            pos = phase + (col + row * 1.5) / width * 2.0
            style = f"bold {palette_color(pos)}" if ch == "█" else palette_color(pos) + " dim"
            text.append(ch, style=style)
        if row < len(LOGO) - 1:
            text.append("\n")
    return text


def tagline(phase: float) -> Text:
    t = Text(no_wrap=True)
    t.append("S A F E   D A T A   T R A N S F E R\n", style=f"bold {palette_color(phase + 1)}")
    t.append("encrypted vault", style="bold")
    t.append("  ·  ", style="dim")
    t.append("verified copy", style="bold")
    t.append("  ·  ", style="dim")
    t.append("secure wipe", style="bold")
    t.append("  ·  ", style="dim")
    t.append("local drop\n", style="bold")
    pulse = (math.sin(phase * 2) + 1) / 2
    t.append("● ", style=_mix((80, 250, 123), (30, 120, 60), pulse))
    t.append("AES-256-GCM · scrypt · SHA-256 verify · SPAKE2", style="dim")
    return t


def usage_bar(fraction: float, width: int = 28) -> Text:
    """▰▰▰▱▱ style bar, green -> yellow -> red as it fills."""
    fraction = max(0.0, min(1.0, fraction))
    filled = round(fraction * width)
    t = Text(no_wrap=True)
    for i in range(width):
        x = i / max(1, width - 1)
        color = _mix((80, 250, 123), (241, 250, 140), x * 2) if x < 0.5 else \
            _mix((241, 250, 140), (255, 85, 85), (x - 0.5) * 2)
        t.append("█" if i < filled else "░", style=color if i < filled else "grey23")
    t.append(f" {fraction * 100:5.1f}%", style="bold")
    return t


def mini_bar(fraction: float, width: int = 8) -> Text:
    fraction = max(0.0, min(1.0, fraction))
    filled = round(fraction * width)
    color = "green" if fraction < 0.6 else "yellow" if fraction < 0.85 else "red"
    return Text("▰" * filled, style=color) + Text("▱" * (width - filled), style="grey35")
