"""Full-screen keyboard-driven interface for sdt (built on Textual).

Start it with `sdt` (no arguments) or `sdt ui`.
"""


def run() -> int:
    from safedatatransfer.tui.app import SdtApp

    SdtApp().run()
    return 0
