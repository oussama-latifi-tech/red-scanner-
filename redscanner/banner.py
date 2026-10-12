"""ASCII banner with a red gradient logo."""
from __future__ import annotations

import os
import shutil
import sys
from typing import Optional

RESET = "\033[0m"
BOLD = "\033[1m"

PALETTE = [(110, 0, 0), (122, 0, 0), (134, 4, 2), (146, 6, 2),
           (156, 8, 2), (164, 8, 2), (170, 10, 3), (176, 14, 6)]
RED256 = [88, 88, 124, 124, 124, 160, 160, 160]
LOGO_WIDTH = 22

LOGO_CHARS = """
      █████▄▄         
           ▀▀██▄▄     
    ▄▄▄████    ▀▀█▄   
  ▄██▀▀          ▀██▄ 
 ▄█▀         ▄▄    ██ 
▄█▀   ██▀▀   ▀███   ██
██   ███      ▀▀▀   ██
██    █             ██
██    ▄        ▄▄   ██
 ██   ▀█▄▄▄▄▄▄█▀   ▄█ 
 ▀██   ▀▀▀▀▀▀ ▀   ██  
  ████▄         ▄█▀   
  ▀█ ▀▀████▄▄██▀▀     
        █  ▀          
"""

LOGO_SHADES = """
0000007777767000000000
0000000000076775700000
0000752555700007577000
0074425000000000077770
0626000000000770000770
7370005117000345700057
6500074500000077700075
6700007000000000000073
7500007000000007700047
0670004323455476000330
0767000777777070004200
0077777000000000334000
0077076777754772700000
0000000070070000000000
"""

TITLE = r"""
 ___ ___ ___    ___  ___   _   _  _ _  _ ___ ___ 
| _ \ __|   \  / __|/ __| /_\ | \| | \| | __| _ \
|   / _|| |) | \__ \ (__ / _ \| .` | .` | _||   /
|_|_\___|___/  |___/\___/_/ \_\_|\_|_|\_|___|_|_\
                                                 
"""

TAGLINE = "I see your open ports. :)"


def _mode() -> str:
    """Pick the color mode: none (pipe / NO_COLOR), true, 256 or basic."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return "none"
    colorterm = os.environ.get("COLORTERM", "")
    if "truecolor" in colorterm or "24bit" in colorterm or os.environ.get("WT_SESSION"):
        return "true"
    if "256" in os.environ.get("TERM", ""):
        return "256"
    return "basic"


def _center(text: str, width: int) -> str:
    return " " * max((width - len(text)) // 2, 0) + text


def _color_char(ch: str, shade: str, mode: str) -> str:
    if mode == "true":
        r, g, b = PALETTE[int(shade)]
        return f"\033[38;2;{r};{g};{b}m{ch}"
    if mode == "256":
        return f"\033[38;5;{RED256[int(shade)]}m{ch}"
    return f"\033[31m{ch}"


def show_banner(force: Optional[str] = None, tagline: str = TAGLINE) -> None:
    """Print the logo, title and tagline, centered in the terminal."""
    mode = force or _mode()
    if os.name == "nt" and mode != "none":
        os.system("")  # enables ANSI escape codes on Windows terminals

    title_lines = TITLE.strip("\n").split("\n")
    title_w = max(len(line) for line in title_lines)
    pad = " " * max((title_w - LOGO_WIDTH) // 2, 0)
    out = []

    for chars, shades in zip(LOGO_CHARS.strip("\n").split("\n"),
                             LOGO_SHADES.strip("\n").split("\n")):
        line = ""
        for ch, shade in zip(chars, shades):
            line += ch if ch == " " or mode == "none" else _color_char(ch, shade, mode)
        out.append(pad + line + ("" if mode == "none" else RESET))
    out.append("")

    on = "" if mode == "none" else BOLD + "\033[31m"
    off = "" if mode == "none" else RESET
    out.append(on + _center("T H E", title_w) + off)
    out.extend(on + line + off for line in title_lines)
    out.append(on + _center(tagline, title_w) + off)

    term_w = shutil.get_terminal_size((80, 24)).columns
    indent = " " * max((term_w - title_w) // 2, 0)
    print("\n".join(indent + line for line in out))


if __name__ == "__main__":
    show_banner(sys.argv[1] if len(sys.argv) > 1 else None)
