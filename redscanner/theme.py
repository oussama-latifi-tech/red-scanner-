"""Red and black terminal theme (Rich)."""
from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

RED_THEME = Theme({
    "banner": "bold red on black",
    "header": "bold red on black",
    "border": "red",
    "open": "bold green on black",
    "closed": "dim red on black",
    "filtered": "dim red on black",
    "info": "white on black",
    "warning": "yellow on black",
    "critical": "bold red on black",
    "muted": "dim white on black",
    "tagline": "red on black",
    "text": "white on black",
})

DISCLAIMER = (
    "LEGAL DISCLAIMER: Only scan systems you own or have explicit written "
    "permission to test. Unauthorized scanning may be illegal in your jurisdiction."
)


def get_console_with_theme(no_color: bool = False) -> Console:
    """Rich console using the scanner theme (Rich also honours NO_COLOR)."""
    return Console(theme=RED_THEME, highlight=False, no_color=no_color)


def print_disclaimer(console: Optional[Console] = None) -> None:
    """Print the legal disclaimer."""
    console = console or get_console_with_theme()
    console.print(Panel(DISCLAIMER, title="[header]WARNING[/header]",
                        border_style="border"))
