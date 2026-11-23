"""Shared terminal presentation helpers.

Kept in one place so the CLI and the interactive console render the same
wordmark, colours and severity styles.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

BANNER = r"""
████████▄     ▄████████    ▄████████    ▄██████▄   ▄██████▄  ███▄▄▄▄      ▄████████ ▄██   ▄      ▄████████
███   ▀███   ███    ███   ███    ███   ███    ███ ███    ███ ███▀▀▀██▄   ███    ███ ███   ██▄   ███    ███
███    ███   ███    ███   ███    ███   ███    █▀  ███    ███ ███   ███   ███    █▀  ███▄▄▄███   ███    █▀
███    ███  ▄███▄▄▄▄██▀   ███    ███  ▄███        ███    ███ ███   ███  ▄███▄▄▄     ▀▀▀▀▀▀███  ▄███▄▄▄
███    ███ ▀▀███▀▀▀▀▀   ▀███████████ ▀▀███ ████▄  ███    ███ ███   ███ ▀▀███▀▀▀     ▄██   ███ ▀▀███▀▀▀
███    ███ ▀███████████   ███    ███   ███    ███ ███    ███ ███   ███   ███    █▄  ███   ███   ███    █▄
███   ▄███   ███    ███   ███    ███   ███    ███ ███    ███ ███   ███   ███    ███ ███   ███   ███    ███
████████▀    ███    ███   ███    █▀    ████████▀   ▀██████▀   ▀█   █▀    ██████████  ▀█████▀    ██████████
             ███    ███
"""

SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
    "unknown": "dim",
}

console = Console()


def banner(style: str = "bold red") -> None:
    """Print the wordmark without letting rich wrap or crop it."""
    width = max(len(line) for line in BANNER.splitlines())
    Console(width=width).print(Text(BANNER, style=style), no_wrap=True, crop=False)
    from . import __version__

    console.print(
        f"  [red]scope-aware recon[/red] [dim]v{__version__}[/dim] · "
        "[dim]only scan assets you are authorized to test[/dim]\n"
    )


def severity_markup(severity: str | None) -> str:
    severity = (severity or "info").lower()
    style = SEV_STYLE.get(severity, SEV_STYLE["unknown"])
    return f"[{style}]{severity}[/]"


def severity_counts(findings: list[dict]) -> str:
    """A compact `critical 1 · high 2 · ...` line (empty severities omitted)."""
    order = ("critical", "high", "medium", "low", "info", "unknown")
    counts: dict[str, int] = {}
    for finding in findings:
        key = (finding.get("severity") or "unknown").lower()
        counts[key] = counts.get(key, 0) + 1
    parts = [
        f"{severity_markup(sev)} {counts[sev]}"
        for sev in order
        if counts.get(sev)
    ]
    return "  ".join(parts) if parts else "[dim]none[/dim]"
