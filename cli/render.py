"""
render.py — CLI presentation layer (feature B)

Splits *what* the REPL says from *how* it is drawn, behind a small `Renderer`
interface with two implementations:

- `PlainRenderer` — the line-printing behavior Mapache has always had. Used for
  pipes, dumb terminals, `--plain`, and any environment without `rich`. Its
  output is byte-for-byte the previous CLI output, so scripts and the smoke
  harness are unaffected.
- `RichRenderer` — panels, colour, a colour-coded phase banner, and styled
  streaming via `rich`. Selected only when `rich` is importable AND stdout is a
  real TTY AND `--plain` was not passed.

`rich` is an OPTIONAL dependency: `pip install rich` upgrades the UI; without it
the plain path is chosen automatically (no crash, no nag). Keeping the selection
+ phase-style logic pure makes it unit-testable without a TTY.
"""

from __future__ import annotations

import sys
from typing import Any, Optional

# Phase → (short label, colour). Drives the colour-coded phase banner; the label
# is what the plain path shows (colour is a no-op there).
PHASE_STYLES: dict[str, tuple[str, str]] = {
    "recon":        ("RECON",   "cyan"),
    "enumeration":  ("ENUM",    "blue"),
    "exploitation": ("EXPLOIT", "red"),
    "post":         ("POST",    "magenta"),
    "report":       ("REPORT",  "green"),
}
_DEFAULT_PHASE = ("PHASE", "white")


def phase_style(phase: str) -> tuple[str, str]:
    return PHASE_STYLES.get((phase or "").lower(), _DEFAULT_PHASE)


def _phase_summary(state: Any) -> Optional[tuple[str, str, str]]:
    """(label, colour, detail) for the phase line, or None if there's nothing yet."""
    if state is None:
        return None
    target = getattr(state, "target", None)
    ports = getattr(state, "open_ports", None) or []
    if not target and not ports:
        return None
    label, colour = phase_style(getattr(state, "current_phase", ""))
    bits = []
    if target:
        bits.append(f"target={target}")
    if ports:
        shown = ", ".join(ports[:8])
        bits.append(f"ports={shown}")
    vulns = getattr(state, "vulnerabilities", None) or []
    if vulns:
        bits.append(f"vulns={len(vulns)}")
    return label, colour, "  ".join(bits)


def rich_available() -> bool:
    try:
        import rich  # noqa: F401
        return True
    except ImportError:
        return False


def make_renderer(plain: bool = False, *, force_rich: Optional[bool] = None) -> "Renderer":
    """Pick a renderer. Rich requires the package installed; with `force_rich`
    unset it also requires a non-`--plain` invocation on a TTY."""
    if not rich_available():
        return PlainRenderer()
    if force_rich is True:
        return RichRenderer()
    if plain or force_rich is False:
        return PlainRenderer()
    if not sys.stdout.isatty():
        return PlainRenderer()
    return RichRenderer()


# --------------------------------------------------------------------------- #
# Plain (default / fallback) — preserves the historical output exactly
# --------------------------------------------------------------------------- #


class Renderer:
    """Interface; PlainRenderer is the reference behavior."""

    is_rich = False


class PlainRenderer(Renderer):
    is_rich = False

    def __init__(self) -> None:
        self._streamed = False

    # -- turn lifecycle ------------------------------------------------- #

    def start_turn(self) -> None:
        self._streamed = False
        print()

    def stream(self, text: str) -> None:
        if not self._streamed:
            print("agent > ", end="", flush=True)
            self._streamed = True
        print(text, end="", flush=True)

    def agent_result(self, content: str, tools: list[str], iterations: int,
                     error: Optional[str]) -> None:
        if self._streamed:
            print()  # finish the streamed line
        else:
            print(f"agent > {content}")
        if tools:
            print(f"        (used: {', '.join(tools)}, {iterations} steps)")
        if error and error != "max_iterations":
            print(f"        ✗ {error}")
        print()
        self._streamed = False

    # -- status --------------------------------------------------------- #

    def phase_line(self, state: Any) -> None:
        summary = _phase_summary(state)
        if summary is None:
            return
        label, _colour, detail = summary
        print(f"  [{label}] {detail}")

    def steering(self, line: str) -> None:
        print(f"\n  ↪ steering: {line}\n", flush=True)

    def error(self, msg: str) -> None:
        print(f"agent > ✗ {msg}")

    def info(self, msg: str) -> None:
        print(msg)


# --------------------------------------------------------------------------- #
# Rich — only constructed when `rich` is importable
# --------------------------------------------------------------------------- #


class RichRenderer(Renderer):
    is_rich = True

    def __init__(self) -> None:
        from rich.console import Console
        self.console = Console()
        self._streamed = False

    def start_turn(self) -> None:
        self._streamed = False
        self.console.print()

    def stream(self, text: str) -> None:
        if not self._streamed:
            self.console.print("[bold green]agent[/] ", end="")
            self._streamed = True
        # Stream raw text (no markup interpretation, so model output is verbatim).
        self.console.print(text, end="", markup=False, highlight=False, soft_wrap=True)

    def agent_result(self, content: str, tools: list[str], iterations: int,
                     error: Optional[str]) -> None:
        from rich.panel import Panel
        if self._streamed:
            self.console.print()
        elif content:
            self.console.print(Panel(content, title="agent", border_style="green",
                                     expand=False))
        if tools:
            self.console.print(
                f"   [dim]used {', '.join(tools)} · {iterations} steps[/]")
        if error and error != "max_iterations":
            self.console.print(f"   [red]✗ {error}[/]")
        self.console.print()
        self._streamed = False

    def phase_line(self, state: Any) -> None:
        summary = _phase_summary(state)
        if summary is None:
            return
        label, colour, detail = summary
        self.console.print(f"  [{colour} bold][{label}][/] [dim]{detail}[/]")

    def steering(self, line: str) -> None:
        self.console.print(f"\n  [yellow]↪ steering:[/] {line}\n")

    def error(self, msg: str) -> None:
        self.console.print(f"[bold green]agent[/] [red]✗ {msg}[/]")

    def info(self, msg: str) -> None:
        self.console.print(msg)
