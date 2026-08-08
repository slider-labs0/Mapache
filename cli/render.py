"""
render.py - CLI presentation layer (feature B)

Splits *what* the REPL says from *how* it is drawn, behind a small `Renderer`
interface with two implementations:

- `PlainRenderer` - the line-printing behavior Mapache has always had. Used for
  pipes, dumb terminals, `--plain`, and any environment without `rich`. Its
  output is byte-for-byte the previous CLI output, so scripts and the smoke
  harness are unaffected.
- `RichRenderer` - panels, colour, a colour-coded phase banner, and styled
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


# Todo status → (checkbox, colour) for the task-list rendering.
_TODO_STYLE = {
    "completed":   ("[x]", "green"),
    "in_progress": ("[~]", "yellow"),
    "pending":     ("[ ]", "white"),
}


def _todo_rows(todos: list) -> list[tuple[str, str, str]]:
    """(checkbox, colour, task) per todo, or [] if there are none."""
    rows = []
    for t in todos or []:
        status = getattr(t, "status", "pending")
        box, colour = _TODO_STYLE.get(status, ("[ ]", "white"))
        rows.append((box, colour, getattr(t, "task", str(t))))
    return rows


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
# Plain (default / fallback) - preserves the historical output exactly
# --------------------------------------------------------------------------- #


class Renderer:
    """Interface; PlainRenderer is the reference behavior."""

    is_rich = False

    # -- "thinking" indicator (shared) ---------------------------------- #
    # A single self-overwriting status line via carriage return. The frame text
    # already carries its own ANSI colour (from cli.theme), so both renderers
    # write it raw and identically; it's a no-op off a TTY so pipes/tests stay
    # byte-for-byte clean.

    def thinking(self, frame: str) -> None:
        try:
            if sys.stdout.isatty():
                sys.stdout.write("\r\033[K" + frame)
                sys.stdout.flush()
        except Exception:
            pass

    def thinking_clear(self) -> None:
        try:
            if sys.stdout.isatty():
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
        except Exception:
            pass

    def action(self, phrase: str) -> None:
        """Narrate the agent's next step in plain language before a tool runs
        (e.g. 'Scanning ports with nmap'). No-op in the line-based renderers -
        the live spinner already carries the phrase there; the TUI overrides this
        to commit a narration line above the tool block."""

    def step_line(self, text: str) -> None:
        """Print a completed-step line, clearing the live spinner first so the line
        settles above the resuming spinner. The text already carries its own ANSI,
        so both renderers use this identically; prints plainly off a TTY."""
        try:
            if sys.stdout.isatty():
                sys.stdout.write("\r\033[K" + text + "\n")
            else:
                sys.stdout.write(text + "\n")
            sys.stdout.flush()
        except Exception:
            pass


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
            print(f"        x {error}")
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
        print(f"agent > x {msg}")

    def info(self, msg: str) -> None:
        print(msg)

    def task_list(self, todos: list) -> None:
        rows = _todo_rows(todos)
        if not rows:
            return
        done = sum(1 for t in todos if getattr(t, "status", "") == "completed")
        print(f"  Tasks ({done}/{len(rows)}):")
        for box, _colour, task in rows:
            print(f"    {box} {task}")


# --------------------------------------------------------------------------- #
# Rich - only constructed when `rich` is importable
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
            self.console.print(f"   [red]x {error}[/]")
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
        self.console.print(f"[bold green]agent[/] [red]x {msg}[/]")

    def info(self, msg: str) -> None:
        self.console.print(msg)

    def task_list(self, todos: list) -> None:
        rows = _todo_rows(todos)
        if not rows:
            return
        from rich.panel import Panel
        done = sum(1 for t in todos if getattr(t, "status", "") == "completed")
        body = "\n".join(f"[{colour}]{box}[/] {task}" for box, colour, task in rows)
        self.console.print(Panel(body, title=f"Task list ({done}/{len(rows)})",
                                 border_style="blue", expand=False))
