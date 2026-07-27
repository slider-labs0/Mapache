"""
tui.py — full-screen chat UI (opt-in via `--tui`).

A prompt_toolkit `Application` that pins a bordered input box to the bottom of the
screen while agent output scrolls in a region above it — the layout the classic
line-based REPL can't give. It reuses the whole existing engine: the same
controller, command handlers, and turn loop feed their output here instead of
straight to stdout.

Design:
- `OutputModel` — pure transcript state (committed ANSI text + one mutable live
  status line). No prompt_toolkit, so it's unit-testable without a console.
- `TuiRenderer` — a `render.Renderer` whose methods append to the model instead of
  printing; the turn loop already talks to a Renderer, so nothing else changes.
- `RaccoonTUI` — the prompt_toolkit glue: an output `Window` (colour via `ANSI`,
  auto-scrolled to the bottom) over a bordered input `Frame`. Enter submits; while a
  turn runs, a submit steers it instead of starting a new one.

Everything degrades safely: if prompt_toolkit can't initialise a real full-screen
app (e.g. mintty), `build_tui` returns None and the caller keeps the classic CLI.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

from cli.render import Renderer
from cli import theme


# --------------------------------------------------------------------------- #
# Pure transcript state (no prompt_toolkit — unit-testable)
# --------------------------------------------------------------------------- #


class OutputModel:
    """The scrolling transcript: committed ANSI text plus one live status line.

    `commit`/`append` add permanent content; `set_status`/`clear_status` manage the
    single self-overwriting line at the very bottom (the spinner). `render()` is the
    full ANSI string the output window draws."""

    def __init__(self, on_change: Optional[Callable[[], None]] = None) -> None:
        self._buf: str = ""
        self._status: str = ""
        self._on_change = on_change

    def _changed(self) -> None:
        if self._on_change is not None:
            self._on_change()

    def append(self, text: str) -> None:
        """Append streamed text verbatim (no trailing newline forced)."""
        if text:
            self._buf += text
            self._changed()

    def commit(self, line: str) -> None:
        """Append a whole line (newline-terminated)."""
        self._buf += line + ("" if line.endswith("\n") else "\n")
        self._changed()

    def set_status(self, text: str) -> None:
        self._status = text
        self._changed()

    def clear_status(self) -> None:
        if self._status:
            self._status = ""
            self._changed()

    def clear(self) -> None:
        self._buf = ""
        self._status = ""
        self._changed()

    def render(self) -> str:
        """The full ANSI transcript, with the live status line last (if any)."""
        if not self._status:
            return self._buf
        sep = "" if (not self._buf or self._buf.endswith("\n")) else "\n"
        return f"{self._buf}{sep}{self._status}"


# --------------------------------------------------------------------------- #
# Renderer that writes into the model (mirrors PlainRenderer's semantics)
# --------------------------------------------------------------------------- #


class TuiRenderer(Renderer):
    is_rich = False

    def __init__(self, model: OutputModel) -> None:
        self.model = model
        self._streamed = False

    # -- turn lifecycle ------------------------------------------------- #

    def start_turn(self) -> None:
        self._streamed = False
        self.model.commit("")

    def stream(self, text: str) -> None:
        if not self._streamed:
            self.model.append("agent > ")
            self._streamed = True
        self.model.append(text)

    def agent_result(self, content, tools, iterations, error) -> None:
        if self._streamed:
            self.model.append("\n")
        else:
            self.model.commit(f"agent > {content}")
        if tools:
            self.model.commit(f"        (used: {', '.join(tools)}, {iterations} steps)")
        if error and error != "max_iterations":
            self.model.commit(f"        ✗ {error}")
        self.model.commit("")
        self._streamed = False

    def phase_line(self, state) -> None:
        from cli.render import _phase_summary
        summary = _phase_summary(state)
        if summary is not None:
            label, _c, detail = summary
            self.model.commit(f"  [{label}] {detail}")

    def steering(self, line: str) -> None:
        self.model.commit(f"  ↪ steering: {line}")

    def error(self, msg: str) -> None:
        self.model.commit(f"agent > ✗ {msg}")

    def info(self, msg: str) -> None:
        self.model.commit(msg)

    def task_list(self, todos) -> None:
        from cli.render import _todo_rows
        rows = _todo_rows(todos)
        if not rows:
            return
        done = sum(1 for t in todos if getattr(t, "status", "") == "completed")
        self.model.commit(f"  Tasks ({done}/{len(rows)}):")
        for box, _c, task in rows:
            self.model.commit(f"    {box} {task}")

    # -- live status (spinner + step lines) ----------------------------- #

    def thinking(self, frame: str) -> None:
        self.model.set_status(frame.lstrip("\r").replace("\033[K", ""))

    def thinking_clear(self) -> None:
        self.model.clear_status()

    def step_line(self, text: str) -> None:
        # A completed-step line settles into the transcript; the spinner (status)
        # keeps living below it.
        self.model.clear_status()
        self.model.commit(text)


# --------------------------------------------------------------------------- #
# stdout shim — routes stray print()s (banner, command handlers) into the model
# --------------------------------------------------------------------------- #


class _ModelStdout:
    """A minimal write-only stream that appends to the OutputModel, so the existing
    print()-based startup banner and command handlers show up in the TUI region
    instead of corrupting the full-screen display."""

    # A UTF-8 encoding so theme's _can_encode() picks the block-art / truecolor
    # mascot banner rather than the ASCII fallback.
    encoding = "utf-8"

    def __init__(self, model: OutputModel) -> None:
        self._model = model

    def write(self, text: str) -> int:
        if text:
            self._model.append(text)
        return len(text)

    def flush(self) -> None:  # pragma: no cover - nothing buffered
        pass

    def isatty(self) -> bool:
        # True so theme.supports_color() keeps ANSI on (the output region renders
        # it) — the banner shows the coloured mascot and status lines stay styled.
        # The spinner's \r paths are handled by TuiRenderer overrides, not here.
        return True


# --------------------------------------------------------------------------- #
# The full-screen application
# --------------------------------------------------------------------------- #

# Submit intents (pure decision, tested without a console).
SUBMIT_EMPTY = "empty"
SUBMIT_STEER = "steer"
SUBMIT_RUN = "run"


def classify_submit(text: str, *, turn_running: bool) -> str:
    """What a submitted line means: nothing, steer the running turn, or run anew."""
    if not text.strip():
        return SUBMIT_EMPTY
    return SUBMIT_STEER if turn_running else SUBMIT_RUN


class RaccoonTUI:
    """Full-screen chat layout: scrolling output over a bordered input box."""

    def __init__(
        self,
        on_run: Callable[[str], Awaitable[None]],
        on_steer: Callable[[str], None],
    ) -> None:
        self._on_run = on_run
        self._on_steer = on_steer
        self.model = OutputModel(on_change=self._invalidate)
        self.renderer = TuiRenderer(self.model)
        self._turn_task: Optional[asyncio.Task] = None
        self._app = None
        self._build()

    # -- prompt_toolkit construction ------------------------------------ #

    def _build(self) -> None:
        from prompt_toolkit.application import Application
        from prompt_toolkit.formatted_text import ANSI
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import HSplit, Layout, Window
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.layout.dimension import Dimension
        from prompt_toolkit.widgets import Frame, TextArea

        def _output_text():
            return ANSI(self.model.render())

        def _cursor_at_end():
            # Reporting a cursor on the last line keeps the Window scrolled to the
            # bottom as content grows.
            from prompt_toolkit.data_structures import Point
            return Point(x=0, y=self.model.render().count("\n"))

        output = Window(
            content=FormattedTextControl(_output_text, get_cursor_position=_cursor_at_end,
                                         focusable=False),
            wrap_lines=True,
            dont_extend_height=False,
        )

        self.input_area = TextArea(
            height=1, multiline=False, wrap_lines=False, prompt="❯ ",
            accept_handler=self._accept,
        )
        input_frame = Frame(self.input_area, title="you")

        root = HSplit([
            output,
            Window(height=1, char="─"),  # thin separator above the box
            input_frame,
        ])

        kb = KeyBindings()

        @kb.add("c-c")
        @kb.add("c-d")
        def _exit(event) -> None:
            event.app.exit()

        @kb.add("c-l")
        def _clear(event) -> None:
            self.model.clear()

        self._app = Application(
            layout=Layout(root, focused_element=self.input_area),
            key_bindings=kb,
            full_screen=True,
            mouse_support=True,
        )

    def _invalidate(self) -> None:
        if self._app is not None:
            try:
                self._app.invalidate()
            except Exception:
                pass

    # -- input handling ------------------------------------------------- #

    def _accept(self, buff) -> bool:
        text = buff.text
        # Clear the box for the next line (return False = don't keep the text).
        intent = classify_submit(text, turn_running=self._turn_running())
        if intent == SUBMIT_STEER:
            self._on_steer(text.strip())
        elif intent == SUBMIT_RUN:
            self._turn_task = asyncio.ensure_future(self._run_wrapper(text.strip()))
        return False

    def _turn_running(self) -> bool:
        return self._turn_task is not None and not self._turn_task.done()

    async def _run_wrapper(self, text: str) -> None:
        try:
            await self._on_run(text)
        except Exception as exc:  # never let a turn crash take down the UI
            self.model.commit(f"agent > ✗ {exc}")
        finally:
            self._invalidate()

    # -- run ------------------------------------------------------------ #

    async def run(self) -> None:
        await self._app.run_async()


def build_tui(on_run, on_steer) -> Optional["RaccoonTUI"]:
    """Construct the TUI, or None if prompt_toolkit can't init a full-screen app
    here (mirrors enhanced_input.make_session's never-crash contract)."""
    try:
        return RaccoonTUI(on_run, on_steer)
    except Exception:
        return None
