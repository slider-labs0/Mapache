"""
tui.py - full-screen chat UI (opt-in via `--tui`).

A prompt_toolkit `Application` that pins a bordered input box to the bottom of the
screen while agent output scrolls in a region above it - the layout the classic
line-based REPL can't give. It reuses the whole existing engine: the same
controller, command handlers, and turn loop feed their output here instead of
straight to stdout.

Design:
- `OutputModel` - pure transcript state (committed ANSI text + one mutable live
  status line). No prompt_toolkit, so it's unit-testable without a console.
- `TuiRenderer` - a `render.Renderer` whose methods append to the model instead of
  printing; the turn loop already talks to a Renderer, so nothing else changes.
- `RaccoonTUI` - the prompt_toolkit glue: an output `Window` (colour via `ANSI`,
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
# Pure transcript state (no prompt_toolkit - unit-testable)
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
# Right-hand agent dashboard (pure state - no prompt_toolkit, unit-testable)
# --------------------------------------------------------------------------- #


def _clip(text: str, n: int) -> str:
    text = (text or "").replace("\n", " ")
    return text if len(text) <= n else text[: max(0, n - 1)] + "…"


class DashboardModel:
    """State for the live agent HUD on the right of the screen: the active agent,
    the target/phase, the engagement budget (time + tokens), tool-call activity, and
    any running shells. Fed by `TuiRenderer` events and a periodic `tick`; `render`
    returns the stacked ANSI panels. No prompt_toolkit here so it's testable."""

    def __init__(self, on_change: Optional[Callable[[], None]] = None,
                 width: int = 36) -> None:
        self.width = width
        self._on_change = on_change
        self.agent = "lead"
        self.agent_accent = "green"
        self.agents = ["lead"]
        self.phase = ""
        self.target = ""
        self.ports: list[str] = []
        self.vulns = 0
        self.tool_count = 0
        self.last_tool = ""          # the most recent tool/command, shown in the Agent panel
        self.recent_tools: list[str] = []
        self.shells_running: "dict[int, str]" = {}
        self.shells_done = 0
        self.elapsed = 0.0
        self.tokens = 0
        self.max_tokens = 0
        self.max_seconds = 0.0
        self.spin = 0
        self._shell_seq = 0
        # Routing shown in the sidebar (moved off the front-and-center banner):
        # the strategy plus the per-role model map (planner/executor/verifier).
        self.strategy = ""
        self.role_models: "dict[str, str]" = {}
        # Live checklist of the agent's plan: list of (task, status) where status is
        # pending | in_progress | completed. Fed by the agent.todos event.
        self.checklist: "list[tuple[str, str]]" = []

    def _changed(self) -> None:
        if self._on_change is not None:
            self._on_change()

    # -- events (mirrored from the transcript renderer) ----------------- #

    def set_agent(self, name: str, accent: str, *, back: bool = False) -> None:
        if back:
            self.agent, self.agent_accent = "lead", "green"
        else:
            self.agent, self.agent_accent = name, accent
            if name not in self.agents:
                self.agents.append(name)
        self._changed()

    def add_tool(self, name: str) -> None:
        self.tool_count += 1
        self.last_tool = name
        self.recent_tools.append(name)
        self.recent_tools = self.recent_tools[-6:]
        self._changed()

    def shell_start(self, cmd: str) -> int:
        self._shell_seq += 1
        self.shells_running[self._shell_seq] = cmd
        self.tool_count += 1
        self.last_tool = _clip(cmd, 24)
        self._changed()
        return self._shell_seq

    def shell_end(self, sid: Optional[int] = None) -> None:
        if sid is None and self.shells_running:
            sid = next(iter(self.shells_running))
        if sid is not None and self.shells_running.pop(sid, None) is not None:
            self.shells_done += 1
            self._changed()

    def set_checklist(self, items: "list") -> None:
        """Update the live checklist from agent.todos. `items` is a list of
        {"task","status"} dicts (or (task,status) tuples)."""
        out: "list[tuple[str, str]]" = []
        for it in items or []:
            if isinstance(it, dict):
                task = str(it.get("task") or it.get("step") or "").strip()
                status = str(it.get("status") or "pending")
            else:
                task, status = str(it[0]).strip(), str(it[1])
            if task:
                out.append((task, status))
        self.checklist = out
        self._changed()

    def set_routing(self, strategy: str, role_models: "dict[str, str]") -> None:
        self.strategy = strategy or ""
        self.role_models = dict(role_models or {})
        self._changed()

    def set_state(self, state: Any) -> None:
        if state is None:
            return
        self.phase = getattr(state, "current_phase", "") or self.phase
        target = getattr(state, "target", "") or ""
        if target:
            self.target = target
        self.ports = [str(p) for p in (getattr(state, "open_ports", None) or [])]
        self.vulns = len(getattr(state, "vulnerabilities", None) or [])
        self._changed()

    def tick(self, elapsed: float, tokens: int, *, max_tokens: int = 0,
             max_seconds: float = 0.0) -> None:
        self.elapsed = elapsed
        self.tokens = tokens or 0
        if max_tokens:
            self.max_tokens = max_tokens
        if max_seconds:
            self.max_seconds = max_seconds
        self.spin = (self.spin + 1) % len(theme.SPINNER_FRAMES)
        self._changed()

    # -- rendering ------------------------------------------------------ #

    def render(self, *, color: bool = True) -> str:
        W = self.width

        def c(text: str, *styles: str) -> str:
            return theme.paint(text, *styles, color=color)

        def kv(key: str, val: str, vstyle: str = "lav") -> str:
            return f"{c(key.ljust(6), 'grey')} {c(val, vstyle)}"

        blocks: list[str] = []

        agent_lines = [kv("agent", _clip(self.agent, W - 10), self.agent_accent),
                       kv("phase", _clip(self.phase or "-", W - 10)),
                       kv("tool", _clip(self.last_tool or "-", W - 10), "teal")]
        if len(self.agents) > 1:
            agent_lines.append(kv("team", f"{len(self.agents)} operators"))
        blocks.append(theme.panel("Agent", agent_lines, color=color, width=W))

        # Live checklist: each planned step + its status (progress at a glance).
        if self.checklist:
            _mark = {"completed": ("[x]", "green"),
                     "in_progress": ("[~]", "amber"),
                     "pending": ("[ ]", "grey")}
            cl_lines: list[str] = []
            for task, status in self.checklist[:9]:
                sym, style = _mark.get(status, ("[ ]", "grey"))
                tstyle = "white" if status == "in_progress" else (
                    "grey" if status == "completed" else "lav")
                cl_lines.append(f"{c(sym, style)} {c(_clip(task, W - 6), tstyle)}")
            if len(self.checklist) > 9:
                cl_lines.append(c(f"  +{len(self.checklist) - 9} more", "grey"))
            done = sum(1 for _, s in self.checklist if s == "completed")
            title = f"Checklist ({done}/{len(self.checklist)})"
            blocks.append(theme.panel(title, cl_lines, color=color, width=W))

        # Routing: strategy + per-role models (moved here from the front banner).
        if self.strategy or self.role_models:
            mlines = []
            if self.strategy:
                mlines.append(kv("strat", _clip(self.strategy, W - 10), "blue"))
            _labels = {"planner": "plan", "executor": "exec", "verifier": "verify"}
            for role, label in _labels.items():
                if role in self.role_models:
                    mlines.append(kv(label, _clip(self.role_models[role], W - 10)))
            blocks.append(theme.panel("Models", mlines, color=color, width=W))

        tgt_lines = [kv("target", _clip(self.target or "-", W - 10), "blue"),
                     kv("ports", _clip(", ".join(self.ports[:6]) or "-", W - 10)),
                     kv("vulns", str(self.vulns), "amber" if self.vulns else "grey")]
        blocks.append(theme.panel("Target", tgt_lines, color=color, width=W))

        tok = theme.format_tokens(self.tokens)
        if self.max_tokens:
            tok += f" / {theme.format_tokens(self.max_tokens)}"
        dur = theme.format_duration(self.elapsed)
        if self.max_seconds:
            dur += f" / {theme.format_duration(self.max_seconds)}"
        blocks.append(theme.panel("Budget", [
            kv("time", dur), kv("tokens", tok),
            kv("tools", str(self.tool_count)),
        ], color=color, width=W))

        if self.shells_running:
            spin = theme.spinner_frame(self.spin)
            sh = [f"{c(spin, 'amber')} {c(_clip(cmd, W - 6), 'white')}"
                  for cmd in list(self.shells_running.values())[:3]]
            title = f"Running shells ({len(self.shells_running)})"
            blocks.append(theme.panel(title, sh, color=color, width=W))

        if self.recent_tools:
            blocks.append(theme.panel("Recent tools",
                          [c(_clip(t, W - 4), "lav") for t in self.recent_tools[-5:]],
                          color=color, width=W))

        return "\n".join(blocks)


# --------------------------------------------------------------------------- #
# Renderer that writes into the model (mirrors PlainRenderer's semantics)
# --------------------------------------------------------------------------- #


class TuiRenderer(Renderer):
    is_rich = False

    def __init__(self, model: OutputModel,
                 dashboard: "Optional[DashboardModel]" = None) -> None:
        self.model = model
        self.dashboard = dashboard   # right-hand HUD; None in the plain-transcript tests
        self._streamed = False
        self._last_shell_sid: Optional[int] = None
        # The active agent's accent colour - "green" for the lead, a per-specialist
        # colour while a sub-agent is running (set by the CLI on delegate start/end).
        self.accent = "green"

    # -- turn lifecycle ------------------------------------------------- #

    def start_turn(self) -> None:
        self._streamed = False
        self.model.commit("")

    def stream(self, text: str) -> None:
        if not self._streamed:
            # Agent prose gets a white dot (Claude-Code style); coloured dots are
            # reserved for tool/action lines and specialist handoffs.
            self.model.append(theme.agent_line("", dot="white", color=True))  # "● "
            self._streamed = True
        self.model.append(text)

    def agent_result(self, content, tools, iterations, error) -> None:
        if self._streamed:
            self.model.append("\n")
        elif content:
            self.model.commit(theme.agent_line(content, dot="white", color=True))
        if error and error != "max_iterations":
            self.model.commit(theme.paint(f"  x {error}", "amber", color=True))
        self.model.commit("")
        self._streamed = False

    # -- transcript pieces the CLI event handlers commit --------------- #

    def user_message(self, text: str) -> None:
        self.model.commit("")
        self.model.commit(theme.user_bar(text, color=True))
        self.model.commit("")

    def action(self, phrase: str) -> None:
        """Narrate the next step ('● Scanning ports with nmap') above the tool
        block, in the active agent's accent."""
        self._break_stream()
        self.model.commit(theme.agent_line(phrase, dot=self.accent, color=True))

    def tool_call(self, name: str, summary: str = "") -> None:
        self._break_stream()
        self.model.commit(theme.tool_call_line(name, summary, accent=self.accent,
                                               color=True))
        if self.dashboard:
            self.dashboard.add_tool(name)

    def shell_command(self, cmd: str, *, user: str, host: str, cwd: str) -> None:
        self._break_stream()
        self.model.commit(theme.shell_command_block(cmd, user=user, host=host,
                                                    cwd=cwd, accent=self.accent,
                                                    color=True))
        if self.dashboard:
            self._last_shell_sid = self.dashboard.shell_start(cmd)

    def shell_result(self, exit_code: int, *, empty: bool) -> None:
        self.model.commit(theme.shell_result_line(exit_code, empty=empty, color=True))
        if self.dashboard:
            self.dashboard.shell_end(self._last_shell_sid)
            self._last_shell_sid = None

    def handoff(self, title: str, accent: str, *, back: bool = False,
                detail: str = "") -> None:
        """Announce work routing to/from a specialist sub-agent."""
        self._break_stream()
        self.model.commit(theme.handoff_line(title, accent=accent, back=back,
                                             detail=detail, color=True))
        if self.dashboard:
            self.dashboard.set_agent(title, accent, back=back)

    def _break_stream(self) -> None:
        # After a tool line, the next agent prose should start a fresh '● ' bullet.
        if self._streamed:
            self.model.append("\n")
            self._streamed = False

    def phase_line(self, state) -> None:
        if self.dashboard:
            self.dashboard.set_state(state)
        from cli.render import _phase_summary
        summary = _phase_summary(state)
        if summary is not None:
            label, _c, detail = summary
            self.model.commit(f"  [{label}] {detail}")

    def steering(self, line: str) -> None:
        self.model.commit(f"  ↪ steering: {line}")

    def error(self, msg: str) -> None:
        self.model.commit(f"agent > x {msg}")

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
# stdout shim - routes stray print()s (banner, command handlers) into the model
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
        # it) - the banner shows the coloured mascot and status lines stay styled.
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
        self.dashboard = DashboardModel(on_change=self._invalidate)
        self.renderer = TuiRenderer(self.model, self.dashboard)
        self._turn_task: Optional[asyncio.Task] = None
        self._app = None
        self._output_win = None       # the transcript Window (set in _build)
        # Auto-follow: keep pinned to the newest line until the user scrolls up.
        # When paused, render at absolute line _scroll_pos (via get_vertical_scroll).
        self._follow = True
        self._scroll_pos = 0
        # Mouse mode: OFF by default so the TERMINAL owns the mouse - you can drag-select
        # and copy text immediately (the top ask). F2 flips it ON for in-app wheel
        # scrolling. (An alt-screen app can't do terminal-copy AND capture the wheel at
        # the same time, so this is a toggle; keyboard scroll works in either mode.)
        self._mouse_on = False
        self._build()

    def _scroll_by(self, lines: int) -> None:
        """Scroll by `lines` (negative = up). Reads the window's actual current scroll
        and adjusts from there, pausing auto-follow. get_vertical_scroll applies it."""
        w = self._output_win
        base = int(getattr(w, "vertical_scroll", 0)) if w is not None else self._scroll_pos
        self._scroll_pos = max(0, base + lines)
        self._follow = False
        self._invalidate()

    def _scroll_to(self, *, top: bool) -> None:
        if top:
            self._scroll_pos = 0
            self._follow = False
        else:
            self._follow = True   # jump to bottom and resume following
        self._invalidate()

    # -- prompt_toolkit construction ------------------------------------ #

    def _build(self) -> None:
        from prompt_toolkit.application import Application
        from prompt_toolkit.filters import Condition
        from prompt_toolkit.formatted_text import ANSI
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import HSplit, Layout, VSplit, Window, FloatContainer, Float
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.layout.dimension import Dimension
        from prompt_toolkit.layout.menus import CompletionsMenu
        from prompt_toolkit.mouse_events import MouseEventType
        from prompt_toolkit.styles import Style
        from prompt_toolkit.widgets import Frame, TextArea
        from cli.enhanced_input import make_completer

        def _output_text():
            return ANSI(self.model.render())

        def _dash_text():
            return ANSI(self.dashboard.render())

        # Scroll-aware transcript window. Scrolling is driven entirely through
        # get_vertical_scroll: while _follow is set we return a huge number (the window
        # clamps it to the bottom = auto-follow); once the user scrolls we return the
        # absolute _scroll_pos. show_cursor=False removes the phantom (0,0) cursor that
        # would otherwise force the view back. The mouse wheel routes into _scroll_by.
        _outer = self

        class _ScrollWindow(Window):
            def _mouse_handler(self, mouse_event):
                et = mouse_event.event_type
                if et == MouseEventType.SCROLL_UP:
                    _outer._scroll_by(-3)
                    return None
                if et == MouseEventType.SCROLL_DOWN:
                    _outer._scroll_by(3)
                    return None
                return super()._mouse_handler(mouse_event)

        def _vscroll(_win):
            return 10 ** 9 if self._follow else self._scroll_pos

        output = _ScrollWindow(
            content=FormattedTextControl(_output_text, focusable=False,
                                         show_cursor=False),
            get_vertical_scroll=_vscroll,
            wrap_lines=True,
            dont_extend_height=False,
        )
        self._output_win = output

        self.input_area = TextArea(
            height=1, multiline=False, wrap_lines=False, prompt="❯ ",
            accept_handler=self._accept,
            completer=make_completer(),      # live "/command" dropdown
            complete_while_typing=True,
        )
        input_frame = Frame(self.input_area, title="you")

        # A dim, always-visible key hint so the controls are discoverable (the mode
        # flips as F2 toggles it).
        def _hint_text():
            return ANSI(theme.paint(
                "  scroll: mouse wheel / PgUp-PgDn / arrows · drag to select+copy · "
                "/sidebar to resize · type / for commands · Ctrl+C quit",
                "dgrey", color=True))
        hint = Window(content=FormattedTextControl(_hint_text, focusable=False),
                      height=1, wrap_lines=False)

        # Left column: transcript over the input box. Right column: the live HUD,
        # its width adjustable with F3/F4.
        left = HSplit([
            output,
            Window(height=1, char="─"),
            input_frame,
            hint,
        ])
        dash = Window(
            content=FormattedTextControl(_dash_text, focusable=False),
            width=lambda: Dimension.exact(self.dashboard.width),
            wrap_lines=False, dont_extend_width=True,
        )
        root = VSplit([
            left,
            Window(width=Dimension.exact(1), char="│"),
            dash,
        ])
        # Float the slash-completion menu above everything.
        root = FloatContainer(content=root, floats=[
            Float(xcursor=True, ycursor=True,
                  content=CompletionsMenu(max_height=8, scroll_offset=1)),
        ])

        kb = KeyBindings()

        @kb.add("c-c")
        @kb.add("c-d")
        def _exit(event) -> None:
            event.app.exit()

        @kb.add("c-l")
        def _clear(event) -> None:
            self.model.clear()

        # Scroll the transcript by keyboard (works even in copy/mouse-off mode).
        # vertical_scroll grows downward, so up = negative. Up/Down are bound too:
        # a full-screen terminal that isn't capturing the mouse (our default, so copy
        # works) translates the MOUSE WHEEL into arrow keys - so this makes the wheel
        # scroll the transcript while drag-select/copy still works.
        @kb.add("pageup")
        def _pgup(event) -> None:
            self._scroll_by(-10)

        @kb.add("pagedown")
        def _pgdn(event) -> None:
            self._scroll_by(10)

        # Up/Down scroll only when the slash-completion menu is NOT open, so they still
        # navigate the dropdown when it is.
        _not_completing = Condition(
            lambda: self.input_area.buffer.complete_state is None)

        @kb.add("up", filter=_not_completing)
        def _up(event) -> None:
            self._scroll_by(-2)

        @kb.add("down", filter=_not_completing)
        def _down(event) -> None:
            self._scroll_by(2)

        @kb.add("c-home")
        def _top(event) -> None:
            self._scroll_to(top=True)

        @kb.add("c-end")
        def _bottom(event) -> None:
            self._scroll_to(top=False)

        # F2: toggle mouse capture. OFF = the terminal owns the mouse, so you can
        # drag-select and copy text (and use the terminal's own scrollback); ON =
        # in-app mouse-wheel scrolling. Keyboard scroll works in both.
        @kb.add("f2")
        def _toggle_mouse(event) -> None:
            self._mouse_on = not self._mouse_on
            self.model.commit(
                "· mouse " + ("ON (wheel scroll)" if self._mouse_on
                              else "OFF (drag to select / copy)"))

        # F3 / F4: shrink / grow the right-hand sidebar.
        @kb.add("f3")
        def _narrower(event) -> None:
            self.dashboard.width = max(20, self.dashboard.width - 4)
            self._invalidate()

        @kb.add("f4")
        def _wider(event) -> None:
            self.dashboard.width = min(70, self.dashboard.width + 4)
            self._invalidate()

        # Purple completion dropdown + scrollbar to match the panels.
        menu_style = Style.from_dict({
            "completion-menu": "bg:#241b38",
            "completion-menu.completion": "bg:#241b38 #d8ccff",
            "completion-menu.completion.current": "bg:#7c6bb0 #ffffff bold",
            "completion-menu.meta.completion": "bg:#241b38 #9a8fbf",
            "completion-menu.meta.completion.current": "bg:#8f7cc7 #ffffff",
            "scrollbar.background": "bg:#241b38",
            "scrollbar.button": "bg:#7c6bb0",
        })

        self._app = Application(
            layout=Layout(root, focused_element=self.input_area),
            key_bindings=kb,
            full_screen=True,
            style=menu_style,
            mouse_support=Condition(lambda: self._mouse_on),
        )

    def _invalidate(self) -> None:
        # Auto-follow is handled by the window's get_vertical_scroll hook (_vscroll).
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
            self.model.commit(f"agent > x {exc}")
        finally:
            self._invalidate()

    # -- run ------------------------------------------------------------ #

    async def run(self) -> None:
        await self._app.run_async()


def _enable_windows_vt() -> None:
    """Turn on ENABLE_VIRTUAL_TERMINAL_PROCESSING on the Windows stdout handle.

    In the VS Code integrated terminal (a ConPTY), prompt_toolkit otherwise selects
    its Win32 console output - which needs a classic console screen buffer and
    raises NoConsoleScreenBufferError there. With VT enabled, prompt_toolkit picks
    the VT-capable output and the full-screen app works. Best-effort + silent."""
    import sys as _sys
    if _sys.platform != "win32":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint()
        if k32.GetConsoleMode(handle, ctypes.byref(mode)):
            k32.SetConsoleMode(handle, mode.value | 0x0004)  # VT processing
    except Exception:
        pass


def build_tui(on_run, on_steer) -> Optional["RaccoonTUI"]:
    """Construct the TUI, or None if prompt_toolkit can't init a full-screen app
    here (mirrors enhanced_input.make_session's never-crash contract)."""
    _enable_windows_vt()
    try:
        return RaccoonTUI(on_run, on_steer)
    except Exception:
        return None
