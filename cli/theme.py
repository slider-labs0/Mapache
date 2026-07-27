"""
theme.py — Mapache's visual identity for the CLI (pure, dependency-free).

Everything here is a plain string/function so it is unit-testable without a TTY
and works whether or not `rich`/`prompt_toolkit` are installed. Colour is applied
with bare ANSI escapes and is stripped automatically when the output isn't a
terminal (pipes, the smoke harness, CI).
"""

from __future__ import annotations

import os
import re
import sys

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# --------------------------------------------------------------------------- #
# ANSI helpers (no dependency on rich)
# --------------------------------------------------------------------------- #

_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "grey": "\033[38;5;245m", "dgrey": "\033[38;5;240m", "black": "\033[38;5;236m",
    "cyan": "\033[38;5;44m", "teal": "\033[38;5;37m", "white": "\033[97m",
    "amber": "\033[38;5;214m", "green": "\033[38;5;42m",
    # Agent-routing accents (recon/initial-access/post-exploitation + more).
    "red": "\033[38;5;203m", "magenta": "\033[38;5;170m",
    "blue": "\033[38;5;39m", "yellow": "\033[38;5;221m",
    # Lavender pair pulled from the mascot's own palette (its slate-purple body
    # ~rgb(46,43,58), brightened) so the wordmark + tagline read as one piece.
    "lav": "\033[38;2;176;165;222m", "lavdim": "\033[38;2;122;114;152m",
}


def supports_color(stream: object = None) -> bool:
    """True when it's safe to emit ANSI: a real TTY, not NO_COLOR, not dumb."""
    stream = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def paint(text: str, *styles: str, color: bool = True) -> str:
    if not color or not styles:
        return text
    prefix = "".join(_ANSI.get(s, "") for s in styles)
    return f"{prefix}{text}{_ANSI['reset']}"


# --------------------------------------------------------------------------- #
# Pixel logo — a masked trash-panda + block wordmark
# --------------------------------------------------------------------------- #

# Kept as an art grid; the raccoon's mask (the eye band) is coloured darker than
# the body so the face reads even in a monochrome terminal via shape alone.
_RACCOON = r"""
   ▟█▙▁▁▁▁▁▁▁▁▁▁▟█▙
  ▟███████████████████▙
 ▐████░░░░░░░░░░░░░████▌
 ▐██░░▟█▙░░░░░░▟█▙░░██▌
 ▐██░░███░░██░░███░░██▌
 ▐████░▀▀░▟██▙░▀▀░████▌
  ▜███████▝▀▀▘███████▛
   ▜███████████████▛
     ▀▀▘        ▝▀▀
"""

_WORDMARK = r"""
 █▀▄▀█ ▄▀█ █▀█ ▄▀█ █▀▀ █ █ █▀▀
 █ ▀ █ █▀█ █▀▀ █▀█ █▄▄ █▀█ ██▄
"""

TAGLINE = "autonomous offensive-security agent"

# Truecolor pixel mascot — a raster raccoon shipped as an ANSI asset next to this
# module (24-bit fg/bg half-blocks). Loaded once; the file stores ESC as a literal
# "\e" so it's easy to edit, and we swap it for a real escape here.
def _load_mascot() -> str:
    try:
        path = os.path.join(os.path.dirname(__file__), "mascot.ans")
        with open(path, encoding="utf-8") as fh:
            return fh.read().replace("\\e", "\x1b")
    except Exception:
        return ""


_MASCOT = _load_mascot()


def _visible(line: str) -> str:
    """A line with its ANSI escapes stripped — used to test emptiness/width."""
    return _ANSI_RE.sub("", line)


def _trim_blank_edges(text: str) -> list[str]:
    """Drop leading/trailing lines that render blank (ignoring ANSI + spaces)."""
    lines = text.strip("\n").splitlines()
    while lines and not _visible(lines[0]).strip():
        lines.pop(0)
    while lines and not _visible(lines[-1]).strip():
        lines.pop()
    return lines


def _wordmark_lines(color: bool, indent: int) -> list[str]:
    pad = " " * max(0, indent)
    return [pad + paint(ln, "lav", "bold", color=color)
            for ln in _WORDMARK.strip("\n").splitlines()]

# ASCII fallback for consoles whose encoding can't render the block art
# (e.g. a Windows cp1252 terminal without PYTHONUTF8). Never crashes startup.
_ASCII_LOGO = r"""
    .-"-.  .-"-.
   / .-. \/ .-. \      __  __   _   ___  _   ___ _  _ ___
   | (o ) ( o) |      |  \/  | /_\ | _ \/_\ / __| || | __|
    \  '-..-'  /      | |\/| |/ _ \|  _/ _ \ (__| __ | _|
     '-.____.-'       |_|  |_/_/ \_\_|/_/ \_\___|_||_|___|   MAPACHE
"""


def _can_encode(text: str) -> bool:
    """Whether the active stdout encoding can render the art (else use ASCII)."""
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        text.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def render_logo(color: bool = True, unicode: bool | None = None) -> str:
    """The full startup logo: masked raccoon over the block wordmark + tagline.

    Falls back to an ASCII version when the terminal encoding can't render the
    block characters (auto-detected unless `unicode` is forced)."""
    if unicode is None:
        unicode = _can_encode(_RACCOON + _WORDMARK)
    if not unicode:
        return paint(_ASCII_LOGO.strip("\n"), "lav", color=color) + \
            "\n" + paint(f"   {TAGLINE}", "lavdim", color=color)

    # Preferred: the truecolor pixel mascot (only meaningful with colour on a TTY,
    # and only if its ANSI asset loaded). Wordmark is centred under the raccoon.
    if color and _MASCOT and _can_encode(_MASCOT):
        art = _trim_blank_edges(_MASCOT)
        art_w = max((len(_visible(ln)) for ln in art), default=0)
        wm_w = max((len(l) for l in _WORDMARK.strip("\n").splitlines()), default=0)
        wm = _wordmark_lines(color, indent=(art_w - wm_w) // 2)
        tag = paint(TAGLINE.center(art_w), "lavdim", color=color)
        return "\n".join([*art, "", *wm, tag])

    lines: list[str] = []
    for ln in _RACCOON.strip("\n").splitlines():
        # Colour the mask band (the two eye rows) darker than the body.
        style = "grey"
        if "▟█▙" in ln and "░" in ln:  # eye row
            style = "dgrey"
        lines.append(paint(ln, style, color=color))
    lines.append("")
    lines.extend(_wordmark_lines(color, indent=0))
    lines.append(paint(f"   {TAGLINE}", "lavdim", color=color))
    return "\n".join(lines)


def render_banner(version: str, mode: str = "Attack Mode", color: bool = True,
                  unicode: bool | None = None) -> str:
    """Logo + a compact version/mode line for CLI startup."""
    sub = paint(f"   v{version}", "grey", color=color) + \
        paint(f"  ·  {mode}", "amber", color=color)
    return render_logo(color=color, unicode=unicode) + "\n" + sub + "\n"


# --------------------------------------------------------------------------- #
# "Thinking" words — shown while the agent works (raccoon-flavoured + hacker)
# --------------------------------------------------------------------------- #

THINKING_WORDS: list[str] = [
    "Tinkering", "Rummaging", "Foraging", "Prowling", "Sniffing around",
    "Picking locks", "Enumerating", "Scheming", "Pivoting", "Rooting around",
    "Casing the joint", "Fingerprinting", "Poking at ports", "Unraveling",
    "Conjuring payloads", "Dumpster-diving", "Prying", "Snooping",
]

# Braille spinner frames — smooth and monospace-safe; ASCII fallback for cp1252.
SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_ASCII_SPINNER = "|/-\\"


def thinking_word(i: int) -> str:
    """The i-th thinking word (wraps around the list)."""
    return THINKING_WORDS[i % len(THINKING_WORDS)]


def spinner_frame(i: int, *, unicode: bool = True) -> str:
    frames = SPINNER_FRAMES if unicode else _ASCII_SPINNER
    return frames[i % len(frames)]


def thinking_line(i: int, *, color: bool = True) -> str:
    """One rendered frame: spinner + a word that changes every few frames.

    The word advances slower than the spinner so it stays readable. Degrades to
    an ASCII spinner + '...' when the terminal encoding can't do braille."""
    uni = _can_encode(SPINNER_FRAMES)
    spin = spinner_frame(i, unicode=uni)
    word = thinking_word(i // 4)
    ell = "…" if _can_encode("…") else "..."
    return paint(f"  {spin} {word}{ell}", "amber", color=color)


def running_line(i: int, label: str, *, color: bool = True) -> str:
    """Live spinner line for an in-flight tool: '⠹ running <label>…'."""
    uni = _can_encode(SPINNER_FRAMES)
    spin = spinner_frame(i, unicode=uni)
    ell = "…" if _can_encode("…") else "..."
    return paint(f"  {spin} running {label}{ell}", "amber", color=color)


def format_duration(seconds: float) -> str:
    """Compact human duration: '820ms', '3s', '1m20s'."""
    if seconds < 1:
        return f"{int(round(seconds * 1000))}ms"
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m{secs:02d}s"


def step_done_line(label: str, seconds: float, *, error: bool = False,
                   color: bool = True) -> str:
    """Completion line shown when a tool finishes: '⏺ ran <label> · 3s'
    (or '✗ <label> failed · 3s'). Degrades to ASCII glyphs on a cp1252 console."""
    dur = format_duration(seconds)
    if error:
        glyph = "✗" if _can_encode("✗") else "x"
        return paint(f"  {glyph} {label} failed · {dur}", "amber", color=color)
    glyph = "⏺" if _can_encode("⏺") else "*"
    return paint(f"  {glyph} ran {label} · {dur}", "grey", color=color)


# --------------------------------------------------------------------------- #
# Transcript line styles (the full-screen TUI, modeled on the design mock)
# --------------------------------------------------------------------------- #

def _dot(style: str, color: bool) -> str:
    glyph = "●" if _can_encode("●") else "*"
    return paint(glyph, style, color=color)


def format_tokens(n: int) -> str:
    """Compact token count: '640', '46.3k', '1.2M'."""
    n = int(n or 0)
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k"
    return f"{n / 1_000_000:.1f}M"


def user_bar(text: str, *, color: bool = True) -> str:
    """The operator's message as a highlighted bar: '> …'."""
    body = f"> {text}"
    if not color:
        return body
    # Dark background bar with light text, spanning the line it's printed on.
    return f"\033[48;5;237m\033[38;5;253m {body} \033[0m"


def agent_line(text: str, *, dot: str = "green", color: bool = True) -> str:
    """A line of agent prose: '● …' with a coloured dot (the active agent's accent)."""
    return f"{_dot(dot, color)} {text}"


def tool_call_line(name: str, summary: str = "", *, accent: str = "teal",
                   color: bool = True) -> str:
    """A tool/skill invocation: '● Name (summary)'. The dot + name take the active
    agent's accent so you can see which specialist ran it; args stay dim."""
    line = f"{_dot(accent, color)} {paint(name, 'bold', accent, color=color)}"
    if summary:
        line += " " + paint(f"({summary})", "grey", color=color)
    return line


def shell_command_block(cmd: str, *, user: str = "root", host: str = "sandbox",
                        cwd: str = "~", accent: str = "green", color: bool = True) -> str:
    """A Kali-style two-line prompt over the command:
        ┌──(user💀host)-[cwd]
        └─# cmd
    The frame takes the active agent's accent (green = lead). Degrades to
    'user@host:cwd$ cmd' where box-drawing/emoji can't render."""
    if not _can_encode("┌─"):
        return paint(f"{user}@{host}:{cwd}$ ", accent, color=color) + \
            paint(cmd, "white", color=color)
    skull = "💀 " if _can_encode("💀") else "@"
    top = (paint("┌──(", accent, color=color)
           + paint(user, "red", color=color) + skull
           + paint(host, accent, color=color)
           + paint(")-[", accent, color=color)
           + paint(cwd, "cyan", color=color)
           + paint("]", accent, color=color))
    bottom = paint("└─# ", accent, color=color) + paint(cmd, "bold", "white", color=color)
    return top + "\n" + bottom


def handoff_line(title: str, *, accent: str = "cyan", back: bool = False,
                 detail: str = "", color: bool = True) -> str:
    """A routing banner when work moves to/from a specialist sub-agent:
        ● → Recon Operator        (delegating to it)
        ● ← Recon Operator         (control returns to the lead)"""
    if back:
        arrow = "←" if _can_encode("←") else "<-"
        body = f"{arrow} {title}"
    else:
        arrow = "→" if _can_encode("→") else "->"
        body = f"{arrow} {title}"
        if detail:
            body += "  " + detail
    return f"{_dot(accent, color)} {paint(body, 'bold', accent, color=color)}"


def shell_result_line(exit_code: int, *, empty: bool = False, color: bool = True) -> str:
    """The dim status under a shell command: '[Command completed… Exit code: N]'."""
    if empty:
        msg = f"[Command completed with no output. Exit code: {exit_code}]"
    else:
        msg = f"[Exit code: {exit_code}]"
    return paint(msg, "dgrey", color=color)


def status_line(word: str, elapsed_s: float, tokens: int = 0, *, color: bool = True) -> str:
    """The live bottom status: '● Hacking… (10s · ↑ 46.3k tokens)'."""
    ell = "…" if _can_encode("…") else "..."
    up = "↑" if _can_encode("↑") else "^"
    parts = [format_duration(elapsed_s)]
    if tokens:
        parts.append(f"{up} {format_tokens(tokens)} tokens")
    meta = paint("(" + " · ".join(parts) + ")", "grey", color=color)
    return f"  {_dot('amber', color)} {paint(word + ell, 'amber', color=color)} {meta}"
