"""
theme.py - Mapache's visual identity for the CLI (pure, dependency-free).

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
# Pixel logo - a masked trash-panda + block wordmark
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

# A bigger wordmark (ANSI-Shadow block letters) for the startup banner - "logo and
# text larger". ~58 cols wide; wraps only on very narrow terminals, else reads big.
_WORDMARK_LARGE = r"""
███╗   ███╗ █████╗ ██████╗  █████╗  ██████╗██╗  ██╗███████╗
████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝
██╔████╔██║███████║██████╔╝███████║██║     ███████║█████╗
██║╚██╔╝██║██╔══██║██╔═══╝ ██╔══██║██║     ██╔══██║██╔══╝
██║ ╚═╝ ██║██║  ██║██║     ██║  ██║╚██████╗██║  ██║███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝
"""

TAGLINE = "autonomous offensive-security agent"

# Truecolor pixel mascot - a raster raccoon shipped as an ANSI asset next to this
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
    """A line with its ANSI escapes stripped - used to test emptiness/width."""
    return _ANSI_RE.sub("", line)


def _trim_blank_edges(text: str) -> list[str]:
    """Drop leading/trailing lines that render blank (ignoring ANSI + spaces)."""
    lines = text.strip("\n").splitlines()
    while lines and not _visible(lines[0]).strip():
        lines.pop(0)
    while lines and not _visible(lines[-1]).strip():
        lines.pop()
    return lines


def _wordmark_lines(color: bool, indent: int, large: bool = False) -> list[str]:
    pad = " " * max(0, indent)
    art = _WORDMARK_LARGE if large else _WORDMARK
    return [pad + paint(ln, "lav", "bold", color=color)
            for ln in art.strip("\n").splitlines()]

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


def render_logo(color: bool = True, unicode: bool | None = None,
                large: bool = False) -> str:
    """The full startup logo: masked raccoon over the block wordmark + tagline.

    `large=True` uses the big ANSI-Shadow wordmark (bigger logo + text). Falls back
    to an ASCII version when the terminal encoding can't render the block characters
    (auto-detected unless `unicode` is forced)."""
    wordmark = _WORDMARK_LARGE if large else _WORDMARK
    if unicode is None:
        unicode = _can_encode(_RACCOON + wordmark)
    if not unicode:
        return paint(_ASCII_LOGO.strip("\n"), "lav", color=color) + \
            "\n" + paint(f"   {TAGLINE}", "lavdim", color=color)

    wm_w = max((len(l) for l in wordmark.strip("\n").splitlines()), default=0)

    # Preferred: the truecolor pixel mascot (only meaningful with colour on a TTY,
    # and only if its ANSI asset loaded). Wordmark is centred under the raccoon.
    if color and _MASCOT and _can_encode(_MASCOT):
        art = _trim_blank_edges(_MASCOT)
        art_w = max((len(_visible(ln)) for ln in art), default=0)
        ref_w = max(art_w, wm_w)                       # centre both to the wider one
        wm = _wordmark_lines(color, indent=(ref_w - wm_w) // 2, large=large)
        art = [(" " * ((ref_w - art_w) // 2)) + ln for ln in art]
        tag = paint(TAGLINE.center(ref_w), "lavdim", color=color)
        return "\n".join([*art, "", *wm, tag])

    lines: list[str] = []
    for ln in _RACCOON.strip("\n").splitlines():
        # Colour the mask band (the two eye rows) darker than the body.
        style = "grey"
        if "▟█▙" in ln and "░" in ln:  # eye row
            style = "dgrey"
        lines.append(paint(ln, style, color=color))
    lines.append("")
    lines.extend(_wordmark_lines(color, indent=0, large=large))
    lines.append(paint(f"   {TAGLINE}", "lavdim", color=color))
    return "\n".join(lines)


def render_banner(version: str, mode: str = "Attack Mode", color: bool = True,
                  unicode: bool | None = None, large: bool = False) -> str:
    """Logo + a compact version/mode line for CLI startup."""
    sub = paint(f"   v{version}", "grey", color=color) + \
        paint(f"  ·  {mode}", "amber", color=color)
    return render_logo(color=color, unicode=unicode, large=large) + "\n" + sub + "\n"


def panel(title: str, lines: list[str], *, color: bool = True, accent: str = "lav",
          width: int | None = None) -> str:
    """A titled rounded panel - the hermes-style neat box:

        ╭─ Title ─────────────────╮
        │ line one                │
        │ line two                │
        ╰─────────────────────────╯

    The title rides in the top border. Inner width auto-fits the content (measured
    on *visible* text so colour escapes don't skew it) unless `width` (the full
    outer width) is given, which pads every row to a fixed size - what the two-column
    HUD needs so panels line up. ASCII corners on a console that can't do the glyphs."""
    uni = _can_encode("╭─╮│╰╯")
    tl, tr, bl, br, h, v = ("╭", "╮", "╰", "╯", "─", "│") if uni else ("+", "+", "+", "+", "-", "|")
    t = f" {title} " if title else ""
    content_w = max((len(_visible(ln)) for ln in lines), default=0)
    inner = max(content_w, len(t) + 1)          # room for the title segment
    if width is not None:
        inner = max(inner, width - 4)           # width = corners + 2 pad + inner
    if t:
        fill = max(0, inner + 1 - len(t))        # dashes after the title segment
        top = (paint(tl + h, accent, color=color)
               + paint(t, "bold", accent, color=color)
               + paint(h * fill + tr, accent, color=color))
    else:
        top = paint(tl + h * (inner + 2) + tr, accent, color=color)
    side = paint(v, accent, color=color)
    out = [top]
    for ln in lines:
        pad = " " * (inner - len(_visible(ln)))
        out.append(f"{side} {ln}{pad} {side}")
    out.append(paint(bl + h * (inner + 2) + br, accent, color=color))
    return "\n".join(out)


def box(lines: list[str], *, color: bool = True, accent: str = "lavdim") -> str:
    """Draw a rounded border around pre-rendered (possibly ANSI-coloured) lines.

    Width is measured on the *visible* text so embedded colour escapes don't throw
    the alignment off. Degrades to ASCII corners on a console that can't render the
    box-drawing glyphs (cp1252 without UTF-8)."""
    uni = _can_encode("╭─╮│╰╯")
    tl, tr, bl, br, h, v = ("╭", "╮", "╰", "╯", "─", "│") if uni else ("+", "+", "+", "+", "-", "|")
    width = max((len(_visible(ln)) for ln in lines), default=0)
    top = paint(tl + h * (width + 2) + tr, accent, color=color)
    bottom = paint(bl + h * (width + 2) + br, accent, color=color)
    side = paint(v, accent, color=color)
    out = [top]
    for ln in lines:
        pad = " " * (width - len(_visible(ln)))
        out.append(f"{side} {ln}{pad} {side}")
    out.append(bottom)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# "Thinking" words - shown while the agent works (raccoon-flavoured + hacker)
# --------------------------------------------------------------------------- #

THINKING_WORDS: list[str] = [
    "Tinkering", "Rummaging", "Foraging", "Prowling", "Sniffing around",
    "Picking locks", "Enumerating", "Scheming", "Pivoting", "Rooting around",
    "Casing the joint", "Fingerprinting", "Poking at ports", "Unraveling",
    "Conjuring payloads", "Dumpster-diving", "Prying", "Snooping",
]

# Thinking spinner: a few small circles rotating around a square (braille) cell - the
# lit dots orbit the cell so it reads as circles spinning in a box. Monospace-safe;
# ASCII fallback for a cp1252 console that can't render braille.
SPINNER_FRAMES = "⣾⣽⣻⢿⡿⣟⣯⣷"
_ASCII_SPINNER = "|/-\\"

# How many spinner frames pass before the thinking WORD changes. The ticker runs at
# ~0.2s per frame, so 10 means the word changes about every 2 seconds (the spinner
# still animates every frame). Larger = slower word cadence.
THINKING_WORD_EVERY = 10


# Gradient endpoints for the live "thinking" word - the mascot's lavender warming
# into a bright teal, so the word shimmers left-to-right like Claude Code's.
_GRAD_START = (176, 165, 222)  # lavender (mascot body, brightened)
_GRAD_END = (86, 204, 201)     # teal


def gradient(text: str, start: tuple[int, int, int] = _GRAD_START,
             end: tuple[int, int, int] = _GRAD_END, *, color: bool = True) -> str:
    """Colour `text` char-by-char, interpolating 24-bit RGB from `start` to `end`.

    Truecolor only (same assumption as the mascot banner); returns the text
    unchanged when colour is off. Whitespace keeps its slot but isn't painted."""
    if not color or not text:
        return text
    chars = list(text)
    n = max(1, len(chars) - 1)
    out: list[str] = []
    for i, ch in enumerate(chars):
        if ch == " ":
            out.append(ch)
            continue
        t = i / n
        r = int(round(start[0] + (end[0] - start[0]) * t))
        g = int(round(start[1] + (end[1] - start[1]) * t))
        b = int(round(start[2] + (end[2] - start[2]) * t))
        out.append(f"\033[38;2;{r};{g};{b}m{ch}")
    return "".join(out) + _ANSI["reset"]


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
    word = thinking_word(i // THINKING_WORD_EVERY)
    ell = "…" if _can_encode("…") else "..."
    return (paint(f"  {spin} ", "amber", color=color)
            + gradient(word, color=color)
            + paint(ell, "grey", color=color))


def running_line(i: int, label: str, *, color: bool = True) -> str:
    """Live spinner line for an in-flight tool: '⠹ running <label>…'."""
    uni = _can_encode(SPINNER_FRAMES)
    spin = spinner_frame(i, unicode=uni)
    ell = "…" if _can_encode("…") else "..."
    return paint(f"  {spin} running {label}{ell}", "amber", color=color)


def activity_line(i: int, phrase: str, *, color: bool = True) -> str:
    """Live spinner line narrating an in-flight action in plain language:
    '⠹ Scanning ports with nmap…' (see `action_phrase`)."""
    uni = _can_encode(SPINNER_FRAMES)
    spin = spinner_frame(i, unicode=uni)
    ell = "…" if _can_encode("…") else "..."
    return paint(f"  {spin} {phrase}{ell}", "amber", color=color)


# Underlying CLI tool (from kali_run's `tool` arg, or a bare shell command's first
# word) → the activity it represents, phrased so the agent narrates its intent
# before the tool runs.
_ACTIVITY_BY_TOOL = {
    "nmap": "Scanning ports with nmap",
    "masscan": "Scanning ports with masscan",
    "rustscan": "Scanning ports with rustscan",
    "gobuster": "Enumerating paths with gobuster",
    "feroxbuster": "Enumerating paths with feroxbuster",
    "dirb": "Enumerating paths with dirb",
    "dirbuster": "Enumerating paths with dirbuster",
    "ffuf": "Fuzzing endpoints with ffuf",
    "wfuzz": "Fuzzing endpoints with wfuzz",
    "nikto": "Scanning for web flaws with nikto",
    "whatweb": "Fingerprinting the web stack",
    "wpscan": "Scanning WordPress with wpscan",
    "sqlmap": "Testing for SQL injection",
    "hydra": "Brute-forcing credentials with hydra",
    "medusa": "Brute-forcing credentials with medusa",
    "john": "Cracking hashes with john",
    "hashcat": "Cracking hashes with hashcat",
    "enum4linux": "Enumerating SMB with enum4linux",
    "smbclient": "Talking to SMB with smbclient",
    "smbmap": "Mapping SMB shares",
    "crackmapexec": "Sweeping hosts with crackmapexec",
    "netexec": "Sweeping hosts with netexec",
    "msfconsole": "Driving Metasploit",
    "searchsploit": "Searching exploits with searchsploit",
    "curl": "Fetching a URL with curl",
    "wget": "Downloading with wget",
    "dig": "Resolving DNS with dig",
    "dnsrecon": "Enumerating DNS with dnsrecon",
    "whois": "Looking up WHOIS",
}

# Named agent tools → their activity, phrased the same way.
_ACTIVITY_BY_NAME = {
    "web_search": "Searching the web",
    "web_fetch": "Fetching a page",
    "http_request": "Sending an HTTP request",
    "cve_lookup": "Looking up CVEs",
    "msf_search": "Searching Metasploit modules",
    "kg_query": "Reviewing findings so far",
    "kg_add": "Recording a finding",
    "opplan_show": "Reviewing the plan",
    "opplan_add": "Updating the plan",
    "opplan_update": "Updating the plan",
    "file_read": "Reading a file",
    "file_write": "Writing a file",
    "file_edit": "Editing a file",
    "file_search": "Searching files",
    "file_list": "Listing files",
    "note": "Jotting a note",
    "vuln_research": "Starting the vuln-research pipeline",
    "create_tool": "Building a new tool",
    "synthesize_skill": "Writing a new skill",
    "delegate": "Handing off to a specialist",
    "delegate_parallel": "Fanning out to specialists",
}


def action_phrase(name: str, args: "dict | None" = None) -> str:
    """A short natural-language description of what a tool call is about to do -
    'Scanning ports with nmap', 'Searching the web', 'Reading a file' - used to
    narrate the agent's next step before the tool runs.

    `kali_run` and `shell` resolve to the underlying command (nmap, gobuster, …);
    everything else keys off the tool name, falling back to 'Running <name>'."""
    args = args or {}
    n = (name or "").strip()

    if n == "kali_run":
        tool = str(args.get("tool") or "").strip().lower()
        base = tool.split()[0].replace("\\", "/").split("/")[-1] if tool else ""
        return _ACTIVITY_BY_TOOL.get(base, f"Running {base}" if base else "Running a Kali tool")
    if n == "shell":
        cmd = str(args.get("cmd") or args.get("command") or "").strip()
        first = cmd.split()[0].replace("\\", "/").split("/")[-1] if cmd else ""
        low = first.lower()
        if low in _ACTIVITY_BY_TOOL:
            return _ACTIVITY_BY_TOOL[low]
        return f"Running `{first}`" if first else "Running a shell command"

    if n in _ACTIVITY_BY_NAME:
        return _ACTIVITY_BY_NAME[n]
    return f"Running {n.replace('_', ' ')}" if n else "Working"


def format_duration(seconds: float) -> str:
    """Compact human duration: '820ms', '3s', '1m20s'."""
    if seconds < 1:
        return f"{int(round(seconds * 1000))}ms"
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m{secs:02d}s"


def _elbow() -> str:
    """The tree branch connector for a nested detail/result line that hangs off the
    action above it (the '⎿' Claude-Code style, matching Mapache's own '└─' prompt
    block). Falls back to '└' then ASCII on a console that can't render it."""
    if _can_encode("⎿"):
        return "⎿"
    if _can_encode("└"):
        return "└"
    return "\\_"


def step_done_line(label: str, seconds: float, *, error: bool = False,
                   color: bool = True) -> str:
    """Completion line shown when a tool finishes, nested under its call with a branch
    connector: '⎿ ran <label> · 3s' (or '⎿ <label> failed · 3s'). Degrades to ASCII
    on a cp1252 console."""
    dur = format_duration(seconds)
    if error:
        return paint(f"  {_elbow()} {label} failed · {dur}", "amber", color=color)
    return paint(f"  {_elbow()} ran {label} · {dur}", "grey", color=color)


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
    """The operator's message: a dim-grey '> …' line (Claude-Code style - quiet
    prompt echo, no loud background bar)."""
    return paint(f"> {text}", "grey", color=color)


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
        ┌──(userhost)-[cwd]
        └─# cmd
    The frame takes the active agent's accent (green = lead). Degrades to
    'user@host:cwd$ cmd' where box-drawing/emoji can't render."""
    if not _can_encode("┌─"):
        return paint(f"{user}@{host}:{cwd}$ ", accent, color=color) + \
            paint(cmd, "white", color=color)
    skull = " " if _can_encode("") else "@"
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
    """The dim status under a shell command, nested with the branch connector:
    '⎿ [Command completed… Exit code: N]'."""
    if empty:
        msg = f"[Command completed with no output. Exit code: {exit_code}]"
    else:
        msg = f"[Exit code: {exit_code}]"
    return paint(f"  {_elbow()} {msg}", "dgrey", color=color)


def status_line(word: str, elapsed_s: float, tokens: int = 0, *, frame: int = 0,
                color: bool = True) -> str:
    """The live bottom status, Claude-Code style:
    '⣾ Hacking… (10s · ↑ 46.3k tokens · ctrl-c to interrupt)' - dim, unobtrusive.
    `frame` advances the spinner (small circles rotating in a square) so the leading
    glyph animates instead of sitting as a static dot."""
    ell = "…" if _can_encode("…") else "..."
    up = "↑" if _can_encode("↑") else "^"
    parts = [format_duration(elapsed_s)]
    if tokens:
        parts.append(f"{up} {format_tokens(tokens)} tokens")
    parts.append("ctrl-c to interrupt")
    meta = paint("(" + " · ".join(parts) + ")", "grey", color=color)
    grad = gradient(word, color=color) + paint(ell, "grey", color=color)
    spin = paint(spinner_frame(frame, unicode=_can_encode(SPINNER_FRAMES)), "amber", color=color)
    return f"  {spin} {grad} {meta}"
