"""
enhanced_input.py — as-you-type slash-command completion for the REPL.

The completion *logic* (`complete_slash`, `suggest_commands`) is pure and
dependency-free, so it is unit-tested without a terminal and also powers the
no-`prompt_toolkit` fallback ("did you mean" after Enter). When `prompt_toolkit`
IS installed and stdin is a real TTY, `make_session()` returns a PromptSession
whose `SlashCompleter` shows a live dropdown, filtered per keystroke, plus
↑ history — everything the user asked for. Absent the package, the CLI keeps its
existing line-based reader untouched.
"""

from __future__ import annotations

import difflib
from typing import Optional

# Canonical slash-command registry: (command, one-line description). This is the
# single source the completer + "did you mean" suggestions read from; keep it in
# sync with HELP_TEXT in mapache_cli.py.
SLASH_COMMANDS: list[tuple[str, str]] = [
    ("/help", "Show all commands"),
    ("/tools", "List tools (optionally by tag)"),
    ("/curate", "Review/archive unused self-authored tools"),
    ("/restore", "Restore an archived self-authored tool"),
    ("/purge", "Permanently delete an archived tool"),
    ("/models", "Show model routing"),
    ("/pipeline", "Set strategy: single|pipeline|auto|hybrid"),
    ("/memory", "Memory stats / notes / search / targets"),
    ("/chain", "Show current attack state"),
    ("/operators", "List specialist sub-agents (delegation roster)"),
    ("/hosts", "Per-host attack states (multi-host delegation)"),
    ("/backend", "Show execution backend (local/ssh/docker)"),
    ("/hub", "Browse/install community skills"),
    ("/voice", "Voice I/O status / toggle"),
    ("/opsec", "Show hybrid OPSEC routing"),
    ("/scope", "Show Rules-of-Engagement scope"),
    ("/log", "Engagement-log summary (or export)"),
    ("/report", "Generate a structured pentest report"),
    ("/cve", "Ground services to CVEs (CVSS + exploits)"),
    ("/synthesize", "Save the attack chain as a reusable skill"),
    ("/history", "Show conversation history"),
    ("/clear", "Clear history and reset attack state"),
    ("/context", "Show project context"),
    ("/soul", "Show the editable persona (soul.md)"),
    ("/user", "Show the agent-maintained user profile"),
    ("/cwd", "Change working directory"),
    ("/confirm", "Toggle confirmation for dangerous ops"),
    ("/debug", "Toggle debug logging"),
    ("/quit", "Exit"),
    ("/exit", "Exit"),
]

# Second-level completions for commands that take a fixed sub-argument.
SUBCOMMANDS: dict[str, list[tuple[str, str]]] = {
    "/pipeline": [("single", ""), ("pipeline", ""), ("auto", ""), ("hybrid", "")],
    "/memory": [("notes", ""), ("search", ""), ("targets", "")],
    "/report": [("md", ""), ("html", ""), ("both", ""), ("sarif", ""),
                ("bounty", ""), ("all", "")],
    "/voice": [("on", ""), ("off", "")],
    "/confirm": [("on", ""), ("off", "")],
    "/debug": [("on", ""), ("off", "")],
    "/log": [("export", "")],
    "/soul": [("init", "")],
    "/hub": [("search", ""), ("install", "")],
}

_COMMAND_NAMES = [c for c, _ in SLASH_COMMANDS]


def complete_slash(text: str) -> list[tuple[str, str, int]]:
    """Completions for a partially-typed slash command.

    Returns (completion_text, meta, start_position) tuples, where start_position
    is the negative length of the fragment being replaced (prompt_toolkit's
    convention). Empty for anything that isn't a slash command."""
    if not text.startswith("/"):
        return []
    parts = text.split(" ")
    if len(parts) == 1:
        frag = parts[0]
        return [(cmd, desc, -len(frag))
                for cmd, desc in SLASH_COMMANDS if cmd.startswith(frag)]
    # Sub-argument completion for a recognised command.
    cmd, last = parts[0], parts[-1]
    return [(sub, desc, -len(last))
            for sub, desc in SUBCOMMANDS.get(cmd, []) if sub.startswith(last)]


def suggest_commands(text: str, n: int = 3) -> list[tuple[str, str]]:
    """Closest command matches for an unknown/partial slash command — used for
    the 'did you mean' hint (fallback mode and unknown-command errors)."""
    if not text.startswith("/"):
        return []
    frag = text.split(" ")[0]
    prefix = [(c, d) for c, d in SLASH_COMMANDS if c.startswith(frag)]
    if prefix:
        return prefix[:n]
    close = difflib.get_close_matches(frag, _COMMAND_NAMES, n=n, cutoff=0.4)
    by_name = dict(SLASH_COMMANDS)
    return [(c, by_name.get(c, "")) for c in close]


# --------------------------------------------------------------------------- #
# prompt_toolkit integration (optional)
# --------------------------------------------------------------------------- #


def ptk_available() -> bool:
    try:
        import prompt_toolkit  # noqa: F401
        return True
    except ImportError:
        return False


def make_completer():
    """A prompt_toolkit Completer that yields the slash-command dropdown, or None
    if the package is absent. Split out so it's testable without a console."""
    if not ptk_available():
        return None
    from prompt_toolkit.completion import Completer, Completion

    class SlashCompleter(Completer):
        def get_completions(self, document, complete_event):
            text = document.text_before_cursor
            for comp_text, meta, start in complete_slash(text):
                yield Completion(comp_text, start_position=start,
                                 display_meta=meta or "")

    return SlashCompleter()


def make_session(history_path: Optional[str] = None):
    """A PromptSession with the slash completer + history, or None if
    prompt_toolkit isn't available OR can't initialise here.

    PromptSession builds its terminal Application eagerly, which raises in a TTY
    that isn't a real console (e.g. Git Bash/mintty on Windows). Returning None on
    any failure makes the CLI fall back to its plain line reader — never crash."""
    if not ptk_available():
        return None
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory, InMemoryHistory
        history = FileHistory(history_path) if history_path else InMemoryHistory()
        return PromptSession(
            completer=make_completer(),
            complete_while_typing=True,   # the live, per-keystroke dropdown
            history=history,
        )
    except Exception:
        return None
