"""
context_builder.py — Mapache context window assembler

Responsible for assembling the full prompt context sent to the model on each turn.
Handles: system prompt, conversation history, tool schemas, memory injection,
and token budget management.

The model never sees raw internal state — everything passes through here first.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from core.injection_shield import SHIELD_CLAUSE, wrap_untrusted

logger = logging.getLogger(__name__)

# Approximate token counts (conservative estimates)
AVG_CHARS_PER_TOKEN = 4
DEFAULT_MAX_TOKENS = 16384
SYSTEM_PROMPT_RESERVE = 1024
TOOL_SCHEMA_RESERVE = 2048


@dataclass
class Message:
    """A single message in the conversation history."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_call_id: Optional[str] = None
    tool_name: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_ollama(self) -> dict[str, Any]:
        """Serialize to Ollama message format."""
        msg: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id
        return msg

    def to_openai(self) -> dict[str, Any]:
        """Serialize to OpenAI-compatible message format."""
        msg: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id
        if self.tool_name:
            msg["name"] = self.tool_name
        return msg

    def token_estimate(self) -> int:
        return max(1, len(self.content) // AVG_CHARS_PER_TOKEN)


@dataclass
class ToolSchema:
    """JSON schema describing a tool the model can call."""

    name: str
    description: str
    parameters: dict[str, Any]

    def to_openai_function(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_ollama_tool(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_json_mode_description(self) -> str:
        """Fallback: describe the tool in plain text for JSON-mode prompting."""
        params = json.dumps(self.parameters, indent=2)
        return f"Tool: {self.name}\nDescription: {self.description}\nParameters:\n{params}"


class ContextBuilder:
    """
    Assembles the full context payload for a model call.

    Manages:
    - System prompt construction
    - Conversation history with rolling window
    - Tool schema injection (native function calling or JSON mode)
    - Memory snippet injection
    - Token budget enforcement
    """

    DEFAULT_SYSTEM_PROMPT = """You are Mapache, an autonomous AI agent with direct access to a \
Windows host system via registered tools.

RULES — follow these exactly, no exceptions:
- You MUST call a tool to answer any question about the system. Never describe what you would \
do — just do it.
- When asked about files, ALWAYS call the shell tool immediately with the appropriate command.
- When a tool returns output, print it EXACTLY as returned. Never use placeholders like \
%USERNAME%, 'username', '/path/to/directory', or any invented values.
- You are on Windows. Use Windows commands only: 'dir' not 'ls', 'type' not 'cat', \
'ipconfig' not 'ifconfig', 'tasklist' not 'ps', 'whoami' for username, 'cd' for directory.
- Never explain commands. Never show examples. Never say what you would do. Just do it.
- If you are unsure of a path or value, run a command to find out — do not guess or invent it.

You have full system access. Act on every request immediately using your tools."""

    def __init__(
        self,
        system_prompt: str | None = None,
        max_context_tokens: int = DEFAULT_MAX_TOKENS,
        use_function_calling: bool = True,
    ) -> None:
        self.system_prompt = system_prompt or self.DEFAULT_SYSTEM_PROMPT
        self.max_context_tokens = max_context_tokens
        self.use_function_calling = use_function_calling

        self._history: list[Message] = []
        self._tools: dict[str, ToolSchema] = {}
        self._memory_snippets: list[str] = []
        # User-editable persona (feature E, soul.md). Prepended to the system
        # prompt; refreshed by the controller each turn so edits hot-reload.
        self.persona: str = ""
        # Running summary of older turns folded away by compaction. Prepended
        # to the system prompt so continuity survives even after the raw
        # messages are dropped from the window.
        self._running_summary: str = ""
        # When set, only tools whose names are in this set are exposed to the
        # model. None means "expose all registered tools". Used for phase-based
        # subsetting to keep the function-calling payload small enough for
        # local models (avoids Ollama tool-schema overflow).
        self._active_tools: set[str] | None = None

    # ------------------------------------------------------------------ #
    # Tool registration
    # ------------------------------------------------------------------ #

    def register_tool(self, schema: ToolSchema) -> None:
        self._tools[schema.name] = schema
        logger.debug("Tool registered in context: %s", schema.name)

    def unregister_tool(self, name: str) -> None:
        self._tools.pop(name, None)

    def clear_tools(self) -> None:
        self._tools.clear()

    def set_active_tools(self, names: object | None) -> None:
        """
        Restrict which registered tools are exposed to the model.

        Pass an iterable of tool names to expose only those; pass None to
        expose all registered tools. Names not actually registered are
        ignored. If the resulting active set would be empty, the filter is
        treated as None (expose all) so the model is never left tool-less.
        """
        if names is None:
            self._active_tools = None
            return
        self._active_tools = {n for n in names if n in self._tools}

    def clear_active_tools(self) -> None:
        self._active_tools = None

    def _active_schemas(self) -> list[ToolSchema]:
        """Return the ToolSchema objects currently exposed to the model."""
        if not self._active_tools:
            return list(self._tools.values())
        active = [t for n, t in self._tools.items() if n in self._active_tools]
        return active or list(self._tools.values())

    @property
    def available_tools(self) -> list[str]:
        return list(self._tools.keys())

    def active_tool_names(self) -> list[str]:
        """Names of the tools currently exposed to the model (post-subsetting)."""
        return [s.name for s in self._active_schemas()]

    # ------------------------------------------------------------------ #
    # History management
    # ------------------------------------------------------------------ #

    def add_message(self, message: Message) -> None:
        self._history.append(message)

    def add_user_message(self, content: str) -> None:
        self.add_message(Message(role="user", content=content))

    def add_assistant_message(self, content: str) -> None:
        self.add_message(Message(role="assistant", content=content))

    def add_tool_result(self, tool_call_id: str, tool_name: str, result: str) -> None:
        """
        Record a tool result in history — exactly once.

        With native function calling the result is a `tool`-role message tied
        to its tool_call_id. In JSON mode the model has no tool role, so the
        result is delivered as a user-role observation instead. Either way it
        appears a single time: the model is expected to reason over the output
        and choose the next action, not echo it back as a final answer.
        """
        # Fence the result as untrusted data so a hostile target can't smuggle
        # instructions into context through a tool's output (see injection_shield).
        fenced = wrap_untrusted(tool_name, result)
        if self.use_function_calling:
            self.add_message(Message(
                role="tool",
                content=fenced,
                tool_call_id=tool_call_id,
                tool_name=tool_name,
            ))
        else:
            self.add_message(Message(
                role="user",
                content=(
                    f"[tool:{tool_name}] returned:\n\n{fenced}\n\n"
                    "Use this to decide the next step. Quote specific findings "
                    "(ports, versions, hashes, paths, flags) exactly as shown; "
                    "never invent values."
                ),
            ))



    def clear_history(self) -> None:
        self._history.clear()
        self._running_summary = ""

    # ------------------------------------------------------------------ #
    # Compaction
    #
    # When the raw history outgrows its token budget we summarize the oldest
    # messages into `_running_summary` (a model call driven by the controller)
    # and drop them, rather than silently discarding them as _trim_history
    # does. The controller asks `needs_compaction()`, takes the prefix from
    # `messages_to_compact()`, summarizes it, and calls `apply_compaction()`.
    # ------------------------------------------------------------------ #

    @property
    def running_summary(self) -> str:
        return self._running_summary

    def history_tokens(self) -> int:
        return sum(m.token_estimate() for m in self._history)

    def _history_budget(self) -> int:
        return (
            self.max_context_tokens
            - SYSTEM_PROMPT_RESERVE
            - (TOOL_SCHEMA_RESERVE if self._tools else 0)
        )

    def needs_compaction(self) -> bool:
        return self.history_tokens() > self._history_budget()

    def messages_to_compact(self, keep_fraction: float = 0.5) -> list[Message]:
        """
        Return the oldest messages that should be folded into the summary.

        A recent window worth roughly `keep_fraction` of the history budget is
        retained verbatim; everything older is returned for summarization. The
        split is advanced so the retained window never begins with a dangling
        tool-result message. Returns [] when nothing should be compacted.
        """
        if len(self._history) <= 2:
            return []

        keep_target = int(self._history_budget() * keep_fraction)
        kept = 0
        split = 0  # history[:split] gets compacted
        for i in range(len(self._history) - 1, -1, -1):
            tokens = self._history[i].token_estimate()
            # Keep at least one message; stop once the recent window is full.
            if kept + tokens > keep_target and (len(self._history) - i) > 1:
                split = i + 1
                break
            kept += tokens

        # Don't let the retained window start on a tool-result message whose
        # originating call is now gone — push such messages into the summary.
        while split < len(self._history) and self._history[split].role == "tool":
            split += 1

        return self._history[:split]

    def apply_compaction(self, summary: str, compacted_count: int) -> None:
        """Replace the oldest `compacted_count` messages with `summary`."""
        if compacted_count <= 0:
            return
        self._running_summary = summary.strip()
        self._history = self._history[compacted_count:]
        logger.debug(
            "Compacted %d messages into summary (%d chars); %d messages remain",
            compacted_count, len(self._running_summary), len(self._history),
        )

    # ------------------------------------------------------------------ #
    # Memory
    # ------------------------------------------------------------------ #

    def set_persona(self, persona: str) -> None:
        """Set the soul.md persona prepended to the system prompt (feature E)."""
        self.persona = (persona or "").strip()

    def inject_memory(self, snippets: list[str]) -> None:
        """Inject memory snippets to be prepended to the system prompt."""
        self._memory_snippets = snippets

    def clear_memory(self) -> None:
        self._memory_snippets.clear()

    # ------------------------------------------------------------------ #
    # Context assembly
    # ------------------------------------------------------------------ #

    def build(self, format: str = "ollama") -> dict[str, Any]:
        """
        Assemble the full context payload.

        Args:
            format: "ollama" | "openai"

        Returns:
            dict with keys: messages, tools (if function calling), system
        """
        system = self._build_system_prompt()
        history = self._trim_history()

        if format == "ollama":
            messages = self._build_ollama_messages(system, history)
            result: dict[str, Any] = {"messages": messages}
            if self.use_function_calling and self._tools:
                result["tools"] = [t.to_ollama_tool() for t in self._active_schemas()]
        else:
            messages = self._build_openai_messages(system, history)
            result = {"messages": messages}
            if self.use_function_calling and self._tools:
                result["tools"] = [t.to_openai_function() for t in self._active_schemas()]
                result["tool_choice"] = "auto"

        return result

    def build_json_mode(self) -> dict[str, Any]:
        """
        Build context for JSON mode fallback (no native function calling).
        Tool schemas are described in plain text within the system prompt.
        Model is instructed to respond with a JSON object.
        """
        tool_descriptions = "\n\n".join(
            t.to_json_mode_description() for t in self._active_schemas()
        )

        json_system = self.system_prompt
        if tool_descriptions:
            json_system += f"""

---
AVAILABLE TOOLS:
{tool_descriptions}

---
RESPONSE FORMAT:
You must respond with a JSON object. Use one of these structures:

To call a tool:
{{"type": "tool_call", "tool": "<tool_name>", "args": {{...}}}}

To call several INDEPENDENT tools at once (they run in parallel):
{{"type": "tool_calls", "calls": [{{"tool": "<name>", "args": {{...}}}}, {{"tool": "<name>", "args": {{...}}}}]}}

To give a final answer:
{{"type": "response", "content": "<your response>"}}

To plan a multi-step task (sets the TASK LIST and starts the first step):
{{"type": "plan", "todos": ["step 1", "step 2", ...], "first_tool": "<tool_name>", "first_args": {{...}}}}

To update progress without calling a tool (mark steps done):
{{"type": "todo_update", "completed": [1, 2]}}

TASK LIST rules:
- For any goal needing 3+ steps, FIRST emit a "plan" with the full list of todos.
- A "=== TASK LIST ===" block is shown to you each turn with [ ] pending,
  [~] in_progress, [x] done. Work the [~] item, then mark it complete.
- Mark steps complete with "todo_update" (by number) or by re-emitting "plan"
  with per-item status: {{"task": "step 1", "status": "completed"}}.
- Keep exactly one step in progress. Do not restate the goal as a single todo.
"""

        system = self._build_system_prompt(override=json_system)
        history = self._trim_history()
        messages = self._build_ollama_messages(system, history)

        return {"messages": messages}

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _build_system_prompt(self, override: str | None = None) -> str:
        base = override or self.system_prompt
        if self._running_summary:
            base = (
                f"CONVERSATION SO FAR (summary of earlier turns):\n"
                f"{self._running_summary}\n\n---\n{base}"
            )
        if self._memory_snippets:
            memory_block = "\n".join(f"- {s}" for s in self._memory_snippets)
            base = f"RELEVANT MEMORY:\n{memory_block}\n\n---\n{base}"
        # Persona (soul.md) frames who the agent is — sits at the very top.
        if self.persona:
            base = f"{self.persona}\n\n---\n{base}"
        # Injection shield: tool output is untrusted data, never instructions.
        # Appended last so it sits close to the model's most-recent-context focus
        # and is present regardless of which system_prompt the caller supplied.
        return f"{base}\n\n---\n{SHIELD_CLAUSE}"

    def _trim_history(self) -> list[Message]:
        """
        Trim history to fit within the token budget.

        A safety net under compaction: the controller normally summarizes
        overflow into the running summary, but if history still exceeds the
        budget (compaction disabled or a single huge message) we keep the most
        recent messages that fit so the model call never overflows.
        """
        budget = self._history_budget()

        # Walk backwards, accumulate until budget exceeded
        kept: list[Message] = []
        used = 0
        for msg in reversed(self._history):
            tokens = msg.token_estimate()
            if used + tokens > budget and kept:
                break
            kept.append(msg)
            used += tokens

        kept.reverse()
        if len(kept) < len(self._history):
            logger.debug(
                "Context trimmed: kept %d/%d messages (%d est. tokens)",
                len(kept), len(self._history), used,
            )
        return kept

    def _build_ollama_messages(self, system: str, history: list[Message]) -> list[dict]:
        messages = [{"role": "system", "content": system}]
        messages += [m.to_ollama() for m in history]
        return messages

    def _build_openai_messages(self, system: str, history: list[Message]) -> list[dict]:
        messages = [{"role": "system", "content": system}]
        messages += [m.to_openai() for m in history]
        return messages

    def token_usage_estimate(self) -> dict[str, int]:
        """Return a rough token budget breakdown for debugging."""
        history_tokens = sum(m.token_estimate() for m in self._history)
        system_tokens = len(self.system_prompt) // AVG_CHARS_PER_TOKEN
        tool_tokens = sum(
            len(json.dumps(t.to_openai_function())) // AVG_CHARS_PER_TOKEN
            for t in self._active_schemas()
        )
        return {
            "system": system_tokens,
            "history": history_tokens,
            "tools": tool_tokens,
            "total_estimate": system_tokens + history_tokens + tool_tokens,
            "budget": self.max_context_tokens,
            "remaining": self.max_context_tokens - system_tokens - history_tokens - tool_tokens,
        }
