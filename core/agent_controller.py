"""
agent_controller.py — Mapache agent controller

Central orchestrator. Owns the main agent loop and wires together
all subsystems. Phase 7 version includes ConversationChain for
persistent attack state and context continuity across turns.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Callable, Optional
from uuid import uuid4

from .context_builder import ContextBuilder, Message, ToolSchema
from .conversation_chain import AttackState, ConversationChain
from .engagement_scope import EngagementScope
from .event_bus import Event, EventBus
from .operators import get_operator, operator_names
from .opsec_routing import OpsecPolicy
from .executor import Executor
from .logger import get_logger
from .project_context import build_project_context

logger = get_logger(__name__)

DANGEROUS_PATTERNS = [
    "rm ", "del ", "rmdir", "format", "drop table",
    "delete from", ":(){:|:&};:", "mkfs", "dd if=",
]

# Names of the built-in tools the model calls to spawn focused sub-agents.
DELEGATE_TOOL = "delegate"
DELEGATE_PARALLEL_TOOL = "delegate_parallel"

VERIFIER_SYSTEM_PROMPT = """You are a verification module for an offensive-security agent. \
Given the user's goal and the agent's final response, decide whether the response actually \
addresses the goal or whether the agent stopped prematurely, skipped a step, or made an \
unsupported claim.

Respond with ONLY a JSON object, no prose:
{"ok": true|false, "reason": "<short why>", "suggestion": "<if not ok, the single concrete \
next action the agent should take>"}

Mark ok=true if the response reasonably completes the goal or is correctly blocked waiting on \
the operator. Mark ok=false only when there is a clear, actionable next step the agent should \
have taken."""


class AgentMode(str, Enum):
    CHAT  = "chat"
    AGENT = "agent"
    PLAN  = "plan"


@dataclass
class AgentResponse:
    content: str
    session_id: str
    tool_calls_made: list[str] = field(default_factory=list)
    iterations: int = 0
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class ToolCallResult:
    tool_name: str
    tool_call_id: str
    output: str
    error: Optional[str] = None


class AgentController:
    """
    Core agent runtime.

    Wires together: event bus, context builder, planner,
    task manager, executor, conversation chain, model provider,
    and tool dispatcher.
    """

    MAX_ITERATIONS = 50
    # How many times per turn to feed a format error back and ask the model to
    # retry before giving up and treating its text as a final answer.
    MAX_REASKS = 2
    # Delegation depth at which the `delegate` tool is no longer offered, so a
    # sub-agent cannot spawn its own sub-agents (no recursion bomb). Depth 0 is
    # the top-level agent; with this set to 1 only it can delegate.
    MAX_DELEGATION_DEPTH = 1
    # Max concurrent operators a single delegate_parallel call may fan out to.
    MAX_FANOUT = 6

    def __init__(
        self,
        model_provider: Any,
        tool_dispatcher: Any = None,
        system_prompt: Optional[str] = None,
        mode: AgentMode = AgentMode.AGENT,
        use_function_calling: bool = True,
        max_context_tokens: int = 16384,
        working_dir: str = ".",
        confirm_dangerous: bool = False,
        confirm_callback: Optional[Callable[[str, dict], Any]] = None,
        enable_tool_subsetting: bool = True,
        enable_verifier: bool = False,
        verify_max_retries: int = 1,
        verifier_caller: Optional[Callable[[list[dict]], Any]] = None,
        enable_compaction: bool = True,
        enable_delegation: bool = True,
        delegation_depth: int = 0,
        scope: Optional[EngagementScope] = None,
        shared_state: Optional["AttackState"] = None,
        allow_state_reset: bool = True,
        bus: Optional[EventBus] = None,
        opsec_policy: Optional["OpsecPolicy"] = None,
        persona_provider: Optional[Callable[[], str]] = None,
        profile_provider: Optional[Callable[[], str]] = None,
    ) -> None:
        self.model = model_provider
        self.tool_dispatcher = tool_dispatcher
        self.mode = mode
        # Hybrid OPSEC routing (feature O). Decides whether a delegated operator
        # must be pinned to a local model even when cloud is allowed. The default
        # is a no-op policy (cloud disabled → nothing to pin); the CLI injects one
        # built from --allow-cloud. Children inherit the lead's policy.
        self.opsec = opsec_policy or OpsecPolicy()
        # User-editable persona (feature E). Called each turn to re-read soul.md
        # so edits hot-reload. None → no persona (backwards-compatible). Not
        # propagated to sub-agents — operators carry their own focused prompts.
        self.persona_provider = persona_provider
        # Agent-maintained user profile (feature F). Called each turn for a
        # compact summary of durable user facts, injected alongside the attack
        # state. None → no profile. Not propagated to sub-agents.
        self.profile_provider = profile_provider
        # Rules-of-Engagement guardrails (feature J). An absent/inactive scope
        # allows everything, so this is a no-op until an operator defines limits.
        self.scope = scope or EngagementScope()
        self.working_dir = working_dir
        self.confirm_dangerous = confirm_dangerous
        self.confirm_callback = confirm_callback
        self.enable_tool_subsetting = enable_tool_subsetting
        # When history outgrows the token budget, summarize the oldest turns
        # into a running summary instead of dropping them (preserves continuity
        # over long engagements). Only fires when actually over budget.
        self.enable_compaction = enable_compaction
        # Delegation: expose a `delegate` tool that spawns a focused sub-agent
        # for a bounded subtask and returns only its conclusion. Offered only
        # while below MAX_DELEGATION_DEPTH so sub-agents can't recurse forever.
        self.delegation_depth = delegation_depth
        self.enable_delegation = (
            enable_delegation and delegation_depth < self.MAX_DELEGATION_DEPTH
        )
        # Opt-in verifier: after the loop produces a final answer, a VERIFIER-
        # role model call judges whether it actually addresses the goal; if not
        # (and retries remain) the loop resumes with the verifier's suggestion.
        self.enable_verifier = enable_verifier
        self.verify_max_retries = verify_max_retries
        self.verifier_caller = verifier_caller

        # Core subsystems. A shared bus may be injected (a delegated sub-agent
        # reuses the lead's bus so its events reach the same engagement log).
        self.bus = bus or EventBus()
        self._owns_bus = bus is None
        self.context = ContextBuilder(
            system_prompt=system_prompt,
            max_context_tokens=max_context_tokens,
            use_function_calling=use_function_calling,
        )
        # Executor is retained only as a shell/tool utility (used by the CLI
        # `!cmd` shortcut and tool dispatch); it no longer drives a parallel
        # event-bus execution pipeline.
        self.executor = Executor(self.bus)
        self.chain = ConversationChain(
            shared_state=shared_state, allow_state_reset=allow_state_reset
        )

        # Wire subsystems
        self.executor.set_model_caller(self._call_model_raw)
        if tool_dispatcher:
            self.executor.set_tool_dispatcher(tool_dispatcher)

        # Expose the built-in delegate tool to the model when delegation is on.
        if self.enable_delegation:
            self.context.register_tool(ToolSchema(
                name=DELEGATE_TOOL,
                description=(
                    "Spawn a focused sub-agent to fully complete ONE bounded "
                    "subtask (e.g. 'enumerate the web service on port 80 and "
                    "report findings'), then return only its conclusion. Pass "
                    "`operator` to run the subtask as a specialist (a tighter "
                    "prompt + tools — e.g. web_operator for a web app, "
                    "iot_operator for an embedded device); omit it for a "
                    "generalist. The sub-agent shares the live attack state but "
                    "has its own scratch context. See /operators."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "task": {
                            "type": "string",
                            "description": "The complete, self-contained subtask for the sub-agent.",
                        },
                        "operator": {
                            "type": "string",
                            "enum": operator_names(),
                            "description": "Optional specialist to run the subtask as. "
                                           "Omit for a generalist sub-agent.",
                        },
                        "target": {
                            "type": "string",
                            "description": "Optional host/IP this subtask is against. If "
                                           "it differs from the current target, the "
                                           "sub-agent gets an isolated per-host attack "
                                           "state. Omit to use the shared blackboard.",
                        },
                    },
                    "required": ["task"],
                },
            ))
            self.context.register_tool(ToolSchema(
                name=DELEGATE_PARALLEL_TOOL,
                description=(
                    "Run SEVERAL operator subtasks at once — multiple angles on one "
                    "host, OR several hosts in parallel. Each entry is "
                    "{task, operator?, target?}. Give each host its own `target` to "
                    "run them against isolated per-host attack states; omit `target` "
                    "to share the current blackboard for multi-angle work."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "tasks": {
                            "type": "array",
                            "description": "Independent subtasks to run concurrently.",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "task": {"type": "string"},
                                    "operator": {"type": "string", "enum": operator_names()},
                                    "target": {"type": "string",
                                               "description": "Optional host/IP for a "
                                               "per-host isolated state."},
                                },
                                "required": ["task"],
                            },
                        },
                    },
                    "required": ["tasks"],
                },
            ))

        self._sessions: dict[str, dict[str, Any]] = {}
        # Per-host sub-states (feature P): when a delegated task targets a host
        # other than the lead's, it gets its own isolated AttackState here —
        # created once, reused — so concurrent multi-host delegations don't
        # collide on one blackboard and findings attribute to the right host.
        self._host_states: dict[str, AttackState] = {}
        # Only the bus owner registers the shared error handler, so a shared bus
        # doesn't accumulate a duplicate per delegated sub-agent.
        if self._owns_bus:
            self._register_handlers()

        # Mid-run steering inbox: a frontend (CLI, Telegram, Discord) can call
        # steer() while a turn is running to redirect it. Messages are drained
        # at the top of each loop iteration. Guarded by a lock so steer() is
        # safe to call from another thread.
        self._steer_lock = threading.Lock()
        self._steer_inbox: list[str] = []

        logger.info("AgentController initialized (mode=%s)", mode.value)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self, inject_project_context: bool = True) -> None:
        if inject_project_context:
            ctx = build_project_context(self.working_dir)
            if ctx:
                self.context.inject_memory([ctx])
                logger.info("Project context injected (%d chars)", len(ctx))

        await self.bus.emit("agent.start", {}, source="controller")
        logger.info("AgentController started")

    async def stop(self) -> None:
        await self.bus.emit("agent.stop", {}, source="controller")
        logger.info("AgentController stopped")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def run(
        self,
        user_input: str,
        session_id: Optional[str] = None,
        stream: bool = False,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> AgentResponse:
        session_id = session_id or self._new_session()
        logger.info("Turn start — session=%s input=%r", session_id, user_input[:80])

        # Notify conversation chain of new turn
        self.chain.on_turn_start(user_input)

        # Persona (feature E): re-read soul.md each turn so edits hot-reload.
        if self.persona_provider is not None:
            try:
                self.context.set_persona(self.persona_provider() or "")
            except Exception:
                pass

        # Inject the durable user profile (feature F) + current attack state.
        # Both are memory snippets; the profile carries cross-engagement facts,
        # the chain context the live per-engagement state.
        snippets: list[str] = []
        if self.profile_provider is not None:
            try:
                profile = self.profile_provider()
                if profile:
                    snippets.append(profile)
            except Exception:
                pass
        chain_context = self.chain.get_context_injection()
        if chain_context:
            snippets.append(chain_context)
        if snippets:
            self.context.inject_memory(snippets)

        self.context.add_user_message(user_input)
        response = await self._agent_loop(user_input, session_id, on_token=on_token)

        if response.content:
            self.context.add_assistant_message(response.content)

        # Notify chain of turn completion
        self.chain.on_turn_end(response.content)

        await self.bus.emit(
            "agent.turn.end",
            {
                "session_id": session_id,
                "response": response.content,
                "iterations": response.iterations,
                "tools_used": response.tool_calls_made,
            },
            source="controller",
            session_id=session_id,
        )

        return response

    async def stream(
        self,
        user_input: str,
        session_id: Optional[str] = None,
    ) -> AsyncIterator[str]:
        """
        Token-streaming view of a turn.

        Thin wrapper over `run()` so there is a single turn implementation: the
        full ReAct loop (todos, reask, verifier, multi-tool) runs exactly as in
        `run()`, and its streamed tokens are forwarded here via an `on_token`
        callback bridged through a queue.
        """
        queue: asyncio.Queue[Optional[str]] = asyncio.Queue()

        async def _produce() -> None:
            try:
                await self.run(
                    user_input,
                    session_id=session_id,
                    on_token=queue.put_nowait,
                )
            except Exception as exc:  # surface as a final token, never hang
                queue.put_nowait(f"\n[error: {exc}]")
            finally:
                queue.put_nowait(None)  # sentinel: stream finished

        task = asyncio.create_task(_produce())
        try:
            while True:
                token = await queue.get()
                if token is None:
                    break
                yield token
        finally:
            await task

    def register_tool(self, schema: ToolSchema) -> None:
        self.context.register_tool(schema)

    def unregister_tool(self, name: str) -> None:
        self.context.unregister_tool(name)

    def set_working_dir(self, path: str) -> None:
        self.working_dir = path

    # ------------------------------------------------------------------ #
    # Agent loop
    # ------------------------------------------------------------------ #

    def _refresh_active_tools(self) -> None:
        """
        Narrow the exposed tool schemas to the current attack phase.

        Keeps the function-calling payload small enough for local models
        (prevents the Ollama tool-schema overflow). Recomputed every loop
        iteration so the toolset widens as the phase advances (e.g. recon →
        enumeration once ports are found).
        """
        if not self.enable_tool_subsetting:
            return
        active = self.chain.active_tool_names(self.context.available_tools)
        self.context.set_active_tools(active)

    async def _agent_loop(
        self,
        user_input: str,
        session_id: str,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> AgentResponse:
        tools_used: list[str] = []
        iteration = 0
        verify_retries_left = self.verify_max_retries
        reasks_left = self.MAX_REASKS
        # Signatures of tool calls already run this turn, mapped to their
        # result, so an identical repeated call is short-circuited instead of
        # re-run (breaks the "fetch the same URL 5 times" loop).
        self._seen_calls: dict[str, str] = {}

        while iteration < self.MAX_ITERATIONS:
            iteration += 1
            self._refresh_active_tools()

            # Pull in any operator steering queued since the last step, so the
            # turn can be redirected mid-flight without restarting the session.
            await self._apply_steering(session_id)

            # Fold older turns into a running summary if we've outgrown the
            # token budget, so continuity survives a long engagement instead of
            # being hard-trimmed away.
            await self._maybe_compact(session_id)

            # Re-inject the live attack state + task list every iteration so
            # the model sees mid-turn progress (ports found, todos completed),
            # not just the snapshot taken at turn start. inject_memory replaces
            # the snippet list, so this is idempotent.
            refreshed = self.chain.get_context_injection()
            if refreshed:
                self.context.inject_memory([refreshed])

            if self.context.use_function_calling:
                # Native tool-calling: schemas go in the `tools` field.
                context_payload = self.context.build(format="ollama")
                model_kwargs: dict[str, Any] = {"tools": context_payload.get("tools")}
            else:
                # Model has no native tool-calling (e.g. deepseek-coder):
                # describe the tools in the prompt and force JSON output that
                # _parse_model_response can turn into tool calls.
                context_payload = self.context.build_json_mode()
                model_kwargs = {"json_mode": True}

            try:
                raw_response = await self._chat(
                    context_payload["messages"], model_kwargs, on_token
                )
            except Exception as exc:
                logger.error("Model call failed: %s", exc)
                return AgentResponse(
                    content=f"Model error: {exc}",
                    session_id=session_id,
                    error=str(exc),
                    iterations=iteration,
                )

            parsed = self._parse_model_response(raw_response)

            # Self-correction: the model produced structured output that we
            # could not turn into a valid action. Feed the error back and ask
            # for a clean retry rather than silently treating it as a final
            # answer (the failure mode behind the original plan-dispatch bug).
            # Bounded by MAX_REASKS; on exhaustion we fail open and return the
            # text so the turn always terminates.
            if parsed.get("type") == "malformed":
                if reasks_left > 0:
                    reasks_left -= 1
                    reason = parsed.get("reason", "it was not a valid action")
                    logger.info("Reasking model (%s); %d left", reason, reasks_left)
                    self.context.add_user_message(
                        f"Your last message could not be used ({reason}). "
                        "Reply with ONLY one JSON object, no prose, in one of "
                        'these forms: {"type":"tool_call","tool":"<name>",'
                        '"args":{...}} to act, or {"type":"response",'
                        '"content":"<final answer>"} when finished.'
                    )
                    await self.bus.emit(
                        "agent.reask",
                        {"reason": reason, "session_id": session_id},
                        source="controller",
                        session_id=session_id,
                    )
                    continue
                # Budget exhausted — accept the raw text as the final answer.
                parsed = {"type": "response", "content": parsed.get("content", "")}

            # Persist any plan the model supplied onto the conversation chain
            # so the task list survives across turns and is re-injected below.
            if parsed.get("todos"):
                self.chain.set_todos(parsed["todos"])

            # Progress-only update: revise statuses, no tool call, no final
            # answer. Re-loop so the model acts with the updated list in view
            # (re-injected at the top of the next iteration). Bounded by
            # MAX_ITERATIONS, so it cannot run away.
            if parsed.get("type") == "todo_update":
                for ref in parsed.get("completed") or []:
                    self.chain.update_todo(ref, "completed")
                continue

            if parsed.get("type") in ("tool_call", "tool_calls"):
                calls = parsed.get("calls") or [
                    {"tool": parsed["tool"], "args": parsed.get("args", {})}
                ]
                await self._execute_tool_calls(calls, session_id, tools_used)
                continue

            content = parsed.get("content") or parsed.get("text", "")
            if not content and isinstance(raw_response, str):
                content = raw_response

            # Empty final answer: the model ended the turn without acting and
            # without saying anything (observed with some local models on the
            # very first step). Treat it like a malformed reply — nudge the model
            # to either act or answer — rather than silently terminating the
            # engagement with a blank result. Bounded by the same reask budget.
            if not (content or "").strip():
                if reasks_left > 0:
                    reasks_left -= 1
                    logger.info("Empty response; nudging model; %d left", reasks_left)
                    self.context.add_user_message(
                        "Your last message was empty. If you are not finished, take "
                        "the next concrete step now by calling a tool: reply with "
                        'ONLY {"type":"tool_call","tool":"<name>","args":{...}}. '
                        'If you are truly done, reply with {"type":"response",'
                        '"content":"<your final answer>"} — never an empty message.'
                    )
                    await self.bus.emit(
                        "agent.reask",
                        {"reason": "empty response", "session_id": session_id},
                        source="controller",
                        session_id=session_id,
                    )
                    continue
                # Budget exhausted — fall through and return what we have.

            # Opt-in verifier: judge the final answer; on a failed verdict with
            # retries left, resume the loop with the verifier's suggestion.
            if (
                self.enable_verifier
                and self.mode == AgentMode.AGENT
                and content
                and verify_retries_left > 0
            ):
                verdict = await self._verify(user_input, content, tools_used)
                if not verdict.get("ok", True):
                    verify_retries_left -= 1
                    suggestion = verdict.get("suggestion") or "continue toward the goal"
                    reason = verdict.get("reason") or "answer may be incomplete"
                    logger.info("Verifier rejected answer: %s → %s", reason, suggestion)
                    self.context.add_user_message(
                        f"[verifier] Your answer may be incomplete: {reason}. "
                        f"Next step: {suggestion}. Continue — call a tool if needed."
                    )
                    await self.bus.emit(
                        "agent.verify.retry",
                        {"reason": reason, "suggestion": suggestion, "session_id": session_id},
                        source="controller",
                        session_id=session_id,
                    )
                    continue

            return AgentResponse(
                content=content,
                session_id=session_id,
                tool_calls_made=tools_used,
                iterations=iteration,
            )

        logger.warning("Max iterations (%d) reached", self.MAX_ITERATIONS)
        return AgentResponse(
            content="Reached maximum reasoning steps without a final answer.",
            session_id=session_id,
            tool_calls_made=tools_used,
            iterations=iteration,
            error="max_iterations",
        )

    # ------------------------------------------------------------------ #
    # Mid-run steering
    # ------------------------------------------------------------------ #

    def steer(self, text: str) -> None:
        """
        Queue an operator message to redirect the turn currently in progress.

        Thread-safe. The message is injected into the conversation before the
        next model call, so the agent can react without the session being
        restarted. A no-op if `text` is blank.
        """
        text = (text or "").strip()
        if not text:
            return
        with self._steer_lock:
            self._steer_inbox.append(text)

    def _drain_steering(self) -> list[str]:
        with self._steer_lock:
            if not self._steer_inbox:
                return []
            pending = self._steer_inbox
            self._steer_inbox = []
        return pending

    async def _apply_steering(self, session_id: str) -> None:
        """Inject any queued steering messages into the live context."""
        for msg in self._drain_steering():
            logger.info("Steering injected: %r", msg[:80])
            # Let a freshly typed target/rescan update the tracked attack state
            # without disturbing the in-progress turn's bookkeeping.
            self.chain.apply_input_signals(msg)
            self.context.add_user_message(f"[operator steering] {msg}")
            await self.bus.emit(
                "agent.steer",
                {"message": msg, "session_id": session_id},
                source="controller",
                session_id=session_id,
            )

    # ------------------------------------------------------------------ #
    # Context compaction
    # ------------------------------------------------------------------ #

    async def _maybe_compact(self, session_id: str) -> None:
        """
        Summarize the oldest history into a running summary when over budget.

        Fails open: any error leaves history untouched, and `_trim_history`
        still keeps the model call within budget by dropping the oldest
        messages — i.e. the pre-compaction behavior.
        """
        if not self.enable_compaction or not self.context.needs_compaction():
            return

        old = self.context.messages_to_compact()
        if len(old) < 2:
            return

        prev = self.context.running_summary
        transcript = "\n".join(
            f"{m.role}: {m.content}" for m in old if m.content
        )
        prompt = [
            {
                "role": "system",
                "content": (
                    "You compress the earlier part of an offensive-security "
                    "engagement transcript into a compact briefing. Preserve "
                    "durable facts EXACTLY: targets, open ports, service "
                    "versions, credentials, hashes, vulnerabilities, flags, "
                    "file paths, what was tried, and what is still pending. "
                    "Drop chatter. Output prose under 200 words, no preamble."
                ),
            },
            {
                "role": "user",
                "content": (
                    (f"Earlier summary to merge:\n{prev}\n\n" if prev else "")
                    + f"Transcript to compress:\n{transcript}"
                ),
            },
        ]

        try:
            raw = await self.model.chat(messages=prompt)
            summary = self._parse_model_response(raw).get("content", "").strip()
        except Exception as exc:
            logger.warning("Compaction failed (%s) — leaving history intact", exc)
            return

        if not summary:
            return

        # Hard cap so the summary can't itself blow the system-prompt reserve.
        summary = summary[:2000]
        self.context.apply_compaction(summary, len(old))
        await self.bus.emit(
            "agent.compact",
            {"compacted": len(old), "summary_chars": len(summary),
             "session_id": session_id},
            source="controller",
            session_id=session_id,
        )

    # ------------------------------------------------------------------ #
    # Model call (streaming-aware)
    # ------------------------------------------------------------------ #

    async def _chat(
        self,
        messages: list[dict[str, Any]],
        model_kwargs: dict[str, Any],
        on_token: Optional[Callable[[str], None]],
    ) -> Any:
        """
        Make one model call, streaming tokens to `on_token` when possible.

        Streaming is used only when a callback is given, the model exposes
        `chat_stream`, and we are in native tool-calling mode — JSON-mode
        models would otherwise stream raw protocol JSON to the user. The
        streamed pieces are reassembled into the same dict shape `chat`
        returns, so the rest of the loop (parse, todos, reask, verifier,
        multi-tool) is identical whether or not we streamed.
        """
        can_stream = (
            on_token is not None
            and self.context.use_function_calling
            and hasattr(self.model, "chat_stream")
        )
        if not can_stream:
            return await self.model.chat(messages=messages, **model_kwargs)

        text_parts: list[str] = []
        tool_call: Optional[dict[str, Any]] = None
        async for piece in self.model.chat_stream(
            messages=messages, tools=model_kwargs.get("tools")
        ):
            if isinstance(piece, dict) and piece.get("type") == "tool_call":
                tool_call = piece
                break
            token = str(piece)
            text_parts.append(token)
            try:
                on_token(token)
            except Exception:  # a display callback must never break the loop
                pass

        message: dict[str, Any] = {"content": "".join(text_parts)}
        if tool_call:
            message["tool_calls"] = [{
                "function": {
                    "name": tool_call.get("tool", ""),
                    "arguments": tool_call.get("args", {}),
                }
            }]
        return {"message": message}

    # ------------------------------------------------------------------ #
    # Response parsing
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalize_call(raw_call: Any) -> Optional[dict[str, Any]]:
        """Coerce one native or JSON tool call into {tool, args} or None."""
        if not isinstance(raw_call, dict):
            return None
        fn = raw_call.get("function", raw_call)
        name = fn.get("name") or fn.get("tool") or ""
        if not name:
            return None
        args = fn.get("arguments")
        if args is None:
            args = fn.get("args", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if not isinstance(args, dict):
            args = {}
        return {"tool": name, "args": args}

    def _parse_model_response(self, raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            tool_calls = raw.get("message", {}).get("tool_calls") or raw.get("tool_calls")
            if tool_calls:
                calls = [c for c in (self._normalize_call(tc) for tc in tool_calls) if c]
                if not calls:
                    # Native tool call(s) with no usable tool name — ask again.
                    return {"type": "malformed", "content": str(raw),
                            "reason": "tool call had no tool name"}
                if len(calls) == 1:
                    return {"type": "tool_call", **calls[0]}
                return {"type": "tool_calls", "calls": calls}

            content = raw.get("message", {}).get("content") or raw.get("content", "")
            raw = content

        if not isinstance(raw, str):
            return {"type": "response", "content": str(raw)}

        data = self._extract_json_object(raw)
        if data is None:
            # No JSON at all — a natural-language final answer.
            return {"type": "response", "content": raw}

        return self._interpret_json_response(data, raw)

    # Keys that let us infer the intended type when the model omits "type".
    def _interpret_json_response(self, data: dict, raw: str) -> dict[str, Any]:
        rtype = data.get("type")

        # Infer a missing/unknown type from the keys present — local models
        # frequently emit the right shape without the "type" tag.
        if rtype not in ("tool_call", "tool_calls", "plan", "todo_update", "response"):
            if isinstance(data.get("calls"), list):
                rtype = "tool_calls"
            elif data.get("tool"):
                rtype = "tool_call"
            elif data.get("first_tool") or data.get("steps") or data.get("todos"):
                rtype = "plan"
            elif "completed" in data:
                rtype = "todo_update"
            elif rtype is not None:
                # An explicit but unrecognized "type" with no usable keys means
                # the model tried to use the protocol and got it wrong — reask.
                return {"type": "malformed", "content": raw,
                        "reason": f"unknown response type {rtype!r}"}
            else:
                # No type tag and no protocol keys: this is just an answer that
                # happens to contain JSON. Treat it as a plain response so we
                # don't reask on incidental braces.
                return {"type": "response", "content": data.get("content", raw)}

        if rtype == "tool_calls":
            raw_calls = data.get("calls")
            if not isinstance(raw_calls, list):
                return {"type": "malformed", "content": raw,
                        "reason": "tool_calls missing a 'calls' list"}
            calls = [c for c in (self._normalize_call(rc) for rc in raw_calls) if c]
            if not calls:
                return {"type": "malformed", "content": raw,
                        "reason": "no valid calls in 'calls' list"}
            if len(calls) == 1:
                return {"type": "tool_call", **calls[0]}
            return {"type": "tool_calls", "calls": calls}

        if rtype == "tool_call":
            tool = data.get("tool") or ""
            if not tool:
                return {"type": "malformed", "content": raw,
                        "reason": "tool_call missing 'tool' name"}
            args = data.get("args")
            if not isinstance(args, dict):
                args = {}
            return {"type": "tool_call", "tool": tool, "args": args}

        if rtype == "plan":
            # A plan seeds/updates the persistent todo list and carries the
            # first concrete action in first_tool/first_args. Dispatch that
            # action instead of treating the plan text as a final answer — the
            # ReAct loop re-plans next turn after seeing the real result (one
            # tool per step). `todos` is surfaced so the loop can persist the
            # list on the conversation chain.
            todos = data.get("todos") or data.get("steps")
            first_tool = data.get("first_tool")
            if first_tool:
                args = data.get("first_args")
                if not isinstance(args, dict):
                    args = {}
                out = {"type": "tool_call", "tool": first_tool, "args": args}
                if todos:
                    out["todos"] = todos
                return out
            out = {"type": "response", "content": data.get("content", raw)}
            if todos:
                out["todos"] = todos
            return out

        if rtype == "todo_update":
            return {"type": "todo_update", "todos": data.get("todos"),
                    "completed": data.get("completed", [])}

        # rtype == "response"
        return {"type": "response", "content": data.get("content", raw)}

    @staticmethod
    def _extract_json_object(text: str) -> Optional[dict]:
        """
        Pull a single JSON object out of a model response.

        Handles the common local-model habits: a bare object, an object fenced
        in ```json ... ``` , or an object embedded in surrounding prose.
        Returns the parsed dict, or None if no JSON object is present.
        """
        stripped = text.strip()
        # Strip a leading ```json / ``` fence if present.
        if stripped.startswith("```"):
            stripped = stripped.split("```", 2)
            stripped = stripped[1] if len(stripped) > 1 else ""
            if stripped.startswith("json"):
                stripped = stripped[4:]
            stripped = stripped.strip().rstrip("`").strip()

        if not stripped or "{" not in stripped:
            return None

        # Fast path: the whole thing is one object.
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                return obj if isinstance(obj, dict) else None
            except json.JSONDecodeError:
                pass

        # Slow path: scan for the first balanced {...} block (string-aware).
        start = stripped.find("{")
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(stripped)):
            ch = stripped[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = stripped[start:i + 1]
                    try:
                        obj = json.loads(candidate)
                        return obj if isinstance(obj, dict) else None
                    except json.JSONDecodeError:
                        return None
        return None

        return {"type": "response", "content": str(raw)}

    # ------------------------------------------------------------------ #
    # Argument recovery
    # ------------------------------------------------------------------ #

    def _apply_arg_fallbacks(
        self, tool_name: str, tool_args: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Recover required arguments the model commonly omits.

        Small local models frequently call nmap_scan without a target even
        when one is clearly established for the engagement. Rather than fail
        the call, backfill it from the tracked attack state so recon proceeds.
        """
        if tool_name == "nmap_scan" and not tool_args.get("target"):
            fallback = self.chain.attack_state.target
            if fallback:
                tool_args["target"] = fallback
                logger.info(
                    "nmap_scan called without target — auto-filled from attack state: %s",
                    fallback,
                )
        return tool_args

    # ------------------------------------------------------------------ #
    # Tool dispatch
    # ------------------------------------------------------------------ #

    @staticmethod
    def _call_signature(tool_name: str, args: dict[str, Any]) -> str:
        try:
            arg_str = json.dumps(args, sort_keys=True, default=str)
        except Exception:
            arg_str = str(args)
        return f"{tool_name}|{arg_str}"

    async def _execute_tool_calls(
        self,
        calls: list[dict[str, Any]],
        session_id: str,
        tools_used: list[str],
    ) -> None:
        """
        Run one or more tool calls the model issued in a single turn.

        Dangerous-op confirmation is handled sequentially up front (it may
        prompt the user). The actual dispatches then run concurrently — the
        model chose to batch these, so they are treated as independent — while
        results are folded back into the conversation chain and context
        serially, in the model's stated order, to keep state updates
        deterministic.
        """
        seen = getattr(self, "_seen_calls", None)
        if seen is None:
            seen = self._seen_calls = {}

        approved: list[tuple[str, str, dict[str, Any]]] = []  # (id, name, args)
        for call in calls:
            tool_name = call["tool"]
            tool_args = self._apply_arg_fallbacks(tool_name, call.get("args", {}))
            tool_call_id = str(uuid4())[:8]

            # Rules-of-Engagement gate (feature J): refuse an out-of-scope or
            # forbidden action before it runs. No-op unless a scope is loaded.
            # Checked after arg-fallbacks so the backfilled target is seen too.
            decision = self.scope.check(
                tool_name, tool_args,
                fallback_target=self.chain.attack_state.target,
            )
            if not decision.allowed:
                logger.warning("RoE refused %s: %s", tool_name, decision.reason)
                self.context.add_tool_result(
                    tool_call_id, tool_name,
                    f"REFUSED by engagement scope: {decision.reason}.\n"
                    "This action was NOT executed. Do not retry it — choose an "
                    "in-scope target, or tell the operator the task is out of scope.",
                )
                await self.bus.emit(
                    "agent.scope_refused",
                    {"tool_name": tool_name, "reason": decision.reason,
                     "args": tool_args, "session_id": session_id},
                    source="controller", session_id=session_id,
                )
                continue

            # No-progress guard: an identical call already run this turn is not
            # re-dispatched. Hand back the prior result with a nudge to move on.
            sig = self._call_signature(tool_name, tool_args)
            if sig in seen:
                logger.info("Duplicate tool call suppressed: %s", tool_name)
                self.context.add_tool_result(
                    tool_call_id, tool_name,
                    f"You already called {tool_name} with these exact arguments "
                    f"this turn; its result was:\n{seen[sig]}\n"
                    "Do NOT repeat it. Use that result, try a different tool/args, "
                    "or give your final answer.",
                )
                await self.bus.emit(
                    "agent.duplicate_call",
                    {"tool_name": tool_name, "session_id": session_id},
                    source="controller", session_id=session_id,
                )
                continue

            if self.confirm_dangerous and self._is_dangerous(tool_name, tool_args):
                confirmed = await self._request_confirmation(tool_name, tool_args)
                if not confirmed:
                    self.context.add_tool_result(
                        tool_call_id, tool_name, "Operation cancelled by user."
                    )
                    continue

            logger.info("Tool call: %s(%s)", tool_name, tool_args)
            approved.append((tool_call_id, tool_name, tool_args))

        if not approved:
            return

        # Dispatch concurrently; preserve order when collecting results.
        results = await asyncio.gather(*(
            self._dispatch_tool(name, args, call_id, session_id)
            for call_id, name, args in approved
        ))

        for (tool_call_id, tool_name, _args), result in zip(approved, results):
            tools_used.append(tool_name)
            tool_output = result.output if not result.error else f"ERROR: {result.error}"
            # Snapshot findings so newly-discovered ones can be emitted as their
            # own timeline events (feature K's engagement log subscribes to these).
            before = self._finding_snapshot()
            self.chain.on_tool_result(tool_name, tool_output)
            await self._emit_new_findings(before, session_id)

            compressed = self.chain.get_compressed_tool_output(tool_name, tool_output)
            seen[self._call_signature(tool_name, _args)] = compressed
            self.context.add_tool_result(
                tool_call_id=tool_call_id,
                tool_name=tool_name,
                result=compressed,
            )

            await self.bus.emit(
                "task.result" if not result.error else "task.error",
                {
                    "task_id": tool_call_id,
                    "tool_name": tool_name,
                    "args": _args,
                    "output": result.output,
                    "error": result.error,
                    "session_id": session_id,
                },
                source="controller",
                session_id=session_id,
            )

    def _finding_snapshot(self) -> tuple[set, set, set, set]:
        st = self.chain.attack_state
        return (set(st.flags), set(st.credentials),
                set(st.vulnerabilities), set(st.open_ports))

    async def _emit_new_findings(
        self, before: tuple[set, set, set, set], session_id: str
    ) -> None:
        """Emit `agent.finding` for anything the last tool result newly revealed.

        Gives the engagement log (feature K) a timestamped record of *when* each
        flag/credential/vuln/port was discovered, which the attack-state snapshot
        alone can't convey.
        """
        st = self.chain.attack_state
        old_flags, old_creds, old_vulns, old_ports = before
        new: list[tuple[str, str]] = []
        new += [("flag", v) for v in st.flags if v not in old_flags]
        new += [("credential", v) for v in st.credentials if v not in old_creds]
        new += [("vulnerability", v) for v in st.vulnerabilities if v not in old_vulns]
        new += [("open_port", v) for v in st.open_ports if v not in old_ports]
        for kind, value in new:
            await self.bus.emit(
                "agent.finding",
                {"finding_type": kind, "value": value,
                 "target": st.target, "session_id": session_id},
                source="controller", session_id=session_id,
            )

    # ------------------------------------------------------------------ #
    # Sub-agent delegation
    # ------------------------------------------------------------------ #

    async def _run_subagent(self, args: dict[str, Any], session_id: str) -> str:
        """
        Spawn a focused child agent for one bounded subtask and return its
        conclusion. The child shares this agent's model, tool dispatcher, and the
        live attack-state blackboard, but runs its own ReAct loop in a separate
        context so the main thread stays clean.

        If `operator` names a specialist (feature P), the child gets that
        operator's focused system prompt and a small curated tool subset instead
        of the lead's generalist prompt + full toolset — the local-model win.
        """
        task = (args.get("task") or args.get("goal") or "").strip()
        if not task:
            return "[delegate] No task provided."
        target = args.get("target") or args.get("host")
        return await self._spawn_and_run(task, args.get("operator"), session_id,
                                         "sub", target=target)

    async def _run_parallel_subagents(self, args: dict[str, Any], session_id: str) -> str:
        """
        Run several operator subtasks concurrently (feature P). Tasks without a
        `target` share the lead's AttackState (several angles on the current
        host); tasks with a distinct `target` each get an isolated per-host
        sub-state, so a true multi-host sweep can run in parallel without the
        children colliding on one blackboard.

        On a single GPU the model calls serialize at the provider, so this is a
        correctness/orchestration win that turns into a wall-clock win once cloud
        routing (G) serves the calls concurrently. Fan-out is capped, and these
        children are at delegation depth 1 so none can fan out further.
        """
        raw_tasks = args.get("tasks") or []
        tasks: list[tuple[str, Optional[str], Optional[str]]] = []
        for item in raw_tasks:
            if isinstance(item, dict):
                t = (item.get("task") or item.get("goal") or "").strip()
                if t:
                    tasks.append((t, item.get("operator"),
                                  item.get("target") or item.get("host")))
            elif isinstance(item, str) and item.strip():
                tasks.append((item.strip(), None, None))
        if not tasks:
            return "[delegate_parallel] No tasks provided."
        if len(tasks) > self.MAX_FANOUT:
            logger.info("delegate_parallel: capping %d tasks to %d",
                        len(tasks), self.MAX_FANOUT)
            tasks = tasks[: self.MAX_FANOUT]

        results = await asyncio.gather(*(
            self._spawn_and_run(t, op, session_id, f"par{i}", target=tgt)
            for i, (t, op, tgt) in enumerate(tasks)
        ))
        joined = "\n\n".join(
            f"[{op or 'generalist'}{f' @ {tgt}' if tgt else ''}] {t}\n{res}"
            for (t, op, tgt), res in zip(tasks, results)
        )
        out = f"[delegate_parallel — {len(tasks)} operators]\n\n{joined}"
        host_summary = self._render_host_states()
        return f"{out}\n\n{host_summary}" if host_summary else out

    def _host_state_for(self, target: Optional[str]) -> tuple["AttackState", bool]:
        """Resolve which AttackState a delegated child should use.

        No target, or the lead's own host → the shared blackboard (multi-angle
        work). A different host → a dedicated per-host sub-state (created once,
        reused), isolating concurrent multi-host delegations. Returns
        (state, is_isolated).
        """
        lead = self.chain.attack_state
        host = (target or "").strip()
        if not host or host == (lead.target or ""):
            return lead, False
        state = self._host_states.get(host)
        if state is None:
            state = AttackState(target=host)
            self._host_states[host] = state
        return state, True

    def _render_host_states(self) -> str:
        """Compact roll-up of the per-host sub-states, for the lead to act on."""
        if not self._host_states:
            return ""
        lines = ["[per-host attack states]"]
        for host, st in self._host_states.items():
            lines.append(
                f"  {host}: ports={len(st.open_ports)} services={len(st.services)} "
                f"vulns={len(st.vulnerabilities)} creds={len(st.credentials)} "
                f"flags={len(st.flags)}")
        return "\n".join(lines)

    def host_states(self) -> dict[str, "AttackState"]:
        """The isolated per-host sub-states recorded by multi-host delegation."""
        return dict(self._host_states)

    async def _spawn_and_run(
        self, task: str, operator_name: Optional[str], session_id: str, suffix: str,
        target: Optional[str] = None,
    ) -> str:
        """Build one specialized (or generalist) child, run the task, return its
        conclusion. Shared by single and parallel delegation."""
        operator = get_operator(operator_name)

        # Per-host sub-state (feature P): a child targeting a different host gets
        # its own isolated AttackState; otherwise it shares the lead's blackboard.
        child_state, isolated = self._host_state_for(target)

        # Hybrid OPSEC routing (feature O): pin a sensitive operator — or any
        # delegation once credentials are captured — to a local model even when
        # the lead is allowed to route to cloud, so loot/creds never leave the
        # host. Falls back gracefully if the model provider can't pin local.
        opsec = self.opsec.decide(operator=operator, attack_state=child_state)
        child_model = self.model
        if opsec.pin_local and hasattr(self.model, "local_variant"):
            child_model = self.model.local_variant()
            logger.info("OPSEC: pinning %s to local — %s",
                        operator.name if operator else "generalist", opsec.reason)

        # Per-operator model routing (feature P): run the operator's loop under
        # the model role its work calls for — reasoning-heavy specialists as
        # PLANNER (the quality model), action specialists as EXECUTOR (the fast
        # one). Applied after the OPSEC pin, so it routes within the local models
        # when pinned. No-op for a generalist or a provider without role routing.
        if operator is not None and hasattr(child_model, "for_role"):
            child_model = child_model.for_role(operator.model_role)

        # An operator's toolset is already small and curated, so phase-based
        # subsetting (which keys off the shared phase) is turned off for it.
        child = AgentController(
            model_provider=child_model,
            tool_dispatcher=self.tool_dispatcher,
            system_prompt=operator.system_prompt if operator else self.context.system_prompt,
            mode=self.mode,
            use_function_calling=self.context.use_function_calling,
            max_context_tokens=self.context.max_context_tokens,
            working_dir=self.working_dir,
            confirm_dangerous=self.confirm_dangerous,
            confirm_callback=self.confirm_callback,
            enable_tool_subsetting=self.enable_tool_subsetting and operator is None,
            enable_verifier=False,            # keep sub-agents lean
            enable_compaction=self.enable_compaction,
            enable_delegation=True,           # actually gated by depth
            delegation_depth=self.delegation_depth + 1,
            scope=self.scope,                 # sub-agents stay in scope too
            # Blackboard: the child shares the resolved AttackState by reference
            # (the lead's, or an isolated per-host one), so its findings are live
            # there — no merge-back. It may not reset/reassign the target from its
            # task wording (the host is fixed by the delegation).
            shared_state=child_state,
            allow_state_reset=False,
            # Share the event bus so the child's tool calls, findings, and RoE
            # refusals land in the same engagement log (feature K) as the lead's.
            bus=self.bus,
            # Children inherit the OPSEC policy so deeper delegations stay pinned.
            opsec_policy=self.opsec,
        )
        # Give the child its tools: an operator gets only its curated subset
        # (intersected with what's registered); a generalist gets everything.
        # The delegation tools are never copied (a sub-agent can't re-delegate).
        for schema in self.context._tools.values():
            if schema.name in (DELEGATE_TOOL, DELEGATE_PARALLEL_TOOL):
                continue
            if operator is not None and schema.name not in operator.tools:
                continue
            child.register_tool(schema)

        await child.start(inject_project_context=False)
        op_label = operator.name if operator else "generalist"
        logger.info("Delegating subtask (depth=%d, operator=%s): %r",
                    child.delegation_depth, op_label, task[:80])
        await self.bus.emit(
            "agent.delegate.start",
            {"task": task[:200], "operator": op_label,
             "depth": child.delegation_depth, "session_id": session_id,
             "target": child_state.target if isolated else None,
             "model_role": operator.model_role if operator else None,
             "opsec": "local-pinned" if (opsec.pin_local and child_model is not self.model)
                      else "cloud-eligible",
             "opsec_reason": opsec.reason},
            source="controller", session_id=session_id,
        )

        result = await child.run(task, session_id=f"{session_id}:{suffix}")

        # No merge-back: the child shared the lead's AttackState by reference, so
        # its findings are already live in the lead's state.
        await self.bus.emit(
            "agent.delegate.end",
            {"task": task[:200], "operator": op_label,
             "iterations": result.iterations, "session_id": session_id},
            source="controller", session_id=session_id,
        )

        content = (result.content or "").strip()
        if result.error and not content:
            content = f"[subagent error: {result.error}]"
        header = (f"[subagent result — host {child_state.target}]" if isolated
                  else "[subagent result]")
        return f"{header}\n{content[:4000]}"

    async def _dispatch_tool(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_call_id: str,
        session_id: str,
    ) -> ToolCallResult:
        # Built-in delegation: handled by the controller, not the dispatcher.
        if tool_name in (DELEGATE_TOOL, DELEGATE_PARALLEL_TOOL):
            runner = (self._run_parallel_subagents
                      if tool_name == DELEGATE_PARALLEL_TOOL else self._run_subagent)
            try:
                output = await runner(tool_args, session_id)
                return ToolCallResult(
                    tool_name=tool_name, tool_call_id=tool_call_id, output=output,
                )
            except Exception as exc:
                logger.error("Sub-agent failed: %s", exc)
                return ToolCallResult(
                    tool_name=tool_name, tool_call_id=tool_call_id,
                    output="", error=str(exc),
                )

        if self.tool_dispatcher is None:
            return ToolCallResult(
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                output=f"[STUB] Tool '{tool_name}' — dispatcher not connected.",
            )
        try:
            output = await self.tool_dispatcher.dispatch(tool_name, tool_args, session_id)
            return ToolCallResult(
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                output=output,
            )
        except Exception as exc:
            logger.error("Tool dispatch error (%s): %s", tool_name, exc)
            return ToolCallResult(
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                output="",
                error=str(exc),
            )

    # ------------------------------------------------------------------ #
    # Dangerous op detection
    # ------------------------------------------------------------------ #

    def _is_dangerous(self, tool_name: str, args: dict) -> bool:
        if tool_name in ("file_write", "file_edit"):
            return True
        if tool_name == "shell":
            cmd = args.get("cmd", "").lower()
            return any(p in cmd for p in DANGEROUS_PATTERNS)
        return False

    async def _request_confirmation(self, tool_name: str, args: dict) -> bool:
        if self.confirm_callback:
            return await self.confirm_callback(tool_name, args)
        return True

    # ------------------------------------------------------------------ #
    # Model helpers
    # ------------------------------------------------------------------ #

    async def _call_model_raw(
        self,
        messages: list[dict],
        json_mode: bool = False,
    ) -> Any:
        return await self.model.chat(messages=messages, json_mode=json_mode)

    # ------------------------------------------------------------------ #
    # Verifier
    # ------------------------------------------------------------------ #

    async def _verify(
        self,
        goal: str,
        response_text: str,
        tools_used: list[str],
    ) -> dict[str, Any]:
        """
        Judge whether the agent's final answer addresses the goal.

        Uses the injected verifier_caller (routes to the VERIFIER-role model)
        when available, otherwise falls back to the primary model. Returns
        {"ok": bool, "reason": str, "suggestion": str}. Any failure or
        unparsable verdict passes (ok=True) so verification never deadlocks
        the turn.
        """
        messages = [
            {"role": "system", "content": VERIFIER_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Goal: {goal}\n\n"
                    f"Tools used: {', '.join(tools_used) or 'none'}\n\n"
                    f"Agent response:\n{response_text}"
                ),
            },
        ]
        try:
            if self.verifier_caller:
                raw = await self.verifier_caller(messages)
            else:
                raw = await self.model.chat(messages=messages, json_mode=True)

            if isinstance(raw, dict):
                text = raw.get("message", {}).get("content", "") or raw.get("content", "")
            else:
                text = str(raw)

            data = json.loads(text.strip())
            return {
                "ok": bool(data.get("ok", True)),
                "reason": str(data.get("reason", "")),
                "suggestion": str(data.get("suggestion", "")),
            }
        except Exception as exc:
            logger.warning("Verifier unavailable/unparsable — passing: %s", exc)
            return {"ok": True, "reason": "", "suggestion": ""}

    # ------------------------------------------------------------------ #
    # Session management
    # ------------------------------------------------------------------ #

    def _new_session(self) -> str:
        session_id = str(uuid4())
        self._sessions[session_id] = {"created_at": asyncio.get_event_loop().time()}
        return session_id

    def end_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #

    def _register_handlers(self) -> None:
        @self.bus.on("error.unhandled")
        async def _on_error(event: Event) -> None:
            logger.error(
                "Unhandled error on topic %r: %s",
                event.data.get("failed_topic"),
                event.data.get("error"),
            )
