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
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Callable, Optional
from uuid import uuid4

from .context_builder import ContextBuilder, Message, ToolSchema
from .conversation_chain import ConversationChain
from .event_bus import Event, EventBus
from .executor import Executor
from .logger import get_logger
from .project_context import build_project_context

logger = get_logger(__name__)

DANGEROUS_PATTERNS = [
    "rm ", "del ", "rmdir", "format", "drop table",
    "delete from", ":(){:|:&};:", "mkfs", "dd if=",
]

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
    ) -> None:
        self.model = model_provider
        self.tool_dispatcher = tool_dispatcher
        self.mode = mode
        self.working_dir = working_dir
        self.confirm_dangerous = confirm_dangerous
        self.confirm_callback = confirm_callback
        self.enable_tool_subsetting = enable_tool_subsetting
        # Opt-in verifier: after the loop produces a final answer, a VERIFIER-
        # role model call judges whether it actually addresses the goal; if not
        # (and retries remain) the loop resumes with the verifier's suggestion.
        self.enable_verifier = enable_verifier
        self.verify_max_retries = verify_max_retries
        self.verifier_caller = verifier_caller

        # Core subsystems
        self.bus = EventBus()
        self.context = ContextBuilder(
            system_prompt=system_prompt,
            max_context_tokens=max_context_tokens,
            use_function_calling=use_function_calling,
        )
        # Executor is retained only as a shell/tool utility (used by the CLI
        # `!cmd` shortcut and tool dispatch); it no longer drives a parallel
        # event-bus execution pipeline.
        self.executor = Executor(self.bus)
        self.chain = ConversationChain()

        # Wire subsystems
        self.executor.set_model_caller(self._call_model_raw)
        if tool_dispatcher:
            self.executor.set_tool_dispatcher(tool_dispatcher)

        self._sessions: dict[str, dict[str, Any]] = {}
        self._register_handlers()

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
    ) -> AgentResponse:
        session_id = session_id or self._new_session()
        logger.info("Turn start — session=%s input=%r", session_id, user_input[:80])

        # Notify conversation chain of new turn
        self.chain.on_turn_start(user_input)

        # Inject current attack state into context
        chain_context = self.chain.get_context_injection()
        if chain_context:
            self.context.inject_memory([chain_context])

        self.context.add_user_message(user_input)
        response = await self._agent_loop(user_input, session_id)

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
        session_id = session_id or self._new_session()
        self.chain.on_turn_start(user_input)

        chain_context = self.chain.get_context_injection()
        if chain_context:
            self.context.inject_memory([chain_context])

        self.context.add_user_message(user_input)

        full_response = ""

        while True:
            self._refresh_active_tools()
            context_payload = self.context.build(format="ollama")

            try:
                if hasattr(self.model, "chat_stream"):
                    buffer = ""
                    tool_call_detected = False
                    tool_call_data: dict = {}

                    async for token in self.model.chat_stream(
                        messages=context_payload["messages"],
                        tools=context_payload.get("tools"),
                    ):
                        if isinstance(token, dict) and token.get("type") == "tool_call":
                            tool_call_detected = True
                            tool_call_data = token
                            break
                        else:
                            text = str(token)
                            buffer += text
                            full_response += text
                            yield text

                    if tool_call_detected:
                        tool_name = tool_call_data.get("tool", "")
                        tool_args = self._apply_arg_fallbacks(
                            tool_name, tool_call_data.get("args", {})
                        )
                        tool_call_id = str(uuid4())[:8]
                        yield f"\n[calling {tool_name}...]\n"
                        result = await self._dispatch_tool(
                            tool_name, tool_args, tool_call_id, session_id
                        )
                        tool_output = result.output if not result.error else f"ERROR: {result.error}"
                        self.chain.on_tool_result(tool_name, tool_output)
                        compressed = self.chain.get_compressed_tool_output(tool_name, tool_output)
                        self.context.add_tool_result(tool_call_id, tool_name, compressed)
                        continue
                    else:
                        self.chain.on_turn_end(full_response)
                        if full_response:
                            self.context.add_assistant_message(full_response)
                        return
                else:
                    raw = await self.model.chat(
                        messages=context_payload["messages"],
                        tools=context_payload.get("tools"),
                    )
                    parsed = self._parse_model_response(raw)

                    if parsed.get("type") == "tool_call":
                        tool_name = parsed["tool"]
                        tool_args = self._apply_arg_fallbacks(tool_name, parsed.get("args", {}))
                        tool_call_id = str(uuid4())[:8]
                        yield f"[calling {tool_name}...]\n"
                        result = await self._dispatch_tool(
                            tool_name, tool_args, tool_call_id, session_id
                        )
                        tool_output = result.output if not result.error else f"ERROR: {result.error}"
                        self.chain.on_tool_result(tool_name, tool_output)
                        compressed = self.chain.get_compressed_tool_output(tool_name, tool_output)
                        self.context.add_tool_result(tool_call_id, tool_name, compressed)
                        continue

                    content = parsed.get("content", "")
                    full_response = content
                    self.chain.on_turn_end(content)
                    self.context.add_assistant_message(content)
                    yield content
                    return

            except Exception as exc:
                yield f"\n[error: {exc}]"
                return

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

    async def _agent_loop(self, user_input: str, session_id: str) -> AgentResponse:
        tools_used: list[str] = []
        iteration = 0
        verify_retries_left = self.verify_max_retries

        while iteration < self.MAX_ITERATIONS:
            iteration += 1
            self._refresh_active_tools()

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
                raw_response = await self.model.chat(
                    messages=context_payload["messages"],
                    **model_kwargs,
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

            if parsed.get("type") == "tool_call":
                tool_name = parsed["tool"]
                tool_args = self._apply_arg_fallbacks(tool_name, parsed.get("args", {}))
                tool_call_id = str(uuid4())[:8]

                # Confirmation for dangerous ops
                if self.confirm_dangerous and self._is_dangerous(tool_name, tool_args):
                    confirmed = await self._request_confirmation(tool_name, tool_args)
                    if not confirmed:
                        self.context.add_tool_result(
                            tool_call_id, tool_name, "Operation cancelled by user."
                        )
                        continue

                logger.info("Tool call: %s(%s)", tool_name, tool_args)
                result = await self._dispatch_tool(
                    tool_name, tool_args, tool_call_id, session_id
                )
                tools_used.append(tool_name)

                # Notify conversation chain
                tool_output = result.output if not result.error else f"ERROR: {result.error}"
                self.chain.on_tool_result(tool_name, tool_output)

                # Inject compressed output to keep context clean
                compressed = self.chain.get_compressed_tool_output(tool_name, tool_output)
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
                        "output": result.output,
                        "error": result.error,
                        "session_id": session_id,
                    },
                    source="controller",
                    session_id=session_id,
                )
                continue

            content = parsed.get("content") or parsed.get("text", "")
            if not content and isinstance(raw_response, str):
                content = raw_response

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
    # Response parsing
    # ------------------------------------------------------------------ #

    def _parse_model_response(self, raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            tool_calls = raw.get("message", {}).get("tool_calls") or raw.get("tool_calls")
            if tool_calls:
                first = tool_calls[0]
                fn = first.get("function", first)
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                return {"type": "tool_call", "tool": fn.get("name", ""), "args": args}

            content = raw.get("message", {}).get("content") or raw.get("content", "")
            raw = content

        if isinstance(raw, str):
            stripped = raw.strip()
            if stripped.startswith("{"):
                try:
                    data = json.loads(stripped)
                    if data.get("type") == "tool_call":
                        return data
                    if data.get("type") in ("response", "plan"):
                        return {"type": "response", "content": data.get("content", stripped)}
                except json.JSONDecodeError:
                    pass
            return {"type": "response", "content": raw}

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

    async def _dispatch_tool(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_call_id: str,
        session_id: str,
    ) -> ToolCallResult:
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
