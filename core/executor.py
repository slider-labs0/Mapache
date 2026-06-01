"""
executor.py — Mapache shell/tool execution utility

A thin helper that actually *runs* low-level actions on the host:

    _run_shell()       ← run a subprocess (timeout + output capture)
    _run_tool_call()   ← route through the tool dispatcher
    _run_model_query() ← ask the model a one-off sub-question

Used directly by the agent loop's CLI `!cmd` shortcut and by callers that
need a raw shell runner. It no longer drives an event-bus execution pipeline;
the agent's real ReAct loop lives in AgentController._agent_loop.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from .event_bus import EventBus
from .logger import get_logger

logger = get_logger(__name__)


class ExecutionResult:
    def __init__(self, output: str, error: Optional[str] = None, duration_ms: float = 0.0):
        self.output = output
        self.error = error
        self.duration_ms = duration_ms

    @property
    def success(self) -> bool:
        return self.error is None


class Executor:
    """
    Executes ready tasks and reports results back to the event bus.

    Supports:
    - tool_call: route through registered tool dispatcher
    - shell:     run a subprocess directly (with timeout + output capture)
    - noop:      pass description directly as output (no-op / direct answer)
    - model_query: ask the model a sub-question (requires model_caller injection)

    Shell execution is intentionally simple at Phase 1.
    Sandboxing, containerization, and permission checks are Phase 2 (sandbox_runtime.py).
    """

    DEFAULT_SHELL_TIMEOUT = 30  # seconds
    MAX_OUTPUT_BYTES = 50_000   # truncate large outputs before sending to model

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._tool_dispatcher: Any = None   # injected by AgentController
        self._model_caller: Any = None       # injected by AgentController
        self._shell_timeout: int = self.DEFAULT_SHELL_TIMEOUT

        logger.info("Executor initialized (shell/tool utility)")

    # ------------------------------------------------------------------ #
    # Dependency injection
    # ------------------------------------------------------------------ #

    def set_tool_dispatcher(self, dispatcher: Any) -> None:
        self._tool_dispatcher = dispatcher

    def set_model_caller(self, caller: Any) -> None:
        self._model_caller = caller

    def set_shell_timeout(self, seconds: int) -> None:
        self._shell_timeout = seconds

    # ------------------------------------------------------------------ #
    # Execution strategies
    # ------------------------------------------------------------------ #

    async def _run_tool_call(
        self,
        tool_name: str,
        tool_args: dict,
        session_id: str,
    ) -> ExecutionResult:
        """Route through the tool dispatcher."""
        if self._tool_dispatcher is None:
            # Phase 1 stub — dispatcher not wired yet
            stub_output = (
                f"[STUB] {tool_name}({json.dumps(tool_args, separators=(',', ':'))})\n"
                f"Tool dispatcher not yet connected — Phase 2 will wire this up."
            )
            logger.debug("Tool dispatcher stub: %s", tool_name)
            return ExecutionResult(output=stub_output)

        try:
            output = await self._tool_dispatcher.dispatch(tool_name, tool_args, session_id)
            return ExecutionResult(output=str(output))
        except Exception as exc:
            return ExecutionResult(output="", error=str(exc))

    async def _run_shell(self, cmd: str) -> ExecutionResult:
        """
        Run a shell command in a subprocess.

        Safety notes (Phase 1 — basic):
        - Commands run as the current user
        - Output is captured and truncated
        - Timeout enforced
        - Phase 2 will add sandboxing via sandbox_runtime.py
        """
        if not cmd or not cmd.strip():
            return ExecutionResult(output="", error="Empty command")

        logger.debug("Shell exec: %r", cmd)

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                limit=self.MAX_OUTPUT_BYTES,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self._shell_timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                return ExecutionResult(
                    output="",
                    error=f"Command timed out after {self._shell_timeout}s",
                )

            output = stdout.decode("utf-8", errors="replace")

            # Truncate very large outputs
            if len(output) > self.MAX_OUTPUT_BYTES:
                output = output[:self.MAX_OUTPUT_BYTES] + "\n[... output truncated]"

            if proc.returncode != 0:
                # Non-zero exit — return output as error context, not a hard error
                # Many tools (nmap, etc.) use non-zero exits for partial results
                return ExecutionResult(
                    output=output,
                    error=f"Exit code {proc.returncode}" if not output.strip() else None,
                )

            return ExecutionResult(output=output)

        except FileNotFoundError as exc:
            return ExecutionResult(output="", error=f"Command not found: {exc}")
        except PermissionError as exc:
            return ExecutionResult(output="", error=f"Permission denied: {exc}")
        except Exception as exc:
            return ExecutionResult(output="", error=f"Shell error: {exc}")

    async def _run_model_query(self, query: str, session_id: str) -> ExecutionResult:
        """Ask the model a sub-question (for model_query task type)."""
        if self._model_caller is None:
            return ExecutionResult(output="", error="No model caller available for sub-query")

        try:
            messages = [
                {"role": "system", "content": "Answer the following question concisely."},
                {"role": "user", "content": query},
            ]
            raw = await self._model_caller(messages)
            if isinstance(raw, dict):
                output = raw.get("message", {}).get("content", "") or raw.get("content", "")
            else:
                output = str(raw)
            return ExecutionResult(output=output)
        except Exception as exc:
            return ExecutionResult(output="", error=f"Model sub-query failed: {exc}")

