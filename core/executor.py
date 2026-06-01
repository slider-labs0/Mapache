"""
executor.py — Mapache executor

The executor sits between the task manager and the tools.
It receives "task.ready" events, runs the appropriate action
(tool call, shell command, or direct model query), and emits
"task.result" or "task.error" back to the task manager.

The executor is the only component that actually *does* things.
Everything else plans, routes, or tracks.

Execution flow:
    task.ready  →  Executor._on_task_ready
                        ↓
                   _run_task(task)
                        ↓
                   _run_tool_call()   ← tool registry / dispatcher
                   _run_shell()       ← direct shell (sandboxed)
                   _run_model_query() ← sub-question to model
                        ↓
                   task.result  |  task.error
"""

from __future__ import annotations

import asyncio
import json
import shlex
import subprocess
import time
from typing import Any, Optional

from .event_bus import Event, EventBus
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
        self._running: dict[str, asyncio.Task] = {}  # task_id → asyncio.Task

        bus.subscribe("task.ready", self._on_task_ready)
        logger.info("Executor initialized")

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
    # Event handler
    # ------------------------------------------------------------------ #

    async def _on_task_ready(self, event: Event) -> None:
        task_id: str = event.data.get("task", {}).get("id", "")
        task_type: str = event.data.get("task_type", "noop")
        session_id: str = event.data.get("session_id") or event.session_id or ""

        if not task_id:
            logger.warning("task.ready event missing task.id — skipping")
            return

        logger.info("Executing task %s [%s]", task_id, task_type)

        # Run in a separate asyncio task so the bus isn't blocked
        coro = self._run_task(event.data, session_id)
        running = asyncio.create_task(coro)
        self._running[task_id] = running

        def _cleanup(fut):
            self._running.pop(task_id, None)

        running.add_done_callback(_cleanup)

    # ------------------------------------------------------------------ #
    # Task dispatch
    # ------------------------------------------------------------------ #

    async def _run_task(self, task_data: dict, session_id: str) -> None:
        task_id: str = task_data.get("task", {}).get("id", "unknown")
        task_type: str = task_data.get("task_type", "noop")
        tool_name: str = task_data.get("tool_name", "")
        tool_args: dict = task_data.get("tool_args", {})
        description: str = task_data.get("description", "")

        start = time.monotonic()

        try:
            if task_type == "tool_call":
                result = await self._run_tool_call(tool_name, tool_args, session_id)

            elif task_type == "shell":
                cmd = tool_args.get("cmd") or description
                result = await self._run_shell(cmd)

            elif task_type == "model_query":
                result = await self._run_model_query(description, session_id)

            elif task_type == "noop":
                # Direct answer — output is the description itself
                result = ExecutionResult(output=description)

            else:
                result = ExecutionResult(
                    output="",
                    error=f"Unknown task type: {task_type!r}",
                )

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("Task %s raised exception: %s", task_id, exc, exc_info=True)
            await self._emit_error(task_id, str(exc), session_id)
            return

        elapsed = (time.monotonic() - start) * 1000
        result.duration_ms = elapsed

        if result.success:
            logger.info("Task %s completed in %.0fms", task_id, elapsed)
            await self._emit_result(task_id, result.output, session_id)
        else:
            logger.warning("Task %s failed in %.0fms: %s", task_id, elapsed, result.error)
            await self._emit_error(task_id, result.error or "unknown", session_id)

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

    # ------------------------------------------------------------------ #
    # Result emission
    # ------------------------------------------------------------------ #

    async def _emit_result(self, task_id: str, output: str, session_id: str) -> None:
        await self.bus.emit(
            "task.result",
            {"task_id": task_id, "output": output, "session_id": session_id},
            source="executor",
            session_id=session_id,
        )

    async def _emit_error(self, task_id: str, error: str, session_id: str) -> None:
        await self.bus.emit(
            "task.error",
            {"task_id": task_id, "error": error, "session_id": session_id},
            source="executor",
            session_id=session_id,
        )

    # ------------------------------------------------------------------ #
    # Control
    # ------------------------------------------------------------------ #

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task by ID."""
        task = self._running.get(task_id)
        if task and not task.done():
            task.cancel()
            logger.info("Task %s cancelled", task_id)
            return True
        return False

    @property
    def running_task_ids(self) -> list[str]:
        return list(self._running.keys())
