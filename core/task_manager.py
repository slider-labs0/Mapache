"""
task_manager.py — Mapache task manager

Manages the lifecycle of tasks within a plan:
  PENDING → RUNNING → COMPLETED | FAILED | CANCELLED

Receives plans from the planner, schedules tasks respecting dependencies,
tracks outputs, and emits lifecycle events the executor listens to.

The task manager never executes — it only schedules and tracks.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from .event_bus import Event, EventBus
from .planner import Plan, PlannedTask, TaskType

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass
class TaskRecord:
    """Runtime record of a task's state and outputs."""

    task: PlannedTask
    plan_id: str
    session_id: str
    status: TaskStatus = TaskStatus.PENDING
    output: Optional[str] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    attempt: int = 0
    max_attempts: int = 2

    @property
    def id(self) -> str:
        return self.task.id

    @property
    def duration_ms(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return delta.total_seconds() * 1000
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status.value,
            "description": self.task.description,
            "tool_name": self.task.tool_name,
            "output": self.output,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "attempt": self.attempt,
        }


class TaskManager:
    """
    Task queue and lifecycle tracker.

    Per-session task state — each session_id gets its own task context.
    Sessions are lightweight dicts, not objects, to keep things simple at this stage.

    Events emitted:
        task.created        — new task registered
        task.ready          — task is unblocked and ready to run
        task.started        — executor picked it up
        task.completed      — executor finished successfully
        task.failed         — executor reported failure
        task.plan_done      — all tasks in a plan are resolved

    Events consumed:
        planner.plan_ready  — register all tasks from a new plan
        task.result         — executor reports success
        task.error          — executor reports failure
    """

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        # session_id → {task_id → TaskRecord}
        self._sessions: dict[str, dict[str, TaskRecord]] = {}
        # session_id → output_key → value (shared across tasks in a session)
        self._outputs: dict[str, dict[str, str]] = {}

        bus.subscribe("planner.plan_ready", self._on_plan_ready)
        bus.subscribe("task.result", self._on_task_result)
        bus.subscribe("task.error", self._on_task_error)
        logger.info("TaskManager initialized")

    # ------------------------------------------------------------------ #
    # Plan intake
    # ------------------------------------------------------------------ #

    async def _on_plan_ready(self, event: Event) -> None:
        plan_data: dict = event.data.get("plan", {})
        session_id: str = event.data.get("session_id", str(uuid4()))

        plan = self._reconstruct_plan(plan_data, session_id)
        await self._register_plan(plan)

    async def _register_plan(self, plan: Plan) -> None:
        session_id = plan.session_id or str(uuid4())

        if session_id not in self._sessions:
            self._sessions[session_id] = {}
        if session_id not in self._outputs:
            self._outputs[session_id] = {}

        records: list[TaskRecord] = []
        for task in plan.tasks:
            record = TaskRecord(task=task, plan_id=plan.id, session_id=session_id)
            self._sessions[session_id][task.id] = record
            records.append(record)

            await self.bus.emit(
                "task.created",
                {"task": record.to_dict(), "plan_id": plan.id},
                source="task_manager",
                session_id=session_id,
            )

        logger.info(
            "Plan %s registered: %d tasks for session %s",
            plan.id[:8], len(records), session_id,
        )

        # Kick off any tasks that have no dependencies
        await self._schedule_ready_tasks(session_id)

    # ------------------------------------------------------------------ #
    # Scheduling
    # ------------------------------------------------------------------ #

    async def _schedule_ready_tasks(self, session_id: str) -> None:
        """Find all pending tasks whose dependencies are satisfied and emit task.ready."""
        session = self._sessions.get(session_id, {})
        outputs = self._outputs.get(session_id, {})

        for record in session.values():
            if record.status != TaskStatus.PENDING:
                continue

            if self._dependencies_met(record.task, session):
                # Substitute output references in tool_args
                resolved_args = self._resolve_args(record.task.tool_args, outputs)
                record.task.tool_args = resolved_args
                record.status = TaskStatus.RUNNING
                record.started_at = datetime.now(timezone.utc)
                record.attempt += 1

                await self.bus.emit(
                    "task.ready",
                    {
                        "task": record.to_dict(),
                        "task_type": record.task.type.value,
                        "tool_name": record.task.tool_name,
                        "tool_args": record.task.tool_args,
                        "description": record.task.description,
                        "plan_id": record.plan_id,
                    },
                    source="task_manager",
                    session_id=session_id,
                )

    def _dependencies_met(self, task: PlannedTask, session: dict[str, TaskRecord]) -> bool:
        for dep_id in task.depends_on:
            dep = session.get(dep_id)
            if dep is None or dep.status != TaskStatus.COMPLETED:
                return False
        return True

    def _resolve_args(self, args: dict[str, Any], outputs: dict[str, str]) -> dict[str, Any]:
        """Replace {output_key} references in tool_args with actual values."""
        resolved = {}
        for k, v in args.items():
            if isinstance(v, str) and v.startswith("{") and v.endswith("}"):
                key = v[1:-1]
                resolved[k] = outputs.get(key, v)
            else:
                resolved[k] = v
        return resolved

    # ------------------------------------------------------------------ #
    # Result handling
    # ------------------------------------------------------------------ #

    async def _on_task_result(self, event: Event) -> None:
        task_id: str = event.data.get("task_id", "")
        output: str = event.data.get("output", "")
        session_id: str = event.data.get("session_id", "")

        record = self._get_record(task_id, session_id)
        if not record:
            logger.warning("task.result for unknown task %s", task_id)
            return

        record.status = TaskStatus.COMPLETED
        record.output = output
        record.completed_at = datetime.now(timezone.utc)

        # Store output under output_key if specified
        if record.task.output_key:
            self._outputs.setdefault(session_id, {})[record.task.output_key] = output

        await self.bus.emit(
            "task.completed",
            {"task": record.to_dict()},
            source="task_manager",
            session_id=session_id,
        )

        logger.info(
            "Task %s completed in %.0fms",
            task_id, record.duration_ms or 0,
        )

        # Check if plan is fully resolved or schedule next tasks
        if await self._check_plan_done(record.plan_id, session_id):
            await self._emit_plan_done(record.plan_id, session_id)
        else:
            await self._schedule_ready_tasks(session_id)

    async def _on_task_error(self, event: Event) -> None:
        task_id: str = event.data.get("task_id", "")
        error: str = event.data.get("error", "unknown error")
        session_id: str = event.data.get("session_id", "")

        record = self._get_record(task_id, session_id)
        if not record:
            return

        if record.attempt < record.max_attempts:
            logger.warning("Task %s failed (attempt %d), retrying: %s", task_id, record.attempt, error)
            record.status = TaskStatus.PENDING
            await self._schedule_ready_tasks(session_id)
            return

        record.status = TaskStatus.FAILED
        record.error = error
        record.completed_at = datetime.now(timezone.utc)

        await self.bus.emit(
            "task.failed",
            {"task": record.to_dict(), "error": error},
            source="task_manager",
            session_id=session_id,
        )

        logger.error("Task %s failed permanently: %s", task_id, error)
        await self._emit_plan_done(record.plan_id, session_id)

    # ------------------------------------------------------------------ #
    # Plan completion
    # ------------------------------------------------------------------ #

    async def _check_plan_done(self, plan_id: str, session_id: str) -> bool:
        session = self._sessions.get(session_id, {})
        plan_tasks = [r for r in session.values() if r.plan_id == plan_id]
        terminal = {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.SKIPPED}
        return all(r.status in terminal for r in plan_tasks)

    async def _emit_plan_done(self, plan_id: str, session_id: str) -> None:
        session = self._sessions.get(session_id, {})
        plan_tasks = [r for r in session.values() if r.plan_id == plan_id]
        outputs = [r.output for r in plan_tasks if r.output]
        errors = [r.error for r in plan_tasks if r.error]

        await self.bus.emit(
            "task.plan_done",
            {
                "plan_id": plan_id,
                "tasks": [r.to_dict() for r in plan_tasks],
                "outputs": outputs,
                "errors": errors,
                "success": len(errors) == 0,
            },
            source="task_manager",
            session_id=session_id,
        )

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    def get_session_tasks(self, session_id: str) -> list[TaskRecord]:
        return list(self._sessions.get(session_id, {}).values())

    def get_task(self, task_id: str, session_id: str) -> Optional[TaskRecord]:
        return self._get_record(task_id, session_id)

    def clear_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        self._outputs.pop(session_id, None)

    def _get_record(self, task_id: str, session_id: str) -> Optional[TaskRecord]:
        return self._sessions.get(session_id, {}).get(task_id)

    def _reconstruct_plan(self, data: dict, session_id: str) -> Plan:
        from .planner import PlannedTask, TaskType
        tasks = []
        for t in data.get("tasks", []):
            tasks.append(PlannedTask(
                id=t.get("id", str(uuid4())[:8]),
                type=TaskType(t.get("type", "noop")),
                description=t.get("description", ""),
                tool_name=t.get("tool_name"),
                tool_args=t.get("tool_args", {}),
                output_key=t.get("output_key"),
            ))
        return Plan(
            id=data.get("id", str(uuid4())),
            goal=data.get("goal", ""),
            tasks=tasks,
            reasoning=data.get("reasoning", ""),
            session_id=session_id,
        )
