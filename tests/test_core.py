"""
test_core.py — Mapache Phase 1 core tests

Tests all core modules without requiring Ollama to be running.
Uses a mock model provider to simulate responses.

Run with: python -m pytest tests/test_core.py -v
      or: python tests/test_core.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.event_bus import EventBus, Event
from core.context_builder import ContextBuilder, Message, ToolSchema
from core.planner import Planner, TaskType
from core.task_manager import TaskManager, TaskStatus
from core.agent_controller import AgentController, AgentMode


# ------------------------------------------------------------------ #
# Mock model provider
# ------------------------------------------------------------------ #

class MockModel:
    """Fake model that returns scripted responses for testing."""

    def __init__(self, responses: list[dict | str] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict] = []

    def queue(self, response: dict | str) -> None:
        self.responses.append(response)

    async def chat(self, messages: list[dict], tools=None, json_mode=False, stream=False) -> Any:
        self.calls.append({"messages": messages, "tools": tools, "json_mode": json_mode})
        if self.responses:
            return self.responses.pop(0)
        return {"message": {"content": "Mock response — no more scripted replies."}}


from typing import Any


# ------------------------------------------------------------------ #
# EventBus tests
# ------------------------------------------------------------------ #

async def test_event_bus_basic():
    bus = EventBus()
    received = []

    @bus.on("test.event")
    async def handler(event: Event):
        received.append(event)

    await bus.emit("test.event", {"key": "value"}, source="test")

    assert len(received) == 1
    assert received[0].topic == "test.event"
    assert received[0].data["key"] == "value"
    assert received[0].source == "test"
    print("  PASS  event_bus_basic")


async def test_event_bus_wildcard():
    bus = EventBus()
    all_events = []

    @bus.on("*")
    async def catch_all(event: Event):
        all_events.append(event.topic)

    await bus.emit("foo.bar", {})
    await bus.emit("baz.qux", {})

    assert "foo.bar" in all_events
    assert "baz.qux" in all_events
    print("  PASS  event_bus_wildcard")


async def test_event_bus_history():
    bus = EventBus()
    await bus.emit("a.b", {"x": 1})
    await bus.emit("a.b", {"x": 2})
    await bus.emit("c.d", {"x": 3})

    history = bus.get_history(topic="a.b")
    assert len(history) == 2
    assert history[0].data["x"] == 1
    print("  PASS  event_bus_history")


async def test_event_bus_no_handler():
    bus = EventBus()
    # Should not raise even if no handler registered
    await bus.emit("orphan.event", {"x": 1})
    print("  PASS  event_bus_no_handler")


# ------------------------------------------------------------------ #
# ContextBuilder tests
# ------------------------------------------------------------------ #

def test_context_builder_messages():
    ctx = ContextBuilder()
    ctx.add_user_message("hello")
    ctx.add_assistant_message("hi there")
    ctx.add_user_message("what can you do?")

    payload = ctx.build(format="ollama")
    msgs = payload["messages"]

    # system + 3 messages
    assert msgs[0]["role"] == "system"
    assert msgs[1]["role"] == "user"
    assert msgs[2]["role"] == "assistant"
    assert msgs[3]["role"] == "user"
    print("  PASS  context_builder_messages")


def test_context_builder_tools():
    ctx = ContextBuilder(use_function_calling=True)
    ctx.register_tool(ToolSchema(
        name="run_nmap",
        description="Run an Nmap scan",
        parameters={"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
    ))

    payload = ctx.build(format="ollama")
    assert "tools" in payload
    assert payload["tools"][0]["function"]["name"] == "run_nmap"
    print("  PASS  context_builder_tools")


def test_context_builder_json_mode():
    ctx = ContextBuilder(use_function_calling=True)
    ctx.register_tool(ToolSchema(
        name="shell",
        description="Run a shell command",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    ))

    payload = ctx.build_json_mode()
    system = payload["messages"][0]["content"]
    assert "shell" in system
    assert "AVAILABLE TOOLS" in system
    assert "RESPONSE FORMAT" in system
    print("  PASS  context_builder_json_mode")


def test_context_builder_memory():
    ctx = ContextBuilder()
    ctx.inject_memory(["Target IP: 10.0.0.1", "Previous scan found port 22 open"])
    payload = ctx.build(format="ollama")
    system = payload["messages"][0]["content"]
    assert "RELEVANT MEMORY" in system
    assert "10.0.0.1" in system
    print("  PASS  context_builder_memory")


def test_context_builder_token_budget():
    ctx = ContextBuilder(max_context_tokens=200)
    # Add many messages that should exceed budget
    for i in range(20):
        ctx.add_user_message(f"Message number {i} with some content to fill tokens")
        ctx.add_assistant_message(f"Response to message {i} also with some content")

    payload = ctx.build(format="ollama")
    msgs = payload["messages"]
    # Should be trimmed — not all 40+ messages
    assert len(msgs) < 42
    print(f"  PASS  context_builder_token_budget (kept {len(msgs)} messages)")


# ------------------------------------------------------------------ #
# Planner tests
# ------------------------------------------------------------------ #

async def test_planner_noop_without_model():
    bus = EventBus()
    planner = Planner(bus)
    # No model set — should emit a passthrough plan

    plans = []

    @bus.on("planner.plan_ready")
    async def capture(event: Event):
        plans.append(event.data["plan"])

    await bus.emit(
        "agent.turn.start",
        {"input": "hello there", "session_id": "test-session"},
    )

    await asyncio.sleep(0.05)  # let async handlers run
    assert len(plans) == 1
    assert plans[0]["tasks"][0]["type"] == "noop"
    print("  PASS  planner_noop_without_model")


async def test_planner_with_mock_model():
    bus = EventBus()
    planner = Planner(bus)

    plan_json = json.dumps({
        "reasoning": "Need to run a port scan first",
        "tasks": [
            {
                "type": "tool_call",
                "description": "Scan target for open ports",
                "tool_name": "run_nmap",
                "tool_args": {"host": "192.168.1.1"},
                "output_key": "scan_result",
            }
        ]
    })

    async def mock_caller(messages, json_mode=True):
        return plan_json

    planner.set_model_caller(mock_caller)
    planner.set_available_tools(["run_nmap", "shell"])

    plans = []

    @bus.on("planner.plan_ready")
    async def capture(event: Event):
        plans.append(event.data["plan"])

    await bus.emit(
        "agent.turn.start",
        {"input": "scan 192.168.1.1", "session_id": "test2"},
    )

    await asyncio.sleep(0.05)
    assert len(plans) == 1
    assert plans[0]["tasks"][0]["tool_name"] == "run_nmap"
    assert plans[0]["reasoning"] == "Need to run a port scan first"
    print("  PASS  planner_with_mock_model")


# ------------------------------------------------------------------ #
# TaskManager tests
# ------------------------------------------------------------------ #

async def test_task_manager_plan_flow():
    bus = EventBus()
    tm = TaskManager(bus)

    ready_tasks = []
    done_plans = []

    @bus.on("task.ready")
    async def on_ready(event: Event):
        ready_tasks.append(event.data)

    @bus.on("task.plan_done")
    async def on_done(event: Event):
        done_plans.append(event.data)

    # Emit a plan directly
    plan_data = {
        "id": "plan-001",
        "goal": "test goal",
        "reasoning": "test",
        "tasks": [
            {
                "id": "t1",
                "type": "tool_call",
                "description": "step 1",
                "tool_name": "shell",
                "tool_args": {"cmd": "echo hi"},
                "output_key": "result1",
                "depends_on": [],
            }
        ]
    }

    await bus.emit("planner.plan_ready", {"plan": plan_data, "session_id": "sess1"})
    await asyncio.sleep(0.05)

    assert len(ready_tasks) == 1
    assert ready_tasks[0]["tool_name"] == "shell"

    # Simulate executor reporting success
    await bus.emit("task.result", {
        "task_id": "t1",
        "output": "hi",
        "session_id": "sess1",
    })
    await asyncio.sleep(0.05)

    assert len(done_plans) == 1
    assert done_plans[0]["success"] is True
    print("  PASS  task_manager_plan_flow")


async def test_task_manager_retry_on_failure():
    bus = EventBus()
    tm = TaskManager(bus)

    ready_count = [0]
    failed_plans = []

    @bus.on("task.ready")
    async def on_ready(event: Event):
        ready_count[0] += 1

    @bus.on("task.plan_done")
    async def on_done(event: Event):
        failed_plans.append(event.data)

    plan_data = {
        "id": "plan-retry",
        "goal": "retry test",
        "reasoning": "",
        "tasks": [{"id": "t2", "type": "tool_call", "description": "flaky step",
                   "tool_name": "flaky_tool", "tool_args": {}, "output_key": None, "depends_on": []}]
    }

    await bus.emit("planner.plan_ready", {"plan": plan_data, "session_id": "sess2"})
    await asyncio.sleep(0.05)

    # First failure — should retry (max_attempts=2)
    await bus.emit("task.error", {"task_id": "t2", "error": "timeout", "session_id": "sess2"})
    await asyncio.sleep(0.05)

    # Second failure — should give up
    await bus.emit("task.error", {"task_id": "t2", "error": "timeout again", "session_id": "sess2"})
    await asyncio.sleep(0.05)

    assert ready_count[0] == 2  # initial + 1 retry
    assert len(failed_plans) == 1
    assert failed_plans[0]["success"] is False
    print("  PASS  task_manager_retry_on_failure")


# ------------------------------------------------------------------ #
# AgentController integration tests
# ------------------------------------------------------------------ #

async def test_agent_direct_response():
    model = MockModel()
    model.queue({"message": {"content": "Hello! I am Mapache."}})

    controller = AgentController(model_provider=model, mode=AgentMode.CHAT)
    await controller.start()

    response = await controller.run("Hello", session_id="test-chat")

    assert response.success
    assert "Mapache" in response.content
    assert response.iterations == 1
    print("  PASS  agent_direct_response")


async def test_agent_tool_call_then_response():
    model = MockModel()
    # Planner call (AGENT mode triggers planning) — return a passthrough plan
    model.queue('{"reasoning": "direct", "tasks": [{"type": "noop", "description": "who am I"}]}')
    # First agent loop call: model requests a tool
    model.queue({"message": {
        "content": "",
        "tool_calls": [{"function": {"name": "shell", "arguments": {"cmd": "whoami"}}}]
    }})
    # Second agent loop call: model gives final answer after seeing tool result
    model.queue({"message": {"content": "The current user is root."}})

    controller = AgentController(model_provider=model, mode=AgentMode.AGENT)
    controller.register_tool(ToolSchema(
        name="shell",
        description="Run a shell command",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    ))
    await controller.start()

    response = await controller.run("who am I?", session_id="test-tools")

    assert response.success
    assert "shell" in response.tool_calls_made
    assert response.iterations == 2
    assert "root" in response.content
    print("  PASS  agent_tool_call_then_response")


async def test_agent_json_mode_tool_call():
    model = MockModel()
    # Planner call
    model.queue('{"reasoning": "direct", "tasks": [{"type": "noop", "description": "list files"}]}')
    # Agent loop: JSON mode tool call
    model.queue(json.dumps({"type": "tool_call", "tool": "shell", "args": {"cmd": "ls"}}))
    # Agent loop: final response
    model.queue(json.dumps({"type": "response", "content": "Listed the files."}))

    controller = AgentController(model_provider=model, use_function_calling=False)
    controller.register_tool(ToolSchema(
        name="shell",
        description="Run shell commands",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    ))
    await controller.start()

    response = await controller.run("list files", session_id="json-mode-test")

    assert response.success
    assert "shell" in response.tool_calls_made
    print("  PASS  agent_json_mode_tool_call")


async def test_agent_max_iterations():
    model = MockModel()
    # Always return a tool call — should hit max iterations
    for _ in range(AgentController.MAX_ITERATIONS + 2):
        model.queue({"message": {
            "content": "",
            "tool_calls": [{"function": {"name": "shell", "arguments": {"cmd": "loop"}}}]
        }})

    controller = AgentController(model_provider=model)
    controller.register_tool(ToolSchema(
        name="shell",
        description="Shell",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    ))
    await controller.start()

    response = await controller.run("loop forever", session_id="loop-test")

    assert response.error == "max_iterations"
    assert response.iterations == AgentController.MAX_ITERATIONS
    print(f"  PASS  agent_max_iterations (hit limit at {response.iterations})")


# ------------------------------------------------------------------ #
# Runner
# ------------------------------------------------------------------ #

async def run_all():
    print("\nMapache Phase 1 — Core test suite\n" + "─" * 40)

    print("\nEventBus")
    await test_event_bus_basic()
    await test_event_bus_wildcard()
    await test_event_bus_history()
    await test_event_bus_no_handler()

    print("\nContextBuilder")
    test_context_builder_messages()
    test_context_builder_tools()
    test_context_builder_json_mode()
    test_context_builder_memory()
    test_context_builder_token_budget()

    print("\nPlanner")
    await test_planner_noop_without_model()
    await test_planner_with_mock_model()

    print("\nTaskManager")
    await test_task_manager_plan_flow()
    await test_task_manager_retry_on_failure()

    print("\nAgentController")
    await test_agent_direct_response()
    await test_agent_tool_call_then_response()
    await test_agent_json_mode_tool_call()
    await test_agent_max_iterations()

    print("\n" + "─" * 40)
    print("All tests passed.\n")


if __name__ == "__main__":
    asyncio.run(run_all())
