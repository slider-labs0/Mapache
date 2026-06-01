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


def test_context_builder_tool_result_function_calling():
    ctx = ContextBuilder(use_function_calling=True)
    ctx.add_tool_result("call-1", "nmap_scan", "22/tcp open ssh")
    # Exactly one message, with the tool role — no duplicate user echo.
    assert len(ctx._history) == 1
    msg = ctx._history[0]
    assert msg.role == "tool"
    assert msg.tool_call_id == "call-1"
    assert "verbatim" not in msg.content.lower()
    print("  PASS  context_builder_tool_result_function_calling")


def test_context_builder_tool_result_json_mode():
    ctx = ContextBuilder(use_function_calling=False)
    ctx.add_tool_result("call-2", "shell", "uid=0(root)")
    # Exactly one message; delivered as user observation since there's no tool role.
    assert len(ctx._history) == 1
    msg = ctx._history[0]
    assert msg.role == "user"
    assert "uid=0(root)" in msg.content
    assert "shell" in msg.content
    print("  PASS  context_builder_tool_result_json_mode")


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


async def test_agent_verifier_retry():
    model = MockModel()
    # 1) loop produces a thin first answer
    model.queue({"message": {"content": "Found something."}})
    # 2) verifier (falls back to primary model here) rejects it
    model.queue('{"ok": false, "reason": "no scan run", "suggestion": "run nmap_scan"}')
    # 3) loop produces the improved final answer
    model.queue({"message": {"content": "Ran the scan; ports 22,80 open."}})

    controller = AgentController(
        model_provider=model, mode=AgentMode.AGENT, enable_verifier=True,
    )
    await controller.start()

    response = await controller.run("scan and report", session_id="verify-test")

    assert response.success
    assert response.content == "Ran the scan; ports 22,80 open."
    # First answer + retried answer = 2 loop iterations (the verifier call
    # itself is out-of-band and does not count as an iteration).
    assert response.iterations == 2
    print("  PASS  agent_verifier_retry")


async def test_agent_verifier_off_by_default():
    model = MockModel()
    model.queue({"message": {"content": "Done."}})
    controller = AgentController(model_provider=model, mode=AgentMode.AGENT)
    await controller.start()
    response = await controller.run("do it", session_id="noverify-test")
    # No verifier call → single iteration, answer returned as-is.
    assert response.iterations == 1
    assert response.content == "Done."
    print("  PASS  agent_verifier_off_by_default")


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
# Model routing tests (Phase 7)
# ------------------------------------------------------------------ #

class FakeProvider:
    """Stand-in for OllamaProvider that records calls and echoes its model."""

    def __init__(self, model_id: str) -> None:
        self.model = model_id
        self.supports_tools = True

    async def chat(self, messages, tools=None, json_mode=False, stream=False):
        return {"message": {"content": f"reply from {self.model}"}}


class FakePool:
    """ModelPool stand-in that hands out FakeProviders and logs get() calls."""

    def __init__(self) -> None:
        self.gets: list[str] = []
        self._providers: dict[str, FakeProvider] = {}

    def get(self, model_id: str) -> FakeProvider:
        self.gets.append(model_id)
        return self._providers.setdefault(model_id, FakeProvider(model_id))


def _routing(strategy):
    from models.model_registry import ModelRegistry
    from models.routing_engine import RoutingEngine
    registry = ModelRegistry()
    engine = RoutingEngine(
        registry, strategy=strategy, primary_model_id="qwen2.5:14b",
        local_only=True, max_vram_gb=12.0,
    )
    # qwen2.5:7b is faster, qwen2.5:14b is higher quality; nomic is embed-only.
    engine.set_available_models(["qwen2.5:14b", "qwen2.5:7b", "nomic-embed-text"])
    return engine


async def test_routing_pipeline_picks_fast_executor():
    from models.model_registry import ModelRole
    from models.routing_engine import RoutingStrategy
    from models.routed_model import RoutedModel

    engine = _routing(RoutingStrategy.PIPELINE)
    pool = FakePool()
    routed = RoutedModel(engine, pool, primary_model_id="qwen2.5:14b")

    # PIPELINE executor prefers speed → the 7B model wins.
    assert routed.model_for(ModelRole.EXECUTOR) == "qwen2.5:7b"
    # Planner prefers quality → the 14B model wins.
    assert routed.model_for(ModelRole.PLANNER) == "qwen2.5:14b"

    # A chat() call (default EXECUTOR role) dispatches to the executor model.
    await routed.chat([{"role": "user", "content": "hi"}])
    assert pool.gets[-1] == "qwen2.5:7b"
    print("  PASS  routing_pipeline_picks_fast_executor")


async def test_routing_excludes_embedding_only_model():
    from models.routing_engine import RoutingStrategy
    engine = _routing(RoutingStrategy.AUTO)
    # nomic-embed-text must never be offered for a chat role.
    assert "nomic-embed-text" not in engine._chat_capable
    print("  PASS  routing_excludes_embedding_only_model")


async def test_routing_strategy_switch_changes_executor():
    from models.model_registry import ModelRole
    from models.routing_engine import RoutingStrategy
    from models.routed_model import RoutedModel

    engine = _routing(RoutingStrategy.AUTO)
    routed = RoutedModel(engine, FakePool(), primary_model_id="qwen2.5:14b")

    # AUTO scores executor by role only → 14B (higher executor_score) wins.
    assert routed.model_for(ModelRole.EXECUTOR) == "qwen2.5:14b"
    # Switching to PIPELINE (speed-weighted) flips it to the 7B.
    routed.set_strategy(RoutingStrategy.PIPELINE)
    assert routed.model_for(ModelRole.EXECUTOR) == "qwen2.5:7b"
    print("  PASS  routing_strategy_switch_changes_executor")


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
    test_context_builder_tool_result_function_calling()
    test_context_builder_tool_result_json_mode()

    print("\nAgentController")
    await test_agent_direct_response()
    await test_agent_tool_call_then_response()
    await test_agent_json_mode_tool_call()
    await test_agent_verifier_retry()
    await test_agent_verifier_off_by_default()
    await test_agent_max_iterations()

    print("\nModelRouting")
    await test_routing_pipeline_picks_fast_executor()
    await test_routing_excludes_embedding_only_model()
    await test_routing_strategy_switch_changes_executor()

    print("\n" + "─" * 40)
    print("All tests passed.\n")


if __name__ == "__main__":
    asyncio.run(run_all())
