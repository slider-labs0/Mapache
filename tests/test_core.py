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
from core.conversation_chain import ConversationChain


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


async def test_agent_plan_dispatches_and_seeds_todos():
    model = MockModel()
    # A plan must dispatch its first_tool AND seed the persistent task list,
    # not be returned as a final answer (the plan-dispatch bug regression).
    model.queue(json.dumps({
        "type": "plan",
        "todos": ["scan host", "enumerate services", "find flag"],
        "first_tool": "shell",
        "first_args": {"cmd": "nmap"},
    }))
    model.queue(json.dumps({"type": "response", "content": "done"}))

    controller = AgentController(model_provider=model, use_function_calling=False)
    controller.register_tool(ToolSchema(
        name="shell", description="Run a shell command",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    ))
    await controller.start()

    response = await controller.run("scan it", session_id="plan-test")

    assert "shell" in response.tool_calls_made, "plan did not dispatch first_tool"
    todos = controller.chain.todos
    assert [t.task for t in todos] == ["scan host", "enumerate services", "find flag"]
    assert todos[0].status == "in_progress"
    print("  PASS  agent_plan_dispatches_and_seeds_todos")


async def test_agent_reask_on_malformed():
    model = MockModel()
    # 1) structured-but-invalid output (unknown type, no usable keys)
    model.queue(json.dumps({"type": "thinking", "text": "hmm"}))
    # 2) after the reask, a clean final answer
    model.queue(json.dumps({"type": "response", "content": "recovered"}))

    controller = AgentController(model_provider=model, use_function_calling=False)
    await controller.start()

    response = await controller.run("do it", session_id="reask-test")

    assert response.content == "recovered"
    # malformed turn + recovered turn = 2 iterations (reask is in-band).
    assert response.iterations == 2, response.iterations
    print("  PASS  agent_reask_on_malformed")


async def test_agent_multi_tool_calls():
    model = MockModel()
    # One turn issuing two independent tool calls, then a final answer.
    model.queue(json.dumps({"type": "tool_calls", "calls": [
        {"tool": "shell", "args": {"cmd": "whoami"}},
        {"tool": "shell", "args": {"cmd": "hostname"}},
    ]}))
    model.queue(json.dumps({"type": "response", "content": "both ran"}))

    controller = AgentController(model_provider=model, use_function_calling=False)
    controller.register_tool(ToolSchema(
        name="shell", description="Run a shell command",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    ))
    await controller.start()

    response = await controller.run("who and where am I", session_id="multi-test")

    # Both calls dispatched within a single model turn (2 tools, 2 iterations).
    assert response.tool_calls_made.count("shell") == 2, response.tool_calls_made
    assert response.iterations == 2, response.iterations
    assert response.content == "both ran"
    print("  PASS  agent_multi_tool_calls")


async def test_agent_streaming_unified():
    # A native-tool-calling model exposing chat_stream: turn 1 streams thinking
    # text then a tool call, turn 2 streams the final answer. Streaming must run
    # through the full loop (tool dispatch happens), and tokens reach on_token.
    class StreamModel:
        supports_tools = True

        def __init__(self):
            self.turn = 0

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            return {"message": {"content": ""}}

        async def chat_stream(self, messages, tools=None):
            self.turn += 1
            if self.turn == 1:
                for t in ["Scanning ", "now. "]:
                    yield t
                yield {"type": "tool_call", "tool": "shell", "args": {"cmd": "nmap"}}
            else:
                for t in ["Ports ", "22,80 ", "open."]:
                    yield t

    model = StreamModel()
    controller = AgentController(
        model_provider=model, mode=AgentMode.AGENT, use_function_calling=True,
    )
    controller.register_tool(ToolSchema(
        name="shell", description="Run a shell command",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    ))
    await controller.start()

    tokens: list[str] = []
    response = await controller.run("scan it", session_id="stream-test", on_token=tokens.append)

    streamed = "".join(tokens)
    assert "Scanning now." in streamed, streamed
    assert "Ports 22,80 open." in streamed, streamed
    assert "shell" in response.tool_calls_made
    assert response.content == "Ports 22,80 open."
    assert response.iterations == 2
    print("  PASS  agent_streaming_unified")


async def test_agent_context_compaction():
    # Over-budget history should be summarized into a running summary and
    # dropped from the window, not silently trimmed away.
    class SummarizingModel:
        supports_tools = False

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            if messages and "compress" in messages[0].get("content", ""):
                return {"message": {"content": "BRIEFING: target 10.0.0.5, ports 22,80 open."}}
            return {"message": {"content": "ok"}}

    controller = AgentController(
        model_provider=SummarizingModel(), mode=AgentMode.AGENT,
        use_function_calling=False, max_context_tokens=1200,
        enable_delegation=False,  # keep the tiny test budget free of tool reserve
    )
    await controller.start()

    for i in range(12):
        controller.context.add_user_message(f"observation {i} " + "y" * 200)

    assert controller.context.needs_compaction()
    before = len(controller.context._history)
    await controller._maybe_compact("compact-test")
    after = len(controller.context._history)

    assert after < before, (before, after)
    assert "BRIEFING" in controller.context.running_summary
    assert not controller.context.needs_compaction()
    # The summary rides in the system prompt so continuity survives.
    assert "CONVERSATION SO FAR" in controller.context._build_system_prompt()
    print("  PASS  agent_context_compaction")


async def test_agent_mid_run_steering():
    # A steering message queued mid-turn must be injected into the context
    # before the next model call and update the tracked target.
    class SteerProbe:
        supports_tools = False

        def __init__(self):
            self.turn = 0
            self.ctrl = None
            self.saw_steer = False

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            self.turn += 1
            if self.turn == 1:
                self.ctrl.steer("actually the target is 10.9.9.9, rescan it")
                return json.dumps({"type": "tool_call", "tool": "shell", "args": {"cmd": "id"}})
            joined = " ".join(m.get("content", "") for m in messages)
            self.saw_steer = "[operator steering]" in joined and "10.9.9.9" in joined
            return json.dumps({"type": "response", "content": "redirected"})

    model = SteerProbe()
    controller = AgentController(
        model_provider=model, mode=AgentMode.AGENT, use_function_calling=False,
    )
    model.ctrl = controller
    controller.register_tool(ToolSchema(
        name="shell", description="Run a shell command",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    ))
    await controller.start()

    response = await controller.run("start on 10.1.1.1", session_id="steer-test")

    assert model.saw_steer, "steering message was not injected"
    assert controller.chain.attack_state.target == "10.9.9.9"
    assert response.content == "redirected"
    assert controller._drain_steering() == []  # inbox fully drained
    print("  PASS  agent_mid_run_steering")


async def test_agent_delegation():
    class Dispatcher:
        async def dispatch(self, name, args, session_id):
            return "HTB{sub_flag} found" if name == "shell" else "ok"

    class DelegModel:
        # Routes by inspecting the visible messages: parent delegates, child
        # runs a tool then reports a flag, parent then finishes.
        supports_tools = False

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            joined = " ".join(m.get("content", "") for m in messages)
            if "enumerate port 80" in joined and "HTB{sub_flag}" not in joined:
                return json.dumps({"type": "tool_call", "tool": "shell", "args": {"cmd": "curl"}})
            if "HTB{sub_flag}" in joined and "subagent result" not in joined:
                return json.dumps({"type": "response", "content": "Found HTB{sub_flag} on port 80"})
            if "subagent result" in joined:
                return json.dumps({"type": "response", "content": "done"})
            return json.dumps({"type": "tool_call", "tool": "delegate",
                               "args": {"task": "enumerate port 80 and report"}})

    controller = AgentController(
        model_provider=DelegModel(), tool_dispatcher=Dispatcher(),
        mode=AgentMode.AGENT, use_function_calling=False,
    )
    await controller.start()

    # The delegate tool is offered at the top level...
    assert "delegate" in controller.context.available_tools
    # ...but a depth-1 agent (a sub-agent) must NOT be able to delegate further.
    deep = AgentController(model_provider=DelegModel(), delegation_depth=1)
    assert "delegate" not in deep.context.available_tools

    response = await controller.run("pwn the web box", session_id="deleg-test")

    assert "delegate" in response.tool_calls_made
    # Sub-agent's finding merged back into the parent's attack state.
    assert "HTB{sub_flag}" in controller.chain.attack_state.flags
    assert response.content == "done"
    print("  PASS  agent_delegation")


async def test_mcp_client():
    import os
    import sys as _sys
    from integrations.mcp import MCPManager, MCPServerConfig
    from tools.tool_dispatcher import ToolDispatcher
    from tools.tool_registry import ToolRegistry

    server = os.path.join(os.path.dirname(__file__), "fake_mcp_server.py")
    cfg = MCPServerConfig(name="fake", command=_sys.executable, args=[server])
    mgr = MCPManager([cfg])
    try:
        tools = await mgr.connect_all()
        assert tools and tools[0].name == "mcp__fake__echo", [t.name for t in tools]

        registry = ToolRegistry()
        for t in tools:
            registry.register(t)
        dispatcher = ToolDispatcher(registry)

        out = await dispatcher.dispatch("mcp__fake__echo", {"text": "hi"}, "sess")
        assert out == "echo: hi", out
        bad = await dispatcher.dispatch("mcp__fake__echo", {}, "sess")
        assert "Invalid arguments" in bad

        # Phase subsetting must keep MCP tools exposed once pinned.
        chain = ConversationChain()
        names = {t.name for t in tools}
        chain.always_tools |= names
        active = chain.active_tool_names(names | {"nmap_scan"})
        assert names <= active, (names, active)
    finally:
        await mgr.close_all()
    print("  PASS  mcp_client")


async def test_agent_duplicate_call_guard():
    # The same tool+args repeated within a turn must run once; later identical
    # calls are short-circuited with the cached result, breaking no-progress
    # loops (the "fetch the same URL 5 times" bug).
    class FetchStub:
        def __init__(self):
            self.hits = 0

        async def dispatch(self, name, args, session_id):
            self.hits += 1
            return "blocked by robot policy"

    class LoopModel:
        supports_tools = False

        def __init__(self):
            self.n = 0

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            self.n += 1
            if self.n <= 4:
                return json.dumps({"type": "tool_call", "tool": "web_fetch",
                                   "args": {"url": "http://x/wiki/VM"}})
            return json.dumps({"type": "response", "content": "Virtual Machine"})

    dispatcher = FetchStub()
    controller = AgentController(
        model_provider=LoopModel(), tool_dispatcher=dispatcher,
        mode=AgentMode.AGENT, use_function_calling=False,
    )
    controller.register_tool(ToolSchema(
        name="web_fetch", description="fetch a url",
        parameters={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    ))
    await controller.start()

    response = await controller.run("what does VM stand for", session_id="dup-test")

    assert dispatcher.hits == 1, dispatcher.hits  # only the first identical call ran
    assert response.content == "Virtual Machine"
    print("  PASS  agent_duplicate_call_guard")


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
# Self-authored tools (generated tools + curator) — feature A
# ------------------------------------------------------------------ #

import tempfile
from datetime import datetime, timedelta, timezone

from tools.tool_registry import ToolRegistry
from tools.tool_dispatcher import ToolDispatcher
from tools.generated_tool import (
    STATE_ACTIVE, STATE_STALE, STATE_ARCHIVED,
    write_generated_tool, load_generated_tool, load_manifest, save_manifest,
    sha256_of,
)
from tools.generated_tool_manager import GeneratedToolManager, build_meta_tools


def _gen_env(tmp: str):
    """Build a registry + dispatcher + controller + manager rooted at tmp."""
    registry = ToolRegistry()
    dispatcher = ToolDispatcher(registry)
    controller = AgentController(
        model_provider=MockModel(), tool_dispatcher=dispatcher,
        mode=AgentMode.AGENT,
    )

    async def fake_shell(cmd: str) -> str:
        return f"ran:{cmd}"

    mgr = GeneratedToolManager(registry, controller, base_dir=tmp, shell=fake_shell)
    for t in build_meta_tools(mgr):
        registry.register(t)
    return registry, dispatcher, controller, mgr


async def test_generated_tool_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        async def shell(cmd):
            return f"ran:{cmd}"

        tool_dir = write_generated_tool(
            tmp, "echo_host", "echo a host",
            {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
            'out = await shell("scan " + args["host"])\nreturn "got:" + out',
            phase="recon",
        )
        tool = load_generated_tool(tool_dir, shell=shell)
        assert tool.name == "echo_host"
        assert tool.phase == "recon"
        result = await tool(host="box")
        assert result.success and result.output == "got:ran:scan box", result.output
    print("  PASS  generated_tool_roundtrip")


async def test_generated_tool_manager_create_and_dispatch():
    with tempfile.TemporaryDirectory() as tmp:
        registry, dispatcher, controller, mgr = _gen_env(tmp)

        # Author a tool via the model-callable meta-tool (end-to-end wiring).
        out = await dispatcher.dispatch("create_tool", {
            "name": "greet",
            "description": "greet a host",
            "parameters": {"type": "object",
                           "properties": {"host": {"type": "string"}},
                           "required": ["host"]},
            "code": 'return "hi " + args["host"]',
            "phase": "recon",
        })
        assert "Created" in out, out

        # Registered everywhere: registry, model context, and chain phase map.
        assert registry.has("greet")
        assert "greet" in controller.context.available_tools
        assert controller.chain.generated_tools.get("greet") == "recon"

        # Exposed for its phase, hidden in another phase.
        controller.chain.attack_state.current_phase = "recon"
        assert "greet" in controller.chain.active_tool_names(registry.list_names())
        controller.chain.attack_state.current_phase = "post"
        assert "greet" not in controller.chain.active_tool_names(registry.list_names())

        # Callable, and usage is tracked on disk.
        res = await dispatcher.dispatch("greet", {"host": "box"}, "")
        assert res == "hi box", res
        manifest = load_manifest(mgr.tools["greet"].tool_dir)
        assert manifest["use_count"] == 1 and manifest["last_used"]
    print("  PASS  generated_tool_manager_create_and_dispatch")


async def test_generated_tool_create_rejects_bad():
    with tempfile.TemporaryDirectory() as tmp:
        registry, dispatcher, controller, mgr = _gen_env(tmp)
        good_params = {"type": "object", "properties": {}}

        assert "invalid tool name" in mgr.create("Bad Name", "d", good_params, "return 1")
        assert "already exists" in mgr.create("create_tool", "d", good_params, "return 1")
        assert "JSON Schema object" in mgr.create("ok1", "d", {"type": "array"}, "return 1")
        assert "did not compile" in mgr.create("ok2", "d", good_params, "return (")
        assert not registry.has("ok2")  # broken code never lands registered
    print("  PASS  generated_tool_create_rejects_bad")


async def test_generated_tool_curator_lifecycle():
    with tempfile.TemporaryDirectory() as tmp:
        registry, dispatcher, controller, mgr = _gen_env(tmp)
        mgr.create("oneoff", "experiment", {"type": "object", "properties": {}},
                   'return "ok"', phase="always")

        # Force "never used, old" so the staleness rule fires.
        tool = mgr.tools["oneoff"]
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        tool.manifest["created"] = old
        save_manifest(tool.tool_dir, tool.manifest)

        assert mgr.refresh_states() == ["oneoff"]
        assert tool.state == STATE_STALE
        assert [n for n, _ in mgr.stale_candidates()] == ["oneoff"]

        # Using a stale tool auto-promotes it back to active.
        await dispatcher.dispatch("oneoff", {}, "")
        assert mgr.tools["oneoff"].state == STATE_ACTIVE

        # Purge refuses a live tool — a hard delete must be a deliberate two-step.
        assert "must be archived" in mgr.purge("oneoff")

        # Archive (the permissioned step): unregistered + folder moved aside.
        assert "Archived" in mgr.archive("oneoff")
        assert not registry.has("oneoff")
        assert "oneoff" not in controller.context.available_tools
        assert "oneoff" not in controller.chain.generated_tools
        assert "oneoff" in mgr.archived_names()

        # Restore brings it back, active and callable again.
        assert "Restored" in mgr.restore("oneoff")
        assert registry.has("oneoff")
        assert mgr.tools["oneoff"].state == STATE_ACTIVE

        # Finally, archive + purge actually removes it for good.
        mgr.archive("oneoff")
        assert "Purged" in mgr.purge("oneoff")
        assert "oneoff" not in mgr.archived_names()
    print("  PASS  generated_tool_curator_lifecycle")


async def test_generated_tool_hub_checksum():
    with tempfile.TemporaryDirectory() as tmp:
        # A hub-origin tool whose tool.py is tampered must refuse to load.
        tool_dir = write_generated_tool(
            tmp, "hub_tool", "from the hub",
            {"type": "object", "properties": {}}, 'return "ok"',
            origin="hub",
        )
        # Loads clean while the checksum matches.
        load_generated_tool(tool_dir, shell=None)
        (tool_dir / "tool.py").write_text(
            (tool_dir / "tool.py").read_text(encoding="utf-8") + "\n# tampered\n",
            encoding="utf-8",
        )
        try:
            load_generated_tool(tool_dir, shell=None)
            raise AssertionError("tampered hub tool should not load")
        except ValueError as exc:
            assert "checksum" in str(exc)
    print("  PASS  generated_tool_hub_checksum")


# ------------------------------------------------------------------ #
# Config layer (feature C0)
# ------------------------------------------------------------------ #

from pathlib import Path as _CfgPath
from core.config import load_config, ProviderConfig, global_config_path


def _write_json(path, data):
    _CfgPath(path).write_text(json.dumps(data), encoding="utf-8")


def test_config_defaults():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = load_config(working_dir=tmp, environ={},
                          global_path=_CfgPath(tmp) / "nope.json")
        assert cfg.default_model == "deepseek-coder:33b"
        assert cfg.default_strategy == "single"
        assert cfg.allow_cloud is False
        assert cfg.providers["ollama"].is_usable          # local always usable
        assert not cfg.providers["openrouter"].is_usable  # no key
    print("  PASS  config_defaults")


def test_config_precedence_chain():
    with tempfile.TemporaryDirectory() as tmp:
        gpath = _CfgPath(tmp) / "global.json"
        _write_json(gpath, {"default_model": "from-global",
                            "default_strategy": "auto"})
        _write_json(_CfgPath(tmp) / "mapache.json", {"default_model": "from-project"})

        # global < project: project wins on model, global still supplies strategy.
        cfg = load_config(working_dir=tmp, environ={}, global_path=gpath)
        assert cfg.default_model == "from-project"
        assert cfg.default_strategy == "auto"

        # CLI overrides win over everything.
        cfg2 = load_config({"default_model": "from-cli"},
                           working_dir=tmp, environ={}, global_path=gpath)
        assert cfg2.default_model == "from-cli"
    print("  PASS  config_precedence_chain")


def test_config_env_layer_and_interpolation():
    with tempfile.TemporaryDirectory() as tmp:
        gpath = _CfgPath(tmp) / "g.json"
        # api_key references an env var; env also supplies the ollama url.
        _write_json(gpath, {"providers": {
            "openrouter": {"kind": "openai_compatible",
                           "api_key": "${OPENROUTER_API_KEY}",
                           "models": ["x/y"], "enabled": True}}})
        env = {"OPENROUTER_API_KEY": "sk-secret", "OLLAMA_URL": "http://host:1"}
        cfg = load_config(working_dir=tmp, environ=env, global_path=gpath)
        assert cfg.providers["openrouter"].api_key == "sk-secret"
        assert cfg.providers["openrouter"].is_usable
        assert cfg.ollama_url == "http://host:1"

        # Unresolved ${VAR} collapses to empty (never a literal token).
        cfg2 = load_config(working_dir=tmp, environ={}, global_path=gpath)
        assert cfg2.providers["openrouter"].api_key == ""
        assert not cfg2.providers["openrouter"].is_usable
    print("  PASS  config_env_layer_and_interpolation")


def test_config_provider_for_model_and_redaction():
    with tempfile.TemporaryDirectory() as tmp:
        gpath = _CfgPath(tmp) / "g.json"
        _write_json(gpath, {"providers": {
            "openrouter": {"kind": "openai_compatible", "api_key": "sk-abcdef",
                           "models": ["anthropic/claude"], "enabled": True}}})
        cfg = load_config(working_dir=tmp, environ={}, global_path=gpath)

        # Cloud model routes to its provider; unknown model falls back to ollama.
        assert cfg.provider_for_model("anthropic/claude").name == "openrouter"
        assert cfg.provider_for_model("qwen2.5:14b").name == "ollama"
        assert cfg.cloud_models() == ["anthropic/claude"]

        # Redaction masks the key but keeps the tail for recognisability.
        red = cfg.redacted()
        assert red["providers"]["openrouter"]["api_key"] == "***cdef"
        assert "sk-abcdef" not in json.dumps(red)
    print("  PASS  config_provider_for_model_and_redaction")


def test_config_global_path_resolution():
    # $MAPACHE_CONFIG wins; otherwise USERPROFILE/HOME drives the default path.
    assert global_config_path({"MAPACHE_CONFIG": "/tmp/x.json"}) == _CfgPath("/tmp/x.json")
    p = global_config_path({"USERPROFILE": "/home/op"})
    assert p.parts[-2:] == (".mapache", "config.json")
    print("  PASS  config_global_path_resolution")


# ------------------------------------------------------------------ #
# Setup wizard (feature C1)
# ------------------------------------------------------------------ #

from core.config import load_global_raw, save_global_config


def test_config_save_and_raw_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        gpath = _CfgPath(tmp) / "config.json"
        assert load_global_raw(gpath) == {}  # missing file → empty, fail-soft

        data = {"default_model": "qwen2.5:32b",
                "providers": {"openrouter": {"api_key": "${OPENROUTER_API_KEY}",
                                             "models": ["a/b"], "enabled": True}}}
        out = save_global_config(data, gpath)
        assert out == gpath and gpath.is_file()
        # Raw read is verbatim — the ${VAR} placeholder is preserved, not resolved.
        raw = load_global_raw(gpath)
        assert raw["providers"]["openrouter"]["api_key"] == "${OPENROUTER_API_KEY}"

        # And load_config layers it normally (interpolates against the env).
        cfg = load_config(working_dir=tmp, environ={"OPENROUTER_API_KEY": "sk-zzzz"},
                          global_path=gpath)
        assert cfg.default_model == "qwen2.5:32b"
        assert cfg.providers["openrouter"].api_key == "sk-zzzz"
    print("  PASS  config_save_and_raw_roundtrip")


def test_wizard_prefs_edit_raw():
    # _step_prefs mutates the raw dict from typed input; empty input keeps current.
    import builtins
    from cli import setup_wizard

    with tempfile.TemporaryDirectory() as tmp:
        cfg = load_config(working_dir=tmp, environ={},
                          global_path=_CfgPath(tmp) / "none.json")
        raw: dict = {}
        answers = iter(["qwen2.5:32b", "", "16"])  # model, keep strategy, vram
        orig_input = builtins.input
        builtins.input = lambda *a, **k: next(answers)
        try:
            model = setup_wizard._step_prefs(cfg, raw)
        finally:
            builtins.input = orig_input

        assert model == "qwen2.5:32b"
        assert raw["default_model"] == "qwen2.5:32b"
        assert raw["default_strategy"] == cfg.default_strategy  # kept on empty
        assert raw["max_vram_gb"] == 16.0
    print("  PASS  wizard_prefs_edit_raw")


def test_wizard_secret_prompt_preserves_on_empty():
    # Empty input → (current, changed=False) so a ${ENV} placeholder is untouched.
    import builtins
    from cli import setup_wizard

    orig_input = builtins.input
    builtins.input = lambda *a, **k: ""        # operator hits Enter
    try:
        val, changed = setup_wizard._prompt_secret("key", "${OPENROUTER_API_KEY}")
    finally:
        builtins.input = orig_input
    assert val == "${OPENROUTER_API_KEY}" and changed is False

    builtins.input = lambda *a, **k: "sk-new"  # operator types a new key
    try:
        val2, changed2 = setup_wizard._prompt_secret("key", "old")
    finally:
        builtins.input = orig_input
    assert val2 == "sk-new" and changed2 is True
    print("  PASS  wizard_secret_prompt_preserves_on_empty")


def test_cli_overrides_and_config_precedence():
    # The REPL resolves settings through MapacheConfig: unset flags fall through
    # to the saved config, an explicit flag still wins (the C1 gap closure).
    from argparse import Namespace
    from cli.mapache_cli import MapacheCLI

    # Sparse: nothing passed → no override layer at all.
    none_args = Namespace(model=None, strategy=None, ollama_url=None,
                          max_vram=None, allow_cloud=False)
    assert MapacheCLI._cli_overrides(none_args) == {}

    # Each explicit flag maps to its config path (ollama_url nests under providers).
    set_args = Namespace(model="m", strategy="auto", ollama_url="http://h:1",
                         max_vram="20", allow_cloud=True)
    ov = MapacheCLI._cli_overrides(set_args)
    assert ov["default_model"] == "m"
    assert ov["default_strategy"] == "auto"
    assert ov["providers"]["ollama"]["base_url"] == "http://h:1"
    assert ov["max_vram_gb"] == 20.0
    assert ov["allow_cloud"] is True

    with tempfile.TemporaryDirectory() as tmp:
        gpath = _CfgPath(tmp) / "config.json"
        _write_json(gpath, {"default_model": "saved-by-wizard",
                            "default_strategy": "hybrid"})
        # No --model: the wizard-saved global value is honored.
        cfg = load_config(MapacheCLI._cli_overrides(none_args), working_dir=tmp,
                          environ={}, global_path=gpath)
        assert cfg.default_model == "saved-by-wizard"
        assert cfg.default_strategy == "hybrid"
        # Explicit --model overrides the saved value.
        cfg2 = load_config(MapacheCLI._cli_overrides(set_args), working_dir=tmp,
                           environ={}, global_path=gpath)
        assert cfg2.default_model == "m"
    print("  PASS  cli_overrides_and_config_precedence")


# ------------------------------------------------------------------ #
# Cloud providers (feature G)
# ------------------------------------------------------------------ #

from core.config import MapacheConfig
from models.providers.openai_compatible import OpenAICompatibleProvider
from models.providers.ollama_provider import OllamaProvider
from models.model_pool import ModelPool
from models.model_registry import ModelProfile, Provider


async def test_openai_provider_normalizes_response():
    p = OpenAICompatibleProvider(model="anthropic/claude", base_url="https://x/v1",
                                 api_key="sk-test")

    async def fake_post(path, payload):
        # Native OpenAI shape: choices[0].message with string tool arguments.
        return {"choices": [{"message": {
            "content": "hello",
            "tool_calls": [{"type": "function", "function": {
                "name": "shell", "arguments": '{"cmd":"id"}'}}],
        }}]}

    p._post = fake_post
    out = await p.chat(messages=[{"role": "user", "content": "hi"}], tools=[{"x": 1}])
    # Normalized to the {"message": {...}} shape the controller reads.
    assert out["message"]["content"] == "hello"
    call = out["message"]["tool_calls"][0]["function"]
    assert call["name"] == "shell" and call["arguments"] == '{"cmd":"id"}'
    await p.close()
    print("  PASS  openai_provider_normalizes_response")


def test_model_pool_provider_selection():
    cfg = MapacheConfig.from_dict({"providers": {
        "ollama": {"kind": "ollama", "base_url": "http://localhost:11434"},
        "openrouter": {"kind": "openai_compatible", "base_url": "https://or/v1",
                       "api_key": "sk-x", "models": ["anthropic/claude"]},
    }})
    pool = ModelPool(base_url="http://localhost:11434", config=cfg)
    assert isinstance(pool.get("anthropic/claude"), OpenAICompatibleProvider)
    assert isinstance(pool.get("qwen2.5:14b"), OllamaProvider)  # falls back to ollama
    # Without a config it stays Ollama-only.
    plain = ModelPool(base_url="http://localhost:11434")
    assert isinstance(plain.get("anything"), OllamaProvider)
    print("  PASS  model_pool_provider_selection")


def test_model_profile_is_local_gate():
    # A free cloud model must NOT count as local (else it bypasses --allow-cloud).
    free_cloud = ModelProfile(id="x/y", provider=Provider.OPENROUTER,
                              cost_per_1k_tokens=0.0)
    assert free_cloud.is_local is False
    local = ModelProfile(id="qwen2.5:14b", provider=Provider.OLLAMA)
    assert local.is_local is True
    print("  PASS  model_profile_is_local_gate")


# ------------------------------------------------------------------ #
# Rules-of-Engagement guardrails (feature J)
# ------------------------------------------------------------------ #

from core.engagement_scope import EngagementScope, load_scope


def test_scope_inactive_allows_everything():
    s = EngagementScope()
    assert not s.active
    # A wordlist path that vaguely resembles a host must not be flagged when no
    # scope is defined (and the precision rules keep it safe even if it were).
    assert s.check("kali_run",
                   {"args": "dir -w /usr/share/wordlists/common.txt"}).allowed
    print("  PASS  scope_inactive_allows_everything")


def test_scope_target_allowlist():
    s = EngagementScope.from_dict(
        {"name": "eng", "targets": ["10.10.10.0/24", "acme.example.com"]})
    assert s.active
    # In-scope IP inside the CIDR.
    assert s.check("nmap_scan", {"target": "10.10.10.5"}).allowed
    # Out-of-scope IP refused; the reason names the offending target.
    d = s.check("nmap_scan", {"target": "8.8.8.8"})
    assert not d.allowed and "8.8.8.8" in d.reason
    # Subdomain of an allowed host is in scope; an unrelated host is not.
    assert s.check("web_fetch", {"url": "https://api.acme.example.com/x"}).allowed
    assert not s.check("web_fetch", {"url": "http://evil.com/"}).allowed
    # Loopback + local utility calls are the operator's own box → allowed.
    assert s.check("shell", {"cmd": "whoami"}).allowed
    assert s.check("nmap_scan", {"target": "127.0.0.1"}).allowed
    # A bare filename in a non-target arg key is NOT treated as a host.
    assert s.check("kali_run", {"args": "-w common.txt -u 10.10.10.5"}).allowed
    print("  PASS  scope_target_allowlist")


def test_scope_fallback_target_and_ip_in_command():
    s = EngagementScope.from_dict({"targets": ["10.10.10.0/24"]})
    # A backfilled target (model omitted it) is still checked.
    assert not s.check("nmap_scan", {}, fallback_target="9.9.9.9").allowed
    assert s.check("nmap_scan", {}, fallback_target="10.10.10.7").allowed
    # An out-of-scope IP embedded in a free-form shell command is caught.
    assert not s.check("shell", {"cmd": "telnet 9.9.9.9 23"}).allowed
    print("  PASS  scope_fallback_target_and_ip_in_command")


def test_scope_forbidden_tools_and_patterns():
    s = EngagementScope.from_dict({
        "targets": ["10.10.10.0/24"],
        "forbidden_tools": ["msf_run"],
        "forbidden_patterns": ["rm -rf"],
    })
    # Forbidden tool refused even against an in-scope target.
    assert not s.check("msf_run", {"target": "10.10.10.5"}).allowed
    # Forbidden command pattern refused.
    assert not s.check("shell", {"cmd": "rm -rf /"}).allowed
    # Otherwise-permitted call still allowed.
    assert s.check("nmap_scan", {"target": "10.10.10.5"}).allowed
    print("  PASS  scope_forbidden_tools_and_patterns")


def test_scope_load_fail_soft():
    # Missing path / file → an inactive scope (fail-soft, never raises).
    assert not load_scope(None).active
    assert not load_scope(_CfgPath("does") / "not" / "exist.json").active
    with tempfile.TemporaryDirectory() as tmp:
        p = _CfgPath(tmp) / "scope.json"
        _write_json(p, {"targets": ["10.0.0.0/8"]})
        s = load_scope(p)
        assert s.active and s.check("nmap_scan", {"target": "10.1.2.3"}).allowed
    print("  PASS  scope_load_fail_soft")


async def test_controller_scope_refusal():
    # The controller refuses an out-of-scope tool call before dispatch, feeds the
    # refusal back to the model, and emits agent.scope_refused (feeds K later).
    model = MockModel()
    model.queue({"message": {"content": "", "tool_calls": [
        {"function": {"name": "nmap_scan", "arguments": {"target": "8.8.8.8"}}}]}})
    model.queue({"message": {"content": "That target is out of scope; stopping."}})

    scope = EngagementScope.from_dict({"name": "eng", "targets": ["10.10.10.0/24"]})
    controller = AgentController(model_provider=model, mode=AgentMode.AGENT, scope=scope)
    controller.register_tool(ToolSchema(
        name="nmap_scan", description="scan",
        parameters={"type": "object", "properties": {"target": {"type": "string"}},
                    "required": ["target"]}))

    refused: list[dict] = []

    async def _capture(event):
        refused.append(event.data)
    controller.bus.subscribe("agent.scope_refused", _capture)
    await controller.start()

    response = await controller.run("scan 8.8.8.8", session_id="scope-test")

    assert refused and refused[0]["tool_name"] == "nmap_scan"
    # Refused calls are never dispatched, so they don't count as tools used.
    assert "nmap_scan" not in response.tool_calls_made
    # The model saw the refusal in the next turn's context.
    second = model.calls[1]["messages"]
    assert any("REFUSED by engagement scope" in (m.get("content") or "")
               for m in second)
    print("  PASS  controller_scope_refusal")


# ------------------------------------------------------------------ #
# Auditable engagement log (feature K)
# ------------------------------------------------------------------ #

import tempfile
from core.engagement_log import EngagementLog


async def test_engagement_log_captures_and_exports():
    with tempfile.TemporaryDirectory() as tmp:
        bus = EventBus()
        log = EngagementLog(path=_CfgPath(tmp) / "eng.jsonl", session_id="s1")
        log.attach(bus, metadata={"model": "m"})

        await bus.emit("task.result", {
            "tool_name": "nmap_scan", "args": {"target": "10.0.0.1"},
            "output": "22/tcp open ssh", "error": None, "session_id": "s1"})
        await bus.emit("agent.finding", {
            "finding_type": "open_port", "value": "22/tcp",
            "target": "10.0.0.1", "session_id": "s1"})
        await bus.emit("agent.scope_refused", {
            "tool_name": "nmap_scan", "reason": "out of scope", "session_id": "s1"})
        await bus.emit("some.other.topic", {"x": 1})  # not in the allowlist → ignored
        log.close(summary={"flags": 0})

        c = log.counts()
        assert c["tool_call"] == 1 and c["finding"] == 1 and c["scope_refused"] == 1
        assert c["session_start"] == 1 and c["session_end"] == 1

        # JSONL: one valid-JSON line per record; bracketed by start/end.
        lines = (_CfgPath(tmp) / "eng.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == len(log.records)
        recs = [json.loads(ln) for ln in lines]
        assert recs[0]["kind"] == "session_start" and recs[-1]["kind"] == "session_end"
        # The off-allowlist topic left no trace.
        assert all(r["kind"] != "other" for r in recs)

        # Records are frozen after close (an audit trail isn't retroactively edited).
        log.record("tool_call", {"tool": "late"})
        assert log.counts()["tool_call"] == 1

        # Markdown export carries the finding + a readable timeline.
        md = log.export_markdown().read_text(encoding="utf-8")
        assert "Findings" in md and "22/tcp" in md and "nmap_scan" in md
    print("  PASS  engagement_log_captures_and_exports")


async def test_controller_emits_tool_call_and_finding_events():
    # The controller feeds the log: task.result now carries args, and a newly
    # discovered flag fires agent.finding.
    model = MockModel()
    model.queue({"message": {"content": "", "tool_calls": [
        {"function": {"name": "shell", "arguments": {"cmd": "cat root.txt"}}}]}})
    model.queue({"message": {"content": "Flag captured."}})

    controller = AgentController(model_provider=model, mode=AgentMode.AGENT)
    controller.register_tool(ToolSchema(
        name="shell", description="run",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}},
                    "required": ["cmd"]}))

    class FakeDispatcher:
        async def dispatch(self, name, args, session_id=""):
            return "uid=0(root) — HTB{rooted_box}"
    controller.tool_dispatcher = FakeDispatcher()

    tool_calls: list[dict] = []
    findings: list[dict] = []

    async def cap_tool(e):
        tool_calls.append(e.data)

    async def cap_find(e):
        findings.append(e.data)
    controller.bus.subscribe("task.result", cap_tool)
    controller.bus.subscribe("agent.finding", cap_find)
    await controller.start()

    await controller.run("get the flag", session_id="k-test")

    assert tool_calls and tool_calls[0]["tool_name"] == "shell"
    assert tool_calls[0]["args"] == {"cmd": "cat root.txt"}  # args ride the event now
    assert any(f["finding_type"] == "flag" and "HTB{rooted_box}" in f["value"]
               for f in findings)
    print("  PASS  controller_emits_tool_call_and_finding_events")


# ------------------------------------------------------------------ #
# Multi-agent blackboard (feature P, increment 1)
# ------------------------------------------------------------------ #

from core.conversation_chain import AttackState


def test_shared_blackboard_semantics():
    # A sub-agent shares the lead's AttackState by reference (no copy): findings
    # are live immediately, and the sub-agent can't reset the shared engagement.
    shared = AttackState(target="10.10.10.5", open_ports=["80/tcp"],
                         current_phase="enumeration")
    child = AgentController(model_provider=MockModel(), shared_state=shared,
                            allow_state_reset=False)
    assert child.chain.attack_state is shared  # same object, not a snapshot

    child.chain.attack_state.add_flag("HTB{live}")
    assert "HTB{live}" in shared.flags  # visible to the lead with no merge step

    # The sub-agent's task wording must not hijack the target or wipe findings.
    child.chain.apply_input_signals("now scan 9.9.9.9 and rescan everything")
    assert shared.target == "10.10.10.5"
    assert shared.open_ports == ["80/tcp"]
    print("  PASS  shared_blackboard_semantics")


def test_lead_state_reset_still_works():
    # The lead (allow_state_reset=True, the default) still reassigns on a new IP
    # and clears stale ports — the operator-facing behavior is unchanged.
    chain = ConversationChain()
    chain.attack_state.target = "10.0.0.1"
    chain.attack_state.open_ports = ["22/tcp"]
    chain.apply_input_signals("switch to 10.0.0.2")
    assert chain.attack_state.target == "10.0.0.2"
    assert chain.attack_state.open_ports == []
    print("  PASS  lead_state_reset_still_works")


def test_operator_roster():
    from core.operators import get_operator, operator_names, GENERALIST_ALIASES
    names = operator_names()
    for expected in ["recon_operator", "web_operator", "exploit_operator",
                     "post_operator", "osint_operator", "iot_operator",
                     "cloud_hunter", "contract_auditor", "reverser", "analyst",
                     "phisher", "mobile_operator", "wireless_operator",
                     "ics_operator", "forensicator", "supply_chain_operator"]:
        assert expected in names, expected

    # Lookup is case-insensitive; the web operator has a tight, focused toolset.
    web = get_operator("Web_Operator")
    assert web is not None
    assert "kali_run" in web.tools and "nmap_scan" not in web.tools
    assert "Web Operator" in web.system_prompt and "ONE objective" in web.system_prompt

    # Role constraints are rendered into the prompt (and reinforce feature J).
    assert "READ-ONLY" in get_operator("osint_operator").system_prompt
    assert "deconfliction" in get_operator("phisher").system_prompt
    assert "lab/canary" in get_operator("ics_operator").system_prompt
    assert "hardware passthrough" in get_operator("wireless_operator").system_prompt

    # Generalist aliases resolve to "no specialist".
    for alias in GENERALIST_ALIASES:
        assert get_operator(alias) is None
    assert get_operator("not_a_real_operator") is None
    print("  PASS  operator_roster")


async def test_delegate_operator_dispatch():
    # delegate(operator="web_operator") runs the subtask as the specialist: the
    # operator label flows to agent.delegate.start (so the engagement log records
    # it) and the turn completes.
    class Dispatcher:
        async def dispatch(self, name, args, session_id):
            return "ok"

    class DelegModel:
        supports_tools = False

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            joined = " ".join(m.get("content", "") for m in messages)
            if "subagent result" in joined:                 # lead, after the child
                return json.dumps({"type": "response", "content": "done"})
            if "Web Operator" in joined:                    # the specialist child
                return json.dumps({"type": "response", "content": "web enumerated"})
            return json.dumps({"type": "tool_call", "tool": "delegate",  # lead, first
                               "args": {"task": "enumerate the web app",
                                        "operator": "web_operator"}})

    controller = AgentController(model_provider=DelegModel(), tool_dispatcher=Dispatcher(),
                                 mode=AgentMode.AGENT, use_function_calling=False)
    controller.register_tool(ToolSchema(name="kali_run", description="run",
        parameters={"type": "object", "properties": {"tool": {"type": "string"}}}))

    events: list[dict] = []

    async def cap(e):
        events.append(e.data)
    controller.bus.subscribe("agent.delegate.start", cap)
    await controller.start()

    resp = await controller.run("test the website", session_id="op-test")
    assert events and events[0]["operator"] == "web_operator"
    assert resp.content == "done"
    print("  PASS  delegate_operator_dispatch")


async def test_delegate_parallel_fans_out():
    # delegate_parallel runs several operators concurrently over the shared
    # blackboard; both children dispatch and the lead gets a combined result.
    class Dispatcher:
        async def dispatch(self, name, args, session_id):
            return "ok"

    class DelegModel:
        supports_tools = False

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            joined = " ".join(m.get("content", "") for m in messages)
            if "Web Operator" in joined:                       # web child
                return json.dumps({"type": "response", "content": "web done"})
            if "Exploit Operator" in joined:                   # exploit child
                return json.dumps({"type": "response", "content": "exploit done"})
            if "delegate_parallel —" in joined or "subagent result" in joined:
                return json.dumps({"type": "response", "content": "all done"})  # lead, after
            return json.dumps({"type": "tool_call", "tool": "delegate_parallel", "args": {
                "tasks": [{"task": "enumerate web", "operator": "web_operator"},
                          {"task": "find exploits", "operator": "exploit_operator"}]}})

    controller = AgentController(model_provider=DelegModel(), tool_dispatcher=Dispatcher(),
                                 mode=AgentMode.AGENT, use_function_calling=False)
    controller.register_tool(ToolSchema(name="kali_run", description="run",
        parameters={"type": "object", "properties": {"tool": {"type": "string"}}}))

    started: list[str] = []

    async def cap(e):
        started.append(e.data.get("operator"))
    controller.bus.subscribe("agent.delegate.start", cap)
    await controller.start()

    resp = await controller.run("assess the host", session_id="par-test")
    assert "delegate_parallel" in resp.tool_calls_made
    assert set(started) == {"web_operator", "exploit_operator"}  # both fanned out
    assert resp.content == "all done"
    print("  PASS  delegate_parallel_fans_out")


# ------------------------------------------------------------------ #
# Automated reporting (feature L)
# ------------------------------------------------------------------ #

from reporting import build_report


def test_report_builder():
    st = AttackState(
        target="10.10.10.5", open_ports=["23/tcp", "445/tcp"],
        services={"23": "telnet", "445": "microsoft-ds"},
        vulnerabilities=["CVE-2017-0144"], credentials=["admin:password123"],
        flags=["HTB{rooted}"], current_phase="post")
    records = [
        {"ts": "t1", "kind": "finding", "finding_type": "vulnerability",
         "value": "CVE-2017-0144"},
        {"ts": "t2", "kind": "tool_call", "tool": "nmap_scan", "ok": True},
        {"ts": "t3", "kind": "scope_refused", "tool": "msf_run", "reason": "out of scope"},
    ]
    report = build_report(st, records, {"Model": "qwen"})

    # Findings span vuln, credential, notable services, and the flag.
    types = {f.finding_type for f in report.findings}
    assert {"vulnerability", "credential", "service", "flag"} <= types
    # Service rules fired (telnet + SMB are High); severity tally is populated.
    assert report.severity_counts()["High"] >= 3
    # First-seen timestamp wired from the engagement-log records.
    vuln = next(f for f in report.findings if f.finding_type == "vulnerability")
    assert vuln.discovered == "t1"
    # Markdown deliverable has the sections, evidence, remediation, and timeline.
    md = report.to_markdown()
    for needle in ("# Penetration Test Report", "Executive summary", "Findings",
                   "Remediation", "CVE-2017-0144", "Methodology"):
        assert needle in md, needle
    # Self-contained HTML.
    doc = report.to_html()
    assert doc.startswith("<!doctype html>") and "Findings" in doc
    print("  PASS  report_builder")


def test_report_redaction_and_empty():
    # Redaction masks the secret half of a credential everywhere it renders.
    st = AttackState(target="x", credentials=["root:hunter2"])
    r = build_report(st, [], {}, redact_secrets=True)
    cred = next(f for f in r.findings if f.finding_type == "credential")
    assert cred.evidence == "root:****" and "hunter2" not in r.to_markdown()
    # An empty engagement still produces a graceful, finding-free report.
    empty = build_report(AttackState(), [], {})
    assert empty.findings == [] and "no findings" in empty.to_markdown().lower()
    print("  PASS  report_redaction_and_empty")


# ------------------------------------------------------------------ #
# Skill synthesis from exploit chains (feature N)
# ------------------------------------------------------------------ #

from core.skill_synthesis import synthesize_from_log, persist_skill
from core import provenance


def test_skill_synthesis_and_signing():
    from tools.tool_registry import ToolRegistry
    from tools.generated_tool_manager import GeneratedToolManager
    from tools.generated_tool import render_tool_source, compile_run
    from plugins.sdk.base_tool import Permission

    st = AttackState(target="10.10.10.5", services={"445": "microsoft-ds"},
                     vulnerabilities=["CVE-2017-0144"], flags=["HTB{rooted}"])
    records = [
        {"kind": "tool_call", "tool": "nmap_scan",
         "args": {"target": "10.10.10.5", "scan_type": "version"}, "ok": True},
        {"kind": "tool_call", "tool": "kali_run",
         "args": {"tool": "crackmapexec", "args": "smb 10.10.10.5"}, "ok": True},
        {"kind": "tool_call", "tool": "shell",
         "args": {"cmd": "cat /root/root.txt 10.10.10.5"}, "ok": True},
        {"kind": "finding", "finding_type": "flag", "value": "HTB{rooted}"},
        {"kind": "tool_call", "tool": "shell",
         "args": {"cmd": "echo after-the-flag"}, "ok": True},  # past the win → excluded
    ]

    skill = synthesize_from_log(records, st, "sess1")
    assert skill is not None
    # Chain is the 3 calls up to the flag; the post-flag step is dropped.
    assert skill.total_steps == 3 and skill.runnable_steps == 3
    # The engagement target is parameterized out of the replay commands.
    assert "10.10.10.5" not in skill.code and "__TARGET__" in skill.code
    # The synthesized body honors the generated-tool contract (compiles).
    compile_run(render_tool_source(skill.code), skill.name)
    # No flag and no credential → nothing to synthesize.
    assert synthesize_from_log([], AttackState(target="x"), "s") is None

    # Persist through a real manager (no controller needed), then check provenance.
    with tempfile.TemporaryDirectory() as tmp:
        reg = ToolRegistry(granted_permissions={Permission.SHELL, Permission.FILESYSTEM})
        mgr = GeneratedToolManager(registry=reg, controller=None, base_dir=tmp)
        key = b"\x02" * 32
        msg = persist_skill(mgr, skill, sign_key=key)
        assert msg.startswith("Synthesized")

        manifest = mgr.tools[skill.name].manifest
        assert manifest["signer"] == provenance.signer_id(key)
        # Signature verifies over the code's sha256, and a tampered sha fails.
        assert provenance.verify(manifest["sha256"], manifest["signature"], key)
        assert not provenance.verify("tampered-sha", manifest["signature"], key)
        assert manifest["synthesized_from"]["origin_target"] == "10.10.10.5"
        assert manifest["synthesized_from"]["steps"] == 3
    print("  PASS  skill_synthesis_and_signing")


# ------------------------------------------------------------------ #
# Hybrid OPSEC routing (feature O)
# ------------------------------------------------------------------ #


def test_opsec_policy_decisions():
    from core.opsec_routing import OpsecPolicy
    from core.operators import get_operator

    sensitive = get_operator("post_operator")   # prefer_local=True  (loot/creds)
    cloud_ok = get_operator("web_operator")      # prefer_local=False (public surface)
    clean = AttackState(target="10.0.0.1")
    looted = AttackState(target="10.0.0.1", credentials=["admin:pw"])

    # Cloud disabled → already local-only, so nothing is ever pinned.
    off = OpsecPolicy(allow_cloud=False)
    assert not off.decide(operator=sensitive, attack_state=looted).pin_local

    on = OpsecPolicy(allow_cloud=True)
    # A sensitive operator is pinned local even on a clean state…
    assert on.decide(operator=sensitive, attack_state=clean).pin_local
    # …a cloud-eligible operator on a clean state may use cloud…
    assert not on.decide(operator=cloud_ok, attack_state=clean).pin_local
    # …but once credentials are captured, even it is pinned local.
    assert on.decide(operator=cloud_ok, attack_state=looted).pin_local
    # A generalist (no operator) on a clean state is cloud-eligible.
    assert not on.decide(operator=None, attack_state=clean).pin_local

    # Escape hatch: pinning can be disabled outright.
    assert not OpsecPolicy(allow_cloud=True, pin_sensitive=False).decide(
        operator=sensitive, attack_state=looted).pin_local
    print("  PASS  opsec_policy_decisions")


def test_opsec_local_variant_pins_local():
    from models.model_registry import ModelRegistry, ModelRole
    from models.routing_engine import RoutingEngine, RoutingStrategy
    from models.routed_model import RoutedModel

    registry = ModelRegistry()
    # Cloud primary with a local model also available; cloud allowed.
    engine = RoutingEngine(registry, strategy=RoutingStrategy.SINGLE,
                           primary_model_id="gpt-4o", local_only=False)
    engine.set_available_models(["gpt-4o", "qwen2.5:14b"])
    routed = RoutedModel(engine, FakePool(), primary_model_id="gpt-4o")

    # The lead routes the loop to the cloud primary…
    assert routed.model_for(ModelRole.EXECUTOR) == "gpt-4o"
    # …but its local variant keeps every role on a local model (even SINGLE,
    # which otherwise just returns the primary).
    local = routed.local_variant()
    assert local.model_for(ModelRole.EXECUTOR) == "qwen2.5:14b"
    assert local.model_for(ModelRole.PLANNER) == "qwen2.5:14b"
    print("  PASS  opsec_local_variant_pins_local")


async def test_opsec_controller_pins_sensitive_operator():
    from core.opsec_routing import OpsecPolicy

    class Dispatcher:
        async def dispatch(self, name, args, session_id):
            return "ok"

    async def delegate_to(operator_name, op_title):
        # A model that records whether it was asked for a local variant; the lead
        # delegates once, the child answers, the lead wraps up.
        class PinModel:
            supports_tools = False

            def __init__(self, label="lead"):
                self.label = label
                self.variant_made = False

            def local_variant(self):
                self.variant_made = True
                return PinModel("local")

            async def chat(self, messages, tools=None, json_mode=False, stream=False):
                joined = " ".join(m.get("content", "") for m in messages)
                if "subagent result" in joined:                 # lead, after child
                    return json.dumps({"type": "response", "content": "done"})
                if op_title in joined:                           # the operator child
                    return json.dumps({"type": "response", "content": "child done"})
                return json.dumps({"type": "tool_call", "tool": "delegate",  # lead first
                    "args": {"task": "go", "operator": operator_name}})

        lead = PinModel()
        controller = AgentController(
            model_provider=lead, tool_dispatcher=Dispatcher(),
            mode=AgentMode.AGENT, use_function_calling=False,
            opsec_policy=OpsecPolicy(allow_cloud=True))
        controller.register_tool(ToolSchema(name="shell", description="run",
            parameters={"type": "object", "properties": {"cmd": {"type": "string"}}}))
        events: list[dict] = []

        async def cap(e):
            events.append(e.data)
        controller.bus.subscribe("agent.delegate.start", cap)
        await controller.start()
        await controller.run("do it", session_id="opsec-test")
        return lead, events[0]

    # A sensitive operator is handed a local-pinned variant of the lead's model.
    lead, ev = await delegate_to("post_operator", "Post-Exploit Operator")
    assert lead.variant_made and ev["opsec"] == "local-pinned"

    # A cloud-eligible operator on a clean state reuses the lead's model.
    lead, ev = await delegate_to("web_operator", "Web Operator")
    assert not lead.variant_made and ev["opsec"] == "cloud-eligible"
    print("  PASS  opsec_controller_pins_sensitive_operator")


# ------------------------------------------------------------------ #
# CVE grounding (feature M)
# ------------------------------------------------------------------ #


def test_cve_cvss_and_lookup():
    from core.cve_grounding import cvss_to_severity, lookup, severity_for_cve

    # CVSS v3 qualitative bands.
    assert cvss_to_severity(10.0) == "Critical"
    assert cvss_to_severity(8.1) == "High"
    assert cvss_to_severity(5.0) == "Medium"
    assert cvss_to_severity(2.0) == "Low"
    assert cvss_to_severity(0.0) == "Info"

    # Lookup by id and by vendor-bulletin alias resolves the same entry.
    assert lookup("CVE-2017-0144").id == "CVE-2017-0144"
    assert lookup("ms17-010").id == "CVE-2017-0144"
    assert lookup("nope") is None

    # severity_for_cve uses the catalog CVSS; unknown CVEs default to High.
    assert severity_for_cve("CVE-2019-0708") == "Critical"   # BlueKeep 9.8
    assert severity_for_cve("CVE-2017-0144") == "High"       # EternalBlue 8.1
    assert severity_for_cve("CVE-2099-0001") == "High"       # unknown → safe default
    print("  PASS  cve_cvss_and_lookup")


def test_cve_ground_services_prioritizes():
    from core.cve_grounding import ground_services

    services = {"21": "ftp", "445": "microsoft-ds", "80": "http"}
    versions = {"21": "vsftpd 2.3.4"}   # version banner confirms the backdoor CVE

    matches = ground_services(services, versions)
    by_id = {m.entry.id: m for m in matches}

    # The vsftpd 2.3.4 backdoor is matched AND version-confirmed.
    assert "CVE-2011-2523" in by_id and by_id["CVE-2011-2523"].version_confirmed
    # SMB matches EternalBlue heuristically (no version banner present).
    assert "CVE-2017-0144" in by_id and not by_id["CVE-2017-0144"].version_confirmed
    # Prioritization: a version-confirmed hit ranks ahead of a service-heuristic
    # one even when the heuristic CVE has its own (lower) score.
    assert matches[0].entry.id == "CVE-2011-2523"
    # An ad-hoc service with no catalog match grounds nothing.
    assert ground_services({"9999": "totally-unknown-svc"}) == []
    print("  PASS  cve_ground_services_prioritizes")


def test_cve_attack_state_and_report_integration():
    from reporting import build_report

    # nmap -sV style output with a version banner the catalog confirms.
    chain = ConversationChain()
    chain.on_turn_start("scan 10.10.10.5")
    chain.on_tool_result(
        "nmap_scan",
        "Nmap scan report for 10.10.10.5\n"
        "21/tcp open  ftp     vsftpd 2.3.4\n"
        "445/tcp open microsoft-ds Samba smbd 3.X\n")
    st = chain.attack_state

    # Version banner captured separately from the bare service name.
    assert st.versions.get("21") == "vsftpd 2.3.4" and st.services.get("21") == "ftp"
    # The version-confirmed CVE was fed into the attack-state vulnerabilities…
    assert "CVE-2011-2523" in st.vulnerabilities
    # …while the heuristic-only SMB match was NOT auto-recorded.
    assert "CVE-2017-0144" not in st.vulnerabilities
    # The grounded plan surfaces in the next-step guidance.
    assert "CVE-2011-2523" in st.suggest_next_step()

    # The report (L) scores that CVE by its real CVSS and enriches the finding.
    report = build_report(st, [], {})
    vuln = next(f for f in report.findings if f.finding_type == "vulnerability")
    assert vuln.severity == "Critical" and "CVSS 9.8" in vuln.evidence
    assert "exploit/unix/ftp/vsftpd_234_backdoor" in vuln.evidence
    print("  PASS  cve_attack_state_and_report_integration")


def test_cve_live_nvd_enrichment():
    import json as _json
    from core.cve_grounding import enrich_from_nvd, cvss_to_severity

    # An NVD 2.0-shaped response, served through an injected fetcher (offline).
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-2023-1111",
                 "descriptions": [{"lang": "en", "value": "Example RCE in foobar"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
        {"cve": {"id": "CVE-2023-2222",
                 "descriptions": [{"lang": "en", "value": "Lesser issue"}],
                 "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.0}}]}}},
    ]}

    got = enrich_from_nvd("foobar", fetch=lambda kw: _json.dumps(payload))
    # Parsed, scored, and sorted by CVSS desc.
    assert [e.id for e in got] == ["CVE-2023-1111", "CVE-2023-2222"]
    assert got[0].cvss == 9.8 and got[0].severity == cvss_to_severity(9.8) == "Critical"
    assert "foobar" in got[0].products and got[0].references

    # A failed fetch degrades to [] (offline catalog stays the default).
    assert enrich_from_nvd("x", fetch=lambda kw: (_ for _ in ()).throw(OSError())) == []
    print("  PASS  cve_live_nvd_enrichment")


# ------------------------------------------------------------------ #
# Multi-host sub-states for parallel delegation (feature P)
# ------------------------------------------------------------------ #


def test_multihost_substate_resolution():
    c = AgentController(model_provider=MockModel())
    c.chain.attack_state.target = "10.0.0.1"

    # No target, or the lead's own host → the shared blackboard (not isolated).
    assert c._host_state_for(None) == (c.chain.attack_state, False)
    assert c._host_state_for("10.0.0.1") == (c.chain.attack_state, False)

    # A different host → a dedicated, target-seeded state, reused on re-ask.
    s2, iso2 = c._host_state_for("10.0.0.2")
    assert iso2 and s2.target == "10.0.0.2" and s2 is not c.chain.attack_state
    s2_again, _ = c._host_state_for("10.0.0.2")
    assert s2_again is s2

    # Roll-up lists the isolated host(s), not the lead's own host.
    render = c._render_host_states()
    assert "10.0.0.2" in render and "10.0.0.1" not in render
    print("  PASS  multihost_substate_resolution")


async def test_multihost_parallel_delegation():
    # delegate_parallel with a distinct target per task isolates each host: a
    # flag looted on one host lands only in that host's sub-state, not the
    # lead's and not the sibling's.
    class Dispatcher:
        async def dispatch(self, name, args, session_id):
            # Echo a host-specific flag so the child records it into its state.
            return f"HTB{{flag-{args.get('cmd', '').split()[-1]}}}"

    class DelegModel:
        supports_tools = False

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            joined = " ".join(m.get("content", "") for m in messages)
            if "delegate_parallel —" in joined or "subagent result" in joined:
                return json.dumps({"type": "response", "content": "all done"})  # lead, after
            if "HTB{" in joined:                                # a child, post-loot
                return json.dumps({"type": "response", "content": "looted"})
            if "hostA" in joined:                               # child A, first turn
                return json.dumps({"type": "tool_call", "tool": "shell",
                                   "args": {"cmd": "loot hostA"}})
            if "hostB" in joined:                               # child B, first turn
                return json.dumps({"type": "tool_call", "tool": "shell",
                                   "args": {"cmd": "loot hostB"}})
            return json.dumps({"type": "tool_call", "tool": "delegate_parallel", "args": {
                "tasks": [{"task": "loot hostA", "target": "hostA"},
                          {"task": "loot hostB", "target": "hostB"}]}})

    controller = AgentController(model_provider=DelegModel(), tool_dispatcher=Dispatcher(),
                                 mode=AgentMode.AGENT, use_function_calling=False)
    controller.register_tool(ToolSchema(name="shell", description="run",
        parameters={"type": "object", "properties": {"cmd": {"type": "string"}}}))

    targets: list = []

    async def cap(e):
        targets.append(e.data.get("target"))
    controller.bus.subscribe("agent.delegate.start", cap)
    await controller.start()

    await controller.run("loot the whole subnet", session_id="mh-test")

    hosts = controller.host_states()
    # Two isolated per-host states, each with only its own flag.
    assert set(hosts) == {"hostA", "hostB"}
    assert hosts["hostA"].flags == ["HTB{flag-hostA}"]
    assert hosts["hostB"].flags == ["HTB{flag-hostB}"]
    assert hosts["hostA"] is not hosts["hostB"]
    # The lead's own blackboard stays clean — findings didn't bleed across.
    assert controller.chain.attack_state.flags == []
    # Both delegations were tagged with their host for the engagement log (K).
    assert set(targets) == {"hostA", "hostB"}
    print("  PASS  multihost_parallel_delegation")


# ------------------------------------------------------------------ #
# Per-operator model routing (feature P)
# ------------------------------------------------------------------ #


async def test_per_operator_model_role():
    from models.model_registry import ModelRole
    from models.routing_engine import RoutingStrategy
    from models.routed_model import RoutedModel
    from core.operators import get_operator

    # Reasoning-heavy specialists are routed as PLANNER; action ones as EXECUTOR.
    assert get_operator("analyst").model_role == "planner"
    assert get_operator("reverser").model_role == "planner"
    assert get_operator("recon_operator").model_role == "executor"
    assert get_operator("post_operator").model_role == "executor"

    # RoutedModel.for_role yields a sibling whose loop is scored as that role,
    # sharing the routing engine + pool. Under PIPELINE, planner→14B, executor→7B.
    engine = _routing(RoutingStrategy.PIPELINE)
    pool = FakePool()
    routed = RoutedModel(engine, pool, primary_model_id="qwen2.5:14b")

    planner = routed.for_role("planner")
    assert planner.default_role == ModelRole.PLANNER
    await planner.chat([{"role": "user", "content": "hi"}])
    assert pool.gets[-1] == "qwen2.5:14b"          # planner default → quality model

    executor = routed.for_role("executor")
    await executor.chat([{"role": "user", "content": "hi"}])
    assert pool.gets[-1] == "qwen2.5:7b"           # executor default → fast model

    # An unknown role name falls back to the model's current default role.
    assert routed.for_role("nonsense").default_role == routed.default_role
    print("  PASS  per_operator_model_role")


async def test_controller_routes_operator_by_role():
    # The controller runs an operator's child under that operator's model role.
    class Dispatcher:
        async def dispatch(self, name, args, session_id):
            return "ok"

    async def delegate_to(operator_name, op_title):
        class RoleModel:
            supports_tools = False

            def __init__(self):
                self.roles: list = []

            def for_role(self, role):
                self.roles.append(role)
                return self            # same instance keeps driving the loop

            async def chat(self, messages, tools=None, json_mode=False, stream=False):
                joined = " ".join(m.get("content", "") for m in messages)
                if "subagent result" in joined:
                    return json.dumps({"type": "response", "content": "done"})
                if op_title in joined:
                    return json.dumps({"type": "response", "content": "child done"})
                return json.dumps({"type": "tool_call", "tool": "delegate",
                    "args": {"task": "go", "operator": operator_name}})

        model = RoleModel()
        controller = AgentController(
            model_provider=model, tool_dispatcher=Dispatcher(),
            mode=AgentMode.AGENT, use_function_calling=False)
        controller.register_tool(ToolSchema(name="shell", description="run",
            parameters={"type": "object", "properties": {"cmd": {"type": "string"}}}))
        await controller.start()
        await controller.run("do it", session_id="role-test")
        return model.roles

    # A reasoning specialist routes as planner; an action specialist as executor.
    assert await delegate_to("analyst", "Analyst") == ["planner"]
    assert await delegate_to("recon_operator", "Recon Operator") == ["executor"]
    print("  PASS  controller_routes_operator_by_role")


# ------------------------------------------------------------------ #
# Editable persona — soul.md (feature E)
# ------------------------------------------------------------------ #


def test_soul_resolution_and_default():
    from core import soul
    from pathlib import Path

    with tempfile.TemporaryDirectory() as proj, tempfile.TemporaryDirectory() as home:
        env = {"USERPROFILE": home, "HOME": home}

        # No file anywhere → the shipped default persona.
        assert soul.load_soul(proj, environ=env) == soul.DEFAULT_SOUL.strip()
        assert soul.soul_file(proj, environ=env) is None

        # init writes the default to the global path; load picks it up.
        path, written = soul.init_soul(environ=env)
        assert written and path.is_file()
        assert soul.init_soul(environ=env)[1] is False        # idempotent

        # A project soul.md overrides the global one.
        (Path(proj) / "soul.md").write_text("Be terse and tactical.", encoding="utf-8")
        assert soul.soul_file(proj, environ=env) == Path(proj) / "soul.md"
        assert soul.load_soul(proj, environ=env) == "Be terse and tactical."
    print("  PASS  soul_resolution_and_default")


def test_soul_persona_in_system_prompt():
    from core.context_builder import ContextBuilder

    cb = ContextBuilder(system_prompt="BASE OFFENSIVE PROMPT")
    payload = cb.build()
    assert "PERSONA" not in payload["messages"][0]["content"]  # none by default

    cb.set_persona("# Persona\nSpeak like a terse operator.")
    system = cb.build()["messages"][0]["content"]
    # Persona sits at the very top, above the base prompt.
    assert system.startswith("# Persona")
    assert "Speak like a terse operator." in system
    assert system.index("Persona") < system.index("BASE OFFENSIVE PROMPT")
    print("  PASS  soul_persona_in_system_prompt")


async def test_soul_hot_reload_each_turn():
    # The controller re-reads the persona provider every turn, so an edit to
    # soul.md takes effect on the next message without a restart.
    persona = {"text": "Persona A — be brief."}

    class CaptureModel:
        supports_tools = False

        def __init__(self):
            self.systems: list[str] = []

        async def chat(self, messages, tools=None, json_mode=False, stream=False):
            self.systems.append(messages[0]["content"])
            return json.dumps({"type": "response", "content": "ok"})

    model = CaptureModel()
    controller = AgentController(model_provider=model, use_function_calling=False,
                                persona_provider=lambda: persona["text"])
    await controller.start()

    await controller.run("turn one", session_id="soul-test")
    assert "Persona A — be brief." in model.systems[-1]

    persona["text"] = "Persona B — be verbose."     # edit between turns
    await controller.run("turn two", session_id="soul-test")
    assert "Persona B — be verbose." in model.systems[-1]
    assert "Persona A" not in model.systems[-1]      # old persona is gone
    print("  PASS  soul_hot_reload_each_turn")


# ------------------------------------------------------------------ #
# Agent-maintained user profile — user.md (feature F)
# ------------------------------------------------------------------ #


def test_user_profile_dedup_caps_and_persistence():
    from memory.user_profile import UserProfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "user.md"
        prof = UserProfile(path=path, max_per_category=3, max_total=10)

        assert prof.add("prefers sqlmap", "Preferences") is True
        assert prof.add("PREFERS SQLMAP", "Preferences") is False   # case-insensitive dup
        assert prof.add("uses zsh", "Habits") is True

        # Per-category cap evicts the oldest of that category only.
        for i in range(5):
            prof.add(f"pref {i}", "Preferences")
        prefs = [f for c, f in prof.facts() if c == "Preferences"]
        assert len(prefs) == 3 and "prefers sqlmap" not in prefs and "pref 4" in prefs
        assert ("Habits", "uses zsh") in prof.facts()               # other category untouched

        # The markdown file is the store — a fresh instance reloads it.
        prof.add("ran HTB box Blue", "Engagements")
        assert path.is_file()
        reloaded = UserProfile(path=path, max_per_category=3, max_total=10)
        assert ("Engagements", "ran HTB box Blue") in reloaded.facts()

        # remove drops the fact and re-saves.
        assert reloaded.remove("ran HTB box Blue") is True
        assert ("Engagements", "ran HTB box Blue") not in reloaded.facts()
    print("  PASS  user_profile_dedup_caps_and_persistence")


def test_user_profile_summary_and_total_cap():
    from memory.user_profile import UserProfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        prof = UserProfile(path=Path(tmp) / "user.md",
                           max_per_category=100, max_total=5)
        for i in range(8):
            prof.add(f"fact {i}", "Notes")
        # Total cap keeps the newest 5 across the board.
        facts = [f for _, f in prof.facts()]
        assert facts == [f"fact {i}" for i in range(3, 8)]

        # Summary is a single labeled block; empty profile yields "".
        s = prof.summary()
        assert s.startswith("USER PROFILE") and "[Notes]" in s and "fact 7" in s
        assert UserProfile(path=Path(tmp) / "none.md").summary() == ""
    print("  PASS  user_profile_summary_and_total_cap")


async def test_user_profile_tool_and_injection():
    from memory.user_profile import UserProfile, UserRememberTool
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        prof = UserProfile(path=Path(tmp) / "user.md")

        # The agent tool records a fact; a re-record is reported as a dup.
        tool = UserRememberTool(prof)
        r = await tool.execute(fact="prefers Burp over ZAP", category="Preferences")
        assert "Remembered" in r.output and ("Preferences", "prefers Burp over ZAP") in prof.facts()
        assert "Already" in (await tool.execute(fact="prefers Burp over ZAP")).output \
            or ("Preferences", "prefers Burp over ZAP") in prof.facts()

        # The controller injects the profile summary into the system prompt.
        class CaptureModel:
            supports_tools = False

            def __init__(self):
                self.systems: list[str] = []

            async def chat(self, messages, tools=None, json_mode=False, stream=False):
                self.systems.append(messages[0]["content"])
                return json.dumps({"type": "response", "content": "ok"})

        model = CaptureModel()
        controller = AgentController(model_provider=model, use_function_calling=False,
                                    profile_provider=lambda: prof.summary())
        await controller.start(inject_project_context=False)
        await controller.run("hello", session_id="prof-test")
        assert "USER PROFILE" in model.systems[-1]
        assert "prefers Burp over ZAP" in model.systems[-1]
    print("  PASS  user_profile_tool_and_injection")


# ------------------------------------------------------------------ #
# Update manager (feature D)
# ------------------------------------------------------------------ #


def test_updater_version_compare_and_local():
    from core import updater
    from pathlib import Path

    assert updater.parse_version("v1.2.10") == (1, 2, 10)
    assert updater.compare_versions("1.2.10", "1.2.9") == 1     # numeric, not lexical
    assert updater.compare_versions("1.2", "1.2.0") == 0        # zero-padded
    assert updater.is_newer("0.8.0", "0.7.0")
    assert not updater.is_newer("0.7.0", "0.7.0")

    with tempfile.TemporaryDirectory() as tmp:
        vf = Path(tmp) / "VERSION"
        vf.write_text("1.5.2\n", encoding="utf-8")
        assert updater.local_version(vf) == "1.5.2"
        assert updater.local_version(Path(tmp) / "missing") == "0.0.0"
    print("  PASS  updater_version_compare_and_local")


def test_updater_check_cache_and_notice():
    from core import updater

    with tempfile.TemporaryDirectory() as home:
        env = {"USERPROFILE": home, "HOME": home}

        # A newer remote → update available, and the latest is cached.
        st = updater.check_for_update(current="0.7.0", latest_fn=lambda: "v0.9.0",
                                      environ=env)
        assert st.update_available and st.latest == "v0.9.0"
        assert updater.read_cached_latest(environ=env) == "v0.9.0"

        # The startup notice is offline (cache-only) and version-aware.
        assert "0.9.0" in (updater.update_notice(environ=env, current="0.7.0") or "")
        assert updater.update_notice(environ=env, current="0.9.0") is None  # not newer

        # No remote/tags → unknown, no crash, not flagged as available.
        st2 = updater.check_for_update(current="0.7.0", latest_fn=lambda: None,
                                       environ=env)
        assert not st2.update_available and st2.latest is None

        # Same version → up to date.
        st3 = updater.check_for_update(current="1.0.0", latest_fn=lambda: "1.0.0",
                                       environ=env)
        assert not st3.update_available
    print("  PASS  updater_check_cache_and_notice")


def test_updater_backup_config():
    from core import updater
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "config.json"
        cfg.write_text('{"x": 1}', encoding="utf-8")
        bak = updater.backup_config(config_path=cfg)
        assert bak is not None and bak.is_file() and bak != cfg
        assert bak.read_text(encoding="utf-8") == '{"x": 1}'
        # Nothing to back up → None (not an error).
        assert updater.backup_config(config_path=Path(tmp) / "none.json") is None
    print("  PASS  updater_backup_config")


# ------------------------------------------------------------------ #
# CLI presentation layer (feature B)
# ------------------------------------------------------------------ #


def test_render_phase_style_and_summary():
    from cli.render import phase_style, _phase_summary
    from core.conversation_chain import AttackState

    assert phase_style("exploitation") == ("EXPLOIT", "red")
    assert phase_style("recon")[0] == "RECON"
    assert phase_style("nonsense") == ("PHASE", "white")   # unknown → default

    # Nothing discovered yet → no phase line.
    assert _phase_summary(AttackState()) is None
    # Target + ports + vulns roll into the detail string.
    st = AttackState(target="10.10.10.5", open_ports=["22/tcp", "80/tcp"],
                     vulnerabilities=["CVE-2017-0144"], current_phase="enumeration")
    label, colour, detail = _phase_summary(st)
    assert label == "ENUM" and colour == "blue"
    assert "target=10.10.10.5" in detail and "22/tcp" in detail and "vulns=1" in detail
    print("  PASS  render_phase_style_and_summary")


def test_render_selection_without_rich():
    import cli.render as render
    from cli.render import make_renderer, PlainRenderer, rich_available

    # --plain always yields the plain renderer.
    assert isinstance(make_renderer(plain=True), PlainRenderer)
    if not rich_available():
        # No rich installed → plain even when forced / on a notional TTY.
        assert isinstance(make_renderer(plain=False), PlainRenderer)
        assert isinstance(make_renderer(force_rich=True), PlainRenderer)
    else:
        # rich present → force_rich gives the rich renderer.
        assert make_renderer(force_rich=True).is_rich
        assert isinstance(make_renderer(plain=True), PlainRenderer)
    print("  PASS  render_selection_without_rich")


def test_render_plain_output_matches_legacy():
    import io
    from contextlib import redirect_stdout
    from cli.render import PlainRenderer
    from core.conversation_chain import AttackState

    # Streamed turn: "agent > " prefix once, then tokens, then meta line.
    r = PlainRenderer()
    buf = io.StringIO()
    with redirect_stdout(buf):
        r.start_turn()
        r.stream("hel")
        r.stream("lo")
        r.agent_result("hello", ["nmap_scan"], 2, None)
    out = buf.getvalue()
    assert "agent > hello" in out
    assert "(used: nmap_scan, 2 steps)" in out

    # Non-streamed turn prints the full content with the agent prefix.
    r2 = PlainRenderer()
    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        r2.start_turn()
        r2.agent_result("done", [], 1, None)
    assert "agent > done" in buf2.getvalue()

    # Phase line is plain (no escape codes) and carries the label + detail.
    buf3 = io.StringIO()
    with redirect_stdout(buf3):
        PlainRenderer().phase_line(AttackState(target="t", open_ports=["80/tcp"],
                                               current_phase="post"))
    line = buf3.getvalue()
    assert "[POST]" in line and "target=t" in line and "\x1b[" not in line

    # Task list renders checkboxes by status (feature B panel, plain form).
    from types import SimpleNamespace
    todos = [SimpleNamespace(task="recon", status="completed"),
             SimpleNamespace(task="exploit", status="in_progress"),
             SimpleNamespace(task="loot", status="pending")]
    buf4 = io.StringIO()
    with redirect_stdout(buf4):
        PlainRenderer().task_list(todos)
    tl = buf4.getvalue()
    assert "Tasks (1/3)" in tl and "[x] recon" in tl and "[~] exploit" in tl and "[ ] loot" in tl
    # No todos → nothing printed.
    buf5 = io.StringIO()
    with redirect_stdout(buf5):
        PlainRenderer().task_list([])
    assert buf5.getvalue() == ""
    print("  PASS  render_plain_output_matches_legacy")


# ------------------------------------------------------------------ #
# Remote execution backends (feature H)
# ------------------------------------------------------------------ #


def test_exec_backend_build_and_argv():
    from core.exec_backend import (build_backend, backend_from_config,
                                   LocalBackend, SSHBackend, DockerBackend)

    # Factory selection.
    assert isinstance(build_backend({"backend": "local"}), LocalBackend)
    assert isinstance(build_backend(None), LocalBackend)
    assert isinstance(build_backend({"backend": "ssh", "host": "h"}), SSHBackend)
    assert isinstance(build_backend({"backend": "docker", "image": "i"}), DockerBackend)

    # Under-specified remote backends raise.
    for bad in ({"backend": "ssh"}, {"backend": "docker"}, {"backend": "weird"}):
        try:
            build_backend(bad)
            assert False, f"expected ValueError for {bad}"
        except ValueError:
            pass

    # ...but backend_from_config never raises — it falls back to local + warns.
    fb, warn = backend_from_config({"backend": "ssh"})
    assert isinstance(fb, LocalBackend) and warn and "local" in warn

    # SSH argv: target, non-default port, key, batch mode, and working-dir wrap.
    ssh = SSHBackend(host="10.0.0.5", user="root", port=2222, key="/k/id")
    argv = ssh.build_argv("id", working_dir="/tmp")
    assert argv[0] == "ssh" and "root@10.0.0.5" in argv
    assert "-p" in argv and "2222" in argv and "-i" in argv and "/k/id" in argv
    assert "BatchMode=yes" in argv and argv[-1] == "cd /tmp && id"
    assert ssh.name == "ssh" and "10.0.0.5" in ssh.describe()
    # Default port omits -p.
    assert "-p" not in SSHBackend(host="h").build_argv("ls")

    # Docker: exec into a named container vs ephemeral run --rm from an image.
    dc = DockerBackend(container="kali")
    assert dc.build_argv("nmap t") == ["docker", "exec", "kali", "sh", "-c", "nmap t"]
    di = DockerBackend(image="kalilinux/kali", workdir="/root")
    assert di.build_argv("id") == ["docker", "run", "--rm", "-w", "/root",
                                   "kalilinux/kali", "sh", "-c", "id"]
    print("  PASS  exec_backend_build_and_argv")


async def test_exec_backend_local_run_and_shell_tool():
    from core.exec_backend import LocalBackend, ExecResult
    from security_tools.shell_tool import ShellTool

    # LocalBackend really runs a subprocess.
    res = await LocalBackend().run("echo backend_ok")
    assert res.success and "backend_ok" in res.output

    # ShellTool with no backend uses the local fast-path (also a real subprocess).
    local = await ShellTool().execute(cmd="echo shell_ok")
    assert local.success and "shell_ok" in local.output

    # A non-local backend is dispatched through instead of the local path.
    class FakeRemote:
        name = "ssh"
        def __init__(self):
            self.calls: list[str] = []
        async def run(self, cmd, *, timeout=30, working_dir=""):
            self.calls.append(cmd)
            return ExecResult("remote-output", exit_code=0)

    fake = FakeRemote()
    out = await ShellTool(backend=fake).execute(cmd="whoami")
    assert fake.calls == ["whoami"]
    assert out.success and out.output == "remote-output"
    assert out.metadata.get("backend") == "ssh"
    print("  PASS  exec_backend_local_run_and_shell_tool")


async def test_exec_backend_kali_run_remote():
    from core.exec_backend import ExecResult
    from security_tools.kali.kali_tools_interface import KaliRunTool

    # A remote backend runs the bare tool name (no local shutil.which) so the
    # remote/container PATH resolves it.
    class FakeRemote:
        name = "docker"
        def __init__(self):
            self.cmds = []
        async def run(self, cmd, *, timeout=60, working_dir=""):
            self.cmds.append(cmd)
            return ExecResult("nikto output", exit_code=0)

    fake = FakeRemote()
    out = await KaliRunTool(backend=fake).execute(tool="nikto", args="-h http://t")
    assert fake.cmds == ["nikto -h http://t"]
    assert out.success and "nikto output" in out.output
    assert out.metadata.get("backend") == "docker"
    print("  PASS  exec_backend_kali_run_remote")


def test_config_execution_section():
    from core.config import MapacheConfig

    # Default config carries a local execution backend.
    assert MapacheConfig.from_dict({}).execution.get("backend") == "local"
    cfg = MapacheConfig.from_dict(
        {"execution": {"backend": "docker", "container": "kali"}})
    assert cfg.execution["backend"] == "docker" and cfg.execution["container"] == "kali"
    assert cfg.to_dict()["execution"]["backend"] == "docker"
    print("  PASS  config_execution_section")


# ------------------------------------------------------------------ #
# Community skill hub (feature I)
# ------------------------------------------------------------------ #


def test_hub_manifest_and_verification():
    from hub import (make_generated_tool_manifest, make_mcp_server_manifest,
                     verify_manifest)
    from core import provenance

    key = b"\x05" * 32
    m = make_generated_tool_manifest(
        "replay_x", "1.0.0", "demo", {"type": "object", "properties": {}},
        'return "hi from hub"\n', sign_key=key)

    # A correctly-published manifest verifies (checksum + signature with the key).
    ok, reason = verify_manifest(m, key=key)
    assert ok and "signature" in reason
    # Without the key the checksum still gates; signature is noted as unverified.
    ok2, reason2 = verify_manifest(m, key=None)
    assert ok2 and "unverified" in reason2
    # A wrong key fails signature verification.
    assert verify_manifest(m, key=b"\x06" * 32)[0] is False
    # Tampered payload → checksum mismatch (the integrity gate).
    m.code = 'return "tampered"\n'
    assert verify_manifest(m, key=key)[0] is False

    # MCP manifest verifies on its canonical command+args digest.
    mc = make_mcp_server_manifest("fs", "1.0.0", "files", "npx",
                                  ["-y", "server-filesystem", "/data"])
    assert verify_manifest(mc)[0] is True
    mc.args = ["-y", "evil"]
    assert verify_manifest(mc)[0] is False
    print("  PASS  hub_manifest_and_verification")


def test_hub_install_generated_and_mcp():
    import json as _json
    from pathlib import Path
    from hub import make_generated_tool_manifest, make_mcp_server_manifest
    from hub.registry import LocalRegistry
    from hub.client import HubClient
    from tools.generated_tool import load_generated_tool

    with tempfile.TemporaryDirectory() as reg, tempfile.TemporaryDirectory() as home:
        gen_dir = Path(home) / "plugins" / "generated"
        mcp_path = Path(home) / "mcp.json"

        good_tool = make_generated_tool_manifest(
            "hub_echo", "1.2.0", "echo skill",
            {"type": "object", "properties": {}}, 'return "hi from hub"\n')
        mcp = make_mcp_server_manifest(
            "fs", "0.1.0", "filesystem", "npx", ["-y", "server-fs", "/data"])
        tampered = make_generated_tool_manifest(
            "bad_tool", "1.0.0", "bad", {"type": "object", "properties": {}},
            'return "x"\n')
        tampered.checksum = "0" * 64  # break the integrity gate

        (Path(reg) / "index.json").write_text(
            _json.dumps([good_tool.to_dict(), mcp.to_dict(), tampered.to_dict()]),
            encoding="utf-8")

        client = HubClient(LocalRegistry(reg), generated_dir=gen_dir, mcp_path=mcp_path)

        # Browse.
        assert {m.name for m in client.list_skills()} == {"hub_echo", "fs", "bad_tool"}
        assert [m.name for m in client.search("filesystem")] == ["fs"]

        # Install the generated tool → A package on disk that loads + compiles
        # (the loader re-verifies the sha256 because origin == "hub").
        msg = client.install("hub_echo")
        assert "Installed generated tool 'hub_echo'" in msg
        tool_dir = gen_dir / "hub_echo"
        assert (tool_dir / "tool.py").is_file() and (tool_dir / "manifest.json").is_file()
        loaded = load_generated_tool(tool_dir)
        assert loaded.name == "hub_echo"

        # Install the MCP server → entry in mcp.json.
        client.install("fs")
        data = _json.loads(mcp_path.read_text(encoding="utf-8"))
        assert data["mcpServers"]["fs"]["command"] == "npx"
        assert data["mcpServers"]["fs"]["args"] == ["-y", "server-fs", "/data"]

        # A tampered package is refused before anything is written.
        refused = client.install("bad_tool")
        assert "Refused" in refused and "checksum" in refused
        assert not (gen_dir / "bad_tool").exists()

        # Unknown skill.
        assert "not found" in client.install("nope")
    print("  PASS  hub_install_generated_and_mcp")


async def test_hub_tools_no_registry():
    from hub.tools import SkillListTool, SkillInstallTool

    # With no configured client the tools degrade gracefully (no crash).
    assert "No skill hub" in (await SkillListTool(lambda: None).execute()).output
    out = await SkillInstallTool(lambda: None).execute(name="whatever")
    assert "No skill hub" in out.output
    print("  PASS  hub_tools_no_registry")


def test_hub_url_registry():
    import json as _json
    from hub import make_generated_tool_manifest, UrlRegistry, LocalRegistry, make_registry

    m = make_generated_tool_manifest("net_skill", "1.0.0", "remote skill",
                                     {"type": "object", "properties": {}}, 'return "ok"\n')
    index = _json.dumps([m.to_dict()])

    # Injected fetcher keeps it offline; same surface as LocalRegistry.
    calls = []
    def fake_fetch(url):
        calls.append(url)
        return index
    reg = UrlRegistry("https://example.com/index.json", fetch=fake_fetch)
    assert [s.name for s in reg.list_skills()] == ["net_skill"]
    assert reg.get("net_skill").version == "1.0.0"
    assert reg.search("remote")[0].name == "net_skill"
    assert calls and calls[0].startswith("https://")

    # A failing fetch degrades to an empty index, never raises.
    def boom(url):
        raise OSError("down")
    assert UrlRegistry("https://x/i.json", fetch=boom).list_skills() == []

    # make_registry routes by scheme.
    assert isinstance(make_registry("https://x/i.json", fetch=fake_fetch), UrlRegistry)
    assert isinstance(make_registry("/some/local/dir"), LocalRegistry)
    print("  PASS  hub_url_registry")


# ------------------------------------------------------------------ #
# Voice I/O (Phase 9)
# ------------------------------------------------------------------ #


def test_voice_factories_and_manager():
    from voice import (make_tts, make_stt, NullTTS, NullSTT, VoiceManager,
                       voice_from_config)

    # Null + unknown/unavailable backends resolve to the null providers.
    assert isinstance(make_tts("null")[0], NullTTS)
    assert isinstance(make_tts("bogus")[0], NullTTS) and make_tts("bogus")[1]
    assert isinstance(make_stt("")[0], NullSTT)
    # pyttsx3/whisper likely absent here → null + a warning (graceful).
    tts, warn = make_tts("pyttsx3")
    assert isinstance(tts, NullTTS) == (warn is not None)  # null iff it warned

    # NullTTS.speak echoes the text (no audio); NullSTT yields "".
    assert NullTTS().speak("hello") == "hello"
    assert NullSTT().transcribe("x.wav") == ""

    # Manager only speaks when enabled.
    class FakeTTS(NullTTS):
        name = "fake"
        def __init__(self):
            self.said = []
        def speak(self, text):
            self.said.append(text)
            return text
    ft = FakeTTS()
    vm = VoiceManager(ft, NullSTT(), enabled=False)
    assert vm.speak("nope") is None and ft.said == []
    vm.enabled = True
    vm.speak("go")
    assert ft.said == ["go"]
    assert "tts=fake" in vm.describe() and "voice on" in vm.describe()

    # voice_from_config wiring + default-disabled.
    vm2, warns = voice_from_config({"enabled": True, "tts": "null", "stt": "null"})
    assert vm2.enabled and isinstance(vm2.tts, NullTTS) and warns == []
    assert voice_from_config({})[0].enabled is False
    print("  PASS  voice_factories_and_manager")


def test_config_voice_section():
    from core.config import MapacheConfig
    assert MapacheConfig.from_dict({}).voice == {}
    cfg = MapacheConfig.from_dict({"voice": {"enabled": True, "tts": "pyttsx3"}})
    assert cfg.voice["enabled"] is True and cfg.voice["tts"] == "pyttsx3"
    assert cfg.to_dict()["voice"]["tts"] == "pyttsx3"
    print("  PASS  config_voice_section")


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
    await test_agent_plan_dispatches_and_seeds_todos()
    await test_agent_reask_on_malformed()
    await test_agent_multi_tool_calls()
    await test_agent_streaming_unified()
    await test_agent_context_compaction()
    await test_agent_mid_run_steering()
    await test_agent_delegation()
    await test_mcp_client()
    await test_agent_duplicate_call_guard()

    print("\nSelf-authored tools (feature A)")
    await test_generated_tool_roundtrip()
    await test_generated_tool_manager_create_and_dispatch()
    await test_generated_tool_create_rejects_bad()
    await test_generated_tool_curator_lifecycle()
    await test_generated_tool_hub_checksum()

    print("\nConfig layer (feature C0)")
    test_config_defaults()
    test_config_precedence_chain()
    test_config_env_layer_and_interpolation()
    test_config_provider_for_model_and_redaction()
    test_config_global_path_resolution()

    print("\nSetup wizard (feature C1)")
    test_config_save_and_raw_roundtrip()
    test_wizard_prefs_edit_raw()
    test_wizard_secret_prompt_preserves_on_empty()
    test_cli_overrides_and_config_precedence()

    print("\nCloud providers (feature G)")
    await test_openai_provider_normalizes_response()
    test_model_pool_provider_selection()
    test_model_profile_is_local_gate()

    print("\nRules-of-Engagement (feature J)")
    test_scope_inactive_allows_everything()
    test_scope_target_allowlist()
    test_scope_fallback_target_and_ip_in_command()
    test_scope_forbidden_tools_and_patterns()
    test_scope_load_fail_soft()
    await test_controller_scope_refusal()

    print("\nEngagement log (feature K)")
    await test_engagement_log_captures_and_exports()
    await test_controller_emits_tool_call_and_finding_events()

    print("\nMulti-agent blackboard + operators (feature P)")
    test_shared_blackboard_semantics()
    test_lead_state_reset_still_works()
    test_operator_roster()
    await test_delegate_operator_dispatch()
    await test_delegate_parallel_fans_out()

    print("\nAutomated reporting (feature L)")
    test_report_builder()
    test_report_redaction_and_empty()

    print("\nSkill synthesis (feature N)")
    test_skill_synthesis_and_signing()

    print("\nHybrid OPSEC routing (feature O)")
    test_opsec_policy_decisions()
    test_opsec_local_variant_pins_local()
    await test_opsec_controller_pins_sensitive_operator()

    print("\nCVE grounding (feature M)")
    test_cve_cvss_and_lookup()
    test_cve_ground_services_prioritizes()
    test_cve_attack_state_and_report_integration()
    test_cve_live_nvd_enrichment()

    print("\nMulti-host delegation (feature P)")
    test_multihost_substate_resolution()
    await test_multihost_parallel_delegation()

    print("\nPer-operator model routing (feature P)")
    await test_per_operator_model_role()
    await test_controller_routes_operator_by_role()

    print("\nEditable persona — soul.md (feature E)")
    test_soul_resolution_and_default()
    test_soul_persona_in_system_prompt()
    await test_soul_hot_reload_each_turn()

    print("\nUser profile — user.md (feature F)")
    test_user_profile_dedup_caps_and_persistence()
    test_user_profile_summary_and_total_cap()
    await test_user_profile_tool_and_injection()

    print("\nUpdate manager (feature D)")
    test_updater_version_compare_and_local()
    test_updater_check_cache_and_notice()
    test_updater_backup_config()

    print("\nCLI presentation layer (feature B)")
    test_render_phase_style_and_summary()
    test_render_selection_without_rich()
    test_render_plain_output_matches_legacy()

    print("\nRemote execution backends (feature H)")
    test_exec_backend_build_and_argv()
    await test_exec_backend_local_run_and_shell_tool()
    await test_exec_backend_kali_run_remote()
    test_config_execution_section()

    print("\nCommunity skill hub (feature I)")
    test_hub_manifest_and_verification()
    test_hub_install_generated_and_mcp()
    await test_hub_tools_no_registry()
    test_hub_url_registry()

    print("\nVoice I/O (Phase 9)")
    test_voice_factories_and_manager()
    test_config_voice_section()

    print("\nModelRouting")
    await test_routing_pipeline_picks_fast_executor()
    await test_routing_excludes_embedding_only_model()
    await test_routing_strategy_switch_changes_executor()

    print("\n" + "─" * 40)
    print("All tests passed.\n")


if __name__ == "__main__":
    asyncio.run(run_all())
