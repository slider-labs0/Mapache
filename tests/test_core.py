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

    print("\nModelRouting")
    await test_routing_pipeline_picks_fast_executor()
    await test_routing_excludes_embedding_only_model()
    await test_routing_strategy_switch_changes_executor()

    print("\n" + "─" * 40)
    print("All tests passed.\n")


if __name__ == "__main__":
    asyncio.run(run_all())
