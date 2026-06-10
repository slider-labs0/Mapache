"""
generated_tool_manager.py — lifecycle owner for self-authored tools

Owns the on-disk library of generated tools and their active -> stale -> archived
lifecycle (the "curator"). Also defines the model-callable meta-tools that drive
it: create_tool, tool_list_generated, tool_delete.

Wiring (done by the CLI / any frontend):
    manager = GeneratedToolManager(registry, controller, base_dir, shell)
    registry.register(CreateToolTool(manager))
    registry.register(ListGeneratedToolsTool(manager))
    registry.register(DeleteGeneratedToolTool(manager))
    manager.load_all()          # reload persisted tools, demote stale ones

A new tool is registered into BOTH the executable ToolRegistry (so the dispatcher
can run it) and the controller's context (so the model sees it) and tagged with a
phase on the ConversationChain (so phase-based subsetting exposes it). Because the
controller refreshes its active tool set every loop iteration, a tool created this
turn becomes callable on the *next* turn — never dispatched in the same response
that created it.

The curator is the GC for this library: it moves unused tools active -> stale
automatically (a non-destructive label; using a stale tool promotes it back), and
stale -> archived only with per-tool user permission (archiving unregisters the
tool and moves its folder out of the load path; nothing is lost — restore() and a
deliberate purge() round out the lifecycle).
"""

from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from tools.generated_tool import (
    STATE_ACTIVE,
    STATE_ARCHIVED,
    STATE_STALE,
    VALID_PHASES,
    GeneratedTool,
    _name_ok,
    compile_run,
    load_generated_tool,
    load_manifest,
    move_tool_dir,
    render_tool_source,
    save_manifest,
    write_generated_tool,
)

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


class GeneratedToolManager:
    """Owns the generated-tool library and its curator lifecycle."""

    def __init__(
        self,
        registry: Any,
        controller: Any,
        base_dir: str | Path,
        shell: Any = None,
        *,
        never_used_after_days: int = 7,
        idle_after_days: int = 30,
    ) -> None:
        self.registry = registry
        self.controller = controller
        self.shell = shell
        self.never_used_after_days = never_used_after_days
        self.idle_after_days = idle_after_days

        base = Path(base_dir)
        self.generated_dir = base / "plugins" / "generated"
        self.archive_dir = base / "plugins" / "archived"
        self.generated_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)

        self.tools: dict[str, GeneratedTool] = {}

    # ------------------------------------------------------------------ #
    # Registration (registry + controller context + chain phase tag)
    # ------------------------------------------------------------------ #

    def _expose(self, tool: GeneratedTool) -> None:
        self.registry.register(tool)
        if self.controller is not None:
            self.controller.register_tool(tool.to_context_schema())
            chain = getattr(self.controller, "chain", None)
            if chain is not None:
                chain.generated_tools[tool.name] = tool.phase
        self.tools[tool.name] = tool

    def _unexpose(self, name: str) -> None:
        self.registry.unregister(name)
        if self.controller is not None:
            self.controller.unregister_tool(name)
            chain = getattr(self.controller, "chain", None)
            if chain is not None:
                chain.generated_tools.pop(name, None)
        self.tools.pop(name, None)

    # ------------------------------------------------------------------ #
    # Startup load
    # ------------------------------------------------------------------ #

    def load_all(self) -> dict[str, int]:
        """
        Load every persisted (non-archived) tool, register it, and apply the
        staleness rule. Fail-soft: a single bad tool never breaks startup
        (mirrors the MCP precedent). Returns {loaded, stale, failed}.
        """
        loaded = failed = 0
        for tool_dir in sorted(self.generated_dir.iterdir() if self.generated_dir.exists() else []):
            if not tool_dir.is_dir() or not (tool_dir / "manifest.json").exists():
                continue
            try:
                tool = load_generated_tool(tool_dir, shell=self.shell)
            except Exception as exc:
                failed += 1
                logger.warning("Generated tool in %s failed to load: %s", tool_dir.name, exc)
                continue
            if tool.state == STATE_ARCHIVED:
                continue  # archived tools live in archive_dir; ignore strays
            self._expose(tool)
            loaded += 1

        stale = len(self.refresh_states())
        return {"loaded": loaded, "stale": stale, "failed": failed}

    # ------------------------------------------------------------------ #
    # Create
    # ------------------------------------------------------------------ #

    def create(
        self,
        name: str,
        description: str,
        parameters: Any,
        code: str,
        phase: str = "always",
    ) -> str:
        """Validate, persist, compile, and register a new self-authored tool."""
        name = (name or "").strip()
        if not _name_ok(name):
            return ("Error: invalid tool name. Use lowercase letters, digits and "
                    "underscores, starting with a letter (2-49 chars).")
        if self.registry.has(name):
            return f"Error: a tool named '{name}' already exists. Pick another name."

        if isinstance(parameters, str):
            try:
                parameters = json.loads(parameters)
            except json.JSONDecodeError:
                return "Error: `parameters` must be a JSON Schema object."
        if not isinstance(parameters, dict) or parameters.get("type") != "object":
            return ("Error: `parameters` must be a JSON Schema object, e.g. "
                    '{"type":"object","properties":{...},"required":[...]}.')

        if phase not in VALID_PHASES:
            phase = "always"

        # Compile before writing so broken code never lands on disk; hand the
        # error back so the model can self-correct.
        source = render_tool_source(code)
        try:
            compile_run(source, name)
        except (SyntaxError, ValueError) as exc:
            return f"Error: generated code did not compile: {exc}"

        tool_dir = write_generated_tool(
            self.generated_dir, name, description, parameters, code,
            origin="self", phase=phase,
        )
        try:
            tool = load_generated_tool(tool_dir, shell=self.shell)
            self._expose(tool)
        except Exception as exc:
            shutil.rmtree(tool_dir, ignore_errors=True)
            return f"Error: failed to register '{name}': {exc}"

        return (
            f"Created tool '{name}' (phase={phase}). It will be available to call "
            f"on the next step."
        )

    # ------------------------------------------------------------------ #
    # Curator lifecycle: active -> stale -> archived (-> restore / purge)
    # ------------------------------------------------------------------ #

    def _staleness_reason(self, tool: GeneratedTool) -> Optional[str]:
        """Return a human reason if the tool should be stale, else None."""
        m = tool.manifest
        created = _parse_iso(m.get("created"))
        last_used = _parse_iso(m.get("last_used"))
        use_count = int(m.get("use_count", 0))
        now = _now()

        if use_count == 0 and last_used is None:
            age_days = (now - created).days if created else 999
            if age_days >= self.never_used_after_days:
                return f"created {created.date() if created else '?'}, never used"
            return None
        if last_used is not None:
            idle_days = (now - last_used).days
            if idle_days >= self.idle_after_days:
                return f"last used {idle_days}d ago"
        return None

    def refresh_states(self) -> list[str]:
        """Demote active tools to stale per the usage rule. Returns stale names."""
        newly_stale = []
        for name, tool in self.tools.items():
            if tool.state != STATE_ACTIVE:
                continue
            reason = self._staleness_reason(tool)
            if reason:
                tool.manifest["state"] = STATE_STALE
                tool.manifest["state_changed"] = _now().isoformat()
                save_manifest(tool.tool_dir, tool.manifest)
                newly_stale.append(name)
        return newly_stale

    def stale_candidates(self) -> list[tuple[str, str]]:
        """Tools currently in the stale state, with a reason for the proposal."""
        out = []
        for name, tool in self.tools.items():
            if tool.state == STATE_STALE:
                reason = self._staleness_reason(tool) or "unused"
                out.append((name, reason))
        return out

    def archive(self, name: str) -> str:
        """Move a tool to archived: unregister + move its folder out of load path."""
        tool = self.tools.get(name)
        if tool is None:
            return f"Error: no generated tool named '{name}'."
        tool_dir = tool.tool_dir
        tool.manifest["state"] = STATE_ARCHIVED
        tool.manifest["state_changed"] = _now().isoformat()
        save_manifest(tool_dir, tool.manifest)
        self._unexpose(name)
        try:
            move_tool_dir(tool_dir, self.archive_dir)
        except Exception as exc:
            return f"Archived '{name}' but could not move folder: {exc}"
        return f"Archived '{name}'. Restore with /restore {name}."

    def restore(self, name: str) -> str:
        """Bring an archived tool back: move into the load path + re-register."""
        src = self.archive_dir / name
        if not src.is_dir():
            return f"Error: no archived tool named '{name}'."
        try:
            new_dir = move_tool_dir(src, self.generated_dir)
            manifest = load_manifest(new_dir)
            manifest["state"] = STATE_ACTIVE
            manifest["state_changed"] = _now().isoformat()
            save_manifest(new_dir, manifest)
            tool = load_generated_tool(new_dir, shell=self.shell)
            self._expose(tool)
        except Exception as exc:
            return f"Error: failed to restore '{name}': {exc}"
        return f"Restored '{name}' — active again."

    def purge(self, name: str) -> str:
        """Hard-delete an *archived* tool. Refuses to touch a live tool."""
        if name in self.tools:
            return (f"Error: '{name}' is still active/stale. Archive it first "
                    f"(it must be archived before it can be purged).")
        src = self.archive_dir / name
        if not src.is_dir():
            return f"Error: no archived tool named '{name}'."
        shutil.rmtree(src, ignore_errors=True)
        return f"Purged '{name}' permanently."

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    def list_info(self) -> list[dict[str, Any]]:
        rows = []
        for name, tool in sorted(self.tools.items()):
            m = tool.manifest
            rows.append({
                "name": name,
                "origin": m.get("origin", "self"),
                "state": m.get("state", STATE_ACTIVE),
                "phase": m.get("phase", "always"),
                "use_count": int(m.get("use_count", 0)),
                "last_used": m.get("last_used"),
                "description": m.get("description", ""),
            })
        return rows

    def archived_names(self) -> list[str]:
        if not self.archive_dir.exists():
            return []
        return sorted(
            d.name for d in self.archive_dir.iterdir()
            if d.is_dir() and (d / "manifest.json").exists()
        )


# --------------------------------------------------------------------------- #
# Model-callable meta-tools
# --------------------------------------------------------------------------- #


class CreateToolTool(BaseTool):
    name = "create_tool"
    description = (
        "Author a brand-new reusable tool when no existing tool fits and you'd "
        "otherwise repeat the same multi-step shell work. You write the BODY of "
        "`async def run(args, shell)`: `args` is a dict of the validated "
        "arguments you declare, and `await shell(\"cmd\")` runs a shell command "
        "and returns its output. Return a string. The tool persists and becomes "
        "callable on your next step. Do not recreate a tool that already exists."
    )
    parameters = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "snake_case tool name (unique, starts with a letter).",
            },
            "description": {
                "type": "string",
                "description": "What the tool does — shown to you when choosing tools.",
            },
            "parameters": {
                "type": "object",
                "description": (
                    "JSON Schema for the tool's arguments, e.g. "
                    '{"type":"object","properties":{"host":{"type":"string"}},'
                    '"required":["host"]}.'
                ),
            },
            "code": {
                "type": "string",
                "description": (
                    "The body of `async def run(args, shell)`. Use args[...] for "
                    "inputs and `await shell(cmd)` to run commands. Return a string."
                ),
            },
            "phase": {
                "type": "string",
                "description": "Attack phase this tool belongs to (default: always).",
                "enum": ["recon", "enumeration", "exploitation", "post", "reporting", "always"],
                "default": "always",
            },
        },
        "required": ["name", "description", "parameters", "code"],
    }
    permissions = {Permission.FILESYSTEM}
    tags = ["meta", "generated"]

    def __init__(self, manager: GeneratedToolManager) -> None:
        self._manager = manager

    async def execute(self, name: str, description: str, parameters: Any,
                      code: str, phase: str = "always", **kwargs: Any) -> ToolResult:
        msg = self._manager.create(name, description, parameters, code, phase)
        ok = msg.startswith("Created")
        return ToolResult.ok(msg) if ok else ToolResult.fail(msg)


class ListGeneratedToolsTool(BaseTool):
    name = "tool_list_generated"
    description = (
        "List the tools you have authored, with their lifecycle state "
        "(active/stale), phase, and how often each has been used."
    )
    parameters = {"type": "object", "properties": {}}
    tags = ["meta", "generated"]

    def __init__(self, manager: GeneratedToolManager) -> None:
        self._manager = manager

    async def execute(self, **kwargs: Any) -> ToolResult:
        rows = self._manager.list_info()
        if not rows:
            return ToolResult.ok("No self-authored tools yet.")
        lines = ["name                 state    phase        uses  description"]
        for r in rows:
            lines.append(
                f"{r['name']:20s} {r['state']:8s} {r['phase']:12s} "
                f"{r['use_count']:4d}  {r['description'][:40]}"
            )
        return ToolResult.ok("\n".join(lines))


class DeleteGeneratedToolTool(BaseTool):
    name = "tool_delete"
    description = (
        "Archive a tool you authored (e.g. one you just created with a mistake). "
        "Archiving is reversible — it unregisters the tool and moves it aside; the "
        "user can restore it. Use only on generated tools, by name."
    )
    parameters = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Name of the generated tool to archive."},
        },
        "required": ["name"],
    }
    permissions = {Permission.DANGEROUS}
    tags = ["meta", "generated"]

    def __init__(self, manager: GeneratedToolManager) -> None:
        self._manager = manager

    async def execute(self, name: str, **kwargs: Any) -> ToolResult:
        msg = self._manager.archive(name)
        ok = msg.startswith("Archived")
        return ToolResult.ok(msg) if ok else ToolResult.fail(msg)


def build_meta_tools(manager: GeneratedToolManager) -> list[BaseTool]:
    """The model-callable meta-tools that drive the generated-tool library."""
    return [
        CreateToolTool(manager),
        ListGeneratedToolsTool(manager),
        DeleteGeneratedToolTool(manager),
    ]
