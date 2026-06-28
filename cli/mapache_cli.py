#!/usr/bin/env python3
"""
mapache_cli.py — Mapache CLI (Phase 7 — Optimized for full-scale attacks)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent_controller import AgentController, AgentMode
from core.logger import get_logger, setup_logging
from integrations.mcp import MCPManager, load_mcp_config
from core.project_context import build_project_context, get_mapache_instructions
from memory.memory_manager import MemoryManager
from models.model_registry import (
    ModelRegistry, ModelRole, ModelProfile, ModelCapabilities, Provider,
)
from core.config import load_config
from core.engagement_scope import load_scope
from core.engagement_log import EngagementLog
from models.routing_engine import RoutingEngine, RoutingStrategy
from models.model_pool import ModelPool
from models.routed_model import RoutedModel
from core.opsec_routing import OpsecPolicy
from core.soul import load_soul, soul_file, init_soul
from memory.user_profile import UserProfile, UserRememberTool
from cli.render import make_renderer
from core.exec_backend import backend_from_config
from voice import voice_from_config
from models.providers.ollama_provider import OllamaProvider
from plugins.sdk.base_tool import Permission
from security_tools.recon.nmap_tool import NmapTool
from security_tools.shell_tool import ShellTool
from security_tools.exploitation.metasploit_tool import (
    MetasploitSearchTool, MetasploitRunTool, MetasploitSessionsTool,
)
from security_tools.exploitation.burpsuite_tool import BurpScanTool, BurpProxyTool
from security_tools.cracking.john_tool import JohnCrackTool, JohnFormatTool
from security_tools.kali.kali_tools_interface import (
    KaliToolListTool, KaliRunTool, SearchsploitTool,
)
from browser.scraping_tools import WebFetchTool, WebSearchTool, TorFetchTool
from tools.filesystem_tool import (
    FileReadTool, FileWriteTool, FileEditTool,
    FileListTool, FileSearchTool,
)
from tools.tool_dispatcher import ToolDispatcher
from tools.tool_registry import ToolRegistry
from tools.generated_tool_manager import GeneratedToolManager, build_meta_tools

try:
    from integrations.social.moltbook_tool import (
        MoltbookRegisterTool, MoltbookStatusTool, MoltbookPostTool,
        MoltbookFeedTool, MoltbookCommentTool, MoltbookSearchTool,
    )
    HAS_MOLTBOOK = True
except ImportError:
    HAS_MOLTBOOK = False

logger = get_logger(__name__)

BANNER = """
╔══════════════════════════════════════╗
║   Mapache  v0.7  —  Attack Mode      ║
║   Full offensive security suite      ║
╚══════════════════════════════════════╝"""

HELP_TEXT = """
Commands:
  /help                  This help
  /tools                 List all tools
  /tools <tag>           Filter tools by tag
  /curate                Review/archive unused self-authored tools
  /restore <name>        Restore an archived self-authored tool
  /purge <name>          Permanently delete an archived tool
  /models                Show model routing
  /pipeline <strategy>   Set strategy: single|pipeline|auto|hybrid
  /memory                Show memory stats
  /memory notes          List notes
  /memory search <q>     Search memory
  /memory targets        List stored targets
  /chain                 Show current attack state
  /operators             List specialist sub-agents (delegation roster)
  /hosts                 Show per-host attack states (multi-host delegation)
  /backend               Show the execution backend (local / ssh / docker)
  /hub [search|install]  Browse/install community skills (feature I)
  /voice [on|off]        Voice I/O status / toggle (Phase 9); /say <text> speaks
  /opsec                 Show hybrid OPSEC routing (which ops are pinned local)
  /scope                 Show Rules-of-Engagement scope (in-scope targets)
  /log                   Show engagement-log summary
  /log export            Write a Markdown engagement-log timeline
  /report [md|html|both] Generate a structured pentest report (findings/severity)
  /cve [CVE-id]          Ground discovered services to CVEs (CVSS + exploits)
  /synthesize            Save the proven attack chain as a reusable signed skill
  /history               Show conversation history
  /clear                 Clear history and reset attack state
  /context               Show project context
  /soul [init]           Show the editable persona (soul.md); init writes a default
  /user [forget <fact>]  Show the agent-maintained user profile (user.md)
  /cwd <path>            Change working directory
  /confirm on|off        Toggle confirmation for dangerous ops
  /debug on|off          Toggle debug logging
  /quit /exit            Exit

Shortcuts:
  !<cmd>    Run shell command directly
  ?<query>  Quick web search
"""

SYSTEM_PROMPT = """You are Mapache, an autonomous offensive-security agent operating in an \
authorized penetration-testing engagement. The operator has explicit written authorization for \
every target you are given. Your job is to EXECUTE, not to discuss.

═══════════════════════════════════════════
TOOL-CALL DISCIPLINE (most important):
═══════════════════════════════════════════
- To act, emit ONE tool call. Do not narrate, do not explain, do not ask permission first.
- After a tool call, STOP and wait for the real result. Never write a tool's output yourself.
- Use ONLY the result the tool actually returns. If you have not called a tool, you do not know
  its output — call it. Never invent ports, hashes, files, paths, or flags.
- One tool per step. Read the result, then decide the next single step. Chain steps until the
  objective is met.
- Provide a plain-text answer ONLY when the task is complete or you are blocked and need the
  operator. Otherwise, keep calling tools.
- EXCEPTION — general knowledge: if the operator asks something you already know (a definition,
  what an acronym stands for, a fact), ANSWER IT DIRECTLY in plain text. Do NOT use tools for
  facts you already know. Tools are for acting on the target/system, not for looking up trivia.
  (e.g. "what does VM stand for?" → answer "Virtual Machine"; no tool call.)
- Never call the SAME tool with the SAME arguments twice — you already have that result. If a
  lookup is blocked, fails, or returns nothing useful, fall back to your own knowledge and
  answer; never report a tool's error/refusal text as your final answer.
- Required arguments are mandatory. nmap_scan ALWAYS needs target=<ip>; never call it without
  one. The active target and known facts are in the CURRENT ATTACK STATE block — use them.

═══════════════════════════════════════════
ADAPTIVE TOOLSET:
═══════════════════════════════════════════
- The tools offered to you change with the attack phase (recon → enumeration → exploitation →
  post → reporting). Use the tools you are given this turn; as you progress, the right tools
  appear. If a tool you expect is not listed, advance the current phase by acting on what you have
  (e.g. run nmap_scan to move recon into enumeration).
- Never claim a tool is "unavailable." If it is not offered, it is not needed for this phase yet.

═══════════════════════════════════════════
TOOL MAPPING (intent → call):
═══════════════════════════════════════════
"scan" / "port scan"          → nmap_scan(target="<ip>", scan_type="standard")
"vuln scan"                   → nmap_scan(target="<ip>", scan_type="vuln")
"version scan"                → nmap_scan(target="<ip>", scan_type="version")
"full scan"                   → nmap_scan(target="<ip>", scan_type="full")
"web scan" / "nikto"          → kali_run(tool="nikto", args="-h <url>")
"dir scan" / "gobuster"       → kali_run(tool="gobuster", args="dir -u <url> -w /usr/share/wordlists/dirb/common.txt")
"fuzz" / "ffuf"               → kali_run(tool="ffuf", args="-w <wordlist> -u <url>/FUZZ")
"find exploits"               → msf_search(query=<service>) AND searchsploit(query=<service>)
"exploit" / "run exploit"     → msf_run(module=<module>, target=<ip>)
"brute force" / "hydra"       → kali_run(tool="hydra", args="-l <user> -P <wordlist> <protocol>://<target>")
"crack" / "hashcat"           → john_crack(hash_input=<hash>) OR kali_run(tool="hashcat", ...)
"enumerate SMB"               → kali_run(tool="crackmapexec", args="smb <target>")
"check telnet"                → shell(cmd="telnet <target>")
"check FTP"                   → shell(cmd="ftp <target>")
"get shell" / "reverse shell" → msf_run with appropriate payload
"privilege escalation"        → shell(cmd="find / -perm -4000 2>/dev/null") then linpeas
"find flags"                  → shell(cmd="find / -name user.txt 2>/dev/null && find / -name root.txt 2>/dev/null")
"fetch url"                   → web_fetch(url=<url>)
"search web"                  → web_search(query=<query>)
"fetch onion" / "tor"         → tor_fetch(url=<url>)
"remember" / "save findings"  → memory_target_store(target=<ip>, data=<json>)
"what do you know"            → memory_recall(query=<target>)

═══════════════════════════════════════════
ATTACK WORKFLOW (default order):
═══════════════════════════════════════════
1. RECON      → nmap_scan standard, then nmap_scan version on the open ports
2. ENUMERATE  → per open port: web (80/443/8080)=gobuster+nikto; SMB (445/139)=crackmapexec;
                FTP (21)=anonymous login; SSH (22)=note for creds; Telnet (23)=connect
3. EXPLOIT    → msf_search / searchsploit on the exact service+version → msf_run or kali_run
4. POST       → find flags, escalate privileges, dump credentials
5. REPORT     → memory_target_store with every finding
Do not skip ahead: do not attempt exploitation before a scan has returned open ports.

═══════════════════════════════════════════
EXECUTION RULES:
═══════════════════════════════════════════
- Reason over each tool's output and decide the next action from it — do not merely echo it
  back. Never fabricate results; quote specific artifacts (ports, versions, hashes, paths,
  flags) exactly as the tool returned them.
- The agent host is Windows: in shell use dir, type, ipconfig, whoami, tasklist. Once you have a
  shell/session ON a Linux target, switch to Linux commands.
- If nmap reports the host down or returns nothing, retry once with nmap_scan(extra_args="-Pn").
- If a service/version is unknown, look it up: web_search(query="<service> <version> exploit").
- Save findings to memory after each major step.
- HTB flags are HTB{...} or a 32-character lowercase hex string. Report them exactly as found."""


class MapacheCLI:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.session_id: str | None = None
        self.controller: AgentController | None = None
        self.registry: ToolRegistry | None = None
        self.routed: RoutedModel | None = None
        self.mcp: MCPManager | None = None
        self.gen_manager: GeneratedToolManager | None = None
        self.scope = None  # EngagementScope, loaded in setup()
        self.engagement_log: EngagementLog | None = None  # feature K, started in run()
        self.memory = MemoryManager()
        self.confirm = args.confirm
        self.working_dir = os.path.abspath(args.dir)

        # Presentation layer (feature B): rich UI on a TTY when `rich` is
        # installed and --plain wasn't passed; otherwise the plain line printer.
        self.render = make_renderer(getattr(args, "plain", False))
        self.exec_backend = None  # feature H — built in setup() from config
        self.hub_client = None    # feature I — built in setup() if a registry is set
        self.voice = None         # Phase 9 — built in setup() from config

        # Config layer (C0/C1). Resolve the effective settings across the full
        # precedence chain — CLI flag > project > global > env > default — by
        # handing load_config ONLY the flags the operator explicitly passed
        # (sparse overrides). This is what makes `mapache setup`'s saved
        # default_model / strategy / allow_cloud actually take effect on a bare
        # `python -m cli` launch; an explicit flag still wins over the file.
        self.config = load_config(self._cli_overrides(args), working_dir=self.working_dir)
        self.model = self.config.default_model
        self.ollama_url = self.config.ollama_url
        self.max_vram = self.config.max_vram_gb
        self.allow_cloud = self.config.allow_cloud

        # Single stdin reader → async queue. One consumer at a time: the REPL
        # when idle, or the steering loop while a turn runs. Lets the operator
        # redirect a running turn (or answer a confirm) without a second reader
        # racing for stdin.
        self._input_q: asyncio.Queue[str | None] | None = None
        self._pending_confirm: asyncio.Future | None = None

        strategy_map = {
            "single":   RoutingStrategy.SINGLE,
            "pipeline": RoutingStrategy.PIPELINE,
            "auto":     RoutingStrategy.AUTO,
            "hybrid":   RoutingStrategy.HYBRID,
        }
        self.strategy = strategy_map.get(self.config.default_strategy.lower(),
                                         RoutingStrategy.AUTO)

    @staticmethod
    def _cli_overrides(args: argparse.Namespace) -> dict:
        """Build the sparse top-precedence override layer from explicit flags.

        Only keys the operator actually set on the command line appear, so unset
        flags fall through to the project/global/env/default layers rather than
        clobbering them. The config-backed flags default to None in parse_args()
        precisely so "not passed" is distinguishable here.
        """
        ov: dict = {}
        if args.model is not None:
            ov["default_model"] = args.model
        if args.strategy is not None:
            ov["default_strategy"] = args.strategy
        if args.ollama_url is not None:
            ov["providers"] = {"ollama": {"base_url": args.ollama_url}}
        if args.max_vram is not None:
            try:
                ov["max_vram_gb"] = float(args.max_vram)
            except ValueError:
                pass
        # --allow-cloud is an on-switch only: passing it forces cloud on, but
        # omitting it must not turn off a config that enabled cloud.
        if args.allow_cloud:
            ov["allow_cloud"] = True
        return ov

    async def setup(self) -> bool:
        # Effective config (incl. provider entries + cloud keys/URLs) was resolved
        # in __init__ across the precedence chain; use the resolved attributes.
        allow_cloud = self.allow_cloud

        # Rules-of-Engagement scope (feature J). Loaded from scope.json in the
        # working dir (or --scope); inactive when absent, so behavior is
        # unchanged until an operator defines limits. Mirrors mcp.json handling.
        scope_path = self.args.scope
        if not os.path.isabs(scope_path):
            scope_path = os.path.join(self.working_dir, scope_path)
        self.scope = load_scope(scope_path)

        # Provider-aware pool: builds Ollama or OpenAI-compatible per model id.
        pool = ModelPool(base_url=self.ollama_url, config=self.config)
        primary_prov = self.config.provider_for_model(self.model)
        primary_is_cloud = primary_prov is not None and primary_prov.is_cloud

        if primary_is_cloud:
            if not allow_cloud:
                print(f"\n  ✗  '{self.model}' is a cloud model "
                      f"({primary_prov.name}); re-run with --allow-cloud.\n")
                return False
            if not primary_prov.is_usable:
                print(f"\n  ✗  Cloud provider '{primary_prov.name}' has no API key.")
                print(f"     Set it in ~/.mapache/config.json or its env var.\n")
                return False
            primary = pool.get(self.model)  # OpenAICompatibleProvider
            available = self.config.cloud_models() or [self.model]
        else:
            primary = OllamaProvider(model=self.model, base_url=self.ollama_url)
            pool.register(self.model, primary)  # reuse the built client
            if not await primary.is_available():
                print(f"\n  ✗  Cannot reach Ollama at {self.ollama_url}")
                print(f"     Run: ollama serve\n")
                return False
            local_models = await primary.list_models()
            model_base = self.model.split(":")[0]
            if local_models and not any(model_base in m for m in local_models):
                print(f"\n  ⚠  Model '{self.model}' not found.")
                pull = input(f"     Pull it now? [y/N] ").strip().lower()
                if pull == "y":
                    await primary.pull_model(self.model)
                else:
                    return False
            # Local models + any usable cloud models the router may also pick.
            available = (local_models or [self.model]) + self.config.cloud_models()

        mode = AgentMode.CHAT if self.args.no_tools else AgentMode.AGENT

        async def confirm_cb(tool_name: str, args: dict) -> bool:
            if not self.confirm:
                return True
            print(f"\n  ⚠ Confirm {tool_name}({str(args)[:100]})? [Y/n] ", end="", flush=True)
            # Read the answer via the single stdin reader (the steering loop
            # routes the next typed line to this future) so we don't open a
            # second competing reader on stdin.
            loop = asyncio.get_event_loop()
            fut: asyncio.Future = loop.create_future()
            self._pending_confirm = fut
            try:
                ans = (await fut).strip().lower()
            finally:
                self._pending_confirm = None
            return ans != "n"

        # Phase 7 — per-role model routing. RoutedModel consults the
        # RoutingEngine on every call and dispatches to the best installed
        # model for the role (the agent loop runs as EXECUTOR). With one
        # model installed this collapses to that single model.
        registry = ModelRegistry()
        self._register_cloud_models(registry)  # so routing + the OPSEC gate see them
        routing = RoutingEngine(
            registry,
            strategy=self.strategy,
            primary_model_id=self.model,
            local_only=not allow_cloud,
            max_vram_gb=float(self.max_vram),
        )
        routing.set_available_models(available or [self.model])

        def _opsec_warn(model_id: str) -> None:
            print(f"\n  ⚠ OPSEC: routing to CLOUD model '{model_id}' — target/scan/"
                  f"cred context is leaving this machine.\n", flush=True)

        self.routed = RoutedModel(routing, pool, primary_model_id=self.model,
                                  on_cloud_call=_opsec_warn)
        self._warn_cloud_roles(registry)  # startup banner if a role is cloud

        # Hybrid OPSEC routing (feature O): when cloud is allowed, sensitive
        # delegations (loot/cred operators, or any op after creds are captured)
        # are pinned to a local model so target data never leaves the host.
        self.opsec = OpsecPolicy(allow_cloud=allow_cloud)

        # Agent-maintained user profile (feature F): durable facts about the
        # operator, injected as a compact summary each turn.
        self.user_profile = UserProfile()

        # Execution backend (feature H): where `shell` runs — local / ssh /
        # docker. From config.execution; --exec-backend overrides the kind.
        exec_spec = dict(getattr(self.config, "execution", None) or {"backend": "local"})
        if getattr(self.args, "exec_backend", None):
            exec_spec["backend"] = self.args.exec_backend
        self.exec_backend, exec_warn = backend_from_config(exec_spec)
        if exec_warn:
            print(f"  ⚠ {exec_warn}")

        # Voice I/O (Phase 9): optional TTS/STT. From config.voice; --voice forces
        # it on. Null providers by default, so this is a no-op until a backend is
        # installed + selected.
        voice_spec = dict(getattr(self.config, "voice", None) or {})
        if getattr(self.args, "voice", False):
            voice_spec["enabled"] = True
        self.voice, voice_warns = voice_from_config(voice_spec)
        for w in voice_warns:
            print(f"  ⚠ {w}")

        # Opt-in verifier (--verify): route the verification call to the
        # VERIFIER-role model so it can use a higher-quality model than the loop.
        async def verifier_caller(messages: list[dict]):
            return await self.routed.chat(
                messages=messages, role=ModelRole.VERIFIER, json_mode=True
            )

        self.controller = AgentController(
            model_provider=self.routed,
            mode=mode,
            use_function_calling=self.routed.supports_tools,
            system_prompt=SYSTEM_PROMPT,
            working_dir=self.working_dir,
            confirm_dangerous=self.confirm,
            confirm_callback=confirm_cb,
            enable_tool_subsetting=not self.args.all_tools,
            enable_verifier=self.args.verify,
            verifier_caller=verifier_caller,
            scope=self.scope,
            opsec_policy=self.opsec,
            # Persona (feature E): re-read soul.md each turn so edits hot-reload.
            persona_provider=lambda: load_soul(self.working_dir),
            # User profile (feature F): inject durable user facts each turn.
            profile_provider=lambda: self.user_profile.summary(),
        )
        self._wire_scope_notifier()

        if not self.args.no_tools:
            self.registry = ToolRegistry(granted_permissions={
                Permission.SHELL,
                Permission.FILESYSTEM,
                Permission.NETWORK,
                Permission.SYSTEM_INFO,
                Permission.TOR,
                Permission.DANGEROUS,
                Permission.UNRESTRICTED,
            })

            # Core — `shell` dispatches through the execution backend (feature H:
            # local / ssh / docker), built from config (--exec-backend overrides).
            self.registry.register(ShellTool(backend=self.exec_backend))

            # Filesystem
            self.registry.register(FileReadTool())
            self.registry.register(FileWriteTool())
            self.registry.register(FileEditTool())
            self.registry.register(FileListTool())
            self.registry.register(FileSearchTool())

            # Recon
            self.registry.register(NmapTool())

            # Browser
            self.registry.register(WebFetchTool())
            self.registry.register(WebSearchTool())
            self.registry.register(TorFetchTool())

            # Phase 6 — Advanced security
            self.registry.register(MetasploitSearchTool())
            self.registry.register(MetasploitRunTool())
            self.registry.register(MetasploitSessionsTool())
            self.registry.register(BurpScanTool())
            self.registry.register(BurpProxyTool())
            self.registry.register(JohnCrackTool())
            self.registry.register(JohnFormatTool())
            self.registry.register(KaliToolListTool())
            self.registry.register(KaliRunTool())
            self.registry.register(SearchsploitTool())

            # Memory
            for tool in self.memory.get_tools():
                self.registry.register(tool)

            # Moltbook
            if HAS_MOLTBOOK:
                self.registry.register(MoltbookRegisterTool())
                self.registry.register(MoltbookStatusTool())
                self.registry.register(MoltbookPostTool())
                self.registry.register(MoltbookFeedTool())
                self.registry.register(MoltbookCommentTool())
                self.registry.register(MoltbookSearchTool())

            # MCP: connect to configured servers and register their tools so
            # they're indistinguishable from built-ins to the model.
            await self._connect_mcp()

            dispatcher = ToolDispatcher(self.registry, scope=self.scope)
            self.controller.tool_dispatcher = dispatcher
            self.controller.executor.set_tool_dispatcher(dispatcher)

            # Self-authored tools (Hermes-style): register the create/list/delete
            # meta-tools, then reload any tools the agent authored previously.
            await self._setup_generated_tools(dispatcher)

            for schema in self.registry.get_context_schemas():
                self.controller.register_tool(schema)

        await self.controller.start(inject_project_context=not self.args.no_context)
        return True

    def _register_cloud_models(self, registry: ModelRegistry) -> None:
        """Register configured cloud models so routing + the OPSEC gate see them.

        Without a profile, the routing engine's local_only filter can't tell a
        model is cloud (a missing profile isn't filtered), so cloud models must
        be registered for --allow-cloud to actually gate them.
        """
        if self.config is None:
            return
        name_map = {
            "openrouter": Provider.OPENROUTER, "nous": Provider.NOUS,
            "openai": Provider.OPENAI, "anthropic": Provider.ANTHROPIC,
        }
        for prov in self.config.usable_providers():
            if not prov.is_cloud:
                continue
            penum = name_map.get(prov.name, Provider.OPENAI)
            for mid in prov.models:
                registry.register(ModelProfile(
                    id=mid, provider=penum, display_name=mid,
                    planner_score=0.90, executor_score=0.85, verifier_score=0.90,
                    capabilities=ModelCapabilities(
                        supports_tools=True, context_window=32768,
                        max_output_tokens=4096),
                    speed_score=0.80, quality_score=0.90,
                    cost_per_1k_tokens=0.001, tags=["cloud", prov.name],
                ))

    def _warn_cloud_roles(self, registry: ModelRegistry) -> None:
        """Startup OPSEC banner listing any role that resolves to a cloud model."""
        if self.routed is None:
            return
        cloud = []
        for role in (ModelRole.PLANNER, ModelRole.EXECUTOR, ModelRole.VERIFIER):
            mid = self.routed.model_for(role)
            prof = registry.get(mid)
            if prof is not None and not prof.is_local:
                cloud.append((role.value, mid))
        if cloud:
            print("\n  ⚠ OPSEC: cloud model(s) active — data will leave this machine:")
            for role, mid in cloud:
                print(f"      {role:9s} → {mid}")

    def _wire_scope_notifier(self) -> None:
        """Print a visible line whenever the RoE gate refuses a call (feature J).

        The refusal is also fed to the model as a tool result, but the operator
        should see it live — it's the signal that the guardrail is doing its job.
        """
        if self.controller is None:
            return

        async def _on_refused(event) -> None:
            data = event.data or {}
            print(f"\n  ⛔ RoE: refused {data.get('tool_name')} — "
                  f"{data.get('reason')}\n", flush=True)

        self.controller.bus.subscribe("agent.scope_refused", _on_refused)

    async def _connect_mcp(self) -> None:
        """Load mcp.json, connect to each server, register its tools."""
        if self.registry is None or self.controller is None:
            return
        path = self.args.mcp_config
        if not os.path.isabs(path):
            path = os.path.join(self.working_dir, path)
        configs = load_mcp_config(path)
        if not configs:
            return

        self.mcp = MCPManager(configs)
        try:
            mcp_tools = await self.mcp.connect_all()
        except Exception as exc:  # never let MCP break startup
            print(f"  MCP      : failed to connect ({exc})")
            self.mcp = None
            return

        for tool in mcp_tools:
            self.registry.register(tool)
        if mcp_tools:
            # Pin MCP tool names so phase-based subsetting keeps them exposed.
            self.controller.chain.always_tools |= set(self.mcp.tool_names)
            print(f"  MCP      : {len(mcp_tools)} tools from "
                  f"{len(self.mcp.clients)} server(s)")

    async def _setup_generated_tools(self, dispatcher: ToolDispatcher) -> None:
        """Register the meta-tools and reload the persisted generated-tool library."""
        if self.registry is None or self.controller is None:
            return

        async def gen_shell(cmd: str) -> str:
            return await dispatcher.dispatch("shell", {"cmd": cmd}, self.session_id or "")

        self.gen_manager = GeneratedToolManager(
            registry=self.registry,
            controller=self.controller,
            base_dir=self.working_dir,
            shell=gen_shell,
        )
        for tool in build_meta_tools(self.gen_manager):
            self.registry.register(tool)

        # Skill synthesis (feature N): an agent-callable tool that saves the
        # current proven chain as a reusable, signed skill. Providers are read
        # lazily so they see the engagement log (started later in run()).
        from core.skill_synthesis import SynthesizeSkillTool
        self.registry.register(SynthesizeSkillTool(
            self.gen_manager,
            lambda: self.engagement_log.records if self.engagement_log else [],
            lambda: self.controller.chain.attack_state if self.controller else None,
            lambda: self.session_id or "",
        ))

        # CVE grounding (feature M): correlate discovered services/versions to
        # known CVEs with CVSS + exploit availability (offline catalog).
        from core.cve_grounding import CVELookupTool
        self.registry.register(CVELookupTool(
            lambda: self.controller.chain.attack_state if self.controller else None,
        ))

        # User profile (feature F): tool to record durable facts about the operator.
        self.registry.register(UserRememberTool(self.user_profile))

        # Community skill hub (feature I): build a client when a registry is
        # configured; install generated tools into the same dir the manager loads
        # from, and MCP servers into mcp.json. Tools register regardless and report
        # cleanly when no hub is configured. trusted_key stays None — the checksum
        # is the integrity gate; foreign signatures are noted, not trusted.
        registry_path = str((getattr(self.config, "hub", None) or {}).get("registry", "")).strip()
        if registry_path:
            from hub import make_registry, HubClient
            self.hub_client = HubClient(
                make_registry(registry_path),  # path → Local, http(s):// → Url
                generated_dir=self.gen_manager.generated_dir,
                mcp_path=self.args.mcp_config)
        from hub.tools import SkillSearchTool, SkillListTool, SkillInstallTool
        self.registry.register(SkillSearchTool(lambda: self.hub_client))
        self.registry.register(SkillListTool(lambda: self.hub_client))
        self.registry.register(SkillInstallTool(lambda: self.hub_client))

        stats = self.gen_manager.load_all()
        if stats["loaded"] or stats["failed"]:
            note = f"  Tools+   : {stats['loaded']} self-authored"
            if stats["stale"]:
                note += f", {stats['stale']} stale (/curate to review)"
            if stats["failed"]:
                note += f", {stats['failed']} failed to load"
            print(note)

    async def run(self) -> None:
        if not await self.setup():
            sys.exit(1)

        session = self.memory.new_session()
        self.session_id = session.session_id
        stats = self.memory.stats()

        # Engagement log (feature K): an append-only audit trail of this session,
        # fed by the controller's event bus. On by default; --no-engagement-log
        # disables it. Path printed below so it is never a silent side effect.
        if not self.args.no_engagement_log and self.controller is not None:
            import datetime as _dt
            stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            log_path = os.path.join(self.working_dir, "engagements",
                                    f"engagement-{stamp}.jsonl")
            self.engagement_log = EngagementLog(path=log_path, session_id=self.session_id)
            self.engagement_log.attach(self.controller.bus, metadata={
                "model": self.model, "strategy": self.strategy.value,
                "working_dir": self.working_dir,
                "scope": self.scope.name if (self.scope and self.scope.active) else None,
                "roe_enforced": bool(self.scope and self.scope.active),
            })

        print(BANNER)
        print(f"  Model    : {self.model}")
        print(f"  Strategy : {self.strategy.value}")
        print(f"  Dir      : {self.working_dir}")
        print(f"  Confirm  : {'on' if self.confirm else 'off'}")
        print(f"  Verifier : {'on (--verify)' if self.args.verify else 'off'}")
        print(f"  ToolSubset: {'off (all tools)' if self.args.all_tools else 'on (phase-based)'}")
        print(f"  Memory   : {stats['notes']} notes, {stats['knowledge_entries']} facts")

        if self.scope and self.scope.active:
            print(f"  RoE      : ENFORCED — in-scope {self.scope.targets_summary()}")
        else:
            print(f"  RoE      : off (no scope.json)")

        if self.engagement_log:
            print(f"  Log      : {self.engagement_log.path}")

        if self.routed:
            print(f"\n{self.routed.explain()}")

        if self.scope and self.scope.active:
            print(f"\n{self.scope.summary()}")

        if self.registry:
            print(f"\n  Tools    : {len(self.registry.list_names())} registered")

        if self.exec_backend is not None and self.exec_backend.name != "local":
            print(f"  Exec     : {self.exec_backend.describe()} (shell runs remote)")

        if self.voice is not None and self.voice.enabled:
            print(f"  Voice    : {self.voice.describe()}")

        if get_mapache_instructions(self.working_dir):
            print("  MAPACHE.md loaded")

        # Version + non-blocking update notice (feature D). The notice reads a
        # cache written by the last `mapache update [--check]`, so it never hits
        # the network at startup.
        from core.updater import local_version, update_notice
        print(f"\n  Version  : mapache {local_version()}")
        notice = update_notice()
        if notice:
            print(f"  ⬆ {notice}")

        print(f"\n  Type /help for commands")
        print(f"  (you can type while the agent works to steer it mid-task)\n")

        # One persistent background reader feeds every typed line into a queue.
        loop = asyncio.get_event_loop()
        self._input_q = asyncio.Queue()

        def _stdin_reader() -> None:
            for line in sys.stdin:
                loop.call_soon_threadsafe(self._input_q.put_nowait, line.rstrip("\n"))
            loop.call_soon_threadsafe(self._input_q.put_nowait, None)  # EOF

        threading.Thread(target=_stdin_reader, daemon=True).start()

        try:
            while True:
                print("you > ", end="", flush=True)
                try:
                    raw = await self._input_q.get()
                except (asyncio.CancelledError, KeyboardInterrupt):
                    print("\nBye.")
                    break
                if raw is None:  # EOF (Ctrl+Z / Ctrl+D)
                    print("\nBye.")
                    break

                raw = raw.strip()
                if not raw:
                    continue

                if raw.startswith("/"):
                    if await self._handle_command(raw):
                        continue
                    break

                if raw.startswith("!"):
                    await self._run_shell_direct(raw[1:].strip())
                    continue

                if raw.startswith("?"):
                    raw = f"search the web for: {raw[1:].strip()}"

                await self._agent_turn(raw)
        finally:
            if self.engagement_log:
                self.engagement_log.close(summary={
                    "target": self.controller.chain.attack_state.target
                    if self.controller else None,
                    "flags": len(self.controller.chain.attack_state.flags)
                    if self.controller else 0,
                })
                print(f"  Engagement log: {self.engagement_log.summary()}")
            if self.mcp:
                await self.mcp.close_all()
            await self.memory.end_session()

    async def _agent_turn(self, user_input: str) -> None:
        if self.controller is None:
            return
        self.render.start_turn()
        # Colour-coded phase banner + target/ports pulled from the attack state.
        self.render.phase_line(self.controller.chain.attack_state)
        turn_id = self.memory.session.start_turn(user_input) if self.memory.session else None
        try:
            # Stream tokens live when the model supports it (native tool-calling
            # models). The controller no-ops the callback in JSON mode, so the
            # renderer's streamed state stays False and it prints the content.
            turn_task = asyncio.create_task(self.controller.run(
                user_input, session_id=self.session_id, on_token=self.render.stream
            ))
            response = await self._drive_turn(turn_task)
            self.session_id = response.session_id
            self.render.agent_result(response.content, response.tool_calls_made,
                                     response.iterations, response.error)
            # Voice (Phase 9): speak the response when voice is enabled (no-op
            # under the null backend). Never let TTS break the turn.
            if self.voice is not None and self.voice.enabled and response.content:
                self.voice.speak(response.content)
            if turn_id and self.memory.session:
                self.memory.session.end_turn(turn_id, response.content)
        except Exception as exc:
            self.render.error(str(exc))
            if self.args.debug:
                import traceback
                traceback.print_exc()

    async def _drive_turn(self, turn_task: asyncio.Task):
        """
        Await a turn while consuming typed lines as live steering.

        Each line typed during the turn is routed to a pending confirmation
        prompt if one is open, otherwise handed to controller.steer(). Lines
        that arrive after the turn ends stay buffered in the queue for the
        next REPL prompt (nothing is lost).
        """
        assert self._input_q is not None
        while not turn_task.done():
            get_task = asyncio.create_task(self._input_q.get())
            done, _pending = await asyncio.wait(
                {turn_task, get_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if get_task in done:
                line = get_task.result()
                if line is None:  # EOF mid-turn — stop steering, let turn finish
                    continue
                line = line.strip()
                if self._pending_confirm is not None and not self._pending_confirm.done():
                    self._pending_confirm.set_result(line)
                elif line and self.controller is not None:
                    self.controller.steer(line)
                    self.render.steering(line)
            else:
                # Turn finished first; don't strand the queued get — its item
                # (if any) remains buffered for the REPL.
                get_task.cancel()
        return turn_task.result()

    async def _read_line(self) -> str:
        """Read one line from the shared stdin queue (no second reader)."""
        if self._input_q is None:
            return ""
        line = await self._input_q.get()
        return "" if line is None else line

    async def _curate(self) -> None:
        """
        Curator: propose archiving stale self-authored tools, one at a time,
        and archive only those the user approves. Archiving is reversible
        (/restore), so this never destroys work.
        """
        if not self.gen_manager:
            print("  No generated-tool library.")
            return
        self.gen_manager.refresh_states()
        candidates = self.gen_manager.stale_candidates()
        if not candidates:
            print("  No stale tools — the generated-tool library is clean.")
            return
        print(f"\n  {len(candidates)} stale tool(s). Archiving is reversible "
              f"(/restore <name>).")
        for name, reason in candidates:
            print(f"\n  • {name} — {reason}")
            print(f"    archive '{name}'? [y/N] ", end="", flush=True)
            ans = (await self._read_line()).strip().lower()
            if ans == "y":
                print(f"    {self.gen_manager.archive(name)}")
            else:
                print(f"    kept '{name}'.")
        print()

    async def _generate_report(self, fmt: str) -> None:
        """Build a structured engagement report (feature L) from the blackboard +
        engagement-log records and write Markdown / HTML under engagements/."""
        if self.controller is None:
            return
        import datetime as _dt
        from reporting import build_report

        records = self.engagement_log.records if self.engagement_log else []
        meta = {
            "Model": self.model,
            "Scope": self.scope.name if (self.scope and self.scope.active) else "none",
            "RoE enforced": bool(self.scope and self.scope.active),
            "Session": self.session_id,
        }
        report = build_report(self.controller.chain.attack_state, records, meta)

        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = os.path.join(self.working_dir, "engagements")
        os.makedirs(out_dir, exist_ok=True)
        written: list[str] = []
        if fmt in ("md", "markdown", "both"):
            path = os.path.join(out_dir, f"report-{stamp}.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(report.to_markdown())
            written.append(path)
        if fmt in ("html", "both"):
            path = os.path.join(out_dir, f"report-{stamp}.html")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(report.to_html())
            written.append(path)

        counts = report.severity_counts()
        sev = ", ".join(f"{n} {s.lower()}" for s, n in counts.items() if n) or "no findings"
        print(f"\n  Report ({len(report.findings)} findings — {sev}):")
        for path in written:
            print(f"    {path}")
        print()

    async def _synthesize_skill(self) -> None:
        """Save the current proven chain as a reusable, signed skill (feature N)."""
        if self.controller is None or self.gen_manager is None:
            print("  Generated-tool library not available.")
            return
        from core.skill_synthesis import synthesize_from_log, persist_skill
        records = self.engagement_log.records if self.engagement_log else []
        skill = synthesize_from_log(records, self.controller.chain.attack_state,
                                    self.session_id or "")
        if skill is None:
            print("  No completed chain to synthesize (no flag/credential captured "
                  "this engagement yet).\n")
            return
        print(f"\n  {persist_skill(self.gen_manager, skill)}")
        print(f"  Methodology:\n    " + skill.methodology.replace("\n", "\n    "))
        print()

    async def _run_shell_direct(self, cmd: str) -> None:
        if self.controller is None:
            return
        print()
        result = await self.controller.executor._run_shell(cmd)
        if result.output:
            print(result.output.rstrip())
        if result.error:
            print(f"✗ {result.error}")
        print()

    async def _handle_command(self, cmd: str) -> bool:
        parts = cmd.split()
        command = parts[0].lower()

        if command in ("/quit", "/exit", "/q"):
            print("Bye.")
            return False

        elif command == "/help":
            print(HELP_TEXT)

        elif command == "/chain":
            if self.controller:
                print(f"\n  {self.controller.chain.summary()}")
                injection = self.controller.chain.get_context_injection()
                if injection:
                    print(f"\n{injection}")
                print()

        elif command == "/log":
            if not self.engagement_log:
                print("  Engagement log is off (--no-engagement-log).")
            elif len(parts) > 1 and parts[1].lower() == "export":
                out = self.engagement_log.export_markdown()
                print(f"  Exported Markdown report → {out}")
            else:
                print(f"\n  {self.engagement_log.summary()}")
                counts = self.engagement_log.counts()
                for kind, n in sorted(counts.items()):
                    print(f"    {kind:16s} {n}")
                print("  /log export  → write a Markdown timeline\n")

        elif command == "/report":
            await self._generate_report(parts[1].lower() if len(parts) > 1 else "both")

        elif command == "/synthesize":
            await self._synthesize_skill()

        elif command == "/operators":
            from core.operators import roster_summary
            print("\n  Specialist operators (delegate task=… operator=<name>):\n")
            print(roster_summary())
            print()

        elif command == "/user":
            if len(parts) > 2 and parts[1].lower() == "forget":
                fact = cmd.split(maxsplit=2)[2].strip()
                ok = self.user_profile.remove(fact)
                print(f"\n  {'Removed' if ok else 'Not found'}: {fact}\n")
            elif self.user_profile.facts():
                print(f"\n  User profile — {self.user_profile.path}:\n")
                print("  " + self.user_profile.render_markdown().replace("\n", "\n  "))
            else:
                print("\n  User profile is empty. The agent records durable facts via "
                      "user_remember\n  (preferences, habits, recurring targets).\n")

        elif command == "/soul":
            if len(parts) > 1 and parts[1].lower() == "init":
                path, written = init_soul()
                print(f"\n  {'Wrote' if written else 'Already exists'}: {path}")
                print("  Edit it to change Mapache's voice; changes apply next message.\n")
            else:
                src = soul_file(self.working_dir)
                persona = load_soul(self.working_dir)
                origin = str(src) if src else "built-in default (/soul init to create one)"
                print(f"\n  Active persona — {origin}:\n")
                print("  " + persona.replace("\n", "\n  "))
                print()

        elif command == "/voice":
            if self.voice is None:
                print("\n  Voice not initialized.\n")
            elif len(parts) > 1 and parts[1].lower() in ("on", "off"):
                self.voice.enabled = parts[1].lower() == "on"
                print(f"\n  {self.voice.describe()}\n")
            else:
                print(f"\n  {self.voice.describe()}")
                print("  Configure config.voice (tts: null|pyttsx3, stt: null|whisper) "
                      "or --voice; /voice on|off toggles.\n")

        elif command == "/say":
            text = cmd.split(maxsplit=1)[1] if len(parts) > 1 else ""
            if self.voice is not None and text:
                spoken = self.voice.tts.speak(text)
                print(f"\n  🔊 {spoken if spoken else text}\n")
            else:
                print("\n  Usage: /say <text>\n")

        elif command == "/hub":
            if self.hub_client is None:
                print("\n  No skill hub configured. Set hub.registry (a dir with "
                      "index.json)\n  in config to browse/install community skills.\n")
            else:
                arg = parts[1] if len(parts) > 1 else "list"
                if arg == "install" and len(parts) > 2:
                    print(f"\n  {self.hub_client.install(parts[2])}\n")
                else:
                    skills = (self.hub_client.search(" ".join(parts[2:]))
                              if arg == "search" else self.hub_client.list_skills())
                    print(f"\n  Hub skills ({len(skills)}):")
                    for m in skills:
                        sig = " ✓signed" if m.signature else ""
                        print(f"    {m.name} v{m.version} [{m.skill_type}]{sig} — {m.description}")
                    print()

        elif command == "/backend":
            if self.exec_backend is None:
                print("\n  Execution backend: local shell\n")
            else:
                note = " (shell commands run off this host)" \
                    if self.exec_backend.name != "local" else ""
                print(f"\n  Execution backend: {self.exec_backend.describe()}{note}")
                print("  Configure in config.execution (backend: local|ssh|docker) "
                      "or --exec-backend.\n")

        elif command == "/hosts":
            hosts = self.controller.host_states() if self.controller else {}
            if not hosts:
                print("\n  No per-host sub-states yet. Delegate with a `target` to "
                      "run\n  hosts in isolated parallel states.\n")
            else:
                print(f"\n  Per-host attack states ({len(hosts)}):\n")
                for st in hosts.values():
                    block = st.to_prompt_block()
                    print("  " + (block or f"{st.target}: (no findings)").replace("\n", "\n  "))
                    print()

        elif command == "/opsec":
            from core.operators import all_operators
            print()
            print(self.opsec.explain(all_operators()) if self.opsec
                  else "  OPSEC routing unavailable (runtime not initialized).")
            print()

        elif command == "/cve":
            from core.cve_grounding import ground_services, lookup, attack_plan
            print()
            if len(parts) > 1 and parts[1].upper().startswith(("CVE-", "MS")):
                entry = lookup(parts[1])
                print(f"  {entry.id} [{entry.severity}/CVSS {entry.cvss}]: {entry.title}\n"
                      f"  Exploit: {entry.exploit or 'none catalogued'}\n"
                      f"  Remediation: {entry.remediation}" if entry
                      else f"  {parts[1]} is not in the offline catalog.")
            elif self.controller is not None:
                st = self.controller.chain.attack_state
                print("  " + attack_plan(
                    ground_services(st.services, st.versions)).replace("\n", "\n  "))
            else:
                print("  No attack state yet — run a scan first.")
            print()

        elif command == "/scope":
            if self.scope and self.scope.active:
                print(f"\n{self.scope.summary()}\n")
            else:
                print("\n  RoE scope: off — no scope.json loaded. Create one in the "
                      "working dir to\n  restrict targets/actions. Example:")
                print('    {"name": "engagement", "targets": ["10.10.10.0/24"],')
                print('     "forbidden_tools": ["msf_run"]}\n')

        elif command == "/models":
            if self.routed:
                print(f"\n{self.routed.routing.registry.summary()}\n")
                print(self.routed.explain())
                calls = self.routed.stats()
                if calls:
                    print("\n  Calls by model:")
                    for model_id, n in sorted(calls.items(), key=lambda x: -x[1]):
                        print(f"    {model_id:30s} {n}")
                print()
            else:
                print(f"\n  Active model : {self.model}\n")

        elif command == "/pipeline":
            if len(parts) > 1 and self.routed:
                strategy_map = {
                    "single":   RoutingStrategy.SINGLE,
                    "pipeline": RoutingStrategy.PIPELINE,
                    "auto":     RoutingStrategy.AUTO,
                    "hybrid":   RoutingStrategy.HYBRID,
                }
                new_strat = strategy_map.get(parts[1].lower())
                if new_strat:
                    self.routed.set_strategy(new_strat)
                    self.strategy = new_strat
                    print(f"  Strategy: {new_strat.value}\n")
                    print(self.routed.explain())
                else:
                    print("  Options: single | pipeline | auto | hybrid\n")
            else:
                print(f"  Current: {self.strategy.value}\n")

        elif command == "/tools":
            if self.registry:
                if len(parts) > 1:
                    cat = parts[1].lower()
                    tools = [t for t in self.registry.list_all() if cat in t.tags]
                    print(f"\n  Tools tagged '{cat}':")
                    for t in tools:
                        print(f"    {t.name:30s} {t.description[:60]}")
                    print()
                else:
                    print(f"\n{self.registry.summary()}\n")

        elif command == "/curate":
            await self._curate()

        elif command == "/restore":
            if not self.gen_manager:
                print("  No generated-tool library.")
            elif len(parts) > 1:
                print(f"  {self.gen_manager.restore(parts[1])}")
            else:
                archived = self.gen_manager.archived_names()
                print(f"  Archived tools: {', '.join(archived) or 'none'}")
                print("  Usage: /restore <name>")

        elif command == "/purge":
            if not self.gen_manager:
                print("  No generated-tool library.")
            elif len(parts) > 1:
                print(f"  {self.gen_manager.purge(parts[1])}")
            else:
                print("  Permanently delete an archived tool. Usage: /purge <name>")
                print(f"  Archived: {', '.join(self.gen_manager.archived_names()) or 'none'}")

        elif command == "/memory":
            sub = parts[1].lower() if len(parts) > 1 else ""
            if not sub:
                stats = self.memory.stats()
                print(f"\n  Notes:   {stats['notes']}")
                print(f"  Facts:   {stats['knowledge_entries']}")
                print(f"  Vectors: {stats['vector_entries']}")
                if self.memory.session:
                    print(f"  Session: {self.memory.session.turn_count} turns")
                print()
            elif sub == "notes":
                notes = self.memory.notes.list_all()
                print(f"\n  {len(notes)} note(s):")
                for n in notes:
                    tags = f" [{', '.join(n.tags)}]" if n.tags else ""
                    print(f"    [{n.id}] {n.title}{tags}")
                print()
            elif sub == "search" and len(parts) > 2:
                query = " ".join(parts[2:])
                results = await self.memory.vectors.search(query, limit=5)
                notes = self.memory.notes.search(query, limit=5)
                print(f"\n  Search: '{query}'")
                for r in results:
                    print(f"    [{int(r.score*100)}%] {r.text[:100]}")
                for n in notes:
                    print(f"    [note] {n.title}")
                if not results and not notes:
                    print("  Nothing found.")
                print()
            elif sub == "targets":
                targets = self.memory.knowledge.list_targets()
                print(f"\n  {len(targets)} target(s):")
                for t in targets:
                    data = self.memory.knowledge.get_target(t) or {}
                    summary = ", ".join(f"{k}={v}" for k, v in list(data.items())[:3])
                    print(f"    {t} — {summary}")
                print()

        elif command == "/history":
            if self.controller:
                msgs = self.controller.context._history
                print()
                for m in msgs[-10:]:
                    preview = m.content[:120].replace("\n", " ")
                    print(f"  [{m.role.upper():10s}] {preview}")
                print()

        elif command == "/clear":
            if self.controller:
                self.controller.context.clear_history()
                self.controller.chain.reset()
                print("  History and attack state cleared.\n")

        elif command == "/context":
            ctx = build_project_context(self.working_dir)
            print(f"\n{ctx}\n" if ctx else "  No project context detected.\n")

        elif command == "/cwd":
            if len(parts) > 1:
                new_dir = " ".join(parts[1:])
                if os.path.isdir(new_dir):
                    self.working_dir = os.path.abspath(new_dir)
                    if self.controller:
                        self.controller.set_working_dir(self.working_dir)
                    print(f"  Working directory: {self.working_dir}\n")
                else:
                    print(f"  Not found: {new_dir}\n")

        elif command == "/confirm":
            self.confirm = len(parts) > 1 and parts[1] == "on"
            if self.controller:
                self.controller.confirm_dangerous = self.confirm
            print(f"  Confirm: {'on' if self.confirm else 'off'}\n")

        elif command == "/debug":
            on = len(parts) > 1 and parts[1] == "on"
            setup_logging(level="DEBUG" if on else "INFO")
            self.args.debug = on
            print(f"  Debug: {'on' if on else 'off'}\n")

        else:
            print(f"  Unknown: {command}. /help for commands.\n")

        return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mapache — Offensive security AI agent",
        epilog="Subcommands: `mapache setup` (interactive config), "
               "`mapache config show|path` (inspect config), "
               "`mapache update [--check]` (update manager), "
               "`mapache version` (print version). "
               "With no subcommand, launches the agent REPL.")
    # Config-backed flags default to None so MapacheCLI._cli_overrides can tell
    # "explicitly passed" from "unset". When unset they fall through to the
    # project/global/env/default layers (env vars like MAPACHE_MODEL / OLLAMA_URL
    # are handled by the config env layer, not baked in here as argparse
    # defaults — that keeps the precedence CLI > project > global > env right).
    parser.add_argument("--model", "-m", default=None,
                        help="Primary model id (default: from config / "
                             "MAPACHE_MODEL env / built-in default)")
    parser.add_argument("--ollama-url", default=None)
    parser.add_argument("--dir", "-d", default=os.getcwd())
    parser.add_argument("--strategy", default=None,
                        choices=["single", "pipeline", "auto", "hybrid"],
                        help="single: always use --model. "
                             "auto/pipeline/hybrid: route per role across "
                             "installed models (may pick a model other than "
                             "--model). Default: from config (single).")
    parser.add_argument("--max-vram", default=None)
    parser.add_argument("--allow-cloud", action="store_true")
    parser.add_argument("--verify", action="store_true",
                        help="Enable the opt-in verifier: after a final answer, a "
                             "VERIFIER-role model judges it and the loop retries once "
                             "with a suggestion if it fell short (adds one model call)")
    parser.add_argument("--no-verifier", action="store_true",
                        help="(deprecated no-op; the verifier is now off unless --verify)")
    parser.add_argument("--no-tools", action="store_true")
    parser.add_argument("--all-tools", action="store_true",
                        help="Disable phase-based tool subsetting and expose all "
                             "tools every turn (may overflow local-model payloads)")
    parser.add_argument("--no-context", action="store_true")
    parser.add_argument("--plain", action="store_true",
                        help="Disable the rich TUI (panels/colour) and use plain "
                             "line output. Auto-selected for pipes/dumb terminals "
                             "or when the `rich` package isn't installed.")
    parser.add_argument("--exec-backend", default=None,
                        choices=["local", "ssh", "docker"],
                        help="Where `shell` commands run (feature H). ssh/docker "
                             "need host/container details in config.execution "
                             "(mapache.json / ~/.mapache/config.json). Default: local.")
    parser.add_argument("--voice", action="store_true",
                        help="Speak agent responses (Phase 9). Needs a TTS backend "
                             "in config.voice (e.g. tts=pyttsx3); no-op otherwise.")
    parser.add_argument("--mcp-config", default="mcp.json",
                        help="Path to an mcp.json (Claude-Desktop-style) listing "
                             "MCP servers to connect to. Ignored if absent.")
    parser.add_argument("--scope", default="scope.json",
                        help="Path to a scope.json defining Rules-of-Engagement "
                             "(in-scope targets, forbidden tools/patterns). "
                             "Enforced in the dispatch path. Ignored if absent.")
    parser.add_argument("--no-engagement-log", action="store_true",
                        help="Disable the append-only engagement audit log "
                             "(written to engagements/ by default).")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--log-dir", default=os.environ.get("MAPACHE_LOG_DIR"))
    return parser.parse_args()


async def main() -> None:
    # Subcommand layer (C1). `setup` and `config` are dispatched before the
    # REPL's flag parser so the bare `python -m cli [--flags]` invocation keeps
    # launching the agent exactly as before.
    argv = sys.argv[1:]
    if argv and argv[0] in ("--version", "-V", "version"):
        from core.updater import local_version
        print(f"mapache {local_version()}")
        sys.exit(0)
    if argv and argv[0] == "update":
        from core.updater import run_update_cmd
        setup_logging(level="WARNING")
        sys.exit(run_update_cmd(argv[1:]))
    if argv and argv[0] == "setup":
        from cli.setup_wizard import run_setup
        setup_logging(level="WARNING")  # keep the wizard's prompts uncluttered
        sys.exit(await run_setup(argv[1:]))
    if argv and argv[0] == "config":
        from cli.setup_wizard import run_config_cmd
        setup_logging(level="WARNING")
        sys.exit(await run_config_cmd(argv[1:]))

    args = parse_args()
    setup_logging(level="DEBUG" if args.debug else "INFO", log_dir=args.log_dir)
    cli = MapacheCLI(args)
    await cli.run()


if __name__ == "__main__":
    asyncio.run(main())
