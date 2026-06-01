#!/usr/bin/env python3
"""
mapache_cli.py — Mapache CLI (Phase 7 — Optimized for full-scale attacks)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent_controller import AgentController, AgentMode
from core.logger import get_logger, setup_logging
from core.project_context import build_project_context, get_mapache_instructions
from memory.memory_manager import MemoryManager
from models.model_manager import ModelManager
from models.routing_engine import RoutingStrategy
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
  /models                Show model routing
  /pipeline <strategy>   Set strategy: single|pipeline|auto|hybrid
  /memory                Show memory stats
  /memory notes          List notes
  /memory search <q>     Search memory
  /memory targets        List stored targets
  /chain                 Show current attack state
  /history               Show conversation history
  /clear                 Clear history and reset attack state
  /context               Show project context
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
- Quote tool output verbatim. Never paraphrase, summarize as fact, or fabricate results.
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
        self.memory = MemoryManager()
        self.model_manager: ModelManager | None = None
        self.confirm = args.confirm
        self.working_dir = os.path.abspath(args.dir)

        strategy_map = {
            "single":   RoutingStrategy.SINGLE,
            "pipeline": RoutingStrategy.PIPELINE,
            "auto":     RoutingStrategy.AUTO,
            "hybrid":   RoutingStrategy.HYBRID,
        }
        self.strategy = strategy_map.get(args.strategy.lower(), RoutingStrategy.AUTO)

    async def setup(self) -> bool:
        primary = OllamaProvider(
            model=self.args.model,
            base_url=self.args.ollama_url,
        )

        if not await primary.is_available():
            print(f"\n  ✗  Cannot reach Ollama at {self.args.ollama_url}")
            print(f"     Run: ollama serve\n")
            return False

        available = await primary.list_models()
        model_base = self.args.model.split(":")[0]
        if available and not any(model_base in m for m in available):
            print(f"\n  ⚠  Model '{self.args.model}' not found.")
            pull = input(f"     Pull it now? [y/N] ").strip().lower()
            if pull == "y":
                await primary.pull_model(self.args.model)
            else:
                return False

        mode = AgentMode.CHAT if self.args.no_tools else AgentMode.AGENT

        async def confirm_cb(tool_name: str, args: dict) -> bool:
            if not self.confirm:
                return True
            ans = input(f"\n  ⚠ Confirm {tool_name}({str(args)[:100]})? [Y/n] ").strip().lower()
            return ans != "n"

        self.controller = AgentController(
            model_provider=primary,
            mode=mode,
            use_function_calling=primary.supports_tools,
            system_prompt=SYSTEM_PROMPT,
            working_dir=self.working_dir,
            confirm_dangerous=self.confirm,
            confirm_callback=confirm_cb,
            enable_tool_subsetting=not self.args.all_tools,
        )

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

            # Core
            self.registry.register(ShellTool())

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

            dispatcher = ToolDispatcher(self.registry)
            self.controller.tool_dispatcher = dispatcher
            self.controller.executor.set_tool_dispatcher(dispatcher)

            for schema in self.registry.get_context_schemas():
                self.controller.register_tool(schema)

            # Phase 7 — multi-model manager
            self.model_manager = ModelManager(
                strategy=self.strategy,
                local_only=not self.args.allow_cloud,
                max_vram_gb=float(self.args.max_vram),
                enable_verifier=not self.args.no_verifier,
                ollama_url=self.args.ollama_url,
            )
            await self.model_manager.setup(
                available_models=available or [self.args.model],
                tool_dispatcher=dispatcher,
            )
            self.model_manager.set_available_tools(self.registry.list_names())

        await self.controller.start(inject_project_context=not self.args.no_context)
        return True

    async def run(self) -> None:
        if not await self.setup():
            sys.exit(1)

        session = self.memory.new_session()
        self.session_id = session.session_id
        stats = self.memory.stats()

        print(BANNER)
        print(f"  Model    : {self.args.model}")
        print(f"  Strategy : {self.strategy.value}")
        print(f"  Dir      : {self.working_dir}")
        print(f"  Confirm  : {'on' if self.confirm else 'off'}")
        print(f"  Verifier : {'on' if not self.args.no_verifier else 'off'}")
        print(f"  ToolSubset: {'off (all tools)' if self.args.all_tools else 'on (phase-based)'}")
        print(f"  Memory   : {stats['notes']} notes, {stats['knowledge_entries']} facts")

        if self.model_manager:
            print(f"\n{self.model_manager.explain_routing()}")

        if self.registry:
            print(f"\n  Tools    : {len(self.registry.list_names())} registered")

        if get_mapache_instructions(self.working_dir):
            print("  MAPACHE.md loaded")

        print(f"\n  Type /help for commands\n")

        try:
            while True:
                try:
                    raw = input("you > ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nBye.")
                    break

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
            await self.memory.end_session()

    async def _agent_turn(self, user_input: str) -> None:
        if self.controller is None:
            return
        print()
        turn_id = self.memory.session.start_turn(user_input) if self.memory.session else None
        try:
            response = await self.controller.run(user_input, session_id=self.session_id)
            self.session_id = response.session_id
            print(f"agent > {response.content}")
            if response.tool_calls_made:
                print(f"        (used: {', '.join(response.tool_calls_made)}, {response.iterations} steps)")
            if response.error and response.error != "max_iterations":
                print(f"        ✗ {response.error}")
            if turn_id and self.memory.session:
                self.memory.session.end_turn(turn_id, response.content)
        except Exception as exc:
            print(f"agent > ✗ {exc}")
            if self.args.debug:
                import traceback
                traceback.print_exc()
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

        elif command == "/models":
            if self.model_manager:
                print(f"\n{self.model_manager.registry.summary()}\n")
                print(self.model_manager.explain_routing())
                s = self.model_manager.stats()
                print(f"\n  Planner calls : {s['planner_calls']}")
                print(f"  Executor calls: {s['executor_calls']}")
                print(f"  Tool calls    : {s['executor_tool_calls']}")
                vs = s.get('verifier_stats', {})
                if vs:
                    print(f"  Verifier      : {vs.get('calls',0)} checks, "
                          f"{vs.get('retries_triggered',0)} retries, "
                          f"{vs.get('failures_caught',0)} failures caught")
                print()
            else:
                print("  Model manager not initialized.\n")

        elif command == "/pipeline":
            if len(parts) > 1 and self.model_manager:
                strategy_map = {
                    "single":   RoutingStrategy.SINGLE,
                    "pipeline": RoutingStrategy.PIPELINE,
                    "auto":     RoutingStrategy.AUTO,
                    "hybrid":   RoutingStrategy.HYBRID,
                }
                new_strat = strategy_map.get(parts[1].lower())
                if new_strat:
                    self.model_manager.routing.strategy = new_strat
                    self.strategy = new_strat
                    print(f"  Strategy: {new_strat.value}\n")
                    print(self.model_manager.explain_routing())
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
    parser = argparse.ArgumentParser(description="Mapache — Offensive security AI agent")
    parser.add_argument("--model", "-m",
                        default=os.environ.get("MAPACHE_MODEL", "deepseek-coder:33b"))
    parser.add_argument("--ollama-url",
                        default=os.environ.get("OLLAMA_URL", "http://localhost:11434"))
    parser.add_argument("--dir", "-d", default=os.getcwd())
    parser.add_argument("--strategy", default="auto",
                        choices=["single", "pipeline", "auto", "hybrid"])
    parser.add_argument("--max-vram", default="12")
    parser.add_argument("--allow-cloud", action="store_true")
    parser.add_argument("--no-verifier", action="store_true")
    parser.add_argument("--no-tools", action="store_true")
    parser.add_argument("--all-tools", action="store_true",
                        help="Disable phase-based tool subsetting and expose all "
                             "tools every turn (may overflow local-model payloads)")
    parser.add_argument("--no-context", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--log-dir", default=os.environ.get("MAPACHE_LOG_DIR"))
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    setup_logging(level="DEBUG" if args.debug else "INFO", log_dir=args.log_dir)
    cli = MapacheCLI(args)
    await cli.run()


if __name__ == "__main__":
    asyncio.run(main())
