#!/usr/bin/env python3
"""
mapache_cli.py - Mapache CLI (Phase 7 - Optimized for full-scale attacks)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent_controller import AgentController, AgentMode
from core.logger import get_logger, setup_logging
from integrations.mcp import MCPManager, load_mcp_config
from core.project_context import build_project_context, get_mapache_instructions
from memory.memory_manager import MemoryManager
from models.model_registry import (
    ModelRegistry, ModelRole, ModelProfile, ModelCapabilities, Provider,
)
from core.config import load_config, load_global_raw, save_global_config
from core.integration_catalog import detect_missing_integration
from core.engagement_scope import load_scope
from core.engagement_log import EngagementLog
from models.routing_engine import RoutingEngine, RoutingStrategy
from models.model_pool import ModelPool
from models.routed_model import RoutedModel
from core.opsec_routing import OpsecPolicy
from core.soul import load_soul, soul_file, init_soul
from memory.user_profile import UserProfile, UserRememberTool
from cli.render import make_renderer
from cli import theme
from cli import enhanced_input
from core.exec_backend import backend_from_config
from core.egress import EgressProfile
from tools.external_tools import build_external_tools
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
from security_tools.kali.heavy_tools import SqlmapTool, FuzzTool
from security_tools.kali.kali_tools_interface import (
    KaliToolListTool, KaliRunTool, SearchsploitTool,
)
from browser.scraping_tools import (WebFetchTool, HttpRequestTool, WebSearchTool,
                                     TorFetchTool, TorControlTool, OnionSearchTool,
                                     EgressCheckTool)
from tools.filesystem_tool import (
    FileReadTool, FileWriteTool, FileEditTool,
    FileListTool, FileSearchTool,
)
from tools.code_tools import CodeRunTool
from tools.tool_dispatcher import ToolDispatcher
from tools.tool_registry import ToolRegistry, ToolNameCollisionError
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

HELP_TEXT = """
TUI (mapache serve): mouse wheel / PageUp-PageDown / arrows scroll · drag to
  select & copy · /sidebar wide|narrow|<n> resizes the panel · type "/" for
  command suggestions · Ctrl+L clear · Ctrl+C quit

Commands:
  /help                  This help
  /tools                 List all tools
  /tools <tag>           Filter tools by tag
  /curate                Review/archive unused self-authored tools
  /restore <name>        Restore an archived self-authored tool
  /purge <name>          Permanently delete an archived tool
  /models                Show model routing
  /pipeline <strategy>   Set model strategy: single|pipeline|auto|hybrid
  /swarm [on|off]        Toggle multi-agent supervisor (autonomous operator routing)
  /memory                Show memory stats
  /memory notes          List notes
  /memory search <q>     Search memory
  /memory targets        List stored targets
  /chain                 Show current attack state
  /operators             List specialist sub-agents (delegation roster)
  /hosts                 Show per-host attack states (multi-host delegation)
  /backend               Show the execution backend (local / ssh / docker)
  /egress                 Show egress/anonymity (proxy/Tor to hide your IP)
  /integrations           List bring-your-own tools (Shodan/API + GitHub/CLI)
  /hub [search|install]  Browse/install community skills (feature I)
  /voice [on|off]        Voice I/O status / toggle (Phase 9); /say <text> speaks
  /opsec                 Show hybrid OPSEC routing (which ops are pinned local)
  /scope                 Show Rules-of-Engagement scope (in-scope targets)
  /todos                 Show the agent's live checklist (steps + progress)
  /log                   Show engagement-log summary
  /log export            Write a Markdown engagement-log timeline
  /report [md|html|both|sarif|bounty|all]  Structured report (findings/severity; SARIF + bounty drafts)
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
MATCH THE SCOPE OF THE REQUEST (read this first):
═══════════════════════════════════════════
- Do EXACTLY what the operator asked - no more. Match the breadth of your actions to the breadth
  of the request. A narrow request gets a narrow response.
- NAMED SINGLE ACTION → run that one tool, report the result, then STOP and wait. Do NOT auto-
  advance the workflow, do NOT delegate to other operators, do NOT run extra tools.
    · "run an nmap scan (for vulnerabilities)"  → nmap_scan once, report, STOP.
      ("for vulnerabilities" selects scan_type=vuln; it does NOT mean go exploit anything.)
    · "run nikto on X" / "gobuster the site" / "search for exploits" → that ONE tool, report, STOP.
- FULL-ENGAGEMENT REQUEST → only then run the multi-phase ATTACK WORKFLOW below and/or delegate
  to operators. Triggers are broad objectives, e.g. "pentest this box", "compromise <host>",
  "get root", "find the flag", "full assessment", "enumerate everything", "own it".
- When unsure whether a request is narrow or broad, do the narrow thing and ASK before expanding.
- "Objective" (in the discipline rules below) means the operator's ACTUAL request, not a whole
  kill chain you inferred. Finishing a named single action IS meeting the objective.

═══════════════════════════════════════════
SHOW YOUR PLAN AS A CHECKLIST:
═══════════════════════════════════════════
- For any goal that needs 3+ steps, call `update_plan` FIRST with the full ordered checklist
  (each step: task + status), so the operator can watch each step and its progress. Then call
  `update_plan` again as you go: mark the finished step completed and the next one in_progress.
  Keep EXACTLY ONE step in_progress. (A NAMED SINGLE ACTION needs no checklist - just do it.)

═══════════════════════════════════════════
IDENTIFY THE ENGAGEMENT - ROUTE BY DISCIPLINE (this is NOT a web/CTF-only bot):
═══════════════════════════════════════════
Mapache is a full-spectrum offensive platform. Real engagements are rarely "an IP with a flag".
BEFORE reaching for nmap, look at WHAT the target actually is and take the matching entry path;
delegate to the named specialist (see /operators) when the work belongs to that discipline. The
network kill chain below is ONE path (for hosts), not the default for everything.
- Network host / IP / "box"        -> NETWORK-HOST WORKFLOW below (recon -> exploit -> post_operator).
- Web app / URL / API              -> web_operator: read the REAL attack surface first, then test
                                      injection / broken-authz-IDOR / SSRF / upload / auth.
- Source tree / repo / "audit this code" -> analyst: SAST (semgrep/bandit/gitleaks), dependency-CVE
                                      sweep, exploit-chain review. No port scan needed.
- Cloud account / keys / bucket / k8s -> cloud_hunter: IAM privesc, public storage, IMDS credential
                                      theft (cloud_metadata), k8s RBAC; provider CLIs via shell.
- Smart contract / Solidity / EVM  -> contract_auditor: reentrancy, oracle/flash-loan, access control.
- Mobile app / APK / IPA           -> mobile_operator: static (jadx/apktool) + dynamic (frida),
                                      API IDOR, SSL-pinning / root-jailbreak bypass.
- Firmware / embedded / IoT device -> iot_operator / reverser: binwalk extraction, hardcoded creds.
- Standalone binary / executable   -> reverser: checksec/strings/ROP triage (binary_analyze).
- Wireless (Wi-Fi/BLE/Zigbee/RF)   -> wireless_operator (needs a radio via hardware/SSH dropbox).
- ICS / OT / SCADA                 -> ics_operator: READ-ONLY enum first; writes only vs an in-scope
                                      lab/canary, never a production controller.
- Phishing / social engineering    -> phisher: blue-team deconfliction is MANDATORY before any send.
- Supply chain / CI-CD / deps      -> supply_chain_operator: dependency confusion, typosquat, provenance.
- LLM / AI application             -> web_operator with llm_inject (OWASP LLM01).
- DFIR / purple-team validation    -> forensicator (read-only): timelines, IOCs, attack->detection map.
- Deep vuln research on one asset  -> Vulnresearch pipeline: scanner -> detector -> verifier ->
                                      patcher -> exploiter.
When the discipline is unclear from the request, ASK which target type it is - do NOT default to a
network scan.

═══════════════════════════════════════════
WHAT SUCCESS IS (real engagement vs CTF):
═══════════════════════════════════════════
- On a REAL target the deliverable is an EVIDENCE-BACKED FINDING plus its remediation - the moment
  you confirm a weakness, call report_finding (title, severity, asset, and the exact request/response
  or command output that proves it). That is success; there is no flag to chase.
- A "flag" is a CTF/lab artifact only. Capture it when the engagement is a CTF/HTB box, but never let
  flag-hunting crowd out the finding+remediation deliverable on a real assessment.

═══════════════════════════════════════════
TOOL-CALL DISCIPLINE (most important):
═══════════════════════════════════════════
- To act, emit ONE tool call. Do not narrate, do not explain, do not ask permission first.
- After a tool call, STOP and wait for the real result. Never write a tool's output yourself.
- Use ONLY the result the tool actually returns. If you have not called a tool, you do not know
  its output - call it. Never invent ports, hashes, files, paths, or flags.
- One tool per step. Read the result, then decide the next single step. Chain steps until the
  objective is met.
- Provide a plain-text answer ONLY when the task is complete or you are blocked and need the
  operator. Otherwise, keep calling tools.
- EXCEPTION - general knowledge: if the operator asks something you already know (a definition,
  what an acronym stands for, a fact), ANSWER IT DIRECTLY in plain text. Do NOT use tools for
  facts you already know. Tools are for acting on the target/system, not for looking up trivia.
  (e.g. "what does VM stand for?" → answer "Virtual Machine"; no tool call.)
- Never call the SAME tool with the SAME arguments twice - you already have that result. If a
  lookup is blocked, fails, or returns nothing useful, fall back to your own knowledge and
  answer; never report a tool's error/refusal text as your final answer.
- Required arguments are mandatory. nmap_scan ALWAYS needs target=<ip>; never call it without
  one. The active target and known facts are in the CURRENT ATTACK STATE block - use them.

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
NETWORK-HOST WORKFLOW (ONE path - for host/IP engagements; see ROUTE BY DISCIPLINE above):
═══════════════════════════════════════════
Use this ONLY when the target is a network host/IP AND the operator asked for a broad objective
(pentest / compromise / get root / full assessment / find the flag). For a non-host discipline
(code / cloud / contract / mobile / firmware / etc.) take that discipline's entry path instead.
For a named single action, do NOT enter this workflow; run the one tool and stop.
1. RECON      → nmap_scan standard, then nmap_scan version on the open ports
2. ENUMERATE  → per open port: web (80/443/8080)=gobuster+nikto; SMB (445/139)=crackmapexec;
                FTP (21)=anonymous login; SSH (22)=note for creds; Telnet (23)=connect
3. EXPLOIT    → msf_search / searchsploit on the exact service+version → msf_run or kali_run
4. POST       → find flags, escalate privileges, dump credentials
5. REPORT     → the DELIVERABLE. The moment you CONFIRM a weakness (not just a flag), call
                report_finding with title, severity, asset, and EVIDENCE (the actual
                request+response / command output that proves it) - impact + remediation
                auto-fill. A proven finding IS success on a real target; the flag is optional.
                Also memory_target_store the facts.
Do not skip ahead: do not attempt exploitation before a scan has returned open ports.

═══════════════════════════════════════════
EXECUTION RULES:
═══════════════════════════════════════════
- Reason over each tool's output and decide the next action from it - do not merely echo it
  back. Never fabricate results; quote specific artifacts (ports, versions, hashes, paths,
  flags) exactly as the tool returned them.
- The agent host is Windows: in shell use dir, type, ipconfig, whoami, tasklist. Once you have a
  shell/session ON a Linux target, switch to Linux commands.
- If nmap reports the host down or returns nothing, retry once with nmap_scan(extra_args="-Pn").
- If a service/version is unknown, look it up: web_search(query="<service> <version> exploit").
- Save findings to memory after each major step.
- CTF/HTB context ONLY: flags are HTB{...} or a 32-character lowercase hex string; report them
  exactly as found. On a real-world engagement there is no flag - the deliverable is the
  evidence-backed report_finding plus its remediation."""


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
        self.cast = None  # AsciicastRecorder when --cast is set
        self._ptk = None          # prompt_toolkit session (enhanced input), set in run()
        self._input_q = None      # fallback stdin queue, set in run()
        self._running_tool = None  # tool currently executing, for the live status line
        self._running_action = None  # plain-language narration of that tool (action_phrase)
        self.swarm = False  # /swarm: autonomous multi-agent supervisor routing (feature P2)
        self.tui = None           # full-screen TUI (RaccoonTUI) when --tui is active
        self._accent_stack = []   # per-agent transcript accent while sub-agents nest
        self.kg = None            # shared knowledge graph (findings store), built in setup()
        self.opplan = None        # operation plan (objectives + status), built in setup()
        self.memory = MemoryManager()
        self.confirm = args.confirm
        self.working_dir, self._workdir_note = self._resolve_working_dir(args.dir)

        # Presentation layer (feature B): rich UI on a TTY when `rich` is
        # installed and --plain wasn't passed; otherwise the plain line printer.
        self.render = make_renderer(getattr(args, "plain", False))
        self.exec_backend = None  # feature H - built in setup() from config
        self.egress = None        # operator anonymity - built in setup() from config
        self._integrations = []   # bring-your-own tools - built in setup()
        self.hub_client = None    # feature I - built in setup() if a registry is set
        self.voice = None         # Phase 9 - built in setup() from config

        # Config layer (C0/C1). Resolve the effective settings across the full
        # precedence chain - CLI flag > project > global > env > default - by
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
            "solo":     RoutingStrategy.SINGLE,   # friendly alias (wizard)
            "pipeline": RoutingStrategy.PIPELINE,
            "auto":     RoutingStrategy.AUTO,
            "hybrid":   RoutingStrategy.HYBRID,
            "swarm":    RoutingStrategy.AUTO,     # swarm = auto routing + supervisor
        }
        _strat = self.config.default_strategy.lower()
        self.strategy = strategy_map.get(_strat, RoutingStrategy.AUTO)
        # "swarm" is the multi-agent supervisor (a toggle, not a routing enum): the
        # lead still routes AUTO, but the Supervisor drives operator fan-out.
        self.swarm = (_strat == "swarm")

    @staticmethod
    def _is_writable_dir(path: str) -> bool:
        try:
            probe = os.path.join(path, ".mapache_write_probe")
            with open(probe, "w"):
                pass
            os.remove(probe)
            return True
        except OSError:
            return False

    def _resolve_working_dir(self, arg_dir) -> "tuple[str, str | None]":
        """Pick the working dir (holds plugins/generated, engagements, project config).

        An explicit --dir always wins. Otherwise use the current directory when it's
        writable; when it isn't - e.g. `mapache serve` launched from C:\\Windows\\
        System32 as a global command - fall back to a stable per-user workspace so
        the app doesn't crash trying to write where it can't. Returns (dir, note)."""
        if arg_dir:
            return os.path.abspath(arg_dir), None
        cwd = os.getcwd()
        if self._is_writable_dir(cwd):
            return cwd, None
        home = os.path.join(os.path.expanduser("~"), ".mapache", "workspace")
        try:
            os.makedirs(home, exist_ok=True)
        except OSError:
            pass
        return home, f"cwd not writable ({cwd}) - using {home}"

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

        # File-authored skills (feature #6): SKILL.md playbooks dropped into
        # <workspace>/skills/ or ~/.mapache/skills/ are parsed and registered into
        # the just-in-time injection set, alongside the built-in playbooks. No-op
        # when the dirs are absent.
        self._load_file_skills()

        # Cross-engagement learning: persistent record of what worked against which
        # target fingerprint, used to bias routing and inject prior-win hints so
        # Mapache gets smarter across engagements.
        from core.learning_store import LearningStore
        self.learning = LearningStore(
            os.path.join(os.path.expanduser("~"), ".mapache", "learning.json"))
        self._ran_operators: set[str] = set()

        # Provider-aware pool: builds Ollama or OpenAI-compatible per model id.
        pool = ModelPool(base_url=self.ollama_url, config=self.config)
        primary_prov = self.config.provider_for_model(self.model)
        primary_is_cloud = primary_prov is not None and primary_prov.is_cloud

        if primary_is_cloud:
            if not allow_cloud:
                print(f"\n  x  '{self.model}' is a cloud model "
                      f"({primary_prov.name}); re-run with --allow-cloud.\n")
                return False
            if not primary_prov.is_usable:
                print(f"\n  x  Cloud provider '{primary_prov.name}' has no API key.")
                print(f"     Set it in ~/.mapache/config.json or its env var.\n")
                return False
            primary = pool.get(self.model)  # OpenAICompatibleProvider
            available = self.config.cloud_models() or [self.model]
        else:
            primary = OllamaProvider(model=self.model, base_url=self.ollama_url)
            pool.register(self.model, primary)  # reuse the built client
            if not await primary.is_available():
                print(f"\n  x  Cannot reach Ollama at {self.ollama_url}")
                print(f"     Run: ollama serve\n")
                return False
            local_models = await primary.list_models()
            model_base = self.model.split(":")[0]
            if local_models and not any(model_base in m for m in local_models):
                print(f"\n  [!]  Model '{self.model}' not found.")
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
            print(f"\n  [!] Confirm {tool_name}({str(args)[:100]})? [Y/n] ", end="", flush=True)
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

        # Phase 7 - per-role model routing. RoutedModel consults the
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

        # Per-role model overrides from config (wizard "customize per role").
        for _role_name, _role_model in (self.config.model_roles or {}).items():
            try:
                routing.override_role(ModelRole(_role_name), _role_model)
            except Exception:
                pass  # unknown role name / model: ignore, fall back to default

        def _opsec_warn(model_id: str) -> None:
            print(f"\n  [!] OPSEC: routing to CLOUD model '{model_id}' - target/scan/"
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

        # Execution backend (feature H): where `shell` runs - local / ssh /
        # docker. From config.execution; --exec-backend overrides the kind.
        exec_spec = dict(getattr(self.config, "execution", None) or {"backend": "local"})
        if getattr(self.args, "exec_backend", None):
            exec_spec["backend"] = self.args.exec_backend
        self.exec_backend, exec_warn = backend_from_config(exec_spec)
        if exec_warn:
            print(f"  [!] {exec_warn}")

        # Egress / operator anonymity: how attack traffic exits (hide the operator
        # IP). From config.egress; --egress overrides (direct | tor | a proxy URL).
        egress_spec = dict(getattr(self.config, "egress", None) or {"mode": "direct"})
        if getattr(self.args, "egress", None):
            self.egress = EgressProfile.parse(self.args.egress)
        elif getattr(self.args, "tor", False):
            # -tor / --tor: opt in to Tor for this run without touching config.
            self.egress = EgressProfile.parse("tor")
        else:
            self.egress = EgressProfile.from_dict(egress_spec)

        # If exiting through Tor, make sure Tor is actually running: the egress path
        # (unlike tor_fetch/tor_control) does NOT auto-start it, so without this every
        # web tool would fail with a connection error ("Tor egress isn't functional").
        if getattr(self.egress, "mode", "") == "tor":
            try:
                import re as _re
                from browser.tor_controller import TorController
                _proxy = self.egress.httpx_proxy() or ""
                _m = _re.search(r":(\d+)", _proxy)
                _port = int(_m.group(1)) if _m else 9050
                _tc = TorController(socks_port=_port, control_port=_port + 1)
                _ok, _msg = await _tc.start()
                print(f"  [egress] Tor {'ready' if _ok else 'NOT ready'} on :{_port} - "
                      f"{_msg.splitlines()[0]}")
            except Exception as _exc:  # never block startup on this
                print(f"  [egress] could not auto-start Tor: {_exc}")

        # Voice I/O (Phase 9): optional TTS/STT. From config.voice; --voice forces
        # it on. Null providers by default, so this is a no-op until a backend is
        # installed + selected.
        voice_spec = dict(getattr(self.config, "voice", None) or {})
        if getattr(self.args, "voice", False):
            voice_spec["enabled"] = True
        self.voice, voice_warns = voice_from_config(voice_spec)
        for w in voice_warns:
            print(f"  [!] {w}")

        # Opt-in verifier (--verify): route the verification call to the
        # VERIFIER-role model so it can use a higher-quality model than the loop.
        async def verifier_caller(messages: list[dict]):
            return await self.routed.chat(
                messages=messages, role=ModelRole.VERIFIER, json_mode=True
            )

        # Shared, disk-persisted findings store (knowledge graph). Sub-agents read
        # prior findings + record their own through it across fresh contexts.
        from core.knowledge_graph import KnowledgeGraph
        self.kg = KnowledgeGraph(
            path=os.path.join(self.working_dir, "knowledge", "graph.json"))
        # Operation plan (OPPLAN): objectives + status transitions for the lead.
        from core.opplan import OPPLAN
        self.opplan = OPPLAN(path=os.path.join(self.working_dir, "opplan.json"))

        sys_prompt = SYSTEM_PROMPT
        if getattr(self.egress, "mode", "") in ("tor", "proxy"):
            _ep = self.egress.httpx_proxy() or ""
            _kind = "Tor" if self.egress.mode == "tor" else "a proxy"
            sys_prompt += (
                "\n\nOUTBOUND ANONYMITY: your web/network traffic ALREADY exits through "
                f"{_kind} ({_ep}), which is running and managed by Mapache. Do NOT test for "
                "or require a local `tor` binary - `where tor` / `tor --version` will not "
                "find the Tor Browser bundle, and `tor_control` is a Mapache TOOL, not a "
                "shell command. NEVER conclude you are blocked for lack of Tor: just use "
                "your web tools (web_fetch/http_request/browser) - they already route "
                "through it. Only call the tor_control tool if you truly need to check.")
        self.controller = AgentController(
            model_provider=self.routed,
            mode=mode,
            knowledge_graph=self.kg,
            opplan_provider=lambda: self.opplan.table() if self.opplan else "",
            use_function_calling=self.routed.supports_tools,
            system_prompt=sys_prompt,
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
            # User profile (feature F) + cross-engagement learning hint: durable user
            # facts plus what worked against similar targets before.
            profile_provider=self._profile_with_learning,
            # Candidate-flag verifier: expected flag format from --flag-format / config.
            flag_format=(getattr(self.args, "flag_format", None)
                         or getattr(self.config, "flag_format", "") or None),
        )
        self._wire_scope_notifier()
        # Engagement budget (optional): a token/time cap that stops the loop
        # gracefully when exceeded. Inert unless configured (config.budget or
        # --budget-tokens/--budget-seconds).
        self._wire_budget()
        # Human-in-the-loop checkpoints (optional): pause at milestones for
        # operator approve/deny/steer. Inert unless configured (config.hitl or
        # --hitl/--hitl-every).
        self._wire_hitl()
        # Defensive follow-up (optional): auto-generate a detection+remediation
        # "vaccine" for each confirmed vuln. Inert unless configured (config.vaccine
        # or --vaccine).
        self._wire_vaccine()
        # Periodic self-critique (optional): inject a reflect-and-refocus checkpoint
        # every N steps. Inert unless configured (config.reflection or --reflect).
        self._wire_reflection()
        self._wire_route_enum()
        # Live status: a spinner shows "running <tool>…" while a tool executes,
        # then a "ran <tool> · <N>s" line settles above it. Replaces the raw
        # agent_controller INFO logs (silenced on the console; still in the file).
        self.controller.bus.subscribe("task.start", self._on_task_start)
        self.controller.bus.subscribe("task.result", self._on_task_end)
        self.controller.bus.subscribe("task.error", self._on_task_end)
        # Colour the transcript by the active specialist: work routing to a recon /
        # initial-access / post-exploitation sub-agent switches the accent colour.
        self.controller.bus.subscribe("agent.delegate.start", self._on_delegate_start)
        self.controller.bus.subscribe("agent.delegate.end", self._on_delegate_end)
        # Self-consistency (#5): announce each fresh attempt.
        async def _on_attempt(event) -> None:
            d = event.data or {}
            print(f"\n  ↻ attempt {d.get('attempt')}/{d.get('of')} - fresh approach\n",
                  flush=True)
        self.controller.bus.subscribe("attempt.start", _on_attempt)
        # Live checklist: mirror the agent's plan into the TUI panel, and (plain mode)
        # print it whenever it changes so the user sees each step + progress.
        self.controller.bus.subscribe("agent.todos", self._on_todos)

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

            # Core - `shell` dispatches through the execution backend (feature H:
            # local / ssh / docker), built from config (--exec-backend overrides).
            self.registry.register(ShellTool(backend=self.exec_backend, egress=self.egress))

            # Filesystem
            self.registry.register(FileReadTool())
            self.registry.register(FileWriteTool())
            self.registry.register(FileEditTool())
            self.registry.register(FileListTool())
            self.registry.register(FileSearchTool())
            # code_run: write+compile+run in the shell's environment (backend-aware)
            # so exploits/PoCs are developed in a tight, structured loop.
            self.registry.register(CodeRunTool(backend=self.exec_backend))

            # Recon
            self.registry.register(NmapTool(egress=self.egress))

            # Browser - HTTP tools route through the egress proxy/Tor when active,
            # and share one persistent cookie jar so a login carries across calls.
            from browser.scraping_tools import WebSession, HttpRepeaterTool
            from browser.http_history import HTTPHistory
            web_session = WebSession()
            http_history = HTTPHistory()
            self.registry.register(WebFetchTool(egress=self.egress, session=web_session))
            self.registry.register(HttpRequestTool(egress=self.egress, session=web_session,
                                                   history=http_history))
            # Burp-lite: replay/tamper/diff any recorded request (IDOR/authz primitive).
            self.registry.register(HttpRepeaterTool(egress=self.egress, session=web_session,
                                                    history=http_history))
            # Evidence-first deliverable: the agent records confirmed findings (title,
            # severity, evidence, impact, remediation) into a shared report - success
            # is a finding with proof, not a flag.
            from core.findings import FindingsStore
            from tools.reporting_tools import ReportFindingTool, PlanTool
            self.findings_store = FindingsStore(
                path=os.path.join(self.working_dir, "findings.json"))
            self.registry.register(ReportFindingTool(store=self.findings_store))
            # Live checklist tool - lets function-calling models maintain the task list
            # the user watches (JSON-mode models use the "plan" response type instead).
            self.registry.register(PlanTool(
                chain_getter=lambda: getattr(self.controller, "chain", None),
                bus_getter=lambda: getattr(self.controller, "bus", None)))
            # Offensive knowledge + specialist web/cloud weapons (payloads corpus, JWT,
            # GraphQL, IMDS, secret-scan, tech-fingerprint).
            from security_tools.web_weapons import SearchPayloadsTool, JwtTool, GraphqlTool
            from security_tools.recon_weapons import SecretScanTool, TechDetectTool
            from security_tools.cloud_metadata import CloudMetadataTool
            from security_tools.llm_attacks import LlmInjectTool
            from security_tools.ad_tools import AdAttackTool
            from security_tools.reversing_tools import BinaryAnalyzeTool
            for _t in (SearchPayloadsTool(), JwtTool(), GraphqlTool(session=web_session),
                       SecretScanTool(), TechDetectTool(session=web_session),
                       CloudMetadataTool(), LlmInjectTool(session=web_session),
                       AdAttackTool(), BinaryAnalyzeTool()):
                self.registry.register(_t)
            # Real headless browser (capability #1): renders JavaScript/SPAs that the
            # raw HTTP tools can't. Safe to register even without Playwright - it
            # reports install steps at call time. Kept for teardown at shutdown.
            from browser.browser_tool import BrowserTool
            self._browser_tool = BrowserTool(egress=self.egress)
            self.registry.register(self._browser_tool)
            self.registry.register(WebSearchTool())
            self.registry.register(TorFetchTool())
            self.registry.register(TorControlTool())
            self.registry.register(OnionSearchTool())
            self.registry.register(EgressCheckTool(egress=self.egress))

            # Phase 6 - Advanced security
            self.registry.register(MetasploitSearchTool())
            self.registry.register(MetasploitRunTool())
            self.registry.register(MetasploitSessionsTool())
            self.registry.register(BurpScanTool())
            self.registry.register(BurpProxyTool())
            self.registry.register(JohnCrackTool())
            self.registry.register(JohnFormatTool())
            self.registry.register(KaliToolListTool())
            # kali_run shares the execution backend (feature H) so the toolchain
            # can run on a remote Kali box / container too.
            self.registry.register(KaliRunTool(backend=self.exec_backend, egress=self.egress))
            self.registry.register(SearchsploitTool())
            # Disciplined heavy exploit/discovery tools (capability #3): guided sqlmap
            # + ffuf that build correct invocations and summarise output, run through
            # the execution backend + egress like kali_run.
            self.registry.register(SqlmapTool(backend=self.exec_backend, egress=self.egress))
            self.registry.register(FuzzTool(backend=self.exec_backend, egress=self.egress))

            # Integrations (bring-your-own tools): http (e.g. Shodan) + command (a
            # CLI / GitHub repo) specs from config.integrations. They run through the
            # execution backend + egress like the built-ins. Warn-don't-block.
            ext_tools, ext_warn = build_external_tools(
                getattr(self.config, "integrations", None),
                backend=self.exec_backend, egress=self.egress)
            for _w in ext_warn:
                print(f"  [!] {_w}")
            registered_ext = []
            for _t in ext_tools:
                try:  # an integration must not shadow a built-in of the same name
                    self.registry.register(_t)
                    registered_ext.append(_t)
                except ToolNameCollisionError as _e:
                    print(f"  [!] integration '{_t.name}' skipped - {_e}")
            self._integrations = registered_ext
            if registered_ext:
                # Pin integrations so phase-based subsetting exposes them (they're
                # phase-agnostic, like MCP tools) - otherwise the model never sees them.
                self.controller.chain.always_tools |= {t.name for t in registered_ext}
                print(f"  Tools+   : {len(registered_ext)} integration(s): "
                      f"{', '.join(t.name for t in registered_ext)}")

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
            "grok": Provider.GROK, "nvidia_nim": Provider.NIM,
            "deepseek": Provider.DEEPSEEK, "moonshot": Provider.MOONSHOT,
            "zhipu": Provider.ZHIPU, "alibaba": Provider.ALIBABA,
            "huggingface": Provider.HUGGINGFACE,
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
            print("\n  [!] OPSEC: cloud model(s) active - data will leave this machine:")
            for role, mid in cloud:
                print(f"      {role:9s} → {mid}")

    def _wire_scope_notifier(self) -> None:
        """Print a visible line whenever the RoE gate refuses a call (feature J).

        The refusal is also fed to the model as a tool result, but the operator
        should see it live - it's the signal that the guardrail is doing its job.
        """
        if self.controller is None:
            return

        async def _on_refused(event) -> None:
            data = event.data or {}
            print(f"\n  [blocked] RoE: refused {data.get('tool_name')} - "
                  f"{data.get('reason')}\n", flush=True)

        self.controller.bus.subscribe("agent.scope_refused", _on_refused)

    def _wire_budget(self) -> None:
        """Register a BudgetMiddleware when an engagement budget is configured.

        Sources (CLI flags override config.budget): --budget-tokens / --budget-seconds
        beat `config.budget = {"max_tokens": …, "max_seconds": …}`. Inert when
        neither cap is set, so the loop is unchanged for the common case.
        """
        if self.controller is None:
            return
        spec = dict(getattr(self.config, "budget", None) or {})
        max_tokens = getattr(self.args, "budget_tokens", None)
        max_seconds = getattr(self.args, "budget_seconds", None)
        if max_tokens is None:
            max_tokens = spec.get("max_tokens")
        if max_seconds is None:
            max_seconds = spec.get("max_seconds")
        if not max_tokens and not max_seconds:
            return
        from core.agent_middlewares import BudgetMiddleware
        self.controller.add_middleware(
            BudgetMiddleware(max_tokens=max_tokens, max_seconds=max_seconds))
        caps = []
        if max_tokens:
            caps.append(f"{int(max_tokens)} tokens")
        if max_seconds:
            caps.append(f"{float(max_seconds):.0f}s")
        print(f"  💳 Engagement budget: {' / '.join(caps)}", flush=True)

    def _wire_hitl(self) -> None:
        """Register a HITLMiddleware when human-in-the-loop checkpoints are enabled.

        Sources (CLI flags override config.hitl): --hitl / --hitl-every N beat
        `config.hitl = {"enabled": …, "every": …, "on_phase_change": …}`. Inert when
        not enabled. At each checkpoint the loop pauses for operator approve/deny/steer.
        """
        if self.controller is None:
            return
        spec = dict(getattr(self.config, "hitl", None) or {})
        every = getattr(self.args, "hitl_every", None)
        if every is None:
            every = spec.get("every", 0)
        every = int(every or 0)
        on_phase = bool(spec.get("on_phase_change", True))
        enabled = (getattr(self.args, "hitl", False) or spec.get("enabled")
                   or every > 0)
        if not enabled:
            return
        from core.agent_middlewares import HITLMiddleware
        self.controller.add_middleware(
            HITLMiddleware(self._hitl_prompt, every=every, on_phase_change=on_phase))
        bits = []
        if every > 0:
            bits.append(f"every {every} steps")
        if on_phase:
            bits.append("on phase change")
        print(f"  🧑 HITL checkpoints: {' + '.join(bits) or 'on phase change'} "
              "([Enter]=approve · 'q'=stop · type guidance to steer)", flush=True)

    def _load_file_skills(self) -> None:
        """Load SKILL.md playbooks from the workspace and the global config dir into
        the just-in-time injection set (feature #6). Global first, then workspace, so
        a workspace skill can override a global one of the same name."""
        from core.skill_format import load_skill_dir
        dirs = [
            os.path.join(os.path.expanduser("~"), ".mapache", "skills"),
            os.path.join(self.working_dir, "skills"),
        ]
        loaded = []
        for d in dirs:
            loaded += load_skill_dir(d)
        if loaded:
            print(f"  📓 Loaded {len(loaded)} SKILL.md playbook(s): "
                  f"{', '.join(s.name for s in loaded)}", flush=True)

    async def _hitl_prompt(self, ctx, reason: str):
        """Console HITL callback: pause, show the checkpoint, read one operator line.

        Reuses the single stdin reader (via `_pending_confirm`) so it never opens a
        second competing reader. Enter approves, 'q'/'stop' halts, any other text
        steers (injected before the next model call).
        """
        from core.agent_middlewares import HITLDecision
        st = ctx.attack_state
        snap = ""
        if st is not None:
            bits = [f"phase={getattr(st, 'current_phase', '?')}"]
            if getattr(st, "open_ports", None):
                bits.append(f"ports={len(st.open_ports)}")
            if getattr(st, "vulnerabilities", None):
                bits.append(f"vulns={len(st.vulnerabilities)}")
            if getattr(st, "credentials", None):
                bits.append(f"creds={len(st.credentials)}")
            if getattr(st, "flags", None):
                bits.append(f"flags={len(st.flags)}")
            snap = "  ·  ".join(bits)
        print(f"\n  ⏸ HITL checkpoint - {reason}", flush=True)
        if snap:
            print(f"     state: {snap}", flush=True)
        print("     [Enter]=approve · 'q'=stop · or type guidance to steer ▸ ",
              end="", flush=True)
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending_confirm = fut
        try:
            ans = (await fut).strip()
        finally:
            self._pending_confirm = None
        if not ans:
            return HITLDecision.approve()
        if ans.lower() in ("q", "quit", "stop", "deny", "n", "halt"):
            return HITLDecision.deny("Operator halted the engagement at a checkpoint.")
        return HITLDecision.steer(ans)

    def _wire_vaccine(self) -> None:
        """Register a VaccineMiddleware when the defensive follow-up is enabled.

        Sources (CLI flag overrides config.vaccine): --vaccine beats
        `config.vaccine = {"enabled": bool, "per_step_cap": int}`. When enabled,
        each confirmed vulnerability yields a model-generated detection + remediation
        written to <workspace>/vaccines/ (and printed).
        """
        if self.controller is None:
            return
        spec = dict(getattr(self.config, "vaccine", None) or {})
        enabled = getattr(self.args, "vaccine", False) or spec.get("enabled")
        if not enabled:
            return
        from core.agent_middlewares import (VaccineMiddleware,
                                             make_model_vaccine_generator)
        cap = int(spec.get("per_step_cap", 3) or 3)
        self.controller.add_middleware(VaccineMiddleware(
            make_model_vaccine_generator(self.controller),
            sink=self._vaccine_sink, per_step_cap=cap))
        print("   Vaccine loop: on - a detection+remediation is generated for each "
              "confirmed vuln (→ vaccines/)", flush=True)

    def _profile_with_learning(self) -> str:
        """User profile plus a 'what worked against similar targets before' hint."""
        parts = [self.user_profile.summary()]
        try:
            st = self.controller.chain.attack_state if self.controller else None
            if st is not None and getattr(self, "learning", None) is not None:
                from core.learning_store import fingerprint_of
                hint = self.learning.hint(fingerprint_of(st.services, st.open_ports))
                if hint:
                    parts.append(hint)
        except Exception:
            pass
        return "\n\n".join(p for p in parts if p)

    def _record_learning(self) -> None:
        """At session end, record what worked against this target's fingerprint."""
        if getattr(self, "learning", None) is None or self.controller is None:
            return
        try:
            from core.learning_store import EngagementOutcome, fingerprint_of
            st = self.controller.chain.attack_state
            fp = fingerprint_of(st.services, st.open_ports)
            if not fp:
                return
            import time as _t
            self.learning.record(EngagementOutcome(
                # Evidence-based win, not flag-only: a vuln or captured creds also count,
                # so cross-engagement learning biases toward what worked on real
                # assessments, not just CTF flag captures.
                fingerprint=fp,
                solved=bool(st.flags or st.vulnerabilities or st.credentials),
                operators=sorted(self._ran_operators),
                vuln_classes=list(st.vulnerabilities)[:8],
                target=st.target or "", ts=str(int(_t.time()))))
        except Exception:
            pass

    async def _maybe_autoreport(self) -> None:
        """At session end, auto-generate the engagement report if anything worth
        reporting was found (agent findings OR blackboard vulns/creds) - so a real
        user always leaves with a deliverable, not just a chat log."""
        if self.controller is None:
            return
        store = getattr(self, "findings_store", None)
        st = self.controller.chain.attack_state
        has_content = (store is not None and len(store) > 0) or \
            st.vulnerabilities or st.credentials or st.flags
        if not has_content:
            return
        try:
            await self._generate_report("both")
        except Exception:
            pass

    def _wire_reflection(self) -> None:
        """Register a ReflectionMiddleware when periodic self-critique is enabled.

        Sources (CLI overrides config): --reflect / --reflect-every N beat
        config.reflection = {"enabled": bool, "every": int}. Inert when not enabled.
        """
        if self.controller is None:
            return
        spec = dict(getattr(self.config, "reflection", None) or {})
        every = getattr(self.args, "reflect_every", None)
        if every is None:
            every = spec.get("every", 6)
        every = int(every or 6)
        enabled = getattr(self.args, "reflect", False) or spec.get("enabled")
        if not enabled:
            return
        from core.agent_middlewares import ReflectionMiddleware
        self.controller.add_middleware(ReflectionMiddleware(every=every))
        print(f"  🧭 Reflection: self-critique checkpoint every {every} steps", flush=True)

    def _wire_route_enum(self) -> None:
        """Register RouteEnumMiddleware (--route-enum): on a web target with few known
        endpoints, probe common routes once and inject the real ones so the single
        agent stops guessing. The swarm path enumerates in the Supervisor instead."""
        if self.controller is None:
            return
        if not getattr(self.args, "route_enum", False):
            return
        from core.agent_middlewares import RouteEnumMiddleware
        self.controller.add_middleware(RouteEnumMiddleware())
        print("  🗺 Route enumeration: probe common paths on a sparse web target", flush=True)

    async def _vaccine_sink(self, ctx, vaccine) -> None:
        """Persist a generated vaccine to <workspace>/vaccines/ and announce it."""
        print(f"\n   Vaccine generated - {vaccine.vulnerability}", flush=True)
        try:
            vdir = os.path.join(self.working_dir, "vaccines")
            os.makedirs(vdir, exist_ok=True)
            slug = "".join(c if c.isalnum() else "-"
                           for c in vaccine.vulnerability.lower()).strip("-")[:60]
            path = os.path.join(vdir, f"{slug or 'vaccine'}.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(vaccine.as_text() + "\n")
        except Exception:
            pass

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
            try:  # an MCP tool must not shadow a built-in / another server's tool
                self.registry.register(tool)
            except ToolNameCollisionError as exc:
                print(f"  [!] MCP tool '{tool.name}' skipped - {exc}")
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
        # cleanly when no hub is configured. trusted_key stays None - the checksum
        # is the integrity gate; foreign signatures are noted, not trusted.
        registry_path = str((getattr(self.config, "hub", None) or {}).get("registry", "")).strip()
        if registry_path:
            from hub import make_registry, HubClient
            from core.config import global_config_path
            self.hub_client = HubClient(
                make_registry(registry_path),  # path → Local, http(s):// → Url
                generated_dir=self.gen_manager.generated_dir,
                mcp_path=self.args.mcp_config,
                # external_tool installs append to the global config's integrations.
                config_path=global_config_path())
        # Knowledge-graph tools: query/record shared findings (feature: fresh-context
        # state). Available to the lead and every specialist sub-agent.
        from tools.kg_tools import KGQueryTool, KGAddTool
        self.registry.register(KGQueryTool(lambda: self.kg))
        self.registry.register(KGAddTool(lambda: self.kg))

        # Operation-plan tools: the lead seeds objectives and transitions their
        # status (pending → in_progress → passed | blocked) as it dispatches work.
        from tools.opplan_tools import OpplanAddTool, OpplanUpdateTool, OpplanShowTool
        self.registry.register(OpplanAddTool(lambda: self.opplan))
        self.registry.register(OpplanUpdateTool(lambda: self.opplan))
        self.registry.register(OpplanShowTool(lambda: self.opplan))
        # Vulnresearch pipeline runner: seeds the 5 staged objectives into the OPPLAN.
        from tools.pipeline_tools import VulnResearchTool
        self.registry.register(VulnResearchTool(lambda: self.opplan))

        from hub.tools import (SkillSearchTool, SkillListTool, SkillInstallTool,
                               InstallGithubToolTool)
        from core.config import global_config_path
        self.registry.register(SkillSearchTool(lambda: self.hub_client))
        self.registry.register(SkillListTool(lambda: self.hub_client))
        self.registry.register(SkillInstallTool(lambda: self.hub_client))

        # Natural-language front door: install a GitHub repo as a tool on request,
        # registered live (same live-register path as generated tools) + persisted.
        # An explicit install WINS (replace=True) - a reinstall/refresh, and it
        # supersedes any same-named self-authored tool (retiring its package so it
        # can't reclaim the name on restart). This is the deliberate asymmetry to the
        # registry guard: implicit create_tool must not shadow; explicit install may.
        def _live_register(tool):
            if self.gen_manager is not None and tool.name in self.gen_manager.tools:
                self.gen_manager._unexpose(tool.name)
                shutil.rmtree(self.gen_manager.generated_dir / tool.name,
                              ignore_errors=True)
            self.registry.register(tool, replace=True)
            self.controller.register_tool(tool.to_context_schema())
            # Pin into always_tools so phase-based subsetting exposes it - without
            # this the freshly installed tool is filtered out of the model's tool
            # list (like MCP tools, integrations are phase-agnostic).
            self.controller.chain.always_tools.add(tool.name)
            if tool not in self._integrations:
                self._integrations.append(tool)
        self.registry.register(InstallGithubToolTool(
            lambda: global_config_path(),
            egress=self.egress, backend=self.exec_backend,
            on_installed=_live_register))

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
            # Evidence capture (--cast): record the engagement as a replayable asciicast.
            if getattr(self.args, "cast", False):
                from core.asciicast import AsciicastRecorder
                self.cast = AsciicastRecorder(
                    os.path.join(self.working_dir, "engagements", f"engagement-{stamp}.cast"),
                    title=f"Mapache - {self.session_id}")
                self.cast.attach(self.controller.bus)

        # Full-screen TUI (--tui): a bordered input box pinned to the bottom with a
        # scrolling output region above. Decided BEFORE the banner so the banner and
        # every command handler's print() land in the TUI region (via a stdout shim)
        # instead of corrupting the full-screen display. Falls back to the classic
        # CLI if it isn't a real TTY or prompt_toolkit can't init a full-screen app.
        tui_mode = (getattr(self.args, "tui", False)
                    and enhanced_input.ptk_available()
                    and sys.stdin.isatty() and sys.stdout.isatty())
        self._orig_stdout = sys.stdout
        if tui_mode:
            from cli.tui import build_tui, _ModelStdout
            self.tui = build_tui(
                on_run=self._tui_on_run,
                on_steer=lambda s: self.controller.steer(s) if self.controller else None,
            )
            if self.tui is not None:
                self.render = self.tui.renderer
                sys.stdout = _ModelStdout(self.tui.model)
                # Re-point the console log handler at the model too, so a WARNING/
                # ERROR (e.g. the OPSEC notice) lands in the output region instead of
                # corrupting the full-screen display. The file handler is untouched.
                # Also clamp it to WARNING: raw INFO lines (Turn start / Tool call /
                # Delegating subtask …) would otherwise interleave with the clean '●'
                # transcript. DEBUG/INFO still go to the file log for troubleshooting.
                import logging as _logging
                for _h in _logging.getLogger("mapache").handlers:
                    if (isinstance(_h, _logging.StreamHandler)
                            and not isinstance(_h, _logging.FileHandler)):
                        try:
                            _h.setStream(sys.stdout)
                            if _h.level < _logging.WARNING:
                                _h.setLevel(_logging.WARNING)
                        except Exception:
                            pass
            else:
                tui_mode = False  # init failed → classic CLI
                print("  [!] full-screen TUI couldn't start in this terminal - using "
                      "the classic CLI. (Try a standalone Windows Terminal/PowerShell "
                      "window if you want the --tui layout.)")

        from core.updater import local_version as _lv
        print(theme.render_banner(_lv(), color=theme.supports_color(), large=True))

        # Session facts as a compact horizontal box (Claude-Code style) instead of
        # a one-per-line vertical list. Labels dim, values highlighted; width is
        # ANSI-aware so the border stays aligned.
        c = theme.supports_color()

        def _kv(label: str, value: str, vstyle: str = "white") -> str:
            return theme.paint(label, "grey", color=c) + " " + theme.paint(value, vstyle, color=c)

        sep = theme.paint("   ·   ", "dgrey", color=c)
        tools_n = len(self.registry.list_names()) if self.registry else 0
        in_scope = bool(self.scope and self.scope.active)
        roe = (f"ENFORCED - in-scope {self.scope.targets_summary()}"
               if in_scope else "off (no scope.json)")
        box_rows = [
            sep.join([_kv("Model", self.model),
                      _kv("Tools", f"{tools_n} registered")]),
            sep.join([_kv("Confirm", "on" if self.confirm else "off"),
                      _kv("Verifier", "on (--verify)" if self.args.verify else "off"),
                      _kv("ToolSubset", "all tools" if self.args.all_tools else "phase-based"),
                      _kv("Memory", f"{stats['notes']} notes / {stats['knowledge_entries']} facts")]),
            _kv("RoE", roe, "amber" if in_scope else "grey"),
            _kv("Dir", str(self.working_dir), "grey"),
        ]
        if self.engagement_log:
            box_rows.append(_kv("Log", str(self.engagement_log.path), "grey"))
        print(theme.box(box_rows, color=c))
        if self._workdir_note:
            print(theme.paint(f"  [!] {self._workdir_note}", "amber", color=c))

        if self.routed:
            # In the TUI the strategy + per-role models live in the sidebar's
            # "Models" panel (a little box), not front-and-center. The classic CLI
            # has no sidebar, so it still prints the routing explanation inline.
            if getattr(self, "tui", None) is not None:
                self.tui.dashboard.set_routing(
                    self.routed.strategy_name(), self.routed.role_map())
            else:
                print(f"\n{self.routed.explain()}")

        if self.scope and self.scope.active:
            print(f"\n{self.scope.summary()}")

        if self.exec_backend is not None and self.exec_backend.name != "local":
            print(f"  Exec     : {self.exec_backend.describe()} (shell runs remote)")
        if self.egress is not None and self.egress.active:
            print(f"  Egress   : {self.egress.describe()} (attack traffic anonymised)")

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

        hint = "  Type /help for commands"
        if tui_mode or self._ptk_enabled():
            hint += "  ·  type / for live command suggestions"
        print(f"\n{hint}")
        # Mid-turn steering: always on in the TUI (submit while a turn runs → steer);
        # in the classic CLI only the plain fallback mode supports it.
        if tui_mode:
            print(f"  (type while the agent works to steer it · Ctrl-C to quit)")
        elif not self._ptk_enabled():
            print(f"  (you can type while the agent works to steer it mid-task)")
        print()

        # Input: prompt_toolkit (when available on a real TTY) gives a live slash-
        # command dropdown + ↑ history; otherwise the persistent background line
        # reader below is used unchanged - the byte-for-byte path pipes/tests rely on.
        # The TUI owns its own input widget, so neither path is set up in TUI mode.
        self._ptk = None
        self._input_q = None
        if not tui_mode and self._ptk_enabled():
            hist = None
            try:
                hist_dir = os.path.join(os.path.expanduser("~"), ".mapache")
                os.makedirs(hist_dir, exist_ok=True)
                hist = os.path.join(hist_dir, "history")
            except Exception:
                hist = None
            self._ptk = enhanced_input.make_session(hist)

        if not tui_mode and self._ptk is None:
            loop = asyncio.get_event_loop()
            self._input_q = asyncio.Queue()

            def _stdin_reader() -> None:
                for line in sys.stdin:
                    loop.call_soon_threadsafe(self._input_q.put_nowait, line.rstrip("\n"))
                loop.call_soon_threadsafe(self._input_q.put_nowait, None)  # EOF

            threading.Thread(target=_stdin_reader, daemon=True).start()

        try:
            if tui_mode and self.tui is not None:
                await self.tui.run()
                return
            while True:
                try:
                    raw = await self._read_command_line()
                except (asyncio.CancelledError, KeyboardInterrupt):
                    print("\nBye.")
                    break
                if raw is None:  # EOF (Ctrl+Z / Ctrl+D)
                    print("\nBye.")
                    break

                if not await self._process_line(raw):
                    break
        finally:
            # Restore stdout first so shutdown messages print to the real terminal
            # (the TUI's full-screen app has torn down by now).
            sys.stdout = getattr(self, "_orig_stdout", sys.stdout)
            if self.cast is not None:
                self.cast.close()
                print(f"  Session recording: {self.cast.path}")
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
            # Tear down the headless browser if one was started this session.
            bt = getattr(self, "_browser_tool", None)
            if bt is not None:
                try:
                    await bt.aclose()
                except Exception:
                    pass
            # Cross-engagement learning: record what worked this engagement.
            self._record_learning()
            # Evidence-first deliverable: auto-generate the report if anything was found.
            await self._maybe_autoreport()
            await self.memory.end_session()

    async def _process_line(self, raw: str) -> bool:
        """Handle one submitted line (command, shell, web-search shorthand, or a
        turn). Returns False if the session should exit. Shared by the classic REPL
        loop and the full-screen TUI so both behave identically."""
        raw = (raw or "").strip()
        if not raw:
            return True

        if raw.startswith("/"):
            # Unknown command → 'did you mean' rather than a silent no-op.
            if not self._is_known_command(raw):
                self._suggest_command(raw)
                return True
            # _handle_command returns truthy to keep the session, falsy to quit.
            return bool(await self._handle_command(raw))

        if raw.startswith("!"):
            await self._run_shell_direct(raw[1:].strip())
            return True

        if raw.startswith("?"):
            raw = f"search the web for: {raw[1:].strip()}"

        # Just-in-time integration setup asks for an API key on stdin, which can't
        # run under the full-screen TUI - skip the prompt there (still available in
        # the classic CLI). The turn itself runs the same in both.
        if self.tui is None:
            await self._maybe_setup_integration(raw)

        await self._agent_turn(raw)
        return True

    async def _tui_on_run(self, text: str) -> None:
        """A line submitted in the TUI: echo it as the operator bar, run it; if a
        command asked to quit, exit."""
        if text.strip() and self.tui is not None:
            self.render.user_message(text.strip())
        keep_going = await self._process_line(text)
        if not keep_going and self.tui is not None and self.tui._app is not None:
            self.tui._app.exit()

    async def _agent_turn(self, user_input: str) -> None:
        if self.controller is None:
            return
        self._turn_start_ts = time.monotonic()  # drives the TUI status elapsed clock
        self.render.start_turn()
        # Colour-coded phase banner + target/ports pulled from the attack state.
        self.render.phase_line(self.controller.chain.attack_state)
        turn_id = self.memory.session.start_turn(user_input) if self.memory.session else None
        # A "thinking" spinner + rotating raccoon-flavoured word runs until the
        # first token/output appears, in both input modes (it's a no-op off a TTY).
        ticker = asyncio.create_task(self._thinking_ticker())

        # Multi-agent swarm mode (feature P2): the supervisor autonomously routes
        # specialist operators instead of the single lead loop. Its delegate.start/
        # end events drive the existing handoff banners + colour routing, so the
        # operators are visible as they're deployed.
        if self.swarm:
            try:
                from core.orchestrator import Supervisor, make_model_planner
                sres = await Supervisor(
                    self.controller, session_id=self.session_id,
                    planner=make_model_planner(self.controller),
                    opplan=self.opplan,
                    fanout=getattr(self.args, "fanout", False),
                ).run(user_input, session_id=self.session_id)
                await self._stop_ticker(ticker, clear=True)
                st = self.controller.chain.attack_state
                n_find = (len(getattr(st, "vulnerabilities", []) or [])
                          + len(getattr(st, "credentials", []) or [])
                          + len(getattr(st, "flags", []) or []))
                if n_find == 0:
                    # De-CTF fallback: the swarm surfaced no offensive evidence, which
                    # for a general or coding objective means the operators had no job.
                    # Hand the objective to the lead agent once so it is actually done,
                    # instead of reporting a bare CTF-style failure.
                    self.render.info(
                        "  swarm found no offensive route - handing to the lead agent")
                    resp = await self.controller.run(
                        user_input, session_id=self.session_id)
                    self.session_id = resp.session_id
                    self.render.agent_result(resp.content, resp.tool_calls_made,
                                             resp.iterations, resp.error)
                    self.render.task_list(self.controller.chain.todos)
                else:
                    summary = (f"swarm complete - {sres.stop_reason}\n"
                               f"        operators: {', '.join(sres.operators_run) or '(none)'}"
                               f"  ·  rounds: {len(sres.rounds)}  ·  findings: {n_find}")
                    self.render.agent_result(summary, sres.operators_run,
                                             len(sres.rounds), None)
            except Exception as exc:
                await self._stop_ticker(ticker, clear=True)
                self.render.error(str(exc))
                if self.args.debug:
                    import traceback
                    traceback.print_exc()
            if turn_id and self.memory.session:
                self.memory.session.end_turn(turn_id, "[swarm run]")
            return

        first_output = {"seen": False}

        def _on_token(text: str) -> None:
            if not first_output["seen"]:
                first_output["seen"] = True
                # Classic CLI: the spinner shares the output line via '\r', so it must
                # stop the moment streaming starts. The TUI status is its own bottom
                # region, so KEEP the ticker running there - the thinking spinner + word
                # stay visible the whole time the agent works (streaming, tool calls,
                # thinking), Claude-Code style, and clear only at turn end.
                if self.tui is None:
                    if not ticker.done():
                        ticker.cancel()
                    self.render.thinking_clear()
            self.render.stream(text)

        try:
            # Stream tokens live when the model supports it (native tool-calling
            # models). The controller no-ops the callback in JSON mode, so the
            # renderer's streamed state stays False and it prints the content.
            attempts = int(getattr(self.args, "attempts", 1) or 1)
            if attempts > 1:
                # Self-consistency (#5): retry with a fresh approach until solved.
                # Token streaming is skipped in this mode (attempt banners show progress).
                from core.multi_attempt import run_with_attempts
                async def _run_attempts():
                    ar = await run_with_attempts(
                        self.controller, user_input,
                        session_id=self.session_id, max_attempts=attempts)
                    return ar.result
                turn_task = asyncio.create_task(_run_attempts())
            else:
                turn_task = asyncio.create_task(self.controller.run(
                    user_input, session_id=self.session_id, on_token=_on_token
                ))
            response = await self._drive_turn(turn_task)
            # TUI: the ticker ran the whole turn in its own status region, so clear it
            # now. Classic: if streaming began the line was already cleared in _on_token
            # (clearing again would wipe the streamed text).
            await self._stop_ticker(
                ticker, clear=(self.tui is not None) or not first_output["seen"])
            self.session_id = response.session_id
            self.render.agent_result(response.content, response.tool_calls_made,
                                     response.iterations, response.error)
            # Task list (feature B): show the current plan/progress as a panel.
            self.render.task_list(self.controller.chain.todos)
            # Voice (Phase 9): speak the response when voice is enabled (no-op
            # under the null backend). Never let TTS break the turn.
            if self.voice is not None and self.voice.enabled and response.content:
                self.voice.speak(response.content)
            if turn_id and self.memory.session:
                self.memory.session.end_turn(turn_id, response.content)
        except Exception as exc:
            await self._stop_ticker(ticker, clear=not first_output["seen"])
            self.render.error(str(exc))
            if self.args.debug:
                import traceback
                traceback.print_exc()

    async def _drive_turn(self, turn_task: asyncio.Task):
        """
        Await a turn. In the fallback (queue) input mode, typed lines are consumed
        as live steering - routed to a pending confirmation prompt if one is open,
        else handed to controller.steer(); lines that arrive after the turn ends
        stay buffered for the next REPL prompt.

        In prompt_toolkit mode mid-turn steering is disabled: its full-screen
        Application can't safely run concurrently with (or be torn down and
        immediately restarted alongside) the turn, so we just await the turn while
        the 'thinking' spinner shows. Steering remains available in the plain
        (no-prompt_toolkit) input mode.
        """
        if self._ptk is not None or self._input_q is None:
            return await turn_task

        while not turn_task.done():
            get_task = asyncio.create_task(self._input_q.get())
            done, _pending = await asyncio.wait(
                {turn_task, get_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if get_task in done:
                line = get_task.result()
                if line is None:  # EOF mid-turn - stop steering, let turn finish
                    continue
                line = line.strip()
                if self._pending_confirm is not None and not self._pending_confirm.done():
                    self._pending_confirm.set_result(line)
                elif line and self.controller is not None:
                    self.controller.steer(line)
                    self.render.steering(line)
            else:
                # Turn finished first; don't strand the pending read - its item
                # (if any) remains buffered for the REPL.
                get_task.cancel()
        return turn_task.result()

    async def _stop_ticker(self, ticker: asyncio.Task, clear: bool = True) -> None:
        """Cancel the 'thinking' ticker and AWAIT its teardown before printing
        anything else, so it can't race the output. `clear` erases the spinner
        line; pass False once streaming has begun (the line was already cleared in
        _on_token, and clearing again would wipe the streamed text)."""
        if ticker is not None and not ticker.done():
            ticker.cancel()
            try:
                await ticker
            except asyncio.CancelledError:
                pass
        if clear:
            self.render.thinking_clear()

    # -- input plumbing (prompt_toolkit or the queue fallback) ---------- #

    def _ptk_enabled(self) -> bool:
        """Use prompt_toolkit only with the package present on a real TTY (never
        under --plain, a pipe, or the smoke harness)."""
        return (enhanced_input.ptk_available()
                and not getattr(self.args, "plain", False)
                and sys.stdin.isatty() and sys.stdout.isatty())

    async def _read_command_line(self):
        """Read one line at the idle prompt. Returns the line, or None on EOF."""
        if self._ptk is not None:
            from prompt_toolkit.patch_stdout import patch_stdout
            try:
                with patch_stdout():
                    return await self._ptk.prompt_async("you > ")
            except EOFError:
                return None
            except KeyboardInterrupt:
                return ""  # Ctrl-C at the prompt clears the line, doesn't exit
        print("you > ", end="", flush=True)
        assert self._input_q is not None
        line = await self._input_q.get()
        return None if line is None else line

    # Tools whose call renders as a Kali-style command block in the TUI.
    _SHELL_TOOLS = {"shell", "kali_run"}

    async def _thinking_ticker(self) -> None:
        """The live status line, painted until cancelled. In the TUI it's the mock's
        '● <word>… (<elapsed> · ↑ <tokens>)'; in the classic CLI it's the spinner
        (or 'running <tool>…' while a tool runs). The single clear happens in
        _stop_ticker / _on_token (one owner)."""
        i = 0
        while True:
            if getattr(self, "tui", None) is not None:
                word = theme.thinking_word(i // theme.THINKING_WORD_EVERY)
                elapsed = time.monotonic() - getattr(self, "_turn_start_ts", time.monotonic())
                tokens = getattr(getattr(self, "controller", None), "session_tokens", 0)
                self.render.thinking(theme.status_line(word, elapsed, tokens, frame=i))
                # Refresh the right-hand HUD in step with the status clock.
                _bud = dict(getattr(self.config, "budget", None) or {})
                self.tui.dashboard.tick(
                    elapsed, tokens,
                    max_tokens=int(getattr(self.args, "budget_tokens", None)
                                   or _bud.get("max_tokens", 0) or 0),
                    max_seconds=float(getattr(self.args, "budget_seconds", None)
                                      or _bud.get("max_seconds", 0) or 0))
            else:
                action = getattr(self, "_running_action", None)
                if action:
                    frame = theme.activity_line(i, action)
                else:
                    tool = getattr(self, "_running_tool", None)
                    frame = theme.running_line(i, tool) if tool else theme.thinking_line(i)
                self.render.thinking(frame)
            i += 1
            await asyncio.sleep(0.2)

    @staticmethod
    def _agent_trace_prefix(data: dict) -> "str | None":
        """Indent + label for a delegated sub-agent's event, or None for the lead.

        Sub-agent events carry an `_agent` tag (operator/depth) stamped by the
        ScopedBus, so the lead can stream the sub-agent's full ReAct trace nested
        under it instead of seeing only the delegate start/end banners."""
        agent = (data or {}).get("_agent")
        if not agent:
            return None
        op = agent.get("operator") or "sub-agent"
        depth = max(1, int(agent.get("depth") or 1))
        return f"{'   ' * depth}⤷ [{op}] "

    async def _on_task_start(self, event) -> None:
        """A tool began. Classic: the spinner shows 'running <tool>…'. TUI: commit a
        '● Name (args)' line, or a Kali command block for shell tools."""
        data = event.data
        name = data.get("tool_name", "")
        args = data.get("args") or {}
        # Delegated sub-agent step: stream it as an attributed, indented line and
        # return - never clobber the lead's live spinner state with a child's tool.
        prefix = self._agent_trace_prefix(data)
        if prefix is not None:
            if name not in ("delegate", "delegate_parallel"):
                print(f"\n{prefix}{theme.action_phrase(name, args)}", flush=True)
                # Surface a sub-agent's tool/command on the HUD too (its steps otherwise
                # bypass the renderer, which is why swarm runs showed tools 0).
                if self.tui is not None:
                    self.tui.dashboard.add_tool(self._shell_cmd(name, args) or name)
            return
        self._running_tool = name
        self._running_action = theme.action_phrase(name, args)
        if self.tui is None:
            return
        if name in ("delegate", "delegate_parallel"):
            return  # the handoff banner (delegate.start) renders the routing instead
        # Claude-Code-style committed line: the tool NAME + its primary arg, e.g.
        # '● Bash(pip install pygame)', '● Write(qwentest.py)', '● Read(x.py)' - one
        # line, never a dumped file body. The live spinner still narrates in plain
        # language ('Scanning ports with nmap') via _running_action.
        display, primary = theme.tool_label(name, args)
        self.render.tool_call(display, primary)

    async def _on_task_end(self, event) -> None:
        """A tool finished. Classic: a 'ran <tool> · <N>s' line. TUI: shell tools get
        the dim exit-code line; other tools already showed their '● Name' line."""
        data = event.data
        name = data.get("tool_name", "")
        # Delegated sub-agent step: close its attributed line; don't touch the lead's
        # spinner state (that belongs to the lead's own in-flight tool, if any).
        prefix = self._agent_trace_prefix(data)
        if prefix is not None:
            secs = (data.get("duration_ms") or 0.0) / 1000.0
            mark = "x" if data.get("error") else "ok"
            print(f"{prefix}{mark} {name} · {secs:.1f}s", flush=True)
            return
        self._running_tool = None
        self._running_action = None
        if self.tui is None:
            self.render.step_line(theme.step_done_line(
                name, (data.get("duration_ms") or 0.0) / 1000.0,
                error=bool(data.get("error")), color=theme.supports_color()))
            return
        if name in self._SHELL_TOOLS:
            err = data.get("error")
            output = data.get("output") or ""
            self.render.shell_result(0 if not err else 1, empty=not output.strip())
        else:
            # Claude-Code-style result summary nested under the tool line ('⎿ …').
            self.render.info(theme.result_line(
                self._result_summary(data), error=bool(data.get("error"))))

    async def _on_todos(self, event) -> None:
        """The agent's checklist changed: update the TUI panel, or (plain mode) print
        it so the user can watch each step and its progress."""
        items = (event.data or {}).get("todos") or []
        if self.tui is not None:
            self.tui.dashboard.set_checklist(items)
            return
        # Plain mode: only print when it actually changed (avoid re-printing).
        sig = tuple((str(i.get("task")), str(i.get("status"))) for i in items)
        if sig == getattr(self, "_last_todos_sig", None) or not sig:
            return
        self._last_todos_sig = sig
        done = sum(1 for i in items if i.get("status") == "completed")
        mark = {"completed": "[x]", "in_progress": "[~]", "pending": "[ ]"}
        lines = [f"\n  Checklist ({done}/{len(items)})"]
        for i in items:
            lines.append(f"    {mark.get(i.get('status'), '[ ]')} {i.get('task')}")
        print("\n".join(lines), flush=True)

    @staticmethod
    def _result_summary(data: dict) -> str:
        """A one-line summary of a tool result for the '⎿ …' line."""
        if data.get("error"):
            return str(data.get("error")).replace("\n", " ")[:70] or "error"
        out = (data.get("output") or "").strip()
        if not out:
            return "(no output)"
        lines = out.splitlines()
        first = lines[0].strip()[:60]
        return f"{first} … (+{len(lines) - 1} lines)" if len(lines) > 1 else first

    @staticmethod
    def _summarize_args(args: dict) -> str:
        """A short one-line summary of tool args for the '● Name (…)' line."""
        if not args:
            return ""
        if len(args) == 1:
            return str(next(iter(args.values())))[:60]
        return ", ".join(f"{k}={str(v)[:20]}" for k, v in list(args.items())[:2])[:60]

    @staticmethod
    def _shell_cmd(name: str, args: dict) -> str | None:
        """The command line to render as a Kali block, or None for a plain tool line.

        `shell` carries the command in cmd/command; `kali_run` names a tool plus its
        args ({tool: 'gobuster', args: 'dir -u …'}) - reconstruct the invocation so
        it reads like a real prompt line instead of a generic '● kali_run (…)'."""
        if name == "kali_run":
            tool = str(args.get("tool") or "").strip()
            rest = str(args.get("args") or "").strip()
            return f"{tool} {rest}".strip() if tool else None
        if name == "shell":
            cmd = args.get("cmd") or args.get("command")
            return str(cmd) if cmd else None
        return None

    def _shell_context(self, args: dict) -> "tuple[str, str, str]":
        """(user, host, cwd) for the Kali command block - the real exec context."""
        import getpass
        import socket
        cwd = str(args.get("working_dir") or self.working_dir)
        be = self.exec_backend
        if be is not None and getattr(be, "name", "local") != "local":
            return "root", str(getattr(be, "name", "remote")), cwd
        try:
            user = getpass.getuser()
        except Exception:
            user = "user"
        try:
            host = socket.gethostname()
        except Exception:
            host = "local"
        return user, host, cwd

    # Killchain phase → transcript accent colour. Recon/initial-access/post read as
    # cyan/red/magenta; the lead agent stays green.
    _PHASE_ACCENT = {
        "recon": "cyan", "enumeration": "blue", "exploitation": "red",
        "post": "magenta", "analysis": "amber", "report": "green",
    }

    def _agent_accent(self, operator_name) -> str:
        if not operator_name or operator_name == "generalist":
            return "green"  # the lead agent
        try:
            from core.operators import get_operator
            op = get_operator(operator_name)
        except Exception:
            op = None
        return self._PHASE_ACCENT.get(op.phase, "teal") if op else "teal"

    @staticmethod
    def _operator_title(operator_name) -> str:
        try:
            from core.operators import get_operator
            op = get_operator(operator_name)
            if op:
                return op.title
        except Exception:
            pass
        return (operator_name or "sub-agent").replace("_", " ").title()

    async def _on_delegate_start(self, event) -> None:
        """Work is routing to a specialist - switch the transcript accent + banner."""
        name = event.data.get("operator")
        if name:
            getattr(self, "_ran_operators", set()).add(name)  # for cross-engagement learning
        if self.tui is None:
            return
        accent = self._agent_accent(name)
        task = (event.data.get("task") or "").strip()
        self._accent_stack.append(getattr(self.render, "accent", "green"))
        self.render.accent = accent
        self.render.handoff(self._operator_title(name), accent,
                            detail=(f"- {task[:60]}" if task else ""))

    async def _on_delegate_end(self, event) -> None:
        """Control returns to the caller - banner, then restore the prior accent."""
        if self.tui is None:
            return
        accent = getattr(self.render, "accent", "green")
        self.render.handoff(self._operator_title(event.data.get("operator")), accent,
                            back=True)
        self.render.accent = self._accent_stack.pop() if self._accent_stack else "green"

    def _is_known_command(self, raw: str) -> bool:
        base = raw.split()[0].lower()
        return base in {c for c, _ in enhanced_input.SLASH_COMMANDS} or base == "/q"

    def _suggest_command(self, raw: str) -> None:
        base = raw.split()[0]
        matches = enhanced_input.suggest_commands(base)
        if matches:
            print(f"  Unknown command {base!r}. Did you mean:")
            for cmd, desc in matches:
                print(f"    {cmd:12s} {desc}")
            print()
        else:
            print(f"  Unknown command {base!r}. /help for commands.\n")

    async def _read_line(self) -> str:
        """Read one line for an inline sub-prompt (curator y/N, etc.)."""
        if self._ptk is not None:
            from prompt_toolkit.patch_stdout import patch_stdout
            try:
                with patch_stdout():
                    return await self._ptk.prompt_async("")
            except (EOFError, KeyboardInterrupt):
                return ""
        if self._input_q is None:
            return ""
        line = await self._input_q.get()
        return "" if line is None else line

    async def _ask(self, prompt: str) -> str:
        """Print an inline prompt and read one line (mode-agnostic)."""
        print(prompt, end="", flush=True)
        return (await self._read_line()).strip()

    def _configured_integration_names(self) -> set:
        return {t.name for t in (self._integrations or [])}

    async def _maybe_setup_integration(self, user_input: str) -> None:
        """If the request names a known service (Shodan/VirusTotal/…) that isn't set
        up, offer a one-question setup: paste the key, we register the tool(s) live
        and persist the spec (key stays a ${ENV} ref). Wizard-style, mid-conversation."""
        if self.controller is None:
            return
        from core.integration_catalog import is_configured
        configured = self._configured_integration_names()
        recipe = detect_missing_integration(user_input, configured)
        if recipe is None:
            return
        have_spec = is_configured(recipe, configured)
        if have_spec:
            # Tools exist; only the API key is missing (a call would 401).
            print(f"\n  🔑 {recipe.display} is wired up but has no API key set "
                  f"(${recipe.env_var}).")
        else:
            print(f"\n  🔌 You mentioned {recipe.display}, but it isn't set up yet.")
            print(f"     {recipe.blurb}")
        print(f"     Get a key: {recipe.signup_url}")
        if (await self._ask("  Set it up now? [Y/n] ")).lower() in ("n", "no"):
            print("  Skipped - add it anytime under config.integrations.\n")
            return
        key = await self._ask(f"  Paste your {recipe.env_var} (blank to cancel): ")
        if not key:
            print("  Cancelled.\n")
            return

        # Make the key usable immediately (this session).
        os.environ[recipe.env_var] = key

        if not have_spec:
            # Persist the spec(s) (key stays a ${ENV} ref) and register the tools live.
            try:
                raw = load_global_raw()
                ints = raw.setdefault("integrations", [])
                names = {i.get("name") for i in ints if isinstance(i, dict)}
                for spec in recipe.specs:
                    if spec["name"] not in names:
                        ints.append(spec)
                save_global_config(raw)
            except Exception as exc:
                print(f"  [!] couldn't persist the spec ({exc}); added this session only.")
            tools, warns = build_external_tools(
                list(recipe.specs), backend=self.exec_backend, egress=self.egress)
            for w in warns:
                print(f"  [!] {w}")
            for t in tools:
                self.registry.register(t, replace=True)  # re-running setup refreshes
                self.controller.register_tool(t.to_context_schema())
                self.controller.chain.always_tools.add(t.name)  # pin for subsetting
                if t not in self._integrations:
                    self._integrations.append(t)
            print(f"  ok {recipe.display} ready - tools: "
                  f"{', '.join(t.name for t in tools)}")
        else:
            print(f"  ok {recipe.env_var} set - {recipe.display} is ready to use.")

        # Offer to persist the key across sessions (else it's just this session).
        if (await self._ask(f"  Remember {recipe.env_var} for future sessions? [y/N] ")
                ).lower() in ("y", "yes"):
            self._persist_env_var(recipe.env_var, key)
        print()

    def _persist_env_var(self, name: str, value: str) -> None:
        """Persist an env var for future sessions (best-effort, per-OS)."""
        try:
            if sys.platform == "win32":
                import subprocess
                subprocess.run(["setx", name, value], capture_output=True, check=False)
                print(f"  ok {name} saved to your user environment (new shells pick it up).")
            else:
                print(f"  To persist, add to your shell profile:\n"
                      f"     export {name}='<your key>'")
        except Exception as exc:
            print(f"  [!] couldn't persist {name} ({exc}); set it manually to keep it.")

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
            print("  No stale tools - the generated-tool library is clean.")
            return
        print(f"\n  {len(candidates)} stale tool(s). Archiving is reversible "
              f"(/restore <name>).")
        for name, reason in candidates:
            print(f"\n  - {name} - {reason}")
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
        extra = self.findings_store.all() if getattr(self, "findings_store", None) else None
        report = build_report(self.controller.chain.attack_state, records, meta,
                              extra_findings=extra)

        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = os.path.join(self.working_dir, "engagements")
        os.makedirs(out_dir, exist_ok=True)
        written: list[str] = []
        if fmt in ("md", "markdown", "both"):
            path = os.path.join(out_dir, f"report-{stamp}.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(report.to_markdown())
            written.append(path)
        if fmt in ("html", "both", "all"):
            path = os.path.join(out_dir, f"report-{stamp}.html")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(report.to_html())
            written.append(path)
        # SARIF (CI / code-scanning) + bug-bounty drafts, from the evidence-rich store.
        store_findings = self.findings_store.all() if getattr(self, "findings_store", None) else []
        if fmt in ("sarif", "all") and store_findings:
            from reporting.exporters import to_sarif
            path = os.path.join(out_dir, f"report-{stamp}.sarif")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(to_sarif(store_findings))
            written.append(path)
        if fmt in ("bounty", "all") and store_findings:
            from reporting.exporters import to_bounty_bundle
            path = os.path.join(out_dir, f"report-{stamp}-bounty.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(to_bounty_bundle(store_findings))
            written.append(path)

        counts = report.severity_counts()
        sev = ", ".join(f"{n} {s.lower()}" for s, n in counts.items() if n) or "no findings"
        print(f"\n  Report ({len(report.findings)} findings - {sev}):")
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
            print(f"x {result.error}")
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
                print(f"\n  User profile - {self.user_profile.path}:\n")
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
                print(f"\n  Active persona - {origin}:\n")
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
                        sig = " oksigned" if m.signature else ""
                        print(f"    {m.name} v{m.version} [{m.skill_type}]{sig} - {m.description}")
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

        elif command == "/egress":
            eg = self.egress
            print(f"\n  Egress: {eg.describe() if eg else 'direct'}")
            if eg and eg.active:
                print("  HTTP tools route through the proxy; shell/nmap wrap with "
                      f"{eg._wrapper_prefix() or 'nothing'} (TCP-connect only).")
                print("  Run `egress_check` to confirm the apparent IP a target sees.")
            else:
                print("  Attack traffic uses your REAL IP. Set config.egress "
                      "(mode: tor | proxy + proxy: socks5://…) or --egress "
                      "tor|<proxy-url>. Strongest hide: attack from a pivot "
                      "(--exec-backend ssh/docker).")
            print()

        elif command == "/integrations":
            tools = self._integrations
            if not tools:
                print("\n  No integrations configured. Add tools under "
                      "config.integrations (http API like Shodan, or a command / "
                      "GitHub-repo CLI). See tools/external_tools.py for the shape.\n")
            else:
                print(f"\n  Integrations ({len(tools)}) - bring-your-own tools:")
                for t in tools:
                    kind = "http" if t.__class__.__name__ == "HttpApiTool" else "cmd"
                    print(f"    [{kind}] {t.name} - {t.description[:60]}")
                print()

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
                print("  No attack state yet - run a scan first.")
            print()

        elif command == "/scope":
            if self.scope and self.scope.active:
                print(f"\n{self.scope.summary()}\n")
            else:
                print("\n  RoE scope: off - no scope.json loaded. Create one in the "
                      "working dir to\n  restrict targets/actions. Example:")
                print('    {"name": "engagement", "targets": ["10.10.10.0/24"],')
                print('     "forbidden_tools": ["msf_run"]}\n')

        elif command == "/todos":
            todos = list(getattr(self.controller.chain, "todos", []) or []) \
                if self.controller else []
            if not todos:
                print("\n  Checklist is empty - the agent builds one as it plans a "
                      "multi-step task.\n")
            else:
                done = sum(1 for t in todos if t.status == "completed")
                print(f"\n  Checklist ({done}/{len(todos)})")
                for i, t in enumerate(todos, 1):
                    print(f"    {i}. {t.marker()} {t.task}")
                print()

        elif command == "/sidebar":
            if self.tui is None:
                print("\n  Sidebar is only shown in the full-screen TUI "
                      "(mapache serve).\n")
            else:
                arg = parts[1].lower() if len(parts) > 1 else ""
                cur = self.tui.dashboard.width
                new = None
                if arg in ("wide", "wider", "+", "big"):
                    new = min(70, cur + 6)
                elif arg in ("narrow", "narrower", "-", "small"):
                    new = max(20, cur - 6)
                elif arg.isdigit():
                    new = max(20, min(70, int(arg)))
                if new is None:
                    print("\n  Usage: /sidebar wide|narrow|<width 20-70>  "
                          f"(current: {cur})\n")
                else:
                    self.tui.dashboard.width = new
                    self.tui.dashboard._changed()
                    print(f"\n  Sidebar width: {new}\n")

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

        elif command == "/swarm":
            if len(parts) > 1:
                self.swarm = parts[1].lower() in ("on", "true", "1", "yes")
            else:
                self.swarm = not self.swarm
            state = "ON" if self.swarm else "off"
            print(f"  Multi-agent swarm: {state} - the supervisor autonomously routes "
                  f"specialist operators (recon → web → exploit → post) based on "
                  f"findings, instead of the single lead agent.\n")

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
                    print(f"    {t} - {summary}")
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
        description="Mapache - Offensive security AI agent",
        epilog="Subcommands: `mapache setup` (interactive config), "
               "`mapache config show|path` (inspect config), "
               "`mapache update [--check]` (update manager), "
               "`mapache version` (print version). "
               "With no subcommand, launches the agent REPL.")
    # Config-backed flags default to None so MapacheCLI._cli_overrides can tell
    # "explicitly passed" from "unset". When unset they fall through to the
    # project/global/env/default layers (env vars like MAPACHE_MODEL / OLLAMA_URL
    # are handled by the config env layer, not baked in here as argparse
    # defaults - that keeps the precedence CLI > project > global > env right).
    parser.add_argument("--model", "-m", default=None,
                        help="Primary model id (default: from config / "
                             "MAPACHE_MODEL env / built-in default)")
    parser.add_argument("--ollama-url", default=None)
    parser.add_argument("--dir", "-d", default=None,
                        help="Working directory (holds plugins/generated, "
                             "engagements, project config). Default: the current "
                             "directory, or a per-user workspace if it isn't writable.")
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
    parser.add_argument("--budget-tokens", type=int, default=None, metavar="N",
                        help="Engagement budget: stop the loop gracefully once "
                             "cumulative tokens reach N (overrides config.budget)")
    parser.add_argument("--budget-seconds", type=float, default=None, metavar="S",
                        help="Engagement budget: stop the loop gracefully after S "
                             "wall-clock seconds (overrides config.budget)")
    parser.add_argument("--hitl", action="store_true",
                        help="Human-in-the-loop: pause the loop at milestones (phase "
                             "changes) for operator approve/deny/steer")
    parser.add_argument("--hitl-every", type=int, default=None, metavar="N",
                        help="HITL: also pause every N iterations for operator review "
                             "(implies --hitl; overrides config.hitl)")
    parser.add_argument("--vaccine", action="store_true",
                        help="Defensive follow-up: generate a detection+remediation "
                             "'vaccine' for each confirmed vulnerability (→ vaccines/)")
    parser.add_argument("--route-enum", action="store_true",
                        help="On a web target with few known endpoints, probe common "
                             "routes once and inject the real ones (so the agent uses "
                             "actual paths instead of guessing /login, /dashboard)")
    parser.add_argument("--reflect", action="store_true",
                        help="Inject a reflect-and-refocus self-critique every N steps "
                             "(confirmed facts → hypothesis → highest-value next action)")
    parser.add_argument("--reflect-every", type=int, default=None, metavar="N",
                        help="Reflection cadence in steps (implies --reflect; default 6)")
    parser.add_argument("--attempts", type=int, default=1, metavar="N",
                        help="Self-consistency: if the objective isn't reached, retry "
                             "with a fresh approach up to N times (stops on first solve)")
    parser.add_argument("--flag-format", default=None, metavar="REGEX",
                        help="Expected flag format (regex) - the verifier flags a "
                             "captured token that doesn't match it as unverified")
    parser.add_argument("--fanout", action="store_true",
                        help="Swarm (/swarm): when a single operator stalls, deploy "
                             "several specialists in parallel to break the plateau")
    parser.add_argument("--no-tools", action="store_true")
    parser.add_argument("--all-tools", action="store_true",
                        help="Disable phase-based tool subsetting and expose all "
                             "tools every turn (may overflow local-model payloads)")
    parser.add_argument("--no-context", action="store_true")
    parser.add_argument("--plain", action="store_true",
                        help="Disable the rich TUI (panels/colour) and use plain "
                             "line output. Auto-selected for pipes/dumb terminals "
                             "or when the `rich` package isn't installed.")
    parser.add_argument("--tui", action="store_true",
                        help="Full-screen chat UI: a bordered input box pinned to "
                             "the bottom with a scrolling output region above "
                             "(needs prompt_toolkit + a real terminal).")
    parser.add_argument("--exec-backend", default=None,
                        choices=["local", "ssh", "docker"],
                        help="Where `shell` commands run (feature H). ssh/docker "
                             "need host/container details in config.execution "
                             "(mapache.json / ~/.mapache/config.json). Default: local.")
    parser.add_argument("--egress", default=None,
                        help="Hide your IP when attacking: 'tor', or a proxy URL "
                             "(socks5://host:port, http://host:port). HTTP tools route "
                             "through it; shell/nmap wrap with torsocks/proxychains "
                             "(TCP-connect only). Strongest hide: attack from a pivot "
                             "via --exec-backend. Default: config.egress or direct.")
    parser.add_argument("-tor", "--tor", dest="tor", action="store_true",
                        help="Route this run through Tor (shortcut for --egress tor; "
                             "auto-starts Tor). Opt-in per run - default stays direct.")
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
    parser.add_argument("--cast", action="store_true",
                        help="Record the engagement as a replayable asciicast "
                             "(engagements/*.cast) - court-ready session evidence.")
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
    if argv and argv[0] == "serve":
        # `serve` = launch the full-screen TUI. Rewrite argv so the normal flag
        # parser handles any extra options (--model, …) with --tui forced on.
        sys.argv = [sys.argv[0], *argv[1:], "--tui"]

    args = parse_args()
    # Console stays quiet by default (WARNING) so the live status line isn't buried
    # under agent_controller INFO logs; the file log keeps everything at DEBUG.
    # `--debug` restores full console verbosity.
    setup_logging(level="DEBUG" if args.debug else "WARNING", log_dir=args.log_dir)
    cli = MapacheCLI(args)
    await cli.run()


def main_sync() -> None:
    """Console-script entry point (`mapache …`). Wraps the async main()."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBye.")
    except SystemExit:
        raise


if __name__ == "__main__":
    asyncio.run(main())
