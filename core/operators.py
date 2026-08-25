"""
operators.py - specialist sub-agent roster (feature P)

Decepticon-style operator specialists for Mapache's delegation. The lead agent
dispatches a bounded objective to one of these via `delegate(task, operator=…)`;
the chosen operator runs as a sub-agent with a *focused* system prompt and a
*small* curated tool subset, sharing the lead's AttackState blackboard.

Why this shape on a local-first agent: a generalist with the full 180-line
offensive prompt and 30+ tools drifts and overflows small-model context. A
`web_operator` with a tight prompt and ~6 tools makes far better decisions -
specialization shrinks both the payload and the decision space. The domain
tooling a specialist names (frida, binwalk, semgrep, evilginx2, modbus clients…)
is driven through `kali_run`/`shell`, or the operator authors a wrapper with
`create_tool`; the expertise lives in the prompt, not in bespoke tool code.

Each Operator also carries the engagement constraints the roles imply - read-only
roles, RoE-gating, hardware/remote requirements, blue-team deconfliction - which
are rendered into the prompt and (for read-only/gated roles) reinforce feature J.
"""

from __future__ import annotations

from dataclasses import dataclass, field


OPERATOR_PREAMBLE = """You are the {title} - a specialist sub-agent in an authorized \
penetration test. You have ONE objective; pursue only it, then hand back a concise report.

Operating discipline:
- Act by emitting ONE tool call at a time; wait for the real result before the next step.
- Never fabricate output. Quote exact artifacts - ports, versions, hashes, paths, flags.
- The CURRENT ATTACK STATE block is the shared source of truth. Read it. Anything you
  discover (flags, creds, vulns, ports) is recorded there automatically for the lead and
  the other operators - you do not need to repeat it back.
- Stay within the engagement scope; an out-of-scope or forbidden action will be refused.
- When the objective is met, or you are blocked and need the lead, stop and report plainly.
{constraints}
Your specialty:
{expertise}"""


@dataclass
class Operator:
    name: str
    title: str
    description: str          # one-liner shown to the lead when it picks a specialist
    phase: str               # killchain phase this operator primarily serves
    expertise: str           # the domain methodology block injected into the prompt
    tools: set[str] = field(default_factory=set)
    triggers: set[str] = field(default_factory=set)  # ports/service tokens that suggest it
    read_only: bool = False
    requires_remote: bool = False        # needs hardware passthrough / SSH dropbox (feature H)
    roe_gated: bool = False              # fragile/regulated; scope-gated, lab/canary writes
    requires_deconfliction: bool = False  # must deconflict with blue team before acting
    prefer_local: bool = True            # OPSEC hint for hybrid routing (feature O)
    # Per-operator model routing (feature P): which model ROLE this operator's
    # loop is scored as. Reasoning-heavy specialists use "planner" (the quality
    # model); action/tool-driven ones use "executor" (the fast one). Only takes
    # effect when several models are installed under a routing strategy.
    model_role: str = "executor"
    # Cost/quality tier for model routing (Decepticon-style): "high" = the strong
    # model (default - never downgrade a hacking-critical operator by accident);
    # "low" = a cheaper/faster model for high-volume, low-stakes discovery work
    # (recon/OSINT/broad scanning). Only takes effect with a tiered model provider.
    tier: str = "high"

    @property
    def constraints_block(self) -> str:
        lines = []
        if self.read_only:
            lines.append("- READ-ONLY role: enumerate and analyze only; do NOT exploit, "
                         "modify, or disrupt the target.")
        if self.roe_gated:
            lines.append("- This target class is fragile/regulated: read-only enumeration "
                         "first; perform writes ONLY against an explicit in-scope lab/canary.")
        if self.requires_deconfliction:
            lines.append("- Do NOT send any lure, payload, or message until blue-team "
                         "deconfliction is explicitly confirmed by the operator.")
        if self.requires_remote:
            lines.append("- Radio/hardware actions need a hardware passthrough or SSH "
                         "dropbox; if none is available, report exactly what is required "
                         "instead of pretending to act.")
        return ("\n".join(lines) + "\n") if lines else ""

    @property
    def system_prompt(self) -> str:
        return OPERATOR_PREAMBLE.format(
            title=self.title,
            constraints=self.constraints_block,
            expertise=self.expertise.strip(),
        )


# Tool subsets reference Mapache's *registered* tool names. shell + kali_run are
# the workhorses (any installed CLI tool runs through them); create_tool lets an
# operator author a missing wrapper. Sets are deliberately small.
_RECON = {"nmap_scan", "web_fetch", "web_search", "http_request", "http_repeater",
          "shell", "searchsploit", "tech_detect"}
_WEB = {"kali_run", "web_fetch", "web_search", "http_request", "http_repeater",
        "browser", "sqlmap", "fuzz", "burp_scan", "burp_proxy", "searchsploit", "shell",
        "tech_detect", "jwt_tool", "graphql", "llm_inject", "code_run"}
_EXPLOIT = {"msf_search", "msf_run", "msf_sessions", "searchsploit", "http_request",
            "http_repeater", "sqlmap", "fuzz", "kali_run", "shell", "jwt_tool", "graphql",
            "llm_inject", "ad_attack", "code_run"}
_POST = {"shell", "kali_run", "john_crack", "john_identify", "msf_sessions", "file_read",
         "ad_attack"}
_ANALYSIS = {"shell", "kali_run", "file_read", "file_list", "file_search",
             "searchsploit", "web_search", "create_tool"}


_OPERATORS: dict[str, Operator] = {}


def _add(op: Operator) -> None:
    _OPERATORS[op.name] = op


# --- killchain core (phase-aligned) ---------------------------------------- #

_add(Operator(
    name="recon_operator", title="Recon Operator", phase="recon", tier="low",
    prefer_local=False,  # early, low-sensitivity host/service discovery - cloud OK
    description="Active host/service discovery - port and version scanning.",
    tools=_RECON,
    expertise="nmap sweeps (standard → version → vuln scripts) over in-scope hosts; "
              "map open ports to services and versions; hand the service inventory to "
              "the lead so the right follow-on operator can be tasked.",
))
_add(Operator(
    name="osint_operator", title="OSINT Operator", phase="recon", read_only=True, tier="low",
    prefer_local=False,  # works over public open-source intel - cloud OK
    model_role="planner",  # research/correlation - reasoning-heavy
    description="Passive open-source intel - domains, emails, employees, breaches, leaks.",
    tools={"web_fetch", "web_search", "osint_search", "phone_lookup", "social_lookup",
           "tor_fetch", "tor_control", "onion_search", "shell", "memory_save"},
    triggers=set(),
    expertise="passive footprinting only: domain/subdomain, email and employee "
              "enumeration, breach/credential-leak and public code-leak discovery, infra "
              "fingerprinting. Prefer `osint_search` over a bare web_search - it fans one "
              "subject out into social/leak/doc/code dorks in a single call. Use "
              "`phone_lookup` to validate/attribute a phone number, and `social_lookup` "
              "to pivot a handle to the person's other profiles (e.g. the LinkedIn behind "
              "an Instagram account). Feeds Recon and Exploit; touch no target system directly.",
))
_add(Operator(
    name="web_operator", title="Web Operator", phase="enumeration",
    prefer_local=False,  # web enumeration over the target's public surface - cloud OK
    description="Web application attacks - content discovery, vuln scanning, exploitation.",
    tools=_WEB, triggers={"80", "443", "8080", "8000", "http", "https"},
    expertise="RECON FIRST: before guessing endpoints or credentials, web_fetch the "
              "target and READ its 'Attack surface' (real form actions + field names, "
              "referenced endpoints, HTML comments) - act on what the app actually "
              "exposes, never on invented routes/params. Then: directory/content brute "
              "force (gobuster/ffuf), nikto/burp vuln scanning, parameter and auth "
              "testing, common web classes (injection, IDOR, SSRF, file upload, "
              "deserialization), and searchsploit on the exact stack+version.",
))
_add(Operator(
    name="exploit_operator", title="Exploit Operator", phase="exploitation",
    description="Service exploitation - match a vuln to a working exploit and land access.",
    tools=_EXPLOIT,
    expertise="correlate discovered service+version to exploits (msf_search/searchsploit), "
              "select and run the right module/PoC against the in-scope target, and confirm "
              "the resulting session/shell.",
))
_add(Operator(
    name="post_operator", title="Post-Exploit Operator", phase="post",
    description="Post-exploitation - privesc, looting, credential and flag capture.",
    tools=_POST,
    expertise="on a foothold: enumerate for privilege escalation (SUID, sudo, kernel, "
              "cron), dump and crack credentials (john), pivot, and capture flags. Linux "
              "commands once on a Linux target; Windows commands on Windows.",
))

# --- operator-level specialists -------------------------------------------- #

_add(Operator(
    name="cloud_hunter", title="Cloud Hunter", phase="exploitation",
    description="Cloud infrastructure attacks - IAM, storage exposure, k8s, metadata abuse.",
    # http_request/http_repeater: raw calls to the metadata service (169.254.169.254 /
    # 169.254.170.2) for credential theft, and to cloud REST APIs.
    tools={"shell", "kali_run", "web_fetch", "http_request", "http_repeater",
           "cloud_metadata", "file_read", "create_tool"},
    expertise="IAM privilege escalation, public S3/blob/bucket exposure, Kubernetes RBAC "
              "escapes and exposed kubelets/dashboards, and cloud metadata-service (IMDS) "
              "abuse for credential theft. Use provider CLIs via shell; respect scope.",
))
_add(Operator(
    name="contract_auditor", title="Contract Auditor", phase="exploitation",
    model_role="planner",  # deep reasoning over source
    description="Solidity / EVM smart-contract audits.",
    # http_request: JSON-RPC calls to a node / block explorer APIs.
    tools={"shell", "file_read", "file_write", "web_fetch", "http_request", "create_tool"},
    expertise="Solidity/EVM review for reentrancy, oracle manipulation, flash-loan abuse, "
              "and broken access control; run slither/mythril-style analysis through shell "
              "and reason over the source.",
))
_add(Operator(
    name="exploit_dev", title="Exploit Developer", phase="exploitation",
    model_role="planner",  # writing correct exploit code is reasoning-heavy
    description="Write and debug attack scripts / exploits (PoC development in a tight loop).",
    # code_run is the workhorse: author + compile + run in the target's own
    # environment. file_* to read the challenge source and refine; shell for the
    # surrounding setup; http_request to probe a service the exploit will hit.
    tools={"code_run", "file_read", "file_write", "file_edit", "file_list",
           "file_search", "shell", "http_request", "binary_analyze"},
    expertise="develop working exploits/PoCs as CODE, not prose. Loop tightly with "
              "code_run: write the script, RUN it, read the compiler/runtime error, "
              "fix, repeat until it actually fires - never hand back untested code. "
              "Python (pwntools for pwn: cyclic pattern → offset → ROP/ret2libc; "
              "requests for web), C for shellcode/format-string/heap work, bash for "
              "glue. Read the challenge source with file_read first and target the "
              "REAL binary/service; quote the exact recovered artifact (flag, shell, "
              "leak) as evidence. Prefer deterministic, re-runnable scripts.",
))
_add(Operator(
    name="general", title="General Agent", phase="analysis", prefer_local=True,
    model_role="executor",
    description="General-purpose assistant for questions and non-offensive tasks.",
    # A light toolset: research + read + a shell for simple, non-attack tasks.
    tools={"web_search", "web_fetch", "file_read", "file_list", "file_search",
           "shell", "code_run"},
    triggers=set(),
    expertise="handle general, non-offensive requests: answer questions from your own "
              "knowledge, research with web_search/web_fetch, read files, and run simple "
              "commands. This is NOT an attack and NOT a capture-the-flag task: do not run "
              "a kill chain or hunt for flags. Answer directly and concisely, and reach for "
              "a tool only when you actually need external information.",
))
_add(Operator(
    name="coder", title="Coder", phase="analysis", roe_gated=False,
    model_role="planner",  # writing correct code is reasoning-heavy
    prefer_local=True,
    description="Write, run, and fix general code, scripts, and tooling (not just exploits).",
    # The coding workhorse: code_run authors + compiles + runs + iterates; file_* to
    # read and refine source; shell for setup. Distinct from exploit_dev, which is
    # attack-PoC focused - this operator handles plain programming requests.
    tools={"code_run", "file_read", "file_write", "file_edit", "file_list",
           "file_search", "shell", "create_tool"},
    triggers={"code", "script", "program", "python", "compile", "function", "refactor"},
    expertise="write, run, and iteratively fix code with code_run for general programming, "
              "scripting, and tooling - not only exploits. This is NOT a capture-the-flag "
              "task: a plain coding request is answered with working, tested code, never a "
              "kill chain. Loop tightly: write, RUN it, read the REAL compiler/runtime error "
              "or output, fix, repeat until it works. Read existing source with file_read "
              "before editing. Return the final working code plus a one-line note on what it "
              "does; do not fabricate output you did not actually run.",
))
_add(Operator(
    name="reverser", title="Reverser", phase="analysis",
    model_role="planner",  # reasoning over binaries
    description="Binary analysis and reverse engineering.",
    # binary_analyze: structured triage (checksec/strings/nm/ROPgadget with parsed output);
    # file_search: grep strings/symbols/xrefs across an unpacked binary/firmware tree.
    tools={"shell", "kali_run", "file_read", "file_list", "file_search", "binary_analyze",
           "code_run", "create_tool"},
    expertise="ELF/PE/Mach-O triage, packer detection, ROP gadget inventories, and "
              "Ghidra/radare2 static recon driven through shell/kali_run; surface "
              "exploitable primitives.",
))
_add(Operator(
    name="analyst", title="Analyst", phase="analysis",
    prefer_local=False,  # reasoning over already-collected findings - cloud OK
    model_role="planner",  # vuln research / exploit-chain construction
    description="Vuln research & reporting - code review, SAST, dependency CVE sweeps.",
    tools=_ANALYSIS,
    expertise="source-code review, static analysis (semgrep/bandit/gitleaks), dependency "
              "CVE sweeps, and multi-hop exploit-chain construction from the collected "
              "findings. Produces the analysis the report builds on.",
))
_add(Operator(
    name="phisher", title="Phisher", phase="exploitation", requires_deconfliction=True,
    description="Initial access via phishing / social engineering (MITRE T1566.*).",
    tools={"shell", "kali_run", "web_fetch", "file_write", "create_tool"},
    expertise="GoPhish campaigns, evilginx2 MFA-bypass token capture, M365/O365 OAuth "
              "device-code harvest, lookalike-domain and pretext engineering. Lure "
              "deconfliction with the blue team is mandatory before anything is sent.",
))
_add(Operator(
    name="mobile_operator", title="Mobile Operator", phase="exploitation",
    description="Android / iOS application attacks.",
    # http_request/http_repeater: test the app's API backend (authz/IDOR on mobile
    # endpoints); file_list/file_search: browse the decompiled apk/ipa tree.
    tools={"shell", "kali_run", "file_read", "file_list", "file_search",
           "http_request", "http_repeater", "create_tool"},
    expertise="static analysis (apktool/jadx/class-dump), dynamic instrumentation "
              "(frida/objection), SSL-pinning and root/jailbreak bypass, exported-component "
              "abuse, WebView JS-bridge exploitation, MobSF runs.",
))
_add(Operator(
    name="wireless_operator", title="Wireless Operator", phase="exploitation",
    requires_remote=True,
    description="Wi-Fi / BLE / Zigbee / sub-GHz attacks.",
    tools={"shell", "kali_run", "create_tool"},
    expertise="WPA2 handshake/PMKID capture, WPA3-SAE downgrade, WPA-Enterprise evil-twin, "
              "KARMA/Mana, deauth, WPS Pixie Dust, BLE GATT, Zigbee Touchlink, sub-GHz "
              "replay. Needs a radio via hardware passthrough or an SSH dropbox.",
))
_add(Operator(
    name="iot_operator", title="IoT Operator", phase="exploitation", requires_remote=True,
    description="IoT / embedded device attacks - firmware, hardcoded creds, radios.",
    # web_fetch/http_request: the device's web UI / REST API; file_list/file_search:
    # walk the binwalk-extracted firmware root for creds/keys/configs.
    tools={"shell", "kali_run", "searchsploit", "file_read", "file_list", "file_search",
           "web_fetch", "http_request", "create_tool"},
    triggers={"1900", "5683", "8883", "upnp", "mqtt", "coap"},
    expertise="firmware acquisition + binwalk extraction, hardcoded credentials, "
              "U-Boot / /dev/mem access, and BLE/Zigbee/Z-Wave/sub-GHz/LoRaWAN radio work "
              "(radios need hardware passthrough or an SSH dropbox).",
))
_add(Operator(
    name="ics_operator", title="ICS Operator", phase="enumeration", roe_gated=True,
    read_only=True,
    description="ICS / OT / SCADA attacks (Modbus, DNP3, S7comm, BACnet, OPC-UA).",
    # http_request: HMI / engineering-workstation web interfaces (read-only enum).
    tools={"shell", "kali_run", "web_fetch", "http_request", "create_tool"},
    triggers={"502", "20000", "102", "44818", "47808", "modbus", "s7", "bacnet", "dnp3"},
    expertise="Modbus/DNP3/S7comm/BACnet/OPC-UA enumeration. OT is fragile: read-only "
              "enumeration first, and writes only against an explicit in-scope lab/canary - "
              "never a production controller.",
))
_add(Operator(
    name="forensicator", title="Forensicator", phase="analysis", read_only=True,
    model_role="planner",  # timeline/IOC analysis + detection mapping
    description="DFIR / purple-team validation - timelines, IOCs, attack→detection mapping.",
    tools={"shell", "kali_run", "file_read", "file_list", "file_search"},
    expertise="disk/memory/log/network timeline analysis, IOC extraction, and mapping the "
              "engagement's actions to the detections they should have triggered - the "
              "purple-team validation pass.",
))
_add(Operator(
    name="supply_chain_operator", title="Supply Chain Operator", phase="exploitation",
    model_role="planner",  # dependency/pipeline analysis
    description="Supply-chain attacks - dependencies, build pipelines, package integrity.",
    # web_fetch/http_request: query package-registry APIs (npm/pypi) for typosquat /
    # dependency-confusion checks and provenance metadata.
    tools={"shell", "kali_run", "file_read", "web_search", "web_fetch",
           "http_request", "create_tool"},
    expertise="dependency confusion / typosquatting, compromised or malicious packages, "
              "CI/CD pipeline and build-artifact integrity, and signing/provenance gaps "
              "across the software supply chain.",
))


# --------------------------------------------------------------------------- #
# Vulnerability-research pipeline (Vulnresearch) - five staged specialists that
# run in order, passing state exclusively through the knowledge graph (each stage
# spawns with a fresh context, reads prior findings via kg_query, records its own
# via kg_add). VULN_PIPELINE is the canonical stage order.
# --------------------------------------------------------------------------- #

_add(Operator(
    name="scanner", title="Scanner", phase="enumeration", model_role="executor", tier="low",
    description="Vuln-research stage 1 - surface vulnerability candidates (CVE/CVSS).",
    tools={"nmap_scan", "kali_run", "searchsploit", "web_fetch", "http_request",
           "cve_lookup", "web_search"},
    expertise="broad discovery: enumerate services/versions and surface VULNERABILITY "
              "CANDIDATES with CVE/CVSS where known. Record each candidate to the "
              "knowledge graph (kg_add type=vulnerability) with the affected service; "
              "do NOT confirm or exploit - that is later stages' job.",
))
_add(Operator(
    name="detector", title="Detector", phase="analysis", model_role="planner",
    read_only=True,
    description="Vuln-research stage 2 - analyze candidates into confidence-rated findings.",
    tools={"file_read", "kali_run", "cve_lookup", "web_search", "searchsploit"},
    expertise="read the scanner's candidates from the knowledge graph, analyze each "
              "(version match, exposure, preconditions) and RATE CONFIDENCE. READ-ONLY: "
              "no exploitation. Record confidence + reasoning back to the graph for the "
              "verifier.",
))
_add(Operator(
    name="verifier", title="Verifier", phase="analysis", model_role="planner",
    description="Vuln-research stage 3 - confirm findings (2+ methods for CRITICAL/HIGH).",
    tools={"kali_run", "shell", "http_request", "msf_search", "searchsploit"},
    expertise="confirm detector findings with concrete evidence - for CRITICAL/HIGH use "
              "TWO independent methods. Quote the exact proof. Mark each finding verified "
              "or refuted in the knowledge graph; only verified findings proceed.",
))
_add(Operator(
    name="patcher", title="Patcher", phase="report", model_role="planner",
    description="Vuln-research stage 4 - produce a patch or configuration fix.",
    tools={"file_read", "file_write", "file_edit", "shell", "kali_run"},
    expertise="for each verified finding, produce a concrete remediation: a code patch "
              "or configuration change with exact file/line/setting. Write the fix to the "
              "workspace and record its location in the knowledge graph.",
))
_add(Operator(
    name="exploiter", title="Exploiter", phase="exploitation", model_role="executor",
    description="Vuln-research stage 5 - build a working proof-of-concept.",
    tools={"msf_search", "msf_run", "kali_run", "shell", "searchsploit", "code_run"},
    expertise="for a verified finding, build a WORKING proof-of-concept against the "
              "in-scope target and capture the exact evidence (session, output, artifact). "
              "Record the PoC + evidence in the knowledge graph.",
))

# Canonical Vulnresearch stage order (Discovery → Analysis → Confirmation →
# Remediation → Exploitation). State flows between stages via the knowledge graph.
VULN_PIPELINE = ("scanner", "detector", "verifier", "patcher", "exploiter")

# Engagement planner (Soundwave-style). Delegated 'plan the engagement': turns the
# mission into an OPPLAN of objectives and a short engagement brief, before any
# offensive action. Read-only w.r.t. the target (planning + document generation).
_add(Operator(
    name="soundwave", title="Engagement Planner", phase="recon", model_role="planner",
    read_only=True,
    description="Engagement planner - turn the mission into an OPPLAN + engagement brief.",
    tools={"opplan_add", "opplan_update", "opplan_show", "file_write", "web_search"},
    expertise="translate the operator's mission into a concrete plan BEFORE any "
              "offensive action: (1) seed the OPPLAN with ordered objectives via "
              "opplan_add, each owned by the right specialist (recon_operator → "
              "exploit_operator → post_operator, or the Vulnresearch stages); (2) write "
              "a short engagement brief to the workspace covering rules of engagement, "
              "scope, objectives, and abort/cleanup notes. Do not scan or exploit - "
              "planning only.",
))


# Every specialist can read prior findings and record its own in the shared
# knowledge graph - the durable channel between fresh-context objectives - and
# record an evidence-first finding into the engagement report (the deliverable).
for _op in _OPERATORS.values():
    _op.tools |= {"kg_query", "kg_add", "report_finding"}


# --------------------------------------------------------------------------- #
# Lookup
# --------------------------------------------------------------------------- #

# Names the lead may pass to mean "no specialist, run the generalist sub-agent".
GENERALIST_ALIASES = {"", "auto", "generalist", "none", "default"}


def get_operator(name: str | None) -> Operator | None:
    if not name:
        return None
    return _OPERATORS.get(name.strip().lower())


def operator_names() -> list[str]:
    return list(_OPERATORS.keys())


def suggest_operators(ports: list[str], services: dict | None = None) -> list[str]:
    """Operators whose triggers match the discovered ports/services.

    Used to nudge the lead (in the attack-state 'next step') toward the right
    specialist once recon reveals what's listening - e.g. port 80 → web_operator,
    a Modbus/502 service → ics_operator.
    """
    tokens: set[str] = set()
    for p in ports or []:
        tokens.add(str(p).split("/")[0])
    for svc in (services or {}).values():
        tokens.add(str(svc).lower())
    return [op.name for op in _OPERATORS.values() if op.triggers and (op.triggers & tokens)]


def all_operators() -> list[Operator]:
    return list(_OPERATORS.values())


def roster_summary() -> str:
    """Compact human-readable roster (for the CLI `/operators` command)."""
    lines = []
    for op in _OPERATORS.values():
        tags = []
        if op.read_only:
            tags.append("read-only")
        if op.roe_gated:
            tags.append("RoE-gated")
        if op.requires_remote:
            tags.append("needs-hardware")
        if op.requires_deconfliction:
            tags.append("deconflict-first")
        if not op.prefer_local:
            tags.append("cloud-ok")  # OPSEC: may route to cloud (feature O)
        if op.model_role != "executor":
            tags.append(f"{op.model_role}-model")  # per-operator routing (feature P)
        suffix = f"  [{', '.join(tags)}]" if tags else ""
        lines.append(f"  {op.name:22s} {op.phase:12s} {op.description}{suffix}")
    return "\n".join(lines)
