"""
operators.py — specialist sub-agent roster (feature P)

Decepticon-style operator specialists for Mapache's delegation. The lead agent
dispatches a bounded objective to one of these via `delegate(task, operator=…)`;
the chosen operator runs as a sub-agent with a *focused* system prompt and a
*small* curated tool subset, sharing the lead's AttackState blackboard.

Why this shape on a local-first agent: a generalist with the full 180-line
offensive prompt and 30+ tools drifts and overflows small-model context. A
`web_operator` with a tight prompt and ~6 tools makes far better decisions —
specialization shrinks both the payload and the decision space. The domain
tooling a specialist names (frida, binwalk, semgrep, evilginx2, modbus clients…)
is driven through `kali_run`/`shell`, or the operator authors a wrapper with
`create_tool`; the expertise lives in the prompt, not in bespoke tool code.

Each Operator also carries the engagement constraints the roles imply — read-only
roles, RoE-gating, hardware/remote requirements, blue-team deconfliction — which
are rendered into the prompt and (for read-only/gated roles) reinforce feature J.
"""

from __future__ import annotations

from dataclasses import dataclass, field


OPERATOR_PREAMBLE = """You are the {title} — a specialist sub-agent in an authorized \
penetration test. You have ONE objective; pursue only it, then hand back a concise report.

Operating discipline:
- Act by emitting ONE tool call at a time; wait for the real result before the next step.
- Never fabricate output. Quote exact artifacts — ports, versions, hashes, paths, flags.
- The CURRENT ATTACK STATE block is the shared source of truth. Read it. Anything you
  discover (flags, creds, vulns, ports) is recorded there automatically for the lead and
  the other operators — you do not need to repeat it back.
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
_RECON = {"nmap_scan", "web_fetch", "web_search", "shell", "searchsploit"}
_WEB = {"kali_run", "web_fetch", "web_search", "burp_scan", "burp_proxy",
        "searchsploit", "shell"}
_EXPLOIT = {"msf_search", "msf_run", "msf_sessions", "searchsploit", "kali_run", "shell"}
_POST = {"shell", "kali_run", "john_crack", "john_identify", "msf_sessions", "file_read"}
_ANALYSIS = {"shell", "kali_run", "file_read", "file_list", "file_search",
             "searchsploit", "web_search", "create_tool"}


_OPERATORS: dict[str, Operator] = {}


def _add(op: Operator) -> None:
    _OPERATORS[op.name] = op


# --- killchain core (phase-aligned) ---------------------------------------- #

_add(Operator(
    name="recon_operator", title="Recon Operator", phase="recon",
    prefer_local=False,  # early, low-sensitivity host/service discovery — cloud OK
    description="Active host/service discovery — port and version scanning.",
    tools=_RECON,
    expertise="nmap sweeps (standard → version → vuln scripts) over in-scope hosts; "
              "map open ports to services and versions; hand the service inventory to "
              "the lead so the right follow-on operator can be tasked.",
))
_add(Operator(
    name="osint_operator", title="OSINT Operator", phase="recon", read_only=True,
    prefer_local=False,  # works over public open-source intel — cloud OK
    model_role="planner",  # research/correlation — reasoning-heavy
    description="Passive open-source intel — domains, emails, employees, breaches, leaks.",
    tools={"web_fetch", "web_search", "tor_fetch", "shell", "memory_save"},
    triggers=set(),
    expertise="passive footprinting only: domain/subdomain, email and employee "
              "enumeration, breach/credential-leak and public code-leak discovery, infra "
              "fingerprinting. Feeds Recon and Exploit; touch no target system directly.",
))
_add(Operator(
    name="web_operator", title="Web Operator", phase="enumeration",
    prefer_local=False,  # web enumeration over the target's public surface — cloud OK
    description="Web application attacks — content discovery, vuln scanning, exploitation.",
    tools=_WEB, triggers={"80", "443", "8080", "8000", "http", "https"},
    expertise="directory/content brute force (gobuster/ffuf), nikto/burp vuln scanning, "
              "parameter and auth testing, common web classes (injection, IDOR, SSRF, "
              "file upload, deserialization), and searchsploit on the exact stack+version.",
))
_add(Operator(
    name="exploit_operator", title="Exploit Operator", phase="exploitation",
    description="Service exploitation — match a vuln to a working exploit and land access.",
    tools=_EXPLOIT,
    expertise="correlate discovered service+version to exploits (msf_search/searchsploit), "
              "select and run the right module/PoC against the in-scope target, and confirm "
              "the resulting session/shell.",
))
_add(Operator(
    name="post_operator", title="Post-Exploit Operator", phase="post",
    description="Post-exploitation — privesc, looting, credential and flag capture.",
    tools=_POST,
    expertise="on a foothold: enumerate for privilege escalation (SUID, sudo, kernel, "
              "cron), dump and crack credentials (john), pivot, and capture flags. Linux "
              "commands once on a Linux target; Windows commands on Windows.",
))

# --- operator-level specialists -------------------------------------------- #

_add(Operator(
    name="cloud_hunter", title="Cloud Hunter", phase="exploitation",
    description="Cloud infrastructure attacks — IAM, storage exposure, k8s, metadata abuse.",
    tools={"shell", "kali_run", "web_fetch", "file_read", "create_tool"},
    expertise="IAM privilege escalation, public S3/blob/bucket exposure, Kubernetes RBAC "
              "escapes and exposed kubelets/dashboards, and cloud metadata-service (IMDS) "
              "abuse for credential theft. Use provider CLIs via shell; respect scope.",
))
_add(Operator(
    name="contract_auditor", title="Contract Auditor", phase="exploitation",
    model_role="planner",  # deep reasoning over source
    description="Solidity / EVM smart-contract audits.",
    tools={"shell", "file_read", "file_write", "web_fetch", "create_tool"},
    expertise="Solidity/EVM review for reentrancy, oracle manipulation, flash-loan abuse, "
              "and broken access control; run slither/mythril-style analysis through shell "
              "and reason over the source.",
))
_add(Operator(
    name="reverser", title="Reverser", phase="analysis",
    model_role="planner",  # reasoning over binaries
    description="Binary analysis and reverse engineering.",
    tools={"shell", "kali_run", "file_read", "file_list", "create_tool"},
    expertise="ELF/PE/Mach-O triage, packer detection, ROP gadget inventories, and "
              "Ghidra/radare2 static recon driven through shell/kali_run; surface "
              "exploitable primitives.",
))
_add(Operator(
    name="analyst", title="Analyst", phase="analysis",
    prefer_local=False,  # reasoning over already-collected findings — cloud OK
    model_role="planner",  # vuln research / exploit-chain construction
    description="Vuln research & reporting — code review, SAST, dependency CVE sweeps.",
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
    tools={"shell", "kali_run", "file_read", "create_tool"},
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
    description="IoT / embedded device attacks — firmware, hardcoded creds, radios.",
    tools={"shell", "kali_run", "searchsploit", "file_read", "create_tool"},
    triggers={"1900", "5683", "8883", "upnp", "mqtt", "coap"},
    expertise="firmware acquisition + binwalk extraction, hardcoded credentials, "
              "U-Boot / /dev/mem access, and BLE/Zigbee/Z-Wave/sub-GHz/LoRaWAN radio work "
              "(radios need hardware passthrough or an SSH dropbox).",
))
_add(Operator(
    name="ics_operator", title="ICS Operator", phase="enumeration", roe_gated=True,
    read_only=True,
    description="ICS / OT / SCADA attacks (Modbus, DNP3, S7comm, BACnet, OPC-UA).",
    tools={"shell", "kali_run", "web_fetch", "create_tool"},
    triggers={"502", "20000", "102", "44818", "47808", "modbus", "s7", "bacnet", "dnp3"},
    expertise="Modbus/DNP3/S7comm/BACnet/OPC-UA enumeration. OT is fragile: read-only "
              "enumeration first, and writes only against an explicit in-scope lab/canary — "
              "never a production controller.",
))
_add(Operator(
    name="forensicator", title="Forensicator", phase="analysis", read_only=True,
    model_role="planner",  # timeline/IOC analysis + detection mapping
    description="DFIR / purple-team validation — timelines, IOCs, attack→detection mapping.",
    tools={"shell", "kali_run", "file_read", "file_list", "file_search"},
    expertise="disk/memory/log/network timeline analysis, IOC extraction, and mapping the "
              "engagement's actions to the detections they should have triggered — the "
              "purple-team validation pass.",
))
_add(Operator(
    name="supply_chain_operator", title="Supply Chain Operator", phase="exploitation",
    model_role="planner",  # dependency/pipeline analysis
    description="Supply-chain attacks — dependencies, build pipelines, package integrity.",
    tools={"shell", "kali_run", "file_read", "web_search", "create_tool"},
    expertise="dependency confusion / typosquatting, compromised or malicious packages, "
              "CI/CD pipeline and build-artifact integrity, and signing/provenance gaps "
              "across the software supply chain.",
))


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
    specialist once recon reveals what's listening — e.g. port 80 → web_operator,
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
