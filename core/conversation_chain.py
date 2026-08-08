"""
conversation_chain.py — Mapache conversation chain manager

Fixes the three root causes of broken conversation continuity:

1. Turn summarization — compresses tool outputs so context stays clean
2. Goal tracking — remembers the overall objective across turns
3. Attack state — tracks what was found and what phase we're in
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


PHASES = ["recon", "enumeration", "exploitation", "post", "reporting"]

# ---------------------------------------------------------------------------
# Phase-based tool subsetting
#
# Exposing all ~33 tool schemas on every model call overflows the function-
# calling payload of local models (the Ollama XML error). Instead we expose a
# small, phase-appropriate subset. CORE_TOOLS are always available; PHASE_TOOLS
# are added based on the current attack phase; open ports pull in extra tools.
#
# Names that are not actually registered are filtered out downstream, so a
# slight mismatch here is harmless.
# ---------------------------------------------------------------------------

CORE_TOOLS = {
    "shell",
    "file_read", "file_write", "file_edit", "file_list", "file_search",
    "memory_recall", "memory_save", "memory_target_store", "memory_target_get",
    # Built-in sub-agent delegation tools — always available when registered.
    "delegate", "delegate_parallel",
    # Self-authored tool meta-tools — always available so the agent can author,
    # inspect, and retire its own tools regardless of attack phase.
    "create_tool", "tool_list_generated", "tool_delete",
    # Skill synthesis (feature N) — save a proven chain as a reusable skill.
    "synthesize_skill",
    # CVE grounding (feature M) — correlate services to CVEs any phase.
    "cve_lookup",
    # Agent-maintained user profile (feature F) — record durable user facts.
    "user_remember",
    # Community skill hub (feature I) — browse + install downloadable skills,
    # and install a GitHub repo as a tool straight from a natural-language request.
    "skill_search", "skill_list", "skill_install", "install_github_tool",
    # Shared findings store — query/record findings across objectives + sub-agents.
    "kg_query", "kg_add",
    # Evidence-first engagement report — record a confirmed finding (the deliverable).
    "report_finding",
    # Offensive knowledge: look up real payloads instead of inventing; scan for secrets.
    "search_payloads", "secret_scan",
    # Operation plan (OPPLAN) — objectives + status transitions for the orchestrator.
    "opplan_add", "opplan_update", "opplan_show",
    # Vulnerability-research pipeline seeder (scanner→detector→verifier→patcher→exploiter).
    "vuln_research",
}

PHASE_TOOLS = {
    "recon": {"nmap_scan", "web_fetch", "http_request", "http_repeater", "web_search",
              "tech_detect"},
    "enumeration": {
        "nmap_scan", "web_fetch", "http_request", "http_repeater", "web_search",
        "kali_list", "kali_run", "searchsploit", "tor_fetch",
        "tech_detect", "graphql", "jwt_tool",
    },
    "exploitation": {
        "msf_search", "msf_run", "msf_sessions", "searchsploit",
        "kali_run", "web_fetch", "http_request", "http_repeater",
        "burp_scan", "burp_proxy", "john_crack", "john_identify",
        "jwt_tool", "graphql", "cloud_metadata", "llm_inject",
        "ad_attack", "binary_analyze",
    },
    "post": {
        "msf_sessions", "kali_run", "john_crack", "john_identify", "ad_attack",
    },
    "reporting": {
        "memory_note_create", "memory_note_search", "memory_note_list",
        "moltbook_post", "moltbook_feed", "moltbook_comment",
    },
}

# Open-port → additional tools that become useful once a service is seen.
PORT_TOOLS = {
    "80":   {"kali_run", "web_fetch", "http_request", "http_repeater", "web_search", "burp_scan", "burp_proxy", "tech_detect", "jwt_tool", "graphql"},
    "443":  {"kali_run", "web_fetch", "http_request", "http_repeater", "web_search", "burp_scan", "burp_proxy", "tech_detect", "jwt_tool", "graphql"},
    "8080": {"kali_run", "web_fetch", "http_request", "http_repeater", "web_search", "burp_scan", "burp_proxy", "tech_detect", "jwt_tool", "graphql"},
    "8000": {"kali_run", "web_fetch", "http_request", "http_repeater", "web_search", "burp_scan", "burp_proxy", "tech_detect", "jwt_tool", "graphql"},
    "445":  {"msf_search", "msf_run", "kali_run"},
    "139":  {"msf_search", "msf_run", "kali_run"},
    "3389": {"msf_search", "msf_run", "kali_run"},
}


@dataclass
class TurnSummary:
    turn_number: int
    user_input: str
    tools_called: list[str]
    key_findings: list[str]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


TODO_STATUSES = ("pending", "in_progress", "completed")


@dataclass
class TodoItem:
    """A single item on the agent's persistent task list."""

    task: str
    status: str = "pending"  # pending | in_progress | completed

    def marker(self) -> str:
        return {
            "completed": "[x]",
            "in_progress": "[~]",
            "pending": "[ ]",
        }.get(self.status, "[ ]")


@dataclass
class AttackState:
    target: Optional[str] = None
    open_ports: list[str] = field(default_factory=list)
    services: dict[str, str] = field(default_factory=dict)
    # port → full version banner (service + version), captured for CVE grounding
    # (feature M). Kept separate from `services` so trigger/operator matching on
    # the bare service name is unaffected.
    versions: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    current_phase: str = "recon"
    notes: list[str] = field(default_factory=list)
    # Distinct web-surface keys discovered (normalized `path?param-names`). This is a
    # PROGRESS signal for the multi-agent supervisor: surface/parameter *discovery*
    # advances the routing signature (so an operator mid-enumeration isn't benched as
    # "stalled"), while value brute-forcing over one param collapses to a single key
    # and correctly reads as no-progress. Capped so the blackboard stays bounded.
    endpoints: list[str] = field(default_factory=list)
    # HTML forms discovered in responses, as human-readable descriptors
    # ("POST /login [fields: username, password]"). Surfaced in the state block so the
    # agent submits the REAL form action/fields instead of inventing an endpoint like
    # /login — the concrete gap that sank the IDOR trading-platform benchmark.
    forms: list[str] = field(default_factory=list)
    # Path templates that returned an IDENTICAL response body across several DISTINCT
    # requests (e.g. ?id=1,2,3 all yielding the same page) — a dead vector the agent
    # should stop fuzzing. A WORKING IDOR yields DIFFERENT bodies per id, so it is never
    # flagged here. Surfaced in the state block as a hard "switch approach" steer.
    dead_vectors: list[str] = field(default_factory=list)

    def record_dead_vector(self, key: str) -> bool:
        if key and key not in self.dead_vectors and len(self.dead_vectors) < 32:
            self.dead_vectors.append(key)
            return True
        return False

    # Credentials DISCLOSED in page content (HTML comments, JS, "password is …"), e.g.
    # a `test:test` left in a comment. Surfaced as a directive to try them on the login
    # form FIRST — the agent had these in context but submitted `admin`/no-password.
    disclosed_creds: list[str] = field(default_factory=list)

    def record_disclosed_creds(self, items) -> int:
        added = 0
        for c in items:
            if c and c not in self.disclosed_creds and len(self.disclosed_creds) < 12:
                self.disclosed_creds.append(c)
                added += 1
        return added

    def record_endpoints(self, keys) -> int:
        """Add distinct normalized endpoint keys; return how many were NEW."""
        added = 0
        for k in keys:
            if not k or k in self.endpoints:
                continue
            if len(self.endpoints) >= 512:
                break
            self.endpoints.append(k)
            added += 1
        return added

    def record_forms(self, descriptors) -> int:
        """Add distinct form descriptors; return how many were NEW."""
        added = 0
        for d in descriptors:
            if not d or d in self.forms:
                continue
            if len(self.forms) >= 24:
                break
            self.forms.append(d)
            added += 1
        return added

    def update_from_nmap(self, nmap_output: str) -> None:
        port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?")
        for match in port_pattern.finditer(nmap_output):
            port, proto, service, banner = match.groups()
            port_str = f"{port}/{proto}"
            if port_str not in self.open_ports:
                self.open_ports.append(port_str)
            self.services[port] = service
            # Capture the version banner (nmap -sV) so CVE grounding (feature M)
            # can match on version, not just service name.
            banner = (banner or "").strip()
            if banner:
                self.versions[port] = banner

        if not self.target:
            target_match = re.search(r"Nmap scan report for (.+)", nmap_output)
            if target_match:
                self.target = target_match.group(1).strip()

        if self.open_ports and self.current_phase == "recon":
            self.current_phase = "enumeration"

    def update_from_exploit(self, output: str) -> None:
        if any(kw in output.lower() for kw in
               ["session", "meterpreter", "shell", "opened"]):
            if self.current_phase in ("recon", "enumeration", "exploitation"):
                self.current_phase = "post"

    def add_flag(self, flag: str) -> None:
        flag = flag.strip()
        if flag and flag not in self.flags:
            self.flags.append(flag)

    def add_credential(self, cred: str) -> None:
        if cred and cred not in self.credentials:
            self.credentials.append(cred)

    def add_vulnerability(self, vuln: str) -> None:
        if vuln and vuln not in self.vulnerabilities:
            self.vulnerabilities.append(vuln)

    def suggest_next_step(self) -> str:
        if not self.target:
            return "No target set. Ask the user for a target IP or hostname."

        if not self.open_ports:
            return f"Run nmap_scan on {self.target} to discover open ports and services."

        if self.current_phase == "enumeration":
            suggestions = []
            ports = [p.split("/")[0] for p in self.open_ports]
            if "80" in ports or "443" in ports or "8080" in ports:
                suggestions.append("web server found — run gobuster for directories and nikto for vulns")
            if "445" in ports or "139" in ports:
                suggestions.append("SMB found — check for EternalBlue with msf_search(query='ms17-010')")
            if "21" in ports:
                suggestions.append("FTP found — check anonymous login")
            if "22" in ports:
                suggestions.append("SSH found — check for weak credentials")
            if "23" in ports:
                suggestions.append("Telnet found — try connecting with no password")
            if "3306" in ports:
                suggestions.append("MySQL found — try default credentials")
            if "6379" in ports:
                suggestions.append("Redis found — often unauthenticated")
            # CVE grounding (feature M): correlate discovered versions to known
            # CVEs and lead with the highest-priority one when present.
            from .cve_grounding import ground_services
            grounded = ground_services(self.services, self.versions)
            cve_note = ""
            if grounded:
                top = grounded[:3]
                cve_note = (". Grounded CVEs (prioritized): " + "; ".join(
                    f"{m.entry.id} [{m.entry.severity}/{m.confidence}] on {m.service}"
                    for m in top)
                    + " — run cve_lookup for the full plan")
            if suggestions:
                base = "Based on open ports: " + "; ".join(suggestions)
                from .operators import suggest_operators
                ops = suggest_operators(self.open_ports, self.services)
                if ops:
                    base += (f". Specialists available — delegate with operator=: "
                             f"{', '.join(ops)}")
                return base + cve_note
            return f"Enumerate discovered services on {self.target}" + cve_note

        if self.current_phase == "exploitation":
            if self.vulnerabilities:
                return f"Exploit found vulnerabilities: {', '.join(self.vulnerabilities[:3])}"
            return "Search for exploits matching discovered service versions"

        if self.current_phase == "post":
            if not self.flags:
                return "Search for flags: find / -name user.txt 2>/dev/null and find / -name root.txt 2>/dev/null"
            return "Escalate privileges if not root, then capture remaining flags"

        return "Continue the attack"

    def to_prompt_block(self) -> str:
        if not (self.target or self.open_ports or self.endpoints or self.forms
                or self.dead_vectors or self.disclosed_creds):
            return ""

        lines = ["=== CURRENT ATTACK STATE ==="]

        if self.target:
            lines.append(f"Target: {self.target}")

        lines.append(f"Phase: {self.current_phase.upper()}")

        if self.open_ports:
            lines.append(f"Open ports: {', '.join(self.open_ports[:20])}")

        if self.services:
            svc_list = ", ".join(f"{p}={s}" for p, s in list(self.services.items())[:10])
            lines.append(f"Services: {svc_list}")

        if self.vulnerabilities:
            lines.append(f"Vulnerabilities: {', '.join(self.vulnerabilities[:5])}")

        if self.credentials:
            lines.append(f"Credentials: {', '.join(self.credentials[:5])}")

        if self.flags:
            lines.append(f"Flags captured: {', '.join(self.flags)}")

        if self.disclosed_creds:
            lines.append("DISCLOSED credentials found in page content (a `user:pass` "
                         "token or labeled value — TRY THESE on the login form FIRST, "
                         "submitting ALL of the form's fields): "
                         + ", ".join(self.disclosed_creds[:8]))

        if self.forms:
            lines.append("Discovered forms (submit the REAL method/action/fields — do "
                         "NOT invent an endpoint like /login; an action of '(self)' "
                         "means POST back to the URL you fetched):")
            for f in self.forms[:6]:
                lines.append(f"  - {f}")

        if self.endpoints:
            lines.append("Discovered endpoints (use these real paths — do not guess "
                         f"/dashboard etc.): {', '.join(self.endpoints[:15])}")

        if self.dead_vectors:
            lines.append("DEAD vectors (identical response for every value tried — STOP "
                         f"fuzzing these, switch approach): {', '.join(self.dead_vectors[:8])}")

        lines.append(f"Next step: {self.suggest_next_step()}")
        lines.append("=== END ATTACK STATE ===")

        return "\n".join(lines)


def summarize_tool_output(tool_name: str, output: str, max_length: int = 500) -> str:
    if len(output) <= max_length:
        return output

    lines = output.splitlines()

    if tool_name == "nmap_scan":
        important = []
        for line in lines:
            if any(kw in line for kw in [
                "open", "Nmap scan report", "Nmap done",
                "OS details", "Service Info", "SUMMARY"
            ]):
                important.append(line)
        if important:
            result = "\n".join(important[:30])
            if len(result) < max_length:
                return result

    elif tool_name in ("web_fetch", "web_search"):
        return output[:max_length] + "\n[... truncated for context efficiency]"

    elif tool_name in ("kali_run", "shell"):
        last_lines = lines[-30:]
        result = "\n".join(last_lines)
        if len(result) <= max_length:
            return result
        return result[:max_length] + "\n[... truncated]"

    first = "\n".join(lines[:10])
    last = "\n".join(lines[-10:])
    return f"{first}\n[...]\n{last}"


class ConversationChain:
    """
    Manages conversation continuity across multiple turns.

    Wire into agent controller:
        chain = ConversationChain()
        chain.on_turn_start(user_input)
        chain.on_tool_result(tool_name, output)
        chain.on_turn_end(response)

    Inject into system prompt each turn:
        extra_context = chain.get_context_injection()
    """

    def __init__(
        self,
        max_turn_summaries: int = 10,
        shared_state: Optional[AttackState] = None,
        allow_state_reset: bool = True,
    ) -> None:
        # Multi-agent blackboard (feature P): when an operator sub-agent is given
        # the lead's AttackState here, both reference the SAME object, so a
        # finding one records is immediately visible to the lead and siblings —
        # no copy-down / merge-back. `allow_state_reset` is False for sub-agents
        # so their task text can't reassign the engagement target or clear the
        # shared findings (only the lead, taking operator input, may do that).
        self.attack_state = shared_state if shared_state is not None else AttackState()
        self._allow_state_reset = allow_state_reset
        self._turn_summaries: list[TurnSummary] = []
        self._current_turn: Optional[TurnSummary] = None
        self._current_goal: str = ""
        self._max_summaries = max_turn_summaries
        self._turn_number = 0
        self._todos: list[TodoItem] = []
        # Tool names to always expose regardless of attack phase (e.g. MCP
        # tools, which don't belong to any phase but must stay callable).
        self.always_tools: set[str] = set()
        # Self-authored (generated) tools mapped to the phase they're exposed in
        # ("always" = every phase). Phase-tagging keeps the function-calling
        # payload small as the generated-tool library grows. Survives target
        # changes (these tools are not target-specific).
        self.generated_tools: dict[str, str] = {}

    def apply_input_signals(self, user_input: str) -> None:
        """
        Update attack state from a piece of operator input.

        Shared by `on_turn_start` and mid-run steering so a freshly typed
        target or a rescan request takes effect either way, without disturbing
        per-turn bookkeeping (turn counter, current-turn accumulator).

        A freshly typed IP that differs from the current target overrides it —
        e.g. HTB reassigns the machine IP mid-session, and we must not keep
        scanning the dead host. When the target changes, stale per-target
        findings (ports, services, vulns) are cleared and the phase resets to
        recon. Hostnames only set the target when none exists yet, so a domain
        mentioned in passing can't hijack the active engagement.
        """
        target = self._extract_target(user_input)
        if target:
            is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target))
            if not self.attack_state.target:
                self.attack_state.target = target
            elif self._allow_state_reset and is_ip and target != self.attack_state.target:
                self.attack_state.target = target
                self.attack_state.open_ports = []
                self.attack_state.services = {}
                self.attack_state.versions = {}
                self.attack_state.vulnerabilities = []
                self.attack_state.current_phase = "recon"
                # New engagement — the old plan no longer applies.
                self._todos = []

        # Detect explicit rescan requests — clear cached data. Lead-only: a
        # sub-agent must not wipe the shared blackboard from its task wording.
        rescan_keywords = [
            "rescan", "scan again", "re-scan", "fresh scan",
            "new scan", "check again", "update scan", "perform a new",
            "do another scan", "run the scan again",
        ]
        if self._allow_state_reset and any(kw in user_input.lower() for kw in rescan_keywords):
            self.attack_state.open_ports = []
            self.attack_state.services = {}
            self.attack_state.versions = {}

    def on_turn_start(self, user_input: str) -> None:
        self._turn_number += 1

        self.apply_input_signals(user_input)

        self._current_turn = TurnSummary(
            turn_number=self._turn_number,
            user_input=user_input[:200],
            tools_called=[],
            key_findings=[],
        )

        if any(kw in user_input.lower() for kw in
               ["attack", "exploit", "hack", "pwn", "root", "flag", "compromise"]):
            self._current_goal = user_input

    def on_tool_result(self, tool_name: str, output: str, args=None) -> None:
        if not self._current_turn:
            return

        self._current_turn.tools_called.append(tool_name)

        if tool_name == "nmap_scan":
            self.attack_state.update_from_nmap(output)
            if self.attack_state.open_ports:
                self._current_turn.key_findings.append(
                    f"Found {len(self.attack_state.open_ports)} open ports: "
                    f"{', '.join(self.attack_state.open_ports[:5])}"
                )
            # CVE grounding (feature M): record version-confirmed CVEs as
            # vulnerabilities so the exploitation phase + report (L) act on them.
            from .cve_grounding import ground_services
            for m in ground_services(self.attack_state.services,
                                     self.attack_state.versions):
                if m.version_confirmed:
                    self.attack_state.add_vulnerability(m.entry.id)
                    self._current_turn.key_findings.append(
                        f"CVE grounded: {m.entry.id} ({m.entry.severity}) on {m.service}")

        elif tool_name in ("msf_run", "kali_run", "shell"):
            self.attack_state.update_from_exploit(output)
            # Exec output may carry a raw 32-hex flag file (user.txt/root.txt).
            self._scan_for_flags(output, hex32=True)
            # shell is the agent's main curl runner — mine page bodies for surface.
            self.attack_state.record_endpoints(self._endpoint_keys(output))
            self.attack_state.record_forms(self._extract_forms(output))
            self.attack_state.record_disclosed_creds(self._extract_creds(output))
            self._detect_dead_vector(tool_name, args, output)

        elif tool_name in ("web_fetch", "http_request", "curl"):
            # Web-recon flags surface in page bodies too (CTF chains end at a flag
            # endpoint). Match only explicit flag formats — a bare 32-hex string in
            # HTML is usually an asset/session hash, not a flag.
            self._scan_for_flags(output, hex32=False)
            self.attack_state.record_endpoints(self._endpoint_keys(output))
            self.attack_state.record_forms(self._extract_forms(output))
            self.attack_state.record_disclosed_creds(self._extract_creds(output))
            self._detect_dead_vector(tool_name, args, output)

        elif tool_name == "msf_search":
            cves = re.findall(r"CVE-\d{4}-\d+", output)
            for cve in cves[:3]:
                self.attack_state.add_vulnerability(cve)

    # Flag formats common to CTF/HTB labs; the wrapped-brace forms are safe to
    # match in arbitrary web content, the bare 32-hex form is not.
    _FLAG_BRACE_RE = re.compile(r"(?:HTB|FLAG|CTF|flag)\{[^}]+\}", re.IGNORECASE)
    _FLAG_HEX32_RE = re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE)
    # A bare 32-hex on an HTTP-header/key-value line is an ETag, session hash, or
    # request id — NOT a flag. `shell` is now the agent's main curl/aws runner, so
    # header lines routinely reach the hex32 path (a curl `-D -` dump of an S3
    # object surfaced its ETag as a "flag" and falsely ended a live engagement).
    # A real user.txt/root.txt prints the hash as a plain value, not a `Key: …` line.
    _HTTP_HEADERISH_RE = re.compile(
        r"(^[<>]?\s*[A-Za-z][A-Za-z0-9-]*:\s)|etag|x-amz-|www-authenticate|http/\d",
        re.IGNORECASE)

    def _scan_for_flags(self, output: str, *, hex32: bool) -> None:
        if not output:
            return
        matches = list(self._FLAG_BRACE_RE.findall(output))
        if hex32:
            for line in output.splitlines():
                for hx in self._FLAG_HEX32_RE.findall(line):
                    if not self._HTTP_HEADERISH_RE.search(line):
                        matches.append(hx)
        for flag in matches:
            if flag not in self.attack_state.flags:
                self.attack_state.add_flag(flag)
                if self._current_turn:
                    self._current_turn.key_findings.append(f"FLAG FOUND: {flag}")

    # Web-surface extraction for the supervisor's progress signal. Full URLs and
    # href/src/action paths in a tool's output are the endpoints the agent has
    # surfaced; normalizing query VALUES away (keeping param NAMES) means param
    # discovery counts as progress while `id=1,2,3…` value iteration collapses to one.
    _URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
    _PATH_ATTR_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']?(/[^\s"'<>)\]]*)""",
                               re.IGNORECASE)

    @staticmethod
    def _norm_endpoint(pathq: str) -> str:
        """Normalize a path+query to a template key: keep param NAMES, drop VALUES, so
        surface/param discovery counts but value iteration (?id=1,2,3) collapses to one."""
        pathq = (pathq or "").strip()
        if "?" not in pathq:
            return pathq or "/"
        path, q = pathq.split("?", 1)
        names = sorted({kv.split("=", 1)[0] for kv in q.split("&") if kv})
        return (path or "/") + ("?" + ",".join(names) if names else "")

    @classmethod
    def _endpoint_keys(cls, output: str) -> list[str]:
        if not output:
            return []
        keys: list[str] = []
        for u in cls._URL_RE.findall(output)[:200]:
            keys.append(cls._norm_endpoint(re.sub(r"^https?://[^/]+", "", u) or "/"))
        for p in cls._PATH_ATTR_RE.findall(output)[:200]:
            keys.append(cls._norm_endpoint(p))
        return keys

    @classmethod
    def _request_url(cls, tool_name: str, args, output: str) -> str:
        """Best-effort recovery of the URL a web tool actually requested — from its
        args (http_request/web_fetch), the curl command (shell), or the request line
        the tool echoes into its output."""
        if isinstance(args, dict):
            if args.get("url"):
                return str(args["url"])
            if args.get("cmd"):
                m = cls._URL_RE.search(str(args["cmd"]))
                if m:
                    return m.group(0)
        # Fall back to the first URL in the output's opening line (tools echo the
        # request line, e.g. "GET http://host/path Status: 200 …").
        head = (output or "")[:300]
        m = cls._URL_RE.search(head)
        return m.group(0) if m else ""

    @staticmethod
    def _response_body(output: str) -> str:
        """Isolate the response BODY from a tool's output (dropping the request/status/
        header lines) so a per-endpoint body hash ignores the varying request line."""
        if not output:
            return ""
        marker = output.find("--- Body")
        if marker != -1:
            nl = output.find("\n", marker)
            return output[nl + 1:] if nl != -1 else ""
        for sep in ("\r\n\r\n", "\n\n"):
            i = output.find(sep)
            if i != -1:
                return output[i + len(sep):]
        return output

    # Form parsing: the real method/action/field-names of every <form> in a response,
    # so the agent authenticates against what the page actually exposes rather than a
    # guessed /login. A `<form method="POST">` with no action submits to the page itself.
    _FORM_OPEN_RE = re.compile(r"<form\b([^>]*)>", re.IGNORECASE)
    _FORM_METHOD_RE = re.compile(r"""method\s*=\s*["']?(\w+)""", re.IGNORECASE)
    _FORM_ACTION_RE = re.compile(r"""action\s*=\s*["']?([^"'\s>]+)""", re.IGNORECASE)
    _INPUT_NAME_RE = re.compile(
        r"""<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']?([^"'\s>]+)""",
        re.IGNORECASE)

    @classmethod
    def _extract_forms(cls, output: str) -> list[str]:
        if not output or "<form" not in output.lower():
            return []
        low = output.lower()
        out: list[str] = []
        for m in cls._FORM_OPEN_RE.finditer(output):
            attrs = m.group(1)
            meth = cls._FORM_METHOD_RE.search(attrs)
            method = meth.group(1).upper() if meth else "GET"
            act = cls._FORM_ACTION_RE.search(attrs)
            action = act.group(1) if act and act.group(1) else "(self — submits to this page's own URL)"
            # Field names live between this <form> tag and the next </form> (bounded so
            # a truncated response body still yields the fields it did include).
            end = low.find("</form>", m.end())
            body = output[m.end():(end if end != -1 else m.end() + 2000)]
            fields: list[str] = []
            for fm in cls._INPUT_NAME_RE.finditer(body):
                if fm.group(1) not in fields:
                    fields.append(fm.group(1))
            desc = f"{method} {action}"
            desc += f" [fields: {', '.join(fields[:12])}]" if fields else " [no named fields captured]"
            out.append(desc)
        return out

    # Disclosed-credential extraction. CTF/app pages leak creds in HTML comments, JS,
    # or "password is …" text. Precision matters: a `user:pass` token is only credible
    # with NO whitespace around the colon (so "TODO: Delete" — space after colon — is
    # skipped while "(test:test)" is caught), and a small denylist rejects obvious
    # non-cred left tokens (http, todo, …).
    _COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
    _CRED_COLON_RE = re.compile(
        r"(?<![\w:/])([A-Za-z][\w.\-]{1,31}):([^\s:\"'<>(),;]{2,32})")
    _CRED_LABELED_RE = re.compile(
        r"""(?:pass(?:word|wd)?|pwd|user(?:name)?|login)\s*(?:is|=|:)\s*["'`]?"""
        r"""([^\s"'`<>,;)]{2,40})""", re.IGNORECASE)
    _CRED_DENY = {"http", "https", "ftp", "ssh", "url", "src", "href", "todo", "note",
                  "fixme", "hint", "warning", "error", "version", "charset", "width",
                  "height", "rel", "type", "id", "class", "style", "name"}

    @classmethod
    def _extract_creds(cls, output: str) -> list[str]:
        if not output:
            return []
        found: list[str] = []
        # `user:pass` tokens — trust them anywhere, but they're most common in comments.
        scopes = cls._COMMENT_RE.findall(output) or []
        scopes.append(output)  # also scan the whole body (JS strings, config dumps)
        for scope in scopes:
            for u, p in cls._CRED_COLON_RE.findall(scope):
                p = p.rstrip(".")
                if u.lower() in cls._CRED_DENY or u.isdigit() or len(p) < 2:
                    continue
                token = f"{u}:{p}"
                if token not in found:
                    found.append(token)
        # Labeled forms: "password is hunter2", user='admin'.
        for v in cls._CRED_LABELED_RE.findall(output):
            v = v.strip().rstrip(".,;")
            if v and v.lower() not in cls._CRED_DENY and f"(labeled) {v}" not in found:
                found.append(f"(labeled) {v}")
        return found[:12]

    # No-op / dead-vector detection: N DISTINCT requests to the same path template that
    # all return the IDENTICAL body = the vector is dead (the param is ignored). A real
    # IDOR returns DIFFERENT bodies per id, so it's never flagged. `_vector_probe` maps a
    # path template → {distinct full URLs seen, distinct body hashes seen}.
    DEAD_VECTOR_MIN = 3

    def _detect_dead_vector(self, tool_name: str, args, output: str) -> None:
        url = self._request_url(tool_name, args, output)
        if not url:
            return
        pathq = re.sub(r"^https?://[^/]+", "", url) or "/"
        if "?" not in pathq:
            return  # only value-fuzzing of a parameter can be a "same response" no-op
        key = self._norm_endpoint(pathq)
        probe = getattr(self, "_vector_probe", None)
        if probe is None:
            probe = self._vector_probe = {}
        rec = probe.setdefault(key, {"urls": set(), "bodies": set()})
        rec["urls"].add(pathq)
        body = self._response_body(output)
        rec["bodies"].add(hashlib.md5(body.strip().encode("utf-8", "replace")).hexdigest())
        if len(rec["urls"]) >= self.DEAD_VECTOR_MIN and len(rec["bodies"]) == 1:
            if self.attack_state.record_dead_vector(key) and self._current_turn:
                self._current_turn.key_findings.append(
                    f"DEAD VECTOR: {key} — identical response for "
                    f"{len(rec['urls'])} distinct values; switch approach")

    def on_turn_end(self, response: str) -> None:
        if not self._current_turn:
            return

        cred_pattern = re.compile(
            r"(?:password|credential|login)[:\s]+([^\s,\n]+:[^\s,\n]+)",
            re.IGNORECASE
        )
        for cred in cred_pattern.findall(response):
            self.attack_state.add_credential(cred)

        self._turn_summaries.append(self._current_turn)
        if len(self._turn_summaries) > self._max_summaries:
            self._turn_summaries = self._turn_summaries[-self._max_summaries:]

        self._current_turn = None

    # ------------------------------------------------------------------ #
    # Persistent TODO list
    #
    # Gives the agent long-horizon coherence: the plan survives across many
    # tool calls instead of being re-derived (or lost) each turn. The model
    # owns the list — it seeds it via a `plan` response and revises it by
    # re-emitting one with per-item status (the TodoWrite pattern). Completed
    # items are preserved across re-emits so a model that restates only the
    # remaining work does not lose progress.
    # ------------------------------------------------------------------ #

    def set_todos(self, items: list) -> None:
        """
        Replace the working todo list from a model-supplied plan.

        `items` may be a list of plain strings (status defaults to pending)
        or a list of dicts ``{"task": str, "status": str}``. Status from any
        previously-completed item is preserved by matching task text. Exactly
        one not-completed item ends up marked in_progress.
        """
        prev_completed = {t.task for t in self._todos if t.status == "completed"}
        new_items: list[TodoItem] = []
        for raw in items:
            if isinstance(raw, dict):
                task = str(raw.get("task") or raw.get("step") or "").strip()
                status = raw.get("status", "pending")
            else:
                task = str(raw).strip()
                status = "pending"
            if not task:
                continue
            if status not in TODO_STATUSES:
                status = "pending"
            if task in prev_completed:
                status = "completed"
            new_items.append(TodoItem(task=task, status=status))

        if not new_items:
            return

        if not any(t.status == "in_progress" for t in new_items):
            for t in new_items:
                if t.status != "completed":
                    t.status = "in_progress"
                    break

        self._todos = new_items

    def update_todo(self, ref, status: str) -> bool:
        """Mark a todo (by 1-based index or task text) with a new status."""
        if status not in TODO_STATUSES:
            return False
        item = self._resolve_todo(ref)
        if item is None:
            return False
        item.status = status
        # Keep one active item: completing the in_progress one promotes the
        # next pending item so the model always sees what to do next.
        if status == "completed" and not any(
            t.status == "in_progress" for t in self._todos
        ):
            for t in self._todos:
                if t.status == "pending":
                    t.status = "in_progress"
                    break
        return True

    def _resolve_todo(self, ref) -> Optional[TodoItem]:
        if isinstance(ref, bool):  # guard: bool is an int subclass
            return None
        if isinstance(ref, int):
            idx = ref - 1
            return self._todos[idx] if 0 <= idx < len(self._todos) else None
        ref_l = str(ref).strip().lower()
        if not ref_l:
            return None
        for t in self._todos:  # exact match first
            if t.task.lower() == ref_l:
                return t
        for t in self._todos:  # then substring
            if ref_l in t.task.lower():
                return t
        return None

    @property
    def todos(self) -> list[TodoItem]:
        return list(self._todos)

    def todos_block(self) -> str:
        if not self._todos:
            return ""
        lines = ["=== TASK LIST ==="]
        for i, t in enumerate(self._todos, 1):
            lines.append(f"{i}. {t.marker()} {t.task}")
        done = sum(1 for t in self._todos if t.status == "completed")
        lines.append(f"({done}/{len(self._todos)} complete)")
        lines.append("=== END TASK LIST ===")
        return "\n".join(lines)

    def get_context_injection(self) -> str:
        parts = []

        state_block = self.attack_state.to_prompt_block()
        if state_block:
            parts.append(state_block)

        todos_block = self.todos_block()
        if todos_block:
            parts.append(todos_block)

        if self._turn_summaries:
            parts.append("=== RECENT ACTIONS ===")
            for summary in self._turn_summaries[-5:]:
                tools = ", ".join(summary.tools_called) if summary.tools_called else "none"
                findings = "; ".join(summary.key_findings) if summary.key_findings else "no key findings"
                parts.append(
                    f"Turn {summary.turn_number}: [{tools}] → {findings}"
                )
            parts.append("=== END RECENT ACTIONS ===")

        return "\n".join(parts)

    def get_compressed_tool_output(self, tool_name: str, output: str) -> str:
        return summarize_tool_output(tool_name, output)

    def active_tool_names(self, registered: object) -> set[str]:
        """
        Compute the subset of tool names to expose for the current phase.

        Args:
            registered: iterable of tool names actually registered with the
                        agent. The returned set is intersected with this.

        Returns:
            The set of tool names to expose. Always non-empty: if the computed
            subset does not intersect the registered tools, the full set of
            registered names is returned (never leave the model tool-less).
        """
        registered_set = set(registered)

        wanted = set(CORE_TOOLS)
        wanted |= self.always_tools  # MCP / phase-agnostic tools
        wanted |= PHASE_TOOLS.get(self.attack_state.current_phase, set())

        for port in self.attack_state.open_ports:
            number = port.split("/")[0]
            wanted |= PORT_TOOLS.get(number, set())

        # Self-authored tools tagged for this phase (or "always").
        phase = self.attack_state.current_phase
        for gname, gphase in self.generated_tools.items():
            if gphase == "always" or gphase == phase:
                wanted.add(gname)

        active = wanted & registered_set
        return active or registered_set

    def _extract_target(self, text: str) -> Optional[str]:
        ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
        if ip_match:
            return ip_match.group(1)
        host_match = re.search(
            r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))\b",
            text
        )
        if host_match:
            return host_match.group(1)
        return None

    def reset(self) -> None:
        self.attack_state = AttackState()
        self._turn_summaries = []
        self._current_goal = ""
        self._turn_number = 0
        self._todos = []

    @property
    def has_active_target(self) -> bool:
        return self.attack_state.target is not None

    @property
    def current_phase(self) -> str:
        return self.attack_state.current_phase

    def summary(self) -> str:
        return (
            f"Target: {self.attack_state.target or 'none'} | "
            f"Phase: {self.attack_state.current_phase} | "
            f"Ports: {len(self.attack_state.open_ports)} | "
            f"Flags: {len(self.attack_state.flags)} | "
            f"Turns: {self._turn_number}"
        )
