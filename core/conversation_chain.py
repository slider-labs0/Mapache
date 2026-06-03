"""
conversation_chain.py — Mapache conversation chain manager

Fixes the three root causes of broken conversation continuity:

1. Turn summarization — compresses tool outputs so context stays clean
2. Goal tracking — remembers the overall objective across turns
3. Attack state — tracks what was found and what phase we're in
"""

from __future__ import annotations

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
}

PHASE_TOOLS = {
    "recon": {"nmap_scan", "web_fetch", "web_search"},
    "enumeration": {
        "nmap_scan", "web_fetch", "web_search",
        "kali_list", "kali_run", "searchsploit", "tor_fetch",
    },
    "exploitation": {
        "msf_search", "msf_run", "msf_sessions", "searchsploit",
        "kali_run", "burp_scan", "burp_proxy", "john_crack", "john_identify",
    },
    "post": {
        "msf_sessions", "kali_run", "john_crack", "john_identify",
    },
    "reporting": {
        "memory_note_create", "memory_note_search", "memory_note_list",
        "moltbook_post", "moltbook_feed", "moltbook_comment",
    },
}

# Open-port → additional tools that become useful once a service is seen.
PORT_TOOLS = {
    "80":   {"kali_run", "web_fetch", "web_search", "burp_scan", "burp_proxy"},
    "443":  {"kali_run", "web_fetch", "web_search", "burp_scan", "burp_proxy"},
    "8080": {"kali_run", "web_fetch", "web_search", "burp_scan", "burp_proxy"},
    "8000": {"kali_run", "web_fetch", "web_search", "burp_scan", "burp_proxy"},
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
    vulnerabilities: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    current_phase: str = "recon"
    notes: list[str] = field(default_factory=list)

    def update_from_nmap(self, nmap_output: str) -> None:
        port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)")
        for match in port_pattern.finditer(nmap_output):
            port, proto, service = match.groups()
            port_str = f"{port}/{proto}"
            if port_str not in self.open_ports:
                self.open_ports.append(port_str)
            self.services[port] = service

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
            if suggestions:
                return "Based on open ports: " + "; ".join(suggestions)
            return f"Enumerate discovered services on {self.target}"

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
        if not self.target and not self.open_ports:
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

    def __init__(self, max_turn_summaries: int = 10) -> None:
        self.attack_state = AttackState()
        self._turn_summaries: list[TurnSummary] = []
        self._current_turn: Optional[TurnSummary] = None
        self._current_goal: str = ""
        self._max_summaries = max_turn_summaries
        self._turn_number = 0
        self._todos: list[TodoItem] = []

    def on_turn_start(self, user_input: str) -> None:
        self._turn_number += 1

        # Extract target from input. A freshly typed IP that differs from the
        # current target overrides it — e.g. HTB reassigns the machine IP
        # mid-session, and we must not keep scanning the dead host. When the
        # target changes, stale per-target findings (ports, services, vulns)
        # are cleared and the phase resets to recon. Hostnames only set the
        # target when none exists yet, so a domain mentioned in passing can't
        # hijack the active engagement.
        target = self._extract_target(user_input)
        if target:
            is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target))
            if not self.attack_state.target:
                self.attack_state.target = target
            elif is_ip and target != self.attack_state.target:
                self.attack_state.target = target
                self.attack_state.open_ports = []
                self.attack_state.services = {}
                self.attack_state.vulnerabilities = []
                self.attack_state.current_phase = "recon"
                # New engagement — the old plan no longer applies.
                self._todos = []

        # Detect explicit rescan requests — clear cached data
        rescan_keywords = [
            "rescan", "scan again", "re-scan", "fresh scan",
            "new scan", "check again", "update scan", "perform a new",
            "do another scan", "run the scan again",
        ]
        if any(kw in user_input.lower() for kw in rescan_keywords):
            self.attack_state.open_ports = []
            self.attack_state.services = {}

        self._current_turn = TurnSummary(
            turn_number=self._turn_number,
            user_input=user_input[:200],
            tools_called=[],
            key_findings=[],
        )

        if any(kw in user_input.lower() for kw in
               ["attack", "exploit", "hack", "pwn", "root", "flag", "compromise"]):
            self._current_goal = user_input

    def on_tool_result(self, tool_name: str, output: str) -> None:
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

        elif tool_name in ("msf_run", "kali_run", "shell"):
            self.attack_state.update_from_exploit(output)
            flag_pattern = re.compile(r"[0-9a-f]{32}|HTB\{[^}]+\}", re.IGNORECASE)
            for flag in flag_pattern.findall(output):
                self.attack_state.add_flag(flag)
                self._current_turn.key_findings.append(f"FLAG FOUND: {flag}")

        elif tool_name == "msf_search":
            cves = re.findall(r"CVE-\d{4}-\d+", output)
            for cve in cves[:3]:
                self.attack_state.add_vulnerability(cve)

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
        wanted |= PHASE_TOOLS.get(self.attack_state.current_phase, set())

        for port in self.attack_state.open_ports:
            number = port.split("/")[0]
            wanted |= PORT_TOOLS.get(number, set())

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
