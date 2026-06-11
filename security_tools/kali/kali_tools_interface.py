"""
kali_tools_interface.py — Mapache Kali Linux tools interface

Provides structured access to the full suite of Kali Linux security tools.
Rather than wrapping each tool individually, this provides a smart execution
layer that:
    - Discovers which Kali tools are installed
    - Executes tools with proper argument formatting
    - Parses and structures output for the model
    - Handles timeouts and errors gracefully

Works on:
    - Kali Linux (native)
    - Any Linux with security tools installed
    - Windows with Kali WSL installed
    - Docker containers with security tools

Covered tool categories:
    Recon:       nmap, masscan, amass, subfinder, theHarvester, shodan
    Web:         nikto, dirb, gobuster, sqlmap, wfuzz, ffuf
    Exploitation: msfconsole, searchsploit
    Password:    hashcat, hydra, medusa, crunch
    Wireless:    aircrack-ng, wifite
    Forensics:   binwalk, foremost, volatility
    Network:     wireshark, tcpdump, netcat, socat
    OSINT:       maltego, recon-ng
"""

from __future__ import annotations

import asyncio
import os
import shutil
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from core.logger import get_logger

logger = get_logger(__name__)

# Tool definitions: name → {description, common_args_example, parse_hints}
KALI_TOOLS = {
    # Recon
    "masscan": {
        "desc": "Fast port scanner (faster than nmap for large ranges)",
        "example": "masscan -p1-65535 192.168.1.0/24 --rate=1000",
        "category": "recon",
    },
    "amass": {
        "desc": "DNS enumeration and subdomain discovery",
        "example": "amass enum -d example.com",
        "category": "recon",
    },
    "subfinder": {
        "desc": "Fast passive subdomain enumeration",
        "example": "subfinder -d example.com",
        "category": "recon",
    },
    "theharvester": {
        "desc": "OSINT email and subdomain gathering",
        "example": "theHarvester -d example.com -b google",
        "category": "recon",
    },
    # Web
    "nikto": {
        "desc": "Web server vulnerability scanner",
        "example": "nikto -h https://example.com",
        "category": "web",
    },
    "gobuster": {
        "desc": "Directory and file brute-forcing",
        "example": "gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt",
        "category": "web",
    },
    "ffuf": {
        "desc": "Fast web fuzzer for directories, files, parameters",
        "example": "ffuf -w wordlist.txt -u https://example.com/FUZZ",
        "category": "web",
    },
    "sqlmap": {
        "desc": "Automated SQL injection detection and exploitation",
        "example": "sqlmap -u 'https://example.com/page?id=1' --dbs",
        "category": "web",
    },
    "wfuzz": {
        "desc": "Web application fuzzer",
        "example": "wfuzz -w wordlist.txt https://example.com/FUZZ",
        "category": "web",
    },
    # Password
    "hashcat": {
        "desc": "GPU-accelerated password hash cracking",
        "example": "hashcat -m 0 hashes.txt rockyou.txt",
        "category": "password",
    },
    "hydra": {
        "desc": "Network login brute-forcer (SSH, FTP, HTTP, etc.)",
        "example": "hydra -l admin -P rockyou.txt ssh://192.168.1.1",
        "category": "password",
    },
    "medusa": {
        "desc": "Parallel network login brute-forcer",
        "example": "medusa -h 192.168.1.1 -u admin -P rockyou.txt -M ssh",
        "category": "password",
    },
    # Network
    "netcat": {
        "desc": "Network utility — listeners, connections, file transfer",
        "example": "nc -lvnp 4444",
        "category": "network",
    },
    "tcpdump": {
        "desc": "Packet capture and analysis",
        "example": "tcpdump -i eth0 -w capture.pcap",
        "category": "network",
    },
    "socat": {
        "desc": "Advanced network relay and tunnel tool",
        "example": "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash",
        "category": "network",
    },
    # Exploitation
    "searchsploit": {
        "desc": "Search Exploit-DB for known exploits",
        "example": "searchsploit apache 2.4",
        "category": "exploitation",
    },
    # Forensics
    "binwalk": {
        "desc": "Firmware and binary file analysis",
        "example": "binwalk -e firmware.bin",
        "category": "forensics",
    },
    "strings": {
        "desc": "Extract printable strings from binary files",
        "example": "strings binary_file",
        "category": "forensics",
    },
    "file": {
        "desc": "Identify file type",
        "example": "file unknown_file",
        "category": "forensics",
    },
    # OSINT
    "whois": {
        "desc": "Domain/IP registration lookup",
        "example": "whois example.com",
        "category": "osint",
    },
    "dig": {
        "desc": "DNS lookup tool",
        "example": "dig example.com ANY",
        "category": "osint",
    },
    "dnsenum": {
        "desc": "DNS enumeration — zone transfers, subdomains",
        "example": "dnsenum example.com",
        "category": "osint",
    },
}


class KaliToolListTool(BaseTool):
    name = "kali_list"
    description = (
        "List all available Kali/security tools that are installed and ready to use. "
        "Shows which tools are available on this system by category."
    )
    parameters = {
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "enum": ["all", "recon", "web", "password", "network", "exploitation", "forensics", "osint"],
                "description": "Filter by category",
                "default": "all",
            },
        },
        "required": [],
    }
    permissions = {Permission.SHELL}
    tags = ["kali", "security", "tools"]

    async def execute(self, category: str = "all", **kwargs: Any) -> ToolResult:
        available = []
        unavailable = []

        for tool_name, info in KALI_TOOLS.items():
            if category != "all" and info["category"] != category:
                continue

            # Check if installed
            found = shutil.which(tool_name) or shutil.which(tool_name.lower())
            if found:
                available.append((tool_name, info["desc"], info["category"], found))
            else:
                unavailable.append((tool_name, info["desc"], info["category"]))

        lines = []

        if available:
            lines.append(f"Installed tools ({len(available)}):\n")
            current_cat = None
            for name, desc, cat, path in sorted(available, key=lambda x: x[2]):
                if cat != current_cat:
                    lines.append(f"  [{cat.upper()}]")
                    current_cat = cat
                lines.append(f"    {name:20s} — {desc}")
        else:
            lines.append("No security tools found installed.")

        if unavailable:
            lines.append(f"\nNot installed ({len(unavailable)}):")
            for name, desc, cat in unavailable[:10]:
                lines.append(f"  {name:20s} — {desc}")
            if len(unavailable) > 10:
                lines.append(f"  ... and {len(unavailable) - 10} more")

        if not available and not unavailable:
            lines.append(f"No tools in category: {category}")

        return ToolResult.ok("\n".join(lines))


class KaliRunTool(BaseTool):
    name = "kali_run"
    description = (
        "Run any Kali Linux / security tool with custom arguments. "
        "Use this for tools not covered by dedicated Mapache tools. "
        "Returns full output. Supports all installed command-line security tools. "
        "Examples: nikto, gobuster, ffuf, sqlmap, hydra, hashcat, amass, etc."
    )
    parameters = {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "description": "Tool name (e.g. 'nikto', 'gobuster', 'hydra', 'sqlmap')",
            },
            "args": {
                "type": "string",
                "description": "Arguments to pass to the tool (e.g. '-h https://example.com -p 80')",
            },
            "timeout": {
                "type": "integer",
                "description": "Max seconds to run (default: 60)",
                "default": 60,
            },
            "working_dir": {
                "type": "string",
                "description": "Working directory to run the tool from",
                "default": "",
            },
        },
        "required": ["tool", "args"],
    }
    permissions = {Permission.SHELL, Permission.NETWORK, Permission.DANGEROUS}
    timeout = 300
    tags = ["kali", "security", "execution"]

    MAX_OUTPUT = 10_000

    async def execute(
        self,
        tool: str,
        args: str,
        timeout: int = 60,
        working_dir: str = "",
        **kwargs: Any,
    ) -> ToolResult:
        # Find the tool
        tool_path = shutil.which(tool)
        if not tool_path:
            # Check if it's in KALI_TOOLS for helpful message
            if tool in KALI_TOOLS:
                info = KALI_TOOLS[tool]
                return ToolResult.fail(
                    f"'{tool}' is not installed.\n"
                    f"Install on Kali: sudo apt install {tool}\n"
                    f"Example usage: {info['example']}"
                )
            return ToolResult.fail(
                f"Tool '{tool}' not found in PATH.\n"
                "Use kali_list to see available tools."
            )

        # Build full command. Quote the resolved path — on Windows shutil.which
        # often returns a path with spaces (e.g. C:\Program Files (x86)\Nmap\
        # nmap.EXE), which create_subprocess_shell would split at the space
        # ("'C:\Program' is not recognized"). Double quotes are honored by both
        # cmd.exe and /bin/sh.
        full_cmd = f'"{tool_path}" {args}'
        cwd = working_dir if working_dir and os.path.isdir(working_dir) else None

        logger.info("Kali run: %s", full_cmd[:100])

        try:
            proc = await asyncio.create_subprocess_shell(
                full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=cwd,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(timeout),
                )
                timed_out = False
            except asyncio.TimeoutError:
                proc.kill()
                stdout = b""
                timed_out = True

            output = stdout.decode("utf-8", errors="replace")

            if len(output) > self.MAX_OUTPUT:
                output = output[:self.MAX_OUTPUT] + "\n[... output truncated]"

            header = f"{tool} {args[:60]}\n"
            if timed_out:
                header += f"[Timed out after {timeout}s — partial output below]\n"
            header += f"Exit code: {proc.returncode}\n\n"

            return ToolResult.ok(
                header + output,
                metadata={
                    "tool": tool,
                    "exit_code": proc.returncode,
                    "timed_out": timed_out,
                },
            )

        except FileNotFoundError:
            return ToolResult.fail(f"Tool not found: {tool}")
        except Exception as exc:
            return ToolResult.fail(f"Execution error: {exc}")


class SearchsploitTool(BaseTool):
    name = "searchsploit"
    description = (
        "Search Exploit-DB for public exploits matching a service, software, or CVE. "
        "Returns exploit titles, paths, and types. "
        "Use after identifying software versions to find known exploits."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query — software name, version, CVE (e.g. 'apache 2.4', 'CVE-2021-44228')",
            },
            "exploit_type": {
                "type": "string",
                "enum": ["any", "remote", "local", "webapps", "dos"],
                "description": "Filter by exploit type",
                "default": "any",
            },
        },
        "required": ["query"],
    }
    permissions = {Permission.SHELL}
    tags = ["security", "exploitation", "recon"]

    async def execute(self, query: str, exploit_type: str = "any", **kwargs: Any) -> ToolResult:
        if not shutil.which("searchsploit"):
            return ToolResult.fail(
                "searchsploit not found.\n"
                "Install on Kali: sudo apt install exploitdb\n"
                "Or update: searchsploit -u"
            )

        cmd = ["searchsploit", "--colour", query]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            output = stdout.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            return ToolResult.fail("searchsploit timed out")
        except Exception as exc:
            return ToolResult.fail(f"searchsploit error: {exc}")

        if "No Results" in output or not output.strip():
            return ToolResult.ok(f"No exploits found for: {query}")

        # Filter by type if specified
        lines = output.splitlines()
        if exploit_type != "any":
            lines = [l for l in lines if exploit_type.lower() in l.lower() or not l.strip() or "---" in l]

        return ToolResult.ok(
            f"Exploit-DB results for: {query}\n\n" + "\n".join(lines[:50]),
            metadata={"query": query},
        )
