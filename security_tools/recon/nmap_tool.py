"""
nmap_tool.py — Mapache Nmap integration

Wraps Nmap into a structured tool the agent can call autonomously.
Returns parsed, model-friendly output instead of raw XML.

Requires nmap installed:
    Windows: https://nmap.org/download.html
    Linux:   sudo apt install nmap
    Mac:     brew install nmap

Scan types supported:
    quick   — top 100 ports, fast (-F)
    standard — top 1000 ports (default)
    full    — all 65535 ports (slow)
    udp     — UDP scan (requires root/admin)
    version — service version detection (-sV)
    os      — OS detection (-O, requires root/admin)
    vuln    — basic vulnerability scripts (--script vuln)
"""

from __future__ import annotations

import asyncio
import platform
import re
import shutil
from typing import Any

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult


class NmapTool(BaseTool):
    name = "nmap_scan"
    description = (
        "Run an Nmap network scan against a target host or IP range. "
        "Returns open ports, services, and versions. "
        "Use for reconnaissance, network mapping, and service enumeration. "
        "Examples: '192.168.1.1', '192.168.1.0/24', 'scanme.nmap.org'"
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP, hostname, or CIDR range (e.g. '192.168.1.1' or '192.168.1.0/24')",
            },
            "scan_type": {
                "type": "string",
                "enum": ["quick", "standard", "full", "version", "os", "vuln", "udp"],
                "description": "Type of scan to run",
                "default": "standard",
            },
            "ports": {
                "type": "string",
                "description": "Specific ports to scan (e.g. '80,443,8080' or '1-1024'). Overrides scan_type port range.",
                "default": "",
            },
            "timing": {
                "type": "integer",
                "description": "Nmap timing template 0-5 (0=paranoid, 3=normal, 5=insane). Default: 3",
                "default": 3,
            },
            "extra_args": {
                "type": "string",
                "description": "Additional raw nmap arguments (advanced use)",
                "default": "",
            },
        },
        "required": ["target"],
    }
    permissions = {Permission.NETWORK, Permission.SHELL}
    timeout = 1000
    version = "0.1.0"
    tags = ["security", "recon", "network"]

    # ------------------------------------------------------------------ #
    # Scan type → nmap flags
    # ------------------------------------------------------------------ #

    SCAN_FLAGS = {
        "quick":    ["-F", "--open"],
        "standard": ["--open"],
        "full":     ["-p-", "--open"],
        "version":  ["-sV", "--open"],
        "os":       ["-O", "--open"],
        "vuln":     ["-sV", "--script", "vuln"],
        "udp":      ["-sU", "--open"],
    }

    def __init__(self, backend: Any = None, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Execution backend (feature H). A remote backend (ssh/docker) runs nmap on
        # that host — e.g. an attacker container that shares the target's isolated
        # network — so we must NOT resolve the binary locally; the remote PATH does.
        # None / local → the local subprocess fast-path below (unchanged).
        self.backend = backend
        # Egress/OPSEC: when active, route the scan through the proxy/Tor. NOTE:
        # proxychains/torsocks hook connect(), so only a TCP-connect scan (-sT)
        # honors it — raw SYN/UDP does not. For raw scans, hide the IP with a pivot
        # backend instead. Applied on the (POSIX) remote path.
        self.egress = egress

    async def execute(
        self,
        target: str,
        scan_type: str = "standard",
        ports: str = "",
        timing: int = 3,
        extra_args: str = "",
        **kwargs: Any,
    ) -> ToolResult:

        # Sanitize target — basic protection against shell injection. Done first
        # because it guards both the local and the remote execution paths.
        if not self._is_safe_target(target):
            return ToolResult.fail(f"Invalid target: {target!r}. Use IP, hostname, or CIDR only.")

        # Remote backend (feature H): nmap lives on the remote host/container (e.g.
        # an attacker box on the target's isolated network), so skip local path
        # resolution and let the remote PATH resolve "nmap".
        if self.backend is not None and getattr(self.backend, "name", "local") != "local":
            return await self._execute_remote(target, scan_type, ports, timing, extra_args)

        # Validate nmap is installed
        nmap_path = self._find_nmap()
        if not nmap_path:
            return ToolResult.fail(
                "Nmap is not installed or not in PATH.\n"
                "Install: https://nmap.org/download.html (Windows) "
                "or 'sudo apt install nmap' (Linux)"
            )

        # Build command
        cmd = self._build_command(nmap_path, target, scan_type, ports, timing, extra_args)

        # Run scan
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(self.timeout),
                )
            except asyncio.TimeoutError:
                proc.kill()
                return ToolResult.fail(f"Nmap scan timed out after {self.timeout}s")

            raw_output = stdout.decode("utf-8", errors="replace")

            if proc.returncode != 0 and not raw_output.strip():
                return ToolResult.fail(f"Nmap failed with exit code {proc.returncode}")

        except FileNotFoundError:
            return ToolResult.fail("Nmap executable not found")
        except Exception as exc:
            return ToolResult.fail(f"Nmap error: {exc}")

        # Parse and format output
        parsed = self._parse_output(raw_output, target, scan_type)

        return ToolResult.ok(
            parsed,
            metadata={
                "target": target,
                "scan_type": scan_type,
                "raw_output": raw_output,
                "cmd": " ".join(cmd),
            },
        )

    # ------------------------------------------------------------------ #
    # Remote execution (feature H)
    # ------------------------------------------------------------------ #

    async def _execute_remote(
        self,
        target: str,
        scan_type: str,
        ports: str,
        timing: int,
        extra_args: str,
    ) -> ToolResult:
        # "nmap" (unqualified) — the remote host/container resolves it on its PATH.
        # target is already sanitized (no shell metacharacters), so joining the
        # argv into a command string for the backend is safe.
        cmd = self._build_command("nmap", target, scan_type, ports, timing, extra_args)
        cmd_str = " ".join(cmd)
        run_str = self.egress.wrap_command(cmd_str, posix=True) if self.egress is not None else cmd_str
        try:
            res = await self.backend.run(run_str, timeout=self.timeout)
        except Exception as exc:
            return ToolResult.fail(f"[backend: {self.backend.name}] Nmap error: {exc}")

        raw_output = res.output or ""
        if res.error and not raw_output.strip():
            return ToolResult.fail(f"[backend: {self.backend.name}] {res.error}")

        parsed = self._parse_output(raw_output, target, scan_type)
        return ToolResult.ok(
            parsed,
            metadata={
                "target": target,
                "scan_type": scan_type,
                "raw_output": raw_output,
                "cmd": cmd_str,
                "backend": self.backend.name,
            },
        )

    # ------------------------------------------------------------------ #
    # Command builder
    # ------------------------------------------------------------------ #

    def _build_command(
        self,
        nmap_path: str,
        target: str,
        scan_type: str,
        ports: str,
        timing: int,
        extra_args: str,
    ) -> list[str]:
        cmd = [nmap_path]

        # Timing
        cmd.append(f"-T{max(0, min(5, timing))}")

        # Scan type flags
        flags = self.SCAN_FLAGS.get(scan_type, self.SCAN_FLAGS["standard"])
        cmd.extend(flags)

        # Port specification
        if ports:
            cmd.extend(["-p", ports])

        # Extra args (split safely)
        if extra_args:
            cmd.extend(extra_args.split())

        # Always request verbose output for parsing
        cmd.extend(["-v", "--reason"])

        cmd.append(target)
        return cmd

    # ------------------------------------------------------------------ #
    # Output parser
    # ------------------------------------------------------------------ #

    def _parse_output(self, raw: str, target: str, scan_type: str) -> str:
        lines = raw.strip().splitlines()
        sections: list[str] = []

        # Extract host status
        host_line = next((l for l in lines if "Nmap scan report" in l), None)
        if host_line:
            sections.append(host_line.strip())

        # Host up/down
        status_line = next((l for l in lines if "Host is" in l), None)
        if status_line:
            sections.append(status_line.strip())

        # Extract open ports table
        port_lines = []
        in_port_section = False
        for line in lines:
            if re.match(r"PORT\s+STATE\s+SERVICE", line):
                in_port_section = True
                port_lines.append(line.strip())
                continue
            if in_port_section:
                if line.strip() == "" or line.startswith("Nmap") or line.startswith("Service"):
                    in_port_section = False
                else:
                    port_lines.append(line.strip())

        if port_lines:
            sections.append("\nOpen ports:")
            sections.extend(port_lines)
        else:
            # Check if host was down or no ports found
            if "Host seems down" in raw:
                sections.append("\nHost appears to be down or not responding to pings.")
                sections.append("Try: scan_type='quick' with extra_args='-Pn' to skip ping check.")
            elif "0 hosts up" in raw:
                sections.append("\nNo hosts found up in that range.")
            else:
                sections.append("\nNo open ports found in the scanned range.")

        # OS detection results
        os_lines = [l.strip() for l in lines if "OS details:" in l or "Running:" in l]
        if os_lines:
            sections.append("\nOS detection:")
            sections.extend(os_lines)

        # Service versions
        version_lines = [l.strip() for l in lines if re.match(r"\d+/tcp\s+open", l) and "/" in l]

        # Nmap stats
        stats_line = next((l for l in lines if "Nmap done" in l), None)
        if stats_line:
            sections.append(f"\n{stats_line.strip()}")

        if not sections:
            return raw  # fallback: return raw if parsing found nothing

        return "\n".join(sections)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _find_nmap(self) -> str | None:
        """Find nmap executable, checking common Windows install paths too."""
        # Check PATH first
        found = shutil.which("nmap")
        if found:
            return found

        # Common Windows install locations
        if platform.system() == "Windows":
            candidates = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ]
            for path in candidates:
                import os
                if os.path.isfile(path):
                    return path

        return None

    def _is_safe_target(self, target: str) -> bool:
        """
        Basic validation — allow IPs, hostnames, CIDR ranges.
        Reject anything with shell metacharacters.
        """
        dangerous = set(';|&`$(){}[]<>!\\"\'\n\r\t')
        if any(c in dangerous for c in target):
            return False
        # Must contain at least one alphanumeric character
        if not re.search(r'[a-zA-Z0-9]', target):
            return False
        return True
