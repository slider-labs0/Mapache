"""
engagement_scope.py - Rules-of-Engagement guardrails (feature J)

An authorized penetration test has a *scope*: the targets you are allowed to
touch and the actions you are not. A general-purpose agent has no concept of
this; an offensive one operating unattended needs it as trust infrastructure -
the thing that makes "leave it running overnight" safe.

`EngagementScope` is loaded once per engagement (a `scope.json`, mirroring the
`mcp.json` precedent) and consulted in the tool-dispatch path. A call that would
act on an out-of-scope target - or that uses a forbidden tool / matches a
forbidden command pattern - is **refused before it runs**, with a logged reason,
rather than executed and regretted.

Design choices:
  - **Opt-in.** No scope file → an inactive scope that allows everything, so
    existing behavior is unchanged until an operator defines limits.
  - **Precision over recall on host extraction.** IPs are pulled from any string
    argument (cheap and unambiguous); bare hostnames only from target-shaped
    arg keys or URLs. This avoids false-positives like a wordlist path
    `common.txt` being mistaken for a host and blocking a legitimate scan. The
    trade-off: a hostname buried in a free-form `shell` command is not caught by
    name (its IP would be) - acceptable for v1, and the loopback/utility case is
    explicitly allowed.
  - **Loopback is in-scope by default.** Local utility commands (whoami, ls) and
    127.0.0.1 are the operator's own box, not a target; blocking them is never
    what RoE means. Toggle with `allow_loopback`.

The dispatch gate emits `agent.scope_refused` on the event bus, which is also
the first raw material for the auditable engagement log (feature K).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Arg keys whose *value* is understood to be a target host (so a bare hostname,
# not just an IP, is extracted from them). Other keys only yield IPs / URL hosts.
TARGET_KEYS = {"target", "host", "hosts", "rhost", "rhosts", "ip", "domain", "url"}

_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Tools that actively scan / sweep hosts by name, and the scanner/host-touching
# binaries a raw shell/kali_run invocation uses. The LAN guard applies to these so an
# agent-invented scan of the operator's own network is refused - while a filename or
# log line that merely mentions a private IP (a different tool) is not.
_SCAN_TOOLS = {"nmap_scan", "masscan"}
_SHELL_TOOLS = {"shell", "kali_run"}
_SCANNER_BIN_RE = re.compile(
    r"\b(nmap|masscan|zmap|unicornscan|hping3|arp-?scan|netdiscover|fping|nbtscan|"
    r"nikto|gobuster|ffuf|dirb|feroxbuster|wpscan|enum4linux|crackmapexec|nxc|"
    r"smbclient|snmpwalk|onesixtyone|showmount|rpcclient|amap)\b", re.IGNORECASE)


def _is_internal_host(host: str) -> bool:
    """True for an RFC1918 / link-local / CGNAT (100.64/10) address - an internal host
    the agent must not scan on its own. Loopback is EXCLUDED: it is governed by
    allow_loopback and used for local practice targets (e.g. a Juice Shop container)."""
    h = (host or "").strip()
    if h.count(":") == 1:  # strip a trailing :port (never touch bare IPv6)
        maybe, _, port = h.partition(":")
        if port.isdigit():
            h = maybe
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if ip.is_loopback:
        return False
    try:
        cgnat = ip in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        cgnat = False
    return ip.is_private or ip.is_link_local or cgnat
# scheme://host[:port] - host captured without the port or path.
_URL_HOST_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://(?P<host>[^/:\s]+)")
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)


@dataclass
class ScopeDecision:
    """The verdict for one tool call. `reason` is empty when allowed."""
    allowed: bool
    reason: str = ""


@dataclass
class EngagementScope:
    name: str = ""
    allowed_cidrs: list[ipaddress._BaseNetwork] = field(default_factory=list)
    allowed_hosts: set[str] = field(default_factory=set)
    forbidden_tools: set[str] = field(default_factory=set)
    forbidden_patterns: list[str] = field(default_factory=list)
    allow_loopback: bool = True
    # LAN safety net: by default the agent may NOT scan internal/RFC1918 hosts it
    # invented (only the stated target or an explicitly in-scope range). Set true for a
    # deliberate internal/LAN pentest to lift that guard.
    allow_private: bool = False

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngagementScope":
        scope = cls(
            name=str(data.get("name", "")),
            forbidden_tools={str(t) for t in (data.get("forbidden_tools") or [])},
            forbidden_patterns=[str(p) for p in (data.get("forbidden_patterns") or [])],
            allow_loopback=bool(data.get("allow_loopback", True)),
            allow_private=bool(data.get("allow_private", False)),
        )
        for raw in (data.get("targets") or []):
            target = str(raw).strip()
            if not target:
                continue
            try:
                # Single IPs become a /32 network, so membership is one code path.
                scope.allowed_cidrs.append(ipaddress.ip_network(target, strict=False))
            except ValueError:
                scope.allowed_hosts.add(target.lower().rstrip("."))
        return scope

    # ------------------------------------------------------------------ #
    # State
    # ------------------------------------------------------------------ #

    @property
    def _targets_defined(self) -> bool:
        return bool(self.allowed_cidrs or self.allowed_hosts)

    @property
    def active(self) -> bool:
        """Whether any rule is defined. An inactive scope allows everything."""
        return bool(
            self._targets_defined or self.forbidden_tools or self.forbidden_patterns
        )

    # ------------------------------------------------------------------ #
    # The gate
    # ------------------------------------------------------------------ #

    def check(
        self,
        tool_name: str,
        args: dict[str, Any],
        fallback_target: Optional[str] = None,
    ) -> ScopeDecision:
        """Decide whether a tool call is permitted under the engagement scope.

        `fallback_target` is the attack-state target the controller backfills for
        tools (e.g. nmap_scan) that the model often calls without one - it is
        checked alongside any host found in the args.
        """
        # LAN safety net - enforced even when no scope.json is loaded. The agent must
        # never SCAN an internal (RFC1918/link-local/CGNAT) host it invented: that is the
        # operator's own network, not an OSINT/recon target. Allowed only when the range
        # is explicitly in scope, IS the engagement's stated target, or allow_private is
        # set for a deliberate internal engagement. Scoped to scanner tools so a private
        # IP that merely appears in a log line or an SSRF payload param is not refused.
        if not self.allow_private and self._is_scan_call(tool_name, args):
            for h in self._extract_hosts(args):
                if _is_internal_host(h) and not self._internal_scan_ok(h, fallback_target):
                    return ScopeDecision(
                        False,
                        f"refusing to scan internal/LAN host {h!r}: it is not your target "
                        "and not in scope. Do NOT scan the local network. If this host is "
                        "authorized, add its range to scope.json 'targets' (or set "
                        "'allow_private': true for an internal engagement).")

        if not self.active:
            return ScopeDecision(True)

        if tool_name in self.forbidden_tools:
            return ScopeDecision(
                False, f"tool '{tool_name}' is forbidden by engagement scope"
                       f"{f' {self.name!r}' if self.name else ''}"
            )

        haystack = " ".join(str(v) for v in args.values()).lower()
        for pat in self.forbidden_patterns:
            if pat and pat.lower() in haystack:
                return ScopeDecision(
                    False, f"argument matches forbidden pattern {pat!r}"
                )

        if self._targets_defined:
            candidates = self._extract_hosts(args)
            if fallback_target:
                candidates.add(str(fallback_target).lower().rstrip("."))
            out_of_scope = sorted(h for h in candidates if not self._in_scope(h))
            if out_of_scope:
                return ScopeDecision(
                    False,
                    f"target(s) out of scope: {', '.join(out_of_scope)} "
                    f"(in-scope: {self.targets_summary()})"
                )

        return ScopeDecision(True)

    # ------------------------------------------------------------------ #
    # Host extraction + membership
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_scan_call(tool_name: str, args: dict[str, Any]) -> bool:
        """Whether this call actively scans hosts: a scan tool by name, or a raw
        shell/kali_run whose command invokes a scanner/host-touching binary."""
        if tool_name in _SCAN_TOOLS:
            return True
        if tool_name in _SHELL_TOOLS:
            cmd = " ".join(str(v) for v in args.values())
            return bool(_SCANNER_BIN_RE.search(cmd))
        return False

    def _internal_scan_ok(self, host: str, fallback: Optional[str]) -> bool:
        """An internal host may be scanned only if it is explicitly in scope, or it is
        (or lies within) the engagement's stated target."""
        if self._in_scope(host):
            return True
        fb = (str(fallback or "").strip().lower().rstrip(".") or "").split()[0:1]
        fb = fb[0] if fb else ""
        if not fb:
            return False
        if host == fb:
            return True
        try:  # fallback given as a CIDR/host that contains this host
            return ipaddress.ip_address(host) in ipaddress.ip_network(fb, strict=False)
        except ValueError:
            return False

    def _extract_hosts(self, args: dict[str, Any]) -> set[str]:
        hosts: set[str] = set()
        for key, val in args.items():
            text = val if isinstance(val, str) else str(val)
            for ip in _IPV4_RE.findall(text):
                hosts.add(ip)
            for m in _URL_HOST_RE.finditer(text):
                hosts.add(m.group("host").lower().rstrip("."))
            # Bare hostnames only from target-shaped keys, to avoid mistaking a
            # filename / flag value for a target.
            if key.lower() in TARGET_KEYS:
                v = text.strip().lower().rstrip(".")
                if _HOSTNAME_RE.match(v):
                    hosts.add(v)
        return hosts

    def _in_scope(self, host: str) -> bool:
        host = (host or "").strip().lower().rstrip(".")
        # Strip a `host:port` suffix (e.g. a backfilled target like 127.0.0.1:37302):
        # scope is about hosts, not ports. Only a single trailing numeric port - never
        # touch bare IPv6, which legitimately contains many colons.
        if host.count(":") == 1:
            maybe_host, _, port = host.partition(":")
            if port.isdigit():
                host = maybe_host
        try:
            ip = ipaddress.ip_address(host)
            if self.allow_loopback and ip.is_loopback:
                return True
            return any(ip in net for net in self.allowed_cidrs)
        except ValueError:
            h = host.lower().rstrip(".")
            if self.allow_loopback and h == "localhost":
                return True
            # Exact match, or a subdomain of an allowed parent domain.
            return any(h == ah or h.endswith("." + ah) for ah in self.allowed_hosts)

    # ------------------------------------------------------------------ #
    # Display
    # ------------------------------------------------------------------ #

    def targets_summary(self) -> str:
        parts = [str(n) for n in self.allowed_cidrs] + sorted(self.allowed_hosts)
        return ", ".join(parts) if parts else "(none)"

    def summary(self) -> str:
        if not self.active:
            return "RoE scope: inactive (all targets allowed)"
        lines = [f"RoE scope: {self.name or 'unnamed'} (ENFORCED)"]
        if self._targets_defined:
            lines.append(f"  in-scope targets: {self.targets_summary()}")
        if self.forbidden_tools:
            lines.append(f"  forbidden tools : {', '.join(sorted(self.forbidden_tools))}")
        if self.forbidden_patterns:
            lines.append(f"  forbidden args  : {', '.join(self.forbidden_patterns)}")
        lines.append(f"  loopback        : {'allowed' if self.allow_loopback else 'blocked'}")
        return "\n".join(lines)


def load_scope(path: Optional[str | Path]) -> EngagementScope:
    """Load a scope.json, fail-soft. Missing/invalid file → an inactive scope."""
    if not path:
        return EngagementScope()
    p = Path(path)
    if not p.is_file():
        return EngagementScope()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return EngagementScope.from_dict(data if isinstance(data, dict) else {})
    except (json.JSONDecodeError, OSError):
        return EngagementScope()
