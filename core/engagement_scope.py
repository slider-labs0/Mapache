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
