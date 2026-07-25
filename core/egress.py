"""
egress.py — operator anonymity / egress control (OPSEC).

Route Mapache's attack traffic so a target sees a chosen exit — a proxy, Tor, or a
pivot host/VM/container — instead of the operator's real IP. This is standard,
authorized-pentest practice: redirectors, VPN/proxy pivots, and Tor for anonymized
recon, used to protect operator infrastructure and to exercise a defender's
blocking/detection.

An `EgressProfile` answers, for every network tool, "where does my traffic exit?":
  - httpx_proxy():  the proxy the HTTP tools (http_request / web_fetch) route through.
  - wrap_command(): how to push a shell/nmap command's TCP through the proxy
                    (torsocks for Tor, proxychains otherwise) — POSIX only.
  - describe():     a human-readable status line for the CLI.

Two complementary mechanisms, which compose:
  1. Proxy/Tor — hides the source of HTTP tools everywhere, and of TCP-connect shell
     traffic on a POSIX box. Caveat: proxychains/torsocks hook connect(), so raw
     SYN/UDP scans (nmap -sS/-sU) do NOT honor it — use -sT through the proxy.
  2. Pivot — run the whole toolchain FROM a VM/container via the execution backend
     (feature H) so the target sees the pivot's IP. This is the robust IP-hide for
     raw scanners and Metasploit, and the per-sub-agent container factory already
     gives each agent its own disposable pivot.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any, Optional

# Tor's default SOCKS ports (system daemon / Tor Browser).
TOR_SOCKS_PORT = 9050
TOR_BROWSER_SOCKS_PORT = 9150
TOR_DEFAULT_PROXY = f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"


def _looks_like_tor(proxy: str) -> bool:
    return f":{TOR_SOCKS_PORT}" in proxy or f":{TOR_BROWSER_SOCKS_PORT}" in proxy


@dataclass(frozen=True)
class EgressProfile:
    """How attack traffic exits. `direct` = the operator's real IP (default,
    backwards-compatible); `proxy`/`tor` route through a SOCKS/HTTP proxy."""

    mode: str = "direct"       # direct | proxy | tor
    proxy: str = ""            # socks5://host:port | socks5h://... | http://host:port
    wrapper: str = "auto"      # shell wrapper: auto | proxychains | torsocks | none
    name: str = field(default="egress", init=False)

    @property
    def effective_proxy(self) -> str:
        if self.mode == "tor":
            return self.proxy or TOR_DEFAULT_PROXY
        if self.mode == "proxy":
            return self.proxy
        return ""

    @property
    def active(self) -> bool:
        """True when traffic should be anonymised (a usable proxy is set)."""
        return bool(self.effective_proxy)

    # -- HTTP tools ----------------------------------------------------- #

    def httpx_proxy(self) -> Optional[str]:
        """Proxy URL for httpx (the http_request / web_fetch tools). None = direct."""
        return self.effective_proxy or None

    # -- shell / scanner tools ------------------------------------------ #

    def _wrapper_prefix(self) -> str:
        w = (self.wrapper or "auto").lower()
        if w == "none":
            return ""
        if w == "torsocks" or (w == "auto" and self.mode == "tor"):
            return "torsocks"
        if w in ("proxychains", "auto"):
            return "proxychains -q"
        return ""

    def wrap_command(self, cmd: str, *, posix: bool = True) -> str:
        """Wrap a shell command so its TCP egress goes through the proxy.

        Returns `cmd` unchanged when egress is direct, wrapping is disabled, or the
        target isn't POSIX (torsocks/proxychains are Linux-only — the local Windows
        operator shell can't wrap, though its HTTP tools still honor httpx_proxy).
        The wrapper prefixes the WHOLE pipeline via `sh -c`, so redirects/pipes in
        `cmd` are covered too."""
        if not self.active or not posix:
            return cmd
        prefix = self._wrapper_prefix()
        if not prefix:
            return cmd
        return f"{prefix} sh -c {shlex.quote(cmd)}"

    # -- presentation --------------------------------------------------- #

    def describe(self) -> str:
        if not self.active:
            return "direct — target sees your real IP (no egress proxy)"
        return f"{self.mode} via {self.effective_proxy}"

    # -- construction --------------------------------------------------- #

    @classmethod
    def from_dict(cls, spec: Optional[dict]) -> "EgressProfile":
        spec = spec or {}
        mode = str(spec.get("mode", "direct")).lower()
        proxy = str(spec.get("proxy", "")).strip()
        wrapper = str(spec.get("wrapper", "auto")).lower()
        # Convenience: a bare proxy with mode unset implies proxy (or tor if it's a
        # Tor SOCKS port), so operators can just set `proxy` and go.
        if mode == "direct" and proxy:
            mode = "tor" if _looks_like_tor(proxy) else "proxy"
        return cls(mode=mode, proxy=proxy, wrapper=wrapper)

    @classmethod
    def parse(cls, spec: str) -> "EgressProfile":
        """Parse a CLI `--egress` value: 'direct' | 'tor' | a proxy URL
        (socks5://…, http://…). Empty/'direct' → direct."""
        s = (spec or "").strip()
        if not s or s.lower() == "direct":
            return cls()
        if s.lower() == "tor":
            return cls(mode="tor")
        if "://" in s:
            return cls.from_dict({"proxy": s})
        # otherwise treat it as a mode name (best effort)
        return cls(mode=s.lower())

    def to_dict(self) -> dict:
        return {"mode": self.mode, "proxy": self.proxy, "wrapper": self.wrapper}
