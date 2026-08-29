"""dfir_tools.py - offline DFIR triage that turns raw logs into a suspicious-event timeline.

`log_timeline` parses the log formats an incident responder meets first - Linux auth.log /
secure, syslog, and web-server access logs (Apache/Nginx combined) - into a single
chronological timeline of the events that matter, with the indicators-of-compromise pulled
out: brute-force / password-spray bursts, successful logins after failures, new-account and
sudo-to-root activity, web attacks (SQLi/traversal/webshell/`;`+curl|wget RCE), and
suspicious user-agents. It is read-only, dependency-free, and evidence-first: every line is
an event that is actually in the file, quoted, with its source line - so a finding can be
cited, not asserted.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

# --- auth.log / secure ------------------------------------------------------ #
_RE_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
_RE_ACCEPT = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
_RE_NEWUSER = re.compile(r"new user: name=(\S+?),")
_RE_SUDO = re.compile(r"sudo:.*?(\S+)\s*:.*COMMAND=(.+)$")
_RE_ADD_SUDO = re.compile(r"to group '(?:sudo|wheel|admin)'")
# syslog timestamp at the start of a classic line: "Aug 28 18:55:00"
_RE_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")

# --- web access log (combined) ---------------------------------------------- #
_RE_ACCESS = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*?) \S+" (\d{3}) (\S+)'
    r'(?: "[^"]*" "([^"]*)")?')
_WEB_ATTACK = [
    ("SQL injection", re.compile(r"(?i)(union\s+select|' or '1'='1|sleep\(|information_schema|xp_cmdshell|/\*!)")),
    ("path traversal", re.compile(r"(?:\.\./){2,}|/etc/passwd|\.\.%2f|%2e%2e%2f")),
    ("command injection / RCE", re.compile(r"(?i)(;|\|\||&&|%0a|`)\s*(?:curl|wget|nc|bash|sh|python|powershell)")),
    ("webshell access", re.compile(r"(?i)(c99|r57|b374k|wso|shell|cmd|eval|/\.\w+\.php)\.(?:php|jsp|asp|aspx)\b")),
    ("local/remote file include", re.compile(r"(?i)(php://|data://|expect://|file=/|=https?://[^&]+\.(?:php|txt))")),
    ("log4shell / JNDI", re.compile(r"(?i)\$\{jndi:(?:ldap|rmi|dns)")),
    ("XSS", re.compile(r"(?i)(<script|onerror=|javascript:|%3cscript)")),
]
_BAD_UA = re.compile(r"(?i)\b(sqlmap|nikto|nmap|masscan|hydra|dirbuster|gobuster|feroxbuster|"
                     r"wpscan|acunetix|nuclei|python-requests|curl|zgrab|go-http-client)\b")


class LogTimelineTool(BaseTool):
    """Build a chronological suspicious-event timeline from auth/syslog and web access
    logs, extracting the IOCs (brute force, privilege escalation, web attacks)."""

    name = "log_timeline"
    description = (
        "DFIR triage: parse a log FILE or a directory of logs (Linux auth.log/secure, "
        "syslog, Apache/Nginx access logs) into a chronological timeline of suspicious "
        "events with IOCs extracted - SSH brute force / password spray (grouped by source "
        "IP), successful login after failures (likely compromise), new users and sudo/root "
        "escalation, and web attacks (SQLi, path traversal, RCE, webshell, LFI/RFI, "
        "Log4Shell, XSS) plus scanner user-agents. Read-only/offline. Give `path`; optional "
        "`max_events` (default 60). Every event is quoted from the source line."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Log file or a directory of logs."},
            "max_events": {"type": "integer", "description": "Cap on timeline events (default 60)."},
        },
        "required": ["path"],
    }
    permissions = {Permission.FILESYSTEM}
    timeout = 60
    tags = ["dfir", "forensics", "logs", "incident-response"]

    def _iter_lines(self, path: str) -> Any:
        files = []
        if os.path.isdir(path):
            for root, _d, fns in os.walk(path):
                for fn in fns:
                    if fn.endswith((".gz", ".zip", ".png", ".jpg", ".pcap")):
                        continue
                    files.append(os.path.join(root, fn))
        else:
            files = [path]
        for fp in files[:50]:
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    for ln in fh:
                        yield os.path.basename(fp), ln.rstrip("\n")
            except Exception:
                continue

    def execute_sync(self, path: str, max_events: int) -> ToolResult:  # testable core
        events: list[tuple[str, str]] = []  # (sort_key, rendered line)
        fails_by_ip: dict[str, int] = defaultdict(int)
        fail_users: dict[str, set] = defaultdict(set)
        web_attacks = 0
        scanners: dict[str, int] = defaultdict(int)
        n_lines = 0

        for src, ln in self._iter_lines(path):
            n_lines += 1
            ts_m = _RE_SYSLOG_TS.match(ln)
            ts = ts_m.group(1) if ts_m else ""

            m = _RE_FAIL.search(ln)
            if m:
                fails_by_ip[m.group(2)] += 1
                fail_users[m.group(2)].add(m.group(1))
                continue
            m = _RE_ACCEPT.search(ln)
            if m:
                user, ip = m.group(1), m.group(2)
                prior = fails_by_ip.get(ip, 0)
                tag = " *** SUCCESS AFTER %d FAILURES (likely brute-force compromise)" % prior if prior >= 5 else ""
                events.append((ts, f"[{ts}] AUTH login OK user={user} from {ip}{tag}  [{src}]"))
                continue
            m = _RE_NEWUSER.search(ln)
            if m:
                events.append((ts, f"[{ts}] ACCOUNT new user created: {m.group(1)}  [{src}]"))
                continue
            if _RE_ADD_SUDO.search(ln):
                events.append((ts, f"[{ts}] PRIVESC user added to admin/sudo group: {ln.strip()[:120]}  [{src}]"))
                continue
            m = _RE_SUDO.search(ln)
            if m and ("root" in ln.lower() or "COMMAND=" in ln):
                events.append((ts, f"[{ts}] SUDO {m.group(1)} ran: {m.group(2).strip()[:100]}  [{src}]"))
                continue

            am = _RE_ACCESS.match(ln)
            if am:
                ip, wts, method, uri, status, _sz, ua = am.groups()
                req = f"{method} {uri}"
                for label, rx in _WEB_ATTACK:
                    if rx.search(uri):
                        web_attacks += 1
                        events.append((wts or ts,
                                       f"[{wts}] WEB-ATTACK {label} ({status}) from {ip}: "
                                       f"{req[:120]}  [{src}]"))
                        break
                if ua and _BAD_UA.search(ua):
                    scanners[ip] += 1

        # Brute-force bursts -> one summarized event per noisy source.
        for ip, cnt in sorted(fails_by_ip.items(), key=lambda x: -x[1]):
            if cnt >= 5:
                users = ", ".join(sorted(fail_users[ip])[:6])
                events.append(("", f"[burst] SSH BRUTE-FORCE/SPRAY from {ip}: {cnt} failed "
                                    f"logins across users [{users}]"))
        for ip, cnt in sorted(scanners.items(), key=lambda x: -x[1]):
            if cnt >= 3:
                events.append(("", f"[burst] SCANNER user-agent from {ip}: {cnt} requests"))

        if n_lines == 0:
            return ToolResult.fail(f"log_timeline: no readable log lines at {path!r}.")

        # Chronological where we have timestamps; bursts float to the end.
        events.sort(key=lambda e: (e[0] == "", e[0]))
        shown = events[:max_events]
        lines = [f"log_timeline - {path}  ({n_lines} lines parsed, {len(events)} suspicious events)"]
        if not events:
            lines.append("\nNo suspicious authentication or web-attack events found in the "
                         "parsed logs. (Confirm the right log format/path; check for gaps or "
                         "cleared logs - an empty window can itself be an anti-forensics IOC.)")
        else:
            lines.append("\nSUSPICIOUS-EVENT TIMELINE:")
            lines += [f"  {e[1]}" for e in shown]
            if len(events) > len(shown):
                lines.append(f"  ... {len(events) - len(shown)} more (raise max_events)")
            lines.append("\nNext: pivot on the top source IPs, correlate the successful "
                         "login timestamps with web-attack events for the intrusion path, "
                         "and map each action to the detection that should have fired "
                         "(purple-team validation).")
        return ToolResult.ok("\n".join(lines),
                             metadata={"events": len(events), "web_attacks": web_attacks,
                                       "brute_force_ips": sum(1 for c in fails_by_ip.values() if c >= 5)})

    async def execute(self, path: str, max_events: int = 60, **kwargs: Any) -> ToolResult:
        path = (path or "").strip()
        if not path or not os.path.exists(path):
            return ToolResult.fail(f"log_timeline: path not found: {path!r}")
        return self.execute_sync(path, max(5, min(int(max_events or 60), 500)))
