"""attack_logic.py - the finding-driven next-move engine.

Given the shared AttackState, produce a prioritized list of concrete next attack moves
across EVERY discipline (network services, web, credentials, Active Directory, cloud,
databases, containers). It is deterministic and additive: it complements the model's own
reasoning by turning the raw findings (open ports, versions, creds, tokens, tech) into
"do THIS next, with THIS tool" guidance, so the agent chains findings into deeper
exploitation instead of stalling or fixating on one class.

`next_moves(state)` returns strings ordered highest-value first; the conversation chain
injects the top few into the CURRENT ATTACK STATE block each turn.
"""

from __future__ import annotations

from typing import Any


# port -> (short exploit chain, the tool/operator to reach for)
_SERVICE_MOVES: dict[str, str] = {
    "21": "FTP - try anonymous login, then exploit the exact ftpd version (vsftpd 2.3.4 "
          "backdoor / ProFTPD) via searchsploit",
    "22": "SSH - spray discovered/default creds (hydra), check for reused private keys",
    "23": "Telnet - connect and try no-password / default creds (often a direct shell)",
    "25": "SMTP - VRFY/EXPN user enumeration and open-relay test",
    "53": "DNS - attempt a zone transfer (axfr) for internal hostnames",
    "88": "Kerberos = Active Directory - AS-REP roast, Kerberoast, then BloodHound "
          "(operator=... , ad_attack)",
    "110": "POP3 - default creds, read mail for secrets",
    "111": "RPCbind/NFS - rpcinfo, showmount -e; mount exports, drop a SUID/authorized_keys",
    "135": "MSRPC - enum, check for known DCOM/PrintNightmare vectors",
    "139": "SMB (NetBIOS) - enum4linux / null session for users + shares",
    "143": "IMAP - default creds, read mail",
    "161": "SNMP - onesixtyone/snmpwalk 'public' for creds, routes, running config",
    "389": "LDAP = Active Directory - anonymous bind, dump users/computers; AS-REP roast",
    "445": "SMB - enum4linux + null session, then MS17-010 EternalBlue "
           "(msf_search ms17-010) and read/write shares (operator=exploit)",
    "512": "rexec / 513 rlogin / 514 rsh - trust-based login, try root with no password",
    "623": "IPMI - dump password hashes (cipher-zero / RAKP)",
    "1099": "Java RMI - deserialization RCE (ysoserial JRMP)",
    "1433": "MSSQL - default 'sa' creds, then xp_cmdshell for RCE",
    "1521": "Oracle TNS - odat, SID brute, default creds",
    "1524": "1524/ingreslock is an OPEN ROOT SHELL - `nc <target> 1524` then run commands "
            "directly. Try this FIRST (tool: shell).",
    "2049": "NFS - showmount -e, mount an export, plant a SUID binary or ~/.ssh/authorized_keys",
    "2375": "Docker API (unauthenticated) - run a privileged container mounting the host "
            "fs = instant host root (curl the /containers API)",
    "3306": "MySQL - default/no creds, then read files (LOAD_FILE) or UDF RCE",
    "3389": "RDP - credential spray, and BlueKeep (CVE-2019-0708) on unpatched hosts",
    "3632": "distccd - CVE-2004-2687 command execution",
    "5432": "PostgreSQL - default creds, then COPY ... TO PROGRAM for RCE",
    "5601": "Kibana - prototype-pollution / CVE RCE on older versions",
    "5900": "VNC - no-auth or weak password screen access",
    "5985": "WinRM - evil-winrm with captured creds for a shell",
    "6379": "Redis (usually unauthenticated) - write an SSH key / cron job / load a module "
            "for RCE",
    "8009": "AJP - Ghostcat (CVE-2020-1938) file read / RCE on Tomcat",
    "9200": "Elasticsearch - unauthenticated read of all indices; Groovy RCE "
            "(CVE-2015-1427) on old versions",
    "11211": "Memcached - unauthenticated dump / UDP amplification",
    "27017": "MongoDB - unauthenticated: dump every database",
    "50070": "Hadoop HDFS - unauthenticated file access / YARN RCE",
}

_WEB_PORTS = {"80", "443", "8080", "8000", "8443", "8888", "3000", "5000"}


def _ports(state: Any) -> set:
    return {str(p).split("/")[0].strip() for p in (getattr(state, "open_ports", None) or [])}


def _haystack(state: Any) -> str:
    parts = []
    for attr in ("services", "versions"):
        d = getattr(state, attr, None)
        if isinstance(d, dict):
            parts += [str(v) for v in d.values()]
    for attr in ("notes", "vulnerabilities", "credentials", "disclosed_creds", "endpoints"):
        v = getattr(state, attr, None)
        if isinstance(v, list):
            parts += [str(x) for x in v]
    parts.append(str(getattr(state, "target", "") or ""))
    return " ".join(parts).lower()


def next_moves(state: Any) -> list[str]:
    """Prioritized, finding-driven next attack moves across all disciplines."""
    if state is None:
        return []
    moves: list[str] = []
    ports = _ports(state)
    hay = _haystack(state)
    creds = (getattr(state, "credentials", None) or []) + \
            (getattr(state, "disclosed_creds", None) or [])
    flags = getattr(state, "flags", None) or []

    # 1. Trivial wins first (an already-open shell).
    if "1524" in ports:
        moves.append(_SERVICE_MOVES["1524"])

    # 2. Credentials in hand but no confirmed access -> spray + escalate everywhere.
    if creds and not flags:
        moves.append("Credentials in hand: SPRAY them across EVERY service (SSH/SMB/RDP/"
                     "WinRM/web login/db) - creds rarely work only where found. On any "
                     "shell, escalate (SUID/sudo/kernel/cron) and loot more creds.")

    # 3. Active Directory (Kerberos/LDAP) gets a dedicated chain.
    if ports & {"88", "389", "636"} or "domain controller" in hay or "kerberos" in hay:
        moves.append("Active Directory in scope: AS-REP roast users without preauth, "
                     "Kerberoast SPNs, run BloodHound to map paths to Domain Admin "
                     "(tool: ad_attack / kali_run).")

    # 4. Per-service network exploit chains.
    for p in sorted(ports):
        if p in _SERVICE_MOVES and p != "1524":
            moves.append(f"{p} open: {_SERVICE_MOVES[p]} (tool: kali_run/searchsploit, "
                         "operator=exploit)")

    # 5. Web surface -> the full modern class set, not just SQLi/IDOR.
    if ports & _WEB_PORTS or "http" in hay or getattr(state, "forms", None) \
            or getattr(state, "endpoints", None):
        moves.append("Web surface: operator=web_operator. Read the real attack surface, "
                     "then by OBJECTIVE reach for the right class - ssrf_probe (cloud "
                     "creds), ssti_probe (RCE), nosqli_probe, oauth_probe, jwt_tool, "
                     "proto_pollution, xxe_tool, cache_poison, smuggle_probe, race_probe.")

    # 6. Token / crypto signals.
    if any(k in hay for k in ("jwt", "bearer", "eyj")):
        moves.append("A JWT/bearer token is present: jwt_tool - alg=none, HS-secret crack, "
                     "RS256->HS256 confusion, and kid/jwk/jku header injection.")

    # 7. Cloud indicators -> IMDS credential theft.
    if any(k in hay for k in ("aws", "s3.amazonaws", "ec2", "169.254.169.254", "metadata",
                              "azure", "gcp", "iam")):
        moves.append("Cloud indicators: if an SSRF or file-read exists, hit the metadata "
                     "endpoint for IAM credentials (ssrf_probe / cloud_metadata), then "
                     "enumerate the account (operator=cloud_hunter).")

    # 8. Nothing actionable yet -> discipline-appropriate first step (respect scope).
    if not moves:
        if not getattr(state, "target", None):
            moves.append("No target/findings yet: identify the target's DISCIPLINE (host/"
                         "web/cloud/code/mobile/binary) and take that path - do not default "
                         "to a network scan.")
        elif not ports:
            moves.append("Target set but nothing enumerated: for a host run nmap_scan; for "
                         "a web app read its surface with web_fetch; route by discipline.")

    # De-dup while preserving priority; cap to keep the prompt tight.
    seen: set = set()
    out = []
    for m in moves:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out[:6]
