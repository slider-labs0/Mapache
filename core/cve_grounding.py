"""
cve_grounding.py — turn recon into a prioritized attack plan (feature M)

Discovered service versions are correlated to known CVEs with real CVSS scores
and exploit availability, so the agent (and the report, L) work from *grounded*
severity instead of guesses. This is deeper than a one-off `searchsploit` call:
it ranks the whole service inventory into a prioritized plan (version-confirmed +
exploit-available rises to the top) and feeds high-confidence hits straight into
the attack-state vulnerabilities and the suggested-next-step logic.

Design — **offline and deterministic**, matching L's reporting and the project's
local-first OPSEC stance: a curated catalog of high-signal CVEs ships in-process,
so grounding is reproducible, testable, and never phones home. A live NVD /
ExploitDB feed and RAG over the vector store are layered enhancements that can
drop in behind `ground_services()` / `lookup()` later — they are not prerequisites
for the mechanism, and keeping the default offline means scan output never leaves
the box just to be scored (the same guarantee feature O makes for routing).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from plugins.sdk.base_tool import BaseTool, ToolResult


# --------------------------------------------------------------------------- #
# CVSS → severity (CVSS v3 qualitative bands, NVD)
# --------------------------------------------------------------------------- #

def cvss_to_severity(score: float) -> str:
    """Map a CVSS base score to the severity vocabulary the report (L) uses."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CVEEntry:
    id: str
    cvss: float
    title: str
    products: tuple[str, ...]              # service/product tokens (lowercase) that imply it
    version_markers: tuple[str, ...] = ()  # substrings that confirm a vulnerable version
    exploit: str = ""                      # ExploitDB id / Metasploit module, "" if none known
    remediation: str = ""
    references: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()          # e.g. vendor bulletin ids ("ms17-010")

    @property
    def severity(self) -> str:
        return cvss_to_severity(self.cvss)

    @property
    def has_exploit(self) -> bool:
        return bool(self.exploit)


# Curated, high-signal CVEs. CVSS values are the NVD v3 base score where one
# exists, else the v2 base. Local-privesc entries (Dirty COW, Sudo) rarely match
# a network service but are kept so `lookup()` can score them for the report.
CVE_CATALOG: tuple[CVEEntry, ...] = (
    CVEEntry("CVE-2017-0144", 8.1, "SMBv1 remote code execution (EternalBlue)",
             products=("microsoft-ds", "netbios-ssn", "smb"),
             exploit="metasploit: exploit/windows/smb/ms17_010_eternalblue",
             remediation="Apply MS17-010, disable SMBv1, and restrict SMB to trusted networks.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2017-0144",),
             aliases=("ms17-010",)),
    CVEEntry("CVE-2019-0708", 9.8, "RDP remote code execution (BlueKeep)",
             products=("ms-wbt-server", "rdp", "terminal services"),
             exploit="metasploit: exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
             remediation="Patch RDP, enable NLA, and place RDP behind a VPN/jump host.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2019-0708",)),
    CVEEntry("CVE-2011-2523", 9.8, "vsftpd 2.3.4 backdoor command execution",
             products=("vsftpd", "ftp"), version_markers=("2.3.4",),
             exploit="metasploit: exploit/unix/ftp/vsftpd_234_backdoor",
             remediation="Upgrade vsftpd to a vendor-supported release.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2011-2523",)),
    CVEEntry("CVE-2015-3306", 9.8, "ProFTPD mod_copy remote command execution",
             products=("proftpd", "ftp"), version_markers=("1.3.5",),
             exploit="metasploit: exploit/unix/ftp/proftpd_modcopy_exec",
             remediation="Upgrade ProFTPD and disable mod_copy if unused.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2015-3306",)),
    CVEEntry("CVE-2014-0160", 7.5, "OpenSSL heap over-read (Heartbleed)",
             products=("https", "ssl", "tls", "openssl"), version_markers=("1.0.1",),
             exploit="metasploit: auxiliary/scanner/ssl/openssl_heartbleed",
             remediation="Upgrade OpenSSL, revoke and reissue affected keys/certs.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2014-0160",)),
    CVEEntry("CVE-2014-6271", 9.8, "Bash environment RCE (Shellshock)",
             products=("cgi", "bash"),
             exploit="metasploit: exploit/multi/http/apache_mod_cgi_bash_env_exec",
             remediation="Patch bash to a fixed version on all affected hosts.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2014-6271",)),
    CVEEntry("CVE-2021-44228", 10.0, "Apache Log4j2 JNDI RCE (Log4Shell)",
             products=("log4j", "java", "solr", "elasticsearch"),
             exploit="metasploit: exploit/multi/http/log4shell_header_injection",
             remediation="Upgrade Log4j to >=2.17.1; remove JndiLookup as interim mitigation.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2021-44228",)),
    CVEEntry("CVE-2017-5638", 10.0, "Apache Struts2 Jakarta multipart RCE",
             products=("struts",),
             exploit="metasploit: exploit/multi/http/struts2_content_type_ognl",
             remediation="Upgrade Struts2 to a fixed version.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2017-5638",)),
    CVEEntry("CVE-2018-7600", 9.8, "Drupal core RCE (Drupalgeddon2)",
             products=("drupal",),
             exploit="metasploit: exploit/unix/webapp/drupal_drupalgeddon2",
             remediation="Update Drupal core to the patched release.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2018-7600",)),
    CVEEntry("CVE-2022-22965", 9.8, "Spring Framework data-binding RCE (Spring4Shell)",
             products=("spring",),
             exploit="exploit-db: 50806",
             remediation="Upgrade Spring Framework to >=5.3.18 / 5.2.20.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2022-22965",)),
    CVEEntry("CVE-2021-34527", 8.8, "Windows Print Spooler RCE (PrintNightmare)",
             products=("spoolss", "print spooler"),
             exploit="metasploit: exploit/windows/dcerpc/cve_2021_1675_printnightmare",
             remediation="Apply the Print Spooler patches; disable the service where unneeded.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2021-34527",)),
    CVEEntry("CVE-2020-1472", 10.0, "Netlogon privilege escalation (Zerologon)",
             products=("netlogon",),
             exploit="metasploit: auxiliary/admin/dcerpc/cve_2020_1472_zerologon",
             remediation="Apply the August 2020+ DC patches and enforce secure RPC.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2020-1472",)),
    CVEEntry("CVE-2016-5195", 7.8, "Linux kernel copy-on-write privesc (Dirty COW)",
             products=("linux", "kernel"),
             exploit="exploit-db: 40611",
             remediation="Patch the Linux kernel to a fixed version and reboot.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2016-5195",)),
    CVEEntry("CVE-2021-3156", 7.8, "Sudo heap overflow privesc (Baron Samedit)",
             products=("sudo",),
             exploit="exploit-db: 49521",
             remediation="Upgrade sudo to >=1.9.5p2.",
             references=("https://nvd.nist.gov/vuln/detail/CVE-2021-3156",)),
)

# id + alias → entry, for O(1) lookup from a CVE/bulletin string.
_BY_ID: dict[str, CVEEntry] = {}
for _e in CVE_CATALOG:
    _BY_ID[_e.id.lower()] = _e
    for _a in _e.aliases:
        _BY_ID[_a.lower()] = _e


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


@dataclass
class CVEMatch:
    entry: CVEEntry
    port: str
    service: str
    version_confirmed: bool

    @property
    def confidence(self) -> str:
        return "version-confirmed" if self.version_confirmed else "service-heuristic"


def lookup(cve_id: str) -> Optional[CVEEntry]:
    """Return the catalog entry for a CVE id or vendor-bulletin alias, or None."""
    return _BY_ID.get((cve_id or "").strip().lower())


def severity_for_cve(value: str) -> str:
    """Severity for a CVE id, from its CVSS — High is the safe default for a
    named-but-uncatalogued vulnerability (used by the report builder, L)."""
    entry = lookup(value)
    return entry.severity if entry else "High"


def ground_services(
    services: dict[str, str],
    versions: Optional[dict[str, str]] = None,
) -> list[CVEMatch]:
    """Correlate a port→service map (+ optional port→version banners) to catalog
    CVEs, returned as a prioritized plan: version-confirmed first, then by CVSS,
    then by exploit availability."""
    versions = versions or {}
    matches: list[CVEMatch] = []
    seen: set[tuple[str, str]] = set()
    for port, service in (services or {}).items():
        text = f"{service} {versions.get(port, '')}".lower()
        for entry in CVE_CATALOG:
            if not any(p in text for p in entry.products):
                continue
            key = (entry.id, port)
            if key in seen:
                continue
            seen.add(key)
            vconf = bool(entry.version_markers) and any(
                v in text for v in entry.version_markers)
            matches.append(CVEMatch(entry, port, service, vconf))
    matches.sort(
        key=lambda m: (m.version_confirmed, m.entry.cvss, m.entry.has_exploit),
        reverse=True,
    )
    return matches


def attack_plan(matches: list[CVEMatch]) -> str:
    """Render grounded matches as a prioritized, human-readable plan."""
    if not matches:
        return "No CVEs grounded from the current service inventory (offline catalog)."
    lines = ["Prioritized CVE grounding (offline catalog):"]
    for m in matches:
        e = m.entry
        exp = f"  →  {e.exploit}" if e.exploit else "  (no public exploit catalogued)"
        lines.append(
            f"  [{e.severity} / CVSS {e.cvss}] {e.id} on {m.port} ({m.service}) "
            f"[{m.confidence}]: {e.title}{exp}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Live enrichment (optional layer over the offline catalog) — deferred M item
# --------------------------------------------------------------------------- #

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="


def _cvss_from_metrics(metrics: dict) -> float:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            try:
                return float(arr[0].get("cvssData", {}).get("baseScore", 0.0))
            except (TypeError, ValueError):
                return 0.0
    return 0.0


def parse_nvd(payload: dict, keyword: str) -> list[CVEEntry]:
    """Parse an NVD 2.0 API response into catalog-shaped CVEEntry objects."""
    out: list[CVEEntry] = []
    for item in (payload or {}).get("vulnerabilities", []) or []:
        cve = item.get("cve", {}) or {}
        cid = cve.get("id", "")
        if not cid:
            continue
        title = next((d.get("value", "") for d in cve.get("descriptions", [])
                      if d.get("lang") == "en"), "")
        out.append(CVEEntry(
            id=cid, cvss=_cvss_from_metrics(cve.get("metrics", {}) or {}),
            title=title.strip()[:140], products=(keyword.lower(),),
            references=(f"https://nvd.nist.gov/vuln/detail/{cid}",)))
    return out


def _nvd_fetch(keyword: str) -> str:
    from urllib.request import urlopen
    with urlopen(NVD_API + keyword, timeout=20) as resp:  # noqa: S310
        return resp.read().decode("utf-8", errors="replace")


def enrich_from_nvd(
    keyword: str,
    *,
    fetch: Optional[Callable[[str], str]] = None,
    limit: int = 5,
) -> list[CVEEntry]:
    """Live NVD lookup for a service keyword (the layered enhancement promised in
    M). OPTIONAL + opt-in: the fetch is injectable (offline-testable) and any
    failure returns [] so the offline catalog remains the reliable default. Only
    a low-sensitivity keyword leaves the box, never scan output."""
    fetch = fetch or _nvd_fetch
    try:
        raw = fetch(keyword)
        payload = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return []
    entries = parse_nvd(payload, keyword)
    entries.sort(key=lambda e: e.cvss, reverse=True)
    return entries[:limit]


# --------------------------------------------------------------------------- #
# Agent-callable meta-tool
# --------------------------------------------------------------------------- #


class CVELookupTool(BaseTool):
    name = "cve_lookup"
    description = (
        "Correlate the discovered services/versions in the current attack state "
        "to known CVEs (offline catalog with CVSS + exploit availability), "
        "returning a prioritized attack plan — deeper than a single searchsploit "
        "call. Optionally pass `cve` to look up one id, or `service` (+ optional "
        "`version`) for an ad-hoc query."
    )
    parameters = {
        "type": "object",
        "properties": {
            "cve": {"type": "string", "description": "A specific CVE id or bulletin to look up."},
            "service": {"type": "string", "description": "Service/product to ground ad-hoc."},
            "version": {"type": "string", "description": "Optional version banner for `service`."},
        },
    }
    tags = ["recon", "intel", "cve"]

    def __init__(self, state_provider: Callable[[], Any]) -> None:
        self._state = state_provider

    async def execute(self, **kwargs: Any) -> ToolResult:
        cve = (kwargs.get("cve") or "").strip()
        if cve:
            entry = lookup(cve)
            if entry is None:
                return ToolResult.ok(f"{cve} is not in the offline catalog.")
            return ToolResult.ok(
                f"{entry.id} [{entry.severity} / CVSS {entry.cvss}]: {entry.title}\n"
                f"  Exploit: {entry.exploit or 'none catalogued'}\n"
                f"  Remediation: {entry.remediation}")

        service = (kwargs.get("service") or "").strip()
        if service:
            matches = ground_services({"adhoc": service},
                                      {"adhoc": kwargs.get("version") or ""})
        else:
            st = self._state()
            matches = ground_services(getattr(st, "services", {}) or {},
                                      getattr(st, "versions", {}) or {})
        return ToolResult.ok(attack_plan(matches))
