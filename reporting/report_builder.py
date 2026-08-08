"""
report_builder.py — structured pentest report from the engagement (feature L)

Turns the reporting phase into an actual deliverable. Hermes gives you a chat
history; Mapache gives you a report a client pays for — findings with severity,
evidence, and remediation, plus a methodology timeline.

Inputs are exactly what features K and P already produce: the shared AttackState
blackboard (target, ports, services, vulns, creds, flags) and the EngagementLog's
records (timestamped tool calls / findings / RoE refusals). It is **deterministic
and offline** — no LLM call, so the report is reproducible, testable, and never
sends findings to a third party (the local-first OPSEC story holds end to end).
A richer LLM narrative pass, and precise CVSS scoring via CVE grounding (feature
M), are layered enhancements, not prerequisites.

Exports Markdown and self-contained HTML. (PDF: open/print the HTML, or add an
optional weasyprint backend later — kept dependency-free here.)
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# Severity ordering for sorting + the exec-summary tally.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Generic, finding-type remediation (precise per-CVE guidance arrives with M).
_REMEDIATION = {
    "credential": "Rotate the exposed credential immediately, enforce strong unique "
                  "passwords, and require MFA on the affected service.",
    "vulnerability": "Apply the vendor patch or upgrade to a fixed version; where no "
                     "fix exists, apply the documented mitigation and restrict exposure.",
    "flag": "Capture-the-flag artifact proving access to the host — remediate the "
            "underlying access vector that allowed it.",
    "open_port": "Restrict the service to trusted networks (firewall / segmentation) "
                 "and disable it if it is not required.",
}

# Service-specific remediation + a baseline severity for an exposed service.
_SERVICE_RULES: dict[str, tuple[str, str]] = {
    "telnet":      ("High",   "Disable Telnet (cleartext); use SSH instead."),
    "ftp":         ("Medium", "Disable anonymous FTP; require SFTP/FTPS with auth."),
    "smb":         ("High",   "Patch SMB (e.g. MS17-010), disable SMBv1, restrict to trusted hosts."),
    "microsoft-ds":("High",   "Patch SMB, disable SMBv1, and restrict access by network."),
    "netbios":     ("Medium", "Restrict NetBIOS to internal segments or disable it."),
    "rdp":         ("High",   "Place RDP behind a VPN/jump host; enable NLA and MFA."),
    "ms-wbt-server":("High",  "Place RDP behind a VPN/jump host; enable NLA and MFA."),
    "vnc":         ("High",   "Require strong VNC auth over a tunnel; do not expose directly."),
    "redis":       ("Critical","Enable auth/ACLs and bind Redis to localhost; never expose unauthenticated."),
    "mysql":       ("Medium", "Restrict DB access by network and enforce strong credentials."),
    "mongodb":     ("Critical","Enable authentication and bind MongoDB to trusted interfaces only."),
    "smtp":        ("Low",    "Disable open relay; enforce auth and TLS."),
}

_NOTABLE = tuple(_SERVICE_RULES.keys())


@dataclass
class Finding:
    title: str
    severity: str
    finding_type: str
    evidence: str
    remediation: str
    discovered: str = ""  # ISO timestamp of first observation, if known

    @property
    def rank(self) -> int:
        return _SEV_RANK.get(self.severity, len(SEVERITY_ORDER))


@dataclass
class EngagementReport:
    target: str
    metadata: dict[str, Any]
    findings: list[Finding]
    timeline: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    generated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # -- summary -------------------------------------------------------- #

    def severity_counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def _summary_sentence(self) -> str:
        counts = self.severity_counts()
        notable = [f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER if counts[s]]
        if not notable:
            return (f"The engagement against {self.target or 'the target'} recorded "
                    "no findings.")
        return (f"The engagement against {self.target or 'the target'} produced "
                f"{len(self.findings)} finding(s): " + ", ".join(notable) + ".")

    # -- Markdown ------------------------------------------------------- #

    def to_markdown(self) -> str:
        L: list[str] = []
        L.append(f"# Penetration Test Report — {self.target or 'engagement'}")
        L.append("")
        L.append(f"*Generated {self.generated}*")
        L.append("")
        for k, v in self.metadata.items():
            if v not in (None, "", []):
                L.append(f"- **{k}**: {v}")
        L.append("")

        L.append("## Executive summary")
        L.append("")
        L.append(self._summary_sentence())
        counts = self.severity_counts()
        L.append("")
        L.append("| Severity | Count |")
        L.append("|---|---|")
        for s in SEVERITY_ORDER:
            if counts[s]:
                L.append(f"| {s} | {counts[s]} |")
        L.append("")

        L.append("## Findings")
        L.append("")
        if not self.findings:
            L.append("_No findings recorded._")
        for i, f in enumerate(sorted(self.findings, key=lambda x: x.rank), 1):
            L.append(f"### {i}. [{f.severity}] {f.title}")
            L.append("")
            L.append(f"- **Type**: {f.finding_type}")
            if f.discovered:
                L.append(f"- **Discovered**: {f.discovered}")
            L.append(f"- **Evidence**: {f.evidence}")
            L.append(f"- **Remediation**: {f.remediation}")
            L.append("")

        L.append("## Methodology & timeline")
        L.append("")
        if self.timeline:
            for r in self.timeline:
                L.append(f"- `{r.get('ts', '')}` {r.get('summary', '')}")
        else:
            L.append("_No timeline recorded._")
        L.append("")

        if self.tool_calls:
            L.append("## Appendix — tool activity")
            L.append("")
            L.append("| Time | Tool | Result |")
            L.append("|---|---|---|")
            for r in self.tool_calls:
                status = "ok" if r.get("ok") else f"error: {r.get('error')}"
                L.append(f"| {r.get('ts', '')} | `{r.get('tool')}` | {status} |")
            L.append("")
        return "\n".join(L) + "\n"

    # -- HTML ----------------------------------------------------------- #

    def to_html(self) -> str:
        def esc(x: Any) -> str:
            return html.escape(str(x))

        counts = self.severity_counts()
        rows = "".join(
            f"<tr><td>{s}</td><td>{counts[s]}</td></tr>"
            for s in SEVERITY_ORDER if counts[s]
        )
        find_html = []
        for i, f in enumerate(sorted(self.findings, key=lambda x: x.rank), 1):
            find_html.append(
                f"<div class='finding sev-{esc(f.severity).lower()}'>"
                f"<h3>{i}. <span class='sev'>[{esc(f.severity)}]</span> {esc(f.title)}</h3>"
                f"<p><b>Type:</b> {esc(f.finding_type)}</p>"
                + (f"<p><b>Discovered:</b> {esc(f.discovered)}</p>" if f.discovered else "")
                + f"<p><b>Evidence:</b> {esc(f.evidence)}</p>"
                f"<p><b>Remediation:</b> {esc(f.remediation)}</p></div>"
            )
        meta = "".join(
            f"<li><b>{esc(k)}:</b> {esc(v)}</li>"
            for k, v in self.metadata.items() if v not in (None, "", [])
        )
        timeline = "".join(
            f"<li><code>{esc(r.get('ts', ''))}</code> {esc(r.get('summary', ''))}</li>"
            for r in self.timeline
        )
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Pentest Report — {esc(self.target or 'engagement')}</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:50rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
 h1{{border-bottom:2px solid #333}} code{{background:#f2f2f2;padding:.1em .3em;border-radius:3px}}
 table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:.3em .6em}}
 .finding{{border-left:4px solid #888;padding:.2em 1em;margin:1em 0;background:#fafafa}}
 .sev-critical{{border-color:#b00020}} .sev-high{{border-color:#d35400}}
 .sev-medium{{border-color:#c9a227}} .sev-low{{border-color:#2e7d32}} .sev-info{{border-color:#607d8b}}
 .sev{{font-variant:small-caps}}
</style></head><body>
<h1>Penetration Test Report — {esc(self.target or 'engagement')}</h1>
<p><em>Generated {esc(self.generated)}</em></p>
<ul>{meta}</ul>
<h2>Executive summary</h2><p>{esc(self._summary_sentence())}</p>
<table><tr><th>Severity</th><th>Count</th></tr>{rows}</table>
<h2>Findings</h2>{''.join(find_html) or '<p>No findings recorded.</p>'}
<h2>Methodology &amp; timeline</h2><ul>{timeline or '<li>No timeline recorded.</li>'}</ul>
</body></html>
"""


# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #


def _service_rule(service: str) -> Optional[tuple[str, str]]:
    s = (service or "").lower()
    for key, rule in _SERVICE_RULES.items():
        if key in s:
            return rule
    return None


def _vuln_severity(value: str) -> str:
    # CVE grounding (feature M) scores known CVEs by their CVSS; an unrecognized
    # named vulnerability still defaults to High (the safe assumption).
    from core.cve_grounding import severity_for_cve
    return severity_for_cve(value)


def _vuln_finding(value: str, records: list[dict]) -> "Finding":
    """Build a vulnerability finding, enriched with CVSS/exploit/remediation from
    the CVE catalog (feature M) when the value is a known CVE."""
    from core.cve_grounding import lookup
    entry = lookup(value)
    if entry is not None:
        exploit = f" Public exploit: {entry.exploit}." if entry.exploit else ""
        refs = (" Refs: " + ", ".join(entry.references)) if entry.references else ""
        return Finding(
            title=f"{entry.id} — {entry.title}",
            severity=entry.severity,
            finding_type="vulnerability",
            evidence=f"{entry.id} (CVSS {entry.cvss}).{exploit}{refs}",
            remediation=entry.remediation or _REMEDIATION["vulnerability"],
            discovered=_first_seen(records, "vulnerability", value),
        )
    return Finding(
        title=f"Vulnerability: {value}",
        severity=_vuln_severity(value),
        finding_type="vulnerability",
        evidence=str(value),
        remediation=_REMEDIATION["vulnerability"],
        discovered=_first_seen(records, "vulnerability", value),
    )


def _first_seen(records: list[dict], finding_type: str, value: str) -> str:
    for r in records:
        if r.get("kind") == "finding" and r.get("finding_type") == finding_type \
                and str(r.get("value")) == str(value):
            return r.get("ts", "")
    return ""


def _mask_secret(cred: str) -> str:
    # user:pass → user:**** ; keep the username, hide the secret half.
    if ":" in cred:
        user, _, _secret = cred.partition(":")
        return f"{user}:****"
    return "****"


def build_report(
    attack_state: Any,
    records: Optional[list[dict]] = None,
    metadata: Optional[dict[str, Any]] = None,
    *,
    redact_secrets: bool = False,
    extra_findings: Optional[list] = None,
) -> EngagementReport:
    """Assemble an EngagementReport from the blackboard + engagement-log records.

    `extra_findings` are agent-authored, evidence-carrying findings (core.findings
    Finding objects recorded via the report_finding tool) — the rich web/authz
    findings with a real request/response as proof. They are merged in FIRST so the
    deliverable leads with proven weaknesses, not just blackboard-derived ones.
    """
    records = records or []
    findings: list[Finding] = []

    for ef in (extra_findings or []):
        ev = ef.evidence or ""
        if getattr(ef, "impact", ""):
            ev += f"\n\nImpact: {ef.impact}"
        if getattr(ef, "asset", ""):
            ev = f"Asset: {ef.asset}\n\n" + ev
        if getattr(ef, "references", ""):
            ev += f"\n\nRef: {ef.references}"
        findings.append(Finding(
            title=ef.title,
            severity=(ef.severity or "medium").capitalize(),
            finding_type=ef.category or "finding",
            evidence=ev.strip(),
            remediation=ef.remediation or _REMEDIATION.get("vulnerability", ""),
        ))

    for vuln in getattr(attack_state, "vulnerabilities", []) or []:
        findings.append(_vuln_finding(vuln, records))

    for cred in getattr(attack_state, "credentials", []) or []:
        shown = _mask_secret(cred) if redact_secrets else cred
        findings.append(Finding(
            title="Exposed / captured credential",
            severity="High",
            finding_type="credential",
            evidence=str(shown),
            remediation=_REMEDIATION["credential"],
            discovered=_first_seen(records, "credential", cred),
        ))

    # Notable exposed services (from the port→service map) become their own
    # findings with service-specific severity + remediation.
    services = getattr(attack_state, "services", {}) or {}
    for port, service in services.items():
        rule = _service_rule(service)
        if rule:
            sev, fix = rule
            findings.append(Finding(
                title=f"Exposed {service} on port {port}",
                severity=sev,
                finding_type="service",
                evidence=f"{service} listening on port {port}",
                remediation=fix,
            ))

    for flag in getattr(attack_state, "flags", []) or []:
        findings.append(Finding(
            title="Flag captured (proof of access)",
            severity="Info",
            finding_type="flag",
            evidence=str(flag),
            remediation=_REMEDIATION["flag"],
            discovered=_first_seen(records, "flag", flag),
        ))

    timeline = [{"ts": r.get("ts", ""), "summary": _summarize_record(r)}
                for r in records if r.get("kind") in _TIMELINE_KINDS]
    tool_calls = [r for r in records if r.get("kind") == "tool_call"]

    meta = dict(metadata or {})
    meta.setdefault("Target", getattr(attack_state, "target", "") or "unknown")
    meta.setdefault("Phase reached", getattr(attack_state, "current_phase", ""))
    meta.setdefault("Open ports", ", ".join(getattr(attack_state, "open_ports", []) or []) or "none")

    return EngagementReport(
        target=getattr(attack_state, "target", "") or "",
        metadata=meta,
        findings=findings,
        timeline=timeline,
        tool_calls=tool_calls,
    )


_TIMELINE_KINDS = {"tool_call", "finding", "scope_refused", "delegate_start",
                   "session_start", "session_end"}


def _summarize_record(r: dict) -> str:
    kind = r.get("kind")
    if kind == "tool_call":
        status = "ok" if r.get("ok") else f"ERROR: {r.get('error')}"
        return f"ran {r.get('tool')} → {status}"
    if kind == "finding":
        return f"found {r.get('finding_type')}: {r.get('value')}"
    if kind == "scope_refused":
        return f"RoE refused {r.get('tool')} — {r.get('reason')}"
    if kind == "delegate_start":
        return f"delegated to {r.get('operator', 'sub-agent')}: {r.get('task', '')}"
    return kind.replace("_", " ") if kind else ""
