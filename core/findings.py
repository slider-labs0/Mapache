"""
findings.py — evidence-first engagement findings (the real deliverable).

A CTF scores a `FLAG{}`; a real authorized engagement produces a *report*: for each
confirmed weakness, WHAT it is, WHERE, the EVIDENCE that proves it, the IMPACT, and
the REMEDIATION. Mapache previously recorded findings as bare `finding_type: value`
strings — no severity, no proof, no fix. This module makes a Finding a first-class,
evidence-carrying object and renders a proper report, so success is a usable
deliverable, not a flag string.

Dependency-free and deterministic, like engagement_log / knowledge_graph.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Ordered worst→best so counts/sorting are trivial.
SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def normalize_severity(s: str) -> str:
    s = (s or "").strip().lower()
    aliases = {"crit": "critical", "hi": "high", "med": "medium", "moderate": "medium",
               "lo": "low", "informational": "info", "information": "info", "none": "info"}
    s = aliases.get(s, s)
    return s if s in _SEV_RANK else "medium"


# Category → default impact + remediation + CWE, so even a terse agent finding gets
# real, actionable remediation text auto-filled. Keys are matched case-insensitively
# by substring, so "broken access control (idor)" resolves to the idor entry.
REMEDIATION: dict[str, dict[str, str]] = {
    "idor": {
        "impact": "An authenticated user can read or modify other users' objects by "
                  "changing an identifier, breaking tenant/user isolation.",
        "remediation": "Enforce object-level authorization on every request: check that "
                       "the current principal owns/may access the referenced object "
                       "server-side. Prefer unguessable IDs (UUIDs) and deny-by-default.",
        "cwe": "CWE-639 (Authorization Bypass Through User-Controlled Key)"},
    "broken-access-control": {
        "impact": "A user can reach functionality or data outside their privilege level.",
        "remediation": "Centralize access-control checks server-side, deny by default, and "
                       "verify role/ownership on every sensitive route and object.",
        "cwe": "CWE-284 (Improper Access Control)"},
    "sql": {
        "impact": "An attacker can read, modify, or destroy database contents and may "
                  "achieve authentication bypass or code execution.",
        "remediation": "Use parameterized queries / prepared statements; never concatenate "
                       "user input into SQL. Apply least-privilege DB accounts and input "
                       "validation as defense in depth.",
        "cwe": "CWE-89 (SQL Injection)"},
    "xss": {
        "impact": "An attacker can run script in victims' browsers to steal sessions, "
                  "credentials, or perform actions as the victim.",
        "remediation": "Contextually output-encode all untrusted data, set a strict "
                       "Content-Security-Policy, and use framework auto-escaping. Validate "
                       "input server-side.",
        "cwe": "CWE-79 (Cross-site Scripting)"},
    "ssrf": {
        "impact": "The server can be coerced into making requests to internal services or "
                  "cloud metadata, exposing credentials or internal systems.",
        "remediation": "Allowlist outbound destinations, block link-local/metadata ranges "
                       "(169.254.169.254), disable unused URL schemes, and require "
                       "authentication on internal services.",
        "cwe": "CWE-918 (Server-Side Request Forgery)"},
    "ssti": {
        "impact": "Template injection typically leads to remote code execution on the server.",
        "remediation": "Never render user input as a template; use logic-less templates or "
                       "sandboxed evaluation and strict input validation.",
        "cwe": "CWE-1336 (Server-Side Template Injection)"},
    "rce": {
        "impact": "An attacker can execute arbitrary commands/code on the host, a full "
                  "compromise.",
        "remediation": "Eliminate the injection sink; avoid passing input to shells/eval. "
                       "Use safe APIs, allowlists, and run with least privilege.",
        "cwe": "CWE-78 (OS Command Injection)"},
    "lfi": {
        "impact": "An attacker can read arbitrary files (secrets, source, config) and may "
                  "escalate to code execution.",
        "remediation": "Canonicalize and allowlist file paths; never build filesystem paths "
                       "from raw user input; run with least privilege.",
        "cwe": "CWE-22 (Path Traversal)"},
    "credential": {
        "impact": "Exposed credentials allow an attacker to authenticate as a legitimate "
                  "user or service.",
        "remediation": "Rotate the exposed secret immediately, remove it from code/comments/"
                       "responses, store secrets in a vault, and enforce MFA.",
        "cwe": "CWE-522 (Insufficiently Protected Credentials)"},
    "default-cred": {
        "impact": "Default/guessable credentials let anyone authenticate.",
        "remediation": "Remove default/test accounts, force a strong password on first use, "
                       "and enforce a password policy + MFA.",
        "cwe": "CWE-1392 (Use of Default Credentials)"},
    "auth": {
        "impact": "An attacker can bypass authentication and act as another user.",
        "remediation": "Fix the auth logic, use vetted session management, enforce MFA, and "
                       "invalidate sessions server-side on logout.",
        "cwe": "CWE-287 (Improper Authentication)"},
    "misconfig": {
        "impact": "A misconfiguration exposes data or functionality unintentionally.",
        "remediation": "Harden the configuration to least privilege, disable debug/verbose "
                       "modes in production, and review defaults against a benchmark.",
        "cwe": "CWE-16 (Configuration)"},
    "info-disclosure": {
        "impact": "Sensitive information is exposed that aids further attacks.",
        "remediation": "Remove sensitive data from responses/errors/headers and restrict "
                       "access to diagnostic endpoints.",
        "cwe": "CWE-200 (Exposure of Sensitive Information)"},
    "cve": {
        "impact": "A known vulnerability in a deployed component is exploitable.",
        "remediation": "Patch/upgrade the affected component to a fixed version; apply "
                       "vendor mitigations until then.",
        "cwe": "CWE-1035 (Using Components with Known Vulnerabilities)"},
}

# vuln-class keyword → REMEDIATION key, for auto-categorizing a free-text finding.
_CATEGORY_HINTS = [
    ("idor", "idor"), ("bola", "idor"), ("insecure direct object", "idor"),
    ("access control", "broken-access-control"), ("authz", "broken-access-control"),
    ("privilege", "broken-access-control"), ("sqli", "sql"), ("sql inject", "sql"),
    ("xss", "xss"), ("cross-site script", "xss"), ("ssrf", "ssrf"),
    ("ssti", "ssti"), ("template inject", "ssti"), ("rce", "rce"),
    ("command inject", "rce"), ("code execution", "rce"), ("lfi", "lfi"),
    ("path traversal", "lfi"), ("directory traversal", "lfi"),
    ("default cred", "default-cred"), ("default password", "default-cred"),
    ("credential", "credential"), ("password", "credential"), ("secret", "credential"),
    ("api key", "credential"), ("token", "credential"), ("auth bypass", "auth"),
    ("authentication", "auth"), ("login", "auth"), ("misconfig", "misconfig"),
    ("disclosure", "info-disclosure"), ("cve-", "cve"),
]


def categorize(text: str) -> str:
    low = (text or "").lower()
    for needle, cat in _CATEGORY_HINTS:
        if needle in low:
            return cat
    return "other"


def _remediation_for(category: str) -> dict[str, str]:
    cat = (category or "").lower()
    for key, entry in REMEDIATION.items():
        if key in cat:
            return entry
    return {"impact": "", "remediation": "", "cwe": ""}


@dataclass
class Finding:
    title: str
    severity: str = "medium"
    category: str = "other"
    asset: str = ""              # affected host / URL / endpoint / parameter
    evidence: str = ""           # the PROOF: request/response, command output, observation
    impact: str = ""
    remediation: str = ""
    confidence: str = "confirmed"  # confirmed | probable | possible
    references: str = ""
    source: str = ""             # which operator/tool recorded it
    ts: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if self.category in ("", "other"):
            self.category = categorize(f"{self.title} {self.evidence}")
        auto = _remediation_for(self.category)
        if not self.impact:
            self.impact = auto.get("impact", "")
        if not self.remediation:
            self.remediation = auto.get("remediation", "")
        if not self.references and auto.get("cwe"):
            self.references = auto["cwe"]

    def key(self) -> tuple[str, str, str]:
        return (self.category, self.asset.lower(), self.title.lower())

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "severity": self.severity, "category": self.category,
                "asset": self.asset, "evidence": self.evidence, "impact": self.impact,
                "remediation": self.remediation, "confidence": self.confidence,
                "references": self.references, "source": self.source, "ts": self.ts}


class FindingsStore:
    """Collects evidence-carrying findings, dedups, and renders the report."""

    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else None
        self._by_key: dict[tuple, Finding] = {}

    def add(self, finding: Finding) -> Finding:
        k = finding.key()
        existing = self._by_key.get(k)
        if existing is not None:
            # Merge: keep the richer evidence and the worse (lower-rank) severity.
            if len(finding.evidence) > len(existing.evidence):
                existing.evidence = finding.evidence
            if _SEV_RANK[finding.severity] < _SEV_RANK[existing.severity]:
                existing.severity = finding.severity
            finding = existing
        else:
            self._by_key[k] = finding
        self.save()
        return finding

    def record(self, **kw: Any) -> Finding:
        return self.add(Finding(**kw))

    def all(self) -> list[Finding]:
        return sorted(self._by_key.values(),
                      key=lambda f: (_SEV_RANK[f.severity], -f.ts))

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self._by_key.values():
            c[f.severity] += 1
        return c

    def __len__(self) -> int:
        return len(self._by_key)

    def to_json(self) -> str:
        return json.dumps({"findings": [f.to_dict() for f in self.all()],
                           "counts": self.counts()}, indent=2)

    def render_markdown(self, *, title: str = "Engagement Findings",
                        target: str = "") -> str:
        findings = self.all()
        c = self.counts()
        lines = [f"# {title}", ""]
        if target:
            lines.append(f"**Target:** {target}  ")
        total = len(findings)
        badge = " · ".join(f"{c[s]} {s}" for s in SEVERITIES if c[s])
        lines.append(f"**Findings:** {total}" + (f" ({badge})" if badge else ""))
        lines.append("")
        if not findings:
            lines.append("_No confirmed findings were recorded for this engagement._")
            return "\n".join(lines) + "\n"
        # Executive summary table.
        lines += ["## Summary", "", "| # | Severity | Finding | Asset |",
                  "|---|---|---|---|"]
        for i, f in enumerate(findings, 1):
            lines.append(f"| {i} | {f.severity.upper()} | {f.title} | "
                         f"{f.asset or '—'} |")
        lines.append("")
        # Per-finding detail.
        lines.append("## Details")
        for i, f in enumerate(findings, 1):
            lines += ["", f"### {i}. {f.title}",
                      f"- **Severity:** {f.severity.upper()}",
                      f"- **Category:** {f.category}",
                      f"- **Confidence:** {f.confidence}"]
            if f.asset:
                lines.append(f"- **Affected asset:** `{f.asset}`")
            if f.references:
                lines.append(f"- **References:** {f.references}")
            if f.impact:
                lines += ["", f"**Impact:** {f.impact}"]
            if f.evidence:
                lines += ["", "**Evidence:**", "", "```", f.evidence.strip()[:4000], "```"]
            if f.remediation:
                lines += ["", f"**Remediation:** {f.remediation}"]
        return "\n".join(lines) + "\n"

    def save(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(self.to_json() + "\n", encoding="utf-8")
        except OSError:
            pass

    def write_report(self, md_path: str | Path, *, target: str = "") -> Path:
        md_path = Path(md_path)
        try:
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(self.render_markdown(target=target), encoding="utf-8")
        except OSError:
            pass
        return md_path
