"""
reporting_tools.py - the agent's evidence-first deliverable tool.

`report_finding` is how the agent turns a confirmed weakness into a real report
entry: title, severity, affected asset, the EVIDENCE that proves it, impact, and
remediation (auto-filled from the category if the agent omits it). This is the
engagement's deliverable - a finding with proof is success on a real target,
whether or not a CTF flag exists.
"""

from __future__ import annotations

from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from core.findings import FindingsStore, Finding, SEVERITIES


class ReportFindingTool(BaseTool):
    name = "report_finding"
    description = (
        "Record a CONFIRMED security finding into the engagement report - the real "
        "deliverable. Call this whenever you prove a weakness (an IDOR that returned "
        "another user's data, an injection that executed, exposed credentials, a "
        "misconfig), NOT just when you capture a flag. Provide the EVIDENCE: the actual "
        "request+response, command output, or observation that proves it. Impact and "
        "remediation are auto-filled from the category if you omit them, but better if "
        "you tailor them. Severity: critical | high | medium | low | info."
    )
    parameters = {
        "type": "object",
        "properties": {
            "title": {"type": "string",
                      "description": "Short finding title, e.g. 'IDOR on /account?id exposes other users'"},
            "severity": {"type": "string",
                         "description": "critical | high | medium | low | info", "default": "medium"},
            "category": {"type": "string",
                         "description": "Vuln class: idor, sql, xss, ssrf, ssti, rce, lfi, "
                         "credential, default-cred, auth, misconfig, info-disclosure, cve"},
            "asset": {"type": "string",
                      "description": "Affected host / URL / endpoint / parameter"},
            "evidence": {"type": "string",
                         "description": "PROOF: the request+response, command output, or "
                         "observation that demonstrates the finding"},
            "impact": {"type": "string", "description": "What an attacker can do (optional; auto-filled)"},
            "remediation": {"type": "string", "description": "How to fix it (optional; auto-filled)"},
            "confidence": {"type": "string",
                           "description": "confirmed | probable | possible", "default": "confirmed"},
            "references": {"type": "string", "description": "Optional CWE/CVE/OWASP refs"},
        },
        "required": ["title", "evidence"],
    }
    permissions: set = set()  # pure record-keeping, no system access
    tags = ["reporting", "findings", "deliverable"]

    def __init__(self, store: Optional[FindingsStore] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.store = store if store is not None else FindingsStore()

    async def execute(self, title: str, evidence: str = "", severity: str = "medium",
                      category: str = "other", asset: str = "", impact: str = "",
                      remediation: str = "", confidence: str = "confirmed",
                      references: str = "", **kwargs: Any) -> ToolResult:
        if not title.strip():
            return ToolResult.fail("A finding needs a title.")
        if not evidence.strip():
            return ToolResult.fail(
                "A finding needs evidence - the request/response, output, or observation "
                "that proves it. Don't report unproven or guessed findings.")
        f = self.store.record(
            title=title.strip(), severity=severity, category=category or "other",
            asset=asset.strip(), evidence=evidence.strip(), impact=impact.strip(),
            remediation=remediation.strip(), confidence=confidence.strip() or "confirmed",
            references=references.strip(), source=kwargs.get("_operator", ""))
        c = self.store.counts()
        badge = ", ".join(f"{c[s]} {s}" for s in SEVERITIES if c[s])
        return ToolResult.ok(
            f"Recorded finding [{f.severity.upper()}] {f.title} on {f.asset or '(asset n/a)'}.\n"
            f"Report now holds {len(self.store)} finding(s): {badge}.\n"
            f"Impact: {f.impact or '(none)'}\nRemediation: {f.remediation or '(none)'}",
            metadata={"severity": f.severity, "category": f.category,
                      "total_findings": len(self.store)})
