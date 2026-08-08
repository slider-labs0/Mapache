"""
exporters.py — additional report formats for real-world deliverables.

Beyond the Markdown/HTML engagement report, real users need machine + platform
formats: SARIF (CI/CD & GitHub code-scanning), a representative CVSS band, and a
bug-bounty submission draft (HackerOne/Bugcrowd style). These operate on the
evidence-first core.findings.Finding objects.
"""

from __future__ import annotations

import json
from typing import Any

# Representative CVSS v3.1 base score + severity band per qualitative severity.
_CVSS_BAND = {"critical": 9.5, "high": 8.1, "medium": 5.5, "low": 3.1, "info": 0.0}
# SARIF level per severity.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def cvss_band(severity: str) -> float:
    """A representative CVSS v3.1 base score for a qualitative severity."""
    return _CVSS_BAND.get((severity or "medium").lower(), 5.5)


def to_sarif(findings: list, *, tool_name: str = "Mapache") -> str:
    """Render findings as SARIF 2.1.0 (GitHub code-scanning / CI ingestible)."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rule_id = f.category or "finding"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": f.remediation or rule_id},
                "helpUri": "",
                "properties": {"security-severity": str(cvss_band(f.severity))},
            }
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get((f.severity or "medium").lower(), "warning"),
            "message": {"text": f"{f.title}\n\n{f.evidence}".strip()},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.asset or "engagement"}}}],
            "properties": {"impact": f.impact, "remediation": f.remediation,
                           "confidence": f.confidence, "references": f.references},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def to_bounty_markdown(f: Any) -> str:
    """A single-finding bug-bounty submission draft (HackerOne/Bugcrowd sections)."""
    L = [f"# {f.title}", "",
         f"**Severity:** {f.severity.capitalize()} (CVSS ~{cvss_band(f.severity)})  ",
         f"**Weakness:** {f.category}"
         + (f" — {f.references}" if f.references else ""), ""]
    if f.asset:
        L += [f"**Affected asset:** `{f.asset}`", ""]
    L += ["## Summary", "",
          f.impact or "A security weakness was identified in the target.", "",
          "## Steps to reproduce / Proof of concept", "", "```", (f.evidence or "").strip(), "```", "",
          "## Impact", "", f.impact or "(see summary)", "",
          "## Remediation", "", f.remediation or "(see references)", ""]
    return "\n".join(L) + "\n"


def to_bounty_bundle(findings: list) -> str:
    """All findings as bug-bounty drafts, worst-first."""
    return "\n\n---\n\n".join(to_bounty_markdown(f) for f in findings)
