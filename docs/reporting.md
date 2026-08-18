# Reporting

Mapache is evidence-first: success is a proven finding with severity, evidence, impact,
and remediation, not a captured flag. This page covers how it turns an engagement into a
report and what formats it exports.

## The report builder

`reporting/report_builder.py` turns the audit-log records and the attack-state blackboard
into a structured pentest report:

- Findings for vulnerabilities, captured credentials, notable exposed services (telnet,
  SMB, RDP, Redis, and others), and flags, each with a severity and concrete remediation.
- First-seen timestamps taken from the audit log.
- An executive summary with a severity tally.
- A methodology timeline.
- A tool-activity appendix.

The builder is deterministic and offline. It makes no LLM call, so it is reproducible,
testable, and never sends findings to a third party. This keeps the local-first OPSEC
story intact from end to end.

## Export formats

- Markdown for readability and version control.
- Self-contained HTML (print it to get a PDF).
- SARIF for ingestion into code-scanning and security dashboards.
- A bug-bounty draft for submission.

Optional secret redaction removes captured credentials from the exported copy.

Generate a report with `/report [md|html|both]`, which writes to `engagements/`.

## Grounding and scoring

Findings can be correlated to known CVEs with severity and exploit availability from an
offline catalog (`cve_lookup`). An optional LLM narrative pass and precise CVSS scoring
are layered enhancements on top of the deterministic core, so you can add polish without
giving up reproducibility.

## Why evidence-first matters

Most agents invent endpoints, field names, and payloads and then declare victory. Mapache
reads a target's real forms, endpoints, and disclosed credentials into state, looks up
payloads from an offline corpus, and detects dead attack vectors so it changes approach
instead of spinning. A finding in the report is backed by the exact request or command
that proved it, recorded in the audit log with a timestamp.
