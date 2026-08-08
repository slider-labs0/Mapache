# Reporting

Mapache is evidence-first: success is a proven finding with remediation, not a captured
flag. A confirmed weakness is recorded as a structured finding and rendered into a report
the operator can hand off.

## Findings

The agent records a finding with the `report_finding` tool the moment it confirms a
weakness. A finding carries:

- title, severity (critical / high / medium / low / info), category
- affected asset (host / URL / endpoint / parameter)
- evidence: the actual request and response, command output, or observation that proves it
- impact and remediation (auto-filled from the category if omitted)

`report_finding` rejects a finding with no evidence, so unproven or guessed findings do
not enter the report. Findings dedupe by category, asset, and title, keeping the richest
evidence.

## Report formats

Generate a report from the REPL with `/report <format>`, or it is written automatically
at the end of a session if anything was found.

| Format | Output |
|--------|--------|
| `md` | Markdown report: executive summary, per-finding detail with evidence and remediation, methodology timeline. |
| `html` | Self-contained HTML version of the same. |
| `both` | Markdown + HTML. |
| `sarif` | SARIF 2.1.0 for CI / code-scanning ingestion. |
| `bounty` | Bug-bounty submission drafts (HackerOne / Bugcrowd sections) per finding. |
| `all` | Every format above. |

Reports are written under `engagements/` in the working directory. The findings store
also persists to `findings.json`. Blackboard facts (ports, services, exposed
credentials) are folded in alongside the agent-authored findings, so the report is
complete even for findings the agent did not explicitly write up.
