# Tools

Mapache exposes a curated toolset to the model. `shell` and `kali_run` are the
workhorses (any installed CLI tool runs through them); the tools below add structured
input handling and output parsing so the agent acts on real data instead of guessing.
Missing binaries degrade gracefully: the tool reports it and the agent adapts.

## Recon and discovery

| Tool | What it does |
|------|--------------|
| `nmap_scan` | Port and version scanning (standard / version / vuln script modes). |
| `web_fetch` | Fetch a URL and return readable content plus a parsed attack surface (real form actions and fields, referenced endpoints, HTML comments). |
| `web_search` | Web search (no API key). |
| `tech_detect` | Fingerprint the stack from response headers and body (server, framework, CDN, exposed docs). |
| `tor_fetch` | Fetch through Tor, including .onion. |
| `egress_check` | Report the public IP a target would see (OPSEC leak test). |

## Web exploitation

| Tool | What it does |
|------|--------------|
| `http_request` | Send arbitrary HTTP requests with structured body/headers/params. Every call is recorded for replay. |
| `http_repeater` | Burp-style repeater: list, show, replay, and tamper recorded requests, and diff responses. Replaying an authenticated request with one id changed and diffing the result is the IDOR / broken-access-control primitive. |
| `sqlmap` | Automated SQL injection. |
| `fuzz` | Directory and parameter fuzzing (ffuf-style). |
| `burp_scan`, `burp_proxy` | Burp integration when available. |
| `jwt_tool` | Parse, forge, alg=none, and crack JSON Web Tokens. |
| `graphql` | Introspect a GraphQL endpoint and flag ID-shaped arguments as IDOR candidates. |
| `llm_inject` | Test an LLM-backed target for prompt injection (OWASP LLM01), confirmed with a canary. |

## Knowledge and grounding

| Tool | What it does |
|------|--------------|
| `search_payloads` | Look up real payloads/techniques from an offline corpus by vuln class and keyword. |
| `secret_scan` | Scan text or files for exposed secrets (keys, tokens, private keys, connection strings). |
| `cve_lookup` | Correlate a service/version to CVEs from the offline catalog. |

## Exploitation and post-exploitation

| Tool | What it does |
|------|--------------|
| `msf_search`, `msf_run`, `msf_sessions` | Metasploit search, run, and session management. |
| `searchsploit` | Exploit-DB search. |
| `john_crack`, `john_identify` | Hash cracking and identification. |
| `ad_attack` | Active Directory: kerberoast, asreproast, secretsdump/dcsync, bloodhound, certipy. Builds correct syntax and parses Kerberos/NTLM loot and ADCS misconfigs. |
| `binary_analyze` | Binary triage: protections (checksec), interesting strings, dangerous imports, ROP gadgets. |
| `cloud_metadata` | Query cloud metadata services (AWS IMDSv2, ECS, GCP, Azure) for credentials. |

## Reporting, memory, and orchestration

| Tool | What it does |
|------|--------------|
| `report_finding` | Record a confirmed finding (title, severity, asset, evidence, impact, remediation). The deliverable. |
| `kg_add`, `kg_query` | Read and write the shared findings knowledge graph across sub-agents. |
| `memory_save`, `memory_recall`, `memory_target_store` | Persistent memory across sessions. |
| `opplan_add`, `opplan_update`, `opplan_show` | Operation plan objectives for the supervisor. |
| `delegate`, `delegate_parallel` | Hand a bounded objective to a specialist sub-agent. |
| `vuln_research` | Seed the staged vuln-research pipeline (scanner, detector, verifier, patcher, exploiter). |
| `create_tool`, `tool_list_generated`, `tool_delete` | Author, list, and retire self-written tools. |
| `shell`, `kali_run`, `file_read/write/edit/list/search` | Run commands and touch the filesystem. |
