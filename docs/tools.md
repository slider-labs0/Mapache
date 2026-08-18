# Tools

Mapache drives roughly fifty registered tools plus a set of meta-tools. Tools are
structured: the model calls them with typed arguments, the result comes back as
structured output, and schema validation catches a malformed call so the model can
self-correct. This page groups the toolchain by area.

## Execution and files

- `shell` runs a command on the active execution backend (local, Docker, or SSH).
- `code_run` is a compile, run, and fix loop. It writes code (Python, C, C++, Go, Rust,
  Bash, and more), compiles it, runs it, and iteratively fixes it, staging into the active
  target and returning a structured verdict (compile failed, exit code, or ok). This is
  the exploit-writing primitive.
- `file_read`, `file_write`, `file_edit`, `file_list`, and `file_search` operate on files.

## Recon and network

- `nmap_scan` runs structured port and service scans with schema validation. If the model
  omits the target, it is backfilled from the attack state.
- `kali_run` and `kali_list` drive the packaged Kali tooling; `searchsploit` looks up
  ExploitDB.
- Operators drive domain CLIs (aws, kubectl, frida, ghidra, jadx, gophish, and others)
  through `shell` and `kali_run`.

## Web

- `http_request` sends a structured HTTP request. Because it is structured JSON, payloads
  with quotes survive intact, unlike a shell curl. This is the primitive for API testing.
- `http_repeater` records, replays, tampers, and diffs requests. It is the primitive
  behind broken-access-control and IDOR testing.
- `web_fetch` and `web_search` read the surface web; `tor_fetch` routes through Tor.
- `browser` is a real headless browser (Playwright) that renders JavaScript and single-page
  apps, so the agent sees what a user sees.
- `sqlmap` and `fuzz` (ffuf) are disciplined wrappers around those classic tools.
- Response-grounded acting nudges the agent off blind endpoint spraying and toward the
  target's real forms and endpoints.

## Exploitation and cracking

- `msf_search` and the Metasploit integration drive MSFRPC.
- The Burp Suite integration uses the REST API and proxy.
- `john` identifies and cracks hashes; hashcat and hydra are available through the Kali
  interface.

## Grounding and research

- `cve_lookup` correlates discovered services and versions to known CVEs with severity and
  exploit availability, from an offline catalog.
- `vuln_research` starts the vulnerability-research pipeline (scanner, detector, verifier,
  patcher, exploiter).
- A payload corpus with a search tool provides known-good payloads instead of guesses.

## Memory and planning meta-tools

- `kg_query` and `kg_add` read and write the knowledge graph (the findings store).
- `opplan_show`, `opplan_add`, and `opplan_update` manage the operation plan.
- The persistent task list is seeded by a plan response and updated with a todo update.

## Delegation meta-tools

- `delegate(task, operator=...)` spawns a focused specialist child for one subtask.
- `delegate_parallel(tasks=[...])` fans several operators out over the shared blackboard.

See [Multi-agent orchestration](multi-agent.md) for how these behave.

## Self-authored tools

The `create_tool` meta-tool lets the model author a brand-new reusable tool at runtime. It
writes the body of an async run function, which is compiled (errors are handed back for
self-correction) and persisted as a hub-installable package under
`plugins/generated/<name>/` with a manifest carrying origin, usage, lifecycle state,
phase, and a sha256 checksum. The tool registers into the tool registry and becomes
callable on the next loop iteration, never in the same response that created it.

Trust model: an agent-written tool (origin self) loads freely; a downloaded tool (origin
hub) is sha256-verified before it compiles and refuses to load if it has been tampered
with. The startup loader is fail-soft, so a bad tool never breaks startup.

Model-facing tools: `create_tool`, `tool_list_generated`, `tool_delete`.

## The curator (tool-library garbage collection)

Self-authored tools move through a reversible lifecycle: active, then stale, then
archived, so the create-tools loop cannot pile up. A usage rule auto-demotes an unused
tool to stale (a non-destructive label; using it promotes it back to active). The only
permissioned step is stale to archived: `/curate` proposes stale tools one at a time and,
on your per-tool approval, unregisters them and moves their folder out of the load path.
`/restore <name>` reverses it, and `/purge <name>` hard-deletes an already-archived tool
as a deliberate two-step.

## MCP tools

Tools exposed by a connected Model Context Protocol server appear as ordinary Mapache
tools named `mcp__<server>__<tool>`. See [MCP and the skill hub](mcp-and-hub.md).
