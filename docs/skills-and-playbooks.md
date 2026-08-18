# Skills and playbooks

A skill is a compact playbook injected into the model's context at the right moment, so a
weak model is grounded on the right technique without bloating every call. Mapache ships
built-in playbooks for every domain and lets you author or import your own as SKILL.md
files.

## Built-in playbooks

Fifteen just-in-time playbooks cover the full spectrum: web, network service, credential,
Active Directory, cloud, binary exploitation, mobile, social engineering, smart
contracts and Web3, supply chain, ICS and OT, IoT and firmware, wireless, OSINT, and DFIR
and purple team. Each one is a concrete, imperative body of guidance (tools, endpoints,
payloads, proof) that is injected only while it is relevant.

The result is that Mapache is not web-only. Every domain operator has injected method.

## How activation works (hybrid)

Mapache uses a hybrid of two activation mechanisms, chosen so the fast path stays free and
offline while foreign skills still activate.

### Predicate matching (the fast path)

Each built-in playbook carries a deterministic predicate over the attack state and the
request: open ports, the target scheme, and keywords. When the predicate fires, the body
is injected. This path is instant, offline, and free, and it is what the built-in domain
playbooks use.

### Model-based selection (for description-only skills)

For skills that carry a description but whose predicate does not fire, which is the case
for trigger-less skills imported from other agents, a model reads a compact catalog of
those skills and selects which apply to the current objective and attack state. The
selection is cached by a signature of the engagement state, so the extra model call fires
only when the situation materially changes, and any failure falls back to selecting
nothing. This lets a foreign skill activate without hand-adding triggers, while the
built-in playbooks keep their zero-cost predicate path.

## Authoring a SKILL.md

A skill is a Markdown file with YAML frontmatter and a body. All trigger fields are
optional; a skill with none never auto-injects on the fast path, and instead relies on
model-based selection through its description.

```markdown
---
name: lfi_ssrf
description: Local file inclusion and SSRF playbook
when_to_use: When a parameter takes a path or a URL
ports: [80, 443, 8080]
keywords: [lfi, ssrf, file=, url=]
target_scheme: [http, https]
phase: exploitation
tools: [http_request]
---
ACTIVE PLAYBOOK: describe the technique here. This body is injected into the model's
context verbatim whenever the skill matches, so write it as concrete, imperative
guidance: tools, endpoints, payloads, and how to prove the finding.
```

Fields:

- `name` (required) and `description` (used for model-based selection).
- `when_to_use` is a human-readable hint.
- `ports`, `keywords`, and `target_scheme` are the fast-path triggers.
- `phase` and `tools` are advisory.
- `allowed-tools` is accepted for compatibility with skills authored for other agents.

The YAML parser handles inline lists, block-style lists, and multi-line scalars, so
richer skills authored for other agents parse faithfully. It uses PyYAML when installed
and a dependency-free parser otherwise.

## Loading skills

Drop skills into `~/.mapache/skills/` (global) or `<workspace>/skills/` (per project).
Both layouts load:

- Flat single files: `skills/my_skill.md`.
- Nested packages: `skills/my-skill/SKILL.md`, discovered recursively.

A nested package can ship bundled resource files (scripts and reference documents)
alongside its `SKILL.md`. When the skill activates, the injected text lists those files
with their paths, so the agent can read a reference with its file tools or run a bundled
script with `code_run` or `shell`. This is progressive disclosure: the playbook prose is
always available, and the heavier resources are opened on demand.

## Compatibility with skills authored for other agents

The container format (SKILL.md with YAML frontmatter and a Markdown body) matches the
common convention, so the prose of another agent's skill is reusable and its `name` and
`description` parse cleanly. Unknown frontmatter keys are ignored rather than causing
errors. The differences to keep in mind:

- Activation in Mapache is by trigger or by model-based selection over the description,
  not purely by the model reading the description at will.
- Bundled scripts are surfaced for the agent to run with its existing tools rather than
  executed automatically.

To reuse a foreign skill, copy its SKILL.md into a skills directory, add trigger
frontmatter if you want the fast path, and re-home any bundled scripts.

## Skill synthesis

Mapache can also write a new skill from a proven chain. The `synthesize_skill` tool saves
the current winning sequence of actions as a reusable, signed skill, so a technique that
worked once can be replayed and shared.
