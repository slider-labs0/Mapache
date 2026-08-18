# Mapache Documentation

Mapache is an autonomous offensive-security agent. You give it an objective in plain
language ("pentest 10.0.0.5", "find the IDOR in the app at http://target/") and it
works the engagement one tool call at a time: it enumerates, exploits, escalates, and
hands back a report of proven findings with remediation.

This directory is the full reference. Start with the overview, then dive into the area
you care about.

## Contents

| Doc | What it covers |
|-----|----------------|
| [Architecture](architecture.md) | The ReAct agent loop, the controller, attack state, phases, context building, the event bus |
| [Model routing and multi-model agents](model-routing.md) | Single vs per-role vs swarm, how sub-agents pick their model, OPSEC pinning, cost tiering |
| [Multi-agent orchestration](multi-agent.md) | Delegation, the operator roster, the autonomous supervisor, parallel fan-out, the shared blackboard |
| [Skills and playbooks](skills-and-playbooks.md) | The built-in domain playbooks, SKILL.md authoring, hybrid activation, bundled resources |
| [Tools](tools.md) | The offensive toolchain, meta-tools, self-authored tools, the curator |
| [Providers](providers.md) | Local Ollama, cloud providers, native Chinese providers, gateways |
| [Execution and OPSEC](execution-and-opsec.md) | Execution backends, egress anonymization, rules of engagement, the audit log, self-defense |
| [Memory](memory.md) | Session memory, notes, the knowledge store, the vector store, the knowledge graph, cross-engagement learning |
| [Middleware](middleware.md) | The composable loop-middleware framework and the built-in middlewares |
| [Reporting](reporting.md) | The deterministic report builder, export formats, SARIF and bounty output |
| [MCP and the skill hub](mcp-and-hub.md) | Connecting to Model Context Protocol servers, installing and publishing community skills and tools |
| [User interface](ui.md) | The CLI, the full-screen TUI dashboard, the setup wizard, every slash command |
| [Configuration](configuration.md) | The config file, environment variables, every option |
| [Use cases](use-cases.md) | End-to-end walkthroughs for web, network, cloud, Active Directory, binary, mobile, and more |

## First run

```bash
git clone https://github.com/slider-labs0/Mapache.git && cd Mapache
python3 -m venv .venv && source .venv/bin/activate
pip install -e .        # installs the `mapache` command
mapache setup           # interactive: pick a provider and a model
mapache serve           # launch the agent
```

Requires Python 3.10 or newer. Kali or ParrotOS is the recommended platform because
the offensive toolchain is packaged there. For local models install
[Ollama](https://ollama.com); for cloud models set the provider key and pass
`--allow-cloud`.

## Safety

Mapache is for authorized security testing only: engagements you own or have written
permission to test. It enforces a rules-of-engagement scope, but scope is a guardrail,
not a guarantee. You are responsible for staying in bounds and for complying with
applicable law. See [Execution and OPSEC](execution-and-opsec.md) for the guardrails.
