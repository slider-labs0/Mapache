# Execution and OPSEC

This page covers where Mapache runs its commands, how it anonymizes its traffic, how it
stays inside an authorized scope, how it records what it did, and how it defends itself.

## Execution backends

Every shell and tool command runs on an execution backend. The backend is selected in
config (`execution.backend`) or with `/backend`.

- Local: commands run on the host that runs Mapache. The default.
- Docker: commands run inside a container through docker exec. This is how Mapache runs a
  Linux toolchain on a Windows host, and how it isolates an engagement from the host.
- SSH: commands run on a remote host over SSH.

A backend returns a structured result (stdout, stderr, exit code) so tools behave the same
regardless of where they run. Sub-agents can be given their own backend, so a specialist's
shell and scans run in an isolated container while the lead coordinates.

## Egress and anonymity

Mapache can route its attack traffic to hide the operator's origin. The egress mode is set
in config (`egress.mode`) or with `/egress`:

- direct: no anonymization.
- proxy: route through an HTTP or SOCKS proxy.
- tor: route through Tor. Mapache detects Tor and guides setup.

When egress is active the CLI shows it at startup, and web and fetch tools honor it.

## Rules of engagement (scope)

An authorized test has a scope: the targets you are allowed to touch. Mapache enforces it
with an optional `scope.json` in the working directory (or `--scope <path>`).

```json
{
  "name": "ACME external pentest",
  "targets": ["10.10.10.0/24", "acme.example.com"],
  "forbidden_tools": ["msf_run"],
  "forbidden_patterns": ["rm -rf", "shutdown", "mkfs"],
  "allow_loopback": true
}
```

- `targets` is an allowlist of IPs, CIDRs, and hostnames. Hostnames match subdomains.
- `forbidden_tools` blocks named tools entirely.
- `forbidden_patterns` blocks any argument matching a pattern (destructive commands).
- `allow_loopback` permits local utility calls (default true).

The gate runs in the dispatch path, after the target is backfilled from the attack state
and before the tool runs. An out-of-scope or forbidden call is refused, never dispatched,
and the refusal is fed back to the model, which then changes approach. A defense-in-depth
re-check covers generated-tool shell calls that bypass the controller, and sub-agents
inherit the scope so delegation stays bounded.

Scope is inactive when no `scope.json` is present, so the default behavior is unchanged.
Host extraction favors precision (IPs from any argument, bare hostnames only from
target-shaped keys and URLs) so a wordlist path is not mistaken for a target. The CLI
shows a startup banner, a `/scope` command, and a live refused line when a call is
blocked.

## The audit log

Mapache keeps an append-only JSONL trail of the whole session, fed purely by the event
bus. It records every tool call with arguments and outcome, every finding (flag,
credential, vulnerability, open port), every scope refusal, and the delegate and verify
events, one flushed line per record so it survives a crash and is frozen after the session
closes.

It is on by default (writes to `engagements/`, which is gitignored; disable with
`--no-engagement-log`). `/log` shows it and `/log export` renders a Markdown findings list
and timeline, which is the seed for the report.

## Self-defense and containment

Mapache defends itself and contains the target side.

- Prompt-injection shield: the agent is hardened against instructions embedded in a
  target's responses (a page, a banner, a file) trying to hijack the agent. Injected
  content is treated as data, not as operator instructions.
- Isolated-lab containment: running the engagement through the Docker or SSH backend keeps
  the target's shell and tools off the host. The scope gate guards the target side; the
  injection shield guards the agent side.

## OPSEC routing

When cloud is allowed, sensitive work can still be pinned to a local model so loot and
credentials never leave the host. This is decided per sub-agent based on the operator and
whether credentials have already been captured. See
[Model routing](model-routing.md) for the full pipeline, and `/opsec` to see which
operations are pinned local.
