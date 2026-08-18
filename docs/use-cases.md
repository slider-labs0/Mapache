# Use cases

This page walks through end-to-end engagements across disciplines. Each one shows a target
to practice against, the prompt to give Mapache, what the agent does, and what you get
back. All targets here are ones you run yourself or are authorized to test.

A reminder: Mapache is for authorized testing only. Put a `scope.json` in your working
directory so the rules-of-engagement gate is active (see
[Execution and OPSEC](execution-and-opsec.md)).

## Web application pentest

Target: OWASP Juice Shop, a modern deliberately-vulnerable web app.

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Prompt:

```
You're authorized to test the web app at http://localhost:3000, which I own. Get
administrator access, prove it with concrete evidence, and give me a finding with
severity, impact, and remediation.
```

What happens: the web playbook activates because the target is a URL. Mapache reads the
real login form and its endpoint with `http_request` (not a guessed path), tests the email
field for SQL injection, uses the injection to log in as the administrator, confirms the
admin token against an admin-only endpoint, and records an evidence-backed finding. Use
`/report both` to export Markdown and HTML.

What you get: a report with the exact request that proved the finding, its severity, its
impact, and how to remediate it.

## Network and host pentest

Target: a lab host you own (for example a vulnerable VM on your own network).

Prompt:

```
Target is 10.0.0.5. Enumerate it, exploit any vulnerable service, escalate to root, and
report proven findings. Use -Pn on the scan.
```

What happens: the recon phase runs a structured `nmap_scan` (the target is backfilled if
omitted), the attack state fills with open ports and services, the network-service or
credential playbook activates from the ports, and the agent moves to exploitation only
after the scan returns. Post-exploitation escalates and loots. If credentials are
captured and a local model is installed, sensitive post-exploit work is pinned local.

What you get: findings for each vulnerable or exposed service, with remediation, plus a
methodology timeline.

## Cloud assessment

Target: a cloud account or a cloud-simulation lab you are authorized to test.

Prompt:

```
Assess the cloud posture reachable from this host. Check instance metadata, look for
over-permissive IAM and exposed storage, and report anything exploitable with evidence.
```

What happens: delegate to the Cloud Hunter operator (or let the supervisor pick it). It
checks instance metadata, IAM, and storage through the cloud CLIs driven by `shell`. The
cloud playbook grounds the technique.

## Active Directory

Target: an AD lab you own.

Prompt:

```
Domain target is 10.0.0.10. Find a path to Domain Admin: enumerate the domain, hunt for
weak credentials and kerberoastable accounts, and report the path with evidence.
```

What happens: the Active Directory playbook activates. The agent enumerates the domain,
looks for weak and reused credentials and kerberoastable accounts, and constructs a path
to Domain Admin, recording each step.

## Binary exploitation and exploit development

Target: a vulnerable binary you are analyzing.

Prompt:

```
Analyze ./vuln (attached in the working dir). Find the memory-corruption bug, then write
and run a working exploit with code_run that proves control of execution.
```

What happens: delegate to the Reverser and Exploit Developer operators, which declare the
planner role so they run on the reasoning model. `code_run` writes the exploit, compiles
it, runs it, and iterates on failures until it works, staging into the active backend.

## Mobile application testing

Target: an Android APK you are authorized to test.

Prompt:

```
Test this Android app (apk in the working dir). Decompile it, look for hardcoded secrets
and insecure endpoints, and report findings.
```

What happens: the Mobile Operator drives the mobile toolchain (for example jadx and frida)
through `shell` and `kali_run`, grounded by the mobile playbook.

## A multi-model team demo

Goal: show three models collaborating on one engagement.

Set up per-role routing (see [Model routing](model-routing.md)) with planner
deepseek-reasoner, executor kimi, verifier glm, then:

```bash
mapache serve --allow-cloud --verify
```

Give it the web-app prompt above. The executor model drives the loop, the planner model
does the reasoning-heavy analysis, and the verifier model validates the finding at the
checkpoint. The TUI Models panel shows the role-to-model map live. Turn on `/swarm` for
more visible specialist hand-off.

## Capture the flag

Target: a CTF challenge you are solving.

Prompt:

```
Solve this challenge at http://localhost:8080. The flag format is CTF{...}.
```

What happens: pass `--flag-format 'CTF\{.*\}'` so the candidate-flag verifier recognizes a
captured token in the right format. Use `--attempts 3` for multi-attempt self-consistency
on a hard challenge.

## Bug bounty triage

Target: an asset in a program you are authorized to test.

Prompt:

```
Assess https://app.example.com within this scope. Focus on access-control and injection
flaws, and give me a bug-bounty draft for anything you can prove.
```

What happens: put the program scope in `scope.json` so the agent stays in bounds. The
`http_repeater` tool is the primitive for the access-control testing. Export a bounty draft
with the report tools.

## DFIR and purple team

Target: logs or artifacts from an incident you are investigating.

Prompt:

```
Here are the logs in ./artifacts. Build a timeline of the intrusion and write detection
rules for what you find.
```

What happens: the Forensicator operator and the DFIR playbook drive the analysis. The
offensive-vaccine middleware, if enabled, turns each confirmed issue into a detection and
remediation note.

## Tips that apply to every engagement

- Put a `scope.json` in the working directory to keep the agent in bounds.
- Add `--budget-seconds 300` so a stuck weak model cannot run forever.
- Use `--verify` to make success evidence-backed.
- Use the `--tui` dashboard to watch the target, budget, tools, and running shells live.
- Use a capable model. Small or free-tier models struggle to drive a full engagement.
