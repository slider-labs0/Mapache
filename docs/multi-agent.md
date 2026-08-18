# Multi-agent orchestration

Mapache can split an engagement into specialists that share one attack state. There are
two ways this happens: the lead agent delegates a bounded subtask, or an autonomous
supervisor routes the whole engagement across operators. This page covers both, the
operator roster, and how work is coordinated.

## Delegation

A built-in `delegate(task, operator=...)` tool lets the model spawn a focused child
`AgentController` for one bounded subtask and get back only its conclusion. The child
runs the named operator's focused system prompt and a small curated tool subset instead
of the lead's generalist prompt and full toolset. On a local model this is a real win:
a smaller payload and narrower decisions.

Recursion is bounded by `MAX_DELEGATION_DEPTH` (default 1), so a sub-agent is not offered
the delegate tool and cannot spawn its own children endlessly. Delegation events fire on
the event bus with the operator label, so the audit log and the dashboard both see them.

### The shared blackboard

The child references the lead's attack state by reference, so its findings are live in
the lead's state with no merge-back step. A guard stops a child's task wording from
reassigning the target or wiping the shared findings. The child also shares the lead's
event bus, so its tool calls, findings, and scope refusals land in the same engagement
log. State mutations are safe for concurrent children.

### Parallel fan-out

`delegate_parallel(tasks=[{task, operator}, ...])` runs several operators concurrently
over the shared blackboard, capped by `MAX_FANOUT`. This gives you several angles on the
current host at once. On a single GPU the model calls serialize at the provider, so it is
a correctness and orchestration win; once cloud routing serves the calls concurrently it
becomes a wall-clock win as well.

## The operator roster

Operators live in `core/operators.py`. Each carries a focused prompt, a curated tool
subset, a declared model role, a cost tier, and role constraints (read-only, gated by
rules of engagement, needs hardware, deconflict first). Naming one in `delegate` or
letting the supervisor pick runs the child as that specialist.

| Operator | Title | Focus |
|----------|-------|-------|
| recon_operator | Recon Operator | Broad host and service discovery |
| osint_operator | OSINT Operator | Passive research and correlation |
| web_operator | Web Operator | Web application attack surface |
| exploit_operator | Exploit Operator | Service and application exploitation |
| post_operator | Post-Exploit Operator | Privilege escalation, loot, pivoting |
| cloud_hunter | Cloud Hunter | Cloud metadata, IAM, storage |
| contract_auditor | Contract Auditor | Smart-contract and Web3 review |
| exploit_dev | Exploit Developer | Writing and running exploit code |
| reverser | Reverser | Binary and firmware reversing |
| analyst | Analyst | Vulnerability research, exploit-chain construction |
| phisher | Phisher | Social engineering, requires deconfliction |
| mobile_operator | Mobile Operator | Android and iOS app testing |
| wireless_operator | Wireless Operator | Wi-Fi and radio |
| iot_operator | IoT Operator | Device and firmware attacks |
| ics_operator | ICS Operator | Industrial control and OT, gated by scope |
| forensicator | Forensicator | DFIR and purple-team analysis |
| supply_chain_operator | Supply Chain Operator | Dependency and CI/CD compromise |

There is also a vulnerability-research pipeline (scanner, detector, verifier, patcher,
exploiter) and an engagement planner (soundwave) used by the supervisor.

Role constraints render into the prompt and reinforce the scope gate. `/operators` lists
the roster, and a next-step suggester nudges the right specialist based on the open ports
and services in the attack state.

## The autonomous supervisor (swarm)

`core/orchestrator.py` holds the supervisor. With `/swarm on` (or `default_strategy` set
to `swarm`), the supervisor autonomously routes the engagement across operators driven by
the attack state, instead of relying on a single generalist agent to do everything.

The supervisor decides which specialist to deploy next from the current state, hands off,
collects the specialist's conclusions into the shared knowledge, and continues. This is
the mode to use when you want the most visible multi-agent action, and it is where the
sub-agent model-selection pipeline in [Model routing](model-routing.md) comes into play:
each specialist can run on a different model based on the role it declares.

## Knowledge graph and the operation plan

The supervisor and the operators write into a disk-persisted knowledge graph (a findings
store) so a freshly spawned specialist can query prior findings with a fresh context.
There is also an operation plan (OPPLAN) that the model reads and updates
(`opplan_show`, `opplan_add`, `opplan_update`) to keep long engagements coherent.

## Trace streaming

Sub-agent activity streams through a scoped event bus, so the operator sees the child's
tool calls and findings live rather than waiting for a summary at the end. In the CLI the
transcript is colored by the active specialist so you can tell which operator is working.
