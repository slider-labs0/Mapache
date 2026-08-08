# Agents and the supervisor

Mapache can run as one generalist agent, or as an autonomous supervisor that routes
bounded objectives to specialist sub-agents. Enable the supervisor with `--fanout` or the
`/swarm` command.

## Delegation

The lead hands a bounded objective to a specialist with `delegate(task, operator=...)`
(or `delegate_parallel` for several at once). A sub-agent is a fresh `AgentController`
with:

- a focused system prompt (the operator's expertise block plus its role constraints),
- a small curated tool subset (a generalist with all ~60 tools drifts and overflows
  context; a specialist with the right handful decides better),
- the lead's shared attack state and knowledge graph, and the same tool dispatcher (so
  the persistent HTTP session and request history carry across the engagement).

Specialists cannot re-delegate. Read-only, RoE-gated, and hardware-dependent roles carry
those constraints in their prompt and are enforced by scope.

## Operator roster

Defined in `core/operators.py`.

Kill-chain core:

- **recon_operator** - active host/service discovery (nmap sweeps).
- **osint_operator** - passive open-source intel (domains, emails, breaches), read-only.
- **web_operator** - web application attacks; reads the real attack surface first.
- **exploit_operator** - match a service/version to a working exploit and land access.
- **post_operator** - privilege escalation, looting, credential and flag capture.

Domain specialists:

- **cloud_hunter** - IAM privesc, storage exposure, Kubernetes, metadata/IMDS credential
  theft.
- **contract_auditor** - Solidity/EVM audits (reentrancy, oracle, access control).
- **reverser** - binary triage and reverse engineering.
- **analyst** - vuln research, source review, static analysis, exploit-chain construction.
- **phisher** - initial access via phishing; blue-team deconfliction required.
- **mobile_operator** - Android/iOS app attacks (static, instrumentation, API backends).
- **wireless_operator** - Wi-Fi/BLE/Zigbee/sub-GHz; needs a radio.
- **iot_operator** - firmware extraction, hardcoded creds, device web/API, radios.
- **ics_operator** - ICS/OT/SCADA enumeration (Modbus, DNP3, S7, BACnet), read-only.
- **forensicator** - DFIR and purple-team validation (timelines, IOCs, detection mapping).
- **supply_chain_operator** - dependency confusion, malicious packages, CI/CD integrity.

Vuln-research pipeline (staged, state flows through the knowledge graph):

- **scanner** to **detector** to **verifier** to **patcher** to **exploiter**.

Planning:

- **soundwave** - turns the mission into an operation plan (OPPLAN) and an engagement
  brief before any offensive action, read-only.

## Routing

The supervisor (`core/orchestrator.py`) chooses the next operator each round from a
`RoutingState` snapshot of the shared blackboard. Its `signature()` is a compact
fingerprint of progress (target, phase, ports, and counts of vulns, creds, flags, and
discovered endpoints); a round that leaves the signature unchanged is a stall.

Routing precedence per round:

1. **Plan-driven** - a pending OPPLAN objective that names an owning operator.
2. **Deterministic router** (`OperatorRouter`) - scores operators by kill-chain
   advancement so the next stage outranks re-doing the previous one: service/port triggers
   for enumeration, findings-driven escalation (creds to post, vulns to exploit), a
   phase-aligned default, and a low-priority exploration ladder that keeps trying different
   specialists when findings-driven routes run dry.
3. **LLM planner** - when the rules run dry, a model call picks the next operator.

### Anti-loop and fan-out

- **Soft bench.** An operator that leaves the signature unchanged is not banned outright;
  it may be re-dispatched a couple of times (`per_sig_cap`) with a steer to change
  technique, so the per-operator budget is actually spent exploring before the run gives
  up with "no route".
- **Progress signal.** Discovered endpoints are part of the signature, so genuine web
  enumeration counts as progress instead of reading as a stall (the fix for premature
  route exhaustion).
- **Fan-out.** On a persistent stall the supervisor deploys several distinct usable
  specialists in parallel, each with a distinct technique angle from a phase-aware menu,
  then re-routes on the merged findings.
- **Route enumeration.** Before routing, one active probe of common web routes seeds the
  shared endpoints so every sub-agent sees real paths.

### Learning

Outcomes are recorded by target fingerprint (services and ports). The router is biased
toward operators that won against similar targets before, so routing gets a little smarter
across many engagements.
