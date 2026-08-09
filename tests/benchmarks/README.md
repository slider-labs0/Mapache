# Mapache discipline benchmarks (real-world, Dockerized, finding-based)

`benchmark_xbow.py` measures **one** discipline (web) with a **CTF** success signal
(an exact flag string). This suite exists because Mapache is a full-spectrum
offensive platform, and on a real engagement **there is no flag** — the deliverable
is an **evidence-backed finding**: the correct diagnosis, proof you actually
inspected the target, and a remediation. These benchmarks score exactly that,
across every discipline Mapache claims.

## What "success" means here

A run is graded by `grader.py` against each scenario's rubric on four axes:

| Axis | Meaning |
|------|---------|
| **D**iagnosis | the final answer names the real weakness (a vuln keyword / CWE) |
| **G**rounded  | a marker unique to the real target appears in the **tool output** — proof the agent actually looked, not guessed |
| **E**vidence  | the answer points at the concrete sink (endpoint, file, register, IOC…) |
| **R**emediation | the answer proposes a correct fix |

**PASS = D ∧ G ∧ (E ∨ R).** Grounding is the anti-fabrication guarantee: a
plausible-sounding guess with no tool evidence fails.

## Docker targets

Each scenario stands up a **container the agent operates against** (build → up →
point the agent → grade → down, like XBOW). Two kinds:

- **`service`** — a live vulnerable target on a loopback port; the agent attacks it
  over the network. Live today: `web-idor-orders` (HTTP IDOR), `net-redis-unauth`
  (unauthenticated Redis), `ics-modbus-exposure` (unauthenticated Modbus PLC).
- **`analysis`** — the target material runs in a container at `/target`; the agent
  works **inside it** via `docker exec` (Mapache's `DockerBackend`). This is
  faithful to review-based disciplines (code / contract / mobile / firmware / dfir /
  osint / supply-chain / phishing / active-directory / cloud-IaC / llm / wireless).

## Disciplines covered (16)

web · network · cloud · code-audit · smart-contract · binary/reversing · mobile ·
iot/firmware · ics/ot · wireless · phishing/SE · supply-chain · dfir · osint ·
active-directory · llm-app

## Running

```bash
# validate every scenario WITHOUT Docker or a model (compose syntax + planted weakness)
python tests/benchmark_disciplines.py --check

# stand up + probe every target, no agent, no spend (needs Docker running)
python tests/benchmark_disciplines.py --preflight

# run one discipline / a subset / everything (needs Docker + a configured model)
python tests/benchmark_disciplines.py --only web-idor-orders --model grok-4
python tests/benchmark_disciplines.py --discipline web,network,ics --model grok-4
python tests/benchmark_disciplines.py --model grok-4
```

The grader and scenario integrity are unit-tested in `tests/test_core.py`
(`test_discipline_benchmarks_valid`) — no Docker, no spend. The live agent run
needs Docker running and a model, exactly like `benchmark_xbow.py`.

## Adding a scenario

Create `scenarios/<id>/scenario.json` with a `target` block and a `rubric`, plus:
- `analysis`: an `artifacts/` dir holding the target material (a generic
  `python:3.11-slim` container receives it at `/target`), **or** a
  `docker-compose.yml` whose image bakes `/target` (e.g. the reversing target,
  which compiles a binary and installs binutils).
- `service`: a `docker-compose.yml` exposing the vulnerable service on
  `127.0.0.1:0:<port>` (host port auto-assigned; the harness discovers it).

Every rubric **grounded marker** must appear verbatim in the target (for `analysis`,
`--check` enforces this; for `service`, it's a string the live service emits).
