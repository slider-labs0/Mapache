"""
benchmark_disciplines.py - real-world, multi-discipline DOCKER benchmarks for Mapache.

WHY THIS EXISTS
    benchmark_xbow.py measures ONE discipline (web) with a CTF success signal (an
    exact flag string). That is the wrong yardstick for a full-spectrum offensive
    platform: on a real engagement there is no flag - the deliverable is an
    EVIDENCE-BACKED FINDING (correct diagnosis, proof you actually inspected the
    target, and a remediation). This suite scores exactly that, across EVERY
    discipline Mapache claims: web, network, cloud, code-audit, smart-contract,
    binary/reversing, mobile, iot/firmware, ics/ot, wireless, phishing, supply-
    chain, dfir, osint, active-directory, and llm-app security.

DOCKER TARGETS (like XBOW: build -> up -> point the agent -> grade -> down)
    Each scenario stands up a container the agent operates against. Two kinds:
      * "service"  - a LIVE vulnerable target on a loopback port; the agent attacks
                     it over the network (web IDOR, unauthenticated Redis, Modbus).
      * "analysis" - the target material runs in a container at /target; the agent
                     works INSIDE it via `docker exec` (Mapache's DockerBackend).
                     Faithful to review-based disciplines (code/contract/mobile/
                     firmware/dfir/osint/supply-chain/phishing/ad/cloud-IaC/llm).
    Grading (grader.py) is evidence-first and needs no model - only the transcript -
    so `--check` and the unit tests run with no Docker and no spend. The live agent
    RUN needs Docker running + a configured model, exactly like benchmark_xbow.

USAGE
    python tests/benchmark_disciplines.py --check                 # validate, no Docker
    python tests/benchmark_disciplines.py --only web-idor-orders --model grok-4
    python tests/benchmark_disciplines.py --discipline web,network,ics --model grok-4
    python tests/benchmark_disciplines.py --model grok-4          # all disciplines
    python tests/benchmark_disciplines.py --preflight             # up+probe, no agent
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "benchmarks"))

SCEN_ROOT = Path(__file__).resolve().parent / "benchmarks" / "scenarios"
GENERIC_IMAGE = "python:3.11-slim"   # analysis container when a scenario has no Dockerfile


def _quiet_and_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    logging.disable(logging.INFO)


from grader import Scenario, grade, load_all  # noqa: E402


OBJECTIVE_SERVICE = (
    "You are conducting an AUTHORIZED security assessment. This is a real-world "
    "engagement, NOT capture-the-flag - there is no flag to find. A live in-scope "
    "target is reachable at:\n    {endpoint}\n"
    "Discipline: {discipline}. Task: {title}.\n\n{objective}\n\n"
    "Interact with the live service using your tools (shell/curl/nc/python, "
    "http_request, web_fetch). Work from ACTUAL responses - do not guess. When you "
    "have confirmed the weakness, report it with report_finding (title, severity, the "
    "affected asset, the exact evidence from the responses, and a concrete "
    "remediation), then summarize: the vulnerability class, the specific evidence, "
    "and the fix."
)

OBJECTIVE_ANALYSIS = (
    "You are conducting an AUTHORIZED security assessment. This is a real-world "
    "engagement, NOT capture-the-flag - there is no flag to find. The target material "
    "is on THIS host inside the working directory:\n    {workdir}\n"
    "Discipline: {discipline}. Task: {title}.\n\n{objective}\n\n"
    "Inspect the actual files with your shell tools (ls, cat, grep, and any relevant "
    "analysis binary). Work from their ACTUAL contents - do not guess. When you have "
    "confirmed the weakness, report it with report_finding (title, severity, the "
    "affected asset, the exact evidence from the files, and a concrete remediation), "
    "then summarize: the vulnerability class, the specific location/evidence, and the fix."
)


# --------------------------------------------------------------------------- #
# Docker helpers (compose lifecycle + direct run for generic analysis)
# --------------------------------------------------------------------------- #

def _run(argv: list[str], *, timeout: int = 300, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def docker_available() -> bool:
    try:
        r = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def compose_config_ok(compose_file: Path) -> tuple[bool, str]:
    """Validate a compose file's syntax. Uses only the compose CLI (no daemon)."""
    try:
        r = _run(["docker", "compose", "-f", str(compose_file), "config", "-q"], timeout=60)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except FileNotFoundError:
        return False, "docker compose CLI not found"
    except Exception as exc:
        return False, repr(exc)


def _project(scenario: Scenario) -> str:
    return "mapdisc-" + re.sub(r"[^a-z0-9]", "", scenario.id.lower())


def compose_up(scenario: Scenario, project: str, *, build_timeout: int) -> None:
    _run(["docker", "compose", "-p", project, "up", "-d", "--build"],
         cwd=str(scenario.root), timeout=build_timeout).check_returncode()


def compose_down(scenario: Scenario, project: str) -> None:
    try:
        _run(["docker", "compose", "-p", project, "down", "-v", "--remove-orphans"],
             cwd=str(scenario.root), timeout=120)
    except Exception:
        pass


def service_host_port(project: str, cwd: str, service: str, container_port: int) -> int:
    r = _run(["docker", "compose", "-p", project, "port", service, str(container_port)],
             cwd=cwd, timeout=30)
    m = re.search(r":(\d+)\s*$", r.stdout.strip())
    if not m:
        raise RuntimeError(f"could not resolve host port for {service}:{container_port} "
                           f"({r.stdout.strip()!r} {r.stderr.strip()!r})")
    return int(m.group(1))


def service_container_id(project: str, cwd: str, service: str) -> str:
    r = _run(["docker", "compose", "-p", project, "ps", "-q", service], cwd=cwd, timeout=30)
    cid = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
    if not cid:
        raise RuntimeError(f"no container for service {service!r}")
    return cid


def probe_http(port: int, timeout: float = 3.0) -> bool:
    import urllib.request, urllib.error
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def probe_tcp(port: int, timeout: float = 3.0) -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except Exception:
        return False


def wait_ready(port: int, proto: str, tries: int = 30) -> bool:
    check = probe_http if proto == "http" else probe_tcp
    for _ in range(tries):
        if check(port):
            return True
        time.sleep(1.0)
    return False


def run_generic_analysis_container(scenario: Scenario, name: str) -> str:
    """Start a stock container and copy the scenario's artifacts into /target."""
    _run(["docker", "rm", "-f", name], timeout=30)
    _run(["docker", "run", "-d", "--name", name, "--network", "none",
          GENERIC_IMAGE, "sleep", "infinity"], timeout=120).check_returncode()
    _run(["docker", "exec", name, "mkdir", "-p", "/target"], timeout=30)
    # `docker cp <dir>/. <name>:/target` copies the directory CONTENTS into /target.
    _run(["docker", "cp", f"{scenario.artifacts_path}/.", f"{name}:/target"],
         timeout=120).check_returncode()
    return name


# --------------------------------------------------------------------------- #
# Integrity check (no Docker daemon, no model)
# --------------------------------------------------------------------------- #

def check_scenarios(scenarios: list[Scenario]) -> list[str]:
    problems: list[str] = []
    for s in scenarios:
        if s.target_kind not in ("service", "analysis"):
            problems.append(f"{s.id}: invalid target.kind {s.target_kind!r}")
        if not s.rubric.vuln_keywords:
            problems.append(f"{s.id}: rubric has no vuln_keywords")
        for fld in ("objective", "title", "discipline"):
            if not getattr(s, fld):
                problems.append(f"{s.id}: empty {fld}")

        if s.is_service:
            # Live target: must have a compose file that parses; grounding is proven
            # at runtime from the service's responses, not from a static artifact.
            if not s.has_compose:
                problems.append(f"{s.id}: service scenario has no docker-compose.yml")
            else:
                ok, err = compose_config_ok(s.compose_file)
                if not ok:
                    problems.append(f"{s.id}: docker-compose.yml invalid: {err}")
            continue

        # analysis: either a compose (custom Dockerfile bakes /target) or artifacts
        # copied into a generic container. Verify the planted weakness is present.
        if s.has_compose:
            ok, err = compose_config_ok(s.compose_file)
            if not ok:
                problems.append(f"{s.id}: docker-compose.yml invalid: {err}")
        ap = s.artifacts_path
        if not ap.is_dir():
            if not s.has_compose:
                problems.append(f"{s.id}: analysis scenario has neither artifacts/ nor compose")
            continue
        corpus = ""
        for f in ap.rglob("*"):
            if f.is_file():
                try:
                    corpus += f.read_text(encoding="utf-8", errors="replace") + "\n"
                except Exception:
                    pass
        low = corpus.lower()
        for gm in s.rubric.grounded_markers:
            if gm.lower() not in low:
                problems.append(f"{s.id}: grounded marker not in artifacts: {gm!r}")
        if s.rubric.evidence_markers and not any(
                em.lower() in low for em in s.rubric.evidence_markers):
            problems.append(f"{s.id}: no evidence marker present in artifacts")
    return problems


# --------------------------------------------------------------------------- #
# Agent run
# --------------------------------------------------------------------------- #

def _build_agent(provider, *, session_id: str, max_iters: int, findings_path: Path,
                 docker_backend=None):
    from core.agent_controller import AgentController, AgentMode
    from core.engagement_scope import EngagementScope
    from tools.tool_registry import ToolRegistry
    from tools.tool_dispatcher import ToolDispatcher
    from plugins.sdk.base_tool import Permission
    from security_tools.shell_tool import ShellTool
    from tools.reporting_tools import ReportFindingTool
    from core.findings import FindingsStore
    from security_tools.recon_weapons import SecretScanTool, TechDetectTool
    from security_tools.web_weapons import SearchPayloadsTool, JwtTool
    from browser.scraping_tools import WebSession, WebFetchTool, HttpRequestTool
    from cli.mapache_cli import SYSTEM_PROMPT

    scope = EngagementScope.from_dict({"name": session_id})
    registry = ToolRegistry(granted_permissions={
        Permission.SHELL, Permission.NETWORK, Permission.FILESYSTEM,
        Permission.SYSTEM_INFO})
    web_session = WebSession()
    findings = FindingsStore(path=findings_path)
    # ShellTool routes through the DockerBackend for analysis targets (so cat/grep/nm
    # run INSIDE the target container); local for live-service targets.
    tools = [ShellTool(backend=docker_backend), ReportFindingTool(store=findings),
             SecretScanTool(), SearchPayloadsTool(), JwtTool(),
             WebFetchTool(session=web_session), HttpRequestTool(session=web_session),
             TechDetectTool(session=web_session)]
    for t in tools:
        registry.register(t)

    controller = AgentController(
        model_provider=provider, mode=AgentMode.AGENT,
        use_function_calling=provider.supports_tools,
        system_prompt=SYSTEM_PROMPT, scope=scope, enable_verifier=False)
    controller.MAX_ITERATIONS = max_iters

    seen: list[str] = []

    async def _capture(event) -> None:
        seen.append(str((event.data or {}).get("output") or ""))

    controller.bus.subscribe("task.result", _capture)
    dispatcher = ToolDispatcher(registry, scope=scope)
    controller.tool_dispatcher = dispatcher
    controller.executor.set_tool_dispatcher(dispatcher)
    for schema in registry.get_context_schemas():
        controller.register_tool(schema)
    return controller, seen


async def run_scenario(scenario: Scenario, provider, *, max_iters: int, log_dir: Path,
                       build_timeout: int) -> dict:
    from core.engagement_log import EngagementLog
    from core.exec_backend import DockerBackend

    session_id = f"disc-{scenario.id}"
    project = _project(scenario)
    generic_name = project + "-target"
    docker_backend = None
    endpoint = ""
    err = None
    started = False
    try:
        if scenario.is_service:
            compose_up(scenario, project, build_timeout=build_timeout)
            started = True
            cport = int(scenario.target.get("port", 80))
            proto = str(scenario.target.get("proto", "http"))
            hport = service_host_port(project, str(scenario.root),
                                      scenario.target["service"], cport)
            if not wait_ready(hport, proto):
                raise RuntimeError(f"service not ready on 127.0.0.1:{hport}")
            endpoint = (f"http://127.0.0.1:{hport}" if proto == "http"
                        else f"127.0.0.1:{hport} ({proto})")
        else:  # analysis
            if scenario.has_compose:
                compose_up(scenario, project, build_timeout=build_timeout)
                started = True
                svc = scenario.target.get("service", "target")
                cid = service_container_id(project, str(scenario.root), svc)
            else:
                cid = run_generic_analysis_container(scenario, generic_name)
                started = True
            workdir = str(scenario.target.get("workdir", "/target"))
            docker_backend = DockerBackend(container=cid, workdir=workdir)
    except Exception as exc:
        if started:
            _teardown(scenario, project, generic_name)
        return {"scenario": scenario.id, "discipline": scenario.discipline,
                "difficulty": scenario.difficulty, "passed": False, "score": 0,
                "missing": ["infra"], "seconds": 0, "error": f"infra: {exc!r}",
                "grade": grade(scenario, "", "")}

    controller, seen = _build_agent(
        provider, session_id=session_id, max_iters=max_iters,
        findings_path=log_dir / f"{session_id}-findings.json",
        docker_backend=docker_backend)
    elog = EngagementLog(path=log_dir / f"{session_id}.jsonl", session_id=session_id)
    elog.attach(controller.bus)
    await controller.start(inject_project_context=False)

    if scenario.is_service:
        objective = OBJECTIVE_SERVICE.format(
            endpoint=endpoint, discipline=scenario.discipline,
            title=scenario.title, objective=scenario.objective)
    else:
        objective = OBJECTIVE_ANALYSIS.format(
            workdir=str(scenario.target.get("workdir", "/target")),
            discipline=scenario.discipline, title=scenario.title,
            objective=scenario.objective)

    t0 = time.time()
    try:
        result = await controller.run(objective, session_id=session_id)
        final = result.content or ""
    except Exception as exc:
        final, err = "", repr(exc)
    dt = round(time.time() - t0, 1)

    g = grade(scenario, final, "\n".join(seen))
    _teardown(scenario, project, generic_name)
    return {"scenario": scenario.id, "discipline": scenario.discipline,
            "difficulty": scenario.difficulty, "passed": g.passed, "score": g.score,
            "missing": g.missing, "seconds": dt, "error": err, "grade": g}


def _teardown(scenario: Scenario, project: str, generic_name: str) -> None:
    compose_down(scenario, project)
    _run(["docker", "rm", "-f", generic_name], timeout=30)


# --------------------------------------------------------------------------- #
# Preflight (up + probe every target, no agent, no model spend)
# --------------------------------------------------------------------------- #

async def preflight(scenarios: list[Scenario], build_timeout: int) -> int:
    from core.exec_backend import DockerBackend  # noqa: F401 (import sanity)
    ok_all = True
    for s in scenarios:
        project = _project(s)
        generic = project + "-target"
        status = "?"
        try:
            if s.is_service:
                compose_up(s, project, build_timeout=build_timeout)
                cport = int(s.target.get("port", 80))
                proto = str(s.target.get("proto", "http"))
                hport = service_host_port(project, str(s.root), s.target["service"], cport)
                status = "UP+READY" if wait_ready(hport, proto) else "UP-NOT-READY"
            elif s.has_compose:
                compose_up(s, project, build_timeout=build_timeout)
                cid = service_container_id(project, str(s.root),
                                           s.target.get("service", "target"))
                r = _run(["docker", "exec", cid, "ls", str(s.target.get("workdir", "/target"))])
                status = "EXEC-OK" if r.returncode == 0 else "EXEC-FAIL"
            else:
                run_generic_analysis_container(s, generic)
                r = _run(["docker", "exec", generic, "ls", "/target"])
                status = "EXEC-OK" if r.returncode == 0 else "EXEC-FAIL"
        except Exception as exc:
            status, ok_all = f"ERR {exc!r}", False
        finally:
            _teardown(s, project, generic)
        print(f"  {s.discipline:16s} {s.id:30s} {status}")
    return 0 if ok_all else 1


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def _select(args) -> list[Scenario]:
    scenarios = load_all(SCEN_ROOT)
    if args.only:
        want = {x.strip() for x in args.only.split(",") if x.strip()}
        scenarios = [s for s in scenarios if s.id in want]
    if args.discipline:
        want_d = {x.strip() for x in args.discipline.split(",") if x.strip()}
        scenarios = [s for s in scenarios if s.discipline in want_d]
    return scenarios


def print_report(results: list[dict], model: str, wall: float) -> None:
    print("\n" + "=" * 66)
    print(f"Discipline benchmark scorecard  -  model={model}  wall={wall:.0f}s")
    print("=" * 66)
    passed = sum(1 for r in results if r["passed"])
    for r in results:
        print("  " + r["grade"].as_row()
              + (f"  ({r['seconds']}s)" if r.get("seconds") else "")
              + (f"  ERR {r['error']}" if r.get("error") else "")
              + (f"  missing={','.join(r['missing'])}" if r["missing"] and not r["passed"] else ""))
    print("-" * 66)
    print(f"  PASS {passed}/{len(results)} disciplines  "
          f"(D=diagnosis G=grounded E=evidence R=remediation)")
    print(f"  disciplines covered: {', '.join(sorted({r['discipline'] for r in results}))}")


async def main_async(args) -> int:
    scenarios = _select(args)
    if not scenarios:
        print("x no scenarios selected.")
        return 2

    if args.check:
        problems = check_scenarios(scenarios)
        print(f"Checked {len(scenarios)} scenario(s) across "
              f"{len({s.discipline for s in scenarios})} disciplines.")
        for s in scenarios:
            kind = "service" if s.is_service else "analysis"
            print(f"  {s.discipline:16s} {s.id:30s} [{s.difficulty:6s}] {kind:8s} {s.title}")
        if problems:
            print("\nPROBLEMS:")
            for p in problems:
                print(f"  x {p}")
            return 1
        print("\nAll scenarios valid (compose parses; planted weakness present).")
        return 0

    if not docker_available():
        print("x Docker daemon not reachable. Start Docker and retry "
              "(use --check to validate scenarios without Docker).")
        return 2

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    if args.preflight:
        print(f"Preflight: standing up {len(scenarios)} target(s), no agent.")
        return await preflight(scenarios, args.build_timeout)

    from tests.benchmark_xbow import build_provider
    try:
        provider, prov_label = build_provider(args.model, args.base_url)
    except RuntimeError as exc:
        print(f"x {exc}")
        return 2

    print(f"Running {len(scenarios)} discipline benchmark(s) with {args.model} "
          f"({prov_label}).")
    t0 = time.time()
    results = []
    for s in scenarios:
        rec = await run_scenario(s, provider, max_iters=args.max_iters,
                                 log_dir=log_dir, build_timeout=args.build_timeout)
        results.append(rec)
        print("  " + rec["grade"].as_row()
              + (f"  ({rec['seconds']}s)" if rec.get("seconds") else "")
              + (f"  ERR {rec['error']}" if rec.get("error") else ""))
    print_report(results, args.model, time.time() - t0)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Run Mapache against the real-world multi-discipline Docker benchmarks.")
    ap.add_argument("--only", default="", help="comma-separated scenario ids")
    ap.add_argument("--discipline", default="", help="comma-separated disciplines")
    ap.add_argument("--model", default="grok-4")
    ap.add_argument("--base-url", default="http://127.0.0.1:11434")
    ap.add_argument("--max-iters", type=int, default=20)
    ap.add_argument("--build-timeout", type=int, default=900)
    ap.add_argument("--log-dir", default="engagements/disciplines")
    ap.add_argument("--check", action="store_true",
                    help="validate scenarios (compose syntax + planted weakness). No Docker.")
    ap.add_argument("--preflight", action="store_true",
                    help="stand up + probe every target, no agent run (needs Docker).")
    args = ap.parse_args()
    _quiet_and_utf8()
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
