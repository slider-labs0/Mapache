"""Live cloud-domain validation - Mapache vs the public flaws2.cloud AWS CTF.

Authorized target: flaws2.cloud is Scott Piper's intentionally-vulnerable AWS CTF,
explicitly published for anyone to attack (attacker track, http://level1.flaws2.cloud/).
This drives Mapache's *cloud* path end-to-end against a REAL internet AWS target to
verify the cloud_hunter operator + cloud_attacks playbook actually engage and drive
`aws`/curl through `shell` - the open item from ROADMAP section S.

Bounded for a paid model (Sonnet 5 via OpenRouter):
  - AgentController.MAX_ITERATIONS caps EVERY controller (lead + fanned-out sub-agents).
  - Supervisor max_rounds caps routing rounds.
  - BudgetMiddleware + an asyncio.wait_for hard wall-clock stop protect credits.

Env knobs: LIVE_MODEL, LIVE_LEAD_ITERS, LIVE_SUBAGENT_ITERS, LIVE_ROUNDS,
LIVE_MAX_SECONDS, LIVE_MAX_TOKENS.

Run:  py -3.11 tests/_live_test_cloud.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.agent_controller import AgentController, AgentMode
from core.engagement_scope import EngagementScope
from core.engagement_log import EngagementLog
from tools.tool_registry import ToolRegistry
from tools.tool_dispatcher import ToolDispatcher
from plugins.sdk.base_tool import Permission
from security_tools.shell_tool import ShellTool
from browser.scraping_tools import WebFetchTool, HttpRequestTool, WebSession
from browser.browser_tool import BrowserTool
from security_tools.kali.heavy_tools import SqlmapTool, FuzzTool
from tools.filesystem_tool import FileReadTool
from core.agent_middlewares import BudgetMiddleware
from cli.mapache_cli import SYSTEM_PROMPT

# tests/benchmark_xbow.py already knows how to turn a model id into a cloud provider.
import benchmark_xbow as bx  # noqa: E402

MODEL = os.environ.get("LIVE_MODEL", "anthropic/claude-sonnet-5")
LEAD_ITERS = int(os.environ.get("LIVE_LEAD_ITERS", "14"))
ROUNDS = int(os.environ.get("LIVE_ROUNDS", "8"))
MAX_SECONDS = float(os.environ.get("LIVE_MAX_SECONDS", "1200"))
MAX_TOKENS = int(os.environ.get("LIVE_MAX_TOKENS", "600000"))

# Bound EVERY controller (lead + sub-agents spawned fresh by the supervisor).
AgentController.MAX_ITERATIONS = int(os.environ.get("LIVE_SUBAGENT_ITERS", "10"))

TARGET = "level1.flaws2.cloud"

# Rules-of-Engagement: keep curl/http calls on flaws2 + AWS + the metadata IPs.
# (aws-CLI shell commands carry no URL, so the scope's utility-command allowance
# lets them through; this only fences the URL-bearing calls.)
SCOPE = EngagementScope.from_dict({
    "name": "flaws2-cloud-live",
    "targets": [
        "flaws2.cloud", "flaws.cloud", "amazonaws.com", "amazonaws.com.cn",
        "169.254.169.254", "169.254.170.2",
    ],
})

OBJECTIVE = (
    "You are authorized to penetration-test the PUBLIC AWS CTF 'flaws2.cloud' "
    "(Scott Piper's intentionally-vulnerable lab, published for anyone to attack). "
    "Work the ATTACKER track. Starting point: http://" + TARGET + "/ .\n\n"
    "This is a CLOUD / AWS engagement. The application is hosted on AWS (Lambda / "
    "API Gateway / ECS containers). Enumerate it, find the vulnerability, and pivot "
    "into the AWS account: hunt for exposed credentials (container/task metadata at "
    "169.254.170.2 and IMDS at 169.254.169.254), read any S3 buckets or ECR images "
    "you can reach, and use `aws` (via the shell tool) to prove access "
    "(`aws sts get-caller-identity`, `aws s3 ls ...`). \n\n"
    "Drive provider CLIs and curl through the `shell` tool. Report concrete PROOF of "
    "each step you achieve: the brute-forced code, retrieved credentials/tokens, the "
    "sts caller identity of any principal you obtain, and any bucket/object contents. "
    "Do NOT fabricate - only report what a tool actually returned."
)


def main() -> None:
    provider, label = bx.build_provider(MODEL, "")
    print(f"[live-cloud] model={MODEL} provider={label} tools={provider.supports_tools}")
    print(f"[live-cloud] target={TARGET} lead_iters={LEAD_ITERS} sub_iters="
          f"{AgentController.MAX_ITERATIONS} rounds={ROUNDS} "
          f"max_seconds={MAX_SECONDS} max_tokens={MAX_TOKENS}")
    print(f"[live-cloud] scope={SCOPE.targets_summary()}")

    registry = ToolRegistry(granted_permissions={
        Permission.SHELL, Permission.NETWORK, Permission.FILESYSTEM,
        Permission.SYSTEM_INFO, Permission.DANGEROUS, Permission.UNRESTRICTED})
    web_session = WebSession()
    for tool in (ShellTool(), WebFetchTool(session=web_session),
                 HttpRequestTool(session=web_session), BrowserTool(),
                 SqlmapTool(), FuzzTool(), FileReadTool()):
        registry.register(tool)

    controller = AgentController(
        model_provider=provider, mode=AgentMode.AGENT,
        use_function_calling=provider.supports_tools,
        system_prompt=SYSTEM_PROMPT, scope=SCOPE, enable_verifier=False)
    controller.MAX_ITERATIONS = LEAD_ITERS
    controller.add_middleware(BudgetMiddleware(max_tokens=MAX_TOKENS,
                                               max_seconds=MAX_SECONDS))

    # ---- trace capture ------------------------------------------------- #
    run_dir = _ROOT / "engagements"
    run_dir.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    jsonl_path = run_dir / f"flaws2-live-{stamp}.jsonl"
    jf = jsonl_path.open("w", encoding="utf-8")

    events: list[tuple[str, dict]] = []
    tool_calls: list[str] = []
    shell_cmds: list[str] = []
    operators: list[str] = []
    playbooks: set[str] = set()
    outputs: list[str] = []

    async def _tap(event) -> None:
        topic = getattr(event, "topic", "") or ""
        d = event.data or {}
        try:
            jf.write(json.dumps({"t": topic, "d": _safe(d)})[:20000] + "\n")
        except Exception:
            pass
        events.append((topic, d))
        low = topic.lower()
        # Tool invocations come through as task.start; their output as task.result.
        if topic == "task.start":
            name = str(d.get("tool") or d.get("name") or d.get("tool_name") or "")
            args = d.get("args")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            args = args or {}
            cmd = str(args.get("cmd") or d.get("cmd") or "")
            if name:
                tool_calls.append(name)
            if cmd:
                shell_cmds.append(cmd)
        if "delegate" in low:
            op = str(d.get("operator") or d.get("agent") or "")
            if op:
                operators.append(op)
        if "skill" in low or "playbook" in low:
            for k in ("skill", "name", "playbook"):
                if d.get(k):
                    playbooks.add(str(d[k]))
        if topic == "task.result":
            outputs.append(str(d.get("output") or ""))

    controller.bus.subscribe("*", _tap)
    elog = EngagementLog(path=run_dir / f"flaws2-live-{stamp}.log",
                         session_id="flaws2-cloud-live")
    elog.attach(controller.bus)

    dispatcher = ToolDispatcher(registry, scope=SCOPE)
    controller.tool_dispatcher = dispatcher
    controller.executor.set_tool_dispatcher(dispatcher)
    for schema in registry.get_context_schemas():
        controller.register_tool(schema)

    from core.orchestrator import Supervisor, OperatorRouter, make_model_planner

    async def _drive():
        await controller.start(inject_project_context=False)
        st = controller.chain.attack_state
        st.target = TARGET
        st.open_ports = ["80/tcp", "443/tcp"]
        st.services = {"80": "http", "443": "https", "cloud": "aws"}
        st.current_phase = "enumeration"
        router = OperatorRouter(explore=True)
        sup = Supervisor(controller, router=router, max_rounds=ROUNDS,
                         session_id="flaws2-cloud-live",
                         planner=make_model_planner(controller), fanout=True)
        return await sup.run(OBJECTIVE, session_id="flaws2-cloud-live")

    t0 = time.time()
    sres = None
    err = None
    try:
        sres = asyncio.run(asyncio.wait_for(_drive(), timeout=MAX_SECONDS + 120))
    except asyncio.TimeoutError:
        err = "hard wall-clock timeout"
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {e}"
    finally:
        jf.close()
    dt = time.time() - t0

    # ---- summary ------------------------------------------------------- #
    from collections import Counter
    print("\n" + "=" * 72)
    print(f"[live-cloud] DONE in {dt:.0f}s  err={err}")
    if sres is not None:
        print(f"  stop_reason : {getattr(sres, 'stop_reason', '?')}")
        print(f"  rounds      : {len(getattr(sres, 'rounds', []) or [])}")
        print(f"  operators   : {', '.join(getattr(sres, 'operators_run', []) or []) or '(none)'}")
        print(f"  solved-flag : {getattr(sres, 'solved', None)}")
    print(f"  events      : {len(events)}")
    print(f"  tool calls  : {len(tool_calls)}  {dict(Counter(tool_calls))}")
    print(f"  operators*  : {dict(Counter(operators))}")
    print(f"  playbooks   : {sorted(playbooks) or '(none captured)'}")

    corpus = "\n".join(outputs + shell_cmds)
    signals = {
        "aws_cli_used": any(c.strip().startswith(("aws ", "aws\t")) or " aws " in c
                            for c in shell_cmds),
        "hit_task_metadata_170": "169.254.170.2" in corpus,
        "hit_imds_169": "169.254.169.254" in corpus,
        "sts_identity": "get-caller-identity" in corpus.lower(),
        "s3_access": "s3://" in corpus or "s3 ls" in corpus.lower(),
        "ecr_used": "ecr" in corpus.lower(),
        "creds_found": ("AccessKeyId" in corpus or "SecretAccessKey" in corpus
                        or "aws_access_key" in corpus.lower()),
    }
    print("  cloud signals:")
    for k, v in signals.items():
        print(f"      {'YES' if v else ' no'}  {k}")

    print(f"\n  shell commands ({len(shell_cmds)}):")
    for c in shell_cmds[:40]:
        print("      $ " + c[:160])

    if sres is not None and getattr(sres, "rounds", None):
        print("\n  final content:")
        print("      " + str(getattr(sres, "final", "") or "")[:1200])

    print(f"\n[live-cloud] full trace: {jsonl_path}")
    print("=" * 72)


def _safe(d):
    out = {}
    for k, v in (d or {}).items():
        s = v if isinstance(v, (int, float, bool, type(None))) else str(v)
        if isinstance(s, str) and len(s) > 4000:
            s = s[:4000] + "…"
        out[k] = s
    return out


if __name__ == "__main__":
    main()
