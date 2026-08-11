"""
benchmark_cyberseceval.py - run a model through Meta's CyberSecEval 3 suite.

CyberSecEval (Meta PurpleLlama, github.com/meta-llama/PurpleLlama) is a
prompt-dataset SAFETY+CAPABILITY eval, not a Docker-target agentic benchmark like
[[benchmark_xbow]] / [[benchmark_cybench]]: it feeds the model-under-test a dataset
of adversarial prompts and grades the responses (usually with a judge LLM). This
bridges Mapache's configured models into it so we can score e.g. GLM 5.2 on
prompt-injection resistance, MITRE ATT&CK offensive capability, and code-interpreter
abuse - the complement to the flag-based benchmarks.

Why a wrapper instead of CyberSecEval's own `run.py`:
  * run.py imports EVERY benchmark at module load, including the code-generation ones
    that pull in `semgrep` (wants a symlink -> needs admin/Developer Mode on Windows)
    and `CodeShield.insecure_code_detector.internal` (absent in the public repo). We
    import ONLY the requested benchmark, so the injection/mitre/interpreter suites
    run on a stock Windows box.
  * The model-under-test + judge are built from Mapache's ~/.mapache/config.json
    (OpenRouter key/base_url) as an `OPENAI::<model>::<key>::<base_url>` spec, so you
    never paste a key and GLM 5.2 via OpenRouter works out of the box.

CyberSecEval lives in its own venv (its pinned deps must not touch Mapache's env):
    py -3.11 -m venv <purplellama>/.venv
    <purplellama>/.venv/Scripts/python -m pip install -r \
        <purplellama>/CybersecurityBenchmarks/requirements.txt
This script auto-re-execs into that venv for a real run, so you can launch it with
plain `py -3.11`.

Examples:
    py -3.11 tests/benchmark_cyberseceval.py --purplellama ~/Downloads/PurpleLlama --check
    py -3.11 tests/benchmark_cyberseceval.py --benchmark prompt-injection \
        --model z-ai/glm-5.2 --num-test-cases 10
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# CyberSecEval benchmarks that run WITHOUT the semgrep/CodeShield code-gen deps.
# name -> (module under CybersecurityBenchmarks.benchmark, registered kind,
#          dataset path under CybersecurityBenchmarks/datasets, needs_judge, needs_expansion)
BENCHMARKS: dict[str, dict] = {
    "prompt-injection": {
        "module": "prompt_injection_benchmark", "class": "PromptInjectionBenchmark",
        "kind": "prompt-injection", "dataset": "prompt_injection/prompt_injection.json",
        "judge": True, "expansion": False,
    },
    "mitre": {
        "module": "mitre_benchmark", "class": "MitreBenchmark", "kind": "mitre",
        "dataset": "mitre/mitre_benchmark_100_per_category_with_augmentation.json",
        "judge": True, "expansion": True,
    },
    "interpreter": {
        "module": "interpreter_benchmark", "class": "InterpreterBenchmark",
        "kind": "interpreter", "dataset": "interpreter/interpreter.json",
        "judge": True, "expansion": False,
    },
}

DEFAULT_CONFIG = Path.home() / ".mapache" / "config.json"


def provider_for(config_path: Path, model: str) -> tuple[str, str, str]:
    """Return (provider_name, api_key, base_url) that serves `model`, read straight
    from ~/.mapache/config.json (no Mapache imports, so this runs under the venv)."""
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    provs = raw.get("providers", {})
    for name, p in provs.items():
        if model in (p.get("models") or []) and p.get("api_key"):
            return name, p["api_key"], p.get("base_url", "")
    # Fall back to OpenRouter if configured (it hosts most catalog models).
    orr = provs.get("openrouter", {})
    if orr.get("api_key"):
        return "openrouter", orr["api_key"], orr.get("base_url", "")
    raise RuntimeError(f"no usable provider with a key serves '{model}' in {config_path}")


def spec_for(model: str, api_key: str, base_url: str) -> str:
    """CyberSecEval llm-under-test spec: OPENAI::<model>::<key>::<base_url>. The
    OPENAI provider speaks OpenAI /chat/completions against any base_url, so an
    OpenAI-compatible endpoint (OpenRouter, NIM, a local server) all work."""
    return f"OPENAI::{model}::{api_key}::{base_url}"


def _redact(spec: str) -> str:
    parts = spec.split("::")
    if len(parts) >= 3 and parts[2]:
        parts[2] = "***" + parts[2][-4:]
    return "::".join(parts)


def _venv_python(purplellama: Path) -> Path | None:
    for rel in ("Scripts/python.exe", "bin/python", "bin/python3"):
        cand = purplellama / ".venv" / rel
        if cand.is_file():
            return cand
    return None


def _reexec_in_venv_if_needed(purplellama: Path) -> None:
    """A real run needs CyberSecEval's deps (openai, langchain-core, …), which live
    in <purplellama>/.venv. If they aren't importable here, re-exec this script with
    the venv's python so `py -3.11 …` just works."""
    try:
        import openai  # noqa: F401  (proxy for "CyberSecEval deps present")
        return
    except Exception:
        pass
    vpy = _venv_python(purplellama)
    if vpy is None:
        raise RuntimeError(
            f"CyberSecEval deps not importable and no venv at {purplellama/'.venv'}.\n"
            f"Create it:\n  py -3.11 -m venv {purplellama/'.venv'}\n"
            f"  {purplellama/'.venv'/'Scripts'/'python'} -m pip install -r "
            f"{purplellama/'CybersecurityBenchmarks'/'requirements.txt'}")
    if os.environ.get("_CYBERSEC_REEXEC") == "1":
        raise RuntimeError("re-exec loop: venv python still can't import openai")
    os.environ["_CYBERSEC_REEXEC"] = "1"
    os.execv(str(vpy), [str(vpy), os.path.abspath(__file__), *sys.argv[1:]])


def run_benchmark(args) -> int:
    purplellama = Path(args.purplellama).expanduser()
    csb = purplellama / "CybersecurityBenchmarks"
    if not csb.is_dir():
        print(f"CybersecurityBenchmarks not found under {purplellama}")
        return 2
    if args.benchmark not in BENCHMARKS:
        print(f"unsupported benchmark '{args.benchmark}'. Supported: "
              f"{', '.join(BENCHMARKS)}")
        return 2
    spec_info = BENCHMARKS[args.benchmark]
    dataset = csb / "datasets" / spec_info["dataset"]
    if not dataset.is_file():
        print(f"dataset missing: {dataset}")
        return 2

    _reexec_in_venv_if_needed(purplellama)   # ensures openai/langchain-core present
    sys.path.insert(0, str(purplellama))

    # Import ONLY the requested benchmark (registers its kind) + the shared bits,
    # so semgrep/CodeShield (code-gen benchmarks) are never touched.
    import importlib
    import asyncio
    mod = importlib.import_module(
        f"CybersecurityBenchmarks.benchmark.{spec_info['module']}")
    from CybersecurityBenchmarks.benchmark.benchmark import Benchmark, BenchmarkConfig
    from CybersecurityBenchmarks.benchmark import llm
    # Registration is explicit in CyberSecEval (run.py calls it for every benchmark);
    # importing the module does NOT self-register, so do it for the one we want.
    Benchmark.register_benchmark(getattr(mod, spec_info["class"]))

    _, key, base = provider_for(Path(args.config).expanduser(), args.model)
    ut_spec = spec_for(args.model, key, base)
    judge_model = args.judge_model or args.model
    _, jk, jb = provider_for(Path(args.config).expanduser(), judge_model)
    judge_spec = spec_for(judge_model, jk, jb)
    print(f"CyberSecEval :: benchmark={args.benchmark}  under-test={_redact(ut_spec)}"
          f"  judge={_redact(judge_spec)}  n={args.num_test_cases or 'all'}")

    out = Path(args.out_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    config = BenchmarkConfig(
        llms_under_test=[llm.create(ut_spec)],
        response_path=out / f"{args.benchmark}_responses.json",
        judge_response_path=out / f"{args.benchmark}_judge_responses.json",
        stat_path=out / f"{args.benchmark}_stats.json",
        judge_llm=llm.create(judge_spec) if spec_info["judge"] else None,
        expansion_llm=llm.create(judge_spec) if spec_info["expansion"] else None,
        num_test_cases=args.num_test_cases,
        prompt_path=str(dataset),
        max_concurrency=args.parallel,
    )
    bench = Benchmark.create_instance(spec_info["kind"], config)
    bench.query_llm_to_generate_responses(prompt_path=dataset,
                                          run_llm_in_parallel=args.parallel)
    asyncio.run(bench.run(args.num_test_cases, args.parallel, True))

    stat_path = out / f"{args.benchmark}_stats.json"
    if stat_path.is_file():
        stats = json.loads(stat_path.read_text(encoding="utf-8"))
        print(f"\n{'='*66}\nCYBERSECEVAL {args.benchmark} - {args.model}\n{'='*66}")
        _print_stats(stats)
        print(f"\nfull stats: {stat_path}")
    else:
        print(f"run finished but no stats file at {stat_path}")
    return 0


def _print_stats(stats: dict, indent: int = 2) -> None:
    """CyberSecEval stat files nest per-category dicts of rates; print leaf numbers
    compactly without assuming a specific benchmark's schema."""
    pad = " " * indent
    for k, v in stats.items():
        if isinstance(v, dict):
            print(f"{pad}{k}:")
            _print_stats(v, indent + 2)
        elif isinstance(v, float):
            print(f"{pad}{k}: {v:.3f}")
        else:
            print(f"{pad}{k}: {v}")


def do_check(args) -> int:
    """Validate the setup without a model run: repo present, datasets exist, spec
    builds. Runs under any python (imports no CyberSecEval)."""
    purplellama = Path(args.purplellama).expanduser()
    csb = purplellama / "CybersecurityBenchmarks"
    print(f"PurpleLlama: {purplellama}  ({'ok' if csb.is_dir() else 'MISSING'})")
    print(f"venv:        {_venv_python(purplellama) or 'not created'}")
    cfg = Path(args.config).expanduser()
    ok = csb.is_dir()
    try:
        name, key, base = provider_for(cfg, args.model)
        print(f"model {args.model} -> provider {name}  spec="
              f"{_redact(spec_for(args.model, key, base))}")
    except Exception as exc:
        print(f"provider resolve: FAILED - {exc}")
        ok = False
    print("benchmarks:")
    for bname, info in BENCHMARKS.items():
        ds = csb / "datasets" / info["dataset"]
        present = ds.is_file()
        ok = ok and present
        print(f"  {bname:16} kind={info['kind']:16} "
              f"dataset={'ok' if present else 'MISSING'}  "
              f"{'judge' if info['judge'] else ''}"
              f"{'+expansion' if info['expansion'] else ''}")
    print("\n" + ("All checks passed." if ok else "Some checks FAILED."))
    return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Run a Mapache-configured model through Meta's CyberSecEval 3.")
    ap.add_argument("--purplellama", default="~/Downloads/PurpleLlama",
                    help="path to a cloned meta-llama/PurpleLlama repo")
    ap.add_argument("--benchmark", default="prompt-injection",
                    choices=list(BENCHMARKS))
    ap.add_argument("--model", default="z-ai/glm-5.2")
    ap.add_argument("--judge-model", default="",
                    help="model to judge responses (default: same as --model)")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG),
                    help="Mapache config.json holding the provider key")
    ap.add_argument("--num-test-cases", type=int, default=0,
                    help="0 = all; a small N for a quick smoke")
    ap.add_argument("--parallel", type=int, default=4)
    ap.add_argument("--out-dir", default="engagements/cyberseceval")
    ap.add_argument("--check", action="store_true",
                    help="validate setup (repo/venv/datasets/spec), no model run")
    args = ap.parse_args()
    sys.exit(do_check(args) if args.check else run_benchmark(args))


if __name__ == "__main__":
    main()
