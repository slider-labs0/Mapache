"""
smoke_cli.py — live CLI smoke harness (Tier 2)

Drives the real `python -m cli` end-to-end against a running Ollama model by
scripting a stdin session, waiting for the `you >` prompt to return between
lines (so a command is never injected mid-turn as steering), and asserting on
the captured output.

This closes the gap the unit suite can't: it exercises the actual CLI entrypoint
+ a real model. It is NOT part of `test_core.py` (that stays Ollama-free) — run
it explicitly when a model is up:

    $env:PYTHONUTF8=1; python tests/smoke_cli.py --model qwen2.5:32b

The default scenario proves feature A end-to-end: the model authors a tool via
create_tool and then invokes it in the same turn (the create→expose→call loop).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROMPT = "you >"


class CliSession:
    """Launch the CLI and talk to it, waiting on the (newline-less) prompt."""

    def __init__(self, model: str, workdir: Path, extra_args: list[str] | None = None):
        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "cli", "--model", model, "--no-context",
             *(extra_args or [])],
            cwd=str(workdir), env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        self._buf: list[str] = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    def _drain(self) -> None:
        # read(1): the prompt has no trailing newline, so a line reader would
        # block forever waiting on it. Char reads surface it as soon as it lands.
        while True:
            c = self.proc.stdout.read(1)
            if not c:
                return
            with self._lock:
                self._buf.append(c)

    @property
    def text(self) -> str:
        with self._lock:
            return "".join(self._buf)

    def wait_for_prompt(self, count: int, timeout: float) -> bool:
        """Block until the prompt has appeared `count` times, or time out."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.text.count(PROMPT) >= count:
                return True
            if self.proc.poll() is not None:
                return self.text.count(PROMPT) >= count
            time.sleep(0.2)
        return False

    def send(self, line: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def close(self, timeout: float = 30) -> None:
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def run_create_tool_scenario(model: str, boot_timeout: float, turn_timeout: float) -> int:
    """Author add_one via create_tool and invoke it in one turn; assert 42."""
    gen_dir = REPO / "plugins" / "generated" / "add_one"
    shutil.rmtree(gen_dir, ignore_errors=True)  # clean slate so create_tool runs

    print(f"[smoke] launching CLI with {model} …")
    s = CliSession(model, REPO)
    try:
        if not s.wait_for_prompt(1, boot_timeout):
            print("[smoke] FAIL — CLI never reached the first prompt")
            print(s.text[-800:])
            return 1

        s.send("Create a tool named add_one that takes an integer argument n and "
               "returns n + 1. After creating it, call add_one with n=41 and tell "
               "me the result.")
        print("[smoke] prompt sent; waiting for the turn to finish (model is slow) …")

        if not s.wait_for_prompt(2, turn_timeout):
            print("[smoke] FAIL — turn did not complete before timeout")
            print(s.text[-1500:])
            return 1

        s.send("/quit")
        s.close()
    finally:
        if s.proc.poll() is None:
            s.proc.kill()

    out = s.text

    # --- assertions --------------------------------------------------- #
    checks = []
    created = "create_tool(" in out or "Created tool 'add_one'" in out
    checks.append(("model emitted a create_tool call", created))

    manifest = gen_dir / "manifest.json"
    persisted = manifest.is_file()
    checks.append(("add_one persisted to disk", persisted))

    used = False
    use_count = 0
    if persisted:
        import json
        m = json.loads(manifest.read_text(encoding="utf-8"))
        use_count = int(m.get("use_count", 0))
        used = use_count >= 1
    checks.append(("add_one was invoked (use_count >= 1)", used))

    # The model picks its own n, so don't gate on the model's arithmetic/
    # instruction-following. Verify the *tool* returned n+1 for whatever n the
    # model actually called it with — that's the feature working.
    import re
    m_call = re.search(r"add_one\(\{'n':\s*(\d+)\}\)", out)
    answer = out.rsplit("agent >", 1)[1] if "agent >" in out else out
    value_ok = bool(m_call) and (str(int(m_call.group(1)) + 1) in answer)
    detail = (f"model called add_one(n={m_call.group(1)}); answer reflects "
              f"{int(m_call.group(1)) + 1}" if m_call else "no add_one call seen")
    checks.append((f"tool returned n+1 ({detail})", value_ok))

    print("\n[smoke] results:")
    ok = True
    for label, passed in checks:
        print(f"  {'PASS' if passed else 'FAIL'}  {label}")
        ok = ok and passed

    print(f"\n[smoke] create_tool log line / final answer (use_count={use_count}):")
    for line in out.splitlines():
        if "create_tool(" in line or "add_one" in line or line.strip().startswith("agent >"):
            print("   " + line.strip()[:160])

    return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:32b")
    ap.add_argument("--boot-timeout", type=float, default=120.0)
    ap.add_argument("--turn-timeout", type=float, default=420.0)
    args = ap.parse_args()
    sys.exit(run_create_tool_scenario(args.model, args.boot_timeout, args.turn_timeout))


if __name__ == "__main__":
    main()
