"""
code_tools.py - Mapache code authoring + execution

`code_run` is the compile-run-fix loop primitive that lets the agent *write code
well* instead of blindly emitting a file and hoping. In ONE atomic action it:

    1. stages the source into the SAME environment the agent's shell runs in
       (backend-aware: local host, or the docker/ssh target - so an exploit the
       agent writes runs where the target's tooling lives, e.g. pwntools inside
       the Linux tools container, not on the Windows host),
    2. compiles it if the language needs it (C/C++/Rust), surfacing compiler
       errors verbatim,
    3. runs it with optional argv + stdin, capturing stdout+stderr+exit code,
    4. returns a STRUCTURED verdict (COMPILE FAILED / EXIT n / OK) so the model
       gets a crisp signal to iterate on rather than parsing raw shell noise.

This is the difference between an agent that hand-waves an exploit and one that
tightens a write -> run -> read-error -> fix loop until the PoC actually fires.
Pair it with the `exploit_dev` operator (core/operators.py).
"""

from __future__ import annotations

import base64
import os
import shlex
import tempfile
from typing import Any

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from core.exec_backend import LocalBackend

# Per-language recipe. {file}/{bin}/{args} are filled at run time. A "compile"
# step (optional) must exit 0 before "run" is attempted; its stderr is the
# feedback the model fixes against.
_LANGS: dict[str, dict[str, str]] = {
    "python":     {"ext": "py",  "run": "python3 {file} {args}"},
    "python2":    {"ext": "py",  "run": "python2 {file} {args}"},
    "bash":       {"ext": "sh",  "run": "bash {file} {args}"},
    "sh":         {"ext": "sh",  "run": "sh {file} {args}"},
    "c":          {"ext": "c",   "compile": "gcc -O2 -w -o {bin} {file}", "run": "{bin} {args}"},
    "cpp":        {"ext": "cpp", "compile": "g++ -O2 -w -o {bin} {file}", "run": "{bin} {args}"},
    "go":         {"ext": "go",  "run": "go run {file} {args}"},
    "rust":       {"ext": "rs",  "compile": "rustc -O -o {bin} {file}", "run": "{bin} {args}"},
    "javascript": {"ext": "js",  "run": "node {file} {args}"},
    "node":       {"ext": "js",  "run": "node {file} {args}"},
    "ruby":       {"ext": "rb",  "run": "ruby {file} {args}"},
    "perl":       {"ext": "pl",  "run": "perl {file} {args}"},
    "php":        {"ext": "php", "run": "php {file} {args}"},
}
_ALIASES = {"py": "python", "c++": "cpp", "cxx": "cpp", "rs": "rust",
            "js": "javascript", "shell": "bash", "rb": "ruby", "pl": "perl"}

MAX_OUTPUT = 20_000


class CodeRunTool(BaseTool):
    name = "code_run"
    description = (
        "Write a program and run it in ONE step, with a structured result you can "
        "iterate on - the right way to develop an exploit/PoC or any script. Give "
        "the `language` and `code`; it stages the source where your shell runs "
        "(inside the target/tools container when one is attached), COMPILES it if "
        "needed (C/C++/Rust) surfacing compiler errors, then RUNS it capturing "
        "stdout+stderr+exit code. Supports `args` (argv) and `stdin`. Prefer this "
        "over file_write+shell for anything you'll run and refine. Languages: "
        + ", ".join(sorted(set(_LANGS) | set(_ALIASES))) + "."
    )
    parameters = {
        "type": "object",
        "properties": {
            "language": {"type": "string",
                         "description": "Source language, e.g. python, c, cpp, go, bash."},
            "code": {"type": "string", "description": "The full program source."},
            "args": {"type": "string", "default": "",
                     "description": "Command-line arguments passed to the program (argv)."},
            "stdin": {"type": "string", "default": "",
                      "description": "Text piped to the program's standard input."},
            "filename": {"type": "string", "default": "",
                         "description": "Optional source filename (else an auto name is used)."},
            "working_dir": {"type": "string", "default": "",
                            "description": "Directory to stage/run in (default: a scratch dir)."},
            "timeout": {"type": "integer", "default": 60,
                        "description": "Seconds to allow compile+run (default 60)."},
        },
        "required": ["language", "code"],
    }
    permissions = {Permission.SHELL, Permission.FILESYSTEM}
    timeout = 180
    version = "0.1.0"
    tags = ["code", "exploit", "core"]

    def __init__(self, backend: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Same contract as ShellTool: None/local runs on the host; a docker/ssh
        # backend routes staging + compile + run onto the target box, so the code
        # executes next to the tooling and the service it targets.
        self.backend = backend

    def _runner(self) -> Any:
        return self.backend if self.backend is not None else LocalBackend()

    @staticmethod
    def _posix(backend: Any) -> bool:
        # Local Windows host is the only non-POSIX runner; docker/ssh are POSIX.
        return getattr(backend, "name", "local") != "local"

    async def execute(self, language: str, code: str, args: str = "", stdin: str = "",
                      filename: str = "", working_dir: str = "", timeout: int = 60,
                      **kwargs: Any) -> ToolResult:
        if not (code or "").strip():
            return ToolResult.fail("No code provided.")
        lang = _ALIASES.get(language.strip().lower(), language.strip().lower())
        spec = _LANGS.get(lang)
        if spec is None:
            return ToolResult.fail(
                f"Unsupported language '{language}'. Supported: "
                + ", ".join(sorted(_LANGS)))

        backend = self._runner()
        posix = self._posix(backend)
        # Stage into a dedicated scratch dir so runs never litter the user's cwd:
        # /tmp on a POSIX target, the OS temp dir on the local host.
        wd = working_dir or ("/tmp/mapache_code" if posix
                             else os.path.join(tempfile.gettempdir(), "mapache_code"))
        stem = (os.path.basename(filename).rsplit(".", 1)[0] if filename else "mapache_prog")
        join = (lambda *a: "/".join(a)) if posix else (lambda *a: os.path.join(*a))
        src = join(wd, f"{stem}.{spec['ext']}")
        binp = join(wd, f"{stem}.bin")
        stdin_path = join(wd, "_stdin.txt")

        # 1. Stage the source (and stdin) atomically. base64 avoids all quoting/
        # heredoc hazards for arbitrary code over a POSIX shell; on the local host
        # we write directly so it works on Windows too (no base64 dependency).
        stage_err = await self._stage(backend, posix, wd, src, stdin_path, code, stdin, timeout)
        if stage_err is not None:
            return ToolResult.fail(f"Could not stage source: {stage_err}")
        stdin_redir = f" < {shlex.quote(stdin_path) if posix else stdin_path}" if stdin else ""

        header: list[str] = [f"language={lang}  file={src}"]

        # 2. Compile (if the language needs it). A non-zero compile is the loop's
        # feedback, not a tool crash - return it as output so the model fixes it.
        if "compile" in spec:
            cc = spec["compile"].format(bin=binp, file=src)
            res = await backend.run(cc, timeout=timeout, working_dir=wd)
            if (res.exit_code or 0) != 0 or (res.error and not (res.output or "").strip()):
                out = (res.output or res.error or "").strip()
                return ToolResult.ok(
                    "COMPILE FAILED\n" + "\n".join(header) + f"\n$ {cc}\n{_cap(out)}",
                    metadata={"phase": "compile", "exit_code": res.exit_code, "ok": False})
            header.append(f"compiled: {cc}")

        # 3. Run, capturing stdout+stderr+exit.
        run_tmpl = spec["run"].format(bin=binp, file=src, args=args).strip()
        run_cmd = run_tmpl + stdin_redir
        res = await backend.run(run_cmd, timeout=timeout, working_dir=wd)
        exit_code = res.exit_code or 0
        out = res.output if (res.output or "").strip() else (res.error or "")
        status = "OK (exit 0)" if exit_code == 0 and res.error is None else (
            f"RUNTIME ERROR (exit {exit_code})")
        body = ("RAN\n" + "\n".join(header) + f"\n$ {run_cmd}\n"
                f"--- {status} ---\n{_cap(out) or '(no output)'}")
        return ToolResult.ok(body, metadata={"phase": "run", "exit_code": exit_code,
                                             "ok": exit_code == 0, "language": lang})

    async def _stage(self, backend: Any, posix: bool, wd: str, src: str,
                     stdin_path: str, code: str, stdin: str, timeout: int) -> str | None:
        """Write the source (+ optional stdin) into the run environment. Returns an
        error string on failure, else None."""
        try:
            if posix:
                b64 = base64.b64encode(code.encode()).decode()
                cmd = f"mkdir -p {shlex.quote(wd)} && echo {b64} | base64 -d > {shlex.quote(src)}"
                if stdin:
                    sb64 = base64.b64encode(stdin.encode()).decode()
                    cmd += f" && echo {sb64} | base64 -d > {shlex.quote(stdin_path)}"
                res = await backend.run(cmd, timeout=min(timeout, 30), working_dir="")
                if (res.exit_code or 0) != 0:
                    return (res.output or res.error or "stage command failed").strip()
                return None
            # Local host: write via the filesystem directly (Windows-safe).
            from pathlib import Path
            Path(wd).mkdir(parents=True, exist_ok=True)
            Path(src).write_text(code, encoding="utf-8")
            if stdin:
                Path(stdin_path).write_text(stdin, encoding="utf-8")
            return None
        except Exception as exc:
            return str(exc)


def _cap(text: str) -> str:
    text = text or ""
    if len(text) <= MAX_OUTPUT:
        return text
    return text[:MAX_OUTPUT] + f"\n[... truncated, {len(text)} chars total]"
