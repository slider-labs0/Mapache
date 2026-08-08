"""
exec_backend.py - pluggable command execution backends (feature H)

Run the offensive toolchain somewhere other than the local shell. A command is
the same string either way; the *backend* decides where it lands:

- `LocalBackend`  - a subprocess on this host (the default; unchanged behavior).
- `SSHBackend`    - wrap the command in an `ssh user@host "<cmd>"` invocation and
                    run that locally (uses the system `ssh` binary - dependency-
                    free, key/agent auth, no paramiko).
- `DockerBackend` - `docker exec <container> sh -c "<cmd>"` for a long-lived
                    container, or `docker run --rm <image> sh -c "<cmd>"` for an
                    ephemeral one (e.g. a Kali image).

`shell` (and any bin runner that adopts it) dispatches through the active backend,
so the whole toolchain can run from an SSH dropbox or a container with no per-tool
changes. The remote backends build an explicit argv (`build_argv`) that is unit-
testable without a live host/daemon; only `run()` actually spawns a process.

OPSEC note: routing commands to a remote host/container means they execute (and
their output returns) off this machine - the engagement scope (J) still gates
*which* commands run, and the active backend is surfaced in the CLI status line.
"""

from __future__ import annotations

import asyncio
import re
import shlex
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

MAX_OUTPUT_BYTES = 50_000
DEFAULT_TIMEOUT = 30


@dataclass
class ExecResult:
    output: str
    exit_code: int = 0
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


async def _spawn(
    argv: Optional[list[str]] = None,
    *,
    shell_cmd: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
) -> ExecResult:
    """Run either an argv (exec) or a shell string, capturing combined output."""
    try:
        if shell_cmd is not None:
            proc = await asyncio.create_subprocess_shell(
                shell_cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, cwd=cwd)
        else:
            proc = await asyncio.create_subprocess_exec(
                *(argv or []), stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, cwd=cwd)
    except FileNotFoundError as exc:
        return ExecResult("", error=f"Command not found: {exc}")
    except PermissionError as exc:
        return ExecResult("", error=f"Permission denied: {exc}")
    except Exception as exc:  # pragma: no cover - defensive
        return ExecResult("", error=f"Exec error: {exc}")

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=float(timeout))
    except asyncio.TimeoutError:
        proc.kill()
        return ExecResult("", error=f"Command timed out after {timeout}s")

    output = stdout.decode("utf-8", errors="replace")
    if len(output) > MAX_OUTPUT_BYTES:
        output = output[:MAX_OUTPUT_BYTES] + "\n[... output truncated]"
    error = (f"Exit code {proc.returncode}"
             if proc.returncode != 0 and not output.strip() else None)
    return ExecResult(output, exit_code=proc.returncode or 0, error=error)


class ExecBackend:
    """Interface; LocalBackend is the reference behavior."""

    name = "base"

    def describe(self) -> str:
        return self.name

    async def run(self, cmd: str, *, timeout: int = DEFAULT_TIMEOUT,
                  working_dir: str = "") -> ExecResult:
        raise NotImplementedError


class LocalBackend(ExecBackend):
    name = "local"

    def describe(self) -> str:
        return "local shell"

    async def run(self, cmd, *, timeout=DEFAULT_TIMEOUT, working_dir="") -> ExecResult:
        if not cmd or not cmd.strip():
            return ExecResult("", error="Empty command")
        return await _spawn(shell_cmd=cmd, timeout=timeout,
                            cwd=working_dir or None)


@dataclass
class SSHBackend(ExecBackend):
    host: str
    user: str = ""
    port: int = 22
    key: str = ""
    name: str = field(default="ssh", init=False)

    def _target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    def build_argv(self, cmd: str, working_dir: str = "") -> list[str]:
        remote = cmd
        if working_dir:
            remote = f"cd {shlex.quote(working_dir)} && {cmd}"
        argv = ["ssh"]
        if self.port and int(self.port) != 22:
            argv += ["-p", str(self.port)]
        if self.key:
            argv += ["-i", self.key]
        # Non-interactive: fail instead of hanging on a password/host-key prompt.
        argv += ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        argv += [self._target(), remote]
        return argv

    def describe(self) -> str:
        return f"ssh {self._target()}"

    async def run(self, cmd, *, timeout=DEFAULT_TIMEOUT, working_dir="") -> ExecResult:
        if not cmd or not cmd.strip():
            return ExecResult("", error="Empty command")
        return await _spawn(self.build_argv(cmd, working_dir), timeout=timeout)


@dataclass
class DockerBackend(ExecBackend):
    container: str = ""
    image: str = ""
    workdir: str = ""
    name: str = field(default="docker", init=False)

    def build_argv(self, cmd: str, working_dir: str = "") -> list[str]:
        wd = working_dir or self.workdir
        if self.container:
            argv = ["docker", "exec"]
            if wd:
                argv += ["-w", wd]
            argv += [self.container, "sh", "-c", cmd]
        else:
            # Ephemeral: a throwaway container from an image, removed on exit.
            argv = ["docker", "run", "--rm"]
            if wd:
                argv += ["-w", wd]
            argv += [self.image, "sh", "-c", cmd]
        return argv

    def describe(self) -> str:
        return (f"docker exec {self.container}" if self.container
                else f"docker run --rm {self.image}")

    async def run(self, cmd, *, timeout=DEFAULT_TIMEOUT, working_dir="") -> ExecResult:
        if not cmd or not cmd.strip():
            return ExecResult("", error="Empty command")
        return await _spawn(self.build_argv(cmd, working_dir), timeout=timeout)


def build_backend(spec: Optional[dict]) -> ExecBackend:
    """Construct a backend from a config dict. Raises ValueError on an
    incompletely-specified remote backend (caller may fall back to local)."""
    spec = spec or {}
    kind = str(spec.get("backend", "local")).lower()
    if kind in ("", "local"):
        return LocalBackend()
    if kind == "ssh":
        host = str(spec.get("host", "")).strip()
        if not host:
            raise ValueError("ssh backend requires a 'host'")
        return SSHBackend(host=host, user=str(spec.get("user", "")),
                          port=int(spec.get("port", 22) or 22),
                          key=str(spec.get("key", "")))
    if kind == "docker":
        container = str(spec.get("container", "")).strip()
        image = str(spec.get("image", "")).strip()
        if not container and not image:
            raise ValueError("docker backend requires a 'container' or 'image'")
        return DockerBackend(container=container, image=image,
                             workdir=str(spec.get("workdir", "")))
    raise ValueError(f"unknown execution backend: {kind!r}")


def backend_from_config(spec: Optional[dict]) -> tuple[ExecBackend, Optional[str]]:
    """Like build_backend, but never raises - on an invalid spec it returns the
    local backend plus a warning string (warn-don't-block)."""
    try:
        return build_backend(spec), None
    except (ValueError, TypeError) as exc:
        return LocalBackend(), f"execution backend misconfigured ({exc}); using local"


# --------------------------------------------------------------------------- #
# Per-sub-agent execution terminals (feature H + P)
# --------------------------------------------------------------------------- #


class DisposableDockerBackend(DockerBackend):
    """A DockerBackend that OWNS the container it runs in (one spun up for a single
    sub-agent) and removes it on `aclose()`. The agent controller calls `aclose`
    when the sub-agent finishes, so each isolated terminal is cleaned up."""

    async def aclose(self) -> None:
        if self.container:
            await _spawn(["docker", "rm", "-f", self.container], timeout=30)


async def spawn_subagent_container(
    image: str, *, network: str = "", name: str = "", workdir: str = "",
) -> DisposableDockerBackend:
    """Start a detached keep-alive container from `image` and return a disposable
    backend bound to it - one sub-agent's private terminal. Removed on aclose()."""
    name = name or f"mapache-sub-{uuid.uuid4().hex[:8]}"
    argv = ["docker", "run", "-d", "--name", name]
    if network:
        argv += ["--network", network]
    # sleep-keep-alive so `docker exec` has a live container for the child's tools.
    argv += ["--entrypoint", "sleep", image, "infinity"]
    res = await _spawn(argv, timeout=120)
    if res.error:
        raise RuntimeError(f"could not start sub-agent container from {image!r}: "
                           f"{res.error or res.output}")
    return DisposableDockerBackend(container=name, workdir=workdir)


def docker_subagent_factory(
    image: str, *, network: str = "", workdir: str = "",
) -> Callable[[Any], Any]:
    """Build a `subagent_backend_factory`: each delegated sub-agent gets its OWN
    disposable container from `image` (on `network`), named after the child so it's
    identifiable, and torn down when the child finishes.

    Usage:
        controller.subagent_backend_factory = docker_subagent_factory(
            "mapache-attacker:latest", network="mapache-lab")

    The returned factory is async (it spins a container up per child); the agent
    controller awaits it. On failure the controller falls back to the shared
    backend, so a Docker hiccup degrades rather than breaks the delegation."""
    def factory(ctx: Any):
        tag = re.sub(r"[^a-zA-Z0-9_.-]", "-", f"{ctx.suffix}-{ctx.operator}")[:32]
        name = f"mapache-sub-{tag}-{uuid.uuid4().hex[:6]}"
        return spawn_subagent_container(image, network=network, name=name,
                                        workdir=workdir)
    return factory
