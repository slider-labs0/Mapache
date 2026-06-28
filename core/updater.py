"""
updater.py — version stamp + update manager (feature D)

Keeps an installed Mapache current: a `VERSION` stamp at the repo root, a
`mapache --version` / `mapache update` entry, and a non-blocking "update
available" notice at startup.

Two deliberate design choices keep this safe and testable:

- **Startup is never blocked on the network.** The startup notice reads a small
  cache (`~/.mapache/.update_check.json`) written by the last explicit
  `mapache update [--check]`, and compares it to the local `VERSION` offline.
  The actual remote lookup (`git ls-remote --tags`) only runs on the explicit
  command.
- **Applying an update is conservative.** `mapache update` backs up the config
  first, then does a fast-forward-only `git pull`; if there's no remote or the
  pull can't fast-forward it says so instead of forcing anything, and it flags
  (does not silently run) a `requirements.txt` reinstall.

Version comparison is numeric-segment based (`v1.2.10 > v1.2.9`), tolerant of a
leading `v` and of missing segments.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = REPO_ROOT / "VERSION"
REQUIREMENTS_FILE = REPO_ROOT / "requirements.txt"


# --------------------------------------------------------------------------- #
# Version parsing / comparison
# --------------------------------------------------------------------------- #


def parse_version(v: str) -> tuple[int, ...]:
    """Numeric segments of a version string ('v1.2.10' → (1, 2, 10))."""
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums) or (0,)


def compare_versions(a: str, b: str) -> int:
    """-1 if a<b, 0 if equal, 1 if a>b (segment-wise, zero-padded)."""
    pa, pb = parse_version(a), parse_version(b)
    width = max(len(pa), len(pb))
    pa += (0,) * (width - len(pa))
    pb += (0,) * (width - len(pb))
    return (pa > pb) - (pa < pb)


def is_newer(candidate: str, current: str) -> bool:
    return compare_versions(candidate, current) > 0


def local_version(path: Path = VERSION_FILE) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


# --------------------------------------------------------------------------- #
# Remote lookup (explicit command only — never at startup)
# --------------------------------------------------------------------------- #


def _run(args: list[str]) -> Optional[str]:
    """Run a command, returning stdout, or None on any failure (never raises)."""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def latest_remote_version(repo: Path = REPO_ROOT) -> Optional[str]:
    """Highest semver tag on the git remote, or None (no remote / git / tags)."""
    out = _run(["git", "-C", str(repo), "ls-remote", "--tags", "--refs"])
    if out is None:
        return None
    tags = re.findall(r"refs/tags/(\S+)", out)
    versions = [t for t in tags if re.match(r"v?\d", t)]
    if not versions:
        return None
    return max(versions, key=parse_version)


# --------------------------------------------------------------------------- #
# Offline cache (powers the non-blocking startup notice)
# --------------------------------------------------------------------------- #


def _cache_path(environ: Optional[dict] = None) -> Path:
    import os
    environ = environ if environ is not None else dict(os.environ)
    home = environ.get("USERPROFILE") or environ.get("HOME") or str(Path.home())
    return Path(home) / ".mapache" / ".update_check.json"


def write_cache(latest: str, *, environ: Optional[dict] = None) -> None:
    path = _cache_path(environ)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(
            {"latest": latest, "checked_at": datetime.now(timezone.utc).isoformat()}),
            encoding="utf-8")
    except OSError:
        pass


def read_cached_latest(*, environ: Optional[dict] = None) -> Optional[str]:
    try:
        data = json.loads(_cache_path(environ).read_text(encoding="utf-8"))
        return data.get("latest")
    except (OSError, json.JSONDecodeError):
        return None


def update_notice(*, environ: Optional[dict] = None,
                  current: Optional[str] = None) -> Optional[str]:
    """A one-line startup notice if the cached latest is newer than local — no
    network, so it never delays startup. None when up to date / nothing cached."""
    current = current or local_version()
    latest = read_cached_latest(environ=environ)
    if latest and is_newer(latest, current):
        return f"Update available: {current} → {latest} (run `mapache update`)"
    return None


# --------------------------------------------------------------------------- #
# Status + apply
# --------------------------------------------------------------------------- #


@dataclass
class UpdateStatus:
    current: str
    latest: Optional[str]
    update_available: bool
    detail: str


def check_for_update(
    *,
    current: Optional[str] = None,
    latest_fn: Callable[[], Optional[str]] = latest_remote_version,
    environ: Optional[dict] = None,
) -> UpdateStatus:
    """Look up the latest remote version and cache it for the startup notice."""
    current = current or local_version()
    try:
        latest = latest_fn()
    except Exception:
        latest = None
    if not latest:
        return UpdateStatus(current, None, False,
                            "Latest version unknown (no git remote or no tags).")
    write_cache(latest, environ=environ)
    if is_newer(latest, current):
        return UpdateStatus(current, latest, True,
                            f"Update available: {current} → {latest}")
    return UpdateStatus(current, latest, False, f"Up to date ({current}).")


def backup_config(*, config_path: Optional[Path] = None,
                  environ: Optional[dict] = None) -> Optional[Path]:
    """Copy the global config to a timestamped .bak before an update."""
    from .config import global_config_path
    src = Path(config_path) if config_path is not None else global_config_path(environ)
    if not src.is_file():
        return None
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = src.with_name(f"{src.name}.{ts}.bak")
    try:
        shutil.copy2(src, dst)
        return dst
    except OSError:
        return None


def apply_update(*, repo: Path = REPO_ROOT, do_pull: bool = True,
                 environ: Optional[dict] = None) -> str:
    """Back up config, then fast-forward `git pull` if an update is available.

    Conservative: ff-only pull, and a requirements reinstall is flagged for the
    user to run, never executed silently.
    """
    lines: list[str] = []
    backup = backup_config(environ=environ)
    lines.append(f"Backed up config → {backup}" if backup
                 else "No config file to back up.")

    status = check_for_update(environ=environ)
    lines.append(status.detail)
    if not status.update_available:
        return "\n".join(lines)

    if do_pull:
        out = _run(["git", "-C", str(repo), "pull", "--ff-only"])
        if out is None:
            lines.append("Could not fast-forward (no remote, or local changes). "
                         "Update manually with `git pull`.")
        else:
            lines.append("Pulled latest:\n" + out.strip())
            if REQUIREMENTS_FILE.is_file():
                lines.append("Dependencies may have changed — run: "
                             "pip install -r requirements.txt")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI entry (`mapache version` / `mapache update [--check]`)
# --------------------------------------------------------------------------- #


def run_update_cmd(argv: list[str]) -> int:
    check_only = "--check" in argv or "-n" in argv
    if check_only:
        status = check_for_update()
        print(f"  {status.detail}")
        return 0
    print(apply_update())
    return 0
