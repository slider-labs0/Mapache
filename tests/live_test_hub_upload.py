"""
live_test_hub_upload.py — LIVE end-to-end test of the GitHub-tool upload flow.

Unlike smoke_hub_upload.py (which uses a local repo), this hits the REAL network:
it publishes a tool that points at a real public GitHub repo, installs it through
the real HubClient path, builds it the way the CLI does at startup, and actually
clones + runs it over the network on THIS machine.

Safety:
  * Writes to a DEDICATED config via MAPACHE_CONFIG — your real
    ~/.mapache/config.json is never touched.
  * The clone lands in the real ~/.mapache/tools/<name> (true install behavior);
    both the clone dir and the temp config are removed at the end.

Run from the repo root (needs internet + git):
    PYTHONUTF8=1 python tests/live_test_hub_upload.py
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_URL = "https://github.com/octocat/Hello-World.git"  # tiny, famous, public
TOOL = "hello_recon"
# A command that proves we ran code against the cloned checkout: list its files
# and read the repo's README. Single-quotes only inside -c so cmd.exe passes it
# through as one arg; {dir} is the clone path CommandTool fills in.
_PY = ("import sys, os; d = sys.argv[1]; "
       "print('CLONED_FILES', sorted(f for f in os.listdir(d) if f != '.git')); "
       "print('README', open(os.path.join(d, 'README')).read().strip())")
COMMAND = 'python -c "' + _PY + '" {dir}'


def main() -> int:
    cfg_dir = Path(tempfile.mkdtemp(prefix="mapache-livecfg-"))
    cfg_path = cfg_dir / "config.json"
    os.environ["MAPACHE_CONFIG"] = str(cfg_path)  # this process only

    from hub import make_external_tool_manifest, add_to_index, HubClient
    from hub.registry import LocalRegistry
    from core.config import load_config, global_config_path, save_global_config
    from tools.external_tools import build_external_tools

    clone_target = Path.home() / ".mapache" / "tools" / TOOL
    ok = False
    try:
        # A configured user: hub.registry set, nothing else. (Dedicated file.)
        reg_dir = cfg_dir / "registry"
        reg_dir.mkdir()
        save_global_config({"hub": {"registry": str(reg_dir)}}, cfg_path)

        # 1. The hub mints a verified manifest for the real GitHub repo.
        print(f"[1] Publish: mint external_tool manifest for {REPO_URL}")
        manifest = make_external_tool_manifest(
            TOOL, "1.0.0", "list a cloned repo + read its README",
            repo=REPO_URL, command=COMMAND, parameters={}, permission="shell")
        index = add_to_index([], manifest)
        (reg_dir / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
        print(f"    registry {reg_dir} has: {[e['name'] for e in index]}")
        print(f"    checksum: {manifest.checksum}")

        # 2. Install through the real HubClient (config_path from MAPACHE_CONFIG,
        #    exactly how mapache_cli.py builds it).
        print("[2] Install via HubClient (real install path)")
        client = HubClient(LocalRegistry(reg_dir), generated_dir=cfg_dir / "gen",
                           mcp_path=cfg_dir / "mcp.json",
                           config_path=global_config_path())
        print("   ", client.install(TOOL))

        # 3. CLI startup: load the config + build the external tools.
        print("[3] CLI startup: load_config + build_external_tools")
        config = load_config()
        tools, warnings = build_external_tools(config.integrations)
        if warnings:
            print("    WARNINGS:", warnings)
        tool = next(t for t in tools if t.name == TOOL)
        print(f"    built '{tool.name}' [{type(tool).__name__}]")

        # 4. Run it — real network clone into ~/.mapache/tools + execute.
        print(f"[4] Execute: clone {REPO_URL} → {clone_target} and run")
        res = asyncio.run(tool.execute())
        out = res.output or res.error or ""
        print("    ---- tool output ----")
        for line in out.splitlines():
            print("   ", line)
        print("    ---------------------")
        ok = res.success and "README" in out and "Hello World" in out
        print(f"\n{'LIVE TEST PASSED' if ok else 'LIVE TEST FAILED'} "
              f"(success={res.success})")
    finally:
        # Windows-safe: git's .git packs are read-only and resist a plain rmtree
        # (a leftover .git wedges the next clone — the bug this file once caused).
        from tools.external_tools import _rmtree_force
        for d in (clone_target, cfg_dir):
            if Path(d).exists():
                _rmtree_force(Path(d))
        os.environ.pop("MAPACHE_CONFIG", None)
        print("cleanup: removed the cloned tool dir + temp config "
              "(your real ~/.mapache/config.json was never touched)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
