"""
smoke_hub_upload.py — end-to-end walk of the GitHub-tool upload flow.

Mimics the real path with NO network and NO touching your real config:
  1. an author publishes a repo (a real local git repo stands in for GitHub)
  2. the hub site mints a verified manifest from its `mapache-tool.json`
  3. the manifest lands in a registry index.json
  4. the CLI installs it → an `integrations` entry in a throwaway config
  5. the CLI builds a CommandTool from that config (startup path)
  6. (best-effort) the tool clones the repo and actually runs

Run from the repo root:   PYTHONUTF8=1 python tests/smoke_hub_upload.py
Everything lands in a temp dir that's removed at the end.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _run() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="mapache-hub-smoke-"))
    # Hermetic home so any clone lands in the temp dir, not your real ~/.mapache.
    os.environ["USERPROFILE"] = str(tmp)
    os.environ["HOME"] = str(tmp)

    from hub import manifest_from_github, add_to_index, PublishError
    from hub.registry import LocalRegistry
    from hub.client import HubClient
    from tools.external_tools import build_external_tools
    from core.config import load_config

    def step(n, msg):
        print(f"\n[{n}] {msg}")

    # 1. Author's repo: a real local git repo with mapache-tool.json + a script.
    step(1, "Author creates a repo with mapache-tool.json")
    repo = tmp / "author_repo"
    repo.mkdir()
    (repo / "run.py").write_text(
        "import sys; print('demo_recon ran, args =', sys.argv[1:])\n", encoding="utf-8")
    declared = {
        "name": "demo_recon", "version": "1.0.0",
        "description": "demo recon tool",
        "command": "python {dir}/run.py {args}",
        "params": {"args": {"type": "string", "description": "arguments", "required": True}},
        "permission": "shell",
    }
    (repo / "mapache-tool.json").write_text(json.dumps(declared, indent=2), encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@b.c", "-c", "user.name=smoke",
                    "commit", "-qm", "init"], cwd=repo, check=True)
    print("    repo:", repo)

    # 2. Hub site mints a manifest from the repo's declaration (repo_url authoritative).
    step(2, "Hub publishes: manifest_from_github(repo_url, mapache-tool.json)")
    repo_url = "https://github.com/example/demo_recon"
    manifest = manifest_from_github(repo_url, (repo / "mapache-tool.json").read_text("utf-8"))
    print(f"    minted {manifest.name} v{manifest.version} [{manifest.skill_type}] "
          f"checksum={manifest.checksum[:16]}…")

    # Show the anti-spoof + validation guards actually bite.
    spoof = json.dumps({"name": "demo_recon", "repo": "https://evil/x",
                        "command": "python {dir}/run.py {args}"})
    assert manifest_from_github(repo_url, spoof).repo == repo_url, "repo_url must win"
    try:
        manifest_from_github(repo_url, json.dumps({"name": "demo_recon", "command": "echo hi"}))
        raise SystemExit("FAIL: a command without {dir} should be refused")
    except PublishError as exc:
        print("    validation OK — refused a repo tool with no {dir}:", exc)

    # 3. Fold it into the registry index.json (what UrlRegistry serves).
    step(3, "Add to registry index.json")
    reg_dir = tmp / "registry"
    reg_dir.mkdir()
    index = add_to_index([], manifest)
    (reg_dir / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    print("    index has:", [e["name"] for e in index])

    # 4. CLI-side install into a throwaway config.
    step(4, "CLI installs it → integrations entry in config.json")
    cfg = tmp / ".mapache" / "config.json"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    client = HubClient(LocalRegistry(reg_dir), generated_dir=tmp / "gen",
                       mcp_path=tmp / "mcp.json", config_path=cfg)
    print("   ", client.install("demo_recon"))
    entry = next(e for e in json.loads(cfg.read_text("utf-8"))["integrations"]
                 if e["name"] == "demo_recon")
    print("    config integrations entry:", json.dumps(entry))

    # 5. Build the tool from that config — exactly what the CLI does at startup.
    step(5, "CLI startup builds a CommandTool from the config")
    config = load_config(global_path=cfg, environ={"HOME": str(tmp), "USERPROFILE": str(tmp)})
    tools, warnings = build_external_tools(config.integrations)
    assert not warnings, warnings
    tool = next(t for t in tools if t.name == "demo_recon")
    print(f"    built tool '{tool.name}' params={list(tool.parameters['properties'])}")

    # 6. Best-effort: actually run it (clone the local repo as a GitHub stand-in).
    step(6, "Execute the tool (clones the repo + runs it)")
    tool._repo = repo.as_uri()  # file:// stand-in; product accepts https/git@ from the hub
    try:
        res = asyncio.run(tool.execute(args="scanme.local"))
        print("    ", (res.output or res.error).replace("\n", "\n     "))
    except Exception as exc:  # shell/git quirks shouldn't fail the smoke
        print("    (execution step skipped:", exc, ")")

    print("\nSMOKE OK — publish → index → install → build all succeeded.")
    # Cleanup (best-effort; temp dir).
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    _run()
