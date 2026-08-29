"""supply_chain_tools.py - offline software-supply-chain risk audit of a dependency manifest.

`dep_audit` parses the dependency manifests a real project ships - package.json,
requirements.txt, Pipfile, and the npm/yarn/pip lockfiles - and turns them into concrete
supply-chain findings without touching the network:

  * typosquats of popular packages (Damerau-Levenshtein distance 1 from a known name, or a
    known confusable) - the dependency-confusion / typosquat entry point,
  * install-time code execution (npm preinstall/install/postinstall lifecycle scripts) -
    the mechanism a malicious package actually uses to run,
  * unpinned / range versions (^, ~, *, latest, git/url deps) that let a compromised
    upstream ship you new code silently,
  * direct git/URL/tarball dependencies that bypass the registry's integrity checks.

It is read-only and dependency-free (stdlib json/re only) and evidence-first: every
finding names the exact package + line it came from. A registry-backed confirmation
(does the name exist publicly? is it newer than the internal one?) is the online follow-up
the report should recommend - this tool gives the offline triage.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

# A compact set of very-high-download packages whose typosquats are the classic vector.
_POPULAR = {
    "npm": {"react", "lodash", "express", "axios", "chalk", "commander", "request",
            "moment", "async", "debug", "webpack", "babel", "eslint", "jquery",
            "colors", "dotenv", "bluebird", "yargs", "uuid", "vue", "next", "typescript",
            "cross-env", "node-fetch", "socket.io", "mongoose", "redux", "electron"},
    "pypi": {"requests", "urllib3", "numpy", "pandas", "flask", "django", "boto3",
             "setuptools", "pip", "wheel", "cryptography", "pyyaml", "jinja2", "click",
             "pytest", "scipy", "tensorflow", "torch", "beautifulsoup4", "selenium",
             "colorama", "python-dateutil", "certifi", "six", "pillow", "sqlalchemy"},
}
# Known confusables people fall for (typosquat/lookalike -> the real package).
_KNOWN_BAD = {
    "npm": {"cross-env.js": "cross-env", "crossenv": "cross-env", "mongose": "mongoose",
            "lodahs": "lodash", "jquery.js": "jquery", "fabric-js": "fabric",
            "node-sqlite": "sqlite3", "babelcli": "babel-cli", "d3.js": "d3"},
    "pypi": {"python-sqlite": "sqlite3", "python3-dateutil": "python-dateutil",
             "jeIlyfish": "jellyfish", "reqeusts": "requests", "beautifulsoup": "beautifulsoup4",
             "djago": "django", "urlib3": "urllib3", "python-mysql": "mysqlclient",
             "colourama": "colorama", "tensorflow-gpu-": "tensorflow"},
}
_UNPINNED_NPM = re.compile(r"^[\^~]|^\*$|^latest$|\|\||\s-\s|x$|\.x$")
_URL_DEP = re.compile(r"^(?:git\+|git:|https?:|file:|github:|[\w.-]+/[\w.-]+#)")


def _dl_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (with transposition) - small strings, so the full DP is fine."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return 2  # we only care about distance-1; anything larger is "far"
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _typosquat(name: str, ecosystem: str) -> Optional[str]:
    n = name.lower().strip()
    known = _KNOWN_BAD.get(ecosystem, {})
    if n in known:
        return known[n]
    if n in _POPULAR.get(ecosystem, ()):  # it IS the popular package
        return None
    for pop in _POPULAR.get(ecosystem, ()):
        if _dl_distance(n, pop) == 1:
            return pop
    return None


class DepAuditTool(BaseTool):
    """Offline supply-chain audit of a dependency manifest: typosquats, install-time
    scripts, unpinned versions, and registry-bypassing git/URL dependencies."""

    name = "dep_audit"
    description = (
        "Audit a software project's dependency manifest for supply-chain risk, offline. "
        "Point it at a project directory or a specific file - package.json, "
        "package-lock.json, yarn.lock, requirements.txt, or Pipfile. Reports: typosquats / "
        "dependency-confusion candidates (a name one edit away from a popular package, or a "
        "known confusable), install-time lifecycle scripts (npm pre/post-install = code "
        "execution on `npm install`), unpinned/range versions (^ ~ * latest) that let a "
        "compromised upstream push code silently, and direct git/URL/tarball deps that skip "
        "registry integrity. Read-only. Give `path`. Recommends the online registry check "
        "(name-exists / newer-than-internal) as follow-up."
    )
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string",
                                "description": "Project dir or a manifest/lockfile."}},
        "required": ["path"],
    }
    permissions = {Permission.FILESYSTEM}
    timeout = 45
    tags = ["supply-chain", "dependencies", "sbom", "static-analysis"]

    _MANIFESTS = ("package.json", "package-lock.json", "yarn.lock", "requirements.txt",
                  "Pipfile")

    def _find_manifests(self, path: str) -> list[str]:
        if os.path.isfile(path):
            return [path]
        found = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "venv", ".venv")]
            for fn in files:
                if fn in self._MANIFESTS:
                    found.append(os.path.join(root, fn))
        return found[:40]

    def _audit_package_json(self, data: str, rel: str, out: dict) -> None:
        try:
            obj = json.loads(data)
        except Exception:
            return
        scripts = obj.get("scripts", {}) or {}
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            if hook in scripts:
                out["install_scripts"].append(
                    f"npm '{hook}' script runs on install: {str(scripts[hook])[:100]}  [{rel}]")
        for sect in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, ver in (obj.get(sect, {}) or {}).items():
                self._check_dep(name, str(ver), "npm", rel, out)

    def _audit_requirements(self, data: str, rel: str, out: dict) -> None:
        for raw in data.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-r", "-e", "--")):
                if line.startswith(("-e", "git+", "http")):
                    out["url_deps"].append(f"editable/URL dependency: {line[:100]}  [{rel}]")
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)\s*([=<>!~]*.*)?$", line)
            if not m:
                if _URL_DEP.match(line):
                    out["url_deps"].append(f"URL/VCS dependency: {line[:100]}  [{rel}]")
                continue
            name, spec = m.group(1), (m.group(2) or "").strip()
            self._check_dep(name, spec, "pypi", rel, out)
            if not spec or spec.startswith((">", "<")) or "*" in spec:
                out["unpinned"].append(f"{name} unpinned/range ('{spec or 'any'}')  [{rel}]")

    def _check_dep(self, name: str, ver: str, eco: str, rel: str, out: dict) -> None:
        real = _typosquat(name, eco)
        if real:
            out["typosquats"].append(
                f"'{name}' is one edit from popular '{real}' - possible typosquat / "
                f"dependency-confusion  [{rel}]")
        if eco == "npm":
            v = ver.strip()
            if _URL_DEP.match(v):
                out["url_deps"].append(f"{name}: git/URL dependency '{v[:60]}' (skips registry)  [{rel}]")
            elif _UNPINNED_NPM.search(v) or v in ("", "*", "latest"):
                out["unpinned"].append(f"{name} unpinned/range ('{v or 'any'}')  [{rel}]")

    def execute_sync(self, path: str) -> ToolResult:
        manifests = self._find_manifests(path)
        if not manifests:
            return ToolResult.fail(
                f"dep_audit: no supported manifest found under {path!r} "
                f"(looked for {', '.join(self._MANIFESTS)}).")
        out = {"typosquats": [], "install_scripts": [], "unpinned": [], "url_deps": []}
        base = path if os.path.isdir(path) else os.path.dirname(path)
        for mf in manifests:
            rel = os.path.relpath(mf, base) if base else os.path.basename(mf)
            try:
                with open(mf, "r", encoding="utf-8", errors="replace") as fh:
                    data = fh.read(2_000_000)
            except Exception:
                continue
            fn = os.path.basename(mf)
            if fn in ("package.json", "package-lock.json"):
                self._audit_package_json(data, rel, out)
            elif fn in ("requirements.txt", "Pipfile"):
                self._audit_requirements(data, rel, out)
            elif fn == "yarn.lock":
                for name in re.findall(r'^"?([A-Za-z0-9@._/-]+?)@', data, re.M):
                    base_name = name.split("/")[-1] if name.startswith("@") else name
                    self._check_dep(base_name, "", "npm", rel, out)

        for k in out:
            out[k] = list(dict.fromkeys(out[k]))
        total = sum(len(v) for v in out.values())
        lines = [f"dep_audit - {path}  ({len(manifests)} manifest(s))"]
        titles = {
            "typosquats": "TYPOSQUAT / DEPENDENCY-CONFUSION CANDIDATES",
            "install_scripts": "INSTALL-TIME CODE EXECUTION (lifecycle scripts)",
            "url_deps": "REGISTRY-BYPASSING (git/URL/tarball) DEPENDENCIES",
            "unpinned": "UNPINNED / RANGE VERSIONS (silent-upstream-update risk)",
        }
        for key, title in titles.items():
            if out[key]:
                lines.append(f"\n{title}:")
                lines += [f"  - {x}" for x in out[key][:25]]
                if len(out[key]) > 25:
                    lines.append(f"  ... {len(out[key]) - 25} more")
        if total == 0:
            lines.append("\nNo typosquats, install scripts, URL deps, or unpinned versions "
                         "found in the parsed manifests. Deps look pinned and registry-backed.")
        else:
            lines.append("\nNext (online): for each typosquat candidate confirm the popular "
                         "package is the intended one; for dependency-confusion, check "
                         "whether an INTERNAL package name is claimable / newer on the PUBLIC "
                         "registry (npm/pypi). Review install scripts before running `install`.")
        return ToolResult.ok("\n".join(lines),
                             metadata={k: len(v) for k, v in out.items()} | {"total": total})

    async def execute(self, path: str, **kwargs: Any) -> ToolResult:
        path = (path or "").strip()
        if not path or not os.path.exists(path):
            return ToolResult.fail(f"dep_audit: path not found: {path!r}")
        return self.execute_sync(path)
