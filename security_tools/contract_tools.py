"""contract_tools.py - offline static analysis of Solidity smart-contract source.

`contract_scan` reads Solidity source (a file, a directory of `.sol`, or pasted code) and
flags the vulnerability classes that actually drain funds on-chain, each anchored to the
line it appears on:

  * reentrancy - an external call (`.call{value:}` / `.transfer` / a token transfer) that
    happens BEFORE state is updated (the DAO / checks-effects-interactions violation),
  * tx.origin authentication - `require(tx.origin == ...)`, phishable delegate-call auth,
  * unchecked low-level call - `.call(...)` whose boolean return is ignored (silent failure),
  * delegatecall to user-controlled address - the proxy-storage / arbitrary-code hazard,
  * unprotected selfdestruct / arbitrary state (missing onlyOwner) - the Parity freeze class,
  * unprotected critical setters / owner change without access control,
  * dangerous randomness from block.timestamp / blockhash (predictable),
  * floating / outdated pragma and (pre-0.8) unchecked arithmetic hints.

Read-only, dependency-free (regex + light structural parse, no solc), evidence-first: each
finding cites the exact line. Deep symbolic work (slither/mythril) is the recommended
follow-up; this is the fast triage that finds the obvious money bugs first.
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

_EXT_CALL = re.compile(r"\.call\s*\{[^}]*value\s*:|\.call\s*\.value\s*\(|\.transfer\s*\(|"
                       r"\.send\s*\(|\.delegatecall\s*\(")
_STATE_WRITE = re.compile(r"^\s*[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*(?:[-+]?=|=)\s*[^=]")
_FUNC = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^\{;]*)")
_MODIFIERS_AUTH = ("onlyowner", "onlyadmin", "auth", "restricted", "require(msg.sender",
                   "onlyrole", "hasrole")


def _line_no(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


class ContractScanTool(BaseTool):
    """Static-analyze Solidity source for the high-impact bug classes (reentrancy,
    tx.origin auth, unchecked calls, delegatecall, unprotected selfdestruct/setters)."""

    name = "contract_scan"
    description = (
        "Static-analyze Solidity smart-contract source for the vulnerability classes that "
        "drain funds: reentrancy (external call before state update - checks-effects "
        "violation), tx.origin authentication (phishable), unchecked low-level .call, "
        "delegatecall to a user-controlled address, unprotected selfdestruct / critical "
        "setters (missing onlyOwner), predictable randomness (block.timestamp/blockhash), "
        "and floating/outdated pragma. Read-only/offline, each finding cites the line. "
        "Give `path` (a .sol file or a dir) OR `source` (pasted code). Recommends "
        "slither/mythril as the deep follow-up."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "A .sol file or a directory of contracts."},
            "source": {"type": "string", "description": "Solidity source pasted directly."},
        },
    }
    permissions = {Permission.FILESYSTEM}
    timeout = 45
    tags = ["web3", "smart-contract", "solidity", "static-analysis"]

    def _scan_source(self, src: str, where: str, findings: list[str]) -> None:
        low = src.lower()

        # pragma hygiene
        pm = re.search(r"pragma\s+solidity\s+([^;]+);", src)
        if pm:
            spec = pm.group(1).strip()
            if spec.startswith("^") or ">" in spec:
                findings.append(f"[{where}] floating pragma '{spec}' - pin an exact compiler "
                                "version so builds are reproducible.")
            mver = re.search(r"0\.(\d+)\.(\d+)", spec)
            if mver and (int(mver.group(1)) < 8):
                findings.append(f"[{where}] pre-0.8 Solidity ({spec}) - arithmetic is NOT "
                                "checked; confirm SafeMath is used on every +-*/ or overflow "
                                "is possible.")

        # tx.origin auth
        for m in re.finditer(r"tx\.origin", src):
            ctx = src[max(0, m.start() - 40):m.start() + 40]
            if "==" in ctx or "require" in ctx.lower():
                findings.append(f"[{where}:{_line_no(src, m.start())}] tx.origin used for "
                                "authorization - phishable; a malicious contract the owner "
                                "calls can impersonate them. Use msg.sender.")

        # unprotected selfdestruct
        for m in re.finditer(r"\bselfdestruct\s*\(|\bsuicide\s*\(", src):
            findings.append(f"[{where}:{_line_no(src, m.start())}] selfdestruct present - "
                            "ensure it is guarded by strict access control (onlyOwner); an "
                            "unprotected selfdestruct lets anyone kill the contract / drain it.")

        # delegatecall to a non-constant target
        for m in re.finditer(r"([A-Za-z_]\w*)\.delegatecall\s*\(", src):
            tgt = m.group(1)
            findings.append(f"[{where}:{_line_no(src, m.start())}] delegatecall to '{tgt}' - "
                            "if that address is user-controllable this is arbitrary code "
                            "execution against THIS contract's storage (proxy hijack).")

        # unchecked low-level call (return value ignored)
        for m in re.finditer(r"(?<![=!<>])(\w+)\.call\s*[\({]", src):
            start = src.rfind("\n", 0, m.start()) + 1
            line = src[start:src.find("\n", m.start()) if src.find("\n", m.start()) != -1 else len(src)]
            if not re.search(r"(require|assert|bool\s+\w+\s*=|if\s*\(|,\s*\)\s*=)", line):
                findings.append(f"[{where}:{_line_no(src, m.start())}] low-level .call return "
                                "value not checked - a failed call silently continues. "
                                "Check the returned bool.")

        # predictable randomness
        for kw in ("block.timestamp", "blockhash", "block.difficulty", "block.number", "now "):
            if kw in low and re.search(r"(random|winner|lottery|seed|roll|draw|reward)", low):
                findings.append(f"[{where}] randomness derived from {kw.strip()} - miners/"
                                "validators can influence it; use a VRF/commit-reveal.")
                break

        # reentrancy: external value call before a state write in the same function body
        self._reentrancy(src, where, findings)

        # unprotected critical functions (state-changing, external/public, no auth modifier)
        self._unprotected(src, where, findings)

    def _reentrancy(self, src: str, where: str, findings: list[str]) -> None:
        for fm in _FUNC.finditer(src):
            body_start = src.find("{", fm.end())
            if body_start == -1:
                continue
            depth, i = 1, body_start + 1
            while i < len(src) and depth:
                if src[i] == "{":
                    depth += 1
                elif src[i] == "}":
                    depth -= 1
                i += 1
            body = src[body_start:i]
            cm = _EXT_CALL.search(body)
            if not cm:
                continue
            after = body[cm.end():]
            # a state write (mapping/balance assignment) AFTER the external call = classic
            # checks-effects-interactions violation (funds sent before balance zeroed).
            if _STATE_WRITE.search(after) or re.search(r"\b\w+\s*\[[^\]]+\]\s*[-+]?=", after):
                findings.append(
                    f"[{where}:{_line_no(src, body_start + cm.start())}] REENTRANCY in "
                    f"{fm.group(1)}(): external value call happens BEFORE state is updated "
                    "(checks-effects-interactions violated). Update balances FIRST, or use a "
                    "nonReentrant guard.")

    def _unprotected(self, src: str, where: str, findings: list[str]) -> None:
        for fm in _FUNC.finditer(src):
            name = fm.group(1)
            sig = (fm.group(3) or "").lower()
            if "view" in sig or "pure" in sig or "internal" in sig or "private" in sig:
                continue
            critical = re.search(r"(owner|admin|withdraw|mint|setowner|transferownership|"
                                 r"upgrade|initialize|pause|setprice|setfee|rescue)", name.lower())
            if not critical:
                continue
            if any(a in sig for a in _MODIFIERS_AUTH):
                continue
            # look a bit into the body for an inline require(msg.sender...) auth check
            body_start = src.find("{", fm.end())
            head = src[body_start:body_start + 200].lower() if body_start != -1 else ""
            if "msg.sender" in head and ("require" in head or "owner" in head):
                continue
            findings.append(f"[{where}:{_line_no(src, fm.start())}] critical function "
                            f"{name}() is external/public with NO visible access-control "
                            "modifier or msg.sender check - confirm it is not callable by "
                            "anyone.")

    def execute_sync(self, path: Optional[str], source: Optional[str]) -> ToolResult:
        findings: list[str] = []
        scanned = 0
        if source:
            self._scan_source(source, "source", findings)
            scanned = 1
        elif path:
            targets = []
            if os.path.isdir(path):
                for root, _d, files in os.walk(path):
                    for fn in files:
                        if fn.endswith(".sol"):
                            targets.append(os.path.join(root, fn))
            elif os.path.isfile(path):
                targets = [path]
            for fp in targets[:60]:
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        code = fh.read(500_000)
                except Exception:
                    continue
                scanned += 1
                self._scan_source(code, os.path.basename(fp), findings)
        else:
            return ToolResult.fail("contract_scan: give `path` (a .sol file/dir) or `source`.")

        if scanned == 0:
            return ToolResult.fail("contract_scan: no Solidity (.sol) source found to scan.")
        findings = list(dict.fromkeys(findings))
        lines = [f"contract_scan - {path or 'inline source'}  ({scanned} file(s))"]
        if not findings:
            lines.append("\nNo high-impact static findings (reentrancy, tx.origin, unchecked "
                         "call, delegatecall, unprotected selfdestruct/setters). Still run "
                         "slither/mythril for deep/symbolic coverage and review economic logic "
                         "(oracle/flash-loan) by hand.")
        else:
            # order: put reentrancy/selfdestruct/delegatecall (fund-draining) first
            def rank(f: str) -> int:
                for i, kw in enumerate(("REENTRANCY", "delegatecall", "selfdestruct",
                                        "tx.origin", "critical function", ".call return",
                                        "randomness", "pragma", "pre-0.8")):
                    if kw in f:
                        return i
                return 99
            findings.sort(key=rank)
            lines.append("\nFINDINGS (highest-impact first):")
            lines += [f"  - {f}" for f in findings[:40]]
            lines.append("\nNext: confirm each on-chain/with a PoC in a forked-mainnet test "
                         "(foundry), then run slither & mythril for symbolic coverage.")
        return ToolResult.ok("\n".join(lines), metadata={"findings": len(findings),
                                                         "files": scanned})

    async def execute(self, path: Optional[str] = None, source: Optional[str] = None,
                      **kwargs: Any) -> ToolResult:
        path = (path or "").strip() or None
        if path and not os.path.exists(path):
            return ToolResult.fail(f"contract_scan: path not found: {path!r}")
        return self.execute_sync(path, source)
