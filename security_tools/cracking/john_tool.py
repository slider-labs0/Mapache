"""
john_tool.py - Mapache John the Ripper integration

Wraps John the Ripper for autonomous password cracking.
The agent can crack hashes found during recon without manual intervention.

Supports:
    - Auto hash format detection
    - Wordlist attacks (rockyou, custom)
    - Rule-based attacks
    - Incremental (brute force) mode
    - Progress monitoring
    - Cracked password retrieval

Prerequisites:
    Windows: https://www.openwall.com/john/ (download John for Windows)
    Linux:   sudo apt install john
    Mac:     brew install john

Common hash formats:
    md5, sha1, sha256, sha512, bcrypt, ntlm, lm,
    md5crypt, sha512crypt, descrypt, phpass
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from core.logger import get_logger

logger = get_logger(__name__)

# Common wordlist locations
WORDLIST_CANDIDATES = [
    r"C:\Tools\wordlists\rockyou.txt",
    r"C:\Program Files\John\run\password.lst",
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/john/password.lst",
    "/opt/john/run/password.lst",
]

JOHN_CANDIDATES = [
    "john",
    r"C:\Program Files\John\run\john.exe",
    r"C:\Tools\john\run\john.exe",
    "/usr/bin/john",
    "/usr/sbin/john",
    "/opt/john/run/john",
]


def _find_john() -> Optional[str]:
    found = shutil.which("john")
    if found:
        return found
    for path in JOHN_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def _find_wordlist() -> Optional[str]:
    for path in WORDLIST_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


class JohnCrackTool(BaseTool):
    name = "john_crack"
    description = (
        "Crack password hashes using John the Ripper. "
        "Paste the hash directly or provide a file path. "
        "Auto-detects hash format. Supports MD5, SHA1, SHA256, NTLM, bcrypt, and more. "
        "Use after finding hashes in /etc/passwd, /etc/shadow, database dumps, or captured traffic."
    )
    parameters = {
        "type": "object",
        "properties": {
            "hash_input": {
                "type": "string",
                "description": "Hash to crack, multiple hashes (one per line), or path to a hash file",
            },
            "wordlist": {
                "type": "string",
                "description": "Path to wordlist file. Leave empty to use rockyou.txt or John's default list.",
                "default": "",
            },
            "format": {
                "type": "string",
                "description": "Hash format (e.g. 'md5', 'sha1', 'ntlm', 'bcrypt'). Leave empty for auto-detect.",
                "default": "",
            },
            "rules": {
                "type": "string",
                "description": "Rule set to use (e.g. 'best64', 'jumbo', 'KoreLogic'). Leave empty for default.",
                "default": "",
            },
            "mode": {
                "type": "string",
                "enum": ["wordlist", "incremental", "single", "mask"],
                "description": "Cracking mode. wordlist=dictionary attack, incremental=brute force",
                "default": "wordlist",
            },
            "timeout": {
                "type": "integer",
                "description": "Max seconds to run (default: 60)",
                "default": 60,
            },
        },
        "required": ["hash_input"],
    }
    permissions = {Permission.SHELL, Permission.FILESYSTEM}
    timeout = 300
    tags = ["security", "cracking", "passwords"]

    async def execute(
        self,
        hash_input: str,
        wordlist: str = "",
        format: str = "",
        rules: str = "",
        mode: str = "wordlist",
        timeout: int = 60,
        **kwargs: Any,
    ) -> ToolResult:
        john_path = _find_john()
        if not john_path:
            return ToolResult.fail(
                "John the Ripper not found.\n"
                "Windows: Download from https://www.openwall.com/john/\n"
                "Linux:   sudo apt install john\n"
                "Mac:     brew install john"
            )

        # Write hashes to temp file if not a file path
        hash_file = hash_input.strip()
        temp_file = None

        if not os.path.isfile(hash_file):
            # Treat as raw hash input
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8"
            )
            tmp.write(hash_input.strip() + "\n")
            tmp.close()
            hash_file = tmp.name
            temp_file = tmp.name

        try:
            # Build john command
            cmd = [john_path]

            # Format
            if format:
                cmd.append(f"--format={format}")

            # Mode and wordlist
            if mode == "wordlist":
                wl = wordlist or _find_wordlist()
                if wl and os.path.isfile(wl):
                    cmd.append(f"--wordlist={wl}")
                    if rules:
                        cmd.append(f"--rules={rules}")
                else:
                    cmd.append("--wordlist")  # use john's built-in list
            elif mode == "incremental":
                cmd.append("--incremental")
            elif mode == "single":
                cmd.append("--single")
            elif mode == "mask":
                cmd.append("--mask=?a?a?a?a?a?a?a?a")  # 8-char all-chars

            cmd.append(hash_file)

            logger.info("John command: %s", " ".join(cmd))

            # Run john
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(timeout),
                )
                output = stdout.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                proc.kill()
                output = "John ran until timeout"

            # Retrieve cracked passwords
            show_cmd = [john_path, "--show", hash_file]
            if format:
                show_cmd.append(f"--format={format}")

            show_proc = await asyncio.create_subprocess_exec(
                *show_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            show_stdout, _ = await show_proc.communicate()
            cracked_output = show_stdout.decode("utf-8", errors="replace")

            # Parse results
            lines = [f"John the Ripper - {mode} attack\n"]

            cracked_lines = [
                l for l in cracked_output.splitlines()
                if ":" in l and not l.startswith("0 ")
            ]

            if cracked_lines:
                lines.append(f"Cracked passwords ({len(cracked_lines)}):")
                for line in cracked_lines:
                    lines.append(f"  {line}")
            else:
                lines.append("No passwords cracked.")
                if "No password hashes loaded" in output:
                    lines.append("\nNote: No valid hashes found in input.")
                    lines.append("Try specifying --format= explicitly.")

            # Include relevant john output
            relevant = [
                l for l in output.splitlines()
                if any(kw in l for kw in ["password", "hash", "crack", "loaded", "guesses", "Warning"])
            ]
            if relevant:
                lines.append("\nJohn output:")
                lines.extend(f"  {l}" for l in relevant[:10])

            return ToolResult.ok(
                "\n".join(lines),
                metadata={"cracked_count": len(cracked_lines)},
            )

        finally:
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)


class JohnFormatTool(BaseTool):
    name = "john_identify"
    description = (
        "Identify the format of a password hash. "
        "Use before cracking to determine which format flag to pass. "
        "Also shows which John the Ripper formats can handle it."
    )
    parameters = {
        "type": "object",
        "properties": {
            "hash_value": {
                "type": "string",
                "description": "The hash string to identify",
            },
        },
        "required": ["hash_value"],
    }
    permissions = set()
    tags = ["security", "cracking", "passwords"]

    async def execute(self, hash_value: str, **kwargs: Any) -> ToolResult:
        import re
        h = hash_value.strip()
        length = len(h)
        is_hex = bool(re.match(r'^[0-9a-fA-F]+$', h))

        candidates = []

        # Length-based identification
        if length == 32 and is_hex:
            candidates.append(("MD5", "md5", "Most common - MySQL, web apps"))
            candidates.append(("NTLM", "nt", "Windows password hash"))
            candidates.append(("MD4", "raw-md4", "Older Windows"))
        elif length == 40 and is_hex:
            candidates.append(("SHA1", "raw-sha1", "Common in older web apps"))
        elif length == 56 and is_hex:
            candidates.append(("SHA224", "raw-sha224", "Less common"))
        elif length == 64 and is_hex:
            candidates.append(("SHA256", "raw-sha256", "Modern web apps, Bitcoin"))
        elif length == 96 and is_hex:
            candidates.append(("SHA384", "raw-sha384", "Less common"))
        elif length == 128 and is_hex:
            candidates.append(("SHA512", "raw-sha512", "Linux /etc/shadow"))
        elif h.startswith("$1$"):
            candidates.append(("MD5crypt", "md5crypt", "Linux /etc/shadow (MD5)"))
        elif h.startswith("$2b$") or h.startswith("$2a$"):
            candidates.append(("bcrypt", "bcrypt", "Modern web apps - very slow to crack"))
        elif h.startswith("$5$"):
            candidates.append(("SHA256crypt", "sha256crypt", "Linux /etc/shadow"))
        elif h.startswith("$6$"):
            candidates.append(("SHA512crypt", "sha512crypt", "Modern Linux /etc/shadow"))
        elif h.startswith("$P$") or h.startswith("$H$"):
            candidates.append(("phpass", "phpass", "WordPress, phpBB passwords"))
        elif length == 13 and not is_hex:
            candidates.append(("DES crypt", "descrypt", "Old Unix passwords"))
        elif ":" in h and len(h.split(":")[0]) == 32:
            candidates.append(("MD5 with username", "md5", "username:hash format"))

        if not candidates:
            candidates.append(("Unknown", "?", "Could not identify format"))

        lines = [f"Hash: {h[:40]}{'...' if len(h) > 40 else ''}", f"Length: {length}\n"]
        lines.append("Possible formats:")
        for name, fmt, note in candidates:
            lines.append(f"  {name:20s} --format={fmt:20s} ({note})")

        if candidates and candidates[0][1] != "?":
            lines.append(f"\nSuggested john command:")
            lines.append(f"  Use john_crack with format='{candidates[0][1]}'")

        return ToolResult.ok("\n".join(lines))
