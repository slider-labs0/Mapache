"""
filesystem_tool.py — Mapache filesystem tools

Gives the agent structured file system access:
    file_read    — read file contents
    file_write   — create or overwrite a file
    file_edit    — find-and-replace within a file (safe, targeted edits)
    file_list    — list directory contents with metadata
    file_search  — search for text across files (grep-like)

These replace fragile shell workarounds with structured, validated operations.
The agent can now read, understand, and edit codebases directly.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

MAX_FILE_SIZE = 100_000   # 100KB — truncate larger files
MAX_SEARCH_RESULTS = 50
MAX_LIST_DEPTH = 3


def _safe_path(path_str: str) -> Path:
    """Resolve path, expanding ~ and env vars."""
    return Path(os.path.expandvars(os.path.expanduser(path_str))).resolve()


def _truncate(text: str, max_len: int = MAX_FILE_SIZE) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n\n[... truncated — file is {len(text)} chars, showing first {max_len}]"


# ------------------------------------------------------------------ #
# file_read
# ------------------------------------------------------------------ #

class FileReadTool(BaseTool):
    name = "file_read"
    description = (
        "Read the contents of a file. Returns the full text content. "
        "Use for reading source code, config files, logs, text files, etc. "
        "Supports any text file. Large files are truncated at 100KB."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the file to read (absolute or relative)",
            },
            "start_line": {
                "type": "integer",
                "description": "Start reading from this line number (1-indexed, optional)",
                "default": 0,
            },
            "end_line": {
                "type": "integer",
                "description": "Stop reading at this line number (inclusive, optional)",
                "default": 0,
            },
        },
        "required": ["path"],
    }
    permissions = {Permission.FILESYSTEM}
    tags = ["filesystem", "code", "read"]

    async def execute(
        self,
        path: str,
        start_line: int = 0,
        end_line: int = 0,
        **kwargs: Any,
    ) -> ToolResult:
        try:
            p = _safe_path(path)
        except Exception as exc:
            return ToolResult.fail(f"Invalid path: {exc}")

        if not p.exists():
            return ToolResult.fail(f"File not found: {path}")

        if p.is_dir():
            return ToolResult.fail(f"'{path}' is a directory. Use file_list to browse directories.")

        if not p.is_file():
            return ToolResult.fail(f"Not a regular file: {path}")

        # Size check
        size = p.stat().st_size
        if size > 10 * 1024 * 1024:  # 10MB hard limit
            return ToolResult.fail(
                f"File too large ({size // 1024}KB). Max supported size is 10MB."
            )

        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except PermissionError:
            return ToolResult.fail(f"Permission denied reading: {path}")
        except Exception as exc:
            return ToolResult.fail(f"Error reading file: {exc}")

        # Line range selection
        if start_line > 0 or end_line > 0:
            lines = text.splitlines(keepends=True)
            s = max(0, start_line - 1)
            e = end_line if end_line > 0 else len(lines)
            selected = lines[s:e]
            text = "".join(selected)
            header = f"[{p.name} lines {start_line}–{min(end_line, len(lines))} of {len(lines)}]\n"
        else:
            total_lines = text.count("\n") + 1
            header = f"[{p.name} — {total_lines} lines, {size} bytes]\n"

        content = header + _truncate(text)

        return ToolResult.ok(
            content,
            metadata={"path": str(p), "size": size},
        )


# ------------------------------------------------------------------ #
# file_write
# ------------------------------------------------------------------ #

class FileWriteTool(BaseTool):
    name = "file_write"
    description = (
        "Write content to a file. Creates the file if it doesn't exist, "
        "overwrites it if it does. Creates parent directories automatically. "
        "Use for creating new files, saving code, writing configs, etc."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to write to (absolute or relative)",
            },
            "content": {
                "type": "string",
                "description": "Content to write to the file",
            },
            "append": {
                "type": "boolean",
                "description": "If true, append to existing file instead of overwriting",
                "default": False,
            },
        },
        "required": ["path", "content"],
    }
    permissions = {Permission.FILESYSTEM}
    tags = ["filesystem", "code", "write"]

    async def execute(
        self,
        path: str,
        content: str,
        append: bool = False,
        **kwargs: Any,
    ) -> ToolResult:
        try:
            p = _safe_path(path)
        except Exception as exc:
            return ToolResult.fail(f"Invalid path: {exc}")

        if p.is_dir():
            return ToolResult.fail(f"'{path}' is a directory, cannot write to it.")

        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if append else "w"
            p.write_text(content, encoding="utf-8") if not append else \
                p.open("a", encoding="utf-8").write(content)
        except PermissionError:
            return ToolResult.fail(f"Permission denied writing to: {path}")
        except Exception as exc:
            return ToolResult.fail(f"Error writing file: {exc}")

        lines = content.count("\n") + 1
        action = "Appended to" if append else "Written"
        return ToolResult.ok(
            f"{action}: {p}\n"
            f"  {lines} lines, {len(content.encode())} bytes",
            metadata={"path": str(p), "lines": lines},
        )


# ------------------------------------------------------------------ #
# file_edit
# ------------------------------------------------------------------ #

class FileEditTool(BaseTool):
    name = "file_edit"
    description = (
        "Make a targeted edit to a file by replacing a specific string with new content. "
        "The old_str must match exactly once in the file. "
        "Use for editing source code, fixing bugs, updating config values. "
        "Safer than rewriting the whole file."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the file to edit",
            },
            "old_str": {
                "type": "string",
                "description": "The exact string to find and replace (must be unique in the file)",
            },
            "new_str": {
                "type": "string",
                "description": "The replacement string",
            },
        },
        "required": ["path", "old_str", "new_str"],
    }
    permissions = {Permission.FILESYSTEM}
    tags = ["filesystem", "code", "edit"]

    async def execute(
        self,
        path: str,
        old_str: str,
        new_str: str,
        **kwargs: Any,
    ) -> ToolResult:
        try:
            p = _safe_path(path)
        except Exception as exc:
            return ToolResult.fail(f"Invalid path: {exc}")

        if not p.exists():
            return ToolResult.fail(f"File not found: {path}")

        try:
            original = p.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return ToolResult.fail(f"Error reading file: {exc}")

        count = original.count(old_str)

        if count == 0:
            # Show a hint — find closest match
            lines = original.splitlines()
            hints = []
            for i, line in enumerate(lines, 1):
                if any(word in line for word in old_str.split()[:3]):
                    hints.append(f"  line {i}: {line.strip()[:80]}")
            hint_text = "\n".join(hints[:5]) if hints else "  (no similar lines found)"
            return ToolResult.fail(
                f"String not found in {path}.\n"
                f"Similar lines:\n{hint_text}\n"
                f"Tip: Read the file first with file_read to see exact content."
            )

        if count > 1:
            return ToolResult.fail(
                f"String found {count} times in {path}. "
                f"old_str must be unique. Make it more specific by including more surrounding context."
            )

        updated = original.replace(old_str, new_str, 1)

        try:
            p.write_text(updated, encoding="utf-8")
        except PermissionError:
            return ToolResult.fail(f"Permission denied writing to: {path}")
        except Exception as exc:
            return ToolResult.fail(f"Error writing file: {exc}")

        # Show diff summary
        old_lines = old_str.count("\n") + 1
        new_lines = new_str.count("\n") + 1

        return ToolResult.ok(
            f"Edited: {p}\n"
            f"  Replaced {old_lines} line(s) with {new_lines} line(s)",
            metadata={"path": str(p)},
        )


# ------------------------------------------------------------------ #
# file_list
# ------------------------------------------------------------------ #

class FileListTool(BaseTool):
    name = "file_list"
    description = (
        "List the contents of a directory. Shows files and subdirectories with sizes and types. "
        "Use to explore project structure, find files, understand a codebase layout."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Directory to list (default: current working directory)",
                "default": ".",
            },
            "recursive": {
                "type": "boolean",
                "description": "List subdirectories recursively (default: false)",
                "default": False,
            },
            "show_hidden": {
                "type": "boolean",
                "description": "Include hidden files and folders (starting with .)",
                "default": False,
            },
            "filter_ext": {
                "type": "string",
                "description": "Only show files with this extension (e.g. '.py', '.js')",
                "default": "",
            },
        },
        "required": [],
    }
    permissions = {Permission.FILESYSTEM}
    tags = ["filesystem", "code", "explore"]

    IGNORE_DIRS = {
        "__pycache__", ".git", "node_modules", ".venv", "venv",
        "env", ".env", "dist", "build", ".next", ".cache",
        "*.egg-info",
    }

    async def execute(
        self,
        path: str = ".",
        recursive: bool = False,
        show_hidden: bool = False,
        filter_ext: str = "",
        **kwargs: Any,
    ) -> ToolResult:
        try:
            p = _safe_path(path)
        except Exception as exc:
            return ToolResult.fail(f"Invalid path: {exc}")

        if not p.exists():
            return ToolResult.fail(f"Path not found: {path}")

        if not p.is_dir():
            return ToolResult.fail(f"'{path}' is a file, not a directory. Use file_read to read it.")

        lines = [f"Directory: {p}\n"]
        total_files = 0
        total_size = 0

        try:
            entries = self._collect(p, recursive, show_hidden, filter_ext, depth=0)
        except PermissionError:
            return ToolResult.fail(f"Permission denied accessing: {path}")

        for indent, entry, is_dir, size in entries:
            if is_dir:
                lines.append(f"{indent}📁 {entry}/")
            else:
                size_str = self._fmt_size(size)
                lines.append(f"{indent}📄 {entry}  ({size_str})")
                total_files += 1
                total_size += size

        lines.append(f"\n{total_files} file(s), {self._fmt_size(total_size)} total")

        return ToolResult.ok("\n".join(lines))

    def _collect(
        self,
        directory: Path,
        recursive: bool,
        show_hidden: bool,
        filter_ext: str,
        depth: int,
    ) -> list[tuple[str, str, bool, int]]:
        if depth > MAX_LIST_DEPTH:
            return [("  " * depth, "... (max depth reached)", True, 0)]

        results = []
        indent = "  " * depth

        try:
            entries = sorted(directory.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
        except PermissionError:
            return [(indent, "(permission denied)", True, 0)]

        for entry in entries:
            name = entry.name

            if not show_hidden and name.startswith("."):
                continue

            if entry.is_dir():
                if name in self.IGNORE_DIRS:
                    continue
                results.append((indent, name, True, 0))
                if recursive:
                    results.extend(
                        self._collect(entry, recursive, show_hidden, filter_ext, depth + 1)
                    )
            elif entry.is_file():
                if filter_ext and not name.endswith(filter_ext):
                    continue
                try:
                    size = entry.stat().st_size
                except Exception:
                    size = 0
                results.append((indent, name, False, size))

        return results

    @staticmethod
    def _fmt_size(size: int) -> str:
        if size < 1024:
            return f"{size}B"
        if size < 1024 * 1024:
            return f"{size // 1024}KB"
        return f"{size // (1024 * 1024)}MB"


# ------------------------------------------------------------------ #
# file_search
# ------------------------------------------------------------------ #

class FileSearchTool(BaseTool):
    name = "file_search"
    description = (
        "Search for text across files in a directory. Like grep. "
        "Returns matching lines with file names and line numbers. "
        "Use to find function definitions, variable usage, error messages, "
        "or any text pattern across a codebase."
    )
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {
                "type": "string",
                "description": "Text or regex pattern to search for",
            },
            "path": {
                "type": "string",
                "description": "Directory or file to search in (default: current directory)",
                "default": ".",
            },
            "file_pattern": {
                "type": "string",
                "description": "Only search files matching this pattern (e.g. '*.py', '*.js')",
                "default": "",
            },
            "case_sensitive": {
                "type": "boolean",
                "description": "Case-sensitive search (default: false)",
                "default": False,
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of matches to return (default: 30)",
                "default": 30,
            },
        },
        "required": ["pattern"],
    }
    permissions = {Permission.FILESYSTEM}
    tags = ["filesystem", "code", "search"]

    SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build"}
    SKIP_EXTS = {".pyc", ".pyo", ".exe", ".dll", ".so", ".bin", ".jpg", ".png", ".gif", ".zip"}

    async def execute(
        self,
        pattern: str,
        path: str = ".",
        file_pattern: str = "",
        case_sensitive: bool = False,
        max_results: int = 30,
        **kwargs: Any,
    ) -> ToolResult:
        try:
            p = _safe_path(path)
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)
        except re.error as exc:
            return ToolResult.fail(f"Invalid regex pattern: {exc}")
        except Exception as exc:
            return ToolResult.fail(f"Invalid path: {exc}")

        if not p.exists():
            return ToolResult.fail(f"Path not found: {path}")

        matches = []
        files_searched = 0

        search_files = [p] if p.is_file() else self._iter_files(p, file_pattern)

        for filepath in search_files:
            if len(matches) >= max_results:
                break
            try:
                text = filepath.read_text(encoding="utf-8", errors="ignore")
                files_searched += 1
            except Exception:
                continue

            for line_num, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    rel = filepath.relative_to(p) if p.is_dir() else filepath
                    matches.append((str(rel), line_num, line.strip()[:120]))
                    if len(matches) >= max_results:
                        break

        if not matches:
            return ToolResult.ok(
                f"No matches for '{pattern}' in {path}\n"
                f"Searched {files_searched} file(s)"
            )

        lines = [f"Search: '{pattern}' in {path} — {len(matches)} match(es)\n"]
        current_file = None
        for filepath, line_num, line_text in matches:
            if filepath != current_file:
                lines.append(f"\n{filepath}:")
                current_file = filepath
            lines.append(f"  {line_num:4d}: {line_text}")

        if len(matches) >= max_results:
            lines.append(f"\n[Results capped at {max_results}. Use a more specific pattern to narrow down.]")

        lines.append(f"\n{files_searched} file(s) searched")

        return ToolResult.ok("\n".join(lines))

    def _iter_files(self, directory: Path, file_pattern: str):
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                if Path(fname).suffix in self.SKIP_EXTS:
                    continue
                if file_pattern:
                    import fnmatch
                    if not fnmatch.fnmatch(fname, file_pattern):
                        continue
                yield Path(root) / fname
