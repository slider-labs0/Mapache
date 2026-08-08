"""
project_context.py - Mapache project context builder

Scans the working directory on startup, builds a mental model of the codebase,
and injects it into the system prompt automatically.

Detects:
- Language / framework
- Project structure
- Key files (README, config, entry points)
- MAPACHE.md custom instructions

This is what makes Mapache feel like Claude Code - it understands
your project before you say a word.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


# Files to read fully for context
KEY_FILES = [
    "MAPACHE.md",       # custom instructions (highest priority)
    "README.md",
    "README.rst",
    ".mapache",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "requirements.txt",
    "Makefile",
]

# Language detection by file extension
LANG_SIGNATURES: dict[str, list[str]] = {
    "Python":     [".py"],
    "JavaScript": [".js", ".mjs", ".cjs"],
    "TypeScript": [".ts", ".tsx"],
    "Rust":       [".rs"],
    "Go":         [".go"],
    "Java":       [".java"],
    "C/C++":      [".c", ".cpp", ".h", ".hpp"],
    "C#":         [".cs"],
    "Ruby":       [".rb"],
    "PHP":        [".php"],
    "Swift":      [".swift"],
    "Kotlin":     [".kt"],
    "Shell":      [".sh", ".bash", ".zsh"],
    "HTML/CSS":   [".html", ".css", ".scss"],
    "SQL":        [".sql"],
    "Markdown":   [".md"],
}

# Framework detection by file existence
FRAMEWORK_SIGNATURES: dict[str, str] = {
    "next.config.js": "Next.js",
    "next.config.ts": "Next.js",
    "vite.config.js": "Vite",
    "vite.config.ts": "Vite",
    "angular.json": "Angular",
    "vue.config.js": "Vue",
    "svelte.config.js": "SvelteKit",
    "astro.config.mjs": "Astro",
    "manage.py": "Django",
    "wsgi.py": "Django/Flask",
    "fastapi": "FastAPI",
    "Cargo.toml": "Rust/Cargo",
    "go.mod": "Go modules",
    "pom.xml": "Maven/Java",
    "build.gradle": "Gradle/Java",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
    "Dockerfile": "Docker",
    ".github": "GitHub Actions",
    "terraform.tf": "Terraform",
}

IGNORE_DIRS = {
    "__pycache__", ".git", "node_modules", ".venv", "venv",
    "env", "dist", "build", ".next", ".cache", "target",
    "*.egg-info", ".idea", ".vscode",
}


def build_project_context(
    working_dir: str = ".",
    max_key_file_size: int = 1000,
) -> Optional[str]:
    """
    Scan the working directory and return a context string
    to inject into the system prompt.

    Returns None if the directory looks empty or irrelevant.
    """
    root = Path(working_dir).resolve()

    if not root.exists() or not root.is_dir():
        return None

    sections = []

    # ---- Custom instructions (MAPACHE.md) ----
    mapache_md = root / "MAPACHE.md"
    if mapache_md.exists():
        try:
            content = mapache_md.read_text(encoding="utf-8", errors="replace")[:max_key_file_size]
            sections.append(f"CUSTOM INSTRUCTIONS (MAPACHE.md):\n{content}")
        except Exception:
            pass

    # ---- Project root info ----
    sections.append(f"WORKING DIRECTORY: {root}")

    # ---- Detect languages ----
    lang_counts: dict[str, int] = {}
    total_files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORE_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            total_files += 1
            for lang, exts in LANG_SIGNATURES.items():
                if ext in exts:
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1

    if total_files == 0:
        return None

    # Top languages
    top_langs = sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)[:4]
    if top_langs:
        lang_str = ", ".join(f"{lang} ({count} files)" for lang, count in top_langs)
        sections.append(f"LANGUAGES: {lang_str}")

    # ---- Detect frameworks ----
    frameworks = []
    for sig, name in FRAMEWORK_SIGNATURES.items():
        if (root / sig).exists():
            frameworks.append(name)
    if frameworks:
        sections.append(f"FRAMEWORKS/TOOLS: {', '.join(frameworks)}")

    # ---- Project structure (top level) ----
    top_level = []
    try:
        entries = sorted(root.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
        for entry in entries:
            if entry.name.startswith(".") or entry.name in IGNORE_DIRS:
                continue
            if entry.is_dir():
                # Count files inside
                try:
                    child_count = sum(1 for _ in entry.iterdir())
                    top_level.append(f"{entry.name}/ ({child_count} items)")
                except Exception:
                    top_level.append(f"{entry.name}/")
            else:
                top_level.append(entry.name)
    except Exception:
        pass

    if top_level:
        structure = "  " + "\n  ".join(top_level[:30])
        sections.append(f"PROJECT STRUCTURE:\n{structure}")

    # ---- Read key files ----
    for filename in KEY_FILES:
        if filename == "MAPACHE.md":
            continue  # Already handled above
        filepath = root / filename
        if filepath.exists() and filepath.is_file():
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
                if content.strip():
                    truncated = content[:max_key_file_size]
                    if len(content) > max_key_file_size:
                        truncated += f"\n[... truncated at {max_key_file_size} chars]"
                    sections.append(f"{filename}:\n{truncated}")
            except Exception:
                pass

    if len(sections) <= 2:  # Only working dir + maybe languages
        return None

    header = "=== PROJECT CONTEXT (auto-detected) ===\n"
    footer = "\n=== END PROJECT CONTEXT ===\n"
    return header + "\n\n".join(sections) + footer


def get_mapache_instructions(working_dir: str = ".") -> Optional[str]:
    """
    Read MAPACHE.md from the working directory.
    Returns None if not found.
    """
    p = Path(working_dir).resolve() / "MAPACHE.md"
    if not p.exists():
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return None
