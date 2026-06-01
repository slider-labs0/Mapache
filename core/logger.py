"""
logger.py — Mapache logging setup

Structured, colored console output + rotating file logs.
All modules use: from core.logger import get_logger; logger = get_logger(__name__)

Log levels:
    DEBUG   — internal state, model payloads, event traces
    INFO    — normal operation milestones
    WARNING — recoverable issues (retry, fallback, trim)
    ERROR   — failures that affect output
    CRITICAL — fatal, requires restart
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------ #
# ANSI color codes (stripped automatically when not a TTY)
# ------------------------------------------------------------------ #

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[31m"
YELLOW  = "\033[33m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"
MAGENTA = "\033[35m"
GREEN   = "\033[32m"

LEVEL_COLORS = {
    "DEBUG":    DIM + WHITE,
    "INFO":     CYAN,
    "WARNING":  YELLOW,
    "ERROR":    RED,
    "CRITICAL": BOLD + RED,
}

LEVEL_SYMBOLS = {
    "DEBUG":    "·",
    "INFO":     "→",
    "WARNING":  "⚠",
    "ERROR":    "✗",
    "CRITICAL": "☠",
}


class MapacheFormatter(logging.Formatter):
    """
    Colored, compact formatter for console output.

    Format:
        [HH:MM:SS] → module_name  message
        [HH:MM:SS] ✗ module_name  ERROR: message
    """

    def __init__(self, use_color: bool = True) -> None:
        super().__init__()
        self.use_color = use_color and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        symbol = LEVEL_SYMBOLS.get(level, "·")
        color  = LEVEL_COLORS.get(level, "") if self.use_color else ""
        reset  = RESET if self.use_color else ""
        dim    = DIM if self.use_color else ""
        bold   = BOLD if self.use_color else ""

        # Shorten module name: core.agent_controller → agent_controller
        module = record.name.split(".")[-1] if "." in record.name else record.name
        module = module[:20].ljust(20)

        time_str = self.formatTime(record, "%H:%M:%S")

        msg = record.getMessage()

        # Attach exception info if present
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)

        return (
            f"{dim}[{time_str}]{reset} "
            f"{color}{symbol}{reset} "
            f"{dim}{module}{reset}  "
            f"{color if level in ('ERROR', 'CRITICAL', 'WARNING') else ''}{msg}{reset}"
        )


class FileFormatter(logging.Formatter):
    """Plain formatter for log files — no ANSI codes."""

    FORMAT = "%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s"
    DATEFMT = "%Y-%m-%d %H:%M:%S"

    def __init__(self) -> None:
        super().__init__(fmt=self.FORMAT, datefmt=self.DATEFMT)


# ------------------------------------------------------------------ #
# Setup
# ------------------------------------------------------------------ #

_initialized = False


def setup_logging(
    level: str = "INFO",
    log_dir: Optional[str] = None,
    log_file: Optional[str] = "mapache.log",
    max_bytes: int = 5 * 1024 * 1024,  # 5 MB
    backup_count: int = 3,
) -> None:
    """
    Configure root logger for Mapache. Call once at startup.

    Args:
        level:        Console log level (DEBUG/INFO/WARNING/ERROR)
        log_dir:      Directory for log files. None = no file logging.
        log_file:     Log filename (within log_dir).
        max_bytes:    Max size per log file before rotation.
        backup_count: Number of rotated files to keep.
    """
    global _initialized
    if _initialized:
        return

    root = logging.getLogger("mapache")
    root.setLevel(logging.DEBUG)  # root captures all; handlers filter

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(getattr(logging, level.upper(), logging.INFO))
    console.setFormatter(MapacheFormatter(use_color=True))
    root.addHandler(console)

    # File handler (optional)
    if log_dir and log_file:
        log_path = Path(log_dir) / log_file
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(FileFormatter())
        root.addHandler(file_handler)
        root.info("File logging enabled: %s", log_path)

    # Silence noisy third-party loggers
    for noisy in ("httpx", "httpcore", "asyncio", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a module.

    Usage:
        from core.logger import get_logger
        logger = get_logger(__name__)
    """
    # Namespace everything under mapache.*
    if not name.startswith("mapache"):
        name = f"mapache.{name}"
    return logging.getLogger(name)


# ------------------------------------------------------------------ #
# Event bus integration helper
# ------------------------------------------------------------------ #

def make_event_logger(bus_logger: logging.Logger):
    """
    Returns an async event handler that logs all bus events at DEBUG level.
    Register with: bus.subscribe("*", make_event_logger(logger))
    """
    async def _log_event(event) -> None:
        bus_logger.debug(
            "BUS  %-30s  src=%-20s  session=%s",
            event.topic,
            event.source or "-",
            (event.session_id or "-")[:8],
        )
    return _log_event


# ------------------------------------------------------------------ #
# Module-level convenience
# ------------------------------------------------------------------ #

# Auto-setup with defaults if imported without explicit setup_logging() call
def _auto_setup() -> None:
    if not _initialized:
        setup_logging(
            level=os.environ.get("MAPACHE_LOG_LEVEL", "INFO"),
            log_dir=os.environ.get("MAPACHE_LOG_DIR"),
        )

_auto_setup()
