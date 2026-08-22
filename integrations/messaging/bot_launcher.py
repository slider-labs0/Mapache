"""
bot_launcher.py - Mapache bot launcher

Starts Mapache with messaging integrations enabled.

Usage:
    python -m integrations.messaging.bot_launcher --telegram
    python -m integrations.messaging.bot_launcher --discord
    python -m integrations.messaging.bot_launcher --telegram --discord
    python -m integrations.messaging.bot_launcher --telegram --model qwen2.5:14b

.env file (place in Mapache_OFF folder):
    TELEGRAM_BOT_TOKEN=your_token
    TELEGRAM_ALLOWED_USERS=your_telegram_id
    DISCORD_BOT_TOKEN=your_token
    DISCORD_ALLOWED_USERS=your_discord_id
    MAPACHE_MODEL=qwen2.5:14b
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.agent_controller import AgentController, AgentMode
from core.logger import get_logger, setup_logging
from integrations.messaging.gateway import MessageGateway
from memory.memory_manager import MemoryManager
from models.providers.ollama_provider import OllamaProvider
from plugins.sdk.base_tool import Permission

# Core tools
from security_tools.shell_tool import ShellTool
from security_tools.recon.nmap_tool import NmapTool

# Filesystem tools
from tools.filesystem_tool import (
    FileReadTool, FileWriteTool, FileEditTool,
    FileListTool, FileSearchTool,
)

# Browser tools
from browser.scraping_tools import WebFetchTool, WebSearchTool, TorFetchTool, TorControlTool

# Phase 6 - Advanced security tools
from security_tools.exploitation.metasploit_tool import (
    MetasploitSearchTool, MetasploitRunTool, MetasploitSessionsTool,
)
from security_tools.exploitation.burpsuite_tool import BurpScanTool, BurpProxyTool
from security_tools.cracking.john_tool import JohnCrackTool, JohnFormatTool
from security_tools.kali.kali_tools_interface import (
    KaliToolListTool, KaliRunTool, SearchsploitTool,
)

from tools.tool_dispatcher import ToolDispatcher
from tools.tool_registry import ToolRegistry

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are Mapache. You MUST use tools to answer requests. Never answer from memory or training data.

CRITICAL - READ THIS FIRST:
- You have tools available. USE THEM.
- When asked to scan: call nmap_scan immediately. No exceptions.
- When asked to read a file: call file_read immediately.
- When asked to search: call web_search immediately.
- NEVER say you don't have a tool. Check the tool list first.
- NEVER describe what you would do. Just do it by calling the tool.
- NEVER use memory as a substitute for running a tool the user explicitly requested.
- If the user says scan, SCAN. If they say fetch, FETCH. If they say crack, CRACK.

Keep responses concise - you are communicating over chat.
Use bullet points for lists. Split complex results into key findings only.
After completing recon, save findings with memory_target_store."""


def _load_dotenv() -> None:
    for candidate in [Path(".env"), Path(__file__).parent.parent.parent / ".env"]:
        if candidate.exists():
            for line in candidate.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip())
            break


async def main() -> None:
    _load_dotenv()

    parser = argparse.ArgumentParser(description="Mapache bot launcher")
    parser.add_argument("--telegram", action="store_true", help="Enable Telegram bot")
    parser.add_argument("--discord", action="store_true", help="Enable Discord bot")
    parser.add_argument("--model", "-m",
                        default=os.environ.get("MAPACHE_MODEL", "qwen2.5:14b"))
    parser.add_argument("--ollama-url",
                        default=os.environ.get("OLLAMA_URL", "http://localhost:11434"))
    parser.add_argument("--allow-all", action="store_true",
                        help="Allow all users (no whitelist)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    setup_logging(level="DEBUG" if args.debug else "INFO")

    if not args.telegram and not args.discord:
        print("Specify at least one platform: --telegram or --discord")
        print("Example: python -m integrations.messaging.bot_launcher --telegram")
        sys.exit(1)

    # Check Ollama
    model = OllamaProvider(model=args.model, base_url=args.ollama_url)
    if not await model.is_available():
        print(f"Cannot reach Ollama at {args.ollama_url}. Run: ollama serve")
        sys.exit(1)

    print(f"  Ollama connected - model: {args.model}")

    # Build tool registry
    registry = ToolRegistry(granted_permissions={
        Permission.SHELL,
        Permission.FILESYSTEM,
        Permission.NETWORK,
        Permission.SYSTEM_INFO,
        Permission.TOR,
        Permission.DANGEROUS,
    })

    # Core
    registry.register(ShellTool())

    # Filesystem
    registry.register(FileReadTool())
    registry.register(FileWriteTool())
    registry.register(FileEditTool())
    registry.register(FileListTool())
    registry.register(FileSearchTool())

    # Recon
    registry.register(NmapTool())

    # Browser
    registry.register(WebFetchTool())
    registry.register(WebSearchTool())
    registry.register(TorFetchTool())
    registry.register(TorControlTool())

    # Phase 6 - Advanced security
    registry.register(MetasploitSearchTool())
    registry.register(MetasploitRunTool())
    registry.register(MetasploitSessionsTool())
    registry.register(BurpScanTool())
    registry.register(BurpProxyTool())
    registry.register(JohnCrackTool())
    registry.register(JohnFormatTool())
    registry.register(KaliToolListTool())
    registry.register(KaliRunTool())
    registry.register(SearchsploitTool())

    # Memory
    memory = MemoryManager()
    memory.new_session()
    for tool in memory.get_tools():
        registry.register(tool)

    # Moltbook (optional)
    try:
        from integrations.social.moltbook_tool import (
            MoltbookRegisterTool, MoltbookStatusTool, MoltbookPostTool,
            MoltbookFeedTool, MoltbookCommentTool, MoltbookSearchTool,
        )
        registry.register(MoltbookRegisterTool())
        registry.register(MoltbookStatusTool())
        registry.register(MoltbookPostTool())
        registry.register(MoltbookFeedTool())
        registry.register(MoltbookCommentTool())
        registry.register(MoltbookSearchTool())
    except ImportError:
        pass

    dispatcher = ToolDispatcher(registry)

    # Build agent
    controller = AgentController(
        model_provider=model,
        mode=AgentMode.AGENT,
        use_function_calling=model.supports_tools,
        system_prompt=SYSTEM_PROMPT,
    )
    controller.tool_dispatcher = dispatcher
    controller.executor.set_tool_dispatcher(dispatcher)

    for schema in registry.get_context_schemas():
        controller.register_tool(schema)

    await controller.start(inject_project_context=False)

    # Build gateway
    allow_all = args.allow_all or os.environ.get("MAPACHE_ALLOW_ALL") == "1"
    gateway = MessageGateway(
        agent_controller=controller,
        allow_all=allow_all,
    )

    # Start bots
    bot_instances = []

    if args.telegram:
        try:
            from integrations.messaging.telegram_bot import TelegramBot
            telegram = TelegramBot(allow_all=allow_all)
            await telegram.start(gateway)
            bot_instances.append(telegram)
            print("  Telegram bot is live. Message it to start.")
        except (ImportError, ValueError) as exc:
            print(f"  Telegram failed: {exc}")

    if args.discord:
        try:
            from integrations.messaging.discord_bot import DiscordBot
            discord_bot = DiscordBot(allow_all=allow_all)
            asyncio.create_task(discord_bot.start(gateway))
            bot_instances.append(discord_bot)
            print("  Discord bot starting...")
        except (ImportError, ValueError) as exc:
            print(f"  Discord failed: {exc}")

    if not bot_instances:
        print("No bots started. Check tokens and dependencies.")
        sys.exit(1)

    tool_count = len(registry.list_names())
    print(f"\n  Model  : {args.model}")
    print(f"  Tools  : {tool_count}")
    print(f"  Auth   : {'all users' if allow_all else 'whitelist only'}")
    print(f"\n  Press Ctrl+C to stop.\n")

    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nShutting down...")
        await memory.end_session()


if __name__ == "__main__":
    asyncio.run(main())
