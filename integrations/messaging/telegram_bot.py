"""
telegram_bot.py - Mapache Telegram integration

Connects Mapache to Telegram so you can operate the agent
entirely from your phone via a Telegram bot.

Setup:
    1. Message @BotFather on Telegram
    2. /newbot → follow prompts → copy the API token
    3. Set TELEGRAM_BOT_TOKEN environment variable
    4. Get your Telegram user ID from @userinfobot
    5. Set TELEGRAM_ALLOWED_USERS=your_id (comma-separated for multiple)

Install:
    pip install python-telegram-bot

Usage:
    bot = TelegramBot(token="...", allowed_users=["123456789"])
    await bot.start(gateway)

Then message your bot on Telegram - it routes to Mapache.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from integrations.messaging.gateway import IncomingMessage, MessageGateway, OutgoingMessage
from core.logger import get_logger

logger = get_logger(__name__)

try:
    from telegram import Update, Bot
    from telegram.ext import (
        Application,
        CommandHandler,
        MessageHandler,
        ContextTypes,
        filters,
    )
    from telegram.constants import ParseMode
    HAS_TELEGRAM = True
except ImportError:
    HAS_TELEGRAM = False


class TelegramBot:
    """
    Telegram bot adapter for Mapache.

    Receives Telegram messages, converts them to IncomingMessage,
    routes through the gateway, and sends responses back.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        allowed_users: Optional[list[str]] = None,
        allow_all: bool = False,
    ) -> None:
        if not HAS_TELEGRAM:
            raise ImportError(
                "python-telegram-bot not installed.\n"
                "Install: pip install python-telegram-bot"
            )

        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        if not self.token:
            raise ValueError(
                "No Telegram bot token. Set TELEGRAM_BOT_TOKEN environment variable.\n"
                "Get one from @BotFather on Telegram."
            )

        self.allowed_users = allowed_users or self._parse_allowed_users()
        self.allow_all = allow_all
        self._gateway: Optional[MessageGateway] = None
        self._app: Optional[Any] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self, gateway: MessageGateway) -> None:
        """Connect to Telegram and start polling."""
        self._gateway = gateway

        # Register this bot's send function with the gateway
        gateway.register_sender("telegram", self._send_message)

        self._app = (
            Application.builder()
            .token(self.token)
            .build()
        )

        # Register handlers
        self._app.add_handler(CommandHandler("start", self._on_command))
        self._app.add_handler(CommandHandler("help",  self._on_command))
        self._app.add_handler(CommandHandler("reset", self._on_command))
        self._app.add_handler(CommandHandler("status",self._on_command))
        self._app.add_handler(CommandHandler("tools", self._on_command))
        self._app.add_handler(CommandHandler("memory",self._on_command))
        self._app.add_handler(CommandHandler("stop",  self._on_command))
        self._app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self._on_message)
        )

        logger.info("Telegram bot starting (polling)...")
        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)
        logger.info("Telegram bot is live. Message it to start.")

    async def stop(self) -> None:
        if self._app:
            await self._app.updater.stop()
            await self._app.stop()
            await self._app.shutdown()
            logger.info("Telegram bot stopped")

    # ------------------------------------------------------------------ #
    # Handlers
    # ------------------------------------------------------------------ #

    async def _on_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not update.message or not update.effective_user:
            return

        # Show "typing..." indicator
        await context.bot.send_chat_action(
            chat_id=update.effective_chat.id,
            action="typing",
        )

        msg = IncomingMessage(
            platform="telegram",
            user_id=str(update.effective_user.id),
            username=update.effective_user.username or update.effective_user.first_name or "unknown",
            text=update.message.text or "",
            chat_id=str(update.effective_chat.id),
            message_id=str(update.message.message_id),
        )

        if self._gateway:
            await self._gateway.handle_message(msg)

    async def _on_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not update.message or not update.effective_user:
            return

        cmd_text = update.message.text or ""

        msg = IncomingMessage(
            platform="telegram",
            user_id=str(update.effective_user.id),
            username=update.effective_user.username or update.effective_user.first_name or "unknown",
            text=cmd_text,
            chat_id=str(update.effective_chat.id),
            message_id=str(update.message.message_id),
        )

        if self._gateway:
            await self._gateway.handle_message(msg)

    # ------------------------------------------------------------------ #
    # Sending
    # ------------------------------------------------------------------ #

    async def _send_message(self, msg: OutgoingMessage) -> None:
        if not self._app:
            return

        # Map parse modes
        parse_mode = None
        if msg.parse_mode == "markdown":
            parse_mode = ParseMode.MARKDOWN_V2
        elif msg.parse_mode == "html":
            parse_mode = ParseMode.HTML

        # Escape markdown for Telegram's MarkdownV2
        text = msg.text
        if parse_mode == ParseMode.MARKDOWN_V2:
            text = self._escape_markdown(text)

        try:
            await self._app.bot.send_message(
                chat_id=msg.chat_id,
                text=text,
                parse_mode=parse_mode,
                reply_to_message_id=int(msg.reply_to) if msg.reply_to else None,
            )
        except Exception as exc:
            # Fallback: send as plain text if markdown fails
            logger.warning("Telegram send with formatting failed, retrying plain: %s", exc)
            try:
                await self._app.bot.send_message(
                    chat_id=msg.chat_id,
                    text=msg.text,
                )
            except Exception as exc2:
                logger.error("Telegram send failed: %s", exc2)

    @staticmethod
    def _escape_markdown(text: str) -> str:
        """Escape special chars for Telegram MarkdownV2."""
        special = r"_*[]()~`>#+-=|{}.!"
        return "".join(f"\\{c}" if c in special else c for c in text)

    @staticmethod
    def _parse_allowed_users() -> list[str]:
        """Read allowed user IDs from TELEGRAM_ALLOWED_USERS env var."""
        raw = os.environ.get("TELEGRAM_ALLOWED_USERS", "")
        return [u.strip() for u in raw.split(",") if u.strip()]

    @staticmethod
    def install_instructions() -> str:
        return (
            "To set up Telegram:\n"
            "1. Message @BotFather on Telegram\n"
            "2. /newbot → follow prompts → copy the token\n"
            "3. Set TELEGRAM_BOT_TOKEN=<your_token>\n"
            "4. Get your user ID from @userinfobot\n"
            "5. Set TELEGRAM_ALLOWED_USERS=<your_id>\n"
            "6. Install: pip install python-telegram-bot"
        )
