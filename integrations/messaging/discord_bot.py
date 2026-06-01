"""
discord_bot.py — Mapache Discord integration

Connects Mapache to Discord. Operates via DMs or a designated channel.

Setup:
    1. Go to https://discord.com/developers/applications
    2. New Application -> Bot -> copy token
    3. Enable Message Content Intent under Bot settings
    4. Invite bot: https://discord.com/oauth2/authorize?client_id=YOUR_ID&permissions=8&scope=bot
    5. Set DISCORD_BOT_TOKEN environment variable
    6. Set DISCORD_ALLOWED_USERS=your_discord_id

Install:
    pip install discord.py
"""

from __future__ import annotations

import os
from typing import Optional

from integrations.messaging.gateway import IncomingMessage, MessageGateway, OutgoingMessage
from core.logger import get_logger

logger = get_logger(__name__)

try:
    import discord
    HAS_DISCORD = True
except ImportError:
    HAS_DISCORD = False

MAX_DISCORD_LENGTH = 1900


class DiscordBot:
    def __init__(
        self,
        token: Optional[str] = None,
        allowed_users: Optional[list[str]] = None,
        allow_all: bool = False,
        channel_id: Optional[int] = None,
        dm_only: bool = False,
    ) -> None:
        if not HAS_DISCORD:
            raise ImportError(
                "discord.py not installed.\n"
                "Install: pip install discord.py"
            )

        self.token = token or os.environ.get("DISCORD_BOT_TOKEN", "")
        if not self.token:
            raise ValueError(
                "No Discord bot token. Set DISCORD_BOT_TOKEN.\n"
                "Get one from https://discord.com/developers/applications"
            )

        self.allowed_users = set(allowed_users or self._parse_allowed_users())
        self.allow_all = allow_all
        self.channel_id = channel_id
        self.dm_only = dm_only
        self._gateway: Optional[MessageGateway] = None
        self._client: Optional[discord.Client] = None

    async def start(self, gateway: MessageGateway) -> None:
        self._gateway = gateway
        gateway.register_sender("discord", self._send_message)

        intents = discord.Intents.default()
        intents.message_content = True
        intents.dm_messages = True

        self._client = discord.Client(intents=intents)

        @self._client.event
        async def on_ready():
            logger.info("Discord bot ready: %s", self._client.user)

        @self._client.event
        async def on_message(message: discord.Message):
            await self._on_message(message)

        logger.info("Discord bot connecting...")
        await self._client.start(self.token)

    async def stop(self) -> None:
        if self._client:
            await self._client.close()
            logger.info("Discord bot stopped")

    async def _on_message(self, message: discord.Message) -> None:
        if message.author == self._client.user:
            return

        is_dm = isinstance(message.channel, discord.DMChannel)

        if self.dm_only and not is_dm:
            return
        if self.channel_id and not is_dm and message.channel.id != self.channel_id:
            return

        # In servers: must mention the bot or use a prefix
        if not is_dm:
            if not (self._client.user in message.mentions or
                    message.content.startswith("!mapache") or
                    message.content.startswith("?")):
                return

        text = message.content

        # Strip bot mention
        if self._client.user:
            mention = f"<@{self._client.user.id}>"
            mention_nick = f"<@!{self._client.user.id}>"
            text = text.replace(mention, "").replace(mention_nick, "").strip()

        if not text:
            return

        async with message.channel.typing():
            msg = IncomingMessage(
                platform="discord",
                user_id=str(message.author.id),
                username=message.author.display_name,
                text=text,
                chat_id=str(message.channel.id),
                message_id=str(message.id),
            )

            if self._gateway:
                await self._gateway.handle_message(msg)

    async def _send_message(self, msg: OutgoingMessage) -> None:
        if not self._client:
            return

        parts = self._split_for_discord(msg.text)

        for i, part in enumerate(parts):
            try:
                # Try cache first (fast)
                channel = self._client.get_channel(int(msg.chat_id))

                # Not in cache — fetch directly (works for DM channels)
                if channel is None:
                    try:
                        channel = await self._client.fetch_channel(int(msg.chat_id))
                    except discord.NotFound:
                        logger.error("Discord: channel %s not found", msg.chat_id)
                        return
                    except discord.Forbidden:
                        logger.error("Discord: no permission to access channel %s", msg.chat_id)
                        return

                await channel.send(part[:MAX_DISCORD_LENGTH])

            except Exception as exc:
                logger.error("Discord send error: %s", exc)

    def _split_for_discord(self, text: str) -> list[str]:
        if len(text) <= MAX_DISCORD_LENGTH:
            return [text]

        parts = []
        while len(text) > MAX_DISCORD_LENGTH:
            split = text.rfind("\n", 0, MAX_DISCORD_LENGTH)
            if split < MAX_DISCORD_LENGTH // 2:
                split = MAX_DISCORD_LENGTH
            parts.append(text[:split])
            text = text[split:].lstrip()

        if text:
            parts.append(text)
        return parts

    @staticmethod
    def _parse_allowed_users() -> list[str]:
        raw = os.environ.get("DISCORD_ALLOWED_USERS", "")
        return [u.strip() for u in raw.split(",") if u.strip()]

    @staticmethod
    def install_instructions() -> str:
        return (
            "To set up Discord:\n"
            "1. https://discord.com/developers/applications\n"
            "2. New Application -> Bot -> copy token\n"
            "3. Enable Message Content Intent\n"
            "4. Invite: https://discord.com/oauth2/authorize?client_id=YOUR_ID&permissions=8&scope=bot\n"
            "5. Set DISCORD_BOT_TOKEN=<token>\n"
            "6. Set DISCORD_ALLOWED_USERS=<your_discord_id>\n"
            "7. pip install discord.py"
        )
