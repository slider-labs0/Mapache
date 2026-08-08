"""
gateway.py - Mapache messaging gateway

The bridge between messaging platforms and the agent controller.
All incoming messages from Telegram, Discord, etc. flow through here.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from uuid import uuid4

from core.logger import get_logger

logger = get_logger(__name__)

MAX_MESSAGE_LENGTH = 4000
RATE_LIMIT_SECONDS = 3
MAX_RESPONSE_PARTS = 5


@dataclass
class IncomingMessage:
    platform: str
    user_id: str
    username: str
    text: str
    chat_id: str = ""
    message_id: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class OutgoingMessage:
    text: str
    chat_id: str
    reply_to: str = ""
    parse_mode: str = ""
    metadata: dict = field(default_factory=dict)


class UserSession:
    def __init__(self, user_id: str, platform: str) -> None:
        self.user_id = user_id
        self.platform = platform
        self.session_id = str(uuid4())
        self.created_at = time.time()
        self.last_active = time.time()
        self.message_count = 0
        self.last_message_time = 0.0

    def touch(self) -> None:
        self.last_active = time.time()
        self.message_count += 1

    def can_send(self) -> bool:
        return (time.time() - self.last_message_time) >= RATE_LIMIT_SECONDS

    def record_send(self) -> None:
        self.last_message_time = time.time()


class MessageGateway:
    """
    Central message router between platforms and the agent.
    """

    COMMANDS = {
        "/start":  "Initialize or reset your session",
        "/help":   "Show available commands",
        "/reset":  "Clear conversation history",
        "/status": "Show agent status",
        "/tools":  "List available tools",
        "/stop":   "Stop current operation",
    }

    def __init__(
        self,
        agent_controller: Any,
        allowed_users: Optional[list[str]] = None,
        allow_all: bool = False,
    ) -> None:
        self.agent = agent_controller
        self.allowed_users = set(allowed_users or [])
        self.allow_all = allow_all
        self._sessions: dict[str, UserSession] = {}
        self._send_callbacks: dict[str, Callable] = {}
        self._active_tasks: dict[str, asyncio.Task] = {}

    def register_sender(self, platform: str, callback: Callable) -> None:
        self._send_callbacks[platform] = callback
        logger.info("Sender registered for platform: %s", platform)

    async def handle_message(self, msg: IncomingMessage) -> None:
        logger.info("[%s] %s: %r", msg.platform, msg.username, msg.text[:80])

        # Auth check - shows actual ID so you can copy it into .env
        if not self.allow_all and msg.user_id not in self.allowed_users:
            await self._send(msg.platform, OutgoingMessage(
                text=f"Not authorized. Your ID is: {msg.user_id}",
                chat_id=msg.chat_id,
                reply_to=msg.message_id,
            ))
            return

        session = self._get_session(msg.user_id, msg.platform)

        if not session.can_send():
            return
        session.record_send()
        session.touch()

        if msg.text.startswith("/"):
            await self._handle_command(msg, session)
            return

        # Cancel any running task for this user
        if msg.user_id in self._active_tasks:
            task = self._active_tasks[msg.user_id]
            if not task.done():
                task.cancel()

        task = asyncio.create_task(self._agent_turn(msg, session))
        self._active_tasks[msg.user_id] = task

        def _cleanup(fut):
            self._active_tasks.pop(msg.user_id, None)

        task.add_done_callback(_cleanup)

    async def _agent_turn(self, msg: IncomingMessage, session: UserSession) -> None:
        try:
            response = await self.agent.run(
                msg.text,
                session_id=session.session_id,
            )

            text = response.content or "(no response)"

            if response.tool_calls_made:
                tools = ", ".join(response.tool_calls_made)
                text += f"\n\n_Used: {tools}_"

            await self._send_long(msg.platform, text, msg.chat_id, msg.message_id)

        except asyncio.CancelledError:
            await self._send(msg.platform, OutgoingMessage(
                text="Operation cancelled.",
                chat_id=msg.chat_id,
            ))
        except Exception as exc:
            logger.error("Agent turn error: %s", exc, exc_info=True)
            await self._send(msg.platform, OutgoingMessage(
                text=f"Error: {exc}",
                chat_id=msg.chat_id,
                reply_to=msg.message_id,
            ))

    async def _handle_command(self, msg: IncomingMessage, session: UserSession) -> None:
        cmd = msg.text.split()[0].lower().rstrip("@")

        if cmd == "/start":
            self._reset_session(msg.user_id, msg.platform)
            self.agent.context.clear_history()
            text = (
                "Mapache is ready.\n\n"
                f"Session: {session.session_id[:8]}\n\n"
                "Send me any task and I will get it done.\n"
                "Type /help for commands."
            )

        elif cmd == "/help":
            lines = ["Mapache Commands\n"]
            for c, desc in self.COMMANDS.items():
                lines.append(f"{c} - {desc}")
            text = "\n".join(lines)

        elif cmd == "/reset":
            self._reset_session(msg.user_id, msg.platform)
            self.agent.context.clear_history()
            text = "Session reset. Starting fresh."

        elif cmd == "/status":
            text = (
                f"Mapache Status\n"
                f"Session: {session.session_id[:8]}\n"
                f"Messages: {session.message_count}\n"
                f"Mode: {self.agent.mode.value}\n"
                f"Tools: {len(self.agent.context.available_tools)}"
            )

        elif cmd == "/tools":
            tools = self.agent.context.available_tools
            if tools:
                text = "Available Tools\n\n" + "\n".join(f"- {t}" for t in tools)
            else:
                text = "No tools registered."

        elif cmd == "/stop":
            if msg.user_id in self._active_tasks:
                self._active_tasks[msg.user_id].cancel()
                text = "Stopped."
            else:
                text = "Nothing running."

        else:
            text = f"Unknown command: {cmd}\nType /help for commands."

        await self._send(msg.platform, OutgoingMessage(
            text=text,
            chat_id=msg.chat_id,
            reply_to=msg.message_id,
        ))

    async def _send(self, platform: str, msg: OutgoingMessage) -> None:
        callback = self._send_callbacks.get(platform)
        if not callback:
            logger.warning("No sender for platform: %s", platform)
            return
        try:
            await callback(msg)
        except Exception as exc:
            logger.error("Send error [%s]: %s", platform, exc)

    async def _send_long(
        self,
        platform: str,
        text: str,
        chat_id: str,
        reply_to: str = "",
    ) -> None:
        if len(text) <= MAX_MESSAGE_LENGTH:
            await self._send(platform, OutgoingMessage(
                text=text,
                chat_id=chat_id,
                reply_to=reply_to,
            ))
            return

        parts = self._split_message(text, MAX_MESSAGE_LENGTH)
        parts = parts[:MAX_RESPONSE_PARTS]

        for i, part in enumerate(parts):
            suffix = f"\n\nPart {i+1}/{len(parts)}" if len(parts) > 1 else ""
            await self._send(platform, OutgoingMessage(
                text=part + suffix,
                chat_id=chat_id,
                reply_to=reply_to if i == 0 else "",
            ))
            if i < len(parts) - 1:
                await asyncio.sleep(0.3)

    @staticmethod
    def _split_message(text: str, max_len: int) -> list[str]:
        if len(text) <= max_len:
            return [text]

        parts = []
        while text:
            if len(text) <= max_len:
                parts.append(text)
                break

            chunk = text[:max_len]
            split_pos = chunk.rfind("\n\n")
            if split_pos < max_len // 2:
                split_pos = chunk.rfind("\n")
            if split_pos < max_len // 2:
                split_pos = max(chunk.rfind(". "), chunk.rfind("! "), chunk.rfind("? "))
            if split_pos < 0:
                split_pos = max_len

            parts.append(text[:split_pos].strip())
            text = text[split_pos:].strip()

        return [p for p in parts if p]

    def _get_session(self, user_id: str, platform: str) -> UserSession:
        key = f"{platform}:{user_id}"
        if key not in self._sessions:
            self._sessions[key] = UserSession(user_id, platform)
            logger.info("New session for %s:%s", platform, user_id)
        return self._sessions[key]

    def _reset_session(self, user_id: str, platform: str) -> UserSession:
        key = f"{platform}:{user_id}"
        session = UserSession(user_id, platform)
        self._sessions[key] = session
        return session

    def add_allowed_user(self, user_id: str) -> None:
        self.allowed_users.add(user_id)

    def remove_allowed_user(self, user_id: str) -> None:
        self.allowed_users.discard(user_id)

    @property
    def active_session_count(self) -> int:
        return len(self._sessions)
