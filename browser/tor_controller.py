"""
tor_controller.py - Mapache Tor controller

Manages the Tor process and provides circuit control.
Uses the stem library for programmatic Tor control.

Two modes:
    1. System Tor   - 'tor' daemon running as a service (port 9050)
    2. Tor Browser  - Tor Browser Bundle running (port 9150)

Capabilities:
    - Start/stop Tor process
    - Request new circuit (new exit IP)
    - Check connectivity and current exit IP
    - List available circuits
    - Route HTTP requests through Tor

Install:
    pip install stem
    
    Windows: Download Tor Expert Bundle from https://www.torproject.org/download/tor/
    Linux:   sudo apt install tor
    Mac:     brew install tor
"""

from __future__ import annotations

import asyncio
import platform
import shutil
import socket
import time
from dataclasses import dataclass
from typing import Any, Optional

from browser.http_client import HttpClient
from core.logger import get_logger

logger = get_logger(__name__)

try:
    import stem
    import stem.control
    import stem.process
    HAS_STEM = True
except ImportError:
    HAS_STEM = False


@dataclass
class TorStatus:
    running: bool
    socks_port: int
    control_port: int
    exit_ip: Optional[str] = None
    is_tor_ip: bool = False
    circuit_count: int = 0
    error: Optional[str] = None

    def to_string(self) -> str:
        if not self.running:
            return f"Tor is NOT running. Error: {self.error or 'unknown'}"
        lines = [
            f"Tor Status: RUNNING",
            f"  SOCKS port:   {self.socks_port}",
            f"  Control port: {self.control_port}",
            f"  Exit IP:      {self.exit_ip or 'unknown'}",
            f"  Is Tor IP:    {'yes' if self.is_tor_ip else 'no'}",
            f"  Circuits:     {self.circuit_count}",
        ]
        return "\n".join(lines)


class TorController:
    """
    Manages Tor connectivity and circuit control.

    Usage (existing Tor installation):
        controller = TorController()
        status = await controller.get_status()
        print(status.to_string())

        # Get a new exit IP
        await controller.new_circuit()

        # Make a request through Tor
        client = controller.get_http_client()
        response = await client.get("http://example.onion")
    """

    DEFAULT_SOCKS_PORT = 9050
    DEFAULT_CONTROL_PORT = 9051
    TOR_BROWSER_SOCKS_PORT = 9150
    TOR_BROWSER_CONTROL_PORT = 9151

    def __init__(
        self,
        socks_port: int = DEFAULT_SOCKS_PORT,
        control_port: int = DEFAULT_CONTROL_PORT,
        control_password: str = "",
    ) -> None:
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self._process: Any = None  # stem process if we launched it

    # ------------------------------------------------------------------ #
    # Status
    # ------------------------------------------------------------------ #

    async def is_running(self) -> bool:
        """Check if Tor SOCKS proxy is reachable."""
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None, self._check_port, "127.0.0.1", self.socks_port
            )
            return True
        except Exception:
            return False

    async def get_status(self) -> TorStatus:
        """Get full Tor status including exit IP."""
        if not await self.is_running():
            # Try Tor Browser ports as fallback
            if self.socks_port == self.DEFAULT_SOCKS_PORT:
                logger.debug("Tor not on 9050, trying Tor Browser port 9150")
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None, self._check_port, "127.0.0.1", self.TOR_BROWSER_SOCKS_PORT
                    )
                    self.socks_port = self.TOR_BROWSER_SOCKS_PORT
                    self.control_port = self.TOR_BROWSER_CONTROL_PORT
                    logger.info("Found Tor Browser on port 9150")
                except Exception:
                    return TorStatus(
                        running=False,
                        socks_port=self.socks_port,
                        control_port=self.control_port,
                        error="Tor is not running on ports 9050 or 9150",
                    )
            else:
                return TorStatus(
                    running=False,
                    socks_port=self.socks_port,
                    control_port=self.control_port,
                    error=f"Tor is not running on port {self.socks_port}",
                )

        # Check exit IP
        exit_ip = None
        is_tor = False
        try:
            async with HttpClient(
                proxy=f"socks5://127.0.0.1:{self.socks_port}",
                timeout=15.0,
            ) as client:
                is_tor, exit_ip = await client.check_tor()
        except Exception as exc:
            logger.warning("Could not check Tor exit IP: %s", exc)

        # Circuit count via stem
        circuit_count = 0
        if HAS_STEM:
            circuit_count = await self._get_circuit_count()

        return TorStatus(
            running=True,
            socks_port=self.socks_port,
            control_port=self.control_port,
            exit_ip=exit_ip,
            is_tor_ip=is_tor,
            circuit_count=circuit_count,
        )

    # ------------------------------------------------------------------ #
    # Circuit control
    # ------------------------------------------------------------------ #

    async def new_circuit(self) -> tuple[bool, str]:
        """
        Request a new Tor circuit (changes exit IP).
        Requires stem library and control port access.
        Returns (success, message).
        """
        if not HAS_STEM:
            return False, (
                "stem library not installed. Install with: pip install stem\n"
                "Without stem, you can restart Tor manually to get a new circuit."
            )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._signal_newnym)
            if result:
                # Wait for circuit to establish
                await asyncio.sleep(3)
                # Get new IP
                async with HttpClient(
                    proxy=f"socks5://127.0.0.1:{self.socks_port}",
                    timeout=15.0,
                ) as client:
                    _, new_ip = await client.check_tor()
                return True, f"New circuit established. Exit IP: {new_ip}"
            return False, "Failed to signal new circuit"
        except Exception as exc:
            return False, f"Circuit renewal failed: {exc}"

    def _signal_newnym(self) -> bool:
        """Send NEWNYM signal to Tor controller (blocking)."""
        try:
            with stem.control.Controller.from_port(port=self.control_port) as controller:
                if self.control_password:
                    controller.authenticate(password=self.control_password)
                else:
                    controller.authenticate()
                controller.signal(stem.Signal.NEWNYM)
                return True
        except Exception as exc:
            logger.error("NEWNYM signal failed: %s", exc)
            return False

    async def _get_circuit_count(self) -> int:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._count_circuits)
        except Exception:
            return 0

    def _count_circuits(self) -> int:
        try:
            with stem.control.Controller.from_port(port=self.control_port) as controller:
                try:
                    controller.authenticate(password=self.control_password)
                except Exception:
                    controller.authenticate()
                return len(controller.get_circuits())
        except Exception:
            return 0

    # ------------------------------------------------------------------ #
    # HTTP client factory
    # ------------------------------------------------------------------ #

    def get_http_client(
        self,
        timeout: float = 45.0,
        verify_ssl: bool = False,
    ) -> HttpClient:
        """Return an HttpClient pre-configured to route through Tor."""
        return HttpClient(
            proxy=f"socks5://127.0.0.1:{self.socks_port}",
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

    # ------------------------------------------------------------------ #
    # Process management (optional - for launching Tor directly)
    # ------------------------------------------------------------------ #

    async def start(self, tor_cmd: str = "tor") -> tuple[bool, str]:
        """
        Start a Tor process. Only needed if Tor isn't already running.
        Prefers the system Tor daemon.
        """
        if await self.is_running():
            return True, f"Tor already running on port {self.socks_port}"

        tor_path = shutil.which(tor_cmd)
        if not tor_path:
            return False, (
                "Tor not found in PATH.\n"
                "Install: sudo apt install tor (Linux) or "
                "download Tor Browser (Windows/Mac)"
            )

        if not HAS_STEM:
            # Start without stem - just subprocess
            try:
                proc = await asyncio.create_subprocess_exec(
                    tor_path,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                # Wait for it to start
                for _ in range(10):
                    await asyncio.sleep(1)
                    if await self.is_running():
                        return True, f"Tor started (PID {proc.pid})"
                return False, "Tor started but not responding on SOCKS port"
            except Exception as exc:
                return False, f"Failed to start Tor: {exc}"

        # Start with stem for better control
        try:
            loop = asyncio.get_event_loop()
            success, msg = await loop.run_in_executor(None, self._start_with_stem, tor_path)
            return success, msg
        except Exception as exc:
            return False, f"Failed to start Tor: {exc}"

    def _start_with_stem(self, tor_path: str) -> tuple[bool, str]:
        try:
            self._process = stem.process.launch_tor_with_config(
                tor_cmd=tor_path,
                config={
                    "SocksPort": str(self.socks_port),
                    "ControlPort": str(self.control_port),
                    "DataDirectory": "/tmp/mapache_tor",
                },
                timeout=60,
            )
            return True, f"Tor launched successfully"
        except Exception as exc:
            return False, str(exc)

    async def stop(self) -> None:
        if self._process:
            self._process.kill()
            self._process = None
            logger.info("Tor process stopped")

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check_port(host: str, port: int) -> None:
        """Blocking port check - run in executor."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((host, port))
            if result != 0:
                raise ConnectionRefusedError(f"Port {port} not open")
        finally:
            sock.close()

    @staticmethod
    def install_instructions() -> str:
        system = platform.system()
        if system == "Windows":
            return (
                "To use Tor on Windows:\n"
                "1. Download Tor Browser: https://www.torproject.org/download/\n"
                "2. Open Tor Browser (keep it open)\n"
                "3. Tor will be available on port 9150\n"
                "   Or download Tor Expert Bundle for headless use (port 9050)"
            )
        elif system == "Darwin":
            return (
                "To use Tor on macOS:\n"
                "1. brew install tor\n"
                "2. brew services start tor\n"
                "   Or open Tor Browser for port 9150"
            )
        else:
            return (
                "To use Tor on Linux:\n"
                "1. sudo apt install tor\n"
                "2. sudo systemctl start tor\n"
                "   Tor will run on port 9050"
            )
