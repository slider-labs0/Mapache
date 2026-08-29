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
import glob
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Optional

from browser.http_client import HttpClient
from core.logger import get_logger


def find_tor_binary() -> tuple[Optional[str], Optional[str]]:
    """Locate a tor executable and, for a Tor Browser bundle, its Data/Tor dir
    (which holds geoip). Returns (tor_path, data_dir); data_dir is None for a
    system `tor` on PATH. Lets Mapache start Tor itself instead of asking the user."""
    onpath = shutil.which("tor")
    if onpath:
        return onpath, None
    system = platform.system()
    candidates: list[str] = []
    if system == "Windows":
        rel = os.path.join("Browser", "TorBrowser", "Tor", "tor.exe")
        roots = [
            os.path.expanduser(r"~\Desktop\Tor Browser"),
            os.path.expanduser(r"~\Downloads\Tor Browser"),
            os.path.expanduser(r"~\OneDrive\Desktop\Tor Browser"),
            os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"), "Tor Browser"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Tor Browser"),
        ]
        candidates = [os.path.join(r, rel) for r in roots if r]
    elif system == "Darwin":
        candidates = [
            "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor",
            os.path.expanduser("~/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"),
            "/opt/homebrew/bin/tor", "/usr/local/bin/tor",
        ]
    else:  # Linux / other
        candidates = ["/usr/bin/tor", "/usr/sbin/tor"]
        candidates += glob.glob(
            os.path.expanduser("~/tor-browser*/Browser/TorBrowser/Tor/tor"))
        candidates += glob.glob(os.path.expanduser(
            "~/.local/share/torbrowser/tbb/*/tor-browser/Browser/TorBrowser/Tor/tor"))
    for c in candidates:
        if c and os.path.isfile(c):
            # a bundle tor sits at .../TorBrowser/Tor/tor(.exe); geoip is in
            # .../TorBrowser/Data/Tor (one level up from the Tor dir).
            data = os.path.normpath(os.path.join(os.path.dirname(c), "..", "Data", "Tor"))
            return c, (data if os.path.isdir(data) else None)
    return None, None

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
                proxy=f"socks5h://127.0.0.1:{self.socks_port}",
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
                    proxy=f"socks5h://127.0.0.1:{self.socks_port}",
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
            # socks5h: remote DNS so .onion hidden services resolve at the Tor proxy.
            proxy=f"socks5h://127.0.0.1:{self.socks_port}",
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

    # ------------------------------------------------------------------ #
    # Process management (optional - for launching Tor directly)
    # ------------------------------------------------------------------ #

    async def start(self, tor_cmd: str = "tor") -> tuple[bool, str]:
        """Start Tor if it isn't already running. Locates a system `tor` OR a Tor
        Browser bundle (Windows/macOS/Linux), launches it detached on this controller's
        SOCKS and control ports, and waits for the SOCKS port to come up. Mapache starts
        Tor itself - it does not ask the operator to launch it."""
        if await self.is_running():
            return True, f"Tor already running on port {self.socks_port}"

        tor_path, data_dir = find_tor_binary()
        if not tor_path:
            tor_path = shutil.which(tor_cmd)
        if not tor_path:
            return False, (
                "No tor binary found (checked PATH and common Tor Browser locations). "
                "Install: `sudo apt install tor` (Linux), `brew install tor` (macOS), "
                "or install the Tor Browser bundle (Windows/macOS)."
            )

        # Fresh, writable DataDirectory (so we never fight a running Tor Browser for its
        # lock); pull geoip from the bundle when available for correct exit selection.
        run_dir = os.path.join(tempfile.gettempdir(), f"mapache-tor-{self.socks_port}")
        try:
            os.makedirs(run_dir, exist_ok=True)
        except Exception:
            run_dir = tempfile.mkdtemp(prefix="mapache-tor-")
        argv = [tor_path,
                "--SocksPort", str(self.socks_port),
                "--ControlPort", str(self.control_port),
                "--DataDirectory", run_dir]
        if data_dir:
            geoip, geoip6 = os.path.join(data_dir, "geoip"), os.path.join(data_dir, "geoip6")
            if os.path.isfile(geoip):
                argv += ["--GeoIPFile", geoip]
            if os.path.isfile(geoip6):
                argv += ["--GeoIPv6File", geoip6]

        loop = asyncio.get_event_loop()
        try:
            self._process = await loop.run_in_executor(None, self._spawn_detached, argv)
        except Exception as exc:
            return False, f"Failed to launch tor ({tor_path}): {exc}"

        # Wait for bootstrap (SOCKS port open). A bundle tor bootstraps in a few seconds.
        for _ in range(45):
            await asyncio.sleep(1)
            if await self.is_running():
                return True, (f"Tor started (pid {getattr(self._process, 'pid', '?')}) via "
                              f"{tor_path} - SOCKS 127.0.0.1:{self.socks_port}, "
                              f"control {self.control_port}")
        return False, ("Tor was launched but its SOCKS port did not come up in time - the "
                       "port may be busy or tor could not bootstrap.")

    def _spawn_detached(self, argv: list[str]) -> Any:
        """Launch tor as a detached background process that outlives this call."""
        kwargs: dict[str, Any] = {
            "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
            "stdin": subprocess.DEVNULL,
        }
        if os.name == "nt":
            # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            kwargs["creationflags"] = 0x00000008 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        return subprocess.Popen(argv, **kwargs)

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
