"""ics_tools.py - read-only ICS/OT enumeration that speaks the real protocols.

`modbus_scan` talks Modbus/TCP (the most widely exposed industrial protocol) to an
in-scope controller and turns an anonymous, unauthenticated response into concrete
evidence: the device-identification strings (vendor / product / firmware) and live
register/coil values. A Modbus device answers with NO authentication at all, so a
single valid response IS the finding - an internet-reachable PLC that anyone can read
(and, with a write function, drive). This tool is deliberately READ-ONLY: it issues
only Read Device Identification, Read Holding/Input Registers and Read Coils. OT is
fragile; writes belong to an explicit lab/canary, never here.

Pure-stdlib (asyncio sockets), no pymodbus dependency, evidence-first: every finding is
a value the controller actually returned.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

# Modbus exception-code meanings (for a clean report when a function is refused).
_EXC = {
    1: "illegal function", 2: "illegal data address", 3: "illegal data value",
    4: "slave device failure", 6: "slave device busy", 11: "gateway target failed",
}
# Read Device Identification object ids (MEI type 0x0E, basic + extended).
_OBJ_NAMES = {
    0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision",
    0x03: "VendorUrl", 0x04: "ProductName", 0x05: "ModelName", 0x06: "UserApplicationName",
}


def _mbap(unit: int, pdu: bytes, txid: int = 1) -> bytes:
    """Wrap a PDU in the Modbus/TCP MBAP header. length = unit byte + PDU."""
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, unit) + pdu


class ModbusScanTool(BaseTool):
    """Read-only Modbus/TCP enumeration of an in-scope industrial controller: device
    identity + live register/coil values, proving unauthenticated access."""

    name = "modbus_scan"
    description = (
        "Enumerate an exposed Modbus/TCP industrial controller (PLC/RTU/HMI) READ-ONLY. "
        "Connects to `host`:`port` (default 502) and, for each unit/slave id, requests "
        "Read Device Identification (vendor/product/firmware) and reads holding registers, "
        "input registers and coils. Any answer proves the device is readable with NO "
        "authentication - that response is the finding. Never writes. Give `host`; "
        "optional `port`, `unit_id` (default: scan 0-2 and 255), `start`/`count` for the "
        "register range. For deeper protocol work (DNP3/S7comm/BACnet) drop to kali_run."
    )
    parameters = {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Target IP/hostname of the controller."},
            "port": {"type": "integer", "description": "Modbus/TCP port (default 502)."},
            "unit_id": {"type": "integer",
                        "description": "A specific unit/slave id. Omit to probe 0,1,2,255."},
            "start": {"type": "integer", "description": "First register address (default 0)."},
            "count": {"type": "integer", "description": "Registers/coils to read (default 8)."},
        },
        "required": ["host"],
    }
    permissions = {Permission.NETWORK}
    timeout = 40
    tags = ["ics", "ot", "scada", "modbus", "enumeration"]

    async def _txn(self, host: str, port: int, pdu: bytes, unit: int,
                   timeout: float = 4.0) -> Optional[bytes]:
        """One request/response Modbus/TCP transaction. Returns the PDU (post-MBAP) or None."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
        except Exception:
            return None
        try:
            writer.write(_mbap(unit, pdu))
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            head = await asyncio.wait_for(reader.readexactly(7), timeout=timeout)
            _tx, _pid, length, _unit = struct.unpack(">HHHB", head)
            body = await asyncio.wait_for(
                reader.readexactly(max(0, length - 1)), timeout=timeout)
            return body
        except Exception:
            return None
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass

    @staticmethod
    def _parse_devid(pdu: bytes) -> dict[int, str]:
        """Parse a Read Device Identification (0x2B/0x0E) response into {obj_id: value}."""
        out: dict[int, str] = {}
        # pdu: func(2B) mei(0E) readcode conformity more nextid count [objects...]
        if len(pdu) < 8 or pdu[0] != 0x2B or pdu[1] != 0x0E:
            return out
        i = 7
        num = pdu[6]
        for _ in range(num):
            if i + 2 > len(pdu):
                break
            oid, olen = pdu[i], pdu[i + 1]
            val = pdu[i + 2:i + 2 + olen]
            out[oid] = val.decode("latin-1", "ignore")
            i += 2 + olen
        return out

    async def execute(self, host: str, port: int = 502, unit_id: Optional[int] = None,
                      start: int = 0, count: int = 8, **kwargs: Any) -> ToolResult:
        host = (host or "").strip()
        if not host:
            return ToolResult.fail("modbus_scan: host is required.")
        count = max(1, min(int(count or 8), 125))
        units = [int(unit_id)] if unit_id is not None else [1, 0, 2, 255]

        reachable = False
        lines = [f"modbus_scan - {host}:{port} (READ-ONLY)"]
        findings: list[str] = []
        identity: dict[int, str] = {}

        for unit in units:
            # 1. Read Device Identification (basic + product).
            devid = await self._txn(host, port, bytes([0x2B, 0x0E, 0x01, 0x00]), unit)
            if devid is not None:
                reachable = True
                parsed = self._parse_devid(devid)
                if parsed:
                    identity.update(parsed)

            # 2. Read Holding Registers (fc 3).
            hr = await self._txn(host, port,
                                 struct.pack(">BHH", 0x03, start, count), unit)
            regs: list[int] = []
            note = ""
            if hr is not None:
                reachable = True
                if hr[0] == 0x03 and len(hr) >= 2:
                    bc = hr[1]
                    regs = list(struct.unpack(">" + "H" * (bc // 2), hr[2:2 + bc]))
                elif hr[0] & 0x80:
                    note = f"holding regs refused ({_EXC.get(hr[1], hr[1])})"

            # 3. Read Coils (fc 1) - just presence, first byte.
            coils = await self._txn(host, port,
                                    struct.pack(">BHH", 0x01, start, min(count, 16)), unit)
            coil_note = ""
            if coils is not None and coils[0] == 0x01 and len(coils) >= 3:
                reachable = True
                coil_note = f"coils[{start}..]=0x{coils[2]:02x}"

            if hr is None and devid is None and coils is None:
                continue  # this unit id did not answer

            u = f"unit {unit}:"
            if regs:
                findings.append(
                    f"{u} READ holding registers [{start}..{start + count - 1}] = {regs} "
                    "(live process values, unauthenticated)")
            if coil_note:
                findings.append(f"{u} {coil_note} (unauthenticated coil read)")
            if note:
                findings.append(f"{u} {note}")

        if not reachable:
            return ToolResult.fail(
                f"modbus_scan: no Modbus/TCP response from {host}:{port}. The port may be "
                "closed/filtered or not Modbus. Confirm reachability (nmap -p502) and scope.")

        if identity:
            lines.append("\nDEVICE IDENTIFICATION (unauthenticated):")
            for oid in sorted(identity):
                lines.append(f"  - {_OBJ_NAMES.get(oid, f'obj{oid}')}: {identity[oid]}")
        if findings:
            lines.append("\nLIVE READS:")
            lines += [f"  - {f}" for f in findings]
        lines.append(
            "\nFINDING: this controller answers Modbus/TCP with NO authentication - any "
            "party who can reach it can read process state, and (with write function codes "
            "0x05/0x06/0x0F/0x10) manipulate outputs/setpoints. Report as a "
            "CRITICAL exposure (CWE-306, missing authentication). Do NOT write to a "
            "production controller. Safety-impact and physical process take priority over "
            "further probing.")
        return ToolResult.ok("\n".join(lines),
                             metadata={"reachable": reachable, "identity": len(identity),
                                       "reads": len(findings)})
