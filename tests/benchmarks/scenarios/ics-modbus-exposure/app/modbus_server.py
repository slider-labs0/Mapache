"""Minimal Modbus/TCP server - standard library only (no pip, no build).

Modbus has no authentication or integrity by design: any client that can reach
502 can read and (here) write registers/coils. This server answers Read Holding
Registers (0x03), Write Single Coil (0x05) and Write Single Register (0x06) for
any unit id, with NO credential. It models an internet-exposed PLC (CWE-306).
There is no flag - the finding is the unauthenticated, writable exposure.
"""

import socketserver
import struct

# 16 holding registers, pre-seeded (e.g. a setpoint bank).
REGISTERS = [100, 200, 300, 50, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0]
COILS = [0] * 16


class ModbusHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            hdr = self._recvn(7)          # MBAP header
            if not hdr:
                return
            tid, pid, length, unit = struct.unpack(">HHHB", hdr)
            pdu = self._recvn(length - 1)  # length counts the unit id byte
            if not pdu:
                return
            resp = self._dispatch(pdu)
            out = struct.pack(">HHHB", tid, pid, len(resp) + 1, unit) + resp
            self.request.sendall(out)

    def _recvn(self, n):
        data = b""
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                return b""
            data += chunk
        return data

    def _dispatch(self, pdu):
        func = pdu[0]
        if func == 0x03:  # Read Holding Registers
            addr, count = struct.unpack(">HH", pdu[1:5])
            vals = REGISTERS[addr:addr + count]
            body = b"".join(struct.pack(">H", v) for v in vals)
            return bytes([0x03, len(body)]) + body
        if func == 0x06:  # Write Single Register (NO AUTH)
            addr, value = struct.unpack(">HH", pdu[1:5])
            if 0 <= addr < len(REGISTERS):
                REGISTERS[addr] = value
            return pdu[:5]
        if func == 0x05:  # Write Single Coil (NO AUTH)
            addr, value = struct.unpack(">HH", pdu[1:5])
            if 0 <= addr < len(COILS):
                COILS[addr] = 1 if value == 0xFF00 else 0
            return pdu[:5]
        if func == 0x11:  # Report Server ID (device identification, no auth)
            sid = b"OpenPLC-Sim v1 Modicon"
            return bytes([0x11, len(sid) + 1]) + sid + bytes([0xFF])  # 0xFF = running
        # Illegal function
        return bytes([func | 0x80, 0x01])


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    print("modbus/tcp listening on 502 (no authentication)")
    Server(("0.0.0.0", 502), ModbusHandler).serve_forever()
