"""wireless_tools.py - offline analysis of a captured Wi-Fi handshake (.pcap/.cap).

`handshake_analyze` reads a packet capture and answers the one question that decides
whether a Wi-Fi engagement can proceed offline: *did we actually capture something
crackable?* It parses the pcap container (both byte-orders, us/ns), radiotap, and the
802.11 frames to report:

  * the network(s) seen - ESSID + BSSID from beacon/probe frames,
  * WPA 4-way-handshake completeness - which of messages M1-M4 were captured per BSSID
    (you need the ANonce + a MIC message to crack; a partial handshake is worthless),
  * a PMKID (RSN PMKID KDE in M1) - the clientless attack that needs no client at all,
  * the exact next command to crack it (hashcat -m 22000 / aircrack-ng).

Read-only, dependency-free (stdlib struct only - no scapy), evidence-first: it reports a
handshake only when the EAPOL-Key messages are really in the capture. Capturing the
handshake (airodump/deauth) needs a radio and belongs to the wireless_operator over a
hardware/dropbox link; this tool is the analysis half that runs anywhere.
"""

from __future__ import annotations

import os
import struct
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

_EAPOL_SNAP = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"  # LLC/SNAP + EAPOL ethertype
_RSN_PMKID = b"\x00\x0f\xac\x04"                    # RSN OUI + KDE data-type 4 (PMKID)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


class HandshakeAnalyzeTool(BaseTool):
    """Analyze a Wi-Fi capture (.pcap/.cap) for a crackable WPA handshake or PMKID and
    emit the crack command - the offline half of a wireless engagement."""

    name = "handshake_analyze"
    description = (
        "Analyze a captured Wi-Fi packet capture (.pcap/.cap/.pcapng-as-pcap) offline for a "
        "crackable WPA/WPA2 4-way handshake or a PMKID. Parses radiotap + 802.11 + EAPOL and "
        "reports, per network (ESSID/BSSID): which handshake messages (M1-M4) were captured, "
        "whether it is CRACKABLE (needs the ANonce + a MIC message), and whether a PMKID was "
        "seen (clientless crack). Emits the exact hashcat -m 22000 / aircrack-ng command. "
        "Read-only/offline. Give `path` to the capture; optional `wordlist` to put in the "
        "crack command. Capturing the handshake needs a radio (wireless_operator)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the .pcap/.cap capture file."},
            "wordlist": {"type": "string",
                         "description": "Wordlist path to place in the crack command (default rockyou)."},
        },
        "required": ["path"],
    }
    permissions = {Permission.FILESYSTEM}
    timeout = 45
    tags = ["wireless", "wifi", "wpa", "handshake", "pcap"]

    # --- pcap container ------------------------------------------------------ #
    def _iter_packets(self, data: bytes) -> Any:
        if len(data) < 24:
            return
        magic = data[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic[:4] == b"\x0a\x0d\x0d\x0a":
            # pcapng - not parsed here; caller reports the guidance.
            self.linktype = -1
            return
        else:
            self.linktype = None
            return
        self.linktype = struct.unpack(endian + "I", data[20:24])[0]
        off = 24
        n = 0
        while off + 16 <= len(data) and n < 200000:
            _ts, _us, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
            off += 16
            if incl <= 0 or off + incl > len(data):
                break
            yield data[off:off + incl]
            off += incl
            n += 1

    # --- 802.11 dissection --------------------------------------------------- #
    def _dot11(self, pkt: bytes) -> Optional[bytes]:
        """Strip radiotap (link 127/163) so `pkt` starts at the 802.11 MAC header."""
        lt = self.linktype
        if lt in (127, 163):  # radiotap / AVS
            if len(pkt) < 4:
                return None
            rt_len = struct.unpack("<H", pkt[2:4])[0]
            return pkt[rt_len:] if 0 < rt_len < len(pkt) else None
        if lt == 105:  # bare 802.11
            return pkt
        # Unknown link layer: still try to find EAPOL by signature later.
        return pkt

    def analyze_bytes(self, data: bytes) -> dict:
        self.linktype = None
        networks: dict[str, str] = {}          # bssid -> essid
        hs: dict[str, set] = {}                # bssid -> {message numbers}
        pmkid: dict[str, str] = {}             # bssid -> pmkid hex
        eapol_frames = 0

        for pkt in self._iter_packets(data):
            frame = self._dot11(pkt)
            if not frame or len(frame) < 10:
                continue
            fc0 = frame[0]
            ftype = (fc0 >> 2) & 0x3
            subtype = (fc0 >> 4) & 0xf

            # Beacon / probe-response -> ESSID + BSSID.
            if ftype == 0 and subtype in (8, 5) and len(frame) >= 36:
                bssid = _mac(frame[16:22])  # Addr3 = BSSID for infrastructure mgmt frames
                body = frame[24 + 12:]      # skip MAC(24) + timestamp/interval/cap(12)
                i = 0
                while i + 2 <= len(body):
                    tag, tlen = body[i], body[i + 1]
                    if tag == 0 and i + 2 + tlen <= len(body):  # SSID element
                        essid = body[i + 2:i + 2 + tlen].decode("latin-1", "ignore")
                        networks.setdefault(bssid, essid or "<hidden>")
                        break
                    i += 2 + tlen
                continue

            # EAPOL-Key (in a data frame) -> handshake message classification + PMKID.
            sig = frame.find(_EAPOL_SNAP)
            if sig == -1:
                continue
            eapol_frames += 1
            # BSSID: for a data frame Addr1(4:10)/Addr2(10:16) - pick the one that also
            # appears as a beacon BSSID, else Addr2 (transmitter) as a reasonable default.
            a1, a2 = _mac(frame[4:10]), _mac(frame[10:16])
            bssid = a1 if a1 in networks else (a2 if a2 in networks else a2)
            eapol = frame[sig + 8:]
            if len(eapol) < 4 or eapol[1] != 0x03:  # EAPOL type 3 = Key
                continue
            # Key Descriptor: type(1) key_info(2) ...
            if len(eapol) < 8:
                continue
            key_info = struct.unpack(">H", eapol[5:7])[0]
            install = bool(key_info & 0x0040)
            ack = bool(key_info & 0x0080)
            mic = bool(key_info & 0x0100)
            secure = bool(key_info & 0x0200)
            if ack and not mic:
                msg = 1
            elif mic and not ack and not secure and not install:
                msg = 2
            elif mic and ack and install and secure:
                msg = 3
            elif mic and secure and not ack:
                msg = 4
            else:
                msg = 2 if mic else 1
            hs.setdefault(bssid, set()).add(msg)

            # PMKID lives in M1's key data (RSN PMKID KDE).
            if msg == 1:
                kdi = eapol.find(_RSN_PMKID)
                if kdi != -1 and len(eapol) >= kdi + 4 + 16:
                    pmkid[bssid] = eapol[kdi + 4:kdi + 4 + 16].hex()

        return {"networks": networks, "handshakes": hs, "pmkid": pmkid,
                "eapol_frames": eapol_frames, "linktype": self.linktype}

    def _render(self, path: str, res: dict, wordlist: str) -> ToolResult:
        if res["linktype"] == -1:
            return ToolResult.fail(
                "handshake_analyze: this is a pcapng file. Convert it first: "
                "`hcxpcapngtool -o hash.22000 " + path + "` (that also extracts the "
                "handshake/PMKID directly), then crack hash.22000 with hashcat -m 22000.")
        if res["linktype"] is None:
            return ToolResult.fail(
                "handshake_analyze: not a recognizable pcap file (bad magic). Provide a "
                "libpcap .pcap/.cap capture.")

        nets, hs, pmkid = res["networks"], res["handshakes"], res["pmkid"]
        lines = [f"handshake_analyze - {path}  (link-type {res['linktype']}, "
                 f"{res['eapol_frames']} EAPOL frames)"]
        crackable_any = False

        seen_bssids = set(nets) | set(hs) | set(pmkid)
        if not seen_bssids:
            return ToolResult.ok(
                lines[0] + "\n\nNo networks, EAPOL handshakes, or PMKIDs found in this "
                "capture. Re-capture on the AP's channel with a client present "
                "(airodump-ng --bssid <AP> -c <ch> -w cap) and force a handshake with a "
                "targeted deauth (aireplay-ng -0), or grab a PMKID (hcxdumptool).",
                metadata={"networks": 0, "crackable": 0})

        lines.append("\nNETWORKS / HANDSHAKES:")
        for b in sorted(seen_bssids):
            essid = nets.get(b, "<unknown ESSID>")
            msgs = sorted(hs.get(b, set()))
            parts = [f"ESSID='{essid}' BSSID={b}"]
            if msgs:
                parts.append("handshake msgs " + "".join(f"M{m}" for m in msgs))
                # crackable = have M1 (ANonce) AND a MIC-bearing message (M2/M3/M4)
                if 1 in msgs and any(m in msgs for m in (2, 3, 4)):
                    parts.append("=> CRACKABLE 4-way handshake")
                    crackable_any = True
                elif len(msgs) >= 2 and any(m in msgs for m in (2, 3)):
                    parts.append("=> likely crackable (has a MIC message)")
                    crackable_any = True
                else:
                    parts.append("=> PARTIAL (need M1+a MIC message; re-capture)")
            if b in pmkid:
                parts.append(f"PMKID={pmkid[b]} => CRACKABLE clientless (PMKID attack)")
                crackable_any = True
            lines.append("  - " + " | ".join(parts))

        wl = (wordlist or "").strip() or "/usr/share/wordlists/rockyou.txt"
        if crackable_any:
            lines.append("\nCRACK IT (offline):")
            lines.append(f"  1. hcxpcapngtool -o hash.22000 {path}   # -> hashcat 22000 format")
            lines.append(f"  2. hashcat -m 22000 hash.22000 {wl}")
            lines.append(f"     (or: aircrack-ng -w {wl} -b <BSSID> {path})")
            lines.append("  A recovered PSK is the finding: WPA2-PSK with a guessable "
                         "passphrase (report the ESSID and that the key was recovered "
                         "offline; do NOT include the plaintext key in a shared report).")
        else:
            lines.append("\nNo fully crackable handshake/PMKID yet - only partial EAPOL "
                         "frames. Re-capture the complete 4-way handshake (deauth a "
                         "connected client) or grab the PMKID with hcxdumptool.")
        return ToolResult.ok("\n".join(lines),
                             metadata={"networks": len(seen_bssids),
                                       "crackable": int(crackable_any),
                                       "pmkid": len(pmkid)})

    async def execute(self, path: str, wordlist: Optional[str] = None,
                      **kwargs: Any) -> ToolResult:
        path = (path or "").strip()
        if not path or not os.path.exists(path):
            return ToolResult.fail(f"handshake_analyze: path not found: {path!r}")
        try:
            with open(path, "rb") as fh:
                data = fh.read(50_000_000)
        except Exception as exc:
            return ToolResult.fail(f"handshake_analyze: cannot read {path}: {exc}")
        res = self.analyze_bytes(data)
        return self._render(path, res, wordlist or "")
