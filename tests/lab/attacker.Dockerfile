# attacker.Dockerfile — the box Mapache's tools run inside (via `docker exec`).
#
# Built on the HOST daemon (which has egress) so apt can fetch packages, then run
# attached to the `--internal` lab network (no egress). Bakes in the full offline
# exploit toolchain so the contained attacker never needs internet at runtime:
#   * metasploit-framework -> msfconsole / msfvenom on PATH
#   * exploitdb            -> searchsploit on PATH
#   * nmap                 -> recon
#   * netcat-traditional   -> raw payload delivery for the manual backdoors
#     (vsftpd 2.3.4, UnrealIRCd 3.2.8.1, Samba usermap) Metasploitable 2 exposes
#   * iputils-ping / curl  -> used by isolated_lab.sh `verify` (reachability + egress)
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        metasploit-framework \
        exploitdb \
        nmap \
        netcat-traditional \
        iputils-ping \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Seed searchsploit's local copy of Exploit-DB so it works fully offline.
RUN searchsploit -u || true

# Kept alive for `docker exec`; the lab script overrides with `sleep infinity`.
CMD ["sleep", "infinity"]
