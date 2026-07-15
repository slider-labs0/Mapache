#!/usr/bin/env sh
# isolated_lab.sh — a CONTAINED Metasploitable 2 lab for Mapache benchmarking.
#
# Why this exists
# ---------------
# Pointing an autonomous agent at a deliberately-hostile host is only safe if the
# host (and the agent's own tool execution) cannot reach anything you care about.
# The injection shield reduces the odds the agent is manipulated; this network is
# the backstop for when a control fails. Containment here is a NETWORK property,
# not a trust property.
#
# Containment model
# -----------------
#   * An `--internal` Docker network has NO gateway to the host LAN or the
#     internet. Nothing on it can phone home.
#   * BOTH the vulnerable target AND the attacker box (where Mapache's shell/kali
#     tools execute, via `docker exec`) live on that network. So:
#       - a reverse shell / data-exfil attempt from the target cannot leave
#       - if the injection shield is ever bypassed, the blast radius is this net
#   * NO ports are published (`-p`) — publishing would punch a hole from the
#     isolated target straight back to your host. The attacker reaches the target
#     by container name / internal IP instead.
#   * Mapache itself runs on the host and drives the attacker over the Docker
#     control plane (`docker exec`), which does not need L3 reachability to the
#     isolated network. Control plane != data plane.
#
# Usage
# -----
#   bash tests/lab/isolated_lab.sh up       # create net + target + attacker
#   bash tests/lab/isolated_lab.sh verify   # prove target reachable, egress blocked
#   bash tests/lab/isolated_lab.sh down     # tear it all down
#
# Then benchmark (tools run INSIDE the attacker; target addressed by IP the
# `up` step prints):
#   python tests/benchmark_metasploitable.py \
#     --target <TARGET_IP> --target-container metasploitable \
#     --attacker-container mapache-attacker --model qwen2.5:32b
#
# With --attacker-container set, ALL of the network tools (nmap_scan, shell,
# kali_run) execute inside the attacker box, so they reach the target on the
# internal network even though the host has no route to it.

set -eu

NET=mapache-lab
TARGET=metasploitable
ATTACKER=mapache-attacker
TARGET_IMAGE=tleemcjr/metasploitable2
# MSF image ships msfconsole + nmap and is Debian-based; kept alive for docker exec.
ATTACKER_IMAGE=metasploitframework/metasploit-framework

need_docker() {
  if ! docker version >/dev/null 2>&1; then
    echo "!! Docker is not reachable — start Docker Desktop and retry." >&2
    exit 1
  fi
}

cmd_up() {
  need_docker
  # Image pulls hit the host daemon (which has internet); the container is only
  # attached to the internal net afterwards, so pulling still works.
  docker network inspect "$NET" >/dev/null 2>&1 \
    || docker network create --internal --driver bridge "$NET" >/dev/null
  echo "network : $NET (internal — no egress)"

  docker rm -f "$TARGET" >/dev/null 2>&1 || true
  docker run -d --name "$TARGET" --network "$NET" "$TARGET_IMAGE" >/dev/null
  echo "target  : $TARGET ($TARGET_IMAGE) — no published ports"

  docker rm -f "$ATTACKER" >/dev/null 2>&1 || true
  docker run -d --name "$ATTACKER" --network "$NET" \
    --entrypoint sleep "$ATTACKER_IMAGE" infinity >/dev/null
  echo "attacker: $ATTACKER ($ATTACKER_IMAGE)"

  ip=$(docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "$TARGET")
  echo
  echo "target IP on $NET: $ip"
  echo "benchmark:"
  echo "  python tests/benchmark_metasploitable.py \\"
  echo "    --target $ip --target-container $TARGET \\"
  echo "    --attacker-container $ATTACKER --model qwen2.5:32b"
}

cmd_verify() {
  need_docker
  echo "[reachability] attacker -> target (expect OK):"
  docker exec "$ATTACKER" sh -c \
    "ping -c1 -W2 $TARGET >/dev/null 2>&1 && echo '  OK target reachable' \
     || echo '  !! target NOT reachable'"
  echo "[egress] attacker -> internet (expect BLOCKED = contained):"
  docker exec "$ATTACKER" sh -c \
    "timeout 5 curl -s https://example.com >/dev/null 2>&1 \
     && echo '  !! EGRESS POSSIBLE — network is NOT isolated' \
     || echo '  OK no egress (contained)'"
  echo "[egress] target -> internet (expect BLOCKED = contained):"
  docker exec "$TARGET" sh -c \
    "timeout 5 sh -c 'wget -q -O /dev/null http://example.com 2>/dev/null \
       || curl -s http://example.com >/dev/null 2>&1' \
     && echo '  !! EGRESS POSSIBLE' || echo '  OK no egress (contained)'"
}

cmd_down() {
  need_docker
  docker rm -f "$TARGET" "$ATTACKER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "torn down: $TARGET, $ATTACKER, network $NET"
}

case "${1:-}" in
  up)     cmd_up ;;
  verify) cmd_verify ;;
  down)   cmd_down ;;
  *) echo "usage: $0 {up|verify|down}" >&2; exit 2 ;;
esac
