#!/usr/bin/env bash
set -euo pipefail

# Create dummy0 if it does not exist, then ensure required IPs are present.
if ! ip link show dummy0 >/dev/null 2>&1; then
  sudo modprobe dummy
  sudo ip link add dummy0 type dummy
fi

sudo ip link set dummy0 up

add_ip_if_missing() {
  local ip_cidr="$1"
  if ! ip -4 addr show dev dummy0 | grep -q "${ip_cidr}"; then
    sudo ip addr add "${ip_cidr}" dev dummy0
  fi
}

add_ip_if_missing "10.64.0.1/32"
add_ip_if_missing "10.64.0.100/32"
add_ip_if_missing "10.0.0.1/32"

echo "dummy0 configured:"
ip -br addr show dummy0
