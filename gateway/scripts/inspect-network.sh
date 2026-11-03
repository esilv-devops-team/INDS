#!/bin/sh
# Read-only inventory. Run with: sh gateway/scripts/inspect-network.sh
set -eu

for tool in nmcli ip bridge; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing required tool: %s\n' "$tool" >&2
        exit 1
    fi
done

printf '\nNetworkManager version\n'
nmcli --version
printf '\nNetworkManager devices\n'
nmcli device status
printf '\nConnection profiles\n'
nmcli -f NAME,UUID,TYPE,DEVICE,AUTOCONNECT connection show
printf '\nLinks and addresses\n'
ip -brief link
ip -brief address
printf '\nIPv4 routes\n'
ip route show
printf '\nIPv6 routes\n'
ip -6 route show
printf '\nBridge ports\n'
bridge link show

if command -v nft >/dev/null 2>&1; then
    printf '\nFirewall inventory requires a separate privileged read: sudo nft list ruleset\n'
fi
