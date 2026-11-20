# INDS-37 — Gateway firewall

The Pi loads a dedicated nftables table, `bridge inds_gateway`, on the
forwarding path between the guest AP and router ports. It starts with an
empty MAC block set. The rules match guest source MACs toward the router and
guest destination MACs in the reverse direction. Other firewall tables are
preserved.

On the Pi, identify both bridge members and substitute their names below.
Run from the repository root with nftables installed.

```sh
sudo python3 -m gateway.firewall check --guest-port AP_PORT --router-port ROUTER_PORT
sudo python3 -m gateway.firewall install --guest-port AP_PORT --router-port ROUTER_PORT
sudo nft list table bridge inds_gateway
```

Both commands check bridge membership. Install is one transaction and refuses
to replace an existing table. From the Pi console, remove only this table to
roll back with `sudo nft delete table bridge inds_gateway`.

Pi acceptance is pending. Verify guest DHCP, DNS, and HTTPS with the empty
policy installed, then verify forwarding with monitoring OFF. INDS-52 owns
approved block execution, and INDS-53 owns reversing individual actions.
