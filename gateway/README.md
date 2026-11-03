# INDS gateway

Host networking for the inline Raspberry Pi prototype lives here. The Pi bridges
two Ethernet ports between a separate guest Wi-Fi AP and the existing router.
The AP provides Wi-Fi; the router remains the DHCP server and internet gateway.

| Location | Purpose |
| --- | --- |
| `config/bridge.nmcli.example` | Reviewed, manual NetworkManager command template |
| `scripts/inspect-network.sh` | Read-only Linux network inventory |
| `../docs/gateway/setup.md` | Hardware, provisioning, activation, and recovery |
| `../docs/gateway/verification.md` | Acceptance checks and measurement record |

Start with [setup](../docs/gateway/setup.md). Templates are not automatically
installed or executed. Store machine-specific notes and generated configurations
in ignored `gateway/local/`; never commit credentials or network captures.

Keep responsibilities separate:

- NetworkManager and the Linux bridge own persistent forwarding.
- Future collectors observe traffic without becoming a forwarding dependency.
- Backend services own persistence, incident state, and administrator approval.
- A future narrowly scoped executor owns INDS firewall rules. It must not flush
  unrelated rules or tear down the bridge during OFF or application shutdown.

No firewall enforcement, collector, ON/OFF controller, or service units are
implemented in this package. The hardware procedure has not been validated on
the team's Pi. Do not treat templates as completed INDS-36 acceptance evidence.
