# INDS gateway

Host networking for the inline Raspberry Pi prototype lives here. The Pi bridges
two Ethernet ports between a separate guest Wi-Fi AP and the existing router.
The AP provides Wi-Fi; the router remains the DHCP server and internet gateway.

| Location | Purpose |
| --- | --- |
| `config/bridge.nmcli.example` | Reviewed, manual NetworkManager command template |
| `scripts/inspect-network.sh` | Read-only Linux network inventory |
| [INDS-42](../docs/INDS-42.md) | Run the passive traffic metadata collector |
| `../docs/gateway/setup.md` | Hardware, provisioning, activation, and recovery |
| `../docs/gateway/verification.md` | Acceptance checks and measurement record |

Start with [setup](../docs/gateway/setup.md). Templates are not automatically
installed or executed. Store machine-specific notes and generated configurations
in ignored `gateway/local/`; never commit credentials or network captures.

Keep responsibilities separate:

- NetworkManager and the Linux bridge own persistent forwarding.
- Collectors observe traffic independently of forwarding.
- Backend services own persistence, incident state, and administrator approval.
- A future narrowly scoped executor owns INDS firewall rules. It must not flush
  unrelated rules or tear down the bridge during OFF or application shutdown.

The hardware procedure still needs validation on the team's Pi for INDS-36.
